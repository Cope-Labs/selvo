"""Version gap analysis — compare installed vs upstream versions."""
from __future__ import annotations

import asyncio
import logging

import httpx
from packaging.version import Version, InvalidVersion

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache

log = logging.getLogger(__name__)

_REPOLOGY_API = "https://repology.org/api/v1/project/{name}"
_TTL = 21600  # 6 hours – reduces re-fetching on repeated CI runs
# Repology rate-limit: ~1 req/s without a key. Semaphore of 2 prevents
# blasting all 50 packages at once; the retry loop handles transient 429s.
_SEM = asyncio.Semaphore(2)


# Repology repo names for stable/current releases we treat as "installed"
_STABLE_REPOS = {
    "debian_12", "debian_13", "debian_14",
    "ubuntu_22_04", "ubuntu_24_04", "ubuntu_25_04",
    "fedora_41", "fedora_42",
    "alpine_3_20", "alpine_3_21", "alpine_3_22",
    "archlinux",
    "nixos_24_11", "nixos_25_05",
}


def _clean_version(raw: str) -> str:
    """Strip Debian epochs (e.g. '1:2.3') and packaging suffixes (.dfsg, .orig, +dfsg, etc.)
    so packaging.version.Version can parse the result."""
    # Drop epoch
    v = raw.split(":")[-1]
    # Strip common distro suffixes
    for suffix in ("+dfsg", ".dfsg", "+orig", ".orig", "+really", "~dfsg", "~bpo"):
        idx = v.lower().find(suffix)
        if idx != -1:
            v = v[:idx]
    return v.strip()


async def _fetch_repology(name: str, client: httpx.AsyncClient) -> tuple[str | None, int, str | None]:
    """
    Query Repology for a package.
    Returns (newest_version, newest_repo_count, distro_current_version).
    newest_repo_count serves as a download_count proxy.
    distro_current_version is the best (highest) version seen in stable distro repos.
    """
    cache_key = f"repology_version:{name}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached[0], cached[1], cached[2] if len(cached) > 2 else None

    async with _SEM:
        try:
            resp = None
            for attempt in range(3):
                resp = await client.get(
                    _REPOLOGY_API.format(name=name),
                    timeout=10.0,
                    follow_redirects=True,
                    headers={"User-Agent": "selvo/0.1 (github.com/Cope-Labs/selvo)"},
                )
                if resp.status_code == 429:
                    delay = float(resp.headers.get("Retry-After", 2 ** (attempt + 1)))
                    log.debug("Repology 429 for %s, sleeping %.0fs", name, delay)
                    await asyncio.sleep(delay)
                    continue
                break
            if resp is None or resp.status_code == 429:
                log.warning(
                    "Repology rate-limit not resolved for %s after 3 retries; "
                    "version gap will be unavailable for this package",
                    name,
                )
                return None, 0, None
            if resp.status_code == 404:
                _cache.set_cache(cache_key, [None, 0, None], _TTL)
                return None, 0, None
            resp.raise_for_status()
            repos = resp.json()
            versions: list[str] = []
            newest_count = 0
            distro_versions: list[str] = []
            for repo in repos:
                status = repo.get("status", "")
                if status in ("newest", "devel"):
                    newest_count += 1
                    ver = repo.get("version", "")
                    if ver:
                        versions.append(ver)
                if repo.get("repo") in _STABLE_REPOS:
                    ver = repo.get("version", "")
                    if ver:
                        distro_versions.append(_clean_version(ver))

            def _safe(v: str) -> Version:
                try:
                    return Version(v)
                except InvalidVersion:
                    return Version("0")

            best = max(versions, key=_safe) if versions else None
            # Best distro-installed version = highest parseable from stable repos
            distro_current: str | None = None
            if distro_versions:
                parseable = [v for v in distro_versions if _safe(v) > Version("0")]
                if parseable:
                    distro_current = max(parseable, key=_safe)
            _cache.set_cache(cache_key, [best, newest_count, distro_current], _TTL)
            return best, newest_count, distro_current
        except Exception:
            return None, 0, None


async def enrich_versions(packages: list[PackageRecord]) -> list[PackageRecord]:
    """Annotate each PackageRecord with upstream version, distro-installed version,
    and a popularity proxy from Repology.

    For Debian packages still showing version=unknown after Repology (usually
    because the discovery name is a binary package name not tracked by Repology),
    fall back to the Version: field from the local Packages.gz index.
    """
    async with httpx.AsyncClient() as client:
        tasks = [_fetch_repology(pkg.name, client) for pkg in packages]
        results = await asyncio.gather(*tasks)

    for pkg, (upstream, newest_count, distro_current) in zip(packages, results):
        if upstream:
            pkg.upstream_version = upstream
        if distro_current and pkg.version in ("unknown", ""):
            pkg.version = distro_current
            pkg.version_source = "repology"
        if pkg.download_count == 0 and newest_count > 0:
            pkg.download_count = newest_count

    # Second pass: for Debian packages that still have no installed version,
    # read it directly from the Packages.gz Version: field.  This covers binary
    # package names (libbz2-1.0, libexpat1, libuuid1 …) that Repology doesn't
    # index.  The Version: field in Packages.gz is the distro-installed version.
    still_unknown = [
        p for p in packages
        if p.version in ("unknown", "")
        and "debian" in [e.strip() for e in p.ecosystem.split(",")]
    ]
    if still_unknown:
        from selvo.analysis.debian_index import load_debian_index
        deb_idx = await load_debian_index()
        for pkg in still_unknown:
            raw = deb_idx.installed_version(pkg.name)
            if raw:
                pkg.version = _clean_version(raw)
                pkg.version_source = "packages.gz"

    return packages
