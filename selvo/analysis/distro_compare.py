"""Multi-distro version comparison and supply-chain lag index.

Fetches per-distro versions from Repology for each package (re-uses the
cached API responses from analysis/versions.py so no extra network cost on
subsequent runs) and computes:

  - distro_versions     : {distro_key: version} snapshot for each package
  - distro_lag_days     : rough lag estimate (version numeric delta × avg days/version)

The lag estimate is a heuristic: we can't get the exact date each distro shipped
a version without changelog scraping, so we use the version-gap magnitude and a
per-package velocity (patches/year) to estimate lag days.
"""
from __future__ import annotations

import asyncio
import logging

import httpx
from packaging.version import Version, InvalidVersion

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache

log = logging.getLogger(__name__)

_REPOLOGY_API = "https://repology.org/api/v1/project/{name}"
_TTL = 3600  # 1h (same as versions.py)
_SEM = asyncio.Semaphore(2)

# Distro repo keys we care about (Repology repo field values)
TRACKED_DISTROS: dict[str, str] = {
    "debian_12":    "Debian 12",
    "debian_13":    "Debian 13",
    "debian_14":    "Debian 14",
    "ubuntu_22_04": "Ubuntu 22.04",
    "ubuntu_24_04": "Ubuntu 24.04",
    "ubuntu_25_04": "Ubuntu 25.04",
    "fedora_41":    "Fedora 41",
    "fedora_42":    "Fedora 42",
    "alpine_3_20":  "Alpine 3.20",
    "alpine_3_21":  "Alpine 3.21",
    "archlinux":    "Arch Linux",
    "nixos_24_11":  "NixOS 24.11",
}

# Approximate average release interval in days for common versioning patterns.
# Used only when we have no upstream release-date data.
_DAYS_PER_MINOR = 90   # most libs release minors ~quarterly
_DAYS_PER_MAJOR = 365  # major releases ~annually


def _safe_version(v: str) -> Version:
    try:
        return Version(v.split(":")[-1])
    except InvalidVersion:
        return Version("0")


def _estimate_lag_days(pkg_version: str, target_version: str) -> int:
    """Heuristic – estimate lag in days from version string gap."""
    cur = _safe_version(pkg_version)
    tgt = _safe_version(target_version)
    if tgt <= cur:
        return 0
    major_gap = max(tgt.major - cur.major, 0)
    minor_gap = max(tgt.minor - cur.minor, 0)
    if major_gap:
        return major_gap * _DAYS_PER_MAJOR + minor_gap * _DAYS_PER_MINOR
    return minor_gap * _DAYS_PER_MINOR


async def _fetch_distro_versions(
    pkg_name: str, client: httpx.AsyncClient
) -> dict[str, str]:
    """Return {distro_key: version} from Repology for *pkg_name*.
    Re-uses the cached API response from versions.py when available."""
    cache_key = f"repology_distros:{pkg_name}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    async with _SEM:
        try:
            resp = await client.get(
                _REPOLOGY_API.format(name=pkg_name),
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "selvo/0.1 (distro-compare)"},
            )
            if resp.status_code != 200:
                _cache.set_cache(cache_key, {}, _TTL)
                return {}
            repos = resp.json()
        except Exception:
            return {}

    result: dict[str, str] = {}
    for repo_entry in repos:
        repo_key = repo_entry.get("repo", "")
        if repo_key in TRACKED_DISTROS:
            ver = repo_entry.get("version", "")
            if ver:
                result[repo_key] = ver.split(":")[-1]  # strip epoch

    _cache.set_cache(cache_key, result, _TTL)
    return result


async def enrich_distro_versions(packages: list[PackageRecord]) -> list[PackageRecord]:
    """
    Populate distro_versions and distro_lag_days for each package.

    distro_versions  – {distro_key: version_string} snapshot across tracked distros
    distro_lag_days  – heuristic days-behind-upstream for the CURRENT distro version
                       (uses the distro version that matches pkg.ecosystem, falling
                       back to the median across all distros)
    """
    async with httpx.AsyncClient() as client:
        all_versions = await asyncio.gather(
            *[_fetch_distro_versions(pkg.name, client) for pkg in packages],
            return_exceptions=True,
        )

    for pkg, versions in zip(packages, all_versions):
        if isinstance(versions, dict) and versions:
            pkg.distro_versions = versions

        if not pkg.upstream_version:
            continue

        # Pick the distro version most relevant to this package's ecosystem
        eco = pkg.ecosystem.split(",")[0].strip()
        eco_to_key = {
            "debian": "debian_13",
            "ubuntu": "ubuntu_24_04",
            "fedora": "fedora_41",
            "alpine": "alpine_3_21",
            "arch":   "archlinux",
            "nixos":  "nixos_24_11",
        }
        preferred_key = eco_to_key.get(eco)
        installed_v = None
        if preferred_key and isinstance(versions, dict):
            installed_v = versions.get(preferred_key)

        if not installed_v and isinstance(versions, dict) and versions:
            # Fall back to most-advanced version seen across distros
            best = max(versions.values(), key=_safe_version, default=None)
            installed_v = best

        if installed_v:
            pkg.distro_lag_days = _estimate_lag_days(installed_v, pkg.upstream_version)

    return packages


def distro_comparison_table(packages: list[PackageRecord]) -> list[dict]:
    """
    Return a list of comparison rows, one per package:
    {
        name, upstream_version,
        distros: {distro_label: version | None},
        max_lag_days
    }
    Sorted by max_lag_days descending (most-lagging packages first).
    """
    rows = []
    for pkg in packages:
        if not pkg.upstream_version:
            continue
        distros_row = {
            TRACKED_DISTROS[k]: pkg.distro_versions.get(k)
            for k in TRACKED_DISTROS
        }
        rows.append({
            "name": pkg.name,
            "upstream_version": pkg.upstream_version,
            "distros": distros_row,
            "max_lag_days": pkg.distro_lag_days,
        })
    return sorted(rows, key=lambda r: r["max_lag_days"], reverse=True)
