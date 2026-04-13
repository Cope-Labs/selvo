"""
OSS-Fuzz coverage signal — flag packages actively fuzz-tested by Google's OSS-Fuzz.

OSS-Fuzz runs continuous fuzzing against 1,000+ open-source projects. A package
covered by OSS-Fuzz has its memory-safety bugs continuously found and fixed, which
meaningfully reduces reliable exploit risk for C/C++ packages.

Signal usage in selvo:
  - ossfuzz_covered = True  → downgrade patch urgency for memory-corruption CVEs
    (the bug is likely caught early; if it's still open, it's harder to exploit)
  - Displayed in patch plan and terminal output as a safety indicator

Source: OSS-Fuzz project index JSON
  https://oss-fuzz.com/static-data/projects.json

The index maps project name → {language, primary_contact, main_repo, ...}.
We match against package names and upstream repo domains.

Result fields on PackageRecord:
  ossfuzz_covered   bool
  ossfuzz_project   str   (OSS-Fuzz project name if matched)
"""
from __future__ import annotations

import logging

import httpx

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache

log = logging.getLogger(__name__)

_INDEX_URL = "https://oss-fuzz.com/static-data/projects.json"
_TTL = 86400  # 24 hours — the index is updated infrequently

_index_cache: dict | None = None


async def _load_index(client: httpx.AsyncClient) -> dict[str, dict]:
    """Return {project_name: project_data} from the OSS-Fuzz project index."""
    global _index_cache
    if _index_cache is not None:
        return _index_cache

    raw = _cache.get("ossfuzz:index")
    if raw:
        import json
        _index_cache = json.loads(raw)
        return _index_cache

    try:
        resp = await client.get(
            _INDEX_URL,
            timeout=20.0,
            follow_redirects=True,
            headers={"User-Agent": "selvo/0.1 (ossfuzz-enricher)"},
        )
        if resp.status_code == 200:
            data = resp.json()
            # Format varies — could be list or dict. Normalise to dict.
            if isinstance(data, list):
                index = {p["name"]: p for p in data if "name" in p}
            elif isinstance(data, dict):
                index = data
            else:
                index = {}
            _index_cache = index
            import json
            _cache.set_cache("ossfuzz:index", json.dumps(index), _TTL)
            log.debug("OSS-Fuzz index loaded: %d projects", len(index))
            return index
    except Exception as exc:
        log.debug("OSS-Fuzz index fetch failed: %s", exc)

    _index_cache = {}
    return {}


def _match_project(pkg: PackageRecord, index: dict[str, dict]) -> str:
    """
    Return the OSS-Fuzz project name if the package is covered, else ''.

    Matching strategy (in priority order):
      1. Exact package name match (e.g. 'curl', 'openssl', 'zlib')
      2. Upstream repo domain match (github.com/OWNER/REPO → REPO)
      3. Common alias expansions (libc6 → glibc, libssl → openssl, …)
    """
    _ALIASES: dict[str, str] = {
        "libc6": "glibc",
        "libc-bin": "glibc",
        "libssl3": "openssl",
        "libssl-dev": "openssl",
        "libz": "zlib",
        "zlib1g": "zlib",
        "libcurl4": "curl",
        "libexpat1": "libexpat",
        "libgcc1": "gcc",
        "libstdc++6": "libstdcxx",
        "libpng16-16": "libpng",
        "libgnutls30": "gnutls",
        "libpcre3": "pcre",
        "libpcre2-8-0": "pcre2",
        "libssh2-1": "libssh2",
        "libkrb5-3": "krb5",
    }

    name = pkg.name.lower()
    if name in index:
        return name

    alias = _ALIASES.get(name, "")
    if alias and alias in index:
        return alias

    # Repo-based match: github.com/torvalds/linux → "linux"
    if pkg.upstream_repo:
        repo_lower = pkg.upstream_repo.lower()
        for proj_name in index:
            if proj_name in repo_lower:
                return proj_name

    return ""


async def enrich_ossfuzz(packages: list[PackageRecord]) -> list[PackageRecord]:
    """
    Enrich each PackageRecord with OSS-Fuzz coverage data.

    Sets:
        pkg.ossfuzz_covered   bool
        pkg.ossfuzz_project   str
    """
    async with httpx.AsyncClient() as client:
        index = await _load_index(client)

    if not index:
        return packages  # API unavailable

    for pkg in packages:
        proj = _match_project(pkg, index)
        if proj:
            pkg.ossfuzz_covered = True
            pkg.ossfuzz_project = proj

    covered = sum(1 for p in packages if p.ossfuzz_covered)
    log.debug("OSS-Fuzz: %d/%d packages covered", covered, len(packages))
    return packages
