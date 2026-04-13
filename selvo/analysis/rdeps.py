"""
Enrich packages with reverse-dependency counts.

Best available proxy: Repology's count of repositories that package a given
project. More repos = more widely deployed = higher downstream blast-radius.
This is fetched alongside version data (same API) with no extra cost.
"""
from __future__ import annotations

import asyncio

import httpx

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache

_REPOLOGY_API = "https://repology.org/api/v1/project/{name}"
_TTL = 3600  # 1 hour


async def _fetch_repo_count(name: str, client: httpx.AsyncClient) -> int:
    """Return the number of distinct distro repos that package `name` via Repology.

    Reads from the ``repology_version:{name}`` cache entry written by
    ``enrich_versions`` (same Repology endpoint, same data) to avoid a
    duplicate HTTP request.  Falls back to a direct API call only when the
    versions cache is absent (e.g. rdeps run in isolation).
    """
    # Fast-path: versions enricher already fetched this record
    cached_ver = _cache.get(f"repology_version:{name}")
    if cached_ver is not None:
        # stored as [version_str, repo_count_int]
        if isinstance(cached_ver, (list, tuple)) and len(cached_ver) > 1:
            return int(cached_ver[1])

    # Slow-path: versions cache cold, make our own call
    cache_key = f"repology_rdeps:{name}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return int(cached)
    try:
        resp = await client.get(
            _REPOLOGY_API.format(name=name),
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "selvo/0.1 (rdeps-enricher)"},
        )
        if resp.status_code == 200:
            repos = resp.json()
            count = len(set(r.get("repo", "") for r in repos if r.get("repo")))
            _cache.set_cache(cache_key, count, _TTL)
            return count
    except Exception:
        pass
    return 0


async def enrich_reverse_deps(packages: list[PackageRecord]) -> list[PackageRecord]:
    """
    Set `reverse_dep_count` on each package to the number of distro repositories
    that ship it (via Repology). Packages already enriched (count > 0) are skipped.
    This serves as a reliable, API-accessible proxy for downstream blast-radius.
    """
    to_fetch = [p for p in packages if p.reverse_dep_count == 0]
    if not to_fetch:
        return packages

    async with httpx.AsyncClient() as client:
        counts = await asyncio.gather(
            *[_fetch_repo_count(pkg.name, client) for pkg in to_fetch]
        )

    for pkg, count in zip(to_fetch, counts):
        pkg.reverse_dep_count = count

    return packages

