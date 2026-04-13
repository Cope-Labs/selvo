"""CVE lifecycle tracking — compute exposure window from disclosure to now.

For each package, finds the oldest open CVE disclosure date and computes
how many days the package has been exposed.

Data source: OSV.dev /vulns/{id} endpoint, which includes a `published` field.
Results are cached at the same 24h TTL as CVE lookups.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache

_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{cve_id}"
_TTL = 86400  # 24h
_SEM = asyncio.Semaphore(10)


async def _fetch_published_date(cve_id: str, client: httpx.AsyncClient) -> str | None:
    """Return the OSV `published` ISO timestamp for a CVE, or None on failure."""
    cache_key = f"osv_published:{cve_id}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached  # may be "" if previously not found

    async with _SEM:
        try:
            resp = await client.get(
                _OSV_VULN_URL.format(cve_id=cve_id),
                timeout=10.0,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                published = resp.json().get("published", "")
                _cache.set_cache(cache_key, published, _TTL)
                return published or None
            _cache.set_cache(cache_key, "", _TTL)
        except Exception:
            pass
    return None


def _days_since(iso_ts: str) -> int:
    """Return whole days from an ISO-8601 timestamp to now (UTC)."""
    try:
        # Handle both 'Z' suffix and '+00:00'
        ts = iso_ts.rstrip("Z").split("+")[0]
        dt = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        return max(int(delta.days), 0)
    except Exception:
        return 0


async def enrich_cve_timeline(packages: list[PackageRecord]) -> list[PackageRecord]:
    """
    For each package with open CVEs, fetch OSV disclosure dates and set:
      - exposure_days        : days since the OLDEST open CVE was disclosed
      - cve_disclosed_at     : ISO date string of that oldest disclosure
    """
    # Collect unique CVE IDs across all packages
    all_cves: set[str] = set()
    for pkg in packages:
        all_cves.update(pkg.cve_ids)

    if not all_cves:
        return packages

    async with httpx.AsyncClient() as client:
        dates = await asyncio.gather(
            *[_fetch_published_date(cve, client) for cve in all_cves],
            return_exceptions=True,
        )

    cve_date_map: dict[str, str] = {}
    for cve, result in zip(all_cves, dates):
        if isinstance(result, str) and result:
            cve_date_map[cve] = result

    for pkg in packages:
        if not pkg.cve_ids:
            continue
        dated = [(cve, cve_date_map[cve]) for cve in pkg.cve_ids if cve in cve_date_map]
        if not dated:
            continue
        oldest_cve, oldest_ts = min(dated, key=lambda x: x[1])
        pkg.exposure_days = _days_since(oldest_ts)
        # Store just the date part (YYYY-MM-DD) for display
        pkg.cve_disclosed_at = oldest_ts[:10]

    return packages
