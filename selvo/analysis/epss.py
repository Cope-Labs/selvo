"""
EPSS (Exploit Prediction Scoring System) enrichment via FIRST.org API.

EPSS gives the *probability* a CVE will be actively exploited in the wild
within the next 30 days, trained on real exploit telemetry. It is the most
actionable single signal for prioritisation — a CVSS 9.8 with 0.1% EPSS is
far less urgent than a CVSS 5.0 with 94% EPSS.

API: https://api.first.org/data/v1/epss
  - No auth required
  - Up to 100 CVEs per batch request
  - Returns: {cve, epss (probability 0-1), percentile}
"""
from __future__ import annotations

import asyncio

import httpx

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache

_EPSS_API = "https://api.first.org/data/v1/epss"
_BATCH_SIZE = 100  # FIRST.org cap per request
_TTL = 21600  # 6 hours


async def _fetch_epss_batch(
    cve_ids: list[str], client: httpx.AsyncClient
) -> dict[str, float]:
    """Return {cve_id: epss_score} for a batch of up to 100 CVE IDs."""
    if not cve_ids:
        return {}
    # Check cache for each CVE individually
    result: dict[str, float] = {}
    uncached: list[str] = []
    for cve in cve_ids:
        cached = _cache.get(f"epss:{cve}")
        if cached is not None:
            result[cve] = float(cached)
        else:
            uncached.append(cve)
    if not uncached:
        return result
    try:
        resp = await client.get(
            _EPSS_API,
            params={"cve": ",".join(uncached)},
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": "selvo/0.1 (epss-enricher)"},
        )
        if resp.status_code == 200:
            for entry in resp.json().get("data", []):
                cve = entry["cve"]
                score = float(entry["epss"])
                result[cve] = score
                _cache.set_cache(f"epss:{cve}", score, _TTL)
    except Exception:
        pass
    return result


_epss_csv_loaded = False


async def enrich_epss(packages: list[PackageRecord]) -> list[PackageRecord]:
    """
    Fetch EPSS scores for every CVE across all packages and set `max_epss`
    to the highest exploitation-probability score among a package's CVEs.

    On first call, downloads the full EPSS CSV (~10 MB) to warm the cache.
    Subsequent calls hit the local cache directly — zero API calls.
    """
    global _epss_csv_loaded
    all_cves = list({cve for pkg in packages for cve in pkg.cve_ids})
    if not all_cves:
        return packages

    # Bulk-load EPSS CSV on first use (one 10MB download vs hundreds of API calls)
    if not _epss_csv_loaded:
        try:
            import logging
            log = logging.getLogger(__name__)
            count = await cache_epss_csv()
            log.info("EPSS bulk CSV loaded: %d scores cached", count)
            _epss_csv_loaded = True
        except Exception:
            pass  # fall back to per-batch API calls below

    # Now all CVEs should be in cache — but fetch any remaining via API
    batches = [all_cves[i : i + _BATCH_SIZE] for i in range(0, len(all_cves), _BATCH_SIZE)]

    async with httpx.AsyncClient() as client:
        batch_results = await asyncio.gather(
            *[_fetch_epss_batch(batch, client) for batch in batches]
        )

    epss_map: dict[str, float] = {}
    for result in batch_results:
        epss_map.update(result)

    for pkg in packages:
        scores = [epss_map[cve] for cve in pkg.cve_ids if cve in epss_map]
        pkg.max_epss = max(scores) if scores else 0.0

    return packages


_EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_EPSS_CSV_TTL = 86400  # 24 h — CSV is published once per day


async def cache_epss_csv() -> int:
    """Download the full EPSS CSV from FIRST.org and bulk-warm the local cache.

    The file is ~10 MB gzipped and contains scores for every public CVE.
    Each score is stored with a 24-hour TTL so the per-CVE cache entries
    created by :func:`_fetch_epss_batch` are automatically refreshed the
    next time ``selvo sync epss`` is run.

    Returns the number of CVE scores successfully cached.
    """
    import csv
    import gzip

    async with httpx.AsyncClient(follow_redirects=True, timeout=120.0) as client:
        resp = await client.get(
            _EPSS_CSV_URL,
            headers={"User-Agent": "selvo/0.1 (epss-bulk-sync)"},
        )
        resp.raise_for_status()

    raw = gzip.decompress(resp.content).decode("utf-8")
    # First line is a comment like  #model_version:v2023.03.01,score_date:2024-01-27T00:00:00+0000
    reader = csv.DictReader(line for line in raw.splitlines() if not line.startswith("#"))

    count = 0
    for row in reader:
        cve = row.get("cve", "").strip()
        epss_str = row.get("epss", "").strip()
        if not cve or not epss_str:
            continue
        try:
            score = float(epss_str)
        except ValueError:
            continue
        _cache.set_cache(f"epss:{cve}", score, _EPSS_CSV_TTL)
        count += 1

    return count


def enrich_epss_velocity(
    packages: list[PackageRecord],
    previous_snapshot: list[dict],
) -> list[PackageRecord]:
    """
    Compare current max_epss values against a previous snapshot to compute
    the velocity (delta) of exploitation probability movement.

    Sets on each PackageRecord:
        epss_prev    float   max_epss from the previous snapshot (0.0 if unseen)
        epss_delta   float   current max_epss − prev max_epss (positive = worsening)

    Call this *after* enrich_epss() so max_epss is already populated.
    The previous_snapshot is the list[dict] returned by cache.load_last_snapshot().
    """
    if not previous_snapshot:
        return packages

    prev_map = {r["name"]: r.get("max_epss", 0.0) for r in previous_snapshot}

    for pkg in packages:
        prev = prev_map.get(pkg.name, 0.0)
        pkg.epss_prev = round(prev, 4)
        pkg.epss_delta = round(pkg.max_epss - prev, 4)

    return packages
