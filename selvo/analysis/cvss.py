"""
CVSS severity enrichment via the NVD (National Vulnerability Database) API v2.

Fetches the numeric CVSS v3 base score (0–10) for each CVE and stores the
maximum score per package. Without a score, raw CVE count is retained as a
fallback signal in the scorer.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
  - No auth required, but rate-limited without a key:
      - With NVD_API_KEY in .env: 50 requests / 30 s
      - Without key            :  5 requests / 30 s  (much slower)
  - Set NVD_API_KEY in .env to opt-in to faster fetching.
"""
from __future__ import annotations

import asyncio
import os
from typing import Optional

import httpx

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_API_KEY = os.environ.get("NVD_API_KEY", "")
_TTL = 86400  # 24 hours

# Semaphore limits concurrency to stay within NVD rate limits
_SEM_WITH_KEY = asyncio.Semaphore(10)
_SEM_NO_KEY = asyncio.Semaphore(2)


def _sem() -> asyncio.Semaphore:
    return _SEM_WITH_KEY if _API_KEY else _SEM_NO_KEY


def _delay() -> float:
    """Seconds to sleep between requests to stay within rate limits."""
    return 0.3 if _API_KEY else 6.5


async def _fetch_cvss(cve_id: str, client: httpx.AsyncClient) -> float:
    """Return the CVSS v3 base score for a single CVE, or 0.0 on failure."""
    cache_key = f"cvss:{cve_id}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return float(cached)

    headers = {"apiKey": _API_KEY} if _API_KEY else {}
    async with _sem():
        try:
            resp = await client.get(
                _NVD_API,
                params={"cveId": cve_id},
                headers={"User-Agent": "selvo/0.1 (cvss-enricher)", **headers},
                timeout=12.0,
                follow_redirects=True,
            )
            if resp.status_code == 200:
                vulns = resp.json().get("vulnerabilities", [])
                if vulns:
                    metrics = vulns[0].get("cve", {}).get("metrics", {})
                    # Prefer CVSSv4.0 → CVSSv3.1 → CVSSv3.0 → CVSSv2
                    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        entries = metrics.get(key, [])
                        if entries:
                            score = float(
                                entries[0].get("cvssData", {}).get("baseScore", 0.0)
                            )
                            _cache.set_cache(cache_key, score, _TTL)
                            return score
        except Exception:
            pass
        await asyncio.sleep(_delay())
        return 0.0


async def enrich_cvss(
    packages: list[PackageRecord],
    console: Optional[object] = None,
) -> list[PackageRecord]:
    """
    Fetch CVSS base scores for all CVEs and set `max_cvss` on each package.

    Without an NVD_API_KEY only the top CVEs by EPSS exploitation probability
    are looked up (EPSS enrichment must run first). This keeps the NVD call
    count within the unauthenticated rate limit while ensuring the most
    actionable CVEs always get a severity score.

    Set NVD_API_KEY=<key> in .env to fetch CVSS for every CVE.
    Register free at https://nvd.nist.gov/developers/request-an-api-key
    """
    all_cves = list({cve for pkg in packages for cve in pkg.cve_ids})
    if not all_cves:
        return packages

    # Without an API key NVD allows ~5 req / 30 s.  Select only the CVEs
    # with the highest EPSS scores — those are both most urgent *and* most
    # likely to already be enriched in the cache from a prior run.
    _MAX_NO_KEY = 15
    cves_to_fetch: list[str]
    if _API_KEY or len(all_cves) <= _MAX_NO_KEY:
        cves_to_fetch = all_cves
    else:
        # Pull cached EPSS scores to rank CVEs; uncached ones score 0.
        epss_scores: dict[str, float] = {}
        for cve in all_cves:
            cached = _cache.get(f"epss:{cve}")
            if cached is not None:
                epss_scores[cve] = float(cached)
        # Per-package selection: pick each package's highest-EPSS CVE as its
        # representative, sort packages by that score, then take the top
        # _MAX_NO_KEY packages.  This distributes the NVD budget across many
        # packages instead of concentrating it on a few high-EPSS ones
        # (e.g. zlib/perl-base hogging all 15 slots while glibc/libuuid1 get 0).
        rep_cves: list[tuple[str, float]] = []  # (cve_id, best_epss)
        for pkg in packages:
            if not pkg.cve_ids:
                continue
            best = max(pkg.cve_ids, key=lambda c: epss_scores.get(c, 0.0))
            rep_cves.append((best, epss_scores.get(best, 0.0)))
        rep_cves.sort(key=lambda x: x[1], reverse=True)
        # Dedup in case two packages share a representative CVE
        cves_to_fetch = list(dict.fromkeys(c for c, _ in rep_cves))[:_MAX_NO_KEY]
        if console and hasattr(console, "print"):
            console.print(
                f"  [dim]CVSS: {len(all_cves)} CVEs across {len(rep_cves)} packages, "
                f"fetching {len(cves_to_fetch)} representative CVEs "
                f"(set NVD_API_KEY for full coverage)[/]"
            )

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            *[_fetch_cvss(cve, client) for cve in cves_to_fetch]
        )
    cvss_map = dict(zip(cves_to_fetch, results))

    for pkg in packages:
        scores = [cvss_map[cve] for cve in pkg.cve_ids if cve in cvss_map]
        if scores:
            pkg.max_cvss = max(scores)

    return packages
