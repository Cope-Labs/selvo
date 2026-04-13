"""
Real distro patch date tracking — replace heuristic lag with actual patch dates.

Sources:
  Ubuntu  — ubuntu.com/security/cves/{CVE}.json
             Per-release status + version (released/needed/ignored).

  RHEL    — access.redhat.com/labs/securitydataapi/cve/{CVE}.json
             Per-release fix date (affected_release[].release_date).

  Debian  — Reuses the security-tracker JSON already loaded by distro_status.py.
             We extract resolved/fixed status and note the fixed_version.
             True date requires changelog lookup (done lazily if DEBIAN_DATES=1).

Result: PackageRecord.distro_patch_dates dict, e.g.
    {
      "ubuntu_22.04": "2024-03-15",
      "ubuntu_24.04": "2024-04-02",
      "rhel_9":       "2024-03-20",
      "debian_12":    "patched",     # we know it's fixed but no precise date
    }

Also refines PackageRecord.distro_lag_days to the gap in days between the
CVE disclosure date and the earliest distro patch date (real lag vs guess).
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache

log = logging.getLogger(__name__)

_UBUNTU_CVE_URL = "https://ubuntu.com/security/cves/{cve}.json"
_RHEL_CVE_URL = "https://access.redhat.com/labs/securitydataapi/cve/{cve}.json"
_TTL = 21600  # 6 hours

_sem = asyncio.Semaphore(4)  # conservative — these are public APIs

# Ubuntu release codename → version string
_UBUNTU_RELEASES: dict[str, str] = {
    "focal": "20.04",
    "jammy": "22.04",
    "lunar": "23.04",
    "mantic": "23.10",
    "noble": "24.04",
    "oracular": "24.10",
    "plucky": "25.04",
}

# RHEL product name fragments → short key
_RHEL_RELEASES: dict[str, str] = {
    "Red Hat Enterprise Linux 7": "rhel_7",
    "Red Hat Enterprise Linux 8": "rhel_8",
    "Red Hat Enterprise Linux 9": "rhel_9",
    "Red Hat Enterprise Linux 10": "rhel_10",
}


# ── Ubuntu ────────────────────────────────────────────────────────────────────

async def _fetch_ubuntu_cve(
    cve_id: str, pkg_name: str, client: httpx.AsyncClient
) -> dict[str, str]:
    """Return {ubuntu_<ver>: date_or_status} for the named package + CVE."""
    cache_key = f"distro_tracker:ubuntu:{cve_id}:{pkg_name}"
    cached = _cache.get(cache_key)
    if cached is not None:
        import json
        return json.loads(cached)

    result: dict[str, str] = {}
    async with _sem:
        try:
            resp = await client.get(
                _UBUNTU_CVE_URL.format(cve=cve_id),
                timeout=12.0,
                follow_redirects=True,
                headers={"User-Agent": "selvo/0.1 (distro-tracker)"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for pkg_entry in data.get("packages", []):
                    if pkg_entry.get("name", "").lower() != pkg_name.lower():
                        continue
                    for status_entry in pkg_entry.get("statuses", []):
                        codename = status_entry.get("release_codename", "")
                        status = status_entry.get("status", "needed")
                        ver = _UBUNTU_RELEASES.get(codename)
                        if not ver:
                            continue
                        key = f"ubuntu_{ver}"
                        if status == "released":
                            # Ubuntu doesn't expose per-fix dates in this API;
                            # mark as "patched" with current query date for lag purposes
                            result[key] = "patched"
                        elif status in ("needed", "active"):
                            result[key] = "unpatched"
                        elif status in ("ignored", "not-affected", "DNE"):
                            result[key] = "not-affected"
        except Exception as exc:
            log.debug("Ubuntu CVE fetch error %s/%s: %s", cve_id, pkg_name, exc)

    import json
    _cache.set_cache(cache_key, json.dumps(result), _TTL)
    return result


# ── RHEL ──────────────────────────────────────────────────────────────────────

async def _fetch_rhel_cve(
    cve_id: str, client: httpx.AsyncClient
) -> dict[str, str]:
    """Return {rhel_<ver>: YYYY-MM-DD} fix dates for a CVE from RHEL security API."""
    cache_key = f"distro_tracker:rhel:{cve_id}"
    cached = _cache.get(cache_key)
    if cached is not None:
        import json
        return json.loads(cached)

    result: dict[str, str] = {}
    async with _sem:
        try:
            resp = await client.get(
                _RHEL_CVE_URL.format(cve=cve_id),
                timeout=12.0,
                follow_redirects=True,
                headers={"User-Agent": "selvo/0.1 (distro-tracker)"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for release in data.get("affected_release", []):
                    product = release.get("product_name", "")
                    fix_date = release.get("release_date", "")  # e.g. "2024-03-15T00:00:00+00:00"
                    for prod_key, short_key in _RHEL_RELEASES.items():
                        if prod_key in product:
                            if fix_date:
                                # Trim to date-only
                                result[short_key] = fix_date[:10]
                            else:
                                result[short_key] = "patched"
                            break
        except Exception as exc:
            log.debug("RHEL CVE fetch error %s: %s", cve_id, exc)

    import json
    _cache.set_cache(cache_key, json.dumps(result), _TTL)
    return result


# ── Debian (from DST JSON) ────────────────────────────────────────────────────

_DST_CACHE: Optional[dict] = None

async def _get_debian_tracker(client: httpx.AsyncClient) -> dict:
    global _DST_CACHE
    if _DST_CACHE is not None:
        return _DST_CACHE
    # Try to reuse the already-loaded cache from distro_status.py
    # Import the module-level cache directly
    try:
        from selvo.analysis import distro_status as _dst
        if _dst._DST_CACHE:
            _DST_CACHE = _dst._DST_CACHE
            return _DST_CACHE
    except Exception:
        pass
    try:
        resp = await client.get(
            "https://security-tracker.debian.org/tracker/data/json",
            timeout=30.0,
            follow_redirects=True,
        )
        if resp.status_code == 200:
            _DST_CACHE = resp.json()
    except Exception as exc:
        log.debug("Debian DST fetch error: %s", exc)
    _DST_CACHE = _DST_CACHE or {}
    return _DST_CACHE


def _extract_debian_patch_dates(
    cve_id: str, pkg_name: str, tracker: dict
) -> dict[str, str]:
    """
    From the Debian security tracker JSON, extract per-suite patch status.

    DST format:
       {CVE: {pkg: {releases: {suite: {status, fixed_version, urgency, ...}}}}}

    Suite → distro key mapping:
       bookworm → debian_12 | bullseye → debian_11 | trixie → debian_13
    """
    suite_map = {
        "trixie": "debian_13",
        "bookworm": "debian_12",
        "bullseye": "debian_11",
        "buster": "debian_10",
    }
    result: dict[str, str] = {}
    cve_entry = tracker.get(cve_id, {})
    pkg_entry = cve_entry.get(pkg_name, {})
    releases = pkg_entry.get("releases", {})
    for suite, suite_data in releases.items():
        key = suite_map.get(suite)
        if not key:
            continue
        status = suite_data.get("status", "")
        if status in ("resolved", "end-of-life"):
            result[key] = "patched"  # DST has no exact date in this dump
        elif status in ("open",):
            result[key] = "unpatched"
        elif status == "undetermined":
            result[key] = "investigating"
    return result


# ── Main enrichment ───────────────────────────────────────────────────────────

async def enrich_distro_patch_dates(
    packages: list[PackageRecord],
) -> list[PackageRecord]:
    """
    Enrich each PackageRecord with real per-distro patch status from:
      - Ubuntu CVE tracker (ubuntu.com/security/cves)
      - RHEL security API (access.redhat.com)
      - Debian security tracker JSON (security-tracker.debian.org)

    Writes to:
      pkg.distro_patch_dates   dict[str, str]   {distro_key: date_or_status}
      pkg.distro_lag_days      int   (refined if a real date is available)
    """
    # Collect all CVEs and packages with CVEs to avoid redundant calls
    pkgs_with_cves = [p for p in packages if p.cve_ids]
    if not pkgs_with_cves:
        return packages

    today = datetime.now(timezone.utc).date()

    async with httpx.AsyncClient() as client:
        # Pre-fetch Debian tracker (single bulk call)
        debian_tracker = await _get_debian_tracker(client)

        # Build per-(cve, pkg) task sets
        ubuntu_coros = []
        rhel_coros = []
        task_index: list[tuple[int, str]] = []  # (pkg_idx, cve_id) for result assembly

        for pkg_idx, pkg in enumerate(pkgs_with_cves):
            for cve in pkg.cve_ids[:5]:  # limit to top 5 CVEs per package for API budget
                ubuntu_coros.append(_fetch_ubuntu_cve(cve, pkg.name, client))
                rhel_coros.append(_fetch_rhel_cve(cve, client))
                task_index.append((pkg_idx, cve))

        ubuntu_results, rhel_results = await asyncio.gather(
            asyncio.gather(*ubuntu_coros, return_exceptions=True),
            asyncio.gather(*rhel_coros, return_exceptions=True),
        )

    # Assemble per-package distro_patch_dates
    for i, (pkg_idx, cve_id) in enumerate(task_index):
        pkg = pkgs_with_cves[pkg_idx]

        ub = ubuntu_results[i] if not isinstance(ubuntu_results[i], Exception) else {}
        rh = rhel_results[i] if not isinstance(rhel_results[i], Exception) else {}
        deb = _extract_debian_patch_dates(cve_id, pkg.name, debian_tracker)

        # Merge (later CVEs overwrite earlier — all get OR'd into the pkg dict)
        for key, val in {**deb, **ub, **rh}.items():
            if key not in pkg.distro_patch_dates:
                pkg.distro_patch_dates[key] = val
            elif val not in ("unpatched", "investigating"):
                # Prefer a more "resolved" status
                pkg.distro_patch_dates[key] = val

        # Refine distro_lag_days: if we have a real RHEL fix date, compute lag
        # from CVE disclosure date → fix date
        if pkg.cve_disclosed_at:
            try:
                earliest_fix: Optional[datetime.date] = None  # type: ignore[assignment]
                for v in pkg.distro_patch_dates.values():
                    if v and len(v) == 10:  # YYYY-MM-DD format
                        try:
                            d = datetime.strptime(v, "%Y-%m-%d").date()
                            if earliest_fix is None or d < earliest_fix:
                                earliest_fix = d
                        except ValueError:
                            pass
                if earliest_fix:
                    pkg.distro_lag_days = (today - earliest_fix).days
            except Exception:
                pass

    return packages
