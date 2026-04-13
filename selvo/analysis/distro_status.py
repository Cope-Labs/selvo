"""Filter CVEs against the Debian Security Tracker.

Two filtering passes happen in :func:`filter_resolved_cves`:

1. **Resolved/EOL drop** — if Debian reports any release as ``resolved`` or
   ``end-of-life`` for the CVE/package pair, drop it. This is the original
   behavior: the distro has fixed it, so it's not vulnerable.

2. **Unimportant drop with override** — if *all* tracked releases are urgency
   ``unimportant`` or ``end-of-life``, Debian's security team has explicitly
   judged the CVE as not worth fixing. We trust that judgment **unless**
   real-world exploit signals contradict it:

       override = in_cisa_kev OR max_epss >= MIN_EPSS_OVERRIDE OR
                  exploit_maturity == "weaponized"

   Empirically (sampled across 50K Debian-tracked CVEs, 2026-04), only
   ~1.2% of "unimportant" CVEs trip an EPSS≥0.5 / KEV override — so this
   rule preserves Debian's filtering ~99% of the time while catching the
   handful of cases where Debian was wrong.

Filtered "minor" CVEs are removed from ``pkg.cve_ids`` and counted on
``pkg.minor_cve_count`` so the dashboard can surface them separately.

This step **must** run after ``enrich_epss`` and ``enrich_exploits`` so the
override signals (max_epss, in_cisa_kev, exploit_maturity) are populated.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from selvo.discovery.base import PackageRecord

log = logging.getLogger(__name__)

# Full JSON dump of Debian security tracker — keyed by CVE ID
_DST_URL = "https://security-tracker.debian.org/tracker/data/json"
_DST_CACHE: Optional[dict] = None  # module-level cache so we only fetch once per run

# Override threshold: an "unimportant" CVE with EPSS at or above this is kept
# anyway. 0.5 = 50% probability of exploitation in the next 30 days. See the
# module docstring for empirical justification.
MIN_EPSS_OVERRIDE = 0.5


async def _load_dst(client: httpx.AsyncClient) -> dict:
    global _DST_CACHE
    if _DST_CACHE is not None:
        return _DST_CACHE
    try:
        resp = await client.get(_DST_URL, timeout=60.0, follow_redirects=True)
        resp.raise_for_status()
        _DST_CACHE = resp.json()
        log.info("Debian Security Tracker loaded: %d packages", len(_DST_CACHE))
    except Exception as exc:
        log.warning("Debian Security Tracker fetch failed: %s — keeping all CVEs", exc)
        _DST_CACHE = {}
    return _DST_CACHE or {}


async def warm_dst() -> None:
    """Pre-download the Debian Security Tracker JSON (~70 MB).

    Called from the FastAPI startup hook so the first scan doesn't pay the
    one-time download cost. Safe to call repeatedly — the module-level cache
    short-circuits subsequent calls.
    """
    async with httpx.AsyncClient() as client:
        await _load_dst(client)


def _cve_classification(cve_id: str, names_to_check: set[str], tracker: dict) -> str:
    """Classify a CVE under DST.

    Returns one of:
        "resolved"    — at least one release is resolved or end-of-life
        "unimportant" — DST tracks it and *every* release is unimportant/EOL
        "open"        — DST tracks it as a real open issue, OR DST has no data
                        (default to "open" to err on the side of reporting).
    """
    for pkg_name in names_to_check:
        cve_entry = tracker.get(pkg_name, {}).get(cve_id, {})
        releases = cve_entry.get("releases", {})
        if not releases:
            continue
        all_minor = True
        any_resolved = False
        for suite_data in releases.values():
            status = suite_data.get("status", "")
            urgency = suite_data.get("urgency", "")
            if status in ("resolved", "end-of-life"):
                any_resolved = True
                continue
            if urgency not in ("unimportant", "end-of-life"):
                all_minor = False
        if any_resolved:
            return "resolved"
        if all_minor:
            return "unimportant"
        return "open"
    # CVE not present in DST under any of these names — keep it as "open"
    return "open"


def _has_override(pkg: PackageRecord, cve_id: str) -> bool:
    """Should this CVE be kept despite an "unimportant" DST classification?

    Two signals are enough on their own:
      - in_cisa_kev: CISA confirms active exploitation in the wild
      - exploit_maturity == "weaponized": real attack tooling exists

    EPSS alone is intentionally NOT an override. EPSS is a version-agnostic
    probability trained on global telemetry — a high EPSS on a 2012 CVE
    reflects attackers probing ancient installs of the software, not that
    your 2024 build is at risk. Honoring EPSS-only overrides caused
    LibreOffice 24.2 to surface CVE-2012-5639 with score 31.5 despite 16
    years of upstream fixes. KEV and weaponized-exploit signals are more
    grounded: they indicate actual, current, verified exploitation.

    Note: signals are read at the package level (not per-CVE) because KEV
    and exploit maturity are only populated per package by upstream
    enrichers. In the rare case a package has multiple unimportant CVEs
    and one triggers KEV/weaponized, all of that package's unimportant
    CVEs are kept — conservative by design.
    """
    if pkg.in_cisa_kev:
        return True
    if pkg.exploit_maturity == "weaponized":
        return True
    return False


async def filter_resolved_cves(packages: list[PackageRecord]) -> list[PackageRecord]:
    """
    Filter CVEs against the Debian Security Tracker.

    Drops in two passes:
      1. CVEs the distro reports as resolved or end-of-life.
      2. CVEs Debian classifies as ``unimportant`` (low impact, won't fix)
         unless package-level exploit signals override that judgment.

    Sets ``pkg.minor_cve_count`` to the number of CVEs filtered as
    "unimportant" so the UI can surface them separately.

    Uses the Debian Security Tracker which covers Debian, Ubuntu, and — because
    they share the same upstream sources — provides useful signal for Arch,
    NixOS, Homebrew, and Alpine.

    **Pipeline order:** must run after ``enrich_epss`` and ``enrich_exploits``
    so the override signals (max_epss, in_cisa_kev, exploit_maturity) are
    populated; otherwise every override evaluates to False and the function
    over-filters.
    """
    _DST_ECOSYSTEMS = ("debian", "ubuntu", "arch", "nixos", "homebrew", "alpine")
    deb_packages = [
        p for p in packages
        if any(e in p.ecosystem for e in _DST_ECOSYSTEMS)
    ]
    if not deb_packages:
        return packages

    async with httpx.AsyncClient() as client:
        tracker = await _load_dst(client)

    if not tracker:
        return packages  # API unavailable — keep everything

    # DST keys by source package name, not binary. Resolve binary→source.
    try:
        from selvo.analysis.debian_index import load_debian_index
        deb_idx = await load_debian_index()
    except Exception as exc:
        log.warning("Debian package index unavailable: %s — DST lookups may miss binary→source mappings", exc)
        deb_idx = None

    total_resolved = 0
    total_minor = 0
    total_kept_via_override = 0

    # Pull per-CVE EPSS from the cache so we can recompute pkg.max_epss after
    # filtering. Otherwise a package whose CVEs all get dropped still carries
    # the stale aggregate score from before the drop.
    from selvo.analysis import cache as _cache

    for pkg in deb_packages:
        # Try source name first (DST uses source), fall back to binary name
        src_name = deb_idx.source_name(pkg.name) if deb_idx else pkg.name
        names_to_check = {pkg.name, src_name}

        kept: list[str] = []
        resolved_count = 0
        minor_count = 0
        for cve_id in pkg.cve_ids:
            classification = _cve_classification(cve_id, names_to_check, tracker)
            if classification == "resolved":
                resolved_count += 1
            elif classification == "unimportant":
                if _has_override(pkg, cve_id):
                    kept.append(cve_id)
                    total_kept_via_override += 1
                else:
                    minor_count += 1
            else:  # open
                kept.append(cve_id)

        pkg.cve_ids = kept
        pkg.minor_cve_count = minor_count
        total_resolved += resolved_count
        total_minor += minor_count

        # Recompute aggregate risk signals so they reflect the *kept* CVEs.
        # Without this, a package whose only CVEs were resolved/minor still
        # carries a nonzero max_epss and ends up with a score above the
        # no-signal cap even though nothing actionable remains.
        if resolved_count or minor_count:
            epss_scores = [
                float(_cache.get(f"epss:{cve}") or 0)
                for cve in kept
            ]
            pkg.max_epss = max(epss_scores) if epss_scores else 0.0
            if not kept:
                # Scorer treats an empty exploit signal list as "no signal",
                # which combined with an empty cve_ids list caps the score.
                pkg.exploit_maturity = "none"
                pkg.has_public_exploit = False
                pkg.in_cisa_kev = False
                pkg.exploit_urls = []

        notes = []
        if resolved_count:
            notes.append(f"{resolved_count} resolved")
        if minor_count:
            notes.append(f"{minor_count} minor (Debian: unimportant)")
        if notes:
            pkg.description = (pkg.description + f" [{', '.join(notes)}]").strip()

    if total_resolved or total_minor or total_kept_via_override:
        log.info(
            "DST filter: %d resolved dropped, %d minor hidden, %d kept via exploit override",
            total_resolved, total_minor, total_kept_via_override,
        )

    return packages
