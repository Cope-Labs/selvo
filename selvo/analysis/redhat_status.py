"""Filter CVEs against the Red Hat Security Data API.

Same pattern as ``distro_status.py`` (Debian Security Tracker) but for
Red Hat family ecosystems: RHEL, Fedora, CentOS, Rocky Linux, AlmaLinux.

Red Hat exposes a per-CVE JSON feed at
``https://access.redhat.com/hydra/rest/securitydata/cve/{id}.json``.
Each response includes:

- ``threat_severity`` — Critical / Important / Moderate / Low
- ``package_state``    — list of ``{product_name, package_name, fix_state, ...}``
  entries describing Red Hat's current position per product-package pair.
  ``fix_state`` values seen in the wild:
      "Affected", "New", "Fix deferred"      — will be fixed eventually
      "Will not fix"                          — explicitly declined
      "Out of support scope"                  — product past EOL
      "Not affected"                          — not vulnerable on this product
- ``affected_release`` — list of published advisories (RHSAs) already shipped

A CVE is considered "minor" for our purposes when **every** package_state
that matches our package has ``fix_state`` in ``{"Will not fix",
"Out of support scope", "Not affected"}`` and no advisory has been released.
That matches the intent of Debian's "unimportant" urgency.

Override logic mirrors ``distro_status.py``: if CISA KEV lists the CVE,
or EPSS >= 0.5, or exploit_maturity is "weaponized", we keep it despite
Red Hat's "won't fix" judgment.

Why we do this at all:
  OSV's Red Hat data is derived from the same Red Hat Security Data Manager,
  but OSV's query response merges all products and reports the CVE as
  "affected" if ANY product was ever affected — including products Red Hat
  has since declined to fix. That inflates results the same way raw DST
  inflated results for Debian.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache

log = logging.getLogger(__name__)

_RH_API = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
_TTL = 86400  # 24 hours
_SEM = asyncio.Semaphore(10)

# fix_state values Red Hat uses to say "you shouldn't care about this CVE":
#   "Will not fix"          — acknowledged but explicitly deprioritized
#   "Out of support scope"  — product past EOL
#   "Not affected"          — the CVE doesn't apply here at all
#
# The third case is load-bearing for OSV noise reduction. OSV's Red Hat
# ecosystem returns every historical advisory that ever fixed a CVE in
# this package, without using version ranges to exclude old ones.
# For example querying openssl 3.1.4 returns RHBA-2017:1929 (CVE-2016-7056)
# even though 3.1.4 post-dates 3.0.0 which rewrote the codebase. Red Hat's
# per-CVE package_state lists "Not affected" for modern product tracks in
# those cases, so including "Not affected" in the filter set drops the
# noise correctly.
_MINOR_FIX_STATES = {
    "Will not fix",
    "Out of support scope",
    "Not affected",
}

# Override threshold; see distro_status.MIN_EPSS_OVERRIDE
MIN_EPSS_OVERRIDE = 0.5

# Eco strings that should pass through this filter
_RH_ECOSYSTEMS = ("fedora", "rocky", "almalinux", "centos", "rhel")


async def _fetch_cve(cve_id: str, client: httpx.AsyncClient) -> Optional[dict]:
    """Return parsed Red Hat CVE JSON, or None on miss/failure. Cached."""
    cache_key = f"rhsec:{cve_id}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached or None  # empty dict means negative cache

    try:
        async with _SEM:
            resp = await client.get(
                _RH_API.format(cve=cve_id),
                timeout=10.0,
                follow_redirects=True,
                headers={"User-Agent": "selvo/0.1 (redhat-filter)"},
            )
        if resp.status_code == 404:
            # Not tracked by Red Hat. Cache the negative so we don't re-query.
            _cache.set_cache(cache_key, {}, _TTL)
            return None
        resp.raise_for_status()
        data = resp.json()
        # Trim to only the fields we need before caching
        slim = {
            "threat_severity": data.get("threat_severity", ""),
            "package_state": data.get("package_state", []),
            "affected_release": data.get("affected_release", []),
        }
        _cache.set_cache(cache_key, slim, _TTL)
        return slim
    except Exception as exc:
        log.debug("Red Hat CVE fetch failed for %s: %s", cve_id, exc)
        return None


def _is_minor_for_package(pkg_name: str, rh_data: dict) -> bool:
    """Is this CVE effectively "Red Hat won't fix" for our package?"""
    states = [
        s for s in rh_data.get("package_state", [])
        if s.get("package_name", "") == pkg_name
    ]
    if not states:
        # Red Hat doesn't track our package under this name. Don't filter.
        return False
    # Must have at least one "Will not fix" / "Out of support scope"
    has_minor = any(s.get("fix_state") in _MINOR_FIX_STATES for s in states)
    # Must not have any state indicating active fixing
    any_active = any(
        s.get("fix_state") in {"Affected", "New", "Fix deferred"}
        for s in states
    )
    if any_active:
        return False
    # And no advisory released for our package
    for rel in rh_data.get("affected_release", []):
        if pkg_name in rel.get("package", ""):
            return False  # advisory was issued → real
    return has_minor


def _has_override(pkg: PackageRecord) -> bool:
    """Same override rules as Debian filter — see distro_status._has_override.

    KEV or weaponized only — EPSS alone is not enough. A high EPSS on an
    old CVE reflects attacks on ancient software builds, not the one the
    user has installed today.
    """
    if pkg.in_cisa_kev:
        return True
    if pkg.exploit_maturity == "weaponized":
        return True
    return False


async def filter_redhat_minor_cves(packages: list[PackageRecord]) -> list[PackageRecord]:
    """Drop Red Hat "Will not fix" / "Out of support scope" CVEs unless overridden.

    Must run after enrich_epss and enrich_exploits so override signals are set.
    Updates ``pkg.cve_ids``, increments ``pkg.minor_cve_count``, and recomputes
    ``pkg.max_epss`` for affected packages (same pattern as ``distro_status``).
    """
    rh_pkgs = [
        p for p in packages
        if any(e in p.ecosystem for e in _RH_ECOSYSTEMS)
    ]
    if not rh_pkgs:
        return packages

    # Union of CVEs across Red Hat-family packages
    all_cves = list({cve for p in rh_pkgs for cve in p.cve_ids})
    if not all_cves:
        return packages

    async with httpx.AsyncClient() as client:
        cve_data_list = await asyncio.gather(
            *[_fetch_cve(cve, client) for cve in all_cves],
            return_exceptions=True,
        )
    cve_data: dict[str, dict] = {}
    for cve, data in zip(all_cves, cve_data_list):
        if isinstance(data, dict) and data:
            cve_data[cve] = data

    total_minor = 0
    total_kept_via_override = 0

    for pkg in rh_pkgs:
        kept: list[str] = []
        minor_count = 0
        for cve in pkg.cve_ids:
            rh = cve_data.get(cve)
            if rh is None:
                # No Red Hat info → keep as-is (don't filter)
                kept.append(cve)
                continue
            if _is_minor_for_package(pkg.name, rh):
                if _has_override(pkg):
                    kept.append(cve)
                    total_kept_via_override += 1
                else:
                    minor_count += 1
            else:
                kept.append(cve)

        if minor_count:
            pkg.cve_ids = kept
            pkg.minor_cve_count += minor_count  # accumulate across filters
            total_minor += minor_count

            # Recompute aggregate signals from kept CVEs — same as distro_status
            epss_scores = [
                float(_cache.get(f"epss:{c}") or 0) for c in kept
            ]
            pkg.max_epss = max(epss_scores) if epss_scores else 0.0
            if not kept:
                pkg.exploit_maturity = "none"
                pkg.has_public_exploit = False
                pkg.in_cisa_kev = False
                pkg.exploit_urls = []

            pkg.description = (
                pkg.description
                + f" [{minor_count} Red Hat 'will-not-fix']"
            ).strip()

    if total_minor or total_kept_via_override:
        log.info(
            "Red Hat filter: %d 'will-not-fix' CVEs hidden, %d kept via exploit override",
            total_minor, total_kept_via_override,
        )

    return packages
