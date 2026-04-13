"""
Vendor advisory feed enrichment — surface CVEs from distro security advisories
before they reach NVD/OSV, and tag packages with advisory IDs.

Sources (all are public, no auth required):
  Ubuntu  — USN RSS feed: https://ubuntu.com/security/notices/rss.xml
             JSON API:    https://ubuntu.com/security/notices.json?limit=100
  Fedora  — Bodhi updates API: https://bodhi.fedoraproject.org/updates/?type=security&status=stable
  RHEL    — RHSA advisory index: https://access.redhat.com/labs/securitydataapi/cve.json?after=DATE

Each source may reveal CVEs that are not yet in the packages' cve_ids (OSV may
lag by 1–7 days). This enricher only *tags* packages with advisory IDs and
updates cve_ids with any newly discovered CVEs.

Result fields on PackageRecord:
  vendor_advisory_ids   list[str]   e.g. ["USN-6954-1", "FEDORA-2024-abcdef"]
"""
from __future__ import annotations

import asyncio
import logging

import httpx

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache

log = logging.getLogger(__name__)

_USN_API = "https://ubuntu.com/security/notices.json"
_BODHI_API = "https://bodhi.fedoraproject.org/updates/"
_TTL = 3600  # 1 hour — advisories are time-sensitive


# ── Ubuntu USN ────────────────────────────────────────────────────────────────

async def _fetch_usn_index(client: httpx.AsyncClient) -> list[dict]:
    """Return recent Ubuntu Security Notices."""
    cached = _cache.get("advisories:usn")
    if cached:
        import json
        return json.loads(cached)

    try:
        resp = await client.get(
            _USN_API,
            params={"limit": 200, "offset": 0},
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": "selvo/0.1 (advisory-enricher)"},
        )
        if resp.status_code == 200:
            data = resp.json()
            notices = data.get("notices", data) if isinstance(data, dict) else data
            if isinstance(notices, list):
                import json
                _cache.set_cache("advisories:usn", json.dumps(notices[:200]), _TTL)
                return notices[:200]
    except Exception as exc:
        log.debug("USN fetch error: %s", exc)
    return []


async def _fetch_bodhi_security(client: httpx.AsyncClient) -> list[dict]:
    """Return recent Fedora security updates from Bodhi."""
    cached = _cache.get("advisories:bodhi")
    if cached:
        import json
        return json.loads(cached)

    try:
        resp = await client.get(
            _BODHI_API,
            params={"type": "security", "status": "stable", "rows_per_page": 100},
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": "selvo/0.1 (advisory-enricher)", "Accept": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            updates = data.get("updates", [])
            import json
            _cache.set_cache("advisories:bodhi", json.dumps(updates[:100]), _TTL)
            return updates[:100]
    except Exception as exc:
        log.debug("Bodhi fetch error: %s", exc)
    return []


# ── Matchers ──────────────────────────────────────────────────────────────────

def _usn_tag_packages(
    usn_notices: list[dict],
    pkg_map: dict[str, PackageRecord],
) -> None:
    """
    Match USN notices to packages by package name and attach advisory IDs + CVEs.

    USN JSON structure (ubuntu.com/security/notices.json):
      [{id, title, summary, cves: [{cve, ...}], packages: [{name, ...}]}, ...]
    """
    for notice in usn_notices:
        notice_id = notice.get("id", "")
        # Collect CVE IDs from this notice
        cve_ids = [
            c.get("cve", c) if isinstance(c, dict) else str(c)
            for c in notice.get("cves", [])
        ]
        cve_ids = [c for c in cve_ids if c.startswith("CVE-")]

        # Collect affected package names
        pkg_entries = notice.get("packages", [])
        affected_names: list[str] = []
        for entry in pkg_entries:
            if isinstance(entry, dict):
                affected_names.append(entry.get("name", ""))
            elif isinstance(entry, str):
                affected_names.append(entry)

        for pkg_name in affected_names:
            pkg = pkg_map.get(pkg_name.lower())
            if pkg:
                if notice_id and notice_id not in pkg.vendor_advisory_ids:
                    pkg.vendor_advisory_ids.append(notice_id)
                for cve in cve_ids:
                    if cve not in pkg.cve_ids:
                        pkg.cve_ids.append(cve)


def _bodhi_tag_packages(
    updates: list[dict],
    pkg_map: dict[str, PackageRecord],
) -> None:
    """
    Match Fedora/Bodhi security updates to packages.

    Bodhi update structure:
      [{alias: "FEDORA-2024-...", builds: [{nvr: "pkg-ver-rel.arch"}], cves: [...]}]
    """
    for update in updates:
        alias = update.get("alias", "")
        builds = update.get("builds", [])
        cve_ids = [
            c.get("cve_id", "") if isinstance(c, dict) else str(c)
            for c in update.get("cves", [])
        ]
        cve_ids = [c for c in cve_ids if c.startswith("CVE-")]

        for build in builds:
            # NVR format: package-version-release.arch → strip after first '-version'
            nvr = build.get("nvr", "") if isinstance(build, dict) else str(build)
            pkg_name = nvr.split("-")[0].lower() if nvr else ""
            pkg = pkg_map.get(pkg_name)
            if pkg:
                if alias and alias not in pkg.vendor_advisory_ids:
                    pkg.vendor_advisory_ids.append(alias)
                for cve in cve_ids:
                    if cve not in pkg.cve_ids:
                        pkg.cve_ids.append(cve)


# ── Main enrichment ───────────────────────────────────────────────────────────

async def enrich_advisories(packages: list[PackageRecord]) -> list[PackageRecord]:
    """
    Fetch and match vendor advisories (USN, Bodhi/Fedora) against packages.

    Tags each matched package with advisory IDs and any newly discovered CVEs.
    """
    if not packages:
        return packages

    pkg_map = {p.name.lower(): p for p in packages}

    async with httpx.AsyncClient() as client:
        usn_notices, bodhi_updates = await asyncio.gather(
            _fetch_usn_index(client),
            _fetch_bodhi_security(client),
            return_exceptions=True,
        )

    if isinstance(usn_notices, list):
        _usn_tag_packages(usn_notices, pkg_map)
    if isinstance(bodhi_updates, list):
        _bodhi_tag_packages(bodhi_updates, pkg_map)

    tagged = sum(1 for p in packages if p.vendor_advisory_ids)
    log.debug("Advisory enrichment: %d packages tagged with vendor advisories", tagged)
    return packages
