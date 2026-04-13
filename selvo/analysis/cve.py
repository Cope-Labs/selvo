"""CVE enrichment via the OSV.dev API."""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

import httpx

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache
from selvo.analysis.debian_index import DebianIndex, load_debian_index

log = logging.getLogger(__name__)

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
_OSV_BATCH_SIZE = 1000  # max queries per batch request
_TTL = 86400  # 24 hours
_SEM = asyncio.Semaphore(8)

# Matches canonical CVE IDs and GitHub Security Advisories.
_CVE_RE = re.compile(r"^(CVE-\d{4}-\d+|GHSA-[0-9a-z-]+)$", re.IGNORECASE)

# Many OSV ecosystems (Debian, Red Hat, …) use distro-specific advisory IDs
# like DEBIAN-CVE-2024-5535, DSA-1234, RHSA-2024:1234. The canonical CVE ID is
# sometimes embedded in the advisory ID itself (DEBIAN-CVE-*) and is always
# available in the `aliases` list of the vuln object.
_DEBIAN_CVE_RE = re.compile(r"^DEBIAN-(CVE-\d{4}-\d+)$", re.IGNORECASE)


def _extract_real_cves(vuln: dict) -> list[str]:
    """Extract canonical CVE/GHSA IDs from an OSV vuln object.

    Checks the primary ``id``, ``aliases`` list, and ``upstream`` list so
    that distro-wrapped advisories (DEBIAN-CVE-*, DSA-*, RHSA-*, RHBA-*, …)
    still contribute their underlying CVE IDs.

    Red Hat OSV entries have empty ``aliases`` and instead list the real
    CVE IDs under ``upstream`` — without reading that field we'd miss
    every RHSA/RHBA. Same check applies to a few other ecosystems.
    """
    ids: list[str] = []
    primary = vuln.get("id", "")
    if _CVE_RE.match(primary):
        ids.append(primary)
    else:
        # e.g. DEBIAN-CVE-2024-5535  →  CVE-2024-5535
        m = _DEBIAN_CVE_RE.match(primary)
        if m:
            ids.append(m.group(1).upper())
    # Different OSV ecosystems expose CVE IDs under different field names:
    #   aliases  — GHSA/MITRE-standard CVE IDs alongside the primary ID
    #   upstream — used by Red Hat / Fedora to list CVEs an RHSA addresses
    #   related  — used by AlmaLinux (ALSA-*) and some SUSE feeds
    # Missing any one of them silently drops CVE coverage for that ecosystem.
    for field in ("aliases", "upstream", "related"):
        for item in vuln.get(field) or []:
            if _CVE_RE.match(item):
                ids.append(item.upper() if item.upper().startswith("CVE-") else item)
    return ids


# Semaphore limiting concurrent /v1/vulns/{id} detail fetches. These follow
# a batch query and typically run in clusters of 10-200 per scan.
_DETAIL_SEM = asyncio.Semaphore(16)


async def _fetch_vuln_detail(vuln_id: str, client: httpx.AsyncClient) -> Optional[dict]:
    """Fetch the full OSV record for a vuln id.

    The batch endpoint returns only ``{id, modified}`` per vuln. For
    ecosystems whose advisory IDs don't embed the CVE (Red Hat RHSA/RHBA,
    raw GHSA, etc.) we need the full record to read ``upstream`` / ``aliases``
    and derive the canonical CVE ID. Cached for 24h.
    """
    if not vuln_id:
        return None
    cache_key = f"osv-vuln:{vuln_id}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached or None
    try:
        async with _DETAIL_SEM:
            resp = await client.get(
                _OSV_VULN_URL.format(id=vuln_id),
                timeout=10.0,
                follow_redirects=True,
            )
        if resp.status_code == 404:
            _cache.set_cache(cache_key, {}, _TTL)
            return None
        resp.raise_for_status()
        data = resp.json()
        # Trim to only the fields _extract_real_cves needs
        slim = {
            "id": data.get("id", ""),
            "aliases": data.get("aliases", []),
            "upstream": data.get("upstream", []),
            "related": data.get("related", []),
        }
        _cache.set_cache(cache_key, slim, _TTL)
        return slim
    except Exception as exc:
        log.debug("OSV vuln detail fetch failed for %s: %s", vuln_id, exc)
        return None


async def _fetch_cves(
    pkg: PackageRecord,
    client: httpx.AsyncClient,
    deb_index: Optional[DebianIndex] = None,
) -> list[str]:
    """Query OSV.dev for known vulnerabilities affecting a package.

    When a package has been merged across ecosystems (ecosystem field contains
    commas, e.g. "debian,ubuntu,fedora"), we query each distinct OSV ecosystem
    and union the results so packages like openssl/curl/gzip get their CVEs.

    For the Debian ecosystem OSV uses **source** package names (e.g. "bzip2",
    "expat", "glibc") rather than binary package names ("libbz2-1.0",
    "libexpat1", "libc6").  We resolve the name via the DebianIndex before
    querying so CVEs are not missed due to the binary↔source name mismatch.
    """
    # Map selvo/discovery ecosystem names → OSV ecosystem names.
    # OSV supports: Debian, Ubuntu, Red Hat, Alpine, and many language ecosystems.
    # Arch Linux and NixOS have no dedicated OSV ecosystem — their packages track
    # upstream closely but distro-specific advisories are not indexed by OSV.
    # We fall back to querying the "Debian" namespace as a best-effort signal;
    # Debian CVEs tend to cover the same upstream vulnerabilities, but
    # distro-specific patches (e.g. Debian backports that Arch ships upstream)
    # may produce false positives or misses.  A warning is logged so operators
    # know coverage is incomplete for these ecosystems.
    # Map selvo ecosystems to OSV ecosystem identifiers.
    # Arch, NixOS, Homebrew, Chocolatey, Winget don't have native OSV
    # ecosystems — they build from the same upstream source as Debian,
    # so we query the Debian namespace which has the best CVE coverage
    # for those package names.
    ecosystem_map = {
        # Native OSV ecosystems
        "debian": "Debian",
        # OSV's "Ubuntu" data is pinned to historical Ubuntu releases and its
        # version comparator can't match modern versions like
        # "3.0.13-0ubuntu3.9" — it returns 0 vulns for everything current.
        # Querying OSV's Debian ecosystem with the same source name works:
        # Debian's version comparator strips the "-Nubuntu*" suffix and
        # matches the upstream version against vulnerable ranges. Slight
        # over-reporting risk (Ubuntu may have backported a fix Debian
        # hasn't), but vastly better than reporting zero CVEs.
        "ubuntu": "Debian",
        "fedora": "Red Hat",
        "alpine": "Alpine",
        "rocky": "Rocky Linux",
        "almalinux": "AlmaLinux",
        "suse": "SUSE",
        "opensuse": "openSUSE",
        "wolfi": "Wolfi",
        "chainguard": "Chainguard",
        "mageia": "Mageia",
        # No native OSV — query via Debian (same upstream sources)
        "arch": "Debian",
        "nixos": "Debian",
        "homebrew": "Debian",
        "chocolatey": "Debian",
        "winget": "Debian",
    }

    # Resolve unique OSV ecosystems from the (possibly comma-joined) pkg.ecosystem
    parts = [e.strip() for e in pkg.ecosystem.split(",")]

    osv_ecosystems = list(dict.fromkeys(
        ecosystem_map[e] for e in parts if e in ecosystem_map
    ))
    if not osv_ecosystems:
        osv_ecosystems = ["Debian"]  # best-effort fallback (see note above)

    all_ids: list[str] = []
    for osv_eco in osv_ecosystems:
        # For Debian and Ubuntu, OSV indexes by SOURCE package name, not binary.
        # Resolve binary → source (e.g. libbz2-1.0 → bzip2, libc6 → glibc, libssl3 → openssl).
        # If the discovery name is already a source name (e.g. "openssl") the
        # lookup returns it unchanged.
        if osv_eco in {"Debian", "Ubuntu"} and deb_index is not None:
            osv_pkg_name = deb_index.source_name(pkg.name)
        else:
            osv_pkg_name = pkg.name

        cache_key = f"osv:{osv_eco}:{osv_pkg_name}"
        cached = _cache.get(cache_key)
        if cached is not None:
            all_ids.extend(cached)
            continue

        payload: dict = {"package": {"name": osv_pkg_name, "ecosystem": osv_eco}}
        if pkg.version and pkg.version != "unknown":
            payload["version"] = pkg.version
        else:
            log.warning("CVE lookup for %s has no version — results may include false positives", pkg.name)

        try:
            async with _SEM:
                resp = await client.post(_OSV_QUERY_URL, json=payload, timeout=10.0)
                resp.raise_for_status()
            data = resp.json()
            ids: list[str] = []
            for vuln in data.get("vulns", []):
                ids.extend(_extract_real_cves(vuln))
            # Deduplicate within this ecosystem before caching
            ids = list(dict.fromkeys(ids))
            _cache.set_cache(cache_key, ids, _TTL)
            all_ids.extend(ids)
        except Exception as exc:
            log.warning("CVE fetch failed for %s/%s: %s", osv_eco, osv_pkg_name, exc)

    # Deduplicate preserving order
    seen: set[str] = set()
    result = []
    for vid in all_ids:
        if vid not in seen:
            seen.add(vid)
            result.append(vid)
    return result


# Ecosystems whose dpkg/apt binary names need translating to a source name
# before querying OSV. Ubuntu is downstream of Debian and uses the same
# source-package naming, so the same Debian index applies.
_DEB_FAMILY = {"debian", "ubuntu"}


def _osv_pkg_name(pkg_name: str, primary_eco: str, deb_index: Optional[DebianIndex]) -> str:
    """Return the canonical OSV package name for *pkg_name*.

    Debian/Ubuntu OSV ecosystems index by source-package name, so we
    translate binary names (e.g. ``libssl3``) to source names (``openssl``)
    via the Debian package index. Other ecosystems pass through unchanged.
    """
    if primary_eco in _DEB_FAMILY and deb_index is not None:
        return deb_index.source_name(pkg_name)
    return pkg_name


async def enrich_cve(packages: list[PackageRecord]) -> list[PackageRecord]:
    """Annotate each PackageRecord with CVE IDs from OSV.dev.

    Loads the Debian package index first so CVE queries for Debian/Ubuntu
    packages can translate binary package names to source package names
    (as required by the OSV Debian and Ubuntu ecosystems).

    Packages that share a source (e.g. libuuid1 and libblkid1 both come
    from util-linux) are grouped so OSV is queried only once per
    (ecosystem, source) combination.  Without this deduplication, concurrent
    asyncio.gather tasks would race to write the same cache key.
    """
    from collections import defaultdict

    deb_index = await load_debian_index()

    # Group packages by their canonical OSV lookup name to avoid duplicate
    # concurrent requests for binaries that share a source package.
    group_key_to_pkgs: dict[tuple[str, str], list[PackageRecord]] = defaultdict(list)
    for pkg in packages:
        primary_eco = pkg.ecosystem.split(",")[0].strip()
        src = _osv_pkg_name(pkg.name, primary_eco, deb_index)
        group_key_to_pkgs[(primary_eco, src)].append(pkg)

    # One representative per unique (ecosystem, source) key
    representatives = [group[0] for group in group_key_to_pkgs.values()]

    # Separate cached vs uncached lookups
    cached_results: dict[int, list[str]] = {}  # rep index → cve_ids
    uncached: list[tuple[int, PackageRecord]] = []  # (rep index, rep pkg)

    for i, rep in enumerate(representatives):
        primary_eco = rep.ecosystem.split(",")[0].strip()
        eco_map = _resolve_ecosystem(primary_eco)
        osv_name = _osv_pkg_name(rep.name, primary_eco, deb_index)
        cache_key = f"osv:{eco_map}:{osv_name}"
        cached = _cache.get(cache_key)
        if cached is not None:
            cached_results[i] = cached
        else:
            uncached.append((i, rep))

    log.info("CVE lookup: %d cached, %d to fetch via batch", len(cached_results), len(uncached))

    # Batch query uncached packages via /v1/querybatch
    uncached_results: dict[int, list[str]] = {}
    if uncached:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Build batch payloads
            for batch_start in range(0, len(uncached), _OSV_BATCH_SIZE):
                batch = uncached[batch_start:batch_start + _OSV_BATCH_SIZE]
                queries = []
                for idx, rep in batch:
                    primary_eco = rep.ecosystem.split(",")[0].strip()
                    eco_map = _resolve_ecosystem(primary_eco)
                    osv_name = _osv_pkg_name(rep.name, primary_eco, deb_index)
                    q: dict = {"package": {"name": osv_name, "ecosystem": eco_map}}
                    if rep.version and rep.version != "unknown":
                        q["version"] = rep.version
                    queries.append(q)

                try:
                    resp = await client.post(_OSV_BATCH_URL, json={"queries": queries}, timeout=30.0)
                    resp.raise_for_status()
                    batch_data = resp.json()

                    # The batch endpoint returns a minimal view of each vuln:
                    # just {id, modified}. For ecosystems whose advisory IDs
                    # embed the CVE (like DEBIAN-CVE-2024-X) the regex in
                    # _extract_real_cves still works. For ecosystems that don't
                    # (Red Hat RHSA-YYYY:NNNN, GHSA-*, etc.) we have to fetch
                    # the full vuln record via /v1/vulns/{id}. Collect those
                    # IDs across the whole batch and fetch them concurrently.
                    pending_vuln_ids: set[str] = set()
                    batch_vuln_lists: list[list[dict]] = []
                    for result in batch_data.get("results", []):
                        vulns = result.get("vulns", []) or []
                        batch_vuln_lists.append(vulns)
                        for v in vulns:
                            if not _extract_real_cves(v):  # no CVE in minimal view
                                pending_vuln_ids.add(v.get("id", ""))
                    pending_vuln_ids.discard("")

                    vuln_detail_cache: dict[str, dict] = {}
                    if pending_vuln_ids:
                        detail_tasks = [
                            _fetch_vuln_detail(vid, client) for vid in pending_vuln_ids
                        ]
                        detail_results = await asyncio.gather(*detail_tasks, return_exceptions=True)
                        for vid, detail in zip(pending_vuln_ids, detail_results):
                            if isinstance(detail, dict):
                                vuln_detail_cache[vid] = detail

                    for j, result in enumerate(batch_data.get("results", [])):
                        idx = batch[j][0]
                        rep = batch[j][1]
                        ids: list[str] = []
                        for vuln in batch_vuln_lists[j]:
                            cves = _extract_real_cves(vuln)
                            if not cves:
                                # Resolve via the follow-up detail we fetched
                                detail = vuln_detail_cache.get(vuln.get("id", ""))
                                if detail is not None:
                                    cves = _extract_real_cves(detail)
                            ids.extend(cves)
                        ids = list(dict.fromkeys(ids))
                        uncached_results[idx] = ids
                        # Cache individual results
                        primary_eco = rep.ecosystem.split(",")[0].strip()
                        eco_map = _resolve_ecosystem(primary_eco)
                        osv_name = _osv_pkg_name(rep.name, primary_eco, deb_index)
                        _cache.set_cache(f"osv:{eco_map}:{osv_name}", ids, _TTL)
                except Exception as exc:
                    log.warning("OSV batch query failed: %s", exc)
                    # Fall back to empty for this batch
                    for idx, _ in batch:
                        uncached_results.setdefault(idx, [])

    # Merge cached + uncached results
    all_results = {**cached_results, **uncached_results}

    # Distribute CVE lists back to every package in each source group
    for i, rep in enumerate(representatives):
        cve_ids = all_results.get(i, [])
        primary_eco = rep.ecosystem.split(",")[0].strip()
        src = _osv_pkg_name(rep.name, primary_eco, deb_index)
        for pkg in group_key_to_pkgs[(primary_eco, src)]:
            pkg.cve_ids = list(cve_ids)

    return packages


def _resolve_ecosystem(primary_eco: str) -> str:
    """Map a selvo ecosystem name to an OSV ecosystem identifier.

    Ubuntu maps to "Debian" because OSV's Ubuntu data is historical-only
    and its version comparator does not match current Ubuntu versions.
    See ``_fetch_cves`` ecosystem_map for the full rationale.
    """
    eco_map = {
        # Linux distros
        "debian": "Debian", "ubuntu": "Debian", "fedora": "Red Hat",
        "alpine": "Alpine", "rocky": "Rocky Linux", "almalinux": "AlmaLinux",
        "suse": "SUSE", "opensuse": "openSUSE", "wolfi": "Wolfi",
        "chainguard": "Chainguard", "mageia": "Mageia",
        # Distros without native OSV — Debian upstream is the closest proxy
        "arch": "Debian", "nixos": "Debian", "homebrew": "Debian",
        "chocolatey": "Debian", "winget": "Debian",
        # Language ecosystems — OSV has native coverage, exact name matching
        # matters. Without these mappings a Python/Cargo/npm scan would silently
        # fall through to the "Debian" default and return almost nothing.
        "pypi": "PyPI", "python": "PyPI",
        "npm": "npm", "node": "npm",
        "cargo": "crates.io", "rust": "crates.io", "crates.io": "crates.io",
        "go": "Go", "golang": "Go",
        "rubygems": "RubyGems", "gem": "RubyGems", "ruby": "RubyGems",
        "packagist": "Packagist", "composer": "Packagist", "php": "Packagist",
        "maven": "Maven", "java": "Maven",
        "nuget": "NuGet", "dotnet": "NuGet",
        "pub": "Pub", "dart": "Pub",
        "hex": "Hex", "erlang": "Hex", "elixir": "Hex",
        "swift": "SwiftURL",
        "cocoapods": "CocoaPods",
        "conan": "ConanCenter",
        "hackage": "Hackage", "haskell": "Hackage",
        "pkgsrc": "pkgsrc",
        "bioconductor": "Bioconductor",
        "cran": "CRAN", "r": "CRAN",
    }
    return eco_map.get(primary_eco.lower(), "Debian")
