"""Collapse binary-package duplicates into a single source-package record.

Debian ships one *source* package (e.g. ``util-linux``) that produces many
*binary* packages (``libuuid1``, ``libblkid1``, ``mount``, ``bsdutils``, …).
Discovery emits individual binary names because those are what end-users
install, but several of them typically appear in the top-N list and
carry **identical CVEs** from the same source.

This module merges every group of binaries that share a Debian source name
into a single :class:`~selvo.discovery.base.PackageRecord` named after the
source.  Single-binary sources pass through unchanged.

After collapsing, callers should re-run ``enrich_graph_metrics`` so that
``transitive_rdep_count`` is computed from *all* binaries of the source
simultaneously (true union blast-radius) instead of the per-binary maximum
used as a temporary placeholder during the merge.
"""
from __future__ import annotations

import logging
from collections import defaultdict

from selvo.discovery.base import PackageRecord
from selvo.analysis.debian_index import DebianIndex

log = logging.getLogger(__name__)


def _merge_group(source_name: str, group: list[PackageRecord]) -> PackageRecord:
    """Merge a list of co-source PackageRecords into one record.

    Strategy:
    - ``name``      → source package name
    - ``ecosystem`` → sorted union of all ecosystems
    - ``version``   → first non-unknown installed version in the group
    - ``upstream_version`` → first non-None upstream version
    - ``cve_ids``   → deduplicated union (order-preserving)
    - ``max_epss``/``max_cvss`` → maximum across group
    - ``transitive_rdep_count`` → maximum (placeholder; re-computed post-collapse)
    - ``betweenness`` → maximum
    - ``reverse_dep_count`` → maximum
    - ``download_count`` → sum (additive popularity)
    - ``upstream_repo``/``description`` → first non-empty/non-None
    """
    # Union CVEs (preserving order, deduplicating)
    seen_cves: set[str] = set()
    all_cves: list[str] = []
    for pkg in group:
        for cve in pkg.cve_ids:
            if cve not in seen_cves:
                seen_cves.add(cve)
                all_cves.append(cve)

    # First non-unknown version
    version = next(
        (p.version for p in group if p.version and p.version not in ("unknown", "")),
        "unknown",
    )
    upstream_version = next(
        (p.upstream_version for p in group if p.upstream_version), None
    )

    # Sorted union of ecosystems
    eco_parts: list[str] = list(dict.fromkeys(
        e.strip()
        for p in group
        for e in p.ecosystem.split(",")
        if e.strip()
    ))

    upstream_repo = next((p.upstream_repo for p in group if p.upstream_repo), None)
    description = next((p.description for p in group if p.description), "")

    return PackageRecord(
        name=source_name,
        ecosystem=",".join(eco_parts),
        version=version,
        upstream_version=upstream_version,
        description=description,
        upstream_repo=upstream_repo,
        download_count=sum(p.download_count for p in group),
        reverse_dep_count=max(p.reverse_dep_count for p in group),
        cve_ids=all_cves,
        max_cvss=max(p.max_cvss for p in group),
        max_epss=max(p.max_epss for p in group),
        # Placeholder: will be replaced by a post-collapse compute_graph_metrics call
        # that starts the BFS from ALL binaries of this source simultaneously.
        transitive_rdep_count=max(p.transitive_rdep_count for p in group),
        betweenness=max(p.betweenness for p in group),
    )


def collapse_by_source(
    packages: list[PackageRecord],
    deb_index: DebianIndex,
) -> list[PackageRecord]:
    """Return a deduplicated package list where Debian source siblings are merged.

    For each group of packages that share the same Debian source name, a single
    merged record is emitted under the source name.  Non-Debian packages and
    packages whose source cannot be determined are passed through unchanged.

    Example:
        libuuid1 + libblkid1 + util-linux + mount + bsdutils + login
        → one record named ``util-linux``
    """
    # Partition into Debian-primary (collapsible) and others (pass-through)
    deb_groups: dict[str, list[PackageRecord]] = defaultdict(list)
    passthrough: list[PackageRecord] = []

    for pkg in packages:
        primary_eco = pkg.ecosystem.split(",")[0].strip()
        if primary_eco == "debian":
            src = deb_index.source_name(pkg.name)
            deb_groups[src].append(pkg)
        else:
            passthrough.append(pkg)

    result: list[PackageRecord] = list(passthrough)
    merged_count = 0

    for src_name, group in deb_groups.items():
        if len(group) == 1:
            result.append(group[0])
        else:
            merged = _merge_group(src_name, group)
            result.append(merged)
            merged_count += 1
            log.info(
                "Collapsed %d binaries of source '%s' into one record "
                "(%d CVEs, trdeps≥%d)",
                len(group),
                src_name,
                len(merged.cve_ids),
                merged.transitive_rdep_count,
            )

    if merged_count:
        log.info(
            "Source collapse: %d binary records → %d unique sources (%d groups merged)",
            len(packages),
            len(result),
            merged_count,
        )

    return result
