"""Enrich PackageRecords with transitive dependency-graph metrics.

Wraps ``graph.builder.compute_graph_metrics()`` and attaches the results so
the scorer can use true blast-radius and chokepoint signals instead of the
blunt Repology repo-count proxy.
"""
from __future__ import annotations

import logging

from selvo.discovery.base import PackageRecord

log = logging.getLogger(__name__)


async def enrich_graph_metrics(
    packages: list[PackageRecord],
    ecosystem: str = "debian",
) -> list[PackageRecord]:
    """Compute and attach ``transitive_rdep_count`` and ``betweenness``.

    Builds the real dependency graph from the Debian ``Packages.gz`` index
    (cached 24 h).  Falls back gracefully — leaves values at 0 — if the
    download or graph computation fails.
    """
    from selvo.graph.builder import compute_graph_metrics

    names = [p.name for p in packages]
    try:
        metrics = await compute_graph_metrics(names, ecosystem=ecosystem, depth=3)
    except Exception as exc:
        log.warning("Graph metrics computation failed: %s", exc)
        return packages

    for pkg in packages:
        m = metrics.get(pkg.name)
        if m:
            pkg.transitive_rdep_count = int(m["transitive_rdep_count"])
            pkg.betweenness = float(m["betweenness"])

    n_enriched = sum(1 for p in packages if p.transitive_rdep_count > 0)
    log.info(
        "Graph metrics: %d/%d packages enriched with transitive dep data",
        n_enriched,
        len(packages),
    )
    return packages
