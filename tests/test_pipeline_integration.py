"""Integration tests — full analysis pipeline wiring (no network I/O).

All external calls (HTTP, disk cache, Debian index download) are replaced
with lightweight stubs so the suite runs in milliseconds.

What these tests catch that unit tests cannot:
  - An import error in any enricher breaking the whole pipeline
  - Wiring order bugs (e.g. CVE data not reaching the scorer because an
    enricher inadvertently returns a fresh list instead of mutating in place)
  - Score ordering regressions: critical > moderate > clean must always hold
  - Runtime-loaded boost being applied (or silently dropped)
  - cve_count and is_outdated computed properties working end-to-end
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


from selvo.discovery.base import PackageRecord
from selvo.prioritizer.scorer import score_and_rank


# ---------------------------------------------------------------------------
# Test fixtures — three packages with known risk profiles
# ---------------------------------------------------------------------------

def _pkg(name: str, **kw) -> PackageRecord:
    defaults = dict(
        ecosystem="debian",
        version="1.0.0",
        upstream_version="1.0.0",
        download_count=0,
        reverse_dep_count=0,
        cve_ids=[],
        max_cvss=0.0,
        max_epss=0.0,
        exploit_maturity="none",
        in_cisa_kev=False,
        transitive_rdep_count=0,
        betweenness=0.0,
        score=0.0,
        sla_band="",
        sla_days_overdue=0,
    )
    defaults.update(kw)
    return PackageRecord(name=name, **defaults)


_CRITICAL = _pkg(
    "critical-lib",
    cve_ids=["CVE-2024-9999"],
    max_cvss=9.8,
    max_epss=0.94,
    exploit_maturity="weaponized",
    in_cisa_kev=True,
    transitive_rdep_count=50_000,
    reverse_dep_count=1_500,
    betweenness=0.85,
    upstream_version="2.0.0",
)
_MODERATE = _pkg(
    "moderate-lib",
    cve_ids=["CVE-2024-1111"],
    max_cvss=6.5,
    max_epss=0.12,
    upstream_version="1.5.0",
    reverse_dep_count=200,
)
_CLEAN = _pkg("clean-lib")

_PACKAGES = [_CRITICAL, _MODERATE, _CLEAN]


# ---------------------------------------------------------------------------
# Passthrough stubs — each enricher gets one that fits its call signature
# ---------------------------------------------------------------------------

async def _pass_async(packages, *_a, **_kw):
    return packages


def _pass_sync(packages, *_a, **_kw):
    return packages


async def _pass_async_top_n(ranked, top_n=5, **_kw):
    return ranked


# ---------------------------------------------------------------------------
# Context manager: patch every network-bound enricher at once
# ---------------------------------------------------------------------------

def _all_enricher_patches(discovery_packages: list[PackageRecord]):
    """Return a list of patch context managers that cover every external call
    made by ``_run_pipeline``.  Let ``score_and_rank`` execute for real so
    scoring regressions are caught."""
    mock_deb_idx = MagicMock()
    mock_deb_idx.source_name = lambda name: name  # identity — no translation

    return [
        patch("selvo.discovery.run_discovery", return_value=list(discovery_packages)),
        patch("selvo.analysis.cache.load_last_snapshot", return_value=None),
        patch("selvo.analysis.cache.save_snapshot"),
        patch(
            "selvo.analysis.debian_index.load_debian_index",
            new_callable=AsyncMock,
            return_value=mock_deb_idx,
        ),
        patch("selvo.analysis.versions.enrich_versions", side_effect=_pass_async),
        patch("selvo.analysis.cve.enrich_cve", side_effect=_pass_async),
        patch("selvo.analysis.distro_status.filter_resolved_cves", side_effect=_pass_async),
        patch("selvo.analysis.epss.enrich_epss", side_effect=_pass_async),
        patch("selvo.analysis.epss.enrich_epss_velocity", side_effect=_pass_sync),
        patch("selvo.analysis.cvss.enrich_cvss", side_effect=_pass_async),
        patch("selvo.analysis.rdeps.enrich_reverse_deps", side_effect=_pass_async),
        patch(
            "selvo.analysis.collapse.collapse_by_source",
            side_effect=lambda pkgs, _idx: pkgs,
        ),
        patch("selvo.analysis.graph_metrics.enrich_graph_metrics", side_effect=_pass_async),
        patch("selvo.analysis.upstream.enrich_upstream_repos", side_effect=_pass_async),
        patch("selvo.analysis.distro_compare.enrich_distro_versions", side_effect=_pass_async),
        patch("selvo.analysis.patch_safety.enrich_patch_safety", side_effect=_pass_sync),
        patch("selvo.analysis.exploit.enrich_exploits", side_effect=_pass_async),
        patch("selvo.analysis.cve_timeline.enrich_cve_timeline", side_effect=_pass_async),
        patch("selvo.analysis.distro_tracker.enrich_distro_patch_dates", side_effect=_pass_async),
        patch("selvo.analysis.ossfuzz.enrich_ossfuzz", side_effect=_pass_async),
        patch("selvo.analysis.advisories.enrich_advisories", side_effect=_pass_async),
        patch("selvo.analysis.sla.enrich_sla", side_effect=_pass_sync),
        patch(
            "selvo.analysis.changelog.enrich_changelog_summaries",
            side_effect=_pass_async_top_n,
        ),
    ]


def _run_pipeline_sync(**kwargs):
    """Run _run_pipeline in a fresh event loop (avoids test isolation issues)."""
    from selvo.mcp_server import _run_pipeline
    return asyncio.run(_run_pipeline(**kwargs))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestPipelineOrdering:
    """Critical packages must rank above moderate, which ranks above clean."""

    def test_smoke_completes(self):
        """Pipeline runs to completion without raising and returns all packages."""
        with _exit_stack(_all_enricher_patches(_PACKAGES)):
            result = _run_pipeline_sync(ecosystem="debian", limit=3, run_cve=True)
        assert len(result) == 3

    def test_critical_ranks_first(self):
        with _exit_stack(_all_enricher_patches(_PACKAGES)):
            result = _run_pipeline_sync(ecosystem="debian", limit=3, run_cve=True)
        assert result[0].name == "critical-lib"

    def test_clean_ranks_last(self):
        with _exit_stack(_all_enricher_patches(_PACKAGES)):
            result = _run_pipeline_sync(ecosystem="debian", limit=3, run_cve=True)
        assert result[-1].name == "clean-lib"

    def test_scores_are_positive(self):
        with _exit_stack(_all_enricher_patches(_PACKAGES)):
            result = _run_pipeline_sync(ecosystem="debian", limit=3, run_cve=True)
        for pkg in result:
            assert pkg.score >= 0.0, f"{pkg.name} has negative score {pkg.score}"

    def test_critical_score_exceeds_clean(self):
        with _exit_stack(_all_enricher_patches(_PACKAGES)):
            result = _run_pipeline_sync(ecosystem="debian", limit=3, run_cve=True)
        by_name = {p.name: p for p in result}
        assert by_name["critical-lib"].score > by_name["clean-lib"].score * 3


class TestScorerDataFlow:
    """Verify CVE and EPSS data on packages reaches score_and_rank correctly."""

    def test_cve_count_property(self):
        pkg = _pkg("foo", cve_ids=["CVE-2024-0001", "CVE-2024-0002"])
        assert pkg.cve_count == 2

    def test_is_outdated_property(self):
        current = _pkg("foo", version="1.0.0", upstream_version="2.0.0")
        up_to_date = _pkg("bar", version="2.0.0", upstream_version="2.0.0")
        assert current.is_outdated is True
        assert up_to_date.is_outdated is False

    def test_score_and_rank_ordering(self):
        """score_and_rank alone (no pipeline) maintains critical > moderate > clean."""
        pkgs = [_CLEAN.__class__(**vars(_CLEAN)),
                _MODERATE.__class__(**vars(_MODERATE)),
                _CRITICAL.__class__(**vars(_CRITICAL))]
        ranked = score_and_rank(pkgs)
        assert ranked[0].name == "critical-lib"
        assert ranked[-1].name == "clean-lib"

    def test_runtime_boost_raises_score(self):
        """A package confirmed loaded in memory must score higher than unloaded."""
        base = _pkg("libfoo", cve_ids=["CVE-2024-1234"], max_cvss=7.0, max_epss=0.5)
        loaded = _pkg("libfoo", cve_ids=["CVE-2024-1234"], max_cvss=7.0, max_epss=0.5,
                      runtime_loaded=True)
        ranked_base = score_and_rank([base])
        ranked_loaded = score_and_rank([loaded])
        assert ranked_loaded[0].score > ranked_base[0].score

    def test_kev_package_outranks_high_cvss_no_kev(self):
        """CISA KEV listing should push a package above a higher-CVSS non-KEV package."""
        kev = _pkg("kev-pkg", cve_ids=["CVE-2024-A"], max_cvss=7.0, max_epss=0.5,
                   in_cisa_kev=True, exploit_maturity="weaponized")
        high_cvss = _pkg("cvss-pkg", cve_ids=["CVE-2024-B"], max_cvss=9.9, max_epss=0.05)
        ranked = score_and_rank([high_cvss, kev])
        assert ranked[0].name == "kev-pkg"

    def test_no_signal_package_scores_zero_or_near(self):
        """A package with no CVEs, no EPSS, and no rdeps should score near zero."""
        pkg = _pkg("silent-lib")
        ranked = score_and_rank([pkg])
        assert ranked[0].score < 5.0


class TestPipelineNoCve:
    """run_cve=False must skip all CVE-related enrichers and still return results."""

    def test_no_cve_pipeline_completes(self):
        with _exit_stack(_all_enricher_patches(_PACKAGES)):
            result = _run_pipeline_sync(ecosystem="debian", limit=3, run_cve=False)
        assert len(result) == 3

    def test_no_cve_pipeline_no_cve_ids(self):
        """Packages should have whatever cve_ids were on the fixture (empty for clean)."""
        with _exit_stack(_all_enricher_patches(_PACKAGES)):
            result = _run_pipeline_sync(ecosystem="debian", limit=3, run_cve=False)
        by_name = {p.name: p for p in result}
        assert by_name["clean-lib"].cve_ids == []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _exit_stack:
    """Minimal context manager that enters a list of patch context managers."""

    def __init__(self, patches):
        self._patches = patches
        self._active = []

    def __enter__(self):
        for p in self._patches:
            self._active.append(p.__enter__())
        return self

    def __exit__(self, *exc):
        for p, active in zip(reversed(self._patches), reversed(self._active)):
            p.__exit__(*exc)
