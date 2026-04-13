"""Shared pytest fixtures for selvo tests."""
from __future__ import annotations

import pytest

from selvo.discovery.base import PackageRecord


def make_pkg(**kwargs) -> PackageRecord:
    """Convenience factory — sane defaults, override with kwargs."""
    defaults = dict(
        name="testpkg",
        ecosystem="debian",
        version="1.0.0",
        upstream_version=None,
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
    defaults.update(kwargs)
    return PackageRecord(**defaults)


@pytest.fixture
def clean_pkg() -> PackageRecord:
    """A package with no security signal."""
    return make_pkg(name="bash", version="5.1.0", upstream_version="5.1.0")


@pytest.fixture
def cve_pkg() -> PackageRecord:
    """A package with a medium-severity CVE."""
    return make_pkg(
        name="libssl3",
        version="3.0.0",
        upstream_version="3.0.14",
        cve_ids=["CVE-2024-0001"],
        max_cvss=7.5,
        max_epss=0.08,
    )


@pytest.fixture
def critical_pkg() -> PackageRecord:
    """A critical package: KEV, weaponized, high CVSS, many rdeps."""
    return make_pkg(
        name="openssl",
        version="1.1.1",
        upstream_version="3.3.0",
        cve_ids=["CVE-2024-9999"],
        max_cvss=9.8,
        max_epss=0.94,
        exploit_maturity="weaponized",
        in_cisa_kev=True,
        transitive_rdep_count=50_000,
        reverse_dep_count=1500,
        betweenness=0.85,
        download_count=100_000,
    )
