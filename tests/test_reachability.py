"""Tests for selvo.analysis.reachability."""
from __future__ import annotations

import pytest

from selvo.analysis.reachability import (
    _apply_reachability,
    _apply_python_reachability,
    _mark_unknown,
    _detect_backend,
    apply_reachability_score_discount,
)
from tests.conftest import make_pkg


def test_apply_reachability_marks_reachable():
    pkg = make_pkg(name="openssl", cve_ids=["CVE-2024-0001", "CVE-2024-0002"])
    _apply_reachability([pkg], {"CVE-2024-0001"}, source="govulncheck")
    assert pkg.reachable is True
    assert "CVE-2024-0001" in pkg.reachable_cves
    assert "CVE-2024-0002" in pkg.unreachable_cves
    assert pkg.reachability_source == "govulncheck"


def test_apply_reachability_all_unreachable():
    pkg = make_pkg(name="curl", cve_ids=["CVE-X", "CVE-Y"])
    _apply_reachability([pkg], set(), source="govulncheck")
    assert pkg.reachable is False
    assert pkg.reachable_cves == []
    assert set(pkg.unreachable_cves) == {"CVE-X", "CVE-Y"}


def test_apply_reachability_case_insensitive():
    pkg = make_pkg(name="libssl", cve_ids=["cve-2024-0001"])
    _apply_reachability([pkg], {"CVE-2024-0001"}, source="govulncheck")
    assert pkg.reachable is True


def test_apply_python_reachability_by_package_name():
    pkg = make_pkg(name="requests", ecosystem="python", cve_ids=["CVE-R"])
    _apply_python_reachability([pkg], {"requests", "flask"})
    assert pkg.reachable is True
    assert pkg.reachable_cves == ["CVE-R"]


def test_apply_python_reachability_not_imported():
    pkg = make_pkg(name="paramiko", ecosystem="python", cve_ids=["CVE-P"])
    _apply_python_reachability([pkg], {"flask", "requests"})
    assert pkg.reachable is False
    assert pkg.unreachable_cves == ["CVE-P"]


def test_apply_python_reachability_normalises_dashes():
    pkg = make_pkg(name="python-dateutil", ecosystem="python", cve_ids=["CVE-D"])
    _apply_python_reachability([pkg], {"python_dateutil"})
    assert pkg.reachable is True


def test_mark_unknown():
    pkg = make_pkg(name="x")
    _mark_unknown([pkg])
    assert pkg.reachability_source == "unknown"


def test_detect_backend_go(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/myapp\ngo 1.21\n")
    assert _detect_backend(tmp_path, "auto") == "go"


def test_detect_backend_python(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='myapp'\n")
    assert _detect_backend(tmp_path, "auto") == "python"


def test_detect_backend_hint_overrides(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n")
    assert _detect_backend(tmp_path, "python") == "python"


def test_score_discount_applied_to_unreachable():
    pkg = make_pkg(name="x", cve_ids=["CVE-X"],
                   max_epss=0.8, in_cisa_kev=True, exploit_maturity="weaponized")
    pkg.reachability_source = "govulncheck"
    pkg.reachable = False
    pkg.unreachable_cves = ["CVE-X"]
    apply_reachability_score_discount([pkg])
    assert pkg.max_epss == pytest.approx(0.16, rel=1e-3)
    assert pkg.in_cisa_kev is False
    assert pkg.exploit_maturity == "none"


def test_score_discount_not_applied_to_reachable():
    pkg = make_pkg(name="y", cve_ids=["CVE-Y"],
                   max_epss=0.8, in_cisa_kev=True, exploit_maturity="weaponized")
    pkg.reachability_source = "govulncheck"
    pkg.reachable = True
    pkg.reachable_cves = ["CVE-Y"]
    apply_reachability_score_discount([pkg])
    assert pkg.max_epss == pytest.approx(0.8)
    assert pkg.in_cisa_kev is True


def test_score_discount_not_applied_when_not_checked():
    pkg = make_pkg(name="z", cve_ids=["CVE-Z"],
                   max_epss=0.8, in_cisa_kev=True)
    # reachability_source == "" → not checked, no discount
    apply_reachability_score_discount([pkg])
    assert pkg.max_epss == pytest.approx(0.8)
    assert pkg.in_cisa_kev is True
