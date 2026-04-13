"""Tests for selvo.analysis.compliance and selvo.reporters.compliance."""
from __future__ import annotations

import io
import json

import pytest

from selvo.analysis.compliance import map_controls, summarise, ComplianceFinding
from selvo.reporters.compliance import render_json, render_markdown
from tests.conftest import make_pkg


# ── map_controls ──────────────────────────────────────────────────────────────

def test_empty_packages_returns_empty():
    assert map_controls([]) == []


def test_kev_package_generates_findings():
    pkg = make_pkg(name="openssl", cve_ids=["CVE-2024-X"], in_cisa_kev=True)
    findings = map_controls([pkg], framework="nist")
    signals = {f.signal for f in findings}
    assert "kev_listed" in signals


def test_weaponized_generates_findings():
    pkg = make_pkg(name="curl", exploit_maturity="weaponized", cve_ids=["CVE-W"])
    findings = map_controls([pkg], framework="nist")
    assert any(f.signal == "weaponized_exploit" for f in findings)


def test_poc_generates_findings():
    pkg = make_pkg(name="libz", exploit_maturity="poc", cve_ids=["CVE-P"])
    findings = map_controls([pkg], framework="nist")
    assert any(f.signal == "poc_exploit" for f in findings)


def test_sla_breach_generates_findings():
    pkg = make_pkg(name="bash", cve_ids=["CVE-S"],
                   sla_band="breach", sla_days_overdue=45)
    findings = map_controls([pkg], framework="nist")
    assert any(f.signal == "sla_breach" for f in findings)


def test_outdated_generates_findings():
    pkg = make_pkg(name="libc", cve_ids=["CVE-O"],
                   version="1.0", upstream_version="2.0", max_cvss=8.0)
    findings = map_controls([pkg], framework="nist")
    assert any(f.signal == "outdated_component" for f in findings)


def test_clean_package_no_findings():
    pkg = make_pkg(name="clean")
    findings = map_controls([pkg], framework="all")
    assert findings == []


def test_framework_filter_fedramp():
    pkg = make_pkg(name="openssl", cve_ids=["CVE-K"], in_cisa_kev=True)
    findings = map_controls([pkg], framework="fedramp")
    for f in findings:
        assert "FedRAMP High" in f.frameworks


def test_framework_all_returns_all_frameworks():
    pkg = make_pkg(name="openssl", cve_ids=["CVE-K"], in_cisa_kev=True)
    findings = map_controls([pkg], framework="all")
    assert len(findings) > 0


def test_invalid_framework_raises():
    pkg = make_pkg(name="x")
    with pytest.raises(ValueError, match="Unknown framework"):
        map_controls([pkg], framework="nonexistent")


def test_nist_controls_present():
    pkg = make_pkg(name="openssl", cve_ids=["CVE-K"], in_cisa_kev=True)
    findings = map_controls([pkg], framework="nist")
    all_controls = [c for f in findings for c in f.controls]
    # KEV → SI-5, RA-5, SI-2 expected
    assert any(c.startswith("SI-") for c in all_controls)
    assert any(c.startswith("RA-") for c in all_controls)


def test_deduplication():
    """Same signal should not produce duplicate finding rows."""
    pkg = make_pkg(name="x", cve_ids=["CVE-1", "CVE-2"], in_cisa_kev=True)
    findings = map_controls([pkg], framework="nist")
    keys = [(f.package, f.signal, f.cve_id, tuple(sorted(f.controls))) for f in findings]
    assert len(keys) == len(set(keys))


# ── summarise ─────────────────────────────────────────────────────────────────

def test_summarise_counts():
    findings = [
        ComplianceFinding("a", "debian", "CVE-1", "kev_listed",
                          ["NIST 800-53 Rev 5"], ["SI-5", "RA-5"], "critical", ""),
        ComplianceFinding("b", "debian", "CVE-2", "poc_exploit",
                          ["NIST 800-53 Rev 5"], ["RA-5"], "medium", ""),
    ]
    s = summarise(findings)
    assert s["total_findings"] == 2
    assert "SI-5" in s["unique_controls"]
    assert s["by_severity"]["critical"] == 1
    assert s["by_severity"]["medium"] == 1


# ── JSON reporter ─────────────────────────────────────────────────────────────

def test_render_json_valid():
    pkg = make_pkg(name="openssl", cve_ids=["CVE-K"], in_cisa_kev=True)
    findings = map_controls([pkg], framework="nist")
    buf = io.StringIO()
    render_json(findings, buf)
    data = json.loads(buf.getvalue())
    assert "findings" in data
    assert "summary" in data
    assert "generated_at" in data


def test_render_json_empty():
    buf = io.StringIO()
    render_json([], buf)
    data = json.loads(buf.getvalue())
    assert data["summary"]["total_findings"] == 0
    assert data["findings"] == []


# ── Markdown reporter ─────────────────────────────────────────────────────────

def test_render_markdown_headings():
    pkg = make_pkg(name="curl", cve_ids=["CVE-W"], exploit_maturity="weaponized")
    findings = map_controls([pkg], framework="nist")
    buf = io.StringIO()
    render_markdown(findings, buf)
    md = buf.getvalue()
    assert "# selvo Compliance Audit Report" in md
    assert "curl" in md


def test_render_markdown_empty():
    buf = io.StringIO()
    render_markdown([], buf)
    md = buf.getvalue()
    assert "No compliance findings" in md
