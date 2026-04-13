"""Tests for selvo.analysis.policy (enforcement engine)."""
from __future__ import annotations


from selvo.analysis.policy import Policy, enforce, _parse_policy
from tests.conftest import make_pkg


def _default_policy(**overrides) -> Policy:
    """Build a Policy with safe defaults, override specific fields."""
    raw: dict = {}
    pol = _parse_policy(raw)
    for k, v in overrides.items():
        object.__setattr__(pol, k, v)
    return pol


# ── enforce() — block rules ───────────────────────────────────────────────────

def test_clean_package_passes():
    pkg = make_pkg(name="clean")
    pol = _default_policy()
    result = enforce([pkg], pol)
    assert result.passed
    assert result.exit_code() == 0


def test_kev_package_blocked():
    pkg = make_pkg(name="openssl", cve_ids=["CVE-2024-9999"], in_cisa_kev=True)
    pol = _default_policy(block_on_kev=True)
    result = enforce([pkg], pol)
    assert not result.passed
    assert any(v.rule == "block.on_kev" for v in result.blocked)


def test_kev_not_blocked_when_disabled():
    pkg = make_pkg(name="openssl", cve_ids=["CVE-2024-9999"], in_cisa_kev=True)
    pol = _default_policy(block_on_kev=False)
    result = enforce([pkg], pol)
    assert result.passed


def test_weaponized_exploit_blocked():
    pkg = make_pkg(name="curl", exploit_maturity="weaponized", cve_ids=["CVE-X"])
    pol = _default_policy(block_on_weaponized=True)
    result = enforce([pkg], pol)
    assert not result.passed
    assert any(v.rule == "block.on_weaponized" for v in result.blocked)


def test_min_cvss_block():
    pkg = make_pkg(name="libc", cve_ids=["CVE-Y"], max_cvss=9.5)
    pol = _default_policy(block_min_cvss=9.0, warn_min_cvss=0.0)
    result = enforce([pkg], pol)
    assert not result.passed
    assert any(v.rule == "block.min_cvss" for v in result.blocked)


def test_min_cvss_warn_below_block():
    pkg = make_pkg(name="libc", cve_ids=["CVE-Y"], max_cvss=7.5)
    pol = _default_policy(block_min_cvss=9.0, warn_min_cvss=7.0)
    result = enforce([pkg], pol)
    assert result.passed          # block not triggered
    assert result.exit_code() == 2  # warnings present
    assert any(v.rule == "warn.min_cvss" for v in result.warnings)


def test_poc_warn():
    pkg = make_pkg(name="x", exploit_maturity="poc", cve_ids=["CVE-P"])
    pol = _default_policy(warn_on_poc=True, block_on_weaponized=False)
    result = enforce([pkg], pol)
    assert result.passed
    assert any(v.rule == "warn.on_poc" for v in result.warnings)


def test_min_epss_block():
    pkg = make_pkg(name="x", cve_ids=["CVE-Z"], max_epss=0.95)
    pol = _default_policy(block_min_epss=0.9)
    result = enforce([pkg], pol)
    assert not result.passed
    assert any(v.rule == "block.min_epss" for v in result.blocked)


def test_min_score_block():
    pkg = make_pkg(name="x", cve_ids=["CVE-A"])
    pkg.score = 85.0
    pol = _default_policy(block_min_score=80.0)
    result = enforce([pkg], pol)
    assert not result.passed
    assert any(v.rule == "block.min_score" for v in result.blocked)


# ── SLA breach ────────────────────────────────────────────────────────────────

def test_sla_breach_blocked():
    pkg = make_pkg(name="x", cve_ids=["CVE-S"], sla_band="breach", sla_days_overdue=45)
    pol = _default_policy()
    result = enforce([pkg], pol)
    assert not result.passed
    assert any(v.rule == "sla.breach" for v in result.blocked)


def test_sla_ok_passes():
    pkg = make_pkg(name="x", cve_ids=["CVE-S"], sla_band="ok", sla_days_overdue=0)
    pol = _default_policy()
    result = enforce([pkg], pol)
    # No CVE/exploit signal other than sla_band=ok
    assert result.passed


# ── Allow-list ────────────────────────────────────────────────────────────────

def test_allowed_cve_suppresses_block():
    import datetime
    pkg = make_pkg(name="x", cve_ids=["CVE-ALLOWED"], max_cvss=9.9)
    future = str(datetime.date.today() + datetime.timedelta(days=365))
    pol = _default_policy(
        block_min_cvss=9.0,
        allowed_cves={"CVE-ALLOWED": {"reason": "test", "expires": datetime.date.fromisoformat(future)}},
    )
    result = enforce([pkg], pol)
    assert result.passed
    assert "CVE-ALLOWED" in result.allowed_cves


def test_expired_allow_list_entry_still_blocks():
    import datetime
    pkg = make_pkg(name="x", cve_ids=["CVE-EXP"], max_cvss=9.9)
    past = datetime.date.today() - datetime.timedelta(days=1)
    pol = _default_policy(
        block_min_cvss=9.0,
        warn_min_cvss=0.0,
        allowed_cves={"CVE-EXP": {"reason": "expired", "expires": past}},
    )
    result = enforce([pkg], pol)
    assert not result.passed


# ── Multiple packages ─────────────────────────────────────────────────────────

def test_multiple_packages_one_bad():
    good = make_pkg(name="good")
    bad = make_pkg(name="bad", cve_ids=["CVE-B"], in_cisa_kev=True)
    pol = _default_policy(block_on_kev=True)
    result = enforce([good, bad], pol)
    assert not result.passed
    assert all(v.package == "bad" for v in result.blocked)


# ── _parse_policy defaults ────────────────────────────────────────────────────

def test_parse_policy_defaults():
    pol = _parse_policy({})
    assert pol.block_on_kev is True
    assert pol.block_on_weaponized is True
    assert pol.block_min_cvss == 9.0
    assert pol.sla_critical == 7
    assert pol.sla_high == 30


def test_parse_policy_overrides():
    raw = {
        "sla": {"critical": 3, "high": 14},
        "block": {"on_kev": False, "min_cvss": 8.0},
        "warn": {"min_cvss": 5.0, "on_poc": True},
    }
    pol = _parse_policy(raw)
    assert pol.sla_critical == 3
    assert pol.sla_high == 14
    assert pol.block_on_kev is False
    assert pol.block_min_cvss == 8.0
    assert pol.warn_on_poc is True
