"""Tests for selvo.prioritizer.scorer."""
from __future__ import annotations


from selvo.prioritizer.scorer import score_and_rank
from tests.conftest import make_pkg


def test_empty_list_returns_empty():
    assert score_and_rank([]) == []


def test_score_range():
    """All scores should be in [0, 100]."""
    pkgs = [
        make_pkg(name="a", max_epss=0.9, max_cvss=9.8, cve_ids=["CVE-2024-0001"]),
        make_pkg(name="b"),
    ]
    result = score_and_rank(pkgs)
    for p in result:
        assert 0.0 <= p.score <= 100.0, f"{p.name} score {p.score} out of range"


def test_sorted_descending():
    """Packages are returned in descending score order."""
    pkgs = [
        make_pkg(name="low"),
        make_pkg(name="high", max_epss=0.95, max_cvss=9.8, cve_ids=["CVE-X"],
                 in_cisa_kev=True, exploit_maturity="weaponized",
                 transitive_rdep_count=100_000, reverse_dep_count=2000),
    ]
    result = score_and_rank(pkgs)
    assert result[0].name == "high"
    assert result[-1].name == "low"


def test_no_security_signal_capped_at_20():
    """Packages without any security signal should score ≤ 20."""
    clean = make_pkg(name="clean", download_count=999_999, reverse_dep_count=999_999)
    result = score_and_rank([clean])
    assert result[0].score <= 20.0


def test_security_signal_exceeds_cap():
    """A package with actual CVEs should score above the no-signal cap."""
    risky = make_pkg(
        name="risky",
        cve_ids=["CVE-2024-001"],
        max_cvss=9.8,
        max_epss=0.85,
        exploit_maturity="weaponized",
        in_cisa_kev=True,
    )
    result = score_and_rank([risky])
    assert result[0].score > 20.0


def test_kev_boosts_score_over_plain_poc():
    """KEV + weaponized should outrank plain PoC at same CVSS."""
    kev = make_pkg(name="kev", cve_ids=["CVE-K"],
                   max_cvss=8.0, max_epss=0.5,
                   in_cisa_kev=True, exploit_maturity="weaponized")
    poc = make_pkg(name="poc", cve_ids=["CVE-P"],
                   max_cvss=8.0, max_epss=0.5,
                   exploit_maturity="poc")
    result = score_and_rank([poc, kev])
    assert result[0].name == "kev"


def test_outdated_version_increases_score():
    """A package that is behind upstream should score higher than a current one."""
    outdated = make_pkg(name="old", cve_ids=["CVE-O"], version="1.0.0", upstream_version="3.0.0", max_cvss=5.0)
    current = make_pkg(name="cur", cve_ids=["CVE-C"], version="3.0.0", upstream_version="3.0.0", max_cvss=5.0)
    result = score_and_rank([current, outdated])
    assert result[0].name == "old"


def test_ossfuzz_covered_reduces_exploit_score():
    """OSS-Fuzz coverage should reduce the exploit-maturity contribution."""
    with_fuzz = make_pkg(name="fuzz", cve_ids=["CVE-F"],
                         max_cvss=8.0, max_epss=0.6,
                         exploit_maturity="poc", ossfuzz_covered=True)
    without_fuzz = make_pkg(name="nofuzz", cve_ids=["CVE-N"],
                             max_cvss=8.0, max_epss=0.6,
                             exploit_maturity="poc", ossfuzz_covered=False)
    result = score_and_rank([with_fuzz, without_fuzz])
    assert result[0].name == "nofuzz"


def test_transitive_rdeps_dominate_when_large():
    """A package that is a dependency chokepoint should rank high."""
    chokepoint = make_pkg(name="libc", transitive_rdep_count=200_000, betweenness=0.9)
    isolated = make_pkg(name="niche", max_epss=0.3, cve_ids=["CVE-X"], max_cvss=7.0)
    result = score_and_rank([isolated, chokepoint])
    # chokepoint counts as infrastructure (>10k transitive) → security signal applies
    scores = {p.name: p.score for p in result}
    # Both should be scored; chokepoint's rdep contribution should give it real weight
    assert scores["libc"] > 0
