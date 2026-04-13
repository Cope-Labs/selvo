"""Tests for selvo.api.dashboard render functions.

All tests are synchronous — the render functions are pure Python string
builders with no I/O, so no async fixtures are needed.
"""
from __future__ import annotations

import time


from selvo.api.dashboard import (
    render_overview,
    render_packages,
    render_cves,
    render_trends,
    render_keys,
    _badge_kev,
    _badge_epss,
    _cvss_bar,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkg(**kwargs) -> dict:
    """Return a minimal package dict with sane defaults."""
    defaults = dict(
        name="testpkg",
        ecosystem="debian",
        version="1.0.0",
        max_cvss=0.0,
        max_epss=0.0,
        cve_count=0,
        cve_ids=[],
        in_cisa_kev=False,
        exploit_maturity="none",
        transitive_rdep_count=0,
        score=0.0,
    )
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestBadgeHelpers:
    def test_badge_kev_contains_kev(self):
        assert "KEV" in _badge_kev()

    def test_badge_epss_high_score(self):
        html = _badge_epss(0.95)
        assert "95.0%" in html
        assert "epss-high" in html

    def test_badge_epss_medium_score(self):
        html = _badge_epss(0.05)
        assert "5.0%" in html
        assert "epss-med" in html

    def test_badge_epss_low_score(self):
        html = _badge_epss(0.001)
        assert "0.1%" in html
        assert "text-muted" in html

    def test_cvss_bar_high(self):
        html = _cvss_bar(9.8)
        # Critical: red color
        assert "#f85149" in html
        assert "CVSS 9.8" in html

    def test_cvss_bar_medium(self):
        html = _cvss_bar(7.5)
        assert "#d29922" in html

    def test_cvss_bar_low(self):
        html = _cvss_bar(3.0)
        assert "#3fb950" in html


# ---------------------------------------------------------------------------
# render_overview
# ---------------------------------------------------------------------------

class TestRenderOverview:
    def test_returns_html_string(self):
        html = render_overview([], None)
        assert isinstance(html, str)
        assert "<!doctype html>" in html.lower()

    def test_shows_package_count(self):
        pkgs = [_pkg(name=f"pkg{i}") for i in range(5)]
        html = render_overview(pkgs, None)
        assert "5" in html

    def test_counts_packages_with_cves(self):
        pkgs = [
            _pkg(name="vuln", cve_count=3, cve_ids=["CVE-2024-0001"]),
            _pkg(name="clean"),
        ]
        html = render_overview(pkgs, None)
        assert "1" in html  # with_cve count

    def test_kev_count_shown(self):
        pkgs = [
            _pkg(name="kevpkg", in_cisa_kev=True),
            _pkg(name="clean"),
        ]
        html = render_overview(pkgs, None)
        assert "KEV" in html

    def test_weaponized_package_shows_badge(self):
        pkgs = [_pkg(name="wpn", exploit_maturity="weaponized", score=99.0)]
        html = render_overview(pkgs, None)
        assert "Weaponized" in html

    def test_poc_package_shows_badge(self):
        pkgs = [_pkg(name="poc", exploit_maturity="poc", score=80.0)]
        html = render_overview(pkgs, None)
        assert "PoC" in html

    def test_snapshot_timestamp_shown(self):
        ts = 1_700_000_000.0
        pkgs = [_pkg(name="pkg1")]
        html = render_overview(pkgs, ts)
        # Should show a human-readable date
        assert "2023" in html or "UTC" in html

    def test_no_snapshot_shows_placeholder(self):
        html = render_overview([], None)
        # Empty state shows getting-started instructions
        assert "welcome" in html.lower() or "no analysis" in html.lower()

    def test_top10_limited_to_10_rows(self):
        pkgs = [_pkg(name=f"pkg{i}", score=float(i)) for i in range(20)]
        html = render_overview(pkgs, None)
        # The table body should contain at most 10 package links
        # (each top-10 pkg gets an <a href="/dash/packages?q=pkg{i}">)
        assert html.count("/dash/packages?q=pkg") <= 10

    def test_empty_packages_renders_without_error(self):
        html = render_overview([], None)
        assert "<!doctype html>" in html.lower()

    def test_title_in_head(self):
        html = render_overview([], None)
        assert "selvo" in html


# ---------------------------------------------------------------------------
# render_packages
# ---------------------------------------------------------------------------

class TestRenderPackages:
    def test_returns_html(self):
        html = render_packages([], "")
        assert "<!doctype html>" in html.lower()

    def test_shows_all_packages_with_show_all(self):
        pkgs = [_pkg(name="curl"), _pkg(name="openssl")]
        html = render_packages(pkgs, "", show_all=True)
        assert "curl" in html
        assert "openssl" in html

    def test_hides_packages_without_issues(self):
        pkgs = [_pkg(name="curl"), _pkg(name="openssl", cve_ids=["CVE-2024-0001"], cve_count=1)]
        html = render_packages(pkgs, "")
        assert "openssl" in html
        assert "curl" not in html or "Show all" in html

    def test_filter_by_query(self):
        pkgs = [_pkg(name="curl"), _pkg(name="openssl")]
        html = render_packages(pkgs, "openssl")
        # openssl should be shown; curl should be filtered out
        assert "openssl" in html
        assert "curl" not in html

    def test_empty_state_shown(self):
        html = render_packages([], "")
        assert "getting started" in html.lower() or "/dash/overview" in html

    def test_kev_badge_in_table(self):
        pkgs = [_pkg(name="kevpkg", in_cisa_kev=True)]
        html = render_packages(pkgs, "")
        assert "KEV" in html


# ---------------------------------------------------------------------------
# render_cves
# ---------------------------------------------------------------------------

class TestRenderCves:
    def test_returns_html(self):
        html = render_cves([])
        assert "<!doctype html>" in html.lower()

    def test_no_cves_shows_empty_state(self):
        html = render_cves([_pkg(name="clean")])
        assert "No CVEs" in html

    def test_cves_appear_in_table(self):
        pkgs = [
            _pkg(
                name="libssl",
                cve_ids=["CVE-2024-0001", "CVE-2024-0002"],
                max_cvss=7.5,
                max_epss=0.12,
            )
        ]
        html = render_cves(pkgs)
        assert "CVE-2024-0001" in html
        assert "CVE-2024-0002" in html
        assert "libssl" in html

    def test_cves_sorted_by_epss_desc(self):
        pkgs = [
            _pkg(name="low", cve_ids=["CVE-LOW"], max_epss=0.01),
            _pkg(name="high", cve_ids=["CVE-HIGH"], max_epss=0.90),
        ]
        html = render_cves(pkgs)
        idx_high = html.index("CVE-HIGH")
        idx_low = html.index("CVE-LOW")
        assert idx_high < idx_low

    def test_kev_badge_in_cve_row(self):
        pkgs = [_pkg(name="kev", cve_ids=["CVE-KEV"], in_cisa_kev=True)]
        html = render_cves(pkgs)
        assert "KEV" in html

    def test_weaponized_badge_in_cve_row(self):
        pkgs = [_pkg(name="wpn", cve_ids=["CVE-WPN"], exploit_maturity="weaponized")]
        html = render_cves(pkgs)
        assert "Weaponized" in html

    def test_nvd_link_present(self):
        pkgs = [_pkg(name="x", cve_ids=["CVE-2024-1234"])]
        html = render_cves(pkgs)
        assert "nvd.nist.gov" in html
        assert "CVE-2024-1234" in html

    def test_total_count_shown(self):
        cves = [f"CVE-2024-{i:04d}" for i in range(5)]
        pkgs = [_pkg(name="multi", cve_ids=cves)]
        html = render_cves(pkgs)
        assert "5" in html


# ---------------------------------------------------------------------------
# render_trends
# ---------------------------------------------------------------------------

class TestRenderTrends:
    def test_returns_html(self):
        html = render_trends([])
        assert "<!doctype html>" in html.lower()

    def test_no_metrics_shows_placeholder(self):
        html = render_trends([])
        assert "No trend data" in html or "/dash/keys" in html

    def test_sparklines_rendered_with_data(self):
        metrics = [
            {"date": "2024-01-01", "package_count": 100, "cve_count": 10, "kev_count": 1},
            {"date": "2024-01-02", "package_count": 105, "cve_count": 12, "kev_count": 2},
            {"date": "2024-01-03", "package_count": 110, "cve_count": 15, "kev_count": 2},
        ]
        html = render_trends(metrics)
        assert "<svg" in html
        assert "<polyline" in html

    def test_dates_shown(self):
        metrics = [
            {"date": "2024-01-01", "package_count": 10, "cve_count": 1, "kev_count": 0},
            {"date": "2024-06-30", "package_count": 20, "cve_count": 2, "kev_count": 0},
        ]
        html = render_trends(metrics)
        assert "2024-01-01" in html
        assert "2024-06-30" in html

    def test_snapshot_count_shown(self):
        metrics = [
            {"date": f"2024-01-{i:02d}", "package_count": i, "cve_count": 0, "kev_count": 0}
            for i in range(1, 8)
        ]
        html = render_trends(metrics)
        assert "7" in html


# ---------------------------------------------------------------------------
# render_keys
# ---------------------------------------------------------------------------

class TestRenderKeys:
    def _key(self, **kwargs) -> dict:
        defaults = dict(
            id=1,
            key_hash="abc123def456",
            plan="free",
            active=True,
            created_at=time.time() - 3600,
            last_used_at=None,
            requests_today=0,
        )
        defaults.update(kwargs)
        return defaults

    def test_returns_html(self):
        html = render_keys("myorg", [])
        assert "<!doctype html>" in html.lower()

    def test_org_id_shown(self):
        html = render_keys("acme", [])
        assert "acme" in html

    def test_empty_keys_shows_placeholder(self):
        html = render_keys("org", [])
        assert "No keys yet" in html

    def test_active_key_shows_revoke_button(self):
        key = self._key(active=True)
        html = render_keys("org", [key])
        assert "Revoke" in html
        assert "Active" in html

    def test_revoked_key_shows_revoked_badge(self):
        key = self._key(active=False)
        html = render_keys("org", [key])
        assert "Revoked" in html
        # No revoke *button* for an already-revoked key (the URL /dash/keys/revoke
        # still appears in the form action, but the submit button should not)
        assert 'type="submit"' not in html or "onclick=\"return confirm" not in html

    def test_message_shown(self):
        html = render_keys("org", [], message="Key created successfully.")
        assert "Key created successfully." in html

    def test_multiple_keys_all_shown(self):
        keys = [self._key(id=i, key_hash=f"hash{i:06d}abc") for i in range(1, 4)]
        html = render_keys("org", keys)
        assert html.count("hash") >= 3
