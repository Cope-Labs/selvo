"""Tests for selvo.analysis.osv_local — local OSV mirror."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO
from unittest.mock import MagicMock, patch



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_advisory(vuln_id: str, pkg_name: str, ecosystem: str = "Debian",
                   introduced: str = "0", fixed: str = "2.0.0") -> dict:
    """Build a minimal OSV advisory dict."""
    return {
        "id": vuln_id,
        "aliases": [f"CVE-2024-{vuln_id[-4:]}"],
        "summary": f"Test advisory for {pkg_name}",
        "affected": [
            {
                "package": {"name": pkg_name, "ecosystem": ecosystem},
                "ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": introduced},
                    {"fixed": fixed},
                ]}],
            }
        ],
    }


def _make_zip(*advisories: dict) -> bytes:
    """Return a bytes zip containing one JSON file per advisory."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for adv in advisories:
            zf.writestr(f"{adv['id']}.json", json.dumps(adv))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Unit tests (no network)
# ---------------------------------------------------------------------------

def test_advisory_rows_basic():
    """_advisory_rows returns one row per (package, range) combination."""
    from selvo.analysis.osv_local import _advisory_rows

    adv = _make_advisory("OSV-2024-0001", "openssl", fixed="3.0.14")
    rows = _advisory_rows(adv, "Debian")
    assert len(rows) == 1
    assert rows[0]["package"] == "openssl"
    assert rows[0]["fixed"] == "3.0.14"
    assert rows[0]["id"] == "OSV-2024-0001"


def test_advisory_rows_multiple_ranges():
    """Multiple range events produce multiple rows."""
    from selvo.analysis.osv_local import _advisory_rows

    adv = {
        "id": "OSV-2024-0002",
        "aliases": [],
        "summary": "Multi-range",
        "affected": [{
            "package": {"name": "curl", "ecosystem": "Debian"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "7.88.0"}]},
                {"type": "ECOSYSTEM", "events": [{"introduced": "8.0.0"}, {"fixed": "8.1.0"}]},
            ],
        }],
    }
    rows = _advisory_rows(adv, "Debian")
    assert len(rows) == 2


def test_advisory_rows_no_affected_package_skipped():
    """Advisory with empty package name is skipped."""
    from selvo.analysis.osv_local import _advisory_rows

    adv = {
        "id": "OSV-2024-0003",
        "aliases": [],
        "summary": "No pkg",
        "affected": [{"package": {"name": "", "ecosystem": "Debian"}, "ranges": []}],
    }
    assert _advisory_rows(adv, "Debian") == []


def test_lookup_local_version_gating(tmp_path, monkeypatch):
    """lookup_local skips advisories where the installed version >= fixed."""
    import selvo.analysis.osv_local as osv_mod

    # Redirect DB to a temp path
    db_path = tmp_path / "osv.db"
    monkeypatch.setattr(osv_mod, "_OSV_DB_PATH", db_path)
    monkeypatch.setattr(osv_mod, "_conn", None)

    conn = osv_mod._get_conn()
    conn.execute(
        "INSERT INTO advisories (id, ecosystem, package, introduced, fixed, aliases, severity, summary) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("CVE-2024-0001", "Debian", "openssl", "0", "3.0.14", "[]", "", "Test"),
    )
    conn.commit()

    # Version >= fixed → should NOT be returned
    ids = osv_mod.lookup_local("openssl", "debian", version="3.0.14")
    assert "CVE-2024-0001" not in ids

    # Version < fixed → should be returned
    ids2 = osv_mod.lookup_local("openssl", "debian", version="3.0.0")
    assert "CVE-2024-0001" in ids2


def test_lookup_local_alias_extraction(tmp_path, monkeypatch):
    """CVE IDs in the aliases JSON column are returned."""
    import selvo.analysis.osv_local as osv_mod

    db_path = tmp_path / "osv.db"
    monkeypatch.setattr(osv_mod, "_OSV_DB_PATH", db_path)
    monkeypatch.setattr(osv_mod, "_conn", None)

    conn = osv_mod._get_conn()
    conn.execute(
        "INSERT INTO advisories (id, ecosystem, package, introduced, fixed, aliases, severity, summary) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("DEBIAN-2024-9999", "Debian", "curl", "0", "", '["CVE-2024-9999"]', "", ""),
    )
    conn.commit()

    ids = osv_mod.lookup_local("curl", "debian")
    assert "CVE-2024-9999" in ids


def test_lookup_local_unknown_ecosystem():
    """Unknown ecosystem returns empty list without crashing."""
    from selvo.analysis.osv_local import lookup_local
    assert lookup_local("openssl", "winget") == []


def test_is_current_no_db(tmp_path, monkeypatch):
    """is_current returns False when DB file does not exist."""
    import selvo.analysis.osv_local as osv_mod
    monkeypatch.setattr(osv_mod, "_OSV_DB_PATH", tmp_path / "nonexistent.db")
    monkeypatch.setattr(osv_mod, "_conn", None)
    assert osv_mod.is_current() is False


def test_is_current_stale(tmp_path, monkeypatch):
    """is_current returns False when synced_at is too old."""
    import selvo.analysis.osv_local as osv_mod

    db_path = tmp_path / "osv.db"
    monkeypatch.setattr(osv_mod, "_OSV_DB_PATH", db_path)
    monkeypatch.setattr(osv_mod, "_conn", None)

    conn = osv_mod._get_conn()
    old_ts = str(time.time() - 200_000)  # ~55 h ago
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('synced_at', ?)", (old_ts,))
    conn.commit()

    assert osv_mod.is_current() is False


def test_is_current_fresh(tmp_path, monkeypatch):
    """is_current returns True when synced_at is within staleness window."""
    import selvo.analysis.osv_local as osv_mod

    db_path = tmp_path / "osv.db"
    monkeypatch.setattr(osv_mod, "_OSV_DB_PATH", db_path)
    monkeypatch.setattr(osv_mod, "_conn", None)

    conn = osv_mod._get_conn()
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('synced_at', ?)", (str(time.time()),))
    conn.commit()

    assert osv_mod.is_current() is True


def test_db_stats_no_db(tmp_path, monkeypatch):
    """db_stats returns exists=False when database is absent."""
    import selvo.analysis.osv_local as osv_mod
    monkeypatch.setattr(osv_mod, "_OSV_DB_PATH", tmp_path / "missing.db")
    monkeypatch.setattr(osv_mod, "_conn", None)
    assert osv_mod.db_stats()["exists"] is False


def test_sync_osv_unknown_ecosystem(tmp_path, monkeypatch):
    """sync_osv with an unknown ecosystem logs a warning and returns 0 rows."""
    import selvo.analysis.osv_local as osv_mod

    db_path = tmp_path / "osv.db"
    monkeypatch.setattr(osv_mod, "_OSV_DB_PATH", db_path)
    monkeypatch.setattr(osv_mod, "_conn", None)

    results = osv_mod.sync_osv(["nonexistent_eco"])
    assert results["nonexistent_eco"] == 0


def test_sync_osv_download(tmp_path, monkeypatch):
    """sync_osv correctly ingests a mocked zip download."""
    import selvo.analysis.osv_local as osv_mod

    db_path = tmp_path / "osv.db"
    monkeypatch.setattr(osv_mod, "_OSV_DB_PATH", db_path)
    monkeypatch.setattr(osv_mod, "_conn", None)

    fake_zip = _make_zip(
        _make_advisory("OSV-2024-1111", "openssl", fixed="3.0.14"),
        _make_advisory("OSV-2024-2222", "curl", fixed="8.0.0"),
    )

    mock_response = MagicMock()
    mock_response.content = fake_zip
    mock_response.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.get = MagicMock(return_value=mock_response)

    with patch("selvo.analysis.osv_local.httpx.Client", return_value=mock_client):
        results = osv_mod.sync_osv(["debian"])

    assert results["debian"] >= 2
    # Verify rows were written
    ids = osv_mod.lookup_local("openssl", "debian")
    assert len(ids) > 0
