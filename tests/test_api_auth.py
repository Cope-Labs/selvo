"""Tests for selvo.api.auth — key generation, verification, and rate limiting."""
from __future__ import annotations

import hashlib
import time

import pytest


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    """Redirect auth DB to a temporary file for each test."""
    db_path = tmp_path / "api_keys.db"
    monkeypatch.setattr("selvo.api.auth._DB_PATH", db_path)
    # Reset the cached connection so each test gets a fresh DB
    import selvo.api.auth as _auth
    monkeypatch.setattr(_auth, "_conn", None)
    yield db_path
    if _auth._conn is not None:
        _auth._conn.close()
        _auth._conn = None


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def test_generate_key_format(tmp_db):
    from selvo.api.auth import register_org, generate_api_key

    register_org("test-org", name="Test Org", email="a@b.com")
    key = generate_api_key("test-org", plan="pro")

    assert key.startswith("sk_"), f"Key should start with 'sk_': {key!r}"
    parts = key.split("_")
    assert len(parts) == 3, f"Expected sk_<slug>_<token>, got {key!r}"
    _prefix, slug, token = parts
    assert len(token) == 32  # 16 bytes hex-encoded


def test_generate_key_is_unique(tmp_db):
    from selvo.api.auth import register_org, generate_api_key

    register_org("org-a", name="A")
    k1 = generate_api_key("org-a")
    k2 = generate_api_key("org-a")
    assert k1 != k2


def test_plaintext_not_stored(tmp_db):
    """The plaintext key must NOT appear anywhere in the DB."""
    from selvo.api.auth import register_org, generate_api_key, _get_conn

    register_org("secret-org", name="S")
    key = generate_api_key("secret-org")
    conn = _get_conn()
    rows = conn.execute("SELECT key_hash FROM api_keys").fetchall()
    for (kh,) in rows:
        assert key not in kh, "Plaintext key must not be stored"
        assert kh == hashlib.sha256(key.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def test_verify_valid_key(tmp_db):
    from selvo.api.auth import register_org, generate_api_key, verify_api_key

    register_org("acme", name="Acme Corp", email="ops@acme.com", plan="pro")
    key = generate_api_key("acme", plan="pro")
    ctx = verify_api_key(key)

    assert ctx is not None
    assert ctx.org_id == "acme"
    assert ctx.plan == "pro"
    assert isinstance(ctx.key_id, int)


def test_verify_wrong_key_returns_none(tmp_db):
    from selvo.api.auth import verify_api_key

    assert verify_api_key("sk_bad_aaaa1111bbbb2222cccc3333dddd4444") is None


def test_verify_increments_counter(tmp_db):
    from selvo.api.auth import register_org, generate_api_key, verify_api_key, _get_conn

    register_org("counter-org", name="C")
    key = generate_api_key("counter-org", plan="pro")

    verify_api_key(key)
    verify_api_key(key)

    row = _get_conn().execute("SELECT requests_today FROM api_keys").fetchone()
    assert row[0] == 2


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_rate_limit_free_plan(tmp_db):
    """Free plan allows 5 requests/day; the 6th must be rejected."""
    from selvo.api.auth import register_org, generate_api_key, verify_api_key, PLAN_LIMITS

    assert PLAN_LIMITS["free"]["requests_per_day"] == 5

    register_org("limited-org", name="L")
    key = generate_api_key("limited-org", plan="free")

    for i in range(5):
        ctx = verify_api_key(key)
        assert ctx is not None, f"Request {i + 1} should succeed"

    # 6th request should be rate-limited
    assert verify_api_key(key) is None


def test_rate_limit_resets_next_day(tmp_db, monkeypatch):
    """Counter should reset when the UTC day rolls over."""
    from selvo.api.auth import register_org, generate_api_key, verify_api_key, _get_conn

    register_org("day-reset-org", name="D")
    key = generate_api_key("day-reset-org", plan="free")

    # Exhaust the free quota
    for _ in range(5):
        verify_api_key(key)
    assert verify_api_key(key) is None

    # Simulate a day change: set day_start to yesterday
    yesterday = time.time() - 86401
    _get_conn().execute("UPDATE api_keys SET day_start=?", (yesterday,))
    _get_conn().commit()

    # Should succeed now
    ctx = verify_api_key(key)
    assert ctx is not None


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

def test_revoke_key(tmp_db):
    from selvo.api.auth import register_org, generate_api_key, verify_api_key, revoke_api_key
    import hashlib

    register_org("revoke-org", name="R")
    key = generate_api_key("revoke-org")
    key_hash = hashlib.sha256(key.encode()).hexdigest()

    assert verify_api_key(key) is not None
    assert revoke_api_key(key_hash) is True
    assert verify_api_key(key) is None


def test_revoke_nonexistent_returns_false(tmp_db):
    from selvo.api.auth import revoke_api_key
    assert revoke_api_key("deadbeef" * 8) is False


# ---------------------------------------------------------------------------
# Plan upgrade
# ---------------------------------------------------------------------------

def test_upgrade_org_updates_keys(tmp_db):
    from selvo.api.auth import register_org, generate_api_key, upgrade_org, _get_conn

    register_org("upgrade-org", name="U", plan="free")
    generate_api_key("upgrade-org", plan="free")
    upgrade_org("upgrade-org", "pro")

    row = _get_conn().execute(
        "SELECT plan FROM api_keys WHERE org_id='upgrade-org'"
    ).fetchone()
    assert row[0] == "pro"

    org_row = _get_conn().execute(
        "SELECT plan FROM orgs WHERE org_id='upgrade-org'"
    ).fetchone()
    assert org_row[0] == "pro"


# ---------------------------------------------------------------------------
# list_org_keys
# ---------------------------------------------------------------------------

def test_list_org_keys(tmp_db):
    from selvo.api.auth import register_org, generate_api_key, list_org_keys

    register_org("list-org", name="List")
    generate_api_key("list-org")
    generate_api_key("list-org")

    keys = list_org_keys("list-org")
    assert len(keys) == 2
    for k in keys:
        assert "id" in k
        assert k["org_id"] == "list-org"
