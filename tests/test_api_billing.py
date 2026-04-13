"""Tests for selvo.api.billing — Stripe webhook signature verification and event handling."""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SECRET = "whsec_test_secret_value"


def _make_sig_header(payload: bytes, secret: str = _SECRET, ts: int | None = None) -> str:
    """Build a valid Stripe-Signature header for the given payload."""
    if ts is None:
        ts = int(time.time())
    signed = f"{ts}.{payload.decode()}"
    sig = hmac.new(
        key=secret.encode(),
        msg=signed.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()
    return f"t={ts},v1={sig}"


def _make_event(event_type: str, data: dict | None = None) -> bytes:
    event = {
        "type": event_type,
        "data": {"object": data or {}},
    }
    return json.dumps(event).encode()


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def test_verify_valid_signature():
    from selvo.api.billing import verify_stripe_signature

    payload = b'{"type": "checkout.session.completed"}'
    sig = _make_sig_header(payload)
    # Should not raise
    verify_stripe_signature(payload, sig, secret=_SECRET)


def test_verify_wrong_secret_raises():
    from selvo.api.billing import verify_stripe_signature, StripeWebhookError

    payload = b'{"type": "test"}'
    sig = _make_sig_header(payload, secret="correct-secret")
    with pytest.raises(StripeWebhookError, match="signature verification failed"):
        verify_stripe_signature(payload, sig, secret="wrong-secret")


def test_verify_tampered_payload_raises():
    from selvo.api.billing import verify_stripe_signature, StripeWebhookError

    payload = b'{"type": "real"}'
    sig = _make_sig_header(payload)
    tampered = b'{"type": "tampered"}'
    with pytest.raises(StripeWebhookError, match="signature verification failed"):
        verify_stripe_signature(tampered, sig, secret=_SECRET)


def test_verify_stale_timestamp_raises():
    from selvo.api.billing import verify_stripe_signature, StripeWebhookError

    payload = b'{"type": "test"}'
    old_ts = int(time.time()) - 400  # > 300s tolerance
    sig = _make_sig_header(payload, ts=old_ts)
    with pytest.raises(StripeWebhookError, match="exceeds.*tolerance"):
        verify_stripe_signature(payload, sig, secret=_SECRET)


def test_verify_empty_secret_raises():
    from selvo.api.billing import verify_stripe_signature, StripeWebhookError

    with pytest.raises(StripeWebhookError, match="STRIPE_WEBHOOK_SECRET"):
        verify_stripe_signature(b"payload", "t=1,v1=abc", secret="")


def test_verify_malformed_header_raises():
    from selvo.api.billing import verify_stripe_signature, StripeWebhookError

    with pytest.raises(StripeWebhookError, match="Malformed|missing"):
        verify_stripe_signature(b"payload", "not-a-valid-header", secret=_SECRET)


# ---------------------------------------------------------------------------
# Event handling — checkout.session.completed
# ---------------------------------------------------------------------------

def test_checkout_completed_upgrades_org(tmp_path, monkeypatch):
    from selvo.api.billing import handle_stripe_event
    import selvo.api.auth as _auth

    # Redirect auth DB
    monkeypatch.setattr(_auth, "_DB_PATH", tmp_path / "keys.db")
    monkeypatch.setattr(_auth, "_conn", None)

    _auth.register_org("stripe-org", name="Stripe Org", plan="free")

    event = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "client_reference_id": "stripe-org",
                "customer": "cus_123",
                "metadata": {"price_id": "price_pro_monthly"},
            }
        },
    }
    result = handle_stripe_event(event)
    assert result["action"] == "upgraded"
    assert result["org_id"] == "stripe-org"
    assert result["plan"] == "pro"

    row = _auth._get_conn().execute("SELECT plan FROM orgs WHERE org_id='stripe-org'").fetchone()
    assert row[0] == "pro"


def test_checkout_unknown_org_ignored():
    from selvo.api.billing import handle_stripe_event

    event = {
        "type": "checkout.session.completed",
        "data": {"object": {"customer": "cus_unknown_xyz"}},
    }
    result = handle_stripe_event(event)
    assert result["action"] == "ignored"


# ---------------------------------------------------------------------------
# Event handling — subscription lifecycle
# ---------------------------------------------------------------------------

def test_subscription_deleted_downgrades_to_free(tmp_path, monkeypatch):
    from selvo.api.billing import handle_stripe_event
    import selvo.api.auth as _auth

    monkeypatch.setattr(_auth, "_DB_PATH", tmp_path / "keys.db")
    monkeypatch.setattr(_auth, "_conn", None)

    _auth.register_org("downgrade-org", name="D", plan="pro")
    # Link a Stripe customer ID
    _auth._get_conn().execute(
        "UPDATE orgs SET stripe_customer_id='cus_del' WHERE org_id='downgrade-org'"
    )
    _auth._get_conn().commit()

    event = {
        "type": "customer.subscription.deleted",
        "data": {"object": {"customer": "cus_del"}},
    }
    result = handle_stripe_event(event)
    assert result["action"] == "downgraded"
    assert result["plan"] == "free"


def test_subscription_updated_inactive_downgrades(tmp_path, monkeypatch):
    from selvo.api.billing import handle_stripe_event
    import selvo.api.auth as _auth

    monkeypatch.setattr(_auth, "_DB_PATH", tmp_path / "keys.db")
    monkeypatch.setattr(_auth, "_conn", None)

    _auth.register_org("inactive-org", name="I", plan="pro")
    _auth._get_conn().execute(
        "UPDATE orgs SET stripe_customer_id='cus_inactive' WHERE org_id='inactive-org'"
    )
    _auth._get_conn().commit()

    event = {
        "type": "customer.subscription.updated",
        "data": {"object": {"customer": "cus_inactive", "status": "past_due"}},
    }
    result = handle_stripe_event(event)
    assert result["action"] == "downgraded"
    assert result["plan"] == "free"


def test_payment_failed_logged():
    from selvo.api.billing import handle_stripe_event

    event = {
        "type": "invoice.payment_failed",
        "data": {"object": {"customer": "cus_broke"}},
    }
    result = handle_stripe_event(event)
    assert result["action"] == "payment_failed"


def test_unknown_event_ignored():
    from selvo.api.billing import handle_stripe_event

    result = handle_stripe_event({"type": "random.event", "data": {"object": {}}})
    assert result["action"] == "ignored"


# ---------------------------------------------------------------------------
# EPSS CSV caching
# ---------------------------------------------------------------------------

def test_cache_epss_csv_parses_rows():
    """cache_epss_csv() should correctly parse mock CSV data."""
    import asyncio
    import gzip
    import unittest.mock as mock

    from selvo.analysis import epss as _epss_mod

    # Build a minimal mock CSV response
    csv_lines = [
        "#model_version:v2023.03.01,score_date:2024-01-27T00:00:00+0000",
        "cve,epss,percentile",
        "CVE-2023-0001,0.12345,0.87000",
        "CVE-2023-0002,0.00123,0.10000",
        "",  # trailing blank line should not crash
    ]
    raw_gz = gzip.compress("\n".join(csv_lines).encode())

    mock_response = mock.MagicMock()
    mock_response.content = raw_gz
    mock_response.raise_for_status = mock.MagicMock()

    stored: dict[str, float] = {}

    def _fake_set_cache(key: str, value, ttl: int):
        stored[key] = float(value)

    with mock.patch.object(_epss_mod._cache, "set_cache", side_effect=_fake_set_cache):
        with mock.patch("httpx.AsyncClient") as mock_client_cls:
            mock_ctx = mock.AsyncMock()
            mock_ctx.__aenter__ = mock.AsyncMock(return_value=mock_ctx)
            mock_ctx.__aexit__ = mock.AsyncMock(return_value=False)
            mock_ctx.get = mock.AsyncMock(return_value=mock_response)
            mock_client_cls.return_value = mock_ctx

            count = asyncio.run(_epss_mod.cache_epss_csv())

    assert count == 2
    assert stored.get("epss:CVE-2023-0001") == pytest.approx(0.12345)
    assert stored.get("epss:CVE-2023-0002") == pytest.approx(0.00123)
