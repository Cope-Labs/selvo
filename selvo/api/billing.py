"""Stripe billing webhook handler for selvo SaaS.

Supports both Stripe webhook API versions:

  v1 (classic)   — full event payload, signed with ``whsec_…``
  v2 (thin events) — thin envelope payload, signed with ``whsec_…`` using
                     endpoint ID prefix; full event fetched via API.

Configure in the Stripe dashboard:
    Webhook URL: https://your-domain.com/api/v1/billing/webhook
    Events to listen for (v1 *and* v2 destinations):
        checkout.session.completed
        customer.subscription.updated
        customer.subscription.deleted
        invoice.payment_failed

Required environment variables (set in docker-compose.yml or .env):
    STRIPE_WEBHOOK_SECRET     whsec_…  (from Stripe → Developers → Webhooks)
    STRIPE_SECRET_KEY         sk_live_… or sk_test_…
    STRIPE_WEBHOOK_ENDPOINT_ID  whe_…  (required for v2 signature verification)

Mapping Stripe Price IDs to selvo plans is done via the
``STRIPE_PRICE_MAP`` env var (JSON) or the ``_PRICE_TO_PLAN`` dict below.
Example::

    STRIPE_PRICE_MAP='{"price_abc123": "pro", "price_xyz789": "enterprise"}'
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse
from typing import Any, Optional

log = logging.getLogger(__name__)

_STRIPE_SECRET_KEY: str = os.environ.get("STRIPE_SECRET_KEY", "")
_STRIPE_API = "https://api.stripe.com/v1"

_STRIPE_WEBHOOK_SECRET: str = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
_STRIPE_WEBHOOK_ENDPOINT_ID: str = os.environ.get("STRIPE_WEBHOOK_ENDPOINT_ID", "")

# Default Price ID → selvo plan mapping.
# Override at runtime via STRIPE_PRICE_MAP JSON env var.
_PRICE_TO_PLAN: dict[str, str] = {
    "price_1TFgV2EPZZ2eFu5y4OKxUoE1": "pro",          # Pro monthly $49
    "price_1T9U6DEPZZ2eFu5yKfdadsR8": "enterprise",    # Enterprise monthly $299
    "price_1T9U6DEPZZ2eFu5yUuvt0DfG": "pro",           # Pro annual $470
    "price_1T9U6CEPZZ2eFu5y7djIawUR": "pro",           # Pro monthly (original)
}

# Merge env-var overrides
_env_map = os.environ.get("STRIPE_PRICE_MAP", "")
if _env_map:
    try:
        _PRICE_TO_PLAN.update(json.loads(_env_map))
    except Exception:
        log.warning("STRIPE_PRICE_MAP is not valid JSON — ignored")


class StripeWebhookError(ValueError):
    """Raised when a webhook payload or signature is invalid."""


class StripeConfigError(RuntimeError):
    """Raised when required Stripe environment variables are not set."""


# ---------------------------------------------------------------------------
# Checkout session creation (no stripe-python SDK — uses httpx directly)
# ---------------------------------------------------------------------------

def create_checkout_session(
    org_id: str,
    plan: str,
    success_url: str,
    cancel_url: str,
    stripe_secret_key: str = "",
) -> dict:
    """Create a Stripe Checkout session and return the response dict.

    ``session["url"]`` is the URL to redirect the user to.

    The ``org_id`` is stored in ``client_reference_id`` so the webhook
    handler can resolve it back without a DB lookup.

    Raises :class:`StripeConfigError` if ``STRIPE_SECRET_KEY`` is not set.
    Raises ``httpx.HTTPStatusError`` on Stripe API errors.
    """
    import httpx

    key = stripe_secret_key or os.getenv("STRIPE_SECRET_KEY", "")
    if not key:
        raise StripeConfigError(
            "STRIPE_SECRET_KEY is not set — set the env var before starting selvo-api"
        )

    # Resolve price_id from plan name (inverse of _PRICE_TO_PLAN)
    plan_to_price = {v: k for k, v in _PRICE_TO_PLAN.items()}
    price_id = plan_to_price.get(plan, "")
    if not price_id:
        raise ValueError(f"No Stripe price configured for plan {plan!r}. Update _PRICE_TO_PLAN or STRIPE_PRICE_MAP.")

    params: dict[str, Any] = {
        "mode": "subscription",
        "client_reference_id": org_id,
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "metadata[org_id]": org_id,
        "metadata[plan]": plan,
        "success_url": success_url,
        "cancel_url": cancel_url,
        "allow_promotion_codes": "true",
    }
    # Encode as application/x-www-form-urlencoded (Stripe v1 API format)
    body = urllib.parse.urlencode(params)

    resp = httpx.post(
        f"{_STRIPE_API}/checkout/sessions",
        content=body,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Signature verification (timing-safe)
# ---------------------------------------------------------------------------

def verify_stripe_signature(
    payload: bytes,
    sig_header: str,
    secret: str = _STRIPE_WEBHOOK_SECRET,
    tolerance_seconds: int = 300,
    endpoint_id: str = _STRIPE_WEBHOOK_ENDPOINT_ID,
) -> str:
    """Verify a Stripe webhook signature (v1 or v2).

    Supports both:
    - v1 (classic): signed payload = ``{t}.{body}``
    - v2 (thin events): signed payload = ``{endpoint_id}.{t}.{body}``

    Returns the detected API version string: ``"v1"`` or ``"v2"``.

    Raises :class:`StripeWebhookError` when:
    - ``secret`` is empty / not configured
    - The ``Stripe-Signature`` header is malformed
    - The computed HMAC doesn't match (invalid payload or secret)
    - The timestamp is stale (> ``tolerance_seconds`` from now)
    - v2 header is present but ``STRIPE_WEBHOOK_ENDPOINT_ID`` is not set
    """
    if not secret:
        raise StripeWebhookError(
            "STRIPE_WEBHOOK_SECRET is not set — set the env var before starting selvo-api"
        )

    try:
        parts = dict(pair.split("=", 1) for pair in sig_header.split(","))
        ts_str = parts.get("t", "")
        v1_sig = parts.get("v1", "")
        v2_sig = parts.get("v2", "")
    except Exception as exc:
        raise StripeWebhookError(f"Malformed Stripe-Signature header: {exc}") from exc

    if not ts_str or (not v1_sig and not v2_sig):
        raise StripeWebhookError("Stripe-Signature header missing t= and both v1=/v2= components")

    try:
        ts = int(ts_str)
    except ValueError as exc:
        raise StripeWebhookError(f"Stripe-Signature t= is not an integer: {ts_str!r}") from exc

    if abs(time.time() - ts) > tolerance_seconds:
        raise StripeWebhookError(
            f"Webhook timestamp is {abs(time.time() - ts):.0f}s old — "
            f"exceeds {tolerance_seconds}s tolerance. Possible replay attack."
        )

    body_str = payload.decode("utf-8", errors="replace")

    # v2 thin events: signed payload includes the webhook endpoint ID prefix.
    if v2_sig:
        if not endpoint_id:
            raise StripeWebhookError(
                "STRIPE_WEBHOOK_ENDPOINT_ID is not set — required for v2 webhook verification"
            )
        signed_payload = f"{endpoint_id}.{ts}.{body_str}"
        expected = hmac.new(
            key=secret.encode(),
            msg=signed_payload.encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, v2_sig):
            raise StripeWebhookError("Stripe v2 signature verification failed")
        return "v2"

    # v1 classic: signed payload is just timestamp + body.
    signed_payload = f"{ts}.{body_str}"
    expected = hmac.new(
        key=secret.encode(),
        msg=signed_payload.encode(),
        digestmod=hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, v1_sig):
        raise StripeWebhookError("Stripe v1 signature verification failed")
    return "v1"


# ---------------------------------------------------------------------------
# v2 thin-event hydration
# ---------------------------------------------------------------------------

def fetch_stripe_event(event_id: str, stripe_secret_key: str = "") -> dict:
    """Fetch a full Stripe event by ID (needed for v2 thin events).

    v2 webhook payloads contain only a thin envelope with the event ID;
    the full event data must be retrieved via the Events API.
    """
    import httpx

    key = stripe_secret_key or _STRIPE_SECRET_KEY
    if not key:
        raise StripeConfigError("STRIPE_SECRET_KEY is not set")

    resp = httpx.get(
        f"{_STRIPE_API}/events/{event_id}",
        headers={"Authorization": f"Bearer {key}"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Customer → org lookup
# ---------------------------------------------------------------------------

def _org_for_customer(stripe_customer_id: str) -> Optional[str]:
    """Return the selvo org_id that owns *stripe_customer_id*, or None."""
    try:
        from selvo.api.auth import _get_conn, _lock
        with _lock:
            row = _get_conn().execute(
                "SELECT org_id FROM orgs WHERE stripe_customer_id=?",
                (stripe_customer_id,),
            ).fetchone()
            return row[0] if row else None
    except Exception as exc:
        log.warning("_org_for_customer: DB lookup failed: %s", exc)
        return None


def _resolve_org(data: dict) -> Optional[str]:
    """Try to extract the org_id from a Stripe event data object."""
    # Checkout sessions carry org_id in client_reference_id (set by the frontend)
    org_id = data.get("client_reference_id") or data.get("metadata", {}).get("org_id")
    if org_id:
        return org_id
    # Fall back to reverse-lookup via the Stripe customer ID
    customer_id = data.get("customer", "")
    if customer_id:
        return _org_for_customer(customer_id)
    return None


# ---------------------------------------------------------------------------
# Event handler
# ---------------------------------------------------------------------------

def handle_stripe_event(event: dict[str, Any]) -> dict[str, str]:
    """Process a verified Stripe event and update the org plan accordingly.

    Returns a human-readable result dict with keys ``action`` and ``org_id``.
    Safe to call from a FastAPI background task.
    """
    from selvo.api.auth import upgrade_org

    event_type: str = event.get("type", "unknown")
    data: dict = event.get("data", {}).get("object", {})

    log.info("stripe event: %s", event_type)

    # ── checkout.session.completed ──────────────────────────────────────────
    if event_type == "checkout.session.completed":
        org_id = _resolve_org(data)
        if not org_id:
            log.warning("checkout.session.completed: cannot resolve org_id")
            return {"action": "ignored", "reason": "unknown org"}

        customer_id = data.get("customer", "")
        price_id = (
            data.get("metadata", {}).get("price_id", "")
            or data.get("line_items", {}).get("data", [{}])[0]
               .get("price", {}).get("id", "")
        )
        plan = _PRICE_TO_PLAN.get(price_id, "pro")
        upgrade_org(org_id, plan, stripe_customer_id=customer_id or None)
        log.info("checkout completed: org=%s → plan=%s (price=%s)", org_id, plan, price_id)
        return {"action": "upgraded", "org_id": org_id, "plan": plan}

    # ── customer.subscription.created ───────────────────────────────────────
    elif event_type == "customer.subscription.created":
        org_id = _resolve_org(data)
        if not org_id:
            return {"action": "ignored", "reason": "unknown org"}
        items = data.get("items", {}).get("data", [])
        price_id = items[0].get("price", {}).get("id", "") if items else ""
        plan = _PRICE_TO_PLAN.get(price_id, "pro")
        upgrade_org(org_id, plan, stripe_customer_id=data.get("customer") or None)
        log.info("subscription created: org=%s → plan=%s", org_id, plan)
        return {"action": "upgraded", "org_id": org_id, "plan": plan}

    # ── customer.subscription.updated ───────────────────────────────────────
    elif event_type == "customer.subscription.updated":
        org_id = _resolve_org(data)
        if not org_id:
            return {"action": "ignored", "reason": "unknown org"}

        status = data.get("status", "")
        if status not in ("active", "trialing"):
            upgrade_org(org_id, "free")
            return {"action": "downgraded", "org_id": org_id, "plan": "free", "reason": status}

        items = data.get("items", {}).get("data", [])
        price_id = items[0].get("price", {}).get("id", "") if items else ""
        plan = _PRICE_TO_PLAN.get(price_id, "pro")
        upgrade_org(org_id, plan, stripe_customer_id=data.get("customer") or None)
        return {"action": "updated", "org_id": org_id, "plan": plan}

    # ── customer.subscription.deleted ───────────────────────────────────────
    elif event_type == "customer.subscription.deleted":
        org_id = _resolve_org(data)
        if not org_id:
            return {"action": "ignored", "reason": "unknown org"}
        upgrade_org(org_id, "free")
        log.info("subscription deleted: org=%s → free", org_id)
        return {"action": "downgraded", "org_id": org_id, "plan": "free"}

    # ── invoice.payment_failed ───────────────────────────────────────────────
    elif event_type == "invoice.payment_failed":
        org_id = _resolve_org(data)
        log.warning("payment failed: org=%s customer=%s", org_id or "?", data.get("customer", ""))
        return {"action": "payment_failed", "org_id": org_id or "unknown"}

    # ── invoice.paid ─────────────────────────────────────────────────────────
    elif event_type == "invoice.paid":
        org_id = _resolve_org(data)
        log.info("invoice paid: org=%s customer=%s amount=%s", org_id or "?",
                 data.get("customer", ""), data.get("amount_paid", "?"))
        return {"action": "invoice_paid", "org_id": org_id or "unknown"}

    # ── invoice.payment_action_required (3DS / bank auth) ───────────────────
    elif event_type == "invoice.payment_action_required":
        org_id = _resolve_org(data)
        hosted_url = data.get("hosted_invoice_url", "")
        log.warning("payment action required: org=%s url=%s", org_id or "?", hosted_url)
        return {"action": "payment_action_required", "org_id": org_id or "unknown"}

    # ── customer.deleted ─────────────────────────────────────────────────────
    elif event_type == "customer.deleted":
        customer_id = data.get("id", "")
        org_id = _org_for_customer(customer_id)
        if org_id:
            upgrade_org(org_id, "free")
            log.info("customer deleted: org=%s → free", org_id)
            return {"action": "downgraded", "org_id": org_id, "plan": "free"}
        return {"action": "ignored", "reason": "unknown customer"}

    else:
        return {"action": "ignored", "event_type": event_type}
