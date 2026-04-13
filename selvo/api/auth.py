"""API key authentication for the selvo SaaS REST API.

Keys are stored as SHA-256 hashes in ~/.cache/selvo/api_keys.db so the
plaintext is never persisted after initial generation.

Key format: ``sk_{org_slug}_{32-hex-token}``

Plans and daily rate limits::

    free        5 requests/day, 1 analyze/day   (default for new orgs)
    pro         10 000 requests/day, 100 analyze/day
    enterprise  1 000 000 requests/day, 10 000 analyze/day

Usage::

    from selvo.api.auth import generate_api_key, verify_api_key, OrgContext

    # --- admin side ---
    key = generate_api_key("acme-corp", plan="pro")   # printed once, never stored
    print(key)  # sk_acme-cor_a1b2c3d4...

    # --- request side ---
    ctx = verify_api_key(request.headers["X-API-Key"])
    if ctx is None:
        raise HTTPException(401)
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_DB_PATH = Path.home() / ".cache" / "selvo" / "api_keys.db"
_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None

# Daily request + analyze quotas per plan
PLAN_LIMITS: dict[str, dict[str, int]] = {
    "free":       {"requests_per_day": 5,         "analyze_per_day": 1,     "max_keys": 3},
    "pro":        {"requests_per_day": 10_000,     "analyze_per_day": 100,   "max_keys": 10},
    "enterprise": {"requests_per_day": 1_000_000,  "analyze_per_day": 10_000, "max_keys": 50},
}


@dataclass
class OrgContext:
    """Authenticated request context attached to ``request.state.org``."""
    org_id: str
    plan: str   # "free" | "pro" | "enterprise"
    key_id: int


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_conn() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            c = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS orgs (
                    org_id              TEXT PRIMARY KEY,
                    name                TEXT NOT NULL,
                    email               TEXT NOT NULL DEFAULT '',
                    plan                TEXT NOT NULL DEFAULT 'free',
                    stripe_customer_id  TEXT,
                    created_at          REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS api_keys (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id         TEXT NOT NULL REFERENCES orgs(org_id),
                    key_hash       TEXT NOT NULL UNIQUE,
                    plan           TEXT NOT NULL DEFAULT 'free',
                    active         INTEGER NOT NULL DEFAULT 1,
                    created_at     REAL NOT NULL,
                    last_used_at   REAL,
                    requests_today INTEGER NOT NULL DEFAULT 0,
                    analyze_today  INTEGER NOT NULL DEFAULT 0,
                    day_start      REAL    NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_key_hash ON api_keys(key_hash);
                CREATE INDEX IF NOT EXISTS idx_org_id   ON api_keys(org_id);
                CREATE TABLE IF NOT EXISTS webhooks (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id     TEXT NOT NULL REFERENCES orgs(org_id),
                    url        TEXT NOT NULL,
                    kind       TEXT NOT NULL DEFAULT 'generic',
                    active     INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(org_id);
                CREATE TABLE IF NOT EXISTS events (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind       TEXT NOT NULL,
                    detail     TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
                -- Per-org package acknowledgements. Stores a hash of the
                -- package's cve_ids at ack time so we can re-surface the
                -- package when the CVE set changes. UNIQUE on (org, pkg) so
                -- a second ack overwrites the first.
                CREATE TABLE IF NOT EXISTS pkg_acks (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id      TEXT NOT NULL REFERENCES orgs(org_id),
                    pkg_name    TEXT NOT NULL,
                    ecosystem   TEXT NOT NULL DEFAULT '',
                    cve_hash    TEXT NOT NULL DEFAULT '',
                    reason      TEXT NOT NULL DEFAULT '',
                    acked_at    REAL NOT NULL,
                    UNIQUE(org_id, pkg_name)
                );
                CREATE INDEX IF NOT EXISTS idx_pkg_acks_org ON pkg_acks(org_id);
                """
            )
            c.commit()
            _conn = c
        return _conn


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _today_start() -> float:
    """Unix timestamp of midnight UTC for the current day."""
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register_org(
    org_id: str,
    name: str,
    email: str = "",
    plan: str = "free",
) -> None:
    """Register a new organisation (idempotent — does nothing if already exists)."""
    with _lock:
        conn = _get_conn()
        conn.execute(
            "INSERT OR IGNORE INTO orgs (org_id, name, email, plan, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (org_id, name, email, plan, time.time()),
        )
        conn.commit()


def count_org_active_keys(org_id: str) -> int:
    """Return the number of active keys for *org_id*."""
    with _lock:
        row = _get_conn().execute(
            "SELECT COUNT(*) FROM api_keys WHERE org_id=? AND active=1",
            (org_id,),
        ).fetchone()
    return row[0] if row else 0


def generate_api_key(org_id: str, plan: str = "free") -> str:
    """Create a new API key for *org_id* and store its SHA-256 hash.

    Returns the **plaintext** key — store it safely, it is not recoverable
    after this function returns.

    Raises ``ValueError`` if the org has reached its plan's key cap.
    """
    max_keys = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["max_keys"]
    if count_org_active_keys(org_id) >= max_keys:
        raise ValueError(
            f"Key limit reached ({max_keys} active keys for '{plan}' plan). "
            "Revoke an existing key or upgrade your plan."
        )

    slug = org_id[:8].lower().replace(" ", "-")
    token = secrets.token_hex(16)
    key = f"sk_{slug}_{token}"
    key_hash = _hash_key(key)

    with _lock:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO api_keys "
            "(org_id, key_hash, plan, active, created_at, day_start) "
            "VALUES (?, ?, ?, 1, ?, ?)",
            (org_id, key_hash, plan, time.time(), _today_start()),
        )
        conn.commit()

    return key


def revoke_api_key(key_hash: str, org_id: str | None = None) -> bool:
    """Deactivate a key by its SHA-256 hash.

    When *org_id* is provided, the key must belong to that org — prevents
    cross-org revocation (IDOR). Returns True if a key was actually revoked.
    """
    with _lock:
        conn = _get_conn()
        if org_id:
            cur = conn.execute(
                "UPDATE api_keys SET active=0 WHERE key_hash=? AND org_id=?",
                (key_hash, org_id),
            )
        else:
            cur = conn.execute(
                "UPDATE api_keys SET active=0 WHERE key_hash=?", (key_hash,)
            )
        conn.commit()
        return cur.rowcount > 0


def list_org_keys(org_id: str) -> list[dict]:
    """Return metadata for all keys belonging to *org_id*."""
    with _lock:
        rows = _get_conn().execute(
            "SELECT id, org_id, key_hash, plan, active, created_at, last_used_at, "
            "requests_today, analyze_today "
            "FROM api_keys WHERE org_id=? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    cols = ["id", "org_id", "key_hash", "plan", "active", "created_at",
            "last_used_at", "requests_today", "analyze_today"]
    return [dict(zip(cols, row)) for row in rows]


# Per-key IP tracking for sharing detection
# {key_hash: {ip: last_seen_timestamp}}
_key_ips: dict[str, dict[str, float]] = {}
_KEY_IP_WINDOW = 86400  # 24 hours
_KEY_IP_MAX = {"free": 3, "pro": 10, "enterprise": 50}


def check_key_sharing(key_hash: str, ip: str, plan: str) -> bool:
    """Track IPs per key. Returns True if within limits, False if sharing detected."""
    now = time.time()
    ips = _key_ips.get(key_hash, {})
    # Prune old entries
    ips = {k: v for k, v in ips.items() if now - v < _KEY_IP_WINDOW}
    ips[ip] = now
    _key_ips[key_hash] = ips
    max_ips = _KEY_IP_MAX.get(plan, 3)
    return len(ips) <= max_ips


def get_key_ip_count(key_hash: str) -> int:
    """Return number of distinct IPs that used this key in the last 24h."""
    now = time.time()
    ips = _key_ips.get(key_hash, {})
    return sum(1 for v in ips.values() if now - v < _KEY_IP_WINDOW)


def verify_api_key(key: str) -> Optional[OrgContext]:
    """Verify *key*, enforce rate limits, and increment the request counter.

    Returns an :class:`OrgContext` on success or ``None`` if the key is
    unknown, inactive, or rate-limited.
    """
    key_hash = _hash_key(key)
    today = _today_start()

    with _lock:
        conn = _get_conn()
        row = conn.execute(
            "SELECT id, org_id, plan, active, requests_today, day_start "
            "FROM api_keys WHERE key_hash=?",
            (key_hash,),
        ).fetchone()

        if row is None:
            return None

        key_id, org_id, plan, active, requests_today, day_start = row

        if not active:
            return None

        # New UTC day → reset counters
        if day_start < today:
            requests_today = 0
            conn.execute(
                "UPDATE api_keys SET requests_today=0, analyze_today=0, "
                "day_start=? WHERE id=?",
                (today, key_id),
            )

        # Rate-limit check
        limit = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["requests_per_day"]
        if requests_today >= limit:
            log.warning("rate-limit: org=%s plan=%s requests_today=%d", org_id, plan, requests_today)
            return None

        # Increment request counter
        conn.execute(
            "UPDATE api_keys SET requests_today=requests_today+1, "
            "last_used_at=? WHERE id=?",
            (time.time(), key_id),
        )
        conn.commit()

    return OrgContext(org_id=org_id, plan=plan, key_id=key_id)


def can_analyze(key_id: int, plan: str) -> bool:
    """Return True if the key has remaining ``analyze`` quota for today."""
    limit = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["analyze_per_day"]
    with _lock:
        row = _get_conn().execute(
            "SELECT analyze_today, day_start FROM api_keys WHERE id=?", (key_id,)
        ).fetchone()
    if row is None:
        return False
    analyze_today, day_start = row
    if day_start < _today_start():
        return True  # implicit reset for new day
    return analyze_today < limit


def increment_analyze(key_id: int) -> None:
    """Increment the ``analyze`` daily counter for *key_id*."""
    with _lock:
        conn = _get_conn()
        conn.execute(
            "UPDATE api_keys SET analyze_today=analyze_today+1 WHERE id=?",
            (key_id,),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Webhook management
# ---------------------------------------------------------------------------

def add_webhook(org_id: str, url: str, kind: str = "generic") -> int:
    """Register a webhook URL for *org_id*. Returns the webhook ID."""
    with _lock:
        conn = _get_conn()
        cur = conn.execute(
            "INSERT INTO webhooks (org_id, url, kind, active, created_at) "
            "VALUES (?, ?, ?, 1, ?)",
            (org_id, url, kind, time.time()),
        )
        conn.commit()
        return cur.lastrowid  # type: ignore[return-value]


def list_webhooks(org_id: str) -> list[dict]:
    """Return all webhooks for *org_id*."""
    with _lock:
        rows = _get_conn().execute(
            "SELECT id, org_id, url, kind, active, created_at "
            "FROM webhooks WHERE org_id=? ORDER BY created_at DESC",
            (org_id,),
        ).fetchall()
    cols = ["id", "org_id", "url", "kind", "active", "created_at"]
    return [dict(zip(cols, row)) for row in rows]


def delete_webhook(webhook_id: int, org_id: str) -> bool:
    """Delete a webhook. Scoped to org for safety."""
    with _lock:
        conn = _get_conn()
        cur = conn.execute(
            "DELETE FROM webhooks WHERE id=? AND org_id=?",
            (webhook_id, org_id),
        )
        conn.commit()
        return cur.rowcount > 0


def track_event(kind: str, detail: str = "") -> None:
    """Record a lightweight event for analytics. Fire-and-forget."""
    try:
        with _lock:
            _get_conn().execute(
                "INSERT INTO events (kind, detail, created_at) VALUES (?, ?, ?)",
                (kind, detail, time.time()),
            )
            _get_conn().commit()
    except Exception:
        pass  # never fail the request over analytics


def get_event_counts(days: int = 30) -> dict[str, int]:
    """Return event counts by kind for the last N days."""
    cutoff = time.time() - (days * 86400)
    with _lock:
        rows = _get_conn().execute(
            "SELECT kind, COUNT(*) FROM events WHERE created_at > ? GROUP BY kind",
            (cutoff,),
        ).fetchall()
    return {row[0]: row[1] for row in rows}


def upgrade_org(
    org_id: str,
    plan: str,
    stripe_customer_id: Optional[str] = None,
) -> None:
    """Update the plan for *org_id* and all its active API keys."""
    with _lock:
        conn = _get_conn()
        conn.execute(
            "UPDATE orgs SET plan=?, "
            "stripe_customer_id=COALESCE(?, stripe_customer_id) "
            "WHERE org_id=?",
            (plan, stripe_customer_id, org_id),
        )
        conn.execute(
            "UPDATE api_keys SET plan=? WHERE org_id=? AND active=1",
            (plan, org_id),
        )
        conn.commit()
