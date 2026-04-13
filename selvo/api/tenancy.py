"""Per-org snapshot isolation for multi-tenant deployments.

All snapshot read/write operations are namespaced under a stable per-org key
prefix derived from ``org_id``.  The underlying storage is the shared
``cache.db``; no schema changes are required.

The prefix format is ``org:{safe_org_id}:`` where ``safe_org_id`` is the
first 32 characters of the org_id with ``:``, ``/`` and whitespace
normalised to ``_``.

Example::

    save_org_snapshot("acme-corp", "debian", packages)
    data, ts = load_org_snapshot("acme-corp", "debian")
"""
from __future__ import annotations

from typing import Any, Optional

_ORG_PREFIX = "org:"
_MAX_ORG_SLUG = 32


def _safe_slug(org_id: str) -> str:
    """Sanitise an org_id for safe use as a cache key component."""
    out = []
    for ch in org_id:
        if ch in (":", "/", "\\", " ", "\t", "\n"):
            out.append("_")
        else:
            out.append(ch)
    return "".join(out)[:_MAX_ORG_SLUG]


def org_ecosystem_key(org_id: str, ecosystem: str) -> str:
    """Return the namespaced cache key for ``(org_id, ecosystem)``."""
    return f"{_ORG_PREFIX}{_safe_slug(org_id)}:{ecosystem}"


def save_org_snapshot(org_id: str, ecosystem: str, packages: list[Any]) -> None:
    """Save *packages* as a snapshot scoped to *org_id*."""
    from selvo.analysis.cache import save_snapshot
    save_snapshot(org_ecosystem_key(org_id, ecosystem), packages)


def load_org_snapshot(
    org_id: str, ecosystem: str
) -> Optional[tuple[list[dict], float]]:
    """Load the most-recent snapshot for *org_id* + *ecosystem*.

    Returns ``(packages, taken_at_epoch)`` or ``None`` if not found.
    """
    from selvo.analysis.cache import load_last_snapshot
    return load_last_snapshot(org_ecosystem_key(org_id, ecosystem))


def record_org_metric(org_id: str, ecosystem: str, packages: list[Any]) -> None:
    """Record trend metrics scoped to *org_id*."""
    from selvo.analysis.trend import record_metric
    record_metric(org_ecosystem_key(org_id, ecosystem), packages)


def load_org_metrics(org_id: str, ecosystem: str, days: int = 90) -> list[dict]:
    """Return historical trend metrics for *org_id* + *ecosystem*."""
    from selvo.analysis.trend import load_metrics
    return load_metrics(org_ecosystem_key(org_id, ecosystem), days=days)
