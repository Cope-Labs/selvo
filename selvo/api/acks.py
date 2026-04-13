"""Per-package acknowledgements.

A user can mark a package "acknowledged" from the dashboard — they've
reviewed it, decided not to act on it right now, and don't want it
cluttering the default packages view. The ack is sticky **until the
package's CVE set changes**, at which point the package re-surfaces so
the user sees the new state.

The "until CVE set changes" part is load-bearing. Without it, a user
could ack a package once and never be alerted again even if a critical
new CVE is discovered. With it, ack means "I've triaged the current
view," not "ignore this forever."

How we detect the change: we hash the sorted list of cve_ids at ack
time. On every render we recompute the hash from the current snapshot;
if it differs, the ack is considered stale and the package shows up
again.

Exposed surface:
  - ack(org_id, pkg_name, cve_ids, reason="", ecosystem="")  -> None
  - unack(org_id, pkg_name)                                  -> None
  - load_acks(org_id)  -> dict[pkg_name, {cve_hash, reason, acked_at, ecosystem}]
  - cve_hash(cve_ids)  -> str   (helper for callers and renderers)
"""
from __future__ import annotations

import hashlib
import time
from typing import Iterable

from selvo.api.auth import _get_conn, _lock


def cve_hash(cve_ids: Iterable[str]) -> str:
    """Stable hash of a CVE-id set (order-independent). Empty set hashes
    to a constant so we can tell "ack on no CVEs" apart from "ack on
    [CVE-x]" via comparison, but two acks of the same set always match."""
    joined = ",".join(sorted({c.strip().upper() for c in cve_ids if c}))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def ack(
    org_id: str,
    pkg_name: str,
    cve_ids: Iterable[str],
    reason: str = "",
    ecosystem: str = "",
) -> None:
    """Mark a package as acknowledged for *org_id*. Re-acking with new
    cve_ids replaces the previous ack (the UNIQUE constraint enforces this)."""
    h = cve_hash(cve_ids)
    with _lock:
        _get_conn().execute(
            """
            INSERT INTO pkg_acks (org_id, pkg_name, ecosystem, cve_hash, reason, acked_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(org_id, pkg_name) DO UPDATE SET
                ecosystem = excluded.ecosystem,
                cve_hash  = excluded.cve_hash,
                reason    = excluded.reason,
                acked_at  = excluded.acked_at
            """,
            (org_id, pkg_name, ecosystem, h, reason[:500], time.time()),
        )
        _get_conn().commit()


def unack(org_id: str, pkg_name: str) -> None:
    with _lock:
        _get_conn().execute(
            "DELETE FROM pkg_acks WHERE org_id=? AND pkg_name=?",
            (org_id, pkg_name),
        )
        _get_conn().commit()


def load_acks(org_id: str) -> dict[str, dict]:
    """Return {pkg_name: {cve_hash, reason, acked_at, ecosystem}} for *org_id*."""
    with _lock:
        rows = _get_conn().execute(
            "SELECT pkg_name, ecosystem, cve_hash, reason, acked_at FROM pkg_acks WHERE org_id=?",
            (org_id,),
        ).fetchall()
    return {
        r[0]: {"ecosystem": r[1], "cve_hash": r[2], "reason": r[3], "acked_at": r[4]}
        for r in rows
    }


def is_acked(pkg: dict, acks: dict[str, dict]) -> bool:
    """True iff this package is acked AND its current CVE set matches the
    hash captured at ack time. The render layer uses this to decide whether
    to hide the package by default. Pass the dict returned by ``load_acks``."""
    name = pkg.get("name", "")
    if name not in acks:
        return False
    return acks[name]["cve_hash"] == cve_hash(pkg.get("cve_ids", []) or [])
