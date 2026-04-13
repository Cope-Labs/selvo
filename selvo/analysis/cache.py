"""
SQLite-backed result cache for selvo API calls.

Stored at ~/.cache/selvo/cache.db. Thread-safe via a module-level lock.
TTL-based expiry — stale entries are ignored (not auto-pruned from disk).

Usage:
    from selvo.analysis.cache import get, set_cache

    cached = get("repology_version:openssl")
    if cached is None:
        cached = await fetch(...)
        set_cache("repology_version:openssl", cached, ttl=3600)

Recommended TTLs:
    Repology versions/rdeps : 3600  (1h)
    OSV CVE lists           : 86400 (24h)
    EPSS scores             : 21600 (6h)
    CVSS scores             : 86400 (24h)
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

_CACHE_PATH = Path.home() / ".cache" / "selvo" / "cache.db"
_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(str(_CACHE_PATH), check_same_thread=False)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                key        TEXT    PRIMARY KEY,
                value      TEXT    NOT NULL,
                expires_at REAL    NOT NULL
            )
            """
        )
        c.commit()
        _conn = c
    return _conn


def get(key: str) -> Optional[Any]:
    """Return the cached value for *key*, or None if missing/expired."""
    with _lock:
        try:
            row = _get_conn().execute(
                "SELECT value FROM cache WHERE key=? AND expires_at > ?",
                (key, time.time()),
            ).fetchone()
            return json.loads(row[0]) if row else None
        except Exception:
            return None


def set_cache(key: str, value: Any, ttl: int) -> None:
    """Store *value* under *key* with an expiry of *ttl* seconds from now."""
    with _lock:
        try:
            conn = _get_conn()
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, value, expires_at) VALUES (?, ?, ?)",
                (key, json.dumps(value), time.time() + ttl),
            )
            conn.commit()
        except Exception:
            pass  # cache failure must never break the pipeline


def prune() -> int:
    """Delete expired entries. Returns the number of rows removed."""
    with _lock:
        try:
            conn = _get_conn()
            cur = conn.execute("DELETE FROM cache WHERE expires_at <= ?", (time.time(),))
            conn.commit()
            return cur.rowcount
        except Exception:
            return 0


def prune_old_metrics(days: int = 90) -> int:
    """Delete metrics rows older than *days* days. Returns the row count removed."""
    cutoff = time.time() - days * 86400
    with _lock:
        try:
            _ensure_metrics_table()
            conn = _get_conn()
            cur = conn.execute(
                "DELETE FROM metrics WHERE taken_at < ?", (cutoff,)
            )
            conn.commit()
            return cur.rowcount
        except Exception:
            return 0


def clear() -> int:
    """Delete ALL cache entries. Returns the number of rows removed."""
    with _lock:
        try:
            conn = _get_conn()
            cur = conn.execute("DELETE FROM cache")
            conn.commit()
            return cur.rowcount
        except Exception:
            return 0


def stats() -> dict[str, Any]:
    """Return {total, live, expired, size_kb} entry counts and disk size."""
    with _lock:
        try:
            conn = _get_conn()
            total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            live = conn.execute(
                "SELECT COUNT(*) FROM cache WHERE expires_at > ?", (time.time(),)
            ).fetchone()[0]
            size_bytes = _CACHE_PATH.stat().st_size if _CACHE_PATH.exists() else 0
            return {
                "total": total,
                "live": live,
                "expired": total - live,
                "size_kb": round(size_bytes / 1024, 1),
                "path": str(_CACHE_PATH),
            }
        except Exception:
            return {"total": 0, "live": 0, "expired": 0, "size_kb": 0.0, "path": str(_CACHE_PATH)}


# ---------------------------------------------------------------------------
# Snapshot / trend tracking
# ---------------------------------------------------------------------------

def _ensure_snapshot_table() -> None:
    conn = _get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ecosystem   TEXT    NOT NULL,
            taken_at    REAL    NOT NULL,
            data        TEXT    NOT NULL
        )
        """
    )
    conn.commit()


def _ensure_metrics_table() -> None:
    """Create the time-series trend metrics table if it doesn't exist."""
    conn = _get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS metrics (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            ecosystem        TEXT    NOT NULL,
            taken_at         REAL    NOT NULL,
            total_packages   INTEGER NOT NULL DEFAULT 0,
            cve_count        INTEGER NOT NULL DEFAULT 0,
            kev_count        INTEGER NOT NULL DEFAULT 0,
            weaponized_count INTEGER NOT NULL DEFAULT 0,
            avg_score        REAL    NOT NULL DEFAULT 0.0,
            max_score        REAL    NOT NULL DEFAULT 0.0,
            avg_epss         REAL    NOT NULL DEFAULT 0.0,
            max_epss         REAL    NOT NULL DEFAULT 0.0
        )
        """
    )
    conn.commit()


def save_snapshot(ecosystem: str, packages: list[Any]) -> None:
    """
    Persist a lightweight snapshot of the current package state for trend diffing.
    Each record: {name, cve_count, max_epss, max_cvss, score, upstream_version}
    """

    def _slim(pkg: Any) -> dict:
        return {
            "name": pkg.name,
            "ecosystem": getattr(pkg, "ecosystem", ""),
            "version": getattr(pkg, "version", ""),
            "cve_count": pkg.cve_count,
            "cve_ids": getattr(pkg, "cve_ids", []) or [],
            "max_epss": pkg.max_epss,
            "max_cvss": pkg.max_cvss,
            "in_cisa_kev": getattr(pkg, "in_cisa_kev", False),
            "exploit_maturity": getattr(pkg, "exploit_maturity", "none"),
            "score": pkg.score,
            "upstream_version": pkg.upstream_version,
            "reverse_dep_count": pkg.reverse_dep_count,
            "transitive_rdep_count": getattr(pkg, "transitive_rdep_count", 0),
            "version_source": getattr(pkg, "version_source", "reference"),
            "dependencies": (getattr(pkg, "dependencies", None) or [])[:30],
            "dependents": (getattr(pkg, "dependents", None) or [])[:30],
            "score_uncertainty": getattr(pkg, "score_uncertainty", 0.0),
            "score_lower": getattr(pkg, "score_lower", 0.0),
            "score_upper": getattr(pkg, "score_upper", 0.0),
            "health_state": getattr(pkg, "health_state", ""),
            "score_confidence": getattr(pkg, "score_confidence", ""),
        }

    with _lock:
        try:
            _ensure_snapshot_table()
            conn = _get_conn()
            conn.execute(
                "INSERT INTO snapshots (ecosystem, taken_at, data) VALUES (?, ?, ?)",
                (ecosystem, time.time(), json.dumps([_slim(p) for p in packages])),
            )
            # Keep only last 10 snapshots per ecosystem to avoid unbounded growth
            conn.execute(
                """
                DELETE FROM snapshots WHERE ecosystem=? AND id NOT IN (
                    SELECT id FROM snapshots WHERE ecosystem=? ORDER BY taken_at DESC LIMIT 10
                )
                """,
                (ecosystem, ecosystem),
            )
            conn.commit()
        except Exception:
            pass


def load_last_snapshot(ecosystem: str) -> list[dict] | None:
    """Return the most recent snapshot for *ecosystem*, or None if none exists."""
    with _lock:
        try:
            _ensure_snapshot_table()
            row = _get_conn().execute(
                "SELECT data, taken_at FROM snapshots WHERE ecosystem=? ORDER BY taken_at DESC LIMIT 1",
                (ecosystem,),
            ).fetchone()
            if row:
                return json.loads(row[0]), row[1]  # type: ignore[return-value]
        except Exception:
            pass
    return None


def diff_snapshots(
    previous: list[dict], current: list[Any]
) -> dict[str, list[dict]]:
    """
    Compare a previous snapshot (list of dicts) with current packages.
    Returns {new_cves, epss_jumps, score_changes, new_packages, resolved}.
    """
    prev_map = {r["name"]: r for r in previous}
    curr_map = {p.name: p for p in current}

    new_packages = [
        {"name": n, "score": p.score, "cve_count": p.cve_count}
        for n, p in curr_map.items()
        if n not in prev_map
    ]

    new_cves: list[dict] = []
    epss_jumps: list[dict] = []
    score_changes: list[dict] = []
    resolved: list[dict] = []

    for name, pkg in curr_map.items():
        if name not in prev_map:
            continue
        prev = prev_map[name]

        cve_delta = pkg.cve_count - prev.get("cve_count", 0)
        if cve_delta > 0:
            new_cves.append({"name": name, "delta": cve_delta, "total": pkg.cve_count})
        elif cve_delta < 0:
            resolved.append({"name": name, "delta": abs(cve_delta), "total": pkg.cve_count})

        epss_prev = prev.get("max_epss", 0.0)
        epss_jump = pkg.max_epss - epss_prev
        if epss_jump >= 0.10:  # ≥10 percentage point jump is notable
            epss_jumps.append({
                "name": name,
                "prev": round(epss_prev, 3),
                "now": round(pkg.max_epss, 3),
                "delta": round(epss_jump, 3),
            })

        score_delta = pkg.score - prev.get("score", 0.0)
        if abs(score_delta) >= 3.0:  # ≥3 point swing in composite score
            score_changes.append({
                "name": name,
                "prev": round(prev.get("score", 0.0), 1),
                "now": round(pkg.score, 1),
                "delta": round(score_delta, 1),
            })

    return {
        "new_packages": new_packages,
        "new_cves": sorted(new_cves, key=lambda x: x["delta"], reverse=True),
        "epss_jumps": sorted(epss_jumps, key=lambda x: x["delta"], reverse=True),
        "score_changes": sorted(score_changes, key=lambda x: abs(x["delta"]), reverse=True),
        "resolved": resolved,
    }
