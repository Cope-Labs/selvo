"""OSV local mirror — download and serve the OSV vulnerability database offline.

OSV publishes a GCS bucket export at:
  https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip

Each zip contains one JSON file per advisory. We parse them into a local
SQLite database so ``enrich_cve`` can skip the live API entirely when the
mirror exists and is fresh (< 24 h old by default).

Supported OSV ecosystems (selvo name → OSV bucket path):
    debian  → Debian
    ubuntu  → Ubuntu
    fedora  → Red Hat
    alpine  → Alpine

Usage:
    selvo sync osv
    selvo sync osv --ecosystems debian,alpine

Programmatic:
    from selvo.analysis.osv_local import sync_osv, lookup_local, is_current
"""
from __future__ import annotations

import io
import json
import logging
import sqlite3
import threading
import time
import zipfile
from pathlib import Path
from typing import Optional

import httpx

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database location and schema
# ---------------------------------------------------------------------------

_OSV_DB_PATH = Path.home() / ".cache" / "selvo" / "osv.db"
_OSV_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
_STALENESS_SECONDS = 86400  # 24 h — refresh once daily

_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None

# Maps selvo ecosystem names → OSV bucket path component
ECOSYSTEM_MAP: dict[str, str] = {
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "fedora": "Red Hat",
    "alpine": "Alpine",
}


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _OSV_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(str(_OSV_DB_PATH), check_same_thread=False)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS advisories (
                id          TEXT NOT NULL,
                ecosystem   TEXT NOT NULL,
                package     TEXT NOT NULL,
                introduced  TEXT,
                fixed       TEXT,
                aliases     TEXT,          -- JSON list of strings
                severity    TEXT,          -- JSON CVSS blob or plain string
                summary     TEXT,
                PRIMARY KEY (id, ecosystem, package)
            );
            CREATE INDEX IF NOT EXISTS idx_pkg ON advisories(ecosystem, package);
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        c.commit()
        _conn = c
    return _conn


# ---------------------------------------------------------------------------
# Download + parse helpers
# ---------------------------------------------------------------------------

def _advisory_rows(advisory: dict, osv_eco: str) -> list[dict]:
    """Flatten one OSV advisory dict into a list of (ecosystem, package) rows."""
    vuln_id = advisory.get("id", "")
    aliases = json.dumps(advisory.get("aliases", []))
    summary = advisory.get("summary", "")

    severity_raw = advisory.get("severity") or advisory.get("database_specific", {}).get("severity", "")
    if isinstance(severity_raw, list):
        severity = json.dumps(severity_raw)
    else:
        severity = str(severity_raw)

    rows = []
    for affected in advisory.get("affected", []):
        pkg_info = affected.get("package", {})
        eco = pkg_info.get("ecosystem", osv_eco)
        pkg_name = pkg_info.get("name", "")
        if not pkg_name:
            continue

        # Walk version ranges to extract introduced/fixed pairs
        ranges = affected.get("ranges", [])
        pairs: list[tuple[str, str]] = []
        for r in ranges:
            introduced = fixed = ""
            for ev in r.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
            pairs.append((introduced, fixed))

        if not pairs:
            pairs = [("", "")]

        for introduced, fixed in pairs:
            rows.append(
                {
                    "id": vuln_id,
                    "ecosystem": eco,
                    "package": pkg_name.lower(),
                    "introduced": introduced,
                    "fixed": fixed,
                    "aliases": aliases,
                    "severity": severity,
                    "summary": summary,
                }
            )
    return rows


def _download_and_ingest(osv_eco: str, conn: sqlite3.Connection) -> int:
    """Download the all.zip for *osv_eco* and ingest into *conn*. Returns row count."""
    url = _OSV_BASE_URL.format(ecosystem=osv_eco)
    log.debug("osv_local: downloading %s", url)
    try:
        with httpx.Client(follow_redirects=True, timeout=120.0) as client:
            resp = client.get(url, headers={"User-Agent": "selvo/0.1 (osv-mirror)"})
            resp.raise_for_status()
    except Exception as exc:
        log.warning("osv_local: download failed for %s: %s", osv_eco, exc)
        return 0

    rows_inserted = 0
    try:
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        # Delete existing entries for this ecosystem so we're idempotent
        conn.execute("DELETE FROM advisories WHERE ecosystem LIKE ?", (f"{osv_eco}%",))
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                advisory = json.loads(zf.read(name))
            except Exception:
                continue
            for row in _advisory_rows(advisory, osv_eco):
                conn.execute(
                    """
                    INSERT OR REPLACE INTO advisories
                        (id, ecosystem, package, introduced, fixed, aliases, severity, summary)
                    VALUES
                        (:id, :ecosystem, :package, :introduced, :fixed, :aliases, :severity, :summary)
                    """,
                    row,
                )
                rows_inserted += 1
        conn.commit()
    except Exception as exc:
        log.warning("osv_local: parse error for %s: %s", osv_eco, exc)

    return rows_inserted


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_current(max_age_seconds: int = _STALENESS_SECONDS) -> bool:
    """Return True if the local mirror exists and is fresh enough."""
    if not _OSV_DB_PATH.exists():
        return False
    with _lock:
        try:
            row = _get_conn().execute(
                "SELECT value FROM meta WHERE key='synced_at'"
            ).fetchone()
            if row is None:
                return False
            return (time.time() - float(row[0])) < max_age_seconds
        except Exception:
            return False


def db_stats() -> dict:
    """Return basic statistics about the local mirror."""
    if not _OSV_DB_PATH.exists():
        return {"exists": False}
    with _lock:
        try:
            conn = _get_conn()
            total = conn.execute("SELECT COUNT(*) FROM advisories").fetchone()[0]
            eco_rows = conn.execute(
                "SELECT ecosystem, COUNT(*) FROM advisories GROUP BY ecosystem ORDER BY ecosystem"
            ).fetchall()
            synced_row = conn.execute("SELECT value FROM meta WHERE key='synced_at'").fetchone()
            synced_at = float(synced_row[0]) if synced_row else 0.0
            age_h = (time.time() - synced_at) / 3600 if synced_at else None
            return {
                "exists": True,
                "total_rows": total,
                "ecosystems": {eco: count for eco, count in eco_rows},
                "synced_at": synced_at,
                "age_hours": round(age_h, 1) if age_h is not None else None,
                "db_path": str(_OSV_DB_PATH),
                "db_size_mb": round(_OSV_DB_PATH.stat().st_size / 1_048_576, 1),
            }
        except Exception as exc:
            return {"exists": True, "error": str(exc)}


def sync_osv(
    ecosystems: Optional[list[str]] = None,
    progress_cb: Optional[callable] = None,  # type: ignore[type-arg]
) -> dict[str, int]:
    """Download OSV advisories for *ecosystems* into the local SQLite mirror.

    Args:
        ecosystems: List of selvo ecosystem names to sync (e.g. ["debian", "alpine"]).
                    Defaults to all four supported ecosystems.
        progress_cb: Optional callable ``(ecosystem_name, rows_inserted)`` called
                     after each ecosystem finishes. Useful for progress bars.

    Returns:
        Dict mapping ``{ecosystem_name: rows_inserted}``.
    """
    if ecosystems is None:
        ecosystems = list(ECOSYSTEM_MAP.keys())

    results: dict[str, int] = {}
    with _lock:
        conn = _get_conn()
        for selvo_eco in ecosystems:
            osv_eco = ECOSYSTEM_MAP.get(selvo_eco)
            if not osv_eco:
                log.warning("osv_local.sync_osv: unknown ecosystem %r — skipped", selvo_eco)
                results[selvo_eco] = 0
                continue
            rows = _download_and_ingest(osv_eco, conn)
            results[selvo_eco] = rows
            if progress_cb:
                progress_cb(selvo_eco, rows)
            log.info("osv_local: synced %s → %d rows", selvo_eco, rows)

        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('synced_at', ?)",
            (str(time.time()),),
        )
        conn.commit()

    return results


def lookup_local(pkg_name: str, ecosystem: str, version: Optional[str] = None) -> list[str]:
    """Look up CVEs for a package in the local mirror.

    Args:
        pkg_name:  Package name (case-insensitive).
        ecosystem: selvo ecosystem name ("debian", "alpine", etc.).
        version:   Installed version string. When given, only advisories whose
                   ``fixed`` version is absent (version unknown) or whose range
                   includes the installed version are returned.  When omitted,
                   all advisories for the package are returned.

    Returns:
        List of CVE/GHSA IDs (deduplicated).
    """
    osv_eco = ECOSYSTEM_MAP.get(ecosystem)
    if not osv_eco:
        return []

    with _lock:
        try:
            rows = _get_conn().execute(
                """
                SELECT id, aliases, introduced, fixed FROM advisories
                WHERE package = ? AND ecosystem LIKE ?
                """,
                (pkg_name.lower(), f"{osv_eco}%"),
            ).fetchall()
        except Exception:
            return []

    ids: list[str] = []
    import re
    _CVE_RE = re.compile(r"^(CVE-\d{4}-\d+|GHSA-[0-9a-z-]+)$", re.IGNORECASE)
    _DEBIAN_CVE_RE = re.compile(r"^DEBIAN-(CVE-\d{4}-\d+)$", re.IGNORECASE)

    for row_id, aliases_json, introduced, fixed in rows:
        # Simple version gating: if we know the installed version and a fix
        # version is recorded and the installed version >= fixed, skip it.
        if version and version != "unknown" and fixed:
            try:
                from packaging.version import Version
                if Version(version) >= Version(fixed):
                    continue  # already at or past the fixed version
            except Exception:
                pass  # unparseable version — include conservatively

        # Collect canonical CVE IDs
        candidates = [row_id]
        try:
            candidates.extend(json.loads(aliases_json))
        except Exception:
            pass

        for cid in candidates:
            if _CVE_RE.match(cid):
                ids.append(cid.upper() if cid.upper().startswith("CVE-") else cid)
            else:
                m = _DEBIAN_CVE_RE.match(cid)
                if m:
                    ids.append(m.group(1).upper())

    return list(dict.fromkeys(ids))  # deduplicate, preserve order
