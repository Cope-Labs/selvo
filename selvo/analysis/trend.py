"""Time-series trend metrics store for selvo.

Records scalar metrics at each pipeline run, enabling trend sparklines and
posture-over-time analysis. Metrics live in a dedicated `metrics` table in
the existing selvo SQLite cache DB.

Stored fields per snapshot:
    ecosystem        — ecosystem key (debian, fedora, all, …)
    taken_at         — Unix timestamp
    total_packages   — count of packages in this run
    cve_count        — total CVEs across all packages
    kev_count        — packages with at least one CISA KEV CVE
    weaponized_count — packages with weaponized exploit_maturity
    avg_score        — mean composite risk score
    max_score        — highest composite risk score
    avg_epss         — mean max_epss across packages with CVEs
    max_epss         — global highest max_epss

Usage:
    from selvo.analysis.trend import record_metric, load_metrics
    record_metric("debian", packages)
    rows = load_metrics("debian", days=90)  # newest first
"""
from __future__ import annotations

import time
from typing import Any


# ── Write ─────────────────────────────────────────────────────────────────────

def record_metric(ecosystem: str, packages: list[Any]) -> None:
    """Record summary metrics for the current package list into the trend store."""
    from selvo.analysis.cache import _get_conn, _lock, _ensure_metrics_table  # type: ignore[attr-defined]

    pkgs_with_cves = [p for p in packages if (getattr(p, "cve_count", 0) or 0) > 0]
    scores = [getattr(p, "score", 0.0) or 0.0 for p in packages]
    epss_vals = [getattr(p, "max_epss", 0.0) or 0.0 for p in pkgs_with_cves]

    row: dict[str, Any] = {
        "ecosystem": ecosystem,
        "taken_at": time.time(),
        "total_packages": len(packages),
        "cve_count": sum(getattr(p, "cve_count", 0) or 0 for p in packages),
        "kev_count": sum(1 for p in packages if getattr(p, "in_cisa_kev", False)),
        "weaponized_count": sum(
            1 for p in packages if (getattr(p, "exploit_maturity", "") or "") == "weaponized"
        ),
        "avg_score": round(sum(scores) / len(scores), 2) if scores else 0.0,
        "max_score": round(max(scores), 2) if scores else 0.0,
        "avg_epss": round(sum(epss_vals) / len(epss_vals), 4) if epss_vals else 0.0,
        "max_epss": round(max(epss_vals), 4) if epss_vals else 0.0,
    }

    with _lock:
        try:
            _ensure_metrics_table()
            _get_conn().execute(
                """
                INSERT INTO metrics
                  (ecosystem, taken_at, total_packages, cve_count, kev_count,
                   weaponized_count, avg_score, max_score, avg_epss, max_epss)
                VALUES
                  (:ecosystem, :taken_at, :total_packages, :cve_count,
                   :kev_count, :weaponized_count, :avg_score, :max_score,
                   :avg_epss, :max_epss)
                """,
                row,
            )
            _get_conn().commit()
        except Exception:
            pass  # trend failure must never break the pipeline


# ── Read ──────────────────────────────────────────────────────────────────────

_COLS = (
    "taken_at", "total_packages", "cve_count", "kev_count",
    "weaponized_count", "avg_score", "max_score", "avg_epss", "max_epss",
)


def prune_metrics(max_age_days: int = 90) -> int:
    """Delete trend metric rows older than *max_age_days* days.

    Returns the number of rows removed. Safe to call regularly — failures are
    swallowed so they never interrupt the analysis pipeline.
    """
    from selvo.analysis.cache import prune_old_metrics
    return prune_old_metrics(max_age_days)


def load_metrics(ecosystem: str = "all", days: int = 90) -> list[dict]:
    """Return trend metric rows for *ecosystem* from the last *days* days (oldest first)."""
    from selvo.analysis.cache import _get_conn, _lock, _ensure_metrics_table  # type: ignore[attr-defined]

    cutoff = time.time() - days * 86_400
    with _lock:
        try:
            _ensure_metrics_table()
            rows = _get_conn().execute(
                f"""
                SELECT {', '.join(_COLS)}
                FROM   metrics
                WHERE  ecosystem = ? AND taken_at >= ?
                ORDER  BY taken_at ASC
                """,
                (ecosystem, cutoff),
            ).fetchall()
            return [dict(zip(_COLS, r)) for r in rows]
        except Exception:
            return []


def load_all_ecosystems(days: int = 90) -> dict[str, list[dict]]:
    """Return trend metrics keyed by ecosystem (oldest first per ecosystem)."""
    from selvo.analysis.cache import _get_conn, _lock, _ensure_metrics_table  # type: ignore[attr-defined]

    cutoff = time.time() - days * 86_400
    with _lock:
        try:
            _ensure_metrics_table()
            rows = _get_conn().execute(
                f"""
                SELECT ecosystem, {', '.join(_COLS)}
                FROM   metrics
                WHERE  taken_at >= ?
                ORDER  BY taken_at ASC
                """,
                (cutoff,),
            ).fetchall()
        except Exception:
            return {}

    result: dict[str, list[dict]] = {}
    for row in rows:
        eco = row[0]
        result.setdefault(eco, []).append(dict(zip(_COLS, row[1:])))
    return result


# ── SVG sparkline renderer (self-contained, no JS) ────────────────────────────

def _sparkline_svg(
    values: list[float],
    width: int = 120,
    height: int = 32,
    color: str = "#58a6ff",
    fill: str = "rgba(88,166,255,0.12)",
) -> str:
    """Render a minimal SVG sparkline path for *values*."""
    if not values or len(values) < 2:
        return f'<svg width="{width}" height="{height}"></svg>'

    mn, mx = min(values), max(values)
    span = mx - mn or 1.0
    pad = 3.0

    def _x(i: int) -> float:
        return round(i / (len(values) - 1) * (width - 2 * pad) + pad, 2)

    def _y(v: float) -> float:
        return round(height - pad - (v - mn) / span * (height - 2 * pad), 2)

    pts = [(str(_x(i)), str(_y(v))) for i, v in enumerate(values)]
    polyline = " ".join(f"{x},{y}" for x, y in pts)

    # Filled area: polyline + close to bottom corners
    area_pts = polyline + f" {pts[-1][0]},{height - pad} {pts[0][0]},{height - pad}"

    return (
        f'<svg width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">'
        f'<polygon points="{area_pts}" fill="{fill}" stroke="none"/>'
        f'<polyline points="{polyline}" fill="none" stroke="{color}" stroke-width="1.5" '
        f'stroke-linejoin="round" stroke-linecap="round"/>'
        f'</svg>'
    )


def render_trend_html(metrics: list[dict]) -> str:
    """Return an HTML snippet (no outer tags) with sparklines for the given metrics."""
    if not metrics:
        return ""

    def _sp(field: str, color: str, fill: str) -> str:
        vals = [float(r.get(field, 0) or 0) for r in metrics]
        return _sparkline_svg(vals, color=color, fill=fill)

    last = metrics[-1]
    ts_last = last.get("taken_at", 0)
    try:
        import datetime
        label = datetime.datetime.fromtimestamp(float(ts_last)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        label = "—"

    cards = [
        ("CVE Count", "cve_count", "#f85149", "rgba(248,81,73,0.12)"),
        ("CISA KEV", "kev_count", "#f85149", "rgba(248,81,73,0.08)"),
        ("Weaponized", "weaponized_count", "#e3b341", "rgba(227,179,65,0.10)"),
        ("Avg Score", "avg_score", "#58a6ff", "rgba(88,166,255,0.12)"),
        ("Max EPSS", "max_epss", "#bc8cff", "rgba(188,140,255,0.10)"),
    ]

    items: list[str] = []
    for label_c, field, color, fill in cards:
        val = last.get(field, 0)
        formatted = f"{val:.3f}" if isinstance(val, float) and val < 1 else str(int(val) if isinstance(val, float) else val)
        svg = _sp(field, color, fill)
        items.append(
            f'<div class="trend-card">'
            f'<div class="trend-label">{label_c}</div>'
            f'<div class="trend-value" style="color:{color}">{formatted}</div>'
            f'<div class="trend-spark">{svg}</div>'
            f'</div>'
        )

    n = len(metrics)
    span = f"{n} snapshot{'s' if n != 1 else ''} · last: {label}"

    return (
        f'<section class="trend-bar" id="trend-section">'
        f'<div class="trend-header">Trend <span class="trend-meta">{span}</span></div>'
        f'<div class="trend-cards">{"".join(items)}</div>'
        f'</section>'
    )
