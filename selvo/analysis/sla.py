"""
Time-to-patch SLA tracking — flag packages that have exceeded organisational patch SLAs.

Default SLA thresholds (configurable via --sla-* CLI flags or ENV):

  Critical  (CVSS ≥ 9.0 or CISA KEV)  →  7 days
  High      (CVSS ≥ 7.0 or EPSS ≥ 0.4)  →  30 days
  Medium    (CVSS ≥ 4.0)                →  60 days
  Low       (anything else)             →  90 days

SLA clock starts at exposure_days (days since oldest open CVE disclosure).

Result fields on PackageRecord:
  sla_band         ""  = no CVEs  |  "ok"  |  "warn" (>75%)  |  "breach"  |  "critical"
  sla_days_overdue int  (0 = within SLA; positive = days over)

`selvo sla` command renders a breach report with 30/60/90-day buckets.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from selvo.discovery.base import PackageRecord


@dataclass
class SLAPolicy:
    """Configurable SLA thresholds (all in days)."""
    critical: int = 7     # CVSS ≥ 9.0 or CISA KEV
    high: int = 30        # CVSS ≥ 7.0 or EPSS ≥ 0.40
    medium: int = 60      # CVSS ≥ 4.0
    low: int = 90         # anything else with a CVE


_DEFAULT_POLICY = SLAPolicy()


def _classify_severity(pkg: PackageRecord) -> Optional[str]:
    """Return 'critical' | 'high' | 'medium' | 'low' | None (no CVEs)."""
    if not pkg.cve_ids:
        return None
    if pkg.max_cvss >= 9.0 or pkg.in_cisa_kev:
        return "critical"
    if pkg.max_cvss >= 7.0 or pkg.max_epss >= 0.40:
        return "high"
    if pkg.max_cvss >= 4.0:
        return "medium"
    return "low"


def _sla_threshold(severity: str, policy: SLAPolicy) -> int:
    return {
        "critical": policy.critical,
        "high": policy.high,
        "medium": policy.medium,
        "low": policy.low,
    }[severity]


def enrich_sla(
    packages: list[PackageRecord],
    policy: Optional[SLAPolicy] = None,
) -> list[PackageRecord]:
    """
    Compute SLA band and overdue days for each package.

    Sets:
        pkg.sla_band          "" | "ok" | "warn" | "breach" | "critical"
        pkg.sla_days_overdue  int  (0 if within SLA)
    """
    p = policy or _DEFAULT_POLICY

    for pkg in packages:
        sev = _classify_severity(pkg)
        if sev is None:
            pkg.sla_band = ""
            pkg.sla_days_overdue = 0
            continue

        threshold = _sla_threshold(sev, p)
        days = pkg.exposure_days  # 0 if not enriched

        if days == 0:
            # No timeline data — mark as ok (can't determine)
            pkg.sla_band = "ok"
            pkg.sla_days_overdue = 0
        elif days > threshold:
            overdue = days - threshold
            pkg.sla_days_overdue = overdue
            # Critical label overrides if severity = critical or very overdue
            if sev == "critical" or overdue > 180:
                pkg.sla_band = "critical"
            else:
                pkg.sla_band = "breach"
        elif days > threshold * 0.75:
            pkg.sla_band = "warn"
            pkg.sla_days_overdue = 0
        else:
            pkg.sla_band = "ok"
            pkg.sla_days_overdue = 0

    return packages


def sla_report(
    packages: list[PackageRecord],
    policy: Optional[SLAPolicy] = None,
) -> dict:
    """
    Build a structured SLA breach report suitable for JSON output or terminal rendering.

    Returns:
        {
          "policy": {...},
          "counts": {"ok": N, "warn": N, "breach": N, "critical": N},
          "critical": [...],
          "breach": [...],
          "warn": [...],
        }
    """
    p = policy or _DEFAULT_POLICY
    buckets: dict[str, list[dict]] = {"critical": [], "breach": [], "warn": [], "ok": []}

    for pkg in packages:
        band = pkg.sla_band
        if not band:
            continue
        buckets.get(band, buckets["ok"]).append({
            "package": pkg.name,
            "sla_band": band,
            "sla_days_overdue": pkg.sla_days_overdue,
            "exposure_days": pkg.exposure_days,
            "cve_count": pkg.cve_count,
            "max_cvss": pkg.max_cvss,
            "max_epss": round(pkg.max_epss, 4),
            "in_cisa_kev": pkg.in_cisa_kev,
            "score": pkg.score,
        })

    for band in buckets:
        buckets[band].sort(key=lambda r: r["sla_days_overdue"], reverse=True)

    return {
        "policy": {
            "critical_days": p.critical,
            "high_days": p.high,
            "medium_days": p.medium,
            "low_days": p.low,
        },
        "counts": {band: len(items) for band, items in buckets.items()},
        "critical": buckets["critical"],
        "breach": buckets["breach"],
        "warn": buckets["warn"],
        "ok_count": len(buckets["ok"]),
    }
