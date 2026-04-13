"""Compliance mapping engine for selvo.

Maps CVE findings on PackageRecords to compliance framework controls
(NIST 800-53, FedRAMP, SOC 2, PCI-DSS, DoD IL4) using a bundled
CWE → control mapping table.

Usage::

    from selvo.analysis.compliance import map_controls, ComplianceFinding

    findings = map_controls(packages, framework="nist")
    for f in findings:
        print(f.package, f.controls)

CLI::

    selvo compliance --framework fedramp --out fedramp-audit.json
    selvo compliance --framework nist --format markdown --out nist-controls.md
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from selvo.discovery.base import PackageRecord

log = logging.getLogger(__name__)

# Supported framework keys (must match keys in compliance_map.json values)
FRAMEWORKS = {
    "nist":    "NIST 800-53 Rev 5",
    "fedramp": "FedRAMP High",
    "soc2":    "SOC 2 Type II",
    "pci":     "PCI-DSS v4.0",
    "dod":     "DoD IL4",
    "all":     "All Frameworks",
}

_MAP_CACHE: dict | None = None


def _load_map() -> dict:
    global _MAP_CACHE
    if _MAP_CACHE is not None:
        return _MAP_CACHE
    # Try the data/ directory relative to the repo root, then package-bundled
    candidates = [
        Path(__file__).parent.parent.parent / "data" / "compliance_map.json",
        Path(__file__).parent / "compliance_map.json",
    ]
    for p in candidates:
        if p.exists():
            _MAP_CACHE = json.loads(p.read_text())
            return _MAP_CACHE
    log.warning("compliance_map.json not found — compliance mapping will be empty")
    _MAP_CACHE = {}
    return _MAP_CACHE


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ComplianceFinding:
    """A single compliance control violation tied to a package + CVE."""

    package: str
    ecosystem: str
    cve_id: str            # "" for package-level findings (KEV, SLA, etc.)
    signal: str            # CWE ID, "kev_listed", "sla_breach", etc.
    frameworks: list[str]  # ["NIST 800-53 Rev 5", "FedRAMP High"]
    controls: list[str]    # ["SI-2", "RA-5(2)"]
    severity: str          # "critical" | "high" | "medium" | "low" | ""
    remediation_deadline: str  # ISO date derived from SLA, or ""
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "package": self.package,
            "ecosystem": self.ecosystem,
            "cve_id": self.cve_id,
            "signal": self.signal,
            "frameworks": self.frameworks,
            "controls": self.controls,
            "severity": self.severity,
            "remediation_deadline": self.remediation_deadline,
            "detail": self.detail,
        }


# ── Mapping logic ─────────────────────────────────────────────────────────────

def map_controls(
    packages: list[PackageRecord],
    framework: str = "all",
) -> list[ComplianceFinding]:
    """Map security signals on *packages* to compliance framework controls.

    Args:
        packages:  List of enriched PackageRecords.
        framework: One of ``"nist"``, ``"fedramp"``, ``"soc2"``, ``"pci"``,
                   ``"dod"``, or ``"all"`` (returns controls for every framework).

    Returns:
        Sorted list of :class:`ComplianceFinding` (by package name, then signal).
    """
    fw = framework.lower()
    if fw not in FRAMEWORKS:
        raise ValueError(f"Unknown framework '{framework}'. Choose from: {list(FRAMEWORKS)}")

    cmap = _load_map()
    findings: list[ComplianceFinding] = []

    for pkg in packages:
        # ── Per-CVE CWE-based findings ────────────────────────────────────────
        # (CWE data is not yet on PackageRecord, so we emit generic CVE findings
        #  using the severity-level signals we do have; CWE enrichment is future work)

        # ── Package-level signal findings ─────────────────────────────────────
        if pkg.in_cisa_kev:
            findings.extend(_make_findings(pkg, "kev_listed", "", fw, cmap))

        if pkg.exploit_maturity == "weaponized":
            findings.extend(_make_findings(pkg, "weaponized_exploit", "", fw, cmap))
        elif pkg.exploit_maturity == "poc":
            findings.extend(_make_findings(pkg, "poc_exploit", "", fw, cmap))

        if pkg.sla_band in ("breach", "critical") and pkg.sla_days_overdue > 0:
            detail = f"{pkg.sla_days_overdue}d overdue (SLA band: {pkg.sla_band})"
            findings.extend(_make_findings(pkg, "sla_breach", "", fw, cmap, detail=detail))

        if pkg.is_outdated:
            findings.extend(_make_findings(pkg, "outdated_component", "", fw, cmap))

        # ── Per-CVE generic severity signal ───────────────────────────────────
        for cve_id in pkg.cve_ids:
            severity = _cvss_severity(pkg.max_cvss)
            signal = _severity_signal(pkg)
            if signal:
                findings.extend(_make_findings(pkg, signal, cve_id, fw, cmap,
                                               severity=severity))

    # Deduplicate (same package+signal+control combo)
    seen: set[tuple] = set()
    unique: list[ComplianceFinding] = []
    for f in findings:
        key = (f.package, f.signal, f.cve_id, tuple(sorted(f.controls)))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return sorted(unique, key=lambda f: (f.package, f.signal, f.cve_id))


def _make_findings(
    pkg: PackageRecord,
    signal: str,
    cve_id: str,
    fw: str,
    cmap: dict,
    detail: str = "",
    severity: str = "",
) -> list[ComplianceFinding]:
    entry = cmap.get(signal, {})
    if not entry:
        return []

    if fw == "all":
        all_controls: list[str] = []
        all_frameworks: list[str] = []
        for fw_key, label in FRAMEWORKS.items():
            if fw_key == "all":
                continue
            controls = entry.get(fw_key, [])
            if controls:
                all_controls.extend(controls)
                all_frameworks.append(label)
        if not all_controls:
            return []
        return [ComplianceFinding(
            package=pkg.name,
            ecosystem=pkg.ecosystem,
            cve_id=cve_id,
            signal=signal,
            frameworks=sorted(set(all_frameworks)),
            controls=sorted(set(all_controls)),
            severity=severity or _cvss_severity(pkg.max_cvss),
            remediation_deadline=_deadline(pkg),
            detail=detail,
        )]
    else:
        controls = entry.get(fw, [])
        if not controls:
            return []
        label = FRAMEWORKS[fw]
        return [ComplianceFinding(
            package=pkg.name,
            ecosystem=pkg.ecosystem,
            cve_id=cve_id,
            signal=signal,
            frameworks=[label],
            controls=list(controls),
            severity=severity or _cvss_severity(pkg.max_cvss),
            remediation_deadline=_deadline(pkg),
            detail=detail,
        )]


def _cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return ""


def _severity_signal(pkg: PackageRecord) -> str:
    """Pick the strongest applicable signal for CVE-level mapping."""
    if pkg.in_cisa_kev:
        return "kev_listed"
    if pkg.exploit_maturity == "weaponized":
        return "weaponized_exploit"
    if pkg.exploit_maturity == "poc":
        return "poc_exploit"
    if pkg.max_cvss >= 7.0:
        return "outdated_component"
    return ""


def _deadline(pkg: PackageRecord) -> str:
    """Return ISO date deadline from SLA data if available."""
    if pkg.sla_days_overdue > 0 and pkg.cve_disclosed_at:
        return pkg.cve_disclosed_at  # already past deadline
    return ""


# ── Summary helpers ───────────────────────────────────────────────────────────

def summarise(findings: list[ComplianceFinding]) -> dict:
    """Return a summary dict with counts by framework and severity."""
    by_framework: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    control_set: set[str] = set()

    for f in findings:
        for fw in f.frameworks:
            by_framework[fw] = by_framework.get(fw, 0) + 1
        if f.severity:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        control_set.update(f.controls)

    return {
        "total_findings": len(findings),
        "unique_controls": sorted(control_set),
        "by_framework": by_framework,
        "by_severity": by_severity,
    }
