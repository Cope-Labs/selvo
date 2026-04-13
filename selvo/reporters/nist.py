"""NIST SP 800-53 Rev 5 assessment report in OSCAL-like JSON.

Produces a machine-readable assessment results document that maps selvo
findings to NIST 800-53 controls.  The output follows the OSCAL Assessment
Results model structure (simplified) so it can be imported by GRC tools
(e.g., OSCAL viewers, Trestle, Lula, Compliance-as-Code).

Usage::

    selvo compliance --framework nist -o nist-oscal -f nist-report.json

OSCAL spec: https://pages.nist.gov/OSCAL/reference/latest/assessment-results/
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from importlib.metadata import version as _pkg_version, PackageNotFoundError

from selvo.analysis.compliance import (
    ComplianceFinding,
    map_controls,
    summarise,
    FRAMEWORKS,
)
from selvo.discovery.base import PackageRecord


def _selvo_version() -> str:
    try:
        return _pkg_version("selvo")
    except PackageNotFoundError:
        return "0.0.0-dev"


# NIST 800-53 control family labels
_CONTROL_FAMILIES: dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}


def _family_label(control_id: str) -> str:
    prefix = control_id.split("-")[0] if "-" in control_id else control_id[:2]
    return _CONTROL_FAMILIES.get(prefix, "Unknown")


def _severity_to_risk(severity: str) -> str:
    return {
        "critical": "very-high",
        "high": "high",
        "medium": "moderate",
        "low": "low",
    }.get(severity, "unknown")


def render_nist(
    packages: list[PackageRecord],
    framework: str = "nist",
) -> str:
    """Render NIST 800-53 (or FedRAMP) assessment results in OSCAL-like JSON.

    Args:
        packages:  Enriched PackageRecords from the analysis pipeline.
        framework: ``"nist"`` for full 800-53 Rev 5, ``"fedramp"`` for
                   FedRAMP High baseline subset.

    Returns:
        JSON string ready to write to file.
    """
    now = datetime.now(timezone.utc)
    findings = map_controls(packages, framework=framework)
    summary = summarise(findings)
    fw_label = FRAMEWORKS.get(framework, framework)

    # Group findings by control
    by_control: dict[str, list[ComplianceFinding]] = {}
    for f in findings:
        for ctrl in f.controls:
            by_control.setdefault(ctrl, []).append(f)

    # Build control results
    control_results = []
    for ctrl_id in sorted(by_control):
        ctrl_findings = by_control[ctrl_id]
        worst = _worst_severity(ctrl_findings)
        status = "not-satisfied" if ctrl_findings else "satisfied"

        observations = []
        for f in ctrl_findings:
            obs = {
                "uuid": str(uuid.uuid4()),
                "title": f"{f.signal} — {f.package}",
                "description": _observation_desc(f),
                "methods": ["EXAMINE", "TEST"],
                "subjects": [
                    {
                        "subject-uuid": str(uuid.uuid5(uuid.NAMESPACE_URL, f.package)),
                        "type": "component",
                        "title": f.package,
                        "props": [
                            {"name": "ecosystem", "value": f.ecosystem},
                        ],
                    }
                ],
                "relevant-evidence": _evidence(f),
            }
            if f.cve_id:
                subjects = obs["subjects"]
                subjects[0]["props"].append(  # type: ignore[index]
                    {"name": "cve-id", "value": f.cve_id}
                )
            observations.append(obs)

        control_results.append({
            "uuid": str(uuid.uuid4()),
            "control-id": ctrl_id,
            "control-family": _family_label(ctrl_id),
            "status": status,
            "risk-level": _severity_to_risk(worst),
            "finding-count": len(ctrl_findings),
            "observations": observations,
        })

    # Assemble OSCAL-like document
    doc = {
        "assessment-results": {
            "uuid": str(uuid.uuid4()),
            "metadata": {
                "title": f"selvo {fw_label} Assessment Results",
                "last-modified": now.isoformat(),
                "version": "1.0",
                "oscal-version": "1.1.2",
                "tool": {
                    "name": "selvo",
                    "version": _selvo_version(),
                    "vendor": "Cope Labs LLC",
                },
                "framework": fw_label,
                "framework-key": framework,
            },
            "import-ap": {
                "href": f"#selvo-{framework}-assessment-plan",
            },
            "summary": {
                "total-findings": summary["total_findings"],
                "unique-controls-triggered": len(summary["unique_controls"]),
                "controls-triggered": summary["unique_controls"],
                "by-severity": summary["by_severity"],
                "by-framework": summary["by_framework"],
                "packages-scanned": len(packages),
                "packages-with-findings": len(
                    {f.package for f in findings}
                ),
            },
            "results": [
                {
                    "uuid": str(uuid.uuid4()),
                    "title": f"{fw_label} Control Assessment",
                    "description": (
                        f"Automated assessment of {len(packages)} packages against "
                        f"{fw_label} controls using selvo v{_selvo_version()}."
                    ),
                    "start": now.isoformat(),
                    "end": now.isoformat(),
                    "reviewed-controls": {
                        "control-selections": [
                            {"include-all": True}
                        ]
                    },
                    "findings": control_results,
                }
            ],
        }
    }

    return json.dumps(doc, indent=2)


def _worst_severity(findings: list[ComplianceFinding]) -> str:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}
    worst = ""
    for f in findings:
        if order.get(f.severity, 0) > order.get(worst, 0):
            worst = f.severity
    return worst


def _observation_desc(f: ComplianceFinding) -> str:
    parts = [f"Package '{f.package}' ({f.ecosystem})"]
    if f.cve_id:
        parts.append(f"has {f.cve_id}")
    parts.append(f"triggered signal '{f.signal}'")
    if f.severity:
        parts.append(f"with severity {f.severity}")
    if f.detail:
        parts.append(f"— {f.detail}")
    if f.remediation_deadline:
        parts.append(f"(remediation deadline: {f.remediation_deadline})")
    return ". ".join(parts) + "."


def _evidence(f: ComplianceFinding) -> list[dict]:
    evidence = []
    if f.cve_id:
        evidence.append({
            "href": f"https://nvd.nist.gov/vuln/detail/{f.cve_id}",
            "description": f"NVD entry for {f.cve_id}",
        })
    if f.signal == "kev_listed":
        evidence.append({
            "href": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "description": "CISA Known Exploited Vulnerabilities Catalog",
        })
    return evidence
