"""Compliance audit report reporter for selvo.

Outputs compliance findings as JSON (for GRC tools) or Markdown (for auditors).
"""
from __future__ import annotations

import json
import datetime
from typing import TextIO

from selvo.analysis.compliance import ComplianceFinding, summarise


def render_json(findings: list[ComplianceFinding], out: TextIO) -> None:
    """Serialize findings to JSON suitable for GRC tool import."""
    summary = summarise(findings)
    payload = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": summary,
        "findings": [f.as_dict() for f in findings],
    }
    json.dump(payload, out, indent=2)
    out.write("\n")


def render_markdown(findings: list[ComplianceFinding], out: TextIO) -> None:
    """Render findings as a Markdown compliance audit report."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = summarise(findings)

    out.write("# selvo Compliance Audit Report\n\n")
    out.write(f"**Generated:** {now}  \n")
    out.write(f"**Total findings:** {summary['total_findings']}  \n")
    out.write(f"**Unique controls triggered:** {len(summary['unique_controls'])}  \n\n")

    # Summary tables
    if summary["by_severity"]:
        out.write("## By Severity\n\n")
        out.write("| Severity | Findings |\n|---|---|\n")
        for sev in ("critical", "high", "medium", "low", ""):
            count = summary["by_severity"].get(sev, 0)
            if count:
                label = sev or "unrated"
                out.write(f"| {label.capitalize()} | {count} |\n")
        out.write("\n")

    if summary["by_framework"]:
        out.write("## By Framework\n\n")
        out.write("| Framework | Findings |\n|---|---|\n")
        for fw, count in sorted(summary["by_framework"].items()):
            out.write(f"| {fw} | {count} |\n")
        out.write("\n")

    if summary["unique_controls"]:
        controls_str = ", ".join(f"`{c}`" for c in summary["unique_controls"])
        out.write(f"## Controls Triggered\n\n{controls_str}\n\n")

    # Detailed findings grouped by package
    out.write("## Detailed Findings\n\n")
    if not findings:
        out.write("_No compliance findings._\n")
        return

    current_pkg = None
    for f in findings:
        if f.package != current_pkg:
            current_pkg = f.package
            out.write(f"### `{f.package}` ({f.ecosystem})\n\n")
            out.write("| Signal | CVE | Severity | Frameworks | Controls | Deadline |\n")
            out.write("|---|---|---|---|---|---|\n")

        cve = f.cve_id or "—"
        sev = f.severity or "—"
        fws = ", ".join(f.frameworks)
        controls = ", ".join(f"`{c}`" for c in f.controls)
        deadline = f.remediation_deadline or "—"
        detail = f" _{f.detail}_" if f.detail else ""
        out.write(f"| {f.signal}{detail} | {cve} | {sev} | {fws} | {controls} | {deadline} |\n")
    out.write("\n")
