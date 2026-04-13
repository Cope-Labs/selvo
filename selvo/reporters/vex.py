"""
VEX (Vulnerability Exploitability eXchange) output in CycloneDX 1.4 JSON format.

VEX documents assert the *exploitability status* of known CVEs in a specific
software context. They satisfy requirements from:
  - NIST SSDF (SP 800-218)
  - Executive Order 14028 (US federal software supply chain)
  - OpenSSF VEX Working Group recommendations

For each package×CVE pair, selvo generates one of:
  not_affected     — CVE exists but this build is not exploitable
                     Justification: component_not_present | vulnerable_code_not_present |
                                    vulnerable_code_cannot_be_controlled_by_adversary |
                                    inline_mitigations_already_exist
  affected         — CVE is present and exploitable (open CVE, no patch)
  fixed            — CVE was present, patch has been applied (distro resolved it)
  under_investigation  — Debian/distro status is undetermined

Justifications are inferred from the data selvo already has:
  - ossfuzz_covered + memory-related CVE → vulnerable_code_cannot_be_controlled_by_adversary
  - distro_patch_dates has "patched" → fixed
  - exploit_maturity == "weaponized" → affected (with kev annotation)
  - default for open CVEs → affected

Output: CycloneDX JSON BOM with a top-level "vulnerabilities" array per
  https://cyclonedx.org/docs/1.4/json/#vulnerabilities

Usage:
    from selvo.reporters.vex import render_vex
    json_str = render_vex(packages)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from selvo.discovery.base import PackageRecord


# ── Status inference ───────────────────────────────────────────────────────────

def _vex_status(pkg: PackageRecord, cve_id: str) -> tuple[str, str, str]:
    """
    Return (status, justification, response) for a package×CVE pair.

    status:        "not_affected" | "affected" | "fixed" | "under_investigation"
    justification: CycloneDX justification string (only for not_affected)
    response:      suggested remediation action string
    """
    # Check if distro tracker says patched
    patch_dates = pkg.distro_patch_dates
    if any(v == "patched" or (v and len(v) == 10) for v in patch_dates.values()):
        return "fixed", "", "update"

    # OSS-Fuzz + typical memory-safety CVE heuristic
    if pkg.ossfuzz_covered and any(
        tag in cve_id.lower() for tag in ["heap", "buffer", "overflow", "uaf", "use-after"]
    ):
        return (
            "not_affected",
            "vulnerable_code_cannot_be_controlled_by_adversary",
            "none_required",
        )

    # Under investigation / undetermined
    if any(v == "investigating" for v in patch_dates.values()):
        return "under_investigation", "", "will_not_fix"

    # Default: open and potentially exploitable
    return "affected", "", "update"


_CWE_MEMORY = {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-416", "CWE-787"}


def _vuln_entry(pkg: PackageRecord, cve_id: str) -> dict[str, Any]:
    """Build one CycloneDX vulnerability object for a package×CVE pair."""
    status, justification, response = _vex_status(pkg, cve_id)

    entry: dict[str, Any] = {
        "id": cve_id,
        "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
        "ratings": [],
        "affects": [
            {
                "ref": f"{pkg.ecosystem}:{pkg.name}",
                "versions": [{"version": pkg.version, "status": status}],
            }
        ],
        "analysis": {
            "state": status,
        },
        "properties": [],
    }

    if status == "not_affected" and justification:
        entry["analysis"]["justification"] = justification

    if response:
        entry["analysis"]["response"] = [response]

    if pkg.max_cvss > 0:
        entry["ratings"].append({
            "source": {"name": "NVD"},
            "score": pkg.max_cvss,
            "severity": _cvss_severity(pkg.max_cvss),
            "method": "CVSSv3",
        })

    if pkg.max_epss > 0:
        entry["ratings"].append({
            "source": {"name": "FIRST.org EPSS"},
            "score": round(pkg.max_epss, 4),
            "severity": "critical" if pkg.max_epss >= 0.5 else "high" if pkg.max_epss >= 0.1 else "low",
            "method": "EPSS",
            "vector": f"EPSS:{pkg.max_epss:.4f}",
        })

    if pkg.in_cisa_kev:
        entry["properties"].append({"name": "selvo:cisa_kev", "value": "true"})
    if pkg.exploit_maturity and pkg.exploit_maturity != "none":
        entry["properties"].append({"name": "selvo:exploit_maturity", "value": pkg.exploit_maturity})
    if pkg.ossfuzz_covered:
        entry["properties"].append({
            "name": "selvo:ossfuzz_covered",
            "value": pkg.ossfuzz_project or "true",
        })

    return entry


def _cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# ── Public API ────────────────────────────────────────────────────────────────

def render_vex(packages: list[PackageRecord]) -> str:
    """
    Generate a CycloneDX 1.4 VEX JSON document for all packages and their CVEs.

    Returns a JSON string ready to write to a .vex.json file.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    components = []
    vulns = []

    for pkg in packages:
        # Add component
        components.append({
            "type": "library",
            "bom-ref": f"{pkg.ecosystem}:{pkg.name}",
            "name": pkg.name,
            "version": pkg.version if pkg.version != "unknown" else "",
        })

        # Add vulnerability entries
        for cve_id in pkg.cve_ids:
            vulns.append(_vuln_entry(pkg, cve_id))

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": now,
            "tools": [{"name": "selvo", "version": "0.1.0"}],
        },
        "components": components,
        "vulnerabilities": vulns,
    }

    return json.dumps(doc, indent=2)
