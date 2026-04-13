"""
SARIF 2.1.0 output reporter.

SARIF (Static Analysis Results Interchange Format) is the standard format
consumed by GitHub's Security / Code Scanning tab, VS Code SARIF Viewer,
Azure DevOps, and most CI security dashboards.

Uploading the output of `selvo analyze --format sarif --file results.sarif`
as a GitHub code-scanning artifact surfaces every CVE directly in the
repository's Security tab with severity, description, and location context —
no extra tooling required.

GitHub workflow example:
  - run: selvo analyze -e debian --format sarif --file results.sarif
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: results.sarif

SARIF spec: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
Schema:     https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from importlib.metadata import version as _pkg_version, PackageNotFoundError
from typing import Any

from selvo.discovery.base import PackageRecord

try:
    _SELVO_VERSION = _pkg_version("selvo")
except PackageNotFoundError:
    _SELVO_VERSION = "0.0.0+dev"

_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SELVO_URI = "https://github.com/Cope-Labs/selvo-report"


# ── Severity mapping ──────────────────────────────────────────────────────────

def _sarif_level(cvss: float, epss: float, kev: bool) -> str:
    """Map risk signals to SARIF level: error | warning | note | none."""
    if kev or cvss >= 9.0 or epss >= 0.5:
        return "error"
    if cvss >= 7.0 or epss >= 0.1:
        return "warning"
    if cvss >= 4.0 or epss >= 0.01:
        return "note"
    return "none"


def _security_severity(cvss: float, epss: float, kev: bool) -> str:
    """GitHub security-severity property (critical/high/medium/low)."""
    if kev or cvss >= 9.0:
        return "critical"
    if cvss >= 7.0 or epss >= 0.5:
        return "high"
    if cvss >= 4.0 or epss >= 0.1:
        return "medium"
    return "low"


# ── Rule generation ───────────────────────────────────────────────────────────

def _make_rules(packages: list[PackageRecord]) -> tuple[list[dict], dict[str, int]]:
    """
    Build the SARIF rules array (one rule per unique CVE ID + package pair).

    Returns (rules_list, rule_index_map) where rule_index_map maps
    rule_id → index in rules_list for result reference.
    """
    rules: list[dict] = []
    rule_map: dict[str, int] = {}  # rule_id → index

    for pkg in packages:
        for cve in pkg.cve_ids:
            rule_id = f"{cve}/{pkg.name}"
            if rule_id in rule_map:
                continue
            rule_map[rule_id] = len(rules)

            cvss = pkg.max_cvss
            epss = pkg.max_epss
            kev = pkg.in_cisa_kev

            level = _sarif_level(cvss, epss, kev)
            severity = _security_severity(cvss, epss, kev)

            description_parts = [
                f"{cve} affects {pkg.name} {pkg.version}.",
            ]
            if pkg.upstream_version and pkg.upstream_version != pkg.version:
                description_parts.append(f"Upstream is {pkg.upstream_version}.")
            if cvss:
                description_parts.append(f"CVSS {cvss:.1f}.")
            if epss:
                description_parts.append(f"EPSS {epss*100:.1f}%.")
            if pkg.exploit_maturity == "weaponized":
                description_parts.append("Weaponized exploit available.")
            elif pkg.exploit_maturity == "poc":
                description_parts.append("Public PoC available.")
            if kev:
                description_parts.append("Listed in CISA KEV.")
            if pkg.ossfuzz_covered:
                description_parts.append(f"Covered by OSS-Fuzz ({pkg.ossfuzz_project}).")
            if pkg.changelog_summary:
                description_parts.append(f"Changelog: {pkg.changelog_summary[:200]}")

            rules.append({
                "id": rule_id,
                "name": cve.replace("-", ""),
                "shortDescription": {"text": f"{cve} in {pkg.name}"},
                "fullDescription": {"text": " ".join(description_parts)},
                "helpUri": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "help": {
                    "text": " ".join(description_parts),
                    "markdown": (
                        f"**[{cve}](https://nvd.nist.gov/vuln/detail/{cve})** "
                        f"in `{pkg.name}` `{pkg.version}`\n\n"
                        + " ".join(description_parts)
                    ),
                },
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": ["security", "vulnerability"] + [e.strip() for e in pkg.ecosystem.split(",")],
                    "security-severity": str(cvss) if cvss else "0.0",
                    "selvo/epss": str(round(epss, 4)),
                    "selvo/exploit_maturity": pkg.exploit_maturity,
                    "selvo/in_cisa_kev": str(kev).lower(),
                    "selvo/sla_band": pkg.sla_band or "unknown",
                    "precision": "high" if cvss >= 7.0 or kev else "medium",
                    "problem.severity": severity,
                },
            })

    return rules, rule_map


# ── Result generation ─────────────────────────────────────────────────────────

def _make_result(
    pkg: PackageRecord,
    cve: str,
    rule_idx: int,
) -> dict[str, Any]:
    """Build one SARIF result object for a package × CVE pair."""
    cvss = pkg.max_cvss
    epss = pkg.max_epss
    kev = pkg.in_cisa_kev
    level = _sarif_level(cvss, epss, kev)

    message_parts = [f"{cve} affects {pkg.name} {pkg.version}."]
    if pkg.upstream_version and pkg.upstream_version != pkg.version:
        message_parts.append(f"Update to {pkg.upstream_version} to remediate.")
    if kev:
        message_parts.append("⚠ CISA KEV: actively exploited in the wild.")
    if pkg.exploit_maturity == "weaponized":
        message_parts.append("Weaponized exploit available.")

    result: dict[str, Any] = {
        "ruleId": f"{cve}/{pkg.name}",
        "ruleIndex": rule_idx,
        "level": level,
        "message": {"text": " ".join(message_parts)},
        # Package name as a logical "location" — SARIF requires at least one
        "locations": [
            {
                "logicalLocations": [
                    {
                        "name": pkg.name,
                        "fullyQualifiedName": f"{pkg.ecosystem}/{pkg.name}@{pkg.version}",
                        "kind": "package",
                    }
                ]
            }
        ],
        "properties": {
            "selvo/score": pkg.score,
            "selvo/max_cvss": cvss,
            "selvo/max_epss": round(epss, 4),
            "selvo/exploit_maturity": pkg.exploit_maturity,
            "selvo/in_cisa_kev": kev,
            "selvo/ossfuzz_covered": pkg.ossfuzz_covered,
            "selvo/sla_band": pkg.sla_band or "",
            "selvo/vendor_advisory_ids": pkg.vendor_advisory_ids,
            "selvo/transitive_rdep_count": pkg.transitive_rdep_count,
        },
    }

    if pkg.exploit_urls:
        result["relatedLocations"] = [
            {
                "id": i + 1,
                "message": {"text": f"Exploit reference {i+1}"},
                "physicalLocation": {
                    "artifactLocation": {"uri": url}
                },
            }
            for i, url in enumerate(pkg.exploit_urls[:3])
        ]

    return result


# ── Public API ────────────────────────────────────────────────────────────────

def render_sarif(packages: list[PackageRecord]) -> str:
    """
    Render a SARIF 2.1.0 document for all package × CVE findings.

    Returns a JSON string ready to write to a `.sarif` file and upload to
    GitHub Code Scanning or any other SARIF consumer.
    """
    rules, rule_map = _make_rules(packages)
    results: list[dict] = []

    for pkg in packages:
        for cve in pkg.cve_ids:
            rule_id = f"{cve}/{pkg.name}"
            if rule_id in rule_map:
                results.append(_make_result(pkg, cve, rule_map[rule_id]))

    doc = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "selvo",
                        "version": _SELVO_VERSION,
                        "informationUri": _SELVO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%dT%H:%M:%SZ"
                        ),
                    }
                ],
                "automationDetails": {
                    "id": f"selvo/{uuid.uuid4()}",
                },
                "properties": {
                    "selvo/total_packages": len(packages),
                    "selvo/packages_with_cves": sum(
                        1 for p in packages if p.cve_ids
                    ),
                    "selvo/kev_count": sum(
                        1 for p in packages if p.in_cisa_kev
                    ),
                    "selvo/weaponized_count": sum(
                        1 for p in packages if p.exploit_maturity == "weaponized"
                    ),
                },
            }
        ],
    }

    return json.dumps(doc, indent=2)
