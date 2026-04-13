"""
SBOM (Software Bill of Materials) export in CycloneDX 1.4 JSON format.

CycloneDX is the CISA-preferred SBOM format and satisfies US Executive Order
14028 requirements for software supply chain transparency.

Each PackageRecord is emitted as a CycloneDX component with:
  - purl (package URL, per PURL spec)
  - CVE vulnerabilities as advisories
  - EPSS and CVSS scores as properties
  - Upstream repo as externalReference

Usage:
    from selvo.reporters.sbom import render_sbom
    json_str = render_sbom(packages)
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from selvo.discovery.base import PackageRecord

# Ecosystem → PURL type mapping per https://github.com/package-url/purl-spec
_PURL_TYPES: dict[str, str] = {
    "debian": "deb",
    "ubuntu": "deb",
    "fedora": "rpm",
    "arch": "alpm",
    "alpine": "apk",
    "nixos": "nix",
}


def _purl(pkg: PackageRecord) -> str:
    """Generate a package URL for a PackageRecord."""
    primary_eco = pkg.ecosystem.split(",")[0].strip()
    ptype = _PURL_TYPES.get(primary_eco, "generic")
    version = pkg.version if pkg.version != "unknown" else ""
    ver_suffix = f"@{version}" if version else ""
    return f"pkg:{ptype}/{pkg.name}{ver_suffix}"


def _component(pkg: PackageRecord) -> dict[str, Any]:
    comp: dict[str, Any] = {
        "type": "library",
        "bom-ref": f"{pkg.ecosystem}:{pkg.name}",
        "name": pkg.name,
        "version": pkg.version if pkg.version != "unknown" else "",
        "purl": _purl(pkg),
        "description": pkg.description or "",
    }

    # External references
    refs = []
    if pkg.upstream_repo:
        refs.append({"type": "vcs", "url": pkg.upstream_repo})
    if pkg.homepage:
        refs.append({"type": "website", "url": pkg.homepage})
    if refs:
        comp["externalReferences"] = refs

    # CVE IDs as advisories
    if pkg.cve_ids:
        comp["vulnerabilities"] = [{"id": cve} for cve in pkg.cve_ids]

    # EPSS + CVSS + score as custom properties
    properties = [{"name": "selvo:ecosystem", "value": pkg.ecosystem}]
    if pkg.max_epss > 0:
        properties.append({"name": "selvo:epss", "value": str(round(pkg.max_epss, 4))})
    if pkg.max_cvss > 0:
        properties.append({"name": "selvo:cvss_max", "value": str(pkg.max_cvss)})
    if pkg.score:
        properties.append({"name": "selvo:priority_score", "value": str(pkg.score)})
    if pkg.reverse_dep_count:
        properties.append({"name": "selvo:reverse_dep_count", "value": str(pkg.reverse_dep_count)})
    if pkg.upstream_version:
        properties.append({"name": "selvo:upstream_version", "value": pkg.upstream_version})
    comp["properties"] = properties

    return comp


def render_sbom(packages: list[PackageRecord]) -> str:
    """
    Render packages as a CycloneDX 1.4 JSON SBOM string.
    """
    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "selvo",
                    "name": "selvo",
                    "version": "0.1",
                    "externalReferences": [
                        {"type": "vcs", "url": "https://github.com/Cope-Labs/selvo"}
                    ],
                }
            ],
        },
        "components": [_component(p) for p in packages],
    }
    return json.dumps(doc, indent=2)
