"""
SBOM input adapter — load CycloneDX 1.4/1.5 or SPDX 2.3 JSON SBOMs as PackageRecord lists.

Allows selvo to layer its CVE + blast-radius + exploit enrichment pipeline on top of
an existing SBOM rather than running its own discovery scraper.

Supported formats:
  CycloneDX JSON  (bomFormat == "CycloneDX", specVersion 1.4 / 1.5)
  SPDX JSON       (spdxVersion starts with "SPDX-2")

Usage:
    from selvo.discovery.sbom_input import load_sbom
    packages = load_sbom("/path/to/bom.json")

The function is sync (file I/O only) and returns list[PackageRecord] ready
to pass directly into enrich_cve / enrich_epss / etc.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from selvo.discovery.base import PackageRecord

# PURL type → selvo ecosystem string
_PURL_ECO: dict[str, str] = {
    "deb": "debian",
    "rpm": "fedora",
    "alpm": "arch",
    "apk": "alpine",
    "nix": "nixos",
    "pypi": "pypi",
    "npm": "npm",
    "gem": "gem",
    "cargo": "cargo",
    "maven": "maven",
    "nuget": "nuget",
    "golang": "go",
}


def _purl_to_parts(purl: str) -> dict[str, str]:
    """
    Parse a package URL into {type, namespace, name, version}.

    PURL spec: pkg:type/[namespace/]name[@version][?qualifiers][#subpath]
    """
    m = re.match(r"pkg:([^/]+)/(?:([^/]+)/)?([^@?#]+)(?:@([^?#]+))?", purl)
    if not m:
        return {}
    return {
        "type": m.group(1).lower(),
        "namespace": m.group(2) or "",
        "name": m.group(3),
        "version": m.group(4) or "unknown",
    }


# ── CycloneDX ─────────────────────────────────────────────────────────────────

def _load_cyclonedx(data: dict[str, Any]) -> list[PackageRecord]:
    components = data.get("components", [])
    records: list[PackageRecord] = []

    for comp in components:
        purl = comp.get("purl", "")
        parts = _purl_to_parts(purl) if purl else {}

        name = comp.get("name", parts.get("name", ""))
        version = comp.get("version", parts.get("version", "unknown"))
        eco = _PURL_ECO.get(parts.get("type", ""), parts.get("type", "unknown"))

        if not name:
            continue

        pkg = PackageRecord(
            name=name,
            ecosystem=eco,
            version=version,
            description=comp.get("description", ""),
            homepage=next(
                (r["url"] for r in comp.get("externalReferences", []) if r.get("type") == "website"),
                None,
            ),
            upstream_repo=next(
                (r["url"] for r in comp.get("externalReferences", []) if r.get("type") == "vcs"),
                None,
            ),
            version_source="sbom",
        )

        # Extract CVE IDs from vulnerabilities embedded in component
        for vuln in comp.get("vulnerabilities", []):
            vid = vuln.get("id", "")
            if vid.startswith("CVE-"):
                pkg.cve_ids.append(vid)
            for ref in vuln.get("references", []):
                rid = ref.get("id", "")
                if rid.startswith("CVE-") and rid not in pkg.cve_ids:
                    pkg.cve_ids.append(rid)

        records.append(pkg)

    # Also extract vulnerabilities from the top-level vulnerabilities array (CycloneDX 1.4+)
    pkg_map = {p.name: p for p in records}
    for vuln in data.get("vulnerabilities", []):
        vid = vuln.get("id", "")
        if not vid.startswith("CVE-"):
            continue
        for affect in vuln.get("affects", []):
            ref = affect.get("ref", "")
            # ref may be bom-ref or package name
            pkg = pkg_map.get(ref) or next(
                (p for p in records if p.name in ref), None
            )
            if pkg and vid not in pkg.cve_ids:
                pkg.cve_ids.append(vid)

    return records


# ── SPDX ──────────────────────────────────────────────────────────────────────

def _load_spdx(data: dict[str, Any]) -> list[PackageRecord]:
    packages = data.get("packages", [])
    records: list[PackageRecord] = []

    for pkg_data in packages:
        name = pkg_data.get("name", "")
        version = pkg_data.get("versionInfo", "unknown")

        # Derive ecosystem from externalRefs PURL
        eco = "unknown"
        purl = ""
        for ref in pkg_data.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator", "")
                break

        if purl:
            parts = _purl_to_parts(purl)
            eco = _PURL_ECO.get(parts.get("type", ""), parts.get("type", "unknown"))
            if version == "unknown":
                version = parts.get("version", "unknown")
            if not name:
                name = parts.get("name", "")

        if not name:
            continue

        homepage = pkg_data.get("homepage", None)
        pkg = PackageRecord(
            name=name,
            ecosystem=eco,
            version=version,
            description=pkg_data.get("description", ""),
            homepage=homepage if homepage and homepage != "NOASSERTION" else None,
            version_source="sbom",
        )
        records.append(pkg)

    return records


# ── Public API ─────────────────────────────────────────────────────────────────

def load_sbom(path: str | Path) -> list[PackageRecord]:
    """
    Parse a CycloneDX or SPDX JSON SBOM and return a list of PackageRecord objects.

    Args:
        path:  Path to the SBOM JSON file.

    Returns:
        list[PackageRecord] ready for selvo enrichment pipeline.

    Raises:
        ValueError:  If the file is not a recognised SBOM format.
        FileNotFoundError:  If the path does not exist.
    """
    data = json.loads(Path(path).read_text())

    bom_format = data.get("bomFormat", "")
    spdx_version = data.get("spdxVersion", "")

    if bom_format == "CycloneDX":
        records = _load_cyclonedx(data)
    elif spdx_version.startswith("SPDX-"):
        records = _load_spdx(data)
    else:
        raise ValueError(
            f"Unrecognised SBOM format in {path!r}. "
            "Expected CycloneDX JSON (bomFormat='CycloneDX') or SPDX JSON (spdxVersion='SPDX-2.x')."
        )

    return records
