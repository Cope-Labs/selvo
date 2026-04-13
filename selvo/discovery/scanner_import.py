"""
Scanner import adapter — load Grype or Trivy JSON scan results as PackageRecord lists.

Lets selvo layer its blast-radius + EPSS velocity + exploit enrichment on top
of an existing scanner's CVE findings, without re-scraping the package ecosystem.

Supported formats:
  Grype JSON   (grype --output json)
  Trivy JSON   (trivy image/fs --format json)

Usage:
    from selvo.discovery.scanner_import import load_grype, load_trivy, load_scanner
    packages = load_scanner("/path/to/grype-result.json")  # auto-detect format
    packages = load_grype("/path/to/grype-result.json")
    packages = load_trivy("/path/to/trivy-result.json")

The functions return list[PackageRecord] with cve_ids, version, and ecosystem
already populated from the scanner output. Pass the result straight into
enrich_epss / enrich_cvss / enrich_exploits / score_and_rank.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from selvo.discovery.base import PackageRecord

# Grype/Trivy ecosystem strings → selvo ecosystem
_ECO_MAP: dict[str, str] = {
    # Grype
    "debian": "debian",
    "ubuntu": "ubuntu",
    "fedora": "fedora",
    "centos": "fedora",
    "rhel": "fedora",
    "rocky": "rocky",
    "almalinux": "almalinux",
    "suse": "suse",
    "opensuse": "opensuse",
    "wolfi": "wolfi",
    "chainguard": "chainguard",
    "alpine": "alpine",
    "arch": "arch",
    "nixos": "nixos",
    "python": "pypi",
    "pip": "pypi",
    "pypi": "pypi",
    "npm": "npm",
    "gem": "gem",
    "rubygems": "gem",
    "rust": "cargo",
    "cargo": "cargo",
    "java": "maven",
    "maven": "maven",
    "go": "go",
    "golang": "go",
    "gomod": "go",
    "dotnet": "nuget",
    "nuget": "nuget",
    "composer": "composer",
    "php": "composer",
    # Trivy type strings (they prefix with the distro and colon)
    "debian:": "debian",
    "ubuntu:": "ubuntu",
    "alpine:": "alpine",
    "rocky:": "rocky",
    "almalinux:": "almalinux",
    "rhel:": "fedora",
    "centos:": "fedora",
    "opensuse-leap": "opensuse",
    "opensuse-tumbleweed": "opensuse",
}


def _norm_eco(raw: str) -> str:
    raw_lower = raw.lower()
    for key, val in _ECO_MAP.items():
        if raw_lower.startswith(key):
            return val
    return raw_lower or "unknown"


# ── Grype ──────────────────────────────────────────────────────────────────────

def load_grype(path: str | Path) -> list[PackageRecord]:
    """
    Parse a Grype JSON report and return list[PackageRecord].

    Grype JSON schema (grype --output json):
      {
        matches: [
          {
            vulnerability: {id, severity, cvss, ...},
            artifact: {name, version, type, purl, ...}
          }
        ]
      }
    """
    data: dict[str, Any] = json.loads(Path(path).read_text())
    matches: list[dict] = data.get("matches", [])

    pkg_map: dict[str, PackageRecord] = {}

    for match in matches:
        artifact = match.get("artifact", {})
        vuln = match.get("vulnerability", {})

        name = artifact.get("name", "")
        version = artifact.get("version", "unknown")
        eco = _norm_eco(artifact.get("type", "") or artifact.get("language", ""))

        if not name:
            continue

        key = f"{eco}:{name}:{version}"
        if key not in pkg_map:
            pkg_map[key] = PackageRecord(
                name=name,
                ecosystem=eco,
                version=version,
                version_source="grype",
            )

        pkg = pkg_map[key]

        cve_id = vuln.get("id", "")
        if cve_id.startswith("CVE-") and cve_id not in pkg.cve_ids:
            pkg.cve_ids.append(cve_id)

        # Extract CVSS from relatedVulnerabilities or vuln.cvss
        for cvss_entry in vuln.get("cvss", []):
            score = cvss_entry.get("metrics", {}).get("baseScore", 0.0)
            if score > pkg.max_cvss:
                pkg.max_cvss = float(score)

    return list(pkg_map.values())


# ── Trivy ──────────────────────────────────────────────────────────────────────

def load_trivy(path: str | Path) -> list[PackageRecord]:
    """
    Parse a Trivy JSON report and return list[PackageRecord].

    Trivy JSON schema (trivy image/fs --format json):
      {
        Results: [
          {
            Target: "...",
            Type: "debian",
            Vulnerabilities: [
              {VulnerabilityID, PkgName, InstalledVersion, CVSS, ...}
            ]
          }
        ]
      }
    """
    data: dict[str, Any] = json.loads(Path(path).read_text())
    results: list[dict] = data.get("Results", data.get("results", []))

    pkg_map: dict[str, PackageRecord] = {}

    for result in results:
        eco = _norm_eco(result.get("Type", "") or result.get("type", ""))
        vulns = result.get("Vulnerabilities", result.get("vulnerabilities")) or []

        for vuln in vulns:
            name = vuln.get("PkgName", vuln.get("pkgName", ""))
            version = vuln.get("InstalledVersion", vuln.get("installedVersion", "unknown"))
            cve_id = vuln.get("VulnerabilityID", vuln.get("vulnerabilityID", ""))

            if not name:
                continue

            key = f"{eco}:{name}:{version}"
            if key not in pkg_map:
                pkg_map[key] = PackageRecord(
                    name=name,
                    ecosystem=eco,
                    version=version,
                    version_source="trivy",
                    upstream_version=vuln.get("FixedVersion", vuln.get("fixedVersion")) or None,
                    description=vuln.get("Title", vuln.get("title", ""))[:200],
                )

            pkg = pkg_map[key]

            if cve_id.startswith("CVE-") and cve_id not in pkg.cve_ids:
                pkg.cve_ids.append(cve_id)

            # CVSS from Trivy
            cvss_data = vuln.get("CVSS", vuln.get("cvss", {}))
            for source_data in (cvss_data.values() if isinstance(cvss_data, dict) else []):
                score = source_data.get("V3Score", 0.0) or source_data.get("v3Score", 0.0)
                if score and float(score) > pkg.max_cvss:
                    pkg.max_cvss = float(score)

    return list(pkg_map.values())


# ── Auto-detect ────────────────────────────────────────────────────────────────

def load_scanner(path: str | Path) -> list[PackageRecord]:
    """
    Auto-detect whether the file is a Grype or Trivy JSON report and load it.

    Detection heuristic:
      - Contains top-level 'matches' key → Grype
      - Contains top-level 'Results' or 'results' key → Trivy
      - Otherwise raises ValueError.
    """
    data = json.loads(Path(path).read_text())

    if "matches" in data:
        return load_grype(path)
    if "Results" in data or "results" in data:
        return load_trivy(path)

    raise ValueError(
        f"Cannot determine scanner format for {path!r}. "
        "Expected Grype JSON ('matches' key) or Trivy JSON ('Results' key)."
    )
