"""Chocolatey package discovery.

Queries the community.chocolatey.org NuGet v2 OData API for the most
popular packages and normalises them into PackageRecords.

OData endpoint: https://community.chocolatey.org/api/v2/Packages
Sorted by DownloadCount descending, 100 per page.

Note: Chocolatey CVE coverage is even sparser than WinGet — packages
are mapped to NVD CPE entries, with significant gaps.  Results are
flagged with ``ecosystem="chocolatey"`` and consumers should note that
not all packages will resolve CVE data.
"""
from __future__ import annotations

import logging
from xml.etree import ElementTree

import httpx

from selvo.discovery.base import PackageRecord

log = logging.getLogger(__name__)

_CHOCO_API = "https://community.chocolatey.org/api/v2/Packages"
_ODATA_NS = "http://schemas.microsoft.com/ado/2007/08/dataservices"
_ATOM_NS = "http://www.w3.org/2005/Atom"

# Curated fallback list of security- and devops-relevant Chocolatey packages
_CORE_CHOCOLATEY: list[tuple[str, str]] = [
    ("git",              "Distributed version control system"),
    ("git.install",      "Git for Windows (installer)"),
    ("openssl.light",   "OpenSSL cryptography library (light)"),
    ("python3",          "Python 3 runtime"),
    ("nodejs",           "Node.js JavaScript runtime"),
    ("golang",           "Go programming language"),
    ("rust",             "Rust toolchain"),
    ("cmake",            "Cross-platform build system"),
    ("7zip",             "7-Zip file archiver"),
    ("7zip.install",     "7-Zip installer"),
    ("curl",             "Command-line URL transfer tool"),
    ("wget",             "Internet file retriever for Windows"),
    ("gnupg",            "GNU Privacy Guard"),
    ("winscp",           "WinSCP SFTP client"),
    ("putty",            "PuTTY SSH client"),
    ("putty.install",    "PuTTY SSH client (installer)"),
    ("notepadplusplus",  "Notepad++ editor"),
    ("vscode",           "Visual Studio Code"),
    ("docker-desktop",   "Docker Desktop for Windows"),
    ("kubernetes-cli",   "Kubernetes CLI (kubectl)"),
    ("kubernetes-helm",  "Helm Kubernetes package manager"),
    ("terraform",        "Terraform infrastructure tool"),
    ("vault",            "HashiCorp Vault secrets manager"),
    ("awscli",           "AWS Command Line Interface"),
    ("azure-cli",        "Azure Command Line Interface"),
    ("googlechrome",     "Google Chrome browser"),
    ("firefox",          "Mozilla Firefox browser"),
    ("vlc",              "VLC media player"),
    ("wireshark",        "Network packet analyser"),
    ("nmap",             "Network exploration and security auditing"),
    ("sysinternals",     "Sysinternals Suite"),
    ("windirstat",       "Windows disk usage tool"),
    ("jq",               "JSON processor"),
    ("yq",               "YAML/JSON/TOML processor"),
    ("powershell-core",  "PowerShell 7+"),
    ("dotnet-8.0-runtime","Microsoft .NET 8 runtime"),
    ("visualstudio2022community", "Visual Studio 2022 Community"),
    ("openjdk17",        "OpenJDK 17"),
    ("openjdk21",        "OpenJDK 21"),
    ("maven",            "Apache Maven build tool"),
    ("gradle",           "Gradle build tool"),
]


def _odata_value(entry: ElementTree.Element, prop: str) -> str:
    node = entry.find(f".//{{{_ODATA_NS}}}{prop}")
    return node.text or "" if node is not None and node.text else ""


class ChocolateyDiscovery:
    """Discover top Chocolatey packages."""

    ecosystem = "chocolatey"

    async def fetch_top(self, limit: int) -> list[PackageRecord]:
        packages = await self._fetch_from_api(limit)
        if not packages:
            packages = self._fallback(limit)
        return packages

    async def _fetch_from_api(self, limit: int) -> list[PackageRecord]:
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                resp = await client.get(
                    _CHOCO_API,
                    params={
                        "$orderby": "DownloadCount desc",
                        "$top": str(min(limit, 100)),
                        "$filter": "IsLatestVersion eq true",
                    },
                    headers={"User-Agent": "selvo/0.1 (chocolatey-discovery)"},
                )
                resp.raise_for_status()
                xml_text = resp.text

            root = ElementTree.fromstring(xml_text)
            result: list[PackageRecord] = []

            for entry in root.findall(f"{{{_ATOM_NS}}}entry"):
                pkg_id = _odata_value(entry, "Id") or ""
                version = _odata_value(entry, "Version") or "unknown"
                desc = _odata_value(entry, "Description") or _odata_value(entry, "Summary") or ""
                homepage_node = entry.find(f"{{{_ATOM_NS}}}link[@rel='alternate']")
                homepage = homepage_node.get("href") if homepage_node is not None else None
                downloads_str = _odata_value(entry, "DownloadCount") or "0"
                try:
                    downloads = int(downloads_str)
                except ValueError:
                    downloads = 0

                if not pkg_id:
                    continue

                result.append(PackageRecord(
                    name=pkg_id,
                    ecosystem=self.ecosystem,
                    version=version,
                    description=desc[:200],
                    homepage=homepage,
                    download_count=downloads,
                ))

            log.debug("chocolatey: fetched %d packages from OData API", len(result))
            return result
        except Exception as exc:
            log.debug("chocolatey: API unavailable (%s) — using curated fallback", exc)
            return []

    def _fallback(self, limit: int) -> list[PackageRecord]:
        return [
            PackageRecord(name=name, ecosystem=self.ecosystem, description=desc)
            for name, desc in _CORE_CHOCOLATEY[:limit]
        ]
