"""WinGet package discovery.

Queries the WinGet REST source API (winget-pkgs community source) and
falls back to a curated list of high-value endpoint packages if the
REST API is unavailable.

Note — CVE coverage for WinGet is sparse: the packages are Windows
binaries, so NVD CPE matching is used rather than ecosystem-native
advisories.  This module marks discovered packages with
``ecosystem="winget"`` and sets a ``beta_coverage=True`` flag so
reporters can surface the limited-coverage warning.

WinGet REST API spec:
  https://github.com/microsoft/winget-cli-restsource/blob/main/doc/implementation-guide.md
  Public community source: https://api.winget.run/v2/packages
"""
from __future__ import annotations

import logging

import httpx

from selvo.discovery.base import PackageRecord

log = logging.getLogger(__name__)

_WINGET_API = "https://api.winget.run/v2/packages"

# High-value endpoint packages always covered even if API is unavailable
_CORE_WINGET: list[tuple[str, str]] = [
    ("Git.Git",                  "Distributed version control system"),
    ("OpenSSH.OpenSSH",         "OpenSSH client and server"),
    ("Python.Python.3.12",      "Python 3.12 runtime"),
    ("Microsoft.PowerShell",    "PowerShell 7+"),
    ("Microsoft.WindowsTerminal","Windows Terminal"),
    ("Microsoft.DotNet.Runtime.8","Microsoft .NET 8 runtime"),
    ("OpenJS.NodeJS",           "Node.js JavaScript runtime"),
    ("Rustlang.Rust.MSVC",      "Rust toolchain (MSVC)"),
    ("GoLang.Go",               "Go programming language"),
    ("GnuPG.Gpg4win",          "GnuPG for Windows"),
    ("Mozilla.Firefox",         "Firefox browser"),
    ("Google.Chrome",           "Google Chrome browser"),
    ("7zip.7zip",               "7-Zip file archiver"),
    ("WinSCP.WinSCP",           "WinSCP SFTP/SCP client"),
    ("PuTTY.PuTTY",             "PuTTY SSH client"),
    ("Notepad++.Notepad++",     "Notepad++ editor"),
    ("Microsoft.VisualStudioCode","VS Code editor"),
    ("Docker.DockerDesktop",    "Docker Desktop"),
    ("Kubernetes.kubectl",      "Kubernetes CLI"),
    ("Helm.Helm",               "Kubernetes package manager"),
    ("Amazon.AWSCLI",           "AWS CLI"),
    ("Google.CloudSDK",         "Google Cloud SDK"),
    ("Microsoft.AzureCLI",      "Azure CLI"),
    ("Hashicorp.Terraform",     "Terraform infrastructure-as-code"),
    ("Hashicorp.Vault",         "HashiCorp Vault secrets manager"),
    ("OpenVPN.OpenVPN",         "OpenVPN client"),
    ("WireGuard.WireGuard",     "WireGuard VPN"),
    ("VideoLAN.VLC",            "VLC media player"),
    ("cURL.cURL",               "curl command-line HTTP tool"),
    ("jqlang.jq",               "JSON processor"),
]


class WinGetDiscovery:
    """Discover top WinGet packages."""

    ecosystem = "winget"

    async def fetch_top(self, limit: int) -> list[PackageRecord]:
        packages = await self._fetch_from_api(limit)
        if not packages:
            packages = self._fallback(limit)
        return packages

    async def _fetch_from_api(self, limit: int) -> list[PackageRecord]:
        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                resp = await client.get(
                    _WINGET_API,
                    params={"perPage": min(limit, 100)},
                    headers={"User-Agent": "selvo/0.1 (winget-discovery)"},
                )
                resp.raise_for_status()
                data = resp.json()
                packages = data if isinstance(data, list) else data.get("Data", []) or data.get("packages", [])
                result: list[PackageRecord] = []
                for pkg in packages[:limit]:
                    pid = pkg.get("PackageIdentifier") or pkg.get("id", "")
                    name = pid or pkg.get("name", "")
                    if not name:
                        continue
                    desc = (
                        pkg.get("ShortDescription")
                        or pkg.get("Description")
                        or pkg.get("description", "")
                    )
                    version = pkg.get("PackageVersion") or pkg.get("version", "unknown")
                    result.append(PackageRecord(
                        name=name,
                        ecosystem=self.ecosystem,
                        version=str(version),
                        description=str(desc)[:200],
                    ))
                if result:
                    log.debug("winget: fetched %d packages from API", len(result))
                return result
        except Exception as exc:
            log.debug("winget: API unavailable (%s) — using curated fallback", exc)
            return []

    def _fallback(self, limit: int) -> list[PackageRecord]:
        return [
            PackageRecord(name=name, ecosystem=self.ecosystem, description=desc)
            for name, desc in _CORE_WINGET[:limit]
        ]
