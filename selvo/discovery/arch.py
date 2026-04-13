"""Arch Linux package discovery via the Arch Linux API."""
from __future__ import annotations

import httpx

from selvo.discovery.base import PackageRecord

_ARCH_API = "https://archlinux.org/packages/search/json/?repo=Core&limit={limit}&offset=0"

_CORE_PACKAGES = [
    "glibc", "gcc-libs", "gcc", "zlib", "openssl", "systemd", "bash",
    "coreutils", "util-linux", "pacman", "python", "tar", "gzip", "bzip2",
    "xz", "curl", "wget", "ca-certificates", "libxml2", "sqlite", "pcre",
    "glib2", "dbus", "pam", "sudo", "shadow", "procps-ng", "e2fsprogs",
    "grep", "sed", "gawk", "findutils", "diffutils", "ncurses", "readline",
    "less", "file", "krb5", "libselinux", "audit", "linux", "linux-headers",
    "mkinitcpio", "grub", "efibootmgr", "dosfstools",
]


class ArchDiscovery:
    """Discover top Arch Linux packages from the Core repo."""

    ecosystem = "arch"

    async def fetch_top(self, limit: int) -> list[PackageRecord]:
        packages = await self._fetch_from_api(limit)
        if not packages:
            packages = self._fallback(limit)
        return packages

    async def _fetch_from_api(self, limit: int) -> list[PackageRecord]:
        try:
            url = _ARCH_API.format(limit=limit)
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, follow_redirects=True)
                resp.raise_for_status()
                data = resp.json()
                return [
                    PackageRecord(
                        name=pkg["pkgname"],
                        ecosystem=self.ecosystem,
                        version=pkg.get("pkgver", "unknown"),
                        description=pkg.get("pkgdesc", ""),
                        homepage=pkg.get("url"),
                    )
                    for pkg in data.get("results", [])[:limit]
                ]
        except Exception:
            return []

    def _fallback(self, limit: int) -> list[PackageRecord]:
        return [
            PackageRecord(name=name, ecosystem=self.ecosystem)
            for name in _CORE_PACKAGES[:limit]
        ]
