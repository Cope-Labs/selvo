"""Ubuntu package discovery — reuses Debian API with Ubuntu suites."""
from __future__ import annotations

import httpx

from selvo.discovery.base import PackageRecord

# Ubuntu popcon (same format as Debian)
_POPCON_URL = "https://popcon.ubuntu.com/by_inst"

# Ubuntu shares most core packages with Debian; names are identical
# We list the ones that differ or are Ubuntu-specific
_CORE_PACKAGES = [
    "libc6", "libgcc-s1", "libstdc++6", "zlib1g", "libssl3", "openssl",
    "libsystemd0", "systemd", "bash", "coreutils", "util-linux", "apt",
    "dpkg", "perl", "python3", "libpython3-stdlib", "tar", "gzip", "bzip2",
    "xz-utils", "curl", "wget", "ca-certificates", "libcurl4", "libxml2",
    "libsqlite3-0", "libpcre3", "libglib2.0-0", "libdbus-1-3", "dbus",
    "libpam-modules", "libpam0g", "sudo", "passwd", "login", "procps",
    "mount", "e2fsprogs", "grep", "sed", "gawk", "findutils", "diffutils",
    "libncurses6", "libreadline8", "readline-common", "less", "file",
    "ubuntu-advantage-tools", "snapd", "cloud-init", "netplan.io",
    "lsb-release", "init-system-helpers",
]


class UbuntuDiscovery:
    """Discover top Ubuntu packages (LTS popcon + fallback curated list)."""

    ecosystem = "ubuntu"

    async def fetch_top(self, limit: int) -> list[PackageRecord]:
        packages = await self._fetch_from_popcon(limit)
        if not packages:
            packages = self._fallback(limit)
        return packages

    async def _fetch_from_popcon(self, limit: int) -> list[PackageRecord]:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(_POPCON_URL, follow_redirects=True)
                resp.raise_for_status()
                return self._parse_popcon(resp.text, limit)
        except Exception:
            return []

    def _parse_popcon(self, text: str, limit: int) -> list[PackageRecord]:
        records: list[PackageRecord] = []
        for line in text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            _rank, name, inst, *_ = parts
            try:
                records.append(
                    PackageRecord(
                        name=name,
                        ecosystem=self.ecosystem,
                        download_count=int(inst),
                    )
                )
            except ValueError:
                continue
            if len(records) >= limit:
                break
        return records

    def _fallback(self, limit: int) -> list[PackageRecord]:
        return [
            PackageRecord(name=name, ecosystem=self.ecosystem)
            for name in _CORE_PACKAGES[:limit]
        ]
