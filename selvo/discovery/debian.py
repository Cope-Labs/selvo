"""Debian/Ubuntu package discovery via the Debian API and popcon data."""
from __future__ import annotations

import httpx

from selvo.discovery.base import PackageRecord

# Debian popcon top packages endpoint (mirrors popcon.debian.org data)
_POPCON_URL = "https://popcon.debian.org/by_inst"

# Fallback: well-known core Debian packages ordered by reverse dependency count
_CORE_PACKAGES = [
    "libc6", "libgcc-s1", "libstdc++6", "zlib1g", "libssl3", "openssl",
    "libsystemd0", "systemd", "bash", "coreutils", "util-linux", "apt",
    "dpkg", "perl", "python3", "libpython3-stdlib", "tar", "gzip", "bzip2",
    "xz-utils", "curl", "wget", "ca-certificates", "libcurl4", "libxml2",
    "libsqlite3-0", "libpcre3", "libglib2.0-0", "libdbus-1-3", "dbus",
    "libpam-modules", "libpam0g", "sudo", "passwd", "login", "procps",
    "mount", "e2fsprogs", "grep", "sed", "awk", "findutils", "diffutils",
    "libncurses6", "libreadline8", "readline-common", "less", "file",
    "lsb-release", "init-system-helpers", "sysvinit-utils",
]


class DebianDiscovery:
    """Discover top Debian packages."""

    ecosystem = "debian"

    async def fetch_top(self, limit: int) -> list[PackageRecord]:
        """Return the top `limit` core Debian packages."""
        packages = await self._fetch_from_api(limit)
        if not packages:
            packages = self._fallback(limit)
        return packages

    async def _fetch_from_api(self, limit: int) -> list[PackageRecord]:
        """Try to fetch real popcon data; return empty list on failure."""
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
