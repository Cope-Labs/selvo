"""Package discovery orchestrator."""
from __future__ import annotations

import asyncio

from selvo.discovery.alpine import AlpineDiscovery
from selvo.discovery.debian import DebianDiscovery
from selvo.discovery.ubuntu import UbuntuDiscovery
from selvo.discovery.fedora import FedoraDiscovery
from selvo.discovery.arch import ArchDiscovery
from selvo.discovery.nixos import NixOSDiscovery
from selvo.discovery.winget import WinGetDiscovery
from selvo.discovery.homebrew import HomebrewDiscovery
from selvo.discovery.chocolatey import ChocolateyDiscovery
from selvo.discovery.base import PackageRecord

# Static cross-ecosystem canonical name map (distro_name → upstream_name)
# Supplements LLM normalization and works offline
_CANONICAL: dict[str, str] = {
    "libc6": "glibc",
    "libgcc-s1": "gcc",
    "gcc-libs": "gcc",
    "libgcc": "gcc",
    "libstdc++6": "gcc",
    "libstdc++": "gcc",
    "zlib1g": "zlib",
    "libssl3": "openssl",
    "openssl-libs": "openssl",
    "libsystemd0": "systemd",
    "libcurl4": "curl",
    "libcurl": "curl",
    "libxml2": "libxml2",
    "libsqlite3-0": "sqlite",
    "libpcre3": "pcre",
    "libglib2.0-0": "glib",
    "glib2": "glib",
    "libdbus-1-3": "dbus",
    "dbus-libs": "dbus",
    "libpam0g": "pam",
    "libpam-modules": "pam",
    "python3-libs": "python3",
    "libpython3-stdlib": "python3",
    "libncurses6": "ncurses",
    "ncurses-libs": "ncurses",
    "libreadline8": "readline",
    "krb5-libs": "krb5",
    "libselinux1": "libselinux",
    "audit-libs": "audit",
    "shadow-utils": "shadow",
    "procps-ng": "procps",
    "util-linux-core": "util-linux",
    "pcre2": "pcre",
    "dnf": "dnf",
}

_ECOSYSTEM_MAP = {
    "debian": [DebianDiscovery],
    "ubuntu": [UbuntuDiscovery],
    "fedora": [FedoraDiscovery],
    "arch": [ArchDiscovery],
    "alpine": [AlpineDiscovery],
    "nixos": [NixOSDiscovery],
    "winget": [WinGetDiscovery],
    "homebrew": [HomebrewDiscovery],
    "chocolatey": [ChocolateyDiscovery],
    "all": [DebianDiscovery, UbuntuDiscovery, FedoraDiscovery, ArchDiscovery, AlpineDiscovery, NixOSDiscovery],
    "all-endpoints": [WinGetDiscovery, HomebrewDiscovery, ChocolateyDiscovery],
}


def _canonical_name(name: str) -> str:
    """Return the canonical upstream name for a distro package name."""
    return _CANONICAL.get(name, name)


async def run_discovery(
    ecosystem: str,
    limit: int,
    llm_normalize: bool = False,
) -> list[PackageRecord]:
    """
    Run discovery for the selected ecosystem(s), apply canonical name normalization,
    merge cross-ecosystem duplicates, and return top `limit` packages.
    """
    discoverers = _ECOSYSTEM_MAP.get(ecosystem, [DebianDiscovery])
    tasks = [cls().fetch_top(limit) for cls in discoverers]
    results: list[list[PackageRecord]] = await asyncio.gather(*tasks)

    # Apply static canonical name map
    for batch in results:
        for pkg in batch:
            pkg.name = _canonical_name(pkg.name)

    # Optional LLM normalization for names the static map misses
    if llm_normalize:
        try:
            from selvo.analysis.llm import get_client
            client = get_client()
            if client.enabled:
                all_pkgs = [p for batch in results for p in batch]
                mapping = await client.normalize_package_names(
                    [(p.name, p.ecosystem) for p in all_pkgs]
                )
                for p in all_pkgs:
                    if p.name in mapping:
                        p.name = mapping[p.name]
        except Exception:
            pass

    # Merge duplicates: same canonical name across ecosystems → best record wins
    # Priority: keep record with highest download_count; merge cve_ids
    canonical_map: dict[str, PackageRecord] = {}
    for batch in results:
        for pkg in batch:
            key = pkg.name
            if key not in canonical_map:
                canonical_map[key] = pkg
            else:
                existing = canonical_map[key]
                # Merge CVEs
                existing.cve_ids = list(set(existing.cve_ids + pkg.cve_ids))
                # Keep highest popularity signal
                if pkg.download_count > existing.download_count:
                    existing.download_count = pkg.download_count
                # Merge ecosystem tag
                if pkg.ecosystem not in existing.ecosystem:
                    existing.ecosystem = f"{existing.ecosystem},{pkg.ecosystem}"

    return list(canonical_map.values())[:limit]
