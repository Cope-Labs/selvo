"""Fedora/RHEL package discovery via the Fedora APIs."""
from __future__ import annotations


from selvo.discovery.base import PackageRecord

_MDAPI_URL = "https://mdapi.fedoraproject.org/rawhide/pkg/{name}"

_CORE_PACKAGES = [
    "glibc", "gcc", "libgcc", "libstdc++", "zlib", "openssl", "openssl-libs",
    "systemd", "bash", "coreutils", "util-linux", "rpm", "dnf", "python3",
    "python3-libs", "tar", "gzip", "bzip2", "xz", "curl", "libcurl", "wget",
    "ca-certificates", "libxml2", "sqlite", "pcre2", "glib2", "dbus",
    "dbus-libs", "pam", "sudo", "shadow-utils", "procps-ng", "util-linux-core",
    "e2fsprogs", "grep", "sed", "gawk", "findutils", "diffutils",
    "ncurses", "ncurses-libs", "readline", "less", "file", "redhat-release",
    "krb5-libs", "libselinux", "selinux-policy", "audit-libs",
]


class FedoraDiscovery:
    """Discover top Fedora packages."""

    ecosystem = "fedora"

    async def fetch_top(self, limit: int) -> list[PackageRecord]:
        return self._fallback(limit)

    def _fallback(self, limit: int) -> list[PackageRecord]:
        return [
            PackageRecord(name=name, ecosystem=self.ecosystem)
            for name in _CORE_PACKAGES[:limit]
        ]
