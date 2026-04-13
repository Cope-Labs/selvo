"""Alpine Linux package discovery.

Uses a curated list of the most fundamental Alpine packages — the core
set found in nearly every Alpine-based Docker image and Alpine install.
Alpine is the dominant container base image (FROM alpine) so even small
packages here have enormous downstream blast radius in the cloud.

Ecosystem note: Alpine packages use 'musl' not 'glibc', 'busybox' not
'coreutils', and naming is generally simpler than Debian.
"""
from __future__ import annotations

from typing import Optional

import httpx

from selvo.discovery.base import PackageRecord

# fmt: off
_ALPINE_CORE: list[tuple[str, str]] = [
    # libc & base runtime
    ("musl",                "C standard library (musl) for Alpine"),
    ("musl-dev",            "musl libc development files"),
    ("libc-dev",            "POSIX C library development files"),
    ("libc-utils",          "Various utilities for libc"),
    # package manager
    ("apk-tools",           "Alpine Package Keeper tools"),
    ("alpine-baselayout",   "Alpine base filesystem layout"),
    ("alpine-keys",         "Public keys for Alpine apk"),
    # core utilities
    ("busybox",             "Size-optimized UNIX tools"),
    ("busybox-extras",      "Additional busybox applets"),
    ("coreutils",           "GNU core utilities"),
    ("util-linux",          "System utilities"),
    ("findutils",           "GNU find, xargs"),
    ("grep",                "Pattern matching"),
    ("sed",                 "Stream editor"),
    ("gawk",                "GNU awk"),
    ("diffutils",           "diff, cmp, patch"),
    ("patch",               "Apply patches"),
    ("file",                "File type identification"),
    # compression
    ("tar",                 "Tape archiver"),
    ("gzip",                "GNU gzip compression"),
    ("bzip2",               "bzip2 compression"),
    ("xz",                  "XZ compression"),
    ("lz4",                 "LZ4 fast compression"),
    ("zstd",                "Zstandard compression"),
    ("zlib",                "Compression library"),
    ("zlib-dev",            "zlib development files"),
    # crypto & TLS
    ("openssl",             "Cryptography and TLS library"),
    ("openssl-dev",         "OpenSSL development files"),
    ("libssl3",             "OpenSSL shared libraries"),
    ("libcrypto3",          "OpenSSL crypto shared library"),
    ("ca-certificates",     "Common CA certificates"),
    ("gnutls",              "GNU TLS library"),
    ("nettle",              "Low-level crypto library"),
    # networking
    ("curl",                "URL transfer tool"),
    ("wget",                "Network downloader"),
    ("openssh",             "OpenSSH client and server"),
    ("openssh-client",      "OpenSSH client"),
    ("iptables",            "IP packet filter"),
    ("iproute2",            "IP routing utilities"),
    ("iputils",             "Common network tools"),
    ("net-tools",           "Network configuration tools"),
    # shell & scripting
    ("bash",                "GNU Bourne Again SHell"),
    ("dash",                "POSIX-compliant shell"),
    ("python3",             "Python 3 interpreter"),
    ("perl",                "Perl scripting language"),
    ("lua5.4",              "Lua scripting language"),
    # build tools
    ("gcc",                 "GNU C compiler"),
    ("g++",                 "GNU C++ compiler"),
    ("make",                "Build automation tool"),
    ("binutils",            "Binary utilities"),
    ("libgcc",              "GCC runtime library"),
    ("libstdc++",           "GNU C++ standard library"),
    # libraries
    ("libffi",              "Foreign function interface library"),
    ("libffi-dev",          "libffi development files"),
    ("ncurses-libs",        "Ncurses terminal control"),
    ("readline",            "GNU readline library"),
    ("expat",               "XML parsing library"),
    ("pcre2",               "Perl-compatible regex"),
    ("libxml2",             "XML processing library"),
    ("sqlite-libs",         "SQLite shared library"),
    ("libpng",              "PNG image library"),
    ("libjpeg-turbo",       "JPEG image codec"),
    # system
    ("linux-pam",           "Pluggable authentication modules"),
    ("shadow",              "Password/group file utilities"),
    ("libcap",              "POSIX capabilities library"),
    ("attr",                "Extended attribute utilities"),
    ("acl",                 "Access control list utilities"),
    ("procps",              "Process utilities (ps, top)"),
    ("e2fsprogs",           "ext2/3/4 filesystem utilities"),
    # dev tools
    ("git",                 "Distributed version control"),
    ("cmake",               "Cross-platform build system"),
    ("pkgconf",             "pkg-config replacement"),
]
# fmt: on


async def _discover_alpine_core(
    limit: int, _client: Optional[httpx.AsyncClient] = None
) -> list[PackageRecord]:
    """Build PackageRecord list from curated Alpine core package list."""
    records = []
    for name, description in _ALPINE_CORE[:limit]:
        records.append(
            PackageRecord(
                name=name,
                ecosystem="alpine",
                version="unknown",
                description=description,
                download_count=0,
            )
        )
    return records


class AlpineDiscovery:
    """Discover popular Alpine Linux packages."""

    async def fetch_top(self, limit: int = 50) -> list[PackageRecord]:
        return await _discover_alpine_core(limit)

    async def get_top_packages(self, limit: int = 50) -> list[PackageRecord]:
        return await self.fetch_top(limit)
