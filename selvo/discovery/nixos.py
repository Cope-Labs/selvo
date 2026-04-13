"""
NixOS / nixpkgs package discovery.

NixOS is the last major ecosystem in the big-5 (Debian/Ubuntu/Fedora/Arch/Alpine/Nix).
The nixpkgs repo is the single largest package repository by count (~90k packages).
Nix packages use unique naming (python311Packages.requests, etc.) but the core
system packages that map well to selvo's purpose are straightforward.

We use a curated list of Nix core/system packages — names as they appear in
nixpkgs attribute paths and as Repology knows them.
"""
from __future__ import annotations

from selvo.discovery.base import PackageRecord

# fmt: off
_NIX_CORE: list[tuple[str, str]] = [
    # libc & runtime
    ("glibc",           "GNU C Library"),
    ("gcc",             "GNU Compiler Collection"),
    ("gcc-unwrapped",   "GCC (unwrapped)"),
    ("libgcc",          "GCC runtime libraries"),
    ("binutils",        "GNU binary utilities"),
    ("binutils-unwrapped", "binutils (unwrapped)"),
    # package management
    ("nix",             "Nix package manager"),
    ("nixos-rebuild",   "NixOS rebuild tool"),
    # core utilities
    ("coreutils",       "GNU core utilities"),
    ("util-linux",      "System utilities"),
    ("findutils",       "GNU find, xargs"),
    ("diffutils",       "GNU diff, cmp, patch"),
    ("gnugrep",         "GNU grep"),
    ("gnused",          "GNU sed"),
    ("gawk",            "GNU awk"),
    ("gnutar",          "GNU tar"),
    ("gzip",            "GNU gzip"),
    ("bzip2",           "bzip2 compression"),
    ("xz",              "XZ compression"),
    ("zstd",            "Zstandard compression"),
    ("zlib",            "zlib compression library"),
    # crypto & TLS
    ("openssl",         "OpenSSL cryptography library"),
    ("openssl_3",       "OpenSSL 3.x"),
    ("gnutls",          "GNU TLS library"),
    ("gnupg",           "GNU Privacy Guard"),
    ("libressl",        "LibreSSL"),
    ("cacert",          "CA certificates"),
    ("krb5",            "Kerberos v5"),
    # networking
    ("curl",            "URL transfer tool"),
    ("wget",            "Network downloader"),
    ("openssh",         "OpenSSH client and server"),
    ("iptables",        "IP packet filter"),
    ("iproute2",        "IP routing utilities"),
    ("iputils",         "Common network tools"),
    ("nmap",            "Network scanner"),
    # shell & scripting
    ("bash",            "GNU Bourne Again SHell"),
    ("zsh",             "Z shell"),
    ("fish",            "Friendly interactive shell"),
    ("python3",         "Python 3 interpreter"),
    ("perl",            "Perl language runtime"),
    ("ruby",            "Ruby language runtime"),
    ("lua",             "Lua scripting language"),
    # build tools
    ("cmake",           "Cross-platform build system"),
    ("gnumake",         "GNU Make"),
    ("ninja",           "Ninja build system"),
    ("pkg-config",      "pkg-config"),
    ("meson",           "Meson build system"),
    ("libtool",         "GNU libtool"),
    ("autoconf",        "Autoconf"),
    ("automake",        "Automake"),
    # libraries
    ("libffi",          "Foreign function interface"),
    ("ncurses",         "Ncurses terminal library"),
    ("readline",        "GNU readline"),
    ("expat",           "XML parsing library"),
    ("pcre2",           "Perl-compatible regex v2"),
    ("libxml2",         "XML processing library"),
    ("libxslt",         "XSLT library"),
    ("sqlite",          "SQLite database"),
    ("libpng",          "PNG image library"),
    ("libjpeg",         "JPEG image codec"),
    ("freetype",        "Font rendering library"),
    ("fontconfig",      "Font configuration library"),
    ("dbus",            "D-Bus message bus"),
    ("glib",            "GLib library"),
    ("pam",             "Linux PAM"),
    ("libcap",          "POSIX capabilities library"),
    ("acl",             "Access control list"),
    ("attr",            "Extended attributes"),
    # system
    ("systemd",         "System and service manager"),
    ("shadow",          "Password management utilities"),
    ("procps",          "Process utilities"),
    ("e2fsprogs",       "ext2/3/4 utilities"),
    ("lvm2",            "Logical volume management"),
    # dev tools
    ("git",             "Distributed version control"),
    ("mercurial",       "Mercurial VCS"),
    ("subversion",      "Apache Subversion"),
    ("strace",          "System call tracer"),
    ("gdb",             "GNU debugger"),
    ("valgrind",        "Memory error detector"),
    ("perf",            "Linux perf tools"),
]
# fmt: on


class NixOSDiscovery:
    """Discover popular NixOS/nixpkgs packages."""

    async def fetch_top(self, limit: int = 50) -> list[PackageRecord]:
        return [
            PackageRecord(
                name=name,
                ecosystem="nixos",
                version="unknown",
                description=desc,
                download_count=0,
            )
            for name, desc in _NIX_CORE[:limit]
        ]
