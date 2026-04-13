"""Homebrew package discovery.

Queries the formulae.brew.sh JSON API for the most-installed Homebrew
formulae (macOS + Linux) and normalises them into PackageRecords.

The API endpoint returns an analytics-ranked list of all formulae with
install counts, versions, and dependency graphs — no auth required.

API reference: https://formulae.brew.sh/docs/api/
"""
from __future__ import annotations

import logging

import httpx

from selvo.discovery.base import PackageRecord

log = logging.getLogger(__name__)

_BREW_ANALYTICS = "https://formulae.brew.sh/api/formula.json"

# Always-included high-value formulae (dev tooling, security-critical)
_CORE_BREW: list[tuple[str, str]] = [
    ("openssl@3",       "TLS/SSL and crypto library"),
    ("curl",            "Transfer data with URLs"),
    ("wget",            "Internet file retriever"),
    ("git",             "Distributed revision control"),
    ("python@3.12",     "Interpreted, interactive object-oriented language"),
    ("node",            "Platform for JavaScript runtime"),
    ("go",              "Open source programming language"),
    ("rust",            "Safe, concurrent, practical programming language"),
    ("cmake",           "Cross-platform build system"),
    ("pkg-config",      "Library compile and link flag helper"),
    ("libyaml",         "YAML parser and emitter library"),
    ("libxml2",         "XML C parser and toolkit"),
    ("libssh2",         "C library implementing SSH protocols"),
    ("gnutls",          "GNU TLS library"),
    ("nettle",          "Low-level cryptographic library"),
    ("gnupg",           "GNU Pretty Good Privacy (PGP) package"),
    ("ca-certificates", "Mozilla CA certificate bundle"),
    ("zstd",            "Zstandard is a real-time compression algorithm"),
    ("lz4",             "Extremely fast compression algorithm"),
    ("xz",              "General-purpose data compression tool"),
    ("zlib",            "Lossless data-compression library"),
    ("bzip2",           "Freely available high-quality data compressor"),
    ("readline",        "Library for command-line editing"),
    ("sqlite",          "Command-line interface for SQLite"),
    ("pcre2",           "Perl compatible regular expressions library"),
    ("glib",            "Core application library for C"),
    ("gettext",         "GNU internationalization tools"),
    ("autoconf",        "Automatic configure script builder"),
    ("automake",        "Tool for generating GNU Standards-compliant Makefiles"),
    ("libtool",         "Generic library support script"),
    ("ninja",           "Small build system for use with gyp or CMake"),
    ("meson",           "Fast and user friendly build system"),
    ("llvm",            "Next-generation compiler infrastructure"),
    ("gcc",             "GNU compiler collection"),
    ("make",            "Utility for directing compilation"),
    ("bash",            "Bourne-Again SHell"),
    ("zsh",             "UNIX shell (command interpreter)"),
    ("fish",            "User-friendly command-line shell"),
    ("tmux",            "Terminal multiplexer"),
    ("vim",             "Vi improved text editor"),
    ("neovim",          "Ambitious Vim-fork focused on extensibility"),
    ("ripgrep",         "Search tool like grep and The Silver Searcher"),
    ("fd",              "Simple, fast and user-friendly alternative to find"),
    ("jq",              "Lightweight and flexible command-line JSON processor"),
    ("yq",              "Process YAML, JSON, XML, CSV, TOML and properties"),
    ("terraform",       "Tool to build, change, and version infrastructure"),
    ("helm",            "The Kubernetes Package Manager"),
    ("kubectl",         "Kubernetes command-line interface"),
    ("docker",          "Docker command-line client"),
    ("docker-compose",  "Isolated development environments using Docker"),
]


class HomebrewDiscovery:
    """Discover top Homebrew formulae."""

    ecosystem = "homebrew"

    async def fetch_top(self, limit: int) -> list[PackageRecord]:
        packages = await self._fetch_from_api(limit)
        if not packages:
            packages = self._fallback(limit)
        return packages

    async def _fetch_from_api(self, limit: int) -> list[PackageRecord]:
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                resp = await client.get(
                    _BREW_ANALYTICS,
                    headers={"User-Agent": "selvo/0.1 (homebrew-discovery)"},
                )
                resp.raise_for_status()
                formulae: list[dict] = resp.json()

            result: list[PackageRecord] = []
            for formula in formulae[:limit]:
                name = formula.get("name", "")
                if not name:
                    continue
                version = (
                    formula.get("versions", {}).get("stable")
                    or formula.get("version", "unknown")
                )
                desc = formula.get("desc", "")
                homepage = formula.get("homepage")
                deps = formula.get("dependencies", [])
                result.append(PackageRecord(
                    name=name,
                    ecosystem=self.ecosystem,
                    version=str(version),
                    description=str(desc)[:200],
                    homepage=homepage,
                    dependencies=list(deps)[:50],
                ))

            log.debug("homebrew: fetched %d formulae from API", len(result))
            return result
        except Exception as exc:
            log.debug("homebrew: API unavailable (%s) — using curated fallback", exc)
            return []

    def _fallback(self, limit: int) -> list[PackageRecord]:
        return [
            PackageRecord(name=name, ecosystem=self.ecosystem, description=desc)
            for name, desc in _CORE_BREW[:limit]
        ]
