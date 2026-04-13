"""Shared Debian Packages.gz index: deps, binary→source, source→binaries.

This module is the single place that downloads and parses the Debian
``Packages.gz`` file.  It exposes a ``DebianIndex`` dataclass that maps:

- ``deps``:  ``{binary_pkg: [dep, ...]}``
- ``b2s``:   ``{binary_pkg: source_pkg}``  — every binary has an entry;
             when the package has no ``Source:`` field the binary **is** the source.
- ``s2b``:   ``{source_pkg: [binary_pkgs]}``

Both ``graph.builder`` and ``analysis.cve`` import from here so the
Packages.gz download is shared and cached once for the whole pipeline.
"""
from __future__ import annotations

import gzip
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import httpx

from selvo.analysis import cache as _cache

log = logging.getLogger(__name__)

_PACKAGES_URL = (
    "https://deb.debian.org/debian/dists/stable/main/binary-amd64/Packages.gz"
)
_CACHE_KEY = "debian_packages_v4"  # bump when DebianIndex schema changes
_TTL = 86400  # 24 hours

_DEP_CLEAN_RE = re.compile(r"[:(].*")


def _clean_dep(raw: str) -> str:
    return _DEP_CLEAN_RE.sub("", raw).strip()


@dataclass
class DebianIndex:
    """Parsed Debian Packages.gz data."""

    deps: dict[str, list[str]] = field(default_factory=dict)
    b2s: dict[str, str] = field(default_factory=dict)
    s2b: dict[str, list[str]] = field(default_factory=dict)
    b2ver: dict[str, str] = field(default_factory=dict)  # binary → raw Version:
    descriptions: dict[str, str] = field(default_factory=dict)  # binary → short description
    homepages: dict[str, str] = field(default_factory=dict)  # binary → Homepage URL string

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def source_name(self, binary: str) -> str:
        """Return the source package name for *binary*, or *binary* if unknown."""
        return self.b2s.get(binary, binary)

    def binaries(self, source: str) -> list[str]:
        """Return all binary packages emitted by source package *source*."""
        return self.s2b.get(source, [])

    def installed_version(self, name: str) -> str | None:
        """Return the raw Packages.gz Version: string for a binary or source name.

        Tries the name directly (binary), then tries each binary of *name* treated
        as a source.  Returns ``None`` when not found.
        """
        if name in self.b2ver:
            return self.b2ver[name]
        for b in self.s2b.get(name, []):
            if b in self.b2ver:
                return self.b2ver[b]
        return None

    def resolve_to_binaries(self, name: str) -> list[str]:
        """Given a source *or* binary name, return the matching binary package(s).

        If *name* is already a known binary (present in ``deps``), returns
        ``[name]``.  If *name* matches a source package, returns all its
        binary packages that are also present in ``deps``.  Falls back to
        ``[name]`` so callers don't need to special-case the empty list.
        """
        if name in self.deps:
            return [name]
        bins = [b for b in self.s2b.get(name, []) if b in self.deps]
        return bins if bins else [name]

    def source_binaries(self, name: str) -> list[str]:
        """Return ALL binary packages produced by source *name*.

        Unlike :meth:`resolve_to_binaries`, this method **always** looks up
        *name* as a source package first, even when *name* is also a binary
        package (e.g. ``util-linux`` is both the source and a binary).  This
        is what you want after source-collapse, where the merged record is
        named after the source and you need the BFS to start from every
        binary the source emits.

        Falls back to ``[name]`` when neither source nor binary is found.
        """
        bins = [b for b in self.s2b.get(name, []) if b in self.deps]
        if bins:
            return bins
        if name in self.deps:
            return [name]
        return [name]


def _parse_packages_gz(data: bytes) -> DebianIndex:
    """Parse a Debian Packages.gz blob into a :class:`DebianIndex`."""
    deps: dict[str, list[str]] = {}
    b2s: dict[str, str] = {}
    s2b: dict[str, list[str]] = {}
    b2ver: dict[str, str] = {}

    current_name: Optional[str] = None
    current_deps: list[str] = []
    current_source: Optional[str] = None
    current_version: Optional[str] = None
    current_description: Optional[str] = None
    current_homepage: Optional[str] = None
    descriptions: dict[str, str] = {}
    homepages: dict[str, str] = {}

    def _flush() -> None:
        nonlocal current_name, current_deps, current_source, current_version
        nonlocal current_description, current_homepage
        if current_name is None:
            return
        deps[current_name] = current_deps
        source = current_source or current_name
        b2s[current_name] = source
        s2b.setdefault(source, []).append(current_name)
        if current_version:
            b2ver[current_name] = current_version
        if current_description:
            descriptions[current_name] = current_description
        if current_homepage:
            homepages[current_name] = current_homepage
        current_name = None
        current_deps = []
        current_source = None
        current_version = None
        current_description = None
        current_homepage = None

    text = gzip.decompress(data).decode("utf-8", errors="replace")
    for line in text.splitlines():
        if line.startswith("Package: "):
            _flush()
            current_name = line[len("Package: "):].strip()
        elif line.startswith("Version: ") and current_name is not None:
            current_version = line[len("Version: "):].strip()
        elif line.startswith("Source: ") and current_name is not None:
            # Source: field may contain a version: "zlib (1:1.3.dfsg+really1.3.1-1)"
            src = line[len("Source: "):].strip().split("(")[0].strip()
            current_source = src
        elif line.startswith("Depends: ") and current_name is not None:
            for clause in line[len("Depends: "):].split(","):
                clause = clause.strip()
                if "|" in clause:
                    clause = clause.split("|")[0]
                dep = _clean_dep(clause)
                if dep:
                    current_deps.append(dep)
        elif line.startswith("Description: ") and current_name is not None:
            # First line of Description: is the short synopsis
            current_description = line[len("Description: "):].strip()
        elif line.startswith("Homepage: ") and current_name is not None:
            current_homepage = line[len("Homepage: "):].strip()
        elif line == "":
            _flush()

    _flush()  # handle last stanza if file has no trailing blank line

    return DebianIndex(deps=deps, b2s=b2s, s2b=s2b, b2ver=b2ver,
                       descriptions=descriptions, homepages=homepages)


# Module-level cache so the index survives across async calls in the same run.
_in_memory: Optional[DebianIndex] = None


async def load_debian_index() -> DebianIndex:
    """Return the parsed Debian Packages.gz index.

    Load order:
    1. Module-level in-memory cache (same Python process).
    2. SQLite cache (survives across runs, 24 h TTL).
    3. Fresh download from deb.debian.org.
    """
    global _in_memory
    if _in_memory is not None:
        return _in_memory

    cached = _cache.get(_CACHE_KEY)
    if cached:
        _in_memory = DebianIndex(**cached)
        return _in_memory

    log.info("Downloading Debian Packages.gz (~12 MB)…")
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(_PACKAGES_URL, follow_redirects=True)
            resp.raise_for_status()
        idx = _parse_packages_gz(resp.content)
        _cache.set_cache(
            _CACHE_KEY,
            {"deps": idx.deps, "b2s": idx.b2s, "s2b": idx.s2b, "b2ver": idx.b2ver,
             "descriptions": idx.descriptions, "homepages": idx.homepages},
            _TTL,
        )
        log.info(
            "Parsed %d Debian binary packages across %d source packages",
            len(idx.deps),
            len(idx.s2b),
        )
        _in_memory = idx
        return idx
    except Exception as exc:
        log.warning("Failed to fetch Packages.gz: %s", exc)
        return DebianIndex()
