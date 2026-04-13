"""Build and analyse dependency graphs from package metadata.

Downloads package index files for the target ecosystem and parses
dependency relationships. Supported ecosystems:

- **Debian/Ubuntu**: ``Packages.gz`` (~12 MB) from deb.debian.org
- **Alpine**: ``APKINDEX.tar.gz`` (~2 MB) from dl-cdn.alpinelinux.org
- **Fedora**: ``primary.xml.gz`` from mirrors.fedoraproject.org
- **Arch**: desc files from repos, parsed for %DEPENDS%

Graph model: directed graph where A → B means "A depends on B".

Key metrics:
- **transitive_rdep_count**: blast-radius for an unpatched CVE.
- **betweenness**: chokepoint packages on many dependency paths.
"""
from __future__ import annotations

import logging
import re
import tarfile
from collections import deque
from io import BytesIO
from typing import Optional

import httpx
import networkx as nx

from selvo.analysis import cache as _cache
from selvo.analysis.debian_index import load_debian_index

log = logging.getLogger(__name__)

# ── Ecosystem dep loaders ────────────────────────────────────────────────────

_ALPINE_URL = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/x86_64/APKINDEX.tar.gz"
_FEDORA_URL = "https://mirrors.fedoraproject.org/metalink?repo=fedora-42&arch=x86_64"
_ARCH_URL = "https://archive.archlinux.org/repos/last/core/os/x86_64/core.db.tar.gz"

_DEP_TTL = 86400  # 24h cache


async def _load_debian_deps() -> dict[str, list[str]]:
    """Return the dep map from the shared DebianIndex (cached 24 h)."""
    idx = await load_debian_index()
    return idx.deps


async def _load_alpine_deps() -> dict[str, list[str]]:
    """Parse Alpine APKINDEX for dependency data."""
    cached = _cache.get("alpine_deps_v1")
    if cached is not None:
        return cached

    deps: dict[str, list[str]] = {}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(_ALPINE_URL, follow_redirects=True)
            resp.raise_for_status()

        with tarfile.open(fileobj=BytesIO(resp.content), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name == "APKINDEX":
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    text = f.read().decode("utf-8", errors="replace")
                    current_pkg: Optional[str] = None
                    current_deps: list[str] = []
                    for line in text.splitlines():
                        if line.startswith("P:"):
                            if current_pkg:
                                deps[current_pkg] = current_deps
                            current_pkg = line[2:].strip()
                            current_deps = []
                        elif line.startswith("D:"):
                            raw = line[2:].strip()
                            current_deps = [
                                re.sub(r"[<>=~].*", "", d).strip()
                                for d in raw.split()
                                if d and not d.startswith("!")
                            ]
                    if current_pkg:
                        deps[current_pkg] = current_deps
        log.info("Alpine APKINDEX: %d packages with deps", len(deps))
        _cache.set("alpine_deps_v1", deps, ttl=_DEP_TTL)
    except Exception:
        log.warning("Failed to load Alpine APKINDEX, graph metrics will be empty")
    return deps


async def _load_arch_deps() -> dict[str, list[str]]:
    """Parse Arch Linux core repo DB for dependency data."""
    cached = _cache.get("arch_deps_v1")
    if cached is not None:
        return cached

    deps: dict[str, list[str]] = {}
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(_ARCH_URL, follow_redirects=True)
            resp.raise_for_status()

        with tarfile.open(fileobj=BytesIO(resp.content), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("/desc"):
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    text = f.read().decode("utf-8", errors="replace")
                    pkg_name: Optional[str] = None
                    pkg_deps: list[str] = []
                    section = ""
                    for line in text.splitlines():
                        if line.startswith("%") and line.endswith("%"):
                            section = line
                            continue
                        if not line.strip():
                            section = ""
                            continue
                        if section == "%NAME%":
                            pkg_name = line.strip()
                        elif section == "%DEPENDS%":
                            dep = re.sub(r"[<>=].*", "", line.strip())
                            if dep:
                                pkg_deps.append(dep)
                    if pkg_name:
                        deps[pkg_name] = pkg_deps
        log.info("Arch core DB: %d packages with deps", len(deps))
        _cache.set("arch_deps_v1", deps, ttl=_DEP_TTL)
    except Exception:
        log.warning("Failed to load Arch repo DB, graph metrics will be empty")
    return deps


async def _load_deps_for_ecosystem(ecosystem: str) -> dict[str, list[str]]:
    """Load dependency map for the given ecosystem."""
    eco = ecosystem.lower()
    if eco in ("debian", "ubuntu"):
        return await _load_debian_deps()
    if eco == "alpine":
        return await _load_alpine_deps()
    if eco in ("arch", "archlinux"):
        return await _load_arch_deps()
    # Fedora/NixOS/others — no dep index available yet, return empty
    return {}


async def build_graph(
    root_packages: list[str],
    ecosystem: str = "debian",
    depth: int = 3,
) -> nx.DiGraph:
    """BFS-build a directed dep graph rooted at ``root_packages``.

    Edges go FROM a package TO its dependencies. Uses the ecosystem's
    package index as the dependency source.
    """
    dep_map = await _load_deps_for_ecosystem(ecosystem)
    g: nx.DiGraph = nx.DiGraph()
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque((p, 0) for p in root_packages)

    while queue:
        name, level = queue.popleft()
        if name in visited or level > depth:
            continue
        visited.add(name)
        g.add_node(name, level=level, ecosystem=ecosystem)
        for dep in dep_map.get(name, []):
            g.add_edge(name, dep)
            if dep not in visited and level + 1 <= depth:
                queue.append((dep, level + 1))

    return g


async def compute_graph_metrics(
    packages: list[str],
    ecosystem: str = "debian",
    depth: int = 3,
) -> dict[str, dict]:
    """Return graph metrics keyed by package name.

    Each entry has:
    - ``transitive_rdep_count`` – how many packages in the full Debian
      ecosystem transitively depend on this one (true blast-radius).
    - ``betweenness`` – normalised betweenness centrality in the focused
      dependency subgraph around our target packages (0–1).

    Name resolution
    ---------------
    Discovery modules use *source* package names (e.g. "zlib", "glibc") but
    Debian's binary package index uses binary names ("zlib1g", "libc6").
    We resolve each target via :meth:`DebianIndex.resolve_to_binaries` so that
    "zlib" triggers a BFS starting from *all* its binary packages and the
    result is reported back under the original name.
    """
    dep_map = await _load_deps_for_ecosystem(ecosystem)
    if not dep_map:
        return {}

    # Build full reverse index: {dependency: [packages_that_declare_it]}
    rev_index: dict[str, list[str]] = {}
    for pkg, deps in dep_map.items():
        for dep in deps:
            rev_index.setdefault(dep, []).append(pkg)

    # For Debian/Ubuntu, resolve source names to all binary package names.
    # For other ecosystems, each package name maps to itself.
    eco = ecosystem.lower()
    if eco in ("debian", "ubuntu"):
        from selvo.analysis.debian_index import DebianIndex
        idx: DebianIndex = await load_debian_index()
        resolved: dict[str, list[str]] = {t: idx.source_binaries(t) for t in packages}
    else:
        resolved = {t: [t] for t in packages}

    # BFS through reverse index: start from ALL resolved binaries for each target
    rdep_counts: dict[str, int] = {}
    for target, start_bins in resolved.items():
        visited: set[str] = set()
        queue: deque[str] = deque(start_bins)
        while queue:
            name = queue.popleft()
            if name in visited:
                continue
            visited.add(name)
            for rdep in rev_index.get(name, []):
                if rdep not in visited:
                    queue.append(rdep)
        # Subtract the seed nodes themselves so we count only *other* packages
        rdep_counts[target] = max(0, len(visited) - len(start_bins))

    # Build focused forward subgraph for betweenness (targets + their deps, depth N)
    # Use the resolved binary name(s) as starting nodes.
    g: nx.DiGraph = nx.DiGraph()
    visited_fwd: set[str] = set()
    fwd_queue: deque[tuple[str, int]] = deque()
    # Map resolved binary back to target name for betweenness attribution
    bin_to_target: dict[str, str] = {}
    for target, bins in resolved.items():
        for b in bins:
            fwd_queue.append((b, 0))
            bin_to_target[b] = target

    while fwd_queue:
        name, level = fwd_queue.popleft()
        if name in visited_fwd or level > depth:
            continue
        visited_fwd.add(name)
        g.add_node(name)
        for dep in dep_map.get(name, []):
            g.add_edge(name, dep)
            if dep not in visited_fwd and level + 1 <= depth:
                fwd_queue.append((dep, level + 1))

    betweenness: dict[str, float] = {}
    if g.number_of_edges() > 0:
        ug = g.to_undirected()
        raw_bw = nx.betweenness_centrality(ug, normalized=True)
        # Collapse binary → target: take max betweenness across all binaries
        for bin_name, bw in raw_bw.items():
            target = bin_to_target.get(bin_name, bin_name)
            if bw > betweenness.get(target, 0.0):
                betweenness[target] = bw

    return {
        pkg: {
            "transitive_rdep_count": rdep_counts.get(pkg, 0),
            "betweenness": betweenness.get(pkg, 0.0),
        }
        for pkg in packages
    }
