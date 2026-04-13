# Copyright (c) 2026 Seth Holloway. All rights reserved.
# SPDX-License-Identifier: Elastic-2.0
"""Runtime reachability analysis using Linux procfs.

Reads ``/proc/<pid>/maps`` for every accessible running process and identifies
which CVE-affected shared libraries (``.so`` files) are *actually loaded in
memory right now* — turning "CVE exists in installed package" into actionable
signal like "libssl3 (CVE-2024-XXXX, EPSS 0.91) is loaded in nginx (PID 1234),
apache2 (PID 5678)".

**No kernel extensions, eBPF, or special compile-time dependencies required.**
Works on any Linux host with a standard ``/proc`` filesystem.

Privilege notes
---------------
Full coverage (all processes) requires ``root`` or ``CAP_SYS_PTRACE``.
When running without sufficient privileges the scan gracefully degrades:
it skips unreadable ``/proc/<pid>/maps`` entries and covers only the processes
the current uid can observe (at minimum: its own processes).

Package resolution
------------------
Loaded ``.so`` paths are resolved back to package names using:

1. ``dpkg -S``    (Debian/Ubuntu)  — batch mode, fast
2. ``rpm -qf``    (Fedora/RHEL)    — per-file, slower
3. ``pacman -Qo`` (Arch Linux)     — per-file
4. ``apk info``   (Alpine Linux)   — per-file
5. Path heuristic fallback         — ``/usr/.../libssl.so.3`` → ``libssl3``

Enriched fields on :class:`~selvo.discovery.base.PackageRecord`
---------------------------------------------------------------
* ``runtime_loaded``  – ``True`` if any ``.so`` from this package is live
* ``runtime_pids``    – list of PIDs that have it loaded
* ``runtime_procs``   – list of process ``comm`` names that have it loaded
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from selvo.discovery.base import PackageRecord

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RuntimeHit:
    """A CVE-affected shared library observed in a live process's address space."""

    pid: int
    process_name: str          # /proc/<pid>/comm
    cmdline: str               # /proc/<pid>/cmdline (truncated, NUL→space)
    so_path: str               # primary .so path from /proc/<pid>/maps
    package: str               # owning package name
    version: str               # installed version string
    ecosystem: str             # 'debian' | 'fedora' | …
    cve_ids: list[str] = field(default_factory=list)
    max_epss: float = 0.0
    max_cvss: float = 0.0
    in_cisa_kev: bool = False
    so_paths: list[str] = field(default_factory=list)  # all matched .so paths (may be >1)


# ---------------------------------------------------------------------------
# /proc helpers
# ---------------------------------------------------------------------------

def _iter_proc_dirs() -> list[Path]:
    """Return all accessible /proc/<PID> directories."""
    proc = Path("/proc")
    if not proc.exists():
        return []
    return [d for d in proc.iterdir() if d.name.isdigit() and d.is_dir()]


def _read_proc_file(path: Path) -> str:
    """Read a /proc file safely; returns '' on permission error or missing file."""
    try:
        return path.read_text(errors="replace")
    except (OSError, PermissionError):
        return ""


def _proc_comm(pid_dir: Path) -> str:
    return _read_proc_file(pid_dir / "comm").strip() or f"[{pid_dir.name}]"


def _proc_cmdline(pid_dir: Path, max_len: int = 128) -> str:
    raw = _read_proc_file(pid_dir / "cmdline")
    return raw.replace("\x00", " ").strip()[:max_len]


def _extract_so_paths(maps_text: str) -> set[str]:
    """Parse /proc/<pid>/maps and return all .so library paths."""
    paths: set[str] = set()
    for line in maps_text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        path = parts[5]
        # Must be an absolute path containing a shared-library component
        if path.startswith("/") and ".so" in path:
            paths.add(path)
    return paths


# ---------------------------------------------------------------------------
# Library scanning
# ---------------------------------------------------------------------------

def _scan_one_pid(pid_dir: Path) -> tuple[int, str, str, set[str]] | None:
    """Read one /proc/<pid> directory. Returns (pid, comm, cmdline, so_paths) or None."""
    maps_text = _read_proc_file(pid_dir / "maps")
    if not maps_text:
        return None
    pid = int(pid_dir.name)
    proc_name = _proc_comm(pid_dir)
    cmdline = _proc_cmdline(pid_dir)
    return pid, proc_name, cmdline, _extract_so_paths(maps_text)


def scan_loaded_libraries(max_workers: int = 16) -> dict[str, list[tuple[int, str, str]]]:
    """Scan all accessible processes in parallel and return a library-to-process mapping.

    Parameters
    ----------
    max_workers:
        Thread-pool size. 16 is a good default for I/O-bound procfs reads.

    Returns
    -------
    dict mapping each ``.so`` path to a list of
    ``(pid, process_name, cmdline)`` tuples for every process that has
    that library mapped into its address space.
    """
    pid_dirs = _iter_proc_dirs()
    lib_map: dict[str, list[tuple[int, str, str]]] = {}
    scanned = skipped = 0

    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(pid_dirs)))) as pool:
        futures = {pool.submit(_scan_one_pid, d): d for d in pid_dirs}
        for fut in as_completed(futures):
            result = fut.result()
            if result is None:
                skipped += 1
                continue
            scanned += 1
            pid, proc_name, cmdline, so_paths = result
            for so_path in so_paths:
                lib_map.setdefault(so_path, []).append((pid, proc_name, cmdline))

    log.debug("procfs scan: %d processes scanned, %d skipped (permission denied)", scanned, skipped)
    return lib_map


# ---------------------------------------------------------------------------
# .so → package resolution
# ---------------------------------------------------------------------------

def _dpkg_map(so_paths: list[str]) -> dict[str, str]:
    """Batch-resolve paths to package names via ``dpkg -S``.

    ``dpkg -S`` indexes the *real* (non-symlink) path on disk.  Paths
    from ``/proc/*/maps`` are often symlinks (e.g. ``libssl.so.3`` →
    ``libssl.so.3.0.14``); resolving them before the query and mapping
    results back to the original proc paths restores correct resolution
    on all Debian/Ubuntu hosts.
    """
    if not shutil.which("dpkg") or not so_paths:
        return {}

    # Resolve symlinks; keep a reverse map: realpath → original proc path.
    # If multiple originals share a realpath, the first wins.
    real_to_orig: dict[str, str] = {}
    for p in so_paths:
        rp = str(Path(p).resolve())
        real_to_orig.setdefault(rp, p)

    result: dict[str, str] = {}
    real_paths = list(real_to_orig.keys())
    chunk_size = 60  # dpkg handles multiple args fine

    for i in range(0, len(real_paths), chunk_size):
        chunk = real_paths[i : i + chunk_size]
        try:
            proc = subprocess.run(
                ["dpkg", "-S"] + chunk,
                capture_output=True,
                text=True,
                timeout=15,
            )
            for line in proc.stdout.splitlines():
                if ": " not in line:
                    continue
                pkg_raw, real_path = line.split(": ", 1)
                # "libssl3:amd64" → "libssl3"
                pkg = pkg_raw.split(":")[0].strip()
                real = real_path.strip()
                # Map resolved path back to the original (symlink) proc path
                orig = real_to_orig.get(real, real)
                result[orig] = pkg
        except (subprocess.TimeoutExpired, FileNotFoundError):
            log.debug("dpkg -S timed out or not available")

    return result


def _rpm_map(so_paths: list[str]) -> dict[str, str]:
    """Resolve paths to package names via ``rpm -qf`` (per-file, slower)."""
    if not shutil.which("rpm") or not so_paths:
        return {}

    result: dict[str, str] = {}
    for path in so_paths:
        try:
            out = subprocess.run(
                ["rpm", "-qf", "--queryformat", "%{NAME}", path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            pkg = out.stdout.strip()
            if pkg and "not owned" not in pkg and "error" not in pkg.lower():
                result[path] = pkg
        except (subprocess.TimeoutExpired, FileNotFoundError):
            log.debug("rpm -qf timed out or not available for %s", path)

    return result


def _pacman_map(so_paths: list[str]) -> dict[str, str]:
    """Resolve paths to package names via ``pacman -Qo`` (Arch Linux)."""
    if not shutil.which("pacman") or not so_paths:
        return {}

    result: dict[str, str] = {}
    for path in so_paths:
        try:
            out = subprocess.run(
                ["pacman", "-Qo", path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Output: "/usr/lib/libssl.so.3 is owned by openssl 3.3.2-1"
            m = re.search(r"is owned by (\S+)", out.stdout)
            if m:
                result[path] = m.group(1)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            log.debug("pacman -Qo timed out or not available for %s", path)

    return result


def _apk_map(so_paths: list[str]) -> dict[str, str]:
    """Resolve paths to package names via ``apk info --who-owns`` (Alpine Linux)."""
    if not shutil.which("apk") or not so_paths:
        return {}

    result: dict[str, str] = {}
    for path in so_paths:
        try:
            out = subprocess.run(
                ["apk", "info", "--who-owns", path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Output: "/usr/lib/libssl.so.3 is owned by libssl3-3.3.2-r0"
            # Extract package name (strip version suffix)
            m = re.search(r"is owned by (\S+)", out.stdout)
            if m:
                # Remove trailing version: "libssl3-3.3.2-r0" → "libssl3"
                pkg_full = m.group(1)
                pkg_name = re.sub(r"-[0-9].*$", "", pkg_full)
                result[path] = pkg_name
        except (subprocess.TimeoutExpired, FileNotFoundError):
            log.debug("apk info timed out or not available for %s", path)

    return result


def _heuristic_map(so_paths: list[str], existing: dict[str, str]) -> dict[str, str]:
    """Path-heuristic fallback: derive a likely package name from the filename.

    E.g. ``/usr/lib/x86_64-linux-gnu/libssl.so.3`` → ``libssl3``
    """
    result: dict[str, str] = {}
    for path in so_paths:
        if path in existing:
            continue
        fname = Path(path).name  # e.g. "libssl.so.3"
        m = re.match(r"(.+?)\.so(\.\d+)?", fname)
        if m:
            base = m.group(1).lower()  # "libssl"
            ver_suffix = (m.group(2) or "").lstrip(".")  # "3"
            result[path] = f"{base}{ver_suffix}" if ver_suffix else base
    return result


def map_sos_to_packages(so_paths: list[str]) -> dict[str, str]:
    """Map a list of loaded ``.so`` paths to their owning package names.

    Resolution order: dpkg → rpm → pacman → apk → heuristic.
    Each backend only runs on paths not already resolved by the previous one.

    Returns
    -------
    dict[so_path, package_name]
    """
    resolved: dict[str, str] = {}

    # Tier 1: dpkg (Debian/Ubuntu — batch, fast)
    resolved.update(_dpkg_map(so_paths))

    # Tier 2: rpm (Fedora/RHEL — per-file, only unresolved paths)
    unresolved = [p for p in so_paths if p not in resolved]
    if unresolved:
        resolved.update(_rpm_map(unresolved))

    # Tier 3: pacman (Arch — per-file, only unresolved paths)
    unresolved = [p for p in so_paths if p not in resolved]
    if unresolved:
        resolved.update(_pacman_map(unresolved))

    # Tier 4: apk (Alpine — per-file, only unresolved paths)
    unresolved = [p for p in so_paths if p not in resolved]
    if unresolved:
        resolved.update(_apk_map(unresolved))

    # Tier 5: path heuristic fallback for anything still unresolved
    resolved.update(_heuristic_map(so_paths, resolved))
    return resolved


# ---------------------------------------------------------------------------
# Main enrichment entry point
# ---------------------------------------------------------------------------

def enrich_runtime(
    packages: list[PackageRecord],
    *,
    cve_only: bool = True,
    deb_idx: Optional[Any] = None,
) -> tuple[list[PackageRecord], list[RuntimeHit]]:
    """Populate runtime load status on each package and return :class:`RuntimeHit` list.

    Parameters
    ----------
    packages:
        CVE-enriched package records (output of ``enrich_cve`` / scorer).
    cve_only:
        When *True* (default) only generate :class:`RuntimeHit` entries for
        packages that have at least one open CVE — this keeps the output
        focused on actionable risk.
    deb_idx:
        Optional :class:`~selvo.analysis.debian_index.DebianIndex`. When
        provided, source package names (e.g. ``openssl``) are expanded to
        their binary package siblings (``libssl3``, ``libcrypto3``) before
        matching against the loaded ``.so`` map — dramatically improving
        recall on Debian/Ubuntu systems where selvo uses source package names.

    Returns
    -------
    ``(enriched_packages, hits)`` where *hits* are sorted by
    ``(in_cisa_kev DESC, max_epss DESC, max_cvss DESC)``.
    """
    log.info("Starting runtime reachability scan via /proc/*/maps …")
    lib_map = scan_loaded_libraries()

    if not lib_map:
        log.warning("No shared library entries found — /proc may be unavailable or empty")
        return packages, []

    log.debug("Found %d distinct .so paths across all accessible processes", len(lib_map))

    # Resolve all loaded paths to package names in one pass
    all_so_paths = list(lib_map.keys())
    so_to_pkg = map_sos_to_packages(all_so_paths)

    # Build reverse index: package_name_lower → [so_path, ...]
    pkg_to_sos: dict[str, list[str]] = {}
    for so_path, pkg_name in so_to_pkg.items():
        pkg_to_sos.setdefault(pkg_name.lower(), []).append(so_path)

    hits: list[RuntimeHit] = []

    for pkg in packages:
        # Match on the package name and common variant spellings.
        # Start with the bare name (works when selvo discovers binary pkg names).
        candidates: set[str] = {pkg.name.lower()}

        # Fix: use removeprefix (prefix-based), not lstrip (char-set-based).
        # "libssl3".removeprefix("lib") = "ssl3"; useful for heuristic-resolved paths.
        stripped = pkg.name.lower().removeprefix("lib")
        if stripped != pkg.name.lower():
            candidates.add(stripped)

        # Source→binary expansion: "openssl" → ["libssl3", "libcrypto3", ...]
        # This is the primary fix for Debian source-package-named records.
        if deb_idx is not None:
            for binary in deb_idx.s2b.get(pkg.name, []):
                b = binary.lower()
                candidates.add(b)
                candidates.add(b.removeprefix("lib"))

        matched_sos: list[str] = []
        for key in candidates:
            matched_sos.extend(pkg_to_sos.get(key, []))
        # Remove duplicates while preserving order
        seen: set[str] = set()
        deduped: list[str] = []
        for s in matched_sos:
            if s not in seen:
                seen.add(s)
                deduped.append(s)
        matched_sos = deduped

        if not matched_sos:
            continue

        # Aggregate (pid, comm, cmdline) across all matched libraries
        all_procs: dict[int, tuple[str, str]] = {}  # pid → (comm, cmdline)
        for so_path in matched_sos:
            for pid, proc_name, cmdline in lib_map.get(so_path, []):
                all_procs[pid] = (proc_name, cmdline)

        if not all_procs:
            continue

        pkg.runtime_loaded = True
        pkg.runtime_pids = sorted(all_procs.keys())
        pkg.runtime_procs = [all_procs[p][0] for p in pkg.runtime_pids]

        if cve_only and not pkg.cve_ids:
            continue

        # One RuntimeHit per (package, pid) pair
        for pid in pkg.runtime_pids:
            proc_name, cmdline = all_procs[pid]
            hits.append(
                RuntimeHit(
                    pid=pid,
                    process_name=proc_name,
                    cmdline=cmdline,
                    so_path=matched_sos[0],   # primary (for backward compat)
                    so_paths=matched_sos,     # all matched .so files for this pkg
                    package=pkg.name,
                    version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    cve_ids=list(pkg.cve_ids),
                    max_epss=pkg.max_epss,
                    max_cvss=pkg.max_cvss,
                    in_cisa_kev=pkg.in_cisa_kev,
                )
            )

    # Deduplicate hits: one hit per (package, pid) is enough
    seen_pairs: set[tuple[str, int]] = set()
    deduped_hits: list[RuntimeHit] = []
    for h in hits:
        key = (h.package, h.pid)
        if key not in seen_pairs:
            seen_pairs.add(key)
            deduped_hits.append(h)

    deduped_hits.sort(
        key=lambda h: (h.in_cisa_kev, h.max_epss, h.max_cvss),
        reverse=True,
    )

    loaded_count = sum(1 for p in packages if p.runtime_loaded)
    cve_loaded_count = sum(1 for p in packages if p.runtime_loaded and p.cve_ids)
    log.info(
        "Runtime scan complete: %d packages loaded, %d with open CVEs, %d hits",
        loaded_count,
        cve_loaded_count,
        len(deduped_hits),
    )

    return packages, deduped_hits


# ---------------------------------------------------------------------------
# eBPF event merge — feed real-time dlopen events back into the package model
# ---------------------------------------------------------------------------

_DIGIT_STRIP_RE = re.compile(r"\d+$")


def merge_ebpf_events(
    events: list,  # list[DlopenEvent]; avoid circular import at definition time
    packages: list[PackageRecord],
    *,
    deb_idx: Optional[Any] = None,
) -> tuple[list[PackageRecord], list["RuntimeHit"]]:
    """Merge real-time eBPF dlopen events into PackageRecord runtime state.

    Translates streaming
    :class:`~selvo.analysis.ebpf_tracer.DlopenEvent` objects produced by
    :func:`~selvo.analysis.ebpf_tracer.trace_dlopen` into the same data
    model as :func:`enrich_runtime`, enabling re-scoring via
    :func:`~selvo.prioritizer.scorer.score_and_rank` after the session.

    Parameters
    ----------
    events:
        List of DlopenEvent captured by the tracer.
    packages:
        CVE-enriched package records.  ``runtime_loaded``,
        ``runtime_pids``, and ``runtime_procs`` are updated in place.
    deb_idx:
        Optional :class:`~selvo.analysis.debian_index.DebianIndex` for
        source→binary name expansion (same semantics as
        :func:`enrich_runtime`).

    Returns
    -------
    ``(updated_packages, hits)`` — same shape as :func:`enrich_runtime`.
    """
    # Build: loaded .so path → [(pid, proc_name)] from eBPF events.
    dlopen_map: dict[str, list[tuple[int, str]]] = {}
    for evt in events:
        if evt.filename:
            dlopen_map.setdefault(evt.filename, []).append((evt.pid, evt.process_name))

    if not dlopen_map:
        return packages, []

    # Resolve .so paths → package names using the same cascade as enrich_runtime.
    so_to_pkg = map_sos_to_packages(list(dlopen_map.keys()))

    # Build reverse index: pkg_name_lower → [so_path, …]
    pkg_to_sos: dict[str, list[str]] = {}
    for so_path, pkg_name in so_to_pkg.items():
        pkg_to_sos.setdefault(pkg_name.lower(), []).append(so_path)

    hits: list[RuntimeHit] = []

    for pkg in packages:
        # Same 4-variant candidate set used in enrich_runtime:
        # full name / lib-stripped / digit-stripped / both stripped
        n = pkg.name.lower()
        ns = _DIGIT_STRIP_RE.sub("", n)
        candidates: set[str] = {n, n.removeprefix("lib"), ns, ns.removeprefix("lib")}

        if deb_idx is not None:
            for binary in deb_idx.s2b.get(pkg.name, []):
                b = binary.lower()
                bs = _DIGIT_STRIP_RE.sub("", b)
                candidates.update({b, b.removeprefix("lib"), bs, bs.removeprefix("lib")})

        matched_sos: list[str] = []
        seen_s: set[str] = set()
        for key in candidates:
            for p in pkg_to_sos.get(key, []):
                if p not in seen_s:
                    seen_s.add(p)
                    matched_sos.append(p)

        if not matched_sos:
            continue

        all_procs: dict[int, str] = {}  # pid → proc_name
        for so_path in matched_sos:
            for pid, proc_name in dlopen_map.get(so_path, []):
                all_procs[pid] = proc_name

        if not all_procs:
            continue

        pkg.runtime_loaded = True
        pkg.runtime_pids = sorted(all_procs.keys())
        pkg.runtime_procs = [all_procs[p] for p in pkg.runtime_pids]

        for pid in pkg.runtime_pids:
            hits.append(
                RuntimeHit(
                    pid=pid,
                    process_name=all_procs[pid],
                    cmdline="",          # eBPF events don't carry cmdline
                    so_path=matched_sos[0],
                    so_paths=matched_sos,
                    package=pkg.name,
                    version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    cve_ids=list(pkg.cve_ids),
                    max_epss=pkg.max_epss,
                    max_cvss=pkg.max_cvss,
                    in_cisa_kev=pkg.in_cisa_kev,
                )
            )

    # Deduplicate: one hit per (package, pid)
    seen_pairs: set[tuple[str, int]] = set()
    deduped_hits: list[RuntimeHit] = []
    for h in hits:
        key = (h.package, h.pid)
        if key not in seen_pairs:
            seen_pairs.add(key)
            deduped_hits.append(h)

    deduped_hits.sort(
        key=lambda h: (h.in_cisa_kev, h.max_epss, h.max_cvss),
        reverse=True,
    )
    return packages, deduped_hits


# ---------------------------------------------------------------------------
# Standalone scan (no package list required)
# ---------------------------------------------------------------------------

def standalone_scan() -> tuple[dict[str, list[tuple[int, str, str]]], dict[str, str]]:
    """Scan for all loaded .so files without cross-referencing CVE data.

    Useful for raw ``selvo runtime --raw`` output or pipeline integration.

    Returns
    -------
    ``(lib_map, so_to_pkg)`` where *lib_map* is path→[(pid, comm, cmdline)]
    and *so_to_pkg* is path→package_name.
    """
    lib_map = scan_loaded_libraries()
    so_to_pkg = map_sos_to_packages(list(lib_map.keys()))
    return lib_map, so_to_pkg
