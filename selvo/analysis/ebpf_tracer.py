# Copyright (c) 2026 Seth Holloway. All rights reserved.
# SPDX-License-Identifier: Elastic-2.0
"""eBPF-based real-time dlopen tracer for selvo.

Attaches uretprobes to the C library's ``dlopen`` family
(``dlopen``, ``dlmopen``, ``android_dlopen_ext``) to trace every successful
shared-library load event as it happens.

This is a live, streaming complement to the procfs snapshot in
:mod:`selvo.analysis.runtime`.  Where :func:`~selvo.analysis.runtime.scan_loaded_libraries`
answers "what is loaded right now?", this tracer answers
"what is being loaded moment-to-moment?" — capturing ephemeral worker
processes, short-lived containers, and dynamic plugin loads that a procfs
snapshot would miss.

Requirements
------------
* Linux kernel ≥ 5.8 (BTF/CO-RE for portable eBPF; kernel 4.14+ works with
  non-CO-RE but requires kernel headers installed)
* ``bcc`` Python bindings — install via distro package manager:

    Debian/Ubuntu:  apt install python3-bpfcc bpfcc-tools
    Fedora/RHEL:    dnf install bcc-tools python3-bcc
    Arch:           pacman -S bcc python-bcc

* ``CAP_BPF`` + ``CAP_SYS_PTRACE`` or plain ``root``

Graceful degradation
--------------------
If ``bcc`` is not importable **or** the required capabilities are absent,
:func:`trace_dlopen` logs a warning and returns an empty iterator.
Callers should fall back to the procfs snapshot via
:func:`selvo.analysis.runtime.enrich_runtime`.

Usage
-----
::

    from selvo.analysis.ebpf_tracer import trace_dlopen, is_ebpf_available

    if is_ebpf_available():
        for event in trace_dlopen(duration_s=30):
            print(event)
    else:
        # fall back to procfs snapshot
        from selvo.analysis.runtime import scan_loaded_libraries
        lib_map = scan_loaded_libraries()
"""
from __future__ import annotations

import collections
import ctypes
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Iterator, Optional

from selvo.discovery.base import PackageRecord

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# BPF C programme (attached to the uretprobe on libc.so dlopen family)
# ---------------------------------------------------------------------------

# The programme fires on every return from dlopen/dlmopen in user-space.
# It reads the filename argument from the *entry* side via a stash map, then
# emits a perf event on return so we capture only successful opens (retval≠NULL).
_BPF_PROG = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct dlopen_event_t {
    u32  pid;
    u32  tgid;
    u32  uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_HASH(fname_stash, u64, char[256]);
BPF_PERF_OUTPUT(dlopen_events);

// Entry probe: stash the filename pointer argument before the call happens.
int probe_dlopen_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    const char *fname = (const char *)PT_REGS_PARM1(ctx);
    char buf[256] = {};
    bpf_probe_read_user_str(buf, sizeof(buf), fname);
    fname_stash.update(&id, &buf);
    return 0;
}

// Return probe: emit event only when dlopen succeeded (retval != NULL).
int probe_dlopen_return(struct pt_regs *ctx) {
    u64 retval = PT_REGS_RC(ctx);
    if (retval == 0)
        return 0;  // dlopen failed — skip

    u64 id = bpf_get_current_pid_tgid();
    char (*stashed)[256] = fname_stash.lookup(&id);
    if (!stashed)
        return 0;

    struct dlopen_event_t evt = {};
    evt.pid  = id & 0xFFFFFFFF;
    evt.tgid = id >> 32;
    evt.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    __builtin_memcpy(evt.filename, *stashed, sizeof(evt.filename));

    dlopen_events.perf_submit(ctx, &evt, sizeof(evt));
    fname_stash.delete(&id);
    return 0;
}
"""

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DlopenEvent:
    """A single dlopen() call captured by the eBPF tracer."""

    pid: int
    tgid: int               # thread-group ID (== PID for single-threaded processes)
    uid: int
    process_name: str       # comm name (first 15 chars)
    filename: str           # path passed to dlopen()
    timestamp: float = field(default_factory=time.time)
    # CVE correlation — populated when enrich_cve_pkgs are passed to the tracer
    package: str = ""        # resolved package name (if known)
    cve_ids: list[str] = field(default_factory=list)
    max_epss: float = 0.0
    max_cvss: float = 0.0
    in_cisa_kev: bool = False


# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------

def is_ebpf_available() -> bool:
    """Return *True* when eBPF tracing can be activated on this host.

    Checks:
    1. ``bcc`` Python bindings are importable.
    2. Running as root **or** has ``CAP_BPF`` (Linux capability 39).
    3. ``/sys/kernel/btf/vmlinux`` exists (BTF present — kernel ≥ 5.2).
    """
    # 1. bcc importable?
    try:
        import bcc  # noqa: F401  # type: ignore[import]
    except ImportError:
        log.debug("bcc not available — eBPF tracer disabled")
        return False

    # 2. Privilege check
    if os.geteuid() != 0:
        # Check for CAP_BPF via /proc/self/status
        try:
            with open("/proc/self/status") as _fh:
                caps_text = _fh.read()
            cap_eff = 0
            for line in caps_text.splitlines():
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split()[1], 16)
                    break
            # CAP_BPF = bit 39
            if not (cap_eff >> 39 & 1):
                log.debug("No CAP_BPF — eBPF tracer disabled")
                return False
        except OSError:
            log.debug("Cannot read /proc/self/status — eBPF tracer disabled")
            return False

    # 3. BTF present (optional but strongly recommended for CO-RE portability)
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        log.warning(
            "BTF not found at /sys/kernel/btf/vmlinux — eBPF may still work "
            "but portability is reduced (kernel headers required)"
        )

    return True


# ---------------------------------------------------------------------------
# /proc/self/maps read-once cache
# ---------------------------------------------------------------------------

_self_maps_cache: str | None = None


def _self_maps() -> str:
    """Read /proc/self/maps once and cache the result for the process lifetime."""
    global _self_maps_cache  # noqa: PLW0603
    if _self_maps_cache is None:
        try:
            _self_maps_cache = open("/proc/self/maps").read()
        except OSError:
            _self_maps_cache = ""
    return _self_maps_cache


# ---------------------------------------------------------------------------
# libc path discovery
# ---------------------------------------------------------------------------

def _find_libc() -> Optional[str]:
    """Return the path to libc.so loaded in the current process, if found."""
    for line in _self_maps().splitlines():
        parts = line.split()
        if len(parts) >= 6:
            path = parts[5]
            if "libc.so" in path or "libc-" in path:
                return path
    return None


def _find_libdl() -> Optional[str]:
    """Return the path to libdl.so loaded in the current process, if found.

    On glibc ≥ 2.34 dlopen is part of libc; on older glibc it's in libdl.
    """
    for line in _self_maps().splitlines():
        parts = line.split()
        if len(parts) >= 6:
            path = parts[5]
            if "libdl.so" in path or "libdl-" in path:
                return path
    # Fallback: glibc 2.34+ merged dlopen into libc
    return _find_libc()


# ---------------------------------------------------------------------------
# Main tracer
# ---------------------------------------------------------------------------

def trace_dlopen(
    *,
    duration_s: float = 10.0,
    pid_filter: Optional[int] = None,
    cve_packages: Optional[list[PackageRecord]] = None,
) -> Iterator[DlopenEvent]:
    """Attach eBPF probes and yield :class:`DlopenEvent` objects in real time.

    Parameters
    ----------
    duration_s:
        How long to trace (seconds). Pass ``float("inf")`` for indefinite.
    pid_filter:
        If set, only emit events from this PID.
    cve_packages:
        Optional list of CVE-enriched :class:`PackageRecord` objects. When
        provided, each emitted event is correlated against the list so that
        ``event.cve_ids``, ``event.max_epss``, ``event.in_cisa_kev``, and
        ``event.package`` are populated for vulnerable libraries.

    Yields
    ------
    :class:`DlopenEvent` for every successful ``dlopen()`` call observed.

    Raises
    ------
    RuntimeError
        If ``bcc`` is not importable or insufficient privileges.
    """
    if not is_ebpf_available():
        raise RuntimeError(
            "eBPF tracing not available: install bcc (python3-bpfcc) and run as root. "
            "Use selvo.analysis.runtime.enrich_runtime() for procfs-based scanning."
        )

    try:
        from bcc import BPF  # type: ignore[import]
    except ImportError as exc:
        raise RuntimeError("bcc not importable") from exc

    libdl_path = _find_libdl()
    if not libdl_path:
        raise RuntimeError("Could not locate libc/libdl in /proc/self/maps")

    log.info("Attaching eBPF uretprobe to %s (dlopen family) for %.0fs …", libdl_path, duration_s)

    bpf = BPF(text=_BPF_PROG)

    # Attach entry + return probes for the dlopen variants.
    # Each sym is wrapped individually so a missing symbol (e.g. dlmopen or
    # android_dlopen_ext not exported on this libc) doesn't block the others.
    attached: list[tuple[str, str]] = []  # track for explicit cleanup
    try:
        for sym in ("dlopen", "dlmopen", "android_dlopen_ext"):
            try:
                bpf.attach_uprobe(
                    name=libdl_path,
                    sym=sym,
                    fn_name="probe_dlopen_entry",
                )
                bpf.attach_uretprobe(
                    name=libdl_path,
                    sym=sym,
                    fn_name="probe_dlopen_return",
                )
                attached.append((libdl_path, sym))
                log.debug("Attached probes to %s:%s", libdl_path, sym)
            except Exception as exc:
                log.debug("Could not attach probe to %s:%s — %s", libdl_path, sym, exc)

        if not attached:
            raise RuntimeError(f"Could not attach any dlopen probes to {libdl_path}")

        # Hoist imports used inside the per-event callback so they are not
        # re-imported on every single BPF event (which fires at kernel speed).
        import re as _re
        import pathlib as _pl
        _so_re = _re.compile(r"(.+?)\.so")

        # Build a fast lookup: so-filename-stem → PackageRecord for CVE correlation.
        # E.g. "libssl" → PackageRecord(name="libssl3", cve_ids=[...])
        #
        # Many Debian binary packages carry a version digit suffix in their
        # *package* name (libssl3, libz1g) that does NOT appear in the .so
        # stem (libssl.so.3, libz.so.1).  Strip trailing digits so both
        # spellings map to the same record.
        _digit_strip = _re.compile(r"\d+$")
        _cve_index: dict[str, PackageRecord] = {}
        if cve_packages:
            for _pkg in cve_packages:
                if not _pkg.cve_ids:
                    continue
                _n = _pkg.name.lower()
                # 1. full name:           "libssl3"
                _cve_index[_n] = _pkg
                # 2. without lib prefix:  "ssl3"
                _cve_index[_n.removeprefix("lib")] = _pkg
                # 3. digit-stripped:      "libssl"  (matches stem from libssl.so.3)
                _ns = _digit_strip.sub("", _n)
                _cve_index[_ns] = _pkg
                # 4. digit-stripped + no lib prefix: "ssl"
                _cve_index[_ns.removeprefix("lib")] = _pkg

        # Event deque shared with the BPF callback (O(1) appendleft/pop)
        events: collections.deque[DlopenEvent] = collections.deque()

        class _RawEvt(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("tgid", ctypes.c_uint32),
                ("uid", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
                ("filename", ctypes.c_char * 256),
            ]

        def _handle(cpu, data, size):  # noqa: ANN001
            raw = ctypes.cast(data, ctypes.POINTER(_RawEvt)).contents
            fname = raw.filename.decode("utf-8", errors="replace").rstrip("\x00")
            if not fname:
                return
            evt = DlopenEvent(
                pid=raw.pid,
                tgid=raw.tgid,
                uid=raw.uid,
                process_name=raw.comm.decode("utf-8", errors="replace").rstrip("\x00"),
                filename=fname,
            )
            if pid_filter is None or raw.pid == pid_filter:
                # CVE correlation: match filename stem against indexed packages.
                # _re and _pl are imported once above the callback, not here.
                if _cve_index:
                    stem = _pl.Path(fname).name  # e.g. "libssl.so.3"
                    m = _so_re.match(stem)
                    if m:
                        key = m.group(1).lower()              # "libssl"
                        pkg = _cve_index.get(key) or _cve_index.get(key.removeprefix("lib"))
                        if pkg:
                            evt.package = pkg.name
                            evt.cve_ids = list(pkg.cve_ids)
                            evt.max_epss = pkg.max_epss
                            evt.max_cvss = pkg.max_cvss
                            evt.in_cisa_kev = pkg.in_cisa_kev
                events.append(evt)

        bpf["dlopen_events"].open_perf_buffer(_handle)

        deadline = time.monotonic() + duration_s
        try:
            while time.monotonic() < deadline:
                bpf.perf_buffer_poll(timeout=200)
                while events:
                    yield events.popleft()
        finally:
            log.info("eBPF dlopen tracer detached")
    except GeneratorExit:
        pass  # caller closed the iterator cleanly


# ---------------------------------------------------------------------------
# Convenience: collect for N seconds and return list
# ---------------------------------------------------------------------------

def collect_dlopen_events(
    duration_s: float = 5.0,
    pid_filter: Optional[int] = None,
    cve_packages: Optional[list[PackageRecord]] = None,
) -> list[DlopenEvent]:
    """Trace dlopen calls for *duration_s* seconds and return all events.

    Parameters
    ----------
    duration_s:
        How long to trace.
    pid_filter:
        Restrict to a single PID if set.
    cve_packages:
        CVE-enriched package records for correlation (forwarded to
        :func:`trace_dlopen`).  When provided, each returned event has
        ``cve_ids``, ``max_epss``, ``max_cvss``, and ``in_cisa_kev`` filled.

    Returns an empty list (not an error) when eBPF is unavailable.
    """
    if not is_ebpf_available():
        log.info("eBPF unavailable — returning empty event list (use procfs runtime scan)")
        return []
    return list(trace_dlopen(duration_s=duration_s, pid_filter=pid_filter, cve_packages=cve_packages))
