"""Tests for selvo.analysis.ebpf_tracer.

Because bcc requires root + a real kernel, every test here works without it:
- is_ebpf_available() false-path and graceful degradation
- collect_dlopen_events() returns [] when eBPF is unavailable
- _cve_index construction and stem-matching logic (extracted to pure helpers)
- _find_libc / _find_libdl via mocked /proc/self/maps cache
- DlopenEvent dataclass defaults
"""
from __future__ import annotations

import re
import pathlib
from unittest.mock import MagicMock

import pytest

import selvo.analysis.ebpf_tracer as tracer_mod
from selvo.analysis.ebpf_tracer import (
    DlopenEvent,
    _find_libc,
    _find_libdl,
    collect_dlopen_events,
    is_ebpf_available,
    trace_dlopen,
)
from tests.conftest import make_pkg


# ---------------------------------------------------------------------------
# Helpers — the CVE index + stem-match logic lives inside trace_dlopen, but
# we can test it in isolation by replicating the exact expressions used there.
# ---------------------------------------------------------------------------

_SO_RE = re.compile(r"(.+?)\.so")


_DIGIT_STRIP = re.compile(r"\d+$")


def _build_cve_index(packages):
    """Mirror of the _cve_index construction inside trace_dlopen."""
    idx = {}
    for pkg in packages:
        if not pkg.cve_ids:
            continue
        n = pkg.name.lower()
        idx[n] = pkg                              # "libssl3"
        idx[n.removeprefix("lib")] = pkg          # "ssl3"
        ns = _DIGIT_STRIP.sub("", n)
        idx[ns] = pkg                             # "libssl"
        idx[ns.removeprefix("lib")] = pkg         # "ssl"
    return idx


def _correlate(fname: str, cve_index: dict):
    """Mirror of the callback's stem-match logic."""
    stem = pathlib.Path(fname).name
    m = _SO_RE.match(stem)
    if not m:
        return None
    key = m.group(1).lower()
    return cve_index.get(key) or cve_index.get(key.removeprefix("lib"))


# ---------------------------------------------------------------------------
# DlopenEvent defaults
# ---------------------------------------------------------------------------

def test_dlopen_event_defaults():
    evt = DlopenEvent(pid=1, tgid=1, uid=0, process_name="nginx", filename="/lib/libssl.so.3")
    assert evt.package == ""
    assert evt.cve_ids == []
    assert evt.max_epss == 0.0
    assert evt.max_cvss == 0.0
    assert evt.in_cisa_kev is False
    assert evt.timestamp > 0.0


# ---------------------------------------------------------------------------
# is_ebpf_available: no bcc → False
# ---------------------------------------------------------------------------

def test_is_ebpf_available_no_bcc(monkeypatch):
    """When bcc is not importable, is_ebpf_available() must return False."""
    import builtins
    real_import = builtins.__import__

    def _block_bcc(name, *args, **kwargs):
        if name == "bcc":
            raise ImportError("no bcc")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _block_bcc)
    assert is_ebpf_available() is False


def test_is_ebpf_available_non_root_no_cap(monkeypatch):
    """Non-root without CAP_BPF must return False (reads /proc/self/status)."""
    import builtins
    real_import = builtins.__import__

    def _allow_bcc(name, *args, **kwargs):
        if name == "bcc":
            return MagicMock()
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _allow_bcc)
    monkeypatch.setattr("os.geteuid", lambda: 1000)

    # Simulate CapEff = 0 (no capabilities)
    fake_status = "Name:\tpython3\nCapEff:\t0000000000000000\n"
    monkeypatch.setattr("builtins.open", lambda path, *a, **kw: __import__("io").StringIO(fake_status)
                        if "status" in str(path) else __import__("builtins").__dict__["open"](path, *a, **kw))

    result = is_ebpf_available()
    assert result is False


# ---------------------------------------------------------------------------
# collect_dlopen_events: gracefully returns [] when eBPF unavailable
# ---------------------------------------------------------------------------

def test_collect_dlopen_events_no_ebpf(monkeypatch):
    """collect_dlopen_events must return [] (not raise) when eBPF is unavailable."""
    monkeypatch.setattr(tracer_mod, "is_ebpf_available", lambda: False)
    result = collect_dlopen_events(duration_s=0.1)
    assert result == []


def test_collect_dlopen_events_passes_cve_packages(monkeypatch):
    """cve_packages kwarg must be threaded through to trace_dlopen."""
    monkeypatch.setattr(tracer_mod, "is_ebpf_available", lambda: True)
    captured = {}

    def _fake_trace(*, duration_s, pid_filter, cve_packages):
        captured["cve_packages"] = cve_packages
        return iter([])

    monkeypatch.setattr(tracer_mod, "trace_dlopen", _fake_trace)
    pkg = make_pkg(name="libssl3", cve_ids=["CVE-X"])
    collect_dlopen_events(duration_s=0.1, cve_packages=[pkg])
    assert captured["cve_packages"] == [pkg]


# ---------------------------------------------------------------------------
# trace_dlopen: raises RuntimeError when eBPF unavailable
# ---------------------------------------------------------------------------

def test_trace_dlopen_raises_when_no_ebpf(monkeypatch):
    monkeypatch.setattr(tracer_mod, "is_ebpf_available", lambda: False)
    with pytest.raises(RuntimeError, match="eBPF tracing not available"):
        list(trace_dlopen(duration_s=0.1))


# ---------------------------------------------------------------------------
# CVE index construction
# ---------------------------------------------------------------------------

def test_cve_index_indexes_by_name():
    pkg = make_pkg(name="libssl3", cve_ids=["CVE-2024-001"], max_epss=0.7)
    idx = _build_cve_index([pkg])
    assert "libssl3" in idx
    assert idx["libssl3"] is pkg


def test_cve_index_indexes_by_stripped_name():
    """'libssl3' → also indexed as 'ssl3' for stem-match against libssl.so.3."""
    pkg = make_pkg(name="libssl3", cve_ids=["CVE-2024-001"])
    idx = _build_cve_index([pkg])
    assert "ssl3" in idx


def test_cve_index_excludes_packages_without_cves():
    clean = make_pkg(name="libfoo2", cve_ids=[])
    idx = _build_cve_index([clean])
    assert "libfoo2" not in idx
    assert "foo2" not in idx


# ---------------------------------------------------------------------------
# CVE correlation stem-match logic
# ---------------------------------------------------------------------------

def test_correlate_matches_libssl_stem():
    pkg = make_pkg(name="libssl3", cve_ids=["CVE-A"])
    idx = _build_cve_index([pkg])
    hit = _correlate("/usr/lib/x86_64-linux-gnu/libssl.so.3", idx)
    assert hit is pkg


def test_correlate_matches_openssl_package_via_no_lib_prefix():
    """openssl (source pkg) indexed as 'openssl' → matches libssl stem? No —
    this tests the negative: 'openssl' doesn't match stem 'libssl' without deb_idx.
    The fix (deb_idx expansion) lives in runtime.py, not here."""
    pkg = make_pkg(name="openssl", cve_ids=["CVE-B"])
    idx = _build_cve_index([pkg])
    # stem key would be "libssl"; openssl indexes as "openssl" / "openssl"
    # (removeprefix("lib") on "openssl" is a no-op — no match without deb_idx)
    hit = _correlate("/usr/lib/libssl.so.3", idx)
    assert hit is None


def test_correlate_returns_none_for_non_so_file():
    idx = {"somepkg": make_pkg(name="somepkg", cve_ids=["CVE-C"])}
    hit = _correlate("/usr/bin/python3", idx)
    assert hit is None


def test_correlate_returns_none_for_empty_index():
    hit = _correlate("/usr/lib/libssl.so.3", {})
    assert hit is None


def test_correlate_populates_event_fields():
    """Mimic the full callback path: correlate + field assignment."""
    pkg = make_pkg(name="libssl3", cve_ids=["CVE-2024-ZZZ"], max_epss=0.91, max_cvss=9.8, in_cisa_kev=True)
    idx = _build_cve_index([pkg])
    evt = DlopenEvent(pid=5, tgid=5, uid=0, process_name="nginx", filename="/lib/libssl.so.3")
    matched = _correlate(evt.filename, idx)
    assert matched is not None
    evt.package = matched.name
    evt.cve_ids = list(matched.cve_ids)
    evt.max_epss = matched.max_epss
    evt.max_cvss = matched.max_cvss
    evt.in_cisa_kev = matched.in_cisa_kev
    assert evt.package == "libssl3"
    assert "CVE-2024-ZZZ" in evt.cve_ids
    assert evt.max_epss == pytest.approx(0.91)
    assert evt.max_cvss == pytest.approx(9.8)
    assert evt.in_cisa_kev is True


# ---------------------------------------------------------------------------
# _find_libc / _find_libdl via mocked maps cache
# ---------------------------------------------------------------------------

_FAKE_MAPS = """\
7f1234000000-7f1235000000 r--p 0 08:01 1 /usr/lib/x86_64-linux-gnu/libc.so.6
7f1235000000-7f1236000000 r--p 0 08:01 2 /usr/lib/x86_64-linux-gnu/libdl.so.2
7f1237000000-7f1238000000 r--p 0 08:01 3 /usr/lib/x86_64-linux-gnu/libssl.so.3
"""


def test_find_libc_parses_maps(monkeypatch):
    monkeypatch.setattr(tracer_mod, "_self_maps_cache", _FAKE_MAPS)
    path = _find_libc()
    assert path == "/usr/lib/x86_64-linux-gnu/libc.so.6"


def test_find_libdl_parses_maps(monkeypatch):
    monkeypatch.setattr(tracer_mod, "_self_maps_cache", _FAKE_MAPS)
    path = _find_libdl()
    assert path == "/usr/lib/x86_64-linux-gnu/libdl.so.2"


def test_find_libdl_falls_back_to_libc_when_absent(monkeypatch):
    """glibc ≥ 2.34 merged dlopen into libc; libdl absent is expected."""
    maps_no_libdl = """\
7f1234000000-7f1235000000 r--p 0 08:01 1 /usr/lib/x86_64-linux-gnu/libc.so.6
"""
    monkeypatch.setattr(tracer_mod, "_self_maps_cache", maps_no_libdl)
    path = _find_libdl()
    # Falls back to libc
    assert path == "/usr/lib/x86_64-linux-gnu/libc.so.6"


def test_find_libc_returns_none_when_absent(monkeypatch):
    monkeypatch.setattr(tracer_mod, "_self_maps_cache", "")
    assert _find_libc() is None


# ---------------------------------------------------------------------------
# android_dlopen_ext: confirms it's in the probe set (doc/code agreement)
# ---------------------------------------------------------------------------

def test_android_dlopen_ext_in_probe_symbols():
    """The attach loop must include android_dlopen_ext (bionic compat)."""
    import inspect
    src = inspect.getsource(trace_dlopen)
    assert "android_dlopen_ext" in src, (
        "android_dlopen_ext must be in the probe symbol list inside trace_dlopen()"
    )


def test_security_file_open_not_in_source():
    """security_file_open was promised but not implemented — it must not appear
    anywhere in the tracer source to avoid misleading documentation."""
    import inspect
    src = inspect.getsource(tracer_mod)
    assert "security_file_open" not in src, (
        "security_file_open was scrubbed from the tracer — it must not reappear"
    )
