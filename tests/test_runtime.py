"""Tests for selvo.analysis.runtime — procfs-based runtime reachability."""
from __future__ import annotations

import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from selvo.analysis.runtime import (
    _extract_so_paths,
    _heuristic_map,
    _rpm_map,
    _pacman_map,
    _apk_map,
    enrich_runtime,
    map_sos_to_packages,
    scan_loaded_libraries,
    standalone_scan,
)
from tests.conftest import make_pkg


# ---------------------------------------------------------------------------
# _extract_so_paths
# ---------------------------------------------------------------------------

SAMPLE_MAPS = textwrap.dedent("""\
    7f1234000000-7f1235000000 r--p 00000000 08:01 123456    /usr/lib/x86_64-linux-gnu/libssl.so.3
    7f1235000000-7f1236000000 r-xp 00080000 08:01 123456    /usr/lib/x86_64-linux-gnu/libssl.so.3
    7f1236000000-7f1237000000 r--p 00180000 08:01 654321    /usr/lib/x86_64-linux-gnu/libcrypto.so.3
    7fff00000000-7fff00001000 r-xp 00000000 00:00 0         [vdso]
    7f1238000000-7f1239000000 rw-p 00000000 00:00 0         [anon]
    7f123a000000-7f123b000000 r--p 00000000 08:01 111111    /usr/lib/x86_64-linux-gnu/libz.so.1.2.11
""")


def test_extract_so_paths_finds_libs():
    paths = _extract_so_paths(SAMPLE_MAPS)
    assert "/usr/lib/x86_64-linux-gnu/libssl.so.3" in paths
    assert "/usr/lib/x86_64-linux-gnu/libcrypto.so.3" in paths
    assert "/usr/lib/x86_64-linux-gnu/libz.so.1.2.11" in paths


def test_extract_so_paths_excludes_anonymous():
    paths = _extract_so_paths(SAMPLE_MAPS)
    # anonymous and vdso mappings must not appear
    for p in paths:
        assert p.startswith("/")
        assert "[" not in p


def test_extract_so_paths_deduplicates():
    # libssl.so.3 appears twice in SAMPLE_MAPS (two mappings of same file)
    paths = _extract_so_paths(SAMPLE_MAPS)
    assert len([p for p in paths if "libssl.so.3" in p]) == 1


def test_extract_so_paths_empty():
    assert _extract_so_paths("") == set()
    assert _extract_so_paths("7fff00 r--p 0 00:00 0 [stack]") == set()


# ---------------------------------------------------------------------------
# _heuristic_map
# ---------------------------------------------------------------------------

def test_heuristic_map_derives_pkg_name():
    paths = ["/usr/lib/x86_64-linux-gnu/libssl.so.3"]
    result = _heuristic_map(paths, existing={})
    assert result[paths[0]] == "libssl3"


def test_heuristic_map_no_version_suffix():
    paths = ["/usr/lib/libfoo.so"]
    result = _heuristic_map(paths, existing={})
    assert result[paths[0]] == "libfoo"


def test_heuristic_map_skips_already_resolved():
    paths = ["/usr/lib/x86_64-linux-gnu/libssl.so.3"]
    result = _heuristic_map(paths, existing={paths[0]: "libssl3"})
    # Should not add a duplicate or override
    assert paths[0] not in result


# ---------------------------------------------------------------------------
# map_sos_to_packages (with mocked dpkg)
# ---------------------------------------------------------------------------

def _fake_dpkg_run(args, **kwargs):
    """Fake subprocess.run for dpkg -S."""
    proc = MagicMock()
    proc.stdout = "libssl3: /usr/lib/x86_64-linux-gnu/libssl.so.3\n"
    return proc


def test_map_sos_to_packages_uses_dpkg(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/dpkg")
    monkeypatch.setattr(subprocess, "run", _fake_dpkg_run)

    result = map_sos_to_packages(["/usr/lib/x86_64-linux-gnu/libssl.so.3"])
    assert result.get("/usr/lib/x86_64-linux-gnu/libssl.so.3") == "libssl3"


def test_map_sos_to_packages_falls_back_to_heuristic(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _: None)  # no dpkg, no rpm

    result = map_sos_to_packages(["/usr/lib/x86_64-linux-gnu/libz.so.1"])
    assert result.get("/usr/lib/x86_64-linux-gnu/libz.so.1") == "libz1"


# ---------------------------------------------------------------------------
# enrich_runtime
# ---------------------------------------------------------------------------

def _fake_scan_loaded():
    """A synthetic /proc scan result with two processes loading libssl.so.3."""
    return {
        "/usr/lib/x86_64-linux-gnu/libssl.so.3": [
            (1234, "nginx", "nginx: master process"),
            (5678, "apache2", "apache2 -D FOREGROUND"),
        ],
        "/usr/lib/x86_64-linux-gnu/libz.so.1": [
            (9999, "sshd", "sshd: /usr/sbin/sshd"),
        ],
    }


def _fake_map_sos(so_paths):
    mapping = {
        "/usr/lib/x86_64-linux-gnu/libssl.so.3": "libssl3",
        "/usr/lib/x86_64-linux-gnu/libz.so.1": "zlib1g",
    }
    return {p: mapping[p] for p in so_paths if p in mapping}


def test_enrich_runtime_marks_loaded(monkeypatch):
    monkeypatch.setattr("selvo.analysis.runtime.scan_loaded_libraries", _fake_scan_loaded)
    monkeypatch.setattr("selvo.analysis.runtime.map_sos_to_packages", _fake_map_sos)

    ssl_pkg = make_pkg(name="libssl3", cve_ids=["CVE-2024-0001"], max_epss=0.8, max_cvss=9.1)
    zlib_pkg = make_pkg(name="zlib1g", cve_ids=["CVE-2023-9999"], max_epss=0.1, max_cvss=5.0)
    bash_pkg = make_pkg(name="bash", cve_ids=[])

    packages, hits = enrich_runtime([ssl_pkg, zlib_pkg, bash_pkg])

    # libssl3 is loaded in two processes
    assert ssl_pkg.runtime_loaded is True
    assert set(ssl_pkg.runtime_pids) == {1234, 5678}
    assert set(ssl_pkg.runtime_procs) == {"nginx", "apache2"}

    # zlib1g is loaded in one process
    assert zlib_pkg.runtime_loaded is True
    assert zlib_pkg.runtime_pids == [9999]

    # bash is not loaded via .so
    assert bash_pkg.runtime_loaded is False


def test_enrich_runtime_generates_hits(monkeypatch):
    monkeypatch.setattr("selvo.analysis.runtime.scan_loaded_libraries", _fake_scan_loaded)
    monkeypatch.setattr("selvo.analysis.runtime.map_sos_to_packages", _fake_map_sos)

    ssl_pkg = make_pkg(name="libssl3", cve_ids=["CVE-2024-0001"], max_epss=0.8, max_cvss=9.1)
    _, hits = enrich_runtime([ssl_pkg])

    assert len(hits) == 2  # one per PID
    pids = {h.pid for h in hits}
    assert pids == {1234, 5678}
    for h in hits:
        assert h.package == "libssl3"
        assert "CVE-2024-0001" in h.cve_ids
        assert h.max_epss == pytest.approx(0.8)


def test_enrich_runtime_cve_only_filter(monkeypatch):
    """With cve_only=True (default), packages without CVEs produce no hits."""
    monkeypatch.setattr("selvo.analysis.runtime.scan_loaded_libraries", _fake_scan_loaded)
    monkeypatch.setattr("selvo.analysis.runtime.map_sos_to_packages", _fake_map_sos)

    clean_ssl = make_pkg(name="libssl3", cve_ids=[])  # no CVEs
    _, hits = enrich_runtime([clean_ssl], cve_only=True)
    assert hits == []


def test_enrich_runtime_all_libs_flag(monkeypatch):
    """With cve_only=False, loaded packages without CVEs still generate hits."""
    monkeypatch.setattr("selvo.analysis.runtime.scan_loaded_libraries", _fake_scan_loaded)
    monkeypatch.setattr("selvo.analysis.runtime.map_sos_to_packages", _fake_map_sos)

    clean_ssl = make_pkg(name="libssl3", cve_ids=[])
    _, hits = enrich_runtime([clean_ssl], cve_only=False)
    assert len(hits) > 0


def test_enrich_runtime_hits_sorted_by_epss(monkeypatch):
    """Hits are sorted highest-risk first."""
    monkeypatch.setattr("selvo.analysis.runtime.scan_loaded_libraries", _fake_scan_loaded)
    monkeypatch.setattr("selvo.analysis.runtime.map_sos_to_packages", _fake_map_sos)

    ssl_pkg = make_pkg(name="libssl3", cve_ids=["CVE-A"], max_epss=0.9, in_cisa_kev=True)
    zlib_pkg = make_pkg(name="zlib1g", cve_ids=["CVE-B"], max_epss=0.2)

    _, hits = enrich_runtime([ssl_pkg, zlib_pkg])
    # KEV + higher EPSS should sort first
    assert hits[0].package == "libssl3"


def test_enrich_runtime_empty_proc(monkeypatch):
    """Gracefully handles an empty /proc scan."""
    monkeypatch.setattr("selvo.analysis.runtime.scan_loaded_libraries", lambda: {})

    pkg = make_pkg(name="libssl3", cve_ids=["CVE-2024-0001"])
    packages, hits = enrich_runtime([pkg])
    assert hits == []
    assert pkg.runtime_loaded is False


# ---------------------------------------------------------------------------
# scan_loaded_libraries — smoke test against real /proc (skipped if no /proc)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not Path("/proc/self/maps").exists(), reason="/proc not available")
def test_scan_loaded_libraries_smoke():
    """Real procfs smoke-test: at minimum we can read our own process maps."""
    lib_map = scan_loaded_libraries()
    # There should be at least one .so loaded in the current Python process
    assert len(lib_map) > 0
    # All keys must be absolute paths containing ".so"
    for path in lib_map:
        assert path.startswith("/")
        assert ".so" in path


# ---------------------------------------------------------------------------
# _rpm_map
# ---------------------------------------------------------------------------

def _fake_rpm_run(args, **kwargs):
    proc = MagicMock()
    if "/usr/lib/x86_64-linux-gnu/libssl.so.3" in args:
        proc.stdout = "openssl-libs"
    else:
        proc.stdout = ""
    return proc


def test_rpm_map_resolves_path(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/rpm")
    monkeypatch.setattr(subprocess, "run", _fake_rpm_run)

    result = _rpm_map(["/usr/lib/x86_64-linux-gnu/libssl.so.3"])
    assert result.get("/usr/lib/x86_64-linux-gnu/libssl.so.3") == "openssl-libs"


def test_rpm_map_skips_when_unavailable(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _: None)
    result = _rpm_map(["/usr/lib/libssl.so.3"])
    assert result == {}


# ---------------------------------------------------------------------------
# _pacman_map
# ---------------------------------------------------------------------------

def _fake_pacman_run(args, **kwargs):
    proc = MagicMock()
    proc.stdout = "/usr/lib/libssl.so.3 is owned by openssl 3.3.2-1"
    return proc


def test_pacman_map_resolves_path(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/pacman")
    monkeypatch.setattr(subprocess, "run", _fake_pacman_run)

    result = _pacman_map(["/usr/lib/libssl.so.3"])
    assert result.get("/usr/lib/libssl.so.3") == "openssl"


# ---------------------------------------------------------------------------
# _apk_map
# ---------------------------------------------------------------------------

def _fake_apk_run(args, **kwargs):
    proc = MagicMock()
    proc.stdout = "/usr/lib/libssl.so.3 is owned by libssl3-3.4.0-r0"
    return proc


def test_apk_map_resolves_path(monkeypatch):
    import shutil
    import subprocess
    monkeypatch.setattr(shutil, "which", lambda _: "/sbin/apk")
    monkeypatch.setattr(subprocess, "run", _fake_apk_run)

    result = _apk_map(["/usr/lib/libssl.so.3"])
    assert result.get("/usr/lib/libssl.so.3") == "libssl3"


# ---------------------------------------------------------------------------
# map_sos_to_packages: tiered resolution — only unresolved paths hit rpm
# ---------------------------------------------------------------------------

def test_map_sos_only_runs_rpm_on_unresolved(monkeypatch):
    """rpm must not run on paths already resolved by dpkg."""
    import shutil
    import subprocess

    ssl_path = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
    other_path = "/opt/custom/libfoo.so.1"

    def _fake_dpkg(args, **kwargs):
        proc = MagicMock()
        proc.stdout = f"libssl3: {ssl_path}\n"
        return proc

    rpm_calls: list[list[str]] = []

    def _fake_rpm(args, **kwargs):
        rpm_calls.append(args)
        proc = MagicMock()
        proc.stdout = "custom-lib"
        return proc

    monkeypatch.setattr(shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
    monkeypatch.setattr(subprocess, "run", lambda args, **kw: _fake_dpkg(args, **kw) if "dpkg" in args[0] else _fake_rpm(args, **kw))

    result = map_sos_to_packages([ssl_path, other_path])

    assert result[ssl_path] == "libssl3"
    # rpm must have been called only with the unresolved path
    for call in rpm_calls:
        assert ssl_path not in call, "dpkg-resolved path must not be passed to rpm"


# ---------------------------------------------------------------------------
# standalone_scan
# ---------------------------------------------------------------------------

def test_standalone_scan_returns_lib_map_and_pkg_map(monkeypatch):
    fake_lib_map = {
        "/usr/lib/x86_64-linux-gnu/libssl.so.3": [(1234, "nginx", "nginx")],
    }
    fake_pkg_map = {"/usr/lib/x86_64-linux-gnu/libssl.so.3": "libssl3"}

    monkeypatch.setattr("selvo.analysis.runtime.scan_loaded_libraries", lambda: fake_lib_map)
    monkeypatch.setattr("selvo.analysis.runtime.map_sos_to_packages", lambda paths: fake_pkg_map)

    lib_map, so_to_pkg = standalone_scan()
    assert lib_map is fake_lib_map
    assert so_to_pkg is fake_pkg_map


# ---------------------------------------------------------------------------
# Source-package name matching via deb_idx (the primary correctness regression)
# ---------------------------------------------------------------------------

def _make_deb_idx(s2b: dict) -> object:
    """Create a minimal DebianIndex-like stub with just the s2b attribute."""
    return SimpleNamespace(s2b=s2b)


def test_enrich_runtime_source_pkg_via_deb_idx(monkeypatch):
    """Source package 'openssl' must match 'libssl3' loaded in memory via deb_idx.s2b."""
    lib_map = {
        "/usr/lib/x86_64-linux-gnu/libssl.so.3": [(1234, "nginx", "nginx")],
    }
    so_to_pkg = {"/usr/lib/x86_64-linux-gnu/libssl.so.3": "libssl3"}

    monkeypatch.setattr("selvo.analysis.runtime.scan_loaded_libraries", lambda: lib_map)
    monkeypatch.setattr("selvo.analysis.runtime.map_sos_to_packages", lambda p: so_to_pkg)

    # selvo names the record after the SOURCE package ("openssl"), not the binary ("libssl3")
    openssl_pkg = make_pkg(name="openssl", cve_ids=["CVE-2024-0001"], max_epss=0.8)
    deb_idx = _make_deb_idx({"openssl": ["libssl3", "libcrypto3"]})

    packages, hits = enrich_runtime([openssl_pkg], deb_idx=deb_idx)

    assert openssl_pkg.runtime_loaded is True, (
        "Source package 'openssl' should be matched via deb_idx.s2b to binary 'libssl3'"
    )
    assert len(hits) == 1
    assert hits[0].package == "openssl"


def test_enrich_runtime_without_deb_idx_misses_source_pkg(monkeypatch):
    """Without deb_idx, 'openssl' correctly fails to match 'libssl3' (known limitation)."""
    lib_map = {
        "/usr/lib/x86_64-linux-gnu/libssl.so.3": [(1234, "nginx", "nginx")],
    }
    so_to_pkg = {"/usr/lib/x86_64-linux-gnu/libssl.so.3": "libssl3"}

    monkeypatch.setattr("selvo.analysis.runtime.scan_loaded_libraries", lambda: lib_map)
    monkeypatch.setattr("selvo.analysis.runtime.map_sos_to_packages", lambda p: so_to_pkg)

    openssl_pkg = make_pkg(name="openssl", cve_ids=["CVE-2024-0001"])
    packages, hits = enrich_runtime([openssl_pkg])  # no deb_idx

    # Without deb_idx there is no match (openssl ≠ libssl3 by name alone)
    assert openssl_pkg.runtime_loaded is False
    assert hits == []


# ---------------------------------------------------------------------------
# so_paths plural field
# ---------------------------------------------------------------------------

def test_runtime_hit_has_so_paths_list(monkeypatch):
    """Each RuntimeHit must carry the full list of matched .so paths."""
    lib_map = {
        "/usr/lib/libssl.so.3": [(1, "nginx", "nginx")],
        "/usr/lib/libcrypto.so.3": [(1, "nginx", "nginx")],
    }
    so_to_pkg = {
        "/usr/lib/libssl.so.3": "libssl3",
        "/usr/lib/libcrypto.so.3": "libssl3",
    }
    monkeypatch.setattr("selvo.analysis.runtime.scan_loaded_libraries", lambda: lib_map)
    monkeypatch.setattr("selvo.analysis.runtime.map_sos_to_packages", lambda p: so_to_pkg)

    pkg = make_pkg(name="libssl3", cve_ids=["CVE-2024-0001"])
    _, hits = enrich_runtime([pkg])

    assert len(hits) == 1
    assert len(hits[0].so_paths) >= 1
    assert hits[0].so_path == hits[0].so_paths[0]


# ---------------------------------------------------------------------------
# Runtime scoring boost (scorer integration)
# ---------------------------------------------------------------------------

def test_runtime_loaded_boost_applied():
    from selvo.prioritizer.scorer import score_and_rank, _RUNTIME_LOADED_BOOST

    loaded_pkg = make_pkg(
        name="libssl3", cve_ids=["CVE-A"],
        max_epss=0.5, max_cvss=8.0, transitive_rdep_count=1000,
        runtime_loaded=True,
    )
    not_loaded_pkg = make_pkg(
        name="libcurl4", cve_ids=["CVE-B"],
        max_epss=0.5, max_cvss=8.0, transitive_rdep_count=1000,
        runtime_loaded=False,
    )

    ranked = score_and_rank([loaded_pkg, not_loaded_pkg])
    # libssl3 (runtime-loaded) must outscore libcurl4 (not loaded) with identical base signal
    assert ranked[0].name == "libssl3"
    assert ranked[0].score == pytest.approx(ranked[1].score * _RUNTIME_LOADED_BOOST, rel=1e-2)

