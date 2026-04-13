"""Local system context detection and installed-version reading.

selvo has two version-data modes:

*reference* (default / CI)
    Pulls version data from Debian's ``Packages.gz`` and Repology.
    Represents what Debian stable / upstream currently ships.
    Useful for: CI, cross-distro audits, GitHub Pages publishing.

*local*
    Reads actually-installed package versions from the system package
    manager (``dpkg``, ``rpm``, ``pacman``, ``apk``).
    Useful for: auditing the specific machine selvo is running on.

:func:`detect_system_context` returns a :class:`SystemContext` describing the
current environment regardless of mode.  :func:`read_local_versions` attempts
to harvest installed versions from the package manager.
"""
from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

log = logging.getLogger(__name__)


@dataclass
class SystemContext:
    """Metadata about the environment that produced the report.

    Serialised into ``data.json`` and rendered in the HTML report so
    consumers know whether they're looking at "Debian stable reference"
    or "this machine on 2026-03-07".
    """

    mode: str                           # "reference" | "local"
    generated_at: str                   # ISO 8601 UTC timestamp
    os_name: str = ""                   # e.g. "Ubuntu", "Debian GNU/Linux"
    os_version: str = ""                # e.g. "24.04", "13 (trixie)"
    os_codename: str = ""               # e.g. "noble", "trixie"
    kernel: str = ""                    # uname -r
    arch: str = ""                      # x86_64, aarch64, …
    hostname: str = ""                  # redacted in CI (empty if not local)
    package_manager: str = ""           # dpkg | rpm | pacman | apk | unknown
    # Reference-mode metadata
    reference_distro: str = "debian"    # which distro's Packages.gz was used
    reference_branch: str = "stable"    # e.g. "stable", "bookworm"

    def as_dict(self) -> dict:
        return asdict(self)


def _run(cmd: list[str]) -> str:
    """Run a subprocess and return stdout, or '' on any error."""
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""


def detect_system_context(mode: str = "reference") -> SystemContext:
    """Return a :class:`SystemContext` describing the current environment.

    Always gathers OS metadata (cheap, purely local).  ``hostname`` is only
    included when *mode* is ``"local"`` to avoid leaking machine identity
    from CI-generated public reports.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ctx = SystemContext(mode=mode, generated_at=now)

    # ── OS info ──────────────────────────────────────────────────────────
    # Try /etc/os-release first (works on all systemd distros)
    if os.path.exists("/etc/os-release"):
        kv: dict[str, str] = {}
        for line in open("/etc/os-release").readlines():
            line = line.strip()
            if "=" in line:
                k, _, v = line.partition("=")
                kv[k] = v.strip('"')
        ctx.os_name = kv.get("NAME", "")
        ctx.os_version = kv.get("VERSION_ID", "")
        ctx.os_codename = kv.get("VERSION_CODENAME", "")
    else:
        ctx.os_name = platform.system()
        ctx.os_version = platform.version()

    ctx.kernel = platform.release()
    ctx.arch = platform.machine()

    if mode == "local":
        ctx.hostname = platform.node()

    # ── Package manager detection ────────────────────────────────────────
    for pm in ("dpkg", "rpm", "pacman", "apk"):
        if shutil.which(pm):
            ctx.package_manager = pm
            break
    else:
        ctx.package_manager = "unknown"

    return ctx


# ---------------------------------------------------------------------------
# Local version harvesting
# ---------------------------------------------------------------------------

def _harvest_dpkg() -> dict[str, str]:
    """Return {pkg_name: installed_version} from dpkg-query."""
    out = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    result: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[1]:
            result[parts[0].strip()] = parts[1].strip()
    return result


def _harvest_rpm() -> dict[str, str]:
    """Return {pkg_name: version-release} from rpm."""
    out = _run(["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
    result: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2:
            result[parts[0].strip()] = parts[1].strip()
    return result


def _harvest_pacman() -> dict[str, str]:
    """Return {pkg_name: version} from pacman -Q."""
    out = _run(["pacman", "-Q"])
    result: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            result[parts[0]] = parts[1]
    return result


def _harvest_apk() -> dict[str, str]:
    """Return {pkg_name: version} from apk info -v."""
    out = _run(["apk", "info", "-v"])
    result: dict[str, str] = {}
    for line in out.splitlines():
        # e.g. "musl-1.2.4-r2"
        m = re.match(r"^(.+?)-(\d[^-]*.*)$", line.strip())
        if m:
            result[m.group(1)] = m.group(2)
    return result


_HARVESTERS = {
    "dpkg": _harvest_dpkg,
    "rpm": _harvest_rpm,
    "pacman": _harvest_pacman,
    "apk": _harvest_apk,
}


def read_local_versions(ctx: SystemContext) -> dict[str, str]:
    """Return {pkg_name: installed_version} from the local package manager.

    Returns an empty dict when the package manager is unavailable or the
    query fails so callers can fall back gracefully.
    """
    harvester = _HARVESTERS.get(ctx.package_manager)
    if not harvester:
        log.debug("No supported package manager found; local versions unavailable.")
        return {}
    try:
        versions = harvester()
        log.info(
            "Local context: read %d installed package versions via %s",
            len(versions),
            ctx.package_manager,
        )
        return versions
    except Exception as exc:
        log.warning("Failed to read local installed versions: %s", exc)
        return {}
