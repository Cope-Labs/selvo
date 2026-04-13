"""Fleet scanning — collect installed package versions from multiple machines.

Supports three collection methods:
  1. SSH (default) — `ssh <host> dpkg -q` / `rpm -qa` / etc.
  2. Local file   — pre-collected dpkg/rpm output dumped to a file
  3. Inline dict  — {hostname: {pkg: version}} already in memory

Fleet spec format (YAML or JSON):
  machines:
    - host: webserver-01
      user: ubuntu          # optional, default = current user
      method: ssh           # optional, default = ssh
      pm: dpkg              # optional, auto-detected
    - host: localhost
      method: local         # reads local package manager directly
    - host: db-02
      file: /tmp/db02-pkgs.txt  # pre-dumped dpkg -l output

Output — a FleetResult with per-machine inventories and an aggregated
risk summary identical in structure to selvo's normal package scoring.
"""
from __future__ import annotations

import asyncio
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Parsers for each package manager output format
# ---------------------------------------------------------------------------

_DPKG_RE = re.compile(r"^ii\s+([a-zA-Z0-9][a-zA-Z0-9.+\-]+?)(?::\S+)?\s+(\S+)", re.MULTILINE)
_RPM_RE  = re.compile(r"^(\S+)-(\d[^-]*)-\S+\.\S+$")
_PAC_RE  = re.compile(r"^(\S+)\s+(\S+)$")        # pacman -Q output
_APK_RE  = re.compile(r"^(\S+)-(\d.*)$")         # apk info


def parse_dpkg(output: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in _DPKG_RE.finditer(output)}


def parse_rpm(output: str) -> dict[str, str]:
    """Parse `rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'`."""
    result: dict[str, str] = {}
    for line in output.splitlines():
        m = _RPM_RE.match(line.strip())
        if m:
            result[m.group(1)] = m.group(2)
    return result


def parse_pacman(output: str) -> dict[str, str]:
    return {m.group(1): m.group(2) for m in _PAC_RE.finditer(output)}


def parse_apk(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        m = _APK_RE.match(line.strip())
        if m:
            result[m.group(1)] = m.group(2)
    return result


_PARSERS = {
    "dpkg": parse_dpkg,
    "rpm":  parse_rpm,
    "pacman": parse_pacman,
    "apk":  parse_apk,
}

_PM_DETECT_CMD = (
    "command -v dpkg >/dev/null 2>&1 && echo dpkg || "
    "command -v rpm  >/dev/null 2>&1 && echo rpm  || "
    "command -v pacman >/dev/null 2>&1 && echo pacman || "
    "command -v apk >/dev/null 2>&1 && echo apk || echo unknown"
)

_PM_LIST_CMDS: dict[str, list[str]] = {
    # All commands are stored as arg lists so _run_local can use shell=False.
    # dpkg-query / rpm / pacman: simple commands; \n in format strings is
    #   interpreted by the tool itself (not the shell), so passing it literally
    #   works identically whether or not a shell is involved.
    # apk: "apk info -v" produces "pkgname-version" lines (one per package)
    #   which parse_apk already handles.  The old form used a sed pipeline and
    #   required shell=True; this formulation avoids that dependency.
    "dpkg":   ["dpkg-query", "-W", "-f=${db:Status-Abbrev}  ${Package}  ${Version}\\n"],
    "rpm":    ["rpm", "-qa", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n"],
    "pacman": ["pacman", "-Q"],
    "apk":    ["apk", "info", "-v"],
}

# Simpler dpkg-query output used when the formatted query fails
_DPKG_FALLBACK = "dpkg-query -W -f='ii  ${Package}  ${Version}\\n'"

# SSH command that collects loaded .so paths and resolves them to package names
# via dpkg -S (or falls back silently on non-Debian systems).
_RUNTIME_COLLECT_CMD = (
    "{ for f in /proc/*/maps; do cat \"$f\" 2>/dev/null; done; } "
    "| awk '$6 ~ /\\.so/{print $6}' | sort -u "
    "| xargs dpkg -S 2>/dev/null || true"
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MachineSpec:
    host: str
    user: Optional[str] = None
    method: str = "ssh"          # "ssh" | "local" | "file"
    pm: Optional[str] = None     # package manager; auto-detected if None
    file: Optional[str] = None   # path to pre-collected output file
    runtime: bool = False        # if True, collect /proc/*/maps data for runtime reachability


@dataclass
class MachineResult:
    host: str
    packages: dict[str, str] = field(default_factory=dict)  # {pkg_name: version}
    pm: str = "unknown"
    error: Optional[str] = None
    package_count: int = 0
    runtime_loaded_pkgs: list[str] = field(default_factory=list)  # pkgs with .so in memory


@dataclass
class FleetResult:
    machines: list[MachineResult] = field(default_factory=list)

    @property
    def all_packages(self) -> set[str]:
        """Union of all package names seen across the fleet."""
        result: set[str] = set()
        for m in self.machines:
            result.update(m.packages)
        return result

    def package_coverage(self) -> dict[str, list[str]]:
        """For each package name → list of machines that have it installed."""
        coverage: dict[str, list[str]] = {}
        for machine in self.machines:
            for pkg in machine.packages:
                coverage.setdefault(pkg, []).append(machine.host)
        return coverage

    def version_variance(self) -> dict[str, dict[str, str]]:
        """For packages where version differs across machines → {pkg: {host: version}}."""
        result: dict[str, dict[str, str]] = {}
        coverage = self.package_coverage()
        for pkg, hosts in coverage.items():
            if len(hosts) < 2:
                continue
            versions = {h: m.packages.get(pkg, "?")
                        for m in self.machines for h in [m.host] if pkg in m.packages}
            if len(set(versions.values())) > 1:
                result[pkg] = versions
        return result

    def runtime_coverage(self) -> dict[str, list[str]]:
        """For each package loaded in memory → list of host names where it is live."""
        coverage: dict[str, list[str]] = {}
        for m in self.machines:
            for pkg in m.runtime_loaded_pkgs:
                coverage.setdefault(pkg, []).append(m.host)
        return coverage

    def to_local_versions(self) -> dict[str, str]:
        """
        Aggregate: for each package, pick the OLDEST version seen across the
        fleet — conservative estimate for risk scoring (worst-case machine).
        """
        from packaging.version import Version, InvalidVersion

        def _v(s: str) -> Version:
            try:
                return Version(s.split(":")[-1])
            except InvalidVersion:
                return Version("0")

        agg: dict[str, str] = {}
        for machine in self.machines:
            for pkg, ver in machine.packages.items():
                if pkg not in agg or _v(ver) < _v(agg[pkg]):
                    agg[pkg] = ver
        return agg


# ---------------------------------------------------------------------------
# Collection helpers
# ---------------------------------------------------------------------------

async def _collect_runtime_ssh(host: str, user: Optional[str]) -> list[str]:
    """Return sorted list of package names with .so files loaded on a remote host.

    Runs ``_RUNTIME_COLLECT_CMD`` over SSH, which cats all ``/proc/*/maps``
    entries, extracts unique ``.so`` paths, and resolves them via ``dpkg
    -S``.  Returns an empty list on errors or non-Debian/Ubuntu hosts.
    """
    stdout, _ = await _run_ssh(host, user, _RUNTIME_COLLECT_CMD, timeout=45)
    pkgs: set[str] = set()
    for line in stdout.splitlines():
        if ": " in line:
            pkg_raw, _ = line.split(": ", 1)
            pkgs.add(pkg_raw.split(":")[0].strip())
    return sorted(pkgs)


async def _run_ssh(host: str, user: Optional[str], cmd: str, timeout: int = 15) -> tuple[str, str]:
    """Run *cmd* on *host* via SSH. Returns (stdout, stderr)."""
    target = f"{user}@{host}" if user else host
    ssh_cmd = ["ssh", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new",
               "-o", "BatchMode=yes", target, cmd]
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=timeout,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace")
    except asyncio.TimeoutError:
        return "", "SSH timeout"
    except Exception as e:
        return "", str(e)


def _run_local(pm: str) -> tuple[str, str]:
    """Run the package list command locally."""
    import shlex
    cmd = _PM_LIST_CMDS.get(pm, "")
    if not cmd:
        return "", f"Unsupported package manager: {pm}"
    try:
        result = subprocess.run(
            shlex.split(cmd), shell=False, capture_output=True, text=True, timeout=30
        )
        return result.stdout, result.stderr
    except Exception as e:
        return "", str(e)


async def _detect_pm_ssh(host: str, user: Optional[str]) -> str:
    stdout, _ = await _run_ssh(host, user, _PM_DETECT_CMD)
    return stdout.strip() or "unknown"


def _detect_pm_local() -> str:
    import shutil
    for pm in ("dpkg", "rpm", "pacman", "apk"):
        if shutil.which(pm):
            return pm
    return "unknown"


async def _scan_machine(spec: MachineSpec) -> MachineResult:
    result = MachineResult(host=spec.host)

    if spec.method == "file":
        if not spec.file:
            result.error = "file method requires a 'file' path"
            return result
        try:
            output = open(spec.file).read()
        except Exception as e:
            result.error = str(e)
            return result
        # Try dpkg format first (most common for pre-dumped files)
        pkgs = parse_dpkg(output)
        if not pkgs:
            pkgs = parse_rpm(output)
        result.packages = pkgs
        result.pm = "dpkg" if pkgs else "unknown"
        result.package_count = len(pkgs)
        return result

    elif spec.method == "local":
        pm = spec.pm or _detect_pm_local()
        result.pm = pm
        if pm == "unknown":
            result.error = "Could not detect local package manager"
            return result
        stdout, stderr = _run_local(pm)
        if not stdout and stderr:
            result.error = stderr[:200]
            return result
        parser = _PARSERS.get(pm, parse_dpkg)
        result.packages = parser(stdout)
        result.package_count = len(result.packages)
        if spec.runtime:
            from selvo.analysis.runtime import scan_loaded_libraries, map_sos_to_packages
            lib_map = scan_loaded_libraries()
            so_to_pkg = map_sos_to_packages(list(lib_map.keys()))
            result.runtime_loaded_pkgs = sorted(set(so_to_pkg.values()))
        return result

    else:  # ssh
        pm = spec.pm
        if not pm:
            pm = await _detect_pm_ssh(spec.host, spec.user)
        result.pm = pm
        if pm == "unknown":
            result.error = "Could not detect remote package manager"
            return result

        cmd_parts = _PM_LIST_CMDS.get(pm, [])
        if not cmd_parts:
            result.error = f"No list command for pm={pm}"
            return result
        # Join into a shell string — the command runs inside a remote shell via SSH
        cmd = " ".join(cmd_parts)

        stdout, stderr = await _run_ssh(spec.host, spec.user, cmd)
        if not stdout:
            result.error = stderr[:200] if stderr else "Empty output from remote"
            return result

        parser = _PARSERS.get(pm, parse_dpkg)
        result.packages = parser(stdout)

        if not result.packages and pm == "dpkg":
            # Retry with simpler format
            stdout2, _ = await _run_ssh(spec.host, spec.user, _DPKG_FALLBACK)
            result.packages = parse_dpkg(stdout2)

        result.package_count = len(result.packages)
        if spec.runtime:
            result.runtime_loaded_pkgs = await _collect_runtime_ssh(spec.host, spec.user)
        return result


async def scan_fleet(specs: list[MachineSpec], concurrency: int = 10) -> FleetResult:
    """Scan all machines concurrently and return a FleetResult."""
    sem = asyncio.Semaphore(concurrency)

    async def bounded_scan(spec: MachineSpec) -> MachineResult:
        async with sem:
            return await _scan_machine(spec)

    results = await asyncio.gather(*[bounded_scan(s) for s in specs])
    return FleetResult(machines=list(results))


async def dry_run_fleet(specs: list[MachineSpec], console: object | None = None) -> None:
    """Validate SSH connectivity and print the commands that *would* be run.

    Does not collect packages. Exits with a summary of reachable vs unreachable hosts.
    """
    import sys

    def _print(msg: str) -> None:
        if console is not None and hasattr(console, "print"):
            console.print(msg)  # type: ignore[union-attr]
        else:
            print(msg, file=sys.stderr)

    _print(f"[bold cyan]selvo fleet --dry-run[/]: validating {len(specs)} host(s)…\n")

    ok: list[str] = []
    fail: list[tuple[str, str]] = []

    for spec in specs:
        if spec.method == "local":
            pm = _detect_pm_local()
            cmd = _PM_LIST_CMDS.get(pm, ["<package manager not detected>"])
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
            _print(f"  [green]local[/] {spec.host} — would run: [dim]{cmd_str}[/]")
            ok.append(spec.host)
            continue

        if spec.method == "file":
            import os
            if spec.file and os.path.exists(spec.file):
                _print(f"  [green]file[/] {spec.host} — {spec.file} exists, {os.path.getsize(spec.file):,} bytes")
                ok.append(spec.host)
            else:
                _print(f"  [red]file[/] {spec.host} — {spec.file!r} not found")
                fail.append((spec.host, f"file not found: {spec.file}"))
            continue

        # SSH: test connectivity with a no-op command
        target = f"{spec.user}@{spec.host}" if spec.user else spec.host
        stdout, stderr = await _run_ssh(spec.host, spec.user, "echo selvo-ok", timeout=10)
        if "selvo-ok" in stdout:
            pm = await _detect_pm_ssh(spec.host, spec.user)
            cmd = _PM_LIST_CMDS.get(pm, ["<unsupported pm>"])
            cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
            _print(f"  [green]✓[/] {target} — pm={pm}, would run: [dim]{cmd_str}[/]")
            ok.append(spec.host)
        else:
            reason = stderr.strip()[:80] or "no response"
            _print(f"  [red]✗[/] {target} — {reason}")
            fail.append((spec.host, reason))

    _print(f"\n[bold]Dry-run complete:[/] {len(ok)} reachable, {len(fail)} unreachable")
    if fail:
        for host, reason in fail:
            _print(f"  [red]{host}:[/] {reason}")


def specs_from_dict(raw: list[dict]) -> list[MachineSpec]:
    """Parse a list of machine spec dicts (loaded from YAML/JSON fleet file)."""
    return [
        MachineSpec(
            host=m["host"],
            user=m.get("user"),
            method=m.get("method", "ssh"),
            pm=m.get("pm"),
            file=m.get("file"),
            runtime=m.get("runtime", False),
        )
        for m in raw
    ]
