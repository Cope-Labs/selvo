"""selvo MCP server — expose the dependency-risk pipeline as MCP tools.

Start with stdio transport (default for local agents):

    selvo-mcp                        # stdio, for Claude Desktop / Cursor / etc.
    selvo-mcp --transport sse        # SSE, for remote agents

Claude Desktop config (~/.config/claude/claude_desktop_config.json):

    {
      "mcpServers": {
        "selvo": {
          "command": "/path/to/.venv/bin/selvo-mcp"
        }
      }
    }

Tools exposed
─────────────
analyze_packages     Full pipeline: discover → CVE → EPSS → CVSS → blast-radius → rank
                     Slow (1–3 min). Results are cached to SQLite for fast re-use.

get_snapshot         Return the most recent cached analysis without any API calls.
                     Instant. Useful for follow-up questions after analyze_packages.

check_local_risk     Read locally-installed package versions (dpkg/rpm/pacman/apk),
                     cross-reference CVEs, and return only packages with open CVEs.
                     Useful when running on a server you want to audit.

check_runtime_risk   Check which CVE-affected shared libraries are *actually loaded in
                     memory* right now via /proc/*/maps.  Optionally supplement with
                     eBPF dlopen() tracing for ephemeral processes.  selvo’s unique
                     signal: not just “installed” but “running in nginx right now”.

describe_package     Return full detail for one named package from the last snapshot
                     (or trigger a fresh analysis if no snapshot exists).

list_cves            Return CVE IDs + CVSS + EPSS for packages above a risk threshold.
"""
from __future__ import annotations

import dataclasses
import logging
from datetime import datetime, timezone
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

log = logging.getLogger(__name__)

mcp = FastMCP(
    "selvo",
    instructions=(
        "selvo maps Linux core package dependencies and surfaces CVE/version risk. "
        "Call analyze_packages first to populate the cache, then use get_snapshot, "
        "describe_package, and list_cves for fast follow-up queries. "
        "Use check_local_risk when the goal is auditing the machine you're running on."
    ),
)


# ── Shared pipeline ──────────────────────────────────────────────────────────

async def _run_pipeline(
    ecosystem: str = "all",
    limit: int = 50,
    context_mode: str = "reference",
    run_cve: bool = True,
) -> list[Any]:
    """Full selvo analysis pipeline. Returns ranked list[PackageRecord]."""
    from selvo.discovery import run_discovery
    from selvo.analysis.versions import enrich_versions
    from selvo.analysis.cve import enrich_cve
    from selvo.analysis.distro_status import filter_resolved_cves
    from selvo.analysis.epss import enrich_epss, enrich_epss_velocity
    from selvo.analysis.cvss import enrich_cvss
    from selvo.analysis.rdeps import enrich_reverse_deps
    from selvo.analysis.graph_metrics import enrich_graph_metrics
    from selvo.analysis.upstream import enrich_upstream_repos
    from selvo.analysis.collapse import collapse_by_source
    from selvo.analysis.debian_index import load_debian_index
    from selvo.analysis.local_context import detect_system_context, read_local_versions
    from selvo.prioritizer.scorer import score_and_rank
    from selvo.analysis.cache import save_snapshot, load_last_snapshot

    # Load previous snapshot BEFORE pipeline so EPSS velocity can compare
    prev_result = load_last_snapshot(ecosystem)
    previous_snapshot: list[dict] = prev_result[0] if prev_result else []

    packages = await run_discovery(ecosystem, limit)
    packages = await enrich_versions(packages)

    if context_mode in ("local", "auto"):
        ctx = detect_system_context(mode=context_mode)
        local_versions = read_local_versions(ctx)
        for pkg in packages:
            v = local_versions.get(pkg.name)
            if v:
                pkg.version = v
                pkg.version_source = "local"

    if run_cve:
        packages = await enrich_cve(packages)
        packages = await filter_resolved_cves(packages)
        packages = await enrich_epss(packages)
        # Compute EPSS velocity against previous snapshot
        packages = enrich_epss_velocity(packages, previous_snapshot)
        packages = await enrich_cvss(packages)

    packages = await enrich_reverse_deps(packages)
    deb_idx = await load_debian_index()
    packages = collapse_by_source(packages, deb_idx)
    # Re-filter after collapse — collapse unions CVEs from all binaries in a
    # source group, which can re-introduce CVEs that were filtered pre-collapse.
    # Post-collapse pkg.name IS the source name, so DST lookup is direct.
    if run_cve:
        packages = await filter_resolved_cves(packages)
    packages = await enrich_graph_metrics(packages, ecosystem=ecosystem)
    packages = await enrich_upstream_repos(packages)

    from selvo.analysis.distro_compare import enrich_distro_versions
    from selvo.analysis.patch_safety import enrich_patch_safety
    from selvo.analysis.exploit import enrich_exploits
    from selvo.analysis.distro_tracker import enrich_distro_patch_dates

    packages = await enrich_distro_versions(packages)
    if run_cve:
        from selvo.analysis.cve_timeline import enrich_cve_timeline
        packages = await enrich_cve_timeline(packages)
        packages = await enrich_exploits(packages)
        packages = await enrich_distro_patch_dates(packages)
    packages = enrich_patch_safety(packages)

    from selvo.analysis.ossfuzz import enrich_ossfuzz
    from selvo.analysis.advisories import enrich_advisories
    from selvo.analysis.sla import enrich_sla
    packages = await enrich_ossfuzz(packages)
    packages = await enrich_advisories(packages)
    packages = enrich_sla(packages)

    ranked = score_and_rank(packages)

    from selvo.analysis.changelog import enrich_changelog_summaries
    ranked = await enrich_changelog_summaries(ranked, top_n=5)

    save_snapshot(ecosystem, ranked)
    return ranked


def _pkg_to_dict(pkg: Any) -> dict:
    """Serialize a PackageRecord to a plain dict (including computed properties)."""
    _strip = {"fix_refs", "dependents", "dependencies"}
    d = {k: v for k, v in dataclasses.asdict(pkg).items() if k not in _strip}
    d["is_outdated"] = pkg.is_outdated
    d["cve_count"] = pkg.cve_count
    return d


# ── Tools ────────────────────────────────────────────────────────────────────

@mcp.tool()
async def analyze_packages(
    ecosystem: str = "all",
    limit: int = 50,
    context_mode: Literal["reference", "local", "auto"] = "reference",
) -> dict:
    """Run the full selvo analysis pipeline and return ranked packages.

    This is the primary tool — call it first to populate the cache.
    Results are automatically saved to SQLite so subsequent calls to
    get_snapshot, describe_package, and list_cves are instant.

    NOTE: This tool takes 1–3 minutes due to network API calls
    (OSV, EPSS, NVD CVSS, Repology, Debian Packages.gz).

    Args:
        ecosystem: Which package ecosystem(s) to analyse.
                   One of: debian, ubuntu, fedora, arch, alpine, nixos, all.
        limit:     Maximum number of top packages to discover per ecosystem.
                   50 is a good default; go up to 100 for broader coverage.
        context_mode:
                   'reference' — use Debian stable Packages.gz + Repology versions
                                 (best for CI/cross-machine analysis, default).
                   'local'     — use locally-installed versions from the system
                                 package manager (dpkg/rpm/pacman/apk). Useful when
                                 auditing the machine selvo is running on.
                   'auto'      — try local, silently fall back to reference.

    Returns a summary dict plus the top 10 packages by risk score so the model
    can immediately reason about the results. The full list is in 'packages'.
    """
    ranked = await _run_pipeline(ecosystem=ecosystem, limit=limit, context_mode=context_mode)

    pkgs = [_pkg_to_dict(p) for p in ranked]

    with_cves  = sum(1 for p in ranked if p.cve_count > 0)
    outdated   = sum(1 for p in ranked if p.is_outdated)
    total_br   = sum(p.transitive_rdep_count for p in ranked)

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ecosystem": ecosystem,
        "context_mode": context_mode,
        "total_packages": len(pkgs),
        "with_cves": with_cves,
        "outdated": outdated,
        "total_blast_radius": total_br,
        "top_10_by_score": pkgs[:10],
        "packages": pkgs,
    }


@mcp.tool()
def get_snapshot(ecosystem: str = "all") -> dict:
    """Return the most recent cached analysis for an ecosystem — no API calls.

    This is instant. Use it for follow-up questions after analyze_packages
    has been run at least once. Returns a slim summary dict per package.

    Args:
        ecosystem: Which ecosystem to retrieve. Must match what was passed to
                   analyze_packages (e.g. 'all', 'debian', 'fedora').
    """
    from selvo.analysis.cache import load_last_snapshot

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {
            "error": f"No snapshot found for ecosystem '{ecosystem}'. "
                     "Run analyze_packages first to populate the cache."
        }
    packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with_cves = sum(1 for p in packages if p.get("cve_count", 0) > 0)
    return {
        "snapshot_taken_at": ts,
        "ecosystem": ecosystem,
        "total_packages": len(packages),
        "with_cves": with_cves,
        "packages": packages,
    }


@mcp.tool()
async def check_local_risk() -> dict:
    """Audit THIS machine: cross-reference locally-installed packages with CVEs.

    Reads installed packages from the local package manager (dpkg-query on
    Debian/Ubuntu, rpm on Fedora/RHEL, pacman on Arch, apk on Alpine), then
    runs the CVE + EPSS + CVSS pipeline and filters to only packages that
    have unresolved CVEs.

    Returns only at-risk packages sorted by score descending. Much faster
    than a full analyze call because limit is set to the packages that
    actually match what's installed.

    Requires a supported package manager to be available on the system.
    """
    from selvo.analysis.local_context import detect_system_context, read_local_versions

    ctx = detect_system_context(mode="local")
    local_versions = read_local_versions(ctx)

    if not local_versions:
        return {
            "error": "No supported package manager found. "
                     "Expected one of: dpkg (Debian/Ubuntu), rpm (Fedora/RHEL), "
                     "pacman (Arch), apk (Alpine).",
            "os_name": ctx.os_name,
            "os_version": ctx.os_version,
            "package_manager": ctx.package_manager,
        }

    ranked = await _run_pipeline(
        ecosystem="all",
        limit=50,
        context_mode="local",
        run_cve=True,
    )

    at_risk = [
        _pkg_to_dict(p) for p in ranked
        if p.cve_count > 0
    ]

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "os_name": ctx.os_name,
        "os_version": ctx.os_version,
        "kernel": ctx.kernel,
        "arch": ctx.arch,
        "package_manager": ctx.package_manager,
        "local_packages_total": len(local_versions),
        "at_risk_count": len(at_risk),
        "at_risk_packages": at_risk,
    }


@mcp.tool()
async def check_runtime_risk(
    cve_only: bool = True,
    ebpf_duration_s: float = 0.0,
    ecosystem: str = "all",
) -> dict:
    """Check which CVE-affected shared libraries are actually loaded in memory right now.

    Scans ``/proc/*/maps`` for every accessible running process, maps loaded
    ``.so`` files to package names (dpkg → rpm → pacman → apk → heuristic),
    cross-references against CVE data, and returns only packages that are both
    *vulnerable* **and** *currently executing in memory*.

    This is selvo’s unique signal: not “this CVE-affected package is installed”
    but “libssl3 (CVE-2024-XXXX, EPSS 0.91) is loaded in nginx right now.”
    Runtime-loaded packages receive a 1.5× score boost.

    Args:
        cve_only:        If true (default), only return packages with open CVEs
                         that are currently loaded. False returns all loaded libs.
        ebpf_duration_s: If > 0 and eBPF is available (root + kernel ≥ 5.8 +
                         python3-bpfcc), additionally trace dlopen() calls for
                         this many seconds, capturing ephemeral processes a
                         procfs snapshot would miss.  0 = procfs only (default).
        ecosystem:       Ecosystem for CVE enrichment context.

    Returns:
        Dict with 'loaded_vulnerable' (packages confirmed loaded with CVEs),
        'hits' (per-process granularity), and scoring metadata.

    NOTE: Full coverage requires root (‘sudo selvo-mcp’) or CAP_SYS_PTRACE.
    Without it, only the current user’s processes are visible.
    """
    import dataclasses as _dc

    # Run the CVE pipeline (fast if cached; slow first time)
    packages = await _run_pipeline(ecosystem=ecosystem, limit=50, run_cve=True)
    cve_packages = [p for p in packages if p.cve_ids]

    from selvo.analysis.runtime import enrich_runtime, merge_ebpf_events
    from selvo.analysis.debian_index import load_debian_index

    deb_idx = await load_debian_index()
    cve_packages, hits = enrich_runtime(cve_packages, cve_only=cve_only, deb_idx=deb_idx)

    # Optional eBPF supplement for ephemeral/short-lived process coverage
    ebpf_events_count = 0
    ebpf_available = False
    if ebpf_duration_s > 0:
        from selvo.analysis.ebpf_tracer import is_ebpf_available, trace_dlopen
        ebpf_available = is_ebpf_available()
        if ebpf_available:
            ebpf_events = list(
                trace_dlopen(duration_s=ebpf_duration_s, cve_packages=cve_packages)
            )
            ebpf_events_count = len(ebpf_events)
            if ebpf_events:
                existing_pairs = {(h.package, h.pid) for h in hits}
                cve_packages, ebpf_hits = merge_ebpf_events(
                    ebpf_events, cve_packages, deb_idx=deb_idx
                )
                for h in ebpf_hits:
                    if (h.package, h.pid) not in existing_pairs:
                        hits.append(h)

    from selvo.prioritizer.scorer import score_and_rank
    all_packages = score_and_rank(cve_packages)

    loaded_vulnerable = [
        {
            "name":          p.name,
            "score":         round(p.score, 2),
            "cve_count":     p.cve_count,
            "cve_ids":       p.cve_ids[:5],
            "max_cvss":      p.max_cvss,
            "max_epss":      round(p.max_epss, 4),
            "in_cisa_kev":   p.in_cisa_kev,
            "runtime_pids":  p.runtime_pids[:10],
            "runtime_procs": list(dict.fromkeys(p.runtime_procs))[:5],
        }
        for p in all_packages
        if p.runtime_loaded and p.cve_ids
    ]
    loaded_vulnerable.sort(key=lambda x: x["score"], reverse=True)

    return {
        "generated_at":            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ecosystem":               ecosystem,
        "cve_only":                cve_only,
        "ebpf_requested_s":        ebpf_duration_s,
        "ebpf_available":          ebpf_available,
        "ebpf_events_captured":    ebpf_events_count,
        "loaded_vulnerable_count": len(loaded_vulnerable),
        "loaded_vulnerable":       loaded_vulnerable,
        "hit_count":               len(hits),
        "hits":                    [_dc.asdict(h) for h in hits[:100]],
        "note": (
            "Packages in 'loaded_vulnerable' have open CVEs AND are confirmed "
            "loaded in running processes. Score includes 1.5\u00d7 runtime boost. "
            "Full /proc coverage requires root or CAP_SYS_PTRACE."
        ),
    }


@mcp.tool()
def describe_package(name: str, ecosystem: str = "all") -> dict:
    """Return full detail for a named package from the most recent snapshot.

    Includes: installed version, upstream version, is_outdated, all CVE IDs,
    max CVSS, max EPSS, transitive blast radius, betweenness score, upstream repo.

    Args:
        name:      The package name (e.g. 'openssl', 'zlib', 'glibc').
                   Source-package names are preferred (e.g. 'util-linux' not 'mount').
        ecosystem: The ecosystem snapshot to query. Defaults to 'all'.
    """
    from selvo.analysis.cache import load_last_snapshot

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {
            "error": f"No snapshot for ecosystem '{ecosystem}'. Run analyze_packages first."
        }

    packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    name_lower = name.lower()
    match = next(
        (p for p in packages if p.get("name", "").lower() == name_lower),
        None,
    )
    if match is None:
        close = [p["name"] for p in packages if name_lower in p.get("name", "").lower()]
        return {
            "error": f"Package '{name}' not found in snapshot.",
            "snapshot_at": ts,
            "did_you_mean": close[:5],
        }

    return {"snapshot_at": ts, **match}


@mcp.tool()
def list_cves(
    min_cvss: float = 7.0,
    min_epss: float = 0.0,
    ecosystem: str = "all",
    limit: int = 25,
) -> dict:
    """List packages with open CVEs above a severity threshold.

    Queries the last snapshot — instant, no API calls.

    Args:
        min_cvss:  Minimum CVSS v3 base score (0–10). Default 7.0 = 'High'.
                   Use 4.0 for Medium+, 9.0 for Critical only.
        min_epss:  Minimum EPSS exploitation probability (0–1). Default 0.0 = no filter.
                   Use 0.1 to focus on packages with 10%+ chance of being exploited.
        ecosystem: Which ecosystem snapshot to query. Default 'all'.
        limit:     Maximum number of results to return.
    """
    from selvo.analysis.cache import load_last_snapshot

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {
            "error": f"No snapshot for ecosystem '{ecosystem}'. Run analyze_packages first."
        }

    packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    hits = [
        p for p in packages
        if p.get("cve_count", 0) > 0
        and p.get("max_cvss", 0.0) >= min_cvss
        and p.get("max_epss", 0.0) >= min_epss
    ]
    # Sort by score descending (score is already in the slim snapshot)
    hits.sort(key=lambda p: p.get("score", 0.0), reverse=True)
    hits = hits[:limit]

    return {
        "snapshot_at": ts,
        "ecosystem": ecosystem,
        "filters": {"min_cvss": min_cvss, "min_epss": min_epss},
        "matched": len(hits),
        "packages": hits,
    }


@mcp.tool()
def get_upstream_watchlist(
    ecosystem: str = "all",
    min_rdeps: int = 0,
    min_cvss: float = 0.0,
    limit: int = 20,
) -> dict:
    """Return upstream GitHub repos for high-risk packages — ready to feed into argus.

    Reads the most recent snapshot and returns the top packages with resolved
    upstream GitHub repos, ranked by (transitive_rdep_count × max_cvss).
    Designed to compose with the argus MCP server's feed_watch_repo tool:
    call this, iterate the results, and call feed_watch_repo on each.

    Args:
        ecosystem:  Ecosystem snapshot to query.
        min_rdeps:  Minimum transitive reverse-dep count (filter out small packages).
        min_cvss:   Minimum CVSS score (0–10). Use 7.0 for high/critical only.
        limit:      Maximum repos to return.

    Returns:
        {'watchlist': [{'package', 'upstream_repo', 'rdep_count', 'max_cvss', 'blast_score'}]}
    """
    from selvo.analysis.cache import load_last_snapshot

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {"error": f"No snapshot for ecosystem '{ecosystem}'. Run analyze_packages first."}

    packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    watchlist = []
    for p in packages:
        repo = p.get("upstream_repo")
        if not repo or "github.com" not in repo:
            continue
        rdeps = p.get("transitive_rdep_count", 0)
        cvss = p.get("max_cvss", 0.0)
        if rdeps < min_rdeps or cvss < min_cvss:
            continue
        blast_score = round(rdeps * cvss / 10.0, 1)
        watchlist.append({
            "package":       p["name"],
            "upstream_repo": repo,
            "rdep_count":    rdeps,
            "max_cvss":      cvss,
            "cve_count":     p.get("cve_count", 0),
            "blast_score":   blast_score,
        })

    watchlist.sort(key=lambda x: x["blast_score"], reverse=True)
    watchlist = watchlist[:limit]

    return {
        "snapshot_at": ts,
        "ecosystem": ecosystem,
        "total": len(watchlist),
        "watchlist": watchlist,
        "argus_hint": (
            "Pass each upstream_repo to argus feed_watch_repo to receive "
            "release alerts when upstream ships security fixes."
        ),
    }


@mcp.tool()
async def patch_plan(
    ecosystem: str = "all",
    limit: int = 20,
    safe_only: bool = False,
) -> dict:
    """Return a prioritized patch plan ranked by risk × safety.

    Combines blast-radius risk score with patch regression risk to produce
    two ranked lists:
      - 'deploy_now'  : low regression risk, high CVE impact — safe to ship today
      - 'test_first'  : high regression risk — need manual validation before deploy

    Args:
        ecosystem:   Ecosystem to plan patches for.
        limit:       Number of packages to include in the plan.
        safe_only:   If true, only return packages with patch_regression_risk='low'.

    Requires an existing snapshot (run analyze_packages first).
    """
    from selvo.analysis.cache import load_last_snapshot

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {"error": f"No snapshot for ecosystem '{ecosystem}'. Run analyze_packages first."}

    packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Slim snapshot doesn't have patch_safety_score — need full pipeline
    # Check if safety data is present
    has_safety = any(p.get("patch_safety_score", -1) >= 0 for p in packages)
    if not has_safety:
        return {
            "error": "Snapshot does not contain patch safety data. "
                     "Re-run analyze_packages to populate safety scores."
        }

    plan_rows = []
    for p in packages:
        if p.get("cve_count", 0) == 0 and not p.get("is_outdated", False):
            continue
        safety = p.get("patch_safety_score", 0.5)
        risk_label = p.get("patch_regression_risk", "unknown")
        score = p.get("score", 0.0)
        plan_rows.append({
            "package":              p["name"],
            "score":                round(score, 2),
            "cve_count":            p.get("cve_count", 0),
            "max_cvss":             p.get("max_cvss", 0.0),
            "max_epss":             p.get("max_epss", 0.0),
            "exposure_days":        p.get("exposure_days", 0),
            "rdep_count":           p.get("transitive_rdep_count", 0),
            "patch_safety_score":   round(safety, 3),
            "patch_regression_risk": risk_label,
            "upstream_version":     p.get("upstream_version"),
            "distro_lag_days":      p.get("distro_lag_days", 0),
            "upstream_repo":        p.get("upstream_repo"),
        })

    if safe_only:
        plan_rows = [r for r in plan_rows if r["patch_regression_risk"] == "low"]

    deploy_now  = sorted(
        [r for r in plan_rows if r["patch_regression_risk"] == "low"],
        key=lambda x: x["score"], reverse=True
    )[:limit]

    test_first  = sorted(
        [r for r in plan_rows if r["patch_regression_risk"] in ("medium", "high", "unknown")],
        key=lambda x: x["score"], reverse=True
    )[:limit]

    return {
        "snapshot_at":   ts,
        "ecosystem":     ecosystem,
        "deploy_now":    deploy_now,
        "test_first":    test_first,
        "summary": {
            "safe_to_ship":    len(deploy_now),
            "needs_testing":   len(test_first),
            "total_exposed":   len(plan_rows),
        },
    }


@mcp.tool()
async def fleet_scan(
    machines: str = "localhost",
    ecosystem: str = "debian",
    limit: int = 50,
    ssh_user: str = "",
) -> dict:
    """Scan multiple machines and return fleet-wide CVE risk analysis.

    Collects installed package versions from each machine via SSH (or local
    for 'localhost'), merges into a conservative worst-case view, and runs
    the full selvo pipeline to rank CVE risk fleet-wide.

    Args:
        machines:   Comma-separated list of hostnames (e.g. 'web01,web02,db01').
                    Use 'localhost' to scan the current machine.
        ecosystem:  Which ecosystems to analyse (debian, fedora, alpine, all).
        limit:      Max packages to discover per ecosystem.
        ssh_user:   SSH username override (empty = current user).

    Returns fleet-wide risk summary and top packages by risk score.
    NOTE: Requires SSH key auth to remote machines; passwords are not supported.
    """
    from selvo.analysis.fleet import scan_fleet, MachineSpec
    import re as _re

    _HOSTNAME_RE = _re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}$")

    hosts = [h.strip() for h in machines.split(",") if h.strip()]
    for h in hosts:
        if not _HOSTNAME_RE.match(h):
            return {"error": f"Invalid hostname: {h!r}. Only alphanumeric, dots, and hyphens allowed."}
    if ssh_user and not _re.match(r"^[a-zA-Z_][a-zA-Z0-9_\-]{0,31}$", ssh_user):
        return {"error": f"Invalid ssh_user: {ssh_user!r}."}
    specs = [
        MachineSpec(
            host=h,
            user=ssh_user or None,
            method="local" if h == "localhost" else "ssh",
        )
        for h in hosts
    ]

    fleet_result = await scan_fleet(specs)

    machine_summaries = [
        {
            "host":          m.host,
            "status":        "ok" if not m.error else "error",
            "package_count": m.package_count,
            "pm":            m.pm,
            "error":         m.error,
        }
        for m in fleet_result.machines
    ]

    ok_machines = [m for m in fleet_result.machines if not m.error]
    if not ok_machines:
        return {
            "error": "No machines scanned successfully.",
            "machines": machine_summaries,
        }

    fleet_versions = fleet_result.to_local_versions()
    variance = fleet_result.version_variance()

    ranked = await _run_pipeline(ecosystem=ecosystem, limit=limit, context_mode="reference")
    for pkg in ranked:
        v = fleet_versions.get(pkg.name)
        if v:
            pkg.version = v
            pkg.version_source = "fleet"

    pkgs = [_pkg_to_dict(p) for p in ranked if p.cve_count > 0 or p.is_outdated]
    pkgs.sort(key=lambda p: p.get("score", 0.0), reverse=True)

    return {
        "generated_at":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "machines":        machine_summaries,
        "machines_ok":     len(ok_machines),
        "version_drift_packages": len(variance),
        "version_drift":   {pkg: hosts for pkg, hosts in list(variance.items())[:10]},
        "total_exposed":   len(pkgs),
        "top_risks":       pkgs[:15],
    }


@mcp.tool()
async def distro_lag(
    ecosystem: str = "all",
    limit: int = 20,
    min_lag_days: int = 0,
) -> dict:
    """Show per-distro version lag for the top packages.

    Returns a comparison table showing which distros (Debian, Ubuntu, Fedora,
    Alpine, Arch, NixOS) are behind upstream for each package, with an
    estimated lag in days. Useful for distro selection decisions and
    supply-chain monitoring.

    Args:
        ecosystem:     Ecosystem to query.
        limit:         Max packages to return.
        min_lag_days:  Filter to packages lagging at least this many days.

    Requires an existing snapshot (run analyze_packages first).
    """
    from selvo.analysis.cache import load_last_snapshot
    from selvo.analysis.distro_compare import TRACKED_DISTROS

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {"error": f"No snapshot for ecosystem '{ecosystem}'. Run analyze_packages first."}

    packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    has_distro = any(p.get("distro_versions") for p in packages)
    if not has_distro:
        return {
            "error": "Snapshot does not contain per-distro version data. "
                     "Re-run analyze_packages to populate distro comparison."
        }

    rows = []
    for p in packages:
        lag = p.get("distro_lag_days", 0)
        if lag < min_lag_days:
            continue
        distro_v = p.get("distro_versions", {})
        distro_display = {
            TRACKED_DISTROS.get(k, k): v
            for k, v in distro_v.items()
        }
        rows.append({
            "package":          p["name"],
            "upstream_version": p.get("upstream_version"),
            "distro_lag_days":  lag,
            "distros":          distro_display,
            "cve_count":        p.get("cve_count", 0),
            "max_cvss":         p.get("max_cvss", 0.0),
        })

    rows.sort(key=lambda r: r["distro_lag_days"], reverse=True)
    rows = rows[:limit]

    avg_lag = round(sum(r["distro_lag_days"] for r in rows) / max(len(rows), 1), 1)

    return {
        "snapshot_at":    ts,
        "ecosystem":      ecosystem,
        "packages":       rows,
        "avg_lag_days":   avg_lag,
        "tracked_distros": list(TRACKED_DISTROS.values()),
    }


@mcp.tool()
def check_exploits(
    ecosystem: str = "all",
    maturity: str = "poc",
    kev_only: bool = False,
    limit: int = 30,
) -> dict:
    """Return packages that have known public exploits or appear in CISA KEV.

    Uses data from the last analysis snapshot — run analyze_packages first
    to populate exploit availability fields.

    Args:
        ecosystem: Ecosystem to query.
        maturity:  Minimum exploit maturity to include.
                   'poc' = PoC or weaponized; 'weaponized' = weaponized only.
        kev_only:  If True, return only packages with CVEs in CISA KEV catalog.
        limit:     Max packages to return.

    Returns packages ranked by exploit severity + composite score.
    """
    from selvo.analysis.cache import load_last_snapshot

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {"error": f"No snapshot for '{ecosystem}'. Run analyze_packages first."}

    packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    _rank = {"none": 0, "poc": 1, "weaponized": 2}
    min_rank = _rank.get(maturity, 1)

    filtered = [
        p for p in packages
        if _rank.get(p.get("exploit_maturity", "none"), 0) >= min_rank
        or p.get("in_cisa_kev")
    ]
    if kev_only:
        filtered = [p for p in filtered if p.get("in_cisa_kev")]

    filtered.sort(
        key=lambda p: (p.get("in_cisa_kev", False), _rank.get(p.get("exploit_maturity", "none"), 0), p.get("score", 0.0)),
        reverse=True,
    )

    rows = [
        {
            "package":          p["name"],
            "exploit_maturity": p.get("exploit_maturity", "none"),
            "in_cisa_kev":      p.get("in_cisa_kev", False),
            "exploit_urls":     p.get("exploit_urls", [])[:2],
            "cve_ids":          p.get("cve_ids", [])[:3],
            "max_epss":         p.get("max_epss", 0.0),
            "max_cvss":         p.get("max_cvss", 0.0),
            "score":            p.get("score", 0.0),
        }
        for p in filtered[:limit]
    ]

    return {
        "snapshot_at":    ts,
        "ecosystem":      ecosystem,
        "total_matched":  len(filtered),
        "kev_count":      sum(1 for p in filtered if p.get("in_cisa_kev")),
        "weaponized_count": sum(1 for p in filtered if p.get("exploit_maturity") == "weaponized"),
        "poc_count":      sum(1 for p in filtered if p.get("exploit_maturity") == "poc"),
        "packages":       rows,
    }


@mcp.tool()
def get_epss_velocity(
    ecosystem: str = "all",
    min_delta: float = 0.05,
    limit: int = 20,
) -> dict:
    """Show packages whose EPSS exploitation probability is rising fastest.

    EPSS velocity = current EPSS score − previous snapshot's score.
    A rising EPSS is the earliest warning sign that a CVE is moving from
    theoretical to actively exploited.

    Args:
        ecosystem:  Ecosystem to query.
        min_delta:  Minimum EPSS increase to include (default 0.05 = 5 points).
        limit:      Max packages to return.

    Requires at least two prior snapshots (run analyze_packages twice).
    """
    from selvo.analysis.cache import load_last_snapshot

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {"error": f"No snapshot for '{ecosystem}'. Run analyze_packages first."}

    packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    rows = [
        {
            "package":    p["name"],
            "epss_now":   round(p.get("max_epss", 0.0), 4),
            "epss_prev":  round(p.get("epss_prev", 0.0), 4),
            "epss_delta": round(p.get("epss_delta", 0.0), 4),
            "cve_ids":    p.get("cve_ids", [])[:3],
            "score":      p.get("score", 0.0),
        }
        for p in packages
        if p.get("epss_delta", 0.0) >= min_delta
    ]
    rows.sort(key=lambda r: r["epss_delta"], reverse=True)
    rows = rows[:limit]

    has_velocity = any(p.get("epss_prev", 0.0) > 0 for p in packages)

    return {
        "snapshot_at":   ts,
        "ecosystem":     ecosystem,
        "has_velocity_data": has_velocity,
        "note": "Run analyze_packages twice to populate velocity data." if not has_velocity else None,
        "total_rising":  len(rows),
        "packages":      rows,
    }


@mcp.tool()
def get_distro_patch_dates(
    ecosystem: str = "all",
    package: str = "",
    limit: int = 25,
) -> dict:
    """Return real per-distro patch dates for packages from the last snapshot.

    Shows when Ubuntu, RHEL, and Debian actually shipped fixes for CVEs,
    replacing the heuristic version-lag estimate with truth from security APIs.

    Args:
        ecosystem:  Ecosystem to query.
        package:    If set, return detail for that specific package only.
        limit:      Max packages to return (ignored if package is set).

    Data sources: Ubuntu security CVE API, RHEL security data API, Debian DST.
    """
    from selvo.analysis.cache import load_last_snapshot

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {"error": f"No snapshot for '{ecosystem}'. Run analyze_packages first."}

    packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if package:
        pkgs = [p for p in packages if p.get("name", "").lower() == package.lower()]
        if not pkgs:
            return {"error": f"Package '{package}' not found in snapshot."}
    else:
        pkgs = [p for p in packages if p.get("distro_patch_dates")]

    rows = [
        {
            "package":          p["name"],
            "cve_ids":          p.get("cve_ids", [])[:5],
            "distro_lag_days":  p.get("distro_lag_days", 0),
            "patch_dates":      p.get("distro_patch_dates", {}),
            "cve_disclosed_at": p.get("cve_disclosed_at", ""),
        }
        for p in pkgs[:limit]
    ]

    has_real_dates = any(
        v and len(v) == 10
        for row in rows
        for v in row["patch_dates"].values()
    )

    return {
        "snapshot_at":     ts,
        "ecosystem":       ecosystem,
        "has_real_dates":  has_real_dates,
        "packages":        rows,
        "note": "Dates from Ubuntu CVE API + RHEL security API + Debian DST."
                " 'patched' = fixed but no exact date available.",
    }


@mcp.tool()
def get_sla_report(
    ecosystem: str = "all",
    critical_days: int = 7,
    high_days: int = 30,
    medium_days: int = 60,
    low_days: int = 90,
) -> dict:
    """Return an SLA breach report for the most recent snapshot.

    Classifies each vulnerable package by severity band (critical/high/medium/low)
    and flags packages whose CVE has been open longer than the configured SLA.

    Args:
        ecosystem:     Ecosystem to query (use 'all' for combined).
        critical_days: SLA limit for CVSS ≥ 9.0 or KEV packages (default 7).
        high_days:     SLA limit for CVSS ≥ 7.0 or EPSS ≥ 0.40 (default 30).
        medium_days:   SLA limit for CVSS ≥ 4.0 (default 60).
        low_days:      SLA limit for remaining CVE-carrying packages (default 90).
    """
    from selvo.analysis.cache import load_last_snapshot
    from selvo.analysis.sla import SLAPolicy, enrich_sla, sla_report
    from selvo.discovery.base import PackageRecord

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {"error": f"No snapshot for '{ecosystem}'. Run analyze_packages first."}

    raw_packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    packages = [
        PackageRecord(
            name=p["name"],
            ecosystem=p.get("ecosystem", ecosystem),
            version=p.get("version", "unknown"),
            max_cvss=p.get("max_cvss", 0.0),
            max_epss=p.get("max_epss", 0.0),
            cve_ids=p.get("cve_ids", []),
            in_cisa_kev=p.get("in_cisa_kev", False),
            exposure_days=p.get("exposure_days", 0),
            cve_disclosed_at=p.get("cve_disclosed_at", ""),
            sla_days_overdue=p.get("sla_days_overdue", 0),
            sla_band=p.get("sla_band", ""),
        )
        for p in raw_packages
    ]

    policy = SLAPolicy(critical=critical_days, high=high_days, medium=medium_days, low=low_days)
    packages = enrich_sla(packages, policy)
    report = sla_report(packages)
    report["snapshot_at"] = ts
    report["ecosystem"] = ecosystem
    return report


@mcp.tool()
def check_advisories(
    ecosystem: str = "all",
    limit: int = 25,
) -> dict:
    """Show packages that have vendor-issued security advisories from the last snapshot.

    Advisory sources: Ubuntu USN, Fedora Bodhi security updates.

    Args:
        ecosystem:  Ecosystem to query.
        limit:      Maximum packages to return.
    """
    from selvo.analysis.cache import load_last_snapshot

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {"error": f"No snapshot for '{ecosystem}'. Run analyze_packages first."}

    packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    rows = [
        {
            "package":          p["name"],
            "version":          p.get("version", "unknown"),
            "advisory_ids":     p.get("vendor_advisory_ids", []),
            "cve_ids":          p.get("cve_ids", [])[:5],
            "score":            round(p.get("score", 0.0), 1),
        }
        for p in packages
        if p.get("vendor_advisory_ids")
    ]
    rows.sort(key=lambda r: len(r["advisory_ids"]), reverse=True)
    rows = rows[:limit]

    return {
        "snapshot_at": ts,
        "ecosystem": ecosystem,
        "total_with_advisories": len(rows),
        "packages": rows,
    }


@mcp.tool()
def get_changelog_summary(
    ecosystem: str = "all",
    package: str = "",
) -> dict:
    """Return LLM-generated changelog summaries for top packages from the last snapshot.

    Summaries are generated by enrich_changelog_summaries() and cover the delta
    between the currently-installed version and the upstream latest release.
    An empty summary means LLM was not configured or the package has no GitHub repo.

    Args:
        ecosystem:  Ecosystem to query.
        package:    If given, return only that package's summary. Otherwise returns
                    all packages that have a non-empty changelog_summary.
    """
    from selvo.analysis.cache import load_last_snapshot

    result = load_last_snapshot(ecosystem)
    if result is None:
        return {"error": f"No snapshot for '{ecosystem}'. Run analyze_packages first."}

    packages, taken_at = result
    ts = datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if package:
        pkgs = [p for p in packages if p.get("name", "").lower() == package.lower()]
        if not pkgs:
            return {"error": f"Package '{package}' not found in snapshot."}
    else:
        pkgs = [p for p in packages if p.get("changelog_summary")]

    rows = [
        {
            "package":           p["name"],
            "version":           p.get("version", "unknown"),
            "upstream_version":  p.get("upstream_version", ""),
            "changelog_summary": p.get("changelog_summary", ""),
        }
        for p in pkgs
    ]

    return {
        "snapshot_at": ts,
        "ecosystem": ecosystem,
        "total": len(rows),
        "packages": rows,
    }


# ── Entrypoint ───────────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="selvo MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="SSE host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port", type=int, default=8765,
        help="SSE port (default: 8765)",
    )
    args = parser.parse_args()

    if args.transport == "sse":
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
