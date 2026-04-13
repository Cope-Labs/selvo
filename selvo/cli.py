# Copyright (c) 2026 Seth Holloway. All rights reserved.
# SPDX-License-Identifier: Elastic-2.0
"""CLI entrypoint for selvo."""
from __future__ import annotations

import asyncio
from enum import Enum
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

app = typer.Typer(
    name="selvo",
    help="Map core Linux dependencies and surface highest-value update opportunities.",
    add_completion=False,
)
console = Console()


class Ecosystem(str, Enum):
    debian = "debian"
    ubuntu = "ubuntu"
    fedora = "fedora"
    arch = "arch"
    alpine = "alpine"
    nixos = "nixos"
    winget = "winget"
    homebrew = "homebrew"
    chocolatey = "chocolatey"
    all = "all"
    all_endpoints = "all-endpoints"


class OutputFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    markdown = "markdown"
    html = "html"
    sbom = "sbom"
    vex = "vex"
    sarif = "sarif"


class ContextMode(str, Enum):
    """Controls where installed package versions come from."""
    auto = "auto"           # Try local package manager; fall back to reference data
    local = "local"         # Use locally-installed versions (dpkg/rpm/pacman/apk)
    reference = "reference"  # Use Debian stable Packages.gz + Repology (CI default)


@app.command()
def discover(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem", help="Package ecosystem to scrape."),
    limit: int = typer.Option(100, "-n", "--limit", help="Number of top packages to consider."),
    output: OutputFormat = typer.Option(OutputFormat.terminal, "-o", "--output", help="Output format."),
    out_file: Optional[str] = typer.Option(None, "-f", "--file", help="Write output to file."),
) -> None:
    """Discover the most-used core packages in the chosen ecosystem(s)."""
    from selvo.discovery import run_discovery
    from selvo.reporters import render

    console.print(f"[bold cyan]selvo[/] discovering top [yellow]{limit}[/] packages for [green]{ecosystem.value}[/]…")
    results = asyncio.run(run_discovery(ecosystem.value, limit))
    render(results, fmt=output.value, out_file=out_file, console=console)


@app.command()
def graph(
    packages: list[str] = typer.Argument(..., help="Package name(s) to graph."),
    ecosystem: Ecosystem = typer.Option(Ecosystem.debian, "-e", "--ecosystem"),
    depth: int = typer.Option(3, "-d", "--depth", help="Dependency depth to traverse."),
) -> None:
    """Build and display the dependency graph for one or more packages."""
    from selvo.graph.builder import build_graph
    from selvo.reporters.terminal import print_graph

    console.print(f"[bold cyan]selvo[/] building dependency graph (depth={depth})…")
    g = asyncio.run(build_graph(packages, ecosystem=ecosystem.value, depth=depth))
    print_graph(g, console=console)


@app.command()
def analyze(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    limit: int = typer.Option(50, "-n", "--limit"),
    cve: bool = typer.Option(True, "--cve/--no-cve", help="Include CVE exposure in scoring."),
    output: OutputFormat = typer.Option(OutputFormat.terminal, "-o", "--output"),
    out_file: Optional[str] = typer.Option(None, "-f", "--file"),
    llm: bool = typer.Option(False, "--llm/--no-llm", help="Use LLM to normalize cross-ecosystem package names."),
    scorecard: bool = typer.Option(False, "--scorecard/--no-scorecard", help="Enrich results with OpenSSF Scorecard maintainer health scores."),
    runtime_scan: bool = typer.Option(False, "--runtime/--no-runtime", help="Cross-reference results with /proc/*/maps to show which packages are loaded in running processes (Linux only, root recommended)."),
    context: ContextMode = typer.Option(
        ContextMode.auto,
        "-C", "--context",
        help=(
            "Version data source. "
            "'reference': Debian stable Packages.gz + Repology (best for CI/publishing). "
            "'local': installed package manager on THIS machine (dpkg/rpm/pacman/apk). "
            "'auto': try local first, fall back to reference silently."
        ),
    ),
) -> None:
    """Analyze packages, score update value, and rank highest-impact opportunities."""
    from selvo.discovery import run_discovery
    from selvo.analysis.versions import enrich_versions
    from selvo.analysis.cve import enrich_cve
    from selvo.analysis.epss import enrich_epss
    from selvo.analysis.cvss import enrich_cvss
    from selvo.analysis.distro_status import filter_resolved_cves
    from selvo.analysis.rdeps import enrich_reverse_deps
    from selvo.analysis.graph_metrics import enrich_graph_metrics
    from selvo.analysis.upstream import enrich_upstream_repos
    from selvo.prioritizer.scorer import score_and_rank
    from selvo.reporters import render
    from selvo.analysis.local_context import detect_system_context, read_local_versions

    console.print("[bold cyan]selvo[/] running full analysis…")

    # ── Build system context (synchronous, cheap) ────────────────────────────
    sys_ctx = detect_system_context(mode=context.value)
    local_versions: dict[str, str] = {}

    if context in (ContextMode.local, ContextMode.auto):
        console.print("  [dim]Reading locally-installed package versions…[/]")
        local_versions = read_local_versions(sys_ctx)
        if local_versions:
            sys_ctx.mode = "local"
            console.print(
                f"  [dim]Local context: {len(local_versions):,} packages via "
                f"[bold]{sys_ctx.package_manager}[/dim][dim] on "
                f"{sys_ctx.os_name} {sys_ctx.os_version}[/]"
            )
        elif context == ContextMode.local:
            console.print("[bold red]✗[/] --context local: no supported package manager found "
                          "(expected dpkg, rpm, pacman, or apk).")
            raise typer.Exit(code=1)
        else:  # auto — fell back silently
            sys_ctx.mode = "reference"
            console.print("  [dim]No local package manager found; using reference (Packages.gz/Repology)[/]")
    else:
        # --context reference: always skip local inspection
        sys_ctx.mode = "reference"

    async def _run() -> list:
        packages = await run_discovery(ecosystem.value, limit, llm_normalize=llm)
        if llm:
            console.print("  [dim]LLM: cross-ecosystem name normalization active[/]")

        packages = await enrich_versions(packages)

        # Override with locally-installed versions where available
        if local_versions:
            for pkg in packages:
                v = local_versions.get(pkg.name)
                if v:
                    pkg.version = v
                    pkg.version_source = "local"
        if cve:
            packages = await enrich_cve(packages)
            console.print("  [dim]Filtering CVEs already resolved in distro…[/]")
            packages = await filter_resolved_cves(packages)
            console.print("  [dim]Fetching EPSS exploitation-probability scores…[/]")
            packages = await enrich_epss(packages)
            # Compute EPSS velocity against previous snapshot
            from selvo.analysis.cache import load_last_snapshot
            prev_result = load_last_snapshot(ecosystem.value)
            prev_snap: list[dict] = prev_result[0] if prev_result else []
            from selvo.analysis.epss import enrich_epss_velocity
            packages = enrich_epss_velocity(packages, prev_snap)
            console.print("  [dim]Fetching CVSS severity scores (NVD)…[/]")
            packages = await enrich_cvss(packages, console=console)
        console.print("  [dim]Fetching real reverse-dependency counts…[/]")
        packages = await enrich_reverse_deps(packages)
        # Collapse co-source binary packages into one source-named record so
        # siblings (libuuid1 + libblkid1 + mount + …  →  util-linux) don't
        # each occupy a row with identical CVEs.  Must run before graph metrics
        # so the BFS starts from ALL binaries of the source simultaneously.
        console.print("  [dim]Collapsing source-duplicate packages…[/]")
        from selvo.analysis.collapse import collapse_by_source
        from selvo.analysis.debian_index import load_debian_index
        deb_idx = await load_debian_index()
        packages = collapse_by_source(packages, deb_idx)
        # Inject description + homepage from Packages.gz for packages that lack them
        for _pkg in packages:
            if not _pkg.description:
                for _bin in [_pkg.name] + deb_idx.s2b.get(_pkg.name, []):
                    if _bin in deb_idx.descriptions:
                        _pkg.description = deb_idx.descriptions[_bin]
                        break
            if not _pkg.homepage:
                for _bin in [_pkg.name] + deb_idx.s2b.get(_pkg.name, []):
                    if _bin in deb_idx.homepages:
                        _pkg.homepage = deb_idx.homepages[_bin]
                        break
        console.print("  [dim]Building dep graph & computing transitive blast-radius…[/]")
        packages = await enrich_graph_metrics(packages)
        packages = await enrich_upstream_repos(packages)
        console.print("  [dim]Fetching per-distro versions & supply-chain lag…[/]")
        from selvo.analysis.distro_compare import enrich_distro_versions
        packages = await enrich_distro_versions(packages)
        if cve:
            console.print("  [dim]Fetching CVE disclosure dates (exposure window)…[/]")
            from selvo.analysis.cve_timeline import enrich_cve_timeline
            packages = await enrich_cve_timeline(packages)
            console.print("  [dim]Checking exploit availability (CISA KEV + PoC-in-GitHub + Nuclei)…[/]")
            from selvo.analysis.exploit import enrich_exploits
            packages = await enrich_exploits(packages)
            console.print("  [dim]Fetching real distro patch dates (Ubuntu / RHEL / Debian)…[/]")
            from selvo.analysis.distro_tracker import enrich_distro_patch_dates
            packages = await enrich_distro_patch_dates(packages)
        from selvo.analysis.patch_safety import enrich_patch_safety
        packages = enrich_patch_safety(packages)
        console.print("  [dim]Checking OSS-Fuzz coverage…[/]")
        from selvo.analysis.ossfuzz import enrich_ossfuzz
        packages = await enrich_ossfuzz(packages)
        console.print("  [dim]Fetching vendor advisories (Ubuntu USN, Fedora Bodhi)…[/]")
        from selvo.analysis.advisories import enrich_advisories
        packages = await enrich_advisories(packages)
        from selvo.analysis.sla import enrich_sla
        packages = enrich_sla(packages)
        ranked = score_and_rank(packages)
        console.print("  [dim]Summarising changelogs for top packages…[/]")
        from selvo.analysis.changelog import enrich_changelog_summaries
        ranked = await enrich_changelog_summaries(ranked, top_n=5)
        return ranked

    ranked = asyncio.run(_run())
    if scorecard:
        console.print("  [dim]Fetching OpenSSF Scorecard maintainer health scores…[/]")
        from selvo.analysis.scorecard import enrich_scorecard as _enrich_sc
        ranked = asyncio.run(_enrich_sc(ranked))
    if runtime_scan:
        import os as _os
        if _os.path.exists("/proc"):
            console.print("  [dim]Scanning /proc/*/maps for runtime-loaded libraries…[/]")
            from selvo.analysis.runtime import enrich_runtime
            ranked, _runtime_hits = enrich_runtime(ranked)
            runtime_loaded = sum(1 for p in ranked if p.runtime_loaded and p.cve_ids)
            if runtime_loaded:
                console.print(f"  [bold yellow]⚡ {runtime_loaded} CVE-affected package(s) loaded in running processes[/] — run [cyan]selvo runtime[/] for details")
            else:
                console.print("  [dim]Runtime scan: no CVE-affected packages found in running processes[/]")
        else:
            console.print("  [yellow]--runtime skipped: /proc not available (Linux only)[/]")
    from selvo.analysis.cache import save_snapshot
    from selvo.analysis.trend import record_metric, load_metrics
    save_snapshot(ecosystem.value, ranked)
    record_metric(ecosystem.value, ranked)
    trend_data = load_metrics(ecosystem.value, days=90)
    render(ranked, fmt=output.value, out_file=out_file, console=console, ctx=sys_ctx,
           trend_metrics=trend_data if output.value == "html" else None)


@app.command()
def patch(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    limit: int = typer.Option(50, "-n", "--limit"),
    output: OutputFormat = typer.Option(OutputFormat.terminal, "-o", "--output"),
    out_file: Optional[str] = typer.Option(None, "-f", "--file"),
    min_score: float = typer.Option(0.0, "--min-score", help="Only show opportunities above this score."),
    llm: bool = typer.Option(False, "--llm/--no-llm", help="Use LLM to classify ambiguous fix refs and generate PR descriptions."),
    github: bool = typer.Option(False, "--github/--no-github", help="Check GitHub for existing PRs covering each CVE (requires GITHUB_TOKEN in .env)."),
    backport: bool = typer.Option(False, "--backport/--no-backport", help="Auto-draft backport instructions for top opportunities using LLM + upstream commit diffs (requires --llm)."),
    scorecard: bool = typer.Option(False, "--scorecard/--no-scorecard", help="Enrich opportunities with OpenSSF Scorecard maintainer health scores."),
) -> None:
    """
    Surface actionable upstream PR/patch opportunities.

    Walks the CVE chain for each package, extracts fix commits and PR
    references from OSV advisories, resolves upstream repos, and ranks
    opportunities by downstream blast radius + CVE severity.
    """
    from selvo.discovery import run_discovery
    from selvo.analysis.versions import enrich_versions
    from selvo.analysis.cve import enrich_cve
    from selvo.analysis.epss import enrich_epss
    from selvo.analysis.cvss import enrich_cvss
    from selvo.analysis.distro_status import filter_resolved_cves
    from selvo.analysis.rdeps import enrich_reverse_deps
    from selvo.analysis.graph_metrics import enrich_graph_metrics
    from selvo.analysis.upstream import enrich_upstream_repos
    from selvo.analysis.patch import enrich_fix_refs, build_pr_opportunities, enrich_backport_drafts
    from selvo.analysis.github import enrich_existing_prs
    from selvo.reporters.terminal import render_pr_opportunities

    console.print("[bold cyan]selvo[/] scanning for PR-able upstream fixes…")

    async def _run():
        packages = await run_discovery(ecosystem.value, limit, llm_normalize=llm)
        packages = await enrich_versions(packages)
        packages = await enrich_cve(packages)
        console.print("  [dim]Filtering CVEs already resolved in distro…[/]")
        packages = await filter_resolved_cves(packages)
        console.print("  [dim]Fetching EPSS exploitation-probability scores…[/]")
        packages = await enrich_epss(packages)
        console.print("  [dim]Fetching CVSS severity scores (NVD)…[/]")
        packages = await enrich_cvss(packages, console=console)
        console.print("  [dim]Fetching real reverse-dependency counts…[/]")
        packages = await enrich_reverse_deps(packages)
        console.print("  [dim]Collapsing source-duplicate packages…[/]")
        from selvo.analysis.collapse import collapse_by_source
        from selvo.analysis.debian_index import load_debian_index
        deb_idx = await load_debian_index()
        packages = collapse_by_source(packages, deb_idx)
        for _pkg in packages:
            if not _pkg.description:
                for _bin in [_pkg.name] + deb_idx.s2b.get(_pkg.name, []):
                    if _bin in deb_idx.descriptions:
                        _pkg.description = deb_idx.descriptions[_bin]
                        break
            if not _pkg.homepage:
                for _bin in [_pkg.name] + deb_idx.s2b.get(_pkg.name, []):
                    if _bin in deb_idx.homepages:
                        _pkg.homepage = deb_idx.homepages[_bin]
                        break
        console.print("  [dim]Building dep graph & computing transitive blast-radius…[/]")
        packages = await enrich_graph_metrics(packages)
        packages = await enrich_upstream_repos(packages)
        packages = await enrich_fix_refs(packages, use_llm=llm)
        opps = build_pr_opportunities(packages)
        if github:
            console.print("  [dim]Checking GitHub for existing PRs…[/]")
            opps = await enrich_existing_prs(opps)
        return opps

    opportunities = asyncio.run(_run())

    # LLM: generate PR descriptions for top opportunities (open only)
    if llm and opportunities:
        from selvo.analysis.llm import get_client
        client = get_client()
        if client.enabled:
            console.print("  [dim]LLM: generating PR descriptions for top opportunities…[/]")

            async def _gen_descriptions():
                import asyncio as _asyncio
                # Only generate for top 5 to keep costs minimal
                tasks = [
                    client.generate_pr_description(
                        package=o.package,
                        ecosystem=o.ecosystem,
                        current_version="unknown",
                        upstream_version="latest",
                        cve_ids=o.affected_cves,
                        fix_urls=[r.url for r in o.fix_refs if r.ref_type == "FIX"][:3],
                        downstream_count=o.downstream_count,
                    )
                    for o in opportunities[:5]
                ]
                return await _asyncio.gather(*tasks)

            descriptions = asyncio.run(_gen_descriptions())
            for opp, desc in zip(opportunities[:5], descriptions):
                if desc:
                    opp._pr_description = desc  # type: ignore[attr-defined]

    # Backport drafts: fetch upstream commit diffs + LLM-generated backport instructions
    if backport and llm and opportunities:
        console.print("  [dim]LLM: fetching commit diffs and drafting backport instructions…[/]")
        opportunities = asyncio.run(enrich_backport_drafts(opportunities, top_n=5))

    opportunities = [o for o in opportunities if o.score >= min_score]

    if scorecard and opportunities:
        from selvo.analysis.scorecard import enrich_scorecard_opportunities
        console.print("  [dim]Fetching OpenSSF Scorecard maintainer health scores…[/]")
        opportunities = asyncio.run(enrich_scorecard_opportunities(opportunities))

    if output.value == "json":
        import json
        import dataclasses
        data = [dataclasses.asdict(o) for o in opportunities]
        out = json.dumps(data, indent=2)
        if out_file:
            open(out_file, "w").write(out)
            console.print(f"[green]Written to {out_file}[/]")
        else:
            console.print(out)
    elif output.value == "markdown":
        from selvo.reporters.markdown import render_pr_opportunities_md
        out = render_pr_opportunities_md(opportunities)
        if out_file:
            open(out_file, "w").write(out)
            console.print(f"[green]Written to {out_file}[/]")
        else:
            console.print(out)
    else:
        render_pr_opportunities(opportunities, console=console)


@app.command(name="cache")
def cache_cmd(
    action: str = typer.Argument("stats", help="Action: stats | prune | clear"),
    ttl: int = typer.Option(0, "--ttl", help="Unused (reserved for future per-TTL pruning). prune always removes expired entries."),
) -> None:
    """Inspect or manage the selvo SQLite cache.

    Actions:
        stats   Show cache size, entry count, and path.
        prune   Remove expired entries from the cache.
        clear   Wipe ALL cache entries (use with caution).
    """
    from selvo.analysis import cache as _cache
    if action == "stats":
        stats = _cache.stats()
        console.print(Panel(
            f"[bold]Path:[/]  {stats['path']}\n"
            f"[bold]Live entries:[/]  {stats['live']} / {stats['total']} total\n"
            f"[bold]Expired:[/]  {stats['expired']}\n"
            f"[bold]Size:[/]  {stats['size_kb']:.1f} KB",
            title="selvo cache stats",
            expand=False,
        ))
    elif action == "prune":
        pruned = _cache.prune()
        from selvo.analysis.trend import prune_metrics as _prune_metrics
        pruned_metrics = _prune_metrics(max_age_days=90)
        console.print(
            f"[green]Pruned {pruned} expired cache entries "
            f"and {pruned_metrics} trend metric row(s) older than 90 days.[/]"
        )
    elif action == "clear":
        typer.confirm("This will delete ALL cached data. Are you sure?", abort=True)
        _cache.clear()
        console.print("[green]Cache cleared.[/]")
    else:
        console.print(f"[red]Unknown action: {action!r}. Use stats, prune, or clear.[/]")
        raise typer.Exit(1)


@app.command()
def diff(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    limit: int = typer.Option(50, "-n", "--limit"),
    llm: bool = typer.Option(False, "--llm/--no-llm"),
) -> None:
    """Show what changed since the last snapshot (trend tracking).

    Runs a fresh analysis, loads the previous snapshot from the cache,
    and renders a diff showing new CVEs, EPSS spikes, score changes,
    newly discovered packages, and resolved issues.
    """
    from selvo.discovery import run_discovery
    from selvo.analysis.versions import enrich_versions
    from selvo.analysis.cve import enrich_cve
    from selvo.analysis.epss import enrich_epss
    from selvo.analysis.cvss import enrich_cvss
    from selvo.analysis.distro_status import filter_resolved_cves
    from selvo.analysis.rdeps import enrich_reverse_deps
    from selvo.analysis.upstream import enrich_upstream_repos
    from selvo.prioritizer.scorer import score_and_rank
    from selvo.analysis.cache import load_last_snapshot, save_snapshot, diff_snapshots
    from selvo.reporters.terminal import render_diff

    console.print("[bold cyan]selvo[/] computing diff from last snapshot…")

    # Load previous snapshot before running so timestamps are accurate
    prev_records, prev_ts = load_last_snapshot(ecosystem.value)

    async def _run() -> list:
        packages = await run_discovery(ecosystem.value, limit, llm_normalize=llm)
        packages = await enrich_versions(packages)
        packages = await enrich_cve(packages)
        packages = await filter_resolved_cves(packages)
        packages = await enrich_epss(packages)
        packages = await enrich_cvss(packages, console=console)
        packages = await enrich_reverse_deps(packages)
        packages = await enrich_upstream_repos(packages)
        return score_and_rank(packages)

    ranked = asyncio.run(_run())
    save_snapshot(ecosystem.value, ranked)

    if not prev_records:
        console.print("[yellow]No previous snapshot found — saving this run as baseline.[/]")
        return

    delta = diff_snapshots(prev_records, ranked)
    render_diff(delta, prev_ts, console=console)


@app.command(name="distro-compare")
def distro_compare(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    limit: int = typer.Option(30, "-n", "--limit"),
    output: OutputFormat = typer.Option(OutputFormat.terminal, "-o", "--output"),
    out_file: Optional[str] = typer.Option(None, "-f", "--file"),
) -> None:
    """Compare package versions across distros and show supply-chain lag.

    Shows which distros are behind upstream for each package, and an
    estimated lag in days based on version-gap magnitude.
    """
    from selvo.discovery import run_discovery
    from selvo.analysis.versions import enrich_versions
    from selvo.analysis.distro_compare import enrich_distro_versions, distro_comparison_table, TRACKED_DISTROS
    import json

    console.print("[bold cyan]selvo[/] comparing versions across distros…")

    async def _run():
        packages = await run_discovery(ecosystem.value, limit)
        packages = await enrich_versions(packages)
        packages = await enrich_distro_versions(packages)
        return packages

    packages = asyncio.run(_run())
    table = distro_comparison_table(packages)

    if output.value == "json":
        out = json.dumps(table, indent=2)
        if out_file:
            open(out_file, "w").write(out)
            console.print(f"[green]Written to {out_file}[/]")
        else:
            console.print(out)
        return

    from rich.table import Table
    distro_labels = list(TRACKED_DISTROS.values())
    tbl = Table(title="selvo — Distro Version Comparison", show_lines=False)
    tbl.add_column("Package", style="cyan", no_wrap=True)
    tbl.add_column("Upstream", style="bold white")
    for label in distro_labels:
        tbl.add_column(label[:12], justify="center")
    tbl.add_column("Lag (days)", justify="right", style="yellow")

    for row in table[:limit]:
        upstream = row["upstream_version"] or "?"
        distro_cells: list[str] = []
        for label in distro_labels:
            v = row["distros"].get(label)
            if v is None:
                distro_cells.append("[dim]–[/]")
            elif v == upstream:
                distro_cells.append(f"[green]{v}[/]")
            else:
                distro_cells.append(f"[red]{v}[/]")
        lag = row["max_lag_days"]
        lag_str = f"{lag:,}" if lag > 0 else "–"
        tbl.add_row(row["name"], upstream, *distro_cells, lag_str)

    console.print(tbl)
    if out_file:
        console.save_text(out_file)
        console.print(f"[green]Written to {out_file}[/]")


@app.command(name="fleet")
def fleet_cmd(
    machines: Optional[str] = typer.Option(
        None, "-m", "--machines",
        help="Comma-separated list of hostnames to scan (e.g. web01,web02,db01)"
    ),
    fleet_file: Optional[str] = typer.Option(
        None, "-f", "--fleet-file",
        help="YAML/JSON fleet spec file (overrides --machines)"
    ),
    user: Optional[str] = typer.Option(None, "-u", "--user", help="SSH user for all hosts"),
    ecosystem: Ecosystem = typer.Option(Ecosystem.debian, "-e", "--ecosystem"),
    limit: int = typer.Option(50, "-n", "--limit"),
    output: OutputFormat = typer.Option(OutputFormat.terminal, "-o", "--output"),
    out_file: Optional[str] = typer.Option(None, "--out-file"),
    dry_run: bool = typer.Option(
        False, "--dry-run",
        help="Validate SSH connectivity and print what would be run — no packages collected.",
    ),
    runtime: bool = typer.Option(
        False, "--runtime",
        help="Also scan /proc/*/maps on each host to identify CVE-affected libraries actually loaded in memory.",
    ),
) -> None:
    """Scan a fleet of machines and rank CVE risk fleet-wide.

    Collects installed package versions from each machine via SSH (or local),
    merges them into a conservative (worst-case) view, then runs the full
    selvo CVE + blast-radius pipeline against the fleet.

    Examples:
        selvo fleet --machines web01,web02,db01
        selvo fleet --fleet-file fleet.yaml
        selvo fleet --machines localhost --user root
        selvo fleet --machines web01,web02 --dry-run
    """
    from selvo.analysis.fleet import scan_fleet, specs_from_dict, MachineSpec, dry_run_fleet
    from selvo.discovery import run_discovery
    from selvo.analysis.versions import enrich_versions
    from selvo.analysis.cve import enrich_cve
    from selvo.analysis.epss import enrich_epss
    from selvo.analysis.cvss import enrich_cvss
    from selvo.analysis.distro_status import filter_resolved_cves
    from selvo.analysis.rdeps import enrich_reverse_deps
    from selvo.analysis.graph_metrics import enrich_graph_metrics
    from selvo.analysis.upstream import enrich_upstream_repos
    from selvo.analysis.collapse import collapse_by_source
    from selvo.analysis.debian_index import load_debian_index
    from selvo.analysis.patch_safety import enrich_patch_safety
    from selvo.analysis.cve_timeline import enrich_cve_timeline
    from selvo.prioritizer.scorer import score_and_rank
    from selvo.reporters import render
    import json

    if fleet_file:
        try:
            if fleet_file.endswith(".json"):
                raw = json.load(open(fleet_file))
            else:
                try:
                    import yaml  # type: ignore[import]
                    raw = yaml.safe_load(open(fleet_file))
                except ImportError:
                    console.print("[red]PyYAML not installed. Use a JSON fleet file or run: pip install pyyaml[/]")
                    raise typer.Exit(1)
            specs = specs_from_dict(raw.get("machines", raw))
        except Exception as e:
            console.print(f"[red]Failed to load fleet file: {e}[/]")
            raise typer.Exit(1)
        if runtime:
            for s in specs:
                s.runtime = True
    elif machines:
        specs = [
            MachineSpec(host=h.strip(), user=user, method="local" if h.strip() == "localhost" else "ssh", runtime=runtime)
            for h in machines.split(",")
        ]
    else:
        console.print("[red]Provide --machines or --fleet-file.[/]")
        raise typer.Exit(1)

    console.print(f"[bold cyan]selvo fleet[/] scanning [yellow]{len(specs)}[/] machine(s)…")

    if dry_run:
        asyncio.run(dry_run_fleet(specs, console=console))
        raise typer.Exit(0)

    fleet_result = asyncio.run(scan_fleet(specs))

    for m in fleet_result.machines:
        status = f"[green]✓[/] {m.package_count:,} packages via {m.pm}" if not m.error else f"[red]✗[/] {m.error}"
        console.print(f"  {m.host}: {status}")

    total_ok = sum(1 for m in fleet_result.machines if not m.error)
    if total_ok == 0:
        console.print("[red]No machines scanned successfully.[/]")
        raise typer.Exit(1)

    fleet_versions = fleet_result.to_local_versions()
    variance = fleet_result.version_variance()
    if variance:
        console.print(f"  [yellow]{len(variance)} package(s) with version drift across machines[/]")

    console.print("[bold cyan]selvo fleet[/] running CVE + blast-radius analysis…")

    async def _run():
        packages = await run_discovery(ecosystem.value, limit)
        packages = await enrich_versions(packages)
        for pkg in packages:
            v = fleet_versions.get(pkg.name)
            if v:
                pkg.version = v
                pkg.version_source = "fleet"
        packages = await enrich_cve(packages)
        packages = await filter_resolved_cves(packages)
        packages = await enrich_epss(packages)
        packages = await enrich_cvss(packages, console=console)
        packages = await enrich_reverse_deps(packages)
        deb_idx = await load_debian_index()
        packages = collapse_by_source(packages, deb_idx)
        packages = await enrich_graph_metrics(packages)
        packages = await enrich_upstream_repos(packages)
        packages = await enrich_cve_timeline(packages)
        packages = enrich_patch_safety(packages)
        from selvo.analysis.scorecard import enrich_scorecard as _enrich_sc
        packages = await _enrich_sc(packages)
        return score_and_rank(packages)

    ranked = asyncio.run(_run())
    render(ranked, fmt=output.value, out_file=out_file, console=console)

    # Runtime reachability — show which CVE-affected packages are live in memory
    if runtime:
        runtime_cov = fleet_result.runtime_coverage()
        if not runtime_cov:
            console.print(
                "\n[yellow]⚠[/] Runtime scan returned no data. "
                "Ensure hosts are running a Debian/Ubuntu system with dpkg available."
            )
        else:
            # Cross-reference loaded packages against ranked CVE packages
            name_to_pkg = {p.name.lower(): p for p in ranked}
            cve_loaded = {
                pkg_name: hosts
                for pkg_name, hosts in runtime_cov.items()
                if name_to_pkg.get(pkg_name.lower()) and name_to_pkg[pkg_name.lower()].cve_ids
            }
            if cve_loaded:
                console.print(
                    f"\n[bold red]Runtime reachability — "
                    f"{len(cve_loaded)} CVE-affected package(s) loaded in memory:[/]"
                )
                # Sort by host count descending (widest blast radius first)
                for pkg_name, hosts in sorted(cve_loaded.items(), key=lambda x: -len(x[1]))[:15]:
                    p = name_to_pkg[pkg_name.lower()]
                    kev_tag = " [bold red][KEV][/]" if p.in_cisa_kev else ""
                    host_list = ", ".join(hosts[:5]) + (f" +{len(hosts)-5} more" if len(hosts) > 5 else "")
                    console.print(
                        f"  [yellow]{p.name}[/]  CVSS {p.max_cvss:.1f}  "
                        f"EPSS {p.max_epss*100:.1f}%{kev_tag}  "
                        f"loaded on {len(hosts)}/{len(specs)} host(s): [dim]{host_list}[/]"
                    )
            else:
                console.print(
                    f"\n[green]✓[/] Runtime scan: none of the {len(runtime_cov)} loaded packages "
                    "have open CVEs in the current analysis."
                )


# ── selvo watch ──────────────────────────────────────────────────────────────

watch_app = typer.Typer(name="watch", help="Continuous monitoring with webhook alerts.", add_completion=False)
app.add_typer(watch_app, name="watch")


@watch_app.command("add")
def watch_add(
    id: str = typer.Option(..., "--id", help="Unique ID for this watch (e.g. prod-debian)."),
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    limit: int = typer.Option(50, "-n", "--limit"),
    interval: float = typer.Option(6.0, "--interval", help="Polling interval in hours."),
    webhook: str = typer.Option("", "--webhook", help="Webhook URL (Slack-compatible)."),
    alert_on: str = typer.Option(
        "new_cve,epss_jump,exploit_available,kev_listed",
        "--alert-on",
        help="Comma-separated alert types: new_cve,epss_jump,exploit_available,kev_listed,score_change",
    ),
    min_epss_jump: float = typer.Option(0.10, "--min-epss-jump", help="Minimum EPSS delta to alert."),
) -> None:
    """Add or update a watch configuration."""
    from selvo.analysis.watcher import WatchConfig, add_watch

    watch = WatchConfig(
        id=id,
        ecosystem=ecosystem.value,
        limit=limit,
        interval_hours=interval,
        webhook_url=webhook,
        alert_on=[a.strip() for a in alert_on.split(",") if a.strip()],
        min_epss_jump=min_epss_jump,
    )
    add_watch(watch)
    console.print(f"[green]✓[/] Watch [bold]{id}[/] saved (ecosystem={ecosystem.value}, interval={interval}h).")
    if not webhook:
        console.print("[yellow]⚠[/] No --webhook set — alerts will be logged only. Add with --webhook <URL>.")


@watch_app.command("remove")
def watch_remove(id: str = typer.Argument(..., help="Watch ID to remove.")) -> None:
    """Remove a watch by ID."""
    from selvo.analysis.watcher import remove_watch
    if remove_watch(id):
        console.print(f"[green]✓[/] Watch [bold]{id}[/] removed.")
    else:
        console.print(f"[red]✗[/] Watch [bold]{id}[/] not found.")
        raise typer.Exit(1)


@watch_app.command("list")
def watch_list() -> None:
    """List all configured watches."""
    from selvo.analysis.watcher import load_watches, watcher_is_running
    from rich.table import Table

    watches = load_watches()
    running = watcher_is_running()

    if not watches:
        console.print("[yellow]No watches configured. Use: selvo watch add --id <id>[/]")
        return

    table = Table(title="selvo watches", show_header=True)
    table.add_column("ID", style="bold cyan")
    table.add_column("Ecosystem")
    table.add_column("Interval")
    table.add_column("Alert on")
    table.add_column("Webhook")

    for w in watches:
        table.add_row(
            w.id,
            w.ecosystem,
            f"{w.interval_hours}h",
            ",".join(w.alert_on),
            (w.webhook_url[:40] + "…") if len(w.webhook_url) > 40 else w.webhook_url or "[dim]none[/]",
        )

    console.print(table)
    status_str = "[green]running[/]" if running else "[dim]stopped[/]"
    console.print(f"Daemon status: {status_str}  •  Run [bold]selvo watch start[/] to activate.")


@watch_app.command("start")
def watch_start(
    background: bool = typer.Option(True, "--background/--foreground", help="Run as background daemon."),
) -> None:
    """Start the watcher daemon."""
    from selvo.analysis.watcher import load_watches, watcher_is_running, run_watcher

    if watcher_is_running():
        console.print("[yellow]Watcher is already running.[/]")
        return

    watches = load_watches()
    if not watches:
        console.print("[red]No watches configured. Add one with: selvo watch add --id <id>[/]")
        raise typer.Exit(1)

    if background:
        import subprocess
        import sys
        proc = subprocess.Popen(
            [sys.executable, "-m", "selvo", "watch", "start", "--no-background"],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        console.print(f"[green]✓[/] Watcher daemon started (PID {proc.pid}).")
    else:
        console.print(f"[bold cyan]selvo watch[/] starting daemon with [yellow]{len(watches)}[/] watch(es)…")
        asyncio.run(run_watcher(watches))


@watch_app.command("stop")
def watch_stop() -> None:
    """Stop the watcher daemon."""
    from selvo.analysis.watcher import stop_watcher, watcher_is_running

    if not watcher_is_running():
        console.print("[yellow]Watcher is not running.[/]")
        return
    if stop_watcher():
        console.print("[green]✓[/] Watcher stopped.")
    else:
        console.print("[red]✗[/] Failed to stop watcher.")
        raise typer.Exit(1)


@watch_app.command("status")
def watch_status() -> None:
    """Show watcher daemon status."""
    from selvo.analysis.watcher import watcher_is_running, load_watches, _PID_FILE

    running = watcher_is_running()
    watches = load_watches()

    if running:
        pid = _PID_FILE.read_text().strip() if _PID_FILE.exists() else "?"
        console.print(f"[green]● Watcher running[/] (PID {pid}) — [yellow]{len(watches)}[/] watch(es) configured.")
    else:
        console.print(f"[dim]○ Watcher stopped[/] — [yellow]{len(watches)}[/] watch(es) configured.")
        if watches:
            console.print("  Run [bold]selvo watch start[/] to activate.")


# ── selvo sla ───────────────────────────────────────────────────────────────

@app.command()
def sla(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    critical_days: int = typer.Option(7, "--critical-days", help="SLA days for critical CVEs."),
    high_days: int = typer.Option(30, "--high-days", help="SLA days for high CVEs."),
    medium_days: int = typer.Option(60, "--medium-days", help="SLA days for medium CVEs."),
    low_days: int = typer.Option(90, "--low-days", help="SLA days for low CVEs."),
    fmt: str = typer.Option("table", "-f", "--format", help="Output format: table | json."),
) -> None:
    """Report SLA breach status for vulnerable packages.

    Classifies each package into an SLA band based on CVSS severity
    and how long the CVE has been open against the configured SLA policy.

    Bands:
      ok       — within SLA window
      warn     — > 50 % of window elapsed
      breach   — SLA exceeded
      critical — KEV-listed or CVSS ≥ 9 and breach > 2× window
    """
    from selvo.analysis.cache import load_last_snapshot
    from selvo.analysis.sla import SLAPolicy, enrich_sla, sla_report
    from rich.table import Table
    import json as _json

    result = load_last_snapshot(ecosystem.value)
    if result is None:
        console.print(f"[red]No snapshot for '{ecosystem.value}'. Run: selvo analyze[/]")
        raise typer.Exit(1)

    raw_packages, _ = result

    # Reconstruct minimal PackageRecord objects from snapshot dicts
    from selvo.discovery.base import PackageRecord
    packages = [
        PackageRecord(
            name=p["name"],
            ecosystem=p.get("ecosystem", ecosystem.value),
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

    policy = SLAPolicy(
        critical=critical_days,
        high=high_days,
        medium=medium_days,
        low=low_days,
    )
    packages = enrich_sla(packages, policy)
    report = sla_report(packages)

    if fmt == "json":
        console.print(_json.dumps(report, indent=2))
        return

    # Table output
    band_color = {"critical": "red", "breach": "bright_red", "warn": "yellow", "ok": "green"}
    table = Table(title="selvo SLA Report", show_header=True)
    table.add_column("Band", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Packages (top 5)")

    for band in ("critical", "breach", "warn", "ok"):
        info = report["bands"].get(band, {})
        count = info.get("count", 0)
        names = ", ".join(info.get("packages", [])[:5])
        color = band_color.get(band, "white")
        table.add_row(f"[{color}]{band}[/{color}]", str(count), names)

    console.print(table)
    if report["breach_count"] > 0:
        console.print(
            f"\n[bold red]⚠ {report['breach_count']} package(s) breaching SLA.[/]  "
            "Run [bold]selvo analyze[/] to refresh."
        )


# ── selvo scan ───────────────────────────────────────────────────────────────

@app.command()
def scan(
    sbom: Optional[str] = typer.Option(None, "--sbom", help="Path to CycloneDX or SPDX SBOM JSON file."),
    grype: Optional[str] = typer.Option(None, "--grype", help="Path to Grype JSON scan output."),
    trivy: Optional[str] = typer.Option(None, "--trivy", help="Path to Trivy JSON scan output."),
    lockfile_path: Optional[str] = typer.Option(None, "--lockfile", help="Path to a lock file (requirements.txt, package-lock.json, Cargo.lock, go.sum, Gemfile.lock, etc.)."),
    image: Optional[str] = typer.Option(None, "--image", help="Docker image to scan (e.g. ubuntu:24.04)."),
    image_tar: Optional[str] = typer.Option(None, "--image-tar", help="Path to Docker image tarball (docker save output)."),
    cve: bool = typer.Option(True, "--cve/--no-cve", help="Include CVE enrichment."),
    reachability: bool = typer.Option(False, "--reachability/--no-reachability", help="Filter CVEs to those reachable from the call graph (Go: requires govulncheck; Python: AST walk)."),
    entrypoint: Optional[str] = typer.Option(None, "--entrypoint", help="Python entrypoint file for AST-based reachability (e.g. src/main.py). Auto-detected if omitted."),
    target_dir: str = typer.Option(".", "--target-dir", help="Project root directory for reachability analysis."),
    scorecard: bool = typer.Option(False, "--scorecard/--no-scorecard", help="Enrich packages with OpenSSF Scorecard maintainer health scores."),
    slsa: bool = typer.Option(False, "--slsa/--no-slsa", help="Verify SLSA provenance attestations via Sigstore Rekor (requires upstream_repo)."),
    output: OutputFormat = typer.Option(OutputFormat.terminal, "-o", "--output"),
    out_file: Optional[str] = typer.Option(None, "-f", "--file"),
) -> None:
    """Scan a SBOM, scanner report, lock file, or container image through the selvo pipeline.

    Input sources (pick one):
      --sbom       CycloneDX 1.4/1.5 or SPDX 2.3 JSON
      --grype      Grype JSON (grype --output json)
      --trivy      Trivy JSON (trivy image/fs --format json)
      --lockfile   requirements.txt, package-lock.json, Cargo.lock, go.sum, Gemfile.lock, …
      --image      Docker image reference (requires Docker daemon)
      --image-tar  Docker image tarball (docker save output; no daemon needed)

    All inputs are fed through the same CVE + EPSS + exploit + scoring
    pipeline as the ecosystem scraper and rendered in the chosen format.
    """
    from selvo.reporters import render

    sources_given = sum(1 for x in [sbom, grype, trivy, lockfile_path, image, image_tar] if x)
    if sources_given == 0:
        console.print("[red]Provide at least one input: --sbom, --grype, --trivy, --image, or --image-tar[/]")
        raise typer.Exit(1)
    if sources_given > 1:
        console.print("[red]Provide only one input source at a time.[/]")
        raise typer.Exit(1)

    # ── Load packages from chosen source ────────────────────────────────────
    if sbom:
        console.print(f"[bold cyan]selvo scan[/] loading SBOM [green]{sbom}[/]…")
        from selvo.discovery.sbom_input import load_sbom
        packages = load_sbom(sbom)

    elif grype:
        console.print(f"[bold cyan]selvo scan[/] loading Grype report [green]{grype}[/]…")
        from selvo.discovery.scanner_import import load_grype
        packages = load_grype(grype)

    elif trivy:
        console.print(f"[bold cyan]selvo scan[/] loading Trivy report [green]{trivy}[/]…")
        from selvo.discovery.scanner_import import load_trivy
        packages = load_trivy(trivy)

    elif lockfile_path:
        console.print(f"[bold cyan]selvo scan[/] loading lock file [green]{lockfile_path}[/]…")
        from selvo.discovery.lockfile import load_lockfile
        packages = load_lockfile(lockfile_path)

    elif image:
        console.print(f"[bold cyan]selvo scan[/] scanning Docker image [green]{image}[/]…")
        from selvo.discovery.container import packages_from_docker_image
        packages = packages_from_docker_image(image)

    else:  # image_tar
        console.print(f"[bold cyan]selvo scan[/] scanning image tarball [green]{image_tar}[/]…")
        from selvo.discovery.container import packages_from_image_tar
        packages = packages_from_image_tar(image_tar)

    console.print(f"  [dim]Loaded {len(packages)} package(s).[/]")

    # ── Run enrichment pipeline ──────────────────────────────────────────────
    async def _run_scan():
        pkgs = packages
        if cve:
            from selvo.analysis.cve import enrich_cve
            from selvo.analysis.distro_status import filter_resolved_cves
            from selvo.analysis.epss import enrich_epss
            from selvo.analysis.cvss import enrich_cvss

            console.print("  [dim]Fetching CVEs…[/]")
            pkgs = await enrich_cve(pkgs)
            pkgs = await filter_resolved_cves(pkgs)
            console.print("  [dim]Fetching EPSS…[/]")
            pkgs = await enrich_epss(pkgs)
            console.print("  [dim]Fetching CVSS…[/]")
            pkgs = await enrich_cvss(pkgs, console=console)
            console.print("  [dim]Checking exploits…[/]")
            from selvo.analysis.exploit import enrich_exploits
            pkgs = await enrich_exploits(pkgs)

        from selvo.analysis.ossfuzz import enrich_ossfuzz
        from selvo.analysis.advisories import enrich_advisories
        from selvo.analysis.sla import enrich_sla
        pkgs = await enrich_ossfuzz(pkgs)
        pkgs = await enrich_advisories(pkgs)
        pkgs = enrich_sla(pkgs)

        from selvo.prioritizer.scorer import score_and_rank
        return score_and_rank(pkgs)

    ranked = asyncio.run(_run_scan())

    if reachability:
        console.print("  [dim]Analysing call-graph reachability…[/]")
        from selvo.analysis.reachability import enrich_reachability, apply_reachability_score_discount
        enrich_reachability(ranked, target_dir=target_dir, entrypoint=entrypoint)
        apply_reachability_score_discount(ranked)
        reachable = sum(1 for p in ranked if p.reachable)
        unreachable_only = sum(1 for p in ranked if p.reachability_source and not p.reachable and p.cve_ids)
        console.print(
            f"  [dim]Reachability: [green]{reachable}[/green] packages with reachable CVEs, "
            f"[yellow]{unreachable_only}[/yellow] packages with CVEs discounted (unreachable).[/dim]"
        )
        from selvo.prioritizer.scorer import score_and_rank
        ranked = score_and_rank(ranked)

    if scorecard:
        console.print("  [dim]Fetching OpenSSF Scorecard scores…[/]")
        from selvo.analysis.scorecard import enrich_scorecard as _enrich_sc
        ranked = asyncio.run(_enrich_sc(ranked))

    if slsa:
        console.print("  [dim]Verifying SLSA attestations via Rekor…[/]")
        from selvo.analysis.slsa import enrich_slsa
        ranked = asyncio.run(enrich_slsa(ranked))
        verified = sum(1 for p in ranked if getattr(p, "slsa_verified", False))
        console.print(
            f"  [dim]SLSA: [green]{verified}[/green]/[yellow]{len(ranked)}[/yellow] "
            f"packages with verified attestations.[/dim]"
        )

    render(ranked, fmt=output.value, out_file=out_file, console=console)


# ── selvo test ──────────────────────────────────────────────────────────────

@app.command()
def test(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    limit: int = typer.Option(50, "-n", "--limit"),
    baseline: Optional[str] = typer.Option(None, "--baseline", "-b",
        help="Path to a baseline JSON file saved by a previous --save-baseline run."),
    save_baseline: Optional[str] = typer.Option(None, "--save-baseline",
        help="Save the current snapshot as a baseline to this path."),
    max_score_increase: float = typer.Option(5.0, "--max-score-increase",
        help="Fail if any package risk score increased by more than this amount."),
    fail_on_new_kev: bool = typer.Option(True, "--fail-on-new-kev/--no-fail-on-new-kev",
        help="Fail if any newly KEV-listed CVEs appear."),
    fail_on_new_weaponized: bool = typer.Option(True,
        "--fail-on-new-weaponized/--no-fail-on-new-weaponized",
        help="Fail if any newly weaponized exploits appear."),
    policy_file: Optional[str] = typer.Option(None, "--policy", "-p",
        help="Path to a selvo.policy.yml file. Auto-discovered if omitted."),
    context: ContextMode = typer.Option(ContextMode.auto, "-C", "--context"),
) -> None:
    """Risk regression gate — fail CI if posture worsened since baseline.

    Workflow:
      1. First run: selvo test --save-baseline baseline.json  (commit this file)
      2. In CI:     selvo test --baseline baseline.json

    Exit codes:
      0  — no regression (safe to merge)
      1  — regression detected (new KEV, weaponized exploit, or score spike)
      2  — error (pipeline failed, baseline unreadable)
    """
    import json as _json
    from selvo.analysis.cache import load_last_snapshot

    # ── Get current snapshot ──────────────────────────────────────────
    # Try the last snapshot first; run pipeline only if there's nothing cached
    cached = load_last_snapshot(ecosystem.value)
    if cached:
        raw_packages, _ = cached
        console.print("  [dim]Using cached snapshot (run selvo analyze to refresh).[/]")
    else:
        console.print("[bold cyan]selvo test[/] no snapshot found — running analysis first…")
        try:
            from selvo.mcp_server import _run_pipeline
            ranked = asyncio.run(_run_pipeline(
                ecosystem=ecosystem.value,
                limit=limit,
                context_mode=context.value,
            ))
            import dataclasses
            raw_packages = [dataclasses.asdict(p) for p in ranked]
        except Exception as exc:
            console.print(f"[red]Error running pipeline: {exc}[/]")
            raise typer.Exit(2)

    current_map: dict[str, dict] = {p["name"]: p for p in raw_packages}

    # ── Save baseline if requested ─────────────────────────────────────
    if save_baseline:
        slim = [
            {
                "name": p["name"],
                "score": p.get("score", 0.0),
                "in_cisa_kev": p.get("in_cisa_kev", False),
                "exploit_maturity": p.get("exploit_maturity", "none"),
                "cve_ids": p.get("cve_ids", []),
                "max_cvss": p.get("max_cvss", 0.0),
                "max_epss": p.get("max_epss", 0.0),
            }
            for p in raw_packages
        ]
        from pathlib import Path
        Path(save_baseline).write_text(_json.dumps(slim, indent=2))
        console.print(f"[green]✓[/] Baseline saved to [bold]{save_baseline}[/] ({len(slim)} packages).")
        return

    # ── Load and compare against baseline ───────────────────────────────
    if not baseline:
        console.print("[yellow]⚠[/] No --baseline provided. Run with [bold]--save-baseline baseline.json[/] first.")
        raise typer.Exit(0)  # not a failure if no baseline yet

    try:
        from pathlib import Path
        baseline_data: list[dict] = _json.loads(Path(baseline).read_text())
    except Exception as exc:
        console.print(f"[red]Error loading baseline '{baseline}': {exc}[/]")
        raise typer.Exit(2)

    baseline_map: dict[str, dict] = {p["name"]: p for p in baseline_data}

    regressions: list[str] = []
    new_kev: list[str] = []
    new_weaponized: list[str] = []
    score_spikes: list[tuple[str, float, float]] = []

    for name, cur in current_map.items():
        prev = baseline_map.get(name)
        cur_kev = cur.get("in_cisa_kev", False)
        cur_wpzn = cur.get("exploit_maturity", "none") == "weaponized"
        cur_score = cur.get("score", 0.0)

        if prev is None:
            # New package — only flag if it's actually risky
            if cur_kev:
                new_kev.append(name)
            if cur_wpzn:
                new_weaponized.append(name)
            continue

        prev_kev = prev.get("in_cisa_kev", False)
        prev_wpzn = prev.get("exploit_maturity", "none") == "weaponized"
        prev_score = prev.get("score", 0.0)

        if cur_kev and not prev_kev:
            new_kev.append(name)
        if cur_wpzn and not prev_wpzn:
            new_weaponized.append(name)
        if cur_score - prev_score > max_score_increase:
            score_spikes.append((name, prev_score, cur_score))

    # ── Report ───────────────────────────────────────────────────────────
    fail = False
    if new_kev and fail_on_new_kev:
        console.print(f"[bold red]✗ New CISA KEV entries:[/] {', '.join(new_kev)}")
        regressions.extend(new_kev)
        fail = True
    elif new_kev:
        console.print(f"[yellow]⚠ New KEV (not blocking):[/] {', '.join(new_kev)}")

    if new_weaponized and fail_on_new_weaponized:
        console.print(f"[bold red]✗ New weaponized exploits:[/] {', '.join(new_weaponized)}")
        regressions.extend(new_weaponized)
        fail = True
    elif new_weaponized:
        console.print(f"[yellow]⚠ New weaponized (not blocking):[/] {', '.join(new_weaponized)}")

    if score_spikes:
        for name, prev_s, cur_s in score_spikes:
            console.print(f"[bold red]✗ Score spike:[/] {name} {prev_s:.1f} → {cur_s:.1f} (+{cur_s-prev_s:.1f})")
        fail = True

    if not fail:
        console.print(
            f"[green]✓ No regressions.[/] "
            f"{len(current_map)} packages vs {len(baseline_map)}-package baseline."
        )

    # ── Policy-as-code evaluation ─────────────────────────────────────────────
    from selvo.analysis.policy import load_policy, enforce, format_result
    policy = load_policy(policy_file)
    if policy:
        from selvo.discovery.base import PackageRecord
        policy_packages = [
            PackageRecord(
                name=p["name"],
                ecosystem=p.get("ecosystem", ecosystem.value),
                version=p.get("version", "unknown"),
                max_cvss=p.get("max_cvss", 0.0),
                max_epss=p.get("max_epss", 0.0),
                cve_ids=p.get("cve_ids", []),
                in_cisa_kev=p.get("in_cisa_kev", False),
                exploit_maturity=p.get("exploit_maturity", "none"),
                score=p.get("score", 0.0),
                sla_band=p.get("sla_band", ""),
                sla_days_overdue=p.get("sla_days_overdue", 0),
            )
            for p in raw_packages
        ]
        result = enforce(policy_packages, policy)
        console.print(format_result(result,
                                    policy_file or "selvo.policy.yml"))
        if not result.passed:
            fail = True

    if not fail:
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# ── selvo api ────────────────────────────────────────────────────────────────

@app.command()
def api(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host."),
    port: int = typer.Option(8765, "--port", help="Bind port."),
    reload: bool = typer.Option(False, "--reload", help="Enable hot-reload (dev only)."),
    log_level: str = typer.Option("info", "--log-level"),
) -> None:
    """Start the selvo REST API server (FastAPI + uvicorn).

    Serves all selvo analysis as REST endpoints at http://HOST:PORT/api/v1/.
    Interactive docs at http://HOST:PORT/docs.

    Requires: pip install 'selvo[api]'
    """
    try:
        from selvo.api.server import create_app
        import uvicorn
    except ImportError:
        console.print("[red]FastAPI/uvicorn not installed. Run: pip install 'selvo[api]'[/]")
        raise typer.Exit(1)

    console.print(
        f"[bold cyan]selvo api[/] starting on [green]http://{host}:{port}[/]  "
        f"— docs: [blue]http://{host}:{port}/docs[/]"
    )
    app_instance = create_app()
    uvicorn.run(app_instance, host=host, port=port, reload=reload, log_level=log_level)


# ── selvo policy ─────────────────────────────────────────────────────────────

policy_app = typer.Typer(name="policy", help="Policy-as-code enforcement.", add_completion=False)
app.add_typer(policy_app)


@policy_app.command("check")
def policy_check(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    policy_file: Optional[str] = typer.Option(None, "--policy", "-p",
        help="Path to policy YAML. Auto-discovered if omitted."),
    exit_on_warn: bool = typer.Option(False, "--exit-on-warn",
        help="Exit code 2 on warnings (default: warnings are informational)."),
    fmt: str = typer.Option("text", "--format", "-f",
        help="Output format: text or json."),
) -> None:
    """Evaluate cached package snapshot against the active policy file.

    Looks for selvo.policy.yml in the current directory or ~/.config/selvo/policy.yml.
    Use --policy to specify an explicit path.

    Exit codes:
      0 — policy passed (no block violations)
      1 — block violation(s) detected
      2 — warnings only (with --exit-on-warn)

    Examples::

        selvo policy check --format json | jq '.blocked[].cve_id'
    """
    import json as _json

    from selvo.analysis.policy import load_policy, enforce, format_result
    from selvo.analysis.cache import load_last_snapshot
    from selvo.discovery.base import PackageRecord

    policy = load_policy(policy_file)
    if policy is None:
        if fmt == "json":
            print(_json.dumps({"error": "No policy file found."}))
        else:
            console.print("[yellow]No policy file found.[/] Create selvo.policy.yml or use --policy.")
        raise typer.Exit(0)

    result = load_last_snapshot(ecosystem.value)
    if result is None:
        if fmt == "json":
            print(_json.dumps({"error": f"No snapshot for '{ecosystem.value}'. Run: selvo analyze"}))
        else:
            console.print(f"[red]No snapshot for '{ecosystem.value}'. Run: selvo analyze[/]")
        raise typer.Exit(1)

    raw_packages, snap_ts = result
    import datetime as _dt
    snap_age = _dt.datetime.fromtimestamp(snap_ts).strftime("%Y-%m-%d %H:%M")
    if fmt != "json":
        console.print(f"[dim]Snapshot: {len(raw_packages)} packages from {snap_age}[/]")

    packages = [
        PackageRecord(
            name=p["name"],
            ecosystem=p.get("ecosystem", ecosystem.value),
            version=p.get("version", "unknown"),
            max_cvss=p.get("max_cvss", 0.0),
            max_epss=p.get("max_epss", 0.0),
            cve_ids=p.get("cve_ids", []),
            in_cisa_kev=p.get("in_cisa_kev", False),
            exploit_maturity=p.get("exploit_maturity", "none"),
            score=p.get("score", 0.0),
            sla_band=p.get("sla_band", ""),
            sla_days_overdue=p.get("sla_days_overdue", 0),
        )
        for p in raw_packages
    ]

    policy_result = enforce(packages, policy)

    if fmt == "json":
        out = {
            "passed": policy_result.passed,
            "policy_file": policy_file or "selvo.policy.yml",
            "snapshot_at": snap_age,
            "package_count": len(packages),
            "blocked": [
                {
                    "rule": v.rule,
                    "package": v.package,
                    "cve_id": v.cve_id,
                    "detail": v.detail,
                    "level": v.level,
                }
                for v in policy_result.blocked
            ],
            "warnings": [
                {
                    "rule": v.rule,
                    "package": v.package,
                    "cve_id": v.cve_id,
                    "detail": v.detail,
                    "level": v.level,
                }
                for v in policy_result.warnings
            ],
            "allowed_cves": sorted(policy_result.allowed_cves),
        }
        print(_json.dumps(out, indent=2))
    else:
        console.print(format_result(policy_result, policy_file or "selvo.policy.yml"))

    raise typer.Exit(policy_result.exit_code() if exit_on_warn else (1 if not policy_result.passed else 0))


@policy_app.command("show")
def policy_show(
    policy_file: Optional[str] = typer.Option(None, "--policy", "-p"),
) -> None:
    """Show the active policy configuration."""
    from selvo.analysis.policy import load_policy, _DEFAULT_POLICY_PATHS

    policy = load_policy(policy_file)
    if policy is None:
        console.print("[yellow]No policy file found.[/]")
        console.print("Searched:")
        for p in _DEFAULT_POLICY_PATHS:
            console.print(f"  {p}")
        raise typer.Exit(1)

    from rich.table import Table
    tbl = Table(title="Active Policy", show_header=True, header_style="bold cyan")
    tbl.add_column("Setting")
    tbl.add_column("Value")

    tbl.add_row("SLA critical", f"{policy.sla_critical}d")
    tbl.add_row("SLA high", f"{policy.sla_high}d")
    tbl.add_row("SLA medium", f"{policy.sla_medium}d")
    tbl.add_row("SLA low", f"{policy.sla_low}d")
    tbl.add_row("block.on_kev", str(policy.block_on_kev))
    tbl.add_row("block.on_weaponized", str(policy.block_on_weaponized))
    tbl.add_row("block.min_cvss", str(policy.block_min_cvss))
    tbl.add_row("warn.on_poc", str(policy.warn_on_poc))
    tbl.add_row("warn.min_cvss", str(policy.warn_min_cvss))
    tbl.add_row("allowed CVEs", str(len(policy.allowed_cves)))
    tbl.add_row("Slack", "configured" if policy.slack_url else "—")
    tbl.add_row("PagerDuty", "configured" if policy.pagerduty_routing_key else "—")
    console.print(tbl)


# ── selvo deps ───────────────────────────────────────────────────────────────

@app.command()
def deps(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    limit: int = typer.Option(100, "-n", "--limit"),
    no_network: bool = typer.Option(False, "--no-network",
        help="Skip PyPI/npm registry checks (local checks only: version confusion + typosquatting)."),
    output: OutputFormat = typer.Option(OutputFormat.terminal, "-o", "--output"),
    out_file: Optional[str] = typer.Option(None, "-f", "--file"),
) -> None:
    """Detect dependency confusion, namespace hijacking, and typosquatting risks.

    Checks each system package against:
      • Version confusion    — implausibly high version numbers (≥100 major)
      • Typosquatting        — name within Levenshtein-1 of a high-value target
      • Namespace confusion  — bare name exists on PyPI/npm with much newer version

    Uses the last cached snapshot; run 'selvo analyze' first.

    Examples:
        selvo deps
        selvo deps --no-network        # fast, local checks only
        selvo deps -o json -f risks.json
    """
    from selvo.analysis.dep_confusion import enrich_dep_confusion, confusion_report
    from selvo.analysis.cache import load_last_snapshot
    from selvo.discovery.base import PackageRecord
    import json as _json

    result = load_last_snapshot(ecosystem.value)
    if result is None:
        console.print(f"[red]No snapshot for '{ecosystem.value}'. Run: selvo analyze[/]")
        raise typer.Exit(1)

    raw_packages, _ = result
    packages = [
        PackageRecord(
            name=p["name"],
            ecosystem=p.get("ecosystem", ecosystem.value),
            version=p.get("version", "unknown"),
        )
        for p in raw_packages[:limit]
    ]

    console.print(
        f"[bold cyan]selvo deps[/] scanning [yellow]{len(packages)}[/] packages"
        + (" [dim](local checks only)[/]" if no_network else "…")
    )

    packages = asyncio.run(
        enrich_dep_confusion(packages, check_registries=not no_network)
    )
    report = confusion_report(packages)

    if not report:
        console.print("[green]✓ No dependency confusion risks detected.[/]")
        raise typer.Exit(0)

    if output.value == "json":
        out = _json.dumps(report, indent=2)
        if out_file:
            from pathlib import Path
            Path(out_file).write_text(out)
            console.print(f"[green]Written to {out_file}[/]")
        else:
            console.print(out)
        return

    from rich.table import Table
    sev_color = {"high": "red", "medium": "yellow", "low": "cyan"}
    tbl = Table(title=f"Dependency Confusion Risks ({len(report)} found)", show_header=True)
    tbl.add_column("Severity", style="bold", width=8)
    tbl.add_column("Type", width=22)
    tbl.add_column("Package")
    tbl.add_column("Registry", width=7)
    tbl.add_column("Detail")

    for row in report[:50]:
        color = sev_color.get(row["severity"], "white")
        tbl.add_row(
            f"[{color}]{row['severity']}[/{color}]",
            row["risk_type"].replace("_", " "),
            row["package"],
            row["registry"],
            row["detail"][:100] + ("…" if len(row["detail"]) > 100 else ""),
        )

    console.print(tbl)
    if len(report) > 50:
        console.print(f"[dim]… and {len(report) - 50} more. Use -o json for full output.[/]")

    high_count = sum(1 for r in report if r["severity"] == "high")
    if high_count:
        console.print(f"\n[bold red]⚠ {high_count} high-severity risk(s) detected.[/]")
        raise typer.Exit(1)


# ── selvo trend ──────────────────────────────────────────────────────────────

@app.command()
def trend(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    days: int = typer.Option(90, "--days", help="Number of days of history to show."),
    output: OutputFormat = typer.Option(OutputFormat.terminal, "-o", "--output"),
) -> None:
    """Show historical risk trend metrics (CVE count, KEV count, score over time).

    Requires at least 2 snapshots from previous 'selvo analyze' runs.
    """
    from selvo.analysis.trend import load_metrics
    import json as _json

    metrics = load_metrics(ecosystem.value, days=days)
    if not metrics:
        console.print(f"[yellow]No trend data for '{ecosystem.value}'.[/] Run 'selvo analyze' a few times to build history.")
        raise typer.Exit(0)

    if output.value == "json":
        console.print(_json.dumps(metrics, indent=2))
        return

    from rich.table import Table
    import datetime as _dt

    tbl = Table(title=f"Risk Trend — {ecosystem.value} ({len(metrics)} snapshots, {days}d)",
                show_header=True, header_style="bold cyan")
    tbl.add_column("Date", width=17)
    tbl.add_column("Pkgs", justify="right")
    tbl.add_column("CVEs", justify="right")
    tbl.add_column("KEV", justify="right")
    tbl.add_column("Wpzn", justify="right")
    tbl.add_column("Avg Score", justify="right")
    tbl.add_column("Max Score", justify="right")
    tbl.add_column("Max EPSS", justify="right")

    for row in metrics:
        ts = _dt.datetime.fromtimestamp(row["taken_at"]).strftime("%Y-%m-%d %H:%M")
        tbl.add_row(
            ts,
            str(row["total_packages"]),
            str(row["cve_count"]),
            f"[red]{row['kev_count']}[/]" if row["kev_count"] else "0",
            f"[yellow]{row['weaponized_count']}[/]" if row["weaponized_count"] else "0",
            f"{row['avg_score']:.1f}",
            f"{row['max_score']:.1f}",
            f"{row['max_epss']:.3f}",
        )

    console.print(tbl)


# ── selvo compliance ─────────────────────────────────────────────────────────

class ComplianceFramework(str, Enum):
    nist = "nist"
    fedramp = "fedramp"
    soc2 = "soc2"
    pci = "pci"
    dod = "dod"
    all = "all"


class ComplianceOutputFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    markdown = "markdown"
    nist_oscal = "nist-oscal"
    fedramp_oscal = "fedramp-oscal"


@app.command()
def compliance(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    framework: ComplianceFramework = typer.Option(ComplianceFramework.all, "--framework", "-F",
        help="Compliance framework to map to: nist, fedramp, soc2, pci, dod, or all."),
    output: ComplianceOutputFormat = typer.Option(ComplianceOutputFormat.terminal, "-o", "--output"),
    out_file: Optional[str] = typer.Option(None, "-f", "--file"),
    min_severity: str = typer.Option("", "--min-severity",
        help="Only show findings at this severity or above: critical, high, medium, low."),
) -> None:
    """Map CVE findings to compliance framework controls.

    Uses the last cached snapshot from 'selvo analyze'. Run 'selvo analyze' first.

    Control frameworks:
      nist     NIST 800-53 Rev 5
      fedramp  FedRAMP High
      soc2     SOC 2 Type II
      pci      PCI-DSS v4.0
      dod      DoD IL4
      all      All frameworks (default)

    Examples:
        selvo compliance
        selvo compliance --framework fedramp -o json -f fedramp.json
        selvo compliance --framework nist -o markdown -f audit.md
        selvo compliance --framework nist -o nist-oscal -f nist-800-53.json
        selvo compliance --framework fedramp -o fedramp-oscal -f fedramp-high.json
        selvo compliance --min-severity high
    """
    from selvo.analysis.cache import load_last_snapshot
    from selvo.discovery.base import PackageRecord
    from selvo.analysis.compliance import map_controls, summarise, FRAMEWORKS

    result = load_last_snapshot(ecosystem.value)
    if result is None:
        console.print(f"[red]No snapshot for '{ecosystem.value}'. Run: selvo analyze --ecosystem {ecosystem.value}[/]")
        raise typer.Exit(1)

    raw_packages, snap_ts = result
    packages = [
        PackageRecord(
            name=p["name"],
            ecosystem=p.get("ecosystem", ecosystem.value),
            version=p.get("version", "unknown"),
            upstream_version=p.get("upstream_version"),
            max_cvss=p.get("max_cvss", 0.0),
            max_epss=p.get("max_epss", 0.0),
            cve_ids=p.get("cve_ids", []),
            in_cisa_kev=p.get("in_cisa_kev", False),
            exploit_maturity=p.get("exploit_maturity", "none"),
            score=p.get("score", 0.0),
            sla_band=p.get("sla_band", ""),
            sla_days_overdue=p.get("sla_days_overdue", 0),
            cve_disclosed_at=p.get("cve_disclosed_at", ""),
        )
        for p in raw_packages
    ]

    import datetime as _dt
    snap_str = _dt.datetime.fromtimestamp(snap_ts).strftime("%Y-%m-%d %H:%M") if snap_ts else "unknown"
    console.print(
        f"[bold cyan]selvo compliance[/] mapping [yellow]{len(packages)}[/] packages "
        f"to [green]{FRAMEWORKS.get(framework.value, framework.value)}[/] "
        f"(snapshot: {snap_str})…"
    )

    findings = map_controls(packages, framework=framework.value)

    # Filter by severity if requested
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
    if min_severity:
        threshold = _sev_order.get(min_severity.lower(), 4)
        findings = [f for f in findings if _sev_order.get(f.severity, 4) <= threshold]

    if output.value in ("nist-oscal", "fedramp-oscal"):
        from selvo.reporters.nist import render_nist
        fw = "nist" if output.value == "nist-oscal" else "fedramp"
        text = render_nist(packages, framework=fw)
        if out_file:
            from pathlib import Path
            Path(out_file).write_text(text)
            console.print(f"[green]Written to {out_file}[/]")
        else:
            console.print(text)
        return

    if output.value == "json":
        import io as _io
        from selvo.reporters.compliance import render_json
        buf = _io.StringIO()
        render_json(findings, buf)
        text = buf.getvalue()
        if out_file:
            from pathlib import Path
            Path(out_file).write_text(text)
            console.print(f"[green]Written to {out_file}[/]")
        else:
            console.print(text)
        return

    if output.value == "markdown":
        import io as _io
        from selvo.reporters.compliance import render_markdown
        buf = _io.StringIO()
        render_markdown(findings, buf)
        text = buf.getvalue()
        if out_file:
            from pathlib import Path
            Path(out_file).write_text(text)
            console.print(f"[green]Written to {out_file}[/]")
        else:
            console.print(text)
        return

    # Terminal output
    summary = summarise(findings)
    if not findings:
        console.print("[green]✓ No compliance findings.[/]")
        raise typer.Exit(0)

    from rich.table import Table
    sev_color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim"}
    tbl = Table(
        title=f"Compliance Findings — {FRAMEWORKS.get(framework.value, framework.value)} ({len(findings)} findings)",
        show_lines=False,
    )
    tbl.add_column("Package", style="cyan", no_wrap=True, max_width=22)
    tbl.add_column("Signal", max_width=24)
    tbl.add_column("CVE", max_width=16)
    tbl.add_column("Sev", width=8)
    tbl.add_column("Controls")
    tbl.add_column("Frameworks")

    for f in findings[:100]:
        color = sev_color.get(f.severity, "white")
        tbl.add_row(
            f.package,
            f.signal.replace("_", " "),
            f.cve_id or "—",
            f"[{color}]{f.severity or '—'}[/{color}]",
            ", ".join(f.controls[:6]) + ("…" if len(f.controls) > 6 else ""),
            ", ".join(f.frameworks[:2]) + ("…" if len(f.frameworks) > 2 else ""),
        )

    console.print(tbl)
    if len(findings) > 100:
        console.print(f"[dim]… and {len(findings) - 100} more. Use -o json or -o markdown for full output.[/]")

    console.print(
        f"\n[bold]Summary:[/] {summary['total_findings']} findings · "
        f"{len(summary['unique_controls'])} unique controls · "
        + " · ".join(f"[{'red' if k=='critical' else 'yellow' if k=='high' else 'cyan'}]{v} {k}[/]"
                     for k, v in summary.get('by_severity', {}).items())
    )

    if out_file:
        import io as _io
        from selvo.reporters.compliance import render_markdown
        buf = _io.StringIO()
        render_markdown(findings, buf)
        from pathlib import Path
        Path(out_file).write_text(buf.getvalue())
        console.print(f"[green]Also written as Markdown to {out_file}[/]")


# ── selvo fix ────────────────────────────────────────────────────────────────

@app.command(name="fix")
def fix_cmd(
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    package: Optional[str] = typer.Option(None, "--package", "-p", help="Fix a specific package by name."),
    cve_id: Optional[str] = typer.Option(None, "--cve", help="Fix a specific CVE ID."),
    top: int = typer.Option(0, "--top", help="Automatically fix the top N scored packages."),
    dry_run: bool = typer.Option(False, "--dry-run/--no-dry-run",
        help="Show what would be done without opening any PRs."),
    min_patch_safety: float = typer.Option(0.0, "--min-patch-safety",
        help="Require patch_safety_score >= this value before opening PR (0 = skip check)."),
    github_token: Optional[str] = typer.Option(None, "--github-token", envvar="GITHUB_TOKEN",
        help="GitHub personal access token for opening PRs (reads GITHUB_TOKEN env var)."),
) -> None:
    """Open upstream PRs to fix CVEs in the top-scored packages.

    Uses the last cached snapshot from 'selvo analyze'. Reads fix references
    from OSV advisories (already in the snapshot), clones the upstream repo,
    creates a branch, updates version files, commits, and opens a PR via
    the GitHub API.

    Safety gates:
      • Requires fix version validated against upstream (Repology)
      • Respects --min-patch-safety threshold
      • --dry-run mode shows plan without writing anything

    Examples:
        selvo fix --dry-run --top 5
        selvo fix --package openssl --cve CVE-2024-0001
        selvo fix --top 3 --min-patch-safety 0.7
    """
    from selvo.analysis.fix import run_fix_pipeline
    from selvo.analysis.cache import load_last_snapshot
    from selvo.discovery.base import PackageRecord

    result = load_last_snapshot(ecosystem.value)
    if result is None:
        console.print(f"[red]No snapshot for '{ecosystem.value}'. Run: selvo analyze --ecosystem {ecosystem.value}[/]")
        raise typer.Exit(1)

    raw_packages, _ = result
    packages = [
        PackageRecord(
            name=p["name"],
            ecosystem=p.get("ecosystem", ecosystem.value),
            version=p.get("version", "unknown"),
            upstream_version=p.get("upstream_version"),
            cve_ids=p.get("cve_ids", []),
            max_cvss=p.get("max_cvss", 0.0),
            max_epss=p.get("max_epss", 0.0),
            upstream_repo=p.get("upstream_repo"),
            score=p.get("score", 0.0),
            patch_safety_score=p.get("patch_safety_score", 0.0),
            in_cisa_kev=p.get("in_cisa_kev", False),
            exploit_maturity=p.get("exploit_maturity", "none"),
        )
        for p in raw_packages
    ]

    # Filter to the requested target(s)
    if package:
        packages = [p for p in packages if p.name.lower() == package.lower()]
        if not packages:
            console.print(f"[red]Package '{package}' not found in snapshot.[/]")
            raise typer.Exit(1)
    elif cve_id:
        packages = [p for p in packages if cve_id.upper() in [c.upper() for c in p.cve_ids]]
        if not packages:
            console.print(f"[red]CVE '{cve_id}' not found in any snapshot package.[/]")
            raise typer.Exit(1)
    elif top > 0:
        packages = sorted(packages, key=lambda p: p.score, reverse=True)[:top]
    else:
        console.print("[red]Provide --package, --cve, or --top N.[/]")
        raise typer.Exit(1)

    if min_patch_safety > 0:
        safe = [p for p in packages if p.patch_safety_score >= min_patch_safety]
        skipped = len(packages) - len(safe)
        if skipped:
            console.print(f"[yellow]{skipped} package(s) skipped (patch_safety_score < {min_patch_safety})[/]")
        packages = safe

    if not packages:
        console.print("[yellow]No packages meet the criteria after filtering.[/]")
        raise typer.Exit(0)

    console.print(
        f"[bold cyan]selvo fix[/] {'[dim](dry-run)[/dim] ' if dry_run else ''}"
        f"targeting [yellow]{len(packages)}[/] package(s)…"
    )

    results = asyncio.run(run_fix_pipeline(
        packages=packages,
        dry_run=dry_run,
        github_token=github_token or "",
        console=console,
    ))

    opened = sum(1 for r in results if r.get("status") == "opened")
    skipped_count = sum(1 for r in results if r.get("status") == "skipped")
    failed = sum(1 for r in results if r.get("status") == "error")

    console.print(
        f"\n[bold]Results:[/] "
        f"[green]{opened} PR(s) {'would be ' if dry_run else ''}opened[/] · "
        f"[yellow]{skipped_count} skipped[/] · "
        f"[red]{failed} error(s)[/]"
    )
    for r in results:
        if r.get("pr_url"):
            console.print(f"  [green]✓[/] [link={r['pr_url']}]{r['package']}[/link]: {r['pr_url']}")
        elif r.get("status") == "skipped":
            console.print(f"  [yellow]–[/] {r['package']}: {r.get('reason', 'skipped')}")
        elif r.get("status") == "error":
            console.print(f"  [red]✗[/] {r['package']}: {r.get('error', 'unknown error')}")

    if not dry_run and opened == 0 and failed > 0:
        raise typer.Exit(1)


# ── selvo sync ───────────────────────────────────────────────────────────────

class SyncTarget(str, Enum):
    osv = "osv"
    epss = "epss"


@app.command()
def sync(
    target: SyncTarget = typer.Argument(SyncTarget.osv, help="What to sync: 'osv' (vulnerability DB) or 'epss' (EPSS scores)."),
    ecosystems: str = typer.Option(
        "debian,ubuntu,fedora,alpine",
        "--ecosystems", "-e",
        help="Comma-separated list of ecosystems to sync (osv only).",
    ),
    check: bool = typer.Option(False, "--check", help="Show DB age and exit without downloading."),
) -> None:
    """Download and cache external databases for offline / faster operation.

    Examples:
        selvo sync osv
        selvo sync osv --ecosystems debian,alpine
        selvo sync osv --check
        selvo sync epss
    """
    from selvo.analysis.osv_local import sync_osv, db_stats, is_current

    if target == SyncTarget.osv:
        stats = db_stats()
        if check:
            if not stats.get("exists"):
                console.print("[yellow]OSV mirror does not exist yet. Run: selvo sync osv[/]")
                raise typer.Exit(1)
            age = stats.get("age_hours")
            total = stats.get("total_rows", 0)
            status = "[green]current[/]" if is_current() else "[yellow]stale[/]"
            console.print(
                f"[bold cyan]OSV mirror[/] {status} · "
                f"[yellow]{total:,}[/] advisories · "
                f"age [yellow]{age}h[/] · "
                f"{stats.get('db_size_mb', 0):.1f} MB · "
                f"{stats.get('db_path', '')}"
            )
            raise typer.Exit(0)

        eco_list = [e.strip() for e in ecosystems.split(",") if e.strip()]
        console.print(
            f"[bold cyan]selvo sync osv[/] syncing [yellow]{', '.join(eco_list)}[/]"
            f" ({len(eco_list)} ecosystem(s)) — this may take a few minutes…"
        )

        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Downloading…", total=len(eco_list))

            def _cb(eco: str, rows: int) -> None:
                progress.advance(task)
                progress.print(f"  [green]✓[/] {eco}: {rows:,} advisories")

            results = sync_osv(eco_list, progress_cb=_cb)

        total = sum(results.values())
        console.print(
            f"\n[bold]Sync complete:[/] [green]{total:,}[/] total advisories in "
            f"{stats.get('db_path', str(__import__('pathlib').Path.home() / '.cache/selvo/osv.db'))}"
        )

    else:  # epss
        console.print("[bold cyan]selvo sync epss[/] caching full FIRST EPSS CSV…")
        from selvo.analysis.epss import cache_epss_csv
        try:
            rows = asyncio.run(cache_epss_csv())
            console.print(f"[green]✓[/] Cached [yellow]{rows:,}[/] EPSS scores.")
        except AttributeError:
            console.print(
                "[yellow]selvo sync epss[/] — incremental EPSS caching not yet "
                "implemented. Use [bold]selvo analyze[/] to fetch EPSS on demand."
            )


# ── selvo attest ─────────────────────────────────────────────────────────────

@app.command()
def attest(
    package: Optional[str] = typer.Option(None, "--package", "-p", help="Show attestation details for this specific package name."),
    ecosystem: Ecosystem = typer.Option(Ecosystem.all, "-e", "--ecosystem"),
    min_slsa_level: int = typer.Option(0, "--min-level", help="Show only packages at or above this SLSA level (0 = all)."),
    fail_below: int = typer.Option(0, "--fail-below", help="Exit with code 1 if any package is below this SLSA level."),
) -> None:
    """Verify SLSA provenance attestations for packages in the last snapshot.

    Queries Sigstore's Rekor transparency log for each package with a known
    upstream GitHub/GitLab repository and assigns an SLSA level (0–3).

    Examples:
        selvo attest
        selvo attest --min-level 2
        selvo attest --fail-below 2 --ecosystem debian
        selvo attest --package openssl
    """
    from selvo.analysis.cache import load_last_snapshot
    from selvo.analysis.slsa import enrich_slsa, check_policy_slsa
    from selvo.discovery.base import PackageRecord

    result = load_last_snapshot(ecosystem.value)
    if result is None:
        console.print(f"[red]No snapshot for '{ecosystem.value}'. Run: selvo analyze --ecosystem {ecosystem.value}[/]")
        raise typer.Exit(1)

    raw_packages, snap_ts = result
    packages = [
        PackageRecord(
            name=p["name"],
            ecosystem=p.get("ecosystem", ecosystem.value),
            version=p.get("version", "unknown"),
            upstream_repo=p.get("upstream_repo"),
        )
        for p in raw_packages
        if not package or p["name"].lower() == package.lower()
    ]

    if not packages:
        console.print(f"[red]Package '{package}' not found in snapshot.[/]")
        raise typer.Exit(1)

    console.print(f"[bold cyan]selvo attest[/] verifying [yellow]{len(packages)}[/] package(s) via Rekor…")
    packages = asyncio.run(enrich_slsa(packages))

    from rich.table import Table
    tbl = Table(show_header=True, header_style="bold cyan")
    tbl.add_column("Package", style="bold")
    tbl.add_column("SLSA", justify="center")
    tbl.add_column("Verified", justify="center")
    tbl.add_column("Builder")
    tbl.add_column("Source Ref")

    _LEVEL_STYLE = {0: "red", 1: "yellow", 2: "green", 3: "bright_green"}

    displayed = 0
    for p in sorted(packages, key=lambda x: getattr(x, "slsa_level", 0), reverse=True):
        level = getattr(p, "slsa_level", 0)
        if level < min_slsa_level:
            continue
        style = _LEVEL_STYLE.get(level, "white")
        tbl.add_row(
            p.name,
            f"[{style}]L{level}[/]",
            "[green]✓[/]" if getattr(p, "slsa_verified", False) else "[red]✗[/]",
            getattr(p, "slsa_builder", "") or "[dim]—[/]",
            getattr(p, "slsa_source_ref", "") or "[dim]—[/]",
        )
        displayed += 1

    console.print(tbl)

    if fail_below > 0:
        failing = check_policy_slsa(packages, fail_below)
        if failing:
            console.print(
                f"\n[red]✗ {len(failing)} package(s) are below SLSA level {fail_below}:[/] "
                + ", ".join(p.name for p in failing[:10])
            )
            raise typer.Exit(1)
        console.print(f"\n[green]✓ All packages meet SLSA level {fail_below}.[/]")


# ── selvo api-key ────────────────────────────────────────────────────────────

api_key_app = typer.Typer(
    name="api-key",
    help="Manage API keys for the selvo SaaS REST API.",
    add_completion=False,
)
app.add_typer(api_key_app, name="api-key")


@api_key_app.command("create")
def apikey_create(
    org_id: str = typer.Option(..., "--org", help="Organisation identifier (slug)."),
    name: str = typer.Option("", "--name", help="Human-readable org name."),
    email: str = typer.Option("", "--email", help="Org contact e-mail."),
    plan: str = typer.Option("free", "--plan", help="Plan: free | pro | enterprise."),
) -> None:
    """Generate a new API key for an org and print it once to stdout.

    The key is printed exactly once — it is never stored in plaintext.
    Store it in a secrets manager immediately after creation.
    """
    from selvo.api.auth import register_org, generate_api_key

    register_org(org_id, name=name or org_id, email=email, plan=plan)
    key = generate_api_key(org_id, plan=plan)
    console.print(f"[bold green]✓[/] API key created for org [yellow]{org_id}[/] (plan=[cyan]{plan}[/])")
    console.print(f"\n  [bold]{key}[/]\n")
    console.print("[dim]Store this key securely — it will not be shown again.[/]")


@api_key_app.command("list")
def apikey_list(
    org_id: str = typer.Option(..., "--org", help="Organisation identifier."),
) -> None:
    """List all API keys for an org (hashes only, no plaintext)."""
    from selvo.api.auth import list_org_keys
    from rich.table import Table
    import datetime as _dt

    keys = list_org_keys(org_id)
    if not keys:
        console.print(f"[yellow]No keys found for org '{org_id}'.[/]")
        return

    tbl = Table(show_header=True, header_style="bold cyan")
    tbl.add_column("ID", justify="right")
    tbl.add_column("Plan")
    tbl.add_column("Active", justify="center")
    tbl.add_column("Created")
    tbl.add_column("Last Used")
    tbl.add_column("Requests Today", justify="right")

    for k in keys:
        created = _dt.datetime.fromtimestamp(k["created_at"]).strftime("%Y-%m-%d") if k.get("created_at") else "—"
        last = _dt.datetime.fromtimestamp(k["last_used_at"]).strftime("%Y-%m-%d %H:%M") if k.get("last_used_at") else "—"
        tbl.add_row(
            str(k["id"]),
            k["plan"],
            "[green]✓[/]" if k["active"] else "[red]✗[/]",
            created,
            last,
            str(k["requests_today"]),
        )

    console.print(tbl)


@api_key_app.command("revoke")
def apikey_revoke(
    key_hash: str = typer.Option(..., "--hash", help="SHA-256 hash of the key to revoke."),
) -> None:
    """Deactivate an API key by its SHA-256 hash."""
    from selvo.api.auth import revoke_api_key

    found = revoke_api_key(key_hash)
    if found:
        console.print(f"[green]✓[/] Key [yellow]{key_hash[:16]}…[/] revoked.")
    else:
        console.print(f"[red]✗[/] No active key found with hash prefix [yellow]{key_hash[:16]}[/].")
        raise typer.Exit(1)


@app.command()
def runtime(
    ecosystem: Ecosystem = typer.Option(Ecosystem.debian, "-e", "--ecosystem"),
    limit: int = typer.Option(50, "-n", "--limit"),
    cve: bool = typer.Option(True, "--cve/--no-cve", help="Enrich packages with CVE data before scanning."),
    all_libs: bool = typer.Option(False, "--all/--cve-only", help="Show all loaded packages, not just those with CVEs."),
    watch: bool = typer.Option(False, "--watch/--no-watch", help="Stream live dlopen() events via eBPF (requires bcc + root, kernel ≥ 5.8). Falls back to procfs snapshot if eBPF unavailable."),
    watch_duration: float = typer.Option(30.0, "--watch-duration", help="How long to stream eBPF events, in seconds (only with --watch)."),
    output: OutputFormat = typer.Option(OutputFormat.terminal, "-o", "--output"),
    out_file: Optional[str] = typer.Option(None, "-f", "--file"),
) -> None:
    """Identify CVE-affected shared libraries loaded in running processes right now.

    Reads /proc/<pid>/maps for every accessible process, resolves each loaded
    .so file back to its owning package, and cross-references with CVE/EPSS
    data to surface libraries that are *actively in memory* and vulnerable.

    With --watch: streams live dlopen() syscall events via eBPF kprobes
    (requires python3-bpfcc and root, kernel ≥ 5.8).

    Requires root or CAP_SYS_PTRACE for full process coverage.
    Gracefully degrades to accessible processes when running unprivileged.

    Examples:
        sudo selvo runtime
        selvo runtime --all
        sudo selvo runtime --watch --watch-duration 60
        selvo runtime --cve -o json -f runtime.json
    """
    import os
    from selvo.analysis.runtime import enrich_runtime, standalone_scan

    if not os.path.exists("/proc"):
        console.print("[red]✗[/] /proc filesystem not found — runtime scan requires Linux.")
        raise typer.Exit(1)

    # ── eBPF watch mode ───────────────────────────────────────────────────────
    if watch:
        from selvo.analysis.ebpf_tracer import is_ebpf_available, trace_dlopen
        if is_ebpf_available():
            # Pre-load CVE data so each dlopen event gets immediate CVE correlation
            watch_cve_pkgs = []
            if cve:
                from selvo.discovery import run_discovery
                from selvo.analysis.versions import enrich_versions
                from selvo.analysis.cve import enrich_cve
                from selvo.analysis.epss import enrich_epss
                from selvo.analysis.distro_status import filter_resolved_cves

                console.print("  [dim]Pre-loading CVE data for correlation…[/]")

                async def _watch_cve():
                    pkgs = await run_discovery(ecosystem.value, limit)
                    pkgs = await enrich_versions(pkgs)
                    pkgs = await enrich_cve(pkgs)
                    pkgs = await filter_resolved_cves(pkgs)
                    pkgs = await enrich_epss(pkgs)
                    return pkgs

                watch_cve_pkgs = asyncio.run(_watch_cve())
                watch_cve_pkgs = [p for p in watch_cve_pkgs if p.cve_ids]
                console.print(f"  [dim]{len(watch_cve_pkgs)} CVE-affected packages indexed for correlation[/]")

            console.print(
                f"[bold cyan]selvo runtime --watch[/] streaming dlopen events via eBPF "
                f"for [yellow]{watch_duration:.0f}s[/] …  [dim](Ctrl-C to stop)[/]"
            )
            try:
                import datetime
                _collected_ebpf: list = []
                for evt in trace_dlopen(duration_s=watch_duration, cve_packages=watch_cve_pkgs or None):
                    _collected_ebpf.append(evt)
                    ts = datetime.datetime.fromtimestamp(evt.timestamp).strftime("%H:%M:%S.%f")[:-3]
                    if evt.cve_ids:
                        kev_tag = " [bold red][KEV][/]" if evt.in_cisa_kev else ""
                        epss_tag = f" [yellow]EPSS {evt.max_epss*100:.0f}%[/]" if evt.max_epss >= 0.1 else ""
                        console.print(
                            f"  [dim]{ts}[/]  [bold red]⚠[/]  "
                            f"[yellow]{evt.process_name}[/] ([dim]{evt.pid}[/])  "
                            f"[bold red]{evt.filename}[/]"
                            f"{kev_tag}{epss_tag}  "
                            f"[dim]{', '.join(evt.cve_ids[:3])}{'...' if len(evt.cve_ids) > 3 else ''}[/]"
                        )
                    else:
                        console.print(
                            f"  [dim]{ts}[/]  "
                            f"[yellow]{evt.process_name}[/] ([dim]{evt.pid}[/])  {evt.filename}"
                        )
            except KeyboardInterrupt:
                pass

            # Feed eBPF events back through the runtime model and re-score.
            # This produces a definitive ranked list of packages *confirmed*
            # loaded in memory during this session, with 1.5× runtime boost.
            if _collected_ebpf and watch_cve_pkgs:
                from selvo.analysis.runtime import merge_ebpf_events
                from selvo.analysis.debian_index import load_debian_index
                from selvo.prioritizer.scorer import score_and_rank

                console.print("\n[bold cyan]Post-session re-score[/] (merging eBPF events into CVE model)…")
                _deb_idx = asyncio.run(load_debian_index())
                _updated, _hits = merge_ebpf_events(_collected_ebpf, watch_cve_pkgs, deb_idx=_deb_idx)
                _updated = score_and_rank(_updated)
                _loaded_cve = [p for p in _updated if p.runtime_loaded and p.cve_ids]
                if _loaded_cve:
                    console.print(
                        f"  [bold red]{len(_loaded_cve)} package(s) confirmed loaded with open CVEs:[/]"
                    )
                    for _p in _loaded_cve[:10]:
                        _kev = " [bold red][KEV][/]" if _p.in_cisa_kev else ""
                        _procs = ", ".join(dict.fromkeys(_p.runtime_procs))[:3]
                        console.print(
                            f"  [yellow]{_p.name}[/]  score=[bold]{_p.score:.1f}[/]"
                            f"  EPSS={_p.max_epss*100:.1f}%{_kev}"
                            f"  procs: {_procs}"
                        )
                else:
                    console.print("  [green]✓[/] No CVE-affected libraries confirmed loaded.")

            console.print("[dim]eBPF tracer stopped.[/]")
            return
        else:
            console.print("[yellow]⚠[/] eBPF unavailable (install python3-bpfcc and run as root, kernel ≥ 5.8).")
            console.print("[dim]  Falling back to procfs snapshot…[/]")

    if os.geteuid() != 0:
        console.print("[yellow]⚠[/] Not running as root — scan limited to accessible processes only.")
        console.print("[dim]  For full coverage: sudo selvo runtime[/]")

    if not cve and not all_libs:
        console.print("[yellow]⚠[/] --no-cve with default --cve-only produces no hits. Pass [cyan]--all[/] to show all loaded libraries without CVE filtering.")

    if cve:
        from selvo.discovery import run_discovery
        from selvo.analysis.versions import enrich_versions
        from selvo.analysis.cve import enrich_cve
        from selvo.analysis.epss import enrich_epss
        from selvo.analysis.cvss import enrich_cvss
        from selvo.analysis.distro_status import filter_resolved_cves

        console.print("[bold cyan]selvo[/] running runtime reachability scan…")

        async def _run():
            packages = await run_discovery(ecosystem.value, limit)
            packages = await enrich_versions(packages)
            packages = await enrich_cve(packages)
            packages = await filter_resolved_cves(packages)
            packages = await enrich_epss(packages)
            packages = await enrich_cvss(packages, console=console)
            return packages

        console.print("  [dim]Fetching packages and CVE data…[/]")
        packages = asyncio.run(_run())
        console.print("  [dim]Scanning /proc/*/maps for loaded shared libraries…[/]")
        # Load Debian index for source→binary expansion (improves recall on Debian/Ubuntu)
        from selvo.analysis.debian_index import load_debian_index
        deb_idx = asyncio.run(load_debian_index())
        packages, hits = enrich_runtime(packages, cve_only=not all_libs, deb_idx=deb_idx)
    else:
        console.print("[bold cyan]selvo[/] scanning /proc/*/maps (no CVE enrichment)…")
        lib_map, so_to_pkg = standalone_scan()
        hits = []
        packages = []
        _seen: set[str] = set()
        from selvo.analysis.runtime import RuntimeHit
        for so_path, procs in lib_map.items():
            pkg_name = so_to_pkg.get(so_path, "")
            if not pkg_name or pkg_name in _seen:
                continue
            _seen.add(pkg_name)
            pid, comm, cmdline = procs[0]
            hits.append(RuntimeHit(
                pid=pid, process_name=comm, cmdline=cmdline,
                so_path=so_path, package=pkg_name, version="unknown",
                ecosystem=ecosystem.value,
            ))

    if output.value == "json":
        import json
        import dataclasses
        data = {
            "hits": [dataclasses.asdict(h) for h in hits],
            "loaded_packages": [p.name for p in packages if p.runtime_loaded],
        }
        out_text = json.dumps(data, indent=2)
        if out_file:
            with open(out_file, "w") as fh:
                fh.write(out_text)
            console.print(f"[green]Written to {out_file}[/]")
        else:
            console.print(out_text)
        return

    # Terminal output
    from rich.table import Table

    if not hits:
        console.print("[green]✓[/] No CVE-affected libraries found loaded in running processes.")
        runtime_count = sum(1 for p in packages if p.runtime_loaded)
        console.print(f"  [dim]{runtime_count} packages from {ecosystem.value} currently loaded in memory (none with open CVEs)[/]")
        return

    tbl = Table(
        title=f"selvo — Runtime Reachability ({len(hits)} CVE-affected library instances)",
        show_lines=False,
        header_style="bold cyan",
    )
    tbl.add_column("Package", style="cyan", no_wrap=True)
    tbl.add_column("Version", style="white")
    tbl.add_column("CVEs", justify="right")
    tbl.add_column("EPSS", justify="right")
    tbl.add_column("CVSS", justify="right")
    tbl.add_column("KEV", justify="center")
    tbl.add_column("PID", justify="right")
    tbl.add_column("Process", style="yellow")

    # Deduplicate to one row per (package, process) for cleaner output
    shown: set[tuple[str, str]] = set()
    for h in hits:
        key = (h.package, h.process_name)
        if key in shown:
            continue
        shown.add(key)

        kev_cell = "[bold red]KEV[/]" if h.in_cisa_kev else "–"
        epss_pct = f"{h.max_epss * 100:.1f}%"
        epss_style = "red" if h.max_epss >= 0.5 else "yellow" if h.max_epss >= 0.1 else "dim"
        cvss_style = "red" if h.max_cvss >= 9.0 else "yellow" if h.max_cvss >= 7.0 else "white"
        tbl.add_row(
            h.package,
            h.version,
            str(len(h.cve_ids)),
            f"[{epss_style}]{epss_pct}[/]",
            f"[{cvss_style}]{h.max_cvss:.1f}[/]" if h.max_cvss else "–",
            kev_cell,
            str(h.pid),
            h.process_name,
        )

    console.print(tbl)
    runtime_count = sum(1 for p in packages if p.runtime_loaded)
    cve_runtime_count = sum(1 for p in packages if p.runtime_loaded and p.cve_ids)
    console.print(
        f"\n  [dim]{runtime_count} packages from {ecosystem.value} currently loaded · "
        f"[bold]{cve_runtime_count} with open CVEs[/dim] · "
        f"{len(hits)} vulnerable instances in live processes[/]"
    )


if __name__ == "__main__":
    app()
