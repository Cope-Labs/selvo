"""Rich terminal reporter."""
from __future__ import annotations

from typing import Optional

import networkx as nx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from selvo.discovery.base import PackageRecord, PrOpportunity


def render_terminal(packages: list[PackageRecord], console: Optional[Console] = None) -> None:
    """Render a rich table of packages to the terminal."""
    con = console or Console()

    table = Table(
        title=f"selvo — Top {len(packages)} Packages",
        box=box.ROUNDED,
        highlight=True,
        show_lines=False,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Package", style="bold cyan", no_wrap=True)
    table.add_column("Ecosystem", style="green")
    table.add_column("Installed", style="yellow")
    table.add_column("Upstream", style="magenta")
    table.add_column("CVEs", style="red", justify="right")
    table.add_column("EPSS%", justify="right", style="bold red")
    table.add_column("CVSS", justify="right", style="red")
    table.add_column("Repos", justify="right", style="dim")
    table.add_column("Upstream Repo", style="dim", no_wrap=True)
    table.add_column("Score", justify="right", style="bold white")

    for i, pkg in enumerate(packages, 1):
        upstream = pkg.upstream_version or "—"
        installed = pkg.version if pkg.version != "unknown" else "—"
        cve_str = str(pkg.cve_count) if pkg.cve_count else "—"
        epss_str = f"{pkg.max_epss*100:.0f}%" if pkg.max_epss > 0 else "—"
        cvss_str = f"{pkg.max_cvss:.1f}" if pkg.max_cvss > 0 else "—"
        rdeps_str = str(pkg.reverse_dep_count) if pkg.reverse_dep_count else "—"
        score_str = f"{pkg.score:.1f}" if pkg.score else "—"
        repo = pkg.upstream_repo or "—"
        # Trim repo for display
        if len(repo) > 35:
            repo = "…" + repo[-34:]
        table.add_row(
            str(i), pkg.name, pkg.ecosystem, installed, upstream,
            cve_str, epss_str, cvss_str, rdeps_str, repo, score_str,
        )

    con.print(table)


def render_pr_opportunities(opportunities: list[PrOpportunity], console: Optional[Console] = None) -> None:
    """Render PR/patch opportunities as an expanded rich table with fix refs."""
    con = console or Console()

    if not opportunities:
        con.print("[yellow]No actionable PR opportunities found.[/]")
        return

    table = Table(
        title=f"selvo — {len(opportunities)} PR Opportunities",
        box=box.ROUNDED,
        highlight=True,
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Package", style="bold cyan", no_wrap=True)
    table.add_column("Ecosystem", style="green")
    table.add_column("CVEs", style="red", justify="right")
    table.add_column("Fix Refs", justify="right")
    table.add_column("Downstream", justify="right", style="yellow")
    table.add_column("Status", justify="center")
    table.add_column("Upstream Repo", style="dim")
    table.add_column("Score", justify="right", style="bold white")

    for i, opp in enumerate(opportunities, 1):
        fix_count = len([r for r in opp.fix_refs if r.ref_type == "FIX"])
        repo_display = "—"
        if opp.upstream_repo:
            repo_display = opp.upstream_repo
            if len(repo_display) > 40:
                repo_display = "…" + repo_display[-39:]
        status = getattr(opp, "status", "open")
        status_cell = {
            "open": "[green]open[/]",
            "track": "[yellow]track[/]",
            "resolved": "[dim]resolved[/]",
        }.get(status, status)
        table.add_row(
            str(i),
            opp.package,
            opp.ecosystem,
            str(len(opp.affected_cves)) if opp.affected_cves else "—",
            str(fix_count) if fix_count else "—",
            str(opp.downstream_count) if opp.downstream_count else "—",
            status_cell,
            repo_display,
            f"{opp.score:.0f}",
        )

    con.print(table)

    # Detail panel for top 5 with actual fix URLs
    if opportunities:
        con.print()
        con.print("[bold]Top fix references:[/]")
        for opp in opportunities[:5]:
            fix_urls = [r.url for r in opp.fix_refs if r.ref_type == "FIX"][:3]
            pr_desc = getattr(opp, "_pr_description", None)
            existing_prs = getattr(opp, "existing_pr_urls", [])
            status = getattr(opp, "status", "open")
            if not fix_urls and not pr_desc and not existing_prs:
                continue
            lines = [f"[bold cyan]{opp.package}[/] ({', '.join(opp.affected_cves[:3])})"]
            if status == "track" and existing_prs:
                lines.append("[yellow]⚠ PR already exists — track instead of opening:[/]")
                for url in existing_prs[:2]:
                    lines.append(f"  [link={url}]{url}[/link]")
            for url in fix_urls:
                lines.append(f"  fix: [link={url}]{url}[/link]")
            if pr_desc:
                lines.append("")
                lines.append("[bold]Draft PR description:[/]")
                lines.append(pr_desc)
            backport = getattr(opp, "_backport_draft", None)
            if backport:
                lines.append("")
                lines.append("[bold]Backport instructions:[/]")
                lines.append(backport)
            con.print(Panel("\n".join(lines), expand=False))


def print_graph(g: nx.DiGraph, console: Optional[Console] = None) -> None:
    """Print a summary of a dependency graph."""
    con = console or Console()
    con.print(f"[bold]Nodes:[/] {g.number_of_nodes()}  [bold]Edges:[/] {g.number_of_edges()}")
    for node in list(g.nodes)[:20]:
        successors = list(g.successors(node))
        if successors:
            con.print(f"  [cyan]{node}[/] → {', '.join(successors[:6])}" + (" …" if len(successors) > 6 else ""))


def render_diff(diff: dict, prev_timestamp: str, console: Optional[Console] = None) -> None:
    """Render a snapshot diff produced by cache.diff_snapshots()."""
    con = console or Console()
    since = prev_timestamp or "unknown"
    con.print(Panel(f"[bold]selvo diff[/] — changes since [yellow]{since}[/]", style="bold blue"))

    new_cves: list[dict] = diff.get("new_cves", [])
    if new_cves:
        rows = "\n".join(
            f"  [red]{item['cve']}[/]  [cyan]{item['package']}[/]  EPSS={item.get('epss', 0):.2%}"
            for item in new_cves[:20]
        )
        con.print(Panel(rows, title=f"[red]:rotating_light: New CVEs ({len(new_cves)})[/]", expand=False))

    epss_jumps: list[dict] = diff.get("epss_jumps", [])
    if epss_jumps:
        rows = "\n".join(
            f"  [yellow]{item['package']}[/]  {item['old_epss']:.2%} → [bold yellow]{item['new_epss']:.2%}[/]  (+{item['delta']:.2%})"
            for item in epss_jumps[:20]
        )
        con.print(Panel(rows, title=f"[yellow]:chart_increasing: EPSS Jumps ({len(epss_jumps)})[/]", expand=False))

    score_changes: list[dict] = diff.get("score_changes", [])
    if score_changes:
        rows = "\n".join(
            f"  [magenta]{item['package']}[/]  {item['old_score']:.1f} → [bold]{item['new_score']:.1f}[/]  ({item['delta']:+.1f})"
            for item in score_changes[:20]
        )
        con.print(Panel(rows, title=f"[magenta]:bar_chart: Score Changes ({len(score_changes)})[/]", expand=False))

    new_packages: list[str] = diff.get("new_packages", [])
    if new_packages:
        con.print(Panel(", ".join(new_packages[:40]), title=f"[green]:new: New Packages ({len(new_packages)})[/]", expand=False))

    resolved: list[str] = diff.get("resolved", [])
    if resolved:
        con.print(Panel(", ".join(resolved[:40]), title=f"[green]:white_check_mark: Resolved / Dropped ({len(resolved)})[/]", expand=False))

    if not any([new_cves, epss_jumps, score_changes, new_packages, resolved]):
        con.print("[green]No significant changes since last snapshot.[/]")
