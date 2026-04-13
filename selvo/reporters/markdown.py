"""Markdown reporter."""
from __future__ import annotations

from selvo.discovery.base import PackageRecord, PrOpportunity


def render_markdown(packages: list[PackageRecord]) -> str:
    """Render packages as a Markdown table."""
    lines: list[str] = [
        "# selvo — Update Priority Report\n",
        "| # | Package | Ecosystem | Installed | Upstream | CVEs | Upstream Repo | Score |",
        "|---|---------|-----------|-----------|----------|------|---------------|-------|",
    ]
    for i, pkg in enumerate(packages, 1):
        upstream = pkg.upstream_version or "—"
        installed = pkg.version if pkg.version != "unknown" else "—"
        cve_str = str(pkg.cve_count) if pkg.cve_count else "—"
        score_str = f"{pkg.score:.1f}" if pkg.score else "—"
        repo = f"[repo]({pkg.upstream_repo})" if pkg.upstream_repo else "—"
        lines.append(f"| {i} | {pkg.name} | {pkg.ecosystem} | {installed} | {upstream} | {cve_str} | {repo} | {score_str} |")
    return "\n".join(lines)


def render_pr_opportunities_md(opportunities: list[PrOpportunity]) -> str:
    """Render PR opportunities as a Markdown document with fix ref links."""
    lines: list[str] = [
        "# selvo — Upstream PR Opportunities\n",
        "> Ranked by composite score: CVE count × 10 + version gap + downstream blast radius.\n",
        "| # | Package | Ecosystem | CVEs | Fix Refs | Downstream | Score |",
        "|---|---------|-----------|------|----------|------------|-------|",
    ]
    for i, opp in enumerate(opportunities, 1):
        cve_str = str(len(opp.affected_cves)) if opp.affected_cves else "—"
        fix_count = len([r for r in opp.fix_refs if r.ref_type == "FIX"])
        fix_str = str(fix_count) if fix_count else "—"
        ds = str(opp.downstream_count) if opp.downstream_count else "—"
        lines.append(
            f"| {i} | {opp.package} | {opp.ecosystem} | {cve_str} | {fix_str} | {ds} | {opp.score:.0f} |"
        )

    lines.append("\n## Detailed Fix References\n")
    for opp in opportunities:
        fix_refs = [r for r in opp.fix_refs if r.ref_type == "FIX"]
        if not fix_refs:
            continue
        repo_link = f"[{opp.upstream_repo}]({opp.upstream_repo})" if opp.upstream_repo else "unknown"
        lines.append(f"### `{opp.package}` ({opp.ecosystem})")
        lines.append(f"- **Upstream repo:** {repo_link}")
        lines.append(f"- **CVEs:** {', '.join(opp.affected_cves[:10])}")
        lines.append("- **Fix commits / PRs:**")
        for ref in fix_refs[:10]:
            lines.append(f"  - [{ref.url}]({ref.url})")
        lines.append("")

    return "\n".join(lines)
