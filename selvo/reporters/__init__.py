"""Reporter dispatcher."""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from rich.console import Console

from selvo.discovery.base import PackageRecord

if TYPE_CHECKING:
    from selvo.analysis.local_context import SystemContext


def render(
    packages: list[PackageRecord],
    fmt: str = "terminal",
    out_file: Optional[str] = None,
    console: Optional[Console] = None,
    ctx: Optional["SystemContext"] = None,
    trend_metrics: Optional[list[dict]] = None,
) -> None:
    """Dispatch to the appropriate reporter."""
    if fmt == "json":
        from selvo.reporters.json_reporter import render_json
        output = render_json(packages, ctx=ctx)
    elif fmt == "markdown":
        from selvo.reporters.markdown import render_markdown
        output = render_markdown(packages)
    elif fmt == "html":
        from selvo.reporters.html import render_html
        output = render_html(packages, ctx=ctx, trend_metrics=trend_metrics)
    elif fmt == "sbom":
        from selvo.reporters.sbom import render_sbom
        output = render_sbom(packages)
    elif fmt == "vex":
        from selvo.reporters.vex import render_vex
        output = render_vex(packages)
    elif fmt == "sarif":
        from selvo.reporters.sarif import render_sarif
        output = render_sarif(packages)
    elif fmt == "nist":
        from selvo.reporters.nist import render_nist
        output = render_nist(packages, framework="nist")
    elif fmt == "fedramp":
        from selvo.reporters.nist import render_nist
        output = render_nist(packages, framework="fedramp")
    elif fmt == "pdf":
        from selvo.reporters.pdf import render_pdf, render_pdf_html
        pdf_bytes = render_pdf(packages)
        if pdf_bytes and out_file:
            with open(out_file, "wb") as f:
                f.write(pdf_bytes)
            if console:
                console.print(f"[green]PDF written to {out_file}[/]")
            return
        output = render_pdf_html(packages)
    else:
        from selvo.reporters.terminal import render_terminal
        render_terminal(packages, console=console)
        return

    if out_file:
        with open(out_file, "w") as f:
            f.write(output)
        if console:
            console.print(f"[green]Output written to {out_file}[/]")
    elif console:
        console.print(output)
    else:
        print(output)
