"""PDF compliance report — generates print-optimized HTML, optionally converts to PDF.

If ``weasyprint`` is installed, ``render_pdf()`` returns raw PDF bytes.
Otherwise, ``render_pdf_html()`` returns self-contained HTML with @media print
styles that produces clean output from the browser's Print → Save as PDF.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from selvo.discovery.base import PackageRecord


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def render_pdf_html(
    packages: list[PackageRecord],
    title: str = "selvo Compliance Report",
    framework: str = "general",
) -> str:
    """Return self-contained, print-optimized HTML for PDF conversion."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(packages)
    with_cves = sum(1 for p in packages if p.cve_count > 0)
    kev_count = sum(1 for p in packages if p.in_cisa_kev)
    max_score = max((p.score for p in packages), default=0)
    total_cves = sum(p.cve_count for p in packages)

    # Build package table rows
    pkg_rows = ""
    for p in sorted(packages, key=lambda x: x.score, reverse=True)[:50]:
        cves = ", ".join(p.cve_ids[:5])
        if len(p.cve_ids) > 5:
            cves += f" +{len(p.cve_ids) - 5} more"
        kev = "YES" if p.in_cisa_kev else ""
        mat = p.exploit_maturity if p.exploit_maturity != "none" else ""
        sla = getattr(p, "sla_band", "")
        pkg_rows += f"""
        <tr>
          <td>{_esc(p.name)}</td>
          <td style="text-align:right">{p.score:.1f}</td>
          <td style="text-align:right">{p.cve_count}</td>
          <td style="text-align:right">{p.max_cvss:.1f}</td>
          <td style="text-align:right">{p.max_epss:.2%}</td>
          <td>{kev}</td>
          <td>{mat}</td>
          <td>{sla}</td>
          <td style="font-size:0.7em">{_esc(cves)}</td>
        </tr>"""

    # SLA summary
    sla_breach = sum(1 for p in packages if getattr(p, "sla_band", "") in ("breach", "critical"))
    sla_warn = sum(1 for p in packages if getattr(p, "sla_band", "") == "warn")

    framework_label = {
        "nist": "NIST SP 800-53 Rev 5",
        "fedramp": "FedRAMP High Baseline",
        "general": "General Vulnerability Assessment",
    }.get(framework, framework.upper())

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_esc(title)}</title>
<style>
  @page {{ size: A4 landscape; margin: 1.5cm; }}
  body {{ font: 11px/1.4 -apple-system, system-ui, sans-serif; color: #1a1a1a; }}
  h1 {{ font-size: 18px; margin-bottom: 4px; }}
  h2 {{ font-size: 14px; margin-top: 20px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }}
  .meta {{ color: #666; font-size: 10px; margin-bottom: 16px; }}
  .summary {{ display: flex; gap: 20px; margin-bottom: 16px; }}
  .stat {{ border: 1px solid #ddd; border-radius: 6px; padding: 8px 16px; text-align: center; }}
  .stat .value {{ font-size: 22px; font-weight: 700; }}
  .stat .label {{ font-size: 9px; color: #666; text-transform: uppercase; }}
  .stat.red .value {{ color: #d32f2f; }}
  .stat.amber .value {{ color: #f57c00; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 10px; }}
  th, td {{ border: 1px solid #ddd; padding: 4px 6px; text-align: left; }}
  th {{ background: #f5f5f5; font-weight: 600; }}
  tr:nth-child(even) {{ background: #fafafa; }}
  .footer {{ margin-top: 20px; font-size: 9px; color: #999; text-align: center; }}
  @media screen {{
    body {{ max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }}
  }}
</style>
</head>
<body>

<h1>{_esc(title)}</h1>
<div class="meta">
  Framework: {_esc(framework_label)} | Generated: {now} | Powered by selvo (selvo.dev)
</div>

<div class="summary">
  <div class="stat"><div class="value">{total}</div><div class="label">Packages</div></div>
  <div class="stat red"><div class="value">{with_cves}</div><div class="label">With CVEs</div></div>
  <div class="stat red"><div class="value">{total_cves}</div><div class="label">Open CVEs</div></div>
  <div class="stat amber"><div class="value">{kev_count}</div><div class="label">CISA KEV</div></div>
  <div class="stat"><div class="value">{max_score:.0f}</div><div class="label">Max Score</div></div>
  <div class="stat red"><div class="value">{sla_breach}</div><div class="label">SLA Breach</div></div>
  <div class="stat amber"><div class="value">{sla_warn}</div><div class="label">SLA Warn</div></div>
</div>

<h2>Package Risk Assessment (Top 50 by Score)</h2>
<table>
  <thead>
    <tr>
      <th>Package</th><th>Score</th><th>CVEs</th><th>CVSS</th><th>EPSS</th>
      <th>KEV</th><th>Exploit</th><th>SLA</th><th>CVE IDs</th>
    </tr>
  </thead>
  <tbody>{pkg_rows}</tbody>
</table>

<h2>Scoring Methodology</h2>
<p>Composite risk score (0-100) based on: dependency blast radius (22%),
EPSS exploitation probability (20%), betweenness centrality (15%),
version lag (14%), CVSS severity (10%), exploit maturity (8%),
ecosystem popularity (7%), download count (2%), exposure days (2%).</p>
<p>CVEs resolved by distro backports are excluded via Debian Security Tracker cross-reference.
EPSS and CVSS data sourced from FIRST.org and NVD respectively.</p>

<h2>Data Sources</h2>
<p>OSV.dev (CVE mapping) | FIRST.org EPSS (exploit probability) | NVD (CVSS v3) |
Debian Security Tracker (resolved CVEs) | CISA KEV (active exploits) |
Repology (upstream versions) | Ubuntu USN | Fedora Bodhi</p>

<div class="footer">
  This report was generated by selvo (selvo.dev) on {now}.
  Results are informational. Verify findings before taking remediation action.
</div>

</body>
</html>"""


def render_pdf(
    packages: list[PackageRecord],
    title: str = "selvo Compliance Report",
    framework: str = "general",
) -> Optional[bytes]:
    """Return PDF bytes if weasyprint is available, otherwise None."""
    html = render_pdf_html(packages, title=title, framework=framework)
    try:
        from weasyprint import HTML
        return HTML(string=html).write_pdf()
    except ImportError:
        return None
