"""
Self-contained HTML reporter.

Generates a single .html file with inline CSS and JavaScript — no CDN,
no server, no build step.  Drop the output on any static host or open
locally in a browser.

Features:
  - Summary stats bar (packages, with CVEs, outdated, total blast radius)
  - Sort by any column (click header)
  - Filter/search by package name or CVE ID
  - Ecosystem badge filters + CVE/outdated quick-filters
  - Blast Radius column (transitive reverse-dep count, formatted K/M)
  - Version cell merges installed + upstream with amber arrow when outdated
  - CVE pill expands on click to show all IDs
  - Colour-coded EPSS (red ≥0.1, amber ≥0.01) and CVSS (≥7 red, ≥4 amber)
  - is_outdated read directly from JSON, not re-derived from version strings
"""
from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

from selvo.discovery.base import PackageRecord

if TYPE_CHECKING:
    from selvo.analysis.local_context import SystemContext

_TS_PLACEHOLDER = "__CODUP_GENERATED_AT__"
_JSON_PLACEHOLDER = "__CODUP_JSON_DATA__"
_CTX_PLACEHOLDER = "__CODUP_CTX_BADGE__"
_TREND_PLACEHOLDER = "__CODUP_TREND_HTML__"
_CTA_PLACEHOLDER = "__CODUP_CTA_HTML__"

_CTA_BLOCK = """\
<div class="cta-banner">
  <div class="cta-text">
    <strong>Want this for your infrastructure?</strong>
    Continuous scanning, fleet monitoring, SARIF exports, Slack alerts.
  </div>
  <a class="cta-btn" href="https://selvo.dev" target="_blank">Try selvo free</a>
</div>"""

_HTML: str = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>selvo — Linux Core Dependency Risk Report</title>
<style>
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--bg4:#2d333b;
  --border:#30363d;--text:#c9d1d9;--muted:#8b949e;
  --red:#f85149;--amber:#e3b341;--green:#3fb950;--blue:#58a6ff;
  --purple:#bc8cff;--cyan:#79c0ff;--orange:#f0883e;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:13px/1.5 ui-monospace,monospace;padding:1.5rem}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}

/* ── Header ── */
header{display:flex;align-items:baseline;gap:1rem;margin-bottom:1.25rem;flex-wrap:wrap}
header h1{font-size:1.35rem;color:var(--blue);white-space:nowrap}
header h1 span{color:var(--muted);font-weight:400}
.meta{color:var(--muted);font-size:.78rem}
.ctx-badge{display:inline-block;font-size:.72rem;padding:.12rem .55rem;
  border-radius:4px;white-space:nowrap;vertical-align:middle;font-family:ui-monospace,monospace}
.ctx-reference{background:rgba(88,166,255,.12);color:var(--cyan);
  border:1px solid rgba(88,166,255,.35)}
.ctx-local{background:rgba(63,185,80,.12);color:var(--green);
  border:1px solid rgba(63,185,80,.35)}

/* ── Summary stats ── */
.stats{display:flex;gap:.75rem;margin-bottom:1.25rem;flex-wrap:wrap}
.stat-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
  padding:.55rem 1rem;min-width:120px;flex:1}
.stat-card .label{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em}
.stat-card .value{font-size:1.3rem;font-weight:700;margin-top:.1rem}
.stat-card.red .value{color:var(--red)}
.stat-card.amber .value{color:var(--amber)}
.stat-card.blue .value{color:var(--blue)}
.stat-card.green .value{color:var(--green)}

/* ── Controls ── */
.controls{display:flex;gap:.6rem;margin-bottom:.85rem;flex-wrap:wrap;align-items:center}
input[type=text]{background:var(--bg3);border:1px solid var(--border);color:var(--text);
  padding:.32rem .65rem;border-radius:6px;font:inherit;width:240px}
input[type=text]:focus{outline:none;border-color:var(--blue)}
.filter-btns{display:flex;gap:.35rem;flex-wrap:wrap}
.filter-btn{background:var(--bg3);border:1px solid var(--border);color:var(--muted);
  padding:.22rem .6rem;border-radius:99px;cursor:pointer;font:inherit;font-size:.75rem;transition:all .15s}
.filter-btn:hover{border-color:var(--blue);color:var(--text)}
.filter-btn.active{background:var(--blue);border-color:var(--blue);color:#0d1117;font-weight:700}
.filter-btn.active-red{background:rgba(248,81,73,.2);border-color:var(--red);color:var(--red)}
.filter-btn.active-amber{background:rgba(227,179,65,.2);border-color:var(--amber);color:var(--amber)}
.sep{width:1px;background:var(--border);margin:0 .15rem;align-self:stretch}
.count{color:var(--muted);font-size:.82rem;margin-left:auto;align-self:center;white-space:nowrap}

/* ── Table ── */
.tbl-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--border)}
table{border-collapse:collapse;width:100%;min-width:980px}
thead th{background:var(--bg2);color:var(--muted);font-weight:600;font-size:.75rem;
  text-transform:uppercase;letter-spacing:.05em;padding:.5rem .7rem;
  text-align:left;white-space:nowrap;cursor:pointer;user-select:none;
  position:sticky;top:0;z-index:1;border-bottom:1px solid var(--border)}
thead th:hover{color:var(--text)}
thead th.sorted-asc::after{content:" ↑";color:var(--blue)}
thead th.sorted-desc::after{content:" ↓";color:var(--blue)}
thead th.sorted-asc,thead th.sorted-desc{color:var(--blue)}
tbody tr{border-top:1px solid var(--border);transition:background .1s}
tbody tr:hover{background:var(--bg2)}
tbody td{padding:.45rem .7rem;font-size:.8rem;vertical-align:top}

/* ── Cell styles ── */
.pkg-name{font-weight:700;color:var(--cyan);white-space:nowrap}
.eco-badge{display:inline-block;padding:.08rem .4rem;border-radius:4px;font-size:.68rem;
  background:var(--bg3);border:1px solid var(--border);white-space:nowrap;margin:.05rem .05rem 0 0}
.eco-debian,.eco-ubuntu{color:var(--purple);border-color:var(--purple)}
.eco-fedora{color:var(--amber);border-color:var(--amber)}
.eco-alpine{color:var(--green);border-color:var(--green)}
.eco-arch{color:var(--blue);border-color:var(--blue)}
.eco-nixos{color:var(--cyan);border-color:var(--cyan)}

/* version cell */
.ver-cell{white-space:nowrap}
.ver-installed{color:var(--muted)}
.ver-arrow{color:var(--amber);margin:0 .2rem}
.ver-upstream-outdated{color:var(--amber);font-weight:600}
.ver-upstream-current{color:var(--green)}
.ver-unknown{color:var(--muted)}

/* badges */
.badge{display:inline-block;padding:.08rem .4rem;border-radius:4px;font-size:.73rem;
  border:1px solid;white-space:nowrap}
.badge-red{color:var(--red);border-color:rgba(248,81,73,.5);background:rgba(248,81,73,.1)}
.badge-amber{color:var(--amber);border-color:rgba(227,179,65,.5);background:rgba(227,179,65,.1)}
.badge-green{color:var(--green);border-color:rgba(63,185,80,.5);background:rgba(63,185,80,.1)}
.badge-muted{color:var(--muted);border-color:var(--border);background:transparent}

/* cve cell */
.cve-count{display:inline-block;background:rgba(248,81,73,.12);color:var(--red);
  border:1px solid rgba(248,81,73,.35);border-radius:4px;padding:.05rem .45rem;
  font-size:.75rem;cursor:pointer;user-select:none}
.cve-count:hover{background:rgba(248,81,73,.22)}
.cve-list{display:none;margin-top:.3rem;font-size:.7rem;color:var(--muted);line-height:1.8;max-width:260px;word-break:break-all}
.cve-list.open{display:block}
.cve-list a{color:var(--muted)}
.cve-list a:hover{color:var(--red)}

/* blast radius */
.blast{font-weight:600;font-size:.82rem}
.blast-hi{color:var(--red)}
.blast-mid{color:var(--amber)}
.blast-lo{color:var(--muted)}

/* score */
.score{font-weight:700;font-size:.95rem}
.score-hi{color:var(--red)}.score-mid{color:var(--amber)}.score-lo{color:var(--muted)}

/* repo link */
.repo-link{font-size:.73rem;display:block;max-width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

.none{color:var(--muted)}
/* exploit / KEV / OSS-Fuzz badges */
.badge-kev{color:#f85149;border-color:rgba(248,81,73,.6);background:rgba(248,81,73,.18);font-weight:700}
.badge-ossfuzz{color:var(--green);border-color:rgba(63,185,80,.5);background:rgba(63,185,80,.1)}
/* SLA band badges */
.sla-badge{display:inline-block;padding:.06rem .38rem;border-radius:4px;font-size:.7rem;border:1px solid;white-space:nowrap}
.sla-critical{color:#f85149;border-color:rgba(248,81,73,.6);background:rgba(248,81,73,.15);font-weight:700}
.sla-breach{color:#f85149;border-color:rgba(248,81,73,.4);background:rgba(248,81,73,.08)}
.sla-warn{color:var(--amber);border-color:rgba(227,179,65,.5);background:rgba(227,179,65,.1)}
.sla-ok{color:var(--green);border-color:rgba(63,185,80,.3);background:transparent}
/* trend sparklines */
.trend-bar{margin-bottom:1.25rem}
.trend-header{font-size:.72rem;color:var(--muted);text-transform:uppercase;
  letter-spacing:.07em;margin-bottom:.5rem}
.trend-meta{font-weight:400;text-transform:none;letter-spacing:0}
.trend-cards{display:flex;gap:.6rem;flex-wrap:wrap}
.trend-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
  padding:.5rem .8rem;min-width:140px;flex:1}
.trend-label{color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.04em}
.trend-value{font-size:1.1rem;font-weight:700;margin:.08rem 0 .3rem}
.trend-spark svg{display:block}
footer{margin-top:2rem;color:var(--muted);font-size:.73rem;text-align:center}
/* ── CTA banner ── */
.cta-banner{display:flex;align-items:center;justify-content:space-between;gap:1rem;
  background:linear-gradient(135deg,rgba(88,166,255,.08),rgba(188,140,255,.08));
  border:1px solid rgba(88,166,255,.25);border-radius:8px;padding:.75rem 1.25rem;margin-bottom:1.25rem}
.cta-text{font-size:.82rem;color:var(--text)}
.cta-text strong{color:var(--blue)}
.cta-btn{display:inline-block;background:var(--blue);color:#0d1117;font-weight:700;
  padding:.4rem 1.1rem;border-radius:6px;font-size:.8rem;white-space:nowrap;text-decoration:none}
.cta-btn:hover{text-decoration:none;opacity:.9}
</style>
</head>
<body>
<header>
  <h1>🔐 selvo <span>— Linux Core Dependency Risk Report</span></h1>
  <div class="meta">Generated __CODUP_GENERATED_AT__ &nbsp;&middot;&nbsp; __CODUP_CTX_BADGE__ &nbsp;&middot;&nbsp; <a href="https://selvo.dev" target="_blank">selvo.dev</a></div>
</header>

__CODUP_CTA_HTML__

<div class="stats" id="stats-bar"></div>

__CODUP_TREND_HTML__

<div class="controls">
  <input type="text" id="search" placeholder="Search package or CVE ID…" oninput="applyFilters()">
  <div class="filter-btns" id="eco-btns"></div>
  <div class="sep"></div>
  <div class="filter-btns">
    <button class="filter-btn" id="btn-cves" onclick="toggleQuick('cves',this)">Has CVEs</button>
    <button class="filter-btn" id="btn-outdated" onclick="toggleQuick('outdated',this)">Outdated</button>
    <button class="filter-btn" id="btn-kev" onclick="toggleQuick('kev',this)">KEV</button>
    <button class="filter-btn" id="btn-weaponized" onclick="toggleQuick('weaponized',this)">Weaponized</button>
  </div>
  <span class="count" id="count-label"></span>
</div>

<div class="tbl-wrap">
<table id="tbl">
<thead>
<tr>
  <th data-col="rank" onclick="sortBy(this)">#</th>
  <th data-col="name" onclick="sortBy(this)">Package</th>
  <th data-col="ecosystems" onclick="sortBy(this)">Ecosystems</th>
  <th data-col="version_sort" onclick="sortBy(this)">Version</th>
  <th data-col="cve_count" onclick="sortBy(this)">CVEs</th>
  <th data-col="max_epss" onclick="sortBy(this)">EPSS</th>
  <th data-col="max_cvss" onclick="sortBy(this)">CVSS</th>
  <th data-col="exploit_level" onclick="sortBy(this)">Exploit</th>
  <th data-col="sla_order" onclick="sortBy(this)">SLA</th>
  <th data-col="transitive_rdep_count" onclick="sortBy(this)">Blast Radius</th>
  <th data-col="score" onclick="sortBy(this)">Score</th>
  <th>Upstream Repo</th>
</tr>
</thead>
<tbody id="tbody"></tbody>
</table>
</div>

<div style="margin-top:2rem;padding:1rem 1.25rem;background:var(--bg2);border:1px solid var(--border);border-radius:8px;font-size:.78rem;color:var(--muted);line-height:1.6">
  <strong style="color:var(--text)">About this report</strong><br>
  Packages are ranked by a composite risk score (0–100) combining: dependency blast radius (22%),
  EPSS exploit probability (20%), betweenness centrality (15%), version lag (14%), CVSS severity (10%),
  exploit maturity (8%), ecosystem popularity (7%), download count (2%), and exposure days (2%).
  CVEs already resolved by distro backports are excluded via the Debian Security Tracker.
  Data sources: OSV.dev, FIRST.org EPSS, NVD, CISA KEV, Repology.
  <a href="https://selvo.dev/#methodology" target="_blank">Full methodology →</a>
</div>

<footer>
  selvo — Linux dependency risk scanner &nbsp;·&nbsp;
  <a href="https://selvo.dev" target="_blank">selvo.dev</a> &nbsp;·&nbsp;
  <a href="https://selvo.dev/#methodology" target="_blank">How it works</a> &nbsp;·&nbsp;
  <a href="https://selvo.dev/privacy" target="_blank">Privacy</a> &nbsp;·&nbsp;
  <a href="data.json" target="_blank">raw JSON</a> &nbsp;·&nbsp;
  <a href="report.sbom.json" target="_blank">CycloneDX SBOM</a>
</footer>

<script>
const RAW = __CODUP_JSON_DATA__;

const DATA = RAW.map((p, i) => ({
  rank: i + 1,
  name: p.name || "",
  ecosystems: (p.ecosystem || "").split(",").map(s => s.trim()).filter(Boolean),
  version: p.version && p.version !== "unknown" ? p.version : null,
  upstream_version: p.upstream_version || null,
  is_outdated: !!p.is_outdated,
  cve_count: (p.cve_ids || []).length,
  cve_ids: p.cve_ids || [],
  max_epss: p.max_epss || 0,
  max_cvss: p.max_cvss || 0,
  transitive_rdep_count: p.transitive_rdep_count || 0,
  score: p.score || 0,
  upstream_repo: p.upstream_repo || null,
  version_sort: p.version && p.version !== "unknown" ? p.version : "",
  // new fields
  exploit_maturity: p.exploit_maturity || "none",
  in_cisa_kev: !!p.in_cisa_kev,
  ossfuzz_covered: !!p.ossfuzz_covered,
  ossfuzz_project: p.ossfuzz_project || "",
  sla_band: p.sla_band || "",
  sla_days_overdue: p.sla_days_overdue || 0,
  vendor_advisory_ids: p.vendor_advisory_ids || [],
  changelog_summary: p.changelog_summary || "",
  // sortable computed fields
  exploit_level: (p.exploit_maturity === "weaponized" ? 3 : p.exploit_maturity === "poc" ? 2 : 0) + (p.in_cisa_kev ? 1 : 0),
  sla_order: ({critical:4, breach:3, warn:2, ok:1}[p.sla_band] || 0),
}));

// Summary stats
function buildStats() {
  const total = DATA.length;
  const withCves = DATA.filter(d => d.cve_count > 0).length;
  const outdated = DATA.filter(d => d.is_outdated).length;
  const totalBlast = DATA.reduce((s, d) => s + d.transitive_rdep_count, 0);
  const kevCount = DATA.filter(d => d.in_cisa_kev).length;
  const wpznCount = DATA.filter(d => d.exploit_maturity === "weaponized").length;
  const fmtK = n => n >= 1e6 ? (n/1e6).toFixed(1)+"M" : n >= 1e3 ? (n/1e3).toFixed(0)+"K" : n;
  const cards = [
    {label:"Packages Analysed", value: total, cls:"blue"},
    {label:"With CVEs", value: withCves, cls:"red"},
    {label:"Outdated", value: outdated, cls:"amber"},
    {label:"CISA KEV", value: kevCount, cls:"red"},
    {label:"Weaponized", value: wpznCount, cls:"red"},
    {label:"Total Blast Radius", value: fmtK(totalBlast), cls:"green"},
  ];
  document.getElementById("stats-bar").innerHTML = cards.map(c =>
    `<div class="stat-card ${c.cls}"><div class="label">${c.label}</div><div class="value">${c.value}</div></div>`
  ).join("");
}
buildStats();

const ECO_SET = [...new Set(DATA.flatMap(d => d.ecosystems))].sort();
let sortCol = "score", sortDir = -1, ecoFilter = "all", searchQ = "";
let quickCves = false, quickOutdated = false, quickKev = false, quickWpzn = false;

const btnWrap = document.getElementById("eco-btns");
["all", ...ECO_SET].forEach(eco => {
  const b = document.createElement("button");
  b.className = "filter-btn" + (eco === "all" ? " active" : "");
  b.textContent = eco;
  b.onclick = () => {
    ecoFilter = eco;
    btnWrap.querySelectorAll(".filter-btn").forEach(x => x.classList.remove("active"));
    b.classList.add("active");
    applyFilters();
  };
  btnWrap.appendChild(b);
});

function toggleQuick(type, btn) {
  if (type === "cves") {
    quickCves = !quickCves;
    btn.classList.toggle("active-red", quickCves);
  } else if (type === "outdated") {
    quickOutdated = !quickOutdated;
    btn.classList.toggle("active-amber", quickOutdated);
  } else if (type === "kev") {
    quickKev = !quickKev;
    btn.classList.toggle("active-red", quickKev);
  } else {
    quickWpzn = !quickWpzn;
    btn.classList.toggle("active-red", quickWpzn);
  }
  applyFilters();
}

function fmtBlast(n) {
  if (!n) return '<span class="none">—</span>';
  const s = n >= 1e6 ? (n/1e6).toFixed(2)+"M" : n >= 1e3 ? (n/1e3).toFixed(1)+"K" : String(n);
  const cls = n >= 20000 ? "blast-hi" : n >= 5000 ? "blast-mid" : "blast-lo";
  return `<span class="blast ${cls}" title="${n.toLocaleString()} packages transitively depend on this">${s}</span>`;
}

function fmtEpss(v) {
  if (!v) return '<span class="none">—</span>';
  const cls = v >= 0.1 ? "badge-red" : v >= 0.01 ? "badge-amber" : "badge-muted";
  return `<span class="badge ${cls}" title="EPSS: probability this CVE is exploited in the next 30 days">${(v*100).toFixed(1)}%</span>`;
}

function fmtCvss(v) {
  if (!v) return '<span class="none">—</span>';
  const cls = v >= 7 ? "badge-red" : v >= 4 ? "badge-amber" : "badge-muted";
  return `<span class="badge ${cls}">${v.toFixed(1)}</span>`;
}

function fmtVersion(d) {
  const ins = d.version || '<span class="ver-unknown">unknown</span>';
  const up = d.upstream_version;
  if (!up) return `<span class="ver-installed">${ins}</span>`;
  if (d.is_outdated) {
    return `<span class="ver-installed">${ins}</span><span class="ver-arrow">→</span><span class="ver-upstream-outdated" title="Outdated: upstream is ${up}">${up}</span>`;
  }
  return `<span class="ver-installed">${ins}</span><span class="ver-arrow">·</span><span class="ver-upstream-current" title="Up to date">${up}</span>`;
}

function fmtCves(d) {
  if (!d.cve_count) return '<span class="none">—</span>';
  const links = d.cve_ids.map(c =>
    `<a href="https://nvd.nist.gov/vuln/detail/${c}" target="_blank">${c}</a>`
  ).join("<br>");
  const id = "cve-" + d.name.replace(/[^a-z0-9]/gi,"-");
  return `<span class="cve-count" onclick="var el=document.getElementById('${id}');el.classList.toggle('open')">${d.cve_count} CVE${d.cve_count>1?"s":""}</span><div class="cve-list" id="${id}">${links}</div>`;
}

function fmtEcos(ecos) {
  return ecos.map(e => `<span class="eco-badge eco-${e}">${e}</span>`).join("");
}

function fmtScore(v) {
  if (!v) return '<span class="none">—</span>';
  const cls = v >= 40 ? "score-hi" : v >= 20 ? "score-mid" : "score-lo";
  return `<span class="score ${cls}">${v.toFixed(1)}</span>`;
}

function fmtExploit(d) {
  const parts = [];
  if (d.in_cisa_kev) parts.push('<span class="badge badge-kev" title="CISA Known Exploited Vulnerability">\uD83D\uDD11 KEV</span>');
  if (d.exploit_maturity === "weaponized") parts.push('<span class="badge badge-red" title="Weaponized exploit available">\uD83D\uDCA3 Armed</span>');
  else if (d.exploit_maturity === "poc") parts.push('<span class="badge badge-amber" title="Public PoC available">\uD83D\uDD2C PoC</span>');
  if (d.ossfuzz_covered) parts.push(`<span class="badge badge-ossfuzz" title="OSS-Fuzz: ${d.ossfuzz_project || 'covered'}">\uD83D\uDEE1 Fuzz</span>`);
  if (d.vendor_advisory_ids && d.vendor_advisory_ids.length > 0) parts.push(`<span class="badge badge-muted" title="${d.vendor_advisory_ids.join(', ')}">${d.vendor_advisory_ids.length} adv</span>`);
  return parts.length ? parts.join(" ") : '<span class="none">—</span>';
}

function fmtSla(d) {
  if (!d.sla_band) return '<span class="none">—</span>';
  const cfg = {critical:{cls:"sla-critical",label:"critical"},breach:{cls:"sla-breach",label:"breach"},warn:{cls:"sla-warn",label:"warn"},ok:{cls:"sla-ok",label:"ok"}}[d.sla_band] || {cls:"",label:d.sla_band};
  const over = d.sla_days_overdue > 0 ? ` +${d.sla_days_overdue}d` : "";
  return `<span class="sla-badge ${cfg.cls}">${cfg.label}${over}</span>`;
}

function renderRow(d) {
  const repoLink = d.upstream_repo
    ? `<a class="repo-link" href="${d.upstream_repo}" target="_blank" title="${d.upstream_repo}">${d.upstream_repo.replace(/https?:\\/\\/(www\\.)?(github|gitlab)\\.com\\//,"")}</a>`
    : '<span class="none">—</span>';
  return `<tr>
    <td class="none">${d.rank}</td>
    <td class="pkg-name">${d.name}</td>
    <td>${fmtEcos(d.ecosystems)}</td>
    <td class="ver-cell">${fmtVersion(d)}</td>
    <td>${fmtCves(d)}</td>
    <td>${fmtEpss(d.max_epss)}</td>
    <td>${fmtCvss(d.max_cvss)}</td>    <td>${fmtExploit(d)}</td>
    <td>${fmtSla(d)}</td>    <td>${fmtBlast(d.transitive_rdep_count)}</td>
    <td>${fmtScore(d.score)}</td>
    <td>${repoLink}</td>
  </tr>`;
}

function applyFilters() {
  searchQ = document.getElementById("search").value.toLowerCase();
  let filtered = DATA.filter(d => {
    if (ecoFilter !== "all" && !d.ecosystems.includes(ecoFilter)) return false;
    if (quickCves && d.cve_count === 0) return false;
    if (quickOutdated && !d.is_outdated) return false;
    if (quickKev && !d.in_cisa_kev) return false;
    if (quickWpzn && d.exploit_maturity !== "weaponized") return false;
    if (searchQ) {
      const nameMatch = d.name.toLowerCase().includes(searchQ);
      const cveMatch = d.cve_ids.some(c => c.toLowerCase().includes(searchQ));
      if (!nameMatch && !cveMatch) return false;
    }
    return true;
  });

  filtered.sort((a, b) => {
    let av = a[sortCol], bv = b[sortCol];
    if (typeof av === "string") return sortDir * av.localeCompare(bv);
    return sortDir * ((av||0) - (bv||0));
  });

  // Re-number after filter
  document.getElementById("tbody").innerHTML = filtered.map((d,i) => {
    const orig = d.rank; d.rank = i+1; const html = renderRow(d); d.rank = orig; return html;
  }).join("");
  document.getElementById("count-label").textContent = `${filtered.length} / ${DATA.length} packages`;
}

function sortBy(th) {
  const col = th.dataset.col;
  sortDir = col === sortCol ? sortDir * -1 : -1;
  sortCol = col;
  document.querySelectorAll("thead th").forEach(t => t.classList.remove("sorted-asc","sorted-desc"));
  th.classList.add(sortDir === -1 ? "sorted-desc" : "sorted-asc");
  applyFilters();
}

// Initial render
document.querySelector("[data-col='score']").classList.add("sorted-desc");
applyFilters();
</script>
</body>
</html>
"""


def render_html(
    packages: list[PackageRecord],
    ctx: Optional["SystemContext"] = None,
    trend_metrics: Optional[list[dict]] = None,
    cta: bool = True,
) -> str:
    """Return a self-contained HTML report for the given packages.

    Args:
        packages: Scored package list from the analysis pipeline.
        ctx: Optional system context (local vs. reference mode).
        trend_metrics: Optional list of historical metric dicts from
            :func:`selvo.analysis.trend.load_metrics` to render sparklines.
        cta: Show the SaaS call-to-action banner (default True).
    """
    _strip = {"fix_refs", "dependents", "dependencies"}
    slim = []
    for p in packages:
        d = {k: v for k, v in dataclasses.asdict(p).items() if k not in _strip}
        d["is_outdated"] = p.is_outdated  # inject computed property
        slim.append(d)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Trend sparklines
    if trend_metrics:
        from selvo.analysis.trend import render_trend_html
        trend_html = render_trend_html(trend_metrics)
    else:
        trend_html = ""

    # Context badge
    if ctx is None:
        ctx_badge = ""
    elif ctx.mode == "local":
        label = ctx.os_name or "Local"
        if ctx.os_version:
            label += f" {ctx.os_version}"
        if ctx.hostname:
            label += f" \u00b7 {ctx.hostname}"
        ctx_badge = f'<span class="ctx-badge ctx-local">\U0001f5a5 Local \u00b7 {label}</span>'
    else:
        ctx_badge = '<span class="ctx-badge ctx-reference">\u2699 Reference \u00b7 Debian stable</span>'

    return (
        _HTML
        .replace(_TS_PLACEHOLDER, ts)
        .replace(_CTX_PLACEHOLDER, ctx_badge)
        .replace(_CTA_PLACEHOLDER, _CTA_BLOCK if cta else "")
        .replace(_TREND_PLACEHOLDER, trend_html)
        # Escape </script> sequences inside the JSON blob so they can't
        # prematurely close the surrounding <script> tag (OWASP XSS defence).
        .replace(
            _JSON_PLACEHOLDER,
            json.dumps(slim, separators=(",", ":")).replace("</", "<\\/"),
        )
    )
