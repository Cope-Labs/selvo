"""Server-side web dashboard for selvo SaaS.

Rendered with Jinja2 + htmx — no client-side build step required.

Routes (all under /dash/):
    GET  /dash/            → redirect to /dash/overview
    GET  /dash/overview    → summary cards + top-10 risk table, HTMX live-reload
    GET  /dash/packages    → filterable package table (htmx-powered search)
    GET  /dash/cves        → CVE listing with EPSS + KEV badges
    GET  /dash/trends      → sparkline time-series chart (SVG inline)
    GET  /dash/keys        → org API key management UI
    POST /dash/keys        → create a new API key
    POST /dash/keys/revoke → deactivate a key

All pages share a minimal Bootstrap 5 + htmx layout injected as a string
constant so the server has zero static-file dependencies.
"""
from __future__ import annotations

import html as _html
import logging
from datetime import datetime, timezone


def _esc(value: object) -> str:
    """HTML-escape a value for safe embedding in templates."""
    return _html.escape(str(value))

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Inline layout template
# If SELVO_OFFLINE_ASSETS=1 (e.g. air-gap / DoD IL4 environments), all
# external CDN links are replaced with a minimal inline CSS fallback so the
# dashboard renders without any outbound network requests.
# ---------------------------------------------------------------------------

_OFFLINE = bool(int(__import__("os").environ.get("SELVO_OFFLINE_ASSETS", "0")))

_CDN_HEAD = """\
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet" crossorigin="anonymous">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=Space+Grotesk:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js"
          crossorigin="anonymous"></script>"""

_OFFLINE_HEAD = """\
  <style>
    /* Minimal offline layout — no Bootstrap, no CDN */
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font:14px/1.5 ui-sans-serif,system-ui,sans-serif;padding:1rem 1.5rem}}
    .container-fluid{{max-width:1400px;margin:0 auto}}
    nav{{display:flex;gap:1.5rem;padding:.75rem 0;border-bottom:1px solid #30363d;margin-bottom:1.5rem;flex-wrap:wrap}}
    nav a{{text-decoration:none;color:#58a6ff;font-weight:600}}nav a:hover{{text-decoration:underline}}
    table{{border-collapse:collapse;width:100%}}
    th,td{{border:1px solid #30363d;padding:.4rem .7rem;text-align:left;font-size:.82rem}}
    th{{background:#21262d;font-weight:700}}
    input[type=text]{{padding:.3rem .6rem;border:1px solid #555;border-radius:4px;font:inherit}}
    .badge{{display:inline-block;padding:.1rem .4rem;border-radius:4px;font-size:.72rem;border:1px solid}}
    pre{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:.75rem;font-size:.8rem;overflow-x:auto}}
  </style>
  <script>
    /* Minimal htmx substitute for offline mode — reloads target via fetch */
    document.addEventListener('DOMContentLoaded',()=>{{
      document.querySelectorAll('[hx-get]').forEach(el=>{{
        el.addEventListener('change',async()=>{{
          const url=el.getAttribute('hx-get');const target=document.querySelector(el.getAttribute('hx-target')||'body');
          if(!url||!target)return;
          const resp=await fetch(url);target.innerHTML=await resp.text();
        }});
      }});
    }});
  </script>"""

_CDN_FOOTER = """\
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        crossorigin="anonymous"></script>"""

_HEAD = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} — selvo</title>
{cdn_or_offline}
  <style>
    /* Copelabs-adjacent palette, dark-theme tuned. Same hues as the
       marketing site so clicking from copelabs.dev to the dashboard
       feels like the same product, not a different one. */
    :root {{
      --serif: 'DM Serif Display', Georgia, serif;
      --sans-display: 'Space Grotesk', -apple-system, 'Segoe UI', system-ui, sans-serif;
      --soil: #6fae80;         /* INTACT — warm green, brighter-on-dark than copelabs' #4a8c5c */
      --soil-dim: #4a8c5c;     /* subdued INTACT for secondary surfaces */
      --amber-warm: #d1a155;   /* DEGRADED — warm amber instead of bootstrap yellow */
      --ink-red: #c85445;      /* ABLATED — muted red, less klaxon than #da3633 */
      --accent: #e07a4a;       /* matches copelabs --accent #cd5d2f, lightened for dark */
    }}
    body {{ background:#0d1117; color:#e6edf3; }}
    h1,h2,h3,h4,h5,h6,.h1,.h2,.h3,.h4,.h5,.h6 {{ color:#e6edf3; }}
    p,label,li {{ color:#e6edf3; }}
    /* Hero state banner — state-first, serif, calm. Used by /dash/overview. */
    .state-hero {{ padding:1.5rem 1.75rem 1.75rem; margin-bottom:1.5rem;
      background:linear-gradient(180deg, #161b22 0%, #12161e 100%);
      border:1px solid #30363d; border-radius:12px; }}
    .state-hero .state {{ font-family:var(--serif); font-size:2.75rem;
      line-height:1.05; letter-spacing:-0.01em; margin-bottom:.35rem; }}
    .state-hero .state.intact   {{ color:var(--soil); }}
    .state-hero .state.degraded {{ color:var(--amber-warm); }}
    .state-hero .state.ablated  {{ color:var(--ink-red); }}
    .state-hero .state.unknown  {{ color:#8b949e; }}
    .state-hero .sub {{ font-family:var(--sans-display); font-size:1rem;
      color:#c9d1d9; margin-bottom:1.1rem; font-weight:400; }}
    .state-hero .sub strong {{ color:#e6edf3; font-weight:600; }}
    .state-hero .actions {{ display:flex; gap:.6rem; flex-wrap:wrap; }}
    .state-hero .actions .btn {{ font-family:var(--sans-display); font-weight:500;
      letter-spacing:.01em; }}
    .state-hero .meta {{ font-family:var(--sans-display); font-size:.78rem;
      color:#8b949e; margin-top:.9rem; letter-spacing:.02em; }}
    .state-hero .meta .dot {{ opacity:.4; margin:0 .4rem; }}
    /* Compact secondary stats under the hero */
    .mini-stats {{ display:flex; gap:.75rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
    .mini-stat {{ flex:1 1 140px; background:#161b22; border:1px solid #30363d;
      border-radius:8px; padding:.75rem 1rem; }}
    .mini-stat .v {{ font-family:var(--sans-display); font-size:1.4rem; font-weight:600;
      color:#e6edf3; }}
    .mini-stat .l {{ font-family:var(--sans-display); font-size:.72rem; color:#8b949e;
      text-transform:uppercase; letter-spacing:.08em; margin-top:.1rem; }}
    /* CVE year badge — tiny, muted pill rendered next to each CVE link */
    .cve-year {{ display:inline-block; font-family:var(--sans-display); font-size:.65rem;
      font-weight:500; color:#8b949e; border:1px solid #30363d; border-radius:3px;
      padding:.05rem .35rem; margin-left:.35rem; letter-spacing:.04em;
      vertical-align:middle; }}
    .cve-year.old {{ opacity:.55; }}              /* >5 years old — visually de-emphasized */
    .cve-year.recent {{ color:#e6edf3; border-color:#58a6ff; }}
    /* Calm health badge overrides — replace bootstrap's harsh red/yellow */
    .badge-health-intact   {{ background:rgba(111,174,128,.18); color:var(--soil);
      border:1px solid rgba(111,174,128,.4); }}
    .badge-health-degraded {{ background:rgba(209,161,85,.18); color:var(--amber-warm);
      border:1px solid rgba(209,161,85,.4); }}
    .badge-health-ablated  {{ background:rgba(200,84,69,.18); color:var(--ink-red);
      border:1px solid rgba(200,84,69,.4); }}
    .badge-health-recovering {{ background:rgba(88,166,255,.15); color:#79c0ff;
      border:1px solid rgba(88,166,255,.4); }}
    .navbar {{ background:#161b22!important; border-bottom:1px solid #30363d; }}
    .card  {{ background:#161b22; border:1px solid #30363d; }}
    .table {{ color:#e6edf3; }}
    .table thead {{ background:#21262d; }}
    .badge-kev  {{ background:#da3633; }}
    .badge-poc  {{ background:#d29922; color:#0d1117; }}
    .badge-wpn  {{ background:#da3633; }}
    .score-bar  {{ height:6px; border-radius:3px; background:#238636; }}
    .epss-high  {{ color:#f85149; font-weight:600; }}
    .epss-med   {{ color:#d29922; }}
    .nav-link {{ color:#8b949e; }}
    .nav-link:hover,.nav-link.active {{ color:#58a6ff; }}
    .stat-card .display-6 {{ font-size:2rem; font-weight:700; }}
    .display-6 {{ color:#e6edf3; }}
    pre {{ background:#161b22; border:1px solid #30363d; border-radius:6px;
           padding:.75rem; color:#8b949e; font-size:.8rem; }}
    /* Dark-background contrast fixes */
    .text-muted {{ color:#8b949e!important; }}
    code {{ color:#79c0ff; }}
    .table td, .table th {{ border-color:#30363d; }}
    .form-control, .form-select {{ background:#0d1117; color:#e6edf3; border-color:#30363d; }}
    .form-control:focus, .form-select:focus {{ background:#0d1117; color:#e6edf3; border-color:#58a6ff; box-shadow:0 0 0 .15rem rgba(88,166,255,.25); }}
    .btn-outline-secondary {{ color:#8b949e; border-color:#30363d; }}
    .btn-outline-secondary:hover {{ color:#e6edf3; background:#21262d; border-color:#8b949e; }}
    small {{ color:#8b949e; }}
    .badge {{ color:#fff; }}
    .badge-kev, .badge-wpn {{ color:#fff; }}
    .alert-danger {{ background:#da363333; color:#f85149; border-color:#da3633; }}
    .alert-success {{ background:#23863633; color:#3fb950; border-color:#238636; }}
    input[type="text"], input[type="email"], input[type="password"] {{ background:#0d1117; color:#e6edf3; border-color:#30363d; }}
    select {{ background:#0d1117; color:#e6edf3; border-color:#30363d; }}
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg mb-4">
  <div class="container-fluid">
    <a class="navbar-brand fw-bold text-info" href="/dash/overview">⚡ selvo</a>
    <div class="navbar-nav ms-3">
      <a class="nav-link" href="/dash/overview">Overview</a>
      <a class="nav-link text-info fw-bold" href="/dash/scan">Scan</a>
      <a class="nav-link" href="/dash/packages">Packages</a>
      <a class="nav-link" href="/dash/cves">CVEs</a>
      <a class="nav-link" href="/dash/trends">Trends</a>
      <a class="nav-link" href="/dash/policy">Policy</a>
      <a class="nav-link" href="/dash/keys">API Keys</a>
      <a class="nav-link" href="/dash/billing">Billing</a>
      <a class="nav-link ms-3 text-muted" href="/dash/logout">Sign out</a>
    </div>
  </div>
</nav>
<div class="container-fluid px-4">
{body}
</div>
{cdn_footer}
</body>
</html>"""


def _page(title: str, body: str) -> str:
    cdn_or_offline = _OFFLINE_HEAD if _OFFLINE else _CDN_HEAD
    cdn_footer = "" if _OFFLINE else _CDN_FOOTER
    return _HEAD.format(title=title, body=body,
                        cdn_or_offline=cdn_or_offline, cdn_footer=cdn_footer)


def render_login(error: str = "") -> str:
    """Render the dashboard login page — minimal layout, no dashboard nav."""
    err_html = f'<div style="background:#da3633;color:#fff;padding:.5rem .75rem;border-radius:6px;margin-bottom:1rem;font-size:.9rem">{_esc(error)}</div>' if error else ""
    return f"""\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — selvo</title>
<style>
body {{ background:#0d1117; color:#e6edf3; font-family:system-ui,-apple-system,sans-serif; margin:0; }}
.wrap {{ max-width:380px; margin:80px auto; padding:0 1rem; }}
.card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:2rem; }}
h4 {{ color:#58a6ff; margin:0 0 .25rem; }}
.muted {{ color:#8b949e; font-size:.85rem; }}
label {{ display:block; color:#8b949e; font-size:.8rem; margin-bottom:.25rem; }}
input {{ width:100%; padding:.5rem .75rem; background:#0d1117; color:#e6edf3; border:1px solid #30363d;
         border-radius:6px; font-size:.9rem; box-sizing:border-box; }}
input:focus {{ outline:none; border-color:#58a6ff; }}
.mb {{ margin-bottom:1rem; }}
button {{ width:100%; padding:.6rem; background:#1f6feb; color:#fff; border:none; border-radius:6px;
          font-size:.9rem; cursor:pointer; font-weight:600; }}
button:hover {{ background:#388bfd; }}
a {{ color:#58a6ff; text-decoration:none; }}
a:hover {{ text-decoration:underline; }}
.footer {{ text-align:center; margin-top:1.25rem; font-size:.8rem; color:#8b949e; }}
.top {{ padding:1rem 2rem; border-bottom:1px solid #30363d; }}
.top a {{ color:#58a6ff; font-weight:700; font-size:1.1rem; text-decoration:none; }}
</style>
</head>
<body>
<div class="top"><a href="/">selvo</a></div>
<div class="wrap">
  <div class="card">
    <h4>Dashboard Login</h4>
    <p class="muted" style="margin-bottom:1.25rem">Sign in with your org ID and email.</p>
    {err_html}
    <form method="post" action="/dash/login">
      <div class="mb">
        <label for="org_id">Organization ID</label>
        <input type="text" name="org_id" id="org_id" required pattern="[a-zA-Z0-9_-]+"
               placeholder="my-org"
               oninput="this.value=this.value.replace(/\\s/g,'-').replace(/[^a-zA-Z0-9_-]/g,'')">
      </div>
      <div class="mb">
        <label for="email">Email</label>
        <input type="email" name="email" id="email" required placeholder="you@example.com">
      </div>
      <button type="submit">Sign in</button>
    </form>
    <div class="footer">
      Don't have an account? <a href="/">Sign up free</a>
    </div>
  </div>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Public landing page (no auth required)
# ---------------------------------------------------------------------------

_LANDING = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>selvo — Linux Dependency Risk Scanner</title>
<meta name="description" content="Scan your Linux servers for CVEs, rank by blast radius and exploit probability, filter out what your distro already patched. 16 ecosystems, 8 data sources, SARIF/VEX/OSCAL exports.">
<meta name="keywords" content="linux, security, CVE, vulnerability, scanner, EPSS, CVSS, CISA KEV, dependency, blast radius, SARIF, VEX, OSCAL, NIST, FedRAMP">
<link rel="canonical" href="https://selvo.dev/">
<meta property="og:type" content="website">
<meta property="og:url" content="https://selvo.dev/">
<meta property="og:title" content="selvo — Linux Dependency Risk Scanner">
<meta property="og:description" content="Know what's actually dangerous on your Linux servers. Prioritized CVE scanning with distro backport filtering, blast radius scoring, and exploit intelligence.">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="selvo — Linux Dependency Risk Scanner">
<meta name="twitter:description" content="Scan Linux packages, rank by blast radius and exploit probability, filter what your distro already patched. Free tier available.">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>&#x26A1;</text></svg>">
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
  --text:#c9d1d9;--muted:#8b949e;--blue:#58a6ff;--green:#3fb950;
  --red:#f85149;--amber:#e3b341;--purple:#bc8cff;--cyan:#79c0ff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:15px/1.6 -apple-system,system-ui,sans-serif}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}

/* nav */
.nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 2rem;
  border-bottom:1px solid var(--border);max-width:1200px;margin:0 auto}
.nav-brand{font-weight:700;font-size:1.2rem;color:var(--cyan)}
.nav-links{display:flex;gap:1.5rem;align-items:center}
.nav-links a{color:var(--muted);font-size:.9rem}
.nav-links a:hover{color:var(--text)}
.btn{display:inline-block;padding:.5rem 1.2rem;border-radius:6px;font-weight:600;
  font-size:.9rem;cursor:pointer;border:none;text-decoration:none}
.btn-primary{background:var(--blue);color:#0d1117}.btn-primary:hover{opacity:.9;text-decoration:none}
.btn-outline{border:1px solid var(--border);color:var(--text);background:transparent}
.btn-outline:hover{border-color:var(--blue);text-decoration:none}
.btn-green{background:var(--green);color:#0d1117}.btn-green:hover{opacity:.9;text-decoration:none}

/* hero */
.hero{text-align:center;padding:5rem 2rem 3rem;max-width:800px;margin:0 auto}
.hero h1{font-size:2.8rem;font-weight:800;line-height:1.15;margin-bottom:1rem}
.hero h1 span{color:var(--blue)}
.hero p{font-size:1.15rem;color:var(--muted);margin-bottom:2rem;max-width:600px;margin-left:auto;margin-right:auto}
.hero-btns{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap}

/* features */
.features{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.5rem;
  max-width:1100px;margin:0 auto;padding:3rem 2rem}
.feature{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:1.5rem}
.feature h3{font-size:1rem;margin-bottom:.5rem;color:var(--text)}
.feature p{font-size:.88rem;color:var(--muted);line-height:1.5}
.feature .icon{font-size:1.5rem;margin-bottom:.75rem}

/* how it works */
.how{max-width:800px;margin:0 auto;padding:3rem 2rem}
.how h2{text-align:center;font-size:1.5rem;margin-bottom:2rem}
.steps{display:flex;flex-direction:column;gap:1rem}
.step{display:flex;gap:1rem;align-items:flex-start;background:var(--bg2);
  border:1px solid var(--border);border-radius:8px;padding:1.2rem}
.step-num{font-size:1.3rem;font-weight:800;color:var(--blue);min-width:2rem}
.step-text h4{font-size:.95rem;margin-bottom:.25rem}
.step-text p{font-size:.85rem;color:var(--muted)}
.step code{background:var(--bg3);padding:.15rem .4rem;border-radius:4px;font-size:.82rem}

/* pricing */
.pricing{max-width:1000px;margin:0 auto;padding:3rem 2rem}
.pricing h2{text-align:center;font-size:1.5rem;margin-bottom:.5rem}
.pricing-sub{text-align:center;color:var(--text);margin-bottom:2rem;font-size:.9rem}
.plans{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1.5rem}
.plan{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:1.5rem;
  display:flex;flex-direction:column}
.plan.featured{border-color:var(--blue);box-shadow:0 0 20px rgba(88,166,255,.1)}
.plan h3{font-size:1.1rem;margin-bottom:.5rem;color:var(--text)}
.plan .price{font-size:2rem;font-weight:800;margin-bottom:.25rem;color:#e6edf3}
.plan .price span{font-size:.9rem;font-weight:400;color:var(--text)}
.plan .desc{font-size:.85rem;color:var(--text);margin-bottom:1rem}
.plan ul{list-style:none;margin-bottom:1.5rem;flex:1}
.plan li{font-size:.85rem;padding:.3rem 0;color:var(--text)}
.plan li::before{content:"\\2713 ";color:var(--green);font-weight:700}
.plan .btn{text-align:center;width:100%}

/* signup section */
.signup{max-width:500px;margin:0 auto;padding:3rem 2rem}
.signup h2{text-align:center;font-size:1.5rem;margin-bottom:.5rem}
.signup-sub{text-align:center;color:var(--text);margin-bottom:1.5rem;font-size:.9rem}
.form-group{margin-bottom:1rem}
.form-group label{display:block;font-size:.85rem;color:var(--text);margin-bottom:.3rem}
.form-group input,.form-group select{width:100%;padding:.55rem .75rem;background:var(--bg3);
  border:1px solid var(--border);border-radius:6px;color:var(--text);font:inherit;font-size:.9rem}
.form-group input:focus,.form-group select:focus{outline:none;border-color:var(--blue)}
.form-error{color:var(--red);font-size:.85rem;margin-bottom:1rem}
.form-success{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.3);
  border-radius:8px;padding:1rem;margin-bottom:1rem}
.key-display{background:var(--bg3);border:1px solid var(--border);border-radius:6px;
  padding:.75rem;font-family:monospace;font-size:.85rem;word-break:break-all;
  margin:.75rem 0;color:var(--amber)}

/* footer */
.foot{text-align:center;padding:3rem 2rem 2rem;color:var(--muted);font-size:.8rem;
  border-top:1px solid var(--border);max-width:1200px;margin:3rem auto 0}
</style>
</head>
<body>

<div class="nav">
  <a class="nav-brand" href="/">selvo</a>
  <div class="nav-links">
    <a href="#demo">Live Demo</a>
    <a href="#pricing">Pricing</a>
    <a href="/dash/overview">Dashboard</a>
    <a class="btn btn-outline" href="/dash/login">Log In</a>
    <a class="btn btn-primary" href="#signup">Sign Up Free</a>
  </div>
</div>

<div class="hero">
  <h1>Know what's <span>actually dangerous</span> on your Linux servers</h1>
  <p>Other scanners dump 50 CVEs. We tell you which 3 to actually patch. Distro backport filtering, blast radius scoring, and exploit probability — not just a CVSS number.</p>
  <div class="hero-btns">
    <a class="btn btn-primary" href="#signup">Scan Your System — Free</a>
    <a class="btn btn-outline" href="#demo">See Live Results</a>
  </div>
</div>

<!-- Inline demo: real scan results, no signup required -->
<div class="how" id="demo" style="padding-top:2rem">
  <h2>Real Scan Results — Debian 12</h2>
  <p style="text-align:center;color:var(--muted);font-size:.9rem;margin-bottom:1.5rem">
    This is what selvo found on a stock Debian 12 install. Updated daily.
  </p>
  <div style="max-width:800px;margin:0 auto">
    <table style="width:100%;border-collapse:collapse;font-size:.85rem">
      <thead>
        <tr style="border-bottom:2px solid var(--border);text-align:left">
          <th style="padding:.5rem">Package</th>
          <th style="padding:.5rem;text-align:right">Score</th>
          <th style="padding:.5rem;text-align:center">Health</th>
          <th style="padding:.5rem;text-align:right">CVEs</th>
          <th style="padding:.5rem;text-align:right">CVSS</th>
          <th style="padding:.5rem;text-align:right">EPSS</th>
        </tr>
      </thead>
      <tbody id="demo-table">
        <tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--muted)">Loading live data...</td></tr>
      </tbody>
    </table>
    <p style="text-align:center;margin-top:1rem;font-size:.8rem;color:var(--muted)">
      <a href="https://copelabs.dev/selvo-report/" target="_blank" class="text-info">Full interactive report &#x2192;</a>
      &nbsp;&middot;&nbsp; Powered by 8 data sources &nbsp;&middot;&nbsp; 16 ecosystems supported
    </p>
  </div>
</div>
<script>
fetch("https://copelabs.dev/selvo-report/data.json")
  .then(r=>r.json()).then(d=>{
    const pkgs=(Array.isArray(d)?d:d.packages||d.data||[])
      .filter(p=>(p.cve_count||p.cve_ids&&p.cve_ids.length)>0)
      .sort((a,b)=>(b.score||0)-(a.score||0)).slice(0,8);
    const hc={"ABLATED":"#da3633","DEGRADED":"#d29922","INTACT":"#238636"};
    document.getElementById("demo-table").innerHTML=pkgs.map(p=>{
      const h=p.health_state||"";
      const c=hc[h]||"#8b949e";
      return "<tr style='border-bottom:1px solid #30363d'>"+
        "<td style='padding:.4rem .5rem;font-weight:600'>"+p.name+"</td>"+
        "<td style='padding:.4rem .5rem;text-align:right'>"+p.score.toFixed(1)+
          "<span style='color:#8b949e;font-size:.7em'> &plusmn;"+(p.score_uncertainty||0).toFixed(0)+"</span></td>"+
        "<td style='padding:.4rem .5rem;text-align:center'><span style='background:"+c+
          ";color:#fff;padding:.1rem .4rem;border-radius:4px;font-size:.7rem'>"+h+"</span></td>"+
        "<td style='padding:.4rem .5rem;text-align:right'>"+(p.cve_count||p.cve_ids.length)+"</td>"+
        "<td style='padding:.4rem .5rem;text-align:right'>"+(p.max_cvss||0).toFixed(1)+"</td>"+
        "<td style='padding:.4rem .5rem;text-align:right'>"+((p.max_epss||0)*100).toFixed(1)+"%</td></tr>"
    }).join("")||"<tr><td colspan='6' style='text-align:center;padding:1rem;color:#8b949e'>No vulnerable packages found.</td></tr>";
  }).catch(()=>{});
</script>

<!-- Three key differentiators -->
<div class="features" id="features" style="max-width:900px">
  <div class="feature">
    <h3>Other scanners report 13 CVEs for zlib. We report 0.</h3>
    <p>Because Debian already backported the fixes. We cross-reference the Debian Security Tracker so you don't waste time on false positives.</p>
  </div>
  <div class="feature">
    <h3>Ranked by blast radius, not just severity</h3>
    <p>A CVSS 7.0 in a library that 10,000 packages depend on is more urgent than a CVSS 9.8 in a leaf package nobody uses. We build real dependency graphs.</p>
  </div>
  <div class="feature">
    <h3>Exploit probability, not just possibility</h3>
    <p>EPSS data tells you the actual chance a CVE gets exploited in the next 30 days. Most CVEs never get exploited. We show you the ones that will.</p>
  </div>
</div>

<div class="how">
  <h2>Connect in 60 Seconds</h2>
  <div class="steps">
    <div class="step">
      <div class="step-num">&#x1f5a5;</div>
      <div class="step-text">
        <h4>One-liner agent (servers)</h4>
        <p>Scans your actual packages and sets up daily monitoring via cron.</p>
        <code>curl -s https://selvo.dev/install.sh | SELVO_API_KEY=sk_xxx bash</code>
      </div>
    </div>
    <div class="step">
      <div class="step-num">&#x2699;</div>
      <div class="step-text">
        <h4>CI/CD (GitHub Actions)</h4>
        <p>Pipe your existing Grype or Trivy output into selvo for prioritized results.</p>
        <code>- uses: Cope-Labs/selvo-action@v1</code>
      </div>
    </div>
    <div class="step">
      <div class="step-num">&#x1f433;</div>
      <div class="step-text">
        <h4>Container images</h4>
        <p>Scan any Docker image for CVEs — no local install needed.</p>
        <code>curl -X POST .../api/v1/scan/image -d '{"image":"nginx:latest"}'</code>
      </div>
    </div>
    <div class="step">
      <div class="step-num">&#x1f514;</div>
      <div class="step-text">
        <h4>Slack / webhook alerts</h4>
        <p>Get notified when new CVEs hit your packages. Connects to Slack or any webhook URL.</p>
        <code>POST /api/v1/orgs/{org}/webhooks {"url":"https://hooks.slack.com/..."}</code>
      </div>
    </div>
  </div>
</div>

<div id="methodology" style="max-width:800px;margin:0 auto;padding:2rem;text-align:center">
  <p style="color:var(--muted);font-size:.85rem">
    9 scoring signals &middot; 8 data sources &middot; 16 ecosystems &middot; SARIF + VEX + NIST OSCAL + FedRAMP exports
    <br><a href="/changelog" style="color:var(--blue)">Changelog</a> &middot;
    <a href="https://copelabs.dev/selvo-report/" target="_blank" style="color:var(--blue)">Full methodology in report</a>
  </p>
</div>

<div class="pricing" id="pricing">
  <h2>Pricing</h2>
  <p class="pricing-sub">Start free. Upgrade when you need more scans.</p>
  <div class="plans">
    <div class="plan">
      <h3>Free</h3>
      <div class="price">$0</div>
      <div class="desc">For individual developers</div>
      <ul>
        <li>5 API calls / day</li>
        <li>1 analysis / day</li>
        <li>All ecosystems</li>
        <li>SARIF + VEX export</li>
        <li>CLI + GitHub Action</li>
      </ul>
      <a class="btn btn-outline" href="#signup">Get Started</a>
    </div>
    <div class="plan featured">
      <h3>Pro</h3>
      <div class="price">$49<span>/mo</span></div>
      <div class="desc">For teams and CI pipelines</div>
      <ul>
        <li>10,000 API calls / day</li>
        <li>100 analyses / day</li>
        <li>Fleet scanning (SSH)</li>
        <li>Trend tracking</li>
        <li>Priority support</li>
      </ul>
      <a class="btn btn-primary" href="#signup">Start Pro</a>
    </div>
    <div class="plan">
      <h3>Enterprise</h3>
      <div class="price">$299<span>/mo</span></div>
      <div class="desc">For security teams at scale</div>
      <ul>
        <li>1M API calls / day</li>
        <li>10,000 analyses / day</li>
        <li>Compliance reports (NIST, FedRAMP)</li>
        <li>Air-gap deployment option</li>
        <li>SLA + DPA available</li>
      </ul>
      <a class="btn btn-primary" href="#signup">Start Enterprise</a>
    </div>
  </div>
</div>

<div class="signup" id="signup" style="max-width:650px">
  <h2>Try It Now — No Account Needed</h2>
  <p class="signup-sub">Run this on your Linux server, then paste the file contents below.</p>
  <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:.6rem .75rem;margin-bottom:.5rem;display:flex;justify-content:space-between;align-items:center">
    <code style="font-size:.82rem">dpkg -l | grep ^ii > ~/Desktop/packages.txt</code>
    <button onclick="navigator.clipboard.writeText('dpkg -l | grep ^ii > ~/Desktop/packages.txt')"
            style="background:var(--bg);border:1px solid var(--border);color:var(--muted);padding:.2rem .5rem;border-radius:4px;font-size:.7rem;cursor:pointer">Copy</button>
  </div>
  <p style="font-size:.78rem;color:var(--muted);margin-bottom:1rem">Then upload <code>packages.txt</code> from your Desktop, or open it and paste the contents below.</p>
  <form method="POST" action="/try" enctype="multipart/form-data">
    <div style="margin-bottom:.5rem">
      <label style="display:block;font-size:.82rem;color:var(--muted);margin-bottom:.3rem">Upload the file or paste below:</label>
      <input type="file" name="file" accept=".txt,.log"
             onchange="const f=this.files[0];if(f){const r=new FileReader();r.onload=e=>document.getElementById('pkg-input').value=e.target.result;r.readAsText(f)}"
             style="font-size:.8rem;color:var(--muted);margin-bottom:.5rem">
    </div>
    <textarea id="pkg-input" name="packages" rows="6"
              placeholder="Or paste output here..."
              style="width:100%;padding:.55rem .75rem;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font:inherit;font-size:.85rem;font-family:monospace;resize:vertical;margin-bottom:.5rem"></textarea>
    <select name="ecosystem" style="width:100%;padding:.45rem .75rem;background:var(--bg3);border:1px solid var(--border);border-radius:6px;color:var(--text);font:inherit;font-size:.85rem;margin-bottom:.75rem">
      <option value="debian" selected>Debian / Ubuntu</option>
      <option value="fedora">Fedora / RHEL / Rocky / Alma</option>
      <option value="alpine">Alpine</option>
      <option value="arch">Arch</option>
    </select>
    <button type="submit" class="btn btn-green" style="width:100%">Scan Packages</button>
  </form>
  <p style="text-align:center;margin-top:.75rem;font-size:.78rem;color:var(--muted)">
    No data is stored. Results appear once and are not saved.
    <br>Want saved results and daily monitoring? <a href="#create-account" style="color:var(--blue)">Create a free account</a>.
  </p>
</div>

<div class="signup" id="create-account" style="max-width:500px">
  <h2 style="font-size:1.2rem">Save Your Results</h2>
  <p class="signup-sub">Create an account for dashboards, trends, alerts, and exports.</p>
  __SIGNUP_CONTENT__
</div>

<div class="foot">
  selvo is a product of Cope Labs LLC &nbsp;&middot;&nbsp;
  <a href="https://stats.uptimerobot.com/xHk9U5qBJK">Status</a> &nbsp;&middot;&nbsp;
  <a href="https://pypi.org/project/selvo/">PyPI</a> &nbsp;&middot;&nbsp;
  <a href="https://github.com/Cope-Labs/selvo-action">GitHub Action</a> &nbsp;&middot;&nbsp;
  <a href="/changelog">Changelog</a> &nbsp;&middot;&nbsp;
  <a href="/contact">Contact</a> &nbsp;&middot;&nbsp;
  <a href="/privacy">Privacy</a> &nbsp;&middot;&nbsp;
  <a href="/terms">Terms</a>
</div>

</body>
</html>"""

_SIGNUP_FORM = """\
<form method="POST" action="/signup">
  <div class="form-group">
    <label for="org_id">Organization ID</label>
    <input type="text" id="org_id" name="org_id" placeholder="my-company" required
           pattern="[a-zA-Z0-9][a-zA-Z0-9_-]*" title="Letters, numbers, hyphens, underscores only (no spaces)"
           oninput="this.value=this.value.replace(/\s/g,'-').replace(/[^a-zA-Z0-9_-]/g,'')">
  </div>
  <div class="form-group">
    <label for="email">Email</label>
    <input type="email" id="email" name="email" placeholder="you@example.com" required>
  </div>
  <input type="hidden" name="plan" value="free">
  <button type="submit" class="btn btn-green" style="width:100%;margin-top:.5rem">Create Free Account</button>
  <div style="text-align:center;margin-top:.5rem;font-size:.78rem;color:var(--muted)">
    Upgrade to Pro or Enterprise anytime from your dashboard.
  </div>
</form>"""


def _signup_error(msg: str) -> str:
    return (
        f'<div class="form-error">{_esc(msg)}</div>{_SIGNUP_FORM}'
        f'<script>document.getElementById("signup").scrollIntoView({{behavior:"smooth"}})</script>'
    )


def _signup_success(org_id: str, api_key: str, plan: str) -> str:
    return (
        f'<div class="form-success">'
        f'<strong>Account created!</strong><br>'
        f'Org: <strong>{_esc(org_id)}</strong>'
        f'</div>'
        f'<div style="margin-bottom:.75rem;font-size:.9rem">'
        f'Your API key (save it now — it won\'t be shown again):</div>'
        f'<div class="key-display">{_esc(api_key)}</div>'
        f'<div style="margin-top:1.25rem">'
        f'<a class="btn btn-primary" style="width:100%;text-align:center" href="/dash/login">'
        f'Go to Dashboard →</a></div>'
        f'<div style="margin-top:1rem;font-size:.82rem;color:var(--muted)">'
        f'<strong>What to do next:</strong></div>'
        f'<div style="font-size:.82rem;color:var(--muted);margin-top:.25rem">'
        f'1. Log in with your org ID + API key above<br>'
        f'2. A reference scan starts automatically — results in ~2 minutes<br>'
        f'3. For real system data: '
        f'<code>curl -s https://selvo.dev/install.sh | SELVO_API_KEY={_esc(api_key)} bash</code></div>'
    )


def render_landing(signup_content: str = "") -> str:
    """Render the public landing page."""
    if not signup_content:
        signup_content = _SIGNUP_FORM
    return _LANDING.replace("__SIGNUP_CONTENT__", signup_content)


def _badge_kev() -> str:
    return '<span class="badge badge-kev">KEV</span>'


def _health_badge(state: str) -> str:
    # Use our calibrated badge classes instead of raw bootstrap bg-danger etc —
    # these are tuned to feel calm on the dark theme rather than alarming.
    calm_map = {
        "ABLATED":    "badge-health-ablated",
        "DEGRADED":   "badge-health-degraded",
        "INTACT":     "badge-health-intact",
        "RECOVERING": "badge-health-recovering",
    }
    if not state:
        return ""
    cls = calm_map.get(state, "bg-secondary")
    return f'<span class="badge {cls}" style="font-size:.7em;font-weight:500">{state}</span>'


def _cve_year_badge(cve_id: str) -> str:
    """Return a tiny year pill for a CVE/GHSA id. Gracefully returns empty string
    when the id doesn't parse as a canonical CVE-YYYY-NNNN."""
    import re as _re
    from datetime import datetime as _dt
    m = _re.match(r"^CVE-(\d{4})-\d+$", cve_id or "", _re.IGNORECASE)
    if not m:
        return ""
    year = int(m.group(1))
    cur = _dt.utcnow().year
    age = cur - year
    cls = "cve-year"
    if age <= 1:
        cls += " recent"
    elif age >= 5:
        cls += " old"
    return f'<span class="{cls}" title="CVE disclosed {year} ({age}y ago)">{year}</span>'


def _has_security_issue(p: dict) -> bool:
    """Return True if the package has any actionable security finding."""
    return bool(
        p.get("cve_count", 0) > 0
        or p.get("in_cisa_kev", False)
        or p.get("has_public_exploit", False)
        or p.get("exploit_maturity", "none") not in ("none", "")
        or p.get("is_outdated", False)
        or p.get("health_state") == "ABLATED"
    )


def _badge_epss(score: float) -> str:
    pct = f"{score * 100:.1f}%"
    cls = "epss-high" if score >= 0.1 else "epss-med" if score >= 0.01 else "text-muted"
    return f'<span class="{cls}">{pct}</span>'


def _cvss_bar(score: float) -> str:
    color = "#f85149" if score >= 9 else "#d29922" if score >= 7 else "#3fb950"
    pct = int(score / 10 * 100)
    return (
        f'<div title="CVSS {score:.1f}" style="width:{pct}%;height:6px;'
        f'border-radius:3px;background:{color}"></div>'
    )


# ---------------------------------------------------------------------------
# Page renderers
# ---------------------------------------------------------------------------

def render_overview(packages: list[dict], taken_at: float | None, org_id: str = "") -> str:
    total = len(packages)
    if total == 0:
        body = """
<div class="card p-4 text-center" style="max-width:600px;margin:3rem auto">
  <h4 class="text-info mb-3">Welcome to selvo</h4>
  <div class="alert alert-info small" style="background:rgba(88,166,255,.1);border-color:rgba(88,166,255,.3);color:#79c0ff">
    A reference scan is running in the background. You can wait for it, or scan your real system now.
  </div>

  <a href="/dash/scan" class="btn btn-info w-100" style="font-size:1.1rem;padding:.75rem">
    Scan a System →
  </a>
  <p class="text-muted small mt-2">
    Run one command on your server, paste the output, see what's vulnerable. Takes 60 seconds.
  </p>

  <hr style="border-color:#30363d;margin:1.5rem 0">

  <p class="text-muted small mb-2">Other ways to scan:</p>
  <div class="d-flex gap-2 justify-content-center flex-wrap">
    <a href="/dash/keys" class="btn btn-sm btn-outline-secondary">API Keys</a>
    <a href="https://selvo.dev/install.sh" class="btn btn-sm btn-outline-secondary">Agent Script</a>
    <a href="https://github.com/Cope-Labs/selvo-action" class="btn btn-sm btn-outline-secondary" target="_blank">GitHub Action</a>
  </div>
</div>"""
        return _page("Overview", body)
    with_cve = sum(1 for p in packages if p.get("cve_count", 0) > 0)
    kev_count = sum(1 for p in packages if p.get("in_cisa_kev"))
    weaponized = sum(1 for p in packages if p.get("exploit_maturity") == "weaponized")
    # Detect scan source — "local" means real system data, anything else is reference
    # System-level health (worst-of across packages)
    health_states = [p.get("health_state", "") for p in packages if p.get("health_state")]
    if any(s == "ABLATED" for s in health_states):
        system_health = "ABLATED"
    elif any(s == "DEGRADED" for s in health_states):
        system_health = "DEGRADED"
    elif health_states:
        system_health = "INTACT"
    else:
        system_health = ""

    sources = {p.get("version_source", "reference") for p in packages}
    is_real_scan = "local" in sources
    source_badge = (
        '<span class="badge bg-success">Your system</span>'
        if is_real_scan else
        '<span class="badge bg-secondary" title="Based on common Debian packages, not your specific system. '
        'Use POST /api/v1/scan/packages with your dpkg output for accurate results.">Reference scan</span>'
    )
    snap_str = (
        datetime.fromtimestamp(taken_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if taken_at else "no snapshot yet"
    )

    # Only show packages with actual security findings in the overview
    actionable = [p for p in packages if _has_security_issue(p)]
    top10 = sorted(actionable, key=lambda p: p.get("score", 0.0), reverse=True)[:10]

    rows = ""
    for i, p in enumerate(top10, 1):
        kev = _badge_kev() if p.get("in_cisa_kev") else ""
        maturity = p.get("exploit_maturity", "none")
        mat_badge = (
            '<span class="badge badge-wpn">Weaponized</span>' if maturity == "weaponized"
            else '<span class="badge badge-poc">PoC</span>' if maturity == "poc"
            else ""
        )
        rows += f"""
        <tr>
          <td class="text-muted">{i}</td>
          <td><a href="/dash/packages?q={_esc(p['name'])}" class="text-info fw-bold">{_esc(p['name'])}</a></td>
          <td><code>{_esc(p.get('version','?'))}</code></td>
          <td>{_cvss_bar(p.get('max_cvss',0))} <small>{p.get('max_cvss',0):.1f}</small></td>
          <td>{_badge_epss(p.get('max_epss',0))}</td>
          <td>{p.get('cve_count',0)}</td>
          <td>{kev} {mat_badge}</td>
          <td>{p.get('score',0):.1f}</td>
        </tr>"""

    # Build the state-first hero sentence. The aggregated margin health_state
    # carries the product's verdict; the sub-line gives the user what to do
    # about it, calibrated to severity. Empty INTACT state is celebrated, not
    # shown as a blank dashboard.
    _state_txt_map = {
        "INTACT":   ("All systems intact.",     "intact"),
        "DEGRADED": ("Some attention needed.",  "degraded"),
        "ABLATED":  ("Immediate action required.", "ablated"),
        "":         ("Snapshot not yet scored.", "unknown"),
    }
    state_headline, state_css = _state_txt_map.get(system_health, _state_txt_map[""])

    # Sub-line adapts to state: empty/intact gets a confident "nothing today",
    # degraded/ablated gets a concrete action pulled from the top package.
    top_package = actionable[0] if actionable else None
    if system_health == "INTACT" or not actionable:
        sub_line = f"<strong>{total:,}</strong> packages tracked. Nothing needs attention today."
        primary_cta = '<a href="/dash/packages" class="btn btn-outline-secondary">View all packages →</a>'
    else:
        name = _esc(top_package.get("name", "?"))
        cves_here = top_package.get("cve_count", 0)
        kev_note = " including a KEV-listed one" if top_package.get("in_cisa_kev") else ""
        sub_line = (
            f"<strong>{len(actionable)}</strong> package{'s' if len(actionable) != 1 else ''} "
            f"need review. Start with <strong>{name}</strong> — "
            f"{cves_here} CVE{'s' if cves_here != 1 else ''}{kev_note}."
        )
        primary_cta = (
            f'<a href="/dash/packages?q={_esc(top_package.get("name",""))}" '
            f'class="btn btn-primary" style="background:var(--accent);border-color:var(--accent)">Review {name} →</a>'
        )

    body = f"""
<div class="state-hero">
  <div class="state {state_css}">{state_headline}</div>
  <div class="sub">{sub_line}</div>
  <div class="actions">
    {primary_cta}
    <a href="/dash/packages" class="btn btn-outline-secondary">All packages</a>
    <a href="/dash/cves" class="btn btn-outline-secondary">All CVEs</a>
  </div>
  <div class="meta">
    {_health_badge(system_health)}
    <span class="dot">·</span> {source_badge}
    <span class="dot">·</span> Snapshot {snap_str}
    <span hx-get="/dash/_refresh_badge" hx-trigger="every 60s" hx-swap="outerHTML"></span>
  </div>
</div>

<div class="mini-stats">
  <div class="mini-stat"><div class="v">{total:,}</div><div class="l">Tracked</div></div>
  <div class="mini-stat"><div class="v">{with_cve}</div><div class="l">With CVEs</div></div>
  <div class="mini-stat"><div class="v" style="color:{'var(--ink-red)' if kev_count else '#e6edf3'}">{kev_count}</div><div class="l">In CISA KEV</div></div>
  <div class="mini-stat"><div class="v" style="color:{'var(--ink-red)' if weaponized else '#e6edf3'}">{weaponized}</div><div class="l">Weaponized</div></div>
</div>

<div class="d-flex justify-content-between align-items-center mb-2">
  <h5 class="mb-0" style="font-family:var(--sans-display);font-weight:500;letter-spacing:-0.01em">Top priorities</h5>
  <small class="text-muted">Ranked by blast radius × exploit probability</small>
</div>
<div class="card">
  <div class="table-responsive">
    <table class="table table-hover mb-0">
      <thead>
        <tr>
          <th>#</th><th>Package</th><th>Version</th>
          <th>CVSS</th><th>EPSS</th><th>CVEs</th><th>Threat</th><th>Score</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>
<div class="mt-3">
  <a href="/dash/packages" class="btn btn-outline-info btn-sm">View all packages →</a>
  <a href="/dash/export/sarif" download class="btn btn-outline-secondary btn-sm ms-2">Download SARIF</a>
  <a href="/dash/export/vex" download class="btn btn-outline-secondary btn-sm ms-2">Download VEX</a>
</div>"""

    return _page("Overview", body)


def render_packages(
    packages: list[dict],
    query: str = "",
    show_all: bool = False,
    show_acked: bool = False,
    acks: dict[str, dict] | None = None,
    csrf_token: str = "",
) -> str:
    """Render the packages table.

    ``acks`` is the dict returned by :func:`selvo.api.acks.load_acks` for the
    current org. Acknowledged packages whose CVE set still matches the
    hash captured at ack time are hidden by default; passing
    ``show_acked=True`` reveals them. If a package's CVE set has changed
    since ack, it is treated as un-acked and shows in the default view.
    """
    from selvo.api.acks import is_acked  # local import — keeps render testable
    acks = acks or {}
    total_count = len(packages)

    # Partition first so we can show counts for both "active" and "acknowledged"
    # consistently regardless of search filter.
    acked_pkgs = [p for p in packages if is_acked(p, acks)]
    active_pkgs = [p for p in packages if not is_acked(p, acks)]
    acked_count = len(acked_pkgs)

    # Choose which set to render based on flags
    if show_acked:
        packages = acked_pkgs
    else:
        packages = active_pkgs

    # Apply search/issues filter on the chosen set
    if query:
        packages = [p for p in packages if query.lower() in p.get("name", "").lower()]
    elif not show_all and not show_acked:
        packages = [p for p in packages if _has_security_issue(p)]

    rows = ""
    for i, p in enumerate(packages):
        kev = _badge_kev() if p.get("in_cisa_kev") else ""
        deps = p.get("dependencies") or []
        depby = p.get("dependents") or []
        cve_ids = p.get("cve_ids") or []
        pkg_name = p.get("name", "")
        has_detail = deps or depby or cve_ids
        toggle = f' style="cursor:pointer" onclick="document.getElementById(\'chain-{i}\').classList.toggle(\'d-none\')"' if has_detail else ""
        chain_html = ""
        if has_detail:
            # CVE links to NVD, with year badge so ancient CVEs visually
            # de-emphasize against recent ones at a glance.
            cve_links = ", ".join(
                f'<a href="https://nvd.nist.gov/vuln/detail/{_esc(c)}" target="_blank" class="text-info">{_esc(c)}</a>{_cve_year_badge(c)}'
                for c in cve_ids[:15]
            )
            more_cves = f" <span class='text-muted'>+{len(cve_ids)-15} more</span>" if len(cve_ids) > 15 else ""
            cve_line = f"<strong>CVEs:</strong> {cve_links}{more_cves}<br>" if cve_ids else ""
            # Dependency links
            dep_links = ", ".join(
                f'<a href="/dash/packages?q={_esc(d)}" class="text-info">{_esc(d)}</a>'
                for d in deps[:20]
            ) or "<span class='text-muted'>none</span>"
            depby_links = ", ".join(
                f'<a href="/dash/packages?q={_esc(d)}" class="text-info">{_esc(d)}</a>'
                for d in depby[:20]
            ) or "<span class='text-muted'>none</span>"
            more_deps = f" <span class='text-muted'>+{len(deps)-20} more</span>" if len(deps) > 20 else ""
            more_depby = f" <span class='text-muted'>+{len(depby)-20} more</span>" if len(depby) > 20 else ""

            # Ack/unack form. Acked rows get an "Restore" button; active rows
            # get an "Acknowledge" button + optional reason input.
            if show_acked:
                ack_form = f"""
              <form method="post" action="/dash/packages/unack" style="display:inline">
                <input type="hidden" name="_csrf" value="{_esc(csrf_token)}">
                <input type="hidden" name="pkg_name" value="{_esc(pkg_name)}">
                <button type="submit" class="btn btn-outline-secondary btn-sm">Restore to active</button>
              </form>"""
            else:
                ack_form = f"""
              <form method="post" action="/dash/packages/ack" style="display:inline-flex;gap:.5rem;align-items:center">
                <input type="hidden" name="_csrf" value="{_esc(csrf_token)}">
                <input type="hidden" name="pkg_name" value="{_esc(pkg_name)}">
                <input type="hidden" name="ecosystem" value="{_esc(p.get('ecosystem',''))}">
                <input type="text" name="reason" placeholder="reason (optional)" maxlength="500"
                       class="form-control form-control-sm bg-dark text-light border-secondary"
                       style="max-width:240px;font-size:.8rem">
                <button type="submit" class="btn btn-outline-secondary btn-sm" title="Hide until CVEs change">Acknowledge</button>
              </form>"""

            chain_html = f"""
        <tr id="chain-{i}" class="d-none">
          <td colspan="10" style="background:#0d1117;border-top:0;padding:.75rem 1rem">
            <div class="small">
              {cve_line}
              <strong>Depends on:</strong> {dep_links}{more_deps}<br>
              <strong>Depended on by:</strong> {depby_links}{more_depby}
              <div class="mt-2 pt-2" style="border-top:1px dashed #30363d">{ack_form}</div>
            </div>
          </td>
        </tr>"""
        expand_icon = ' <span class="text-muted small">&#9662;</span>' if has_detail else ""
        rows += f"""
        <tr{toggle}>
          <td><strong>{_esc(p['name'])}</strong>{expand_icon}</td>
          <td><code>{_esc(p.get('ecosystem','?'))}</code></td>
          <td><code>{_esc(p.get('version','?'))}</code></td>
          <td>{p.get('max_cvss',0):.1f}</td>
          <td>{_badge_epss(p.get('max_epss',0))}</td>
          <td>{p.get('cve_count',0)}</td>
          <td>{p.get('transitive_rdep_count',0):,}</td>
          <td>{kev}</td>
          <td>{_health_badge(p.get('health_state', ''))}</td>
          <td title="Range: {p.get('score_lower',0):.0f}–{p.get('score_upper',0):.0f} ({p.get('score_confidence','?')})">{p.get('score',0):.1f}<span class="text-muted" style="font-size:.7em"> ±{p.get('score_uncertainty',0):.0f}</span></td>
        </tr>{chain_html}"""

    if show_acked:
        page_title = f"Acknowledged packages <span class='text-muted fs-6'>({acked_count})</span>"
        nav_link = '<a href="/dash/packages" class="text-info small">← Back to active packages</a>'
    else:
        ack_link = (f' · <a href="/dash/packages?show_acked=1" class="text-muted small">{acked_count} acknowledged</a>'
                    if acked_count else '')
        page_title = f"Packages{ack_link}"
        nav_link = ""

    body = f"""
<h5 class="mb-3">{page_title}</h5>
{nav_link}
<div class="card mb-3">
  <div class="card-body pb-0">
    <input class="form-control bg-dark text-light border-secondary"
           placeholder="Filter by name…"
           name="q" value="{_esc(query)}"
           hx-get="/dash/packages{'?show_acked=1' if show_acked else ''}"
           hx-trigger="keyup changed delay:300ms"
           hx-target="#pkg-table"
           hx-push-url="true">
  </div>
</div>
<div id="pkg-table">
<div class="card">
  <div class="table-responsive">
    <table class="table table-hover mb-0">
      <thead>
        <tr>
          <th>Package</th><th>Ecosystem</th><th>Version</th>
          <th>CVSS</th><th>EPSS</th><th>CVEs</th><th>rdeps</th><th>KEV</th><th>Health</th><th>Score</th>
        </tr>
      </thead>
      <tbody>{rows if rows else '<tr><td colspan="10" class="text-center py-4">Nothing here. <a href="/dash/overview" class="text-info">Back to overview →</a></td></tr>'}</tbody>
    </table>
  </div>
</div>
{f'<div class="text-center mt-2"><a href="/dash/packages?show_all=1" class="text-muted small">Show all {total_count} packages (including no issues) →</a></div>' if not show_all and not query and not show_acked else ''}
{'<div class="text-center mt-2"><a href="/dash/packages" class="text-muted small">← Show only packages with issues</a></div>' if show_all and not show_acked else ''}
</div>"""

    return _page("Packages", body)


def render_cves(packages: list[dict]) -> str:
    rows_data: list[dict] = []
    for p in packages:
        for cve in p.get("cve_ids", []):
            rows_data.append({
                "cve": cve,
                "package": p["name"],
                "cvss": p.get("max_cvss", 0.0),
                "epss": p.get("max_epss", 0.0),
                "kev": p.get("in_cisa_kev", False),
                "maturity": p.get("exploit_maturity", "none"),
                "score": p.get("score", 0.0),
            })
    rows_data.sort(key=lambda r: (r["epss"], r["cvss"]), reverse=True)

    rows = ""
    for r in rows_data[:200]:
        kev = _badge_kev() if r["kev"] else ""
        mat = r["maturity"]
        mat_badge = (
            '<span class="badge badge-wpn">Weaponized</span>' if mat == "weaponized"
            else '<span class="badge badge-poc">PoC</span>' if mat == "poc"
            else '<span class="text-muted">—</span>'
        )
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{_esc(r['cve'])}"
        rows += f"""
        <tr>
          <td><a href="{nvd_url}" target="_blank" class="text-info">{_esc(r['cve'])}</a>{_cve_year_badge(r['cve'])}</td>
          <td>{_esc(r['package'])}</td>
          <td>{r['cvss']:.1f}</td>
          <td>{_badge_epss(r['epss'])}</td>
          <td>{kev}</td>
          <td>{mat_badge}</td>
        </tr>"""

    body = f"""
<h5 class="mb-3">CVEs <span class="text-muted fs-6">({len(rows_data)} total)</span></h5>
<div class="card">
  <div class="table-responsive">
    <table class="table table-hover mb-0">
      <thead>
        <tr>
          <th>CVE ID</th><th>Package</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Exploit</th>
        </tr>
      </thead>
      <tbody>{rows if rows else '<tr><td colspan="6" class="text-center py-4">No CVEs found. <a href="/dash/overview" class="text-info">Run an analysis first →</a></td></tr>'}</tbody>
    </table>
  </div>
</div>
<small class="text-muted mt-2 d-block">Showing top 200 by EPSS. <a href="/api/v1/cves" class="text-info">Full list via API →</a></small>"""

    return _page("CVEs", body)


def render_trends(metrics: list[dict]) -> str:
    """Render a simple inline SVG sparkline for package + CVE counts."""
    if not metrics:
        body = """
<h5 class="mb-3">Trends</h5>
<div class="card p-4 text-center">
  <p>No trend data yet. Run a few analyses to build history.</p>
  <div class="card p-3 mt-3" style="background:#0d1117;text-align:left">
    <p class="small mb-2">Option 1: curl</p>
    <pre style="margin:0"><code>curl -X POST https://selvo.dev/api/v1/analyze \\
  -H "X-API-Key: YOUR_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"ecosystem":"debian","limit":20}'</code></pre>
  </div>
  <div class="card p-3 mt-3" style="background:#0d1117;text-align:left">
    <p class="small mb-2">Option 2: GitHub Action</p>
    <pre style="margin:0"><code>- uses: Cope-Labs/selvo-action@v1
  with:
    api-key: ${{ secrets.SELVO_API_KEY }}
    ecosystem: debian</code></pre>
  </div>
  <p class="small mt-3">Your API key is on the <a href="/dash/keys" class="text-info">API Keys</a> page.</p>
</div>"""
        return _page("Trends", body)

    dates = [m.get("date", "") for m in metrics]
    pkg_counts = [m.get("package_count", 0) for m in metrics]
    cve_counts = [m.get("cve_count", 0) for m in metrics]
    kev_counts = [m.get("kev_count", 0) for m in metrics]

    def _svg_line(values: list[int], color: str, w: int = 800, h: int = 80) -> str:
        if len(values) < 2:
            return ""
        mn, mx = min(values), max(values)
        rng = mx - mn or 1
        xs = [i * w / (len(values) - 1) for i in range(len(values))]
        ys = [h - (v - mn) / rng * (h - 10) - 5 for v in values]
        pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
        return (
            f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'style="width:100%;height:{h}px">'
            f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="2"/>'
            f"</svg>"
        )

    body = f"""
<h5 class="mb-3">Trends</h5>
<div class="row g-3">
  <div class="col-12">
    <div class="card p-3">
      <div class="fw-bold mb-2 text-info">Package count over time</div>
      {_svg_line(pkg_counts, '#58a6ff')}
      <div class="d-flex justify-content-between mt-1">
        <small class="text-muted">{dates[0] if dates else ''}</small>
        <small class="text-muted">{dates[-1] if dates else ''}</small>
      </div>
    </div>
  </div>
  <div class="col-12 col-md-6">
    <div class="card p-3">
      <div class="fw-bold mb-2 text-warning">CVEs over time</div>
      {_svg_line(cve_counts, '#d29922')}
    </div>
  </div>
  <div class="col-12 col-md-6">
    <div class="card p-3">
      <div class="fw-bold mb-2 text-danger">KEV listings over time</div>
      {_svg_line(kev_counts, '#f85149')}
    </div>
  </div>
</div>
<small class="text-muted mt-2 d-block">{len(metrics)} snapshots tracked.</small>"""

    return _page("Trends", body)


def render_keys(org_id: str, keys: list[dict], message: str = "", csrf_token: str = "") -> str:
    rows = ""
    for k in keys:
        import datetime as _dt
        created = _dt.datetime.fromtimestamp(k["created_at"]).strftime("%Y-%m-%d") if k.get("created_at") else "—"
        last = _dt.datetime.fromtimestamp(k["last_used_at"]).strftime("%Y-%m-%d %H:%M") if k.get("last_used_at") else "—"
        active_badge = '<span class="badge bg-success">Active</span>' if k["active"] else '<span class="badge bg-secondary">Revoked</span>'
        revoke_btn = ""
        if k["active"]:
            revoke_btn = f"""
            <form method="post" action="/dash/keys/revoke" class="d-inline"
                  hx-post="/dash/keys/revoke" hx-target="#keys-section" hx-swap="outerHTML">
              <input type="hidden" name="_csrf" value="{_esc(csrf_token)}">
              <input type="hidden" name="key_hash" value="{_esc(k['key_hash'])}">
              <input type="hidden" name="org_id" value="{_esc(org_id)}">
              <button type="submit" class="btn btn-outline-danger btn-sm"
                      onclick="return confirm('Revoke this key?')">Revoke</button>
            </form>"""
        rows += f"""
        <tr>
          <td>{k['id']}</td>
          <td><code class="text-muted">{_esc(k['key_hash'][:16])}…</code></td>
          <td>{_esc(k['plan'])}</td>
          <td>{active_badge}</td>
          <td>{created}</td>
          <td>{last}</td>
          <td>{k['requests_today']}</td>
          <td>{revoke_btn}</td>
        </tr>"""

    msg_html = message if message.startswith("<") else (f'<div class="alert alert-info mt-2">{_esc(message)}</div>' if message else "")

    body = f"""
<h5 class="mb-3">API Keys
  <small class="text-muted fs-6">org: <code>{_esc(org_id) or 'not configured'}</code></small>
</h5>
{msg_html}
<div id="keys-section">
<div class="card mb-4">
  <div class="table-responsive">
    <table class="table table-hover mb-0">
      <thead>
        <tr>
          <th>ID</th><th>Key (hash prefix)</th><th>Plan</th><th>Status</th>
          <th>Created</th><th>Last used</th><th>Req today</th><th></th>
        </tr>
      </thead>
      <tbody>{rows if rows else '<tr><td colspan="8" class="text-muted text-center py-4">No keys yet.</td></tr>'}</tbody>
    </table>
  </div>
</div>
<div class="card p-3">
  <h6 class="mb-3">Create new key</h6>
  <form method="post" action="/dash/keys"
        hx-post="/dash/keys" hx-target="#keys-section" hx-swap="outerHTML">
    <input type="hidden" name="_csrf" value="{_esc(csrf_token)}">
    <input type="hidden" name="org_id" value="{_esc(org_id)}">
    <button type="submit" class="btn btn-outline-info btn-sm">Generate new key</button>
  </form>
</div>
</div>"""

    return _page("API Keys", body)


def render_new_key_result(org_id: str, plaintext_key: str, keys: list[dict], csrf_token: str = "") -> str:
    """Called after key creation — shows the key once then re-renders the table."""
    rows = ""
    for k in keys:
        import datetime as _dt
        created = _dt.datetime.fromtimestamp(k["created_at"]).strftime("%Y-%m-%d") if k.get("created_at") else "—"
        last = _dt.datetime.fromtimestamp(k["last_used_at"]).strftime("%Y-%m-%d %H:%M") if k.get("last_used_at") else "—"
        active_badge = '<span class="badge bg-success">Active</span>' if k["active"] else '<span class="badge bg-secondary">Revoked</span>'
        revoke_btn = ""
        if k["active"]:
            revoke_btn = f"""
            <form method="post" action="/dash/keys/revoke" class="d-inline"
                  hx-post="/dash/keys/revoke" hx-target="#keys-section" hx-swap="outerHTML">
              <input type="hidden" name="_csrf" value="{_esc(csrf_token)}">
              <input type="hidden" name="key_hash" value="{_esc(k['key_hash'])}">
              <input type="hidden" name="org_id" value="{_esc(org_id)}">
              <button type="submit" class="btn btn-outline-danger btn-sm">Revoke</button>
            </form>"""
        rows += f"""
        <tr>
          <td>{k['id']}</td>
          <td><code class="text-muted">{_esc(k['key_hash'][:16])}…</code></td>
          <td>{_esc(k['plan'])}</td>
          <td>{active_badge}</td>
          <td>{created}</td>
          <td>{last}</td>
          <td>{k['requests_today']}</td>
          <td>{revoke_btn}</td>
        </tr>"""

    return f"""
<div id="keys-section">
<div class="alert alert-success">
  <strong>New API key created.</strong> Copy it now — it will not be shown again.<br>
  <code class="user-select-all fs-6 mt-2 d-block">{_esc(plaintext_key)}</code>
</div>
<div class="card mb-4">
  <div class="table-responsive">
    <table class="table table-hover mb-0">
      <thead>
        <tr>
          <th>ID</th><th>Key (hash prefix)</th><th>Plan</th><th>Status</th>
          <th>Created</th><th>Last used</th><th>Req today</th><th></th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</div>
<div class="card p-3">
  <h6 class="mb-3">Create new key</h6>
  <form method="post" action="/dash/keys"
        hx-post="/dash/keys" hx-target="#keys-section" hx-swap="outerHTML">
    <input type="hidden" name="_csrf" value="{_esc(csrf_token)}">
    <input type="hidden" name="org_id" value="{_esc(org_id)}">
    <button type="submit" class="btn btn-outline-info btn-sm">Generate new key</button>
  </form>
</div>
</div>"""


def render_scan(csrf_token: str = "", result: dict | None = None, api_key: str = "") -> str:
    """Render the Scan a System page — paste package list, get results."""
    result_html = ""
    if result is not None:
        total = result.get("total_packages", 0)
        with_cves = result.get("with_cves", 0)
        kev = result.get("kev_count", 0)
        job_id = result.get("job_id", "")
        status = result.get("status", "")
        error = result.get("error", "")

        if status == "queued" or status == "running":
            result_html = f"""
<div class="card p-3 mt-3">
  <div class="alert alert-info small" style="background:rgba(88,166,255,.1);border-color:rgba(88,166,255,.3);color:#79c0ff">
    Scan queued (job {_esc(job_id)}). Results will appear on your
    <a href="/dash/overview" class="text-info">Overview</a> and
    <a href="/dash/packages" class="text-info">Packages</a> pages in about 2 minutes.
  </div>
  <div class="text-center">
    <a href="/dash/packages" class="btn btn-info">Go to Packages →</a>
  </div>
</div>"""
        elif status == "error":
            result_html = f'<div class="alert alert-danger mt-3">{_esc(error)}</div>'
        elif total > 0:
            result_html = f"""
<div class="card p-3 mt-3">
  <div class="d-flex gap-3 mb-2">
    <div><strong>{total}</strong> <span class="text-muted small">packages</span></div>
    <div><strong class="text-warning">{with_cves}</strong> <span class="text-muted small">with CVEs</span></div>
    <div><strong class="text-danger">{kev}</strong> <span class="text-muted small">CISA KEV</span></div>
  </div>
  <a href="/dash/packages" class="btn btn-info w-100">View Full Results →</a>
</div>"""

    if api_key:
        quick_setup = f"""
<div class="card p-3 mb-3" style="border-color:rgba(63,185,80,.3)">
  <h6 class="text-success mb-2">Automated scanning (recommended)</h6>
  <p class="small mb-2">Run this on any Linux server to scan + set up daily monitoring:</p>
  <div class="card p-2" style="background:#0d1117">
    <div class="d-flex justify-content-between align-items-center">
      <code id="install-cmd" style="font-size:.78rem;word-break:break-all">curl -s https://selvo.dev/install.sh | SELVO_API_KEY={_esc(api_key)} bash</code>
      <button class="btn btn-sm btn-outline-secondary" onclick="navigator.clipboard.writeText(document.getElementById('install-cmd').textContent)" style="font-size:.7rem;white-space:nowrap;margin-left:.5rem">Copy</button>
    </div>
  </div>
  <p class="small text-muted mt-2 mb-0">API key: <code>{_esc(api_key)}</code> — save this, it won't be shown again.</p>
</div>"""
    else:
        quick_setup = """
<div class="card p-3 mb-3">
  <h6 class="mb-2">Automated scanning</h6>
  <p class="small mb-2">Generate an API key to get a ready-to-copy install command for your servers.</p>
  <form method="POST" action="/dash/scan/generate-key">
    <button type="submit" class="btn btn-info btn-sm">Generate Key + Install Command</button>
  </form>
</div>"""

    body = f"""
<h5 class="mb-3">Scan a System</h5>
{quick_setup}

<div class="card p-3 mb-3">
  <p class="small mb-2">Or scan manually — run this command, then paste the output below:</p>
  <div class="card p-2 mb-3" style="background:#0d1117">
    <div class="d-flex justify-content-between align-items-center">
      <code id="scan-cmd" style="font-size:.82rem">dpkg -l | grep ^ii</code>
      <button class="btn btn-sm btn-outline-secondary" onclick="navigator.clipboard.writeText(document.getElementById('scan-cmd').textContent)" style="font-size:.7rem">Copy</button>
    </div>
  </div>
  <p class="text-muted small mb-1">Other package managers:</p>
  <ul class="text-muted small mb-3" style="font-size:.78rem">
    <li>RPM (Fedora/RHEL): <code>rpm -qa --qf '%{{NAME}}-%{{VERSION}}-%{{RELEASE}}.%{{ARCH}}\\n'</code></li>
    <li>Pacman (Arch): <code>pacman -Q</code></li>
    <li>APK (Alpine): <code>apk info -v</code></li>
  </ul>
</div>

<div class="card p-3">
  <form method="POST" action="/dash/scan">
    <input type="hidden" name="_csrf" value="{csrf_token}">
    <div class="mb-2">
      <label class="small mb-1">Upload file or paste below:</label>
      <input type="file" accept=".txt,.log" class="form-control form-control-sm bg-dark text-light border-secondary mb-2" style="font-size:.78rem"
             onchange="const f=this.files[0];if(f){{const r=new FileReader();r.onload=e=>document.getElementById('dash-pkg-input').value=e.target.result;r.readAsText(f)}}">
      <textarea id="dash-pkg-input" name="packages" class="form-control bg-dark text-light border-secondary font-monospace"
                rows="12" style="font-size:.78rem"
                placeholder="ii  adduser  3.118+deb11u1
ii  apt  2.2.4
ii  base-files  11.1+deb11u10
..."></textarea>
    </div>
    <div class="mb-3">
      <label class="small mb-1">Ecosystem:</label>
      <select name="ecosystem" class="form-select bg-dark text-light border-secondary" style="font-size:.85rem">
        <option value="debian" selected>Debian / Ubuntu (dpkg)</option>
        <option value="fedora">Fedora / RHEL (rpm)</option>
        <option value="rocky">Rocky Linux (rpm)</option>
        <option value="almalinux">AlmaLinux (rpm)</option>
        <option value="suse">SUSE / openSUSE (rpm)</option>
        <option value="arch">Arch Linux (pacman)</option>
        <option value="alpine">Alpine (apk)</option>
      </select>
    </div>
    <button type="submit" class="btn btn-info w-100">Scan Packages</button>
  </form>
</div>
{result_html}"""

    return _page("Scan", body)


def render_policy(result: dict | None = None, csrf_token: str = "") -> str:
    """Render the policy-as-code page with a YAML editor and results."""
    result_html = ""
    if result is not None:
        passed = result.get("passed", True)
        blocked = result.get("blocked", [])
        warnings = result.get("warnings", [])
        summary = result.get("summary", {})

        status_badge = (
            '<span class="badge bg-success fs-6">PASSED</span>'
            if passed else
            '<span class="badge bg-danger fs-6">FAILED</span>'
        )

        rows = ""
        for v in blocked:
            rows += (
                f'<tr class="table-danger"><td>{_esc(v.get("rule",""))}</td>'
                f'<td>{_esc(v.get("package",""))}</td>'
                f'<td>{_esc(v.get("cve",""))}</td>'
                f'<td>{_esc(v.get("detail",""))}</td>'
                f'<td><span class="badge bg-danger">BLOCK</span></td></tr>'
            )
        for v in warnings:
            rows += (
                f'<tr class="table-warning"><td>{_esc(v.get("rule",""))}</td>'
                f'<td>{_esc(v.get("package",""))}</td>'
                f'<td>{_esc(v.get("cve",""))}</td>'
                f'<td>{_esc(v.get("detail",""))}</td>'
                f'<td><span class="badge bg-warning text-dark">WARN</span></td></tr>'
            )

        result_html = f"""
<div class="card p-3 mt-3">
  <div class="d-flex align-items-center gap-2 mb-3">
    <h6 class="mb-0">Result</h6> {status_badge}
    <small class="text-muted ms-auto">{summary.get('blocked_count',0)} blocked, {summary.get('warning_count',0)} warnings</small>
  </div>
  <div class="table-responsive">
    <table class="table table-sm mb-0">
      <thead><tr><th>Rule</th><th>Package</th><th>CVE</th><th>Detail</th><th>Level</th></tr></thead>
      <tbody>{rows if rows else '<tr><td colspan="5" class="text-center py-3">No violations found.</td></tr>'}</tbody>
    </table>
  </div>
</div>"""

    default_policy = """\
version: 1
block:
  on_kev: true
  on_weaponized: true
  min_cvss: 9.0
  min_score: 80
warn:
  on_poc: true
  min_cvss: 7.0
sla:
  critical: 7
  high: 30
  medium: 90
  low: 365"""

    body = f"""
<h5 class="mb-3">Policy-as-Code</h5>
<p class="text-muted small mb-3">Define security gates for your packages. Block or warn on KEV, CVSS, EPSS, exploit maturity, and SLA thresholds.</p>

<div class="card p-3">
  <form method="POST" action="/dash/policy">
    <input type="hidden" name="_csrf" value="{csrf_token}">
    <label class="small mb-1">Policy (YAML)</label>
    <textarea name="policy_yaml" class="form-control bg-dark text-light border-secondary font-monospace"
              rows="14" style="font-size:.8rem">{_esc(default_policy)}</textarea>
    <button type="submit" class="btn btn-info w-100 mt-2">Evaluate Policy</button>
  </form>
</div>
{result_html}

<div class="card p-3 mt-3">
  <h6>API Usage</h6>
  <pre style="margin:0"><code>curl -X POST https://selvo.dev/api/v1/policy/check \\
  -H "X-API-Key: YOUR_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{{"ecosystem":"debian","policy":{{"version":1,"block":{{"on_kev":true,"min_cvss":9.0}}}}}}'</code></pre>
</div>"""

    return _page("Policy", body)


def render_billing(plan: str = "free", csrf_token: str = "") -> str:
    """Render the billing / upgrade page with pricing cards."""
    import os as _os
    pro_price_id = _os.environ.get("STRIPE_PRO_MONTHLY_PRICE_ID", "")
    ent_price_id = _os.environ.get("STRIPE_ENT_MONTHLY_PRICE_ID", "")

    plan_color = {"free": "secondary", "pro": "info", "enterprise": "warning"}.get(plan, "secondary")
    plan_label = plan.title()

    def _plan_card(name: str, price: str, price_id: str, features: list, highlight: bool = False) -> str:
        pkey = name.lower()
        active = plan == pkey
        if active:
            btn = '<button class="btn btn-success w-100" disabled>Current plan</button>'
        elif price_id:
            btn = (
                f'<button class="btn btn-{"warning" if pkey == "enterprise" else "info"} w-100" '
                f'hx-post="/dash/billing/checkout" '
                f'hx-vals=\'{{"plan":"{pkey}","price_id":"{price_id}","_csrf":"{csrf_token}"}}\' '
                f'hx-target="#checkout-result" hx-indicator="#checkout-spinner">'
                f'Upgrade to {name}</button>'
            )
        else:
            btn = '<a href="/contact" class="btn btn-outline-warning w-100">Contact Sales</a>'
        border = " border-info" if highlight else ""
        feats = "".join(f"<li class='mb-1'>\u2713 {_esc(f)}</li>" for f in features)
        return f"""
        <div class="col-12 col-md-4">
          <div class="card h-100{border} p-3">
            <h5 style="color:{'#58a6ff' if highlight else '#e6edf3'}">{name}</h5>
            <div class="display-6 fw-bold mb-1" style="color:#e6edf3">{price}</div>
            <small style="color:#8b949e" class="mb-3">/month</small>
            <ul class="list-unstyled small mb-4" style="color:#c9d1d9">{feats}</ul>
            {btn}
          </div>
        </div>"""

    body = f"""
<div class="d-flex align-items-center mb-4 gap-3">
  <h5 class="mb-0">Billing &amp; Plan</h5>
  <span class="badge bg-{plan_color} fs-6">{_esc(plan_label)}</span>
</div>
<div class="row g-3 mb-4">
  {_plan_card("Free", "$0", "", [
      "50 packages / run", "All 16 ecosystems",
      "CVE + EPSS enrichment", "API access (rate-limited)",
  ])}
  {_plan_card("Pro", "$49", pro_price_id, [
      "500 packages / run", "All ecosystems",
      "SBOM / Grype / Trivy import", "Fleet SSH scanning",
      "Compliance exports (SARIF, VEX)", "Priority support",
  ], highlight=True)}
  {_plan_card("Enterprise", "$299", ent_price_id, [
      "Unlimited packages", "Team seats + SSO",
      "Air-gap / offline mode", "Custom SLA", "Dedicated support",
  ])}
</div>
<div id="checkout-result" class="mt-3"></div>
<div id="checkout-spinner" class="htmx-indicator text-muted small">Redirecting to Stripe\u2026</div>"""

    return _page("Billing", body)
