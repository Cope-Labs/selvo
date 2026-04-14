"""
selvo REST API server (FastAPI).

Start:
    selvo-api                          # default: localhost:8765
    selvo-api --host 0.0.0.0 --port 8000
    selvo api --port 8000              # via CLI

All routes are under /api/v1/.

Endpoints
─────────
GET  /api/v1/packages            List packages from last snapshot (fast)
GET  /api/v1/packages/{name}     Full detail for one package
GET  /api/v1/cves                CVE listing filtered by CVSS / EPSS thresholds
GET  /api/v1/exploits            Packages with exploit availability data
GET  /api/v1/snapshot            Raw last-snapshot metadata
GET  /api/v1/diff                Diff current snapshot vs previous
POST /api/v1/analyze             Trigger a fresh pipeline run (slow, async)
GET  /api/v1/patch-plan          Ordered patch recommendations
GET  /api/v1/distro-compare      Cross-distro version comparison table
POST /api/v1/fleet/scan          SSH fleet scan

All successful responses are JSON. Long-running endpoints (POST /analyze,
POST /fleet/scan) return a 202 Accepted immediately with a job_id and
stream progress via GET /api/v1/jobs/{job_id}.
"""
from __future__ import annotations

import dataclasses
import hmac
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Literal, Optional

log = logging.getLogger(__name__)

# ── Sentry error tracking (init before FastAPI) ─────────────────────────────
_SENTRY_DSN = os.getenv("SENTRY_DSN", "")
if _SENTRY_DSN:
    try:
        import sentry_sdk
        sentry_sdk.init(
            dsn=_SENTRY_DSN,
            traces_sample_rate=0.1,
            send_default_pii=False,
            environment="production" if os.getenv("SELVO_API_AUTH") else "development",
        )
        log.info("Sentry initialized")
    except ImportError:
        log.debug("sentry-sdk not installed, skipping")

try:
    from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, RedirectResponse  # noqa: F401
    from pydantic import BaseModel, Field
    import uvicorn
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False


# ── Job tracking (simple in-memory for single-process deploy) ─────────────────

_jobs: dict[str, dict[str, Any]] = {}


def _new_job(kind: str, params: dict, org_id: str = "") -> str:
    jid = str(uuid.uuid4())[:8]
    _jobs[jid] = {
        "id": jid,
        "kind": kind,
        "params": params,
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "result": None,
        "error": None,
        "org_id": org_id,
    }
    return jid


# ── Request models ────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    ecosystem: str = Field("all", description="Ecosystem(s) to analyse")
    limit: int = Field(50, ge=1, le=200)
    context_mode: Literal["reference", "local", "auto"] = "reference"


def _validate_fleet_host(host_str: str) -> str:
    """Validate a fleet host string against SSRF.

    Rejects internal/loopback/link-local IPs and metadata service addresses.
    """
    import ipaddress
    host = host_str.split(":")[0]
    # Block obvious internal hostnames
    blocked_names = {"localhost", "metadata.google.internal", "169.254.169.254"}
    if host.lower() in blocked_names:
        raise ValueError(f"Host not allowed: {host}")
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved:
            raise ValueError(f"Host not allowed: {host}")
    except ValueError as exc:
        if "not allowed" in str(exc):
            raise
        # Not a literal IP — that's fine (it's a hostname), but check for common SSRF targets
        pass
    return host_str


class FleetScanRequest(BaseModel):
    hosts: list[str] = Field(..., description="host[:port] strings")
    username: str = ""
    key_file: Optional[str] = None
    ecosystem: str = "auto"


class ScanRequest(BaseModel):
    sbom: Optional[str] = Field(None, description="SBOM JSON content (inline) or server-side path")
    grype: Optional[str] = Field(None, description="Grype JSON content (inline) or server-side path")
    trivy: Optional[str] = Field(None, description="Trivy JSON content (inline) or server-side path")
    lockfile: Optional[str] = Field(None, description="Lock file content (inline) or server-side path")
    run_cve: bool = Field(True, description="Run CVE + EPSS + CVSS enrichment")


class PackageListRequest(BaseModel):
    """Accept raw package manager output for accurate per-system scanning."""
    packages: str = Field(..., description=(
        "Raw output from: dpkg-query -W -f='${db:Status-Abbrev}  ${Package}  ${Version}\\n' "
        "OR rpm -qa OR pacman -Q OR apk info -v "
        "OR simple 'name\\tversion' lines (one per line)"
    ))
    ecosystem: str = Field("debian", description="Package ecosystem (debian, fedora, alpine, arch)")
    format: str = Field("auto", description="Parser: auto, dpkg, rpm, pacman, apk, tsv")


class ImageScanRequest(BaseModel):
    """Scan a container image for vulnerabilities."""
    image: str = Field(..., description="Image reference (e.g. nginx:latest, ghcr.io/org/app:v1)")
    ecosystem: str = Field("debian", description="Base OS ecosystem")


class WebhookRequest(BaseModel):
    url: str = Field(..., description="Webhook URL (https required)")
    kind: str = Field("generic", description="Type: generic, slack")


class CheckoutRequest(BaseModel):
    org_id: str
    plan: str = Field("pro", pattern="^(pro|enterprise)$")


import html as _html_mod
import json as _json_mod
import re as _re
import secrets as _secrets
import time as _time_mod
import hashlib as _hashlib_mod

_SAFE_ORG_RE = _re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")

# ── Legal pages ──────────────────────────────────────────────────────────────

_LEGAL_STYLE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — selvo</title>
<style>
body{{background:#0d1117;color:#c9d1d9;font:15px/1.7 -apple-system,system-ui,sans-serif;
  max-width:700px;margin:0 auto;padding:2rem}}
h1{{color:#58a6ff;font-size:1.5rem;margin-bottom:.5rem}}
h2{{color:#e6edf3;font-size:1.1rem;margin-top:2rem}}
a{{color:#58a6ff}}
.updated{{color:#8b949e;font-size:.85rem;margin-bottom:2rem}}
.back{{margin-top:2rem;font-size:.9rem}}
</style></head><body>"""

_PRIVACY_HTML = _LEGAL_STYLE.format(title="Privacy Policy") + """
<h1>Privacy Policy</h1>
<div class="updated">Last updated: April 7, 2026</div>

<p>selvo is operated by Cope Labs LLC ("we", "us"). This policy describes what data we collect
and how we use it.</p>

<h2>What We Collect</h2>
<p><strong>Account data:</strong> Organization name, email address, and API keys you create.
We store API keys as SHA-256 hashes — the plaintext is shown once at creation and never stored.</p>

<p><strong>Scan data:</strong> When you submit a scan, we receive your installed package names and
versions. We use this data solely to perform the vulnerability analysis you requested.
Scan results are stored per-organization for dashboard viewing and trend tracking.</p>

<p><strong>Usage data:</strong> API request counts, timestamps for rate limiting, and aggregate event
counts (page views, signups, scan submissions). These are stored as simple counters in our
database with no personally identifiable information attached. IP addresses are held only in
the in-memory rate limiter (cleared on restart) and are not persisted.</p>

<p><strong>Error tracking:</strong> We use Sentry (sentry.io) to capture application errors.
Error reports may include request URLs and stack traces but not request bodies, API keys,
or package data. Sentry's privacy policy applies to this data.</p>

<h2>What We Do Not Collect</h2>
<ul>
<li>We do not collect source code, file contents, or network traffic.</li>
<li>We do not use tracking pixels, third-party analytics, or advertising cookies.</li>
<li>We do not sell, share, or transfer your data to third parties for marketing purposes.</li>
<li>We do not track individual user behavior or build user profiles.</li>
</ul>

<h2>Data Retention</h2>
<p>Scan snapshots are retained for trend tracking (last 10 per ecosystem per org).
You can request deletion of your org and all associated data by emailing
<a href="/contact">Contact us</a>.</p>

<h2>Third-Party Services</h2>
<ul>
<li><strong>Stripe</strong> — payment processing. Stripe's privacy policy applies to payment data.</li>
<li><strong>Fly.io</strong> — hosting. Scan data is processed on Fly.io infrastructure in the US (IAD region).</li>
<li><strong>Sentry</strong> — error tracking. Application errors are reported to Sentry for debugging. No user data or package lists are included in error reports.</li>
<li><strong>UptimeRobot</strong> — uptime monitoring. Monitors our public status endpoint only.</li>
</ul>

<h2>Contact</h2>
<p><a href="/contact">Contact us</a></p>

<div class="back"><a href="/">← Back to selvo</a></div>
</body></html>"""

_TERMS_HTML = _LEGAL_STYLE.format(title="Terms of Service") + """
<h1>Terms of Service</h1>
<div class="updated">Last updated: April 7, 2026</div>

<p>By using selvo ("the Service"), operated by Cope Labs LLC ("we", "us"), you agree to these terms.</p>

<h2>The Service</h2>
<p>selvo provides vulnerability scanning and risk prioritization for Linux packages. Results are
informational — we do not guarantee completeness or accuracy of vulnerability data. You are
responsible for your own patching and security decisions.</p>

<h2>Accounts and API Keys</h2>
<p>You are responsible for keeping your API keys secure. Do not share keys or embed them in
public repositories. We may revoke keys that appear compromised.</p>

<h2>Acceptable Use</h2>
<p>You may not use the Service to:</p>
<ul>
<li>Scan systems you do not own or have authorization to scan.</li>
<li>Attempt to access other organizations' data.</li>
<li>Circumvent rate limits or authentication controls.</li>
<li>Resell API access without written permission.</li>
</ul>

<h2>Free Tier</h2>
<p>The free tier is provided as-is with no uptime guarantee. We may adjust rate limits at any time.
Paid plans include the service levels described on the pricing page.</p>

<h2>Paid Plans</h2>
<p>Paid plans are billed monthly via Stripe. You may cancel at any time; access continues until
the end of the billing period. No refunds for partial months.</p>

<h2>Limitation of Liability</h2>
<p>The Service is provided "as is." To the maximum extent permitted by law, Cope Labs LLC is not
liable for any damages arising from your use of the Service, including but not limited to
security incidents, data loss, or inaccurate vulnerability reports.</p>

<h2>Changes</h2>
<p>We may update these terms. Continued use after changes constitutes acceptance.</p>

<h2>Contact</h2>
<p><a href="/contact">Contact us</a></p>

<div class="back"><a href="/">← Back to selvo</a></div>
</body></html>"""

_CHANGELOG_HTML = _LEGAL_STYLE.format(title="Changelog") + """
<h1>Changelog</h1>
<div class="updated">selvo 1.0.0</div>

<h2>1.0.0 — March 28, 2026</h2>
<p>First public release.</p>
<ul>
<li><strong>Accurate CVE counts</strong> — Cross-references Debian Security Tracker to filter CVEs your distro already patched. Binary-to-source package name resolution ensures correct lookups. Filter runs twice (pre and post source-collapse) to catch edge cases.</li>
<li><strong>9 scoring signals</strong> — Composite 0-100 risk score weighted by blast radius, EPSS exploit probability, betweenness centrality, version lag, CVSS severity, exploit maturity, ecosystem popularity, downloads, and exposure days.</li>
<li><strong>Multi-ecosystem graphs</strong> — Dependency graph metrics for Debian, Ubuntu, Alpine, and Arch. Transitive reverse-dep count and betweenness centrality from real package indexes.</li>
<li><strong>Real system scanning</strong> — <code>POST /scan/packages</code> accepts dpkg/rpm/pacman/apk output. Dashboard labels "Your system" vs "Reference scan" so you know what you're looking at.</li>
<li><strong>One-liner agent</strong> — <code>curl https://selvo.dev/install.sh | SELVO_API_KEY=sk_xxx bash</code> installs a daily cron scanner.</li>
<li><strong>Container image scanning</strong> — <code>POST /scan/image</code> pulls and scans Docker images server-side.</li>
<li><strong>GitHub Action</strong> — <code>Cope-Labs/selvo-action@v1</code> auto-detects runner packages, posts PR comments, enforces KEV/score gates.</li>
<li><strong>Policy-as-code</strong> — YAML policy evaluation via API and dashboard. Block on KEV, CVSS, EPSS, SLA thresholds. CVE allow-lists with expiry.</li>
<li><strong>Auto-remediation</strong> — <code>POST /api/v1/fix</code> opens upstream PRs to bump vulnerable packages.</li>
<li><strong>Webhook/Slack alerts</strong> — Notifications on every scan completion with CVE/KEV counts.</li>
<li><strong>Export formats</strong> — SARIF, VEX, NIST 800-53 OSCAL, FedRAMP OSCAL, PDF, CycloneDX SBOM.</li>
<li><strong>8 data sources</strong> — OSV.dev, FIRST.org EPSS, NVD, CISA KEV, Debian Security Tracker, Repology, Ubuntu USN, Fedora Bodhi.</li>
<li><strong>Security hardening</strong> — Org-scoped data isolation, key sharing detection, SSRF fleet host validation, CSRF tokens, rate limiting, session rotation.</li>
</ul>

<div class="back"><a href="/">← Back to selvo</a></div>
</body></html>"""


def _contact_html(csrf_token: str = "", error: str = "", success: bool = False) -> str:
    err_html = f'<div style="color:#f85149;margin-bottom:1rem;font-size:.9rem">{_html_mod.escape(error)}</div>' if error else ""
    if success:
        body = """
<h1>Message Sent</h1>
<p>Thanks for reaching out. We'll get back to you soon.</p>
<div class="back"><a href="/">← Back to selvo</a></div>"""
    else:
        body = f"""
<h1>Contact Us</h1>
<p style="color:#8b949e;margin-bottom:1.5rem">Questions, feedback, or enterprise inquiries.</p>
{err_html}
<form method="POST" action="/contact">
  <input type="hidden" name="_csrf" value="{csrf_token}">
  <div style="margin-bottom:1rem">
    <label style="display:block;color:#8b949e;font-size:.85rem;margin-bottom:.3rem">Name</label>
    <input type="text" name="name" required style="width:100%;padding:.5rem .75rem;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:6px;font:inherit">
  </div>
  <div style="margin-bottom:1rem">
    <label style="display:block;color:#8b949e;font-size:.85rem;margin-bottom:.3rem">Email</label>
    <input type="email" name="email" required style="width:100%;padding:.5rem .75rem;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:6px;font:inherit">
  </div>
  <div style="margin-bottom:1rem">
    <label style="display:block;color:#8b949e;font-size:.85rem;margin-bottom:.3rem">Message</label>
    <textarea name="message" required rows="5" style="width:100%;padding:.5rem .75rem;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:6px;font:inherit;resize:vertical"></textarea>
  </div>
  <button type="submit" style="width:100%;padding:.6rem;background:#1f6feb;color:#fff;border:none;border-radius:6px;font-size:.9rem;cursor:pointer;font-weight:600">Send Message</button>
</form>"""

    return _LEGAL_STYLE.format(title="Contact") + body + """
<div class="back"><a href="/">← Back to selvo</a></div>
</body></html>"""


# ── Dashboard session cookie helpers ─────────────────────────────────────────
# Cookie format: base64(json({"org_id": ..., "plan": ..., "exp": ...})).signature
# Signed with HMAC-SHA256 using SELVO_API_SECRET or a random per-boot key.

_SESSION_COOKIE = "selvo_session"
_SESSION_MAX_AGE = 86400 * 7  # 7 days


def _session_secret() -> str:
    """Return a stable secret for signing session cookies."""
    return os.getenv("SELVO_API_SECRET", "") or os.getenv("SELVO_SESSION_SECRET", "")


def _sign_session(payload: dict) -> str:
    """Create a signed session cookie value."""
    import base64
    payload["exp"] = int(_time_mod.time()) + _SESSION_MAX_AGE
    data = base64.urlsafe_b64encode(_json_mod.dumps(payload).encode()).decode()
    sig = hmac.new(_session_secret().encode(), data.encode(), _hashlib_mod.sha256).hexdigest()
    return f"{data}.{sig}"


def _verify_session(cookie: str) -> dict | None:
    """Verify and decode a session cookie. Returns payload or None."""
    import base64
    secret = _session_secret()
    if not secret or "." not in cookie:
        return None
    data, sig = cookie.rsplit(".", 1)
    expected = hmac.new(secret.encode(), data.encode(), _hashlib_mod.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = _json_mod.loads(base64.urlsafe_b64decode(data))
    except Exception:
        return None
    if payload.get("exp", 0) < _time_mod.time():
        return None
    return payload

# CSRF token store: {token: expiry_timestamp}
_csrf_tokens: dict[str, float] = {}


def _generate_csrf_token() -> str:
    """Generate a CSRF token valid for 1 hour."""
    import time
    token = _secrets.token_urlsafe(32)
    _csrf_tokens[token] = time.time() + 3600
    # Prune expired tokens
    now = time.time()
    expired = [t for t, exp in _csrf_tokens.items() if exp < now]
    for t in expired:
        _csrf_tokens.pop(t, None)
    return token


def _verify_csrf_token(token: str) -> bool:
    """Verify and consume a CSRF token."""
    import time
    exp = _csrf_tokens.pop(token, None)
    return exp is not None and exp > time.time()


def _validate_scan_path(path: str) -> str:
    """Reject path traversal and restrict to safe directories."""
    from pathlib import Path
    p = Path(path).resolve()
    allowed = (Path.home() / ".cache" / "selvo", Path("/tmp"))
    if not any(str(p).startswith(str(a)) for a in allowed):
        raise ValueError(f"Path not allowed: {path}")
    return str(p)


# ── Simple IP-based rate limiter for signup / org creation ───────────────────
# Allows max _SIGNUP_RATE_MAX requests per IP within _SIGNUP_RATE_WINDOW seconds.
_SIGNUP_RATE_WINDOW = 3600  # 1 hour
_SIGNUP_RATE_MAX = 5        # max 5 signups per IP per hour
_signup_attempts: dict[str, list[float]] = {}


def _check_signup_rate(ip: str) -> bool:
    """Return True if the IP is within rate limits, False if exceeded."""
    now = _time_mod.time()
    attempts = _signup_attempts.get(ip, [])
    # Prune old attempts
    attempts = [t for t in attempts if now - t < _SIGNUP_RATE_WINDOW]
    if len(attempts) >= _SIGNUP_RATE_MAX:
        _signup_attempts[ip] = attempts
        return False
    attempts.append(now)
    _signup_attempts[ip] = attempts
    return True


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> "FastAPI":
    if not _FASTAPI_AVAILABLE:
        raise RuntimeError(
            "FastAPI is not installed. Run: pip install 'selvo[api]'"
        )

    try:
        from importlib.metadata import version as _pkg_version
        _selvo_version = _pkg_version("selvo")
    except Exception:
        _selvo_version = "0.0.0+dev"

    _is_production = bool(os.getenv("SELVO_API_AUTH"))
    app = FastAPI(
        title="selvo API",
        description="Linux dependency risk analysis as a REST service.",
        version=_selvo_version,
        docs_url=None if _is_production else "/docs",
        redoc_url=None if _is_production else "/redoc",
    )

    @app.on_event("startup")
    async def _warm_bulk_caches() -> None:
        """Pre-download bulk CVE/exploit data so the first scan is fast.

        Runs as a background task so it doesn't delay startup. The first
        scan that arrives before warming completes falls back to the
        on-demand path (no failure, just slower for that one request).
        """
        import asyncio as _asyncio

        async def _warm():
            from selvo.analysis.distro_status import warm_dst
            from selvo.analysis.exploit import warm_caches as _warm_exploits
            from selvo.analysis.epss import cache_epss_csv
            log.info("Pre-warming DST, CISA KEV, Nuclei, and EPSS caches…")
            results = await _asyncio.gather(
                warm_dst(),
                _warm_exploits(),
                cache_epss_csv(),
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, Exception):
                    log.warning("Cache warm task failed: %s", r)
            log.info("Bulk cache warm complete.")

        _asyncio.create_task(_warm())

    _allowed_origins = os.getenv(
        "SELVO_CORS_ORIGINS", "https://selvo.dev,https://selvo.fly.dev"
    ).split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["X-API-Key", "Content-Type"],
    )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://unpkg.com https://cdn.jsdelivr.net 'unsafe-inline'; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' https://copelabs.dev; "
            "frame-ancestors 'none'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        # Rate limit headers for API key-authenticated requests
        org = getattr(request.state, "org", None)
        if org and org.key_id > 0:
            from selvo.api.auth import PLAN_LIMITS
            limits = PLAN_LIMITS.get(org.plan, PLAN_LIMITS["free"])
            response.headers["X-RateLimit-Limit"] = str(limits["requests_per_day"])
            # Remaining requires a DB read — use key_id to look up
            try:
                from selvo.api.auth import _get_conn, _lock
                with _lock:
                    row = _get_conn().execute(
                        "SELECT requests_today FROM api_keys WHERE id=?", (org.key_id,)
                    ).fetchone()
                if row:
                    remaining = max(0, limits["requests_per_day"] - row[0])
                    response.headers["X-RateLimit-Remaining"] = str(remaining)
            except Exception:
                pass
        return response

    # ── Optional API-key authentication middleware ──────────────────────────
    # Activated only when SELVO_API_AUTH=1 is set in the environment so that
    # single-user / local installs continue to work without any key setup.
    #
    # Skip rules (no auth required):
    #   - Exact paths: /api/v1/status, billing webhook
    #   - Landing page (/) and signup (/signup)
    #   - Dashboard login page (/dash/login)
    #
    # Dashboard routes (/dash/*) require a session cookie.
    # API routes require X-API-Key header.
    #
    # Master bypass: if SELVO_API_SECRET is set and the request presents it as
    # X-API-Key, it is granted enterprise access as the "system" org without a
    # DB lookup. Used by the daily analysis cron and admin scripts.

    _AUTH_SKIP_PATHS = frozenset({
        "/api/v1/status",
        "/api/v1/status/data",
        "/api/v1/billing/webhook",
        "/install.sh",
    })

    _DASH_PUBLIC_PATHS = frozenset({
        "/dash/login",
    })

    if os.getenv("SELVO_API_AUTH"):
        from selvo.api.auth import verify_api_key as _verify_key, OrgContext as _OrgCtx

        _MASTER_SECRET = os.getenv("SELVO_API_SECRET", "")

        @app.middleware("http")
        async def _auth_middleware(request: Request, call_next):
            path = request.url.path
            # Public paths — no auth
            if path in _AUTH_SKIP_PATHS or path in ("/", "/signup", "/try", "/privacy", "/terms", "/changelog", "/contact", "/robots.txt", "/sitemap.xml", "/favicon.ico"):
                return await call_next(request)

            # Dashboard routes — session cookie auth
            if path.startswith("/dash/"):
                if path in _DASH_PUBLIC_PATHS:
                    return await call_next(request)
                cookie = request.cookies.get(_SESSION_COOKIE, "")
                session = _verify_session(cookie)
                if session is None:
                    return RedirectResponse(url="/dash/login", status_code=302)
                # Always read current plan from DB — session may be stale after upgrade/downgrade
                org_id = session["org_id"]
                try:
                    from selvo.api.auth import _get_conn, _lock
                    with _lock:
                        row = _get_conn().execute(
                            "SELECT plan FROM orgs WHERE org_id=?", (org_id,)
                        ).fetchone()
                    current_plan = row[0] if row else session.get("plan", "free")
                except Exception:
                    current_plan = session.get("plan", "free")
                request.state.org = _OrgCtx(
                    org_id=org_id,
                    plan=current_plan,
                    key_id=0,
                )
                return await call_next(request)
            api_key = request.headers.get("X-API-Key", "")
            if not api_key:
                return JSONResponse(
                    {"detail": "Missing X-API-Key header"},
                    status_code=401,
                )
            # Master bypass for internal/cron callers.
            # hmac.compare_digest prevents timing-oracle attacks on the secret.
            if _MASTER_SECRET and hmac.compare_digest(api_key, _MASTER_SECRET):
                request.state.org = _OrgCtx(org_id="system", plan="enterprise", key_id=0)
                return await call_next(request)
            ctx = _verify_key(api_key)
            if ctx is None:
                return JSONResponse(
                    {"detail": "Invalid, expired, or rate-limited API key"},
                    status_code=401,
                )
            # Check for key sharing (too many distinct IPs)
            from selvo.api.auth import check_key_sharing, _hash_key
            client_ip = request.client.host if request.client else "unknown"
            key_hash = _hash_key(api_key)
            if not check_key_sharing(key_hash, client_ip, ctx.plan):
                return JSONResponse(
                    {"detail": "API key used from too many IP addresses. "
                     "Each key is licensed for a single team. "
                     "Contact support or create additional keys."},
                    status_code=429,
                )
            request.state.org = ctx
            return await call_next(request)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _pkg_to_dict(pkg: Any) -> dict:
        _strip = {"fix_refs", "dependents", "dependencies"}
        d = {k: v for k, v in dataclasses.asdict(pkg).items() if k not in _strip}
        d["is_outdated"] = pkg.is_outdated
        d["cve_count"] = pkg.cve_count
        return d

    def _get_snapshot_packages(ecosystem: str = "all", request: Optional[Request] = None) -> tuple[list[dict], float]:
        """Load snapshot — org-scoped if authenticated, global fallback otherwise."""
        org = getattr(request.state, "org", None) if request else None
        if org is not None and org.org_id != "system":
            from selvo.api.tenancy import load_org_snapshot
            result = load_org_snapshot(org.org_id, ecosystem)
            if result is not None:
                return result
        from selvo.analysis.cache import load_last_snapshot
        result = load_last_snapshot(ecosystem)
        if result is None:
            return [], 0.0
        pkgs, taken_at = result
        return pkgs, taken_at

    # ── / → dashboard redirect ────────────────────────────────────────────────

    from fastapi.responses import RedirectResponse as _RR, HTMLResponse as _HTML_R

    @app.get("/", response_class=_HTML_R, include_in_schema=False)
    async def landing_page():
        from selvo.api.auth import track_event
        track_event("page_view", "landing")
        if _DASH_AVAILABLE:
            return _HTML_R(_dash.render_landing())
        return _RR(url="/dash/overview", status_code=302)

    @app.get("/privacy", response_class=_HTML_R, include_in_schema=False)
    async def privacy_page():
        return _HTML_R(_PRIVACY_HTML)

    @app.get("/changelog", response_class=_HTML_R, include_in_schema=False)
    async def changelog_page():
        return _HTML_R(_CHANGELOG_HTML)

    @app.get("/terms", response_class=_HTML_R, include_in_schema=False)
    async def terms_page():
        return _HTML_R(_TERMS_HTML)

    @app.get("/contact", response_class=_HTML_R, include_in_schema=False)
    async def contact_page():
        csrf = _generate_csrf_token()
        return _HTML_R(_contact_html(csrf_token=csrf))

    @app.post("/contact", response_class=_HTML_R, include_in_schema=False)
    async def contact_submit(request: Request):
        form = await request.form()
        csrf = str(form.get("_csrf", ""))
        if not _verify_csrf_token(csrf):
            return _HTML_R(_contact_html(error="Invalid form. Please reload and try again."))

        name = str(form.get("name", "")).strip()[:200]
        email = str(form.get("email", "")).strip()[:200]
        message = str(form.get("message", "")).strip()[:2000]

        if not name or not email or not message:
            return _HTML_R(_contact_html(error="All fields are required."))

        from selvo.api.auth import track_event
        track_event("contact_form", f"{name} <{email}>: {message[:100]}")

        # Send email via background HTTP to avoid blocking
        import httpx as _hx
        try:
            # Use a simple SMTP relay or just store — for now store in events
            log.info("Contact form: name=%s email=%s message=%s", name, email, message[:100])
        except Exception:
            pass

        return _HTML_R(_contact_html(success=True))

    @app.get("/robots.txt", include_in_schema=False)
    async def robots_txt():
        from starlette.responses import Response
        return Response(
            content="User-agent: *\nAllow: /\nDisallow: /dash/\nDisallow: /api/\nSitemap: https://selvo.dev/sitemap.xml\n",
            media_type="text/plain",
        )

    @app.get("/sitemap.xml", include_in_schema=False)
    async def sitemap_xml():
        from starlette.responses import Response
        return Response(
            content='<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            '  <url><loc>https://selvo.dev/</loc><priority>1.0</priority></url>\n'
            '  <url><loc>https://selvo.dev/privacy</loc></url>\n'
            '  <url><loc>https://selvo.dev/terms</loc></url>\n'
            '  <url><loc>https://selvo.dev/changelog</loc></url>\n'
            '  <url><loc>https://selvo.dev/contact</loc></url>\n'
            '</urlset>\n',
            media_type="application/xml",
        )

    @app.get("/llms.txt", include_in_schema=False)
    async def llms_txt():
        from starlette.responses import Response
        content = (
            "# selvo\n\n"
            "> Linux dependency risk scanner. Ranks CVEs by blast radius and exploit probability. "
            "Filters what your distro already patched.\n\n"
            "selvo scans installed Linux packages across 16 ecosystems, checks 8 data sources (NVD, EPSS, "
            "CISA KEV, GitHub Advisory, OSV, Exploit-DB, and distro trackers), filters out backported fixes, "
            "and ranks findings by blast radius and exploit probability. Exports SARIF, VEX, OSCAL, NIST.\n\n"
            "## Plans\n\n"
            "- Free: 5 requests/day\n"
            "- Pro: $49/mo, 10,000 requests/day\n"
            "- Enterprise: $299/mo, 1,000,000 requests/day\n\n"
            "## Install\n\n"
            "- pip install selvo\n"
            "- docker pull ghcr.io/cope-labs/selvo\n"
            "- GitHub Action: Cope-Labs/selvo-action@v1\n\n"
            "## Key pages\n\n"
            "- https://selvo.dev/: Landing, pricing, docs\n"
            "- https://selvo.dev/dash/: Scan dashboard\n"
            "- https://selvo.dev/api/v1/status: API status\n\n"
            "## Source\n\n"
            "- GitHub: https://github.com/Cope-Labs/selvo\n"
            "- Parent: https://copelabs.dev (Cope Labs LLC)\n"
        )
        return Response(content=content, media_type="text/plain")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        from starlette.responses import Response
        # Inline SVG lightning bolt emoji as favicon
        svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">&#x26A1;</text></svg>'
        return Response(content=svg, media_type="image/svg+xml")

    @app.post("/signup", response_class=_HTML_R, include_in_schema=False)
    async def signup_form(request: "Request"):
        """Handle self-serve signup form submission."""
        client_ip = request.client.host if request.client else "unknown"
        if not _check_signup_rate(client_ip):
            return _HTML_R(_dash.render_landing(
                _dash._signup_error("Too many signup attempts. Please try again later.")
            ))

        form = await request.form()
        org_id = str(form.get("org_id", "")).strip()
        email = str(form.get("email", "")).strip()

        if not _SAFE_ORG_RE.match(org_id):
            return _HTML_R(_dash.render_landing(
                _dash._signup_error("Org ID must be alphanumeric, hyphens, underscores (1-63 chars).")
            ))

        if not org_id:
            return _HTML_R(_dash.render_landing(_dash._signup_error("Organization ID is required.")))
        if not email:
            return _HTML_R(_dash.render_landing(_dash._signup_error("Email is required.")))

        # Always register as FREE. Upgrade only happens after Stripe payment succeeds.
        try:
            from selvo.api.auth import register_org, generate_api_key, track_event
            register_org(org_id, name=org_id, email=email, plan="free")
            api_key = generate_api_key(org_id, plan="free")
            track_event("signup", org_id)
        except Exception as exc:
            return _HTML_R(_dash.render_landing(_dash._signup_error(str(exc))))

        # Auto-login: create session cookie and redirect to dashboard
        session_value = _sign_session({
            "org_id": org_id,
            "plan": "free",
            "sid": _secrets.token_urlsafe(16),
        })
        response = RedirectResponse(url="/dash/overview", status_code=302)
        response.set_cookie(
            _SESSION_COOKIE,
            session_value,
            max_age=_SESSION_MAX_AGE,
            httponly=True,
            secure=request.url.scheme == "https" or bool(os.getenv("SELVO_API_AUTH")),
            samesite="lax",
        )
        # Flash the API key via a query param so the dashboard can show it once
        response = RedirectResponse(
            url=f"/dash/keys?new_key={api_key}",
            status_code=302,
        )
        response.set_cookie(
            _SESSION_COOKIE,
            session_value,
            max_age=_SESSION_MAX_AGE,
            httponly=True,
            secure=request.url.scheme == "https" or bool(os.getenv("SELVO_API_AUTH")),
            samesite="lax",
        )
        return response

    # ── /try — anonymous scan, no account needed ────────────────────────────

    _try_cache: dict[str, str] = {}
    _TRY_CACHE_MAX = 50

    @app.post("/try", response_class=_HTML_R, include_in_schema=False)
    async def try_scan(request: "Request"):
        """Anonymous scan — parse packages, run CVE pipeline, return results inline."""
        from selvo.api.auth import track_event

        client_ip = request.client.host if request.client else "unknown"
        if not _check_signup_rate(client_ip):
            return _HTML_R(_dash.render_landing(
                '<div class="form-error">Too many scans. Please try again later.</div>'
            ))

        form = await request.form()
        packages_text = str(form.get("packages", "")).strip()[:500_000]
        ecosystem = str(form.get("ecosystem", "debian")).strip()

        # Check cache — same input = same report
        cache_key = _hashlib_mod.sha256(f"{ecosystem}:{packages_text}".encode()).hexdigest()[:16]
        if cache_key in _try_cache:
            track_event("try_scan", f"cached:{ecosystem}")
            return _HTML_R(_try_cache[cache_key])

        if not packages_text:
            return _HTML_R(_dash.render_landing(
                '<div class="form-error">Please paste your package list.</div>'
            ))

        from selvo.analysis.fleet import parse_dpkg, parse_rpm, parse_pacman, parse_apk
        parsers = {
            "debian": parse_dpkg, "ubuntu": parse_dpkg,
            "fedora": parse_rpm, "rocky": parse_rpm, "almalinux": parse_rpm, "suse": parse_rpm,
            "arch": parse_pacman, "alpine": parse_apk,
        }
        parser = parsers.get(ecosystem, parse_dpkg)
        parsed = parser(packages_text)

        if not parsed:
            return _HTML_R(_dash.render_landing(
                '<div class="form-error">Could not parse any packages. Check your input and ecosystem selection.</div>'
            ))

        track_event("try_scan", f"anon:{ecosystem}:{len(parsed)}pkgs")

        # Run synchronous enrichment (limited to keep response fast)
        from selvo.discovery.base import PackageRecord
        from selvo.analysis.cve import enrich_cve
        from selvo.analysis.distro_status import filter_resolved_cves
        from selvo.analysis.redhat_status import filter_redhat_minor_cves
        from selvo.analysis.epss import enrich_epss
        from selvo.analysis.exploit import enrich_exploits
        from selvo.prioritizer.scorer import score_and_rank

        # Anonymous endpoint — keep a generous cap to prevent abuse.
        # Real desktops have ~2700 packages; servers ~600. 5000 covers everything realistic.
        _items = list(parsed.items())[:5000]
        records = [
            PackageRecord(name=name, version=version, ecosystem=ecosystem)
            for name, version in _items
        ]

        try:
            import asyncio as _asyncio
            records = await enrich_cve(records)
            # EPSS and exploit lookups are independent: run in parallel.
            await _asyncio.gather(
                enrich_epss(records),
                enrich_exploits(records),  # deep=False: uses only KEV + Nuclei bulk indices
            )
            # Distro filters run LAST among CVE-list mutators — they consult
            # the EPSS/exploit signals to decide on override. Debian and
            # Red Hat filters are independent (each only touches packages in
            # its own ecosystem family) so they can run concurrently.
            await _asyncio.gather(
                filter_resolved_cves(records),
                filter_redhat_minor_cves(records),
            )
            ranked = score_and_rank(records)
            from selvo.api.silent_zero import check as _silent_zero_check
            _silent_zero_check(ranked, ecosystem, {
                "source": "/try", "client_ip": client_ip,
            })
        except Exception:
            ranked = records

        # Generate full interactive HTML report — same format as the public report
        from selvo.reporters.html import render_html
        report_html = render_html(ranked, cta=True)

        # Inject a banner at the top of the report
        banner = (
            '<div style="background:linear-gradient(135deg,rgba(88,166,255,.12),rgba(63,185,80,.12));'
            'border:1px solid rgba(88,166,255,.3);border-radius:8px;padding:1rem 1.5rem;'
            'margin-bottom:1.5rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem">'
            '<div>'
            f'<strong style="color:#58a6ff">{len(parsed)} packages scanned</strong>'
            f' &mdash; {sum(1 for p in ranked if p.cve_count > 0)} with open CVEs'
            '<br><span style="color:#8b949e;font-size:.82rem">'
            'This is a one-time scan. Want this running daily across your fleet with Slack alerts?</span>'
            '</div>'
            '<a href="https://selvo.dev/#create-account" '
            'style="background:#1f6feb;color:#fff;padding:.5rem 1.2rem;border-radius:6px;'
            'font-weight:600;font-size:.9rem;text-decoration:none;white-space:nowrap">'
            'Create Free Account</a>'
            '</div>'
        )
        report_html = report_html.replace('<body>', '<body>' + banner, 1)

        # Strip any lone UTF-16 surrogates that snuck in via CVE descriptions or
        # package metadata — Starlette's UTF-8 encoder rejects them.
        report_html = report_html.encode("utf-8", errors="replace").decode("utf-8")

        # Cache the result
        if len(_try_cache) >= _TRY_CACHE_MAX:
            _try_cache.pop(next(iter(_try_cache)))  # evict oldest
        _try_cache[cache_key] = report_html

        return _HTML_R(report_html)

    # ── /install.sh — one-liner agent script ─────────────────────────────────

    @app.get("/install.sh", include_in_schema=False)
    async def install_script():
        """Serve the one-liner install script for system scanning."""
        from pathlib import Path as _P
        from starlette.responses import Response
        from selvo.api.auth import track_event
        track_event("install_sh_download")
        script = _P(__file__).parent / "install.sh"
        if script.exists():
            return Response(
                content=script.read_text(),
                media_type="text/x-shellscript",
                headers={"Content-Disposition": "inline; filename=install.sh"},
            )
        raise HTTPException(status_code=404, detail="Install script not found")

    # ── /api/v1/status ────────────────────────────────────────────────────────

    @app.head("/api/v1/status", include_in_schema=False)
    @app.get("/api/v1/status")
    async def status() -> dict:
        """Health check + server info."""
        return {
            "status": "ok",
            "service": "selvo",
            "version": _selvo_version,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    @app.get("/api/v1/stats")
    async def admin_stats(request: Request) -> dict:
        """Full analytics dashboard. Requires master key or system org."""
        caller = getattr(request.state, "org", None)
        if not caller or caller.org_id != "system":
            raise HTTPException(status_code=403, detail="Admin only")
        from selvo.api.auth import get_event_counts, _get_conn, _lock
        import httpx as _hx

        # Internal events
        events_30d = get_event_counts(30)
        events_7d = get_event_counts(7)

        # Org count
        with _lock:
            org_count = _get_conn().execute("SELECT COUNT(*) FROM orgs").fetchone()[0]
            key_count = _get_conn().execute("SELECT COUNT(*) FROM api_keys WHERE active=1").fetchone()[0]

        # PyPI downloads
        pypi = {}
        try:
            async with _hx.AsyncClient(timeout=5.0) as client:
                for pkg in ("selvo", "margin"):
                    resp = await client.get(f"https://pypistats.org/api/packages/{pkg}/overall")
                    if resp.status_code == 200:
                        data = resp.json().get("data", [])
                        pypi[pkg] = {r["category"]: r["downloads"] for r in data}
        except Exception:
            pass

        # GitHub repo traffic
        github = {}
        try:
            gh_token = os.getenv("GITHUB_TOKEN", "")
            if gh_token:
                headers = {"Authorization": f"token {gh_token}"}
                async with _hx.AsyncClient(timeout=5.0, headers=headers) as client:
                    for repo in ("selvo", "selvo-action", "selvo-report", "margin"):
                        try:
                            cr = await client.get(f"https://api.github.com/repos/Cope-Labs/{repo}/traffic/clones")
                            vr = await client.get(f"https://api.github.com/repos/Cope-Labs/{repo}/traffic/views")
                            github[repo] = {
                                "clones_14d": cr.json().get("count", 0) if cr.status_code == 200 else 0,
                                "unique_cloners": cr.json().get("uniques", 0) if cr.status_code == 200 else 0,
                                "views_14d": vr.json().get("count", 0) if vr.status_code == 200 else 0,
                                "unique_visitors": vr.json().get("uniques", 0) if vr.status_code == 200 else 0,
                            }
                        except Exception:
                            pass
        except Exception:
            pass

        return {
            "events_30d": events_30d,
            "events_7d": events_7d,
            "orgs": org_count,
            "active_keys": key_count,
            "pypi_downloads": pypi,
            "github_traffic": github,
        }

    @app.get("/api/v1/status/data")
    async def data_freshness() -> dict:
        """Show when each data source was last fetched. No auth required."""
        from selvo.analysis import cache as _c
        sources = {
            "osv": {"desc": "CVE database (OSV.dev)", "cache_key": "osv:"},
            "epss": {"desc": "Exploit probability (FIRST.org)", "cache_key": "epss:"},
            "nvd": {"desc": "CVSS severity (NVD)", "cache_key": "nvd:"},
            "dst": {"desc": "Debian Security Tracker", "cache_key": "dst_data"},
            "repology": {"desc": "Upstream versions (Repology)", "cache_key": "repology_version:"},
            "debian_packages": {"desc": "Debian Packages.gz (dep graph)", "cache_key": "debian_packages_v4"},
            "cisa_kev": {"desc": "CISA KEV catalog", "cache_key": "kev_data"},
        }
        result = {}
        try:
            conn = _c._get_conn()
            for name, info in sources.items():
                row = conn.execute(
                    "SELECT MAX(expires_at) FROM cache WHERE key LIKE ?",
                    (info["cache_key"] + "%",),
                ).fetchone()
                if row and row[0]:
                    # expires_at is when the cache expires; subtract TTL to get fetch time
                    from datetime import datetime, timezone
                    expires = datetime.fromtimestamp(row[0], tz=timezone.utc)
                    result[name] = {
                        "description": info["desc"],
                        "cache_expires": expires.isoformat(),
                        "status": "fresh" if row[0] > _time_mod.time() else "stale",
                    }
                else:
                    result[name] = {
                        "description": info["desc"],
                        "cache_expires": None,
                        "status": "no_data",
                    }
        except Exception:
            result["error"] = "Cache introspection unavailable"
        return {"data_sources": result}

    # ── /api/v1/snapshot ─────────────────────────────────────────────────────

    @app.get("/api/v1/snapshot")
    async def snapshot(ecosystem: str = Query("all"), request: Request = None) -> dict:
        """Return the last cached analysis snapshot metadata."""
        pkgs, taken_at = _get_snapshot_packages(ecosystem, request=request)
        if not pkgs:
            raise HTTPException(
                status_code=404,
                detail=f"No snapshot for ecosystem '{ecosystem}'. POST /api/v1/analyze first.",
            )
        return {
            "ecosystem": ecosystem,
            "taken_at": datetime.fromtimestamp(taken_at, tz=timezone.utc).isoformat()
            if taken_at else None,
            "package_count": len(pkgs),
            "packages": pkgs,
        }

    # ── /api/v1/packages ─────────────────────────────────────────────────────

    @app.get("/api/v1/packages")
    async def list_packages(
        ecosystem: str = Query("all"),
        limit: int = Query(50, ge=1, le=500),
        min_score: float = Query(0.0, ge=0.0),
        min_cvss: float = Query(0.0, ge=0.0, le=10.0),
        has_cve: Optional[bool] = Query(None),
        exploit_maturity: Optional[str] = Query(None, description="none|poc|weaponized"),
        in_kev: Optional[bool] = Query(None),
        request: Request = None,
    ) -> dict:
        """List packages from the last snapshot with optional filters."""
        pkgs, taken_at = _get_snapshot_packages(ecosystem, request=request)
        if not pkgs:
            raise HTTPException(status_code=404, detail=f"No snapshot for '{ecosystem}'.")

        # Apply filters
        filtered = pkgs
        if min_score > 0.0:
            filtered = [p for p in filtered if p.get("score", 0.0) >= min_score]
        if min_cvss > 0.0:
            filtered = [p for p in filtered if p.get("max_cvss", 0.0) >= min_cvss]
        if has_cve is not None:
            if has_cve:
                filtered = [p for p in filtered if p.get("cve_count", 0) > 0]
            else:
                filtered = [p for p in filtered if p.get("cve_count", 0) == 0]
        if exploit_maturity is not None:
            filtered = [p for p in filtered if p.get("exploit_maturity") == exploit_maturity]
        if in_kev is not None:
            filtered = [p for p in filtered if bool(p.get("in_cisa_kev")) == in_kev]

        return {
            "ecosystem": ecosystem,
            "total_matched": len(filtered),
            "packages": filtered[:limit],
        }

    # ── /api/v1/packages/{name} ───────────────────────────────────────────────

    @app.get("/api/v1/packages/{name}")
    async def get_package(name: str, ecosystem: str = Query("all"), request: Request = None) -> dict:
        """Return full detail for one package by name."""
        pkgs, _ = _get_snapshot_packages(ecosystem, request=request)
        for p in pkgs:
            if p.get("name", "").lower() == name.lower():
                return p
        raise HTTPException(status_code=404, detail=f"Package '{name}' not found in snapshot.")

    # ── /api/v1/cves ─────────────────────────────────────────────────────────

    @app.get("/api/v1/cves")
    async def list_cves(
        ecosystem: str = Query("all"),
        min_cvss: float = Query(0.0, ge=0.0, le=10.0),
        min_epss: float = Query(0.0, ge=0.0, le=1.0),
        limit: int = Query(100, ge=1, le=1000),
        request: Request = None,
    ) -> dict:
        """List CVE IDs with associated package and severity info."""
        pkgs, _ = _get_snapshot_packages(ecosystem, request=request)
        rows: list[dict] = []
        for p in pkgs:
            if not p.get("cve_ids"):
                continue
            if p.get("max_cvss", 0.0) < min_cvss:
                continue
            if p.get("max_epss", 0.0) < min_epss:
                continue
            for cve in p["cve_ids"]:
                rows.append({
                    "cve_id": cve,
                    "package": p["name"],
                    "ecosystem": p.get("ecosystem", ecosystem),
                    "max_cvss": p.get("max_cvss", 0.0),
                    "max_epss": p.get("max_epss", 0.0),
                    "exploit_maturity": p.get("exploit_maturity", "none"),
                    "in_cisa_kev": p.get("in_cisa_kev", False),
                    "package_score": p.get("score", 0.0),
                })
        rows.sort(key=lambda r: (r["max_epss"], r["max_cvss"]), reverse=True)
        return {"total": len(rows), "cves": rows[:limit]}

    # ── /api/v1/exploits ─────────────────────────────────────────────────────

    @app.get("/api/v1/exploits")
    async def list_exploits(
        ecosystem: str = Query("all"),
        maturity: Optional[str] = Query(None, description="poc|weaponized"),
        kev_only: bool = Query(False),
        request: Request = None,
    ) -> dict:
        """Return packages with exploit data."""
        pkgs, _ = _get_snapshot_packages(ecosystem, request=request)
        exploitable = [
            p for p in pkgs
            if p.get("has_public_exploit") or p.get("in_cisa_kev")
        ]
        if maturity:
            exploitable = [p for p in exploitable if p.get("exploit_maturity") == maturity]
        if kev_only:
            exploitable = [p for p in exploitable if p.get("in_cisa_kev")]
        return {
            "total": len(exploitable),
            "kev_count": sum(1 for p in exploitable if p.get("in_cisa_kev")),
            "packages": exploitable,
        }

    # ── /api/v1/patch-plan ────────────────────────────────────────────────────

    @app.get("/api/v1/patch-plan")
    async def patch_plan(
        ecosystem: str = Query("all"),
        limit: int = Query(20, ge=1, le=100),
        min_score: float = Query(10.0),
        request: Request = None,
    ) -> dict:
        """Return an ordered patch plan from the last snapshot."""
        pkgs, _ = _get_snapshot_packages(ecosystem, request=request)
        actionable = [
            p for p in pkgs
            if p.get("score", 0.0) >= min_score
            and (p.get("cve_count", 0) > 0 or p.get("is_outdated"))
        ]
        actionable.sort(key=lambda p: p.get("score", 0.0), reverse=True)
        plan = []
        for p in actionable[:limit]:
            plan.append({
                "package": p["name"],
                "current_version": p.get("version", "unknown"),
                "upstream_version": p.get("upstream_version"),
                "score": p.get("score", 0.0),
                "cve_count": p.get("cve_count", 0),
                "max_epss": p.get("max_epss", 0.0),
                "exploit_maturity": p.get("exploit_maturity", "none"),
                "in_cisa_kev": p.get("in_cisa_kev", False),
                "patch_safety": p.get("patch_safety_score", 0.0),
                "regression_risk": p.get("patch_regression_risk", ""),
                "distro_patch_dates": p.get("distro_patch_dates", {}),
            })
        return {"total": len(plan), "patch_plan": plan}

    # ── /api/v1/diff ─────────────────────────────────────────────────────────

    @app.get("/api/v1/diff")
    async def get_diff(ecosystem: str = Query("all")) -> dict:
        """Show what changed since the previous snapshot."""
        from selvo.analysis.cache import load_last_snapshot
        # We need to peek at the second-most-recent snapshot — for now return
        # the diff metadata stored in the most recent snapshot (approximate)
        result = load_last_snapshot(ecosystem)
        if result is None:
            raise HTTPException(status_code=404, detail="No snapshot found.")
        pkgs, taken_at = result
        return {
            "ecosystem": ecosystem,
            "note": "POST /api/v1/analyze to refresh and get a live diff",
            "snapshot_taken_at": datetime.fromtimestamp(taken_at, tz=timezone.utc).isoformat()
            if taken_at else None,
            "package_count": len(pkgs),
        }

    # ── POST /api/v1/analyze ─────────────────────────────────────────────────

    @app.post("/api/v1/analyze", status_code=202)
    async def analyze(req: AnalyzeRequest, background_tasks: BackgroundTasks, request: Request) -> dict:
        """
        Trigger a fresh full pipeline run.

        Returns immediately with a job_id. Poll GET /api/v1/jobs/{job_id}
        for status. This takes 1–3 minutes.
        """
        from selvo.mcp_server import _run_pipeline

        caller = getattr(request.state, "org", None)
        jid = _new_job("analyze", req.model_dump(), org_id=caller.org_id if caller else "")

        _caller_org_id = caller.org_id if caller else ""

        async def _run() -> None:
            _jobs[jid]["status"] = "running"
            try:
                packages = await _run_pipeline(
                    ecosystem=req.ecosystem,
                    limit=req.limit,
                    context_mode=req.context_mode,
                    run_cve=True,
                )
                # Save to org-scoped snapshot so dashboard sees results
                if _caller_org_id:
                    from selvo.api.tenancy import save_org_snapshot, record_org_metric
                    save_org_snapshot(_caller_org_id, req.ecosystem, packages)
                    record_org_metric(_caller_org_id, req.ecosystem, packages)
                    # Also save under "all" so the dashboard default view works
                    if req.ecosystem != "all":
                        save_org_snapshot(_caller_org_id, "all", packages)
                        record_org_metric(_caller_org_id, "all", packages)

                result = {
                    "total_packages": len(packages),
                    "with_cves": sum(1 for p in packages if p.cve_count > 0),
                    "top_5": [
                        {"name": p.name, "score": p.score, "cve_count": p.cve_count}
                        for p in packages[:5]
                    ],
                }
                _jobs[jid]["status"] = "done"
                _jobs[jid]["result"] = result

                if _caller_org_id:
                    try:
                        await _fire_webhooks(_caller_org_id, result)
                    except Exception:
                        log.warning("Webhook delivery failed for org %s", _caller_org_id)
            except Exception as exc:
                _jobs[jid]["status"] = "error"
                _jobs[jid]["error"] = str(exc)

        background_tasks.add_task(_run)

        return {
            "job_id": jid,
            "status": "queued",
            "poll_url": f"/api/v1/jobs/{jid}",
            "note": "Analysis takes 1–3 minutes. Poll poll_url for completion.",
        }

    # ── GET /api/v1/jobs/{job_id} ─────────────────────────────────────────────

    @app.get("/api/v1/jobs/{job_id}")
    async def get_job(job_id: str, request: Request) -> dict:
        """Poll analyze/fleet-scan job status."""
        if job_id not in _jobs:
            raise HTTPException(status_code=404, detail="Job not found.")
        job = _jobs[job_id]
        caller = getattr(request.state, "org", None)
        if caller and job.get("org_id") and caller.org_id != job["org_id"] and caller.org_id != "system":
            raise HTTPException(status_code=404, detail="Job not found.")
        return job

    # ── POST /api/v1/fleet/scan ───────────────────────────────────────────────

    @app.post("/api/v1/fleet/scan", status_code=202)
    async def fleet_scan(req: FleetScanRequest, background_tasks: BackgroundTasks, request: Request) -> dict:
        """Scan a fleet of SSH hosts for installed packages and CVE exposure."""
        # Validate all hosts against SSRF before proceeding
        for h in req.hosts:
            try:
                _validate_fleet_host(h)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc))

        caller = getattr(request.state, "org", None)
        jid = _new_job("fleet_scan", req.model_dump(), org_id=caller.org_id if caller else "")

        async def _run() -> None:
            _jobs[jid]["status"] = "running"
            try:
                from selvo.analysis.fleet import scan_fleet, MachineSpec

                specs = [
                    MachineSpec(
                        host=h.split(":")[0],
                        port=int(h.split(":")[1]) if ":" in h else 22,
                        username=req.username or None,
                        key_file=req.key_file,
                        ecosystem=req.ecosystem,
                    )
                    for h in req.hosts
                ]
                fleet_result = await scan_fleet(specs)

                # Run CVE enrichment on merged package set for aggregate view
                from selvo.discovery.base import PackageRecord
                from selvo.analysis.cve import enrich_cve
                from selvo.analysis.distro_status import filter_resolved_cves
                from selvo.analysis.redhat_status import filter_redhat_minor_cves
                from selvo.analysis.epss import enrich_epss
                from selvo.analysis.exploit import enrich_exploits
                from selvo.prioritizer.scorer import score_and_rank

                # Build per-host package lists for CVE-to-host mapping
                host_pkgs: dict[str, dict[str, str]] = {}
                all_pkg_names: set[str] = set()
                eco = req.ecosystem if req.ecosystem != "auto" else "debian"
                for m in fleet_result.machines:
                    if not m.error:
                        host_pkgs[m.host] = m.packages
                        all_pkg_names.update(m.packages.keys())

                # Create merged PackageRecords for CVE lookup
                merged_records = [
                    PackageRecord(
                        name=name,
                        version=next((hp[name] for hp in host_pkgs.values() if name in hp), "unknown"),
                        ecosystem=eco,
                    )
                    for name in all_pkg_names
                ]

                # Enrich with CVEs. Distro filters run after epss/exploits so
                # the "unimportant" override checks see populated signals.
                if merged_records:
                    import asyncio as _asyncio
                    merged_records = await enrich_cve(merged_records)
                    await _asyncio.gather(
                        enrich_epss(merged_records),
                        enrich_exploits(merged_records),
                    )
                    await _asyncio.gather(
                        filter_resolved_cves(merged_records),
                        filter_redhat_minor_cves(merged_records),
                    )
                    merged_records = score_and_rank(merged_records)
                    from selvo.api.silent_zero import check as _silent_zero_check
                    _silent_zero_check(merged_records, eco, {
                        "source": "fleet/scan", "host_count": len(host_pkgs),
                    })

                # Build CVE-to-hosts aggregate
                cve_hosts: dict[str, dict] = {}
                for pkg in merged_records:
                    if not pkg.cve_ids:
                        continue
                    affected_hosts = [h for h, pkgs in host_pkgs.items() if pkg.name in pkgs]
                    for cve in pkg.cve_ids:
                        if cve not in cve_hosts:
                            cve_hosts[cve] = {
                                "cve_id": cve,
                                "package": pkg.name,
                                "max_cvss": pkg.max_cvss,
                                "max_epss": pkg.max_epss,
                                "hosts": affected_hosts,
                                "host_count": len(affected_hosts),
                            }
                        else:
                            # Same CVE from different package — merge hosts
                            existing = cve_hosts[cve]
                            for h in affected_hosts:
                                if h not in existing["hosts"]:
                                    existing["hosts"].append(h)
                            existing["host_count"] = len(existing["hosts"])

                # Sort by breadth of exposure (most hosts first)
                cve_aggregate = sorted(cve_hosts.values(), key=lambda c: (-c["host_count"], -c["max_epss"]))

                _jobs[jid]["status"] = "done"
                _jobs[jid]["result"] = {
                    "hosts": [
                        {
                            "host": m.host,
                            "package_count": m.package_count,
                            "error": m.error,
                        }
                        for m in fleet_result.machines
                    ],
                    "aggregate": {
                        "total_hosts": len(host_pkgs),
                        "total_packages": len(all_pkg_names),
                        "total_cves": len(cve_hosts),
                        "cves_by_exposure": cve_aggregate[:50],
                    },
                    "version_variance": fleet_result.version_variance(),
                }
            except Exception as exc:
                _jobs[jid]["status"] = "error"
                _jobs[jid]["error"] = str(exc)

        background_tasks.add_task(_run)
        return {"job_id": jid, "status": "queued", "poll_url": f"/api/v1/jobs/{jid}"}

    # ── GET /api/v1/fleet/aggregate ──────────────────────────────────────────

    @app.get("/api/v1/fleet/aggregate")
    async def fleet_aggregate(
        request: Request,
        min_hosts: int = Query(1, ge=1, description="Only show CVEs affecting at least N hosts"),
        min_epss: float = Query(0.0, ge=0.0, le=1.0, description="Minimum EPSS score"),
    ) -> dict:
        """Aggregate CVE exposure across the last fleet scan.

        Returns CVEs sorted by number of affected hosts, filtered by
        min_hosts and min_epss thresholds.
        """
        caller = getattr(request.state, "org", None)
        caller_org = caller.org_id if caller else ""

        # Find the most recent completed fleet scan for this org
        fleet_job = None
        for jid_key in sorted(_jobs, key=lambda k: _jobs[k].get("created_at", ""), reverse=True):
            job = _jobs[jid_key]
            if (job.get("kind") == "fleet_scan"
                    and job.get("status") == "done"
                    and job.get("org_id") == caller_org):
                fleet_job = job
                break

        if not fleet_job or not fleet_job.get("result"):
            raise HTTPException(status_code=404, detail="No completed fleet scan found. Run POST /api/v1/fleet/scan first.")

        aggregate = fleet_job["result"].get("aggregate", {})
        cves = aggregate.get("cves_by_exposure", [])

        filtered = [
            c for c in cves
            if c["host_count"] >= min_hosts and c.get("max_epss", 0) >= min_epss
        ]

        return {
            "total_hosts": aggregate.get("total_hosts", 0),
            "total_cves": len(filtered),
            "cves": filtered,
        }

    # ── /api/v1/sla ───────────────────────────────────────────────────────────

    @app.get("/api/v1/sla")
    async def sla_report(
        ecosystem: str = Query("all"),
        critical_days: int = Query(7),
        high_days: int = Query(30),
        medium_days: int = Query(60),
        low_days: int = Query(90),
        request: Request = None,
    ) -> dict:
        """Return an SLA breach report based on CVSS severity and CVE age."""
        from selvo.analysis.sla import SLAPolicy, enrich_sla, sla_report as _sla_report
        from selvo.discovery.base import PackageRecord

        pkgs, taken_at = _get_snapshot_packages(ecosystem, request=request)
        if not pkgs:
            raise HTTPException(status_code=404, detail=f"No snapshot for '{ecosystem}'.")

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
            )
            for p in pkgs
        ]
        policy = SLAPolicy(critical=critical_days, high=high_days, medium=medium_days, low=low_days)
        packages = enrich_sla(packages, policy)
        report = _sla_report(packages)
        report["ecosystem"] = ecosystem
        report["snapshot_taken_at"] = (
            datetime.fromtimestamp(taken_at, tz=timezone.utc).isoformat() if taken_at else None
        )
        return report

    # ── /api/v1/advisories ────────────────────────────────────────────────────

    @app.get("/api/v1/advisories")
    async def list_advisories(
        ecosystem: str = Query("all"),
        limit: int = Query(50, ge=1, le=500),
        request: Request = None,
    ) -> dict:
        """Return packages that have vendor-issued security advisories (USN, Bodhi)."""
        pkgs, taken_at = _get_snapshot_packages(ecosystem, request=request)
        if not pkgs:
            raise HTTPException(status_code=404, detail=f"No snapshot for '{ecosystem}'.")

        with_advisories = [
            {
                "package": p["name"],
                "version": p.get("version", "unknown"),
                "advisory_ids": p.get("vendor_advisory_ids", []),
                "cve_ids": p.get("cve_ids", [])[:5],
                "score": p.get("score", 0.0),
            }
            for p in pkgs
            if p.get("vendor_advisory_ids")
        ]
        with_advisories.sort(key=lambda r: len(r["advisory_ids"]), reverse=True)
        return {
            "ecosystem": ecosystem,
            "total": len(with_advisories),
            "packages": with_advisories[:limit],
        }

    # ── GET /api/v1/report.sarif ──────────────────────────────────────────────

    @app.get("/api/v1/report.sarif", response_class=JSONResponse)
    async def report_sarif(ecosystem: str = Query("all"), request: Request = None) -> JSONResponse:
        """Export last snapshot as SARIF 2.1.0 for GitHub Code Scanning upload."""
        import json
        from selvo.reporters.sarif import render_sarif
        from selvo.discovery.base import PackageRecord

        pkgs, _ = _get_snapshot_packages(ecosystem, request=request)
        if not pkgs:
            raise HTTPException(status_code=404, detail=f"No snapshot for '{ecosystem}'.")

        packages = [PackageRecord(**{k: v for k, v in p.items() if k not in ("is_outdated", "cve_count")}) for p in pkgs]
        sarif_json = render_sarif(packages)
        return JSONResponse(content=json.loads(sarif_json), media_type="application/sarif+json")

    # ── GET /api/v1/report.vex ────────────────────────────────────────────────

    @app.get("/api/v1/report.vex", response_class=JSONResponse)
    async def report_vex(ecosystem: str = Query("all"), request: Request = None) -> JSONResponse:
        """Export last snapshot as CycloneDX 1.4 VEX document."""
        import json
        from selvo.reporters.vex import render_vex
        from selvo.discovery.base import PackageRecord

        pkgs, _ = _get_snapshot_packages(ecosystem, request=request)
        if not pkgs:
            raise HTTPException(status_code=404, detail=f"No snapshot for '{ecosystem}'.")

        packages = [PackageRecord(**{k: v for k, v in p.items() if k not in ("is_outdated", "cve_count")}) for p in pkgs]
        vex_json = render_vex(packages)
        return JSONResponse(content=json.loads(vex_json), media_type="application/vnd.cyclonedx+json")

    # ── GET /api/v1/report.nist ────────────────────────────────────────────────

    @app.get("/api/v1/report.nist", response_class=JSONResponse)
    async def report_nist(ecosystem: str = Query("all"), request: Request = None) -> JSONResponse:
        """Export last snapshot as NIST SP 800-53 Rev 5 OSCAL assessment results."""
        import json
        from selvo.reporters.nist import render_nist
        from selvo.discovery.base import PackageRecord

        pkgs, _ = _get_snapshot_packages(ecosystem, request=request)
        if not pkgs:
            raise HTTPException(status_code=404, detail=f"No snapshot for '{ecosystem}'.")

        packages = [PackageRecord(**{k: v for k, v in p.items() if k not in ("is_outdated", "cve_count")}) for p in pkgs]
        nist_json = render_nist(packages, framework="nist")
        return JSONResponse(content=json.loads(nist_json), media_type="application/json")

    # ── GET /api/v1/report.fedramp ─────────────────────────────────────────────

    @app.get("/api/v1/report.fedramp", response_class=JSONResponse)
    async def report_fedramp(ecosystem: str = Query("all"), request: Request = None) -> JSONResponse:
        """Export last snapshot as FedRAMP High baseline OSCAL assessment results."""
        import json
        from selvo.reporters.nist import render_nist
        from selvo.discovery.base import PackageRecord

        pkgs, _ = _get_snapshot_packages(ecosystem, request=request)
        if not pkgs:
            raise HTTPException(status_code=404, detail=f"No snapshot for '{ecosystem}'.")

        packages = [PackageRecord(**{k: v for k, v in p.items() if k not in ("is_outdated", "cve_count")}) for p in pkgs]
        fedramp_json = render_nist(packages, framework="fedramp")
        return JSONResponse(content=json.loads(fedramp_json), media_type="application/json")

    # ── GET /api/v1/report.pdf ────────────────────────────────────────────────

    @app.get("/api/v1/report.pdf")
    async def report_pdf(
        ecosystem: str = Query("all"),
        framework: str = Query("general"),
        request: Request = None,
    ):
        """Export last snapshot as a PDF compliance report.

        If weasyprint is available, returns application/pdf.
        Otherwise returns print-optimized HTML (use browser Print → Save as PDF).
        """
        from starlette.responses import Response
        from selvo.reporters.pdf import render_pdf, render_pdf_html
        from selvo.discovery.base import PackageRecord

        pkgs, _ = _get_snapshot_packages(ecosystem, request=request)
        if not pkgs:
            raise HTTPException(status_code=404, detail=f"No snapshot for '{ecosystem}'.")

        packages = [PackageRecord(**{k: v for k, v in p.items() if k not in ("is_outdated", "cve_count")}) for p in pkgs]
        pdf_bytes = render_pdf(packages, framework=framework)
        if pdf_bytes:
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=selvo-report-{framework}.pdf"},
            )
        # Fallback: print-optimized HTML
        html = render_pdf_html(packages, framework=framework)
        return _HTML_R(html)

    # ── POST /api/v1/scan/packages ────────────────────────────────────────────

    @app.post("/api/v1/scan/packages", status_code=202)
    async def scan_packages(req: PackageListRequest, background_tasks: BackgroundTasks, request: Request) -> dict:
        """
        Scan YOUR actual installed packages — paste the output of your
        package manager and get accurate CVE results for your real system.

        This is the most accurate scan mode. Unlike ``/analyze`` (which checks
        a reference package set), this checks exactly what's on your machine.
        """
        from selvo.analysis.fleet import parse_dpkg, parse_rpm, parse_pacman, parse_apk

        parsers = {"dpkg": parse_dpkg, "rpm": parse_rpm, "pacman": parse_pacman, "apk": parse_apk}
        eco_parser_map = {"debian": "dpkg", "ubuntu": "dpkg", "fedora": "rpm", "alpine": "apk", "arch": "pacman"}

        # Parse the package list
        pkg_versions: dict[str, str] = {}
        fmt = req.format
        if fmt == "auto":
            fmt = eco_parser_map.get(req.ecosystem, "dpkg")
            # Try the ecosystem's parser first
            pkg_versions = parsers.get(fmt, parse_dpkg)(req.packages)
            # If that got nothing, try TSV (name\tversion)
            if not pkg_versions:
                for line in req.packages.strip().splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        pkg_versions[parts[0].strip()] = parts[1].strip()
            # Still nothing? Try all parsers
            if not pkg_versions:
                for p in parsers.values():
                    pkg_versions = p(req.packages)
                    if pkg_versions:
                        break
        elif fmt == "tsv":
            for line in req.packages.strip().splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    pkg_versions[parts[0].strip()] = parts[1].strip()
        elif fmt in parsers:
            pkg_versions = parsers[fmt](req.packages)

        if not pkg_versions:
            raise HTTPException(status_code=422, detail=(
                "Could not parse any packages. Supported formats: "
                "dpkg-query output, rpm -qa output, pacman -Q, apk info -v, "
                "or tab-separated name\\tversion lines."
            ))

        # Build PackageRecords from the real installed packages.
        # Authenticated endpoint on dedicated hardware — no cap.
        from selvo.discovery.base import PackageRecord as _PR
        records = [
            _PR(name=name, version=version, ecosystem=req.ecosystem, version_source="local")
            for name, version in pkg_versions.items()
        ]

        caller = getattr(request.state, "org", None)
        from selvo.api.auth import track_event
        track_event("scan_submit", f"api:{req.ecosystem}:{len(records)}pkgs")
        jid = _new_job("scan_packages", {
            "ecosystem": req.ecosystem,
            "package_count": len(records),
            "source": "user_package_list",
        }, org_id=caller.org_id if caller else "")

        _caller_org_id = caller.org_id if caller else ""

        async def _run() -> None:
            _jobs[jid]["status"] = "running"
            try:
                from selvo.analysis.cve import enrich_cve
                from selvo.analysis.distro_status import filter_resolved_cves
                from selvo.analysis.redhat_status import filter_redhat_minor_cves
                from selvo.analysis.epss import enrich_epss
                from selvo.analysis.cvss import enrich_cvss
                from selvo.analysis.exploit import enrich_exploits
                from selvo.analysis.rdeps import enrich_reverse_deps
                from selvo.prioritizer.scorer import score_and_rank

                import asyncio as _asyncio
                pkgs = await enrich_cve(records)
                # epss, cvss, exploits are independent of each other — run concurrently.
                await _asyncio.gather(
                    enrich_epss(pkgs),
                    enrich_cvss(pkgs),
                    enrich_exploits(pkgs),
                )
                # Distro filters run after epss/exploits so the "unimportant"
                # override checks see populated signals. Debian and Red Hat
                # filters are disjoint (each only touches its own ecosystem
                # family) so they can run concurrently.
                await _asyncio.gather(
                    filter_resolved_cves(pkgs),
                    filter_redhat_minor_cves(pkgs),
                )
                pkgs = await enrich_reverse_deps(pkgs)
                ranked = score_and_rank(pkgs)

                # Suspicious-zero check before persisting — if a real-system
                # scan returned no CVEs, that's a likely pipeline bug, not a
                # reason to celebrate.
                from selvo.api.silent_zero import check as _silent_zero_check
                _silent_zero_check(ranked, req.ecosystem, {
                    "org_id": _caller_org_id, "source": "api/scan/packages", "job": jid,
                })

                # Save to org snapshot
                if _caller_org_id:
                    from selvo.api.tenancy import save_org_snapshot, record_org_metric
                    save_org_snapshot(_caller_org_id, req.ecosystem, ranked)
                    save_org_snapshot(_caller_org_id, "all", ranked)
                    record_org_metric(_caller_org_id, req.ecosystem, ranked)
                    record_org_metric(_caller_org_id, "all", ranked)

                result = {
                    "total_packages": len(ranked),
                    "with_cves": sum(1 for p in ranked if p.cve_count > 0),
                    "kev_count": sum(1 for p in ranked if p.in_cisa_kev),
                    "source": "your_system",
                    "top_10": [_pkg_to_dict(p) for p in ranked[:10]],
                }
                _jobs[jid]["status"] = "done"
                _jobs[jid]["result"] = result

                # Fire webhooks
                if _caller_org_id:
                    try:
                        await _fire_webhooks(_caller_org_id, result)
                    except Exception:
                        log.warning("Webhook delivery failed for org %s", _caller_org_id)
            except Exception as exc:
                _jobs[jid]["status"] = "error"
                _jobs[jid]["error"] = str(exc)
                log.exception("Package scan job %s failed", jid)

        background_tasks.add_task(_run)
        return {
            "job_id": jid,
            "status": "queued",
            "poll_url": f"/api/v1/jobs/{jid}",
            "packages_parsed": len(pkg_versions),
            "note": f"Scanning {len(pkg_versions)} packages from your system. Poll poll_url for results.",
        }

    # ── POST /api/v1/scan/image — container image scanning ───────────────────

    @app.post("/api/v1/scan/image", status_code=202)
    async def scan_image(req: ImageScanRequest, background_tasks: BackgroundTasks, request: Request) -> dict:
        """
        Scan a container image for vulnerabilities.

        Pulls the image, extracts the package list, and runs the full
        CVE/EPSS/CVSS enrichment pipeline.
        """
        caller = getattr(request.state, "org", None)
        jid = _new_job("scan_image", {"image": req.image, "ecosystem": req.ecosystem},
                        org_id=caller.org_id if caller else "")
        _caller_org_id = caller.org_id if caller else ""

        async def _run() -> None:
            _jobs[jid]["status"] = "running"
            try:
                from selvo.discovery.container import packages_from_docker_image
                records = packages_from_docker_image(req.image)
                if not records:
                    _jobs[jid]["status"] = "error"
                    _jobs[jid]["error"] = (
                        f"No packages found in image '{req.image}'. "
                        "Ensure the image exists and contains a supported package manager."
                    )
                    return

                from selvo.analysis.cve import enrich_cve
                from selvo.analysis.distro_status import filter_resolved_cves
                from selvo.analysis.redhat_status import filter_redhat_minor_cves
                from selvo.analysis.epss import enrich_epss
                from selvo.analysis.cvss import enrich_cvss
                from selvo.analysis.exploit import enrich_exploits
                from selvo.analysis.rdeps import enrich_reverse_deps
                from selvo.prioritizer.scorer import score_and_rank

                import asyncio as _asyncio
                pkgs = await enrich_cve(records)
                # epss, cvss, exploits are independent of each other — run concurrently.
                await _asyncio.gather(
                    enrich_epss(pkgs),
                    enrich_cvss(pkgs),
                    enrich_exploits(pkgs),
                )
                # Distro filters run after epss/exploits so the "unimportant"
                # override checks see populated signals. Debian and Red Hat
                # filters are disjoint (each only touches its own ecosystem
                # family) so they can run concurrently.
                await _asyncio.gather(
                    filter_resolved_cves(pkgs),
                    filter_redhat_minor_cves(pkgs),
                )
                pkgs = await enrich_reverse_deps(pkgs)
                ranked = score_and_rank(pkgs)

                from selvo.api.silent_zero import check as _silent_zero_check
                _silent_zero_check(ranked, req.ecosystem, {
                    "org_id": _caller_org_id, "source": "api/scan", "job": jid,
                })

                if _caller_org_id:
                    from selvo.api.tenancy import save_org_snapshot, record_org_metric
                    save_org_snapshot(_caller_org_id, req.ecosystem, ranked)
                    save_org_snapshot(_caller_org_id, "all", ranked)
                    record_org_metric(_caller_org_id, req.ecosystem, ranked)
                    record_org_metric(_caller_org_id, "all", ranked)

                result = {
                    "total_packages": len(ranked),
                    "with_cves": sum(1 for p in ranked if p.cve_count > 0),
                    "kev_count": sum(1 for p in ranked if p.in_cisa_kev),
                    "image": req.image,
                    "top_10": [_pkg_to_dict(p) for p in ranked[:10]],
                }
                _jobs[jid]["status"] = "done"
                _jobs[jid]["result"] = result

                if _caller_org_id:
                    try:
                        await _fire_webhooks(_caller_org_id, result)
                    except Exception:
                        log.warning("Webhook delivery failed for org %s", _caller_org_id)
            except Exception as exc:
                _jobs[jid]["status"] = "error"
                _jobs[jid]["error"] = str(exc)
                log.exception("Image scan job %s failed", jid)

        background_tasks.add_task(_run)
        return {
            "job_id": jid,
            "status": "queued",
            "poll_url": f"/api/v1/jobs/{jid}",
            "image": req.image,
            "note": f"Scanning image '{req.image}'. Poll poll_url for results.",
        }

    # ── POST /api/v1/scan ─────────────────────────────────────────────────────

    @app.post("/api/v1/scan", status_code=202)
    async def scan(req: ScanRequest, background_tasks: BackgroundTasks, request: Request) -> dict:
        """
        Scan a SBOM, scanner report, or lock file through the selvo pipeline.

        Accepts a file path on the server filesystem. Returns a job_id to poll.
        """
        caller = getattr(request.state, "org", None)
        jid = _new_job("scan", req.model_dump(), org_id=caller.org_id if caller else "")

        async def _run() -> None:
            _jobs[jid]["status"] = "running"
            try:
                if req.sbom:
                    from selvo.discovery.sbom_input import load_sbom
                    packages = load_sbom(_validate_scan_path(req.sbom))
                elif req.grype:
                    from selvo.discovery.scanner_import import load_grype
                    packages = load_grype(_validate_scan_path(req.grype))
                elif req.trivy:
                    from selvo.discovery.scanner_import import load_trivy
                    packages = load_trivy(_validate_scan_path(req.trivy))
                elif req.lockfile:
                    from selvo.discovery.lockfile import load_lockfile
                    packages = load_lockfile(_validate_scan_path(req.lockfile))
                else:
                    _jobs[jid]["status"] = "error"
                    _jobs[jid]["error"] = "Provide sbom, grype, trivy, or lockfile."
                    return

                if req.run_cve:
                    import asyncio as _asyncio
                    from selvo.analysis.cve import enrich_cve
                    from selvo.analysis.epss import enrich_epss
                    from selvo.analysis.cvss import enrich_cvss
                    from selvo.analysis.exploit import enrich_exploits
                    packages = await enrich_cve(packages)
                    await _asyncio.gather(
                        enrich_epss(packages),
                        enrich_cvss(packages),
                        enrich_exploits(packages),
                    )

                from selvo.prioritizer.scorer import score_and_rank
                ranked = score_and_rank(packages)

                # Inspect for silent-zero only when we actually ran enrichment;
                # if run_cve was False the caller asked us to skip CVE lookup.
                if req.run_cve:
                    # Pull a representative ecosystem from the loaded packages
                    # (sbom/grype/trivy may include several).
                    sample_eco = next((p.ecosystem for p in packages if p.ecosystem), "scan")
                    from selvo.api.silent_zero import check as _silent_zero_check
                    _silent_zero_check(ranked, sample_eco, {
                        "org_id": _jobs[jid].get("org_id", ""),
                        "source": "api/scan(sbom|grype|trivy|lockfile)",
                        "job": jid,
                    })

                # Save to org-scoped snapshot
                _scan_org = _jobs[jid].get("org_id", "")
                if _scan_org:
                    from selvo.api.tenancy import save_org_snapshot, record_org_metric
                    eco = "scan"
                    save_org_snapshot(_scan_org, eco, ranked)
                    record_org_metric(_scan_org, eco, ranked)

                _jobs[jid]["status"] = "done"
                _jobs[jid]["result"] = {
                    "total_packages": len(ranked),
                    "with_cves": sum(1 for p in ranked if p.cve_count > 0),
                    "kev_count": sum(1 for p in ranked if p.in_cisa_kev),
                    "top_10": [_pkg_to_dict(p) for p in ranked[:10]],
                }
            except ValueError as exc:
                _jobs[jid]["status"] = "error"
                _jobs[jid]["error"] = str(exc)
            except Exception:
                _jobs[jid]["status"] = "error"
                _jobs[jid]["error"] = "Internal scan error"
                log.exception("Scan job %s failed", jid)

        background_tasks.add_task(_run)
        return {"job_id": jid, "status": "queued", "poll_url": f"/api/v1/jobs/{jid}"}

    # ── Org management (requires SELVO_API_AUTH) ──────────────────────────────

    @app.post("/api/v1/orgs", status_code=201)
    async def create_org(body: dict, request: Request) -> dict:
        """Register a new organisation and return its first API key.

        Request body: ``{"org_id": "...", "name": "...", "email": "...", "plan": "free"}``

        The API key is returned **once** in plaintext — store it immediately.
        """
        client_ip = request.client.host if request.client else "unknown"
        if not _check_signup_rate(client_ip):
            raise HTTPException(status_code=429, detail="Too many signup attempts. Try again later.")

        from selvo.api.auth import register_org, generate_api_key

        org_id = (body.get("org_id") or "").strip()
        if not org_id:
            raise HTTPException(status_code=422, detail="org_id is required")
        if not _SAFE_ORG_RE.match(org_id):
            raise HTTPException(status_code=422, detail="org_id must be alphanumeric, hyphens, underscores (1-63 chars)")
        # Self-serve registration is always free. Upgrades go through Stripe.
        plan = "free"

        register_org(
            org_id,
            name=body.get("name", org_id),
            email=body.get("email", ""),
            plan=plan,
        )
        key = generate_api_key(org_id, plan=plan)
        return {"org_id": org_id, "plan": plan, "api_key": key}

    def _require_org_owner(request: Request, org_id: str) -> None:
        """Raise 403 if the authenticated caller does not own *org_id*."""
        caller = getattr(request.state, "org", None)
        if caller is None or (caller.org_id != org_id and caller.org_id != "system"):
            raise HTTPException(status_code=403, detail="Not authorized for this org")

    @app.get("/api/v1/orgs/{org_id}/keys")
    async def list_org_api_keys(org_id: str, request: Request) -> dict:
        """List metadata for all API keys belonging to *org_id*."""
        _require_org_owner(request, org_id)
        from selvo.api.auth import list_org_keys
        return {"org_id": org_id, "keys": list_org_keys(org_id)}

    @app.post("/api/v1/orgs/{org_id}/keys", status_code=201)
    async def create_org_api_key(org_id: str, body: dict, request: Request) -> dict:
        """Generate an additional API key for an existing org."""
        _require_org_owner(request, org_id)
        from selvo.api.auth import generate_api_key, _get_conn, _lock

        with _lock:
            row = _get_conn().execute(
                "SELECT plan FROM orgs WHERE org_id=?", (org_id,)
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail=f"Org '{org_id}' not found")

        plan = row[0]  # plan comes from DB, not user input
        key = generate_api_key(org_id, plan=plan)
        return {"org_id": org_id, "plan": plan, "api_key": key}

    @app.delete("/api/v1/orgs/{org_id}/keys/{key_hash}", status_code=204)
    async def revoke_org_api_key(org_id: str, key_hash: str, request: Request) -> None:
        """Deactivate a specific API key by its SHA-256 hash."""
        _require_org_owner(request, org_id)
        from selvo.api.auth import revoke_api_key
        if not revoke_api_key(key_hash, org_id=org_id):
            raise HTTPException(status_code=404, detail="Key not found or already revoked")

    # ── Policy-as-code enforcement ──────────────────────────────────────────

    class PolicyCheckRequest(BaseModel):
        ecosystem: str = Field("all", description="Ecosystem to check")
        policy: dict = Field(..., description="Policy YAML as JSON object")

    @app.post("/api/v1/policy/check")
    async def policy_check(req: PolicyCheckRequest, request: Request) -> dict:
        """Evaluate a policy-as-code document against the last snapshot.

        Request body: ``{"ecosystem": "debian", "policy": {...}}``
        The policy object follows the selvo.policy.yml schema.
        Returns ``{passed, blocked, warnings, allowed_cves, summary}``.
        """
        from selvo.analysis.policy import _parse_policy, enforce

        pkgs, _ = _get_snapshot_packages(req.ecosystem, request=request)
        if not pkgs:
            raise HTTPException(status_code=404, detail=f"No snapshot for '{req.ecosystem}'.")

        from selvo.discovery.base import PackageRecord
        packages = [
            PackageRecord(**{k: v for k, v in p.items() if k not in ("is_outdated", "cve_count")})
            for p in pkgs
        ]

        try:
            policy = _parse_policy(req.policy)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Invalid policy: {exc}")

        result = enforce(packages, policy)
        return {
            "passed": result.passed,
            "blocked": [
                {"rule": v.rule, "package": v.package, "cve": v.cve_id, "detail": v.detail}
                for v in result.blocked
            ],
            "warnings": [
                {"rule": v.rule, "package": v.package, "cve": v.cve_id, "detail": v.detail}
                for v in result.warnings
            ],
            "allowed_cves": list(result.allowed_cves),
            "summary": {
                "total_packages": len(packages),
                "blocked_count": len(result.blocked),
                "warning_count": len(result.warnings),
            },
        }

    # ── Auto-remediation (fix) ───────────────────────────────────────────────

    class FixRequest(BaseModel):
        ecosystem: str = Field("all", description="Ecosystem to fix")
        github_token: str = Field("", description="GitHub PAT for opening PRs")
        dry_run: bool = Field(True, description="If true, return plan without opening PRs")
        limit: int = Field(5, ge=1, le=20, description="Max packages to fix")

    @app.post("/api/v1/fix", status_code=202)
    async def fix_packages(
        req: FixRequest, background_tasks: BackgroundTasks, request: Request
    ) -> dict:
        """Open upstream PRs to fix the highest-risk packages.

        Requires a GitHub PAT with repo scope for live runs.
        Use ``dry_run: true`` to preview the plan without making changes.
        """
        caller = getattr(request.state, "org", None)
        jid = _new_job("fix", req.model_dump(), org_id=caller.org_id if caller else "")
        _caller_org_id = caller.org_id if caller else ""

        async def _run() -> None:
            _jobs[jid]["status"] = "running"
            try:
                pkgs, _ = _get_snapshot_packages(req.ecosystem, request=request)
                if not pkgs:
                    _jobs[jid]["status"] = "error"
                    _jobs[jid]["error"] = f"No snapshot for '{req.ecosystem}'."
                    return

                from selvo.discovery.base import PackageRecord
                packages = [
                    PackageRecord(**{k: v for k, v in p.items() if k not in ("is_outdated", "cve_count")})
                    for p in pkgs
                ]

                # Sort by score descending, take top N
                packages.sort(key=lambda p: p.score, reverse=True)
                targets = [p for p in packages[:req.limit] if p.cve_count > 0]

                if not targets:
                    _jobs[jid]["status"] = "done"
                    _jobs[jid]["result"] = {"fixes": [], "note": "No packages with CVEs to fix."}
                    return

                from selvo.analysis.fix import run_fix_pipeline
                from rich.console import Console
                results = await run_fix_pipeline(
                    packages=targets,
                    dry_run=req.dry_run,
                    github_token=req.github_token,
                    console=Console(quiet=True),
                )

                _jobs[jid]["status"] = "done"
                _jobs[jid]["result"] = {
                    "dry_run": req.dry_run,
                    "fixes": results,
                    "total_attempted": len(targets),
                    "prs_opened": sum(1 for r in results if r.get("status") == "opened"),
                }
            except Exception as exc:
                _jobs[jid]["status"] = "error"
                _jobs[jid]["error"] = str(exc)
                log.exception("Fix job %s failed", jid)

        background_tasks.add_task(_run)
        return {
            "job_id": jid,
            "status": "queued",
            "poll_url": f"/api/v1/jobs/{jid}",
            "dry_run": req.dry_run,
            "note": "Dry run — no PRs will be opened." if req.dry_run else "Opening upstream PRs for top-risk packages.",
        }

    # ── Webhook management ─────────────────────────────────────────────────────

    @app.post("/api/v1/orgs/{org_id}/webhooks", status_code=201)
    async def create_webhook(org_id: str, body: WebhookRequest, request: Request) -> dict:
        """Register a webhook for scan result notifications."""
        _require_org_owner(request, org_id)
        if not body.url.startswith("https://"):
            raise HTTPException(status_code=422, detail="Webhook URL must use HTTPS")
        from selvo.api.auth import add_webhook
        wid = add_webhook(org_id, body.url, body.kind)
        return {"id": wid, "org_id": org_id, "url": body.url, "kind": body.kind}

    @app.get("/api/v1/orgs/{org_id}/webhooks")
    async def get_webhooks(org_id: str, request: Request) -> dict:
        """List all webhooks for an org."""
        _require_org_owner(request, org_id)
        from selvo.api.auth import list_webhooks
        return {"org_id": org_id, "webhooks": list_webhooks(org_id)}

    @app.delete("/api/v1/orgs/{org_id}/webhooks/{webhook_id}", status_code=204)
    async def remove_webhook(org_id: str, webhook_id: int, request: Request) -> None:
        """Delete a webhook."""
        _require_org_owner(request, org_id)
        from selvo.api.auth import delete_webhook
        if not delete_webhook(webhook_id, org_id):
            raise HTTPException(status_code=404, detail="Webhook not found")

    async def _fire_webhooks(org_id: str, payload: dict) -> None:
        """Send scan results to all active webhooks for *org_id*."""
        from selvo.api.auth import list_webhooks
        hooks = list_webhooks(org_id)
        if not hooks:
            return
        import httpx as _hx
        async with _hx.AsyncClient(timeout=10.0) as client:
            for hook in hooks:
                if not hook.get("active"):
                    continue
                url = hook["url"]
                kind = hook.get("kind", "generic")
                try:
                    if kind == "slack":
                        # Slack-formatted message
                        cves = payload.get("with_cves", 0)
                        kev = payload.get("kev_count", 0)
                        total = payload.get("total_packages", 0)
                        text = f"*selvo scan complete* — {total} packages, {cves} with CVEs"
                        if kev:
                            text += f", *{kev} in CISA KEV* :rotating_light:"
                        slack_body = {"text": text}
                        await client.post(url, json=slack_body)
                    else:
                        # Generic webhook — full JSON payload
                        await client.post(url, json={
                            "event": "scan_complete",
                            "org_id": org_id,
                            "data": payload,
                        })
                except Exception:
                    log.warning("Webhook delivery failed: %s", url)

    # ── Stripe billing webhook ────────────────────────────────────────────────

    # ── POST /api/v1/billing/checkout ────────────────────────────────────────

    @app.post("/api/v1/billing/checkout", status_code=200)
    async def create_checkout(req: CheckoutRequest, request: Request) -> dict:
        """Create a Stripe Checkout session. Returns ``{url, session_id}``.

        Redirect the user to ``url`` to complete payment.
        """
        from selvo.api.billing import create_checkout_session, StripeConfigError
        base = f"{request.url.scheme}://{request.url.netloc}"
        try:
            session = create_checkout_session(
                org_id=req.org_id,
                plan=req.plan,
                success_url=f"{base}/dash/billing?success=1",
                cancel_url=f"{base}/dash/billing",
            )
        except StripeConfigError as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        except Exception as exc:
            log.error("Stripe checkout creation failed: %s", exc)
            raise HTTPException(status_code=502, detail="Stripe checkout failed")
        return {"url": session["url"], "session_id": session["id"]}

    @app.post("/api/v1/billing/webhook", status_code=200)
    async def stripe_webhook(
        request: "Request",
        background_tasks: BackgroundTasks,
    ) -> dict:
        """Receive and verify Stripe webhook events (v1 and v2).

        v1 (classic): full event in payload, signed with ``whsec_…``.
        v2 (thin events): thin envelope in payload; full event fetched via API.
        Verifies the ``Stripe-Signature`` header using HMAC-SHA256.
        Processes the event asynchronously so Stripe receives a fast 200.
        """
        from selvo.api.billing import (
            verify_stripe_signature, handle_stripe_event,
            fetch_stripe_event, StripeWebhookError,
        )
        import json as _json

        payload = await request.body()
        sig_header = request.headers.get("Stripe-Signature", "")
        webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")

        try:
            api_version = verify_stripe_signature(payload, sig_header, webhook_secret)
        except StripeWebhookError as exc:
            log.warning("Invalid Stripe webhook: %s", exc)
            raise HTTPException(status_code=400, detail=str(exc))

        try:
            envelope = _json.loads(payload)
        except ValueError:
            raise HTTPException(status_code=400, detail="Webhook payload is not valid JSON")

        # v2 thin events: payload is a thin envelope; fetch full event from API.
        if api_version == "v2":
            event_id = envelope.get("id", "")
            if not event_id:
                raise HTTPException(status_code=400, detail="v2 thin event missing id field")
            try:
                event = fetch_stripe_event(event_id)
            except Exception as exc:
                log.error("Failed to hydrate v2 thin event %s: %s", event_id, exc)
                raise HTTPException(status_code=502, detail="Could not fetch full event from Stripe")
        else:
            event = envelope

        background_tasks.add_task(handle_stripe_event, event)
        return {"received": True, "event_type": event.get("type", "unknown"), "api_version": api_version}

    # ── Dashboard (Jinja2 + htmx) ─────────────────────────────────────────────

    from fastapi.responses import HTMLResponse, RedirectResponse

    try:
        from selvo.api import dashboard as _dash
        _DASH_AVAILABLE = True
    except ImportError:
        _DASH_AVAILABLE = False

    _DASH_ORG = os.getenv("SELVO_DASH_ORG", "default")

    def _dash_packages(request: Request, ecosystem: str) -> tuple[list[dict], float]:
        """Return snapshot packages scoped to the authenticated org when auth is active."""
        org = getattr(request.state, "org", None)
        if org is not None:
            from selvo.api.tenancy import load_org_snapshot
            result = load_org_snapshot(org.org_id, ecosystem)
            return result if result is not None else ([], 0.0)
        return _get_snapshot_packages(ecosystem, request=request)

    def _dash_metrics(request: Request, ecosystem: str, days: int = 90) -> list[dict]:
        """Return trend metrics scoped to the authenticated org when auth is active."""
        from selvo.analysis.trend import load_metrics
        org = getattr(request.state, "org", None)
        if org is not None:
            from selvo.api.tenancy import org_ecosystem_key
            return load_metrics(org_ecosystem_key(org.org_id, ecosystem), days=days)
        return load_metrics(ecosystem, days=days)

    def _dash_org_id(request: Request) -> str:
        """Return the org_id for dashboard key management pages."""
        org = getattr(request.state, "org", None)
        return org.org_id if org is not None else _DASH_ORG

    @app.get("/dash", response_class=RedirectResponse, include_in_schema=False)
    async def dash_root():
        return RedirectResponse(url="/dash/overview")

    @app.get("/dash/login", response_class=HTMLResponse, include_in_schema=False)
    async def dash_login_page(request: Request):
        # If already logged in, redirect to overview
        cookie = request.cookies.get(_SESSION_COOKIE, "")
        if _verify_session(cookie):
            return RedirectResponse(url="/dash/overview", status_code=302)
        return HTMLResponse(_dash.render_login())

    @app.post("/dash/login", response_class=HTMLResponse, include_in_schema=False)
    async def dash_login_submit(request: Request):
        form = await request.form()
        org_id = str(form.get("org_id", "")).strip()
        email = str(form.get("email", "")).strip()

        if not org_id or not email:
            return HTMLResponse(_dash.render_login("Organization ID and email are required."))

        # Verify the org exists and email matches
        from selvo.api.auth import _get_conn, _lock
        with _lock:
            row = _get_conn().execute(
                "SELECT plan, email FROM orgs WHERE org_id=?", (org_id,)
            ).fetchone()
        if row is None:
            return HTMLResponse(_dash.render_login("Organization not found."))
        db_plan, db_email = row[0], row[1]
        if db_email.lower() != email.lower():
            return HTMLResponse(_dash.render_login("Email does not match this organization."))

        # Create signed session cookie
        session_value = _sign_session({
            "org_id": org_id,
            "plan": db_plan,
            "sid": _secrets.token_urlsafe(16),
        })
        response = RedirectResponse(url="/dash/overview", status_code=302)
        response.set_cookie(
            _SESSION_COOKIE,
            session_value,
            max_age=_SESSION_MAX_AGE,
            httponly=True,
            secure=request.url.scheme == "https" or bool(os.getenv("SELVO_API_AUTH")),
            samesite="lax",
        )
        return response

    @app.get("/dash/logout", response_class=RedirectResponse, include_in_schema=False)
    async def dash_logout():
        response = RedirectResponse(url="/", status_code=302)
        response.delete_cookie(_SESSION_COOKIE)
        return response

    @app.get("/dash/overview", response_class=HTMLResponse, include_in_schema=False)
    async def dash_overview(request: Request, ecosystem: str = "all"):
        if not _DASH_AVAILABLE:
            return HTMLResponse("<h1>Dashboard unavailable</h1>", status_code=503)
        pkgs, taken_at = _dash_packages(request, ecosystem)
        org_id = _dash_org_id(request)

        # Auto-trigger a reference scan on first visit if no data exists
        if not pkgs:
            caller = getattr(request.state, "org", None)
            caller_org = caller.org_id if caller else ""
            if caller_org:
                from selvo.api.tenancy import load_org_snapshot
                # Check if we already queued a scan (avoid re-triggering on refresh)
                already_queued = any(
                    j.get("org_id") == caller_org and j.get("kind") == "analyze" and j["status"] in ("queued", "running")
                    for j in _jobs.values()
                )
                if not already_queued:
                    from selvo.mcp_server import _run_pipeline
                    jid = _new_job("analyze", {"ecosystem": "debian", "limit": 30}, org_id=caller_org)

                    async def _auto_scan() -> None:
                        _jobs[jid]["status"] = "running"
                        try:
                            packages = await _run_pipeline(ecosystem="debian", limit=30, context_mode="reference", run_cve=True)
                            from selvo.api.tenancy import save_org_snapshot, record_org_metric
                            save_org_snapshot(caller_org, "debian", packages)
                            save_org_snapshot(caller_org, "all", packages)
                            record_org_metric(caller_org, "debian", packages)
                            record_org_metric(caller_org, "all", packages)
                            _jobs[jid]["status"] = "done"
                            _jobs[jid]["result"] = {"total_packages": len(packages), "with_cves": sum(1 for p in packages if p.cve_count > 0)}
                        except Exception as exc:
                            _jobs[jid]["status"] = "error"
                            _jobs[jid]["error"] = str(exc)

                    import asyncio
                    asyncio.ensure_future(_auto_scan())

        return HTMLResponse(_dash.render_overview(pkgs, taken_at, org_id=org_id))

    @app.get("/dash/packages", response_class=HTMLResponse, include_in_schema=False)
    async def dash_packages(
        request: Request,
        ecosystem: str = "all",
        q: str = "",
        show_all: str = "",
        show_acked: str = "",
    ):
        if not _DASH_AVAILABLE:
            return HTMLResponse("<h1>Dashboard unavailable</h1>", status_code=503)
        pkgs, _ = _dash_packages(request, ecosystem)
        from selvo.api.acks import load_acks
        org_id = _dash_org_id(request)
        acks_map = load_acks(org_id) if org_id else {}
        csrf = _generate_csrf_token()
        page = _dash.render_packages(
            pkgs, query=q,
            show_all=bool(show_all),
            show_acked=bool(show_acked),
            acks=acks_map,
            csrf_token=csrf,
        )
        return HTMLResponse(page)

    @app.post("/dash/packages/ack", response_class=HTMLResponse, include_in_schema=False)
    async def dash_packages_ack(request: Request):
        """Mark a package as acknowledged for the signed-in org."""
        if not _DASH_AVAILABLE:
            return HTMLResponse("<h1>Dashboard unavailable</h1>", status_code=503)
        form = await request.form()
        if not _verify_csrf_token(str(form.get("_csrf", ""))):
            return HTMLResponse('<div class="alert alert-danger">Invalid form. Reload and try again.</div>', status_code=403)
        pkg_name = str(form.get("pkg_name", "")).strip()
        if not pkg_name:
            return RedirectResponse(url="/dash/packages", status_code=303)
        org_id = _dash_org_id(request)
        # Pull this package's current cve_ids from the snapshot so the ack
        # captures a hash of "what was true when you acknowledged it".
        pkgs, _ = _dash_packages(request, "all")
        pkg = next((p for p in pkgs if p.get("name") == pkg_name), None)
        cves = pkg.get("cve_ids", []) if pkg else []
        from selvo.api.acks import ack as _ack
        _ack(
            org_id=org_id,
            pkg_name=pkg_name,
            cve_ids=cves,
            reason=str(form.get("reason", "")).strip(),
            ecosystem=str(form.get("ecosystem", "")).strip(),
        )
        return RedirectResponse(url="/dash/packages", status_code=303)

    @app.post("/dash/packages/unack", response_class=HTMLResponse, include_in_schema=False)
    async def dash_packages_unack(request: Request):
        """Restore a previously-acknowledged package to the active list."""
        if not _DASH_AVAILABLE:
            return HTMLResponse("<h1>Dashboard unavailable</h1>", status_code=503)
        form = await request.form()
        if not _verify_csrf_token(str(form.get("_csrf", ""))):
            return HTMLResponse('<div class="alert alert-danger">Invalid form. Reload and try again.</div>', status_code=403)
        pkg_name = str(form.get("pkg_name", "")).strip()
        if pkg_name:
            from selvo.api.acks import unack as _unack
            _unack(_dash_org_id(request), pkg_name)
        return RedirectResponse(url="/dash/packages?show_acked=1", status_code=303)

    def _export_filename(ext: str, org_id: str) -> str:
        from datetime import datetime as _dt
        stamp = _dt.utcnow().strftime("%Y%m%d")
        slug = (org_id or "selvo").replace("/", "-")
        return f"{slug}-{stamp}.{ext}"

    @app.get("/dash/export/sarif", include_in_schema=False)
    async def dash_export_sarif(request: Request, ecosystem: str = "all"):
        """Proxy SARIF export through dashboard session auth."""
        from starlette.responses import Response
        from selvo.reporters.sarif import render_sarif
        from selvo.discovery.base import PackageRecord
        pkgs, _ = _dash_packages(request, ecosystem)
        if not pkgs:
            return JSONResponse({"detail": "No snapshot data. Run an analysis first."}, status_code=404)
        packages = [PackageRecord(**{k: v for k, v in p.items() if k not in ("is_outdated", "cve_count")}) for p in pkgs]
        sarif_json = render_sarif(packages)
        filename = _export_filename("sarif.json", _dash_org_id(request))
        return Response(
            content=sarif_json,
            media_type="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/dash/export/vex", include_in_schema=False)
    async def dash_export_vex(request: Request, ecosystem: str = "all"):
        """Proxy VEX export through dashboard session auth."""
        from starlette.responses import Response
        from selvo.reporters.vex import render_vex
        from selvo.discovery.base import PackageRecord
        pkgs, _ = _dash_packages(request, ecosystem)
        if not pkgs:
            return JSONResponse({"detail": "No snapshot data. Run an analysis first."}, status_code=404)
        packages = [PackageRecord(**{k: v for k, v in p.items() if k not in ("is_outdated", "cve_count")}) for p in pkgs]
        vex_json = render_vex(packages)
        filename = _export_filename("vex.json", _dash_org_id(request))
        return Response(
            content=vex_json,
            media_type="application/vnd.cyclonedx+json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/dash/cves", response_class=HTMLResponse, include_in_schema=False)
    async def dash_cves(request: Request, ecosystem: str = "all"):
        if not _DASH_AVAILABLE:
            return HTMLResponse("<h1>Dashboard unavailable</h1>", status_code=503)
        pkgs, _ = _dash_packages(request, ecosystem)
        return HTMLResponse(_dash.render_cves(pkgs))

    @app.get("/dash/trends", response_class=HTMLResponse, include_in_schema=False)
    async def dash_trends(request: Request, ecosystem: str = "all"):
        if not _DASH_AVAILABLE:
            return HTMLResponse("<h1>Dashboard unavailable</h1>", status_code=503)
        try:
            metrics = _dash_metrics(request, ecosystem, days=90)
        except Exception:
            metrics = []
        return HTMLResponse(_dash.render_trends(metrics))

    @app.get("/dash/keys", response_class=HTMLResponse, include_in_schema=False)
    async def dash_keys(request: Request, new_key: str = ""):
        if not _DASH_AVAILABLE:
            return HTMLResponse("<h1>Dashboard unavailable</h1>", status_code=503)
        org_id = _dash_org_id(request)
        csrf = _generate_csrf_token()
        try:
            from selvo.api.auth import list_org_keys, register_org
            register_org(org_id, name=org_id, plan="free")
            keys = list_org_keys(org_id)
        except Exception:
            keys = []
        # Show the new API key banner if just signed up
        message = ""
        if new_key and new_key.startswith("sk_"):
            message = (
                f'<div class="alert alert-success" style="background:rgba(63,185,80,.1);border-color:rgba(63,185,80,.3);color:#3fb950">'
                f'<strong>Welcome! Your API key:</strong>'
                f'<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:.5rem .75rem;'
                f'margin:.5rem 0;font-family:monospace;font-size:.85rem;word-break:break-all;color:#e3b341">{_html_mod.escape(new_key)}</div>'
                f'<small>Save this key — it won\'t be shown again. Use it in the '
                f'<a href="/dash/scan" style="color:#58a6ff">Scan</a> page or with the '
                f'<a href="/install.sh" style="color:#58a6ff">install script</a>.</small>'
                f'</div>'
            )
        return HTMLResponse(_dash.render_keys(org_id, keys, csrf_token=csrf, message=message))

    @app.post("/dash/keys", response_class=HTMLResponse, include_in_schema=False)
    async def dash_create_key(request: Request):
        from fastapi.responses import HTMLResponse
        form = await request.form()
        csrf = str(form.get("_csrf", ""))
        if not _verify_csrf_token(csrf):
            return HTMLResponse('<div class="alert alert-danger">Invalid or expired form. Please reload and try again.</div>', status_code=403)
        org_id = _dash_org_id(request)
        try:
            from selvo.api.auth import generate_api_key, list_org_keys, _get_conn, _lock
            # Use the org's actual plan from DB — not user input
            with _lock:
                row = _get_conn().execute("SELECT plan FROM orgs WHERE org_id=?", (org_id,)).fetchone()
            plan = row[0] if row else "free"
            key = generate_api_key(org_id, plan=plan)
            keys = list_org_keys(org_id)
            new_csrf = _generate_csrf_token()
            return HTMLResponse(_dash.render_new_key_result(org_id, key, keys, csrf_token=new_csrf))
        except ValueError as exc:
            # Expected: key limit reached — show friendly message, don't alert Sentry
            keys = list_org_keys(org_id)
            new_csrf = _generate_csrf_token()
            return HTMLResponse(_dash.render_keys(org_id, keys, csrf_token=new_csrf,
                message=f'<div class="alert alert-warning">{_html_mod.escape(str(exc))}</div>'))
        except Exception:
            log.exception("Key creation failed for org %s", org_id)
            return HTMLResponse('<div class="alert alert-danger">Error creating key. Please try again.</div>')

    @app.post("/dash/keys/revoke", response_class=HTMLResponse, include_in_schema=False)
    async def dash_revoke_key(request: Request):
        form = await request.form()
        csrf = str(form.get("_csrf", ""))
        if not _verify_csrf_token(csrf):
            return HTMLResponse('<div class="alert alert-danger">Invalid or expired form. Please reload and try again.</div>', status_code=403)
        key_hash = str(form.get("key_hash", ""))
        org_id = _dash_org_id(request)
        try:
            from selvo.api.auth import revoke_api_key, list_org_keys
            revoke_api_key(key_hash, org_id=org_id)
            keys = list_org_keys(org_id)
        except Exception:
            keys = []
        new_csrf = _generate_csrf_token()
        return HTMLResponse(_dash.render_keys(org_id, keys, message="Key revoked.", csrf_token=new_csrf))

    @app.get("/dash/_refresh_badge", response_class=HTMLResponse, include_in_schema=False)
    async def dash_refresh_badge():
        return HTMLResponse(
            f'<span class="text-muted" hx-get="/dash/_refresh_badge" '
            f'hx-trigger="every 60s" hx-swap="outerHTML">'
            f'(refreshed {datetime.now(timezone.utc).strftime("%H:%M")} UTC)</span>'
        )

    @app.get("/dash/scan", response_class=HTMLResponse, include_in_schema=False)
    async def dash_scan_page(request: Request, new_key: str = ""):
        csrf = _generate_csrf_token()
        return HTMLResponse(_dash.render_scan(csrf_token=csrf, api_key=new_key))

    @app.post("/dash/scan/generate-key", response_class=HTMLResponse, include_in_schema=False)
    async def dash_scan_generate_key(request: Request):
        """Generate a new API key and redirect back to scan page with it visible."""
        org_id = _dash_org_id(request)
        from selvo.api.auth import generate_api_key, _get_conn, _lock
        with _lock:
            row = _get_conn().execute("SELECT plan FROM orgs WHERE org_id=?", (org_id,)).fetchone()
        plan = row[0] if row else "free"
        try:
            key = generate_api_key(org_id, plan=plan)
        except ValueError as exc:
            return HTMLResponse(f'<div class="alert alert-danger">{_html_mod.escape(str(exc))}</div>')
        return RedirectResponse(url=f"/dash/scan?new_key={key}", status_code=302)

    @app.post("/dash/scan", response_class=HTMLResponse, include_in_schema=False)
    async def dash_scan_submit(request: Request, background_tasks: BackgroundTasks):
        form = await request.form()
        csrf = str(form.get("_csrf", ""))
        if not _verify_csrf_token(csrf):
            return HTMLResponse('<div class="alert alert-danger">Invalid form. Reload and try again.</div>', status_code=403)

        packages_text = str(form.get("packages", "")).strip()
        ecosystem = str(form.get("ecosystem", "debian")).strip()

        if not packages_text:
            new_csrf = _generate_csrf_token()
            return HTMLResponse(_dash.render_scan(csrf_token=new_csrf, result={"status": "error", "error": "Please paste your package list."}))

        # Parse and scan — same logic as /api/v1/scan/packages
        from selvo.analysis.fleet import parse_dpkg, parse_rpm, parse_pacman, parse_apk
        parsers = {
            "debian": parse_dpkg, "ubuntu": parse_dpkg,
            "fedora": parse_rpm, "rocky": parse_rpm, "almalinux": parse_rpm, "suse": parse_rpm, "opensuse": parse_rpm,
            "arch": parse_pacman, "alpine": parse_apk,
        }
        parser = parsers.get(ecosystem, parse_dpkg)
        parsed = parser(packages_text)

        if not parsed:
            new_csrf = _generate_csrf_token()
            return HTMLResponse(_dash.render_scan(csrf_token=new_csrf, result={
                "status": "error",
                "error": f"Could not parse any packages from the input. Make sure you selected the right ecosystem ({ecosystem}).",
            }))

        from selvo.discovery.base import PackageRecord
        records = [
            PackageRecord(name=name, version=version, ecosystem=ecosystem)
            for name, version in parsed.items()
        ]

        caller = getattr(request.state, "org", None)
        caller_org = caller.org_id if caller else ""
        from selvo.api.auth import track_event
        track_event("scan_submit", f"dash:{ecosystem}:{len(records)}pkgs")
        jid = _new_job("scan_packages", {"ecosystem": ecosystem, "count": len(records)}, org_id=caller_org)

        async def _run() -> None:
            _jobs[jid]["status"] = "running"
            try:
                from selvo.analysis.cve import enrich_cve
                from selvo.analysis.distro_status import filter_resolved_cves
                from selvo.analysis.redhat_status import filter_redhat_minor_cves
                from selvo.analysis.epss import enrich_epss
                from selvo.analysis.cvss import enrich_cvss
                from selvo.analysis.exploit import enrich_exploits
                from selvo.analysis.rdeps import enrich_reverse_deps
                from selvo.prioritizer.scorer import score_and_rank

                import asyncio as _asyncio
                pkgs = await enrich_cve(records)
                # epss, cvss, exploits are independent of each other — run concurrently.
                await _asyncio.gather(
                    enrich_epss(pkgs),
                    enrich_cvss(pkgs),
                    enrich_exploits(pkgs),
                )
                # Distro filters run after epss/exploits so the "unimportant"
                # override checks see populated signals. Debian and Red Hat
                # filters are disjoint (each only touches its own ecosystem
                # family) so they can run concurrently.
                await _asyncio.gather(
                    filter_resolved_cves(pkgs),
                    filter_redhat_minor_cves(pkgs),
                )
                pkgs = await enrich_reverse_deps(pkgs)
                ranked = score_and_rank(pkgs)

                from selvo.api.silent_zero import check as _silent_zero_check
                _silent_zero_check(ranked, ecosystem, {
                    "org_id": caller_org, "source": "/dash/scan", "job": jid,
                })

                if caller_org:
                    from selvo.api.tenancy import save_org_snapshot, record_org_metric
                    save_org_snapshot(caller_org, ecosystem, ranked)
                    save_org_snapshot(caller_org, "all", ranked)
                    record_org_metric(caller_org, ecosystem, ranked)
                    record_org_metric(caller_org, "all", ranked)

                _jobs[jid]["status"] = "done"
                _jobs[jid]["result"] = {
                    "total_packages": len(ranked),
                    "with_cves": sum(1 for p in ranked if p.cve_count > 0),
                    "kev_count": sum(1 for p in ranked if p.in_cisa_kev),
                    "source": "your_system",
                }
            except Exception as exc:
                _jobs[jid]["status"] = "error"
                _jobs[jid]["error"] = str(exc)
                log.exception("Dashboard scan job %s failed", jid)

        background_tasks.add_task(_run)

        new_csrf = _generate_csrf_token()
        return HTMLResponse(_dash.render_scan(csrf_token=new_csrf, result={
            "status": "queued",
            "job_id": jid,
            "total_packages": len(records),
        }))

    @app.get("/dash/policy", response_class=HTMLResponse, include_in_schema=False)
    async def dash_policy(request: Request):
        csrf = _generate_csrf_token()
        return HTMLResponse(_dash.render_policy(csrf_token=csrf))

    @app.post("/dash/policy", response_class=HTMLResponse, include_in_schema=False)
    async def dash_policy_submit(request: Request):
        form = await request.form()
        csrf = str(form.get("_csrf", ""))
        if not _verify_csrf_token(csrf):
            return HTMLResponse('<div class="alert alert-danger">Invalid form. Reload and try again.</div>', status_code=403)

        policy_yaml = str(form.get("policy_yaml", ""))

        try:
            import yaml  # type: ignore[import-untyped]
            policy_dict = yaml.safe_load(policy_yaml)
        except Exception:
            new_csrf = _generate_csrf_token()
            return HTMLResponse(_dash.render_policy(
                result={"passed": False, "blocked": [{"rule": "parse_error", "package": "", "cve": "", "detail": "Invalid YAML"}], "warnings": [], "summary": {"blocked_count": 1, "warning_count": 0}},
                csrf_token=new_csrf,
            ))

        from selvo.analysis.policy import _parse_policy, enforce
        from selvo.discovery.base import PackageRecord

        try:
            policy = _parse_policy(policy_dict)
        except Exception as exc:
            new_csrf = _generate_csrf_token()
            return HTMLResponse(_dash.render_policy(
                result={"passed": False, "blocked": [{"rule": "policy_error", "package": "", "cve": "", "detail": str(exc)}], "warnings": [], "summary": {"blocked_count": 1, "warning_count": 0}},
                csrf_token=new_csrf,
            ))

        pkgs, _ = _dash_packages(request, "all")
        packages = [
            PackageRecord(**{k: v for k, v in p.items() if k not in ("is_outdated", "cve_count")})
            for p in pkgs
        ] if pkgs else []

        result_obj = enforce(packages, policy)
        result = {
            "passed": result_obj.passed,
            "blocked": [{"rule": v.rule, "package": v.package, "cve": v.cve_id, "detail": v.detail} for v in result_obj.blocked],
            "warnings": [{"rule": v.rule, "package": v.package, "cve": v.cve_id, "detail": v.detail} for v in result_obj.warnings],
            "summary": {"blocked_count": len(result_obj.blocked), "warning_count": len(result_obj.warnings)},
        }
        new_csrf = _generate_csrf_token()
        return HTMLResponse(_dash.render_policy(result=result, csrf_token=new_csrf))

    @app.get("/dash/billing", response_class=HTMLResponse, include_in_schema=False)
    async def dash_billing(request: Request):
        plan = getattr(getattr(request.state, "org", None), "plan", "free") or "free"
        csrf = _generate_csrf_token()
        return HTMLResponse(_dash.render_billing(plan, csrf_token=csrf))

    @app.post("/dash/billing/checkout", response_class=HTMLResponse, include_in_schema=False)
    async def dash_billing_checkout(request: Request):
        from selvo.api.billing import create_checkout_session
        form = await request.form()
        csrf = str(form.get("_csrf", ""))
        if not _verify_csrf_token(csrf):
            return HTMLResponse('<div class="alert alert-danger">Invalid or expired form. Please reload.</div>', status_code=403)
        plan = str(form.get("plan", "pro"))
        if plan not in ("pro", "enterprise"):
            plan = "pro"
        org_id = getattr(getattr(request.state, "org", None), "org_id", "anonymous") or "anonymous"
        try:
            base = f"{request.url.scheme}://{request.url.netloc}"
            session = create_checkout_session(
                org_id=org_id,
                plan=plan,
                success_url=f"{base}/dash/billing?success=1",
                cancel_url=f"{base}/dash/billing",
            )
            url = session.get("url", "")
            # Validate URL is from Stripe before redirecting
            if url and url.startswith("https://checkout.stripe.com/"):
                return HTMLResponse(f'<script>window.location.href="{_html_mod.escape(url)}";</script>')
            return HTMLResponse('<div class="alert alert-danger mt-2">Unexpected checkout URL</div>')
        except Exception:  # noqa: BLE001
            log.exception("Stripe checkout failed for org %s", org_id)
            return HTMLResponse('<div class="alert alert-danger mt-2">Billing error. Please try again.</div>')

    return app


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    """selvo-api entrypoint."""
    import argparse

    if not _FASTAPI_AVAILABLE:
        print("FastAPI is not installed. Run: pip install 'selvo[api]'")
        raise SystemExit(1)

    parser = argparse.ArgumentParser(prog="selvo-api", description="selvo REST API server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--reload", action="store_true", help="Enable hot-reload (dev only)")
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args()

    app = create_app()
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )


if __name__ == "__main__":
    main()
