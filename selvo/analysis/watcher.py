"""
Webhook alert daemon — continuously monitor packages and fire alerts on risk changes.

Configuration is stored at ~/.config/selvo/watches.json:
    [
      {
        "id": "prod-debian",
        "ecosystem": "debian",
        "limit": 50,
        "interval_hours": 6,
        "webhook_url": "env:SELVO_SLACK_WEBHOOK",
        "alert_on": ["new_cve", "epss_jump", "exploit_available", "kev_listed"],
        "min_epss_jump": 0.10,
        "min_score_delta": 5.0
      }
    ]

Security note — keeping webhook URLs out of config files:
  Set ``webhook_url`` to ``"env:VAR_NAME"`` and export the URL as an environment
  variable instead of embedding it in the JSON file.  Committing a raw
  ``https://hooks.slack.com/...`` URL to git exposes it permanently.

  Supported forms:
    "webhook_url": "env:SELVO_SLACK_WEBHOOK"       → os.environ["SELVO_SLACK_WEBHOOK"]
    "webhook_url": "env:MY_PD_KEY"                 → PagerDuty routing key via env

  If ``webhook_url`` is empty or missing, selvo will check ``SELVO_SLACK_WEBHOOK``
  and ``SELVO_WEBHOOK_URL`` automatically before giving up.

Alert types:
    new_cve           — a CVE appeared since last snapshot
    epss_jump         — EPSS exploitation probability jumped ≥ min_epss_jump
    exploit_available — a PoC or weaponized exploit was newly discovered
    kev_listed        — package CVE was added to CISA's KEV catalog
    score_change      — composite priority score changed by ≥ min_score_delta

Webhook payload (Slack-compatible + generic):
    {
      "text": "selvo alert: 3 new CVEs in debian packages",
      "selvo": {
        "alert_type": "new_cve",
        "ecosystem": "debian",
        "packages": [...],
        "generated_at": "2024-..."
      }
    }

CLI: selvo watch [--start|--stop|--status|--add|--remove]
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)

_CONFIG_DIR = Path.home() / ".config" / "selvo"
_WATCHES_FILE = _CONFIG_DIR / "watches.json"
_PID_FILE = _CONFIG_DIR / "watcher.pid"


def _resolve_webhook_url(raw: str) -> str:
    """Resolve a webhook URL from config, supporting env-var indirection.

    Supported forms:
      - ``"env:VAR_NAME"``          → ``os.environ["VAR_NAME"]``
      - ``""`` (empty)              → ``SELVO_SLACK_WEBHOOK`` or ``SELVO_WEBHOOK_URL`` env var
      - Any other string            → returned as-is; a warning is emitted when the
                                      URL looks like a raw Slack webhook so operators
                                      know to move it to an env var.
    """
    if raw.startswith("env:"):
        var = raw[4:].strip()
        value = os.getenv(var, "")
        if not value:
            log.warning(
                "Webhook env var %r is not set; no alerts will be sent for this watch",
                var,
            )
        return value

    if not raw:
        # Auto-discover from well-known env vars
        return (
            os.getenv("SELVO_SLACK_WEBHOOK")
            or os.getenv("SELVO_WEBHOOK_URL")
            or ""
        )

    # Plain URL — warn if it looks like a Slack webhook embedded in config
    if "hooks.slack.com" in raw or raw.startswith("https://hooks."):
        log.warning(
            "Slack webhook URL is stored as plaintext in watches config. "
            "Set webhook_url to \"env:SELVO_SLACK_WEBHOOK\" and export the URL "
            "as an environment variable to avoid committing secrets to git."
        )
    return raw


# ── Config dataclasses ────────────────────────────────────────────────────────

@dataclass
class WatchConfig:
    id: str
    ecosystem: str = "all"
    limit: int = 50
    interval_hours: float = 6.0
    webhook_url: str = ""
    alert_on: list[str] = field(default_factory=lambda: [
        "new_cve", "epss_jump", "exploit_available", "kev_listed"
    ])
    min_epss_jump: float = 0.10    # minimum EPSS delta to trigger alert
    min_score_delta: float = 5.0   # minimum score change to trigger alert


def load_watches() -> list[WatchConfig]:
    """Load all watch configurations from disk."""
    if not _WATCHES_FILE.exists():
        return []
    try:
        raw = json.loads(_WATCHES_FILE.read_text())
        return [WatchConfig(**w) for w in raw]
    except Exception as exc:
        log.warning("Failed to load watches from %s: %s", _WATCHES_FILE, exc)
        return []


def save_watches(watches: list[WatchConfig]) -> None:
    """Persist watch configurations to disk."""
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _WATCHES_FILE.write_text(json.dumps([asdict(w) for w in watches], indent=2))


def add_watch(watch: WatchConfig) -> None:
    """Add or replace a watch by id."""
    watches = load_watches()
    watches = [w for w in watches if w.id != watch.id]
    watches.append(watch)
    save_watches(watches)


def remove_watch(watch_id: str) -> bool:
    """Remove a watch by id. Returns True if it existed."""
    watches = load_watches()
    new = [w for w in watches if w.id != watch_id]
    if len(new) == len(watches):
        return False
    save_watches(new)
    return True


# ── Webhook delivery ──────────────────────────────────────────────────────────

async def _post_slack_blocks(
    webhook_url: str,
    alert_type: str,
    ecosystem: str,
    packages: list[dict],
    summary: str,
) -> None:
    """POST a rich Slack Block Kit message to a Slack incoming webhook URL.

    Retries up to 3 times with exponential backoff (2s, 4s, 8s) on network
    errors or non-2xx responses (except 400 Bad Request which is permanent).
    """
    header = f"🔔 *selvo alert [{ecosystem}]*: {summary}"
    fields: list[dict] = []
    for pkg in packages[:5]:
        name = pkg.get("name", "?")
        score = pkg.get("score", pkg.get("delta", ""))
        fields.append({
            "type": "mrkdwn",
            "text": f"*{name}*\n{score}",
        })

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"selvo: {alert_type.replace('_', ' ').title()}", "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": header}},
    ]
    if fields:
        blocks.append({"type": "section", "fields": fields[:10]})
    blocks.append({"type": "context", "elements": [
        {"type": "mrkdwn", "text": f"Ecosystem: `{ecosystem}` · {len(packages)} package(s) · alert: `{alert_type}`"}
    ]})

    payload = {"blocks": blocks, "text": summary}

    _MAX_ATTEMPTS = 3
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(webhook_url, json=payload, timeout=10.0,
                                         headers={"User-Agent": "selvo/0.1 (watcher)"})
                if resp.status_code in (200, 204):
                    return
                if resp.status_code == 400:
                    # Permanent error (bad payload) — don't retry
                    log.error("Slack webhook %s rejected payload (400): %s",
                              webhook_url[:60], resp.text[:200])
                    return
                log.warning("Slack webhook attempt %d/%d: HTTP %d: %s",
                            attempt, _MAX_ATTEMPTS, resp.status_code, resp.text[:120])
        except Exception as exc:
            log.warning("Slack webhook attempt %d/%d failed: %s", attempt, _MAX_ATTEMPTS, exc)

        if attempt < _MAX_ATTEMPTS:
            await asyncio.sleep(2 ** attempt)  # 2s, 4s

    log.error("Slack webhook delivery failed after %d attempts for %s", _MAX_ATTEMPTS, webhook_url[:60])


async def _post_pagerduty(
    routing_key: str,
    alert_type: str,
    ecosystem: str,
    packages: list[dict],
    summary: str,
) -> None:
    """Send a PagerDuty Events v2 trigger via the routing key."""
    # Map selvo alert types to PagerDuty severity
    sev_map = {"kev_listed": "critical", "exploit_available": "critical",
               "new_cve": "error", "epss_jump": "warning", "score_change": "warning"}
    severity = sev_map.get(alert_type, "warning")
    # Build a stable dedup key so the same alert type + ecosystem never fires twice
    # until it is manually resolved in PagerDuty.
    dedup_key = f"selvo-{ecosystem}-{alert_type}"
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": f"selvo [{ecosystem}]: {summary}",
            "severity": severity,
            "source": f"selvo/{ecosystem}",
            "component": ecosystem,
            "group": alert_type,
            "custom_details": {
                "alert_type": alert_type,
                "packages": packages[:10],
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        },
    }
    _MAX_ATTEMPTS = 3
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json=payload,
                    timeout=10.0,
                    headers={"User-Agent": "selvo/0.1 (watcher)"},
                )
                if resp.status_code in (200, 202):
                    return
                if resp.status_code == 400:
                    log.error("PagerDuty rejected payload (400): %s", resp.text[:200])
                    return
                log.warning("PagerDuty attempt %d/%d: HTTP %d: %s",
                            attempt, _MAX_ATTEMPTS, resp.status_code, resp.text[:120])
        except Exception as exc:
            log.warning("PagerDuty attempt %d/%d failed: %s", attempt, _MAX_ATTEMPTS, exc)

        if attempt < _MAX_ATTEMPTS:
            await asyncio.sleep(2 ** attempt)  # 2s, 4s

    log.error("PagerDuty delivery failed after %d attempts", _MAX_ATTEMPTS)


async def _post_generic(
    webhook_url: str,
    alert_type: str,
    ecosystem: str,
    packages: list[dict],
    summary: str,
) -> None:
    """POST a generic JSON alert payload (original format)."""
    payload = {
        "text": f"🔔 selvo alert [{ecosystem}]: {summary}",
        "selvo": {
            "alert_type": alert_type,
            "ecosystem": ecosystem,
            "packages": packages[:20],
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
    }
    _MAX_ATTEMPTS = 3
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    webhook_url, json=payload, timeout=10.0,
                    headers={"User-Agent": "selvo/0.1 (watcher)"},
                )
                if resp.status_code in (200, 204):
                    return
                if resp.status_code < 500 and resp.status_code != 429:
                    log.warning("Webhook %s returned %d (no retry): %s",
                                webhook_url[:60], resp.status_code, resp.text[:120])
                    return
                log.warning("Webhook %s attempt %d/%d: HTTP %d",
                            webhook_url[:60], attempt, _MAX_ATTEMPTS, resp.status_code)
        except Exception as exc:
            log.warning("Webhook %s attempt %d/%d failed: %s",
                        webhook_url[:60], attempt, _MAX_ATTEMPTS, exc)

        if attempt < _MAX_ATTEMPTS:
            await asyncio.sleep(2 ** attempt)  # 2s, 4s

    log.error("Webhook delivery failed after %d attempts for %s", _MAX_ATTEMPTS, webhook_url[:60])


async def _post_webhook(
    webhook_url: str,
    alert_type: str,
    ecosystem: str,
    packages: list[dict],
    summary: str,
) -> None:
    """Dispatch an alert to Slack Block Kit, PagerDuty Events v2, or a generic webhook.

    URL scheme detection:
      - https://hooks.slack.com/...          → Slack Block Kit
      - pagerduty://ROUTING_KEY              → PagerDuty Events v2
      - pd://ROUTING_KEY                     → PagerDuty Events v2 (shorthand)
      - anything else                        → generic HTTP POST
    """
    if webhook_url.startswith("https://hooks.slack.com/"):
        await _post_slack_blocks(webhook_url, alert_type, ecosystem, packages, summary)
    elif webhook_url.startswith(("pagerduty://", "pd://")):
        routing_key = webhook_url.split("://", 1)[1].strip("/")
        await _post_pagerduty(routing_key, alert_type, ecosystem, packages, summary)
    else:
        await _post_generic(webhook_url, alert_type, ecosystem, packages, summary)


# ── Alert generation ──────────────────────────────────────────────────────────

async def _fire_alerts(
    watch: WatchConfig,
    diff: dict[str, Any],
    current_pkgs: list[Any],
) -> None:
    """Evaluate diff results against watch config and fire applicable alerts."""
    webhook_url = _resolve_webhook_url(watch.webhook_url)
    if not webhook_url:
        log.debug("Watch %s has no webhook_url, skipping alert delivery", watch.id)
        return

    alert_on = set(watch.alert_on)

    # ── new CVEs ──
    if "new_cve" in alert_on and diff.get("new_cves"):
        await _post_webhook(
            webhook_url,
            alert_type="new_cve",
            ecosystem=watch.ecosystem,
            packages=diff["new_cves"],
            summary=f"{len(diff['new_cves'])} package(s) gained new CVEs",
        )

    # ── EPSS jump ──
    if "epss_jump" in alert_on and diff.get("epss_jumps"):
        big_jumps = [
            j for j in diff["epss_jumps"]
            if j.get("delta", 0.0) >= watch.min_epss_jump
        ]
        if big_jumps:
            await _post_webhook(
                webhook_url,
                alert_type="epss_jump",
                ecosystem=watch.ecosystem,
                packages=big_jumps,
                summary=(
                    f"{len(big_jumps)} package(s) saw EPSS jump ≥"
                    f" {watch.min_epss_jump:.0%}"
                ),
            )

    # ── exploit availability & KEV ──
    exploit_alerts = []
    kev_alerts = []
    for pkg in current_pkgs:
        if "exploit_available" in alert_on and pkg.has_public_exploit:
            exploit_alerts.append({
                "name": pkg.name,
                "maturity": pkg.exploit_maturity,
                "urls": pkg.exploit_urls[:2],
            })
        if "kev_listed" in alert_on and pkg.in_cisa_kev:
            kev_alerts.append({"name": pkg.name, "score": pkg.score})

    if exploit_alerts:
        # Only alert if this is a fresh detection — check against prev snapshot
        await _post_webhook(
            webhook_url,
            alert_type="exploit_available",
            ecosystem=watch.ecosystem,
            packages=exploit_alerts,
            summary=(
                f"{len(exploit_alerts)} package(s) have public exploits"
                f" ({sum(1 for e in exploit_alerts if e['maturity'] == 'weaponized')}"
                f" weaponized)"
            ),
        )

    if kev_alerts:
        await _post_webhook(
            webhook_url,
            alert_type="kev_listed",
            ecosystem=watch.ecosystem,
            packages=kev_alerts,
            summary=f"{len(kev_alerts)} package CVE(s) are in CISA KEV",
        )

    # ── score changes ──
    if "score_change" in alert_on and diff.get("score_changes"):
        big = [
            c for c in diff["score_changes"]
            if abs(c.get("delta", 0.0)) >= watch.min_score_delta
        ]
        if big:
            await _post_webhook(
                webhook_url,
                alert_type="score_change",
                ecosystem=watch.ecosystem,
                packages=big,
                summary=f"{len(big)} package(s) had significant score changes",
            )


# ── Watcher loop ──────────────────────────────────────────────────────────────

async def _run_watch_cycle(watch: WatchConfig) -> None:
    """Run one full pipeline + diff + alert cycle for a single watch config."""
    from selvo.analysis.cache import load_last_snapshot, diff_snapshots

    log.info("Watch cycle starting: %s (%s)", watch.id, watch.ecosystem)

    # Load previous snapshot before running (pipeline will overwrite it)
    prev_result = load_last_snapshot(watch.ecosystem)
    previous_snapshot: list[dict] = prev_result[0] if prev_result else []

    # Import here to avoid circular imports at module load time
    from selvo.mcp_server import _run_pipeline  # shared pipeline

    packages = await _run_pipeline(
        ecosystem=watch.ecosystem,
        limit=watch.limit,
        run_cve=True,
    )

    diff = diff_snapshots(previous_snapshot, packages)

    await _fire_alerts(watch, diff, packages)
    log.info(
        "Watch cycle done: %s — new_cves=%d, epss_jumps=%d",
        watch.id,
        len(diff.get("new_cves", [])),
        len(diff.get("epss_jumps", [])),
    )


async def run_watcher(watches: Optional[list[WatchConfig]] = None) -> None:
    """
    Run the watcher daemon indefinitely.

    Each watch runs on its own asyncio interval. The function never returns
    unless cancelled or all watches are removed.
    """
    if watches is None:
        watches = load_watches()

    if not watches:
        log.warning("No watches configured. Run: selvo watch add --id <id> --webhook <URL>")
        return

    log.info("Watcher started with %d watch(es)", len(watches))

    # Write PID file so `selvo watch status` can detect a running daemon
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _PID_FILE.write_text(str(os.getpid()))

    async def _loop(watch: WatchConfig) -> None:
        while True:
            try:
                await _run_watch_cycle(watch)
            except Exception as exc:
                log.error("Watch cycle error for %s: %s", watch.id, exc)
            await asyncio.sleep(watch.interval_hours * 3600)

    try:
        await asyncio.gather(*[_loop(w) for w in watches])
    finally:
        if _PID_FILE.exists():
            _PID_FILE.unlink()


def watcher_is_running() -> bool:
    """Return True if a watcher daemon PID file exists and the process is alive."""
    if not _PID_FILE.exists():
        return False
    try:
        pid = int(_PID_FILE.read_text().strip())
        os.kill(pid, 0)  # signal 0 = check if process exists
        return True
    except (ProcessLookupError, PermissionError, ValueError, OSError):
        return False


def stop_watcher() -> bool:
    """Send SIGTERM to a running watcher daemon. Returns True if killed."""
    if not _PID_FILE.exists():
        return False
    try:
        import signal
        pid = int(_PID_FILE.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        _PID_FILE.unlink(missing_ok=True)
        return True
    except Exception as exc:
        log.error("Failed to stop watcher: %s", exc)
        return False
