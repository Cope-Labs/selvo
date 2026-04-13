"""Silent-zero detection — alert when a scan suspiciously produces no CVEs.

Every silent-failure bug we shipped in the OSV pipeline before 2026-04-12
had the same shape: an ecosystem that should have returned CVEs returned
none, the scan succeeded, and nobody noticed because the dashboard just
showed "all clear." Defending against that by tests alone is a losing
battle (you can only test for what you remembered to test). The honest
defense is a runtime monitor that's suspicious of calm.

Heuristic implemented here:

  * Linux base systems — debian, ubuntu, fedora, rhel, rocky, alma,
    alpine, suse, opensuse — virtually always carry **some** open CVEs
    against modern installed versions. There is no real-world baseline
    Linux package set with 100+ packages and 0 open CVEs.
  * If a scan in one of those ecosystems contains >= MIN_PKGS packages
    and zero CVEs total across them, fire a warning to Sentry, log,
    and record an event row. This is a "data pipeline likely broken"
    signal, not a "user's system is clean" signal.

Doesn't fire for:
  * Language ecosystems (pypi, npm, etc.) — small dependency sets with
    zero CVEs are routine for well-maintained projects.
  * Tiny scans (< MIN_PKGS) — could be a single-package check.
  * Scans where at least one package has any CVE — pipeline is working.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

log = logging.getLogger(__name__)

# Ecosystems where a non-trivial scan with zero CVEs is almost certainly a bug.
_BASE_OS_ECOSYSTEMS = {
    "debian", "ubuntu",
    "fedora", "rhel", "rocky", "almalinux", "centos",
    "alpine", "wolfi", "chainguard",
    "suse", "opensuse",
    "arch", "nixos",
}

# Threshold — fewer than this and we don't have signal. A real Linux base
# system has hundreds of packages; choosing 80 keeps tiny one-off scans
# from triggering false alarms while still catching every full-system scan.
MIN_PKGS = 80


def check(packages: Iterable[Any], ecosystem: str, context: dict | None = None) -> bool:
    """Inspect a finished scan; warn if it looks like a silent-zero failure.

    Args:
        packages:   list[PackageRecord] returned by the enrichment pipeline.
        ecosystem:  the ecosystem string the user asked us to scan.
        context:    optional dict logged with the alert (org_id, scan source,
                    job id, etc.) for triage.

    Returns:
        True if a warning was raised, False otherwise.
    """
    primary_eco = (ecosystem or "").split(",")[0].strip().lower()
    if primary_eco not in _BASE_OS_ECOSYSTEMS:
        return False

    pkg_list = list(packages)
    if len(pkg_list) < MIN_PKGS:
        return False

    total_cves = sum(len(getattr(p, "cve_ids", []) or []) for p in pkg_list)
    if total_cves > 0:
        return False  # pipeline producing data

    msg = (
        f"silent-zero suspected: ecosystem={primary_eco} "
        f"packages={len(pkg_list)} cves=0 — likely OSV data-shape change"
    )
    log.warning("%s context=%s", msg, context or {})

    # Sentry alert — non-fatal, tagged so we can build an alert rule on it.
    try:
        import sentry_sdk
        with sentry_sdk.push_scope() as scope:
            scope.set_tag("alert", "silent_zero")
            scope.set_tag("ecosystem", primary_eco)
            scope.set_extra("packages", len(pkg_list))
            for k, v in (context or {}).items():
                scope.set_extra(k, v)
            sentry_sdk.capture_message(msg, level="warning")
    except Exception as exc:
        log.debug("Sentry capture for silent-zero failed: %s", exc)

    # Persistent event row for in-app review (selvo's own analytics).
    try:
        from selvo.api.auth import track_event
        detail = f"{primary_eco}:{len(pkg_list)}pkgs"
        if context and "org_id" in context:
            detail += f":{context['org_id']}"
        track_event("silent_zero", detail[:200])
    except Exception as exc:
        log.debug("track_event for silent-zero failed: %s", exc)

    return True
