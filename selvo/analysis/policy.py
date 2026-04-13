"""Policy-as-code enforcement engine for selvo.

Loads a selvo.policy.yml (or custom path) and evaluates a list of PackageRecords
against the policy, producing a PolicyResult with block / warn violations.

Policy file schema:

    version: 1

    sla:
      critical: 7     # days to remediate critical-CVSS CVEs
      high: 30
      medium: 90
      low: 365

    allow:
      cves:
        - id: CVE-2023-12345
          reason: "Not reachable via our call graph"
          expires: 2024-12-31   # optional — allow-list entry auto-expires

    block:
      on_kev: true              # fail if any package is CISA KEV-listed
      on_weaponized: true       # fail if any package has a weaponized exploit
      min_cvss: 9.0             # fail if any CVE CVSS >= threshold
      min_score: 0.0            # fail if any composite score >= threshold (0=off)
      min_epss: 0.0             # fail if any CVE EPSS >= threshold (0=off)
      cwe_classes: []           # fail if any CVE matches CWE class (future)

    warn:
      on_poc: true              # warn on PoC exploits (non-blocking)
      min_cvss: 7.0
      min_epss: 0.0

    notifications:
      slack: "https://hooks.slack.com/services/..."
      pagerduty_routing_key: "abc123"

CLI: selvo policy check [--policy selvo.policy.yml]
"""
from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

_DEFAULT_POLICY_PATHS = [
    Path("selvo.policy.yml"),
    Path("selvo.policy.yaml"),
    Path(".selvo.policy.yml"),
    Path.home() / ".config" / "selvo" / "policy.yml",
]


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class PolicyViolation:
    rule: str
    package: str
    cve_id: Optional[str]
    detail: str
    level: str  # "block" | "warn"

    def __str__(self) -> str:
        cve = f" [{self.cve_id}]" if self.cve_id else ""
        icon = "🔴" if self.level == "block" else "🟡"
        return f"{icon} {self.level.upper()} [{self.rule}] {self.package}{cve}: {self.detail}"


@dataclass
class PolicyResult:
    passed: bool
    blocked: list[PolicyViolation] = field(default_factory=list)
    warnings: list[PolicyViolation] = field(default_factory=list)
    allowed_cves: set[str] = field(default_factory=set)

    @property
    def violations(self) -> list[PolicyViolation]:
        return self.blocked + self.warnings

    def exit_code(self) -> int:
        """0=pass, 1=block violations, 2=warnings only."""
        if self.blocked:
            return 1
        if self.warnings:
            return 2
        return 0


@dataclass
class Policy:
    raw: dict[str, Any]

    # SLA thresholds in days
    sla_critical: int = 7
    sla_high: int = 30
    sla_medium: int = 90
    sla_low: int = 365

    # Allow-list: cve_id → {reason, expires (date | None)}
    allowed_cves: dict[str, dict] = field(default_factory=dict)

    # Block gates
    block_on_kev: bool = True
    block_on_weaponized: bool = True
    block_min_cvss: float = 9.0
    block_min_score: float = 0.0   # 0 = disabled
    block_min_epss: float = 0.0    # 0 = disabled
    block_cwe_classes: list[str] = field(default_factory=list)

    # Warn gates
    warn_on_poc: bool = False
    warn_min_cvss: float = 7.0
    warn_min_epss: float = 0.0

    # Notification endpoints
    slack_url: str = ""
    pagerduty_routing_key: str = ""


# ── Loading ───────────────────────────────────────────────────────────────────

def load_policy(path: Optional[str] = None) -> Optional[Policy]:
    """Load and parse a policy YAML file.

    Searches default locations if *path* is None. Returns None if no file found
    or if PyYAML is not installed.
    """
    try:
        import yaml  # type: ignore[import]
    except ImportError:
        log.debug("PyYAML not installed — policy loading requires: pip install pyyaml")
        return None

    search: list[Path] = [Path(path)] if path else _DEFAULT_POLICY_PATHS
    for p in search:
        if p.exists():
            try:
                raw = yaml.safe_load(p.read_text()) or {}
                pol = _parse_policy(raw)
                log.debug("Loaded policy from %s", p)
                return pol
            except Exception as exc:
                log.warning("Failed to parse policy file %s: %s", p, exc)
                return None

    return None


_KNOWN_TOP_KEYS = {"version", "sla", "block", "warn", "allow", "notifications"}
_KNOWN_SLA_KEYS = {"critical", "high", "medium", "low"}
_KNOWN_BLOCK_KEYS = {"on_kev", "on_weaponized", "min_cvss", "min_score", "min_epss", "cwe_classes"}
_KNOWN_WARN_KEYS = {"on_poc", "min_cvss", "min_epss"}
_KNOWN_NOTIF_KEYS = {"slack", "pagerduty_routing_key"}


def _validate_schema(raw: dict) -> list[str]:
    """Return a list of human-readable schema warnings for unexpected or malformed keys."""
    issues: list[str] = []

    unknown_top = set(raw.keys()) - _KNOWN_TOP_KEYS
    for k in sorted(unknown_top):
        issues.append(f"Unknown top-level key '{k}' — will be ignored")

    version = raw.get("version")
    if version is not None and version not in (1, "1"):
        issues.append(f"Unknown policy version '{version}' — expected 1")

    for section, known in [
        ("sla", _KNOWN_SLA_KEYS), ("block", _KNOWN_BLOCK_KEYS),
        ("warn", _KNOWN_WARN_KEYS), ("notifications", _KNOWN_NOTIF_KEYS),
    ]:
        sub = raw.get(section)
        if isinstance(sub, dict):
            unknown_sub = set(sub.keys()) - known
            for k in sorted(unknown_sub):
                issues.append(f"Unknown key '{section}.{k}' — will be ignored")
        elif sub is not None:
            issues.append(f"Section '{section}' must be a mapping, got {type(sub).__name__}")

    # Numeric field type checks
    for section_key, field_key in [
        ("sla", "critical"), ("sla", "high"), ("sla", "medium"), ("sla", "low"),
        ("block", "min_cvss"), ("block", "min_score"), ("block", "min_epss"),
        ("warn", "min_cvss"), ("warn", "min_epss"),
    ]:
        sub = (raw.get(section_key) or {})
        if isinstance(sub, dict):
            val = sub.get(field_key)
            if val is not None:
                try:
                    float(val)
                except (TypeError, ValueError):
                    issues.append(
                        f"Field '{section_key}.{field_key}' must be numeric, got {val!r}"
                    )

    return issues


def _parse_policy(raw: dict) -> Policy:
    for issue in _validate_schema(raw):
        log.warning("policy schema: %s", issue)

    sla = raw.get("sla") or {}
    block = raw.get("block") or {}
    warn = raw.get("warn") or {}
    notif = raw.get("notifications") or {}

    # Parse CVE allow-list
    allowed_cves: dict[str, dict] = {}
    for entry in (raw.get("allow") or {}).get("cves") or []:
        cve_id = str(entry.get("id", "")).upper().strip()
        if not cve_id:
            continue
        expires_raw = entry.get("expires")
        expires: Optional[datetime.date] = None
        if expires_raw:
            try:
                expires = datetime.date.fromisoformat(str(expires_raw))
            except ValueError:
                log.warning("Invalid expires date for CVE allow-list entry %s: %s", cve_id, expires_raw)
        allowed_cves[cve_id] = {"reason": entry.get("reason", ""), "expires": expires}

    return Policy(
        raw=raw,
        sla_critical=int(sla.get("critical") or 7),
        sla_high=int(sla.get("high") or 30),
        sla_medium=int(sla.get("medium") or 90),
        sla_low=int(sla.get("low") or 365),
        allowed_cves=allowed_cves,
        block_on_kev=bool(block.get("on_kev", True)),
        block_on_weaponized=bool(block.get("on_weaponized", True)),
        block_min_cvss=float(block.get("min_cvss") or 9.0),
        block_min_score=float(block.get("min_score") or 0.0),
        block_min_epss=float(block.get("min_epss") or 0.0),
        block_cwe_classes=list(block.get("cwe_classes") or []),
        warn_on_poc=bool(warn.get("on_poc", False)),
        warn_min_cvss=float(warn.get("min_cvss") or 7.0),
        warn_min_epss=float(warn.get("min_epss") or 0.0),
        slack_url=str(notif.get("slack") or ""),
        pagerduty_routing_key=str(notif.get("pagerduty_routing_key") or ""),
    )


# ── Enforcement ───────────────────────────────────────────────────────────────

def _cve_allowed(cve_id: str, policy: Policy) -> bool:
    """Return True if the CVE is allow-listed and the entry hasn't expired."""
    entry = policy.allowed_cves.get(cve_id.upper())
    if entry is None:
        return False
    expires = entry.get("expires")
    if expires and datetime.date.today() > expires:
        log.debug("Allow-list entry for %s expired on %s", cve_id, expires)
        return False
    return True


def enforce(packages: list, policy: Policy) -> PolicyResult:
    """Evaluate *packages* (list[PackageRecord]) against *policy*.

    Returns a :class:`PolicyResult` with all violations categorised as
    **block** (CI-failing) or **warn** (informational).
    """
    blocked: list[PolicyViolation] = []
    warnings: list[PolicyViolation] = []
    effective_allowed: set[str] = set()

    for pkg in packages:
        name = getattr(pkg, "name", str(pkg))
        cvss = getattr(pkg, "max_cvss", 0.0) or 0.0
        epss = getattr(pkg, "max_epss", 0.0) or 0.0
        score = getattr(pkg, "score", 0.0) or 0.0
        maturity = getattr(pkg, "exploit_maturity", "none") or "none"
        in_kev = getattr(pkg, "in_cisa_kev", False)
        sla_band = getattr(pkg, "sla_band", "") or ""
        sla_overdue = getattr(pkg, "sla_days_overdue", 0) or 0

        # ── CVE-level checks ──────────────────────────────────────────────────
        cve_ids: list[str] = list(getattr(pkg, "cve_ids", None) or [])
        for cve_id in cve_ids:
            if _cve_allowed(cve_id, policy):
                effective_allowed.add(cve_id)
                continue

            if policy.block_min_cvss > 0 and cvss >= policy.block_min_cvss:
                blocked.append(PolicyViolation(
                    rule="block.min_cvss",
                    package=name,
                    cve_id=cve_id,
                    detail=f"CVSS {cvss:.1f} ≥ block threshold {policy.block_min_cvss}",
                    level="block",
                ))
            elif policy.warn_min_cvss > 0 and cvss >= policy.warn_min_cvss:
                warnings.append(PolicyViolation(
                    rule="warn.min_cvss",
                    package=name,
                    cve_id=cve_id,
                    detail=f"CVSS {cvss:.1f} ≥ warn threshold {policy.warn_min_cvss}",
                    level="warn",
                ))

            if policy.block_min_epss > 0 and epss >= policy.block_min_epss:
                blocked.append(PolicyViolation(
                    rule="block.min_epss",
                    package=name,
                    cve_id=cve_id,
                    detail=f"EPSS {epss:.1%} ≥ block threshold {policy.block_min_epss:.1%}",
                    level="block",
                ))

        # ── Package-level checks ──────────────────────────────────────────────
        if policy.block_on_kev and in_kev:
            live_cves = [c for c in cve_ids if not _cve_allowed(c, policy)]
            if live_cves:
                blocked.append(PolicyViolation(
                    rule="block.on_kev",
                    package=name,
                    cve_id=live_cves[0],
                    detail="Package has CVEs in CISA Known Exploited Vulnerabilities catalog",
                    level="block",
                ))

        if policy.block_on_weaponized and maturity == "weaponized":
            blocked.append(PolicyViolation(
                rule="block.on_weaponized",
                package=name,
                cve_id=None,
                detail="Weaponized exploit publicly available for this package",
                level="block",
            ))
        elif policy.warn_on_poc and maturity == "poc":
            warnings.append(PolicyViolation(
                rule="warn.on_poc",
                package=name,
                cve_id=None,
                detail="Public PoC exploit exists for this package",
                level="warn",
            ))

        if policy.block_min_score > 0 and score >= policy.block_min_score:
            blocked.append(PolicyViolation(
                rule="block.min_score",
                package=name,
                cve_id=None,
                detail=f"Composite risk score {score:.1f} ≥ block threshold {policy.block_min_score}",
                level="block",
            ))

        # ── SLA breach ────────────────────────────────────────────────────────
        if sla_band in ("critical", "breach") and sla_overdue > 0:
            blocked.append(PolicyViolation(
                rule="sla.breach",
                package=name,
                cve_id=None,
                detail=f"SLA {sla_band}: {sla_overdue}d overdue",
                level="block",
            ))

    return PolicyResult(
        passed=len(blocked) == 0,
        blocked=blocked,
        warnings=warnings,
        allowed_cves=effective_allowed,
    )


def format_result(result: PolicyResult, policy_path: str = "") -> str:
    """Return a human-readable policy evaluation summary."""
    src = f" [{policy_path}]" if policy_path else ""
    lines: list[str] = []

    if result.passed:
        lines.append(f"✅ Policy{src}: PASSED")
    else:
        lines.append(
            f"❌ Policy{src}: FAILED "
            f"({len(result.blocked)} block(s), {len(result.warnings)} warning(s))"
        )

    if result.allowed_cves:
        lines.append(f"  ⚪ Allowed CVEs: {', '.join(sorted(result.allowed_cves))}")

    for v in result.blocked[:25]:
        lines.append(f"  {v}")
    if len(result.blocked) > 25:
        lines.append(f"  … and {len(result.blocked) - 25} more block violations")

    for v in result.warnings[:10]:
        lines.append(f"  {v}")

    return "\n".join(lines)
