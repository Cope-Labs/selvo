"""Dependency confusion and namespace hijacking detector.

Checks for:

1. **Namespace confusion** — a system package's "bare" name (stripped of lib/python3-/
   -dev/etc. packaging decoration) exactly matches a package on PyPI or npm, and the
   public registry has a significantly newer major version. This is the core
   dependency confusion attack vector: if a developer accidentally resolves the bare
   name from a public registry instead of the internal/system one, they fetch the
   attacker-controlled version.

2. **Version confusion** — packages installed at an implausibly high version number
   (major ≥ 100). Dependency confusion attack payloads commonly use versions like
   9999.0.0 to ensure they win version resolution against the legitimate package.

3. **Typosquatting proximity** — package name is within Levenshtein distance 1 of a
   known high-value target package (common single-character substitutions: 0→o, 1→l,
   rn→m, etc.). Checked against a curated seed list of ~40 critical packages.

Results are attached to packages as `confusion_risks: list[ConfusionRisk]` and can
be consumed by the CLI command `selvo deps` or the REST API `/api/v1/dep-confusion`.

Usage:
    from selvo.analysis.dep_confusion import enrich_dep_confusion, confusion_report
    packages = await enrich_dep_confusion(packages)
    report = confusion_report(packages)          # → list[dict], sorted by severity
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)

# ── Name normalisation ────────────────────────────────────────────────────────

_STRIP_PREFIXES = ("python3-", "python-", "lib", "nodejs-", "ruby-", "perl-", "php-")
_STRIP_SUFFIXES = (
    "-dev", "-devel", "-doc", "-docs", "-common", "-utils", "-tools",
    "-bin", "-cli", "-core", "-base", "-data", "-runtime", "-static",
)

# Version number high enough to be suspicious
_HIGH_VERSION_THRESHOLD = 100

# Curated seed list of high-value package names to check typo-proximity against
_HIGH_VALUE_TARGETS: frozenset[str] = frozenset({
    # Python ecosystem
    "numpy", "pandas", "requests", "flask", "django", "scipy", "matplotlib",
    "cryptography", "paramiko", "boto3", "setuptools", "pip", "wheel",
    # Node ecosystem
    "lodash", "express", "react", "webpack", "babel", "axios",
    # System / security
    "openssl", "libssl", "curl", "libcurl", "zlib", "glibc",
    "openssh", "libssh", "gnupg", "libgcrypt",
    # Common targets in dep-confusion attacks (disclosed)
    "shopify-scripts", "npmrc", "twilio-utils", "torch", "tensorflow",
})


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class ConfusionRisk:
    risk_type: str       # "namespace_confusion" | "version_confusion" | "typosquatting"
    registry: str        # "pypi" | "npm" | "local"
    bare_name: str
    public_version: str  # latest version on public registry (empty for local checks)
    installed_version: str
    detail: str
    severity: str        # "high" | "medium" | "low"


# ── Name stripping ────────────────────────────────────────────────────────────

def _strip_distro_decoration(name: str) -> str:
    """Remove Linux packaging prefixes/suffixes to recover the upstream bare name."""
    n = name.lower().replace("_", "-")
    for prefix in _STRIP_PREFIXES:
        if n.startswith(prefix):
            n = n[len(prefix):]
            break
    for suffix in _STRIP_SUFFIXES:
        if n.endswith(suffix):
            n = n[: -len(suffix)]
            break
    return n


def _major_version(v: str) -> Optional[int]:
    m = re.match(r"(\d+)", v or "")
    return int(m.group(1)) if m else None


def _levenshtein(a: str, b: str) -> int:
    """Classic dynamic-programming Levenshtein distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[len(b)]


# ── Registry lookups ──────────────────────────────────────────────────────────

async def _pypi_latest(name: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        r = await client.get(
            f"https://pypi.org/pypi/{name}/json",
            timeout=8.0,
            follow_redirects=True,
        )
        if r.status_code == 200:
            return r.json().get("info", {}).get("version")
    except Exception:
        pass
    return None


async def _npm_latest(name: str, client: httpx.AsyncClient) -> Optional[str]:
    try:
        r = await client.get(
            f"https://registry.npmjs.org/{name}/latest",
            timeout=8.0,
            follow_redirects=True,
        )
        if r.status_code == 200:
            return r.json().get("version")
    except Exception:
        pass
    return None


# ── Per-package analysis ───────────────────────────────────────────────────────

async def _analyze(
    pkg: Any,
    client: httpx.AsyncClient,
    check_registries: bool = True,
) -> list[ConfusionRisk]:
    risks: list[ConfusionRisk] = []
    installed_v = pkg.version or "unknown"
    bare = _strip_distro_decoration(pkg.name)

    # ── Version confusion (no network) ────────────────────────────────────────
    major = _major_version(installed_v)
    if major is not None and major >= _HIGH_VERSION_THRESHOLD:
        risks.append(ConfusionRisk(
            risk_type="version_confusion",
            registry="local",
            bare_name=pkg.name,
            public_version="",
            installed_version=installed_v,
            detail=(
                f"Installed version {installed_v} has an unusually high major version "
                f"(≥ {_HIGH_VERSION_THRESHOLD}). This pattern is a hallmark of "
                "dependency confusion attack payloads."
            ),
            severity="high",
        ))

    # ── Typosquatting proximity (no network) ──────────────────────────────────
    for target in _HIGH_VALUE_TARGETS:
        if bare != target and _levenshtein(bare, target) == 1:
            risks.append(ConfusionRisk(
                risk_type="typosquatting",
                registry="local",
                bare_name=bare,
                public_version="",
                installed_version=installed_v,
                detail=(
                    f"Package bare name '{bare}' is Levenshtein distance 1 from "
                    f"high-value target '{target}'. Possible typosquat."
                ),
                severity="medium",
            ))
            break  # one typo flag per package is enough

    # ── Namespace confusion (network checks) ─────────────────────────────────
    # Skip if bare == original (no decoration was stripped) to reduce false positives
    if not check_registries or bare == pkg.name.lower():
        return risks

    # PyPI check
    pypi_v = await _pypi_latest(bare, client)
    if pypi_v:
        pub_major = _major_version(pypi_v)
        ins_major = _major_version(installed_v)
        gap = (pub_major or 0) - (ins_major or 0)
        if gap >= 2:
            risks.append(ConfusionRisk(
                risk_type="namespace_confusion",
                registry="pypi",
                bare_name=bare,
                public_version=pypi_v,
                installed_version=installed_v,
                detail=(
                    f"System package '{pkg.name}' strips to '{bare}' which exists on PyPI "
                    f"(installed: {installed_v}, PyPI latest: {pypi_v}, gap: {gap} major). "
                    "Build tooling resolving this bare name from PyPI instead of the system "
                    "registry could be hijacked."
                ),
                severity="high" if gap >= 5 else "medium",
            ))

    # npm check (only if not already flagged via PyPI to save requests)
    if not any(r.risk_type == "namespace_confusion" for r in risks):
        npm_v = await _npm_latest(bare, client)
        if npm_v:
            pub_major = _major_version(npm_v)
            ins_major = _major_version(installed_v)
            gap = (pub_major or 0) - (ins_major or 0)
            if gap >= 2:
                risks.append(ConfusionRisk(
                    risk_type="namespace_confusion",
                    registry="npm",
                    bare_name=bare,
                    public_version=npm_v,
                    installed_version=installed_v,
                    detail=(
                        f"System package '{pkg.name}' strips to '{bare}' which exists on npm "
                        f"(installed: {installed_v}, npm latest: {npm_v}). "
                        "Potential namespace confusion via npm resolution."
                    ),
                    severity="medium",
                ))

    return risks


# ── Public API ────────────────────────────────────────────────────────────────

async def enrich_dep_confusion(
    packages: list[Any],
    check_registries: bool = True,
    concurrency: int = 20,
) -> list[Any]:
    """Enrich packages with a ``confusion_risks`` attribute (list[ConfusionRisk]).

    Packages whose names contain Linux packaging decoration (python3-X, libX-dev, etc.)
    are cross-checked against PyPI and npm for namespace collisions.
    All packages are checked for version confusion and typosquatting regardless.
    """
    sem = asyncio.Semaphore(concurrency)

    async def _bounded(pkg: Any, client: httpx.AsyncClient) -> tuple[Any, list[ConfusionRisk]]:
        async with sem:
            risks = await _analyze(pkg, client, check_registries=check_registries)
            return pkg, risks

    async with httpx.AsyncClient(
        headers={"User-Agent": "selvo/0.1 (dep-confusion-scanner)"}
    ) as client:
        results = await asyncio.gather(
            *[_bounded(p, client) for p in packages],
            return_exceptions=True,
        )

    for item in results:
        if isinstance(item, Exception):
            log.debug("dep_confusion error: %s", item)
            continue
        pkg, risks = item  # type: ignore[misc]
        pkg.confusion_risks = risks

    return packages


def confusion_report(packages: list[Any]) -> list[dict]:
    """Return a flat list of confusion risk dicts, sorted by severity."""
    _sev_order = {"high": 0, "medium": 1, "low": 2}
    out: list[dict] = []
    for pkg in packages:
        for risk in getattr(pkg, "confusion_risks", []):
            out.append({
                "package": pkg.name,
                "risk_type": risk.risk_type,
                "registry": risk.registry,
                "bare_name": risk.bare_name,
                "installed_version": risk.installed_version,
                "public_version": risk.public_version,
                "severity": risk.severity,
                "detail": risk.detail,
            })
    return sorted(out, key=lambda x: _sev_order.get(x["severity"], 9))
