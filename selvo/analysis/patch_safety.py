"""Patch safety scoring — estimate regression risk before deploying a package update.

Score is 0.0 (very risky) → 1.0 (very safe to auto-deploy).

Factors considered:
  - Version bump magnitude (major > minor > patch)
  - Package criticality category (kernel/glibc > crypto > userland)
  - Distro coverage (how many stable distros already ship the target version)
  - Whether the package is at a known-stable version per Repology
"""
from __future__ import annotations

import re

from packaging.version import Version, InvalidVersion

from selvo.discovery.base import PackageRecord

# ---------------------------------------------------------------------------
# Known high-risk packages — their patches always require manual validation
# ---------------------------------------------------------------------------
_CRITICAL_PACKAGES = frozenset({
    # Core ABI / boot
    "linux", "linux-image", "glibc", "libc6", "ld-linux",
    "systemd", "dbus", "udev",
    # Compilers / toolchains
    "gcc", "gcc-14", "gcc-13", "binutils", "glibc-devel",
    # Crypto libraries
    "openssl", "gnutls", "libgcrypt", "nss", "libssl3",
    # Package management
    "apt", "dpkg", "rpm", "pacman",
    # Init / boot
    "grub", "grub2", "shim", "efi-boot",
})

_HIGH_RISK_RE = re.compile(
    r"^(linux-image|linux-headers|linux-modules|libc6|libssl|libgnutls|libgcrypt)",
    re.IGNORECASE,
)

# Distro Repology repo keys that serve as "tested by a stable release" signals
_STABLE_DISTROS = [
    "debian_12", "debian_13", "debian_14",
    "ubuntu_22_04", "ubuntu_24_04", "ubuntu_25_04",
    "fedora_41", "fedora_42",
    "alpine_3_20", "alpine_3_21",
    "archlinux",
    "nixos_24_11",
]
_N_STABLE = len(_STABLE_DISTROS)


def _bump_risk(pkg: PackageRecord) -> float:
    """Return 0–1 risk from version bump magnitude. Higher = riskier."""
    if not pkg.upstream_version or pkg.version in ("unknown", "", None):
        return 0.5  # unknown bump → moderate risk assumption
    try:
        cur = Version(pkg.version.split(":")[-1])
        up = Version(pkg.upstream_version.split(":")[-1])
    except InvalidVersion:
        return 0.5
    if up <= cur:
        return 0.0  # already current

    if up.major > cur.major:
        return 1.0  # major bump — potentially breaking ABI
    if up.minor > cur.minor:
        minor_gap = up.minor - cur.minor
        return min(0.4 + minor_gap * 0.1, 0.8)  # 0.4–0.8
    patch_gap = up.micro - cur.micro
    return min(0.05 + patch_gap * 0.02, 0.35)  # 0.05–0.35


def _package_criticality(pkg: PackageRecord) -> float:
    """Return 0–1 baseline risk from how critical the package is. Higher = riskier."""
    name = pkg.name.lower()
    if name in _CRITICAL_PACKAGES or _HIGH_RISK_RE.match(name):
        return 1.0
    # Crypto / security middleware
    if any(k in name for k in ("ssl", "tls", "crypto", "nss", "gnutls", "gcrypt")):
        return 0.8
    # Core libraries
    if name.startswith("lib") or name.startswith("python3-") or "perl" in name:
        return 0.4
    # Everything else
    return 0.15


def _distro_coverage_safety(pkg: PackageRecord) -> float:
    """
    Return 0–1 safety boost from how many stable distros already ship the
    upstream_version. More stable distros → more QA → safer to deploy.
    """
    if not pkg.distro_versions or not pkg.upstream_version:
        return 0.0
    try:
        target = Version(pkg.upstream_version.split(":")[-1])
    except InvalidVersion:
        return 0.0
    matches = 0
    for _distro_key, dv in pkg.distro_versions.items():
        try:
            if Version(dv.split(":")[-1]) >= target:
                matches += 1
        except InvalidVersion:
            pass
    return min(matches / max(_N_STABLE, 1), 1.0)


def _compute_safety_score(pkg: PackageRecord) -> tuple[float, str]:
    """Return (score 0–1, risk_label)."""
    bump = _bump_risk(pkg)
    criticality = _package_criticality(pkg)
    coverage_boost = _distro_coverage_safety(pkg)

    # Base risk (0–1, higher = riskier)
    raw_risk = (bump * 0.5) + (criticality * 0.35) + (1.0 - coverage_boost) * 0.15
    raw_risk = min(max(raw_risk, 0.0), 1.0)

    safety = round(1.0 - raw_risk, 3)

    if safety >= 0.75:
        label = "low"
    elif safety >= 0.45:
        label = "medium"
    else:
        label = "high"

    return safety, label


def enrich_patch_safety(packages: list[PackageRecord]) -> list[PackageRecord]:
    """Annotate each PackageRecord with patch_safety_score and patch_regression_risk."""
    for pkg in packages:
        score, label = _compute_safety_score(pkg)
        pkg.patch_safety_score = score
        pkg.patch_regression_risk = label
    return packages
