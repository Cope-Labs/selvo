"""Scoring engine — rank packages by update value/impact."""
from __future__ import annotations

from packaging.version import Version, InvalidVersion

from selvo.discovery.base import PackageRecord

# ---------------------------------------------------------------------------
# Weights — sum to 100
# ---------------------------------------------------------------------------
# EPSS (exploitation probability) is the most actionable real-world signal.
# CVSS severity adds severity context when NVD data is available.
# Transitive reverse-dep count and betweenness capture the real blast radius:
#   - transitive_rdep_count: how many packages in the dep graph ultimately
#     rely on this one — fixing its CVE helps all of them.
#   - betweenness: how often this package sits on the shortest path between
#     other packages — a high value means it's a dependency chokepoint.
_W_EPSS = 20.0              # Exploitation probability (FIRST.org EPSS, 0–1)
_W_EXPLOIT_MATURITY = 8.0   # Known exploit availability: weaponized>poc>none; KEV bonus
_W_CVSS = 10.0              # Severity of worst CVE (NVD CVSS v3 base score)
_W_VERSION_GAP = 14.0       # How many major/minor versions behind upstream
_W_TRANSITIVE_RDEPS = 22.0  # True blast radius: transitive dependent count
_W_BETWEENNESS = 15.0       # Chokepoint score (betweenness centrality)
_W_REVERSE_DEPS = 7.0       # Direct blast radius fallback (Repology repo count)
_W_DOWNLOADS = 2.0          # Usage popularity / install count
_W_EXPOSURE_DAYS = 2.0      # Urgency from days-open (capped; older = more urgent)

# Runtime boost: multiply the total score when the package's .so files are
# confirmed loaded in a live process right now.
# 1.5× is conservative — "confirmed exploitable path" vs "installed but maybe not loaded".
_RUNTIME_LOADED_BOOST = 1.5


def _strip_epoch(v: str) -> str:
    """Strip Debian/RPM epoch prefix (e.g. '1:2.29.2-1' → '2.29.2-1')."""
    if ":" in v:
        v = v.split(":", 1)[1]
    # Strip Debian revision suffix (e.g. '-1+deb9u1', '.dfsg')
    for suffix in ("+deb", "+dfsg", ".dfsg", "~bpo", "+b"):
        idx = v.find(suffix)
        if idx > 0:
            v = v[:idx]
    # Strip trailing Debian revision after last hyphen (e.g. '2.29.2-1' → '2.29.2')
    if "-" in v:
        v = v.rsplit("-", 1)[0]
    return v


def _version_gap(pkg: PackageRecord) -> float:
    """Return a 0–1 score representing how far behind the installed version is."""
    if not pkg.upstream_version or pkg.version == "unknown":
        return 0.0
    try:
        current = Version(_strip_epoch(pkg.version))
        upstream = Version(_strip_epoch(pkg.upstream_version))
    except InvalidVersion:
        return 0.0
    if upstream <= current:
        return 0.0
    gap = (upstream.major - current.major) * 10 + (upstream.minor - current.minor)
    return min(gap / 20.0, 1.0)  # cap at 1.0


def _epss_score(pkg: PackageRecord) -> float:
    """
    Exploitation-probability signal (0–1).
    Uses EPSS if enriched, falls back to a count-based CVE approximation
    so the scorer works before EPSS enrichment runs.
    """
    if pkg.max_epss > 0.0:
        return pkg.max_epss  # already 0–1
    # Fallback: rough proxy from CVE count (cap at 10)
    return min(pkg.cve_count / 10.0, 1.0) * 0.5  # discount unenriched signal


def _cvss_score(pkg: PackageRecord) -> float:
    """
    Severity signal (0–1) from CVSS v3 base score (max 10).
    Returns 0 when not yet enriched so it contributes nothing (no penalty).
    """
    return pkg.max_cvss / 10.0


def _transitive_rdep_score(pkg: PackageRecord, max_transitive: int) -> float:
    """True blast-radius from the dep graph (transitive reverse-dep count)."""
    if max_transitive == 0:
        return 0.0
    return min(pkg.transitive_rdep_count / max_transitive, 1.0)


def _direct_rdep_score(pkg: PackageRecord, max_rdeps: int) -> float:
    """Fallback blast-radius from Repology repo count (direct reverse-dep proxy)."""
    if max_rdeps == 0:
        return 0.0
    return min(pkg.reverse_dep_count / max_rdeps, 1.0)


def _betweenness_score(pkg: PackageRecord) -> float:
    """Chokepoint signal — normalised betweenness centrality (already 0–1)."""
    return pkg.betweenness


def _download_score(pkg: PackageRecord, max_dl: int) -> float:
    if max_dl == 0:
        return 0.0
    return min(pkg.download_count / max_dl, 1.0)


def _exposure_score(pkg: PackageRecord) -> float:
    """Urgency from CVE age — longer exposure = more urgent. Caps at ~2 years."""
    if pkg.exposure_days <= 0:
        return 0.0
    return min(pkg.exposure_days / 730, 1.0)  # 730 days = 2 years → full score


_MATURITY_SCORES = {"weaponized": 1.0, "poc": 0.5, "none": 0.0}


def _exploit_maturity_score(pkg: PackageRecord) -> float:
    """
    Exploit availability signal (0–1).

    Scoring:
      weaponized  — 1.0  (CISA KEV adds bonus, capped at 1.0)
      poc         — 0.5  (public PoC exists; attacker with moderate skill can exploit)
      none        — 0.0

    CISA KEV bonus: +0.2 on top of weaponized base (capped at 1.0) — these are
    definitively being exploited in the wild by threat actors.

    OSS-Fuzz discount: packages actively fuzz-tested by OSS-Fuzz have memory-safety
    bugs continuously found and fixed by the project itself.  Discount the exploit
    maturity signal by 20% because the attack surface is actively shrinking.
    """
    base = _MATURITY_SCORES.get(pkg.exploit_maturity, 0.0)
    if pkg.in_cisa_kev:
        base = min(base + 0.2, 1.0)
    if pkg.ossfuzz_covered and base > 0.0:
        base = base * 0.8  # OSS-Fuzz coverage reduces exploitability urgency
    return base


def score_and_rank(packages: list[PackageRecord]) -> list[PackageRecord]:
    """Compute a composite priority score and return packages sorted descending.

    Packages with no security signal at all (no CVEs, no version gap, no
    EPSS/CVSS) are capped at 20 points regardless of popularity. This prevents
    high-download packages like bash (which ships everywhere but has no open
    CVEs in the current run) from topping the list over packages with real
    exploitable vulnerabilities.

    Each package also gets uncertainty bounds and a health state via the
    ``margin`` library, reflecting the confidence in data sources.
    """
    if not packages:
        return packages

    max_transitive = max((p.transitive_rdep_count for p in packages), default=0)
    max_rdeps = max((p.reverse_dep_count for p in packages), default=0)
    max_dl = max((p.download_count for p in packages), default=0)

    # When graph data is unavailable, redistribute the graph weights (44% total)
    # proportionally to EPSS, CVSS, version gap, and exploit maturity so the
    # total always sums to 100. Without this, non-Debian ecosystems lose nearly
    # half their scoring resolution.
    has_graph = max_transitive > 0
    if has_graph:
        w_epss, w_mat, w_cvss, w_gap = _W_EPSS, _W_EXPLOIT_MATURITY, _W_CVSS, _W_VERSION_GAP
        w_trans, w_bet, w_rdeps = _W_TRANSITIVE_RDEPS, _W_BETWEENNESS, _W_REVERSE_DEPS
    else:
        # Redistribute 44 points (22+15+7) across the remaining signals
        # proportional to their original weights
        _non_graph = _W_EPSS + _W_EXPLOIT_MATURITY + _W_CVSS + _W_VERSION_GAP + _W_DOWNLOADS + _W_EXPOSURE_DAYS
        _boost = (100.0 - _W_DOWNLOADS - _W_EXPOSURE_DAYS) / _non_graph
        w_epss = _W_EPSS * _boost
        w_mat = _W_EXPLOIT_MATURITY * _boost
        w_cvss = _W_CVSS * _boost
        w_gap = _W_VERSION_GAP * _boost
        w_trans, w_bet, w_rdeps = 0.0, 0.0, 0.0

    for pkg in packages:
        has_security_signal = (
            pkg.cve_count > 0
            or pkg.max_epss > 0
            or pkg.max_cvss > 0
            or pkg.is_outdated
            or pkg.has_public_exploit
            or pkg.in_cisa_kev
            or pkg.transitive_rdep_count > 10_000
        )
        s = (
            w_epss * _epss_score(pkg)
            + w_mat * _exploit_maturity_score(pkg)
            + w_cvss * _cvss_score(pkg)
            + w_gap * _version_gap(pkg)
            + w_trans * _transitive_rdep_score(pkg, max_transitive)
            + w_bet * _betweenness_score(pkg)
            + w_rdeps * _direct_rdep_score(pkg, max_rdeps)
            + _W_DOWNLOADS * _download_score(pkg, max_dl)
            + _W_EXPOSURE_DAYS * _exposure_score(pkg)
        )
        if not has_security_signal:
            s = min(s, 20.0)
        if pkg.runtime_loaded and pkg.cve_count > 0:
            s = s * _RUNTIME_LOADED_BOOST
        pkg.score = round(min(s, 100.0), 2)

    # Enrich with margin uncertainty + health classification
    _enrich_margin(packages, max_transitive)

    return sorted(packages, key=lambda p: p.score, reverse=True)


def _enrich_margin(packages: list[PackageRecord], max_transitive: int) -> None:
    """Attach uncertainty bounds, health state, and confidence to each package.

    Uncertainty sources:
    - EPSS: +/- 0.05 (FIRST.org model inherent variance)
    - Blast radius: +/- 10% (dep graph snapshot may be stale)
    - Version gap: +/- 0.15 (Repology coverage varies)
    - CVSS: 0 uncertainty (deterministic NVD score)
    - Betweenness: +/- 0.05 (graph depth-limited to 3)
    """
    try:
        from margin.uncertain import UncertainValue
        from margin.algebra import weighted_average
        from margin.health import Health
        from margin.confidence import Confidence
    except ImportError:
        return  # margin not installed — skip

    for pkg in packages:
        # Build uncertain signals matching scorer weights
        signals = [
            UncertainValue(point=_epss_score(pkg), uncertainty=0.05, source='EPSS'),
            UncertainValue(point=_exploit_maturity_score(pkg), uncertainty=0.0, source='exploit-db'),
            UncertainValue(point=_cvss_score(pkg), uncertainty=0.0, source='NVD'),
            UncertainValue(point=_version_gap(pkg), uncertainty=0.15, source='Repology'),
            UncertainValue(point=_transitive_rdep_score(pkg, max_transitive),
                           uncertainty=0.1, source='dep-graph'),
            UncertainValue(point=_betweenness_score(pkg), uncertainty=0.05, source='NetworkX'),
            UncertainValue(point=_direct_rdep_score(pkg, max(1, max_transitive)),
                           uncertainty=0.0, source='Repology'),
        ]
        weights = [
            _W_EPSS, _W_EXPLOIT_MATURITY, _W_CVSS, _W_VERSION_GAP,
            _W_TRANSITIVE_RDEPS, _W_BETWEENNESS, _W_REVERSE_DEPS,
        ]

        combined = weighted_average(signals, weights)
        # Scale to 0-100 like the point score
        unc_scaled = round(combined.uncertainty * 100 / sum(weights), 2)

        pkg.score_uncertainty = unc_scaled
        pkg.score_lower = round(max(0, pkg.score - unc_scaled), 2)
        pkg.score_upper = round(min(100, pkg.score + unc_scaled), 2)

        # Health state
        if pkg.score >= 70 or pkg.in_cisa_kev:
            pkg.health_state = Health.ABLATED.value
        elif pkg.score >= 30 or pkg.cve_count > 0:
            pkg.health_state = Health.DEGRADED.value
        else:
            pkg.health_state = Health.INTACT.value

        # Confidence — based on data source completeness
        has_epss = pkg.max_epss > 0
        has_cvss = pkg.max_cvss > 0
        has_graph = pkg.transitive_rdep_count > 0
        data_completeness = sum([has_epss, has_cvss, has_graph, pkg.version_source != "unknown"])
        if data_completeness >= 4:
            pkg.score_confidence = Confidence.CERTAIN.value
        elif data_completeness >= 3:
            pkg.score_confidence = Confidence.HIGH.value
        elif data_completeness >= 2:
            pkg.score_confidence = Confidence.MODERATE.value
        else:
            pkg.score_confidence = Confidence.LOW.value
