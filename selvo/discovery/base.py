"""Shared data models for package records."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FixRef:
    """A single upstream fix reference extracted from an OSV advisory."""

    cve_id: str
    url: str                        # commit, PR, or issue URL
    ref_type: str = "FIX"          # FIX | REPORT | WEB
    summary: str = ""


@dataclass
class PrOpportunity:
    """An actionable upstream PR/patch opportunity."""

    package: str
    ecosystem: str
    upstream_repo: Optional[str]        # resolved GitHub/GitLab URL
    fix_refs: list[FixRef]              # upstream commits or PRs from OSV
    affected_cves: list[str]            # CVE IDs this opportunity resolves
    downstream_count: int = 0           # packages that would benefit
    score: float = 0.0
    status: str = "open"               # 'open' | 'track' | 'resolved'
    existing_pr_urls: list[str] = field(default_factory=list)

    @property
    def is_actionable(self) -> bool:
        """True when we have at least one fix ref pointing to a known repo."""
        return bool(self.fix_refs or self.upstream_repo)


@dataclass
class PackageRecord:
    """Canonical representation of a discovered package."""

    name: str
    ecosystem: str  # 'debian' | 'fedora' | 'arch'
    version: str = "unknown"
    upstream_version: Optional[str] = None
    description: str = ""
    homepage: Optional[str] = None
    upstream_repo: Optional[str] = None   # resolved VCS repo URL
    download_count: int = 0
    reverse_dep_count: int = 0  # number of packages that depend on this
    cve_ids: list[str] = field(default_factory=list)
    # CVEs the distro classifies as low-impact ("unimportant" in DST) and that
    # have no exploit signal contradicting that judgment. Tracked separately so
    # the dashboard can report "X minor issues hidden" without inflating
    # cve_count or score. Populated by analysis/distro_status.py.
    minor_cve_count: int = 0
    fix_refs: list[FixRef] = field(default_factory=list)
    dependents: list[str] = field(default_factory=list)  # packages that dep on this
    score: float = 0.0
    dependencies: list[str] = field(default_factory=list)
    # CVE severity & exploitability (enriched by analysis/cvss.py + analysis/epss.py)
    max_cvss: float = 0.0   # CVSS v3 base score 0–10 (NVD)
    max_epss: float = 0.0   # EPSS exploitation probability 0–1 (FIRST.org)
    # Dependency graph metrics (enriched by analysis/graph_metrics.py)
    transitive_rdep_count: int = 0  # packages that TRANSITIVELY depend on this
    betweenness: float = 0.0        # normalised betweenness centrality (0–1)
    # Provenance: where did the installed version string come from?
    # "local" = read from local package manager (dpkg/rpm/pacman/apk)
    # "packages.gz" = extracted from Debian Packages.gz archive
    # "repology" = best stable-distro version seen on Repology
    # "unknown" = we have no version at all
    version_source: str = "unknown"
    # Patch safety (enriched by analysis/patch_safety.py)
    # 0.0 = risky to deploy blind; 1.0 = safe to auto-deploy
    patch_safety_score: float = 0.0
    patch_regression_risk: str = ""  # "low" | "medium" | "high" | ""
    # CVE lifecycle (enriched by analysis/cve_timeline.py)
    exposure_days: int = 0           # days since oldest open CVE was disclosed
    cve_disclosed_at: str = ""       # ISO date of oldest open CVE disclosure
    # Supply-chain lag (enriched by analysis/distro_compare.py)
    distro_lag_days: int = 0         # how many versions behind upstream the distro is (proxy)
    distro_versions: dict = field(default_factory=dict)  # {distro_key: version_string}
    # Real distro patch dates (enriched by analysis/distro_tracker.py)
    distro_patch_dates: dict = field(default_factory=dict)  # {distro: "YYYY-MM-DD"}
    # Exploit availability (enriched by analysis/exploit.py)
    # maturity: "none" | "poc" | "weaponized"
    exploit_maturity: str = "none"
    has_public_exploit: bool = False
    exploit_urls: list = field(default_factory=list)
    in_cisa_kev: bool = False        # CISA Known Exploited Vulnerabilities catalog
    # EPSS velocity (enriched by analysis/epss.py after snapshot comparison)
    epss_delta: float = 0.0          # change in max_epss since last snapshot
    epss_prev: float = 0.0           # max_epss from last snapshot
    # OSS-Fuzz coverage (enriched by analysis/ossfuzz.py)
    ossfuzz_covered: bool = False    # True if actively fuzz-tested by OSS-Fuzz
    ossfuzz_project: str = ""        # OSS-Fuzz project name if covered
    # SLA tracking (enriched by analysis/sla.py)
    sla_days_overdue: int = 0        # days past the SLA threshold (0 = within SLA)
    sla_band: str = ""               # "" | "ok" | "warn" | "breach" | "critical"
    # Vendor advisory (enriched by analysis/advisories.py)
    vendor_advisory_ids: list = field(default_factory=list)  # USN-XXXX, FEDORA-SA-XX, RHSA-XX
    # LLM changelog summary (enriched by analysis/changelog.py)
    changelog_summary: str = ""      # LLM-generated plain-English summary of pending changes
    # Reachability (enriched by analysis/reachability.py)
    reachable: bool = False                  # True if any CVE is reachable from the call graph
    reachability_source: str = ""            # "govulncheck" | "pyast" | "unknown" | ""
    reachable_cves: list[str] = field(default_factory=list)    # CVE IDs confirmed reachable
    unreachable_cves: list[str] = field(default_factory=list)  # CVE IDs confirmed unreachable

    # Dependency confusion risks (enriched by analysis/dep_confusion.py)
    confusion_risks: list = field(default_factory=list)
    # SLSA provenance attestation (enriched by analysis/slsa.py)
    slsa_level: int = 0              # 0–3 per SLSA specification v1.0
    slsa_builder: str = ""           # builder ID URI from attestation
    slsa_verified: bool = False      # True when level ≥ 2 (hosted build)
    slsa_source_ref: str = ""        # source repo/ref URI from attestation
    # Runtime reachability (enriched by analysis/runtime.py)
    # True if at least one .so from this package is loaded in a live process right now
    runtime_loaded: bool = False
    runtime_pids: list[int] = field(default_factory=list)    # PIDs with this package loaded
    runtime_procs: list[str] = field(default_factory=list)   # process comm names
    # Margin uncertainty + health (enriched by prioritizer/scorer.py)
    score_uncertainty: float = 0.0       # +/- uncertainty on the composite score
    score_lower: float = 0.0            # score - uncertainty
    score_upper: float = 0.0            # score + uncertainty
    health_state: str = ""              # "INTACT" | "DEGRADED" | "ABLATED"
    score_confidence: str = ""          # "certain" | "high" | "moderate" | "low"

    @property
    def is_outdated(self) -> bool:
        return bool(
            self.upstream_version
            and self.version
            and self.version not in ("unknown", "")
            and self.upstream_version != self.version
        )

    @property
    def cve_count(self) -> int:
        return len(self.cve_ids)
