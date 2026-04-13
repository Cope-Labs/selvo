"""Analysis sub-package."""
from selvo.analysis import cache
from selvo.analysis.versions import enrich_versions
from selvo.analysis.cve import enrich_cve
from selvo.analysis.epss import enrich_epss
from selvo.analysis.cvss import enrich_cvss
from selvo.analysis.patch import enrich_fix_refs, build_pr_opportunities, enrich_backport_drafts
from selvo.analysis.upstream import enrich_upstream_repos
from selvo.analysis.rdeps import enrich_reverse_deps
from selvo.analysis.distro_status import filter_resolved_cves
from selvo.analysis.github import enrich_existing_prs
from selvo.analysis.llm import get_client as get_llm_client
from selvo.analysis.scorecard import enrich_scorecard, enrich_scorecard_opportunities
from selvo.analysis.reachability import enrich_reachability, apply_reachability_score_discount
from selvo.analysis.compliance import map_controls

__all__ = [
    "cache",
    "enrich_versions",
    "enrich_cve",
    "enrich_epss",
    "enrich_cvss",
    "enrich_fix_refs",
    "enrich_upstream_repos",
    "enrich_reverse_deps",
    "filter_resolved_cves",
    "enrich_existing_prs",
    "build_pr_opportunities",
    "enrich_backport_drafts",
    "get_llm_client",
    "enrich_scorecard",
    "enrich_scorecard_opportunities",
    "enrich_reachability",
    "apply_reachability_score_discount",
    "map_controls",
]
