"""Patch opportunity analysis — extract fix refs from OSV advisories and build PR candidates."""
from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

import httpx

from selvo.discovery.base import FixRef, PackageRecord, PrOpportunity

_OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"

# Patterns that suggest a link is a concrete fix (commit/PR/MR) vs just a report
_FIX_PATTERNS = [
    re.compile(r"github\.com/.+/commit/[0-9a-f]{7,}"),
    re.compile(r"github\.com/.+/pull/\d+"),
    re.compile(r"gitlab\.com/.+/-/merge_requests/\d+"),
    re.compile(r"gitlab\.com/.+/-/commit/[0-9a-f]{7,}"),
    re.compile(r"git\.kernel\.org/.+/commit/\?h=.+"),
    re.compile(r"patchwork\..+/patch/\d+"),
]

_UPSTREAM_PATTERNS = [
    re.compile(r"(https?://github\.com/[^/]+/[^/]+)"),
    re.compile(r"(https?://gitlab\.com/[^/]+/[^/\s]+)"),
    re.compile(r"(https?://git\.kernel\.org/[^/]+/[^/\s]+)"),
]


def _looks_like_fix(url: str) -> bool:
    return any(p.search(url) for p in _FIX_PATTERNS)


def _extract_repo_from_url(url: str) -> str | None:
    for pattern in _UPSTREAM_PATTERNS:
        m = pattern.search(url)
        if m:
            return m.group(1).rstrip(".git/")
    return None


async def _fetch_osv_advisory(vuln_id: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(_OSV_VULN_URL.format(vuln_id=vuln_id), timeout=10.0)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


def _parse_fix_refs(vuln_id: str, advisory: dict) -> list[FixRef]:
    """Extract fix-pointing references from an OSV advisory."""
    refs: list[FixRef] = []
    summary = advisory.get("summary", "")

    for ref in advisory.get("references", []):
        url = ref.get("url", "")
        ref_type = ref.get("type", "WEB")

        if ref_type == "FIX" or _looks_like_fix(url):
            refs.append(FixRef(cve_id=vuln_id, url=url, ref_type="FIX", summary=summary))
        elif ref_type == "REPORT":
            refs.append(FixRef(cve_id=vuln_id, url=url, ref_type="REPORT", summary=summary))

    return refs


async def enrich_fix_refs(packages: list[PackageRecord], use_llm: bool = False) -> list[PackageRecord]:
    """Fetch full OSV advisories for each CVE and attach FixRefs to each package."""
    all_cve_ids: list[tuple[int, str]] = [
        (i, cve) for i, pkg in enumerate(packages) for cve in pkg.cve_ids
    ]

    async with httpx.AsyncClient() as client:
        advisories = await asyncio.gather(
            *[_fetch_osv_advisory(cve, client) for _, cve in all_cve_ids]
        )

    for (pkg_idx, cve_id), advisory in zip(all_cve_ids, advisories):
        fix_refs = _parse_fix_refs(cve_id, advisory)
        packages[pkg_idx].fix_refs.extend(fix_refs)

        # Opportunistically derive upstream repo from fix URLs
        if not packages[pkg_idx].upstream_repo:
            for ref in fix_refs:
                repo = _extract_repo_from_url(ref.url)
                if repo:
                    packages[pkg_idx].upstream_repo = repo
                    break

    # LLM pass: reclassify ambiguous refs that regex couldn't determine
    if use_llm:
        from selvo.analysis.llm import get_client
        llm = get_client()
        if llm.enabled:
            for pkg in packages:
                ambiguous = [
                    r for r in pkg.fix_refs if r.ref_type == "WEB"
                ]
                if ambiguous:
                    classifications = await llm.classify_fix_refs([r.url for r in ambiguous])
                    for ref in ambiguous:
                        cls = classifications.get(ref.url)
                        if cls in ("FIX", "REPORT", "INFO"):
                            ref.ref_type = cls

    return packages


def build_pr_opportunities(packages: list[PackageRecord]) -> list[PrOpportunity]:
    """
    For each package with fix refs, build a PrOpportunity.
    Downstream count = number of other packages that list this one as a dependency.
    """
    # Build reverse dep index
    dep_index: dict[str, int] = {}
    for pkg in packages:
        for dep in pkg.dependencies:
            dep_index[dep] = dep_index.get(dep, 0) + 1

    opportunities: list[PrOpportunity] = []
    for pkg in packages:
        if not pkg.fix_refs and not pkg.is_outdated:
            continue

        downstream = dep_index.get(pkg.name, 0) + pkg.reverse_dep_count
        # Align scoring with the analyze pipeline:
        #   40pts  exploitation probability (EPSS 0.0–1.0)
        #   20pts  severity (CVSS 0–10 → 0–20)
        #   20pts  version lag bonus
        #   15pts  blast-radius (rev-dep count, capped at 1000)
        #    5pts  per confirmed fix ref
        score = (
            pkg.max_epss * 40
            + (pkg.max_cvss / 10.0) * 20
            + (20 if pkg.is_outdated else 0)
            + min(downstream / 1000.0, 1.0) * 15
            + len([r for r in pkg.fix_refs if r.ref_type == "FIX"]) * 5
        )

        opportunities.append(
            PrOpportunity(
                package=pkg.name,
                ecosystem=pkg.ecosystem,
                upstream_repo=pkg.upstream_repo or pkg.homepage,
                fix_refs=pkg.fix_refs,
                affected_cves=pkg.cve_ids,
                downstream_count=downstream,
                score=round(float(score), 2),
            )
        )

    return sorted(opportunities, key=lambda o: o.score, reverse=True)


# ---------------------------------------------------------------------------
# Backport auto-draft
# ---------------------------------------------------------------------------

_GH_COMMIT_RE = re.compile(
    r"github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-f]{7,})"
)


def _load_github_token() -> str:
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        return token
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("GITHUB_TOKEN="):
                return line.split("=", 1)[1].strip()
    return ""


async def fetch_commit_diff(url: str, client: httpx.AsyncClient) -> str:
    """
    Fetch the raw unified diff for a GitHub commit URL.
    Returns empty string if the URL doesn't match or the request fails.
    """
    m = _GH_COMMIT_RE.search(url)
    if not m:
        return ""
    owner, repo, sha = m.group("owner"), m.group("repo"), m.group("sha")
    token = _load_github_token()
    headers: dict[str, str] = {
        "Accept": "application/vnd.github.v3.diff",
        "User-Agent": "selvo/0.1 (backport-drafter)",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
        resp = await client.get(api_url, headers=headers, timeout=12.0, follow_redirects=True)
        if resp.status_code == 200:
            return resp.text[:5000]  # Truncate to avoid LLM token overflow
    except Exception:
        pass
    return ""


async def enrich_backport_drafts(
    opportunities: list[PrOpportunity],
    top_n: int = 5,
) -> list[PrOpportunity]:
    """
    For the top `top_n` open opportunities with GitHub fix commits, fetch the
    diff and generate a backport draft via the LLM. Stored as `_backport_draft`.
    """
    from selvo.analysis.llm import get_client

    llm = get_client()
    if not llm.enabled:
        return opportunities

    candidates = [
        o for o in opportunities[:top_n]
        if o.status == "open" and any(
            _GH_COMMIT_RE.search(r.url) for r in o.fix_refs if r.ref_type == "FIX"
        )
    ]
    if not candidates:
        return opportunities

    async with httpx.AsyncClient() as client:
        for opp in candidates:
            # Pick first GitHub commit fix ref
            fix_ref = next(
                r for r in opp.fix_refs
                if r.ref_type == "FIX" and _GH_COMMIT_RE.search(r.url)
            )
            diff = await fetch_commit_diff(fix_ref.url, client)
            if diff:
                cve_id = opp.affected_cves[0] if opp.affected_cves else "unknown"
                draft = await llm.generate_backport_patch(
                    package=opp.package,
                    cve_id=cve_id,
                    fix_url=fix_ref.url,
                    diff_snippet=diff,
                )
                if draft:
                    opp._backport_draft = draft  # type: ignore[attr-defined]

    return opportunities
