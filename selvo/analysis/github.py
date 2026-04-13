"""Check GitHub for existing PRs/issues covering a CVE in an upstream repo."""
from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Optional

import httpx

from selvo.discovery.base import PrOpportunity

_GH_SEARCH_URL = "https://api.github.com/search/issues"
_REPO_RE = re.compile(r"github\.com/([^/]+/[^/\s]+)")


def _load_github_token() -> Optional[str]:
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("GITHUB_TOKEN="):
                return line.split("=", 1)[1].strip()
    return None


def _repo_slug(url: str) -> Optional[str]:
    m = _REPO_RE.search(url)
    if m:
        return m.group(1).rstrip(".git")
    return None


async def _check_existing_pr(
    cve_id: str,
    repo: str,
    client: httpx.AsyncClient,
    token: Optional[str],
) -> Optional[str]:
    """Search GitHub for an open PR or issue referencing this CVE in the repo. Returns URL or None."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    params = {
        "q": f"{cve_id} repo:{repo}",
        "type": "issues",
        "per_page": 1,
    }
    try:
        resp = await client.get(_GH_SEARCH_URL, params=params, headers=headers, timeout=10.0)
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            if items:
                return items[0]["html_url"]
        elif resp.status_code == 403:
            # Rate limited without token — skip silently
            pass
    except Exception:
        pass
    return None


async def enrich_existing_prs(opportunities: list[PrOpportunity]) -> list[PrOpportunity]:
    """
    For each PrOpportunity with a GitHub upstream repo, check if an issue/PR
    already exists for each of its CVEs. Attaches results as `existing_pr_url`.
    Sets `has_existing_pr` flag so callers can differentiate "open" vs "track" opportunities.
    """
    token = _load_github_token()
    if not token:
        # Without a token, GitHub search is rate-limited to 10 req/min — skip
        return opportunities

    async with httpx.AsyncClient() as client:
        for opp in opportunities:
            if not opp.upstream_repo:
                continue
            repo = _repo_slug(opp.upstream_repo)
            if not repo:
                continue

            tasks = [
                _check_existing_pr(cve, repo, client, token)
                for cve in opp.affected_cves[:3]  # cap: 3 CVEs per package
            ]
            results = await asyncio.gather(*tasks)
            existing = [r for r in results if r]
            if existing:
                opp.existing_pr_urls = existing  # type: ignore[attr-defined]
                opp.status = "track"  # type: ignore[attr-defined]
            else:
                opp.status = "open"  # type: ignore[attr-defined]

    return opportunities
