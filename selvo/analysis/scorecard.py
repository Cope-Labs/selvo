"""
OpenSSF Security Scorecard enrichment.

Scorecard rates upstream GitHub repos on a 0–10 maintainer health scale
using automated checks: CI, code review, signed releases, branch protection,
dependency update tools, fuzzing, SAST, etc.

A high Scorecard score means a PR is likely to be reviewed, merged, and
released. A low score means the upstream is poorly maintained — the patch
may sit unmergeable for years.

API: https://api.securityscorecards.dev/projects/{platform}/{owner}/{repo}
  - No auth required, rate limit generous for reasonable use
  - Returns: {score (0-10), checks [{name, score, reason}]}
"""
from __future__ import annotations

import asyncio
import logging
import re

import httpx

from selvo.discovery.base import PackageRecord, PrOpportunity
from selvo.analysis import cache as _cache

log = logging.getLogger(__name__)

_SCORECARD_API = "https://api.securityscorecards.dev/projects/{platform}/{owner}/{repo}"
_TTL = 86400  # 24 hours — changes slowly

_GH_RE = re.compile(r"github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$")
_GL_RE = re.compile(r"gitlab\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$")


def _parse_repo(url: str) -> tuple[str, str, str] | None:
    """Extract (platform, owner, repo) from a GitHub or GitLab URL."""
    m = _GH_RE.search(url)
    if m:
        return "github.com", m.group("owner"), m.group("repo")
    m = _GL_RE.search(url)
    if m:
        return "gitlab.com", m.group("owner"), m.group("repo")
    return None


async def _fetch_scorecard(url: str, client: httpx.AsyncClient) -> float:
    """Fetch the OpenSSF Scorecard score for a repo URL. Returns 0.0 on failure."""
    parts = _parse_repo(url)
    if not parts:
        return 0.0
    platform, owner, repo = parts
    cache_key = f"scorecard:{platform}:{owner}/{repo}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return float(cached)

    try:
        api_url = _SCORECARD_API.format(platform=platform, owner=owner, repo=repo)
        resp = await client.get(
            api_url,
            timeout=12.0,
            follow_redirects=True,
            headers={"User-Agent": "selvo/0.1 (scorecard-enricher)"},
        )
        if resp.status_code == 200:
            score = float(resp.json().get("score", 0.0))
            _cache.set_cache(cache_key, score, _TTL)
            return score
        log.warning("Scorecard API returned HTTP %d for %s", resp.status_code, url)
    except Exception as exc:
        log.warning("Scorecard API failed for %s: %s", url, exc)
    return 0.0


async def enrich_scorecard(packages: list[PackageRecord]) -> list[PackageRecord]:
    """
    Fetch OpenSSF Scorecard scores for all packages with a known upstream repo.
    Sets `scorecard` attribute on each package (0–10, 0 = unknown/failed).
    """
    with_repo = [p for p in packages if p.upstream_repo]
    if not with_repo:
        return packages

    async with httpx.AsyncClient() as client:
        scores = await asyncio.gather(
            *[_fetch_scorecard(p.upstream_repo, client) for p in with_repo]  # type: ignore[arg-type]
        )

    for pkg, score in zip(with_repo, scores):
        pkg.scorecard = score  # type: ignore[attr-defined]

    return packages


async def enrich_scorecard_opportunities(
    opportunities: list[PrOpportunity],
) -> list[PrOpportunity]:
    """Fetch Scorecard for PR opportunities that have an upstream repo."""
    with_repo = [o for o in opportunities if o.upstream_repo]
    if not with_repo:
        return opportunities

    async with httpx.AsyncClient() as client:
        scores = await asyncio.gather(
            *[_fetch_scorecard(o.upstream_repo, client) for o in with_repo]  # type: ignore[arg-type]
        )

    for opp, score in zip(with_repo, scores):
        opp.scorecard = score  # type: ignore[attr-defined]

    return opportunities
