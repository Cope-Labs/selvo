"""
LLM-powered changelog summarization — turn upstream changelogs into actionable briefs.

For each package in the patch plan, fetch the changelog between the installed
version and the upstream target, then use the LLM to write a one-paragraph
plain-English summary highlighting only security-relevant changes.

Changelog sources (tried in order):
  1. GitHub releases API (github.com repos)
  2. PyPI releases JSON (Python packages)
  3. Raw CHANGELOG.md at upstream repo root

Result field on PackageRecord:
  changelog_summary   str   (empty if LLM unavailable or no change data found)
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

import httpx

from selvo.discovery.base import PackageRecord
from selvo.analysis import cache as _cache

log = logging.getLogger(__name__)

_GH_RELEASES_URL = "https://api.github.com/repos/{owner}/{repo}/releases"
_GH_CHANGELOG_URL = "https://raw.githubusercontent.com/{owner}/{repo}/HEAD/CHANGELOG.md"
_TTL = 21600  # 6 hours


def _parse_github_slug(repo_url: str) -> Optional[tuple[str, str]]:
    """Extract (owner, repo) from a GitHub URL."""
    m = re.search(r"github\.com[/:]([^/]+)/([^/.]+)", repo_url)
    if m:
        return m.group(1), m.group(2).rstrip(".git")
    return None


async def _fetch_github_releases(
    owner: str, repo: str, client: httpx.AsyncClient
) -> list[dict]:
    """Return the 10 most recent GitHub releases for a repo."""
    cache_key = f"changelog:gh_releases:{owner}/{repo}"
    cached = _cache.get(cache_key)
    if cached:
        import json
        return json.loads(cached)

    import os
    headers: dict[str, str] = {"User-Agent": "selvo/0.1 (changelog)"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = await client.get(
            _GH_RELEASES_URL.format(owner=owner, repo=repo),
            params={"per_page": 10},
            headers=headers,
            timeout=10.0,
            follow_redirects=True,
        )
        if resp.status_code == 200:
            releases = resp.json()
            import json
            _cache.set_cache(cache_key, json.dumps(releases), _TTL)
            return releases
    except Exception as exc:
        log.debug("GitHub releases fetch error %s/%s: %s", owner, repo, exc)
    return []


async def _fetch_changelog_md(
    owner: str, repo: str, client: httpx.AsyncClient
) -> str:
    """Fetch raw CHANGELOG.md from the upstream repo (first 8 KB)."""
    cache_key = f"changelog:md:{owner}/{repo}"
    cached = _cache.get(cache_key)
    if cached:
        return cached

    try:
        resp = await client.get(
            _GH_CHANGELOG_URL.format(owner=owner, repo=repo),
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "selvo/0.1 (changelog)"},
        )
        if resp.status_code == 200:
            text = resp.text[:8000]
            _cache.set_cache(cache_key, text, _TTL)
            return text
    except Exception as exc:
        log.debug("CHANGELOG.md fetch error %s/%s: %s", owner, repo, exc)
    return ""


def _releases_between(
    releases: list[dict],
    current_version: str,
    upstream_version: str,
) -> str:
    """
    Extract release notes for versions between current and upstream.
    Returns concatenated release body text (capped at 4 KB).
    """
    # Normalise version strings for loose comparison
    def _norm(v: str) -> str:
        return v.lstrip("vV").strip()

    norm_current = _norm(current_version)
    norm_upstream = _norm(upstream_version)

    # Find the range of releases newer than current
    collecting = False
    parts: list[str] = []
    total = 0

    for release in releases:
        tag = _norm(release.get("tag_name", "") or release.get("name", ""))
        if tag == norm_upstream:
            collecting = True
        if collecting:
            body = release.get("body", "")
            if body:
                parts.append(f"## {release.get('tag_name', tag)}\n{body}")
                total += len(body)
        if tag == norm_current:
            break
        if total > 4000:
            break

    return "\n\n".join(parts)[:4000]


async def _summarise_with_llm(
    pkg_name: str,
    current_version: str,
    upstream_version: str,
    change_text: str,
) -> str:
    """Use the LLM client to produce a one-paragraph changelog summary."""
    from selvo.analysis.llm import get_client

    client = get_client()
    if not client.enabled or not change_text.strip():
        return ""

    prompt = (
        f"Package: {pkg_name}\n"
        f"Current version: {current_version}\n"
        f"Available version: {upstream_version}\n\n"
        f"Upstream changelog (excerpt):\n{change_text}\n\n"
        "Write a SINGLE concise paragraph (≤80 words) for a security engineer that:\n"
        "1. Names any CVEs or security fixes\n"
        "2. Notes breaking-change risk (API changes, config format changes)\n"
        "3. Summarises other notable changes relevant to system stability\n"
        "If there are no security changes, say so plainly."
    )
    return await client.complete(
        prompt,
        system="You are a terse Linux security engineer. Write one dense paragraph. No bullet points.",
    )


_sem = asyncio.Semaphore(3)  # limit concurrent LLM calls


async def _summarise_package(
    pkg: PackageRecord, client: httpx.AsyncClient
) -> None:
    """Fetch changelog and summarise in-place for one package."""
    if not pkg.upstream_repo or pkg.version == "unknown" or not pkg.upstream_version:
        return

    slug = _parse_github_slug(pkg.upstream_repo)
    if not slug:
        return

    owner, repo = slug
    change_text = ""

    releases = await _fetch_github_releases(owner, repo, client)
    if releases:
        change_text = _releases_between(releases, pkg.version, pkg.upstream_version)

    if not change_text:
        change_text = await _fetch_changelog_md(owner, repo, client)

    if not change_text:
        return

    async with _sem:
        summary = await _summarise_with_llm(
            pkg.name, pkg.version, pkg.upstream_version, change_text
        )

    if summary:
        pkg.changelog_summary = summary


async def enrich_changelog_summaries(
    packages: list[PackageRecord],
    top_n: int = 10,
) -> list[PackageRecord]:
    """
    Generate LLM changelog summaries for the top-N highest-scored outdated packages.

    Only packages with a GitHub upstream repo and a version gap are processed.
    Requires OPENROUTER_API_KEY (or similar) for LLM access.

    Args:
        packages:  Full ranked package list (scored + sorted already).
        top_n:     Maximum number of packages to summarise (controls LLM cost).
    """
    from selvo.analysis.llm import get_client
    if not get_client().enabled:
        log.debug("LLM not configured — skipping changelog summarization")
        return packages

    candidates = [
        p for p in packages
        if p.is_outdated and p.upstream_repo and "github.com" in (p.upstream_repo or "")
    ][:top_n]

    if not candidates:
        return packages

    async with httpx.AsyncClient() as http:
        await asyncio.gather(
            *[_summarise_package(p, http) for p in candidates],
            return_exceptions=True,
        )

    summarised = sum(1 for p in candidates if p.changelog_summary)
    log.debug("Changelog summaries: %d/%d packages", summarised, len(candidates))
    return packages
