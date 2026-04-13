"""Resolve upstream VCS repository URLs for packages via Repology."""
from __future__ import annotations

import asyncio
import re

import httpx

from selvo.discovery.base import PackageRecord

_REPOLOGY_API = "https://repology.org/api/v1/project/{name}"
_GITHUB_RE = re.compile(r"https?://github\.com/[^/]+/[^/\s\"'>]+")
_GITLAB_RE = re.compile(r"https?://gitlab\.com/[^/]+/[^/\s\"'>]+")
_KERNEL_RE = re.compile(r"https?://git\.kernel\.org/[^\s\"'>]+")


def _extract_vcs_url(text: str) -> str | None:
    for pattern in (_GITHUB_RE, _GITLAB_RE, _KERNEL_RE):
        m = pattern.search(text)
        if m:
            return m.group(0).rstrip("/.git")
    return None


async def _resolve_one(pkg: PackageRecord, client: httpx.AsyncClient) -> str | None:
    """Try to resolve an upstream VCS repo URL for `pkg`."""
    # 1. Already set (e.g. from OSV fix refs)
    if pkg.upstream_repo:
        return pkg.upstream_repo

    # 2. Homepage contains a VCS URL
    if pkg.homepage:
        repo = _extract_vcs_url(pkg.homepage)
        if repo:
            return repo

    # 3. Query Repology for the project — it sometimes has urls.homepage entries
    try:
        resp = await client.get(
            _REPOLOGY_API.format(name=pkg.name),
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "selvo/0.1 (upstream-resolver)"},
        )
        if resp.status_code == 200:
            repos = resp.json()
            for entry in repos:
                for url_field in ("www", "homepage"):
                    urls = entry.get(url_field) or []
                    if isinstance(urls, str):
                        urls = [urls]
                    for url in urls:
                        repo = _extract_vcs_url(url)
                        if repo:
                            return repo
    except Exception:
        pass

    return None


async def enrich_upstream_repos(packages: list[PackageRecord]) -> list[PackageRecord]:
    """Annotate each PackageRecord with a resolved upstream VCS repo URL."""
    async with httpx.AsyncClient() as client:
        repos = await asyncio.gather(*[_resolve_one(pkg, client) for pkg in packages])

    for pkg, repo in zip(packages, repos):
        if repo:
            pkg.upstream_repo = repo

    return packages
