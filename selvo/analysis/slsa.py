"""SLSA (Supply-chain Levels for Software Artifacts) provenance attestation verifier.

Verifies build attestations against Sigstore's public-good Rekor transparency
log.  For each package with a known ``upstream_repo``, we query Rekor for
`hashedrekord` and `intoto` entries whose subject matches the package.

SLSA levels assigned:
  0 — no attestation found (default)
  1 — attestation present but not hosted-build (docs/manual)
  2 — hosted build (GitHub Actions, GitLab CI, etc.)
  3 — hardened build (pinned actions + non-forgeable provenance)

API: https://rekor.sigstore.dev/api/v1/

Reference: https://slsa.dev/spec/v1.0/levels
"""
from __future__ import annotations

import asyncio
import logging
import re

import httpx

from selvo.analysis import cache as _cache
from selvo.discovery.base import PackageRecord

log = logging.getLogger(__name__)

_REKOR_API = "https://rekor.sigstore.dev/api/v1"
_TTL = 86400  # 24 h — attestations are effectively immutable once published

# GitHub Actions builders that qualify as SLSA level 2+
_GH_BUILDERS = re.compile(
    r"https://github\.com/(slsa-framework/slsa-github-generator|actions/runner)",
    re.IGNORECASE,
)
# Builders known to produce SLSA level 3 (hardened, non-forgeable)
_L3_BUILDERS = re.compile(
    r"https://github\.com/slsa-framework/slsa-github-generator(/|$)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# SLSA level inference helpers
# ---------------------------------------------------------------------------

def _infer_slsa_level(entries: list[dict]) -> tuple[int, str, bool, str]:
    """
    Infer ``(slsa_level, builder_id, verified, source_ref)`` from a list of
    Rekor log entries.

    Returns ``(0, "", False, "")`` when no entries are present.
    """
    if not entries:
        return 0, "", False, ""

    best_level = 1  # presence of *any* attestation → level 1
    best_builder = ""
    best_source_ref = ""

    for entry in entries:
        body = entry.get("body", {})
        if isinstance(body, str):
            import base64
            import json as _json
            try:
                body = _json.loads(base64.b64decode(body + "=="))
            except Exception:
                continue

        spec = body.get("spec", {})
        # intoto envelope
        predicate = spec.get("content", {}).get("predicate", {})
        builder_id = (
            predicate.get("builder", {}).get("id", "")
            or spec.get("signature", {}).get("verifier", "")
        )
        source_ref = (
            predicate.get("buildConfig", {}).get("source", {}).get("ref", "")
            or predicate.get("materials", [{"uri": ""}])[0].get("uri", "")
        )

        if _L3_BUILDERS.search(builder_id):
            level = 3
        elif _GH_BUILDERS.search(builder_id) or "github" in builder_id.lower():
            level = 2
        else:
            level = 1

        if level > best_level:
            best_level = level
            best_builder = builder_id
            best_source_ref = source_ref

    verified = best_level >= 2  # only hosted builds are considered verified
    return best_level, best_builder, verified, best_source_ref


# ---------------------------------------------------------------------------
# Rekor queries
# ---------------------------------------------------------------------------

async def _search_rekor(
    subject: str, client: httpx.AsyncClient
) -> list[dict]:
    """Search Rekor for log entries whose subject SHA/URL matches *subject*."""
    cache_key = f"rekor:{subject}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return list(cached)

    entries: list[dict] = []
    try:
        resp = await client.post(
            f"{_REKOR_API}/index/retrieve",
            json={"query": {"subject": subject}},
            timeout=15.0,
            headers={"User-Agent": "selvo/0.1 (slsa-verifier)"},
        )
        if resp.status_code == 200:
            uuids: list[str] = resp.json()
            if uuids:
                # Fetch entry details for up to 5 UUIDs (cap to avoid blowup)
                for uuid in uuids[:5]:
                    detail_resp = await client.get(
                        f"{_REKOR_API}/log/entries/{uuid}",
                        timeout=10.0,
                        headers={"User-Agent": "selvo/0.1 (slsa-verifier)"},
                    )
                    if detail_resp.status_code == 200:
                        data = detail_resp.json()
                        entries.extend(data.values())
    except Exception as exc:
        log.debug("rekor search failed for %s: %s", subject, exc)

    _cache.set_cache(cache_key, entries, _TTL)
    return entries


def _repo_subject_candidates(upstream_repo: str) -> list[str]:
    """Return a list of subject strings to probe in Rekor for *upstream_repo*."""
    # Strip trailing slashes / .git suffixes
    repo = upstream_repo.rstrip("/").removesuffix(".git")
    candidates = [repo]
    # Some publishers use the canonical GitHub API URL as subject
    m = re.search(r"github\.com/([^/]+)/([^/]+)", repo)
    if m:
        owner, name = m.group(1), m.group(2)
        candidates.append(f"https://github.com/{owner}/{name}")
        candidates.append(f"https://api.github.com/repos/{owner}/{name}")
    return candidates


async def _fetch_slsa_for_repo(
    upstream_repo: str, client: httpx.AsyncClient
) -> tuple[int, str, bool, str]:
    """Return ``(slsa_level, builder, verified, source_ref)`` for a repo URL."""
    all_entries: list[dict] = []
    for subject in _repo_subject_candidates(upstream_repo):
        entries = await _search_rekor(subject, client)
        all_entries.extend(entries)
    return _infer_slsa_level(all_entries)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def enrich_slsa(
    packages: list[PackageRecord],
    concurrency: int = 6,
) -> list[PackageRecord]:
    """Fetch SLSA attestations from Rekor for packages with ``upstream_repo``.

    Sets the following fields on each qualifying ``PackageRecord``:
        slsa_level      — int 0–3
        slsa_builder    — builder ID string
        slsa_verified   — True when level ≥ 2
        slsa_source_ref — source repo/ref URI from the attestation
    """
    with_repo = [p for p in packages if p.upstream_repo]
    if not with_repo:
        return packages

    sem = asyncio.Semaphore(concurrency)

    async def _bounded(pkg: PackageRecord, client: httpx.AsyncClient) -> tuple[PackageRecord, tuple]:
        async with sem:
            result = await _fetch_slsa_for_repo(pkg.upstream_repo, client)  # type: ignore[arg-type]
            return pkg, result

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            *[_bounded(p, client) for p in with_repo],
            return_exceptions=True,
        )

    for item in results:
        if isinstance(item, Exception):
            log.debug("slsa enrich error: %s", item)
            continue
        pkg, (level, builder, verified, source_ref) = item  # type: ignore[misc]
        pkg.slsa_level = level
        pkg.slsa_builder = builder
        pkg.slsa_verified = verified
        pkg.slsa_source_ref = source_ref

    return packages


def check_policy_slsa(packages: list[PackageRecord], min_level: int) -> list[PackageRecord]:
    """Return packages that fail the SLSA level gate (slsa_level < min_level)."""
    return [
        p for p in packages
        if getattr(p, "slsa_level", 0) < min_level
        and p.upstream_repo  # only gate packages where we *could* verify
    ]
