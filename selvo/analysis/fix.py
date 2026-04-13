"""Auto-remediation pipeline — open upstream PRs to bump CVE-affected packages.

Each package in the pipeline must have:
  • upstream_repo  pointing at a GitHub repo (https://github.com/owner/repo)
  • cve_ids        non-empty
  • upstream_version > version (a known fix target)

The pipeline uses the GitHub REST API (no local git clone).  For every
qualifying package it:
  1. Creates a feature branch off the default branch.
  2. Locates the first version-anchoring file (pyproject.toml, CMakeLists.txt …).
  3. Substitutes the old version string with the fix version.
  4. Opens a PR with a structured body referencing the CVE(s).

In dry-run mode nothing is written; the plan is printed to *console* instead.
"""
from __future__ import annotations

import asyncio
import base64
import re
from typing import Optional

import httpx
from rich.console import Console

from selvo.discovery.base import PackageRecord

_GH_API = "https://api.github.com"
_GH_ACCEPT = "application/vnd.github+json"
_GH_VERSION = "2022-11-28"

# Ordered list of files to probe for a pinned/declared version string
_VERSION_FILES = [
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "CMakeLists.txt",
    "meson.build",
    "configure.ac",
    "Cargo.toml",
    "go.mod",
    "version.txt",
    "Makefile",
    "VERSION",
]


# ---------------------------------------------------------------------------
# Helpers — GitHub API primitives
# ---------------------------------------------------------------------------

def _parse_github_repo(url: Optional[str]) -> Optional[tuple[str, str]]:
    """Return ``(owner, repo)`` from a GitHub URL, or *None*."""
    if not url:
        return None
    m = re.search(r"github\.com[:/]([^/]+)/([^/#\s]+?)(?:\.git)?/?$", url)
    if m:
        return m.group(1), m.group(2)
    return None


def _gh_headers(token: str) -> dict[str, str]:
    headers: dict[str, str] = {
        "Accept": _GH_ACCEPT,
        "X-GitHub-Api-Version": _GH_VERSION,
        "User-Agent": "selvo/0.1 (auto-fix)",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _get_default_branch(
    client: httpx.AsyncClient, owner: str, repo: str, headers: dict
) -> Optional[str]:
    r = await client.get(f"{_GH_API}/repos/{owner}/{repo}", headers=headers, timeout=15.0)
    if r.status_code == 200:
        return r.json().get("default_branch", "main")
    return None


async def _get_ref_sha(
    client: httpx.AsyncClient, owner: str, repo: str, branch: str, headers: dict
) -> Optional[str]:
    r = await client.get(
        f"{_GH_API}/repos/{owner}/{repo}/git/ref/heads/{branch}",
        headers=headers, timeout=10.0,
    )
    if r.status_code == 200:
        return r.json()["object"]["sha"]
    return None


async def _create_branch(
    client: httpx.AsyncClient, owner: str, repo: str,
    branch: str, sha: str, headers: dict,
) -> tuple[bool, bool]:
    """Create *branch* at *sha*.  Returns ``(ok, already_existed)``.

    HTTP 422 means the branch already exists on the remote (e.g. a previous
    selvo run that did not open a PR, or a user branch with the same name).
    We treat it as a non-fatal collision rather than success so the caller can
    decide whether to reuse the branch or abort safely.
    """
    r = await client.post(
        f"{_GH_API}/repos/{owner}/{repo}/git/refs",
        headers=headers,
        json={"ref": f"refs/heads/{branch}", "sha": sha},
        timeout=10.0,
    )
    if r.status_code in (200, 201):
        return True, False
    if r.status_code == 422:
        # Branch already exists — signal collision to caller
        return True, True
    return False, False


async def _get_file(
    client: httpx.AsyncClient, owner: str, repo: str,
    path: str, ref: str, headers: dict,
) -> Optional[tuple[str, str]]:
    """Return ``(decoded_content, blob_sha)`` or *None*."""
    r = await client.get(
        f"{_GH_API}/repos/{owner}/{repo}/contents/{path}",
        headers=headers, params={"ref": ref}, timeout=10.0,
    )
    if r.status_code == 200:
        data = r.json()
        if data.get("encoding") == "base64":
            content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            return content, data["sha"]
    return None


async def _update_file(
    client: httpx.AsyncClient,
    owner: str, repo: str, path: str, branch: str,
    new_content: str, blob_sha: str, message: str, headers: dict,
) -> bool:
    r = await client.put(
        f"{_GH_API}/repos/{owner}/{repo}/contents/{path}",
        headers=headers,
        json={
            "message": message,
            "content": base64.b64encode(new_content.encode()).decode(),
            "sha": blob_sha,
            "branch": branch,
        },
        timeout=15.0,
    )
    return r.status_code in (200, 201)


async def _open_pr(
    client: httpx.AsyncClient,
    owner: str, repo: str, head: str, base: str,
    title: str, body: str, headers: dict,
) -> Optional[str]:
    """Create a PR and return its ``html_url``, or *None* on failure."""
    r = await client.post(
        f"{_GH_API}/repos/{owner}/{repo}/pulls",
        headers=headers,
        json={"title": title, "head": head, "base": base, "body": body},
        timeout=15.0,
    )
    if r.status_code in (200, 201):
        return r.json().get("html_url")
    return None


# ---------------------------------------------------------------------------
# Version-file patching
# ---------------------------------------------------------------------------

def _bump_version_in_text(content: str, old: str, new: str) -> Optional[str]:
    """Replace *old* version with *new* in *content*.

    Attempts common declarative patterns first; falls back to plain substring
    replacement.  Returns *None* if the old version string was not found.
    """
    old_esc = re.escape(old)
    # Patterns: `version = "X.Y.Z"`, `version: X.Y.Z`, `VERSION=X.Y.Z`, etc.
    for pattern in [
        rf'((?:version|VERSION)\s*[=:]\s*["\']?){old_esc}(["\']?)',
        rf'(\bv?){old_esc}(\b)',
    ]:
        updated, count = re.subn(pattern, rf'\g<1>{new}\2', content)
        if count:
            return updated
    # Plain literal replacement as last resort
    if old in content:
        return content.replace(old, new, 1)
    return None


async def _patch_version_file(
    client: httpx.AsyncClient,
    owner: str, repo: str, branch: str,
    old_version: str, new_version: str,
    commit_msg: str, headers: dict,
) -> Optional[str]:
    """Find the first patchable version file and update it.  Returns the file
    path that was updated, or *None* if none was found / patched.
    """
    for fname in _VERSION_FILES:
        result = await _get_file(client, owner, repo, fname, branch, headers)
        if result is None:
            continue
        content, blob_sha = result
        new_content = _bump_version_in_text(content, old_version, new_version)
        if new_content is None or new_content == content:
            continue
        ok = await _update_file(
            client, owner, repo, fname, branch,
            new_content, blob_sha, commit_msg, headers,
        )
        if ok:
            return fname
    return None


# ---------------------------------------------------------------------------
# Per-package processor
# ---------------------------------------------------------------------------

def _skipped(package: str, reason: str) -> dict:
    return {"status": "skipped", "package": package, "pr_url": None, "reason": reason, "error": ""}


def _error(package: str, error: str) -> dict:
    return {"status": "error", "package": package, "pr_url": None, "reason": "", "error": error}


def _opened(package: str, pr_url: Optional[str], reason: str) -> dict:
    return {"status": "opened", "package": package, "pr_url": pr_url, "reason": reason, "error": ""}


async def _process_package(
    pkg: PackageRecord,
    dry_run: bool,
    github_token: str,
    console: Console,
) -> dict:
    # ── Validate prerequisites ──────────────────────────────────────────────
    gh_repo = _parse_github_repo(pkg.upstream_repo)
    if not gh_repo:
        return _skipped(pkg.name, f"No GitHub upstream_repo (got {pkg.upstream_repo!r})")

    if not pkg.cve_ids:
        return _skipped(pkg.name, "No CVEs associated with this package")

    fix_version = pkg.upstream_version or ""
    if not fix_version or fix_version in (pkg.version, "unknown", ""):
        return _skipped(
            pkg.name,
            f"No fix version available (current={pkg.version!r}, upstream={fix_version!r})",
        )

    owner, repo = gh_repo
    cve_summary = ", ".join(pkg.cve_ids[:3]) + ("…" if len(pkg.cve_ids) > 3 else "")
    # Sanitise branch name: max 63 chars, no special chars
    safe_version = fix_version.replace(".", "-").replace("+", "-")
    branch_name = re.sub(r"[^a-zA-Z0-9/_-]", "-", f"selvo/fix-{pkg.name}-{safe_version}")[:63]
    pr_title = f"chore: bump {pkg.name} to {fix_version} (fixes {cve_summary})"
    fix_refs_md = "".join(f"- {r.url}\n" for r in pkg.fix_refs[:5])
    pr_body = (
        f"## Security update: {pkg.name} `{pkg.version}` → `{fix_version}`\n\n"
        f"**Affected CVEs:** {', '.join(pkg.cve_ids)}\n"
        f"**Max CVSS:** {pkg.max_cvss:.1f} | "
        f"**Max EPSS:** {pkg.max_epss:.2%}\n\n"
        f"This PR was automatically generated by "
        f"[selvo](https://github.com/selvo/selvo).\n\n"
        + (f"### Fix references\n{fix_refs_md}\n" if fix_refs_md else "")
        + "\n---\n_Please review before merging._"
    )

    # ── Dry-run path ────────────────────────────────────────────────────────
    if dry_run:
        console.print(
            f"  [dim][dry-run][/dim] [cyan]{owner}/{repo}[/] "
            f"branch [yellow]{branch_name}[/]: "
            f"{pkg.name} [red]{pkg.version}[/] → [green]{fix_version}[/] "
            f"({cve_summary})"
        )
        return _opened(pkg.name, None, f"[dry-run] {pr_title}")

    # ── Live path ───────────────────────────────────────────────────────────
    if not github_token:
        return _skipped(pkg.name, "No GitHub token — set --github-token or GITHUB_TOKEN env var")

    headers = _gh_headers(github_token)

    try:
        async with httpx.AsyncClient() as client:
            default_branch = await _get_default_branch(client, owner, repo, headers)
            if not default_branch:
                return _error(pkg.name, f"Cannot fetch repo metadata for {owner}/{repo}")

            sha = await _get_ref_sha(client, owner, repo, default_branch, headers)
            if not sha:
                return _error(pkg.name, f"Cannot resolve HEAD of {owner}/{repo}@{default_branch}")

            created, already_existed = await _create_branch(
                client, owner, repo, branch_name, sha, headers
            )
            if not created:
                return _error(pkg.name, f"Cannot create branch {branch_name!r} on {owner}/{repo}")
            if already_existed:
                # Branch from a previous run exists — reuse it only if it still
                # points to the same base SHA so we don't clobber unrelated work.
                existing_sha = await _get_ref_sha(
                    client, owner, repo, branch_name, headers
                )
                if existing_sha != sha:
                    return _skipped(
                        pkg.name,
                        f"Branch {branch_name!r} already exists on {owner}/{repo} with a "
                        f"different base commit ({existing_sha[:8] if existing_sha else '?'} "
                        f"vs expected {sha[:8]}). Delete it manually to let selvo retry.",
                    )

            commit_msg = (
                f"chore: bump {pkg.name} from {pkg.version} to {fix_version}\n\n"
                f"Resolves: {', '.join(pkg.cve_ids)}"
            )
            patched_file = await _patch_version_file(
                client, owner, repo, branch_name,
                pkg.version, fix_version, commit_msg, headers,
            )
            if not patched_file:
                return _skipped(
                    pkg.name,
                    f"Version string {pkg.version!r} not found in any version file in {owner}/{repo}",
                )

            pr_url = await _open_pr(
                client, owner, repo,
                head=branch_name, base=default_branch,
                title=pr_title, body=pr_body,
                headers=headers,
            )
            if not pr_url:
                return _error(pkg.name, "PR creation call succeeded but returned no html_url")

            console.print(f"  [green]✓[/] PR opened: [link={pr_url}]{pr_url}[/link]")
            return _opened(pkg.name, pr_url, pr_title)

    except Exception as exc:  # noqa: BLE001
        return _error(pkg.name, str(exc))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def run_fix_pipeline(
    packages: list[PackageRecord],
    dry_run: bool,
    github_token: str,
    console: Console,
) -> list[dict]:
    """Run the auto-fix pipeline over *packages*.

    Returns a list of per-package result dicts, each with keys:
        ``status``   – ``"opened"`` | ``"skipped"`` | ``"error"``
        ``package``  – package name
        ``pr_url``   – GitHub PR URL (or *None*)
        ``reason``   – human-readable status note
        ``error``    – error detail (empty string when no error)
    """
    sem = asyncio.Semaphore(4)  # cap concurrent GitHub API calls

    async def _bounded(pkg: PackageRecord) -> dict:
        async with sem:
            return await _process_package(pkg, dry_run, github_token, console)

    results = await asyncio.gather(*[_bounded(p) for p in packages])
    return list(results)
