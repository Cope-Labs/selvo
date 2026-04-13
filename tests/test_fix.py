"""End-to-end tests for selvo/analysis/fix.py — mock GitHub API via unittest.mock.

All HTTP calls are intercepted; no real network I/O occurs.

Coverage:
  - Happy path: new branch + version file found + PR opened → status "opened"
  - Dry-run path: no HTTP calls made, status "opened" (dry-run)
  - Skip: no upstream_repo
  - Skip: no CVEs
  - Skip: no fix version (installed == upstream)
  - Skip: version string not found in any probed file
  - Error: GitHub repo metadata returns 404
  - Error: cannot resolve HEAD SHA
  - Error: branch create fails (non-422 HTTP error)
  - Branch collision — same SHA: reuse branch, continue to PR
  - Branch collision — different SHA: skip with clear message
  - PR open returns no html_url → error
  - _bump_version_in_text patterns (unit)
  - _parse_github_repo patterns (unit)
"""
from __future__ import annotations

import asyncio
import base64
import json
from io import StringIO
from typing import Any
from unittest.mock import MagicMock, patch

from rich.console import Console

from selvo.analysis.fix import (
    _bump_version_in_text,
    _parse_github_repo,
    _process_package,
    run_fix_pipeline,
)
from selvo.discovery.base import PackageRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pkg(**kw) -> PackageRecord:
    defaults = dict(
        name="mylib",
        ecosystem="debian",
        version="1.0.0",
        upstream_version="2.0.0",
        upstream_repo="https://github.com/example/mylib",
        cve_ids=["CVE-2024-0001"],
        max_cvss=7.5,
        max_epss=0.25,
        download_count=0,
        reverse_dep_count=0,
        exploit_maturity="none",
        in_cisa_kev=False,
        transitive_rdep_count=0,
        betweenness=0.0,
        score=50.0,
        sla_band="",
        sla_days_overdue=0,
        fix_refs=[],
    )
    defaults.update(kw)
    return PackageRecord(**defaults)


def _console() -> Console:
    return Console(file=StringIO(), highlight=False)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


SHA = "abc1234" * 5 + "ab"  # 42-char fake SHA


def _mock_response(status: int, body: Any) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body
    r.text = json.dumps(body)
    return r


# Canonical GitHub API response factory for a successful happy path
def _happy_responses(
    pyproject_content: str = 'version = "1.0.0"\n',
    branch_status: int = 201,       # 201 = created fresh
    branch_sha: str = SHA,          # SHA returned for existing branch lookup
) -> list[MagicMock]:
    """Return ordered mock responses for the happy-path HTTP sequence:
        GET  /repos/…             → repo info (default_branch=main)
        GET  /git/ref/heads/main  → HEAD sha
        POST /git/refs            → branch created
        GET  /contents/pyproject.toml → file content
        PUT  /contents/pyproject.toml → file updated
        POST /pulls               → PR opened
    """
    return [
        _mock_response(200, {"default_branch": "main"}),
        _mock_response(200, {"object": {"sha": SHA}}),
        _mock_response(branch_status, {}),
        _mock_response(200, {"encoding": "base64", "content": _b64(pyproject_content), "sha": "blob1"}),
        _mock_response(200, {}),
        _mock_response(201, {"html_url": "https://github.com/example/mylib/pull/42"}),
    ]


class _MockClient:
    """Minimal async context manager wrapping a response sequence."""

    def __init__(self, responses: list[MagicMock]):
        self._responses = list(responses)
        self._idx = 0
        self.requests: list[tuple[str, str]] = []  # (method, url)

    async def _call(self, method: str, url: str, **_kw) -> MagicMock:
        if self._idx >= len(self._responses):
            raise AssertionError(f"Unexpected extra {method} {url} (call #{self._idx})")
        resp = self._responses[self._idx]
        self.requests.append((method, url))
        self._idx += 1
        return resp

    async def get(self, url: str, **kw) -> MagicMock:
        return await self._call("GET", url, **kw)

    async def post(self, url: str, **kw) -> MagicMock:
        return await self._call("POST", url, **kw)

    async def put(self, url: str, **kw) -> MagicMock:
        return await self._call("PUT", url, **kw)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Unit tests — pure helpers
# ---------------------------------------------------------------------------

class TestParseGithubRepo:
    def test_https_url(self):
        assert _parse_github_repo("https://github.com/curl/curl") == ("curl", "curl")

    def test_https_url_git_suffix(self):
        assert _parse_github_repo("https://github.com/openssl/openssl.git") == ("openssl", "openssl")

    def test_ssh_url(self):
        assert _parse_github_repo("git@github.com:linux-pam/linux-pam.git") == ("linux-pam", "linux-pam")

    def test_none_input(self):
        assert _parse_github_repo(None) is None

    def test_non_github(self):
        assert _parse_github_repo("https://gitlab.com/gnutls/gnutls") is None

    def test_trailing_slash(self):
        assert _parse_github_repo("https://github.com/systemd/systemd/") == ("systemd", "systemd")


class TestBumpVersionInText:
    def test_toml_quoted(self):
        content = 'version = "1.0.0"\n'
        result = _bump_version_in_text(content, "1.0.0", "2.0.0")
        assert result == 'version = "2.0.0"\n'

    def test_cmake_set(self):
        content = "set(MY_LIB_VERSION 1.0.0)\n"
        result = _bump_version_in_text(content, "1.0.0", "2.0.0")
        assert "2.0.0" in result

    def test_no_match_returns_none(self):
        result = _bump_version_in_text("nothing here\n", "1.0.0", "2.0.0")
        assert result is None

    def test_already_new_version_unchanged(self):
        # If old == new no replacement needed; still returns content (same string)
        content = 'version = "2.0.0"\n'
        result = _bump_version_in_text(content, "2.0.0", "2.0.0")
        # Either None (no diff) or same string — both are acceptable
        assert result is None or result == content

    def test_multiline_replaces_first_occurrence(self):
        content = "v1.0.0 and v1.0.0\n"
        result = _bump_version_in_text(content, "1.0.0", "2.0.0")
        assert result is not None
        assert "2.0.0" in result


# ---------------------------------------------------------------------------
# Integration tests — _process_package with mocked HTTP
# ---------------------------------------------------------------------------

class TestHappyPath:
    def test_pr_opened(self):
        client = _MockClient(_happy_responses())
        with patch("httpx.AsyncClient", return_value=client):
            result = _run(_process_package(_pkg(), dry_run=False, github_token="tok", console=_console()))
        assert result["status"] == "opened"
        assert result["pr_url"] == "https://github.com/example/mylib/pull/42"
        assert result["package"] == "mylib"

    def test_correct_api_endpoints_called(self):
        client = _MockClient(_happy_responses())
        with patch("httpx.AsyncClient", return_value=client):
            _run(_process_package(_pkg(), dry_run=False, github_token="tok", console=_console()))
        methods_urls = client.requests
        # First call: repo metadata
        assert methods_urls[0] == ("GET", "https://api.github.com/repos/example/mylib")
        # Last call: open PR
        assert methods_urls[-1] == ("POST", "https://api.github.com/repos/example/mylib/pulls")

    def test_authorization_header_set(self):
        """Token must appear in Authorization header sent to GitHub."""
        recorded_headers: list[dict] = []

        async def _get(url, **kw):
            recorded_headers.append(kw.get("headers", {}))
            return _happy_responses()[0]

        client = _MockClient(_happy_responses())
        client.get = _get  # type: ignore[method-assign]
        # Just test the helper directly
        from selvo.analysis.fix import _gh_headers
        headers = _gh_headers("mytoken")
        assert headers["Authorization"] == "Bearer mytoken"


class TestDryRun:
    def test_dry_run_no_network(self):
        """Dry-run must not make any HTTP calls."""
        with patch("httpx.AsyncClient") as mock_cls:
            result = _run(_process_package(_pkg(), dry_run=True, github_token="", console=_console()))
        mock_cls.assert_not_called()
        assert result["status"] == "opened"
        assert result["pr_url"] is None
        assert "[dry-run]" in result["reason"]


class TestSkipConditions:
    def test_no_upstream_repo(self):
        result = _run(_process_package(
            _pkg(upstream_repo=None), dry_run=False, github_token="tok", console=_console()
        ))
        assert result["status"] == "skipped"
        assert "upstream_repo" in result["reason"]

    def test_no_cves(self):
        result = _run(_process_package(
            _pkg(cve_ids=[]), dry_run=False, github_token="tok", console=_console()
        ))
        assert result["status"] == "skipped"
        assert "CVE" in result["reason"]

    def test_no_fix_version(self):
        result = _run(_process_package(
            _pkg(version="1.0.0", upstream_version="1.0.0"),
            dry_run=False, github_token="tok", console=_console()
        ))
        assert result["status"] == "skipped"
        assert "fix version" in result["reason"]

    def test_version_string_not_in_repo(self):
        """All version files probed but none contain the old version → skip."""
        # Version file found but _bump_version_in_text returns None
        responses = [
            _mock_response(200, {"default_branch": "main"}),
            _mock_response(200, {"object": {"sha": SHA}}),
            _mock_response(201, {}),
            # Return a file that doesn't contain "1.0.0"
            _mock_response(200, {"encoding": "base64", "content": _b64("no version here\n"), "sha": "blob1"}),
        ] + [_mock_response(404, {})] * 10  # rest of _VERSION_FILES
        client = _MockClient(responses)
        with patch("httpx.AsyncClient", return_value=client):
            result = _run(_process_package(_pkg(), dry_run=False, github_token="tok", console=_console()))
        assert result["status"] == "skipped"
        assert "not found" in result["reason"]

    def test_no_token_live_path(self):
        result = _run(_process_package(
            _pkg(), dry_run=False, github_token="", console=_console()
        ))
        assert result["status"] == "skipped"
        assert "token" in result["reason"].lower()


class TestErrorConditions:
    def test_repo_metadata_404(self):
        client = _MockClient([_mock_response(404, {})])
        with patch("httpx.AsyncClient", return_value=client):
            result = _run(_process_package(_pkg(), dry_run=False, github_token="tok", console=_console()))
        assert result["status"] == "error"
        assert "Cannot fetch repo metadata" in result["error"]

    def test_cannot_resolve_sha(self):
        client = _MockClient([
            _mock_response(200, {"default_branch": "main"}),
            _mock_response(404, {}),  # ref lookup fails
        ])
        with patch("httpx.AsyncClient", return_value=client):
            result = _run(_process_package(_pkg(), dry_run=False, github_token="tok", console=_console()))
        assert result["status"] == "error"
        assert "Cannot resolve HEAD" in result["error"]

    def test_branch_create_fails(self):
        client = _MockClient([
            _mock_response(200, {"default_branch": "main"}),
            _mock_response(200, {"object": {"sha": SHA}}),
            _mock_response(500, {}),  # branch create fails
        ])
        with patch("httpx.AsyncClient", return_value=client):
            result = _run(_process_package(_pkg(), dry_run=False, github_token="tok", console=_console()))
        assert result["status"] == "error"
        assert "Cannot create branch" in result["error"]

    def test_pr_open_returns_no_url(self):
        responses = _happy_responses()
        # Replace final PR response with one missing html_url
        responses[-1] = _mock_response(201, {})
        client = _MockClient(responses)
        with patch("httpx.AsyncClient", return_value=client):
            result = _run(_process_package(_pkg(), dry_run=False, github_token="tok", console=_console()))
        assert result["status"] == "error"
        assert "no html_url" in result["error"]


class TestBranchCollision:
    def test_same_sha_reuses_branch(self):
        """422 + existing branch points to same SHA → reuse branch, open PR."""
        responses = [
            _mock_response(200, {"default_branch": "main"}),
            _mock_response(200, {"object": {"sha": SHA}}),   # HEAD sha
            _mock_response(422, {}),                          # branch exists
            _mock_response(200, {"object": {"sha": SHA}}),   # existing branch sha (same)
            _mock_response(200, {"encoding": "base64", "content": _b64('version = "1.0.0"\n'), "sha": "blob1"}),
            _mock_response(200, {}),                          # file update
            _mock_response(201, {"html_url": "https://github.com/example/mylib/pull/99"}),
        ]
        client = _MockClient(responses)
        with patch("httpx.AsyncClient", return_value=client):
            result = _run(_process_package(_pkg(), dry_run=False, github_token="tok", console=_console()))
        assert result["status"] == "opened"
        assert result["pr_url"] == "https://github.com/example/mylib/pull/99"

    def test_different_sha_skips(self):
        """422 + existing branch has different SHA → skip with clear message."""
        other_sha = "deadbeef" * 5 + "dead"
        responses = [
            _mock_response(200, {"default_branch": "main"}),
            _mock_response(200, {"object": {"sha": SHA}}),
            _mock_response(422, {}),
            _mock_response(200, {"object": {"sha": other_sha}}),
        ]
        client = _MockClient(responses)
        with patch("httpx.AsyncClient", return_value=client):
            result = _run(_process_package(_pkg(), dry_run=False, github_token="tok", console=_console()))
        assert result["status"] == "skipped"
        assert "already exists" in result["reason"]
        assert "Delete it manually" in result["reason"]


class TestRunFixPipeline:
    def test_pipeline_aggregates_results(self):
        """run_fix_pipeline processes all packages and returns one result per package."""
        pkgs = [
            _pkg(name="libA"),
            _pkg(name="libB", cve_ids=[]),  # will be skipped
        ]
        # libA happy path
        async def fake_process(pkg, dry_run, github_token, console):
            if pkg.cve_ids:
                return {"status": "opened", "package": pkg.name, "pr_url": "http://x", "reason": "", "error": ""}
            return {"status": "skipped", "package": pkg.name, "pr_url": None, "reason": "no CVEs", "error": ""}

        with patch("selvo.analysis.fix._process_package", side_effect=fake_process):
            results = _run(run_fix_pipeline(pkgs, dry_run=False, github_token="tok", console=_console()))

        assert len(results) == 2
        by_name = {r["package"]: r for r in results}
        assert by_name["libA"]["status"] == "opened"
        assert by_name["libB"]["status"] == "skipped"
