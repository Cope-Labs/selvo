"""Tests for selvo.analysis.slsa — SLSA attestation verifier."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

from tests.conftest import make_pkg


# ---------------------------------------------------------------------------
# _infer_slsa_level
# ---------------------------------------------------------------------------

def test_infer_level_zero_no_entries():
    """No Rekor entries → SLSA level 0, not verified."""
    from selvo.analysis.slsa import _infer_slsa_level
    level, builder, verified, source_ref = _infer_slsa_level([])
    assert level == 0
    assert verified is False
    assert builder == ""


def test_infer_level_one_unknown_builder():
    """Entry present but unrecognised builder → level 1, not verified."""
    from selvo.analysis.slsa import _infer_slsa_level

    entries = [{"body": {"spec": {"content": {"predicate": {
        "builder": {"id": "https://unknown.example.com/builder"},
    }}}}}]
    level, builder, verified, _ = _infer_slsa_level(entries)
    assert level == 1
    assert verified is False


def test_infer_level_two_github_actions():
    """GitHub Actions builder → level 2, verified."""
    from selvo.analysis.slsa import _infer_slsa_level

    entries = [{"body": {"spec": {"content": {"predicate": {
        "builder": {"id": "https://github.com/actions/runner"},
    }}}}}]
    level, builder, verified, _ = _infer_slsa_level(entries)
    assert level == 2
    assert verified is True


def test_infer_level_three_slsa_generator():
    """SLSA GitHub Generator → level 3, verified."""
    from selvo.analysis.slsa import _infer_slsa_level

    entries = [{"body": {"spec": {"content": {"predicate": {
        "builder": {"id": "https://github.com/slsa-framework/slsa-github-generator"},
    }}}}}]
    level, builder, verified, _ = _infer_slsa_level(entries)
    assert level == 3
    assert verified is True
    assert "slsa-framework" in builder


def test_infer_picks_highest_level():
    """When multiple entries are present the highest level wins."""
    from selvo.analysis.slsa import _infer_slsa_level

    entries = [
        {"body": {"spec": {"content": {"predicate": {
            "builder": {"id": "https://unknown.example.com/x"},
        }}}}},
        {"body": {"spec": {"content": {"predicate": {
            "builder": {"id": "https://github.com/slsa-framework/slsa-github-generator"},
        }}}}},
    ]
    level, _, verified, _ = _infer_slsa_level(entries)
    assert level == 3
    assert verified is True


# ---------------------------------------------------------------------------
# _repo_subject_candidates
# ---------------------------------------------------------------------------

def test_repo_subject_candidates_github():
    """GitHub URL produces three candidate subjects."""
    from selvo.analysis.slsa import _repo_subject_candidates
    candidates = _repo_subject_candidates("https://github.com/openssl/openssl")
    assert any("github.com/openssl/openssl" in c for c in candidates)
    assert any("api.github.com" in c for c in candidates)


def test_repo_subject_candidates_non_github():
    """Non-GitHub URL has at least the bare URL as a candidate."""
    from selvo.analysis.slsa import _repo_subject_candidates
    candidates = _repo_subject_candidates("https://gitlab.com/some/repo")
    assert len(candidates) >= 1
    assert candidates[0].startswith("https://gitlab.com")


# ---------------------------------------------------------------------------
# enrich_slsa (mocked network)
# ---------------------------------------------------------------------------


def test_enrich_slsa_no_upstream_repo():
    """Packages without upstream_repo are skipped (no Rekor call)."""
    from selvo.analysis.slsa import enrich_slsa
    pkg = make_pkg(name="bash", upstream_repo=None)
    result = asyncio.run(enrich_slsa([pkg]))
    assert result[0].slsa_level == 0
    assert result[0].slsa_verified is False


def test_enrich_slsa_sets_fields():
    """enrich_slsa correctly sets fields from Rekor response."""
    from selvo.analysis.slsa import enrich_slsa

    pkg = make_pkg(name="openssl", upstream_repo="https://github.com/openssl/openssl")

    # Patch _search_rekor to return a L2 entry without network
    mock_entries = [{"body": {"spec": {"content": {"predicate": {
        "builder": {"id": "https://github.com/actions/runner"},
        "materials": [{"uri": "https://github.com/openssl/openssl"}],
    }}}}}]

    with patch("selvo.analysis.slsa._search_rekor", new=AsyncMock(return_value=mock_entries)):
        result = asyncio.run(enrich_slsa([pkg]))

    assert result[0].slsa_level == 2
    assert result[0].slsa_verified is True
    assert "actions/runner" in result[0].slsa_builder


def test_enrich_slsa_rekor_failure_graceful():
    """Rekor errors don't crash the pipeline — package stays at level 0."""
    from selvo.analysis.slsa import enrich_slsa

    pkg = make_pkg(name="curl", upstream_repo="https://github.com/curl/curl")

    with patch("selvo.analysis.slsa._search_rekor", new=AsyncMock(side_effect=Exception("network error"))):
        result = asyncio.run(enrich_slsa([pkg]))

    assert result[0].slsa_level == 0


# ---------------------------------------------------------------------------
# check_policy_slsa
# ---------------------------------------------------------------------------

def test_check_policy_slsa_passes():
    """No packages returned when all meet the minimum level."""
    from selvo.analysis.slsa import check_policy_slsa
    pkg = make_pkg(name="openssl", upstream_repo="https://github.com/openssl/openssl")
    pkg.slsa_level = 2  # type: ignore[attr-defined]
    pkg.slsa_verified = True  # type: ignore[attr-defined]
    failing = check_policy_slsa([pkg], min_level=2)
    assert failing == []


def test_check_policy_slsa_fails():
    """Packages below minimum level are returned."""
    from selvo.analysis.slsa import check_policy_slsa
    pkg = make_pkg(name="curl", upstream_repo="https://github.com/curl/curl")
    pkg.slsa_level = 1  # type: ignore[attr-defined]
    failing = check_policy_slsa([pkg], min_level=2)
    assert len(failing) == 1
    assert failing[0].name == "curl"


def test_check_policy_slsa_no_repo_excluded():
    """Packages without upstream_repo are excluded from the gate."""
    from selvo.analysis.slsa import check_policy_slsa
    pkg = make_pkg(name="bash", upstream_repo=None)
    pkg.slsa_level = 0  # type: ignore[attr-defined]
    failing = check_policy_slsa([pkg], min_level=2)
    assert failing == []
