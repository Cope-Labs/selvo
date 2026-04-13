"""Tests for WinGet, Homebrew, and Chocolatey discovery modules.

These tests verify fallback behavior and basic structure of discovered
packages without requiring external network access.
"""
from __future__ import annotations

import pytest

from selvo.discovery.base import PackageRecord
from selvo.discovery.winget import WinGetDiscovery
from selvo.discovery.homebrew import HomebrewDiscovery
from selvo.discovery.chocolatey import ChocolateyDiscovery


# ---------------------------------------------------------------------------
# WinGet
# ---------------------------------------------------------------------------

class TestWinGetDiscovery:
    def setup_method(self):
        self.disco = WinGetDiscovery()

    def test_ecosystem_tag(self):
        assert self.disco.ecosystem == "winget"

    def test_fallback_returns_package_records(self):
        results = self.disco._fallback(10)
        assert len(results) == 10
        for pkg in results:
            assert isinstance(pkg, PackageRecord)
            assert pkg.ecosystem == "winget"
            assert pkg.name

    def test_fallback_respects_limit(self):
        results = self.disco._fallback(5)
        assert len(results) == 5

    def test_fallback_limit_larger_than_curated_list(self):
        # Should not raise; returns however many curated entries exist
        results = self.disco._fallback(1000)
        assert len(results) > 0
        assert all(isinstance(p, PackageRecord) for p in results)

    @pytest.mark.asyncio
    async def test_fetch_top_falls_back_on_network_error(self, monkeypatch):
        """When the API is unreachable, fetch_top returns curated fallback."""

        async def bad_api(self, limit):
            return []

        monkeypatch.setattr(WinGetDiscovery, "_fetch_from_api", bad_api)

        disco = WinGetDiscovery()
        results = await disco.fetch_top(5)
        assert len(results) == 5
        assert all(p.ecosystem == "winget" for p in results)

    @pytest.mark.asyncio
    async def test_fetch_top_prefers_api_results(self, monkeypatch):
        """When the API returns data, curated fallback is not used."""
        stub_pkgs = [
            PackageRecord(name="stub.Package", ecosystem="winget", version="1.0")
        ]

        async def good_api(self, limit):
            return stub_pkgs

        monkeypatch.setattr(WinGetDiscovery, "_fetch_from_api", good_api)

        disco = WinGetDiscovery()
        results = await disco.fetch_top(5)
        assert results == stub_pkgs


# ---------------------------------------------------------------------------
# Homebrew
# ---------------------------------------------------------------------------

class TestHomebrewDiscovery:
    def setup_method(self):
        self.disco = HomebrewDiscovery()

    def test_ecosystem_tag(self):
        assert self.disco.ecosystem == "homebrew"

    def test_fallback_returns_package_records(self):
        results = self.disco._fallback(10)
        assert len(results) == 10
        for pkg in results:
            assert isinstance(pkg, PackageRecord)
            assert pkg.ecosystem == "homebrew"
            assert pkg.name

    def test_fallback_respects_limit(self):
        results = self.disco._fallback(3)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_fetch_top_falls_back_on_network_error(self, monkeypatch):
        async def bad_api(self, limit):
            return []

        monkeypatch.setattr(HomebrewDiscovery, "_fetch_from_api", bad_api)

        disco = HomebrewDiscovery()
        results = await disco.fetch_top(5)
        assert len(results) == 5
        assert all(p.ecosystem == "homebrew" for p in results)

    @pytest.mark.asyncio
    async def test_fetch_top_prefers_api_results(self, monkeypatch):
        stub_pkgs = [
            PackageRecord(name="openssl", ecosystem="homebrew", version="3.3.0")
        ]

        async def good_api(self, limit):
            return stub_pkgs

        monkeypatch.setattr(HomebrewDiscovery, "_fetch_from_api", good_api)

        disco = HomebrewDiscovery()
        results = await disco.fetch_top(5)
        assert results == stub_pkgs


# ---------------------------------------------------------------------------
# Chocolatey
# ---------------------------------------------------------------------------

class TestChocolateyDiscovery:
    def setup_method(self):
        self.disco = ChocolateyDiscovery()

    def test_ecosystem_tag(self):
        assert self.disco.ecosystem == "chocolatey"

    def test_fallback_returns_package_records(self):
        results = self.disco._fallback(10)
        assert len(results) == 10
        for pkg in results:
            assert isinstance(pkg, PackageRecord)
            assert pkg.ecosystem == "chocolatey"
            assert pkg.name

    def test_fallback_respects_limit(self):
        results = self.disco._fallback(4)
        assert len(results) == 4

    @pytest.mark.asyncio
    async def test_fetch_top_falls_back_on_network_error(self, monkeypatch):
        async def bad_api(self, limit):
            return []

        monkeypatch.setattr(ChocolateyDiscovery, "_fetch_from_api", bad_api)

        disco = ChocolateyDiscovery()
        results = await disco.fetch_top(5)
        assert len(results) == 5
        assert all(p.ecosystem == "chocolatey" for p in results)

    @pytest.mark.asyncio
    async def test_fetch_top_prefers_api_results(self, monkeypatch):
        stub_pkgs = [
            PackageRecord(name="git", ecosystem="chocolatey", version="2.44.0")
        ]

        async def good_api(self, limit):
            return stub_pkgs

        monkeypatch.setattr(ChocolateyDiscovery, "_fetch_from_api", good_api)

        disco = ChocolateyDiscovery()
        results = await disco.fetch_top(5)
        assert results == stub_pkgs


# ---------------------------------------------------------------------------
# Ecosystem registration
# ---------------------------------------------------------------------------

def test_ecosystems_registered_in_init():
    """All three new ecosystems are registered in the discovery map."""
    from selvo.discovery import _ECOSYSTEM_MAP

    assert "winget" in _ECOSYSTEM_MAP
    assert "homebrew" in _ECOSYSTEM_MAP
    assert "chocolatey" in _ECOSYSTEM_MAP
    assert "all-endpoints" in _ECOSYSTEM_MAP

    assert WinGetDiscovery in _ECOSYSTEM_MAP["winget"]
    assert HomebrewDiscovery in _ECOSYSTEM_MAP["homebrew"]
    assert ChocolateyDiscovery in _ECOSYSTEM_MAP["chocolatey"]

    all_ep = _ECOSYSTEM_MAP["all-endpoints"]
    assert WinGetDiscovery in all_ep
    assert HomebrewDiscovery in all_ep
    assert ChocolateyDiscovery in all_ep
