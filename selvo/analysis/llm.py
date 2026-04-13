"""OpenRouter LLM client — cheapest-model-first, optional enrichment."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import httpx

_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Ordered cheapest → capable; first that works is used
_MODEL_PREFERENCE = [
    "google/gemma-3-1b-it:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "mistralai/mistral-7b-instruct:free",
]


def _load_key() -> Optional[str]:
    """Read OPENROUTER_API_KEY from env or .env file."""
    key = os.environ.get("OPENROUTER_API_KEY")
    if key:
        return key
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line.startswith("OPENROUTER_API_KEY="):
                return line.split("=", 1)[1].strip()
    return None


class LLMClient:
    """Thin async wrapper around OpenRouter's chat completion API."""

    def __init__(self) -> None:
        self.api_key = _load_key()
        self.enabled = bool(self.api_key)

    async def complete(self, prompt: str, system: str = "", model: Optional[str] = None) -> str:
        """Send a prompt and return the response text. Returns '' on failure."""
        if not self.enabled:
            return ""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/selvo",
            "X-Title": "selvo",
        }
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        models = [model] if model else _MODEL_PREFERENCE
        async with httpx.AsyncClient(timeout=20.0) as client:
            for m in models:
                try:
                    resp = await client.post(
                        _OPENROUTER_URL,
                        headers=headers,
                        json={"model": m, "messages": messages, "max_tokens": 512},
                    )
                    if resp.status_code == 200:
                        return resp.json()["choices"][0]["message"]["content"].strip()
                except Exception:
                    continue
        return ""

    async def normalize_package_names(self, packages: list[tuple[str, str]]) -> dict[str, str]:
        """
        Given [(name, ecosystem), ...], return {distro_pkg_name: canonical_upstream_name} for
        packages that are known cross-ecosystem aliases (e.g. libc6 → glibc).
        Returns empty dict when LLM unavailable.
        """
        if not self.enabled:
            return {}
        items = "\n".join(f"- package_name={name}, ecosystem={eco}" for name, eco in packages)
        prompt = (
            "You are a Linux package expert. For each entry below, if the distro package name "
            "differs from the canonical upstream project name, map it. "
            "Examples: libc6→glibc, libssl3→openssl, openssl-libs→openssl, gcc-libs→gcc, "
            "libstdc++6→gcc, zlib1g→zlib.\n"
            "Reply ONLY with a valid JSON object where keys are the exact package_name values "
            "from the list and values are the canonical upstream names. "
            "Omit entries where distro name and upstream name are the same.\n\n"
            f"{items}"
        )
        raw = await self.complete(prompt, system="Reply only with valid JSON, no markdown fences.")
        try:
            raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            return json.loads(raw)
        except Exception:
            return {}

    async def classify_fix_refs(self, urls: list[str]) -> dict[str, str]:
        """
        Classify a list of URLs as FIX | REPORT | INFO.
        Returns {url: classification}. Falls back to empty dict.
        """
        if not self.enabled or not urls:
            return {}
        items = "\n".join(f"- {u}" for u in urls[:20])
        prompt = (
            "Classify each URL as one of: FIX (a commit, PR, or patch that fixes a bug/CVE), "
            "REPORT (a bug report or issue tracker), or INFO (documentation/announcement). "
            "Reply ONLY with a JSON object mapping url → classification.\n\n"
            f"{items}"
        )
        raw = await self.complete(prompt, system="Reply only with valid JSON, no markdown.")
        try:
            raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            return json.loads(raw)
        except Exception:
            return {}

    async def generate_pr_description(
        self,
        package: str,
        ecosystem: str,
        current_version: str,
        upstream_version: str,
        cve_ids: list[str],
        fix_urls: list[str],
        downstream_count: int,
    ) -> str:
        """Generate a ready-to-paste PR/bug-report description."""
        if not self.enabled:
            return ""
        prompt = (
            f"Write a concise, professional upstream PR or distro bug report description for:\n"
            f"- Package: {package} ({ecosystem})\n"
            f"- Current distro version: {current_version}\n"
            f"- Upstream version: {upstream_version}\n"
            f"- CVEs addressed: {', '.join(cve_ids[:5]) or 'none listed'}\n"
            f"- Fix references: {chr(10).join(fix_urls[:3]) or 'none'}\n"
            f"- Packages that would benefit from this update: {downstream_count}\n\n"
            "Include: summary, motivation (CVEs + downstream impact), fix references, request for update. "
            "Keep it under 200 words."
        )
        return await self.complete(prompt, system="Write clear, concise technical prose. No fluff.")


    async def generate_backport_patch(
        self,
        package: str,
        cve_id: str,
        fix_url: str,
        diff_snippet: str,
    ) -> str:
        """
        Given a fix commit diff and context, generate backport instructions.
        diff_snippet should be the first ~3000 chars of the upstream patch.
        """
        if not self.enabled:
            return ""
        prompt = (
            f"A Linux package needs a CVE backport.\n"
            f"Package: {package}\n"
            f"CVE: {cve_id}\n"
            f"Upstream fix: {fix_url}\n\n"
            f"Upstream patch diff (truncated):\n```diff\n{diff_snippet[:3000]}\n```\n\n"
            "Write concise backport instructions for a distro maintainer: what changed, "
            "what to watch for when applying to an older version, and the minimum set of "
            "hunks needed. Keep it under 250 words."
        )
        return await self.complete(
            prompt,
            system="You are a Linux distro security engineer. Be concise and technical.",
        )


# Module-level singleton
_client: Optional[LLMClient] = None


def get_client() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient()
    return _client
