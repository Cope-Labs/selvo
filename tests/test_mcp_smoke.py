"""Smoke test: spawn selvo-mcp over stdio, complete the JSON-RPC handshake,
and assert the tool surface looks right.

This catches regressions like:
- selvo-mcp entry point broken
- MCP SDK version drift breaking initialize
- A tool getting accidentally renamed or dropped from the registry
- Fast-failing imports inside the server module

Heavyweight tool calls (analyze_packages, check_local_risk) are NOT exercised
here — they hit the network and the local package manager, neither of which
belong in CI. tests/test_mcp_tools.py would be the place for that, gated
behind an opt-in marker.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time

import pytest

# Ground-truth list of MCP tools selvo advertises. Updating this is the right
# friction surface — if a tool is renamed or removed, the registry entry +
# downstream MCP clients all need to know, so the test failing here forces
# the conversation.
EXPECTED_TOOLS = {
    "analyze_packages",
    "get_snapshot",
    "check_local_risk",
    "check_runtime_risk",
    "describe_package",
}


def _drain(proc: subprocess.Popen, want_id: int, timeout: float = 10.0) -> dict | None:
    """Read JSON-RPC frames from stdout until we see one with the matching id."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            return None
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == want_id:
            return msg
    return None


@pytest.mark.skipif(
    shutil.which("selvo-mcp") is None,
    reason="selvo-mcp entry point not installed",
)
def test_selvo_mcp_handshake_and_tool_list() -> None:
    proc = subprocess.Popen(
        ["selvo-mcp", "--transport", "stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    try:
        # initialize
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "smoke-test", "version": "1.0"},
            },
        }) + "\n")
        proc.stdin.flush()
        init = _drain(proc, want_id=1)
        assert init is not None, "initialize returned no response within timeout"
        assert init.get("result", {}).get("serverInfo", {}).get("name") == "selvo"

        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }) + "\n")
        proc.stdin.flush()

        # tools/list
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        }) + "\n")
        proc.stdin.flush()
        listing = _drain(proc, want_id=2)
        assert listing is not None, "tools/list returned no response within timeout"

        names = {t["name"] for t in listing["result"]["tools"]}
        missing = EXPECTED_TOOLS - names
        assert not missing, f"selvo-mcp dropped expected tools: {missing}"

        # We've shipped 16 tools historically; assert the floor isn't quietly
        # eroded. Bump this if/when the surface intentionally shrinks.
        assert len(names) >= 16, f"tool count regressed: {len(names)} < 16"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
