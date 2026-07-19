# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Internal turn-capture transport for the ai-memory OpenAI shim.

Records one turn to ai-memory by spawning ``ai-memory mcp --profile full``
and calling the ``memory_capture_turn`` MCP tool per RFC-0001
(``docs/rfc/RFC-0001-mcp-turn-capture.md``). Importable port of the reference
host-adapter shim (``clients/host-adapter-shim/python/capture_turn.py``).

**Non-wedging invariant:** every function here is total — it NEVER raises. A
capture failure emits a stderr WARN and returns ``False`` so the caller's LLM
call is never disturbed.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

_ENV_BIN = "AI_MEMORY_BIN"
_DEFAULT_BIN = "ai-memory"
_CAPTURE_TIMEOUT_SECS = 30
_CALL_ID = 2


def _frames(capture_request: dict[str, Any]) -> str:
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "ai-memory-openai-shim-py", "version": "0.1"},
        },
    }
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    call = {
        "jsonrpc": "2.0",
        "id": _CALL_ID,
        "method": "tools/call",
        "params": {"name": "memory_capture_turn", "arguments": capture_request},
    }
    return "\n".join(json.dumps(o) for o in (init, initialized, call)) + "\n"


def _pick_call_response(stdout_text: str) -> dict[str, Any] | None:
    for line in stdout_text.splitlines():
        trimmed = line.strip()
        if not trimmed.startswith("{"):
            continue
        try:
            obj = json.loads(trimmed)
        except json.JSONDecodeError:
            continue
        if obj.get("id") == _CALL_ID:
            return obj
    return None


def build_capture_request(
    *,
    host_session_id: str,
    host_turn_index: int,
    role: str,
    content: str,
    namespace: str | None = None,
    host_kind: str | None = None,
    host_version: str | None = None,
    timestamp_iso: str | None = None,
) -> dict[str, Any]:
    """Assemble the ``memory_capture_turn`` argument object (pure)."""
    req: dict[str, Any] = {
        "host_session_id": host_session_id,
        "host_turn_index": host_turn_index,
        "role": role,
        "content": content,
    }
    if namespace:
        req["namespace"] = namespace
    if host_kind:
        req["host_kind"] = host_kind
    if host_version:
        req["host_version"] = host_version
    if timestamp_iso:
        req["timestamp_iso"] = timestamp_iso
    return req


def capture_turn(
    *,
    host_session_id: str,
    host_turn_index: int,
    role: str,
    content: str,
    namespace: str | None = None,
    host_kind: str | None = None,
    host_version: str | None = None,
    timestamp_iso: str | None = None,
    ai_memory_bin: str | None = None,
) -> bool:
    """Record one turn to ai-memory. Returns ``True`` on success. NEVER raises."""
    bin_path = ai_memory_bin or os.environ.get(_ENV_BIN, _DEFAULT_BIN)
    request = build_capture_request(
        host_session_id=host_session_id,
        host_turn_index=host_turn_index,
        role=role,
        content=content,
        namespace=namespace,
        host_kind=host_kind,
        host_version=host_version,
        timestamp_iso=timestamp_iso,
    )
    frames = _frames(request)
    try:
        result = subprocess.run(
            [bin_path, "mcp", "--profile", "full"],
            input=frames,
            capture_output=True,
            text=True,
            check=False,
            timeout=_CAPTURE_TIMEOUT_SECS,
        )
    except FileNotFoundError:
        print(f"WARN ai-memory-openai-shim: binary not found: {bin_path}", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print("WARN ai-memory-openai-shim: capture timed out (30s)", file=sys.stderr)
        return False
    except OSError as e:  # pragma: no cover - defensive
        print(f"WARN ai-memory-openai-shim: capture spawn failed: {e}", file=sys.stderr)
        return False

    if result.returncode != 0:
        print(f"WARN ai-memory-openai-shim: substrate exited {result.returncode}", file=sys.stderr)
        return False
    resp = _pick_call_response(result.stdout)
    if resp is None:
        print("WARN ai-memory-openai-shim: no capture response from substrate", file=sys.stderr)
        return False
    # A top-level JSON-RPC `error` member (e.g. an unknown-method / invalid-params
    # fault) is a FAILURE, not a success — it carries no `result`, so it would
    # otherwise slip past the `isError` check below and be mis-counted as a
    # captured turn. Screen it before the tool-level `isError` branch.
    if resp.get("error") is not None:
        print("WARN ai-memory-openai-shim: substrate returned JSON-RPC error", file=sys.stderr)
        return False
    if isinstance(resp.get("result"), dict) and resp["result"].get("isError") is True:
        print("WARN ai-memory-openai-shim: substrate returned isError:true", file=sys.stderr)
        return False
    return True
