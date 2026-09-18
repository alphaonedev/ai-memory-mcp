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
from typing import Any, TypedDict

# #3544 — the ONE success predicate, byte-identical in both shim
# packages and pinned as such by tests/test_capture_outcome_parity.py.
from ._capture_outcome import classify_capture_response

_SHIM_NAME = "ai-memory-openai-shim"
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
    """Record one turn to ai-memory.

    Returns ``True`` ONLY when the substrate confirms the turn was
    **persisted** — that is, when the ``memory_capture_turn`` envelope carries
    a non-empty ``memory_id`` (``src/mcp/tools/capture_turn.rs:531-547``; the
    same field RFC-0001 lists in the tool result's ``required`` set). Returns
    ``False`` for everything else and names the reason on stderr:

    * ``status=ask`` — governance asked for approval; **nothing was persisted**
      and there is no recovery handle (``capture_turn.rs:437-444``).
    * ``status=pending`` — the write is **durably queued, not lost**; the
      ``pending_id`` is printed so you can redeem the turn with
      ``memory_pending_approve`` (``capture_turn.rs:488-496``).
    * a transport fault, an unreadable payload, or any envelope this shim does
      not recognise — it fails CLOSED rather than claim a success it cannot
      prove.

    NEVER raises: every failure path emits a stderr WARN and returns ``False``
    so the caller's LLM call is never disturbed.
    """
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
        print(f"WARN {_SHIM_NAME}: binary not found: {bin_path}", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print(f"WARN {_SHIM_NAME}: capture timed out (30s)", file=sys.stderr)
        return False
    except OSError as e:  # pragma: no cover - defensive
        print(f"WARN {_SHIM_NAME}: capture spawn failed: {e}", file=sys.stderr)
        return False

    if result.returncode != 0:
        print(f"WARN {_SHIM_NAME}: substrate exited {result.returncode}", file=sys.stderr)
        return False
    resp = _pick_call_response(result.stdout)
    # #3544 — ONE predicate decides this, shared byte-identically with the
    # sibling shim package: a turn is captured IFF the tool payload carries a
    # non-empty `memory_id`. The pre-fix code was the ABSENCE form (success
    # unless the response matched an enumerated failure), so an unreadable
    # payload, an empty object, or a `status` a later substrate release adds
    # was reported to the caller as a captured turn that was never stored.
    # Governance `ask` (nothing persisted, no handle) and `pending` (durably
    # QUEUED and redeemable via memory_pending_approve, carrying the only id
    # that redeems it) are each surfaced as what they are; anything the
    # predicate does not recognise fails CLOSED.
    outcome = classify_capture_response(resp)
    if not outcome.captured:
        print(f"WARN {_SHIM_NAME}: {outcome.detail}", file=sys.stderr)
    return outcome.captured


class _CaptureDurability(TypedDict):
    durability_class: str
    fsync: str


class CaptureTurnReceipt(_CaptureDurability, total=False):
    """#3555 MCP capture or pending-approval receipt."""

    memory_id: str
    dedup_hit: bool
    status: str
    pending_id: str
    quorum_acks: int
    quorum_n: int
