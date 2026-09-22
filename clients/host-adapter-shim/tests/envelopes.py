# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""SSOT for the `memory_capture_turn` receipt vocabulary the trio must agree on.

Every envelope below is copied from the substrate — `src/mcp/tools/capture_turn.rs`
— not invented here:

* ``:437-444``  permission ``Decision::Ask``   -> ``{"status": "ask", "reason",
  "action", "namespace"}``. NOTHING is persisted; no id, no recovery handle.
* ``:488-496``  ``GovernanceDecision::Pending`` -> ``{"status": "pending",
  "pending_id", "reason", "action", "namespace"}``. DURABLY QUEUED, redeemable
  with ``memory_pending_approve``.
* ``:531-538``  dedup hit   -> ``{"memory_id", "dedup_hit": true, "layer": "L4",
  ...}`` — no ``status`` key at all.
* ``:539-547``  fresh write -> ``{"memory_id", "dedup_hit": false, "layer":
  "L4", ...}`` — no ``status`` key at all.

``grep -n '"status"' src/mcp/tools/capture_turn.rs`` returns exactly ``:439``
and ``:490``: that is the WHOLE closed vocabulary. ``Decision::Deny`` /
``GovernanceDecision::Deny`` return ``Err(..)``, which the MCP layer renders as
``isError: true`` (``src/mcp/mod.rs``), never as a ``status``. RFC-0001 pins
``memory_id`` in the tool result's ``required`` set
(``docs/rfc/RFC-0001-mcp-turn-capture.md:160``).

#3544 — the predicate the three adapters implement, and that this module's
table pins:

    a turn is CAPTURED if and only if the tool payload carries a
    non-empty string ``memory_id``.

``status`` is read only to say WHY and to carry the recovery handle, so a
status a later substrate release grows fails CLOSED without any adapter having
to know it exists.
"""
from __future__ import annotations

import json
from typing import Any

# ── the substrate's closed status vocabulary ──────────────────────────────
KNOWN_STATUSES = frozenset({"ask", "pending"})

PENDING_APPROVE_TOOL = "memory_pending_approve"

# ── payloads ──────────────────────────────────────────────────────────────
PERSISTED_PAYLOAD: dict[str, Any] = {
    "memory_id": "11111111-2222-3333-4444-555555555555",
    "dedup_hit": False,
    "layer": "L4",
    "agent_id": "tester",
    "attest_level": "none",
    "elapsed_ms": 3,
}

DEDUP_PAYLOAD: dict[str, Any] = {
    "memory_id": "66666666-7777-8888-9999-000000000000",
    "dedup_hit": True,
    "layer": "L4",
    "agent_id": "tester",
    "elapsed_ms": 1,
}

ASK_PAYLOAD: dict[str, Any] = {
    "status": "ask",
    "reason": "rule requires confirmation",
    "action": "capture_turn",
    "namespace": "default",
}

PENDING_ID = "pend-abc123"
PENDING_PAYLOAD: dict[str, Any] = {
    "status": "pending",
    "pending_id": PENDING_ID,
    "reason": "governance requires approval",
    "action": "capture_turn",
    "namespace": "default",
}

UNKNOWN_STATUS_PAYLOAD: dict[str, Any] = {
    "status": "quarantined",
    "reason": "a status this release has never seen",
}

NO_MEMORY_ID_PAYLOAD: dict[str, Any] = {"dedup_hit": False, "layer": "L4"}

BLANK_MEMORY_ID_PAYLOAD: dict[str, Any] = {
    "memory_id": "",
    "dedup_hit": False,
    "layer": "L4",
}

# ── the exact stderr detail each adapter must emit ────────────────────────
# Byte-identical across python / node / bash: that identity is what makes the
# three implementations ONE predicate rather than three lookalikes.
DETAIL_ASK = (
    "capture_turn returned status=ask (governance approval requested; "
    "NOTHING was persisted and there is no recovery handle); "
    "not counting as a captured turn"
)
DETAIL_PENDING = (
    f"capture_turn returned status=pending, pending_id={json.dumps(PENDING_ID)} "
    f"(the turn is DURABLY QUEUED for approval, NOT lost; redeem it with "
    f"{PENDING_APPROVE_TOOL}); not counting as a captured turn"
)
DETAIL_UNREADABLE = (
    "capture result payload was unreadable "
    "(result.content[0].text is not a JSON object); "
    "refusing to count it as a captured turn"
)
DETAIL_IS_ERROR = "substrate returned isError:true"
#: No frame carried the tools/call id — nothing proves a row exists.
DETAIL_NO_FRAME = "no capture response from substrate"


def detail_no_memory_id(status: Any) -> str:
    """The fail-closed message for any payload that proves nothing was stored."""
    return (
        f"capture_turn returned no memory_id (status={json.dumps(status)}); "
        "the turn was NOT persisted - not counting as a captured turn"
    )


# ── wire helpers ──────────────────────────────────────────────────────────
def tool_result_line(payload: Any) -> str:
    """One JSON-RPC tools/call response line carrying `payload` as the result.

    Mirrors the one level of JSON nesting the MCP layer adds:
    `src/mcp/mod.rs:3762` serialises the handler value with
    `serde_json::to_string_pretty` into `result.content[0].text`.
    """
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [{"type": "text", "text": json.dumps(payload, indent=2)}]
            },
        }
    )


def raw_text_line(text: str) -> str:
    """A tools/call response whose `text` is not a JSON object at all."""
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"content": [{"type": "text", "text": text}]},
        }
    )


IS_ERROR_LINE = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "isError": True,
            "content": [{"type": "text", "text": "refused"}],
        },
    }
)

INIT_LINE = json.dumps(
    {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-03-26"}}
)

# ── the conformance table ─────────────────────────────────────────────────
# (case id, tools/call response line, expected exit code, expected stderr detail)
#
# The six cells the #3544 acceptance asks for are here in order — persisted
# (the allowed-path control), dedup hit, ask, pending, unknown status,
# unreadable payload — plus the two payload shapes that carry no provable id
# and the MCP error envelope.
CASES: list[tuple[str, str, int, str]] = [
    ("persisted", tool_result_line(PERSISTED_PAYLOAD), 0, ""),
    ("dedup_hit", tool_result_line(DEDUP_PAYLOAD), 0, ""),
    ("ask", tool_result_line(ASK_PAYLOAD), 2, DETAIL_ASK),
    ("pending", tool_result_line(PENDING_PAYLOAD), 2, DETAIL_PENDING),
    (
        "unknown_status",
        tool_result_line(UNKNOWN_STATUS_PAYLOAD),
        2,
        detail_no_memory_id("quarantined"),
    ),
    ("unreadable_payload", raw_text_line("ok"), 2, DETAIL_UNREADABLE),
    (
        "no_memory_id",
        tool_result_line(NO_MEMORY_ID_PAYLOAD),
        2,
        detail_no_memory_id(None),
    ),
    (
        "blank_memory_id",
        tool_result_line(BLANK_MEMORY_ID_PAYLOAD),
        2,
        detail_no_memory_id(None),
    ),
    ("is_error", IS_ERROR_LINE, 2, DETAIL_IS_ERROR),
]
