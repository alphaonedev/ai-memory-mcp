# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Shared capture-outcome predicate for the ai-memory Direct-API Python shims.

**This file is byte-identical in `ai_memory_openai_shim` and
`ai_memory_anthropic_shim`** and is pinned as such by
`tests/test_capture_outcome_parity.py` in BOTH packages: the two published
wheels must not be able to disagree about what "captured" means. It carries
no shim-specific text for that reason — the caller supplies its own WARN
prefix and prints `CaptureOutcome.detail`. (The packages declare
`dependencies = []` and are published independently to PyPI, so a shared
third package would add a runtime dependency to both; one vendored source
plus a byte-identity pin is the single-predicate form that keeps each wheel
self-contained.)

#3544 — the pre-fix predicate was the ABSENCE form: a response was counted
as a captured turn unless it matched one of the failure shapes the author had
enumerated (JSON-RPC `error`, `isError: true`, and later `status` in
{ask, pending}). Anything unenumerated — an unreadable payload, an empty
object, a `status` the substrate grows in a later release — was reported to
the caller as success for a turn that was never stored.

This module is the PRESENCE form, and it is the whole predicate:

    a turn is CAPTURED if and only if the tool payload carries a
    non-empty string `memory_id`.

Everything else is not a captured turn, and `status` is read only to say WHY
and to carry the recovery handle — never to decide the verdict. An
unrecognised status therefore fails CLOSED (`NOT_CAPTURED`) without this file
having to know it exists.

Envelope vocabulary (the substrate is the source of truth; measured at
`src/mcp/tools/capture_turn.rs`, base 436459898):

* `:437-444`  permission `Decision::Ask`  -> `{"status": "ask", "reason",
  "action", "namespace"}`. NOTHING is persisted; there is no id and no
  recovery path.
* `:488-496`  `GovernanceDecision::Pending` -> `{"status": "pending",
  "pending_id", "reason": GOVERNANCE_REQUIRES_APPROVAL, "action",
  "namespace"}`. The turn is DURABLY QUEUED and recoverable via
  `memory_pending_approve` — deferred, not lost.
* `:531-538`  dedup hit -> `{"memory_id", "dedup_hit": true, "layer": "L4",
  ...}` — **no `status` key at all**.
* `:539-547`  fresh write -> `{"memory_id", "dedup_hit": false,
  "layer": "L4", ...}` — **no `status` key at all**.

Those two literals are the entire closed `status` vocabulary of
`memory_capture_turn`: `grep -n '"status"' src/mcp/tools/capture_turn.rs`
returns exactly `:439` and `:490`. `Decision::Deny` / `GovernanceDecision::
Deny` return `Err(..)`, which the MCP layer renders as `isError: true`
(`src/mcp/mod.rs`), not as a `status`. The persisted shape is pinned
independently by RFC-0001, which lists `memory_id` in the tool result's
`required` set (`docs/rfc/RFC-0001-mcp-turn-capture.md:160`).

The tool payload rides one level of JSON nesting: `src/mcp/mod.rs:3762`
serialises the handler `Value` with `serde_json::to_string_pretty` into
`result.content[0].text`.

**Non-wedging invariant:** every function here is total — it NEVER raises,
for any input, including `None` and arbitrary non-dict objects.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Final

# ── the substrate's closed `status` vocabulary ────────────────────────────
#: `capture_turn.rs:439` — permission Ask. Nothing persisted, no recovery id.
STATUS_ASK: Final[str] = "ask"
#: `capture_turn.rs:490` — governance Pending. Durably queued, recoverable.
STATUS_PENDING: Final[str] = "pending"
#: Every `status` the substrate renders for `memory_capture_turn`. A value
#: outside this set is NOT assumed benign — see `classify_capture_response`.
KNOWN_STATUSES: Final[frozenset[str]] = frozenset({STATUS_ASK, STATUS_PENDING})

# ── outcome kinds ─────────────────────────────────────────────────────────
#: The turn is persisted: the payload carried a non-empty `memory_id`.
CAPTURED: Final[str] = "captured"
#: Governance asked for approval; NOTHING was persisted and nothing is queued.
ASK: Final[str] = "ask"
#: Governance deferred the write; the turn is durably queued under `pending_id`.
PENDING: Final[str] = "pending"
#: Anything else — transport fault, unreadable payload, a status this release
#: does not know, or a payload with no `memory_id`. Fail closed.
NOT_CAPTURED: Final[str] = "not_captured"

#: The recovery verb a caller uses to redeem a `PENDING` turn.
PENDING_APPROVE_TOOL: Final[str] = "memory_pending_approve"


@dataclass(frozen=True)
class CaptureOutcome:
    """What the substrate actually did with one `memory_capture_turn` call."""

    kind: str
    memory_id: str | None = None
    pending_id: str | None = None
    dedup_hit: bool = False
    #: Human-readable reason, with no shim name — the caller prefixes it.
    detail: str = ""

    @property
    def captured(self) -> bool:
        """True ONLY for a persisted turn. The one success predicate."""
        return self.kind == CAPTURED

    @property
    def deferred(self) -> bool:
        """True when the turn is durably queued and recoverable, not stored."""
        return self.kind == PENDING


def capture_payload(resp: Any) -> dict[str, Any] | None:
    """The `memory_capture_turn` tool payload dict, or `None`.

    Unwraps the single level of JSON nesting the MCP layer adds
    (`result.content[0].text`, `src/mcp/mod.rs:3762`). Returns `None` on
    every shape mismatch. `None` is NOT a success shape — the persisted
    envelope is a JSON object carrying `memory_id`.
    """
    if not isinstance(resp, dict):
        return None
    result = resp.get("result")
    if not isinstance(result, dict):
        return None
    content = result.get("content")
    if not isinstance(content, list) or not content:
        return None
    first = content[0]
    if not isinstance(first, dict):
        return None
    text = first.get("text")
    if not isinstance(text, str):
        return None
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def classify_capture_response(resp: Any) -> CaptureOutcome:
    """Classify one JSON-RPC `tools/call` response for `memory_capture_turn`.

    `resp` is the decoded response object, or `None` when the substrate
    produced no matching frame. Total: never raises, for any input.

    The verdict is the PRESENCE form — captured iff a non-empty string
    `memory_id` is in the payload — so every shape this function has never
    seen, including a `status` added in a future release, is reported as NOT
    captured rather than silently acknowledged.
    """
    if resp is None:
        return CaptureOutcome(NOT_CAPTURED, detail="no capture response from substrate")
    if not isinstance(resp, dict):
        return CaptureOutcome(
            NOT_CAPTURED, detail="capture response was not a JSON-RPC object"
        )
    # A top-level JSON-RPC `error` member (unknown-method / invalid-params and
    # friends) carries no `result`, so screen it before the tool-level checks.
    if resp.get("error") is not None:
        return CaptureOutcome(NOT_CAPTURED, detail="substrate returned JSON-RPC error")
    result = resp.get("result")
    if not isinstance(result, dict):
        return CaptureOutcome(
            NOT_CAPTURED, detail="capture response carried no result object"
        )
    # MCP renders a handler `Err(..)` — including governance Deny — as an Ok
    # result with `isError: true` (`src/mcp/mod.rs`).
    if result.get("isError") is True:
        return CaptureOutcome(NOT_CAPTURED, detail="substrate returned isError:true")

    payload = capture_payload(resp)
    if payload is None:
        return CaptureOutcome(
            NOT_CAPTURED,
            detail=(
                "capture result payload was unreadable "
                "(result.content[0].text is not a JSON object); "
                "refusing to count it as a captured turn"
            ),
        )

    status = payload.get("status")
    if status == STATUS_ASK:
        # Nothing was written and there is no handle to redeem. Say exactly
        # that, and do NOT name a recovery path that does not exist.
        return CaptureOutcome(
            ASK,
            detail=(
                "capture_turn returned status=ask (governance approval "
                "requested; NOTHING was persisted and there is no recovery "
                "handle); not counting as a captured turn"
            ),
        )
    if status == STATUS_PENDING:
        raw_id = payload.get("pending_id")
        pending_id = raw_id if isinstance(raw_id, str) and raw_id else None
        # The opposite lie from the original bug: a Pending turn is NOT lost.
        # It is durably queued, and `pending_id` is the ONLY handle that
        # redeems it — it must reach the caller, never be discarded.
        return CaptureOutcome(
            PENDING,
            pending_id=pending_id,
            detail=(
                f"capture_turn returned status=pending, pending_id={pending_id} "
                f"(the turn is DURABLY QUEUED for approval, NOT lost; redeem it "
                f"with {PENDING_APPROVE_TOOL}); not counting as a captured turn"
            ),
        )

    memory_id = payload.get("memory_id")
    if isinstance(memory_id, str) and memory_id:
        return CaptureOutcome(
            CAPTURED,
            memory_id=memory_id,
            dedup_hit=payload.get("dedup_hit") is True,
        )

    # Fail closed. Reached by an unrecognised `status`, an empty object, or a
    # payload whose `memory_id` is absent/blank/not a string. None of these is
    # a turn we can prove was stored, so none of them is success.
    return CaptureOutcome(
        NOT_CAPTURED,
        detail=(
            f"capture_turn returned no memory_id (status={status!r}); "
            "the turn was NOT persisted — not counting as a captured turn"
        ),
    )
