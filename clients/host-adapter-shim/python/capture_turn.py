#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Reference L4 host-adapter shim (Python) — calls `memory_capture_turn`
via MCP stdio per RFC-0001 (`docs/rfc/RFC-0001-mcp-turn-capture.md`).

Fallback path for hosts whose only integration surface is "spawn a
process from a Stop / SessionEnd / per-turn hook." Hosts with native
MCP integration call the tool directly without this shim.

Usage:

    python3 capture_turn.py \\
      --host-session-id <opaque-session-id> \\
      --host-turn-index <n> \\
      --role <user|assistant|tool_use|tool_result|system|other> \\
      --content-file <path-or-"-"-for-stdin> \\
      [--host-kind <k>] [--host-version <v>] [--namespace <ns>] \\
      [--timestamp-iso <RFC3339>] [--ai-memory-bin <path>]

Exit codes:

    0 — the substrate PERSISTED the turn (the receipt carried a
        non-empty `memory_id`; `dedup_hit:true` counts, the row exists)
    1 — usage error
    2 — the turn was NOT persisted (transport fault, substrate error,
        governance `ask`/`pending`, an unreadable receipt, or any
        receipt this release cannot prove describes a stored row)
    3 — content file missing/unreadable

#3544 — exit 0 used to mean "none of the failures I enumerated
happened", so governance `ask` (nothing stored, no recovery handle),
governance `pending` (queued, not stored) and an unreadable receipt all
reported success for a turn the substrate never wrote. The verdict is
now the PRESENCE of a persisted `memory_id`; everything else fails
CLOSED. The exit-code SET is unchanged — only the meaning of 0 is, which
is the defect. A `pending` turn is not lost: its `pending_id` is printed
on stderr and redeems the turn via `memory_pending_approve`.

Failure mode: this shim MUST NOT wedge the host's operation. On any
non-persisted outcome, emits stderr WARN and exits 2.

Compatibility: stdlib-only; runs on CPython 3.10+.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, NoReturn


class _ShimArgumentParser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error; this shim's contract says 1.

    #3544 made exit 2 mean "the turn was NOT persisted", so a mistyped flag
    must not be indistinguishable from an unstored turn. The sibling
    `node/capture-turn.mjs` and `bash/capture-turn.sh` already exit 1 here; this
    brings the Python adapter back onto its own documented contract. `--help`
    still exits 0 — only the error path is remapped.
    """

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def parse_args() -> argparse.Namespace:
    p = _ShimArgumentParser(
        prog="capture-turn",
        description="L4 host-adapter shim for memory_capture_turn MCP tool",
    )
    p.add_argument("--host-session-id", required=True)
    p.add_argument("--host-turn-index", required=True, type=int)
    p.add_argument(
        "--role",
        required=True,
        choices=["user", "assistant", "tool_use", "tool_result", "system", "other"],
    )
    p.add_argument(
        "--content-file",
        required=True,
        help='File path with the turn content, or "-" for stdin',
    )
    p.add_argument("--host-kind")
    p.add_argument("--host-version")
    p.add_argument("--namespace")
    p.add_argument("--timestamp-iso")
    p.add_argument(
        "--ai-memory-bin",
        default=os.environ.get("AI_MEMORY_BIN", "ai-memory"),
    )
    return p.parse_args()


def read_content(content_file: str) -> str:
    if content_file == "-":
        return sys.stdin.read()
    try:
        with open(content_file, encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        print(f"ERROR: content file not readable: {content_file}: {e}", file=sys.stderr)
        sys.exit(3)


def build_request(args: argparse.Namespace, content: str) -> dict[str, Any]:
    req: dict[str, Any] = {
        "host_session_id": args.host_session_id,
        "host_turn_index": args.host_turn_index,
        "role": args.role,
        "content": content,
    }
    if args.host_kind:
        req["host_kind"] = args.host_kind
    if args.host_version:
        req["host_version"] = args.host_version
    if args.namespace:
        req["namespace"] = args.namespace
    if args.timestamp_iso:
        req["timestamp_iso"] = args.timestamp_iso
    return req


def build_mcp_frames(capture_request: dict[str, Any]) -> str:
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "capture-turn-shim-py", "version": "0.1"},
        },
    }
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "memory_capture_turn", "arguments": capture_request},
    }
    return "\n".join(json.dumps(o) for o in (init, initialized, call)) + "\n"


def pick_tools_call_response(stdout_text: str) -> dict[str, Any] | None:
    """Find the response to the tools/call request (id=2)."""
    for line in stdout_text.splitlines():
        trimmed = line.strip()
        if not trimmed.startswith("{"):
            continue
        try:
            obj = json.loads(trimmed)
        except json.JSONDecodeError:
            continue
        if obj.get("id") == 2:
            return obj
    return None


# ── #3544: the capture-outcome predicate ──────────────────────────────────
#
# The substrate is the source of truth for this vocabulary; measured at
# `src/mcp/tools/capture_turn.rs`:
#
#   :437-444  permission `Decision::Ask`        -> {"status": "ask", ...}
#             NOTHING is persisted; no id, no recovery handle.
#   :488-496  `GovernanceDecision::Pending`     -> {"status": "pending",
#             "pending_id", ...}  DURABLY QUEUED, redeemable.
#   :531-538  dedup hit  -> {"memory_id", "dedup_hit": true,  "layer": "L4", ...}
#   :539-547  fresh write-> {"memory_id", "dedup_hit": false, "layer": "L4", ...}
#
# `grep -n '"status"' src/mcp/tools/capture_turn.rs` returns exactly those two
# literals — that is the whole closed vocabulary. `Decision::Deny` /
# `GovernanceDecision::Deny` return `Err(..)`, which MCP renders as
# `isError: true` (`src/mcp/mod.rs`), never as a `status`. RFC-0001 pins
# `memory_id` in the result's `required` set
# (`docs/rfc/RFC-0001-mcp-turn-capture.md:160`).
#
# THE WHOLE PREDICATE: a turn is CAPTURED if and only if the tool payload
# carries a non-empty string `memory_id`. `status` is read only to say WHY and
# to carry the recovery handle — never to decide the verdict, so a status a
# later substrate release grows fails CLOSED without this file knowing it
# exists. Kept self-contained (stdlib-only, one file) because operators copy
# this script to their host; the identical predicate is implemented by the
# sibling `node/capture-turn.mjs` and `bash/capture-turn.sh`, and all three are
# pinned to the same verdicts and the same stderr text by
# `clients/host-adapter-shim/tests/test_capture_outcome_conformance.py`.

STATUS_ASK = "ask"
STATUS_PENDING = "pending"

CAPTURED = "captured"
ASK = "ask"
PENDING = "pending"
NOT_CAPTURED = "not_captured"

PENDING_APPROVE_TOOL = "memory_pending_approve"


def capture_payload(resp: Any) -> dict[str, Any] | None:
    """The tool payload dict, or None.

    Unwraps the one level of JSON nesting the MCP layer adds
    (`result.content[0].text`, `src/mcp/mod.rs:3762`). Returns None on every
    shape mismatch; None is NOT a success shape. Total: never raises.
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


def classify_capture_response(resp: Any) -> tuple[str, str]:
    """Return (kind, detail) for one tools/call response. Never raises."""
    if resp is None:
        return (NOT_CAPTURED, "no capture response from substrate")
    if not isinstance(resp, dict):
        return (NOT_CAPTURED, "capture response was not a JSON-RPC object")
    if resp.get("error") is not None:
        return (NOT_CAPTURED, "substrate returned JSON-RPC error")
    result = resp.get("result")
    if not isinstance(result, dict):
        return (NOT_CAPTURED, "capture response carried no result object")
    if result.get("isError") is True:
        return (NOT_CAPTURED, "substrate returned isError:true")

    payload = capture_payload(resp)
    if payload is None:
        return (
            NOT_CAPTURED,
            "capture result payload was unreadable "
            "(result.content[0].text is not a JSON object); "
            "refusing to count it as a captured turn",
        )

    status = payload.get("status")
    if status == STATUS_ASK:
        # Nothing was written and there is no handle to redeem. Do NOT name a
        # recovery path that does not exist.
        return (
            ASK,
            "capture_turn returned status=ask (governance approval requested; "
            "NOTHING was persisted and there is no recovery handle); "
            "not counting as a captured turn",
        )
    if status == STATUS_PENDING:
        raw_id = payload.get("pending_id")
        pending_id = raw_id if isinstance(raw_id, str) and raw_id else None
        # The opposite lie from the original bug: a Pending turn is NOT lost.
        # `pending_id` is the ONLY handle that redeems it and must reach the
        # operator rather than being discarded.
        return (
            PENDING,
            f"capture_turn returned status=pending, "
            f"pending_id={json.dumps(pending_id)} "
            f"(the turn is DURABLY QUEUED for approval, NOT lost; redeem it "
            f"with {PENDING_APPROVE_TOOL}); not counting as a captured turn",
        )

    memory_id = payload.get("memory_id")
    if isinstance(memory_id, str) and memory_id:
        return (CAPTURED, "")

    # Fail closed: an unrecognised status, an empty object, or a payload whose
    # `memory_id` is absent/blank/not a string. None of these is a turn we can
    # prove was stored, so none of them is success.
    return (
        NOT_CAPTURED,
        f"capture_turn returned no memory_id (status={json.dumps(status)}); "
        "the turn was NOT persisted - not counting as a captured turn",
    )


def main() -> int:
    args = parse_args()
    content = read_content(args.content_file)
    capture_request = build_request(args, content)
    frames = build_mcp_frames(capture_request)

    try:
        result = subprocess.run(
            [args.ai_memory_bin, "mcp", "--profile", "full"],
            input=frames,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except FileNotFoundError:
        print(
            f"ERROR: ai-memory binary not found: {args.ai_memory_bin}",
            file=sys.stderr,
        )
        return 2
    except subprocess.TimeoutExpired:
        print("WARN: substrate timed out (30s)", file=sys.stderr)
        return 2

    if result.returncode != 0:
        print(f"WARN: substrate exited {result.returncode}", file=sys.stderr)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return 2

    resp = pick_tools_call_response(result.stdout)
    if resp is None:
        if result.stderr:
            sys.stderr.write(result.stderr)
        # Same wording as the sibling adapters: the classifier owns every
        # not-captured message, so the three cannot drift apart.
        print(f"WARN: {classify_capture_response(None)[1]}", file=sys.stderr)
        return 2

    print(json.dumps(resp, indent=2))

    # #3544 — the verdict is the PRESENCE of a persisted `memory_id`, never the
    # ABSENCE of an enumerated failure.
    kind, detail = classify_capture_response(resp)
    if kind != CAPTURED:
        print(f"WARN: {detail}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
