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

    0 — success (dedup_hit:true or memory created)
    1 — usage error
    2 — MCP call failed
    3 — content file missing/unreadable

Failure mode: this shim MUST NOT wedge the host's operation. On MCP
failure, emits stderr WARN and exits 2.

Compatibility: stdlib-only; runs on CPython 3.10+.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
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
        print("WARN: no tools/call response in substrate stdout", file=sys.stderr)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return 2

    print(json.dumps(resp, indent=2))

    # MCP tool error envelope: result.isError:true marks failure.
    if isinstance(resp.get("result"), dict) and resp["result"].get("isError") is True:
        print("WARN: substrate returned isError:true", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
