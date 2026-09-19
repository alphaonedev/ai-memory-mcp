#!/usr/bin/env node
// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Reference L4 host-adapter shim (Node.js) — calls `memory_capture_turn`
// via MCP stdio per RFC-0001 (`docs/rfc/RFC-0001-mcp-turn-capture.md`).
//
// Fallback path for hosts whose only integration surface is "spawn a
// process from a Stop / SessionEnd / per-turn hook." Hosts with native
// MCP integration call the tool directly without this shim.
//
// # Usage
//
//   node capture-turn.mjs \
//     --host-session-id "<opaque-session-id>" \
//     --host-turn-index <n> \
//     --role <user|assistant|tool_use|tool_result|system|other> \
//     --content-file <path-or-"-"-for-stdin> \
//     [--host-kind claude-code|codex|gemini|...] \
//     [--host-version <version>] \
//     [--namespace <ns>] \
//     [--timestamp-iso <RFC3339>] \
//     [--ai-memory-bin <path>]    # default: ai-memory in $PATH
//
// # Exit codes
//
// - 0  — the substrate PERSISTED the turn (the receipt carried a
//        non-empty `memory_id`; `dedup_hit:true` counts, the row exists)
// - 1  — usage error
// - 2  — the turn was NOT persisted (transport fault, substrate error,
//        governance `ask`/`pending`, an unreadable receipt, or any
//        receipt this release cannot prove describes a stored row)
// - 3  — content file missing/unreadable
//
// #3544 — exit 0 used to mean "none of the failures I enumerated
// happened", so governance `ask` (nothing stored, no recovery handle),
// governance `pending` (queued, not stored) and an unreadable receipt
// all reported success for a turn the substrate never wrote. The verdict
// is now the PRESENCE of a persisted `memory_id`; everything else fails
// CLOSED. The exit-code SET is unchanged — only the meaning of 0 is,
// which is the defect. A `pending` turn is not lost: its `pending_id` is
// printed on stderr and redeems the turn via `memory_pending_approve`.
//
// # Failure mode
//
// Per the architecture: this shim MUST NOT wedge the host's
// operation. On any non-persisted outcome, emits stderr WARN and exits 2.

import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { parseArgs } from "node:util";

const REQUIRED = ["host-session-id", "host-turn-index", "role", "content-file"];

function parseFlags() {
  const { values } = parseArgs({
    options: {
      "host-session-id": { type: "string" },
      "host-turn-index": { type: "string" },
      role: { type: "string" },
      "content-file": { type: "string" },
      "host-kind": { type: "string" },
      "host-version": { type: "string" },
      namespace: { type: "string" },
      "timestamp-iso": { type: "string" },
      "ai-memory-bin": { type: "string" },
      help: { type: "boolean", short: "h" },
    },
    strict: true,
  });
  return values;
}

function usage(code = 1) {
  process.stderr.write(
    "usage: node capture-turn.mjs --host-session-id <id> --host-turn-index <n> " +
      "--role <user|assistant|...> --content-file <path|-> " +
      "[--host-kind <k>] [--host-version <v>] [--namespace <ns>] " +
      "[--timestamp-iso <RFC3339>] [--ai-memory-bin <path>]\n",
  );
  process.exit(code);
}

async function readContent(arg) {
  if (arg === "-") {
    const chunks = [];
    for await (const c of process.stdin) chunks.push(c);
    return Buffer.concat(chunks).toString("utf8");
  }
  try {
    return await readFile(arg, "utf8");
  } catch (e) {
    process.stderr.write(`ERROR: content file not readable: ${arg}: ${e.message}\n`);
    process.exit(3);
  }
}

function buildRequest(args, content) {
  const req = {
    host_session_id: args["host-session-id"],
    host_turn_index: Number.parseInt(args["host-turn-index"], 10),
    role: args["role"],
    content,
  };
  if (args["host-kind"]) req.host_kind = args["host-kind"];
  if (args["host-version"]) req.host_version = args["host-version"];
  if (args["namespace"]) req.namespace = args["namespace"];
  if (args["timestamp-iso"]) req.timestamp_iso = args["timestamp-iso"];
  return req;
}

function buildMcpFrames(captureRequest) {
  const init = {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "capture-turn-shim-node", version: "0.1" },
    },
  };
  const initialized = { jsonrpc: "2.0", method: "notifications/initialized" };
  const call = {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "memory_capture_turn", arguments: captureRequest },
  };
  return `${JSON.stringify(init)}\n${JSON.stringify(initialized)}\n${JSON.stringify(call)}\n`;
}

function spawnSubstrate(bin) {
  return spawn(bin, ["mcp", "--profile", "full"], {
    stdio: ["pipe", "pipe", "pipe"],
    env: process.env,
  });
}

function pickToolsCallResponse(stdoutText) {
  // The substrate emits one JSON object per line; we want the
  // tools/call response (id=2). Filter lines that parse to JSON
  // with id == 2.
  for (const line of stdoutText.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const obj = JSON.parse(trimmed);
      if (obj.id === 2) return obj;
    } catch {
      // Not JSON; skip.
    }
  }
  return null;
}

// ── #3544: the capture-outcome predicate ──────────────────────────────────
//
// The substrate is the source of truth for this vocabulary; measured at
// `src/mcp/tools/capture_turn.rs`:
//
//   :437-444  permission `Decision::Ask`     -> {"status": "ask", ...}
//             NOTHING is persisted; no id, no recovery handle.
//   :488-496  `GovernanceDecision::Pending`  -> {"status": "pending",
//             "pending_id", ...}  DURABLY QUEUED, redeemable.
//   :531-538  dedup hit   -> {"memory_id", "dedup_hit": true,  "layer": "L4", ...}
//   :539-547  fresh write -> {"memory_id", "dedup_hit": false, "layer": "L4", ...}
//
// `grep -n '"status"' src/mcp/tools/capture_turn.rs` returns exactly those two
// literals — that is the whole closed vocabulary. `Decision::Deny` /
// `GovernanceDecision::Deny` return `Err(..)`, which MCP renders as
// `isError: true` (`src/mcp/mod.rs`), never as a `status`. RFC-0001 pins
// `memory_id` in the result's `required` set
// (`docs/rfc/RFC-0001-mcp-turn-capture.md:160`).
//
// THE WHOLE PREDICATE: a turn is CAPTURED if and only if the tool payload
// carries a non-empty string `memory_id`. `status` is read only to say WHY and
// to carry the recovery handle — never to decide the verdict, so a status a
// later substrate release grows fails CLOSED without this file knowing it
// exists. Kept self-contained (node builtins only, one file) because operators
// copy this script to their host; the identical predicate is implemented by the
// sibling `python/capture_turn.py` and `bash/capture-turn.sh`, and all three
// are pinned to the same verdicts and the same stderr text by
// `clients/host-adapter-shim/tests/test_capture_outcome_conformance.py`.

const STATUS_ASK = "ask";
const STATUS_PENDING = "pending";

const CAPTURED = "captured";
const ASK = "ask";
const PENDING = "pending";
const NOT_CAPTURED = "not_captured";

const PENDING_APPROVE_TOOL = "memory_pending_approve";

function asObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value : null;
}

/** The tool payload object, or null. Unwraps `result.content[0].text`. Total. */
function capturePayload(resp) {
  const outer = asObject(resp);
  if (!outer) return null;
  const result = asObject(outer.result);
  if (!result) return null;
  const content = result.content;
  if (!Array.isArray(content) || content.length === 0) return null;
  const first = asObject(content[0]);
  if (!first) return null;
  if (typeof first.text !== "string") return null;
  try {
    return asObject(JSON.parse(first.text));
  } catch {
    return null;
  }
}

/** Return { kind, detail } for one tools/call response. Never throws. */
function classifyCaptureResponse(resp) {
  if (resp === null || resp === undefined) {
    return { kind: NOT_CAPTURED, detail: "no capture response from substrate" };
  }
  const outer = asObject(resp);
  if (!outer) {
    return { kind: NOT_CAPTURED, detail: "capture response was not a JSON-RPC object" };
  }
  if (outer.error !== null && outer.error !== undefined) {
    return { kind: NOT_CAPTURED, detail: "substrate returned JSON-RPC error" };
  }
  const result = asObject(outer.result);
  if (!result) {
    return { kind: NOT_CAPTURED, detail: "capture response carried no result object" };
  }
  if (result.isError === true) {
    return { kind: NOT_CAPTURED, detail: "substrate returned isError:true" };
  }

  const payload = capturePayload(resp);
  if (!payload) {
    return {
      kind: NOT_CAPTURED,
      detail:
        "capture result payload was unreadable " +
        "(result.content[0].text is not a JSON object); " +
        "refusing to count it as a captured turn",
    };
  }

  const status = payload.status;
  if (status === STATUS_ASK) {
    // Nothing was written and there is no handle to redeem. Do NOT name a
    // recovery path that does not exist.
    return {
      kind: ASK,
      detail:
        "capture_turn returned status=ask (governance approval requested; " +
        "NOTHING was persisted and there is no recovery handle); " +
        "not counting as a captured turn",
    };
  }
  if (status === STATUS_PENDING) {
    const rawId = payload.pending_id;
    const pendingId = typeof rawId === "string" && rawId ? rawId : null;
    // The opposite lie from the original bug: a Pending turn is NOT lost.
    // `pending_id` is the ONLY handle that redeems it and must reach the
    // operator rather than being discarded.
    return {
      kind: PENDING,
      detail:
        `capture_turn returned status=pending, pending_id=${JSON.stringify(pendingId)} ` +
        `(the turn is DURABLY QUEUED for approval, NOT lost; redeem it with ` +
        `${PENDING_APPROVE_TOOL}); not counting as a captured turn`,
    };
  }

  const memoryId = payload.memory_id;
  if (typeof memoryId === "string" && memoryId) {
    return { kind: CAPTURED, detail: "" };
  }

  // Fail closed: an unrecognised status, an empty object, or a payload whose
  // `memory_id` is absent/blank/not a string. None of these is a turn we can
  // prove was stored, so none of them is success.
  return {
    kind: NOT_CAPTURED,
    detail:
      `capture_turn returned no memory_id (status=${JSON.stringify(status) ?? "null"}); ` +
      "the turn was NOT persisted - not counting as a captured turn",
  };
}

async function main() {
  let args;
  try {
    args = parseFlags();
  } catch (e) {
    process.stderr.write(`ERROR: ${e.message}\n`);
    usage(1);
  }
  if (args.help) usage(0);
  for (const name of REQUIRED) {
    if (!args[name]) {
      process.stderr.write(`ERROR: required arg --${name} missing\n`);
      usage(1);
    }
  }

  const content = await readContent(args["content-file"]);
  const captureRequest = buildRequest(args, content);
  const frames = buildMcpFrames(captureRequest);

  const bin = args["ai-memory-bin"] || "ai-memory";
  const child = spawnSubstrate(bin);

  const stdoutChunks = [];
  const stderrChunks = [];
  child.stdout.on("data", (c) => stdoutChunks.push(c));
  child.stderr.on("data", (c) => stderrChunks.push(c));

  child.stdin.write(frames);
  child.stdin.end();

  const exitCode = await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", resolve);
  });

  const stdoutText = Buffer.concat(stdoutChunks).toString("utf8");
  const stderrText = Buffer.concat(stderrChunks).toString("utf8");

  if (exitCode !== 0) {
    process.stderr.write(`WARN: substrate exited ${exitCode}\n`);
    if (stderrText) process.stderr.write(stderrText);
    process.exit(2);
  }

  const resp = pickToolsCallResponse(stdoutText);
  if (!resp) {
    if (stderrText) process.stderr.write(stderrText);
    // Same wording as the sibling adapters: the classifier owns every
    // not-captured message, so the three cannot drift apart.
    process.stderr.write(`WARN: ${classifyCaptureResponse(null).detail}\n`);
    process.exit(2);
  }

  process.stdout.write(`${JSON.stringify(resp, null, 2)}\n`);

  // #3544 — the verdict is the PRESENCE of a persisted `memory_id`, never the
  // ABSENCE of an enumerated failure.
  const outcome = classifyCaptureResponse(resp);
  if (outcome.kind !== CAPTURED) {
    process.stderr.write(`WARN: ${outcome.detail}\n`);
    process.exit(2);
  }
  process.exit(0);
}

main().catch((e) => {
  process.stderr.write(`ERROR: ${e.message}\n`);
  process.exit(2);
});
