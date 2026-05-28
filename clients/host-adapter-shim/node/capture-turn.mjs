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
// - 0  — success (either dedup_hit:true or memory created)
// - 1  — usage error
// - 2  — MCP call failed (substrate error; check stderr)
// - 3  — content file missing/unreadable
//
// # Failure mode
//
// Per the architecture: this shim MUST NOT wedge the host's
// operation. On MCP failure, emits stderr WARN and exits 2.

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
    process.stderr.write("WARN: no tools/call response found in substrate stdout\n");
    if (stderrText) process.stderr.write(stderrText);
    process.exit(2);
  }

  process.stdout.write(`${JSON.stringify(resp, null, 2)}\n`);

  // The MCP wire shape encodes the tool's success/failure under
  // result.isError. Treat isError:true as exit-2 for the shim's
  // caller (operator inspection or downstream piping).
  if (resp.result && resp.result.isError === true) {
    process.stderr.write("WARN: substrate returned isError:true\n");
    process.exit(2);
  }
  process.exit(0);
}

main().catch((e) => {
  process.stderr.write(`ERROR: ${e.message}\n`);
  process.exit(2);
});
