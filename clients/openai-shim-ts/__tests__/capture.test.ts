// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Transport-level tests for captureTurn's JSON-RPC response classification.
// Hermetic + offline: a throwaway POSIX shell "fake substrate" is spawned in
// place of the real `ai-memory` binary (it drains stdin, then prints a canned
// JSON-RPC response line), so no real binary / vendor key is needed. POSIX-only
// (the fake is a /bin/sh script); skipped on Windows, where these packages' CI
// does not run.
//
// #3544 — these cells pin the PRESENCE predicate: a turn is a captured turn if
// and only if the tool payload carries a non-empty string `memory_id`. The
// envelopes below are copied from the substrate, `src/mcp/tools/capture_turn.rs`
// (`:439` ask, `:490` pending, `:531-538` dedup hit, `:539-547` fresh write) —
// that file's two `"status"` literals are the whole closed vocabulary, so an
// unlisted status is a shape this release has never seen and must fail closed.
//
// The two pre-#3544 "success" cells were THEMSELVES the absence form: they
// asserted that `text: "ok"` and `{"content":[]}` — payloads that prove nothing
// was stored — ARE captured turns. Both now carry the substrate's real
// persisted envelope, so they stay green on the old code AND the new and are
// the control that keeps the predicate from being "refuse everything".
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { captureTurn, captureTurnAsync } from "../src/index.ts";

const POSIX = process.platform !== "win32";

/** The substrate's fresh-write envelope — `capture_turn.rs:539-547`. */
const PERSISTED_PAYLOAD = {
  memory_id: "11111111-2222-3333-4444-555555555555",
  dedup_hit: false,
  layer: "L4",
  agent_id: "tester",
  attest_level: "none",
  elapsed_ms: 3,
};

/** The substrate's dedup-hit envelope — `capture_turn.rs:531-538`. */
const DEDUP_PAYLOAD = {
  memory_id: "66666666-7777-8888-9999-000000000000",
  dedup_hit: true,
  layer: "L4",
  agent_id: "tester",
  elapsed_ms: 1,
};

/** Permission `Decision::Ask` — `capture_turn.rs:437-444`. Nothing persisted. */
const ASK_PAYLOAD = {
  status: "ask",
  reason: "rule requires confirmation",
  action: "capture_turn",
  namespace: "default",
};

/** `GovernanceDecision::Pending` — `capture_turn.rs:488-496`. Durably queued. */
const PENDING_PAYLOAD = {
  status: "pending",
  pending_id: "pend-abc123",
  reason: "governance requires approval",
  action: "capture_turn",
  namespace: "default",
};

/** One JSON-RPC tools/call response line carrying `payload` as the tool result. */
function envelope(payload: unknown): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: 2,
    result: {
      content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
    },
  });
}

function fakeSubstrate(responseLine: string): string {
  const dir = mkdtempSync(join(tmpdir(), "shim-fake-"));
  const script = join(dir, "fake-ai-memory");
  // Drain stdin so the shim's write never SIGPIPEs, then emit the canned line.
  writeFileSync(script, `#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '${responseLine}'\n`);
  chmodSync(script, 0o755);
  return script;
}

function call(bin: string): boolean {
  return captureTurn({
    hostSessionId: "s",
    hostTurnIndex: 0,
    role: "user",
    content: "x",
    aiMemoryBin: bin,
  });
}

function callAsync(bin: string): Promise<boolean> {
  return captureTurnAsync({
    hostSessionId: "s",
    hostTurnIndex: 0,
    role: "user",
    content: "x",
    aiMemoryBin: bin,
  });
}

/** Run `fn` with stderr captured, returning [result, stderrText]. */
function withStderr<T>(fn: () => T): [T, string] {
  const original = process.stderr.write.bind(process.stderr);
  let buf = "";
  (process.stderr as unknown as { write: (c: string) => boolean }).write = (c: string) => {
    buf += c;
    return true;
  };
  try {
    return [fn(), buf];
  } finally {
    (process.stderr as unknown as { write: typeof original }).write = original;
  }
}

const posix = { skip: POSIX ? false : "posix-only fake-substrate test" };

// ── controls: the two shapes the substrate emits for a PERSISTED turn ────── //

test("persisted envelope is a captured turn", posix, () => {
  assert.equal(call(fakeSubstrate(envelope(PERSISTED_PAYLOAD))), true);
});

test("dedup-hit envelope is a captured turn", posix, () => {
  assert.equal(call(fakeSubstrate(envelope(DEDUP_PAYLOAD))), true);
});

test("async persisted envelope is a captured turn", posix, async () => {
  assert.equal(await callAsync(fakeSubstrate(envelope(PERSISTED_PAYLOAD))), true);
});

// ── transport-level failures (pre-#3544 cells, kept) ─────────────────────── //

test("jsonrpc error response is a failure", posix, () => {
  const bin = fakeSubstrate('{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"boom"}}');
  assert.equal(call(bin), false);
});

test("tool isError response is a failure", posix, () => {
  const bin = fakeSubstrate('{"jsonrpc":"2.0","id":2,"result":{"isError":true}}');
  assert.equal(call(bin), false);
});

test("async capture leaves the event loop responsive", posix, async () => {
  const pending = callAsync(fakeSubstrate(envelope(PERSISTED_PAYLOAD)));
  let ticked = false;
  await new Promise<void>((resolve) =>
    setImmediate(() => {
      ticked = true;
      resolve();
    }),
  );
  assert.equal(ticked, true, "spawn transport must yield to other callbacks");
  assert.equal(await pending, true);
});

// ── #3544: governance outcomes are NOT captured turns ────────────────────── //

test("ask status is not a captured turn and claims no recovery", posix, () => {
  const bin = fakeSubstrate(envelope(ASK_PAYLOAD));
  const [ok, err] = withStderr(() => call(bin));
  assert.equal(ok, false);
  assert.match(err, /status=ask/);
  // Nothing was queued, so the message must NOT offer a handle to redeem.
  assert.equal(err.includes("pending_id"), false);
  assert.equal(err.includes("pending_approve"), false);
});

test("pending status is not a captured turn but surfaces pending_id", posix, () => {
  const bin = fakeSubstrate(envelope(PENDING_PAYLOAD));
  const [ok, err] = withStderr(() => call(bin));
  assert.equal(ok, false);
  assert.match(err, /status=pending/);
  // The turn is durably queued; `pending_id` is the ONLY handle that redeems
  // it and must reach the caller rather than being discarded.
  assert.match(err, /pend-abc123/);
  assert.match(err, /memory_pending_approve/);
});

test("async ask status is not a captured turn", posix, async () => {
  assert.equal(await callAsync(fakeSubstrate(envelope(ASK_PAYLOAD))), false);
});

test("async pending status is not a captured turn", posix, async () => {
  assert.equal(await callAsync(fakeSubstrate(envelope(PENDING_PAYLOAD))), false);
});

// ── #3544: everything unenumerated fails CLOSED ──────────────────────────── //

test("unknown status is not a captured turn", posix, () => {
  // A status the substrate may grow in a later release. The shim has never
  // seen it, so it must NOT be silently acknowledged as a stored turn.
  const bin = fakeSubstrate(envelope({ status: "quarantined", reason: "future release" }));
  assert.equal(call(bin), false);
});

test("payload without memory_id is not a captured turn", posix, () => {
  const bin = fakeSubstrate(envelope({ dedup_hit: false, layer: "L4" }));
  assert.equal(call(bin), false);
});

test("blank memory_id is not a captured turn", posix, () => {
  const bin = fakeSubstrate(envelope({ memory_id: "", dedup_hit: false, layer: "L4" }));
  assert.equal(call(bin), false);
});

test("unreadable payload is not a captured turn", posix, () => {
  // `result.content[0].text` that is not a JSON object proves nothing was
  // stored. This is the exact cell the pre-#3544 suite asserted was SUCCESS.
  const bin = fakeSubstrate('{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}');
  assert.equal(call(bin), false);
});

test("empty content array is not a captured turn", posix, () => {
  const bin = fakeSubstrate('{"jsonrpc":"2.0","id":2,"result":{"content":[]}}');
  assert.equal(call(bin), false);
});

test("async unreadable payload is not a captured turn", posix, async () => {
  const bin = fakeSubstrate('{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}');
  assert.equal(await callAsync(bin), false);
});

test("async unknown status is not a captured turn", posix, async () => {
  const bin = fakeSubstrate(envelope({ status: "quarantined", reason: "future release" }));
  assert.equal(await callAsync(bin), false);
});
