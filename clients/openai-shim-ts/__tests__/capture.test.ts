// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Transport-level tests for captureTurn's JSON-RPC response classification.
// Hermetic + offline: a throwaway POSIX shell "fake substrate" is spawned in
// place of the real `ai-memory` binary (it drains stdin, then prints a canned
// JSON-RPC response line), so no real binary / vendor key is needed. Pins the
// non-wedging contract that a top-level JSON-RPC `error` is a FAILURE, not a
// mis-counted success. POSIX-only (the fake is a /bin/sh script); skipped on
// Windows, where these packages' CI does not run.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { captureTurn, captureTurnAsync } from "../src/index.ts";

const POSIX = process.platform !== "win32";

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

test(
  "jsonrpc error response is a failure",
  { skip: POSIX ? false : "posix-only fake-substrate test" },
  () => {
    const bin = fakeSubstrate('{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"boom"}}');
    assert.equal(call(bin), false);
  },
);

test(
  "async capture leaves the event loop responsive",
  { skip: POSIX ? false : "posix-only fake-substrate test" },
  async () => {
    const bin = fakeSubstrate('{"jsonrpc":"2.0","id":2,"result":{"content":[]}}');
    const pending = captureTurnAsync({
      hostSessionId: "s",
      hostTurnIndex: 0,
      role: "user",
      content: "x",
      aiMemoryBin: bin,
    });
    let ticked = false;
    await new Promise<void>((resolve) => setImmediate(() => {
      ticked = true;
      resolve();
    }));
    assert.equal(ticked, true, "spawn transport must yield to other callbacks");
    assert.equal(await pending, true);
  },
);

test(
  "tool isError response is a failure",
  { skip: POSIX ? false : "posix-only fake-substrate test" },
  () => {
    const bin = fakeSubstrate('{"jsonrpc":"2.0","id":2,"result":{"isError":true}}');
    assert.equal(call(bin), false);
  },
);

test(
  "ok result response is a success",
  { skip: POSIX ? false : "posix-only fake-substrate test" },
  () => {
    const bin = fakeSubstrate('{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"ok"}]}}');
    assert.equal(call(bin), true);
  },
);
