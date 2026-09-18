// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// #3544 byte-identity pin. `src/captureOutcome.ts` is VENDORED — the same
// source lives in this package and in `clients/anthropic-shim-ts/src/`, because
// both are published independently to npm by `publish-sdk-shims.yml` and a
// shared third package would add a runtime dependency to both. The copies are
// only one predicate as long as they are one FILE, so this cell exists in BOTH
// packages and each compares its own copy against the sibling's: edit either
// and BOTH suites go red, so the two published packages cannot drift into
// disagreeing about what "captured" means.
//
// It skips — it does not silently pass — when the sibling is not on disk (an
// installed package outside the repo checkout). Both CI legs that run this
// suite (`clients-ci.yml` and the `publish-sdk-shims.yml` test gate) run from
// a full checkout, where the sibling is present.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ASK,
  CAPTURED,
  KNOWN_STATUSES,
  NOT_CAPTURED,
  PENDING,
  PENDING_APPROVE_TOOL,
  STATUS_ASK,
  STATUS_PENDING,
  classifyCaptureResponse,
  isCaptured,
  isDeferred,
} from "../src/captureOutcome.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const OWN = join(HERE, "..", "src", "captureOutcome.ts");
const SIBLING = join(HERE, "..", "..", "anthropic-shim-ts", "src", "captureOutcome.ts");

test("the vendored capture-outcome module is byte-identical in both shims", () => {
  if (!existsSync(SIBLING)) {
    // Not a pass: announce the skip so a missing sibling is visible, never silent.
    console.log(`# SKIP sibling shim not on disk: ${SIBLING}`);
    return;
  }
  const own = readFileSync(OWN);
  const sibling = readFileSync(SIBLING);
  assert.equal(
    own.equals(sibling),
    true,
    "clients/*-shim-ts/src/captureOutcome.ts diverged; the two published " +
      "packages would disagree about what a captured turn is",
  );
});

test("the substrate's status vocabulary is exactly {ask, pending}", () => {
  // `grep -n '\"status\"' src/mcp/tools/capture_turn.rs` returns exactly two
  // literals, `:439` and `:490`. If the substrate grows a third, this cell is
  // where the shim learns about it — and until then an unknown status fails
  // closed rather than being counted as a stored turn.
  assert.deepEqual([...KNOWN_STATUSES].sort(), ["ask", "pending"]);
  assert.equal(STATUS_ASK, "ask");
  assert.equal(STATUS_PENDING, "pending");
  assert.equal(PENDING_APPROVE_TOOL, "memory_pending_approve");
});

test("isCaptured is true only for the persisted kind", () => {
  for (const kind of [CAPTURED, ASK, PENDING, NOT_CAPTURED]) {
    const outcome = {
      kind,
      memoryId: null,
      pendingId: null,
      dedupHit: false,
      detail: "",
    } as const;
    assert.equal(isCaptured(outcome), kind === CAPTURED, `kind=${kind}`);
    assert.equal(isDeferred(outcome), kind === PENDING, `kind=${kind}`);
  }
});

test("the classifier never throws on hostile input", () => {
  const hostile: unknown[] = [
    null,
    undefined,
    0,
    "",
    "not json",
    [],
    {},
    { result: 7 },
    { result: { content: [] } },
    { result: { content: [{ text: "{" }] } },
    { result: { content: [{ text: "[]" }] } },
    { result: { content: ["nope"] } },
    { error: { code: -1 } },
  ];
  for (const value of hostile) {
    const outcome = classifyCaptureResponse(value);
    assert.equal(isCaptured(outcome), false, `must fail closed: ${JSON.stringify(value)}`);
  }
});
