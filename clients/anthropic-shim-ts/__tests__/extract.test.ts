// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Offline extraction tests — the shape-sensitive seam, pinned against RECORDED
// real Anthropic response payloads (__tests__/cassettes/).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { extractLastRequestTurn, extractResponseText } from "../src/index.ts";

function load(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(import.meta.dirname, "cassettes", name), "utf-8"));
}

test("extract response text from recorded payload", () => {
  assert.equal(
    extractResponseText(load("messages_create_text.json")),
    "Paris is the capital of France.",
  );
});

test("multiblock records text and opaque tool_use", () => {
  const text = extractResponseText(load("messages_create_multiblock.json"));
  assert.ok(text.includes("Let me look that up."));
  assert.ok(text.includes("get_weather")); // tool_use recorded opaquely, not dropped
});

test("empty content", () => {
  assert.equal(extractResponseText({ content: null }), "");
  assert.equal(extractResponseText({ content: [] }), "");
});

test("last request turn: string content", () => {
  const turn = extractLastRequestTurn({
    messages: [
      { role: "user", content: "hi" },
      { role: "user", content: "2+2?" },
    ],
  });
  assert.deepEqual(turn, ["user", "2+2?"]);
});

test("last request turn: block content", () => {
  const turn = extractLastRequestTurn({
    messages: [{ role: "user", content: [{ type: "text", text: "hello" }] }],
  });
  assert.deepEqual(turn, ["user", "hello"]);
});

test("last request turn: empty is null", () => {
  assert.equal(extractLastRequestTurn({ messages: [] }), null);
  assert.equal(extractLastRequestTurn({}), null);
});
