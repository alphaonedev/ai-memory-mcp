// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Offline extraction tests — the shape-sensitive seam, pinned against RECORDED
// real OpenAI Chat Completions payloads (__tests__/cassettes/).
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
    extractResponseText(load("chat_completion_text.json")),
    "Paris is the capital of France.",
  );
});

test("tool_call recorded opaquely when content is null", () => {
  const text = extractResponseText(load("chat_completion_toolcall.json"));
  assert.ok(text.includes("get_weather"));
});

test("empty", () => {
  assert.equal(extractResponseText({ choices: [] }), "");
  assert.equal(extractResponseText({ choices: null }), "");
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

test("last request turn: multipart content", () => {
  const turn = extractLastRequestTurn({
    messages: [{ role: "user", content: [{ type: "text", text: "hello" }] }],
  });
  assert.deepEqual(turn, ["user", "hello"]);
});

test("last request turn: empty is null", () => {
  assert.equal(extractLastRequestTurn({ messages: [] }), null);
  assert.equal(extractLastRequestTurn({}), null);
});
