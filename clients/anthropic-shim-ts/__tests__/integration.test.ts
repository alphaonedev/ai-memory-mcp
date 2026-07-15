// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Opt-in integration legs (skipped by default so CI stays green):
//   * real @anthropic-ai/sdk shape extraction  — ANTHROPIC_API_KEY
//   * real self-spawned-MCP capture            — AI_MEMORY_TEST_BIN
// The vendor SDK is dynamically imported inside the test body so a skipped run
// never fails at load when the peer dependency is absent.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { captureTurn, extractResponseText } from "../src/index.ts";

const HAS_ANTHROPIC = Boolean(process.env.ANTHROPIC_API_KEY);
const AI_MEMORY_BIN = process.env.AI_MEMORY_TEST_BIN;

test(
  "real anthropic response shape extraction",
  { skip: HAS_ANTHROPIC ? false : "ANTHROPIC_API_KEY unset (opt-in real-SDK leg)" },
  async () => {
    const mod = await import("@anthropic-ai/sdk");
    const Anthropic = mod.default;
    const client = new Anthropic();
    const resp = await client.messages.create({
      model: "claude-3-5-haiku-latest",
      max_tokens: 16,
      messages: [{ role: "user", content: "Reply with the single word: ok" }],
    });
    const text = extractResponseText(resp);
    assert.ok(typeof text === "string" && text.trim().length > 0);
  },
);

test(
  "self-spawned MCP capture lands",
  { skip: AI_MEMORY_BIN ? false : "AI_MEMORY_TEST_BIN unset (opt-in substrate leg)" },
  () => {
    const dir = mkdtempSync(join(tmpdir(), "shim-it-"));
    const prevDb = process.env.AI_MEMORY_DB;
    const prevNoConfig = process.env.AI_MEMORY_NO_CONFIG;
    process.env.AI_MEMORY_DB = join(dir, "shim-it.db");
    process.env.AI_MEMORY_NO_CONFIG = "1";
    try {
      const ok = captureTurn({
        hostSessionId: "shim-it",
        hostTurnIndex: 0,
        role: "user",
        content: "integration probe",
        aiMemoryBin: AI_MEMORY_BIN,
      });
      assert.equal(ok, true);
    } finally {
      if (prevDb === undefined) delete process.env.AI_MEMORY_DB;
      else process.env.AI_MEMORY_DB = prevDb;
      if (prevNoConfig === undefined) delete process.env.AI_MEMORY_NO_CONFIG;
      else process.env.AI_MEMORY_NO_CONFIG = prevNoConfig;
    }
  },
);
