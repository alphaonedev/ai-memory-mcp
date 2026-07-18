// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Opt-in integration legs (skipped by default):
//   * real openai SDK shape extraction — OPENAI_API_KEY
//   * real self-spawned-MCP capture     — AI_MEMORY_TEST_BIN
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { captureTurn, extractResponseText } from "../src/index.ts";

const HAS_OPENAI = Boolean(process.env.OPENAI_API_KEY);
const AI_MEMORY_BIN = process.env.AI_MEMORY_TEST_BIN;

test(
  "real openai response shape extraction",
  { skip: HAS_OPENAI ? false : "OPENAI_API_KEY unset (opt-in real-SDK leg)" },
  async () => {
    const mod = await import("openai");
    const OpenAI = mod.default;
    const client = new OpenAI();
    const resp = await client.chat.completions.create({
      model: "gpt-4o-mini",
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
