// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Integration tests for `AiMemoryClient`.
 *
 * These tests hit a real ai-memory daemon at `AI_MEMORY_TEST_URL`
 * (default `http://localhost:9077`). The entire block is skipped unless
 * `AI_MEMORY_TEST_DAEMON=1` is set, so CI without a daemon stays green.
 *
 * Start a daemon for local testing:
 *
 * ```bash
 * AI_MEMORY_NO_CONFIG=1 cargo run -- daemon --port 9077
 * AI_MEMORY_TEST_DAEMON=1 npm test
 * ```
 */

import { AiMemoryClient } from "../src/client.js";
import { ValidationError, NotFoundError } from "../src/errors.js";

const BASE_URL = process.env.AI_MEMORY_TEST_URL ?? "http://localhost:9077";
const DAEMON_ENABLED = process.env.AI_MEMORY_TEST_DAEMON === "1";
const describeIntegration = DAEMON_ENABLED ? describe : describe.skip;

// ---------------------------------------------------------------------------
// Pure unit tests — always run. Do not require a daemon.
// ---------------------------------------------------------------------------

// The webhook-HMAC tests moved to __tests__/webhooks.test.ts (#2455). The
// version that lived here built its expected signature with `signWebhookBody`
// — the SAME construction the verifier used — so it asserted the module
// agreed with itself and stayed green while the SDK could not verify a single
// genuine delivery. The replacement asserts against a fixture emitted by the
// RUST signer.

describe("AiMemoryClient constructor", () => {
  test("requires baseUrl", () => {
    expect(() => new AiMemoryClient({ baseUrl: "" })).toThrow();
  });

  test("strips trailing slash", () => {
    const c = new AiMemoryClient({ baseUrl: "http://localhost:9077/" });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((c as any).baseUrl).toBe("http://localhost:9077");
  });
});

// ---------------------------------------------------------------------------
// C-20 (3x7 claims register, 2026-08-01) — the daemon registers `delete` on
// the COLLECTION path `/api/v1/subscriptions` only; the id rides the query
// string (`UnsubscribeQuery` in `src/handlers/subscriptions.rs`). The SDK used
// to send `DELETE /api/v1/subscriptions/:id`, which matches no route — so
// webhook teardown appeared to fail safe while the decommissioned endpoint
// kept receiving signed deliveries indefinitely.
//
// Offline: the client takes an injectable fetch as its second constructor arg,
// so this asserts the URL the SDK builds without needing a daemon.
// ---------------------------------------------------------------------------

describe("AiMemoryClient.unsubscribe URL shape (C-20)", () => {
  function captureUrl(): {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    fetchImpl: any;
    seen: () => string;
  } {
    let captured = "";
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const fetchImpl = async (url: any, _init: any) => {
      captured = String(url);
      return {
        ok: true,
        status: 200,
        headers: { get: () => "application/json" },
        json: async () => ({ deleted: true }),
        text: async () => '{"deleted":true}',
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any;
    };
    return { fetchImpl, seen: () => captured };
  }

  test("targets the collection path with ?id=<id>", async () => {
    const { fetchImpl, seen } = captureUrl();
    const client = new AiMemoryClient(
      { baseUrl: "http://localhost:9077" },
      fetchImpl,
    );

    const res = await client.unsubscribe("sub-abc-123");
    expect(res).toEqual({ deleted: true });

    const url = new URL(seen());
    // The registered route is the bare collection path.
    expect(url.pathname).toBe("/api/v1/subscriptions");
    // The id is a query parameter, not a path segment.
    expect(url.searchParams.get("id")).toBe("sub-abc-123");
    // Guard the exact regression: no `/api/v1/subscriptions/<id>` form.
    expect(seen()).not.toContain("/api/v1/subscriptions/");
  });
});

// ---------------------------------------------------------------------------
// #2646 — `storeBulk` posted `{ memories }` (an OBJECT wrapper) at a handler
// that is `Json<Vec<CreateMemory>>` (a BARE ARRAY), so every call was dead on
// arrival; and it typed a `{ created: Memory[]; count }` response the daemon
// has never emitted. This offline test pins BOTH: the request body is an
// array, and a representative `BulkCreateResponse` envelope (including a
// rejected row) parses through.
// ---------------------------------------------------------------------------

describe("AiMemoryClient.storeBulk wire shape (#2646)", () => {
  function capture(responseBody: unknown, status = 207): {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    fetchImpl: any;
    seenBody: () => string;
  } {
    let body = "";
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const fetchImpl = async (_url: any, init: any) => {
      body = String(init?.body ?? "");
      return {
        ok: status >= 200 && status < 300,
        status,
        headers: { get: () => "application/json" },
        json: async () => responseBody,
        text: async () => JSON.stringify(responseBody),
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any;
    };
    return { fetchImpl, seenBody: () => body };
  }

  test("sends a BARE ARRAY body, never an object wrapper", async () => {
    const envelope = {
      sent: 2,
      created: 2,
      updated: 0,
      deduped: 0,
      rejected: 0,
      errors: [],
      pending: [],
    };
    const { fetchImpl, seenBody } = capture(envelope, 200);
    const client = new AiMemoryClient(
      { baseUrl: "http://localhost:9077" },
      fetchImpl,
    );

    await client.storeBulk([
      { title: "a", content: "one" },
      { title: "b", content: "two" },
    ]);

    const parsed = JSON.parse(seenBody());
    // The daemon's `Json<Vec<CreateMemory>>` extractor requires a top-level
    // array; the pre-#2646 `{ memories: [...] }` wrapper 400s outright.
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed).toHaveLength(2);
    expect(parsed[0]).toMatchObject({ title: "a", content: "one" });
  });

  test("parses the ledger envelope including a rejected row (207)", async () => {
    const envelope = {
      sent: 4,
      created: 1,
      updated: 1,
      deduped: 1,
      rejected: 1,
      errors: [
        {
          index: 2,
          code: "CONFLICT",
          error: "conflict: already exists",
          existing_id: "row-abc",
        },
      ],
      deduped_rows: [{ index: 0, superseded_by: 1 }],
      updated_rows: [{ index: 3, superseded_by: "row-xyz" }],
      pending: [],
      warnings: ["quorum replication deferred"],
    };
    const { fetchImpl } = capture(envelope, 207);
    const client = new AiMemoryClient(
      { baseUrl: "http://localhost:9077" },
      fetchImpl,
    );

    const res = await client.storeBulk([
      { title: "a", content: "one" },
      { title: "b", content: "two" },
      { title: "c", content: "three" },
      { title: "d", content: "four" },
    ]);

    // Reconciliation identity the module docs promise.
    expect(res.created + res.updated + res.deduped + res.rejected + res.pending.length).toBe(
      res.sent,
    );
    expect(res.rejected).toBe(1);
    expect(res.errors[0]).toMatchObject({ index: 2, code: "CONFLICT", existing_id: "row-abc" });
    expect(res.deduped_rows).toEqual([{ index: 0, superseded_by: 1 }]);
    expect(res.updated_rows).toEqual([{ index: 3, superseded_by: "row-xyz" }]);
    expect(res.warnings).toEqual(["quorum replication deferred"]);
  });
});

// ---------------------------------------------------------------------------
// Live integration tests — opt-in via AI_MEMORY_TEST_DAEMON=1.
// ---------------------------------------------------------------------------

describeIntegration("AiMemoryClient (live daemon)", () => {
  const client = new AiMemoryClient({
    baseUrl: BASE_URL,
    apiKey: process.env.AI_MEMORY_TEST_API_KEY,
    agentId: "sdk-test-agent",
  });

  let createdId: string | undefined;

  test("health", async () => {
    const h = await client.health();
    expect(["ok", "error"]).toContain(h.status);
  });

  test("store + get + delete round-trip", async () => {
    const created = await client.store({
      title: `sdk-test-${Date.now()}`,
      content: "integration test memory",
      tier: "short",
      namespace: "sdk-tests",
      tags: ["sdk", "test"],
    });
    expect(created.id).toBeDefined();
    createdId = created.id;

    const fetched = await client.get(created.id);
    expect(fetched.id).toBe(created.id);
    expect(fetched.title).toBe(created.title);

    const del = await client.delete(created.id);
    expect(del.deleted).toBe(true);
    createdId = undefined;
  });

  test("validation error maps to ValidationError", async () => {
    await expect(
      client.store({ title: "", content: "empty title fails" }),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  test("not found maps to NotFoundError", async () => {
    await expect(client.get("does-not-exist-xyz")).rejects.toBeInstanceOf(
      NotFoundError,
    );
  });

  test("recall returns scored results", async () => {
    const stored = await client.store({
      title: "recall test fixture",
      content: "the quick brown fox jumps over the lazy dog",
      namespace: "sdk-tests",
    });
    try {
      const r = await client.recall({
        context: "quick fox",
        namespace: "sdk-tests",
        limit: 5,
      });
      expect(Array.isArray(r.memories)).toBe(true);
      expect(typeof r.tokens_used).toBe("number");
    } finally {
      await client.delete(stored.id);
    }
  });

  test("search", async () => {
    const r = await client.search({ q: "test", namespace: "sdk-tests", limit: 5 });
    expect(Array.isArray(r.results)).toBe(true);
    expect(r.query).toBe("test");
  });

  test("stats", async () => {
    const s = await client.stats();
    expect(typeof s.total).toBe("number");
    expect(Array.isArray(s.by_tier)).toBe(true);
  });

  afterAll(async () => {
    if (createdId) {
      try {
        await client.delete(createdId);
      } catch {
        // best-effort
      }
    }
  });
});
