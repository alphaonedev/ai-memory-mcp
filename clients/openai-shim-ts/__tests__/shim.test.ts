// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Shim behavior tests. Offline (always run) — DI'd fake client + capture spy.
import { test } from "node:test";
import assert from "node:assert/strict";

import { wrap, type CaptureTurnParams } from "../src/index.ts";

function textResponse(): Record<string, unknown> {
  return {
    choices: [{ message: { role: "assistant", content: "Paris is the capital of France." } }],
  };
}

function fakeClient(response: unknown): Record<string, unknown> {
  return {
    apiKey: "sk-fake",
    chat: {
      completions: {
        create(_kwargs: Record<string, unknown>): Promise<unknown> {
          return Promise.resolve(response);
        },
      },
    },
  };
}

function spyOpts(spy: CaptureTurnParams[], extra: Record<string, unknown> = {}) {
  return {
    ...extra,
    captureFn: (p: CaptureTurnParams): boolean => {
      spy.push(p);
      return true;
    },
  };
}

type Completions = { create: (a: unknown) => Promise<unknown> };
function completions(client: Record<string, unknown>): Completions {
  return (client.chat as { completions: Completions }).completions;
}

test("records user then assistant and passes response through", async () => {
  const resp = textResponse();
  const spy: CaptureTurnParams[] = [];
  const client = wrap(fakeClient(resp), spyOpts(spy, { hostSessionId: "s1" }));
  const out = await completions(client).create({
    model: "gpt-4o",
    messages: [{ role: "user", content: "capital of France?" }],
  });
  assert.equal(out, resp); // passthrough identity
  assert.deepEqual(
    spy.map((c) => c.role),
    ["user", "assistant"],
  );
  assert.equal(spy[0].content, "capital of France?");
  assert.equal(spy[1].content, "Paris is the capital of France.");
  assert.deepEqual([spy[0].hostTurnIndex, spy[1].hostTurnIndex], [0, 1]);
  assert.equal(spy[0].hostSessionId, "s1");
});

test("delegates unknown properties", () => {
  const spy: CaptureTurnParams[] = [];
  const client = wrap(fakeClient(textResponse()), spyOpts(spy));
  assert.equal(client.apiKey, "sk-fake");
});

test("non-wedging when capture throws", async () => {
  const resp = textResponse();
  const client = wrap(fakeClient(resp), {
    captureFn: () => {
      throw new Error("substrate down");
    },
  });
  const out = await completions(client).create({ messages: [{ role: "user", content: "hi" }] });
  assert.equal(out, resp);
});

test("streaming records request only", () => {
  const spy: CaptureTurnParams[] = [];
  const client = wrap(fakeClient(textResponse()), spyOpts(spy));
  completions(client).create({ stream: true, messages: [{ role: "user", content: "stream me" }] });
  assert.deepEqual(
    spy.map((c) => c.role),
    ["user"],
  );
});

test("monotonic turn indices, stable session across calls", async () => {
  const spy: CaptureTurnParams[] = [];
  const client = wrap(fakeClient(textResponse()), spyOpts(spy));
  const create = completions(client).create;
  await create({ messages: [{ role: "user", content: "one" }] });
  await create({ messages: [{ role: "user", content: "two" }] });
  assert.deepEqual(
    spy.map((c) => c.hostTurnIndex),
    [0, 1, 2, 3],
  );
  assert.equal(new Set(spy.map((c) => c.hostSessionId)).size, 1);
});
