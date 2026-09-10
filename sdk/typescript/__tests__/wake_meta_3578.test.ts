// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/** Shared binary codec pins; no live-hub or JSON-input claim (#3578). */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { decodeFrame, decodeWakeMeta, encodeFrame, Kind, WakeError } from "../src/wake.js";

interface Vector {
  name: string;
  hex: string;
  expected: {
    inbox_row_id: string;
    namespace: string;
    sender: string;
    digest: string;
    seq_high_watermark: number;
  };
}

const vectors: { allowed: Vector[]; denied: Vector[]; reserved_kinds: number[] } =
  JSON.parse(readFileSync(resolve(__dirname, "../../fixtures/wake_meta_3578.json"), "utf8"));

test("allowed vectors have exactly five fields #3578", () => {
  expect(vectors.allowed).toHaveLength(4);
  for (const { hex, expected } of vectors.allowed) {
    expect(decodeWakeMeta(Buffer.from(hex, "hex"))).toEqual({
      inboxRowId: expected.inbox_row_id,
      namespace: expected.namespace,
      sender: expected.sender,
      digestHex: expected.digest,
      seqHighWatermark: expected.seq_high_watermark,
    });
  }
});

test("exact 256-byte boundary and 257-byte refusal #3578", () => {
  const raw = Buffer.from(vectors.allowed[2]!.hex, "hex");
  expect(raw).toHaveLength(256);
  expect(decodeWakeMeta(raw).sender).toBe("s".repeat(84));
  expect(() => decodeWakeMeta(Buffer.concat([raw, Buffer.from([0])]))).toThrow(/ceiling/);
});

test("appended content/title and other denied vectors #3578", () => {
  expect(vectors.denied).toHaveLength(5);
  for (const { hex } of vectors.denied) {
    expect(() => decodeWakeMeta(Buffer.from(hex, "hex"))).toThrow(WakeError);
  }
});

test("every truncation is refused #3578", () => {
  for (const { hex } of vectors.allowed) {
    const raw = Buffer.from(hex, "hex");
    for (let end = 0; end < raw.length; end += 1) {
      expect(() => decodeWakeMeta(raw.subarray(0, end))).toThrow(WakeError);
    }
  }
});

test("reserved body kinds with allowed control #3578", () => {
  const frame = {
    kind: Kind.Wake,
    from: "producer",
    to: "ai:alice",
    payload: Buffer.from(vectors.allowed[1]!.hex, "hex"),
    tsMs: 0,
    ttlMs: 0,
  };
  const raw = encodeFrame(frame);
  expect(decodeFrame(raw)).toEqual(frame);
  expect(vectors.reserved_kinds).toEqual([11, 12, 13]);
  for (const kind of vectors.reserved_kinds) {
    const denied = Buffer.from(raw);
    denied[5] = kind;
    expect(() => decodeFrame(denied)).toThrow(/permanently reserved/);
  }
});
