// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Write-attestation conformance against a RUST-GENERATED vector (#2455).
 *
 * `POST /api/v1/memories` is `WriteSurface::HttpDirect` and fails CLOSED by
 * default, so before #2455 `client.store()` could not succeed at all against
 * a stock daemon: `CreateMemoryRequest` had no `signature` / `created_at`
 * fields and the SDK shipped no Ed25519 helper.
 *
 * The load-bearing assertion is byte-equality of the canonical CBOR envelope
 * with the one the RUST encoder emits
 * (`sdk/fixtures/write_attestation_vector.json`). An SDK that signs a
 * *different* byte sequence than the daemon verifies produces a 403 that looks
 * like a key-enrollment problem, so a self-computed "expected" value would
 * prove nothing.
 *
 * The Ed25519 primitive itself is pinned against RFC 8032 section 7.1 TEST 3 —
 * an external authority, independent of ai-memory.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  AgentSigningKey,
  DOMAIN_SEPARATION_TAG,
  attestationFields,
  canonicalCborWrite,
  canonicalizeCreatedAt,
  contentSha256,
  rfc3339Now,
  signWrite,
} from "../src/attestation.js";
import { AiMemoryClient } from "../src/client.js";

interface AttestationVector {
  domain_separation_tag: string;
  agent_id: string;
  namespace: string;
  title: string;
  kind: string;
  created_at: string;
  content: string;
  content_sha256_hex: string;
  canonical_cbor_hex: string;
  rfc8032_test3: {
    seed_hex: string;
    public_key_hex: string;
    message_hex: string;
    signature_hex: string;
  };
}

const vector: AttestationVector = JSON.parse(
  readFileSync(
    resolve(__dirname, "..", "..", "fixtures", "write_attestation_vector.json"),
    "utf8",
  ),
) as AttestationVector;

function envelope(overrides: Partial<{
  agentId: string;
  namespace: string;
  title: string;
  kind: string;
  createdAt: string;
  content: string;
}> = {}): Buffer {
  return canonicalCborWrite({
    agentId: overrides.agentId ?? vector.agent_id,
    namespace: overrides.namespace ?? vector.namespace,
    title: overrides.title ?? vector.title,
    kind: overrides.kind ?? vector.kind,
    createdAt: overrides.createdAt ?? vector.created_at,
    contentSha256: contentSha256(overrides.content ?? vector.content),
  });
}

describe("attestation envelope — Rust conformance (#2455)", () => {
  test("content hash matches Rust", () => {
    expect(contentSha256(vector.content).toString("hex")).toBe(
      vector.content_sha256_hex,
    );
  });

  test("canonical CBOR is byte-identical to Rust", () => {
    expect(envelope().toString("hex")).toBe(vector.canonical_cbor_hex);
  });

  test("domain separation tag matches Rust", () => {
    expect(DOMAIN_SEPARATION_TAG).toBe(vector.domain_separation_tag);
  });

  test("every signed field changes the envelope", () => {
    // A field silently dropped from the encoding would let a signature minted
    // for one write be replayed onto another.
    const baseline = envelope().toString("hex");
    expect(envelope({ agentId: "other" }).toString("hex")).not.toBe(baseline);
    expect(envelope({ namespace: "other" }).toString("hex")).not.toBe(baseline);
    expect(envelope({ title: "other" }).toString("hex")).not.toBe(baseline);
    expect(envelope({ kind: "other" }).toString("hex")).not.toBe(baseline);
    expect(envelope({ createdAt: "2020-01-01T00:00:00+00:00" }).toString("hex")).not.toBe(
      baseline,
    );
    expect(envelope({ content: "other" }).toString("hex")).not.toBe(baseline);
  });

  test("rejects a non-32-byte content hash", () => {
    expect(() =>
      canonicalCborWrite({
        agentId: vector.agent_id,
        namespace: vector.namespace,
        title: vector.title,
        kind: vector.kind,
        createdAt: vector.created_at,
        contentSha256: Buffer.from("too-short"),
      }),
    ).toThrow(RangeError);
  });
});

describe("Ed25519 primitive — RFC 8032 conformance", () => {
  const tv = vector.rfc8032_test3;

  test("derives the RFC 8032 TEST 3 public key", () => {
    const key = AgentSigningKey.fromSeed(Buffer.from(tv.seed_hex, "hex"));
    expect(key.publicKeyBytes().toString("hex")).toBe(tv.public_key_hex);
  });

  test("produces the RFC 8032 TEST 3 signature", () => {
    const key = AgentSigningKey.fromSeed(Buffer.from(tv.seed_hex, "hex"));
    expect(key.sign(Buffer.from(tv.message_hex, "hex")).toString("hex")).toBe(
      tv.signature_hex,
    );
  });

  test("publicKeyBase64 is URL-safe and unpadded", () => {
    // `PUT /agents/{id}/pubkey` expects the `AgentKeypair::public_base64` form.
    const key = AgentSigningKey.fromSeed(Buffer.from(tv.seed_hex, "hex"));
    const b64 = key.publicKeyBase64();
    expect(b64).not.toMatch(/[+/=]/);
    expect(Buffer.from(b64, "base64url").toString("hex")).toBe(tv.public_key_hex);
  });

  test("rejects a wrong-length seed", () => {
    expect(() => AgentSigningKey.fromSeed(Buffer.alloc(31))).toThrow(RangeError);
  });

  test("signature is STANDARD base64, 64 bytes", () => {
    // `prepare_signed_store` decodes STANDARD base64, not URL-safe.
    const key = AgentSigningKey.fromSeed(Buffer.from(tv.seed_hex, "hex"));
    const sig = signWrite(key, {
      agentId: vector.agent_id,
      namespace: vector.namespace,
      title: vector.title,
      content: vector.content,
      kind: vector.kind,
      createdAt: vector.created_at,
    });
    expect(Buffer.from(sig, "base64")).toHaveLength(64);
  });
});

describe("attestationFields", () => {
  test("signs the created_at it returns", () => {
    // The daemon adopts the wire `created_at` verbatim and re-derives the
    // envelope from it; a mismatch is an unexplainable 403.
    const key = AgentSigningKey.generate();
    const fields = attestationFields(key, {
      agentId: vector.agent_id,
      namespace: vector.namespace,
      title: vector.title,
      content: vector.content,
      kind: vector.kind,
    });
    expect(fields.signature).toBe(
      signWrite(key, {
        agentId: vector.agent_id,
        namespace: vector.namespace,
        title: vector.title,
        content: vector.content,
        kind: vector.kind,
        createdAt: fields.created_at,
      }),
    );
  });

  test("defaults kind to the server's default", () => {
    const key = AgentSigningKey.generate();
    const fields = attestationFields(key, {
      agentId: vector.agent_id,
      namespace: vector.namespace,
      title: vector.title,
      content: vector.content,
    });
    expect(fields.kind).toBe("observation");
  });

  test("rfc3339Now uses the +00:00 offset form", () => {
    expect(rfc3339Now()).toMatch(/\+00:00$/);
  });

  // -------------------------------------------------------------------------
  // #3422 - canonical, storage-stable created_at
  // -------------------------------------------------------------------------

  test.each([
    // `Z` suffix -> the `+00:00` form postgres returns.
    ["2026-09-01T12:00:00Z", "2026-09-01T12:00:00+00:00"],
    // Non-UTC offset -> the same instant, canonically rendered.
    ["2026-09-01T14:00:00+02:00", "2026-09-01T12:00:00+00:00"],
    // Already canonical -> unchanged (fixpoint).
    ["2026-09-01T12:00:00+00:00", "2026-09-01T12:00:00+00:00"],
    // Sub-microsecond digits cannot survive TIMESTAMPTZ: truncated.
    ["2026-09-01T12:00:00.123456789Z", "2026-09-01T12:00:00.123456+00:00"],
    // AutoSi widths: 0, 3 or 6 digits - the shortest exact rendering.
    ["2026-09-01T12:00:00.000Z", "2026-09-01T12:00:00+00:00"],
    ["2026-09-01T12:00:00.100000Z", "2026-09-01T12:00:00.100+00:00"],
    ["2026-09-01T12:00:00.123400Z", "2026-09-01T12:00:00.123400+00:00"],
  ])("canonicalizeCreatedAt(%s) === %s", (raw, expected) => {
    expect(canonicalizeCreatedAt(raw)).toBe(expected);
    // Idempotent: the canonical form is its own fixpoint.
    expect(canonicalizeCreatedAt(expected)).toBe(expected);
  });

  test("canonicalizeCreatedAt rejects a non-RFC3339 stamp", () => {
    expect(() => canonicalizeCreatedAt("2026-09-01 noon")).toThrow(RangeError);
  });

  test("rfc3339Now is storage-stable (its own fixpoint)", () => {
    const now = rfc3339Now();
    expect(canonicalizeCreatedAt(now)).toBe(now);
  });

  test("attestationFields signs the canonical created_at (#3422)", () => {
    const key = AgentSigningKey.generate();
    const fields = attestationFields(key, {
      agentId: "ai:sdk-demo@example",
      namespace: "team/alpha",
      title: "pg upgrade window",
      content: "body",
      createdAt: "2026-09-01T12:00:00Z",
    });
    expect(fields.created_at).toBe("2026-09-01T12:00:00+00:00");
    expect(fields.signature).toBe(
      signWrite(key, {
        agentId: "ai:sdk-demo@example",
        namespace: "team/alpha",
        title: "pg upgrade window",
        content: "body",
        kind: "observation",
        createdAt: "2026-09-01T12:00:00+00:00",
      }),
    );
  });
});

describe("client.store signing", () => {
  function captureClient(): { client: AiMemoryClient; sent: () => unknown } {
    let body: unknown;
    const fetchImpl = (async (_url: string, init: { body?: string }) => {
      body = JSON.parse(init.body ?? "{}");
      return {
        ok: true,
        status: 201,
        headers: new Map([["content-type", "application/json"]]) as unknown as Headers,
        json: async () => ({ id: "m1" }),
        text: async () => "{}",
      };
    }) as never;
    const client = new AiMemoryClient({ baseUrl: "http://localhost:9077" }, fetchImpl);
    return { client, sent: () => body };
  }

  test("signs the namespace and kind it actually sends", async () => {
    const key = AgentSigningKey.generate();
    const { client, sent } = captureClient();
    await client.store(
      { title: "t", content: "c", agent_id: "svc" },
      { signingKey: key },
    );
    const body = sent() as Record<string, string>;
    expect(body.namespace).toBe("global");
    expect(body.kind).toBe("observation");
    expect(body.signature).toBe(
      signWrite(key, {
        agentId: "svc",
        namespace: "global",
        title: "t",
        content: "c",
        kind: "observation",
        createdAt: body.created_at,
      }),
    );
  });

  test("refuses to sign without an agent_id", async () => {
    const { client } = captureClient();
    await expect(
      client.store({ title: "t", content: "c" }, { signingKey: AgentSigningKey.generate() }),
    ).rejects.toThrow(TypeError);
  });

  test("refuses both a signingKey and an explicit signature", async () => {
    const { client } = captureClient();
    await expect(
      client.store(
        { title: "t", content: "c", agent_id: "svc", signature: "AAAA" },
        { signingKey: AgentSigningKey.generate() },
      ),
    ).rejects.toThrow(TypeError);
  });

  test("unsigned store sends no attestation fields", async () => {
    const { client, sent } = captureClient();
    await client.store({ title: "t", content: "c" });
    const body = sent() as Record<string, unknown>;
    expect(body.signature).toBeUndefined();
    expect(body.created_at).toBeUndefined();
  });
});
