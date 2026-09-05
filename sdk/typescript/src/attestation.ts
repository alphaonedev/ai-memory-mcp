// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Ed25519 agent-attestation signing for the HTTP store path (#626 / #2455).
 *
 * ## Why this module exists
 *
 * `POST /api/v1/memories` is classified `WriteSurface::HttpDirect`, which
 * **fails closed by default** (`src/identity/attest.rs:130-136` — the `_` arm
 * of `resolve_require_agent_attestation` returns `true` for `HttpDirect` when
 * the env var is unset). An unsigned HTTP store is answered with
 * `403 ATTESTATION_FAILED`.
 *
 * Before #2455 this SDK shipped no signing helper and `CreateMemoryRequest`
 * carried no `signature` / `created_at` fields, so `client.store()` could not
 * succeed against a stock daemon at all. This module closes that: it
 * reproduces the daemon's `SignableWrite` envelope byte-for-byte and signs it,
 * so the SDK works against the **shipped fail-closed default** rather than
 * requiring the operator to weaken the daemon with
 * `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=0`.
 *
 * ## The envelope
 *
 * Ed25519 over the RFC 8949 4.2.1 deterministic-CBOR encoding of exactly seven
 * entries (`src/identity/sign.rs::canonical_cbor_write`):
 *
 * | key                | value                                              |
 * | ------------------ | -------------------------------------------------- |
 * | `_dst`             | domain tag, always `"ai-memory/write/v1"`           |
 * | `kind`             | memory kind (`"observation"`, `"decision"`, ...)    |
 * | `title`            | memory title                                        |
 * | `agent_id`         | the claiming agent id                               |
 * | `namespace`        | target namespace                                    |
 * | `created_at`       | RFC3339 timestamp the caller signed                 |
 * | `content_sha256`   | SHA-256 of content UTF-8 bytes (CBOR byte string)   |
 *
 * Map keys are emitted in encoded-key sort order (length first, then
 * bytewise), which for this fixed key set is the order shown. Byte-level
 * agreement with the Rust encoder is pinned by a fixture printed by the Rust
 * encoder itself — `sdk/fixtures/write_attestation_vector.json`, asserted in
 * `__tests__/attestation.test.ts`.
 *
 * ## Enrolling the key
 *
 * A signature only attests if the daemon has the matching public key bound to
 * the agent. Bind it before signing writes with
 * `client.bindAgentPubkey(agentId, signingKey)`. This issues an admin-gated
 * `POST /api/v1/agents/{id}/pubkey/challenge`, signs its transcript, and answers
 * `PUT /api/v1/agents/{id}/pubkey` with `{pubkey_b64, nonce, proof_b64}`.
 * A bare public key is insufficient.
 * Without a bound key the daemon cannot verify and still returns 403
 * (fail-closed, by design).
 *
 * ## Known limits (stated rather than hidden)
 *
 * - The daemon redacts secret-screened content *before* verifying
 *   (`identity::attest::redact_before_sign`). Content that trips the
 *   credential screen under `AI_MEMORY_SECRET_SCREEN_MODE=redact` verifies
 *   against different bytes than you signed and is refused; under the default
 *   `refuse` mode it is rejected earlier anyway. Do not put credentials in
 *   memories.
 * - `created_at` must be inside the daemon's +/-300s attestation freshness
 *   window (`ATTEST_CREATED_AT_SKEW_SECS`); sign shortly before sending.
 * - The signature commits to those six fields ONLY — not tags, priority, or
 *   metadata.
 *
 * Uses Node's built-in `node:crypto` — no third-party crypto dependency.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";

/** The `_dst` domain-separation value for the write envelope (#1931). */
export const DOMAIN_SEPARATION_TAG = "ai-memory/write/v1";

/** Length of an Ed25519 seed / public key in bytes. */
const KEY_LEN = 32;

// DER scaffolding for raw-seed <-> KeyObject conversion. Ed25519 PKCS#8 and
// SPKI encodings are fixed-length, so a constant prefix + the 32 raw bytes is
// the whole structure (RFC 8410).
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// ---------------------------------------------------------------------------
// Deterministic CBOR (RFC 8949 4.2.1) — only the shapes this envelope needs.
// ---------------------------------------------------------------------------

function cborHead(major: number, length: number): Buffer {
  const prefix = major << 5;
  if (length < 24) return Buffer.from([prefix | length]);
  if (length < 0x100) return Buffer.from([prefix | 24, length]);
  if (length < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = prefix | 25;
    b.writeUInt16BE(length, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = prefix | 26;
  b.writeUInt32BE(length, 1);
  return b;
}

function cborText(value: string): Buffer {
  const raw = Buffer.from(value, "utf8");
  return Buffer.concat([cborHead(3, raw.length), raw]);
}

function cborBytes(value: Buffer): Buffer {
  return Buffer.concat([cborHead(2, value.length), value]);
}

/** SHA-256 over the UTF-8 bytes of `content` (the bounded commitment). */
export function contentSha256(content: string): Buffer {
  return createHash("sha256").update(content, "utf8").digest();
}

/** Fields the write signature commits to. */
export interface SignableWrite {
  agentId: string;
  namespace: string;
  title: string;
  /** Memory kind discriminant, e.g. `"observation"` / `"decision"`. */
  kind: string;
  /** RFC3339 timestamp; must match the `created_at` sent on the wire. */
  createdAt: string;
  /** 32-byte SHA-256 digest from {@link contentSha256}. */
  contentSha256: Buffer;
}

/**
 * Deterministic-CBOR encoding of the `SignableWrite` envelope.
 *
 * Byte-identical to `crate::identity::sign::canonical_cbor_write`.
 *
 * @throws {RangeError} if `contentSha256` is not exactly 32 bytes.
 */
export function canonicalCborWrite(write: SignableWrite): Buffer {
  if (write.contentSha256.length !== KEY_LEN) {
    throw new RangeError(
      `contentSha256 must be a 32-byte SHA-256 digest, got ${write.contentSha256.length}`,
    );
  }
  // RFC 8949 4.2.1 orders map keys by their ENCODED bytes: shorter keys first,
  // then bytewise. For this fixed key set that is the literal order below
  // ('_' 0x5F sorts before 'k' 0x6B at length 4). Hard-coding the resolved
  // order keeps the encoder simple and makes any future key addition an
  // explicit, reviewable re-ordering rather than a silent one. The order is
  // pinned against the Rust-emitted fixture.
  const entries: Array<[string, Buffer]> = [
    ["_dst", cborText(DOMAIN_SEPARATION_TAG)],
    ["kind", cborText(write.kind)],
    ["title", cborText(write.title)],
    ["agent_id", cborText(write.agentId)],
    ["namespace", cborText(write.namespace)],
    ["created_at", cborText(write.createdAt)],
    ["content_sha256", cborBytes(write.contentSha256)],
  ];
  const parts: Buffer[] = [cborHead(5, entries.length)];
  for (const [key, encodedValue] of entries) {
    parts.push(cborText(key), encodedValue);
  }
  return Buffer.concat(parts);
}

/** RFC3339 date-time, decomposed so the fraction survives `Date`'s millisecond floor. */
const RFC3339_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$/;

/**
 * Canonicalize an RFC3339 timestamp into the ONE `created_at` rendering both
 * daemon storage backends return byte-for-byte (#3422).
 *
 * The daemon REFUSES to attest any other rendering. `created_at` is inside the
 * signed `SignableWrite` envelope as TEXT, and every re-verification (the store
 * gate, and the federation receive path on a relayed row) rebuilds the envelope
 * from the PERSISTED row: SQLite returns the stored TEXT verbatim, while
 * PostgreSQL stores `TIMESTAMPTZ` (microseconds) and re-renders the readback as
 * `+00:00`. A signature minted over `"…Z"`, over a non-UTC offset, or over
 * nanosecond precision could therefore never be re-derived from a Postgres row.
 *
 * Canonical form: UTC, `+00:00` offset, microseconds TRUNCATED (never rounded —
 * that is what `TIMESTAMPTZ` does), and 0, 3 or 6 fractional digits — the
 * shortest width that represents the value exactly, matching chrono's
 * `SecondsFormat::AutoSi`.
 *
 * @throws {RangeError} if `value` is not an RFC3339 date-time.
 */
export function canonicalizeCreatedAt(value: string): string {
  const m = RFC3339_PATTERN.exec(value.trim());
  if (m === null) {
    throw new RangeError(`created_at must be an RFC3339 date-time, got: ${value}`);
  }
  const [, year, month, day, hour, minute, second, fraction = "", offset] = m;
  // TIMESTAMPTZ keeps microseconds and drops the rest — truncate, never round.
  const micros = Number(`${fraction}000000`.slice(0, 6));
  let offsetMinutes = 0;
  if (offset !== "Z" && offset !== "z") {
    const sign = offset.startsWith("-") ? -1 : 1;
    offsetMinutes = sign * (Number(offset.slice(1, 3)) * 60 + Number(offset.slice(4, 6)));
  }
  // Build via the UTC setters rather than `Date.UTC`, whose two-digit-year
  // legacy mapping would turn year 0099 into 1999.
  const moment = new Date(0);
  moment.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  moment.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  const whole = new Date(moment.getTime() - offsetMinutes * 60_000)
    .toISOString()
    .slice(0, 19);
  let frac = "";
  if (micros !== 0) {
    frac =
      micros % 1000 === 0
        ? `.${String(micros / 1000).padStart(3, "0")}`
        : `.${String(micros).padStart(6, "0")}`;
  }
  return `${whole}${frac}+00:00`;
}

/**
 * Current UTC time in the canonical `created_at` form the daemon persists and
 * re-derives signatures from (#3422) — UTC, `+00:00`, microsecond-truncated.
 *
 * (`Date#toISOString` emits `Z` with a fixed 3-digit fraction; both the suffix
 * and a `.000` fraction are rejected by the daemon's attestation funnel, since
 * neither survives a PostgreSQL `TIMESTAMPTZ` round-trip unchanged.)
 */
export function rfc3339Now(date: Date = new Date()): string {
  return canonicalizeCreatedAt(date.toISOString());
}

// ---------------------------------------------------------------------------
// Key handling
// ---------------------------------------------------------------------------

function decodeBase64Any(value: string): Buffer {
  const raw = value.trim();
  // Buffer's base64 decoder accepts both alphabets and tolerates missing pad.
  return Buffer.from(raw, "base64");
}

/**
 * An Ed25519 signing key for agent write attestation.
 *
 * Wraps a 32-byte seed — the exact on-disk format the daemon's own key store
 * uses (`<key_dir>/<agent_id>.priv`, 32 raw bytes, mode 0600) — so a key made
 * by `ai-memory identity generate` loads directly with {@link fromSeed}.
 */
export class AgentSigningKey {
  private readonly key: KeyObject;

  private constructor(key: KeyObject) {
    this.key = key;
  }

  /** Build from the raw 32-byte seed (the `<agent_id>.priv` file contents). */
  static fromSeed(seed: Uint8Array): AgentSigningKey {
    if (seed.length !== KEY_LEN) {
      throw new RangeError(`Ed25519 seed must be 32 bytes, got ${seed.length}`);
    }
    const der = Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]);
    return new AgentSigningKey(
      createPrivateKey({ key: der, format: "der", type: "pkcs8" }),
    );
  }

  /** Build from a base64 seed (standard or URL-safe, padded or not). */
  static fromBase64(seedB64: string): AgentSigningKey {
    return AgentSigningKey.fromSeed(decodeBase64Any(seedB64));
  }

  /** Generate a fresh key from the OS CSPRNG. */
  static generate(): AgentSigningKey {
    return AgentSigningKey.fromSeed(randomBytes(KEY_LEN));
  }

  /** The raw 32-byte Ed25519 public key. */
  publicKeyBytes(): Buffer {
    const spki = createPublicKey(this.key).export({
      format: "der",
      type: "spki",
    });
    return Buffer.from(spki.subarray(SPKI_PREFIX.length));
  }

  /**
   * URL-safe, unpadded base64 public key.
   *
   * The form `PUT /api/v1/agents/{id}/pubkey` expects in its `pubkey_b64`
   * body field, matching `AgentKeypair::public_base64`.
   */
  publicKeyBase64(): string {
    return this.publicKeyBytes().toString("base64url");
  }

  /** Raw 64-byte Ed25519 signature over `payload`. */
  sign(payload: Buffer): Buffer {
    return cryptoSign(null, payload, this.key);
  }
}

// ---------------------------------------------------------------------------
// #3464 — proof of possession for agent public-key binding
// ---------------------------------------------------------------------------

/**
 * Domain tag for the bind-challenge transcript. Distinct from every other
 * signing domain in the substrate, so a signature minted for a write, a link,
 * a lineage record or a sub-key cert can never be replayed as a possession
 * proof.
 */
export const BIND_CHALLENGE_V1_DOMAIN = "ai-memory/bind-pubkey/v1";

/**
 * The exact bytes a candidate key must sign to prove possession.
 *
 * Domain-separated and LENGTH-PREFIXED, so no field boundary can be shifted to
 * make one transcript read as another (`agentId="a", pubkey="bc"` and
 * `agentId="ab", pubkey="c"` produce different bytes). Mirrors
 * `crate::identity::pubkey_bind::bind_challenge_transcript` byte for byte.
 */
export function bindChallengeTranscript(input: {
  agentId: string;
  pubkeyB64: string;
  nonce: string;
  expiresAt: string;
}): Buffer {
  const parts: Buffer[] = [Buffer.from(BIND_CHALLENGE_V1_DOMAIN, "utf8")];
  for (const field of [input.agentId, input.pubkeyB64, input.nonce, input.expiresAt]) {
    const raw = Buffer.from(field, "utf8");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(raw.length, 0);
    parts.push(len, raw);
  }
  return Buffer.concat(parts);
}

/**
 * Answer a bind challenge; returns the URL-safe-unpadded base64 proof.
 *
 * The public key is derived from `key`, so this can only ever produce a proof
 * for a key the caller actually holds.
 */
export function signBindChallenge(
  key: AgentSigningKey,
  input: { agentId: string; nonce: string; expiresAt: string },
): string {
  const transcript = bindChallengeTranscript({
    agentId: input.agentId,
    pubkeyB64: key.publicKeyBase64(),
    nonce: input.nonce,
    expiresAt: input.expiresAt,
  });
  return key.sign(transcript).toString("base64url");
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/** Inputs to {@link signWrite} / {@link attestationFields}. */
export interface AttestationInput {
  agentId: string;
  namespace: string;
  title: string;
  content: string;
  /** Defaults to `"observation"` — the daemon's default when absent. */
  kind?: string;
  /** Defaults to now. Must be the SAME string sent on the wire. */
  createdAt?: string;
}

/**
 * Sign a write envelope and return the STANDARD-base64 signature.
 *
 * Standard (not URL-safe) base64 is what `prepare_signed_store` decodes from
 * the `signature` wire field (`src/identity/attest.rs:194`).
 */
export function signWrite(
  key: AgentSigningKey,
  input: Required<Pick<AttestationInput, "agentId" | "namespace" | "title" | "content" | "kind" | "createdAt">>,
): string {
  const envelope = canonicalCborWrite({
    agentId: input.agentId,
    namespace: input.namespace,
    title: input.title,
    kind: input.kind,
    createdAt: input.createdAt,
    contentSha256: contentSha256(input.content),
  });
  return key.sign(envelope).toString("base64");
}

/** The three wire fields a signed store must carry. */
export interface AttestationFields {
  signature: string;
  created_at: string;
  kind: string;
}

/**
 * Build the `{signature, created_at, kind}` triple for a store request.
 *
 * The three keys drop straight into a `CreateMemoryRequest`. `created_at`
 * defaults to now — the daemon adopts the value verbatim after checking it
 * against the +/-300s freshness window, so it must be the SAME string that was
 * signed, which is why it is returned rather than left to the caller.
 *
 * #3422 — a caller-supplied `createdAt` is folded through
 * {@link canonicalizeCreatedAt} BEFORE signing, so the SDK always signs (and
 * sends) the exact string the daemon will store and later re-derive the
 * signature from on either backend.
 */
export function attestationFields(
  key: AgentSigningKey,
  input: AttestationInput,
): AttestationFields {
  const kind = input.kind ?? "observation";
  const createdAt =
    input.createdAt === undefined ? rfc3339Now() : canonicalizeCreatedAt(input.createdAt);
  return {
    signature: signWrite(key, {
      agentId: input.agentId,
      namespace: input.namespace,
      title: input.title,
      content: input.content,
      kind,
      createdAt,
    }),
    created_at: createdAt,
    kind,
  };
}
