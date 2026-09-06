// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Minimal `ai-memory wake-hub` client (issue #3470, EPIC #3466).
 *
 * ## Why this module exists
 *
 * Before the wake plane, an agent learned it had mail by polling
 * `GET /api/v1/inbox`. The reference fleet polled every three minutes. This is
 * the TypeScript half of the replacement: keep ONE authenticated session on
 * the hub's Unix domain socket and read the inbox when there is something to
 * read — with a bounded `<= 60 s` poll so a lost hub degrades LATENCY and
 * nothing else.
 *
 * ## What it carries, and what it cannot
 *
 * The hub is CONTENT-FREE by construction: the v1 protocol has no `request` /
 * `reply` / `notify` kinds, and the largest routed payload is a 256-byte hint
 * `{inbox_row_id, namespace, sender, digest, seq_high_watermark}`. A wake
 * tells you WHICH row to read and gives you a SHA-256 to verify it against;
 * the durable ai-memory inbox row is the record, and reading it is your job
 * ({@link AiMemoryClient.inbox}).
 *
 * ## One identity root
 *
 * This client embeds NO identity of its own. It loads the scoped
 * `a2a-hub/join/v1` delegation bundle that
 * `ai-memory identity delegate --scope a2a-hub` writes into the agent's key
 * directory (`<key-dir>/<agent-id>.a2a-hub.json`, mode 0600). That bundle
 * holds a DELEGATED private key and never the agent's enrolled one, so a
 * compromised listener is worth "someone may be woken as me until this
 * expires", never "someone may write my history". It never reads an enrolled
 * `.priv`, never generates key material, and never writes a key.
 *
 * Every check {@link DelegationBundle.load} performs is a REFUSAL, and there
 * is deliberately no flag that skips one: mode 0600, caller-owned, not a
 * symlink, a version this build understands, scope `a2a-hub`, the bundle's own
 * principal, THIS hub's id, a private key that is the one the certificate
 * authorises, and a window that contains now.
 *
 * **Stated honestly:** the certificate's ISSUER SIGNATURE — the proof that the
 * agent's enrolled key minted it — is verified authoritatively by the HUB, and
 * additionally pre-checked locally by the Rust `ai-memory wake-listen`. This
 * SDK does not reproduce the canonical-CBOR pre-image, so it does not
 * re-verify that signature. That is a DEGRADE, never a widening: this client
 * can present a bundle the hub then refuses, but it can never admit one the
 * hub would refuse.
 *
 * ## Exactly one catch-up read per event
 *
 * {@link WakeListener} never reads your inbox for you; it emits a signal you
 * handle, exactly ONCE per event — on the welcome, on each wake, when the
 * welcome reports `lagged`, and when a wake's `seq_high_watermark` skips
 * (wakes happened that you did not see). Never a read per queued hint.
 *
 * ## The backstop is always armed
 *
 * The bounded poll runs whether or not the hub is reachable, and its clock is
 * reset by every catch-up read rather than firing on a fixed schedule. A hub
 * that is down, refusing, or was never deployed therefore costs latency only,
 * bounded by {@link BACKSTOP_POLL_MAX_MS}. A `pollIntervalMs` above that bound
 * is REFUSED rather than clamped: a client that silently polled less often
 * than the plane's contract would be reporting a guarantee it does not
 * provide. Reconnects use jittered exponential backoff capped at the same
 * bound, so a hub restart cannot produce a synchronised reconnect blast.
 *
 * Uses Node's built-in `node:net` / `node:crypto` / `node:fs` — no
 * third-party dependency.
 */

import { createHash } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { connect as netConnect, type Socket } from "node:net";
import { join } from "node:path";

import { AgentSigningKey } from "./attestation.js";

/**
 * Normative maximum interval between inbox reads
 * (`wake_sink::BACKSTOP_POLL_MAX`). A wake-plane client MUST read at least
 * this often: the hub holds no durable truth, so this poll — not the hint —
 * is the delivery guarantee.
 */
export const BACKSTOP_POLL_MAX_MS = 60_000;

/** Compiled default hub identifier (`wake_hub::DEFAULT_HUB_ID`). */
export const DEFAULT_HUB_ID = "ai-memory-wake-hub";

const MAGIC = Buffer.from("AWH1", "ascii");
const WIRE_VERSION = 1;
const FRAME_HEADER_BYTES = 24;
const MAX_FRAME_BYTES = FRAME_HEADER_BYTES + 2 * 128 + 1536;
const HELLO_NONCE_BYTES = 32;
const SIGNATURE_BYTES = 64;
const WAKE_DIGEST_BYTES = 32;
const MAX_WAKE_META_BYTES = 256;
const WELCOME_BYTES = 4 + 8 + 4 + 1 + 4 + 4;
const HELLO_TRANSCRIPT_DOMAIN = Buffer.from("a2a/v1/hello", "ascii");
const A2A_HUB_SCOPE = "a2a-hub";
const DELEGATION_WIRE_VERSION = 1;
const DELEGATE_KEY_ID_BYTES = 32;
const BUNDLE_VERSION = 1;
const HANDSHAKE_TIMEOUT_MS = 5_000;
const DEFAULT_RECONNECT_BASE_MS = 250;
const DEFAULT_RECONNECT_JITTER_MS = 750;
/**
 * A session must LAST this long before the reconnect ladder resets, so a hub
 * that accepts and instantly drops cannot become a hot loop.
 */
const HEALTHY_SESSION_MS = 30_000;

/** A refusal from the wake plane. Every one of these is fail-closed. */
export class WakeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WakeError";
  }
}

/** Frame kinds the v1 protocol admits. There is no body kind. */
export const Kind = {
  Hello: 1,
  Welcome: 2,
  Join: 3,
  Depart: 4,
  Subscribe: 5,
  Unsubscribe: 6,
  Wake: 7,
  Ping: 8,
  Pong: 9,
  Error: 10,
} as const;

export type KindValue = (typeof Kind)[keyof typeof Kind];

/**
 * Wire numbers permanently reserved for the removed body-bearing kinds. A
 * peer that sends one is refused BY NAME rather than ignored, so a client
 * built against the pre-vote draft fails closed with a legible error.
 */
export const RESERVED_PAYLOAD_KINDS: readonly number[] = [11, 12, 13];

/** One decoded wake-hub frame. */
export interface Frame {
  kind: number;
  from: string;
  to: string;
  payload: Buffer;
  tsMs: number;
  ttlMs: number;
}

/** Encode a frame body (the codec adds the length prefix). */
export function encodeFrame(frame: {
  kind: number;
  from: string;
  to: string;
  payload: Buffer;
  tsMs?: number;
  ttlMs?: number;
}): Buffer {
  const from = Buffer.from(frame.from, "utf8");
  const to = Buffer.from(frame.to, "utf8");
  if (from.length > 128 || to.length > 128) {
    throw new WakeError("an agent id may not exceed 128 bytes");
  }
  if (frame.payload.length > 0xffff) {
    throw new WakeError("payload exceeds the u16 length field");
  }
  const head = Buffer.alloc(FRAME_HEADER_BYTES);
  MAGIC.copy(head, 0);
  head[4] = WIRE_VERSION;
  head[5] = frame.kind;
  head[6] = 0;
  head[7] = from.length;
  head[8] = to.length;
  head[9] = 0;
  head.writeUInt16BE(frame.payload.length, 10);
  head.writeBigUInt64BE(BigInt(frame.tsMs ?? 0), 12);
  head.writeUInt32BE(frame.ttlMs ?? 0, 20);
  return Buffer.concat([head, from, to, frame.payload]);
}

/** Decode a frame body, refusing every malformed or reserved shape. */
export function decodeFrame(body: Buffer): Frame {
  if (body.length < FRAME_HEADER_BYTES) {
    throw new WakeError(`frame shorter than the ${FRAME_HEADER_BYTES}-byte header`);
  }
  if (!body.subarray(0, 4).equals(MAGIC)) {
    throw new WakeError("frame did not start with the wake-hub magic");
  }
  if (body[4] !== WIRE_VERSION) {
    throw new WakeError(`unsupported wire version ${body[4]}`);
  }
  const kind = body[5]!;
  if (RESERVED_PAYLOAD_KINDS.includes(kind)) {
    throw new WakeError(
      `wire kind ${kind} is permanently reserved: the wake plane carries no message bodies`,
    );
  }
  // Reserved bytes are CHECKED, not ignored, so they stay available for a
  // future version instead of being quietly accepted by today's parser.
  if (body[6] !== 0 || body[9] !== 0) {
    throw new WakeError("a reserved header byte was non-zero");
  }
  const fromLen = body[7]!;
  const toLen = body[8]!;
  const payloadLen = body.readUInt16BE(10);
  const end = FRAME_HEADER_BYTES + fromLen + toLen + payloadLen;
  if (body.length !== end) {
    throw new WakeError(`declared length ${end} != actual ${body.length}`);
  }
  let off = FRAME_HEADER_BYTES;
  const from = body.subarray(off, off + fromLen).toString("utf8");
  off += fromLen;
  const to = body.subarray(off, off + toLen).toString("utf8");
  off += toLen;
  return {
    kind,
    from,
    to,
    payload: body.subarray(off),
    tsMs: Number(body.readBigUInt64BE(12)),
    ttlMs: body.readUInt32BE(20),
  };
}

/** The content-free hint a `wake` carries. There is no body field. */
export interface WakeMeta {
  inboxRowId: string;
  namespace: string;
  sender: string;
  /**
   * SHA-256 of the notification body, so a recipient can verify what it later
   * READS without the hub ever having seen it. Lowercase hex.
   */
  digestHex: string;
  /**
   * The producer's host-wide wake counter when the hint was minted. Read it as
   * "wakes happened that you did not see"; the correct response to a gap is
   * ONE catch-up read.
   */
  seqHighWatermark: number;
}

function takeShort(buf: Buffer): [Buffer, Buffer] {
  if (buf.length === 0) throw new WakeError("wake metadata ended mid-field");
  const len = buf[0]!;
  if (buf.length - 1 < len) throw new WakeError("wake metadata ended mid-field");
  return [buf.subarray(1, 1 + len), buf.subarray(1 + len)];
}

/** Decode a `wake` payload. */
export function decodeWakeMeta(buf: Buffer): WakeMeta {
  if (buf.length > MAX_WAKE_META_BYTES) {
    throw new WakeError(`wake metadata ${buf.length} B exceeds the 256 B ceiling`);
  }
  const fields: Buffer[] = [];
  let rest = buf;
  for (let i = 0; i < 4; i += 1) {
    const [field, tail] = takeShort(rest);
    fields.push(field);
    rest = tail;
  }
  if (rest.length !== 8) throw new WakeError("wake metadata ended mid-field");
  const digest = fields[3]!;
  if (digest.length !== 0 && digest.length !== WAKE_DIGEST_BYTES) {
    throw new WakeError("a digest is empty or exactly 32 bytes");
  }
  return {
    inboxRowId: fields[0]!.toString("utf8"),
    namespace: fields[1]!.toString("utf8"),
    sender: fields[2]!.toString("utf8"),
    digestHex: digest.toString("hex"),
    seqHighWatermark: Number(rest.readBigUInt64BE(0)),
  };
}

/** What the hub tells an accepted session. */
export interface Welcome {
  session: number;
  /** Wakes coalesced while this agent was offline. */
  pendingCount: number;
  /** Distinct inbox-row ids retained from that window. */
  pendingIds: number;
  /**
   * `true` when the pending set stopped retaining ids: the client MUST do a
   * full catch-up read rather than trust the id set.
   */
  lagged: boolean;
  reconnectBaseMs: number;
  reconnectJitterMs: number;
}

/** Decode a `welcome` payload. */
export function decodeWelcome(buf: Buffer): Welcome {
  if (buf.length !== WELCOME_BYTES) {
    throw new WakeError(`welcome is ${WELCOME_BYTES} bytes, got ${buf.length}`);
  }
  return {
    session: buf.readUInt32BE(0),
    pendingCount: Number(buf.readBigUInt64BE(4)),
    pendingIds: buf.readUInt32BE(12),
    lagged: buf[16] !== 0,
    reconnectBaseMs: buf.readUInt32BE(17),
    reconnectJitterMs: buf.readUInt32BE(21),
  };
}

/** SHA-256 over the canonical topic list (`wake_hub::identity`). */
export function topicsHash(topics: readonly string[] = []): Buffer {
  const h = createHash("sha256");
  for (const t of topics) {
    const raw = Buffer.from(t, "utf8");
    h.update(Buffer.from([Math.min(raw.length, 255)]));
    h.update(raw);
  }
  return h.digest();
}

/**
 * Build the domain-separated, length-prefixed hello transcript.
 *
 * The length prefixes are what make the encoding injective: without them
 * `hubId="ab", agentId="c"` and `hubId="a", agentId="bc"` would hash the same
 * bytes and a signature harvested for one pair would verify for the other.
 */
export function helloTranscript(
  hubId: string,
  nonce: Buffer,
  agentId: string,
  topics: readonly string[] = [],
): Buffer {
  if (nonce.length !== HELLO_NONCE_BYTES) {
    throw new WakeError(`the hello nonce is ${HELLO_NONCE_BYTES} bytes`);
  }
  const hub = Buffer.from(hubId, "utf8");
  const agent = Buffer.from(agentId, "utf8");
  return Buffer.concat([
    HELLO_TRANSCRIPT_DOMAIN,
    Buffer.from([hub.length]),
    hub,
    nonce,
    Buffer.from([agent.length]),
    agent,
    topicsHash(topics),
  ]);
}

interface Certificate {
  principal: string;
  scope: string;
  delegateKeyId: Buffer;
  hubId: string;
  notBefore: string;
  notAfter: string;
}

function decodeCertificate(buf: Buffer): Certificate {
  if (buf.length === 0 || buf[0] !== DELEGATION_WIRE_VERSION) {
    throw new WakeError("delegation certificate has an unsupported version");
  }
  const short = (b: Buffer): [Buffer, Buffer] => {
    if (b.length === 0) throw new WakeError("delegation certificate ended mid-field");
    const len = b[0]!;
    if (b.length - 1 < len) throw new WakeError("delegation certificate ended mid-field");
    return [b.subarray(1, 1 + len), b.subarray(1 + len)];
  };
  let rest = buf.subarray(1);
  const [principal, r1] = short(rest);
  const [scope, r2] = short(r1);
  rest = r2;
  if (rest.length < DELEGATE_KEY_ID_BYTES) {
    throw new WakeError("delegation certificate ended mid-field");
  }
  const delegateKeyId = rest.subarray(0, DELEGATE_KEY_ID_BYTES);
  rest = rest.subarray(DELEGATE_KEY_ID_BYTES);
  const [hubId, r3] = short(rest);
  const [notBefore, r4] = short(r3);
  const [notAfter, r5] = short(r4);
  if (r5.length !== SIGNATURE_BYTES) {
    throw new WakeError("delegation certificate ended mid-field");
  }
  return {
    principal: principal.toString("utf8"),
    scope: scope.toString("utf8"),
    delegateKeyId,
    hubId: hubId.toString("utf8"),
    notBefore: notBefore.toString("utf8"),
    notAfter: notAfter.toString("utf8"),
  };
}

/** The on-disk shape `ai-memory identity delegate --scope a2a-hub` writes. */
export interface BundleFile {
  version: number;
  agent_id: string;
  hub_id: string;
  delegation_b64: string;
  delegate_private_b64: string;
  not_before?: string;
  not_after?: string;
}

/**
 * The scoped `a2a-hub/join/v1` credential, loaded from the key directory.
 *
 * The delegated private key stays in memory for the life of the process and is
 * never rendered by `toString` / `toJSON`.
 */
export class DelegationBundle {
  readonly agentId: string;
  readonly hubId: string;
  readonly notAfter: string;
  private readonly delegation: Buffer;
  private readonly key: AgentSigningKey;

  private constructor(
    agentId: string,
    hubId: string,
    notAfter: string,
    delegation: Buffer,
    key: AgentSigningKey,
  ) {
    this.agentId = agentId;
    this.hubId = hubId;
    this.notAfter = notAfter;
    this.delegation = delegation;
    this.key = key;
  }

  /** Where `ai-memory identity delegate --scope a2a-hub` writes it. */
  static defaultPath(keyDir: string, agentId: string): string {
    return join(keyDir, `${agentId}.a2a-hub.json`);
  }

  /** Load and check a bundle. Every failure is a refusal. */
  static load(
    path: string,
    opts: { hubId?: string; now?: number } = {},
  ): DelegationBundle {
    const st = lstatSync(path);
    if (st.isSymbolicLink()) {
      throw new WakeError(
        `${path} is a symlink: a credential reached through a link is one whose ` +
          "permissions were checked on the wrong file",
      );
    }
    if (!st.isFile()) throw new WakeError(`${path} is not a regular file`);
    if ((st.mode & 0o077) !== 0) {
      throw new WakeError(
        `${path} is mode ${(st.mode & 0o7777).toString(8).padStart(4, "0")}; a bundle ` +
          "holding a private key must be 0600, or another local user can join the hub " +
          "as this agent",
      );
    }
    if (typeof process.geteuid === "function" && st.uid !== process.geteuid()) {
      throw new WakeError(`${path} is owned by uid ${st.uid}, not by the caller`);
    }
    return DelegationBundle.fromObject(
      JSON.parse(readFileSync(path, "utf8")) as BundleFile,
      { ...opts, source: path },
    );
  }

  /** The verification core, over an already-parsed bundle. */
  static fromObject(
    bundle: BundleFile,
    opts: { hubId?: string; now?: number; source?: string } = {},
  ): DelegationBundle {
    const hubId = opts.hubId ?? DEFAULT_HUB_ID;
    const source = opts.source ?? "<bundle>";
    if (bundle.version !== BUNDLE_VERSION) {
      throw new WakeError(
        `${source} is a v${bundle.version} delegation bundle; this client reads ` +
          `v${BUNDLE_VERSION}. A credential format this build does not understand is ` +
          "refused, never guessed at.",
      );
    }
    if (!bundle.agent_id) {
      throw new WakeError(`${source} names no agent, so there is no identity to join as`);
    }
    if (bundle.hub_id !== hubId) {
      throw new WakeError(
        `${source} was minted for hub ${JSON.stringify(bundle.hub_id)} but this client ` +
          `dials ${JSON.stringify(hubId)}. A delegation is bound to ONE hub on purpose.`,
      );
    }
    const certificate = Buffer.from(bundle.delegation_b64, "base64url");
    const cert = decodeCertificate(certificate);
    if (cert.scope !== A2A_HUB_SCOPE) {
      throw new WakeError(
        `${source}: the certificate carries scope ${JSON.stringify(cert.scope)}, not ` +
          `${JSON.stringify(A2A_HUB_SCOPE)}. The scope element exists to be CHECKED.`,
      );
    }
    if (cert.principal !== bundle.agent_id) {
      throw new WakeError(
        `${source}: the certificate speaks for ${JSON.stringify(cert.principal)} but ` +
          `the bundle claims ${JSON.stringify(bundle.agent_id)}`,
      );
    }
    if (cert.hubId !== hubId) {
      throw new WakeError(
        `${source}: the certificate is bound to hub ${JSON.stringify(cert.hubId)}`,
      );
    }
    const seed = Buffer.from(bundle.delegate_private_b64, "base64url");
    if (seed.length !== DELEGATE_KEY_ID_BYTES) {
      throw new WakeError(
        `${source}: the delegated seed is ${seed.length} bytes, not ${DELEGATE_KEY_ID_BYTES}`,
      );
    }
    const key = AgentSigningKey.fromSeed(seed);
    if (!key.publicKeyBytes().equals(cert.delegateKeyId)) {
      throw new WakeError(
        `${source}: the bundle's private key is NOT the key its certificate authorises. ` +
          "A mismatched pair is a tampered bundle, not a credential.",
      );
    }
    const start = Date.parse(cert.notBefore);
    const end = Date.parse(cert.notAfter);
    if (Number.isNaN(start) || Number.isNaN(end)) {
      throw new WakeError(`${source}: the certificate window does not parse`);
    }
    const now = opts.now ?? Date.now();
    if (!(start <= now && now < end)) {
      throw new WakeError(
        `${source}: the certificate is outside its validity window ` +
          `[${cert.notBefore}, ${cert.notAfter}). Mint a fresh one with ` +
          "`ai-memory identity delegate --scope a2a-hub`.",
      );
    }
    return new DelegationBundle(
      bundle.agent_id,
      hubId,
      cert.notAfter,
      certificate,
      key,
    );
  }

  /**
   * Build the `hello` payload: key, signature, delegation, NO topics.
   *
   * No topics is deliberate: a substrate wake is addressed directly to the
   * recipient and the hub's route table is keyed by the identity the hello
   * authenticated, so this session can only ever be handed wakes for its own
   * inbox. Subscribing to a topic would be asking for wakes the delegation
   * does not cover.
   */
  helloPayload(transcript: Buffer): Buffer {
    const len = Buffer.alloc(2);
    len.writeUInt16BE(this.delegation.length, 0);
    return Buffer.concat([
      this.key.publicKeyBytes(),
      this.key.sign(transcript),
      len,
      this.delegation,
      Buffer.from([0]), // zero topics
    ]);
  }

  /** A log line never renders key material. */
  toString(): string {
    return (
      `DelegationBundle(agentId=${this.agentId}, hubId=${this.hubId}, ` +
      `notAfter=${this.notAfter}, delegationBytes=${this.delegation.length}, ` +
      "delegate=<delegated session key>)"
    );
  }

  toJSON(): Record<string, unknown> {
    return {
      agentId: this.agentId,
      hubId: this.hubId,
      notAfter: this.notAfter,
      delegate: "<delegated session key>",
    };
  }
}

/**
 * Why a catch-up inbox read is due.
 *
 * Reported so an operator can tell "the hub told me" from "the backstop
 * fired" — the second silently replacing the first is exactly what a broken
 * wake plane looks like.
 */
export type WakeReason = "welcome" | "lagged" | "wake" | "gap" | "backstop";

/** `true` when this signal came from the hub rather than from the poll. */
export function isHubDriven(reason: WakeReason): boolean {
  return reason !== "backstop";
}

/** One "read your inbox now" signal. */
export interface WakeSignal {
  reason: WakeReason;
  /** The hint, when the hub supplied one. Absent for welcome/lagged/backstop. */
  meta?: WakeMeta;
  pendingCount: number;
  missed: number;
}

/**
 * Turns a `seq_high_watermark` gap into exactly one extra read.
 *
 * Fail-safe in one direction only: it may report a gap that was not one (after
 * a producer restart, say), costing one redundant read; it can never report
 * contiguity across a real gap.
 */
export class SeqTracker {
  last: number | null = null;

  observe(seq: number): number {
    // The first wake of a session establishes the baseline: the session's own
    // welcome already forced a catch-up read.
    const missed = this.last === null ? 0 : Math.max(0, seq - this.last - 1);
    this.last = this.last === null ? seq : Math.max(this.last, seq);
    return missed;
  }
}

/**
 * Exponential reconnect delay in ms, capped at {@link BACKSTOP_POLL_MAX_MS}.
 *
 * The cap IS the backstop: waiting longer than the interval a client polls at
 * anyway would buy nothing and only widen the window in which a recovered hub
 * sits idle.
 */
export function backoffForMs(baseMs: number, attempt: number): number {
  const shift = Math.min(Math.max(attempt - 1, 0), 16);
  return Math.min(baseMs * 2 ** shift, BACKSTOP_POLL_MAX_MS);
}

/**
 * Accumulates bytes and yields whole frames.
 *
 * The `u32` length prefix is checked against the frame ceiling BEFORE a byte
 * of body is buffered, so a peer that announces a 4 GiB frame gets a refusal
 * rather than a 4 GiB allocation.
 */
export class FrameBuffer {
  private buf: Buffer = Buffer.alloc(0);

  push(chunk: Buffer): Frame[] {
    this.buf = Buffer.concat([this.buf, chunk]);
    const out: Frame[] = [];
    for (;;) {
      if (this.buf.length < 4) return out;
      const length = this.buf.readUInt32BE(0);
      if (length > MAX_FRAME_BYTES) {
        throw new WakeError(
          `peer announced a ${length} B frame; ceiling is ${MAX_FRAME_BYTES}`,
        );
      }
      if (this.buf.length < 4 + length) return out;
      out.push(decodeFrame(this.buf.subarray(4, 4 + length)));
      this.buf = this.buf.subarray(4 + length);
    }
  }
}

/** Frame the codec's length prefix around an already-encoded body. */
export function lengthPrefixed(body: Buffer): Buffer {
  if (body.length > MAX_FRAME_BYTES) {
    throw new WakeError("refusing to emit a frame the hub would refuse to read");
  }
  const len = Buffer.alloc(4);
  len.writeUInt32BE(body.length, 0);
  return Buffer.concat([len, body]);
}

/** What one fed frame produced. */
export interface Step {
  /** Signals to act on — each is exactly ONE catch-up inbox read. */
  signals: WakeSignal[];
  /** Bytes to write back (a pong, and nothing else). */
  send: Buffer[];
}

/**
 * The pure state machine: frames in, signals out.
 *
 * Deliberately transport-free so it can be driven byte-for-byte in a test
 * with no socket, no hub and no Rust binary.
 */
export class WakeStateMachine {
  private state: "challenge" | "welcome" | "live" = "challenge";
  private readonly seq = new SeqTracker();

  constructor(private readonly bundle: DelegationBundle) {}

  /** `true` once the hub has welcomed this session. */
  get isLive(): boolean {
    return this.state === "live";
  }

  onFrame(frame: Frame): Step {
    switch (this.state) {
      case "challenge": {
        if (frame.kind !== Kind.Hello) {
          throw new WakeError("the hub's first frame must be a hello challenge");
        }
        if (frame.payload.length !== HELLO_NONCE_BYTES) {
          throw new WakeError(`the hello challenge is ${HELLO_NONCE_BYTES} bytes`);
        }
        const transcript = helloTranscript(
          this.bundle.hubId,
          frame.payload,
          this.bundle.agentId,
        );
        this.state = "welcome";
        return {
          signals: [],
          send: [
            lengthPrefixed(
              encodeFrame({
                kind: Kind.Hello,
                from: this.bundle.agentId,
                to: "",
                payload: this.bundle.helloPayload(transcript),
              }),
            ),
          ],
        };
      }
      case "welcome": {
        if (frame.kind === Kind.Error) {
          throw new WakeError(`the hub refused the handshake: ${errorText(frame.payload)}`);
        }
        if (frame.kind !== Kind.Welcome) {
          throw new WakeError(
            `the hub answered the hello with kind ${frame.kind}, not a welcome`,
          );
        }
        const welcome = decodeWelcome(frame.payload);
        this.state = "live";
        return {
          signals: [
            {
              reason: welcome.lagged ? "lagged" : "welcome",
              pendingCount: welcome.pendingCount,
              missed: 0,
            },
          ],
          send: [],
        };
      }
      default: {
        if (frame.kind === Kind.Wake) {
          const meta = decodeWakeMeta(frame.payload);
          const missed = this.seq.observe(meta.seqHighWatermark);
          return {
            signals: [
              { reason: missed > 0 ? "gap" : "wake", meta, pendingCount: 0, missed },
            ],
            send: [],
          };
        }
        if (frame.kind === Kind.Ping) {
          return {
            signals: [],
            send: [
              lengthPrefixed(
                encodeFrame({
                  kind: Kind.Pong,
                  from: this.bundle.agentId,
                  to: frame.from,
                  payload: Buffer.alloc(0),
                }),
              ),
            ],
          };
        }
        if (frame.kind === Kind.Error) {
          throw new WakeError(`the hub refused this session: ${errorText(frame.payload)}`);
        }
        // Anything else is ignored rather than fatal: a future hub may send
        // frames this version has no opinion about, and dropping the session
        // over one would trade wake latency for nothing.
        return { signals: [], send: [] };
      }
    }
  }
}

function errorText(payload: Buffer): string {
  if (payload.length < 2) return "unparseable refusal";
  return `${payload.readUInt16BE(0)} ${payload.subarray(2).toString("utf8")}`;
}

/** Options for {@link WakeListener}. */
export interface WakeListenerOptions {
  /** Longest gap between inbox reads. REFUSED above the normative bound. */
  pollIntervalMs?: number;
  reconnectBaseMs?: number;
  reconnectJitterMs?: number;
  /** Injectable for deterministic tests; defaults to `Math.random`. */
  random?: () => number;
}

/**
 * One long-lived session, plus the bounded poll that makes it safe.
 *
 * `onSignal` is called EXACTLY ONCE per event and is where you perform your
 * catch-up inbox read.
 */
export class WakeListener {
  readonly metrics = { signals: 0, sessions: 0, reconnects: 0 };
  /**
   * The most recent session failure, so a listener degraded to the backstop
   * can say WHY rather than looking like a quiet inbox.
   */
  lastError: string | null = null;

  private readonly pollIntervalMs: number;
  private readonly reconnectBaseMs: number;
  private readonly reconnectJitterMs: number;
  private readonly random: () => number;
  private stopped = false;
  private socket: Socket | null = null;
  private backstop: NodeJS.Timeout | null = null;

  constructor(
    private readonly socketPath: string,
    private readonly bundle: DelegationBundle,
    private readonly onSignal: (signal: WakeSignal) => void,
    opts: WakeListenerOptions = {},
  ) {
    this.pollIntervalMs = opts.pollIntervalMs ?? BACKSTOP_POLL_MAX_MS;
    if (!(this.pollIntervalMs > 0 && this.pollIntervalMs <= BACKSTOP_POLL_MAX_MS)) {
      throw new WakeError(
        `pollIntervalMs ${this.pollIntervalMs} is outside (0, ${BACKSTOP_POLL_MAX_MS}]. ` +
          "The ceiling is REFUSED rather than clamped so nothing silently runs slower " +
          "than the wake plane's contract.",
      );
    }
    this.reconnectBaseMs = opts.reconnectBaseMs ?? DEFAULT_RECONNECT_BASE_MS;
    this.reconnectJitterMs = opts.reconnectJitterMs ?? DEFAULT_RECONNECT_JITTER_MS;
    this.random = opts.random ?? Math.random;
  }

  private emit(signal: WakeSignal): void {
    this.metrics.signals += 1;
    this.onSignal(signal);
  }

  private armBackstop(): void {
    if (this.backstop) clearTimeout(this.backstop);
    this.backstop = setTimeout(() => {
      if (this.stopped) return;
      // The backstop is armed whether or not a hub is reachable, so a hub
      // that is down, refusing, or absent costs LATENCY and nothing else.
      this.emit({ reason: "backstop", pendingCount: 0, missed: 0 });
      this.armBackstop();
    }, this.pollIntervalMs);
    this.backstop.unref?.();
  }

  /** Connect, serve, back off, repeat — until {@link stop} is called. */
  async run(): Promise<void> {
    this.stopped = false;
    this.armBackstop();
    let attempt = 0;
    while (!this.stopped) {
      const started = Date.now();
      try {
        await this.session();
      } catch (err) {
        this.lastError = err instanceof Error ? err.message : String(err);
      }
      if (this.stopped) break;
      if (Date.now() - started >= HEALTHY_SESSION_MS) {
        // This session carried wakes for a while, so the ladder it inherited
        // describes an outage that is over.
        attempt = 0;
      }
      attempt += 1;
      this.metrics.reconnects += 1;
      const wait =
        backoffForMs(this.reconnectBaseMs, attempt) +
        this.random() * this.reconnectJitterMs;
      await new Promise((resolve) => {
        const t = setTimeout(resolve, wait);
        t.unref?.();
      });
    }
    if (this.backstop) clearTimeout(this.backstop);
  }

  /** Stop the listener and close any live session. */
  stop(): void {
    this.stopped = true;
    if (this.backstop) clearTimeout(this.backstop);
    this.socket?.destroy();
  }

  private session(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const machine = new WakeStateMachine(this.bundle);
      const frames = new FrameBuffer();
      const socket = netConnect(this.socketPath);
      this.socket = socket;
      let settled = false;
      const finish = (err?: Error): void => {
        if (settled) return;
        settled = true;
        socket.destroy();
        this.socket = null;
        if (err) reject(err);
        else resolve();
      };
      const handshakeTimer = setTimeout(
        () => finish(new WakeError("the wake-hub handshake timed out")),
        HANDSHAKE_TIMEOUT_MS,
      );
      handshakeTimer.unref?.();

      socket.on("error", (err) => finish(err));
      socket.on("close", () =>
        finish(new WakeError("the hub closed the connection")),
      );
      socket.on("data", (chunk: Buffer) => {
        try {
          for (const frame of frames.push(chunk)) {
            const wasLive = machine.isLive;
            const step = machine.onFrame(frame);
            for (const out of step.send) socket.write(out);
            for (const signal of step.signals) {
              this.emit(signal);
              // A catch-up read just happened, so the backstop's clock
              // restarts: the bound is "at most pollInterval since the LAST
              // read", not a fixed schedule that fires right after a wake.
              this.armBackstop();
            }
            if (!wasLive && machine.isLive) {
              clearTimeout(handshakeTimer);
              this.metrics.sessions += 1;
            }
          }
        } catch (err) {
          finish(err instanceof Error ? err : new WakeError(String(err)));
        }
      });
    });
  }
}
