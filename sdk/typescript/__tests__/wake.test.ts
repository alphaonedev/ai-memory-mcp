// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for the wake-hub client (#3470).
 *
 * Two layers, on purpose:
 *
 * - **Frame parsing and the state machine** are driven byte-for-byte with no
 *   socket at all, so the wire contract and every refusal are pinned without
 *   a hub and without the Rust binary.
 * - **A mock hub over a real Unix domain socket** exercises `WakeListener`
 *   end to end, plus one OPT-IN leg against a live `ai-memory wake-hub`
 *   (`AI_MEMORY_TEST_WAKE_HUB_SOCKET` + `AI_MEMORY_TEST_WAKE_HUB_BUNDLE`),
 *   which skips rather than pretending to have proved something it has not.
 */

import { createServer, type Server, type Socket } from "node:net";
import { mkdtempSync, rmSync, writeFileSync, chmodSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { AgentSigningKey } from "../src/attestation.js";
import {
  BACKSTOP_POLL_MAX_MS,
  DelegationBundle,
  FrameBuffer,
  Kind,
  RESERVED_PAYLOAD_KINDS,
  SeqTracker,
  WakeError,
  WakeListener,
  WakeStateMachine,
  backoffForMs,
  decodeFrame,
  decodeWakeMeta,
  decodeWelcome,
  encodeFrame,
  helloTranscript,
  isHubDriven,
  lengthPrefixed,
  topicsHash,
  type BundleFile,
  type WakeSignal,
} from "../src/wake.js";

const HUB_ID = "hub-3470-ts";
const AGENT_ID = "ai:listener-3470";

function short(raw: Buffer): Buffer {
  return Buffer.concat([Buffer.from([raw.length]), raw]);
}

function makeCertificate(opts: {
  principal?: string;
  scope?: string;
  delegateKeyId: Buffer;
  hubId?: string;
  notBefore?: string;
  notAfter?: string;
}): Buffer {
  const now = new Date();
  now.setMilliseconds(0);
  const nb = opts.notBefore ?? now.toISOString().replace(".000Z", "Z");
  const na =
    opts.notAfter ??
    new Date(now.getTime() + 3_600_000).toISOString().replace(".000Z", "Z");
  return Buffer.concat([
    Buffer.from([1]),
    short(Buffer.from(opts.principal ?? AGENT_ID, "utf8")),
    short(Buffer.from(opts.scope ?? "a2a-hub", "utf8")),
    opts.delegateKeyId,
    short(Buffer.from(opts.hubId ?? HUB_ID, "utf8")),
    short(Buffer.from(nb, "utf8")),
    short(Buffer.from(na, "utf8")),
    // The issuer signature is opaque to this client: the HUB verifies it.
    Buffer.alloc(64),
  ]);
}

function makeBundle(
  overrides: Partial<Parameters<typeof makeCertificate>[0]> = {},
): { file: BundleFile; seed: Buffer; key: AgentSigningKey } {
  const seed = randomBytes(32);
  const key = AgentSigningKey.fromSeed(seed);
  const cert = makeCertificate({ delegateKeyId: key.publicKeyBytes(), ...overrides });
  return {
    file: {
      version: 1,
      agent_id: overrides.principal ?? AGENT_ID,
      hub_id: overrides.hubId ?? HUB_ID,
      delegation_b64: cert.toString("base64url"),
      delegate_private_b64: seed.toString("base64url"),
    },
    seed,
    key,
  };
}

function loadedBundle(): DelegationBundle {
  return DelegationBundle.fromObject(makeBundle().file, { hubId: HUB_ID });
}

// ---------------------------------------------------------------------------
// Frame parsing
// ---------------------------------------------------------------------------

describe("frame parsing", () => {
  it("round-trips a frame and admits no body kind", () => {
    const frame = { kind: Kind.Wake, from: "producer", to: "ai:alice", payload: Buffer.from([1, 2]) };
    const decoded = decodeFrame(encodeFrame(frame));
    expect(decoded.kind).toBe(Kind.Wake);
    expect(decoded.from).toBe("producer");
    expect(decoded.payload).toEqual(Buffer.from([1, 2]));
    // The v1 protocol has NO kind that admits a message body.
    expect(Object.keys(Kind)).not.toEqual(
      expect.arrayContaining(["Request", "Reply", "Notify"]),
    );
  });

  it.each(RESERVED_PAYLOAD_KINDS)("refuses reserved wire kind %i by name", (reserved) => {
    const wire = Buffer.from(
      encodeFrame({ kind: Kind.Wake, from: "a", to: "b", payload: Buffer.alloc(0) }),
    );
    wire[5] = reserved;
    expect(() => decodeFrame(wire)).toThrow(/permanently reserved/);
  });

  it("refuses a malformed frame rather than guessing at it", () => {
    const good = encodeFrame({
      kind: Kind.Wake,
      from: "a",
      to: "b",
      payload: Buffer.from("xyz"),
    });

    const badMagic = Buffer.from(good);
    badMagic[0] ^= 0xff;
    expect(() => decodeFrame(badMagic)).toThrow(/magic/);

    const badVersion = Buffer.from(good);
    badVersion[4] = 9;
    expect(() => decodeFrame(badVersion)).toThrow(/unsupported wire version/);

    // Reserved header bytes are CHECKED, not ignored, so they stay available.
    for (const offset of [6, 9]) {
      const bad = Buffer.from(good);
      bad[offset] = 1;
      expect(() => decodeFrame(bad)).toThrow(/reserved header byte/);
    }

    expect(() => decodeFrame(good.subarray(0, 10))).toThrow(/shorter than/);
    expect(() => decodeFrame(Buffer.concat([good, Buffer.from("x")]))).toThrow(
      /declared length/,
    );
  });

  it("decodes the wake hint and never a body", () => {
    const seq = Buffer.alloc(8);
    seq.writeBigUInt64BE(42n, 0);
    const payload = Buffer.concat([
      short(Buffer.from("row-3470")),
      short(Buffer.from("_inbox/ai:alice")),
      short(Buffer.from("ai:bob")),
      short(Buffer.alloc(32, 0xab)),
      seq,
    ]);
    const meta = decodeWakeMeta(payload);
    expect(meta.inboxRowId).toBe("row-3470");
    expect(meta.sender).toBe("ai:bob");
    expect(meta.seqHighWatermark).toBe(42);
    expect(meta.digestHex).toBe("ab".repeat(32));
    expect(Object.keys(meta)).not.toEqual(expect.arrayContaining(["body", "content"]));

    expect(() => decodeWakeMeta(Buffer.alloc(300))).toThrow(/ceiling/);
    const badDigest = Buffer.concat([
      short(Buffer.from("r")),
      short(Buffer.from("n")),
      short(Buffer.from("s")),
      short(Buffer.from([1, 2])),
      seq,
    ]);
    expect(() => decodeWakeMeta(badDigest)).toThrow(/32 bytes/);
  });

  it("decodes the offline backlog and the lagged flag", () => {
    const raw = Buffer.alloc(25);
    raw.writeUInt32BE(7, 0);
    raw.writeBigUInt64BE(3n, 4);
    raw.writeUInt32BE(2, 12);
    raw[16] = 1;
    raw.writeUInt32BE(250, 17);
    raw.writeUInt32BE(750, 21);
    const welcome = decodeWelcome(raw);
    expect(welcome).toMatchObject({
      session: 7,
      pendingCount: 3,
      pendingIds: 2,
      lagged: true,
      reconnectBaseMs: 250,
      reconnectJitterMs: 750,
    });
    expect(() => decodeWelcome(raw.subarray(0, 24))).toThrow(/25 bytes/);
  });

  it("length-prefixes the hello transcript so it is injective", () => {
    const nonce = randomBytes(32);
    // Without length prefixes these two pairs would hash the same bytes and a
    // signature harvested for one would verify for the other.
    const a = helloTranscript("ab", nonce, "c");
    const b = helloTranscript("a", nonce, "bc");
    expect(a.equals(b)).toBe(false);
    expect(a.subarray(0, 12).toString()).toBe("a2a/v1/hello");
    expect(a.subarray(a.length - 32).equals(topicsHash([]))).toBe(true);
    expect(() => helloTranscript("h", Buffer.alloc(8), "a")).toThrow(/32 bytes/);
  });

  it("refuses an oversize length prefix before buffering the body", () => {
    const announce = Buffer.alloc(4);
    announce.writeUInt32BE(0xffffffff, 0);
    expect(() => new FrameBuffer().push(announce)).toThrow(/ceiling/);
  });

  it("reassembles a frame split across chunks", () => {
    const body = encodeFrame({
      kind: Kind.Wake,
      from: "p",
      to: "a",
      payload: Buffer.from("z"),
    });
    const wire = lengthPrefixed(body);
    const buf = new FrameBuffer();
    expect(buf.push(wire.subarray(0, 3))).toHaveLength(0);
    expect(buf.push(wire.subarray(3, 9))).toHaveLength(0);
    expect(buf.push(wire.subarray(9))).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Bundle: fail closed, with no flag that opens it
// ---------------------------------------------------------------------------

describe("delegation bundle", () => {
  it("loads a freshly minted bundle and signs with the DELEGATED key", () => {
    const { file, key } = makeBundle();
    const bundle = DelegationBundle.fromObject(file, { hubId: HUB_ID });
    expect(bundle.agentId).toBe(AGENT_ID);

    const transcript = helloTranscript(HUB_ID, Buffer.alloc(32), AGENT_ID);
    const payload = bundle.helloPayload(transcript);
    expect(payload.subarray(0, 32).equals(key.publicKeyBytes())).toBe(true);
    // Zero topics: own-inbox only (#3468).
    expect(payload[payload.length - 1]).toBe(0);
    // A log line never renders key material.
    expect(bundle.toString()).toContain("<delegated session key>");
    expect(JSON.stringify(bundle)).not.toContain(file.delegate_private_b64);
  });

  it("refuses a bundle minted for another hub or another agent", () => {
    const { file } = makeBundle();
    expect(() => DelegationBundle.fromObject(file, { hubId: "other-hub" })).toThrow(
      /bound to ONE hub/,
    );

    const mismatched = makeBundle({ principal: "ai:someone-else" }).file;
    mismatched.agent_id = AGENT_ID;
    expect(() => DelegationBundle.fromObject(mismatched, { hubId: HUB_ID })).toThrow(
      /speaks for/,
    );
  });

  it("refuses a bundle whose key is not the certified one", () => {
    const { file } = makeBundle();
    file.delegate_private_b64 = randomBytes(32).toString("base64url");
    expect(() => DelegationBundle.fromObject(file, { hubId: HUB_ID })).toThrow(
      /NOT the key its certificate authorises/,
    );
  });

  it("refuses a foreign scope and an unknown version", () => {
    const foreign = makeBundle({ scope: "write" }).file;
    expect(() => DelegationBundle.fromObject(foreign, { hubId: HUB_ID })).toThrow(/scope/);

    const { file } = makeBundle();
    file.version = 99;
    expect(() => DelegationBundle.fromObject(file, { hubId: HUB_ID })).toThrow(
      /refused, never guessed at/,
    );
  });

  it("refuses an expired bundle and names the remediation", () => {
    const { file } = makeBundle();
    expect(() =>
      DelegationBundle.fromObject(file, { hubId: HUB_ID, now: Date.now() + 86_400_000 }),
    ).toThrow(/identity delegate/);
  });

  it("refuses a group-readable or symlinked bundle on disk", () => {
    const dir = mkdtempSync(join(tmpdir(), "wake-3470-"));
    try {
      const { file } = makeBundle();
      const path = join(dir, "b.json");
      writeFileSync(path, JSON.stringify(file));
      chmodSync(path, 0o600);
      expect(DelegationBundle.load(path, { hubId: HUB_ID }).agentId).toBe(AGENT_ID);

      chmodSync(path, 0o644);
      expect(() => DelegationBundle.load(path, { hubId: HUB_ID })).toThrow(/must be 0600/);
      chmodSync(path, 0o600);

      const link = join(dir, "link.json");
      symlinkSync(path, link);
      expect(() => DelegationBundle.load(link, { hubId: HUB_ID })).toThrow(/symlink/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("resolves the path `identity delegate` writes", () => {
    expect(DelegationBundle.defaultPath("/keys", AGENT_ID)).toBe(
      `/keys/${AGENT_ID}.a2a-hub.json`,
    );
  });
});

// ---------------------------------------------------------------------------
// The state machine, with no socket at all
// ---------------------------------------------------------------------------

function challengeFrame(): Buffer {
  return encodeFrame({ kind: Kind.Hello, from: "hub", to: "", payload: Buffer.alloc(32) });
}

function welcomeFrame(opts: { lagged?: boolean; pending?: number } = {}): Buffer {
  const payload = Buffer.alloc(25);
  payload.writeUInt32BE(1, 0);
  payload.writeBigUInt64BE(BigInt(opts.pending ?? 0), 4);
  payload[16] = opts.lagged ? 1 : 0;
  payload.writeUInt32BE(250, 17);
  payload.writeUInt32BE(750, 21);
  return encodeFrame({ kind: Kind.Welcome, from: "hub", to: AGENT_ID, payload });
}

function wakeFrame(row: string, seq: number): Buffer {
  const tail = Buffer.alloc(8);
  tail.writeBigUInt64BE(BigInt(seq), 0);
  const payload = Buffer.concat([
    short(Buffer.from(row)),
    short(Buffer.from(`_inbox/${AGENT_ID}`)),
    short(Buffer.from("ai:bob")),
    short(Buffer.alloc(32)),
    tail,
  ]);
  return encodeFrame({
    kind: Kind.Wake,
    from: "wake-hub-producer",
    to: AGENT_ID,
    payload,
  });
}

function drive(frames: Buffer[]): { signals: WakeSignal[]; sent: number[] } {
  const machine = new WakeStateMachine(loadedBundle());
  const signals: WakeSignal[] = [];
  const sent: number[] = [];
  for (const body of frames) {
    const step = machine.onFrame(decodeFrame(body));
    signals.push(...step.signals);
    for (const out of step.send) sent.push(decodeFrame(out.subarray(4)).kind);
  }
  return { signals, sent };
}

describe("state machine", () => {
  it("signs the hub nonce and turns the welcome into ONE read", () => {
    const { signals, sent } = drive([challengeFrame(), welcomeFrame({ pending: 3 })]);
    expect(sent).toEqual([Kind.Hello]);
    expect(signals.map((s) => s.reason)).toEqual(["welcome"]);
    expect(signals[0]!.pendingCount).toBe(3);
    expect(signals[0]!.meta).toBeUndefined();
  });

  it("reports a lagged welcome as lagged, not as a plain welcome", () => {
    const { signals } = drive([challengeFrame(), welcomeFrame({ lagged: true })]);
    expect(signals.map((s) => s.reason)).toEqual(["lagged"]);
  });

  it("costs exactly one read per wake and reports a watermark gap", () => {
    const { signals } = drive([
      challengeFrame(),
      welcomeFrame(),
      wakeFrame("row-a", 5),
      wakeFrame("row-b", 9),
    ]);
    expect(signals.map((s) => s.reason)).toEqual(["welcome", "wake", "gap"]);
    expect(signals[1]!.missed).toBe(0);
    // Three wakes happened that this listener did not see.
    expect(signals[2]!.missed).toBe(3);
    expect(signals[2]!.meta?.inboxRowId).toBe("row-b");
  });

  it("answers a ping in place and charges no inbox read for it", () => {
    const ping = encodeFrame({
      kind: Kind.Ping,
      from: "hub",
      to: AGENT_ID,
      payload: Buffer.alloc(0),
    });
    const { signals, sent } = drive([challengeFrame(), welcomeFrame(), ping]);
    expect(sent).toEqual([Kind.Hello, Kind.Pong]);
    expect(signals.map((s) => s.reason)).toEqual(["welcome"]);
  });

  it("ignores an unknown frame kind rather than ending the session", () => {
    const depart = encodeFrame({
      kind: Kind.Depart,
      from: "hub",
      to: AGENT_ID,
      payload: Buffer.alloc(0),
    });
    const { signals } = drive([
      challengeFrame(),
      welcomeFrame(),
      depart,
      wakeFrame("row-x", 1),
    ]);
    expect(signals.map((s) => s.reason)).toEqual(["welcome", "wake"]);
  });

  it("turns a refused handshake into a legible failure", () => {
    const payload = Buffer.concat([Buffer.alloc(2), Buffer.from("unauthorized")]);
    payload.writeUInt16BE(401, 0);
    const error = encodeFrame({ kind: Kind.Error, from: "hub", to: "", payload });
    expect(() => drive([challengeFrame(), error])).toThrow(/401 unauthorized/);
  });

  it("refuses a first frame that is not a challenge", () => {
    expect(() => drive([welcomeFrame()])).toThrow(/hello challenge/);
  });
});

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

describe("bounds", () => {
  it("refuses a poll interval over the normative bound rather than clamping", () => {
    expect(
      () =>
        new WakeListener("/x.sock", loadedBundle(), () => {}, {
          pollIntervalMs: BACKSTOP_POLL_MAX_MS + 1,
        }),
    ).toThrow(/REFUSED rather than clamped/);
    expect(
      () => new WakeListener("/x.sock", loadedBundle(), () => {}, { pollIntervalMs: 0 }),
    ).toThrow(WakeError);
  });

  it("caps the reconnect ladder at the backstop", () => {
    expect(backoffForMs(250, 1)).toBe(250);
    expect(backoffForMs(250, 2)).toBe(500);
    expect(backoffForMs(250, 30)).toBe(BACKSTOP_POLL_MAX_MS);
    expect(backoffForMs(3_600_000, 1)).toBe(BACKSTOP_POLL_MAX_MS);
  });

  it("reports a gap but never false contiguity", () => {
    const t = new SeqTracker();
    expect(t.observe(100)).toBe(0); // the welcome already forced a read
    expect(t.observe(101)).toBe(0);
    expect(t.observe(105)).toBe(3);
    // A reordered or duplicated watermark must never rewind the baseline into
    // claiming a later gap that is not one.
    expect(t.observe(103)).toBe(0);
    expect(t.last).toBe(105);
    expect(t.observe(106)).toBe(0);
  });

  it("separates hub-driven signals from the poll", () => {
    expect(isHubDriven("wake")).toBe(true);
    expect(isHubDriven("gap")).toBe(true);
    expect(isHubDriven("lagged")).toBe(true);
    expect(isHubDriven("backstop")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// A mock hub over a real Unix domain socket
// ---------------------------------------------------------------------------

describe("WakeListener over a socket", () => {
  let dir: string;
  let server: Server | null = null;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "wake-hub-3470-"));
  });

  afterEach(async () => {
    if (server) await new Promise<void>((r) => server!.close(() => r()));
    server = null;
    rmSync(dir, { recursive: true, force: true });
  });

  it("handshakes with a mock hub and turns a wake into one signal", async () => {
    const sockPath = join(dir, "h.sock");
    const bundle = loadedBundle();
    server = createServer((sock: Socket) => {
      sock.write(lengthPrefixed(challengeFrame()));
      sock.once("data", () => {
        sock.write(lengthPrefixed(welcomeFrame()));
        sock.write(lengthPrefixed(wakeFrame("row-sock", 7)));
      });
    });
    await new Promise<void>((r) => server!.listen(sockPath, r));

    const signals: WakeSignal[] = [];
    const listener = new WakeListener(sockPath, bundle, (s) => signals.push(s), {
      pollIntervalMs: 30_000,
      reconnectBaseMs: 10,
      reconnectJitterMs: 0,
    });
    const running = listener.run();
    const deadline = Date.now() + 5_000;
    while (signals.length < 2 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
    listener.stop();
    await running;

    expect(signals.map((s) => s.reason)).toEqual(["welcome", "wake"]);
    expect(signals[1]!.meta?.inboxRowId).toBe("row-sock");
    expect(listener.metrics.sessions).toBe(1);
  });

  it("degrades to the bounded backstop when no hub is listening", async () => {
    // No hub at all is the documented degraded mode, not an error.
    const signals: WakeSignal[] = [];
    const listener = new WakeListener(
      join(dir, "absent.sock"),
      loadedBundle(),
      (s) => signals.push(s),
      { pollIntervalMs: 50, reconnectBaseMs: 5, reconnectJitterMs: 0 },
    );
    const running = listener.run();
    const deadline = Date.now() + 5_000;
    while (signals.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
    listener.stop();
    await running;

    expect(signals.length).toBeGreaterThan(0);
    expect(signals.every((s) => s.reason === "backstop")).toBe(true);
    expect(listener.metrics.sessions).toBe(0);
    expect(listener.metrics.reconnects).toBeGreaterThan(0);
    expect(listener.lastError).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Real hub, opt-in
// ---------------------------------------------------------------------------

const REAL_SOCKET = process.env.AI_MEMORY_TEST_WAKE_HUB_SOCKET;
const REAL_BUNDLE = process.env.AI_MEMORY_TEST_WAKE_HUB_BUNDLE;
const describeReal = REAL_SOCKET && REAL_BUNDLE ? describe : describe.skip;

describeReal("a live ai-memory wake-hub", () => {
  it("admits this client over a real socket", async () => {
    const hubId = process.env.AI_MEMORY_TEST_WAKE_HUB_ID ?? "ai-memory-wake-hub";
    const bundle = DelegationBundle.load(REAL_BUNDLE!, { hubId });
    const signals: WakeSignal[] = [];
    const listener = new WakeListener(REAL_SOCKET!, bundle, (s) => signals.push(s), {
      pollIntervalMs: 30_000,
      reconnectBaseMs: 100,
      reconnectJitterMs: 0,
    });
    const running = listener.run();
    const deadline = Date.now() + 10_000;
    while (signals.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 20));
    }
    listener.stop();
    await running;

    expect(["welcome", "lagged"]).toContain(signals[0]?.reason);
    expect(listener.metrics.sessions).toBe(1);
  }, 20_000);
});
