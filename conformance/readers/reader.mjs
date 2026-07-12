#!/usr/bin/env node
// SPDX-License-Identifier: CC0-1.0
//
// ai-memory conformance corpus reference reader (Node.js, stdlib-only).
//
// A clean-room, dependency-free consumer of the ai-memory Portability v2
// signed-record family (docs/spec/PORTABILITY-V2.md; byte layouts frozen in
// docs/v1.0.0/format-decisions/SIGNABLE-WRITE-V2-AND-VERIFIER-SPEC-DRAFT.md).
// It implements the R24 verifier spec-section-7 obligations reachable from
// the Node standard library, INCLUDING Ed25519 signature verification via
// WebCrypto (globalThis.crypto.subtle, Node >= 19 — no third-party crypto,
// nothing vendored):
//
//   1. Decode each corpus vector under the restricted CBOR profile
//      (definite-length only; uint / nint / bytes / text / array; every
//      other shape is a hard reject).
//   2. RE-ENCODE the decoded value through an independent shortest-form
//      encoder and byte-compare against the original (spec section 7
//      step 1: re-encode-and-compare, never decode-and-trust).
//   3. Check the manifest's structural pins: leading domain tag, outer
//      element count, byte length.
//   4. Verify the detached Ed25519 signatures on the signed vectors —
//      including PROVING REJECTION of the deliberately tampered one.
//   5. Verify the self-contained equivocation proof end-to-end: both
//      embedded attestations re-encoded + verified under the embedded
//      subject key, then the divergence key checked (same subject /
//      epoch / head_sequence, DIFFERENT head_hash).
//
// Usage:  node reader.mjs [--corpus DIR]
// Exit status: 0 when every vector passes, 1 otherwise.

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const subtle = globalThis.crypto?.subtle;

// --- restricted CBOR profile (spec section 1 / Appendix A.1) ---------------

const MT_UINT = 0; // unsigned integer
const MT_NINT = 1; // negative integer
const MT_BYTES = 2; // byte string
const MT_TEXT = 3; // UTF-8 text
const MT_ARRAY = 4; // array
const AI_INDEFINITE = 31; // indefinite-length code (forbidden)

class ProfileError extends Error {}

/** A CBOR major-type-1 negative integer (argument n; value is -1 - n). */
class Nint {
  constructor(arg) {
    this.arg = arg;
  }
}

/** Read one CBOR head; enforce shortest-form. Returns [major, argBigInt, off]. */
function readHead(buf, off) {
  if (off >= buf.length) throw new ProfileError("truncated: expected a CBOR head");
  const initial = buf[off];
  const major = initial >> 5;
  const info = initial & 0x1f;
  off += 1;
  if (info < 24) return [major, BigInt(info), off];
  if (info === AI_INDEFINITE)
    throw new ProfileError("indefinite-length item (forbidden by profile)");
  const widths = { 24: 1, 25: 2, 26: 4, 27: 8 };
  const width = widths[info];
  if (width === undefined) throw new ProfileError(`reserved additional-info value ${info}`);
  if (off + width > buf.length) throw new ProfileError("truncated: argument overruns buffer");
  let arg = 0n;
  for (let i = 0; i < width; i += 1) arg = (arg << 8n) | BigInt(buf[off + i]);
  off += width;
  const floors = { 1: 24n, 2: 0x100n, 4: 0x1_0000n, 8: 0x1_0000_0000n };
  if (arg < floors[width])
    throw new ProfileError(`non-shortest-form argument ${arg} in ${width}-byte head`);
  return [major, arg, off];
}

/** Decode one profile-restricted item; returns [value, newOffset]. */
function decodeItem(buf, off) {
  const [major, argBig, next] = readHead(buf, off);
  off = next;
  if (major === MT_UINT) return [argBig, off];
  if (major === MT_NINT) return [new Nint(argBig), off];
  const arg = Number(argBig);
  if (major === MT_BYTES) {
    if (off + arg > buf.length) throw new ProfileError("truncated byte string");
    return [buf.subarray(off, off + arg), off + arg];
  }
  if (major === MT_TEXT) {
    if (off + arg > buf.length) throw new ProfileError("truncated text string");
    return [new TextDecoder("utf-8", { fatal: true }).decode(buf.subarray(off, off + arg)), off + arg];
  }
  if (major === MT_ARRAY) {
    const items = [];
    for (let i = 0; i < arg; i += 1) {
      const [value, o] = decodeItem(buf, off);
      items.push(value);
      off = o;
    }
    return [items, off];
  }
  throw new ProfileError(`major type ${major} forbidden by the v2 profile`);
}

/** Decode a whole buffer as exactly one item. */
function decode(buf) {
  const [value, off] = decodeItem(buf, 0);
  if (off !== buf.length)
    throw new ProfileError(`${buf.length - off} trailing byte(s) after the record`);
  return value;
}

/** Append the shortest-form head for `major` carrying bigint `arg`. */
function encodeHead(major, arg, out) {
  const mt = major << 5;
  if (arg < 24n) {
    out.push(mt | Number(arg));
    return;
  }
  const width = arg < 0x100n ? 1 : arg < 0x1_0000n ? 2 : arg < 0x1_0000_0000n ? 4 : 8;
  out.push(mt | { 1: 24, 2: 25, 4: 26, 8: 27 }[width]);
  for (let i = width - 1; i >= 0; i -= 1) out.push(Number((arg >> BigInt(8 * i)) & 0xffn));
}

/** Append the canonical encoding of a decoded value. */
function encodeItem(value, out) {
  if (typeof value === "bigint") {
    encodeHead(MT_UINT, value, out);
  } else if (value instanceof Nint) {
    encodeHead(MT_NINT, value.arg, out);
  } else if (value instanceof Uint8Array) {
    encodeHead(MT_BYTES, BigInt(value.length), out);
    for (const b of value) out.push(b);
  } else if (typeof value === "string") {
    const raw = new TextEncoder().encode(value);
    encodeHead(MT_TEXT, BigInt(raw.length), out);
    for (const b of raw) out.push(b);
  } else if (Array.isArray(value)) {
    encodeHead(MT_ARRAY, BigInt(value.length), out);
    for (const item of value) encodeItem(item, out);
  } else {
    throw new ProfileError(`unencodable value type ${typeof value}`);
  }
}

function encode(value) {
  const out = [];
  encodeItem(value, out);
  return Uint8Array.from(out);
}

// --- Ed25519 via WebCrypto (Node stdlib; nothing vendored) ------------------

/** Verify a raw Ed25519 signature; returns a boolean, never throws on a bad sig. */
async function ed25519Verify(pubkey, sig, msg) {
  const key = await subtle.importKey("raw", pubkey, { name: "Ed25519" }, false, ["verify"]);
  return subtle.verify({ name: "Ed25519" }, key, sig, msg);
}

// --- helpers -----------------------------------------------------------------

const ATTESTATION_ENTRY_ELEMENTS = 6; // five committed fields + the signature

function hexToBytes(hex) {
  const clean = hex.trim();
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean))
    throw new ProfileError("vector file is not clean hex");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  return a.every((v, i) => v === b[i]);
}

function checkStructure(value, entry) {
  if (!Array.isArray(value)) throw new ProfileError("top-level item is not an array");
  if (value.length !== entry.elements)
    throw new ProfileError(
      `outer array has ${value.length} elements, manifest pins ${entry.elements}`,
    );
  if (typeof value[0] !== "string" || value[0] !== entry.domain_tag)
    throw new ProfileError(
      `element [0] is ${JSON.stringify(value[0])}, manifest pins ${entry.domain_tag}`,
    );
}

/** Full offline verification of a self-contained equivocation proof. */
async function checkEquivocation(value, headDomain) {
  const [, pubkey, entryA, entryB] = value;
  if (!(pubkey instanceof Uint8Array) || pubkey.length !== 32)
    throw new ProfileError("subject pubkey is not 32 raw bytes");
  for (const [label, e] of [
    ["attestation_a", entryA],
    ["attestation_b", entryB],
  ]) {
    if (!Array.isArray(e) || e.length !== ATTESTATION_ENTRY_ELEMENTS)
      throw new ProfileError(`${label} is not a ${ATTESTATION_ENTRY_ELEMENTS}-element entry`);
    // Re-encode the committed fields under the peer-head domain and verify
    // the subject's signature over those exact bytes (never decode-and-trust).
    const signable = encode([headDomain, e[0], e[1], e[2], e[3], e[4]]);
    if (!(await ed25519Verify(pubkey, e[5], signable)))
      throw new ProfileError(`${label} signature does not verify under subject key`);
  }
  // Divergence key: same (subject, epoch, head_sequence), different hash.
  if (entryA[0] !== entryB[0]) throw new ProfileError("subject mismatch — not equivocation");
  if (entryA[1] !== entryB[1]) throw new ProfileError("epoch mismatch — not equivocation");
  if (entryA[2] !== entryB[2]) throw new ProfileError("sequence mismatch — not equivocation");
  if (bytesEqual(entryA[3], entryB[3]))
    throw new ProfileError("same head hash — agreement, not equivocation");
}

// --- main ---------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);
  const corpusFlag = args.indexOf("--corpus");
  const corpus =
    corpusFlag >= 0
      ? resolve(args[corpusFlag + 1])
      : resolve(dirname(fileURLToPath(import.meta.url)), "..");

  if (!subtle) {
    console.error("ERROR: WebCrypto (globalThis.crypto.subtle) unavailable; need Node >= 19");
    return 2;
  }

  const manifest = JSON.parse(readFileSync(join(corpus, "manifest.json"), "utf-8"));
  const headDomain = manifest.domain_tags.peer_head_attestation;
  let failed = 0;

  for (const entry of manifest.vectors) {
    try {
      const raw = hexToBytes(readFileSync(join(corpus, entry.file), "utf-8"));
      if (raw.length !== entry.length_bytes)
        throw new ProfileError(
          `vector is ${raw.length} bytes, manifest pins ${entry.length_bytes}`,
        );
      const value = decode(raw);
      // Spec section 7 step 1 half A: re-encode and byte-compare.
      if (!bytesEqual(encode(value), raw))
        throw new ProfileError("re-encoded bytes differ from the original");
      checkStructure(value, entry);

      switch (entry.verdict) {
        case "reencode-match":
          break; // fully covered above
        case "signature-valid": {
          const ok = await ed25519Verify(
            hexToBytes(entry.pubkey),
            hexToBytes(entry.signature),
            raw,
          );
          if (!ok) throw new ProfileError("expected VALID signature failed to verify");
          break;
        }
        case "signature-invalid": {
          const ok = await ed25519Verify(
            hexToBytes(entry.pubkey),
            hexToBytes(entry.signature),
            raw,
          );
          if (ok) throw new ProfileError("expected INVALID signature verified (must reject)");
          break;
        }
        case "equivocation-proven":
          await checkEquivocation(value, headDomain);
          break;
        default:
          throw new ProfileError(`unknown manifest verdict ${entry.verdict}`);
      }
      console.log(`PASS ${entry.name} [${entry.verdict}]`);
    } catch (err) {
      console.log(`FAIL ${entry.name}: ${err.message}`);
      failed += 1;
    }
  }

  const total = manifest.vectors.length;
  console.log(`\n${total - failed}/${total} vectors passed${failed === 0 ? "" : " (FAILURES)"}`);
  return failed === 0 ? 0 : 1;
}

process.exitCode = await main();
