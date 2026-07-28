// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Webhook signature verification for ai-memory subscription callbacks.
 *
 * ## Wire contract
 *
 * Canonical source: `src/subscriptions.rs:980-990`. Each delivery carries
 *
 * - `X-AI-Memory-Signature: sha256=<hex>`
 * - `X-AI-Memory-Timestamp: <unix-epoch-seconds>`
 * - `X-AI-Memory-Correlation-Id: <uuid>`
 *
 * where `<hex>` is
 *
 * ```text
 * HMAC-SHA256(key = SHA256(plaintext_secret), msg = "{timestamp}.{body}")
 * ```
 *
 * Two details are load-bearing and were BOTH wrong in this SDK before #2455:
 *
 * 1. **The HMAC key is the SHA-256 DIGEST of the secret, not the secret.**
 *    The daemon stores `secret_hash = sha256_hex(secret)` at subscribe time
 *    and keys the HMAC on the hex-DECODED bytes of that hash — the raw
 *    32-byte digest. Keying on the plaintext secret yields a different MAC.
 * 2. **The signed message is `"{timestamp}.{body}"`, not the bare body.**
 *    The timestamp prefix (literal `.` separator) binds a signature to the
 *    instant it was minted so it cannot be replayed at another time.
 *
 * Because the pre-#2455 implementation got both wrong,
 * {@link verifyWebhookSignature} could never return `true` for a genuine
 * delivery. The regression fixture in `__tests__/client.test.ts` is generated
 * from the RUST signer (`__tests__/fixtures/webhook_hmac_vector.json`) rather
 * than from {@link signWebhookBody}, so the test can no longer agree with a
 * wrong implementation.
 *
 * ## Replay window
 *
 * The timestamp is verified, not merely consumed: a delivery older than
 * `maxAgeSecs` (default 300s) or further into the future than `maxSkewSecs`
 * (default 60s) is rejected even with a valid MAC. These mirror the daemon's
 * own inbound verifier (`APPROVAL_HMAC_MAX_AGE_SECS` /
 * `APPROVAL_HMAC_MAX_SKEW_SECS` in `src/handlers/approvals.rs`).
 *
 * Uses Node's built-in `node:crypto` — no third-party crypto dependency.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

/** Header carrying `sha256=<hex>`. */
export const SIGNATURE_HEADER = "X-AI-Memory-Signature";
/** Header carrying the Unix-epoch-seconds timestamp that was signed. */
export const TIMESTAMP_HEADER = "X-AI-Memory-Timestamp";

/** Maximum age of a delivery's timestamp before it is treated as a replay. */
export const DEFAULT_MAX_AGE_SECS = 300;
/** Maximum clock skew INTO THE FUTURE tolerated on a delivery's timestamp. */
export const DEFAULT_MAX_SKEW_SECS = 60;

const SIG_PREFIX = "sha256=";

/** Options for {@link verifyWebhookSignature}. */
export interface VerifyWebhookOptions {
  /**
   * The `X-AI-Memory-Timestamp` header value. Fed VERBATIM into the signed
   * message, so pass the raw header string rather than a re-formatted number.
   * Required — omitting it throws (see {@link verifyWebhookSignature}).
   */
  timestamp: string | number;
  /** Reject a delivery whose timestamp is older than this. Default 300s. */
  maxAgeSecs?: number;
  /** Reject a delivery this far ahead of local time. Default 60s. */
  maxSkewSecs?: number;
  /** Override for the current Unix time (seconds), for tests. */
  nowSecs?: number;
}

function toBuffer(body: string | Uint8Array): Buffer {
  return typeof body === "string" ? Buffer.from(body, "utf8") : Buffer.from(body);
}

/** The exact bytes the daemon signs: `"{timestamp}.{body}"` as UTF-8. */
function canonical(timestamp: string, body: string | Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), toBuffer(body)]);
}

/** `SHA256(plaintext_secret)` — the raw 32-byte HMAC key. */
function hmacKey(secret: string): Buffer {
  return createHash("sha256").update(secret, "utf8").digest();
}

/**
 * Sign a payload the way the daemon does — `sha256=<hex>` over
 * `"{timestamp}.{body}"` keyed on `SHA256(secret)`.
 *
 * Useful for local webhook replay harnesses. Production SDK users only need
 * {@link verifyWebhookSignature}.
 *
 * @param body      Raw body bytes (or a string, encoded as UTF-8).
 * @param secret    The PLAINTEXT subscription secret — hashed here, do not
 *                  pre-hash it.
 * @param timestamp Unix epoch **seconds**; stringified as given.
 * @returns `sha256=<64 hex chars>`.
 */
export function signWebhookBody(
  body: string | Uint8Array,
  secret: string,
  timestamp: string | number,
): string {
  const hex = createHmac("sha256", hmacKey(secret))
    .update(canonical(String(timestamp), body))
    .digest("hex");
  return `${SIG_PREFIX}${hex}`;
}

/**
 * Verify an HMAC-SHA256 webhook signature and its replay window.
 *
 * @param body      Raw request body (string or Buffer). Pass the EXACT bytes
 *                  the server signed — not a re-serialized JSON object.
 * @param signature The `X-AI-Memory-Signature` header value. Accepts both
 *                  `sha256=<hex>` and bare `<hex>` forms.
 * @param secret    The PLAINTEXT subscription secret established at
 *                  `.subscribe()` time.
 * @param options   Must carry `timestamp` — the `X-AI-Memory-Timestamp`
 *                  header value.
 * @returns `true` iff the signature matches AND the timestamp is inside the
 *          replay window; `false` otherwise. Never throws for malformed
 *          DELIVERY data (bad hex, wrong length, unparseable timestamp) —
 *          those return `false`.
 * @throws {TypeError} when `options.timestamp` is missing. That is a
 *          programmer error (a call site not updated for the #2455 wire
 *          contract), not untrusted input, and failing loudly is safer than
 *          silently verifying against the wrong construction. TypeScript
 *          callers get a compile error instead.
 *
 * @example
 * ```ts
 * import {
 *   verifyWebhookSignature,
 *   SIGNATURE_HEADER,
 *   TIMESTAMP_HEADER,
 * } from "@alphaone/ai-memory/webhooks";
 *
 * app.post("/webhook", (req, res) => {
 *   const sig = req.header(SIGNATURE_HEADER) ?? "";
 *   const ts = req.header(TIMESTAMP_HEADER) ?? "";
 *   if (
 *     !verifyWebhookSignature(req.rawBody, sig, process.env.WEBHOOK_SECRET!, {
 *       timestamp: ts,
 *     })
 *   ) {
 *     return res.status(401).send("bad signature");
 *   }
 *   // ... handle event
 * });
 * ```
 */
export function verifyWebhookSignature(
  body: string | Uint8Array,
  signature: string,
  secret: string,
  options: VerifyWebhookOptions,
): boolean {
  if (options === undefined || options === null || options.timestamp === undefined || options.timestamp === null) {
    throw new TypeError(
      "verifyWebhookSignature requires options.timestamp (the " +
        `${TIMESTAMP_HEADER} header value) — the daemon signs ` +
        '"{timestamp}.{body}", so verification without it is impossible. See #2455.',
    );
  }
  if (!signature || !secret) return false;

  const ts = String(options.timestamp).trim();
  if (ts.length === 0) return false;

  // Freshness first: a stale-but-authentic replay must be rejected, and doing
  // it before the MAC compare avoids spending a hash on it.
  if (!/^-?\d+$/.test(ts)) return false;
  const tsValue = Number(ts);
  if (!Number.isSafeInteger(tsValue)) return false;
  const maxAge = options.maxAgeSecs ?? DEFAULT_MAX_AGE_SECS;
  const maxSkew = options.maxSkewSecs ?? DEFAULT_MAX_SKEW_SECS;
  const now = options.nowSecs ?? Math.floor(Date.now() / 1000);
  const age = now - tsValue;
  if (age > maxAge || -age > maxSkew) return false;

  const provided = signature.startsWith(SIG_PREFIX)
    ? signature.slice(SIG_PREFIX.length)
    : signature;

  // Hex must be non-empty and even-length; anything else rejects early.
  if (provided.length === 0 || provided.length % 2 !== 0) return false;
  if (!/^[0-9a-fA-F]+$/.test(provided)) return false;

  const expectedHex = createHmac("sha256", hmacKey(secret))
    .update(canonical(ts, body))
    .digest("hex");

  // Length mismatch implies forgery attempt — timingSafeEqual would throw.
  if (expectedHex.length !== provided.length) return false;

  try {
    const a = Buffer.from(expectedHex, "hex");
    const b = Buffer.from(provided, "hex");
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}
