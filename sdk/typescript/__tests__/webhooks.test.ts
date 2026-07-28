// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Webhook HMAC conformance against a RUST-GENERATED vector (#2455).
 *
 * R-203: the first test here FAILS against the pre-#2455 implementation and
 * PASSES after. The defect: the SDK keyed the HMAC on the PLAINTEXT secret
 * over the BARE body, while the daemon keys on `SHA256(secret)` over
 * `"{timestamp}.{body}"` — so `verifyWebhookSignature` could never return
 * `true` for a real webhook.
 *
 * The tests that should have caught it were tautological: they built the
 * expected signature with `signWebhookBody`, i.e. the same construction the
 * verifier used, so the module only ever agreed with itself. Every assertion
 * below is anchored to `sdk/fixtures/webhook_hmac_vector.json`, whose values
 * were PRINTED BY THE RUST SIGNER (provenance documented in the fixture).
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  DEFAULT_MAX_AGE_SECS,
  DEFAULT_MAX_SKEW_SECS,
  signWebhookBody,
  verifyWebhookSignature,
} from "../src/webhooks.js";

interface WebhookVector {
  secret: string;
  timestamp: string;
  body: string;
  secret_sha256_hex: string;
  signature_header: string;
}

const vector: WebhookVector = JSON.parse(
  readFileSync(
    resolve(__dirname, "..", "..", "fixtures", "webhook_hmac_vector.json"),
    "utf8",
  ),
) as WebhookVector;

const TS = Number(vector.timestamp);
/** A "now" 10s after the vector's timestamp — inside the replay window. */
const FRESH = TS + 10;

describe("webhook HMAC — Rust conformance (#2455)", () => {
  test("verifies a genuine Rust-signed delivery", () => {
    expect(
      verifyWebhookSignature(vector.body, vector.signature_header, vector.secret, {
        timestamp: vector.timestamp,
        nowSecs: FRESH,
      }),
    ).toBe(true);
  });

  test("key is SHA256(secret), not the secret itself", () => {
    // Passing the hex digest as if it were the secret must FAIL — that would
    // double-hash. Proves the SDK hashes exactly once, at the right layer.
    expect(
      verifyWebhookSignature(
        vector.body,
        vector.signature_header,
        vector.secret_sha256_hex,
        { timestamp: vector.timestamp, nowSecs: FRESH },
      ),
    ).toBe(false);
  });

  test("signed message is `{timestamp}.{body}`, not the bare body", () => {
    // Same body + secret under a DIFFERENT timestamp must fail, proving the
    // timestamp is inside the MAC rather than merely carried alongside it.
    const other = String(TS + 1);
    expect(
      verifyWebhookSignature(vector.body, vector.signature_header, vector.secret, {
        timestamp: other,
        nowSecs: Number(other) + 10,
      }),
    ).toBe(false);
  });

  test("signWebhookBody reproduces the Rust signature byte-for-byte", () => {
    expect(signWebhookBody(vector.body, vector.secret, vector.timestamp)).toBe(
      vector.signature_header,
    );
  });

  test("accepts a Buffer body identical to the string body", () => {
    expect(
      verifyWebhookSignature(
        Buffer.from(vector.body, "utf8"),
        vector.signature_header,
        vector.secret,
        { timestamp: vector.timestamp, nowSecs: FRESH },
      ),
    ).toBe(true);
  });
});

describe("webhook HMAC — rejection paths", () => {
  test("rejects the wrong secret", () => {
    expect(
      verifyWebhookSignature(vector.body, vector.signature_header, "not-the-secret", {
        timestamp: vector.timestamp,
        nowSecs: FRESH,
      }),
    ).toBe(false);
  });

  test("rejects a tampered body", () => {
    expect(
      verifyWebhookSignature(
        `${vector.body} tampered`,
        vector.signature_header,
        vector.secret,
        { timestamp: vector.timestamp, nowSecs: FRESH },
      ),
    ).toBe(false);
  });

  test("accepts bare hex without the sha256= prefix", () => {
    const bare = vector.signature_header.replace("sha256=", "");
    expect(
      verifyWebhookSignature(vector.body, bare, vector.secret, {
        timestamp: vector.timestamp,
        nowSecs: FRESH,
      }),
    ).toBe(true);
  });

  test("rejects empty / malformed signatures", () => {
    for (const bad of ["", "sha256=zzzz", "sha256=abc"]) {
      expect(
        verifyWebhookSignature(vector.body, bad, vector.secret, {
          timestamp: vector.timestamp,
          nowSecs: FRESH,
        }),
      ).toBe(false);
    }
  });
});

describe("webhook HMAC — replay window", () => {
  test("rejects a stale delivery", () => {
    expect(
      verifyWebhookSignature(vector.body, vector.signature_header, vector.secret, {
        timestamp: vector.timestamp,
        nowSecs: TS + DEFAULT_MAX_AGE_SECS + 1,
      }),
    ).toBe(false);
  });

  test("accepts at the age boundary", () => {
    expect(
      verifyWebhookSignature(vector.body, vector.signature_header, vector.secret, {
        timestamp: vector.timestamp,
        nowSecs: TS + DEFAULT_MAX_AGE_SECS,
      }),
    ).toBe(true);
  });

  test("rejects a post-dated delivery beyond the skew tolerance", () => {
    expect(
      verifyWebhookSignature(vector.body, vector.signature_header, vector.secret, {
        timestamp: vector.timestamp,
        nowSecs: TS - DEFAULT_MAX_SKEW_SECS - 1,
      }),
    ).toBe(false);
  });

  test("rejects an unparseable timestamp", () => {
    for (const bad of ["", "   ", "not-a-number", "2026-07-28T00:00:00Z"]) {
      expect(
        verifyWebhookSignature(vector.body, vector.signature_header, vector.secret, {
          timestamp: bad,
        }),
      ).toBe(false);
    }
  });

  test("throws when the timestamp is omitted entirely", () => {
    // A pre-#2455 3-argument call must fail LOUDLY, never silently
    // mis-verify. TypeScript callers get a compile error; JS callers get this.
    expect(() =>
      (
        verifyWebhookSignature as unknown as (
          b: string,
          s: string,
          k: string,
        ) => boolean
      )(vector.body, vector.signature_header, vector.secret),
    ).toThrow(TypeError);
  });
});
