// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared capture-outcome predicate for the ai-memory Direct-API TypeScript shims.
 *
 * **This file is byte-identical in `clients/openai-shim-ts/src/` and
 * `clients/anthropic-shim-ts/src/`** and is pinned as such by
 * `__tests__/capture_outcome_parity.test.ts` in BOTH packages: the two
 * published npm packages must not be able to disagree about what "captured"
 * means. It carries no shim-specific text for that reason — the caller
 * supplies its own WARN prefix and prints `CaptureOutcome.detail`. (Each
 * package declares only an OPTIONAL vendor peer dependency and is published
 * independently to npm by `publish-sdk-shims.yml`, so a shared third package
 * would add a runtime dependency to both; one vendored source plus a
 * byte-identity pin is the single-predicate form that keeps each package
 * self-contained.)
 *
 * #3544 — the pre-fix predicate was the ABSENCE form: a response was counted
 * as a captured turn unless it matched one of the failure shapes the author
 * had enumerated (spawn error, non-zero exit, no matching frame, JSON-RPC
 * `error`, `isError: true`). Anything unenumerated — `status: "ask"`,
 * `status: "pending"`, an unreadable payload, an empty object, a `status` the
 * substrate grows in a later release — was reported to the caller as success
 * for a turn that was never stored.
 *
 * This module is the PRESENCE form, and it is the whole predicate:
 *
 *     a turn is CAPTURED if and only if the tool payload carries a
 *     non-empty string `memory_id`.
 *
 * Everything else is not a captured turn, and `status` is read only to say WHY
 * and to carry the recovery handle — never to decide the verdict. An
 * unrecognised status therefore fails CLOSED (`NOT_CAPTURED`) without this
 * file having to know it exists.
 *
 * Envelope vocabulary (the substrate is the source of truth; measured at
 * `src/mcp/tools/capture_turn.rs`):
 *
 * - `:437-444`  permission `Decision::Ask`  -> `{"status": "ask", "reason",
 *   "action", "namespace"}`. NOTHING is persisted; there is no id and no
 *   recovery path.
 * - `:488-496`  `GovernanceDecision::Pending` -> `{"status": "pending",
 *   "pending_id", "reason": GOVERNANCE_REQUIRES_APPROVAL, "action",
 *   "namespace"}`. The turn is DURABLY QUEUED and recoverable via
 *   `memory_pending_approve` — deferred, not lost.
 * - `:531-538`  dedup hit -> `{"memory_id", "dedup_hit": true, "layer": "L4",
 *   ...}` — **no `status` key at all**.
 * - `:539-547`  fresh write -> `{"memory_id", "dedup_hit": false,
 *   "layer": "L4", ...}` — **no `status` key at all**.
 *
 * Those two literals are the entire closed `status` vocabulary of
 * `memory_capture_turn`: `grep -n '"status"' src/mcp/tools/capture_turn.rs`
 * returns exactly `:439` and `:490`. `Decision::Deny` /
 * `GovernanceDecision::Deny` return `Err(..)`, which the MCP layer renders as
 * `isError: true` (`src/mcp/mod.rs`), not as a `status`. The persisted shape
 * is pinned independently by RFC-0001, which lists `memory_id` in the tool
 * result's `required` set (`docs/rfc/RFC-0001-mcp-turn-capture.md:160`).
 *
 * The tool payload rides one level of JSON nesting: `src/mcp/mod.rs:3762`
 * serialises the handler `Value` with `serde_json::to_string_pretty` into
 * `result.content[0].text`.
 *
 * **Non-wedging invariant:** every function here is total — it NEVER throws,
 * for any input, including `null`, `undefined` and arbitrary non-objects.
 */

// ── the substrate's closed `status` vocabulary ───────────────────────────── //

/** `capture_turn.rs:439` — permission Ask. Nothing persisted, no recovery id. */
export const STATUS_ASK = "ask";
/** `capture_turn.rs:490` — governance Pending. Durably queued, recoverable. */
export const STATUS_PENDING = "pending";
/**
 * Every `status` the substrate renders for `memory_capture_turn`. A value
 * outside this set is NOT assumed benign — see `classifyCaptureResponse`.
 */
export const KNOWN_STATUSES: ReadonlySet<string> = new Set([STATUS_ASK, STATUS_PENDING]);

// ── outcome kinds ────────────────────────────────────────────────────────── //

/** The turn is persisted: the payload carried a non-empty `memory_id`. */
export const CAPTURED = "captured";
/** Governance asked for approval; NOTHING was persisted and nothing is queued. */
export const ASK = "ask";
/** Governance deferred the write; the turn is durably queued under `pending_id`. */
export const PENDING = "pending";
/**
 * Anything else — transport fault, unreadable payload, a status this release
 * does not know, or a payload with no `memory_id`. Fail closed.
 */
export const NOT_CAPTURED = "not_captured";

export type CaptureOutcomeKind = "captured" | "ask" | "pending" | "not_captured";

/** The recovery verb a caller uses to redeem a `PENDING` turn. */
export const PENDING_APPROVE_TOOL = "memory_pending_approve";

/** What the substrate actually did with one `memory_capture_turn` call. */
export interface CaptureOutcome {
  readonly kind: CaptureOutcomeKind;
  readonly memoryId: string | null;
  readonly pendingId: string | null;
  readonly dedupHit: boolean;
  /** Human-readable reason, with no shim name — the caller prefixes it. */
  readonly detail: string;
}

/** True ONLY for a persisted turn. The one success predicate. */
export function isCaptured(outcome: CaptureOutcome): boolean {
  return outcome.kind === CAPTURED;
}

/** True when the turn is durably queued and recoverable, not stored. */
export function isDeferred(outcome: CaptureOutcome): boolean {
  return outcome.kind === PENDING;
}

function make(
  kind: CaptureOutcomeKind,
  fields: Partial<Omit<CaptureOutcome, "kind">> = {},
): CaptureOutcome {
  return Object.freeze({
    kind,
    memoryId: fields.memoryId ?? null,
    pendingId: fields.pendingId ?? null,
    dedupHit: fields.dedupHit ?? false,
    detail: fields.detail ?? "",
  });
}

function asObject(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/**
 * The `memory_capture_turn` tool payload object, or `null`.
 *
 * Unwraps the single level of JSON nesting the MCP layer adds
 * (`result.content[0].text`, `src/mcp/mod.rs:3762`). Returns `null` on every
 * shape mismatch. `null` is NOT a success shape — the persisted envelope is a
 * JSON object carrying `memory_id`.
 */
export function capturePayload(resp: unknown): Record<string, unknown> | null {
  const outer = asObject(resp);
  if (!outer) return null;
  const result = asObject(outer.result);
  if (!result) return null;
  const content = result.content;
  if (!Array.isArray(content) || content.length === 0) return null;
  const first = asObject(content[0]);
  if (!first) return null;
  const text = first.text;
  if (typeof text !== "string") return null;
  try {
    return asObject(JSON.parse(text));
  } catch {
    return null;
  }
}

/**
 * Classify one JSON-RPC `tools/call` response for `memory_capture_turn`.
 *
 * `resp` is the decoded response object, or `null`/`undefined` when the
 * substrate produced no matching frame. Total: never throws, for any input.
 *
 * The verdict is the PRESENCE form — captured iff a non-empty string
 * `memory_id` is in the payload — so every shape this function has never
 * seen, including a `status` added in a future release, is reported as NOT
 * captured rather than silently acknowledged.
 */
export function classifyCaptureResponse(resp: unknown): CaptureOutcome {
  if (resp === null || resp === undefined) {
    return make(NOT_CAPTURED, { detail: "no capture response from substrate" });
  }
  const outer = asObject(resp);
  if (!outer) {
    return make(NOT_CAPTURED, { detail: "capture response was not a JSON-RPC object" });
  }
  // A top-level JSON-RPC `error` member (unknown-method / invalid-params and
  // friends) carries no `result`, so screen it before the tool-level checks.
  if (outer.error !== null && outer.error !== undefined) {
    return make(NOT_CAPTURED, { detail: "substrate returned JSON-RPC error" });
  }
  const result = asObject(outer.result);
  if (!result) {
    return make(NOT_CAPTURED, { detail: "capture response carried no result object" });
  }
  // MCP renders a handler `Err(..)` — including governance Deny — as an Ok
  // result with `isError: true` (`src/mcp/mod.rs`).
  if (result.isError === true) {
    return make(NOT_CAPTURED, { detail: "substrate returned isError:true" });
  }

  const payload = capturePayload(resp);
  if (!payload) {
    return make(NOT_CAPTURED, {
      detail:
        "capture result payload was unreadable " +
        "(result.content[0].text is not a JSON object); " +
        "refusing to count it as a captured turn",
    });
  }

  const status = payload.status;
  if (status === STATUS_ASK) {
    // Nothing was written and there is no handle to redeem. Say exactly that,
    // and do NOT name a recovery path that does not exist.
    return make(ASK, {
      detail:
        "capture_turn returned status=ask (governance approval requested; " +
        "NOTHING was persisted and there is no recovery handle); " +
        "not counting as a captured turn",
    });
  }
  if (status === STATUS_PENDING) {
    const rawId = payload.pending_id;
    const pendingId = typeof rawId === "string" && rawId ? rawId : null;
    // The opposite lie from the original bug: a Pending turn is NOT lost. It
    // is durably queued, and `pending_id` is the ONLY handle that redeems it —
    // it must reach the caller, never be discarded.
    return make(PENDING, {
      pendingId,
      detail:
        `capture_turn returned status=pending, pending_id=${String(pendingId)} ` +
        `(the turn is DURABLY QUEUED for approval, NOT lost; redeem it with ` +
        `${PENDING_APPROVE_TOOL}); not counting as a captured turn`,
    });
  }

  const memoryId = payload.memory_id;
  if (typeof memoryId === "string" && memoryId) {
    return make(CAPTURED, { memoryId, dedupHit: payload.dedup_hit === true });
  }

  // Fail closed. Reached by an unrecognised `status`, an empty object, or a
  // payload whose `memory_id` is absent/blank/not a string. None of these is a
  // turn we can prove was stored, so none of them is success.
  return make(NOT_CAPTURED, {
    detail:
      `capture_turn returned no memory_id (status=${JSON.stringify(status) ?? "undefined"}); ` +
      "the turn was NOT persisted — not counting as a captured turn",
  });
}
