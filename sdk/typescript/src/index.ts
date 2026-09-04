// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * `@alphaone/ai-memory` — TypeScript SDK for the ai-memory HTTP API.
 *
 * Primary entry point:
 * - {@link AiMemoryClient} — main client class.
 *
 * Also re-exports all request/response types and the error hierarchy.
 * Webhook helpers live in the `./webhooks` subpath so the SDK can ship
 * to browsers without pulling in `node:crypto` by default.
 */

export {
  AiMemoryClient,
  DEFAULT_MEMORY_KIND,
  DEFAULT_NAMESPACE,
} from "./client.js";
export type { StoreOptions, UpdateOptions } from "./client.js";

export * from "./types.js";

export {
  ApiError,
  ValidationError,
  UnauthorizedError,
  NotFoundError,
  ConflictError,
  ServerError,
  NetworkError,
  apiErrorFromResponse,
} from "./errors.js";

export type { ApiErrorBody } from "./errors.js";

export {
  DEFAULT_MAX_AGE_SECS,
  DEFAULT_MAX_SKEW_SECS,
  SIGNATURE_HEADER,
  TIMESTAMP_HEADER,
  signWebhookBody,
  verifyWebhookSignature,
} from "./webhooks.js";
export type { VerifyWebhookOptions } from "./webhooks.js";

// #2455 — Ed25519 write attestation. `POST /api/v1/memories` fails CLOSED by
// default, so a client that cannot sign cannot store against a stock daemon.
export {
  AgentSigningKey,
  DOMAIN_SEPARATION_TAG,
  attestationFields,
  // #3464 — proof-of-possession bind challenge helpers.
  bindChallengeTranscript,
  signBindChallenge,
  BIND_CHALLENGE_V1_DOMAIN,
  canonicalCborWrite,
  canonicalizeCreatedAt,
  contentSha256,
  rfc3339Now,
  signWrite,
} from "./attestation.js";
export type {
  AttestationFields,
  AttestationInput,
  SignableWrite,
} from "./attestation.js";

// v0.6.4-007 — `requireProfile` runtime profile-bootstrap helper.
export {
  ProfileNotLoaded,
  requireProfile,
  resolveRequiredFamilies,
} from "./profile.js";
export type { CapabilitiesProbe } from "./profile.js";
