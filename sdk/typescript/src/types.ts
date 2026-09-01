// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

/**
 * TypeScript mirror of `src/models.rs`. Field names match the Rust struct
 * serde output verbatim (snake_case on the wire). Keep this file in lock-step
 * with `src/models.rs` in the main repo.
 */

/** Memory tier — mirrors human memory systems (short: 6h TTL, mid: 7d, long: permanent). */
export type Tier = "short" | "mid" | "long";

/** Visibility scope (Task 1.5). Controls which agents can see the memory. */
export type Scope = "private" | "team" | "unit" | "org" | "collective";

/**
 * Link relation kinds (closed set — server validates).
 *
 * All 9 variants of `MemoryLinkRelation` (`src/models/link.rs`), mirrored by
 * `VALID_RELATIONS` in `src/validate.rs` and the SQL CHECK constraints.
 *
 * Note `derived_from` and `derives_from` differ by one character and point in
 * OPPOSITE directions: `derived_from` is N->1 consolidation-merge provenance,
 * `derives_from` is 1->N atomisation-split provenance.
 */
export type Relation =
  | "related_to"
  | "supersedes"
  | "contradicts"
  | "derived_from"
  | "reflects_on"
  | "derives_from"
  | "decomposes_into"
  | "depends_on"
  | "advances";

/** Allowed `source` values — see `src/validate.rs` `VALID_SOURCES`. */
export type Source =
  | "user"
  | "claude"
  | "hook"
  | "api"
  | "cli"
  | "import"
  | "consolidation"
  | "system"
  | "chaos";

/**
 * A Memory row. Corresponds to `ai_memory::models::Memory`, which carries
 * **30 fields** at v1.0.0 (`Memory::FIELD_COUNT`, SSOT
 * `src/models/memory.rs`) — and all 30 are now declared here (#2834). The
 * first 15 are the v0.6.x core; the 15 declared after `metadata` are the
 * v0.7.0+ additions (`reflection_depth`, `memory_kind`, `entity_id`,
 * `persona_version`, `citations`, `source_uri`, `source_span`,
 * `confidence_source`, `confidence_signals`, `confidence_decayed_at`,
 * `version`, `lifecycle_state`, `cid`, `valid_from`, `valid_until`).
 *
 * This is a **typing-completeness** change, not a data-loss fix: TypeScript
 * interfaces are structural and do not strip at runtime, so those 15 already
 * survived a round trip — they were untyped, never lost. Declaring them gives
 * callers static types for the full row. (`kind_provenance` is a schema-v79 DB
 * column but is NOT a field on the Rust `struct Memory`, so it is deliberately
 * not declared here.)
 *
 * Every added field is `?: T | null` so a response from an OLDER daemon that
 * omits it still type-checks.
 *
 * NOTE: `metadata` is `serde_json::Value` server-side — we expose it as
 * `Record<string, unknown>` on the SDK side (server validates it must be
 * a JSON object at write time).
 */
export interface Memory {
  id: string;
  tier: Tier;
  namespace: string;
  title: string;
  content: string;
  tags: string[];
  /** 1..=10 */
  priority: number;
  /** 0.0..=1.0 */
  confidence: number;
  source: string;
  access_count: number;
  /** RFC3339 */
  created_at: string;
  /** RFC3339 */
  updated_at: string;
  last_accessed_at?: string | null;
  expires_at?: string | null;
  metadata: Record<string, unknown>;
  // v0.7.0+ typed columns (#2834 typing completeness). Wire keys match the
  // Rust serde field names verbatim (snake_case). All optional so an older
  // daemon's response that omits any of them still type-checks.
  /** Recursion depth in the reflection tree (0 for caller-minted rows). */
  reflection_depth?: number | null;
  /**
   * snake_case memory-kind discriminator on the wire (e.g. `"observation"`,
   * `"reflection"`, `"persona"`). Kept as `string` so a future variant the
   * SDK predates still type-checks.
   */
  memory_kind?: string | null;
  entity_id?: string | null;
  persona_version?: number | null;
  /** Fact-provenance Citation envelopes ({uri, accessed_at, hash?, span?}). */
  citations?: unknown[] | null;
  source_uri?: string | null;
  /** Byte-range into the cited source body: `{ start, end }`. */
  source_span?: { start: number; end: number } | null;
  /** snake_case confidence-provenance discriminator (e.g. `"caller_provided"`). */
  confidence_source?: string | null;
  confidence_signals?: Record<string, unknown> | null;
  /** RFC3339 */
  confidence_decayed_at?: string | null;
  /** Optimistic-concurrency version counter. */
  version?: number | null;
  /** snake_case lifecycle state (e.g. `"open"`). */
  lifecycle_state?: string | null;
  /** BLAKE3 content-id (`b3:<hex>`). */
  cid?: string | null;
  /** RFC3339 claim-validity lower bound (inclusive). */
  valid_from?: string | null;
  /** RFC3339 claim-validity upper bound (exclusive). */
  valid_until?: string | null;
}

/** Envelope returned by `GET /api/v1/memories/:id`. */
export interface MemoryDetail {
  memory: Memory;
  links: MemoryLink[];
}

/** A scored Memory returned by `/recall` (Memory + `score` field). */
export interface ScoredMemory extends Memory {
  score: number;
}

/** Typed directional relationship between two memories. */
export interface MemoryLink {
  source_id: string;
  target_id: string;
  relation: string;
  created_at: string;
}

/** Body for `POST /api/v1/memories`. */
export interface CreateMemoryRequest {
  title: string;
  content: string;
  tier?: Tier;
  namespace?: string;
  tags?: string[];
  /** 1..=10 (default 5) */
  priority?: number;
  /** 0.0..=1.0 (default 1.0) */
  confidence?: number;
  source?: Source | string;
  /** RFC3339 */
  expires_at?: string;
  /** Positive, <=1 year */
  ttl_secs?: number;
  metadata?: Record<string, unknown>;
  /**
   * Optional explicit agent_id (precedence: this > `X-Agent-Id` header >
   * server-side anonymous fallback).
   */
  agent_id?: string;
  scope?: Scope;
  /**
   * #1385 — Batman-taxonomy memory kind (`"observation"` default,
   * `"decision"`, `"claim"`, ...). It is INSIDE the signed attestation
   * envelope, so a signed write must send the same kind it signed.
   */
  kind?: string;
  /**
   * #626 Layer-3 / #2455 — detached Ed25519 attestation over the
   * `SignableWrite` envelope, STANDARD base64.
   *
   * `POST /api/v1/memories` is `WriteSurface::HttpDirect` and fails CLOSED by
   * default (`src/identity/attest.rs:130-136`), so an UNSIGNED store is
   * `403 ATTESTATION_FAILED` on a stock daemon. Before #2455 this field did
   * not exist here and the SDK could not produce a successful store at all.
   * Populate it with `attestationFields()` from `@alphaone/ai-memory` — or
   * pass `signingKey` to `client.store()` and let the client do it.
   *
   * When set, {@link CreateMemoryRequest.created_at} is REQUIRED.
   */
  signature?: string;
  /**
   * RFC3339 timestamp the caller signed. Required alongside `signature`;
   * validated against the daemon's +/-300s attestation freshness window and
   * then adopted verbatim.
   */
  created_at?: string;
}

/**
 * Body for `PUT /api/v1/memories/:id`.
 *
 * **Optimistic concurrency is a HEADER, not a body field.** The daemon reads
 * the expected row version from `If-Match` (bare integer or quoted
 * ETag-style) — `src/handlers/memories.rs:245-260`. Rust's `struct
 * UpdateMemory` (`src/models/memory.rs:1602`) has NO `version` field, so a
 * `version` key placed in this body would be ignored by the server while
 * giving the caller a false sense of lost-update protection. Pass
 * `expectedVersion` to `client.update()` instead; a stale version yields
 * `409` (`ConflictError`).
 */
export interface UpdateMemoryRequest {
  title?: string;
  content?: string;
  tier?: Tier;
  namespace?: string;
  tags?: string[];
  priority?: number;
  confidence?: number;
  expires_at?: string;
  metadata?: Record<string, unknown>;
}

/**
 * A per-row rejection in a {@link BulkCreateResponse} `errors[]` entry.
 *
 * `field` is echoed only when the server has a slug-shaped attribution;
 * `existing_id` is present for a `CONFLICT` row that collided with a
 * pre-existing stored `(title, namespace)` under `on_conflict=error`
 * (`src/handlers/bulk.rs::BulkLedger::{reject_class,reject_conflict}`).
 */
export interface BulkCreateError {
  index: number;
  code: string;
  error: string;
  field?: string;
  existing_id?: string;
}

/**
 * A `deduped_rows[]` disclosure: input row `index` was superseded, within
 * the SAME batch, by a LATER row (`superseded_by`, an input index) sharing
 * its `(title, namespace)`. `superseded_by` is a NUMBER here.
 */
export interface BulkDedupedRow {
  index: number;
  superseded_by: number;
}

/**
 * An `updated_rows[]` disclosure (#2725): input row `index` REPLACED a
 * pre-existing stored row under an explicit overwrite `on_conflict`;
 * `superseded_by` is the overwritten STORED id (a string).
 */
export interface BulkUpdatedRow {
  index: number;
  superseded_by: string;
}

/**
 * Response envelope for `POST /api/v1/memories/bulk`
 * (`src/handlers/bulk.rs::BulkLedger::into_response`).
 *
 * The reconciliation identity a fleet loader asserts is
 * `created + updated + deduped + rejected + pending.length === sent`.
 * `created` counts rows this call INSERTED and `updated` counts rows it
 * upserted onto an already-existing `(title, namespace)`.
 *
 * The daemon answers **207 Multi-Status** for a partially-applied batch and
 * **202** for a fully-queued (all-pending) batch — both 2xx, so `res.ok`
 * gating (client.ts) accepts them. `deduped_rows`, `updated_rows`,
 * `warnings`, `embed_status`, and `embed_status_reason` are emitted only
 * when non-empty / degraded, so they are optional.
 */
export interface BulkCreateResponse {
  sent: number;
  created: number;
  updated: number;
  deduped: number;
  rejected: number;
  errors: BulkCreateError[];
  pending: Array<Record<string, unknown>>;
  deduped_rows?: BulkDedupedRow[];
  updated_rows?: BulkUpdatedRow[];
  warnings?: string[];
  embed_status?: string;
  embed_status_reason?: string;
}

/** Body for `POST /api/v1/recall`. */
export interface RecallRequest {
  context: string;
  namespace?: string;
  limit?: number;
  /** Comma-separated tag filter. */
  tags?: string;
  since?: string;
  until?: string;
  as_agent?: string;
  budget_tokens?: number;
}

/** Query for `GET /api/v1/recall`. */
export interface RecallQuery extends Partial<RecallRequest> {
  context?: string;
}

/** Response from `/recall`. */
export interface RecallResponse {
  memories: ScoredMemory[];
  count: number;
  tokens_used: number;
  budget_tokens?: number;
}

/** Query for `GET /api/v1/search`. */
export interface SearchQuery {
  q: string;
  namespace?: string;
  tier?: Tier;
  limit?: number;
  min_priority?: number;
  since?: string;
  until?: string;
  tags?: string;
  agent_id?: string;
  as_agent?: string;
}

/** Response from `/search`. */
export interface SearchResponse {
  results: Memory[];
  count: number;
  query: string;
}

/** Query for `GET /api/v1/memories`. */
export interface ListQuery {
  namespace?: string;
  tier?: Tier;
  limit?: number;
  offset?: number;
  min_priority?: number;
  since?: string;
  until?: string;
  tags?: string;
  agent_id?: string;
}

/** Response from `/memories` list. */
export interface ListResponse {
  memories: Memory[];
  count: number;
}

/** Body for `POST /api/v1/links`. */
export interface LinkRequest {
  source_id: string;
  target_id: string;
  /** Default: "related_to". */
  relation?: Relation;
}

/** Body for `POST /api/v1/forget`. */
export interface ForgetRequest {
  namespace?: string;
  pattern?: string;
  tier?: Tier;
}

export interface TierCount {
  tier: string;
  count: number;
}
export interface NamespaceCount {
  namespace: string;
  count: number;
}

export interface Stats {
  total_memories: number;
  by_tier: TierCount[];
  by_namespace: NamespaceCount[];
  expiring_soon: number;
  links_count: number;
  db_size_bytes: number;
  live: number;
  expired_pending_gc: number;
  storage_backend: string;
}

export interface HealthResponse {
  status: "ok" | "error";
  service: string;
}

/** Agent registration (Task 1.3). */
export interface AgentRegistration {
  agent_id: string;
  agent_type: string;
  capabilities: string[];
  registered_at: string;
  last_seen_at: string;
}

export interface RegisterAgentRequest {
  agent_id: string;
  agent_type: string;
  capabilities?: string[];
}

// --------------------------------------------------------------------------
// v0.6.0.0 new endpoints (target shape — some may not yet be merged in Rust)
// --------------------------------------------------------------------------

/** Webhook subscription for memory events. */
export interface Subscription {
  id: string;
  agent_id: string;
  /** Target URL that receives POSTed events. */
  callback_url: string;
  /** Event types to subscribe to (e.g. "memory.stored", "memory.updated"). */
  events: string[];
  /** HMAC-SHA256 secret for webhook signature verification. */
  secret?: string;
  /** Optional namespace filter. */
  namespace?: string;
  created_at: string;
}

export interface CreateSubscriptionRequest {
  callback_url: string;
  events: string[];
  secret?: string;
  namespace?: string;
}

export interface ListSubscriptionsResponse {
  subscriptions: Subscription[];
  count: number;
}

/** Memory ACL grant/revoke (Task 1.5 extensions). */
export interface GrantRequest {
  /** Agent receiving access. */
  agent_id: string;
  /** Permission level granted. */
  permission: "read" | "write" | "admin";
}

export interface RevokeRequest {
  agent_id: string;
}

/** Agent-to-agent notification (inbox). */
export interface NotifyRequest {
  target_agent_id: string;
  title: string;
  payload?: unknown;
  content?: string;
  priority?: number;
  tier?: Tier;
  agent_id?: string;
  why_trace?: unknown;
}

export interface InboxMessage {
  id: string;
  from: string;
  to: string;
  subject: string;
  body: string;
  memory_id?: string;
  payload?: Record<string, unknown>;
  read: boolean;
  created_at: string;
}

export interface InboxResponse {
  messages: InboxMessage[];
  count: number;
  unread: number;
}

export interface InboxQuery {
  /** Only return unread messages. */
  unread?: boolean;
  limit?: number;
  since?: string;
}

/** Cluster peer info. */
export interface ClusterPeer {
  agent_id: string;
  endpoint: string;
  last_seen_at: string;
  status: "healthy" | "degraded" | "unreachable";
}

export interface ClusterRequest {
  /** Action: "join", "leave", "list", "status". */
  action: "join" | "leave" | "list" | "status";
  endpoint?: string;
  agent_id?: string;
}

export interface ClusterResponse {
  peers: ClusterPeer[];
  self: ClusterPeer;
}

/** Raw Prometheus text-format payload wrapper. */
export interface MetricsResponse {
  /** Prometheus exposition format text. */
  body: string;
  content_type: string;
}

// --------------------------------------------------------------------------
// Client configuration
// --------------------------------------------------------------------------

export interface ClientOptions {
  /**
   * Base URL, e.g. `http://localhost:9077`. The `/api/v1/` prefix is added
   * by the client — pass only the scheme + host + port.
   */
  baseUrl: string;
  /** Optional API key (sent as `X-API-Key` header). */
  apiKey?: string;
  /**
   * Optional default `X-Agent-Id` header sent on every request. Can be
   * overridden per-call via request-level options.
   */
  agentId?: string;
  /** Request timeout in milliseconds. Default: 30_000. */
  timeoutMs?: number;
  /** Extra headers merged into every request. */
  headers?: Record<string, string>;
  /**
   * Optional AbortSignal — when aborted, all in-flight requests using this
   * client's fetch() invocation will abort.
   */
  signal?: AbortSignal;
}

/** Per-call overrides for any client method. */
export interface RequestOptions {
  /** Overrides the client's default agent_id header for this request. */
  agentId?: string;
  signal?: AbortSignal;
  /** Extra headers merged into this request. */
  headers?: Record<string, string>;
}
