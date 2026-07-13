// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Crate-wide SSOT for JSON/row FIELD-NAME strings (#1558 batch 5 wave 4).
//
// Every wire-payload object key (`json!({...})`), `serde_json::Value`
// extraction key (`.get("x")` / `["x"]`), and DB row column-name string
// (sqlx `row.try_get("x")`, rusqlite `row.get("x")`, standalone
// column-name arguments) that is duplicated across production sites
// references ONE named const here instead of a scattered literal, per
// the pm-v3.1 hardcoded-literal lint-gate
// (`scripts/check-hardcoded-literals.sh`).
//
// Position classes routed here:
//   - `json!({ (field_names::CREATED_AT): value, ... })` — the
//     parenthesized-key form (compile-verified pattern; see
//     `crate::handlers::QUOTA_REFUSED_FIELD` usage from wave 3).
//   - `.get(field_names::X)` / `[field_names::X]` on response/row JSON.
//   - sqlx / rusqlite column-name arguments.
//
// NOT routed here:
//   - serde attribute positions (`#[serde(rename/alias)]`), derive-macro
//     positions, thiserror `#[error]` strings, struct field identifiers.
//   - Names embedded inside larger SQL statement strings — SQL text is
//     left alone entirely.
//
// Relationship to `crate::mcp::param_names`: that module remains the
// public SSOT surface for MCP tool-call parameter extraction. To keep a
// single spelling per string, every param_names const whose name also
// lives here is defined as an alias of the corresponding const below.
//
// Keep alphabetical. Const name mirrors the canonical snake_case JSON
// key / column spelling in UPPER_SNAKE.

/// `access_count` — wire/row field name.
pub const ACCESS_COUNT: &str = "access_count";
/// `action_type` — wire/row field name.
pub const ACTION_TYPE: &str = "action_type";
/// `agent_filter` — wire/row field name.
pub const AGENT_FILTER: &str = "agent_filter";
/// `agent_pubkey` — wire/row field name.
pub const AGENT_PUBKEY: &str = "agent_pubkey";
/// `agent_type` — wire/row field name.
pub const AGENT_TYPE: &str = "agent_type";
/// `allowed_tools` — wire/row field name.
pub const ALLOWED_TOOLS: &str = "allowed_tools";
/// `archived_at` — wire/row field name.
pub const ARCHIVED_AT: &str = "archived_at";
/// `archive_reason` — wire/row field name.
pub const ARCHIVE_REASON: &str = "archive_reason";
/// #1725 (v0.8.0) — the `archive_reason` VALUE stamped on the
/// immediately-prior content snapshot captured before a lossless
/// in-place content edit (the default update path archives the old
/// content under the SAME memory_id, no fork). Shared SSOT so the
/// sqlite + postgres backends and the parity test agree on the marker.
pub const ARCHIVE_REASON_IN_PLACE_EDIT: &str = "in_place_edit";
/// `atomisation_archived_at` — wire/row field name.
pub const ATOMISATION_ARCHIVED_AT: &str = "atomisation_archived_at";
/// `atom_count` — wire/row field name.
pub const ATOM_COUNT: &str = "atom_count";
/// `atomised_into` — wire/row field name (#1637 archive projection).
pub const ATOMISED_INTO: &str = "atomised_into";
/// `atom_of` — wire/row field name (#1637 archive projection).
pub const ATOM_OF: &str = "atom_of";
/// `mentioned_entity_id` — wire/row field name (#1637 archive projection).
pub const MENTIONED_ENTITY_ID: &str = "mentioned_entity_id";
/// `attest_level` — wire/row field name.
pub const ATTEST_LEVEL: &str = "attest_level";
/// `write_signature` — optional `metadata` key carrying a base64 detached
/// Ed25519 per-write content signature over the #626 [`SignableWrite`]
/// envelope (`agent_id + namespace + title + kind + created_at +
/// sha256(content)`). Read on the federation receive path (#1464) to verify
/// relayed content against the claimed author's enrolled key and upgrade the
/// row from `attest_level=claimed` to `agent_attested`. Additive, free-form;
/// absent on legacy/unsigned peers (sender-side emit is the tracked v0.9
/// half). `SignableWrite` excludes `metadata`, so the signature is stable
/// even as this key is added to the map.
///
/// [`SignableWrite`]: crate::identity::sign::SignableWrite
pub const WRITE_SIGNATURE: &str = "write_signature";
/// v1.0.0 crypto-core (#1942, spec §2.3) — `write_v2` presentation-envelope
/// + `agent_subkey_certs` JSON field keys. One named const per key so the
/// v2 ingest parser, the CLI enroll/inspect surface, and the docs never
/// scatter the raw string (the hardcoded-literal gate SSOT).
pub const CERT_SIGNATURE: &str = "cert_signature";
/// `not_before` — sub-key cert validity-window start (RFC3339).
pub const NOT_BEFORE: &str = "not_before";
/// `signature_b64` — base64 detached-signature JSON output field (shared by
/// the rules + #1831 recovery-guardian CLI/MCP surfaces).
pub const SIGNATURE_B64: &str = "signature_b64";
/// `not_after` — sub-key cert validity-window end (RFC3339).
pub const NOT_AFTER: &str = "not_after";
/// `instance_key_id` — certified per-instance sub-key id (base64 bytes).
pub const INSTANCE_KEY_ID: &str = "instance_key_id";
/// `model_version_ref` — bound model-version reference (base64 bytes).
pub const MODEL_VERSION_REF: &str = "model_version_ref";
/// `content_codec` — v2 content-digest multihash codec token.
pub const CONTENT_CODEC: &str = "content_codec";
/// `cert` — the nested sub-key-cert object in a `write_v2` envelope.
pub const CERT: &str = "cert";
/// `principal` — the certified principal (agent id) key.
pub const PRINCIPAL: &str = "principal";
/// `suite_tag` — committed advisory algorithm-suite tag key.
pub const SUITE_TAG: &str = "suite_tag";
/// `session_id` — optional presence-encoded session id key.
pub const SESSION_ID: &str = "session_id";
/// `version_vector` — per-memory CRDT vector-clock metadata key (#1756 /
/// #1719 item 2). Lives inside `metadata`; merged by pointwise-max.
pub const VERSION_VECTOR: &str = "version_vector";
/// `budget_tokens` — wire/row field name.
pub const BUDGET_TOKENS: &str = "budget_tokens";
/// `by_namespace` — wire/row field name.
pub const BY_NAMESPACE: &str = "by_namespace";
/// `by_source_uri` — wire/row field name.
pub const BY_SOURCE_URI: &str = "by_source_uri";
/// `candidates_scanned` — wire/row field name.
pub const CANDIDATES_SCANNED: &str = "candidates_scanned";
/// `canonical_name` — wire/row field name.
pub const CANONICAL_NAME: &str = "canonical_name";
/// `capabilities` — wire/row field name.
pub const CAPABILITIES: &str = "capabilities";
/// `compatibility` — wire/row field name.
pub const COMPATIBILITY: &str = "compatibility";
/// `confidence` — wire/row field name.
pub const CONFIDENCE: &str = "confidence";
/// `confidence_decayed_at` — wire/row field name.
pub const CONFIDENCE_DECAYED_AT: &str = "confidence_decayed_at";
/// `confidence_signals` — wire/row field name.
pub const CONFIDENCE_SIGNALS: &str = "confidence_signals";
/// `confidence_source` — wire/row field name.
pub const CONFIDENCE_SOURCE: &str = "confidence_source";
/// `confirmed_contradictions` — wire/row field name.
pub const CONFIRMED_CONTRADICTIONS: &str = "confirmed_contradictions";
/// `consolidated` — wire/row field name.
pub const CONSOLIDATED: &str = "consolidated";
/// `content_sha256` — wire/row field name.
pub const CONTENT_SHA256: &str = "content_sha256";
/// v0.9.0 G7 (#1824) — `contradiction_conserved` metadata JSON key.
/// Set `true` on the loser row when a confirmed contradiction was
/// CONSERVED (both memories retained) instead of hard-deleting the
/// loser. The re-entry gate in `forget_if_superseded` reads this to
/// stay idempotent. LOCAL-only: `merge_metadata` never adopts it from a
/// peer (see `crdt_merge`).
pub const CONTRADICTION_CONSERVED: &str = "contradiction_conserved";
/// v0.9.0 G7 (#1824) — `contradiction_soft_loser` metadata JSON key.
/// Set `true` on the conserved loser as a reversible, node-local soft
/// down-weight marker (recall ranking may consult it). Cleared on
/// rollback. LOCAL-only (never adopted from a peer).
pub const CONTRADICTION_SOFT_LOSER: &str = "contradiction_soft_loser";
/// v0.9.0 G7 (#1824) — `contradiction_winner_id` metadata JSON key.
/// Carries the id of the winning (newer, higher-or-equal confidence)
/// memory on the conserved loser row. LOCAL-only (never adopted from a
/// peer).
pub const CONTRADICTION_WINNER_ID: &str = "contradiction_winner_id";
/// `correlation_id` — wire/row field name.
pub const CORRELATION_ID: &str = "correlation_id";
/// `created_at` — wire/row field name.
pub const CREATED_AT: &str = "created_at";
/// `created_by` — wire/row field name.
pub const CREATED_BY: &str = "created_by";
/// `current_tier` — wire/row field name.
pub const CURRENT_TIER: &str = "current_tier";
/// `custom_kind` — wire/row field name.
pub const CUSTOM_KIND: &str = "custom_kind";
/// `decided_at` — wire/row field name.
pub const DECIDED_AT: &str = "decided_at";
/// `decided_by` — wire/row field name.
pub const DECIDED_BY: &str = "decided_by";
/// `default_timeout_seconds` — wire/row field name.
pub const DEFAULT_TIMEOUT_SECONDS: &str = "default_timeout_seconds";
/// `description` — wire/row field name.
pub const DESCRIPTION: &str = "description";
/// `earliest_updated_at` — wire/row field name.
pub const EARLIEST_UPDATED_AT: &str = "earliest_updated_at";
/// `elapsed_ms` — wire/row field name.
pub const ELAPSED_MS: &str = "elapsed_ms";
/// `embeddings` — wire field name. Federation `/sync/push` payloads
/// carry shipped source-side embedding vectors under this key
/// (#1566 / #1579 B1 embed-once-replicate-vector). The array lives
/// inside the Ed25519-signed body bytes; decode is tolerant of the
/// field's absence so older peers interoperate.
pub const EMBEDDINGS: &str = "embeddings";
/// `embedding_dim` — wire/row field name (#1169 dim reporting; #1598
/// `ResolvedEmbeddings` Debug field).
pub const EMBEDDING_DIM: &str = "embedding_dim";
/// `entity_id` — metadata key naming the entity a reflection is about
/// (drives auto-persona cadence via the denormalised
/// [`MENTIONED_ENTITY_ID`] column). Canonical spelling SSOT; the MCP
/// param `crate::mcp::param_names::ENTITY_ID` aliases this const (#1665).
pub const ENTITY_ID: &str = "entity_id";
/// `event_types` — wire/row field name.
pub const EVENT_TYPES: &str = "event_types";
/// `excluded_for_scope` — wire/row field name.
pub const EXCLUDED_FOR_SCOPE: &str = "excluded_for_scope";
/// `excluded_for_scope_private` — wire/row field name.
pub const EXCLUDED_FOR_SCOPE_PRIVATE: &str = "excluded_for_scope_private";
/// `expanded_terms` — wire/row field name.
pub const EXPANDED_TERMS: &str = "expanded_terms";
/// `expired_at` — wire/row field name.
pub const EXPIRED_AT: &str = "expired_at";
/// `expired_deleted` — wire/row field name.
pub const EXPIRED_DELETED: &str = "expired_deleted";
/// `expires_at` — wire/row field name.
pub const EXPIRES_AT: &str = "expires_at";
/// `exported_at` — wire/row field name.
pub const EXPORTED_AT: &str = "exported_at";
/// `from_agent_id` — wire/row field name.
pub const FROM_AGENT_ID: &str = "from_agent_id";
/// `generated_at` — wire/row field name.
pub const GENERATED_AT: &str = "generated_at";
/// `governance` — wire/row field name.
pub const GOVERNANCE: &str = "governance";
/// `imported_from_agent_id` — wire/row field name.
pub const IMPORTED_FROM_AGENT_ID: &str = "imported_from_agent_id";
/// `include_invalidated` — wire/row field name.
pub const INCLUDE_INVALIDATED: &str = "include_invalidated";
/// v0.9.0 §11.5 B7-SKILL (#1865) — `invocation_record` wire field name.
/// Carries the `{event_id, recorded_at}` envelope of the `signed_events`
/// row appended by `memory_skill_get`'s activation-invocation capture.
pub const INVOCATION_RECORD: &str = "invocation_record";
/// `is_duplicate` — wire/row field name.
pub const IS_DUPLICATE: &str = "is_duplicate";
/// `is_reflection` — wire/row field name.
pub const IS_REFLECTION: &str = "is_reflection";
/// `key_source` — wire/row field name.
pub const KEY_SOURCE: &str = "key_source";
/// `last_accessed_at` — wire/row field name.
pub const LAST_ACCESSED_AT: &str = "last_accessed_at";
/// `lifecycle_state` — wire/row field name (v0.8.0 Pillar 2 #1709, schema v64).
pub const LIFECYCLE_STATE: &str = "lifecycle_state";
/// `encrypted_envelope` — wire/row field name (#228 at-rest content
/// encryption, schema v44 sqlite / v68 postgres). The BLOB/BYTEA column
/// carrying the sealed [`crate::encryption::Envelope`] ciphertext when at-rest
/// encryption is enabled; NULL on every legacy + encryption-off row.
pub const ENCRYPTED_ENVELOPE: &str = "encrypted_envelope";
/// `cid` — wire/row field name (v0.9.0 G8 #1825, schema v74). The
/// additive `b3:<hex>` content-address minted from a memory's genesis
/// identity; NULL on legacy rows the v74 backfill couldn't stamp.
pub const CID: &str = "cid";
/// `cid_genesis` — row field name (v0.9.0 G8 #1825, schema v74). The
/// storage-internal BLOB carrying the canonical cid pre-image
/// ([`crate::identity::cid::canonical_cid_preimage`]); read on demand by
/// the verify path only, NEVER a `Memory` field. NULLed on erasure
/// (RecordKind::Forget) so the stored content digest cannot become a
/// confirmation-oracle for erased content, while `cid` is retained.
pub const CID_GENESIS: &str = "cid_genesis";
/// `last_seen_at` — wire/row field name.
pub const LAST_SEEN_AT: &str = "last_seen_at";
/// `latency_ms` — wire/row field name.
pub const LATENCY_MS: &str = "latency_ms";
/// `latest_updated_at` — wire/row field name.
pub const LATEST_UPDATED_AT: &str = "latest_updated_at";
/// `local_depth_at_arrival` — wire/row field name.
pub const LOCAL_DEPTH_AT_ARRIVAL: &str = "local_depth_at_arrival";
/// `memories_dropped` — wire/row field name.
pub const MEMORIES_DROPPED: &str = "memories_dropped";
/// `memory_kind` — wire/row field name.
pub const MEMORY_KIND: &str = "memory_kind";
/// `namespaces` — wire/row field name.
pub const NAMESPACES: &str = "namespaces";
/// `namespace_filter` — wire/row field name.
pub const NAMESPACE_FILTER: &str = "namespace_filter";
/// `observations` — wire/row field name.
pub const OBSERVATIONS: &str = "observations";
/// `observed_by` — wire/row field name.
pub const OBSERVED_BY: &str = "observed_by";
/// `older_than_days` — wire/row field name.
pub const OLDER_THAN_DAYS: &str = "older_than_days";
/// `original_depth` — wire/row field name.
pub const ORIGINAL_DEPTH: &str = "original_depth";
/// `owner_scope` — wire/row field name.
pub const OWNER_SCOPE: &str = "owner_scope";
/// `parameters_schema` — wire/row field name.
pub const PARAMETERS_SCHEMA: &str = "parameters_schema";
/// `parent_namespace` — wire/row field name.
pub const PARENT_NAMESPACE: &str = "parent_namespace";
/// `peer_origin` — wire/row field name.
pub const PEER_ORIGIN: &str = "peer_origin";
/// `pending_id` — wire/row field name.
pub const PENDING_ID: &str = "pending_id";
/// `persona_version` — wire/row field name.
pub const PERSONA_VERSION: &str = "persona_version";
/// `previous_valid_until` — wire/row field name.
pub const PREVIOUS_VALID_UNTIL: &str = "previous_valid_until";
/// `properties` — wire/row field name (JSON-Schema object key).
pub const PROPERTIES: &str = "properties";
/// `reflection_depth` — wire/row field name.
pub const REFLECTION_DEPTH: &str = "reflection_depth";
/// `reflection_id` — wire/row field name.
pub const REFLECTION_ID: &str = "reflection_id";
/// `reflection_metadata` — wire/row field name.
pub const REFLECTION_METADATA: &str = "reflection_metadata";
/// `registered` — wire/row field name.
pub const REGISTERED: &str = "registered";
/// `registered_at` — wire/row field name.
pub const REGISTERED_AT: &str = "registered_at";
/// `requested_at` — wire/row field name.
pub const REQUESTED_AT: &str = "requested_at";
/// `requested_by` — wire/row field name.
pub const REQUESTED_BY: &str = "requested_by";
/// `required_tier` — wire/row field name.
pub const REQUIRED_TIER: &str = "required_tier";
/// `resource_path` — wire/row field name.
pub const RESOURCE_PATH: &str = "resource_path";
/// `schema_version` — wire/row field name.
pub const SCHEMA_VERSION: &str = "schema_version";
/// `scope_status` — wire/row field name.
pub const SCOPE_STATUS: &str = "scope_status";
/// `sender_agent_id` — wire/row field name.
pub const SENDER_AGENT_ID: &str = "sender_agent_id";
/// `signing_agent` — wire/row field name.
pub const SIGNING_AGENT: &str = "signing_agent";
/// `similarity` — wire/row field name.
pub const SIMILARITY: &str = "similarity";
/// `skill_description` — wire/row field name.
pub const SKILL_DESCRIPTION: &str = "skill_description";
/// `skill_name` — wire/row field name.
pub const SKILL_NAME: &str = "skill_name";
/// `source_ids` — wire/row field name.
pub const SOURCE_IDS: &str = "source_ids";
/// `source_memory_id` — wire/row field name.
pub const SOURCE_MEMORY_ID: &str = "source_memory_id";
/// `source_span` — wire/row field name.
pub const SOURCE_SPAN: &str = "source_span";
/// `source_uri` — wire/row field name.
pub const SOURCE_URI: &str = "source_uri";
/// `standard_id` — wire/row field name.
pub const STANDARD_ID: &str = "standard_id";
/// `storage_backend` — wire/row field name.
pub const STORAGE_BACKEND: &str = "storage_backend";
/// `subscription_id` — wire/row field name.
pub const SUBSCRIPTION_ID: &str = "subscription_id";
/// `subscriptions` — wire/row field name.
pub const SUBSCRIPTIONS: &str = "subscriptions";
/// `suggested_merge` — wire/row field name.
pub const SUGGESTED_MERGE: &str = "suggested_merge";
/// `superseded_id` — wire/row field name.
pub const SUPERSEDED_ID: &str = "superseded_id";
/// `synthesized` — wire/row field name.
pub const SYNTHESIZED: &str = "synthesized";
/// `target_agent_id` — wire/row field name.
pub const TARGET_AGENT_ID: &str = "target_agent_id";
/// `target_folder` — wire/row field name.
pub const TARGET_FOLDER: &str = "target_folder";
/// `target_namespace` — wire/row field name.
pub const TARGET_NAMESPACE: &str = "target_namespace";
/// `tier-locked` — wire/row field name.
pub const TIER_LOCKED: &str = "tier-locked";
/// `tokens_used` — wire/row field name.
pub const TOKENS_USED: &str = "tokens_used";
/// `total_count` — wire/row field name.
pub const TOTAL_COUNT: &str = "total_count";
/// `total_lines` — wire/row field name.
pub const TOTAL_LINES: &str = "total_lines";
/// `total_memories` — wire/row field name.
pub const TOTAL_MEMORIES: &str = "total_memories";
/// `to_namespace` — wire/row field name.
pub const TO_NAMESPACE: &str = "to_namespace";
/// `transcripts` — wire/row field name.
pub const TRANSCRIPTS: &str = "transcripts";
/// `unread_only` — wire/row field name.
pub const UNREAD_ONLY: &str = "unread_only";
/// `updated_at` — wire/row field name.
pub const UPDATED_AT: &str = "updated_at";
/// `updated_since` — wire/row field name.
pub const UPDATED_SINCE: &str = "updated_since";
/// `valid_from` — wire/row field name.
pub const VALID_FROM: &str = "valid_from";
/// `valid_until` — wire/row field name.
pub const VALID_UNTIL: &str = "valid_until";
