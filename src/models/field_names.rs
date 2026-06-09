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
/// `agent_type` — wire/row field name.
pub const AGENT_TYPE: &str = "agent_type";
/// `archived_at` — wire/row field name.
pub const ARCHIVED_AT: &str = "archived_at";
/// `attest_level` — wire/row field name.
pub const ATTEST_LEVEL: &str = "attest_level";
/// `budget_tokens` — wire/row field name.
pub const BUDGET_TOKENS: &str = "budget_tokens";
/// `canonical_name` — wire/row field name.
pub const CANONICAL_NAME: &str = "canonical_name";
/// `capabilities` — wire/row field name.
pub const CAPABILITIES: &str = "capabilities";
/// `confidence` — wire/row field name.
pub const CONFIDENCE: &str = "confidence";
/// `confidence_signals` — wire/row field name.
pub const CONFIDENCE_SIGNALS: &str = "confidence_signals";
/// `confirmed_contradictions` — wire/row field name.
pub const CONFIRMED_CONTRADICTIONS: &str = "confirmed_contradictions";
/// `consolidated` — wire/row field name.
pub const CONSOLIDATED: &str = "consolidated";
/// `created_at` — wire/row field name.
pub const CREATED_AT: &str = "created_at";
/// `created_by` — wire/row field name.
pub const CREATED_BY: &str = "created_by";
/// `decided_by` — wire/row field name.
pub const DECIDED_BY: &str = "decided_by";
/// `description` — wire/row field name.
pub const DESCRIPTION: &str = "description";
/// `expires_at` — wire/row field name.
pub const EXPIRES_AT: &str = "expires_at";
/// `governance` — wire/row field name.
pub const GOVERNANCE: &str = "governance";
/// `last_accessed_at` — wire/row field name.
pub const LAST_ACCESSED_AT: &str = "last_accessed_at";
/// `memory_kind` — wire/row field name.
pub const MEMORY_KIND: &str = "memory_kind";
/// `namespace_filter` — wire/row field name.
pub const NAMESPACE_FILTER: &str = "namespace_filter";
/// `observed_by` — wire/row field name.
pub const OBSERVED_BY: &str = "observed_by";
/// `older_than_days` — wire/row field name.
pub const OLDER_THAN_DAYS: &str = "older_than_days";
/// `owner_scope` — wire/row field name.
pub const OWNER_SCOPE: &str = "owner_scope";
/// `parent_namespace` — wire/row field name.
pub const PARENT_NAMESPACE: &str = "parent_namespace";
/// `peer_origin` — wire/row field name.
pub const PEER_ORIGIN: &str = "peer_origin";
/// `pending_id` — wire/row field name.
pub const PENDING_ID: &str = "pending_id";
/// `persona_version` — wire/row field name.
pub const PERSONA_VERSION: &str = "persona_version";
/// `properties` — wire/row field name (JSON-Schema object key).
pub const PROPERTIES: &str = "properties";
/// `reflection_depth` — wire/row field name.
pub const REFLECTION_DEPTH: &str = "reflection_depth";
/// `registered` — wire/row field name.
pub const REGISTERED: &str = "registered";
/// `registered_at` — wire/row field name.
pub const REGISTERED_AT: &str = "registered_at";
/// `requested_by` — wire/row field name.
pub const REQUESTED_BY: &str = "requested_by";
/// `schema_version` — wire/row field name.
pub const SCHEMA_VERSION: &str = "schema_version";
/// `sender_agent_id` — wire/row field name.
pub const SENDER_AGENT_ID: &str = "sender_agent_id";
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
/// `target_agent_id` — wire/row field name.
pub const TARGET_AGENT_ID: &str = "target_agent_id";
/// `target_folder` — wire/row field name.
pub const TARGET_FOLDER: &str = "target_folder";
/// `target_namespace` — wire/row field name.
pub const TARGET_NAMESPACE: &str = "target_namespace";
/// `tokens_used` — wire/row field name.
pub const TOKENS_USED: &str = "tokens_used";
/// `total_lines` — wire/row field name.
pub const TOTAL_LINES: &str = "total_lines";
/// `total_memories` — wire/row field name.
pub const TOTAL_MEMORIES: &str = "total_memories";
/// `transcripts` — wire/row field name.
pub const TRANSCRIPTS: &str = "transcripts";
/// `updated_at` — wire/row field name.
pub const UPDATED_AT: &str = "updated_at";
/// `valid_from` — wire/row field name.
pub const VALID_FROM: &str = "valid_from";
/// `valid_until` — wire/row field name.
pub const VALID_UNTIL: &str = "valid_until";
