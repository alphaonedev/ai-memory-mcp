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
/// `pubkey_bound_at` — RFC3339 stamp written next to [`AGENT_PUBKEY`] on
/// every bind/rotate so key provenance is auditable. The two keys are a
/// PAIR: they are written together by `bind_agent_pubkey`, stripped
/// together by `revoke_agent_pubkey`, and preserved together across an
/// upsert (see `crate::RESERVED_UPSERT_METADATA_KEYS`) — a row carrying a
/// pubkey with no bind stamp, or the reverse, is a torn state.
pub const PUBKEY_BOUND_AT: &str = "pubkey_bound_at";
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
/// Parity finding #1 (2026-08) — the DEFAULT `archive_reason` VALUE
/// stamped when an archive is requested with no explicit reason.
///
/// Shared SSOT so the sqlite funnel (`storage::archive_memory_no_tx`)
/// and the postgres funnel (`PostgresStore::archive_by_ids`) cannot
/// drift: they previously defaulted to `"archive"` and `"manual"`
/// respectively, so the SAME reason-less operation produced two
/// different audit-trail values depending on the backend, and any
/// reason-filtered query / `archive_stats` report disagreed across
/// backends. `"archive"` is the value the sqlite unit test
/// `archive_memory_default_reason_is_archive` has pinned since v0.6.
pub const ARCHIVE_REASON_DEFAULT: &str = "archive";
/// v1.0.0 #3012 — the `archive_reason` VALUE stamped when the targeted CLI
/// `delete <id>` archives-then-deletes (its recoverable default). Distinct
/// from the bulk `forget` reason so an operator can tell WHICH destructive
/// verb produced an archived row. Shared SSOT so the storage layer, the CLI
/// and the regression tests agree on the marker.
pub const ARCHIVE_REASON_DELETE: &str = "delete";
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
/// `resolved_at` — wire/row field name for a checkpoint's resolution timestamp
/// (#2391 checkpoint-resolve HTTP surface; also the `checkpoints` row column).
pub const RESOLVED_AT: &str = "resolved_at";
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
/// `compressed_size` — I4 transcript metadata / MCP-HTTP replay envelope.
pub const COMPRESSED_SIZE: &str = "compressed_size";
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
/// `dependents` — MCP/HTTP `memory_dependents_of_invalidated` list key.
pub const DEPENDENTS: &str = "dependents";
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
/// `existing_id` — wire field: the stored id a conflict/dedup collided with
/// (single-create 409 + bulk `errors[]` CONFLICT rows, #2725).
pub const EXISTING_ID: &str = "existing_id";
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
/// `export_scope` — additive `ai-memory export` marker (#1944): names the
/// record scope the JSON convenience export actually carries.
pub const EXPORT_SCOPE: &str = "export_scope";
/// `portability_complete` — additive `ai-memory export` marker (#1944):
/// `false` because the JSON export omits the tamper-evidence spine.
pub const PORTABILITY_COMPLETE: &str = "portability_complete";
/// `excludes` — additive `ai-memory export` marker (#1944): the signed
/// record classes the JSON convenience export omits.
pub const EXCLUDES: &str = "excludes";
/// `withheld` — additive `ai-memory export` marker (#2490): the
/// machine-readable accounting of rows present in the corpus that the
/// artifact does NOT carry (forbidden-class drops + quarantined), plus the
/// count of rows whose bytes the secret screen ALTERED. Counts and a class
/// histogram only — the ids ride the operator stderr channel, never the
/// portable artifact.
pub const WITHHELD: &str = "withheld";
/// `withheld_by_class` — the class histogram nested under [`WITHHELD`].
pub const WITHHELD_BY_CLASS: &str = "withheld_by_class";
/// `withheld_ids` — operator-channel-only list of withheld ids (#2490).
/// NEVER written into the portable export artifact.
pub const WITHHELD_IDS: &str = "withheld_ids";
/// `redacted` — count of exported rows whose stored bytes the secret screen
/// ALTERED (#2490).
pub const REDACTED: &str = "redacted";
/// `redacted_ids` — operator-channel-only sibling of [`REDACTED`] (#2490).
pub const REDACTED_IDS: &str = "redacted_ids";
/// `quarantined` — count of live rows the SQL lifecycle allow-list excluded
/// from the export because they are quarantined (#2490 / #1948).
pub const QUARANTINED: &str = "quarantined";
/// `tombstoned` — count of live rows excluded as tombstoned (#2490).
pub const TOMBSTONED: &str = "tombstoned";
/// `expired` — count of live rows excluded because their TTL has passed
/// (#2490).
pub const EXPIRED: &str = "expired";
/// `dangling_links_withheld` — v1.0.0 #3405: count of graph edges the
/// exporter DROPPED because at least one endpoint memory is not carried by
/// this artifact (an endpoint withheld by the confidentiality boundary, or
/// excluded as tombstoned / quarantined / expired). A COUNT only — safe
/// in-band; the rendered edges ride the operator stderr channel under
/// [`DANGLING_LINK_EDGES`].
pub const DANGLING_LINKS_WITHHELD: &str = "dangling_links_withheld";
/// `dangling_link_edges` — operator-channel-only sibling of
/// [`DANGLING_LINKS_WITHHELD`] (#3405). NEVER written into the portable
/// export artifact: an endpoint named here is by construction an id the
/// export withheld, so publishing it would leak the #2490 objection-O3
/// index into the source corpus.
pub const DANGLING_LINK_EDGES: &str = "dangling_link_edges";
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
/// `include_retired` — #2024 skill-retire discovery flag wire field name.
pub const INCLUDE_RETIRED: &str = "include_retired";
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
/// `namespace_count` — wire field on `GET /api/v1/stats` `others` (#3343).
/// Count of namespaces folded out of `by_namespace` (not a list —
/// [`NAMESPACES`] is the list key on `/namespaces`).
pub const NAMESPACE_COUNT: &str = "namespace_count";
/// `namespace_filter` — wire/row field name.
pub const NAMESPACE_FILTER: &str = "namespace_filter";
/// `next_since` — wire/row field name.
///
/// #2441 — the `/sync/since` PULL CURSOR. Distinct from
/// [`LATEST_UPDATED_AT`], which describes only the rows actually
/// PROJECTED into `memories[]` (post namespace-allowlist +
/// post-visibility). `next_since` is derived from the rows the server
/// EXAMINED, so a page whose every row was filtered out still advances
/// the puller's cursor instead of stalling it forever on the identical
/// window. `null` means "do not move your cursor" (nothing was
/// examined, or advancing could not be proven safe).
pub const NEXT_SINCE: &str = "next_since";
/// `observations` — wire/row field name.
pub const OBSERVATIONS: &str = "observations";
/// `observed_by` — wire/row field name.
pub const OBSERVED_BY: &str = "observed_by";
/// `older_than_days` — wire/row field name.
pub const OLDER_THAN_DAYS: &str = "older_than_days";
/// `original_depth` — wire/row field name.
pub const ORIGINAL_DEPTH: &str = "original_depth";
/// `original_size` — I4 transcript metadata / MCP-HTTP replay envelope.
pub const ORIGINAL_SIZE: &str = "original_size";
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
/// `retire_reason` — #2024 skill-retire lifecycle wire/row field name.
pub const RETIRE_REASON: &str = "retire_reason";
/// `retired` — #2024 skill-retire lifecycle response flag (bool; the
/// symmetric sibling of the skill_get `current` field).
pub const RETIRED: &str = "retired";
/// `retired_at` — #2024 skill-retire lifecycle wire/row field name
/// (epoch secs; NULL/absent = active).
pub const RETIRED_AT: &str = "retired_at";
/// `retired_by` — #2024 skill-retire lifecycle wire/row field name.
pub const RETIRED_BY: &str = "retired_by";
/// `schema_version` — wire/row field name.
pub const SCHEMA_VERSION: &str = "schema_version";
/// `scope_status` — wire/row field name.
pub const SCOPE_STATUS: &str = "scope_status";
/// `sender_agent_id` — wire/row field name.
pub const SENDER_AGENT_ID: &str = "sender_agent_id";
/// `sender_policy_digest_hex` — FED-RQ-03 (#1947) federation `/sync/push`
/// wire field: the lowercase-hex whole-ruleset governance policy digest the
/// sender was governed by at push time (paired with `sender_policy_seq`).
pub const SENDER_POLICY_DIGEST_HEX: &str = "sender_policy_digest_hex";
/// `sender_policy_seq` — FED-RQ-03 (#1947) federation `/sync/push` wire
/// field: the sender's committed governance `policy_version` sequence at push
/// time. ADDITIVE + backward-compatible (absent on pre-#1947 peers).
pub const SENDER_POLICY_SEQ: &str = "sender_policy_seq";
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
/// `span_end` — I4 transcript link offset (half-open).
pub const SPAN_END: &str = "span_end";
/// `span_start` — I4 transcript link offset (half-open).
pub const SPAN_START: &str = "span_start";
/// `standard_id` — wire/row field name.
pub const STANDARD_ID: &str = "standard_id";
/// `standards_withheld` — wire field name (#2537). Count-only disclosure of
/// namespace standards that resolved for the recalled namespace chain but
/// were NOT injected because the caller fails
/// [`crate::visibility::is_visible_to_caller`]. Deliberately a bare integer:
/// emitting the withheld standard's id / owner / namespace would turn the
/// honesty marker into a cross-tenant existence oracle. Mirrors the
/// count-only shape of the `confidence_filtered_out` recall-meta disclosure.
pub const STANDARDS_WITHHELD: &str = "standards_withheld";
/// `storage_backend` — wire/row field name.
pub const STORAGE_BACKEND: &str = "storage_backend";
/// `subscription_id` — wire/row field name.
pub const SUBSCRIPTION_ID: &str = "subscription_id";
/// `subscriptions` — wire/row field name.
pub const SUBSCRIPTIONS: &str = "subscriptions";
/// `suggested_merge` — wire/row field name.
pub const SUGGESTED_MERGE: &str = "suggested_merge";
/// `superseded_by` — wire field: the id whose content was superseded, in the
/// bulk `deduped_rows[]`/`updated_rows[]` disclosure arrays (#2551, #2725) and
/// the skill supersession response.
pub const SUPERSEDED_BY: &str = "superseded_by";
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
/// `transcript_id` — I2 link / I4 replay envelope.
pub const TRANSCRIPT_ID: &str = "transcript_id";
/// `transcripts` — wire/row field name.
pub const TRANSCRIPTS: &str = "transcripts";
/// `transitive_count` — MCP/HTTP `memory_dependents_of_invalidated`.
pub const TRANSITIVE_COUNT: &str = "transitive_count";
/// `transitive_suspects` — MCP/HTTP `memory_dependents_of_invalidated`.
pub const TRANSITIVE_SUSPECTS: &str = "transitive_suspects";
/// `unread_only` — wire/row field name.
pub const UNREAD_ONLY: &str = "unread_only";
/// `unretired` — #2024 skill-retire lifecycle response flag (bool; the
/// UNRETIRE sibling of [`RETIRED`]).
pub const UNRETIRED: &str = "unretired";
/// `updated_at` — wire/row field name.
pub const UPDATED_AT: &str = "updated_at";
/// `updated_since` — wire/row field name.
pub const UPDATED_SINCE: &str = "updated_since";
/// `valid_from` — wire/row field name.
pub const VALID_FROM: &str = "valid_from";
/// `valid_until` — wire/row field name.
pub const VALID_UNTIL: &str = "valid_until";
