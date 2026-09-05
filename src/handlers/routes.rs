// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! HTTP route-path SSOT (#1558 batch 4).
//!
//! One named const per production route path. The axum router in
//! `src/lib.rs` REGISTERS these paths and the postgres surface gate
//! (`handlers/postgres_gate.rs`), federation receiver, CLI doctor,
//! and daemon runtime MATCH on them — a drifted copy between the
//! registration site and a match site silently changes routing or
//! gating behavior, so the path strings live here exactly once.
//! Param segments use the axum `{param}` capture syntax.

pub const ACTIONS_ID_TRANSITION: &str = "/api/v1/actions/{id}/transition";
pub const SIGNALS: &str = "/api/v1/signals";
pub const AGENTS: &str = "/api/v1/agents";
/// #1539 — admin-gated attestation pubkey bind for a registered agent.
pub const AGENTS_ID_PUBKEY: &str = "/api/v1/agents/{id}/pubkey";
/// v1.0.0 #3464 — issue a single-use bind challenge for a candidate key. The
/// candidate key must sign the challenge transcript and present the signature
/// on [`AGENTS_ID_PUBKEY`]; without it the bind is refused, so an admin can no
/// longer bind a key they merely assert.
pub const AGENTS_ID_PUBKEY_CHALLENGE: &str = "/api/v1/agents/{id}/pubkey/challenge";
pub const APPROVALS_STREAM: &str = "/api/v1/approvals/stream";
pub const APPROVALS_PENDING_ID: &str = "/api/v1/approvals/{pending_id}";
pub const ARCHIVE: &str = "/api/v1/archive";
pub const ARCHIVE_STATS: &str = "/api/v1/archive/stats";
pub const ARCHIVE_ID_RESTORE: &str = "/api/v1/archive/{id}/restore";
pub const AUTO_TAG: &str = "/api/v1/auto_tag";
pub const CAPABILITIES: &str = "/api/v1/capabilities";
pub const CAPTURE_TURN: &str = "/api/v1/capture_turn";
pub const CHECK_DUPLICATE: &str = "/api/v1/check_duplicate";
/// #2391 — commit-checkpoint resolution write surface. The SEND leg of the
/// FED-RQ-01 (#1936) checkpoint-federation transport: local resolve +
/// W-of-N fanout via `federation::broadcast_checkpoint_resolution_quorum`.
pub const CHECKPOINTS_ID_RESOLVE: &str = "/api/v1/checkpoints/{id}/resolve";
pub const CONSOLIDATE: &str = "/api/v1/consolidate";
pub const CONTRADICTIONS: &str = "/api/v1/contradictions";
pub const ENTITIES: &str = "/api/v1/entities";
pub const ENTITIES_BY_ALIAS: &str = "/api/v1/entities/by_alias";
pub const EXPAND_QUERY: &str = "/api/v1/expand_query";
pub const EXPORT: &str = "/api/v1/export";
pub const FIND_PATHS: &str = "/api/v1/find_paths";
pub const FORGET: &str = "/api/v1/forget";
pub const GC: &str = "/api/v1/gc";
pub const HEALTH: &str = "/api/v1/health";
pub const IMPORT: &str = "/api/v1/import";
pub const INBOX: &str = "/api/v1/inbox";
/// v1.0.0 #3465 — SSE wake stream for the caller's OWN inbox. Fed
/// from the in-process `inbox_wake` broadcast bus, never the webhook
/// lane; identity-bound at stream open.
pub const INBOX_STREAM: &str = "/api/v1/inbox/stream";
pub const KG_FIND_PATHS: &str = "/api/v1/kg/find_paths";
pub const KG_INVALIDATE: &str = "/api/v1/kg/invalidate";
pub const KG_QUERY: &str = "/api/v1/kg/query";
pub const KG_TIMELINE: &str = "/api/v1/kg/timeline";
pub const LINKS: &str = "/api/v1/links";
pub const LINKS_VERIFY: &str = "/api/v1/links/verify";
pub const LINKS_ID: &str = "/api/v1/links/{id}";
pub const MEMORIES: &str = "/api/v1/memories";
pub const MEMORIES_BULK: &str = "/api/v1/memories/bulk";
pub const MEMORIES_ID: &str = "/api/v1/memories/{id}";
/// v0.9.0 G13-mem (#1859) — derivation lineage-DAG walk
/// (ancestors/descendants over the provenance link subset).
pub const MEMORIES_ID_LINEAGE: &str = "/api/v1/memories/{id}/lineage";
pub const MEMORIES_ID_PROMOTE: &str = "/api/v1/memories/{id}/promote";
pub const MEMORY_ATOMISE: &str = "/api/v1/memory_atomise";
pub const MEMORY_CALIBRATE_CONFIDENCE: &str = "/api/v1/memory_calibrate_confidence";
pub const MEMORY_CHECK_AGENT_ACTION: &str = "/api/v1/memory_check_agent_action";
pub const MEMORY_DEPENDENTS_OF_INVALIDATED: &str = "/api/v1/memory_dependents_of_invalidated";
pub const MEMORY_EXPORT_REFLECTION: &str = "/api/v1/memory_export_reflection";
pub const MEMORY_LOAD_FAMILY: &str = "/api/v1/memory_load_family";
pub const MEMORY_RECALL_OBSERVATIONS: &str = "/api/v1/memory_recall_observations";
pub const MEMORY_REFLECT: &str = "/api/v1/memory_reflect";
pub const MEMORY_REFLECTION_ORIGIN: &str = "/api/v1/memory_reflection_origin";
pub const MEMORY_REPLAY: &str = "/api/v1/memory_replay";
pub const MEMORY_RULE_LIST: &str = "/api/v1/memory_rule_list";
pub const MEMORY_SMART_LOAD: &str = "/api/v1/memory_smart_load";
pub const MEMORY_SUBSCRIPTION_DLQ_LIST: &str = "/api/v1/memory_subscription_dlq_list";
pub const MEMORY_SUBSCRIPTION_REPLAY: &str = "/api/v1/memory_subscription_replay";
pub const MEMORY_VERIFY: &str = "/api/v1/memory_verify";
pub const METRICS: &str = "/api/v1/metrics";
pub const NAMESPACES: &str = "/api/v1/namespaces";
pub const NAMESPACES_NS_STANDARD: &str = "/api/v1/namespaces/{ns}/standard";
pub const NOTIFY: &str = "/api/v1/notify";
pub const PENDING: &str = "/api/v1/pending";
pub const PENDING_ID_APPROVE: &str = "/api/v1/pending/{id}/approve";
pub const PENDING_ID_REJECT: &str = "/api/v1/pending/{id}/reject";
pub const QUOTA_STATUS: &str = "/api/v1/quota/status";
pub const RECALL: &str = "/api/v1/recall";
pub const SEARCH: &str = "/api/v1/search";
pub const SESSION_START: &str = "/api/v1/session/start";
pub const SHARE: &str = "/api/v1/share";
pub const SKILL_LIST: &str = "/api/v1/skill/list";
pub const SKILL_REGISTER: &str = "/api/v1/skill/register";
pub const SKILL_ID: &str = "/api/v1/skill/{id}";
pub const SKILL_ID_COMPOSE: &str = "/api/v1/skill/{id}/compose";
pub const SKILL_ID_EXPORT: &str = "/api/v1/skill/{id}/export";
pub const SKILL_ID_PROMOTE: &str = "/api/v1/skill/{id}/promote";
pub const SKILL_ID_RESOURCE: &str = "/api/v1/skill/{id}/resource";
/// #2024 — operator-authorized skill retire/unretire (admin-gated).
pub const SKILL_ID_RETIRE: &str = "/api/v1/skill/{id}/retire";
/// v1.0.0 #2402 — admin-gated operator quarantine INSPECT surface. The
/// #1948 route-OUT contract advertised "operator dequarantine" and shipped no
/// caller; under `asi-hard` (where the quarantine knob is pinned on) a held
/// row was invisible AND unreleasable.
pub const ADMIN_QUARANTINE: &str = "/api/v1/admin/quarantine";
/// v1.0.0 #2402 — admin-gated operator quarantine RELEASE surface. Appends a
/// `memory.dequarantined` signed audit row in the same transaction as the
/// state change, on both backends.
pub const ADMIN_QUARANTINE_ID_RELEASE: &str = "/api/v1/admin/quarantine/{id}/release";
pub const STATS: &str = "/api/v1/stats";
pub const SUBSCRIPTIONS: &str = "/api/v1/subscriptions";
pub const SYNC_PUSH: &str = "/api/v1/sync/push";
pub const SYNC_SINCE: &str = "/api/v1/sync/since";
pub const TAXONOMY: &str = "/api/v1/taxonomy";
pub const TOOLS_LIST: &str = "/api/v1/tools/list";
pub const METRICS_BARE: &str = "/metrics";
