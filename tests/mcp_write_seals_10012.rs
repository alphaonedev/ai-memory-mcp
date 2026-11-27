// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10012 / #10010 — every stdio MCP write tool seals its writes with the
//! session signer (GA standard 3, "signed writes").
//!
//! PR #9953 sealed four tools (`memory_store`, `memory_reflect`,
//! `memory_consolidate`, `memory_entity_register`). Every other stdio tool
//! that inserts or changes a `memories` row (update, promote, notify, share,
//! namespace standards, restore, skill promotion, ...) stored it `claimed`
//! with no signature, and the tools with their own signature column signed
//! with the on-disk active key instead of the session key.
//!
//! Invariant pinned here, one `ai-memory mcp` process per posture: with a
//! session key installed, after EVERY registered tool call
//! - every `memories` row the call inserted or changed and the session agent
//!   owns is `agent_attested` with a `write_signature` that verifies against
//!   the key BOUND to the session agent;
//! - no row the call inserted or changed is sealed for another agent; under
//!   `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1` no such row is stored at all;
//! - every row the call inserted or changed in a table with a signature
//!   column carries a signature that VERIFIES against the key bound to the
//!   session agent over that table's signed fields (a non-empty check is not
//!   a proof);
//! - a `ReadOnly` tool changes no row in any table outside `EXEMPT_TABLES`
//!   (for `memories`, the signed columns), except a `READONLY_ALLOWANCES`
//!   row naming the tool, the table and the reason;
//! - every other table the call changed is a table the tool's classification
//!   row names (the row-attested tables, which have no signature column);
//! - after every call the `row_attestations` verifier (#10040) reports no
//!   defect: every row key of `memories` and of every row-attested table has
//!   a latest attestation that verifies against the bound key and the live
//!   row, and the signed per-table watermark covers the whole table.
//!
//! The ratchet (`every_registered_tool_is_classified_and_driven_10012`)
//! fails on any registered tool that has no classification row or no drive
//! step, so a new tool fails by default.
//!
//! Stdio MCP opens SQLite only (`run_mcp_server` calls `db::open`, and the
//! seal funnel is armed in `db::open`), so there is no postgres cell for
//! this transport.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use base64::Engine as _;
use serde_json::{Value, json};

#[path = "common/child_stdin_report.rs"]
mod child_stdin_report;
#[path = "common/mcp_wait.rs"]
mod mcp_wait;

const AGENT: &str = "ai:sealer-10012";
const OTHER_AGENT: &str = "ai:other-10012";
const EXTRA_AGENT: &str = "ai:extra-10012";
const ENV_KEY_FILE: &str = "AI_MEMORY_MCP_SIGNING_KEY_FILE";
const ENV_REQUIRE: &str = "AI_MEMORY_REQUIRE_AGENT_ATTESTATION";
const NAMESPACE: &str = "seal-10012";
const FORGET_NAMESPACE: &str = "seal-forget-10012";
const WAIT_LABEL: &str = "mcp_write_seals_10012";
const ATTESTED: &str = "agent_attested";
const SCRATCH: &str = ".local-runs/mcp_write_seals_10012";
const POSTURES: [&str; 2] = ["0", "1"];

/// Tables the attestation and bookkeeping machinery writes on every path;
/// they are never a tool's stored state (reason per entry).
const EXEMPT_TABLES: [(&str, &str); 15] = [
    (
        "row_attestations",
        "the signed row-attestation ledger of the write (#10040); verified after every step",
    ),
    (
        "audit_log",
        "hash-chained audit trail of the write, not the write",
    ),
    ("attested_write_ledger", "replay ledger of the seal itself"),
    ("signed_events", "the signed event stream of the write"),
    ("token_cost_counters", "usage counters, no stored memory"),
    ("embed_skip", "embedder skip cache, regenerable"),
    ("memories_fts", "FTS index, regenerable from memories"),
    ("memories_fts_data", "FTS shadow table, regenerable"),
    ("memories_fts_idx", "FTS shadow table, regenerable"),
    ("memories_fts_docsize", "FTS shadow table, regenerable"),
    ("agent_quotas", "per-agent quota counter, no stored memory"),
    (
        "archived_memories",
        "verbatim archive copy of a prior memories row; its metadata keeps that row's write_signature",
    ),
    (
        "forget_tombstones",
        "removal receipt signed by the daemon audit key (#1832); records that a row is gone",
    ),
    (
        "memory_revisions",
        "identity-only revision leaf signed by the daemon audit key (#1823), not a session row",
    ),
    (
        "skill_resources",
        "covered by the parent skills row signature, which commits to every resource digest",
    ),
];

/// Tables with a signature carrier: `(table, signature column)`.
const SIGNED_TABLES: [(&str, &str); 6] = [
    ("memory_links", "signature"),
    ("signals", "signature"),
    ("checkpoints", "signature"),
    ("routines", "signature"),
    ("skills", "signature"),
    ("offloaded_blobs", "signature_b64"),
];

/// Side tables with no signature column, attested row by row in
/// `row_attestations` (#10040, 3-agent vote (71472661) V1-10040).
const ROW_ATTESTED_TABLES: [&str; 13] = [
    "actions",
    "action_edges",
    "leases",
    "subscriptions",
    "subscription_events",
    "subscription_dlq",
    "pending_actions",
    "namespace_meta",
    "routine_runs",
    "recall_observations",
    "memory_transcripts",
    "memory_transcript_links",
    "entity_aliases",
];

/// How a tool's stored writes are attested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// Writes no stored state of its own (any `memories` row it touched is
    /// still swept and must verify).
    ReadOnly,
    /// Writes `memories` rows (sealed by the funnel) and/or signature-column
    /// rows (signed with the session key).
    Sealed,
    /// Also writes a side table with no signature column; every changed row
    /// key there carries a verifying `row_attestations` entry (#10040).
    Attested,
}

/// One classification row per registered tool: `(tool, class, side tables
/// the tool may change without a signature carrier, reason)`.
const TOOL_CLASS: [(&str, Class, &[&str], &str); 104] = [
    ("memory_store", Class::Sealed, &[], "inserts memories rows"),
    (
        "memory_recall",
        Class::Attested,
        &["recall_observations"],
        "logs a recall observation row",
    ),
    (
        "memory_recall_observations",
        Class::ReadOnly,
        &[],
        "lists recall observations",
    ),
    ("memory_search", Class::ReadOnly, &[], "keyword search"),
    ("memory_list", Class::ReadOnly, &[], "lists rows"),
    (
        "memory_load_family",
        Class::ReadOnly,
        &[],
        "returns a tool family",
    ),
    (
        "memory_smart_load",
        Class::ReadOnly,
        &[],
        "returns a tool family",
    ),
    (
        "memory_get_taxonomy",
        Class::ReadOnly,
        &[],
        "namespace counts",
    ),
    (
        "memory_check_duplicate",
        Class::ReadOnly,
        &[],
        "similarity probe",
    ),
    (
        "memory_entity_register",
        Class::Attested,
        &["entity_aliases"],
        "entity memory plus alias rows",
    ),
    (
        "memory_entity_get_by_alias",
        Class::ReadOnly,
        &[],
        "alias lookup",
    ),
    ("memory_kg_timeline", Class::ReadOnly, &[], "link timeline"),
    (
        "memory_kg_invalidate",
        Class::Sealed,
        &[],
        "changes a signed link row",
    ),
    ("memory_kg_query", Class::ReadOnly, &[], "graph traversal"),
    ("memory_find_paths", Class::ReadOnly, &[], "graph traversal"),
    ("memory_lineage", Class::ReadOnly, &[], "lineage walk"),
    (
        "memory_delete",
        Class::Sealed,
        &[],
        "removes a row (nothing left to seal)",
    ),
    (
        "memory_promote",
        Class::Sealed,
        &[],
        "changes a memories row",
    ),
    (
        "memory_forget",
        Class::Sealed,
        &[],
        "removes rows (nothing left to seal)",
    ),
    ("memory_stats", Class::ReadOnly, &[], "counts"),
    (
        "memory_update",
        Class::Sealed,
        &[],
        "changes a memories row",
    ),
    ("memory_get", Class::ReadOnly, &[], "reads a row"),
    (
        "memory_link",
        Class::Sealed,
        &[],
        "inserts a signed link row",
    ),
    ("memory_get_links", Class::ReadOnly, &[], "reads links"),
    ("memory_verify", Class::ReadOnly, &[], "verifies signatures"),
    ("memory_replay", Class::ReadOnly, &[], "replays history"),
    (
        "memory_reflect",
        Class::Sealed,
        &[],
        "inserts a reflection row",
    ),
    (
        "memory_export_reflection",
        Class::ReadOnly,
        &[],
        "renders a reflection",
    ),
    ("memory_persona", Class::ReadOnly, &[], "reads a persona"),
    (
        "memory_persona_generate",
        Class::Sealed,
        &[],
        "inserts a persona row",
    ),
    (
        "memory_reflection_origin",
        Class::ReadOnly,
        &[],
        "reads provenance",
    ),
    (
        "memory_dependents_of_invalidated",
        Class::ReadOnly,
        &[],
        "graph walk",
    ),
    (
        "memory_swarm_rewind",
        Class::ReadOnly,
        &[],
        "dry-run rewind",
    ),
    (
        "memory_consolidate",
        Class::Sealed,
        &[],
        "inserts the consolidated row",
    ),
    (
        "memory_ingest_multistep",
        Class::Sealed,
        &[],
        "inserts memories rows",
    ),
    ("memory_atomise", Class::Sealed, &[], "inserts atom rows"),
    ("memory_share", Class::Sealed, &[], "inserts a shared copy"),
    (
        "memory_action_create",
        Class::Attested,
        &["actions"],
        "action row, no signature column",
    ),
    ("memory_action_get", Class::ReadOnly, &[], "reads an action"),
    (
        "memory_action_transition",
        Class::Attested,
        &["actions"],
        "action state, no signature column",
    ),
    ("memory_action_list", Class::ReadOnly, &[], "lists actions"),
    (
        "memory_action_add_edge",
        Class::Attested,
        &["action_edges"],
        "edge row, no signature column",
    ),
    ("memory_action_edges", Class::ReadOnly, &[], "reads edges"),
    (
        "memory_action_frontier",
        Class::ReadOnly,
        &[],
        "reads the frontier",
    ),
    (
        "memory_action_next",
        Class::ReadOnly,
        &[],
        "reads the next action",
    ),
    (
        "memory_lease_acquire",
        Class::Attested,
        &["leases"],
        "lease row, no signature column",
    ),
    (
        "memory_lease_renew",
        Class::Attested,
        &["leases"],
        "lease row, no signature column",
    ),
    (
        "memory_lease_release",
        Class::Attested,
        &["leases"],
        "lease row, no signature column",
    ),
    ("memory_lease_get", Class::ReadOnly, &[], "reads a lease"),
    (
        "memory_signal_send",
        Class::Sealed,
        &[],
        "inserts a signed signal row",
    ),
    ("memory_signal_read", Class::ReadOnly, &[], "reads a signal"),
    ("memory_signal_inbox", Class::ReadOnly, &[], "lists signals"),
    (
        "memory_signal_thread",
        Class::ReadOnly,
        &[],
        "lists a thread",
    ),
    (
        "memory_signal_ack",
        Class::Sealed,
        &[],
        "changes a signed signal row",
    ),
    (
        "memory_checkpoint_create",
        Class::Sealed,
        &[],
        "inserts a signed checkpoint",
    ),
    (
        "memory_checkpoint_resolve",
        Class::Sealed,
        &[],
        "changes a signed checkpoint",
    ),
    (
        "memory_checkpoint_query",
        Class::ReadOnly,
        &[],
        "lists checkpoints",
    ),
    (
        "memory_checkpoint_verify",
        Class::ReadOnly,
        &[],
        "verifies a checkpoint",
    ),
    (
        "memory_routine_create",
        Class::Sealed,
        &[],
        "inserts a signed routine",
    ),
    (
        "memory_routine_freeze",
        Class::Sealed,
        &[],
        "changes a signed routine",
    ),
    (
        "memory_routine_run",
        Class::Attested,
        &["routine_runs"],
        "run row, no signature column",
    ),
    ("memory_routine_status", Class::ReadOnly, &[], "reads a run"),
    (
        "memory_routine_list",
        Class::ReadOnly,
        &[],
        "lists routines",
    ),
    (
        "memory_calibrate_confidence",
        Class::ReadOnly,
        &[],
        "computes a report",
    ),
    (
        "memory_capabilities",
        Class::ReadOnly,
        &[],
        "reports capabilities",
    ),
    (
        "memory_capture_turn",
        Class::Attested,
        &["memory_transcripts", "memory_transcript_links"],
        "transcript rows, no signature column",
    ),
    (
        "memory_expand_query",
        Class::ReadOnly,
        &[],
        "query expansion",
    ),
    (
        "memory_auto_tag",
        Class::Sealed,
        &[],
        "changes a memories row",
    ),
    (
        "memory_detect_contradiction",
        Class::Sealed,
        &[],
        "may insert a link row",
    ),
    (
        "memory_archive_list",
        Class::ReadOnly,
        &[],
        "lists the archive",
    ),
    (
        "memory_archive_restore",
        Class::Sealed,
        &[],
        "re-inserts a memories row",
    ),
    (
        "memory_archive_purge",
        Class::Sealed,
        &[],
        "removes archive rows",
    ),
    ("memory_archive_stats", Class::ReadOnly, &[], "counts"),
    (
        "memory_gc",
        Class::Attested,
        &["recall_observations"],
        "removes expired rows, prunes recall observations",
    ),
    (
        "memory_session_start",
        Class::ReadOnly,
        &[],
        "loads context",
    ),
    (
        "memory_namespace_set_standard",
        Class::Attested,
        &["namespace_meta"],
        "standard pointer row, no signature column",
    ),
    (
        "memory_namespace_get_standard",
        Class::ReadOnly,
        &[],
        "reads the standard",
    ),
    (
        "memory_namespace_clear_standard",
        Class::Attested,
        &["namespace_meta"],
        "standard pointer row, no signature column",
    ),
    (
        "memory_pending_list",
        Class::ReadOnly,
        &[],
        "lists pending actions",
    ),
    (
        "memory_pending_approve",
        Class::Attested,
        &["pending_actions"],
        "pending row, no signature column",
    ),
    (
        "memory_pending_reject",
        Class::Attested,
        &["pending_actions"],
        "pending row, no signature column",
    ),
    (
        "memory_agent_register",
        Class::Sealed,
        &[],
        "inserts an agent memories row",
    ),
    ("memory_agent_list", Class::ReadOnly, &[], "lists agents"),
    (
        "memory_notify",
        Class::Sealed,
        &[],
        "inserts an inbox memories row",
    ),
    ("memory_inbox", Class::ReadOnly, &[], "lists the inbox"),
    (
        "memory_subscribe",
        Class::Attested,
        &["subscriptions"],
        "subscription row, no signature column",
    ),
    (
        "memory_unsubscribe",
        Class::Attested,
        &["subscriptions"],
        "subscription row, no signature column",
    ),
    (
        "memory_list_subscriptions",
        Class::ReadOnly,
        &[],
        "lists subscriptions",
    ),
    (
        "memory_subscription_replay",
        Class::Attested,
        &["subscription_events", "subscription_dlq"],
        "replay rows, no signature column",
    ),
    (
        "memory_subscription_dlq_list",
        Class::ReadOnly,
        &[],
        "lists the dlq",
    ),
    ("memory_quota_status", Class::ReadOnly, &[], "reads quotas"),
    (
        "memory_check_agent_action",
        Class::ReadOnly,
        &[],
        "policy probe",
    ),
    ("memory_rule_list", Class::ReadOnly, &[], "lists rules"),
    (
        "memory_skill_register",
        Class::Sealed,
        &[],
        "inserts a signed skill",
    ),
    ("memory_skill_list", Class::ReadOnly, &[], "lists skills"),
    ("memory_skill_get", Class::ReadOnly, &[], "reads a skill"),
    (
        "memory_skill_resource",
        Class::ReadOnly,
        &[],
        "reads a resource",
    ),
    (
        "memory_skill_export",
        Class::ReadOnly,
        &[],
        "writes files outside the store",
    ),
    (
        "memory_skill_promote_from_reflection",
        Class::Sealed,
        &[],
        "inserts a signed skill",
    ),
    (
        "memory_skill_retire",
        Class::Sealed,
        &[],
        "changes a signed skill",
    ),
    ("memory_skill_delete", Class::Sealed, &[], "removes a skill"),
    (
        "memory_skill_compositional_context",
        Class::ReadOnly,
        &[],
        "reads context",
    ),
    (
        "memory_offload",
        Class::Sealed,
        &[],
        "inserts a signed blob",
    ),
    ("memory_deref", Class::ReadOnly, &[], "reads a blob"),
];

/// One drive step: the tool, its arguments (with `$SLOT` placeholders), and
/// the slot to fill from the named key of the result.
struct Step {
    tool: &'static str,
    args: fn() -> Value,
    capture: Option<(&'static str, &'static str)>,
    expect: Expect,
}

/// The exact outcome of one drive step.
#[derive(Clone, Copy, Debug)]
enum Expect {
    /// The call succeeds under both postures.
    Ok,
    /// The call fails under both postures with this exact message prefix
    /// (a tier gate or a missing fixture; it writes nothing).
    Refused(&'static str),
    /// The call writes a memories row owned by another agent: it succeeds
    /// with strict mode off (the row stays unsigned) and is refused with
    /// exactly [`FOREIGN_ROW_STRICT_REFUSAL`] with strict mode on.
    ForeignRow,
}

/// The session signer's strict refusal for a memories row it does not own,
/// before the row tag (`RowRefusal::Foreign`, written out so this test also
/// compiles on the base, where it is red). The full text is
/// `<head> (row <id>); refused`: [`foreign_refusal`].
const FOREIGN_ROW_STRICT_REFUSAL: &str = "ATTESTATION_FAILED: mcp session signer (#10012): under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 a write to a memory row the session agent does not own cannot be sealed";

/// Strict refusal of a write over memory content the session did not seal
/// (`RowRefusal::Unsealed`, head before the row tag).
const UNSEALED_STRICT_REFUSAL: &str = "ATTESTATION_FAILED: mcp session signer (#10012): under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 a write over memory content the session did not seal cannot be sealed";

/// Refusal of a write over a row whose stored seal no longer verifies, both
/// postures (`RowRefusal::Tampered`, head before the row tag).
const TAMPERED_REFUSAL: &str = "ATTESTATION_FAILED: mcp session signer (#10012): stored seal does not verify; refusing to re-sign";

/// The exact strict refusal naming row `id` (`RowRefusal::Foreign.text`).
fn foreign_refusal(id: &str) -> String {
    format!("{FOREIGN_ROW_STRICT_REFUSAL} (row {id}); refused")
}

/// The exact unsealed-content refusal naming row `id`.
fn unsealed_refusal(id: &str) -> String {
    format!("{UNSEALED_STRICT_REFUSAL} (row {id}); refused")
}

/// The exact tampered-seal refusal naming row `id`.
fn tampered_refusal(id: &str) -> String {
    format!("{TAMPERED_REFUSAL} (row {id})")
}

/// Whether `text` is exactly the foreign-row refusal for SOME row id of the
/// row-id alphabet (the sweep does not know which row a tool touched).
fn is_foreign_refusal(text: &str) -> bool {
    text.strip_prefix(FOREIGN_ROW_STRICT_REFUSAL)
        .and_then(|t| t.strip_prefix(" (row "))
        .and_then(|t| t.strip_suffix("); refused"))
        .is_some_and(|id| {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Rows a create step stores unsigned BY DESIGN: the row is signed when it
/// is frozen or resolved, and the sweep checks the signature at that step.
const SIGNED_LATER: [(&str, &str, &str); 2] = [
    (
        "memory_checkpoint_create",
        "checkpoints",
        "signed at resolve (src/checkpoints/mod.rs)",
    ),
    (
        "memory_routine_create",
        "routines",
        "signed at freeze (src/routines/mod.rs)",
    ),
];

const fn step(tool: &'static str, args: fn() -> Value) -> Step {
    Step {
        tool,
        args,
        capture: None,
        expect: Expect::Ok,
    }
}

const fn refused(tool: &'static str, args: fn() -> Value, prefix: &'static str) -> Step {
    Step {
        tool,
        args,
        capture: None,
        expect: Expect::Refused(prefix),
    }
}

const fn foreign(tool: &'static str, args: fn() -> Value) -> Step {
    Step {
        tool,
        args,
        capture: None,
        expect: Expect::ForeignRow,
    }
}

const fn cap(
    tool: &'static str,
    args: fn() -> Value,
    slot: &'static str,
    key: &'static str,
) -> Step {
    Step {
        tool,
        args,
        capture: Some((slot, key)),
        expect: Expect::Ok,
    }
}

fn body(title: &str) -> String {
    format!("Body of {title}: a plain sentence long enough to be stored as prose.")
}

fn store_args(title: &str) -> Value {
    json!({"title": title, "content": body(title), "namespace": NAMESPACE, "kind": "observation"})
}

const INLINE_SKILL: &str = "---\nname: seal-skill-10012\nnamespace: seal-10012\ndescription: A test skill for the seal sweep.\n---\n\n# Seal skill\n\nDo the sealed thing.\n";

/// Every registered tool, driven once or more, in dependency order.
const STEPS: &[Step] = &[
    cap("memory_store", || store_args("seal a 10012"), "A", "id"),
    cap("memory_store", || store_args("seal b 10012"), "B", "id"),
    cap("memory_store", || store_args("seal c 10012"), "C", "id"),
    cap("memory_store", || store_args("seal d 10012"), "D", "id"),
    cap(
        "memory_store",
        || json!({"title": "seal forget 10012", "content": body("forget"), "namespace": FORGET_NAMESPACE}),
        "F",
        "id",
    ),
    step(
        "memory_update",
        || json!({"id": "$A", "content": body("seal a updated 10012")}),
    ),
    step(
        "memory_promote",
        || json!({"id": "$B", "target_tier": "long"}),
    ),
    step(
        "memory_link",
        || json!({"source_id": "$A", "target_id": "$B", "relation": "related_to"}),
    ),
    cap(
        "memory_reflect",
        || json!({"source_ids": ["$A", "$B"], "title": "seal reflection 10012", "content": body("reflection"), "namespace": NAMESPACE}),
        "R",
        "id",
    ),
    cap(
        "memory_consolidate",
        || json!({"ids": ["$C", "$D"], "title": "seal consolidation 10012", "summary": body("consolidation"), "namespace": NAMESPACE}),
        "CON",
        "id",
    ),
    cap(
        "memory_entity_register",
        || json!({"canonical_name": "Seal Entity 10012", "namespace": NAMESPACE, "aliases": ["seal-entity-10012"]}),
        "ENT",
        "entity_id",
    ),
    step(
        "memory_entity_get_by_alias",
        || json!({"alias": "seal-entity-10012", "namespace": NAMESPACE}),
    ),
    step(
        "memory_persona",
        || json!({"entity_id": "$ENT", "namespace": NAMESPACE}),
    ),
    refused(
        "memory_persona_generate",
        || json!({"entity_id": "$ENT", "namespace": NAMESPACE}),
        "memory_persona_generate requires smart tier or higher",
    ),
    refused(
        "memory_auto_tag",
        || json!({"id": "$A"}),
        "auto-tagging requires smart or autonomous tier",
    ),
    refused(
        "memory_detect_contradiction",
        || json!({"id_a": "$A", "id_b": "$B"}),
        "contradiction detection requires smart or autonomous tier",
    ),
    refused(
        "memory_check_duplicate",
        || json!({"title": "seal a 10012", "content": body("seal a 10012"), "namespace": NAMESPACE}),
        "memory_check_duplicate requires the embedder",
    ),
    step("memory_atomise", || json!({"memory_id": "$A"})),
    step(
        "memory_ingest_multistep",
        || json!({"content": body("ingest"), "namespace": NAMESPACE}),
    ),
    step(
        "memory_capture_turn",
        || json!({"host_session_id": "seal-session-10012", "host_turn_index": 1, "role": "user", "content": body("turn"), "namespace": NAMESPACE}),
    ),
    foreign(
        "memory_share",
        || json!({"source_memory_id": "$A", "target_agent_id": OTHER_AGENT}),
    ),
    step(
        "memory_notify",
        || json!({"target_agent_id": OTHER_AGENT, "title": "seal notify 10012", "payload": body("notify")}),
    ),
    step("memory_inbox", || json!({})),
    step(
        "memory_namespace_set_standard",
        || json!({"namespace": NAMESPACE, "id": "$B"}),
    ),
    step(
        "memory_namespace_get_standard",
        || json!({"namespace": NAMESPACE}),
    ),
    step(
        "memory_namespace_clear_standard",
        || json!({"namespace": NAMESPACE}),
    ),
    step("memory_get", || json!({"id": "$A"})),
    step("memory_get_links", || json!({"id": "$A"})),
    step("memory_kg_query", || json!({"source_id": "$A"})),
    step("memory_kg_timeline", || json!({"source_id": "$A"})),
    step(
        "memory_find_paths",
        || json!({"source_id": "$A", "target_id": "$B"}),
    ),
    step("memory_lineage", || json!({"id": "$R"})),
    step(
        "memory_verify",
        || json!({"source_id": "$A", "target_id": "$B", "relation": "related_to"}),
    ),
    step("memory_replay", || json!({"memory_id": "$A"})),
    step("memory_reflection_origin", || json!({"memory_id": "$R"})),
    step("memory_export_reflection", || json!({"memory_id": "$R"})),
    step(
        "memory_kg_invalidate",
        || json!({"source_id": "$A", "target_id": "$B", "relation": "related_to"}),
    ),
    step(
        "memory_dependents_of_invalidated",
        || json!({"memory_id": "$A"}),
    ),
    cap(
        "memory_skill_promote_from_reflection",
        || json!({"reflection_id": "$R", "skill_name": "seal-promoted-10012", "skill_description": "A skill promoted from the seal reflection."}),
        "SKP",
        "skill_id",
    ),
    cap(
        "memory_skill_register",
        || json!({"inline_skill": INLINE_SKILL}),
        "SK",
        "id",
    ),
    step("memory_skill_list", || json!({})),
    step("memory_skill_get", || json!({"skill_id": "$SK"})),
    // An inline skill carries no resource files; the read is refused and
    // writes nothing (the tool is read-only either way).
    refused(
        "memory_skill_resource",
        || json!({"skill_id": "$SK", "resource_path": "SKILL.md"}),
        "resource not found: skill_id=",
    ),
    step(
        "memory_skill_export",
        || json!({"skill_id": "$SK", "target_folder": "export"}),
    ),
    step(
        "memory_skill_compositional_context",
        || json!({"skill_id": "$SK"}),
    ),
    step(
        "memory_skill_retire",
        || json!({"skill_id": "$SK", "reason": "seal sweep"}),
    ),
    step(
        "memory_skill_delete",
        || json!({"skill_id": "$SKP", "force": true}),
    ),
    cap(
        "memory_action_create",
        || json!({"namespace": NAMESPACE, "kind": "task", "title": "seal action 10012"}),
        "ACT",
        "id",
    ),
    cap(
        "memory_action_create",
        || json!({"namespace": NAMESPACE, "kind": "task", "title": "seal action two 10012"}),
        "ACT2",
        "id",
    ),
    step(
        "memory_action_add_edge",
        || json!({"from_action": "$ACT", "to_action": "$ACT2", "edge_type": "blocks"}),
    ),
    step("memory_action_get", || json!({"id": "$ACT"})),
    step("memory_action_list", || json!({"namespace": NAMESPACE})),
    step("memory_action_edges", || json!({"id": "$ACT"})),
    step("memory_action_frontier", || json!({"namespace": NAMESPACE})),
    step("memory_action_next", || json!({"namespace": NAMESPACE})),
    step(
        "memory_lease_acquire",
        || json!({"action_id": "$ACT", "holder": AGENT}),
    ),
    step("memory_lease_get", || json!({"action_id": "$ACT"})),
    step(
        "memory_lease_renew",
        || json!({"action_id": "$ACT", "holder": AGENT}),
    ),
    step(
        "memory_lease_release",
        || json!({"action_id": "$ACT", "holder": AGENT}),
    ),
    step(
        "memory_action_transition",
        || json!({"id": "$ACT", "to": "claimed", "claimed_by": AGENT}),
    ),
    step(
        "memory_action_transition",
        || json!({"id": "$ACT", "to": "in_progress", "claimed_by": AGENT}),
    ),
    cap(
        "memory_signal_send",
        || json!({"namespace": NAMESPACE, "from_agent": AGENT, "to_agent": AGENT, "subject": "seal signal 10012", "correlation_id": "seal-corr-10012"}),
        "SIG",
        "id",
    ),
    step("memory_signal_read", || json!({"id": "$SIG"})),
    step("memory_signal_inbox", || json!({"namespace": NAMESPACE})),
    step(
        "memory_signal_thread",
        || json!({"correlation_id": "seal-corr-10012"}),
    ),
    step("memory_signal_ack", || json!({"id": "$SIG"})),
    cap(
        "memory_checkpoint_create",
        || json!({"namespace": NAMESPACE, "title": "seal checkpoint 10012"}),
        "CK",
        "id",
    ),
    step(
        "memory_checkpoint_query",
        || json!({"namespace": NAMESPACE}),
    ),
    step("memory_checkpoint_verify", || json!({"id": "$CK"})),
    step(
        "memory_checkpoint_resolve",
        || json!({"id": "$CK", "state": "resolved", "resolved_by": AGENT}),
    ),
    cap(
        "memory_routine_create",
        || json!({"namespace": NAMESPACE, "name": "seal-routine-10012", "template": {"steps": []}}),
        "RT",
        "id",
    ),
    step("memory_routine_list", || json!({"namespace": NAMESPACE})),
    step("memory_routine_freeze", || json!({"id": "$RT"})),
    cap(
        "memory_routine_run",
        || json!({"routine_id": "$RT", "arguments": {}}),
        "RUN",
        "id",
    ),
    step("memory_routine_status", || json!({"run_id": "$RUN"})),
    cap(
        "memory_offload",
        || json!({"content": body("offload"), "namespace": NAMESPACE}),
        "REF",
        "ref_id",
    ),
    step("memory_deref", || json!({"ref_id": "$REF"})),
    cap(
        "memory_subscribe",
        || json!({"url": "https://example.invalid/seal-10012", "secret": "seal-hmac-10012"}),
        "SUB",
        "id",
    ),
    step("memory_list_subscriptions", || json!({})),
    step(
        "memory_subscription_replay",
        || json!({"subscription_id": "$SUB", "since": "2026-01-01T00:00:00Z"}),
    ),
    step("memory_subscription_dlq_list", || json!({})),
    step("memory_unsubscribe", || json!({"id": "$SUB"})),
    step("memory_pending_list", || json!({})),
    refused(
        "memory_pending_approve",
        || json!({"id": "seal-no-such-pending-10012"}),
        "pending action not found: seal-no-such-pending-10012",
    ),
    refused(
        "memory_pending_reject",
        || json!({"id": "seal-no-such-pending-10012"}),
        "pending action not found or already decided: seal-no-such-pending-10012",
    ),
    foreign(
        "memory_agent_register",
        || json!({"agent_id": EXTRA_AGENT, "agent_type": "ai:test"}),
    ),
    step("memory_agent_list", || json!({})),
    step("memory_quota_status", || json!({})),
    step(
        "memory_check_agent_action",
        || json!({"kind": "custom", "custom_kind": "seal-10012"}),
    ),
    step("memory_rule_list", || json!({})),
    step("memory_calibrate_confidence", || json!({})),
    step("memory_capabilities", || json!({})),
    refused(
        "memory_expand_query",
        || json!({"query": "seal"}),
        "query expansion requires smart or autonomous tier",
    ),
    step("memory_get_taxonomy", || json!({})),
    step("memory_list", || json!({"namespace": NAMESPACE})),
    step("memory_search", || json!({"query": "seal"})),
    step(
        "memory_recall",
        || json!({"context": "seal", "namespace": NAMESPACE}),
    ),
    step("memory_recall_observations", || json!({})),
    step("memory_smart_load", || json!({"intent": "store a memory"})),
    step("memory_load_family", || json!({"family": "core"})),
    step("memory_session_start", || json!({"namespace": NAMESPACE})),
    step("memory_stats", || json!({})),
    step(
        "memory_swarm_rewind",
        || json!({"to": "$A", "dry_run": true}),
    ),
    step("memory_delete", || json!({"id": "$B"})),
    step(
        "memory_forget",
        || json!({"namespace": FORGET_NAMESPACE, "pattern": "forget"}),
    ),
    step("memory_archive_list", || json!({})),
    step("memory_archive_restore", || json!({"id": "$F"})),
    step("memory_archive_stats", || json!({})),
    step("memory_archive_purge", || json!({})),
    step("memory_gc", || json!({})),
];

struct Sandbox {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join(SCRATCH);
        std::fs::create_dir_all(&scratch).expect("scratch dir under .local-runs");
        let dir = tempfile::Builder::new()
            .prefix("seal-")
            .tempdir_in(&scratch)
            .expect("tempdir under .local-runs");
        let root = dir.path().to_path_buf();
        let keys = root.join("keys");
        std::fs::create_dir_all(&keys).expect("key dir");
        set_mode(&keys, 0o700);
        Self { _dir: dir, root }
    }

    fn db(&self) -> PathBuf {
        self.root.join("store.db")
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "integration child: runs the ai-memory binary built from this repo (child env isolation: #10183)"
    )]
    fn base_command(&self, agent: &str, require: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("home/.config"))
            .env("TMPDIR", &self.root)
            .env("AI_MEMORY_KEY_DIR", self.root.join("keys"))
            .env("AI_MEMORY_DB", self.db())
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_AGENT_ID", agent)
            .env(ENV_REQUIRE, require);
        cmd
    }

    fn cli(&self, agent: &str, args: &[&str]) -> Output {
        self.base_command(agent, "0")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run ai-memory cli")
    }

    fn cli_ok(&self, agent: &str, args: &[&str]) -> String {
        let out = self.cli(agent, args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// `AGENT` generated, registered and bound; its key copied to a 0600
    /// session key file.
    fn bound_key_file(&self) -> PathBuf {
        let out = self.cli(AGENT, &["identity", "generate", "--agent-id", AGENT]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() || err.contains("already exists"),
            "identity generate: {err}"
        );
        let priv_path = self.root.join("keys").join(format!("{AGENT}.priv"));
        self.cli_ok(
            AGENT,
            &[
                "agents",
                "register",
                "--agent-id",
                AGENT,
                "--agent-type",
                "ai:test",
            ],
        );
        self.cli_ok(
            AGENT,
            &[
                "agents",
                "register",
                "--agent-id",
                OTHER_AGENT,
                "--agent-type",
                "ai:test",
            ],
        );
        let pubkey = self.cli_ok(AGENT, &["identity", "export-pub", "--agent-id", AGENT]);
        assert!(!pubkey.is_empty(), "export-pub printed a key");
        self.cli_ok(
            AGENT,
            &[
                "agents",
                "bind-key",
                "--agent-id",
                AGENT,
                "--pubkey",
                &pubkey,
            ],
        );
        let bytes = std::fs::read(&priv_path).expect("read generated key");
        let path = self.root.join("session.key");
        let mut f = std::fs::File::create(&path).expect("create key file");
        f.write_all(&bytes).expect("write key file");
        drop(f);
        set_mode(&path, 0o600);
        path
    }

    fn start(&self, require: &str, key_file: &Path) -> Mcp {
        self.start_with(require, key_file, "keyword", &[])
    }

    /// The stdio MCP server at `tier`, with `extra_env` on top of the
    /// sandbox environment.
    fn start_with(
        &self,
        require: &str,
        key_file: &Path,
        tier: &str,
        extra_env: &[(&str, &str)],
    ) -> Mcp {
        let mut cmd = self.base_command(AGENT, require);
        cmd.args([
            "--db",
            self.db().to_str().expect("utf-8 db path"),
            "mcp",
            "--profile",
            "full",
            "--tier",
            tier,
        ])
        .env(ENV_KEY_FILE, key_file)
        .envs(extra_env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
        Mcp::spawn(cmd)
    }

    /// A raw read-write connection with no seal triggers: the tests use it
    /// to seed rows the session did not seal (strip, tamper, re-attribute).
    fn seed_conn(&self) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(self.db()).expect("open sandbox db");
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .expect("busy timeout");
        conn
    }

    /// A READ-ONLY connection: the sweep never migrates or takes a write lock.
    fn conn(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(self.db(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open sandbox db read-only")
    }
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

struct Mcp {
    child: std::process::Child,
    input: std::process::ChildStdin,
    output: std::sync::mpsc::Receiver<String>,
    next_id: u64,
}

impl Mcp {
    fn spawn(mut cmd: Command) -> Self {
        let mut child = cmd.spawn().expect("spawn ai-memory mcp");
        let input = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let (tx, output) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut mcp = Self {
            child,
            input,
            output,
            next_id: 1,
        };
        let response = mcp.request(
            "initialize",
            &json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "seal-10012", "version": "1"}
            }),
        );
        assert!(response.get("error").is_none(), "initialize: {response}");
        mcp
    }

    fn request(&mut self, method: &str, params: &Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        child_stdin_report::write_line_or_report(
            &mut self.input,
            &mut self.child,
            None,
            "MCP request",
            &req.to_string(),
        );
        loop {
            let line = mcp_wait::recv_mcp_response(&self.output, WAIT_LABEL);
            let response: Value = serde_json::from_str(&line).expect("JSON RPC");
            if response.get("id") == req.get("id") {
                return response;
            }
        }
    }

    /// `(is_error, text)` of one tool call; an RPC-level error is reported
    /// as `is_error` with the error object as text.
    fn call_raw(&mut self, tool: &str, arguments: &Value) -> (bool, String) {
        let response = self.request("tools/call", &json!({"name": tool, "arguments": arguments}));
        if let Some(err) = response.get("error") {
            return (true, err.to_string());
        }
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        (response["result"]["isError"] == true, text)
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Replace `$SLOT` strings (whole value, or a `$DIR/...` prefix).
fn fill(value: &Value, slots: &BTreeMap<String, String>) -> Value {
    match value {
        Value::String(s) if s.starts_with('$') => {
            let (head, tail) = s[1..]
                .split_once('/')
                .map_or((&s[1..], ""), |(h, t)| (h, t));
            slots.get(head).map_or_else(
                || value.clone(),
                |v| {
                    if tail.is_empty() {
                        Value::String(v.clone())
                    } else {
                        Value::String(format!("{v}/{tail}"))
                    }
                },
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(|v| fill(v, slots)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), fill(v, slots)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

/// Every user table's rows as `(table -> {row text})`; `memories` keeps
/// only the signed columns so an access-count bump is not a change.
type Snapshot = BTreeMap<String, BTreeMap<String, String>>;

fn table_names(conn: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .expect("list tables");
    stmt.query_map([], |r| r.get::<_, String>(0))
        .expect("query tables")
        .map(|r| r.expect("table name"))
        .collect()
}

fn cell_text(v: rusqlite::types::ValueRef<'_>) -> String {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Null => "NULL".to_string(),
        ValueRef::Integer(i) => i.to_string(),
        ValueRef::Real(f) => f.to_string(),
        ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
        ValueRef::Blob(b) => base64::engine::general_purpose::STANDARD.encode(b),
    }
}

fn snapshot(sb: &Sandbox) -> Snapshot {
    let conn = sb.conn();
    let mut snap = Snapshot::new();
    for table in table_names(&conn) {
        let sql = if table == "memories" {
            "SELECT id, namespace, title, content, memory_kind, created_at, metadata FROM memories"
                .to_string()
        } else {
            format!("SELECT rowid, * FROM \"{table}\"")
        };
        let Ok(mut stmt) = conn.prepare(&sql) else {
            continue; // virtual tables without rowid
        };
        let cols = stmt.column_count();
        let mut rows = BTreeMap::new();
        let mut q = stmt.query([]).expect("query rows");
        while let Some(row) = q.next().expect("next row") {
            let key = cell_text(row.get_ref(0).expect("key"));
            let text: Vec<String> = (0..cols)
                .map(|i| {
                    format!(
                        "{}={}",
                        row.as_ref().column_name(i).unwrap_or("?"),
                        cell_text(row.get_ref(i).expect("cell"))
                    )
                })
                .collect();
            rows.insert(key, text.join("\u{1f}"));
        }
        snap.insert(table, rows);
    }
    snap
}

/// Keys of rows inserted or changed between two snapshots of one table.
fn changed(before: &Snapshot, after: &Snapshot, table: &str) -> Vec<String> {
    let empty = BTreeMap::new();
    let old = before.get(table).unwrap_or(&empty);
    after
        .get(table)
        .unwrap_or(&empty)
        .iter()
        .filter(|(k, v)| old.get(*k) != Some(*v))
        .map(|(k, _)| k.clone())
        .collect()
}

/// The exact defects of one memories row the step inserted or changed, or
/// none when it is sealed for the session agent and verifies.
fn memory_row_defects(sb: &Sandbox, id: &str, require: &str) -> Vec<String> {
    let conn = sb.conn();
    let Some(mem) = ai_memory::db::get_any(&conn, id).expect("get_any") else {
        return Vec::new();
    };
    let owner = mem.metadata["agent_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let level = mem.metadata["attest_level"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if owner != AGENT {
        if require == "1" {
            return vec![format!(
                "row {id} owned by {owner:?} stored under strict mode"
            )];
        }
        if level == ATTESTED {
            let bound = ai_memory::db::agent_pubkey(&conn, &owner).expect("owner key lookup");
            if bound.is_none() {
                return vec![format!(
                    "row {id} owned by {owner:?} is agent_attested with no key of its own"
                )];
            }
        }
        return Vec::new();
    }
    if level != ATTESTED {
        return vec![format!(
            "row {id} attest_level {level:?}, expected {ATTESTED:?}"
        )];
    }
    let Some(sig_b64) = mem.metadata["write_signature"].as_str() else {
        return vec![format!("row {id} has no write_signature")];
    };
    let Ok(sig) = base64::engine::general_purpose::STANDARD.decode(sig_b64) else {
        return vec![format!("row {id} write_signature is not base64")];
    };
    let bound = ai_memory::db::agent_pubkey(&conn, AGENT).expect("bound key lookup");
    match ai_memory::identity::attest::resolve_write_attest_level(
        &mem,
        AGENT,
        bound.as_deref(),
        Some(&sig),
        true,
    ) {
        Ok(ai_memory::identity::verify::AttestLevel::AgentAttested) => Vec::new(),
        Ok(other) => vec![format!("row {id} verified level {other:?}")],
        Err(e) => vec![format!(
            "row {id} signature does not verify against the bound key: {e}"
        )],
    }
}

/// The cells of one snapshot row, by column name.
fn cells(row: &str) -> BTreeMap<&str, &str> {
    row.split('\u{1f}')
        .filter_map(|cell| cell.split_once('='))
        .collect()
}

/// The public key bound to the session agent in the sandbox database.
fn session_public_key(conn: &rusqlite::Connection) -> ed25519_dalek::VerifyingKey {
    let b64 = ai_memory::db::agent_pubkey(conn, AGENT)
        .expect("bound key lookup")
        .expect("the session agent has a bound key");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .expect("bound key is url-safe base64");
    let raw: [u8; 32] = raw.as_slice().try_into().expect("bound key is 32 bytes");
    ed25519_dalek::VerifyingKey::from_bytes(&raw).expect("bound key is a point")
}

fn cell_opt<'a>(row: &BTreeMap<&str, &'a str>, col: &str) -> Option<&'a str> {
    row.get(col).copied().filter(|v| *v != "NULL")
}

fn cell_blob(row: &BTreeMap<&str, &str>, col: &str) -> Option<Vec<u8>> {
    cell_opt(row, col).and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
}

/// Whether the stored signature of one signed side row verifies with the
/// session agent's bound key over that table's signed fields.
fn signed_row_verifies(
    conn: &rusqlite::Connection,
    public: &ed25519_dalek::VerifyingKey,
    table: &str,
    row: &BTreeMap<&str, &str>,
) -> bool {
    let id = cell_opt(row, "id").unwrap_or_default();
    match table {
        "memory_links" => {
            let (Some(src), Some(dst), Some(relation), Some(sig)) = (
                cell_opt(row, "source_id"),
                cell_opt(row, "target_id"),
                cell_opt(row, "relation"),
                cell_blob(row, "signature"),
            ) else {
                return false;
            };
            let link = ai_memory::identity::sign::SignableLink {
                src_id: src,
                dst_id: dst,
                relation,
                observed_by: cell_opt(row, "observed_by"),
                created_at: cell_opt(row, "created_at"),
                valid_from: cell_opt(row, "valid_from"),
                valid_until: cell_opt(row, "valid_until"),
            };
            cell_opt(row, "observed_by") == Some(AGENT)
                && ai_memory::identity::verify::verify(public, &link, &sig).is_ok()
        }
        "signals" => ai_memory::signals::get(conn, id)
            .expect("signal read")
            .is_some_and(|sig| {
                sig.from_agent == AGENT
                    && ai_memory::signals::verify_with_key(&sig, public.as_bytes())
            }),
        "checkpoints" => ai_memory::checkpoints::get(conn, id)
            .expect("checkpoint read")
            .is_some_and(|cp| {
                cp.resolver_pubkey == public.as_bytes() && ai_memory::checkpoints::verify(&cp)
            }),
        "routines" => ai_memory::routines::routine_get(conn, id)
            .expect("routine read")
            .is_some_and(|r| {
                r.signer_pubkey == public.as_bytes() && ai_memory::routines::verify(&r)
            }),
        "skills" => {
            let (Some(digest), Some(sig)) = (cell_blob(row, "digest"), cell_blob(row, "signature"))
            else {
                return false;
            };
            cell_opt(row, "signing_agent") == Some(AGENT)
                && ed25519_dalek::Signature::from_slice(&sig)
                    .is_ok_and(|sig| public.verify_strict(&digest, &sig).is_ok())
        }
        "offloaded_blobs" => {
            // The blob envelope, rebuilt here independently of the product
            // code: deterministic CBOR over {content_sha256, namespace,
            // ref_id, stored_at} (keys in sorted order), Ed25519 over it.
            let (Some(ref_id), Some(sha), Some(namespace), Some(stored_at), Some(sig)) = (
                cell_opt(row, "ref_id"),
                cell_opt(row, "content_sha256"),
                cell_opt(row, "namespace"),
                cell_opt(row, "stored_at").and_then(|v| v.parse::<i64>().ok()),
                cell_opt(row, "signature_b64").and_then(|v| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(v)
                        .ok()
                }),
            ) else {
                return false;
            };
            let text = |v: &str| ciborium::Value::Text(v.to_string());
            let envelope = ciborium::Value::Map(vec![
                (text("content_sha256"), text(sha)),
                (text("namespace"), text(namespace)),
                (text("ref_id"), text(ref_id)),
                (
                    text("stored_at"),
                    ciborium::Value::Integer(stored_at.into()),
                ),
            ]);
            let mut payload = Vec::new();
            ciborium::into_writer(&envelope, &mut payload).expect("encode offload envelope");
            cell_opt(row, "agent_id") == Some(AGENT)
                && ed25519_dalek::Signature::from_slice(&sig)
                    .is_ok_and(|sig| public.verify_strict(&payload, &sig).is_ok())
        }
        other => panic!("{other} is in SIGNED_TABLES with no verifier"),
    }
}

/// The exact defect of one changed signed side row, or none when its stored
/// signature verifies with the session key (#10054: presence is no proof).
fn signed_row_defect(
    sb: &Sandbox,
    after: &Snapshot,
    table: &str,
    column: &str,
    key: &str,
) -> Option<String> {
    let row = cells(&after[table][key]);
    if cell_opt(&row, column).is_none_or(str::is_empty) {
        return Some(format!("{table} row {key} has no {column}"));
    }
    let conn = sb.conn();
    let public = session_public_key(&conn);
    (!signed_row_verifies(&conn, &public, table, &row)).then(|| {
        format!("{table} row {key}: {column} does not verify with the key bound to {AGENT}")
    })
}

/// The ONLY changes a `ReadOnly` tool may make outside `EXEMPT_TABLES`:
/// `(tool, table, reason)`. Every other change by a `ReadOnly` tool is a
/// defect (#10054).
const READONLY_ALLOWANCES: [(&str, &str, &str); 1] = [(
    "memory_signal_read",
    "signals",
    "read receipt: sets read_at on the recipient's signal; read_at is outside the signed signal fields and the row still verifies",
)];

/// The exact mismatch between a step's outcome and its [`Expect`], if any.
fn outcome_defect(expect: Expect, require: &str, is_error: bool, text: &str) -> Option<String> {
    let strict = require == "1";
    if matches!(expect, Expect::ForeignRow) && strict {
        return match (is_error, is_foreign_refusal(text)) {
            (true, true) => None,
            (true, false) => Some(format!(
                "expected refusal {FOREIGN_ROW_STRICT_REFUSAL:?} (row <id>); refused, got error {text:?}"
            )),
            (false, _) => Some(format!(
                "expected refusal {FOREIGN_ROW_STRICT_REFUSAL:?}, got success {text:?}"
            )),
        };
    }
    let refused_with = match expect {
        Expect::Ok | Expect::ForeignRow => None,
        Expect::Refused(prefix) => Some(prefix),
    };
    match (refused_with, is_error) {
        (None, false) => None,
        (None, true) => Some(format!("expected success, got error {text:?}")),
        (Some(p), true) if text.starts_with(p) => None,
        (Some(p), true) => Some(format!("expected refusal {p:?}, got error {text:?}")),
        (Some(p), false) => Some(format!("expected refusal {p:?}, got success {text:?}")),
    }
}

fn class_of(tool: &str) -> (Class, &'static [&'static str]) {
    TOOL_CLASS
        .iter()
        .find(|(name, ..)| *name == tool)
        .map_or_else(
            || panic!("{tool} has no TOOL_CLASS row"),
            |(_, c, t, _)| (*c, *t),
        )
}

/// Drive every step under one posture; return every defect, attributed to
/// the tool call that produced it.
fn sweep_all_tools(require: &str) -> Vec<String> {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let mut mcp = sb.start(require, &key);
    let mut slots = BTreeMap::new();
    slots.insert("DIR".to_string(), sb.root.to_string_lossy().into_owned());
    let mut defects = Vec::new();
    let mut before = snapshot(&sb);
    for (n, s) in STEPS.iter().enumerate() {
        let args = fill(&(s.args)(), &slots);
        let (is_error, text) = mcp.call_raw(s.tool, &args);
        if let (false, Some((slot, field))) = (is_error, s.capture) {
            let parsed: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            if let Some(id) = parsed[field].as_str() {
                slots.insert(slot.to_string(), id.to_string());
            }
        }
        let after = snapshot(&sb);
        let label = format!("step {n} {} REQUIRE={require}", s.tool);
        let (class, side) = class_of(s.tool);
        if let Some(d) = outcome_defect(s.expect, require, is_error, &text) {
            defects.push(format!("{label}: {d}"));
        }
        for id in changed(&before, &after, "memories") {
            for d in memory_row_defects(&sb, &id, require) {
                defects.push(format!("{label}: {d}"));
            }
        }
        for (table, column) in SIGNED_TABLES {
            if SIGNED_LATER
                .iter()
                .any(|(t, tb, _)| *t == s.tool && *tb == table)
            {
                continue;
            }
            for k in changed(&before, &after, table) {
                if let Some(d) = signed_row_defect(&sb, &after, table, column, &k) {
                    defects.push(format!("{label}: {d}"));
                }
            }
        }
        if class == Class::ReadOnly {
            for table in after.keys() {
                let allowed = EXEMPT_TABLES.iter().any(|(t, _)| t == table)
                    || READONLY_ALLOWANCES
                        .iter()
                        .any(|(tool, t, _)| *tool == s.tool && t == table);
                let rows = changed(&before, &after, table);
                if !allowed && !rows.is_empty() {
                    defects.push(format!(
                        "{label}: read-only tool changed {table} rows {rows:?}"
                    ));
                }
            }
        }
        // #10040: every row key of every attested table (memories and the
        // 13 side tables) carries a latest attestation that verifies against
        // the bound key and the live row, and the signed watermark covers
        // the whole table (C-5 completeness). #10086: the key comes from
        // the sandbox key directory (the trust anchor), never the database;
        // an unanchored run is a defect, not a silent pass.
        let anchor =
            ai_memory::storage::row_attest::anchor::TrustAnchor::load_dir(&sb.root.join("keys"));
        match ai_memory::storage::row_attest::sqlite::verify_sqlite_with(&sb.conn(), &anchor) {
            Ok(report) => {
                if !report.ok() && report.defects.is_empty() {
                    defects.push(format!(
                        "{label}: row attestation outcome {}",
                        report.outcome().kind()
                    ));
                }
                for d in report.defects {
                    defects.push(format!("{label}: row attestation: {d}"));
                }
            }
            Err(e) => defects.push(format!("{label}: row attestation verifier: {e:#}")),
        }
        for table in after.keys() {
            let known = table == "memories"
                || EXEMPT_TABLES.iter().any(|(t, _)| t == table)
                || SIGNED_TABLES.iter().any(|(t, _)| t == table)
                || side.contains(&table.as_str());
            if !known && !changed(&before, &after, table).is_empty() {
                defects.push(format!(
                    "{label}: changed table {table} its TOOL_CLASS row does not name"
                ));
            }
        }
        eprintln!(
            "seal-10012 {label}: is_error={is_error} {}",
            text.chars().take(100).collect::<String>()
        );
        before = after;
    }
    defects
}

/// FAILS on the base (`fix/stdio-selfsign`): `memory_update`,
/// `memory_promote`, ... store `claimed` rows and the side tools sign with
/// the on-disk key, not the session key.
#[test]
fn every_tool_write_is_sealed_permissive_10012() {
    let defects = sweep_all_tools(POSTURES[0]);
    assert!(
        defects.is_empty(),
        "{} defects:\n{}",
        defects.len(),
        defects.join("\n")
    );
}

#[test]
fn every_tool_write_is_sealed_strict_10012() {
    let defects = sweep_all_tools(POSTURES[1]);
    assert!(
        defects.is_empty(),
        "{} defects:\n{}",
        defects.len(),
        defects.join("\n")
    );
}

/// The ratchet: the registry, `TOOL_CLASS` and `STEPS` name the same tools,
/// each `TOOL_CLASS` name once, every side table a known row-attested
/// table, only `Attested` rows name side tables, and the row-attested
/// tables plus `memories` are exactly `row_attest::TABLES` (#10040).
#[test]
fn every_registered_tool_is_classified_and_driven_10012() {
    let defs = ai_memory::mcp::tool_definitions();
    let registry: BTreeSet<String> = defs["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().expect("tool name").to_string())
        .collect();
    let classified: Vec<&str> = TOOL_CLASS.iter().map(|(n, ..)| *n).collect();
    let classified_set: BTreeSet<String> = classified.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(
        classified.len(),
        classified_set.len(),
        "a TOOL_CLASS name repeats"
    );
    let driven: BTreeSet<String> = STEPS.iter().map(|s| s.tool.to_string()).collect();
    let unclassified: Vec<_> = registry.difference(&classified_set).collect();
    let undriven: Vec<_> = registry.difference(&driven).collect();
    let unknown: Vec<_> = classified_set
        .union(&driven)
        .filter(|n| !registry.contains(*n))
        .collect();
    assert_eq!(
        unclassified,
        Vec::<&String>::new(),
        "registered tools with no TOOL_CLASS row"
    );
    assert_eq!(
        undriven,
        Vec::<&String>::new(),
        "registered tools with no drive step"
    );
    assert_eq!(
        unknown,
        Vec::<&String>::new(),
        "classified or driven tools not in the registry"
    );
    for (name, class, side, reason) in TOOL_CLASS {
        assert!(!reason.is_empty(), "{name}: reason");
        assert_eq!(
            class == Class::Attested,
            !side.is_empty(),
            "{name}: Attested iff side tables"
        );
        for t in side {
            assert!(
                ROW_ATTESTED_TABLES.contains(t),
                "{name}: {t} is not a row-attested table"
            );
        }
    }
    // #10040: the attested side tables plus `memories` are exactly the
    // tables the row-attestation funnel covers, so no side table can be
    // classified without a verifier behind it.
    let mut expected: BTreeSet<&str> = ROW_ATTESTED_TABLES.iter().copied().collect();
    expected.insert("memories");
    let funnel: BTreeSet<&str> = ai_memory::storage::row_attest::TABLES
        .iter()
        .map(|s| s.table)
        .collect();
    assert_eq!(
        funnel, expected,
        "row_attest::TABLES vs ROW_ATTESTED_TABLES"
    );
}

// --- Seeded rows: unsigned, tampered, foreign (#10053, #10054, #10055) ---
//
// A raw connection has no seal triggers, so these tests can strip, tamper
// or re-attribute a row the session sealed, then drive one tool over stdio
// and compare the row's signed fields and seal byte for byte.

/// The signed columns and the seal of one memories row, read raw.
fn seal_state(sb: &Sandbox, id: &str) -> String {
    sb.conn()
        .query_row(
            "SELECT namespace || char(31) || title || char(31) || content || char(31) || \
             memory_kind || char(31) || created_at || char(31) || \
             COALESCE(json_extract(metadata, '$.agent_id'), 'NULL') || char(31) || \
             COALESCE(json_extract(metadata, '$.attest_level'), 'NULL') || char(31) || \
             COALESCE(json_extract(metadata, '$.write_signature'), 'NULL') \
             FROM memories WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .expect("read seal state")
}

fn attest_level(sb: &Sandbox, id: &str) -> Option<String> {
    sb.conn()
        .query_row(
            "SELECT json_extract(metadata, '$.attest_level') FROM memories WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .expect("read attest_level")
}

/// One raw write on the sandbox store (no seal triggers), exactly one row.
fn raw_write(sb: &Sandbox, sql: &str, id: &str) {
    let conn = sb.seed_conn();
    let n = conn.execute(sql, [id]).expect("raw seed write");
    assert_eq!(n, 1, "{sql}: rows changed");
}

/// Change sealed content behind the signer's back.
const TAMPER_SQL: &str = "UPDATE memories SET content = content || ' tampered' WHERE id = ?1";

/// Re-attribute a row to another agent with no seal: a foreign claimed row.
const FOREIGN_SQL: &str = "UPDATE memories SET metadata = json_set(json_remove(metadata, '$.write_signature'), '$.attest_level', 'claimed', '$.agent_id', 'ai:other-10012') WHERE id = ?1";

fn store_id(mcp: &mut Mcp, title: &str) -> String {
    let (is_error, text) = mcp.call_raw("memory_store", &store_args(title));
    assert!(!is_error, "store {title}: {text}");
    let v: Value = serde_json::from_str(&text).expect("store json");
    v["id"].as_str().expect("store id").to_string()
}

/// Session writes over a seeded row. `refusal` is the exact error text the
/// posture must return (`None`: the write succeeds); `ids` the rows whose
/// signed fields and seal must stay byte for byte as seeded.
struct SeededCase {
    tool: &'static str,
    args: Value,
    refusal: Option<String>,
    ids: Vec<String>,
}

fn run_seeded(sb: &Sandbox, mcp: &mut Mcp, case: &SeededCase, label: &str) -> Vec<String> {
    let mut defects = Vec::new();
    let before: Vec<String> = case.ids.iter().map(|id| seal_state(sb, id)).collect();
    let attested_before: Vec<bool> = case
        .ids
        .iter()
        .map(|id| attest_level(sb, id).as_deref() == Some(ATTESTED))
        .collect();
    let (is_error, text) = mcp.call_raw(case.tool, &case.args);
    match (&case.refusal, is_error) {
        (Some(want), true) if text == *want => {}
        (Some(want), _) => defects.push(format!(
            "{label} {}: expected refusal {want:?}, got is_error={is_error} {text:?}",
            case.tool
        )),
        (None, false) => {}
        (None, true) => defects.push(format!(
            "{label} {}: expected success, got error {text:?}",
            case.tool
        )),
    }
    for ((id, prior), was_attested) in case.ids.iter().zip(&before).zip(attested_before) {
        let now = seal_state(sb, id);
        if now != *prior {
            defects.push(format!(
                "{label} {}: row {id} signed fields or seal changed:\n  before {prior:?}\n  after  {now:?}",
                case.tool
            ));
        }
        if !was_attested && attest_level(sb, id).as_deref() == Some(ATTESTED) {
            defects.push(format!(
                "{label} {}: row {id} carries {ATTESTED} over bytes the session did not seal",
                case.tool
            ));
        }
    }
    defects
}

/// #10053: a claimed, unsigned session row is never resealed by a tags or
/// priority update, a promote or a consolidate; strict refuses exactly.
fn unsigned_session_row_defects(require: &str) -> Vec<String> {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    // A is written by a session with no signer (the CLI, before the signed
    // MCP session opens): a real claimed row. Stripping a seal with raw SQL
    // instead is a write outside the #10040 funnel, which refuses it.
    let out = sb.cli_ok(
        AGENT,
        &[
            "store",
            "-T",
            "seal unsigned a 10053",
            "-c",
            &body("unsigned a 10053"),
            "--namespace",
            NAMESPACE,
            "--tier",
            "mid",
            "--json",
        ],
    );
    let stored: Value = serde_json::from_str(&out).expect("store json");
    let a = stored["id"].as_str().expect("id").to_string();
    let mut mcp = sb.start(require, &key);
    let strict = require == "1";
    let mut defects = Vec::new();
    let b = store_id(&mut mcp, "seal unsigned b 10053");
    if attest_level(&sb, &a).as_deref() == Some(ATTESTED) {
        defects.push(format!("REQUIRE={require}: the CLI row {a} is sealed"));
    }
    let unsealed = |id: &str| strict.then(|| unsealed_refusal(id));
    let cases = [
        SeededCase {
            tool: "memory_update",
            args: json!({"id": a, "priority": 9}),
            refusal: unsealed(&a),
            ids: vec![a.clone()],
        },
        SeededCase {
            tool: "memory_update",
            args: json!({"id": a, "tags": ["seal-10053"]}),
            refusal: unsealed(&a),
            ids: vec![a.clone()],
        },
        SeededCase {
            tool: "memory_promote",
            args: json!({"id": a, "target_tier": "long"}),
            refusal: unsealed(&a),
            ids: vec![a.clone()],
        },
    ];
    for case in &cases {
        defects.extend(run_seeded(
            &sb,
            &mut mcp,
            case,
            &format!("REQUIRE={require}"),
        ));
    }
    // Consolidate folds A (unsigned) into a new row the session seals over
    // content it supplied in this call; A itself is never resealed.
    let before_a = seal_state(&sb, &a);
    let (is_error, text) = mcp.call_raw(
        "memory_consolidate",
        &json!({"ids": [a, b], "title": "seal consolidation 10053", "summary": body("consolidation 10053"), "namespace": NAMESPACE}),
    );
    let label = format!("REQUIRE={require} memory_consolidate");
    if is_error {
        defects.push(format!("{label}: expected success, got error {text:?}"));
    } else {
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        match v["id"].as_str() {
            Some(new_id) => {
                for d in memory_row_defects(&sb, new_id, require) {
                    defects.push(format!("{label}: {d}"));
                }
            }
            None => defects.push(format!("{label}: no id in {text:?}")),
        }
        let row_left: bool = sb
            .conn()
            .query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [&a], |r| {
                r.get::<_, i64>(0)
            })
            .expect("count a")
            == 1;
        if row_left && seal_state(&sb, &a) != before_a {
            defects.push(format!("{label}: unsigned source row {a} changed"));
        }
        if row_left && attest_level(&sb, &a).as_deref() == Some(ATTESTED) {
            defects.push(format!("{label}: unsigned source row {a} was resealed"));
        }
    }
    defects
}

#[test]
fn unsigned_session_row_is_never_resealed_permissive_10053() {
    let defects = unsigned_session_row_defects(POSTURES[0]);
    assert!(defects.is_empty(), "{}", defects.join("\n"));
}

#[test]
fn unsigned_session_row_is_never_resealed_strict_10053() {
    let defects = unsigned_session_row_defects(POSTURES[1]);
    assert!(defects.is_empty(), "{}", defects.join("\n"));
}

/// #10055: content changed behind the signer, then a metadata-only update:
/// refused in both postures with the exact text, and nothing changes.
fn tampered_row_defects(require: &str) -> Vec<String> {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let mut mcp = sb.start(require, &key);
    let a = store_id(&mut mcp, "seal tampered a 10055");
    raw_write(&sb, TAMPER_SQL, &a);
    let label = format!("REQUIRE={require}");
    let mut defects = Vec::new();
    for args in [
        json!({"id": a, "priority": 9}),
        json!({"id": a, "tags": ["seal-10055"]}),
    ] {
        let case = SeededCase {
            tool: "memory_update",
            args,
            refusal: Some(tampered_refusal(&a)),
            ids: vec![a.clone()],
        };
        defects.extend(run_seeded(&sb, &mut mcp, &case, &label));
    }
    let promote = SeededCase {
        tool: "memory_promote",
        args: json!({"id": a, "target_tier": "long"}),
        refusal: Some(tampered_refusal(&a)),
        ids: vec![a.clone()],
    };
    defects.extend(run_seeded(&sb, &mut mcp, &promote, &label));
    // The stored seal is the one the session wrote over the untampered
    // bytes: it still names the session and still does not verify.
    let tampered_still_fails = memory_row_defects(&sb, &a, require);
    if tampered_still_fails.is_empty() {
        defects.push(format!(
            "{label}: tampered row {a} verifies; the tamper was resealed"
        ));
    }
    defects
}

#[test]
fn tampered_row_is_refused_not_resealed_permissive_10055() {
    let defects = tampered_row_defects(POSTURES[0]);
    assert!(defects.is_empty(), "{}", defects.join("\n"));
}

#[test]
fn tampered_row_is_refused_not_resealed_strict_10055() {
    let defects = tampered_row_defects(POSTURES[1]);
    assert!(defects.is_empty(), "{}", defects.join("\n"));
}

/// The ownership gate's refusal of a write to a row another agent owns.
const NOT_OWNER_REFUSAL: &str = "caller does not own this memory";

/// Code LOW-1: a session write to a row attributed to another agent is
/// refused before any seal is computed, in both postures, and the foreign
/// signed fields and seal stay byte for byte; under strict mode a write
/// that would create a row attributed to another agent (`memory_share`) is
/// refused with the exact text naming that row, and the row does not exist.
fn foreign_row_defects(require: &str) -> Vec<String> {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let mut mcp = sb.start(require, &key);
    let f = store_id(&mut mcp, "seal foreign f 10012");
    raw_write(&sb, FOREIGN_SQL, &f);
    let label = format!("REQUIRE={require}");
    let mut defects = Vec::new();
    for (tool, args) in [
        ("memory_update", json!({"id": f, "priority": 9})),
        (
            "memory_update",
            json!({"id": f, "content": body("foreign rewrite")}),
        ),
        ("memory_promote", json!({"id": f, "target_tier": "long"})),
    ] {
        let case = SeededCase {
            tool,
            args,
            refusal: Some(NOT_OWNER_REFUSAL.to_string()),
            ids: vec![f.clone()],
        };
        defects.extend(run_seeded(&sb, &mut mcp, &case, &label));
    }
    if require == "1" {
        let own = store_id(&mut mcp, "seal foreign share 10012");
        let before = snapshot(&sb);
        let (is_error, text) = mcp.call_raw(
            "memory_share",
            &json!({"source_memory_id": own, "target_agent_id": OTHER_AGENT}),
        );
        let after = snapshot(&sb);
        let named = text
            .strip_prefix(FOREIGN_ROW_STRICT_REFUSAL)
            .and_then(|t| t.strip_prefix(" (row "))
            .and_then(|t| t.strip_suffix("); refused"))
            .map(str::to_string);
        match (is_error, named) {
            (true, Some(id)) => {
                if text != foreign_refusal(&id) {
                    defects.push(format!("{label} memory_share: refusal {text:?}"));
                }
                if sb
                    .conn()
                    .query_row("SELECT COUNT(*) FROM memories WHERE id = ?1", [&id], |r| {
                        r.get::<_, i64>(0)
                    })
                    .expect("count shared")
                    != 0
                {
                    defects.push(format!("{label} memory_share: refused row {id} was stored"));
                }
            }
            _ => defects.push(format!(
                "{label} memory_share: expected {FOREIGN_ROW_STRICT_REFUSAL:?} (row <id>); refused, got is_error={is_error} {text:?}"
            )),
        }
        for table in after.keys() {
            if !EXEMPT_TABLES.iter().any(|(t, _)| t == table)
                && !changed(&before, &after, table).is_empty()
            {
                defects.push(format!(
                    "{label} memory_share: refused call changed {table}"
                ));
            }
        }
    }
    defects
}

#[test]
fn foreign_row_write_is_refused_by_row_strict_10012() {
    let defects = foreign_row_defects(POSTURES[1]);
    assert!(defects.is_empty(), "{}", defects.join("\n"));
}

#[test]
fn foreign_row_write_keeps_its_bytes_permissive_10012() {
    let defects = foreign_row_defects(POSTURES[0]);
    assert!(defects.is_empty(), "{}", defects.join("\n"));
}

// --- kg_invalidate over seeded edges (Code LOW-2, #10054) ---

const EDGE_PREFIX: &str = "ATTESTATION_FAILED: mcp session signer (#10012): ";
const EDGE_TAMPERED: &str = "ATTESTATION_FAILED: mcp session signer (#10012): stored link signature does not verify; refusing to re-sign";
const EDGE_FOREIGN_SEAL: &str = "ATTESTATION_FAILED: mcp session signer (#10012): the invalidation changes a link signed by another agent; refused";
const EDGE_NO_OBSERVER_STRICT: &str = "ATTESTATION_FAILED: mcp session signer (#10012): under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 a link with no observer cannot be sealed: no observer; the session does not re-sign; refused";
const EDGE_UNSIGNED_STRICT: &str = "ATTESTATION_FAILED: mcp session signer (#10012): under AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1 an unsigned link the session did not seal cannot be sealed; refused";

/// How one seeded edge differs from the session's sealed edge.
#[derive(Debug, Clone, Copy)]
enum EdgeSeed {
    NoObserver,
    UnsignedOwn,
    Tampered,
    SignedForeign,
    Intact,
}

impl EdgeSeed {
    const ALL: [Self; 5] = [
        Self::NoObserver,
        Self::UnsignedOwn,
        Self::Tampered,
        Self::SignedForeign,
        Self::Intact,
    ];

    const fn sql(self) -> Option<&'static str> {
        match self {
            Self::NoObserver => Some(
                "UPDATE memory_links SET observed_by = NULL, signature = NULL, attest_level = 'unsigned' WHERE source_id = ?1",
            ),
            Self::UnsignedOwn => Some(
                "UPDATE memory_links SET signature = NULL, attest_level = 'unsigned' WHERE source_id = ?1",
            ),
            Self::Tampered => Some(
                "UPDATE memory_links SET created_at = '2020-01-01T00:00:00+00:00' WHERE source_id = ?1",
            ),
            Self::SignedForeign => {
                Some("UPDATE memory_links SET observed_by = 'ai:other-10012' WHERE source_id = ?1")
            }
            Self::Intact => None,
        }
    }

    /// The expected refusal, written out per posture (`None`: success).
    const fn refusal(self, strict: bool) -> Option<&'static str> {
        match (self, strict) {
            (Self::NoObserver, true) => Some(EDGE_NO_OBSERVER_STRICT),
            (Self::UnsignedOwn, true) => Some(EDGE_UNSIGNED_STRICT),
            (Self::Tampered, _) => Some(EDGE_TAMPERED),
            (Self::SignedForeign, _) => Some(EDGE_FOREIGN_SEAL),
            (Self::NoObserver | Self::UnsignedOwn | Self::Intact, _) => None,
        }
    }
}

fn link_row(sb: &Sandbox, source: &str) -> String {
    sb.conn()
        .query_row(
            "SELECT COALESCE(observed_by, 'NULL') || char(31) || created_at || char(31) || \
             COALESCE(valid_until, 'NULL') || char(31) || COALESCE(attest_level, 'NULL') || \
             char(31) || CASE WHEN signature IS NULL THEN 'NULL' ELSE hex(signature) END \
             FROM memory_links WHERE source_id = ?1",
            [source],
            |r| r.get(0),
        )
        .expect("read link")
}

fn edge_defects(require: &str) -> Vec<String> {
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let mut mcp = sb.start(require, &key);
    let strict = require == "1";
    let b = store_id(&mut mcp, "seal edge b 10012");
    let relation = "related_to";
    let mut defects = Vec::new();
    for seed in EdgeSeed::ALL {
        let a = store_id(&mut mcp, &format!("seal edge {seed:?} 10012"));
        let label = format!("REQUIRE={require} {seed:?}");
        let (is_error, text) = mcp.call_raw(
            "memory_link",
            &json!({"source_id": a, "target_id": b, "relation": relation}),
        );
        assert!(!is_error, "{label} link: {text}");
        if let Some(sql) = seed.sql() {
            raw_write(&sb, sql, &a);
        }
        let before = link_row(&sb, &a);
        let (is_error, text) = mcp.call_raw(
            "memory_kg_invalidate",
            &json!({"source_id": a, "target_id": b, "relation": relation, "valid_until": "2030-01-01T00:00:00+00:00"}),
        );
        let after = link_row(&sb, &a);
        match (seed.refusal(strict), is_error) {
            (Some(want), true) if text == want => {
                if after != before {
                    defects.push(format!(
                        "{label}: refused but the link changed:\n  {before:?}\n  {after:?}"
                    ));
                }
            }
            (Some(want), _) => defects.push(format!(
                "{label}: expected refusal {want:?}, got is_error={is_error} {text:?}"
            )),
            (None, true) => defects.push(format!("{label}: expected success, got error {text:?}")),
            (None, false) => {
                let snap = snapshot(&sb);
                let key = snap["memory_links"]
                    .iter()
                    .find(|(_, row)| cells(row).get("source_id") == Some(&a.as_str()))
                    .map(|(k, _)| k.clone());
                let signed = !after.ends_with("\u{1f}NULL");
                match (seed, key) {
                    (EdgeSeed::Intact, Some(k)) => {
                        if let Some(d) =
                            signed_row_defect(&sb, &snap, "memory_links", "signature", &k)
                        {
                            defects.push(format!("{label}: {d}"));
                        }
                    }
                    (EdgeSeed::Intact, None) => defects.push(format!("{label}: link row gone")),
                    (_, _) if signed => defects.push(format!(
                        "{label}: an unsigned link left the invalidation signed: {after:?}"
                    )),
                    _ => {}
                }
            }
        }
        if text.starts_with(EDGE_PREFIX) && !is_error {
            defects.push(format!("{label}: refusal text on a success: {text:?}"));
        }
    }
    defects
}

#[test]
fn kg_invalidate_seeded_edges_permissive_10012() {
    let defects = edge_defects(POSTURES[0]);
    assert!(defects.is_empty(), "{}", defects.join("\n"));
}

#[test]
fn kg_invalidate_seeded_edges_strict_10012() {
    let defects = edge_defects(POSTURES[1]);
    assert!(defects.is_empty(), "{}", defects.join("\n"));
}

// --- Smart-tier tools against a loopback stub LLM (Code LOW-3) ---

/// The stub's chat answer: a tag list for `auto_tag`, "no" contradiction, a
/// persona body for `persona_generate`.
const STUB_CHAT_ANSWER: &str = "seal-tag-one, seal-tag-two";
const STUB_MODEL: &str = "seal-stub-10012";

fn stub_llm(rt: &tokio::runtime::Runtime) -> wiremock::MockServer {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    rt.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"models": [{"name": format!("{STUB_MODEL}:latest")}]})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/pull"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "success"})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "model": STUB_MODEL,
                "message": {"role": "assistant", "content": STUB_CHAT_ANSWER},
                "done": true
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/generate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "model": STUB_MODEL, "response": STUB_CHAT_ANSWER, "done": true
            })))
            .mount(&server)
            .await;
        server
    })
}

/// One smart-tier step: the tool, its args and the exact change it must
/// commit (`changes`: the tables whose rows must change).
fn smart_tier_defects(require: &str) -> Vec<String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let server = stub_llm(&rt);
    let uri = server.uri();
    let sb = Sandbox::new();
    let key = sb.bound_key_file();
    let extra = [
        ("AI_MEMORY_LLM_BACKEND", "ollama"),
        ("AI_MEMORY_LLM_BASE_URL", uri.as_str()),
        ("AI_MEMORY_LLM_MODEL", STUB_MODEL),
        ("AI_MEMORY_EMBED_BASE_URL", uri.as_str()),
        ("AI_MEMORY_EMBED_OFFLINE", "1"),
        ("AI_MEMORY_INFERENCE_EGRESS", "loopback-only"),
    ];
    let mut mcp = sb.start_with(require, &key, "smart", &extra);
    let label = format!("REQUIRE={require}");
    let mut defects = Vec::new();
    let a = store_id(&mut mcp, "seal smart a 10012");
    let b = store_id(&mut mcp, "seal smart b 10012");
    let f = store_id(&mut mcp, "seal smart foreign 10012");
    raw_write(&sb, FOREIGN_SQL, &f);
    let entity = "seal-persona-10012";
    for i in 0..2 {
        let (is_error, text) = mcp.call_raw(
            "memory_store",
            &json!({"title": format!("seal persona obs {i} 10012"), "content": body(&format!("persona obs {i}")), "namespace": NAMESPACE, "kind": "reflection", "tags": ["reflection"], "metadata": {"entity_id": entity}}),
        );
        assert!(!is_error, "{label} persona seed {i}: {text}");
    }
    let promote_pending = {
        let conn = sb.seed_conn();
        ai_memory::storage::queue_pending_action(
            &conn,
            ai_memory::models::GovernedAction::Promote,
            NAMESPACE,
            Some(&a),
            OTHER_AGENT,
            &json!({}),
        )
        .expect("queue pending promote")
    };
    let reject_pending = {
        let conn = sb.seed_conn();
        ai_memory::storage::queue_pending_action(
            &conn,
            ai_memory::models::GovernedAction::Promote,
            NAMESPACE,
            Some(&b),
            OTHER_AGENT,
            &json!({}),
        )
        .expect("queue pending reject")
    };
    // (tool, args, the tables the call must change; empty: none). The
    // `memories` snapshot keeps only the signed columns, so a change to the
    // unsigned `tags` or `tier` columns is checked on its own below.
    let steps: [(&str, Value, &[&str]); 5] = [
        ("memory_auto_tag", json!({"id": a}), &[]),
        (
            "memory_detect_contradiction",
            json!({"id_a": a, "id_b": b}),
            &[],
        ),
        (
            "memory_persona_generate",
            json!({"entity_id": entity, "namespace": NAMESPACE}),
            &["memories", "memory_links"],
        ),
        (
            "memory_pending_approve",
            json!({"id": promote_pending}),
            &["pending_actions"],
        ),
        (
            "memory_pending_reject",
            json!({"id": reject_pending}),
            &["pending_actions"],
        ),
    ];
    for (tool, args, must_change) in steps {
        let before = snapshot(&sb);
        let (is_error, text) = mcp.call_raw(tool, &args);
        let after = snapshot(&sb);
        let step = format!("{label} {tool}");
        eprintln!(
            "seal-10012 smart {step}: is_error={is_error} {}",
            text.chars().take(160).collect::<String>()
        );
        if is_error {
            defects.push(format!("{step}: expected success, got error {text:?}"));
            continue;
        }
        let changed_tables: BTreeSet<&str> = after
            .keys()
            .filter(|t| !EXEMPT_TABLES.iter().any(|(e, _)| e == *t))
            .filter(|t| !changed(&before, &after, t).is_empty())
            .map(String::as_str)
            .collect();
        let want: BTreeSet<&str> = must_change.iter().copied().collect();
        if changed_tables != want {
            defects.push(format!(
                "{step}: changed tables {changed_tables:?}, expected {want:?}"
            ));
        }
        for id in changed(&before, &after, "memories") {
            for d in memory_row_defects(&sb, &id, require) {
                defects.push(format!("{step}: {d}"));
            }
        }
        for (table, column) in SIGNED_TABLES {
            for k in changed(&before, &after, table) {
                if let Some(d) = signed_row_defect(&sb, &after, table, column, &k) {
                    defects.push(format!("{step}: {d}"));
                }
            }
        }
    }
    // Code LOW-1: a row attributed to another agent is not visible to the
    // session, so the contradiction check over it is refused with the exact
    // text and changes nothing.
    {
        let before = snapshot(&sb);
        let (is_error, text) = mcp.call_raw(
            "memory_detect_contradiction",
            &json!({"id_a": a, "id_b": f}),
        );
        let after = snapshot(&sb);
        if !is_error || text != "memory B not found" {
            defects.push(format!(
                "{label} memory_detect_contradiction(foreign): expected \"memory B not found\", got is_error={is_error} {text:?}"
            ));
        }
        for table in after.keys() {
            if !EXEMPT_TABLES.iter().any(|(t, _)| t == table)
                && !changed(&before, &after, table).is_empty()
            {
                defects.push(format!(
                    "{label} memory_detect_contradiction(foreign): refused call changed {table}"
                ));
            }
        }
        if attest_level(&sb, &f).as_deref() == Some(ATTESTED) {
            defects.push(format!(
                "{label} memory_detect_contradiction(foreign): row {f} became {ATTESTED}"
            ));
        }
    }
    // The unsigned columns the smart tools wrote (written out, not derived).
    let unsigned = |id: &str| -> (String, String) {
        sb.conn()
            .query_row("SELECT tags, tier FROM memories WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .expect("read unsigned columns")
    };
    let (tags_a, tier_a) = unsigned(&a);
    if !tags_a.contains(STUB_CHAT_ANSWER) {
        defects.push(format!(
            "{label} memory_auto_tag: tags of {a} are {tags_a:?}"
        ));
    }
    if tier_a != "long" {
        defects.push(format!(
            "{label} memory_pending_approve: tier of {a} is {tier_a:?}, expected \"long\""
        ));
    }
    let (_, tier_b) = unsigned(&b);
    if tier_b == "long" {
        defects.push(format!(
            "{label} memory_pending_reject: rejected promote of {b} was applied"
        ));
    }
    for id in [&a, &b] {
        for d in memory_row_defects(&sb, id, require) {
            defects.push(format!("{label} after smart steps: {d}"));
        }
    }
    drop(mcp);
    drop(server);
    defects
}

#[test]
fn smart_tier_tools_commit_sealed_writes_permissive_10012() {
    let defects = smart_tier_defects(POSTURES[0]);
    assert!(defects.is_empty(), "{}", defects.join("\n"));
}

#[test]
fn smart_tier_tools_commit_sealed_writes_strict_10012() {
    let defects = smart_tier_defects(POSTURES[1]);
    assert!(defects.is_empty(), "{}", defects.join("\n"));
}
