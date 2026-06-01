// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_store` handler.
//!
//! #881 (PR-4): the entry-point handler + dispatch. Per-stage logic
//! lives in sibling sub-modules:
//!
//! * [`validation`]        — `OnConflict` enum + client-default
//!                           resolution.
//! * [`transport`]         — MCP → HTTP federation forward bridge
//!                           (`forward_to_http`, `forward_store_to_http`).
//! * [`synthesis`]         — Form 1 batch-action synthesis call +
//!                           verdict honouring (update / delete).
//! * [`legacy_classifier`] — v0.6.x per-pair contradiction loop +
//!                           post-store autonomy-hook metadata update.
//! * [`embed`]             — source-embed pipeline + HNSW warm-up.
//!
//! Wire compatibility preserved verbatim. Every response field,
//! error message, and tracing label is byte-identical to the
//! pre-#881 monolithic [`handle_store`].

mod embed;
mod legacy_classifier;
mod synthesis;
mod transport;
mod validation;

use crate::db;
use crate::embeddings::Embed;
use crate::hnsw::VectorIndex;
use crate::llm::OllamaClient;
use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path;

use self::validation::OnConflict;

/// Re-export of the canonical `OnConflict` enum (formerly `pub(super)`)
/// so external consumers — most notably the HTTP handler at
/// `src/handlers/create.rs` — can route through the single
/// `OnConflict::parse` SSOT instead of carrying duplicated string
/// allowlist matches. Multi-agent sweep ref: scanner B finding F-B3.x.
pub use self::validation::OnConflict as OnConflictMode;

// --- D1.3 (#984): per-tool McpTool impl for `memory_store` ---

/// v0.7.0 #972 D1.3 (#984) — request body for `memory_store`.
/// Schemars-derived schema replaces the hand-coded entry in
/// [`crate::mcp::registry::tool_definitions`] (D1.6 (#987) collapses
/// the macro). Every doc-comment description is byte-equal to the
/// legacy `description` text — see the d1_3_984_tests parity contract
/// at the bottom of this file.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct StoreRequest {
    /// Short title
    pub title: String,

    /// Memory content
    pub content: String,

    #[serde(default)]
    pub tier: Option<String>,

    /// Namespace
    #[serde(default)]
    pub namespace: Option<String>,

    #[serde(default)]
    pub tags: Option<Vec<String>>,

    #[serde(default)]
    pub priority: Option<i64>,

    #[serde(default)]
    pub confidence: Option<f64>,

    #[serde(default)]
    pub source: Option<String>,

    /// JSON metadata
    ///
    /// **#1009 fix:** typed as `Map<String, Value>` rather than the
    /// permissive `Value` so the schemars derive emits
    /// `"type": "object"` on the wire (the pinned #859/#912/F15
    /// discovery contract). Behavior change: callers must now send a
    /// JSON object for `metadata`; scalars/arrays/nulls were never the
    /// documented shape, so this aligns the implementation with the
    /// existing contract.
    #[serde(default)]
    pub metadata: Option<serde_json::Map<String, Value>>,

    /// NHI agent_id; synthesized if omitted.
    #[serde(default)]
    pub agent_id: Option<String>,

    /// Task 1.5 visibility. Default private.
    #[serde(default)]
    pub scope: Option<String>,

    /// P2/G6 (title,ns) collision: error=v2 default; merge=v1; version='(N)'.
    #[serde(default)]
    pub on_conflict: Option<String>,

    /// Form 6 (#759) memory-kind. Default observation.
    #[serde(default)]
    pub kind: Option<String>,

    #[serde(default)]
    #[schemars(description = "#519 bypass proactive contradiction detection.")]
    pub force: Option<bool>,

    #[serde(default)]
    #[schemars(description = "#885 Source URI (doc:/uri:/file:); indexed for #889.")]
    pub source_uri: Option<String>,

    /// #626 Layer-3 (C7) — detached Ed25519 agent-attestation signature,
    /// standard base64, over the `SignableWrite` envelope
    /// (agent_id+namespace+title+kind+created_at+sha256(content)). When
    /// present, `created_at` MUST also be supplied (the signer cannot
    /// predict the server clock). A signature that fails to verify against
    /// the agent's bound public key is always rejected.
    #[serde(default)]
    #[schemars(
        description = "#626 Ed25519 attestation signature (std base64); pair with created_at."
    )]
    pub signature: Option<String>,

    /// #626 Layer-3 (C7) — RFC3339 timestamp the caller signed. Required
    /// when `signature` is present; the server validates it against a
    /// ±300s freshness window and then adopts it verbatim so the verifier
    /// re-derives the identical signed envelope.
    #[serde(default)]
    #[schemars(
        description = "#626 RFC3339 created_at the caller signed (required with signature)."
    )]
    pub created_at: Option<String>,
}

/// v0.7.0 #972 D1.3 (#984) — `McpTool` impl for `memory_store`.
#[allow(dead_code)]
pub struct StoreTool;

impl McpTool for StoreTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_STORE
    }
    fn description() -> &'static str {
        "Store a memory; deduplicates by title+namespace."
    }
    fn docs() -> &'static str {
        "Store a memory. Dedupes by (title, namespace). Tier defaults to mid (7d TTL); long is permanent. on_conflict: error|merge|version. scope: Task 1.5 visibility. force (#519): bypass proactive contradiction detection on near-duplicate writes."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(StoreRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "core"
    }
}

#[cfg(test)]
mod d1_3_984_tests {
    //! D1.3 (#984) — schema parity for the `memory_store` tool.
    //! Reuses the allowed-diffs catalog documented in d1_2_983_tests.
    use super::*;

    fn legacy_props(tool_name: &str) -> serde_json::Map<String, Value> {
        let defs = crate::mcp::registry::tool_definitions();
        let tools = defs
            .get("tools")
            .and_then(Value::as_array)
            .expect("tool_definitions emits `tools` array");
        let entry = tools
            .iter()
            .find(|t| t.get("name").and_then(Value::as_str) == Some(tool_name))
            .unwrap_or_else(|| panic!("{tool_name} must be in legacy catalog"));
        entry
            .pointer("/inputSchema/properties")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{tool_name}.inputSchema.properties must be object"))
            .clone()
    }

    fn derived_props_for<T: schemars::JsonSchema>() -> serde_json::Map<String, Value> {
        let schema = schemars::schema_for!(T);
        let v = serde_json::to_value(schema).expect("schema → value");
        v.get("properties")
            .and_then(Value::as_object)
            .or_else(|| {
                v.pointer(&format!(
                    "/definitions/{}/properties",
                    std::any::type_name::<T>().rsplit("::").next().unwrap_or("")
                ))
                .and_then(Value::as_object)
            })
            .cloned()
            .expect("schemars schema must have properties at a known path")
    }

    fn assert_property_set_parity(tool_name: &str, derived: &serde_json::Map<String, Value>) {
        let legacy = legacy_props(tool_name);
        let legacy_keys: std::collections::BTreeSet<&str> =
            legacy.keys().map(String::as_str).collect();
        let derived_keys: std::collections::BTreeSet<&str> =
            derived.keys().map(String::as_str).collect();
        assert_eq!(
            legacy_keys,
            derived_keys,
            "{tool_name}: property set drift; diff = {:?}",
            legacy_keys
                .symmetric_difference(&derived_keys)
                .collect::<Vec<_>>()
        );
    }

    fn assert_descriptions_match(tool_name: &str, derived: &serde_json::Map<String, Value>) {
        let legacy = legacy_props(tool_name);
        for (name, legacy_prop) in &legacy {
            if let Some(want) = legacy_prop.get("description").and_then(Value::as_str) {
                let got = derived
                    .get(name)
                    .and_then(|p| p.get("description"))
                    .and_then(Value::as_str);
                assert_eq!(
                    got,
                    Some(want),
                    "{tool_name}.{name}: description must match legacy byte-for-byte"
                );
            }
        }
    }

    #[test]
    fn store_parity_984() {
        let derived = derived_props_for::<StoreRequest>();
        assert_property_set_parity("memory_store", &derived);
        assert_descriptions_match("memory_store", &derived);
    }

    #[test]
    fn store_tool_metadata_984() {
        assert_eq!(StoreTool::name(), "memory_store");
        assert_eq!(StoreTool::family(), "core");
    }
}

// --- Tool handlers ---

/// Minimum content length (bytes) before the post-store autonomy hook
/// will invoke LLM `auto_tag` / `detect_contradiction`. Below this the
/// LLM round-trip cost exceeds the informational payoff. Shared
/// across the per-stage sub-modules.
pub(super) const AUTONOMY_MIN_CONTENT_LEN: usize = 50;

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_store(
    conn: &rusqlite::Connection,
    db_path: &Path,
    params: &Value,
    embedder: Option<&dyn Embed>,
    llm: Option<&OllamaClient>,
    vector_index: Option<&VectorIndex>,
    resolved_ttl: &crate::config::ResolvedTtl,
    autonomous_hooks: bool,
    mcp_client: Option<&str>,
    federation_forward_url: Option<&str>,
    // Issue #1239 — synthesis Update / Delete verdicts now emit a
    // `supersedes` link new → target via `db::create_link_signed`. The
    // active daemon keypair (when configured) signs the link so the
    // edge lands with `attest_level='self_signed'` — matching the
    // legacy supersede path through `update_with_archive_on_supersede`.
    active_keypair: Option<&crate::identity::keypair::AgentKeypair>,
) -> Result<Value, String> {
    // v0.7.0 (issue #318) — when operators have configured a federation
    // forward URL, every MCP write routes through the local HTTP daemon
    // so its `broadcast_store_quorum` fanout runs. Direct-SQLite path
    // below is the legacy single-node behaviour, preserved as default
    // for environments without a sibling `ai-memory serve` process.
    if let Some(url) = federation_forward_url {
        return transport::forward_store_to_http(url, params, mcp_client);
    }

    // #881 — input parse + validation + Memory construction extracted
    // to `super::validation::parse_and_build_memory`. Returns the
    // fully-built Memory plus the resolved `OnConflict`, `agent_id`,
    // and `explicit_scope` ready for the governance gate.
    let (mut mem, on_conflict, agent_id, explicit_scope) =
        validation::parse_and_build_memory(params, mcp_client, resolved_ttl, conn)?;

    // v0.7.x Form 6 — substrate-side auto-classify pre_store hook.
    // Consults the namespace `auto_classify_kind` policy (None ⇒ Off).
    // Caller-supplied non-default kind always wins (preserved inside
    // the hook), so this is a no-op when the caller passed an explicit
    // `kind`. The regex pass is allocation-light and runs in tens of
    // microseconds; the optional LLM round-trip is opt-in via the
    // `RegexThenLlm` policy.
    // #880 — `auto_classify_kind` lives on `policy.kind_class` after
    // the governance decomposition.
    let auto_classify_policy = db::resolve_governance_policy(conn, &mem.namespace)
        .and_then(|p| p.kind_class.auto_classify_kind);
    crate::hooks::pre_store::maybe_auto_classify(&mut mem, auto_classify_policy);

    // #626 Layer-3 (C7) — agent-attestation gate on the MCP store path.
    // A remote caller signs the `SignableWrite` envelope
    // (agent_id+namespace+title+kind+created_at+sha256(content)) and
    // presents the detached Ed25519 signature (standard base64) plus the
    // `created_at` it signed. Because the signed surface commits to
    // `created_at` — which the server normally stamps with `now()` — the
    // remote signer must supply the timestamp it used; the server validates
    // it against a bounded freshness window (replay / post-dating guard)
    // and then adopts it verbatim so the verifier re-derives the identical
    // envelope. With no signature the path is byte-equal to the legacy
    // build unless the operator set `AI_MEMORY_REQUIRE_AGENT_ATTESTATION`,
    // in which case the unsigned write is rejected by the gate.
    {
        let presented_sig = params["signature"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(sig_b64) = presented_sig {
            let (sig_bytes, signed_created_at) = crate::identity::attest::prepare_signed_store(
                sig_b64,
                params["created_at"].as_str(),
            )?;
            // Adopt the signed timestamp verbatim so the verifier rebuilds
            // the identical envelope. `created_at` is the only signed time
            // field; `updated_at` stays at the server's persist time.
            mem.created_at = signed_created_at.to_string();
            crate::identity::attest::stamp_attestation_sync(
                conn,
                &mut mem,
                &agent_id,
                Some(&sig_bytes),
            )
            .map_err(|e| e.to_string())?;
        } else if crate::identity::attest::require_agent_attestation_enabled() {
            crate::identity::attest::stamp_attestation_sync(conn, &mut mem, &agent_id, None)
                .map_err(|e| e.to_string())?;
        }
    }

    // #969 — single `to_value(&mem)` shared across the K9 permission
    // gate and the K3 governance gate below. Pre-fix the two scoped
    // blocks each called `to_value(&mem).unwrap_or_default()` against
    // the same (read-only between gates) `mem`. Hoisting saves one
    // clone+serialise per `memory_store` invocation on the hot path.
    let mem_payload = serde_json::to_value(&mem).unwrap_or_default();

    // v0.7.0 K9 — unified permission pipeline. The K9 evaluator
    // composes declarative `[permissions.rules]` matchers + the K3
    // `[permissions].mode` knob + (when wired) hook decisions into
    // a single `Decision`. Deny-first: if a rule denies, we
    // short-circuit before the K3 governance gate ever resolves a
    // policy. Allow falls through to the existing K3 / governance
    // gate so legacy `[governance]` policies continue to work.
    {
        use crate::permissions::{Op, PermissionContext, Permissions};
        let ctx = PermissionContext {
            op: Op::MemoryStore,
            namespace: mem.namespace.clone(),
            agent_id: agent_id.clone(),
            payload: mem_payload.clone(),
        };
        match Permissions::evaluate(&ctx, &[]) {
            crate::permissions::Decision::Allow | crate::permissions::Decision::Modify(_) => {}
            crate::permissions::Decision::Deny(reason) => {
                return Err(crate::governance::deny_message(
                    "store",
                    crate::governance::DenyGate::PermissionRule,
                    &reason,
                ));
            }
            crate::permissions::Decision::Ask(prompt) => {
                return Ok(json!({
                    "status": "ask",
                    "reason": prompt,
                    "action": "store",
                    "namespace": mem.namespace,
                }));
            }
        }
    }

    // Task 1.9: governance enforcement (store-side).
    {
        use crate::models::{GovernanceDecision, GovernedAction};
        match db::enforce_governance(
            conn,
            GovernedAction::Store,
            &mem.namespace,
            &agent_id,
            None,
            None,
            &mem_payload,
        )
        .map_err(|e| e.to_string())?
        {
            GovernanceDecision::Allow => {}
            GovernanceDecision::Deny(refusal) => {
                return Err(crate::governance::deny_message(
                    "store",
                    crate::governance::DenyGate::Governance,
                    &refusal.reason,
                ));
            }
            GovernanceDecision::Pending(pending_id) => {
                // v0.7.0 K4 — surface the new pending row through the
                // subscription dispatcher so K10's Approval API sees a
                // uniform stream of `approval_requested` events
                // regardless of which transport (MCP / HTTP) created
                // the row. Best-effort, fire-and-forget: a dispatch
                // failure must not roll back the pending row.
                crate::subscriptions::dispatch_approval_requested(conn, &pending_id, db_path);
                return Ok(json!({
                    "status": "pending",
                    "pending_id": pending_id,
                    "reason": "governance requires approval",
                    "action": "store",
                    "namespace": mem.namespace,
                }));
            }
        }
    }

    // True dedup: check for exact title+namespace match (#97).
    //
    // v0.6.3.1 P2 (G6) — only the Merge policy enters the dedup-then-update
    // branch. `Error` mode already short-circuited above; `Version` mode
    // already rewrote the title to a free suffix so an exact dup cannot
    // exist. The candidate pool feeds both the Form 1 synthesis curator
    // (`run_synthesis_pass`) and the wire-side `potential_contradictions`
    // echo. #1337 — the synthesis curator path uses
    // `find_synthesis_candidates` (Stage-1 FTS5 recall only) so the LLM
    // sees legitimately-similar memories whose titles share only one
    // strong content token (e.g. `"kubernetes deployment notes"` vs
    // `"kubernetes rolling deploy strategy"`, Jaccard 1/6 ≈ 0.167). The
    // wire-output `contradiction_ids` then applies the #1320 Jaccard
    // floor below to keep stopword-only overlaps off the wire.
    let existing =
        db::find_synthesis_candidates(conn, &mem.title, &mem.namespace).unwrap_or_default();

    // v0.7.x Form 1 (#754) — Resolve namespace policy ONCE up-front so
    // both the synthesis path (Form 1) and the synchronous-atomise mode
    // (Form 2) share a single resolution. Falls back to defaults when
    // no namespace standard is configured.
    let ns_policy = db::resolve_governance_policy(conn, &mem.namespace).unwrap_or_default();

    // v0.7.x Form 1 — single batch action-emitting synthesis call
    // BEFORE the SQL write. Gated on: autonomous_hooks + LLM wired +
    // content meets threshold + namespace not internal + the namespace
    // policy has NOT opted in to the legacy per-pair classifier.
    //
    // On success the synthesis verdict drives the per-candidate
    // {add, update, delete, no_op} branch. `update` SKIPs the new-row
    // insert (the merge subsumed the incoming fact). `delete` removes
    // the candidate then proceeds with the standard insert. `add` /
    // `no_op` are pass-throughs to the existing path.
    //
    // v0.7.0 Cluster-B (issue #767):
    //
    // * SEC-1 — every delete verdict is re-checked against K9
    //   `MemoryDelete` BEFORE the row is touched. K9-denied candidates
    //   are dropped from the delete list, never silently applied.
    // * SEC-1 — the per-batch delete count is capped at the namespace's
    //   `synthesis_max_deletes_per_call` (default 1). Over-cap
    //   batches refuse with `synthesis.refused_unbounded_delete`.
    // * COR-5 — every `update` verdict is honoured (not just the
    //   first). A WARN logs when >1 update verbs appear; the
    //   per-batch tally feeds telemetry.
    // * COR-6 — failure surfaces in the response envelope as
    //   `synthesis_failed: true` + reason. The `synthesis_failure_mode`
    //   namespace policy controls whether failure falls through to the
    //   legacy path (default, backward-compatible) or refuses the
    //   write outright.
    // * PERF-7 — per-candidate content is truncated to the namespace's
    //   `synthesis_max_candidate_chars` (default 1500) before being
    //   inlined into the LLM prompt.
    // #881 — Form 1 synthesis pass extracted to `super::synthesis`.
    // Returns the per-candidate update/delete queue + the counts the
    // response envelope echoes back. SEC-1 / COR-5 / COR-6 contracts
    // are encapsulated inside the helper.
    // Issue #1240 — synthesis-pass cycle-depth guard. Acquire the
    // per-thread depth guard BEFORE invoking `run_synthesis_pass`; if
    // the post-increment depth exceeds `MAX_SYNTHESIS_DEPTH` we refuse
    // with `SYNTHESIS_DEPTH_EXCEEDED`. The guard is held across the
    // synthesis-pass body so any post-store hooks that chain-fire a
    // nested `memory_store` observe the higher depth and either stay
    // within budget or refuse on entry.
    //
    // The guard is bound to `_synthesis_depth_guard` even when the
    // pass is skipped so an `_` binding doesn't accidentally drop the
    // guard early on the eligible branch (Rust drops `let _ = ...`
    // bindings at the end of the statement, but
    // `let _name = ...` retains the binding for the rest of the
    // function — we want the latter).
    let (_synthesis_depth, _synthesis_depth_guard) = crate::synthesis::enter_synthesis_pass();
    let synthesis_outcome = if synthesis::synthesis_eligible(
        autonomous_hooks,
        llm.is_some(),
        mem.content.len(),
        &mem.namespace,
        &ns_policy,
    ) {
        if _synthesis_depth > crate::synthesis::MAX_SYNTHESIS_DEPTH {
            tracing::warn!(
                target: "synthesis",
                namespace = %mem.namespace,
                attempted = _synthesis_depth,
                cap = crate::synthesis::MAX_SYNTHESIS_DEPTH,
                "synthesis.depth_exceeded",
            );
            return Err(format!(
                "SYNTHESIS_DEPTH_EXCEEDED: synthesis depth {} would exceed compiled \
                 max_synthesis_depth {} (namespace='{}')",
                _synthesis_depth,
                crate::synthesis::MAX_SYNTHESIS_DEPTH,
                mem.namespace,
            ));
        }
        let llm_client = llm.expect("synthesis_eligible guarantees llm.is_some()");
        synthesis::run_synthesis_pass(llm_client, &mem, &agent_id, &existing, &ns_policy)?
    } else {
        synthesis::SynthesisOutcome::empty()
    };

    // v0.7.x Form 1 — verdict honouring: when the synthesiser elected
    // to UPDATE existing candidates, apply each merge in place.
    //
    // v0.7.0 Cluster-B (COR-5) — HONOUR ALL updates. The first update
    // we apply is the "primary" — the one that subsumes the incoming
    // fact and skips the new-row insert (the response carries that
    // candidate's id back to the caller). Subsequent updates are still
    // applied so the curator's merges actually land in the substrate
    // instead of being silently dropped. A WARN log fired upstream
    // recorded the multi-update case.
    // #881 — verdict honouring extracted to `super::synthesis`. When
    // the synthesiser elected an UPDATE, the helper applies every
    // queued merge + delete and returns the echo response (the new
    // row insert is then skipped — the merge subsumed the incoming
    // fact).
    if let Some(resp) = synthesis::apply_synthesis_updates_and_deletes(
        conn,
        &mem,
        &existing,
        embedder,
        vector_index,
        &synthesis_outcome,
        active_keypair,
    ) {
        return Ok(resp);
    }
    // When no update fired, capture the list of to-be-deleted
    // candidate ids. Per issue #1239, we delete them AFTER the
    // standard insert below + link emit so the supersedes link from
    // the new memory → each deleted candidate has both endpoints
    // alive at FK-check time. When the synthesis verdict carried no
    // deletes, this is a zero-cost empty list.
    let pending_synthesis_delete_targets =
        synthesis::pending_synthesis_delete_targets(&synthesis_outcome);

    let exact_dup = if matches!(on_conflict, OnConflict::Merge) {
        existing
            .iter()
            .find(|c| c.title == mem.title && c.namespace == mem.namespace)
    } else {
        None
    };
    if let Some(dup) = exact_dup {
        // Update existing memory instead of creating a duplicate.
        // Preserve the original agent_id (provenance is immutable) — the
        // existing memory's metadata.agent_id wins over anything in the
        // incoming store.
        let preserved_metadata = crate::identity::preserve_agent_id(&dup.metadata, &mem.metadata);
        let (_found, content_changed) = db::update(
            conn,
            &dup.id,
            None,                       // title (unchanged)
            Some(mem.content.as_str()), // content (update)
            Some(&mem.tier),            // tier
            None,                       // namespace (unchanged)
            Some(&mem.tags),            // tags
            Some(mem.priority),         // priority
            Some(mem.confidence),       // confidence
            None,                       // expires_at
            Some(&preserved_metadata),  // metadata (agent_id preserved)
        )
        .map_err(|e| e.to_string())?;
        // Regenerate embedding if content changed during dedup update
        if content_changed && let Some(emb) = embedder {
            let text = format!("{} {}", mem.title, mem.content);
            if let Ok(embedding) = emb.embed(&text) {
                let _ = db::set_embedding(conn, &dup.id, &embedding);
                if let Some(idx) = vector_index {
                    idx.remove(&dup.id);
                    idx.insert(dup.id.clone(), embedding);
                }
            }
        }
        // #196: echo the preserved agent_id (original on dedup, not the caller's)
        let echoed_agent_id = preserved_metadata
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        return Ok(json!({
            "id": dup.id,
            "tier": mem.tier,
            "title": mem.title,
            "namespace": mem.namespace,
            "agent_id": echoed_agent_id,
            "duplicate": true,
            "action": "updated existing memory"
        }));
    }

    // v0.7.0 (issue #519) — proactive contradiction detection. When
    // an embedder is wired AND the caller did NOT pass `force=true`,
    // scan the top-K most similar live memories in the namespace and
    // refuse the write if any near-duplicate (≥ 0.95 cosine) has a
    // differing content body (deterministic substrate-layer
    // contradiction signal — see `db::proactive_conflict_check`).
    //
    // Bypass with `force=true` for callers that explicitly want the
    // conflicting fact to land alongside the existing one (e.g. a
    // curator pass that intends to revise an earlier claim).
    let force_write = params["force"].as_bool().unwrap_or(false);
    if !force_write && let Some(emb) = embedder {
        let text = format!("{} {}", mem.title, mem.content);
        if let Ok(query_embedding) = emb.embed(&text)
            && let Ok(Some(conflict)) = db::proactive_conflict_check(conn, &mem, &query_embedding)
        {
            tracing::info!(
                target: "memory_store",
                namespace = %mem.namespace,
                existing_id = %conflict.existing_id,
                similarity = conflict.similarity,
                reason = conflict.reason,
                "memory_store refused by proactive conflict detection (#519); \
                 pass force=true to override",
            );
            return Err(format!(
                "CONFLICT: memory near-duplicates an existing memory in namespace \
                 '{}' (existing id: {}, title: '{}', similarity: {:.3}, reason: {}). \
                 Pass force=true to insert anyway.",
                mem.namespace,
                conflict.existing_id,
                conflict.existing_title,
                conflict.similarity,
                conflict.reason,
            ));
        }
    }

    // v0.7 K8 — per-agent quota gate. Pre-write check; on exceeded
    // limit returns a `QUOTA_EXCEEDED` diagnostic naming the limit
    // hit. Bytes counted = (title + content + serialized metadata)
    // to match the post-write `record_op` accounting below.
    let payload_bytes = i64::try_from(
        mem.title.len()
            + mem.content.len()
            + serde_json::to_string(&mem.metadata)
                .map(|s| s.len())
                .unwrap_or(0),
    )
    .unwrap_or(i64::MAX);
    // H12 (#628 blocker): combine the quota check + counter
    // increment in a single atomic transaction so concurrent writers
    // cannot each pass the check and then both bump the counter past
    // the cap.
    // v0.7.0 #1156 — charge against the per-namespace accounting row
    // (the v50 PK extension). Per-namespace allotments hold even when
    // a single agent writes across many namespaces.
    if let Err(e) = crate::quotas::check_and_record(
        conn,
        &agent_id,
        &mem.namespace,
        crate::quotas::QuotaOp::Memory {
            bytes: payload_bytes,
        },
    ) {
        return Err(e.to_string());
    }

    let actual_id = match db::insert(conn, &mem) {
        Ok(id) => id,
        Err(e) => {
            // Insert failed AFTER we committed quota — refund so the
            // counter reflects only successful stores. Refund lands on
            // the same `(agent_id, namespace)` row the check_and_record
            // above incremented (v50, #1156).
            if let Err(re) = crate::quotas::refund_op(
                conn,
                &agent_id,
                &mem.namespace,
                crate::quotas::QuotaOp::Memory {
                    bytes: payload_bytes,
                },
            ) {
                tracing::warn!("quota refund_op failed for agent {}: {}", &agent_id, re);
            }
            // v0.7.0 L1-6 Deliverable E — surface the substrate
            // governance pre-write hook's refusal with a clearly-
            // identifiable wire prefix so MCP clients can distinguish
            // a policy refusal from a database error. The
            // `GOVERNANCE_REFUSED:` prefix mirrors the HTTP layer's
            // `code` field; the operator-authored reason follows
            // verbatim. Refusals on the MCP path are NOT logged at
            // ERROR (it's the documented policy outcome, not a fault).
            if let Some(refusal) = e.downcast_ref::<crate::storage::GovernanceRefusal>() {
                tracing::info!(
                    "mcp store refused by substrate governance: {}",
                    refusal.reason
                );
                return Err(format!("GOVERNANCE_REFUSED: {}", refusal.reason));
            }
            return Err(e.to_string());
        }
    };

    // Issue #1239 — synthesis Delete + reinsert path: now that the
    // new memory has been inserted, emit a `supersedes` link from it
    // to each Delete-verdict candidate BEFORE deleting the candidate
    // (the FK gate requires both endpoints alive at link-insert
    // time). Best-effort: per-candidate failures warn-log and the
    // standard insert is not rolled back.
    synthesis::apply_pending_synthesis_deletes_with_links(
        conn,
        &actual_id,
        &pending_synthesis_delete_targets,
        active_keypair,
    );

    // PR-5 (issue #487): security audit trail. No-op when disabled.
    crate::audit::emit(crate::audit::EventBuilder::new(
        crate::audit::AuditAction::Store,
        crate::audit::actor(
            agent_id.clone(),
            mcp_client.map_or("host_fallback", |_| "mcp_client_info"),
            explicit_scope.clone(),
        ),
        crate::audit::target_memory(
            actual_id.clone(),
            mem.namespace.clone(),
            Some(mem.title.clone()),
            Some(mem.tier.to_string()),
            explicit_scope.clone(),
        ),
    ));

    // Exclude self-ID from contradictions (both proposed and actual, since upsert may reuse existing ID)
    //
    // #1320 wire-output discipline: re-fetch the Stage-1+Stage-2
    // filtered pool via `find_contradictions` so the wire
    // `potential_contradictions` echo applies the Jaccard floor on
    // stopword-stripped title tokens (rejects pure-stopword overlaps
    // that would otherwise leak through the broader synthesis pool
    // used above for the curator). On storage error the wire field is
    // omitted rather than silently echoing the un-filtered pool — the
    // synthesis path's verdicts still applied; only the wire-side
    // contradictions hint is suppressed.
    let filtered_contradictions =
        db::find_contradictions(conn, &mem.title, &mem.namespace).unwrap_or_default();
    let contradiction_ids: Vec<String> = filtered_contradictions
        .iter()
        .filter(|c| c.id != mem.id && c.id != actual_id)
        .map(|c| c.id.clone())
        .collect();

    // v0.7.x Form 2 (#755) — resolve atomisation execution mode. When
    // policy is `Synchronous`, SKIP source embedding (atoms get their
    // own embed-on-insert path); the synchronous atomise pass runs
    // BELOW after the post-store autonomy hooks. `Deferred` (legacy
    // WT-1-D) and `Off` modes keep the source-embed step.
    let atomise_mode = ns_policy.effective_auto_atomise_mode();
    // #881 — embed pipeline extracted to `super::embed`.
    if !embed::skip_source_embed_for_synchronous_atomise(atomise_mode, mem.content.len())
        && let Some(emb) = embedder
    {
        embed::store_source_embedding(conn, emb, &mem, &actual_id, vector_index);
    }

    // v0.6.0.0 post-store autonomy hooks. When enabled via
    // `AI_MEMORY_AUTONOMOUS_HOOKS=1` or `autonomous_hooks = true` in
    // config.toml AND an LLM is wired AND the content is long enough
    // to be meaningfully taggable, fire `auto_tag` + `detect_contradiction`
    // synchronously and persist the results into the memory's metadata.
    // Best-effort: any LLM error is logged and does not fail the store.
    // Skipped for internal/system namespaces to avoid feedback loops.
    //
    // #881 — extracted to `super::legacy_classifier`.
    let hooks_skipped_reason = legacy_classifier::autonomy_skip_reason(
        autonomous_hooks,
        llm.is_some(),
        mem.content.len(),
        &mem.namespace,
    );
    let autonomy_outcome = if hooks_skipped_reason.is_none()
        && let Some(llm_client) = llm
    {
        legacy_classifier::maybe_run_autonomy_hooks(
            conn, llm_client, &mem, &actual_id, &existing, &ns_policy,
        )
    } else {
        legacy_classifier::AutonomyHookOutcome {
            auto_tags: Vec::new(),
            confirmed_contradictions: Vec::new(),
        }
    };

    // v0.6.0.0: fire webhook subscribers on successful store. Best-effort
    // fire-and-forget — each subscriber gets its own OS thread; the
    // response here does not wait on any webhook dispatch.
    crate::subscriptions::dispatch_event(
        conn,
        crate::mcp::registry::tool_names::MEMORY_STORE,
        &actual_id,
        &mem.namespace,
        Some(&agent_id),
        db_path,
    );

    // v0.7.0 WT-1-D — auto-atomisation pre_store substrate hook. The
    // call resolves the namespace policy, token-counts the body, and
    // spawns a detached worker thread when the threshold is exceeded.
    // NEVER blocks the response on the `Deferred` path.
    //
    // v0.7.x Form 2 (#755) — the `Synchronous` mode runs the atomiser
    // INSIDE this handler so atoms surface in recall before the
    // response returns. Source embedding was skipped above; the
    // atomiser archives the parent with `atomised_into > 0` BEFORE
    // the response returns.
    //
    // Refused-store path: this hook is unreachable on a Deny because
    // the governance gate above already short-circuited via Err(...)
    // before we reached `db::insert`. The store-side governance refusal
    // ensures a denied write never feeds the curator.
    let mut atomise_outcome: Option<&'static str> = None;
    {
        // Cluster-F PERF-10 — pass the in-flight Memory by reference
        // along with the resolved `actual_id` (which may differ from
        // `mem.id` under merge-mode upserts). Avoids cloning the
        // multi-KB content / tags / metadata blob just to swap the id.
        match atomise_mode {
            crate::models::AutoAtomiseMode::Synchronous => {
                // Form 2 — synchronous atomise-before-the-response.
                atomise_outcome = Some(crate::hooks::pre_store::run_synchronous_auto_atomise(
                    conn, &mem, &actual_id, &agent_id,
                ));
            }
            crate::models::AutoAtomiseMode::Deferred => {
                // Cluster-F PERF-1 — reuse the caller's connection
                // for policy resolution; the worker thread spawns
                // inside the hook still opens its own connection.
                let _outcome = crate::hooks::pre_store::maybe_enqueue_auto_atomise(
                    conn, &mem, &actual_id, &agent_id,
                );
                // Outcome is for telemetry only; the response shape
                // does NOT surface it (the curator pass is
                // fire-and-forget by design).
            }
            crate::models::AutoAtomiseMode::Off => {
                // Substrate stays quiet for this namespace.
            }
        }
    }

    // #196: echo the resolved agent_id
    let mut response = json!({
        "id": actual_id,
        "tier": mem.tier,
        "title": mem.title,
        "namespace": mem.namespace,
        "agent_id": agent_id,
    });
    if !contradiction_ids.is_empty() {
        response["potential_contradictions"] = json!(contradiction_ids);
    }
    // #881 — autonomy-hook echo extracted to `super::legacy_classifier`.
    legacy_classifier::merge_autonomy_outcome_into_response(&mut response, &autonomy_outcome);
    if let Some(reason) = hooks_skipped_reason
        && autonomous_hooks
    {
        response["autonomy_hook_skipped"] = json!(reason);
    }
    if let Some(counts) = &synthesis_outcome.counts {
        response["synthesis_decisions"] = counts.to_json();
    }
    if let Some(reason) = &synthesis_outcome.failed_reason {
        // v0.7.0 Cluster-B (COR-6) — surface curator failure to the
        // caller. The namespace policy chose to fall through, but the
        // caller still observes that the new write did not benefit
        // from the synthesis pass.
        response["synthesis_failed"] = json!(true);
        response["synthesis_failed_reason"] = json!(reason);
    }
    if let Some(outcome) = atomise_outcome {
        response["atomise_mode"] = json!("synchronous");
        response["atomise_outcome"] = json!(outcome);
    }

    // v0.7.0 Gap 3 (#886) — recall-consumption hook.
    //
    // When the request body cites a prior `recall_id` plus a list
    // of `cited_memory_ids` the caller used to compose this store
    // request, flip the matching `recall_observations` rows to
    // `consumed = TRUE` with `consumed_by_memory_id = actual_id`.
    // Best-effort; a substrate error here does NOT roll back the
    // store (audit-trail discipline: never let the ledger block
    // the underlying write).
    crate::observations::try_mark_consumed_from_params(conn, params, &actual_id);

    Ok(response)
}

// #881 — `handle_store` test scaffold extracted to the sibling
// `tests.rs` file so this module stays focused on production-path
// orchestration. Tests still resolve `super::*` (this module's
// public + private surface) since they live in a child mod.
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
