// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.x Form 1 synthesis batch-action dispatch + verdict honouring.
//!
//! #881 (PR-4 extraction): split out of the monolithic
//! `src/mcp/tools/store.rs` so the synthesis curator branch lives in
//! its own ~250-LOC module. Wire-compat preserved verbatim: every
//! tracing label, error string, and SynthesisCounts shape matches the
//! pre-#881 inline code path.
//!
//! The synthesis pass runs at `memory_store` time when:
//!
//! * `autonomous_hooks = true`
//! * an LLM client is wired
//! * content meets the [`AUTONOMY_MIN_CONTENT_LEN`] threshold
//! * namespace is not internal (`_*`)
//! * the namespace policy has NOT opted in to the legacy per-pair
//!   classifier (`legacy_per_pair_classifier`)
//!
//! On success, the curator returns a single batch of per-candidate
//! verdicts (`add`/`update`/`delete`/`no_op`). The store handler
//! consumes the verdicts in two phases:
//!
//! 1. [`apply_synthesis_updates_and_deletes`] (this module) applies
//!    every update + delete the verdict elected and returns the
//!    primary-update echo response when one exists. The store
//!    handler short-circuits on a non-`None` return.
//! 2. The remaining `add` / `no_op` verdicts fall through to the
//!    standard `db::insert` path in `mod.rs`.

use serde_json::{Value, json};

use crate::identity::keypair::AgentKeypair;
use crate::llm::OllamaClient;
use crate::mcp::param_names;
use crate::models::{GovernancePolicy, Memory, MemoryLinkRelation};
use crate::{db, hnsw::VectorSearchIndex};

use super::AUTONOMY_MIN_CONTENT_LEN;

/// #3173 — `allow_inbox` for every synthesis-plane ownership check.
///
/// STRICTER than the `memory_delete` gate (`allow_inbox = true`) and equal to
/// the `memory_update` / `memory_promote` gates: a synthesis verdict is an
/// AUTONOMOUS mutation the caller never named, so an inbox RECIPIENT — who
/// never asked for that row to be merged away or hard-deleted — must not be
/// treated as an owner here.
const SYNTHESIS_ALLOW_INBOX: bool = false;

/// #3173 — the single ownership predicate every synthesis-plane mutate site
/// applies. Thin, named wrapper over the canonical #1786
/// [`crate::visibility::caller_owns_for_mutation`] so the pool filter in
/// `mod.rs` and the per-site re-checks below can never drift apart.
#[must_use]
pub(super) fn caller_may_mutate(mem: &Memory, caller: &str) -> bool {
    crate::visibility::caller_owns_for_mutation(mem, caller, SYNTHESIS_ALLOW_INBOX)
}

/// #3173 — emit the security audit row for a REFUSED cross-owner synthesis
/// mutation. `AuditOutcome::Deny`, so a SIEM sees the attempt rather than the
/// pre-#3173 silent success.
pub(super) fn audit_mutation_refusal(
    action: crate::audit::AuditAction,
    mem: &Memory,
    caller: &str,
) {
    tracing::warn!(
        target: "synthesis",
        namespace = %mem.namespace,
        candidate_id = %mem.id,
        caller = %caller,
        "synthesis.refused_cross_owner_mutation",
    );
    crate::audit::emit(
        crate::audit::EventBuilder::new(
            action,
            crate::audit::actor(
                caller.to_string(),
                crate::audit::synthesis_sources::HOST_FALLBACK,
                None,
            ),
            crate::audit::target_memory(
                mem.id.clone(),
                mem.namespace.clone(),
                Some(mem.title.clone()),
                Some(mem.tier.to_string()),
                None,
            ),
        )
        .outcome(crate::audit::AuditOutcome::Deny),
    );
}

/// #3173 — REFUSE (never silently skip) when a synthesis verdict names a row
/// the caller may not mutate.
///
/// `candidates` is the already-ownership-filtered pool, so the target must be
/// present in it AND still pass [`caller_may_mutate`]; a target absent from the
/// vetted pool is refused too (it can only come from a pool/verdict mismatch,
/// which is exactly the state a mutate site must not act on). A `None` caller
/// is the single-operator default — trust-all, byte-unchanged.
///
/// # Errors
/// [`crate::errors::msg::CALLER_DOES_NOT_OWN_MEMORY`] when the caller is set
/// and the target is not caller-mutable.
pub(super) fn assert_caller_may_mutate(
    candidates: &[Memory],
    caller: Option<&str>,
    action: crate::audit::AuditAction,
    target_id: &str,
) -> Result<(), String> {
    let Some(caller) = caller else {
        return Ok(());
    };
    match candidates.iter().find(|c| c.id == target_id) {
        Some(row) if caller_may_mutate(row, caller) => Ok(()),
        Some(row) => {
            audit_mutation_refusal(action, row, caller);
            Err(crate::errors::msg::CALLER_DOES_NOT_OWN_MEMORY.into())
        }
        None => {
            tracing::warn!(
                target: "synthesis",
                candidate_id = %target_id,
                caller = %caller,
                "synthesis.refused_unvetted_mutation_target",
            );
            Err(crate::errors::msg::CALLER_DOES_NOT_OWN_MEMORY.into())
        }
    }
}

/// #3173 — [`assert_caller_may_mutate`] over a whole verdict queue, used to
/// vet the deferred delete list BEFORE the standard insert commits.
///
/// # Errors
/// Propagates the first [`assert_caller_may_mutate`] refusal.
pub(super) fn assert_caller_may_mutate_all(
    candidates: &[Memory],
    caller: Option<&str>,
    target_ids: &[String],
) -> Result<(), String> {
    for id in target_ids {
        assert_caller_may_mutate(candidates, caller, crate::audit::AuditAction::Delete, id)?;
    }
    Ok(())
}

/// Outcome of the synthesis pass that the store handler needs to
/// thread through the rest of the write path.
pub(super) struct SynthesisOutcome {
    pub counts: Option<crate::synthesis::SynthesisCounts>,
    pub updates: Vec<(String, String)>,
    pub deletes: Vec<String>,
    /// `Some(reason)` when synthesis fell through (COR-6). The store
    /// handler surfaces this on the response envelope as
    /// `synthesis_failed: true` + `synthesis_failed_reason`.
    pub failed_reason: Option<String>,
}

impl SynthesisOutcome {
    pub(super) fn empty() -> Self {
        Self {
            counts: None,
            updates: Vec::new(),
            deletes: Vec::new(),
            failed_reason: None,
        }
    }
}

/// v0.7.x Form 1 — single batch action-emitting synthesis call.
///
/// Eligibility, K9 re-check on delete verdicts, delete-cap refusal,
/// and failure-mode handling are encapsulated here so the store
/// handler reads the outcome as a single struct.
///
/// # Errors
///
/// Returns `Err(reason)` when:
///
/// * The verdict's delete count exceeds the namespace's
///   `synthesis_max_deletes_per_call` cap (SEC-1 refusal — surfaced
///   as `GOVERNANCE_REFUSED: synthesis batch attempted ...` per the
///   pre-#881 wire shape).
/// * The namespace's `synthesis_failure_mode` is `BlockWrite` and the
///   curator round-trip failed (COR-6 refusal — surfaced as
///   `SYNTHESIS_FAILED: namespace policy 'block_write' refuses ...`
///   per the pre-#881 wire shape).
pub(super) fn run_synthesis_pass(
    llm: &OllamaClient,
    mem: &Memory,
    agent_id: &str,
    existing: &[Memory],
    ns_policy: &GovernancePolicy,
) -> Result<SynthesisOutcome, String> {
    // Cluster-F PERF-14 — borrow the candidates as `&[&Memory]` so
    // the recall hit-set is NOT cloned just to feed the synthesiser.
    let cands: Vec<&Memory> = existing
        .iter()
        .filter(|c| c.id != mem.id && c.title != mem.title)
        .collect();
    if cands.is_empty() {
        return Ok(SynthesisOutcome::empty());
    }

    // PERF-7 — resolve the per-namespace prompt cap once.
    let cap = ns_policy.effective_synthesis_max_candidate_chars();
    match crate::synthesis::synthesise_with_cap(llm, &mem.title, &mem.content, &cands, cap) {
        Ok(resp) => {
            let counts = crate::synthesis::SynthesisCounts::from_response(&resp);
            tracing::info!(
                target: "synthesis",
                namespace = %mem.namespace,
                add = counts.add,
                update = counts.update,
                delete = counts.delete,
                no_op = counts.no_op,
                "synthesis batch decision",
            );

            // SEC-1 — refuse batches whose delete count exceeds the
            // namespace's per-call cap. This is the unbounded-delete
            // refusal point: the curator may not mass-delete without
            // an explicit K10 approval flow. Audit-honest WARN log.
            let delete_cap = ns_policy.effective_synthesis_max_deletes_per_call() as usize;
            if counts.delete > delete_cap {
                tracing::warn!(
                    target: "synthesis",
                    namespace = %mem.namespace,
                    requested = counts.delete,
                    cap = delete_cap,
                    "synthesis.refused_unbounded_delete",
                );
                return Err(format!(
                    "GOVERNANCE_REFUSED: synthesis batch attempted {} \
                     deletes, exceeding namespace cap of {} (K10 approval \
                     required for unbounded-delete; raise \
                     `synthesis_max_deletes_per_call` to opt in per-namespace)",
                    counts.delete, delete_cap
                ));
            }

            // COR-5 — honour ALL update verdicts in sequence. Emit a
            // WARN when more than one update verb appears so operators
            // can spot the case in telemetry.
            if counts.update > 1 {
                tracing::warn!(
                    target: "synthesis",
                    namespace = %mem.namespace,
                    update_count = counts.update,
                    "synthesis_decisions.update_count > 1; honouring all updates in sequence",
                );
            }
            let mut updates: Vec<(String, String)> = Vec::new();
            let mut deletes: Vec<String> = Vec::new();
            for v in &resp.verdicts {
                match v.verb {
                    crate::synthesis::SynthesisVerb::Update => {
                        let merged = v
                            .merged_content
                            .clone()
                            .unwrap_or_else(|| mem.content.clone());
                        updates.push((v.candidate_id.clone(), merged));
                    }
                    crate::synthesis::SynthesisVerb::Delete => {
                        // SEC-1 — re-check K9 per delete verdict. The
                        // curator's verdict is advice; the K9 pipeline
                        // remains authoritative.
                        if k9_allows_synthesis_delete(&mem.namespace, agent_id, &v.candidate_id) {
                            deletes.push(v.candidate_id.clone());
                        }
                    }
                    crate::synthesis::SynthesisVerb::Add
                    | crate::synthesis::SynthesisVerb::NoOp => {}
                }
            }
            Ok(SynthesisOutcome {
                counts: Some(counts),
                updates,
                deletes,
                failed_reason: None,
            })
        }
        Err(e) => {
            let reason = e.to_string();
            // COR-6 — observe the failure on the response envelope so
            // callers don't silently inherit the legacy fall-through
            // path. Then consult the namespace's `synthesis_failure_mode`
            // policy to decide whether to fall through or block.
            tracing::warn!(
                target: "synthesis",
                namespace = %mem.namespace,
                "synthesis call failed: {reason}",
            );
            match ns_policy.effective_synthesis_failure_mode() {
                crate::models::SynthesisFailureMode::BlockWrite => Err(format!(
                    "SYNTHESIS_FAILED: namespace policy `block_write` refuses \
                     the store while the curator is unavailable: {reason}"
                )),
                crate::models::SynthesisFailureMode::FallThrough => Ok(SynthesisOutcome {
                    counts: None,
                    updates: Vec::new(),
                    deletes: Vec::new(),
                    failed_reason: Some(reason),
                }),
            }
        }
    }
}

/// SEC-1 helper — consult the K9 permission pipeline on a synthesis
/// delete verdict. Returns `true` when K9 allows (Allow / Modify);
/// `false` when K9 denies or asks for approval (the synthesis path
/// has no operator UI to surface a prompt). The store handler's
/// audit-honest WARN logs the deny/ask reason verbatim — preserved
/// here so the call sites stay aligned with the pre-#881 trace
/// output.
fn k9_allows_synthesis_delete(namespace: &str, agent_id: &str, candidate_id: &str) -> bool {
    use crate::permissions::{Decision, Op, PermissionContext, Permissions};
    let payload = json!({
        "id": candidate_id,
        "via": "synthesis_verdict",
    });
    let ctx = PermissionContext {
        op: Op::MemoryDelete,
        namespace: namespace.to_string(),
        agent_id: agent_id.to_string(),
        payload,
    };
    match Permissions::evaluate(&ctx, &[]) {
        Decision::Allow | Decision::Modify(_) => true,
        Decision::Deny(reason) => {
            tracing::warn!(
                target: "synthesis",
                namespace = %namespace,
                candidate_id = %candidate_id,
                "synthesis delete verdict denied by K9: {reason}",
            );
            false
        }
        Decision::Ask(reason) => {
            // Ask outside K10 flow → treat as deny on the synthesis
            // path (no operator UI to surface the prompt).
            // Curator-driven deletes that need approval must be
            // promoted to an explicit `memory_delete` call.
            tracing::warn!(
                target: "synthesis",
                namespace = %namespace,
                candidate_id = %candidate_id,
                "synthesis delete verdict held for approval (ask): {reason}; \
                 skipping in this batch",
            );
            false
        }
    }
}

/// v0.7.x Form 1 verdict honouring — apply every queued update +
/// delete from the synthesis pass and return the primary-update
/// response envelope when one exists.
///
/// Returns `Some(response)` when the synthesiser elected to UPDATE an
/// existing candidate (the merge subsumes the incoming fact, the new
/// row insert is skipped, and the response echoes the merged
/// candidate's id). Returns `None` when no updates ran, in which case
/// the standard insert path proceeds in the store handler.
///
/// Queued deletes that target the primary-update id are skipped so
/// the store handler does not delete the very row it just merged the
/// incoming fact into.
///
/// #3173 — `caller` is the ENFORCED-read caller (`None` = single-operator
/// trust-all). Every `db::update` / `db::delete` below re-checks ownership
/// against the vetted `existing` pool and REFUSES the whole store call
/// (`Err`) rather than silently skipping a cross-owner mutation. The refusal
/// is raised BEFORE the transaction opens, so no partial merge can land.
///
/// # Errors
/// [`crate::errors::msg::CALLER_DOES_NOT_OWN_MEMORY`] when any queued update
/// or delete targets a row the caller does not own.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_synthesis_updates_and_deletes(
    conn: &rusqlite::Connection,
    mem: &Memory,
    existing: &[Memory],
    embedder: Option<&dyn crate::embeddings::Embed>,
    vector_index: Option<&dyn VectorSearchIndex>,
    outcome: &SynthesisOutcome,
    active_keypair: Option<&AgentKeypair>,
    caller: Option<&str>,
) -> Result<Option<Value>, String> {
    let primary_update = outcome.updates.first().cloned();
    let Some((primary_id, _)) = primary_update.as_ref() else {
        return Ok(None);
    };

    // #3173 — vet EVERY queued mutation before the BEGIN IMMEDIATE below, so a
    // cross-owner verdict can never leave a half-applied merge behind. The pool
    // is already ownership-filtered in `mod.rs`; this is the mutate-site
    // re-check the issue requires (`delete.rs:231-236` precedent).
    for (cand_id, _) in &outcome.updates {
        assert_caller_may_mutate(existing, caller, crate::audit::AuditAction::Update, cand_id)?;
    }
    for del_id in &outcome.deletes {
        if del_id == primary_id {
            continue;
        }
        assert_caller_may_mutate(existing, caller, crate::audit::AuditAction::Delete, del_id)?;
    }

    // #1700 — apply the whole synthesis merge atomically. db::update /
    // db::insert / db::delete / create_link_signed are all transaction-free, so
    // one BEGIN IMMEDIATE wraps the candidate updates + provenance rows +
    // supersedes links + deletes; a CORE write failure (update/delete) rolls
    // the entire merge back instead of leaving a half-synthesised store.
    // Vector-index mutations are in-memory and DEFERRED until after COMMIT so a
    // rollback can never leave the index out of sync with the DB.
    // #3163 — RAII guard. The early `return Ok(None)` arms below keep their
    // explicit ROLLBACK so the write lock is released at the exact bail-out
    // point; the guard is what covers a PANIC unwind out of any of the
    // update/link/delete calls, and it no-ops once the connection is back in
    // autocommit, so the two are idempotent with each other.
    let Ok(write_txn) = crate::storage::connection::WriteTxn::begin(conn) else {
        return Ok(None);
    };
    let mut deferred_index_ops: Vec<(String, Vec<f32>)> = Vec::new();

    // Issue #1239 — counter into `outcome.updates` so subsequent
    // iterations of a multi-update verdict (COR-5) mint distinct ids
    // for their provenance rows instead of colliding on `mem.id` PK.
    let mut updates_emitted: usize = 0;
    // Apply every queued update in sequence.
    for (cand_id, merged_content) in &outcome.updates {
        let Some(target) = existing.iter().find(|c| c.id == *cand_id).cloned() else {
            tracing::warn!(
                target: "synthesis",
                "synthesis update target {cand_id} not found in candidate set",
            );
            continue;
        };
        let preserved_metadata =
            crate::identity::preserve_provenance_keys(&target.metadata, &mem.metadata);
        let upd = db::update(
            conn,
            cand_id,
            None,
            Some(merged_content.as_str()),
            Some(&mem.tier),
            None,
            Some(&mem.tags),
            Some(mem.priority),
            Some(mem.confidence),
            None,
            Some(&preserved_metadata),
        );
        let (_found, content_changed) = match upd {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    target: "synthesis",
                    "synthesis update failed for {cand_id}: {e}; rolling back merge",
                );
                let _ = conn.execute_batch(crate::storage::connection::SQL_ROLLBACK);
                return Ok(None);
            }
        };
        if content_changed && let Some(emb) = embedder {
            let text = crate::embeddings::embedding_document(&target.title, &merged_content);
            if let Ok(embedding) = emb.embed(&text) {
                let _ = db::set_embedding(conn, cand_id, &embedding, &emb.space_fingerprint());
                if vector_index.is_some() {
                    // #1700 — defer the in-memory index swap until after COMMIT.
                    deferred_index_ops.push((cand_id.to_string(), embedding));
                }
            }
        }

        // Issue #1239 — emit a `supersedes` link so the merge is
        // provenance-visible in the KG. Without this, a synthesis
        // Update verdict silently drops the historical "the new fact
        // subsumed the older one" edge that the legacy supersede path
        // (link.rs + update_with_archive_on_supersede) persists via
        // metadata.superseded_id.
        //
        // The merged content lives in `target.id` after the in-place
        // update above. The incoming `mem.id` is not naturally
        // inserted on the Update path (the new-row insert is skipped
        // since the merge subsumed the incoming fact). To make the
        // supersedes edge structurally valid — both endpoints must
        // resolve in `memories` for the FK to hold — we persist a
        // lightweight provenance row keyed on `mem.id` carrying the
        // merged content. The row is the audit-honest "the new
        // arrival landed (after being merged into target)" record;
        // target.id remains the canonical merged survivor (echoed in
        // the response). Both endpoints alive ⇒ the supersedes link
        // lands in `memory_links`.
        let mut provenance_row = mem.clone();
        // Each Update verdict gets a distinct provenance row id so a
        // multi-update batch (COR-5) doesn't collide on the
        // `memories.id` PK. The first iteration reuses `mem.id` so
        // single-update callers observe the supersedes link's
        // `source_id` matching the new memory's intended identity;
        // subsequent iterations mint fresh UUIDs.
        if updates_emitted > 0 {
            provenance_row.id = uuid::Uuid::new_v4().to_string();
        }
        provenance_row.content = merged_content.clone();
        provenance_row.metadata =
            crate::identity::preserve_provenance_keys(&target.metadata, &mem.metadata);
        // #2122 — TRACT covenant clause 1: this provenance row is a GENUINE
        // internal bookkeeping writer — it exists only so the `supersedes`
        // edge has a structurally-valid FK endpoint after a synthesis Update
        // verdict merged the incoming fact into `target` (content already
        // merged into an existing, already-gated row). Without the substrate
        // rationale, `db::insert`'s why_trace gate refused it under
        // AI_MEMORY_REQUIRE_WHY_TRACE=1 and the supersedes lineage edge was
        // silently dropped (warn-only path below). Stamp-if-absent: a
        // caller-supplied why_trace on the incoming memory wins.
        crate::storage::stamp_substrate_why_trace(&mut provenance_row.metadata);
        // The (title, namespace) UNIQUE constraint on `memories`
        // would otherwise collide with the live target — append a
        // stable per-target suffix so the provenance row claims a
        // distinct slot. The trailing ` (sup ⟶ <id>)` is a fixed
        // shape Form-1 telemetry can recognise.
        provenance_row.title = format!("{} (sup ⟶ {})", mem.title, &target.id);
        match db::insert(conn, &provenance_row) {
            Ok(provenance_id) => {
                if let Err(e) = db::create_link_signed(
                    conn,
                    &provenance_id,
                    &target.id,
                    MemoryLinkRelation::Supersedes.as_str(),
                    active_keypair,
                ) {
                    tracing::warn!(
                        target: "synthesis",
                        "synthesis supersedes link emit failed for {} -> {}: {e}",
                        provenance_id,
                        target.id,
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "synthesis",
                    "synthesis provenance-row insert failed for {} (target={}): {e}",
                    mem.id,
                    target.id,
                );
            }
        }
        updates_emitted += 1;
    }

    // Apply queued deletes from the same batch (skip the primary
    // update target so we don't delete the very row we just merged
    // the incoming fact into).
    for del_id in &outcome.deletes {
        if del_id == primary_id {
            continue;
        }
        if let Err(e) = db::delete(conn, del_id) {
            tracing::warn!(
                target: "synthesis",
                "synthesis delete failed for {del_id}: {e}; rolling back merge",
            );
            let _ = conn.execute_batch(crate::storage::connection::SQL_ROLLBACK);
            return Ok(None);
        }
    }

    // #1700 — all core writes succeeded; commit the merge as one unit, then
    // apply the deferred in-memory vector-index swaps (the DB is now durable).
    // A failed COMMIT leaves the guard armed: dropping it here rolls the
    // whole merge back, so the deferred vector-index swaps below are never
    // applied against a store that did not durably change.
    if write_txn.commit().is_err() {
        return Ok(None);
    }
    if let Some(idx) = vector_index {
        for (id, embedding) in deferred_index_ops {
            idx.remove(&id);
            idx.insert(id, embedding);
        }
    }

    // Construct the response from the PRIMARY update's target.
    let Some(target) = existing.iter().find(|c| c.id == *primary_id).cloned() else {
        return Ok(None);
    };
    let preserved_metadata =
        crate::identity::preserve_provenance_keys(&target.metadata, &mem.metadata);
    let echoed_agent_id = preserved_metadata
        .get(param_names::AGENT_ID)
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let mut resp = json!({
        "id": target.id,
        "tier": mem.tier,
        "title": target.title,
        "namespace": mem.namespace,
        "agent_id": echoed_agent_id,
        "duplicate": true,
        "action": "synthesised: update existing memory",
    });
    if let Some(c) = &outcome.counts {
        resp["synthesis_decisions"] = c.to_json();
    }
    if let Some(reason) = &outcome.failed_reason {
        resp["synthesis_failed"] = json!(true);
        resp["synthesis_failed_reason"] = json!(reason);
    }
    Ok(Some(resp))
}

/// Apply pending delete verdicts when no update fired — the store
/// handler runs the standard `db::insert` afterward.
///
/// Issue #1239 — returns the set of ids that were deleted so the
/// caller (the store handler in `mod.rs`) can emit `supersedes` links
/// from the just-inserted memory to each deleted candidate. Because
/// `db::delete` removes the row from `memories`, the FK on
/// `memory_links` will reject any link to a deleted id — therefore
/// the store handler emits the link BEFORE calling `db::delete` on
/// each candidate. To preserve that order, we expose the list here
/// and let the handler drive the actual deletion + linking sequence.
pub(super) fn pending_synthesis_delete_targets(outcome: &SynthesisOutcome) -> Vec<String> {
    if !outcome.updates.is_empty() {
        return Vec::new();
    }
    outcome.deletes.clone()
}

/// Issue #1239 — emit a `supersedes` link from the newly-inserted
/// memory (`new_id`) to each pending Delete-verdict candidate, then
/// delete each candidate. Order matters: the link FK requires both
/// endpoints to exist in `memories`, so we emit before deleting.
/// Both `new_id` and each `del_id` are alive at the start of this
/// loop; after each emit the candidate is removed.
///
/// Best-effort: a per-candidate failure (link emit, delete) is
/// warn-logged and does not roll back the standard insert.
///
/// #3173 — the LAST-RESORT ownership re-check. The queue was already vetted
/// by [`assert_caller_may_mutate_all`] BEFORE the standard insert committed
/// (that is where a cross-owner verdict REFUSES the store call); by the time
/// this runs the new row is durable, so a violation here cannot refuse — it
/// skips the candidate with a WARN + a `Deny` audit row rather than
/// hard-deleting a row the caller does not own.
pub(super) fn apply_pending_synthesis_deletes_with_links(
    conn: &rusqlite::Connection,
    new_id: &str,
    pending_deletes: &[String],
    active_keypair: Option<&AgentKeypair>,
    candidates: &[Memory],
    caller: Option<&str>,
) {
    for del_id in pending_deletes {
        if assert_caller_may_mutate(
            candidates,
            caller,
            crate::audit::AuditAction::Delete,
            del_id,
        )
        .is_err()
        {
            continue;
        }
        if let Err(e) = db::create_link_signed(
            conn,
            new_id,
            del_id,
            MemoryLinkRelation::Supersedes.as_str(),
            active_keypair,
        ) {
            tracing::warn!(
                target: "synthesis",
                "synthesis supersedes link emit failed for {new_id} -> {del_id}: {e}",
            );
        }
        if let Err(e) = db::delete(conn, del_id) {
            tracing::warn!(
                target: "synthesis",
                "synthesis delete failed for {del_id}: {e}",
            );
        }
    }
}

/// Eligibility predicate for the synthesis pass. Lifted from the
/// inline guard in `handle_store` so the store handler reads a
/// single boolean.
pub(super) fn synthesis_eligible(
    autonomous_hooks: bool,
    llm_present: bool,
    content_len: usize,
    namespace: &str,
    ns_policy: &GovernancePolicy,
) -> bool {
    autonomous_hooks
        && llm_present
        && content_len >= AUTONOMY_MIN_CONTENT_LEN
        && !namespace.starts_with('_')
        && !ns_policy.effective_legacy_per_pair_classifier()
}
