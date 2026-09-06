// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3521 — SAL `MemoryStore` DEFAULT-ARM contract pins.
//!
//! Every optional `MemoryStore` capability ships a default body so a new
//! adapter compiles without implementing the whole surface. The contract
//! for those bodies is FAIL-CLOSED: an adapter that has not implemented a
//! capability must surface `StoreError::UnsupportedCapability` naming that
//! capability — never a silent `Ok(())` that would let an upper layer
//! believe a federated apply / governance decision / record-stop landed
//! when nothing was written. A handful of defaults are deliberately
//! *benign* (`Ok(false)` / `Ok(None)` / `Ok(())`) because "this adapter
//! holds no such state" is the truthful answer and the caller degrades
//! rather than corrupts; those are pinned here too so the distinction
//! cannot be flipped silently.
//!
//! The probe adapter implements ONLY the eleven required trait methods, so
//! every call below executes the default body in `src/store/mod.rs`
//! verbatim (no override can mask a regression).

#![cfg(feature = "sal")]

use ai_memory::models::{
    AgentRegistration, CheckpointState, ConditionType, ConfidenceSource, LifecycleState, Memory,
    MemoryKind, MemoryLink, RoutineRunState, RoutineState, Tier,
};
use ai_memory::store::{
    CallerContext, Capabilities, Filter, MemoryStore, StoreError, StoreResult, UpdatePatch,
    VerifyReport,
};

/// Minimal adapter: the eleven REQUIRED trait methods and nothing else.
struct DefaultsOnlyStore;

fn probe_memory() -> Memory {
    Memory {
        id: "m-3521".to_string(),
        tier: Tier::Long,
        namespace: "cov-3521".into(),
        title: "probe".into(),
        content: "body".into(),
        tags: Vec::new(),
        priority: 5,
        confidence: 1.0,
        source: "user".into(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
        cid: None,
        valid_from: None,
        valid_until: None,
    }
}

#[async_trait::async_trait]
impl MemoryStore for DefaultsOnlyStore {
    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }
    async fn store(&self, _ctx: &CallerContext, memory: &Memory) -> StoreResult<String> {
        Ok(memory.id.clone())
    }
    async fn get(&self, _ctx: &CallerContext, id: &str) -> StoreResult<Memory> {
        Err(StoreError::NotFound { id: id.to_string() })
    }
    async fn update(&self, _ctx: &CallerContext, id: &str, _patch: UpdatePatch) -> StoreResult<()> {
        Err(StoreError::NotFound { id: id.to_string() })
    }
    async fn delete(&self, _ctx: &CallerContext, id: &str) -> StoreResult<()> {
        Err(StoreError::NotFound { id: id.to_string() })
    }
    async fn list(&self, _ctx: &CallerContext, _filter: &Filter) -> StoreResult<Vec<Memory>> {
        Ok(Vec::new())
    }
    async fn search(
        &self,
        _ctx: &CallerContext,
        _query: &str,
        _filter: &Filter,
    ) -> StoreResult<Vec<Memory>> {
        Ok(Vec::new())
    }
    async fn verify(&self, _ctx: &CallerContext, id: &str) -> StoreResult<VerifyReport> {
        Ok(VerifyReport {
            memory_id: id.to_string(),
            integrity_ok: true,
            findings: Vec::new(),
            signature_verified: false,
            cid_ok: None,
            cid_mismatch: None,
        })
    }
    async fn link(&self, _ctx: &CallerContext, _link: &MemoryLink) -> StoreResult<()> {
        Ok(())
    }
    async fn list_links(&self, _namespace: Option<&str>) -> StoreResult<Vec<MemoryLink>> {
        Ok(Vec::new())
    }
    async fn register_agent(
        &self,
        _ctx: &CallerContext,
        _agent: &AgentRegistration,
    ) -> StoreResult<()> {
        Ok(())
    }
}

/// Assert a default arm refused with `UnsupportedCapability` naming
/// `capability`, and return nothing useful — the refusal IS the contract.
#[track_caller]
fn refused<T: std::fmt::Debug>(res: StoreResult<T>, capability: &str) {
    match res {
        Err(StoreError::UnsupportedCapability { capability: got }) => {
            assert_eq!(got, capability, "default arm named the wrong capability");
        }
        other => panic!("expected UnsupportedCapability({capability}), got {other:?}"),
    }
}

/// Every unimplemented WRITE / federated-apply / governance capability
/// refuses loudly, naming itself. Nothing here may ever become `Ok`.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn unimplemented_default_arms_refuse_naming_their_capability() {
    let s = DefaultsOnlyStore;
    let ctx = CallerContext::for_agent("cov-3521".to_string());
    let mem = probe_memory();
    let now = chrono::Utc::now().to_rfc3339();

    // --- write funnels -------------------------------------------------
    refused(
        s.store_with_embedding_no_overwrite(&ctx, &mem, None, None)
            .await,
        "STORE_WITH_EMBEDDING_NO_OVERWRITE",
    );
    refused(
        s.restore_or_conflict(&ctx, &mem).await,
        "RESTORE_OR_CONFLICT",
    );
    refused(
        s.set_row_metadata(&ctx, &mem.id, "{}").await,
        "SET_ROW_METADATA",
    );
    refused(
        s.reclassify_memory_kind(&ctx, &mem.id, MemoryKind::Reflection)
            .await,
        "RECLASSIFY_MEMORY_KIND",
    );
    refused(s.reown(&ctx, "ns", "agent-b", false, true).await, "REOWN");
    refused(s.size_gc("ns", 1_024, false).await, "SIZE_GC");
    refused(s.delete_link(&ctx, "a", "b").await, "DELETE_LINK");

    // --- curator / confidence -----------------------------------------
    refused(
        s.prune_curator_reports(&ctx, false).await,
        "PRUNE_CURATOR_REPORTS",
    );
    refused(
        s.calibrate_confidence_report(30, chrono::Utc::now()).await,
        "CALIBRATE_CONFIDENCE",
    );

    // --- quarantine ----------------------------------------------------
    refused(
        s.operator_dequarantine(&ctx, &mem.id).await,
        "OPERATOR_DEQUARANTINE",
    );
    refused(s.list_quarantined(None, 10).await, "LIST_QUARANTINED");

    // --- turn capture / recovery ---------------------------------------
    refused(
        s.recover_turn_idempotent(
            &ctx,
            &ai_memory::models::RecoverTurnWrite {
                memory: probe_memory(),
                normalized_sha256: vec![0_u8; 32],
                raw_sha256: vec![1_u8; 32],
                host_kind: "claude-code".to_string(),
                transcript_path: "/dev/null".to_string(),
                host_session_id: None,
                host_turn_index: None,
                recovered_at_ms: 0,
            },
        )
        .await,
        "L2_RECOVER_TURN",
    );

    // --- identity / attestation ----------------------------------------
    refused(
        s.agent_pubkey_versions("agent-a").await,
        "AGENT_PUBKEY_VERSIONS",
    );
    refused(
        s.agent_pubkey_for_attestation_at("agent-a", &now).await,
        "AGENT_PUBKEY_FOR_ATTESTATION_AT",
    );
    refused(
        s.admit_attested_write(&[0_u8; 32], "agent-a", &now).await,
        "ATTESTED_WRITE_REPLAY_LEDGER",
    );

    // --- record-stop (the fleet halt switch) ---------------------------
    refused(
        s.record_stop(&ctx, true, "operator", "global").await,
        "RECORD_STOP",
    );
    refused(s.record_stop_status(&ctx).await, "RECORD_STOP");

    // --- federation apply arms ------------------------------------------
    refused(
        s.list_memories_updated_since_counted(None, 10).await,
        "FEDERATION_LIST_SINCE",
    );
    refused(
        s.merge_inbound(&ctx, &mem, false).await,
        "FEDERATION_MERGE_INBOUND",
    );
    refused(
        s.archived_namespace_by_id(&ctx, &mem.id).await,
        "ARCHIVED_NAMESPACE_BY_ID",
    );
    refused(
        s.apply_remote_archive(&ctx, &mem.id).await,
        "APPLY_REMOTE_ARCHIVE",
    );
    refused(
        s.apply_remote_restore(&ctx, &mem.id).await,
        "APPLY_REMOTE_RESTORE",
    );

    // --- governance -----------------------------------------------------
    refused(
        s.reject_with_approver_type(&ctx, "pending-1", "approver-a")
            .await,
        "GOVERNANCE_PENDING_REJECT",
    );
    refused(
        s.forget_distinct_namespaces(None, Some(&Tier::Long)).await,
        "FORGET_DISTINCT_NAMESPACES",
    );

    // --- actions / signals ----------------------------------------------
    refused(
        s.action_create(
            &ctx,
            &ai_memory::models::Action {
                id: "act-3521".to_string(),
                namespace: "cov-3521".to_string(),
                kind: "probe".to_string(),
                state: ai_memory::models::ActionState::default(),
                title: "probe".to_string(),
                payload: serde_json::json!({}),
                priority: 5,
                agent_id: None,
                claimed_by: None,
                vector_clock: serde_json::json!({}),
                metadata: serde_json::json!({}),
                created_at: 0,
                updated_at: 0,
            },
        )
        .await,
        "ACTIONS",
    );

    // --- checkpoints ------------------------------------------------------
    refused(s.checkpoint_get(&ctx, "cp-1").await, "CHECKPOINTS");
    refused(
        s.checkpoint_list(&ctx, "ns", Some(CheckpointState::Pending), 10)
            .await,
        "CHECKPOINTS",
    );
    refused(
        s.checkpoint_resolve(
            &ctx,
            "cp-1",
            CheckpointState::Resolved,
            "operator",
            None,
            None,
            0,
            None,
        )
        .await,
        "CHECKPOINTS",
    );
    refused(
        s.checkpoint_query(&ctx, "ns", Some(ConditionType::Approval), None, 10)
            .await,
        "CHECKPOINTS",
    );

    // --- routines ---------------------------------------------------------
    refused(s.routine_get(&ctx, "r-1").await, "ROUTINES");
    refused(
        s.routine_list(&ctx, "ns", Some(RoutineState::Draft), 10)
            .await,
        "ROUTINES",
    );
    refused(s.routine_freeze(&ctx, "r-1", 0, None).await, "ROUTINES");
    refused(
        s.routine_materialize(&ctx, "r-1", &serde_json::json!({}))
            .await,
        "ROUTINES",
    );
    refused(s.routine_run_get(&ctx, "run-1").await, "ROUTINES");
    refused(s.routine_runs_for(&ctx, "r-1", 10).await, "ROUTINES");
    refused(
        s.routine_run_set_state(
            &ctx,
            "run-1",
            RoutineRunState::Failed,
            None,
            None,
            Some("boom"),
        )
        .await,
        "ROUTINES",
    );

    // --- lineage / transcripts ---------------------------------------------
    refused(
        s.list_dependents_of_invalidated(&mem.id).await,
        "LIST_DEPENDENTS_OF_INVALIDATED",
    );
    refused(
        s.list_outbound_reflects_on(&mem.id).await,
        "LIST_OUTBOUND_REFLECTS_ON",
    );
    refused(
        s.replay_transcript_union(&mem.id, Some(2)).await,
        "REPLAY_TRANSCRIPT_UNION",
    );
    refused(
        s.fetch_transcript_content("t-1").await,
        "FETCH_TRANSCRIPT_CONTENT",
    );
    refused(s.store_transcript("ns", "text").await, "STORE_TRANSCRIPT");
    refused(
        s.link_memory_transcript(&mem.id, "t-1", None, None).await,
        "LINK_MEMORY_TRANSCRIPT",
    );

    // --- derived-artifact reads (regenerable, still fail closed) ----------
    refused(
        s.get_embedding_with_space(&ctx, &mem.id).await,
        "GET_EMBEDDING",
    );
}

/// The deliberately BENIGN defaults. "This adapter holds no such state" is
/// the truthful answer, so the caller degrades (fewer results / no
/// short-circuit) instead of seeing a spurious refusal. Pinned so none of
/// them can drift into a silent success for a capability that DOES write.
#[tokio::test]
async fn benign_default_arms_degrade_without_refusing() {
    let s = DefaultsOnlyStore;
    let ctx = CallerContext::for_agent("cov-3521".to_string());

    // No quarantine state → nothing to release, and that is not an error.
    assert!(
        !s.dequarantine("m-3521")
            .await
            .expect("dequarantine default")
    );
    // No watermark → the federation catch-up never short-circuits.
    assert!(
        s.agent_max_created_at("agent-a")
            .await
            .expect("agent_max_created_at default")
            .is_none()
    );
    // No attestation ledger → an empty map, never a fabricated level.
    assert!(
        s.latest_link_attest_levels(&["a", "b"])
            .await
            .expect("latest_link_attest_levels default")
            .is_empty()
    );
    // No quota accounting → admit the write rather than refuse it.
    s.check_memory_quota(&ctx, "ns", 1, 1_024)
        .await
        .expect("check_memory_quota default admits");
    // `namespace_by_id` lifts the required `get`'s NotFound into Ok(None)
    // so a missing row can never be mistaken for a backend fault.
    assert!(
        s.namespace_by_id(&ctx, "missing")
            .await
            .expect("namespace_by_id default")
            .is_none()
    );
}
