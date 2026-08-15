// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![cfg(feature = "sal")]

//! #1955 [P1][R45] — substrate record-stop actuator + signed
//! stop-attestation.
//!
//! Pins the acceptance criteria on the sqlite backend (the postgres
//! twin shares the backend-blind [`MemoryStore`] surface + the same
//! `signed_events`-derived flag; its live-PG tests are `#[ignore]`d by
//! infra, not by design):
//!
//! - STOP → every mutating funnel refuses with the typed error (SAL
//!   `StoreError::Stopped`; the bare-`db::` funnel the MCP stdio path
//!   uses → `StorageError::RecordStopped`).
//! - READS stay live while stopped (the record remains auditable).
//! - RESUME restores the write path.
//! - Issuing stop/resume emits ONE signed `substrate.record_stop` /
//!   `substrate.record_resume` attestation, chained + chain-intact.
//! - EFFECT-LATENCY: stop issued → next write refused in ≤ 100 ms.
//! - PERSISTENCE: the stop is derivable from the audit chain after a
//!   fresh open (survives a daemon restart).
//! - Federation-receive IS stopped (the "atomic write-fence" — inbound
//!   convergence pauses under record-stop).

use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::record_stop::SCOPE_RECORD_PLANE;
use ai_memory::store::{CallerContext, Filter, MemoryStore, StoreError, sqlite::SqliteStore};
use serde_json::json;
use tempfile::NamedTempFile;

const NS: &str = "record-stop-r45";

fn mk_memory(title: &str, content: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec!["r45".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": "ai:operator"}),
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
        ..Memory::default()
    }
}

fn fresh_store() -> (Arc<dyn MemoryStore>, NamedTempFile) {
    let f = NamedTempFile::new().expect("tempfile");
    let store: Arc<dyn MemoryStore> =
        Arc::new(SqliteStore::open(f.path()).expect("open SqliteStore"));
    (store, f)
}

fn ctx() -> CallerContext {
    CallerContext::for_agent("ai:operator")
}

#[tokio::test]
async fn stop_refuses_writes_reads_stay_live_resume_restores() {
    let (store, _f) = fresh_store();
    let c = ctx();

    // Seed a row while RUNNING.
    let seed = mk_memory("seed", "content before the stop");
    let seed_id = store.store(&c, &seed).await.expect("store while running");

    // Engage the record-stop.
    let changed = store
        .record_stop(&c, true, "ai:operator", SCOPE_RECORD_PLANE)
        .await
        .expect("engage record-stop");
    assert!(changed, "first stop must report a state change");

    // Every mutating funnel now refuses with the typed error.
    let blocked = mk_memory("blocked", "must not land");
    match store.store(&c, &blocked).await {
        Err(StoreError::Stopped { scope, .. }) => assert_eq!(scope, SCOPE_RECORD_PLANE),
        other => panic!("store must refuse with Stopped, got {other:?}"),
    }
    assert!(
        matches!(
            store.delete(&c, &seed_id).await,
            Err(StoreError::Stopped { .. })
        ),
        "delete must refuse under stop"
    );
    assert!(
        matches!(
            store
                .consolidate(
                    &c,
                    std::slice::from_ref(&seed_id),
                    "m",
                    "s",
                    NS,
                    &Tier::Long,
                    "test",
                    "ai:operator"
                )
                .await,
            Err(StoreError::Stopped { .. })
        ),
        "consolidate must refuse under stop"
    );

    // READS stay live — the record remains auditable while stopped.
    let got = store
        .get(&c, &seed_id)
        .await
        .expect("get is live under stop");
    assert_eq!(got.id, seed_id);
    let listed = store
        .list(
            &c,
            &Filter {
                namespace: Some(NS.to_string()),
                limit: 50,
                ..Default::default()
            },
        )
        .await
        .expect("list is live under stop");
    assert!(
        listed.iter().any(|m| m.id == seed_id),
        "seed visible while stopped"
    );

    // RESUME restores the write path.
    let changed = store
        .record_stop(&c, false, "ai:operator", SCOPE_RECORD_PLANE)
        .await
        .expect("release record-stop");
    assert!(changed, "resume must report a state change");
    let after = mk_memory("after-resume", "landed after resume");
    store.store(&c, &after).await.expect("store after resume");
}

#[tokio::test]
async fn mcp_direct_db_funnel_is_fenced() {
    // The MCP stdio path writes through the bare-`Connection` `db::`
    // primitives, not the SAL adapter. Stopping via the SAL surface must
    // also fence that funnel (same DB path → same flag).
    let (store, f) = fresh_store();
    let c = ctx();
    store
        .record_stop(&c, true, "ai:operator", SCOPE_RECORD_PLANE)
        .await
        .expect("engage");

    let conn = ai_memory::db::open(f.path()).expect("open bare connection");
    let mem = mk_memory("mcp-direct", "via db::insert");
    let err = ai_memory::db::insert(&conn, &mem).expect_err("db::insert must refuse under stop");
    let se = err
        .downcast_ref::<ai_memory::storage::StorageError>()
        .expect("typed StorageError in the anyhow chain");
    assert!(
        matches!(se, ai_memory::storage::StorageError::RecordStopped { .. }),
        "db:: funnel must refuse with RecordStopped, got {se:?}"
    );
}

#[tokio::test]
async fn federation_receive_is_stopped() {
    // DISPOSITION: inbound federated writes ARE stopped — a relayed write
    // is still a record-plane mutation, so record-stop pauses convergence
    // (the issue's "atomic write-fence").
    let (store, _f) = fresh_store();
    let c = ctx();
    store
        .record_stop(&c, true, "ai:operator", SCOPE_RECORD_PLANE)
        .await
        .expect("engage");

    let inbound = mk_memory("inbound", "relayed from a peer");
    assert!(
        matches!(
            store.apply_remote_memory(&c, &inbound).await,
            Err(StoreError::Stopped { .. })
        ),
        "apply_remote_memory (federation-receive funnel) must refuse under stop"
    );
    // merge_inbound is the other federation convergence entry point.
    let merge = mk_memory("merge-inbound", "peer merge under stop");
    assert!(
        matches!(
            store.merge_inbound(&c, &merge, false).await,
            Err(StoreError::Stopped { .. })
        ),
        "merge_inbound must refuse under stop"
    );
}

#[tokio::test]
async fn effect_latency_under_100ms() {
    let (store, _f) = fresh_store();
    let c = ctx();

    // Issue stop, then time the very next write to first-refusal.
    store
        .record_stop(&c, true, "ai:operator", SCOPE_RECORD_PLANE)
        .await
        .expect("engage");
    let blocked = mk_memory("latency", "should refuse immediately");
    let t0 = Instant::now();
    let res = store.store(&c, &blocked).await;
    let elapsed = t0.elapsed();
    assert!(
        matches!(res, Err(StoreError::Stopped { .. })),
        "next write refused"
    );
    assert!(
        elapsed <= Duration::from_millis(100),
        "stop effect-latency {elapsed:?} exceeds the 100ms target"
    );
}

#[tokio::test]
async fn attestation_events_signed_and_chained() {
    let (store, f) = fresh_store();
    let c = ctx();
    store
        .record_stop(&c, true, "ai:operator", SCOPE_RECORD_PLANE)
        .await
        .expect("engage");
    store
        .record_stop(&c, false, "ai:operator", SCOPE_RECORD_PLANE)
        .await
        .expect("release");

    let conn = ai_memory::db::open(f.path()).expect("reopen");
    // Exactly one stop + one resume attestation landed on the chain.
    let stop_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = 'substrate.record_stop'",
            [],
            |r| r.get(0),
        )
        .expect("count stop events");
    let resume_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = 'substrate.record_resume'",
            [],
            |r| r.get(0),
        )
        .expect("count resume events");
    assert_eq!(stop_rows, 1, "one signed stop attestation");
    assert_eq!(resume_rows, 1, "one signed resume attestation");

    // The cross-row hash chain holds end-to-end (the attestation rows are
    // chained, not free-floating).
    let report =
        ai_memory::signed_events::verify_audit_trail(&conn, None, None).expect("verify chain");
    assert!(
        report.chain_intact,
        "signed_events chain must hold with the attestation rows"
    );
    assert!(
        report.head_sequence >= 2,
        "at least the stop + resume rows are sequenced"
    );
}

#[tokio::test]
async fn stop_persists_across_reopen() {
    let f = NamedTempFile::new().expect("tempfile");
    {
        let store: Arc<dyn MemoryStore> = Arc::new(SqliteStore::open(f.path()).expect("open"));
        store
            .record_stop(&ctx(), true, "ai:operator", SCOPE_RECORD_PLANE)
            .await
            .expect("engage");
    }
    // The persisted flag is derivable from the audit chain alone — prove
    // it directly (independent of any in-process cache) so the property
    // holds for a genuinely fresh process / daemon restart.
    let conn = ai_memory::db::open(f.path()).expect("reopen");
    let derived =
        ai_memory::store::record_stop::read_state_sqlite(&conn).expect("derive state from chain");
    assert!(
        derived.stopped,
        "a stop persisted before reopen is derived as stopped"
    );
    assert_eq!(derived.issued_by, "ai:operator");
}

#[tokio::test]
async fn redundant_stop_is_idempotent_no_duplicate_attestation() {
    let (store, f) = fresh_store();
    let c = ctx();
    assert!(
        store
            .record_stop(&c, true, "ai:operator", SCOPE_RECORD_PLANE)
            .await
            .unwrap()
    );
    // Second stop while already stopped: no state change, no new event.
    assert!(
        !store
            .record_stop(&c, true, "ai:operator", SCOPE_RECORD_PLANE)
            .await
            .unwrap()
    );

    let conn = ai_memory::db::open(f.path()).expect("reopen");
    let stop_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = 'substrate.record_stop'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        stop_rows, 1,
        "a redundant stop emits no duplicate attestation"
    );
}
