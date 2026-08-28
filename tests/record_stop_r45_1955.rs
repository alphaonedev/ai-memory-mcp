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
//! - EFFECT: stop issued → the very NEXT write is refused, SYNCHRONOUSLY
//!   with the write attempt. (v1.0.0 #3140: the wall-clock bound here was
//!   `≤ 100 ms`, which on a loaded shared CI runner measures the runner,
//!   not the stop plane. It is now a shape guard — see
//!   `STOP_EFFECT_SYNCHRONOUS_CEILING`. The product's ≤100 ms figure is a
//!   REFERENCE-HARDWARE claim and needs a bench producer to be enforced;
//!   this suite does not, and never truthfully did, establish it.)
//! - PERSISTENCE: the stop is derivable from the audit chain after a
//!   fresh open (survives a daemon restart).
//! - Federation-receive IS stopped (the "atomic write-fence" — inbound
//!   convergence pauses under record-stop).

use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_memory::models::{
    ActionState, ConfidenceSource, Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Tier,
};
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
async fn sal_gate_enforces_stop_when_open_path_differs_from_resolved_path() {
    // Regression (macOS enterprise-fed CI): the SAL write-funnel gate must key
    // the record-stop registry off the connection's OWN resolved path — the
    // same key the actuator, the `db::` gate, the status read and the seed use
    // (`conn.path()`) — NOT the raw path handed to `SqliteStore::open`.
    //
    // SQLite's VFS resolves symlinks in the pathname, so opening through a
    // symlinked directory makes `conn.path()` diverge from the open path (on
    // macOS this happens for EVERY temp DB, since the temp dir sits under the
    // `/var -> /private/var` symlink). Keying the SAL gate off the open path
    // let it read a stale RUNNING registry entry while the stop was engaged
    // under the resolved key, so `store()` fell through to the deeper `db::`
    // gate and surfaced `StoreError::Backend` instead of the SAL
    // `StoreError::Stopped` (a silent single-layer degradation of a
    // fail-closed control). Pin that the SAL gate refuses with `Stopped`
    // regardless of open-path/resolved-path divergence.
    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real");
    std::fs::create_dir(&real).expect("mkdir real");
    let db_path = {
        let link = dir.path().join("via-link");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, &link).expect("symlink real dir");
            link.join("mem.db")
        }
        #[cfg(not(unix))]
        {
            let _ = &link;
            real.join("mem.db")
        }
    };

    let store: Arc<dyn MemoryStore> =
        Arc::new(SqliteStore::open(&db_path).expect("open via symlinked path"));
    let c = ctx();
    store
        .record_stop(&c, true, "ai:operator", SCOPE_RECORD_PLANE)
        .await
        .expect("engage record-stop");

    let blocked = mk_memory("blocked", "must not land under stop");
    match store.store(&c, &blocked).await {
        Err(StoreError::Stopped { scope, .. }) => assert_eq!(scope, SCOPE_RECORD_PLANE),
        other => panic!(
            "SAL gate must refuse with StoreError::Stopped regardless of \
             open-path vs resolved-path divergence, got {other:?}"
        ),
    }
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

/// Wave-2 B2 — same-id federation merge (existing-row `overwrite_full_row_by_id`
/// branch) must refuse under record-stop. The SAL adapter already gated
/// `merge_inbound`; the hole was the free-fn `db::merge_inbound` that
/// `federation_receive` calls directly, which skipped `gate_storage_conn`
/// on the existing-row path (`insert_if_newer` already gated the no-row path).
#[test]
fn db_merge_inbound_same_id_refuses_under_record_stop_b2() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("open");
    let mut mem = mk_memory("same-id-b2", "local row");
    let id = ai_memory::db::insert(&conn, &mem).expect("seed local row");
    mem.id.clone_from(&id);

    assert!(
        ai_memory::storage::record_stop::actuate_sqlite(
            &conn,
            true,
            "ai:operator",
            SCOPE_RECORD_PLANE,
        )
        .expect("engage record-stop"),
        "first engage must report a state change"
    );

    mem.content = "hostile overwrite".to_string();
    mem.updated_at = chrono::Utc::now().to_rfc3339();
    let err = ai_memory::db::merge_inbound(&conn, &mem, false)
        .expect_err("same-id merge_inbound must refuse under stop");
    let se = err
        .downcast_ref::<ai_memory::storage::StorageError>()
        .expect("typed StorageError in the anyhow chain");
    assert!(
        matches!(se, ai_memory::storage::StorageError::RecordStopped { .. }),
        "existing-row merge must refuse with RecordStopped, got {se:?}"
    );

    let stored: String = conn
        .query_row("SELECT content FROM memories WHERE id = ?1", [&id], |r| {
            r.get(0)
        })
        .expect("read");
    assert_eq!(
        stored, "local row",
        "stopped merge must not overwrite the local row"
    );
}

/// Wave-2 B5 — record-stop completeness: a same-id link, an action
/// execute, a dequarantine, and sqlite `action_transition_cas` all
/// refuse under stop (federation-receive / local action planes, not
/// just the memory plane B2 fenced).
#[tokio::test]
async fn federation_receive_link_action_dequarantine_cas_refused_under_stop_b5() {
    let (store, _f) = fresh_store();
    let c = ctx();
    let src = store
        .store(&c, &mk_memory("b5-src", "s"))
        .await
        .expect("seed src");
    let tgt = store
        .store(&c, &mk_memory("b5-tgt", "t"))
        .await
        .expect("seed tgt");

    store
        .record_stop(&c, true, "ai:operator", SCOPE_RECORD_PLANE)
        .await
        .expect("engage");

    let link = MemoryLink {
        source_id: src.clone(),
        target_id: tgt,
        relation: MemoryLinkRelation::RelatedTo,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: None,
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    };
    assert!(
        matches!(
            store.apply_remote_link(&c, &link, "unsigned").await,
            Err(StoreError::Stopped { .. })
        ),
        "same-id/inbound link via federation-receive must refuse under stop"
    );
    assert!(
        matches!(
            store.execute_pending_action(&c, "no-such-pending-b5").await,
            Err(StoreError::Stopped { .. })
        ),
        "action execute via federation-receive must refuse under stop (gate before lookup)"
    );
    assert!(
        matches!(
            store.dequarantine(&src).await,
            Err(StoreError::Stopped { .. })
        ),
        "dequarantine via federation-receive must refuse under stop"
    );
    assert!(
        matches!(
            store
                .action_transition_cas(
                    &c,
                    "no-such-action-b5",
                    ActionState::Pending,
                    ActionState::Claimed,
                    None,
                    1,
                )
                .await,
            Err(StoreError::Stopped { .. })
        ),
        "sqlite action_transition_cas must refuse under stop (B2 pg-parity)"
    );
}

/// Wave-2 B5 — the sqlite `/sync/push` write-dispatch has ONE
/// record-stop chokepoint (`refuse_if_record_stopped`) after taking the
/// connection lock and before any `db::` write funnel. A new write
/// funnel added without going through that gate fails this pin.
#[test]
fn sync_push_write_dispatch_has_record_stop_chokepoint_b5() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers/federation_receive.rs"),
    )
    .expect("read federation_receive.rs");
    let after_lock = src
        .split("let lock = state.lock().await")
        .nth(1)
        .expect("sqlite sync_push must take the db lock");
    let gate_at = after_lock
        .find("refuse_if_record_stopped(&lock.0)")
        .expect("sqlite sync_push must call refuse_if_record_stopped at the write-dispatch");
    let merge_at = after_lock
        .find("db::merge_inbound")
        .expect("sqlite sync_push still reaches merge_inbound");
    assert!(
        gate_at < merge_at,
        "record-stop chokepoint must sit after the lock and before the first db:: write"
    );
    for funnel in [
        "create_link_inbound",
        "upsert_pending_action",
        "execute_pending_action",
        "dequarantine",
        "archive_memory",
        "restore_archived",
        "set_embedding",
        "sync_state_observe",
        "sync_state_merge_authorized",
    ] {
        assert!(
            src.contains(funnel),
            "sync_push must still reach {funnel} (update this pin if the funnel was renamed)"
        );
    }
    let sal = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/handlers/federation_signing_check.rs"),
    )
    .expect("read federation_signing_check.rs");
    assert!(
        sal.contains("record_stop_status"),
        "SAL sync_push_via_store must chokepoint via record_stop_status"
    );
}

/// v1.0.0 #3140 — ceiling on how long the refusal may take.
///
/// This is a SHAPE guard, not a performance budget: it fails if the stop plane
/// ever becomes eventually-consistent (a background reconcile, a network
/// round-trip, a retry loop), which would take seconds or never refuse at all.
/// It is deliberately ~20x the product's reference-hardware ≤100 ms figure so
/// it can only fire on that structural regression, never on a loaded shared CI
/// runner. Enforcing the ≤100 ms figure itself requires a bench producer on
/// reference hardware; no such bench exists today, and the previous 100 ms
/// assertion here did not establish it either — it only made this suite flaky.
const STOP_EFFECT_SYNCHRONOUS_CEILING: Duration = Duration::from_secs(2);

/// R-45 (#1955) — once a stop is engaged the very next write is refused,
/// synchronously with the write attempt.
#[tokio::test]
async fn effect_refuses_next_write_synchronously() {
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
        elapsed <= STOP_EFFECT_SYNCHRONOUS_CEILING,
        "the stop must refuse SYNCHRONOUSLY with the write attempt; \
         {elapsed:?} exceeds {STOP_EFFECT_SYNCHRONOUS_CEILING:?}, which means the \
         refusal became eventually-consistent"
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
