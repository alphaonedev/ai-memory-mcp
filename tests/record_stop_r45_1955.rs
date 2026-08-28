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

use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_memory::models::{
    Action, ActionState, Checkpoint, CheckpointState, ConditionType, ConfidenceSource, EdgeType,
    Memory, MemoryKind, MemoryLink, MemoryLinkRelation, Routine, RoutineRun, RoutineRunState,
    RoutineState, Signal, SignalType, Tier,
};
use ai_memory::storage::StorageError;
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

fn stopped_anyhow(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        e.downcast_ref::<StorageError>()
            .is_some_and(|s| matches!(s, StorageError::RecordStopped { .. }))
            || e.to_string().contains("record plane stopped")
    })
}

fn stopped_rusqlite(err: &rusqlite::Error) -> bool {
    let mut cur: Option<&dyn Error> = Some(err);
    while let Some(e) = cur {
        if e.downcast_ref::<StorageError>()
            .is_some_and(|s| matches!(s, StorageError::RecordStopped { .. }))
            || e.to_string().contains("record plane stopped")
        {
            return true;
        }
        cur = e.source();
    }
    false
}

/// Wave-2 B6 — TABLE-DRIVEN completeness: every named mutating SSOT
/// free-fn refuses under record-stop. A new sibling that is not in this
/// table AND not gated will not be caught here — add the row when adding
/// the funnel (the SSOT pin).
#[allow(clippy::too_many_lines)] // completeness table is the pin; splitting hides siblings
#[test]
fn mutating_ssot_funnels_refuse_under_record_stop_b6() {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("open");
    assert!(
        ai_memory::storage::record_stop::actuate_sqlite(
            &conn,
            true,
            "ai:operator",
            SCOPE_RECORD_PLANE,
        )
        .expect("engage")
    );

    let mut failures = Vec::new();
    macro_rules! check_any {
        ($name:expr, $res:expr) => {{
            match $res {
                Ok(_) => failures.push(format!("{} returned Ok under stop", $name)),
                Err(e) => {
                    if !stopped_anyhow(&e) {
                        failures.push(format!("{} err was not RecordStopped: {e}", $name));
                    }
                }
            }
        }};
    }

    check_any!(
        "forget",
        ai_memory::db::forget(&conn, Some(NS), None, None, false).map(|_| ())
    );
    check_any!(
        "archive_memory",
        ai_memory::db::archive_memory(&conn, "no-such", None).map(|_| ())
    );
    check_any!(
        "restore_archived",
        ai_memory::db::restore_archived(&conn, "no-such").map(|_| ())
    );
    check_any!(
        "dequarantine",
        ai_memory::db::dequarantine(&conn, "no-such").map(|_| ())
    );
    check_any!(
        "delete_link",
        ai_memory::db::delete_link(&conn, "a", "b").map(|_| ())
    );
    check_any!(
        "bind_agent_pubkey",
        ai_memory::db::bind_agent_pubkey(&conn, "ai:x", "AAAA")
    );
    check_any!(
        "purge_archive",
        ai_memory::db::purge_archive(&conn, None).map(|_| ())
    );
    check_any!(
        "purge_archive_for_caller",
        ai_memory::db::purge_archive_for_caller(&conn, "ai:x", None).map(|_| ())
    );
    check_any!(
        "set_embedding",
        ai_memory::db::set_embedding(&conn, "no-such", &[0.1], "space")
    );
    check_any!(
        "set_namespace_standard",
        ai_memory::db::set_namespace_standard(&conn, NS, "no-such", None)
    );
    check_any!(
        "clear_namespace_standard",
        ai_memory::db::clear_namespace_standard(&conn, NS).map(|_| ())
    );
    check_any!("gc", ai_memory::db::gc(&conn, false).map(|_| ()));

    let action = Action {
        id: "b6-act".into(),
        namespace: NS.into(),
        kind: "test".into(),
        state: ActionState::Pending,
        title: "t".into(),
        payload: json!({}),
        priority: 5,
        agent_id: Some("ai:x".into()),
        claimed_by: None,
        vector_clock: json!({}),
        metadata: json!({}),
        created_at: 1,
        updated_at: 1,
    };
    match ai_memory::actions::create(&conn, &action) {
        Ok(_) => failures.push("actions::create returned Ok under stop".into()),
        Err(e) => {
            if !stopped_rusqlite(&e) {
                failures.push(format!("actions::create err was not RecordStopped: {e}"));
            }
        }
    }
    match ai_memory::actions::transition(&conn, "b6-act", ActionState::Claimed, None, 2) {
        Ok(_) => failures.push("actions::transition returned Ok under stop".into()),
        Err(e) => {
            if !stopped_rusqlite(&e) {
                failures.push(format!(
                    "actions::transition err was not RecordStopped: {e}"
                ));
            }
        }
    }
    match ai_memory::actions::add_edge(&conn, "a", "b", EdgeType::Requires, 1) {
        Ok(_) => failures.push("actions::add_edge returned Ok under stop".into()),
        Err(e) => {
            if !stopped_rusqlite(&e) {
                failures.push(format!("actions::add_edge err was not RecordStopped: {e}"));
            }
        }
    }
    match ai_memory::actions::lease_acquire(&conn, "b6-act", "h", 1, 2) {
        Ok(_) => failures.push("actions::lease_acquire returned Ok under stop".into()),
        Err(e) => {
            if !stopped_rusqlite(&e) {
                failures.push(format!(
                    "actions::lease_acquire err was not RecordStopped: {e}"
                ));
            }
        }
    }
    match ai_memory::actions::lease_renew(&conn, "b6-act", "h", 1, 2) {
        Ok(_) => failures.push("actions::lease_renew returned Ok under stop".into()),
        Err(e) => {
            if !stopped_rusqlite(&e) {
                failures.push(format!(
                    "actions::lease_renew err was not RecordStopped: {e}"
                ));
            }
        }
    }
    match ai_memory::actions::lease_release(&conn, "b6-act", "h") {
        Ok(_) => failures.push("actions::lease_release returned Ok under stop".into()),
        Err(e) => {
            if !stopped_rusqlite(&e) {
                failures.push(format!(
                    "actions::lease_release err was not RecordStopped: {e}"
                ));
            }
        }
    }

    macro_rules! check_rusqlite {
        ($name:expr, $res:expr) => {{
            match $res {
                Ok(_) => failures.push(format!("{} returned Ok under stop", $name)),
                Err(e) => {
                    if !stopped_rusqlite(&e) {
                        failures.push(format!("{} err was not RecordStopped: {e}", $name));
                    }
                }
            }
        }};
    }

    let signal = Signal {
        id: "b6-sig".into(),
        namespace: NS.into(),
        from_agent: "ai:x".into(),
        to_agent: Some("ai:y".into()),
        subject: "s".into(),
        body: json!({}),
        signal_type: SignalType::Notify,
        in_reply_to: None,
        correlation_id: None,
        reference_ids: json!([]),
        created_at: 1,
        expires_at: None,
        delivered_at: None,
        read_at: None,
        acknowledged_at: None,
        signature: vec![],
        sender_pubkey: vec![],
    };
    check_rusqlite!(
        "signals::insert",
        ai_memory::signals::insert(&conn, &signal)
    );
    check_rusqlite!(
        "signals::mark_acked",
        ai_memory::signals::mark_acked(&conn, "b6-sig", 1)
    );
    check_rusqlite!(
        "signals::mark_read",
        ai_memory::signals::mark_read(&conn, "b6-sig", 1)
    );
    check_rusqlite!(
        "signals::mark_delivered",
        ai_memory::signals::mark_delivered(&conn, "b6-sig", 1)
    );
    check_rusqlite!(
        "signals::prune_expired",
        ai_memory::signals::prune_expired(&conn, 1)
    );

    let checkpoint = Checkpoint {
        id: "b6-cp".into(),
        namespace: NS.into(),
        title: "t".into(),
        condition_type: ConditionType::Approval,
        condition: json!({}),
        state: CheckpointState::Pending,
        created_by: "ai:x".into(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: vec![],
        resolver_pubkey: vec![],
        created_at: 1,
        deadline_at: None,
        resolved_at: None,
        metadata: json!({}),
    };
    check_rusqlite!(
        "checkpoints::insert",
        ai_memory::checkpoints::insert(&conn, &checkpoint)
    );
    check_rusqlite!(
        "checkpoints::resolve",
        ai_memory::checkpoints::resolve(
            &conn,
            "b6-cp",
            CheckpointState::Resolved,
            "ai:x",
            None,
            None,
            1,
            None,
        )
    );
    check_rusqlite!(
        "checkpoints::store_resolution_attestation",
        ai_memory::checkpoints::store_resolution_attestation(&conn, "b6-cp", &[], &[])
    );
    check_rusqlite!(
        "checkpoints::apply_inbound_resolution",
        ai_memory::checkpoints::apply_inbound_resolution(&conn, &checkpoint)
    );

    let routine = Routine {
        id: "b6-rt".into(),
        namespace: NS.into(),
        name: "n".into(),
        template: json!({"actions": []}),
        parameters: json!([]),
        state: RoutineState::Draft,
        created_by: "ai:x".into(),
        created_at: 1,
        frozen_at: None,
        signature: vec![],
        signer_pubkey: vec![],
        metadata: json!({}),
    };
    check_rusqlite!(
        "routines::routine_insert",
        ai_memory::routines::routine_insert(&conn, &routine)
    );
    check_rusqlite!(
        "routines::routine_freeze",
        ai_memory::routines::routine_freeze(&conn, "b6-rt", 1, None)
    );
    let run = RoutineRun {
        id: "b6-run".into(),
        routine_id: "b6-rt".into(),
        namespace: NS.into(),
        arguments: json!({}),
        state: RoutineRunState::Pending,
        created_action_ids: json!([]),
        started_at: 1,
        finished_at: None,
        error: None,
        metadata: json!({}),
    };
    check_rusqlite!(
        "routines::run_insert",
        ai_memory::routines::run_insert(&conn, &run)
    );
    check_rusqlite!(
        "routines::run_set_state",
        ai_memory::routines::run_set_state(
            &conn,
            "b6-run",
            RoutineRunState::Failed,
            None,
            None,
            None
        )
    );

    check_any!(
        "size_gc",
        ai_memory::db::size_gc(&conn, NS, 1, false).map(|_| ())
    );
    check_any!(
        "sweep_pending_action_timeouts",
        ai_memory::db::sweep_pending_action_timeouts(&conn, 60).map(|_| ())
    );

    assert!(
        failures.is_empty(),
        "B6 completeness failures:\n  {}",
        failures.join("\n  ")
    );
}

/// Wave-2 B6 — MCP dispatch fail-closed: write tools (including
/// `memory_routine_*` create/freeze/run) are NOT in the read-only
/// allowlist, and `tools/call` calls `gate_storage_conn` before dispatch.
#[test]
fn mcp_dispatch_fail_closed_record_stop_b6() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mcp/mod.rs"),
    )
    .expect("read mcp/mod.rs");
    let start = src
        .find("fn mcp_tool_is_read_only")
        .expect("mcp_tool_is_read_only must exist");
    let allow = src[start..].split("\n}\n").next().expect("allowlist body");
    for write in [
        "MEMORY_FORGET",
        "MEMORY_STORE",
        "MEMORY_ROUTINE_CREATE",
        "MEMORY_ROUTINE_FREEZE",
        "MEMORY_ROUTINE_RUN",
        "MEMORY_SIGNAL_SEND",
        "MEMORY_SIGNAL_ACK",
        "MEMORY_CHECKPOINT_CREATE",
        "MEMORY_CHECKPOINT_RESOLVE",
        "MEMORY_ACTION_CREATE",
        "MEMORY_ACTION_TRANSITION",
        "MEMORY_LEASE_ACQUIRE",
    ] {
        assert!(
            !allow.contains(write),
            "{write} must not be classified read-only (fail-closed write)"
        );
    }
    for read in [
        "MEMORY_RECALL",
        "MEMORY_ROUTINE_LIST",
        "MEMORY_ROUTINE_STATUS",
        "MEMORY_SIGNAL_INBOX",
        "MEMORY_SIGNAL_READ",
        "MEMORY_CHECKPOINT_QUERY",
        "MEMORY_ACTION_GET",
    ] {
        assert!(
            allow.contains(read),
            "{read} must stay live under record-stop"
        );
    }
    let dispatch = src
        .split("Wave-2 B6 — MCP dispatch-layer record-stop fence")
        .nth(1)
        .expect("MCP tools/call must carry the B6 dispatch fence");
    assert!(
        dispatch.contains("if !mcp_tool_is_read_only(tool_name)"),
        "dispatch must fail-closed on non-read tools"
    );
    assert!(
        dispatch.contains("gate_storage_conn(conn)"),
        "dispatch must call gate_storage_conn"
    );
}

/// Wave-2 B6 — both SAL adapters must fence coordination-plane writes
/// at `gate_record_stop` (postgres is sqlx-native; sqlite is defense
/// in depth on top of the rusqlite SSOT). A new sibling method that
/// is not in this list will not be caught — add the name when adding
/// the funnel.
#[test]
fn coordination_sal_write_methods_gate_record_stop_b6() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (file, methods) in [
        (
            "src/store/postgres.rs",
            &[
                "async fn action_create",
                "async fn action_transition(",
                "async fn action_add_edge",
                "async fn lease_acquire",
                "async fn lease_renew",
                "async fn lease_release",
                "async fn signal_send",
                "async fn signal_ack",
                "async fn checkpoint_create",
                "async fn checkpoint_resolve",
                "async fn routine_create",
                "async fn routine_freeze",
                "async fn routine_run_create",
                "async fn routine_run_set_state",
                "async fn run_gc",
                "async fn size_gc",
            ][..],
        ),
        (
            "src/store/sqlite.rs",
            &[
                "async fn action_create",
                "async fn signal_send",
                "async fn checkpoint_create",
                "async fn routine_create",
                "async fn routine_freeze",
                "async fn run_gc",
                "async fn size_gc",
            ][..],
        ),
        ("src/routines/mod.rs", &["gate_storage_conn_rusqlite"][..]),
        (
            "src/checkpoints/mod.rs",
            &["gate_storage_conn_rusqlite"][..],
        ),
        ("src/signals/mod.rs", &["gate_storage_conn_rusqlite"][..]),
        ("src/actions/mod.rs", &["gate_storage_conn_rusqlite"][..]),
    ] {
        let src = std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| {
            panic!("read {file}: {e}");
        });
        for method in methods {
            if *method == "gate_storage_conn_rusqlite" {
                assert!(src.contains(method), "{file} must call {method}");
                continue;
            }
            let idx = src.find(method).unwrap_or_else(|| {
                panic!("{file} must contain {method}");
            });
            let window = &src[idx..src.len().min(idx.saturating_add(500))];
            assert!(
                window.contains("gate_record_stop"),
                "{file} {method} must call gate_record_stop in the first 500 bytes"
            );
        }
    }
}
