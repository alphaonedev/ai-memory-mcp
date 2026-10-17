// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7321 archive-gc tests, moved out of `mcp::tests` so `mcp/mod.rs`
//! stays at or below its QUAL-10 size (the ceiling is a ratchet).

use super::*;

/// archive — gc handler not-dry-run path runs db::gc.
#[test]
fn chunkc_archive_gc_real_run_invokes_db_gc() {
    // #7321: serialise with the tests that latch the process-global audit gate.
    let _sink = crate::audit::sink_test_lock();
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    // Seed an expired memory so gc has work to do.
    let past = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
    let mem = Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Short,
        namespace: "chunkc-gc-real".to_string(),
        title: "stale".to_string(),
        content: "stale".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: Some(past),
        metadata: json!({}),
        reflection_depth: 0,
        memory_kind: crate::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: crate::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    };
    db::insert(&conn, &mem).unwrap();
    let req = make_tools_call("memory_gc", json!({"dry_run": false}));
    let resp = invoke_handle_request(&conn, &req);
    assert!(resp.error.is_none(), "gc real run failed: {:?}", resp.error);
    let payload = i4_decode_response_payload(&resp);
    assert_eq!(payload["dry_run"], false);
}

/// archive — gc with `archive=false` (memory_gc_no_archive) deletes
/// expired without preserving them. Drives the second branch of
/// `handle_gc(..., archive=false)`.
#[test]
fn chunkc_archive_gc_dry_run_returns_count() {
    chunkc_archive_gc_dry_run_body();
}

/// Body of `chunkc_archive_gc_dry_run_returns_count`, callable from the
/// #7321 isolation test on another thread.
fn chunkc_archive_gc_dry_run_body() {
    // #7321: serialise with the tests that latch the process-global audit gate.
    let _sink = crate::audit::sink_test_lock();
    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    let past = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
    let mem = Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Short,
        namespace: "chunkc-gc-dry".to_string(),
        title: "stale".to_string(),
        content: "stale".to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: Some(past),
        metadata: json!({}),
        reflection_depth: 0,
        memory_kind: crate::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: crate::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    };
    db::insert(&conn, &mem).unwrap();
    let req = make_tools_call("memory_gc", json!({"dry_run": true}));
    let resp = invoke_handle_request(&conn, &req);
    assert!(resp.error.is_none(), "gc dry-run failed: {:?}", resp.error);
    let payload = i4_decode_response_payload(&resp);
    assert_eq!(payload["dry_run"], true);
    assert!(payload["collected"].as_u64().unwrap() >= 1);
}

/// #7321 / #7379 / #7382 - the gc dry-run test must serialise with the
/// tests that latch the process-global audit gate. The proof is structural
/// and involves no latch and no wall-clock hold: this thread holds
/// `sink_test_lock`, the gc test runs on a worker, and the worker must be
/// seen blocked on that lock (observed through the lock's waiter registry)
/// before it has finished. A gc test that skips the lock finishes without
/// waiting, which fails the assertion (rust-1-98 TEST-01/TEST-02).
#[test]
fn chunkc_archive_gc_dry_run_ignores_sibling_latch_7321() {
    let sink = crate::audit::sink_test_lock();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(chunkc_archive_gc_dry_run_returns_count);
        let _ = done_tx.send(());
        outcome
    });
    let worker_id = worker.thread().id();
    // Deterministic handshake: spin until the worker is either blocked on
    // the lock (serialised) or finished (not serialised). No sleep, no timeout.
    let finished_without_waiting = loop {
        if crate::audit::sink_test_lock_is_waited_on_by(worker_id) {
            break false;
        }
        if done_rx.try_recv().is_ok() {
            break true;
        }
        std::thread::yield_now();
    };
    drop(sink);
    let outcome = worker.join().expect("worker thread joins");
    assert!(
        !finished_without_waiting,
        "gc dry-run test ran to completion without taking sink_test_lock"
    );
    assert!(
        outcome.is_ok(),
        "gc dry-run test failed once it obtained the lock"
    );
}
