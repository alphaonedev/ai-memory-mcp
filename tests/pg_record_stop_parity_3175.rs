// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// #1986: crate-level `//!` docs are still linted when `#![cfg(feature =
// "sal-postgres")]` is false (the allow below that cfg is configured out).
#![allow(clippy::doc_markdown)]

//! v1.0.0 #3175 — the record-stop kill switch must cover the postgres
//! `undo_in_place_edit` / `recover_turn_idempotent` write paths, and
//! `record_stop_status` must answer from the PERSISTED chain, not a stale
//! process-local cache.
//!
//! The scenario is the one that actually exists in production: two daemons
//! (two pools) against one postgres cluster. `store_a` connects while the
//! plane is RUNNING; `store_b` engages the stop. Pre-#3175:
//!
//! * `store_a.record_stop_status()` answered from the cache it seeded at
//!   `connect` and confidently reported RUNNING while the chain said STOPPED;
//! * `store_a.undo_in_place_edit()` (a destructive content restore that also
//!   appends a signed audit event) and `store_a.recover_turn_idempotent()`
//!   contained ZERO `gate_record_stop` calls and wrote anyway.
//!
//! This is the SOLE test in this binary and it releases the stop before it
//! returns: engaging the record plane is a cluster-wide state on the shared
//! test database.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL` (skips cleanly when unset).

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use ai_memory::models::{Memory, RecoverTurnWrite};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

#[tokio::test]
async fn pg_record_stop_covers_undo_and_recover_and_reads_the_chain_3175() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        return; // no live PG — skip cleanly
    };
    // `store_a` connects FIRST, while the plane is running: its cache is
    // seeded RUNNING and only a chain read can correct it.
    let store_a = PostgresStore::connect(&url).await.expect("connect store_a");
    let store_b = PostgresStore::connect(&url).await.expect("connect store_b");
    let ctx = CallerContext::for_admin("ai:3175");

    // Engage from the OTHER pool, then always release (even on panic path we
    // release explicitly below; the assertions are ordered so the release runs).
    store_b
        .record_stop(&ctx, true, "ai:3175", "test")
        .await
        .expect("engage record-stop");

    let status = store_a
        .record_stop_status(&ctx)
        .await
        .expect("record_stop_status");
    let stopped_seen = status.stopped;

    // Both formerly-ungated write paths must now refuse. The ids are
    // deliberately NONEXISTENT: a `Stopped` result therefore also proves the
    // gate runs BEFORE the row lookup (an ungated body would return NotFound).
    let undo = store_a
        .undo_in_place_edit(&ctx, "no-such-id-3175", false)
        .await;
    let undo_stopped = matches!(undo, Err(StoreError::Stopped { .. }));

    let now = chrono::Utc::now().to_rfc3339();
    let write = RecoverTurnWrite {
        memory: Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: "recover-3175".to_string(),
            title: "turn".to_string(),
            content: "body".to_string(),
            source: "test".to_string(),
            created_at: now.clone(),
            updated_at: now,
            ..Default::default()
        },
        normalized_sha256: vec![1_u8; 32],
        raw_sha256: vec![2_u8; 32],
        host_kind: "test".to_string(),
        transcript_path: "/dev/null".to_string(),
        host_session_id: Some(uuid::Uuid::new_v4().to_string()),
        host_turn_index: Some(0),
        recovered_at_ms: chrono::Utc::now().timestamp_millis(),
    };
    let recovered_id = write.memory.id.clone();
    let recover = store_a.recover_turn_idempotent(&ctx, &write).await;
    let recover_stopped = matches!(recover, Err(StoreError::Stopped { .. }));
    let row_landed: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM memories WHERE id = $1)")
            .bind(&recovered_id)
            .fetch_one(store_a.pool())
            .await
            .expect("recovered-row probe");

    // Release BEFORE asserting so a failure cannot leave the cluster stopped.
    store_b
        .record_stop(&ctx, false, "ai:3175", "test")
        .await
        .expect("release record-stop");

    assert!(
        stopped_seen,
        "#3175: record_stop_status must derive from the persisted signed_events \
         chain — a stop engaged by ANOTHER pool left this one reporting RUNNING"
    );
    assert!(
        undo_stopped,
        "#3175: undo_in_place_edit must refuse with Stopped on a stopped plane \
         (it restores content over the live row and appends a signed audit \
         event); got {undo:?}"
    );
    assert!(
        recover_stopped,
        "#3175: recover_turn_idempotent must refuse with Stopped on a stopped \
         plane; got {recover:?}"
    );
    assert!(
        !row_landed,
        "#3175: no durable row may land while the record plane is STOPPED"
    );

    // The release must be visible through the same chain-derived read.
    let after = store_a
        .record_stop_status(&ctx)
        .await
        .expect("record_stop_status after release");
    assert!(
        !after.stopped,
        "#3175: the resume must be visible to every pool through the chain"
    );
}
