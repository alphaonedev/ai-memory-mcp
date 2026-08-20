// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
//! #3007 (Wave-2 Cluster B) — postgres twin of the `epoch_advance` resolve
//! authz gate. Proves the `PostgresStore::checkpoint_resolve` SAL adapter (the
//! backend the HTTP `resolve_checkpoint` pg branch fans through) WITHHOLDS the
//! auto-supplied daemon key from an `epoch_advance` freeze anchor under the
//! certified posture — the anchor resolves but stays Unsigned / `verify()==false`
//! (so peers under `FED_REQUIRE_CHECKPOINT_SIG` reject it and it is never
//! broadcast-accepted) — and still signs it under standard posture (advisory).
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL` (skips cleanly when unset), like the
//! other `cov_postgres_*` suites. This is the ONLY test in the binary, so the
//! process-global posture env it sets cannot leak into an unrelated test.

#![cfg(feature = "sal-postgres")]
#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use ai_memory::checkpoints;
use ai_memory::enterprise_federation_posture::ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE;
use ai_memory::identity::keypair;
use ai_memory::models::{Checkpoint, CheckpointState, ConditionType};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

fn epoch_anchor(id: &str) -> Checkpoint {
    let now = chrono::Utc::now().timestamp();
    Checkpoint {
        id: id.to_string(),
        namespace: "_epoch".to_string(),
        title: "freeze".to_string(),
        condition_type: ConditionType::EpochAdvance,
        condition: serde_json::Value::Null,
        state: CheckpointState::Pending,
        created_by: "attacker".to_string(),
        resolved_by: None,
        resolution: None,
        resolution_note: None,
        signature: Vec::new(),
        resolver_pubkey: Vec::new(),
        created_at: now,
        deadline_at: None,
        resolved_at: None,
        metadata: serde_json::Value::Null,
    }
}

#[tokio::test]
async fn pg_epoch_advance_resolve_withholds_daemon_signature_under_posture_3007() {
    let Some(url) = postgres_url() else {
        return; // no live PG — skip cleanly
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ctx = CallerContext::for_agent("node-daemon");
    let kp = keypair::generate("node-daemon").expect("keypair");

    // --- Posture ENGAGED: epoch_advance resolve stays Unsigned (withheld). ---
    // SAFETY: sole test in this binary; no concurrent reader of this env.
    unsafe {
        std::env::set_var(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE, "1");
    }
    let id_engaged = format!("epoch-3007-engaged-{}", uuid::Uuid::new_v4());
    store
        .checkpoint_create(&ctx, &epoch_anchor(&id_engaged))
        .await
        .expect("create epoch_advance checkpoint");
    let now = chrono::Utc::now().timestamp();
    let outcome = store
        .checkpoint_resolve(
            &ctx,
            &id_engaged,
            CheckpointState::Resolved,
            "node-daemon",
            Some("deadbeef"),
            None,
            now,
            Some(&kp),
        )
        .await
        .expect("resolve");
    let checkpoints::ResolveOutcome::Resolved(cp) = outcome else {
        panic!("expected Resolved, got {outcome:?}");
    };
    assert!(
        cp.signature.is_empty() && cp.resolver_pubkey.is_empty(),
        "pg epoch_advance under certified posture must NOT be daemon-signed"
    );
    assert!(
        !checkpoints::verify(&cp),
        "a withheld epoch anchor must not verify (peers reject it)"
    );

    // --- Posture NOT engaged (standard): the same resolve SIGNS (advisory). ---
    // SAFETY: as above.
    unsafe {
        std::env::remove_var(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE);
    }
    let id_std = format!("epoch-3007-std-{}", uuid::Uuid::new_v4());
    store
        .checkpoint_create(&ctx, &epoch_anchor(&id_std))
        .await
        .expect("create epoch_advance checkpoint (std)");
    let now = chrono::Utc::now().timestamp();
    let outcome = store
        .checkpoint_resolve(
            &ctx,
            &id_std,
            CheckpointState::Resolved,
            "node-daemon",
            Some("deadbeef"),
            None,
            now,
            Some(&kp),
        )
        .await
        .expect("resolve std");
    let checkpoints::ResolveOutcome::Resolved(cp) = outcome else {
        panic!("expected Resolved, got {outcome:?}");
    };
    assert!(
        !cp.signature.is_empty() && checkpoints::verify(&cp),
        "under STANDARD posture the pg adapter signs epoch anchors as before (advisory)"
    );
}
