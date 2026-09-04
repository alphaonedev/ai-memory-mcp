// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 G17 (#1831 / #2007) — live-Postgres integration coverage for the
//! M-of-N threshold key-RECOVERY mint + recovery-aware resolution on the
//! Postgres SAL adapter.
//!
//! The pre-#2007 postgres `append_lineage_record` unconditionally REFUSED a
//! `LineageReason::Recovery` mint ("cannot be minted in v0.9.0"), and
//! `current_authoritative_key` used the recovery-BLIND `verify_lineage`. The
//! Gate-3 cleanup (#2007) brought the postgres path to K3 parity with the
//! sqlite SSOT (`crate::storage::{append_lineage_record,current_authoritative_key}`):
//! the recovery branch verifies the M-of-N guardian quorum via
//! `verify_recovery_record`, and resolution routes through
//! `verify_lineage_with_recovery`. These tests exercise those exact new lines
//! against a live Postgres backend (the existing pg lineage tests only cover
//! genesis/rotation, so the recovery branch was uncovered → the Per-Module
//! coverage floor regressed).
//!
//! Mirrors the sqlite twin `storage::tests::recovery_1831_ceremony_persists_and_verifies`
//! + the negative arm in `tests/identity_lineage_succession.rs`.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; self-skips cleanly when unset (the
//! CI Per-Module coverage leg sets it, so the recovery lines are covered there).

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]
// The recovery-guardian env vars are process-global; hold the file-local lock
// across the whole test body (incl. awaits) so a sibling test in this binary
// can't flip them mid-ceremony. Each #[tokio::test] runs on its own runtime
// thread, so holding the std Mutex across awaits merely serialises the file's
// tests — which is the point.
#![allow(clippy::await_holding_lock)]

use std::sync::Mutex;

use ed25519_dalek::Signer;

use ai_memory::identity::keypair;
use ai_memory::identity::lineage::{
    LineageRecord, RECOVERY_GUARDIAN_PUBKEYS_ENV, RECOVERY_THRESHOLD_ENV, RecoveryAttestation,
    encode_recovery_quorum, guardian_set_id_digest,
};
use ai_memory::identity::sign::sign_succession;
use ai_memory::models::AgentRegistration;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

/// Serialises this file's tests — the recovery-guardian env vars are global.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn connect() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn set_guardian_env(guardians: &[keypair::AgentKeypair], threshold: usize) {
    let joined = guardians
        .iter()
        .map(keypair::AgentKeypair::public_base64)
        .collect::<Vec<_>>()
        .join(",");
    // SAFETY: test-only env mutation, serialised by `env_guard()` above; each
    // tokio::test owns its runtime thread so there is no concurrent reader.
    unsafe {
        std::env::set_var(RECOVERY_GUARDIAN_PUBKEYS_ENV, joined);
        std::env::set_var(RECOVERY_THRESHOLD_ENV, threshold.to_string());
    }
}

fn clear_guardian_env() {
    // SAFETY: see `set_guardian_env`.
    unsafe {
        std::env::remove_var(RECOVERY_GUARDIAN_PUBKEYS_ENV);
        std::env::remove_var(RECOVERY_THRESHOLD_ENV);
    }
}

async fn register(store: &PostgresStore, ctx: &CallerContext, agent_id: &str) {
    let reg = AgentRegistration {
        agent_id: agent_id.to_string(),
        agent_type: "nhi".to_string(),
        capabilities: vec!["read".to_string(), "write".to_string()],
        registered_at: chrono::Utc::now().to_rfc3339(),
        last_seen_at: chrono::Utc::now().to_rfc3339(),
    };
    store
        .register_agent(ctx, &reg)
        .await
        .expect("register agent");
}

/// Enroll a genesis record (epoch 0, self-signed by `k0`) through the postgres
/// SAL `append_lineage_record` — the same funnel the recovery record uses —
/// and return it so the recovery record can hash-link to the persisted head.
async fn enroll_genesis(
    store: &PostgresStore,
    ctx: &CallerContext,
    agent_id: &str,
    k0: &keypair::AgentKeypair,
    recovery_pub_b64: &str,
) -> LineageRecord {
    let genesis = LineageRecord::genesis(
        agent_id,
        &k0.public_base64(),
        Some(recovery_pub_b64.to_string()),
        "2026-07-10T00:00:00+00:00",
    );
    let sig = sign_succession(k0, &genesis.to_signable()).expect("sign genesis");
    store
        .append_lineage_record(ctx, agent_id, &genesis, &sig)
        .await
        .expect("enroll genesis on postgres");
    genesis
}

/// A guardian's detached Ed25519 attestation over the recovery signing input.
fn guardian_attest(recovery: &LineageRecord, g: &keypair::AgentKeypair) -> RecoveryAttestation {
    let input = recovery.signing_input().expect("recovery signing input");
    let sig = g
        .private
        .as_ref()
        .expect("guardian keypair can sign")
        .sign(&input);
    RecoveryAttestation {
        guardian_pubkey_b64: g.public_base64(),
        signature: sig.to_bytes().to_vec(),
    }
}

// ---------------------------------------------------------------------------
// 1. Happy path — a 2-of-3 guardian quorum mints a fresh head through the
//    postgres recovery branch, and `current_authoritative_key` resolves it via
//    `verify_lineage_with_recovery`.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_recovery_mint_persists_and_resolves_authoritative_head() {
    let Some(store) = connect().await else { return };
    let _g = env_guard();

    let agent_id = format!("ai:rec-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent(&agent_id);
    register(&store, &ctx, &agent_id).await;

    let k0 = keypair::generate(&agent_id).expect("k0");
    let cold = keypair::generate(&agent_id).expect("cold recovery key");
    let genesis = enroll_genesis(&store, &ctx, &agent_id, &k0, &cold.public_base64()).await;

    // Prepare an otherwise-valid K0-signed rotation before revocation. The
    // signature must become stale authority once the history head is closed.
    let stale_successor = keypair::generate(&agent_id).expect("stale successor");
    let stale_rotation = LineageRecord::rotation(
        &genesis,
        &stale_successor.public_base64(),
        None,
        "2026-07-10T12:00:00+00:00",
    )
    .expect("prepare stale rotation");
    let stale_signature =
        sign_succession(&k0, &stale_rotation.to_signable()).expect("sign before revoke");
    store
        .revoke_agent_pubkey(&ctx, &agent_id)
        .await
        .expect("close postgres history head");
    let stale_error = store
        .append_lineage_record(&ctx, &agent_id, &stale_rotation, &stale_signature)
        .await
        .expect_err("predecessor signature prepared before revoke must not reopen the head");
    assert!(
        matches!(
            &stale_error,
            ai_memory::store::StoreError::PermissionDenied { .. }
        ),
        "closed-head refusal stays typed: {stale_error}"
    );
    assert_eq!(store.agent_pubkey(&agent_id).await.expect("flat"), None);
    assert_eq!(
        store.read_lineage(&agent_id).await.expect("lineage").len(),
        1
    );

    // K0 is LOST/revoked. Enroll 3 guardians (2-of-3) and mint a fresh head.
    let k_new = keypair::generate(&agent_id).expect("k_new");
    let guardians: Vec<keypair::AgentKeypair> = (0..3)
        .map(|_| keypair::generate("guardian").expect("guardian"))
        .collect();
    let gid = guardian_set_id_digest(&guardians.iter().map(|g| g.public).collect::<Vec<_>>());
    set_guardian_env(&guardians, 2);

    let recovery = LineageRecord::recovery(
        &genesis,
        &k_new.public_base64(),
        None,
        None,
        gid,
        2,
        "2026-07-11T00:00:00+00:00",
    )
    .expect("recovery record");
    let quorum = vec![
        guardian_attest(&recovery, &guardians[0]),
        guardian_attest(&recovery, &guardians[1]),
    ];
    let quorum_blob = encode_recovery_quorum(&quorum).expect("encode quorum");

    // The pre-#2007 postgres path REFUSED this unconditionally; now it verifies
    // the M-of-N quorum and persists.
    store
        .append_lineage_record(&ctx, &agent_id, &recovery, &quorum_blob)
        .await
        .expect("postgres recovery mint must persist the fresh head");

    let history = store
        .agent_pubkey_versions(&agent_id)
        .await
        .expect("postgres history");
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[1].bind_authority,
        ai_memory::identity::pubkey_bind::BindAuthority::GuardianRecovery.as_str(),
        "guardian recovery must be distinguishable in the durable audit history"
    );

    store
        .append_lineage_record(&ctx, &agent_id, &recovery, &quorum_blob)
        .await
        .expect_err("a persisted guardian recovery cannot be replayed");
    assert_eq!(
        store
            .agent_pubkey_versions(&agent_id)
            .await
            .expect("history after replay refusal")
            .len(),
        2,
        "replay refusal leaves key history unchanged"
    );

    // Recovery-aware resolution (verify_lineage_with_recovery) resolves the
    // fresh primary as the authoritative head.
    let head = store
        .current_authoritative_key(&agent_id)
        .await
        .expect("infra ok")
        .expect("chain resolves to a head via the guardian quorum");
    assert_eq!(
        head,
        k_new.public_base64(),
        "postgres current_authoritative_key must resolve the recovered head"
    );

    // Also drive the lineage check inside `verify_audit_trail`, which routes
    // through `verify_agent_lineage_pg` → the recovery-aware
    // `verify_lineage_with_recovery` (#2007 parity). The recovery env is still
    // set, so the enrolled recovered chain verifies rather than fail-closing.
    // The shared test DB carries unrelated rows, so we assert only that the
    // walk succeeds at the infra level (not a whole-chain verdict).
    store
        .verify_audit_trail(None, None)
        .await
        .expect("verify_audit_trail walks the recovery-aware lineage check");

    clear_guardian_env();
}

// ---------------------------------------------------------------------------
// 2. Fail-closed — a quorum of ONE (below the committed threshold of 2) is
//    refused by `verify_recovery_record`; nothing persists.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_recovery_mint_below_threshold_is_refused() {
    let Some(store) = connect().await else { return };
    let _g = env_guard();

    let agent_id = format!("ai:rec-under-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent(&agent_id);
    register(&store, &ctx, &agent_id).await;

    let k0 = keypair::generate(&agent_id).expect("k0");
    let cold = keypair::generate(&agent_id).expect("cold");
    let genesis = enroll_genesis(&store, &ctx, &agent_id, &k0, &cold.public_base64()).await;

    let k_new = keypair::generate(&agent_id).expect("k_new");
    let guardians: Vec<keypair::AgentKeypair> = (0..3)
        .map(|_| keypair::generate("guardian").expect("guardian"))
        .collect();
    let gid = guardian_set_id_digest(&guardians.iter().map(|g| g.public).collect::<Vec<_>>());
    set_guardian_env(&guardians, 2);

    let recovery = LineageRecord::recovery(
        &genesis,
        &k_new.public_base64(),
        None,
        None,
        gid,
        2, // committed threshold 2
        "2026-07-11T00:00:00+00:00",
    )
    .expect("recovery record");
    // Only ONE guardian signs — below the committed threshold.
    let quorum = vec![guardian_attest(&recovery, &guardians[0])];
    let quorum_blob = encode_recovery_quorum(&quorum).expect("encode quorum");

    let err = store
        .append_lineage_record(&ctx, &agent_id, &recovery, &quorum_blob)
        .await
        .expect_err("under-threshold quorum must be refused");
    assert!(
        err.to_string().contains("unverifiable recovery record"),
        "expected the recovery-verify refusal, got: {err}"
    );

    // Nothing was persisted — the head is still unset (no rotation applied).
    let head = store
        .current_authoritative_key(&agent_id)
        .await
        .expect("infra ok");
    assert_eq!(
        head.as_deref(),
        Some(k0.public_base64().as_str()),
        "a refused recovery must leave the genesis head unchanged"
    );

    clear_guardian_env();
}

// ---------------------------------------------------------------------------
// 3. Fail-closed — no guardians enrolled (RecoveryPolicy::from_env == None)
//    refuses the mint before any signature check.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pg_recovery_mint_without_enrolled_guardians_is_refused() {
    let Some(store) = connect().await else { return };
    let _g = env_guard();
    clear_guardian_env(); // ensure no policy resolvable

    let agent_id = format!("ai:rec-noguard-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent(&agent_id);
    register(&store, &ctx, &agent_id).await;

    let k0 = keypair::generate(&agent_id).expect("k0");
    let cold = keypair::generate(&agent_id).expect("cold");
    let genesis = enroll_genesis(&store, &ctx, &agent_id, &k0, &cold.public_base64()).await;

    let k_new = keypair::generate(&agent_id).expect("k_new");
    let guardians: Vec<keypair::AgentKeypair> = (0..3)
        .map(|_| keypair::generate("guardian").expect("guardian"))
        .collect();
    let gid = guardian_set_id_digest(&guardians.iter().map(|g| g.public).collect::<Vec<_>>());
    let recovery = LineageRecord::recovery(
        &genesis,
        &k_new.public_base64(),
        None,
        None,
        gid,
        2,
        "2026-07-11T00:00:00+00:00",
    )
    .expect("recovery record");
    let quorum = vec![
        guardian_attest(&recovery, &guardians[0]),
        guardian_attest(&recovery, &guardians[1]),
    ];
    let quorum_blob = encode_recovery_quorum(&quorum).expect("encode quorum");

    let err = store
        .append_lineage_record(&ctx, &agent_id, &recovery, &quorum_blob)
        .await
        .expect_err("no enrolled guardians must refuse the mint");
    assert!(
        err.to_string().contains("no recovery guardians enrolled"),
        "expected the no-guardians refusal, got: {err}"
    );
}
