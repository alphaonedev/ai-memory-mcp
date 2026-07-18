// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2004 (spec §5.3, vote `4d3ea1c5`) — end-to-end tests for the
//! crypto-agility RE-ANCHOR ceremony wired into the `checkpoints` table.
//!
//! The ceremony countersigns the current `signed_events` chain head under the
//! enrolled suite (the FROZEN `re-anchor/v1` format,
//! `ai_memory::identity::re_anchor`) and persists it as a signed
//! [`ConditionType::ReAnchor`] checkpoint — mirroring the #1822 audit-head
//! witness's off-daemon-custody, K1-pinnable persistence. These tests prove
//! the ceremony ROUND-TRIPS (emit → reload → verify) and FAIL-CLOSES on every
//! tamper class, on both backends (K3).
//!
//! Pins:
//! - (a) emit → the persisted anchor verifies; the decoded record binds the
//!   real head sequence + the Ed25519 suite tag.
//! - (b) a tampered `resolution` (envelope broken) → `EnvelopeInvalid`.
//! - (c) a tampered detached countersignature (envelope RE-SIGNED so only the
//!   inner signature is wrong) → `CountersignatureInvalid`.
//! - (d) verify under a DIFFERENT enrolled key → `PubkeyNotEnrolled` (K1).
//! - (e) a non-re-anchor checkpoint → `NotReAnchor`.
//! - (f) no witness key enrolled / an empty chain → `Ok(None)` (opt-in no-op).
//! - (g) `#[cfg(feature = "sal-postgres")]` postgres parity: the same built
//!   anchor inserted + read back through the pg SAL verifies identically.
//!
//! The witness key-dir / pubkey env vars are process-global, so every test
//! serialises via a module-local lock and clears the env on exit (the #1822
//! discipline).

#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::governance::audit::{self as witness, ReAnchorCheckpointError};
use ai_memory::identity::cbor_array::SUITE_ED25519_SHA256;
use ai_memory::models::ConditionType;
use ai_memory::signed_events::{
    SignedEvent, append_signed_event, emit_reanchor_ceremony, payload_hash,
};
use rusqlite::Connection;

/// Process-global serialisation for the witness ENV.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock() -> MutexGuard<'static, ()> {
    env_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Tempdirs under `.local-runs/` (project no-`/tmp` HARD RULE).
fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-2004-reanchor");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn open_db(dir: &std::path::Path) -> (PathBuf, Connection) {
    let path = dir.join("audit.db");
    drop(ai_memory::db::open(&path).expect("init db"));
    let conn = ai_memory::db::open(&path).expect("open db");
    (path, conn)
}

/// Enrol a fresh witness keypair into a temp custody dir + the out-of-band
/// pubkey env. Returns the keypair (private held by the test). Caller MUST
/// already hold [`lock`]. Paired with [`clear_witness_env`].
fn enrol_witness(dir: &std::path::Path) -> ai_memory::identity::keypair::AgentKeypair {
    let kp = ai_memory::identity::keypair::generate(witness::WITNESS_KEY_LABEL).expect("gen");
    ai_memory::identity::keypair::save(&kp, dir).expect("save witness key");
    unsafe {
        std::env::set_var(witness::WITNESS_KEY_DIR_ENV, dir);
        std::env::set_var(witness::WITNESS_PUBKEY_ENV, kp.public_base64());
    }
    kp
}

fn clear_witness_env() {
    unsafe {
        std::env::remove_var(witness::WITNESS_KEY_DIR_ENV);
        std::env::remove_var(witness::WITNESS_PUBKEY_ENV);
    }
}

fn append_rows(conn: &Connection, n: usize) {
    for i in 0..n {
        let payload = format!("payload-{i}");
        let ev = SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "alice".to_string(),
            event_type: "memory_link.created".to_string(),
            payload_hash: payload_hash(payload.as_bytes()),
            signature: None,
            attest_level: "unsigned".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ..SignedEvent::default()
        };
        append_signed_event(conn, &ev).expect("append");
    }
}

// ── (a) emit → persisted anchor verifies + binds the real head ──────────────

#[test]
fn emit_then_verify_round_trips() {
    let _g = lock();
    let kdir = fresh_dir("a-keys");
    let ddir = fresh_dir("a-db");
    let kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 5);
    let cp = emit_reanchor_ceremony(&conn)
        .expect("emit ok")
        .expect("a witness key is enrolled and the chain is non-empty → Some");

    assert_eq!(cp.condition_type, ConditionType::ReAnchor);
    assert_eq!(cp.namespace, witness::REANCHOR_CHECKPOINT_NAMESPACE);
    assert_eq!(cp.resolver_pubkey, kp.public.to_bytes().to_vec());

    let record = witness::verify_reanchor_checkpoint(&cp, &kp.public)
        .expect("the freshly-persisted anchor verifies under the enrolled key");
    // The ceremony countersigned the CURRENT head (sequence 5) under Ed25519.
    assert_eq!(record.prior_head_sequence, 5);
    assert_eq!(record.new_suite_tag, SUITE_ED25519_SHA256);

    clear_witness_env();
}

// ── (b) tampered resolution → the ENVELOPE signature catches it ─────────────

#[test]
fn verify_rejects_tampered_resolution() {
    let _g = lock();
    let kdir = fresh_dir("b-keys");
    let ddir = fresh_dir("b-db");
    let kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 3);
    let mut cp = emit_reanchor_ceremony(&conn)
        .expect("emit ok")
        .expect("Some");

    // Flip a byte inside the signed resolution string — the checkpoint envelope
    // signature is computed over the whole resolution, so ANY mutation breaks
    // it BEFORE the inner countersignature is even reached.
    let mut res = cp.resolution.take().expect("resolution present");
    let last = res.pop().expect("non-empty");
    res.push(if last == 'A' { 'B' } else { 'A' });
    cp.resolution = Some(res);

    assert_eq!(
        witness::verify_reanchor_checkpoint(&cp, &kp.public),
        Err(ReAnchorCheckpointError::EnvelopeInvalid),
    );

    clear_witness_env();
}

// ── (c) tampered inner countersig (envelope re-signed) → CountersignatureInvalid ──

#[test]
fn verify_rejects_tampered_countersignature() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let _g = lock();
    let kdir = fresh_dir("c-keys");
    let ddir = fresh_dir("c-db");
    let kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 4);
    let mut cp = emit_reanchor_ceremony(&conn)
        .expect("emit ok")
        .expect("Some");

    // Swap the detached countersignature for a valid-length-but-wrong one
    // (64 zero bytes), then RE-SIGN the envelope so the outer signature passes
    // — isolating the inner-countersignature check as the sole gate.
    let mut wire: serde_json::Value =
        serde_json::from_str(cp.resolution.as_deref().unwrap()).expect("resolution json");
    wire["re_anchor_sig"] = serde_json::Value::String(B64.encode([0u8; 64]));
    cp.resolution = Some(serde_json::to_string(&wire).unwrap());
    ai_memory::checkpoints::sign_resolution_into(&mut cp, &kp).expect("re-sign envelope");

    match witness::verify_reanchor_checkpoint(&cp, &kp.public) {
        Err(ReAnchorCheckpointError::CountersignatureInvalid(_)) => {}
        other => panic!("expected CountersignatureInvalid, got {other:?}"),
    }

    clear_witness_env();
}

// ── (d) K1: verify under a DIFFERENT enrolled key → PubkeyNotEnrolled ────────

#[test]
fn verify_rejects_wrong_enrolled_pubkey() {
    let _g = lock();
    let kdir = fresh_dir("d-keys");
    let ddir = fresh_dir("d-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 3);
    let cp = emit_reanchor_ceremony(&conn)
        .expect("emit ok")
        .expect("Some");

    let attacker = ai_memory::identity::keypair::generate("attacker").expect("gen");
    assert_eq!(
        witness::verify_reanchor_checkpoint(&cp, &attacker.public),
        Err(ReAnchorCheckpointError::PubkeyNotEnrolled),
    );

    clear_witness_env();
}

// ── (e) a non-re-anchor checkpoint → NotReAnchor ────────────────────────────

#[test]
fn verify_rejects_non_reanchor_checkpoint() {
    let _g = lock();
    let kdir = fresh_dir("e-keys");
    let ddir = fresh_dir("e-db");
    let kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());

    append_rows(&conn, 3);
    let mut cp = emit_reanchor_ceremony(&conn)
        .expect("emit ok")
        .expect("Some");
    // Re-label the condition type: the type guard refuses it up-front, before
    // any signature work.
    cp.condition_type = ConditionType::AuditHeadWitness;
    assert_eq!(
        witness::verify_reanchor_checkpoint(&cp, &kp.public),
        Err(ReAnchorCheckpointError::NotReAnchor),
    );

    clear_witness_env();
}

// ── (f) opt-in no-op: no key enrolled / empty chain → Ok(None) ──────────────

#[test]
fn no_witness_key_is_noop() {
    let _g = lock();
    let ddir = fresh_dir("f-db");
    clear_witness_env(); // ensure no key is enrolled
    let (_path, conn) = open_db(ddir.path());
    append_rows(&conn, 3);
    assert!(
        emit_reanchor_ceremony(&conn).expect("ok").is_none(),
        "no enrolled witness key → the ceremony is a no-op",
    );
}

#[test]
fn empty_chain_is_noop() {
    let _g = lock();
    let kdir = fresh_dir("g-keys");
    let ddir = fresh_dir("g-db");
    let _kp = enrol_witness(kdir.path());
    let (_path, conn) = open_db(ddir.path());
    // No rows appended → head sequence 0 → nothing to anchor.
    assert!(
        emit_reanchor_ceremony(&conn).expect("ok").is_none(),
        "an empty signed_events chain → the ceremony is a no-op",
    );
    clear_witness_env();
}

// ── (g) postgres parity (live-gated) — same anchor, pg round-trip verifies ──

#[cfg(feature = "sal-postgres")]
mod postgres_parity {
    use super::*;
    use ai_memory::store::MemoryStore;
    use ai_memory::store::postgres::PostgresStore;

    async fn live_pg() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        match PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skip: postgres connect failed: {e}");
                None
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL — live postgres"]
    async fn reanchor_checkpoint_round_trips_through_pg() {
        let Some(pg) = live_pg().await else {
            return;
        };
        let kp = ai_memory::identity::keypair::generate(witness::WITNESS_KEY_LABEL).expect("gen");
        // Build the anchor backend-agnostically (a synthetic head), then persist
        // + reload through the pg SAL: proves the ConditionType::ReAnchor text
        // spelling + the resolution/signature BYTEA survive the pg round-trip.
        let head = [0xAB_u8; 32];
        let now = chrono::Utc::now();
        let cp = witness::build_signed_reanchor_checkpoint(
            &head,
            7,
            &now.to_rfc3339(),
            now.timestamp(),
            &kp,
        )
        .expect("build re-anchor checkpoint");

        let ctx = ai_memory::store::CallerContext::for_agent("ai:2004-pg-parity");
        pg.checkpoint_create(&ctx, &cp)
            .await
            .expect("pg checkpoint_create");
        let reloaded = pg
            .checkpoint_get(&ctx, &cp.id)
            .await
            .expect("pg checkpoint_get")
            .expect("row present");

        assert_eq!(reloaded.condition_type, ConditionType::ReAnchor);
        let record = witness::verify_reanchor_checkpoint(&reloaded, &kp.public)
            .expect("pg-reloaded anchor verifies identically to sqlite (K3)");
        assert_eq!(record.prior_head_sequence, 7);
        assert_eq!(record.new_suite_tag, SUITE_ED25519_SHA256);

        sqlx::query("DELETE FROM checkpoints WHERE id = $1")
            .bind(&cp.id)
            .execute(pg.pool())
            .await
            .ok();
    }
}
