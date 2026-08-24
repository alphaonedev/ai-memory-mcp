// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1956 [P1][R56] — crypto-erase via per-record envelope-key destruction +
//! mandatory tombstones on EVERY delete path + signed erasure attestation.
//!
//! Gate-2 acceptance criteria (issue #1956):
//!
//! * **Crypto-erase primitive** — for an ENCRYPTED per-record (`0x03`) row,
//!   erasure destroys the embedded wrapped DEK so the ciphertext is
//!   cryptographically unrecoverable (not merely row-deleted).
//! * **Mandatory tombstones on every delete path** — `forget`, `gc`
//!   (hard-delete), and `size_gc` (hard-delete) each emit a `forget_tombstones`
//!   row so a forgotten/evicted memory cannot be resurrected via federation LWW.
//! * **Erasure attestation** — a signed `substrate.crypto_erase` event lands on
//!   the append-only `signed_events` chain and the chain still verifies.
//! * **Honest limit** — a PLAINTEXT (or legacy `0x02`) row can only be
//!   row-deleted + tombstoned, NOT crypto-erased.
//! * **Restart persistence** — a crypto-erased envelope survives a DB reopen.

use ai_memory::encryption::{
    crypto_erase_marker, envelope_is_crypto_erasable, envelope_is_erased, get_or_create_keypair,
    seal_content_per_record,
};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::signed_events::{event_types, verify_audit_trail};
use ai_memory::storage as db;
use ai_memory::storage::ErasureKind;
use rusqlite::{OptionalExtension, params};

#[path = "key_dir_sandbox.rs"]
mod key_dir_sandbox;

fn fresh_conn() -> rusqlite::Connection {
    let _ = key_dir_sandbox::pin();
    db::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

fn make_mem(title: &str, content: &str, ns: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

/// Insert a memory whose content is sealed under a `0x03` per-record envelope
/// keyed to `agent`, returning the row id. Mirrors the storage seal path but
/// keeps the test deterministic without touching the global encryption flag.
fn insert_encrypted(
    conn: &rusqlite::Connection,
    agent: &str,
    title: &str,
    plaintext: &str,
    ns: &str,
) -> String {
    let _ = key_dir_sandbox::pin();
    let kp = get_or_create_keypair(agent).expect("keypair");
    let sealed = seal_content_per_record(plaintext, &kp.public).expect("seal per-record");
    assert!(
        envelope_is_crypto_erasable(&sealed),
        "seal must produce a 0x03 envelope"
    );
    let mut mem = make_mem(title, "", ns);
    mem.metadata = serde_json::json!({ "agent_id": agent });
    let id = db::insert(conn, &mem).expect("insert");
    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        params![sealed, &id],
    )
    .expect("persist envelope");
    id
}

fn crypto_erase_event_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        params![event_types::SUBSTRATE_CRYPTO_ERASE],
        |r| r.get(0),
    )
    .expect("count crypto_erase events")
}

fn tombstone_exists(conn: &rusqlite::Connection, id: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM forget_tombstones WHERE memory_id = ?1)",
        params![id],
        |r| r.get(0),
    )
    .expect("tombstone existence")
}

fn envelope_bytes(conn: &rusqlite::Connection, id: &str) -> Option<Vec<u8>> {
    conn.query_row(
        "SELECT encrypted_envelope FROM memories WHERE id = ?1",
        params![id],
        |r| r.get::<_, Option<Vec<u8>>>(0),
    )
    .optional()
    .expect("read envelope")
    .flatten()
}

#[test]
fn encrypted_record_reads_back_then_crypto_erase_makes_it_unrecoverable() {
    let conn = fresh_conn();
    let agent = "r56-erase-agent";
    let plaintext = "launch codes 1138 0451 4815";
    let id = insert_encrypted(&conn, agent, "r56-erase", plaintext, "global");

    // Pre-erase: the 0x03 read path recovers the plaintext transparently.
    let mem = db::get(&conn, &id).expect("get").expect("present");
    assert_eq!(mem.content, plaintext, "0x03 envelope must decrypt on read");

    // Destroy the per-record envelope key.
    let destroyed = db::crypto_erase_record_envelope(&conn, &id).expect("crypto-erase");
    assert!(
        destroyed,
        "an encrypted per-record row must report key-destroyed"
    );

    // The stored envelope is now the 0x04 erased marker.
    let env = envelope_bytes(&conn, &id).expect("envelope present");
    assert!(
        envelope_is_erased(&env),
        "envelope must be the crypto-erased marker"
    );

    // Post-erase: the ciphertext is unrecoverable — reads fail-closed.
    let err = db::get(&conn, &id).expect_err("erased row must fail-closed on read");
    assert!(
        format!("{err}").contains("crypto-erased") || format!("{err}").contains("decrypt failed"),
        "unexpected error: {err}"
    );
}

#[test]
fn forget_encrypted_row_emits_tombstone_and_signed_attestation() {
    let conn = fresh_conn();
    let agent = "r56-forget-agent";
    let id = insert_encrypted(&conn, agent, "r56-forget", "forget me — encrypted", "fgt");

    let before = crypto_erase_event_count(&conn);
    let deleted = db::forget(&conn, Some("fgt"), None, None, false).expect("forget");
    assert!(deleted >= 1, "forget must delete the row");

    // Mandatory tombstone.
    assert!(
        tombstone_exists(&conn, &id),
        "forget must emit a tombstone (federation resurrection guard)"
    );
    // Signed erasure attestation.
    assert!(
        crypto_erase_event_count(&conn) > before,
        "forget must emit a substrate.crypto_erase attestation"
    );
    // Row is gone.
    assert!(
        db::get(&conn, &id).expect("get").is_none(),
        "forgotten row must be deleted"
    );
    // The audit chain still verifies with the new event chained in.
    let report = verify_audit_trail(&conn, None, None).expect("verify audit trail");
    assert!(
        report.chain_intact,
        "signed_events chain must remain intact after the erasure attestation"
    );
}

#[test]
fn gc_hard_delete_emits_tombstone_and_attestation() {
    let conn = fresh_conn();
    let agent = "r56-gc-agent";
    let id = insert_encrypted(&conn, agent, "r56-gc", "expire me — encrypted", "gcn");
    // Force TTL expiry in the past.
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    conn.execute(
        "UPDATE memories SET expires_at = ?1 WHERE id = ?2",
        params![past, &id],
    )
    .expect("set past expiry");

    let before = crypto_erase_event_count(&conn);
    let reaped = db::gc(&conn, false).expect("gc hard-delete");
    assert!(reaped >= 1, "gc must reap the expired row");
    assert!(
        tombstone_exists(&conn, &id),
        "gc hard-delete must emit a tombstone"
    );
    assert!(
        crypto_erase_event_count(&conn) > before,
        "gc hard-delete must emit a crypto_erase attestation"
    );
    assert!(
        db::get(&conn, &id).expect("get").is_none(),
        "gc'd row must be gone"
    );
    assert!(
        verify_audit_trail(&conn, None, None)
            .expect("verify")
            .chain_intact
    );
}

#[test]
fn size_gc_hard_delete_emits_tombstone_and_attestation() {
    let conn = fresh_conn();
    let agent = "r56-sizegc-agent";
    let id = insert_encrypted(&conn, agent, "r56-sizegc", "evict me — encrypted", "sgc");

    let before = crypto_erase_event_count(&conn);
    // Cap of 1 byte forces eviction of the single row.
    let evicted = db::size_gc(&conn, "sgc", 1, false).expect("size_gc hard-delete");
    assert!(evicted >= 1, "size_gc must evict the over-cap row");
    assert!(
        tombstone_exists(&conn, &id),
        "size_gc hard-delete must emit a tombstone"
    );
    assert!(
        crypto_erase_event_count(&conn) > before,
        "size_gc hard-delete must emit a crypto_erase attestation"
    );
    assert!(
        db::get(&conn, &id).expect("get").is_none(),
        "evicted row must be gone"
    );
    assert!(
        verify_audit_trail(&conn, None, None)
            .expect("verify")
            .chain_intact
    );
}

#[test]
fn plaintext_record_is_tombstoned_not_crypto_erased_honest_limit() {
    let conn = fresh_conn();
    // A plaintext row (no envelope) has NO per-record key to destroy.
    let mut mem = make_mem("r56-plaintext", "plain content, not encrypted", "pln");
    mem.metadata = serde_json::json!({ "agent_id": "r56-plain-agent" });
    let id = db::insert(&conn, &mem).expect("insert plaintext");

    // crypto_erase reports NO key destroyed → classified row-deleted-tombstoned.
    let destroyed = db::crypto_erase_record_envelope(&conn, &id).expect("crypto-erase probe");
    assert!(
        !destroyed,
        "a plaintext row is NOT crypto-erasable (honest limit)"
    );
    assert_eq!(
        ErasureKind::RowDeletedTombstoned.as_str(),
        "row-deleted-tombstoned"
    );
    assert_eq!(ErasureKind::KeyDestroyed.as_str(), "key-destroyed");

    // The forget path still tombstones + attests it (delete with no tombstone
    // is the #1956 defect — must not happen even for plaintext).
    let before = crypto_erase_event_count(&conn);
    let deleted = db::forget(&conn, Some("pln"), None, None, false).expect("forget plaintext");
    assert!(deleted >= 1);
    assert!(
        tombstone_exists(&conn, &id),
        "even a plaintext delete must tombstone"
    );
    assert!(
        crypto_erase_event_count(&conn) > before,
        "plaintext delete still emits an attestation"
    );
}

#[test]
fn crypto_erase_persists_across_db_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("r56-restart.db");
    let agent = "r56-restart-agent";
    let id = {
        let conn = db::open(&path).expect("open file db");
        let id = insert_encrypted(&conn, agent, "r56-restart", "shred and reopen", "rst");
        let destroyed = db::crypto_erase_record_envelope(&conn, &id).expect("crypto-erase");
        assert!(destroyed);
        id
        // conn dropped here (modeled restart)
    };

    // Reopen the same file — the crypto-erased envelope must persist.
    let conn2 = db::open(&path).expect("reopen file db");
    let env = envelope_bytes(&conn2, &id).expect("envelope present after reopen");
    assert!(
        envelope_is_erased(&env),
        "erased envelope must survive a restart"
    );
    assert!(
        db::get(&conn2, &id).is_err(),
        "erased row must still fail-closed on read after a restart"
    );
}

#[test]
fn crypto_erase_marker_and_predicates_are_consistent() {
    let marker = crypto_erase_marker();
    assert!(envelope_is_erased(&marker));
    assert!(!envelope_is_crypto_erasable(&marker));
    assert!(!envelope_is_erased(&[]));
    assert!(!envelope_is_crypto_erasable(&[]));
}
