// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #10074 — a daemon signature verifies under exactly one domain and one
//! preimage.
//!
//! Defect class: a verifier that accepts one signature under more than one
//! preimage form, with a key that signs caller-chosen bytes. Every test here
//! builds rows with the PRODUCTION signers (the append path, the revision-leaf
//! signer, the tombstone signer) and then presents a signature made for one
//! meaning as the signature of a `signed_events` row with another meaning. The
//! invariant: every such row lands in `signature_failures` and dirties the full
//! audit-trail verdict, on the library verifier AND the CLI verifier.
//!
//! No database here holds a legacy cutoff row, so (S-2) no legacy form is
//! accepted anywhere in the chain.

use std::process::Command;
use std::sync::OnceLock;

use ai_memory::revisions::{RecordKind, RevisionLeaf};
use ai_memory::signed_events::{
    SignedEvent, ZERO_HASH, append_signed_event, canonical_chain_bytes, daemon_row_signing_input,
    payload_hash, verify_audit_trail, verify_chain,
};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::params;
use sha2::{Digest, Sha256};

/// Deterministic seed for the one daemon key this test binary installs. The
/// process-wide signer is first-install-wins, so every test shares it.
const TEST_DAEMON_SEED: [u8; 32] = [0x5a; 32];
/// Number of genuine rows each fixture appends before forging.
const GENUINE_ROWS: i64 = 3;
/// Agent id a forger writes into a transplanted row.
const FORGED_AGENT: &str = "mallory";
/// Event type of the genuine fixture rows.
const FIXTURE_EVENT_TYPE: &str = "governance.test";

fn daemon_key() -> &'static SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let key = SigningKey::from_bytes(&TEST_DAEMON_SEED);
        ai_memory::governance::audit::init_audit_signers(Some(&key));
        key
    })
}

fn verifying_key() -> VerifyingKey {
    daemon_key().verifying_key()
}

fn open_db() -> (tempfile::TempDir, std::path::PathBuf, rusqlite::Connection) {
    let dir = tempfile::Builder::new()
        .prefix("signed-events-10074-")
        .tempdir()
        .expect("tempdir");
    let path = dir.path().join("audit-10074.db");
    let conn = ai_memory::db::open(&path).expect("open db");
    (dir, path, conn)
}

/// Append one genuine daemon-signed row through the production append path
/// (which signs the row's identity at its final sequence).
fn append_genuine(conn: &rusqlite::Connection, n: i64) {
    let _ = daemon_key();
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: FIXTURE_EVENT_TYPE.to_string(),
        payload_hash: payload_hash(format!("payload-{n}").as_bytes()),
        // Any `Some` marks the row for daemon re-signing at append.
        signature: Some(vec![0u8; 64]),
        attest_level: "daemon_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    append_signed_event(conn, &ev).expect("append genuine row");
}

fn load_rows(conn: &rusqlite::Connection) -> Vec<SignedEvent> {
    let mut stmt = conn
        .prepare(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
                    timestamp, prev_hash, sequence, cause_hash \
             FROM signed_events ORDER BY sequence ASC",
        )
        .expect("prepare");
    stmt.query_map([], |r| {
        Ok(SignedEvent {
            id: r.get(0)?,
            agent_id: r.get(1)?,
            event_type: r.get(2)?,
            payload_hash: r.get(3)?,
            signature: r.get(4)?,
            attest_level: r.get(5)?,
            timestamp: r.get(6)?,
            prev_hash: r.get::<_, Option<Vec<u8>>>(7)?.unwrap_or_default(),
            sequence: r.get(8)?,
            cause_hash: r.get(9)?,
        })
    })
    .expect("query")
    .collect::<rusqlite::Result<Vec<_>>>()
    .expect("collect")
}

fn canon_hash(ev: &SignedEvent) -> Vec<u8> {
    Sha256::digest(canonical_chain_bytes(ev)).to_vec()
}

/// Rewrite every `prev_hash` so the cross-row hash chain is intact again after
/// a forger replaced or added a row. `prev_hash` is not under any row
/// signature, so the genuine rows' signatures survive the relink.
fn relink(conn: &rusqlite::Connection) {
    let rows = load_rows(conn);
    let mut prev = ZERO_HASH.to_vec();
    for row in &rows {
        conn.execute(
            "UPDATE signed_events SET prev_hash = ?1 WHERE sequence = ?2",
            params![prev, row.sequence],
        )
        .expect("relink");
        let mut linked = row.clone();
        linked.prev_hash.clone_from(&prev);
        prev = canon_hash(&linked);
    }
}

/// Replace the row at `seq` with a forged one carrying `payload` and
/// `signature`, attributed to [`FORGED_AGENT`], then relink the chain.
fn forge_row_at(conn: &rusqlite::Connection, seq: i64, payload: &[u8], signature: &[u8]) {
    conn.execute(
        "UPDATE signed_events SET id = ?1, agent_id = ?2, payload_hash = ?3, signature = ?4, \
             attest_level = 'daemon_signed', cause_hash = NULL WHERE sequence = ?5",
        params![
            uuid::Uuid::new_v4().to_string(),
            FORGED_AGENT,
            payload,
            signature,
            seq
        ],
    )
    .expect("forge row");
    relink(conn);
}

/// Append a forged row at the head carrying `payload` and `signature`, then
/// relink the chain.
fn forge_head_row(conn: &rusqlite::Connection, payload: &[u8], signature: &[u8]) -> i64 {
    let next: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM signed_events",
            [],
            |r| r.get(0),
        )
        .expect("next seq");
    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, 'daemon_signed', ?6, ?7, ?8, NULL)",
        params![
            uuid::Uuid::new_v4().to_string(),
            FORGED_AGENT,
            FIXTURE_EVENT_TYPE,
            payload,
            signature,
            chrono::Utc::now().to_rfc3339(),
            ZERO_HASH.to_vec(),
            next
        ],
    )
    .expect("insert forged head row");
    relink(conn);
    next
}

/// Assert the full verifiers convict `seq` with an intact hash chain (so the
/// conviction is the signature check, not a chain break).
fn assert_convicted(conn: &rusqlite::Connection, seq: i64, what: &str) {
    let vk = verifying_key();
    let chain = verify_chain(conn, None, Some(&vk)).expect("verify_chain");
    assert_eq!(
        chain.chain_break, None,
        "{what}: the relinked chain is intact"
    );
    assert!(
        chain.signature_failures.contains(&seq),
        "{what}: row {seq} must be a signature failure; got {:?}",
        chain.signature_failures
    );
    let trail = verify_audit_trail(conn, None, Some(&vk)).expect("verify_audit_trail");
    assert!(
        !trail.is_clean(),
        "{what}: the full audit-trail verdict must be dirty"
    );
}

/// S-1 — a row's identity signature moved into another row (with any agent
/// id) is refused: the signature was made for one row identity, not as a
/// signature over an arbitrary 32-byte payload hash.
#[test]
fn s1_identity_signature_transplant_into_prefix_row_is_dirty_10074() {
    let (_dir, _path, conn) = open_db();
    for n in 1..=GENUINE_ROWS {
        append_genuine(&conn, n);
    }
    let rows = load_rows(&conn);
    let donor = rows.last().expect("donor row");
    let donor_sig = donor.signature.clone().expect("donor signed");
    let identity_digest = daemon_row_signing_input(donor);
    forge_row_at(&conn, 2, &identity_digest, &donor_sig);
    assert_convicted(&conn, 2, "identity-signature transplant");
}

/// A revision-leaf signature (made by the production leaf signer over the
/// leaf's signable bytes) presented as a `signed_events` row is refused.
#[test]
fn revision_leaf_signature_transplant_is_dirty_10074() {
    let (_dir, _path, conn) = open_db();
    for n in 1..=GENUINE_ROWS {
        append_genuine(&conn, n);
    }
    let leaf = RevisionLeaf::new(
        uuid::Uuid::new_v4().to_string(),
        "mem-10074",
        RecordKind::Supersede,
        Some(1),
        "ns-10074",
        Some("alice".to_string()),
        chrono::Utc::now().to_rfc3339(),
    )
    .signed();
    let sig = leaf
        .signature
        .clone()
        .expect("leaf signed by the daemon key");
    let seq = forge_head_row(&conn, &leaf.signable_bytes(), &sig);
    assert_convicted(&conn, seq, "revision-leaf transplant");
}

/// A forget-tombstone signature (made by the production tombstone signer)
/// presented as a `signed_events` row is refused.
#[test]
fn tombstone_signature_transplant_is_dirty_10074() {
    let (_dir, _path, conn) = open_db();
    for n in 1..=GENUINE_ROWS {
        append_genuine(&conn, n);
    }
    let now = chrono::Utc::now().to_rfc3339();
    ai_memory::storage::evict_tombstone_and_erase(&conn, "mem-10074-t", "ns-10074", None, &now)
        .expect("tombstone");
    let sig: Vec<u8> = conn
        .query_row(
            "SELECT signature FROM forget_tombstones WHERE memory_id = 'mem-10074-t'",
            [],
            |r| r.get(0),
        )
        .expect("tombstone signature");
    let body = ai_memory::storage::forget_tombstone_signable_bytes("mem-10074-t", "ns-10074", &now);
    let seq = forge_head_row(&conn, &body, &sig);
    assert_convicted(&conn, seq, "tombstone transplant");
}

/// The cross-domain matrix over every production signature form reachable
/// at base: each donor signature, placed in a row whose payload is the exact
/// bytes the donor signed, is refused.
#[test]
fn cross_domain_matrix_every_donor_refused_10074() {
    let (_dir, _path, conn) = open_db();
    for n in 1..=GENUINE_ROWS {
        append_genuine(&conn, n);
    }
    let rows = load_rows(&conn);
    let mut donors: Vec<(&str, Vec<u8>, Vec<u8>)> = Vec::new();
    for row in &rows {
        donors.push((
            "event-row",
            daemon_row_signing_input(row),
            row.signature.clone().expect("signed"),
        ));
    }
    let leaf = RevisionLeaf::new(
        "leaf-m",
        "mem-m",
        RecordKind::Forget,
        None,
        "ns-m",
        None,
        "2026-11-24T00:00:00Z",
    )
    .signed();
    donors.push((
        "revision-leaf",
        leaf.signable_bytes(),
        leaf.signature.clone().expect("leaf signed"),
    ));
    let now = chrono::Utc::now().to_rfc3339();
    ai_memory::storage::evict_tombstone_and_erase(&conn, "mem-m-t", "ns-m", None, &now)
        .expect("tombstone");
    let tomb_sig: Vec<u8> = conn
        .query_row(
            "SELECT signature FROM forget_tombstones WHERE memory_id = 'mem-m-t'",
            [],
            |r| r.get(0),
        )
        .expect("tombstone signature");
    donors.push((
        "tombstone",
        ai_memory::storage::forget_tombstone_signable_bytes("mem-m-t", "ns-m", &now),
        tomb_sig,
    ));
    let mut forged = Vec::new();
    for (name, body, sig) in &donors {
        forged.push((*name, forge_head_row(&conn, body, sig)));
    }
    let vk = verifying_key();
    let chain = verify_chain(&conn, None, Some(&vk)).expect("verify_chain");
    assert_eq!(chain.chain_break, None, "relinked chain intact");
    let missed: Vec<_> = forged
        .iter()
        .filter(|(_, seq)| !chain.signature_failures.contains(seq))
        .collect();
    assert!(
        missed.is_empty(),
        "every cross-domain donor must be refused; accepted: {missed:?}"
    );
}

/// A legacy payload-only row whose identity columns were rewritten is refused
/// when it sits above the cutoff (here: no cutoff at all).
#[test]
fn identity_rewrite_of_legacy_row_above_cutoff_is_dirty_10074() {
    let (_dir, _path, conn) = open_db();
    for n in 1..=GENUINE_ROWS {
        append_genuine(&conn, n);
    }
    // The legacy (pre-#1925) daemon form: the signature over the payload hash
    // alone, as the pre-identity append path stored it.
    let ph = payload_hash(b"legacy-payload");
    let sig = daemon_key().sign(&ph).to_bytes().to_vec();
    let seq = forge_head_row(&conn, &ph, &sig);
    assert_convicted(&conn, seq, "identity rewrite of a legacy row");
}

/// S-2 — a database with no cutoff row accepts no legacy form: a genuine,
/// untampered payload-only row is refused, also when the walk starts above it.
#[test]
fn missing_cutoff_refuses_every_payload_only_row_10074() {
    let (_dir, _path, conn) = open_db();
    for n in 1..=GENUINE_ROWS {
        append_genuine(&conn, n);
    }
    let ph = payload_hash(b"legacy-genuine");
    let sig = daemon_key().sign(&ph).to_bytes().to_vec();
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1, signature = ?2 WHERE sequence = 3",
        params![ph, sig],
    )
    .expect("legacy row");
    relink(&conn);
    assert_convicted(&conn, 3, "untampered payload-only row with no cutoff");
    let vk = verifying_key();
    let windowed = verify_chain(&conn, Some(1), Some(&vk)).expect("verify_chain since 1");
    assert!(
        windowed.signature_failures.contains(&3),
        "a walk that starts above the (absent) cutoff still refuses the row; got {:?}",
        windowed.signature_failures
    );
}

/// S-8 — the CLI verifier passes a verifier: with the audit pin enrolled it
/// reports the forged row and exits non-zero.
#[test]
fn cli_verify_signed_events_chain_convicts_forged_row_10074() {
    let (dir, path, conn) = open_db();
    for n in 1..=GENUINE_ROWS {
        append_genuine(&conn, n);
    }
    let rows = load_rows(&conn);
    let donor = rows.last().expect("donor");
    let donor_sig = donor.signature.clone().expect("signed");
    forge_row_at(&conn, 2, &daemon_row_signing_input(donor), &donor_sig);
    drop(conn);
    let pin = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key().to_bytes());
    let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("HOME", dir.path())
        .env("AI_MEMORY_AUDIT_PUBKEY", &pin)
        .args([
            "--db",
            path.to_str().expect("utf-8 path"),
            "verify-signed-events-chain",
            "--format",
            "json",
        ])
        .output()
        .expect("run ai-memory");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the CLI verifier must exit 1 on a forged row; stdout: {stdout}"
    );
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    let failures = report["signature_failures"]
        .as_array()
        .expect("signature_failures array");
    assert!(
        failures.iter().any(|v| v.as_i64() == Some(2)),
        "the CLI report names the forged row; got {stdout}"
    );
}
