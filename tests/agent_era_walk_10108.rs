// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 step 2 (`3-agent vote (71472661)` V1V2-AGENT-ROW-VERIFY B-4, B-5,
//! B-6 and V1-AGENT-SIG-SCHEMA S-3, S-4, S-5; #10135) — the two-era agent-row
//! walk on sqlite.
//!
//! Invariant: a row that claims agent attribution counts as verified only
//! when the walk recomputed `payload_hash` from the stored domain row and
//! checked the domain signature under the daemon key resolved outside the
//! database. Every other state is a distinct, counted outcome, and
//! `fully_verified` stays false.

use std::path::PathBuf;
use std::sync::OnceLock;

use ai_memory::db;
use ai_memory::governance::daemon_signer::DaemonDomain;
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::signed_events::agent_era::{
    AgentDomainEvidence, ReceiptAnchors, SourceBinding, StoredReceiptRow, StoredTombstoneRow,
};
use ai_memory::signed_events::agent_payload::{
    AgentEventKind, AgentPayloadHash, AgentSignedPayload, AtomisationReceipt,
};
use ai_memory::signed_events::{
    AGENT_CUTOVER_EVENT_TYPE, ChainVerificationReport, RowSignatureVerdict, SignatureFailure,
    SignedEvent, SkipReason, ZERO_HASH, append_signed_event, canonical_chain_bytes, payload_hash,
    verify_audit_trail, verify_chain,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::params;
use sha2::{Digest, Sha256};

#[path = "common/home_sandbox.rs"]
mod home_sandbox;

/// The test daemon key (one per process).
const TEST_DAEMON_SEED: [u8; 32] = [0x5d; 32];
/// A key that is not the daemon's.
const OTHER_SEED: [u8; 32] = [0x2a; 32];
/// The atomisation event type.
const ATOMISATION: &str = "atomisation_complete";
/// The ladder rung below v103.
const V102_RUNG: i64 = 102;
/// Genuine rows before v103 runs.
const PREFIX_ROWS: usize = 3;
/// The fixed receipt time.
const ATOMISED_AT: &str = "2026-11-26T00:00:00Z";
/// The curator model of the fixture receipts.
const CURATOR: &str = "curator-10108";
/// The calling agent of the fixture receipts.
const CALLER: &str = "ai:caller-10108";
/// The agent label of the raw agent rows.
const AGENT: &str = "ai:agent-10108";
/// Receipts and rows in the end-to-end case (each row costs two ed25519
/// verifications at opt-level 0).
const MANY_RECEIPTS: usize = 200;
/// Wall-clock ceiling of the end-to-end case.
const MANY_CEILING_SECS: u64 = 60;
/// Unsigned receipts, tombstones and lookups in the index bound.
const INDEX_ROWS: usize = 100_000;
/// Signed receipts in the index bound.
const INDEX_SIGNED: usize = 200;
/// Wall-clock ceiling of the index bound.
const INDEX_CEILING_SECS: u64 = 60;
/// The namespace of the index bound's tombstones.
const INDEX_NAMESPACE: &str = "era-index-10108";

/// W-13 — a signature by `signer` over `body` under the receipt domain.
fn receipt_sign(signer: &SigningKey, body: &[u8]) -> [u8; 64] {
    signer
        .sign(&[DaemonDomain::AtomisationReceipt.tag(), body].concat())
        .to_bytes()
}

fn sink() -> VerifyingKey {
    static SINK: OnceLock<tempfile::TempDir> = OnceLock::new();
    SINK.get_or_init(|| {
        let dir = home_sandbox::per_test_dir("forensic-era-10108-");
        ai_memory::governance::audit::init(
            dir.path(),
            Some(SigningKey::from_bytes(&TEST_DAEMON_SEED)),
        )
        .expect("init sink");
        dir
    });
    ai_memory::governance::daemon_signer::verifying_key().expect("daemon key installed")
}

/// #10007 — the process resolves no path under the real home.
#[test]
fn test_process_resolves_no_path_under_the_real_home_10108() {
    let _ = home_sandbox::real_home();
    let _ = sink();
    home_sandbox::assert_process_isolated();
    let child = home_sandbox::per_test_dir("child-env-era-10108-");
    for (key, path) in home_sandbox::child_env(child.path()) {
        home_sandbox::assert_outside_real_home(key, &path);
    }
}

fn open_db() -> (tempfile::TempDir, PathBuf, rusqlite::Connection) {
    let _ = sink();
    let dir = home_sandbox::per_test_dir("agent-era-10108-");
    let path = dir.path().join("era-10108.db");
    let conn = db::open(&path).expect("open db");
    (dir, path, conn)
}

/// A released pre-v103 database: a fresh open writes the signed genesis
/// marker (#10145), so the legacy fixtures drop it and stamp v102, the
/// state a database written before the cutover is in.
fn open_legacy_db() -> (tempfile::TempDir, PathBuf, rusqlite::Connection) {
    let (dir, path, conn) = open_db();
    conn.execute(
        "DELETE FROM signed_events WHERE event_type = ?1",
        params![AGENT_CUTOVER_EVENT_TYPE],
    )
    .expect("drop the genesis marker");
    conn.execute_batch(&format!(
        "DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES ({V102_RUNG});"
    ))
    .expect("stamp v102");
    assert!(load_rows(&conn).is_empty(), "the legacy chain starts empty");
    (dir, path, conn)
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

fn head_sequence(conn: &rusqlite::Connection) -> i64 {
    load_rows(conn).last().map_or(0, |r| r.sequence)
}

/// One genuine daemon row through the production append path.
fn append_genuine(conn: &rusqlite::Connection) {
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: "governance.test".to_string(),
        payload_hash: payload_hash(uuid::Uuid::new_v4().as_bytes()),
        signature: Some(vec![0u8; 64]),
        attest_level: "daemon_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    append_signed_event(conn, &ev).expect("append genuine row");
}

/// A raw row at the chain head, linked to the head (a writer that bypasses
/// the production append path, as a pre-cutover binary would).
fn insert_raw(
    conn: &rusqlite::Connection,
    event_type: &str,
    attest_level: &str,
    signature: Option<&[u8]>,
) -> i64 {
    let head = load_rows(conn).pop();
    let (sequence, prev_hash) = head.map_or((1, ZERO_HASH.to_vec()), |h| {
        (
            h.sequence + 1,
            Sha256::digest(canonical_chain_bytes(&h)).to_vec(),
        )
    });
    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
        params![
            uuid::Uuid::new_v4().to_string(),
            AGENT,
            event_type,
            payload_hash(uuid::Uuid::new_v4().as_bytes()),
            signature,
            attest_level,
            chrono::Utc::now().to_rfc3339(),
            prev_hash,
            sequence
        ],
    )
    .expect("insert raw row");
    sequence
}

/// A chain of `PREFIX_ROWS` genuine rows taken back to v102 and re-opened,
/// so v103 writes the cutover marker at the head.
fn with_marker(path: &std::path::Path, conn: rusqlite::Connection) -> rusqlite::Connection {
    for _ in 0..PREFIX_ROWS {
        append_genuine(&conn);
    }
    conn.execute_batch(&format!(
        "DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES ({V102_RUNG});"
    ))
    .expect("rewind to v102");
    drop(conn);
    let conn = db::open(path).expect("re-open runs v103");
    assert_eq!(
        load_rows(&conn)
            .iter()
            .filter(|r| r.event_type == AGENT_CUTOVER_EVENT_TYPE)
            .count(),
        1,
        "v103 wrote one marker"
    );
    conn
}

/// A database whose chain carries a valid marker, so every row appended
/// after it is in the signed era.
fn open_signed_era() -> (tempfile::TempDir, rusqlite::Connection) {
    let (dir, path, conn) = open_db();
    let conn = with_marker(&path, conn);
    (dir, conn)
}

fn receipt(source_id: &str, atom_ids: &[&str]) -> AtomisationReceipt {
    AtomisationReceipt {
        source_id: source_id.to_string(),
        atomised_at: ATOMISED_AT.to_string(),
        atom_ids: atom_ids.iter().map(|a| (*a).to_string()).collect(),
        atom_count: u64::try_from(atom_ids.len()).expect("count fits"),
        calling_agent_id: CALLER.to_string(),
        curator_model: Some(CURATOR.to_string()),
    }
}

/// Store a receipt row. `sig` NULL stores an unsigned receipt.
fn store_receipt(conn: &rusqlite::Connection, r: &AtomisationReceipt, sig: Option<[u8; 64]>) {
    conn.execute(
        "INSERT INTO atomisation_receipts \
            (source_id, atomised_at, atom_ids, atom_count, calling_agent_id, curator_model, \
             signer_agent_id, signature) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            r.source_id,
            r.atomised_at,
            serde_json::to_string(&r.atom_ids).expect("atom ids json"),
            i64::try_from(r.atom_count).expect("count fits"),
            r.calling_agent_id,
            r.curator_model,
            sig.map(|_| "daemon"),
            sig.map(|s| s.to_vec()),
        ],
    )
    .expect("insert receipt");
}

/// The new-era chain row of a receipt signed by `signer`: daemon-signed,
/// `payload_hash` from the encoder, `cause_hash` the source binding.
fn append_atomisation(
    conn: &rusqlite::Connection,
    r: &AtomisationReceipt,
    signer: &SigningKey,
) -> (i64, [u8; 64]) {
    let bytes = r.canonical_bytes();
    let sig = receipt_sign(signer, &bytes);
    let pubkey = sink().to_bytes();
    let hash = AgentPayloadHash::encode(&AgentSignedPayload {
        kind: AgentEventKind::AtomisationComplete,
        signed_bytes: &bytes,
        signature: &sig,
        pubkey: &pubkey,
    });
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: ATOMISATION.to_string(),
        payload_hash: hash.to_vec(),
        signature: Some(vec![0u8; 64]),
        attest_level: "daemon_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        cause_hash: Some(SourceBinding::of_source(&r.source_id).as_bytes().to_vec()),
        ..SignedEvent::default()
    };
    append_signed_event(conn, &ev).expect("append atomisation row");
    (head_sequence(conn), sig)
}

fn daemon_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_DAEMON_SEED)
}

fn source(conn: &rusqlite::Connection) -> String {
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: format!("era-{}", uuid::Uuid::new_v4().simple()),
        title: format!("note-{}", uuid::Uuid::new_v4()),
        content: "atomised source 10108".to_string(),
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": "ai:test:10108" }),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert memory")
}

fn walk(conn: &rusqlite::Connection) -> ChainVerificationReport {
    let vk = sink();
    let chain = verify_chain(conn, None, Some(&vk)).expect("verify_chain");
    assert_eq!(chain.chain_break, None, "the fixture chain stays linked");
    chain
}

/// The defect the walk recorded for `seq`, if any.
fn defect(report: &ChainVerificationReport, seq: i64) -> Option<SignatureFailure> {
    report
        .agent_signature_defects
        .iter()
        .find(|(s, _)| *s == seq)
        .map(|(_, f)| *f)
}

fn fully_verified(report: &ChainVerificationReport) -> bool {
    report.chain_holds()
        && report.signature_failures.is_empty()
        && report.rows_positively_verified == report.rows_checked
}

/// B-4 — a genuine receipt and its daemon-signed row: recomputed from the
/// stored receipt, verified, counted positively; nothing else fails.
#[test]
fn genuine_receipt_row_is_recomputed_and_verified_10108() {
    let (_dir, conn) = open_signed_era();
    let r = receipt(&source(&conn), &["a1", "a2"]);
    let (seq, sig) = append_atomisation(&conn, &r, &daemon_key());
    store_receipt(&conn, &r, Some(sig));
    let report = walk(&conn);
    assert_eq!(defect(&report, seq), None);
    assert!(report.signature_failures.is_empty(), "{report:?}");
    assert!(fully_verified(&report), "{report:?}");
    assert_eq!(report.agent_receipts_erased, 0);
}

/// B-4 — a receipt edited after the row was written (one atom dropped): the
/// stored row no longer recomputes to the chain's hash.
#[test]
fn tampered_receipt_is_a_payload_mismatch_10108() {
    let (_dir, conn) = open_signed_era();
    let r = receipt(&source(&conn), &["a1", "a2"]);
    let (seq, sig) = append_atomisation(&conn, &r, &daemon_key());
    store_receipt(&conn, &receipt(&r.source_id, &["a1"]), Some(sig));
    let report = walk(&conn);
    assert_eq!(
        defect(&report, seq),
        Some(SignatureFailure::DomainPayloadMismatch)
    );
    assert!(report.signature_failures.contains(&seq));
    assert!(!fully_verified(&report));
}

/// B-4 — a receipt signed by a key that is not the daemon's: the recompute
/// matches but the domain signature does not verify.
#[test]
fn receipt_signed_by_another_key_is_domain_signature_invalid_10108() {
    let (_dir, conn) = open_signed_era();
    let r = receipt(&source(&conn), &["a1"]);
    let (seq, sig) = append_atomisation(&conn, &r, &SigningKey::from_bytes(&OTHER_SEED));
    store_receipt(&conn, &r, Some(sig));
    let report = walk(&conn);
    assert_eq!(
        defect(&report, seq),
        Some(SignatureFailure::DomainSignatureInvalid)
    );
    assert!(!fully_verified(&report));
}

/// B-4 — the receipt's signature column was nulled.
#[test]
fn unsigned_receipt_is_agent_signature_missing_10108() {
    let (_dir, conn) = open_signed_era();
    let r = receipt(&source(&conn), &["a1"]);
    let (seq, _) = append_atomisation(&conn, &r, &daemon_key());
    store_receipt(&conn, &r, None);
    let report = walk(&conn);
    assert_eq!(
        defect(&report, seq),
        Some(SignatureFailure::AgentSignatureMissing)
    );
    assert!(!fully_verified(&report));
}

/// B-4 — the receipt row is gone and no tombstone explains it.
#[test]
fn deleted_receipt_without_tombstone_is_domain_row_missing_10108() {
    let (_dir, conn) = open_signed_era();
    let r = receipt(&source(&conn), &["a1"]);
    let (seq, _) = append_atomisation(&conn, &r, &daemon_key());
    let report = walk(&conn);
    assert_eq!(
        defect(&report, seq),
        Some(SignatureFailure::DomainRowMissing)
    );
    assert_eq!(report.agent_receipts_erased, 0);
    assert!(!fully_verified(&report));
}

/// B-4 — a genuine receipt borrowed by a row whose signed cause names a
/// different source.
#[test]
fn receipt_of_another_source_is_a_payload_mismatch_10108() {
    let (_dir, conn) = open_signed_era();
    let r = receipt(&source(&conn), &["a1"]);
    let bytes = r.canonical_bytes();
    let sig = receipt_sign(&daemon_key(), &bytes);
    let pubkey = sink().to_bytes();
    let hash = AgentPayloadHash::encode(&AgentSignedPayload {
        kind: AgentEventKind::AtomisationComplete,
        signed_bytes: &bytes,
        signature: &sig,
        pubkey: &pubkey,
    });
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: ATOMISATION.to_string(),
        payload_hash: hash.to_vec(),
        signature: Some(vec![0u8; 64]),
        attest_level: "daemon_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        cause_hash: Some(SourceBinding::of_source("other-source").as_bytes().to_vec()),
        ..SignedEvent::default()
    };
    append_signed_event(&conn, &ev).expect("append");
    store_receipt(&conn, &r, Some(sig));
    let seq = head_sequence(&conn);
    let report = walk(&conn);
    assert_eq!(
        defect(&report, seq),
        Some(SignatureFailure::DomainPayloadMismatch)
    );
}

/// #10135 — a forget erased the receipt and left a tombstone for the
/// source: a distinct counted outcome, never verified, never a failure.
#[test]
fn receipt_erased_under_tombstone_is_counted_not_verified_10108() {
    let (_dir, conn) = open_signed_era();
    let src = source(&conn);
    let namespace: String = conn
        .query_row(
            "SELECT namespace FROM memories WHERE id = ?1",
            params![src],
            |r| r.get(0),
        )
        .expect("namespace");
    let r = receipt(&src, &["a1"]);
    let (seq, sig) = append_atomisation(&conn, &r, &daemon_key());
    store_receipt(&conn, &r, Some(sig));
    db::forget(&conn, Some(&namespace), None, None, false).expect("forget");
    let report = walk(&conn);
    assert_eq!(defect(&report, seq), None);
    assert!(!report.signature_failures.contains(&seq));
    assert_eq!(report.agent_receipts_erased, 1);
    assert!(
        report.rows_positively_verified < report.rows_checked,
        "an erased receipt is never verified: {report:?}"
    );
    assert!(!fully_verified(&report));
    let trail = verify_audit_trail(&conn, None, Some(&sink())).expect("trail");
    assert_eq!(trail.agent_receipts_erased, 1);
}

/// B-4 — a daemon-signed row with no cause binding and no receipt.
#[test]
fn row_without_cause_or_receipt_is_domain_row_missing_10108() {
    let (_dir, conn) = open_signed_era();
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: ATOMISATION.to_string(),
        payload_hash: payload_hash(b"no-receipt-10108"),
        signature: Some(vec![0u8; 64]),
        attest_level: "daemon_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    append_signed_event(&conn, &ev).expect("append");
    let seq = head_sequence(&conn);
    let report = walk(&conn);
    assert_eq!(
        defect(&report, seq),
        Some(SignatureFailure::DomainRowMissing)
    );
}

/// S-4 / B-6 — legacy agent rows (no marker): NULL and 64-byte signatures
/// are counted legacy, never failed, never verified; any other length is
/// malformed.
#[test]
fn legacy_agent_rows_are_counted_never_failed_10108() {
    let (_dir, _path, conn) = open_legacy_db();
    let null_row = insert_raw(&conn, ATOMISATION, "self_signed", None);
    let full_row = insert_raw(&conn, ATOMISATION, "self_signed", Some(&[7u8; 64]));
    let short_row = insert_raw(&conn, ATOMISATION, "self_signed", Some(&[7u8; 63]));
    let report = walk(&conn);
    assert_eq!(defect(&report, null_row), None);
    assert_eq!(defect(&report, full_row), None);
    assert!(!report.signature_failures.contains(&null_row));
    assert!(!report.signature_failures.contains(&full_row));
    assert_eq!(
        defect(&report, short_row),
        Some(SignatureFailure::AgentSignatureMalformed)
    );
    assert!(report.agent_signed_rows_not_verified >= 2, "{report:?}");
    assert!(!fully_verified(&report));
}

/// S-4 — legacy rows below the marker keep the legacy outcome.
#[test]
fn agent_rows_below_the_marker_are_legacy_10108() {
    let (_dir, path, conn) = open_legacy_db();
    let below = insert_raw(&conn, ATOMISATION, "self_signed", None);
    let conn = with_marker(&path, conn);
    let report = walk(&conn);
    assert_eq!(defect(&report, below), None);
    assert!(!report.signature_failures.contains(&below));
}

/// S-5 / S-3 residual — an agent-labelled row above the marker was written
/// by a binary that predates the cutover.
#[test]
fn agent_row_above_the_marker_is_a_pre_cutover_writer_10108() {
    let (_dir, path, conn) = open_db();
    let conn = with_marker(&path, conn);
    let signed = insert_raw(&conn, ATOMISATION, "self_signed", Some(&[7u8; 64]));
    let null = insert_raw(&conn, "memory_link.created", "self_signed", None);
    let unsigned = insert_raw(&conn, ATOMISATION, "unsigned", None);
    let report = walk(&conn);
    for seq in [signed, null, unsigned] {
        assert_eq!(
            defect(&report, seq),
            Some(SignatureFailure::PreCutoverWriter),
            "row {seq}: {report:?}"
        );
        assert!(report.signature_failures.contains(&seq));
    }
    assert!(!fully_verified(&report));
}

/// B-5 — a second marker makes the era of every agent row unresolvable.
#[test]
fn agent_row_with_an_invalid_marker_is_unresolvable_10108() {
    let (_dir, path, conn) = open_db();
    let conn = with_marker(&path, conn);
    let marker = load_rows(&conn)
        .into_iter()
        .find(|r| r.event_type == AGENT_CUTOVER_EVENT_TYPE)
        .expect("marker");
    let head = load_rows(&conn).pop().expect("head");
    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
        params![
            uuid::Uuid::new_v4().to_string(),
            marker.agent_id,
            marker.event_type,
            marker.payload_hash,
            marker.signature,
            marker.attest_level,
            marker.timestamp,
            Sha256::digest(canonical_chain_bytes(&head)).to_vec(),
            head.sequence + 1
        ],
    )
    .expect("insert second marker");
    let agent = insert_raw(&conn, ATOMISATION, "self_signed", None);
    let report = walk(&conn);
    assert_eq!(
        defect(&report, agent),
        Some(SignatureFailure::AgentEraUnresolvable)
    );
}

/// One daemon row of `event_type` with a plain (pre-encoding) payload hash,
/// through the production append path.
fn append_daemon_kind(conn: &rusqlite::Connection, event_type: &str) -> i64 {
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: event_type.to_string(),
        payload_hash: payload_hash(uuid::Uuid::new_v4().as_bytes()),
        signature: Some(vec![0u8; 64]),
        attest_level: "daemon_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    append_signed_event(conn, &ev).expect("append daemon row");
    head_sequence(conn)
}

/// B-4 era gate — a legacy-era daemon row of an agent kind predates the
/// payload encoding: with no marker, and below a valid marker, it keeps the
/// daemon-row check and verifies. Above the marker the same row has no
/// domain row and fails.
#[test]
fn legacy_daemon_agent_kind_rows_keep_the_daemon_check_10108() {
    let (_dir, path, conn) = open_legacy_db();
    let kinds = [ATOMISATION, "memory_link.created"];
    let no_marker: Vec<i64> = kinds.iter().map(|k| append_daemon_kind(&conn, k)).collect();
    let report = walk(&conn);
    for seq in &no_marker {
        assert_eq!(defect(&report, *seq), None, "row {seq}: {report:?}");
    }
    assert!(fully_verified(&report), "{report:?}");

    let conn = with_marker(&path, conn);
    let above: Vec<i64> = kinds.iter().map(|k| append_daemon_kind(&conn, k)).collect();
    let report = walk(&conn);
    for seq in &no_marker {
        assert_eq!(defect(&report, *seq), None, "below row {seq}: {report:?}");
        assert!(!report.signature_failures.contains(seq));
    }
    for seq in &above {
        assert_eq!(
            defect(&report, *seq),
            Some(SignatureFailure::DomainRowMissing),
            "above row {seq}: {report:?}"
        );
        assert!(report.signature_failures.contains(seq));
    }
}

/// B-5 era gate — under an invalid marker a daemon row of an agent kind has
/// no era to trust and fails closed.
#[test]
fn daemon_agent_kind_row_with_an_invalid_marker_is_unresolvable_10108() {
    let (_dir, path, conn) = open_db();
    let conn = with_marker(&path, conn);
    let marker = load_rows(&conn)
        .into_iter()
        .find(|r| r.event_type == AGENT_CUTOVER_EVENT_TYPE)
        .expect("marker");
    let head = load_rows(&conn).pop().expect("head");
    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
        params![
            uuid::Uuid::new_v4().to_string(),
            marker.agent_id,
            marker.event_type,
            marker.payload_hash,
            marker.signature,
            marker.attest_level,
            marker.timestamp,
            Sha256::digest(canonical_chain_bytes(&head)).to_vec(),
            head.sequence + 1
        ],
    )
    .expect("insert second marker");
    let daemon = append_daemon_kind(&conn, "memory_link.created");
    let plain = append_daemon_kind(&conn, "governance.test");
    let report = walk(&conn);
    assert_eq!(
        defect(&report, daemon),
        Some(SignatureFailure::AgentEraUnresolvable)
    );
    assert_eq!(
        defect(&report, plain),
        None,
        "a non-agent kind is unaffected"
    );
    assert!(!report.signature_failures.contains(&plain));
}

/// Unbounded input — the evidence index is built and answers in linear
/// time: `INDEX_ROWS` unsigned receipts, `INDEX_ROWS` unsigned tombstones,
/// `INDEX_ROWS` anchors and `INDEX_ROWS` row verdicts finish within the
/// ceiling (a scan per lookup would be 10^10 comparisons). Signed receipts
/// and signed tombstones are kept to `INDEX_SIGNED` because each costs one
/// ed25519 verification. An unsigned tombstone never evidences an erasure
/// (#10135) and every receipt is anchored, so no chain-level failure.
#[test]
fn evidence_index_is_linear_at_100k_10108() {
    let key = daemon_key();
    let vk = sink();
    let mut stored: Vec<StoredReceiptRow> = (0..INDEX_ROWS)
        .map(|i| StoredReceiptRow {
            source_id: format!("unsigned-{i}"),
            atomised_at: ATOMISED_AT.to_string(),
            atom_ids_json: "[\"a\"]".to_string(),
            atom_count: 1,
            calling_agent_id: CALLER.to_string(),
            curator_model: None,
            signature: None,
        })
        .collect();
    let mut hashes = Vec::with_capacity(INDEX_SIGNED);
    for i in 0..INDEX_SIGNED {
        let r = receipt(&format!("signed-{i}"), &["a"]);
        let bytes = r.canonical_bytes();
        let sig = receipt_sign(&key, &bytes);
        hashes.push(
            AgentPayloadHash::encode(&AgentSignedPayload {
                kind: AgentEventKind::AtomisationComplete,
                signed_bytes: &bytes,
                signature: &sig,
                pubkey: &vk.to_bytes(),
            })
            .to_vec(),
        );
        stored.push(StoredReceiptRow {
            source_id: r.source_id,
            atomised_at: r.atomised_at,
            atom_ids_json: "[\"a\"]".to_string(),
            atom_count: 1,
            calling_agent_id: r.calling_agent_id,
            curator_model: r.curator_model,
            signature: Some(sig.to_vec()),
        });
    }
    let tombstone = |id: String, signature: Option<Vec<u8>>| StoredTombstoneRow {
        memory_id: id,
        namespace: INDEX_NAMESPACE.to_string(),
        forgotten_at: ATOMISED_AT.to_string(),
        signature,
    };
    let mut tombstones: Vec<StoredTombstoneRow> = (0..INDEX_ROWS)
        .map(|i| tombstone(format!("unsigned-gone-{i}"), None))
        .collect();
    for i in 0..INDEX_SIGNED {
        let id = format!("gone-{i}");
        let body =
            ai_memory::storage::forget_tombstone_signing_body(&id, INDEX_NAMESPACE, ATOMISED_AT);
        let sig = key
            .sign(&[DaemonDomain::Tombstone.tag(), &body[..]].concat())
            .to_bytes();
        tombstones.push(tombstone(id, Some(sig.to_vec())));
    }
    let mut anchors = ReceiptAnchors::default();
    for i in 0..INDEX_ROWS {
        let binding = SourceBinding::of_source(&format!("unsigned-{i}"));
        anchors.insert(&payload_hash(b"x"), Some(binding.as_bytes().as_slice()));
    }
    for h in &hashes {
        anchors.insert(h, None);
    }
    let started = std::time::Instant::now();
    let ev = AgentDomainEvidence::build(&stored, &tombstones, &anchors, Some(&vk));
    assert_eq!(ev.chain_failure(), None, "every receipt is anchored");
    let row = |payload: Vec<u8>, source: &str| SignedEvent {
        event_type: ATOMISATION.to_string(),
        attest_level: "daemon_signed".to_string(),
        payload_hash: payload,
        cause_hash: Some(SourceBinding::of_source(source).as_bytes().to_vec()),
        ..SignedEvent::default()
    };
    let kind = AgentEventKind::AtomisationComplete;
    for i in 0..INDEX_ROWS {
        let unsigned = row(payload_hash(b"x"), &format!("unsigned-{i}"));
        assert_eq!(
            ev.verdict(&unsigned, kind),
            RowSignatureVerdict::Failed(SignatureFailure::AgentSignatureMissing)
        );
        let gone = row(payload_hash(b"x"), &format!("gone-{}", i % INDEX_SIGNED));
        assert_eq!(
            ev.verdict(&gone, kind),
            RowSignatureVerdict::Skipped(SkipReason::ReceiptErasedUnderTombstone)
        );
        let forged = row(payload_hash(b"x"), &format!("unsigned-gone-{i}"));
        assert_eq!(
            ev.verdict(&forged, kind),
            RowSignatureVerdict::Failed(SignatureFailure::DomainRowMissing)
        );
        let j = i % INDEX_SIGNED;
        let signed = row(hashes[j].clone(), &format!("signed-{j}"));
        assert_eq!(ev.verdict(&signed, kind), RowSignatureVerdict::Verified);
    }
    assert!(
        started.elapsed().as_secs() < INDEX_CEILING_SECS,
        "index took {:?}",
        started.elapsed()
    );
}

/// End to end — `MANY_RECEIPTS` receipts and their rows all verify.
#[test]
fn many_receipts_walk_all_verified_10108() {
    let (_dir, conn) = open_signed_era();
    let key = daemon_key();
    for i in 0..MANY_RECEIPTS {
        let r = receipt(&format!("src-{i}"), &["a"]);
        let (_, sig) = append_atomisation(&conn, &r, &key);
        store_receipt(&conn, &r, Some(sig));
    }
    let started = std::time::Instant::now();
    let report = walk(&conn);
    assert!(
        started.elapsed().as_secs() < MANY_CEILING_SECS,
        "walk took {:?}",
        started.elapsed()
    );
    assert!(report.signature_failures.is_empty(), "{report:?}");
    assert!(fully_verified(&report));
}
