// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 slice 2 (`3-agent vote (71472661)` V1-10108-STEP3-WRITERS W-12,
//! W-13, W-14 and V1-AGENT-SIG-SCHEMA S-4, S-6; #10135) — the atomisation
//! receipt on sqlite.
//!
//! Invariant: after the v103 marker every atomisation receipt is signed by
//! the daemon under its own typed domain and written in one transaction with
//! the source's dedup column and its chain row. The walk takes the era only
//! from the chain row's position relative to the marker. A receipt with no
//! chain row, a post-marker row over a raw-signed receipt, a signature made
//! under any other domain, and an erasure claim no daemon tombstone signature
//! backs are never verified. A pre-marker receipt is counted legacy and no
//! byte of it is rewritten.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ai_memory::atomisation::curator::{Atom, Curator, CuratorError};
use ai_memory::atomisation::{AtomiseError, Atomiser, AtomiserConfig};
use ai_memory::config::FeatureTier;
use ai_memory::db;
use ai_memory::governance::daemon_signer::{self, DaemonDomain};
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::signed_events::agent_era::SourceBinding;
use ai_memory::signed_events::agent_payload::{
    AgentEventKind, AgentPayloadHash, AgentSignedPayload, AtomisationReceipt,
};
use ai_memory::signed_events::{
    AGENT_CUTOVER_EVENT_TYPE, CHAIN_LEVEL_FAILURE_SEQUENCE, ChainVerificationReport,
    SignatureFailure, SignedEvent, append_signed_event, payload_hash, verify_chain,
};
use ai_memory::storage::forget_tombstone_signing_body;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::params;

#[path = "common/home_sandbox.rs"]
mod home_sandbox;

/// The test daemon key (one per process).
const TEST_DAEMON_SEED: [u8; 32] = [0x5d; 32];
/// The receipt domain tag (W-13). The tests find the domain by this tag at
/// run time, so the binary builds on a tree that lacks the domain.
const RECEIPT_TAG: &[u8] = b"ai-memory/daemon-sig/v2/atomisation-receipt\0";
/// The S-6 version tag every receipt encoding starts with.
const RECEIPT_ENCODING_TAG: &[u8] = b"ai-memory/atomisation-receipt-v1\0";
/// W-13: the receipt domain is the seventh daemon domain.
const DAEMON_DOMAIN_COUNT: usize = 7;
const ATOMISATION: &str = "atomisation_complete";
const LINK_CREATED: &str = "memory_link.created";
/// The raw receipts the released-database fixture writes before the marker.
const PRE_MARKER_RECEIPTS: u64 = 3;
const V102_RUNG: i64 = 102;
const PREFIX_ROWS: usize = 3;
const ATOMISED_AT: &str = "2026-11-27T00:00:00Z";
const CALLER: &str = "ai:caller-10108";
const CURATOR: &str = "curator-10108";
/// The reason the walk prints for a receipt no chain row anchors (W-14).
const ORPHAN_REASON: &str = "agent_receipt_chain_row_missing";
/// Paragraphs in a source long enough to atomise.
const SOURCE_PARAGRAPHS: usize = 30;
const MAX_ATOM_TOKENS: u32 = 200;
/// The tombstone forgotten-at of a hand-written tombstone.
const FORGOTTEN_AT: &str = "2026-11-27T01:00:00Z";

fn sink() -> VerifyingKey {
    static SINK: OnceLock<tempfile::TempDir> = OnceLock::new();
    SINK.get_or_init(|| {
        let dir = home_sandbox::per_test_dir("receipt-sink-10108-");
        ai_memory::governance::audit::init(
            dir.path(),
            Some(SigningKey::from_bytes(&TEST_DAEMON_SEED)),
        )
        .expect("init sink");
        dir
    });
    daemon_signer::verifying_key().expect("daemon key installed")
}

/// The atomiser writes through process-wide hooks; one atomise at a time.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static M: Mutex<()> = Mutex::new(());
    M.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn receipt_domain() -> DaemonDomain {
    *DaemonDomain::ALL
        .iter()
        .find(|d| d.tag() == RECEIPT_TAG)
        .expect("W-13: DaemonDomain::ALL holds the atomisation-receipt domain")
}

fn daemon_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_DAEMON_SEED)
}

/// A daemon signature over `body` under the receipt domain.
fn receipt_sign(body: &[u8]) -> [u8; 64] {
    let pre = [RECEIPT_TAG, body].concat();
    daemon_key().sign(&pre).to_bytes()
}

fn open_db() -> (tempfile::TempDir, PathBuf, rusqlite::Connection) {
    let _ = sink();
    let dir = home_sandbox::per_test_dir("receipt-10108-");
    let path = dir.path().join("receipt-10108.db");
    let conn = db::open(&path).expect("open db");
    (dir, path, conn)
}

/// W-14 — a released pre-v103 database: a fresh open writes the signed
/// genesis marker (#10145), so the fixture drops it and stamps v102, the
/// state of a database written before the cutover.
fn open_released_db() -> (tempfile::TempDir, PathBuf, rusqlite::Connection) {
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
    assert_eq!(head_sequence(&conn), 0, "the released chain starts empty");
    (dir, path, conn)
}

fn head_sequence(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM signed_events",
        [],
        |r| r.get(0),
    )
    .expect("head")
}

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

/// Take the database back to v102 and re-open it, so v103 writes the marker
/// at the head; every row already present is below the marker.
fn rewind_and_reopen(path: &Path, conn: rusqlite::Connection) -> rusqlite::Connection {
    conn.execute_batch(&format!(
        "DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES ({V102_RUNG});"
    ))
    .expect("rewind to v102");
    drop(conn);
    let conn = db::open(path).expect("re-open runs v103");
    let markers: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            [AGENT_CUTOVER_EVENT_TYPE],
            |r| r.get(0),
        )
        .expect("count markers");
    assert_eq!(markers, 1, "v103 wrote one marker");
    conn
}

fn open_signed_era() -> (tempfile::TempDir, PathBuf, rusqlite::Connection) {
    let (dir, path, conn) = open_db();
    for _ in 0..PREFIX_ROWS {
        append_genuine(&conn);
    }
    let conn = rewind_and_reopen(&path, conn);
    (dir, path, conn)
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

/// The chain row of a receipt whose stored signature is `sig`.
fn append_row(conn: &rusqlite::Connection, r: &AtomisationReceipt, sig: &[u8; 64]) -> i64 {
    let bytes = r.canonical_bytes();
    let pubkey = sink().to_bytes();
    let hash = AgentPayloadHash::encode(&AgentSignedPayload {
        kind: AgentEventKind::AtomisationComplete,
        signed_bytes: &bytes,
        signature: sig,
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
    head_sequence(conn)
}

fn long_body() -> String {
    (0..SOURCE_PARAGRAPHS)
        .map(|i| {
            format!(
                "Paragraph {i}: the rolling deploy strategy required canary health checks. \
                 The readiness probe must pass before traffic shifts. Failures roll back \
                 within thirty seconds. Dashboards track replica counts and error rates."
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn source(conn: &rusqlite::Connection) -> String {
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: format!("receipt-{}", uuid::Uuid::new_v4().simple()),
        title: format!("source-{}", uuid::Uuid::new_v4()),
        content: long_body(),
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": "ai:test:10108" }),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert memory")
}

fn walk(conn: &rusqlite::Connection) -> ChainVerificationReport {
    let chain = verify_chain(conn, None, Some(&sink())).expect("verify_chain");
    assert_eq!(chain.chain_break, None, "the fixture chain stays linked");
    chain
}

fn defect(report: &ChainVerificationReport, seq: i64) -> Option<SignatureFailure> {
    report
        .agent_signature_defects
        .iter()
        .find(|(s, _)| *s == seq)
        .map(|(_, f)| *f)
}

fn orphan_reported(report: &ChainVerificationReport) -> bool {
    report
        .agent_signature_defects
        .iter()
        .any(|(s, f)| *s == CHAIN_LEVEL_FAILURE_SEQUENCE && f.reason() == ORPHAN_REASON)
        && report
            .signature_failures
            .contains(&CHAIN_LEVEL_FAILURE_SEQUENCE)
}

fn fully_verified(report: &ChainVerificationReport) -> bool {
    report.chain_holds()
        && report.signature_failures.is_empty()
        && report.rows_positively_verified == report.rows_checked
}

// ---------------------------------------------------------------- W-13

/// W-13 — the receipt domain is the seventh domain, its tag is a prefix of
/// no other tag, and a receipt signature verifies under its own domain only:
/// never under the other six, never under the raw rule; and the reverse.
#[test]
fn receipt_domain_is_separated_from_every_other_domain_and_raw_10108() {
    let vk = sink();
    let domain = receipt_domain();
    assert_eq!(DaemonDomain::ALL.len(), DAEMON_DOMAIN_COUNT);
    let body = receipt("src-w13", &["a1", "a2"]).canonical_bytes();
    assert!(body.starts_with(RECEIPT_ENCODING_TAG), "S-6 version tag");
    let (sig, _) = daemon_signer::sign(domain, &body).expect("daemon key installed");
    assert!(daemon_signer::verify(&vk, domain, &body, &sig));
    let raw = daemon_key().sign(&body).to_bytes();
    assert!(
        !daemon_signer::verify(&vk, domain, &body, &raw),
        "a raw signature verifies under the receipt domain"
    );
    let sig_bytes = <[u8; 64]>::try_from(sig.as_slice()).expect("64 bytes");
    assert!(
        vk.verify_strict(&body, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
            .is_err(),
        "a receipt-domain signature verifies under the raw rule"
    );
    let others: Vec<DaemonDomain> = DaemonDomain::ALL
        .iter()
        .copied()
        .filter(|d| *d != domain)
        .collect();
    assert_eq!(others.len(), DAEMON_DOMAIN_COUNT - 1);
    for other in others {
        assert!(!other.tag().starts_with(RECEIPT_TAG) && !RECEIPT_TAG.starts_with(other.tag()));
        assert!(
            !daemon_signer::verify(&vk, other, &body, &sig),
            "a receipt signature verifies under {other:?}"
        );
        let (theirs, _) = daemon_signer::sign(other, &body).expect("daemon key installed");
        assert!(
            !daemon_signer::verify(&vk, domain, &body, &theirs),
            "a {other:?} signature verifies under the receipt domain"
        );
    }
}

// ---------------------------------------------------------------- W-12 / W-13 walk

/// W-13 — a genuine receipt signed under the receipt domain verifies.
#[test]
fn domain_signed_receipt_verifies_10108() {
    let (_dir, _path, conn) = open_signed_era();
    let r = receipt(&source(&conn), &["a1", "a2"]);
    let sig = receipt_sign(&r.canonical_bytes());
    let seq = append_row(&conn, &r, &sig);
    store_receipt(&conn, &r, Some(sig));
    let report = walk(&conn);
    assert_eq!(defect(&report, seq), None, "{report:?}");
    assert!(fully_verified(&report), "{report:?}");
}

/// W-12 — a post-marker chain row over a raw-signed receipt is Failed.
#[test]
fn post_marker_row_over_raw_signed_receipt_fails_10108() {
    let (_dir, _path, conn) = open_signed_era();
    let r = receipt(&source(&conn), &["a1"]);
    let raw = daemon_key().sign(&r.canonical_bytes()).to_bytes();
    let seq = append_row(&conn, &r, &raw);
    store_receipt(&conn, &r, Some(raw));
    let report = walk(&conn);
    assert_eq!(
        defect(&report, seq),
        Some(SignatureFailure::DomainSignatureInvalid)
    );
    assert!(!fully_verified(&report));
}

/// W-13 (walk) — a receipt signed under each other daemon domain is Failed.
#[test]
fn receipt_signed_under_another_domain_fails_10108() {
    let domain = receipt_domain();
    for other in DaemonDomain::ALL.iter().copied().filter(|d| *d != domain) {
        let (_dir, _path, conn) = open_signed_era();
        let r = receipt(&source(&conn), &["a1"]);
        let (sig, _) = daemon_signer::sign(other, &r.canonical_bytes()).expect("key");
        let sig = <[u8; 64]>::try_from(sig.as_slice()).expect("64 bytes");
        let seq = append_row(&conn, &r, &sig);
        store_receipt(&conn, &r, Some(sig));
        let report = walk(&conn);
        assert_eq!(
            defect(&report, seq),
            Some(SignatureFailure::DomainSignatureInvalid),
            "{other:?}"
        );
    }
}

/// W-12 — a receipt field (an `atomised_at` before the marker) cannot move
/// a post-marker row into the legacy era: the raw-signed receipt still fails.
#[test]
fn receipt_field_cannot_change_the_era_10108() {
    let (_dir, _path, conn) = open_signed_era();
    let mut r = receipt(&source(&conn), &["a1"]);
    r.atomised_at = "1970-01-01T00:00:00Z".to_string();
    let raw = daemon_key().sign(&r.canonical_bytes()).to_bytes();
    let seq = append_row(&conn, &r, &raw);
    store_receipt(&conn, &r, Some(raw));
    let report = walk(&conn);
    assert_eq!(
        defect(&report, seq),
        Some(SignatureFailure::DomainSignatureInvalid)
    );
}

// ---------------------------------------------------------------- W-14

/// W-14 — a signed receipt that no chain row anchors is a chain-level
/// failure, on a full walk and on a windowed walk.
#[test]
fn receipt_without_chain_row_is_never_verified_10108() {
    let (_dir, _path, conn) = open_signed_era();
    let r = receipt(&source(&conn), &["a1"]);
    store_receipt(&conn, &r, Some(receipt_sign(&r.canonical_bytes())));
    append_genuine(&conn);
    let report = walk(&conn);
    assert!(orphan_reported(&report), "{report:?}");
    assert!(!fully_verified(&report));
    let windowed =
        verify_chain(&conn, Some(head_sequence(&conn) - 1), Some(&sink())).expect("windowed walk");
    assert!(orphan_reported(&windowed), "{windowed:?}");
}

/// W-14 — an unsigned receipt with no chain row is reported too.
#[test]
fn unsigned_receipt_without_chain_row_is_reported_10108() {
    let (_dir, _path, conn) = open_signed_era();
    let r = receipt(&source(&conn), &["a1"]);
    store_receipt(&conn, &r, None);
    let report = walk(&conn);
    assert!(orphan_reported(&report), "{report:?}");
}

/// W-14 — a database with pre-marker raw receipts upgrades through v103 and
/// stays fully verified; no receipt byte and no chain row byte is rewritten.
#[test]
fn pre_marker_raw_receipts_upgrade_verified_and_byte_identical_10108() {
    let (_dir, path, conn) = open_released_db();
    append_genuine(&conn);
    for atoms in [&["a1"][..], &["b1", "b2"], &["c1", "c2", "c3"]] {
        let r = receipt(&source(&conn), atoms);
        let raw = daemon_key().sign(&r.canonical_bytes()).to_bytes();
        append_row(&conn, &r, &raw);
        store_receipt(&conn, &r, Some(raw));
    }
    let before = dump(&conn);
    let conn = rewind_and_reopen(&path, conn);
    let after = dump(&conn);
    assert_eq!(before.0, after.0, "a receipt byte was rewritten");
    assert_eq!(
        before.1[..],
        after.1[..before.1.len()],
        "a chain row byte was rewritten"
    );
    let report = walk(&conn);
    assert!(fully_verified(&report), "{report:?}");
    assert!(!orphan_reported(&report));
    assert_eq!(
        report.agent_receipts_legacy, PRE_MARKER_RECEIPTS,
        "W-12: each pre-marker receipt is counted legacy"
    );
}

type Dump = (
    Vec<Vec<rusqlite::types::Value>>,
    Vec<Vec<rusqlite::types::Value>>,
);

fn dump(conn: &rusqlite::Connection) -> Dump {
    let read = |sql: &str, n: usize| {
        let mut stmt = conn.prepare(sql).expect("prepare dump");
        stmt.query_map([], |r| {
            (0..n)
                .map(|i| r.get::<_, rusqlite::types::Value>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .expect("query dump")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect dump")
    };
    (
        read(
            "SELECT source_id, atomised_at, atom_ids, atom_count, calling_agent_id, \
                    curator_model, signer_agent_id, signature \
             FROM atomisation_receipts ORDER BY source_id, atomised_at",
            8,
        ),
        read(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
                    timestamp, prev_hash, sequence, cause_hash \
             FROM signed_events ORDER BY sequence",
            10,
        ),
    )
}

// ---------------------------------------------------------------- #10135

fn namespace_of(conn: &rusqlite::Connection, id: &str) -> String {
    conn.query_row(
        "SELECT namespace FROM memories WHERE id = ?1",
        params![id],
        |r| r.get(0),
    )
    .expect("namespace")
}

fn insert_tombstone(conn: &rusqlite::Connection, id: &str, ns: &str, sig: Option<&[u8]>) {
    conn.execute(
        "INSERT INTO forget_tombstones (memory_id, namespace, forgotten_at, agent_id, signature) \
         VALUES (?1, ?2, ?3, NULL, ?4)",
        params![id, ns, FORGOTTEN_AT, sig],
    )
    .expect("insert tombstone");
}

/// #10135 — a receipt removed by hand with an unsigned tombstone written for
/// its source is a missing domain row, never an erasure.
#[test]
fn unsigned_tombstone_does_not_excuse_a_missing_receipt_10135() {
    let (_dir, _path, conn) = open_signed_era();
    let src = source(&conn);
    let r = receipt(&src, &["a1"]);
    let seq = append_row(&conn, &r, &receipt_sign(&r.canonical_bytes()));
    insert_tombstone(&conn, &src, &namespace_of(&conn, &src), None);
    let report = walk(&conn);
    assert_eq!(
        defect(&report, seq),
        Some(SignatureFailure::DomainRowMissing)
    );
    assert_eq!(report.agent_receipts_erased, 0);
}

/// One forged tombstone signature: `(other key, source id, namespace)`.
type Forgery = fn(&SigningKey, &str, &str) -> Vec<u8>;

/// #10135 — a tombstone signed by another key, or by the daemon under
/// another domain, or over another source's body, is no erasure record.
#[test]
fn forged_tombstone_does_not_excuse_a_missing_receipt_10135() {
    let other = SigningKey::from_bytes(&[0x2a; 32]);
    let forgeries: [Forgery; 3] = [
        |k, id, ns| {
            let body = forget_tombstone_signing_body(id, ns, FORGOTTEN_AT);
            k.sign(&[DaemonDomain::Tombstone.tag(), &body[..]].concat())
                .to_bytes()
                .to_vec()
        },
        |_, id, ns| {
            let body = forget_tombstone_signing_body(id, ns, FORGOTTEN_AT);
            daemon_signer::sign(DaemonDomain::EventPayload, &body)
                .expect("key")
                .0
        },
        |_, _, ns| {
            let body = forget_tombstone_signing_body("another-source", ns, FORGOTTEN_AT);
            daemon_signer::sign(DaemonDomain::Tombstone, &body)
                .expect("key")
                .0
        },
    ];
    for (i, forge) in forgeries.iter().enumerate() {
        let (_dir, _path, conn) = open_signed_era();
        let src = source(&conn);
        let ns = namespace_of(&conn, &src);
        let r = receipt(&src, &["a1"]);
        let seq = append_row(&conn, &r, &receipt_sign(&r.canonical_bytes()));
        insert_tombstone(&conn, &src, &ns, Some(&forge(&other, &src, &ns)));
        let report = walk(&conn);
        assert_eq!(
            defect(&report, seq),
            Some(SignatureFailure::DomainRowMissing),
            "forgery {i}"
        );
        assert_eq!(report.agent_receipts_erased, 0, "forgery {i}");
    }
}

/// #10135 — a genuine forget (daemon-signed tombstone) is the counted
/// erased outcome, never verified and never Failed.
#[test]
fn genuine_forget_is_the_erased_outcome_10135() {
    let (_dir, _path, conn) = open_signed_era();
    let src = source(&conn);
    let ns = namespace_of(&conn, &src);
    let r = receipt(&src, &["a1"]);
    let sig = receipt_sign(&r.canonical_bytes());
    let seq = append_row(&conn, &r, &sig);
    store_receipt(&conn, &r, Some(sig));
    db::forget(&conn, Some(&ns), None, None, false).expect("forget");
    let report = walk(&conn);
    assert_eq!(defect(&report, seq), None, "{report:?}");
    assert!(!report.signature_failures.contains(&seq));
    assert_eq!(report.agent_receipts_erased, 1);
    assert!(!fully_verified(&report));
}

// ---------------------------------------------------------------- S-6 writer

struct OneShot(Mutex<Option<Vec<Atom>>>);

impl Curator for OneShot {
    fn decompose(&self, _: &str, _: u32, _: u32) -> Result<Vec<Atom>, CuratorError> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| CuratorError::MalformedResponse("one shot".into()))
    }
}

fn atomiser() -> Atomiser {
    let atoms = ["Atom one.", "Atom two.", "Atom three."]
        .iter()
        .map(|t| Atom {
            text: (*t).to_string(),
        })
        .collect();
    Atomiser::new(
        Box::new(OneShot(Mutex::new(Some(atoms)))),
        None,
        AtomiserConfig::default(),
        FeatureTier::Smart,
    )
    .with_curator_model(CURATOR)
}

fn receipts_of(conn: &rusqlite::Connection, src: &str) -> Vec<(String, String, Option<Vec<u8>>)> {
    let mut stmt = conn
        .prepare(
            "SELECT atomised_at, signer_agent_id, signature FROM atomisation_receipts \
             WHERE source_id = ?1",
        )
        .expect("prepare");
    stmt.query_map(params![src], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("query")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("collect")
}

fn atomised_into(conn: &rusqlite::Connection, src: &str) -> Option<i64> {
    conn.query_row(
        "SELECT atomised_into FROM memories WHERE id = ?1",
        params![src],
        |r| r.get(0),
    )
    .expect("atomised_into")
}

fn completion_rows(conn: &rusqlite::Connection) -> Vec<SignedEvent> {
    let mut stmt = conn
        .prepare(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                    sequence, cause_hash FROM signed_events WHERE event_type = ?1",
        )
        .expect("prepare");
    stmt.query_map([ATOMISATION], |r| {
        Ok(SignedEvent {
            id: r.get(0)?,
            agent_id: r.get(1)?,
            event_type: r.get(2)?,
            payload_hash: r.get(3)?,
            signature: r.get(4)?,
            attest_level: r.get(5)?,
            timestamp: r.get(6)?,
            sequence: r.get(7)?,
            cause_hash: r.get(8)?,
            ..SignedEvent::default()
        })
    })
    .expect("query")
    .collect::<rusqlite::Result<Vec<_>>>()
    .expect("collect")
}

/// S-6 / W-13 — the writer stores one daemon receipt signed under the
/// receipt domain and one daemon chain row bound to it; the walk verifies.
#[test]
fn atomise_writes_a_domain_signed_receipt_and_its_chain_row_10108() {
    let _g = serial();
    let (_dir, _path, conn) = open_signed_era();
    let src = source(&conn);
    let result = atomiser()
        .atomise_sync(&conn, &src, MAX_ATOM_TOKENS, false, CALLER)
        .expect("atomise");
    let stored = receipts_of(&conn, &src);
    assert_eq!(stored.len(), 1, "one receipt per atomisation");
    let (atomised_at, signer, sig) = &stored[0];
    assert_eq!(atomised_at, &result.archived_at);
    assert_eq!(signer, "daemon");
    let sig = sig.as_deref().expect("a signed receipt");
    let r = AtomisationReceipt {
        source_id: src.clone(),
        atomised_at: result.archived_at.clone(),
        atom_ids: result.atom_ids.clone(),
        atom_count: u64::try_from(result.atom_count).expect("fits"),
        calling_agent_id: CALLER.to_string(),
        curator_model: Some(CURATOR.to_string()),
    };
    assert!(daemon_signer::verify(
        &sink(),
        receipt_domain(),
        &r.canonical_bytes(),
        sig
    ));
    let rows = completion_rows(&conn);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].agent_id, "daemon");
    assert_eq!(rows[0].attest_level, "daemon_signed");
    assert_eq!(
        rows[0].cause_hash.as_deref(),
        Some(&SourceBinding::of_source(&src).as_bytes()[..])
    );
    let report = walk(&conn);
    assert_eq!(defect(&report, rows[0].sequence), None, "{report:?}");
    assert!(
        !report.signature_failures.contains(&rows[0].sequence),
        "{report:?}"
    );
    assert!(!orphan_reported(&report), "{report:?}");
    assert_eq!(report.agent_receipts_legacy, 0, "a signed-era receipt");
    // The atoms' `atom_of` edges still go through the agent link writer,
    // which later slices of #10108 move to the daemon; until then those
    // rows (and only those) read as pre-cutover writers above the marker.
    for (seq, f) in &report.agent_signature_defects {
        let event_type: String = conn
            .query_row(
                "SELECT event_type FROM signed_events WHERE sequence = ?1",
                [seq],
                |r| r.get(0),
            )
            .expect("defect row");
        assert_eq!(
            (event_type.as_str(), *f),
            (LINK_CREATED, SignatureFailure::PreCutoverWriter),
            "row {seq}: {report:?}"
        );
    }
}

/// The step an injected failure aborts.
#[derive(Debug, Clone, Copy)]
enum Step {
    Archive,
    Receipt,
    ChainRow,
}

const STEPS: [Step; 3] = [Step::Archive, Step::Receipt, Step::ChainRow];

fn inject(conn: &rusqlite::Connection, step: Step) -> &'static str {
    let (sql, tag) = match step {
        Step::Archive => (
            "CREATE TEMP TRIGGER inject_10108 BEFORE UPDATE OF atomised_into ON memories \
             BEGIN SELECT RAISE(ABORT, 'inject-archive-10108'); END",
            "inject-archive-10108",
        ),
        Step::Receipt => (
            "CREATE TEMP TRIGGER inject_10108 BEFORE INSERT ON atomisation_receipts \
             BEGIN SELECT RAISE(ABORT, 'inject-receipt-10108'); END",
            "inject-receipt-10108",
        ),
        Step::ChainRow => (
            "CREATE TEMP TRIGGER inject_10108 BEFORE INSERT ON signed_events \
             WHEN NEW.event_type = 'atomisation_complete' \
             BEGIN SELECT RAISE(ABORT, 'inject-chain-10108'); END",
            "inject-chain-10108",
        ),
    };
    conn.execute_batch(sql).expect("create trigger");
    tag
}

/// S-6 — a failure injected at each step leaves no receipt, no dedup write
/// and no chain row, and the error names the step.
#[test]
fn a_failure_at_any_step_writes_nothing_10108() {
    let _g = serial();
    for step in STEPS {
        let (_dir, _path, conn) = open_signed_era();
        let src = source(&conn);
        let tag = inject(&conn, step);
        let err = atomiser()
            .atomise_sync(&conn, &src, MAX_ATOM_TOKENS, false, CALLER)
            .expect_err("an injected failure fails the atomise");
        match &err {
            AtomiseError::DbError(msg) => assert!(msg.contains(tag), "{step:?}: {msg}"),
            other => panic!("{step:?}: {other:?}"),
        }
        assert!(
            receipts_of(&conn, &src).is_empty(),
            "{step:?}: receipt left"
        );
        assert_eq!(atomised_into(&conn, &src), None, "{step:?}: dedup written");
        assert!(
            completion_rows(&conn).is_empty(),
            "{step:?}: chain row left"
        );
        conn.execute_batch("DROP TRIGGER inject_10108")
            .expect("drop trigger");
        let report = walk(&conn);
        assert!(!orphan_reported(&report), "{step:?}: {report:?}");
    }
}

/// S-6 — a receipt already stored at the same `(source_id, atomised_at)` is
/// an error, never a replace or an ignore, and nothing else is written.
#[test]
fn receipt_key_collision_is_an_error_10108() {
    let _g = serial();
    let (_dir, _path, conn) = open_signed_era();
    let src = source(&conn);
    conn.execute_batch(
        "CREATE TEMP TRIGGER collide_10108 BEFORE INSERT ON atomisation_receipts \
         BEGIN INSERT INTO atomisation_receipts \
             (source_id, atomised_at, atom_ids, atom_count, calling_agent_id, curator_model, \
              signer_agent_id, signature) \
           VALUES (NEW.source_id, NEW.atomised_at, '[]', 0, 'ai:other', NULL, NULL, NULL); \
         END",
    )
    .expect("create collision trigger");
    let err = atomiser()
        .atomise_sync(&conn, &src, MAX_ATOM_TOKENS, false, CALLER)
        .expect_err("a key collision fails the atomise");
    match &err {
        AtomiseError::DbError(msg) => assert!(msg.contains("UNIQUE"), "{msg}"),
        other => panic!("{other:?}"),
    }
    assert!(receipts_of(&conn, &src).is_empty(), "the receipt was kept");
    assert_eq!(atomised_into(&conn, &src), None);
    assert_eq!(completion_rows(&conn).len(), 0, "a chain row was written");
}
