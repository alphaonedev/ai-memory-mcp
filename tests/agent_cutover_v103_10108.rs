// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 (`3-agent vote (71472661)` V1-AGENT-SIG-SCHEMA, decision A) — the
//! v103 schema step on sqlite:
//!
//! - S-1: strictly additive and idempotent (two NULL-able `transcript_line_dedup`
//!   columns with their pair rule, the `atomisation_receipts` table).
//! - S-3: the `signed_events.agent_cutover` marker is written in the SAME
//!   transaction as the v103 stamp; a failed marker write leaves the database
//!   at v102 with no marker, and no other writer can append a marker row.
//! - B-5 / S-3: both walks judge the marker by recompute; a tampered or a
//!   second marker fails with `agent_cutover_marker_invalid`.
//! - S-7: an import of a DIFFERENT marker is refused.
//! - S-8: a hard delete and a forget purge the receipts of the source id.

use std::path::PathBuf;
use std::sync::OnceLock;

use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::signed_events::agent_cutover::{
    AGENT_CUTOVER_AGENT_ID, MarkerOrigin, build_marker, resolve_sqlite_agent_cutover,
    signed_marker_payload_hash,
};
use ai_memory::signed_events::{
    AGENT_CUTOVER_EVENT_TYPE, AgentCutover, RowSignatureVerdict, SignatureFailure, SignedEvent,
    ZERO_HASH, append_signed_event, canonical_chain_bytes, payload_hash, verify_audit_trail,
    verify_chain,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::params;
use sha2::{Digest, Sha256};

#[path = "common/home_sandbox.rs"]
mod home_sandbox;

/// The test daemon key (one per process).
const TEST_DAEMON_SEED: [u8; 32] = [0x5d; 32];
/// The event type of the fixture rows.
const FIXTURE_EVENT_TYPE: &str = "governance.test";
/// The ladder rung below the step under test.
const V102_RUNG: i64 = 102;
/// The ladder tip this step moves to.
const V103_TIP: i64 = 103;
/// An Ed25519 signature's length in bytes.
const SIGNATURE_LEN: usize = 64;
/// Rows the fixture chains hold before v103 runs.
const PREFIX_ROWS: i64 = 3;
/// The exact pair-rule refusal of the v103 triggers.
const PAIR_RULE_MESSAGE: &str =
    "transcript_line_dedup: host_signature and host_pubkey are both set or both NULL";

fn sink() -> VerifyingKey {
    static SINK: OnceLock<tempfile::TempDir> = OnceLock::new();
    SINK.get_or_init(|| {
        let dir = home_sandbox::per_test_dir("forensic-10108-");
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
    let child = home_sandbox::per_test_dir("child-env-10108-");
    for (key, path) in home_sandbox::child_env(child.path()) {
        home_sandbox::assert_outside_real_home(key, &path);
    }
}

fn open_db() -> (tempfile::TempDir, PathBuf, rusqlite::Connection) {
    let _ = sink();
    let dir = home_sandbox::per_test_dir("agent-cutover-10108-");
    let path = dir.path().join("cutover-10108.db");
    let conn = db::open(&path).expect("open db");
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

fn markers(conn: &rusqlite::Connection) -> Vec<SignedEvent> {
    load_rows(conn)
        .into_iter()
        .filter(|r| r.event_type == AGENT_CUTOVER_EVENT_TYPE)
        .collect()
}

fn version(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .expect("schema version")
}

/// One genuine row through the production append path.
fn append_genuine(conn: &rusqlite::Connection) {
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: FIXTURE_EVENT_TYPE.to_string(),
        payload_hash: payload_hash(uuid::Uuid::new_v4().as_bytes()),
        signature: Some(vec![0u8; 64]),
        attest_level: "daemon_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    append_signed_event(conn, &ev).expect("append genuine row");
}

/// A raw agent-labelled row at the chain head, linked to the head.
fn insert_agent_labelled(conn: &rusqlite::Connection) {
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
         VALUES (?1, 'ai:agent-10108', ?2, ?3, ?4, 'self_signed', ?5, ?6, ?7, NULL)",
        params![
            uuid::Uuid::new_v4().to_string(),
            FIXTURE_EVENT_TYPE,
            payload_hash(b"agent-labelled-10108"),
            vec![7u8; 64],
            chrono::Utc::now().to_rfc3339(),
            prev_hash,
            sequence
        ],
    )
    .expect("insert agent-labelled row");
}

/// Put the database back at v102 (the v103 DDL is `IF NOT EXISTS` and its
/// column adds are guarded, so re-running the step adds nothing twice).
fn rewind_to_v102(conn: &rusqlite::Connection) {
    conn.execute_batch(&format!(
        "DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES ({V102_RUNG});"
    ))
    .expect("rewind to v102");
}

/// A chain of `PREFIX_ROWS` genuine rows taken back to v102 and re-opened, so
/// v103 runs over a non-empty chain. Returns the re-opened connection.
fn migrated_over_prefix(
    path: &std::path::Path,
    conn: rusqlite::Connection,
) -> rusqlite::Connection {
    drop_genesis_marker(&conn);
    for _ in 0..PREFIX_ROWS {
        append_genuine(&conn);
    }
    rewind_to_v102(&conn);
    drop(conn);
    db::open(path).expect("re-open runs v103")
}

/// #10145 — a v102-shaped chain: remove the genesis marker a fresh open
/// wrote (asserting there was exactly one), so a bump has a chain with no
/// marker to write above.
fn drop_genesis_marker(conn: &rusqlite::Connection) {
    assert_eq!(markers(conn).len(), 1, "a fresh open writes one genesis marker");
    conn.execute(
        "DELETE FROM signed_events WHERE event_type = ?1",
        params![AGENT_CUTOVER_EVENT_TYPE],
    )
    .expect("drop genesis marker");
}

fn walk_failures(conn: &rusqlite::Connection) -> (Vec<i64>, Vec<i64>) {
    let vk = sink();
    let chain = verify_chain(conn, None, Some(&vk)).expect("verify_chain");
    assert_eq!(chain.chain_break, None, "the chain stays linked");
    let trail = verify_audit_trail(conn, None, Some(&vk)).expect("verify_audit_trail");
    (chain.signature_failures, trail.signature_failures)
}

fn columns(conn: &rusqlite::Connection, table: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
        .expect("prepare");
    stmt.query_map([], |r| r.get(0))
        .expect("query")
        .collect::<rusqlite::Result<Vec<String>>>()
        .expect("collect")
}

/// S-1 / S-3 — v103 over a non-empty chain appends exactly one marker at the
/// head, stamps 103, and the marker verifies on both walks. Re-running the
/// step writes no second marker (idempotent).
#[test]
fn v103_appends_one_verified_marker_with_the_stamp_10108() {
    let (_dir, path, conn) = open_db();
    let conn = migrated_over_prefix(&path, conn);
    assert_eq!(version(&conn), V103_TIP);
    let found = markers(&conn);
    assert_eq!(found.len(), 1, "exactly one marker");
    let marker = &found[0];
    assert_eq!(
        marker.sequence,
        PREFIX_ROWS + 1,
        "the marker sits at the head"
    );
    assert_eq!(marker.agent_id, AGENT_CUTOVER_AGENT_ID);
    assert_eq!(marker.attest_level, "daemon_signed");
    assert_eq!(marker.signature.as_ref().map(Vec::len), Some(SIGNATURE_LEN));
    assert_eq!(
        marker.payload_hash.first(),
        Some(&MarkerOrigin::Migrate.byte()),
        "a bump is origin Migrate"
    );
    assert_eq!(
        resolve_sqlite_agent_cutover(&conn, Some(&sink())).expect("resolve"),
        AgentCutover::Valid {
            sequence: PREFIX_ROWS + 1,
            legacy_agent_rows: 0
        }
    );
    assert_eq!(walk_failures(&conn), (Vec::new(), Vec::new()));

    rewind_to_v102(&conn);
    drop(conn);
    let conn = db::open(&path).expect("second run");
    assert_eq!(version(&conn), V103_TIP);
    assert_eq!(markers(&conn).len(), 1, "a re-run writes no second marker");
    // Rows appended after the marker link above it and verify.
    append_genuine(&conn);
    assert_eq!(walk_failures(&conn), (Vec::new(), Vec::new()));
}

/// S-3 — the marker counts the agent-labelled rows below it, and that count is
/// bound into its `payload_hash`.
#[test]
fn v103_marker_binds_the_legacy_agent_row_count_10108() {
    let (_dir, path, conn) = open_db();
    drop_genesis_marker(&conn);
    append_genuine(&conn);
    insert_agent_labelled(&conn);
    rewind_to_v102(&conn);
    drop(conn);
    let conn = db::open(&path).expect("re-open runs v103");
    let marker = markers(&conn).pop().expect("marker written");
    let below = load_rows(&conn)
        .into_iter()
        .find(|r| r.sequence == marker.sequence - 1)
        .expect("row below");
    let prev = Sha256::digest(canonical_chain_bytes(&below)).to_vec();
    assert_eq!(marker.prev_hash, prev);
    assert_eq!(
        Some(marker.payload_hash.clone()),
        signed_marker_payload_hash(marker.sequence, &prev, 1, MarkerOrigin::Migrate)
    );
    assert_ne!(
        Some(marker.payload_hash),
        signed_marker_payload_hash(3, &prev, 0, MarkerOrigin::Migrate),
        "control: another count gives another hash"
    );
    assert_eq!(
        resolve_sqlite_agent_cutover(&conn, Some(&sink())).expect("resolve"),
        AgentCutover::Valid {
            sequence: 3,
            legacy_agent_rows: 1
        }
    );
}

/// #10145 W-9 — a fresh create writes the signed genesis marker at sequence
/// 1 above `ZERO_HASH`, origin Create, in the same transaction as the stamp;
/// it verifies under the daemon key on both walks, and a re-open writes no
/// second marker.
#[test]
fn a_fresh_create_writes_one_signed_genesis_marker_10145() {
    let (_dir, path, conn) = open_db();
    assert_eq!(version(&conn), V103_TIP);
    let found = markers(&conn);
    assert_eq!(found.len(), 1, "exactly one genesis marker");
    let genesis = &found[0];
    assert_eq!(genesis.sequence, 1);
    assert_eq!(genesis.prev_hash, ZERO_HASH.to_vec());
    assert_eq!(genesis.attest_level, "daemon_signed");
    assert_eq!(
        Some(genesis.payload_hash.clone()),
        signed_marker_payload_hash(1, &ZERO_HASH, 0, MarkerOrigin::Create)
    );
    assert_eq!(
        resolve_sqlite_agent_cutover(&conn, Some(&sink())).expect("resolve"),
        AgentCutover::Valid {
            sequence: 1,
            legacy_agent_rows: 0
        }
    );
    assert_eq!(
        resolve_sqlite_agent_cutover(&conn, None).expect("resolve"),
        AgentCutover::Invalid,
        "no verifier never reads Valid"
    );
    let other = SigningKey::from_bytes(&[0x11; 32]).verifying_key();
    assert_eq!(
        resolve_sqlite_agent_cutover(&conn, Some(&other)).expect("resolve"),
        AgentCutover::Invalid,
        "another key never reads Valid"
    );
    assert_eq!(walk_failures(&conn), (Vec::new(), Vec::new()));
    drop(conn);
    let conn = db::open(&path).expect("re-open");
    assert_eq!(markers(&conn).len(), 1, "a re-open writes no second marker");
}

/// S-3 — a marker write that fails rolls the whole step back: the database is
/// still at v102 with no marker, and the next open (with the fault gone)
/// completes the step.
#[test]
fn v103_marker_and_stamp_commit_together_10108() {
    let (_dir, path, conn) = open_db();
    drop_genesis_marker(&conn);
    for _ in 0..PREFIX_ROWS {
        append_genuine(&conn);
    }
    rewind_to_v102(&conn);
    conn.execute_batch(&format!(
        "CREATE TRIGGER fault_10108 BEFORE INSERT ON signed_events \
         WHEN NEW.event_type = '{AGENT_CUTOVER_EVENT_TYPE}' \
         BEGIN SELECT RAISE(ABORT, 'fault_10108'); END;"
    ))
    .expect("install fault");
    drop(conn);
    let err = db::open(&path).expect_err("the failed marker refuses the step");
    assert!(format!("{err:#}").contains("fault_10108"), "{err:#}");

    let raw = rusqlite::Connection::open(&path).expect("raw open");
    assert_eq!(version(&raw), V102_RUNG, "no v103 stamp without its marker");
    assert!(markers(&raw).is_empty(), "no marker without its stamp");
    raw.execute_batch("DROP TRIGGER fault_10108;")
        .expect("remove fault");
    drop(raw);

    let conn = db::open(&path).expect("the step completes");
    assert_eq!(version(&conn), V103_TIP);
    assert_eq!(markers(&conn).len(), 1);
}

/// S-3 — no append path writes a marker-type row.
#[test]
fn append_refuses_the_marker_event_type_10108() {
    let (_dir, _path, conn) = open_db();
    append_genuine(&conn);
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: AGENT_CUTOVER_AGENT_ID.to_string(),
        event_type: AGENT_CUTOVER_EVENT_TYPE.to_string(),
        payload_hash: payload_hash(b"forged-marker"),
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    let err = append_signed_event(&conn, &ev).expect_err("reserved type");
    assert_eq!(
        format!("{err:#}"),
        format!(
            "append signed_event: event_type {AGENT_CUTOVER_EVENT_TYPE} is reserved for \
             schema step v103"
        )
    );
    assert_eq!(markers(&conn).len(), 1, "nothing written beside the genesis marker");
}

/// B-5 / S-3 — a tampered marker fails on both walks with the exact reason.
#[test]
fn a_tampered_marker_fails_both_walks_10108() {
    let (_dir, path, conn) = open_db();
    let conn = migrated_over_prefix(&path, conn);
    let marker = markers(&conn).pop().expect("marker");
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
        params![payload_hash(b"tampered-10108"), marker.sequence],
    )
    .expect("tamper");
    assert_eq!(
        resolve_sqlite_agent_cutover(&conn, Some(&sink())).expect("resolve"),
        AgentCutover::Invalid
    );
    let tampered = markers(&conn).pop().expect("marker");
    assert_eq!(
        AgentCutover::Invalid.verdict_for(&tampered),
        Some(RowSignatureVerdict::Failed(
            SignatureFailure::CutoverMarkerInvalid
        ))
    );
    assert_eq!(
        SignatureFailure::CutoverMarkerInvalid.reason(),
        "agent_cutover_marker_invalid"
    );
    assert_eq!(
        walk_failures(&conn),
        (vec![marker.sequence], vec![marker.sequence])
    );
}

/// B-5 / S-3 — a second marker-type row makes every marker fail.
#[test]
fn a_second_marker_fails_both_markers_10108() {
    let (_dir, path, conn) = open_db();
    let conn = migrated_over_prefix(&path, conn);
    let first = markers(&conn).pop().expect("marker");
    let second = build_marker(
        &first,
        0,
        uuid::Uuid::new_v4().to_string(),
        chrono::Utc::now().to_rfc3339(),
    )
    .expect("a row above the head");
    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, ?8, NULL)",
        params![
            second.id,
            second.agent_id,
            second.event_type,
            second.payload_hash,
            second.attest_level,
            second.timestamp,
            second.prev_hash,
            second.sequence
        ],
    )
    .expect("insert second marker");
    assert_eq!(
        resolve_sqlite_agent_cutover(&conn, Some(&sink())).expect("resolve"),
        AgentCutover::Invalid
    );
    let both = vec![first.sequence, second.sequence];
    assert_eq!(walk_failures(&conn), (both.clone(), both));
}

/// S-1 — the step is additive: the new columns are NULL on rows that existed
/// before it, the pair rule refuses a half-set pair on insert and update, and
/// the receipt table refuses a signer without a signature.
#[test]
fn v103_columns_are_additive_with_their_rules_10108() {
    let (_dir, path, conn) = open_db();
    conn.execute(
        "INSERT INTO transcript_line_dedup (sha256, memory_id, host_kind, recovered_at) \
         VALUES (?1, 'm-10108', 'claude-code', 0)",
        params![vec![1u8; 32]],
    )
    .expect("insert dedup row");
    rewind_to_v102(&conn);
    drop(conn);
    let conn = db::open(&path).expect("re-open runs v103");
    let cols = columns(&conn, "transcript_line_dedup");
    assert!(cols.iter().any(|c| c == "host_signature"), "{cols:?}");
    assert!(cols.iter().any(|c| c == "host_pubkey"), "{cols:?}");
    let pair: (Option<Vec<u8>>, Option<Vec<u8>>) = conn
        .query_row(
            "SELECT host_signature, host_pubkey FROM transcript_line_dedup WHERE memory_id = 'm-10108'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("existing row");
    assert_eq!(
        pair,
        (None, None),
        "standard 1: the existing row is not rewritten"
    );

    let half = conn
        .execute(
            "INSERT INTO transcript_line_dedup \
                (sha256, memory_id, host_kind, recovered_at, host_signature) \
             VALUES (?1, 'm2-10108', 'claude-code', 0, ?2)",
            params![vec![2u8; 32], vec![3u8; 64]],
        )
        .expect_err("half a pair on insert");
    assert!(half.to_string().contains(PAIR_RULE_MESSAGE), "{half}");
    let half = conn
        .execute(
            "UPDATE transcript_line_dedup SET host_pubkey = ?1 WHERE memory_id = 'm-10108'",
            params![vec![4u8; 32]],
        )
        .expect_err("half a pair on update");
    assert!(half.to_string().contains(PAIR_RULE_MESSAGE), "{half}");
    conn.execute(
        "UPDATE transcript_line_dedup SET host_signature = ?1, host_pubkey = ?2 \
         WHERE memory_id = 'm-10108'",
        params![vec![3u8; 64], vec![4u8; 32]],
    )
    .expect("a whole pair is accepted");

    let receipt = conn.execute(
        "INSERT INTO atomisation_receipts \
            (source_id, atomised_at, atom_ids, atom_count, calling_agent_id, curator_model, \
             signer_agent_id, signature) \
         VALUES ('s-10108', '2026-11-26T00:00:00Z', '[]', 0, 'ai:a', 'm', 'ai:a', NULL)",
        [],
    );
    assert!(receipt.is_err(), "a signer without a signature is refused");
}

fn seed_memory(conn: &rusqlite::Connection, namespace: &str) -> String {
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("note-{}", uuid::Uuid::new_v4()),
        content: "atomised source 10108".to_string(),
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": "ai:test:10108" }),
        ..Memory::default()
    };
    db::insert(conn, &mem).expect("insert memory")
}

fn seed_receipt(conn: &rusqlite::Connection, source_id: &str) {
    conn.execute(
        "INSERT INTO atomisation_receipts \
            (source_id, atomised_at, atom_ids, atom_count, calling_agent_id, curator_model, \
             signer_agent_id, signature) \
         VALUES (?1, '2026-11-26T00:00:00Z', '[]', 0, 'ai:a', 'm', NULL, NULL)",
        params![source_id],
    )
    .expect("insert receipt");
}

fn receipts(conn: &rusqlite::Connection, source_id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM atomisation_receipts WHERE source_id = ?1",
        params![source_id],
        |r| r.get(0),
    )
    .expect("count receipts")
}

/// S-8 — a forget purges the receipts of the forgotten sources only.
#[test]
fn forget_purges_the_receipts_of_the_forgotten_source_10108() {
    let (_dir, _path, conn) = open_db();
    let gone = seed_memory(&conn, "erase-10108");
    let kept = seed_memory(&conn, "keep-10108");
    seed_receipt(&conn, &gone);
    seed_receipt(&conn, &kept);
    db::forget(&conn, Some("erase-10108"), None, None, false).expect("forget");
    assert_eq!(
        receipts(&conn, &gone),
        0,
        "the forgotten source's receipt is purged"
    );
    assert_eq!(
        receipts(&conn, &kept),
        1,
        "another source's receipt survives"
    );
}

/// S-8 — a hard delete purges the receipts of the deleted source.
#[test]
fn delete_purges_the_receipts_of_the_deleted_source_10108() {
    let (_dir, _path, conn) = open_db();
    let gone = seed_memory(&conn, "delete-10108");
    let kept = seed_memory(&conn, "delete-10108");
    seed_receipt(&conn, &gone);
    seed_receipt(&conn, &kept);
    assert!(db::delete(&conn, &gone).expect("delete"));
    assert_eq!(
        receipts(&conn, &gone),
        0,
        "the deleted source's receipt is purged"
    );
    assert_eq!(
        receipts(&conn, &kept),
        1,
        "another source's receipt survives"
    );
}

/// S-7 — an import that carries a DIFFERENT marker into a database that holds
/// one is refused with the exact reason; the same marker restores.
#[test]
fn import_refuses_a_second_agent_cutover_marker_10108() {
    use ai_memory::portability::emit::{ExportEnvelope, SPEC_VERSION_V2};
    use ai_memory::portability::import::{ImportOptions, import_full_envelope};
    fn envelope_of(rows: &[SignedEvent]) -> ExportEnvelope {
        ExportEnvelope {
            spec_version: SPEC_VERSION_V2.to_string(),
            db_schema_version: 0,
            source: "issue-10108-test".into(),
            exported_at: "2026-11-26T00:00:00Z".into(),
            memories: Vec::new(),
            links: Vec::new(),
            signed_events: rows
                .iter()
                .map(ai_memory::portability::dto::SignedEventDto::from)
                .collect(),
            memory_revisions: Vec::new(),
            forget_tombstones: Vec::new(),
            agent_lineage: Vec::new(),
            model_attestations: Vec::new(),
            governance_rules: Vec::new(),
            trust_anchors: Vec::new(),
            archived_memories: Vec::new(),
            namespace_meta: Vec::new(),
            archived_memory_links: Vec::new(),
            portability_complete: false,
            conformance_level: "L1".into(),
            conformance_by_class: std::collections::BTreeMap::new(),
            count: 0,
        }
    }
    let opts = ImportOptions {
        caller_agent_id: "ai:importer-10108".into(),
        ..ImportOptions::default()
    };
    let (_da, pa, dst) = open_db();
    let dst = migrated_over_prefix(&pa, dst);
    let (_db, pb, src) = open_db();
    let src = migrated_over_prefix(&pb, src);
    let src_marker = markers(&src).pop().expect("source marker");
    let own = markers(&dst).pop().expect("own marker");
    assert_ne!(own.id, src_marker.id, "control");

    let err = import_full_envelope(&dst, &envelope_of(std::slice::from_ref(&src_marker)), &opts)
        .expect_err("a second marker is refused");
    let want = format!(
        "import signed_event {} (sequence {}): a different agent cutover row already \
         exists; refusing a second cutover marker",
        src_marker.id, src_marker.sequence
    );
    assert!(format!("{err:#}").contains(&want), "{err:#}");
    assert_eq!(markers(&dst).len(), 1, "no second marker was written");

    import_full_envelope(&dst, &envelope_of(&[own]), &opts).expect("the same marker restores");
    assert_eq!(markers(&dst).len(), 1);
}
