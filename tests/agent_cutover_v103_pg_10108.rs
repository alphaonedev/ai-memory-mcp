// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
#![cfg(feature = "sal-postgres")]

//! #10108 lane o (#10145 parity) — the v103 agent cut-over marker on
//! postgres, cell for cell with the sqlite file `agent_cutover_v103_10108.rs`
//! (the same cell names with a `_pg` part):
//!
//! - a fresh create writes one signed genesis marker at sequence 1, built by
//!   the one shared constructor and verified by the one shared verifier;
//! - v103 over a non-empty chain appends one signed marker at the head and a
//!   re-run of the step writes no second marker;
//! - a one-byte change to the marker's payload or signature, or a stripped
//!   signature, fails the walk at the marker;
//! - a second marker row fails both markers;
//! - a v103 database whose marker is gone fails the walk at the chain level
//!   and no re-open repairs it.
//!
//! Every cell runs on its own scratch database and soft-skips without
//! `AI_MEMORY_TEST_POSTGRES_URL`.

use std::sync::OnceLock;

use ai_memory::governance::daemon_signer::{self, DaemonChainSigner};
use ai_memory::signed_events::agent_cutover::{
    AGENT_CUTOVER_AGENT_ID, MarkerOrigin, build_signed_marker, signed_marker_payload_hash,
    verify_signed_marker,
};
use ai_memory::signed_events::{
    AGENT_CUTOVER_EVENT_TYPE, AuditTrailReport, SignedEvent, ZERO_HASH,
};
use ai_memory::store::postgres::PostgresStore;
use chrono::{DateTime, SubsecRound, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};

#[path = "common/home_sandbox.rs"]
mod home_sandbox;

#[path = "common/pg_barrier.rs"]
mod pg_barrier;

/// The test daemon key (the same seed as the sqlite cells).
const TEST_DAEMON_SEED: [u8; 32] = [0x5d; 32];
/// Another key, which must not verify the marker.
const OTHER_SEED: [u8; 32] = [0x6e; 32];
/// The ladder rung below the step under test.
const V102_RUNG: i32 = 102;
/// The ladder tip this step moves to.
const V103_TIP: i32 = 103;
/// An Ed25519 signature's length in bytes.
const SIGNATURE_LEN: usize = 64;
/// Rows the fixture chains hold before v103 runs.
const PREFIX_ROWS: i64 = 3;
/// The daemon attest level of a signed row.
const DAEMON_SIGNED: &str = "daemon_signed";
/// The chain-level failure sequence of a walk.
const CHAIN_LEVEL: i64 = 0;
/// Scratch database name prefix for this file.
const SCRATCH_PREFIX: &str = "ai_memory_10108mk";
/// Postgres keeps micro-seconds: a signed time is cut to this many digits.
const PG_SUBSEC_DIGITS: u16 = 6;
/// The argv0 of the fixture's daemon rows.
const FIXTURE_ARGV0: &str = "agent-cutover-10108-pg";
/// The caller of the fixture's daemon rows.
const FIXTURE_CALLER: &str = "fixture";
/// The marker reads its rows in chain order.
const SELECT_ROWS: &str = "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
        timestamp, prev_hash, sequence, cause_hash FROM signed_events \
     WHERE sequence IS NOT NULL ORDER BY sequence";

fn sink() -> VerifyingKey {
    static SINK: OnceLock<tempfile::TempDir> = OnceLock::new();
    SINK.get_or_init(|| {
        let dir = home_sandbox::per_test_dir("forensic-10108-pg-");
        ai_memory::governance::audit::init(
            dir.path(),
            Some(SigningKey::from_bytes(&TEST_DAEMON_SEED)),
        )
        .expect("init sink");
        dir
    });
    daemon_signer::verifying_key().expect("daemon key installed")
}

/// #10007 — the process resolves no path under the real home.
#[test]
fn test_process_resolves_no_path_under_the_real_home_pg_10108() {
    let _ = home_sandbox::real_home();
    let _ = sink();
    home_sandbox::assert_process_isolated();
    let child = home_sandbox::per_test_dir("child-env-10108-pg-");
    for (key, path) in home_sandbox::child_env(child.path()) {
        home_sandbox::assert_outside_real_home(key, &path);
    }
}

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// A fresh scratch database and a store connected to it (the daemon key is
/// installed first, so the schema create signs with the test key).
async fn scratch_store(url: &str) -> (pg_barrier::ScratchDb, PostgresStore) {
    let _ = sink();
    let scratch = pg_barrier::ScratchDb::create(url, SCRATCH_PREFIX)
        .await
        .expect("create scratch database");
    let pg = PostgresStore::connect(&scratch.url())
        .await
        .expect("connect scratch database");
    (scratch, pg)
}

/// Close `pg` and open the scratch database again (runs the ladder).
async fn reopen(scratch: &pg_barrier::ScratchDb, pg: PostgresStore) -> PostgresStore {
    pg.pool().close().await;
    PostgresStore::connect(&scratch.url())
        .await
        .expect("re-open scratch database")
}

/// The shared constructor's marker as a chain row.
fn signed_marker(prev: Option<&SignedEvent>, origin: MarkerOrigin) -> SignedEvent {
    let _ = sink();
    let signer = DaemonChainSigner::provision_default().expect("daemon key installed");
    build_signed_marker(
        &signer,
        prev,
        0,
        origin,
        uuid::Uuid::new_v4().to_string(),
        Utc::now().trunc_subsecs(PG_SUBSEC_DIGITS).to_rfc3339(),
    )
    .map(Into::<SignedEvent>::into)
    .expect("a marker above the head")
}

type Row = (
    String,
    String,
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    String,
    DateTime<Utc>,
    Vec<u8>,
    i64,
    Option<Vec<u8>>,
);

async fn rows(pg: &PostgresStore) -> Vec<SignedEvent> {
    let rows: Vec<Row> = sqlx::query_as(SELECT_ROWS)
        .fetch_all(pg.pool())
        .await
        .expect("read pg rows");
    rows.into_iter()
        .map(
            |(id, agent_id, event_type, ph, sig, attest, ts, prev, seq, cause)| SignedEvent {
                id,
                agent_id,
                event_type,
                payload_hash: ph,
                signature: sig,
                attest_level: attest,
                timestamp: ts.to_rfc3339(),
                prev_hash: prev,
                sequence: seq,
                cause_hash: cause,
            },
        )
        .collect()
}

async fn markers(pg: &PostgresStore) -> Vec<SignedEvent> {
    rows(pg)
        .await
        .into_iter()
        .filter(|r| r.event_type == AGENT_CUTOVER_EVENT_TYPE)
        .collect()
}

async fn version(pg: &PostgresStore) -> i32 {
    sqlx::query_scalar("SELECT MAX(version) FROM schema_version")
        .fetch_one(pg.pool())
        .await
        .expect("schema version")
}

/// Remove every chain row (a fresh create wrote the genesis marker).
async fn clear_chain(pg: &PostgresStore) {
    sqlx::query("DELETE FROM signed_events")
        .execute(pg.pool())
        .await
        .expect("clear chain");
}

/// Put the database back at v102.
async fn rewind_to_v102(pg: &PostgresStore) {
    sqlx::query("DELETE FROM schema_version WHERE version > $1")
        .bind(V102_RUNG)
        .execute(pg.pool())
        .await
        .expect("rewind to v102");
}

/// Insert `ev` with its committed time `ts`.
async fn insert(pg: &PostgresStore, ev: &SignedEvent, ts: DateTime<Utc>) {
    sqlx::query(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(&ev.id)
    .bind(&ev.agent_id)
    .bind(&ev.event_type)
    .bind(&ev.payload_hash)
    .bind(&ev.signature)
    .bind(&ev.attest_level)
    .bind(ts)
    .bind(&ev.prev_hash)
    .bind(ev.sequence)
    .bind(&ev.cause_hash)
    .execute(pg.pool())
    .await
    .expect("insert pg row");
}

/// `PREFIX_ROWS` daemon-signed rows through the production append path.
async fn append_prefix(pg: &PostgresStore) {
    let _ = sink();
    for _ in 0..PREFIX_ROWS {
        pg.emit_spawn_audit(FIXTURE_ARGV0, FIXTURE_CALLER).await;
    }
    assert_eq!(
        i64::try_from(rows(pg).await.len()).expect("row count"),
        PREFIX_ROWS,
        "every fixture row appended"
    );
}

/// A chain of `PREFIX_ROWS` rows taken back to v102 and re-opened, so v103
/// runs over a non-empty chain.
async fn migrated_over_prefix(scratch: &pg_barrier::ScratchDb, pg: PostgresStore) -> PostgresStore {
    clear_chain(&pg).await;
    append_prefix(&pg).await;
    rewind_to_v102(&pg).await;
    reopen(scratch, pg).await
}

async fn walk(pg: &PostgresStore, vk: &VerifyingKey) -> AuditTrailReport {
    pg.verify_audit_trail(None, Some(vk))
        .await
        .expect("pg verify")
}

/// The marker must be a signed row before a tamper means anything.
fn assert_signed(marker: &SignedEvent) {
    assert_eq!(marker.agent_id, AGENT_CUTOVER_AGENT_ID);
    assert_eq!(marker.attest_level, DAEMON_SIGNED);
    assert_eq!(
        marker.signature.as_ref().map(Vec::len),
        Some(SIGNATURE_LEN),
        "the marker carries a daemon signature"
    );
}

/// #10145 (I-2, I-9) — a fresh create writes exactly one marker, at sequence
/// 1 above the zero hash, built by the shared constructor; the shared
/// verifier accepts it under the daemon key and refuses it under another.
#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_create_writes_one_signed_genesis_marker_pg_10145() {
    let Some(url) = pg_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let vk = sink();
    let (_scratch, pg) = scratch_store(&url).await;
    let found = markers(&pg).await;
    assert_eq!(found.len(), 1, "a fresh create writes one genesis marker");
    let marker = &found[0];
    assert_signed(marker);
    assert_eq!(marker.sequence, 1);
    assert_eq!(marker.prev_hash, ZERO_HASH.to_vec());
    assert_eq!(
        Some(marker.payload_hash.clone()),
        signed_marker_payload_hash(1, &ZERO_HASH, 0, MarkerOrigin::Create)
    );
    assert_eq!(
        verify_signed_marker(&vk, marker, None, 0),
        Some(MarkerOrigin::Create)
    );
    let other = SigningKey::from_bytes(&OTHER_SEED).verifying_key();
    assert_eq!(verify_signed_marker(&other, marker, None, 0), None);
    assert_eq!(walk(&pg, &vk).await.signature_failures, Vec::<i64>::new());
}

/// S-1 / S-3 — v103 over a non-empty chain appends exactly one signed marker
/// at the head, stamps 103 and the walk verifies it. Re-running the step
/// writes no second marker.
#[tokio::test(flavor = "multi_thread")]
async fn v103_appends_one_verified_marker_with_the_stamp_pg_10108() {
    let Some(url) = pg_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let vk = sink();
    let (scratch, pg) = scratch_store(&url).await;
    let pg = migrated_over_prefix(&scratch, pg).await;
    assert_eq!(version(&pg).await, V103_TIP);
    let chain = rows(&pg).await;
    let found = markers(&pg).await;
    assert_eq!(found.len(), 1, "one marker above the prefix");
    let marker = &found[0];
    assert_signed(marker);
    assert_eq!(marker.sequence, PREFIX_ROWS + 1);
    let head = chain
        .iter()
        .find(|r| r.sequence == PREFIX_ROWS)
        .expect("prefix head");
    assert_eq!(
        verify_signed_marker(&vk, marker, Some(head), 0),
        Some(MarkerOrigin::Migrate)
    );
    assert_eq!(walk(&pg, &vk).await.signature_failures, Vec::<i64>::new());

    rewind_to_v102(&pg).await;
    let pg = reopen(&scratch, pg).await;
    assert_eq!(markers(&pg).await.len(), 1, "a re-run writes no marker");
    assert_eq!(version(&pg).await, V103_TIP);
    assert_eq!(walk(&pg, &vk).await.signature_failures, Vec::<i64>::new());
}

/// B-5 / S-3 — a one-byte change to the marker's payload or signature, or a
/// stripped signature, fails the walk at the marker; the untouched marker
/// verifies again once restored.
#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_marker_fails_the_walk_pg_10108() {
    let Some(url) = pg_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let vk = sink();
    let (scratch, pg) = scratch_store(&url).await;
    let pg = migrated_over_prefix(&scratch, pg).await;
    let marker = markers(&pg).await.pop().expect("marker");
    assert_signed(&marker);
    let sig = marker.signature.clone().expect("signed");
    let mut payload = marker.payload_hash.clone();
    payload[1] ^= 1;
    let mut flipped = sig.clone();
    flipped[0] ^= 1;
    let tampers: [(&str, Vec<u8>, Option<Vec<u8>>); 3] = [
        ("payload byte", payload, Some(sig.clone())),
        ("signature byte", marker.payload_hash.clone(), Some(flipped)),
        ("stripped signature", marker.payload_hash.clone(), None),
    ];
    for (what, ph, signature) in tampers {
        sqlx::query(
            "UPDATE signed_events SET payload_hash = $1, signature = $2 WHERE sequence = $3",
        )
        .bind(&ph)
        .bind(&signature)
        .bind(marker.sequence)
        .execute(pg.pool())
        .await
        .expect("tamper");
        assert_eq!(
            walk(&pg, &vk).await.signature_failures,
            vec![marker.sequence],
            "{what}"
        );
    }
    sqlx::query("UPDATE signed_events SET payload_hash = $1, signature = $2 WHERE sequence = $3")
        .bind(&marker.payload_hash)
        .bind(Some(sig))
        .bind(marker.sequence)
        .execute(pg.pool())
        .await
        .expect("restore");
    assert_eq!(walk(&pg, &vk).await.signature_failures, Vec::<i64>::new());
}

/// B-5 / S-3 — a second marker-type row, built and signed by the shared
/// constructor, makes every marker fail.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_marker_fails_both_markers_pg_10108() {
    let Some(url) = pg_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let vk = sink();
    let (scratch, pg) = scratch_store(&url).await;
    let pg = migrated_over_prefix(&scratch, pg).await;
    let first = markers(&pg).await.pop().expect("marker");
    assert_signed(&first);
    let second = signed_marker(Some(&first), MarkerOrigin::Migrate);
    let ts = DateTime::parse_from_rfc3339(&second.timestamp)
        .expect("rfc3339")
        .with_timezone(&Utc);
    let second = SignedEvent {
        timestamp: ts.to_rfc3339(),
        ..second
    };
    insert(&pg, &second, ts).await;
    assert_eq!(
        walk(&pg, &vk).await.signature_failures,
        vec![first.sequence, second.sequence]
    );
}

/// #10145 (W-10) — a v103 database whose marker is gone fails the walk at
/// the chain level, and a re-open writes no marker.
#[tokio::test(flavor = "multi_thread")]
async fn a_markerless_v103_database_fails_and_is_never_repaired_pg_10145() {
    let Some(url) = pg_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let vk = sink();
    let (scratch, pg) = scratch_store(&url).await;
    assert_eq!(
        markers(&pg).await.len(),
        1,
        "a fresh create writes one marker"
    );
    clear_chain(&pg).await;
    append_prefix(&pg).await;
    assert!(
        walk(&pg, &vk)
            .await
            .signature_failures
            .contains(&CHAIN_LEVEL),
        "a markerless v103 database fails at the chain level"
    );
    let pg = reopen(&scratch, pg).await;
    assert_eq!(markers(&pg).await.len(), 0, "a re-open repairs nothing");
    assert_eq!(version(&pg).await, V103_TIP);
    assert!(
        walk(&pg, &vk)
            .await
            .signature_failures
            .contains(&CHAIN_LEVEL),
        "a re-open leaves the chain-level failure"
    );
}
