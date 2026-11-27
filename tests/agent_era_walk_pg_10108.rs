// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
#![cfg(feature = "sal-postgres")]

//! #10108 step 2 (`3-agent vote (71472661)` B-4, B-6, S-4; #10135) — the
//! postgres leg of the two-era agent-row walk, and its parity with sqlite.
//!
//! One fixture of chain rows, receipts and tombstones is written to both
//! backends with the same bytes (micro-precision timestamps, daemon row
//! signatures over `daemon_row_signing_input`). Both walks must report the
//! same failing rows, the same erased-receipt count and the same legacy
//! agent-row count; the expected outcome of every row is written out below.
//! Soft-skips without `AI_MEMORY_TEST_POSTGRES_URL`.

use std::sync::OnceLock;

use ai_memory::db;
use ai_memory::governance::daemon_signer::{self, DaemonChainSigner, DaemonDomain};
use ai_memory::signed_events::agent_cutover::{MarkerOrigin, build_signed_marker};
use ai_memory::signed_events::agent_era::SourceBinding;
use ai_memory::signed_events::agent_payload::{
    AgentEventKind, AgentPayloadHash, AgentSignedPayload, AtomisationReceipt,
};
use ai_memory::signed_events::{
    AGENT_CUTOVER_EVENT_TYPE, AuditTrailReport, SignedEvent, ZERO_HASH, canonical_chain_bytes,
    daemon_row_signing_input, payload_hash, verify_audit_trail,
};
use ai_memory::store::postgres::PostgresStore;
use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

#[path = "common/home_sandbox.rs"]
mod home_sandbox;

#[path = "common/pg_barrier.rs"]
mod pg_barrier;

/// Scratch database name prefix for this file.
const SCRATCH_PREFIX: &str = "ai_memory_10108era";

/// The test daemon key.
const TEST_DAEMON_SEED: [u8; 32] = [0x5d; 32];
/// The atomisation event type.
const ATOMISATION: &str = "atomisation_complete";
/// The fixed receipt time.
const ATOMISED_AT: &str = "2026-11-26T00:00:00Z";
/// The fixture's first row time (whole seconds; rows step one second).
const FIRST_ROW_UNIX: i64 = 1_795_000_000;
/// The fixture's micro-second offset (postgres keeps micro-seconds).
const ROW_MICROS: i64 = 123_456;

/// What a fixture row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Spec {
    /// A daemon row of a non-agent kind.
    Daemon,
    /// A daemon atomisation row whose receipt is stored as signed.
    Genuine,
    /// A daemon atomisation row whose stored receipt lost an atom.
    Tampered,
    /// A daemon atomisation row whose receipt was erased under a tombstone.
    Erased,
    /// A daemon atomisation row with no receipt and no tombstone.
    Missing,
    /// A legacy agent row with a NULL signature.
    LegacyNull,
    /// A legacy agent row with a 63-byte signature.
    LegacyShort,
    /// The v103 cutover marker.
    Marker,
    /// An agent-labelled row above the marker (a pre-cutover writer).
    PreCutover,
}

/// The fixture in chain order, and the outcome both walks must report.
const FIXTURE: [(Spec, Outcome); 9] = [
    (Spec::Daemon, Outcome::Clean),
    (Spec::LegacyNull, Outcome::Clean),
    (Spec::LegacyShort, Outcome::Failed),
    (Spec::Marker, Outcome::Clean),
    (Spec::Genuine, Outcome::Clean),
    (Spec::Tampered, Outcome::Failed),
    (Spec::Erased, Outcome::Clean),
    (Spec::Missing, Outcome::Failed),
    (Spec::PreCutover, Outcome::Failed),
];
/// Agent-labelled rows below the marker (`LegacyNull`, `LegacyShort`).
const LEGACY_BELOW_MARKER: u64 = 2;
/// Rows of the fixture whose receipt was erased.
const WANT_ERASED: u64 = 1;
/// Legacy agent rows counted, never verified.
const WANT_LEGACY: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Clean,
    Failed,
}

fn sink() -> VerifyingKey {
    static SINK: OnceLock<tempfile::TempDir> = OnceLock::new();
    SINK.get_or_init(|| {
        let dir = home_sandbox::per_test_dir("forensic-era-pg-10108-");
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
fn test_process_resolves_no_path_under_the_real_home_10108() {
    let _ = home_sandbox::real_home();
    let _ = sink();
    home_sandbox::assert_process_isolated();
    let child = home_sandbox::per_test_dir("child-env-era-pg-10108-");
    for (key, path) in home_sandbox::child_env(child.path()) {
        home_sandbox::assert_outside_real_home(key, &path);
    }
}

fn pg_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// The receipt of fixture row `i` (`run` keeps sources unique per run).
fn receipt(run: &str, i: usize, atoms: &[&str]) -> AtomisationReceipt {
    AtomisationReceipt {
        source_id: format!("src-{run}-{i}"),
        atomised_at: ATOMISED_AT.to_string(),
        atom_ids: atoms.iter().map(|a| (*a).to_string()).collect(),
        atom_count: u64::try_from(atoms.len()).expect("count fits"),
        calling_agent_id: "ai:caller-10108".to_string(),
        curator_model: None,
    }
}

/// One stored receipt row: `(receipt, signature)`.
type StoredReceipt = (AtomisationReceipt, [u8; 64]);

/// The backend-neutral fixture: chain rows (without sequence and
/// prev_hash), receipts and forgotten source ids.
struct Fixture {
    rows: Vec<SignedEvent>,
    receipts: Vec<StoredReceipt>,
    forgotten: Vec<String>,
}

fn row_time(i: usize) -> DateTime<Utc> {
    let secs = FIRST_ROW_UNIX + i64::try_from(i).expect("index fits");
    Utc.timestamp_opt(secs, 0).single().expect("valid time") + Duration::microseconds(ROW_MICROS)
}

fn fixture(run: &str) -> Fixture {
    let key = SigningKey::from_bytes(&TEST_DAEMON_SEED);
    let pubkey = sink().to_bytes();
    let mut out = Fixture {
        rows: Vec::new(),
        receipts: Vec::new(),
        forgotten: Vec::new(),
    };
    for (i, (spec, _)) in FIXTURE.iter().enumerate() {
        let mut ev = SignedEvent {
            id: format!("era-pg-{run}-{i}"),
            agent_id: "daemon".to_string(),
            event_type: ATOMISATION.to_string(),
            attest_level: "daemon_signed".to_string(),
            timestamp: row_time(i).to_rfc3339(),
            ..SignedEvent::default()
        };
        match spec {
            Spec::Daemon => {
                ev.event_type = "governance.test".to_string();
                ev.payload_hash = payload_hash(ev.id.as_bytes());
            }
            Spec::Genuine | Spec::Tampered | Spec::Erased | Spec::Missing => {
                let r = receipt(run, i, &["a1", "a2"]);
                let bytes = r.canonical_bytes();
                let sig = key.sign(&bytes).to_bytes();
                ev.payload_hash = AgentPayloadHash::encode(&AgentSignedPayload {
                    kind: AgentEventKind::AtomisationComplete,
                    signed_bytes: &bytes,
                    signature: &sig,
                    pubkey: &pubkey,
                })
                .to_vec();
                ev.cause_hash = Some(SourceBinding::of_source(&r.source_id).as_bytes().to_vec());
                match spec {
                    Spec::Genuine => out.receipts.push((r, sig)),
                    Spec::Tampered => {
                        out.receipts.push((receipt(run, i, &["a1"]), sig));
                    }
                    Spec::Erased => out.forgotten.push(r.source_id),
                    _ => {}
                }
            }
            Spec::LegacyNull | Spec::LegacyShort | Spec::PreCutover => {
                ev.agent_id = "ai:agent-10108".to_string();
                ev.attest_level = "self_signed".to_string();
                ev.payload_hash = payload_hash(ev.id.as_bytes());
                ev.signature = match spec {
                    Spec::LegacyShort => Some(vec![7u8; 63]),
                    Spec::PreCutover => Some(vec![7u8; 64]),
                    _ => None,
                };
            }
            // `link` derives every committed field of the marker.
            Spec::Marker => ev.event_type = AGENT_CUTOVER_EVENT_TYPE.to_string(),
        }
        out.rows.push(ev);
    }
    out
}

/// Link `ev` after `head` (as both walks recompute it) and daemon-sign it;
/// a marker placeholder becomes the signed v103 marker above `head`, built by
/// the one shared constructor both backends' writers use.
fn link(mut ev: SignedEvent, head: Option<&SignedEvent>) -> SignedEvent {
    if ev.event_type == AGENT_CUTOVER_EVENT_TYPE {
        let head = head.expect("a marker sits above a row");
        let signer = DaemonChainSigner::provision_default().expect("daemon key installed");
        return build_signed_marker(
            &signer,
            Some(head),
            LEGACY_BELOW_MARKER,
            MarkerOrigin::Migrate,
            ev.id,
            ev.timestamp,
        )
        .map(Into::<SignedEvent>::into)
        .expect("marker above head");
    }
    let (seq, prev) = head.map_or((1, ZERO_HASH.to_vec()), |h| {
        (
            h.sequence + 1,
            Sha256::digest(canonical_chain_bytes(h)).to_vec(),
        )
    });
    ev.sequence = seq;
    if ev.attest_level == "daemon_signed" {
        let (sig, _) = daemon_signer::sign(DaemonDomain::EventRow, &daemon_row_signing_input(&ev))
            .expect("daemon key installed");
        ev.signature = Some(sig);
    }
    ev.prev_hash = prev;
    ev
}

/// The fixture outcome as offsets from the fixture's first sequence.
fn outcome(report: &AuditTrailReport, first_seq: i64) -> Vec<Outcome> {
    (0..FIXTURE.len())
        .map(|i| {
            let seq = first_seq + i64::try_from(i).expect("index fits");
            if report.signature_failures.contains(&seq) {
                Outcome::Failed
            } else {
                Outcome::Clean
            }
        })
        .collect()
}

fn sqlite_leg(run: &str) -> (Vec<Outcome>, AuditTrailReport) {
    let vk = sink();
    let dir = home_sandbox::per_test_dir("agent-era-pg-10108-");
    let conn = db::open(&dir.path().join("era.db")).expect("open db");
    let fx = fixture(run);
    clear_chain_sqlite(&conn);
    assert_no_marker(&conn);
    let mut head = sqlite_head(&conn);
    let mut first_seq = None;
    for ev in fx.rows {
        let ev = link(ev, head.as_ref());
        first_seq.get_or_insert(ev.sequence);
        conn.execute(
            "INSERT INTO signed_events \
                (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                 prev_hash, sequence, cause_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                ev.id,
                ev.agent_id,
                ev.event_type,
                ev.payload_hash,
                ev.signature,
                ev.attest_level,
                ev.timestamp,
                ev.prev_hash,
                ev.sequence,
                ev.cause_hash
            ],
        )
        .expect("insert sqlite row");
        head = Some(ev);
    }
    for (r, sig) in &fx.receipts {
        conn.execute(
            "INSERT INTO atomisation_receipts \
                (source_id, atomised_at, atom_ids, atom_count, calling_agent_id, curator_model, \
                 signer_agent_id, signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'daemon', ?7)",
            rusqlite::params![
                r.source_id,
                r.atomised_at,
                serde_json::to_string(&r.atom_ids).expect("json"),
                i64::try_from(r.atom_count).expect("fits"),
                r.calling_agent_id,
                r.curator_model,
                sig.to_vec()
            ],
        )
        .expect("insert sqlite receipt");
    }
    for id in &fx.forgotten {
        conn.execute(
            "INSERT INTO forget_tombstones (memory_id, namespace, forgotten_at) \
             VALUES (?1, 'era-10108', ?2)",
            rusqlite::params![id, ATOMISED_AT],
        )
        .expect("insert sqlite tombstone");
    }
    let report = verify_audit_trail(&conn, None, Some(&vk)).expect("sqlite verify");
    assert!(report.chain_intact, "sqlite fixture chain: {report:?}");
    (outcome(&report, first_seq.expect("rows")), report)
}

fn sqlite_head(conn: &rusqlite::Connection) -> Option<SignedEvent> {
    conn.query_row(
        "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                sequence, cause_hash FROM signed_events WHERE sequence IS NOT NULL \
         ORDER BY sequence DESC LIMIT 1",
        [],
        |r| {
            Ok(SignedEvent {
                id: r.get(0)?,
                agent_id: r.get(1)?,
                event_type: r.get(2)?,
                payload_hash: r.get(3)?,
                signature: r.get(4)?,
                attest_level: r.get(5)?,
                timestamp: r.get(6)?,
                prev_hash: Vec::new(),
                sequence: r.get(7)?,
                cause_hash: r.get(8)?,
            })
        },
    )
    .optional()
    .expect("read sqlite head")
}

/// #10145 — a fresh database holds its genesis marker; the fixture is its
/// own whole chain (with the only marker), so the leg starts from no rows.
fn clear_chain_sqlite(conn: &rusqlite::Connection) {
    conn.execute("DELETE FROM signed_events", [])
        .expect("clear sqlite chain");
}

/// The fixture adds the only marker; a database that already holds one
/// would make both walks unresolvable.
fn assert_no_marker(conn: &rusqlite::Connection) {
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            [AGENT_CUTOVER_EVENT_TYPE],
            |r| r.get(0),
        )
        .expect("count markers");
    assert_eq!(n, 0, "the sqlite fixture base holds no marker");
}

async fn pg_head(pool: &sqlx::PgPool) -> Option<SignedEvent> {
    type Row = (
        String,
        String,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        String,
        DateTime<Utc>,
        i64,
        Option<Vec<u8>>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                sequence, cause_hash FROM signed_events WHERE sequence IS NOT NULL \
         ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .expect("read pg head");
    row.map(
        |(id, agent_id, event_type, ph, sig, attest, ts, seq, cause)| SignedEvent {
            id,
            agent_id,
            event_type,
            payload_hash: ph,
            signature: sig,
            attest_level: attest,
            timestamp: ts.to_rfc3339(),
            prev_hash: Vec::new(),
            sequence: seq,
            cause_hash: cause,
        },
    )
}

async fn pg_leg(pg: &PostgresStore, run: &str) -> (Vec<Outcome>, AuditTrailReport) {
    let vk = sink();
    let pool = pg.pool();
    let fx = fixture(run);
    sqlx::query("DELETE FROM signed_events")
        .execute(pool)
        .await
        .expect("clear pg chain (the genesis marker of a fresh create)");
    let markers: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM signed_events WHERE event_type = $1")
            .bind(AGENT_CUTOVER_EVENT_TYPE)
            .fetch_one(pool)
            .await
            .expect("count pg markers");
    assert_eq!(
        markers, 0,
        "the pg fixture base holds no marker (isolated db)"
    );
    let mut head = pg_head(pool).await;
    let mut first_seq = None;
    for (i, ev) in fx.rows.into_iter().enumerate() {
        let ev = link(ev, head.as_ref());
        first_seq.get_or_insert(ev.sequence);
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
        .bind(row_time(i))
        .bind(&ev.prev_hash)
        .bind(ev.sequence)
        .bind(&ev.cause_hash)
        .execute(pool)
        .await
        .expect("insert pg row");
        head = Some(ev);
    }
    for (r, sig) in &fx.receipts {
        sqlx::query(
            "INSERT INTO atomisation_receipts \
                (source_id, atomised_at, atom_ids, atom_count, calling_agent_id, curator_model, \
                 signer_agent_id, signature) VALUES ($1,$2,$3,$4,$5,$6,'daemon',$7)",
        )
        .bind(&r.source_id)
        .bind(&r.atomised_at)
        .bind(serde_json::to_string(&r.atom_ids).expect("json"))
        .bind(i64::try_from(r.atom_count).expect("fits"))
        .bind(&r.calling_agent_id)
        .bind(&r.curator_model)
        .bind(sig.to_vec())
        .execute(pool)
        .await
        .expect("insert pg receipt");
    }
    for id in &fx.forgotten {
        sqlx::query(
            "INSERT INTO forget_tombstones (memory_id, namespace, forgotten_at) \
             VALUES ($1, 'era-10108', $2)",
        )
        .bind(id)
        .bind(ATOMISED_AT)
        .execute(pool)
        .await
        .expect("insert pg tombstone");
    }
    let report = pg
        .verify_audit_trail(None, Some(&vk))
        .await
        .expect("pg verify");
    assert!(report.chain_intact, "pg fixture chain: {report:?}");
    (outcome(&report, first_seq.expect("rows")), report)
}

/// B-4 / S-4 / #10135 — both backends give every fixture row the written
/// outcome and the same counts.
#[tokio::test]
async fn agent_era_walk_parity_10108() {
    let Some(url) = pg_url() else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    // The daemon key first, so the schema create signs with the test key.
    let _ = sink();
    let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
        .await
        .expect("create scratch database");
    let pg = PostgresStore::connect(&scratch.url())
        .await
        .expect("pg connect");
    let run = uuid::Uuid::new_v4().simple().to_string();
    let want: Vec<Outcome> = FIXTURE.iter().map(|(_, o)| *o).collect();

    let (sqlite_out, sqlite_report) = sqlite_leg(&run);
    assert_eq!(sqlite_out, want, "sqlite outcomes");
    assert_eq!(sqlite_report.agent_receipts_erased, WANT_ERASED);
    assert_eq!(sqlite_report.agent_signed_rows_not_verified, WANT_LEGACY);

    let (pg_out, pg_report) = pg_leg(&pg, &run).await;
    assert_eq!(pg_out, want, "pg outcomes");
    assert_eq!(pg_report.agent_receipts_erased, WANT_ERASED);
    assert_eq!(pg_report.agent_signed_rows_not_verified, WANT_LEGACY);
}
