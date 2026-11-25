// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #10074 (S-7, `3-agent vote (71472661) V1-SIGNED-EVENTS-FALLBACK`) —
//! SQLite and PostgreSQL give identical results for the legacy cutoff.
//!
//! Each scenario builds the same row shape on both backends (legacy
//! payload-only and identity rows signed the way a pre-#10074 binary signed
//! them, domain-tagged rows, the operator mint), applies the same tamper, and
//! asserts the audit-trail signature failures and the mint refusals equal a
//! WRITTEN-OUT expected value on each backend, so the two can only agree by
//! both being right. The PostgreSQL cell runs under
//! `AI_MEMORY_TEST_POSTGRES_URL` on a scratch database and skips otherwise.

#![cfg(feature = "sal-postgres")]

use std::sync::OnceLock;

use ai_memory::governance::daemon_signer::{self, DaemonDomain};
use ai_memory::signed_events::{
    LEGACY_CUTOFF_EVENT_TYPE, LegacyCutoffMintRefusal, LegacyCutoffMinted, SignedEvent, ZERO_HASH,
    canonical_chain_bytes, daemon_row_signing_input, payload_hash, verify_audit_trail,
};
use ai_memory::store::postgres::PostgresStore;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

#[path = "common/legacy_cutoff_cli.rs"]
mod cli;
#[path = "common/home_sandbox.rs"]
mod home_sandbox;
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

/// Deterministic seed for the one daemon key this test binary installs.
const TEST_DAEMON_SEED: [u8; 32] = [0x5a; 32];
/// Event type of the fixture rows.
const FIXTURE_EVENT_TYPE: &str = "governance.test";
/// Prefix of this binary's scratch databases (swept when stale).
const SCRATCH_PREFIX: &str = "legacy_cutoff_10074";
const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";

fn legacy_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_DAEMON_SEED)
}

/// Start the forensic sink once (the mint needs it and the daemon key).
fn sink() -> VerifyingKey {
    static SINK: OnceLock<tempfile::TempDir> = OnceLock::new();
    SINK.get_or_init(|| {
        let dir = home_sandbox::per_test_dir("forensic-10074-pg-");
        ai_memory::governance::audit::init(dir.path(), Some(legacy_key())).expect("init sink");
        dir
    });
    daemon_signer::verifying_key().expect("daemon key installed")
}

/// #10007 — no path this test process can write resolves under the real HOME
/// (witness key directory and head-anchor log, key directory, temporary root).
#[test]
fn test_process_resolves_no_path_under_the_real_home_10007() {
    let _ = home_sandbox::real_home();
    let _ = sink();
    home_sandbox::assert_process_isolated();
}

/// One row of a scenario, in chain order.
#[derive(Clone, Copy, Debug)]
enum Row {
    /// Untagged signature over `payload_hash` (pre-#10074 payload-only form).
    PayloadOnly,
    /// Untagged signature over the identity digest (pre-#10074 #1925 form).
    Identity,
    /// Typed-signer signature over the identity digest under this domain.
    Tagged(DaemonDomain),
    /// A signature that verifies under no form.
    Garbage,
    /// #10101 — the forensic sink's form: the daemon key's untagged signature
    /// over a JSON record, the record bytes stored as the payload hash.
    Sink,
    /// #10105 — an agent-signed row of this `attest_level`, signed by an
    /// agent key (never the daemon key) in the given form.
    Agent(&'static str, AgentSig),
}

/// #10105 — the signature an agent-signed fixture row carries.
#[derive(Clone, Copy, Debug)]
enum AgentSig {
    /// A 64-byte Ed25519 signature by the agent key.
    Valid,
    /// No signature (NULL column).
    Missing,
    /// A blob of the wrong length.
    Short,
}

/// #10105 — the agent fixture key (distinct from the daemon key).
const TEST_AGENT_SEED: [u8; 32] = [0x6b; 32];
/// #10105 — length of the wrong-length signature blob.
const SHORT_SIG_LEN: usize = 10;

/// #10101 — a forensic-sink-shaped record (JSON, never a 32-byte digest).
const SINK_RECORD: &[u8] =
    br#"{"ts":"2026-11-24T00:00:00.000Z","actor":"daemon","decision":"allow","kind":"10101"}"#;

/// A tamper applied after the rows and the mint.
#[derive(Clone, Copy, Debug)]
enum Tamper {
    None,
    /// Row 1 takes row 2's identity digest as payload hash and row 2's
    /// signature; the chain is relinked.
    TransplantIntoPrefix,
    /// Row 2 (identity form) is replaced by another validly signed
    /// identity-form row: same form, count and db identity.
    SameFormSubstitution,
    /// A second row of the reserved cutoff type, a copy of the first.
    DuplicateCutoff,
    /// The cutoff row's payload hash is changed.
    CutoffPayload,
}

struct Scenario {
    name: &'static str,
    before_mint: &'static [Row],
    mint: bool,
    after_mint: &'static [Row],
    tamper: Tamper,
    /// Expected `signature_failures`, written out.
    failures: &'static [i64],
}

const P: Row = Row::PayloadOnly;
const I: Row = Row::Identity;
const T: Row = Row::Tagged(DaemonDomain::EventRow);

/// Every scenario; sequences start at 1 on a fresh store.
const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "minted prefix is clean",
        before_mint: &[P, I, T],
        mint: true,
        after_mint: &[T],
        tamper: Tamper::None,
        failures: &[],
    },
    Scenario {
        name: "S-1 transplant into the prefix voids the cutoff",
        before_mint: &[P, I, T],
        mint: true,
        after_mint: &[],
        tamper: Tamper::TransplantIntoPrefix,
        failures: &[1, 2, 4],
    },
    Scenario {
        name: "S-1 same-form substitution in the prefix voids the cutoff",
        before_mint: &[P, I, T],
        mint: true,
        after_mint: &[],
        tamper: Tamper::SameFormSubstitution,
        failures: &[1, 2, 4],
    },
    Scenario {
        name: "S-2 duplicated cutoff row means cutoff zero",
        before_mint: &[P, I, T],
        mint: true,
        after_mint: &[],
        tamper: Tamper::DuplicateCutoff,
        failures: &[1, 2, 4, 5],
    },
    Scenario {
        name: "S-2 tampered cutoff row means cutoff zero",
        before_mint: &[P, I, T],
        mint: true,
        after_mint: &[],
        tamper: Tamper::CutoffPayload,
        failures: &[1, 2, 4],
    },
    Scenario {
        name: "S-2 no cutoff row refuses every legacy row",
        before_mint: &[T, P, I],
        mint: false,
        after_mint: &[],
        tamper: Tamper::None,
        failures: &[2, 3],
    },
    Scenario {
        name: "S-5/S-6 legacy rows above the cutoff fail",
        before_mint: &[P, I, T],
        mint: true,
        after_mint: &[I, P, T],
        tamper: Tamper::None,
        failures: &[5, 6],
    },
    Scenario {
        name: "S-4 every other domain in a ledger row fails",
        before_mint: &[
            T,
            Row::Tagged(DaemonDomain::EventPayload),
            Row::Tagged(DaemonDomain::Governance),
            Row::Tagged(DaemonDomain::Tombstone),
            Row::Tagged(DaemonDomain::RevisionLeaf),
            Row::Tagged(DaemonDomain::LegacyCutoff),
        ],
        mint: false,
        after_mint: &[],
        tamper: Tamper::None,
        failures: &[2, 3, 4, 5, 6],
    },
];

fn make_row(kind: Row, sequence: i64, timestamp: String) -> SignedEvent {
    let mut ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: FIXTURE_EVENT_TYPE.to_string(),
        payload_hash: payload_hash(uuid::Uuid::new_v4().as_bytes()),
        signature: None,
        attest_level: "daemon_signed".to_string(),
        timestamp,
        prev_hash: ZERO_HASH.to_vec(),
        sequence,
        cause_hash: None,
    };
    let sig = match kind {
        Row::PayloadOnly => legacy_key().sign(&ev.payload_hash).to_bytes().to_vec(),
        Row::Identity => legacy_key()
            .sign(&daemon_row_signing_input(&ev))
            .to_bytes()
            .to_vec(),
        Row::Tagged(d) => {
            daemon_signer::sign(d, &daemon_row_signing_input(&ev))
                .expect("signer installed")
                .0
        }
        Row::Garbage => vec![7u8; 64],
        Row::Sink => {
            ev.payload_hash = SINK_RECORD.to_vec();
            legacy_key().sign(SINK_RECORD).to_bytes().to_vec()
        }
        Row::Agent(attest, form) => {
            ev.agent_id = "ai:agent-10105".to_string();
            attest.clone_into(&mut ev.attest_level);
            ev.signature = match form {
                AgentSig::Valid => Some(
                    SigningKey::from_bytes(&TEST_AGENT_SEED)
                        .sign(&ev.payload_hash)
                        .to_bytes()
                        .to_vec(),
                ),
                AgentSig::Missing => None,
                AgentSig::Short => Some(vec![1u8; SHORT_SIG_LEN]),
            };
            return ev;
        }
    };
    ev.signature = Some(sig);
    ev
}

/// The PostgreSQL-safe timestamp (TIMESTAMPTZ keeps microseconds), as the
/// RFC 3339 string the row is signed over and read back as.
fn micros_now() -> chrono::DateTime<chrono::Utc> {
    let now = chrono::Utc::now();
    chrono::DateTime::from_timestamp_micros(now.timestamp_micros()).expect("in range")
}

/// The canonical chain hash of `row` (the next row's `prev_hash`).
fn chain_hash(row: &SignedEvent) -> Vec<u8> {
    Sha256::digest(canonical_chain_bytes(row)).to_vec()
}

fn relinked(mut rows: Vec<SignedEvent>) -> Vec<SignedEvent> {
    let mut prev = ZERO_HASH.to_vec();
    for r in &mut rows {
        r.prev_hash.clone_from(&prev);
        prev = Sha256::digest(canonical_chain_bytes(r)).to_vec();
    }
    rows
}

/// The rows a tamper rewrites (relinked), or `None` for no rewrite.
fn tampered(rows: &[SignedEvent], tamper: Tamper) -> Option<Vec<SignedEvent>> {
    let mut rows = rows.to_vec();
    match tamper {
        Tamper::None => return None,
        Tamper::TransplantIntoPrefix => {
            let donor = rows[1].clone();
            rows[0].id = uuid::Uuid::new_v4().to_string();
            rows[0].payload_hash = daemon_row_signing_input(&donor);
            rows[0].signature.clone_from(&donor.signature);
        }
        Tamper::SameFormSubstitution => {
            // Row 2 (identity form), not the genesis row the db id derives from.
            rows[1].id = uuid::Uuid::new_v4().to_string();
            rows[1].payload_hash = payload_hash(b"another legacy identity-form row, 10074");
            let sig = legacy_key().sign(&daemon_row_signing_input(&rows[1]));
            rows[1].signature = Some(sig.to_bytes().to_vec());
        }
        Tamper::DuplicateCutoff => {
            let cutoff = rows
                .iter()
                .find(|r| r.event_type == LEGACY_CUTOFF_EVENT_TYPE)
                .expect("a cutoff row")
                .clone();
            let mut copy = cutoff;
            copy.id = uuid::Uuid::new_v4().to_string();
            copy.sequence = rows.last().map_or(1, |r| r.sequence + 1);
            rows.push(copy);
        }
        Tamper::CutoffPayload => {
            let c = rows
                .iter_mut()
                .find(|r| r.event_type == LEGACY_CUTOFF_EVENT_TYPE)
                .expect("a cutoff row");
            c.payload_hash = payload_hash(b"not the prefix");
        }
    }
    Some(relinked(rows))
}

// ----- SQLite cell -------------------------------------------------------

mod sqlite {
    use super::{Row, SignedEvent, micros_now};
    use rusqlite::params;

    pub fn open() -> (tempfile::TempDir, std::path::PathBuf, rusqlite::Connection) {
        let _ = super::sink();
        let dir = super::home_sandbox::per_test_dir("legacy-cutoff-10074-pg-twin-");
        let path = dir.path().join("twin.db");
        let conn = ai_memory::db::open(&path).expect("open db");
        (dir, path, conn)
    }

    pub fn load(conn: &rusqlite::Connection) -> Vec<SignedEvent> {
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

    pub fn replace_all(conn: &rusqlite::Connection, rows: &[SignedEvent]) {
        conn.execute("DELETE FROM signed_events", [])
            .expect("clear");
        for r in rows {
            insert(conn, r);
        }
    }

    fn insert(conn: &rusqlite::Connection, r: &SignedEvent) {
        conn.execute(
            "INSERT INTO signed_events \
                (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                 prev_hash, sequence, cause_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
            params![
                r.id,
                r.agent_id,
                r.event_type,
                r.payload_hash,
                r.signature,
                r.attest_level,
                r.timestamp,
                r.prev_hash,
                r.sequence
            ],
        )
        .expect("insert");
    }

    pub fn append(conn: &rusqlite::Connection, kinds: &[Row]) {
        for &k in kinds {
            let rows = load(conn);
            let seq = rows.last().map_or(1, |r| r.sequence + 1);
            let mut row = super::make_row(k, seq, micros_now().to_rfc3339());
            if let Some(last) = rows.last() {
                row.prev_hash = super::chain_hash(last);
            }
            insert(conn, &row);
        }
    }
}

// ----- PostgreSQL cell ---------------------------------------------------

mod pg {
    use super::{Row, SignedEvent, micros_now};
    use ai_memory::store::postgres::PostgresStore;

    type WalkRow = (
        String,
        String,
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        String,
        chrono::DateTime<chrono::Utc>,
        Vec<u8>,
        i64,
        Option<Vec<u8>>,
    );

    pub async fn load(store: &PostgresStore) -> Vec<SignedEvent> {
        let rows: Vec<WalkRow> = sqlx::query_as(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
                    timestamp, prev_hash, sequence, cause_hash \
             FROM signed_events ORDER BY sequence ASC",
        )
        .fetch_all(store.pool())
        .await
        .expect("load rows");
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

    async fn insert(store: &PostgresStore, r: &SignedEvent) {
        let ts = chrono::DateTime::parse_from_rfc3339(&r.timestamp)
            .expect("rfc3339")
            .with_timezone(&chrono::Utc);
        sqlx::query(
            "INSERT INTO signed_events \
                (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                 prev_hash, sequence, cause_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL)",
        )
        .bind(&r.id)
        .bind(&r.agent_id)
        .bind(&r.event_type)
        .bind(&r.payload_hash)
        .bind(&r.signature)
        .bind(&r.attest_level)
        .bind(ts)
        .bind(&r.prev_hash)
        .bind(r.sequence)
        .execute(store.pool())
        .await
        .expect("insert");
    }

    pub async fn replace_all(store: &PostgresStore, rows: &[SignedEvent]) {
        sqlx::query("DELETE FROM signed_events")
            .execute(store.pool())
            .await
            .expect("clear");
        for r in rows {
            insert(store, r).await;
        }
    }

    pub async fn append(store: &PostgresStore, kinds: &[Row]) {
        for &k in kinds {
            let rows = load(store).await;
            let seq = rows.last().map_or(1, |r| r.sequence + 1);
            let mut row = super::make_row(k, seq, micros_now().to_rfc3339());
            if let Some(last) = rows.last() {
                row.prev_hash = super::chain_hash(last);
            }
            insert(store, &row).await;
        }
    }
}

fn pg_url() -> Option<String> {
    match std::env::var(PG_URL_ENV) {
        Ok(u) if !u.trim().is_empty() => Some(u),
        _ => {
            eprintln!("SKIP signed_events_legacy_cutoff_10074_pg: {PG_URL_ENV} unset");
            None
        }
    }
}

async fn fresh_pg(url: &str) -> (pg_barrier::ScratchDb, PostgresStore) {
    let _ = sink();
    let scratch = pg_barrier::ScratchDb::create(url, SCRATCH_PREFIX)
        .await
        .expect("create scratch database");
    let store = PostgresStore::connect(&scratch.url())
        .await
        .expect("connect scratch database");
    (scratch, store)
}

/// S-7 — every scenario gives the written-out failures on SQLite AND on
/// PostgreSQL.
#[tokio::test(flavor = "multi_thread")]
async fn s7_backends_agree_on_every_cutoff_scenario_10074() {
    let vk = sink();
    let Some(url) = pg_url() else { return };
    for sc in SCENARIOS {
        // SQLite.
        let (_d, _p, conn) = sqlite::open();
        sqlite::append(&conn, sc.before_mint);
        if sc.mint {
            let minted = ai_memory::signed_events::mint_legacy_cutoff(&conn).expect("mint runs");
            assert!(minted.is_ok(), "{}: sqlite mint {minted:?}", sc.name);
        }
        sqlite::append(&conn, sc.after_mint);
        if let Some(rows) = tampered(&sqlite::load(&conn), sc.tamper) {
            sqlite::replace_all(&conn, &rows);
        }
        let trail = verify_audit_trail(&conn, None, Some(&vk)).expect("sqlite verify");
        assert!(trail.chain_intact, "{}: sqlite chain intact", sc.name);
        assert_eq!(trail.signature_failures, sc.failures, "{}: sqlite", sc.name);

        // PostgreSQL.
        let (_scratch, store) = fresh_pg(&url).await;
        pg::append(&store, sc.before_mint).await;
        if sc.mint {
            let minted = store.mint_legacy_cutoff().await.expect("pg mint runs");
            assert!(minted.is_ok(), "{}: pg mint {minted:?}", sc.name);
        }
        pg::append(&store, sc.after_mint).await;
        if let Some(rows) = tampered(&pg::load(&store).await, sc.tamper) {
            pg::replace_all(&store, &rows).await;
        }
        let trail = store
            .verify_audit_trail(None, Some(&vk))
            .await
            .expect("pg verify");
        assert!(trail.chain_intact, "{}: pg chain intact", sc.name);
        assert_eq!(trail.signature_failures, sc.failures, "{}: pg", sc.name);
    }
}

/// S-3 / S-7 — the mint refusals are the same on both backends: a second
/// mint, a re-mint after the cutoff row is deleted (the off-table anchor),
/// an unverifiable prefix row.
#[tokio::test(flavor = "multi_thread")]
async fn s7_mint_refusals_agree_10074() {
    let _ = sink();
    let Some(url) = pg_url() else { return };

    // SQLite.
    let (_d, path, conn) = sqlite::open();
    sqlite::append(&conn, &[P, I, T]);
    let mint = ai_memory::signed_events::mint_legacy_cutoff;
    assert_eq!(
        mint(&conn).expect("mint runs"),
        Ok(LegacyCutoffMinted::Minted(4))
    );
    assert_eq!(
        mint(&conn).expect("mint runs"),
        Err(LegacyCutoffMintRefusal::CutoffRowExists)
    );
    conn.execute("DELETE FROM signed_events WHERE sequence = 4", [])
        .expect("delete cutoff");
    drop(conn);
    let conn = ai_memory::db::open(&path).expect("re-open runs migrations");
    assert_eq!(
        mint(&conn).expect("mint runs"),
        Err(LegacyCutoffMintRefusal::AnchorExists)
    );
    let (_d2, _p2, conn) = sqlite::open();
    sqlite::append(&conn, &[T, Row::Garbage]);
    assert_eq!(
        mint(&conn).expect("mint runs"),
        Err(LegacyCutoffMintRefusal::UnverifiableRow(2))
    );

    // PostgreSQL.
    let (scratch, store) = fresh_pg(&url).await;
    pg::append(&store, &[P, I, T]).await;
    assert_eq!(
        store.mint_legacy_cutoff().await.expect("mint runs"),
        Ok(LegacyCutoffMinted::Minted(4))
    );
    assert_eq!(
        store.mint_legacy_cutoff().await.expect("mint runs"),
        Err(LegacyCutoffMintRefusal::CutoffRowExists)
    );
    sqlx::query("DELETE FROM signed_events WHERE sequence = 4")
        .execute(store.pool())
        .await
        .expect("delete cutoff");
    drop(store);
    let store = PostgresStore::connect(&scratch.url())
        .await
        .expect("re-connect runs migrations");
    let cutoffs: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM signed_events WHERE event_type = $1")
            .bind(LEGACY_CUTOFF_EVENT_TYPE)
            .fetch_one(store.pool())
            .await
            .expect("count");
    assert_eq!(cutoffs, 0, "no boot or migration path mints");
    assert_eq!(
        store.mint_legacy_cutoff().await.expect("mint runs"),
        Err(LegacyCutoffMintRefusal::AnchorExists)
    );
    let (_scratch2, store) = fresh_pg(&url).await;
    pg::append(&store, &[T, Row::Garbage]).await;
    assert_eq!(
        store.mint_legacy_cutoff().await.expect("mint runs"),
        Err(LegacyCutoffMintRefusal::UnverifiableRow(2))
    );
}

/// What the mint must do over one prefix.
#[derive(Debug)]
enum MintOutcome {
    /// The mint succeeds; the certified legacy prefix is rows `1..=legacy_end`
    /// (0 = no legacy row), which ends before the first tagged row.
    Certified { legacy_end: i64 },
    /// The mint refuses with exactly this reason and writes nothing.
    Refused(LegacyCutoffMintRefusal),
}

struct MintCase {
    name: &'static str,
    rows: &'static [Row],
    outcome: MintOutcome,
}

/// #10101 / #10102 — every case, with the expected outcome written out.
const MINT_CASES: &[MintCase] = &[
    MintCase {
        name: "legacy prefix then a tagged row",
        rows: &[P, I, T],
        outcome: MintOutcome::Certified { legacy_end: 2 },
    },
    MintCase {
        name: "legacy rows only",
        rows: &[P, P],
        outcome: MintOutcome::Certified { legacy_end: 2 },
    },
    MintCase {
        name: "tagged rows only",
        rows: &[T, T],
        outcome: MintOutcome::Certified { legacy_end: 0 },
    },
    MintCase {
        name: "#10102 payload-only row after one tagged row",
        rows: &[P, T, P],
        outcome: MintOutcome::Refused(LegacyCutoffMintRefusal::LegacyAfterTagged {
            sequence: 3,
            first_tagged: 2,
        }),
    },
    MintCase {
        name: "#10102 identity row after two tagged rows",
        rows: &[I, T, T, I],
        outcome: MintOutcome::Refused(LegacyCutoffMintRefusal::LegacyAfterTagged {
            sequence: 4,
            first_tagged: 2,
        }),
    },
    MintCase {
        name: "#10102 legacy row after a tagged genesis",
        rows: &[T, P],
        outcome: MintOutcome::Refused(LegacyCutoffMintRefusal::LegacyAfterTagged {
            sequence: 2,
            first_tagged: 1,
        }),
    },
    MintCase {
        name: "#10101 sink signature after a legacy row",
        rows: &[P, Row::Sink],
        outcome: MintOutcome::Refused(LegacyCutoffMintRefusal::ForeignSignatureForm(2)),
    },
    MintCase {
        name: "#10101 sink signature at genesis",
        rows: &[Row::Sink, P],
        outcome: MintOutcome::Refused(LegacyCutoffMintRefusal::ForeignSignatureForm(1)),
    },
    MintCase {
        name: "#10101 sink signature after a tagged row",
        rows: &[P, T, Row::Sink],
        outcome: MintOutcome::Refused(LegacyCutoffMintRefusal::ForeignSignatureForm(3)),
    },
    MintCase {
        name: "unverifiable row after a tagged row",
        rows: &[P, T, Row::Garbage],
        outcome: MintOutcome::Refused(LegacyCutoffMintRefusal::UnverifiableRow(3)),
    },
];

/// Rows of the reserved cutoff type in the sqlite table.
fn sqlite_cutoff_rows(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        rusqlite::params![LEGACY_CUTOFF_EVENT_TYPE],
        |r| r.get(0),
    )
    .expect("count")
}

/// #10101 / #10102 (S-7) — the mint certifies as legacy only rows that are
/// legacy by construction, in a contiguous prefix that ends before the first
/// tagged row, or refuses with the exact reason; SQLite and PostgreSQL agree.
#[tokio::test(flavor = "multi_thread")]
async fn c2_mint_certifies_only_a_contiguous_legacy_prefix_10101_10102() {
    let vk = sink();
    for case in MINT_CASES {
        let (_d, _p, conn) = sqlite::open();
        sqlite::append(&conn, case.rows);
        let head = i64::try_from(case.rows.len()).expect("small");
        let minted = ai_memory::signed_events::mint_legacy_cutoff(&conn).expect("mint runs");
        match &case.outcome {
            MintOutcome::Certified { legacy_end } => {
                assert_eq!(
                    minted,
                    Ok(LegacyCutoffMinted::Minted(head + 1)),
                    "{}: sqlite mint",
                    case.name
                );
                let cutoff =
                    ai_memory::signed_events::resolve_sqlite_legacy_cutoff(&conn, Some(&vk))
                        .expect("resolve");
                assert_eq!(cutoff.sequence(), *legacy_end, "{}: legacy end", case.name);
                assert_eq!(cutoff.row_sequence(), Some(head + 1), "{}: row", case.name);
                let trail = verify_audit_trail(&conn, None, Some(&vk)).expect("verify");
                assert_eq!(trail.signature_failures, Vec::<i64>::new(), "{}", case.name);
            }
            MintOutcome::Refused(reason) => {
                assert_eq!(minted, Err(reason.clone()), "{}: sqlite refusal", case.name);
                assert_eq!(
                    sqlite_cutoff_rows(&conn),
                    0,
                    "{}: nothing written",
                    case.name
                );
            }
        }
    }
    let Some(url) = pg_url() else { return };
    for case in MINT_CASES {
        let (_scratch, store) = fresh_pg(&url).await;
        pg::append(&store, case.rows).await;
        let head = i64::try_from(case.rows.len()).expect("small");
        let minted = store.mint_legacy_cutoff().await.expect("pg mint runs");
        let cutoffs: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM signed_events WHERE event_type = $1")
                .bind(LEGACY_CUTOFF_EVENT_TYPE)
                .fetch_one(store.pool())
                .await
                .expect("count");
        match &case.outcome {
            MintOutcome::Certified { .. } => {
                assert_eq!(
                    minted,
                    Ok(LegacyCutoffMinted::Minted(head + 1)),
                    "{}: pg mint",
                    case.name
                );
                assert_eq!(cutoffs, 1, "{}: one cutoff row", case.name);
                let trail = store
                    .verify_audit_trail(None, Some(&vk))
                    .await
                    .expect("pg verify");
                assert_eq!(trail.signature_failures, Vec::<i64>::new(), "{}", case.name);
            }
            MintOutcome::Refused(reason) => {
                assert_eq!(minted, Err(reason.clone()), "{}: pg refusal", case.name);
                assert_eq!(cutoffs, 0, "{}: nothing written", case.name);
            }
        }
    }
}

/// #10106 — the `DaemonDomain::LegacyCutoff` tag, written out.
const LEGACY_CUTOFF_TAG_BYTES: &[u8] = b"ai-memory/daemon-sig/v2/legacy-cutoff\0";

/// #10106 (S-7) — the PostgreSQL mint signs the cutoff row over the
/// written-out domain bytes, and a cutoff row the test signs over those bytes
/// is the one the PostgreSQL verify accepts (a swap of both sides is red).
#[tokio::test(flavor = "multi_thread")]
async fn c3_pg_cutoff_domain_bytes_are_pinned_10106() {
    let vk = sink();
    let Some(url) = pg_url() else { return };
    let (_scratch, store) = fresh_pg(&url).await;
    pg::append(&store, &[P, I, T]).await;
    let minted = store.mint_legacy_cutoff().await.expect("pg mint runs");
    assert_eq!(minted, Ok(LegacyCutoffMinted::Minted(4)), "pg mint");
    let mut rows = pg::load(&store).await;
    let cutoff = rows
        .iter_mut()
        .find(|r| r.event_type == LEGACY_CUTOFF_EVENT_TYPE)
        .expect("the cutoff row");
    let preimage = [LEGACY_CUTOFF_TAG_BYTES, &daemon_row_signing_input(cutoff)].concat();
    let sig = ed25519_dalek::Signature::from_slice(cutoff.signature.as_deref().expect("signed"))
        .expect("64-byte signature");
    assert!(
        vk.verify_strict(&preimage, &sig).is_ok(),
        "the pg cutoff row is signed over the pinned domain bytes"
    );
    // Verify side: the test's own signature over the pinned bytes (fresh id,
    // so the bytes are not the mint's) is accepted.
    cutoff.id = uuid::Uuid::new_v4().to_string();
    let preimage = [LEGACY_CUTOFF_TAG_BYTES, &daemon_row_signing_input(cutoff)].concat();
    cutoff.signature = Some(legacy_key().sign(&preimage).to_bytes().to_vec());
    pg::replace_all(&store, &relinked(rows)).await;
    let trail = store
        .verify_audit_trail(None, Some(&vk))
        .await
        .expect("pg verify");
    assert!(trail.chain_intact, "pg chain intact");
    assert_eq!(
        trail.signature_failures,
        Vec::<i64>::new(),
        "the pinned-domain cutoff certifies the legacy prefix on pg"
    );
}

/// Agent id of the CLI children of the #10104 pg test.
const CLI_AGENT: &str = "pg-mint-10104";

/// #10104 — the test daemon key installed as the agent key of the CLI child,
/// so the child mints over rows this process signed.
fn install_child_key(root: &std::path::Path) {
    let keys = home_sandbox::child_env(root)
        .into_iter()
        .find(|(k, _)| *k == "AI_MEMORY_KEY_DIR")
        .map(|(_, v)| v)
        .expect("child key dir");
    let key = legacy_key();
    ai_memory::identity::keypair::save(
        &ai_memory::identity::keypair::AgentKeypair {
            agent_id: CLI_AGENT.to_string(),
            public: key.verifying_key(),
            private: Some(key),
        },
        std::path::Path::new(&keys),
    )
    .expect("save the child key");
}

async fn pg_cutoff_rows(store: &PostgresStore) -> usize {
    pg::load(store)
        .await
        .iter()
        .filter(|r| r.event_type == LEGACY_CUTOFF_EVENT_TYPE)
        .count()
}

/// #10104 / #10103 (S-7) — the pg twin of the sqlite crash-between test: the
/// row committed by a child whose sink kept the anchor is repaired by a child
/// whose sink lost it (exit 0, one cutoff row, the same anchor fields); a
/// third mint is the exact refusal; a forged anchor line beside the genuine
/// one is the exact "not trusted" refusal, never a repair.
#[tokio::test(flavor = "multi_thread")]
async fn c4_pg_crash_between_commit_and_anchor_is_repaired_10104() {
    let _ = sink();
    let Some(url) = pg_url() else { return };
    let (scratch, store) = fresh_pg(&url).await;
    pg::append(&store, &[P, I, T]).await;
    let dir = home_sandbox::per_test_dir("cli-pg-repair-10104-");
    let root = dir.path();
    install_child_key(root);
    let db = root.join("unused.db");
    let store_url = scratch.url();
    let mint = |sink: &std::path::Path| {
        cli::run(
            root,
            &db,
            CLI_AGENT,
            sink,
            &[],
            &[
                "verify-signed-events-chain",
                "--mint-legacy-cutoff",
                "--store-url",
                &store_url,
            ],
        )
    };
    let a = cli::sink_dir(root, "sink-a");
    let b = cli::sink_dir(root, "sink-b");

    let out = mint(&a);
    assert_eq!(out.code, Some(0), "pg mint: {}", out.text);
    assert!(
        out.text
            .contains("minted the legacy cutoff row at sequence=4"),
        "{}",
        out.text
    );
    let anchors_a = cli::anchor_lines(&a);
    assert_eq!(anchors_a.len(), 1, "one anchor in sink A");

    let forged = cli::forged_sink(root, "sink-forged", &a, cli::Forgery::Unsigned);
    let out = mint(&forged);
    assert_eq!(out.code, Some(1), "pg forged: {}", out.text);
    assert!(
        out.text.contains(
            "legacy cutoff mint refused: the off-table legacy cutoff anchor is not trusted"
        ) && out.text.contains(cli::Forgery::Unsigned.reason()),
        "{}",
        out.text
    );

    let out = mint(&b);
    assert_eq!(out.code, Some(0), "pg repair: {}", out.text);
    assert!(
        out.text
            .contains("repaired the off-table anchor of the legacy cutoff row at sequence=4"),
        "{}",
        out.text
    );
    assert_eq!(pg_cutoff_rows(&store).await, 1, "the repair adds no row");
    let anchors_b = cli::anchor_lines(&b);
    assert_eq!(anchors_b.len(), 1, "one repaired anchor in sink B");
    assert_eq!(
        cli::anchor_fields(&anchors_b[0]),
        cli::anchor_fields(&anchors_a[0]),
        "the repaired anchor binds the committed row"
    );

    let out = mint(&b);
    assert_eq!(out.code, Some(1), "pg third mint: {}", out.text);
    assert!(
        out.text
            .contains("legacy cutoff mint refused: a legacy cutoff row already exists"),
        "{}",
        out.text
    );
    assert_eq!(pg_cutoff_rows(&store).await, 1);
}

/// #10105 — the agent-signed chain of the parity test: genuine daemon rows
/// around one valid row per agent form, then a missing and a short signature.
const AGENT_CHAIN: &[Row] = &[
    T,
    Row::Agent("self_signed", AgentSig::Valid),
    Row::Agent("signed_by_peer", AgentSig::Valid),
    Row::Agent("peer_attested", AgentSig::Valid),
    Row::Agent("self_signed", AgentSig::Missing),
    Row::Agent("self_signed", AgentSig::Short),
    T,
];
/// #10105 — expected `signature_failures` of [`AGENT_CHAIN`], written out.
const AGENT_CHAIN_FAILURES: &[i64] = &[5, 6];
/// #10105 — expected agent-signed rows not verified of [`AGENT_CHAIN`].
const AGENT_CHAIN_NOT_VERIFIED: u64 = 3;

/// #10105 (option C) — both backends linkage-check agent-signed rows, never
/// verify them against the daemon key, count them apart from verified rows,
/// and fail exactly the missing and malformed signatures. Under the enrolled
/// pin the skipped rows stay unverified (L4).
#[tokio::test(flavor = "multi_thread")]
async fn agent_signed_rows_agree_on_both_backends_10105() {
    let vk = sink();
    let expected_check = ai_memory::signed_events::SignatureCheck::Unverified {
        checked: 7,
        unverified: 5,
    };

    let (_d, _p, conn) = sqlite::open();
    sqlite::append(&conn, AGENT_CHAIN);
    let trail = verify_audit_trail(&conn, None, Some(&vk)).expect("sqlite verify");
    assert!(trail.chain_intact, "sqlite chain intact");
    assert_eq!(trail.signature_failures, AGENT_CHAIN_FAILURES, "sqlite");
    assert_eq!(
        trail.agent_signed_rows_not_verified, AGENT_CHAIN_NOT_VERIFIED,
        "sqlite"
    );
    assert_eq!(trail.signature_check, expected_check, "sqlite");

    let Some(url) = pg_url() else { return };
    let (_scratch, store) = fresh_pg(&url).await;
    pg::append(&store, AGENT_CHAIN).await;
    let trail = store
        .verify_audit_trail(None, Some(&vk))
        .await
        .expect("pg verify");
    assert!(trail.chain_intact, "pg chain intact");
    assert_eq!(trail.signature_failures, AGENT_CHAIN_FAILURES, "pg");
    assert_eq!(
        trail.agent_signed_rows_not_verified, AGENT_CHAIN_NOT_VERIFIED,
        "pg"
    );
    assert_eq!(trail.signature_check, expected_check, "pg");
}

/// #10106 — a legacy prefix longer than two pages of the postgres resolver
/// (`PG_PREFIX_PAGE_ROWS` = 512 in `src/store/postgres/legacy_cutoff_10074.rs`).
/// Written out here, not read from the code under test.
const LONG_PREFIX_ROWS: i64 = 1100;

/// `LONG_PREFIX_ROWS` payload-only (legacy) rows, linked from the zero hash.
fn long_legacy_prefix() -> Vec<SignedEvent> {
    let ts = micros_now().to_rfc3339();
    relinked(
        (1..=LONG_PREFIX_ROWS)
            .map(|seq| make_row(P, seq, ts.clone()))
            .collect(),
    )
}

/// #10106 — the cutoff over a prefix longer than one page resolves on both
/// backends: every legacy row verifies under it (none is a failure), and
/// without the cutoff every row is a failure (control). A resolver that reads
/// only the first page, skips or repeats a row at a page edge, sees a prefix
/// hash that does not match the cutoff and resolves no cutoff.
#[tokio::test(flavor = "multi_thread")]
async fn c6_cutoff_over_a_multi_page_prefix_agrees_10106() {
    let vk = sink();
    let rows = long_legacy_prefix();
    let all: Vec<i64> = (1..=LONG_PREFIX_ROWS).collect();

    let (_d, _p, conn) = sqlite::open();
    sqlite::replace_all(&conn, &rows);
    let before = verify_audit_trail(&conn, None, Some(&vk)).expect("sqlite verify");
    assert_eq!(before.signature_failures, all, "sqlite control");
    let minted = ai_memory::signed_events::mint_legacy_cutoff(&conn).expect("mint runs");
    assert_eq!(minted, Ok(LegacyCutoffMinted::Minted(LONG_PREFIX_ROWS + 1)));
    let trail = verify_audit_trail(&conn, None, Some(&vk)).expect("sqlite verify");
    assert_eq!(trail.signature_failures, Vec::<i64>::new(), "sqlite");

    let Some(url) = pg_url() else { return };
    let (_scratch, store) = fresh_pg(&url).await;
    // Its own rows (fresh ids), as every other test builds each backend's
    // chain: the mint anchor is keyed by the chain's identity.
    pg::replace_all(&store, &long_legacy_prefix()).await;
    let before = store
        .verify_audit_trail(None, Some(&vk))
        .await
        .expect("pg verify");
    assert_eq!(before.signature_failures, all, "pg control");
    let minted = store.mint_legacy_cutoff().await.expect("pg mint runs");
    assert_eq!(minted, Ok(LegacyCutoffMinted::Minted(LONG_PREFIX_ROWS + 1)));
    let trail = store
        .verify_audit_trail(None, Some(&vk))
        .await
        .expect("pg verify");
    assert_eq!(trail.signature_failures, Vec::<i64>::new(), "pg");
}

/// #10106 — the postgres check of an EXISTING cutoff row reads its prefix in
/// pages too: over a prefix longer than one page, a mint with a fresh sink
/// (no anchor) finds the committed row certified and REPAIRS the anchor. A
/// check that saw only the first page would call the row uncertified and
/// refuse with "a legacy cutoff row already exists".
#[tokio::test]
async fn c6_pg_repair_over_a_multi_page_prefix_10106() {
    let _ = sink();
    let Some(url) = pg_url() else { return };
    let (scratch, store) = fresh_pg(&url).await;
    pg::replace_all(&store, &long_legacy_prefix()).await;
    let dir = home_sandbox::per_test_dir("cli-pg-repair-pages-10106-");
    let root = dir.path();
    install_child_key(root);
    let db = root.join("unused.db");
    let store_url = scratch.url();
    let mint = |sink: &std::path::Path| {
        cli::run(
            root,
            &db,
            CLI_AGENT,
            sink,
            &[],
            &[
                "verify-signed-events-chain",
                "--mint-legacy-cutoff",
                "--store-url",
                &store_url,
            ],
        )
    };
    let cutoff = LONG_PREFIX_ROWS + 1;

    let out = mint(&cli::sink_dir(root, "sink-a"));
    assert_eq!(out.code, Some(0), "pg mint: {}", out.text);
    assert!(
        out.text.contains(&format!(
            "minted the legacy cutoff row at sequence={cutoff}"
        )),
        "{}",
        out.text
    );

    let out = mint(&cli::sink_dir(root, "sink-b"));
    assert_eq!(out.code, Some(0), "pg repair: {}", out.text);
    assert!(
        out.text.contains(&format!(
            "repaired the off-table anchor of the legacy cutoff row at sequence={cutoff}"
        )),
        "{}",
        out.text
    );
    assert_eq!(pg_cutoff_rows(&store).await, 1, "the repair adds no row");
}

/// Count and content digest of every base table in every user schema of the
/// scratch database: each row rendered with `row::text`, the rendered rows
/// sorted, then md5 (independent of physical row order).
async fn pg_db_digest(store: &PostgresStore) -> std::collections::BTreeMap<String, (i64, String)> {
    let tables: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_schema::text, table_name::text FROM information_schema.tables \
         WHERE table_type = 'BASE TABLE' \
           AND table_schema NOT IN ('pg_catalog', 'information_schema') \
           AND table_schema NOT LIKE 'pg\\_%' \
         ORDER BY 1, 2",
    )
    .fetch_all(store.pool())
    .await
    .expect("list tables");
    let mut out = std::collections::BTreeMap::new();
    for (schema, table) in tables {
        let sql = format!(
            "SELECT COUNT(*)::bigint, \
                    md5(COALESCE(string_agg(t::text, E'\\n' ORDER BY t::text), '')) \
             FROM \"{schema}\".\"{table}\" t"
        );
        let row: (i64, String) = sqlx::query_as(&sql)
            .fetch_one(store.pool())
            .await
            .expect("digest table");
        out.insert(format!("{schema}.{table}"), row);
    }
    out
}

/// GA standard 1 (no data destruction) on a POPULATED PostgreSQL database:
/// the chain walk, the mint and the anchor repair alter no stored memory.
/// Every table other than `signed_events` keeps its exact row count and
/// content digest; `signed_events` keeps every earlier row identical and gains
/// exactly the one cutoff row.
#[tokio::test(flavor = "multi_thread")]
async fn std1_pg_mint_verify_repair_alter_no_stored_memory_10074() {
    use ai_memory::store::MemoryStore as _;
    const MEMORIES: i64 = 6;
    let _ = sink();
    let Some(url) = pg_url() else { return };
    let (scratch, store) = fresh_pg(&url).await;
    pg::append(&store, &[P, I, T]).await;
    let ctx = ai_memory::store::CallerContext::for_agent(CLI_AGENT);
    for i in 0..MEMORIES {
        let now = chrono::Utc::now().to_rfc3339();
        let memory = ai_memory::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: ai_memory::models::Tier::Long,
            namespace: "std1-10074".to_string(),
            title: format!("std1 row {i}"),
            content: format!("standard 1 populated memory {i} (#10074)"),
            priority: 5,
            confidence: 0.9,
            source: "test".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({ "agent_id": CLI_AGENT }),
            version: 1,
            ..ai_memory::models::Memory::default()
        };
        store.store(&ctx, &memory).await.expect("store memory");
    }
    let memories = || async {
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*)::bigint FROM memories")
            .fetch_one(store.pool())
            .await
            .expect("count memories")
            .0
    };
    assert_eq!(memories().await, MEMORIES, "the database is populated");

    let dir = home_sandbox::per_test_dir("cli-pg-std1-10074-");
    let root = dir.path();
    install_child_key(root);
    let db = root.join("unused.db");
    let store_url = scratch.url();
    // The CLI chain walk refuses a PostgreSQL store (#10106), so the walk is
    // the store's own verifier; the mint and the repair run as CLI children.
    let mint = |sink: &std::path::Path| {
        cli::run(
            root,
            &db,
            CLI_AGENT,
            sink,
            &[],
            &[
                "verify-signed-events-chain",
                "--mint-legacy-cutoff",
                "--store-url",
                &store_url,
            ],
        )
    };
    let walk = || async {
        let trail = store
            .verify_audit_trail(None, Some(&sink()))
            .await
            .expect("pg verify");
        assert!(trail.chain_intact, "pg chain intact");
    };
    let a = cli::sink_dir(root, "sink-a");
    let b = cli::sink_dir(root, "sink-b");

    let before = pg_db_digest(&store).await;
    let events_before = pg::load(&store).await;
    walk().await;
    assert_eq!(
        pg_db_digest(&store).await,
        before,
        "the walk alters no table"
    );

    let out = mint(&a);
    assert_eq!(out.code, Some(0), "pg mint: {}", out.text);
    let after_mint = pg_db_digest(&store).await;
    let out = mint(&b);
    assert_eq!(out.code, Some(0), "pg repair: {}", out.text);
    assert!(
        out.text.contains("repaired the off-table anchor"),
        "{}",
        out.text
    );
    walk().await;
    let after = pg_db_digest(&store).await;
    assert_eq!(after, after_mint, "the repair and the walk alter no table");

    let mut changed: Vec<&String> = before
        .keys()
        .chain(after.keys())
        .filter(|t| before.get(*t) != after.get(*t))
        .collect();
    changed.sort();
    changed.dedup();
    assert_eq!(changed.len(), 1, "only signed_events changes: {changed:?}");
    assert!(changed[0].ends_with(".signed_events"), "{changed:?}");
    let events_after = pg::load(&store).await;
    assert_eq!(
        events_after.len(),
        events_before.len() + 1,
        "exactly one row added"
    );
    assert_eq!(
        &events_after[..events_before.len()],
        &events_before[..],
        "every earlier signed event is unchanged"
    );
    assert_eq!(
        pg_cutoff_rows(&store).await,
        1,
        "the added row is the cutoff row"
    );
    assert_eq!(memories().await, MEMORIES, "no memory lost");
}
