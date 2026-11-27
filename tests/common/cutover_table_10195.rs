// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10195 — the agent cut-over marker verdict table, shared by the two test
//! binaries that run it (one with no in-process daemon key, one with it).
//!
//! Include after `home_sandbox` with
//! `#[path = "common/cutover_table_10195.rs"] mod cutover_table;`.
//!
//! The table is {no verifier, pinned key, in-process key} x {valid, edited,
//! bad signature, duplicate, removed}. The expected column is written by hand
//! ([`expected`]); it is never derived from the code under test. A fresh
//! database holds exactly one chain row: the genesis marker at sequence 1.

#![allow(dead_code)]
#![allow(clippy::missing_panics_doc, clippy::doc_markdown)]

use ai_memory::db;
use ai_memory::governance::daemon_signer::DaemonChainSigner;
use ai_memory::signed_events::agent_cutover::{MarkerOrigin, build_signed_marker};
use ai_memory::signed_events::{
    AGENT_CUTOVER_EVENT_TYPE, SignatureCheck, SignedEvent, verify_audit_trail, verify_chain,
};
use ed25519_dalek::VerifyingKey;
use rusqlite::params;

/// The sequence of the genesis marker a fresh database holds.
pub const GENESIS_SEQ: i64 = 1;
/// The sequence of the second marker the duplicate scenario adds.
pub const SECOND_SEQ: i64 = 2;
/// The chain-level sequence a missing marker is reported at.
pub const CHAIN_LEVEL: i64 = 0;
/// The payload byte the edited scenario flips (byte 0 is the origin).
pub const EDITED_PAYLOAD_BYTE: usize = 1;
/// The signature byte the bad-signature scenario flips.
pub const FLIPPED_SIGNATURE_BYTE: usize = 0;

/// What is done to the genesis marker before the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// The marker exactly as the open wrote it.
    Valid,
    /// One payload byte changed (the structure no longer matches).
    Edited,
    /// One signature byte changed (the structure still matches).
    BadSignature,
    /// A second signed marker row added above the first.
    Duplicate,
    /// The marker row deleted.
    Removed,
}

impl Scenario {
    pub const ALL: [Self; 5] = [
        Self::Valid,
        Self::Edited,
        Self::BadSignature,
        Self::Duplicate,
        Self::Removed,
    ];
}

/// Which verifier the walk has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierState {
    /// No key passed and no in-process daemon key.
    None,
    /// The daemon key passed to the walk (`audit_pubkey`).
    Pinned,
    /// No key passed; the in-process daemon key verifies.
    InProcess,
}

impl VerifierState {
    /// Whether the walk is given the key (the pin is enrolled).
    pub fn pin_enrolled(self) -> bool {
        match self {
            Self::Pinned => true,
            Self::None | Self::InProcess => false,
        }
    }
}

/// The hand-written expectation of one cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// The sequences both walks report in `signature_failures`.
    pub failures: Vec<i64>,
    /// Chain rows walked.
    pub checked: u64,
    /// Chain rows that positively verified.
    pub verified: u64,
}

/// The verdict table. Exhaustive, no wildcard arm: a new scenario or verifier
/// state does not compile until its row is written.
pub fn expected(scenario: Scenario, verifier: VerifierState) -> Expected {
    let (failures, checked, verified): (&[i64], u64, u64) = match (scenario, verifier) {
        // A correctly signed marker with no verifier is unchecked: it fails
        // nothing and verifies nothing.
        (Scenario::Valid, VerifierState::None) => (&[], 1, 0),
        (Scenario::Valid, VerifierState::Pinned | VerifierState::InProcess) => (&[], 1, 1),
        // A structural defect is invalid whether or not a key is present.
        (
            Scenario::Edited,
            VerifierState::None | VerifierState::Pinned | VerifierState::InProcess,
        ) => (&[GENESIS_SEQ], 1, 0),
        // A bad signature cannot be seen without a key; with one it is invalid.
        (Scenario::BadSignature, VerifierState::None) => (&[], 1, 0),
        (Scenario::BadSignature, VerifierState::Pinned | VerifierState::InProcess) => {
            (&[GENESIS_SEQ], 1, 0)
        }
        (
            Scenario::Duplicate,
            VerifierState::None | VerifierState::Pinned | VerifierState::InProcess,
        ) => (&[GENESIS_SEQ, SECOND_SEQ], 2, 0),
        (
            Scenario::Removed,
            VerifierState::None | VerifierState::Pinned | VerifierState::InProcess,
        ) => (&[CHAIN_LEVEL], 0, 0),
    };
    Expected {
        failures: failures.to_vec(),
        checked,
        verified,
    }
}

/// The audit-trail signature coverage the cell must report.
pub fn expected_signature_check(scenario: Scenario, verifier: VerifierState) -> SignatureCheck {
    let e = expected(scenario, verifier);
    let unverified = e.checked - e.verified;
    if !verifier.pin_enrolled() {
        return SignatureCheck::Unenforced {
            checked: e.checked,
            unverified,
        };
    }
    if unverified == 0 {
        SignatureCheck::Verified { checked: e.checked }
    } else {
        SignatureCheck::Unverified {
            checked: e.checked,
            unverified,
        }
    }
}

/// What one backend's audit-trail walk reported (compared across backends).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailCell {
    pub failures: Vec<i64>,
    pub signature_check: SignatureCheck,
}

/// What the sqlite chain walk reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCell {
    pub chain_break: Option<i64>,
    pub failures: Vec<i64>,
    pub checked: u64,
    pub verified: u64,
}

/// A second marker above `first`, signed by the shared constructor with the
/// daemon key this process resolves.
pub fn second_marker(first: &SignedEvent, timestamp: String) -> SignedEvent {
    let signer = DaemonChainSigner::provision_default().expect("daemon key resolves");
    build_signed_marker(
        &signer,
        Some(first),
        0,
        MarkerOrigin::Migrate,
        uuid::Uuid::new_v4().to_string(),
        timestamp,
    )
    .map(Into::into)
    .expect("a row above the head")
}

fn sqlite_markers(conn: &rusqlite::Connection) -> Vec<SignedEvent> {
    let mut stmt = conn
        .prepare(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
                    timestamp, prev_hash, sequence, cause_hash \
             FROM signed_events WHERE event_type = ?1 ORDER BY sequence ASC",
        )
        .expect("prepare");
    stmt.query_map(params![AGENT_CUTOVER_EVENT_TYPE], |r| {
        Ok(SignedEvent {
            id: r.get(0)?,
            agent_id: r.get(1)?,
            event_type: r.get(2)?,
            payload_hash: r.get(3)?,
            signature: r.get(4)?,
            attest_level: r.get(5)?,
            timestamp: r.get(6)?,
            prev_hash: r.get(7)?,
            sequence: r.get(8)?,
            cause_hash: r.get(9)?,
        })
    })
    .expect("query")
    .collect::<Result<_, _>>()
    .expect("rows")
}

/// Apply `scenario` to a fresh sqlite database (one genesis marker).
pub fn sqlite_apply(conn: &rusqlite::Connection, scenario: Scenario) {
    let found = sqlite_markers(conn);
    assert_eq!(found.len(), 1, "a fresh open writes one genesis marker");
    let marker = &found[0];
    assert_eq!(marker.sequence, GENESIS_SEQ, "the genesis marker is row 1");
    match scenario {
        Scenario::Valid => {}
        Scenario::Edited => {
            let mut ph = marker.payload_hash.clone();
            ph[EDITED_PAYLOAD_BYTE] ^= 1;
            conn.execute(
                "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
                params![ph, marker.sequence],
            )
            .expect("edit marker");
        }
        Scenario::BadSignature => {
            let mut sig = marker.signature.clone().expect("the marker is signed");
            sig[FLIPPED_SIGNATURE_BYTE] ^= 1;
            conn.execute(
                "UPDATE signed_events SET signature = ?1 WHERE sequence = ?2",
                params![sig, marker.sequence],
            )
            .expect("flip signature");
        }
        Scenario::Duplicate => {
            let second = second_marker(marker, chrono::Utc::now().to_rfc3339());
            conn.execute(
                "INSERT INTO signed_events \
                    (id, agent_id, event_type, payload_hash, signature, attest_level, \
                     timestamp, prev_hash, sequence, cause_hash) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
                params![
                    second.id,
                    second.agent_id,
                    second.event_type,
                    second.payload_hash,
                    second.signature,
                    second.attest_level,
                    second.timestamp,
                    second.prev_hash,
                    second.sequence
                ],
            )
            .expect("insert second marker");
        }
        Scenario::Removed => {
            conn.execute(
                "DELETE FROM signed_events WHERE event_type = ?1",
                params![AGENT_CUTOVER_EVENT_TYPE],
            )
            .expect("remove marker");
        }
    }
}

/// Open a fresh sqlite database under `dir`, apply `scenario`, walk both
/// ways with `key` passed as the audit key.
pub fn sqlite_cell(
    dir: &std::path::Path,
    scenario: Scenario,
    key: Option<&VerifyingKey>,
) -> (ChainCell, TrailCell) {
    let conn = db::open(&dir.join("cutover-10195.db")).expect("open db");
    sqlite_apply(&conn, scenario);
    let chain = verify_chain(&conn, None, key).expect("verify_chain");
    let trail = verify_audit_trail(&conn, None, key).expect("verify_audit_trail");
    (
        ChainCell {
            chain_break: chain.chain_break,
            failures: chain.signature_failures,
            checked: chain.rows_checked,
            verified: chain.rows_positively_verified,
        },
        TrailCell {
            failures: trail.signature_failures,
            signature_check: trail.signature_check,
        },
    )
}

/// Assert one sqlite cell against the table.
pub fn assert_sqlite_cell(
    scenario: Scenario,
    verifier: VerifierState,
    (chain, trail): &(ChainCell, TrailCell),
) {
    let e = expected(scenario, verifier);
    let what = format!("{scenario:?} x {verifier:?}");
    assert_eq!(
        chain,
        &ChainCell {
            chain_break: None,
            failures: e.failures.clone(),
            checked: e.checked,
            verified: e.verified,
        },
        "sqlite chain walk, {what}"
    );
    assert_trail_cell(scenario, verifier, trail, "sqlite");
}

/// Assert one audit-trail cell (either backend) against the table.
pub fn assert_trail_cell(
    scenario: Scenario,
    verifier: VerifierState,
    trail: &TrailCell,
    backend: &str,
) {
    assert_eq!(
        trail,
        &TrailCell {
            failures: expected(scenario, verifier).failures,
            signature_check: expected_signature_check(scenario, verifier),
        },
        "{backend} audit trail, {scenario:?} x {verifier:?}"
    );
}

#[cfg(feature = "sal-postgres")]
pub mod pg {
    //! The PostgreSQL twin of the cell.

    use super::{
        AGENT_CUTOVER_EVENT_TYPE, EDITED_PAYLOAD_BYTE, FLIPPED_SIGNATURE_BYTE, GENESIS_SEQ,
        Scenario, SignedEvent, TrailCell, second_marker,
    };
    use ai_memory::store::postgres::PostgresStore;
    use chrono::{DateTime, SubsecRound, Utc};
    use ed25519_dalek::VerifyingKey;

    /// PostgreSQL keeps microseconds; the signed timestamp must round-trip.
    const PG_SUBSEC_DIGITS: u16 = 6;

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

    async fn markers(pg: &PostgresStore) -> Vec<SignedEvent> {
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, agent_id, event_type, payload_hash, signature, attest_level, \
                    timestamp, prev_hash, sequence, cause_hash FROM signed_events \
             WHERE event_type = $1 ORDER BY sequence",
        )
        .bind(AGENT_CUTOVER_EVENT_TYPE)
        .fetch_all(pg.pool())
        .await
        .expect("read pg markers");
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

    /// Apply `scenario` to a fresh PostgreSQL store (one genesis marker).
    pub async fn apply(pg: &PostgresStore, scenario: Scenario) {
        let found = markers(pg).await;
        assert_eq!(found.len(), 1, "a fresh create writes one genesis marker");
        let marker = &found[0];
        assert_eq!(marker.sequence, GENESIS_SEQ, "the genesis marker is row 1");
        match scenario {
            Scenario::Valid => {}
            Scenario::Edited => {
                let mut ph = marker.payload_hash.clone();
                ph[EDITED_PAYLOAD_BYTE] ^= 1;
                sqlx::query("UPDATE signed_events SET payload_hash = $1 WHERE sequence = $2")
                    .bind(ph)
                    .bind(marker.sequence)
                    .execute(pg.pool())
                    .await
                    .expect("edit marker");
            }
            Scenario::BadSignature => {
                let mut sig = marker.signature.clone().expect("the marker is signed");
                sig[FLIPPED_SIGNATURE_BYTE] ^= 1;
                sqlx::query("UPDATE signed_events SET signature = $1 WHERE sequence = $2")
                    .bind(sig)
                    .bind(marker.sequence)
                    .execute(pg.pool())
                    .await
                    .expect("flip signature");
            }
            Scenario::Duplicate => {
                let ts = Utc::now().trunc_subsecs(PG_SUBSEC_DIGITS);
                let second = second_marker(marker, ts.to_rfc3339());
                sqlx::query(
                    "INSERT INTO signed_events \
                        (id, agent_id, event_type, payload_hash, signature, attest_level, \
                         timestamp, prev_hash, sequence, cause_hash) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                )
                .bind(&second.id)
                .bind(&second.agent_id)
                .bind(&second.event_type)
                .bind(&second.payload_hash)
                .bind(&second.signature)
                .bind(&second.attest_level)
                .bind(ts)
                .bind(&second.prev_hash)
                .bind(second.sequence)
                .bind(&second.cause_hash)
                .execute(pg.pool())
                .await
                .expect("insert second marker");
            }
            Scenario::Removed => {
                sqlx::query("DELETE FROM signed_events WHERE event_type = $1")
                    .bind(AGENT_CUTOVER_EVENT_TYPE)
                    .execute(pg.pool())
                    .await
                    .expect("remove marker");
            }
        }
    }

    /// Create a scratch database, apply `scenario`, walk with `key` passed.
    pub async fn cell(
        admin_url: &str,
        prefix: &str,
        scenario: Scenario,
        key: Option<&VerifyingKey>,
    ) -> TrailCell {
        let scratch = crate::pg_barrier::ScratchDb::create(admin_url, prefix)
            .await
            .expect("create scratch database");
        let pg = PostgresStore::connect(&scratch.url())
            .await
            .expect("connect scratch database");
        apply(&pg, scenario).await;
        let trail = pg
            .verify_audit_trail(None, key)
            .await
            .expect("verify_audit_trail");
        pg.pool().close().await;
        drop(scratch);
        TrailCell {
            failures: trail.signature_failures,
            signature_check: trail.signature_check,
        }
    }
}
