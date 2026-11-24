// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #10074 — the legacy cutoff (3-agent vote (71472661)
//! V1-SIGNED-EVENTS-FALLBACK, S-1 .. S-6, S-8).
//!
//! Invariant: an untagged legacy daemon signature verifies only for a row at
//! or below ONE validated cutoff row; the cutoff binds its whole prefix, so no
//! prefix row can be replaced, added or removed without a full verify going
//! dirty; a missing, duplicated or invalid cutoff means cutoff zero; and the
//! cutoff is minted once, by the explicit operator order only.
//!
//! The legacy prefix rows are built the way a pre-#10074 binary signed them
//! (the untagged payload-only and untagged identity forms) with the test's
//! own copy of the daemon key; every post-fix row comes from the production
//! append path and the production mint.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use ai_memory::governance::daemon_signer::{self, DaemonDomain};
use ai_memory::signed_events::{
    LEGACY_CUTOFF_EVENT_TYPE, LegacyCutoffMintRefusal, RowSignatureVerdict, SignatureFailure,
    SignedEvent, ZERO_HASH, append_signed_event, canonical_chain_bytes, classify_row_signature,
    daemon_row_signing_input, legacy_cutoff_payload_hash, mint_legacy_cutoff, payload_hash,
    resolve_sqlite_legacy_cutoff, verify_audit_trail, verify_chain,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rusqlite::params;
use sha2::{Digest, Sha256};

#[path = "common/home_sandbox.rs"]
mod home_sandbox;

/// Deterministic seed for the one daemon key this test binary installs.
const TEST_DAEMON_SEED: [u8; 32] = [0x3c; 32];
/// Event type of the fixture rows.
const FIXTURE_EVENT_TYPE: &str = "governance.test";
/// Rounds of the S-5 property test.
const PROPERTY_ROUNDS: usize = 64;

/// The test's copy of the daemon key (a fixture: it signs the legacy prefix
/// the way a pre-#10074 binary did). Built on demand, never held in a static.
fn legacy_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_DAEMON_SEED)
}

/// Start the forensic sink once, in an isolated directory, with the daemon
/// key installed (the mint needs both). The directory lives for the process.
fn sink() -> VerifyingKey {
    static SINK: OnceLock<tempfile::TempDir> = OnceLock::new();
    SINK.get_or_init(|| {
        let dir = tempfile::Builder::new()
            .prefix("forensic-10074-")
            .tempdir()
            .expect("forensic tempdir");
        ai_memory::governance::audit::init(dir.path(), Some(legacy_key())).expect("init sink");
        dir
    });
    let vk = daemon_signer::verifying_key().expect("daemon key installed");
    assert_eq!(
        vk,
        legacy_key().verifying_key(),
        "one daemon key per process"
    );
    vk
}

/// #10007 — no path this test process can write resolves under the real HOME
/// (witness key directory and head-anchor log, key directory, temporary root).
#[test]
fn test_process_resolves_no_path_under_the_real_home_10007() {
    let _ = home_sandbox::real_home();
    let _ = sink();
    home_sandbox::assert_process_isolated();
}

fn open_db() -> (tempfile::TempDir, PathBuf, rusqlite::Connection) {
    let _ = sink();
    let dir = tempfile::Builder::new()
        .prefix("legacy-cutoff-10074-")
        .tempdir()
        .expect("tempdir");
    let path = dir.path().join("cutoff-10074.db");
    let conn = ai_memory::db::open(&path).expect("open db");
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

fn row_at(conn: &rusqlite::Connection, seq: i64) -> SignedEvent {
    load_rows(conn)
        .into_iter()
        .find(|r| r.sequence == seq)
        .expect("row at sequence")
}

/// Rewrite every `prev_hash` so the cross-row hash chain is intact again.
/// `prev_hash` is under no row signature, so signatures survive the relink.
fn relink(conn: &rusqlite::Connection) {
    let mut prev = ZERO_HASH.to_vec();
    for row in load_rows(conn) {
        conn.execute(
            "UPDATE signed_events SET prev_hash = ?1 WHERE sequence = ?2",
            params![prev, row.sequence],
        )
        .expect("relink");
        let mut linked = row;
        linked.prev_hash.clone_from(&prev);
        prev = Sha256::digest(canonical_chain_bytes(&linked)).to_vec();
    }
}

fn next_sequence(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(MAX(sequence), 0) + 1 FROM signed_events",
        [],
        |r| r.get(0),
    )
    .expect("next seq")
}

/// How a pre-#10074 binary signed a row.
#[derive(Clone, Copy, Debug)]
enum Legacy {
    /// The untagged signature over `payload_hash` alone.
    PayloadOnly,
    /// The untagged signature over the #1925 identity digest.
    Identity,
}

/// A daemon-signed head row whose signature is made by `sign` over the row as
/// it will be stored; the chain is relinked afterwards.
fn insert_head_row(
    conn: &rusqlite::Connection,
    tag: &str,
    sign: impl FnOnce(&SignedEvent) -> Vec<u8>,
) -> i64 {
    let mut ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: FIXTURE_EVENT_TYPE.to_string(),
        payload_hash: payload_hash(format!("{tag}-{}", uuid::Uuid::new_v4()).as_bytes()),
        signature: None,
        attest_level: "daemon_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        prev_hash: ZERO_HASH.to_vec(),
        sequence: next_sequence(conn),
        cause_hash: None,
    };
    ev.signature = Some(sign(&ev));
    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
        params![
            ev.id,
            ev.agent_id,
            ev.event_type,
            ev.payload_hash,
            ev.signature,
            ev.attest_level,
            ev.timestamp,
            ev.prev_hash,
            ev.sequence
        ],
    )
    .expect("insert head row");
    relink(conn);
    ev.sequence
}

fn insert_legacy(conn: &rusqlite::Connection, form: Legacy) -> i64 {
    insert_head_row(conn, "legacy", |ev| {
        let key = legacy_key();
        let msg = match form {
            Legacy::PayloadOnly => ev.payload_hash.clone(),
            Legacy::Identity => daemon_row_signing_input(ev),
        };
        key.sign(&msg).to_bytes().to_vec()
    })
}

/// One genuine row through the production append path (EventRow-tagged).
fn append_genuine(conn: &rusqlite::Connection) -> i64 {
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
    next_sequence(conn) - 1
}

/// A legacy prefix (payload-only, identity, one tagged row), then the mint.
/// Returns the cutoff row's sequence.
fn legacy_prefix_and_mint(conn: &rusqlite::Connection) -> i64 {
    insert_legacy(conn, Legacy::PayloadOnly);
    insert_legacy(conn, Legacy::Identity);
    append_genuine(conn);
    let minted = mint_legacy_cutoff(conn).expect("mint runs");
    let row = minted.expect("the first mint over a verifiable prefix succeeds");
    assert_eq!(row, 4, "the cutoff row follows the three prefix rows");
    row
}

fn assert_clean(conn: &rusqlite::Connection, what: &str) {
    let vk = sink();
    let chain = verify_chain(conn, None, Some(&vk)).expect("verify_chain");
    assert_eq!(chain.chain_break, None, "{what}: chain intact");
    assert_eq!(
        chain.signature_failures,
        Vec::<i64>::new(),
        "{what}: no failure"
    );
    let trail = verify_audit_trail(conn, None, Some(&vk)).expect("verify_audit_trail");
    assert_eq!(
        trail.signature_failures,
        Vec::<i64>::new(),
        "{what}: trail failures"
    );
}

fn failures(conn: &rusqlite::Connection, since: Option<i64>) -> Vec<i64> {
    let vk = sink();
    let chain = verify_chain(conn, since, Some(&vk)).expect("verify_chain");
    assert_eq!(chain.chain_break, None, "the relinked chain is intact");
    chain.signature_failures
}

fn trail_dirty(conn: &rusqlite::Connection) -> bool {
    let vk = sink();
    !verify_audit_trail(conn, None, Some(&vk))
        .expect("verify_audit_trail")
        .is_clean()
}

fn cutoff_rows(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        params![LEGACY_CUTOFF_EVENT_TYPE],
        |r| r.get(0),
    )
    .expect("count cutoff rows")
}

/// S-1 — a minted cutoff validates its prefix; replacing one prefix row with a
/// transplanted row (the identity digest of another row as its payload hash,
/// that row's signature) and relinking leaves the hash chain intact but voids
/// the cutoff, so the full verify is dirty — with no witness enrolled.
#[test]
fn s1_transplant_below_minted_cutoff_is_dirty_10074() {
    let (_d, _p, conn) = open_db();
    let cutoff_row = legacy_prefix_and_mint(&conn);
    let vk = sink();
    let cutoff = resolve_sqlite_legacy_cutoff(&conn, Some(&vk)).expect("resolve");
    assert_eq!(cutoff.sequence(), 3, "the prefix is rows 1..=3");
    assert_eq!(cutoff.row_sequence(), Some(cutoff_row));
    assert_clean(&conn, "the minted prefix");

    let donor = row_at(&conn, 2);
    conn.execute(
        "UPDATE signed_events SET id = ?1, payload_hash = ?2, signature = ?3 WHERE sequence = 1",
        params![
            uuid::Uuid::new_v4().to_string(),
            daemon_row_signing_input(&donor),
            donor.signature
        ],
    )
    .expect("transplant");
    relink(&conn);

    let cutoff = resolve_sqlite_legacy_cutoff(&conn, Some(&vk)).expect("resolve");
    assert_eq!(cutoff.sequence(), 0, "a changed prefix voids the cutoff");
    assert_eq!(cutoff.row_sequence(), None);
    let failed = failures(&conn, None);
    for seq in [1, 2, cutoff_row] {
        assert!(failed.contains(&seq), "row {seq} fails; got {failed:?}");
    }
    assert!(trail_dirty(&conn), "the full verify is dirty");
}

/// S-1 — a prefix row removed, or one added below the cutoff, voids it too.
#[test]
fn s1_prefix_row_removed_or_added_voids_cutoff_10074() {
    let vk = sink();
    // Removed: delete row 2, renumber nothing (a gap is a chain break), so
    // instead delete and shift the later rows down, then relink.
    let (_d, _p, conn) = open_db();
    legacy_prefix_and_mint(&conn);
    conn.execute("DELETE FROM signed_events WHERE sequence = 2", [])
        .expect("delete");
    conn.execute(
        "UPDATE signed_events SET sequence = sequence - 1 WHERE sequence > 2",
        [],
    )
    .expect("shift");
    relink(&conn);
    let cutoff = resolve_sqlite_legacy_cutoff(&conn, Some(&vk)).expect("resolve");
    assert_eq!(
        cutoff.sequence(),
        0,
        "a removed prefix row voids the cutoff"
    );
    assert!(failures(&conn, None).contains(&1));
    assert!(trail_dirty(&conn));

    // Added: one more legacy row placed below the cutoff row.
    let (_d2, _p2, conn) = open_db();
    let cutoff_row = legacy_prefix_and_mint(&conn);
    conn.execute(
        "UPDATE signed_events SET sequence = sequence + 1 WHERE sequence >= ?1",
        params![cutoff_row],
    )
    .expect("make room");
    let extra = row_at(&conn, 1);
    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
        params![
            uuid::Uuid::new_v4().to_string(),
            extra.agent_id,
            extra.event_type,
            extra.payload_hash,
            extra.signature,
            extra.attest_level,
            extra.timestamp,
            ZERO_HASH.to_vec(),
            cutoff_row
        ],
    )
    .expect("insert extra prefix row");
    relink(&conn);
    let cutoff = resolve_sqlite_legacy_cutoff(&conn, Some(&vk)).expect("resolve");
    assert_eq!(cutoff.sequence(), 0, "an added prefix row voids the cutoff");
    assert!(trail_dirty(&conn));
}

/// Replace prefix row 2 (the legacy identity-form row, not the genesis row
/// the db identity derives from) with another identity-form row the same key
/// signed: a new id and payload, the same sequence, form and count.
fn substitute_identity_row_2(conn: &rusqlite::Connection) {
    let mut ev = row_at(conn, 2);
    ev.id = uuid::Uuid::new_v4().to_string();
    ev.payload_hash = payload_hash(b"another legacy identity-form row, 10074");
    let sig = legacy_key()
        .sign(&daemon_row_signing_input(&ev))
        .to_bytes()
        .to_vec();
    conn.execute(
        "UPDATE signed_events SET id = ?1, payload_hash = ?2, signature = ?3 WHERE sequence = 2",
        params![ev.id, ev.payload_hash, sig],
    )
    .expect("substitute");
}

/// S-1 — a prefix row swapped for another validly signed legacy row of the
/// SAME form keeps the payload-only count, the db identity and every row
/// signature valid, and `prev_hash` is under no signature. The swap voids the
/// cutoff and the full verify is dirty.
#[test]
fn s1_same_form_substitution_in_prefix_voids_cutoff_10074() {
    let (_d, _p, conn) = open_db();
    let cutoff_row = legacy_prefix_and_mint(&conn);
    let vk = sink();
    assert_clean(&conn, "the minted prefix");
    let before = resolve_sqlite_legacy_cutoff(&conn, Some(&vk)).expect("resolve");
    assert_eq!(before.sequence(), 3);

    substitute_identity_row_2(&conn);
    relink(&conn);
    assert_eq!(
        classify_row_signature(&row_at(&conn, 2), Some(&vk), None, &before),
        RowSignatureVerdict::Verified,
        "precondition: on its own the substitute is a valid legacy prefix row"
    );

    let cutoff = resolve_sqlite_legacy_cutoff(&conn, Some(&vk)).expect("resolve");
    assert_eq!(
        cutoff.sequence(),
        0,
        "a substituted prefix row voids the cutoff"
    );
    assert_eq!(cutoff.row_sequence(), None);
    let failed = failures(&conn, None);
    assert_eq!(
        failed,
        vec![1, 2, cutoff_row],
        "exact failures after the swap"
    );
    assert!(trail_dirty(&conn), "the full verify is dirty");
}

/// S-1 — the same swap WITHOUT a relink leaves the last prefix row, its hash,
/// the count and the db identity untouched, so only the cutoff's digest over
/// every prefix row binds row 2: the cutoff is void, not merely the chain
/// link reported broken.
#[test]
fn s1_unrelinked_substitution_in_prefix_voids_cutoff_10074() {
    let (_d, _p, conn) = open_db();
    let cutoff_row = legacy_prefix_and_mint(&conn);
    let vk = sink();
    assert_clean(&conn, "the minted prefix");
    substitute_identity_row_2(&conn);

    let cutoff = resolve_sqlite_legacy_cutoff(&conn, Some(&vk)).expect("resolve");
    assert_eq!(
        cutoff.sequence(),
        0,
        "an unrelinked substitution voids the cutoff"
    );
    assert_eq!(cutoff.row_sequence(), None);
    let chain = verify_chain(&conn, None, Some(&vk)).expect("verify_chain");
    assert_eq!(chain.chain_break, Some(3), "row 3 no longer links to row 2");
    assert!(cutoff_row > 3, "the cutoff row sits above the swapped row");
    assert!(trail_dirty(&conn), "the full verify is dirty");
}

/// S-1 — known-answer vectors for the cutoff payload hash, computed
/// independently (Python `hashlib` over the documented layout), and each bound
/// field changes the hash.
#[test]
fn s1_cutoff_payload_hash_known_answer_10074() {
    let h = |last: u8, prefix: u8| {
        hex::encode(legacy_cutoff_payload_hash(
            3,
            &[last; 32],
            &[prefix; 32],
            1,
            "db-10074",
        ))
    };
    assert_eq!(
        h(0x11, 0x22),
        "c8f2eca952c54c1989ce682b8c9502f86913204b3a9a821354532e62703cd7f3"
    );
    assert_eq!(
        h(0x33, 0x22),
        "5d84c2e32baecf9c83a5c905a45d0a2f8ef0a9a8e711905afd40536b358b734f",
        "the last prefix chain hash is bound"
    );
    assert_eq!(
        h(0x11, 0x44),
        "2e8528847daabd55164bfbfd195fa1ee7483ab001997b9a45340ab3ed0687f1d",
        "the prefix digest is bound"
    );
}

/// S-2 — a duplicated cutoff row means cutoff zero: every legacy row fails.
#[test]
fn s2_duplicated_cutoff_row_means_no_cutoff_10074() {
    let (_d, _p, conn) = open_db();
    let cutoff_row = legacy_prefix_and_mint(&conn);
    let copy = row_at(&conn, cutoff_row);
    insert_head_row(&conn, "dup", |_| copy.signature.clone().unwrap_or_default());
    let head = next_sequence(&conn) - 1;
    conn.execute(
        "UPDATE signed_events SET event_type = ?1, agent_id = ?2, payload_hash = ?3 \
         WHERE sequence = ?4",
        params![
            LEGACY_CUTOFF_EVENT_TYPE,
            copy.agent_id,
            copy.payload_hash,
            head
        ],
    )
    .expect("duplicate the cutoff row");
    relink(&conn);
    assert_eq!(cutoff_rows(&conn), 2);
    let vk = sink();
    let cutoff = resolve_sqlite_legacy_cutoff(&conn, Some(&vk)).expect("resolve");
    assert_eq!(cutoff.sequence(), 0, "two cutoff rows mean none");
    let failed = failures(&conn, None);
    for seq in [1, 2, cutoff_row, head] {
        assert!(failed.contains(&seq), "row {seq} fails; got {failed:?}");
    }
    assert!(!failed.contains(&3), "the tagged row still verifies");
}

/// S-2 — a cutoff row whose payload hash was altered is not a cutoff.
#[test]
fn s2_tampered_cutoff_row_means_no_cutoff_10074() {
    let (_d, _p, conn) = open_db();
    let cutoff_row = legacy_prefix_and_mint(&conn);
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
        params![payload_hash(b"not the prefix"), cutoff_row],
    )
    .expect("tamper");
    relink(&conn);
    let vk = sink();
    assert_eq!(
        resolve_sqlite_legacy_cutoff(&conn, Some(&vk))
            .expect("resolve")
            .sequence(),
        0
    );
    let failed = failures(&conn, None);
    for seq in [1, 2, cutoff_row] {
        assert!(failed.contains(&seq), "row {seq} fails; got {failed:?}");
    }
}

/// S-2 — with no cutoff row, a windowed walk that starts above every legacy
/// row's predecessor still refuses the legacy rows inside the window.
#[test]
fn s2_since_window_without_cutoff_refuses_legacy_10074() {
    let (_d, _p, conn) = open_db();
    append_genuine(&conn);
    let payload_only = insert_legacy(&conn, Legacy::PayloadOnly);
    let identity = insert_legacy(&conn, Legacy::Identity);
    let failed = failures(&conn, Some(1));
    assert_eq!(
        failed,
        vec![payload_only, identity],
        "both legacy rows fail"
    );
}

/// S-2 — with a valid cutoff, a windowed walk that starts above it still
/// refuses a legacy row above the cutoff (the cutoff is resolved over the
/// whole table, not the window).
#[test]
fn s2_since_window_above_cutoff_refuses_legacy_10074() {
    let (_d, _p, conn) = open_db();
    let cutoff_row = legacy_prefix_and_mint(&conn);
    let identity = insert_legacy(&conn, Legacy::Identity);
    let failed = failures(&conn, Some(cutoff_row));
    assert_eq!(failed, vec![identity]);
}

/// S-2 — a second cutoff row is refused at write: the append path refuses
/// the reserved event type.
#[test]
fn s2_append_refuses_the_reserved_event_type_10074() {
    let (_d, _p, conn) = open_db();
    legacy_prefix_and_mint(&conn);
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: LEGACY_CUTOFF_EVENT_TYPE.to_string(),
        payload_hash: payload_hash(b"second cutoff"),
        signature: Some(vec![0u8; 64]),
        attest_level: "daemon_signed".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    let err = append_signed_event(&conn, &ev).expect_err("the reserved type is refused");
    assert!(
        format!("{err:#}").contains("is reserved"),
        "the refusal names the reserved type: {err:#}"
    );
    assert_eq!(cutoff_rows(&conn), 1);
}

/// S-3 — the mint runs once: a second mint is refused while the row exists;
/// with the row deleted, a re-run of the migrations signs nothing and a
/// re-mint is refused by the off-table anchor.
#[test]
fn s3_cutoff_is_minted_once_10074() {
    let (_d, path, conn) = open_db();
    let cutoff_row = legacy_prefix_and_mint(&conn);
    assert_eq!(
        mint_legacy_cutoff(&conn).expect("mint runs"),
        Err(LegacyCutoffMintRefusal::CutoffRowExists)
    );
    conn.execute(
        "DELETE FROM signed_events WHERE sequence = ?1",
        params![cutoff_row],
    )
    .expect("delete the cutoff row");
    drop(conn);
    let conn = ai_memory::db::open(&path).expect("re-open runs the migrations");
    assert_eq!(cutoff_rows(&conn), 0, "no boot or migration path mints");
    assert_eq!(
        mint_legacy_cutoff(&conn).expect("mint runs"),
        Err(LegacyCutoffMintRefusal::AnchorExists)
    );
    assert_eq!(cutoff_rows(&conn), 0, "no second cutoff is signed");
    let failed = failures(&conn, None);
    assert!(failed.contains(&1) && failed.contains(&2), "{failed:?}");
}

/// S-3 — the mint refuses an empty chain and a prefix holding a row that
/// verifies under no form; it never vouches for an unverifiable row.
#[test]
fn s3_mint_refuses_empty_and_unverifiable_prefix_10074() {
    let (_d, _p, conn) = open_db();
    if next_sequence(&conn) == 1 {
        assert_eq!(
            mint_legacy_cutoff(&conn).expect("mint runs"),
            Err(LegacyCutoffMintRefusal::EmptyChain)
        );
    }
    append_genuine(&conn);
    let bad = insert_head_row(&conn, "bad", |_| vec![7u8; 64]);
    assert_eq!(
        mint_legacy_cutoff(&conn).expect("mint runs"),
        Err(LegacyCutoffMintRefusal::UnverifiableRow(bad))
    );
    assert_eq!(cutoff_rows(&conn), 0);
}

/// S-4 — for every ordered pair of daemon domains, a signature made under one
/// verifies under that one only; and a signature of any domain other than
/// `EventRow` over a row's identity bytes, placed in that row, fails it.
#[test]
fn s4_every_domain_pair_is_disjoint_10074() {
    let vk = sink();
    let body = b"one body, six meanings";
    for a in DaemonDomain::ALL {
        let (sig, _) = daemon_signer::sign(a, body).expect("signer installed");
        for b in DaemonDomain::ALL {
            assert_eq!(
                daemon_signer::verify(&vk, b, body, &sig),
                a == b,
                "signed under {a:?}, verified under {b:?}"
            );
        }
    }
    let (_d, _p, conn) = open_db();
    append_genuine(&conn);
    for d in DaemonDomain::ALL {
        let seq = insert_head_row(&conn, "domain", |ev| {
            daemon_signer::sign(d, &daemon_row_signing_input(ev))
                .expect("signer installed")
                .0
        });
        let failed = failures(&conn, None);
        assert_eq!(
            failed.contains(&seq),
            d != DaemonDomain::EventRow,
            "a {d:?} signature in a signed_events row; failures {failed:?}"
        );
    }
}

/// S-5 — no signature the typed signer produces, under any domain, verifies
/// under either untagged legacy form (property over many rows).
#[test]
fn s5_no_tagged_signature_verifies_as_legacy_10074() {
    let vk = sink();
    for round in 0..PROPERTY_ROUNDS {
        let ev = SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: format!("agent-{round}"),
            event_type: FIXTURE_EVENT_TYPE.to_string(),
            payload_hash: payload_hash(uuid::Uuid::new_v4().as_bytes()),
            signature: None,
            attest_level: "daemon_signed".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            prev_hash: ZERO_HASH.to_vec(),
            sequence: i64::try_from(round).expect("small") + 1,
            cause_hash: None,
        };
        let identity = daemon_row_signing_input(&ev);
        for d in DaemonDomain::ALL {
            for body in [&identity, &ev.payload_hash] {
                let (sig, _) = daemon_signer::sign(d, body).expect("signer installed");
                let sig = ed25519_dalek::Signature::from_slice(&sig).expect("64 bytes");
                assert!(
                    vk.verify_strict(&identity, &sig).is_err(),
                    "{d:?}: verifies as the untagged identity form"
                );
                assert!(
                    vk.verify_strict(&ev.payload_hash, &sig).is_err(),
                    "{d:?}: verifies as the untagged payload-only form"
                );
            }
        }
    }
}

/// S-5 / S-6 — above the minted cutoff an untagged identity row fails as a
/// daemon signature failure and a payload-only row fails with exactly
/// `LegacyPayloadOnlyAfterCutoff`; both land in `signature_failures`, dirty
/// the report, and never block a later append.
#[test]
fn s6_legacy_rows_above_cutoff_fail_exactly_10074() {
    let (_d, _p, conn) = open_db();
    let cutoff_row = legacy_prefix_and_mint(&conn);
    let vk = sink();
    let cutoff = resolve_sqlite_legacy_cutoff(&conn, Some(&vk)).expect("resolve");
    let identity = insert_legacy(&conn, Legacy::Identity);
    let payload_only = insert_legacy(&conn, Legacy::PayloadOnly);

    let verdict = |seq| classify_row_signature(&row_at(&conn, seq), Some(&vk), None, &cutoff);
    assert_eq!(
        verdict(payload_only),
        RowSignatureVerdict::Failed(SignatureFailure::LegacyPayloadOnlyAfterCutoff)
    );
    assert_eq!(
        verdict(identity),
        RowSignatureVerdict::Failed(SignatureFailure::DaemonSignature)
    );
    for seq in [1, 2] {
        assert_eq!(
            verdict(seq),
            RowSignatureVerdict::Verified,
            "prefix row {seq}"
        );
    }
    assert!(verdict(payload_only).signature_failure());

    let later = append_genuine(&conn);
    assert_eq!(later, payload_only + 1, "a later append is not blocked");
    let failed = failures(&conn, None);
    assert_eq!(failed, vec![identity, payload_only]);
    let trail = verify_audit_trail(&conn, None, Some(&vk)).expect("verify_audit_trail");
    assert_eq!(trail.signature_failures, vec![identity, payload_only]);
    assert_eq!(trail.head_sequence, later);
    assert!(!trail.is_clean());
    assert!(cutoff_row < identity);
}

/// S-8 — the CLI mints on the explicit operator flag only: the plain walk
/// signs nothing, the flag mints once (exit 0), a second order is refused
/// (exit 1), and the walk is clean afterwards (exit 0).
#[test]
fn s8_cli_mint_once_on_explicit_flag_10074() {
    let root = tempfile::Builder::new()
        .prefix("cli-mint-10074-")
        .tempdir()
        .expect("tempdir");
    let home = root.path().join("home");
    let keys = root.path().join("keys");
    std::fs::create_dir_all(home.join(".config")).expect("home");
    std::fs::create_dir_all(&keys).expect("keys");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let db = root.path().join("store.db");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("AI_MEMORY_KEY_DIR", &keys)
            .env("AI_MEMORY_DB", &db)
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_AGENT_ID", "cli-mint-10074")
            .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
            .args(args)
            .output()
            .expect("run ai-memory")
    };
    let out = run(&[
        "--json",
        "store",
        "-T",
        "row",
        "--content",
        "a ledger row (#10074)",
    ]);
    assert!(
        out.status.success(),
        "store: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stored: serde_json::Value = serde_json::from_slice(&out.stdout).expect("store json");
    let id = stored["id"].as_str().expect("id").to_string();
    let out = run(&["delete", "--hard", &id]);
    assert!(
        out.status.success(),
        "delete: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let count = || {
        let conn = rusqlite::Connection::open(&db).expect("open sqlite");
        cutoff_rows(&conn)
    };
    let out = run(&["verify-signed-events-chain"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "walk: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(count(), 0, "the plain walk mints nothing");

    let out = run(&["verify-signed-events-chain", "--mint-legacy-cutoff"]);
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "mint: {text}");
    assert!(text.contains("minted the legacy cutoff row"), "{text}");
    assert_eq!(count(), 1);

    let out = run(&["verify-signed-events-chain", "--mint-legacy-cutoff"]);
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "second mint: {text}");
    assert!(text.contains("legacy cutoff mint refused"), "{text}");
    assert_eq!(count(), 1, "no second cutoff row");

    let out = run(&["verify-signed-events-chain"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "walk after mint: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
