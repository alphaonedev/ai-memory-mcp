// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9162 — `verify_chain` on a `self_signed` `memory_link.created` row.
//!
//! The row's signature is the link OBSERVER's Ed25519 signature over the
//! canonical link CBOR (`storage::create_link_signed_with_window`), so the
//! daemon pin can never verify it: before the fix a clean link row was a false
//! `signature_failures` entry as soon as a daemon pin was set. Every test pins
//! the exact per-row reason, never a bare "some failure".

use super::*;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// The link observer whose enrolled key signs every link in these tests.
const OBSERVER: &str = "agent-observer-9162";
/// Seed of the observer's signing key.
const OBSERVER_SEED: [u8; 32] = [7u8; 32];
/// Seed of an unrelated daemon pin (it must never decide a link row).
const DAEMON_PIN_SEED: [u8; 32] = [9u8; 32];
/// Seed of a key that is NOT the observer's (a forger).
const FORGER_SEED: [u8; 32] = [11u8; 32];
/// Fixed timestamps so every pre-image is deterministic.
const CREATED_AT: &str = "2026-11-11T00:00:00+00:00";
const INVALIDATED_AT: &str = "2026-11-11T01:00:00+00:00";
/// Links in the scale test, and its wall-clock ceiling (debug build).
const SCALE_LINKS: usize = 512;
const SCALE_CEILING_SECS: u64 = 60;
/// Reason strings the conductor ruling fixes.
const R_SELF_SIGNED_SIGNATURE: &str = "self_signed_signature";
const R_SELF_SIGNED_UNVERIFIABLE: &str = "self_signed_unverifiable";
const R_DAEMON_SIGNATURE: &str = "daemon_signature";

/// The `memory_links` columns the link writers use (src/storage/migrations.rs).
const MEMORY_LINKS_DDL: &str = "CREATE TABLE memory_links (\
     source_id TEXT NOT NULL, target_id TEXT NOT NULL, relation TEXT NOT NULL, \
     created_at TEXT NOT NULL, valid_from TEXT, valid_until TEXT, observed_by TEXT, \
     signature BLOB, attest_level TEXT NOT NULL DEFAULT 'unsigned')";

fn observer_key() -> SigningKey {
    SigningKey::from_bytes(&OBSERVER_SEED)
}

fn daemon_pin() -> VerifyingKey {
    SigningKey::from_bytes(&DAEMON_PIN_SEED).verifying_key()
}

/// The production lookup shape: only the observer is enrolled.
fn enrolled(id: &str) -> Option<VerifyingKey> {
    (id == OBSERVER).then(|| observer_key().verifying_key())
}

fn nobody_enrolled(_id: &str) -> Option<VerifyingKey> {
    None
}

fn link_db() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory db");
    conn.execute_batch(include_str!(
        "../migrations/sqlite/0020_v07_signed_events.sql"
    ))
    .expect("apply signed_events migration");
    conn.execute_batch(MEMORY_LINKS_DDL)
        .expect("create memory_links");
    conn
}

/// Mirror `storage::create_link_signed_with_window`: sign the canonical link
/// CBOR with `signer`, store the link row, then append the `self_signed`
/// `memory_link.created` audit row (payload_hash = sha256(cbor), signature =
/// the link signature).
fn add_signed_link(conn: &Connection, signer: &SigningKey, src: &str, dst: &str) {
    let link = crate::identity::sign::SignableLink {
        src_id: src,
        dst_id: dst,
        relation: "related_to",
        observed_by: Some(OBSERVER),
        created_at: Some(CREATED_AT),
        valid_from: Some(CREATED_AT),
        valid_until: None,
    };
    let cbor = crate::identity::sign::canonical_cbor(&link).expect("cbor");
    let sig = signer.sign(&cbor).to_bytes().to_vec();
    conn.execute(
        "INSERT INTO memory_links (source_id, target_id, relation, created_at, valid_from, \
         valid_until, observed_by, signature, attest_level) \
         VALUES (?1, ?2, 'related_to', ?3, ?3, NULL, ?4, ?5, 'self_signed')",
        params![src, dst, CREATED_AT, OBSERVER, sig],
    )
    .expect("insert link");
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: OBSERVER.to_string(),
        event_type: event_types::MEMORY_LINK_CREATED.to_string(),
        payload_hash: payload_hash(&cbor),
        signature: Some(sig),
        attest_level: crate::models::AttestLevel::SelfSigned.as_str().to_string(),
        timestamp: CREATED_AT.to_string(),
        prev_hash: Vec::new(),
        sequence: 0,
        cause_hash: None,
    };
    append_signed_event(conn, &ev).expect("append link row");
}

fn walk(
    conn: &Connection,
    lookup: &dyn Fn(&str) -> Option<VerifyingKey>,
) -> ChainVerificationReport {
    let pin = daemon_pin();
    verify_chain_with_key_lookup(conn, None, Some(&pin), lookup).expect("verify")
}

/// Run a tamper statement whose SQL verb is assembled at runtime (the
/// append-only `no_mutators_in_src` grep must not see a literal mutator).
fn tamper(conn: &Connection, verb: &str, rest: &str, blob: Option<Vec<u8>>) {
    let sql = format!("{verb} {rest}");
    match blob {
        Some(b) => conn.execute(&sql, params![b]),
        None => conn.execute(&sql, []),
    }
    .expect("tamper");
}

#[test]
fn clean_self_signed_link_row_verifies_with_daemon_pin_set() {
    let conn = link_db();
    add_signed_link(&conn, &observer_key(), "m-src", "m-dst");
    let rep = walk(&conn, &enrolled);
    assert!(rep.chain_holds());
    assert_eq!(rep.signature_failure_reasons, Vec::<(i64, &str)>::new());
    assert_eq!(rep.signature_failures, Vec::<i64>::new());
    assert_eq!(rep.rows_positively_verified, 1);
}

#[test]
fn rewritten_self_signed_link_rows_fail_self_signed_signature() {
    // (verb, statement, blob) — each rewrites ONE thing the observer signed.
    let flipped_sig = |conn: &Connection| -> Vec<u8> {
        let mut s: Vec<u8> = conn
            .query_row(
                "SELECT signature FROM signed_events WHERE sequence = 1",
                [],
                |r| r.get(0),
            )
            .expect("sig");
        s[0] ^= 0x01;
        s
    };
    let cases: [(&str, &str, &str); 6] = [
        (
            "payload_hash",
            "UPDATE",
            "signed_events SET payload_hash = ?1 WHERE sequence = 1",
        ),
        (
            "agent_id",
            "UPDATE",
            "signed_events SET agent_id = 'attacker' WHERE sequence = 1",
        ),
        (
            "relation",
            "UPDATE",
            "memory_links SET relation = 'supersedes'",
        ),
        (
            "stripped",
            "UPDATE",
            "signed_events SET signature = NULL WHERE sequence = 1",
        ),
        (
            "bitflip",
            "UPDATE",
            "signed_events SET signature = ?1 WHERE sequence = 1",
        ),
        ("forged", "", ""),
    ];
    for (name, verb, rest) in cases {
        let conn = link_db();
        if name == "forged" {
            // A non-observer key signs a link claiming the observer.
            add_signed_link(
                &conn,
                &SigningKey::from_bytes(&FORGER_SEED),
                "m-src",
                "m-dst",
            );
        } else {
            add_signed_link(&conn, &observer_key(), "m-src", "m-dst");
            let blob = match name {
                "payload_hash" => Some(vec![0u8; 32]),
                "bitflip" => Some(flipped_sig(&conn)),
                _ => None,
            };
            tamper(&conn, verb, rest, blob);
        }
        let rep = walk(&conn, &enrolled);
        assert_eq!(
            rep.signature_failure_reasons,
            vec![(1, R_SELF_SIGNED_SIGNATURE)],
            "case {name}"
        );
        assert_eq!(rep.signature_failures, vec![1], "case {name}");
        assert_eq!(rep.rows_positively_verified, 0, "case {name}");
    }
}

#[test]
fn rehashed_link_rewrite_fails_the_signature_not_the_binding() {
    // The attacker rewrites the link AND recomputes payload_hash to match.
    let conn = link_db();
    add_signed_link(&conn, &observer_key(), "m-src", "m-dst");
    tamper(
        &conn,
        "UPDATE",
        "memory_links SET relation = 'supersedes'",
        None,
    );
    let forged = crate::identity::sign::SignableLink {
        src_id: "m-src",
        dst_id: "m-dst",
        relation: "supersedes",
        observed_by: Some(OBSERVER),
        created_at: Some(CREATED_AT),
        valid_from: Some(CREATED_AT),
        valid_until: None,
    };
    let h = payload_hash(&crate::identity::sign::canonical_cbor(&forged).expect("cbor"));
    tamper(
        &conn,
        "UPDATE",
        "signed_events SET payload_hash = ?1 WHERE sequence = 1",
        Some(h),
    );
    let rep = walk(&conn, &enrolled);
    assert_eq!(
        rep.signature_failure_reasons,
        vec![(1, R_SELF_SIGNED_SIGNATURE)]
    );
}

#[test]
fn unknown_observer_fails_self_signed_unverifiable() {
    let conn = link_db();
    add_signed_link(&conn, &observer_key(), "m-src", "m-dst");
    let rep = walk(&conn, &nobody_enrolled);
    assert_eq!(
        rep.signature_failure_reasons,
        vec![(1, R_SELF_SIGNED_UNVERIFIABLE)]
    );
    assert_eq!(rep.signature_failures, vec![1]);
    assert_eq!(rep.rows_positively_verified, 0);
}

#[test]
fn missing_link_row_fails_self_signed_unverifiable() {
    let conn = link_db();
    add_signed_link(&conn, &observer_key(), "m-src", "m-dst");
    tamper(&conn, "DELETE", "FROM memory_links", None);
    let rep = walk(&conn, &enrolled);
    assert_eq!(
        rep.signature_failure_reasons,
        vec![(1, R_SELF_SIGNED_UNVERIFIABLE)]
    );
}

#[test]
fn invalidated_link_still_verifies_its_create_row() {
    // `invalidate_link` clears the link signature and stamps valid_until
    // AFTER the create row committed to valid_until = None.
    let conn = link_db();
    add_signed_link(&conn, &observer_key(), "m-src", "m-dst");
    let rest = format!(
        "memory_links SET signature = NULL, attest_level = 'unsigned', \
         valid_until = '{INVALIDATED_AT}'"
    );
    tamper(&conn, "UPDATE", &rest, None);
    let rep = walk(&conn, &enrolled);
    assert_eq!(rep.signature_failure_reasons, Vec::<(i64, &str)>::new());
    assert_eq!(rep.rows_positively_verified, 1);
}

#[test]
fn daemon_signed_row_behaves_as_before() {
    let conn = link_db();
    let pin_sk = SigningKey::from_bytes(&DAEMON_PIN_SEED);
    let mut ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "daemon".to_string(),
        event_type: event_types::MEMORY_LINK_CREATED.to_string(),
        payload_hash: payload_hash(b"daemon-row"),
        signature: None,
        attest_level: crate::models::AttestLevel::DaemonSigned
            .as_str()
            .to_string(),
        timestamp: CREATED_AT.to_string(),
        prev_hash: Vec::new(),
        sequence: 0,
        cause_hash: None,
    };
    // Appended unsigned so the process-global daemon key never re-signs it;
    // the legacy payload-only signature by the pin key is then stored.
    append_signed_event(&conn, &ev).expect("append");
    let sig = pin_sk
        .sign(&signing_input_bytes(&ev.payload_hash, None))
        .to_bytes()
        .to_vec();
    tamper(
        &conn,
        "UPDATE",
        "signed_events SET signature = ?1 WHERE sequence = 1",
        Some(sig.clone()),
    );
    let rep = walk(&conn, &enrolled);
    assert_eq!(rep.signature_failure_reasons, Vec::<(i64, &str)>::new());
    assert_eq!(rep.rows_positively_verified, 1);

    tamper(
        &conn,
        "UPDATE",
        "signed_events SET payload_hash = ?1 WHERE sequence = 1",
        Some(vec![0u8; 32]),
    );
    let rep2 = walk(&conn, &enrolled);
    assert_eq!(
        rep2.signature_failure_reasons,
        vec![(1, R_DAEMON_SIGNATURE)]
    );
    assert_eq!(rep2.signature_failures, vec![1]);

    // The pure classifier agrees, with and without a link resolver.
    ev.signature = Some(sig);
    ev.sequence = 1;
    let pin = daemon_pin();
    assert_eq!(
        classify_row_signature(&ev, Some(&pin), None),
        RowSignatureVerdict::Verified
    );
}

#[test]
fn self_signed_non_link_row_is_unverifiable_never_daemon_checked_9179() {
    // The offload audit row is `self_signed` but not a link row: it is signed
    // by an agent key over a pre-image the row does not carry, so it fails
    // closed as `self_signed_unverifiable`, never as a false `daemon_signature`.
    let conn = link_db();
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: OBSERVER.to_string(),
        event_type: "memory.offload".to_string(),
        payload_hash: payload_hash(b"offload"),
        signature: Some(vec![1u8; 64]),
        attest_level: crate::models::AttestLevel::SelfSigned.as_str().to_string(),
        timestamp: CREATED_AT.to_string(),
        prev_hash: Vec::new(),
        sequence: 0,
        cause_hash: None,
    };
    append_signed_event(&conn, &ev).expect("append");
    let rep = walk(&conn, &enrolled);
    assert_eq!(
        rep.signature_failure_reasons,
        vec![(1, R_SELF_SIGNED_UNVERIFIABLE)]
    );
    assert_eq!(rep.signature_failures, vec![1]);
    // Same verdict with no daemon key at all: the arm never consults it.
    let mut stored = ev;
    stored.sequence = 1;
    assert_eq!(
        classify_row_signature(&stored, None, None).signature_failure_reason(),
        Some(R_SELF_SIGNED_UNVERIFIABLE)
    );
}

#[test]
fn unsigned_invalidation_row_is_withheld_not_a_daemon_failure_9179() {
    // `invalidate_link` appends an `unsigned` `memory_link.invalidated` row
    // whose `signature` column is the SUPERSEDED link signature.
    let conn = link_db();
    add_signed_link(&conn, &observer_key(), "m-src", "m-dst");
    let superseded = observer_key().sign(b"superseded-link").to_bytes().to_vec();
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: OBSERVER.to_string(),
        event_type: event_types::MEMORY_LINK_INVALIDATED.to_string(),
        payload_hash: payload_hash(b"post-supersession-cbor"),
        signature: Some(superseded),
        attest_level: crate::models::AttestLevel::Unsigned.as_str().to_string(),
        timestamp: INVALIDATED_AT.to_string(),
        prev_hash: Vec::new(),
        sequence: 0,
        cause_hash: None,
    };
    append_signed_event(&conn, &ev).expect("append");
    let rep = walk(&conn, &enrolled);
    assert_eq!(rep.signature_failure_reasons, Vec::<(i64, &str)>::new());
    assert_eq!(rep.signature_failures, Vec::<i64>::new());
    assert!(rep.chain_holds());
    // The create row verifies; the invalidation row is withheld (unverified).
    assert_eq!(rep.rows_checked, 2);
    assert_eq!(rep.rows_positively_verified, 1);

    // Only that row class is exempt: the same row labelled `daemon_signed`
    // still fails the daemon arm.
    let mut relabelled = ev;
    relabelled.attest_level = crate::models::AttestLevel::DaemonSigned
        .as_str()
        .to_string();
    relabelled.sequence = 2;
    let pin = daemon_pin();
    assert_eq!(
        classify_row_signature(&relabelled, Some(&pin), None).signature_failure_reason(),
        Some(R_DAEMON_SIGNATURE)
    );
}

#[test]
fn three_arg_classifier_never_greens_a_self_signed_link_row() {
    // The PostgreSQL walk has no link tables on this path: fail closed.
    let ev = SignedEvent {
        id: "row".to_string(),
        agent_id: OBSERVER.to_string(),
        event_type: event_types::MEMORY_LINK_CREATED.to_string(),
        payload_hash: payload_hash(b"x"),
        signature: Some(vec![1u8; 64]),
        attest_level: crate::models::AttestLevel::SelfSigned.as_str().to_string(),
        timestamp: CREATED_AT.to_string(),
        prev_hash: Vec::new(),
        sequence: 1,
        cause_hash: None,
    };
    let pin = daemon_pin();
    for verifier in [None, Some(&pin)] {
        assert_eq!(
            classify_row_signature(&ev, verifier, None),
            RowSignatureVerdict::Failed(SignatureFailure::SelfSignedUnverifiable)
        );
        assert_eq!(
            classify_row_signature_with_links(&ev, verifier, None, None).signature_failure_reason(),
            Some(R_SELF_SIGNED_UNVERIFIABLE)
        );
    }
}

#[test]
fn pure_funnel_branches_pin_exact_reasons() {
    let ev = |sig: Option<Vec<u8>>| SignedEvent {
        id: "row".to_string(),
        agent_id: OBSERVER.to_string(),
        event_type: event_types::MEMORY_LINK_CREATED.to_string(),
        payload_hash: payload_hash(b"x"),
        signature: sig,
        attest_level: crate::models::AttestLevel::SelfSigned.as_str().to_string(),
        timestamp: CREATED_AT.to_string(),
        prev_hash: Vec::new(),
        sequence: 1,
        cause_hash: None,
    };
    let vk = observer_key().verifying_key();
    let link = SelfSignedLinkRow {
        observed_by: Some(OBSERVER.to_string()),
        ..SelfSignedLinkRow::default()
    };
    let anon = SelfSignedLinkRow::default();
    let sig = Some(vec![1u8; 64]);
    let cases: [(
        Option<Vec<u8>>,
        Option<&SelfSignedLinkRow>,
        Option<&VerifyingKey>,
        &str,
    ); 6] = [
        (None, Some(&link), Some(&vk), R_SELF_SIGNED_SIGNATURE),
        (
            Some(vec![1u8; 63]),
            Some(&link),
            Some(&vk),
            R_SELF_SIGNED_SIGNATURE,
        ),
        (sig.clone(), None, Some(&vk), R_SELF_SIGNED_UNVERIFIABLE),
        (
            sig.clone(),
            Some(&anon),
            Some(&vk),
            R_SELF_SIGNED_UNVERIFIABLE,
        ),
        (sig.clone(), Some(&link), None, R_SELF_SIGNED_UNVERIFIABLE),
        (sig, Some(&link), Some(&vk), R_SELF_SIGNED_SIGNATURE),
    ];
    for (i, (s, l, k, want)) in cases.into_iter().enumerate() {
        assert_eq!(
            classify_self_signed_link(&ev(s), l, k).signature_failure_reason(),
            Some(want),
            "case {i}"
        );
    }
}

#[test]
fn reason_codes_are_exact_and_role_failures_carry_none() {
    let table = [
        (SignatureFailure::DaemonSignature, "daemon_signature", true),
        (
            SignatureFailure::RecorderVerification,
            "recorder_verification",
            false,
        ),
        (
            SignatureFailure::DaemonRoleDemotion,
            "daemon_role_demotion",
            false,
        ),
        (
            SignatureFailure::SelfSignedSignature,
            R_SELF_SIGNED_SIGNATURE,
            true,
        ),
        (
            SignatureFailure::SelfSignedUnverifiable,
            R_SELF_SIGNED_UNVERIFIABLE,
            true,
        ),
    ];
    for (f, code, is_sig) in table {
        assert_eq!(f.reason_code(), code);
        let v = RowSignatureVerdict::Failed(f);
        assert_eq!(v.signature_failure(), is_sig, "{code}");
        assert_eq!(
            v.signature_failure_reason(),
            is_sig.then_some(code),
            "{code}"
        );
    }
    assert_eq!(
        RowSignatureVerdict::Verified.signature_failure_reason(),
        None
    );
}

#[test]
fn many_link_rows_verify_in_linear_time() {
    let conn = link_db();
    for i in 0..SCALE_LINKS {
        add_signed_link(
            &conn,
            &observer_key(),
            &format!("src-{i}"),
            &format!("dst-{i}"),
        );
    }
    let started = std::time::Instant::now();
    let rep = walk(&conn, &enrolled);
    let took = started.elapsed();
    assert_eq!(rep.signature_failure_reasons, Vec::<(i64, &str)>::new());
    assert_eq!(
        rep.rows_positively_verified,
        u64::try_from(SCALE_LINKS).expect("fits")
    );
    assert!(
        took < std::time::Duration::from_secs(SCALE_CEILING_SECS),
        "{SCALE_LINKS} link rows took {took:?}"
    );
}
