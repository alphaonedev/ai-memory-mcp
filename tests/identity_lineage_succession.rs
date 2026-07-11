// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G13 (#1828) — identity-lineage succession chain, end-to-end
//! over the sqlite substrate (with a live-postgres parity suite at the
//! bottom, gated on `AI_MEMORY_TEST_POSTGRES_URL`-style env like every
//! other pg test — see `postgres_parity` below).
//!
//! Covers the §26.5 required claims + the mandatory conditions:
//!
//! - (a) no-lineage byte-identical fall-through to the flat key;
//! - (b) genesis self-sign + witness row + `verify_chain` GREEN;
//! - (c) **C2** — the successor resolves THROUGH `verify_lineage`
//!   (fail-closed `None` on a structurally-broken chain whose flat
//!   `agent_pubkey` is still synced — the old wording would have
//!   passed via the sync alone);
//! - (d) forged succession rejected (wrong-predecessor AND
//!   wrong-signature variants);
//! - (e) **C1** — genesis substitution / wholesale chain-rewrite under
//!   an attacker `K0'` rejected via the append-only witness anchor;
//! - (f) **C3** — newest-record truncation/rollback rejected by
//!   reconciling against the surviving witness rows;
//! - (g) tampered record body rejected (witness anchor first; with a
//!   forged witness the un-re-signable record fails `SignatureInvalid`
//!   AND the forged INSERT breaks the `signed_events` chain);
//! - (h) head-key desync → `HeadKeyMismatch`;
//! - (i) **C5** — duplicate epoch refused by the composite PK (raw SQL)
//!   AND by the append pre-flight;
//! - (j) **C4** — a mid-append failure rolls ALL THREE writes back (no
//!   half-migrated identity);
//! - (k) postgres parity — identical verdicts on both backends.

#![allow(clippy::too_many_lines, clippy::doc_markdown, clippy::similar_names)]

mod common;

use ai_memory::db;
use ai_memory::identity::keypair::{self, AgentKeypair};
use ai_memory::identity::lineage::{LineageError, LineageRecord};
use ai_memory::identity::sign::sign_succession;
use common::EnvVarGuard;
use rusqlite::{Connection, params};

// ---------------------------------------------------------------------------
// v0.9.0 pre-GA (#1853) flake fix — `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE` is a
// PROCESS-GLOBAL env var read by `verify_audit_trail`
// (`identity::lineage::require_identity_lineage_enabled`, consulted at
// src/signed_events.rs:1710). `require_identity_lineage_fail_closes_when_missing`
// below sets it truthy to pin the Missing-verdict fail-closed behaviour, while
// `successor_verifies_via_chain_and_fails_closed_when_broken_but_synced` and
// `audit_trail_lineage_verdicts` also call `verify_audit_trail` and assert the
// DEFAULT (unset) verdicts (Forged / Unknown / NotDetected respectively).
// Cargo's default multi-threaded harness runs all `#[test]` fns in this
// binary concurrently, so the mutator's set/remove window could transiently
// flip a sibling's verdict to `Missing` — this raced as a full-suite-only
// flake (green in isolation / `--test-threads=1`); the assertions themselves
// were always correct.
//
// Fix: reuse the crate's ALREADY-ESTABLISHED `tests/common::EnvVarGuard`
// (issue #821; process-wide `ENV_LOCK`, RAII restore-on-drop, same
// discipline the #1853 HMAC fix at afebc9df and the #1874 AGENT_ID
// env-guard at e078c89b both cite/extend) instead of inventing a new
// module-local lock. The mutator wraps its `set_var` in
// `EnvVarGuard::set(...)`; the two readers that depend on the DEFAULT
// (unset) value wrap themselves in `EnvVarGuard::remove(...)` — both
// acquire the SAME process-wide `ENV_LOCK` for the whole test body, so the
// three tests can never interleave on this global, and a mid-body panic in
// any of them still restores prior env state on unwind (RAII, not manual
// set/remove).
// ---------------------------------------------------------------------------

/// Fresh migrated sqlite DB (temp file — `db::open` runs the ladder).
fn fresh_db() -> (tempfile::TempDir, Connection) {
    let dir = tempfile::Builder::new()
        .prefix("lineage-g13-")
        .tempdir()
        .expect("tempdir");
    let path = dir.path().join("test.db");
    let conn = db::open(&path).expect("open + migrate");
    (dir, conn)
}

fn kp(label: &str) -> AgentKeypair {
    keypair::generate(label).expect("generate keypair")
}

/// Register `agent_id` and enroll a K0 genesis; returns K0.
fn register_and_enroll(conn: &Connection, agent_id: &str) -> AgentKeypair {
    db::register_agent(conn, agent_id, "ai:test", &[]).expect("register agent");
    let k0 = kp(agent_id);
    // #1949 — recovery_pubkey is now REQUIRED at genesis for new chains.
    let recovery = kp(agent_id).public_base64();
    db::enroll_lineage(conn, agent_id, &k0, Some(&recovery)).expect("enroll genesis");
    k0
}

/// Build the standard K0 → K1 → K2 chain; returns the three keypairs.
fn enroll_three_key_chain(
    conn: &Connection,
    agent_id: &str,
) -> (AgentKeypair, AgentKeypair, AgentKeypair) {
    let k0 = register_and_enroll(conn, agent_id);
    let k1 = kp(agent_id);
    db::append_succession(conn, agent_id, &k0, &k1.public_base64(), None)
        .expect("K0 -> K1 succession");
    let k2 = kp(agent_id);
    db::append_succession(conn, agent_id, &k1, &k2.public_base64(), None)
        .expect("K1 -> K2 succession");
    (k0, k1, k2)
}

// ---------------------------------------------------------------------------
// (a) no-lineage byte-identical fall-through
// ---------------------------------------------------------------------------

#[test]
fn no_lineage_falls_through_to_flat_key() {
    let (_dir, conn) = fresh_db();
    // Unregistered agent: flat lookup is None → resolver is None.
    assert_eq!(
        db::current_authoritative_key(&conn, "ghost").expect("resolve unregistered"),
        None
    );

    // Registered agent with a bound flat key but NO lineage: the
    // resolver returns exactly the decoded flat key (legacy identity).
    db::register_agent(&conn, "flat-agent", "ai:test", &[]).expect("register");
    let k = kp("flat-agent");
    db::bind_agent_pubkey(&conn, "flat-agent", &k.public_base64()).expect("bind");
    let resolved = db::current_authoritative_key(&conn, "flat-agent")
        .expect("resolve")
        .expect("flat key resolves");
    assert_eq!(
        resolved.to_bytes(),
        k.public.to_bytes(),
        "no-lineage resolution must be byte-identical to agent_pubkey(A)"
    );
    // And registered-but-unbound stays None (legacy posture).
    db::register_agent(&conn, "unbound-agent", "ai:test", &[]).expect("register");
    assert_eq!(
        db::current_authoritative_key(&conn, "unbound-agent").expect("resolve unbound"),
        None
    );
}

// ---------------------------------------------------------------------------
// (b) genesis self-signs, lands its witness, chain verify stays GREEN
// ---------------------------------------------------------------------------

#[test]
fn genesis_self_signs_and_verifies() {
    let (_dir, conn) = fresh_db();
    db::register_agent(&conn, "gen-agent", "ai:test", &[]).expect("register");
    let k0 = kp("gen-agent");
    let record = db::enroll_lineage(
        &conn,
        "gen-agent",
        &k0,
        Some(&kp("gen-agent").public_base64()),
    )
    .expect("enroll");
    assert_eq!(record.epoch, 0);
    assert_eq!(record.predecessor_pubkey_b64, record.successor_pubkey_b64);
    assert!(record.recovery_pubkey_b64.is_some());

    // Genesis verifies through the walk and the resolver.
    let verified = db::verify_agent_lineage(&conn, "gen-agent")
        .expect("read")
        .expect("genesis chain verifies");
    assert_eq!(verified.epoch, 0);
    assert_eq!(verified.head_key.to_bytes(), k0.public.to_bytes());

    // The flat binding was synced in the same transaction.
    let bound = db::agent_pubkey(&conn, "gen-agent").expect("read pubkey");
    assert_eq!(bound.as_deref(), Some(k0.public_base64().as_str()));

    // Exactly one identity.lineage.genesis witness row, carrying the
    // payload hash over the exact signed bytes.
    let (count, payload): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT COUNT(*), MAX(payload_hash) FROM signed_events \
             WHERE agent_id = 'gen-agent' AND event_type = 'identity.lineage.genesis'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("witness row");
    assert_eq!(count, 1, "exactly one genesis witness");
    assert_eq!(payload, record.witness_payload_hash().expect("hash"));

    // verify-signed-events-chain stays GREEN with lineage rows present.
    let report = ai_memory::signed_events::verify_chain(&conn, None).expect("verify chain");
    assert!(report.chain_holds(), "chain must hold: {report:?}");
    assert!(
        report.signature_failures.is_empty(),
        "lineage witness rows must not be false-failed: {report:?}"
    );

    // A second enroll is refused (single genesis per identity).
    let err = db::enroll_lineage(
        &conn,
        "gen-agent",
        &k0,
        Some(&kp("gen-agent").public_base64()),
    )
    .expect_err("re-enroll refused");
    assert!(format!("{err:#}").contains("already"), "got: {err:#}");
}

// ---------------------------------------------------------------------------
// (c) C2 — resolution THROUGH verify_lineage, fail-closed on
//     broken-but-synced
// ---------------------------------------------------------------------------

#[test]
fn successor_verifies_via_chain_and_fails_closed_when_broken_but_synced() {
    // v0.9.0 pre-GA (#1853) flake fix — this test asserts the Forged verdict
    // that `verify_audit_trail` computes with `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE`
    // UNSET (default). Force-unset + hold `ENV_LOCK` for the whole body so
    // `require_identity_lineage_fail_closes_when_missing`'s transient `"1"`
    // can never race this assertion (see the module doc-comment above).
    let _lineage_env =
        EnvVarGuard::remove(ai_memory::identity::lineage::REQUIRE_IDENTITY_LINEAGE_ENV);
    let (_dir, conn) = fresh_db();
    let (_k0, _k1, k2) = enroll_three_key_chain(&conn, "c2-agent");

    // The chain walk itself resolves head == K2 ...
    let verified = db::verify_agent_lineage(&conn, "c2-agent")
        .expect("read")
        .expect("3-key chain verifies");
    assert_eq!(verified.head_key.to_bytes(), k2.public.to_bytes());
    assert_eq!(verified.epoch, 2);
    assert_eq!(verified.records_checked, 3);
    // ... and the resolver agrees.
    let resolved = db::current_authoritative_key(&conn, "c2-agent")
        .expect("resolve")
        .expect("head resolves");
    assert_eq!(resolved.to_bytes(), k2.public.to_bytes());

    // A K2-signed write attests as this identity through the UNTOUCHED
    // attest_write gate (which reads the synced flat key — C6).
    let bound = db::agent_pubkey(&conn, "c2-agent")
        .expect("pubkey")
        .expect("bound");
    let content_hash: [u8; 32] = {
        use sha2::Digest as _;
        sha2::Sha256::digest(b"hello").into()
    };
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id: "c2-agent",
        namespace: "ns",
        title: "t",
        kind: "fact",
        created_at: "2026-06-30T00:00:00+00:00",
        content_sha256: &content_hash,
    };
    let sig = ai_memory::identity::sign::sign_write(&k2, &write).expect("sign write");
    let level = ai_memory::identity::verify::attest_write(&write, Some(&bound), Some(&sig), false)
        .expect("attest");
    assert_eq!(
        level,
        ai_memory::identity::verify::AttestLevel::AgentAttested
    );

    // C2 CORE — structurally break the chain while LEAVING the flat
    // agent_pubkey synced to K2. A resolver that read the flat key
    // would happily return K2; going through verify_lineage it must
    // fail closed to None.
    conn.execute(
        "UPDATE agent_lineage SET prev_record_hash = X'DEADBEEF' \
         WHERE agent_id = 'c2-agent' AND epoch = 2",
        [],
    )
    .expect("break the chain");
    assert_eq!(
        db::agent_pubkey(&conn, "c2-agent")
            .expect("pubkey")
            .as_deref(),
        Some(k2.public_base64().as_str()),
        "precondition: the flat key is STILL synced to K2 (broken-but-synced)"
    );
    assert_eq!(
        db::current_authoritative_key(&conn, "c2-agent").expect("resolve broken"),
        None,
        "a broken-but-synced chain must resolve fail-closed None, never the flat key"
    );
    // And the audit surface reports Forged.
    let report = ai_memory::signed_events::verify_audit_trail(&conn, None).expect("audit trail");
    match &report.lineage {
        ai_memory::identity::lineage::LineageCheck::Forged { detail } => {
            assert!(detail.contains("c2-agent"), "got: {detail}");
        }
        other => panic!("expected Forged lineage verdict, got {other:?}"),
    }
    assert!(!report.is_clean(), "a forged lineage dirties the report");
}

// ---------------------------------------------------------------------------
// (d) forged succession rejected (both variants)
// ---------------------------------------------------------------------------

#[test]
fn forged_succession_rejected() {
    let (_dir, conn) = fresh_db();
    let k0 = register_and_enroll(&conn, "forge-agent");
    let head = db::lineage_head(&conn, "forge-agent")
        .expect("head")
        .expect("genesis present")
        .0;
    let kx = kp("forge-agent"); // never attested by the chain

    // Variant 1 — wrong predecessor: K_x claims to be its own
    // predecessor at epoch 1. The append pre-flight refuses it.
    let mut wrong_pred = LineageRecord::rotation(
        &head,
        &kx.public_base64(),
        None,
        "2026-06-30T00:00:00+00:00",
    )
    .expect("build");
    wrong_pred.predecessor_pubkey_b64 = kx.public_base64();
    let sig = sign_succession(&kx, &wrong_pred.to_signable()).expect("sign");
    let err = db::append_lineage_record(&conn, "forge-agent", &wrong_pred, &sig)
        .expect_err("wrong-predecessor record must be refused");
    assert!(format!("{err:#}").contains("predecessor"), "got: {err:#}");

    // Variant 2 — right predecessor, wrong SIGNATURE (signed by K_x,
    // not K0). Refused before anything is persisted.
    let forged = LineageRecord::rotation(
        &head,
        &kx.public_base64(),
        None,
        "2026-06-30T00:00:00+00:00",
    )
    .expect("build");
    let bad_sig = sign_succession(&kx, &forged.to_signable()).expect("sign with wrong key");
    let err = db::append_lineage_record(&conn, "forge-agent", &forged, &bad_sig)
        .expect_err("wrong-signature record must be refused");
    assert!(format!("{err:#}").contains("unverifiable"), "got: {err:#}");

    // Nothing landed; the resolver still returns K0, never K_x.
    let resolved = db::current_authoritative_key(&conn, "forge-agent")
        .expect("resolve")
        .expect("K0 still authoritative");
    assert_eq!(resolved.to_bytes(), k0.public.to_bytes());
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_lineage WHERE agent_id = 'forge-agent'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "only the genesis row exists");

    // Recovery records are refused this train (verify path = v1.0).
    let mut recovery = LineageRecord::rotation(
        &head,
        &kx.public_base64(),
        None,
        "2026-06-30T00:00:00+00:00",
    )
    .expect("build");
    recovery.reason = ai_memory::identity::lineage::LineageReason::Recovery;
    let sig = sign_succession(&k0, &recovery.to_signable()).expect("sign");
    let err = db::append_lineage_record(&conn, "forge-agent", &recovery, &sig)
        .expect_err("recovery mint must be refused in v0.9.0");
    assert!(format!("{err:#}").contains("v1.0"), "got: {err:#}");
}

// ---------------------------------------------------------------------------
// (e) C1 — genesis substitution / wholesale rewrite rejected via the
//     append-only witness anchor
// ---------------------------------------------------------------------------

#[test]
fn genesis_substitution_and_wholesale_rewrite_rejected() {
    let (_dir, conn) = fresh_db();
    let (_k0, _k1, k2) = enroll_three_key_chain(&conn, "c1-agent");

    // WHOLESALE REWRITE — attacker K0' deletes the stored chain and
    // writes a fresh self-consistent chain under their own key, syncing
    // the flat agent_pubkey. Without the witness anchor this chain
    // would verify (it is internally valid!) — the append-only witness
    // set is what rejects it.
    let k0_prime = kp("c1-agent");
    let forged_genesis = LineageRecord::genesis(
        "c1-agent",
        &k0_prime.public_base64(),
        None,
        "2026-06-30T00:00:00+00:00",
    );
    let forged_sig = sign_succession(&k0_prime, &forged_genesis.to_signable()).expect("sign");
    conn.execute("DELETE FROM agent_lineage WHERE agent_id = 'c1-agent'", [])
        .expect("attacker wipes the table");
    conn.execute(
        "INSERT INTO agent_lineage \
            (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey, recovery_pubkey, \
             not_before, prev_record_hash, signature, record_bytes, created_at) \
         VALUES (?1, 0, 'genesis', ?2, ?2, NULL, ?3, ?4, ?5, ?6, ?3)",
        params![
            "c1-agent",
            k0_prime.public_base64(),
            "2026-06-30T00:00:00+00:00",
            ai_memory::identity::lineage::ZERO_PREV_HASH.to_vec(),
            forged_sig,
            forged_genesis.canonical_bytes().unwrap(),
        ],
    )
    .expect("attacker inserts forged genesis");
    db::bind_agent_pubkey(&conn, "c1-agent", &k0_prime.public_base64())
        .expect("attacker syncs the flat key (defeating HeadKeyMismatch alone)");

    let verdict = db::verify_agent_lineage(&conn, "c1-agent").expect("read");
    assert!(
        matches!(
            verdict,
            Err(LineageError::WitnessMismatch { epoch: 0 } | LineageError::Truncated { .. })
        ),
        "forged chain must be rejected via the witness anchor, got {verdict:?}"
    );
    assert_eq!(
        db::current_authoritative_key(&conn, "c1-agent").expect("resolve"),
        None,
        "an attacker chain must never resolve to an authoritative key"
    );
    // The legitimate head K2's witness survives in signed_events even
    // though the attacker rewrote the mutable table — that asymmetry
    // is the entire C1 defense.
    drop(k2);
}

#[test]
fn single_genesis_substitution_rejected() {
    let (_dir, conn) = fresh_db();
    let (_k0, k1, _k2) = enroll_three_key_chain(&conn, "sub-agent");
    // Replace ONLY the genesis row with an attacker-signed one that
    // keeps the same successor (K0) so the rest of the chain still
    // links. Its witness hash does not exist in signed_events.
    let head0 = db::read_lineage(&conn, "sub-agent").expect("read")[0]
        .0
        .clone();
    let mut forged = head0.clone();
    forged.not_before = "2020-01-01T00:00:00+00:00".to_string();
    let forged_bytes = forged.canonical_bytes().unwrap();
    conn.execute(
        "UPDATE agent_lineage SET not_before = ?1, record_bytes = ?2 \
         WHERE agent_id = 'sub-agent' AND epoch = 0",
        params!["2020-01-01T00:00:00+00:00", forged_bytes],
    )
    .expect("substitute genesis");
    let verdict = db::verify_agent_lineage(&conn, "sub-agent").expect("read");
    assert!(
        matches!(verdict, Err(LineageError::WitnessMismatch { epoch: 0 })),
        "substituted genesis must fail the witness anchor, got {verdict:?}"
    );
    drop(k1);
}

// ---------------------------------------------------------------------------
// (f) C3 — truncation / rollback rejected
// ---------------------------------------------------------------------------

#[test]
fn truncation_rollback_rejected() {
    let (_dir, conn) = fresh_db();
    let (_k0, k1, _k2) = enroll_three_key_chain(&conn, "c3-agent");

    // Roll the head back to the burned K1: drop the newest record and
    // re-sync the flat key. The chain that remains is internally valid
    // AND head-key-consistent — only the surviving witness row for the
    // dropped record exposes the rollback.
    conn.execute(
        "DELETE FROM agent_lineage WHERE agent_id = 'c3-agent' AND epoch = 2",
        [],
    )
    .expect("attacker rolls back the head");
    db::bind_agent_pubkey(&conn, "c3-agent", &k1.public_base64())
        .expect("attacker re-syncs the flat key to the burned key");

    let verdict = db::verify_agent_lineage(&conn, "c3-agent").expect("read");
    assert!(
        matches!(
            verdict,
            Err(LineageError::Truncated {
                records: 2,
                witnesses: 3
            })
        ),
        "rollback must be rejected via witness reconciliation, got {verdict:?}"
    );
    assert_eq!(
        db::current_authoritative_key(&conn, "c3-agent").expect("resolve"),
        None,
        "a rolled-back chain must not resolve to the burned key"
    );
}

// ---------------------------------------------------------------------------
// (g) tampered body — rejected; with a forged witness it surfaces as
//     BrokenLink AND breaks the signed_events chain
// ---------------------------------------------------------------------------

#[test]
fn tampered_body_breaks_link() {
    let (_dir, conn) = fresh_db();
    let (_k0, _k1, _k2) = enroll_three_key_chain(&conn, "tamper-agent");

    // Tamper record 1's not_before in place. The record's witness hash
    // no longer matches the append-only anchor → rejected at C1.
    let records = db::read_lineage(&conn, "tamper-agent").expect("read");
    let mut tampered = records[1].0.clone();
    tampered.not_before = "2027-01-01T00:00:00+00:00".to_string();
    conn.execute(
        "UPDATE agent_lineage SET not_before = ?1 \
         WHERE agent_id = 'tamper-agent' AND epoch = 1",
        params![tampered.not_before],
    )
    .expect("tamper the body");
    let verdict = db::verify_agent_lineage(&conn, "tamper-agent").expect("read");
    assert!(
        matches!(verdict, Err(LineageError::WitnessMismatch { epoch: 1 })),
        "tampered body must fail its witness anchor first, got {verdict:?}"
    );

    // A DILIGENT attacker also forges a matching witness row (raw
    // INSERT). Now the tampered record clears C1 — and the walk still
    // rejects it: the stored signature was minted over the ORIGINAL
    // bytes and the attacker cannot re-sign without K0, so the record
    // fails `SignatureInvalid`. (A tamper of the NEXT record's
    // `prev_record_hash` instead surfaces as `BrokenLink` — pinned by
    // the C2 test above and the `tampered_body_is_broken_link` unit
    // test.) Meanwhile the forged INSERT breaks the signed_events
    // cross-row chain — the second detection surface.
    let forged_witness = tampered.witness_payload_hash().expect("hash");
    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES (?1, 'tamper-agent', 'identity.lineage.succession', ?2, NULL, \
                 'lineage_signed', ?3, X'00', \
                 (SELECT MAX(sequence) + 1 FROM signed_events), NULL)",
        params![
            uuid::Uuid::new_v4().to_string(),
            forged_witness,
            chrono::Utc::now().to_rfc3339(),
        ],
    )
    .expect("attacker forges a witness row");

    let verdict = db::verify_agent_lineage(&conn, "tamper-agent").expect("read");
    assert!(
        matches!(verdict, Err(LineageError::SignatureInvalid { epoch: 1 })),
        "with a forged witness the un-re-signable tamper is caught at the signature, \
         got {verdict:?}"
    );
    // ... and the forged witness row broke the tamper-evident chain.
    let report = ai_memory::signed_events::verify_chain(&conn, None).expect("verify chain");
    assert!(
        !report.chain_holds(),
        "the forged witness INSERT must break the signed_events chain"
    );
}

// ---------------------------------------------------------------------------
// (h) head-key desync
// ---------------------------------------------------------------------------

#[test]
fn head_key_mismatch_detected() {
    let (_dir, conn) = fresh_db();
    let (k0, _k1, _k2) = enroll_three_key_chain(&conn, "desync-agent");
    // Desync the flat binding back to K0 (e.g. an operator re-bind
    // outside the lineage path). The chain itself is intact.
    db::bind_agent_pubkey(&conn, "desync-agent", &k0.public_base64()).expect("desync");
    let verdict = db::verify_agent_lineage(&conn, "desync-agent").expect("read");
    assert!(
        matches!(verdict, Err(LineageError::HeadKeyMismatch)),
        "got {verdict:?}"
    );
    assert_eq!(
        db::current_authoritative_key(&conn, "desync-agent").expect("resolve"),
        None,
        "a desynced head fail-closes (tamper indicator)"
    );
}

// ---------------------------------------------------------------------------
// (i) C5 — duplicate epoch refused by the composite PK
// ---------------------------------------------------------------------------

#[test]
fn duplicate_epoch_rejected_by_unique_constraint() {
    let (_dir, conn) = fresh_db();
    let k0 = register_and_enroll(&conn, "dup-agent");

    // Raw-SQL equivocation attempt at the SAME epoch — the DATABASE
    // constraint refuses it (the C5 defense is the PK, not app code).
    let err = conn
        .execute(
            "INSERT INTO agent_lineage \
                (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey, recovery_pubkey, \
                 not_before, prev_record_hash, signature, record_bytes, created_at) \
             VALUES ('dup-agent', 0, 'genesis', 'x', 'x', NULL, \
                     '2026-06-30T00:00:00+00:00', X'00', X'00', X'00', \
                     '2026-06-30T00:00:00+00:00')",
            [],
        )
        .expect_err("duplicate (agent_id, epoch) must be refused by the PK");
    assert!(
        format!("{err}").to_lowercase().contains("unique"),
        "got: {err}"
    );

    // And the API pre-flight refuses a competing genesis outright.
    let competing = LineageRecord::genesis(
        "dup-agent",
        &kp("dup-agent").public_base64(),
        None,
        "2026-06-30T00:00:00+00:00",
    );
    let sig = sign_succession(&k0, &competing.to_signable()).expect("sign");
    assert!(
        db::append_lineage_record(&conn, "dup-agent", &competing, &sig).is_err(),
        "a second genesis must be refused"
    );
}

// ---------------------------------------------------------------------------
// (j) C4 — a mid-append failure rolls all three writes back
// ---------------------------------------------------------------------------

#[test]
fn crash_mid_append_leaves_no_half_migrated_identity() {
    let (_dir, conn) = fresh_db();
    let k0 = register_and_enroll(&conn, "atomic-agent");
    let bound_before = db::agent_pubkey(&conn, "atomic-agent").expect("pubkey");
    let witness_count_before: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE agent_id = 'atomic-agent'",
            [],
            |r| r.get(0),
        )
        .unwrap();

    // Poison the signed_events chain head read with a NULL-sequence row
    // (the COR-9 diagnostic hard-fails read_chain_head), so the WITNESS
    // append — the LAST of the three writes — fails mid-transaction.
    conn.execute(
        "INSERT INTO signed_events \
            (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
             prev_hash, sequence, cause_hash) \
         VALUES ('poison', 'poisoner', 'memory.stored', X'00', NULL, 'unsigned', \
                 '2026-06-30T00:00:00+00:00', NULL, NULL, NULL)",
        [],
    )
    .expect("insert poison row");

    let k1 = kp("atomic-agent");
    let err = db::append_succession(&conn, "atomic-agent", &k0, &k1.public_base64(), None)
        .expect_err("witness failure must abort the whole append");
    assert!(
        format!("{err:#}").contains("witness") || format!("{err:#}").contains("sequence"),
        "got: {err:#}"
    );

    // NOTHING moved: no body row at epoch 1, the flat key still K0,
    // no partial witness row.
    let epochs: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_lineage WHERE agent_id = 'atomic-agent'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(epochs, 1, "the rotation body must have rolled back");
    assert_eq!(
        db::agent_pubkey(&conn, "atomic-agent").expect("pubkey"),
        bound_before,
        "the flat agent_pubkey must NOT have advanced (attest_write would trust K1 \
         while the record was lost)"
    );
    let witness_count_after: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE agent_id = 'atomic-agent'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(witness_count_after, witness_count_before);

    // Remove the poison: the SAME succession now lands cleanly, and the
    // identity resolves to K1 (no residue from the failed attempt).
    conn.execute("DELETE FROM signed_events WHERE id = 'poison'", [])
        .expect("remove poison");
    db::append_succession(&conn, "atomic-agent", &k0, &k1.public_base64(), None)
        .expect("retry succeeds");
    let resolved = db::current_authoritative_key(&conn, "atomic-agent")
        .expect("resolve")
        .expect("head resolves");
    assert_eq!(resolved.to_bytes(), k1.public.to_bytes());
}

// ---------------------------------------------------------------------------
// LineageCheck verdict surface (verify-audit-trail aggregation)
// ---------------------------------------------------------------------------

#[test]
fn audit_trail_lineage_verdicts() {
    // v0.9.0 pre-GA (#1853) flake fix — see the module doc-comment: this
    // test asserts the Unknown/NotDetected verdicts `verify_audit_trail`
    // computes with `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE` UNSET (default).
    // Force-unset + hold `ENV_LOCK` for the whole body.
    let _lineage_env =
        EnvVarGuard::remove(ai_memory::identity::lineage::REQUIRE_IDENTITY_LINEAGE_ENV);
    let (_dir, conn) = fresh_db();
    // No lineage anywhere → Unknown, clean (byte-identical legacy).
    let report = ai_memory::signed_events::verify_audit_trail(&conn, None).expect("audit");
    assert_eq!(
        report.lineage,
        ai_memory::identity::lineage::LineageCheck::Unknown
    );
    assert!(report.is_clean());

    // Clean enrolled chain → NotDetected, clean.
    let _keys = enroll_three_key_chain(&conn, "verdict-agent");
    let report = ai_memory::signed_events::verify_audit_trail(&conn, None).expect("audit");
    assert_eq!(
        report.lineage,
        ai_memory::identity::lineage::LineageCheck::NotDetected
    );
    assert!(report.is_clean());
}

#[test]
fn require_identity_lineage_fail_closes_when_missing() {
    // v0.9.0 pre-GA (#1853) flake fix — see the module doc-comment: this is
    // the only test in this binary that MUTATES the require flag. Using
    // `EnvVarGuard::set` (rather than raw `set_var`/`remove_var`) acquires
    // the process-wide `ENV_LOCK` for the whole body (serialising against
    // the two reader tests above, which hold the same lock) AND restores
    // the prior value via `Drop` even if the `.expect`/assert below panics
    // — no manual `remove_var` needed.
    let _lineage_env = EnvVarGuard::set(
        ai_memory::identity::lineage::REQUIRE_IDENTITY_LINEAGE_ENV,
        "1".to_string(),
    );
    let (_dir, conn) = fresh_db();
    let report = ai_memory::signed_events::verify_audit_trail(&conn, None).expect("audit");
    assert_eq!(
        report.lineage,
        ai_memory::identity::lineage::LineageCheck::Missing
    );
    assert!(
        !report.is_clean(),
        "require-mode with no enrolled lineage must fail closed"
    );
}

// ---------------------------------------------------------------------------
// rotate_with_succession end-to-end (CLI `identity succeed` core)
// ---------------------------------------------------------------------------

#[test]
fn rotate_with_succession_end_to_end() {
    let (_dir, conn) = fresh_db();
    let key_dir = tempfile::Builder::new()
        .prefix("lineage-keys-")
        .tempdir()
        .expect("key dir");
    db::register_agent(&conn, "rot-agent", "ai:test", &[]).expect("register");
    let k0 = kp("rot-agent");
    keypair::save(&k0, key_dir.path()).expect("save K0");
    db::enroll_lineage(
        &conn,
        "rot-agent",
        &k0,
        Some(&kp("rot-agent").public_base64()),
    )
    .expect("enroll");

    let outcome = keypair::rotate_with_succession("rot-agent", key_dir.path(), |k_old, k_new| {
        db::append_succession(&conn, "rot-agent", k_old, &k_new.public_base64(), None).map(|_| ())
    })
    .expect("rotate with succession");
    assert!(outcome.archived_pub.exists());

    // The on-disk active key IS the chain head AND the flat binding.
    let active = keypair::load("rot-agent", key_dir.path()).expect("load");
    let resolved = db::current_authoritative_key(&conn, "rot-agent")
        .expect("resolve")
        .expect("head resolves");
    assert_eq!(resolved.to_bytes(), active.public.to_bytes());
    assert_eq!(
        db::agent_pubkey(&conn, "rot-agent")
            .expect("pubkey")
            .as_deref(),
        Some(active.public_base64().as_str())
    );

    // register-recovery-key path: self-succession carrying the key.
    let recovery = kp("rot-agent");
    let record = db::append_succession(
        &conn,
        "rot-agent",
        &active,
        &active.public_base64(),
        Some(&recovery.public_base64()),
    )
    .expect("register recovery key");
    assert_eq!(
        record.recovery_pubkey_b64.as_deref(),
        Some(recovery.public_base64().as_str())
    );
    assert_eq!(record.successor_pubkey_b64, active.public_base64());
    // Chain still verifies; head unchanged.
    let verified = db::verify_agent_lineage(&conn, "rot-agent")
        .expect("read")
        .expect("chain verifies after recovery registration");
    assert_eq!(verified.head_key.to_bytes(), active.public.to_bytes());

    // A subsequent plain rotation CARRIES the recovery commitment
    // forward (a rotation never silently drops it).
    let k_next = kp("rot-agent");
    let carried = db::append_succession(&conn, "rot-agent", &active, &k_next.public_base64(), None)
        .expect("plain rotation");
    assert_eq!(
        carried.recovery_pubkey_b64.as_deref(),
        Some(recovery.public_base64().as_str()),
        "recovery commitment must carry forward"
    );
}

// ---------------------------------------------------------------------------
// v1.0.0 #1949 (R13) — custody-class + signed revocation on the chain
// ---------------------------------------------------------------------------

/// Enroll a genesis, then append a rotation, returning (k0, k1).
fn enroll_and_rotate(conn: &Connection, agent_id: &str) -> (AgentKeypair, AgentKeypair) {
    let k0 = register_and_enroll(conn, agent_id);
    let k1 = kp(agent_id);
    db::append_succession(conn, agent_id, &k0, &k1.public_base64(), None).expect("rotate");
    (k0, k1)
}

#[test]
fn revocation_round_trips_and_verifies_suspect_window() {
    // #1949 — mint a revocation, read it back losslessly, and confirm the
    // chain still verifies with the Suspect window surfaced (R13).
    let (_dir, conn) = fresh_db();
    let (_k0, k1) = enroll_and_rotate(&conn, "rev-agent");
    let k2 = kp("rev-agent");
    let record = db::append_revocation(&conn, "rev-agent", &k1, &k2.public_base64(), 77, None)
        .expect("append revocation");
    assert_eq!(record.epoch, 2);
    assert_eq!(
        record.reason,
        ai_memory::identity::lineage::LineageReason::Revocation
    );
    assert_eq!(record.suspected_compromise_from_seq, Some(77));

    // read_lineage reconstructs the revocation fields losslessly.
    let read = db::read_lineage(&conn, "rev-agent").expect("read");
    let (head, _) = read.last().expect("head");
    assert_eq!(
        head.reason,
        ai_memory::identity::lineage::LineageReason::Revocation
    );
    assert_eq!(head.suspected_compromise_from_seq, Some(77));
    assert_eq!(
        head.custody_class,
        ai_memory::identity::lineage::CustodyClass::SoftwareFile
    );

    // The chain STILL verifies (revocation is not a break), and surfaces
    // the window + head custody.
    let verified = db::verify_agent_lineage(&conn, "rev-agent")
        .expect("read")
        .expect("revoked chain still verifies");
    assert_eq!(verified.epoch, 2);
    assert_eq!(verified.revoked_from_seq, Some(77));
    assert_eq!(
        verified.head_custody_class,
        ai_memory::identity::lineage::CustodyClass::SoftwareFile
    );
}

#[test]
fn revocation_ordering_is_witness_sequence_not_wall_clock() {
    // #1949 — the Suspect window is dated by the witness SEQUENCE the
    // caller commits, INDEPENDENT of any not_before wall-clock. A record
    // minted with a stale/backdated not_before still reports the same
    // committed from_seq (wall-clock manipulation changes nothing).
    let (_dir, conn) = fresh_db();
    let (_k0, k1) = enroll_and_rotate(&conn, "seq-agent");
    let k2 = kp("seq-agent");
    db::append_revocation(&conn, "seq-agent", &k1, &k2.public_base64(), 500, None).expect("revoke");
    let verified = db::verify_agent_lineage(&conn, "seq-agent")
        .expect("read")
        .expect("verifies");
    // The ordering authority is the committed sequence, not any clock.
    assert_eq!(verified.revoked_from_seq, Some(500));
}

#[test]
fn truncation_after_revocation_is_detected() {
    // #1949 / C3 — rolling back the revocation record from the mutable
    // table while its append-only witness survives is still detected as
    // truncation.
    let (_dir, conn) = fresh_db();
    let (_k0, k1) = enroll_and_rotate(&conn, "trunc-agent");
    let k2 = kp("trunc-agent");
    db::append_revocation(&conn, "trunc-agent", &k1, &k2.public_base64(), 9, None).expect("revoke");
    // Delete the newest (revocation) row; its witness row remains.
    conn.execute(
        "DELETE FROM agent_lineage WHERE agent_id = 'trunc-agent' AND epoch = 2",
        [],
    )
    .expect("delete head");
    let err = db::verify_agent_lineage(&conn, "trunc-agent")
        .expect("read")
        .expect_err("truncation detected");
    assert!(
        matches!(err, LineageError::Truncated { .. }),
        "got: {err:?}"
    );
}

#[test]
fn custody_refuse_guard_blocks_non_software_file_mint() {
    // #1949 — the OSS refuse-guard is CODE: append_lineage_record refuses
    // any record whose custody_class is not software-file, and persists
    // nothing.
    let (_dir, conn) = fresh_db();
    db::register_agent(&conn, "cust-agent", "ai:test", &[]).expect("register");
    let k0 = kp("cust-agent");
    let mut genesis = LineageRecord::genesis(
        "cust-agent",
        &k0.public_base64(),
        Some(kp("cust-agent").public_base64()),
        "2026-06-01T00:00:00+00:00",
    );
    genesis.custody_class = ai_memory::identity::lineage::CustodyClass::Tpm2;
    let sig = sign_succession(&k0, &genesis.to_signable()).expect("sign");
    let err = db::append_lineage_record(&conn, "cust-agent", &genesis, &sig)
        .expect_err("non-software-file mint refused");
    assert!(format!("{err:#}").contains("software-file"), "got: {err:#}");
    // Nothing persisted.
    assert!(
        db::read_lineage(&conn, "cust-agent")
            .expect("read")
            .is_empty(),
        "refused mint must persist nothing"
    );
}

#[test]
fn unknown_custody_slug_fails_closed_on_read() {
    // #1949 — a forged/unknown custody_class column value fails closed on
    // read (never guessed to software-file).
    let (_dir, conn) = fresh_db();
    let _k0 = register_and_enroll(&conn, "slug-agent");
    conn.execute(
        "UPDATE agent_lineage SET custody_class = 'quantum-vault' \
         WHERE agent_id = 'slug-agent' AND epoch = 0",
        [],
    )
    .expect("inject bogus slug");
    let err = db::read_lineage(&conn, "slug-agent").expect_err("unknown slug fails closed");
    assert!(format!("{err:#}").contains("custody_class"), "got: {err:#}");
}

#[test]
fn legacy_null_custody_verifies_as_software_file() {
    // #1949 back-compat — a legacy row (NULL custody_class, as an upgrade
    // DB carries) reads as software-file and verifies unchanged.
    let (_dir, conn) = fresh_db();
    let k0 = register_and_enroll(&conn, "legacy-agent");
    // Simulate a pre-v80 row: NULL the custody column the mint wrote.
    conn.execute(
        "UPDATE agent_lineage SET custody_class = NULL WHERE agent_id = 'legacy-agent'",
        [],
    )
    .expect("null the column");
    let read = db::read_lineage(&conn, "legacy-agent").expect("read");
    assert_eq!(
        read[0].0.custody_class,
        ai_memory::identity::lineage::CustodyClass::SoftwareFile
    );
    let verified = db::verify_agent_lineage(&conn, "legacy-agent")
        .expect("read")
        .expect("legacy chain verifies");
    assert_eq!(verified.head_key.to_bytes(), k0.public.to_bytes());
}

#[test]
fn enroll_requires_recovery_pubkey_for_new_chains() {
    // #1949 — recovery_pubkey is REQUIRED at genesis for new chains.
    let (_dir, conn) = fresh_db();
    db::register_agent(&conn, "no-rec-agent", "ai:test", &[]).expect("register");
    let k0 = kp("no-rec-agent");
    let err = db::enroll_lineage(&conn, "no-rec-agent", &k0, None)
        .expect_err("genesis without recovery refused");
    assert!(
        format!("{err:#}").contains("recovery_pubkey"),
        "got: {err:#}"
    );
}

// ---------------------------------------------------------------------------
// (k) postgres parity — identical verdicts on both backends
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod postgres_parity {
    use super::*;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    fn postgres_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
    }

    async fn connect() -> Option<PostgresStore> {
        let url = postgres_url()?;
        Some(
            PostgresStore::connect(&url)
                .await
                .expect("connect postgres"),
        )
    }

    async fn raw_pool() -> Option<sqlx::PgPool> {
        let url = postgres_url()?;
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("connect raw pool"),
        )
    }

    /// Register + enroll a fresh uuid-suffixed agent on pg; returns
    /// (agent_id, K0).
    async fn pg_register_and_enroll(store: &PostgresStore) -> (String, AgentKeypair) {
        let agent_id = format!("lineage-pg-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let ctx = CallerContext::for_agent(agent_id.clone());
        store
            .register_agent(
                &ctx,
                &ai_memory::models::AgentRegistration {
                    agent_id: agent_id.clone(),
                    agent_type: "ai:test".to_string(),
                    capabilities: vec![],
                    registered_at: chrono::Utc::now().to_rfc3339(),
                    last_seen_at: chrono::Utc::now().to_rfc3339(),
                },
            )
            .await
            .expect("register agent");
        let k0 = kp("pg-agent");
        let genesis = LineageRecord::genesis(
            &agent_id,
            &k0.public_base64(),
            None,
            &chrono::Utc::now().to_rfc3339(),
        );
        let sig = sign_succession(&k0, &genesis.to_signable()).expect("sign genesis");
        store
            .append_lineage_record(&ctx, &agent_id, &genesis, &sig)
            .await
            .expect("append genesis");
        (agent_id, k0)
    }

    /// The full parity sweep in ONE test so the shared pg database sees
    /// a deterministic sequence: clean 3-key resolution, C2
    /// broken-but-synced fail-closed, C3 rollback, C5 duplicate epoch,
    /// forged-succession refusal — each asserting the SAME verdict the
    /// sqlite twin above asserts.
    #[tokio::test]
    async fn postgres_parity_identical_verdicts() {
        let Some(store) = connect().await else { return };
        let Some(pool) = raw_pool().await else { return };

        let (agent_id, k0) = pg_register_and_enroll(&store).await;
        let ctx = CallerContext::for_agent(agent_id.clone());

        // K0 → K1 → K2.
        let head = store.read_lineage(&agent_id).await.expect("read")[0]
            .0
            .clone();
        let k1 = kp("pg-agent");
        let r1 = LineageRecord::rotation(
            &head,
            &k1.public_base64(),
            None,
            &chrono::Utc::now().to_rfc3339(),
        )
        .expect("build r1");
        let sig1 = sign_succession(&k0, &r1.to_signable()).expect("sign r1");
        store
            .append_lineage_record(&ctx, &agent_id, &r1, &sig1)
            .await
            .expect("append r1");
        let k2 = kp("pg-agent");
        let r2 = LineageRecord::rotation(
            &r1,
            &k2.public_base64(),
            None,
            &chrono::Utc::now().to_rfc3339(),
        )
        .expect("build r2");
        let sig2 = sign_succession(&k1, &r2.to_signable()).expect("sign r2");
        store
            .append_lineage_record(&ctx, &agent_id, &r2, &sig2)
            .await
            .expect("append r2");

        // Clean chain resolves to K2 — identical to the sqlite twin.
        let resolved = store
            .current_authoritative_key(&agent_id)
            .await
            .expect("resolve")
            .expect("head resolves");
        assert_eq!(resolved, k2.public_base64());
        // Flat binding synced in the same tx.
        assert_eq!(
            store
                .agent_pubkey(&agent_id)
                .await
                .expect("pubkey")
                .as_deref(),
            Some(k2.public_base64().as_str())
        );
        // Witness parity: one row per record.
        let witnesses = store
            .lineage_witness_hashes(&agent_id)
            .await
            .expect("witnesses");
        assert_eq!(witnesses.len(), 3);

        // C5 — duplicate epoch refused by the composite PK (raw SQL).
        let raw_err = sqlx::query(
            "INSERT INTO agent_lineage \
                (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey, \
                 recovery_pubkey, not_before, prev_record_hash, signature, record_bytes, \
                 created_at) \
             VALUES ($1, 2, 'rotation', 'x', 'x', NULL, 'now', $2, $2, $2, 'now')",
        )
        .bind(&agent_id)
        .bind(vec![0u8; 1])
        .execute(&pool)
        .await
        .expect_err("duplicate (agent_id, epoch) must be refused by the PK");
        assert!(
            format!("{raw_err}").to_lowercase().contains("duplicate")
                || format!("{raw_err}").to_lowercase().contains("unique"),
            "got: {raw_err}"
        );

        // Forged succession (wrong signature) refused, nothing lands.
        let kx = kp("pg-agent");
        let forged = LineageRecord::rotation(
            &r2,
            &kx.public_base64(),
            None,
            &chrono::Utc::now().to_rfc3339(),
        )
        .expect("build forged");
        let bad_sig = sign_succession(&kx, &forged.to_signable()).expect("sign wrong key");
        assert!(
            store
                .append_lineage_record(&ctx, &agent_id, &forged, &bad_sig)
                .await
                .is_err(),
            "forged succession must be refused on pg exactly as on sqlite"
        );
        assert_eq!(store.read_lineage(&agent_id).await.expect("read").len(), 3);

        // C2 — broken-but-synced fail-closes to None.
        sqlx::query(
            "UPDATE agent_lineage SET prev_record_hash = $2 \
             WHERE agent_id = $1 AND epoch = 2",
        )
        .bind(&agent_id)
        .bind(vec![0xDE_u8, 0xAD_u8])
        .execute(&pool)
        .await
        .expect("break the chain");
        assert_eq!(
            store
                .agent_pubkey(&agent_id)
                .await
                .expect("pubkey")
                .as_deref(),
            Some(k2.public_base64().as_str()),
            "precondition: flat key still synced (broken-but-synced)"
        );
        assert_eq!(
            store
                .current_authoritative_key(&agent_id)
                .await
                .expect("resolve broken"),
            None,
            "pg resolver must fail closed exactly like sqlite"
        );

        // C3 — rollback (drop the newest record; witness survives).
        sqlx::query("DELETE FROM agent_lineage WHERE agent_id = $1 AND epoch = 2")
            .bind(&agent_id)
            .execute(&pool)
            .await
            .expect("roll back the head");
        store
            .bind_agent_pubkey(&ctx, &agent_id, &k1.public_base64())
            .await
            .expect("re-sync to the burned key");
        assert_eq!(
            store
                .current_authoritative_key(&agent_id)
                .await
                .expect("resolve rolled back"),
            None,
            "pg rollback verdict must match sqlite (Truncated → None)"
        );

        // No-lineage fall-through parity: a second agent with only a
        // flat binding resolves to it byte-identically.
        let flat_id = format!("lineage-pg-flat-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let flat_ctx = CallerContext::for_agent(flat_id.clone());
        store
            .register_agent(
                &flat_ctx,
                &ai_memory::models::AgentRegistration {
                    agent_id: flat_id.clone(),
                    agent_type: "ai:test".to_string(),
                    capabilities: vec![],
                    registered_at: chrono::Utc::now().to_rfc3339(),
                    last_seen_at: chrono::Utc::now().to_rfc3339(),
                },
            )
            .await
            .expect("register flat agent");
        let kf = kp("pg-agent");
        store
            .bind_agent_pubkey(&flat_ctx, &flat_id, &kf.public_base64())
            .await
            .expect("bind flat");
        assert_eq!(
            store
                .current_authoritative_key(&flat_id)
                .await
                .expect("resolve flat"),
            Some(kf.public_base64()),
            "no-lineage fall-through must be byte-identical to agent_pubkey"
        );
    }
}
