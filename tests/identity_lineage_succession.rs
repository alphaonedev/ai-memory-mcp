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

/// Raw corruption helper for adversarial lineage-verifier tests. Public bind
/// APIs now refuse these desynchronisations by construction (#3464), so tests
/// that exercise the deeper tamper detector must model a database attacker.
fn force_flat_key(conn: &Connection, agent_id: &str, pubkey_b64: &str) {
    let title = ai_memory::models::agent_registration_title(agent_id);
    conn.execute_batch(
        "DROP TRIGGER IF EXISTS agent_pubkey_history_authoritative_insert_v97;
         DROP TRIGGER IF EXISTS agent_pubkey_history_authoritative_update_v97;",
    )
    .expect("model a database attacker bypassing the v97 authority triggers");
    conn.execute(
        "UPDATE memories SET
            metadata = json_set(metadata, '$.agent_pubkey', ?3),
            content = json_set(content, '$.agent_pubkey', ?3)
         WHERE namespace = ?1 AND title = ?2",
        params![ai_memory::models::AGENTS_NAMESPACE, title, pubkey_b64],
    )
    .expect("force flat-key corruption");
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
    db::bind_agent_pubkey_with_keypair(&conn, "flat-agent", &k).expect("bind");
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
    let report = ai_memory::signed_events::verify_chain(&conn, None, None).expect("verify chain");
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

#[test]
fn legitimate_rotation_emits_succession_audit_witness_and_history_anchor() {
    let (_dir, conn) = fresh_db();
    let k0 = register_and_enroll(&conn, "rotation-audit-agent");
    let k1 = kp("rotation-audit-agent");
    let record = db::append_succession(
        &conn,
        "rotation-audit-agent",
        &k0,
        &k1.public_base64(),
        None,
    )
    .expect("legitimate predecessor-signed rotation");

    let (count, payload): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT COUNT(*), MAX(payload_hash) FROM signed_events
             WHERE agent_id = 'rotation-audit-agent'
               AND event_type = 'identity.lineage.succession'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("rotation audit witness");
    assert_eq!(count, 1, "successful rotation emits exactly one witness");
    assert_eq!(
        payload,
        record.witness_payload_hash().expect("payload hash")
    );

    let history =
        db::agent_pubkey_versions(&conn, "rotation-audit-agent").expect("read v97 history");
    assert_eq!(history.len(), 2);
    assert!(history[0].superseded_at.is_some());
    assert!(history[1].superseded_at.is_none());
    assert!(history.iter().all(|version| {
        version.bind_authority
            == ai_memory::identity::pubkey_bind::BindAuthority::LineageSuccession.as_str()
    }));
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
    let report =
        ai_memory::signed_events::verify_audit_trail(&conn, None, None).expect("audit trail");
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

    // Recovery mint is refused without an enrolled guardian quorum. #1831
    // shipped M-of-N threshold recovery (G17); a mint now needs an enrolled
    // guardian set, and none is enrolled in this test — so the refusal reason
    // changed from the pre-#1831 "verify path = v1.0" to the guardian check.
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
        .expect_err("recovery mint must be refused without enrolled guardians (#1831)");
    assert!(
        format!("{err:#}").contains("no recovery guardians enrolled"),
        "got: {err:#}"
    );
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
    force_flat_key(&conn, "c1-agent", &k0_prime.public_base64());

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
    force_flat_key(&conn, "c3-agent", &k1.public_base64());

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
    let report = ai_memory::signed_events::verify_chain(&conn, None, None).expect("verify chain");
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
    force_flat_key(&conn, "desync-agent", &k0.public_base64());
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
    let report = ai_memory::signed_events::verify_audit_trail(&conn, None, None).expect("audit");
    assert_eq!(
        report.lineage,
        ai_memory::identity::lineage::LineageCheck::Unknown
    );
    assert!(report.is_clean());

    // Clean enrolled chain → NotDetected, clean.
    let _keys = enroll_three_key_chain(&conn, "verdict-agent");
    let report = ai_memory::signed_events::verify_audit_trail(&conn, None, None).expect("audit");
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
    let report = ai_memory::signed_events::verify_audit_trail(&conn, None, None).expect("audit");
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

    async fn pg_register(store: &PostgresStore, agent_id: &str) {
        let ctx = CallerContext::for_agent(agent_id.to_string());
        store
            .register_agent(
                &ctx,
                &ai_memory::models::AgentRegistration {
                    agent_id: agent_id.to_string(),
                    agent_type: "ai:test".to_string(),
                    capabilities: vec![],
                    registered_at: chrono::Utc::now().to_rfc3339(),
                    last_seen_at: chrono::Utc::now().to_rfc3339(),
                },
            )
            .await
            .expect("register agent");
    }

    async fn seed_pg_genuinely_attested_registration(
        store: &PostgresStore,
        pool: &sqlx::PgPool,
        agent_id: &str,
        signer: &AgentKeypair,
    ) {
        use ai_memory::models::field_names;
        use base64::Engine as _;

        let title = ai_memory::models::agent_registration_title(agent_id);
        let (id,): (String,) =
            sqlx::query_as("SELECT id FROM memories WHERE namespace = $1 AND title = $2")
                .bind(ai_memory::models::AGENTS_NAMESPACE)
                .bind(&title)
                .fetch_one(pool)
                .await
                .expect("registration id");
        let ctx = CallerContext::for_agent(agent_id.to_string());
        let mut mem = store.get(&ctx, &id).await.expect("read registration");
        let stamp = ai_memory::identity::attest::now_attestable_rfc3339();
        mem.created_at.clone_from(&stamp);
        mem.updated_at.clone_from(&stamp);
        let mut mirrored = mem.metadata.clone();
        let obj = mirrored
            .as_object_mut()
            .expect("registration metadata object");
        obj.insert(
            field_names::ATTEST_LEVEL.to_string(),
            serde_json::Value::String("agent_attested".to_string()),
        );
        obj.insert(
            field_names::WRITE_SIGNATURE.to_string(),
            serde_json::Value::String("signed-mirror-before-identity-mutation".to_string()),
        );
        mem.content = serde_json::to_string(&mirrored).expect("registration content");
        let signature = ai_memory::identity::attest::sign_memory_write(signer, &mem, agent_id)
            .expect("sign exact registration envelope");
        mem.metadata = mirrored;
        mem.metadata.as_object_mut().expect("metadata").insert(
            field_names::WRITE_SIGNATURE.to_string(),
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&signature)),
        );
        sqlx::query(
            "UPDATE memories SET metadata = $2, content = $3, created_at = $4::timestamptz, \
             updated_at = $4::timestamptz WHERE id = $1",
        )
        .bind(&id)
        .bind(&mem.metadata)
        .bind(&mem.content)
        .bind(&stamp)
        .execute(pool)
        .await
        .expect("seed genuinely attested registration");
        let seeded = store
            .get(&ctx, &id)
            .await
            .expect("read seeded registration");
        assert_eq!(
            ai_memory::identity::attest::resolve_write_attest_level(
                &seeded,
                agent_id,
                Some(&signer.public_base64()),
                Some(&signature),
                false,
            )
            .expect("seeded signature verifies"),
            ai_memory::identity::verify::AttestLevel::AgentAttested,
            "test precondition: mutation starts from a genuinely signed registration"
        );
    }

    async fn assert_pg_registration_attestation_invalidated(pool: &sqlx::PgPool, agent_id: &str) {
        use ai_memory::models::field_names;

        let (metadata, content): (serde_json::Value, String) = sqlx::query_as(
            "SELECT metadata, content FROM memories WHERE namespace = $1 AND title = $2",
        )
        .bind(ai_memory::models::AGENTS_NAMESPACE)
        .bind(ai_memory::models::agent_registration_title(agent_id))
        .fetch_one(pool)
        .await
        .expect("read registration projections");
        let content: serde_json::Value =
            serde_json::from_str(&content).expect("parse registration mirror");
        for projection in [&metadata, &content] {
            assert!(projection.get(field_names::WRITE_SIGNATURE).is_none());
            assert_eq!(projection[field_names::ATTEST_LEVEL], "claimed");
        }
    }

    /// Register + enroll a fresh uuid-suffixed agent on pg; returns
    /// (agent_id, K0).
    async fn pg_register_and_enroll(store: &PostgresStore) -> (String, AgentKeypair) {
        let agent_id = format!("lineage-pg-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        pg_register(store, &agent_id).await;
        let ctx = CallerContext::for_agent(agent_id.clone());
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

    #[tokio::test]
    async fn postgres_identity_mutations_invalidate_prior_registration_attestation_3464() {
        let Some(store) = connect().await else { return };
        let Some(pool) = raw_pool().await else { return };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let bind_agent = format!("signed-bind-pg-{}", &suffix[..8]);
        let bind_key = kp(&bind_agent);
        let bind_ctx = CallerContext::for_agent(bind_agent.clone());
        pg_register(&store, &bind_agent).await;
        seed_pg_genuinely_attested_registration(&store, &pool, &bind_agent, &bind_key).await;
        let proof = ai_memory::store::prove_possession_via_store(
            &store,
            &bind_ctx,
            &bind_agent,
            bind_key.private.as_ref().expect("private"),
        )
        .await
        .expect("prove bind possession");
        store
            .bind_agent_pubkey(&bind_ctx, &bind_agent, &bind_key.public_base64(), proof)
            .await
            .expect("PoP bind");
        assert_pg_registration_attestation_invalidated(&pool, &bind_agent).await;

        let (rotate_agent, old) = pg_register_and_enroll(&store).await;
        let rotate_ctx = CallerContext::for_agent(rotate_agent.clone());
        seed_pg_genuinely_attested_registration(&store, &pool, &rotate_agent, &old).await;
        let successor = kp(&rotate_agent);
        let head = store.read_lineage(&rotate_agent).await.expect("read head")[0]
            .0
            .clone();
        let rotation = LineageRecord::rotation(
            &head,
            &successor.public_base64(),
            None,
            &chrono::Utc::now().to_rfc3339(),
        )
        .expect("build rotation");
        let rotation_sig = sign_succession(&old, &rotation.to_signable()).expect("sign rotation");
        store
            .append_lineage_record(&rotate_ctx, &rotate_agent, &rotation, &rotation_sig)
            .await
            .expect("lineage rotation");
        assert_pg_registration_attestation_invalidated(&pool, &rotate_agent).await;

        let revoke_agent = format!("signed-revoke-pg-{}", &suffix[..8]);
        let revoke_key = kp(&revoke_agent);
        let revoke_ctx = CallerContext::for_agent(revoke_agent.clone());
        pg_register(&store, &revoke_agent).await;
        let revoke_proof = ai_memory::store::prove_possession_via_store(
            &store,
            &revoke_ctx,
            &revoke_agent,
            revoke_key.private.as_ref().expect("private"),
        )
        .await
        .expect("prove revoke-agent bootstrap");
        store
            .bind_agent_pubkey(
                &revoke_ctx,
                &revoke_agent,
                &revoke_key.public_base64(),
                revoke_proof,
            )
            .await
            .expect("initial bind");
        seed_pg_genuinely_attested_registration(&store, &pool, &revoke_agent, &revoke_key).await;
        store
            .revoke_agent_pubkey(&revoke_ctx, &revoke_agent)
            .await
            .expect("revoke");
        assert_pg_registration_attestation_invalidated(&pool, &revoke_agent).await;
    }

    #[tokio::test]
    async fn postgres_future_history_and_retired_key_reuse_leave_identity_unchanged_3464() {
        use base64::Engine as _;
        let Some(store) = connect().await else { return };
        let Some(pool) = raw_pool().await else { return };
        let (agent_id, old) = pg_register_and_enroll(&store).await;
        let ctx = CallerContext::for_agent(agent_id.clone());
        let next = kp(&agent_id);
        let head = store.read_lineage(&agent_id).await.expect("lineage")[0]
            .0
            .clone();
        let rotation = LineageRecord::rotation(
            &head,
            &next.public_base64(),
            None,
            &chrono::Utc::now().to_rfc3339(),
        )
        .expect("rotation");
        let signature = sign_succession(&old, &rotation.to_signable()).expect("sign rotation");
        store
            .append_lineage_record(&ctx, &agent_id, &rotation, &signature)
            .await
            .expect("rotate to next");

        let before_reuse = store
            .agent_pubkey_versions(&agent_id)
            .await
            .expect("history");
        let lineage_before_reuse = store.read_lineage(&agent_id).await.expect("lineage");
        let current_head = lineage_before_reuse.last().expect("head").0.clone();
        let padded_old = base64::engine::general_purpose::STANDARD.encode(old.public.to_bytes());
        let reuse = LineageRecord::rotation(
            &current_head,
            &padded_old,
            None,
            &chrono::Utc::now().to_rfc3339(),
        )
        .expect("retired-key succession");
        let reuse_sig = sign_succession(&next, &reuse.to_signable()).expect("sign reuse");
        let error = store
            .append_lineage_record(&ctx, &agent_id, &reuse, &reuse_sig)
            .await
            .expect_err("a retired key can never become live again");
        assert!(error.to_string().contains("reactivate"), "got: {error}");
        assert_eq!(
            store.agent_pubkey_versions(&agent_id).await.unwrap(),
            before_reuse,
            "reuse refusal occurs before the open head is closed"
        );
        assert_eq!(
            store.read_lineage(&agent_id).await.unwrap(),
            lineage_before_reuse
        );

        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        sqlx::query(
            "UPDATE agent_pubkey_history SET bound_at = $2
             WHERE agent_id = $1 AND superseded_at IS NULL",
        )
        .bind(&agent_id)
        .bind(&future)
        .execute(&pool)
        .await
        .expect("seed future-stamped open history");
        let future_history = store
            .agent_pubkey_versions(&agent_id)
            .await
            .expect("future history");
        let future_lineage = store
            .read_lineage(&agent_id)
            .await
            .expect("lineage snapshot");
        let successor = kp(&agent_id);
        let future_rotation = LineageRecord::rotation(
            &future_lineage.last().expect("head").0,
            &successor.public_base64(),
            None,
            &chrono::Utc::now().to_rfc3339(),
        )
        .expect("future rotation");
        let future_sig =
            sign_succession(&next, &future_rotation.to_signable()).expect("sign future rotation");
        assert!(
            store
                .append_lineage_record(&ctx, &agent_id, &future_rotation, &future_sig)
                .await
                .is_err(),
            "postgres rotation refuses a non-monotonic wall-clock stamp"
        );
        assert!(
            store.revoke_agent_pubkey(&ctx, &agent_id).await.is_err(),
            "postgres revoke refuses a non-monotonic wall-clock stamp"
        );
        assert_eq!(
            store.agent_pubkey_versions(&agent_id).await.unwrap(),
            future_history
        );
        assert_eq!(store.read_lineage(&agent_id).await.unwrap(), future_lineage);
        assert_eq!(
            store.agent_pubkey(&agent_id).await.unwrap(),
            Some(next.public_base64())
        );
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
        let key_history = store
            .agent_pubkey_versions(&agent_id)
            .await
            .expect("key history");
        assert_eq!(
            key_history.len(),
            3,
            "every postgres lineage transition must append its v97 key-history anchor"
        );
        assert!(
            key_history.iter().all(|version| {
                version.bind_authority
                    == ai_memory::identity::pubkey_bind::BindAuthority::LineageSuccession.as_str()
            }),
            "lineage transitions must retain their cryptographic authority label"
        );

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
        // Public bind APIs refuse this rollback by construction (#3464).
        // The flat row remains at K2 while the lineage body is truncated; the
        // deeper witness reconciliation must still fail closed.
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
        let kf_proof = ai_memory::store::prove_possession_via_store(
            &store,
            &flat_ctx,
            &flat_id,
            kf.private.as_ref().expect("generated private key"),
        )
        .await
        .expect("prove possession");
        store
            .bind_agent_pubkey(&flat_ctx, &flat_id, &kf.public_base64(), kf_proof)
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

        let attacker = kp("pg-admin-owned-candidate");
        let attacker_proof = ai_memory::store::prove_possession_via_store(
            &store,
            &flat_ctx,
            &flat_id,
            attacker.private.as_ref().expect("generated private key"),
        )
        .await
        .expect("candidate possession is genuine");
        let refusal = store
            .bind_agent_pubkey(
                &flat_ctx,
                &flat_id,
                &attacker.public_base64(),
                attacker_proof,
            )
            .await
            .expect_err("candidate proof cannot replace another agent's anchored key");
        assert!(
            matches!(
                refusal,
                ai_memory::store::StoreError::PermissionDenied { .. }
            ),
            "postgres must preserve the typed authorization refusal: {refusal}"
        );
        assert_eq!(
            store.agent_pubkey(&flat_id).await.expect("flat key"),
            Some(kf.public_base64()),
            "refused postgres hijack leaves the victim key unchanged"
        );
        assert_eq!(
            store
                .agent_pubkey_versions(&flat_id)
                .await
                .expect("history")
                .len(),
            1,
            "refused postgres hijack leaves no history mutation"
        );
    }

    #[tokio::test]
    async fn postgres_competing_bootstraps_admit_exactly_one_3464() {
        let Some(store) = connect().await else { return };
        let agent_id = format!("bind-race-pg-{}", &uuid::Uuid::new_v4().to_string()[..8]);
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
            .expect("register race target");
        let first = kp("pg-bootstrap-a");
        let second = kp("pg-bootstrap-b");
        let first_key = first.public_base64();
        let second_key = second.public_base64();
        let first_proof = ai_memory::store::prove_possession_via_store(
            &store,
            &ctx,
            &agent_id,
            first.private.as_ref().expect("private"),
        )
        .await
        .expect("first proof");
        let second_proof = ai_memory::store::prove_possession_via_store(
            &store,
            &ctx,
            &agent_id,
            second.private.as_ref().expect("private"),
        )
        .await
        .expect("second proof");

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let run = |key: String,
                   proof: ai_memory::identity::pubkey_bind::PossessionProof,
                   store: PostgresStore,
                   barrier: std::sync::Arc<tokio::sync::Barrier>,
                   agent_id: String| {
            tokio::spawn(async move {
                let ctx = CallerContext::for_agent(agent_id.clone());
                barrier.wait().await;
                store
                    .bind_agent_pubkey(&ctx, &agent_id, &key, proof)
                    .await
                    .is_ok()
            })
        };
        let a = run(
            first_key,
            first_proof,
            store.clone(),
            barrier.clone(),
            agent_id.clone(),
        );
        let b = run(
            second_key,
            second_proof,
            store.clone(),
            barrier.clone(),
            agent_id.clone(),
        );
        barrier.wait().await;
        let admitted = usize::from(a.await.expect("first contender"))
            + usize::from(b.await.expect("second contender"));
        assert_eq!(admitted, 1, "the row lock admits one postgres bootstrap");
        let history = store
            .agent_pubkey_versions(&agent_id)
            .await
            .expect("history");
        assert_eq!(history.len(), 1, "the loser leaves no history mutation");
        assert_eq!(
            store.agent_pubkey(&agent_id).await.expect("flat"),
            Some(history[0].pubkey_b64.clone()),
            "flat and history commit atomically"
        );
    }

    #[tokio::test]
    async fn postgres_bind_challenges_refuse_replay_stale_and_gc_expired_rows_3464() {
        let Some(store) = connect().await else { return };
        let Some(pool) = raw_pool().await else { return };
        let agent_id = format!(
            "bind-challenge-pg-{}",
            &uuid::Uuid::new_v4().to_string()[..8]
        );
        let ctx = CallerContext::for_agent(agent_id.clone());
        let key = kp("pg-challenge").public_base64();

        let once = store
            .issue_pubkey_bind_challenge(&ctx, &agent_id, &key, "test-daemon")
            .await
            .expect("issue single-use challenge");
        assert!(
            store
                .consume_pubkey_bind_challenge(&ctx, &agent_id, &once.nonce_b64)
                .await
                .expect("first consume")
                .is_some()
        );
        assert!(
            store
                .consume_pubkey_bind_challenge(&ctx, &agent_id, &once.nonce_b64)
                .await
                .expect("replay consume")
                .is_none(),
            "postgres conditional UPDATE must refuse replay"
        );

        let stale = store
            .issue_pubkey_bind_challenge(&ctx, &agent_id, &key, "test-daemon")
            .await
            .expect("issue stale challenge");
        let past = ai_memory::validate::canonical_rfc3339(
            &(chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339(),
        );
        sqlx::query("UPDATE agent_pubkey_challenges SET expires_at = $1 WHERE nonce = $2")
            .bind(&past)
            .bind(&stale.nonce_b64)
            .execute(&pool)
            .await
            .expect("expire challenge");
        assert!(
            store
                .consume_pubkey_bind_challenge(&ctx, &agent_id, &stale.nonce_b64)
                .await
                .expect("stale consume")
                .is_none(),
            "postgres consume must enforce durable expiry"
        );

        sqlx::query(
            "UPDATE agent_pubkey_challenges SET expires_at = $1 \
             WHERE nonce = $2 OR nonce = $3",
        )
        .bind(&past)
        .bind(&once.nonce_b64)
        .bind(&stale.nonce_b64)
        .execute(&pool)
        .await
        .expect("expire both consumed and unconsumed challenges");
        let live = store
            .issue_pubkey_bind_challenge(&ctx, &agent_id, &key, "test-daemon")
            .await
            .expect("issue live challenge");

        store.run_gc(false).await.expect("gc expired challenges");

        let (consumed_expired, unconsumed_expired, live_remains): (bool, bool, bool) =
            sqlx::query_as(
                "SELECT
                    EXISTS(SELECT 1 FROM agent_pubkey_challenges WHERE nonce = $1),
                    EXISTS(SELECT 1 FROM agent_pubkey_challenges WHERE nonce = $2),
                    EXISTS(SELECT 1 FROM agent_pubkey_challenges WHERE nonce = $3)",
            )
            .bind(&once.nonce_b64)
            .bind(&stale.nonce_b64)
            .bind(&live.nonce_b64)
            .fetch_one(&pool)
            .await
            .expect("inspect challenge retention after gc");
        assert!(
            !consumed_expired,
            "gc must reap an expired consumed receipt"
        );
        assert!(
            !unconsumed_expired,
            "gc must reap an expired unused challenge"
        );
        assert!(live_remains, "gc must preserve an unexpired challenge");
    }

    #[tokio::test]
    async fn postgres_generic_sal_and_federation_cannot_plant_or_replace_binding_3464() {
        use ai_memory::models::field_names;
        let Some(store) = connect().await else { return };
        let Some(pool) = raw_pool().await else { return };
        let (has_index, has_trigger, has_function): (bool, bool, bool) = sqlx::query_as(
            "SELECT
                to_regclass('idx_agent_pubkey_history_one_open') IS NOT NULL,
                EXISTS (
                    SELECT 1 FROM pg_trigger
                     WHERE tgname = 'agent_pubkey_history_authoritative_v97'
                       AND tgrelid = 'memories'::regclass
                       AND NOT tgisinternal
                ),
                to_regprocedure('reconcile_agent_pubkey_from_history_v97()') IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .expect("inspect v97 greenfield/runtime schema objects");
        assert!(has_index && has_trigger && has_function);
        let agent_id = format!("generic-bind-pg-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let ctx = CallerContext::for_agent(agent_id.clone());
        let attacker = kp("generic-bind-pg-attacker");
        let attacker_key = attacker.public_base64();
        let created = chrono::Utc::now().to_rfc3339();
        let planted_meta = serde_json::json!({
            "agent_id": agent_id,
            (field_names::AGENT_PUBKEY): attacker_key,
            (field_names::PUBKEY_BOUND_AT): created,
            (field_names::WRITE_SIGNATURE): "forged-carried-signature",
            (field_names::ATTEST_LEVEL): "agent_attested",
        });
        let mut row = ai_memory::models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: ai_memory::models::Tier::Long,
            namespace: ai_memory::models::AGENTS_NAMESPACE.to_string(),
            title: ai_memory::models::agent_registration_title(&agent_id),
            content: serde_json::to_string(&planted_meta).expect("registration mirror"),
            created_at: created.clone(),
            updated_at: created,
            metadata: planted_meta,
            ..ai_memory::models::Memory::default()
        };
        store
            .store(&ctx, &row)
            .await
            .expect("generic SAL fresh insert");
        assert_eq!(store.agent_pubkey(&agent_id).await.expect("flat"), None);
        assert!(
            store
                .agent_pubkey_versions(&agent_id)
                .await
                .expect("history")
                .is_empty()
        );
        let (fresh_meta, fresh_content): (serde_json::Value, String) = sqlx::query_as(
            "SELECT metadata, content FROM memories WHERE namespace = $1 AND title = $2",
        )
        .bind(ai_memory::models::AGENTS_NAMESPACE)
        .bind(ai_memory::models::agent_registration_title(&agent_id))
        .fetch_one(&pool)
        .await
        .expect("read stripped fresh row");
        assert!(fresh_meta.get(field_names::AGENT_PUBKEY).is_none());
        assert!(fresh_meta.get(field_names::WRITE_SIGNATURE).is_none());
        assert_eq!(fresh_meta[field_names::ATTEST_LEVEL], "claimed");
        let fresh_content: serde_json::Value =
            serde_json::from_str(&fresh_content).expect("mirrored JSON");
        assert!(fresh_content.get(field_names::AGENT_PUBKEY).is_none());
        assert!(fresh_content.get(field_names::WRITE_SIGNATURE).is_none());
        assert_eq!(fresh_content[field_names::ATTEST_LEVEL], "claimed");

        let legitimate = kp("generic-bind-pg-legitimate");
        let proof = ai_memory::store::prove_possession_via_store(
            &store,
            &ctx,
            &agent_id,
            legitimate.private.as_ref().expect("private"),
        )
        .await
        .expect("prove legitimate bootstrap");
        store
            .bind_agent_pubkey(&ctx, &agent_id, &legitimate.public_base64(), proof)
            .await
            .expect("legitimate bind");

        row.updated_at = "2099-01-01T00:00:00Z".to_string();
        row.metadata.as_object_mut().expect("metadata").insert(
            field_names::AGENT_PUBKEY.to_string(),
            serde_json::Value::String(attacker_key.clone()),
        );
        row.metadata.as_object_mut().expect("metadata").insert(
            field_names::PUBKEY_BOUND_AT.to_string(),
            serde_json::Value::String("2099-01-01T00:00:00Z".to_string()),
        );
        row.content = serde_json::to_string(&row.metadata).expect("attacker mirror");
        let sal_attempt = row.clone();
        let federation_attempt = row.clone();
        let (sal_result, federation_result) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(
                    store.store(&ctx, &sal_attempt),
                    store.apply_remote_memory(&ctx, &federation_attempt)
                )
            })
            .await
            .expect("concurrent PG trigger reconciliation must not deadlock");
        sal_result.expect("generic SAL replacement");
        federation_result.expect("generic federation replacement");

        let legitimate_key = legitimate.public_base64();
        assert_eq!(
            store.agent_pubkey(&agent_id).await.expect("flat"),
            Some(legitimate_key.clone()),
            "database trigger must reconcile generic writes to current history"
        );
        let history = store
            .agent_pubkey_versions(&agent_id)
            .await
            .expect("history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].pubkey_b64, legitimate_key);
        let (final_meta, final_content): (serde_json::Value, String) = sqlx::query_as(
            "SELECT metadata, content FROM memories WHERE namespace = $1 AND title = $2",
        )
        .bind(ai_memory::models::AGENTS_NAMESPACE)
        .bind(ai_memory::models::agent_registration_title(&agent_id))
        .fetch_one(&pool)
        .await
        .expect("read reconciled row");
        assert_eq!(
            final_meta
                .get(field_names::AGENT_PUBKEY)
                .and_then(serde_json::Value::as_str),
            Some(legitimate_key.as_str())
        );
        assert!(final_meta.get(field_names::WRITE_SIGNATURE).is_none());
        assert_eq!(final_meta[field_names::ATTEST_LEVEL], "claimed");
        let final_content: serde_json::Value =
            serde_json::from_str(&final_content).expect("final mirrored JSON");
        assert_eq!(
            final_content
                .get(field_names::AGENT_PUBKEY)
                .and_then(serde_json::Value::as_str),
            Some(legitimate_key.as_str())
        );
        assert!(final_content.get(field_names::WRITE_SIGNATURE).is_none());
        assert_eq!(final_content[field_names::ATTEST_LEVEL], "claimed");
    }

    #[tokio::test]
    async fn postgres_v97_cutover_lock_backfills_concurrent_generic_writer_3464() {
        use base64::Engine as _;

        let Some(url) = postgres_url() else { return };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .expect("connect v97 cutover pool");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let schema = format!("v97_cutover_{}", &suffix[..12]);
        let agent_id = format!("v97-cutover-{}", &suffix[..8]);
        let title = ai_memory::models::agent_registration_title(&agent_id);
        let initial = serde_json::json!({"agent_id": agent_id});

        sqlx::raw_sql(&format!(
            "CREATE SCHEMA {schema};
             CREATE TABLE {schema}.schema_version (
                 version INTEGER PRIMARY KEY,
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
             );
             CREATE TABLE {schema}.memories (
                 id TEXT PRIMARY KEY,
                 namespace TEXT NOT NULL,
                 title TEXT NOT NULL,
                 metadata JSONB NOT NULL,
                 content TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
             );"
        ))
        .execute(&pool)
        .await
        .expect("create isolated pre-v97 schema");
        let poison_key = kp("v97-cutover-noncanonical-poison").public_base64();
        let poison = serde_json::json!({
            "agent_id": agent_id,
            "agent_pubkey": poison_key,
            "pubkey_bound_at": "2026-09-03T23:59:59Z",
        });
        sqlx::query(&format!(
            "INSERT INTO {schema}.memories
                 (id, namespace, title, metadata, content, created_at)
             VALUES ($1, '_agents', '0000-noncanonical-poison', $2, $3,
                     '2026-09-03T23:59:59Z')"
        ))
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&poison)
        .bind(poison.to_string())
        .execute(&pool)
        .await
        .expect("seed earlier noncanonical backfill poison row");
        sqlx::query(&format!(
            "INSERT INTO {schema}.memories
                 (id, namespace, title, metadata, content, created_at)
             VALUES ($1, '_agents', $2, $3, $4, '2026-09-04T00:00:00Z')"
        ))
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&title)
        .bind(&initial)
        .bind(initial.to_string())
        .execute(&pool)
        .await
        .expect("seed pre-v97 registration");

        // Hold the exact RowExclusive/row locks a generic registration UPDATE
        // owns while it commits a previously legal flat key. The v97 ladder's
        // SHARE ROW EXCLUSIVE lock must wait before taking its backfill
        // snapshot; otherwise this writer could land between backfill and
        // trigger installation and permanently evade history.
        let planted_kp = kp("v97-cutover-writer");
        let planted_key = planted_kp.public_base64();
        let planted_padded =
            base64::engine::general_purpose::STANDARD.encode(planted_kp.public.to_bytes());
        let planted = serde_json::json!({
            "agent_id": agent_id,
            "agent_pubkey": planted_padded,
            "pubkey_bound_at": "2026-09-04T00:00:01Z",
            "write_signature": "pre-v97-carried-signature",
            "attest_level": "agent_attested",
        });
        let mut writer = pool.begin().await.expect("begin concurrent writer");
        sqlx::query(&format!("SET LOCAL search_path TO {schema}, public"))
            .execute(&mut *writer)
            .await
            .expect("scope writer schema");
        sqlx::query(
            "UPDATE memories SET metadata = $1, content = $2
             WHERE namespace = '_agents' AND title = $3",
        )
        .bind(&planted)
        .bind(planted.to_string())
        .bind(&title)
        .execute(&mut *writer)
        .await
        .expect("hold generic pre-v97 write open");

        let migration_pool = pool.clone();
        let migration_schema = schema.clone();
        let migration = async move {
            let mut tx = migration_pool.begin().await.expect("begin v97 migration");
            sqlx::query(&format!(
                "SET LOCAL search_path TO {migration_schema}, public"
            ))
            .execute(&mut *tx)
            .await
            .expect("scope migration schema");
            sqlx::query("SET LOCAL lock_timeout = '10s'")
                .execute(&mut *tx)
                .await
                .expect("bound v97 lock acquisition");
            sqlx::raw_sql(include_str!(
                "../migrations/postgres/0054_v97_agent_pubkey_history.sql"
            ))
            .execute(&mut *tx)
            .await
            .expect("apply v97 migration");
            sqlx::query(
                "INSERT INTO schema_version (version) VALUES (97)
                 ON CONFLICT (version) DO NOTHING",
            )
            .execute(&mut *tx)
            .await
            .expect("stamp literal v97 in the migration transaction");
            tx.commit().await.expect("commit v97 migration");
        };

        let release_writer = async {
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                loop {
                    let waiting: bool = sqlx::query_scalar(
                        "SELECT EXISTS (
                         SELECT 1
                           FROM pg_locks AS locks
                           JOIN pg_class AS relation ON relation.oid = locks.relation
                           JOIN pg_namespace AS namespace
                             ON namespace.oid = relation.relnamespace
                          WHERE namespace.nspname = $1
                            AND relation.relname = 'memories'
                            AND locks.mode = 'ShareRowExclusiveLock'
                            AND NOT locks.granted
                     )",
                    )
                    .bind(&schema)
                    .fetch_one(&pool)
                    .await
                    .expect("observe migration table lock");
                    if waiting {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("v97 migration must wait on the in-flight writer lock");
            writer.commit().await.expect("commit pre-v97 writer");
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(migration, release_writer)
        })
        .await
        .expect("v97 cutover must finish within the bounded lock window");

        let (history_key, history_count): (String, i64) = sqlx::query_as(&format!(
            "SELECT MIN(pubkey_b64), COUNT(*)
               FROM {schema}.agent_pubkey_history
              WHERE agent_id = $1"
        ))
        .bind(&agent_id)
        .fetch_one(&pool)
        .await
        .expect("read cutover history");
        assert_eq!(history_key, planted_key);
        assert_eq!(history_count, 1, "committed writer must be backfilled once");
        assert_ne!(
            history_key, poison_key,
            "a noncanonical title carrying the victim agent_id must never win version 1"
        );
        let (migrated_meta, migrated_content): (serde_json::Value, String) = sqlx::query_as(
            &format!("SELECT metadata, content FROM {schema}.memories WHERE title = $1"),
        )
        .bind(&title)
        .fetch_one(&pool)
        .await
        .expect("read canonicalized legacy projection");
        let migrated_content: serde_json::Value =
            serde_json::from_str(&migrated_content).expect("canonical content JSON");
        for projection in [&migrated_meta, &migrated_content] {
            assert_eq!(projection["agent_pubkey"], planted_key);
            assert_eq!(projection["attest_level"], "claimed");
            assert!(projection.get("write_signature").is_none());
        }
        let stamp: i32 = sqlx::query_scalar(&format!(
            "SELECT version FROM {schema}.schema_version WHERE version = 97"
        ))
        .fetch_one(&pool)
        .await
        .expect("v97 stamp committed with history and trigger");
        assert_eq!(stamp, 97);

        let attacker_key = kp("v97-cutover-post-trigger-attacker").public_base64();
        let attacker = serde_json::json!({
            "agent_id": agent_id,
            "agent_pubkey": attacker_key,
            "pubkey_bound_at": "2099-01-01T00:00:00Z",
            "write_signature": "post-v97-forgery",
            "attest_level": "agent_attested",
        });
        let mut post_cutover = pool.begin().await.expect("begin post-cutover writer");
        sqlx::query(&format!("SET LOCAL search_path TO {schema}, public"))
            .execute(&mut *post_cutover)
            .await
            .expect("scope post-cutover writer");
        sqlx::query(
            "UPDATE memories SET metadata = $1, content = $2
             WHERE namespace = '_agents' AND title = $3",
        )
        .bind(&attacker)
        .bind(attacker.to_string())
        .bind(&title)
        .execute(&mut *post_cutover)
        .await
        .expect("attempt generic post-v97 replacement");
        post_cutover
            .commit()
            .await
            .expect("commit reconciled write");

        let (metadata, content): (serde_json::Value, String) = sqlx::query_as(&format!(
            "SELECT metadata, content FROM {schema}.memories
              WHERE namespace = '_agents' AND title = $1"
        ))
        .bind(&title)
        .fetch_one(&pool)
        .await
        .expect("read post-cutover registration");
        let content: serde_json::Value = serde_json::from_str(&content).expect("content JSON");
        for projection in [&metadata, &content] {
            assert_eq!(
                projection
                    .get("agent_pubkey")
                    .and_then(serde_json::Value::as_str),
                Some(planted_key.as_str())
            );
            assert!(projection.get("write_signature").is_none());
            assert_eq!(projection["attest_level"], "claimed");
        }
        let final_count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {schema}.agent_pubkey_history WHERE agent_id = $1"
        ))
        .bind(&agent_id)
        .fetch_one(&pool)
        .await
        .expect("count immutable history");
        assert_eq!(
            final_count, 1,
            "generic writes must not append trust history"
        );
        for (version, tail) in "AEIMQUYcgkosw048".chars().enumerate() {
            use base64::Engine as _;

            let encoded = format!("{}{tail}", "A".repeat(42));
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&encoded)
                .expect("canonical 32-byte base64");
            assert_eq!(decoded.len(), 32);
            assert_eq!(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded),
                encoded
            );
            sqlx::query(&format!(
                "INSERT INTO {schema}.agent_pubkey_history
                 (agent_id, version, pubkey_b64, bind_authority, bound_at)
                 VALUES ($1, $2, $3, 'legacy_unproven', '2026-09-04T00:00:00Z')"
            ))
            .bind(format!("pg-tail-{tail}"))
            .bind(i64::try_from(version + 1).expect("bounded version"))
            .bind(encoded)
            .execute(&pool)
            .await
            .expect("every canonical 32-byte base64 tail passes the PG constraint");
        }
        let mut impossible = planted_key.clone();
        impossible.replace_range(42..43, "B");
        let error = sqlx::query(&format!(
            "INSERT INTO {schema}.agent_pubkey_history
             (agent_id, version, pubkey_b64, bind_authority, bound_at)
             VALUES ('bad-tail', 1, $1, 'legacy_unproven', '2026-09-04T00:00:00Z')"
        ))
        .bind(impossible)
        .execute(&pool)
        .await
        .expect_err("PG CHECK rejects noncanonical unused base64 tail bits");
        assert!(
            error
                .to_string()
                .contains("agent_pubkey_history_pubkey_canonical")
        );

        sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&pool)
            .await
            .expect("drop isolated v97 cutover schema");
    }

    #[tokio::test]
    async fn postgres_historical_attestation_key_is_windowed_and_ambiguous_fails_3464() {
        let Some(store) = connect().await else { return };
        let Some(pool) = raw_pool().await else { return };

        let agent_id = format!("history-at-pg-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        let old_kp = kp("history-at-pg-old");
        let next_kp = kp("history-at-pg-next");
        let current_kp = kp("history-at-pg-current");
        sqlx::query(
            "INSERT INTO agent_pubkey_history
                (agent_id, version, pubkey_b64, bind_authority, proof_nonce,
                 bound_at, superseded_at)
             VALUES
                ($1, 1, $2, 'legacy_unproven', NULL,
                 '2026-01-01T00:00:00+00:00', '2026-02-01T00:00:00+00:00'),
                ($1, 2, $3, 'lineage_succession', NULL,
                 '2026-02-01T00:00:00+00:00', '2026-03-01T00:00:00+00:00'),
                ($1, 3, $4, 'lineage_succession', NULL,
                 '2026-04-01T00:00:00+00:00', NULL)",
        )
        .bind(&agent_id)
        .bind(old_kp.public_base64())
        .bind(next_kp.public_base64())
        .bind(current_kp.public_base64())
        .execute(&pool)
        .await
        .expect("seed disjoint history");

        let old = store
            .agent_pubkey_for_attestation_at(&agent_id, "2026-01-15T00:00:00+00:00")
            .await
            .expect("resolve old window");
        assert!(old.history_exists);
        assert_eq!(old.candidate_pubkeys_b64, [old_kp.public_base64()]);
        let at_bound = store
            .agent_pubkey_for_attestation_at(&agent_id, "2026-01-01T00:00:00+00:00")
            .await
            .expect("bound_at is inclusive");
        assert_eq!(at_bound.candidate_pubkeys_b64, [old_kp.public_base64()]);
        let at_handoff = store
            .agent_pubkey_for_attestation_at(&agent_id, "2026-02-01T00:00:00+00:00")
            .await
            .expect("resolve exact handoff");
        assert_eq!(
            at_handoff.candidate_pubkeys_b64,
            [old_kp.public_base64(), next_kp.public_base64()],
            "the signature disambiguates the two skew-eligible handoff keys"
        );
        let gap = store
            .agent_pubkey_for_attestation_at(&agent_id, "2026-03-15T00:00:00+00:00")
            .await
            .expect("resolve revoked gap");
        assert!(gap.history_exists);
        assert!(
            gap.candidate_pubkeys_b64.is_empty(),
            "gap must not use the current key"
        );

        let second_open = sqlx::query(
            "INSERT INTO agent_pubkey_history
                (agent_id, version, pubkey_b64, bind_authority, proof_nonce,
                 bound_at, superseded_at)
             VALUES ($1, 4, $2, 'lineage_succession', NULL,
                     '2026-05-01T00:00:00+00:00', NULL)",
        )
        .bind(&agent_id)
        .bind(next_kp.public_base64())
        .execute(&pool)
        .await;
        assert!(
            second_open.is_err(),
            "postgres partial unique index permits at most one open key"
        );

        // Surface-level PostgreSQL re-verification: an envelope created in
        // v1's window verifies under v1 after rotation, while substituting the
        // current key for that old instant is a forgery refusal.
        let signed_at = "2026-01-15T00:00:00+00:00";
        let historical_memory = ai_memory::models::Memory {
            id: format!("history-pg-memory-{}", uuid::Uuid::new_v4()),
            namespace: "identity/history".to_string(),
            title: "postgres historical attestation".to_string(),
            content: "old key remains verifiable after rotation".to_string(),
            created_at: signed_at.to_string(),
            updated_at: signed_at.to_string(),
            metadata: serde_json::json!({"agent_id": agent_id}),
            ..ai_memory::models::Memory::default()
        };
        let old_signature =
            ai_memory::identity::attest::sign_memory_write(&old_kp, &historical_memory, &agent_id)
                .expect("sign historical postgres envelope");
        assert_eq!(
            ai_memory::identity::attest::resolve_historical_write_attest_level(
                &historical_memory,
                &agent_id,
                Some(&old),
                Some(&old_signature),
                false,
            )
            .expect("historical pg key verifies old envelope"),
            ai_memory::identity::verify::AttestLevel::AgentAttested
        );
        assert!(
            ai_memory::identity::attest::resolve_write_attest_level(
                &historical_memory,
                &agent_id,
                Some(&current_kp.public_base64()),
                Some(&old_signature),
                false,
            )
            .is_err(),
            "the postgres current key must not verify an old envelope"
        );

        let boundary = chrono::DateTime::parse_from_rfc3339("2026-02-01T00:00:00+00:00")
            .expect("fixed handoff");
        for (stamp, signer, label) in [
            (
                boundary - chrono::Duration::seconds(1),
                &next_kp,
                "slow new key",
            ),
            (
                boundary + chrono::Duration::seconds(1),
                &old_kp,
                "fast old key",
            ),
        ] {
            let created_at = stamp.to_rfc3339();
            let mem = ai_memory::models::Memory {
                id: format!("history-pg-{label}-{}", uuid::Uuid::new_v4()),
                namespace: "identity/history".to_string(),
                title: label.to_string(),
                content: "admitted skewed signature remains re-verifiable".to_string(),
                created_at: created_at.clone(),
                updated_at: created_at.clone(),
                metadata: serde_json::json!({"agent_id": agent_id}),
                ..ai_memory::models::Memory::default()
            };
            let signature = ai_memory::identity::attest::sign_memory_write(signer, &mem, &agent_id)
                .expect("sign skewed envelope");
            let candidates = store
                .agent_pubkey_for_attestation_at(&agent_id, &created_at)
                .await
                .expect("resolve expanded postgres candidates");
            assert_eq!(candidates.candidate_pubkeys_b64.len(), 2, "{label}");
            assert_eq!(
                ai_memory::identity::attest::resolve_historical_write_attest_level(
                    &mem,
                    &agent_id,
                    Some(&candidates),
                    Some(&signature),
                    false,
                )
                .expect("signature selects one postgres history key"),
                ai_memory::identity::verify::AttestLevel::AgentAttested,
                "{label}"
            );
        }
        let forged_at_boundary = ai_memory::models::Memory {
            id: format!("history-pg-no-match-{}", uuid::Uuid::new_v4()),
            namespace: "identity/history".to_string(),
            title: "no eligible key signed".to_string(),
            content: "forged candidate set".to_string(),
            created_at: boundary.to_rfc3339(),
            updated_at: boundary.to_rfc3339(),
            metadata: serde_json::json!({"agent_id": agent_id}),
            ..ai_memory::models::Memory::default()
        };
        let forged = ai_memory::identity::attest::sign_memory_write(
            &current_kp,
            &forged_at_boundary,
            &agent_id,
        )
        .expect("sign with ineligible key");
        assert!(
            ai_memory::identity::attest::resolve_historical_write_attest_level(
                &forged_at_boundary,
                &agent_id,
                Some(&at_handoff),
                Some(&forged),
                false,
            )
            .is_err(),
            "a postgres candidate-set no-match fails closed"
        );

        let exact_lower = store
            .agent_pubkey_for_attestation_at(
                &agent_id,
                &(chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00").unwrap()
                    - chrono::Duration::seconds(300))
                .to_rfc3339(),
            )
            .await
            .expect("exact expanded lower bound");
        assert_eq!(exact_lower.candidate_pubkeys_b64, [old_kp.public_base64()]);
        let exact_upper = store
            .agent_pubkey_for_attestation_at(
                &agent_id,
                &(boundary + chrono::Duration::seconds(300)).to_rfc3339(),
            )
            .await
            .expect("exact expanded upper bound");
        assert_eq!(
            exact_upper.candidate_pubkeys_b64,
            [next_kp.public_base64()],
            "old-key upper eligibility endpoint is exclusive"
        );

        sqlx::query(
            "UPDATE agent_pubkey_history SET superseded_at = '2026-04-01T00:00:00+00:00'
             WHERE agent_id = $1 AND version = 1",
        )
        .bind(&agent_id)
        .execute(&pool)
        .await
        .expect("make history overlap");
        let error = store
            .agent_pubkey_for_attestation_at(&agent_id, "2026-03-15T00:00:00+00:00")
            .await
            .expect_err("ambiguous history must fail closed");
        assert!(
            matches!(error, ai_memory::store::StoreError::IntegrityFailed { .. }),
            "postgres must preserve typed integrity refusal: {error}"
        );

        sqlx::query(
            "UPDATE agent_pubkey_history SET superseded_at = '2026-02-01T00:00:00+00:00'
             WHERE agent_id = $1 AND version = 1",
        )
        .bind(&agent_id)
        .execute(&pool)
        .await
        .expect("restore non-overlap");
        sqlx::query("DELETE FROM agent_pubkey_history WHERE agent_id = $1 AND version = 1")
            .bind(&agent_id)
            .execute(&pool)
            .await
            .expect("make version gap");
        let error = store
            .agent_pubkey_for_attestation_at(&agent_id, "2026-02-15T00:00:00+00:00")
            .await
            .expect_err("missing version must fail closed");
        assert!(
            matches!(error, ai_memory::store::StoreError::IntegrityFailed { .. }),
            "postgres missing-version refusal stays typed: {error}"
        );
    }

    #[tokio::test]
    async fn postgres_v97_migration_refuses_duplicate_retired_key_history_3464() {
        let Some(pool) = raw_pool().await else { return };
        let schema = format!("v97_duplicate_{}", uuid::Uuid::new_v4().simple());
        let mut tx = pool.begin().await.expect("begin isolated migration");
        sqlx::raw_sql(&format!(
            "CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema}, public;
             CREATE TABLE memories (
               namespace TEXT NOT NULL, title TEXT NOT NULL, metadata JSONB NOT NULL,
               content TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL
             );
             CREATE TABLE agent_pubkey_history (
               agent_id TEXT NOT NULL, version BIGINT NOT NULL, pubkey_b64 TEXT NOT NULL,
               bind_authority TEXT NOT NULL, proof_nonce TEXT, bound_at TEXT NOT NULL,
               superseded_at TEXT, PRIMARY KEY(agent_id, version)
             );
             INSERT INTO agent_pubkey_history VALUES
               ('ai:corrupt', 1, 'same-key', 'legacy_unproven', NULL,
                '2026-01-01T00:00:00+00:00', '2026-02-01T00:00:00+00:00'),
               ('ai:corrupt', 2, 'same-key', 'guardian_recovery', NULL,
                '2026-03-01T00:00:00+00:00', NULL);"
        ))
        .execute(&mut *tx)
        .await
        .expect("seed duplicate-key corruption");
        let error = sqlx::raw_sql(include_str!(
            "../migrations/postgres/0054_v97_agent_pubkey_history.sql"
        ))
        .execute(&mut *tx)
        .await
        .expect_err("v97 must refuse rather than deduplicate ambiguous history");
        assert!(
            error
                .to_string()
                .contains("retired key appears in multiple versions"),
            "got: {error}"
        );
        tx.rollback()
            .await
            .expect("drop isolated schema by rollback");
    }
}
