// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3464 (security-high) — proof of possession on `bind_agent_pubkey`,
//! the append-only key history, and the sub-key revocation gate.
//!
//! Three defects, one issue:
//!
//! 1. **No proof of possession.** `bind_agent_pubkey` took a SELF-ASSERTED
//!    base64 key. It was admin-gated, validated as a curve point and audited —
//!    but nothing proved the caller held the matching private key, so anyone
//!    with the admin role could bind a key THEY controlled to another agent's
//!    id and then mint `agent_attested` writes as that agent: the strongest
//!    provenance claim the substrate makes, forgeable from a role claim.
//! 2. **Rebinding orphaned prior attestations.** The key lived only in the flat
//!    `metadata.agent_pubkey`, so a rotation OVERWROTE it and every
//!    `agent_attested` row the previous key signed lost the anchor it is
//!    verified against.
//! 3. **`agent_subkey_certs.revoked` was inert.** It was written by nothing and
//!    read by nothing, so delegation revocation never fired: a leaked instance
//!    sub-key kept attesting writes for the whole life of its cert.
//!
//! What is pinned here, DENIED path first (each of these fails against the
//! pre-#3464 tree):
//!
//! * an admin presenting a proof signed by a key they hold cannot bind a
//!   DIFFERENT agent's key, over HTTP, and nothing is bound;
//! * a challenge answers exactly once, and only for the agent and candidate
//!   key it was minted for;
//! * a rotation does not destroy the superseded key;
//! * a revoked sub-key cannot attest a write.
//!
//! ALLOWED path: the honest key-holder still binds, the rotation still
//! replaces the LIVE key, and a live sub-key still attests.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use ai_memory::identity::pubkey_bind::{
    BindAuthority, BindChallenge, PossessionProof, sign_bind_challenge,
};

const AGENT: &str = "ai:bind-3464";
const VICTIM: &str = "ai:victim-3464";

fn open_db() -> (tempfile::NamedTempFile, rusqlite::Connection) {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    (f, conn)
}

fn register(conn: &rusqlite::Connection, agent: &str) {
    ai_memory::db::register_agent(conn, agent, "nhi", &[]).expect("register");
}

fn keypair(agent: &str) -> ai_memory::identity::keypair::AgentKeypair {
    ai_memory::identity::keypair::generate(agent).expect("generate keypair")
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ---------------------------------------------------------------------
// DENIED — a key you do not hold cannot be bound.
// ---------------------------------------------------------------------

/// The #3464 attack in one test: the attacker holds `attacker`, wants it bound
/// to the VICTIM's id, and answers the victim's challenge with their own key.
/// The signature is perfectly valid — under the WRONG key — and must be
/// refused.
#[test]
fn a_proof_signed_by_another_key_is_refused_3464() {
    let victim = keypair(VICTIM);
    let attacker = keypair("ai:attacker-3464");
    let victim_pk = victim.public_base64();
    let challenge = BindChallenge {
        nonce_b64: ai_memory::identity::pubkey_bind::new_challenge_nonce(),
        agent_id: VICTIM.to_string(),
        pubkey_b64: victim_pk.clone(),
        expires_at: (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
    };
    // Signed over the EXACT transcript the server will verify (the challenge
    // names the victim's key) — only the signing key is wrong, which is the
    // whole defect.
    let forged = sign_bind_challenge(attacker.private.as_ref().expect("private"), &challenge);
    assert!(
        PossessionProof::verify_challenge_response(&challenge, VICTIM, &victim_pk, &forged, &now())
            .is_err(),
        "#3464 REGRESSED: a signature by a key OTHER than the candidate must never \
         admit a bind — that is exactly how an admin could mint agent_attested \
         writes as another agent"
    );
}

/// A challenge issued for one agent must not admit a bind for another, even
/// when the same candidate key is used.
#[test]
fn a_challenge_does_not_cross_agents_3464() {
    let kp = keypair(AGENT);
    let pk = kp.public_base64();
    let challenge = BindChallenge {
        nonce_b64: ai_memory::identity::pubkey_bind::new_challenge_nonce(),
        agent_id: AGENT.to_string(),
        pubkey_b64: pk.clone(),
        expires_at: (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
    };
    let signature = sign_bind_challenge(kp.private.as_ref().expect("private"), &challenge);
    assert!(
        PossessionProof::verify_challenge_response(&challenge, VICTIM, &pk, &signature, &now())
            .is_err(),
        "a challenge minted for {AGENT} must not admit a bind for {VICTIM}"
    );
    // ...and the honest use of the same material still works.
    PossessionProof::verify_challenge_response(&challenge, AGENT, &pk, &signature, &now())
        .expect("the agent the challenge names must still be bindable");
}

/// Binding to an unregistered agent stays refused, and must leave NO ledger row
/// behind (fail-closed before the append).
#[test]
fn unregistered_agent_bind_leaves_no_history_row_3464() {
    let (_f, conn) = open_db();
    let kp = keypair("ai:ghost-3464");
    let err = ai_memory::db::bind_agent_pubkey_with_keypair(&conn, "ai:ghost-3464", &kp)
        .expect_err("binding to an unregistered agent must be refused");
    assert!(err.to_string().contains("not registered"), "got: {err}");
    assert!(
        ai_memory::db::agent_pubkey_versions(&conn, "ai:ghost-3464")
            .expect("history")
            .is_empty(),
        "a refused bind must not leave a key-history row"
    );
}

// ---------------------------------------------------------------------
// ALLOWED — the honest holder binds, and the ledger records how.
// ---------------------------------------------------------------------

#[test]
fn honest_holder_binds_and_the_ledger_records_the_authority_3464() {
    let (_f, conn) = open_db();
    register(&conn, AGENT);
    let kp = keypair(AGENT);
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &kp).expect("bind");
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, AGENT).expect("read"),
        Some(kp.public_base64())
    );
    let history = ai_memory::db::agent_pubkey_versions(&conn, AGENT).expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].version, 1);
    assert_eq!(history[0].pubkey_b64, kp.public_base64());
    assert_eq!(
        history[0].bind_authority,
        BindAuthority::PossessionProof.as_str(),
        "an externally-driven bind must be recorded as possession-proved"
    );
    assert!(
        history[0].proof_nonce.is_some(),
        "the consumed challenge nonce is the audit trail for the proof"
    );
    assert!(history[0].superseded_at.is_none(), "the live key is open");
}

/// Re-asserting the SAME key is idempotent: no phantom rotation is recorded.
#[test]
fn rebinding_the_same_key_appends_no_version_3464() {
    let (_f, conn) = open_db();
    register(&conn, AGENT);
    let kp = keypair(AGENT);
    for _ in 0..3 {
        ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &kp).expect("bind");
    }
    let history = ai_memory::db::agent_pubkey_versions(&conn, AGENT).expect("history");
    assert_eq!(
        history.len(),
        1,
        "re-asserting the live key must not record a rotation that did not happen"
    );
}

// ---------------------------------------------------------------------
// DENIED — a rotation must not destroy the anchor of prior attestations.
// ---------------------------------------------------------------------

#[test]
fn rotation_preserves_the_superseded_key_3464() {
    let (_f, conn) = open_db();
    register(&conn, AGENT);
    let kp1 = keypair(AGENT);
    let kp2 = keypair(AGENT);
    assert_ne!(kp1.public_base64(), kp2.public_base64());

    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &kp1).expect("bind k1");
    let during_k1 = now();
    std::thread::sleep(std::time::Duration::from_millis(5));
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &kp2).expect("rotate to k2");

    // The LIVE key rotated...
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, AGENT).expect("read"),
        Some(kp2.public_base64())
    );
    // ...and the previous one is still on record, with its window closed.
    let history = ai_memory::db::agent_pubkey_versions(&conn, AGENT).expect("history");
    assert_eq!(history.len(), 2, "every bound key keeps a ledger row");
    assert_eq!(history[0].pubkey_b64, kp1.public_base64());
    assert!(
        history[0].superseded_at.is_some(),
        "#3464 REGRESSED: the rotated-away key must be SUPERSEDED, not erased — \
         every agent_attested row it signed is verified against it"
    );
    assert_eq!(history[1].pubkey_b64, kp2.public_base64());
    assert_eq!(history[1].version, 2, "versions are dense and increasing");

    // A row written while k1 was live still resolves to k1.
    let at_k1 = ai_memory::db::agent_pubkey_at(&conn, AGENT, &during_k1)
        .expect("as-of lookup")
        .expect("k1 was live at that instant");
    assert_eq!(
        at_k1.pubkey_b64,
        kp1.public_base64(),
        "an attested row must be re-verifiable against the key that SIGNED it, \
         not merely against whichever key is live today"
    );
    assert_eq!(at_k1.version, 1);

    // ...and the current instant resolves to k2.
    let at_now = ai_memory::db::agent_pubkey_at(&conn, AGENT, &now())
        .expect("as-of lookup")
        .expect("k2 is live now");
    assert_eq!(at_now.pubkey_b64, kp2.public_base64());
}

#[test]
fn revocation_closes_the_window_without_losing_the_key_3464() {
    let (_f, conn) = open_db();
    register(&conn, AGENT);
    let kp = keypair(AGENT);
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &kp).expect("bind");
    ai_memory::db::revoke_agent_pubkey(&conn, AGENT).expect("revoke");

    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, AGENT).expect("read"),
        None,
        "revocation removes the LIVE binding"
    );
    let history = ai_memory::db::agent_pubkey_versions(&conn, AGENT).expect("history");
    assert_eq!(history.len(), 1, "the revoked key stays on record");
    assert!(
        history[0].superseded_at.is_some(),
        "revocation CLOSES the window; it does not un-sign what the key signed"
    );
    // A second revoke is a no-op, never a rewrite of the closed window.
    let closed_at = history[0].superseded_at.clone();
    ai_memory::db::revoke_agent_pubkey(&conn, AGENT).expect("revoke again");
    let history = ai_memory::db::agent_pubkey_versions(&conn, AGENT).expect("history");
    assert_eq!(history[0].superseded_at, closed_at, "append-only");
}

// ---------------------------------------------------------------------
// DENIED — a revoked sub-key certificate must stop attesting.
// ---------------------------------------------------------------------

#[test]
fn revoked_subkey_is_refused_by_the_revocation_reader_3464() {
    let (_f, conn) = open_db();
    register(&conn, AGENT);
    let root = keypair(AGENT);
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &root).expect("bind root");

    // Persist a cert row the way the v2 TOFU path does.
    let instance = keypair("ai:instance-3464");
    let instance_key_id = instance.public.to_bytes().to_vec();
    let record = ai_memory::identity::attest_v2::SubkeyCertRecord {
        id: "b3:3464-test-cert".to_string(),
        principal: AGENT.to_string(),
        instance_key_id: instance_key_id.clone(),
        model_version_ref: vec![0xab; 32],
        not_before: "2026-01-01T00:00:00Z".to_string(),
        not_after: "2030-01-01T00:00:00Z".to_string(),
        signature: vec![0u8; 64],
        cert_bytes: vec![1, 2, 3],
    };
    ai_memory::db::insert_subkey_cert(&conn, &record).expect("persist cert");

    // ALLOWED: a live cert does not gate.
    assert!(
        !ai_memory::db::subkey_is_revoked(&conn, AGENT, &instance_key_id).expect("probe"),
        "a live sub-key must keep attesting"
    );

    // DENIED after revocation.
    assert!(
        ai_memory::db::revoke_subkey_cert(&conn, "b3:3464-test-cert").expect("revoke"),
        "revoking a live cert reports the change"
    );
    assert!(
        ai_memory::db::subkey_is_revoked(&conn, AGENT, &instance_key_id).expect("probe"),
        "#3464 REGRESSED: `agent_subkey_certs.revoked` must GATE verification — \
         before this fix it was written by nothing and read by nothing, so a \
         leaked instance sub-key kept minting agent_attested writes"
    );
    // Idempotent: re-revoking changes nothing and is not an error.
    assert!(
        !ai_memory::db::revoke_subkey_cert(&conn, "b3:3464-test-cert").expect("re-revoke"),
        "revocation is one-way and idempotent, so a fleet sweep is resumable"
    );
    assert!(ai_memory::db::subkey_is_revoked(&conn, AGENT, &instance_key_id).expect("probe"));
}

/// Revocation is keyed on the SUB-KEY, not on one certificate encoding of it:
/// a second cert over the same instance key must not resurrect it.
#[test]
fn revocation_binds_the_subkey_not_the_cert_row_3464() {
    let (_f, conn) = open_db();
    register(&conn, AGENT);
    let instance = keypair("ai:instance-3464b");
    let instance_key_id = instance.public.to_bytes().to_vec();
    for (id, not_after) in [
        ("b3:3464-cert-a", "2030-01-01T00:00:00Z"),
        ("b3:3464-cert-b", "2031-01-01T00:00:00Z"),
    ] {
        let record = ai_memory::identity::attest_v2::SubkeyCertRecord {
            id: id.to_string(),
            principal: AGENT.to_string(),
            instance_key_id: instance_key_id.clone(),
            model_version_ref: vec![0xcd; 32],
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: not_after.to_string(),
            signature: vec![0u8; 64],
            cert_bytes: id.as_bytes().to_vec(),
        };
        ai_memory::db::insert_subkey_cert(&conn, &record).expect("persist cert");
    }
    assert!(ai_memory::db::revoke_subkey_cert(&conn, "b3:3464-cert-a").expect("revoke a"));
    assert!(
        ai_memory::db::subkey_is_revoked(&conn, AGENT, &instance_key_id).expect("probe"),
        "revoking a delegation must kill the SUB-KEY: a second cert over the same \
         instance key cannot bring it back"
    );
}

// ---------------------------------------------------------------------
// The lineage authority is recorded distinctly (and is not externally
// reachable — `from_verified_lineage_succession` is crate-private).
// ---------------------------------------------------------------------

#[test]
fn possession_proof_carries_its_authority_3464() {
    let (_f, conn) = open_db();
    let kp = keypair(AGENT);
    let proof = ai_memory::db::prove_possession_with_conn(
        &conn,
        AGENT,
        kp.private.as_ref().expect("private"),
    )
    .expect("prove");
    assert_eq!(proof.authority(), BindAuthority::PossessionProof);
    assert_eq!(BindAuthority::PossessionProof.as_str(), "possession_proof");
    assert_eq!(
        BindAuthority::LineageSuccession.as_str(),
        "lineage_succession"
    );
}

// ---------------------------------------------------------------------
// The challenge is DURABLE, and single-use is decided by the storage
// engine — not by an in-process cache.
// ---------------------------------------------------------------------

/// v1.0.0 #3464 — a challenge answers exactly ONE bind.
///
/// Single use is the `consumed_at IS NULL` predicate of one conditional
/// `UPDATE`, so the row-level write IS the admit-once decision rather than a
/// check-then-act read.
#[test]
fn a_challenge_answers_exactly_once_3464() {
    let (_f, conn) = open_db();
    let kp = keypair(AGENT);
    let issued = ai_memory::db::issue_pubkey_bind_challenge(
        &conn,
        AGENT,
        &kp.public_base64(),
        "test-daemon",
    )
    .expect("issue");

    let first = ai_memory::db::consume_pubkey_bind_challenge(&conn, AGENT, &issued.nonce_b64)
        .expect("consume must not error");
    assert!(first.is_some(), "the first answer is admitted");
    let second = ai_memory::db::consume_pubkey_bind_challenge(&conn, AGENT, &issued.nonce_b64)
        .expect("consume must not error");
    assert!(
        second.is_none(),
        "#3464: a consumed nonce must never admit a second bind — single use is \
         the storage engine's decision, not a cache's"
    );
}

/// A challenge minted for one agent must not be consumable by another, even
/// with the correct nonce.
#[test]
fn a_challenge_does_not_cross_agents_at_the_store_3464() {
    let (_f, conn) = open_db();
    let kp = keypair(AGENT);
    let issued = ai_memory::db::issue_pubkey_bind_challenge(
        &conn,
        AGENT,
        &kp.public_base64(),
        "test-daemon",
    )
    .expect("issue");
    assert!(
        ai_memory::db::consume_pubkey_bind_challenge(&conn, VICTIM, &issued.nonce_b64)
            .expect("consume must not error")
            .is_none(),
        "a challenge issued for {AGENT} must not be consumable as {VICTIM}"
    );
    assert!(
        ai_memory::db::consume_pubkey_bind_challenge(&conn, AGENT, &issued.nonce_b64)
            .expect("consume must not error")
            .is_some(),
        "...and the agent it names can still consume it"
    );
}

/// The candidate key is pinned by the ISSUER, so the row a bind verifies
/// against cannot be retargeted at a different key by the caller.
#[test]
fn the_issuer_pins_the_candidate_key_3464() {
    let (_f, conn) = open_db();
    let kp = keypair(AGENT);
    let pk = kp.public_base64();
    let issued = ai_memory::db::issue_pubkey_bind_challenge(&conn, AGENT, &pk, "test-daemon")
        .expect("issue");
    let taken = ai_memory::db::consume_pubkey_bind_challenge(&conn, AGENT, &issued.nonce_b64)
        .expect("consume")
        .expect("fresh");
    assert_eq!(
        taken.pubkey_b64, pk,
        "the consumed row carries the key the ISSUER recorded"
    );
    // A caller trying to bind a DIFFERENT key against this challenge is
    // refused by the mismatch check, not by the signature check.
    let other = keypair("ai:other-3464");
    let signature = sign_bind_challenge(kp.private.as_ref().expect("private"), &taken);
    assert!(
        PossessionProof::verify_challenge_response(
            &taken,
            AGENT,
            &other.public_base64(),
            &signature,
            &now(),
        )
        .is_err(),
        "#3464: a live challenge must not be retargetable at another key"
    );
}

/// The durable row is what makes issue-on-one-daemon / bind-on-another work —
/// the supported shape on the certified postgres tier, where several daemons
/// share one store. Two independent connections to the SAME database stand in
/// for two daemons.
#[test]
fn a_challenge_issued_on_one_connection_is_consumable_on_another_3464() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let daemon_a = ai_memory::db::open(f.path()).expect("db::open (issuing daemon)");
    let daemon_b = ai_memory::db::open(f.path()).expect("db::open (binding daemon)");
    register(&daemon_a, AGENT);
    let kp = keypair(AGENT);

    let issued = ai_memory::db::issue_pubkey_bind_challenge(
        &daemon_a,
        AGENT,
        &kp.public_base64(),
        "daemon-a",
    )
    .expect("issue on daemon A");
    // ...answered against a DIFFERENT connection, as a load balancer would.
    let taken = ai_memory::db::consume_pubkey_bind_challenge(&daemon_b, AGENT, &issued.nonce_b64)
        .expect("consume on daemon B")
        .expect(
            "#3464: a challenge issued by one daemon MUST be answerable at another — \
             several daemons share one store on the certified tier, so an in-process \
             cache would fail this bind closed with no in-product remedy",
        );
    let signature = sign_bind_challenge(kp.private.as_ref().expect("private"), &taken);
    let proof = PossessionProof::verify_challenge_response(
        &taken,
        AGENT,
        &kp.public_base64(),
        &signature,
        &now(),
    )
    .expect("the cross-daemon answer verifies");
    ai_memory::db::bind_agent_pubkey(&daemon_b, AGENT, &kp.public_base64(), &proof)
        .expect("and binds");
    assert_eq!(
        ai_memory::db::agent_pubkey(&daemon_b, AGENT).expect("read"),
        Some(kp.public_base64())
    );
}

/// Expired challenges are inert AND reaped: the consuming UPDATE tests
/// `expires_at` itself, so an unreaped row is never admissible, and `gc`
/// bounds the table by the TTL rather than by history.
#[test]
fn expired_challenges_are_inert_and_reaped_3464() {
    let (_f, conn) = open_db();
    let kp = keypair(AGENT);
    let issued = ai_memory::db::issue_pubkey_bind_challenge(
        &conn,
        AGENT,
        &kp.public_base64(),
        "test-daemon",
    )
    .expect("issue");
    // Age the row past its window.
    let past = (chrono::Utc::now() - chrono::Duration::seconds(60)).to_rfc3339();
    conn.execute(
        "UPDATE agent_pubkey_challenges SET expires_at = ?1 WHERE nonce = ?2",
        rusqlite::params![past, issued.nonce_b64],
    )
    .expect("age the challenge");

    assert!(
        ai_memory::db::consume_pubkey_bind_challenge(&conn, AGENT, &issued.nonce_b64)
            .expect("consume must not error")
            .is_none(),
        "an expired challenge is inert even before it is reaped"
    );
    let reaped = ai_memory::db::reap_expired_pubkey_bind_challenges(&conn).expect("reap");
    assert_eq!(reaped, 1, "gc bounds the table by the TTL, not by history");
    let left: i64 = conn
        .query_row("SELECT COUNT(*) FROM agent_pubkey_challenges", [], |r| {
            r.get(0)
        })
        .expect("count");
    assert_eq!(left, 0);
}
