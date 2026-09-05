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

use ai_memory::identity::pubkey_bind::{BindAuthority, PossessionProof, sign_bind_challenge};

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
    ai_memory::identity::attest::now_attestable_rfc3339()
}

fn rotate_with_lineage(
    conn: &rusqlite::Connection,
    agent: &str,
    current: &ai_memory::identity::keypair::AgentKeypair,
    successor: &ai_memory::identity::keypair::AgentKeypair,
) {
    let recovery = keypair("ai:recovery-3464");
    ai_memory::db::enroll_lineage(conn, agent, current, Some(&recovery.public_base64()))
        .expect("enroll current key as lineage genesis");
    ai_memory::db::append_succession(conn, agent, current, &successor.public_base64(), None)
        .expect("current key authorizes lineage rotation");
}

fn seed_genuinely_attested_registration(
    conn: &rusqlite::Connection,
    agent: &str,
    signer: &ai_memory::identity::keypair::AgentKeypair,
) {
    use ai_memory::models::field_names;
    use base64::Engine as _;

    let title = ai_memory::models::agent_registration_title(agent);
    let id: String = conn
        .query_row(
            "SELECT id FROM memories WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![ai_memory::models::AGENTS_NAMESPACE, title],
            |row| row.get(0),
        )
        .expect("registration id");
    let mut mem = ai_memory::db::get(conn, &id)
        .expect("read registration")
        .expect("registration exists");
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
    let signature = ai_memory::identity::attest::sign_memory_write(signer, &mem, agent)
        .expect("sign exact registration envelope");
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);
    mem.metadata = mirrored;
    mem.metadata.as_object_mut().expect("metadata").insert(
        field_names::WRITE_SIGNATURE.to_string(),
        serde_json::Value::String(signature_b64),
    );
    conn.execute(
        "UPDATE memories SET metadata = ?2, content = ?3, created_at = ?4, updated_at = ?4 \
         WHERE id = ?1",
        rusqlite::params![id, mem.metadata.to_string(), mem.content, stamp],
    )
    .expect("seed genuinely attested registration");
    let seeded = ai_memory::db::get(conn, &id)
        .expect("read seeded registration")
        .expect("seeded registration exists");
    assert_eq!(
        ai_memory::identity::attest::resolve_write_attest_level(
            &seeded,
            agent,
            Some(&signer.public_base64()),
            Some(&signature),
            false,
        )
        .expect("seeded signature verifies"),
        ai_memory::identity::verify::AttestLevel::AgentAttested,
        "test precondition: the mutation starts from a genuinely signed registration"
    );
}

fn assert_registration_attestation_invalidated(conn: &rusqlite::Connection, agent: &str) {
    use ai_memory::models::field_names;

    let title = ai_memory::models::agent_registration_title(agent);
    let id: String = conn
        .query_row(
            "SELECT id FROM memories WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![ai_memory::models::AGENTS_NAMESPACE, title],
            |row| row.get(0),
        )
        .expect("registration id");
    let row = ai_memory::db::get(conn, &id)
        .expect("read registration")
        .expect("registration exists");
    let content: serde_json::Value =
        serde_json::from_str(&row.content).expect("parse registration mirror");
    for projection in [&row.metadata, &content] {
        assert!(projection.get(field_names::WRITE_SIGNATURE).is_none());
        assert_eq!(projection[field_names::ATTEST_LEVEL], "claimed");
    }
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
    let (_f, conn) = open_db();
    let victim = keypair(VICTIM);
    let attacker = keypair("ai:attacker-3464");
    let victim_pk = victim.public_base64();
    let challenge =
        ai_memory::db::issue_pubkey_bind_challenge(&conn, VICTIM, &victim_pk, "test-daemon")
            .expect("issue durable challenge");
    // Signed over the EXACT transcript the server will verify (the challenge
    // names the victim's key) — only the signing key is wrong, which is the
    // whole defect.
    let forged = sign_bind_challenge(attacker.private.as_ref().expect("private"), &challenge);
    let consumed =
        ai_memory::db::consume_pubkey_bind_challenge(&conn, VICTIM, &challenge.nonce_b64)
            .expect("consume")
            .expect("fresh challenge");
    assert!(
        PossessionProof::verify_challenge_response(consumed, VICTIM, &victim_pk, &forged).is_err(),
        "#3464 REGRESSED: a signature by a key OTHER than the candidate must never \
         admit a bind — that is exactly how an admin could mint agent_attested \
         writes as another agent"
    );
}

/// A challenge issued for one agent must not admit a bind for another, even
/// when the same candidate key is used.
#[test]
fn a_challenge_does_not_cross_agents_3464() {
    let (_f, conn) = open_db();
    let kp = keypair(AGENT);
    let pk = kp.public_base64();
    let challenge = ai_memory::db::issue_pubkey_bind_challenge(&conn, AGENT, &pk, "test-daemon")
        .expect("issue durable challenge");
    let signature = sign_bind_challenge(kp.private.as_ref().expect("private"), &challenge);
    let consumed = ai_memory::db::consume_pubkey_bind_challenge(&conn, AGENT, &challenge.nonce_b64)
        .expect("consume")
        .expect("fresh challenge");
    assert!(
        PossessionProof::verify_challenge_response(consumed, VICTIM, &pk, &signature).is_err(),
        "a challenge minted for {AGENT} must not admit a bind for {VICTIM}"
    );
    // ...and the honest use of the same material still works.
    let honest = ai_memory::db::issue_pubkey_bind_challenge(&conn, AGENT, &pk, "test-daemon")
        .expect("issue fresh honest challenge");
    let honest_signature = sign_bind_challenge(kp.private.as_ref().expect("private"), &honest);
    let honest_consumed =
        ai_memory::db::consume_pubkey_bind_challenge(&conn, AGENT, &honest.nonce_b64)
            .expect("consume")
            .expect("fresh challenge");
    PossessionProof::verify_challenge_response(honest_consumed, AGENT, &pk, &honest_signature)
        .expect("the agent the challenge names must still be bindable");
}

/// A verified witness is itself bound to the tuple it verified. Passing it to
/// the storage funnel with a different target must fail even though the Rust
/// type is otherwise valid.
#[test]
fn a_valid_witness_cannot_be_retargeted_at_storage_3464() {
    let (_f, conn) = open_db();
    register(&conn, AGENT);
    register(&conn, VICTIM);
    let kp = keypair(AGENT);
    let proof = ai_memory::db::prove_possession_with_conn(
        &conn,
        AGENT,
        kp.private.as_ref().expect("private"),
    )
    .expect("prove exact tuple");
    ai_memory::db::bind_agent_pubkey(&conn, VICTIM, &kp.public_base64(), proof)
        .expect_err("a proof for one agent cannot bootstrap another");
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, VICTIM).expect("read"),
        None
    );
    assert!(
        ai_memory::db::agent_pubkey_versions(&conn, VICTIM)
            .expect("history")
            .is_empty()
    );
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

#[test]
fn generic_sqlite_writes_cannot_plant_or_replace_flat_binding_3464() {
    use ai_memory::models::field_names;
    let (_f, conn) = open_db();
    conn.execute_batch("PRAGMA recursive_triggers=ON")
        .expect("exercise authoritative projection with recursion enabled");
    let victim = "ai:generic-write-victim-3464";
    let attacker = keypair("ai:generic-write-attacker-3464");
    let attacker_key = attacker.public_base64();
    let created = now();
    let metadata = serde_json::json!({
        "agent_id": victim,
        (field_names::AGENT_PUBKEY): attacker_key,
        (field_names::PUBKEY_BOUND_AT): created,
        (field_names::WRITE_SIGNATURE): "forged-carried-signature",
        (field_names::ATTEST_LEVEL): "agent_attested",
    });
    let planted = ai_memory::models::Memory {
        id: "generic-registration-plant-3464".to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: ai_memory::models::AGENTS_NAMESPACE.to_string(),
        title: ai_memory::models::agent_registration_title(victim),
        content: serde_json::to_string(&metadata).expect("mirror"),
        created_at: created.clone(),
        updated_at: created,
        metadata,
        ..ai_memory::models::Memory::default()
    };
    ai_memory::db::insert(&conn, &planted).expect("generic fresh insert still stores roster row");
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, victim).expect("flat"),
        None
    );
    assert!(
        ai_memory::db::agent_pubkey_versions(&conn, victim)
            .expect("history")
            .is_empty(),
        "a generic fresh insert must not bootstrap history"
    );
    let fresh = ai_memory::db::get(&conn, &planted.id)
        .expect("get")
        .expect("row");
    assert!(fresh.metadata.get(field_names::AGENT_PUBKEY).is_none());
    assert!(fresh.metadata.get(field_names::WRITE_SIGNATURE).is_none());
    assert_eq!(fresh.metadata[field_names::ATTEST_LEVEL], "claimed");
    let fresh_content: serde_json::Value =
        serde_json::from_str(&fresh.content).expect("mirrored registration content");
    assert!(fresh_content.get(field_names::AGENT_PUBKEY).is_none());
    assert!(fresh_content.get(field_names::WRITE_SIGNATURE).is_none());
    assert_eq!(fresh_content[field_names::ATTEST_LEVEL], "claimed");

    let legitimate = keypair(victim);
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, victim, &legitimate)
        .expect("PoP bootstrap");
    let legitimate_key = legitimate.public_base64();

    let mut federated = ai_memory::db::get(&conn, &planted.id)
        .expect("get")
        .expect("bound row");
    federated.updated_at = "2099-01-01T00:00:00Z".to_string();
    federated
        .metadata
        .as_object_mut()
        .expect("metadata")
        .insert(
            field_names::AGENT_PUBKEY.to_string(),
            serde_json::Value::String(attacker_key.clone()),
        );
    federated.content = serde_json::to_string(&federated.metadata).expect("fake mirror");
    ai_memory::db::insert_if_newer(&conn, &federated).expect("generic federation merge");

    let fake_patch = serde_json::json!({
        "agent_id": victim,
        (field_names::AGENT_PUBKEY): attacker_key,
        (field_names::PUBKEY_BOUND_AT): "2099-01-01T00:00:00Z",
    });
    ai_memory::db::update(
        &conn,
        &planted.id,
        None,
        Some(&serde_json::to_string(&fake_patch).expect("fake content")),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&fake_patch),
    )
    .expect("generic update");

    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, victim).expect("flat"),
        Some(legitimate_key.clone()),
        "generic federation/update paths must retain the history-authorized key"
    );
    let history = ai_memory::db::agent_pubkey_versions(&conn, victim).expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].pubkey_b64, legitimate_key);
    let final_row = ai_memory::db::get(&conn, &planted.id)
        .expect("get")
        .expect("final row");
    let final_content: serde_json::Value =
        serde_json::from_str(&final_row.content).expect("final mirror");
    assert_eq!(
        final_content
            .get(field_names::AGENT_PUBKEY)
            .and_then(serde_json::Value::as_str),
        Some(legitimate_key.as_str())
    );
    assert!(
        final_row
            .metadata
            .get(field_names::WRITE_SIGNATURE)
            .is_none()
    );
    assert_eq!(final_row.metadata[field_names::ATTEST_LEVEL], "claimed");
    assert!(final_content.get(field_names::WRITE_SIGNATURE).is_none());
    assert_eq!(final_content[field_names::ATTEST_LEVEL], "claimed");
}

#[test]
fn sqlite_v97_backfill_ignores_noncanonical_registration_poison_3464() {
    use ai_memory::models::field_names;
    use base64::Engine as _;

    let (_f, conn) = open_db();
    conn.execute_batch(
        "DROP TRIGGER IF EXISTS agent_pubkey_history_authoritative_insert_v97;
         DROP TRIGGER IF EXISTS agent_pubkey_history_authoritative_update_v97;
         DROP TABLE agent_pubkey_challenges;
         DROP TABLE agent_pubkey_history;",
    )
    .expect("restore a pre-v97 identity schema");

    let victim = "ai:v97-backfill-victim-3464";
    let attacker_key = keypair("ai:v97-backfill-attacker-3464").public_base64();
    let legitimate = keypair(victim);
    let legitimate_key = legitimate.public_base64();
    let legacy_padded =
        base64::engine::general_purpose::STANDARD.encode(legitimate.public.to_bytes());
    let created = "2026-09-04T00:00:00Z";
    let poison_metadata = serde_json::json!({
        "agent_id": victim,
        (field_names::AGENT_PUBKEY): attacker_key,
        (field_names::PUBKEY_BOUND_AT): created,
    });
    let poison = ai_memory::models::Memory {
        id: "v97-backfill-poison-3464".to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: ai_memory::models::AGENTS_NAMESPACE.to_string(),
        title: "0000-noncanonical-poison".to_string(),
        content: poison_metadata.to_string(),
        created_at: created.to_string(),
        updated_at: created.to_string(),
        metadata: poison_metadata,
        ..ai_memory::models::Memory::default()
    };
    ai_memory::db::insert(&conn, &poison).expect("seed earlier noncanonical poison row");
    conn.execute(
        "UPDATE memories SET metadata = ?2, content = ?2 WHERE id = ?1",
        rusqlite::params![poison.id, poison.content],
    )
    .expect("model a pre-v97 generic poison write");

    let legitimate_metadata = serde_json::json!({
        "agent_id": victim,
        (field_names::AGENT_PUBKEY): legacy_padded,
        (field_names::PUBKEY_BOUND_AT): created,
        (field_names::WRITE_SIGNATURE): "stale-after-canonicalization",
        (field_names::ATTEST_LEVEL): "agent_attested",
    });
    let legitimate = ai_memory::models::Memory {
        id: "v97-backfill-legitimate-3464".to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: ai_memory::models::AGENTS_NAMESPACE.to_string(),
        title: ai_memory::models::agent_registration_title(victim),
        content: legitimate_metadata.to_string(),
        created_at: created.to_string(),
        updated_at: created.to_string(),
        metadata: legitimate_metadata,
        ..ai_memory::models::Memory::default()
    };
    ai_memory::db::insert(&conn, &legitimate).expect("seed canonical registration second");
    conn.execute(
        "UPDATE memories SET metadata = ?2, content = ?2 WHERE id = ?1",
        rusqlite::params![legitimate.id, legitimate.content],
    )
    .expect("model a pre-v97 canonical registration write");

    conn.execute_batch(include_str!(
        "../migrations/sqlite/0081_v97_agent_pubkey_history.sql"
    ))
    .expect("apply v97 migration doc twin");

    let history = ai_memory::db::agent_pubkey_versions(&conn, victim).expect("read v97 history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].version, 1);
    assert_eq!(history[0].pubkey_b64, legitimate_key);
    assert_eq!(history[0].bind_authority, "legacy_unproven");
    assert_ne!(history[0].pubkey_b64, attacker_key);
    let row = ai_memory::db::get(&conn, "v97-backfill-legitimate-3464")
        .expect("read canonicalized registration")
        .expect("registration exists");
    let content: serde_json::Value = serde_json::from_str(&row.content).expect("content JSON");
    for projection in [&row.metadata, &content] {
        assert_eq!(projection[field_names::AGENT_PUBKEY], legitimate_key);
        assert_eq!(projection[field_names::ATTEST_LEVEL], "claimed");
        assert!(projection.get(field_names::WRITE_SIGNATURE).is_none());
    }
}

#[test]
fn sqlite_v97_history_constraint_rejects_noncanonical_tail_3464() {
    let (_f, conn) = open_db();
    let mut impossible = keypair("ai:bad-tail-3464").public_base64();
    impossible.replace_range(42..43, "B");
    let error = conn
        .execute(
            "INSERT INTO agent_pubkey_history
             (agent_id, version, pubkey_b64, bind_authority, bound_at)
             VALUES ('ai:bad-tail-3464', 1, ?1, 'legacy_unproven',
                     '2026-09-04T00:00:00Z')",
            rusqlite::params![impossible],
        )
        .expect_err("a nonzero unused-bit tail is not canonical base64");
    assert!(error.to_string().contains("CHECK constraint failed"));
}

#[test]
fn sqlite_v97_history_constraint_accepts_every_canonical_tail_3464() {
    use base64::Engine as _;

    let (_f, conn) = open_db();
    for (version, tail) in "AEIMQUYcgkosw048".chars().enumerate() {
        let encoded = format!("{}{tail}", "A".repeat(42));
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .expect("canonical 32-byte base64");
        assert_eq!(decoded.len(), 32);
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded),
            encoded
        );
        conn.execute(
            "INSERT INTO agent_pubkey_history
             (agent_id, version, pubkey_b64, bind_authority, bound_at)
             VALUES (?1, ?2, ?3, 'legacy_unproven', '2026-09-04T00:00:00Z')",
            rusqlite::params![format!("ai:tail-{tail}"), version + 1, encoded],
        )
        .expect("every canonical 32-byte base64 tail passes the DB constraint");
    }
}

#[test]
fn sqlite_v97_migration_refuses_invalid_legacy_key_instead_of_ignoring_it_3464() {
    let (_f, conn) = open_db();
    let agent = "ai:invalid-legacy-key-3464";
    register(&conn, agent);
    conn.execute_batch(
        "DROP TRIGGER agent_pubkey_history_authoritative_insert_v97;
         DROP TRIGGER agent_pubkey_history_authoritative_update_v97;
         DROP TABLE agent_pubkey_challenges;
         DROP TABLE agent_pubkey_history;",
    )
    .expect("restore pre-v97 identity schema");
    let title = ai_memory::models::agent_registration_title(agent);
    let mut invalid = keypair(agent).public_base64();
    invalid.replace_range(42..43, "B");
    conn.execute(
        "UPDATE memories SET
           metadata = json_set(metadata, '$.agent_pubkey', ?2),
           content = json_set(metadata, '$.agent_pubkey', ?2)
         WHERE namespace = '_agents' AND title = ?1",
        rusqlite::params![title, invalid],
    )
    .expect("seed invalid pre-v97 flat key");
    let error = conn
        .execute_batch(include_str!(
            "../migrations/sqlite/0081_v97_agent_pubkey_history.sql"
        ))
        .expect_err("CHECK failure must abort rather than silently omit the legacy anchor");
    assert!(error.to_string().contains("CHECK constraint failed"));
}

#[test]
fn sqlite_pubkey_history_database_refuses_two_open_keys_3464() {
    let (_f, conn) = open_db();
    let one = keypair("ai:one-open-a").public_base64();
    let two = keypair("ai:one-open-b").public_base64();
    conn.execute(
        "INSERT INTO agent_pubkey_history
         (agent_id, version, pubkey_b64, bind_authority, bound_at)
         VALUES ('ai:one-open', 1, ?1, 'legacy_unproven',
                 '2026-01-01T00:00:00+00:00')",
        rusqlite::params![one],
    )
    .expect("first open key");
    let error = conn
        .execute(
            "INSERT INTO agent_pubkey_history
             (agent_id, version, pubkey_b64, bind_authority, bound_at)
             VALUES ('ai:one-open', 2, ?1, 'lineage_succession',
                     '2026-02-01T00:00:00+00:00')",
            rusqlite::params![two],
        )
        .expect_err("the partial unique index permits at most one open key");
    assert!(error.to_string().contains("UNIQUE constraint failed"));
}

#[test]
fn sqlite_identity_mutations_invalidate_prior_registration_attestation_3464() {
    let (_f, conn) = open_db();

    let bind_agent = "ai:signed-bind-3464";
    let bind_key = keypair(bind_agent);
    register(&conn, bind_agent);
    seed_genuinely_attested_registration(&conn, bind_agent, &bind_key);
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, bind_agent, &bind_key).expect("PoP bind");
    assert_registration_attestation_invalidated(&conn, bind_agent);

    let rotate_agent = "ai:signed-rotate-3464";
    let old = keypair(rotate_agent);
    let successor = keypair(rotate_agent);
    let recovery = keypair("ai:signed-rotate-recovery-3464");
    register(&conn, rotate_agent);
    ai_memory::db::enroll_lineage(&conn, rotate_agent, &old, Some(&recovery.public_base64()))
        .expect("enroll genesis");
    seed_genuinely_attested_registration(&conn, rotate_agent, &old);
    ai_memory::db::append_succession(&conn, rotate_agent, &old, &successor.public_base64(), None)
        .expect("lineage rotation");
    assert_registration_attestation_invalidated(&conn, rotate_agent);

    let revoke_agent = "ai:signed-revoke-3464";
    let revoke_key = keypair(revoke_agent);
    register(&conn, revoke_agent);
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, revoke_agent, &revoke_key)
        .expect("initial bind");
    seed_genuinely_attested_registration(&conn, revoke_agent, &revoke_key);
    ai_memory::db::revoke_agent_pubkey(&conn, revoke_agent).expect("revoke");
    assert_registration_attestation_invalidated(&conn, revoke_agent);
}

// ---------------------------------------------------------------------
// ALLOWED — the honest holder binds, and the ledger records how.
// ---------------------------------------------------------------------

#[test]
fn honest_holder_binds_and_the_ledger_records_the_authority_3464() {
    use base64::Engine as _;
    let (_f, conn) = open_db();
    register(&conn, AGENT);
    let kp = keypair(AGENT);
    let canonical = kp.public_base64();
    let padded = base64::engine::general_purpose::STANDARD.encode(kp.public.to_bytes());
    let challenge = ai_memory::db::issue_pubkey_bind_challenge(&conn, AGENT, &padded, "test")
        .expect("issue challenge from accepted legacy spelling");
    assert_eq!(challenge.pubkey_b64, canonical);
    let signature = sign_bind_challenge(kp.private.as_ref().expect("private"), &challenge);
    let consumed = ai_memory::db::consume_pubkey_bind_challenge(&conn, AGENT, &challenge.nonce_b64)
        .expect("consume")
        .expect("live challenge");
    let proof = PossessionProof::verify_challenge_response(consumed, AGENT, &padded, &signature)
        .expect("proof tuple canonicalizes without changing signed transcript");
    ai_memory::db::bind_agent_pubkey(&conn, AGENT, &padded, proof).expect("bind padded alias");
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, AGENT).expect("read"),
        Some(canonical.clone())
    );
    let history = ai_memory::db::agent_pubkey_versions(&conn, AGENT).expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].version, 1);
    assert_eq!(history[0].pubkey_b64, canonical);
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
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &kp).expect("initial bind");
    let original_bound_at = ai_memory::db::agent_pubkey_versions(&conn, AGENT)
        .expect("initial history")[0]
        .bound_at
        .clone();
    std::thread::sleep(std::time::Duration::from_millis(5));
    for _ in 0..2 {
        ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &kp).expect("bind");
    }
    let history = ai_memory::db::agent_pubkey_versions(&conn, AGENT).expect("history");
    assert_eq!(
        history.len(),
        1,
        "re-asserting the live key must not record a rotation that did not happen"
    );
    assert_eq!(
        history[0].bound_at, original_bound_at,
        "same-key reassertion must not move the historical validity boundary"
    );
    let title = ai_memory::models::agent_registration_title(AGENT);
    let flat_bound_at: String = conn
        .query_row(
            "SELECT json_extract(metadata, '$.pubkey_bound_at') FROM memories
             WHERE namespace = '_agents' AND title = ?1",
            [title],
            |row| row.get(0),
        )
        .expect("flat projection bound_at");
    assert_eq!(flat_bound_at, original_bound_at);
}

/// The issue's exact attack: an authenticated administrator proves possession
/// of a key THEY control and tries to replace another agent's anchored key.
/// Candidate possession is true, but target-agent authorization is absent.
#[test]
fn admin_owned_candidate_cannot_replace_another_agents_key_3464() {
    let (_f, conn) = open_db();
    register(&conn, VICTIM);
    let victim = keypair(VICTIM);
    let attacker = keypair("ai:admin-owned-candidate-3464");
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, VICTIM, &victim).expect("bootstrap");

    let proof = ai_memory::db::prove_possession_with_conn(
        &conn,
        VICTIM,
        attacker.private.as_ref().expect("private"),
    )
    .expect("attacker genuinely possesses candidate key");
    let error = ai_memory::db::bind_agent_pubkey(&conn, VICTIM, &attacker.public_base64(), proof)
        .expect_err("candidate possession cannot substitute for victim authorization");
    assert!(
        error
            .downcast_ref::<ai_memory::identity::pubkey_bind::BindProofError>()
            .is_some(),
        "refusal must remain typed: {error:#}"
    );
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, VICTIM).expect("read"),
        Some(victim.public_base64()),
        "the victim's live key must remain unchanged"
    );
    assert_eq!(
        ai_memory::db::agent_pubkey_versions(&conn, VICTIM)
            .expect("history")
            .len(),
        1,
        "a refused hijack must not append or close history"
    );
}

#[test]
fn revoked_identity_cannot_be_reopened_by_candidate_possession_3464() {
    let (_f, conn) = open_db();
    register(&conn, VICTIM);
    let victim = keypair(VICTIM);
    let attacker = keypair("ai:post-revoke-attacker-3464");
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, VICTIM, &victim).expect("bootstrap");
    ai_memory::db::revoke_agent_pubkey(&conn, VICTIM).expect("revoke");

    let error = ai_memory::db::bind_agent_pubkey_with_keypair(&conn, VICTIM, &attacker)
        .expect_err("closed history must require lineage recovery");
    assert!(
        error
            .downcast_ref::<ai_memory::identity::pubkey_bind::BindProofError>()
            .is_some(),
        "refusal must remain typed: {error:#}"
    );
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, VICTIM).expect("read"),
        None
    );
}

#[test]
fn competing_bootstraps_admit_exactly_one_key_3464() {
    let file = tempfile::NamedTempFile::new().expect("tempfile");
    let path = file.path().to_path_buf();
    let seed = ai_memory::db::open(&path).expect("open seed");
    register(&seed, VICTIM);
    let first = keypair("ai:bootstrap-race-a-3464");
    let second = keypair("ai:bootstrap-race-b-3464");
    let first_key = first.public_base64();
    let second_key = second.public_base64();
    let first_proof = ai_memory::db::prove_possession_with_conn(
        &seed,
        VICTIM,
        first.private.as_ref().expect("private"),
    )
    .expect("first proof");
    let second_proof = ai_memory::db::prove_possession_with_conn(
        &seed,
        VICTIM,
        second.private.as_ref().expect("private"),
    )
    .expect("second proof");
    drop(seed);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let spawn =
        |key: String, proof: PossessionProof, barrier: std::sync::Arc<std::sync::Barrier>| {
            let path = path.clone();
            std::thread::spawn(move || {
                let conn = ai_memory::db::open(&path).expect("open contender");
                conn.execute_batch("PRAGMA recursive_triggers=ON")
                    .expect("exercise bootstrap race with recursive triggers enabled");
                barrier.wait();
                ai_memory::db::bind_agent_pubkey(&conn, VICTIM, &key, proof).is_ok()
            })
        };
    let a = spawn(first_key.clone(), first_proof, barrier.clone());
    let b = spawn(second_key.clone(), second_proof, barrier.clone());
    barrier.wait();
    let admitted = usize::from(a.join().expect("first contender"))
        + usize::from(b.join().expect("second contender"));
    assert_eq!(admitted, 1, "the storage transaction admits one bootstrap");

    let check = ai_memory::db::open(&path).expect("open check");
    let history = ai_memory::db::agent_pubkey_versions(&check, VICTIM).expect("history");
    assert_eq!(history.len(), 1, "the loser leaves no ledger mutation");
    assert!(
        history[0].pubkey_b64 == first_key || history[0].pubkey_b64 == second_key,
        "the sole anchor is one of the contending keys"
    );
    assert_eq!(
        ai_memory::db::agent_pubkey(&check, VICTIM).expect("flat"),
        Some(history[0].pubkey_b64.clone()),
        "flat key and history commit atomically"
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
    let signed_before_rotation = ai_memory::models::Memory {
        id: "history-reverify-sqlite-3464".to_string(),
        namespace: "identity/history".to_string(),
        title: "signed before key rotation".to_string(),
        content: "the old key remains the durable provenance anchor".to_string(),
        created_at: during_k1.clone(),
        updated_at: during_k1.clone(),
        metadata: serde_json::json!({"agent_id": AGENT}),
        ..ai_memory::models::Memory::default()
    };
    let old_signature =
        ai_memory::identity::attest::sign_memory_write(&kp1, &signed_before_rotation, AGENT)
            .expect("sign historical envelope with k1");
    std::thread::sleep(std::time::Duration::from_millis(5));
    rotate_with_lineage(&conn, AGENT, &kp1, &kp2);

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

    // Surface-level re-verification: the historical resolver admits the old
    // signature, while substituting the NEW current key for the SAME old
    // timestamp is a forgery refusal.
    let historical = ai_memory::db::agent_pubkey_for_attestation_at(&conn, AGENT, &during_k1)
        .expect("historical lookup");
    assert!(historical.history_exists);
    assert_eq!(
        historical.candidate_pubkeys_b64,
        [kp1.public_base64(), kp2.public_base64()],
        "near rotation both keys are eligible until the signature disambiguates"
    );
    assert_eq!(
        ai_memory::identity::attest::resolve_historical_write_attest_level(
            &signed_before_rotation,
            AGENT,
            Some(&historical),
            Some(&old_signature),
            false,
        )
        .expect("old envelope verifies under its historical anchor"),
        ai_memory::identity::verify::AttestLevel::AgentAttested
    );
    assert!(
        ai_memory::identity::attest::resolve_write_attest_level(
            &signed_before_rotation,
            AGENT,
            Some(&kp2.public_base64()),
            Some(&old_signature),
            false,
        )
        .is_err(),
        "the new current key must not be substituted for an old envelope"
    );

    // ...and the current instant resolves to k2.
    let at_now = ai_memory::db::agent_pubkey_at(&conn, AGENT, &now())
        .expect("as-of lookup")
        .expect("k2 is live now");
    assert_eq!(at_now.pubkey_b64, kp2.public_base64());
}

#[test]
fn sqlite_skew_boundary_reverification_cryptographically_selects_one_key_3464() {
    let (_f, conn) = open_db();
    register(&conn, AGENT);
    let old = keypair(AGENT);
    let next = keypair(AGENT);
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &old).expect("bind old");
    std::thread::sleep(std::time::Duration::from_millis(2));
    rotate_with_lineage(&conn, AGENT, &old, &next);
    let history = ai_memory::db::agent_pubkey_versions(&conn, AGENT).expect("history");
    let boundary =
        chrono::DateTime::parse_from_rfc3339(&history[1].bound_at).expect("rotation boundary");
    let old_bound =
        chrono::DateTime::parse_from_rfc3339(&history[0].bound_at).expect("old-key boundary");
    let exact_lower = ai_memory::db::agent_pubkey_for_attestation_at(
        &conn,
        AGENT,
        &(old_bound - chrono::Duration::seconds(300)).to_rfc3339(),
    )
    .expect("exact expanded lower endpoint");
    assert_eq!(exact_lower.candidate_pubkeys_b64, [old.public_base64()]);
    let outside_lower = ai_memory::db::agent_pubkey_for_attestation_at(
        &conn,
        AGENT,
        &(old_bound - chrono::Duration::seconds(300) - chrono::Duration::microseconds(1))
            .to_rfc3339(),
    )
    .expect("outside expanded lower endpoint");
    assert!(outside_lower.candidate_pubkeys_b64.is_empty());
    let exact_old_upper = ai_memory::db::agent_pubkey_for_attestation_at(
        &conn,
        AGENT,
        &(boundary + chrono::Duration::seconds(300)).to_rfc3339(),
    )
    .expect("exact old-key upper endpoint");
    assert_eq!(
        exact_old_upper.candidate_pubkeys_b64,
        [next.public_base64()],
        "the old key's superseded_at + 300s endpoint is exclusive"
    );

    for (stamp, signer, label) in [
        (
            boundary - chrono::Duration::seconds(1),
            &next,
            "slow new key",
        ),
        (
            boundary + chrono::Duration::seconds(1),
            &old,
            "fast old key",
        ),
    ] {
        let created_at =
            ai_memory::identity::attest::canonicalize_attested_created_at(&stamp.to_rfc3339())
                .expect("canonical skewed timestamp");
        let mem = ai_memory::models::Memory {
            id: format!("skew-{label}"),
            namespace: "identity/history".to_string(),
            title: label.to_string(),
            content: "clock skew must not orphan an admitted signature".to_string(),
            created_at: created_at.clone(),
            updated_at: created_at.clone(),
            metadata: serde_json::json!({"agent_id": AGENT}),
            ..ai_memory::models::Memory::default()
        };
        let signature = ai_memory::identity::attest::sign_memory_write(signer, &mem, AGENT)
            .expect("sign skewed envelope");
        let candidates = ai_memory::db::agent_pubkey_for_attestation_at(&conn, AGENT, &created_at)
            .expect("resolve skew-expanded candidates");
        assert_eq!(candidates.candidate_pubkeys_b64.len(), 2, "{label}");
        assert_eq!(
            ai_memory::identity::attest::resolve_historical_write_attest_level(
                &mem,
                AGENT,
                Some(&candidates),
                Some(&signature),
                false,
            )
            .expect("signature selects its actual key"),
            ai_memory::identity::verify::AttestLevel::AgentAttested,
            "{label}"
        );
    }
}

#[test]
fn sqlite_historical_lookup_allows_flat_only_without_history_3464() {
    let (_f, conn) = open_db();
    let agent = "ai:legacy-flat-3464";
    register(&conn, agent);
    // Model a legacy pre-v97 image. Current generic writes cannot create this
    // state, but the reader must retain compatibility during upgrade.
    conn.execute_batch(
        "DROP TRIGGER agent_pubkey_history_authoritative_insert_v97;
         DROP TRIGGER agent_pubkey_history_authoritative_update_v97;",
    )
    .expect("simulate pre-v97 database without authoritative triggers");
    conn.execute(
        "UPDATE memories SET metadata = json_set(metadata, '$.agent_pubkey', 'legacy-flat')
         WHERE namespace = ?1 AND title = ?2",
        rusqlite::params![
            ai_memory::models::AGENTS_NAMESPACE,
            ai_memory::models::agent_registration_title(agent)
        ],
    )
    .expect("seed legacy flat key");
    let resolved =
        ai_memory::db::agent_pubkey_for_attestation_at(&conn, agent, "2025-01-01T00:00:00+00:00")
            .expect("legacy lookup");
    assert!(!resolved.history_exists);
    assert_eq!(resolved.candidate_pubkeys_b64, ["legacy-flat"]);
}

#[test]
fn sqlite_future_history_refuses_rotation_revoke_and_retired_key_reuse_3464() {
    use base64::Engine as _;

    let (_f, conn) = open_db();
    register(&conn, AGENT);
    let old = keypair(AGENT);
    let next = keypair(AGENT);
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &old).expect("bind old");
    rotate_with_lineage(&conn, AGENT, &old, &next);

    let before = ai_memory::db::agent_pubkey_versions(&conn, AGENT).expect("history before reuse");
    let padded_old = base64::engine::general_purpose::STANDARD.encode(old.public.to_bytes());
    let err = ai_memory::db::append_succession(&conn, AGENT, &next, &padded_old, None)
        .expect_err("a retired key can never become live again");
    assert!(err.to_string().contains("reactivate"), "got: {err}");
    assert_eq!(
        ai_memory::db::agent_pubkey_versions(&conn, AGENT).expect("history after reuse"),
        before,
        "reuse refusal must occur before closing the current head"
    );

    let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    conn.execute(
        "UPDATE agent_pubkey_history SET bound_at = ?2 WHERE agent_id = ?1 AND superseded_at IS NULL",
        rusqlite::params![AGENT, future],
    )
    .expect("seed future-stamped current history");
    let history_before =
        ai_memory::db::agent_pubkey_versions(&conn, AGENT).expect("future history");
    let flat_before = ai_memory::db::agent_pubkey(&conn, AGENT).expect("flat before");
    let successor = keypair(AGENT);
    assert!(
        ai_memory::db::append_succession(&conn, AGENT, &next, &successor.public_base64(), None)
            .is_err(),
        "rotation must refuse a non-monotonic wall-clock stamp"
    );
    assert!(
        ai_memory::db::revoke_agent_pubkey(&conn, AGENT).is_err(),
        "revoke must refuse a non-monotonic wall-clock stamp"
    );
    assert_eq!(
        ai_memory::db::agent_pubkey_versions(&conn, AGENT).unwrap(),
        history_before
    );
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, AGENT).unwrap(),
        flat_before
    );
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
    assert_eq!(
        BindAuthority::GuardianRecovery.as_str(),
        "guardian_recovery"
    );
}

// ---------------------------------------------------------------------
// The challenge is DURABLE, and single-use is decided by the storage
// engine — not by an in-process cache.
// ---------------------------------------------------------------------

/// v1.0.0 #3464 — a challenge authorizes at most ONE proof attempt.
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
    let signature = sign_bind_challenge(kp.private.as_ref().expect("private"), &issued);
    let taken = ai_memory::db::consume_pubkey_bind_challenge(&conn, AGENT, &issued.nonce_b64)
        .expect("consume")
        .expect("fresh");
    // A caller trying to bind a DIFFERENT key against this challenge is
    // refused by the mismatch check, not by the signature check.
    let other = keypair("ai:other-3464");
    assert!(
        PossessionProof::verify_challenge_response(
            taken,
            AGENT,
            &other.public_base64(),
            &signature,
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
    let signature = sign_bind_challenge(kp.private.as_ref().expect("private"), &issued);
    // ...answered against a DIFFERENT connection, as a load balancer would.
    let taken = ai_memory::db::consume_pubkey_bind_challenge(&daemon_b, AGENT, &issued.nonce_b64)
        .expect("consume on daemon B")
        .expect(
            "#3464: a challenge issued by one daemon MUST be answerable at another — \
             several daemons share one store on the certified tier, so an in-process \
             cache would fail this bind closed with no in-product remedy",
        );
    let proof =
        PossessionProof::verify_challenge_response(taken, AGENT, &kp.public_base64(), &signature)
            .expect("the cross-daemon answer verifies");
    ai_memory::db::bind_agent_pubkey(&daemon_b, AGENT, &kp.public_base64(), proof)
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
