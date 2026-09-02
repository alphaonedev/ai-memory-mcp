// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! v1.0.0 #2941 — a re-register must never silently unbind an agent's key.
//!
//! `storage::register_agent` is documented as "register or refresh" and
//! rebuilds the registration row's `metadata` from scratch with NO
//! `agent_pubkey`, then hands it to `insert()`, whose `ON CONFLICT … DO
//! UPDATE` overwrote `metadata` wholesale while preserving only
//! `agent_id`, `derived_from` and `consolidated_from_agents`. So ANY
//! idempotent re-register — MCP `memory_agent`, `POST /agents`, the SAL
//! trait, the CLI — silently erased the bound public key on BOTH backends.
//!
//! The end-state is a durable PROVENANCE DOWNGRADE, and the default
//! posture is the dangerous one:
//!
//!   * strict (`AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1`) — every later
//!     signed write 403s. Loud, and the failure mode #2941 was filed for.
//!   * DEFAULT permissive — a genuinely signed write is persisted as
//!     `claimed` instead of `agent_attested`, with no error, no WARN and
//!     no counter. Nothing downstream can tell the difference between
//!     "this agent never signed" and "this agent signed and we lost the
//!     key we needed to prove it".
//!
//! The fix has two layers and this binary pins both:
//!
//!   1. `register_agent` carries the bound-key PAIR through its existing
//!      pre-read, on both backends, so the metadata it re-stores is
//!      already correct.
//!   2. the upsert preserve-list itself is a reserved-key SET
//!      ([`ai_memory::RESERVED_UPSERT_METADATA_KEYS`]) that now covers the
//!      pair. This is the load-bearing half: it is evaluated INSIDE the
//!      conflicting statement, so a `bind-key` landing between any
//!      caller's pre-read and its upsert cannot be clobbered either.
//!
//! Layer 2 is only sound while both backends preserve the SAME set, so
//! the first two tests here are the anti-drift gate for that.

use base64::Engine as _;
use serde_json::json;
use tempfile::NamedTempFile;

use ai_memory::config::ResolvedTtl;

/// The canonical element list, as spliced into both backends' SQL.
fn canonical_sql_list() -> &'static str {
    ai_memory::reserved_upsert_metadata_keys_sql!()
}

/// Parse the SQL element list back into the keys it names.
fn parse_sql_list(list: &str) -> Vec<String> {
    list.split(',')
        .map(|element| element.trim().trim_matches('\'').to_string())
        .collect()
}

/// The SQL list and the typed set are two spellings of one thing, and the
/// SQL half is what actually governs the durable write. Pin them together
/// so a key added to one but not the other cannot merge.
#[test]
fn reserved_upsert_metadata_keys_sql_matches_the_typed_set() {
    let from_sql = parse_sql_list(canonical_sql_list());
    let typed: Vec<String> = ai_memory::RESERVED_UPSERT_METADATA_KEYS
        .iter()
        .copied()
        .map(String::from)
        .collect();
    assert_eq!(
        from_sql, typed,
        "the SQL preserve-list and RESERVED_UPSERT_METADATA_KEYS must name \
         exactly the same keys in the same order"
    );
    assert!(
        typed.iter().any(|k| k == "agent_pubkey") && typed.iter().any(|k| k == "pubkey_bound_at"),
        "#2941 — the agent-registration pubkey PAIR must be preserved: {typed:?}"
    );
}

/// Both backends must preserve the SAME set: a key preserved on sqlite but
/// dropped on postgres — or on one upsert funnel but not its siblings — is a
/// silent provenance divergence that only ever surfaces as an unexplained
/// attestation downgrade in production.
///
/// The set is open-coded in THIRTEEN SQL literals (3 sqlite: the insert
/// funnel, the `memory_update` metadata patch, the newer-wins federation
/// merge; 10 postgres). Restructuring all thirteen to splice the shared text
/// at compile time would touch far more of the hot write path than this fix
/// warrants, so this scan is what holds them in lockstep with the crate SSOT.
#[test]
fn both_backends_preserve_the_same_reserved_key_set() {
    let expected = canonical_sql_list();
    let mut total = 0_usize;

    for (label, src, marker) in [
        (
            "sqlite",
            include_str!("../src/storage/mod.rs"),
            "WHERE key IN (",
        ),
        (
            "postgres",
            include_str!("../src/store/postgres.rs"),
            "WHERE prov.k IN (",
        ),
    ] {
        let sites: Vec<&str> = src.match_indices(marker).map(|(i, _)| &src[i..]).collect();
        assert!(
            !sites.is_empty(),
            "{label}: expected at least one upsert preserve-clause"
        );
        for (n, site) in sites.iter().enumerate() {
            let rendered = site
                .strip_prefix(marker)
                .and_then(|rest| rest.split_once(')'))
                .map(|(list, _)| list)
                .unwrap_or_default();
            assert_eq!(
                rendered, expected,
                "{label} preserve-list site #{n} has drifted from the crate SSOT \
                 (RESERVED_UPSERT_METADATA_KEYS)"
            );
        }
        total += sites.len();
    }

    assert!(
        total >= 13,
        "expected every known preserve-site to be scanned, saw {total}"
    );
}

fn sign_envelope(
    kp: &ai_memory::identity::keypair::AgentKeypair,
    agent_id: &str,
    namespace: &str,
    title: &str,
    content: &str,
    created_at: &str,
) -> String {
    let content_hash = ai_memory::identity::attest::content_sha256(content);
    let write = ai_memory::identity::sign::SignableWrite {
        agent_id,
        namespace,
        title,
        kind: ai_memory::models::MemoryKind::Observation.as_str(),
        created_at,
        content_sha256: &content_hash,
    };
    let sig = ai_memory::identity::sign::sign_write(kp, &write).expect("sign");
    base64::engine::general_purpose::STANDARD.encode(sig)
}

fn bound_pubkey(conn: &rusqlite::Connection, agent_id: &str) -> Option<String> {
    let title = ai_memory::models::agent_registration_title(agent_id);
    conn.query_row(
        "SELECT json_extract(metadata, '$.agent_pubkey') FROM memories \
         WHERE namespace = ?1 AND title = ?2",
        rusqlite::params![ai_memory::models::AGENTS_NAMESPACE, &title],
        |r| r.get::<_, Option<String>>(0),
    )
    .expect("read registry row")
}

/// THE #2941 REGRESSION (sqlite): register → bind → RE-register → the key
/// must still be bound, and a signed write must still land
/// `agent_attested`.
///
/// Pre-fix the re-register wiped `metadata.agent_pubkey`, so this test's
/// third assertion saw `claimed` — the silent permissive-posture downgrade
/// — rather than an error.
#[test]
fn reregister_preserves_bound_pubkey_and_signed_store_stays_agent_attested() {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");

    let agent_id = "ai:rereg";
    let kp = ai_memory::identity::keypair::generate(agent_id).expect("keypair");
    let pubkey = kp.public_base64();

    ai_memory::storage::register_agent(&conn, agent_id, "nhi", &[]).expect("register");
    ai_memory::storage::bind_agent_pubkey_with_keypair(&conn, agent_id, &kp).expect("bind");
    assert_eq!(
        bound_pubkey(&conn, agent_id).as_deref(),
        Some(pubkey.as_str()),
        "precondition: the bind must have landed"
    );
    let registered_at: Option<String> = conn
        .query_row(
            "SELECT json_extract(metadata, '$.registered_at') FROM memories \
             WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![
                ai_memory::models::AGENTS_NAMESPACE,
                &ai_memory::models::agent_registration_title(agent_id)
            ],
            |r| r.get(0),
        )
        .expect("read registered_at");

    // The idempotent refresh every enrollment path performs on reconnect.
    ai_memory::storage::register_agent(&conn, agent_id, "nhi", &["recall".to_string()])
        .expect("re-register");

    assert_eq!(
        bound_pubkey(&conn, agent_id).as_deref(),
        Some(pubkey.as_str()),
        "#2941 — an idempotent re-register must NOT unbind the agent's key"
    );
    let bound_at: Option<String> = conn
        .query_row(
            "SELECT json_extract(metadata, '$.pubkey_bound_at') FROM memories \
             WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![
                ai_memory::models::AGENTS_NAMESPACE,
                &ai_memory::models::agent_registration_title(agent_id)
            ],
            |r| r.get(0),
        )
        .expect("read pubkey_bound_at");
    assert!(
        bound_at.is_some(),
        "#2941 — the bind stamp is half of the key PAIR and must survive too"
    );
    let registered_at_after: Option<String> = conn
        .query_row(
            "SELECT json_extract(metadata, '$.registered_at') FROM memories \
             WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![
                ai_memory::models::AGENTS_NAMESPACE,
                &ai_memory::models::agent_registration_title(agent_id)
            ],
            |r| r.get(0),
        )
        .expect("read registered_at after");
    assert_eq!(
        registered_at, registered_at_after,
        "the pre-existing registered_at preservation must be unaffected"
    );

    // The end-to-end consequence: a genuinely signed write must still be
    // provable, i.e. land `agent_attested` and not the silent `claimed`.
    let title = "post-rereg-signed";
    let content = "Body of the signed write issued after an idempotent re-register.";
    let namespace = "attest-rereg";
    // #3422 — the attestation funnel accepts ONLY the canonical
    // storage-stable rendering (UTC, `+00:00`, microsecond-truncated):
    // it is the one form both backends return byte-for-byte, so the
    // signature stays re-derivable from the persisted row.
    let created_at = ai_memory::identity::attest::now_attestable_rfc3339();
    let sig_b64 = sign_envelope(&kp, agent_id, namespace, title, content, &created_at);
    let ttl = ResolvedTtl::default();
    let params = json!({
        "title": title,
        "content": content,
        "namespace": namespace,
        "tier": "mid",
        "agent_id": agent_id,
        "signature": sig_b64,
        "created_at": created_at,
    });
    let resp = ai_memory::mcp::tools::handle_store_for_tests(
        &conn, &db_path, &params, None, None, None, &ttl, false, None, None,
    )
    .expect("valid signed write must be accepted");

    let attest: Option<String> = conn
        .query_row(
            "SELECT json_extract(metadata, '$.attest_level') FROM memories \
             WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![namespace, title],
            |r| r.get(0),
        )
        .expect("read persisted attest_level");
    assert_eq!(
        attest.as_deref(),
        Some("agent_attested"),
        "#2941 — after a re-register a signed write must still prove out as \
         agent_attested, never silently downgrade to claimed; resp={resp}"
    );
}

/// Live-Postgres twin of the regression above. Gated on
/// `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset.
#[cfg(feature = "sal-postgres")]
mod pg {
    use ai_memory::models::AgentRegistration;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    async fn connect() -> Option<PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
        Some(
            PostgresStore::connect(&url)
                .await
                .expect("connect postgres"),
        )
    }

    #[tokio::test]
    async fn pg_reregister_preserves_bound_pubkey() {
        let Some(store) = connect().await else {
            eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let agent_id = format!("ai:rereg-{}", uuid::Uuid::new_v4());
        let ctx = CallerContext::for_agent(agent_id.clone());
        let kp = ai_memory::identity::keypair::generate(&agent_id).expect("keypair");
        let pubkey = kp.public_base64();

        let reg = AgentRegistration {
            agent_id: agent_id.clone(),
            agent_type: "nhi".to_string(),
            capabilities: Vec::new(),
            registered_at: String::new(),
            last_seen_at: String::new(),
        };
        store.register_agent(&ctx, &reg).await.expect("register");
        let proof = ai_memory::store::prove_possession_via_store(
            &store,
            &ctx,
            &agent_id,
            kp.private.as_ref().expect("generated private key"),
        )
        .await
        .expect("prove possession");
        store
            .bind_agent_pubkey(&ctx, &agent_id, &pubkey, &proof)
            .await
            .expect("bind");
        assert_eq!(
            store.agent_pubkey(&agent_id).await.expect("read bound key"),
            Some(pubkey.clone()),
            "precondition: the bind must have landed"
        );

        // The idempotent refresh — the exact call that silently unbound.
        let refreshed = AgentRegistration {
            capabilities: vec!["recall".to_string()],
            ..reg
        };
        store
            .register_agent(&ctx, &refreshed)
            .await
            .expect("re-register");

        assert_eq!(
            store.agent_pubkey(&agent_id).await.expect("read bound key"),
            Some(pubkey),
            "#2941 — an idempotent re-register must NOT unbind the agent's key \
             on the postgres backend either"
        );
    }
}
