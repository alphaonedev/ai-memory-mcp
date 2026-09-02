// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]

//! #3145 — backend PARITY for `MemoryStore::agent_pubkey`.
//!
//! The defect was an ASYMMETRY: the postgres twin
//! (`PostgresStore::agent_pubkey`) already used `fetch_optional` + `map_err`
//! and propagated a real fault, while the sqlite twin
//! (`SqliteStore::agent_pubkey` → `db::agent_pubkey`) collapsed every error
//! into `Ok(None)` = "no bound key". A backend-blind caller
//! (`identity::attest::stamp_attestation_async`) therefore recorded DIFFERENT
//! durable provenance for the same fault depending on the backend.
//!
//! Both backends must satisfy the same three-row contract:
//!
//! | state                        | result        |
//! |------------------------------|---------------|
//! | agent registered + bound key | `Ok(Some(k))` |
//! | no such agent / no bound key | `Ok(None)`    |
//! | backend fault                | `Err(_)`      |
//!
//! Only the third row was broken, and only on sqlite.
//!
//! The injected fault necessarily differs per backend — the fault SURFACES
//! differ — but the asserted contract does not: sqlite loses the `memories`
//! relation out from under its live connection; postgres has its pool closed.
//! Both are real, deterministic backend faults with no sleeps and no races.

use ai_memory::store::MemoryStore;

const AGENT: &str = "ai:parity-3145";
const UNBOUND: &str = "ai:never-registered-parity-3145";

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_agent_pubkey_contract_3145() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("db.sqlite");
    let kp = ai_memory::identity::keypair::generate(AGENT).expect("generate");
    {
        let conn = ai_memory::db::open(&path).expect("db::open");
        ai_memory::db::register_agent(&conn, AGENT, "nhi", &[]).expect("register");
        ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &kp).expect("bind");
    }
    let store = ai_memory::store::sqlite::SqliteStore::open(&path).expect("SqliteStore::open");

    assert_eq!(
        store.agent_pubkey(AGENT).await.expect("bound lookup"),
        Some(kp.public_base64()),
        "row 1: bound agent resolves to its key"
    );
    assert_eq!(
        store.agent_pubkey(UNBOUND).await.expect("unbound lookup"),
        None,
        "row 2: an unregistered agent is Ok(None), not an error"
    );

    // Row 3 — a real backend fault. Drop the relation the lookup reads from a
    // side connection; the store's live connection then fails the query
    // ("no such table: memories"). Pre-#3145 this returned Ok(None).
    {
        let side = rusqlite::Connection::open(&path).expect("side connection");
        side.execute_batch("DROP TABLE memories")
            .expect("drop memories");
    }
    let err = store
        .agent_pubkey(AGENT)
        .await
        .expect_err("row 3: a backend fault is Err — NEVER Ok(None)");
    assert!(
        format!("{err:#}").contains(AGENT),
        "the error must name the agent whose key could not be resolved, got: {err:#}"
    );
}

/// Postgres twin of the same contract. `#[ignore]`d + gated on
/// `AI_MEMORY_TEST_POSTGRES_URL` per the house convention; run with
/// `--features sal-postgres -- --include-ignored`.
#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL"]
async fn postgres_agent_pubkey_contract_3145() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!(
            "skipping postgres_agent_pubkey_contract_3145: AI_MEMORY_TEST_POSTGRES_URL unset"
        );
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres adapter");

    let agent = format!("{AGENT}-{}", uuid::Uuid::new_v4());
    let kp = ai_memory::identity::keypair::generate("ai:parity-3145").expect("generate");
    let ctx = ai_memory::store::CallerContext::for_agent(agent.clone());
    store
        .register_agent(
            &ctx,
            &ai_memory::models::AgentRegistration {
                agent_id: agent.clone(),
                agent_type: "nhi".to_string(),
                capabilities: Vec::new(),
                registered_at: chrono::Utc::now().to_rfc3339(),
                last_seen_at: chrono::Utc::now().to_rfc3339(),
            },
        )
        .await
        .expect("register");
    let proof = ai_memory::store::prove_possession_via_store(
        &store,
        &ctx,
        &agent,
        kp.private.as_ref().expect("generated private key"),
    )
    .await
    .expect("prove possession");
    store
        .bind_agent_pubkey(&ctx, &agent, &kp.public_base64(), &proof)
        .await
        .expect("bind");

    assert_eq!(
        store.agent_pubkey(&agent).await.expect("bound lookup"),
        Some(kp.public_base64()),
        "row 1: bound agent resolves to its key"
    );
    assert_eq!(
        store.agent_pubkey(UNBOUND).await.expect("unbound lookup"),
        None,
        "row 2: an unregistered agent is Ok(None), not an error"
    );

    // Row 3 — a real backend fault: the pool is gone. Done LAST because it
    // renders the store unusable.
    store.pool().close().await;
    assert!(
        store.agent_pubkey(&agent).await.is_err(),
        "row 3: a backend fault is Err — NEVER Ok(None)"
    );
}
