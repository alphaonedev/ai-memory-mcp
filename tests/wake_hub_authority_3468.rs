// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Durable v97 authority, public snapshot, audit and mint integration.

use ai_memory::identity::{hub_cache, keypair};
use ai_memory::wake_hub::delegation_verifier::{AllowlistCache, RootKeyResolver};
use base64::Engine as _;

const AGENT: &str = "ai:hub-authority-3468";

#[test]
fn sqlite_proven_root_exports_and_revocation_is_audited_and_removes_it() {
    let dir = tempfile::tempdir().unwrap();
    let conn = ai_memory::db::open(&dir.path().join("identity.db")).unwrap();
    ai_memory::db::register_agent(&conn, AGENT, "nhi", &[]).unwrap();
    let key = keypair::generate(AGENT).unwrap();
    let agents = vec![AGENT.to_owned()];
    assert!(
        hub_cache::derive_sqlite(&conn, &agents)
            .unwrap()
            .agents
            .is_empty()
    );
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &key).unwrap();
    let allowed = hub_cache::derive_sqlite(&conn, &agents).unwrap();
    assert_eq!(allowed.agents.len(), 1);
    assert_eq!(allowed.agents[0].pubkey_b64, key.public_base64());
    hub_cache::audit_sqlite(&conn, None, &allowed).unwrap();
    let path = dir.path().join("public.json");
    hub_cache::publish(&path, &allowed).unwrap();
    assert_eq!(
        AllowlistCache::load_from_file(&path)
            .unwrap()
            .resolve(AGENT)
            .unwrap()
            .pubkey,
        key.public
    );
    ai_memory::db::revoke_agent_pubkey(&conn, AGENT).unwrap();
    let revoked = hub_cache::derive_sqlite(&conn, &agents).unwrap();
    assert!(revoked.agents.is_empty());
    hub_cache::audit_sqlite(&conn, Some(&allowed), &revoked).unwrap();
    hub_cache::publish(&path, &revoked).unwrap();
    assert!(
        AllowlistCache::load_from_file(&path)
            .unwrap()
            .resolve(AGENT)
            .is_err()
    );
    for event in [hub_cache::HUB_ALLOW_EVENT, hub_cache::HUB_REVOKE_EVENT] {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                [event],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "{event}");
    }
    assert!(
        ai_memory::signed_events::verify_audit_trail(&conn, None, None)
            .unwrap()
            .chain_intact
    );
}

#[test]
fn sqlite_mint_requires_the_current_enrolled_key_and_writes_only_the_delegate_secret() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("identity.db");
    let keys = dir.path().join("keys");
    let conn = ai_memory::db::open(&db).unwrap();
    ai_memory::db::register_agent(&conn, AGENT, "nhi", &[]).unwrap();
    let key = keypair::generate(AGENT).unwrap();
    keypair::save(&key, &keys).unwrap();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut out = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);
    let bundle_path = dir.path().join("delegation.json");
    assert!(
        ai_memory::cli::identity_delegate::run(
            &db,
            None,
            &keys,
            AGENT,
            "a2a-hub",
            "hub",
            60,
            Some(&bundle_path),
            true,
            &mut out
        )
        .is_err()
    );
    assert!(!bundle_path.exists());
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, AGENT, &key).unwrap();
    ai_memory::cli::identity_delegate::run(
        &db,
        None,
        &keys,
        AGENT,
        "a2a-hub",
        "hub",
        60,
        Some(&bundle_path),
        true,
        &mut out,
    )
    .unwrap();
    let bundle: ai_memory::cli::identity_delegate::DelegationBundle =
        serde_json::from_slice(&std::fs::read(&bundle_path).unwrap()).unwrap();
    let root_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(key.private.as_ref().unwrap().to_bytes());
    assert_ne!(bundle.delegate_private_b64, root_secret);
    ai_memory::db::revoke_agent_pubkey(&conn, AGENT).unwrap();
    assert!(
        ai_memory::cli::identity_delegate::run(
            &db,
            None,
            &keys,
            AGENT,
            "a2a-hub",
            "hub",
            60,
            Some(&dir.path().join("revoked.json")),
            true,
            &mut out
        )
        .is_err()
    );
}

#[test]
fn expired_cache_and_future_cache_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.json");
    for seconds in [-61, 60] {
        let cache = ai_memory::wake_hub::delegation_verifier::AllowlistFile {
            version: ai_memory::wake_hub::delegation_verifier::ALLOWLIST_FILE_VERSION,
            refreshed_at: Some(
                (chrono::Utc::now() + chrono::Duration::seconds(seconds)).to_rfc3339(),
            ),
            agents: Vec::new(),
        };
        hub_cache::publish(&path, &cache).unwrap();
        assert!(AllowlistCache::load_from_file(&path).is_err());
    }
}

#[cfg(feature = "sal-postgres")]
/// The database segment of a `postgres://…/<db>?…` URL (empty when absent).
fn database_name(url: &str) -> &str {
    url.split('/')
        .next_back()
        .unwrap_or_default()
        .split('?')
        .next()
        .unwrap_or_default()
}

/// The port segment of a `postgres://user:pass@host:port/db` URL, if any.
fn port_of(url: &str) -> Option<u16> {
    let authority = url.split("//").nth(1)?.split('/').next()?;
    let host_port = authority.rsplit('@').next()?;
    host_port.rsplit(':').next()?.parse().ok()
}

/// The certified tier's port on both nodes; the `:9077` test-fleet daemon's
/// shared `ai_memory_test` database lives there and nowhere else.
const SHARED_LIVE_STORE_PORT: u16 = 5445;

/// True only for the shared live store: the `ai_memory_test` database on the
/// certified tier's port. A same-named database on any other port (the CI
/// coverage service container on :5432) is a throwaway and may be used.
fn is_shared_live_store(url: &str) -> bool {
    database_name(url) == "ai_memory_test" && port_of(url) == Some(SHARED_LIVE_STORE_PORT)
}

#[test]
fn shared_live_store_guard_cases() {
    assert!(is_shared_live_store(
        "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test?sslmode=verify-full"
    ));
    assert!(is_shared_live_store(
        "postgres://ai_memory:pw@localhost:5445/ai_memory_test"
    ));
    // CI coverage service container: same name, throwaway port.
    assert!(!is_shared_live_store(
        "postgres://ai_memory:ai_memory_test@127.0.0.1:5432/ai_memory_test"
    ));
    // Isolated lane / gate databases on the certified tier.
    assert!(!is_shared_live_store(
        "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_gate_tip4?sslmode=verify-full"
    ));
    assert!(!is_shared_live_store(
        "postgres://ai_memory:pw@127.0.0.1:5445/ai_memory_test_ci_123_x"
    ));
    assert_eq!(database_name("postgres://u:p@h:5445/db?x=1"), "db");
    assert_eq!(port_of("postgres://u:p@h:5445/db?x=1"), Some(5445));
    assert_eq!(port_of("postgres://u:p@h/db"), None);
}

#[tokio::test]
async fn postgres_proven_root_and_revocation_match_sqlite_and_audit_the_decisions() {
    use ai_memory::identity::pubkey_bind::{PossessionProof, sign_bind_challenge};
    use ai_memory::store::{CallerContext, MemoryStore as _};
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("live isolated PostgreSQL URL required; never skip");
    // v1.0.0 #3508 — the original assertion pinned the #3468 lane's OWN
    // database name (`ai_memory_codex_3468`), so this test could only ever
    // pass inside that one worktree: every other lane, the merge gate
    // (`ai_memory_gate_<n>`) and CI (`ai_memory_test_ci_<run>_*`) failed it on
    // an environment mismatch rather than on the behaviour under test. The
    // invariant it protects is "never run against the SHARED live store" (the
    // :9077 test-fleet daemon's `ai_memory_test`), so assert that instead —
    // it holds for every correctly isolated lane.
    // 2026-09-06 (final-tip campaign on 158c816a) — the NAME alone is not
    // the invariant either: the coverage workflow boots a throwaway
    // PostgreSQL service container whose database is also called
    // `ai_memory_test` (on :5432), and the name-only guard refused it. The
    // shared live store is the one on the certified tier's port (:5445);
    // `is_shared_live_store` keys on BOTH the name and that port, with the
    // cases pinned in `shared_live_store_guard_cases` below.
    assert!(
        !is_shared_live_store(&url),
        "refusing to run against the shared live store; point \
         AI_MEMORY_TEST_POSTGRES_URL at this lane's own isolated database"
    );
    assert!(
        !database_name(&url).is_empty(),
        "AI_MEMORY_TEST_POSTGRES_URL must name a database"
    );
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .unwrap();
    let agent = format!("{AGENT}-pg-{}", uuid::Uuid::new_v4());
    let ctx = CallerContext::for_agent(&agent);
    let now = chrono::Utc::now().to_rfc3339();
    store
        .register_agent(
            &ctx,
            &ai_memory::models::AgentRegistration {
                agent_id: agent.clone(),
                agent_type: "nhi".to_owned(),
                capabilities: Vec::new(),
                registered_at: now.clone(),
                last_seen_at: now,
            },
        )
        .await
        .unwrap();
    let key = keypair::generate(&agent).unwrap();
    let challenge = store
        .issue_pubkey_bind_challenge(&ctx, &agent, &key.public_base64(), &agent)
        .await
        .unwrap();
    let signature = sign_bind_challenge(key.private.as_ref().unwrap(), &challenge);
    let consumed = store
        .consume_pubkey_bind_challenge(&ctx, &agent, &challenge.nonce_b64)
        .await
        .unwrap()
        .unwrap();
    let proof = PossessionProof::verify_challenge_response(
        consumed,
        &agent,
        &key.public_base64(),
        &signature,
    )
    .unwrap();
    store
        .bind_agent_pubkey(&ctx, &agent, &key.public_base64(), proof)
        .await
        .unwrap();
    let agents = vec![agent.clone()];
    let allowed = store.derive_hub_cache(&agents).await.unwrap();
    assert_eq!(allowed.agents.len(), 1);
    assert_eq!(allowed.agents[0].pubkey_b64, key.public_base64());
    store.audit_hub_cache(None, &allowed).await.unwrap();
    store.revoke_agent_pubkey(&ctx, &agent).await.unwrap();
    let revoked = store.derive_hub_cache(&agents).await.unwrap();
    assert!(revoked.agents.is_empty());
    store
        .audit_hub_cache(Some(&allowed), &revoked)
        .await
        .unwrap();
    for event in [hub_cache::HUB_ALLOW_EVENT, hub_cache::HUB_REVOKE_EVENT] {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM signed_events WHERE agent_id = $1 AND event_type = $2",
        )
        .bind(&agent)
        .bind(event)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(count, 1, "{event}");
    }
}
