// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::items_after_statements)]
//! #2743 — `POST /api/v1/memories` on a POSTGRES-backed daemon must HONOR
//! `on_conflict`.
//!
//! The CONFIRMED backend-parity asymmetry: `create_memory_postgres` never
//! resolved `body.on_conflict`, so every single-create whose `(title,
//! namespace)` collided with a PRE-EXISTING stored row went straight to
//! `store_with_embedding`'s upsert arm and silently, unrecoverably OVERWROTE
//! the stored content (no pre-overwrite snapshot). Meanwhile the sqlite
//! single-create arm (`resolve_create_conflict_title`) AND both #2725 (CB-23)
//! bulk arms defaulted `on_conflict=error` (409 + `existing_id`) — so on
//! postgres the BULK path was STRICTER than the SINGLE-create path, which is
//! itself the tell.
//!
//! **R-203.** At the parent commit `default_collision_is_rejected_2743` fails
//! for the right reason: the collision returned `201 CREATED` and the stored
//! content was silently REPLACED (the out-of-band re-GET observed the second
//! write's body). `explicit_version_renames_2743` observed the title upserted
//! in place instead of being renamed. The `merge` cell is a CONTROL proving the
//! opt-in upsert path is unchanged.
//!
//! Counter / status assertions are ALWAYS paired with an out-of-band re-GET of
//! the stored row — a status-only assertion is precisely how the silent-
//! overwrite class hides (the response envelope is self-consistent and wrong).
//!
//! Gated on `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`; skips
//! cleanly otherwise. The file-level `#![cfg(feature = "sal-postgres")]` keeps
//! it out of the default `cargo test` build entirely, and the per-test runtime
//! `postgres_url()` guard early-returns (skip) when the URL is unset — so the
//! cells are NOT `#[ignore]`d (the Postgres feature gate runs `cargo test
//! --features sal-postgres` WITHOUT `--include-ignored`, so an `#[ignore]` cell
//! would silently self-skip in CI). Under the Postgres feature gate, which
//! compiles `sal-postgres` AND sets `AI_MEMORY_TEST_POSTGRES_URL`, they execute
//! for real. Mirrors `tests/g6_postgres_quota_enforcement_1795.rs`.

#![cfg(feature = "sal-postgres")]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use ai_memory::store::postgres::PostgresStore;
use serde_json::{Value, json};
use tokio::sync::{Mutex, Notify, RwLock};

mod common;
use common::{DAEMON_READY_TIMEOUT, free_port, postgres_url, wait_for_http_ready};

/// #1985 — pin this binary to the explicit permissive agent-attestation
/// opt-out; the v1.0 HTTP-direct default is REQUIRED and would reject the
/// unsigned store fixtures (needed to SEED the pre-existing row) before the
/// `on_conflict` disposition under test runs. Mirrors
/// `tests/bulk_on_conflict_2725.rs::permissive_attestation_for_tests`.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before the caller issues any gated store. This is
    // NOT a `$HOME` mutation, so the #2146 test-env-lock gate does not apply.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

async fn build_postgres_app_state(url: &str) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let path = std::path::PathBuf::from(":memory:");
    let db: Db = Arc::new(Mutex::new((conn, path, ResolvedTtl::default(), true)));
    let store: Arc<dyn MemoryStore> = Arc::new(
        PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    );
    AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Postgres,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    }
}

async fn spawn_daemon(
    url: &str,
) -> (
    String,
    Arc<Notify>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    permissive_attestation_for_tests();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let app_state = build_postgres_app_state(url).await;
    let shutdown = Arc::new(Notify::new());
    let shutdown_for_daemon = shutdown.clone();
    let addr_for_daemon = addr.clone();
    let handle = tokio::spawn(async move {
        ai_memory::daemon_runtime::serve_http_with_shutdown(
            &addr_for_daemon,
            api_key_state,
            app_state,
            shutdown_for_daemon,
        )
        .await
    });
    wait_for_http_ready(&addr, DAEMON_READY_TIMEOUT)
        .await
        .expect("postgres-backed serve never became ready");
    (format!("http://{addr}"), shutdown, handle)
}

/// POST a single create; returns the `(status, body)` pair. `on_conflict` is
/// omitted from the body when `None` so the compiled `error` default applies.
async fn http_store(
    client: &reqwest::Client,
    base: &str,
    agent: &str,
    ns: &str,
    title: &str,
    content: &str,
    on_conflict: Option<&str>,
) -> (reqwest::StatusCode, Value) {
    let mut body = json!({
        "tier": "long", "namespace": ns, "title": title,
        "content": content, "tags": [], "priority": 5, "confidence": 1.0,
        "source": "api", "metadata": {}, "agent_id": agent,
    });
    if let Some(oc) = on_conflict {
        body["on_conflict"] = json!(oc);
    }
    let resp = client
        .post(format!("{base}/api/v1/memories"))
        .header("X-Agent-Id", agent)
        .json(&body)
        .send()
        .await
        .expect("store POST");
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(json!({}));
    (status, v)
}

/// Out-of-band re-read of the stored row's content by id — the load-bearing
/// data-integrity check (never trust the write's own echo).
async fn http_get_content(client: &reqwest::Client, base: &str, agent: &str, id: &str) -> String {
    let resp = client
        .get(format!("{base}/api/v1/memories/{id}"))
        .header("X-Agent-Id", agent)
        .send()
        .await
        .expect("get POST");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "#2743: stored row must still be readable by id after the conflict op"
    );
    let v: Value = resp.json().await.expect("get body");
    // GET /api/v1/memories/{id} WRAPS the row: `{"memory": mem, "links": [...]}`
    // (src/handlers/memories.rs — `Json(json!({"memory": mem, "links": edges}))`),
    // so the content is under `["memory"]`, NOT at the top level (the POST-create
    // 201 serializes `mem` at the top level, which is why the `id`/`title` reads
    // in the cells above stay top-level — verified against src/handlers/create.rs).
    v["memory"]["content"]
        .as_str()
        .expect("stored row content")
        .to_string()
}

/// Default (`on_conflict` absent) → the DEFAULT `error` disposition: a
/// pre-existing `(title, namespace)` collision must 409 with `existing_id` and
/// must NOT overwrite the stored content.
#[tokio::test(flavor = "multi_thread")]
async fn default_collision_is_rejected_2743() {
    let Some(url) = postgres_url() else {
        eprintln!("skipping default_collision_is_rejected_2743: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let (base, shutdown, handle) = spawn_daemon(&url).await;
    let client = reqwest::Client::new();
    let suffix = uuid::Uuid::new_v4();
    let agent = format!("c2743-err-{suffix}");
    let ns = format!("c2743-err-ns-{suffix}");
    let title = "collision target";

    // Seed the pre-existing row.
    let (status, first) = http_store(
        &client,
        &base,
        &agent,
        &ns,
        title,
        "ORIGINAL durable content",
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "seed store: {first}");
    let existing_id = first["id"].as_str().expect("seed id").to_string();

    // A second create with the SAME (title, namespace) and NO on_conflict must
    // 409 (default `error`), never overwrite.
    let (status, conflict) = http_store(
        &client,
        &base,
        &agent,
        &ns,
        title,
        "ATTACKER overwrite content",
        None,
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::CONFLICT,
        "#2743: default on_conflict must refuse a pre-existing collision, not upsert: {conflict}"
    );
    assert_eq!(
        conflict["code"], "CONFLICT",
        "#2743: 409 envelope carries the CONFLICT code: {conflict}"
    );
    assert_eq!(
        conflict["existing_id"].as_str(),
        Some(existing_id.as_str()),
        "#2743: 409 echoes the pre-existing id so a loader can reconcile: {conflict}"
    );

    // OUT-OF-BAND: the durable content must be UNCHANGED (the silent-overwrite
    // class the fix closes).
    let stored = http_get_content(&client, &base, &agent, &existing_id).await;
    assert_eq!(
        stored, "ORIGINAL durable content",
        "#2743: a refused collision must NOT have overwritten the stored content"
    );

    shutdown.notify_one();
    let _ = handle.await;
}

/// Explicit `on_conflict=merge` KEEPS the upsert path: the pre-existing row's
/// content is replaced and the SAME id is returned (never rewritten by the
/// conflict arm, per the #2551 returned-id contract).
#[tokio::test(flavor = "multi_thread")]
async fn explicit_merge_upserts_2743() {
    let Some(url) = postgres_url() else {
        eprintln!("skipping explicit_merge_upserts_2743: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let (base, shutdown, handle) = spawn_daemon(&url).await;
    let client = reqwest::Client::new();
    let suffix = uuid::Uuid::new_v4();
    let agent = format!("c2743-merge-{suffix}");
    let ns = format!("c2743-merge-ns-{suffix}");
    let title = "merge target";

    let (status, first) = http_store(&client, &base, &agent, &ns, title, "content v1", None).await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "seed store: {first}");
    let existing_id = first["id"].as_str().expect("seed id").to_string();

    let (status, merged) = http_store(
        &client,
        &base,
        &agent,
        &ns,
        title,
        "content v2 (merged)",
        Some("merge"),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "#2743: on_conflict=merge upserts and reports CREATED: {merged}"
    );
    assert_eq!(
        merged["id"].as_str(),
        Some(existing_id.as_str()),
        "#2551/#2743: the upsert returns the PRE-EXISTING id, never a fresh one: {merged}"
    );

    // OUT-OF-BAND: the merge replaced the content in place.
    let stored = http_get_content(&client, &base, &agent, &existing_id).await;
    assert_eq!(
        stored, "content v2 (merged)",
        "#2743: on_conflict=merge must overwrite the stored content in place"
    );

    shutdown.notify_one();
    let _ = handle.await;
}

/// Explicit `on_conflict=version` RENAMES: the write lands under a fresh
/// `(title (2), namespace)` with a NEW id, leaving the original untouched.
#[tokio::test(flavor = "multi_thread")]
async fn explicit_version_renames_2743() {
    let Some(url) = postgres_url() else {
        eprintln!("skipping explicit_version_renames_2743: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let (base, shutdown, handle) = spawn_daemon(&url).await;
    let client = reqwest::Client::new();
    let suffix = uuid::Uuid::new_v4();
    let agent = format!("c2743-ver-{suffix}");
    let ns = format!("c2743-ver-ns-{suffix}");
    let title = "version target";

    let (status, first) = http_store(&client, &base, &agent, &ns, title, "original", None).await;
    assert_eq!(status, reqwest::StatusCode::CREATED, "seed store: {first}");
    let first_id = first["id"].as_str().expect("seed id").to_string();

    let (status, versioned) = http_store(
        &client,
        &base,
        &agent,
        &ns,
        title,
        "the versioned copy",
        Some("version"),
    )
    .await;
    assert_eq!(
        status,
        reqwest::StatusCode::CREATED,
        "#2743: on_conflict=version creates a renamed row: {versioned}"
    );
    assert_ne!(
        versioned["id"].as_str(),
        Some(first_id.as_str()),
        "#2743: version writes a NEW row, never upserting the original: {versioned}"
    );
    assert_ne!(
        versioned["title"].as_str(),
        Some(title),
        "#2743: version renames the title away from the colliding base: {versioned}"
    );

    // OUT-OF-BAND: the original row is untouched.
    let stored = http_get_content(&client, &base, &agent, &first_id).await;
    assert_eq!(
        stored, "original",
        "#2743: on_conflict=version must leave the original row's content intact"
    );

    shutdown.notify_one();
    let _ = handle.await;
}
