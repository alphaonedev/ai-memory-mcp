// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3730 — the recipient's delete admission is DERIVED from the namespace,
//! never asserted beside it.
//!
//! The inbox drain lets the ADDRESSED RECIPIENT (`metadata.target_agent_id`)
//! delete a message it did not author. That admission and the retention
//! policy (`visibility::inbox_delete_retains`: an inbox row is ARCHIVED on
//! delete, every other row is ERASED) are two predicates over different
//! axes — the gate reads the row's metadata and is namespace-blind, the
//! routing reads the namespace and is principal-blind. When the gate ran
//! BEFORE the namespace lookup with a bare `allow_inbox = true`, a row
//! addressed to the caller but living OUTSIDE an inbox namespace passed the
//! gate and fell through to the erase path: a non-owner who merely had a row
//! addressed to it could sever, tombstone and crypto-erase that row — an
//! irrecoverable loss by someone who was never the owner. It was reachable by
//! writing `target_agent_id` into any row's metadata.
//!
//! The Conductor's ruling (2026-09-14, on #3730-r2) and the reviewer probe
//! that measured it (2026-09-15, RED on `14748e776` on BOTH backends; on the
//! `c3ba52943` base postgres refused the recipient outright, so the r4 parity
//! commit introduced the erasure there, while on sqlite the bare `true`
//! pre-dated #3730): ONE predicate governs both decisions. The namespace is
//! looked up first and `inbox_delete_retains(namespace)` is what the gate
//! receives as `allow_inbox`, so the recipient is authorised exactly for the
//! path that keeps the record and never for the path that erases it — and
//! the two cannot drift apart because they read the same value.
//!
//! Why the existing drain pin (`bucket_b_inbox_recipient_delete_archives_and_
//! drains_3730`, `recipient_delete_archives_and_drains_every_read_surface_3730`)
//! did not catch this: it only exercises the inbox namespace, which is exactly
//! the case the defect exempts. A pin that only exercises the permitted path
//! cannot see a gate that is too wide. Every cell here drives the FORBIDDEN
//! path (a non-inbox row addressed to the caller) and asserts the row still
//! exists, then the permitted path as the control that keeps the scope real
//! (the recipient still drains its inbox, archived).
//!
//! Four sites, four funnels, one cell each:
//! * `SqliteStore::delete` (SAL, sqlite) — `sal_sqlite_*`
//! * `PostgresStore::delete` (SAL, postgres; the HTTP pg arm calls it) —
//!   `sal_postgres_*` (skips without `AI_MEMORY_TEST_POSTGRES_URL`)
//! * MCP `memory_delete` (real binary, sqlite) — `mcp_*`
//! * HTTP `DELETE /api/v1/memories/{id}` sqlite arm (production router) —
//!   `http_sqlite_*`
//!
//! RED on `14748e776` (every cell: `delete -> Ok`, row gone, archive empty),
//! GREEN on the fix.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex as AsyncMutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};

const ALICE: &str = "ai:alice-3730-gate";
const BOB: &str = "ai:bob-3730-gate";

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// A row authored by `owner`, addressed to `recipient`, in `namespace`.
fn addressed_row(owner: &str, recipient: &str, namespace: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: unique("addressed-3730"),
        content: "addressed to the recipient".to_string(),
        tags: vec!["3730-gate".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test-3730-gate".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({ "agent_id": owner, "target_agent_id": recipient }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: vec![],
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..Memory::default()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SAL — the two stores, driven through the trait the HTTP handlers call
// ─────────────────────────────────────────────────────────────────────────────

async fn sal_forbidden_path_keeps_the_row(store: &dyn MemoryStore, backend: &str) {
    let ns = unique("team/gate-3730");
    let alice = CallerContext::for_agent(ALICE);
    let bob = CallerContext::for_agent(BOB);
    let admin = CallerContext::for_admin("ai:probe-admin-3730");
    let id = store
        .store(&alice, &addressed_row(ALICE, BOB, &ns))
        .await
        .expect("alice stores");

    let outcome = store.delete(&bob, &id).await;
    assert!(
        matches!(outcome, Err(StoreError::PermissionDenied { .. })),
        "[{backend}] a recipient is not admitted to delete a row addressed to it OUTSIDE an \
         inbox namespace: {outcome:?}"
    );
    let live = store.get(&admin, &id).await;
    assert!(live.is_ok(), "[{backend}] the row still exists: {live:?}");
    let archived = store
        .list_archived(Some(ns.as_str()), 50, 0)
        .await
        .unwrap_or_default();
    assert!(
        archived.is_empty(),
        "[{backend}] nothing was archived either: {archived:?}"
    );
    // The owner still can.
    store.delete(&alice, &id).await.expect("the owner deletes");
}

async fn sal_permitted_path_still_drains(store: &dyn MemoryStore, backend: &str) {
    let ns = ai_memory::inbox_namespace(BOB);
    let alice = CallerContext::for_agent(ALICE);
    let bob = CallerContext::for_agent(BOB);
    let admin = CallerContext::for_admin("ai:probe-admin-3730");
    let id = store
        .store(&alice, &addressed_row(ALICE, BOB, &ns))
        .await
        .expect("alice delivers");

    store
        .delete(&bob, &id)
        .await
        .expect("the recipient drains its inbox");
    assert!(
        store.get(&admin, &id).await.is_err(),
        "[{backend}] drained from the live set"
    );
    let archived = store
        .list_archived(Some(ns.as_str()), 50, 0)
        .await
        .expect("list_archived");
    assert!(
        archived
            .iter()
            .any(|m| m["id"].as_str() == Some(id.as_str())),
        "[{backend}] the drained message is archived, not erased: {archived:?}"
    );
}

#[tokio::test]
async fn sal_sqlite_recipient_cannot_erase_a_non_inbox_row_addressed_to_it_3730() {
    let dir = tempfile::tempdir_in(".local-runs").expect("scratch");
    let store = SqliteStore::open(dir.path().join("gate.db")).expect("sqlite");
    sal_forbidden_path_keeps_the_row(&store, "sqlite").await;
    sal_permitted_path_still_drains(&store, "sqlite").await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn sal_postgres_recipient_cannot_erase_a_non_inbox_row_addressed_to_it_3730() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect");
    sal_forbidden_path_keeps_the_row(&store, "postgres").await;
    sal_permitted_path_still_drains(&store, "postgres").await;
}

// ─────────────────────────────────────────────────────────────────────────────
// MCP — the real stdio binary as the recipient (`AI_MEMORY_AGENT_ID`)
// ─────────────────────────────────────────────────────────────────────────────

/// One `tools/call` against the real MCP stdio server, as `caller`.
fn mcp(
    db: &std::path::Path,
    home: &std::path::Path,
    caller: &str,
    tool: &str,
    args: &Value,
) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", caller)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("HOME", home)
        .args([
            "--db",
            db.to_str().expect("db path"),
            "mcp",
            "--profile",
            "full",
            "--tier",
            "keyword",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("mcp child");
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":args}});
    writeln!(child.stdin.take().expect("stdin"), "{request}").expect("request");
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().expect("poll").is_none() {
        assert!(Instant::now() < deadline, "MCP child timed out on {tool}");
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("output");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let response = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|v| v["id"] == 1)
        .unwrap_or_else(|| {
            panic!(
                "no response for {caller} {tool}: status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        });
    if let Some(text) = response["result"]["content"][0]["text"].as_str() {
        if response["result"]["isError"].as_bool() == Some(true) {
            return json!({"error": text});
        }
        return serde_json::from_str(text).unwrap_or_else(|_| json!({"text": text}));
    }
    json!({"error": response["error"].clone()})
}

#[test]
fn mcp_recipient_cannot_erase_a_non_inbox_row_addressed_to_it_3730() {
    let dir = tempfile::tempdir_in(".local-runs").expect("scratch");
    let db = dir.path().join("gate.db");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let ns = unique("team/gate-3730");

    // Alice authors a row in a team namespace and addresses it to Bob.
    let stored = mcp(
        &db,
        &home,
        ALICE,
        "memory_store",
        &json!({
            "title": unique("addressed-3730"),
            "content": "addressed to bob, outside any inbox",
            "namespace": ns,
            "tier": "long",
            "metadata": { "target_agent_id": BOB },
        }),
    );
    let id = stored["id"]
        .as_str()
        .unwrap_or_else(|| panic!("store id: {stored}"))
        .to_string();

    // Bob may not erase it.
    let refused = mcp(&db, &home, BOB, "memory_delete", &json!({"id": id}));
    let err = refused["error"].as_str().unwrap_or_default();
    assert!(
        err.contains(ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY),
        "memory_delete by the addressed non-owner outside the inbox is refused: {refused}"
    );
    let still = mcp(&db, &home, ALICE, "memory_get", &json!({"id": id}));
    assert_eq!(still["id"], json!(id), "the row still exists: {still}");
    let archive = mcp(
        &db,
        &home,
        ALICE,
        "memory_archive_list",
        &json!({"namespace": ns, "limit": 50}),
    );
    assert!(
        !archive.to_string().contains(&id),
        "and nothing was archived: {archive}"
    );

    // The permitted path: Bob drains a message DELIVERED to its inbox.
    let notified = mcp(
        &db,
        &home,
        ALICE,
        "memory_notify",
        &json!({"target_agent_id": BOB, "title": unique("hello-3730"), "payload": "handle me"}),
    );
    let msg = notified["id"]
        .as_str()
        .unwrap_or_else(|| panic!("notify id: {notified}"))
        .to_string();
    let drained = mcp(&db, &home, BOB, "memory_delete", &json!({"id": msg}));
    assert_eq!(drained["deleted"], json!(true), "{drained}");
    assert_eq!(
        drained["archived"],
        json!(true),
        "the inbox drain still archives: {drained}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP — the production router's sqlite arm via `tower::oneshot`
// ─────────────────────────────────────────────────────────────────────────────

fn sqlite_router() -> (axum::Router, tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir_in(".local-runs").expect("scratch");
    let db_path = dir.path().join("gate.db");
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(AsyncMutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = Arc::new(SqliteStore::open(&db_path).expect("SqliteStore"));
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(AsyncMutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (
        ai_memory::build_router(api_key_state, app_state),
        dir,
        db_path,
    )
}

async fn send(router: &axum::Router, method: &str, uri: &str, caller: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-agent-id", caller)
        .body(Body::empty())
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn http_sqlite_recipient_cannot_erase_a_non_inbox_row_addressed_to_it_3730() {
    let (router, _dir, db_path) = sqlite_router();
    let ns = unique("team/gate-3730");
    // Seeded through the storage funnel (no HTTP store attestation ceremony
    // needed): a row Alice authored in a team namespace, addressed to Bob.
    let conn = ai_memory::db::open(&db_path).expect("seed conn");
    let id = ai_memory::db::insert(&conn, &addressed_row(ALICE, BOB, &ns)).expect("seed");
    let msg = ai_memory::db::insert(
        &conn,
        &addressed_row(ALICE, BOB, &ai_memory::inbox_namespace(BOB)),
    )
    .expect("seed inbox message");
    drop(conn);

    let (status, body) = send(&router, "DELETE", &format!("/api/v1/memories/{id}"), BOB).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "DELETE by the addressed non-owner outside the inbox is refused: {body}"
    );
    let (status, body) = send(&router, "GET", &format!("/api/v1/memories/{id}"), ALICE).await;
    assert_eq!(status, StatusCode::OK, "the row still exists: {body}");
    assert_eq!(body["memory"]["id"], json!(id), "{body}");

    // The permitted path: Bob drains its inbox and the message is archived.
    let (status, body) = send(&router, "DELETE", &format!("/api/v1/memories/{msg}"), BOB).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], json!(true), "{body}");
    assert_eq!(
        body["archived"],
        json!(true),
        "the inbox drain archives: {body}"
    );
}
