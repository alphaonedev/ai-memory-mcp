// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3204 item 1 — `GET /api/v1/memories/{id}` must not disclose the far
//! endpoint of an edge the caller may not read.
//!
//! Pre-fix the anchor was visibility-checked and its `links` array was
//! returned verbatim (`get_links_for_anchor` on postgres, `db::get_links` on
//! sqlite): a caller who owned ONE memory enumerated the id + relation of
//! every other tenant's `scope=private` row linked to it (no content, but a
//! cross-tenant id/relation oracle). The fix applies the `GET /links/{id}`
//! far-endpoint filter on both backends.
//!
//! DENIED: an edge whose far endpoint is another agent's private row, or a
//! row in a substrate namespace the request did not name, is dropped — in
//! BOTH directions (an INBOUND edge from a foreign private row is the
//! subtler leak). ALLOWED: edges to the caller's own rows and to collective
//! rows still ride the response, so graph navigation is intact.
//!
//! Three routers: direct sqlite, the established fake-PG shape (the router
//! advertises `StorageBackend::Postgres` over a real `SqliteStore` so the
//! production postgres dispatch branch runs without a service), and a live
//! PostgreSQL twin that soft-skips without `AI_MEMORY_TEST_POSTGRES_URL`.

#![cfg(feature = "sal")]
#![allow(clippy::too_many_lines)]

use std::sync::Arc;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Memory, Tier};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

const CALLER: &str = "ai:me-3204";
const OTHER: &str = "ai:other-3204";
const NS: &str = "graph-3204";
const OTHER_INBOX: &str = "_messages/ai:other-3204";

struct Fixture {
    router: axum::Router,
    file: NamedTempFile,
    anchor: String,
    own: String,
    collective: String,
    other_private: String,
    other_inbox: String,
}

fn insert(conn: &rusqlite::Connection, namespace: &str, metadata: Value) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let memory = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("#3204 {namespace} {}", uuid::Uuid::new_v4()),
        content: format!("far-endpoint probe row in {namespace}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        ..Memory::default()
    };
    let id = memory.id.clone();
    ai_memory::db::insert(conn, &memory).expect("seed #3204 row");
    id
}

fn fixture_with_store(
    storage_backend: StorageBackend,
    live_store: Option<Arc<dyn ai_memory::store::MemoryStore>>,
) -> Fixture {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let file = NamedTempFile::new().expect("tempfile");
    let path = file.path().to_path_buf();
    let conn = ai_memory::db::open(&path).expect("open DB");
    let anchor = insert(&conn, NS, json!({"agent_id": CALLER, "scope": "private"}));
    let own = insert(&conn, NS, json!({"agent_id": CALLER, "scope": "private"}));
    let collective = insert(&conn, NS, json!({"agent_id": OTHER, "scope": "collective"}));
    let other_private = insert(&conn, NS, json!({"agent_id": OTHER, "scope": "private"}));
    let other_inbox = insert(
        &conn,
        OTHER_INBOX,
        json!({"agent_id": "ai:sender", "target_agent_id": OTHER, "scope": "private"}),
    );
    // Outbound edges from the anchor …
    for target in [&own, &collective, &other_inbox] {
        ai_memory::db::create_link(&conn, &anchor, target, "derived_from").expect("seed edge");
    }
    // … and the subtle one: an INBOUND edge whose SOURCE is the foreign
    // private row. `get_links` returns both directions, so the far endpoint
    // must be resolved per edge, not assumed to be the target.
    ai_memory::db::create_link(&conn, &other_private, &anchor, "related_to")
        .expect("seed inbound foreign edge");

    // The live-PG router gets an empty SQLite scratch connection: an
    // accidental fallback must fail rather than read the seeded twins.
    let router_conn = if live_store.is_some() {
        ai_memory::db::open(std::path::Path::new(":memory:")).expect("empty scratch DB")
    } else {
        conn
    };
    let db: Db = Arc::new(Mutex::new((
        router_conn,
        path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> = live_store.unwrap_or_else(|| {
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SAL store"))
    });
    let state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend,
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
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
    let api_keys = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    Fixture {
        router: ai_memory::build_router(api_keys, state),
        file,
        anchor,
        own,
        collective,
        other_private,
        other_inbox,
    }
}

async fn get_as(router: &axum::Router, uri: &str, caller: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(ai_memory::HEADER_AGENT_ID, caller)
        .body(Body::empty())
        .expect("request");
    let resp = router.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn far_ids(body: &Value, anchor: &str) -> Vec<String> {
    body["links"]
        .as_array()
        .expect("links array")
        .iter()
        .map(|l| {
            let src = l["source_id"].as_str().unwrap_or_default();
            let tgt = l["target_id"].as_str().unwrap_or_default();
            if src == anchor {
                tgt.to_string()
            } else {
                src.to_string()
            }
        })
        .collect()
}

async fn assert_far_endpoint_matrix(f: &Fixture, label: &str) {
    let (status, body) = get_as(&f.router, &format!("/api/v1/memories/{}", f.anchor), CALLER).await;
    assert_eq!(status, StatusCode::OK, "{label}: {body}");
    assert_eq!(body["memory"]["id"], f.anchor, "{label}: {body}");
    let far = far_ids(&body, &f.anchor);
    // ALLOWED — the caller's own row and the collective row still ride.
    assert!(
        far.contains(&f.own),
        "{label}: own far endpoint must ride: {body}"
    );
    assert!(
        far.contains(&f.collective),
        "{label}: collective far endpoint must ride: {body}"
    );
    // DENIED — the foreign private row (INBOUND edge) and the foreign inbox
    // (substrate namespace not named by the request) are gone, id and all.
    let rendered = body.to_string();
    assert!(
        !rendered.contains(&f.other_private),
        "{label}: foreign private far endpoint disclosed: {body}"
    );
    assert!(
        !rendered.contains(&f.other_inbox),
        "{label}: foreign inbox far endpoint disclosed: {body}"
    );
    assert_eq!(
        far.len(),
        2,
        "{label}: exactly the two readable edges: {body}"
    );

    // ALLOWED (control) — the OTHER agent reading its own collective row sees
    // the edge back to the anchor only when the anchor is readable to it; the
    // anchor is CALLER-private, so the far endpoint is dropped for OTHER too.
    let (status, body) = get_as(
        &f.router,
        &format!("/api/v1/memories/{}", f.collective),
        OTHER,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{label}: {body}");
    assert!(
        !body.to_string().contains(&f.anchor),
        "{label}: the caller-private anchor must not leak to OTHER: {body}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_get_memory_hides_foreign_far_endpoints_3204() {
    let f = fixture_with_store(StorageBackend::Sqlite, None);
    assert_far_endpoint_matrix(&f, "sqlite").await;
    drop(f.file);
}

#[cfg(feature = "sal")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fake_pg_get_memory_hides_foreign_far_endpoints_3204() {
    let f = fixture_with_store(StorageBackend::Postgres, None);
    assert_far_endpoint_matrix(&f, "fake-pg").await;
    drop(f.file);
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_pg_get_memory_hides_foreign_far_endpoints_3204() {
    use ai_memory::store::{CallerContext, MemoryStore};
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!(
            "skip: live_pg_get_memory_hides_foreign_far_endpoints_3204: AI_MEMORY_TEST_POSTGRES_URL unset"
        );
        return;
    };
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect live PostgreSQL"),
    );
    let f = fixture_with_store(StorageBackend::Postgres, Some(Arc::clone(&store)));
    let conn = ai_memory::db::open(f.file.path()).expect("fixture rows");
    let ctx = CallerContext::for_admin("fixture-3204");
    for id in [
        &f.anchor,
        &f.own,
        &f.collective,
        &f.other_private,
        &f.other_inbox,
    ] {
        let mem = ai_memory::db::get(&conn, id)
            .expect("fetch fixture")
            .expect("fixture exists");
        store.store(&ctx, &mem).await.expect("seed live PostgreSQL");
    }
    for link in ai_memory::db::get_links(&conn, &f.anchor).expect("seed links") {
        store.link(&ctx, &link).await.expect("seed PostgreSQL edge");
    }
    assert_far_endpoint_matrix(&f, "live-pg").await;
}
