// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3348 — HTTP parity for ambient substrate-namespace suppression.
//!
//! The router advertises `StorageBackend::Postgres` while its SAL handle is a
//! real `SqliteStore`. That established fake-PG pattern drives the production
//! Postgres-dispatch branches without an external service and, importantly,
//! returns rows that the HTTP layer must post-filter using the request's exact
//! namespace.

#![cfg(feature = "sal")]

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

const NEEDLE: &str = "http3348uniquepayload";
const CALLER: &str = "ai:me";
const OWN_INBOX: &str = "_messages/ai:me";
const OTHER_INBOX: &str = "_messages/ai:other";

struct Fixture {
    router: axum::Router,
    file: NamedTempFile,
    ordinary: String,
    neighbor: String,
    own_inbox: String,
    other_inbox: String,
    registry: String,
    substrate: Vec<String>,
}

fn insert(conn: &rusqlite::Connection, namespace: &str, mut metadata: Value) -> String {
    metadata["family"] = json!("graph");
    let now = chrono::Utc::now().to_rfc3339();
    let memory = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("#3348 {namespace} {}", uuid::Uuid::new_v4()),
        content: format!("{NEEDLE} in {namespace}"),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        ..Memory::default()
    };
    let id = memory.id.clone();
    ai_memory::db::insert(conn, &memory).expect("seed #3348 HTTP row");
    id
}

fn fixture(storage_backend: StorageBackend) -> Fixture {
    fixture_with_store(storage_backend, None)
}

fn fixture_with_store(
    storage_backend: StorageBackend,
    live_store: Option<Arc<dyn ai_memory::store::MemoryStore>>,
) -> Fixture {
    let file = NamedTempFile::new().expect("tempfile");
    let path = file.path().to_path_buf();
    let conn = ai_memory::db::open(&path).expect("open DB");
    let ordinary = insert(
        &conn,
        "operator-memory",
        json!({"agent_id": CALLER, "scope": "private"}),
    );
    let own_inbox = insert(
        &conn,
        OWN_INBOX,
        json!({
            "agent_id": "ai:sender",
            "target_agent_id": CALLER,
            "scope": "private"
        }),
    );
    let other_inbox = insert(
        &conn,
        OTHER_INBOX,
        json!({
            "agent_id": "ai:sender",
            "target_agent_id": "ai:other",
            "scope": "private"
        }),
    );
    // Deliberately collective: ordinary scope visibility alone admits this row.
    let registry = insert(
        &conn,
        "_agents",
        json!({"agent_id": "ai:registry", "scope": "collective"}),
    );

    let neighbor = insert(
        &conn,
        "graph-neighbor-3498",
        json!({"agent_id": CALLER, "scope": "private"}),
    );
    for target in [&neighbor, &own_inbox, &other_inbox, &registry] {
        ai_memory::db::create_link(&conn, &ordinary, target, "derived_from")
            .expect("seed graph edge");
    }

    ai_memory::db::create_link(&conn, &registry, &neighbor, "derived_from")
        .expect("hidden intermediate edge");
    let substrate = [
        "_inbox/ai:me",
        "_inbox/ai:other",
        "_agent_sessions",
        "_standards",
    ]
    .into_iter()
    .map(|namespace| {
        let recipient = if namespace.ends_with("other") {
            "ai:other"
        } else {
            CALLER
        };
        let scope = if namespace.starts_with("_inbox/") {
            "private"
        } else {
            "collective"
        };
        let id = insert(
            &conn,
            namespace,
            json!({"agent_id": recipient, "target_agent_id": recipient, "scope": scope}),
        );
        ai_memory::db::create_link(&conn, &ordinary, &id, "derived_from").expect("substrate edge");
        id
    })
    .collect();

    // The live-PG router gets an empty SQLite scratch connection: an
    // accidental fallback must fail the matrix rather than read seeded twins.
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
        Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SAL fake-PG store"),
        )
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
        ordinary,
        neighbor,
        own_inbox,
        other_inbox,
        registry,
        substrate,
    }
}

async fn get(router: &axum::Router, uri: &str) -> Value {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(ai_memory::HEADER_AGENT_ID, CALLER)
                .body(Body::empty())
                .expect("GET request"),
        )
        .await
        .expect("GET response");
    assert_eq!(response.status(), StatusCode::OK, "GET {uri}");
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("GET body");
    serde_json::from_slice(&bytes).expect("GET JSON")
}

async fn post_recall(router: &axum::Router, namespace: Option<&str>) -> Value {
    let mut body = json!({"context": NEEDLE, "limit": 50});
    if let Some(namespace) = namespace {
        body["namespace"] = json!(namespace);
    }
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/recall")
                .header(ai_memory::HEADER_AGENT_ID, CALLER)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).expect("recall body")))
                .expect("POST request"),
        )
        .await
        .expect("POST response");
    assert_eq!(response.status(), StatusCode::OK, "POST recall");
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("POST body");
    serde_json::from_slice(&bytes).expect("POST JSON")
}

fn ids(response: &Value, key: &str) -> Vec<String> {
    response[key]
        .as_array()
        .expect("response row array")
        .iter()
        .filter_map(|row| row["id"].as_str().map(str::to_string))
        .collect()
}

fn assert_ambient(ids: &[String], fixture: &Fixture, surface: &str) {
    assert!(
        ids.contains(&fixture.ordinary),
        "{surface}: ordinary caller-owned memory must remain readable; got {ids:?}"
    );
    for (label, id) in [
        ("own inbox", &fixture.own_inbox),
        ("other inbox", &fixture.other_inbox),
        ("collective registry", &fixture.registry),
    ] {
        assert!(
            !ids.contains(id),
            "{surface}: ambient read exposed {label}; got {ids:?}"
        );
    }
}

async fn assert_http_read_funnels_share_system_namespace_rule(fixture: &Fixture) {
    let list = get(&fixture.router, "/api/v1/memories?limit=50").await;
    assert_ambient(&ids(&list, "memories"), fixture, "list");

    let search = get(
        &fixture.router,
        &format!("/api/v1/search?q={NEEDLE}&limit=50"),
    )
    .await;
    assert_ambient(&ids(&search, "results"), fixture, "search");

    let recall_get = get(
        &fixture.router,
        &format!("/api/v1/recall?context={NEEDLE}&limit=50"),
    )
    .await;
    assert_ambient(&ids(&recall_get, "memories"), fixture, "GET recall");

    let recall_post = post_recall(&fixture.router, None).await;
    assert_ambient(&ids(&recall_post, "memories"), fixture, "POST recall");

    // Explicit namespace is the opt-in, but it never lifts owner/inbox
    // confinement. Drive every list/search/recall branch in both postures.
    let own_list = get(
        &fixture.router,
        "/api/v1/memories?namespace=_messages%2Fai%3Ame&limit=50",
    )
    .await;
    assert!(ids(&own_list, "memories").contains(&fixture.own_inbox));

    let own_search = get(
        &fixture.router,
        &format!("/api/v1/search?q={NEEDLE}&namespace=_messages%2Fai%3Ame&limit=50"),
    )
    .await;
    assert!(ids(&own_search, "results").contains(&fixture.own_inbox));

    let own_get = get(
        &fixture.router,
        &format!("/api/v1/recall?context={NEEDLE}&namespace=_messages%2Fai%3Ame&limit=50"),
    )
    .await;
    assert!(ids(&own_get, "memories").contains(&fixture.own_inbox));
    let own_post = post_recall(&fixture.router, Some(OWN_INBOX)).await;
    assert!(ids(&own_post, "memories").contains(&fixture.own_inbox));

    let other_list = get(
        &fixture.router,
        "/api/v1/memories?namespace=_messages%2Fai%3Aother&limit=50",
    )
    .await;
    assert!(!ids(&other_list, "memories").contains(&fixture.other_inbox));
    let other_search = get(
        &fixture.router,
        &format!("/api/v1/search?q={NEEDLE}&namespace=_messages%2Fai%3Aother&limit=50"),
    )
    .await;
    assert!(!ids(&other_search, "results").contains(&fixture.other_inbox));
    let other_get = get(
        &fixture.router,
        &format!("/api/v1/recall?context={NEEDLE}&namespace=_messages%2Fai%3Aother&limit=50"),
    )
    .await;
    assert!(!ids(&other_get, "memories").contains(&fixture.other_inbox));
    let other_post = post_recall(&fixture.router, Some(OTHER_INBOX)).await;
    assert!(!ids(&other_post, "memories").contains(&fixture.other_inbox));
}

#[tokio::test]
async fn fake_pg_http_read_funnels_share_system_namespace_rule_3348() {
    let fixture = fixture(StorageBackend::Postgres);
    assert_http_read_funnels_share_system_namespace_rule(&fixture).await;
}

#[tokio::test]
async fn direct_sqlite_http_read_funnels_share_system_namespace_rule_3348() {
    let fixture = fixture(StorageBackend::Sqlite);
    assert_http_read_funnels_share_system_namespace_rule(&fixture).await;
}

// #3366 shares these HTTP read funnels with #3348; retain the same fixture so
// timestamp filtering is exercised alongside the production visibility gates.
#[tokio::test]
async fn http_timestamp_bounds_refuse_malformed_3366() {
    for backend in [StorageBackend::Sqlite, StorageBackend::Postgres] {
        let fixture = fixture(backend);
        for (field, value) in [
            ("since", "garbage"),
            ("until", "not-a-date"),
            ("since", "1725000000"),
        ] {
            for surface in ["search", "recall", "recall-post"] {
                let request = timestamp_request(surface, field, value, None);
                let response = fixture.router.clone().oneshot(request).await.unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::BAD_REQUEST,
                    "{surface} {field}"
                );
                let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap();
                let body: Value = serde_json::from_slice(&bytes).unwrap();
                assert!(body["error"].as_str().unwrap().contains("RFC3339"));
            }
        }
    }
}

fn timestamp_request(
    surface: &str,
    field: &str,
    value: &str,
    until: Option<&str>,
) -> Request<Body> {
    let mut request = Request::builder().header(ai_memory::HEADER_AGENT_ID, CALLER);
    if surface == "recall-post" {
        let mut body = json!({"context": NEEDLE, "namespace": "operator-memory", (field): value});
        if let Some(until) = until {
            body["until"] = json!(until);
        }
        request = request
            .method("POST")
            .uri("/api/v1/recall")
            .header("content-type", "application/json");
        request
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    } else {
        let query_key = if surface == "search" { "q" } else { "context" };
        let value = value.replace('+', "%2B");
        let until = until
            .map(|until| format!("&until={}", until.replace('+', "%2B")))
            .unwrap_or_default();
        let uri = format!(
            "/api/v1/{surface}?{query_key}={NEEDLE}&namespace=operator-memory&{field}={value}{until}"
        );
        request.uri(uri).body(Body::empty()).unwrap()
    }
}

#[tokio::test]
async fn http_offset_windows_select_same_rows_3366() {
    for backend in [StorageBackend::Sqlite, StorageBackend::Postgres] {
        let fixture = fixture(backend);
        let conn = ai_memory::db::open(fixture.file.path()).unwrap();
        let old = insert(
            &conn,
            "operator-memory",
            json!({"agent_id": CALLER, "scope": "private"}),
        );
        let future = insert(
            &conn,
            "operator-memory",
            json!({"agent_id": CALLER, "scope": "private"}),
        );
        for (id, timestamp) in [
            (&old, "2026-01-01T00:00:00.000000Z"),
            (&fixture.ordinary, "2026-03-01T02:00:00.000000Z"),
            (&future, "2026-06-01T02:00:00.000000Z"),
        ] {
            conn.execute(
                "UPDATE memories SET created_at = ?1 WHERE id = ?2",
                rusqlite::params![timestamp, id],
            )
            .unwrap();
        }
        for (since, until) in [
            ("2026-03-01T00:00:00+00:00", "2026-06-01T00:00:00+00:00"),
            ("2026-03-01T05:00:00+05:00", "2026-06-01T05:00:00+05:00"),
        ] {
            for surface in ["search", "recall", "recall-post"] {
                let response = fixture
                    .router
                    .clone()
                    .oneshot(timestamp_request(surface, "since", since, Some(until)))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::OK, "{surface}");
                let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap();
                let body: Value = serde_json::from_slice(&bytes).unwrap();
                let key = if surface == "search" {
                    "results"
                } else {
                    "memories"
                };
                assert_eq!(
                    ids(&body, key).as_slice(),
                    std::slice::from_ref(&fixture.ordinary),
                    "{surface} since={since}"
                );
            }
        }
    }
}

/// Exercise the identical #3348 matrix through an actual PostgreSQL adapter.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn live_pg_http_read_funnels_share_system_namespace_rule_3498() {
    let Some(fixture) = live_fixture_3498().await else {
        return;
    };
    assert_http_read_funnels_share_system_namespace_rule(&fixture).await;
}

#[cfg(feature = "sal-postgres")]
async fn live_fixture_3498() -> Option<Fixture> {
    use ai_memory::store::{CallerContext, MemoryStore};
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!(
            "skip: live_pg_http_read_funnels_share_system_namespace_rule_3498: AI_MEMORY_TEST_POSTGRES_URL unset"
        );
        return None;
    };
    let store: Arc<dyn MemoryStore> = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect live PostgreSQL"),
    );
    let fixture = fixture_with_store(StorageBackend::Postgres, Some(Arc::clone(&store)));
    let conn = ai_memory::db::open(fixture.file.path()).expect("fixture rows");
    let ctx = CallerContext::for_admin("fixture-3498");
    for id in [
        &fixture.ordinary,
        &fixture.neighbor,
        &fixture.own_inbox,
        &fixture.other_inbox,
        &fixture.registry,
    ]
    .into_iter()
    .chain(fixture.substrate.iter())
    {
        let mem = ai_memory::db::get(&conn, id)
            .expect("fetch fixture")
            .expect("fixture exists");
        store.store(&ctx, &mem).await.expect("seed live PostgreSQL");
    }
    for link in ai_memory::db::get_links(&conn, &fixture.ordinary).expect("seed links") {
        store.link(&ctx, &link).await.expect("seed PostgreSQL edge");
    }
    for link in ai_memory::db::get_links(&conn, &fixture.registry).expect("intermediate links") {
        if link.source_id == fixture.registry {
            store
                .link(&ctx, &link)
                .await
                .expect("seed intermediate edge");
        }
    }
    Some(fixture)
}

async fn post_graph(router: &axum::Router, uri: &str, body: Value) -> Value {
    let (status, value) = post_graph_response(router, uri, body).await;
    assert_eq!(status, StatusCode::OK, "{uri}: {value}");
    value
}

async fn post_graph_response(router: &axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(ai_memory::HEADER_AGENT_ID, CALLER)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    (status, value)
}

async fn graph_http_matrix_3498(f: &Fixture) {
    let query = post_graph(
        &f.router,
        "/api/v1/kg/query",
        json!({"source_id": f.ordinary, "max_depth": 2}),
    )
    .await;
    let timeline = get(
        &f.router,
        &format!("/api/v1/kg/timeline?source_id={}", f.ordinary),
    )
    .await;
    let lineage = get(
        &f.router,
        &format!("/api/v1/memories/{}/lineage", f.ordinary),
    )
    .await;
    for (out, key, id_key) in [
        (&query, "memories", "target_id"),
        (&timeline, "events", "target_id"),
        (&lineage, "nodes", "id"),
    ] {
        let rows = out[key].as_array().expect("graph rows");
        assert!(
            rows.iter().any(|row| row[id_key] == f.neighbor),
            "allowed graph row: {out}"
        );
        for id in [&f.own_inbox, &f.other_inbox, &f.registry]
            .into_iter()
            .chain(f.substrate.iter())
        {
            assert!(
                !out.to_string().contains(id),
                "substrate graph row or path: {out}"
            );
        }
    }
    let links = get(&f.router, &format!("/api/v1/links/{}", f.ordinary)).await;
    assert_eq!(
        links["links"].as_array().unwrap().len(),
        1,
        "only ordinary edge: {links}"
    );
    for (target, count) in [
        (&f.neighbor, 1),
        (&f.own_inbox, 0),
        (&f.other_inbox, 0),
        (&f.registry, 0),
    ] {
        let paths = post_graph(
            &f.router,
            "/api/v1/kg/find_paths",
            json!({"source_id": f.ordinary, "target_id": target}),
        )
        .await;
        assert_eq!(paths["count"], count, "path visibility: {paths}");
    }
    for (namespace, expected) in [
        (None, Some(&f.ordinary)),
        (Some(OWN_INBOX), Some(&f.own_inbox)),
        (Some(OTHER_INBOX), None),
        (Some("_inbox/ai:me"), Some(&f.substrate[0])),
        (Some("_inbox/ai:other"), None),
    ] {
        let family = post_graph(
            &f.router,
            "/api/v1/memory_load_family",
            json!({"family": "graph", "namespace": namespace, "k": 50}),
        )
        .await;
        let got = ids(&family, "memories");
        if let Some(expected) = expected {
            assert!(got.contains(expected), "allowed family row: {family}");
        } else {
            assert!(got.is_empty(), "foreign inbox: {family}");
        }
        if namespace.is_none() {
            for hidden in [&f.own_inbox, &f.other_inbox, &f.registry]
                .into_iter()
                .chain(f.substrate.iter())
            {
                assert!(!got.contains(hidden), "ambient family leak: {family}");
            }
        }
    }
    for anchor in [&f.own_inbox, &f.other_inbox, &f.registry] {
        let links = get(&f.router, &format!("/api/v1/links/{anchor}")).await;
        assert!(
            links["links"].as_array().unwrap().is_empty(),
            "substrate anchor links withheld: {links}"
        );
        for uri in [
            format!("/api/v1/kg/timeline?source_id={anchor}"),
            format!("/api/v1/memories/{anchor}/lineage"),
        ] {
            let response = f
                .router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(&uri)
                        .header(ai_memory::HEADER_AGENT_ID, CALLER)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                matches!(
                    response.status(),
                    StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
                ),
                "substrate anchor refused: {uri}"
            );
        }
    }
    for target in [&f.neighbor, &f.own_inbox, &f.registry] {
        let (status, body) = post_graph_response(
            &f.router,
            "/api/v1/links",
            json!({"source_id": f.ordinary, "target_id": target, "relation": "related_to"}),
        )
        .await;
        if target == &f.neighbor {
            assert!(status.is_success(), "ordinary link admitted: {body}");
        } else {
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "substrate link refused: {body}"
            );
        }
    }
}

#[tokio::test]
async fn sqlite_graph_http_matrix_3498() {
    graph_http_matrix_3498(&fixture(StorageBackend::Sqlite)).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn live_pg_graph_http_matrix_3498() {
    let Some(fixture) = live_fixture_3498().await else {
        return;
    };
    graph_http_matrix_3498(&fixture).await;
}
