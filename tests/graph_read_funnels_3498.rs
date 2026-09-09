// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3498: graph/family reads apply the substrate opt-in and owner checks.

use ai_memory::models::Memory;
use serde_json::{Value, json};

const CALLER: &str = "ai:me";

fn seed(conn: &rusqlite::Connection, namespace: &str, target: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: namespace.to_string(),
        title: format!("{namespace} {}", uuid::Uuid::new_v4()),
        content: "graph visibility regression".to_string(),
        created_at: now.clone(),
        updated_at: now,
        source_uri: Some("doc:visibility-3498".to_string()),
        metadata: json!({"agent_id": target, "scope": if namespace.starts_with("_inbox/") || namespace.starts_with("_messages/") { "private" } else { "collective" }, "target_agent_id": target, "family": "graph"}),
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("seed memory")
}

fn fixture() -> (rusqlite::Connection, String, String, Vec<String>) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("open");
    let root = seed(&conn, "ordinary", CALLER);
    let ordinary = seed(&conn, "ordinary", CALLER);
    let hidden = [
        "_inbox/ai:me",
        "_messages/ai:me",
        "_inbox/ai:other",
        "_agents",
        "_agent_sessions",
        "_standards",
    ]
    .into_iter()
    .map(|ns| {
        seed(
            &conn,
            ns,
            if ns.ends_with("other") {
                "ai:other"
            } else {
                CALLER
            },
        )
    })
    .collect::<Vec<_>>();
    for id in std::iter::once(&ordinary).chain(hidden.iter()) {
        ai_memory::db::create_link(&conn, &root, id, "derived_from").expect("seed edge");
    }
    (conn, root, ordinary, hidden)
}

fn assert_rows(out: &Value, key: &str, id_key: &str, ordinary: &str, hidden: &[String]) {
    let rows = out[key].as_array().expect("rows");
    assert!(
        rows.iter().any(|r| r[id_key] == ordinary),
        "allowed row missing: {out}"
    );
    for id in hidden {
        assert!(
            !rows.iter().any(|r| r[id_key] == *id),
            "substrate row leaked: {out}"
        );
    }
}

#[test]
fn family_named_mail_and_ambient_matrix() {
    let (conn, _, ordinary, hidden) = fixture();
    for caller in [None, Some(CALLER)] {
        let out =
            ai_memory::mcp::handle_load_family(&conn, &json!({"family": "graph", "k": 50}), caller)
                .expect("family");
        assert_rows(&out, "memories", "id", &ordinary, &hidden);
    }
    let out = ai_memory::mcp::handle_load_family(&conn, &json!({"family": "graph", "k": 1}), None)
        .expect("small family page");
    assert_eq!(
        out["count"], 1,
        "hidden rows cannot consume the page: {out}"
    );
    assert_eq!(out["memories"][0]["namespace"], "ordinary");
    for namespace in ["_inbox/ai:me", "_messages/ai:me"] {
        let out = ai_memory::mcp::handle_load_family(
            &conn,
            &json!({"family": "graph", "namespace": namespace}),
            Some(CALLER),
        )
        .expect("own mail");
        assert_eq!(out["count"], 1, "named own mail: {out}");
    }
    let out = ai_memory::mcp::handle_load_family(
        &conn,
        &json!({"family": "graph", "namespace": "_inbox/ai:other"}),
        Some(CALLER),
    )
    .expect("foreign mail");
    assert_eq!(out["count"], 0, "foreign mail: {out}");
}

#[test]
fn kg_query_walk_and_source_uri_withhold_ambient_substrate() {
    let (conn, root, ordinary, hidden) = fixture();
    for params in [
        json!({"source_id": root}),
        json!({"by_source_uri": "doc:visibility-3498"}),
    ] {
        let out = ai_memory::mcp::handle_kg_query(&conn, &params).expect("query");
        assert_rows(&out, "memories", "target_id", &ordinary, &hidden);
    }
    // Chain-3 reconciliation (Conductor): with #3386 the `namespace` param is
    // an exact-match RESULT filter and, as on `memory_recall --namespace`, the
    // explicit opt-in for substrate rows in THAT namespace (#3348/#3498),
    // still subject to caller visibility. Own mail named by namespace is
    // therefore returned; the ambient (no-namespace) walk above withholds it.
    for namespace in ["_inbox/ai:me", "_messages/ai:me"] {
        let out = ai_memory::mcp::handle_kg_query(
            &conn,
            &json!({"source_id": root, "namespace": namespace}),
        )
        .expect("named query");
        let rows = out["memories"].as_array().unwrap();
        assert!(
            !rows.is_empty() && rows.iter().all(|m| m["target_namespace"] == namespace),
            "own mail allowed and restricted to {namespace}: {out}"
        );
    }
}

#[test]
fn lineage_explicit_anchors_and_ambient_neighbors() {
    let (conn, root, ordinary, hidden) = fixture();
    for caller in [None, Some(CALLER)] {
        let out =
            ai_memory::mcp::handle_lineage(&conn, &json!({"id": root}), caller).expect("lineage");
        assert_rows(&out, "nodes", "id", &ordinary, &hidden);
        for id in &hidden {
            let result = ai_memory::mcp::handle_lineage(&conn, &json!({"id": id}), caller);
            assert_eq!(
                result.is_ok(),
                caller.is_none() || id != &hidden[2],
                "anchor gate: {result:?}"
            );
        }
    }
}

#[test]
fn timeline_explicit_anchors_and_ambient_targets() {
    let (conn, root, ordinary, hidden) = fixture();
    for caller in [None, Some(CALLER)] {
        let out = ai_memory::mcp::handle_kg_timeline(&conn, &json!({"source_id": root}), caller)
            .expect("timeline");
        assert_rows(&out, "events", "target_id", &ordinary, &hidden);
        for id in &hidden {
            let result =
                ai_memory::mcp::handle_kg_timeline(&conn, &json!({"source_id": id}), caller);
            assert_eq!(
                result.is_ok(),
                caller.is_none() || id != &hidden[2],
                "anchor gate: {result:?}"
            );
        }
    }
}

#[test]
fn paths_explicit_endpoints_and_ambient_intermediates() {
    let (conn, root, ordinary, hidden) = fixture();
    for id in &hidden {
        ai_memory::db::create_link(&conn, id, &ordinary, "derived_from").expect("indirect edge");
    }
    for caller in [None, Some(CALLER)] {
        let out = ai_memory::mcp::handle_find_paths(
            &conn,
            &json!({"source_id": root, "target_id": ordinary}),
            caller,
        )
        .expect("paths");
        assert_eq!(out["count"], 1, "only direct ordinary path: {out}");
        for id in &hidden {
            let out = ai_memory::mcp::handle_find_paths(
                &conn,
                &json!({"source_id": root, "target_id": id}),
                caller,
            )
            .expect("denied path");
            assert_eq!(
                out["count"].as_u64().unwrap() > 0,
                caller.is_none() || id != &hidden[2],
                "anchor path gate: {out}"
            );
            let reverse = ai_memory::mcp::handle_find_paths(
                &conn,
                &json!({"source_id": id, "target_id": ordinary}),
                caller,
            );
            assert_eq!(
                reverse.is_ok(),
                caller.is_none() || id != &hidden[2],
                "source anchor gate: {reverse:?}"
            );
            if let Ok(out) = reverse {
                assert!(
                    out["count"].as_u64().unwrap() > 0,
                    "readable source anchor: {out}"
                );
            }
        }
    }
}

fn build_router_with_db(
    #[cfg(feature = "sal")] live_store: Option<std::sync::Arc<dyn ai_memory::store::MemoryStore>>,
) -> (axum::Router, ai_memory::handlers::Db, tempfile::TempDir) {
    let scratch = tempfile::tempdir().unwrap();
    let path = scratch.path().join("memory.db");
    let conn = ai_memory::db::open(&path).unwrap();
    let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
        conn,
        path.clone(),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    let storage_backend = ai_memory::handlers::StorageBackend::Sqlite;
    #[cfg(feature = "sal")]
    let storage_backend = if live_store.is_some() {
        ai_memory::handlers::StorageBackend::Postgres
    } else {
        storage_backend
    };
    #[cfg(feature = "sal")]
    let store: std::sync::Arc<dyn ai_memory::store::MemoryStore> =
        live_store.unwrap_or_else(|| {
            std::sync::Arc::new(
                ai_memory::store::sqlite::SqliteStore::open(&path).expect("open SqliteStore"),
            )
        });
    let app_state = ai_memory::handlers::AppState {
        db: std::sync::Arc::clone(&db),
        embedder: std::sync::Arc::new(None),
        vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        federation: std::sync::Arc::new(None),
        tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
        profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: std::sync::Arc::new(None),
        active_keypair: std::sync::Arc::new(None),
        family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend,
        #[cfg(feature = "sal")]
        store,
        llm: std::sync::Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: std::sync::Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),

        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: std::sync::Arc::new(None),
        deferred_audit_queue: std::sync::Arc::new(None),
        admin_agent_ids: std::sync::Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, db, scratch)
}

#[tokio::test]
async fn http_anchor_and_legacy_link_contracts() {
    http_anchor_contract_matrix(
        #[cfg(feature = "sal")]
        None,
    )
    .await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn live_pg_http_anchor_and_legacy_link_contracts() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: live_pg_http_anchor_and_legacy_link_contracts requires PostgreSQL");
        return;
    };
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("live PostgreSQL");
    http_anchor_contract_matrix(Some(std::sync::Arc::new(store))).await;
}

async fn http_anchor_contract_matrix(
    #[cfg(feature = "sal")] live_store: Option<std::sync::Arc<dyn ai_memory::store::MemoryStore>>,
) {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt as _;
    let (router, db, _scratch) = build_router_with_db(
        #[cfg(feature = "sal")]
        live_store.clone(),
    );
    let (root, ordinary, own, other, unowned, empty_owner, foreign_owned) = {
        let lock = db.lock().await;
        let root = seed(&lock.0, "ordinary", CALLER);
        let ordinary = seed(&lock.0, "ordinary", CALLER);
        let own = seed(&lock.0, "_inbox/ai:me", CALLER);
        let other = seed(&lock.0, "_inbox/ai:other", "ai:other");
        let mut legacy = ai_memory::db::get(&lock.0, &ordinary).unwrap().unwrap();
        legacy.id = uuid::Uuid::new_v4().to_string();
        legacy.title = "legacy unowned".to_string();
        legacy.metadata = json!({});
        let unowned = ai_memory::db::insert(&lock.0, &legacy).unwrap();
        legacy.id = uuid::Uuid::new_v4().to_string();
        legacy.title = "legacy empty owner".to_string();
        legacy.metadata = json!({"agent_id": ""});
        let empty_owner = ai_memory::db::insert(&lock.0, &legacy).unwrap();
        legacy.id = uuid::Uuid::new_v4().to_string();
        legacy.title = "foreign ordinary owner".to_string();
        legacy.metadata = json!({"agent_id": "ai:other"});
        let foreign_owned = ai_memory::db::insert(&lock.0, &legacy).unwrap();
        // The inbox reader is its target, not its writer (#944).
        lock.0
            .execute(
                "UPDATE memories SET metadata = ?1 WHERE id = ?2",
                [
                    json!({"agent_id": "ai:sender", "target_agent_id": CALLER}).to_string(),
                    own.clone(),
                ],
            )
            .unwrap();
        for source in [&root, &own] {
            for target in [&ordinary, &other] {
                ai_memory::db::create_link(&lock.0, source, target, "derived_from").unwrap();
            }
        }
        (
            root,
            ordinary,
            own,
            other,
            unowned,
            empty_owner,
            foreign_owned,
        )
    };
    #[cfg(feature = "sal")]
    if let Some(store) = live_store {
        let (memories, links) = {
            let lock = db.lock().await;
            let memories = [
                &root,
                &ordinary,
                &own,
                &other,
                &unowned,
                &empty_owner,
                &foreign_owned,
            ]
            .into_iter()
            .map(|id| ai_memory::db::get(&lock.0, id).unwrap().unwrap())
            .collect::<Vec<_>>();
            let links = [&root, &own]
                .into_iter()
                .flat_map(|id| ai_memory::db::get_links(&lock.0, id).unwrap())
                .collect::<Vec<_>>();
            (memories, links)
        };
        let ctx = ai_memory::store::CallerContext::for_admin("fixture-3498b");
        for mem in memories {
            store
                .store(&ctx, &mem)
                .await
                .expect("seed PostgreSQL memory");
        }
        for link in links {
            store.link(&ctx, &link).await.expect("seed PostgreSQL link");
        }
        // Prove the HTTP route uses PostgreSQL by emptying its SQLite fallback.
        let mut lock = db.lock().await;
        lock.0 = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    }
    for (anchor, expected) in [
        (&own, StatusCode::OK),
        (&other, StatusCode::NOT_FOUND),
        (&foreign_owned, StatusCode::FORBIDDEN),
        (&unowned, StatusCode::OK),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/kg/timeline?source_id={anchor}"))
                    .header(ai_memory::HEADER_AGENT_ID, CALLER)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "timeline anchor {anchor}");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        if anchor == &own {
            assert_rows(
                &body,
                "events",
                "target_id",
                &ordinary,
                std::slice::from_ref(&other),
            );
        } else if anchor == &other {
            assert_eq!(body["found"], false, "hidden substrate envelope");
        }
    }
    for (target, expected) in [
        (&unowned, StatusCode::CREATED),
        (&empty_owner, StatusCode::CREATED),
        (&own, StatusCode::CREATED),
        (&other, StatusCode::FORBIDDEN),
        (&foreign_owned, StatusCode::CREATED),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/links")
                    .header("content-type", "application/json")
                    .header(ai_memory::HEADER_AGENT_ID, CALLER)
                    .body(Body::from(
                        json!({"source_id": root, "target_id": target, "relation": "related_to"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            status,
            expected,
            "link target {target}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
}
