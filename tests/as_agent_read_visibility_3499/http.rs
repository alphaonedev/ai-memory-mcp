// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use super::*;
use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{MemoryLink, MemoryLinkRelation};
#[cfg(feature = "sal-postgres")]
use ai_memory::store::CallerContext;
use ai_memory::store::MemoryStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

fn links(f: &Fixture) -> Vec<MemoryLink> {
    [
        ("public", "alice", ALICE),
        ("public", "registry", ALICE),
        ("team-root", "team", TEAM_AGENT),
    ]
    .into_iter()
    .map(|(source, target, owner)| MemoryLink {
        source_id: f.id(source).to_string(),
        target_id: f.id(target).to_string(),
        relation: MemoryLinkRelation::DependsOn,
        created_at: chrono::Utc::now().to_rfc3339(),
        signature: None,
        observed_by: Some(owner.to_string()),
        valid_from: None,
        valid_until: None,
        attest_level: None,
        source_cid: None,
        target_cid: None,
    })
    .collect()
}

fn router(
    f: &Fixture,
    storage_backend: StorageBackend,
    pg: Option<Arc<dyn MemoryStore>>,
) -> (axum::Router, tempfile::TempDir) {
    let sidecar = tempfile::tempdir().expect("empty sidecar");
    let path = if pg.is_some() {
        sidecar.path().join("empty.db")
    } else {
        f.path.clone()
    };
    let conn = ai_memory::db::open(&path).expect("router database");
    if pg.is_none() {
        for link in links(f) {
            ai_memory::db::create_link_inbound(&conn, &link, "unsigned").expect("fixture link");
        }
    } else {
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM memories", [], |row| row.get(0))
            .expect("sidecar count");
        assert_eq!(
            count, 0,
            "native PostgreSQL must not fall back to seeded SQLite"
        );
    }
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> = pg.unwrap_or_else(|| {
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&path).expect("SQLite store"))
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
    (ai_memory::build_router(api_keys, state), sidecar)
}

async fn request(
    router: &axum::Router,
    caller: Option<&str>,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request =
        Request::builder()
            .uri(path)
            .method(if body.is_some() { "POST" } else { "GET" });
    if let Some(caller) = caller {
        request = request.header("x-agent-id", caller);
    }
    let body = body.map_or_else(Body::empty, |value| {
        Body::from(serde_json::to_vec(&value).expect("body"))
    });
    let response = router
        .clone()
        .oneshot(
            request
                .header("content-type", "application/json")
                .body(body)
                .expect("request"),
        )
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("response bytes");
    (
        status,
        serde_json::from_slice(&bytes).expect("response JSON"),
    )
}

async fn assert_reads(router: &axum::Router, f: &Fixture) {
    for (caller, scope, namespace, expected) in [
        (Some(ALICE), Some(ALICE), NS, vec!["alice", "public"]),
        (Some(BOB), Some(BOB), NS, vec!["bob", "public"]),
        (Some(ALICE), None, NS, vec!["alice", "public"]),
        (Some(ALICE), Some(ALICE), INBOX, vec!["inbox"]),
        (Some(BOB), Some(BOB), INBOX, vec![]),
        (
            Some(TEAM_AGENT),
            Some(TEAM_AGENT),
            TEAM_NS,
            vec!["team", "team-root"],
        ),
    ] {
        let suffix = scope.map_or_else(String::new, |scope| format!("&as_agent={scope}"));
        for path in [
            format!("/api/v1/recall?context={NEEDLE}&namespace={namespace}{suffix}"),
            format!("/api/v1/search?q={NEEDLE}&namespace={namespace}{suffix}"),
        ] {
            let (status, body) = request(router, caller, &path, None).await;
            assert_eq!(status, StatusCode::OK, "{path}: {body}");
            assert_eq!(titles(&body), expected, "{path} {caller:?}: {body}");
        }
        let mut params = json!({"context": NEEDLE, "namespace":namespace});
        if let Some(scope) = scope {
            params["as_agent"] = json!(scope);
        }
        let (status, body) = request(router, caller, "/api/v1/recall", Some(params)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(titles(&body), expected, "POST recall {caller:?}: {body}");
    }
    for caller in [None, Some(BOB)] {
        for path in [
            format!("/api/v1/recall?context={NEEDLE}&namespace={INBOX}&as_agent={ALICE}"),
            format!("/api/v1/search?q={NEEDLE}&namespace={INBOX}&as_agent={ALICE}"),
        ] {
            let (status, body) = request(router, caller, &path, None).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        }
        for (path, params) in [
            (
                "/api/v1/recall",
                json!({"context":NEEDLE,"namespace":INBOX,"as_agent":ALICE}),
            ),
            (
                "/api/v1/kg/query",
                json!({"source_id":f.id("public"),"as_agent":ALICE}),
            ),
        ] {
            let (status, body) = request(router, caller, path, Some(params)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        }
    }
    for (caller, source, namespace, scope, expected) in [
        (ALICE, "public", Some(NS), Some(ALICE), vec!["alice"]),
        (ALICE, "public", Some("absent3499"), Some(ALICE), vec![]),
        (ALICE, "public", None, None, vec!["alice"]),
        (
            ALICE,
            "public",
            Some("_agents"),
            Some(ALICE),
            vec!["registry"],
        ),
        (BOB, "public", Some(NS), Some(BOB), vec![]),
        (
            TEAM_AGENT,
            "team-root",
            Some(TEAM_NS),
            Some(TEAM_AGENT),
            vec!["team"],
        ),
    ] {
        let mut params = json!({"source_id":f.id(source),"max_depth":1});
        if let Some(namespace) = namespace {
            params["namespace"] = json!(namespace);
        }
        if let Some(scope) = scope {
            params["as_agent"] = json!(scope);
        }
        let (status, body) = request(router, Some(caller), "/api/v1/kg/query", Some(params)).await;
        assert_eq!(status, StatusCode::OK, "KG query: {body}");
        assert_eq!(
            titles(&body),
            expected,
            "KG query {caller} {namespace:?}: {body}"
        );
    }
    for field in ["namespace", "as_agent"] {
        let mut params = json!({"source_id":f.id("public")});
        params[field] = json!("invalid namespace");
        let (status, body) = request(router, Some(ALICE), "/api/v1/kg/query", Some(params)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "invalid {field}: {body}");
    }
}

#[tokio::test]
async fn sqlite_http_recall_search_and_kg_confine_scope() {
    let f = Fixture::new();
    let (router, _sidecar) = router(&f, StorageBackend::Sqlite, None);
    assert_reads(&router, &f).await;
    // Exercise SQLite's separate source-URI-only search branch too.
    for (caller, expected) in [(ALICE, vec!["inbox"]), (BOB, vec![])] {
        let path =
            format!("/api/v1/search?q=&source_uri={URI}&namespace={INBOX}&as_agent={caller}");
        let (status, body) = request(&router, Some(caller), &path, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(titles(&body), expected, "source URI: {body}");
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_postgres_http_recall_search_and_kg_confine_scope() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: live #3499 needs the certified PostgreSQL endpoint");
        return;
    };
    let f = Fixture::new();
    let store = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("certified PostgreSQL"),
    );
    assert_eq!(store.kg_backend(), ai_memory::store::KgBackend::Age);
    for memory in &f.memories {
        let owner = memory.metadata["agent_id"].as_str().expect("owner");
        store
            .store(&CallerContext::for_agent(owner), memory)
            .await
            .expect("seed native PostgreSQL");
    }
    for link in links(&f) {
        let owner = link.observed_by.as_deref().expect("link owner");
        store
            .link(&CallerContext::for_agent(owner), &link)
            .await
            .expect("seed native AGE edge");
    }
    let (router, _sidecar) = router(&f, StorageBackend::Postgres, Some(store));
    assert_reads(&router, &f).await;
}
