// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use super::*;
use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
#[cfg(feature = "sal-postgres")]
use ai_memory::store::CallerContext;
use ai_memory::store::MemoryStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt as _;
const EXPORT: &str = "/api/v1/memory_export_reflection";

fn router(
    f: &Fixture,
    storage_backend: StorageBackend,
    pg: Option<Arc<dyn MemoryStore>>,
    admin: bool,
) -> (axum::Router, tempfile::TempDir) {
    let sidecar = tempfile::tempdir().expect("empty sidecar");
    let path = if pg.is_some() {
        sidecar.path().join("empty.db")
    } else {
        f.path.clone()
    };
    let conn = ai_memory::db::open(&path).expect("router database");
    if pg.is_some() {
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
    let enrolled = Arc::new(
        ai_memory::handlers::identity_binding::EnrolledAgentKeys::from_map(
            [
                (ALICE, "alice-test-token-3551"),
                (BOB, "bob-test-token-3551"),
                (ADMIN, "admin-test-token-3551"),
            ]
            .into_iter()
            .map(|(actor, token)| {
                (
                    ai_memory::handlers::identity_binding::api_key_sha256_hex(token),
                    actor.to_string(),
                )
            })
            .collect(),
        ),
    );
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
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
        admin_agent_ids: Arc::new(if admin {
            vec![ADMIN.to_string()]
        } else {
            Vec::new()
        }),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: ai_memory::config::HttpIdentityMode::Enforce,
    };
    let api_keys = ApiKeyState {
        key: Some("shared-test-token-3551".to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled.clone(),
        identity_mode: ai_memory::config::HttpIdentityMode::Enforce,
    };
    (ai_memory::build_router(api_keys, state), sidecar)
}

async fn request(
    router: &axum::Router,
    caller: Option<&str>,
    path: &str,
    body: Option<Value>,
    shared_key: bool,
) -> (StatusCode, Value) {
    let mut request =
        Request::builder()
            .uri(path)
            .method(if body.is_some() { "POST" } else { "GET" });
    if let Some(caller) = caller {
        request = request.header("x-agent-id", caller);
    }
    let token = if shared_key {
        "shared-test-token-3551"
    } else {
        match caller {
            Some(ALICE) => "alice-test-token-3551",
            Some(BOB) => "bob-test-token-3551",
            Some(ADMIN) => "admin-test-token-3551",
            _ => "shared-test-token-3551",
        }
    };
    request = request.header("x-api-key", token);
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

async fn export_cases(router: &axum::Router, f: &Fixture) {
    let absent = uuid::Uuid::new_v4().to_string();
    let (_, missing) = request(
        router,
        Some(BOB),
        EXPORT,
        Some(json!({"memory_id":absent})),
        false,
    )
    .await;
    assert_refusal(&missing, &absent);

    for format in ["md", "json"] {
        for name in ["private", "shared"] {
            let id = f.id(name);
            let (status, denied) = request(
                router,
                Some(BOB),
                EXPORT,
                Some(json!({"memory_id":id,"format":format})),
                false,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
            assert_refusal(&denied, id);
            let (status, allowed) = request(
                router,
                Some(ALICE),
                EXPORT,
                Some(json!({"memory_id":id,"format":format})),
                false,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{allowed}");
            assert!(
                allowed["content"]
                    .as_str()
                    .expect("content")
                    .contains(SECRET)
            );
        }
    }
    let (status, denied) = request(
        router,
        Some(ALICE),
        EXPORT,
        Some(json!({"memory_id":f.id("private")})),
        true,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "forged owner via shared key: {denied}"
    );
    assert!(!denied.to_string().contains(SECRET));
    let (status, denied) = request(
        router,
        Some(BOB),
        EXPORT,
        Some(json!({"memory_id":f.id("private"),"agent_id":ALICE})),
        false,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "body principal spoof: {denied}"
    );
    assert!(!denied.to_string().contains(SECRET));
    let id = f.id("substrate-source");
    let (_, denied) = request(
        router,
        Some(ALICE),
        EXPORT,
        Some(json!({"memory_id":id})),
        false,
    )
    .await;
    assert_refusal(&denied, id);
}

async fn admin_cases(router: &axum::Router, f: &Fixture) {
    let id = f.id("private");
    let (status, allowed) = request(
        router,
        Some(ADMIN),
        EXPORT,
        Some(json!({"memory_id":id})),
        false,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "enrolled key-bound admin: {allowed}"
    );
    assert!(
        allowed["content"]
            .as_str()
            .expect("admin content")
            .contains(SECRET)
    );
    let (status, denied) = request(
        router,
        Some(ADMIN),
        EXPORT,
        Some(json!({"memory_id":id})),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "name-only admin: {denied}");
    assert!(!denied.to_string().contains(SECRET));
}

#[tokio::test]
async fn sqlite_http_visibility_admin_binding_and_zero_mutation_promotion() {
    let f = Fixture::new();
    let (router, _sidecar) = router(&f, StorageBackend::Sqlite, None, true);
    export_cases(&router, &f).await;
    admin_cases(&router, &f).await;
    let id = f.id("private");
    let path = format!("/api/v1/skill/{id}/promote");
    let args = json!({"name":"http-admin-skill", "description":"Admitted admin promotion."});
    for (caller, shared) in [(BOB, false), (ADMIN, true)] {
        let before = f.snapshot();
        let (status, denied) =
            request(&router, Some(caller), &path, Some(args.clone()), shared).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{denied}");
        assert_eq!(
            f.snapshot(),
            before,
            "refused promotion wrote bundle/resource/source"
        );
    }
    let missing_id = f.id("missing-source");
    let before = f.snapshot();
    let (status, denied) = request(
        &router,
        Some(ADMIN),
        &format!("/api/v1/skill/{missing_id}/promote"),
        Some(args.clone()),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{denied}");
    assert_refusal(&denied, missing_id);
    assert_eq!(f.snapshot(), before);
    let (_, denied) = request(
        &router,
        Some(ADMIN),
        EXPORT,
        Some(json!({"memory_id":missing_id})),
        false,
    )
    .await;
    assert_refusal(&denied, missing_id);
    let (status, allowed) = request(&router, Some(ADMIN), &path, Some(args), false).await;
    assert_eq!(status, StatusCode::OK, "{allowed}");
    assert_eq!(allowed["sources_attached"], 1);
    let conn = ai_memory::db::open(&f.path).expect("skill attribution");
    let actor: String = conn
        .query_row(
            "SELECT json_extract(metadata, '$.promoted_by') FROM skills WHERE id=?1",
            [allowed["skill_id"].as_str().expect("skill id")],
            |row| row.get(0),
        )
        .expect("actor");
    assert_eq!(actor, ADMIN);
}

#[tokio::test]
async fn key_bound_but_unenrolled_admin_has_no_export_bypass() {
    let f = Fixture::new();
    let (router, _sidecar) = router(&f, StorageBackend::Sqlite, None, false);
    let id = f.id("private");
    let (_, denied) = request(
        &router,
        Some(ADMIN),
        EXPORT,
        Some(json!({"memory_id":id})),
        false,
    )
    .await;
    assert_refusal(&denied, id);
}

#[cfg(feature = "sal-postgres")]
async fn pg_snapshot(pool: &sqlx::PgPool) -> Vec<(String, Option<Value>)> {
    let tables:Vec<String>=sqlx::query_scalar("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name")
        .fetch_all(pool).await.expect("PG table census");
    let mut rows = Vec::new();
    for table in tables {
        let quoted = table.replace('"', "\"\"");
        let value: Option<Value> = sqlx::query_scalar(&format!(
            "SELECT jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text) FROM public.\"{quoted}\" t"
        ))
        .fetch_one(pool)
        .await
        .expect("PG table snapshot");
        rows.push((table, value));
    }
    rows
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn native_pg_export_and_501_promotion_preserve_pg_and_scratch() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!(
            "skip: native_pg_export_and_501_promotion_preserve_pg_and_scratch requires certified PG"
        );
        return;
    };
    let f = Fixture::new();
    let store = Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("certified PG connection"),
    );
    assert_eq!(store.kg_backend(), ai_memory::store::KgBackend::Age);
    for memory in &f.memories {
        store
            .store(&CallerContext::for_agent(ALICE), memory)
            .await
            .expect("native PG row");
    }
    for link in &f.links {
        store
            .link(&CallerContext::for_agent(ALICE), link)
            .await
            .expect("native PG lineage");
    }
    let pool = sqlx::PgPool::connect(&url)
        .await
        .expect("direct PG evidence");
    let (router, sidecar) = router(&f, StorageBackend::Postgres, Some(store), true);
    export_cases(&router, &f).await;
    admin_cases(&router, &f).await;
    let scratch = ai_memory::db::open(&sidecar.path().join("empty.db")).expect("scratch");
    for caller in [BOB, ALICE, ADMIN] {
        let before_pg = pg_snapshot(&pool).await;
        let before_sqlite = snapshot(&scratch);
        let (status, refused) = request(
            &router,
            Some(caller),
            &format!("/api/v1/skill/{}/promote", f.id("private")),
            Some(json!({"name":"must-not-land","description":"PG promotion unsupported."})),
            false,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{refused}");
        assert!(!refused.to_string().contains(SECRET));
        assert_eq!(
            pg_snapshot(&pool).await,
            before_pg,
            "501 mutated PostgreSQL"
        );
        assert_eq!(
            snapshot(&scratch),
            before_sqlite,
            "501 mutated scratch SQLite"
        );
    }
    pool.close().await;
}
