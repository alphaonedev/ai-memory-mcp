// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3424 — `POST /api/v1/kg/query` must answer with ONE wire shape, whatever
//! the backend.
//!
//! `docs/API_REFERENCE.md` documents a NINE-field row. The sqlite branch
//! projected all nine from `models::KgQueryNode`; the postgres branch
//! hand-built a FOUR-field object (`target_id`, `relation`, `depth`, `path`),
//! silently dropping `title`, `target_namespace`, `valid_from`, `valid_until`
//! and `observed_by`. The root cause was one layer down: the SAL row type
//! `store::KgQueryRow` carried only those four fields, so the data never
//! reached the handler at all — the sqlite ADAPTER was discarding five values
//! it already had.
//!
//! The fix is one projection (`kg_query_memories_json`) called by both
//! branches, over a `KgQueryRow` that now mirrors `KgQueryNode`
//! field-for-field. This suite is the golden: it drives the SAME request
//! through BOTH handler lanes and asserts the responses are byte-identical,
//! so a future divergence fails here rather than at a consumer.
//!
//! The SQLite and fake-PG lanes exercise both dispatch arms. The live-PG
//! fixture seeds actual memories and an AGE edge, requires a nonempty result,
//! and compares all nine row values. Both routes also test owner access and
//! private-row denial; duplicate checks use an in-process embedding server.

#![cfg(feature = "sal")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{MemoryLink, MemoryLinkRelation};
use ai_memory::{db, models};

const CALLER: &str = "ai:alice@node";
const NS: &str = "kg3424";
const SRC: &str = "11111111-1111-4111-8111-111111111111";
const TGT: &str = "22222222-2222-4222-8222-222222222222";
const VALID_FROM: &str = "2026-01-01T00:00:00+00:00";
const VALID_UNTIL: &str = "2027-01-01T00:00:00+00:00";

/// The nine fields `docs/API_REFERENCE.md` documents for a `memories[]` row.
const DOCUMENTED_ROW_KEYS: [&str; 9] = [
    "depth",
    "observed_by",
    "path",
    "relation",
    "target_id",
    "target_namespace",
    "title",
    "valid_from",
    "valid_until",
];

fn seed(db_path: &std::path::Path) {
    let conn = db::open(db_path).expect("db::open");
    let now = "2026-01-01T00:00:00+00:00".to_string();
    for (id, title) in [(SRC, "the source memory"), (TGT, "the target memory")] {
        let mem = models::Memory {
            id: id.to_string(),
            tier: models::Tier::Long,
            namespace: NS.to_string(),
            title: title.to_string(),
            content: "body".to_string(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: json!({ "agent_id": CALLER, "scope": "private" }),
            ..models::Memory::default()
        };
        db::insert(&conn, &mem).expect("insert");
    }
    db::create_link_inbound(&conn, &fixture_link(), "unsigned").expect("create link");
}

fn fixture_link() -> MemoryLink {
    MemoryLink {
        source_id: SRC.to_string(),
        target_id: TGT.to_string(),
        relation: MemoryLinkRelation::DependsOn,
        created_at: VALID_FROM.to_string(),
        signature: None,
        observed_by: Some(CALLER.to_string()),
        valid_from: Some(VALID_FROM.to_string()),
        valid_until: Some(VALID_UNTIL.to_string()),
        attest_level: None,
        source_cid: None,
        target_cid: None,
    }
}

fn build_router(backend: StorageBackend) -> (axum::Router, NamedTempFile) {
    router_with(backend, None, None)
}

fn router_with(
    backend: StorageBackend,
    store_override: Option<Arc<dyn ai_memory::store::MemoryStore>>,
    embedder: Option<ai_memory::embeddings::Embedder>,
) -> (axum::Router, NamedTempFile) {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = db::open(&db_path).expect("db::open");
    seed(&db_path);
    let conn = db::open(&db_path).expect("reopen for AppState");
    let dbh: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    let app_state = AppState {
        db: dbh,
        embedder: Arc::new(embedder),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
        store: store_override.unwrap_or(store),
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
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), f)
}

async fn kg_query(router: &axum::Router) -> (StatusCode, Value) {
    post(
        router,
        CALLER,
        "/api/v1/kg/query",
        json!({ "source_id": SRC, "max_depth": 1 }),
    )
    .await
}

async fn post(router: &axum::Router, caller: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", caller)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn sorted_keys(v: &Value) -> Vec<String> {
    let mut k: Vec<String> = v.as_object().expect("object row").keys().cloned().collect();
    k.sort();
    k
}

// ---------------------------------------------------------------------------
// The golden: both lanes, one shape
// ---------------------------------------------------------------------------

/// Both dispatch arms preserve every documented row field and seeded value.
#[tokio::test]
async fn kg_query_row_shape_is_identical_on_both_backends_3424() {
    let (sqlite_router, _f1) = build_router(StorageBackend::Sqlite);
    let (pg_router, _f2) = build_router(StorageBackend::Postgres);

    let (s_status, s_body) = kg_query(&sqlite_router).await;
    let (p_status, p_body) = kg_query(&pg_router).await;
    assert_eq!(s_status, StatusCode::OK, "sqlite: {s_body}");
    assert_eq!(p_status, StatusCode::OK, "postgres: {p_body}");

    let s_rows = s_body["memories"].as_array().expect("sqlite memories");
    let p_rows = p_body["memories"].as_array().expect("postgres memories");
    assert_eq!(s_rows.len(), 1, "sqlite: {s_body}");
    assert_eq!(
        p_rows.len(),
        1,
        "postgres lane must return the same row set: {p_body}"
    );

    // The postgres lane used to emit exactly four keys here.
    assert_eq!(
        sorted_keys(&p_rows[0]),
        DOCUMENTED_ROW_KEYS
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>(),
        "postgres row key set is not the documented nine: {p_body}"
    );
    assert_eq!(
        sorted_keys(&s_rows[0]),
        sorted_keys(&p_rows[0]),
        "the two backends disagree on the row key set"
    );

    // Not just the key SET — the values must agree too, so a field that is
    // present-but-empty on one lane still fails.
    assert_eq!(
        s_rows[0], p_rows[0],
        "the two backends disagree on the row VALUES:\nsqlite  = {}\npostgres= {}",
        s_rows[0], p_rows[0]
    );

    // And the values are the seeded ones, so the assertion cannot pass by both
    // lanes being equally empty.
    let row = &p_rows[0];
    assert_eq!(row["target_id"].as_str(), Some(TGT), "{row}");
    assert_eq!(row["title"].as_str(), Some("the target memory"), "{row}");
    assert_eq!(row["target_namespace"].as_str(), Some(NS), "{row}");
    assert_eq!(row["relation"].as_str(), Some("depends_on"), "{row}");
    assert_eq!(row["valid_from"].as_str(), Some(VALID_FROM), "{row}");
    assert_eq!(row["valid_until"].as_str(), Some(VALID_UNTIL), "{row}");
    assert_eq!(row["observed_by"].as_str(), Some(CALLER), "{row}");
    assert_eq!(row["depth"].as_u64(), Some(1), "{row}");
    assert_eq!(
        row["path"].as_str(),
        Some(&*format!("{SRC}->{TGT}")),
        "{row}"
    );
}

/// The envelope around `memories` is also one shape.
#[tokio::test]
async fn kg_query_envelope_is_identical_on_both_backends_3424() {
    let (sqlite_router, _f1) = build_router(StorageBackend::Sqlite);
    let (pg_router, _f2) = build_router(StorageBackend::Postgres);
    let (_, s_body) = kg_query(&sqlite_router).await;
    let (_, p_body) = kg_query(&pg_router).await;

    assert_eq!(
        sorted_keys(&s_body),
        sorted_keys(&p_body),
        "envelope key sets differ:\nsqlite  = {s_body}\npostgres= {p_body}"
    );
    for k in ["source_id", "max_depth", "count"] {
        assert_eq!(s_body[k], p_body[k], "`{k}` differs: {s_body} vs {p_body}");
    }
}

/// The owner receives the complete row; another principal receives no row data.
#[tokio::test]
async fn kg_query_private_target_is_denied_on_both_backends_3424() {
    for backend in [StorageBackend::Sqlite, StorageBackend::Postgres] {
        let (router, _file) = build_router(backend);
        let (status, body) = post(
            &router,
            "ai:stranger",
            "/api/v1/kg/query",
            json!({"source_id": SRC, "max_depth": 1}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["memories"], json!([]), "{body}");
        assert_eq!(body["count"], 0, "{body}");
        assert!(!body.to_string().contains("the target memory"), "{body}");
    }
}

async fn embedder() -> (ai_memory::embeddings::Embedder, wiremock::MockServer) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/tags"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"models": []})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/embed"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"embeddings": [vec![0.5_f32; 768]]})),
        )
        .mount(&server)
        .await;
    let uri = server.uri();
    let client = tokio::task::spawn_blocking(move || {
        ai_memory::llm::OllamaClient::new_with_url(&uri, "test-model").expect("mock client")
    })
    .await
    .expect("client task");
    (
        ai_memory::embeddings::Embedder::new_ollama(Arc::new(client)),
        server,
    )
}

async fn duplicate(router: &axum::Router, caller: &str) -> Value {
    let (status, mut body) = post(
        router,
        caller,
        "/api/v1/check_duplicate",
        json!({
            "title": "the target memory", "content": "body", "namespace": NS, "threshold": 0.85
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Existing additive diagnostic is outside the documented response contract.
    body.as_object_mut()
        .expect("object")
        .remove("storage_backend");
    body
}

fn assert_duplicate_allowed(body: &Value) {
    assert_eq!(body["is_duplicate"], true, "{body}");
    assert_eq!(body["suggested_merge"], TGT, "{body}");
    assert_eq!(
        body["nearest"],
        json!({"id": TGT, "title": "the target memory", "namespace": NS, "similarity": 1.0})
    );
    assert_eq!(body["candidates_scanned"], 2, "{body}");
}

fn assert_duplicate_denied(body: &Value) {
    assert_eq!(body["is_duplicate"], false, "{body}");
    assert!(body["nearest"].is_null(), "{body}");
    assert!(body["suggested_merge"].is_null(), "{body}");
    assert!(!body.to_string().contains(TGT), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_allowed_and_denied_wire_parity_3424() {
    let (emb, _server) = embedder().await;
    let (sqlite, _s_file) = router_with(StorageBackend::Sqlite, None, Some(emb.clone()));
    let (pg, _p_file) = router_with(StorageBackend::Postgres, None, Some(emb));
    let allowed = duplicate(&sqlite, CALLER).await;
    assert_duplicate_allowed(&allowed);
    assert_eq!(allowed, duplicate(&pg, CALLER).await);
    let denied = duplicate(&sqlite, "ai:stranger").await;
    assert_duplicate_denied(&denied);
    assert_eq!(denied, duplicate(&pg, "ai:stranger").await);
}

#[cfg(feature = "sal-postgres")]
mod live_pg {
    use super::*;
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, KgBackend, MemoryStore};

    async fn seeded() -> Option<(Arc<PostgresStore>, sqlx::PgPool)> {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: live #3424 requires AI_MEMORY_TEST_POSTGRES_URL");
            return None;
        };
        let store = Arc::new(
            PostgresStore::connect(&url)
                .await
                .expect("live PostgreSQL connection"),
        );
        assert_eq!(
            store.kg_backend(),
            KgBackend::Age,
            "certified AGE tier required"
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("fixture pool");
        let f = NamedTempFile::new().unwrap();
        seed(f.path());
        let conn = db::open(f.path()).unwrap();
        let ctx = CallerContext::for_agent(CALLER);
        for id in [SRC, TGT] {
            let mem = db::get(&conn, id).unwrap().unwrap();
            store
                .store(&ctx, &mem)
                .await
                .expect("seed PostgreSQL memory");
        }
        store
            .link(&ctx, &fixture_link())
            .await
            .expect("seed relational and AGE edge");
        // Unsigned local link writes deliberately clear observer claims. Seed
        // the retained inbound attribution to exercise its read projection.
        sqlx::query("UPDATE memory_links SET observed_by=$3 WHERE source_id=$1 AND target_id=$2")
            .bind(SRC)
            .bind(TGT)
            .bind(CALLER)
            .execute(&pool)
            .await
            .expect("seed observer");

        Some((store, pool))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_postgres_allowed_denied_and_wire_parity_3424() {
        let Some((store, pool)) = seeded().await else {
            return;
        };
        let (emb, _server) = embedder().await;
        let (sqlite, _s_file) = router_with(StorageBackend::Sqlite, None, Some(emb.clone()));
        let (pg, _p_file) = router_with(StorageBackend::Postgres, Some(store.clone()), Some(emb));
        let (s_status, s_body) = kg_query(&sqlite).await;
        let (p_status, p_body) = kg_query(&pg).await;
        assert_eq!(s_status, StatusCode::OK, "{s_body}");
        assert_eq!(p_status, StatusCode::OK, "{p_body}");
        assert_eq!(
            p_body["count"], 1,
            "live fixture must traverse a real edge: {p_body}"
        );
        assert_eq!(s_body["memories"], p_body["memories"]);
        assert_eq!(sorted_keys(&p_body["memories"][0]), DOCUMENTED_ROW_KEYS);
        for router in [&sqlite, &pg] {
            let (status, body) = post(
                router,
                "ai:stranger",
                "/api/v1/kg/query",
                json!({"source_id": SRC}),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["count"], 0, "{body}");
            assert_eq!(body["memories"], json!([]));
        }
        let allowed = duplicate(&sqlite, CALLER).await;
        assert_duplicate_allowed(&allowed);
        assert_eq!(allowed, duplicate(&pg, CALLER).await);
        let denied = duplicate(&sqlite, "ai:stranger").await;
        assert_duplicate_denied(&denied);
        assert_eq!(denied, duplicate(&pg, "ai:stranger").await);
        // Two relations between the same vertices must retain their own attribution.
        sqlx::query("INSERT INTO memory_links (source_id, target_id, relation, observed_by) VALUES ($1, $2, 'related_to', 'ai:other')")
            .bind(SRC).bind(TGT).execute(&pool).await.expect("parallel relation");
        let rows = store.kg_query_cte(SRC, 1).await.expect("hydrated CTE");
        assert!(!rows.is_empty());
        for row in rows {
            let observer = if row.relation == "depends_on" {
                CALLER
            } else {
                "ai:other"
            };
            assert_eq!(row.observed_by.as_deref(), Some(observer), "{row:?}");
        }
        sqlx::query("DELETE FROM memory_links WHERE source_id=$1 AND target_id=$2 AND relation='related_to'")
            .bind(SRC).bind(TGT).execute(&pool).await.expect("remove parallel edge");
        pool.close().await;
    }
}
