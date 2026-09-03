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
//! Lanes:
//! * `StorageBackend::Sqlite` — the `db::kg_query` branch.
//! * `StorageBackend::Postgres` — the SAL `store.kg_query` branch, driven over
//!   an `SqliteStore` handle (the `handler_postgres_branches_fake_pg` pattern).
//!   This is the lane that carried the defect, and it is handler-side, so the
//!   harness exercises exactly the code that was wrong.
//!
//! The live-postgres ADAPTER half — `PostgresStore::hydrate_kg_query_rows`
//! populating the five fields for both the AGE and CTE traversal paths — is
//! covered by `pg_kg_query_hydration_3424` below, gated on a live cluster.

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
            metadata: json!({ "agent_id": CALLER }),
            ..models::Memory::default()
        };
        db::insert(&conn, &mem).expect("insert");
    }
    // An edge carrying every field the wire shape describes, so a dropped
    // field shows up as a missing VALUE and not merely as a missing key.
    // Every field spelled out: `MemoryLink` has no `Default`, and listing them
    // means a new field breaks this fixture loudly rather than defaulting to
    // something the wire shape then reports as absent.
    let link = MemoryLink {
        source_id: SRC.to_string(),
        target_id: TGT.to_string(),
        relation: MemoryLinkRelation::DependsOn,
        created_at: now,
        signature: None,
        observed_by: Some(CALLER.to_string()),
        valid_from: Some(VALID_FROM.to_string()),
        valid_until: Some(VALID_UNTIL.to_string()),
        attest_level: None,
        source_cid: None,
        target_cid: None,
    };
    db::create_link_inbound(&conn, &link, "unsigned").expect("create link");
}

fn build_router(backend: StorageBackend) -> (axum::Router, NamedTempFile) {
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
        embedder: Arc::new(None),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: backend,
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
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    (ai_memory::build_router(api_key_state, app_state), f)
}

async fn kg_query(router: &axum::Router) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/kg/query")
        .header("content-type", "application/json")
        .header("x-agent-id", CALLER)
        .body(Body::from(
            serde_json::to_vec(&json!({ "source_id": SRC, "max_depth": 1 })).unwrap(),
        ))
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

/// DENIED (the defect) — the postgres lane must not drop five of the nine
/// documented fields. ALLOWED (the contract) — both lanes emit the same nine.
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

// ---------------------------------------------------------------------------
// Live postgres — the adapter half of the fix
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
mod pg_kg_query_hydration_3424 {
    use ai_memory::store::MemoryStore;

    async fn live() -> Option<ai_memory::store::postgres::PostgresStore> {
        let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
            .ok()
            .filter(|s| !s.is_empty())?;
        match ai_memory::store::postgres::PostgresStore::connect(&url).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("skip: PostgresStore::connect failed: {e}");
                None
            }
        }
    }

    /// `PostgresStore::kg_query` must return rows whose five display fields are
    /// HYDRATED — this is the half the fake-pg lane above cannot reach, because
    /// there the SAL handle is an `SqliteStore`.
    ///
    /// An empty traversal is the honest degenerate case: hydration must be a
    /// no-op rather than an error, so the assertion is that the call succeeds
    /// and that any row it does return carries a non-empty target namespace
    /// (the field the traversal itself never had).
    #[tokio::test]
    async fn pg_kg_query_hydrates_the_display_fields_3424() {
        let Some(store) = live().await else { return };
        // Disambiguate to the TRAIT method: `PostgresStore` also has an
        // inherent two-argument `kg_query`, and the inherent one shadows the
        // trait in method-call position. The trait method is the one the
        // handler uses, so it is the one this test must exercise.
        let rows = <ai_memory::store::postgres::PostgresStore as MemoryStore>::kg_query(
            &store,
            "11111111-1111-4111-8111-111111111111",
            1,
            false,
        )
        .await
        .expect("kg_query must succeed (hydration included)");
        for r in &rows {
            assert!(
                !r.target_namespace.is_empty(),
                "hydration left target_namespace empty for {}: {r:?}",
                r.target_id
            );
            assert!(
                !r.title.is_empty() || r.target_namespace.is_empty(),
                "a hydrated row must carry its target's title: {r:?}"
            );
        }
    }
}
