// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3380: source admission before summaries and destructive consolidation.
use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::{Memory, Tier};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;
const CALLER: &str = "ai:consolidator3380";
struct Fixture {
    router: axum::Router,
    file: NamedTempFile,
    #[cfg(feature = "sal-postgres")]
    pg: Option<Arc<ai_memory::store::postgres::PostgresStore>>,
}
#[cfg_attr(not(feature = "sal-postgres"), allow(clippy::unused_async))]
async fn fixture(pg_url: Option<&str>) -> Fixture {
    let file = NamedTempFile::new().expect("tempfile");
    let db_path = file.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("open SQLite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let storage_backend = if pg_url.is_some() {
        StorageBackend::Postgres
    } else {
        StorageBackend::Sqlite
    };
    #[cfg(feature = "sal-postgres")]
    let pg = if let Some(url) = pg_url {
        Some(Arc::new(
            ai_memory::store::postgres::PostgresStore::connect(url)
                .await
                .expect("connect live PostgreSQL"),
        ))
    } else {
        None
    };
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> = {
        #[cfg(feature = "sal-postgres")]
        if let Some(pg) = &pg {
            let store = Arc::clone(pg);
            return build(file, db, storage_backend, store, Some(Arc::clone(pg)));
        }
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SAL SQLite"))
    };
    build(
        file,
        db,
        storage_backend,
        #[cfg(feature = "sal")]
        store,
        #[cfg(feature = "sal-postgres")]
        None,
    )
}
fn build(
    file: NamedTempFile,
    db: Db,
    storage_backend: StorageBackend,
    #[cfg(feature = "sal")] store: Arc<dyn ai_memory::store::MemoryStore>,
    #[cfg(feature = "sal-postgres")] pg: Option<Arc<ai_memory::store::postgres::PostgresStore>>,
) -> Fixture {
    let app_state = AppState {
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
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
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
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(
            ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
        ),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    Fixture {
        router: ai_memory::build_router(api_key_state, app_state),
        file,
        #[cfg(feature = "sal-postgres")]
        pg,
    }
}

#[cfg_attr(not(feature = "sal-postgres"), allow(clippy::unused_async))]
async fn seed(f: &Fixture, namespace: &str, metadata: Value) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: namespace.into(),
        tier: Tier::Mid,
        title: format!("source {}", uuid::Uuid::new_v4()),
        content: "confidential source body for consolidation".into(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        ..Memory::default()
    };
    #[cfg(feature = "sal-postgres")]
    if let Some(pg) = &f.pg {
        use ai_memory::store::MemoryStore as _;
        pg.store(
            &ai_memory::store::CallerContext::for_admin("fixture-3380"),
            &mem,
        )
        .await
        .expect("seed PostgreSQL");
        return mem.id;
    }
    let conn = ai_memory::db::open(f.file.path()).expect("open seed SQLite");
    ai_memory::db::insert(&conn, &mem).expect("seed SQLite")
}

#[cfg_attr(not(feature = "sal-postgres"), allow(clippy::unused_async))]
async fn snapshot(f: &Fixture) -> Value {
    #[cfg(feature = "sal-postgres")]
    if let Some(pg) = &f.pg {
        let memories = sqlx::query_scalar::<_, Value>(
            "SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY id), '[]'::jsonb) FROM memories m",
        )
        .fetch_one(pg.pool())
        .await
        .expect("snapshot PostgreSQL");
        let links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memory_links")
            .fetch_one(pg.pool())
            .await
            .expect("snapshot PostgreSQL links");
        return json!({"memories": memories, "links": links});
    }
    let conn = ai_memory::db::open(f.file.path()).expect("snapshot SQLite");
    let mut stmt = conn
        .prepare("SELECT id, content, lifecycle_state, updated_at FROM memories ORDER BY id")
        .expect("prepare");
    let rows: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!([
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?
            ]))
        })
        .expect("rows")
        .map(|row| row.expect("row"))
        .collect();
    let links: i64 = conn
        .query_row("SELECT COUNT(*) FROM memory_links", [], |r| r.get(0))
        .expect("snapshot SQLite links");
    json!({"memories": rows, "links": links})
}

async fn call(
    f: &Fixture,
    ids: &[String],
    namespace: Option<&str>,
    summary: bool,
) -> (StatusCode, Value) {
    let mut body = json!({"ids": ids, "title": format!("merged {}", uuid::Uuid::new_v4())});
    if let Some(ns) = namespace {
        body["namespace"] = json!(ns);
    }
    if summary {
        body["summary"] = json!("A supplied summary of the source observations.");
    }
    let response = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/consolidate")
                .header(ai_memory::HEADER_AGENT_ID, CALLER)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).expect("serialize")))
                .expect("request"),
        )
        .await
        .expect("route");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).expect("JSON response"),
    )
}

async fn source_matrix(f: &Fixture) {
    let ns = format!("consolidate-3380-{}", uuid::Uuid::new_v4());
    let own = seed(f, &ns, json!({"agent_id": CALLER, "scope": "private"})).await;
    let private = seed(
        f,
        &ns,
        json!({"agent_id": "ai:foreign", "scope": "private"}),
    )
    .await;
    let collective = seed(
        f,
        &ns,
        json!({"agent_id": "ai:foreign", "scope": "collective"}),
    )
    .await;
    let unowned = seed(f, &ns, json!({})).await;
    let substrate = seed(
        f,
        "_agents",
        json!({"agent_id": CALLER, "scope": "private"}),
    )
    .await;
    let inbox = seed(
        f,
        "_messages/ai:consolidator3380",
        json!({"agent_id": "ai:foreign", "target_agent_id": CALLER, "scope": "private"}),
    )
    .await;
    let absent = uuid::Uuid::new_v4().to_string();
    for supplied in [false, true] {
        for (id, namespace, status) in [
            (&private, Some(ns.as_str()), StatusCode::NOT_FOUND),
            (&absent, Some(ns.as_str()), StatusCode::NOT_FOUND),
            (&unowned, Some(ns.as_str()), StatusCode::NOT_FOUND),
            (&collective, Some(ns.as_str()), StatusCode::FORBIDDEN),
            (&substrate, None, StatusCode::NOT_FOUND),
            (&substrate, Some(ns.as_str()), StatusCode::NOT_FOUND),
            (
                &inbox,
                Some("_messages/ai:consolidator3380"),
                StatusCode::FORBIDDEN,
            ),
        ] {
            let before = snapshot(f).await;
            let (actual, body) = call(f, &[own.clone(), id.clone()], namespace, supplied).await;
            assert_eq!(actual, status, "id={id} body={body}");
            let error = if status == StatusCode::NOT_FOUND {
                ai_memory::errors::msg::memory_not_found(id)
            } else {
                ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY.into()
            };
            assert_eq!(body, json!({"error": error}));
            assert_eq!(
                snapshot(f).await,
                before,
                "refusal must not change sources or create output"
            );
        }
        let a = seed(f, &ns, json!({"agent_id": CALLER, "scope": "private"})).await;
        let b = seed(f, &ns, json!({"agent_id": CALLER, "scope": "private"})).await;
        let (status, body) = call(f, &[a, b], Some(&ns), supplied).await;
        assert_eq!(status, StatusCode::CREATED, "owner body={body}");
        assert_eq!(body["consolidated"], 2);
        let a = seed(
            f,
            "_agents",
            json!({"agent_id": CALLER, "scope": "private"}),
        )
        .await;
        let b = seed(
            f,
            "_agents",
            json!({"agent_id": CALLER, "scope": "private"}),
        )
        .await;
        let (status, body) = call(f, &[a, b], Some("_agents"), supplied).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "explicit substrate owner body={body}"
        );
    }
}

#[tokio::test]
async fn sqlite_source_admission_3380() {
    source_matrix(&fixture(None).await).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn live_pg_source_admission_3380() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: live_pg_source_admission_3380: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    source_matrix(&fixture(Some(&url)).await).await;
}

#[test]
fn mcp_and_cli_consolidation_remain_sqlite_only_3380() {
    let source = include_str!("../src/mcp/mod.rs");
    let dispatch = source
        .split("fn dispatch_memory_consolidate(")
        .nth(1)
        .expect("dispatch")
        .split("fn dispatch_memory_atomise(")
        .next()
        .expect("next dispatch");
    assert!(dispatch.contains("ctx.conn"));
    assert!(!dispatch.contains("ctx.store"));
    let handler = include_str!("../src/mcp/tools/consolidate.rs");
    assert!(handler.contains("conn: &rusqlite::Connection"));
    assert!(!handler.contains("Postgres"));
    let cli = include_str!("../src/cli/consolidate.rs");
    assert!(cli.contains("refuse_pg_store(db_path, \"consolidate\", out)"));
    assert!(cli.contains("refuse_pg_store(db_path, \"auto-consolidate\", out)"));
}

#[tokio::test]
async fn cli_explicit_source_admission_3380() {
    use ai_memory::cli::consolidate::{ConsolidateArgs, run};
    let f = fixture(None).await;
    let ns = "cli-consolidate-3380";
    let own = seed(&f, ns, json!({"agent_id": CALLER})).await;
    for (source_ns, metadata, requested, ownership_error) in [
        (
            ns,
            json!({"agent_id": "ai:foreign", "scope": "private"}),
            Some(ns),
            false,
        ),
        (
            ns,
            json!({"agent_id": "ai:foreign", "scope": "collective"}),
            Some(ns),
            true,
        ),
        ("_agents", json!({"agent_id": CALLER}), None, false),
        (
            "_messages/ai:consolidator3380",
            json!({"agent_id": "ai:foreign", "target_agent_id": CALLER}),
            Some("_messages/ai:consolidator3380"),
            true,
        ),
    ] {
        let source = seed(&f, source_ns, metadata).await;
        let before = snapshot(&f).await;
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let result = run(
            f.file.path(),
            ConsolidateArgs {
                ids: format!("{own},{source}"),
                title: "CLI merge".into(),
                summary: "A supplied summary of these source observations.".into(),
                namespace: requested.map(str::to_owned),
            },
            true,
            Some(CALLER),
            &mut ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr),
        );
        let expected = if ownership_error {
            ai_memory::errors::msg::CALLER_DOES_NOT_OWN_MEMORY.into()
        } else {
            ai_memory::errors::msg::memory_not_found(&source)
        };
        assert_eq!(result.expect_err("CLI must refuse").to_string(), expected);
        assert!(stdout.is_empty(), "denial must not print sources");
        assert_eq!(snapshot(&f).await, before);
    }
    for namespace in [ns, "_agents"] {
        let a = seed(&f, namespace, json!({"agent_id": CALLER})).await;
        let b = seed(&f, namespace, json!({"agent_id": CALLER})).await;
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        run(
            f.file.path(),
            ConsolidateArgs {
                ids: format!("{a},{b}"),
                title: "CLI owner merge".into(),
                summary: "A supplied summary of these source observations.".into(),
                namespace: Some(namespace.into()),
            },
            true,
            Some(CALLER),
            &mut ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr),
        )
        .expect("CLI owner succeeds");
        let body: Value = serde_json::from_slice(&stdout).expect("CLI JSON");
        assert_eq!(body["consolidated"], 2);
    }
}

#[tokio::test]
async fn cli_auto_source_admission_and_dry_run_3380() {
    use ai_memory::cli::consolidate::{AutoConsolidateArgs, run_auto};
    let f = fixture(None).await;
    let ns = "cli-auto-consolidate-3380";
    let own = seed(&f, ns, json!({"agent_id": CALLER})).await;
    let foreign = seed(
        &f,
        ns,
        json!({"agent_id": "ai:foreign", "scope": "collective"}),
    )
    .await;
    let _private = seed(
        &f,
        ns,
        json!({"agent_id": "ai:foreign", "scope": "private"}),
    )
    .await;
    let _substrate = seed(&f, "_agents", json!({"agent_id": CALLER})).await;
    let invoke = |dry_run, namespace: Option<&str>| {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        run_auto(
            f.file.path(),
            &AutoConsolidateArgs {
                namespace: namespace.map(str::to_owned),
                short_only: false,
                min_count: 2,
                dry_run,
            },
            true,
            Some(CALLER),
            &mut ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr),
        )
        .expect("CLI auto scan");
        serde_json::from_slice::<Value>(&stdout).expect("CLI JSON")
    };
    for namespace in [None, Some(ns)] {
        for dry_run in [false, true] {
            let before = snapshot(&f).await;
            let body = invoke(dry_run, namespace);
            assert_eq!(
                body,
                if dry_run {
                    json!({"dry_run": true, "groups": []})
                } else {
                    json!({"consolidated": 0})
                }
            );
            assert_eq!(
                snapshot(&f).await,
                before,
                "non-owner rows are not candidates"
            );
        }
    }
    let _second = seed(&f, ns, json!({"agent_id": CALLER})).await;
    assert_eq!(invoke(false, Some(ns))["consolidated"], 2);
    let conn = ai_memory::db::open(f.file.path()).expect("inspect sources");
    assert!(
        ai_memory::db::get(&conn, &foreign)
            .expect("foreign source")
            .is_some()
    );
    assert!(
        ai_memory::db::get(&conn, &own)
            .expect("owner source")
            .is_none()
    );
}
