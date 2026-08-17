// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 P0-1 (#1869) — recall-purity kill-test, postgres half +
//! cross-backend fold parity (RQ-PARITY style).
//!
//! `#[ignore]` + `sal-postgres`; CI-run via the
//! `.github/workflows/postgres-parity-nightly.yml` allowlist (an
//! in-crate `live_` test never runs in CI — vote condition 3). Run
//! locally with:
//! ```text
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://... \
//!   cargo test --features sal-postgres --test recall_purity_p01_postgres \
//!   -- --include-ignored --test-threads=1
//! ```
//!
//! Covered:
//! * pure default purity through the SAL `recall_hybrid` entry path
//!   AND the real HTTP handler (postgres branch of
//!   `handlers::recall`), full-schema dump-compare over EVERY table
//!   except the sanctioned `recall_observations` ledger;
//! * RQ-PARITY: an identical ledger fixture folded on both backends
//!   yields identical `(access_count, tier, priority,
//!   expires_at-is-null, confidence)` tuples — including an
//!   `AI_MEMORY_CONFIDENCE_DECAY=1` case with timestamp
//!   normalization, and an n>=5 single-window fixture crossing BOTH
//!   the promotion threshold and a priority decade (where
//!   set-based-vs-loop ladder divergence hides);
//! * fold-before-gc: a recalled row expiring inside the fold interval
//!   is retained after fold + `run_gc`, while an un-recalled control
//!   twin expires.

#![cfg(feature = "sal-postgres")]

mod common;

use std::sync::{Mutex, MutexGuard, OnceLock};

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};
use common::postgres_env::PostgresTestEnv;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn clear_flags() {
    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::remove_var("AI_MEMORY_CONFIDENCE_DECAY");
    }
}

fn mem(ns: &str, title: &str, content: &str, tier: Tier) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let expires = match tier {
        Tier::Long => None,
        _ => Some((chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339()),
    };
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: content.to_string(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test-p01".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: expires,
        // Collective scope: visible to the synthesized-anonymous HTTP
        // principal (see the sqlite twin for the rationale).
        metadata: json!({ "agent_id": "ai:test:p01", "scope": "collective" }),
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

/// Content dump of every BASE TABLE in the test schema except
/// `recall_observations`: one sorted `row::text` aggregate per table.
async fn dump_all_but_ledger(pool: &sqlx::PgPool, schema: &str) -> String {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM information_schema.tables
         WHERE table_schema = $1 AND table_type = 'BASE TABLE'
           AND table_name != 'recall_observations'
         ORDER BY table_name",
    )
    .bind(schema)
    .fetch_all(pool)
    .await
    .expect("list tables");
    let mut out = String::new();
    for t in &tables {
        let rows: String = sqlx::query_scalar(&format!(
            "SELECT COALESCE(string_agg(t::text, E'\\n' ORDER BY t::text), '') \
             FROM \"{schema}\".\"{t}\" t"
        ))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("dump {t}: {e}"));
        out.push_str(t);
        out.push('\n');
        out.push_str(&rows);
        out.push('\n');
    }
    out
}

async fn ledger_counts(pool: &sqlx::PgPool) -> (i64, i64) {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recall_observations")
        .fetch_one(pool)
        .await
        .unwrap();
    let unfolded: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM recall_observations WHERE NOT folded")
            .fetch_one(pool)
            .await
            .unwrap();
    (total, unfolded)
}

async fn inspection_pool(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .expect("inspection pool")
}

// =====================================================================
// A — purity through SAL recall_hybrid + the real HTTP handler
// =====================================================================

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
// M-LINT-OVERRIDE-EXPECT — the env-serialization guard MUST span the
// test body (recall paths read the flags internally, including across
// awaits); each test runs on its own thread + runtime, so a blocked
// std::Mutex merely parks that test thread.
#[expect(clippy::await_holding_lock)]
async fn postgres_recall_purity_sal_and_http_entry_paths() {
    let _g = env_lock();
    clear_flags();
    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("p01_purity").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(env.url()).await.expect("connect");
    let admin = CallerContext::for_admin("operator:p01");
    let ns = "p01-purity-ns";
    let mut ids = Vec::new();
    for i in 0..12 {
        let tier = match i % 3 {
            0 => Tier::Short,
            1 => Tier::Mid,
            _ => Tier::Long,
        };
        let m = mem(
            ns,
            &format!("purityfox pg {i}"),
            &format!("purityfox content {i}"),
            tier,
        );
        ids.push(store.store(&admin, &m).await.expect("store"));
    }

    let pool = inspection_pool(env.url()).await;
    let pre_dump = dump_all_but_ledger(&pool, env.schema_name()).await;
    let (pre_total, _) = ledger_counts(&pool).await;
    let mut expected_growth: i64 = 0;

    // ---- SAL entry path (recall_hybrid) — pure read on postgres. ----
    let ctx = CallerContext::for_agent("ai:test:p01");
    let filter = Filter {
        namespace: Some(ns.to_string()),
        limit: 10,
        ..Default::default()
    };
    let mut first_ids: Option<Vec<String>> = None;
    for _ in 0..10 {
        let rows = store
            .recall_hybrid(&ctx, "purityfox", None, &filter)
            .await
            .expect("sal recall_hybrid");
        assert!(!rows.is_empty(), "SAL recall must return the corpus");
        let got: Vec<String> = rows.iter().map(|(m, _)| m.id.clone()).collect();
        match &first_ids {
            None => first_ids = Some(got),
            Some(prev) => assert_eq!(prev, &got, "SAL result set drifted"),
        }
    }

    // ---- HTTP entry path (postgres branch of handlers::recall). ----
    {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt as _;

        let sqlite_dir = tempfile::tempdir().expect("tempdir");
        let sqlite_path = sqlite_dir.path().join("p01-http.db");
        let db: ai_memory::handlers::Db = std::sync::Arc::new(tokio::sync::Mutex::new((
            ai_memory::db::open(&sqlite_path).expect("sqlite open"),
            sqlite_path.clone(),
            ai_memory::config::ResolvedTtl::default(),
            true,
        )));
        let store_arc: std::sync::Arc<dyn MemoryStore> = std::sync::Arc::new(
            PostgresStore::connect(env.url())
                .await
                .expect("connect http store"),
        );
        let app_state = ai_memory::handlers::AppState {
            db,
            embedder: std::sync::Arc::new(None),
            vector_index: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            federation: std::sync::Arc::new(None),
            tier_config: std::sync::Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
            scoring: std::sync::Arc::new(ai_memory::config::ResolvedScoring::default()),
            profile: std::sync::Arc::new(ai_memory::profile::Profile::core()),
            mcp_config: std::sync::Arc::new(None),
            active_keypair: std::sync::Arc::new(None),
            family_embeddings: std::sync::Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
            storage_backend: ai_memory::handlers::StorageBackend::Postgres,
            store: store_arc,
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
            enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
            http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
        };
        let router = ai_memory::build_router(
            ai_memory::handlers::ApiKeyState {
                key: None,
                mtls_enforced: false,
                enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
                identity_mode: ai_memory::config::HttpIdentityMode::default(),
            },
            app_state,
        );
        for _ in 0..10 {
            let resp = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/api/v1/recall?context=purityfox&namespace={ns}&limit=10"
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let mems = v["memories"].as_array().expect("memories");
            assert!(
                !mems.is_empty(),
                "HTTP pg recall must return the corpus: {v}"
            );
            assert_eq!(v["storage_backend"], "postgres");
            expected_growth += i64::try_from(mems.len()).unwrap();
        }
    }

    // (a) Zero row deltas anywhere but the ledger.
    let post_dump = dump_all_but_ledger(&pool, env.schema_name()).await;
    assert_eq!(
        pre_dump, post_dump,
        "PURITY VIOLATION (postgres): recall mutated a table other than recall_observations"
    );
    // (c) Ledger grew by exactly the HTTP returned-row total (the SAL
    // trait recall itself does not append on postgres — the handler
    // does), every row unfolded in the pure default.
    let (post_total, unfolded) = ledger_counts(&pool).await;
    assert_eq!(post_total - pre_total, expected_growth);
    assert_eq!(unfolded, expected_growth);
    drop(pool);
}

// =====================================================================
// B — RQ-PARITY: identical ledger fixture folds identically on both
// backends (promotion + decade crossing in a single window, plus a
// decay-enabled case with timestamp normalization).
// =====================================================================

struct FoldedRow {
    access_count: i64,
    tier: String,
    priority: i64,
    expires_is_null: bool,
    confidence: f64,
    confidence_source: String,
}

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
// M-LINT-OVERRIDE-EXPECT — the env-serialization guard MUST span the
// test body (recall paths read the flags internally, including across
// awaits); each test runs on its own thread + runtime, so a blocked
// std::Mutex merely parks that test thread.
#[expect(clippy::await_holding_lock)]
async fn postgres_sqlite_fold_parity_promotion_decade_and_decay() {
    let _g = env_lock();
    clear_flags();
    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("p01_parity").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(env.url()).await.expect("connect");
    let pool = inspection_pool(env.url()).await;
    let admin = CallerContext::for_admin("operator:p01");

    // The divergence-hiding fixture: mid tier, access_count 2, 9
    // observations in ONE fold window → crosses the promotion
    // threshold (5) AND the 10-access decade. Decay case: aged anchor
    // + AI_MEMORY_CONFIDENCE_DECAY=1.
    let sqlite_dir = tempfile::tempdir().expect("tempdir");
    let sqlite_conn =
        ai_memory::db::open(&sqlite_dir.path().join("parity.db")).expect("sqlite open");

    // -- seed both backends identically --
    let created = "2025-06-01T00:00:00Z";
    let mut fixture = mem(
        "p01-parity",
        "parityfox row",
        "parityfox content",
        Tier::Mid,
    );
    fixture.confidence = 0.9;
    fixture.created_at = created.to_string();
    fixture.updated_at = created.to_string();
    let pg_id = store.store(&admin, &fixture).await.expect("pg store");
    sqlx::query(
        "UPDATE memories SET access_count = 2, priority = 5, created_at = $2::timestamptz, \
         confidence = 0.9, confidence_decayed_at = NULL WHERE id = $1",
    )
    .bind(&pg_id)
    .bind(created)
    .execute(&pool)
    .await
    .expect("pg fixture shape");
    let sq_id = ai_memory::db::insert(&sqlite_conn, &fixture).expect("sqlite insert");
    sqlite_conn
        .execute(
            "UPDATE memories SET access_count = 2, priority = 5, created_at = ?2, \
             confidence = 0.9, confidence_decayed_at = NULL WHERE id = ?1",
            rusqlite::params![sq_id, created],
        )
        .expect("sqlite fixture shape");

    // -- identical ledger fixture: 9 observations per backend --
    for k in 0..9 {
        store
            .record_recall_observation(
                &format!("parity-r{k}"),
                &[(pg_id.clone(), "fts5".to_string(), 1, 0.5)],
                None,
                None,
            )
            .await
            .expect("pg ledger row");
        ai_memory::observations::record_recall(
            &sqlite_conn,
            &format!("parity-r{k}"),
            &[ai_memory::observations::Candidate {
                memory_id: &sq_id,
                retriever: "fts5",
                rank: 1,
                score: 0.5,
            }],
        )
        .expect("sqlite ledger row");
    }

    // -- decay-enabled fold on BOTH backends --
    // SAFETY: serialized via env_lock.
    unsafe { std::env::set_var("AI_MEMORY_CONFIDENCE_DECAY", "1") };
    let pg_folded = store.fold_recall_accesses().await.expect("pg fold");
    assert_eq!(pg_folded, 1);
    let sq_folded =
        ai_memory::db::fold_recall_accesses(&sqlite_conn, crate_short_extend(), crate_mid_extend())
            .expect("sqlite fold");
    assert_eq!(sq_folded, 1);
    // SAFETY: serialized via env_lock.
    unsafe { std::env::remove_var("AI_MEMORY_CONFIDENCE_DECAY") };

    // -- compare the folded tuples --
    let pg_row: (
        i64,
        String,
        i32,
        Option<chrono::DateTime<chrono::Utc>>,
        f64,
        String,
    ) = sqlx::query_as(
        "SELECT access_count, tier, priority, expires_at, confidence, confidence_source \
             FROM memories WHERE id = $1",
    )
    .bind(&pg_id)
    .fetch_one(&pool)
    .await
    .expect("pg read");
    let pg = FoldedRow {
        access_count: pg_row.0,
        tier: pg_row.1,
        priority: i64::from(pg_row.2),
        expires_is_null: pg_row.3.is_none(),
        confidence: pg_row.4,
        confidence_source: pg_row.5,
    };
    let sq = sqlite_conn
        .query_row(
            "SELECT access_count, tier, priority, expires_at, confidence, confidence_source \
             FROM memories WHERE id = ?1",
            [sq_id.as_str()],
            |r| {
                Ok(FoldedRow {
                    access_count: r.get(0)?,
                    tier: r.get(1)?,
                    priority: r.get(2)?,
                    expires_is_null: r.get::<_, Option<String>>(3)?.is_none(),
                    confidence: r.get(4)?,
                    confidence_source: r.get(5)?,
                })
            },
        )
        .expect("sqlite read");

    assert_eq!(pg.access_count, sq.access_count, "access_count parity");
    assert_eq!(pg.access_count, 11, "2 + 9 observations");
    assert_eq!(pg.tier, sq.tier, "tier parity");
    assert_eq!(pg.tier, "long", "promotion crossed in a single window");
    assert_eq!(pg.priority, sq.priority, "priority parity");
    assert_eq!(pg.priority, 6, "one decade crossed (2 → 11)");
    assert_eq!(
        pg.expires_is_null, sq.expires_is_null,
        "expires_at-window parity"
    );
    assert!(pg.expires_is_null, "promotion clears expires_at");
    // Decay parity with timestamp normalization: both backends decay
    // 0.9 from the SAME created_at anchor at (approximately) the same
    // wall-clock instant — the residual difference is the sub-second
    // skew between the two fold calls.
    assert_eq!(pg.confidence_source, "decayed");
    assert_eq!(sq.confidence_source, "decayed");
    assert!(pg.confidence < 0.9, "pg decayed (got {})", pg.confidence);
    assert!(
        (pg.confidence - sq.confidence).abs() < 0.01,
        "decayed confidence parity (pg {} vs sqlite {})",
        pg.confidence,
        sq.confidence
    );
    drop(pool);
}

fn crate_short_extend() -> i64 {
    ai_memory::SECS_PER_HOUR
}

fn crate_mid_extend() -> i64 {
    ai_memory::SECS_PER_DAY
}

// =====================================================================
// C — fold-before-gc race (postgres eviction path)
// =====================================================================

#[tokio::test]
#[ignore = "requires AI_MEMORY_TEST_POSTGRES_URL (live postgres); run with --include-ignored"]
// M-LINT-OVERRIDE-EXPECT — the env-serialization guard MUST span the
// test body (recall paths read the flags internally, including across
// awaits); each test runs on its own thread + runtime, so a blocked
// std::Mutex merely parks that test thread.
#[expect(clippy::await_holding_lock)]
async fn postgres_fold_before_gc_retains_recalled_expiring_row() {
    let _g = env_lock();
    clear_flags();
    common::permissive_attestation_for_tests();
    let Some(env) = PostgresTestEnv::new("p01_race").await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
        return;
    };
    let store = PostgresStore::connect(env.url()).await.expect("connect");
    let pool = inspection_pool(env.url()).await;
    let admin = CallerContext::for_admin("operator:p01");

    let recalled = store
        .store(
            &admin,
            &mem("p01-race", "racefox recalled", "c", Tier::Short),
        )
        .await
        .expect("store recalled");
    let control = store
        .store(
            &admin,
            &mem("p01-race", "racefox control", "c", Tier::Short),
        )
        .await
        .expect("store control");
    // Both expire in <1s.
    let soon = chrono::Utc::now() + chrono::Duration::milliseconds(900);
    for id in [&recalled, &control] {
        sqlx::query("UPDATE memories SET expires_at = $2 WHERE id = $1")
            .bind(id)
            .bind(soon)
            .execute(&pool)
            .await
            .expect("shape expiry");
    }
    // Only one is recalled (ledger row), then fold BEFORE gc.
    store
        .record_recall_observation(
            "race-r1",
            &[(recalled.clone(), "fts5".to_string(), 1, 0.5)],
            None,
            None,
        )
        .await
        .expect("ledger row");
    assert_eq!(store.fold_recall_accesses().await.expect("fold"), 1);
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    store.run_gc(false).await.expect("run_gc");

    let count = |id: &str| {
        let pool = pool.clone();
        let id = id.to_string();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM memories WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        count(&recalled).await,
        1,
        "recalled row survived: its TTL extension was folded before gc"
    );
    assert_eq!(
        count(&control).await,
        0,
        "un-recalled control row expired as scheduled"
    );
    drop(pool);
}
