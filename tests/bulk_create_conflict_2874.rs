// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(
    clippy::missing_panics_doc,
    clippy::uninlined_format_args,
    clippy::doc_markdown,
    clippy::items_after_statements
)]
//! #2874 — the default `on_conflict=error` disposition on the BULK create
//! surface (`POST /api/v1/memories/bulk`) must be ATOMICALLY fail-closed, the
//! same guarantee #2771 gave single-create: a row racing into the same
//! `(title, namespace)` key BETWEEN the Stage-2 pre-existing probe and the
//! write is REFUSED (typed 409-class conflict, carrying `existing_id`), never
//! allowed to silently upsert-overwrite the first writer's durable content.
//!
//! Pre-#2874 the bulk `error` rows probed then WROTE via an upsert (sqlite
//! `db::insert` / postgres `store_batch`'s `ON CONFLICT DO UPDATE`), so a
//! writer that slipped in between the probe and the write had its content
//! clobbered with no 409 and no snapshot — the IDENTICAL North-Star
//! lost-update #2771 closed on the single-create path, but on the bulk path.
//!
//! The load-bearing no-overwrite assertion is the schema-v45 `version` column:
//! a fresh insert lands `version = 1`, and an upsert-MERGE bumps it (`#1632`).
//! So `version == 1` on the surviving row PROVES the loser hit the fail-closed
//! `DO NOTHING` arm and never upsert-merged — the pre-#2874 bug would leave
//! `version == 2`. Counter assertions are ALWAYS paired with an out-of-band
//! read of the stored row (a self-consistent envelope is how the class hides).
//!
//! sqlite is covered by a genuine TWO-CONNECTION race (two routers on ONE db
//! file — each holds its own `app.db` mutex, so they serialise on the SQLite
//! file lock, not the tokio mutex) plus a `merge` CONTROL and the #2725
//! in-batch last-wins dedup guard; postgres is covered by a real TWO-TASK race
//! through the actual `bulk_create_postgres` handler (gated on
//! `AI_MEMORY_TEST_POSTGRES_URL`).

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};

const AGENT: &str = "bulk-conflict-2874-agent";

/// #1985 — pin this binary to the explicit permissive agent-attestation
/// opt-out; the v1.0 HTTP-direct default is REQUIRED and would reject these
/// unsigned store fixtures before the accounting under test runs. Mirrors
/// `tests/bulk_on_conflict_2725.rs::permissive_attestation_for_tests`.
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: `Once`-gated process-global env write, one stable value for the
    // process lifetime, set before the caller issues any gated store.
    ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
}

/// A router backed by the sqlite file at `db_path`. Two routers on the SAME
/// path share the durable file but hold DISTINCT `app.db` mutexes, so two
/// concurrent bulk posts genuinely race on the SQLite write lock.
fn build_router_on(db_path: &Path) -> axum::Router {
    permissive_attestation_for_tests();
    // Materialise the schema once, then open the router's own connection.
    let _ = ai_memory::db::open(db_path).expect("db::open seed schema");
    let conn = ai_memory::db::open(db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("open SqliteStore"));
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
        storage_backend: ai_memory::handlers::StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store,
        llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
        auto_tag_model: Arc::new(None),
        llm_call_timeout: std::time::Duration::from_secs(30),
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
        verify_require_nonce: false,
        federation_nonce_cache: std::sync::Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn row(namespace: &str, title: &str, content: &str) -> Value {
    json!({
        "tier": "long", "namespace": namespace, "title": title, "content": content,
        "tags": [], "priority": 5, "confidence": 1.0, "source": "api", "metadata": {},
    })
}

fn row_merge(namespace: &str, title: &str, content: &str) -> Value {
    let mut r = row(namespace, title, content);
    r["on_conflict"] = json!("merge");
    r
}

async fn post(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories/bulk")
        .header("content-type", "application/json")
        .header("x-agent-id", AGENT)
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let parsed = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

// Out-of-band ground truth — never the response's own counters.
fn db_row_count(db_path: &Path, namespace: &str, title: &str) -> i64 {
    Connection::open(db_path)
        .expect("open")
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = ?1 AND title = ?2",
            params![namespace, title],
            |r| r.get(0),
        )
        .expect("count")
}

fn db_content_id_version(db_path: &Path, namespace: &str, title: &str) -> (String, String, i64) {
    Connection::open(db_path)
        .expect("open")
        .query_row(
            "SELECT content, id, version FROM memories WHERE namespace = ?1 AND title = ?2",
            params![namespace, title],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("row")
}

fn u64_of(v: &Value, k: &str) -> u64 {
    v[k].as_u64().unwrap_or_else(|| panic!("missing {k}: {v}"))
}

// ───────────────────────────────────────────────────────────────────
// sqlite — genuine two-connection race (multi-process-shaped)
// ───────────────────────────────────────────────────────────────────

/// Two routers on ONE db file race a bulk `error`-mode create of the SAME
/// `(title, namespace)`. The `(title, namespace)` UNIQUE index guarantees
/// exactly one winner; the loser is REJECTED as a 409-class conflict carrying
/// the winner's `existing_id` — NEVER a silent overwrite, NEVER two rows. The
/// surviving row's `version == 1` proves the loser hit the fail-closed
/// `DO NOTHING` arm (an upsert-merge would have bumped it to 2), whether it
/// was refused by the write arm (true race) or the up-front probe (the writers
/// happened to serialise).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_error_mode_race_exactly_one_winner_no_overwrite_sqlite_2874() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("m.db");
    let ns = "race-2874";
    let title = "raced-title";

    let router_a = build_router_on(&db_path);
    let router_b = build_router_on(&db_path);

    let ba = json!([row(ns, title, "content-from-A")]);
    let bb = json!([row(ns, title, "content-from-B")]);
    let (ra, rb) = tokio::join!(post(&router_a, &ba), post(&router_b, &bb));

    let (status_a, va) = ra;
    let (status_b, vb) = rb;

    let created_total = u64_of(&va, "created") + u64_of(&vb, "created");
    let rejected_total = u64_of(&va, "rejected") + u64_of(&vb, "rejected");
    assert_eq!(
        created_total, 1,
        "exactly one bulk create must win the race: A={va} B={vb}"
    );
    assert_eq!(
        rejected_total, 1,
        "exactly one bulk create must be refused as a conflict: A={va} B={vb}"
    );

    // Exactly one durable row, never overwritten (version == 1).
    assert_eq!(
        db_row_count(&db_path, ns, title),
        1,
        "the race must leave exactly one row"
    );
    let (content, id, version) = db_content_id_version(&db_path, ns, title);
    assert!(
        content == "content-from-A" || content == "content-from-B",
        "the durable content must be an unmodified writer's, not a merge: {content}"
    );
    assert_eq!(
        version, 1,
        "#2874: the surviving row must NOT have been upsert-merged (version stays 1)"
    );

    // The loser's response carries the typed 409 conflict + the winner's id.
    let (loser_status, loser) = if u64_of(&va, "rejected") == 1 {
        (status_a, &va)
    } else {
        (status_b, &vb)
    };
    assert_eq!(
        loser_status,
        StatusCode::CONFLICT,
        "an all-rejected bulk is a dominant 409: {loser}"
    );
    assert_eq!(loser["errors"][0]["code"], json!("CONFLICT"), "{loser}");
    assert_eq!(
        loser["errors"][0]["existing_id"],
        json!(id),
        "the conflict must carry the surviving row's id so a loader can reconcile: {loser}"
    );
    // Whichever won answered 200 with created:1.
    let winner_status = if u64_of(&va, "created") == 1 {
        status_a
    } else {
        status_b
    };
    assert_eq!(winner_status, StatusCode::OK, "the winner is a clean 200");
}

// ───────────────────────────────────────────────────────────────────
// sqlite — CONTROL: the `merge` disposition still upserts (unchanged).
// ───────────────────────────────────────────────────────────────────

/// The `merge` disposition keeps the LEGACY upsert — it overwrites the stored
/// content AND bumps `version` to 2 — proving #2874 changed ONLY the `error`
/// disposition and the fix is load-bearing (the same op under `error` refuses).
#[tokio::test]
async fn bulk_merge_mode_still_upserts_content_sqlite_2874() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("m.db");
    let ns = "merge-2874";
    let title = "dup";
    let router = build_router_on(&db_path);

    let (status, v) = post(&router, &json!([row(ns, title, "original")])).await;
    assert_eq!(status, StatusCode::OK, "seed lands: {v}");
    assert_eq!(v["created"], json!(1), "{v}");
    let (_, _, v_before) = db_content_id_version(&db_path, ns, title);
    assert_eq!(v_before, 1, "fresh insert is version 1");

    let (status, v) = post(&router, &json!([row_merge(ns, title, "merged content")])).await;
    assert_eq!(status, StatusCode::OK, "clean merge-update is 200: {v}");
    assert_eq!(v["created"], json!(0), "{v}");
    assert_eq!(v["updated"], json!(1), "{v}");

    let (content, _, v_after) = db_content_id_version(&db_path, ns, title);
    assert_eq!(
        content, "merged content",
        "the merge disposition DOES overwrite (legacy upsert, unchanged by #2874)"
    );
    assert_eq!(
        v_after, 2,
        "the merge upsert bumps version — proving the error-mode version==1 check is load-bearing"
    );
    assert_eq!(db_row_count(&db_path, ns, title), 1, "still one row: {v}");
}

// ───────────────────────────────────────────────────────────────────
// sqlite — GUARD: in-batch last-wins dedup is preserved (#2725) under the
// new fail-closed routing (a later same-key sibling must NOT self-conflict).
// ───────────────────────────────────────────────────────────────────

/// Two `error`-mode rows sharing `(title, namespace)` in the SAME batch, no
/// pre-existing row: the FIRST occurrence lands via the fail-closed no-overwrite
/// write, and the LATER sibling collapses onto it (last-wins content) as an
/// in-batch dedup — NOT a self-conflict. This pins that the #2874 `landed`-set
/// routing preserves the #2725 in-batch semantics.
#[tokio::test]
async fn bulk_in_batch_error_dedup_last_wins_preserved_sqlite_2874() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("m.db");
    let ns = "dedup-2874";
    let title = "same";
    let router = build_router_on(&db_path);

    let (status, v) = post(
        &router,
        &json!([row(ns, title, "first"), row(ns, title, "second")]),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::MULTI_STATUS,
        "partial-fill dedup is 207: {v}"
    );
    assert_eq!(v["created"], json!(1), "one survivor created: {v}");
    assert_eq!(
        v["rejected"],
        json!(0),
        "an in-batch sibling must NOT be a conflict under fail-closed routing: {v}"
    );
    assert_eq!(
        v["deduped"],
        json!(1),
        "the earlier sibling is deduped: {v}"
    );
    let deduped = v["deduped_rows"].as_array().expect("deduped_rows[]");
    assert_eq!(
        deduped[0]["superseded_by"],
        json!(1),
        "LAST input wins: {v}"
    );

    let (content, _, version) = db_content_id_version(&db_path, ns, title);
    assert_eq!(content, "second", "the LAST row's content is durable");
    assert_eq!(db_row_count(&db_path, ns, title), 1, "{v}");
    // The sibling collapse rides the upsert arm, so version is bumped (as it
    // was pre-#2874) — the in-batch path is deliberately unchanged.
    assert_eq!(version, 2, "in-batch collapse upserts (unchanged): {v}");
}

// ───────────────────────────────────────────────────────────────────
// postgres — real TWO-TASK race through the actual handler (gated on live pg)
// ───────────────────────────────────────────────────────────────────

#[cfg(feature = "sal-postgres")]
mod pg {
    use super::{AGENT, permissive_attestation_for_tests, row, row_merge, u64_of};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::{Value, json};
    use std::sync::Arc;
    use tokio::sync::{Mutex, RwLock};
    use tower::ServiceExt as _;

    use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
    use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    fn postgres_url() -> Option<String> {
        std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
    }

    fn uid(prefix: &str) -> String {
        format!("{prefix}-{}", uuid::Uuid::new_v4())
    }

    fn build_pg_router(store: Arc<dyn MemoryStore>) -> axum::Router {
        permissive_attestation_for_tests();
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
        let db: Db = Arc::new(Mutex::new((
            conn,
            std::path::PathBuf::from(":memory:"),
            ResolvedTtl::default(),
            true,
        )));
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
            family_embeddings: Arc::new(RwLock::new(Some(Vec::new()))),
            storage_backend: StorageBackend::Postgres,
            store,
            llm: Arc::new(ai_memory::reload::SwappableLlm::new(None)),
            auto_tag_model: Arc::new(None),
            llm_call_timeout: std::time::Duration::from_secs(30),
            replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
            verify_require_nonce: false,
            federation_nonce_cache: std::sync::Arc::new(
                ai_memory::identity::replay::FederationNonceCache::default(),
            ),
            autonomous_hooks: false,
            auto_tag_queue: None,
            recall_scope: Arc::new(None),
            deferred_audit_queue: Arc::new(None),
            admin_agent_ids: Arc::new(Vec::new()),
            rule_cache: std::sync::Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
            resolved_models: std::sync::Arc::new(ai_memory::reload::Swappable::new(
                ai_memory::config::ResolvedModels::default(),
            )),
            runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
            max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
            enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
            http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
        };
        let api_key_state = ApiKeyState {
            key: None,
            mtls_enforced: false,
            enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
        };
        ai_memory::build_router(api_key_state, app_state)
    }

    async fn post(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/memories/bulk")
            .header("content-type", "application/json")
            .header("x-agent-id", AGENT)
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
        (status, parsed)
    }

    /// Two concurrent `bulk_create_postgres` invocations (separate pooled
    /// connections, one shared router) race a fresh `(title, namespace)` under
    /// the default `error` disposition. Exactly one wins; the other is refused
    /// as a 409-class conflict carrying the winner's id — NEVER a silent upsert
    /// (`store_with_embedding`'s `ON CONFLICT DO UPDATE`) over the durable
    /// content. `version == 1` proves fail-closed on the survivor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bulk_error_mode_race_exactly_one_winner_no_overwrite_pg_2874() {
        let Some(url) = postgres_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store: Arc<dyn MemoryStore> = Arc::new(
            PostgresStore::connect(&url)
                .await
                .expect("connect postgres"),
        );
        let router = build_pg_router(Arc::clone(&store));
        let ns = uid("race-ns");
        let title = "pg-raced-title";

        let ba = json!([row(&ns, title, "content-A")]);
        let bb = json!([row(&ns, title, "content-B")]);
        let (ra, rb) = tokio::join!(post(&router, &ba), post(&router, &bb));
        let (status_a, va) = ra;
        let (status_b, vb) = rb;

        assert_eq!(
            u64_of(&va, "created") + u64_of(&vb, "created"),
            1,
            "exactly one pg bulk create must win: A={va} B={vb}"
        );
        assert_eq!(
            u64_of(&va, "rejected") + u64_of(&vb, "rejected"),
            1,
            "exactly one pg bulk create must be refused: A={va} B={vb}"
        );

        // Out-of-band durability check via an admin (visibility-bypass) read.
        // The `(title, namespace)` UNIQUE index guarantees at most one row, so
        // resolving the id by key is also the "exactly one row" proof.
        let ctx = CallerContext::for_admin("ai:reader-2874");
        let winner_id = store
            .find_by_title_namespace(title, &ns)
            .await
            .expect("probe survivor")
            .expect("exactly one durable row for the raced key");
        let winner = store.get(&ctx, &winner_id).await.expect("get survivor");
        assert!(
            winner.content == "content-A" || winner.content == "content-B",
            "the durable pg content must be an unmodified writer's: {}",
            winner.content
        );
        assert_eq!(
            winner.version, 1,
            "#2874: the surviving pg row must NOT have been upsert-merged (version stays 1)"
        );

        let (loser_status, loser) = if u64_of(&va, "rejected") == 1 {
            (status_a, &va)
        } else {
            (status_b, &vb)
        };
        assert_eq!(
            loser_status,
            StatusCode::CONFLICT,
            "loser is a 409: {loser}"
        );
        assert_eq!(loser["errors"][0]["code"], json!("CONFLICT"), "{loser}");
        assert_eq!(
            loser["errors"][0]["existing_id"],
            json!(winner.id),
            "{loser}"
        );
    }

    /// CONTROL: the `merge` disposition still upserts on postgres (content
    /// replaced, `version` bumped) — proving #2874 changed only `error`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bulk_merge_mode_still_upserts_pg_2874() {
        let Some(url) = postgres_url() else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let store: Arc<dyn MemoryStore> = Arc::new(
            PostgresStore::connect(&url)
                .await
                .expect("connect postgres"),
        );
        let router = build_pg_router(Arc::clone(&store));
        let ns = uid("merge-ns");
        let title = "pg-merge-title";

        let (status, v) = post(&router, &json!([row(&ns, title, "original")])).await;
        assert_eq!(status, StatusCode::OK, "seed lands: {v}");
        assert_eq!(v["created"], json!(1), "{v}");

        let (status, v) = post(&router, &json!([row_merge(&ns, title, "merged content")])).await;
        assert_eq!(status, StatusCode::OK, "clean merge is 200: {v}");
        assert_eq!(v["updated"], json!(1), "{v}");

        let ctx = CallerContext::for_admin("ai:reader-2874");
        let row_id = store
            .find_by_title_namespace(title, &ns)
            .await
            .expect("probe row")
            .expect("still one row (id preserved on upsert)");
        let row_after = store.get(&ctx, &row_id).await.expect("get");
        assert_eq!(
            row_after.content, "merged content",
            "the merge disposition DOES overwrite on pg (legacy, unchanged by #2874)"
        );
        assert_eq!(
            row_after.version, 2,
            "the merge upsert bumps version — the error-mode version==1 check is load-bearing"
        );
    }
}
