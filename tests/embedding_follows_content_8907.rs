// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::too_many_lines)]
//! #8907 / #8948 / #9062 — the stored vector follows the embedded document.
//!
//! ## The invariant
//!
//! After ANY write that changes a memory's embedded document (its title or
//! content), on either backend and on every transport, the stored vector is
//! EITHER the embedding of the NEW document, OR absent with the write
//! response carrying the degraded marker (`embed_status` /
//! `embed_status_reason`, the keys the HTTP create path has always emitted).
//! It is never the OLD document's vector: that row would rank by text it no
//! longer holds.
//!
//! ## The defects
//!
//! * #8907 — a content update whose re-embed FAILED kept the OLD vector and
//!   reported nothing (`if let Ok(v) = embed(..) { let _ = set_embedding(..) }`
//!   at every update site).
//! * #8948 — the postgres HTTP `PUT` never re-embedded at all.
//! * #9062 — the same defect seen from recall: the updated row still ranked
//!   by its old text.
//!
//! ## The rows
//!
//! One table per surface; every row seeds a row WITH a vector, changes its
//! document, and asserts the exact stored vector plus the exact marker.
//! Embedder failure comes from `embeddings::test_hold_hook::arm_fail` (no
//! network). CLI and MCP-stdio rows drive the real binary with `--db` under
//! the cargo target scratch root.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::embeddings::{Embedder, embedding_document, test_hold_hook};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::identity::test_agent_id::AgentIdOverride;
use ai_memory::mcp::dispatch_test_hook::handle_request_with_embedder_for_test;
use ai_memory::runtime_context::RuntimeContext;

/// Vector width of the stand-in embedder (the postgres default dim).
const DIM: usize = 384;
const AGENT: &str = "ai:t8907";
const NAMESPACE: &str = "t8907";
/// The embedding space a directly-seeded vector carries.
const SEED_SPACE: &str = "test-space-8907";
/// `embed_status` value for a write whose re-embed failed.
const STATUS_FAILED: &str = "failed";
/// `embed_status` value for a write that had no embedder to re-embed with.
const STATUS_SKIPPED: &str = "skipped";
/// The caller-safe reason of a non-provider embed error (#3648).
const REASON_EMBEDDING_FAILED: &str = "embedding_failed";
/// Pins `ai_memory::embeddings::NO_EMBEDDER_REASON`.
const REASON_NO_EMBEDDER: &str = "no embedder configured";
const OLD_CONTENT: &str = "the original body about apples";
const NEW_CONTENT: &str = "the rewritten body about cherries";
/// A cosine at or above this is the same vector (f32 rounding only).
const SAME_VECTOR_COSINE: f32 = 0.999;

/// Whether the re-embed of a row succeeds or fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Embeds,
    Fails,
}

/// Which HTTP handler branch a row drives.
#[derive(Clone, Copy, Debug)]
enum Branch {
    Sqlite,
    /// `StorageBackend::Postgres` over a `SqliteStore` (postgres handler code).
    #[cfg(feature = "sal")]
    FakePg,
    /// A real `PostgresStore` from `AI_MEMORY_TEST_POSTGRES_URL`.
    #[cfg(feature = "sal-postgres")]
    RealPg,
}

fn scratch_root() -> PathBuf {
    let root = PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into()))
        .join("embed-8907");
    std::fs::create_dir_all(&root).expect("scratch root");
    root
}

/// A unique model name + failure marker per row, so parallel rows never
/// share an armed hook.
fn unique(label: &str) -> (String, String) {
    let id = uuid::Uuid::new_v4().simple().to_string();
    (
        format!("embed-8907-{label}-{id}"),
        format!("zqxfail{}", &id[..12]),
    )
}

/// The new content for `outcome`: carries the failure marker when the
/// re-embed must fail.
fn new_content(outcome: Outcome, marker: &str) -> String {
    match outcome {
        Outcome::Embeds => NEW_CONTENT.to_string(),
        Outcome::Fails => format!("{NEW_CONTENT} {marker}"),
    }
}

/// The deterministic stand-in vector for `doc` (the armed model never
/// fails an unmarked text).
fn expected_vector(model: &str, doc: &str) -> Vec<f32> {
    test_hold_hook::embedder(model, DIM)
        .expect("embedder")
        .embed(doc)
        .expect("stand-in vector")
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    dot / (na * nb)
}

/// Assert the stored vector after a document-changing write: the NEW
/// document's vector on success; absent plus the exact marker on failure.
fn assert_follows(
    row: &str,
    outcome: Outcome,
    stored: Option<&Vec<f32>>,
    (model, doc): (&str, &str),
    response: &Value,
) {
    match outcome {
        Outcome::Embeds => {
            let expected = expected_vector(model, doc);
            assert_eq!(
                stored.map(Vec::as_slice),
                Some(expected.as_slice()),
                "{row}: the stored vector is not the NEW document's embedding (#8907/#8948)"
            );
            assert!(
                response.get("embed_status").is_none(),
                "{row}: a successful re-embed must not report degraded: {response}"
            );
        }
        Outcome::Fails => {
            assert!(
                stored.is_none(),
                "{row}: the re-embed failed but the row kept a vector (the OLD document's) \
                 — #8907 (first 3: {:?})",
                stored.map(|v| v.iter().take(3).copied().collect::<Vec<_>>())
            );
            assert_eq!(
                response["embed_status"], STATUS_FAILED,
                "{row}: degraded marker missing: {response}"
            );
            assert_eq!(
                response["embed_status_reason"], REASON_EMBEDDING_FAILED,
                "{row}: degraded reason: {response}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP: the real router over both backends.
// ---------------------------------------------------------------------------

struct Fixture {
    router: axum::Router,
    db_path: PathBuf,
    model: String,
    marker: String,
    #[cfg(feature = "sal-postgres")]
    pg_store: Option<Arc<dyn ai_memory::store::MemoryStore>>,
    _db: tempfile::NamedTempFile,
    #[cfg(feature = "sal-postgres")]
    _pg: Option<common::postgres_env::PostgresTestEnv>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        test_hold_hook::disarm(&self.model);
    }
}

/// The router for `branch` with a stand-in embedder ARMED to fail every
/// marked text. `None` when a real-postgres branch has no URL.
async fn fixture(label: &str, branch: Branch) -> Option<Fixture> {
    fixture_with(label, branch, Some(test_hold_hook::Effect::Fail)).await
}

/// [`fixture`] with the marked-embed `effect`; `None` = the node runs with
/// NO embedder at all (#9284 X-3).
#[cfg_attr(not(feature = "sal-postgres"), allow(clippy::unused_async))]
async fn fixture_with(
    label: &str,
    branch: Branch,
    effect: Option<test_hold_hook::Effect>,
) -> Option<Fixture> {
    common::permissive_attestation_for_tests();
    let (model, marker) = unique(label);
    // Arm BEFORE the first embed: an unarmed stand-in would hit the network.
    test_hold_hook::arm_effect(
        &model,
        &marker,
        effect.unwrap_or(test_hold_hook::Effect::Fail),
    );
    let embedder: Embedder = test_hold_hook::embedder(&model, DIM).expect("stand-in embedder");
    let f = tempfile::Builder::new()
        .prefix("e8907-")
        .suffix(".db")
        .tempfile_in(scratch_root())
        .expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal-postgres")]
    let mut pg_env = None;
    #[cfg(feature = "sal-postgres")]
    let mut pg_store: Option<Arc<dyn ai_memory::store::MemoryStore>> = None;
    let storage_backend = match branch {
        Branch::Sqlite => StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        Branch::FakePg => StorageBackend::Postgres,
        #[cfg(feature = "sal-postgres")]
        Branch::RealPg => StorageBackend::Postgres,
    };
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> = match branch {
        #[cfg(feature = "sal-postgres")]
        Branch::RealPg => {
            let env = common::postgres_env::PostgresTestEnv::new(label).await?;
            let store: Arc<dyn ai_memory::store::MemoryStore> = Arc::new(
                ai_memory::store::postgres::PostgresStore::connect_with_dim(
                    env.url(),
                    u32::try_from(DIM).expect("dim fits"),
                )
                .await
                .expect("connect postgres adapter"),
            );
            pg_env = Some(env);
            pg_store = Some(Arc::clone(&store));
            store
        }
        _ => Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"),
        ),
    };
    let app_state = AppState {
        db,
        embedder: Arc::new(effect.map(|_| embedder)),
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
        llm_call_timeout: Duration::from_secs(30),
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
        runtime: RuntimeContext::global_arc(),
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
        ..Default::default()
    };
    Some(Fixture {
        router: ai_memory::build_router(api_key_state, app_state),
        db_path,
        model,
        marker,
        #[cfg(feature = "sal-postgres")]
        pg_store,
        _db: f,
        #[cfg(feature = "sal-postgres")]
        _pg: pg_env,
    })
}

impl Fixture {
    /// The stored vector of `id` on the branch's own store.
    async fn stored(&self, id: &str) -> Option<Vec<f32>> {
        #[cfg(feature = "sal-postgres")]
        if let Some(store) = &self.pg_store {
            return store
                .get_embedding(&ai_memory::store::CallerContext::for_agent(AGENT), id)
                .await
                .expect("pg get_embedding");
        }
        // The sqlite read is synchronous; `ready` keeps one async signature
        // for both feature sets (the pg arm above awaits the store).
        let conn = ai_memory::db::open(&self.db_path).expect("reopen");
        std::future::ready(ai_memory::db::get_embedding(&conn, id).expect("read embedding")).await
    }
}

fn request(method: &str, uri: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-agent-id", AGENT)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).expect("json body")))
        .expect("request")
}

async fn send(router: axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.oneshot(req).await.expect("router is infallible");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn memory_body(title: &str, content: &str) -> Value {
    json!({
        "tier": "long",
        "namespace": NAMESPACE,
        "title": title,
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "metadata": {},
        "agent_id": AGENT,
    })
}

/// POST one memory and return its id; asserts it was indexed.
async fn seed(fx: &Fixture, title: &str, content: &str) -> String {
    let (status, body) = send(
        fx.router.clone(),
        request("POST", "/api/v1/memories", &memory_body(title, content)),
    )
    .await;
    assert!(status.is_success(), "seed {title}: {status} {body}");
    assert!(
        body.get("embed_status").is_none() && body.get("embed_status_reason").is_none(),
        "seed {title}: an indexed create must not carry the degraded marker: {body}"
    );
    let id = body["id"].as_str().expect("seed id").to_string();
    let seeded = expected_vector(&fx.model, &embedding_document(title, content));
    assert_eq!(
        fx.stored(&id).await.as_deref(),
        Some(seeded.as_slice()),
        "seed {title}: the seed row must start WITH its own vector"
    );
    id
}

/// The HTTP write that changes a seeded row's document.
#[derive(Clone, Copy, Debug)]
enum HttpWrite {
    /// `PUT /api/v1/memories/{id}` with new content.
    Put,
    /// `POST /api/v1/memories` re-storing the same (title, namespace).
    Restore,
}

const HTTP_WRITES: [HttpWrite; 2] = [HttpWrite::Put, HttpWrite::Restore];
const OUTCOMES: [Outcome; 2] = [Outcome::Embeds, Outcome::Fails];

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

fn http_rows(branch: Branch) {
    runtime().block_on(async {
        for write in HTTP_WRITES {
            // The fake-postgres branch runs over a `SqliteStore`, which has
            // no STORE_WITH_EMBEDDING capability (the create handler 501s);
            // the real-postgres branch carries the re-store row.
            #[cfg(feature = "sal")]
            if matches!((branch, write), (Branch::FakePg, HttpWrite::Restore)) {
                continue;
            }
            for outcome in OUTCOMES {
                let row = format!("http {branch:?} {write:?} {outcome:?}");
                let Some(fx) = fixture("e8907http", branch).await else {
                    eprintln!("skip {row}: AI_MEMORY_TEST_POSTGRES_URL unset");
                    return;
                };
                let title = format!("doc-8907-{write:?}-{outcome:?}");
                let id = seed(&fx, &title, OLD_CONTENT).await;
                let content = new_content(outcome, &fx.marker);
                let (status, body) = match write {
                    HttpWrite::Put => {
                        send(
                            fx.router.clone(),
                            request(
                                "PUT",
                                &format!("/api/v1/memories/{id}"),
                                &json!({"content": content, "agent_id": AGENT}),
                            ),
                        )
                        .await
                    }
                    HttpWrite::Restore => {
                        // `on_conflict=merge` is the re-store that upserts
                        // over the live (title, namespace) row; the HTTP
                        // default (`error`) refuses it with a 409, and
                        // `force` skips the near-duplicate contradiction
                        // gate, which a rewritten body trips by design.
                        let mut body = memory_body(&title, &content);
                        body["on_conflict"] = json!("merge");
                        body["force"] = json!(true);
                        send(
                            fx.router.clone(),
                            request("POST", "/api/v1/memories", &body),
                        )
                        .await
                    }
                };
                assert!(status.is_success(), "{row}: {status} {body}");
                let doc = embedding_document(&title, &content);
                assert_follows(
                    &row,
                    outcome,
                    fx.stored(&id).await.as_ref(),
                    (&fx.model, &doc),
                    &body,
                );
            }
        }
    });
}

/// `POST /api/v1/memories/bulk` with an embedder that indexes every row: the
/// envelope carries no degraded marker, and every row has its own vector.
fn http_bulk_rows(branch: Branch) {
    runtime().block_on(async {
        let row = format!("http {branch:?} bulk");
        let Some(fx) = fixture("e8907bulk", branch).await else {
            eprintln!("skip {row}: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let rows = json!([
            {"title": "bulk-8907-a", "content": OLD_CONTENT, "namespace": NAMESPACE, "tier": "mid"},
            {"title": "bulk-8907-b", "content": NEW_CONTENT, "namespace": NAMESPACE, "tier": "mid"},
        ]);
        let (status, body) = send(
            fx.router.clone(),
            request("POST", "/api/v1/memories/bulk", &rows),
        )
        .await;
        assert!(status.is_success(), "{row}: {status} {body}");
        assert_eq!(body["created"].as_u64(), Some(2), "{row}: {body}");
        assert_no_marker(&row, &body);
    });
}

#[test]
fn http_update_vector_follows_content_sqlite_8907() {
    http_rows(Branch::Sqlite);
    http_bulk_rows(Branch::Sqlite);
}

#[cfg(feature = "sal")]
#[test]
fn http_update_vector_follows_content_postgres_branch_8948() {
    http_rows(Branch::FakePg);
    http_bulk_rows(Branch::FakePg);
}

#[cfg(feature = "sal-postgres")]
#[test]
fn http_update_vector_follows_content_real_postgres_8948() {
    http_rows(Branch::RealPg);
    http_bulk_rows(Branch::RealPg);
}

/// #9062 — after an update moves row A onto the query's topic, A is the
/// top semantic match for that query, at the query's own vector.
fn semantic_rank_rows(branch: Branch) {
    runtime().block_on(async {
        let row = format!("rank {branch:?}");
        let Some(fx) = fixture("e8907rank", branch).await else {
            eprintln!("skip {row}: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let a = seed(&fx, "rank-a-9062", OLD_CONTENT).await;
        let b = seed(&fx, "rank-b-9062", "an unrelated body about granite").await;
        let (status, body) = send(
            fx.router.clone(),
            request(
                "PUT",
                &format!("/api/v1/memories/{a}"),
                &json!({"content": NEW_CONTENT, "agent_id": AGENT}),
            ),
        )
        .await;
        assert!(status.is_success(), "{row}: {status} {body}");
        let query = expected_vector(&fx.model, &embedding_document("rank-a-9062", NEW_CONTENT));
        let mut ranked = Vec::new();
        for id in [&a, &b] {
            let stored = fx.stored(id).await.expect("both rows indexed");
            ranked.push((cosine(&query, &stored), id.clone()));
        }
        ranked.sort_by(|x, y| y.0.total_cmp(&x.0));
        assert_eq!(
            ranked[0].1, a,
            "{row}: the updated row is not top-1: {ranked:?}"
        );
        assert!(
            ranked[0].0 >= SAME_VECTOR_COSINE,
            "{row}: the updated row ranks by its OLD text (cosine {}) — #9062",
            ranked[0].0
        );
    });
}

#[test]
fn semantic_rank_follows_updated_content_sqlite_9062() {
    semantic_rank_rows(Branch::Sqlite);
}

#[cfg(feature = "sal")]
#[test]
fn semantic_rank_follows_updated_content_postgres_branch_9062() {
    semantic_rank_rows(Branch::FakePg);
}

#[cfg(feature = "sal-postgres")]
#[test]
fn semantic_rank_follows_updated_content_real_postgres_9062() {
    semantic_rank_rows(Branch::RealPg);
}

// ---------------------------------------------------------------------------
// MCP: the real `tools/call` dispatch with the armed embedder.
// ---------------------------------------------------------------------------

/// The MCP write that changes a seeded row's document.
#[derive(Clone, Copy, Debug)]
enum McpWrite {
    /// `memory_update` in place (`edit_source: "agent"`).
    UpdateInPlace,
    /// `memory_update` append-and-archive (`edit_source: "llm"`): the
    /// patched content lands on a NEW row.
    UpdateSupersede,
    /// `memory_store` over an existing (title, namespace): the dedup merge.
    StoreDedup,
}

const MCP_WRITES: [McpWrite; 3] = [
    McpWrite::UpdateInPlace,
    McpWrite::UpdateSupersede,
    McpWrite::StoreDedup,
];

fn call(id: u64, tool: &str, args: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    })
}

fn tool_result(resp: &Value) -> Value {
    assert!(resp.get("error").is_none(), "{resp}");
    assert_ne!(resp["result"]["isError"], true, "{resp}");
    serde_json::from_str(
        resp["result"]["content"][0]["text"]
            .as_str()
            .expect("tool text"),
    )
    .expect("tool JSON")
}

#[test]
fn mcp_update_and_dedup_vector_follows_content_8907() {
    let _identity = AgentIdOverride::set(AGENT);
    let scratch = tempfile::tempdir_in(scratch_root()).expect("scratch");
    for write in MCP_WRITES {
        for outcome in OUTCOMES {
            let row = format!("mcp {write:?} {outcome:?}");
            let (model, marker) = unique("mcp");
            test_hold_hook::arm_fail(&model, &marker);
            let embedder = test_hold_hook::embedder(&model, DIM).expect("embedder");
            let db_path = scratch.path().join(format!("{write:?}-{outcome:?}.db"));
            let conn = ai_memory::db::open(&db_path).expect("open db");
            let title = format!("mcp-8907-{write:?}-{outcome:?}");
            let seeded = tool_result(&handle_request_with_embedder_for_test(
                &conn,
                &db_path,
                &call(
                    1,
                    "memory_store",
                    &json!({"title": title, "content": OLD_CONTENT, "namespace": NAMESPACE, "tier": "long"}),
                ),
                &embedder,
            ));
            assert!(
                seeded.get("embed_status").is_none() && seeded.get("embed_status_reason").is_none(),
                "{row}: an indexed MCP create must not carry the degraded marker: {seeded}"
            );
            let id = seeded["id"].as_str().expect("seed id").to_string();
            assert_eq!(
                ai_memory::db::get_embedding(&conn, &id).expect("seed vector"),
                Some(expected_vector(
                    &model,
                    &embedding_document(&title, OLD_CONTENT)
                )),
                "{row}: the seed row must start WITH its own vector"
            );
            let content = new_content(outcome, &marker);
            let request = match write {
                McpWrite::UpdateInPlace => call(
                    2,
                    "memory_update",
                    &json!({"id": id, "content": content, "edit_source": "agent"}),
                ),
                McpWrite::UpdateSupersede => call(
                    2,
                    "memory_update",
                    &json!({"id": id, "content": content, "edit_source": "llm"}),
                ),
                McpWrite::StoreDedup => call(
                    2,
                    "memory_store",
                    &json!({"title": title, "content": content, "namespace": NAMESPACE, "tier": "long"}),
                ),
            };
            let response = tool_result(&handle_request_with_embedder_for_test(
                &conn, &db_path, &request, &embedder,
            ));
            // The supersede path writes the new document onto a NEW row.
            let target = match write {
                McpWrite::UpdateSupersede => response["new_id"]
                    .as_str()
                    .expect("supersede new_id")
                    .to_string(),
                McpWrite::UpdateInPlace | McpWrite::StoreDedup => id.clone(),
            };
            let doc = embedding_document(&title, &content);
            let stored = ai_memory::db::get_embedding(&conn, &target).expect("read vector");
            assert_follows(&row, outcome, stored.as_ref(), (&model, &doc), &response);
            test_hold_hook::disarm(&model);
        }
    }
}

// ---------------------------------------------------------------------------
// CLI and MCP stdio: the real binary, no embedder on that surface.
// ---------------------------------------------------------------------------

fn run_cli(db: &Path, args: &[&str], input: &str) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    command
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .arg("--db")
        .arg(db)
        .arg("--agent-id")
        .arg(AGENT)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn isolated CLI");
    common::child_stdin_report::send_and_close(&mut child, "stdin payload", input.as_bytes());
    let output = child.wait_with_output().expect("CLI output");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 output")
}

fn stdio_tool(db: &Path, name: &str, arguments: &Value) -> Value {
    let frames = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"embed-8907","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":name,"arguments":arguments}}),
    ]
    .map(|frame| frame.to_string())
    .join("\n")
        + "\n";
    // `--tier keyword` pins the no-embedder surface: the default MCP tier
    // loads a local embedder, which would re-embed instead of degrading.
    let output = run_cli(
        db,
        &["mcp", "--profile", "full", "--tier", "keyword"],
        &frames,
    );
    let response = output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["id"] == 2)
        .expect("MCP response");
    tool_result(&response)
}

/// The binary-surface write that changes a seeded row's document.
#[derive(Clone, Copy, Debug)]
enum BinaryWrite {
    /// `ai-memory update <id> --content ..`.
    CliUpdate,
    /// MCP stdio `memory_update`.
    StdioUpdate,
    /// MCP stdio `memory_store` over the same (title, namespace).
    StdioStoreDedup,
}

const BINARY_WRITES: [BinaryWrite; 3] = [
    BinaryWrite::CliUpdate,
    BinaryWrite::StdioUpdate,
    BinaryWrite::StdioStoreDedup,
];

/// With no embedder on the surface the new document cannot be embedded,
/// so the old vector must go and the response must say why.
#[test]
fn cli_and_stdio_update_clear_the_stale_vector_8907() {
    let scratch = tempfile::tempdir_in(scratch_root()).expect("scratch");
    let stale: Vec<f32> = vec![1.0 / (f32::from(u16::try_from(DIM).expect("dim")).sqrt()); DIM];
    for write in BINARY_WRITES {
        let row = format!("binary {write:?}");
        let db = scratch.path().join(format!("{write:?}.db"));
        let title = format!("bin-8907-{write:?}");
        let stored: Value = serde_json::from_str(&run_cli(
            &db,
            &[
                "store",
                "--json",
                "--namespace",
                NAMESPACE,
                "--title",
                &title,
                "--content",
                OLD_CONTENT,
            ],
            "",
        ))
        .expect("store receipt");
        assert_no_marker(&format!("{row} create"), &stored);
        let id = stored["id"].as_str().expect("stored id").to_string();
        {
            let conn = ai_memory::db::open(&db).expect("open db");
            ai_memory::db::set_embedding(&conn, &id, &stale, SEED_SPACE).expect("seed vector");
        }
        let response: Value = match write {
            BinaryWrite::CliUpdate => serde_json::from_str(&run_cli(
                &db,
                &["update", &id, "--json", "--content", NEW_CONTENT],
                "",
            ))
            .expect("update receipt"),
            BinaryWrite::StdioUpdate => stdio_tool(
                &db,
                "memory_update",
                &json!({"id": id, "content": NEW_CONTENT}),
            ),
            BinaryWrite::StdioStoreDedup => stdio_tool(
                &db,
                "memory_store",
                &json!({"title": title, "content": NEW_CONTENT, "namespace": NAMESPACE}),
            ),
        };
        let conn = ai_memory::db::open(&db).expect("reopen db");
        let after = ai_memory::db::get_embedding(&conn, &id).expect("read vector");
        assert!(
            after.is_none(),
            "{row}: the content changed with no embedder, yet the OLD vector stayed — #8907: {response}"
        );
        assert_eq!(
            response["embed_status"], STATUS_SKIPPED,
            "{row}: degraded marker missing: {response}"
        );
        assert_eq!(
            response["embed_status_reason"], REASON_NO_EMBEDDER,
            "{row}: degraded reason: {response}"
        );
    }
}

/// The degraded marker is ABSENT: the write ended with a vector stored or
/// with nothing to embed (status Indexed), exactly as on create.
fn assert_no_marker(row: &str, receipt: &Value) {
    assert!(
        receipt.get("embed_status").is_none() && receipt.get("embed_status_reason").is_none(),
        "{row}: the receipt must not carry the degraded marker: {receipt}"
    );
}

/// A write that leaves the document alone has nothing to embed: no marker
/// on the CLI or the stdio MCP receipt, and the seeded vector stays.
#[test]
fn cli_and_stdio_priority_only_update_carries_no_marker_8907() {
    let scratch = tempfile::tempdir_in(scratch_root()).expect("scratch");
    let stale: Vec<f32> = vec![1.0 / (f32::from(u16::try_from(DIM).expect("dim")).sqrt()); DIM];
    for write in [BinaryWrite::CliUpdate, BinaryWrite::StdioUpdate] {
        let row = format!("binary priority-only {write:?}");
        let db = scratch.path().join(format!("prio-{write:?}.db"));
        let title = format!("bin-prio-8907-{write:?}");
        let stored: Value = serde_json::from_str(&run_cli(
            &db,
            &[
                "store",
                "--json",
                "--namespace",
                NAMESPACE,
                "--title",
                &title,
                "--content",
                OLD_CONTENT,
            ],
            "",
        ))
        .expect("store receipt");
        let id = stored["id"].as_str().expect("stored id").to_string();
        {
            let conn = ai_memory::db::open(&db).expect("open db");
            ai_memory::db::set_embedding(&conn, &id, &stale, SEED_SPACE).expect("seed vector");
        }
        let response: Value = match write {
            BinaryWrite::CliUpdate => serde_json::from_str(&run_cli(
                &db,
                &["update", &id, "--json", "--priority", "7"],
                "",
            ))
            .expect("update receipt"),
            _ => stdio_tool(&db, "memory_update", &json!({"id": id, "priority": 7})),
        };
        let applied = response
            .get("memory")
            .map_or(&response["priority"], |memory| &memory["priority"]);
        assert_eq!(applied, 7, "{row}: the update must apply: {response}");
        assert_no_marker(&row, &response);
        let conn = ai_memory::db::open(&db).expect("reopen db");
        assert_eq!(
            ai_memory::db::get_embedding(&conn, &id).expect("read vector"),
            Some(stale.clone()),
            "{row}: an unchanged document must keep its vector"
        );
    }
}

/// CLI re-store over a live (title, namespace) with the SAME
/// document: the upsert changes nothing to embed, so no marker either.
#[test]
fn cli_store_upsert_of_unchanged_document_carries_no_marker_8907() {
    let scratch = tempfile::tempdir_in(scratch_root()).expect("scratch");
    let db = scratch.path().join("upsert.db");
    let args = [
        "store",
        "--json",
        "--namespace",
        NAMESPACE,
        "--title",
        "bin-upsert-8907",
        "--content",
        OLD_CONTENT,
    ];
    let first: Value = serde_json::from_str(&run_cli(&db, &args, "")).expect("first receipt");
    assert_no_marker("cli create", &first);
    let second: Value = serde_json::from_str(&run_cli(&db, &args, "")).expect("second receipt");
    assert_eq!(
        second["id"], first["id"],
        "the re-store must hit the same row: {second}"
    );
    assert_no_marker("cli store upsert", &second);
}

// ---------------------------------------------------------------------------
// Store layer: the ONE decision point. A document change clears the vector
// in the same statement; an unchanged document keeps it.
// ---------------------------------------------------------------------------

/// The store-level write a row performs.
#[cfg(feature = "sal")]
#[derive(Clone, Copy, Debug)]
enum StoreWrite {
    /// `MemoryStore::update` with new content.
    UpdateContent,
    /// `MemoryStore::update` with a new title (the title is embedded too).
    UpdateTitle,
    /// `MemoryStore::store` over the same (title, namespace), new content.
    UpsertContent,
    /// `MemoryStore::update` of priority only: the document is unchanged.
    UpdatePriorityOnly,
}

#[cfg(feature = "sal")]
const STORE_WRITES: [StoreWrite; 4] = [
    StoreWrite::UpdateContent,
    StoreWrite::UpdateTitle,
    StoreWrite::UpsertContent,
    StoreWrite::UpdatePriorityOnly,
];

#[cfg(feature = "sal")]
fn store_memory(title: &str, content: &str) -> ai_memory::models::Memory {
    let now = chrono::Utc::now().to_rfc3339();
    ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: NAMESPACE.to_owned(),
        title: title.to_owned(),
        content: content.to_owned(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": AGENT}),
        ..ai_memory::models::Memory::default()
    }
}

#[cfg(feature = "sal")]
async fn store_rows(label: &str, store: &dyn ai_memory::store::MemoryStore) {
    use ai_memory::store::{CallerContext, UpdatePatch};
    let ctx = CallerContext::for_agent(AGENT);
    let seeded: Vec<f32> = (0..DIM).map(|i| if i == 0 { 1.0 } else { 0.0 }).collect();
    for write in STORE_WRITES {
        let row = format!("store {label} {write:?}");
        let title = format!("store-8907-{write:?}");
        let id = store
            .store(&ctx, &store_memory(&title, OLD_CONTENT))
            .await
            .expect("seed");
        store
            .update_embedding(&ctx, &id, Some(&seeded), SEED_SPACE)
            .await
            .expect("seed vector");
        match write {
            StoreWrite::UpdateContent => store
                .update(
                    &ctx,
                    &id,
                    UpdatePatch {
                        content: Some(NEW_CONTENT.to_owned()),
                        ..UpdatePatch::default()
                    },
                )
                .await
                .expect("update content"),
            StoreWrite::UpdateTitle => store
                .update(
                    &ctx,
                    &id,
                    UpdatePatch {
                        title: Some(format!("{title}-renamed")),
                        ..UpdatePatch::default()
                    },
                )
                .await
                .expect("update title"),
            StoreWrite::UpsertContent => {
                store
                    .store(&ctx, &store_memory(&title, NEW_CONTENT))
                    .await
                    .expect("upsert");
            }
            StoreWrite::UpdatePriorityOnly => store
                .update(
                    &ctx,
                    &id,
                    UpdatePatch {
                        priority: Some(9),
                        ..UpdatePatch::default()
                    },
                )
                .await
                .expect("update priority"),
        }
        let after = store.get_embedding(&ctx, &id).await.expect("read vector");
        match write {
            StoreWrite::UpdatePriorityOnly => assert_eq!(
                after.as_deref(),
                Some(seeded.as_slice()),
                "{row}: an unchanged document must keep its vector"
            ),
            StoreWrite::UpdateContent | StoreWrite::UpdateTitle | StoreWrite::UpsertContent => {
                assert!(
                    after.is_none(),
                    "{row}: the document changed but the store kept the OLD vector — #8907/#8948"
                );
            }
        }
    }
}

#[cfg(feature = "sal")]
#[test]
fn store_layer_clears_vector_on_document_change_sqlite_8907() {
    let scratch = tempfile::tempdir_in(scratch_root()).expect("scratch");
    let store = ai_memory::store::sqlite::SqliteStore::open(scratch.path().join("store.db"))
        .expect("open SqliteStore");
    runtime().block_on(store_rows("sqlite", &store));
}

#[cfg(feature = "sal-postgres")]
#[test]
fn store_layer_clears_vector_on_document_change_real_postgres_8948() {
    runtime().block_on(async {
        let Some(env) = common::postgres_env::PostgresTestEnv::new("e8907store").await else {
            eprintln!("skip store real postgres: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let store = ai_memory::store::postgres::PostgresStore::connect_with_dim(
            env.url(),
            u32::try_from(DIM).expect("dim fits"),
        )
        .await
        .expect("connect postgres adapter");
        store_rows("real-postgres", &store).await;
    });
}

// ---------------------------------------------------------------------------
// #9284 round 1 (NOTICE-FIX-9284-r1): a second writer between the steps.
// ---------------------------------------------------------------------------

/// How long a held embed sleeps while the second writer commits.
const HOLD: Duration = Duration::from_secs(3);
/// The longest wait for the held embed to start.
const ENTER_TIMEOUT: Duration = Duration::from_secs(120);
/// The second writer's document body.
const DOC_B: &str = "the second writer's body about plums";
/// #9284 X-5 — the receipt reason of an embed task that did not complete.
const REASON_TASK_INCOMPLETE: &str = "embed task did not complete";
/// #9284 X-5 — the receipt reason of an embedder that returned no vector.
const REASON_EMPTY_VECTOR: &str = "embedder returned empty vector";

/// The second writer B on the SQLite file: a NEW content commit plus the
/// vector of that new document, on its own connection (another process).
fn sqlite_second_writer(db_path: &Path, id: &str, title: &str, model: &str) -> Vec<f32> {
    let conn = ai_memory::db::open(db_path).expect("writer B opens its own connection");
    let (found, _) = ai_memory::db::update(
        &conn,
        id,
        None,
        Some(DOC_B),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("writer B content commit");
    assert!(found, "writer B: the row exists");
    let vector = expected_vector(model, &embedding_document(title, DOC_B));
    ai_memory::db::set_embedding(&conn, id, &vector, SEED_SPACE).expect("writer B vector");
    vector
}

/// The MCP surface: seed `title` with an unmarked body, return (db, id).
fn mcp_seed(
    scratch: &Path,
    label: &str,
    title: &str,
    embedder: &Embedder,
) -> (PathBuf, rusqlite::Connection, String) {
    let db_path = scratch.join(format!("{label}.db"));
    let conn = ai_memory::db::open(&db_path).expect("open db");
    let seeded = tool_result(&handle_request_with_embedder_for_test(
        &conn,
        &db_path,
        &call(
            1,
            "memory_store",
            &json!({"title": title, "content": OLD_CONTENT, "namespace": NAMESPACE, "tier": "long"}),
        ),
        embedder,
    ));
    let id = seeded["id"].as_str().expect("seed id").to_string();
    assert!(
        ai_memory::db::get_embedding(&conn, &id)
            .expect("seed vector")
            .is_some(),
        "{label}: the seed row must start WITH its own vector"
    );
    (db_path, conn, id)
}

/// The field a stale pre-read sees the other writer change.
#[derive(Clone, Copy, Debug)]
enum StaleField {
    Content,
    Title,
}

/// T-1 (X-1) — writer B commits a new document AND its vector between the
/// update funnel's pre-read and its UPDATE; a priority-only patch computed
/// from that stale pre-read rewrites the old document (PRE-EXISTING #9285)
/// and must leave NO vector: B's vector belongs to B's document, not to the
/// bytes the row now holds (I-1). The compare runs inside the UPDATE.
#[test]
fn stale_preread_update_leaves_no_foreign_vector_9284() {
    let _identity = AgentIdOverride::set(AGENT);
    let scratch = tempfile::tempdir_in(scratch_root()).expect("scratch");
    for field in [StaleField::Content, StaleField::Title] {
        let row = format!("stale pre-read {field:?}");
        let (model, marker) = unique("t1");
        test_hold_hook::arm_effect(&model, &marker, test_hold_hook::Effect::Vectors);
        let embedder = test_hold_hook::embedder(&model, DIM).expect("embedder");
        let title = format!("t1-9284-{field:?}");
        let (_db, conn, id) = mcp_seed(scratch.path(), &format!("t1-{field:?}"), &title, &embedder);
        let foreign = expected_vector(&model, DOC_B);
        let hook_vector = foreign.clone();
        ai_memory::storage::embed_cas::arm_after_update_preread(move |c, hook_id| {
            let sql = match field {
                StaleField::Content => "UPDATE memories SET content = ?1 WHERE id = ?2",
                StaleField::Title => "UPDATE memories SET title = ?1 WHERE id = ?2",
            };
            c.execute(sql, rusqlite::params![DOC_B, hook_id])
                .expect("writer B document commit");
            ai_memory::db::set_embedding(c, hook_id, &hook_vector, SEED_SPACE)
                .expect("writer B vector");
        });
        let (found, _) = ai_memory::db::update(
            &conn,
            &id,
            None,
            None,
            None,
            None,
            None,
            Some(7),
            None,
            None,
            None,
        )
        .expect("priority-only update");
        assert!(found, "{row}: the row exists");
        let stored = ai_memory::db::get_embedding(&conn, &id).expect("read vector");
        assert_eq!(
            stored, None,
            "{row}: the row holds the pre-read document but kept writer B's vector \
             (the clear trusted a flag from the stale pre-read) — #9284 X-1"
        );
        test_hold_hook::disarm(&model);
    }
}

/// T-2 (X-2) MCP over SQLite — A's `memory_update` embeds its document;
/// while that embed is held, B commits a new document and its vector. A's
/// vector write must land 0 rows: B's vector is intact and A's receipt
/// says `failed` / `embedding_failed` (I-1, I-2).
#[test]
fn mcp_update_second_writer_keeps_its_vector_9284() {
    let scratch = tempfile::tempdir_in(scratch_root()).expect("scratch");
    let (model, marker) = unique("t2mcp");
    test_hold_hook::arm_effect(&model, &marker, test_hold_hook::Effect::Vectors);
    let embedder = test_hold_hook::embedder(&model, DIM).expect("embedder");
    let title = "t2-9284-mcp";
    let (db_path, conn, id) = {
        let _identity = AgentIdOverride::set(AGENT);
        mcp_seed(scratch.path(), "t2-mcp", title, &embedder)
    };
    drop(conn);
    let entered = test_hold_hook::arm(&model, &marker, HOLD);
    let writer_a = {
        let (db_path, id, marker, embedder) = (
            db_path.clone(),
            id.clone(),
            marker.clone(),
            embedder.clone(),
        );
        std::thread::spawn(move || {
            let _identity = AgentIdOverride::set(AGENT);
            let conn = ai_memory::db::open(&db_path).expect("writer A connection");
            tool_result(&handle_request_with_embedder_for_test(
                &conn,
                &db_path,
                &call(
                    2,
                    "memory_update",
                    &json!({"id": id, "content": format!("{NEW_CONTENT} {marker}"), "edit_source": "agent"}),
                ),
                &embedder,
            ))
        })
    };
    entered
        .recv_timeout(ENTER_TIMEOUT)
        .expect("writer A reached its embed");
    let vector_b = sqlite_second_writer(&db_path, &id, title, &model);
    let receipt = writer_a.join().expect("writer A joins");
    let conn = ai_memory::db::open(&db_path).expect("reopen");
    assert_eq!(
        ai_memory::db::get_embedding(&conn, &id).expect("read vector"),
        Some(vector_b),
        "mcp: writer A's stale vector write erased or replaced writer B's vector — #9284 X-2"
    );
    assert_eq!(receipt["embed_status"], STATUS_FAILED, "mcp: {receipt}");
    assert_eq!(
        receipt["embed_status_reason"], REASON_EMBEDDING_FAILED,
        "mcp: {receipt}"
    );
    test_hold_hook::disarm(&model);
}

impl Fixture {
    /// Writer B on the branch's own store: a new content commit and its
    /// vector.
    async fn second_writer(&self, id: &str, title: &str) -> Vec<f32> {
        #[cfg(feature = "sal-postgres")]
        if let Some(store) = &self.pg_store {
            use ai_memory::store::{CallerContext, UpdatePatch};
            let ctx = CallerContext::for_agent(AGENT);
            store
                .update(
                    &ctx,
                    id,
                    UpdatePatch {
                        content: Some(DOC_B.to_owned()),
                        ..UpdatePatch::default()
                    },
                )
                .await
                .expect("writer B content commit");
            let vector = expected_vector(&self.model, &embedding_document(title, DOC_B));
            store
                .update_embedding(&ctx, id, Some(&vector), SEED_SPACE)
                .await
                .expect("writer B vector");
            return vector;
        }
        std::future::ready(sqlite_second_writer(&self.db_path, id, title, &self.model)).await
    }

    /// Put `vector` on `id` directly (a node with no embedder cannot).
    async fn put_vector(&self, id: &str, vector: &[f32]) {
        #[cfg(feature = "sal-postgres")]
        if let Some(store) = &self.pg_store {
            store
                .update_embedding(
                    &ai_memory::store::CallerContext::for_agent(AGENT),
                    id,
                    Some(vector),
                    SEED_SPACE,
                )
                .await
                .expect("seed vector");
            return;
        }
        let conn = ai_memory::db::open(&self.db_path).expect("reopen");
        std::future::ready(
            ai_memory::db::set_embedding(&conn, id, vector, SEED_SPACE).expect("seed vector"),
        )
        .await;
    }
}

/// T-2 (X-2) over HTTP `PUT` for one branch.
fn http_second_writer_rows(branch: Branch) {
    runtime().block_on(async {
        let row = format!("http {branch:?} second writer");
        let Some(fx) = fixture_with("t2http", branch, Some(test_hold_hook::Effect::Vectors)).await
        else {
            eprintln!("skip {row}: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let title = format!("t2-9284-{branch:?}");
        let id = seed(&fx, &title, OLD_CONTENT).await;
        let entered = test_hold_hook::arm(&fx.model, &fx.marker, HOLD);
        let put = request(
            "PUT",
            &format!("/api/v1/memories/{id}"),
            &json!({"content": format!("{NEW_CONTENT} {}", fx.marker), "agent_id": AGENT}),
        );
        let writer_a = tokio::spawn(send(fx.router.clone(), put));
        entered
            .recv_timeout(ENTER_TIMEOUT)
            .expect("writer A reached its embed");
        let vector_b = fx.second_writer(&id, &title).await;
        let (status, receipt) = writer_a.await.expect("writer A joins");
        assert!(status.is_success(), "{row}: {status} {receipt}");
        assert_eq!(
            fx.stored(&id).await,
            Some(vector_b),
            "{row}: writer A's stale vector write erased or replaced writer B's vector — #9284 X-2"
        );
        assert_eq!(receipt["embed_status"], STATUS_FAILED, "{row}: {receipt}");
        assert_eq!(
            receipt["embed_status_reason"], REASON_EMBEDDING_FAILED,
            "{row}: {receipt}"
        );
    });
}

#[test]
fn http_update_second_writer_keeps_its_vector_sqlite_9284() {
    http_second_writer_rows(Branch::Sqlite);
}

#[cfg(feature = "sal")]
#[test]
fn http_update_second_writer_keeps_its_vector_postgres_branch_9284() {
    http_second_writer_rows(Branch::FakePg);
}

#[cfg(feature = "sal-postgres")]
#[test]
fn http_update_second_writer_keeps_its_vector_real_postgres_9284() {
    http_second_writer_rows(Branch::RealPg);
}

/// The HTTP write a T-3 row drives.
#[derive(Clone, Copy, Debug)]
enum FailureWrite {
    Create,
    Put,
}

/// T-3 (X-5) — one row per failure mode, the exact reason each.
fn failure_reason_rows(branch: Branch) {
    use test_hold_hook::Effect;
    runtime().block_on(async {
        let rows: [(Effect, FailureWrite, &str, &str); 4] = [
            (
                Effect::Panic,
                FailureWrite::Create,
                STATUS_FAILED,
                REASON_TASK_INCOMPLETE,
            ),
            (
                Effect::Panic,
                FailureWrite::Put,
                STATUS_FAILED,
                REASON_TASK_INCOMPLETE,
            ),
            (
                Effect::EmptyVector,
                FailureWrite::Create,
                STATUS_FAILED,
                REASON_EMPTY_VECTOR,
            ),
            (
                Effect::EmptyVector,
                FailureWrite::Put,
                STATUS_FAILED,
                REASON_EMPTY_VECTOR,
            ),
        ];
        for (effect, write, status_word, reason) in rows {
            let row = format!("reason {branch:?} {effect:?} {write:?}");
            // The fake-postgres branch has no create (501, see http_rows).
            #[cfg(feature = "sal")]
            if matches!((branch, write), (Branch::FakePg, FailureWrite::Create)) {
                continue;
            }
            let Some(fx) = fixture_with("t3", branch, Some(effect)).await else {
                eprintln!("skip {row}: AI_MEMORY_TEST_POSTGRES_URL unset");
                return;
            };
            let title = format!("t3-9284-{effect:?}-{write:?}");
            let content = format!("{NEW_CONTENT} {}", fx.marker);
            let (status, receipt, id) = match write {
                FailureWrite::Create => {
                    let (status, receipt) = send(
                        fx.router.clone(),
                        request("POST", "/api/v1/memories", &memory_body(&title, &content)),
                    )
                    .await;
                    let id = receipt["id"].as_str().unwrap_or_default().to_string();
                    (status, receipt, id)
                }
                FailureWrite::Put => {
                    let id = seed(&fx, &title, OLD_CONTENT).await;
                    let (status, receipt) = send(
                        fx.router.clone(),
                        request(
                            "PUT",
                            &format!("/api/v1/memories/{id}"),
                            &json!({"content": content, "agent_id": AGENT}),
                        ),
                    )
                    .await;
                    (status, receipt, id)
                }
            };
            assert!(status.is_success(), "{row}: {status} {receipt}");
            assert_eq!(fx.stored(&id).await, None, "{row}: a vector was stored");
            assert_eq!(receipt["embed_status"], status_word, "{row}: {receipt}");
            assert_eq!(receipt["embed_status_reason"], reason, "{row}: {receipt}");
        }

        // Oversize: the document exceeds the embed cap (create).
        #[cfg(feature = "sal")]
        let oversize_runs = !matches!(branch, Branch::FakePg);
        #[cfg(not(feature = "sal"))]
        let oversize_runs = true;
        if oversize_runs {
            let row = format!("reason {branch:?} oversize create");
            let Some(fx) = fixture_with("t3big", branch, Some(Effect::Vectors)).await else {
                eprintln!("skip {row}: AI_MEMORY_TEST_POSTGRES_URL unset");
                return;
            };
            let title = "t3-9284-oversize";
            let content = "x".repeat(ai_memory::embeddings::EMBED_MAX_BYTES + 1);
            let doc_len = embedding_document(title, &content).len();
            let (status, receipt) = send(
                fx.router.clone(),
                request("POST", "/api/v1/memories", &memory_body(title, &content)),
            )
            .await;
            assert!(status.is_success(), "{row}: {status}");
            let id = receipt["id"].as_str().expect("id").to_string();
            assert_eq!(fx.stored(&id).await, None, "{row}: a vector was stored");
            assert_eq!(receipt["embed_status"], STATUS_SKIPPED, "{row}");
            assert_eq!(
                receipt["embed_status_reason"],
                format!(
                    "content {doc_len} bytes exceeds embed cap {} bytes",
                    ai_memory::embeddings::EMBED_MAX_BYTES
                ),
                "{row}"
            );
        }
    });
}

#[test]
fn http_failure_reasons_are_exact_sqlite_9284() {
    failure_reason_rows(Branch::Sqlite);
}

#[cfg(feature = "sal")]
#[test]
fn http_failure_reasons_are_exact_postgres_branch_9284() {
    failure_reason_rows(Branch::FakePg);
}

#[cfg(feature = "sal-postgres")]
#[test]
fn http_failure_reasons_are_exact_real_postgres_9284() {
    failure_reason_rows(Branch::RealPg);
}

/// T-3 (X-3) — a node with NO embedder re-stores over a live row with a
/// new body: the old vector is cleared and the receipt must say so with
/// `skipped` / `no embedder configured` (docs/API_REFERENCE.md create
/// receipt rule).
fn no_embedder_upsert_rows(branch: Branch) {
    runtime().block_on(async {
        let row = format!("no-embedder upsert {branch:?}");
        let Some(fx) = fixture_with("t3none", branch, None).await else {
            eprintln!("skip {row}: AI_MEMORY_TEST_POSTGRES_URL unset");
            return;
        };
        let title = format!("t3-9284-none-{branch:?}");
        let (status, created) = send(
            fx.router.clone(),
            request(
                "POST",
                "/api/v1/memories",
                &memory_body(&title, OLD_CONTENT),
            ),
        )
        .await;
        assert!(status.is_success(), "{row}: {status} {created}");
        let id = created["id"].as_str().expect("id").to_string();
        let old = expected_vector(&fx.model, &embedding_document(&title, OLD_CONTENT));
        fx.put_vector(&id, &old).await;
        let mut body = memory_body(&title, NEW_CONTENT);
        body["on_conflict"] = json!("merge");
        body["force"] = json!(true);
        let (status, receipt) = send(
            fx.router.clone(),
            request("POST", "/api/v1/memories", &body),
        )
        .await;
        assert!(status.is_success(), "{row}: {status} {receipt}");
        assert_eq!(
            receipt["id"].as_str(),
            Some(id.as_str()),
            "{row}: {receipt}"
        );
        assert_eq!(fx.stored(&id).await, None, "{row}: the old vector stayed");
        assert_eq!(receipt["embed_status"], STATUS_SKIPPED, "{row}: {receipt}");
        assert_eq!(
            receipt["embed_status_reason"], REASON_NO_EMBEDDER,
            "{row}: {receipt}"
        );
    });
}

#[test]
fn http_create_upsert_without_embedder_reports_skipped_sqlite_9284() {
    no_embedder_upsert_rows(Branch::Sqlite);
}

#[cfg(feature = "sal-postgres")]
#[test]
fn http_create_upsert_without_embedder_reports_skipped_real_postgres_9284() {
    no_embedder_upsert_rows(Branch::RealPg);
}
