// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8497 (umbrella #8493, control E + data F2) — `entity_register` owner is the
//! verified subject on every entry point and both backends.
//!
//! Pre-fix: the MCP tool let a wire `agent_id` beat the process principal, the
//! HTTP route preferred `body.agent_id` over `X-Agent-Id`, and the postgres
//! funnel `or_insert`-ed the owner so an inline `metadata.agent_id` won. The
//! sqlite twin carried the #3171 `insert` fix; postgres did not.
//!
//! Cells: (1) caller X + body `agent_id: Y` is refused with an audit row and
//! no entity row; (2) no body owner stamps X; (3) alias lookup returns X's
//! entity; (4) HTTP header-vs-body; (5) sqlite/postgres parity through the SAL
//! trait (postgres cell gated on `AI_MEMORY_TEST_POSTGRES_URL`).

#![allow(
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::uninlined_format_args
)]

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::identity::test_agent_id::AgentIdOverride;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

const OWNER_X: &str = "ai:owner-x-8497";
const FORGED_Y: &str = "ai:forged-y-8497";

/// Process-wide audit trail file (the sink is global to the test binary).
fn audit_trail() -> &'static PathBuf {
    static TRAIL: OnceLock<(PathBuf, tempfile::TempDir)> = OnceLock::new();
    &TRAIL
        .get_or_init(|| {
            let dir = tempfile::tempdir().expect("audit dir");
            let path = dir.path().join("audit.log");
            ai_memory::audit::init(&path, true, false).expect("audit init");
            (path, dir)
        })
        .0
}

fn unique(tag: &str) -> String {
    format!("{tag}-{}", uuid::Uuid::new_v4().simple())
}

/// Audit lines that mention `needle` and carry a deny outcome.
fn deny_rows(needle: &str) -> usize {
    std::fs::read_to_string(audit_trail())
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains(needle) && l.contains("\"deny\""))
        .count()
}

fn open_db() -> (rusqlite::Connection, NamedTempFile) {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    (conn, f)
}

fn entity_rows(conn: &rusqlite::Connection, ns: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
        [ns],
        |r| r.get(0),
    )
    .expect("count")
}

fn owner_of(conn: &rusqlite::Connection, ns: &str, title: &str) -> Option<String> {
    conn.query_row(
        "SELECT json_extract(metadata, '$.agent_id') FROM memories \
         WHERE namespace = ?1 AND title = ?2",
        [ns, title],
        |r| r.get::<_, Option<String>>(0),
    )
    .expect("owner row")
}

#[test]
fn mcp_wire_agent_id_mismatch_is_refused_with_audit_row_and_no_row() {
    let _ = audit_trail();
    let _env = AgentIdOverride::set(OWNER_X);
    let (conn, _f) = open_db();
    let ns = unique("ns-mismatch");
    let err = ai_memory::mcp::handle_entity_register(
        &conn,
        &json!({"canonical_name": "Acme", "namespace": ns, "agent_id": FORGED_Y}),
        None,
    )
    .expect_err("a wire agent_id that differs from the caller is refused");
    assert!(err.contains("mismatch"), "typed refusal text, got: {err}");
    assert_eq!(entity_rows(&conn, &ns), 0, "no entity row on refusal");
    assert_eq!(deny_rows(&ns), 1, "exactly one deny audit row for {ns}");
}

#[test]
fn mcp_inline_metadata_agent_id_mismatch_is_refused() {
    let _ = audit_trail();
    let _env = AgentIdOverride::set(OWNER_X);
    let (conn, _f) = open_db();
    let ns = unique("ns-inline");
    let err = ai_memory::mcp::handle_entity_register(
        &conn,
        &json!({
            "canonical_name": "Acme",
            "namespace": ns,
            "metadata": {"agent_id": FORGED_Y},
        }),
        None,
    )
    .expect_err("an inline metadata.agent_id that differs is refused");
    assert!(err.contains("mismatch"), "got: {err}");
    assert_eq!(entity_rows(&conn, &ns), 0);
    assert_eq!(deny_rows(&ns), 1);
}

#[test]
fn mcp_no_body_owner_stamps_the_caller_and_alias_resolves_to_it() {
    let _env = AgentIdOverride::set(OWNER_X);
    let (conn, _f) = open_db();
    let ns = unique("ns-owner");
    let alias = unique("alias");
    let out = ai_memory::mcp::handle_entity_register(
        &conn,
        &json!({"canonical_name": "Acme", "namespace": ns, "aliases": [alias]}),
        None,
    )
    .expect("register as the caller");
    assert_eq!(out["created"], true);
    assert_eq!(owner_of(&conn, &ns, "Acme").as_deref(), Some(OWNER_X));
    let got = ai_memory::db::entity_get_by_alias(&conn, &alias, Some(&ns))
        .expect("alias lookup")
        .expect("alias resolves");
    assert_eq!(got.entity_id, out["entity_id"].as_str().unwrap());
}

#[test]
fn mcp_matching_wire_agent_id_is_accepted() {
    let _env = AgentIdOverride::set(OWNER_X);
    let (conn, _f) = open_db();
    let ns = unique("ns-match");
    ai_memory::mcp::handle_entity_register(
        &conn,
        &json!({"canonical_name": "Acme", "namespace": ns, "agent_id": OWNER_X}),
        None,
    )
    .expect("a wire agent_id equal to the caller is fine");
    assert_eq!(owner_of(&conn, &ns, "Acme").as_deref(), Some(OWNER_X));
}

// ---- HTTP ----------------------------------------------------------------

fn build_router_fixture() -> (axum::Router, NamedTempFile) {
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
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
        ..Default::default()
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn post_entity(router: &axum::Router, body: Value, caller: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/entities")
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

fn row_count_in(f: &NamedTempFile, ns: &str) -> i64 {
    let conn = ai_memory::db::open(f.path()).expect("reopen");
    entity_rows(&conn, ns)
}

#[tokio::test]
async fn kg_http_entity_register_rejects_body_agent_id_mismatch_8493() {
    let _ = audit_trail();
    let (router, f) = build_router_fixture();
    let ns = unique("ns-http-mismatch");
    let (status, body) = post_entity(
        &router,
        json!({"canonical_name": "Acme", "namespace": ns, "agent_id": FORGED_Y}),
        OWNER_X,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "AGENT_ID_MISMATCH", "typed code, body={body}");
    assert_eq!(row_count_in(&f, &ns), 0, "no entity row on refusal");
    assert_eq!(deny_rows(&ns), 1, "one deny audit row for {ns}");
}

#[tokio::test]
async fn kg_http_entity_register_rejects_inline_metadata_agent_id_mismatch_8493() {
    let (router, f) = build_router_fixture();
    let ns = unique("ns-http-inline");
    let (status, body) = post_entity(
        &router,
        json!({
            "canonical_name": "Acme",
            "namespace": ns,
            "metadata": {"agent_id": FORGED_Y},
        }),
        OWNER_X,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(row_count_in(&f, &ns), 0);
}

#[tokio::test]
async fn kg_http_entity_register_owner_is_the_header_principal_8493() {
    let (router, f) = build_router_fixture();
    let ns = unique("ns-http-owner");
    let (status, body) = post_entity(
        &router,
        json!({"canonical_name": "Acme", "namespace": ns}),
        OWNER_X,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body={body}");
    let conn = ai_memory::db::open(f.path()).expect("reopen");
    assert_eq!(owner_of(&conn, &ns, "Acme").as_deref(), Some(OWNER_X));
}

// ---- SAL trait parity (sqlite always under `sal`, postgres when reachable) --

#[cfg(feature = "sal")]
mod sal_parity {
    use ai_memory::store::{CallerContext, MemoryStore, StoreError};
    use serde_json::json;

    use super::{FORGED_Y, OWNER_X, unique};

    /// Run the four owner cells against `store` and return a backend-neutral
    /// transcript, so the sqlite and postgres runs can be asserted equal.
    pub async fn transcript(store: &dyn MemoryStore) -> Vec<String> {
        let ns = unique("ns-parity");
        let ctx = CallerContext::for_agent(OWNER_X);
        let mut out = Vec::new();

        // A: wire agent_id disagrees with the verified caller.
        let a = store
            .entity_register(
                &ctx,
                "A",
                &ns,
                &["alias-a".into()],
                &json!({}),
                Some(FORGED_Y),
            )
            .await;
        out.push(describe("A wire-mismatch", &a));
        // B: inline metadata.agent_id disagrees.
        let b = store
            .entity_register(
                &ctx,
                "B",
                &ns,
                &["alias-b".into()],
                &json!({"agent_id": FORGED_Y}),
                Some(OWNER_X),
            )
            .await;
        out.push(describe("B inline-mismatch", &b));
        // C: no owner supplied.
        let c = store
            .entity_register(&ctx, "C", &ns, &["alias-c".into()], &json!({}), None)
            .await;
        out.push(describe("C no-owner", &c));
        // D: matching claims.
        let d = store
            .entity_register(
                &ctx,
                "D",
                &ns,
                &["alias-d".into()],
                &json!({"agent_id": OWNER_X}),
                Some(OWNER_X),
            )
            .await;
        out.push(describe("D matching", &d));

        for (label, alias) in [("A", "alias-a"), ("B", "alias-b")] {
            let hit = store
                .entity_get_by_alias(alias, Some(&ns))
                .await
                .expect("alias lookup");
            out.push(format!("{label} row present: {}", hit.is_some()));
        }
        for (label, id) in [("C", &c), ("D", &d)] {
            if let Ok(reg) = id {
                let mem = store.get(&ctx, &reg.entity_id).await.expect("get");
                out.push(format!(
                    "{label} owner: {}",
                    mem.metadata["agent_id"].as_str().unwrap_or("<none>")
                ));
            }
        }
        out
    }

    fn describe(
        label: &str,
        r: &Result<ai_memory::models::EntityRegistration, StoreError>,
    ) -> String {
        match r {
            Ok(reg) => format!("{label}: created={}", reg.created),
            Err(StoreError::PermissionDenied { .. }) => format!("{label}: refused"),
            Err(other) => format!("{label}: unexpected {other}"),
        }
    }

    pub fn expected() -> Vec<String> {
        vec![
            "A wire-mismatch: refused".to_string(),
            "B inline-mismatch: refused".to_string(),
            "C no-owner: created=true".to_string(),
            "D matching: created=true".to_string(),
            "A row present: false".to_string(),
            "B row present: false".to_string(),
            format!("C owner: {OWNER_X}"),
            format!("D owner: {OWNER_X}"),
        ]
    }
}

#[cfg(feature = "sal")]
#[tokio::test]
async fn sqlite_store_entity_register_owner_is_the_verified_subject_8497() {
    let f = NamedTempFile::new().expect("tempfile");
    let store = ai_memory::store::sqlite::SqliteStore::open(f.path()).expect("open");
    assert_eq!(sal_parity::transcript(&store).await, sal_parity::expected());
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn pg_resolved_id_wins_over_inline_metadata_agent_id_8497() {
    let Some(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("skip pg_resolved_id_wins_over_inline_metadata_agent_id_8497: URL unset");
        return;
    };
    let pg = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let pg_transcript = sal_parity::transcript(&pg).await;
    assert_eq!(pg_transcript, sal_parity::expected(), "postgres cells");

    let f = NamedTempFile::new().expect("tempfile");
    let sqlite = ai_memory::store::sqlite::SqliteStore::open(f.path()).expect("open");
    assert_eq!(
        sal_parity::transcript(&sqlite).await,
        pg_transcript,
        "sqlite and postgres must agree"
    );
}
