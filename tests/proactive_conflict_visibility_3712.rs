// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3712 — the near-duplicate (proactive conflict, #519) refusal on store is
//! DISCRETIONARY: we chose to run the check, so on a row the caller cannot
//! read it must NOT FIRE AT ALL — unlike the STRUCTURAL `(title, namespace)`
//! refusal of #3696, which may fire and must not describe (a 409 with an
//! empty `existing_id`, one bit). Here the invisible neighbour costs the
//! caller ZERO bits: the write SUCCEEDS and the response never names or
//! describes the neighbour.
//!
//! The pin is the PAIR on one sink, per the Conductor's ruling: the store of
//! a near-duplicate of another agent's private row must produce a
//! SUCCESSFUL write (the row is present, stamped to the writer) AND a
//! response that carries neither the neighbour's id nor its title — an
//! assertion on absence alone would pass just as well if the write started
//! failing outright. Plus the allowed-path control on the SAME sink: the
//! same near-duplicate by a caller who CAN read the row (its owner, and the
//! trust-all viewer) is still refused and still named, so the feature is
//! scoped, not disabled.
//!
//! Both production sinks are pinned with their own viewer resolution:
//! * MCP `memory_store` — the viewer is `identity::resolve_read_visibility_caller`
//!   (`AI_MEMORY_AGENT_ID`), so this binary is DEDICATED: the env mutation
//!   goes through `common::EnvVarGuard` (the process-wide `ENV_LOCK`) and can
//!   leak into no other suite.
//! * HTTP `POST /api/v1/memories` — the viewer is the resolved request agent
//!   (`X-Agent-Id`); the embedder is a wiremock ollama answering `/api/embed`
//!   with ONE fixed vector, so any two writes are cosine 1.0 and only the
//!   visibility filter decides whether the check fires.

#![allow(clippy::too_many_lines)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::doc_markdown)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::embeddings::{Embed, Embedder};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};

const NS: &str = "team/ops-3712";
const ALICE: &str = "ai:alice-3712";
const BOB: &str = "ai:bob-3712";
const ALICE_TITLE: &str = "alice private canary deploy note";
const ALICE_CONTENT: &str =
    "the deploy uses canary health checks before traffic shifts to the new replica set";
const NEAR_DUP_TITLE: &str = "bob deploy note";
/// Differs from alice's content (the #519 guard is near-duplicate WITH
/// differing content).
const NEAR_DUP_CONTENT: &str = "the deploy uses canary health checks before traffic shifts to the new replica set and rolls back on failure";

/// The neighbour must be absent from the response as an id AND as a title,
/// and the response must not carry the refusal shape at all.
fn assert_neighbour_absent(rendered: &str, neighbour_id: &str) {
    assert!(
        !rendered.contains(neighbour_id),
        "the invisible neighbour's id leaked into the response: {rendered}"
    );
    assert!(
        !rendered.contains(ALICE_TITLE),
        "the invisible neighbour's title leaked into the response: {rendered}"
    );
    assert!(
        !rendered.contains("near-duplicate") && !rendered.contains("existing_id"),
        "the response carries the refusal shape for a check that must not have fired: {rendered}"
    );
}

fn row_owner(conn: &rusqlite::Connection, id: &str) -> Option<String> {
    conn.query_row(
        "SELECT json_extract(metadata, '$.agent_id') FROM memories WHERE id = ?1",
        [id],
        |r| r.get(0),
    )
    .ok()
}

// ---------------------------------------------------------------------------
// MCP `memory_store` sink
// ---------------------------------------------------------------------------

/// Fixed 8-dim vector regardless of text — any two writes are cosine 1.0.
struct ConstEmbed;

impl Embed for ConstEmbed {
    fn embed(&self, _text: &str) -> anyhow::Result<Vec<f32>> {
        Ok(vec![0.5_f32; 8])
    }
    fn embed_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<f32>>> {
        Ok(texts.iter().map(|_| vec![0.5_f32; 8]).collect())
    }
}

fn mcp_store(
    conn: &rusqlite::Connection,
    db_path: &std::path::Path,
    title: &str,
    content: &str,
    scope: &str,
) -> Result<Value, String> {
    let ttl = ResolvedTtl::default();
    let params = json!({
        "title": title,
        "content": content,
        "namespace": NS,
        "tier": "long",
        "scope": scope,
    });
    ai_memory::mcp::tools::handle_store_for_tests(
        conn,
        db_path,
        &params,
        Some(&ConstEmbed as &dyn Embed),
        None,
        None,
        &ttl,
        false,
        None,
        None,
    )
}

#[test]
fn mcp_store_succeeds_past_an_invisible_near_duplicate_and_the_owner_is_still_refused_3712() {
    common::permissive_attestation_for_tests();
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("mcp-3712.db");
    let conn = ai_memory::db::open(&db_path).expect("db::open");

    // Alice seeds a PRIVATE row through the same sink, as herself.
    let alice_id = {
        let _alice = common::EnvVarGuard::set("AI_MEMORY_AGENT_ID", ALICE.to_string());
        let resp = mcp_store(&conn, &db_path, ALICE_TITLE, ALICE_CONTENT, "private")
            .expect("alice's seed store lands");
        resp["id"].as_str().expect("seed id").to_owned()
    };
    assert_eq!(row_owner(&conn, &alice_id).as_deref(), Some(ALICE));

    // THE PAIR — bob, who cannot read alice's row, stores a near-duplicate:
    // (present) the write SUCCEEDS and his row is on disk, stamped to him;
    // (absent) the response names neither alice's id nor her title and
    // carries no refusal shape.
    {
        let _bob = common::EnvVarGuard::set("AI_MEMORY_AGENT_ID", BOB.to_string());
        let resp = mcp_store(&conn, &db_path, NEAR_DUP_TITLE, NEAR_DUP_CONTENT, "private")
            .unwrap_or_else(|e| {
                panic!("bob's store must SUCCEED past a neighbour he cannot read; refused: {e}")
            });
        let bob_id = resp["id"].as_str().expect("bob's id").to_owned();
        assert_ne!(bob_id, alice_id, "a fresh row, not a merge into alice's");
        assert_eq!(
            row_owner(&conn, &bob_id).as_deref(),
            Some(BOB),
            "bob's row is present and stamped to bob"
        );
        assert_neighbour_absent(&resp.to_string(), &alice_id);
    }

    // ALLOWED-PATH CONTROL, same sink — a caller who CAN read alice's row
    // (its owner; and the trust-all viewer with no identity) is still
    // refused, and the refusal still names the row. One guard at a time:
    // each holds the process-wide env lock for its lifetime.
    let control = |label: &str| {
        let err = mcp_store(
            &conn,
            &db_path,
            &format!("{NEAR_DUP_TITLE} ({label})"),
            NEAR_DUP_CONTENT,
            "private",
        )
        .expect_err("a visible near-duplicate is still refused");
        assert!(
            err.starts_with("CONFLICT:") && err.contains("near-duplicates"),
            "{label}: the visible near-duplicate keeps the #519 refusal: {err}"
        );
        assert!(
            err.contains(&alice_id),
            "{label}: the visible refusal still names alice's row: {err}"
        );
    };
    {
        let _owner = common::EnvVarGuard::set("AI_MEMORY_AGENT_ID", ALICE.to_string());
        control("owner");
    }
    {
        let _trust_all = common::EnvVarGuard::remove("AI_MEMORY_AGENT_ID");
        control("trust-all");
    }
}

// ---------------------------------------------------------------------------
// HTTP `POST /api/v1/memories` sink
// ---------------------------------------------------------------------------

/// A wiremock ollama whose `/api/embed` answers ONE fixed 768-dim vector.
async fn mock_embed_server() -> MockServer {
    let server = MockServer::start().await;
    let vector: Vec<f32> = vec![0.5; 768];
    Mock::given(method("POST"))
        .and(path("/api/embed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"embeddings": [vector]})))
        .mount(&server)
        .await;
    server
}

fn build_router(embed_base_url: &str) -> (axum::Router, Db, tempfile::NamedTempFile) {
    let db_tmp = tempfile::NamedTempFile::new().expect("db tempfile");
    let db_path = db_tmp.path().to_path_buf();
    let _ = ai_memory::db::open(&db_path).expect("db::open");
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let client = ai_memory::llm::OllamaClient::new_with_url_no_health_check(
        embed_base_url,
        "nomic-embed-text",
    )
    .expect("mock ollama client");
    let embedder = Embedder::new_ollama(Arc::new(client));
    let app_state = AppState {
        db: db.clone(),
        embedder: Arc::new(Some(embedder)),
        vector_index: Arc::new(Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        #[cfg(feature = "sal")]
        store: Arc::new(
            ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"),
        ),
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
    (
        ai_memory::build_router(api_key_state, app_state),
        db,
        db_tmp,
    )
}

async fn http_store(
    router: &axum::Router,
    agent: &str,
    title: &str,
    content: &str,
) -> (StatusCode, Value) {
    let body = json!({
        "tier": "long",
        "namespace": NS,
        "title": title,
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "metadata": {},
        "scope": "private",
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories")
        .header("content-type", "application/json")
        .header("x-agent-id", agent)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed)
}

#[tokio::test]
async fn http_create_succeeds_past_an_invisible_near_duplicate_and_the_owner_is_still_refused_3712()
{
    common::permissive_attestation_for_tests();
    let server = mock_embed_server().await;
    let (router, db, _tmp) = build_router(&server.uri());

    // Alice seeds a PRIVATE row through the same sink, as herself.
    let (status, seed) = http_store(&router, ALICE, ALICE_TITLE, ALICE_CONTENT).await;
    assert_eq!(status, StatusCode::CREATED, "{seed}");
    let alice_id = seed["id"].as_str().expect("seed id").to_owned();
    {
        let lock = db.lock().await;
        assert_eq!(row_owner(&lock.0, &alice_id).as_deref(), Some(ALICE));
    }

    // THE PAIR — bob (the resolved request agent) cannot read alice's row:
    // 201 with his row present and stamped to him, and a body that names
    // neither alice's id nor her title and carries no refusal shape.
    let (status, resp) = http_store(&router, BOB, NEAR_DUP_TITLE, NEAR_DUP_CONTENT).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "bob's create must SUCCEED past a neighbour he cannot read: {resp}"
    );
    let bob_id = resp["id"].as_str().expect("bob's id").to_owned();
    assert_ne!(bob_id, alice_id);
    {
        let lock = db.lock().await;
        assert_eq!(
            row_owner(&lock.0, &bob_id).as_deref(),
            Some(BOB),
            "bob's row is present and stamped to bob"
        );
    }
    assert_neighbour_absent(&resp.to_string(), &alice_id);

    // ALLOWED-PATH CONTROL, same sink — alice herself is still refused with
    // the #519 409, and the 409 still names her own row (id AND title).
    let (status, refusal) =
        http_store(&router, ALICE, "alice second deploy note", NEAR_DUP_CONTENT).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a visible near-duplicate is still refused: {refusal}"
    );
    assert_eq!(refusal["existing_id"].as_str(), Some(alice_id.as_str()));
    assert_eq!(refusal["existing_title"].as_str(), Some(ALICE_TITLE));
}
