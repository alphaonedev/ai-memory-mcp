// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3549 — the DENIED / ALLOWED matrix for the caller-authority
//! chokepoints, driven through the REAL router (`ai_memory::build_router`)
//! and the REAL `ai-memory mcp` binary over stdio, not through the resolver
//! in isolation (that matrix lives in `identity::authority::tests`).
//!
//! HTTP cells prove the layer runs on a route that previously IGNORED the
//! header (`GET /api/v1/memories` list) — a malformed principal assertion is
//! refused there now — while the probe and federation exemptions are NOT
//! refused by the authority layer. MCP cells prove a valid configured identity
//! and the unset (local-operator) identity both serve through the real
//! dispatch, and an unusable configured identity never serves a single line;
//! the dispatch-level refusal on an already-running server is pinned in-crate
//! (`mcp::authority_dispatch_3549_tests`) through the #3523 thread-local seam.
//!
//! No process env is mutated in this binary: identity is passed to the CHILD
//! process environment only.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

const ENV_AGENT_ID: &str = "AI_MEMORY_AGENT_ID";

// ---------------------------------------------------------------------------
// HTTP — the real router
// ---------------------------------------------------------------------------

fn router(api_key: Option<&str>, admins: Vec<String>) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(api_key.is_some());
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("open");
    let db: ai_memory::handlers::Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ai_memory::config::ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store: Arc<dyn ai_memory::store::MemoryStore> = {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        let p = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&p).expect("open SqliteStore"))
    };
    let enrolled = Arc::new(ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty());
    let app_state = ai_memory::handlers::AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(ai_memory::config::FeatureTier::Keyword.config()),
        scoring: Arc::new(ai_memory::config::ResolvedScoring::default()),
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
        federation_nonce_cache: Arc::new(
            ai_memory::identity::replay::FederationNonceCache::default(),
        ),
        autonomous_hooks: false,
        auto_tag_queue: None,
        atomise_queue: None,
        recall_scope: Arc::new(None),
        deferred_audit_queue: Arc::new(None),
        admin_agent_ids: Arc::new(admins),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::clone(&enrolled),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ai_memory::handlers::ApiKeyState {
        key: api_key.map(str::to_string),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn get(path: &str, agent: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(a) = agent {
        b = b.header(ai_memory::HEADER_AGENT_ID, a);
    }
    b.body(Body::empty()).expect("request")
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// DENIED — a malformed `X-Agent-Id` is refused at the chokepoint on the
/// list route, which historically did not validate the header itself.
#[tokio::test]
async fn http_malformed_principal_is_refused_before_the_handler_3549() {
    let app = router(None, vec![]);
    let resp = app
        .oneshot(get("/api/v1/memories", Some("bad id with spaces")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert_eq!(v["code"], ai_memory::errors::error_codes::VALIDATION_FAILED);
    assert!(
        v["error"].as_str().is_some_and(|s| s.starts_with("invalid agent_id")),
        "{v}"
    );
}

/// DENIED — a RESERVED principal (`daemon`) is refused with the #977 reason,
/// on a route that is not an admin route.
#[tokio::test]
async fn http_reserved_principal_is_refused_with_the_reserved_reason_3549() {
    let app = router(None, vec![]);
    let resp = app
        .oneshot(get("/api/v1/memories", Some("daemon")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let v = body_json(resp).await;
    assert!(
        v["error"]
            .as_str()
            .is_some_and(|s| s.contains("reserved for internal use")),
        "{v}"
    );
}

/// ALLOWED — a valid asserted principal reaches the handler.
#[tokio::test]
async fn http_valid_principal_reaches_the_handler_3549() {
    let app = router(None, vec![]);
    let resp = app
        .oneshot(get("/api/v1/memories", Some("ai:alice")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// ALLOWED — no asserted identity is the anonymous per-request principal,
/// never a refusal.
#[tokio::test]
async fn http_no_principal_is_anonymous_and_allowed_3549() {
    let app = router(None, vec![]);
    let resp = app.oneshot(get("/api/v1/memories", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// EXEMPT — the liveness probe is never refused on identity.
#[tokio::test]
async fn http_health_probe_is_exempt_from_the_authority_layer_3549() {
    let app = router(None, vec![]);
    let resp = app
        .oneshot(get(
            ai_memory::handlers::routes::HEALTH,
            Some("bad id with spaces"),
        ))
        .await
        .unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "/health must not fail on a header quirk"
    );
}

/// EXEMPT — the federation boundary is authenticated by the peer key, not by
/// `X-Agent-Id`; the authority layer attaches nothing and refuses nothing
/// there (ruling 4). Whatever the receiver answers, it is NOT the authority
/// layer's typed 400.
#[tokio::test]
async fn http_federation_boundary_is_not_gated_by_the_authority_layer_3549() {
    let app = router(None, vec![]);
    let req = Request::builder()
        .method("POST")
        .uri(ai_memory::handlers::routes::SYNC_PUSH)
        .header(ai_memory::HEADER_AGENT_ID, "bad id with spaces")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let v = body_json(resp).await;
    let authority_refusal = status == StatusCode::BAD_REQUEST
        && v["error"]
            .as_str()
            .is_some_and(|s| s.starts_with("invalid agent_id"));
    assert!(
        !authority_refusal,
        "the federation boundary must not be gated by the authority layer: {status} {v}"
    );
}

/// The #984 contract on the ADMIN route is preserved through the chokepoint:
/// invalid → 400 with the validator reason; a legitimate non-admin → 403.
#[tokio::test]
async fn http_admin_route_keeps_the_984_contract_through_the_chokepoint_3549() {
    let app = router(Some("k"), vec!["ai:operator".to_string()]);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(ai_memory::handlers::routes::STATS)
                .header(ai_memory::HEADER_API_KEY, "k")
                .header(ai_memory::HEADER_AGENT_ID, "bad;rm")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(ai_memory::handlers::routes::STATS)
                .header(ai_memory::HEADER_API_KEY, "k")
                .header(ai_memory::HEADER_AGENT_ID, "ai:not-an-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// MCP — the real binary over stdio (`CARGO_BIN_EXE_ai-memory`)
// ---------------------------------------------------------------------------

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

struct McpChild {
    child: Child,
}

impl Drop for McpChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn scratch_dir() -> std::path::PathBuf {
    let d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("authority-3549");
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

/// Spawn `ai-memory mcp` with the given `AI_MEMORY_AGENT_ID` disposition
/// (`Some(v)` sets it, `None` removes it from the child env).
fn spawn_mcp(agent_id: Option<&str>) -> (McpChild, ChildStdin, mpsc::Receiver<String>) {
    let dir = scratch_dir();
    let db = dir.join(format!("mcp-{}.db", uuid::Uuid::new_v4()));
    let key_dir = dir.join(format!("keys-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&key_dir).expect("key dir");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &key_dir)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env_remove(ENV_AGENT_ID);
    if let Some(a) = agent_id {
        cmd.env(ENV_AGENT_ID, a);
    }
    let mut child = cmd
        .args([
            "--db",
            db.to_str().expect("utf8 path"),
            "mcp",
            "--profile",
            "core",
            "--tier",
            "keyword",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ai-memory mcp");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut sink = stderr;
            let mut buf = [0u8; 4096];
            while let Ok(n) = sink.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        });
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    (McpChild { child }, stdin, rx)
}

fn send(stdin: &mut ChildStdin, rx: &mpsc::Receiver<String>, req: &serde_json::Value) -> serde_json::Value {
    writeln!(stdin, "{req}").expect("write request");
    let line = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("mcp response within 60s");
    serde_json::from_str(&line).expect("json response")
}

fn call(id: u64, tool: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    })
}

/// ALLOWED — a valid configured identity serves a READ and a WRITE tool
/// through the real stdio dispatch; the owner reads back its own row.
#[test]
fn mcp_valid_configured_identity_serves_read_and_write_3549() {
    let (_child, mut stdin, rx) = spawn_mcp(Some("ai:alice"));
    let stored = send(
        &mut stdin,
        &rx,
        &call(1, "memory_store", serde_json::json!({
            "title": "t-3549", "content": "c-3549", "namespace": "ns-3549"
        })),
    );
    assert!(stored["error"].is_null(), "{stored}");
    let listed = send(
        &mut stdin,
        &rx,
        &call(2, "memory_list", serde_json::json!({"namespace": "ns-3549"})),
    );
    assert!(listed["error"].is_null(), "{listed}");
    let text = listed["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("t-3549"), "the owner reads back its own row: {text}");
}

/// ALLOWED — the unset identity is the local-operator trust domain (F13):
/// dispatch serves normally.
#[test]
fn mcp_unset_identity_is_served_as_the_local_operator_3549() {
    let (_child, mut stdin, rx) = spawn_mcp(None);
    let listed = send(&mut stdin, &rx, &call(1, "memory_list", serde_json::json!({})));
    assert!(listed["error"].is_null(), "{listed}");
}

/// DENIED — an unusable configured identity is refused BEFORE serving (the
/// #3356 boot gate); the dispatch-level twin for a server that is already up
/// is pinned in-crate by `mcp::authority_dispatch_3549_tests`, which steers
/// the principal through the thread-local seam the boot gate cannot see.
#[test]
fn mcp_unusable_configured_identity_never_serves_3549() {
    let (mut child, _stdin, rx) = spawn_mcp(Some("bad id with spaces"));
    let status = child
        .child
        .wait()
        .expect("child exits");
    assert!(!status.success(), "boot must refuse an unusable identity");
    assert!(rx.recv_timeout(Duration::from_secs(5)).is_err(), "no response line is ever served");
}
