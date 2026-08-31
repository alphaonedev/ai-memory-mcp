//! #3071 — `POST /api/v1/memories/bulk` must refuse a secret in content with
//! the SAME class single-create uses.
//!
//! Single-create (`POST /api/v1/memories`) runs the caller-origin secret screen
//! (`validate_content` -> `screen_for_caller`) BEFORE the agent-attestation
//! gate, so a row carrying credential material is refused `400` (secret-screen)
//! and never reaches attestation. `bulk_create` used to consult the whole-batch
//! attestation presence gate FIRST, so the SAME secret in an UNSIGNED row (under
//! the required-attestation default) came back `403 ATTESTATION_FAILED` purely
//! because the write arrived in a batch. Both fail closed (nothing persisted),
//! but the refusal CLASS diverged.
//!
//! These two cells pin the fix and its fail-closed backstop:
//!   * `bulk_secret_row_is_400_not_403` — an UNSIGNED row whose content carries
//!     a PEM private key is refused `400 VALIDATION_FAILED` (secret-screen),
//!     NOT `403 ATTESTATION_FAILED`.
//!   * `bulk_clean_unsigned_row_still_403` — an UNSIGNED row with CLEAN content
//!     still fails the attestation gate `403 ATTESTATION_FAILED` (a genuine
//!     attestation failure is unchanged).
//!
//! Both run under required-attestation ON + secret-screen `refuse`, the secure
//! v0.9 HTTP-direct default posture.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::sync::Mutex;
use tower::ServiceExt as _;

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::secret_screen::SecretScreenMode;

/// A structurally-detected PEM private-key block (no entropy gate) — the
/// `screen` PEM detector fires on `-----BEGIN` + `PRIVATE KEY-----`.
const PEM_SECRET: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACD3n0Q0example000000000000000000000000000000000000AAAAA\n\
-----END OPENSSH PRIVATE KEY-----";

/// Pin required-agent-attestation ON (HTTP-direct default) and the secret
/// screen to `refuse`, ONCE for this process. `screen_mode` is a process-wide
/// `OnceLock`, so a single seed governs every test in this binary.
fn strict_posture() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: `Once`-gated process-global env write, one stable value for
        // the process lifetime, set before any gated store is issued.
        unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "1") };
        ai_memory::secret_screen::set_screen_mode(SecretScreenMode::Refuse);
    });
}

fn build_router() -> (axum::Router, NamedTempFile) {
    strict_posture();
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
        replay_cache: std::sync::Arc::new(ai_memory::identity::replay::ReplayCache::default()),
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
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        http_identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let api_key_state = ApiKeyState {
        key: None,
        mtls_enforced: false,
        enrolled_agent_keys: std::sync::Arc::new(std::collections::HashMap::new()),
        identity_mode: ai_memory::config::HttpIdentityMode::default(),
    };
    let router = ai_memory::build_router(api_key_state, app_state);
    (router, f)
}

async fn post_bulk(router: &axum::Router, body: &Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/memories/bulk")
        .header("content-type", "application/json")
        .header("x-agent-id", "bulk-secret-agent")
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

fn row(content: &str) -> Value {
    json!({
        "tier": "long",
        "namespace": "bulk-secret-3071",
        "title": "row",
        "content": content,
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "metadata": {},
        // deliberately UNSIGNED — no `signature` / `created_at`.
    })
}

/// #3071 — an UNSIGNED row whose content carries a secret is refused with the
/// 400 secret-screen class, NOT 403 ATTESTATION_FAILED. Before the fix the
/// whole-batch attestation presence gate fired first and returned 403.
#[tokio::test]
async fn bulk_secret_row_is_400_not_403() {
    let (router, _tmp) = build_router();

    let (status, body) = post_bulk(&router, &json!([row(PEM_SECRET)])).await;

    // The whole-request status is the dominant rejection cause: 400, not 403.
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "#3071: a secret in a bulk row must refuse 400 (secret-screen), not \
         403 ATTESTATION_FAILED; got {status} body={body}"
    );
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "#3071: the secret must not surface the attestation refusal class"
    );

    // Nothing persisted; exactly one row rejected with the validation class.
    assert_eq!(body["created"], json!(0), "fail-closed: nothing persisted");
    assert_eq!(body["rejected"], json!(1), "the one secret row is rejected");
    let code = body["errors"][0]["code"].as_str().unwrap_or_default();
    assert_eq!(
        code, "VALIDATION_FAILED",
        "#3071: the row carries the secret-screen (validation) class, not \
         ATTESTATION_FAILED; body={body}"
    );
    assert_ne!(
        code, "ATTESTATION_FAILED",
        "#3071: the secret must not be classified as an attestation failure"
    );
}

/// #3071 backstop — the fix must NOT weaken attestation: a CLEAN unsigned row
/// under required-attestation still fails the whole-batch attestation gate 403.
#[tokio::test]
async fn bulk_clean_unsigned_row_still_403() {
    let (router, _tmp) = build_router();

    let (status, body) = post_bulk(&router, &json!([row("a perfectly ordinary memory")])).await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "#3071 backstop: a NON-secret unsigned row must still 403; got \
         {status} body={body}"
    );
    assert_eq!(
        body["code"], "ATTESTATION_FAILED",
        "#3071 backstop: a genuine attestation failure keeps its class; \
         body={body}"
    );
}
