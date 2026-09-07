// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3474 — the admin HTTP enrolment surface for per-agent api-keys.
//!
//! #3418 made the enrolled registry LIVE and gave the CLI a `--store-url`;
//! what it deliberately did NOT ship was the network surface, because a route
//! that MINTS a bearer credential is its own security design. Without it a
//! fleet controller with no shell on the data tier cannot enrol a dynamically
//! minted agent at all, so `advisory` (self-asserted `X-Agent-Id`) stays the
//! only workable posture — exactly what `enforce` exists to refuse.
//!
//! Every control is pinned in BOTH directions — the DENIED path refuses AND
//! the ALLOWED path still works — because a refusal test alone cannot tell a
//! working gate from a broken route:
//!
//! * an admin mint BINDS, and the minted token authenticates the VERY NEXT
//!   request with no daemon restart; a non-admin is refused with the generic
//!   `admin role required` envelope, identical for a real and an absent target
//!   (no enumeration oracle), and nothing is bound;
//! * the raw token never reaches the tracing stream or the signed audit row,
//!   while the key FINGERPRINT does (so the assertion is not vacuous);
//! * the rate limiter admits the budget and refuses the N+1th mint;
//! * revoking ANOTHER principal's key queues a pending action, the requester's
//!   own approval is refused, a DIFFERENT registered approver applies it, and
//!   only THEN does the revoked token stop authenticating;
//! * revoking your OWN key is immediate;
//! * a mint over a transport the daemon has not promised is confidential is
//!   refused, and binds nothing.
//!
//! v1.0.0 #3535 adds the four #3474 advisories to the same discipline:
//!
//! * the TARGET must be a REGISTERED agent — both forms refuse an id the
//!   `_agents` roster does not know, nothing is bound, and registering that
//!   very id makes the identical call succeed;

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::agent_api_key::{
    MIN_SUPPLIED_TOKEN_BYTES, MINT_RATE_LIMIT_PER_WINDOW, RATE_LIMITED, TARGET_NOT_REGISTERED,
    TOKEN_TOO_SHORT, TRANSPORT_REFUSAL, approval_subject, mark_credential_transport_confidential,
};
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::store::MemoryStore;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt as _;

mod common;

const SHARED_KEY: &str = "3474-shared-transport-key";
const HMAC_SECRET: &str = "3474-approval-hmac-secret";
const ALICE: &str = "ai:key-alice";
const MALLORY: &str = "ai:key-mallory";

/// Every test in this binary mutates PROCESS-GLOBAL state (the admin-role
/// authn marker, the credential-transport marker, the forensic sink, the
/// approval HMAC secret), so they run one at a time. Same idiom as
/// `tests/k10_approval_http.rs`, with an ASYNC-aware mutex because the
/// critical section spans `.await` points — a blocking guard held across an
/// await is CONCURRENCY-20 / `clippy::await_holding_lock`.
async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
    LOCK.lock().await
}

/// In-memory `tracing` writer, so the no-log assertion reads what the
/// subscriber actually emitted rather than trusting that nothing was logged.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn scratch(tag: &str) -> TempDir {
    let root = PathBuf::from(".local-runs").join("agent-api-key-3474");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

struct Fixture {
    router: axum::Router,
    store: Arc<dyn MemoryStore>,
    registry: Arc<EnrolledAgentKeys>,
    db_path: PathBuf,
    _dir: TempDir,
}

/// Build a fully wired sqlite daemon router whose `AppState` and
/// `ApiKeyState` share ONE live registry `Arc` — exactly as `bootstrap_serve`
/// wires them, which is what makes "effective on the next request" testable.
fn fixture(tag: &str, admins: &[&str]) -> Fixture {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    mark_credential_transport_confidential(true);
    ai_memory::config::set_active_hooks_hmac_secret(Some(HMAC_SECRET.to_string()));

    let dir = scratch(tag);
    let db_path = dir.path().join("m.db");
    {
        // Register every admin so the approver-eligibility gate (which
        // requires a REGISTERED approver on the HTTP surface) can admit one.
        //
        // v1.0.0 #3535 — ALICE, the canonical TARGET, is registered here for
        // the OTHER half of the same rule: the mint/bind form now refuses a
        // target that is not on the `_agents` roster, so a fixture that left
        // the target unregistered would be testing the refusal, not the
        // control under test. `register_target` adds any further target a
        // single test needs.
        let conn = ai_memory::db::open(&db_path).expect("db::open");
        for a in admins.iter().copied().chain(std::iter::once(ALICE)) {
            ai_memory::db::register_agent(&conn, a, "human", &[]).expect("register agent");
        }
    }
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("SqliteStore"));
    let registry = Arc::new(EnrolledAgentKeys::empty());
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::full()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend: StorageBackend::Sqlite,
        store: Arc::clone(&store),
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
        admin_agent_ids: Arc::new(admins.iter().map(|a| (*a).to_string()).collect()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::clone(&registry),
        http_identity_mode: HttpIdentityMode::Advisory,
    };
    let api_key_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: Arc::clone(&registry),
        identity_mode: HttpIdentityMode::Advisory,
    };
    Fixture {
        router: ai_memory::build_router(api_key_state, app_state),
        store,
        registry,
        db_path,
        _dir: dir,
    }
}

/// v1.0.0 #3535 — put an extra agent on the `_agents` roster.
///
/// The mint/bind form refuses an unregistered target, so a test whose subject
/// is some OTHER control has to register the target it mints for; a test whose
/// subject IS the refusal deliberately does not.
fn register_target(fx: &Fixture, agent_id: &str) {
    let conn = ai_memory::db::open(&fx.db_path).expect("reopen for register");
    ai_memory::db::register_agent(&conn, agent_id, "human", &[]).expect("register target");
}

async fn call(
    router: &axum::Router,
    req: Request<Body>,
) -> (StatusCode, Vec<(String, String)>, Value) {
    let resp = router.clone().oneshot(req).await.expect("route");
    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("body");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, value)
}

fn mint_req(caller: &str, target: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/agents/{target}/api-key"))
        .header(ai_memory::HEADER_API_KEY, SHARED_KEY)
        .header(ai_memory::HEADER_AGENT_ID, caller)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).expect("serialise")))
        .expect("build mint request")
}

fn revoke_req(caller: &str, target: &str, body: &Value) -> Request<Body> {
    let raw = serde_json::to_string(body).expect("serialise");
    let mut b = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/agents/{target}/api-key/revoke"))
        .header(ai_memory::HEADER_API_KEY, SHARED_KEY)
        .header(ai_memory::HEADER_AGENT_ID, caller)
        .header("content-type", "application/json");
    // The approve arm rides the SAME K10 HMAC gate as
    // `POST /api/v1/pending/{id}/approve` — plus the APPROVER inside the
    // signed subject, so this route can never be a weaker second approval
    // funnel and a captured signature cannot be presented by another
    // principal.
    if let Some(pending_id) = body.get("approve_pending_id").and_then(Value::as_str) {
        let ts = chrono::Utc::now().timestamp().to_string();
        let subject = approval_subject(pending_id, caller);
        let sig = common::sign_canonical_envelope(HMAC_SECRET, &ts, "POST", &subject, &raw);
        b = b
            .header(ai_memory::HEADER_AI_MEMORY_SIGNATURE, sig)
            .header(ai_memory::HEADER_AI_MEMORY_TIMESTAMP, ts);
    }
    b.body(Body::from(raw)).expect("build revoke request")
}

/// A request that only needs TRANSPORT authentication — the cheapest honest
/// probe of "does this bearer token still work on the next request".
fn probe_req(token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/api/v1/capabilities")
        .header(ai_memory::HEADER_API_KEY, token)
        .body(Body::empty())
        .expect("build probe request")
}

async fn token_authenticates(router: &axum::Router, token: &str) -> bool {
    let (status, _, _) = call(router, probe_req(token)).await;
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the probe route must not error"
    );
    status != StatusCode::UNAUTHORIZED
}

async fn mint(
    router: &axum::Router,
    caller: &str,
    target: &str,
) -> (StatusCode, Value, Vec<(String, String)>) {
    let (status, headers, body) = call(router, mint_req(caller, target, &json!({}))).await;
    (status, body, headers)
}

// ---------------------------------------------------------------------------
// ALLOWED — a mint binds, and it is live on the next request.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_mint_binds_a_key_that_authenticates_the_very_next_request_3474() {
    const ADMIN: &str = "ai:key-admin-mint";
    let _g = serial().await;
    let fx = fixture("mint", &[ADMIN]);

    // An unenrolled bearer token is refused BEFORE the mint — otherwise the
    // post-mint success below would prove nothing.
    assert!(
        !token_authenticates(&fx.router, "not-a-token-3474").await,
        "an unknown token must not authenticate"
    );

    let (status, body, headers) = mint(&fx.router, ADMIN, ALICE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["agent_id"], ALICE);
    assert_eq!(body["bound"], true);
    let token = body["token"].as_str().expect("minted token").to_string();
    assert!(!token.is_empty());

    // The credential response must never be cached by an intermediary.
    let cache_control = headers
        .iter()
        .find(|(k, _)| k == "cache-control")
        .map(|(_, v)| v.clone())
        .expect("cache-control header");
    assert_eq!(cache_control, "no-store");

    // LIVE on the very next request — no daemon restart, no refresh-window wait.
    assert!(
        token_authenticates(&fx.router, &token).await,
        "the minted token must authenticate immediately"
    );

    // Only the digest reached the store; the raw token is nowhere in it.
    let digest = api_key_sha256_hex(&token);
    assert_eq!(
        fx.store
            .agent_id_for_api_key(&digest)
            .await
            .expect("resolve"),
        Some(ALICE.to_string())
    );
    assert_eq!(fx.registry.len(), 1);
}

/// ALLOWED — the BIND form (operator-supplied token) binds that token's digest
/// and deliberately does NOT echo the secret back.
#[tokio::test]
async fn admin_bind_of_an_operator_supplied_token_never_echoes_it_3474() {
    const ADMIN: &str = "ai:key-admin-bind";
    let _g = serial().await;
    let fx = fixture("bind", &[ADMIN]);

    // At least MIN_SUPPLIED_TOKEN_BYTES: the bind form must not accept a
    // token weaker than the one it would have minted.
    let supplied = "operator-supplied-token-3474-long-enough-to-be-a-credential";
    let (status, _, body) = call(
        &fx.router,
        mint_req(ADMIN, ALICE, &json!({ "token": supplied })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.get("token").is_none(),
        "a token the operator already holds must not be echoed: {body}"
    );
    assert!(
        token_authenticates(&fx.router, supplied).await,
        "the bound token authenticates immediately"
    );
    assert_eq!(
        fx.store
            .agent_id_for_api_key(&api_key_sha256_hex(supplied))
            .await
            .expect("resolve"),
        Some(ALICE.to_string())
    );
}

// ---------------------------------------------------------------------------
// DENIED — non-admin, and no enumeration oracle.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_non_admin_is_refused_identically_for_real_and_absent_targets_3474() {
    const ADMIN: &str = "ai:key-admin-authz";
    let _g = serial().await;
    let fx = fixture("authz", &[ADMIN]);

    // Give the real target a key so the two refusals below differ ONLY in
    // whether the agent exists.
    let (status, body, _) = mint(&fx.router, ADMIN, ALICE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let alice_token = body["token"].as_str().expect("token").to_string();

    let absent = "ai:key-nobody-here";
    for target in [ALICE, absent] {
        for verb in ["mint", "revoke"] {
            let (status, _, body) = if verb == "mint" {
                call(&fx.router, mint_req(MALLORY, target, &json!({}))).await
            } else {
                call(&fx.router, revoke_req(MALLORY, target, &json!({}))).await
            };
            assert_eq!(status, StatusCode::FORBIDDEN, "{verb} {target}: {body}");
            assert_eq!(
                body,
                json!({"error": "admin role required"}),
                "{verb} {target} must not reveal whether the agent exists"
            );
        }
    }

    // Nothing was bound for the absent target, and the real one is untouched.
    assert_eq!(
        fx.store
            .agent_id_for_api_key(&api_key_sha256_hex(&alice_token))
            .await
            .expect("resolve"),
        Some(ALICE.to_string()),
        "a refused call must not have revoked the existing binding"
    );
    assert_eq!(fx.registry.len(), 1);
}

// ---------------------------------------------------------------------------
// No-log token transport.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_minted_token_reaches_neither_the_trace_stream_nor_the_audit_row_3474() {
    const ADMIN: &str = "ai:key-admin-nolog";
    let _g = serial().await;
    let fx = fixture("nolog", &[ADMIN]);
    let audit_dir = scratch("audit");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    let sink = Capture::default();
    let sink_for_writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || sink_for_writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();

    let (status, body, _) = {
        let _default = tracing::subscriber::set_default(subscriber);
        mint(&fx.router, ADMIN, ALICE).await
    };
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().expect("token").to_string();
    let fingerprint = body["key_fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_string();

    let logs = String::from_utf8_lossy(
        &sink
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    )
    .to_string();
    assert!(
        !logs.contains(&token),
        "the raw token leaked into the trace stream"
    );

    ai_memory::governance::audit::shutdown();
    let mut audit_text = String::new();
    for entry in std::fs::read_dir(audit_dir.path()).expect("read audit dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            audit_text.push_str(&std::fs::read_to_string(&path).expect("read forensic file"));
        }
    }
    // Non-vacuous: the audit row for this mint actually landed…
    assert!(
        audit_text.contains(&fingerprint),
        "the audit row must carry the key fingerprint, else this assertion is vacuous"
    );
    assert!(
        audit_text.contains("agent_api_key_mint"),
        "the audit row must name the action"
    );
    // …and it carries the DIGEST PREFIX, never the secret.
    assert!(
        !audit_text.contains(&token),
        "the raw token leaked into the signed audit row"
    );
}

// ---------------------------------------------------------------------------
// Rate limit.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_rate_limiter_admits_the_budget_and_refuses_the_next_mint_3474() {
    // A dedicated caller id: the limiter is process-wide and keyed by the
    // ADMITTED principal, so a shared id would let a sibling test spend this
    // test's budget.
    const ADMIN: &str = "ai:key-admin-ratelimit";
    let _g = serial().await;
    let fx = fixture("ratelimit", &[ADMIN]);

    // #3535 — every burst target is on the roster, INCLUDING the N+1th, so
    // the refusal below can only be the limiter and not the registration gate.
    for i in 0..MINT_RATE_LIMIT_PER_WINDOW {
        register_target(&fx, &format!("ai:key-burst-{i}"));
    }
    register_target(&fx, "ai:key-burst-over");

    for i in 0..MINT_RATE_LIMIT_PER_WINDOW {
        let target = format!("ai:key-burst-{i}");
        let (status, body, _) = mint(&fx.router, ADMIN, &target).await;
        assert_eq!(status, StatusCode::OK, "mint {i} must be admitted: {body}");
    }
    let (status, _, body) =
        call(&fx.router, mint_req(ADMIN, "ai:key-burst-over", &json!({}))).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the N+1th mint must be refused: {body}"
    );
    assert_eq!(body["error"], RATE_LIMITED);
    assert_eq!(body["limit"], MINT_RATE_LIMIT_PER_WINDOW);
    // The refused mint bound nothing.
    assert_eq!(
        fx.registry.len(),
        MINT_RATE_LIMIT_PER_WINDOW as usize,
        "a rate-limited mint must not enrol a key"
    );
}

// ---------------------------------------------------------------------------
// Approval gate.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoking_another_principals_key_needs_a_second_approver_3474() {
    const ADMIN: &str = "ai:key-admin-revoker";
    const APPROVER: &str = "ai:key-admin-approver";
    // A third admin exists only so step 4 can present a signature nobody has
    // spent yet: the K10 replay cache keys on the signature, which now commits
    // to the approver, so re-posting as ADMIN or APPROVER would be refused one
    // layer ABOVE the decided-row check this step is about.
    const WITNESS: &str = "ai:key-admin-witness";
    let _g = serial().await;
    let fx = fixture("approval", &[ADMIN, APPROVER, WITNESS]);

    let (status, body, _) = mint(&fx.router, ADMIN, ALICE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().expect("token").to_string();

    // 1. The revoke is PARKED, not applied.
    let (status, _, body) = call(&fx.router, revoke_req(ADMIN, ALICE, &json!({}))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "pending_approval");
    assert_eq!(body["reason"], "another_principal");
    let pending_id = body["pending_id"].as_str().expect("pending id").to_string();
    assert!(
        token_authenticates(&fx.router, &token).await,
        "a queued revoke must not have taken effect"
    );

    // 2. SELF-APPROVAL by the requester is refused — the two-person rule.
    let (status, _, body) = call(
        &fx.router,
        revoke_req(
            ADMIN,
            ALICE,
            &json!({ "approve_pending_id": pending_id.clone() }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "approval_refused");
    assert!(
        token_authenticates(&fx.router, &token).await,
        "a refused self-approval must not have revoked anything"
    );

    // 3. A DIFFERENT registered approver applies it — and only now does the
    //    credential die, live, with no restart.
    let (status, _, body) = call(
        &fx.router,
        revoke_req(
            APPROVER,
            ALICE,
            &json!({ "approve_pending_id": pending_id.clone() }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked"], true);
    assert_eq!(body["bindings_removed"], 1);
    assert!(
        !token_authenticates(&fx.router, &token).await,
        "the revoked token must stop authenticating immediately"
    );
    assert_eq!(fx.registry.len(), 0);

    // 4. REPLAY — the same approval cannot be spent twice. On the revoke side
    //    a second application is merely idempotent, but the SAME code path
    //    serves mint/bind, where a standing `approved` row that any admin
    //    could re-post would turn ONE authorisation into an unbounded
    //    credential mint. Re-posted as a THIRD admin, whose signed subject
    //    nobody has spent, so this exercises the DECIDED-ROW refusal and not
    //    the K10 signature-replay cache one layer above it.
    let (status, _, body) = call(
        &fx.router,
        revoke_req(WITNESS, ALICE, &json!({ "approve_pending_id": pending_id })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "pending_action_already_decided");
}

/// DENIED — an approval signature names its signer, so a captured one cannot
/// be presented by a DIFFERENT principal. Without the approver in the signed
/// subject the K10 canonical says only WHICH row is being approved, and the
/// `X-Agent-Id` beside it is self-asserted.
#[tokio::test]
async fn an_approval_signature_cannot_be_presented_by_another_principal_3474() {
    const ADMIN: &str = "ai:key-admin-crossreplay";
    const APPROVER: &str = "ai:key-admin-crossreplay-2";
    let _g = serial().await;
    let fx = fixture("crossreplay", &[ADMIN, APPROVER]);

    let (_, body, _) = mint(&fx.router, ADMIN, ALICE).await;
    let token = body["token"].as_str().expect("token").to_string();
    let (_, _, body) = call(&fx.router, revoke_req(ADMIN, ALICE, &json!({}))).await;
    let pending_id = body["pending_id"].as_str().expect("pending id").to_string();

    // Sign as APPROVER, present as ADMIN. The bytes are otherwise identical to
    // the request that WOULD succeed.
    let payload = json!({ "approve_pending_id": pending_id });
    let raw = serde_json::to_string(&payload).expect("serialise");
    let ts = chrono::Utc::now().timestamp().to_string();
    let sig = common::sign_canonical_envelope(
        HMAC_SECRET,
        &ts,
        "POST",
        &approval_subject(&pending_id, APPROVER),
        &raw,
    );
    let stolen = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/agents/{ALICE}/api-key/revoke"))
        .header(ai_memory::HEADER_API_KEY, SHARED_KEY)
        .header(ai_memory::HEADER_AGENT_ID, ADMIN)
        .header("content-type", "application/json")
        .header(ai_memory::HEADER_AI_MEMORY_SIGNATURE, sig)
        .header(ai_memory::HEADER_AI_MEMORY_TIMESTAMP, ts)
        .body(Body::from(raw))
        .expect("build stolen-signature request");
    let (status, _, body) = call(&fx.router, stolen).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(
        token_authenticates(&fx.router, &token).await,
        "a signature presented by the wrong principal must revoke nothing"
    );
}

/// DENIED — the approve arm is not a weaker second approval funnel: it demands
/// the SAME K10 HMAC signature `POST /api/v1/pending/{id}/approve` demands.
#[tokio::test]
async fn an_unsigned_approval_is_refused_by_the_same_hmac_gate_3474() {
    const ADMIN: &str = "ai:key-admin-unsigned";
    const APPROVER: &str = "ai:key-admin-unsigned-2";
    let _g = serial().await;
    let fx = fixture("unsigned", &[ADMIN, APPROVER]);

    let (_, body, _) = mint(&fx.router, ADMIN, ALICE).await;
    let token = body["token"].as_str().expect("token").to_string();
    let (_, _, body) = call(&fx.router, revoke_req(ADMIN, ALICE, &json!({}))).await;
    let pending_id = body["pending_id"].as_str().expect("pending id").to_string();

    // Same request as the successful approval, minus the signature headers.
    let unsigned = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/agents/{ALICE}/api-key/revoke"))
        .header(ai_memory::HEADER_API_KEY, SHARED_KEY)
        .header(ai_memory::HEADER_AGENT_ID, APPROVER)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "approve_pending_id": pending_id }).to_string(),
        ))
        .expect("build unsigned approval");
    let (status, _, body) = call(&fx.router, unsigned).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(
        token_authenticates(&fx.router, &token).await,
        "an unsigned approval must not revoke anything"
    );
}

#[tokio::test]
async fn revoking_your_own_key_is_immediate_3474() {
    const ADMIN: &str = "ai:key-admin-self";
    let _g = serial().await;
    let fx = fixture("self", &[ADMIN]);

    // Enrol the admin's OWN key plus one other, so this revoke cannot be the
    // last enrolled key (which would need a second principal by itself).
    let (_, admin_body, _) = mint(&fx.router, ADMIN, ADMIN).await;
    let admin_token = admin_body["token"].as_str().expect("token").to_string();
    let (_, alice_body, _) = mint(&fx.router, ADMIN, ALICE).await;
    let alice_token = alice_body["token"].as_str().expect("token").to_string();
    assert!(token_authenticates(&fx.router, &admin_token).await);

    let (status, _, body) = call(&fx.router, revoke_req(ADMIN, ADMIN, &json!({}))).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a principal revoking its own compromised key must not have to find a \
         second operator first: {body}"
    );
    assert_eq!(body["revoked"], true);
    assert_eq!(body["effective"], "immediately");
    assert!(
        !token_authenticates(&fx.router, &admin_token).await,
        "the operator's own revoked token must stop working at once"
    );
    assert!(
        token_authenticates(&fx.router, &alice_token).await,
        "revoking one agent must not disturb another's binding"
    );
}

/// DENIED — revoking the LAST enrolled key disarms the identity gate
/// fleet-wide (#1985), so even a self-revoke is parked for a second principal.
#[tokio::test]
async fn revoking_the_last_enrolled_key_is_parked_even_for_yourself_3474() {
    const ADMIN: &str = "ai:key-admin-lastkey";
    let _g = serial().await;
    let fx = fixture("lastkey", &[ADMIN]);

    let (_, body, _) = mint(&fx.router, ADMIN, ADMIN).await;
    let token = body["token"].as_str().expect("token").to_string();
    assert_eq!(fx.registry.len(), 1);

    let (status, _, body) = call(&fx.router, revoke_req(ADMIN, ADMIN, &json!({}))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["reason"], "last_enrolled_key");
    assert!(
        token_authenticates(&fx.router, &token).await,
        "the last key must survive until a second principal approves"
    );
}

// ---------------------------------------------------------------------------
// Confidential transport.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_mint_over_a_non_confidential_transport_is_refused_3474() {
    const ADMIN: &str = "ai:key-admin-transport";
    let _g = serial().await;
    let fx = fixture("transport", &[ADMIN]);

    mark_credential_transport_confidential(false);
    let (status, _, body) = call(&fx.router, mint_req(ADMIN, ALICE, &json!({}))).await;
    // Restore before asserting so a failure cannot poison a sibling test.
    mark_credential_transport_confidential(true);

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], TRANSPORT_REFUSAL);
    assert_eq!(
        fx.registry.len(),
        0,
        "a refused mint must not enrol anything"
    );

    // ALLOWED — the same call succeeds once the posture is confidential, so
    // the refusal above is the control and not a broken route.
    let (status, body, _) = mint(&fx.router, ADMIN, ALICE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// DENIED — a supplied token shorter than the bar is refused, echoing nothing
/// of it, and binds nothing; ALLOWED — one of exactly the minimum length
/// still binds, so the check is a floor and not an outage.
#[tokio::test]
async fn a_supplied_token_below_the_minimum_is_refused_and_binds_nothing_3474() {
    const ADMIN: &str = "ai:key-admin-weak";
    let _g = serial().await;
    let fx = fixture("weak", &[ADMIN]);

    let weak = "a".repeat(MIN_SUPPLIED_TOKEN_BYTES - 1);
    let (status, _, body) = call(
        &fx.router,
        mint_req(ADMIN, ALICE, &json!({ "token": weak })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], TOKEN_TOO_SHORT);
    assert_eq!(body["min_token_bytes"], MIN_SUPPLIED_TOKEN_BYTES);
    assert!(
        !body.to_string().contains(&weak),
        "the refusal echoed the candidate token: {body}"
    );
    assert_eq!(
        fx.registry.len(),
        0,
        "a refused weak token must not enrol anything"
    );
    assert!(
        !token_authenticates(&fx.router, &weak).await,
        "a refused weak token must not authenticate"
    );

    // ALLOWED — exactly at the bar. Without this the refusal above could be a
    // broken route rather than a working floor.
    let ok = "b".repeat(MIN_SUPPLIED_TOKEN_BYTES);
    let (status, _, body) = call(&fx.router, mint_req(ADMIN, ALICE, &json!({ "token": ok }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(token_authenticates(&fx.router, &ok).await);
    assert_eq!(
        fx.store
            .agent_id_for_api_key(&api_key_sha256_hex(&ok))
            .await
            .expect("resolve"),
        Some(ALICE.to_string())
    );
}

/// DENIED — a malformed body is answered with a fixed string that echoes
/// NOTHING, because the body may carry a bearer token.
#[tokio::test]
async fn a_malformed_body_is_refused_without_echoing_it_3474() {
    const ADMIN: &str = "ai:key-admin-body";
    let _g = serial().await;
    let fx = fixture("body", &[ADMIN]);

    let leak = "leak-me-3474";
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/agents/{ALICE}/api-key"))
        .header(ai_memory::HEADER_API_KEY, SHARED_KEY)
        .header(ai_memory::HEADER_AGENT_ID, ADMIN)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            "{{\"token\": \"{leak}\", \"bogus\": 1}}"
        )))
        .expect("build request");
    let (status, _, body) = call(&fx.router, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        !body.to_string().contains(leak),
        "the refusal echoed the request body: {body}"
    );
    assert_eq!(fx.registry.len(), 0);
}

// ---------------------------------------------------------------------------
// #3529 — the last-key rule is enforced ATOMICALLY, not by a pre-check.
// ---------------------------------------------------------------------------

/// Reads the whole forensic chain the process has written so far.
///
/// `shutdown` first, so the assertion reads flushed bytes rather than whatever
/// happened to be on disk when the writer was still buffering.
fn forensic_text(dir: &TempDir) -> String {
    ai_memory::governance::audit::shutdown();
    let mut text = String::new();
    for entry in std::fs::read_dir(dir.path()).expect("read audit dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            text.push_str(&std::fs::read_to_string(&path).expect("read forensic file"));
        }
    }
    text
}

/// The #3474 A1 defect, driven CONCURRENTLY through the real router.
///
/// Before #3529 each request read the enrolled set, saw the OTHER holder's key
/// still there, concluded "I am not the last key", and then revoked in a
/// separate step — so both applied and the registry ended EMPTY, which makes
/// `enforce_for_request` inert in every mode (#1985) with no second approver
/// ever having authorised it.
///
/// The assertion is deterministic under EVERY interleaving, which is what
/// makes it a real proof rather than a timing bet: the count and the delete
/// now happen in one transaction, so whichever request reaches the store
/// second either finds itself holding the only remaining key (and is parked
/// for approval by the pre-check) or is refused by the store's re-check (and
/// is parked by the handler). One `200`, one `202`, exactly one key left —
/// under every schedule.
#[tokio::test]
async fn two_concurrent_self_revokes_by_the_last_two_holders_leave_one_key_3529() {
    const ADMIN_A: &str = "ai:key-admin-race-a";
    const ADMIN_B: &str = "ai:key-admin-race-b";
    let _g = serial().await;
    let fx = fixture("lastkeyrace", &[ADMIN_A, ADMIN_B]);

    // The last TWO key-holders: each holds exactly one key, and it is its own.
    let (status, a_body, _) = mint(&fx.router, ADMIN_A, ADMIN_A).await;
    assert_eq!(status, StatusCode::OK, "{a_body}");
    let a_token = a_body["token"].as_str().expect("token").to_string();
    let (status, b_body, _) = mint(&fx.router, ADMIN_B, ADMIN_B).await;
    assert_eq!(status, StatusCode::OK, "{b_body}");
    let b_token = b_body["token"].as_str().expect("token").to_string();
    assert_eq!(fx.registry.len(), 2);

    // Both self-revokes are in flight at once. Each one's pre-check can
    // legitimately observe the other's key.
    let (left, right) = tokio::join!(
        call(&fx.router, revoke_req(ADMIN_A, ADMIN_A, &json!({}))),
        call(&fx.router, revoke_req(ADMIN_B, ADMIN_B, &json!({}))),
    );
    let (a_status, _, a_out) = left;
    let (b_status, _, b_out) = right;

    let mut statuses = [a_status, b_status];
    statuses.sort_by_key(StatusCode::as_u16);
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::ACCEPTED],
        "exactly one self-revoke may apply and the other must be parked for a \
         second principal: a={a_status} {a_out}, b={b_status} {b_out}"
    );

    // The load-bearing assertion: the registry is NOT empty.
    assert_eq!(
        fx.registry.len(),
        1,
        "two concurrent self-revokes by the last two holders must never empty \
         the enrolled registry (#1985): a={a_out}, b={b_out}"
    );
    let a_live = token_authenticates(&fx.router, &a_token).await;
    let b_live = token_authenticates(&fx.router, &b_token).await;
    assert!(
        a_live ^ b_live,
        "exactly one of the two tokens must still authenticate \
         (a_live={a_live}, b_live={b_live})"
    );

    // The parked one carries the honest reason AND the disclosure that
    // approving it empties the registry.
    let parked = if a_status == StatusCode::ACCEPTED {
        &a_out
    } else {
        &b_out
    };
    assert_eq!(parked["reason"], "last_enrolled_key", "{parked}");
    assert_eq!(parked["empties_registry"], true, "{parked}");
}

/// A queued approval whose target BECAME the last enrolled key is refused at
/// APPLY time, audited, and changes nothing.
///
/// The approver said yes to "revoke that principal's key" while another
/// key-holder still existed. By the time the approval is presented the other
/// holder is gone, so applying it would empty the registry — a materially
/// different act that nobody authorised. It is refused, the registry is
/// untouched, and the refusal is on the signed chain.
#[tokio::test]
async fn an_approved_revoke_that_became_the_last_key_is_refused_at_apply_3529() {
    const ADMIN: &str = "ai:key-admin-applylast";
    const APPROVER: &str = "ai:key-approver-applylast";
    let _g = serial().await;
    let fx = fixture("applylast", &[ADMIN, APPROVER]);
    let audit_dir = scratch("audit-applylast");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    // Two holders: ALICE and the admin itself.
    let (_, alice_body, _) = mint(&fx.router, ADMIN, ALICE).await;
    let alice_token = alice_body["token"].as_str().expect("token").to_string();
    let (_, admin_body, _) = mint(&fx.router, ADMIN, ADMIN).await;
    let admin_token = admin_body["token"].as_str().expect("token").to_string();
    assert_eq!(fx.registry.len(), 2);

    // Park a revoke of ANOTHER principal's key. Two holders exist, so this
    // does NOT empty the registry and the queued row says so.
    let (status, _, queued) = call(&fx.router, revoke_req(ADMIN, ALICE, &json!({}))).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{queued}");
    assert_eq!(queued["reason"], "another_principal");
    assert_eq!(
        queued["empties_registry"], false,
        "another holder is still enrolled: {queued}"
    );
    let pending_id = queued["pending_id"]
        .as_str()
        .expect("pending id")
        .to_string();

    // The state the approval rested on now changes: the admin revokes its own
    // key (immediate — ALICE still holds one), leaving ALICE as the LAST key.
    let (status, _, body) = call(&fx.router, revoke_req(ADMIN, ADMIN, &json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!token_authenticates(&fx.router, &admin_token).await);
    assert_eq!(fx.registry.len(), 1);

    // A DIFFERENT registered approver presents the approval. Refused.
    let (status, _, refused) = call(
        &fx.router,
        revoke_req(
            APPROVER,
            ALICE,
            &json!({ "approve_pending_id": pending_id }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an approval granted while another holder existed must not be the \
         thing that empties the registry: {refused}"
    );
    assert_eq!(refused["error"], "revoke_would_empty_registry", "{refused}");

    // Nothing was revoked.
    assert_eq!(
        fx.registry.len(),
        1,
        "the refused apply must change nothing"
    );
    assert!(
        token_authenticates(&fx.router, &alice_token).await,
        "the last enrolled key must still authenticate after a refused apply"
    );

    // …and the refusal is on the signed chain (non-vacuous: the queue row for
    // the same action is there too, so the file is genuinely being written).
    let audit_text = forensic_text(&audit_dir);
    assert!(
        audit_text.contains("queued_pending_approval"),
        "the queue decision must be audited, else this assertion is vacuous"
    );
    assert!(
        audit_text.contains("apply_refused_last_enrolled_key"),
        "the refused apply must be audited: {audit_text}"
    );
}

// ---------------------------------------------------------------------------
// #3530 — validate the path segment BEFORE the transport refusal is audited.
// ---------------------------------------------------------------------------

/// A malformed `{id}` over a NON-confidential transport is a `400` that writes
/// NO audit row, while a well-formed one over the same transport still writes
/// the transport refusal — so the ordering, not a broken audit sink, is what
/// keeps the unvalidated segment off the signed chain.
#[tokio::test]
async fn a_malformed_agent_id_is_refused_before_any_audit_row_is_written_3530() {
    const ADMIN: &str = "ai:key-admin-a2order";
    let _g = serial().await;
    let fx = fixture("a2order", &[ADMIN]);
    let audit_dir = scratch("audit-a2order");
    ai_memory::governance::audit::init(audit_dir.path(), None).expect("forensic init");

    // Unbounded caller-controlled content: 600 bytes, far past the 128-byte
    // agent-id ceiling. This is exactly the value that used to be JSON-encoded
    // onto an append-only, signed chain before anything had validated it.
    let malformed = "z".repeat(600);
    mark_credential_transport_confidential(false);
    let (status, _, body) = call(&fx.router, mint_req(ADMIN, &malformed, &json!({}))).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a malformed agent_id must be refused on shape alone: {body}"
    );
    assert!(
        !body.to_string().contains(&malformed),
        "the refusal must not echo the raw segment back: {body}"
    );

    // Same transport posture, a WELL-FORMED id: the transport refusal and its
    // audit row are unchanged.
    let (status, _, body) = call(&fx.router, mint_req(ADMIN, ALICE, &json!({}))).await;
    mark_credential_transport_confidential(true);
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], TRANSPORT_REFUSAL);

    let audit_text = forensic_text(&audit_dir);
    // Non-vacuous: the well-formed refusal DID land, with its target.
    assert!(
        audit_text.contains("transport_not_confidential"),
        "the transport refusal must still be audited, else this assertion is \
         vacuous: {audit_text}"
    );
    assert!(
        audit_text.contains(ALICE),
        "the audited refusal must name the (validated) target agent"
    );
    // …and the never-validated segment reached no row at all.
    assert!(
        !audit_text.contains(&malformed),
        "an unvalidated {{id}} must never reach the signed audit chain"
    );
}

/// The transport refusal itself is UNCHANGED by the reordering: a well-formed
/// id over a non-confidential transport is still `403`
/// `credential_transport_not_confidential`, still binds nothing, and the same
/// call still succeeds once the posture is confidential.
#[tokio::test]
async fn a_well_formed_id_over_a_non_confidential_transport_still_refuses_3530() {
    const ADMIN: &str = "ai:key-admin-a2unchanged";
    let _g = serial().await;
    let fx = fixture("a2unchanged", &[ADMIN]);

    mark_credential_transport_confidential(false);
    let (status, _, body) = call(&fx.router, mint_req(ADMIN, ALICE, &json!({}))).await;
    mark_credential_transport_confidential(true);

    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], TRANSPORT_REFUSAL);
    assert_eq!(
        fx.registry.len(),
        0,
        "a transport-refused mint must not enrol anything"
    );

    let (status, body, _) = mint(&fx.router, ADMIN, ALICE).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the refusal above must be the control, not a broken route: {body}"
    );
}

// ---------------------------------------------------------------------------
// v1.0.0 #3535 (#3474 advisory 1) — the TARGET must be a registered agent.
// ---------------------------------------------------------------------------

/// DENIED — neither form of the enrolment route will create a credential for a
/// principal the `_agents` roster does not know, and the SAME call succeeds the
/// moment the target is registered, so the refusal is a gate and not a broken
/// route.
///
/// The defect this pins: a typo'd `{id}` used to mint a LIVE bearer token for
/// an agent that does not exist. `enforce` would then bind an `X-Agent-Id` to
/// that id while `is_registered_agent` — the same predicate the governance
/// `registered` level and every approver-eligibility gate consult — says there
/// is no such agent, which is two identity subsystems disagreeing about who
/// exists.
#[tokio::test]
async fn an_unregistered_target_is_refused_on_both_forms_and_binds_nothing_3535() {
    const ADMIN: &str = "ai:key-admin-unregistered";
    const GHOST: &str = "ai:key-ghost-typo";
    let _g = serial().await;
    let fx = fixture("unregistered", &[ADMIN]);

    let supplied = "operator-supplied-token-3535-long-enough-to-be-a-credential";
    for body in [json!({}), json!({ "token": supplied })] {
        let (status, _, resp) = call(&fx.router, mint_req(ADMIN, GHOST, &body)).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an unregistered target must be refused: {resp}"
        );
        assert_eq!(resp["error"], TARGET_NOT_REGISTERED, "{resp}");
        assert!(
            !resp.to_string().contains(supplied),
            "the refusal must not echo the supplied token: {resp}"
        );
        assert!(
            resp.get("token").is_none(),
            "a refused mint must not return a token: {resp}"
        );
    }

    // Nothing durable and nothing live: no binding for the ghost, and the
    // operator-supplied token does not authenticate.
    assert_eq!(fx.registry.len(), 0, "a refused mint must enrol nothing");
    assert_eq!(
        fx.store
            .agent_id_for_api_key(&api_key_sha256_hex(supplied))
            .await
            .expect("resolve"),
        None
    );
    assert!(!token_authenticates(&fx.router, supplied).await);

    // ALLOWED — register the very same id and the very same call works, in one
    // extra call by the SAME principal.
    register_target(&fx, GHOST);
    let (status, body, _) = mint(&fx.router, ADMIN, GHOST).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "registering the target must make the refused call succeed: {body}"
    );
    let token = body["token"].as_str().expect("minted token").to_string();
    assert!(token_authenticates(&fx.router, &token).await);
    assert_eq!(
        fx.store
            .agent_id_for_api_key(&api_key_sha256_hex(&token))
            .await
            .expect("resolve"),
        Some(GHOST.to_string())
    );
}

/// The refusal is NOT reachable without admin, so it adds no enumeration
/// oracle: an unregistered target and a registered one are still the same
/// generic `403` for a non-admin.
#[tokio::test]
async fn the_unregistered_target_refusal_is_behind_the_admin_gate_3535() {
    const ADMIN: &str = "ai:key-admin-ghostoracle";
    const GHOST: &str = "ai:key-ghost-oracle";
    let _g = serial().await;
    let fx = fixture("ghostoracle", &[ADMIN]);

    for target in [ALICE, GHOST] {
        let (status, _, body) = call(&fx.router, mint_req(MALLORY, target, &json!({}))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{target}: {body}");
        assert_eq!(
            body,
            json!({"error": "admin role required"}),
            "{target} must not reveal whether the agent is registered"
        );
    }
}

/// REVOKE is deliberately NOT gated on registration: refusing a revocation is
/// strictly worse than performing one, and revoking a key bound to an
/// unregistered id is exactly the cleanup an operator needs for a binding that
/// predates this rule.
#[tokio::test]
async fn revoke_is_not_gated_on_target_registration_3535() {
    const ADMIN: &str = "ai:key-admin-revokeghost";
    const GHOST: &str = "ai:key-ghost-legacy";
    let _g = serial().await;
    let fx = fixture("revokeghost", &[ADMIN]);

    // A binding that predates the rule: enrolled directly at the store seam,
    // the way `ai-memory agents bind-api-key` would have.
    let legacy = "legacy-enrolled-token-3535-that-predates-the-registration-rule";
    let digest = api_key_sha256_hex(legacy);
    {
        let conn = ai_memory::db::open(&fx.db_path).expect("reopen");
        assert_eq!(
            ai_memory::db::bind_agent_api_key(&conn, GHOST, &digest).expect("legacy bind"),
            ai_memory::storage::BindApiKeyOutcome::Bound
        );
    }
    // A second holder, so the revoke is not the last enrolled key.
    let (status, body, _) = mint(&fx.router, ADMIN, ADMIN).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _, body) = call(&fx.router, revoke_req(ADMIN, GHOST, &json!({}))).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "revoking ANOTHER principal's key is parked, not refused for being unregistered: {body}"
    );
    assert_ne!(
        body["error"], TARGET_NOT_REGISTERED,
        "revoke must never refuse on registration: {body}"
    );
}
