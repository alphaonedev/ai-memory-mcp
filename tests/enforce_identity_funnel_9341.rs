// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9341 / #8502 / #8590 — the Enforce identity funnel, behavioural cells.
//!
//! Invariant: under `HttpIdentityMode::Enforce` with at least one per-agent
//! key enrolled, no request reaches a handler with a NAMED principal that is
//! not proven (an enrolled per-agent key bound to that agent, or an mTLS
//! client certificate mapped to that agent, #8357). A shared-key caller that
//! names an agent is refused 403 `attested_identity_required` in ONE place
//! (`authority_layer`), before any extractor or handler runs, on every route
//! of [`route_table::ROUTE_TABLE`] that is not exempt.
//!
//! The backend is SQLite by default; with `--features sal-postgres` and
//! `AI_MEMORY_TEST_POSTGRES_URL` set (the ci-v2-pg wrapper) the same cells run
//! against a `PostgresStore`.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

#[path = "enforce_funnel_9341_common/route_table.rs"]
mod route_table;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::errors::error_codes::VALIDATION_FAILED;
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::{ApiKeyState, AppState, Db};
use ai_memory::mtls_agent_binding::{AgentBindingMode, ClientCertAgentBinding};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use route_table::{AUDIT_UNGATED_ROUTES, ROUTE_TABLE, RouteClass, RouteRow, concrete_path};
use tempfile::NamedTempFile;
use tower::ServiceExt as _;

const SHARED_KEY: &str = "shared-key-9341";
const ALICE_KEY: &str = "alice-per-agent-key-9341";
const BOB_KEY: &str = "bob-per-agent-key-9341";
const ALICE: &str = "alice";
const BOB: &str = "bob";
/// #9366: an enrolled admin that is neither alice nor bob.
const CAROL_KEY: &str = "carol-admin-per-agent-key-9366";
const CAROL: &str = "carol";
/// B-3: a well-formed id no row carries, for the input-echo control.
const B3_DECOY_ID: &str = "00000000-0000-4000-8000-000000009366";
/// The wire code of the one funnel refusal.
const ATTESTED_IDENTITY_REQUIRED: &str = "attested_identity_required";
/// The wire code `api_key_auth` returns for a per-agent key whose agent
/// differs from the claimed header.
const IDENTITY_BINDING_MISMATCH: &str = "identity_binding_mismatch";
/// Per-request ceiling: a handler that blocks is a finding, never a hang.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const BODY_LIMIT: usize = 1 << 20;
/// Ceiling on reading a response body (a stream route never ends).
const BODY_READ_TIMEOUT: Duration = Duration::from_millis(500);

/// Keeps the per-test database file alive for the router's lifetime.
struct Fixture {
    router: axum::Router,
    _db_file: NamedTempFile,
}

fn enrolled(with_keys: bool) -> Arc<EnrolledAgentKeys> {
    let mut map = HashMap::new();
    if with_keys {
        map.insert(api_key_sha256_hex(ALICE_KEY), ALICE.to_string());
        map.insert(api_key_sha256_hex(BOB_KEY), BOB.to_string());
        map.insert(api_key_sha256_hex(CAROL_KEY), CAROL.to_string());
    }
    Arc::new(EnrolledAgentKeys::from_map(map))
}

#[cfg_attr(not(feature = "sal-postgres"), allow(clippy::unused_async))]
async fn store_for(
    db_path: &std::path::Path,
) -> (
    Arc<dyn ai_memory::store::MemoryStore>,
    ai_memory::handlers::StorageBackend,
) {
    #[cfg(feature = "sal-postgres")]
    if let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") {
        let pg = ai_memory::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("connect postgres");
        return (Arc::new(pg), ai_memory::handlers::StorageBackend::Postgres);
    }
    (
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(db_path).expect("sqlite store")),
        ai_memory::handlers::StorageBackend::Sqlite,
    )
}

/// Writes in this binary exercise the identity funnel, not the #8357 body
/// attestation gate: turn the attestation requirement off once per process
/// (the `mtls_agent_binding_8357` precedent).
fn permissive_attestation_for_tests() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: set once, before any router of this binary reads it; no
        // other thread of this test binary writes the environment.
        unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") };
    });
}

/// Build the in-process router: shared key configured, `mode`, and (when
/// `with_keys`) alice and bob each enrolled with a per-agent key.
async fn build(mode: HttpIdentityMode, with_keys: bool) -> Fixture {
    build_with(mode, with_keys, Some(SHARED_KEY)).await
}

/// The fixture with the shared key configured (`Some`) or not (`None`).
async fn build_with(mode: HttpIdentityMode, with_keys: bool, shared_key: Option<&str>) -> Fixture {
    build_with_admin(mode, with_keys, shared_key, ALICE).await
}

/// [`build_with`] with `admin` as the one allowlisted admin id.
async fn build_with_admin(
    mode: HttpIdentityMode,
    with_keys: bool,
    shared_key: Option<&str>,
    admin: &str,
) -> Fixture {
    permissive_attestation_for_tests();
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let f = NamedTempFile::new().expect("tempfile");
    let db_path = f.path().to_path_buf();
    let conn = ai_memory::db::open(&db_path).expect("open db");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let (store, storage_backend) = store_for(&db_path).await;
    let keys = enrolled(with_keys);
    let app_state = AppState {
        db,
        embedder: Arc::new(None),
        vector_index: Arc::new(tokio::sync::Mutex::new(None)),
        federation: Arc::new(None),
        tier_config: Arc::new(FeatureTier::Keyword.config()),
        scoring: Arc::new(ResolvedScoring::default()),
        profile: Arc::new(ai_memory::profile::Profile::core()),
        mcp_config: Arc::new(None),
        active_keypair: Arc::new(None),
        family_embeddings: Arc::new(tokio::sync::RwLock::new(Some(Vec::new()))),
        storage_backend,
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
        admin_agent_ids: Arc::new(vec![admin.to_string()]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: keys.clone(),
        http_identity_mode: mode,
    };
    let api_key_state = ApiKeyState {
        key: shared_key.map(str::to_string),
        mtls_enforced: false,
        enrolled_agent_keys: keys,
        identity_mode: mode,
        ..Default::default()
    };
    Fixture {
        router: ai_memory::build_router(api_key_state, app_state),
        _db_file: f,
    }
}

/// One request's observable outcome.
#[derive(Debug)]
struct Outcome {
    status: StatusCode,
    body: serde_json::Value,
}

impl Outcome {
    fn error_code(&self) -> &str {
        self.body
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
    }
    fn code(&self) -> &str {
        self.body
            .get("code")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
    }
    fn is_funnel_refusal(&self) -> bool {
        self.status == StatusCode::FORBIDDEN && self.error_code() == ATTESTED_IDENTITY_REQUIRED
    }
    /// The postgres route gate's 501 for a route the postgres backend does
    /// not serve. That gate wraps the router outside every auth layer, so no
    /// handler runs and nothing is served: a fail-closed outcome for the
    /// route sweeps, emitted only when the fixture runs on postgres.
    fn is_backend_gate_refusal(&self) -> bool {
        self.status == StatusCode::NOT_IMPLEMENTED
            && self
                .body
                .get("storage_backend")
                .and_then(serde_json::Value::as_str)
                == Some("postgres")
    }
}

async fn send(router: &axum::Router, req: Request<Body>) -> Outcome {
    let fut = router.clone().oneshot(req);
    let Ok(resp) = tokio::time::timeout(REQUEST_TIMEOUT, fut).await else {
        return Outcome {
            status: StatusCode::REQUEST_TIMEOUT,
            body: serde_json::json!({"error": "test-timeout"}),
        };
    };
    let resp = resp.expect("infallible router");
    let status = resp.status();
    // A streaming (SSE) body never ends: bound the read too and keep the
    // status, which is all a streaming route's cell needs.
    let bytes = match tokio::time::timeout(
        BODY_READ_TIMEOUT,
        axum::body::to_bytes(resp.into_body(), BODY_LIMIT),
    )
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(_)) | Err(_) => axum::body::Bytes::new(),
    };
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    Outcome { status, body }
}

/// A request to `method path` with the given key and `X-Agent-Id` values.
fn request(
    method: &str,
    uri: &str,
    key: &str,
    agent_ids: &[&str],
    body: Option<&serde_json::Value>,
) -> axum::http::request::Builder {
    let mut b = Request::builder()
        .method(method.to_ascii_uppercase().as_str())
        .uri(uri);
    if !key.is_empty() {
        b = b.header("x-api-key", key);
    }
    for id in agent_ids {
        b = b.header("x-agent-id", *id);
    }
    if body.is_some() || method != "get" {
        b = b.header("content-type", "application/json");
    }
    b
}

fn body_for(method: &str, body: Option<serde_json::Value>) -> Body {
    match (method, body) {
        (_, Some(v)) => Body::from(v.to_string()),
        ("get", None) => Body::empty(),
        (_, None) => Body::from("{}"),
    }
}

async fn send_simple(
    router: &axum::Router,
    method: &str,
    uri: &str,
    key: &str,
    agent_ids: &[&str],
    body: Option<serde_json::Value>,
) -> Outcome {
    let req = request(method, uri, key, agent_ids, body.as_ref())
        .body(body_for(method, body))
        .expect("request");
    send(router, req).await
}

/// [`concrete_path`] with every `{id}` segment naming `id` (other params
/// keep the placeholder, so a namespace echo is not mistaken for a row read).
fn concrete_path_naming(path: &str, id: &str) -> String {
    concrete_path(path)
        .split('/')
        .zip(path.split('/'))
        .map(|(concrete, raw)| if raw == "{id}" { id } else { concrete })
        .collect::<Vec<_>>()
        .join("/")
}

/// (1a) The table cell: under Enforce with keys enrolled, a shared-key caller
/// naming ANOTHER enrolled agent (bob) is refused 403
/// `attested_identity_required` on every non-exempt route, before any
/// extractor runs (so the refusal does not depend on the body shape).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_key_named_agent_is_refused_on_every_gated_route_9341() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    let mut mismatches = Vec::new();
    let mut audit_open = Vec::new();
    let mut checked = 0usize;
    for row in ROUTE_TABLE {
        if row.class == RouteClass::Exempt {
            continue;
        }
        checked += 1;
        let out = send_simple(
            &fx.router,
            row.method,
            &concrete_path(row.path),
            SHARED_KEY,
            &[BOB],
            None,
        )
        .await;
        if !out.is_funnel_refusal() && !out.is_backend_gate_refusal() {
            if AUDIT_UNGATED_ROUTES.contains(&(row.name, row.method)) {
                audit_open.push(format!("{} {}", row.name, row.method));
            }
            mismatches.push(format!(
                "{} {} {} -> {} {}",
                row.name, row.method, row.path, out.status, out.body
            ));
        }
    }
    eprintln!("#9341 audit routes honoured as bob: {}", audit_open.len());
    for r in &audit_open {
        eprintln!("#9341 AUDIT-OPEN {r}");
    }
    for m in &mismatches {
        eprintln!("#9341 NOT-REFUSED {m}");
    }
    assert!(checked > 0, "the table has gated rows");
    assert!(
        mismatches.is_empty(),
        "#9341: {} of {checked} gated routes did not refuse a shared-key named \
         caller with 403 {ATTESTED_IDENTITY_REQUIRED}",
        mismatches.len()
    );
}

/// (1a') Exempt routes are not refused by the funnel (design point 3).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exempt_routes_are_not_refused_by_the_funnel_9341() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    for row in ROUTE_TABLE.iter().filter(|r| r.class == RouteClass::Exempt) {
        let out = send_simple(
            &fx.router,
            row.method,
            &concrete_path(row.path),
            SHARED_KEY,
            &[BOB],
            None,
        )
        .await;
        assert_ne!(
            out.error_code(),
            ATTESTED_IDENTITY_REQUIRED,
            "{} {} must stay outside the funnel: {} {}",
            row.name,
            row.method,
            out.status,
            out.body
        );
    }
}

/// An EMPTY header stays the documented "no assertion" (the resolver's
/// `filter(|h| !h.is_empty())` precedent), so it is not in this list.
///
/// (1c) The invalid-header cell: a malformed `X-Agent-Id` is a 400
/// `VALIDATION_FAILED` on every non-exempt route, never a silent
/// `anonymous:invalid` principal (#9342).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_header_is_400_on_every_gated_route_9342() {
    const INVALID_IDS: &[&str] = &["bad id with spaces", " bob ", "bob\tx"];
    let fx = build(HttpIdentityMode::Enforce, true).await;
    let mut wrong = Vec::new();
    for row in ROUTE_TABLE.iter().filter(|r| r.class != RouteClass::Exempt) {
        for id in INVALID_IDS {
            let out = send_simple(
                &fx.router,
                row.method,
                &concrete_path(row.path),
                SHARED_KEY,
                &[id],
                None,
            )
            .await;
            let is_400 = out.status == StatusCode::BAD_REQUEST && out.code() == VALIDATION_FAILED;
            if !is_400 && !out.is_backend_gate_refusal() {
                wrong.push(format!(
                    "{} {} {id:?} -> {} {}",
                    row.name, row.method, out.status, out.body
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "#9342 invalid header not 400: {wrong:#?}");
}

/// A header naming an anonymous sentinel is a client ASSERTION, never the
/// server-minted anonymous principal: under the funnel it is an unproven
/// named principal and is refused before any handler (decision line in the
/// READY file).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_supplied_anonymous_sentinel_is_refused_9341() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    let mut wrong = Vec::new();
    for row in ROUTE_TABLE.iter().filter(|r| r.class != RouteClass::Exempt) {
        for id in ["anonymous:req-deadbeef", "anonymous:invalid"] {
            let out = send_simple(
                &fx.router,
                row.method,
                &concrete_path(row.path),
                SHARED_KEY,
                &[id],
                None,
            )
            .await;
            let refused_before_handler = out.is_funnel_refusal()
                || out.is_backend_gate_refusal()
                || (out.status == StatusCode::BAD_REQUEST && out.code() == VALIDATION_FAILED);
            if !refused_before_handler {
                wrong.push(format!(
                    "{} {} {id:?} -> {} {}",
                    row.name, row.method, out.status, out.body
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "#9341 anonymous sentinel header reached a handler: {wrong:#?}"
    );
}

/// A present but non-UTF-8 `X-Agent-Id` is refused 400, never read as
/// "no header" (the anonymous principal).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_utf8_agent_id_header_is_400_9342() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    for (method, path) in [
        ("post", ai_memory::handlers::routes::SIGNALS),
        ("get", ai_memory::handlers::routes::MEMORIES),
    ] {
        let req = request(method, path, SHARED_KEY, &[], None)
            .header(
                "x-agent-id",
                axum::http::HeaderValue::from_bytes(b"b\xffob").expect("opaque header"),
            )
            .body(body_for(method, None))
            .expect("request");
        let out = send(&fx.router, req).await;
        assert_eq!(
            (out.status, out.code()),
            (StatusCode::BAD_REQUEST, VALIDATION_FAILED),
            "{method} {path}: {}",
            out.body
        );
    }
}

/// Positive control: alice's own per-agent key acting as alice is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_agent_key_bound_caller_is_served_9341() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    // A per-run title: a postgres backend keeps rows between runs, and a
    // fixed title would make the re-run a 409 rather than a positive control.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let title = format!("t-9341-{}-{nanos}", std::process::id());
    let out = send_simple(
        &fx.router,
        "post",
        route_table::concrete_path(ai_memory::handlers::routes::MEMORIES).as_str(),
        ALICE_KEY,
        &[ALICE],
        Some(serde_json::json!({"title": title, "content": "c-9341", "namespace": "ns-9341"})),
    )
    .await;
    assert!(
        out.status.is_success(),
        "alice's bound key must create: {} {}",
        out.status,
        out.body
    );
}

/// Anonymous caller (no header) on an anonymous-allowed route is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_caller_on_catalogue_route_is_served_9341() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    for row in ROUTE_TABLE
        .iter()
        .filter(|r| r.class == RouteClass::AnonymousAllowed)
    {
        let out = send_simple(&fx.router, row.method, row.path, SHARED_KEY, &[], None).await;
        assert!(
            !out.is_funnel_refusal(),
            "{} anonymous must not be refused: {} {}",
            row.name,
            out.status,
            out.body
        );
    }
}

/// Advisory mode never refuses (only Enforce does).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advisory_mode_does_not_refuse_named_shared_key_caller_9341() {
    let fx = build(HttpIdentityMode::Advisory, true).await;
    let out = send_simple(
        &fx.router,
        "post",
        ai_memory::handlers::routes::SIGNALS,
        SHARED_KEY,
        &[BOB],
        None,
    )
    .await;
    assert!(!out.is_funnel_refusal(), "{} {}", out.status, out.body);
}

// ---------------------------------------------------------------- break-it

/// Case variants are distinct principals and are refused the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_case_variant_is_refused_9341() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    for id in ["BOB", "Bob", "ALICE"] {
        let out = send_simple(
            &fx.router,
            "post",
            ai_memory::handlers::routes::SIGNALS,
            SHARED_KEY,
            &[id],
            None,
        )
        .await;
        assert!(out.is_funnel_refusal(), "{id}: {} {}", out.status, out.body);
    }
}

/// Duplicate `X-Agent-Id` headers: a shared-key caller is refused whatever
/// the order; a per-agent key whose agent differs from the FIRST value is
/// `identity_binding_mismatch`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_agent_id_headers_are_refused_9341() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    for ids in [[BOB, ALICE], [ALICE, BOB]] {
        let out = send_simple(
            &fx.router,
            "post",
            ai_memory::handlers::routes::SIGNALS,
            SHARED_KEY,
            &ids,
            None,
        )
        .await;
        assert!(
            out.is_funnel_refusal(),
            "{ids:?}: {} {}",
            out.status,
            out.body
        );
    }
    let out = send_simple(
        &fx.router,
        "post",
        ai_memory::handlers::routes::SIGNALS,
        ALICE_KEY,
        &[BOB, ALICE],
        None,
    )
    .await;
    assert_eq!(out.status, StatusCode::FORBIDDEN, "{}", out.body);
    assert_eq!(out.error_code(), IDENTITY_BINDING_MISMATCH, "{}", out.body);
}

/// A per-agent key whose agent differs from the header stays
/// `identity_binding_mismatch` (the transport rung runs first).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_agent_key_for_other_agent_is_binding_mismatch_9341() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    for row in ROUTE_TABLE.iter().filter(|r| r.class != RouteClass::Exempt) {
        let out = send_simple(
            &fx.router,
            row.method,
            &concrete_path(row.path),
            ALICE_KEY,
            &[BOB],
            None,
        )
        .await;
        if out.is_backend_gate_refusal() {
            continue;
        }
        assert_eq!(
            (out.status, out.error_code()),
            (StatusCode::FORBIDDEN, IDENTITY_BINDING_MISMATCH),
            "{} {}: {}",
            row.name,
            row.method,
            out.body
        );
    }
}

/// A body `agent_id` that differs from the proven header principal is
/// refused, never laundered into the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_agent_id_differing_from_header_is_refused_9341() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    let out = send_simple(
        &fx.router,
        "post",
        ai_memory::handlers::routes::MEMORIES,
        ALICE_KEY,
        &[ALICE],
        Some(serde_json::json!({
            "title": "t-9341", "content": "c-9341", "namespace": "ns-9341", "agent_id": BOB
        })),
    )
    .await;
    assert_eq!(
        (out.status, out.code()),
        (StatusCode::FORBIDDEN, "AGENT_ID_MISMATCH"),
        "{}",
        out.body
    );
}

/// #8590: a caller whose mTLS certificate is mapped to bob, presenting the
/// shared key and naming bob, is PROVEN and is served (the cert rung counts
/// at the funnel AND at the handler gate).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mapped_cert_with_shared_key_is_served_8590() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    for (method, path) in [
        ("get", ai_memory::handlers::routes::MEMORIES),
        ("post", ai_memory::handlers::routes::SIGNALS),
    ] {
        let req = request(method, path, SHARED_KEY, &[BOB], None)
            .extension(ClientCertAgentBinding::new(
                Some(BOB.to_string()),
                AgentBindingMode::Enforce,
            ))
            .body(body_for(method, None))
            .expect("request");
        let out = send(&fx.router, req).await;
        assert_ne!(
            out.status,
            StatusCode::FORBIDDEN,
            "#8590 {method} {path}: a cert-proven caller must not be refused: {}",
            out.body
        );
    }
}

/// An unmapped certificate under Warn binding adds no proof: the shared-key
/// named caller is refused by the funnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unmapped_cert_with_shared_key_is_refused_9341() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    let req = request(
        "post",
        ai_memory::handlers::routes::SIGNALS,
        SHARED_KEY,
        &[BOB],
        None,
    )
    .extension(ClientCertAgentBinding::new(None, AgentBindingMode::Warn))
    .body(body_for("post", None))
    .expect("request");
    let out = send(&fx.router, req).await;
    assert!(out.is_funnel_refusal(), "{} {}", out.status, out.body);
}

// ------------------------------------------- 3-agent vote (71472661) cells

/// Per-run unique suffix: a postgres backend keeps rows between runs.
fn run_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{}-{nanos}", std::process::id())
}

/// B-1: one state of the four (per-agent keys enrolled or not, shared key
/// configured or not). A named, unproven caller is refused 403
/// `attested_identity_required` in every one.
async fn assert_named_unproven_refused(with_keys: bool, shared_key: Option<&str>) {
    let fx = build_with(HttpIdentityMode::Enforce, with_keys, shared_key).await;
    let out = send_simple(
        &fx.router,
        "post",
        ai_memory::handlers::routes::SIGNALS,
        shared_key.unwrap_or(""),
        &[BOB],
        None,
    )
    .await;
    assert_eq!(
        out.status,
        StatusCode::FORBIDDEN,
        "B-1 keys={with_keys} shared={}: {}",
        shared_key.is_some(),
        out.body
    );
    assert_eq!(out.error_code(), ATTESTED_IDENTITY_REQUIRED, "{}", out.body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b1_enforce_keys_enrolled_shared_key_refuses_named_9341() {
    assert_named_unproven_refused(true, Some(SHARED_KEY)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b1_enforce_no_keys_shared_key_refuses_named_9341() {
    assert_named_unproven_refused(false, Some(SHARED_KEY)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b1_enforce_keys_enrolled_no_shared_key_refuses_named_9341() {
    assert_named_unproven_refused(true, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b1_enforce_no_keys_no_shared_key_refuses_named_9341() {
    assert_named_unproven_refused(false, None).await;
}

/// B-3: under Enforce the anonymous shared-key caller (no `X-Agent-Id`),
/// swept over EVERY non-exempt route of the router-pinned table, never sees
/// alice's private row and never writes a row attributed to a named agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b3_anonymous_shared_key_reads_no_private_row_writes_nothing_named_9341() {
    let fx = build(HttpIdentityMode::Enforce, true).await;
    let suffix = run_suffix();
    let marker = format!("private-marker-9341-{suffix}");
    let ns = format!("ns-b3-9341-{suffix}");
    let seeded = send_simple(
        &fx.router,
        "post",
        &concrete_path(ai_memory::handlers::routes::MEMORIES),
        ALICE_KEY,
        &[ALICE],
        Some(serde_json::json!({
            "title": marker, "content": marker, "namespace": ns, "scope": "private",
        })),
    )
    .await;
    assert!(
        seeded.status.is_success(),
        "seed: {} {}",
        seeded.status,
        seeded.body
    );
    // The row id, never the marker: a search route echoes its query string,
    // so the marker in a response body is not by itself a read of the row.
    let seeded_id = seeded
        .body
        .get("id")
        .or_else(|| seeded.body.pointer("/memory/id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("seed returns the row id: {}", seeded.body))
        .to_string();

    let gated = || ROUTE_TABLE.iter().filter(|r| r.class != RouteClass::Exempt);
    // Every path parameter names the seeded row, so `/memories/{id}`-shaped
    // routes probe exactly the private row.
    let uri_for = |row: &RouteRow| {
        let mut uri = concrete_path_naming(row.path, &seeded_id);
        if row.method == "get" {
            uri.push_str(&format!("?namespace={ns}&q={marker}&query={marker}"));
        }
        uri
    };
    // The body names the row id under every key a body-addressed route reads,
    // so POST routes that take the id in the body probe the private row too.
    let probe_body_for = |id: &str| {
        serde_json::json!({
            "namespace": ns, "query": marker, "q": marker, "context": marker,
            "id": id, "memory_id": id, "ids": [id],
        })
    };
    let probe_body = probe_body_for(&seeded_id);
    // Positive control, read-only first: the GET sweep as alice DOES return
    // her row, so the probe is sensitive and an empty leak list is evidence.
    let mut owner_reads = 0usize;
    for row in gated().filter(|r| r.method == "get") {
        let out = send_simple(
            &fx.router,
            row.method,
            &uri_for(row),
            ALICE_KEY,
            &[ALICE],
            Some(probe_body.clone()),
        )
        .await;
        owner_reads += usize::from(out.body.to_string().contains(&seeded_id));
    }
    assert!(
        owner_reads > 0,
        "B-3 probe is blind: alice reads her row nowhere"
    );

    let mut leaks = Vec::new();
    let mut backend_gated = Vec::new();
    let mut echoes = Vec::new();
    let mut checked = 0usize;
    for row in gated() {
        checked += 1;
        let out = send_simple(
            &fx.router,
            row.method,
            &uri_for(row),
            SHARED_KEY,
            &[],
            Some(probe_body.clone()),
        )
        .await;
        // Classified, never skipped silently: the postgres route gate serves
        // nothing, so the row is fail-closed on that backend, not probed.
        if out.is_backend_gate_refusal() {
            backend_gated.push(row.name);
            continue;
        }
        let seen = out.body.to_string();
        if seen.contains(&seeded_id) {
            // An input echo is not a read: the same route answers a decoy id
            // of the same shape byte-identically once both ids are masked.
            let decoy = send_simple(
                &fx.router,
                row.method,
                &uri_for(row).replace(&seeded_id, B3_DECOY_ID),
                SHARED_KEY,
                &[],
                Some(probe_body_for(B3_DECOY_ID)),
            )
            .await;
            if seen.replace(&seeded_id, "<ID>")
                == decoy.body.to_string().replace(B3_DECOY_ID, "<ID>")
            {
                echoes.push(row.name);
                continue;
            }
            leaks.push(format!(
                "{} {} -> {} {}",
                row.name,
                row.method,
                out.status,
                out.body.to_string().chars().take(600).collect::<String>()
            ));
        }
    }
    assert!(checked > 0, "the table has gated rows");
    assert!(
        leaks.is_empty(),
        "B-3 private row read anonymously: {leaks:?}"
    );
    if on_postgres() {
        assert!(
            backend_gated.contains(&"MEMORY_RECALL_OBSERVATIONS"),
            "B-3 on postgres: the recall-observations route is classified 501: {backend_gated:?}"
        );
    } else {
        assert!(
            backend_gated.is_empty(),
            "B-3 on sqlite: no route answers the postgres 501: {backend_gated:?}"
        );
    }
    eprintln!("B-3 backend-gated (postgres 501): {backend_gated:?}");
    eprintln!("B-3 input echoes (decoy-identical): {echoes:?}");

    // Nothing the anonymous sweep sent (DELETE/PUT/PATCH included) touched the
    // private row: alice still reads it back unchanged.
    let after = send_simple(
        &fx.router,
        "get",
        &concrete_path_naming(ai_memory::handlers::routes::MEMORIES_ID, &seeded_id),
        ALICE_KEY,
        &[ALICE],
        None,
    )
    .await;
    assert!(
        after.status.is_success() && after.body.to_string().contains(&marker),
        "B-3 anonymous sweep changed alice's private row: {} {}",
        after.status,
        after.body
    );

    // Every row in the namespace, as alice sees it: only her seed is named.
    let listed = send_simple(
        &fx.router,
        "get",
        &format!(
            "{}?namespace={ns}",
            concrete_path(ai_memory::handlers::routes::MEMORIES)
        ),
        ALICE_KEY,
        &[ALICE],
        None,
    )
    .await;
    let rows = listed
        .body
        .get("memories")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let named_foreign: Vec<String> = rows
        .iter()
        .filter(|m| m.get("title").and_then(serde_json::Value::as_str) != Some(marker.as_str()))
        .filter_map(|m| {
            let owner = m
                .pointer("/metadata/agent_id")
                .and_then(serde_json::Value::as_str)?;
            (owner == ALICE || owner == BOB).then(|| owner.to_string())
        })
        .collect();
    assert!(
        named_foreign.is_empty(),
        "B-3 anonymous sweep wrote rows attributed to a named agent: {named_foreign:?}"
    );

    // Blindness census: per route, alice probes a FRESH private row of her
    // own with the same shapes. A route that does not return the id even to
    // its owner cannot show a leak, so it is reported (READY `b3-blind:`).
    let mut blind = Vec::new();
    for (census_idx, row) in gated().enumerate() {
        let fresh = send_simple(
            &fx.router,
            "post",
            &concrete_path(ai_memory::handlers::routes::MEMORIES),
            ALICE_KEY,
            &[ALICE],
            Some(serde_json::json!({
                "title": format!("{marker}-census-{census_idx}-{}-{}", row.name, row.method),
                "content": marker,
                "namespace": ns, "scope": "private",
            })),
        )
        .await;
        let Some(fresh_id) = fresh.body.get("id").and_then(serde_json::Value::as_str) else {
            panic!("census seed: {} {}", fresh.status, fresh.body);
        };
        let mut uri = concrete_path_naming(row.path, fresh_id);
        if row.method == "get" {
            uri.push_str(&format!("?namespace={ns}&q={marker}&query={marker}"));
        }
        let out = send_simple(
            &fx.router,
            row.method,
            &uri,
            ALICE_KEY,
            &[ALICE],
            Some(probe_body_for(fresh_id)),
        )
        .await;
        if !out.body.to_string().contains(fresh_id) {
            blind.push(format!(
                "{} {} {}",
                row.name,
                row.method,
                out.status.as_u16()
            ));
        }
    }
    eprintln!(
        "B-3 blind (owner reads no id here): {} {blind:?}",
        blind.len()
    );
}

/// #9366 direct cell: a recall-observation row is returned only to the
/// principal it belongs to, or to an admin. alice recalls her private row;
/// alice reads exactly her rows, bob and the anonymous shared-key caller read
/// zero of them, the enrolled admin carol reads all of them. On postgres the
/// route is gated 501 for every caller (fail closed, nothing served).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recall_observations_rows_scoped_to_owner_or_admin_9366() {
    let fx = build_with_admin(HttpIdentityMode::Enforce, true, Some(SHARED_KEY), CAROL).await;
    let suffix = run_suffix();
    let marker = format!("obs-marker-9366-{suffix}");
    let ns = format!("ns-obs-9366-{suffix}");
    let seeded = send_simple(
        &fx.router,
        "post",
        &concrete_path(ai_memory::handlers::routes::MEMORIES),
        ALICE_KEY,
        &[ALICE],
        Some(serde_json::json!({
            "title": marker, "content": marker, "namespace": ns, "scope": "private",
        })),
    )
    .await;
    let seeded_id = seeded
        .body
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("seed: {} {}", seeded.status, seeded.body))
        .to_string();
    let recalled = send_simple(
        &fx.router,
        "get",
        &format!(
            "{}?context={marker}&namespace={ns}",
            ai_memory::handlers::routes::RECALL
        ),
        ALICE_KEY,
        &[ALICE],
        None,
    )
    .await;
    assert!(
        recalled.status.is_success(),
        "recall: {} {}",
        recalled.status,
        recalled.body
    );

    // (rows naming alice's seeded memory, rows owned by alice, total rows)
    let read_as = |key: &'static str, ids: &'static [&'static str]| {
        let router = fx.router.clone();
        let seeded_id = seeded_id.clone();
        async move {
            let out = send_simple(
                &router,
                "post",
                ai_memory::handlers::routes::MEMORY_RECALL_OBSERVATIONS,
                key,
                ids,
                Some(serde_json::json!({})),
            )
            .await;
            if on_postgres() {
                assert!(
                    out.is_backend_gate_refusal(),
                    "pg: {} {}",
                    out.status,
                    out.body
                );
                return None;
            }
            assert_eq!(out.status, StatusCode::OK, "{key}: {}", out.body);
            let rows = out.body["observations"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let of = |f: &str, v: &str| rows.iter().filter(|r| r[f].as_str() == Some(v)).count();
            Some((
                of("memory_id", &seeded_id),
                of("agent_id", ALICE),
                rows.len(),
            ))
        }
    };
    let alice = read_as(ALICE_KEY, &[ALICE]).await;
    let bob = read_as(BOB_KEY, &[BOB]).await;
    let anonymous = read_as(SHARED_KEY, &[]).await;
    let admin = read_as(CAROL_KEY, &[CAROL]).await;
    let Some(alice) = alice else { return };
    assert_eq!(
        alice,
        (1, 1, 1),
        "alice reads exactly her one observation row"
    );
    assert_eq!(bob, Some((0, 0, 0)), "bob reads none of alice's rows");
    assert_eq!(
        anonymous,
        Some((0, 0, 0)),
        "the anonymous caller reads no row"
    );
    assert_eq!(admin, Some((1, 1, 1)), "the admin reads every row");
}

/// `true` when this binary's store is postgres (the [`store_for`] predicate).
fn on_postgres() -> bool {
    cfg!(feature = "sal-postgres") && std::env::var("AI_MEMORY_TEST_POSTGRES_URL").is_ok()
}

/// B-8: Advisory with the shared key and a named id is served (reported,
/// not refused) and the report counter rises.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b8_advisory_named_shared_key_is_counted_not_refused_9341() {
    let fx = build(HttpIdentityMode::Advisory, true).await;
    let before = ai_memory::handlers::advisory_identity_report::advisory_unproven_total();
    let claimed = format!("bob-b8-{}", run_suffix());
    let out = send_simple(
        &fx.router,
        "post",
        ai_memory::handlers::routes::SIGNALS,
        SHARED_KEY,
        &[claimed.as_str()],
        None,
    )
    .await;
    assert!(!out.is_funnel_refusal(), "{} {}", out.status, out.body);
    let after = ai_memory::handlers::advisory_identity_report::advisory_unproven_total();
    assert!(after > before, "B-8 counter must rise: {before} -> {after}");
    // Deterministic under parallel cells (the counter is process-wide): the
    // layer recorded exactly this (key, claimed id) pair, so it is not due.
    assert!(
        ai_memory::handlers::advisory_identity_report::observe_unproven_claim(SHARED_KEY, &claimed)
            .is_none(),
        "B-8: the authority layer did not report the Advisory claim"
    );
}

/// B-8 break-it: control bytes, newline, ANSI escape and quotes come out
/// escaped; a 100K id is cut to the constant within a time ceiling.
#[test]
fn b8_claimed_id_is_escaped_and_bounded_9341() {
    use ai_memory::handlers::advisory_identity_report::{
        CLAIMED_ID_LOG_MAX_CHARS, claimed_id_for_log,
    };
    const HUGE_ID_LEN: usize = 100_000;
    const ESCAPE_CEILING: Duration = Duration::from_millis(50);
    for hostile in [
        "a\u{0}b",
        "a\nINFO forged",
        "a\u{1b}[31mred",
        "a\"b\\c",
        "a\tb\r",
    ] {
        let shown = claimed_id_for_log(hostile);
        assert!(
            shown.bytes().all(|b| (0x20..0x7f).contains(&b)),
            "{hostile:?} -> {shown:?}"
        );
        assert!(
            !shown.contains('\n') && !shown.contains('\u{1b}'),
            "{shown:?}"
        );
    }
    let huge = "x".repeat(HUGE_ID_LEN);
    let t = std::time::Instant::now();
    let shown = claimed_id_for_log(&huge);
    assert!(t.elapsed() < ESCAPE_CEILING, "{:?}", t.elapsed());
    assert!(
        shown.len() <= CLAIMED_ID_LOG_MAX_CHARS * 4 + 16,
        "{}",
        shown.len()
    );
    assert!(shown.ends_with("...(cut)"), "{shown}");
}

/// B-8 dedup: the WARN is due once per (key, claimed id); the counter counts
/// every call; the set never grows past its cap.
#[test]
fn b8_dedup_per_key_and_claimed_id_is_bounded_9341() {
    use ai_memory::handlers::advisory_identity_report::{
        ADVISORY_UNPROVEN_DEDUP_CAP, advisory_unproven_total, observe_unproven_claim,
    };
    let suffix = run_suffix();
    let claimed = format!("dedup-{suffix}");
    let before = advisory_unproven_total();
    assert!(observe_unproven_claim("k1", &claimed).is_some());
    assert!(
        observe_unproven_claim("k1", &claimed).is_none(),
        "same pair twice"
    );
    assert!(
        observe_unproven_claim("k2", &claimed).is_some(),
        "other key is a new pair"
    );
    assert!(advisory_unproven_total() >= before + 3);
    // Cycle more ids than the cap: once full, nothing new is due.
    let due = (0..=ADVISORY_UNPROVEN_DEDUP_CAP * 2)
        .filter(|i| observe_unproven_claim("k-cycle", &format!("c-{suffix}-{i}")).is_some())
        .count();
    assert!(
        due <= ADVISORY_UNPROVEN_DEDUP_CAP,
        "dedup set must be bounded: {due}"
    );
}
