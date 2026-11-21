// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9616 — an invalid `X-Agent-Id` header is refused with ONE named 400 on
//! BOTH backends on every route, and no fallback ever turns it into a
//! principal.
//!
//! Pre-#9616 the HTTP handlers resolved the caller with
//! `resolve_http_agent_id(..).unwrap_or_else(|_| <fallback>)` at 26 sites,
//! and the postgres `DELETE /api/v1/memories/{id}` arm folded the error into
//! the NAMED principal `ai:http` (sqlite refused with 400). Every header read
//! also used `to_str().ok()`, so a header that is not valid UTF-8 was treated
//! as ABSENT and the request was served as an anonymous caller, and a request
//! carrying two `X-Agent-Id` headers was served as whichever came first.
//!
//! The invariant pinned here, for every route in the census and every
//! invalid form in [`INVALID_FORMS`], on sqlite and on postgres: the answer
//! is `400` with EXACTLY the body [`expected_body`] gives for the layer that
//! refuses it, and a refused destructive request leaves the memory in place.
//! Two legs run per backend:
//!
//! * the full router: every route under the authority layer answers that
//!   layer's envelope (`{"code":"VALIDATION_FAILED","error":..}`), and
//!   `GET /api/v1/sync/since`, which the layer exempts, answers the handler's
//!   `CallerRefusal` (`{"error":..}`);
//! * a router with NO authority layer, the same handlers on the same paths:
//!   every route answers the handler's `CallerRefusal`, so the handler's own
//!   refusal is pinned and not hidden behind the layer.
//!
//! A route that the postgres route gate does not serve answers its gate
//! status (501) for the valid control AND every invalid form, so no principal
//! is formed there either; that cell is reported as `pg-gate`.
//!
//! The missing header keeps its documented anonymous default
//! (`docs/API_REFERENCE.md`), so it is not an invalid form here.

#![allow(clippy::too_many_lines)]

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

mod common;

const ALICE: &str = "ai:alice-9616";
const BOB: &str = "ai:bob-9616";
const API_KEY: &str = "agent-id-refusal-9616";
/// Prefix of the per-run namespace. A postgres lane database outlives one
/// run, so each run writes under its own namespace and a fixture title from an
/// earlier run never collides (409) with this one.
const NAMESPACE_PREFIX: &str = "ns-9616-";

fn namespace() -> &'static str {
    static RUN_NAMESPACE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    RUN_NAMESPACE.get_or_init(|| format!("{NAMESPACE_PREFIX}{}", uuid::Uuid::new_v4().simple()))
}
/// The authority layer's error code (`errors::error_codes::VALIDATION_FAILED`).
const VALIDATION_FAILED: &str = "VALIDATION_FAILED";
/// The one route the authority layer exempts that resolves a caller: its
/// handler's `CallerRefusal` is the only defence there.
const SYNC_SINCE: &str = "/api/v1/sync/since";
/// One byte past the 128-byte `validate_agent_id` ceiling.
const OVERSIZE_LEN: usize = 129;
/// Bytes that are a legal header value (obs-text) but not UTF-8.
const NON_UTF8_BYTES: &[u8] = b"ai:\xffmallory-9616";
const BODY_LIMIT: usize = 1024 * 1024;

/// One invalid identity form, as the header values the request carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    BadShape,
    Reserved,
    Oversize,
    NonUtf8,
    Duplicate,
}

const INVALID_FORMS: &[Form] = &[
    Form::BadShape,
    Form::Reserved,
    Form::Oversize,
    Form::NonUtf8,
    Form::Duplicate,
];

impl Form {
    fn name(self) -> &'static str {
        match self {
            Self::BadShape => "bad-shape",
            Self::Reserved => "reserved",
            Self::Oversize => "oversize",
            Self::NonUtf8 => "non-utf8",
            Self::Duplicate => "duplicate",
        }
    }

    fn values(self) -> Vec<HeaderValue> {
        match self {
            Self::BadShape => vec![HeaderValue::from_static("bad id 9616")],
            Self::Reserved => vec![HeaderValue::from_static("daemon")],
            Self::Oversize => vec![HeaderValue::from_str(&"a".repeat(OVERSIZE_LEN)).unwrap()],
            Self::NonUtf8 => vec![HeaderValue::from_bytes(NON_UTF8_BYTES).unwrap()],
            Self::Duplicate => vec![
                HeaderValue::from_static(ALICE),
                HeaderValue::from_static(BOB),
            ],
        }
    }
}

/// The exact `error` text each invalid form is refused with, written out by
/// hand (never computed from the code under test). The same text is the
/// handler's `CallerRefusal` message and the authority layer's `error`.
const EXPECTED_ERROR: [(Form, &str); 5] = [
    (
        Form::BadShape,
        "invalid agent_id: agent_id contains invalid character ' ' (allowed: alphanumeric, _-:@./)",
    ),
    (
        Form::Reserved,
        "invalid agent_id: agent_id 'daemon' is reserved for internal use and cannot be supplied \
         by wire callers",
    ),
    (
        Form::Oversize,
        "invalid agent_id: agent_id exceeds max length of 128 bytes",
    ),
    (
        Form::NonUtf8,
        "invalid agent_id: X-Agent-Id header is not valid UTF-8",
    ),
    (
        Form::Duplicate,
        "invalid agent_id: more than one X-Agent-Id header",
    ),
];

/// The layer a census cell pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layer {
    /// `handlers::authority::authority_layer`: `{"code","error"}`.
    Authority,
    /// The handler's own `CallerRefusal`: `{"error"}` only.
    Handler,
    /// `handlers::create::resolve_create_caller`: the create and bulk wire
    /// contract maps the `CallerRefusal` into its `{"code","error"}` field
    /// error, so the body equals the authority layer's.
    CreateFunnel,
    /// The v2 approval-signature check that pending approve / reject run
    /// before caller resolution; it fails closed with a `401` on a header
    /// that is one valid-UTF-8 value, whatever its shape.
    ApprovalSignature,
    /// A build without `sal`: `verify_link_handler` is a stub that answers
    /// `501` before it reads any input.
    SalStub,
}

impl Layer {
    fn name(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::Handler => "handler",
            Self::CreateFunnel => "create-funnel",
            Self::ApprovalSignature => "approval-signature",
            Self::SalStub => "sal-stub",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::Authority | Self::Handler | Self::CreateFunnel => StatusCode::BAD_REQUEST,
            Self::ApprovalSignature => StatusCode::UNAUTHORIZED,
            Self::SalStub => StatusCode::NOT_IMPLEMENTED,
        }
    }
}

/// The non-`sal` `verify_link_handler` stub body, hand-written.
const SAL_STUB_ERROR: &str = "verify_link requires --features sal";

/// The approval-signature refusal, hand-written.
const APPROVAL_SIGNATURE_ERROR: &str = "invalid or missing X-AI-Memory-Signature";
const APPROVAL_SIGNATURE_HINT: &str = r#"approval decides require signature layout v2: X-AI-Memory-Signature: sha256=<HMAC-SHA256(SHA256(secret), "<ts>.<METHOD>.<n>:<pending_id>@<m>:<X-Agent-Id>.<body>")> (<n>, <m> = the decimal byte lengths of the two ids) with X-AI-Memory-Timestamp: <unix-epoch-secs>. The approver named by X-Agent-Id is inside the signed subject; a v1 signature over <ts>.<METHOD>.<pending_id>.<body> does not bind the approver and is refused."#;
const APPROVAL_SIGNATURE_LAYOUT: u64 = 2;

fn expected_error(form: Form) -> &'static str {
    EXPECTED_ERROR
        .iter()
        .find(|(f, _)| *f == form)
        .map(|(_, text)| *text)
        .expect("every form has a hand-written row")
}

/// The whole body a refused request must answer at `layer`.
fn expected_body(form: Form, layer: Layer) -> Value {
    match layer {
        Layer::Authority | Layer::CreateFunnel => {
            json!({"code": VALIDATION_FAILED, "error": expected_error(form)})
        }
        Layer::Handler => json!({"error": expected_error(form)}),
        Layer::ApprovalSignature => json!({
            "error": APPROVAL_SIGNATURE_ERROR,
            "hint": APPROVAL_SIGNATURE_HINT,
            "signature_layout_version": APPROVAL_SIGNATURE_LAYOUT,
        }),
        Layer::SalStub => json!({"error": SAL_STUB_ERROR}),
    }
}

/// The layer that refuses `form` on a route when the request reaches the
/// production handler directly (no authority layer in front of it).
fn handler_layer(method: &str, uri: &str, form: Form) -> Layer {
    let approval = method == "POST"
        && (uri == "/api/v1/pending/{id}/approve" || uri == "/api/v1/pending/{id}/reject");
    let verify_stub =
        cfg!(not(feature = "sal")) && method == "POST" && uri == "/api/v1/links/verify";
    match form {
        _ if verify_stub => Layer::SalStub,
        Form::BadShape | Form::Reserved | Form::Oversize if approval => Layer::ApprovalSignature,
        _ if method == "POST" && uri == "/api/v1/memories" => Layer::CreateFunnel,
        _ => Layer::Handler,
    }
}

/// One census route: method, uri (with `{id}` for the fixture memory and
/// `{ns}` for the per-run fixture namespace) and
/// an optional JSON body.
struct Route {
    method: &'static str,
    uri: &'static str,
    body: Option<fn(&str) -> Value>,
    /// `true` when a refusal must leave the fixture memory in place.
    destructive: bool,
}

fn create_body(_: &str) -> Value {
    json!({
        "namespace": namespace(),
        "title": "refused create 9616",
        "content": "must never be written",
        "tier": "long",
        "tags": [],
        "priority": 5,
        "confidence": 1.0,
        "source": "api",
        "metadata": {}
    })
}

/// A well-formed id that names no memory: the link target, so the body is
/// not refused as a self-link before the caller is resolved.
const ABSENT_TARGET_ID: &str = "00000000-0000-4000-8000-000000009616";

fn link_body(id: &str) -> Value {
    json!({"source_id": id, "target_id": ABSENT_TARGET_ID, "relation": "related_to"})
}

fn namespace_body(id: &str) -> Value {
    json!({"namespace": namespace(), "id": id})
}

fn duplicate_body(_: &str) -> Value {
    json!({"title": "t", "content": "c"})
}

fn empty_body(_: &str) -> Value {
    json!({})
}

fn ids_body(id: &str) -> Value {
    json!({"ids": [id]})
}

fn agent_body(_: &str) -> Value {
    json!({"agent_id": "ai:registered-9616", "agent_type": "ai:claude"})
}

fn share_body(id: &str) -> Value {
    json!({"source_memory_id": id, "target_agent_id": BOB})
}

fn id_body(id: &str) -> Value {
    json!({"id": id})
}

fn census_routes() -> Vec<Route> {
    let r = |method, uri, body, destructive| Route {
        method,
        uri,
        body,
        destructive,
    };
    vec![
        r("GET", "/api/v1/memories/{id}", None, false),
        r("DELETE", "/api/v1/memories/{id}", None, true),
        r("GET", "/api/v1/memories", None, false),
        r("POST", "/api/v1/memories", Some(create_body), false),
        r("GET", "/api/v1/search?q=refused", None, false),
        r("GET", "/api/v1/contradictions?topic=refused", None, false),
        r("DELETE", "/api/v1/links", Some(link_body), true),
        r("GET", "/api/v1/links/{id}", None, false),
        r("GET", "/api/v1/memories/{id}/lineage", None, false),
        r("POST", "/api/v1/namespaces", Some(namespace_body), false),
        r("DELETE", "/api/v1/namespaces?namespace={ns}", None, true),
        r(
            "POST",
            "/api/v1/check_duplicate",
            Some(duplicate_body),
            false,
        ),
        r(
            "GET",
            "/api/v1/entities/by_alias?alias=refused",
            None,
            false,
        ),
        r("POST", "/api/v1/links/verify", Some(link_body), false),
        r("POST", "/api/v1/archive", Some(ids_body), true),
        r("DELETE", "/api/v1/archive", None, true),
        r("POST", "/api/v1/archive/{id}/restore", None, false),
        r("POST", "/api/v1/agents", Some(agent_body), false),
        r("GET", "/api/v1/pending", None, false),
        r("POST", "/api/v1/pending/{id}/approve", None, false),
        r("POST", "/api/v1/pending/{id}/reject", None, false),
        r("POST", "/api/v1/share", Some(share_body), false),
        r(
            "POST",
            ai_memory::handlers::routes::MEMORY_REFLECTION_ORIGIN,
            Some(id_body),
            false,
        ),
        r(
            "POST",
            ai_memory::handlers::routes::MEMORY_DEPENDENTS_OF_INVALIDATED,
            Some(id_body),
            false,
        ),
        r(
            "POST",
            ai_memory::handlers::routes::MEMORY_VERIFY,
            Some(id_body),
            false,
        ),
        r(
            "POST",
            ai_memory::handlers::routes::MEMORY_SMART_LOAD,
            Some(empty_body),
            false,
        ),
        r("GET", SYNC_SINCE, None, false),
    ]
}

/// The layer that refuses an invalid form on `uri` in the FULL router.
fn full_router_layer(uri: &str) -> Layer {
    if uri == SYNC_SINCE {
        Layer::Handler
    } else {
        Layer::Authority
    }
}

/// The census routes registered on their production handlers with NO
/// authority layer, no transport auth and no postgres gate: a request reaches
/// the handler with the header exactly as sent.
fn handler_router(app: AppState) -> axum::Router {
    use ai_memory::handlers as h;
    use axum::routing::{delete, get, post};
    axum::Router::new()
        .route(
            "/api/v1/memories/{id}",
            get(h::get_memory).delete(h::delete_memory),
        )
        .route(
            "/api/v1/memories",
            get(h::list_memories).post(h::create_memory),
        )
        .route("/api/v1/search", get(h::search_memories))
        .route("/api/v1/contradictions", get(h::detect_contradictions))
        .route("/api/v1/links", delete(h::delete_link))
        .route("/api/v1/links/{id}", get(h::get_links))
        .route("/api/v1/memories/{id}/lineage", get(h::get_lineage))
        .route(
            "/api/v1/namespaces",
            post(h::set_namespace_standard_qs).delete(h::clear_namespace_standard_qs),
        )
        .route("/api/v1/check_duplicate", post(h::check_duplicate))
        .route("/api/v1/entities/by_alias", get(h::entity_get_by_alias))
        .route("/api/v1/links/verify", post(h::verify_link_handler))
        .route(
            "/api/v1/archive",
            post(h::archive_by_ids).delete(h::purge_archive),
        )
        .route("/api/v1/archive/{id}/restore", post(h::restore_archive))
        .route("/api/v1/agents", post(h::register_agent))
        .route("/api/v1/pending", get(h::list_pending))
        .route("/api/v1/pending/{id}/approve", post(h::approve_pending))
        .route("/api/v1/pending/{id}/reject", post(h::reject_pending))
        .route("/api/v1/share", post(h::share_memory))
        .route(
            h::routes::MEMORY_REFLECTION_ORIGIN,
            post(h::route_1111::handle_reflection_origin_http),
        )
        .route(
            h::routes::MEMORY_DEPENDENTS_OF_INVALIDATED,
            post(h::route_1111::handle_dependents_of_invalidated_http),
        )
        .route(
            h::routes::MEMORY_VERIFY,
            post(h::route_1111::handle_verify_http),
        )
        .route(
            h::routes::MEMORY_SMART_LOAD,
            post(h::route_1111::handle_smart_load_http),
        )
        .route(SYNC_SINCE, get(h::sync_since))
        .with_state(app)
}

/// Which router a census leg drives.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Leg {
    Full,
    HandlerOnly,
}

#[cfg_attr(
    not(feature = "sal"),
    expect(
        clippy::needless_pass_by_value,
        reason = "`SalStore` is a ZST without `sal`, but under `sal` its inner \
                  `Arc<dyn MemoryStore>` is MOVED into the struct literal below; \
                  one signature keeps both feature legs building identically."
    )
)]
fn app_state_with(db: Db, backend: StorageBackend, store: SalStore) -> AppState {
    let _ = &store;
    AppState {
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
        storage_backend: backend,
        #[cfg(feature = "sal")]
        store: store.0,
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
    }
}

#[cfg(feature = "sal")]
struct SalStore(Arc<dyn ai_memory::store::MemoryStore>);
#[cfg(not(feature = "sal"))]
struct SalStore(());

fn sqlite_app_state(path: &std::path::Path) -> AppState {
    let conn = ai_memory::db::open(path).expect("open sqlite fixture db");
    let db: Db = Arc::new(Mutex::new((
        conn,
        path.to_path_buf(),
        ResolvedTtl::default(),
        true,
    )));
    #[cfg(feature = "sal")]
    let store = SalStore(Arc::new(
        ai_memory::store::sqlite::SqliteStore::open(path.to_path_buf()).expect("open SqliteStore"),
    ));
    #[cfg(not(feature = "sal"))]
    let store = SalStore(());
    app_state_with(db, StorageBackend::Sqlite, store)
}

#[cfg(feature = "sal-postgres")]
async fn postgres_app_state(url: &str) -> AppState {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
    let db: Db = Arc::new(Mutex::new((
        conn,
        std::path::PathBuf::from(":memory:"),
        ResolvedTtl::default(),
        true,
    )));
    let store = SalStore(Arc::new(
        ai_memory::store::postgres::PostgresStore::connect(url)
            .await
            .expect("connect postgres adapter"),
    ));
    app_state_with(db, StorageBackend::Postgres, store)
}

fn router(app: AppState) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    ai_memory::build_router(
        ApiKeyState {
            key: Some(API_KEY.into()),
            mtls_enforced: false,
            enrolled_agent_keys: Arc::new(
                ai_memory::handlers::identity_binding::EnrolledAgentKeys::empty(),
            ),
            identity_mode: ai_memory::config::HttpIdentityMode::default(),
            ..Default::default()
        },
        app,
    )
}

async fn call(
    router: &axum::Router,
    method: &str,
    uri: &str,
    agent_ids: &[HeaderValue],
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-api-key", API_KEY);
    for value in agent_ids {
        req = req.header("x-agent-id", value.clone());
    }
    let req = if let Some(b) = body {
        req.header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        req.header("content-length", "0")
            .body(Body::empty())
            .unwrap()
    };
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), BODY_LIMIT)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn alice() -> Vec<HeaderValue> {
    vec![HeaderValue::from_static(ALICE)]
}

/// Create the memory every cell targets, owned by ALICE.
async fn create_fixture(router: &axum::Router) -> String {
    let (status, created) = call(
        router,
        "POST",
        "/api/v1/memories",
        &alice(),
        Some(json!({
            "namespace": namespace(),
            "title": "fixture 9616",
            "content": "alice owns this row",
            "tier": "long",
            "tags": [],
            "priority": 5,
            "confidence": 1.0,
            "source": "api",
            "metadata": {}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    created["id"].as_str().expect("created id").to_string()
}

/// Run the census on one backend. Returns the per-cell table and the list of
/// cells that broke the invariant; the caller asserts the list is empty so
/// one run reports EVERY broken cell, not only the first. A destructive cell
/// that removed the fixture is reported and the fixture is recreated, so one
/// removal never cascades into the cells after it.
async fn census(app: AppState, backend: &str, leg: Leg) -> (Vec<String>, Vec<String>) {
    let router = match leg {
        Leg::Full => router(app),
        Leg::HandlerOnly => handler_router(app),
    };
    let mut id = create_fixture(&router).await;

    let mut table = Vec::new();
    let mut broken = Vec::new();
    for route in census_routes() {
        // The valid control only classifies a postgres-gated route (the gate
        // is in the full router only); it is never sent to a destructive
        // route (it would act on the fixture).
        let gated = if backend == "postgres" && leg == Leg::Full && !route.destructive {
            let uri = route.uri.replace("{id}", &id).replace("{ns}", namespace());
            let control_body = route.body.map(|b| b(&id));
            let (control, _) = call(&router, route.method, &uri, &alice(), control_body).await;
            control == StatusCode::NOT_IMPLEMENTED
        } else {
            false
        };
        for form in INVALID_FORMS {
            let layer = match leg {
                Leg::Full => full_router_layer(route.uri),
                Leg::HandlerOnly => handler_layer(route.method, route.uri, *form),
            };
            let uri = route.uri.replace("{id}", &id).replace("{ns}", namespace());
            let (status, body) = call(
                &router,
                route.method,
                &uri,
                &form.values(),
                route.body.map(|b| b(&id)),
            )
            .await;
            let expected = (layer.status(), expected_body(*form, layer));
            let refused = (status, &body) == (expected.0, &expected.1);
            let gate_held = gated && status == StatusCode::NOT_IMPLEMENTED;
            let cell = if refused {
                "exact"
            } else if gate_held {
                "pg-gate"
            } else {
                "BROKEN"
            };
            table.push(format!(
                "{backend} | {} | {} {} | {} | {} | {cell}",
                layer.name(),
                route.method,
                route.uri,
                form.name(),
                status.as_u16()
            ));
            if !(refused || gate_held) {
                broken.push(format!(
                    "{backend} layer={} {} {} form={} -> {status} {body}; expected {} {}",
                    layer.name(),
                    route.method,
                    route.uri,
                    form.name(),
                    expected.0,
                    expected.1
                ));
            }
            if route.destructive {
                let (still, row) = call(
                    &router,
                    "GET",
                    &format!("/api/v1/memories/{id}"),
                    &alice(),
                    None,
                )
                .await;
                if still != StatusCode::OK {
                    broken.push(format!(
                        "{backend} {} {} form={} removed the fixture: {still} {row}",
                        route.method,
                        route.uri,
                        form.name()
                    ));
                    id = create_fixture(&router).await;
                }
            }
        }
    }
    (table, broken)
}

fn report(table: &[String], broken: &[String]) {
    eprintln!("backend | layer | route | form | status | cell");
    for line in table {
        eprintln!("{line}");
    }
    assert_eq!(
        broken,
        Vec::<String>::new(),
        "{} census cell(s) broke the #9616 invariant",
        broken.len()
    );
}

/// Every census row on one backend: the cell count is the route count times
/// the form count, so a row that silently dropped out is a red.
fn assert_full_table(table: &[String]) {
    assert_eq!(table.len(), census_routes().len() * INVALID_FORMS.len());
}

/// `GET /api/v1/sync/since` checks the per-message federation signature
/// BEFORE it reads `X-Agent-Id` (default on, `AI_MEMORY_FED_REQUIRE_SIG`).
/// The census sends no signature, so this binary runs with the check off to
/// let the request reach the caller resolution the cell pins. Set once, for
/// the life of this test process (its own binary), before any request.
fn unsigned_sync_since_for_tests() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // SAFETY: `Once`-gated process-global env write before the calling
        // test issues any request; never mutated again in this process.
        unsafe {
            std::env::set_var(ai_memory::federation::signing::REQUIRE_SIG_ENV, "0");
        }
    });
}

async fn sqlite_census(leg: Leg) {
    common::permissive_attestation_for_tests();
    unsigned_sync_since_for_tests();
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let (table, broken) = census(
        sqlite_app_state(&dir.path().join("memories.db")),
        "sqlite",
        leg,
    )
    .await;
    report(&table, &broken);
    assert_full_table(&table);
}

#[cfg(feature = "sal-postgres")]
async fn postgres_census(leg: Leg) {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    unsigned_sync_since_for_tests();
    let (table, broken) = census(postgres_app_state(&url).await, "postgres", leg).await;
    report(&table, &broken);
    assert_full_table(&table);
}

#[tokio::test]
async fn sqlite_invalid_agent_id_is_one_named_400_on_every_route_9616() {
    sqlite_census(Leg::Full).await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_invalid_agent_id_is_one_named_400_on_every_route_9616() {
    postgres_census(Leg::Full).await;
}

/// The handler's own refusal, with no authority layer in front of it.
#[tokio::test]
async fn sqlite_handler_refuses_every_form_without_the_authority_layer_9616() {
    sqlite_census(Leg::HandlerOnly).await;
}

/// The handler's own refusal, with no authority layer in front of it.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_handler_refuses_every_form_without_the_authority_layer_9616() {
    postgres_census(Leg::HandlerOnly).await;
}

/// The reflect body refusal a request past the caller step meets, written by
/// hand.
const REFLECT_BODY_ERROR: &str = "title is required";

/// `POST /api/v1/memory_reflect` reads header presence before it picks a
/// backend branch: every invalid form is the handler's exact refusal there
/// too, with no authority layer in front of it, and a request with no header
/// is not refused at that step.
#[tokio::test]
async fn sqlite_reflect_presence_refuses_every_form_9616() {
    use ai_memory::handlers::routes::MEMORY_REFLECT;
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let app = sqlite_app_state(&dir.path().join("reflect.db"));
    let router = axum::Router::new()
        .route(
            MEMORY_REFLECT,
            axum::routing::post(ai_memory::handlers::route_1111::handle_reflect_http),
        )
        .with_state(app);
    let body = json!({"source_ids": [ABSENT_TARGET_ID]});
    for form in INVALID_FORMS {
        assert_eq!(
            call(
                &router,
                "POST",
                MEMORY_REFLECT,
                &form.values(),
                Some(body.clone())
            )
            .await,
            (
                StatusCode::BAD_REQUEST,
                expected_body(*form, Layer::Handler)
            ),
            "reflect form={}",
            form.name()
        );
    }
    // Past the caller step: the body (no title) is what the handler refuses.
    assert_eq!(
        call(&router, "POST", MEMORY_REFLECT, &[], Some(body)).await,
        (
            StatusCode::BAD_REQUEST,
            json!({"error": REFLECT_BODY_ERROR})
        ),
        "reflect with no header"
    );
}

/// Documented prefix of the per-request anonymous principal a request with
/// NO `X-Agent-Id` header receives (`docs/API_REFERENCE.md`).
const ANONYMOUS_REQUEST_PREFIX: &str = "anonymous:req-";
/// Hex length of the per-request suffix after the prefix.
const ANONYMOUS_SUFFIX_LEN: usize = 8;

/// The WARN `identity::resolve_http_agent_id` emits on its one missing-header
/// arm; the pin asserts it names the principal it assigned.
const ANONYMOUS_WARN: &str = "without agent_id body field or X-Agent-Id header; assigned ";

/// In-memory tracing sink for the missing-header WARN pin.
#[derive(Clone, Default)]
struct WarnSink(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for WarnSink {
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

/// The split is deliberate: a MISSING header is not refused, it keeps the
/// documented anonymous default, and two missing-header requests never share
/// one principal. Pinned per backend so a later change to the missing arm of
/// `caller_identity` is a visible, tested decision.
async fn assert_missing_header_stays_anonymous(app: AppState, backend: &str) {
    let router = router(app);
    let sink = WarnSink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    let _capture = tracing::subscriber::set_default(subscriber);
    let mut principals = Vec::new();
    for n in 0..2 {
        let (status, created) = call(
            &router,
            "POST",
            "/api/v1/memories",
            &[],
            Some(json!({
                "namespace": namespace(),
                "title": format!("anonymous 9616 {n}"),
                "content": "no agent header",
                "tier": "long",
                "tags": [],
                "priority": 5,
                "confidence": 1.0,
                "source": "api",
                "metadata": {}
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{backend}: {created}");
        // sqlite answers a write receipt (`agent_id` at the top level),
        // postgres the stored memory (`metadata.agent_id`).
        let agent = created["agent_id"]
            .as_str()
            .or_else(|| created["metadata"]["agent_id"].as_str())
            .unwrap_or_default()
            .to_string();
        let suffix = agent
            .strip_prefix(ANONYMOUS_REQUEST_PREFIX)
            .unwrap_or_else(|| panic!("{backend}: missing header gave {agent:?}, not anonymous"));
        assert_eq!(suffix.len(), ANONYMOUS_SUFFIX_LEN, "{backend}: {agent:?}");
        assert!(
            suffix.bytes().all(|b| b.is_ascii_hexdigit()),
            "{backend}: {agent:?}"
        );
        principals.push(agent);
    }
    assert_ne!(
        principals[0], principals[1],
        "{backend}: two anonymous requests shared one principal"
    );
    let logs = String::from_utf8_lossy(
        &sink
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    )
    .into_owned();
    for agent in &principals {
        assert!(
            logs.contains(&format!("{ANONYMOUS_WARN}{agent}")),
            "{backend}: no missing-header WARN naming {agent}:\n{logs}"
        );
    }
}

#[tokio::test]
async fn sqlite_missing_agent_id_stays_anonymous_9616() {
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    assert_missing_header_stays_anonymous(
        sqlite_app_state(&dir.path().join("memories.db")),
        "sqlite",
    )
    .await;
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_missing_agent_id_stays_anonymous_9616() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    assert_missing_header_stays_anonymous(postgres_app_state(&url).await, "postgres").await;
}

#[path = "agent_id_refusal_9616/ratchet.rs"]
mod ratchet;

#[path = "agent_id_refusal_9616/bind_request_9666.rs"]
mod bind_request_9666;
