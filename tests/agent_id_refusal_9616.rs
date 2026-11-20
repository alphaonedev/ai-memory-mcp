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
//! is `400` with an `error` that starts with [`INVALID_AGENT_ID_PREFIX`], and
//! a refused destructive request leaves the memory in place. A route that the
//! postgres route gate does not serve answers its gate status (501) for the
//! valid control AND every invalid form, so no principal is formed there
//! either; that cell is reported as `pg-gate`.
//!
//! The missing header keeps its documented anonymous default
//! (`docs/API_REFERENCE.md`), so it is not an invalid form here.

#![allow(clippy::too_many_lines)]

use ai_memory::config::{FeatureTier, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use serde_json::{Value, json};
#[cfg(feature = "sal-postgres")]
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tower::ServiceExt as _;

mod common;

const ALICE: &str = "ai:alice-9616";
const BOB: &str = "ai:bob-9616";
const API_KEY: &str = "agent-id-refusal-9616";
const NAMESPACE: &str = "ns-9616";
/// The named-400 prefix (`errors::msg::invalid("agent_id", ..)`).
const INVALID_AGENT_ID_PREFIX: &str = "invalid agent_id:";
/// One byte past the 128-byte `validate_agent_id` ceiling.
const OVERSIZE_LEN: usize = 129;
/// Bytes that are a legal header value (obs-text) but not UTF-8.
const NON_UTF8_BYTES: &[u8] = b"ai:\xffmallory-9616";
const BODY_LIMIT: usize = 1024 * 1024;

/// One invalid identity form, as the header values the request carries.
#[derive(Clone, Copy)]
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

/// One census route: method, uri (with `{id}` for the fixture memory) and
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
        "namespace": NAMESPACE,
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

fn link_body(id: &str) -> Value {
    json!({"source_id": id, "target_id": id, "relation": "related_to"})
}

fn namespace_body(id: &str) -> Value {
    json!({"namespace": NAMESPACE, "id": id})
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
        r(
            "DELETE",
            "/api/v1/namespaces?namespace=ns-9616",
            None,
            true,
        ),
        r("POST", "/api/v1/check_duplicate", Some(duplicate_body), false),
        r("GET", "/api/v1/entities/by_alias?alias=refused", None, false),
        r("POST", "/api/v1/links/verify", Some(empty_body), false),
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
    ]
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
        PathBuf::from(":memory:"),
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
            "namespace": NAMESPACE,
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
async fn census(app: AppState, backend: &str) -> (Vec<String>, Vec<String>) {
    let router = router(app);
    let mut id = create_fixture(&router).await;

    let mut table = Vec::new();
    let mut broken = Vec::new();
    for route in census_routes() {
        // The valid control only classifies a postgres-gated route; it is
        // never sent to a destructive route (it would act on the fixture).
        let gated = if backend == "postgres" && !route.destructive {
            let uri = route.uri.replace("{id}", &id);
            let control_body = route.body.map(|b| b(&id));
            let (control, _) = call(&router, route.method, &uri, &alice(), control_body).await;
            control == StatusCode::NOT_IMPLEMENTED
        } else {
            false
        };
        for form in INVALID_FORMS {
            let uri = route.uri.replace("{id}", &id);
            let (status, body) = call(
                &router,
                route.method,
                &uri,
                &form.values(),
                route.body.map(|b| b(&id)),
            )
            .await;
            let error = body["error"].as_str().unwrap_or_default();
            let refused = status == StatusCode::BAD_REQUEST
                && error.starts_with(INVALID_AGENT_ID_PREFIX);
            let gate_held = gated && status == StatusCode::NOT_IMPLEMENTED;
            let cell = if refused {
                "400 named"
            } else if gate_held {
                "pg-gate"
            } else {
                "BROKEN"
            };
            table.push(format!(
                "{backend} | {} {} | {} | {} | {cell}",
                route.method,
                route.uri,
                form.name(),
                status.as_u16()
            ));
            if !(refused || gate_held) {
                broken.push(format!(
                    "{backend} {} {} form={} -> {status} {body}",
                    route.method,
                    route.uri,
                    form.name()
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
    eprintln!("backend | route | form | status | cell");
    for line in table {
        eprintln!("{line}");
    }
    assert!(
        broken.is_empty(),
        "{} census cell(s) broke the #9616 invariant:\n{}",
        broken.len(),
        broken.join("\n")
    );
}

#[tokio::test]
async fn sqlite_invalid_agent_id_is_one_named_400_on_every_route_9616() {
    common::permissive_attestation_for_tests();
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let (table, broken) = census(sqlite_app_state(&dir.path().join("memories.db")), "sqlite").await;
    report(&table, &broken);
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_invalid_agent_id_is_one_named_400_on_every_route_9616() {
    let Some(url) = common::postgres_url() else {
        return;
    };
    common::permissive_attestation_for_tests();
    let (table, broken) = census(postgres_app_state(&url).await, "postgres").await;
    report(&table, &broken);
}

/// The one module allowed to read the `X-Agent-Id` header under
/// `src/handlers`.
const CALLER_IDENTITY_MODULE: &str = "caller_identity.rs";

/// Source forms that re-open the #9616 class, matched on whitespace-free
/// source: a raw header read (non-UTF-8 read as absent, a duplicate read as
/// its first value) and a resolver result folded into a fallback principal.
const FORBIDDEN_FORMS: &[(&str, &str)] = &[
    (".get(crate::HEADER_AGENT_ID)", "raw X-Agent-Id read"),
    (".get(HEADER_AGENT_ID)", "raw X-Agent-Id read"),
    (
        "resolve_http_agent_id(None,header_agent_id).unwrap_or",
        "resolver error folded into a fallback",
    ),
    (
        "resolve_http_agent_id(None,header_agent_id).ok()",
        "resolver error folded into None",
    ),
];

fn handler_sources(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src/handlers") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            handler_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Ratchet: every `X-Agent-Id` read under `src/handlers` goes through
/// `caller_identity`, and no resolver error is folded into a principal. One
/// run lists every offending site.
#[test]
fn handlers_read_the_agent_id_header_only_through_caller_identity_9616() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers");
    let mut files = Vec::new();
    handler_sources(&root, &mut files);
    files.sort();
    assert!(
        files.iter().any(|f| f.ends_with(CALLER_IDENTITY_MODULE)),
        "src/handlers/{CALLER_IDENTITY_MODULE} is the one header reader and must exist"
    );
    let mut offenders = Vec::new();
    for file in &files {
        let name = file.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if name == CALLER_IDENTITY_MODULE || name == "tests.rs" || name.ends_with("_tests.rs") {
            continue;
        }
        let source = std::fs::read_to_string(file).expect("read handler source");
        let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        for (form, why) in FORBIDDEN_FORMS {
            let hits = compact.matches(form).count();
            if hits > 0 {
                offenders.push(format!(
                    "{} : {hits} x {why} ({form})",
                    file.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap_or(file).display()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "{} handler site group(s) bypass caller_identity:\n{}",
        offenders.len(),
        offenders.join("\n")
    );
}
