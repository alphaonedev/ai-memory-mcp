// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8947 (v1.0.0, HIGH) and #2135 — HTTP `POST /api/v1/session/start` must
//! resolve the agent whose `scope=private` rows it may return from the
//! principal the identity gate admitted, never from a body field the gate did
//! not prove.
//!
//! Defect class: a handler behind the identity gate resolves its visibility
//! caller from request-controlled data (here the body `agent_id`) instead of the
//! gated principal. Pre-fix, `enforce_idor_identity` read only the
//! `X-Agent-Id` header, so a shared-transport-key caller that sent NO header
//! and a body `agent_id` naming another agent got that agent's private rows.
//!
//! Invariant pinned here: for HTTP `session_start` under `enforce`, no body
//! `agent_id` spelling can widen the result past the gated principal. A named
//! body principal is held to the same proof as a named header principal.
//!
//! The harness is the Enforce router of
//! `tests/http_per_agent_key_route_gate_2044.rs` (real `build_router`, the
//! `api_key_auth` + authority layers on, per-agent keys enrolled), with the
//! per-binary seeding style of `tests/session_start_scope_private_1420.rs` and
//! the Postgres router of `tests/cov_ga2_pg_handlers_2.rs`.
//!
//! Cells (SQLite always; PostgreSQL when `AI_MEMORY_TEST_POSTGRES_URL` is set,
//! same assertions on an isolated scratch database):
//!   * `a8947_*`   — the body leg, a table over id spellings;
//!   * `positive_*` — the owner still gets its own rows, shared rows stay visible;
//!   * `h2135_*`   — the header leg;
//!   * `m8947_*`   — mode coverage and own-id pins: the full (key kind x
//!     `X-Agent-Id` x body `agent_id`) table in the shipped default mode, which
//!     the fix must leave byte-for-byte as the base answers it, and the
//!     own-claimed-id rows under Enforce;
//!   * `default_mode_is_the_shipped_default_8947` — names the default mode;
//!   * `e8947_*`   — round 1 (security review H1): an EMPTY / whitespace /
//!     absent `X-Agent-Id` with a body that names no usable principal (`{}`,
//!     `{"agent_id":null}`, the key-case twin `{"Agent_Id":"<B>"}`), per key
//!     kind, under Enforce and the default mode. The caller must be the
//!     principal the gate resolved (`anonymous:req-<uuid>` for these headers),
//!     never the raw header string. The SSOT layer of the same hole (an empty
//!     caller matching rows with no target) is pinned separately in
//!     `tests/visibility_blank_caller_9356.rs`.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::collections::HashMap;
use std::sync::Arc;

use ai_memory::config::{FeatureTier, HttpIdentityMode, ResolvedScoring, ResolvedTtl};
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::{ApiKeyState, AppState, Db, StorageBackend};
use ai_memory::models::Memory;
use ai_memory::store::MemoryStore;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

const SESSION_START_PATH: &str = "/api/v1/session/start";
const AGENT_A: &str = "agent-a-8947";
const AGENT_B: &str = "agent-b-8947";
const AGENT_B_UPPER: &str = "AGENT-B-8947";
const KEY_A: &str = "key-a-8947-per-agent";
const KEY_B: &str = "key-b-8947-per-agent";
const SHARED_KEY: &str = "shared-transport-key-8947";
const NAMESPACE: &str = "ns-8947-session";
const MARKER_A_PRIVATE: &str = "marker-8947-a-private-content";
const MARKER_B_PRIVATE: &str = "marker-8947-b-private-content";
const MARKER_SHARED: &str = "marker-8947-shared-content";
const ERR_ATTESTED_REQUIRED: &str = "attested_identity_required";
const ERR_BINDING_MISMATCH: &str = "identity_binding_mismatch";
const ERR_BODY_HEADER_MISMATCH: &str = "agent_id body parameter does not match X-Agent-Id header";
const SESSION_LIMIT: u64 = 50;
const BODY_LIMIT_BYTES: usize = 512 * 1024;
/// A third owner: every seeded row has NO `target_agent_id`, the shape an empty
/// caller matched through `target == caller` (`"" == ""`).
const AGENT_C: &str = "agent-c-8947";
const MARKER_C_PRIVATE: &str = "marker-8947-c-private-content";
/// Private markers no caller in the `e8947` tables may see except its own.
const ALL_PRIVATE: [&str; 3] = [MARKER_A_PRIVATE, MARKER_B_PRIVATE, MARKER_C_PRIVATE];
/// `X-Agent-Id` values that name no principal.
const HDR_EMPTY: &str = "";
const HDR_SPACE: &str = " ";
const HDR_TAB: &str = "\t";
const BLANK_HEADERS: [Option<&str>; 4] = [Some(HDR_EMPTY), Some(HDR_SPACE), Some(HDR_TAB), None];
/// Raw JSON bodies that carry no usable `agent_id` (serde reads `agent_id`
/// only, so the key-case twin is ignored).
const BODY_EMPTY: &str = "{}";
const BODY_NULL_AGENT: &str = r#"{"agent_id":null}"#;
const BODY_KEYCASE_B: &str = r#"{"Agent_Id":"agent-b-8947"}"#;
const BLANK_BODIES: [&str; 3] = [BODY_EMPTY, BODY_NULL_AGENT, BODY_KEYCASE_B];

fn memory(owner: &str, title: &str, marker: &str, shared: bool) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = json!({ "agent_id": owner });
    if shared && let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "scope".to_string(),
            json!(ai_memory::models::namespace::MemoryScope::Collective.as_str()),
        );
    }
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: NAMESPACE.to_string(),
        title: title.to_string(),
        content: marker.to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test-8947".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        version: 1,
        ..Memory::default()
    }
}

fn seed_rows() -> [Memory; 4] {
    [
        memory(AGENT_A, "a-private-8947", MARKER_A_PRIVATE, false),
        memory(AGENT_B, "b-private-8947", MARKER_B_PRIVATE, false),
        memory(AGENT_C, "c-private-8947", MARKER_C_PRIVATE, false),
        memory(AGENT_B, "shared-8947", MARKER_SHARED, true),
    ]
}

/// Enforce router with per-agent keys for A and B plus a shared transport key.
/// The same router in an explicit identity mode (both `AppState` and
/// `ApiKeyState` carry it, as the daemon wires them).
fn build_router_in_mode(
    db: Db,
    store: Arc<dyn MemoryStore>,
    backend: StorageBackend,
    mode: HttpIdentityMode,
) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let mut enrolled = HashMap::new();
    enrolled.insert(api_key_sha256_hex(KEY_A), AGENT_A.to_string());
    enrolled.insert(api_key_sha256_hex(KEY_B), AGENT_B.to_string());
    let enrolled = Arc::new(EnrolledAgentKeys::from_map(enrolled));
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
        storage_backend: backend,
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
        admin_agent_ids: Arc::new(Vec::new()),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: enrolled.clone(),
        http_identity_mode: mode,
    };
    let api_key_state = ApiKeyState {
        key: Some(SHARED_KEY.to_string()),
        mtls_enforced: false,
        enrolled_agent_keys: enrolled,
        identity_mode: mode,
        ..Default::default()
    };
    ai_memory::build_router(api_key_state, app_state)
}

fn sqlite_router(dir: &tempfile::TempDir) -> axum::Router {
    sqlite_router_in_mode(dir, HttpIdentityMode::Enforce)
}

fn sqlite_router_in_mode(dir: &tempfile::TempDir, mode: HttpIdentityMode) -> axum::Router {
    let db_path = dir.path().join("session-start-8947.db");
    let conn = ai_memory::db::open(&db_path).expect("db::open");
    for m in seed_rows() {
        ai_memory::db::insert(&conn, &m).expect("db::insert");
    }
    let conn = ai_memory::db::open(&db_path).expect("reopen for AppState");
    let db: Db = Arc::new(tokio::sync::Mutex::new((
        conn,
        db_path.clone(),
        ResolvedTtl::default(),
        true,
    )));
    let store: Arc<dyn MemoryStore> =
        Arc::new(ai_memory::store::sqlite::SqliteStore::open(&db_path).expect("open SqliteStore"));
    build_router_in_mode(db, store, StorageBackend::Sqlite, mode)
}

/// One `session_start` call. `key` is the `x-api-key` value, `x_agent` the
/// `X-Agent-Id` header, `body_agent` the JSON body `agent_id`.
async fn call(
    router: &axum::Router,
    key: &str,
    x_agent: Option<&str>,
    body_agent: Option<&str>,
) -> (StatusCode, Value, String) {
    let mut body = json!({ "namespace": NAMESPACE, "limit": SESSION_LIMIT });
    if let Some(b) = body_agent {
        body["agent_id"] = json!(b);
    }
    let mut req = Request::builder()
        .method("POST")
        .uri(SESSION_START_PATH)
        .header("content-type", "application/json")
        .header("x-api-key", key);
    if let Some(h) = x_agent {
        req = req.header("x-agent-id", h);
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), BODY_LIMIT_BYTES)
        .await
        .unwrap();
    let raw = String::from_utf8_lossy(&bytes).into_owned();
    let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed, raw)
}

fn assert_no_b_private(raw: &str, ctx: &str) {
    assert!(
        !raw.contains(MARKER_B_PRIVATE),
        "{ctx}: response leaked B's private content: {raw}"
    );
}

// ---------------------------------------------------------------------------
// Cell bodies (backend-agnostic)
// ---------------------------------------------------------------------------

/// Shared-key caller with NO header and a body naming another agent: the gate
/// must refuse it exactly like the header form. The table covers the id
/// spellings the handler accepts (exact, case variant, the caller's own id)
/// and the ones its validator refuses (surrounding whitespace).
async fn cell_a8947_body_leg_shared_key(router: &axum::Router) {
    // (body agent_id, expected status, expected error code or text fragment)
    let table: [(&str, StatusCode, &str); 5] = [
        (AGENT_B, StatusCode::FORBIDDEN, ERR_ATTESTED_REQUIRED),
        (AGENT_B_UPPER, StatusCode::FORBIDDEN, ERR_ATTESTED_REQUIRED),
        (AGENT_A, StatusCode::FORBIDDEN, ERR_ATTESTED_REQUIRED),
        (" agent-b-8947", StatusCode::BAD_REQUEST, "agent_id"),
        ("agent-b-8947 ", StatusCode::BAD_REQUEST, "agent_id"),
    ];
    for (spelling, want_status, want_err) in table {
        let (status, parsed, raw) = call(router, SHARED_KEY, None, Some(spelling)).await;
        assert_no_b_private(&raw, &format!("a8947 shared-key body={spelling:?}"));
        assert_eq!(
            status, want_status,
            "a8947 shared-key body={spelling:?}: status; body={raw}"
        );
        let err = parsed["error"].as_str().unwrap_or_default();
        assert!(
            err.contains(want_err),
            "a8947 shared-key body={spelling:?}: want error containing {want_err:?}, got {raw}"
        );
    }
}

/// A's own per-agent key with a body naming B: the key binds the header to A,
/// the body disagrees, so the request is refused with the handler family's
/// body/header mismatch (400) before any row is read.
async fn cell_a8947_body_leg_per_agent_key(router: &axum::Router) {
    for spelling in [AGENT_B, AGENT_B_UPPER] {
        let (status, parsed, raw) = call(router, KEY_A, None, Some(spelling)).await;
        assert_no_b_private(&raw, &format!("a8947 key-a body={spelling:?}"));
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a8947 key-a body={spelling:?}: status; body={raw}"
        );
        assert_eq!(
            parsed["error"].as_str(),
            Some(ERR_BODY_HEADER_MISMATCH),
            "a8947 key-a body={spelling:?}: error; body={raw}"
        );
    }
}

/// The owner keeps its own rows and shared rows stay visible, with the body
/// `agent_id` equal to the principal and with the field absent.
async fn cell_positive(router: &axum::Router) {
    for body_agent in [Some(AGENT_A), None] {
        let (status, _parsed, raw) = call(router, KEY_A, None, body_agent).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "positive A body={body_agent:?}: {raw}"
        );
        assert!(
            raw.contains(MARKER_A_PRIVATE),
            "positive A body={body_agent:?}: A must see its own private row: {raw}"
        );
        assert!(
            raw.contains(MARKER_SHARED),
            "positive A body={body_agent:?}: shared row stays visible: {raw}"
        );
        assert_no_b_private(&raw, &format!("positive A body={body_agent:?}"));
    }
    let (status, _parsed, raw) = call(router, KEY_B, None, Some(AGENT_B)).await;
    assert_eq!(status, StatusCode::OK, "positive B: {raw}");
    assert!(
        raw.contains(MARKER_B_PRIVATE),
        "positive B sees own row: {raw}"
    );
    assert!(
        !raw.contains(MARKER_A_PRIVATE),
        "positive B must not see A's private row: {raw}"
    );
}

/// The header leg (#2135): A's key with `X-Agent-Id: B` is refused by
/// `api_key_auth`; a shared-key caller naming B is refused by the handler gate.
async fn cell_h2135_header_leg(router: &axum::Router) {
    let (status, parsed, raw) = call(router, KEY_A, Some(AGENT_B), None).await;
    assert_no_b_private(&raw, "h2135 key-a header=B");
    assert_eq!(status, StatusCode::FORBIDDEN, "h2135 key-a header=B: {raw}");
    assert_eq!(
        parsed["error"].as_str(),
        Some(ERR_BINDING_MISMATCH),
        "h2135 key-a header=B: {raw}"
    );
}

async fn cell_h2135_header_leg_shared_key(router: &axum::Router) {
    for body_agent in [None, Some(AGENT_B)] {
        let (status, parsed, raw) = call(router, SHARED_KEY, Some(AGENT_B), body_agent).await;
        assert_no_b_private(&raw, &format!("h2135 shared header=B body={body_agent:?}"));
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "h2135 shared header=B body={body_agent:?}: {raw}"
        );
        assert_eq!(
            parsed["error"].as_str(),
            Some(ERR_ATTESTED_REQUIRED),
            "h2135 shared header=B body={body_agent:?}: {raw}"
        );
    }
}

/// One request of a (mode x key kind x header x body) table with its expected
/// answer: exact status, exact error code or text (`None` = no error field), and
/// whether the rows of A and B appear in the response.
struct Row {
    key: &'static str,
    header: Option<&'static str>,
    body: Option<&'static str>,
    status: StatusCode,
    err: Option<&'static str>,
    sees_a: bool,
    sees_b: bool,
}

const fn row(
    key: &'static str,
    header: Option<&'static str>,
    body: Option<&'static str>,
    status: StatusCode,
    err: Option<&'static str>,
    sees_a: bool,
    sees_b: bool,
) -> Row {
    Row {
        key,
        header,
        body,
        status,
        err,
        sees_a,
        sees_b,
    }
}

const NONE: Option<&str> = None;
const HDR_A: Option<&str> = Some(AGENT_A);
const HDR_B: Option<&str> = Some(AGENT_B);

/// Run every row of `rows` against `router`; `label` names the table in
/// failures. Every row is checked and every mismatch is reported together, so a
/// failing run names each differing row, not only the first.
async fn run_rows(router: &axum::Router, label: &str, rows: &[Row]) {
    let mut mismatches: Vec<String> = Vec::new();
    for r in rows {
        let ctx = format!(
            "{label} key={} header={:?} body={:?}",
            r.key, r.header, r.body
        );
        let (status, parsed, raw) = call(router, r.key, r.header, r.body).await;
        let err = parsed["error"].as_str();
        let err_ok = match r.err {
            Some(want) => err.unwrap_or_default().contains(want),
            None => parsed["error"].is_null(),
        };
        let sees_a = raw.contains(MARKER_A_PRIVATE);
        let sees_b = raw.contains(MARKER_B_PRIVATE);
        // A caller whose key proves A (or that is refused) never sees B.
        let b_leak = sees_b && (r.key == KEY_A || status != StatusCode::OK);
        if status != r.status || !err_ok || sees_a != r.sees_a || sees_b != r.sees_b || b_leak {
            mismatches.push(format!(
                "{ctx}: want status={} err={:?} a={} b={}; got status={} err={err:?} a={sees_a} b={sees_b}",
                r.status.as_u16(),
                r.err,
                r.sees_a,
                r.sees_b,
                status.as_u16(),
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} rows differ:\n{}",
        mismatches.len(),
        rows.len(),
        mismatches.join("\n")
    );
}

/// The shipped default mode answers every (key kind x header x body) request
/// exactly as the base did: the #8947 fix only acts under Enforce. The shared
/// key rows that show a private row are the documented Advisory behaviour (a
/// merely-claimed principal draws a warning, not a refusal).
async fn cell_m8947_default_mode_matrix(router: &axum::Router) {
    let ok = StatusCode::OK;
    let bad = StatusCode::BAD_REQUEST;
    let mismatch = Some(ERR_BODY_HEADER_MISMATCH);
    let rows = [
        row(SHARED_KEY, NONE, NONE, ok, None, false, false),
        row(SHARED_KEY, NONE, HDR_A, ok, None, true, false),
        row(SHARED_KEY, NONE, HDR_B, ok, None, false, true),
        row(SHARED_KEY, HDR_A, NONE, ok, None, true, false),
        row(SHARED_KEY, HDR_A, HDR_A, ok, None, true, false),
        row(SHARED_KEY, HDR_A, HDR_B, bad, mismatch, false, false),
        row(SHARED_KEY, HDR_B, NONE, ok, None, false, true),
        row(SHARED_KEY, HDR_B, HDR_A, bad, mismatch, false, false),
        row(SHARED_KEY, HDR_B, HDR_B, ok, None, false, true),
        row(KEY_A, NONE, NONE, ok, None, true, false),
        row(KEY_A, NONE, HDR_A, ok, None, true, false),
        row(KEY_A, NONE, HDR_B, bad, mismatch, false, false),
        row(KEY_A, HDR_A, NONE, ok, None, true, false),
        row(KEY_A, HDR_A, HDR_A, ok, None, true, false),
        row(KEY_A, HDR_A, HDR_B, bad, mismatch, false, false),
        row(KEY_A, HDR_B, NONE, ok, None, true, false),
        row(KEY_A, HDR_B, HDR_A, ok, None, true, false),
        row(KEY_A, HDR_B, HDR_B, bad, mismatch, false, false),
    ];
    run_rows(router, "m8947 default-mode", &rows).await;
}

/// Under Enforce a caller naming ITS OWN claimed id: a per-agent key for A keeps
/// working with the id in the header, the body, or both; a shared key proves no
/// agent, so every spelling that names one is refused.
async fn cell_m8947_enforce_own_id_matrix(router: &axum::Router) {
    let ok = StatusCode::OK;
    let denied = StatusCode::FORBIDDEN;
    let attested = Some(ERR_ATTESTED_REQUIRED);
    let rows = [
        row(KEY_A, HDR_A, HDR_A, ok, None, true, false),
        row(KEY_A, NONE, HDR_A, ok, None, true, false),
        row(KEY_A, HDR_A, NONE, ok, None, true, false),
        row(SHARED_KEY, HDR_A, HDR_A, denied, attested, false, false),
        row(SHARED_KEY, NONE, HDR_A, denied, attested, false, false),
        row(SHARED_KEY, HDR_A, NONE, denied, attested, false, false),
    ];
    run_rows(router, "m8947 enforce own-id", &rows).await;
}

/// One `session_start` call with a RAW JSON body: `body` is parsed, the test's
/// namespace and limit are added, and every other key (a `null` `agent_id`, the
/// key-case twin) is sent exactly as written.
async fn call_raw(
    router: &axum::Router,
    key: &str,
    x_agent: Option<&str>,
    body: &str,
) -> (StatusCode, Value, String) {
    let mut payload: Value = serde_json::from_str(body).expect("table body is JSON");
    payload["namespace"] = json!(NAMESPACE);
    payload["limit"] = json!(SESSION_LIMIT);
    let mut req = Request::builder()
        .method("POST")
        .uri(SESSION_START_PATH)
        .header("content-type", "application/json")
        .header("x-api-key", key);
    if let Some(h) = x_agent {
        req = req.header("x-agent-id", h);
    }
    let resp = router
        .clone()
        .oneshot(req.body(Body::from(payload.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), BODY_LIMIT_BYTES)
        .await
        .unwrap();
    let raw = String::from_utf8_lossy(&bytes).into_owned();
    let parsed = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, parsed, raw)
}

/// Wire `code` of the authority chokepoint's malformed-header refusal
/// (`src/handlers/authority.rs`, `#3549`).
const CODE_VALIDATION_FAILED: &str = "VALIDATION_FAILED";
/// Leading text of that refusal for a whitespace `X-Agent-Id` (the rest names
/// the offending character).
const ERR_INVALID_AGENT_ID_PREFIX: &str = "invalid agent_id: agent_id contains invalid character";

/// The expected error of one `e8947` cell.
#[derive(Clone, Copy)]
enum BlankErr {
    /// No `error` field.
    None,
    /// `error` equals this text exactly.
    Exact(&'static str),
    /// The authority chokepoint's malformed-header 400: `code` is
    /// [`CODE_VALIDATION_FAILED`] and `error` starts with
    /// [`ERR_INVALID_AGENT_ID_PREFIX`].
    MalformedHeader,
}

impl BlankErr {
    const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Exact(text) => text,
            Self::MalformedHeader => CODE_VALIDATION_FAILED,
        }
    }
}

/// The expected answer of one `e8947` cell: exact status, the error, and the
/// private markers the caller may see.
struct BlankWant {
    status: StatusCode,
    err: BlankErr,
    own: &'static [&'static str],
}

/// The rule the `e8947` table is generated from (one rule, every cell):
///   * shared key, header empty or absent: no header value names a principal,
///     so the gate admits the request as the anonymous principal it resolved;
///     the answer is 200 with the shared row and NO private row of any owner;
///   * shared key, whitespace header: a malformed id, refused before any
///     handler by the authority chokepoint (400 `VALIDATION_FAILED`) in every
///     mode;
///   * per-agent key A, header empty or absent: the transport binds the
///     request to A (`api_key_auth` inserts `X-Agent-Id: A`), so 200 with A's
///     own row only;
///   * per-agent key A, whitespace header: a non-empty value that is not A;
///     Enforce refuses it as a binding mismatch (403), the default mode
///     corrects it to A (200 with A's own row only).
fn blank_want(mode: HttpIdentityMode, key: &str, header: Option<&str>) -> BlankWant {
    const A_ONLY: &[&str] = &[MARKER_A_PRIVATE];
    let whitespace = header.is_some_and(|h| !h.is_empty());
    match (key == KEY_A, whitespace, mode) {
        (false, false, _) => BlankWant {
            status: StatusCode::OK,
            err: BlankErr::None,
            own: &[],
        },
        (false, true, _) => BlankWant {
            status: StatusCode::BAD_REQUEST,
            err: BlankErr::MalformedHeader,
            own: &[],
        },
        (true, true, HttpIdentityMode::Enforce) => BlankWant {
            status: StatusCode::FORBIDDEN,
            err: BlankErr::Exact(ERR_BINDING_MISMATCH),
            own: &[],
        },
        (true, _, _) => BlankWant {
            status: StatusCode::OK,
            err: BlankErr::None,
            own: A_ONLY,
        },
    }
}

/// #8947 round 1 H1: (key kind x blank header x blank body) under `mode`. No
/// cell may return a private row the key does not prove, and every 200 still
/// returns the shared row (the answer is filtered, not empty by accident).
async fn cell_e8947_blank_header_matrix(router: &axum::Router, mode: HttpIdentityMode) {
    let mut mismatches: Vec<String> = Vec::new();
    let mut cells = 0usize;
    for key in [SHARED_KEY, KEY_A] {
        for header in BLANK_HEADERS {
            for body in BLANK_BODIES {
                cells += 1;
                let want = blank_want(mode, key, header);
                let (status, parsed, raw) = call_raw(router, key, header, body).await;
                let err = parsed["error"].as_str();
                let err_ok = match want.err {
                    BlankErr::None => parsed["error"].is_null(),
                    BlankErr::Exact(text) => err == Some(text),
                    BlankErr::MalformedHeader => {
                        parsed["code"].as_str() == Some(CODE_VALIDATION_FAILED)
                            && err.is_some_and(|e| e.starts_with(ERR_INVALID_AGENT_ID_PREFIX))
                    }
                };
                let seen: Vec<&str> = ALL_PRIVATE
                    .iter()
                    .copied()
                    .filter(|m| raw.contains(m))
                    .collect();
                let foreign: Vec<&str> = seen
                    .iter()
                    .copied()
                    .filter(|m| !want.own.contains(m))
                    .collect();
                let shared_ok = status != StatusCode::OK || raw.contains(MARKER_SHARED);
                if status != want.status
                    || !err_ok
                    || seen != want.own
                    || !foreign.is_empty()
                    || !shared_ok
                {
                    mismatches.push(format!(
                        "e8947 {} key={key} header={header:?} body={body}: want status={} \
                         err={} own={:?}; got status={} err={err:?} seen={seen:?} \
                         foreign={foreign:?} shared={shared_ok}",
                        mode.as_str(),
                        want.status.as_u16(),
                        want.err.label(),
                        want.own,
                        status.as_u16(),
                    ));
                }
            }
        }
    }
    assert_eq!(cells, 2 * BLANK_HEADERS.len() * BLANK_BODIES.len());
    assert!(
        mismatches.is_empty(),
        "{} of {cells} cells differ:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

// ---------------------------------------------------------------------------
// SQLite cells
// ---------------------------------------------------------------------------

fn scratch_dir() -> tempfile::TempDir {
    let root = std::path::PathBuf::from(".local-runs").join("issue-8947");
    std::fs::create_dir_all(&root).expect("create .local-runs/issue-8947");
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

#[tokio::test]
async fn a8947_sqlite_shared_key_body_leg_is_refused() {
    let dir = scratch_dir();
    cell_a8947_body_leg_shared_key(&sqlite_router(&dir)).await;
}

#[tokio::test]
async fn a8947_sqlite_per_agent_key_body_mismatch_is_refused() {
    let dir = scratch_dir();
    cell_a8947_body_leg_per_agent_key(&sqlite_router(&dir)).await;
}

#[tokio::test]
async fn positive_sqlite_owner_and_shared_rows_visible() {
    let dir = scratch_dir();
    cell_positive(&sqlite_router(&dir)).await;
}

#[tokio::test]
async fn h2135_sqlite_per_agent_key_header_mismatch_is_refused() {
    let dir = scratch_dir();
    cell_h2135_header_leg(&sqlite_router(&dir)).await;
}

#[tokio::test]
async fn h2135_sqlite_shared_key_header_is_refused() {
    let dir = scratch_dir();
    cell_h2135_header_leg_shared_key(&sqlite_router(&dir)).await;
}

#[test]
fn default_mode_is_the_shipped_default_8947() {
    // `HttpIdentityMode` derives `Default` with `#[default] Advisory`
    // (src/config.rs); the matrix below is built from `default()`, never a
    // hard-coded variant.
    assert_eq!(HttpIdentityMode::default(), HttpIdentityMode::Advisory);
    assert_eq!(HttpIdentityMode::default().as_str(), "advisory");
}

#[tokio::test]
async fn m8947_sqlite_default_mode_matrix_is_unchanged() {
    let dir = scratch_dir();
    let router = sqlite_router_in_mode(&dir, HttpIdentityMode::default());
    cell_m8947_default_mode_matrix(&router).await;
}

#[tokio::test]
async fn m8947_sqlite_enforce_own_id_matrix() {
    let dir = scratch_dir();
    cell_m8947_enforce_own_id_matrix(&sqlite_router(&dir)).await;
}

#[tokio::test]
async fn e8947_sqlite_blank_header_enforce() {
    let dir = scratch_dir();
    let mode = HttpIdentityMode::Enforce;
    cell_e8947_blank_header_matrix(&sqlite_router_in_mode(&dir, mode), mode).await;
}

#[tokio::test]
async fn e8947_sqlite_blank_header_default_mode() {
    let dir = scratch_dir();
    let mode = HttpIdentityMode::default();
    cell_e8947_blank_header_matrix(&sqlite_router_in_mode(&dir, mode), mode).await;
}

// ---------------------------------------------------------------------------
// PostgreSQL cells (isolated scratch database; self-skip without a URL)
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

#[cfg(feature = "sal-postgres")]
mod postgres_cells {
    use super::{
        Arc, Db, HttpIdentityMode, MemoryStore, ResolvedTtl, StorageBackend, build_router_in_mode,
        cell_a8947_body_leg_per_agent_key, cell_a8947_body_leg_shared_key,
        cell_e8947_blank_header_matrix, cell_h2135_header_leg, cell_h2135_header_leg_shared_key,
        cell_m8947_default_mode_matrix, cell_m8947_enforce_own_id_matrix, cell_positive,
        pg_barrier, seed_rows,
    };
    use ai_memory::store::CallerContext;
    use ai_memory::store::postgres::PostgresStore;

    const SCRATCH_PREFIX: &str = "ai_memory_8947ss";

    /// #1751 — the v0.9 store-path default demands signed attestation; this
    /// suite's unsigned seed rows use the explicit permissive opt-out, set once.
    fn permissive_attestation_for_tests() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        // SAFETY: `Once`-gated process-global env write, one stable value.
        ONCE.call_once(|| unsafe { std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0") });
    }

    async fn pg_router() -> Option<(pg_barrier::ScratchDb, axum::Router)> {
        pg_router_in_mode(HttpIdentityMode::Enforce).await
    }

    async fn pg_router_in_mode(
        mode: HttpIdentityMode,
    ) -> Option<(pg_barrier::ScratchDb, axum::Router)> {
        permissive_attestation_for_tests();
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("SKIP: AI_MEMORY_TEST_POSTGRES_URL not set");
            return None;
        };
        let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
            .await
            .expect("create scratch database");
        let pg = PostgresStore::connect(&scratch.url())
            .await
            .expect("connect scratch database");
        for m in seed_rows() {
            let owner = m.metadata["agent_id"].as_str().expect("owner").to_string();
            let ctx = CallerContext::for_agent(&owner);
            pg.store(&ctx, &m).await.expect("seed row");
        }
        let store: Arc<dyn MemoryStore> = Arc::new(pg);
        let conn = ai_memory::db::open(std::path::Path::new(":memory:")).expect("scratch sqlite");
        let db: Db = Arc::new(tokio::sync::Mutex::new((
            conn,
            std::path::PathBuf::from(":memory:"),
            ResolvedTtl::default(),
            true,
        )));
        let router = build_router_in_mode(db, store, StorageBackend::Postgres, mode);
        Some((scratch, router))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a8947_pg_shared_key_body_leg_is_refused() {
        let Some((_scratch, router)) = pg_router().await else {
            return;
        };
        cell_a8947_body_leg_shared_key(&router).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a8947_pg_per_agent_key_body_mismatch_is_refused() {
        let Some((_scratch, router)) = pg_router().await else {
            return;
        };
        cell_a8947_body_leg_per_agent_key(&router).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn positive_pg_owner_and_shared_rows_visible() {
        let Some((_scratch, router)) = pg_router().await else {
            return;
        };
        cell_positive(&router).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn h2135_pg_header_leg_is_refused() {
        let Some((_scratch, router)) = pg_router().await else {
            return;
        };
        cell_h2135_header_leg(&router).await;
        cell_h2135_header_leg_shared_key(&router).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn m8947_pg_default_mode_matrix_is_unchanged() {
        let Some((_scratch, router)) = pg_router_in_mode(HttpIdentityMode::default()).await else {
            return;
        };
        cell_m8947_default_mode_matrix(&router).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn m8947_pg_enforce_own_id_matrix() {
        let Some((_scratch, router)) = pg_router().await else {
            return;
        };
        cell_m8947_enforce_own_id_matrix(&router).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn e8947_pg_blank_header_enforce() {
        let mode = HttpIdentityMode::Enforce;
        let Some((_scratch, router)) = pg_router_in_mode(mode).await else {
            return;
        };
        cell_e8947_blank_header_matrix(&router, mode).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn e8947_pg_blank_header_default_mode() {
        let mode = HttpIdentityMode::default();
        let Some((_scratch, router)) = pg_router_in_mode(mode).await else {
            return;
        };
        cell_e8947_blank_header_matrix(&router, mode).await;
    }
}
