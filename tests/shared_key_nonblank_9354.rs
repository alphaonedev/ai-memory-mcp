// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9354 — a blank configured shared `api_key` must never authenticate.
//!
//! Defect class: an auth state held as an untyped string whose validity is
//! enforced at one call site instead of by construction. Instance: the daemon
//! boot path drops an empty / whitespace `api_key` (`bootstrap_serve`), but
//! every other constructor of `ApiKeyState` (the public `ai_memory::build_router`
//! and `build_router_with_timeout`, `daemon_runtime::build_router`, the
//! `serve_http_with_shutdown*` harnesses, a direct `api_key_auth` layer) stored
//! the blank string as the expected key, and the constant-time compare then
//! admitted a request whose `X-API-Key` carried the same blank bytes.
//!
//! Invariant: no `ApiKeyState` can hold a blank shared key. On every
//! constructor path a configured shared key is non-empty after `str::trim`, and
//! a request whose `X-API-Key` is empty or whitespace never authenticates, in
//! every identity mode. A blank value at a non-normalizing constructor is
//! refused closed (it is no key, and nothing compares against it); the boot
//! path keeps its precedent (blank = no shared key, pinned in b1 and b2) and
//! says so at boot with one WARN naming the remedy (b3).
//!
//! Blank corpus: `str::trim` strips Unicode `White_Space`, so U+00A0 (NBSP),
//! CR, U+2003, U+3000, U+0085, U+2028 and U+1680 are blank too (pinned per
//! member in p5); U+200B and U+FEFF are not `White_Space` and are real keys
//! (p6). No panic or assert message in this file formats a key value: a case
//! is named by its label only.
//!
//! Backends: the shared-key gate runs before any handler and reads no store;
//! the harness opens SQLite only because `AppState` needs one. Backend parity
//! is n/a for this binary.

#[path = "common/tls.rs"]
mod tls_helper;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_memory::config::HttpIdentityMode;
use ai_memory::handlers::identity_binding::{EnrolledAgentKeys, api_key_sha256_hex};
use ai_memory::handlers::monitoring::{MonitoringConfig, STATUS_PATH};
use ai_memory::handlers::{ApiKeyState, AppState};
use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tower::ServiceExt as _;

/// Configured shared keys that are blank after `str::trim` (label, value).
/// `str::trim` strips Unicode `White_Space`, so every member is blank to the
/// product (`ConfiguredKey::new` returns `None`); p5 pins that per member.
const BLANK_KEYS: [(&str, &str); 11] = [
    ("empty", ""),
    ("space", " "),
    ("tab", "\t"),
    ("space-newline-space", " \n "),
    ("nbsp", "\u{00a0}"),
    // CR alone: blank; a header cannot carry it (HeaderValue refuses CR).
    ("cr", "\r"),
    // U+2003 EM SPACE: Unicode White_Space, blank.
    ("em-space", "\u{2003}"),
    // U+3000 IDEOGRAPHIC SPACE: Unicode White_Space, blank.
    ("ideographic-space", "\u{3000}"),
    // U+0085 NEXT LINE: Unicode White_Space, blank.
    ("next-line", "\u{0085}"),
    // U+2028 LINE SEPARATOR: Unicode White_Space, blank.
    ("line-separator", "\u{2028}"),
    // U+1680 OGHAM SPACE MARK: Unicode White_Space, blank.
    ("ogham-space", "\u{1680}"),
];
/// Keys that look blank to a human but are NOT `White_Space` for `str::trim`:
/// the product treats each as a real, non-blank key (label, value). A zero
/// width space and a BOM are not blank. A header does carry their UTF-8 bytes
/// (`HeaderValue::from_bytes` accepts them as obs-text), but both gates read
/// `x-api-key` with `HeaderValue::to_str`, which refuses any byte that is not
/// visible ASCII, so such a key is never matched and every request fails closed.
const NON_BLANK_LOOKALIKES: [(&str, &str); 2] =
    [("zero-width-space", "\u{200b}"), ("bom", "\u{feff}")];
/// U+00A0 NO-BREAK SPACE, Unicode `White_Space`.
const NBSP: &str = "\u{00a0}";
/// CR alone (blank; refused by a header).
const CR: &str = "\r";
/// A value the HTTP stack cannot carry in a header (LF).
const SPACE_NEWLINE_SPACE: &[u8] = b" \n ";
const MODES: [HttpIdentityMode; 3] = [
    HttpIdentityMode::Off,
    HttpIdentityMode::Advisory,
    HttpIdentityMode::Enforce,
];
/// A real (non-blank) shared key for the positive controls.
const REAL_KEY: &str = "shared-real-key-9354";
/// A real key with surrounding whitespace: compared byte for byte, as today.
const PADDED_KEY: &str = "  shared-real-key-9354  ";
/// A real key with INNER spaces: non-blank, compared byte for byte.
const INNER_SPACE_KEY: &str = "real key 9354 with inner spaces";
const AGENT_A: &str = "ai:alice-9354";
const KEY_A: &str = "alice-per-agent-token-9354";
const READ_ROUTE: &str = "/api/v1/memories";
const REFUSAL_STATUS: StatusCode = StatusCode::UNAUTHORIZED;
/// The body `api_key_auth` renders for a missing or invalid credential.
const REFUSAL_ERROR: &str = "missing or invalid API key";
/// The body the outer monitoring gate renders for an unauthenticated probe.
const MONITORING_REFUSAL_ERROR: &str = "monitoring_requires_authentication";
const MISMATCH_CODE: &str = "identity_binding_mismatch";
/// Oversize blank credential length for the unbounded-input cell (p4).
const HUGE_BLANK_BYTES: usize = 100_001;
/// Wall-clock ceiling for answering the oversize blank credential (p4).
const HUGE_CEILING: Duration = Duration::from_secs(5);
/// Bounded wait for a spawned listener to accept (c5).
const TCP_READY_ATTEMPTS: u32 = 200;
const TCP_READY_STEP: Duration = Duration::from_millis(25);
const TCP_IO_CEILING: Duration = Duration::from_secs(20);
const BODY_LIMIT: usize = 1 << 20;
const SRC_DIR: &str = "src";
/// Every read of a field named `key` in `src/**/*.rs` (comments and string
/// literals blanked; `transport.rs` included) must be one of these exact
/// (file, trimmed line, why) entries, so a new raw read of the shared key under
/// any binding name fails s1 until a reviewer admits it here. Entries about
/// `ApiKeyState::key` are the accessor, the presence checks and unit-test
/// asserts; the others are unrelated structs that merely name a field `key`.
/// Number of allowlisted reads (asserted against the scan in s1).
const ALLOWED_KEY_FIELD_READS_COUNT: usize = 28;
const ALLOWED_KEY_FIELD_READS: [(&str, &str, &str); ALLOWED_KEY_FIELD_READS_COUNT] = [
    (
        "src/handlers/transport.rs",
        "self.key.as_deref().and_then(ConfiguredKey::new)",
        "ApiKeyState: the one typed accessor",
    ),
    (
        "src/handlers/transport.rs",
        "if auth.key.is_none() {",
        "ApiKeyState: presence check, the unset-key early return",
    ),
    (
        "src/daemon_runtime.rs",
        "if api_key_state.key.is_some() {",
        "ApiKeyState: presence check (boot posture)",
    ),
    (
        "src/daemon_runtime.rs",
        "crate::handlers::admin_role::mark_request_authn_configured(api_key_state.key.is_some());",
        "ApiKeyState: presence check (boot posture)",
    ),
    (
        "src/daemon_runtime.rs",
        "&& api_key_state.key.is_none()",
        "ApiKeyState: presence check (boot posture)",
    ),
    (
        "src/daemon_runtime.rs",
        "assert_eq!(bs.api_key_state.key.as_deref(), Some(\"test-key\"));",
        "ApiKeyState: unit-test assert on the booted key",
    ),
    (
        "src/daemon_runtime.rs",
        "assert_eq!(bs.api_key_state.key.as_deref(), Some(\"s3cret\"));",
        "ApiKeyState: unit-test assert on the booted key",
    ),
    (
        "src/daemon_runtime.rs",
        "assert_eq!(bs.api_key_state.key.as_deref(), Some(\"only-tls\"));",
        "ApiKeyState: unit-test assert on the booted key",
    ),
    (
        "src/daemon_runtime.rs",
        "assert_eq!(bs.api_key_state.key.as_deref(), Some(\"fed-key\"));",
        "ApiKeyState: unit-test assert on the booted key",
    ),
    (
        "src/cli/store.rs",
        "Some(v) => unsafe { std::env::set_var(self.key, v) },",
        "unrelated: env guard field",
    ),
    (
        "src/cli/store.rs",
        "None => unsafe { std::env::remove_var(self.key) },",
        "unrelated: env guard field",
    ),
    (
        "src/test_support.rs",
        "std::env::set_var(self.key, v);",
        "unrelated: env guard field",
    ),
    (
        "src/test_support.rs",
        "std::env::remove_var(self.key);",
        "unrelated: env guard field",
    ),
    (
        "src/test_support.rs",
        "std::env::set_var(self.key, v);",
        "unrelated: env guard field",
    ),
    (
        "src/test_support.rs",
        "std::env::remove_var(self.key);",
        "unrelated: env guard field",
    ),
    (
        "src/config/deprecated_keys.rs",
        "if !present.iter().any(|p| p == row.key) {",
        "unrelated: deprecated-key row",
    ),
    (
        "src/config/deprecated_keys.rs",
        "f.row.key,",
        "unrelated: deprecated-key row",
    ),
    (
        "src/config/deprecated_keys.rs",
        "f.row.key,",
        "unrelated: deprecated-key row",
    ),
    (
        "src/config/deprecated_keys.rs",
        "DEPRECATED_KEYS.iter().find(|r| r.key == key)",
        "unrelated: deprecated-key row",
    ),
    (
        "src/config/deprecated_keys.rs",
        "accepted.iter().any(|k| k == row.key),",
        "unrelated: deprecated-key row",
    ),
    (
        "src/config/deprecated_keys.rs",
        "row.key",
        "unrelated: deprecated-key row",
    ),
    (
        "src/config/deprecated_keys.rs",
        "assert!(!row.replacement.is_empty(), \"{}\", row.key);",
        "unrelated: deprecated-key row",
    ),
    (
        "src/config/deprecated_keys.rs",
        "assert!(version_triple(row.deprecated_in).is_some(), \"{}\", row.key);",
        "unrelated: deprecated-key row",
    ),
    (
        "src/config/deprecated_keys.rs",
        "assert!(version_triple(r).is_some(), \"{}\", row.key);",
        "unrelated: deprecated-key row",
    ),
    (
        "src/config/deprecated_keys.rs",
        "assert_eq!(c.deprecated[0].row.key, \"llm_model\");",
        "unrelated: deprecated-key row",
    ),
    (
        "src/store/mod.rs",
        ".get(&self.key)",
        "unrelated: metadata map key",
    ),
    (
        "src/store/postgres.rs",
        ".map(|m| (m.key.clone(), m.value.clone()));",
        "unrelated: metadata row",
    ),
    (
        "src/store/sqlite.rs",
        ".map(|m| (m.key.as_str(), m.value.as_str()));",
        "unrelated: metadata row",
    ),
];
/// Source type whose `key` field the ratchet guards (destructuring check).
const KEY_STATE_TYPE: &str = "ApiKeyState";

/// The `X-API-Key` header of one request.
#[derive(Clone, Copy, Debug)]
enum HeaderCase {
    Absent,
    Empty,
    Space,
    /// The same bytes as the configured blank key.
    SameAsKey,
}

const HEADER_CASES: [HeaderCase; 4] = [
    HeaderCase::Absent,
    HeaderCase::Empty,
    HeaderCase::Space,
    HeaderCase::SameAsKey,
];

fn header_value(case: HeaderCase, key: &str) -> Option<&[u8]> {
    match case {
        HeaderCase::Absent => None,
        HeaderCase::Empty => Some(b""),
        HeaderCase::Space => Some(b" "),
        HeaderCase::SameAsKey => Some(key.as_bytes()),
    }
}

/// One identity posture of the key state.
#[derive(Clone, Copy, Debug)]
struct Posture {
    mode: HttpIdentityMode,
    enrolled: bool,
}

/// Every identity mode, without and with an enrolled per-agent key.
fn postures() -> Vec<Posture> {
    let mut out = Vec::new();
    for mode in MODES {
        for enrolled in [false, true] {
            out.push(Posture { mode, enrolled });
        }
    }
    out
}

/// The constructor paths that build `ApiKeyState` without the boot normalizer
/// and route a request into `api_key_auth`.
#[derive(Clone, Copy, Debug)]
enum Entry {
    /// `ai_memory::build_router` (src/lib.rs).
    LibBuildRouter,
    /// `ai_memory::build_router_with_timeout` (src/lib.rs).
    LibBuildRouterWithTimeout,
    /// `ai_memory::daemon_runtime::build_router`.
    DaemonBuildRouter,
    /// A direct `from_fn_with_state(state, api_key_auth)` layer (the shape of
    /// the in-crate test harnesses).
    Middleware,
}

fn registry(enrolled: bool) -> Arc<EnrolledAgentKeys> {
    let map: HashMap<String, String> = if enrolled {
        [(api_key_sha256_hex(KEY_A), AGENT_A.to_string())]
            .into_iter()
            .collect()
    } else {
        HashMap::new()
    };
    Arc::new(EnrolledAgentKeys::from_map(map))
}

fn app_state(mode: HttpIdentityMode, enrolled: &Arc<EnrolledAgentKeys>) -> AppState {
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
    AppState {
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
        admin_agent_ids: Arc::new(vec![]),
        rule_cache: Arc::new(ai_memory::governance::rule_cache::RuleCache::new()),
        resolved_models: Arc::new(ai_memory::reload::Swappable::new(
            ai_memory::config::ResolvedModels::default(),
        )),
        runtime: ai_memory::runtime_context::RuntimeContext::global_arc(),
        max_page_size: ai_memory::handlers::MAX_BULK_SIZE,
        enrolled_agent_keys: Arc::clone(enrolled),
        http_identity_mode: mode,
    }
}

/// The key state exactly as a library or test caller writes it: the raw
/// configured string, no normalizer.
fn key_state(
    key: Option<&str>,
    posture: Posture,
    enrolled: &Arc<EnrolledAgentKeys>,
) -> ApiKeyState {
    ApiKeyState {
        key: key.map(str::to_string),
        mtls_enforced: false,
        enrolled_agent_keys: Arc::clone(enrolled),
        identity_mode: posture.mode,
        ..Default::default()
    }
}

fn router(entry: Entry, key: Option<&str>, posture: Posture) -> axum::Router {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let enrolled = registry(posture.enrolled);
    let state = key_state(key, posture, &enrolled);
    let app = app_state(posture.mode, &enrolled);
    match entry {
        Entry::LibBuildRouter => ai_memory::build_router(state, app),
        Entry::LibBuildRouterWithTimeout => {
            ai_memory::build_router_with_timeout(state, app, Duration::from_secs(30))
        }
        Entry::DaemonBuildRouter => ai_memory::daemon_runtime::build_router(app, state),
        Entry::Middleware => axum::Router::new()
            .route(READ_ROUTE, axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state,
                ai_memory::handlers::api_key_auth,
            )),
    }
}

/// One GET with a raw (possibly unbuildable) `X-API-Key`. `None` when the
/// HTTP stack cannot carry the value at all (it never reaches a server).
async fn send(app: &axum::Router, path: &str, key: Option<&[u8]>) -> Option<(StatusCode, Value)> {
    let mut b = Request::builder().method("GET").uri(path);
    if let Some(k) = key {
        let value = HeaderValue::from_bytes(k).ok()?;
        b = b.header(ai_memory::HEADER_API_KEY, value);
    }
    let resp = app
        .clone()
        .oneshot(b.body(Body::empty()).expect("request"))
        .await
        .expect("oneshot");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), BODY_LIMIT)
        .await
        .expect("body");
    Some((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

fn refusal_body() -> Value {
    json!({ "error": REFUSAL_ERROR })
}

/// Got past `api_key_auth` (the handler may still answer with its own verdict).
fn admitted(status: StatusCode, body: &Value) -> bool {
    status != StatusCode::UNAUTHORIZED
        && status != StatusCode::TOO_MANY_REQUESTS
        && !(status == StatusCode::FORBIDDEN && body["error"] == MISMATCH_CODE)
}

/// Every blank configured key x header case x posture through `entry`; every
/// carried request must get the exact refusal.
async fn blank_key_sweep(entry: Entry) {
    let mut off_contract = Vec::new();
    let mut carried = 0usize;
    for posture in postures() {
        for (label, blank) in BLANK_KEYS {
            let app = router(entry, Some(blank), posture);
            for case in HEADER_CASES {
                let Some((status, body)) = send(&app, READ_ROUTE, header_value(case, blank)).await
                else {
                    continue;
                };
                carried += 1;
                if status != REFUSAL_STATUS || body != refusal_body() {
                    off_contract.push(format!(
                        "{entry:?} {posture:?} key={label} header={case:?}: {status} {body}"
                    ));
                }
            }
        }
    }
    assert!(carried > 0, "{entry:?}: no request was carried");
    assert!(
        off_contract.is_empty(),
        "{entry:?}: {} of {carried} blank-key requests not refused exactly:\n{}",
        off_contract.len(),
        off_contract.join("\n")
    );
}

/// c1 — `ai_memory::build_router`.
#[tokio::test]
async fn c1_lib_build_router_blank_key_never_authenticates_9354() {
    blank_key_sweep(Entry::LibBuildRouter).await;
}

/// c2 — `ai_memory::build_router_with_timeout`.
#[tokio::test]
async fn c2_lib_build_router_with_timeout_blank_key_never_authenticates_9354() {
    blank_key_sweep(Entry::LibBuildRouterWithTimeout).await;
}

/// c3 — `ai_memory::daemon_runtime::build_router`.
#[tokio::test]
async fn c3_daemon_build_router_blank_key_never_authenticates_9354() {
    blank_key_sweep(Entry::DaemonBuildRouter).await;
}

/// c4 — a direct `api_key_auth` layer (the in-crate harness shape).
#[tokio::test]
async fn c4_api_key_auth_layer_blank_key_never_authenticates_9354() {
    blank_key_sweep(Entry::Middleware).await;
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe")
        .local_addr()
        .expect("probe addr")
        .port()
}

/// One raw HTTP/1.1 GET over TCP (hyper parses the header, so leading and
/// trailing OWS is stripped exactly as for a real client).
async fn tcp_get(addr: &str, key: Option<&[u8]>) -> (StatusCode, Value) {
    let mut raw =
        format!("GET {READ_ROUTE} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n").into_bytes();
    if let Some(k) = key {
        raw.extend_from_slice(ai_memory::HEADER_API_KEY.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(k);
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(b"\r\n");
    let io = async {
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream.write_all(&raw).await.expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        buf
    };
    let buf = tokio::time::timeout(TCP_IO_CEILING, io)
        .await
        .expect("tcp exchange within ceiling");
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let code: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .expect("status code");
    (
        StatusCode::from_u16(code).expect("status"),
        serde_json::from_str(body).unwrap_or(Value::Null),
    )
}

/// The header bytes a raw HTTP/1.1 request line can carry.
fn tcp_carriable(value: &[u8]) -> bool {
    HeaderValue::from_bytes(value).is_ok() && !value.iter().any(|b| matches!(b, b'\r' | b'\n'))
}

/// c5 — `daemon_runtime::serve_http_with_shutdown_future` over a real socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn c5_serve_http_tcp_blank_key_never_authenticates_9354() {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let mut off_contract = Vec::new();
    let mut carried = 0usize;
    for mode in MODES {
        let posture = Posture {
            mode,
            enrolled: false,
        };
        for (label, blank) in BLANK_KEYS {
            let enrolled = registry(false);
            let state = key_state(Some(blank), posture, &enrolled);
            let app = app_state(mode, &enrolled);
            let addr = format!("127.0.0.1:{}", free_port());
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
            let serve_addr = addr.clone();
            let server = tokio::spawn(async move {
                ai_memory::daemon_runtime::serve_http_with_shutdown_future(
                    &serve_addr,
                    state,
                    app,
                    async move {
                        let _ = stop_rx.await;
                    },
                )
                .await
            });
            let mut ready = false;
            for _ in 0..TCP_READY_ATTEMPTS {
                if tokio::net::TcpStream::connect(&addr).await.is_ok() {
                    ready = true;
                    break;
                }
                tokio::time::sleep(TCP_READY_STEP).await;
            }
            assert!(ready, "listener {addr} never accepted");
            for case in HEADER_CASES {
                let value = header_value(case, blank);
                if value.is_some_and(|v| !tcp_carriable(v)) {
                    continue;
                }
                carried += 1;
                let (status, body) = tcp_get(&addr, value).await;
                if status != REFUSAL_STATUS || body != refusal_body() {
                    off_contract.push(format!(
                        "tcp {mode:?} key={label} header={case:?}: {status} {body}"
                    ));
                }
            }
            let _ = stop_tx.send(());
            server.await.expect("join").expect("serve");
        }
    }
    assert!(carried > 0, "tcp: no request was carried");
    assert!(
        off_contract.is_empty(),
        "tcp: {} of {carried} blank-key requests not refused exactly:\n{}",
        off_contract.len(),
        off_contract.join("\n")
    );
}

/// c6 — the outer monitoring gate (`monitoring::access`, mounted by
/// `ai_memory::build_router`): a blank header never authenticates a health
/// probe against a blank configured key.
#[tokio::test]
async fn c6_monitoring_gate_blank_key_never_authenticates_9354() {
    ai_memory::handlers::admin_role::mark_request_authn_configured(true);
    let monitoring_refusal = json!({ "error": MONITORING_REFUSAL_ERROR });
    let mut off_contract = Vec::new();
    for mode in MODES {
        for (label, blank) in BLANK_KEYS {
            let enrolled = Arc::new(
                EnrolledAgentKeys::from_map(HashMap::new())
                    .with_monitoring(MonitoringConfig::default(), true),
            );
            let posture = Posture {
                mode,
                enrolled: false,
            };
            let app = ai_memory::build_router(
                key_state(Some(blank), posture, &enrolled),
                app_state(mode, &enrolled),
            );
            for case in HEADER_CASES {
                let Some((status, body)) = send(&app, STATUS_PATH, header_value(case, blank)).await
                else {
                    continue;
                };
                if status != REFUSAL_STATUS || body != monitoring_refusal {
                    off_contract.push(format!(
                        "monitoring {mode:?} key={label} header={case:?}: {status} {body}"
                    ));
                }
            }
        }
        // Positive control: a real configured key still opens the probe.
        let enrolled = Arc::new(
            EnrolledAgentKeys::from_map(HashMap::new())
                .with_monitoring(MonitoringConfig::default(), true),
        );
        let posture = Posture {
            mode,
            enrolled: false,
        };
        let app = ai_memory::build_router(
            key_state(Some(REAL_KEY), posture, &enrolled),
            app_state(mode, &enrolled),
        );
        let (status, body) = send(&app, STATUS_PATH, Some(REAL_KEY.as_bytes()))
            .await
            .expect("carried");
        assert!(
            status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
            "monitoring {mode:?}: real key must open the probe: {status} {body}"
        );
    }
    assert!(
        off_contract.is_empty(),
        "monitoring: {} blank-key probes not refused exactly:\n{}",
        off_contract.len(),
        off_contract.join("\n")
    );
}

/// p1 — positive control: a non-blank key authenticates on every router entry
/// and mode, and a blank header against it gets the exact refusal.
#[tokio::test]
async fn p1_real_key_authenticates_and_blank_header_is_refused_9354() {
    for entry in [
        Entry::LibBuildRouter,
        Entry::LibBuildRouterWithTimeout,
        Entry::DaemonBuildRouter,
        Entry::Middleware,
    ] {
        for posture in postures() {
            let app = router(entry, Some(REAL_KEY), posture);
            let (status, body) = send(&app, READ_ROUTE, Some(REAL_KEY.as_bytes()))
                .await
                .expect("carried");
            assert!(
                admitted(status, &body),
                "{entry:?} {posture:?}: real key must admit: {status} {body}"
            );
            for case in [HeaderCase::Absent, HeaderCase::Empty, HeaderCase::Space] {
                let (status, body) = send(&app, READ_ROUTE, header_value(case, REAL_KEY))
                    .await
                    .expect("carried");
                assert_eq!(
                    status, REFUSAL_STATUS,
                    "{entry:?} {posture:?} {case:?}: {body}"
                );
                assert_eq!(body, refusal_body(), "{entry:?} {posture:?} {case:?}");
            }
        }
    }
}

/// p2 — pin: surrounding whitespace on a real key is compared byte for byte,
/// as today (no trimming of a non-blank key), and a key with inner spaces is a
/// valid non-blank key that admits itself and refuses its space-stripped form.
#[tokio::test]
async fn p2_padded_real_key_is_compared_verbatim_9354() {
    for posture in postures() {
        let app = router(Entry::LibBuildRouter, Some(INNER_SPACE_KEY), posture);
        let (status, body) = send(&app, READ_ROUTE, Some(INNER_SPACE_KEY.as_bytes()))
            .await
            .expect("carried");
        assert!(
            admitted(status, &body),
            "{posture:?}: the inner-space key byte for byte must admit: {status} {body}"
        );
        let stripped = INNER_SPACE_KEY.replace(' ', "");
        let (status, body) = send(&app, READ_ROUTE, Some(stripped.as_bytes()))
            .await
            .expect("carried");
        assert_eq!(
            status, REFUSAL_STATUS,
            "{posture:?}: inner-space key, spaces removed: {body}"
        );
        assert_eq!(
            body,
            refusal_body(),
            "{posture:?}: inner-space key stripped"
        );
        let app = router(Entry::LibBuildRouter, Some(PADDED_KEY), posture);
        let (status, body) = send(&app, READ_ROUTE, Some(PADDED_KEY.as_bytes()))
            .await
            .expect("carried");
        assert!(
            admitted(status, &body),
            "{posture:?}: the padded key byte for byte must admit: {status} {body}"
        );
        let (status, body) = send(&app, READ_ROUTE, Some(PADDED_KEY.trim().as_bytes()))
            .await
            .expect("carried");
        assert_eq!(
            status, REFUSAL_STATUS,
            "{posture:?}: trimmed padded key: {body}"
        );
        assert_eq!(body, refusal_body(), "{posture:?}: trimmed padded key");
    }
}

/// p3 — a blank configured key refuses closed without locking out an enrolled
/// per-agent key, in every mode.
#[tokio::test]
async fn p3_blank_key_keeps_enrolled_per_agent_keys_working_9354() {
    for posture in postures().into_iter().filter(|p| p.enrolled) {
        for (label, blank) in BLANK_KEYS {
            let app = router(Entry::LibBuildRouter, Some(blank), posture);
            let (status, body) = send(&app, READ_ROUTE, Some(KEY_A.as_bytes()))
                .await
                .expect("carried");
            assert!(
                admitted(status, &body),
                "{posture:?} key={label}: enrolled per-agent key must admit: {status} {body}"
            );
        }
    }
}

/// p4 — a 100K blank credential is answered with the exact refusal in bounded
/// time, against a short blank key and against a 100K blank key.
#[tokio::test]
async fn p4_huge_blank_header_refused_in_bounded_time_9354() {
    let huge = " ".repeat(HUGE_BLANK_BYTES);
    for configured in [" ", huge.as_str()] {
        for mode in MODES {
            let posture = Posture {
                mode,
                enrolled: false,
            };
            let app = router(Entry::LibBuildRouter, Some(configured), posture);
            let t0 = Instant::now();
            let (status, body) = send(&app, READ_ROUTE, Some(huge.as_bytes()))
                .await
                .expect("carried");
            let elapsed = t0.elapsed();
            assert!(elapsed < HUGE_CEILING, "{mode:?}: {elapsed:?} over ceiling");
            assert_eq!(
                status,
                REFUSAL_STATUS,
                "{mode:?} configured={}B: {body}",
                configured.len()
            );
            assert_eq!(
                body,
                refusal_body(),
                "{mode:?} configured={}B",
                configured.len()
            );
        }
    }
}

/// p5 — pin the blank corpus per member: every `BLANK_KEYS` member is blank to
/// `str::trim` (the product's one blank test, `ConfiguredKey::new`), exactly
/// the table below; NBSP rides in a header but is not a visible-ASCII token;
/// LF and CR cannot be carried at all.
#[test]
fn p5_blank_corpus_pins_9354() {
    for (label, blank) in BLANK_KEYS {
        assert!(blank.trim().is_empty(), "{label} must be blank after trim");
    }
    for (label, key) in NON_BLANK_LOOKALIKES {
        assert!(
            !key.trim().is_empty(),
            "{label} is not White_Space and must stay a non-blank key"
        );
    }
    assert!(
        !INNER_SPACE_KEY.trim().is_empty() && INNER_SPACE_KEY.trim() == INNER_SPACE_KEY,
        "a key with inner spaces is non-blank and needs no trimming"
    );
    assert!(NBSP.trim().is_empty(), "str::trim strips U+00A0");
    let nbsp = HeaderValue::from_bytes(NBSP.as_bytes()).expect("NBSP bytes ride in a header");
    assert!(nbsp.to_str().is_err(), "NBSP is not a visible-ASCII token");
    assert!(
        HeaderValue::from_bytes(SPACE_NEWLINE_SPACE).is_err(),
        "LF cannot be carried in a header"
    );
    assert!(
        HeaderValue::from_bytes(CR.as_bytes()).is_err(),
        "CR cannot be carried in a header"
    );
}

/// 6 postures x 2 lookalike keys x 4 headers (absent, empty, space, the key).
const LOOKALIKE_EXPECTED_REQUESTS: usize = 48;

/// p6 — the not-`White_Space` lookalikes (U+200B, U+FEFF) are real keys: the
/// router holds them as the configured key. Every header case is carried (the
/// `SameAsKey` header holds the key's own UTF-8 bytes as obs-text), and every
/// request is refused with the exact refusal because both gates read the
/// header with `HeaderValue::to_str`, which refuses those bytes: fail-closed,
/// never an admit, in every identity mode. The boot path keeps them verbatim.
#[tokio::test]
async fn p6_non_whitespace_lookalikes_are_non_blank_keys_9354() {
    let mut carried = 0usize;
    for posture in postures() {
        for (label, key) in NON_BLANK_LOOKALIKES {
            let app = router(Entry::LibBuildRouter, Some(key), posture);
            for case in HEADER_CASES {
                let (status, body) = send(&app, READ_ROUTE, header_value(case, key))
                    .await
                    .unwrap_or_else(|| panic!("{posture:?} key={label} {case:?}: carried"));
                carried += 1;
                assert_eq!(
                    status, REFUSAL_STATUS,
                    "{posture:?} key={label} {case:?}: {body}"
                );
                assert_eq!(body, refusal_body(), "{posture:?} key={label} {case:?}");
            }
        }
    }
    assert_eq!(
        carried, LOOKALIKE_EXPECTED_REQUESTS,
        "every lookalike request is carried"
    );
    for (label, key) in NON_BLANK_LOOKALIKES {
        let path = scratch_db();
        let tls = tls_helper::TestTls::generate(&path.with_extension("tls9354"));
        let args = loopback_args("127.0.0.1", &tls);
        let cfg = ai_memory::config::AppConfig {
            api_key: Some(key.to_string()),
            ..Default::default()
        };
        let bs = ai_memory::daemon_runtime::bootstrap_serve(&path, &args, &cfg)
            .await
            .unwrap_or_else(|e| panic!("{label}: loopback boot: {e:#}"));
        assert!(
            bs.api_key_state.key.as_deref() == Some(key),
            "{label}: the boot path keeps a non-blank key verbatim"
        );
        for h in bs.task_handles {
            h.abort();
        }
    }
}

fn loopback_args(host: &str, tls: &tls_helper::TestTls) -> ai_memory::daemon_runtime::ServeArgs {
    ai_memory::daemon_runtime::ServeArgs {
        host: host.to_string(),
        port: 0,
        tls_cert: Some(tls.cert_path.clone()),
        tls_key: Some(tls.key_path.clone()),
        mtls_allowlist: None,
        shutdown_grace_secs: 30,
        quorum_writes: 0,
        quorum_peers: vec![],
        quorum_timeout_ms: 2000,
        quorum_client_cert: None,
        quorum_client_key: None,
        quorum_ca_cert: None,
        catchup_interval_secs: 30,
        federation_identity: None,
        check: false,
        #[cfg(feature = "sal")]
        store_url: None,
    }
}

fn scratch_db() -> std::path::PathBuf {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile for db");
    let path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    path
}

/// b1 — the boot precedent (pinned, unchanged): `bootstrap_serve` turns a blank
/// configured `api_key` into no shared key, and a real key is kept verbatim.
#[tokio::test]
async fn b1_boot_blank_key_is_no_shared_key_9354() {
    for (label, blank) in BLANK_KEYS.iter().copied().chain([("real", REAL_KEY)]) {
        let path = scratch_db();
        let tls = tls_helper::TestTls::generate(&path.with_extension("tls9354"));
        let args = loopback_args("127.0.0.1", &tls);
        let cfg = ai_memory::config::AppConfig {
            api_key: Some(blank.to_string()),
            ..Default::default()
        };
        let bs = ai_memory::daemon_runtime::bootstrap_serve(&path, &args, &cfg)
            .await
            .unwrap_or_else(|e| panic!("{label}: loopback boot: {e:#}"));
        let expected = (label == "real").then_some(REAL_KEY);
        assert!(
            bs.api_key_state.key.as_deref() == expected,
            "{label}: the booted shared key is not the expected one"
        );
        for h in bs.task_handles {
            h.abort();
        }
    }
}

/// b2 — the boot precedent is not fail-open: a blank `api_key` on a routable
/// bind is no key, so boot refuses exactly as for an unset key.
#[tokio::test]
async fn b2_boot_blank_key_on_routable_bind_refuses_9354() {
    for (label, blank) in BLANK_KEYS {
        let path = scratch_db();
        let tls = tls_helper::TestTls::generate(&path.with_extension("tls9354"));
        let args = loopback_args("0.0.0.0", &tls);
        let cfg = ai_memory::config::AppConfig {
            api_key: Some(blank.to_string()),
            ..Default::default()
        };
        let msg = match ai_memory::daemon_runtime::bootstrap_serve(&path, &args, &cfg).await {
            Ok(_) => panic!("{label}: routable bind with a blank key must refuse"),
            Err(e) => format!("{e:#}"),
        };
        assert!(
            msg.contains("refusing to bind") && msg.contains("non-loopback"),
            "{label}: {msg}"
        );
    }
}

/// The exact boot WARN for a blank configured `api_key` (ruling 28907a4f): it
/// says what happened and names the remedy; it never carries the key value.
const BLANK_KEY_BOOT_WARN: &str = "#9354: api_key is configured but blank (empty or whitespace) and is \
treated as no shared key: HTTP API-key auth is off and a non-loopback bind is refused; remedy: set \
top-level `api_key = \"...\"` to a non-blank secret, or remove the blank value";

/// A `tracing` writer into a shared buffer.
#[derive(Clone, Default)]
struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);

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

/// Boot on loopback with `api_key`, capturing every event of the boot; the
/// router is built from the booted state exactly as `serve` composes it.
async fn boot_capturing(label: &str, api_key: Option<&str>) -> (String, axum::Router) {
    let path = scratch_db();
    let tls = tls_helper::TestTls::generate(&path.with_extension("tls9354"));
    let args = loopback_args("127.0.0.1", &tls);
    let cfg = ai_memory::config::AppConfig {
        api_key: api_key.map(str::to_string),
        ..Default::default()
    };
    let sink = Capture::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::WARN)
        .with_ansi(false)
        .finish();
    let bs = {
        let _default = tracing::subscriber::set_default(subscriber);
        ai_memory::daemon_runtime::bootstrap_serve(&path, &args, &cfg).await
    }
    .unwrap_or_else(|e| panic!("{label}: loopback boot: {e:#}"));
    for h in bs.task_handles {
        h.abort();
    }
    let logs = String::from_utf8_lossy(
        &sink
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
    .to_string();
    let app = ai_memory::daemon_runtime::build_router(bs.app_state, bs.api_key_state);
    (logs, app)
}

/// b3 — ruling 28907a4f: a daemon configured with a blank key starts, with
/// exactly one boot WARN naming the remedy, and its health and monitoring
/// probes answer exactly as on a daemon with no key (an unset key and a real
/// key get no such WARN).
#[tokio::test]
async fn b3_boot_blank_key_warns_with_remedy_and_probes_stay_reachable_9354() {
    // Messages name the case, never the key and never the boot log (a boot log
    // of a keyed daemon is not guaranteed free of configuration values).
    let (unset_logs, unset_app) = boot_capturing("unset", None).await;
    assert!(
        !unset_logs.contains(BLANK_KEY_BOOT_WARN),
        "unset key: no boot WARN expected"
    );
    let (real_logs, _) = boot_capturing("real", Some(REAL_KEY)).await;
    assert!(
        !real_logs.contains(BLANK_KEY_BOOT_WARN),
        "real key: no boot WARN expected"
    );
    for (label, blank) in BLANK_KEYS {
        let (logs, app) = boot_capturing(label, Some(blank)).await;
        assert_eq!(
            logs.matches(BLANK_KEY_BOOT_WARN).count(),
            1,
            "{label}: one boot WARN with the remedy"
        );
        for path in [ai_memory::handlers::routes::HEALTH, STATUS_PATH] {
            for case in HEADER_CASES {
                let header = header_value(case, blank);
                let Some((status, body)) = send(&app, path, header).await else {
                    continue;
                };
                let (unset_status, unset_body) = send(&unset_app, path, header)
                    .await
                    .expect("carried on the unset daemon too");
                // A success body carries live figures; a refusal body is exact.
                assert_eq!(
                    (status, status.is_success() || body == unset_body),
                    (unset_status, true),
                    "{label} {path} {case:?}: a probe must answer as with no key: \
                     {body} vs {unset_body}"
                );
                assert_ne!(body, refusal_body(), "{label} {path} {case:?}");
            }
        }
        let (status, body) = send(&app, ai_memory::handlers::routes::HEALTH, None)
            .await
            .expect("carried");
        assert!(status.is_success(), "{label}: liveness: {status} {body}");
    }
}

/// Blank every comment and string/char literal of Rust source (newlines kept,
/// so line numbers hold). Handles `//`, nested `/* */`, `"..."` with escapes
/// (multi-line too, and the `b"..."` / `c"..."` forms), raw strings
/// `r#"..."#` with their `br` / `cr` forms, char literals (`'\''` included),
/// byte chars and lifetimes.
fn blank_literals_and_comments(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let blank = |ch: char| if ch == '\n' { '\n' } else { ' ' };
    let mut i = 0;
    while i < c.len() {
        let rest_is =
            |at: usize, pat: &str| c[at..].iter().take(pat.len()).collect::<String>() == pat;
        if rest_is(i, "//") {
            while i < c.len() && c[i] != '\n' {
                out.push(' ');
                i += 1;
            }
        } else if rest_is(i, "/*") {
            let mut depth = 0usize;
            while i < c.len() {
                if rest_is(i, "/*") {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if rest_is(i, "*/") {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(c[i]));
                    i += 1;
                }
            }
        } else if c[i] == 'r'
            && (i == 0
                || !is_ident(c[i - 1])
                || (matches!(c[i - 1], 'b' | 'c') && (i < 2 || !is_ident(c[i - 2]))))
            && (rest_is(i, "r\"") || rest_is(i, "r#"))
        {
            let mut j = i + 1;
            let mut hashes = 0usize;
            while j < c.len() && c[j] == '#' {
                hashes += 1;
                j += 1;
            }
            if j < c.len() && c[j] == '"' {
                let end = format!("\"{}", "#".repeat(hashes));
                let mut k = j + 1;
                while k < c.len() && !rest_is(k, &end) {
                    k += 1;
                }
                let stop = (k + end.len()).min(c.len());
                out.extend(c[i..stop].iter().map(|&ch| blank(ch)));
                i = stop;
            } else {
                out.push(c[i]);
                i += 1;
            }
        } else if c[i] == '"' {
            out.push(' ');
            i += 1;
            while i < c.len() && c[i] != '"' {
                if c[i] == '\\' && i + 1 < c.len() {
                    out.push(' ');
                    i += 1;
                }
                out.push(blank(c[i]));
                i += 1;
            }
            out.push(' ');
            i += 1;
        } else if c[i] == '\'' {
            if i + 1 < c.len() && c[i + 1] == '\\' {
                // The escaped char sits at i + 2 (`'\''` escapes a quote),
                // so the closing quote is searched from i + 3.
                let mut k = i + 3;
                while k < c.len() && c[k] != '\'' {
                    k += 1;
                }
                let stop = (k + 1).min(c.len());
                out.extend(c[i..stop].iter().map(|&ch| blank(ch)));
                i = stop;
            } else if i + 2 < c.len() && c[i + 2] == '\'' {
                out.push_str("   ");
                i += 3;
            } else {
                out.push(c[i]);
                i += 1;
            }
        } else {
            out.push(c[i]);
            i += 1;
        }
    }
    out
}

fn is_ident(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

/// The identifier that starts at `at` (not preceded by an ident char), if any.
fn ident_at(c: &[char], at: usize) -> Option<String> {
    let starts = c.get(at).is_some_and(|&ch| is_ident(ch)) && (at == 0 || !is_ident(c[at - 1]));
    starts.then(|| c[at..].iter().take_while(|&&ch| is_ident(ch)).collect())
}

/// Index of the first char at or after `at` that is not whitespace.
fn skip_ws(c: &[char], mut at: usize) -> usize {
    while at < c.len() && c[at].is_whitespace() {
        at += 1;
    }
    at
}

/// Index just past the last char before `end` that is not whitespace.
fn skip_ws_back(c: &[char], mut end: usize) -> usize {
    while end > 0 && c[end - 1].is_whitespace() {
        end -= 1;
    }
    end
}

/// The identifier that ends right before `end` (whitespace skipped), with its
/// start index.
fn ident_before(c: &[char], end: usize) -> Option<(usize, String)> {
    let stop = skip_ws_back(c, end);
    let mut start = stop;
    while start > 0 && is_ident(c[start - 1]) {
        start -= 1;
    }
    (start < stop).then(|| (start, c[start..stop].iter().collect()))
}

/// Index of the bracket that closes the one opened at `open` (`{`, `(` and
/// `[` counted together), or `c.len()` when it never closes.
fn matching_close(c: &[char], open: usize) -> usize {
    let mut depth = 0usize;
    for (at, &ch) in c.iter().enumerate().skip(open) {
        match ch {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return at;
                }
            }
            _ => {}
        }
    }
    c.len()
}

/// Index of the innermost unclosed `{`, `(` or `[` before `at`, if any.
fn enclosing_open(c: &[char], at: usize) -> Option<usize> {
    let mut depth = 0usize;
    for back in (0..at).rev() {
        match c[back] {
            '}' | ')' | ']' => depth += 1,
            '{' | '(' | '[' => match depth.checked_sub(1) {
                Some(outer) => depth = outer,
                None => return Some(back),
            },
            _ => {}
        }
    }
    None
}

/// The statement text before `at` (since the last `;`, `{` or `}`).
fn stmt_prefix(c: &[char], at: usize) -> String {
    let start = c[..at]
        .iter()
        .rposition(|&ch| matches!(ch, ';' | '{' | '}'))
        .map_or(0, |p| p + 1);
    c[start..at].iter().collect()
}

fn has_word(text: &str, word: &str) -> bool {
    text.split(|ch: char| !is_ident(ch)).any(|w| w == word)
}

/// Every name of the guarded type in one source: the type itself, each
/// `use .. T as X` rename and each `type X = T;` / `type X = path::T;` alias.
fn guarded_names(c: &[char], guarded_type: &str) -> Vec<String> {
    let path_suffix = format!("::{guarded_type}");
    let mut names = vec![guarded_type.to_string()];
    for at in 0..c.len() {
        let Some(word) = ident_at(c, at) else {
            continue;
        };
        let after = skip_ws(c, at + word.chars().count());
        if word == guarded_type && ident_at(c, after).as_deref() == Some("as") {
            if let Some(alias) = ident_at(c, skip_ws(c, after + 2)) {
                names.push(alias);
            }
        } else if word == "type" {
            if let Some(alias) = ident_at(c, after) {
                let from = after + alias.chars().count();
                let semi = c[from..]
                    .iter()
                    .position(|&ch| ch == ';')
                    .map_or(c.len(), |p| from + p);
                let rhs: String = c[from..semi]
                    .iter()
                    .filter(|ch| !ch.is_whitespace())
                    .collect();
                if let Some(target) = rhs.strip_prefix('=') {
                    if target == guarded_type || target.ends_with(&path_suffix) {
                        names.push(alias);
                    }
                }
            }
        }
    }
    names
}

/// Bodies `(open, close)` of every `impl` whose self type is a guarded name
/// (`impl T {` and `impl Trait for T {`): inside them `Self` is the type.
fn guarded_impl_bodies(c: &[char], names: &[String]) -> Vec<(usize, usize)> {
    let mut bodies = Vec::new();
    for at in 0..c.len() {
        let Some(word) = ident_at(c, at) else {
            continue;
        };
        let open = skip_ws(c, at + word.chars().count());
        if names.contains(&word)
            && c.get(open) == Some(&'{')
            && has_word(&stmt_prefix(c, at), "impl")
        {
            bodies.push((open, matching_close(c, open)));
        }
    }
    bodies
}

/// Is the item spanning `start..end` a pattern (`Some(true)`), an expression
/// (`Some(false)`), or unknown (`None`), judged by its neighbours? An item
/// with no decisive neighbour inside `( )`, `[ ]` or a `Path { }` takes the
/// verdict of that enclosing item.
fn pattern_position(c: &[char], mut start: usize, mut end: usize) -> Option<bool> {
    loop {
        let next = skip_ws(c, end);
        let after = c.get(next).copied();
        let after2 = c.get(next + 1).copied();
        match after {
            Some('=') if after2 != Some('=') => return Some(true),
            Some(':') if after2 != Some(':') => return Some(true),
            Some('|' | '@') => return Some(true),
            Some(';' | '.' | '?') => return Some(false),
            _ => {}
        }
        if matches!(ident_at(c, next).as_deref(), Some("in" | "if")) {
            return Some(true);
        }
        let mut before = skip_ws_back(c, start);
        loop {
            if before > 0 && c[before - 1] == '&' {
                before = skip_ws_back(c, before - 1);
                continue;
            }
            match ident_before(c, before) {
                Some((at, w)) if w == "mut" || w == "ref" => before = skip_ws_back(c, at),
                _ => break,
            }
        }
        let prev = before.checked_sub(1).map(|at| c[at]);
        let prev2 = before.checked_sub(2).map(|at| c[at]);
        match prev {
            Some('|' | '@') => return Some(true),
            Some('>') if prev2 == Some('=') => return Some(false),
            Some('=') if !matches!(prev2, Some('=' | '!' | '<' | '>')) => return Some(false),
            _ => {}
        }
        match ident_before(c, before).map(|(_, w)| w).as_deref() {
            Some("let" | "for") => return Some(true),
            Some("return") => return Some(false),
            _ => {}
        }
        let open = enclosing_open(c, start)?;
        end = matching_close(c, open) + 1;
        start = match ident_before(c, open) {
            Some((at, _)) => at,
            None if c[open] == '{' => return None,
            None => open,
        };
    }
}

/// 1-based line numbers (of comment/literal-blanked source) that read a field
/// named `key` under ANY binding name, in every syntax: `<expr>.key` and
/// `<expr>.r#key` (whitespace allowed after the dot) not followed by `(` (so a
/// `.key()` method is not a field), and every brace group of the guarded type
/// (the type, a `use .. as` or `type` alias of it, `Self` inside its `impl`)
/// that names `key`, unless it is provably a construction: a functional
/// update `..base`, or an expression position (after a single `=`, `=>` or
/// `return`, before `;`, `.` or `?`, as an argument of such an item). A `..`
/// rest or a pattern position (`let`, `for .. in`, closure and fn parameters,
/// `match` arms and guards, `if let`, `while let`, destructuring assignment,
/// nested in a tuple, slice, tuple-struct or struct pattern) is a read, and a
/// group that is neither is a read too (fail closed). The struct declaration,
/// an `impl` header and a `-> T {` fn body are not groups of the type.
fn key_field_read_lines(blanked: &str, guarded_type: &str) -> Vec<usize> {
    let c: Vec<char> = blanked.chars().collect();
    let line_of = |at: usize| c[..at].iter().filter(|&&ch| ch == '\n').count() + 1;
    let names = guarded_names(&c, guarded_type);
    let impl_bodies = guarded_impl_bodies(&c, &names);
    let mut lines = Vec::new();
    for i in 0..c.len() {
        if c[i] == '.' && (i == 0 || c[i - 1] != '.') && c.get(i + 1) != Some(&'.') {
            let mut k = skip_ws(&c, i + 1);
            if c.get(k) == Some(&'r') && c.get(k + 1) == Some(&'#') {
                k += 2;
            }
            if c[k..].starts_with(&['k', 'e', 'y'])
                && c.get(k + 3).is_none_or(|&ch| !is_ident(ch))
                && c.get(skip_ws(&c, k + 3)) != Some(&'(')
            {
                lines.push(line_of(i));
            }
        }
        let Some(word) = ident_at(&c, i) else {
            continue;
        };
        let guarded = names.contains(&word)
            || (word == "Self"
                && impl_bodies
                    .iter()
                    .any(|&(open, close)| open < i && i < close));
        let open = skip_ws(&c, i + word.chars().count());
        if !guarded || c.get(open) != Some(&'{') {
            continue;
        }
        let before = skip_ws_back(&c, i);
        let return_type = before >= 2 && c[before - 2] == '-' && c[before - 1] == '>';
        let prefix = stmt_prefix(&c, i);
        if return_type
            || ["impl", "struct", "enum", "union"]
                .iter()
                .any(|w| has_word(&prefix, w))
        {
            continue;
        }
        let close = matching_close(&c, open);
        let mut depth = 0usize;
        let (mut names_key, mut rest, mut update) = (false, false, false);
        for at in open..close {
            match c[at] {
                '{' | '(' | '[' => depth += 1,
                '}' | ')' | ']' => depth = depth.saturating_sub(1),
                _ => {}
            }
            if depth != 1 {
                continue;
            }
            names_key |= ident_at(&c, at).as_deref() == Some("key");
            let lead = c[..skip_ws_back(&c, at)].last().copied();
            if c[at..].starts_with(&['.', '.']) && matches!(lead, Some(',' | '{')) {
                if c.get(skip_ws(&c, at + 2)) == Some(&'}') {
                    rest = true;
                } else {
                    update = true;
                }
            }
        }
        let read =
            names_key && (rest || (!update && pattern_position(&c, i, close + 1) != Some(false)));
        if read {
            lines.push(line_of(i));
        }
    }
    lines.dedup();
    lines
}

/// s1b — the s1 scanner finds what it must (alias bindings, multi-line chains,
/// comparisons, every destructuring form in `SCANNER_FORM_CELLS`, a group it
/// cannot classify) and nothing else (strings and chars of every literal form,
/// comments, construction, the declaration, an `impl` header, a `.key()`
/// method).
#[test]
fn s1b_key_field_scanner_self_test_9354() {
    let hits = |src: &str| key_field_read_lines(&blank_literals_and_comments(src), KEY_STATE_TYPE);
    assert_eq!(
        hits("let a = &state.auth;\ntoken.zip(a.key.as_deref());"),
        vec![2]
    );
    assert_eq!(hits("let k = s\n    .key\n    .clone();"), vec![2]);
    assert_eq!(hits("if x.key == y {}"), vec![1]);
    assert_eq!(hits("let ApiKeyState { key, .. } = s;"), vec![1]);
    assert_eq!(
        hits("match s {\n ApiKeyState { key: k, .. } => k,\n}"),
        vec![2]
    );
    assert_eq!(
        hits("fn f(ApiKeyState { key, .. }: ApiKeyState) {}"),
        vec![1]
    );
    assert_eq!(
        hits("let r#\"a.key.b\"#; // z.key.c\n/* y.key.d */ \"x.key.e\";"),
        Vec::<usize>::new()
    );
    assert_eq!(
        hits("let s = ApiKeyState { key: None, ..Default::default() };"),
        Vec::<usize>::new()
    );
    assert_eq!(hits("let k = t.key();"), Vec::<usize>::new());
    assert_eq!(hits("let r = 0..key;"), Vec::<usize>::new());
    assert_eq!(hits("let c = '\\''; let l: &'a str = s.key;"), vec![1]);
    let wrong: Vec<String> = SCANNER_FORM_CELLS
        .iter()
        .filter_map(|&(name, src, want)| {
            let got = hits(src);
            (got != want).then(|| format!("{name}: want {want:?} got {got:?}"))
        })
        .collect();
    assert_eq!(SCANNER_FORM_CELLS.len(), SCANNER_FORM_CELLS_COUNT);
    assert!(
        wrong.is_empty(),
        "s1b scanner cells wrong:\n{}",
        wrong.join("\n")
    );
}

/// Number of s1b syntax-form cells (asserted in s1b).
const SCANNER_FORM_CELLS_COUNT: usize = 34;
/// s1b syntax-form cells (name, synthetic source, 1-based lines that must be
/// reported). Every syntax that binds or reads the `key` field of the guarded
/// type is a read; a construction, the struct declaration and an `impl` body
/// are not; a brace group of the guarded type that names `key` and is neither
/// provably a pattern nor provably a construction is a read (fail closed).
/// The literal cells hide a `.key` in each Rust string / char form and put a
/// real read after it, so a lexer that misreads the literal loses the read.
const SCANNER_FORM_CELLS: [(&str, &str, &[usize]); SCANNER_FORM_CELLS_COUNT] = [
    (
        "self-destructure-in-impl",
        "impl ApiKeyState {\n fn raw(&self) -> Option<&str> {\n  let Self { key, .. } = self;\n  key.as_deref()\n }\n}",
        &[3],
    ),
    (
        "self-closure-in-impl",
        "impl ApiKeyState {\n fn f(v: Vec<Self>) { v.into_iter().map(|Self { key, .. }| key); }\n}",
        &[2],
    ),
    (
        "self-in-trait-impl",
        "impl Drop for ApiKeyState {\n fn drop(&mut self) { let Self { key, .. } = self; }\n}",
        &[2],
    ),
    (
        "self-match-arm-in-impl",
        "impl ApiKeyState {\n fn f(&self) -> bool {\n  match self {\n   Self { key: Some(_), .. } => true,\n   _ => false,\n  }\n }\n}",
        &[4],
    ),
    (
        "closure-param",
        "let k = Some(s).map(|ApiKeyState { key, .. }| key);",
        &[1],
    ),
    (
        "closure-param-ref",
        "xs.iter().map(|&ApiKeyState { ref key, .. }| key);",
        &[1],
    ),
    (
        "for-pattern",
        "for ApiKeyState { key, .. } in states {}",
        &[1],
    ),
    (
        "for-tuple-pattern",
        "for (ApiKeyState { key, .. }, n) in pairs {}",
        &[1],
    ),
    (
        "match-arm-wrapped",
        "match o {\n Some(ApiKeyState { key, .. }) => key,\n None => None,\n}",
        &[2],
    ),
    (
        "match-arm-guard",
        "match s {\n ApiKeyState { key, .. } if flag => 1,\n _ => 0,\n}",
        &[2],
    ),
    (
        "if-let",
        "if let Some(ApiKeyState { key, .. }) = o {}",
        &[1],
    ),
    (
        "while-let",
        "while let Some(ApiKeyState { key, .. }) = it.next() {}",
        &[1],
    ),
    (
        "fn-param-tuple",
        "fn f((ApiKeyState { key, .. }, n): (ApiKeyState, u8)) {}",
        &[1],
    ),
    (
        "renamed-binding",
        "let ApiKeyState { key: k, .. } = s;",
        &[1],
    ),
    (
        "nested-binding",
        "let Outer { inner: ApiKeyState { key, .. }, .. } = o;",
        &[1],
    ),
    (
        "tuple-struct-wrapping",
        "let Wrap(ApiKeyState { key, .. }) = w;",
        &[1],
    ),
    (
        "all-fields-pattern",
        "let ApiKeyState { key, mtls_enforced, enrolled_agent_keys, identity_mode, auth_backoff } = s;",
        &[1],
    ),
    (
        "destructuring-assignment",
        "ApiKeyState { key, .. } = s;",
        &[1],
    ),
    (
        "alias-use-as",
        "use crate::handlers::ApiKeyState as Aks;\nfn f(s: Aks) { let Aks { key, .. } = s; }",
        &[2],
    ),
    (
        "alias-type",
        "type Aks = crate::handlers::ApiKeyState;\nfn f(s: Aks) { let Aks { key, .. } = s; }",
        &[2],
    ),
    (
        "unclassified-group-fails-closed",
        "ApiKeyState { key: k, mtls_enforced: m }",
        &[1],
    ),
    ("raw-ident-field", "let k = s.r#key.clone();", &[1]),
    (
        "raw-ident-pattern",
        "let ApiKeyState { r#key, .. } = s;",
        &[1],
    ),
    ("dot-then-newline", "let k = s.\n    key.clone();", &[1]),
    ("dot-then-space", "let k = s . key;", &[1]),
    ("byte-raw-string", "let a = br\"\\\";\nlet k = s.key;", &[2]),
    (
        "byte-raw-hash-string",
        "let a = br#\"a \" b.key\"#;\nlet k = s.key;",
        &[2],
    ),
    ("c-raw-string", "let a = cr\"\\\";\nlet k = s.key;", &[2]),
    (
        "byte-string-escape",
        "let a = b\"\\\".key\";\nlet k = s.key;",
        &[2],
    ),
    ("c-string", "let a = c\"x.key\";\nlet k = s.key;", &[2]),
    (
        "char-escaped-quote",
        "let q = ['\\'','\"'];\nlet k = s.key;",
        &[2],
    ),
    ("byte-char-quote", "let q = b'\"';\nlet k = s.key;", &[2]),
    (
        "self-of-other-impl-is-not-guarded",
        "impl Other {\n fn f(s: Self) { let Self { key, .. } = s; }\n}",
        &[],
    ),
    (
        "declaration-impl-and-constructions",
        "pub struct ApiKeyState {\n pub key: Option<String>,\n}\nimpl ApiKeyState {\n fn new(key: Option<String>) -> Self { Self { key, ..Default::default() } }\n}\nlet s = ApiKeyState { key: Some(k), mtls_enforced: m, enrolled_agent_keys: e, identity_mode: i, auth_backoff: b };\nlet t = ApiKeyState { key: None, ..Default::default() };\nf(ApiKeyState { key: k, mtls_enforced: m });\nlet n = Some(ApiKeyState { key: k, mtls_enforced: m })?;",
        &[],
    ),
];

/// Every read of a `key` field in `src/**/*.rs`, transport.rs included, as
/// `relative/path: trimmed original line` (comments and literals blanked
/// before matching, the original line quoted).
fn key_field_reads_in_src() -> Vec<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut stack = vec![root.join(SRC_DIR)];
    let mut reads = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let source = std::fs::read_to_string(&path).expect("read source");
                let rel = path
                    .strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let originals: Vec<&str> = source.lines().collect();
                for line in
                    key_field_read_lines(&blank_literals_and_comments(&source), KEY_STATE_TYPE)
                {
                    reads.push(format!("{rel}: {}", originals[line - 1].trim()));
                }
            }
        }
    }
    reads.sort();
    reads
}

/// s1 — structural ratchet over the whole of `src/`: the set of reads of a
/// field named `key` (any binding name, transport.rs included) is exactly
/// `ALLOWED_KEY_FIELD_READS`; a new raw read of `ApiKeyState::key` fails here
/// until it is admitted by name, so a compare can only go through
/// `ApiKeyState::configured_key`.
#[test]
fn s1_no_raw_shared_key_read_outside_allowlist_9354() {
    let found = key_field_reads_in_src();
    let mut allowed: Vec<String> = ALLOWED_KEY_FIELD_READS
        .iter()
        .map(|(file, line, _why)| format!("{file}: {line}"))
        .collect();
    allowed.sort();
    let unlisted: Vec<&String> = found.iter().filter(|f| !allowed.contains(f)).collect();
    let stale: Vec<&String> = allowed.iter().filter(|a| !found.contains(a)).collect();
    assert!(
        unlisted.is_empty() && stale.is_empty(),
        "key field reads not in the allowlist:\n{}\nallowlist entries with no read:\n{}",
        unlisted
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        stale
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
    );
    assert_eq!(found.len(), ALLOWED_KEY_FIELD_READS_COUNT);
    assert_eq!(found, allowed, "exact multiset of key field reads");
}

/// Every unset-key request: entries x postures x headers.
const UNSET_HEADERS: [HeaderCase; 3] = [HeaderCase::Absent, HeaderCase::Empty, HeaderCase::Space];
/// A header no configured key could equal.
const UNSET_GARBAGE: &[u8] = b"garbage-9354";
const ENTRIES: [Entry; 4] = [
    Entry::LibBuildRouter,
    Entry::LibBuildRouterWithTimeout,
    Entry::DaemonBuildRouter,
    Entry::Middleware,
];

/// c7 — no key setting at all behaves exactly as before in every identity
/// mode: for each entry the (status, body) is identical in Off, Advisory and
/// Enforce, enrolled or not, for every header, and equals the entry's no-auth
/// baseline (Off, no header); the bare middleware is exactly `200 "ok"`'s
/// pass-through. Never the refusal.
#[tokio::test]
async fn c7_unset_key_behaves_as_before_in_every_mode_9354() {
    let mut off_contract = Vec::new();
    let mut carried = 0usize;
    for entry in ENTRIES {
        let baseline_posture = Posture {
            mode: HttpIdentityMode::Off,
            enrolled: false,
        };
        let baseline_app = router(entry, None, baseline_posture);
        let baseline = send(&baseline_app, READ_ROUTE, None)
            .await
            .expect("carried");
        assert!(
            admitted(baseline.0, &baseline.1) && baseline.1 != refusal_body(),
            "{entry:?}: the unset-key baseline must pass through: {} {}",
            baseline.0,
            baseline.1
        );
        if matches!(entry, Entry::Middleware) {
            assert_eq!(
                baseline.0,
                StatusCode::OK,
                "bare middleware pass-through status"
            );
        }
        for posture in postures() {
            let app = router(entry, None, posture);
            let garbage = [UNSET_GARBAGE];
            let headers = UNSET_HEADERS
                .iter()
                .map(|case| header_value(*case, ""))
                .chain(garbage.iter().map(|g| Some(*g)));
            for header in headers {
                let (status, body) = send(&app, READ_ROUTE, header).await.expect("carried");
                carried += 1;
                if (status, &body) != (baseline.0, &baseline.1) {
                    off_contract.push(format!(
                        "{entry:?} {posture:?} header={}: {status} {body}",
                        header.map_or(0, <[u8]>::len)
                    ));
                }
            }
        }
    }
    assert_eq!(
        carried, UNSET_EXPECTED_REQUESTS,
        "every unset-key request is carried"
    );
    assert!(
        off_contract.is_empty(),
        "unset key: {} of {carried} requests differ from the no-auth baseline:\n{}",
        off_contract.len(),
        off_contract.join("\n")
    );
}
/// 4 entries x 6 postures x 4 headers (absent, empty, space, garbage).
const UNSET_EXPECTED_REQUESTS: usize = 96;
