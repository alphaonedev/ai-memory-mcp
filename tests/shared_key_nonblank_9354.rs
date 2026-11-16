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
//! Blank corpus: `str::trim` strips Unicode `White_Space`, so U+00A0 (NBSP) is
//! blank too (pinned in p5).
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
const BLANK_KEYS: [(&str, &str); 5] = [
    ("empty", ""),
    ("space", " "),
    ("tab", "\t"),
    ("space-newline-space", " \n "),
    ("nbsp", "\u{00a0}"),
];
/// U+00A0 NO-BREAK SPACE, Unicode `White_Space`.
const NBSP: &str = "\u{00a0}";
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
/// Literal the structural cell (s1) forbids outside the transport module:
/// a read of the raw constructor-facing `ApiKeyState::key` field.
const RAW_KEY_READ: &str = "auth.key.";
const TRANSPORT_SOURCE: &str = "src/handlers/transport.rs";
const SRC_DIR: &str = "src";

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
/// as today (no trimming of a non-blank key).
#[tokio::test]
async fn p2_padded_real_key_is_compared_verbatim_9354() {
    for posture in postures() {
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

/// p5 — pin the blank corpus: `str::trim` strips NBSP (Unicode `White_Space`),
/// NBSP rides in a header but is not a visible-ASCII token, and LF cannot be
/// carried at all.
#[test]
fn p5_blank_corpus_pins_9354() {
    for (label, blank) in BLANK_KEYS {
        assert!(blank.trim().is_empty(), "{label} must be blank after trim");
    }
    assert!(NBSP.trim().is_empty(), "str::trim strips U+00A0");
    let nbsp = HeaderValue::from_bytes(NBSP.as_bytes()).expect("NBSP bytes ride in a header");
    assert!(nbsp.to_str().is_err(), "NBSP is not a visible-ASCII token");
    assert!(
        HeaderValue::from_bytes(SPACE_NEWLINE_SPACE).is_err(),
        "LF cannot be carried in a header"
    );
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
        assert_eq!(bs.api_key_state.key.as_deref(), expected, "{label}");
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
async fn boot_capturing(api_key: Option<&str>) -> (String, axum::Router) {
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
    .unwrap_or_else(|e| panic!("{api_key:?}: loopback boot: {e:#}"));
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
    let (unset_logs, unset_app) = boot_capturing(None).await;
    assert!(
        !unset_logs.contains(BLANK_KEY_BOOT_WARN),
        "unset key: {unset_logs}"
    );
    let (real_logs, _) = boot_capturing(Some(REAL_KEY)).await;
    assert!(
        !real_logs.contains(BLANK_KEY_BOOT_WARN),
        "real key: {real_logs}"
    );
    for (label, blank) in BLANK_KEYS {
        let (logs, app) = boot_capturing(Some(blank)).await;
        assert_eq!(
            logs.matches(BLANK_KEY_BOOT_WARN).count(),
            1,
            "{label}: one boot WARN with the remedy: {logs}"
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

/// s1 — structural ratchet: outside the transport module no source reads the
/// raw constructor-facing `ApiKeyState::key` string to authenticate; every
/// shared-key read goes through the typed constructor there.
#[test]
fn s1_no_raw_shared_key_read_outside_transport_9354() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let transport = root.join(TRANSPORT_SOURCE);
    let mut stack = vec![root.join(SRC_DIR)];
    let mut hits = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read src dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") && path != transport {
                let source = std::fs::read_to_string(&path).expect("read source");
                for (i, line) in source.lines().enumerate() {
                    if line.contains(RAW_KEY_READ) {
                        hits.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                    }
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "raw shared-key reads:\n{}",
        hits.join("\n")
    );
}
