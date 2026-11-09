// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Full SQLite dispatch against an isolated, verifying TLS receiver (#6401).

use super::super::*;
use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, Uri},
};
use axum_server::accept::Accept;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

const CHILD_ROLE: &str = "AI_MEMORY_TEST_TLS_6401_CHILD";
const CHILD_SCRATCH: &str = "AI_MEMORY_TEST_TLS_8649_SCRATCH";
const CHILD_TIMEOUT: Duration = Duration::from_secs(120);
const CHILD_POLL: Duration = Duration::from_millis(20);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(60);
const SERVER_TIMEOUT: Duration = Duration::from_secs(5);
const TEST_SECRET: &str = "tls-6401-test-secret";
const WRONG_PORT_URL: &str = "https://localhost:80/hook";
const PORT_MISMATCH: &str = "tls-test-port-mismatch";
static RECEIVER_PORT: AtomicU16 = AtomicU16::new(0);

struct ChildProcess(std::process::Child);

impl Drop for ChildProcess {
    fn drop(&mut self) {
        // Reap before the parent TempDir drops, including polling/assertion panics.
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            // Best effort on unwind; never cause a second panic in Drop.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Only the isolated child remaps the logical HTTPS pin to its owned socket.
/// A wrong logical port fails before any connection to a host service.
pub(crate) fn map_receiver(
    host: &str,
    addresses: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, String> {
    let port = RECEIVER_PORT.load(Ordering::Acquire);
    if port == 0 {
        return Ok(addresses);
    }
    assert_eq!(
        host, "localhost",
        "only the isolated receiver host is mapped"
    );
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| address.port() != super::HTTPS_PORT)
    {
        return Err(PORT_MISMATCH.to_string());
    }
    Ok(vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)])
}

fn run_child(name: &str) {
    let scratch = tempfile::tempdir_in(std::env::temp_dir()).expect("child scratch");
    let scratch_path = scratch.path().to_path_buf();
    run_child_in(name, scratch);
    assert!(!scratch_path.exists(), "child PKI scratch must be removed");
}

fn run_child_in(name: &str, scratch: tempfile::TempDir) {
    let stdout_path = scratch.path().join("stdout");
    let stderr_path = scratch.path().join("stderr");
    let module = module_path!().split_once("::").expect("crate module").1;
    let filter = format!("{module}::{name}");
    let mut command = crate::spawn_audit::audited_command(
        std::env::current_exe().expect("current lib test binary"),
        "webhook_tls_8203_tests::run_child",
    );
    command
        .args(["--exact", &filter, "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("AI_MEMORY_NO_CONFIG", "1")
        // The parent owns this Drop guard: child process statics do not drop.
        .env("TMPDIR", scratch.path())
        .env(CHILD_SCRATCH, scratch.path())
        .env(CHILD_ROLE, "1")
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|v| ("LLVM_PROFILE_FILE", v)))
        .stdout(std::fs::File::create(&stdout_path).expect("child stdout"))
        .stderr(std::fs::File::create(&stderr_path).expect("child stderr"));
    let mut child = ChildProcess(command.spawn().expect("spawn isolated TLS test"));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("poll TLS child") {
            break status;
        }
        if started.elapsed() >= CHILD_TIMEOUT {
            child.0.kill().expect("kill timed-out child");
            child.0.wait().expect("reap timed-out child");
            panic!("#6401: isolated TLS child exceeded {CHILD_TIMEOUT:?}");
        }
        std::thread::sleep(CHILD_POLL);
    };
    let stdout = std::fs::read_to_string(stdout_path).expect("read child stdout");
    let stderr = std::fs::read_to_string(stderr_path).expect("read child stderr");
    assert!(
        status.success(),
        "#6401: child {filter}:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("1 passed") && !stdout.contains("0 passed"),
        "child must run one test: {stdout}"
    );
}

struct Received {
    method: Method,
    path: String,
    headers: HeaderMap,
    body: Bytes,
}

async fn receive(
    State(sender): State<UnboundedSender<Received>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Json<serde_json::Value> {
    let correlation = headers["x-ai-memory-correlation-id"]
        .to_str()
        .expect("correlation header")
        .to_string();
    sender
        .send(Received {
            method,
            path: uri.path().to_string(),
            headers,
            body,
        })
        .expect("record request");
    Json(serde_json::json!({"status": "ack", "correlation_id": correlation}))
}

struct Receiver {
    requests: UnboundedReceiver<Received>,
    handshake_failures: UnboundedReceiver<Option<rustls::Error>>,
    handle: axum_server::Handle<SocketAddr>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

/// Observe the real server handshake without changing certificate verification.
#[derive(Clone)]
struct RecordingAcceptor<A> {
    inner: A,
    failures: UnboundedSender<Option<rustls::Error>>,
}

impl<I, S, A> Accept<I, S> for RecordingAcceptor<A>
where
    A: Accept<I, S>,
    A::Future: Send + 'static,
{
    type Stream = A::Stream;
    type Service = A::Service;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<(A::Stream, A::Service)>> + Send>,
    >;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let accepted = self.inner.accept(stream, service);
        let failures = self.failures.clone();
        Box::pin(async move {
            accepted.await.inspect_err(|error| {
                failures
                    .send(
                        error
                            .get_ref()
                            .and_then(|cause| cause.downcast_ref::<rustls::Error>())
                            .cloned(),
                    )
                    .expect("record receiver handshake failure");
            })
        })
    }
}

#[derive(Clone, Copy)]
enum ReceiverTrust {
    Trusted,
    Untrusted,
}

impl Receiver {
    async fn start(trust: ReceiverTrust) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = crate::test_support::tls_test_pki();
        if matches!(trust, ReceiverTrust::Trusted) {
            install_dispatch_root_certificate(&std::fs::read(&pki.ca_pem).expect("test CA"))
                .expect("trust existing test CA");
        } else {
            assert!(
                dispatch_root_certificate().is_none(),
                "isolated trust store"
            );
        }
        let config = crate::tls::load_rustls_config(&pki.leaf_pem, &pki.leaf_key_pem)
            .await
            .expect("test TLS config");
        let (failures, handshake_failures) = unbounded_channel();
        let acceptor = RecordingAcceptor {
            inner: crate::tls::serve_rustls_acceptor(&config),
            failures,
        };
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("ephemeral loopback listener");
        listener.set_nonblocking(true).expect("async listener");
        RECEIVER_PORT.store(
            listener.local_addr().expect("listener address").port(),
            Ordering::Release,
        );
        let (sender, requests) = unbounded_channel();
        let app = axum::Router::new().fallback(receive).with_state(sender);
        let handle = axum_server::Handle::new();
        let server = axum_server::from_tcp(listener)
            .expect("adopt listener")
            .acceptor(acceptor)
            .handle(handle.clone());
        let task = tokio::spawn(server.serve(app.into_make_service()));
        Self {
            requests,
            handshake_failures,
            handle,
            task,
        }
    }

    async fn stop(self) {
        self.handle.graceful_shutdown(Some(SERVER_TIMEOUT));
        tokio::time::timeout(SERVER_TIMEOUT, self.task)
            .await
            .expect("server shutdown deadline")
            .expect("join receiver")
            .expect("receiver exit");
        RECEIVER_PORT.store(0, Ordering::Release);
    }
}

fn register(conn: &Connection, url: &str) -> String {
    insert(
        conn,
        &NewSubscription {
            url,
            events: crate::mcp::registry::tool_names::MEMORY_STORE,
            secret: Some(TEST_SECRET),
            namespace_filter: None,
            agent_filter: None,
            created_by: None,
            event_types: None,
        },
    )
    .expect("register subscription")
}

async fn dispatch(conn: &Connection, path: &std::path::Path) {
    dispatch_event(
        conn,
        crate::mcp::registry::tool_names::MEMORY_STORE,
        "tls-memory",
        "tls-namespace",
        None,
        path,
    );
    tokio::time::timeout(DRAIN_TIMEOUT, wait_dispatch_idle())
        .await
        .expect("dispatch must drain");
}

fn verify_signature(request: &Received) {
    use hmac::{Hmac, Mac as _};
    let timestamp = request.headers[crate::HEADER_AI_MEMORY_TIMESTAMP]
        .to_str()
        .expect("timestamp");
    let header = request.headers[crate::HEADER_AI_MEMORY_SIGNATURE]
        .to_str()
        .expect("signature");
    let signature = hex_decode(header.strip_prefix("sha256=").expect("signature algorithm"))
        .expect("hex signature");
    let mut mac = Hmac::<Sha256>::new_from_slice(&Sha256::digest(TEST_SECRET)).expect("HMAC key");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(&request.body);
    mac.verify_slice(&signature)
        .expect("signature verifies with test secret and raw body");
}

async fn check_delivery() {
    let mut receiver = Receiver::start(ReceiverTrust::Trusted).await;
    let file = tempfile::NamedTempFile::new_in(std::env::temp_dir()).expect("SQLite fixture");
    let conn = crate::db::open(file.path()).expect("production SQLite schema");
    let id = register(&conn, super::IMPLICIT_URL);
    dispatch(&conn, file.path()).await;
    let request = receiver
        .requests
        .try_recv()
        .expect("#6401: implicit HTTPS must deliver one signed POST");
    assert_eq!(request.method, Method::POST);
    assert_eq!(request.path, "/hook");
    verify_signature(&request);
    assert!(
        receiver.requests.try_recv().is_err(),
        "exactly one POST after drain"
    );
    let rows: Vec<(String, String, String)> = conn.prepare(
        "SELECT correlation_id, payload, delivery_status FROM subscription_events WHERE subscription_id = ?1"
    ).expect("audit query").query_map(params![id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("audit rows").collect::<rusqlite::Result<_>>().expect("decode audit");
    assert_eq!(rows.len(), 1, "exactly one durable audit row");
    assert_eq!(
        rows[0].0,
        request.headers["x-ai-memory-correlation-id"]
            .to_str()
            .expect("correlation")
    );
    assert_eq!(rows[0].1.as_bytes(), request.body.as_ref());
    assert_eq!(rows[0].2, "ack");
    assert!(
        list_dlq(&conn, None).expect("DLQ query").is_empty(),
        "successful dispatch has no DLQ row"
    );
    let counters: (i64, i64) = conn
        .query_row(
            "SELECT dispatch_count, failure_count FROM subscriptions WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("dispatch counters");
    assert_eq!(counters, (1, 0));
    receiver.stop().await;
}

async fn check_wrong_port() {
    let mut receiver = Receiver::start(ReceiverTrust::Trusted).await;
    let file = tempfile::NamedTempFile::new_in(std::env::temp_dir()).expect("SQLite fixture");
    let conn = crate::db::open(file.path()).expect("production SQLite schema");
    let id = register(&conn, WRONG_PORT_URL);
    dispatch(&conn, file.path()).await;
    assert!(
        receiver.requests.try_recv().is_err(),
        "port 80 must never reach TLS receiver"
    );
    let rows = list_dlq(&conn, Some(&id)).expect("DLQ query");
    assert_eq!(rows.len(), 1, "wrong port must dead-letter");
    assert_eq!(rows[0].last_error, PORT_MISMATCH);
    let status: String = conn
        .query_row(
            "SELECT delivery_status FROM subscription_events WHERE subscription_id = ?1",
            params![id],
            |row| row.get(0),
        )
        .expect("audit status");
    assert_eq!(status, "failed");
    let counters: (i64, i64) = conn
        .query_row(
            "SELECT dispatch_count, failure_count FROM subscriptions WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("dispatch counters");
    assert_eq!(counters, (1, 1));
    receiver.stop().await;
}

async fn check_untrusted_ca() {
    let mut receiver = Receiver::start(ReceiverTrust::Untrusted).await;
    let file = tempfile::NamedTempFile::new_in(std::env::temp_dir()).expect("SQLite fixture");
    let conn = crate::db::open(file.path()).expect("production SQLite schema");
    let id = register(&conn, super::IMPLICIT_URL);
    dispatch(&conn, file.path()).await;
    // The client verifies the server certificate. The server observes the
    // client's UnknownCA alert; this is not a server-side client-cert check.
    let failure = tokio::time::timeout(SERVER_TIMEOUT, receiver.handshake_failures.recv())
        .await
        .expect("receiver must observe certificate rejection within the deadline")
        .expect("receiver handshake evidence channel must remain open");
    assert_eq!(
        failure,
        Some(rustls::Error::AlertReceived(
            rustls::AlertDescription::UnknownCA
        )),
        "#8649: the same receiver must observe the client's unknown-CA TLS alert"
    );
    assert_eq!(
        receiver.requests.len(),
        0,
        "#8649: untrusted certificate must yield exactly zero accepted HTTP requests"
    );
    let rows = list_dlq(&conn, Some(&id)).expect("DLQ query");
    assert_eq!(rows.len(), 1, "untrusted certificate must dead-letter");
    assert_eq!(
        rows[0].last_error, "network: connect",
        "#8649 ruling B: TLS refusal preserves the exact sanitized DLQ vocabulary"
    );
    for forbidden in [
        super::IMPLICIT_URL,
        "https://",
        "localhost",
        "443",
        "?",
        "@",
        "/hook",
    ] {
        assert!(
            !rows[0].last_error.contains(forbidden),
            "#8649: sanitized TLS refusal must contain no URL, host, port, query or userinfo"
        );
    }
    let status: String = conn
        .query_row(
            "SELECT delivery_status FROM subscription_events WHERE subscription_id = ?1",
            params![id],
            |row| row.get(0),
        )
        .expect("audit status");
    assert_eq!(status, "failed");
    let counters: (i64, i64) = conn
        .query_row(
            "SELECT dispatch_count, failure_count FROM subscriptions WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("dispatch counters");
    assert_eq!(counters, (1, 1));
    receiver.stop().await;
}

fn runtime() -> tokio::runtime::Runtime {
    crate::config::set_allow_loopback_webhooks(true);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("TLS runtime")
}

#[test]
fn registered_implicit_https_delivery_is_signed_and_audited_6401() {
    if std::env::var_os(CHILD_ROLE).is_none() {
        run_child("registered_implicit_https_delivery_is_signed_and_audited_6401");
        return;
    }
    runtime().block_on(check_delivery());
}

#[test]
fn port_80_control_dead_letters_without_receiver_request_6401() {
    if std::env::var_os(CHILD_ROLE).is_none() {
        run_child("port_80_control_dead_letters_without_receiver_request_6401");
        return;
    }
    runtime().block_on(check_wrong_port());
}

#[test]
fn untrusted_ca_dead_letters_without_receiver_request_8649() {
    if std::env::var_os(CHILD_ROLE).is_none() {
        run_child("untrusted_ca_dead_letters_without_receiver_request_8649");
        return;
    }
    runtime().block_on(check_untrusted_ca());
}

#[test]
fn child_pki_is_removed_after_panic_8649() {
    const EXPECTED_PANIC: &str = "#8649 intentional child panic after PKI creation";
    if std::env::var_os(CHILD_ROLE).is_some() {
        let pki = crate::test_support::tls_test_pki();
        let scratch = std::env::var_os(CHILD_SCRATCH).expect("parent-owned child scratch");
        assert!(
            pki.leaf_key_pem.starts_with(std::path::Path::new(&scratch)),
            "child PKI must live beneath the parent Drop guard"
        );
        assert!(pki.leaf_key_pem.is_file(), "PKI exists before panic");
        panic!("{EXPECTED_PANIC}");
    }
    let scratch = tempfile::tempdir_in(std::env::temp_dir()).expect("panic child scratch");
    let scratch_path = scratch.path().to_path_buf();
    let failure = std::panic::catch_unwind(|| {
        run_child_in("child_pki_is_removed_after_panic_8649", scratch);
    })
    .expect_err("child failure must propagate");
    let message = failure
        .downcast_ref::<String>()
        .expect("child panic message");
    assert!(message.contains(EXPECTED_PANIC), "{message}");
    assert!(
        !scratch_path.exists(),
        "panic must remove child PKI scratch"
    );
}
