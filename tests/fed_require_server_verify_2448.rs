// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2448 (R-203) — outbound federation TLS must verify the peer's SERVER
//! certificate.
//!
//! ## The defect
//!
//! Federation replicates **plaintext** memory content (NOT end-to-end
//! encrypted — `src/encryption/mod.rs`, #1968). Before this fix, a single CLI
//! flag (`--insecure-skip-server-verify`) was enough to make the sync daemon
//! accept **any** peer server certificate, so an adversary in DNS or BGP
//! position could present a self-signed cert, complete the handshake, and
//! receive every memory this node pushes. The compensating control the
//! accept-any posture leaned on — the peer fingerprint-pinning OUR client cert
//! via `--mtls-allowlist` — protects the PEER from an impostor CLIENT; it does
//! not protect US from an impostor SERVER.
//!
//! ## R-203 evidence contract
//!
//! [`insecure_skip_server_verify_is_refused_by_default_2448`] is the
//! fail-at-parent / pass-after regression pin. It drives the **production**
//! entry point `cli::sync::run_daemon` — whose signature is unchanged by this
//! fix, so the test compiles at BOTH commits:
//!
//! - **At parent `47939793`:** `run_daemon` accepts the insecure posture and
//!   enters its infinite sync loop → the `timeout` elapses → the assertion
//!   that it refused FAILS.
//! - **After the fix:** `run_daemon` returns `Err` naming #2448 before the
//!   loop → PASSES.
//!
//! The sibling tests stand up a real self-signed TLS server and drive real
//! rustls handshakes, proving (a) the refused disposition genuinely WAS a
//! forged-certificate acceptance, and (b) the secure default genuinely
//! rejects that same certificate.

use ai_memory::cli::sync::{SyncDaemonArgs, build_sync_client, run_daemon};
use ai_memory::tls;
use axum::routing::get;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Serialises the process-wide `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY`
/// mutations. `env::set_var` / `remove_var` are process-global; the crate's
/// own `tls::fed_pin_env_lock` is `pub(crate)` and therefore unreachable from
/// an integration-test crate, so this file owns its own lock. Integration
/// test files are separate binaries, so a cross-file race is impossible.
///
/// A `tokio::sync::Mutex` (not `std::sync`) because every holder awaits while
/// holding it — a std guard across an await point is the
/// `clippy::await_holding_lock` hazard. Tokio mutexes are not poisoned, so no
/// poison-tolerance shim is needed.
async fn verify_env_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

/// Args for a sync daemon pointed at `peer_url`, carrying the committed
/// fixture cert/key as the mTLS client identity (the pre-existing gate:
/// `--insecure-skip-server-verify` is refused outright without both).
fn args_for(peer_url: &str, insecure: bool) -> SyncDaemonArgs {
    SyncDaemonArgs {
        peers: vec![peer_url.to_string()],
        interval: 1,
        api_key: None,
        batch_size: 10,
        client_cert: Some(fixture("valid_cert.pem")),
        client_key: Some(fixture("valid_key_pkcs8.pem")),
        insecure_skip_server_verify: insecure,
        ca_cert: None,
    }
}

/// Stand up an HTTPS server on an ephemeral loopback port using the committed
/// **self-signed** fixture cert. Its SAN is `DNS:ai-memory-test.local` with no
/// IP SAN, and its issuer is itself — so to a client connecting to
/// `https://127.0.0.1:<port>` it is untrusted on BOTH counts. That is exactly
/// the shape of the certificate a DNS/BGP-position adversary presents.
///
/// Returns `(base_url, shutdown_notify)`.
async fn spawn_self_signed_peer() -> (String, Arc<Notify>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls_config =
        tls::load_rustls_config(&fixture("valid_cert.pem"), &fixture("valid_key_pkcs8.pem"))
            .await
            .expect("self-signed fixture server config");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    let socket_addr: std::net::SocketAddr =
        format!("127.0.0.1:{port}").parse().expect("socket addr");

    let app = axum::Router::new().route("/api/v1/health", get(|| async { "ok" }));
    let handle = axum_server::Handle::new();
    let handle_clone = handle.clone();
    let shutdown = Arc::new(Notify::new());
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        shutdown_clone.notified().await;
        handle_clone.graceful_shutdown(Some(Duration::from_secs(2)));
    });
    tokio::spawn(async move {
        let _ = axum_server::bind(socket_addr)
            .acceptor(tls::serve_rustls_acceptor(&tls_config))
            .handle(handle)
            .serve(app.into_make_service())
            .await;
    });

    (format!("https://127.0.0.1:{port}"), shutdown)
}

/// Poll `GET <base>/api/v1/health` with `client` until it answers or the
/// budget elapses. Returns the last outcome so the caller can assert on
/// acceptance vs. rejection of the server certificate.
async fn probe(client: &reqwest::Client, base: &str) -> Result<reqwest::StatusCode, String> {
    let url = format!("{base}/api/v1/health");
    let mut last = String::from("never attempted");
    for _ in 0..60 {
        match client.get(&url).send().await {
            Ok(resp) => return Ok(resp.status()),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(last)
}

/// **R-203 PIN.** `--insecure-skip-server-verify` must be REFUSED by default.
///
/// Fails on parent `47939793` (the daemon accepts the posture and loops until
/// the timeout elapses); passes after the fix (the daemon returns `Err`).
#[tokio::test]
async fn insecure_skip_server_verify_is_refused_by_default_2448() {
    let _guard = verify_env_lock().await;
    // SAFETY: the process-wide env mutation is serialized by the file-local
    // lock taken above; no other thread in this test binary reads it.
    unsafe { std::env::remove_var(tls::FED_REQUIRE_SERVER_VERIFY_ENV) };
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = tempfile::tempdir().expect("tempdir");
    let db = dir.path().join("r203.db");

    // An unreachable peer: whether the refusal fires must not depend on any
    // network outcome. If the daemon does NOT refuse it proceeds into the
    // sync loop (retrying the dead peer forever) and the timeout elapses.
    let args = args_for("https://127.0.0.1:1/", true);
    let outcome = tokio::time::timeout(
        Duration::from_millis(1500),
        run_daemon(&db, args, Some("r203-agent")),
    )
    .await;

    // `let ... else` rather than a wildcard `Err(_)` match arm: the elapsed
    // case is THE vulnerability signal, so it gets its own named branch.
    let Ok(returned) = outcome else {
        panic!(
            "sync-daemon entered its sync loop with server-cert verification DISABLED — \
             --insecure-skip-server-verify was accepted, so this node would push plaintext \
             memory content to any server presenting any certificate (#2448)"
        );
    };
    let err = returned.expect_err("sync-daemon returned Ok — expected a #2448 refusal");
    let msg = err.to_string();
    assert!(
        msg.contains("--insecure-skip-server-verify"),
        "refusal must name the offending flag: {msg}"
    );
    assert!(
        msg.contains(tls::FED_REQUIRE_SERVER_VERIFY_ENV),
        "refusal must name the escape hatch: {msg}"
    );
}

/// The disposition #2448 refuses genuinely WAS forged-certificate acceptance:
/// with the escape hatch set, the outbound client completes a real TLS
/// handshake against a self-signed server it has no reason to trust.
///
/// This is the "currently ACCEPTED" half of the R-203 evidence, kept in the
/// suite permanently so the escape hatch stays honest about what it enables.
#[tokio::test]
async fn escape_hatch_accepts_a_self_signed_peer_2448() {
    let _guard = verify_env_lock().await;
    // SAFETY: serialized by the file-local lock taken above.
    unsafe { std::env::set_var(tls::FED_REQUIRE_SERVER_VERIFY_ENV, "0") };

    let (base, shutdown) = spawn_self_signed_peer().await;
    let client = build_sync_client(&args_for(&base, true))
        .await
        .expect("escape hatch must permit the accept-any client");
    let status = probe(&client, &base)
        .await
        .expect("accept-any client must complete the handshake against a self-signed peer");
    assert_eq!(status, reqwest::StatusCode::OK);

    shutdown.notify_one();
    // SAFETY: serialized by the file-local lock still held.
    unsafe { std::env::remove_var(tls::FED_REQUIRE_SERVER_VERIFY_ENV) };
}

/// The secure default genuinely validates: the SAME self-signed certificate
/// the escape hatch accepts is REJECTED at the handshake when the daemon runs
/// without `--insecure-skip-server-verify` (#1794's `CaValidated` arm).
#[tokio::test]
async fn secure_default_rejects_a_self_signed_peer_1794() {
    let _guard = verify_env_lock().await;
    // SAFETY: serialized by the file-local lock taken above.
    unsafe { std::env::remove_var(tls::FED_REQUIRE_SERVER_VERIFY_ENV) };

    let (base, shutdown) = spawn_self_signed_peer().await;
    let client = build_sync_client(&args_for(&base, false))
        .await
        .expect("the CA-validated default client must build");
    let err = probe(&client, &base)
        .await
        .expect_err("a self-signed peer cert must NOT pass CA validation");
    assert!(
        !err.contains("never attempted"),
        "the probe must have actually attempted a handshake: {err}"
    );

    shutdown.notify_one();
}

/// Server-cert PINNING outranks the insecure flag: a pinned host is verified
/// by SHA-256(DER), so #2448's require-flag has nothing to refuse. Guards
/// against the fix accidentally breaking the #1678 pinning precedence.
#[test]
fn pinning_outranks_the_insecure_flag_2448() {
    assert_eq!(
        tls::select_sync_tls_mode(true, true, true).expect("pinning must not be refused"),
        tls::SyncTlsMode::Pinning
    );
}
