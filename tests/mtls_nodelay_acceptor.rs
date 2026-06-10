// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1581 — security-equivalence + socket-option tests for the mTLS serve
//! acceptor (`tls::serve_rustls_acceptor`, the `TCP_NODELAY` fix).
//!
//! The #1579 P3 fleet audit measured a fixed ~40 ms first-request cost on
//! every fresh mTLS API connection (TTFB ~52–57 ms vs ~5–8 ms on a reused
//! connection, with in-region RTT 2–3 ms). Diagnosis: `serve()` bound the
//! TLS listener via `axum_server::bind_rustls`, whose `DefaultAcceptor`
//! never sets `TCP_NODELAY` on the accepted socket. After the TLS 1.3
//! handshake the server flushes the `NewSessionTicket` records as a small
//! TCP segment ahead of the first response; with Nagle's algorithm enabled
//! the response segment is held until that ticket segment is ACK'd, and the
//! client kernel's delayed-ACK timer (40 ms minimum on Linux) supplies the
//! ACK. Subsequent requests on the same connection never hit the pattern,
//! which is why only the FIRST request paid the cost.
//!
//! The fix (`tls::serve_rustls_acceptor`) wraps the rustls acceptor around
//! `axum_server::accept::NoDelayAcceptor` so `TCP_NODELAY` is set on every
//! accepted socket before the handshake. This is a pure socket-option
//! change at a security boundary, so these tests pin BOTH properties:
//!
//! 1. SECURITY EQUIVALENCE — the nodelay acceptor accepts/rejects exactly
//!    the same client certs as the legacy `DefaultAcceptor`-wrapped path:
//!    allowlisted cert accepted, unknown cert rejected, absent cert
//!    rejected (`client_auth_mandatory` preserved).
//! 2. The accepted socket really has `TCP_NODELAY` set on the new path
//!    (and really did NOT on the legacy path — proving the bug existed and
//!    that the behavioural delta is exactly the socket option).

use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ai_memory::tls;
use axum_server::accept::Accept as _;

/// Path to a committed TLS fixture (see `tests/fixtures/tls/README.md`).
fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(rel)
}

/// Server-side handshake budget. Generous so slow CI hosts don't flake;
/// the handshake itself completes in single-digit milliseconds on loopback.
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(10);

/// Build the production mTLS `RustlsConfig` whose allowlist pins exactly
/// the committed fixture cert (`valid_cert.pem`).
async fn mtls_config_pinning_fixture_cert() -> axum_server::tls_rustls::RustlsConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let allowlist = tempfile::NamedTempFile::new().expect("tempfile");
    let fp = std::fs::read_to_string(fixture("valid_cert_sha256.txt"))
        .expect("fixture fingerprint — regenerate via tests/fixtures/tls/regenerate.sh");
    std::fs::write(allowlist.path(), fp).expect("write allowlist");
    tls::load_mtls_rustls_config(
        &fixture("valid_cert.pem"),
        &fixture("valid_key_pkcs8.pem"),
        allowlist.path(),
    )
    .await
    .expect("mTLS server config from committed fixtures")
}

/// Client config presenting the allowlisted fixture cert — the same
/// production builder the sync-daemon uses for outbound mTLS.
async fn allowlisted_client_config() -> rustls::ClientConfig {
    tls::build_rustls_client_config(&fixture("valid_cert.pem"), &fixture("valid_key_pkcs8.pem"))
        .await
        .expect("client config with allowlisted fixture cert")
}

/// Client config presenting a freshly minted cert that is NOT on the
/// allowlist (rcgen ephemeral — different DER every run, so its SHA-256
/// can never collide with the pinned fixture fingerprint).
fn unknown_client_config() -> rustls::ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
    let params =
        rcgen::CertificateParams::new(vec!["unknown-peer.local".to_string()]).expect("cert params");
    let cert = params.self_signed(&key).expect("self-signed cert");
    let certs = vec![cert.der().clone()];
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(tls::DangerousAnyServerVerifier))
        .with_client_auth_cert(certs, key_der)
        .expect("client config with unknown cert")
}

/// Client config presenting NO client certificate at all.
fn certless_client_config() -> rustls::ClientConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(tls::DangerousAnyServerVerifier))
        .with_no_client_auth()
}

/// Outcome of one server-side accept through an acceptor under test.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Handshake completed; payload is the accepted socket's `TCP_NODELAY`.
    Accepted { nodelay: bool },
    /// Handshake refused (bad/missing client cert ⇒ accept future errored).
    Rejected,
}

/// Spawn a raw rustls client on a std thread and drive ONE handshake
/// against `addr`. The thread holds the socket open (blocking read with a
/// timeout) so the server side can finish its half without racing an EOF.
fn spawn_client(addr: std::net::SocketAddr, config: rustls::ClientConfig) {
    std::thread::spawn(move || {
        let server_name =
            rustls::pki_types::ServerName::try_from("ai-memory-test.local".to_string())
                .expect("server name");
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .expect("client connection");
        let Ok(mut sock) = std::net::TcpStream::connect(addr) else {
            return;
        };
        let _ = sock.set_read_timeout(Some(HANDSHAKE_BUDGET));
        let mut stream = rustls::Stream::new(&mut conn, &mut sock);
        // The write drives the full handshake (and is the first app-data
        // record on success). Rejection paths error here or on the read —
        // both are fine; the assertion under test is server-side.
        let _ = stream.write_all(b"ping");
        let _ = stream.flush();
        let mut buf = [0u8; 16];
        let _ = stream.read(&mut buf);
    });
}

/// Accept exactly one connection through the NEW production acceptor
/// (`tls::serve_rustls_acceptor` — nodelay) and report the outcome.
async fn outcome_via_nodelay_acceptor(client: rustls::ClientConfig) -> Outcome {
    let config = mtls_config_pinning_fixture_cert().await;
    let acceptor = tls::serve_rustls_acceptor(&config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    spawn_client(addr, client);
    let (tcp, _peer) = listener.accept().await.expect("tcp accept");
    let accept = tokio::time::timeout(HANDSHAKE_BUDGET, acceptor.accept(tcp, ()));
    match accept.await.expect("handshake within budget") {
        Ok((stream, ())) => {
            let (tcp_ref, _conn) = stream.get_ref();
            Outcome::Accepted {
                nodelay: tcp_ref.nodelay().expect("query TCP_NODELAY"),
            }
        }
        Err(_) => Outcome::Rejected,
    }
}

/// Accept exactly one connection through the LEGACY acceptor shape
/// (`RustlsAcceptor::new` over `DefaultAcceptor` — what
/// `axum_server::bind_rustls` constructed before #1581) and report the
/// outcome. This is the security-equivalence baseline.
async fn outcome_via_legacy_acceptor(client: rustls::ClientConfig) -> Outcome {
    let config = mtls_config_pinning_fixture_cert().await;
    let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    spawn_client(addr, client);
    let (tcp, _peer) = listener.accept().await.expect("tcp accept");
    let accept = tokio::time::timeout(HANDSHAKE_BUDGET, acceptor.accept(tcp, ()));
    match accept.await.expect("handshake within budget") {
        Ok((stream, ())) => {
            let (tcp_ref, _conn) = stream.get_ref();
            Outcome::Accepted {
                nodelay: tcp_ref.nodelay().expect("query TCP_NODELAY"),
            }
        }
        Err(_) => Outcome::Rejected,
    }
}

// ---------------------------------------------------------------------------
// Security equivalence: allowlisted cert ACCEPTED on both acceptor shapes.
// The nodelay payload is the perf assertion: the legacy path really left
// Nagle enabled (nodelay=false) and the new path really sets it.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_equiv_allowlisted_cert_accepted_and_nodelay_set() {
    let outcome = outcome_via_nodelay_acceptor(allowlisted_client_config().await).await;
    assert_eq!(
        outcome,
        Outcome::Accepted { nodelay: true },
        "allowlisted client cert must complete the handshake through the \
         production serve acceptor AND the accepted socket must have \
         TCP_NODELAY set (the #1581 fix)"
    );
}

#[tokio::test]
async fn mtls_equiv_allowlisted_cert_accepted_on_legacy_acceptor() {
    let outcome = outcome_via_legacy_acceptor(allowlisted_client_config().await).await;
    assert_eq!(
        outcome,
        Outcome::Accepted { nodelay: false },
        "equivalence baseline: the legacy DefaultAcceptor path accepts the \
         same cert — and demonstrably never set TCP_NODELAY (the #1581 bug)"
    );
}

// ---------------------------------------------------------------------------
// Security equivalence: unknown (non-allowlisted) cert REJECTED on both.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_equiv_unknown_cert_rejected_on_nodelay_acceptor() {
    let outcome = outcome_via_nodelay_acceptor(unknown_client_config()).await;
    assert_eq!(
        outcome,
        Outcome::Rejected,
        "a client cert whose fingerprint is not on the allowlist must be \
         rejected at the handshake — unchanged by the nodelay acceptor"
    );
}

#[tokio::test]
async fn mtls_equiv_unknown_cert_rejected_on_legacy_acceptor() {
    let outcome = outcome_via_legacy_acceptor(unknown_client_config()).await;
    assert_eq!(outcome, Outcome::Rejected);
}

// ---------------------------------------------------------------------------
// Security equivalence: NO client cert REJECTED on both
// (client_auth_mandatory preserved through the acceptor change).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mtls_equiv_missing_cert_rejected_on_nodelay_acceptor() {
    let outcome = outcome_via_nodelay_acceptor(certless_client_config()).await;
    assert_eq!(
        outcome,
        Outcome::Rejected,
        "client_auth_mandatory must survive the acceptor change: a client \
         presenting no certificate is refused at the handshake"
    );
}

#[tokio::test]
async fn mtls_equiv_missing_cert_rejected_on_legacy_acceptor() {
    let outcome = outcome_via_legacy_acceptor(certless_client_config()).await;
    assert_eq!(outcome, Outcome::Rejected);
}
