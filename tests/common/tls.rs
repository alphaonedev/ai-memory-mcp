// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3705 — "only encrypted data in transit": the ONE way an integration test
//! stands up a TLS listener and talks to it.
//!
//! Since the mandate the daemon refuses every plaintext bind (loopback
//! included), so every suite that spawns `ai-memory serve` — or a mock peer
//! the daemon must federate with — needs a certificate. This helper mints a
//! per-test self-signed leaf with `rcgen` (SANs `localhost`, `127.0.0.1`,
//! `::1`) under the test's own scratch directory, hands out the `--tls-cert`
//! / `--tls-key` argv, and builds `reqwest` clients that TRUST exactly that
//! leaf — no `danger_accept_invalid_certs`, no verification bypass: the test
//! client verifies the daemon the way a real client would.
//!
//! Also carries an in-process TLS server (`serve_router`) for suites that
//! used to bind a plain `axum::serve` mock peer.

#![allow(dead_code)]

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// `<key_dir>/tls/` — where the daemon's zero-config material lives (#3709).
pub const LOCAL_TLS_SUBDIR: &str = "tls";
/// The zero-config local CA certificate file inside [`LOCAL_TLS_SUBDIR`].
pub const LOCAL_CA_CERT_FILE: &str = "local-ca.pem";
/// The zero-config local CA private key file.
pub const LOCAL_CA_KEY_FILE: &str = "local-ca.key";
/// The zero-config server certificate file.
pub const SERVER_CERT_FILE: &str = "server.pem";
/// The zero-config server private key file.
pub const SERVER_KEY_FILE: &str = "server.key";

/// A freshly minted self-signed TLS leaf for one test.
#[derive(Clone, Debug)]
pub struct TestTls {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub cert_pem: String,
}

impl TestTls {
    /// Mint a leaf valid for `localhost`, `127.0.0.1` and `::1`, writing
    /// `cert.pem` + `key.pem` (key 0600) into `dir` (created if missing).
    pub fn generate(dir: &Path) -> Self {
        std::fs::create_dir_all(dir).expect("create TLS scratch dir");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("generate ECDSA P-256 keypair");
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("certificate params");
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(IpAddr::V4(
                std::net::Ipv4Addr::LOCALHOST,
            )));
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(IpAddr::V6(
                std::net::Ipv6Addr::LOCALHOST,
            )));
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "ai-memory test leaf (#3705)");
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).expect("self-signed leaf");
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, &cert_pem).expect("write cert.pem");
        std::fs::write(&key_path, key_pem).expect("write key.pem");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 0600 key.pem");
        }
        Self {
            cert_path,
            key_path,
            cert_pem,
        }
    }

    /// The `serve` argv that enables in-process TLS with this leaf.
    #[must_use]
    pub fn serve_args(&self) -> Vec<String> {
        vec![
            "--tls-cert".to_string(),
            self.cert_path.display().to_string(),
            "--tls-key".to_string(),
            self.key_path.display().to_string(),
        ]
    }

    /// The same four argv entries as `&str`s, for `.args([...])` call sites
    /// that hold a borrowed slice (the strings live as long as `self`).
    #[must_use]
    pub fn serve_arg_strs(&self) -> [&str; 4] {
        [
            "--tls-cert",
            self.cert_path.to_str().expect("utf-8 cert path"),
            "--tls-key",
            self.key_path.to_str().expect("utf-8 key path"),
        ]
    }

    /// The `--ca-cert` / `--quorum-ca-cert` value: this leaf's own PEM.
    #[must_use]
    pub fn ca_path(&self) -> &Path {
        &self.cert_path
    }

    /// A `reqwest::Certificate` for this leaf (to trust it as a root).
    #[must_use]
    pub fn certificate(&self) -> reqwest::Certificate {
        reqwest::Certificate::from_pem(self.cert_pem.as_bytes()).expect("parse leaf PEM")
    }

    /// A blocking client that trusts exactly this leaf (full verification).
    #[must_use]
    pub fn client(&self) -> reqwest::blocking::Client {
        self.client_with_timeout(Duration::from_secs(5))
    }

    /// [`Self::client`] with an explicit per-request timeout.
    #[must_use]
    pub fn client_with_timeout(&self, timeout: Duration) -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(self.certificate())
            .timeout(timeout)
            .build()
            .expect("build trusting blocking client")
    }

    /// An async client that trusts exactly this leaf (full verification).
    #[must_use]
    pub fn async_client(&self) -> reqwest::Client {
        self.async_client_with_timeout(Duration::from_secs(5))
    }

    /// [`Self::async_client`] with an explicit per-request timeout.
    #[must_use]
    pub fn async_client_with_timeout(&self, timeout: Duration) -> reqwest::Client {
        reqwest::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(self.certificate())
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(2))
            .build()
            .expect("build trusting async client")
    }

    /// `https://127.0.0.1:{port}`.
    #[must_use]
    pub fn base_url(port: u16) -> String {
        format!("https://127.0.0.1:{port}")
    }

    /// `curl` argv that verifies the daemon against this leaf.
    #[must_use]
    pub fn curl_args(&self) -> [String; 2] {
        ["--cacert".to_string(), self.cert_path.display().to_string()]
    }

    /// Serve `router` over TLS with this leaf on an ephemeral loopback port.
    /// Returns the bound port and the axum-server handle (call
    /// `handle.shutdown()` to stop). Replaces the plain `axum::serve` mock
    /// peers the federation suites used to bind.
    pub async fn serve_router(
        &self,
        router: axum::Router,
    ) -> (u16, axum_server::Handle<std::net::SocketAddr>) {
        // Under feature graphs where BOTH `ring` and `aws-lc-rs` are present
        // rustls cannot auto-select a CryptoProvider — pin ring, as the
        // production serve() path does. Idempotent.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_config = ai_memory::tls::load_rustls_config(&self.cert_path, &self.key_path)
            .await
            .expect("rustls config from the minted leaf");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        // tokio adopts a std listener only in non-blocking mode.
        listener
            .set_nonblocking(true)
            .expect("non-blocking mock listener");
        let port = listener.local_addr().expect("local_addr").port();
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        tokio::spawn(async move {
            axum_server::from_tcp(listener)
                .expect("axum_server::from_tcp")
                .acceptor(ai_memory::tls::serve_rustls_acceptor(&tls_config))
                .handle(server_handle)
                .serve(router.into_make_service())
                .await
                .ok();
        });
        // `listening()` resolves once the acceptor is bound (None only if
        // the server shut down first).
        let bound = tokio::time::timeout(Duration::from_secs(10), handle.listening())
            .await
            .expect("in-process TLS mock listener never came up")
            .expect("in-process TLS mock server shut down before listening");
        assert_eq!(bound.port(), port);
        (port, handle)
    }
}

/// #3709 — the ZERO-CONFIG path: a `serve` with no `--tls-cert`/`--tls-key`
/// generates `<key_dir>/tls/local-ca.pem` (+ key, server pair) on first boot
/// and serves TLS. Poll for the CA file the child writes, then build a
/// blocking client that trusts exactly that CA (full verification — the
/// CA-issued leaf's SANs cover `127.0.0.1`). `None` if the file never
/// appeared within `deadline`.
pub fn local_ca_client(key_dir: &Path, deadline: Duration) -> Option<reqwest::blocking::Client> {
    // Literal names (not the crate constants) so this helper also compiles on
    // the pre-#3709 head for the fails-on-head proof.
    let ca_path = key_dir.join(LOCAL_TLS_SUBDIR).join(LOCAL_CA_CERT_FILE);
    let until = std::time::Instant::now() + deadline;
    loop {
        if let Ok(pem) = std::fs::read(&ca_path)
            && let Ok(cert) = reqwest::Certificate::from_pem(&pem)
        {
            return Some(
                reqwest::blocking::Client::builder()
                    .use_rustls_tls()
                    .add_root_certificate(cert)
                    .timeout(Duration::from_secs(5))
                    .build()
                    .expect("build local-CA-trusting client"),
            );
        }
        if std::time::Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A process-wide leaf for suites whose helpers only carry a port
/// (`curl_get(port, path)` and friends): minted once per test binary under
/// `dir`, shared by every spawn in that binary.
pub fn shared(dir: &Path) -> &'static TestTls {
    static SHARED: std::sync::OnceLock<TestTls> = std::sync::OnceLock::new();
    SHARED.get_or_init(|| TestTls::generate(&dir.join(format!("tls-{}", std::process::id()))))
}

/// Convenience for `Arc`-sharing across spawned tasks.
pub fn shared_arc(dir: &Path) -> Arc<TestTls> {
    Arc::new(shared(dir).clone())
}
