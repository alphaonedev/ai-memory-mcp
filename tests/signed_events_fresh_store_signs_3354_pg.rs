// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3354 — PostgreSQL twin through the daemon: a postgres-backed `serve`
//! whose resolved agent id has no signing key generates one at boot and the
//! ledger row a captured turn appends on postgres is `self_signed`, never
//! `unsigned`. Live only under `AI_MEMORY_TEST_POSTGRES_URL` (a FRESH
//! `ai_memory_f2a_*` database — never `ai_memory_test`); skips otherwise.
//!
//! FAILS ON THE PARENT: the postgres row lands `unsigned` and no key is
//! generated for the resolved id.
//!
//! TRANSPORT: the daemon is spawned with `--tls-cert` / `--tls-key` (a leaf
//! minted here with `rcgen`, trusted exactly — no verification bypass) and
//! probed over `https://`. Explicit TLS is accepted on this branch's own
//! base (where a plaintext loopback bind would also have booted) and is the
//! ONLY posture the daemon accepts once #3705 ("only encrypted data in
//! transit") is in the tree, so the same test measures the same claim on
//! both. The mint is inlined rather than taken from #3705's
//! `tests/common/tls.rs` because that helper does not exist on this
//! branch's base.

#![cfg(feature = "sal-postgres")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::free_port;

const AGENT_ID: &str = "ai:ledger-3354-pg";
const PG_URL_ENV: &str = "AI_MEMORY_TEST_POSTGRES_URL";

fn pg_url() -> Option<String> {
    match std::env::var(PG_URL_ENV) {
        Ok(u) if !u.trim().is_empty() => Some(u),
        _ => {
            eprintln!("SKIP signed_events_fresh_store_signs_3354_pg: {PG_URL_ENV} unset");
            None
        }
    }
}

struct Sandbox {
    _root: tempfile::TempDir,
    home: PathBuf,
    keys: PathBuf,
    db: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    tls_cert_pem: String,
}

/// Mint a self-signed leaf for `localhost` / `127.0.0.1` / `::1` into `dir`
/// (key 0600). The daemon serves it; the test client trusts exactly it.
fn mint_tls_leaf(dir: &std::path::Path) -> (PathBuf, PathBuf, String) {
    std::fs::create_dir_all(dir).expect("tls scratch dir");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("generate ECDSA P-256 keypair");
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("certificate params");
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V6(
            std::net::Ipv6Addr::LOCALHOST,
        )));
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "ai-memory test leaf (#3354 pg)");
    params.distinguished_name = dn;
    let cert = params.self_signed(&key).expect("self-signed leaf");
    let cert_pem = cert.pem();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, &cert_pem).expect("write cert.pem");
    std::fs::write(&key_path, key.serialize_pem()).expect("write key.pem");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 key.pem");
    }
    (cert_path, key_path, cert_pem)
}

/// A blocking client that trusts exactly the minted leaf (full verification).
fn tls_client(sb: &Sandbox, timeout: Duration) -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(
            reqwest::Certificate::from_pem(sb.tls_cert_pem.as_bytes()).expect("parse leaf PEM"),
        )
        .timeout(timeout)
        .build()
        .expect("trusting blocking client")
}

fn sandbox() -> Sandbox {
    let root = tempfile::tempdir().expect("tempdir under TMPDIR");
    let home = root.path().join("home");
    let keys = root.path().join("keys");
    std::fs::create_dir_all(home.join(".config")).expect("home");
    std::fs::create_dir_all(&keys).expect("keys");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("0700");
    }
    let db = root.path().join("sidecar.db");
    let (tls_cert, tls_key, tls_cert_pem) = mint_tls_leaf(&root.path().join("tls"));
    Sandbox {
        _root: root,
        home,
        keys,
        db,
        tls_cert,
        tls_key,
        tls_cert_pem,
    }
}

fn command(sb: &Sandbox, url: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &sb.home)
        .env("XDG_CONFIG_HOME", sb.home.join(".config"))
        .env("AI_MEMORY_KEY_DIR", &sb.keys)
        .env("AI_MEMORY_DB", &sb.db)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", AGENT_ID)
        .env("AI_MEMORY_STORE_URL", url)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    cmd
}

struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Boot a postgres-backed daemon over TLS and wait for `/health` over
/// `https://`.
fn serve(sb: &Sandbox, url: &str) -> (Daemon, u16) {
    let port = free_port();
    let child = command(sb, url)
        .args(["serve", "--port", &port.to_string(), "--tls-cert"])
        .arg(&sb.tls_cert)
        .arg("--tls-key")
        .arg(&sb.tls_key)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let mut daemon = Daemon { child };
    let client = tls_client(sb, Duration::from_secs(2));
    let health_url = format!("{}/api/v1/health", base_url(port));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(resp) = client.get(&health_url).send()
            && resp.status().is_success()
        {
            break;
        }
        if let Ok(Some(status)) = daemon.child.try_wait() {
            let mut err = String::new();
            if let Some(mut e) = daemon.child.stderr.take() {
                use std::io::Read as _;
                let _ = e.read_to_string(&mut err);
            }
            panic!("serve exited before /health ({status}): {err}");
        }
        assert!(Instant::now() < deadline, "serve never became healthy");
        std::thread::sleep(Duration::from_millis(200));
    }
    (daemon, port)
}

/// `https://127.0.0.1:{port}`.
fn base_url(port: u16) -> String {
    format!("https://127.0.0.1:{port}")
}

/// `(agent_id, attest_level, count)` over the whole `signed_events` ledger.
fn ledger_levels(rt: &tokio::runtime::Runtime, url: &str) -> Vec<(String, String, i64)> {
    rt.block_on(async {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(url)
            .await
            .expect("pg pool");
        sqlx::query_as::<_, (String, String, i64)>(
            "SELECT agent_id, attest_level, COUNT(*) FROM signed_events \
             GROUP BY agent_id, attest_level",
        )
        .fetch_all(&pool)
        .await
        .expect("levels")
    })
}

/// Review round 3: a `capture_turn` row carries the L4 HOST attestation level
/// (`self_signed` with no host signature pair) and the HOST's signature — it
/// says nothing about the daemon key. The capture cell below proves key
/// generation + that the writer appends its row; the signed property is
/// proved on a writer that daemon-signs: `DELETE /api/v1/memories/{id}`
/// writes a forget tombstone signed through `try_sign_audit_payload`, so
/// `signature IS NOT NULL` and it verifies under `<id>.pub`.
#[test]
fn pg_daemon_generates_the_key_at_boot_and_signs_the_first_tombstone_3354() {
    let Some(url) = pg_url() else { return };
    let sb = sandbox();
    let (_daemon, port) = serve(&sb, &url);

    // The daemon generated the key for the resolved id at boot.
    let priv_path = sb.keys.join(format!("{AGENT_ID}.priv"));
    let pub_path = sb.keys.join(format!("{AGENT_ID}.pub"));
    assert!(
        priv_path.is_file(),
        "signing key generated at boot for the resolved id"
    );
    assert!(pub_path.is_file(), "with its public half");

    // One captured turn through the HTTP surface appends its ledger row
    // (keyed to the resolved HTTP caller, #1413 — read as a before/after
    // delta over every agent). Key generation is the claim here, not the
    // row's attestation level, which is the host's, not the daemon's.
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let before = ledger_levels(&rt, &url);
    let client = tls_client(&sb, Duration::from_secs(10));
    let session = format!("sess-3354-pg-{}", uuid::Uuid::new_v4().simple());
    let resp = client
        .post(format!("{}/api/v1/capture_turn", base_url(port)))
        .json(&serde_json::json!({
            "host_session_id": session,
            "host_turn_index": 1,
            "role": "assistant",
            "content": "pg turn — the daemon key was generated at boot (#3354)",
            "host_kind": "claude-code",
        }))
        .send()
        .expect("capture_turn request");
    assert!(
        resp.status().is_success(),
        "capture_turn over HTTP: {} {}",
        resp.status(),
        resp.text().unwrap_or_default()
    );
    let after = ledger_levels(&rt, &url);
    let appended: i64 = after.iter().map(|(_, _, n)| n).sum::<i64>()
        - before.iter().map(|(_, _, n)| n).sum::<i64>();
    assert!(appended >= 1, "the turn appended a ledger row on postgres");

    // A daemon-signing writer: create, then DELETE — the forget tombstone is
    // signed with the key ensured at boot.
    let resp = client
        .post(format!("{}/api/v1/memories", base_url(port)))
        .header("x-agent-id", AGENT_ID)
        .json(&serde_json::json!({
            "title": format!("row to forget {}", uuid::Uuid::new_v4().simple()),
            "content": "its tombstone must be daemon-signed (#3354)",
        }))
        .send()
        .expect("create request");
    assert!(
        resp.status().is_success(),
        "create: {} {}",
        resp.status(),
        resp.text().unwrap_or_default()
    );
    let created: serde_json::Value = resp.json().expect("create json");
    let id = created["id"].as_str().expect("id").to_string();
    let resp = client
        .delete(format!("{}/api/v1/memories/{id}", base_url(port)))
        .header("x-agent-id", AGENT_ID)
        .send()
        .expect("delete request");
    assert!(
        resp.status().is_success(),
        "delete: {} {}",
        resp.status(),
        resp.text().unwrap_or_default()
    );

    let (namespace, forgotten_at, signature): (String, String, Option<Vec<u8>>) =
        rt.block_on(async {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&url)
                .await
                .expect("pg pool");
            sqlx::query_as::<_, (String, String, Option<Vec<u8>>)>(
                "SELECT namespace, forgotten_at, signature FROM forget_tombstones \
                 WHERE memory_id = $1",
            )
            .bind(&id)
            .fetch_one(&pool)
            .await
            .expect("the delete left a forget tombstone")
        });
    let signature = signature.unwrap_or_else(|| {
        panic!(
            "#3354 (pg): the fresh store's first tombstone is daemon-signed, never signature = NULL"
        )
    });
    let pub_bytes: [u8; 32] = std::fs::read(&pub_path)
        .expect("read .pub")
        .try_into()
        .expect("a raw 32-byte Ed25519 public key");
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pub_bytes).expect("public key");
    let sig_bytes: [u8; 64] = signature
        .as_slice()
        .try_into()
        .expect("a 64-byte Ed25519 signature");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let signable =
        ai_memory::storage::forget_tombstone_signable_bytes(&id, &namespace, &forgotten_at);
    verifying
        .verify_strict(&signable, &sig)
        .expect("#3354 (pg): the tombstone signature verifies under <id>.pub");
}
