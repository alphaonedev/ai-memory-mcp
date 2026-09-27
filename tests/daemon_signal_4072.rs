// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Real process termination must run the certified daemon shutdown path.
#![cfg(unix)]
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn pending_request(
    ca: &std::path::Path,
    port: u16,
) -> rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream> {
    let certificate = pem::parse(std::fs::read(ca).unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            certificate.into_contents(),
        ))
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connection = rustls::ClientConnection::new(
        std::sync::Arc::new(config),
        rustls::pki_types::ServerName::try_from("127.0.0.1".to_owned()).unwrap(),
    )
    .unwrap();
    let socket = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut stream = rustls::StreamOwned::new(connection, socket);
    stream.write_all(b"POST /api/v1/memories HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n").unwrap();
    stream.flush().unwrap();
    let response = read_header(&mut stream);
    assert!(
        response.starts_with("HTTP/1.1 100"),
        "server must acknowledge the outstanding request: {response}"
    );
    stream
}

fn read_header(stream: &mut impl Read) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 8192, "oversized HTTP header");
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).unwrap()
}

#[test]
fn sigterm_runs_the_same_certified_shutdown_as_sigint_4072() {
    for signal in ["INT", "TERM"] {
        exercise_shutdown(signal, None, false);
    }
}

#[test]
fn final_witness_persistence_failure_exits_75() {
    exercise_shutdown("INT", None, true);
}

#[allow(clippy::too_many_lines)]
fn exercise_shutdown(signal: &str, postgres_url: Option<&str>, anchor_fault: bool) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("daemon.db");
    let config_dir = dir.path().join("config/ai-memory");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(config_dir.join("config.toml"), "tier = \"keyword\"\n").unwrap();
    let log = dir.path().join("daemon.log");
    let custody = dir.path().join("witness");
    let key =
        ai_memory::identity::keypair::generate(ai_memory::governance::audit::WITNESS_KEY_LABEL)
            .unwrap();
    ai_memory::identity::keypair::save(&key, &custody).unwrap();
    if postgres_url.is_none() {
        let conn = ai_memory::db::open(&db).unwrap();
        ai_memory::signed_events::append_signed_event(
            &conn,
            &ai_memory::signed_events::SignedEvent {
                id: uuid::Uuid::new_v4().to_string(),
                agent_id: "ai:signal4072".into(),
                event_type: "shutdown_probe".into(),
                payload_hash: ai_memory::signed_events::payload_hash(b"signal"),
                attest_level: "unsigned".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                ..Default::default()
            },
        )
        .unwrap();
        drop(conn);
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let file = std::fs::File::create(&log).unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("TMPDIR", std::env::var_os("TMPDIR").unwrap())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_CACHE_HOME", dir.path().join("cache"))
            .env("AI_MEMORY_AUDIT_DIR", dir.path().join("audit"))
            .env(ai_memory::governance::audit::WITNESS_KEY_DIR_ENV, &custody)
            .env(
                ai_memory::governance::audit::WITNESS_PUBKEY_ENV,
                key.public_base64(),
            )
            .env("AI_MEMORY_SECURITY_PROFILE", "standard")
            .envs(
                postgres_url
                    .into_iter()
                    .map(|url| ("AI_MEMORY_STORE_URL", url)),
            )
            .env("AI_MEMORY_KEY_DIR", dir.path().join("keys"))
            .env("AI_MEMORY_LOG_DIR", dir.path().join("logs"))
            .env("RUST_LOG", "info")
            .args([
                "--db",
                db.to_str().unwrap(),
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--catchup-interval-secs",
                "0",
            ])
            .stdout(Stdio::from(file.try_clone().unwrap()))
            .stderr(Stdio::from(file))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "daemon exited at boot: {text}"
        );
        if text.contains("ai-memory listening")
            && std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
        {
            break;
        }
        assert!(Instant::now() < deadline, "daemon not ready: {text}");
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut pending = pending_request(&dir.path().join("keys/tls/local-ca.pem"), port);
    if anchor_fault {
        let anchor = custody.join(ai_memory::governance::audit::HEAD_ANCHOR_LOG_FILENAME);
        if anchor.is_file() {
            std::fs::remove_file(&anchor).unwrap();
        }
        std::fs::create_dir_all(&anchor).unwrap();
    }
    assert!(
        Command::new("kill")
            .args(["-s", signal, &child.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    // The 100 Continue handshake proves the server is already reading this
    // request body. A graceful signal must keep it alive until that body ends.
    loop {
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "signal bypassed the in-flight request drain: {text}"
        );
        assert!(
            !text.contains("deferred-audit queue drained"),
            "certification began before the request completed: {text}"
        );
        if text.contains("shutting down — draining") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "shutdown signal not observed: {text}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    pending.write_all(b"{}").unwrap();
    pending.flush().unwrap();
    let response = read_header(&mut pending);
    assert!(
        response.starts_with("HTTP/1.1 4"),
        "the in-flight invalid create must finish before certification: {response}"
    );
    drop(pending);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "shutdown deadline exceeded");
        std::thread::sleep(Duration::from_millis(10));
    };
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(
        status.code() == Some(if anchor_fault { 75 } else { 0 }),
        "{signal}: expected certified success or explicit exit75 on anchor failure: {status}; {text}"
    );
    assert!(
        text.contains("deferred-audit queue drained"),
        "{signal} skipped drain: {text}"
    );
    if anchor_fault {
        assert!(
            text.contains("final witness/WAL certification failed"),
            "{text}"
        );
    }
    if postgres_url.is_none() {
        let conn = rusqlite::Connection::open(&db).unwrap();
        let witnesses: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM checkpoints WHERE condition_type = 'audit_head_witness'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(witnesses > 0, "{signal} omitted final witness");
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires dedicated AI_MEMORY_TEST_POSTGRES_URL"]
async fn postgres_final_witness_binds_active_heads_and_failure_exits_75_4070() {
    use sha2::{Digest, Sha256};
    use sqlx::Row as _;
    let _sandbox = ai_memory::identity::test_key_dir::install();
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").expect("dedicated database");
    let pg = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .unwrap();
    for anchor_fault in [false, true] {
        let before: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) FROM signed_events")
                .fetch_one(pg.pool())
                .await
                .unwrap();
        pg.emit_spawn_audit("shutdown-probe", "daemon4070").await;
        let after: i64 = sqlx::query_scalar("SELECT MAX(sequence) FROM signed_events")
            .fetch_one(pg.pool())
            .await
            .unwrap();
        assert!(
            after > before,
            "the real PostgreSQL append must create a tail"
        );
        let child_url = url.clone();
        tokio::task::spawn_blocking(move || {
            exercise_shutdown("INT", Some(&child_url), anchor_fault)
        })
        .await
        .unwrap();
        if !anchor_fault {
            let resolution: String = sqlx::query_scalar("SELECT resolution FROM checkpoints WHERE condition_type = 'audit_head_witness' ORDER BY (resolution::jsonb #>> '{signed_events,head_sequence}')::bigint DESC, created_at DESC LIMIT 1").fetch_one(pg.pool()).await.unwrap();
            let resolution: serde_json::Value = serde_json::from_str(&resolution).unwrap();
            let head: i64 = sqlx::query_scalar("SELECT MAX(sequence) FROM signed_events")
                .fetch_one(pg.pool())
                .await
                .unwrap();
            let revisions: i64 =
                sqlx::query_scalar("SELECT COALESCE(MAX(sequence),0) FROM memory_revisions")
                    .fetch_one(pg.pool())
                    .await
                    .unwrap();
            let (id, agent, payload): (String, String, Vec<u8>) =
                sqlx::query_as(ai_memory::signed_events::GENESIS_ROW_SQL)
                    .fetch_one(pg.pool())
                    .await
                    .unwrap();
            let identity =
                ai_memory::signed_events::db_id_from_genesis_parts(&id, &agent, &payload);
            let row = sqlx::query("SELECT * FROM signed_events WHERE sequence = $1")
                .bind(head)
                .fetch_one(pg.pool())
                .await
                .unwrap();
            let event = ai_memory::signed_events::SignedEvent {
                id: row.get("id"),
                agent_id: row.get("agent_id"),
                event_type: row.get("event_type"),
                payload_hash: row.get("payload_hash"),
                signature: row.get("signature"),
                attest_level: row.get("attest_level"),
                timestamp: row
                    .get::<chrono::DateTime<chrono::Utc>, _>("timestamp")
                    .to_rfc3339(),
                prev_hash: row.get("prev_hash"),
                sequence: head,
                cause_hash: row.get("cause_hash"),
            };
            let expected_hash = format!(
                "{:x}",
                Sha256::digest(ai_memory::signed_events::canonical_chain_bytes(&event))
            );
            assert_eq!(resolution["signed_events"]["head_hash"], expected_hash);
            assert_eq!(resolution["signed_events"]["head_sequence"], head);
            assert_eq!(resolution["memory_revisions"]["head_sequence"], revisions);
            assert_eq!(resolution["db_id"], identity);
        }
    }
}
