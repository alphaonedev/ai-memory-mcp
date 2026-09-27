// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Real process termination must run the certified daemon shutdown path.
#![cfg(unix)]
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn sigterm_runs_the_same_certified_shutdown_as_sigint_4072() {
    for signal in ["INT", "TERM"] {
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
        assert!(
            Command::new("kill")
                .args(["-s", signal, &child.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "shutdown deadline exceeded");
            std::thread::sleep(Duration::from_millis(10));
        };
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(
            status.success(),
            "{signal} must certify graceful shutdown: {status}; {text}"
        );
        assert!(
            text.contains("deferred-audit queue drained"),
            "{signal} skipped drain: {text}"
        );
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
