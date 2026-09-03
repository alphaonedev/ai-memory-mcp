// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use std::io::Write as _;
use std::process::{Command, Stdio};

#[test]
fn bind_api_key_accepts_stdin_and_clap_refuses_two_secret_sources_3437() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("agents.db");
    let conn = ai_memory::db::open(&db_path).unwrap();
    ai_memory::db::register_agent(&conn, "ai:stdin-agent", "ai:test", &[]).unwrap();
    drop(conn);

    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "agents",
            "bind-api-key",
            "--agent-id",
            "ai:stdin-agent",
            "--token-file",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"stdin-secret\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let conn = ai_memory::db::open(&db_path).unwrap();
    let digest = ai_memory::handlers::identity_binding::api_key_sha256_hex("stdin-secret");
    assert_eq!(
        ai_memory::db::agent_id_for_api_key(&conn, &digest)
            .unwrap()
            .as_deref(),
        Some("ai:stdin-agent")
    );

    let token_path = dir.path().join("token");
    std::fs::write(&token_path, "file-secret").unwrap();
    let denied = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "agents",
            "bind-api-key",
            "--agent-id",
            "ai:stdin-agent",
            "--token",
            "argv-secret",
            "--token-file",
            token_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(2));
}
