// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Backend certification and erasure admission regressions, in isolated processes.
#![cfg(feature = "sal")]
use ai_memory::config::AppConfig;
#[cfg(feature = "sal-postgres")]
use ai_memory::daemon_runtime::{FatalShutdownError, serve};
use ai_memory::daemon_runtime::{ServeArgs, bootstrap_serve};

fn isolated_child(name: &str) -> bool {
    if std::env::var("C5_LIFECYCLE_CHILD").ok().as_deref() == Some(name) {
        return false;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--include-ignored"])
        .env("C5_LIFECYCLE_CHILD", name)
        .env("AI_MEMORY_SECURITY_PROFILE", "standard")
        .status()
        .unwrap();
    assert!(status.success(), "isolated regression failed: {name}");
    true
}

fn bind_failure_args() -> ServeArgs {
    ServeArgs {
        host: "127.0.0.1".to_string(),
        port: 0,
        tls_cert: None,
        tls_key: None,
        mtls_allowlist: None,
        shutdown_grace_secs: 30,
        quorum_writes: 0,
        quorum_peers: vec![],
        quorum_timeout_ms: 2_000,
        quorum_client_cert: None,
        quorum_client_key: None,
        quorum_ca_cert: None,
        catchup_interval_secs: 0,
        federation_identity: None,
        #[cfg(feature = "sal")]
        store_url: None,
    }
}

fn keyword_config() -> AppConfig {
    AppConfig {
        tier: Some("keyword".to_string()),
        ..AppConfig::default()
    }
}

#[cfg(feature = "sal")]
#[tokio::test]
async fn disabled_replay_clears_erasure_admission_4067() {
    if isolated_child("disabled_replay_clears_erasure_admission_4067") {
        return;
    }
    let _sandbox = ai_memory::identity::test_key_dir::install();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("erasure.db");
    let mut args = bind_failure_args();
    args.quorum_writes = 1;
    args.quorum_peers = vec!["https://127.0.0.1:65520".into()];
    for interval in [1, 0] {
        args.catchup_interval_secs = interval;
        let bs = bootstrap_serve(&path, &args, &keyword_config())
            .await
            .unwrap();
        let conn = &bs.db_state.lock().await.0;
        assert_eq!(
            ai_memory::federation::erasure_outbox::is_drainable(conn),
            interval > 0,
            "the admission marker must match the replay worker, including restart positive -> zero"
        );
        for task in bs.task_handles {
            task.abort();
            let _ = task.await;
        }
        // Stop replay only after checking bootstrap, so admission can be observed
        // deterministically without racing its delivery of these probe erasures.
        for surface in ["cli", "mcp"] {
            let id = uuid::Uuid::new_v4().to_string();
            let now = chrono::Utc::now().to_rfc3339();
            let row = ai_memory::models::Memory {
                id: id.clone(),
                title: id.clone(),
                namespace: "erasure4067".into(),
                content: "erasable probe".into(),
                created_at: now.clone(),
                updated_at: now,
                ..Default::default()
            };
            ai_memory::db::insert(conn, &row).unwrap();
            erase_through_surface(&path, &id, surface);
            assert!(
                ai_memory::db::get(conn, &id).unwrap().is_none(),
                "{surface}: local erasure must complete"
            );
            let queued: i64 = conn.query_row("SELECT COUNT(*) FROM federation_push_dlq WHERE memory_id = ?1 AND replayed_at IS NULL", [&id], |row| row.get(0)).unwrap();
            assert_eq!(
                queued,
                i64::from(interval > 0),
                "{surface}: only a configured replay worker permits queueing"
            );
        }
    }
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires dedicated AI_MEMORY_TEST_POSTGRES_URL"]
async fn shutdown_certifies_active_postgres_head_4070() {
    if isolated_child("shutdown_certifies_active_postgres_head_4070") {
        return;
    }
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL")
        .expect("dedicated PostgreSQL database required");
    let _sandbox = ai_memory::identity::test_key_dir::install();
    let directory = tempfile::tempdir().unwrap();
    let custody = directory.path().join("witness");
    let key =
        ai_memory::identity::keypair::generate(ai_memory::governance::audit::WITNESS_KEY_LABEL)
            .unwrap();
    ai_memory::identity::keypair::save(&key, &custody).unwrap();
    // SAFETY: isolated child owns witness custody and all env readers.
    unsafe {
        std::env::set_var(ai_memory::governance::audit::WITNESS_KEY_DIR_ENV, &custody);
        std::env::set_var(
            ai_memory::governance::audit::WITNESS_PUBKEY_ENV,
            key.public_base64(),
        );
    }
    let pg = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) FROM signed_events")
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
    let prior: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM checkpoints WHERE condition_type = 'audit_head_witness'",
    )
    .fetch_one(pg.pool())
    .await
    .unwrap();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut args = bind_failure_args();
    args.port = occupied.local_addr().unwrap().port();
    args.store_url = Some(url);
    let error = serve(
        directory.path().join("empty-sidecar.db"),
        args,
        &keyword_config(),
    )
    .await
    .unwrap_err();
    assert!(error.is::<FatalShutdownError>());
    assert!(
        error.to_string().contains("daemon server setup failed"),
        "{error:#}"
    );
    let after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM checkpoints WHERE condition_type = 'audit_head_witness'",
    )
    .fetch_one(pg.pool())
    .await
    .unwrap();
    assert!(
        after > prior,
        "shutdown witnessed the sidecar instead of the active PostgreSQL head"
    );
}

fn erase_through_surface(path: &std::path::Path, id: &str, surface: &str) {
    if surface == "cli" {
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let mut out = ai_memory::cli::io_writer::CliOutput::from_std(&mut stdout, &mut stderr);
        ai_memory::cli::crud::cmd_delete(
            path,
            &ai_memory::cli::crud::DeleteArgs {
                id: id.into(),
                capability: None,
                capability_file: None,
                hard: false,
            },
            true,
            None,
            &mut out,
        )
        .unwrap();
        return;
    }
    let init = serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
        "protocolVersion":"2024-11-05", "capabilities":{}, "clientInfo":{"name":"erasure4067","version":"1"}
    }});
    let call = serde_json::json!({"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{
        "name":"memory_delete", "arguments":{"id":id}
    }});
    let result = assert_cmd::Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args([
            "mcp",
            "--profile",
            "full",
            "--tier",
            "keyword",
            "--db",
            path.to_str().unwrap(),
        ])
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_LOG_DIR", path.parent().unwrap().join("logs"))
        .env("AI_MEMORY_AUDIT_DIR", path.parent().unwrap().join("audit"))
        .write_stdin(format!("{init}\n{call}\n"))
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success();
    let text = String::from_utf8_lossy(&result.get_output().stdout);
    let response = text
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["id"] == 2)
        .expect("MCP tool response");
    assert!(
        response.get("error").is_none() && response["result"]["isError"] != true,
        "MCP erasure failed: {response}"
    );
}
