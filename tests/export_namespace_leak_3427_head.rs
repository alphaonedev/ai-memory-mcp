// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3427 — the HEAD proof. This file is copied verbatim onto a pristine
//! release-head worktree (f0175b709) and run there, so it uses ONLY API that
//! exists on the head: `bootstrap_serve` + the pre-existing in-process
//! `serve_http_with_shutdown_future` harness, plain http (on the head a
//! plaintext listener boots; under the #3705 mandate branch the same test
//! must be driven over TLS — this file is deliberately the head-shaped one).
//!
//! On the head both tests FAIL:
//! - `export_namespace_filter_is_honoured_3427_head`: `GET
//!   /api/v1/export?namespace=A` returns BOTH namespaces (`count == 2`) —
//!   the query was silently ignored and the whole corpus dumped.
//! - `bulk_invalid_kind_is_validation_failed_3427_head`: the per-row error
//!   for `kind: "nonsense"` is classed `INTERNAL_ERROR`.
//! On the fixed branch both pass.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ai_memory::config::{AdminConfig, AppConfig};
use ai_memory::daemon_runtime::{ServeArgs, bootstrap_serve, serve_http_with_shutdown_future};
use tokio::sync::Notify;

const ADMIN: &str = "ops:admin-3427";
const READY_TIMEOUT: Duration = Duration::from_secs(20);

fn serve_args(port: u16) -> ServeArgs {
    ServeArgs {
        host: "127.0.0.1".to_string(),
        port,
        tls_cert: None,
        tls_key: None,
        mtls_allowlist: None,
        shutdown_grace_secs: 5,
        quorum_writes: 0,
        quorum_peers: vec![],
        quorum_timeout_ms: 2000,
        quorum_client_cert: None,
        quorum_client_key: None,
        quorum_ca_cert: None,
        catchup_interval_secs: 30,
        federation_identity: None,
        #[cfg(feature = "sal")]
        store_url: None,
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// A booted loopback daemon (admin allowlist = [`ADMIN`]) and its base URL.
struct Daemon {
    base: String,
    shutdown: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

async fn boot() -> Daemon {
    // Permissive attestation so plain JSON seeds land on the head fixture
    // exactly as tests/common does. SAFETY: set before the daemon's worker
    // tasks exist; this test binary has no other env reader racing it.
    unsafe {
        std::env::set_var("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    }
    let dir = tempfile::tempdir().expect("tempdir under TMPDIR");
    let db_path = dir.path().join("head-3427.db");
    let port = free_port();
    let mut cfg = AppConfig::default();
    cfg.tier = Some("keyword".to_string());
    cfg.admin = Some(AdminConfig {
        agent_ids: vec![ADMIN.to_string()],
    });
    let boot = bootstrap_serve(&db_path, &serve_args(port), &cfg)
        .await
        .expect("bootstrap_serve on loopback");
    let addr = format!("127.0.0.1:{port}");
    let shutdown = Arc::new(Notify::new());
    let shutdown_for_task = shutdown.clone();
    let addr_for_task = addr.clone();
    let task = tokio::spawn(async move {
        let _ = serve_http_with_shutdown_future(
            &addr_for_task,
            boot.api_key_state,
            boot.app_state,
            async move { shutdown_for_task.notified().await },
        )
        .await;
    });
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Ok(resp) = client.get(format!("{base}/api/v1/health")).send().await
            && resp.status().is_success()
        {
            break;
        }
        assert!(Instant::now() < deadline, "daemon never became ready");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Daemon {
        base,
        shutdown,
        task,
        _dir: dir,
    }
}

async fn stop(d: Daemon) {
    d.shutdown.notify_one();
    let _ = tokio::time::timeout(Duration::from_secs(10), d.task).await;
}

async fn seed(client: &reqwest::Client, base: &str, namespace: &str, title: &str) {
    let resp = client
        .post(format!("{base}/api/v1/memories"))
        .header("x-agent-id", ADMIN)
        .json(&serde_json::json!({
            "namespace": namespace,
            "title": title,
            "content": format!("content for {title}"),
        }))
        .send()
        .await
        .expect("seed request");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "seed {namespace}/{title} must succeed: {status} {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn export_namespace_filter_is_honoured_3427_head() {
    let d = boot().await;
    let client = reqwest::Client::new();
    seed(&client, &d.base, "ns-a-3427", "in-a").await;
    seed(&client, &d.base, "ns-b-3427", "in-b").await;
    let resp = client
        .get(format!("{}/api/v1/export?namespace=ns-a-3427", d.base))
        .header("x-agent-id", ADMIN)
        .send()
        .await
        .expect("export request");
    let status = resp.status();
    let v: serde_json::Value = resp.json().await.expect("export answers JSON");
    stop(d).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(
        v["count"], 1,
        "GET /api/v1/export?namespace=ns-a-3427 must return ONLY that namespace: {v}"
    );
    let rows = v["memories"].as_array().expect("memories array");
    assert_eq!(rows.len(), 1, "{v}");
    assert!(
        rows.iter().all(|m| m["namespace"] == "ns-a-3427"),
        "a row from another namespace leaked: {v}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bulk_invalid_kind_is_validation_failed_3427_head() {
    let d = boot().await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/memories/bulk", d.base))
        .header("x-agent-id", ADMIN)
        .json(&serde_json::json!([{
            "namespace": "bulk-kind-3427",
            "title": "bad kind",
            "content": "body",
            "kind": "nonsense",
        }]))
        .send()
        .await
        .expect("bulk request");
    let status = resp.status();
    let v: serde_json::Value = resp.json().await.expect("bulk answers JSON");
    stop(d).await;
    assert_eq!(v["created"], 0, "status {status}: {v}");
    let errors = v["errors"].as_array().expect("errors array");
    assert_eq!(errors.len(), 1, "{v}");
    assert_eq!(
        errors[0]["code"], "VALIDATION_FAILED",
        "an invalid kind is a validation failure, never INTERNAL_ERROR: {v}"
    );
}
