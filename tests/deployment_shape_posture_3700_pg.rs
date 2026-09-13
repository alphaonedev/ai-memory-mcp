// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3700 — PostgreSQL twin of `tests/deployment_shape_posture_3700.rs`: the
//! agent-registry shape signal is read from the REAL store of the
//! deployment, so a two-agent registry on PostgreSQL makes the daemon
//! fleet-shaped exactly like one on sqlite. Runs only with a live database
//! (`AI_MEMORY_TEST_POSTGRES_URL`; a FRESH `ai_memory_f2a_*` db — never the
//! operator's `ai_memory_test`), in a per-test schema that is dropped on
//! exit; prints a SKIP line otherwise. Both tests FAIL on the pre-fix head
//! `f0175b709`: the daemon boots healthy in both postures and never prints
//! a `#3700` line.

#![cfg(feature = "sal-postgres")]
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use std::io::{BufRead as _, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ai_memory::models::AgentRegistration;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

mod common;
use common::free_port;
use common::postgres_env::PostgresTestEnv;

const BOOT_DEADLINE: Duration = Duration::from_secs(45);
const PROBE_INTERVAL: Duration = Duration::from_millis(100);
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

fn command(root: &Path, store_url: &str) -> Command {
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).expect("mkdir key sandbox");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 key sandbox");
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("AI_MEMORY_KEY_DIR", keys)
        .env("AI_MEMORY_DB", root.join("store.db"))
        .env("AI_MEMORY_AUDIT_DIR", root.join("audit"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("RUST_LOG", "error")
        .env("AI_MEMORY_STORE_URL", store_url);
    cmd
}

fn health_is_200(port: u16) -> bool {
    let client = reqwest::blocking::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .build()
        .expect("client");
    client
        .get(format!("http://127.0.0.1:{port}/api/v1/health"))
        .send()
        .is_ok_and(|r| r.status().is_success())
}

enum BootOutcome {
    Exited {
        status: std::process::ExitStatus,
        stderr: String,
    },
    Healthy {
        stderr: String,
    },
}

/// Spawn `serve --port <free>` against the postgres store and drive it to
/// an exit or a healthy `/health` (then kill), capturing stderr.
fn boot_on_loopback(root: &Path, store_url: &str, extra_env: &[(&str, &str)]) -> BootOutcome {
    let port = free_port();
    let mut cmd = command(root, store_url);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .args(["serve", "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let reader = child.stderr.take().map(|err| {
        let sink = std::sync::Arc::clone(&buf);
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                let mut g = sink.lock().unwrap();
                g.push_str(&line);
                g.push('\n');
            }
        })
    });
    let deadline = Instant::now() + BOOT_DEADLINE;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            if let Some(h) = reader {
                let _ = h.join();
            }
            let stderr = buf.lock().unwrap().clone();
            return BootOutcome::Exited { status, stderr };
        }
        if health_is_200(port) {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(h) = reader {
                let _ = h.join();
            }
            let stderr = buf.lock().unwrap().clone();
            return BootOutcome::Healthy { stderr };
        }
        assert!(
            Instant::now() < deadline,
            "serve neither exited nor became healthy within {BOOT_DEADLINE:?}; stderr:\n{}",
            buf.lock().unwrap()
        );
        std::thread::sleep(PROBE_INTERVAL);
    }
}

/// Register two agents in the per-test schema through the SAL store (the
/// same registry `bootstrap_serve` reads on a postgres deployment).
async fn seed_two_agents(url: &str, run: &str) {
    let store = PostgresStore::connect(url).await.expect("connect");
    let ctx = CallerContext::for_agent("ai:shape-seed-3700");
    let now = chrono::Utc::now().to_rfc3339();
    for suffix in ["alpha", "bravo"] {
        let agent = AgentRegistration {
            agent_id: format!("ai:shape-{suffix}-{run}"),
            agent_type: "worker".to_string(),
            capabilities: Vec::new(),
            registered_at: now.clone(),
            last_seen_at: now.clone(),
        };
        store
            .register_agent(&ctx, &agent)
            .await
            .expect("register agent");
    }
    let listed = store.list_agents().await.expect("list agents");
    assert_eq!(
        listed.len(),
        2,
        "the seed must be visible to the registry read"
    );
}

/// A two-agent registry on PostgreSQL with the selector UNSET: the shape is
/// learned after the store opens, nothing can be pinned, so the boot REFUSES
/// naming the registry signal and both one-line choices.
///
/// FAILS ON HEAD: the daemon boots healthy (the `Healthy` arm panics).
#[tokio::test(flavor = "multi_thread")]
async fn pg_fleet_by_agent_registry_after_open_refuses_by_omission_3700() {
    let Some(env) = PostgresTestEnv::new("shape_refuse_3700").await else {
        eprintln!("SKIP deployment_shape_posture_3700_pg: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let run = uuid::Uuid::new_v4().simple().to_string();
    seed_two_agents(env.url(), &run).await;
    let root = tempfile::tempdir().unwrap();
    let url = env.url().to_string();
    let root_path = root.path().to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || boot_on_loopback(&root_path, &url, &[]))
        .await
        .expect("boot task");
    let err = match outcome {
        BootOutcome::Exited { status, stderr } => {
            assert!(!status.success(), "must refuse; stderr:\n{stderr}");
            stderr
        }
        BootOutcome::Healthy { stderr } => {
            panic!(
                "a two-agent postgres registry under standard-by-omission must refuse:\n{stderr}"
            )
        }
    };
    assert!(err.contains("#3700"), "{err}");
    assert!(err.contains("agent_registry"), "{err}");
    assert!(err.contains("by OMISSION"), "{err}");
    assert!(err.contains("AI_MEMORY_REQUIRE_WITNESS unset"), "{err}");
    assert!(err.contains("AI_MEMORY_SECURITY_PROFILE=asi-hard"), "{err}");
    assert!(err.contains("AI_MEMORY_SECURITY_PROFILE=standard"), "{err}");
}

/// The same registry under an EXPLICIT `standard`: boots healthy on the
/// postgres store, warns exactly ONCE (the registry-derived exception is
/// warned and recorded after the store opens).
///
/// FAILS ON HEAD: the daemon boots but never prints `WARN #3700`
/// (`assert_eq!(warns, 1)` fails).
#[tokio::test(flavor = "multi_thread")]
async fn pg_fleet_explicit_standard_boots_and_warns_once_3700() {
    let Some(env) = PostgresTestEnv::new("shape_warn_3700").await else {
        eprintln!("SKIP deployment_shape_posture_3700_pg: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let run = uuid::Uuid::new_v4().simple().to_string();
    seed_two_agents(env.url(), &run).await;
    let root = tempfile::tempdir().unwrap();
    let url = env.url().to_string();
    let root_path = root.path().to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        boot_on_loopback(
            &root_path,
            &url,
            &[("AI_MEMORY_SECURITY_PROFILE", "standard")],
        )
    })
    .await
    .expect("boot task");
    let err = match outcome {
        BootOutcome::Healthy { stderr } => stderr,
        BootOutcome::Exited { status, stderr } => {
            panic!("explicit standard must boot on postgres; exited {status}; stderr:\n{stderr}")
        }
    };
    let warns = err.matches("WARN #3700").count();
    assert_eq!(warns, 1, "exactly one warning, got {warns}:\n{err}");
    assert!(err.contains("agent_registry"), "{err}");
    assert!(err.contains("AI_MEMORY_SECURITY_PROFILE=standard"), "{err}");
}
