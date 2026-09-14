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
    Sandbox {
        _root: root,
        home,
        keys,
        db,
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

/// Boot a postgres-backed daemon and wait for `/health`.
fn serve(sb: &Sandbox, url: &str) -> (Daemon, u16) {
    let port = free_port();
    let child = command(sb, url)
        .args(["serve", "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let mut daemon = Daemon { child };
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client");
    let health_url = format!("http://127.0.0.1:{port}/api/v1/health");
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

#[test]
fn pg_daemon_without_key_generates_it_and_signs_the_ledger_3354() {
    let Some(url) = pg_url() else { return };
    let sb = sandbox();
    let (_daemon, port) = serve(&sb, &url);

    // The daemon generated the key for the resolved id at boot.
    let priv_path = sb.keys.join(format!("{AGENT_ID}.priv"));
    assert!(
        priv_path.is_file(),
        "signing key generated at boot for the resolved id"
    );

    // One captured turn through the HTTP surface appends a ledger row. The
    // row is keyed to the RESOLVED CALLER of the HTTP request (the L4 channel
    // stamps `metadata.agent_id` from the caller, #1413), not to the daemon's
    // own `AI_MEMORY_AGENT_ID` — so the ledger is read as a BEFORE/AFTER delta
    // over every agent, the same shape the SQLite twin asserts, instead of a
    // filter on the daemon's id that the capture row never carries.
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let before = ledger_levels(&rt, &url);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let session = format!("sess-3354-pg-{}", uuid::Uuid::new_v4().simple());
    let resp = client
        .post(format!("http://127.0.0.1:{port}/api/v1/capture_turn"))
        .json(&serde_json::json!({
            "host_session_id": session,
            "host_turn_index": 1,
            "role": "assistant",
            "content": "pg turn — its ledger row must be self_signed (#3354)",
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

    // The postgres ledger carries the NEW row signed, never unsigned.
    let after = ledger_levels(&rt, &url);
    let levels: Vec<(String, String, i64)> = after
        .iter()
        .map(|(agent, level, n)| {
            let was = before
                .iter()
                .find(|(a, l, _)| a == agent && l == level)
                .map_or(0, |(_, _, n)| *n);
            (agent.clone(), level.clone(), n - was)
        })
        .filter(|(_, _, delta)| *delta > 0)
        .collect();
    assert!(
        !levels.is_empty(),
        "the turn appended a ledger row on postgres"
    );
    assert!(
        levels.iter().all(|(_, level, _)| level != "unsigned"),
        "#3354 (pg): no unsigned row: {levels:?}"
    );
    assert!(
        levels.iter().any(|(_, level, _)| level == "self_signed"),
        "#3354 (pg): the row is self_signed (L4: the capture-turn row is signed by the resolved agent`s own key): {levels:?}"
    );
}
