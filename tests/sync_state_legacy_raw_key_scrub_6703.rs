// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6703 (residual of #6101) — before #3675 the sync daemon keyed
//! `sync_state.peer_id` by the RAW peer URL, credential included. The #3675
//! heal (`rekey_peer`) only runs for a peer the daemon still cycles, and
//! #6101 / #6628 refuse a peer without a durable key before any heal, so a
//! legacy raw row of a peer that is no longer configured, or is refused,
//! kept the credential at rest (every backup, every `VACUUM INTO`).
//!
//! The sync daemon now scrubs every legacy raw-URL key once at boot: a
//! durable one is folded into its rendered key (cursors kept), any other is
//! deleted (the cursor resets; pulls are idempotent upserts, so nothing is
//! lost). `doctor` reports how many such rows remain. Deleting the cursor
//! follows 3-agent vote (6def5ab6), option A.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;

const MARKER: &str = "SECRETK6703";
const RENDERED: &str = "https://peer.example:9077/mesh";

fn scratch(tag: &str) -> TempDir {
    let root = Path::new(".local-runs").join("sync-state-scrub-6703");
    std::fs::create_dir_all(&root).expect("scratch root under .local-runs");
    tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("scratch dir")
}

/// A database holding four rows: a durable legacy raw key (userinfo and a
/// query token), a refused legacy raw key (a literal `@` after the
/// authority), a rendered key of another agent and a plain-named peer.
fn planted(dir: &TempDir) -> PathBuf {
    let db = dir.path().join("sync.db");
    let conn = ai_memory::db::open(&db).expect("seed db");
    let durable = format!("https://alice:{MARKER}@peer.example:9077/mesh?token={MARKER}");
    let refused = format!("https://svc:123/{MARKER}@peer.example/mesh");
    for (agent, peer, at) in [
        ("me-6703", durable.as_str(), "2026-09-01T00:00:00Z"),
        ("me-6703", refused.as_str(), "2026-09-02T00:00:00Z"),
        ("other-6703", RENDERED, "2026-09-03T00:00:00Z"),
        ("me-6703", "peer-1", "2026-09-04T00:00:00Z"),
    ] {
        ai_memory::db::sync_state_observe(&conn, agent, peer, at).expect("plant row");
    }
    db
}

fn rows(db: &Path) -> Vec<(String, String, String)> {
    let conn = Connection::open(db).expect("open");
    let mut stmt = conn
        .prepare(
            "SELECT agent_id, peer_id, last_seen_at FROM sync_state ORDER BY agent_id, peer_id",
        )
        .expect("prepare");
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

/// `doctor --json` against `db`: (the Sync section, stdout + stderr).
fn doctor_sync(dir: &TempDir, db: &Path) -> (Value, String) {
    let keys = dir.path().join("keys");
    std::fs::create_dir_all(&keys).expect("key dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("AI_MEMORY_AUDIT_DIR", dir.path().join("audit"))
        .arg("--db")
        .arg(db)
        .args(["doctor", "--json"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run doctor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let all = format!("{stdout}\n{}", String::from_utf8_lossy(&out.stderr));
    let report: Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("parse: {e}\n{all}"));
    let sync = report["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|s| s["name"].as_str() == Some("Sync"))
        .unwrap_or_else(|| panic!("no Sync section in {report}"))
        .clone();
    (sync, all)
}

fn fact(section: &Value, key: &str) -> Option<String> {
    section["facts"]
        .as_array()?
        .iter()
        .find(|f| f[0].as_str() == Some(key))
        .and_then(|f| f[1].as_str().map(str::to_string))
}

#[test]
fn doctor_counts_legacy_raw_peer_keys_without_echoing_them_6703() {
    let dir = scratch("doctor");
    let db = planted(&dir);
    let (sync, all) = doctor_sync(&dir, &db);
    assert_eq!(
        fact(&sync, "legacy_raw_peer_keys").as_deref(),
        Some("2"),
        "#6703: doctor does not count the legacy raw-URL keys: {sync}"
    );
    assert_ne!(
        sync["severity"].as_str(),
        Some("info"),
        "#6703: a credential at rest is reported as healthy: {sync}"
    );
    assert!(
        !all.contains(MARKER),
        "#6703: doctor echoes a raw key:\n{all}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_daemon_boot_scrubs_legacy_raw_peer_keys_6703() {
    let dir = scratch("boot");
    let db = planted(&dir);
    let shutdown = Arc::new(tokio::sync::Notify::new());
    // A stored permit: the loop returns after its first (peer-less) pass.
    shutdown.notify_one();
    ai_memory::daemon_runtime::run_sync_daemon_with_shutdown_using_client(
        reqwest::Client::new(),
        db.clone(),
        "me-6703".into(),
        Vec::new(),
        None,
        1,
        10,
        shutdown,
    )
    .await
    .expect("sync daemon boots and shuts down");
    let after = rows(&db);
    assert!(
        after.iter().all(|(_, peer, _)| !peer.contains(MARKER)),
        "#6703: a legacy raw credential key survived the boot scrub: {after:?}"
    );
    let want = vec![
        (
            "me-6703".to_string(),
            RENDERED.to_string(),
            "2026-09-01T00:00:00Z".to_string(),
        ),
        (
            "me-6703".to_string(),
            "peer-1".to_string(),
            "2026-09-04T00:00:00Z".to_string(),
        ),
        (
            "other-6703".to_string(),
            RENDERED.to_string(),
            "2026-09-03T00:00:00Z".to_string(),
        ),
    ];
    assert_eq!(
        after, want,
        "#6703: the durable row must fold into its rendered key with its cursor, the refused \
         row must go, and unrelated rows must stay"
    );
    let (sync, _) = doctor_sync(&dir, &db);
    assert_eq!(fact(&sync, "legacy_raw_peer_keys").as_deref(), Some("0"));
}
