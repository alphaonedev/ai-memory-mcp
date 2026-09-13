// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3718 — head-compilable proof through the binary (a fresh process per
//! verb, so the in-memory key cache is empty exactly as after a restart):
//! store a sealed row, delete the agent's `.x25519.priv`, `get` the row.
//! The read must fail WITHOUT creating any file under the key directory
//! and without touching the row.
//!
//! FAILS ON THE PARENT: the read mints a new `<agent>.x25519.{priv,pub}`
//! before failing ("no new file" is the assertion that catches it).

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

const AGENT: &str = "agent-3718-head";
const PRIV_SUFFIX: &str = ".x25519.priv";

fn key_dir_0700(root: &Path) -> std::path::PathBuf {
    let dir = root.join("keys");
    std::fs::create_dir_all(&dir).expect("mkdir key dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 key dir");
    }
    dir
}

fn cmd(root: &Path, db: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    c.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", root.join("keys"))
        .env("AI_MEMORY_AUDIT_DIR", root.join("audit"))
        .env("AI_MEMORY_ENCRYPT_AT_REST", "1")
        .env("AI_MEMORY_AGENT_ID", AGENT)
        .arg("--db")
        .arg(db);
    c
}

fn listing(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("list key dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect()
}

fn raw_row(db: &Path, id: &str) -> (Option<Vec<u8>>, String) {
    let conn = rusqlite::Connection::open(db).expect("open db for the assertion");
    conn.query_row(
        "SELECT encrypted_envelope, content FROM memories WHERE id = ?1",
        rusqlite::params![id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("raw row")
}

#[test]
fn cli_read_with_absent_key_creates_no_file_and_leaves_the_row_3718() {
    let root = tempfile::tempdir().expect("scratch under TMPDIR");
    let key_dir = key_dir_0700(root.path());
    let db = root.path().join("store.db");

    let out = cmd(root.path(), &db)
        .args([
            "--json",
            "store",
            "-T",
            "sealed row",
            "--content",
            "secret content sealed at rest (#3718)",
        ])
        .output()
        .expect("run store");
    assert!(
        out.status.success(),
        "store must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stored: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let id = stored["id"].as_str().expect("id").to_string();

    let priv_path = key_dir.join(format!("{AGENT}{PRIV_SUFFIX}"));
    assert!(priv_path.is_file(), "the seal minted the live key");
    let (env_before, content_before) = raw_row(&db, &id);
    assert!(env_before.is_some(), "the row is sealed");
    std::fs::remove_file(&priv_path).expect("delete .priv");
    let before = listing(&key_dir);

    let out = cmd(root.path(), &db)
        .args(["get", &id])
        .output()
        .expect("run get");
    assert!(
        !out.status.success(),
        "a read with the key missing must fail"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains(&key_dir.display().to_string()),
        "the caller never sees the key path: {err}"
    );

    assert_eq!(
        listing(&key_dir),
        before,
        "#3718: the read must not create key material under the key dir"
    );
    assert!(!priv_path.exists(), "no impostor .priv minted");
    assert_eq!(
        raw_row(&db, &id),
        (env_before, content_before),
        "row untouched"
    );
}
