// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3718 — head-compilable proof through the binary (a fresh process per
//! verb, so the in-memory key cache is empty exactly as after a restart):
//! store a sealed row, delete the agent's `.x25519.priv`, `get` the row.
//! The read must fail WITHOUT creating any file under the key directory
//! and without touching the row.
//!
//! FAILS ON THE PARENT: the read mints a new `<agent>.x25519.{priv,pub}`
//! before failing ("no new x25519 file" is the assertion that catches it).
//!
//! SCOPE (ruling on #3354 × #3718): the contract here is ENCRYPTION key
//! material — a refused read or seal must not mint a fresh x25519 seal key
//! that forks the key generation and strands every row sealed under the
//! first one. The listing assertions therefore compare the x25519 material
//! only (`seal_material`). #3354 mints the resolved agent's Ed25519 *audit
//! signing* pair on the first ledger-writing verb so the refusal's audit row
//! is signed rather than silently unsigned; that pair is a different key for
//! a different purpose, cannot strand a sealed row, and is permitted here.
//! The precise `!priv_path.exists()` assertion is the one that pins the
//! forked generation and is deliberately untouched.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

const AGENT: &str = "agent-3718-head";
const PRIV_SUFFIX: &str = ".x25519.priv";
const PUB_SUFFIX: &str = ".x25519.pub";

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

/// The x25519 seal material under the key dir — the ONLY material #3718's
/// contract is about. The Ed25519 audit signing pair #3354 mints on a
/// ledger-writing verb (`<agent>.priv` / `<agent>.pub`, no `.x25519`
/// infix) is deliberately excluded: it records the refusal, it does not
/// seal anything, and it cannot fork the seal-key generation.
fn seal_material(dir: &Path) -> BTreeSet<String> {
    listing(dir)
        .into_iter()
        .filter(|name| name.ends_with(PRIV_SUFFIX) || name.ends_with(PUB_SUFFIX))
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
    let before = seal_material(&key_dir);

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
        seal_material(&key_dir),
        before,
        "#3718: the read must not create seal key material under the key dir \
         (the Ed25519 audit signing pair #3354 may mint is not seal material)"
    );
    assert!(!priv_path.exists(), "no impostor .priv minted");
    assert_eq!(
        raw_row(&db, &id),
        (env_before, content_before),
        "row untouched"
    );
}

/// #3718 (review) — the SEAL path over a corpus that already holds sealed
/// rows for the agent, with the key dir wiped: the write must REFUSE (the key
/// was lost; a new one would strand row one), mint NO file, and write NO row.
/// On the pre-fix head the second `store` minted a fresh key and succeeded —
/// forking the key generation — which is what this case pins against. Then
/// the fresh-agent counterpart: a wiped key dir with NO sealed rows mints
/// normally (a different agent id, in the same store).
#[test]
fn cli_store_over_sealed_rows_with_wiped_key_dir_refuses_and_mints_nothing_3718() {
    let root = tempfile::tempdir().expect("scratch under TMPDIR");
    let key_dir = key_dir_0700(root.path());
    let db = root.path().join("store.db");

    let out = cmd(root.path(), &db)
        .args([
            "--json",
            "store",
            "-T",
            "row one",
            "--content",
            "sealed row one (#3718)",
        ])
        .output()
        .expect("run store");
    assert!(
        out.status.success(),
        "first store must succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stored: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let first = stored["id"].as_str().expect("id").to_string();
    let priv_path = key_dir.join(format!("{AGENT}{PRIV_SUFFIX}"));
    assert!(priv_path.is_file(), "the first seal minted the live key");
    let row_first = raw_row(&db, &first);
    assert!(row_first.0.is_some(), "row one is sealed");

    // Wipe the agent's key material (a new process starts with an empty cache).
    for name in listing(&key_dir) {
        if name.starts_with(AGENT) {
            std::fs::remove_file(key_dir.join(name)).expect("wipe key material");
        }
    }
    let before = seal_material(&key_dir);

    let out = cmd(root.path(), &db)
        .args([
            "--json",
            "store",
            "-T",
            "row two",
            "--content",
            "sealed row two (#3718)",
        ])
        .output()
        .expect("run store");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "#3718: a seal over sealed rows with no key must refuse, not mint: {err}"
    );
    assert!(
        !err.contains(&key_dir.display().to_string()),
        "the caller never sees the key path: {err}"
    );
    assert_eq!(
        seal_material(&key_dir),
        before,
        "#3718: the refused seal minted no seal key material (the Ed25519 \
         audit signing pair #3354 mints to sign the refusal's ledger row is \
         permitted: a different key for a different purpose, it cannot \
         strand a sealed row)"
    );
    assert!(!priv_path.exists(), "no impostor .priv minted");
    let conn = rusqlite::Connection::open(&db).expect("open db");
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = 'row two'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(n, 0, "the refused write left no row");
    assert_eq!(raw_row(&db, &first), row_first, "row one untouched");

    // A FRESH agent (no sealed rows) with the same wiped key dir mints
    // normally: the guard is about lost keys, not about first writes.
    let fresh = "agent-3718-head-fresh";
    let out = cmd(root.path(), &db)
        .env("AI_MEMORY_AGENT_ID", fresh)
        .args([
            "--json",
            "store",
            "-T",
            "fresh row",
            "--content",
            "fresh agent row (#3718)",
        ])
        .output()
        .expect("run store");
    assert!(
        out.status.success(),
        "a fresh agent's first seal mints normally: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        key_dir.join(format!("{fresh}{PRIV_SUFFIX}")).is_file(),
        "the fresh agent's key was minted"
    );
}
