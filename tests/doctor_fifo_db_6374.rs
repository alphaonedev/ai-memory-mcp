// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6374 (WP-EGRESS #6053) — `ai-memory doctor --db <FIFO>` must fail with
//! exit 2 like every other corrupt input, never hang.
//!
//! `open_existing_read_only` only checked `try_exists`, which is true for a
//! named pipe; SQLite's `open(2)` of a FIFO with no writer blocks forever.
//! The cell runs the real binary under a hard timeout.

#![cfg(unix)]

use std::time::Duration;

use assert_cmd::Command;
use tempfile::TempDir;

#[test]
fn doctor_on_a_fifo_db_exits_2_without_hanging_6374() {
    let dir = TempDir::new().expect("tempdir");
    let fifo = dir.path().join("pipe.db");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(made.success(), "fixture: mkfifo");
    let keys = dir.path().join("keys-6374");
    std::fs::create_dir_all(&keys).expect("key sandbox");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let out = Command::cargo_bin("ai-memory")
        .expect("ai-memory binary")
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .args([
            "--db",
            fifo.to_str().expect("utf8 path"),
            "doctor",
            "--json",
        ])
        .timeout(Duration::from_secs(20))
        .output()
        .expect("#6374: doctor must return, not hang on a FIFO --db");
    assert_eq!(
        out.status.code(),
        Some(2),
        "#6374: a FIFO --db is a corrupt input -> exit 2.\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
