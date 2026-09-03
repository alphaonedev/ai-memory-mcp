// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "sal")]

use std::process::Command;

#[test]
fn migrate_dry_run_does_not_create_destination_3435() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.db");
    let destination = dir.path().join("missing-destination.db");
    drop(ai_memory::db::open(&source).unwrap());

    let output = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args([
            "migrate",
            "--from",
            &format!("sqlite://{}", source.display()),
            "--to",
            &format!("sqlite://{}", destination.display()),
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !destination.exists(),
        "migrate --dry-run must not create its destination"
    );
}
