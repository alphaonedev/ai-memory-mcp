// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #5084 — runs the closed-world gate `scripts/check-sqlite-write-txn-immediate.py`
//! (and its `--self-test`) from `cargo test`, so a DEFERRED production
//! transaction fails the suite without a CI workflow edit.

use std::path::Path;
use std::process::Command;

fn run(args: &[&str]) -> (bool, String) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3")
        .arg(root.join("scripts/check-sqlite-write-txn-immediate.py"))
        .args(args)
        .arg("--root")
        .arg(root)
        .output()
        .expect("python3 must be available to run the #5084 gate");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn no_deferred_production_write_txn_in_src_5084() {
    let (ok, text) = run(&[]);
    assert!(ok, "DEFERRED production transaction(s) in src/:\n{text}");
}

#[test]
fn deferred_txn_gate_self_test_passes_5084() {
    let (ok, text) = run(&["--self-test"]);
    assert!(ok, "gate self-test failed:\n{text}");
}
