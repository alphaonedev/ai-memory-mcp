// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Offline packaging and installer fault injection through the shipped script.
#![cfg(unix)]

#[test]
fn install_upgrade_packaging_contracts_4077_4080_4082_4084() {
    let result = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/test-install-upgrade.py"
        ))
        .output()
        .expect("python3 is required for installer regression tests");
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
