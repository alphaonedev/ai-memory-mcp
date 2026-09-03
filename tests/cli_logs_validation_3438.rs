// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn logs_accepts_valid_bounds_and_refuses_unparseable_or_ignored_options_3438() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("ai-memory.log.2026-09-03"),
        "2026-09-03T12:00:00Z level=INFO ready\n",
    )
    .unwrap();

    let allowed = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args([
            "logs",
            "cat",
            "--log-dir",
            dir.path().to_str().unwrap(),
            "--since",
            "2026-09-03T00:00:00Z",
            "--until",
            "2026-09-04",
            "--level",
            "INFO",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(
        allowed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let line: serde_json::Value = serde_json::from_slice(&allowed.stdout).unwrap();
    assert_eq!(line["line"], "2026-09-03T12:00:00Z level=INFO ready");

    for denied_args in [
        vec!["logs", "cat", "--since", "not-a-timestamp"],
        vec!["logs", "cat", "--format", "yaml"],
        vec!["logs", "cat", "--level", "verbose"],
        vec!["logs", "tail", "--follow-interval-ms", "50"],
        vec!["logs", "tail", "--follow", "--follow-interval-ms", "0"],
    ] {
        let denied = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .args(denied_args)
            .output()
            .unwrap();
        assert_eq!(
            denied.status.code(),
            Some(2),
            "stdout: {}; stderr: {}",
            String::from_utf8_lossy(&denied.stdout),
            String::from_utf8_lossy(&denied.stderr)
        );
    }

    let ignored_on_mutation = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args([
            "logs",
            "archive",
            "--log-dir",
            dir.path().to_str().unwrap(),
            "--since",
            "2026-09-03",
        ])
        .output()
        .unwrap();
    assert!(!ignored_on_mutation.status.success());
    assert!(
        String::from_utf8_lossy(&ignored_on_mutation.stderr)
            .contains("apply only to `logs tail` and `logs cat`")
    );
}
