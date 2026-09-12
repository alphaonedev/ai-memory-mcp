// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Offline CLI regressions for URL credentials in issue #3667.
//!
//! Every child runs with a cleared environment so the host's `AI_MEMORY_*`
//! configuration cannot mask or cause a leak. `LLVM_PROFILE_FILE` (coverage
//! runs) and `TMPDIR` (scratch must never fall back to a system tmpfs) are
//! forwarded explicitly.

use assert_cmd::Command;

/// Variables a hermetic child still needs from the harness.
const FORWARDED_ENV: [&str; 2] = ["LLVM_PROFILE_FILE", "TMPDIR"];

/// A cleared-environment `ai-memory` invocation rooted at `home`.
fn hermetic_cmd(home: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    cmd.env_clear()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("HOME", home)
        .env("AI_MEMORY_KEY_DIR", home.join("keys"));
    for name in FORWARDED_ENV {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd
}

fn issue_3667_init_db(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let db = dir.join(name);
    hermetic_cmd(dir)
        .arg("--db")
        .arg(&db)
        .arg("stats")
        .assert()
        .success();
    db
}

#[test]
fn issue_3667_url_shaped_db_refusal_is_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let url = "postgres://u:AUTH_CANARY@db/m?%70assword=QUERY_CANARY&password=SECOND_CANARY";
    let output = hermetic_cmd(dir.path())
        .args(["--db", url, "doctor", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("filesystem path"), "{stderr}");
    for secret in ["AUTH_CANARY", "QUERY_CANARY", "SECOND_CANARY"] {
        assert!(!stderr.contains(secret), "{stderr}");
    }
}

#[cfg(feature = "sal-postgres")]
#[test]
fn issue_3667_doctor_postgres_json_and_text_redact_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let db = issue_3667_init_db(dir.path(), "doctor.db");
    // Invalid port guarantees rejection before DNS, sockets or pgpass lookup.
    let url = "postgres://u:AUTH_CANARY@localhost:invalid/m?%70assword=QUERY_CANARY&password=SECOND_CANARY";
    for json in [false, true] {
        let mut cmd = hermetic_cmd(dir.path());
        cmd.env("AI_MEMORY_STORE_URL", url)
            .arg("--db")
            .arg(&db)
            .arg("doctor");
        if json {
            cmd.arg("--json");
        }
        let output = cmd.output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stdout.contains("Postgres extensions (#3264)"),
            "{stdout} {stderr}"
        );
        if json {
            serde_json::from_str::<serde_json::Value>(&stdout).unwrap();
        }
        for secret in ["AUTH_CANARY", "QUERY_CANARY", "SECOND_CANARY"] {
            assert!(!stdout.contains(secret), "{stdout}");
            assert!(!stderr.contains(secret), "{stderr}");
        }
    }
}

#[test]
fn issue_3667_doctor_provider_json_and_text_redact_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let db = issue_3667_init_db(dir.path(), "provider.db");
    let url =
        "https://u:AUTH_CANARY@localhost:invalid/m?%70assword=QUERY_CANARY&password=SECOND_CANARY";
    for json in [false, true] {
        let mut cmd = hermetic_cmd(dir.path());
        cmd.env("AI_MEMORY_LLM_BASE_URL", url)
            .env("AI_MEMORY_LLM_BACKEND", "openai-compatible")
            .env("AI_MEMORY_LLM_MODEL", "synthetic-model")
            .arg("--db")
            .arg(&db)
            .arg("doctor");
        if json {
            cmd.arg("--json");
        }
        let output = cmd.output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stdout.contains("LLM Reachability"), "{stdout} {stderr}");
        assert!(
            stdout.contains("localhost:invalid"),
            "provider URL must be present: {stdout}"
        );
        if json {
            serde_json::from_str::<serde_json::Value>(&stdout).unwrap();
        }
        for secret in ["AUTH_CANARY", "QUERY_CANARY", "SECOND_CANARY"] {
            assert!(!stdout.contains(secret), "{stdout}");
            assert!(!stderr.contains(secret), "{stderr}");
        }
    }
}
