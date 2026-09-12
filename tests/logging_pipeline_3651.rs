// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3651 — a log pipeline that fails must not look like one that works.
//!
//! Before #3651 the binary caught every logging-initialisation error and
//! kept running ("continuing without"), including the `syslog` sink on a
//! build without `--features syslog`, which the operator documentation
//! promises fails closed at boot. A second subscriber installation was a
//! DEBUG line and reported success. These tests drive the real binary for
//! the boot posture and hold the one in-process global-install test.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ai_memory::config::LoggingConfig;
use ai_memory::logging::{self, LogPipelineState};

/// `EX_CONFIG` from sysexits.h, the code every boot refusal exits with.
const EX_CONFIG: i32 = 78;

fn sandbox() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("create test scratch root");
    tempfile::tempdir_in(root).expect("isolated test directory")
}

/// Write `[logging]` config into an isolated HOME and run the binary there.
fn run_with_logging(home: &Path, logging_toml: &str, args: &[&str]) -> Output {
    let config_root = home.join(".config").join("ai-memory");
    std::fs::create_dir_all(&config_root).expect("create config root");
    std::fs::write(
        config_root.join("config.toml"),
        format!("schema_version = 2\ntier = \"keyword\"\n\n[logging]\n{logging_toml}"),
    )
    .expect("write config");
    let db: PathBuf = home.join("pipeline.db");
    Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env(
            "AI_MEMORY_KEY_DIR",
            ai_memory::identity::test_key_dir::install(),
        )
        .current_dir(home)
        .arg("--db")
        .arg(&db)
        .args(args)
        .output()
        .expect("run isolated CLI")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[cfg(not(feature = "syslog"))]
#[test]
fn syslog_sink_without_the_feature_refuses_boot_3651() {
    // The documented fail-closed promise, now kept: the operator asked for
    // off-host shipping, so neither a silent local fallback nor running with
    // no sink at all is acceptable.
    let home = sandbox();
    let out = run_with_logging(
        home.path(),
        "enabled = true\nsink = \"syslog\"\nsyslog_address = \"127.0.0.1:1\"\n",
        &["stats"],
    );
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(EX_CONFIG), "stderr: {err}");
    assert!(err.contains("refusing to start"), "stderr: {err}");
    assert!(err.contains("--features syslog"), "stderr: {err}");
    assert!(!err.contains("continuing without"), "stderr: {err}");
}

#[cfg(unix)]
#[test]
fn unusable_log_directory_refuses_boot_3651() {
    let home = sandbox();
    let blocker = home.path().join("blocker");
    std::fs::write(&blocker, b"a file, not a directory").expect("write blocker");
    let out = run_with_logging(
        home.path(),
        &format!(
            "enabled = true\nsink = \"file\"\nrotation = \"never\"\npath = \"{}\"\n",
            blocker.join("sub").display()
        ),
        &["stats"],
    );
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(EX_CONFIG), "stderr: {err}");
    assert!(err.contains("creating log dir"), "stderr: {err}");
    assert!(err.contains("[logging].enabled = false"), "stderr: {err}");
}

#[cfg(not(feature = "syslog"))]
#[test]
fn doctor_still_runs_and_reports_the_failed_sink_3651() {
    let home = sandbox();
    let out = run_with_logging(
        home.path(),
        "enabled = true\nsink = \"syslog\"\nsyslog_address = \"127.0.0.1:1\"\n",
        &["doctor", "--json"],
    );
    let err = stderr(&out);
    assert_ne!(
        out.status.code(),
        Some(EX_CONFIG),
        "doctor must not be refused: {err}"
    );
    assert!(err.contains("`doctor` continues"), "stderr: {err}");
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("doctor --json prints a report");
    let section = report["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|s| s["name"] == "Logging pipeline (#3651)")
        .expect("the logging section is present");
    assert_eq!(section["severity"], "critical", "section: {section}");
    let facts = section["facts"].to_string();
    assert!(facts.contains("FAILED"), "facts: {facts}");
    assert!(facts.contains("--features syslog"), "facts: {facts}");
}

#[test]
fn a_working_file_sink_still_boots_3651() {
    let home = sandbox();
    let logs = home.path().join("logs");
    let out = run_with_logging(
        home.path(),
        &format!(
            "enabled = true\nsink = \"file\"\nrotation = \"never\"\npath = \"{}\"\n",
            logs.display()
        ),
        &["stats"],
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(logs.is_dir(), "the file sink created its directory");
}

#[test]
fn a_second_subscriber_installation_is_an_error_3651() {
    // The ONLY test in this binary that touches the global subscriber, so
    // the order of tests cannot change what it observes.
    tracing::subscriber::set_global_default(tracing_subscriber::registry())
        .expect("first install in this process");
    let cfg = LoggingConfig {
        enabled: Some(true),
        sink: Some("stdout".to_string()),
        ..Default::default()
    };
    let err = logging::init_file_logging(&cfg)
        .expect_err("a second installation must not report success");
    let msg = format!("{err:#}");
    assert!(msg.contains("already active"), "got: {msg}");

    let status = logging::log_pipeline_status();
    assert_eq!(status.state, LogPipelineState::Failed);
    assert!(
        status
            .failure
            .as_deref()
            .is_some_and(|f| f.contains("already active")),
        "status: {status:?}"
    );
    assert_eq!(status.records_delivered, None, "nothing was measured");
}
