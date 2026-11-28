// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10309 / #10329 — `tls init` with the local CA key written but
//! not confirmed durable.
//!
//! The directory fsync after the CA key fails with an injected `EIO` (the
//! test seam, per thread). Every TLS file is still written (#10214), and the
//! command fails closed (#10329): it exits non-zero, its error is the
//! durability report, stdout is empty, and stderr carries one note naming the
//! files kept on disk. A durable run prints nothing on stderr.
//!
//! #10343 — a failed stderr write never changes the outcome: a durable run
//! stays a success with its stdout intact, a not-durable run keeps the
//! report as its error.

use super::*;
use crate::cli::test_utils::TestEnv;
use crate::storage::snapshot_file::{Durability, NotDurable, NotDurableReport, seam};
use std::path::{Path, PathBuf};

/// The head of the stderr note (written out here, not taken from the code
/// under test).
const KEPT_NOTE_10329: &str = "note: the command failed, and its files are kept on disk:";
/// The exit status `main` gives an `Err` (std `Termination`: `ExitCode::FAILURE`).
const FAILED_EXIT_10329: u8 = 1;
/// The `what` label of every TLS file (written out, as above).
const TLS_MATERIAL_10309: &str = "TLS material";
/// The TLS subdirectory and the local CA key file name (written out).
const TLS_DIR_10309: &str = "tls";
const CA_KEY_10309: &str = "local-ca.key";
/// The one stdout line that carries a clock-derived value.
const EXPIRES_PREFIX_10309: &str = "  expires:";

/// Clears the thread's seam state on every exit of a test.
struct SeamReset;

impl Drop for SeamReset {
    fn drop(&mut self) {
        seam::reset();
    }
}

/// #10343 — a stderr that refuses every write (a closed pipe).
struct ClosedStderr10343;

impl std::io::Write for ClosedStderr10343 {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
}

fn key_dir_10309(env: &TestEnv) -> PathBuf {
    let dir = env
        .db_path
        .parent()
        .expect("db path has a parent")
        .join("tls-keys-10309");
    std::fs::create_dir_all(&dir).expect("key dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("0700");
    }
    dir
}

/// One real `tls init`, failing the `nth` directory fsync when given, with a
/// closed stderr when `closed_stderr`; returns the result, the key dir,
/// stdout and stderr. The `TestEnv` is returned so its temporary directory
/// outlives the call.
fn init_10309(
    json: bool,
    nth: Option<u32>,
    closed_stderr: bool,
) -> (Result<()>, PathBuf, String, String, TestEnv) {
    let mut env = TestEnv::fresh();
    let dir = key_dir_10309(&env);
    seam::reset();
    if let Some(nth) = nth {
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
    }
    let host = Some("127.0.0.1");
    let res = if closed_stderr {
        let mut closed = ClosedStderr10343;
        let mut out = crate::cli::CliOutput::from_std(&mut env.stdout, &mut closed);
        run_init(&dir, host, DeploymentShape::Singleton, json, &mut out)
    } else {
        let mut out = env.output();
        run_init(&dir, host, DeploymentShape::Singleton, json, &mut out)
    };
    seam::reset();
    let stdout = env.stdout_str().to_string();
    let stderr = env.stderr_str().to_string();
    (res, dir, stdout, stderr, env)
}

/// The durability report of the CA key under `dir`, built from the
/// `NotDurable` state the code under test notes (an injected `EIO`).
fn expected_report_10309(dir: &Path) -> NotDurableReport {
    let tls = dir.join(TLS_DIR_10309);
    let mut report = NotDurableReport::new();
    report.note(Durability::NotDurable(NotDurable::new(
        TLS_MATERIAL_10309,
        &tls.join(CA_KEY_10309),
        &tls,
        std::io::Error::from_raw_os_error(libc::EIO),
    )));
    report
}

/// The exact stderr of a not-durable run.
fn expected_stderr_10329(dir: &Path) -> String {
    format!("{KEPT_NOTE_10329} {}\n", expected_report_10309(dir))
}

/// The run failed closed: its error is exactly `want` (typed, so it reads
/// as written-but-not-durable), and `main` exits with status 1.
fn assert_fails_closed_10329(res: Result<()>, want: &NotDurableReport) {
    let err = res.expect_err("a written, not durable tls init fails closed (#10329)");
    assert_eq!(
        format!("{err:#}"),
        want.to_string(),
        "the error is the report"
    );
    assert!(
        err.downcast_ref::<NotDurableReport>().is_some(),
        "the error is the typed report: {err:#}"
    );
    let status = std::process::Termination::report(Err::<(), _>(err));
    assert!(
        status == std::process::ExitCode::from(FAILED_EXIT_10329),
        "exit status {FAILED_EXIT_10329}"
    );
}

/// stdout without the clock-derived line.
fn stable_10309(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter(|l| !l.starts_with(EXPIRES_PREFIX_10309))
        .collect()
}

/// Text mode: a durable run succeeds with an empty stderr; a written, not
/// durable run exits 1 with the report as its error, no stdout, the exact
/// note on stderr, and the CA key kept.
#[test]
fn tls_init_not_durable_fails_closed_and_names_kept_files_10329() {
    let _reset = SeamReset;
    let (clean, _clean_dir, clean_out, clean_err, _clean_env) = init_10309(false, None, false);
    clean.unwrap_or_else(|e| panic!("a durable tls init succeeds: {e:#}"));
    assert_eq!(clean_err, "", "a durable tls init prints no note");
    assert!(
        !clean_out.is_empty(),
        "a durable tls init reports on stdout"
    );

    let (res, dir, stdout, stderr, _env) = init_10309(false, Some(1), false);
    assert_fails_closed_10329(res, &expected_report_10309(&dir));
    assert_eq!(stdout, "", "a failed tls init prints nothing on stdout");
    assert_eq!(stderr, expected_stderr_10329(&dir));
    assert!(dir.join(TLS_DIR_10309).join(CA_KEY_10309).is_file());
}

/// JSON mode: the same failure; stdout carries no JSON document.
#[test]
fn tls_init_json_not_durable_fails_closed_10329() {
    let _reset = SeamReset;
    let (res, dir, stdout, stderr, _env) = init_10309(true, Some(1), false);
    assert_fails_closed_10329(res, &expected_report_10309(&dir));
    assert_eq!(stdout, "", "a failed tls init prints no JSON document");
    assert_eq!(stderr, expected_stderr_10329(&dir));
}

/// #10343 — a closed stderr: a durable tls init still succeeds with the
/// stdout of a durable run, and a not-durable one keeps the report as its
/// error.
#[test]
fn tls_closed_stderr_never_changes_the_outcome_10343() {
    let _reset = SeamReset;
    for json in [false, true] {
        let (open, open_dir, open_out, _, _open_env) = init_10309(json, None, false);
        open.unwrap_or_else(|e| panic!("json={json}: a durable tls init succeeds: {e:#}"));
        let (res, dir, stdout, _, _env) = init_10309(json, None, true);
        res.unwrap_or_else(|e| panic!("json={json}: a closed stderr fails no tls init: {e:#}"));
        let moved = open_out.replace(&open_dir.display().to_string(), &dir.display().to_string());
        assert_eq!(stdout.lines().count(), moved.lines().count(), "json={json}");
        if json {
            // The document carries clock-derived fields; its outcome is stable.
            let v: serde_json::Value =
                serde_json::from_str(stdout.trim()).expect("stdout is one JSON document");
            assert_eq!(v["outcome"].as_str(), Some("generated"));
        } else {
            assert_eq!(stable_10309(&stdout), stable_10309(&moved));
        }

        let (res, dir, stdout, _, _env) = init_10309(json, Some(1), true);
        assert_fails_closed_10329(res, &expected_report_10309(&dir));
        assert_eq!(stdout, "", "json={json}");
    }
}
