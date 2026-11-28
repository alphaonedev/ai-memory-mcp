// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10309 / #10329 — `capability init` with a key written but not
//! confirmed durable.
//!
//! The owner key pair is complete on disk when the directory fsync after its
//! `.priv` claim fails (#10214). The command fails closed (the posture of
//! #10214, settled for #10329): it exits non-zero, its error is the
//! durability report naming the write that is not confirmed durable, stdout
//! is empty, and stderr carries one note naming the files kept on disk. A
//! durable run prints nothing on stderr.
//!
//! #10343 — a failed stderr write never changes the outcome: a durable run
//! stays a success with its stdout intact, a not-durable run keeps the
//! report as its error.

use super::*;
use crate::cli::test_utils::TestEnv;
use crate::config::AppConfig;
use crate::storage::snapshot_file::{Durability, NotDurable, NotDurableReport, seam};
use std::path::{Path, PathBuf};

/// The head of the stderr note (written out here, not taken from the code
/// under test).
const KEPT_NOTE_10329: &str = "note: the command failed, and its files are kept on disk:";
/// The exit status `main` gives an `Err` (std `Termination`: `ExitCode::FAILURE`).
const FAILED_EXIT_10329: u8 = 1;
/// The `what` label of a private key file (written out, as above).
const PRIVATE_KEY_10309: &str = "private key";
/// The owner key file the first directory fsync follows.
const OWNER_PRIV_10309: &str = "owner.priv";

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
    env.db_path
        .parent()
        .expect("db path has a parent")
        .join("caps-keys-10309")
}

/// The durability report for `file` under `dir`, built from the
/// `NotDurable` state the code under test notes (an injected `EIO`).
fn expected_report_10309(dir: &Path, file: &str) -> NotDurableReport {
    let mut report = NotDurableReport::new();
    report.note(Durability::NotDurable(NotDurable::new(
        PRIVATE_KEY_10309,
        &dir.join(file),
        dir,
        std::io::Error::from_raw_os_error(libc::EIO),
    )));
    report
}

/// The exact stderr of a not-durable run.
fn expected_stderr_10329(dir: &Path, file: &str) -> String {
    format!("{KEPT_NOTE_10329} {}\n", expected_report_10309(dir, file))
}

/// The run failed closed: its error is exactly `want` (typed, so it reads
/// as written-but-not-durable), and `main` exits with status 1.
fn assert_fails_closed_10329(res: Result<()>, want: &NotDurableReport) {
    let err = res.expect_err("a written, not durable init fails closed (#10329)");
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

/// Run `capability init` into `dir`, failing the `nth` directory fsync when
/// given, with a closed stderr when `closed_stderr`; returns the result,
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
    let args = CapabilityArgs {
        key_dir: Some(dir.clone()),
        action: CapabilityAction::Init,
    };
    let res = if closed_stderr {
        let mut closed = ClosedStderr10343;
        let mut out = CliOutput::from_std(&mut env.stdout, &mut closed);
        run(args, json, &AppConfig::default(), &mut out)
    } else {
        let mut out = env.output();
        run(args, json, &AppConfig::default(), &mut out)
    };
    seam::reset();
    let stdout = env.stdout_str().to_string();
    let stderr = env.stderr_str().to_string();
    (res, dir, stdout, stderr, env)
}

/// Text mode: a durable run succeeds with an empty stderr; a written, not
/// durable run exits 1 with the report as its error, no stdout, the exact
/// note on stderr, and every file kept.
#[test]
fn init_not_durable_fails_closed_and_names_kept_files_10329() {
    let _reset = SeamReset;
    let (clean, _clean_dir, clean_out, clean_err, _clean_env) = init_10309(false, None, false);
    clean.unwrap_or_else(|e| panic!("a durable init succeeds: {e:#}"));
    assert_eq!(clean_err, "", "a durable init prints no note");
    assert!(!clean_out.is_empty(), "a durable init reports on stdout");

    let (res, dir, stdout, stderr, _env) = init_10309(false, Some(1), false);
    assert_fails_closed_10329(res, &expected_report_10309(&dir, OWNER_PRIV_10309));
    assert_eq!(stdout, "", "a failed init prints nothing on stdout");
    assert_eq!(stderr, expected_stderr_10329(&dir, OWNER_PRIV_10309));
    for f in [OWNER_PRIV_10309, "owner.pub", "owner.caproot"] {
        assert!(dir.join(f).is_file(), "{f} is kept on disk");
    }
}

/// JSON mode: the same failure; stdout carries no JSON document.
#[test]
fn init_json_not_durable_fails_closed_10329() {
    let _reset = SeamReset;
    let (res, dir, stdout, stderr, _env) = init_10309(true, Some(1), false);
    assert_fails_closed_10329(res, &expected_report_10309(&dir, OWNER_PRIV_10309));
    assert_eq!(stdout, "", "a failed init prints no JSON document");
    assert_eq!(stderr, expected_stderr_10329(&dir, OWNER_PRIV_10309));
}

/// #10343 — a closed stderr: a durable init still succeeds with the stdout
/// of a durable run, and a not-durable init keeps the report as its error.
#[test]
fn closed_stderr_never_changes_the_outcome_10343() {
    let _reset = SeamReset;
    for json in [false, true] {
        let (open, open_dir, open_out, _, _open_env) = init_10309(json, None, false);
        open.unwrap_or_else(|e| panic!("json={json}: a durable init succeeds: {e:#}"));
        let (res, dir, stdout, _, _env) = init_10309(json, None, true);
        res.unwrap_or_else(|e| panic!("json={json}: a closed stderr fails no init: {e:#}"));
        assert_eq!(
            stdout,
            open_out.replace(&open_dir.display().to_string(), &dir.display().to_string()),
            "json={json}: stdout is intact"
        );

        let (res, dir, stdout, _, _env) = init_10309(json, Some(1), true);
        assert_fails_closed_10329(res, &expected_report_10309(&dir, OWNER_PRIV_10309));
        assert_eq!(stdout, "", "json={json}");
    }
}
