// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10309 — `tls init` with the local CA key written but not
//! confirmed durable.
//!
//! The directory fsync after the CA key fails with an injected `EIO` (the
//! test seam, per thread). Every TLS file is still written (#10214), so the
//! command succeeds, its stdout is the durable run's stdout, and stderr
//! carries exactly one warning built from the durability report. A durable
//! run prints nothing on stderr.

use super::*;
use crate::cli::test_utils::TestEnv;
use crate::storage::snapshot_file::{Durability, NotDurable, NotDurableReport, seam};
use std::path::{Path, PathBuf};

/// The head of the stderr warning (written out here, not taken from the
/// code under test).
const WARNING_HEAD_10309: &str = "warning: the command succeeded and its files are kept, but";
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

/// One real `tls init`; returns the result, the key dir, stdout and stderr.
/// The `TestEnv` is returned so its temporary directory outlives the call.
fn init_10309(json: bool, nth: Option<u32>) -> (Result<()>, PathBuf, String, String, TestEnv) {
    let mut env = TestEnv::fresh();
    let dir = key_dir_10309(&env);
    seam::reset();
    if let Some(nth) = nth {
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
    }
    let res = {
        let mut out = env.output();
        run_init(
            &dir,
            Some("127.0.0.1"),
            DeploymentShape::Singleton,
            json,
            &mut out,
        )
    };
    seam::reset();
    let stdout = env.stdout_str().to_string();
    let stderr = env.stderr_str().to_string();
    (res, dir, stdout, stderr, env)
}

fn expected_stderr_10309(dir: &Path) -> String {
    let tls = dir.join(TLS_DIR_10309);
    let mut report = NotDurableReport::new();
    report.note(Durability::NotDurable(NotDurable::new(
        TLS_MATERIAL_10309,
        &tls.join(CA_KEY_10309),
        &tls,
        std::io::Error::from_raw_os_error(libc::EIO),
    )));
    format!("{WARNING_HEAD_10309} {report}\n")
}

/// stdout without the clock-derived line.
fn stable_10309(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter(|l| !l.starts_with(EXPIRES_PREFIX_10309))
        .collect()
}

/// Text mode: success, the durable run's stdout, the exact warning on
/// stderr; a durable run has an empty stderr.
#[test]
fn tls_init_not_durable_warns_on_stderr_and_succeeds_10309() {
    let _reset = SeamReset;
    let (clean, clean_dir, clean_out, clean_err, _clean_env) = init_10309(false, None);
    clean.unwrap_or_else(|e| panic!("a durable tls init succeeds: {e:#}"));
    assert_eq!(clean_err, "", "a durable tls init prints no warning");

    let (res, dir, stdout, stderr, _env) = init_10309(false, Some(1));
    res.unwrap_or_else(|e| panic!("a written, not durable tls init succeeds: {e:#}"));
    let moved = clean_out.replace(&clean_dir.display().to_string(), &dir.display().to_string());
    assert_eq!(stable_10309(&stdout), stable_10309(&moved));
    assert_eq!(stdout.lines().count(), moved.lines().count());
    assert_eq!(stderr, expected_stderr_10309(&dir));
    assert!(dir.join(TLS_DIR_10309).join(CA_KEY_10309).is_file());
}

/// JSON mode: stdout stays exactly one JSON document; the warning goes to
/// stderr only.
#[test]
fn tls_init_json_not_durable_keeps_stdout_one_document_10309() {
    let _reset = SeamReset;
    let (res, dir, stdout, stderr, _env) = init_10309(true, Some(1));
    res.unwrap_or_else(|e| panic!("a written, not durable tls init succeeds: {e:#}"));
    assert_eq!(stdout.lines().count(), 1, "stdout: {stdout}");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout is one JSON document");
    assert_eq!(v["outcome"].as_str(), Some("generated"));
    assert_eq!(stderr, expected_stderr_10309(&dir));
}
