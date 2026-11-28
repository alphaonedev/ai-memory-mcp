// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10309 — `capability init` with a key written but not confirmed
//! durable.
//!
//! The owner key pair is complete on disk when the directory fsync after its
//! `.priv` claim fails (#10214). The command therefore succeeds, prints its
//! usual stdout unchanged, and puts one warning built from the durability
//! report on stderr. A durable run prints nothing on stderr.

use super::*;
use crate::cli::test_utils::TestEnv;
use crate::config::AppConfig;
use crate::storage::snapshot_file::{Durability, NotDurable, NotDurableReport, seam};
use std::path::{Path, PathBuf};

/// The head of the stderr warning (written out here, not taken from the
/// code under test).
const WARNING_HEAD_10309: &str = "warning: the command succeeded and its files are kept, but";
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

fn key_dir_10309(env: &TestEnv) -> PathBuf {
    env.db_path
        .parent()
        .expect("db path has a parent")
        .join("caps-keys-10309")
}

/// The exact stderr: the warning for `file` under `dir`, built from the
/// `NotDurable` state the code under test notes (an injected `EIO`).
fn expected_stderr_10309(dir: &Path, file: &str) -> String {
    let mut report = NotDurableReport::new();
    report.note(Durability::NotDurable(NotDurable::new(
        PRIVATE_KEY_10309,
        &dir.join(file),
        dir,
        std::io::Error::from_raw_os_error(libc::EIO),
    )));
    format!("{WARNING_HEAD_10309} {report}\n")
}

/// Run `capability init` into `dir`, failing the `nth` directory fsync when
/// given; returns the result, stdout and stderr.
fn init_10309(json: bool, nth: Option<u32>) -> (Result<()>, PathBuf, String, String) {
    let mut env = TestEnv::fresh();
    let dir = key_dir_10309(&env);
    seam::reset();
    if let Some(nth) = nth {
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
    }
    let res = {
        let mut out = env.output();
        run(
            CapabilityArgs {
                key_dir: Some(dir.clone()),
                action: CapabilityAction::Init,
            },
            json,
            &AppConfig::default(),
            &mut out,
        )
    };
    seam::reset();
    (
        res,
        dir,
        env.stdout_str().to_string(),
        env.stderr_str().to_string(),
    )
}

/// Text mode: success, the usual stdout, the exact warning on stderr; a
/// durable run has an empty stderr.
#[test]
fn init_not_durable_warns_on_stderr_and_succeeds_10309() {
    let _reset = SeamReset;
    let (clean, clean_dir, clean_out, clean_err) = init_10309(false, None);
    clean.unwrap_or_else(|e| panic!("a durable init succeeds: {e:#}"));
    assert_eq!(clean_err, "", "a durable init prints no warning");

    let (res, dir, stdout, stderr) = init_10309(false, Some(1));
    res.unwrap_or_else(|e| panic!("a written, not durable init still succeeds: {e:#}"));
    assert_eq!(
        stdout,
        clean_out.replace(
            &clean_dir.display().to_string(),
            &dir.display().to_string()
        ),
        "stdout is the durable run's stdout"
    );
    assert_eq!(stderr, expected_stderr_10309(&dir, OWNER_PRIV_10309));
    for f in [OWNER_PRIV_10309, "owner.pub", "owner.caproot"] {
        assert!(dir.join(f).is_file(), "{f} is on disk");
    }
}

/// JSON mode: stdout stays exactly one JSON document with the usual fields;
/// the warning goes to stderr only.
#[test]
fn init_json_not_durable_keeps_stdout_one_document_10309() {
    let _reset = SeamReset;
    let (res, dir, stdout, stderr) = init_10309(true, Some(1));
    res.unwrap_or_else(|e| panic!("a written, not durable init still succeeds: {e:#}"));
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout is one JSON document");
    assert_eq!(stdout.lines().count(), 1, "stdout: {stdout}");
    assert_eq!(v["created_keypair"].as_bool(), Some(true));
    assert_eq!(v["created_root_secret"].as_bool(), Some(true));
    assert_eq!(stderr, expected_stderr_10309(&dir, OWNER_PRIV_10309));
}
