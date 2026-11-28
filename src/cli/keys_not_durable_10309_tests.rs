// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10309 / #10329 — `keys init` with a key or certificate written
//! but not confirmed durable.
//!
//! Each row fails one directory fsync with an injected `EIO` (the test seam,
//! per thread): the identity key (`run_step` keypair arm), the local CA key
//! (`run_step` TLS arm) and the capability owner key (`init_owner`). The
//! file is complete on disk (#10214), and the command fails closed (#10329):
//! it exits non-zero, its error is the durability report, stdout is empty,
//! and stderr carries one note naming the files kept on disk. A durable run
//! prints nothing on stderr.
//!
//! #10343 — a failed stderr write never changes the outcome: a durable run
//! stays a success with its stdout intact, a not-durable run keeps the
//! report as its error.

use super::*;
use crate::cli::test_utils::TestEnv;
use crate::config::AppConfig;
use crate::config::shape::{DeploymentSection, DeploymentShape};
use crate::storage::snapshot_file::{Durability, NotDurable, NotDurableReport, seam};
use std::path::{Path, PathBuf};

/// The head of the stderr note (written out here, not taken from the code
/// under test).
const KEPT_NOTE_10329: &str = "note: the command failed, and its files are kept on disk:";
/// The exit status `main` gives an `Err` (std `Termination`: `ExitCode::FAILURE`).
const FAILED_EXIT_10329: u8 = 1;
/// The `what` labels (written out, as above).
const PRIVATE_KEY_10309: &str = "private key";
const TLS_MATERIAL_10309: &str = "TLS material";
/// The TLS subdirectory and the local CA key file name (written out).
const TLS_DIR_10309: &str = "tls";
const CA_KEY_10309: &str = "local-ca.key";
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

/// Which file's directory fsync fails.
#[derive(Clone, Copy, Debug)]
enum Site {
    Identity,
    LocalCa,
    Owner,
}

fn config_10309() -> AppConfig {
    let mut cfg = AppConfig::default();
    cfg.deployment = Some(DeploymentSection {
        shape: Some(DeploymentShape::Singleton),
    });
    cfg.encryption = Some(crate::config::EncryptionSection {
        at_rest: Some(false),
    });
    cfg
}

fn key_dir_10309(env: &TestEnv, tag: &str) -> PathBuf {
    let dir = env
        .db_path
        .parent()
        .expect("db path has a parent")
        .join(format!("keys-10309-{tag}"));
    std::fs::create_dir_all(&dir).expect("key dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("0700");
    }
    dir
}

/// One real `keys init` run, failing the `nth` directory fsync when given,
/// with a closed stderr when `closed_stderr`; returns the result, the key
/// dir, stdout, stderr and the directories fsynced on this thread.
fn init_10309(
    agent: &str,
    tag: &str,
    json: bool,
    nth: Option<u32>,
    closed_stderr: bool,
) -> (Result<()>, PathBuf, String, String, Vec<PathBuf>) {
    let mut env = TestEnv::fresh();
    let dir = key_dir_10309(&env, tag);
    seam::reset();
    if let Some(nth) = nth {
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
    }
    let opts = || crate::keys::roles::PlanOptions {
        recovery_key_out: None,
        host: Some("127.0.0.1".into()),
    };
    let cfg = config_10309();
    let res = if closed_stderr {
        let mut closed = ClosedStderr10343;
        let mut out = crate::cli::CliOutput::from_std(&mut env.stdout, &mut closed);
        run_init(&dir, opts(), false, json, Some(agent), &cfg, &mut out)
    } else {
        let mut out = env.output();
        run_init(&dir, opts(), false, json, Some(agent), &cfg, &mut out)
    };
    let syncs = seam::take_dir_syncs();
    seam::reset();
    (
        res,
        dir,
        env.stdout_str().to_string(),
        env.stderr_str().to_string(),
        syncs,
    )
}

/// The 1-based index of the directory fsync that follows `site`'s first
/// file in a clean run (the injection point only; the expected text is
/// written out below).
fn nth_for_10309(site: Site, dir: &Path, syncs: &[PathBuf]) -> u32 {
    let tls = dir.join(TLS_DIR_10309);
    let idx = match site {
        Site::Identity => syncs.iter().position(|p| p == dir),
        Site::LocalCa => syncs.iter().position(|p| *p == tls),
        Site::Owner => {
            let last_tls = syncs
                .iter()
                .rposition(|p| *p == tls)
                .expect("the clean run writes TLS material");
            syncs[last_tls..]
                .iter()
                .position(|p| p == dir)
                .map(|i| i + last_tls)
        }
    }
    .unwrap_or_else(|| panic!("{site:?}: no directory fsync in {syncs:?}"));
    u32::try_from(idx + 1).expect("a handful of syncs")
}

/// The durability report for `site` under `dir`, built from the
/// `NotDurable` state the code under test notes.
fn expected_report_10309(site: Site, agent: &str, dir: &Path) -> NotDurableReport {
    let (what, file_dir, file) = match site {
        Site::Identity => (
            PRIVATE_KEY_10309,
            dir.to_path_buf(),
            format!("{agent}.priv"),
        ),
        Site::LocalCa => (
            TLS_MATERIAL_10309,
            dir.join(TLS_DIR_10309),
            CA_KEY_10309.to_string(),
        ),
        Site::Owner => (
            PRIVATE_KEY_10309,
            dir.to_path_buf(),
            OWNER_PRIV_10309.to_string(),
        ),
    };
    let mut report = NotDurableReport::new();
    report.note(Durability::NotDurable(NotDurable::new(
        what,
        &file_dir.join(&file),
        &file_dir,
        std::io::Error::from_raw_os_error(libc::EIO),
    )));
    report
}

/// The exact stderr of a not-durable run.
fn expected_stderr_10329(site: Site, agent: &str, dir: &Path) -> String {
    format!(
        "{KEPT_NOTE_10329} {}\n",
        expected_report_10309(site, agent, dir)
    )
}

/// The run failed closed: its error is exactly `want` (typed, so it reads
/// as written-but-not-durable), and `main` exits with status 1.
fn assert_fails_closed_10329(res: Result<()>, want: &NotDurableReport, ctx: &str) {
    let err = res.expect_err(ctx);
    assert_eq!(
        format!("{err:#}"),
        want.to_string(),
        "{ctx}: the error is the report"
    );
    assert!(
        err.downcast_ref::<NotDurableReport>().is_some(),
        "{ctx}: the error is the typed report: {err:#}"
    );
    let status = std::process::Termination::report(Err::<(), _>(err));
    assert!(
        status == std::process::ExitCode::from(FAILED_EXIT_10329),
        "{ctx}: exit status {FAILED_EXIT_10329}"
    );
}

fn agent_10309(tag: &str) -> String {
    format!("agent-10309-{tag}-{}", uuid::Uuid::new_v4().simple())
}

/// Text mode, every site: a durable run succeeds with an empty stderr; a
/// written, not durable run exits 1 with the report as its error, no stdout
/// and the exact note on stderr.
#[test]
fn keys_init_not_durable_fails_closed_per_site_10329() {
    let _reset = SeamReset;
    for site in [Site::Identity, Site::LocalCa, Site::Owner] {
        let agent = agent_10309("text");
        let (clean, clean_dir, clean_out, clean_err, syncs) =
            init_10309(&agent, "clean", false, None, false);
        clean.unwrap_or_else(|e| panic!("{site:?}: a durable keys init succeeds: {e:#}"));
        assert_eq!(
            clean_err, "",
            "{site:?}: a durable keys init prints no note"
        );
        assert!(
            !clean_out.is_empty(),
            "{site:?}: a durable run reports on stdout"
        );
        let nth = nth_for_10309(site, &clean_dir, &syncs);

        let (res, dir, stdout, stderr, _) = init_10309(&agent, "faulty", false, Some(nth), false);
        assert_fails_closed_10329(
            res,
            &expected_report_10309(site, &agent, &dir),
            &format!("{site:?}: a written, not durable keys init fails closed (#10329)"),
        );
        assert_eq!(
            stdout, "",
            "{site:?}: a failed keys init prints nothing on stdout"
        );
        assert_eq!(
            stderr,
            expected_stderr_10329(site, &agent, &dir),
            "{site:?}"
        );
    }
}

/// JSON mode: the same failure; stdout carries no JSON document.
#[test]
fn keys_init_json_not_durable_fails_closed_10329() {
    let _reset = SeamReset;
    let agent = agent_10309("json");
    let (res, dir, stdout, stderr, _) = init_10309(&agent, "json", true, Some(1), false);
    assert_fails_closed_10329(
        res,
        &expected_report_10309(Site::Identity, &agent, &dir),
        "json: a written, not durable keys init fails closed (#10329)",
    );
    assert_eq!(stdout, "", "a failed keys init prints no JSON document");
    assert_eq!(stderr, expected_stderr_10329(Site::Identity, &agent, &dir));
}

/// #10343 — a closed stderr: a durable keys init still succeeds with the
/// stdout of a durable run, and a not-durable one keeps the report as its
/// error.
#[test]
fn keys_closed_stderr_never_changes_the_outcome_10343() {
    let _reset = SeamReset;
    for json in [false, true] {
        let agent = agent_10309("closed");
        let (open, open_dir, open_out, _, _) = init_10309(&agent, "open", json, None, false);
        open.unwrap_or_else(|e| panic!("json={json}: a durable keys init succeeds: {e:#}"));
        let (res, dir, stdout, _, _) = init_10309(&agent, "closed", json, None, true);
        res.unwrap_or_else(|e| panic!("json={json}: a closed stderr fails no keys init: {e:#}"));
        let moved = open_out.replace(&open_dir.display().to_string(), &dir.display().to_string());
        if json {
            // The document may carry clock-derived fields; its shape is stable.
            assert_eq!(stdout.lines().count(), 1, "stdout: {stdout}");
            let v: serde_json::Value =
                serde_json::from_str(stdout.trim()).expect("stdout is one JSON document");
            assert_eq!(v["dry_run"].as_bool(), Some(false));
        } else {
            assert_eq!(stdout, moved, "stdout is intact");
        }

        let (res, dir, stdout, _, _) = init_10309(&agent, "faulty", json, Some(1), true);
        assert_fails_closed_10329(
            res,
            &expected_report_10309(Site::Identity, &agent, &dir),
            &format!("json={json}: a closed stderr keeps the report as the error (#10343)"),
        );
        assert_eq!(stdout, "", "json={json}");
    }
}
