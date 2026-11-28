// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10309 — `keys init` with a key or certificate written but not
//! confirmed durable.
//!
//! Each row fails one directory fsync with an injected `EIO` (the test seam,
//! per thread): the identity key (`run_step` keypair arm), the local CA key
//! (`run_step` TLS arm) and the capability owner key (`init_owner`). The
//! file is complete on disk (#10214), so the command succeeds, its stdout is
//! the durable run's stdout, and stderr carries exactly one warning built
//! from the durability report. A durable run prints nothing on stderr.

use super::*;
use crate::cli::test_utils::TestEnv;
use crate::config::AppConfig;
use crate::config::shape::{DeploymentSection, DeploymentShape};
use crate::storage::snapshot_file::{Durability, NotDurable, NotDurableReport, seam};
use std::path::{Path, PathBuf};

/// The head of the stderr warning (written out here, not taken from the
/// code under test).
const WARNING_HEAD_10309: &str = "warning: the command succeeded and its files are kept, but";
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

/// One real `keys init` run; returns the result, the key dir, stdout,
/// stderr and the directories fsynced on this thread.
fn init_10309(
    agent: &str,
    tag: &str,
    json: bool,
    nth: Option<u32>,
) -> (Result<()>, PathBuf, String, String, Vec<PathBuf>) {
    let mut env = TestEnv::fresh();
    let dir = key_dir_10309(&env, tag);
    seam::reset();
    if let Some(nth) = nth {
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
    }
    let res = {
        let mut out = env.output();
        run_init(
            &dir,
            crate::keys::roles::PlanOptions {
                recovery_key_out: None,
                host: Some("127.0.0.1".into()),
            },
            false,
            json,
            Some(agent),
            &config_10309(),
            &mut out,
        )
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

/// The exact stderr for `site` under `dir`, built from the `NotDurable`
/// state the code under test notes.
fn expected_stderr_10309(site: Site, agent: &str, dir: &Path) -> String {
    let (what, file_dir, file) = match site {
        Site::Identity => (PRIVATE_KEY_10309, dir.to_path_buf(), format!("{agent}.priv")),
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
    format!("{WARNING_HEAD_10309} {report}\n")
}

fn agent_10309(tag: &str) -> String {
    format!("agent-10309-{tag}-{}", uuid::Uuid::new_v4().simple())
}

/// Text mode, every site: success, the durable run's stdout, the exact
/// warning on stderr.
#[test]
fn keys_init_not_durable_warns_per_site_and_succeeds_10309() {
    let _reset = SeamReset;
    for site in [Site::Identity, Site::LocalCa, Site::Owner] {
        let agent = agent_10309("text");
        let (clean, clean_dir, clean_out, clean_err, syncs) =
            init_10309(&agent, "clean", false, None);
        clean.unwrap_or_else(|e| panic!("{site:?}: a durable keys init succeeds: {e:#}"));
        assert_eq!(clean_err, "", "{site:?}: a durable keys init prints no warning");
        let nth = nth_for_10309(site, &clean_dir, &syncs);

        let (res, dir, stdout, stderr, _) = init_10309(&agent, "faulty", false, Some(nth));
        res.unwrap_or_else(|e| panic!("{site:?}: a written, not durable keys init succeeds: {e:#}"));
        assert_eq!(
            stdout,
            clean_out.replace(
                &clean_dir.display().to_string(),
                &dir.display().to_string()
            ),
            "{site:?}: stdout is the durable run's stdout"
        );
        assert_eq!(
            stderr,
            expected_stderr_10309(site, &agent, &dir),
            "{site:?}"
        );
    }
}

/// JSON mode: stdout stays exactly one JSON document; the warning goes to
/// stderr only.
#[test]
fn keys_init_json_not_durable_keeps_stdout_one_document_10309() {
    let _reset = SeamReset;
    let agent = agent_10309("json");
    let (res, dir, stdout, stderr, _) = init_10309(&agent, "json", true, Some(1));
    res.unwrap_or_else(|e| panic!("a written, not durable keys init succeeds: {e:#}"));
    assert_eq!(stdout.lines().count(), 1, "stdout: {stdout}");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout is one JSON document");
    assert_eq!(v["dry_run"].as_bool(), Some(false));
    assert_eq!(stderr, expected_stderr_10309(Site::Identity, &agent, &dir));
}
