// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10310 — a later error of the TLS bootstrap keeps the durability
//! report of the files written before it.
//!
//! [`ensure_local_tls_reported`] notes every file written but not confirmed
//! durable (#10214) and goes on. When a later step then fails, the error
//! must still say which files are on disk but not confirmed durable;
//! dropping the report there tells the caller only that the step failed.
//!
//! Each test makes one TLS file name a directory, so replacing it fails
//! with `EISDIR` after the CA key was published under an injected `EIO`
//! directory fsync (the test seam, per thread).

use super::*;
use crate::storage::snapshot_file::{NotDurable, seam};

/// The head of the context a later error carries (written out here, not
/// taken from the code under test).
const WRITTEN_BEFORE_10310: &str = "files written before this error are kept on disk";
/// The `what` label of every TLS file (written out, as above).
const TLS_MATERIAL_10310: &str = "TLS material";
/// The binding host of every row.
const HOST_10310: &str = "127.0.0.1";

/// Clears the thread's seam state on every exit of a test.
struct SeamReset;

impl Drop for SeamReset {
    fn drop(&mut self) {
        seam::reset();
    }
}

/// The report of the CA key written under a failed directory fsync, built
/// from the `NotDurable` state the code under test notes.
fn ca_key_report_10310(dir: &Path) -> NotDurableReport {
    let mut report = NotDurableReport::new();
    report.note(crate::storage::snapshot_file::Durability::NotDurable(
        NotDurable::new(
            TLS_MATERIAL_10310,
            &dir.join(LOCAL_CA_KEY_FILE),
            dir,
            std::io::Error::from_raw_os_error(libc::EIO),
        ),
    ));
    report
}

/// The later error: replacing `path`, which is a directory.
fn replacing_dir_10310(path: &Path) -> String {
    format!(
        "replacing {} (#3709): {}",
        path.display(),
        std::io::Error::from_raw_os_error(libc::EISDIR)
    )
}

/// Run a first boot with `blocker` (a file name under `tls/`) made a
/// directory and the CA key's directory fsync failing when `fail_ca_sync`.
fn first_boot_blocked_10310(
    blocker: &str,
    fail_ca_sync: bool,
) -> (tempfile::TempDir, PathBuf, anyhow::Error) {
    let tmp = tempfile::tempdir().expect("tempdir under TMPDIR");
    let dir = tmp.path().join(TLS_SUBDIR);
    std::fs::create_dir_all(dir.join(blocker)).expect("the blocking directory");
    seam::reset();
    if fail_ca_sync {
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, 1);
    }
    let err = ensure_local_tls_reported(tmp.path(), HOST_10310)
        .err()
        .expect("a TLS file name that is a directory fails the boot");
    seam::reset();
    (tmp, dir, err)
}

/// Site `generate_ca`: the CA key is written (not confirmed durable), then
/// the CA certificate write fails. The error names both.
#[test]
fn ca_cert_failure_keeps_ca_key_report_10310() {
    let _reset = SeamReset;
    let (_tmp, dir, err) = first_boot_blocked_10310(LOCAL_CA_CERT_FILE, true);
    assert_eq!(
        format!("{err:#}"),
        format!(
            "{WRITTEN_BEFORE_10310}: {}: {}",
            ca_key_report_10310(&dir),
            replacing_dir_10310(&dir.join(LOCAL_CA_CERT_FILE))
        )
    );
    assert!(dir.join(LOCAL_CA_KEY_FILE).is_file(), "the CA key is kept");
    assert!(
        err.downcast_ref::<NotDurableReport>().is_none(),
        "a failed boot never reads as written-but-not-durable: {err:#}"
    );
    assert!(err.downcast_ref::<NotDurable>().is_none(), "{err:#}");
}

/// Site `issue_leaf`: the CA is written (its key not confirmed durable),
/// then the server key write fails. The error names both.
#[test]
fn leaf_failure_keeps_ca_report_10310() {
    let _reset = SeamReset;
    let (_tmp, dir, err) = first_boot_blocked_10310(SERVER_KEY_FILE, true);
    assert_eq!(
        format!("{err:#}"),
        format!(
            "{WRITTEN_BEFORE_10310}: {}: {}",
            ca_key_report_10310(&dir),
            replacing_dir_10310(&dir.join(SERVER_KEY_FILE))
        )
    );
    for file in [LOCAL_CA_KEY_FILE, LOCAL_CA_CERT_FILE] {
        assert!(dir.join(file).is_file(), "{file} is kept");
    }
    assert!(
        err.downcast_ref::<NotDurableReport>().is_none(),
        "a failed boot never reads as written-but-not-durable: {err:#}"
    );
    assert!(err.downcast_ref::<NotDurable>().is_none(), "{err:#}");
}

/// With every file durable the later error is returned unchanged: no
/// durability context is invented.
#[test]
fn durable_files_leave_later_error_unchanged_10310() {
    let _reset = SeamReset;
    for blocker in [LOCAL_CA_CERT_FILE, SERVER_KEY_FILE, SERVER_CERT_FILE] {
        let (_tmp, dir, err) = first_boot_blocked_10310(blocker, false);
        assert_eq!(
            format!("{err:#}"),
            replacing_dir_10310(&dir.join(blocker)),
            "blocker {blocker}"
        );
    }
}
