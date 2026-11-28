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

// #10330 / #10335 — every log line of a failed reissue or renewal prints
// every cause of its error chain, at both arms: the `reissued_tick` reload
// error arm and the `renewal_tick` `Failed` arm. The expected error text is
// written out by hand; only the tick message comes from
// `renewal_tick_message`, which `renewal_tick_message_texts_10308` pins.

/// The tracing target of both arms (written out, not taken from the code).
const TARGET_10330: &str = "security.transit";
/// The outer error of the two-level reload chain.
const RELOAD_OUTER_10330: &str = "the listener refused the pair";
/// The root cause under it: `EACCES`, rendered by `std::io::Error`.
const RELOAD_ROOT_10330: &str = "Permission denied (os error 13)";
/// The rendered root cause of a TLS file name that is a directory.
const EISDIR_TEXT_10330: &str = "Is a directory (os error 21)";

/// A reload error with one cause under it.
#[derive(Debug)]
struct ReloadOuter10330(std::io::Error);

impl std::fmt::Display for ReloadOuter10330 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(RELOAD_OUTER_10330)
    }
}

impl std::error::Error for ReloadOuter10330 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// An in-memory tracing sink (precedent `src/mcp/span_capture_4088_tests.rs`).
#[derive(Clone, Default)]
struct LogSink10330(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogSink10330 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log sink").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink10330 {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl LogSink10330 {
    fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + use<> {
        tracing_subscriber::fmt()
            .with_writer(self.clone())
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .without_time()
            .finish()
    }

    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("log sink").clone()).expect("utf-8 log")
    }
}

/// The one ERROR line both arms emit, with `error` the rendered chain.
fn error_line_10330(message: &str, error: &str) -> String {
    format!("ERROR {TARGET_10330}: {message} error={error}\n")
}

/// Arm `reissued_tick` (reload error): a two-level reload chain logs both
/// levels, outer first.
#[test]
fn reissued_tick_reload_error_logs_whole_chain_10330() {
    if crate::config::run_env_isolated_child_or_spawn(
        "tls_bootstrap::not_durable_10310_tests::reissued_tick_reload_error_logs_whole_chain_10330",
    ) {
        return;
    }
    let sink = LogSink10330::default();
    let report = NotDurableReport::new();
    let reload = Err(std::io::Error::other(ReloadOuter10330(
        std::io::Error::from_raw_os_error(libc::EACCES),
    )));
    let tick = tracing::subscriber::with_default(sink.subscriber(), || {
        reissued_tick(reload, &report, 90)
    });
    assert_eq!(tick, RenewalTick::ReloadFailed);
    let message = renewal_tick_message(tick, &report).expect("a failed reload logs");
    assert_eq!(
        sink.text(),
        error_line_10330(
            &message,
            &format!("{RELOAD_OUTER_10330}: {RELOAD_ROOT_10330}")
        )
    );
}

/// Arm `renewal_tick` `Failed`: the CA key is written (not confirmed
/// durable), then the CA certificate write fails. The log names the kept
/// file, the failed write and its root cause (#10335's exact case).
#[tokio::test(flavor = "current_thread")]
async fn renewal_tick_failed_logs_whole_chain_10330() {
    if crate::config::run_env_isolated_child_or_spawn(
        "tls_bootstrap::not_durable_10310_tests::renewal_tick_failed_logs_whole_chain_10330",
    ) {
        return;
    }
    let _reset = SeamReset;
    let listener_dir = tempfile::tempdir().expect("tempdir under TMPDIR");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = ensure_local_tls(listener_dir.path(), HOST_10310).expect("first boot");
    let reload = crate::tls::load_rustls_config(&tls.cert_path, &tls.key_path)
        .await
        .expect("the listener loads the local leaf");
    let tmp = tempfile::tempdir().expect("tempdir under TMPDIR");
    let dir = tmp.path().join(TLS_SUBDIR);
    std::fs::create_dir_all(dir.join(LOCAL_CA_CERT_FILE)).expect("the blocking directory");
    seam::reset();
    seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, 1);
    let sink = LogSink10330::default();
    let tick = {
        let _guard = tracing::subscriber::set_default(sink.subscriber());
        renewal_tick(&reload, tmp.path(), HOST_10310).await
    };
    seam::reset();
    assert_eq!(tick, RenewalTick::Failed);
    let message = renewal_tick_message(RenewalTick::Failed, &NotDurableReport::new())
        .expect("a failed tick logs");
    assert_eq!(
        sink.text(),
        error_line_10330(
            &message,
            &format!(
                "{WRITTEN_BEFORE_10310}: {}: replacing {} (#3709): {EISDIR_TEXT_10330}",
                ca_key_report_10310(&dir),
                dir.join(LOCAL_CA_CERT_FILE).display()
            )
        )
    );
}
