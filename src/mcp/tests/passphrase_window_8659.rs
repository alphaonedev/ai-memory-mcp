// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Observe the audit reader's actual passphrase-window ownership, without
//! depending on the brief b11 seed overlapping a parallel SQLite open.

use crate::storage::connection::OPEN_TRACE_5084;
use std::cell::Cell;
use std::sync::TryLockError;
use std::time::Duration;

const CHILD_ROLE: &str = "AI_MEMORY_PASSPHRASE_WINDOW_8659_CHILD";
const NO_CONFIG_ENV: &str = "AI_MEMORY_NO_CONFIG";
const EXACT_TEST: &str =
    "mcp::tests::passphrase_window_8659::audit_dispatch_holds_passphrase_window_8659";
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Probe {
    Acquired,
    Excluded,
    Poisoned,
    ThreadFailed,
}

thread_local! {
    static OBSERVED: Cell<Option<Probe>> = const { Cell::new(None) };
}

struct RestoreTrace(Option<fn(&str)>);

impl Drop for RestoreTrace {
    fn drop(&mut self) {
        OPEN_TRACE_5084.with(|trace| trace.set(self.0));
    }
}

fn probe_window(_sql: &str) {
    if OBSERVED.with(Cell::get).is_some() {
        return;
    }
    // CONCURRENCY-11: join the probe while the audited dispatch is suspended
    // in its SQL callback. Never panic across SQLite's callback boundary.
    let result =
        std::thread::Builder::new().spawn(|| match crate::test_support::env_mutex().try_lock() {
            Ok(_guard) => Probe::Acquired,
            Err(TryLockError::WouldBlock) => Probe::Excluded,
            Err(TryLockError::Poisoned(_)) => Probe::Poisoned,
        });
    let observed = match result {
        Ok(thread) => thread.join().unwrap_or(Probe::ThreadFailed),
        Err(_) => Probe::ThreadFailed,
    };
    OBSERVED.with(|cell| cell.set(Some(observed)));
}

fn observe_audit_reader() {
    OBSERVED.with(|cell| cell.set(None));
    let _restore = RestoreTrace(OPEN_TRACE_5084.with(|trace| trace.replace(Some(probe_window))));
    super::issue_965_audit_serial_dispatch_50_calls_through_single_connection();
    let observed = OBSERVED.with(Cell::take);
    assert!(
        observed.is_some(),
        "#8659: the SQL hook must run on the audit test's real connection; observed={observed:?}"
    );
    assert_eq!(
        observed,
        Some(Probe::Excluded),
        "#8659: the audit reader must hold the shared passphrase window throughout dispatch; \
         Acquired means a b11 seeder could interleave, while poisoning/thread failure is not exclusion"
    );
}

#[test]
fn audit_dispatch_holds_passphrase_window_8659() {
    if std::env::var(CHILD_ROLE).as_deref() == Ok(EXACT_TEST) {
        observe_audit_reader();
        return;
    }
    // Only this test runs in the fresh child, so a sibling cannot hold the
    // mutex and manufacture an Excluded result for an unguarded audit reader.
    let mut command = crate::spawn_audit::audited_command(
        std::env::current_exe().expect("#8659: locate the lib-test executable"),
        "mcp::tests::passphrase_window_8659",
    );
    command
        .args(["--exact", EXACT_TEST, "--nocapture", "--test-threads=1"])
        .env_clear()
        .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|value| ("LLVM_PROFILE_FILE", value)))
        .env("TMPDIR", std::env::temp_dir())
        .env(NO_CONFIG_ENV, "1")
        .env(CHILD_ROLE, EXACT_TEST);
    let output = assert_cmd::Command::from_std(command)
        .timeout(CHILD_TIMEOUT)
        .output()
        .expect("#8659: execute and reap the bounded audit-reader child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "#8659: the isolated audit reader must exclude the mutex probe; status={}\n\
         child stdout:\n{stdout}\nchild stderr:\n{stderr}",
        output.status
    );
    assert!(
        stdout.contains("test result: ok. 1 passed; 0 failed;")
            && !stdout.contains("test result: ok. 0 passed;"),
        "#8659: the exact child test must execute once; child stdout:\n{stdout}\nchild stderr:\n{stderr}"
    );
}
