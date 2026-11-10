// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8732: a tracing capture read through the shared operator-log helper holds
//! every event the capturing closure emits on the calling thread and no event
//! from any other test, for every schedule of sibling tests in the binary.
//!
//! The `tracing` callsite-interest cache is process-global. While only ONE
//! thread-local dispatcher is live, the registry computes a new callsite's
//! interest from the registering thread's own dispatcher; a sibling thread
//! with no subscriber that reaches a callsite first therefore pins it to
//! `never`, and the capturing thread then reads nothing (the #3426 / #4090
//! mechanism). A present-plus-absent assertion flakes on that; an
//! absence-only assertion passes without checking anything.
//!
//! No lock ordering, retry, sleep or run count decides any result below.

#[allow(dead_code)]
#[path = "common/operator_log_capture.rs"]
mod operator_capture;

use operator_capture::captured;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Barrier;

/// Fixed panic text of a nested `captured` on one thread.
const NESTED_CAPTURE_PANIC: &str =
    "operator_log_capture: captured() called while this thread already holds an active capture";
/// Fixed panic text when another global subscriber is already installed.
const GLOBAL_INSTALL_PANIC: &str = "operator_log_capture: another global tracing subscriber is already installed in this test binary";

/// Sibling threads that emit with no sink while captures run on the test thread.
const SIBLING_THREADS: usize = 8;
/// Emissions per sibling thread.
const SIBLING_EMISSIONS: usize = 200;
/// Environment switch that makes the re-executed child run the child branch.
const CHILD_ENV: &str = "OPERATOR_LOG_CAPTURE_8732_CHILD";
/// Exact name of the test the child re-runs.
const CHILD_TEST: &str = "foreign_global_subscriber_panics_with_fixed_message_8732";

/// Source files that must hold no thread-local subscriber install.
const SCANNED_SOURCES: &[(&str, &str)] = &[
    (
        "tests/common/operator_log_capture.rs",
        include_str!("common/operator_log_capture.rs"),
    ),
    (
        "tests/skill_cli_http_parity.rs",
        include_str!("skill_cli_http_parity.rs"),
    ),
    (
        "tests/operator_log_context_8205.rs",
        include_str!("operator_log_context_8205.rs"),
    ),
    (
        "tests/operator_log_masking_ratchet_8205.rs",
        include_str!("operator_log_masking_ratchet_8205.rs"),
    ),
];

/// Thread-local subscriber install forms (the pattern list of #4090).
const INSTALL_PATTERNS: &[&str] = &[
    "subscriber::set_default(",
    "subscriber::with_default(",
    "dispatcher::set_default(",
    "dispatcher::with_default(",
    "set_default(",
    "with_default(",
];

fn emit_sibling_race(who: &str) {
    tracing::info!(who, "isolation_probe_sibling_race_8732");
}

/// One distinct callsite per round: each `info!` expansion owns its own static.
macro_rules! callsite_table {
    (@one $slot:tt) => {
        (|who: &str| tracing::info!(who, "isolation_probe_hammer_8732")) as fn(&str)
    };
    ($($slot:tt)*) => {
        [$(callsite_table!(@one $slot)),*]
    };
}

const HAMMER_CALLSITES: [fn(&str); 32] = callsite_table!(
    _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
);

fn emit_concurrent(who: &str) {
    tracing::info!(who, "isolation_probe_concurrent_8732");
}

fn emit_plain(who: &str) {
    tracing::info!(who, "isolation_probe_plain_8732");
}

fn lines_with<'a>(log: &'a str, marker: &str) -> Vec<&'a str> {
    log.lines().filter(|line| line.contains(marker)).collect()
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<non-string panic>".to_owned())
}

/// (a) A sibling with no sink reaches the callsite first, inside the capture.
#[test]
fn sibling_pins_callsite_before_capturing_thread_emits_8732() {
    let ((), log) = captured(|| {
        std::thread::spawn(|| emit_sibling_race("sibling"))
            .join()
            .expect("sibling thread");
        emit_sibling_race("capturing");
    });
    let lines = lines_with(&log, "isolation_probe_sibling_race_8732");
    assert_eq!(
        lines.len(),
        1,
        "exactly the capturing thread's line: {log:?}"
    );
    assert!(
        lines[0].contains("capturing"),
        "wrong event captured: {log:?}"
    );
    assert!(!log.contains("sibling"), "sibling event leaked: {log:?}");
}

/// (b) Many sinkless siblings hammer a fresh callsite in every round, in step
/// with the capturing thread, so each round races the first registration of
/// its callsite.
#[test]
fn sibling_hammer_never_starves_or_leaks_a_capture_8732() {
    let start = Barrier::new(SIBLING_THREADS + 1);
    let end = Barrier::new(SIBLING_THREADS + 1);
    let mut failures = Vec::new();
    std::thread::scope(|scope| {
        for _ in 0..SIBLING_THREADS {
            scope.spawn(|| {
                for emit in HAMMER_CALLSITES {
                    start.wait();
                    for _ in 0..SIBLING_EMISSIONS {
                        emit("sibling");
                    }
                    end.wait();
                }
            });
        }
        for (round, emit) in HAMMER_CALLSITES.iter().enumerate() {
            let own = format!("own-{round}");
            let ((), log) = captured(|| {
                start.wait();
                emit(&own);
                end.wait();
            });
            let lines = lines_with(&log, "isolation_probe_hammer_8732");
            // Record, never panic here: a panic would strand the siblings at the barriers.
            if lines.len() != 1 || !lines[0].contains(&own) || log.contains("sibling") {
                failures.push(format!("round {round}: expected only {own}: {log:?}"));
            }
        }
    });
    assert!(
        failures.is_empty(),
        "{} of {} rounds: {failures:#?}",
        failures.len(),
        HAMMER_CALLSITES.len()
    );
}

/// (c) Two threads capture at the same time; neither sees the other's event.
#[test]
fn concurrent_captures_do_not_see_each_other_8732() {
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        for name in ["left", "right"] {
            let barrier = &barrier;
            scope.spawn(move || {
                let ((), log) = captured(|| {
                    barrier.wait();
                    emit_concurrent(name);
                    barrier.wait();
                });
                let lines = lines_with(&log, "isolation_probe_concurrent_8732");
                assert_eq!(lines.len(), 1, "{name}: exactly one line: {log:?}");
                assert!(lines[0].contains(name), "{name}: wrong line: {log:?}");
            });
        }
    });
}

/// (d) A nested capture on one thread panics with the fixed message.
#[test]
fn nested_capture_panics_with_fixed_message_8732() {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        captured(|| {
            captured(|| emit_plain("inner"));
        })
    }));
    let payload = outcome.expect_err("a nested capture must panic");
    assert_eq!(panic_text(payload.as_ref()), NESTED_CAPTURE_PANIC);
}

/// (e) A panic inside the closure leaves no active sink behind.
#[test]
fn panic_inside_capture_leaves_the_next_capture_clean_8732() {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        captured(|| {
            emit_plain("before-panic");
            panic!("fixture panic 8732");
        })
    }));
    assert!(outcome.is_err(), "the fixture closure panics");
    let ((), log) = captured(|| emit_plain("after-panic"));
    let lines = lines_with(&log, "isolation_probe_plain_8732");
    assert_eq!(lines.len(), 1, "exactly one line: {log:?}");
    assert!(lines[0].contains("after-panic"), "wrong line: {log:?}");
    assert!(!log.contains("before-panic"), "stale event leaked: {log:?}");
}

/// A thread with no active capture drops its events instead of buffering them.
#[test]
fn events_outside_a_capture_are_not_carried_into_the_next_one_8732() {
    emit_plain("outside");
    let ((), log) = captured(|| emit_plain("inside"));
    assert!(!log.contains("outside"), "uncaptured event leaked: {log:?}");
    assert_eq!(
        lines_with(&log, "isolation_probe_plain_8732").len(),
        1,
        "{log:?}"
    );
}

/// Parent: re-run this binary with the child branch. Child: another global
/// subscriber is already installed, so the helper must refuse by name.
#[test]
fn foreign_global_subscriber_panics_with_fixed_message_8732() {
    if std::env::var_os(CHILD_ENV).is_some() {
        tracing::subscriber::set_global_default(tracing::subscriber::NoSubscriber::default())
            .expect("child installs the foreign global subscriber first");
        let outcome = catch_unwind(AssertUnwindSafe(|| captured(|| emit_plain("child"))));
        let payload = outcome.expect_err("the helper must refuse a foreign global subscriber");
        assert_eq!(panic_text(payload.as_ref()), GLOBAL_INSTALL_PANIC);
        return;
    }
    let exe = std::env::current_exe().expect("test binary path");
    let output = std::process::Command::new(exe)
        .args(["--exact", CHILD_TEST, "--test-threads=1", "--nocapture"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn child test process");
    assert!(
        output.status.success(),
        "child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// (f) The helper and its three callers hold no thread-local install.
#[test]
fn capture_sources_hold_no_thread_local_install_8732() {
    for (path, source) in SCANNED_SOURCES {
        for pattern in INSTALL_PATTERNS {
            assert!(
                !source.contains(pattern),
                "{path} holds the thread-local install pattern {pattern}"
            );
        }
    }
}
