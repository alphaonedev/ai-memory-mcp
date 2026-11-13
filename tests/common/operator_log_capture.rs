// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Operator-log capture shared by the #6822 / #8205 test binaries (#8732).
//!
//! One process-global routing subscriber is installed once per binary at
//! TRACE level. Its writer appends to the CURRENT thread's active sink and
//! discards when the thread has none. Callsite interest is therefore the same
//! whichever thread registers a callsite first, so a sibling test with no
//! capture cannot starve a capturing test (the callsite-interest mechanism of
//! #3426 / #4090).
//!
//! Bound: events `operation` causes on OTHER threads (spawned workers,
//! `spawn_blocking`, a multi-thread runtime) are not captured. Callers drive
//! the code under test on the calling thread.
//!
//! The helper panics with a fixed message when another global subscriber is
//! already installed in the binary, and when `captured` is nested on one
//! thread. It never falls back to a thread-local install.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

pub const FIXTURE_PASSWORD: &str = "fixture-only-6822";
pub const FIXTURE_QUERY: &str = "fixture-query-6822";
pub const FIXTURE_FRAGMENT: &str = "fixture-fragment-6822";
const HOSTILE_CONTROLS: &str = "caller\0\nforged\r\t\x1b[31m\u{85}\u{2028}\u{2029}\u{202e}";
pub const CONTROL_PAIRS: &[(char, &str)] = &[
    ('\0', "\\0"),
    ('\n', "\\n"),
    ('\r', "\\r"),
    ('\t', "\\t"),
    ('\u{1b}', "\\u{1b}"),
    ('\u{85}', "\\u{85}"),
    ('\u{2028}', "\\u{2028}"),
    ('\u{2029}', "\\u{2029}"),
    ('\u{202e}', "\\u{202e}"),
];

pub fn hostile_detail() -> String {
    let mut url = reqwest::Url::parse("https://example.invalid/path").expect("fixture URL");
    url.set_username("fixture").expect("fixture username");
    url.set_password(Some(FIXTURE_PASSWORD))
        .expect("fixture password");
    url.set_query(Some(FIXTURE_QUERY));
    url.set_fragment(Some(FIXTURE_FRAGMENT));
    format!("{HOSTILE_CONTROLS} {url}")
}

/// Fixed panic text of a nested `captured` on one thread.
pub const NESTED_CAPTURE_PANIC: &str =
    "operator_log_capture: captured() called while this thread already holds an active capture";
/// Fixed panic text when another global subscriber is already installed.
pub const GLOBAL_INSTALL_PANIC: &str = "operator_log_capture: another global tracing subscriber is already installed in this test binary";
/// Fixed panic text when a capture that must hold an event is empty.
#[allow(dead_code)]
pub const EMPTY_CAPTURE_PANIC: &str =
    "operator_log_capture: expected a captured event but the capture is empty";

type Sink = Arc<Mutex<Vec<u8>>>;

thread_local! {
    /// The calling thread's active sink; `None` outside `captured`.
    static ACTIVE_SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
}

/// Writer of the global subscriber: append to this thread's sink, else discard.
struct RoutingWriter;

impl std::io::Write for RoutingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        // `try_with`: an event during thread teardown has no sink to reach.
        let _ = ACTIVE_SINK.try_with(|active| {
            if let Some(sink) = active.borrow().as_ref() {
                sink.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(bytes);
            }
        });
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Clears the calling thread's sink when dropped, including on unwind.
struct ActiveSinkGuard;

impl ActiveSinkGuard {
    fn activate(sink: &Sink) -> Self {
        ACTIVE_SINK.with(|active| {
            let mut slot = active.borrow_mut();
            assert!(slot.is_none(), "{NESTED_CAPTURE_PANIC}");
            *slot = Some(Arc::clone(sink));
        });
        Self
    }
}

impl Drop for ActiveSinkGuard {
    fn drop(&mut self) {
        let _ = ACTIVE_SINK.try_with(|active| active.borrow_mut().take());
    }
}

fn install_global_subscriber() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(|| RoutingWriter)
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::TRACE)
            .finish();
        assert!(
            tracing::subscriber::set_global_default(subscriber).is_ok(),
            "{GLOBAL_INSTALL_PANIC}"
        );
    });
}

/// Run `operation` and return its result with every event it emitted on the
/// calling thread. Events from other threads and other tests never appear.
pub fn captured<T>(operation: impl FnOnce() -> T) -> (T, String) {
    install_global_subscriber();
    let sink = Sink::default();
    let result = {
        let _active = ActiveSinkGuard::activate(&sink);
        operation()
    };
    let bytes = sink.lock().unwrap_or_else(PoisonError::into_inner).clone();
    (result, String::from_utf8(bytes).expect("UTF-8 log"))
}

/// Fail with the fixed empty-capture text when `log` holds no event, so a
/// capture that read nothing names itself instead of passing an absence check.
#[allow(dead_code)]
pub fn assert_event_captured(log: &str, what: &str) {
    assert!(!log.is_empty(), "{EMPTY_CAPTURE_PANIC}: {what}");
}
