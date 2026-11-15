// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #8907 — the vector of a row follows the document bytes of that
//! same row (invariant I-1 of NOTICE-FIX-9284-r1).
//!
//! The update funnel reads the old row before it opens its write; a
//! writer that commits in that window must never leave its vector on a
//! row whose document the funnel then rewrites. The test seam below lets
//! an integration test commit exactly such a write inside that window.

#[cfg(any(test, feature = "test-support"))]
use std::cell::RefCell;

/// A one-shot callback run on the funnel's own connection right after
/// its pre-read: the stand-in for a second writer that commits between
/// the pre-read and the UPDATE.
#[cfg(any(test, feature = "test-support"))]
type AfterPreread = Box<dyn FnOnce(&rusqlite::Connection, &str)>;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static AFTER_PREREAD: RefCell<Option<AfterPreread>> = const { RefCell::new(None) };
}

/// #8907 test seam — arm a one-shot `hook` that the next
/// `update_with_expected_version` on THIS thread runs right after its
/// pre-read, on the same connection, with the row id.
#[cfg(any(test, feature = "test-support"))]
pub fn arm_after_update_preread(hook: impl FnOnce(&rusqlite::Connection, &str) + 'static) {
    AFTER_PREREAD.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// Run the armed pre-read hook once (test builds); a no-op otherwise.
#[cfg(any(test, feature = "test-support"))]
pub(super) fn after_update_preread(conn: &rusqlite::Connection, id: &str) {
    if let Some(hook) = AFTER_PREREAD.with(|slot| slot.borrow_mut().take()) {
        hook(conn, id);
    }
}

/// Run the armed pre-read hook once (test builds); a no-op otherwise.
#[cfg(not(any(test, feature = "test-support")))]
#[inline]
pub(super) fn after_update_preread(_conn: &rusqlite::Connection, _id: &str) {}
