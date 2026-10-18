// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7381 - the fail-closed latch is scoped to the thread whose test set it.
//!
//! Before the fix the latch was process-global, so a test that latched it made
//! an unlocked write-path test on another thread (the shape of
//! `handle_store_happy_returns_id_and_tier`, a plain `memory_store` write)
//! refuse with "the audit trail is not recording". Each cell below drives the
//! same chokepoint those tests reach, `storage::insert` behind
//! `audit_trail_gate`. The cells need the lib's `cfg(test)` latch helpers, so
//! they live in the lib test tree and not under `tests/`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::fail_closed::{force_on_for_test, latch_for_test};
use super::{
    AuditAction, EventBuilder, REQUIRE_AUDIT_TRAIL_ENV, actor, audit_trail_gate,
    audit_trail_latched, emit, init_for_test_with_writer, shutdown_for_test, sink_test_lock,
    target_memory,
};

fn memory(title: &str) -> crate::models::Memory {
    crate::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "t7381".to_string(),
        title: title.to_string(),
        content: format!("content {title}"),
        ..crate::models::Memory::default()
    }
}

/// An unlocked write on its own thread: the shape of the 52 inventoried tests.
fn unlocked_store_on_other_thread() -> Result<(), String> {
    std::thread::spawn(|| {
        audit_trail_gate().map_err(|e| e.reason)?;
        let conn = crate::storage::open(std::path::Path::new(":memory:"))
            .map_err(|e| format!("open: {e}"))?;
        crate::storage::insert(&conn, &memory("unlocked-writer")).map_err(|e| e.to_string())?;
        Ok(())
    })
    .join()
    .expect("writer thread panicked")
}

/// Cell A - a latch held on thread A does not refuse an unlocked store on
/// thread B. Red before #7381: thread B refused with the fail-closed text.
#[test]
fn a_latch_on_one_thread_does_not_refuse_an_unlocked_store_on_another_7381() {
    let _g = sink_test_lock();
    let _latch = latch_for_test();
    assert!(audit_trail_latched(), "thread A is latched");
    unlocked_store_on_other_thread().expect("the unlocked writer on thread B must succeed");
}

/// Cell B - the latch still refuses on its own thread, at the gate and at the
/// storage chokepoint, and the refusal names the knob. Green on base and head.
#[test]
fn the_latch_still_refuses_on_its_own_thread_7381() {
    let _g = sink_test_lock();
    let latch = latch_for_test();
    let refused = audit_trail_gate().expect_err("the owning thread is refused");
    assert!(
        refused.reason.contains(REQUIRE_AUDIT_TRAIL_ENV),
        "{}",
        refused.reason
    );
    let conn = crate::storage::open(std::path::Path::new(":memory:")).expect("open");
    let err = crate::storage::insert(&conn, &memory("own-thread")).expect_err("write refused");
    assert!(
        matches!(
            err.downcast_ref::<crate::storage::StorageError>(),
            Some(crate::storage::StorageError::AuditTrailUnavailable { .. })
        ),
        "{err:?}"
    );
    drop(latch);
    assert!(audit_trail_gate().is_ok(), "dropping the guard reopens it");
}

/// A sink whose writes fail while `fail` is set.
struct Failing {
    fail: Arc<AtomicBool>,
    buf: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Write for Failing {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(std::io::Error::from_raw_os_error(28)); // ENOSPC
        }
        self.buf.lock().expect("buffer").extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Cell C - the production latch path (a real failed append through
/// `note_failure_for_latch`, not the `latch_for_test` shortcut) still refuses
/// the thread that turned the mode on, while an unlocked thread is untouched.
#[test]
fn a_real_failed_append_latches_the_owner_and_spares_other_threads_7381() {
    let _g = sink_test_lock();
    force_on_for_test(true);
    let fail = Arc::new(AtomicBool::new(false));
    init_for_test_with_writer(Box::new(Failing {
        fail: Arc::clone(&fail),
        buf: Arc::new(Mutex::new(Vec::new())),
    }));
    fail.store(true, Ordering::SeqCst);
    emit(EventBuilder::new(
        AuditAction::Store,
        actor("ai:t7381", "explicit", None),
        target_memory("m", "ns", None, None, None),
    ));
    assert!(audit_trail_latched(), "the failed append latched");
    assert!(audit_trail_gate().is_err(), "the owner thread is refused");
    unlocked_store_on_other_thread().expect("another thread is not refused");
    shutdown_for_test();
    force_on_for_test(false);
}
