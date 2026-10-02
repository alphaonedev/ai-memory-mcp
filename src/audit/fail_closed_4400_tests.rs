// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4400 — the opt-in fail-closed audit trail, end to end in one process:
//! a failed append latches, the record-stop chokepoints refuse mutations
//! (reads stay live), and a successful retry clears the latch and writes a
//! `trail_resumed` record. Every cell holds `sink_test_lock` (the sink and the
//! latch are process-global) and turns the mode on through the test override,
//! never the process environment.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use super::fail_closed::force_on_for_test;
use super::{
    AuditAction, EventBuilder, actor, audit_trail_gate, audit_trail_latched, emit,
    init_for_test_with_writer, shutdown_for_test, sink_test_lock, target_memory,
};

/// A sink whose writes fail (like a full disk) while `fail` is set.
struct Toggle {
    buf: Arc<Mutex<Vec<u8>>>,
    fail: Arc<AtomicBool>,
}

impl std::io::Write for Toggle {
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

/// Install a toggleable sink; returns (captured bytes, failure switch).
fn install() -> (Arc<Mutex<Vec<u8>>>, Arc<AtomicBool>) {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(AtomicBool::new(false));
    init_for_test_with_writer(Box::new(Toggle {
        buf: Arc::clone(&buf),
        fail: Arc::clone(&fail),
    }));
    (buf, fail)
}

fn emit_store() {
    emit(EventBuilder::new(
        AuditAction::Store,
        actor("ai:t4400", "explicit", None),
        target_memory("m", "ns", None, None, None),
    ));
}

fn memory(title: &str) -> crate::models::Memory {
    crate::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "t4400".to_string(),
        title: title.to_string(),
        content: format!("content {title}"),
        ..crate::models::Memory::default()
    }
}

/// Mode on + a failed append: the db funnel refuses the next insert with the
/// typed audit-trail refusal, and a read is still served. Red before #4400:
/// the insert succeeded (the failure was only counted).
#[test]
fn a_failed_audit_append_refuses_the_next_write_but_not_reads_4400() {
    let _g = sink_test_lock();
    force_on_for_test(true);
    let (_buf, fail) = install();
    let tmp = tempfile::tempdir().expect("tempdir");
    let conn = crate::storage::open(&tmp.path().join("t.db")).expect("open");
    let id = crate::storage::insert(&conn, &memory("before")).expect("first write");

    fail.store(true, Ordering::SeqCst);
    emit_store();
    assert!(
        audit_trail_latched(),
        "the failed append latched the process"
    );

    let refused = crate::storage::insert(&conn, &memory("during"));
    let err = refused.expect_err("a mutation is refused while latched");
    let typed = err
        .downcast_ref::<crate::storage::StorageError>()
        .expect("typed storage error");
    assert!(
        matches!(
            typed,
            crate::storage::StorageError::AuditTrailUnavailable { .. }
        ),
        "{typed:?}"
    );
    assert_eq!(
        typed.code(),
        crate::errors::error_codes::AUDIT_TRAIL_UNAVAILABLE
    );
    assert!(
        crate::storage::get(&conn, &id).expect("read").is_some(),
        "reads stay live"
    );

    shutdown_for_test();
    force_on_for_test(false);
}

/// The trail recovers: the next gated write retries it with a real
/// `trail_resumed` append, the latch clears, and the write goes through.
#[test]
fn a_recovered_trail_clears_the_latch_and_records_the_resumption_4400() {
    let _g = sink_test_lock();
    force_on_for_test(true);
    let (buf, fail) = install();
    let tmp = tempfile::tempdir().expect("tempdir");
    let conn = crate::storage::open(&tmp.path().join("t.db")).expect("open");

    fail.store(true, Ordering::SeqCst);
    emit_store();
    assert!(audit_trail_latched());
    // The first retry runs on the first gated write after latching: still
    // failing, so refused.
    assert!(crate::storage::insert(&conn, &memory("still-down")).is_err());

    fail.store(false, Ordering::SeqCst);
    // Past the retry interval.
    super::fail_closed::reset_probe_clock_for_test();
    crate::storage::insert(&conn, &memory("recovered")).expect("the retry succeeded");
    assert!(
        !audit_trail_latched(),
        "a successful retry clears the latch"
    );
    let trail = String::from_utf8(buf.lock().expect("buffer").clone()).expect("utf8");
    assert!(
        trail.contains("\"trail_resumed\""),
        "the retry is a real record in the trail: {trail}"
    );

    shutdown_for_test();
    force_on_for_test(false);
}

/// Mode off: a failed append is counted and nothing is refused (the
/// byte-identical pre-#4400 behaviour).
#[test]
fn with_the_mode_off_a_failure_never_latches_4400() {
    let _g = sink_test_lock();
    force_on_for_test(false);
    let (_buf, fail) = install();
    fail.store(true, Ordering::SeqCst);
    emit_store();
    assert!(!audit_trail_latched());
    assert!(audit_trail_gate().is_ok());
    let tmp = tempfile::tempdir().expect("tempdir");
    let conn = crate::storage::open(&tmp.path().join("t.db")).expect("open");
    crate::storage::insert(&conn, &memory("unaffected")).expect("writes proceed");
    shutdown_for_test();
}

/// The SAL surface (both backends share `gate_flag`) refuses with its own
/// typed variant, mapped to 503.
#[cfg(feature = "sal")]
#[test]
fn the_store_gate_refuses_with_its_own_variant_4400() {
    let _g = sink_test_lock();
    force_on_for_test(true);
    let (_buf, fail) = install();
    fail.store(true, Ordering::SeqCst);
    emit_store();
    let flag = crate::storage::record_stop::RecordStopFlag::default();
    let err = crate::store::record_stop::gate_flag(&flag).expect_err("refused while latched");
    assert!(
        matches!(err, crate::store::StoreError::AuditTrailUnavailable { .. }),
        "{err:?}"
    );
    assert_eq!(
        err.code(),
        crate::errors::error_codes::AUDIT_TRAIL_UNAVAILABLE
    );
    shutdown_for_test();
    force_on_for_test(false);
}

/// The general error type carries it as a retryable 503 whose text names the
/// knob, and MCP passes the text through (own vocabulary, not flattened).
#[test]
fn the_refusal_is_a_503_that_names_the_knob_4400() {
    let se = crate::storage::StorageError::AuditTrailUnavailable {
        reason: format!("x {} y", super::REQUIRE_AUDIT_TRAIL_ENV),
    };
    let me = crate::errors::MemoryError::from(anyhow::Error::new(se));
    assert_eq!(me.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        me.code(),
        crate::errors::error_codes::AUDIT_TRAIL_UNAVAILABLE
    );
    assert!(crate::mcp::error_text::mcp_error_text(&me).contains(super::REQUIRE_AUDIT_TRAIL_ENV));
}
