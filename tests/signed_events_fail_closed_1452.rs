// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Regression coverage for #1452 (SEC, HIGH) — `verify_chain` must
//! FAIL-CLOSED on a row that carries no signature blob while a verifier
//! IS installed, *unless* the row is a legitimately-unsigned legacy row
//! (`attest_level == "unsigned"`).
//!
//! Before the fix, the per-row Ed25519 check only fired when the row
//! HAD a signature; a row with `signature: None` was silently skipped
//! even on a signing daemon. A tamperer could therefore insert a new
//! row, or strip the signature off an existing one, and escape per-row
//! signature detection. This test installs a real daemon verifying key
//! and asserts:
//!
//!   * an `attest_level == "unsigned"` row with no signature is skipped
//!     (no false failure — preserves legacy posture);
//!   * an `attest_level != "unsigned"` row with no signature is recorded
//!     as a signature failure (the fail-closed fix);
//!   * a properly daemon-signed row verifies clean (positive control).

use ai_memory::signed_events::{SignedEvent, append_signed_event, payload_hash, verify_chain};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

#[test]
fn missing_signature_fails_closed_unless_attest_level_unsigned() {
    let dir = tempfile::Builder::new()
        .prefix("ai-memory-1452-")
        .tempdir()
        .expect("tempdir");

    // Install a process-wide daemon signing key so
    // `resolve_daemon_verifying_key()` returns Some inside verify_chain.
    let signing = SigningKey::generate(&mut OsRng);
    ai_memory::governance::audit::init(dir.path(), Some(signing)).expect("init audit sink");
    assert!(
        ai_memory::governance::audit::resolve_daemon_verifying_key().is_some(),
        "verifier MUST be installed for this test to exercise the signed path",
    );

    let db_path = dir.path().join("chain.db");
    drop(ai_memory::db::open(&db_path).expect("init db"));
    let conn = ai_memory::db::open(&db_path).expect("open db");
    let now = chrono::Utc::now().to_rfc3339();

    // Row 1 (sequence 1): legitimately-unsigned legacy row.
    let row1 = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "alice".to_string(),
        event_type: "memory_link.created".to_string(),
        payload_hash: payload_hash(b"legacy-unsigned"),
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: now.clone(),
        ..SignedEvent::default()
    };
    append_signed_event(&conn, &row1).expect("append row1");

    // Row 2 (sequence 2): CLAIMS to be signed but carries no signature —
    // the stripped / never-signed forgery case.
    let row2 = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "alice".to_string(),
        event_type: "memory_link.created".to_string(),
        payload_hash: payload_hash(b"stripped-signature"),
        signature: None,
        attest_level: "ed25519".to_string(),
        timestamp: now.clone(),
        ..SignedEvent::default()
    };
    append_signed_event(&conn, &row2).expect("append row2");

    // Row 3 (sequence 3): properly daemon-signed (positive control).
    let row3 = SignedEvent::with_daemon_signature(
        payload_hash(b"properly-signed"),
        "alice".to_string(),
        "memory_link.created".to_string(),
        now,
    );
    assert!(
        row3.signature.is_some(),
        "with_daemon_signature MUST produce a signature when a key is installed",
    );
    append_signed_event(&conn, &row3).expect("append row3");

    let report = verify_chain(&conn, None).expect("verify_chain");

    // The prev_hash chain itself is intact (we appended through the
    // production writer), so chain_holds() is true — signature failures
    // are tracked separately.
    assert!(
        report.chain_holds(),
        "prev_hash chain MUST be intact; report = {report:?}"
    );
    assert_eq!(report.rows_checked, 3, "all three rows walked: {report:?}");

    // The fix: row 2 (signed-claim with no signature) is a failure.
    assert!(
        report.signature_failures.contains(&2),
        "row 2 (attest_level != unsigned, signature None) MUST fail closed; report = {report:?}"
    );
    // Legacy unsigned row is still skipped (no false positive).
    assert!(
        !report.signature_failures.contains(&1),
        "row 1 (attest_level == unsigned) MUST remain skip-by-design; report = {report:?}"
    );
    // Properly-signed row verifies clean.
    assert!(
        !report.signature_failures.contains(&3),
        "row 3 (properly daemon-signed) MUST verify clean; report = {report:?}"
    );

    ai_memory::governance::audit::shutdown();
}
