// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#2592](https://github.com/alphaonedev/ai-memory-mcp/issues/2592) —
//! the 1000-subscriber dispatch cliff must not be SILENT.
//!
//! `dispatch_event_postgres` pulls subscription mirror rows with a hard
//! `LIMIT SUBSCRIPTION_DISPATCH_LIMIT` on an `ORDER BY namespace` scan and no
//! cursor. Past that ceiling, subscribers sorting after it receive no event —
//! and because the ordering is stable, the SAME tail is cut on every
//! subsequent write, so the loss is permanent rather than transient. Pre-#2592
//! that produced no error, no warning, no metric and no DLQ entry: a
//! correctness cliff indistinguishable from "nobody was subscribed".
//!
//! This file pins the three surfaces an operator actually watches, plus the
//! source-level invariant that the dispatch path still checks for truncation
//! at all (cell C is the one that fails if a later refactor drops the check
//! while leaving the helper behind).

#![allow(clippy::missing_panics_doc, clippy::uninlined_format_args)]

use ai_memory::subscriptions::{
    DISPATCH_SCAN_TRUNCATED_SUB_ID, list_dlq, record_dispatch_scan_truncation,
};

/// The ceiling the production scan uses, mirrored here so the cells read the
/// same number the dispatcher does.
const DISPATCH_LIMIT: usize = 1000;

// ---------------------------------------------------------------------------
// CELL A — a truncated scan lands a DURABLE, inspectable record.
// ---------------------------------------------------------------------------

#[test]
fn a_truncated_scan_appends_an_inspectable_dlq_row_2592() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("dispatch.db");
    let conn = ai_memory::db::open(&path).expect("open");

    record_dispatch_scan_truncation(
        &path,
        "memory_created",
        "mem-abc",
        "team/ops",
        DISPATCH_LIMIT,
        DISPATCH_LIMIT,
    );

    let rows = list_dlq(&conn, Some(DISPATCH_SCAN_TRUNCATED_SUB_ID)).expect("list_dlq");
    assert_eq!(
        rows.len(),
        1,
        "a truncated dispatch must leave exactly one durable record, got {rows:?}"
    );
    let row = &rows[0];
    assert_eq!(row.subscription_id, DISPATCH_SCAN_TRUNCATED_SUB_ID);
    assert_eq!(
        row.event_type, "memory_created",
        "the record must name the event that went undelivered"
    );
    // The payload has to carry enough to act on: WHICH write, WHICH namespace,
    // and how far the scan got before the ceiling cut it.
    let payload: serde_json::Value = serde_json::from_str(&row.payload).expect("payload is json");
    assert_eq!(payload["memory_id"], "mem-abc");
    assert_eq!(payload["namespace"], "team/ops");
    assert_eq!(payload["scanned"], DISPATCH_LIMIT);
    assert_eq!(payload["limit"], DISPATCH_LIMIT);
    assert!(
        row.last_error.contains("truncated"),
        "the record must say WHY it exists, got {:?}",
        row.last_error
    );
}

// ---------------------------------------------------------------------------
// CELL B — the metric moves, so a fleet sees the cliff without reading logs.
// ---------------------------------------------------------------------------

#[test]
fn b_truncated_scan_increments_the_metric_2592() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("metric.db");
    let _conn = ai_memory::db::open(&path).expect("open");

    let before = ai_memory::metrics::subscription_dispatch_truncated_count();
    record_dispatch_scan_truncation(
        &path,
        "memory_updated",
        "mem-1",
        "ns",
        DISPATCH_LIMIT,
        DISPATCH_LIMIT,
    );
    record_dispatch_scan_truncation(
        &path,
        "memory_updated",
        "mem-2",
        "ns",
        DISPATCH_LIMIT,
        DISPATCH_LIMIT,
    );
    let after = ai_memory::metrics::subscription_dispatch_truncated_count();
    // `>=` not `==`: the registry is process-global and the sibling cells in
    // this binary run in parallel, so a strict equality would be flaky for a
    // reason unrelated to the contract under test.
    assert!(
        after - before >= 2,
        "each truncated dispatch tick must move the counter; {before} -> {after}"
    );
}

// ---------------------------------------------------------------------------
// CELL C — the dispatch path still DETECTS truncation.
// ---------------------------------------------------------------------------

/// Cells A and B prove the reporter works; this one proves it is still wired
/// to the scan. A refactor that dropped the length check would leave A and B
/// green while restoring the silent cliff, which is exactly the vacuity trap
/// the #2449 harness lesson names.
#[test]
fn c_dispatch_path_checks_the_scan_against_the_ceiling_2592() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers/subscriptions.rs"),
    )
    .expect("read src/handlers/subscriptions.rs");
    let start = src
        .find("pub async fn dispatch_event_postgres(")
        .expect("dispatch_event_postgres must exist");
    let body = &src[start..];
    let end = body
        .find("\npub ")
        .or_else(|| body.find("\n#[cfg(test)]"))
        .unwrap_or(body.len());
    let body = &body[..end];

    assert!(
        body.contains("saturating_add(1)")
            && body.contains("memories.len() > SUBSCRIPTION_DISPATCH_LIMIT"),
        "the dispatcher must fetch LIMIT+1 and compare with `>` so an exactly-full \
         population is not a false-positive truncation:\n{body}"
    );
    assert!(
        body.contains("record_dispatch_scan_truncation"),
        "a truncated scan must be reported, not inferred from a missing webhook:\n{body}"
    );
    // The report must precede the zero-match early return: the truncated tail
    // is exactly where the matching subscribers may have been, so "matched
    // zero subscribers" is not evidence that nothing was lost.
    //
    // Anchor on the CODE of the early return (`if matching.is_empty() {`), not
    // on its log text: the fix's own rationale comment quotes that text, so a
    // text anchor matches the comment tens of lines earlier and this ordering
    // assertion would grade the comment instead of the control.
    let report_at = body
        .find("record_dispatch_scan_truncation")
        .expect("reporter call");
    let early_return_at = body
        .find("if matching.is_empty() {")
        .expect("the zero-match early return");
    assert!(
        report_at < early_return_at,
        "truncation must be reported BEFORE the zero-match early return \
         (reporter at {report_at}, early return at {early_return_at})"
    );
}
