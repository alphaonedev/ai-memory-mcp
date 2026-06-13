// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::doc_markdown)]

//! v0.7.0 issue #1421 — MCP `memory_store` Form-4 wire-truthfulness
//! sister-fix to the HTTP #1411 closure.
//!
//! Pre-fix `src/mcp/tools/store/validation.rs::parse_and_build_memory`
//! hardcoded `citations: Vec::new()` and `source_span: None` on the
//! constructed `Memory` row. The MCP wire schema accepted both fields
//! (validated by `crate::validate::validate_citations` /
//! `validate_source_span` indirectly via the post-fix call) and the
//! tool's `inputSchema` advertised them, but the substrate silently
//! dropped them — recall queries filtering by `citations.uri` or
//! `source_uri_prefix` missed MCP-authored rows even when the caller
//! had supplied non-empty values.
//!
//! This test pins the round-trip post-fix:
//!
//! - `memory_store` with full Form-4 fields → the inserted row carries
//!   `citations.len() == N`, `source_uri = Some(...)`, `source_span =
//!   Some(...)`.
//! - `memory_store` without the fields → empty Vec / None / None
//!   (legacy posture preserved).
//! - Invalid `citations` payload (bad shape) → `INVALID_INPUT`.
//! - Invalid `source_span` payload → `INVALID_INPUT`.

use ai_memory::config::ResolvedTtl;
use ai_memory::models::{Citation, Memory, SourceSpan};
use serde_json::{Value, json};
use std::path::PathBuf;

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1421-mcp-store-form4-test")
}

fn fresh_db() -> (tempfile::TempDir, std::path::PathBuf, rusqlite::Connection) {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::tempdir_in(&root).expect("tempdir under .local-runs");
    let db_path = dir.path().join("mcp-store.db");
    let conn = ai_memory::storage::open(&db_path).expect("open");
    (dir, db_path, conn)
}

fn call_store(
    conn: &rusqlite::Connection,
    db_path: &std::path::Path,
    params: &Value,
) -> Result<Value, String> {
    let ttl = ResolvedTtl::default();
    ai_memory::mcp::tools::handle_store_for_tests(
        conn, db_path, params, None, None, None, &ttl, false, None, None,
    )
}

/// Fetch the row back from the DB by the response's `id` so we
/// inspect the inserted `Memory` shape (not just the response envelope).
fn fetch_inserted(conn: &rusqlite::Connection, response: &Value) -> Memory {
    let id = response["id"].as_str().expect("response.id present");
    ai_memory::storage::get(conn, id)
        .expect("storage::get")
        .expect("row exists")
}

// ─────────────────────────────────────────────────────────────────────────────
// Round-trip: all three Form-4 fields land on the row
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mcp_store_round_trips_citations_source_uri_and_source_span() {
    let (_dir, db_path, conn) = fresh_db();

    let resp = call_store(
        &conn,
        &db_path,
        &json!({
            "title": "form4-mcp-roundtrip-1421",
            "content": "Form 4 wire-truthfulness regression body via MCP.",
            "namespace": "ns-1421",
            "tags": ["form4", "regression"],
            "citations": [
                {
                    "uri": "uri:https://example.test/spec.html",
                    "accessed_at": "2026-01-01T00:00:00Z",
                    "hash": "a".repeat(64),
                    "span": { "start": 0, "end": 64 }
                }
            ],
            "source_uri": "doc:parent-1421",
            "source_span": { "start": 12, "end": 24 }
        }),
    )
    .expect("memory_store ok");

    let mem = fetch_inserted(&conn, &resp);

    // citations
    assert_eq!(
        mem.citations.len(),
        1,
        "pre-#1421 this was 0 (citations dropped on insert); post-fix the single supplied citation round-trips"
    );
    assert_eq!(
        mem.citations[0].uri, "uri:https://example.test/spec.html",
        "citation.uri round-trips"
    );

    // source_uri (was already wired pre-fix; verify still works)
    assert_eq!(
        mem.source_uri.as_deref(),
        Some("doc:parent-1421"),
        "source_uri round-trips"
    );

    // source_span (pre-#1421 was None despite caller-supplied)
    let span = mem
        .source_span
        .as_ref()
        .expect("pre-#1421 this was None (source_span dropped on insert); post-fix it round-trips");
    assert_eq!(span.start, 12);
    assert_eq!(span.end, 24);
}

// ─────────────────────────────────────────────────────────────────────────────
// Negative control — absent fields → empty Vec / None (legacy preserved)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mcp_store_with_no_form4_fields_lands_empty_defaults() {
    let (_dir, db_path, conn) = fresh_db();

    let resp = call_store(
        &conn,
        &db_path,
        &json!({
            "title": "form4-mcp-control-1421",
            "content": "No Form 4 fields supplied.",
            "namespace": "ns-1421-control",
        }),
    )
    .expect("memory_store ok");

    let mem = fetch_inserted(&conn, &resp);
    assert!(mem.citations.is_empty(), "absent citations → empty Vec");
    assert!(mem.source_uri.is_none(), "absent source_uri → None");
    assert!(mem.source_span.is_none(), "absent source_span → None");
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation: malformed Form-4 payloads error cleanly
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mcp_store_rejects_malformed_citations_payload() {
    let (_dir, db_path, conn) = fresh_db();

    let err = call_store(
        &conn,
        &db_path,
        &json!({
            "title": "form4-malformed-citations-1421",
            "content": "x",
            "namespace": "ns-1421",
            "citations": "not-an-array"
        }),
    )
    .expect_err("malformed citations must error");
    assert!(
        err.contains("invalid `citations`"),
        "error names the field, got: {err}"
    );
}

#[test]
fn mcp_store_rejects_malformed_source_span_payload() {
    let (_dir, db_path, conn) = fresh_db();

    let err = call_store(
        &conn,
        &db_path,
        &json!({
            "title": "form4-malformed-span-1421",
            "content": "x",
            "namespace": "ns-1421",
            "source_span": { "start": "not-a-number" }
        }),
    )
    .expect_err("malformed source_span must error");
    assert!(
        err.contains("invalid `source_span`"),
        "error names the field, got: {err}"
    );
}

#[test]
fn mcp_store_rejects_invalid_citation_via_validator() {
    // The Citation struct enforces `validate_source_uri` on `uri` and
    // `validate_source_span` on `span` via `validate_citations`. A
    // citation with a malformed `uri` scheme errors at parse-and-build
    // time, BEFORE the substrate ever touches the row.
    let (_dir, db_path, conn) = fresh_db();

    let err = call_store(
        &conn,
        &db_path,
        &json!({
            "title": "form4-bad-citation-uri-1421",
            "content": "x",
            "namespace": "ns-1421",
            "citations": [
                {
                    "uri": "not-a-valid-scheme",
                    "accessed_at": "2026-01-01T00:00:00Z"
                }
            ]
        }),
    )
    .expect_err("citation with bad URI scheme must error");
    assert!(
        !err.is_empty(),
        "validation error message must be non-empty: {err}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Type assertions on the structured Memory shape (cross-check)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn citation_round_trip_preserves_hash_and_inner_span() {
    let (_dir, db_path, conn) = fresh_db();

    let inner_span = SourceSpan { start: 5, end: 50 };
    let citation_hash = "f".repeat(64);

    let resp = call_store(
        &conn,
        &db_path,
        &json!({
            "title": "form4-hash-span-cite-1421",
            "content": "x",
            "namespace": "ns-1421",
            "citations": [
                {
                    "uri": "doc:contract-2026",
                    "accessed_at": "2026-01-01T00:00:00Z",
                    "hash": citation_hash.clone(),
                    "span": inner_span.clone()
                }
            ]
        }),
    )
    .expect("memory_store ok");

    let mem = fetch_inserted(&conn, &resp);
    let landed: &Citation = &mem.citations[0];
    assert_eq!(landed.uri, "doc:contract-2026");
    assert_eq!(landed.hash.as_deref(), Some(citation_hash.as_str()));
    let landed_span = landed
        .span
        .as_ref()
        .expect("inner span round-trips on citation");
    assert_eq!(landed_span.start, 5);
    assert_eq!(landed_span.end, 50);
}
