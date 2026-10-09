// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4214 (WP-FAULT #6051) — ONE non-BLOB `encrypted_envelope` cell must not
//! fail the whole embedding backfill batch.
//!
//! `embeddable_row_mapper` (the row mapper behind every unembedded /
//! reembed scan) still read the envelope with a typed `Option<Vec<u8>>`
//! get, so a TEXT / INTEGER / REAL cell (corruption or tampering, the #4133
//! input) made the whole `query_map` fail with `Invalid column type`. The
//! backfill returned the error and never got past that row: no later row
//! was embedded and semantic recall degraded for the entire corpus (the
//! #2336 / #2383 one-row-denies-the-scan class).
//!
//! Expected (the #4133 scan-read disposition, as `resolve_embeddable_scan`
//! already applies to an undecryptable envelope): the poisoned row is
//! SKIPPED with a WARN + the `corrupt_provenance` metric, the raw cursor
//! advances past it, and the healthy sibling is still returned.

use ai_memory::models::{Memory, Tier};
use rusqlite::types::Value as Sql;
use serde_json::json;
use std::path::Path;

const NS: &str = "env4214";
const OWNER: &str = "ai:owner-4214";
const ENVELOPE_COLUMN: &str = "encrypted_envelope";

/// The corrupt envelope cells under test: (label, value).
fn corrupt_envelopes() -> [(&'static str, Sql); 3] {
    [
        ("text", Sql::Text("not-an-envelope".to_string())),
        ("integer", Sql::Integer(17)),
        ("real", Sql::Real(1.5)),
    ]
}

fn seed(conn: &rusqlite::Connection, id: &str, marker: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: id.to_string(),
        title: format!("{marker} title 4214"),
        content: format!("{marker} body 4214"),
        namespace: NS.to_string(),
        tier: Tier::Long,
        metadata: json!({"agent_id": OWNER}),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("seed")
}

/// Fresh in-memory store with two unembedded rows; the POISONED row sorts
/// FIRST by id so the keyset scan has to get past it to reach the healthy
/// one. Returns `(conn, poisoned_id, healthy_id)`.
fn fixture(envelope: &Sql) -> (rusqlite::Connection, String, String) {
    let conn = ai_memory::db::open(Path::new(":memory:")).expect("open");
    let mut ids = [
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    ];
    ids.sort();
    let poisoned = seed(&conn, &ids[0], "poisoned");
    let healthy = seed(&conn, &ids[1], "healthy");
    let n = conn
        .execute(
            "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
            rusqlite::params![envelope, poisoned],
        )
        .expect("poison envelope");
    assert_eq!(n, 1);
    (conn, poisoned, healthy)
}

fn corrupt_envelope_rows_total() -> u64 {
    ai_memory::metrics::registry()
        .corrupt_provenance_rows_total
        .with_label_values(&[ENVELOPE_COLUMN])
        .get()
}

fn ids(rows: &[(String, String, String)]) -> Vec<String> {
    rows.iter().map(|(id, ..)| id.clone()).collect()
}

/// The keyset backfill scan (the live MCP tick + the resilient sweep).
#[test]
fn keyset_backfill_scan_skips_a_non_blob_envelope_and_continues_4214() {
    for (label, envelope) in corrupt_envelopes() {
        let (conn, poisoned, healthy) = fixture(&envelope);
        let before = corrupt_envelope_rows_total();
        let scan = ai_memory::db::get_unembedded_ids_batch_after(&conn, None, 100)
            .unwrap_or_else(|e| panic!("{label}: one poisoned row failed the whole batch: {e}"));
        assert_eq!(
            ids(&scan.rows),
            vec![healthy.clone()],
            "{label}: the healthy sibling must still be returned and the \
             poisoned row omitted"
        );
        assert_eq!(
            scan.decrypt_skipped, 1,
            "{label}: the malformed cell counts as a decrypt-skip"
        );
        assert_eq!(
            scan.raw_last_id.as_deref(),
            Some(healthy.as_str()),
            "{label}: the raw cursor advances past the poisoned row"
        );
        assert!(
            corrupt_envelope_rows_total() > before,
            "{label}: the corrupt_provenance metric must be bumped for {ENVELOPE_COLUMN}"
        );
        assert!(
            !ids(&scan.rows).contains(&poisoned),
            "{label}: the poisoned row must never be handed to the embedder"
        );
    }
}

/// The LIMIT-only batch (free-function boot path).
#[test]
fn limit_backfill_scan_skips_a_non_blob_envelope_4214() {
    for (label, envelope) in corrupt_envelopes() {
        let (conn, _poisoned, healthy) = fixture(&envelope);
        let rows = ai_memory::db::get_unembedded_ids_batch(&conn, 100)
            .unwrap_or_else(|e| panic!("{label}: one poisoned row failed the whole batch: {e}"));
        assert_eq!(ids(&rows), vec![healthy], "{label}");
    }
}

/// The `ai-memory reembed` full-corpus sweep shares the same row mapper.
#[test]
fn reembed_scan_skips_a_non_blob_envelope_4214() {
    for (label, envelope) in corrupt_envelopes() {
        let (conn, _poisoned, healthy) = fixture(&envelope);
        let scan = ai_memory::db::get_memory_texts_batch(&conn, Some(NS), None, 100, None)
            .unwrap_or_else(|e| panic!("{label}: one poisoned row failed the whole sweep: {e}"));
        assert_eq!(ids(&scan.rows), vec![healthy], "{label}");
        assert_eq!(scan.decrypt_skipped, 1, "{label}");
    }
}

/// Control: a healthy BLOB-less corpus is untouched by the fix — both rows
/// are returned and nothing is counted as skipped.
#[test]
fn healthy_rows_still_scan_unchanged_4214() {
    let conn = ai_memory::db::open(Path::new(":memory:")).expect("open");
    let mut ids_sorted = [
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    ];
    ids_sorted.sort();
    let a = seed(&conn, &ids_sorted[0], "a");
    let b = seed(&conn, &ids_sorted[1], "b");
    let scan = ai_memory::db::get_unembedded_ids_batch_after(&conn, None, 100).expect("scan");
    assert_eq!(ids(&scan.rows), vec![a, b.clone()]);
    assert_eq!(scan.decrypt_skipped, 0);
    assert_eq!(scan.raw_last_id.as_deref(), Some(b.as_str()));
}
