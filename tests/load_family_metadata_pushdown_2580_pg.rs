// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2580 — postgres twin of
//! `tests/load_family_metadata_pushdown_2580.rs`.
//!
//! `PostgresStore::list` now pushes the SAL `Filter::metadata_eq` axis
//! into SQL as `metadata @> jsonb_build_object($9::text, $10::text)` —
//! the GIN-servable containment shape the pre-existing
//! `memories_metadata_gin` index answers with a Bitmap Index Scan.
//! Pre-#2580 the `memory_load_family` postgres branch instead fetched
//! `MAX_BULK_SIZE` (=1000) FULL rows regardless of `k` and filtered them
//! in Rust: ~982 kB moved per call to return ZERO rows, 54.3 ms p50.
//!
//! What is pinned here:
//!
//! * **Cross-backend semantic parity** — jsonb `@>` containment must
//!   accept EXACTLY the JSON shapes the sqlite `json_each` predicate and
//!   the Rust twin `as_str() == Some(v)` accept. `@>` has documented
//!   array/nesting special cases; this asserts against the live planner
//!   rather than against the docs.
//! * **The pre-existing under-return is FIXED, never regressed** — with
//!   more than `LIST_MAX_LIMIT` rows in a namespace where the
//!   family-tagged rows sort BELOW rank 1000, the pre-#2580 pipeline
//!   returned ZERO of them (a real correctness defect sqlite never had,
//!   because sqlite always pushed the predicate down). The pushdown
//!   returns them.
//! * **Unset axis is inert** — the new field must not narrow anything by
//!   default.
//!
//! Live-postgres gated via the SKIP-IF-URL-UNSET convention of the
//! shipped `*_pg` suite (`tests/claim_bitemporal_1834_pg.rs` precedent):
//! each test self-skips with an eprintln when `AI_MEMORY_TEST_POSTGRES_URL`
//! is unset so a plain `cargo test` stays green on nodes without postgres
//! routing. DELIBERATELY NOT `#[ignore]` — the coverage job does not pass
//! `--include-ignored`.
//!
//! ## How to run
//!
//! ```sh
//! AI_MEMORY_TEST_POSTGRES_URL=postgres://user:pwd@host:5432/db \
//!   cargo test --features sal,sal-postgres --test load_family_metadata_pushdown_2580_pg
//! ```

#![cfg(feature = "sal-postgres")]
#![allow(clippy::missing_panics_doc, clippy::field_reassign_with_default)]

use ai_memory::models::Memory;
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore, MetadataEq};
use serde_json::json;

async fn live_pg() -> Option<PostgresStore> {
    let url = std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()?;
    match PostgresStore::connect(&url).await {
        Ok(s) => Some(s),
        Err(e) => {
            eprintln!("skip: PostgresStore::connect failed: {e}");
            None
        }
    }
}

fn mem(id: &str, ns: &str, metadata: serde_json::Value, priority: i32) -> Memory {
    // `Memory::default()` leaves the RFC3339 stamps EMPTY, which the
    // postgres write funnel rejects as `IntegrityFailed` — set them
    // explicitly (the `tests/claim_bitemporal_1834_pg.rs` fixture shape).
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: id.to_string(),
        namespace: ns.to_string(),
        title: format!("t-{id}"),
        content: format!("body for {id}"),
        priority,
        metadata,
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    }
}

/// Every JSON shape a `metadata.family` value can take, paired with
/// whether the pre-#2580 Rust predicate accepted it. IDENTICAL to the
/// sqlite twin's matrix — that identity is the parity proof.
fn shape_matrix() -> Vec<(&'static str, serde_json::Value, bool)> {
    vec![
        ("string-exact", json!({"family": "core"}), true),
        ("string-other", json!({"family": "graph"}), false),
        ("string-prefix", json!({"family": "corex"}), false),
        ("string-case", json!({"family": "Core"}), false),
        ("string-empty", json!({"family": ""}), false),
        ("number", json!({"family": 123}), false),
        ("null", json!({"family": null}), false),
        ("bool", json!({"family": true}), false),
        ("array", json!({"family": ["core"]}), false),
        ("object", json!({"family": {"x": "core"}}), false),
        ("nested-elsewhere", json!({"a": {"family": "core"}}), false),
        ("absent", json!({"other": "core"}), false),
    ]
}

/// Drop every row of this test's OWN scratch namespace. Scoped by
/// namespace so a shared `ai_memory_test` database (the Atlas corpus and
/// sibling lanes' fixtures live in the same instance) is never touched.
async fn purge(store: &PostgresStore, ns: &str) {
    let ctx = CallerContext::for_admin("test-2580-pg");
    let _ = store.forget(&ctx, Some(ns), None, None, false).await;
}

#[tokio::test]
async fn pg_metadata_eq_pushdown_matches_rust_predicate_on_every_json_shape_2580() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let ns = "pushdown_ns_2580_shapes";
    purge(&store, ns).await;
    let ctx = CallerContext::for_admin("test-2580-pg");

    let matrix = shape_matrix();
    for (label, metadata, _) in &matrix {
        store
            .store(
                &ctx,
                &mem(&format!("pg2580-{label}"), ns, metadata.clone(), 5),
            )
            .await
            .expect("store");
    }

    let filter = Filter {
        namespace: Some(ns.to_string()),
        limit: ai_memory::storage::LIST_MAX_LIMIT,
        metadata_eq: Some(MetadataEq::new(ai_memory::META_KEY_FAMILY, "core")),
        ..Default::default()
    };
    let rows = store.list(&ctx, &filter).await.expect("list");
    let got: std::collections::BTreeSet<String> = rows.iter().map(|m| m.id.clone()).collect();
    let expected: std::collections::BTreeSet<String> = matrix
        .iter()
        .filter(|(_, _, should_match)| *should_match)
        .map(|(label, _, _)| format!("pg2580-{label}"))
        .collect();

    assert_eq!(
        got, expected,
        "postgres `metadata @> jsonb_build_object(...)` must accept EXACTLY the JSON \
         shapes the sqlite `json_each` predicate and the Rust twin accept. A divergence \
         is a cross-backend behaviour split on an ALWAYS-ON core-profile tool. \
         (jsonb containment has array/nesting special cases — this asserts against the \
         live planner, not the docs.)"
    );

    // Fail-closed twin: SQL must never widen past the Rust predicate.
    let eq = MetadataEq::new(ai_memory::META_KEY_FAMILY, "core");
    for row in &rows {
        assert!(
            eq.matches(row),
            "postgres returned {} but the canonical Rust twin rejects it — the pushdown \
             WIDENED the result set (fail-OPEN). Metadata: {}",
            row.id,
            row.metadata
        );
    }

    purge(&store, ns).await;
}

#[tokio::test]
async fn pg_unset_metadata_eq_is_inert_2580() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let ns = "pushdown_ns_2580_inert";
    purge(&store, ns).await;
    let ctx = CallerContext::for_admin("test-2580-pg");

    let matrix = shape_matrix();
    for (label, metadata, _) in &matrix {
        store
            .store(
                &ctx,
                &mem(&format!("pgin2580-{label}"), ns, metadata.clone(), 5),
            )
            .await
            .expect("store");
    }

    let filter = Filter {
        namespace: Some(ns.to_string()),
        limit: ai_memory::storage::LIST_MAX_LIMIT,
        metadata_eq: None,
        ..Default::default()
    };
    let rows = store.list(&ctx, &filter).await.expect("list");
    assert_eq!(
        rows.len(),
        matrix.len(),
        "with the axis UNSET the postgres adapter must return the full legacy window — \
         the new field must not narrow anything by default"
    );

    purge(&store, ns).await;
}

/// The pre-#2580 pipeline applied `LIMIT 1000` BEFORE the family filter,
/// so family rows that sort below global rank 1000 were SILENTLY DROPPED
/// — postgres returned fewer rows than sqlite for identical data. The
/// pushdown filters first, so they are returned.
///
/// This is a strict SUPERSET change (the fix only ever ADDS rows the old
/// code should have returned): restricting the ordering to family-tagged
/// rows can only move a family row UP in rank, so every family row inside
/// the old top-1000 is still inside the new top-1000.
#[tokio::test]
async fn pg_pushdown_recovers_family_rows_below_the_legacy_1000_row_window_2580() {
    let Some(store) = live_pg().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let ns = "pushdown_ns_2580_window";
    purge(&store, ns).await;
    let ctx = CallerContext::for_admin("test-2580-pg");

    let cap = ai_memory::storage::LIST_MAX_LIMIT;
    // `cap + 50` untagged rows at HIGH priority fill the legacy window...
    let mut batch: Vec<Memory> = (0..(cap + 50))
        .map(|i| mem(&format!("pgw2580-filler-{i:05}"), ns, json!({}), 9))
        .collect();
    // ...and 3 family-tagged rows at LOW priority sort below all of them.
    for i in 0..3 {
        batch.push(mem(
            &format!("pgw2580-family-{i}"),
            ns,
            json!({"family": "core"}),
            1,
        ));
    }
    store.store_batch(&ctx, &batch).await.expect("store_batch");

    // Legacy pipeline, replayed verbatim: fetch the top MAX_BULK_SIZE
    // rows with NO pushdown, then filter in Rust.
    let legacy = Filter {
        namespace: Some(ns.to_string()),
        limit: cap,
        ..Default::default()
    };
    let eq = MetadataEq::new(ai_memory::META_KEY_FAMILY, "core");
    let legacy_hits: Vec<String> = store
        .list(&ctx, &legacy)
        .await
        .expect("legacy list")
        .into_iter()
        .filter(|m| eq.matches(m))
        .map(|m| m.id)
        .collect();
    assert!(
        legacy_hits.is_empty(),
        "fixture invalid: the legacy fetch-then-filter pipeline was supposed to miss \
         every family row (they sort below rank {cap}); got {legacy_hits:?}"
    );

    // Pushdown pipeline: the same window, filtered FIRST.
    let pushed = Filter {
        namespace: Some(ns.to_string()),
        limit: cap,
        metadata_eq: Some(eq.clone()),
        ..Default::default()
    };
    let mut ids: Vec<String> = store
        .list(&ctx, &pushed)
        .await
        .expect("pushdown list")
        .into_iter()
        .map(|m| m.id)
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        vec![
            "pgw2580-family-0".to_string(),
            "pgw2580-family-1".to_string(),
            "pgw2580-family-2".to_string(),
        ],
        "#2580: pushing the family predicate into SQL must recover the family rows the \
         pre-fix `LIMIT {cap}`-then-filter pipeline silently dropped — postgres now \
         matches what sqlite's `handle_load_family` always returned"
    );

    purge(&store, ns).await;
}
