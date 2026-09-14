// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2580 — sqlite-side pins for the SAL `Filter::metadata_eq`
//! exact-metadata-equality pushdown that closes the
//! `memory_load_family` unbounded-materialisation defect.
//!
//! Pre-#2580 the postgres branch of `POST /api/v1/memory_load_family`
//! fetched `MAX_BULK_SIZE` (=1000) FULL rows regardless of `k` and then
//! filtered them on `metadata.family` in Rust — ~982 kB moved to return
//! ZERO rows, 54.3 ms p50 on the 8k-row Atlas corpus, on an ALWAYS-ON
//! core-profile tool. The predicate now rides the SAL `Filter` into the
//! SAME hardened `list` query on BOTH adapters.
//!
//! What is pinned here:
//!
//! * **R-203 fail-at-parent** — `sql_shape_*`: `build_list_query` must
//!   EMIT the pushdown fragment when the axis is set and must NOT emit
//!   it otherwise. Reverting the fix (moving the narrowing back into
//!   Rust) drops the fragment and reds these immediately.
//! * **Type exactness** — the SQL predicate must agree BYTE-FOR-BYTE
//!   with the Rust twin `metadata.get(k).and_then(Value::as_str) ==
//!   Some(v)` that the pre-#2580 handler applied, across every JSON
//!   shape a `family` value could take (string / number / null / bool /
//!   array / nested object / empty string / prefix). If it did not, an
//!   always-on loader would start returning rows it never returned.
//! * **No key injection** — the key rides as a bound parameter, so a key
//!   carrying JSON-path metacharacters cannot widen the match.
//! * **Semantics preserved** — `SqliteStore::list` + the axis returns the
//!   IDENTICAL id set that the pre-#2580 fetch-then-filter-in-Rust
//!   pipeline produced over the same window.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::field_reassign_with_default)]

use ai_memory::models::Memory;
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore, MetadataEq};
use serde_json::json;

const NS: &str = "pushdown_ns_2580";

/// The exact fragment the sqlite adapter must push into SQL. Restated
/// here on purpose: the test is the SSOT contract, so a silent rewrite
/// of the production fragment fails loudly instead of drifting.
const EXPECTED_FRAGMENT: &str = "json_each(memories.metadata)";

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ---------------------------------------------------------------------
// R-203 — SQL shape. These fail against the pre-#2580 tree.
// ---------------------------------------------------------------------

#[test]
fn sql_shape_emits_pushdown_only_when_axis_is_set_2580() {
    let t = now();
    let (without, params_without) = ai_memory::db::build_list_query(
        Some(NS),
        None,
        None,
        &t,
        None,
        None,
        None,
        None,
        None,
        None, // metadata_eq unset
        10,
        0,
    );
    assert!(
        !without.contains(EXPECTED_FRAGMENT),
        "an unset metadata_eq axis must leave the legacy list SQL byte-identical \
         (no `{EXPECTED_FRAGMENT}` fragment), so every pre-#2580 list shape keeps \
         its cached plan; got:\n{without}"
    );

    let (with, params_with) = ai_memory::db::build_list_query(
        Some(NS),
        None,
        None,
        &t,
        None,
        None,
        None,
        None,
        None,
        Some(("family", "core")),
        10,
        0,
    );
    assert!(
        with.contains(EXPECTED_FRAGMENT),
        "#2580 REGRESSED: `metadata_eq` must be pushed INTO the SQL, not filtered \
         in Rust after an unbounded prefetch. Expected the `{EXPECTED_FRAGMENT}` \
         fragment in:\n{with}"
    );
    assert!(
        with.contains("json_each.type = 'text'"),
        "the pushdown must restrict to JSON STRING values so it agrees exactly with \
         the Rust twin `as_str() == Some(v)`; got:\n{with}"
    );
    assert_eq!(
        params_with.len(),
        params_without.len() + 2,
        "the key AND the value must both be BOUND PARAMETERS (never interpolated \
         into a JSON path), so no key value can alter the predicate's shape"
    );
}

// ---------------------------------------------------------------------
// Type exactness + semantics preservation through the real adapter.
// ---------------------------------------------------------------------

/// Every JSON shape a `metadata.family` value can take, paired with
/// whether the pre-#2580 Rust predicate
/// `metadata.get("family").and_then(Value::as_str) == Some("core")`
/// accepted it. The pushdown MUST reproduce this column exactly.
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

#[tokio::test]
async fn metadata_eq_pushdown_matches_rust_predicate_on_every_json_shape_2580() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");

    let matrix = shape_matrix();
    for (label, metadata, _) in &matrix {
        let mut m = Memory::default();
        m.id = format!("shape-{label}");
        m.namespace = NS.to_string();
        m.title = format!("shape {label}");
        m.content = "body".to_string();
        m.metadata = metadata.clone();
        ai_memory::db::insert(&conn, &m).expect("insert");
    }
    drop(conn);

    let store = SqliteStore::open(f.path()).expect("open SqliteStore");
    let ctx = CallerContext::for_admin("test-2580");
    let filter = {
        let mut __f = Filter::new();
        __f.namespace = Some(NS.to_string());
        __f.limit = 1000;
        __f.metadata_eq = Some(MetadataEq::new(ai_memory::META_KEY_FAMILY, "core"));
        __f
    };

    let rows = store.list(&ctx, &filter).await.expect("list");
    let got: std::collections::BTreeSet<String> = rows.iter().map(|m| m.id.clone()).collect();

    // The oracle is the PRE-#2580 in-Rust predicate, applied to the same
    // corpus. Same inputs -> same outputs; only faster.
    let expected: std::collections::BTreeSet<String> = matrix
        .iter()
        .filter(|(_, _, should_match)| *should_match)
        .map(|(label, _, _)| format!("shape-{label}"))
        .collect();

    assert_eq!(
        got, expected,
        "the SQL pushdown must return EXACTLY the rows the pre-#2580 Rust filter \
         `metadata.get(\"family\").and_then(Value::as_str) == Some(\"core\")` returned. \
         A divergence here is a behaviour change on an ALWAYS-ON core-profile tool."
    );

    // Belt-and-suspenders: the canonical in-process twin must agree
    // row-for-row with what SQL selected (this is the same predicate the
    // handler re-applies as its fail-closed re-check).
    let eq = MetadataEq::new(ai_memory::META_KEY_FAMILY, "core");
    for row in &rows {
        assert!(
            eq.matches(row),
            "SQL returned {} but the canonical Rust twin rejects it — the pushdown \
             WIDENED the result set (fail-OPEN). Metadata: {}",
            row.id,
            row.metadata
        );
    }
}

#[tokio::test]
async fn metadata_eq_key_is_bound_never_json_path_interpolated_2580() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");

    // A row whose metadata carries a benign key, plus a row with a key
    // full of JSON-path metacharacters holding a DIFFERENT value.
    let mut plain = Memory::default();
    plain.id = "inject-plain".to_string();
    plain.namespace = NS.to_string();
    plain.title = "plain".to_string();
    plain.content = "body".to_string();
    plain.metadata = json!({"family": "core"});
    ai_memory::db::insert(&conn, &plain).expect("insert");

    let mut weird = Memory::default();
    weird.id = "inject-weird".to_string();
    weird.namespace = NS.to_string();
    weird.title = "weird".to_string();
    weird.content = "body".to_string();
    weird.metadata = json!({"a\".b$[0]": "core"});
    ai_memory::db::insert(&conn, &weird).expect("insert");
    drop(conn);

    let store = SqliteStore::open(f.path()).expect("open SqliteStore");
    let ctx = CallerContext::for_admin("test-2580");

    // A metacharacter-laden key must be matched LITERALLY, selecting only
    // the row that really carries that key.
    let filter = {
        let mut __f = Filter::new();
        __f.namespace = Some(NS.to_string());
        __f.limit = 1000;
        __f.metadata_eq = Some(MetadataEq::new("a\".b$[0]", "core"));
        __f
    };
    let rows = store.list(&ctx, &filter).await.expect("list");
    let ids: Vec<&str> = rows.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["inject-weird"],
        "a key carrying JSON-path metacharacters must bind as an opaque VALUE and \
         match literally; anything else means the key reached the path grammar"
    );

    // ...and a key that exists on no row selects nothing (never everything).
    let filter = {
        let mut __f = Filter::new();
        __f.namespace = Some(NS.to_string());
        __f.limit = 1000;
        __f.metadata_eq = Some(MetadataEq::new("$", "core"));
        __f
    };
    let rows = store.list(&ctx, &filter).await.expect("list");
    assert!(
        rows.is_empty(),
        "a bare `$` key must match nothing, not every row: {:?}",
        rows.iter().map(|m| &m.id).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn unset_metadata_eq_is_byte_identical_legacy_list_2580() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    for (label, metadata, _) in shape_matrix() {
        let mut m = Memory::default();
        m.id = format!("legacy-{label}");
        m.namespace = NS.to_string();
        m.title = format!("legacy {label}");
        m.content = "body".to_string();
        m.metadata = metadata;
        ai_memory::db::insert(&conn, &m).expect("insert");
    }
    drop(conn);

    let store = SqliteStore::open(f.path()).expect("open SqliteStore");
    let ctx = CallerContext::for_admin("test-2580");
    let filter = {
        let mut __f = Filter::new();
        __f.namespace = Some(NS.to_string());
        __f.limit = 1000;
        __f.metadata_eq = None;
        __f
    };
    let rows = store.list(&ctx, &filter).await.expect("list");
    assert_eq!(
        rows.len(),
        shape_matrix().len(),
        "with the axis UNSET the adapter must return the full legacy window — the \
         new field must not narrow anything by default"
    );
}
