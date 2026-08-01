// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1877 — SAL `list()` limit-clamp parity. `PostgresStore::list` clamps
//! `filter.limit` to `LIST_MAX_LIMIT` (1000); `SqliteStore::list` previously
//! passed it through UNCLAMPED, so any SAL caller with `limit > 1000` read a
//! different window on each backend. This regression pins the sqlite side to
//! the same cap: with more than `LIST_MAX_LIMIT` rows and `limit > cap`, the
//! returned window must be exactly `LIST_MAX_LIMIT`.

#![cfg(feature = "sal")]
#![allow(clippy::missing_panics_doc, clippy::field_reassign_with_default)]

use ai_memory::models::Memory;
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, Filter, MemoryStore};

#[tokio::test]
async fn sqlite_list_clamps_limit_to_list_max_limit_1877() {
    let max = ai_memory::storage::LIST_MAX_LIMIT;
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");

    // Seed LIST_MAX_LIMIT + 25 rows in one namespace via the low-level insert.
    for i in 0..(max + 25) {
        let mut m = Memory::default();
        m.id = format!("clamp-{i:05}");
        m.namespace = "clamp_ns_1877".to_string();
        m.title = format!("row {i}");
        m.content = "x".to_string();
        ai_memory::db::insert(&conn, &m).expect("insert");
    }
    drop(conn);

    let store = SqliteStore::open(f.path()).expect("open SqliteStore");
    let ctx = CallerContext::for_admin("test-1877"); // bypass_visibility
    let filter = Filter {
        namespace: Some("clamp_ns_1877".to_string()),
        tier: None,
        tags_any: Vec::new(),
        agent_id: None,
        since: None,
        until: None,
        valid_at: None,
        limit: 5000, // > LIST_MAX_LIMIT
        active_embedding_space: None,
        // #2580 — metadata-equality pushdown axis unused on this path.
        metadata_eq: None,
    };

    let rows = store.list(&ctx, &filter).await.expect("list");
    assert!(
        rows.len() <= max,
        "SqliteStore::list returned {} rows for limit=5000 — must clamp to LIST_MAX_LIMIT ({max}); #1877 regressed",
        rows.len()
    );
    assert_eq!(
        rows.len(),
        max,
        "with {} rows and limit>cap, the clamped window must be exactly LIST_MAX_LIMIT ({max})",
        max + 25
    );
}
