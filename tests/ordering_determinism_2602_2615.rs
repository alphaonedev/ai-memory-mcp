// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2602 + #2615 — total-order tiebreak regression suite for the
//! two non-deterministic wire-visible `ORDER BY` surfaces.
//!
//! #2602 — `storage::list` (`build_list_query`) + `memory_load_family`
//! ordered by `priority DESC, updated_at DESC` with NO final tiebreak.
//! `(priority, updated_at)` ties are common (priority is 1-10; bulk /
//! federated rows share an `updated_at` ms), so which rows page vs fall
//! off under LIMIT/OFFSET was plan-dependent. The fix appends `id ASC`
//! (the UUID primary key) as the final total-order key on ALL THREE
//! sites (sqlite `build_list_query`, `PostgresStore::list`,
//! `memory_load_family`), so the sort is now a STRICT total order.
//!
//! #2615 — `list_recall_observations` ordered by `observed_at DESC`
//! only; every row a single recall appends shares `observed_at`, so the
//! within-`recall_id` permutation was arbitrary on the append-only P0-1
//! AUDIT ledger. The fix appends `rank ASC, memory_id ASC`.
//!
//! These tests exercise the sqlite path (the MCP-stdio / CLI backend +
//! the sqlite half of the SAL). The postgres twins carry byte-identical
//! `ORDER BY` clauses (verified by inspection + the shared comment
//! anchors) and are covered under the live-PG suites.

use ai_memory::observations;
use rusqlite::{Connection, params};

fn fresh_db() -> Connection {
    ai_memory::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
}

/// Seed a memory with an explicit `priority` + `updated_at` + optional
/// `metadata.family`, so ties can be forced deterministically.
fn seed_mem(conn: &Connection, id: &str, ns: &str, priority: i64, updated_at: &str, family: &str) {
    let metadata = format!(r#"{{"family":"{family}"}}"#);
    conn.execute(
        "INSERT INTO memories \
            (id, tier, namespace, title, content, priority, metadata, created_at, updated_at) \
         VALUES (?1, 'long', ?2, ?3, 'content', ?4, ?5, '2025-01-01T00:00:00Z', ?6)",
        params![
            id,
            ns,
            format!("title-{id}"),
            priority,
            metadata,
            updated_at
        ],
    )
    .expect("seed memory");
}

// --------------------------------------------------------------------
// #2602 — storage::list total order
// --------------------------------------------------------------------

/// All six rows share `(priority, updated_at)`. The tiebreak makes the
/// returned order STRICTLY `id ASC`, and identical across two calls.
#[test]
fn list_ties_resolve_to_id_ascending_stably_2602() {
    let conn = fresh_db();
    let ns = "detns";
    let tied_at = "2026-01-01T00:00:00.000Z";
    // Insert deliberately OUT of id order so a naive plan could echo the
    // insertion / rowid order instead of the id order.
    for id in [
        "mem-id-03",
        "mem-id-01",
        "mem-id-05",
        "mem-id-02",
        "mem-id-06",
        "mem-id-04",
    ] {
        seed_mem(&conn, id, ns, 5, tied_at, "core");
    }

    let ids = |limit: usize, offset: usize| -> Vec<String> {
        ai_memory::storage::list(
            &conn,
            Some(ns),
            None,
            limit,
            offset,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("list")
        .into_iter()
        .map(|m| m.id)
        .collect()
    };

    let run1 = ids(100, 0);
    let run2 = ids(100, 0);
    assert_eq!(
        run1, run2,
        "two identical list calls must return identical order"
    );
    assert_eq!(
        run1,
        vec![
            "mem-id-01",
            "mem-id-02",
            "mem-id-03",
            "mem-id-04",
            "mem-id-05",
            "mem-id-06",
        ],
        "ties must resolve to strict id-ascending order"
    );

    // Which rows PAGE under LIMIT/OFFSET is now well-defined: the first
    // page is the three lowest ids, the second page the next three — no
    // row is dropped or duplicated across the boundary.
    assert_eq!(ids(3, 0), vec!["mem-id-01", "mem-id-02", "mem-id-03"]);
    assert_eq!(ids(3, 3), vec!["mem-id-04", "mem-id-05", "mem-id-06"]);
}

/// The tiebreak is subordinate to `priority DESC, updated_at DESC` — it
/// only orders WITHIN a tie group, never overrides the primary keys.
#[test]
fn list_id_tiebreak_is_subordinate_to_priority_and_updated_at_2602() {
    let conn = fresh_db();
    let ns = "ordns";
    // Higher priority wins regardless of id; newer updated_at wins within
    // a priority; id only breaks a full (priority, updated_at) tie.
    seed_mem(&conn, "zzz-hi", ns, 9, "2020-01-01T00:00:00.000Z", "core"); // pri 9 → first
    seed_mem(
        &conn,
        "aaa-mid-new",
        ns,
        5,
        "2026-01-01T00:00:00.000Z",
        "core",
    );
    seed_mem(
        &conn,
        "aaa-mid-old-b",
        ns,
        5,
        "2020-01-01T00:00:00.000Z",
        "core",
    );
    seed_mem(
        &conn,
        "aaa-mid-old-a",
        ns,
        5,
        "2020-01-01T00:00:00.000Z",
        "core",
    );

    let got: Vec<String> = ai_memory::storage::list(
        &conn,
        Some(ns),
        None,
        100,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("list")
    .into_iter()
    .map(|m| m.id)
    .collect();

    assert_eq!(
        got,
        vec![
            "zzz-hi",        // priority 9
            "aaa-mid-new",   // priority 5, newest updated_at
            "aaa-mid-old-a", // priority 5, tied updated_at, id ASC
            "aaa-mid-old-b",
        ],
    );
}

// --------------------------------------------------------------------
// #2602 — memory_load_family total order (always-on core-profile loader)
// --------------------------------------------------------------------

#[test]
fn load_family_ties_resolve_to_id_ascending_stably_2602() {
    let conn = fresh_db();
    let ns = "famns";
    let tied_at = "2026-03-03T00:00:00.000Z";
    for id in ["fam-03", "fam-01", "fam-05", "fam-02", "fam-06", "fam-04"] {
        seed_mem(&conn, id, ns, 5, tied_at, "core");
    }

    let ids = |k: u64| -> Vec<String> {
        let resp = ai_memory::mcp::handle_load_family(
            &conn,
            &serde_json::json!({"family": "core", "namespace": ns, "k": k}),
            None,
        )
        .expect("load_family");
        resp["memories"]
            .as_array()
            .expect("memories array")
            .iter()
            .map(|m| m["id"].as_str().expect("id").to_string())
            .collect()
    };

    let run1 = ids(100);
    let run2 = ids(100);
    assert_eq!(run1, run2, "two identical load_family calls must match");
    assert_eq!(
        run1,
        vec!["fam-01", "fam-02", "fam-03", "fam-04", "fam-05", "fam-06"],
    );
    // Under the k budget the SAME lowest-id prefix is served.
    assert_eq!(ids(3), vec!["fam-01", "fam-02", "fam-03"]);
}

// --------------------------------------------------------------------
// #2615 — list_recall_observations total order (audit ledger)
// --------------------------------------------------------------------

/// Insert observations that share `observed_at` (the single-recall
/// case). The tiebreak makes the order `rank ASC, memory_id ASC`,
/// stable across two reads.
#[test]
fn recall_observations_tiebreak_is_rank_then_memory_id_2615() {
    let conn = fresh_db();
    for id in ["mA", "mB", "mC", "mD"] {
        seed_mem(&conn, id, "obs", 5, "2025-01-01T00:00:00Z", "core");
    }

    let tied_at = "2026-02-02T00:00:00.000Z";
    // Same recall_id, all rows share observed_at. Insert out of order.
    // Two rows share rank=2 (mB, mA) → memory_id ASC breaks it (mA<mB).
    let insert = |memory_id: &str, rank: i64, observed_at: &str| {
        conn.execute(
            "INSERT INTO recall_observations \
                (recall_id, memory_id, retriever, rank, score, observed_at, folded) \
             VALUES ('rid', ?1, 'hybrid', ?2, 0.5, ?3, 0)",
            params![memory_id, rank, observed_at],
        )
        .expect("insert observation");
    };
    insert("mB", 2, tied_at);
    insert("mA", 2, tied_at);
    insert("mC", 1, tied_at);
    // A row with a strictly NEWER observed_at must still sort FIRST — the
    // tiebreak is subordinate to the primary `observed_at DESC` key.
    insert("mD", 9, "2026-02-02T00:00:01.000Z");

    let order = |conn: &Connection| -> Vec<(String, i64)> {
        observations::list_observations(conn, Some("rid"), None, None, None, 100)
            .expect("list_observations")
            .into_iter()
            .map(|o| (o.memory_id, o.rank))
            .collect()
    };

    let run1 = order(&conn);
    let run2 = order(&conn);
    assert_eq!(
        run1, run2,
        "two identical ledger reads must return identical order"
    );
    assert_eq!(
        run1,
        vec![
            ("mD".to_string(), 9), // newest observed_at → first
            ("mC".to_string(), 1), // then rank ASC within the tied observed_at
            ("mA".to_string(), 2), // rank tie → memory_id ASC
            ("mB".to_string(), 2),
        ],
    );
}
