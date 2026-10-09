// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4718 — the sqlite bind-time chain-depth check (#4492) reads ONLY the
//! affected subgraph of `namespace_meta`, not the whole link column, while it
//! holds the bind's write lock: the upward chains from the bound namespace's
//! OLD and NEW parents plus every row whose own chain reaches the bound
//! namespace, through one recursive CTE. The decision
//! (`governance::bind_chain_depth::bind_exceeds_chain_depth`) is unchanged
//! and renders the IDENTICAL verdict on the subgraph and on the full column.
//!
//! Cells:
//! - a bind whose neighbourhood is intact succeeds although an UNRELATED link
//!   row cannot be read (the full-column read failed closed on it: red on the
//!   pre-#4718 tree);
//! - the subgraph never carries more than the neighbourhood (1,000 unrelated
//!   chains stay unread);
//! - verdict parity with the full-column read over random graphs with chains,
//!   cycles, `*` parents, slash-named nodes and dangling parents.

use ai_memory::db::bind_chain_depth::load_bind_link_subgraph;
use ai_memory::governance::bind_chain_depth::{LinkRow, bind_exceeds_chain_depth};
use tempfile::TempDir;

fn fresh_conn() -> (TempDir, rusqlite::Connection) {
    let tmp = TempDir::new().expect("tempdir");
    let conn = ai_memory::db::open(&tmp.path().join("ai-memory.db")).expect("open");
    (tmp, conn)
}

/// A standard memory the bind can point at.
fn plant_standard(conn: &rusqlite::Connection, id: &str) {
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
         VALUES (?1, 'long', 'std4718', ?1, 'standard', \
                 '2026-10-03T00:00:00Z', '2026-10-03T00:00:00Z')",
        rusqlite::params![id],
    )
    .expect("plant standard memory");
}

fn plant_links(conn: &rusqlite::Connection, links: &[(String, Option<String>)]) {
    for (ns, parent) in links {
        conn.execute(
            "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace) \
             VALUES (?1, 'ghost', '2026-10-03T00:00:00Z', ?2) \
             ON CONFLICT(namespace) DO UPDATE SET parent_namespace = ?2",
            rusqlite::params![ns, parent],
        )
        .expect("plant link");
    }
}

/// `{p}{from} -> ... -> {p}{to}` as (namespace, parent) rows.
fn chain(p: &str, from: usize, to: usize) -> Vec<(String, Option<String>)> {
    (from..to)
        .map(|i| (format!("{p}{i}"), Some(format!("{p}{}", i + 1))))
        .collect()
}

fn all_links(conn: &rusqlite::Connection) -> Vec<LinkRow> {
    let mut stmt = conn
        .prepare("SELECT namespace, parent_namespace FROM namespace_meta WHERE parent_namespace IS NOT NULL")
        .expect("prepare");
    stmt.query_map([], |r| {
        Ok(LinkRow {
            namespace: r.get(0)?,
            parent: r.get(1)?,
        })
    })
    .expect("query")
    .collect::<rusqlite::Result<Vec<_>>>()
    .expect("rows")
}

/// The defect's observable edge: a bind must not read (and fail closed on) a
/// link row that is not in its neighbourhood.
#[test]
fn bind_ignores_an_unreadable_unrelated_link_row_4718() {
    let (_t, conn) = fresh_conn();
    plant_standard(&conn, "std-4718");
    // The bound namespace's neighbourhood: v -> p -> q.
    plant_links(&conn, &[("p".into(), Some("q".into()))]);
    // An unrelated chain with a row that cannot be read as text.
    plant_links(&conn, &chain("u", 0, 3));
    conn.execute(
        "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace) \
         VALUES (X'DEADBEEF', 'ghost', '2026-10-03T00:00:00Z', 'u0')",
        [],
    )
    .expect("plant unreadable unrelated row");
    ai_memory::db::set_namespace_standard(&conn, "v", "std-4718", Some("p"))
        .expect("a bind reads only its own neighbourhood (#4718)");
    let parent: Option<String> = conn
        .query_row(
            "SELECT parent_namespace FROM namespace_meta WHERE namespace = 'v'",
            [],
            |r| r.get(0),
        )
        .expect("bound row");
    assert_eq!(parent.as_deref(), Some("p"));
}

/// The bind's own neighbourhood is still read in full: a link that would
/// cross the bound is refused exactly as before (#4492).
#[test]
fn bind_still_refuses_a_crossing_link_from_the_subgraph_4718() {
    let (_t, conn) = fresh_conn();
    plant_standard(&conn, "std-4718");
    // c1 -> ... -> c9 (8 hops from c1); binding v -> c1 is 9.
    plant_links(&conn, &chain("c", 1, 9));
    let err = ai_memory::db::set_namespace_standard(&conn, "v", "std-4718", Some("c1"))
        .expect_err("nine hops must be refused");
    assert!(
        ai_memory::db::bind_chain_depth::is_bind_chain_over_depth(&err),
        "{err:#}"
    );
}

#[test]
fn subgraph_is_bounded_by_the_neighbourhood_4718() {
    let (_t, conn) = fresh_conn();
    // 1,000 unrelated two-hop chains.
    let mut rows = Vec::new();
    for i in 0..1_000 {
        rows.extend(chain(&format!("x{i}_"), 0, 2));
    }
    plant_links(&conn, &rows);
    // The neighbourhood: a -> b -> v (old) ; v -> o1 -> o2 ; new parent n1 -> n2.
    plant_links(
        &conn,
        &[
            ("a".into(), Some("b".into())),
            ("b".into(), Some("v".into())),
            ("v".into(), Some("o1".into())),
            ("o1".into(), Some("o2".into())),
            ("n1".into(), Some("n2".into())),
        ],
    );
    let sub = load_bind_link_subgraph(&conn, "v", Some("n1")).expect("subgraph");
    let names: Vec<&str> = sub.iter().map(|r| r.namespace.as_str()).collect();
    for expected in ["a", "b", "v", "o1", "n1"] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    assert!(
        sub.len() <= 5,
        "the subgraph must not carry unrelated rows: {names:?}"
    );
}

/// Deterministic xorshift so the parity cell needs no `rand` dependency.
fn next(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn subgraph_verdict_matches_the_full_read_on_random_graphs_4718() {
    let (_t, mut conn) = fresh_conn();
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut refusals_seen = 0usize;
    for round in 0..300 {
        let nodes = 3 + usize::try_from(next(&mut state) % 40).unwrap_or(3);
        let name = |i: usize| {
            if i % 7 == 6 {
                format!("s/{i}")
            } else {
                format!("n{i}")
            }
        };
        let mut rows: Vec<(String, Option<String>)> = Vec::new();
        for i in 0..nodes {
            let roll = next(&mut state) % 10;
            if roll == 0 {
                continue; // no row
            }
            let parent = if roll == 1 {
                "*".to_string()
            } else {
                let to = match next(&mut state) % 4 {
                    0 => usize::try_from(next(&mut state) % 50).unwrap_or(0),
                    _ => (i + 1) % (nodes + usize::from(round % 3 == 0)),
                };
                name(to)
            };
            rows.push((name(i), Some(parent)));
        }
        {
            let tx = conn.transaction().expect("tx");
            tx.execute("DELETE FROM namespace_meta", []).expect("clear");
            for (ns, parent) in &rows {
                tx.execute(
                    "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace) \
                     VALUES (?1, 'ghost', '2026-10-03T00:00:00Z', ?2)",
                    rusqlite::params![ns, parent],
                )
                .expect("plant link");
            }
            tx.commit().expect("commit");
        }
        let full = all_links(&conn);
        for _ in 0..4 {
            let bound = name(usize::try_from(next(&mut state) % 50).unwrap_or(0));
            let new_parent = match next(&mut state) % 5 {
                0 => None,
                1 => Some("*".to_string()),
                _ => Some(name(usize::try_from(next(&mut state) % 50).unwrap_or(0))),
            };
            let sub =
                load_bind_link_subgraph(&conn, &bound, new_parent.as_deref()).expect("subgraph");
            let want = bind_exceeds_chain_depth(&full, &bound, new_parent.as_deref());
            let got = bind_exceeds_chain_depth(&sub, &bound, new_parent.as_deref());
            assert_eq!(
                got, want,
                "round {round}: bind {bound} -> {new_parent:?} verdict diverged on {rows:?}"
            );
            refusals_seen += usize::from(want);
        }
    }
    assert!(
        refusals_seen > 10,
        "the generator must produce refused binds ({refusals_seen})"
    );
}
