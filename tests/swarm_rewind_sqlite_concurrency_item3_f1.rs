// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! Boids item 3 f1-review F2/F3, SQLite parity (ruling `ITEM3-P1P4-f1`).
//! The sqlite `swarm_rewind` writes under `BEGIN IMMEDIATE`, but it read the
//! root (the already-rewound decision AND the metadata it later wrote back) in
//! autocommit BEFORE that lock — a PRE-EXISTING window since #3322 for any
//! second connection (MCP stdio, the HTTP daemon's SAL store, the CLI) on the
//! same file. RED on 362b505ab: two rewinds parked behind a held write lock
//! both append a `swarm.rewind` event, and a metadata key committed while the
//! rewind waited is overwritten by the stale root-marker copy.
//!
//! The interleaving: a holder connection takes `BEGIN IMMEDIATE`; the rewinds
//! (own connections, WAL readers) take their autocommit preview read and then
//! park in `busy_timeout` on their own `BEGIN IMMEDIATE`; the holder commits.
//! The settle sleep only matters for the RED direction — on the fixed code the
//! decision is taken under the lock whatever the timing.

use ai_memory::db;
use ai_memory::models::Memory;
use rusqlite::Connection;
use serde_json::json;

const DEPTH: usize = ai_memory::storage::LINEAGE_MAX_DEPTH;
const SETTLE: std::time::Duration = std::time::Duration::from_millis(1500);

fn db_path(tag: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "f1-sqlite-{tag}-{}.db",
        uuid::Uuid::new_v4().simple()
    ))
}

/// A root already contaminated WITHOUT the `rewind` marker (f1's fixture).
fn contaminated_root(path: &std::path::Path) -> String {
    let conn = db::open(path).expect("open");
    let now = chrono::Utc::now().to_rfc3339();
    let root = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "f1/sqlite-rewind".to_string(),
        title: format!("tainted root {}", uuid::Uuid::new_v4()),
        content: "already tainted".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({
            "agent_id": "ai:f1-victim",
            "contamination": {"prior_lifecycle_state": "open", "contaminated_from": "fixture"},
        }),
        ..Memory::default()
    };
    let id = db::insert(&conn, &root).expect("insert");
    conn.execute(
        "UPDATE memories SET lifecycle_state = 'contaminated' WHERE id = ?1",
        [&id],
    )
    .expect("initial taint");
    id
}

fn hold_write_lock(path: &std::path::Path) -> Connection {
    let holder = db::open(path).expect("holder");
    holder.execute_batch("BEGIN IMMEDIATE").expect("hold");
    holder
}

/// `conn` is opened BEFORE the holder takes the write lock (`db::open` runs
/// its own pragma/migration writes).
fn spawn_rewind(
    conn: Connection,
    root: &str,
    issuer: &str,
) -> std::thread::JoinHandle<ai_memory::storage::SwarmRewindReport> {
    let (root, issuer) = (root.to_string(), issuer.to_string());
    std::thread::spawn(move || {
        ai_memory::storage::swarm_rewind(&conn, &root, DEPTH, &issuer, "memory", &[], false)
            .expect("rewind succeeds")
    })
}

#[test]
fn sqlite_concurrent_rewinds_append_exactly_one_signed_event_f3() {
    let path = db_path("f3");
    let root = contaminated_root(&path);
    let issuer = format!("ai:f1-f3-{}", uuid::Uuid::new_v4().simple());
    let conns = [db::open(&path).expect("a"), db::open(&path).expect("b")];
    let holder = hold_write_lock(&path);
    let calls = conns.map(|c| spawn_rewind(c, &root, &issuer));
    std::thread::sleep(SETTLE);
    holder.execute_batch("COMMIT").expect("release");
    let already: usize = calls
        .into_iter()
        .map(|c| usize::from(c.join().expect("join").already_rewound))
        .sum();
    let conn = db::open(&path).expect("reopen");
    let events: i64 = conn
        .query_row(
            "SELECT count(*) FROM signed_events WHERE event_type = 'swarm.rewind' \
             AND agent_id = ?1",
            [&issuer],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(events, 1, "exactly ONE swarm.rewind event");
    assert_eq!(already, 1, "exactly one call reports already_rewound");
}

#[test]
fn sqlite_rewind_root_marker_preserves_concurrently_committed_metadata_f2() {
    let path = db_path("f2");
    let root = contaminated_root(&path);
    let conn = db::open(&path).expect("rewind conn");
    let holder = hold_write_lock(&path);
    let call = spawn_rewind(conn, &root, "ai:f1-f2-admin");
    std::thread::sleep(SETTLE);
    holder
        .execute(
            "UPDATE memories SET metadata = json_set(metadata, '$.concurrent_committed', \
             json('true')), version = version + 1 WHERE id = ?1",
            [&root],
        )
        .expect("concurrent writer");
    holder.execute_batch("COMMIT").expect("release");
    let report = call.join().expect("join");
    assert!(!report.already_rewound, "{report:?}");
    let conn = db::open(&path).expect("reopen");
    let meta: String = conn
        .query_row(
            "SELECT metadata FROM memories WHERE id = ?1",
            [&root],
            |r| r.get(0),
        )
        .expect("metadata");
    let meta: serde_json::Value = serde_json::from_str(&meta).expect("json");
    assert_eq!(
        meta.get("concurrent_committed"),
        Some(&json!(true)),
        "the concurrently committed key must survive the root marker: {meta}"
    );
    assert_eq!(meta["contamination"]["rewind"], json!(true), "{meta}");
}
