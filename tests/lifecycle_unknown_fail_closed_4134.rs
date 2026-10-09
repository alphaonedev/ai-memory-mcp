// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4134 — an UNKNOWN or NON-TEXT `lifecycle_state` must decode FAIL-CLOSED
//! (GOD ruling, 5-agent vote 4d3ea1c5, option (a)).
//!
//! The SQL allow-list (`lifecycle_visible_clause`) already hides an
//! unrecognised value in every scan; the Rust row mapper was the one
//! fail-OPEN exception — `LifecycleState::from_str(..).unwrap_or_default()`
//! read garbage as `Open` — and it is reached by get-by-id and the Rust
//! post-filters, so a quarantined or tombstoned row whose column was
//! corrupted or tampered became VISIBLE through `get`. Hiding a row is a
//! reversible degrade; showing a quarantined row is a wrong result.
//!
//! Binding requirements pinned here (sqlite half):
//! 1. TEXT garbage and an INTEGER value on quarantined / tombstoned rows are
//!    NOT visible via `get`, `list` or keyword recall; a fresh `open` row on
//!    the same store stays visible (control).
//! 2. An in-place update does not rewrite the raw value (never laundered
//!    into `'open'`), and the in-place transition path refuses it.
//! 3. The operator repair path: `operator_dequarantine` releases a row
//!    holding an unrecognised value (otherwise it would stay hidden for good,
//!    since the release matched only the literal `'quarantined'`).

use ai_memory::db;
use ai_memory::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};

mod common;
use common::fresh_db_tempfile_conn as fresh_db;

const NS: &str = "lifecycle-unknown-4134";
const OWNER: &str = "ai:alice-4134";

fn row(title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: title.to_string(),
        content: format!("{title} body with the term corruptible"),
        priority: 5,
        confidence: 1.0,
        source: "api".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": OWNER }),
        memory_kind: MemoryKind::Observation,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    }
}

/// Write a RAW column value (TEXT or INTEGER), bypassing every typed path —
/// the corruption / tamper the ruling is about.
fn set_raw_lifecycle(conn: &rusqlite::Connection, id: &str, value: &dyn rusqlite::ToSql) {
    conn.execute(
        "UPDATE memories SET lifecycle_state = ?1 WHERE id = ?2",
        rusqlite::params![value, id],
    )
    .expect("raw lifecycle write");
}

fn raw_lifecycle(conn: &rusqlite::Connection, id: &str) -> rusqlite::types::Value {
    conn.query_row(
        "SELECT lifecycle_state FROM memories WHERE id = ?1",
        [id],
        |r| r.get::<_, rusqlite::types::Value>(0),
    )
    .expect("raw lifecycle read")
}

fn listed_ids(conn: &rusqlite::Connection) -> Vec<String> {
    db::list(
        conn,
        Some(NS),
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
    .collect()
}

fn recalled_ids(conn: &rusqlite::Connection) -> Vec<String> {
    let (rows, _) = db::recall(
        conn,
        "corruptible",
        Some(NS),
        50,
        None,
        None,
        None,
        ai_memory::SECS_PER_HOUR,
        ai_memory::SECS_PER_DAY,
        None,
        None,
        false,
        None,
        None,
        None,
    )
    .expect("keyword recall");
    rows.into_iter().map(|(m, _)| m.id).collect()
}

/// TEXT garbage on a quarantined row, an INTEGER on a tombstoned row: both
/// hidden from get / list / recall; the open control stays visible.
#[test]
fn unknown_or_non_text_lifecycle_is_hidden_on_every_read_4134() {
    let (_tmp, conn) = fresh_db();
    let garbage = db::insert(&conn, &row("garbage-text-4134")).expect("insert");
    let integer = db::insert(&conn, &row("integer-4134")).expect("insert");
    let control = db::insert(&conn, &row("control-open-4134")).expect("insert");
    set_raw_lifecycle(&conn, &garbage, &LifecycleState::Quarantined.as_str());
    set_raw_lifecycle(&conn, &integer, &LifecycleState::Tombstoned.as_str());
    // The corruption: a value no binary recognises, and a non-text value.
    set_raw_lifecycle(&conn, &garbage, &"qu4rant1ned??");
    set_raw_lifecycle(&conn, &integer, &7_i64);

    for (id, what) in [(&garbage, "TEXT garbage"), (&integer, "INTEGER")] {
        assert!(
            db::get(&conn, id).expect("get").is_none(),
            "#4134: a row whose lifecycle_state is {what} must not be visible via get"
        );
        assert!(
            !listed_ids(&conn).contains(id),
            "#4134: {what} row must not be listed"
        );
        assert!(
            !recalled_ids(&conn).contains(id),
            "#4134: {what} row must not be recalled"
        );
    }
    assert!(
        db::get(&conn, &control).expect("get").is_some(),
        "control: an open row on the same store stays visible"
    );
    assert!(listed_ids(&conn).contains(&control));
    assert!(recalled_ids(&conn).contains(&control));
}

/// An update does not rewrite (launder) the raw value, and the transition
/// path refuses to move a row whose current state is unrecognised.
#[test]
fn update_preserves_the_raw_unknown_value_4134() {
    let (_tmp, conn) = fresh_db();
    let id = db::insert(&conn, &row("preserve-raw-4134")).expect("insert");
    set_raw_lifecycle(&conn, &id, &"qu4rant1ned??");

    // An in-place content patch (the HTTP PUT / MCP update primitive).
    let _ = db::update_with_expected_version(
        &conn,
        &id,
        None,
        Some("patched body"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert_eq!(
        raw_lifecycle(&conn, &id),
        rusqlite::types::Value::Text("qu4rant1ned??".to_string()),
        "#4134: an update must never persist a substituted state over the raw value"
    );

    // The caller transition path cannot "repair" it into a known state.
    assert!(
        db::set_lifecycle_state(&conn, &id, LifecycleState::Active).is_err(),
        "#4134: an unrecognised current state has no legal outbound transition"
    );
    assert_eq!(
        raw_lifecycle(&conn, &id),
        rusqlite::types::Value::Text("qu4rant1ned??".to_string()),
        "the refused transition leaves the raw value untouched"
    );
}

/// The operator repair path: a row holding a corrupt value is released by
/// `operator_dequarantine` (audited), after which it is visible again.
#[test]
fn operator_release_repairs_an_unknown_lifecycle_4134() {
    let (_tmp, mut conn) = fresh_db();
    let id = db::insert(&conn, &row("operator-repair-4134")).expect("insert");
    set_raw_lifecycle(&conn, &id, &7_i64);
    assert!(
        db::get(&conn, &id).expect("get").is_none(),
        "hidden before repair"
    );

    let released = db::operator_dequarantine(&mut conn, &id, "operator:4134").expect("release");
    assert!(
        released,
        "#4134: the operator release must repair a row holding an unrecognised value \
         (pre-fix it matched only the literal 'quarantined' and left the row hidden for good)"
    );
    let row = db::get(&conn, &id)
        .expect("get")
        .expect("visible after repair");
    assert_eq!(row.lifecycle_state, LifecycleState::Open);
}
