// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8341 - the v102 `_agents` projection guard and its class invariant.
//!
//! 1. No trigger on `memories` changes title, content or tags
//!    (`no_memories_trigger_rewrites_the_row_8341`, with the mutation proofs
//!    `trigger_checker_flags_the_v97_rewriters_8341` and
//!    `trigger_checker_flags_an_injected_rewriter_8341`).
//! 2. Every Rust write funnel writes the authoritative projection before its
//!    statement (one test per funnel below; the guard aborts a write that
//!    omits it, pinned by the raw-write tests with the exact message).
//! 3. `memories_fts` equals `memories` after every write path (every test
//!    ends with the FTS5 `integrity-check`).
//!
//! The ladder step is pinned on a drifted v101 fixture, on a clean database
//! (idempotent), at 100K bound rows under a time bound, and with federation
//! writes right after the upgrade.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use ai_memory::models::{AGENTS_NAMESPACE, Memory, agent_registration_title};
use std::time::{Duration, Instant};

const INTEGRITY_CHECK: &str =
    "INSERT INTO memories_fts(memories_fts, rank) VALUES('integrity-check', 1)";
/// SQLITE_CORRUPT_VTAB, the #8341 symptom.
const SQLITE_CORRUPT_VTAB: i32 = 267;
/// The exact guard refusal for a write without the projection.
const MISMATCH_MESSAGE_8341: &str = "agent_projection_guard: _agents write does not carry the authoritative agent_pubkey_history projection (metadata and content agent_pubkey/pubkey_bound_at must equal the open history row)";
const GUARD_TRIGGERS: [&str; 2] = [
    "agent_pubkey_history_projection_guard_insert",
    "agent_pubkey_history_projection_guard_update",
];
const V97_INSERT_TRIGGER: &str = "agent_pubkey_history_authoritative_insert_v97";
const V97_UPDATE_TRIGGER: &str = "agent_pubkey_history_authoritative_update_v97";
const V97_MIGRATION_SQL: &str =
    include_str!("../migrations/sqlite/0081_v97_agent_pubkey_history.sql");
/// The v102 ladder step this file pins (provisional number, see PR body).
const GUARD_LADDER_VERSION: i64 = 102;
/// 100K bound registration rows for the ladder time bound.
const MIGRATION_V102_BOUND_ROWS: i64 = 100_000;
/// Wall-clock ceiling for the ladder step at [`MIGRATION_V102_BOUND_ROWS`].
///
/// Measured on f2 with every row drifted: 55-67 s in the test profile (the
/// bundled SQLite is built at opt-level 0) and 13.0 s on a release-built
/// SQLite 3.53 (FTS rebuild 2.2 s, reconcile 9.2 s, rebuild 1.7 s). The
/// reconcile is the funnel's own projection text (one SSOT, pinned by
/// `migration_file_carries_the_templates_8341`); every ledger lookup in it is
/// an index search on `agent_pubkey_history` (its primary key covers
/// `agent_id`), so its cost is linear in drifted rows. A step that turned
/// superlinear (a per-row scan of `memories` or a per-row FTS rebuild) costs
/// at least 10^10 row visits at this size, hours; the ceiling separates that
/// from the linear cost with 2.7x headroom for a loaded runner.
const MIGRATION_V102_BOUND_MS: u64 = 180_000;
/// Rows of the drifted fixture whose projection disagrees with the ledger.
const DRIFTED_STALE_ROWS: i64 = 2;
/// The forged key a hostile writer tries to project.
const FORGED_KEY: &str = "Zm9yZ2VkLWtleS1ub3QtaW4tdGhlLWxlZGdlci04MzQx";
const FORGED_BOUND_AT: &str = "2001-01-01T00:00:00+00:00";
const FUTURE_STAMP: &str = "2999-01-01T00:00:00+00:00";
/// Count of bound registration rows that disagree with the open history row.
const COUNT_STALE_SQL: &str = "SELECT COUNT(*) FROM memories m
      JOIN agent_pubkey_history h
        ON h.agent_id = substr(m.title, length('agent:') + 1) AND h.superseded_at IS NULL
     WHERE m.namespace = '_agents' AND (
           json_extract(m.metadata, '$.agent_pubkey') IS NOT h.pubkey_b64
        OR json_extract(m.metadata, '$.pubkey_bound_at') IS NOT h.bound_at
        OR json_extract(m.content, '$.agent_pubkey') IS NOT h.pubkey_b64
        OR json_extract(m.content, '$.pubkey_bound_at') IS NOT h.bound_at)";

// ---------------------------------------------------------------- helpers

fn open(path: &std::path::Path) -> rusqlite::Connection {
    ai_memory::db::open(path).expect("db::open")
}

fn bind(conn: &rusqlite::Connection, agent: &str) {
    ai_memory::db::register_agent(conn, agent, "test", &[]).expect("register");
    let kp = ai_memory::identity::keypair::generate(agent).expect("keypair");
    ai_memory::db::bind_agent_pubkey_with_keypair(conn, agent, &kp).expect("bind");
}

fn registration_id(conn: &rusqlite::Connection, agent: &str) -> String {
    conn.query_row(
        "SELECT id FROM memories WHERE namespace = ?1 AND title = ?2",
        rusqlite::params![AGENTS_NAMESPACE, agent_registration_title(agent)],
        |r| r.get(0),
    )
    .expect("registration id")
}

fn registration(conn: &rusqlite::Connection, agent: &str) -> Memory {
    ai_memory::db::get(conn, &registration_id(conn, agent))
        .expect("get")
        .expect("registration row")
}

/// The registration row as a hostile peer or importer would send it: the
/// forged key in both mirrors, a newer stamp.
fn forged(conn: &rusqlite::Connection, agent: &str) -> Memory {
    let mut mem = registration(conn, agent);
    mem.metadata["agent_pubkey"] = serde_json::json!(FORGED_KEY);
    mem.metadata["pubkey_bound_at"] = serde_json::json!(FORGED_BOUND_AT);
    let mut content: serde_json::Value =
        serde_json::from_str(&mem.content).expect("registration content is JSON");
    content["agent_pubkey"] = serde_json::json!(FORGED_KEY);
    content["pubkey_bound_at"] = serde_json::json!(FORGED_BOUND_AT);
    mem.content = content.to_string();
    mem.updated_at = FUTURE_STAMP.to_string();
    mem
}

fn stale_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(COUNT_STALE_SQL, [], |r| r.get(0))
        .expect("stale count")
}

/// Invariant 2 and 3: the row equals the ledger and the index is in step.
fn assert_projected_and_in_step(conn: &rusqlite::Connection, agent: &str) {
    let (key, bound_at): (String, String) = conn
        .query_row(
            "SELECT pubkey_b64, bound_at FROM agent_pubkey_history
              WHERE agent_id = ?1 AND superseded_at IS NULL",
            [agent],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("open history row");
    let row: [Option<String>; 5] = conn
        .query_row(
            "SELECT json_extract(metadata, '$.agent_pubkey'), json_extract(metadata, '$.pubkey_bound_at'),
                    json_extract(content, '$.agent_pubkey'), json_extract(content, '$.pubkey_bound_at'),
                    json_extract(metadata, '$.attest_level')
               FROM memories WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![AGENTS_NAMESPACE, agent_registration_title(agent)],
            |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?]),
        )
        .expect("registration row");
    assert_eq!(
        row,
        [
            Some(key.clone()),
            Some(bound_at.clone()),
            Some(key),
            Some(bound_at),
            Some("claimed".to_string())
        ],
        "registration row must carry the ledger projection"
    );
    conn.execute_batch(INTEGRITY_CHECK)
        .expect("memories_fts in step with memories");
}

fn raw_message(err: &rusqlite::Error) -> Option<&str> {
    match err {
        rusqlite::Error::SqliteFailure(_, Some(message)) => Some(message.as_str()),
        _ => None,
    }
}

fn chain_message(err: &anyhow::Error) -> Option<String> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<rusqlite::Error>())
        .and_then(raw_message)
        .map(str::to_string)
}

fn fts_code(conn: &rusqlite::Connection) -> Option<i32> {
    match conn.execute_batch(INTEGRITY_CHECK) {
        Ok(()) => None,
        Err(rusqlite::Error::SqliteFailure(e, _)) => Some(e.extended_code),
        Err(other) => panic!("unexpected integrity-check error: {other}"),
    }
}

/// One `CREATE TRIGGER ... END;` statement of the v97 migration text.
fn v97_trigger_sql(name: &str) -> &'static str {
    let head = format!("CREATE TRIGGER IF NOT EXISTS {name}");
    let start = V97_MIGRATION_SQL.find(&head).expect("v97 trigger in 0081");
    let tail = &V97_MIGRATION_SQL[start..];
    let end = tail.find("END;").expect("v97 trigger END") + "END;".len();
    &tail[..end]
}

fn rewind_ladder(conn: &rusqlite::Connection) {
    conn.execute_batch(&format!(
        "DELETE FROM schema_version; INSERT INTO schema_version(version) VALUES ({});",
        GUARD_LADDER_VERSION - 1
    ))
    .expect("rewind to v101");
}

/// Model a v101 database: the v97 rewriters in place, the guards absent.
fn install_v101_triggers(conn: &rusqlite::Connection) {
    for trigger in GUARD_TRIGGERS {
        conn.execute_batch(&format!("DROP TRIGGER IF EXISTS {trigger};"))
            .expect("drop guard");
    }
    conn.execute_batch(v97_trigger_sql(V97_INSERT_TRIGGER))
        .expect("v97 insert trigger");
    conn.execute_batch(v97_trigger_sql(V97_UPDATE_TRIGGER))
        .expect("v97 update trigger");
}

/// Statements in a trigger body that write the `memories` table. Invariant 1:
/// a trigger ON memories may not contain one.
fn rewrites_memories(trigger_sql: &str) -> bool {
    let upper = trigger_sql.to_ascii_uppercase();
    let Some(begin) = upper.find("BEGIN") else {
        return false;
    };
    let body: String = upper[begin..]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    [
        "UPDATE MEMORIES ",
        "INTO MEMORIES ",
        "INTO MEMORIES(",
        "FROM MEMORIES ",
    ]
    .iter()
    .any(|needle| {
        body.match_indices(needle).any(|(at, _)| {
            // `DELETE FROM memories` writes; a `SELECT .. FROM memories` reads.
            needle != &"FROM MEMORIES " || body[..at].ends_with("DELETE ")
        })
    })
}

fn memories_triggers(conn: &rusqlite::Connection) -> Vec<(String, String)> {
    let mut stmt = conn
        .prepare(
            "SELECT name, sql FROM sqlite_master
              WHERE type = 'trigger' AND tbl_name = 'memories' ORDER BY name",
        )
        .expect("prepare");
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
}

// ------------------------------------------------- invariant 1: no rewriter

#[test]
fn no_memories_trigger_rewrites_the_row_8341() {
    let conn = open(std::path::Path::new(":memory:"));
    let triggers = memories_triggers(&conn);
    assert!(
        GUARD_TRIGGERS
            .iter()
            .all(|g| triggers.iter().any(|(name, _)| name == g)),
        "both v102 guards installed, got {triggers:?}"
    );
    let offenders: Vec<&str> = triggers
        .iter()
        .filter(|(_, sql)| rewrites_memories(sql))
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        offenders.is_empty(),
        "triggers on memories that write memories: {offenders:?}"
    );
}

/// Mutation proof: the checker flags both v97 rewriters verbatim.
#[test]
fn trigger_checker_flags_the_v97_rewriters_8341() {
    assert!(rewrites_memories(v97_trigger_sql(V97_INSERT_TRIGGER)));
    assert!(rewrites_memories(v97_trigger_sql(V97_UPDATE_TRIGGER)));
    for guard in GUARD_TRIGGERS {
        let conn = open(std::path::Path::new(":memory:"));
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = ?1",
                [guard],
                |r| r.get(0),
            )
            .expect("guard sql");
        assert!(!rewrites_memories(&sql), "{guard} must only RAISE");
    }
}

/// Mutation proof: a live injected rewriter makes the ratchet red.
#[test]
fn trigger_checker_flags_an_injected_rewriter_8341() {
    let conn = open(std::path::Path::new(":memory:"));
    conn.execute_batch(
        "CREATE TRIGGER injected_rewriter_8341 AFTER UPDATE ON memories BEGIN
             UPDATE   memories SET content = content || '' WHERE id = NEW.id;
         END;",
    )
    .expect("inject");
    let flagged: Vec<String> = memories_triggers(&conn)
        .into_iter()
        .filter(|(_, sql)| rewrites_memories(sql))
        .map(|(name, _)| name)
        .collect();
    assert_eq!(flagged, vec!["injected_rewriter_8341".to_string()]);
}

// ------------------------------------- the guard: exact refusal, sealed rows

#[test]
fn raw_update_without_projection_aborts_exact_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:raw-update-8341";
    bind(&conn, agent);
    for column in ["metadata", "content"] {
        let err = conn
            .execute(
                &format!(
                    "UPDATE memories SET {column} = json_set({column}, '$.agent_pubkey', ?1)
                      WHERE namespace = ?2 AND title = ?3"
                ),
                rusqlite::params![
                    FORGED_KEY,
                    AGENTS_NAMESPACE,
                    agent_registration_title(agent)
                ],
            )
            .expect_err("a raw write without the projection aborts");
        assert_eq!(raw_message(&err), Some(MISMATCH_MESSAGE_8341), "{column}");
    }
    assert_projected_and_in_step(&conn, agent);
}

#[test]
fn raw_insert_without_projection_aborts_exact_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:raw-insert-8341";
    bind(&conn, agent);
    let id = registration_id(&conn, agent);
    let cols = column_list(&conn, "memories").join(", ");
    conn.execute_batch(&format!(
        "CREATE TEMP TABLE held_8341 AS SELECT {cols} FROM memories WHERE id = '{id}';
         UPDATE held_8341 SET metadata = json_set(metadata, '$.pubkey_bound_at', '{FORGED_BOUND_AT}');
         DELETE FROM memories WHERE id = '{id}';"
    ))
    .expect("hold the row");
    // `pragma_table_info` omits generated columns, so the explicit column
    // list is what a plain INSERT can supply.
    let err = conn
        .execute_batch(&format!(
            "INSERT INTO memories ({cols}) SELECT {cols} FROM held_8341;"
        ))
        .expect_err("a raw insert without the projection aborts");
    assert_eq!(raw_message(&err), Some(MISMATCH_MESSAGE_8341));
    conn.execute_batch(&format!(
        "UPDATE held_8341 SET metadata = json_set(metadata, '$.pubkey_bound_at',
             (SELECT bound_at FROM agent_pubkey_history WHERE superseded_at IS NULL));
         INSERT INTO memories ({cols}) SELECT {cols} FROM held_8341;"
    ))
    .expect("the projected row inserts");
    assert_projected_and_in_step(&conn, agent);
}

/// A sealed row (content '' plus an envelope) passes on a matching metadata
/// pair and aborts on a mismatching one.
#[test]
fn sealed_row_passes_only_with_the_ledger_pair_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:sealed-8341";
    bind(&conn, agent);
    let title = agent_registration_title(agent);
    conn.execute(
        "UPDATE memories SET content = '', encrypted_envelope = X'00'
          WHERE namespace = ?1 AND title = ?2",
        rusqlite::params![AGENTS_NAMESPACE, &title],
    )
    .expect("a sealed row with the ledger pair passes");
    let err = conn
        .execute(
            "UPDATE memories SET metadata = json_set(metadata, '$.agent_pubkey', ?1)
              WHERE namespace = ?2 AND title = ?3",
            rusqlite::params![FORGED_KEY, AGENTS_NAMESPACE, &title],
        )
        .expect_err("a sealed row with a forged pair aborts");
    assert_eq!(raw_message(&err), Some(MISMATCH_MESSAGE_8341));
}

// ------------------------------------------------ invariant 2: every funnel

#[test]
fn register_refresh_projects_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:register-refresh-8341";
    bind(&conn, agent);
    ai_memory::db::register_agent(&conn, agent, "refreshed", &["recall".to_string()])
        .expect("re-register a bound agent");
    assert_projected_and_in_step(&conn, agent);
}

#[test]
fn update_with_forged_metadata_projects_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:update-8341";
    bind(&conn, agent);
    let hostile = forged(&conn, agent);
    ai_memory::db::update(
        &conn,
        &hostile.id,
        None,
        Some(&hostile.content),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&hostile.metadata),
    )
    .expect("update projects instead of failing");
    assert_projected_and_in_step(&conn, agent);
}

#[test]
fn insert_with_conflict_error_projects_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:insert-conflict-8341";
    bind(&conn, agent);
    let hostile = forged(&conn, agent);
    assert!(ai_memory::db::delete(&conn, &hostile.id).expect("delete"));
    ai_memory::db::insert_with_conflict(&conn, &hostile, ai_memory::storage::ConflictMode::Error)
        .expect("insert_with_conflict(Error) projects");
    assert_projected_and_in_step(&conn, agent);
}

#[test]
fn insert_if_newer_strips_and_projects_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:insert-if-newer-8341";
    bind(&conn, agent);
    ai_memory::db::insert_if_newer(&conn, &forged(&conn, agent))
        .expect("federation receive projects");
    assert_projected_and_in_step(&conn, agent);
}

#[test]
fn merge_inbound_strips_and_projects_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:merge-inbound-8341";
    bind(&conn, agent);
    ai_memory::db::merge_inbound(&conn, &forged(&conn, agent), false)
        .expect("federation merge projects");
    assert_projected_and_in_step(&conn, agent);
}

#[test]
fn restore_archived_projects_a_tampered_archive_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:restore-8341";
    bind(&conn, agent);
    let id = registration_id(&conn, agent);
    assert!(ai_memory::db::archive_memory(&conn, &id, Some("test")).expect("archive"));
    conn.execute(
        "UPDATE archived_memories
            SET metadata = json_set(metadata, '$.agent_pubkey', ?1),
                content  = json_set(content, '$.agent_pubkey', ?1)
          WHERE id = ?2",
        rusqlite::params![FORGED_KEY, &id],
    )
    .expect("tamper the archive");
    assert!(ai_memory::db::restore_archived(&conn, &id).expect("restore projects"));
    assert_projected_and_in_step(&conn, agent);
}

#[test]
fn same_key_rebind_and_revoke_keep_the_index_in_step_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:revoke-8341";
    bind(&conn, agent);
    ai_memory::db::revoke_agent_pubkey(&conn, agent).expect("revoke");
    let open_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_pubkey_history
              WHERE agent_id = ?1 AND superseded_at IS NULL",
            [agent],
            |r| r.get(0),
        )
        .expect("open rows");
    assert_eq!(open_rows, 0);
    ai_memory::db::register_agent(&conn, agent, "after-revoke", &[])
        .expect("an unbound registration writes freely");
    conn.execute_batch(INTEGRITY_CHECK)
        .expect("memories_fts in step after revoke");
}

#[test]
fn plain_memory_writes_are_untouched_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let mut mem = registration_free_memory();
    mem.metadata = serde_json::json!({"agent_pubkey": FORGED_KEY});
    let id = ai_memory::db::insert(&conn, &mem).expect("insert");
    let stored = ai_memory::db::get(&conn, &id).expect("get").expect("row");
    assert_eq!(
        stored.metadata["agent_pubkey"],
        serde_json::json!(FORGED_KEY)
    );
    conn.execute_batch(INTEGRITY_CHECK).expect("in step");
}

fn registration_free_memory() -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: "plain-8341".to_string(),
        title: "agent:not-a-registration".to_string(),
        content: "plain content".to_string(),
        source: "api".to_string(),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    }
}

// ------------------------------------------------------- the ladder step

/// A v101 database whose index is already corrupt (the #8341 symptom) and
/// whose rows disagree with the ledger is repaired by one reopen.
#[test]
fn ladder_repairs_a_drifted_v101_database_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let agents = ["ai:drift-a-8341", "ai:drift-b-8341", "ai:drift-c-8341"];
    {
        let conn = open(f.path());
        for agent in agents {
            bind(&conn, agent);
        }
        install_v101_triggers(&conn);
        // The v97 rewriter re-projects after the FTS sync: the index desyncs.
        conn.execute(
            "UPDATE memories SET content = json_set(content, '$.agent_pubkey', ?1)
              WHERE namespace = ?2 AND title = ?3",
            rusqlite::params![
                FORGED_KEY,
                AGENTS_NAMESPACE,
                agent_registration_title(agents[0])
            ],
        )
        .expect("v97 rewrite");
        assert_eq!(
            fts_code(&conn),
            Some(SQLITE_CORRUPT_VTAB),
            "fixture is drifted"
        );
        // Rows already out of step (written before v97, or by hand).
        for trigger in [V97_INSERT_TRIGGER, V97_UPDATE_TRIGGER] {
            conn.execute_batch(&format!("DROP TRIGGER {trigger};"))
                .expect("drop v97 for the stale rows");
        }
        for agent in &agents[1..] {
            conn.execute(
                "UPDATE memories SET metadata = json_set(metadata, '$.pubkey_bound_at', ?1)
                  WHERE namespace = ?2 AND title = ?3",
                rusqlite::params![
                    FORGED_BOUND_AT,
                    AGENTS_NAMESPACE,
                    agent_registration_title(agent)
                ],
            )
            .expect("stale row");
        }
        assert_eq!(stale_count(&conn), DRIFTED_STALE_ROWS);
        conn.execute_batch(v97_trigger_sql(V97_INSERT_TRIGGER))
            .expect("restore v97 insert");
        conn.execute_batch(v97_trigger_sql(V97_UPDATE_TRIGGER))
            .expect("restore v97 update");
        rewind_ladder(&conn);
    }
    let conn = open(f.path());
    assert_eq!(fts_code(&conn), None, "ladder rebuilt memories_fts");
    assert_eq!(stale_count(&conn), 0, "ladder reconciled every row");
    for agent in agents {
        assert_projected_and_in_step(&conn, agent);
    }
    let names: Vec<String> = memories_triggers(&conn)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert!(
        !names
            .iter()
            .any(|n| n == V97_INSERT_TRIGGER || n == V97_UPDATE_TRIGGER)
    );
    // Spec (e): federation writes right after the upgrade do not fail.
    ai_memory::db::insert_if_newer(&conn, &forged(&conn, agents[0])).expect("insert_if_newer");
    ai_memory::db::merge_inbound(&conn, &forged(&conn, agents[1]), true).expect("merge_inbound");
    for agent in agents {
        assert_projected_and_in_step(&conn, agent);
    }
}

type Snapshot = Vec<(String, String, String, String)>;

fn snapshot(conn: &rusqlite::Connection) -> Snapshot {
    let mut stmt = conn
        .prepare("SELECT id, title, content, metadata FROM memories ORDER BY id")
        .expect("prepare");
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
}

#[test]
fn ladder_is_idempotent_on_a_clean_database_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let before = {
        let conn = open(f.path());
        bind(&conn, "ai:clean-8341");
        let before = snapshot(&conn);
        rewind_ladder(&conn);
        before
    };
    for _ in 0..2 {
        let conn = open(f.path());
        assert_eq!(snapshot(&conn), before, "a clean database is unchanged");
        assert_projected_and_in_step(&conn, "ai:clean-8341");
        rewind_ladder(&conn);
    }
}

/// The ladder step on 100K stale bound rows stays under the named bound.
#[test]
fn ladder_reconciles_100k_bound_rows_under_the_bound_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let seed = "ai:bulk-seed-8341";
    {
        let conn = open(f.path());
        bind(&conn, seed);
        for trigger in GUARD_TRIGGERS {
            conn.execute_batch(&format!("DROP TRIGGER {trigger};"))
                .expect("drop guard for the bulk fixture");
        }
        let mem_cols = column_list(&conn, "memories");
        let hist_cols = column_list(&conn, "agent_pubkey_history");
        let mem_select = mem_cols
            .iter()
            .map(|c| match c.as_str() {
                "id" => "s.id || '-' || n.i".to_string(),
                "title" => "s.title || '-' || n.i".to_string(),
                "metadata" => {
                    format!("json_set(s.metadata, '$.pubkey_bound_at', '{FORGED_BOUND_AT}')")
                }
                other => format!("s.{other}"),
            })
            .collect::<Vec<_>>()
            .join(", ");
        let hist_select = hist_cols
            .iter()
            .map(|c| match c.as_str() {
                "agent_id" => "h.agent_id || '-' || n.i".to_string(),
                other => format!("h.{other}"),
            })
            .collect::<Vec<_>>()
            .join(", ");
        let tx = conn.unchecked_transaction().expect("tx");
        tx.execute_batch(&format!(
            "CREATE TEMP TABLE n_8341(i INTEGER PRIMARY KEY);
             WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < {MIGRATION_V102_BOUND_ROWS})
             INSERT INTO n_8341 SELECT i FROM c;
             INSERT INTO memories ({mc}) SELECT {mem_select} FROM memories s, n_8341 n
              WHERE s.namespace = '_agents' AND s.title = '{title}';
             INSERT INTO agent_pubkey_history ({hc}) SELECT {hist_select}
               FROM agent_pubkey_history h, n_8341 n WHERE h.agent_id = '{seed}';",
            mc = mem_cols.join(", "),
            hc = hist_cols.join(", "),
            title = agent_registration_title(seed),
        ))
        .expect("bulk fixture");
        tx.commit().expect("commit");
        assert_eq!(stale_count(&conn), MIGRATION_V102_BOUND_ROWS);
        rewind_ladder(&conn);
    }
    let started = Instant::now();
    let conn = open(f.path());
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_millis(MIGRATION_V102_BOUND_MS),
        "v102 ladder step took {elapsed:?} at {MIGRATION_V102_BOUND_ROWS} rows"
    );
    assert_eq!(stale_count(&conn), 0);
    conn.execute_batch(INTEGRITY_CHECK).expect("in step");
}

fn column_list(conn: &rusqlite::Connection, table: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
        .expect("prepare");
    stmt.query_map([], |r| r.get(0))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("rows")
}

/// A funnel error surfaces the exact message through `anyhow`.
#[test]
fn funnel_refusal_carries_the_exact_message_8341() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:funnel-refusal-8341";
    bind(&conn, agent);
    // A projection-less statement inside a funnel-shaped transaction.
    let err = conn
        .execute_batch(&format!(
            "UPDATE memories SET content = json_set(content, '$.pubkey_bound_at', '{FORGED_BOUND_AT}')
              WHERE namespace = '_agents' AND title = '{}';",
            agent_registration_title(agent)
        ))
        .map_err(anyhow::Error::new)
        .expect_err("aborts");
    assert_eq!(chain_message(&err).as_deref(), Some(MISMATCH_MESSAGE_8341));
}
