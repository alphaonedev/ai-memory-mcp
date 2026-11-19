// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9405 / #9406 - the v102 `_agents` projection guard, round 2.
//!
//! INV-1 (#9405): every SQLite write funnel reads the `_agents` projection
//! INSIDE the write transaction that writes the row. A second connection that
//! commits a ledger change (revoke) between the projection read and the row
//! write must not make the funnel write a stale projection. The race is driven
//! deterministically: a `sqlite3_trace` hook on the funnel's connection sees
//! the projection query (`... AS row_in`) and, on the very next statement the
//! funnel runs, hands `go` over a channel to a second thread, which commits
//! the ledger change on its own connection and answers back (the handshake
//! is the ordering; no sleeps).
//! Outside a transaction the second connection commits and the guard aborts
//! the funnel with the exact mismatch text (red at c7e15b31); inside one the
//! second connection gets SQLITE_BUSY and the funnel commits the projection.
//!
//! INV-2 (#9406): the update guard's `UPDATE OF` list names every column its
//! WHEN clause and body read, `encrypted_envelope` included. An
//! envelope-only UPDATE that unseals a bound row is re-checked and aborted, and
//! the column list is pinned to the `NEW.` columns of the installed trigger.
//!
//! Every cell runs with `recursive_triggers` OFF and ON.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use ai_memory::models::{AGENTS_NAMESPACE, Memory, agent_registration_title};
use std::cell::RefCell;
use std::collections::BTreeSet;

const INTEGRITY_CHECK: &str =
    "INSERT INTO memories_fts(memories_fts, rank) VALUES('integrity-check', 1)";
/// The exact guard refusal for a write without the authoritative projection.
const MISMATCH_MESSAGE: &str = "agent_projection_guard: _agents write does not carry the authoritative agent_pubkey_history projection (metadata and content agent_pubkey/pubkey_bound_at must equal the open history row)";
/// The exact guard refusal for a bound row whose content is not an object.
const NON_OBJECT_MESSAGE: &str = "agent_projection_guard: bound _agents registration content is not a JSON object; re-register the agent (register_agent) to rebuild it";
/// SQLite's message for SQLITE_BUSY with no busy timeout.
const BUSY_MESSAGE: &str = "database is locked";
const GUARD_UPDATE_TRIGGER: &str = "agent_pubkey_history_projection_guard_update";
const GUARD_INSERT_TRIGGER: &str = "agent_pubkey_history_projection_guard_insert";
/// The text only the projection query carries (`agent_projection::projected`).
const PROJECTION_MARK: &str = "AS row_in";
/// Legacy `sqlite3_trace` marks the start of every trigger program with this.
const TRIGGER_MARK: &str = "-- TRIGGER ";
/// The ledger half of `revoke_agent_pubkey` (mod.rs revoke_agent_pubkey_no_tx).
const CLOSE_LEDGER_SQL: &str = "UPDATE agent_pubkey_history SET superseded_at = ?2
      WHERE agent_id = ?1 AND superseded_at IS NULL";
const REVOKED_AT: &str = "2026-11-16T00:00:00+00:00";
const FORGED_KEY: &str = "Zm9yZ2VkLWtleS1ub3QtaW4tdGhlLWxlZGdlci05NDA1";
const FORGED_BOUND_AT: &str = "2001-01-01T00:00:00+00:00";
const FUTURE_STAMP: &str = "2999-01-01T00:00:00+00:00";
/// The columns the projection reads from the row it writes
/// (`agent_projection::PROJECTION_SQL` binds exactly these).
const PROJECTION_INPUTS: [&str; 4] = ["content", "metadata", "namespace", "title"];
/// The columns the v102 update guard must list (WHEN clause and body).
const GUARD_COLUMNS: [&str; 5] = [
    "content",
    "encrypted_envelope",
    "metadata",
    "namespace",
    "title",
];

// ---------------------------------------------------------------- helpers

fn open(path: &std::path::Path, recursive_triggers: bool) -> rusqlite::Connection {
    let conn = ai_memory::db::open(path).expect("db::open");
    let pragma = if recursive_triggers {
        "PRAGMA recursive_triggers=ON"
    } else {
        "PRAGMA recursive_triggers=OFF"
    };
    conn.execute_batch(pragma).expect("recursive_triggers");
    conn
}

fn bind(conn: &rusqlite::Connection, agent: &str) {
    ai_memory::db::register_agent(conn, agent, "test", &[]).expect("register");
    let kp = ai_memory::identity::keypair::generate(agent).expect("keypair");
    ai_memory::db::bind_agent_pubkey_with_keypair(conn, agent, &kp).expect("bind");
}

fn registration(conn: &rusqlite::Connection, agent: &str) -> Memory {
    let id: String = conn
        .query_row(
            "SELECT id FROM memories WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![AGENTS_NAMESPACE, agent_registration_title(agent)],
            |r| r.get(0),
        )
        .expect("registration id");
    ai_memory::db::get(conn, &id)
        .expect("get")
        .expect("registration row")
}

/// The registration row with a forged key in both mirrors and a newer stamp,
/// so the funnel must project (the projection query runs and differs).
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

fn open_history_rows(conn: &rusqlite::Connection, agent: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM agent_pubkey_history WHERE agent_id = ?1 AND superseded_at IS NULL",
        [agent],
        |r| r.get(0),
    )
    .expect("open history rows")
}

/// The registration row equals the open ledger row and the index is in step.
fn assert_projected_and_in_step(conn: &rusqlite::Connection, agent: &str) {
    let (key, bound_at): (String, String) = conn
        .query_row(
            "SELECT pubkey_b64, bound_at FROM agent_pubkey_history
              WHERE agent_id = ?1 AND superseded_at IS NULL",
            [agent],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("open history row");
    let row: [Option<String>; 4] = conn
        .query_row(
            "SELECT json_extract(metadata, '$.agent_pubkey'), json_extract(metadata, '$.pubkey_bound_at'),
                    json_extract(content, '$.agent_pubkey'), json_extract(content, '$.pubkey_bound_at')
               FROM memories WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![AGENTS_NAMESPACE, agent_registration_title(agent)],
            |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?]),
        )
        .expect("registration row");
    assert_eq!(
        row,
        [
            Some(key.clone()),
            Some(bound_at.clone()),
            Some(key),
            Some(bound_at)
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

// ------------------------------------------------- the deterministic race

/// The ledger change the second connection commits inside the window.
#[derive(Clone, Copy)]
enum Racer {
    /// `db::revoke_agent_pubkey` (ledger close plus row strip, one txn).
    Revoke,
    /// The ledger half of the revoke alone (the row is absent, so the full
    /// revoke would refuse with "not registered").
    CloseLedger,
}

/// The racer's answer: `Ok` it committed, `Err(message)` it was refused.
type Outcome = Result<(), String>;

/// Upper bound on the handshake. The racer runs with busy_timeout 0, so it
/// answers at once; the bound only stops a broken build from hanging.
const HANDSHAKE_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// The funnel thread's half of the handshake, read by the trace sink.
struct Race {
    go: std::sync::mpsc::Sender<()>,
    answer: std::sync::mpsc::Receiver<Outcome>,
    projection_seen: bool,
    outcome: Option<Outcome>,
}

thread_local! {
    static RACE: RefCell<Option<Race>> = const { RefCell::new(None) };
}

fn run_racer(conn: &rusqlite::Connection, agent: &str, racer: Racer) -> Outcome {
    match racer {
        Racer::Revoke => ai_memory::db::revoke_agent_pubkey(conn, agent)
            .map_err(|e| chain_message(&e).unwrap_or_else(|| format!("{e:#}"))),
        Racer::CloseLedger => conn
            .execute(CLOSE_LEDGER_SQL, rusqlite::params![agent, REVOKED_AT])
            .map(|_| ())
            .map_err(|e| raw_message(&e).map_or_else(|| e.to_string(), str::to_string)),
    }
}

/// Trace sink on the funnel's connection. Never panics (it runs under FFI).
/// After the projection query, the next statement the funnel starts hands
/// `go` to the racer thread and waits for its answer before returning, so
/// the racer's commit attempt lands exactly between the projection read and
/// the row write.
fn race_sink(sql: &str) {
    if sql.starts_with(TRIGGER_MARK) {
        return;
    }
    RACE.with(|cell| {
        let Ok(mut slot) = cell.try_borrow_mut() else {
            return;
        };
        let Some(race) = slot.as_mut() else {
            return;
        };
        if race.outcome.is_some() {
            return;
        }
        if sql.contains(PROJECTION_MARK) {
            race.projection_seen = true;
            return;
        }
        if race.projection_seen {
            let answer = race
                .go
                .send(())
                .map_err(|e| format!("racer gone: {e}"))
                .and_then(|()| {
                    race.answer
                        .recv_timeout(HANDSHAKE_BOUND)
                        .map_err(|e| format!("racer silent: {e}"))
                        .and_then(|outcome| outcome)
                });
            race.outcome = Some(answer);
        }
    });
}

/// Run `funnel` on `conn` while a second thread, on its own connection to
/// the same file, waits for the handshake and then commits `racer`. Returns
/// the funnel result and the racer's outcome.
fn race_funnel<T>(
    conn: &mut rusqlite::Connection,
    path: &std::path::Path,
    recursive: bool,
    agent: &str,
    racer: Racer,
    funnel: impl FnOnce(&rusqlite::Connection) -> anyhow::Result<T>,
) -> (anyhow::Result<T>, Option<Outcome>) {
    let racer_conn = open(path, recursive);
    racer_conn
        .busy_timeout(std::time::Duration::ZERO)
        .expect("busy_timeout 0");
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (answer_tx, answer_rx) = std::sync::mpsc::channel::<Outcome>();
    let racer_agent = agent.to_string();
    let racer_thread = std::thread::spawn(move || {
        // A dropped `go` (the funnel never reached its row write) ends the
        // thread without running the racer.
        if go_rx.recv().is_ok() {
            let outcome = run_racer(&racer_conn, &racer_agent, racer);
            let _ = answer_tx.send(outcome);
        }
    });
    RACE.with(|cell| {
        *cell.borrow_mut() = Some(Race {
            go: go_tx,
            answer: answer_rx,
            projection_seen: false,
            outcome: None,
        });
    });
    conn.trace(Some(race_sink));
    let result = funnel(conn);
    conn.trace(None);
    let race = RACE
        .with(|cell| cell.borrow_mut().take())
        .expect("race state");
    let Race {
        go,
        projection_seen,
        outcome,
        ..
    } = race;
    drop(go);
    racer_thread.join().expect("racer thread");
    assert!(projection_seen, "the funnel must run the projection query");
    (result, outcome)
}

/// The outcome both cells require on the fixed code: the racer was refused
/// with SQLITE_BUSY (the funnel held the write lock from the projection read
/// to its row write), the funnel committed the projection, and the racer's
/// change applies cleanly afterwards.
fn assert_one_transaction<T: std::fmt::Debug>(
    site: &str,
    recursive: bool,
    result: anyhow::Result<T>,
    outcome: Option<Result<(), String>>,
) {
    let result = result.map_err(|e| chain_message(&e).unwrap_or_else(|| format!("{e:#}")));
    assert_eq!(
        (result.map(|_| ()), outcome),
        (Ok(()), Some(Err(BUSY_MESSAGE.to_string()))),
        "{site} recursive={recursive}: the projection read and the row write must be one write transaction (#9405)"
    );
}

#[test]
fn update_projects_inside_its_write_transaction_9405() {
    for recursive in [false, true] {
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        let mut conn = open(f.path(), recursive);
        let agent = "ai:update-race-9405";
        bind(&conn, agent);
        let hostile = forged(&conn, agent);
        let (result, outcome) =
            race_funnel(&mut conn, f.path(), recursive, agent, Racer::Revoke, |c| {
                ai_memory::db::update(
                    c,
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
            });
        if let Err(e) = &result {
            // Red at c7e15b31: the racer committed in the window and the
            // guard aborts the stale projection with the exact text.
            assert_eq!(
                (chain_message(e).as_deref(), outcome.clone()),
                (Some(MISMATCH_MESSAGE), Some(Ok(()))),
                "update recursive={recursive}: only the guard's mismatch may abort"
            );
        }
        assert_one_transaction("update", recursive, result, outcome);
        assert_projected_and_in_step(&conn, agent);
        ai_memory::db::revoke_agent_pubkey(&conn, agent).expect("revoke after the update");
        assert_eq!(open_history_rows(&conn, agent), 0);
        conn.execute_batch(INTEGRITY_CHECK)
            .expect("memories_fts in step after the revoke");
    }
}

#[test]
fn insert_with_conflict_error_projects_inside_its_write_transaction_9405() {
    for recursive in [false, true] {
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        let mut conn = open(f.path(), recursive);
        let agent = "ai:insert-conflict-race-9405";
        bind(&conn, agent);
        let hostile = forged(&conn, agent);
        assert!(ai_memory::db::delete(&conn, &hostile.id).expect("delete"));
        let (result, outcome) = race_funnel(
            &mut conn,
            f.path(),
            recursive,
            agent,
            Racer::CloseLedger,
            |c| {
                ai_memory::db::insert_with_conflict(
                    c,
                    &hostile,
                    ai_memory::storage::ConflictMode::Error,
                )
            },
        );
        if let Err(e) = &result {
            assert_eq!(
                (chain_message(e).as_deref(), outcome.clone()),
                (Some(MISMATCH_MESSAGE), Some(Ok(()))),
                "insert_with_conflict recursive={recursive}: only the guard's mismatch may abort"
            );
        }
        assert_one_transaction("insert_with_conflict(Error)", recursive, result, outcome);
        assert_projected_and_in_step(&conn, agent);
        conn.execute(CLOSE_LEDGER_SQL, rusqlite::params![agent, REVOKED_AT])
            .expect("the ledger close applies after the insert");
        assert_eq!(open_history_rows(&conn, agent), 0);
    }
}

// ------------------------------------------- INV-2: the UPDATE OF column list

/// An envelope-only UPDATE that unseals a bound row (content '' with no
/// envelope) is re-checked by the guard and aborted with the exact text.
#[test]
fn envelope_only_unseal_is_rechecked_9406() {
    for recursive in [false, true] {
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = open(f.path(), recursive);
        let agent = "ai:envelope-9406";
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
                "UPDATE memories SET encrypted_envelope = NULL WHERE namespace = ?1 AND title = ?2",
                rusqlite::params![AGENTS_NAMESPACE, &title],
            )
            .expect_err("an envelope-only unseal of a bound row must be re-checked (#9406)");
        assert_eq!(
            raw_message(&err),
            Some(NON_OBJECT_MESSAGE),
            "recursive={recursive}"
        );
        let envelope: Option<Vec<u8>> = conn
            .query_row(
                "SELECT encrypted_envelope FROM memories WHERE namespace = ?1 AND title = ?2",
                rusqlite::params![AGENTS_NAMESPACE, &title],
                |r| r.get(0),
            )
            .expect("row");
        assert_eq!(
            envelope,
            Some(vec![0u8]),
            "the aborted unseal left the row sealed"
        );
        conn.execute_batch(INTEGRITY_CHECK)
            .expect("memories_fts in step");
    }
}

/// The installed guard's SQL, from `sqlite_master`.
fn trigger_sql(conn: &rusqlite::Connection, name: &str) -> String {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
        [name],
        |r| r.get(0),
    )
    .expect("guard trigger installed")
}

/// Every `NEW.<column>` the trigger reads (WHEN clause and body).
fn new_columns(sql: &str) -> BTreeSet<String> {
    const MARK: &str = "NEW.";
    let mut out = BTreeSet::new();
    let mut rest = sql;
    while let Some(at) = rest.find(MARK) {
        let tail = &rest[at + MARK.len()..];
        let ident: String = tail
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !ident.is_empty() {
            out.insert(ident);
        }
        rest = tail;
    }
    out
}

/// The `UPDATE OF a, b, ... ON` column list.
fn update_of_columns(sql: &str) -> BTreeSet<String> {
    const OF: &str = "UPDATE OF ";
    let start = sql.find(OF).expect("UPDATE OF list") + OF.len();
    let end = sql[start..].find(" ON ").expect("ON after UPDATE OF") + start;
    sql[start..end]
        .split(',')
        .map(|c| c.trim().to_string())
        .collect()
}

#[test]
fn update_guard_lists_every_column_it_reads_9406() {
    for recursive in [false, true] {
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        let conn = open(f.path(), recursive);
        let update_sql = trigger_sql(&conn, GUARD_UPDATE_TRIGGER);
        let listed = update_of_columns(&update_sql);
        let read = new_columns(&update_sql);
        let expected: BTreeSet<String> = GUARD_COLUMNS.iter().map(ToString::to_string).collect();
        assert_eq!(
            listed, read,
            "recursive={recursive}: UPDATE OF must name exactly the NEW. columns the guard reads"
        );
        assert_eq!(listed, expected, "recursive={recursive}");
        // The insert guard reads the same columns, so an update that changes
        // any of them is re-checked against the same predicate.
        assert_eq!(new_columns(&trigger_sql(&conn, GUARD_INSERT_TRIGGER)), read);
        let inputs: BTreeSet<String> = PROJECTION_INPUTS.iter().map(ToString::to_string).collect();
        assert!(
            listed.is_superset(&inputs),
            "every projection input column must re-fire the guard: listed {listed:?}, inputs {inputs:?}"
        );
    }
}

/// Self-test of the column scanners: a list missing a read column differs.
#[test]
fn column_scanners_flag_a_missing_column_9406() {
    let planted = "CREATE TRIGGER t AFTER UPDATE OF metadata, content ON memories \
                   WHEN NEW.metadata IS NOT NULL AND NEW.encrypted_envelope IS NULL \
                   BEGIN SELECT NEW.content; END";
    let listed = update_of_columns(planted);
    let read = new_columns(planted);
    assert_eq!(
        listed,
        ["content", "metadata"]
            .iter()
            .map(ToString::to_string)
            .collect()
    );
    assert_eq!(
        read,
        ["content", "encrypted_envelope", "metadata"]
            .iter()
            .map(ToString::to_string)
            .collect()
    );
    assert_ne!(listed, read);
}
