// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9259 and #9260 - two defects of the `_agents` public-key projection,
//! fixed with the #8341 v102 guard.
//!
//! * #9259: a same-key rebind appends no history version (idempotent by
//!   contract) but wrote `pubkey_bound_at = now` into the registration row,
//!   moving the validity boundary the ledger keeps.
//! * #9260: a bound registration row whose content is not a JSON object
//!   cannot hold the content mirror. It must fail closed with one exact,
//!   actionable error, and `register_agent` must repair it.
//!
//! Both tests use only APIs that exist on the base, so they run red there.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use ai_memory::models::{AGENTS_NAMESPACE, agent_registration_title};

const INTEGRITY_CHECK: &str =
    "INSERT INTO memories_fts(memories_fts, rank) VALUES('integrity-check', 1)";
/// The exact #9260 refusal (v102 guard, `storage::agent_projection`).
const NON_OBJECT_MESSAGE_9260: &str = "agent_projection_guard: bound _agents registration content is not a JSON object; re-register the agent (register_agent) to rebuild it";
/// Every trigger name either side of v102 that guards or rewrites the row.
const PROJECTION_TRIGGERS: [&str; 4] = [
    "agent_pubkey_history_authoritative_insert_v97",
    "agent_pubkey_history_authoritative_update_v97",
    "agent_pubkey_history_projection_guard_insert",
    "agent_pubkey_history_projection_guard_update",
];
/// Bound registration rows the #9260 fixture leaves with non-object content.
const NON_OBJECT_ROWS_9260: i64 = 1;
/// SQL counting bound registration rows whose content is not a JSON object.
const COUNT_NON_OBJECT_SQL: &str = "SELECT COUNT(*) FROM memories m
     WHERE m.namespace = '_agents' AND m.encrypted_envelope IS NULL
       AND EXISTS (SELECT 1 FROM agent_pubkey_history h
                    WHERE h.agent_id = substr(m.title, length('agent:') + 1)
                      AND h.superseded_at IS NULL)
       AND json_type(CASE WHEN json_valid(m.content) THEN m.content ELSE 'null' END)
           IS NOT 'object'";

fn open(path: &std::path::Path) -> rusqlite::Connection {
    ai_memory::db::open(path).expect("db::open")
}

fn bound_agent(
    conn: &rusqlite::Connection,
    agent: &str,
) -> ai_memory::identity::keypair::AgentKeypair {
    ai_memory::db::register_agent(conn, agent, "test", &[]).expect("register");
    let kp = ai_memory::identity::keypair::generate(agent).expect("keypair");
    ai_memory::db::bind_agent_pubkey_with_keypair(conn, agent, &kp).expect("bind");
    kp
}

/// (key, bound_at) of the open history row.
fn ledger(conn: &rusqlite::Connection, agent: &str) -> (String, String) {
    conn.query_row(
        "SELECT pubkey_b64, bound_at FROM agent_pubkey_history
          WHERE agent_id = ?1 AND superseded_at IS NULL",
        [agent],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("open history row")
}

/// (metadata key, metadata bound_at, content key, content bound_at).
fn projection(conn: &rusqlite::Connection, agent: &str) -> [Option<String>; 4] {
    conn.query_row(
        "SELECT json_extract(metadata, '$.agent_pubkey'), json_extract(metadata, '$.pubkey_bound_at'),
                json_extract(content, '$.agent_pubkey'), json_extract(content, '$.pubkey_bound_at')
           FROM memories WHERE namespace = ?1 AND title = ?2",
        rusqlite::params![AGENTS_NAMESPACE, agent_registration_title(agent)],
        |r| Ok([r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?]),
    )
    .expect("registration row")
}

fn sqlite_message(err: &anyhow::Error) -> Option<String> {
    err.chain()
        .find_map(|cause| match cause.downcast_ref::<rusqlite::Error>() {
            Some(rusqlite::Error::SqliteFailure(_, Some(message))) => Some(message.clone()),
            _ => None,
        })
}

/// #9259 - a same-key rebind keeps the ledger's `bound_at` in the row (both
/// mirrors), appends no version, and leaves the FTS index in step.
#[test]
fn same_key_rebind_keeps_ledger_bound_at_9259() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = open(f.path());
    let agent = "ai:same-key-rebind-9259";
    let kp = bound_agent(&conn, agent);
    let (key, bound_at) = ledger(&conn, agent);
    std::thread::sleep(std::time::Duration::from_millis(5));
    ai_memory::db::bind_agent_pubkey_with_keypair(&conn, agent, &kp).expect("same-key rebind");
    let versions: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_pubkey_history WHERE agent_id = ?1",
            [agent],
            |r| r.get(0),
        )
        .expect("versions");
    assert_eq!(versions, 1, "a same-key rebind appends no version");
    assert_eq!(ledger(&conn, agent), (key.clone(), bound_at.clone()));
    assert_eq!(
        projection(&conn, agent),
        [
            Some(key.clone()),
            Some(bound_at.clone()),
            Some(key),
            Some(bound_at)
        ],
        "the registration row must carry the ledger bound_at, not the rebind time"
    );
    conn.execute_batch(INTEGRITY_CHECK)
        .expect("memories_fts in step after a same-key rebind");
}

/// #9260 - a bound registration row with non-object content survives the
/// upgrade unchanged (counted), refuses the next write with the exact error,
/// and `register_agent` rebuilds it.
#[test]
fn non_object_registration_fails_closed_and_register_repairs_9260() {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let agent = "ai:non-object-9260";
    let title = agent_registration_title(agent);
    {
        let conn = open(f.path());
        bound_agent(&conn, agent);
        for trigger in PROJECTION_TRIGGERS {
            conn.execute_batch(&format!("DROP TRIGGER IF EXISTS {trigger};"))
                .expect("model a hand-edited registration row");
        }
        conn.execute(
            "UPDATE memories SET content = 'registration text, not JSON'
              WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![AGENTS_NAMESPACE, &title],
        )
        .expect("plant non-object content");
        let current: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .expect("schema version");
        conn.execute_batch(&format!(
            "DELETE FROM schema_version; INSERT INTO schema_version(version) VALUES ({});",
            current - 1
        ))
        .expect("rewind one ladder step");
    }
    let conn = open(f.path());
    let count: i64 = conn
        .query_row(COUNT_NON_OBJECT_SQL, [], |r| r.get(0))
        .expect("count");
    assert_eq!(
        count, NON_OBJECT_ROWS_9260,
        "the upgrade leaves the row as it was"
    );
    let id: String = conn
        .query_row(
            "SELECT id FROM memories WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![AGENTS_NAMESPACE, &title],
            |r| r.get(0),
        )
        .expect("id");
    let err = ai_memory::db::update(
        &conn,
        &id,
        None,
        None,
        None,
        None,
        None,
        Some(7),
        None,
        None,
        None,
    )
    .expect_err("a write to a bound non-object registration row fails closed");
    assert_eq!(
        sqlite_message(&err).as_deref(),
        Some(NON_OBJECT_MESSAGE_9260),
        "exact refusal, got {err:#}"
    );
    ai_memory::db::register_agent(&conn, agent, "test", &[]).expect("register repairs");
    let (key, bound_at) = ledger(&conn, agent);
    assert_eq!(
        projection(&conn, agent),
        [
            Some(key.clone()),
            Some(bound_at.clone()),
            Some(key),
            Some(bound_at)
        ]
    );
    let after: i64 = conn
        .query_row(COUNT_NON_OBJECT_SQL, [], |r| r.get(0))
        .expect("count");
    assert_eq!(after, 0);
    let attest: Option<String> = conn
        .query_row(
            "SELECT json_extract(content, '$.attest_level') FROM memories
              WHERE namespace = ?1 AND title = ?2",
            rusqlite::params![AGENTS_NAMESPACE, &title],
            |r| r.get(0),
        )
        .expect("attest");
    assert_eq!(attest.as_deref(), Some("claimed"));
    conn.execute_batch(INTEGRITY_CHECK)
        .expect("memories_fts in step");
}
