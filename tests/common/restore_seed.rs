// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #9944 / #10014 / #10015 — the SQLite corpus seed that gives every
//! table a restore-fidelity cell compares at least two rows, and every
//! compared column a value on some row.
//!
//! decision: schema-driven raw-SQL rows for the node-local tables over
//! per-table funnels because ~40 node-local tables have no CLI or library
//! writer reachable from a test, and BACKUP_RESTORE copies the store bytes
//! regardless of which writer put them there. The Portability v2 record
//! classes (tombstones, revisions, lineage, attestations, governance rules,
//! signed events) are written through the product funnels, because the
//! export and import paths read and validate them.
//!
//! Every generated value is written out by [`generated_value`] from the
//! table name, the column name and the row index; nothing is read back from
//! the code under test.
//!
//! Included with `#[path]` by the SQLite binary only.

#![allow(dead_code)]

use rusqlite::Connection;
use rusqlite::types::Value;

/// Rows written to every node-local table (`MIN_SOURCE_ROWS`).
pub const SEED_ROWS: usize = 2;

/// The node-local tables, parents before children (foreign keys are ON in
/// `db::open`). `embed_skip` is last: the `memories_embed_skip_clear_*`
/// triggers delete its rows when a memory's content or embedding changes.
pub const NODE_LOCAL_TABLES: &[&str] = &[
    "a2a_tasks",
    "a2a_task_memories",
    "actions",
    "action_edges",
    "agent_api_keys",
    "agent_pubkey_challenges",
    "agent_pubkey_history",
    "agent_quotas",
    "agent_subkey_certs",
    "attested_write_ledger",
    "audit_log",
    "checkpoints",
    "confidence_shadow_observations",
    "entity_aliases",
    "federation_nonce_cache",
    "federation_push_dlq",
    "leases",
    "lineage_integrity_watermark",
    "memory_transcripts",
    "memory_transcript_links",
    "offloaded_blobs",
    "pending_actions",
    "recall_observations",
    "routines",
    "routine_runs",
    "signals",
    "signed_events_dlq",
    "skills",
    "skill_resources",
    "subscriptions",
    "subscription_dlq",
    "subscription_events",
    "sync_peer_contact",
    "sync_state",
    "transcript_line_dedup",
    "token_cost_counters",
    "embed_skip",
];

/// Columns whose CHECK constraint or decoder needs a specific value; one
/// value per seeded row.
const OVERRIDES: &[(&str, &str, [&str; SEED_ROWS])] = &[
    (
        "agent_pubkey_challenges",
        "pubkey_b64",
        [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE",
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBI",
        ],
    ),
    (
        "agent_pubkey_history",
        "pubkey_b64",
        [
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCM",
            "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDQ",
        ],
    ),
    ("embed_skip", "reason", ["undecryptable", "oversize"]),
    (
        "token_cost_counters",
        "scope_kind",
        ["namespace", "lineage"],
    ),
];

/// The written-out value of `table.column` on seeded row `k`, from its
/// declared type and name.
#[must_use]
pub fn generated_value(table: &str, column: &str, decl: &str, k: usize) -> Value {
    if let Some((_, _, vals)) = OVERRIDES
        .iter()
        .find(|(t, c, _)| *t == table && *c == column)
    {
        return Value::Text(vals[k].to_string());
    }
    let decl = decl.to_ascii_uppercase();
    let k_i64 = i64::try_from(k).expect("row index fits i64");
    let k_u8 = u8::try_from(k).expect("row index fits u8");
    if decl.contains("INT") {
        return Value::Integer(k_i64);
    }
    if decl.contains("REAL") || decl.contains("FLOA") || decl.contains("DOUB") {
        return Value::Real(0.25 + f64::from(k_u8));
    }
    if decl.contains("BLOB") {
        return Value::Blob(vec![k_u8, 0xFF, 0x00, 0x80]);
    }
    let is_time = column.ends_with("_at")
        || matches!(column, "valid_from" | "valid_until" | "ts" | "timestamp");
    if is_time {
        return Value::Text(format!(
            "2031-05-0{}T0{k}:00:00.000000+00:00",
            k.saturating_add(1)
        ));
    }
    if column.ends_with("_json") {
        // A JSON column is decoded on read; a corrupt value fails the read.
        return Value::Text(format!("{{\"seed\":\"{table}.{column}#{k}\"}}"));
    }
    Value::Text(format!("{table}.{column}#{k}"))
}

/// One column of `PRAGMA table_xinfo`: name, declared type, hidden flag.
fn columns(conn: &Connection, table: &str) -> Vec<(String, String, i64)> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_xinfo(\"{table}\")"))
        .expect("prepare table_xinfo");
    stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, i64>(6)?,
        ))
    })
    .expect("query table_xinfo")
    .collect::<Result<Vec<_>, _>>()
    .expect("read table_xinfo")
}

/// `(from column, parent table, parent column)` for each foreign key.
fn foreign_keys(conn: &Connection, table: &str) -> Vec<(String, String, Option<String>)> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA foreign_key_list(\"{table}\")"))
        .expect("prepare foreign_key_list");
    stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(3)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(4)?,
        ))
    })
    .expect("query foreign_key_list")
    .collect::<Result<Vec<_>, _>>()
    .expect("read foreign_key_list")
}

/// The value seeded row `k` holds in `table.column` (its declared type
/// looked up in the live schema).
fn parent_value(conn: &Connection, table: &str, column: Option<&str>, k: usize) -> Value {
    let cols = columns(conn, table);
    let (name, decl, _) = match column {
        Some(c) => cols
            .iter()
            .find(|(n, _, _)| n == c)
            .expect("parent column exists"),
        None => cols.first().expect("parent has a column"),
    };
    generated_value(table, name, decl, k)
}

/// Write [`SEED_ROWS`] rows into every node-local table. A foreign key to
/// `memories` points at `live[k]`; a self reference is NULL on row 0 and
/// names row 0 on every later row; any other
/// foreign key holds the parent's generated value. Generated (hidden)
/// columns are skipped.
pub fn seed_node_local(conn: &Connection, live: &[String]) {
    assert!(live.len() >= SEED_ROWS, "need {SEED_ROWS} live memories");
    for table in NODE_LOCAL_TABLES {
        let cols: Vec<(String, String)> = columns(conn, table)
            .into_iter()
            .filter(|(_, _, hidden)| *hidden == 0)
            .map(|(n, d, _)| (n, d))
            .collect();
        assert!(!cols.is_empty(), "{table}: no columns in the live schema");
        let fks = foreign_keys(conn, table);
        for (k, live_id) in live.iter().enumerate().take(SEED_ROWS) {
            let values: Vec<Value> = cols
                .iter()
                .map(
                    |(name, decl)| match fks.iter().find(|(from, _, _)| from == name) {
                        Some((_, parent, _)) if parent == "memories" => {
                            Value::Text(live_id.clone())
                        }
                        Some((_, parent, to)) if parent == table => {
                            // Row 0 is the root; later rows point at it.
                            if k == 0 {
                                Value::Null
                            } else {
                                parent_value(conn, parent, to.as_deref(), 0)
                            }
                        }
                        Some((_, parent, to)) => parent_value(conn, parent, to.as_deref(), k),
                        None => generated_value(table, name, decl, k),
                    },
                )
                .collect();
            let names: Vec<String> = cols.iter().map(|(n, _)| format!("\"{n}\"")).collect();
            let marks = vec!["?"; cols.len()].join(", ");
            let sql = format!(
                "INSERT INTO \"{table}\" ({}) VALUES ({marks})",
                names.join(", ")
            );
            conn.execute(&sql, rusqlite::params_from_iter(values))
                .unwrap_or_else(|e| panic!("seed {table} row {k}: {e}"));
        }
    }
}
