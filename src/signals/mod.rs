// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — signed-signal sqlite free-functions.
//!
//! These operate on a raw [`rusqlite::Connection`] so BOTH the SAL
//! [`crate::store::sqlite::SqliteStore`] adapter (which delegates here) AND
//! the future MCP stdio `memory_signal_*` tool handlers (which hold a bare
//! `Connection`, not a SAL store) share one implementation — exactly the
//! split [`crate::actions`] uses for the coordination-action surface. The
//! postgres adapter keeps its own sqlx-native path in `crate::store::postgres`.
//!
//! No Ed25519 signing happens here: `signature` / `sender_pubkey` are stored
//! and read back as caller-provided byte vectors (empty `Vec` for now). The
//! signing / verification logic lands in a subsequent unit.

use crate::models::{Signal, SignalType};
use rusqlite::{Connection, OptionalExtension, params};

/// SELECT column list for the `signals` table, in the canonical order
/// [`row_to_signal`] expects. One definition shared by every signal read.
pub const SIGNAL_SELECT_SQL: &str = "SELECT id, namespace, from_agent, to_agent, subject, body, \
     signal_type, in_reply_to, correlation_id, reference_ids, created_at, expires_at, \
     delivered_at, read_at, acknowledged_at, signature, sender_pubkey FROM signals";

/// Map a `rusqlite` row (the [`SIGNAL_SELECT_SQL`] column order) to a
/// [`Signal`].
///
/// # Errors
/// Propagates the `rusqlite` column-access error.
pub fn row_to_signal(r: &rusqlite::Row<'_>) -> rusqlite::Result<Signal> {
    Ok(Signal {
        id: r.get(0)?,
        namespace: r.get(1)?,
        from_agent: r.get(2)?,
        to_agent: r.get(3)?,
        subject: r.get(4)?,
        body: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or(serde_json::Value::Null),
        signal_type: SignalType::from_str(&r.get::<_, String>(6)?).unwrap_or_default(),
        in_reply_to: r.get(7)?,
        correlation_id: r.get(8)?,
        reference_ids: serde_json::from_str(&r.get::<_, String>(9)?)
            .unwrap_or(serde_json::Value::Null),
        created_at: r.get(10)?,
        expires_at: r.get(11)?,
        delivered_at: r.get(12)?,
        read_at: r.get(13)?,
        acknowledged_at: r.get(14)?,
        signature: r.get::<_, Vec<u8>>(15)?,
        sender_pubkey: r.get::<_, Vec<u8>>(16)?,
    })
}

/// Insert a signal. Returns the signal id.
///
/// # Errors
/// Propagates the `rusqlite` insert error.
pub fn insert(conn: &Connection, signal: &Signal) -> rusqlite::Result<String> {
    conn.execute(
        "INSERT INTO signals \
            (id, namespace, from_agent, to_agent, subject, body, signal_type, \
             in_reply_to, correlation_id, reference_ids, created_at, expires_at, \
             delivered_at, read_at, acknowledged_at, signature, sender_pubkey) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
        params![
            signal.id,
            signal.namespace,
            signal.from_agent,
            signal.to_agent,
            signal.subject,
            signal.body.to_string(),
            signal.signal_type.as_str(),
            signal.in_reply_to,
            signal.correlation_id,
            signal.reference_ids.to_string(),
            signal.created_at,
            signal.expires_at,
            signal.delivered_at,
            signal.read_at,
            signal.acknowledged_at,
            signal.signature,
            signal.sender_pubkey,
        ],
    )?;
    Ok(signal.id.clone())
}

/// Fetch a signal by id. `None` when absent.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn get(conn: &Connection, id: &str) -> rusqlite::Result<Option<Signal>> {
    conn.query_row(
        &format!("{SIGNAL_SELECT_SQL} WHERE id = ?1"),
        params![id],
        row_to_signal,
    )
    .optional()
}

/// List a namespace inbox, newest-first, capped at `limit`. When `to_agent`
/// is `Some`, returns both direct messages (`to_agent = ?2`) and broadcasts
/// (`to_agent IS NULL`); when `None`, returns every signal in the namespace.
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn list_inbox(
    conn: &Connection,
    namespace: &str,
    to_agent: Option<&str>,
    limit: usize,
) -> rusqlite::Result<Vec<Signal>> {
    let lim = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut sql = format!("{SIGNAL_SELECT_SQL} WHERE namespace = ?");
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(namespace.to_string())];
    if let Some(agent) = to_agent {
        sql.push_str(" AND (to_agent = ? OR to_agent IS NULL)");
        binds.push(Box::new(agent.to_string()));
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT ?");
    binds.push(Box::new(lim));
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        rusqlite::params_from_iter(binds.iter().map(|b| &**b)),
        row_to_signal,
    )?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Every signal sharing a `correlation_id`, oldest-first (thread order).
///
/// # Errors
/// Propagates the `rusqlite` query error.
pub fn thread(conn: &Connection, correlation_id: &str) -> rusqlite::Result<Vec<Signal>> {
    let mut stmt = conn.prepare(&format!(
        "{SIGNAL_SELECT_SQL} WHERE correlation_id = ?1 ORDER BY created_at ASC"
    ))?;
    let rows = stmt.query_map(params![correlation_id], row_to_signal)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Stamp `delivered_at` on a signal once. Returns `true` when this call set
/// the timestamp, `false` when it was already delivered (or no row matched).
///
/// # Errors
/// Propagates the `rusqlite` update error.
pub fn mark_delivered(conn: &Connection, id: &str, now: i64) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE signals SET delivered_at = ?1 WHERE id = ?2 AND delivered_at IS NULL",
        params![now, id],
    )?;
    Ok(n > 0)
}

/// Stamp `read_at` on a signal once. Returns `true` when this call set the
/// timestamp, `false` when it was already read (or no row matched).
///
/// # Errors
/// Propagates the `rusqlite` update error.
pub fn mark_read(conn: &Connection, id: &str, now: i64) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE signals SET read_at = ?1 WHERE id = ?2 AND read_at IS NULL",
        params![now, id],
    )?;
    Ok(n > 0)
}

/// Stamp `acknowledged_at` on a signal once. Returns `true` when this call set
/// the timestamp, `false` when it was already acked (or no row matched).
///
/// # Errors
/// Propagates the `rusqlite` update error.
pub fn mark_acked(conn: &Connection, id: &str, now: i64) -> rusqlite::Result<bool> {
    let n = conn.execute(
        "UPDATE signals SET acknowledged_at = ?1 WHERE id = ?2 AND acknowledged_at IS NULL",
        params![now, id],
    )?;
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open in-memory db")
    }

    fn sample(id: &str) -> Signal {
        Signal {
            id: id.to_string(),
            namespace: "_sig".to_string(),
            from_agent: "agent-from".to_string(),
            to_agent: Some("agent-to".to_string()),
            subject: "s".to_string(),
            body: serde_json::json!({"k": "v"}),
            signal_type: SignalType::Notify,
            in_reply_to: None,
            correlation_id: None,
            reference_ids: serde_json::json!([]),
            created_at: 1_700_000_000,
            expires_at: None,
            delivered_at: None,
            read_at: None,
            acknowledged_at: None,
            signature: vec![],
            sender_pubkey: vec![],
        }
    }

    #[test]
    fn insert_then_get_roundtrips() {
        let conn = fresh();
        let id = insert(&conn, &sample("s1")).unwrap();
        assert_eq!(id, "s1");
        let got = get(&conn, "s1").unwrap().expect("present");
        assert_eq!(got.namespace, "_sig");
        assert_eq!(got.from_agent, "agent-from");
        assert_eq!(got.to_agent.as_deref(), Some("agent-to"));
        assert_eq!(got.signal_type, SignalType::Notify);
        assert_eq!(got.body, serde_json::json!({"k": "v"}));
        assert_eq!(got.reference_ids, serde_json::json!([]));
        assert!(got.signature.is_empty());
        assert!(got.sender_pubkey.is_empty());
        assert!(get(&conn, "missing").unwrap().is_none());
    }

    #[test]
    fn list_inbox_sees_direct_and_broadcast() {
        let conn = fresh();
        // Direct message to agent-to.
        insert(&conn, &sample("direct")).unwrap();
        // Broadcast (to_agent NULL) in the same namespace.
        let mut bcast = sample("bcast");
        bcast.to_agent = None;
        bcast.signal_type = SignalType::Broadcast;
        bcast.created_at = 1_700_000_100;
        insert(&conn, &bcast).unwrap();
        // A message addressed to a DIFFERENT agent must not surface.
        let mut other = sample("other");
        other.to_agent = Some("agent-elsewhere".to_string());
        insert(&conn, &other).unwrap();

        let inbox = list_inbox(&conn, "_sig", Some("agent-to"), 50).unwrap();
        let ids: Vec<&str> = inbox.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"direct"), "direct message visible");
        assert!(ids.contains(&"bcast"), "broadcast visible");
        assert!(!ids.contains(&"other"), "other-agent message hidden");
        // Newest-first ordering: the broadcast (later created_at) leads.
        assert_eq!(inbox[0].id, "bcast");

        // to_agent = None returns every signal in the namespace.
        let all = list_inbox(&conn, "_sig", None, 50).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn thread_groups_by_correlation_id() {
        let conn = fresh();
        let mut a = sample("t-a");
        a.correlation_id = Some("corr-1".to_string());
        a.created_at = 1_700_000_000;
        insert(&conn, &a).unwrap();
        let mut b = sample("t-b");
        b.correlation_id = Some("corr-1".to_string());
        b.created_at = 1_700_000_050;
        insert(&conn, &b).unwrap();
        // Different correlation id — must not appear in the thread.
        let mut c = sample("t-c");
        c.correlation_id = Some("corr-2".to_string());
        insert(&conn, &c).unwrap();

        let t = thread(&conn, "corr-1").unwrap();
        assert_eq!(t.len(), 2);
        // Oldest-first ordering.
        assert_eq!(t[0].id, "t-a");
        assert_eq!(t[1].id, "t-b");
    }

    #[test]
    fn mark_lifecycle_flips_once() {
        let conn = fresh();
        insert(&conn, &sample("m1")).unwrap();

        // delivered: first call flips, second is a no-op.
        assert!(mark_delivered(&conn, "m1", 1_700_000_010).unwrap());
        assert!(!mark_delivered(&conn, "m1", 1_700_000_020).unwrap());
        // read: first call flips, second is a no-op.
        assert!(mark_read(&conn, "m1", 1_700_000_030).unwrap());
        assert!(!mark_read(&conn, "m1", 1_700_000_040).unwrap());
        // acked: first call flips, second is a no-op.
        assert!(mark_acked(&conn, "m1", 1_700_000_050).unwrap());
        assert!(!mark_acked(&conn, "m1", 1_700_000_060).unwrap());

        let got = get(&conn, "m1").unwrap().expect("present");
        assert_eq!(got.delivered_at, Some(1_700_000_010));
        assert_eq!(got.read_at, Some(1_700_000_030));
        assert_eq!(got.acknowledged_at, Some(1_700_000_050));

        // A missing row never flips.
        assert!(!mark_delivered(&conn, "missing", 1_700_000_070).unwrap());
    }
}
