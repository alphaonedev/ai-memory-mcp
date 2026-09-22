// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3790 — a refusal that is a pure function of the stored webhook URL is
//! dead-lettered on the FIRST attempt; a transient failure still walks the
//! whole `RETRY_BACKOFFS` ladder.
//!
//! `deliver_with_retry` used to retry EVERY `send` error, including
//! `ssrf_rejected` — the syntactic guard's verdict on the row's own URL,
//! final on attempt 1 — so each event cost such a row 1 + 3 attempts and
//! 6.2 s of sleep on a bounded dispatch worker (`AI_MEMORY_WEBHOOK_DISPATCH_
//! CONCURRENCY`), capacity taken from deliverable webhooks. Rows in that
//! state exist wherever a guard tightened after registration (#3705 refused
//! `http://`; #3744 taught the guard to read userinfo).
//! RED on the untouched tip (the deterministic cell records `retry_count`
//! 4), GREEN on the fix.

#![cfg(feature = "sal")]

use ai_memory::subscriptions::{
    NewSubscription, RETRY_BACKOFFS, dispatch_event, dlq_reason, insert, list_dlq,
    wait_dispatch_idle,
};
use rusqlite::Connection;

/// The two cells set the PROCESS-GLOBAL loopback knob in opposite
/// directions (`set_allow_loopback_webhooks`), so they must not overlap:
/// each owns the knob for its whole window. Async-aware so the guard may
/// span the `wait_dispatch_idle().await`.
static KNOB: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn fresh_db() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir_in(".local-runs").expect("scratch under .local-runs");
    let db = dir.path().join("hooks.db");
    let _ = ai_memory::db::open(&db).expect("seed db");
    (dir, db)
}

fn register(conn: &Connection, url: &str) -> String {
    insert(
        conn,
        &NewSubscription {
            url,
            events: "*",
            secret: Some("test-sub-secret-3790"),
            namespace_filter: None,
            agent_filter: None,
            created_by: None,
            event_types: None,
        },
    )
    .expect("a public target registers")
}

/// The full ladder: one initial attempt plus one per backoff.
fn ladder_attempts() -> i64 {
    i64::try_from(1 + RETRY_BACKOFFS.len()).expect("small")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deterministic_refusal_dead_letters_on_the_first_attempt_3790() {
    let _knob = KNOB.lock().await;
    ai_memory::config::set_allow_loopback_webhooks(false);
    let (_dir, db) = fresh_db();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    // A row the guard at `insert` would refuse today — registered before
    // the guard learned to (the #3744 legacy shape), so rewritten in place.
    let legacy_url = format!("https://a:b@127.0.0.1:{port}/hook");
    let sub_id = {
        let conn = Connection::open(&db).expect("open");
        let id = register(&conn, "https://hooks.example.com/services/T/B/legacy-3790");
        conn.execute(
            "UPDATE subscriptions SET url = ?1 WHERE id = ?2",
            rusqlite::params![legacy_url, id],
        )
        .expect("rewrite the stored URL");
        id
    };
    let started = std::time::Instant::now();
    {
        let conn = Connection::open(&db).expect("open");
        dispatch_event(&conn, "memory_store", "evt-3790", "ns-3790", None, &db);
        wait_dispatch_idle().await;
    }
    let elapsed = started.elapsed();
    let rows = {
        let conn = Connection::open(&db).expect("open");
        list_dlq(&conn, Some(sub_id.as_str())).expect("dlq")
    };
    assert_eq!(rows.len(), 1, "#3790: one DLQ row: {rows:?}");
    assert_eq!(rows[0].last_error, dlq_reason::SSRF_REJECTED);
    assert_eq!(
        rows[0].retry_count, 1,
        "#3790: a refusal that is a pure function of the stored URL is final on attempt 1"
    );
    let ladder: std::time::Duration = RETRY_BACKOFFS.iter().sum();
    assert!(
        elapsed < ladder,
        "#3790: the ladder was not slept for a deterministic refusal ({elapsed:?} >= {ladder:?})"
    );
    match listener.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("#3790: the loopback listener must never be connected to: {other:?}"),
    }
}

/// Allowed-path control: a TRANSIENT failure (a valid public-shaped target
/// that refuses the connection) still walks the whole ladder, so the
/// short-circuit is aimed at the deterministic class and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transient_connect_failure_still_walks_the_ladder_3790() {
    let _knob = KNOB.lock().await;
    // Loopback is the only unroutable-but-valid host a test can own; the
    // guard admits it only when the knob is on, and http:// is refused
    // outright (#3705), so the target is https to a closed loopback port.
    ai_memory::config::set_allow_loopback_webhooks(true);
    let (_dir, db) = fresh_db();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
        // dropped here: the port is closed by the time the dispatcher connects
    };
    let sub_id = {
        let conn = Connection::open(&db).expect("open");
        register(&conn, &format!("https://127.0.0.1:{port}/hook"))
    };
    {
        let conn = Connection::open(&db).expect("open");
        dispatch_event(&conn, "memory_store", "evt-3790-t", "ns-3790", None, &db);
        wait_dispatch_idle().await;
    }
    let rows = {
        let conn = Connection::open(&db).expect("open");
        list_dlq(&conn, Some(sub_id.as_str())).expect("dlq")
    };
    assert_eq!(rows.len(), 1, "#3790: one DLQ row: {rows:?}");
    assert_ne!(rows[0].last_error, dlq_reason::SSRF_REJECTED);
    assert_eq!(
        rows[0].retry_count,
        ladder_attempts(),
        "#3790: a transient failure keeps the full ladder: {rows:?}"
    );
}
