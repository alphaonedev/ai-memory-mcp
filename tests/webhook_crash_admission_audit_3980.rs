// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3980 — a webhook delivery admitted but not yet started must survive a
//! crash (SIGKILL / OOM kill / abort) as a durable `subscription_events` row.
//!
//! Before the fix the per-delivery audit row was written by the delivery's
//! worker, which runs only once the delivery holds a `DISPATCH_SEMAPHORE`
//! permit. #3979 covers the graceful drain deadline (unstarted deliveries are
//! recorded to the DLQ), but a crash never reaches the drain: every delivery
//! still queued behind a permit vanished with no audit row and no DLQ row.
//!
//! The pin: two subscriptions on an endpoint that accepts the TCP connection
//! and never answers (so the first delivery holds the single permit through
//! its timeout/backoff ladder), a real `ai-memory store` child with
//! `AI_MEMORY_WEBHOOK_DISPATCH_CONCURRENCY=1`, SIGKILL once the first
//! delivery is under way, then reopen the database the way a restart does.
//! Every dispatched delivery (one per matching subscription) must have its
//! `subscription_events` row.

#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ai_memory::subscriptions::{self, NewSubscription};
use rusqlite::Connection;

/// How long the child may take to start its first delivery.
const START_DEADLINE: Duration = Duration::from_secs(60);

/// Pause after the first delivery started, before the kill: the dispatch
/// loop has admitted every delivery long before this.
const SETTLE: Duration = Duration::from_millis(500);

fn audit_rows_by_subscription(db_path: &Path, sub_id: &str) -> i64 {
    Connection::open(db_path)
        .expect("open audit db")
        .query_row(
            "SELECT COUNT(*) FROM subscription_events WHERE subscription_id = ?1",
            [sub_id],
            |r| r.get(0),
        )
        .unwrap_or(0)
}

fn total_audit_rows(db_path: &Path) -> i64 {
    Connection::open(db_path)
        .expect("open audit db")
        .query_row("SELECT COUNT(*) FROM subscription_events", [], |r| r.get(0))
        .unwrap_or(0)
}

#[test]
fn a_delivery_queued_behind_a_permit_survives_sigkill_3980() {
    // The registration-time SSRF guard reads the process-wide opt-in.
    ai_memory::config::set_allow_loopback_webhooks(true);
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("crash-3980.db");
    // An endpoint that completes the TCP handshake (kernel backlog) and then
    // never says a word: the TLS handshake waits out the ACK timeout on every
    // attempt, so the first delivery keeps the only permit for seconds.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").expect("bind silent endpoint");
    let url = format!(
        "https://127.0.0.1:{}/hook",
        silent.local_addr().expect("local addr").port()
    );

    let sub_ids: Vec<String> = {
        let conn = ai_memory::db::open(&db_path).expect("db::open");
        (0..2)
            .map(|_| {
                subscriptions::insert(
                    &conn,
                    &NewSubscription {
                        url: &url,
                        events: "*",
                        secret: Some("test-secret-3980"),
                        namespace_filter: None,
                        agent_filter: None,
                        created_by: None,
                        event_types: None,
                    },
                )
                .expect("insert subscription")
            })
            .collect()
    };

    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_ALLOW_LOOPBACK_WEBHOOKS", "1")
        .env("AI_MEMORY_WEBHOOK_DISPATCH_CONCURRENCY", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("AI_MEMORY_AGENT_ID", "ai:test-3980")
        .args([
            "--db",
            db_path.to_str().expect("utf8 db path"),
            "store",
            "-n",
            "ns-3980",
            "-T",
            "crash pin 3980",
            "-c",
            "content-placeholder-3980",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ai-memory store");

    let started_by = Instant::now() + START_DEADLINE;
    while total_audit_rows(&db_path) < 1 {
        if Instant::now() >= started_by {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "no delivery started within {START_DEADLINE:?}; the pin never reached its state"
            );
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("ai-memory store exited ({status}) before any delivery started");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    std::thread::sleep(SETTLE);
    assert!(
        child.try_wait().expect("poll child").is_none(),
        "the child must still be draining (the first delivery holds the only permit)"
    );
    // SIGKILL: no drain, no shutdown sweep, no destructors.
    child.kill().expect("SIGKILL the child");
    let _ = child.wait();
    drop(silent);

    // The restart: reopen through the production open path.
    drop(ai_memory::db::open(&db_path).expect("reopen after the crash"));
    for sub in &sub_ids {
        assert_eq!(
            audit_rows_by_subscription(&db_path, sub),
            1,
            "#3980: subscription {sub}'s admitted delivery has no subscription_events row \
             after SIGKILL — a delivery queued behind the dispatch permit was lost"
        );
    }
}
