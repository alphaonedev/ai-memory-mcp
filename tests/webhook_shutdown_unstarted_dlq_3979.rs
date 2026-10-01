// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3979 — a webhook delivery still waiting for a worker when the shutdown
//! drain misses its deadline must leave a durable row, never vanish.
//!
//! A delivery's `subscription_events` audit row is written by its worker,
//! and the worker runs only once the delivery holds a `DISPATCH_SEMAPHORE`
//! permit and the blocking pool has started it. Before #3979, a delivery
//! queued behind the permit when `drain_dispatches` timed out was dropped
//! with the runtime: no audit row, no DLQ row, invisible to replay and to
//! `memory_subscription_dlq_list`. The shutdown WARN claimed that "every
//! admitted delivery has a persisted audit row".
//!
//! The shape (from the lane F review): pin the concurrency to ONE permit,
//! register two subscribers on a receiver that never ACKs in time, dispatch
//! one event, wait until the first delivery's worker has started, drain
//! with a short timeout, then DROP the runtime the way a process exit does.
//! Every dispatched delivery must then have either its audit row (it had
//! started) or a `subscription_dlq` row with reason `shutdown_unstarted`
//! (it had not). Exactly one of each is expected, and no delivery may have
//! both: a started delivery with a `shutdown_unstarted` row would mean the
//! sweep recorded a delivery its worker already owned.
//!
//! Red on the carrier (the queued delivery has neither row), green with the
//! #3979 drain-deadline sweep. The concurrency override is process-wide, so
//! this binary holds exactly one test.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use ai_memory::config::set_allow_loopback_webhooks;
use ai_memory::subscriptions::{self, NewSubscription, override_dispatch_concurrency_for_tests};
use common::tls_receiver::{TlsReceiver, ack_echo_slow};
use rusqlite::{Connection, params};

mod common;
use common::fresh_db_tempfile_path as fresh_db;

/// The reason the drain sweep writes (`subscriptions::dlq_reason`). Spelled
/// as a literal so this file also compiles on the pre-fix carrier, where it
/// must fail on the assertion, not on a missing constant.
const SHUTDOWN_UNSTARTED: &str = "shutdown_unstarted";

/// Far longer than the ~26 s ACK/backoff ladder, so the first delivery
/// holds the single permit for the whole test.
const RECEIVER_DELAY: Duration = Duration::from_secs(120);

/// How long the first worker may take to write its audit row.
const START_DEADLINE: Duration = Duration::from_secs(30);

/// The drain budget. The first delivery cannot finish inside it.
const SHORT_DRAIN: Duration = Duration::from_millis(500);

#[derive(Debug, Default)]
struct Rows {
    /// `subscription_events` correlation ids.
    audit: Vec<String>,
    /// `subscription_dlq` (correlation id, `last_error`, `retry_count`).
    dlq: Vec<(String, String, i64)>,
}

fn rows_by_subscription(db_path: &std::path::Path) -> BTreeMap<String, Rows> {
    let conn = Connection::open(db_path).expect("open audit db");
    let mut out: BTreeMap<String, Rows> = BTreeMap::new();
    let mut stmt = conn
        .prepare("SELECT subscription_id, correlation_id FROM subscription_events")
        .expect("prepare events");
    for row in stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .expect("query events")
    {
        let (sub, corr) = row.expect("events row");
        out.entry(sub).or_default().audit.push(corr);
    }
    let mut stmt = conn
        .prepare(
            "SELECT subscription_id, correlation_id, last_error, retry_count \
             FROM subscription_dlq",
        )
        .expect("prepare dlq");
    for row in stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .expect("query dlq")
    {
        let (sub, corr, err, retries) = row.expect("dlq row");
        out.entry(sub).or_default().dlq.push((corr, err, retries));
    }
    out
}

fn audit_row_count(db_path: &std::path::Path) -> i64 {
    Connection::open(db_path)
        .expect("open audit db")
        .query_row("SELECT COUNT(*) FROM subscription_events", params![], |r| {
            r.get(0)
        })
        .expect("count events")
}

/// Each dispatched delivery has its audit row (it had started) or exactly
/// one `shutdown_unstarted` DLQ row (it had not), never both and never
/// neither; one of each is expected.
fn assert_every_delivery_left_one_row(sub_ids: &[String], db_path: &std::path::Path) {
    let rows = rows_by_subscription(db_path);
    let mut started = 0;
    let mut unstarted = 0;
    for sub in sub_ids {
        let r = rows.get(sub);
        let audit = r.map_or(0, |r| r.audit.len());
        let unstarted_dlq: Vec<&(String, String, i64)> = r.map_or_else(Vec::new, |r| {
            r.dlq
                .iter()
                .filter(|(_, err, _)| err == SHUTDOWN_UNSTARTED)
                .collect()
        });
        assert!(
            audit > 0 || !unstarted_dlq.is_empty(),
            "#3979: subscription {sub}'s delivery has NEITHER a subscription_events \
             audit row NOR a subscription_dlq row after the drain deadline and runtime \
             drop — it was silently lost. rows = {rows:?}"
        );
        assert!(
            audit == 0 || unstarted_dlq.is_empty(),
            "#3979: subscription {sub}'s delivery has an audit row (its worker had \
             started) AND a `{SHUTDOWN_UNSTARTED}` DLQ row — the sweep recorded a \
             delivery its worker already owned. rows = {rows:?}"
        );
        if audit > 0 {
            started += 1;
        } else {
            assert_eq!(
                unstarted_dlq.len(),
                1,
                "exactly one DLQ row per unstarted delivery"
            );
            assert_eq!(
                unstarted_dlq[0].2, 0,
                "an unstarted delivery made no attempt"
            );
            unstarted += 1;
        }
    }
    assert_eq!(
        (started, unstarted),
        (1, 1),
        "one delivery held the permit, the other was queued behind it"
    );
}

#[test]
fn a_delivery_queued_at_the_drain_deadline_gets_a_dlq_row_not_silence_3979() {
    override_dispatch_concurrency_for_tests(1)
        .expect("the concurrency override must be the first in this binary");
    set_allow_loopback_webhooks(true);
    let (_keep, db_path) = fresh_db();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");

    let (sub_ids, receiver) = rt.block_on(async {
        let tls = common::tls_receiver::dispatch_tls(&std::env::temp_dir());
        let receiver = TlsReceiver::start_with(tls, ack_echo_slow(RECEIVER_DELAY)).await;
        let url = format!("{}/hook", receiver.uri());
        let conn = Connection::open(&db_path).expect("open");
        let sub_ids: Vec<String> = (0..2)
            .map(|_| {
                subscriptions::insert(
                    &conn,
                    &NewSubscription {
                        url: &url,
                        events: "*",
                        secret: Some("test-secret-3979"),
                        namespace_filter: None,
                        agent_filter: None,
                        created_by: None,
                        event_types: None,
                    },
                )
                .expect("insert subscription")
            })
            .collect();

        subscriptions::dispatch_event(&conn, "memory_store", "mem-3979", "ns-3979", None, &db_path);

        // Wait for the delivery that won the single permit to start: its
        // worker writes the audit row before the first send. The other one
        // is now queued behind the permit.
        let started_by = Instant::now() + START_DEADLINE;
        while audit_row_count(&db_path) < 1 {
            assert!(
                Instant::now() < started_by,
                "no delivery worker started within {START_DEADLINE:?}; the test \
                 never reached the state it pins"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let drained = subscriptions::drain_dispatches(SHORT_DRAIN).await;
        assert!(
            !drained,
            "the first delivery holds the only permit for its whole ~26 s ladder, \
             so a {SHORT_DRAIN:?} drain must miss"
        );
        (sub_ids, receiver)
    });

    // What a process exit does to the queued task: drop it, unpolled.
    rt.shutdown_background();

    assert_every_delivery_left_one_row(&sub_ids, &db_path);
    drop(receiver);
}
