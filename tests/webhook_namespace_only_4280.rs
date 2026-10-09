// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4280 — a namespace-only subscription records its events, it does not
//! deliver them.
//!
//! `POST /api/v1/subscriptions` with `{agent_id, namespace}` and no `url`
//! stores an ordinary subscription row whose url is the synthetic
//! `https://localhost/_ns/<agent>/<namespace>`. Before the fix the dispatcher
//! treated it like any webhook: every matching event wrote the audit row
//! (wanted: `memory_subscription_replay` reads it) AND attempted a delivery to
//! the synthetic loopback URL, which the dispatch-time SSRF guard refuses by
//! default, so each event also left a permanent `subscription_dlq` row no
//! operator can act on (and with `allow_loopback_webhooks` the daemon sent a request
//! to whatever listens on localhost:443).
//!
//! The process-wide loopback opt-in is toggled between phases; the cells are
//! serialized on one lock.

use std::time::Duration;

use ai_memory::config::set_allow_loopback_webhooks;
use ai_memory::subscriptions::{self, NewSubscription};
use common::tls_receiver::{TlsReceiver, ack_echo};
use rusqlite::{Connection, params};

mod common;
use common::fresh_db_tempfile_path as fresh_db;

/// Serializes the cells: the loopback opt-in is process-wide.
static LOOPBACK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The terminal status a namespace-only event's audit row carries. Spelled
/// as a literal so this file compiles on the pre-fix carrier.
const RECORDED: &str = "recorded";

/// Seed a namespace-only row the way the HTTP synthesizer stores it, with
/// raw SQL so the cell does not depend on the registration API under test.
fn seed_namespace_only(conn: &Connection, agent: &str, ns: &str) -> String {
    let id = format!("sub-ns-{}", uuid::Uuid::new_v4());
    conn.execute(
        "INSERT INTO subscriptions (id, url, events, secret_hash, namespace_filter, \
         agent_filter, created_by, created_at) VALUES (?1, ?2, '*', ?3, ?4, ?5, ?5, ?6)",
        params![
            id,
            format!("https://localhost/_ns/{agent}/{ns}"),
            "0".repeat(64),
            ns,
            agent,
            chrono::Utc::now().to_rfc3339(),
        ],
    )
    .expect("seed namespace-only subscription");
    id
}

fn statuses(conn: &Connection, sub_id: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT delivery_status FROM subscription_events WHERE subscription_id = ?1")
        .expect("prepare");
    stmt.query_map([sub_id], |r| r.get::<_, String>(0))
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
}

fn dlq_rows(conn: &Connection, sub_id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM subscription_dlq WHERE subscription_id = ?1",
        [sub_id],
        |r| r.get(0),
    )
    .expect("count dlq")
}

fn dispatch_count(conn: &Connection, sub_id: &str) -> i64 {
    conn.query_row(
        "SELECT dispatch_count + failure_count FROM subscriptions WHERE id = ?1",
        [sub_id],
        |r| r.get(0),
    )
    .expect("dispatch count")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_namespace_only_subscription_records_without_delivering_4280() {
    let _serial = LOOPBACK.lock().await;
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).expect("open");
    let agent = "ai:ns-only-4280";
    let ns = "ns-4280";
    let ns_sub = seed_namespace_only(&conn, agent, ns);

    // Phase 1 — the default posture (loopback refused).
    set_allow_loopback_webhooks(false);
    subscriptions::dispatch_event(&conn, "memory_store", "mem-1", ns, Some(agent), &db_path);
    subscriptions::drain_dispatches(Duration::from_secs(60)).await;
    assert_eq!(
        statuses(&conn, &ns_sub),
        [RECORDED],
        "#4280: one audit row per event, settled as never-sent by design"
    );
    assert_eq!(
        dlq_rows(&conn, &ns_sub),
        0,
        "#4280: a namespace-only event must not leave a DLQ row"
    );

    // Phase 2 — loopback allowed: still no delivery attempt; a real webhook
    // subscription in the same dispatch is delivered as before.
    set_allow_loopback_webhooks(true);
    let tls = common::tls_receiver::dispatch_tls(&std::env::temp_dir());
    let receiver = TlsReceiver::start_with(tls, ack_echo()).await;
    let real_sub = subscriptions::insert(
        &conn,
        &NewSubscription {
            url: &format!("{}/hook-4280", receiver.uri()),
            events: "*",
            secret: Some("test-secret-4280"),
            namespace_filter: Some(ns),
            agent_filter: None,
            created_by: None,
            event_types: None,
        },
    )
    .expect("register a real webhook");
    subscriptions::dispatch_event(&conn, "memory_store", "mem-2", ns, Some(agent), &db_path);
    subscriptions::drain_dispatches(Duration::from_secs(60)).await;
    assert_eq!(statuses(&conn, &ns_sub), [RECORDED, RECORDED]);
    assert_eq!(dlq_rows(&conn, &ns_sub), 0);
    assert_eq!(
        dispatch_count(&conn, &ns_sub),
        0,
        "#4280: no delivery attempt is counted for a namespace-only row"
    );
    assert_eq!(
        statuses(&conn, &real_sub),
        ["ack"],
        "a real webhook is unchanged"
    );
    assert_eq!(
        receiver.received_count().await,
        1,
        "only the real webhook was sent"
    );

    // Replay still returns both events.
    let replayed =
        subscriptions::replay_subscription_events(&conn, &ns_sub, "1970-01-01T00:00:00Z")
            .expect("replay");
    assert_eq!(
        replayed.len(),
        2,
        "#4280: replay returns every recorded event"
    );
    set_allow_loopback_webhooks(false);
}

/// The synthetic prefix is reserved: no caller may register a webhook URL
/// that the dispatcher would read as namespace-only (that would silently turn
/// its deliveries into audit-only rows). Refused even with loopback allowed,
/// in any letter case.
#[test]
fn a_caller_supplied_url_with_the_namespace_only_prefix_is_refused_4280() {
    let _serial = LOOPBACK.blocking_lock();
    let (_keep, db_path) = fresh_db();
    let conn = Connection::open(&db_path).expect("open");
    set_allow_loopback_webhooks(true);
    for url in [
        "https://localhost/_ns/ai:victim/team",
        "HTTPS://LOCALHOST/_ns/ai:victim/team",
        "https://LocalHost/_ns/x",
    ] {
        let res = subscriptions::insert(
            &conn,
            &NewSubscription {
                url,
                events: "*",
                secret: Some("test-secret-4280"),
                namespace_filter: None,
                agent_filter: None,
                created_by: None,
                event_types: None,
            },
        );
        assert!(
            res.is_err(),
            "#4280: {url} uses the reserved namespace-only prefix and must be refused"
        );
    }
    assert!(
        subscriptions::validate_url("https://localhost/hook-4280").is_ok(),
        "an ordinary loopback webhook is still accepted under the opt-in"
    );
    set_allow_loopback_webhooks(false);
}
