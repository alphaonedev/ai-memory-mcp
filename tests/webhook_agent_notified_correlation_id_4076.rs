// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4076 — an `agent_notified` webhook payload must carry exactly ONE
//! top-level `correlation_id`: the delivery UUID the dispatcher checks the
//! ACK against.
//!
//! The details block is flattened into the delivery envelope. Before the
//! fix, `AgentNotifiedEventDetails` serialized its notification digest
//! (`sha256:<hex>` over the inbox row id) under the SAME key, so the body
//! carried two `correlation_id` keys with different values. A JSON parser
//! keeps the last one (the digest), so a receiver that follows the
//! documented contract (parse the body, echo `correlation_id`) acked the
//! digest and every delivery ended as an ACK mismatch in the DLQ.
//!
//! The receiver here echoes from the BODY only (never the header), the way
//! a body-parsing receiver does. The notification digest must still be on
//! the wire, under `notification_correlation_id`.

use std::time::{Duration, Instant};

use ai_memory::config::set_allow_loopback_webhooks;
use ai_memory::subscriptions::{self, NewSubscription};
use ai_memory::write_events::{self, AgentNotified};
use common::tls_receiver::{Recorded, Respond, Responder, TlsReceiver};
use rusqlite::Connection;

mod common;
use common::fresh_db_tempfile_path as fresh_db;

/// Longer than the whole ACK/backoff ladder, so a failed delivery has
/// reached its final status before the deadline.
const SETTLE_DEADLINE: Duration = Duration::from_secs(60);

/// The documented receiver: parse the body, echo its `correlation_id`.
fn body_echo() -> Responder {
    std::sync::Arc::new(|req: &Recorded| {
        let echoed = serde_json::from_slice::<serde_json::Value>(&req.body)
            .ok()
            .and_then(|v| {
                v.get("correlation_id")
                    .and_then(|c| c.as_str().map(str::to_string))
            })
            .unwrap_or_default();
        Respond::ok().json(serde_json::json!({"status": "ack", "correlation_id": echoed}))
    })
}

fn final_status(db_path: &std::path::Path) -> Option<(String, String)> {
    Connection::open(db_path)
        .expect("open audit db")
        .query_row(
            "SELECT correlation_id, delivery_status FROM subscription_events \
             WHERE delivery_status IN ('ack', 'failed')",
            [],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_notified_body_echo_receiver_acks_with_one_correlation_id_4076() {
    set_allow_loopback_webhooks(true);
    let (_keep, db_path) = fresh_db();
    let tls = common::tls_receiver::dispatch_tls(&std::env::temp_dir());
    let receiver = TlsReceiver::start_with(tls, body_echo()).await;
    let url = format!("{}/hook", receiver.uri());
    let conn = Connection::open(&db_path).expect("open");
    subscriptions::insert(
        &conn,
        &NewSubscription {
            url: &url,
            events: "agent_notified",
            secret: Some("test-secret-4076"),
            namespace_filter: None,
            agent_filter: None,
            created_by: None,
            event_types: None,
        },
    )
    .expect("insert subscription");

    let inbox_row_id = "inbox-row-4076";
    write_events::agent_notified(
        &conn,
        &db_path,
        &AgentNotified {
            recipient_agent_id: "ai:recipient-4076",
            sender_agent_id: "ai:sender-4076",
            inbox_row_id,
            namespace: "_messages/ai:recipient-4076",
            content: "body-placeholder-4076",
        },
    );

    let deadline = Instant::now() + SETTLE_DEADLINE;
    let (audit_corr, status) = loop {
        if let Some(done) = final_status(&db_path) {
            break done;
        }
        assert!(
            Instant::now() < deadline,
            "the delivery never reached a final status"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    let requests = receiver.received_requests().await.expect("recorded");
    let first = requests.first().expect("at least one delivery attempt");
    let raw = String::from_utf8_lossy(&first.body).into_owned();
    assert_eq!(
        raw.matches("\"correlation_id\":").count(),
        1,
        "#4076: the agent_notified body must carry exactly one top-level \
         `correlation_id` key; body = {raw}"
    );
    let body: serde_json::Value = serde_json::from_slice(&first.body).expect("json body");
    let header = first
        .headers
        .get("x-ai-memory-correlation-id")
        .and_then(|v| v.to_str().ok())
        .expect("correlation header")
        .to_string();
    assert_eq!(
        body.get("correlation_id").and_then(|v| v.as_str()),
        Some(header.as_str()),
        "#4076: the body's correlation_id must be the delivery id the header carries"
    );
    assert_eq!(audit_corr, header, "audit row and header name the same delivery");
    assert_eq!(
        body.get("notification_correlation_id")
            .and_then(|v| v.as_str()),
        Some(write_events::correlation_id_for(inbox_row_id).as_str()),
        "#4076: the notification digest must survive under its own key"
    );
    assert_eq!(
        status, "ack",
        "#4076: a receiver that echoes the body's correlation_id must be acked"
    );
    assert_eq!(requests.len(), 1, "one request, no retry ladder");
    let dlq = subscriptions::list_dlq(&conn, None).expect("dlq list");
    assert!(dlq.is_empty(), "no DLQ row for an acked delivery: {dlq:?}");
}
