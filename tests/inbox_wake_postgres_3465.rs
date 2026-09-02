// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3465 — the POSTGRES half of the notify wake control.
//!
//! `tests/inbox_wake_3465.rs` pins the sqlite lanes. The charter
//! requires both backends where the code has both paths, and notify
//! does: `SqliteStore::notify` and `PostgresStore::notify` are separate
//! implementations of the same trait method. This file drives the
//! postgres adapter against a live cluster and asserts the same
//! property — a committed notify wakes its recipient, and the wake
//! carries a digest, never the body.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset, so
//! the default CI leg is unaffected.

// The CLIPPY LEG TRAP (#3465 pool rule): these `#![allow]`s sit BEFORE
// the `#![cfg]` so they still apply on a leg where the cfg empties the
// crate but the `//!` module docs above are still linted.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::similar_names
)]
#![cfg(feature = "sal-postgres")]

use std::time::Duration;

use ai_memory::inbox_wake::{InboxEvent, subscribe};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore};

fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

async fn connect() -> Option<PostgresStore> {
    let url = postgres_url()?;
    Some(
        PostgresStore::connect(&url)
            .await
            .expect("connect postgres"),
    )
}

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

/// Drain the process-wide bus until a wake for `recipient` arrives.
async fn wake_for(
    rx: &mut tokio::sync::broadcast::Receiver<InboxEvent>,
    recipient: &str,
) -> Option<InboxEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(ev)) if ev.recipient_agent_id() == recipient => return Some(ev),
            // Another test's recipient, or a ring overrun caused by a
            // concurrent test: keep looking until the deadline.
            Ok(Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) | Err(_) => return None,
        }
    }
}

/// ALLOWED path on postgres: `PostgresStore::notify` wakes the
/// recipient, names the durable row it just committed, and reports the
/// namespace that row actually landed in.
#[tokio::test]
async fn postgres_sal_notify_publishes_a_wake_3465() {
    let Some(store) = connect().await else {
        return;
    };
    let recipient = uid("ai:pg3465-target");
    let ctx = CallerContext::for_agent("ai:pg3465-sender");
    let mut rx = subscribe();

    let new_id = store
        .notify(&ctx, &recipient, "ping", "pg body", Some(7), None, None)
        .await
        .expect("pg notify");

    let ev = wake_for(&mut rx, &recipient)
        .await
        .expect("postgres notify must publish a wake");
    assert_eq!(ev.recipient_agent_id(), recipient);
    assert!(ev.seq() > 0);
    let InboxEvent::AgentNotified {
        inbox_row_id,
        namespace,
        sender_agent_id,
        content_digest,
        correlation_id,
        ..
    } = ev;
    assert_eq!(inbox_row_id, new_id, "the wake must name the durable row");
    assert_eq!(namespace, ai_memory::inbox_namespace(&recipient));
    assert_eq!(sender_agent_id, "ai:pg3465-sender");
    assert_eq!(
        correlation_id,
        ai_memory::write_events::correlation_id_for(&new_id),
        "the postgres wake and its webhook twin must derive the same handle"
    );
    assert!(content_digest.starts_with("sha256:"), "{content_digest}");
}

/// DENIED path on postgres: the body never reaches the bus. Same
/// property as the sqlite lane, asserted against the other adapter.
#[tokio::test]
async fn postgres_wake_frame_never_carries_the_body_3465() {
    let Some(store) = connect().await else {
        return;
    };
    let recipient = uid("ai:pg3465-secret-target");
    let secret = "PG-SUPER-SECRET-NOTIFY-BODY-3465";
    let ctx = CallerContext::for_agent("ai:pg3465-sender");
    let mut rx = subscribe();

    store
        .notify(&ctx, &recipient, "subject", secret, None, None, None)
        .await
        .expect("pg notify");

    let ev = wake_for(&mut rx, &recipient)
        .await
        .expect("postgres notify must publish a wake");
    let wire = serde_json::to_string(&ev).expect("serialise");
    assert!(
        !wire.contains(secret),
        "the notification body must never appear on the wake bus: {wire}"
    );
    assert!(!wire.contains("subject"), "{wire}");
}
