// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3469 — the POSTGRES half of the wake-hub bus-sink control.
//!
//! `tests/wake_sink_3469.rs` pins the sqlite lanes. The bus itself is
//! backend-blind, but the EMITTER is not: `SqliteStore::notify` and
//! `PostgresStore::notify` are separate implementations of the same trait
//! method, so "a committed notify reaches the hub" has to be proved on both.
//! This file drives the postgres adapter against a live cluster and asserts the
//! same end-to-end property — a committed notify becomes a hub `wake` frame on
//! the recipient's writer queue, naming the durable row, stamped with the
//! reserved producer identity, carrying a digest and never a body.
//!
//! Gated on `AI_MEMORY_TEST_POSTGRES_URL`; skips cleanly when unset, so the
//! default CI leg is unaffected.

// The CLIPPY LEG TRAP (#3465 pool rule): these `#![allow]`s sit BEFORE the
// `#![cfg]` so they still apply on a leg where the cfg empties the crate but
// the `//!` module docs above are still linted.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::similar_names
)]
#![cfg(feature = "sal-postgres")]

use std::sync::Arc;
use std::time::Duration;

use ai_memory::identity::sentinels::WAKE_HUB_PRODUCER;
use ai_memory::inbox_wake::{InboxEvent, InboxWakeSink as _, subscribe};
use ai_memory::store::postgres::PostgresStore;
use ai_memory::store::{CallerContext, MemoryStore as _};
use ai_memory::wake_hub::frame::{Frame, Kind, WakeMeta};
use ai_memory::wake_hub::limits::{
    DEFAULT_GLOBAL_EGRESS_BYTES, DEFAULT_PENDING_MAX_AGENTS, DEFAULT_PENDING_MAX_IDS,
    DEFAULT_RECIPIENT_QUEUE_BYTES, DEFAULT_RECIPIENT_QUEUE_FRAMES, EgressBudget,
};
use ai_memory::wake_hub::metrics::HubMetrics;
use ai_memory::wake_hub::pending::PendingStore;
use ai_memory::wake_hub::routing::{Egress, EgressAccount, EgressHandle, Router};
use ai_memory::wake_sink::in_process::InProcessWakeSink;
use tokio::sync::{Notify, mpsc};

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

/// A live router with one registered recipient whose writer queue this test
/// holds — the same shape a connected hub session installs.
fn hub_probe(recipient: &str) -> (Arc<Router>, mpsc::Receiver<Egress>) {
    let egress = Arc::new(EgressBudget::new(DEFAULT_GLOBAL_EGRESS_BYTES));
    let router = Arc::new(Router::new(
        DEFAULT_RECIPIENT_QUEUE_FRAMES,
        DEFAULT_RECIPIENT_QUEUE_BYTES,
        Arc::clone(&egress),
        PendingStore::new(DEFAULT_PENDING_MAX_AGENTS, DEFAULT_PENDING_MAX_IDS),
        Arc::new(HubMetrics::default()),
    ));
    let (tx, queue) = mpsc::channel(DEFAULT_RECIPIENT_QUEUE_FRAMES);
    let handle = EgressHandle::new(
        tx,
        Arc::new(EgressAccount::new()),
        egress,
        Arc::new(Notify::new()),
        DEFAULT_RECIPIENT_QUEUE_BYTES,
    );
    assert!(router.register(recipient, 1, handle).is_none());
    (router, queue)
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
            Ok(Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) | Err(_) => return None,
        }
    }
}

/// ALLOWED, postgres funnel: a committed `PostgresStore::notify` reaches the
/// hub's router as a `wake` naming the durable row.
#[tokio::test]
async fn postgres_notify_reaches_the_hub_sink_3469() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let recipient = uid("bob-pg");
    let secret = "SUPER-SECRET-NOTIFY-BODY-3469-PG";
    let (router, mut queue) = hub_probe(&recipient);
    let sink = InProcessWakeSink::for_router(Arc::clone(&router));
    let mut rx = subscribe();

    let ctx = CallerContext::for_agent("ai:alice");
    let row_id = store
        .notify(&ctx, &recipient, "ping", secret, Some(5), None, None)
        .await
        .expect("pg notify");

    let event = wake_for(&mut rx, &recipient)
        .await
        .expect("the postgres adapter must publish a wake");
    sink.on_wake(&event);

    let Some(Egress::Frame(bytes)) = queue.recv().await else {
        panic!("the wake must reach the recipient's writer queue");
    };
    let frame = Frame::decode(&bytes).expect("the hub only queues legal frames");
    assert_eq!(frame.kind, Kind::Wake);
    assert_eq!(frame.to, recipient);
    assert!(
        !frame.to_is_topic(),
        "substrate wakes are never topic-routed"
    );
    assert_eq!(
        frame.from, WAKE_HUB_PRODUCER,
        "a substrate wake is stamped with the reserved producer id, not the sender"
    );

    let meta = WakeMeta::decode(&frame.payload).expect("wake metadata");
    assert_eq!(
        meta.inbox_row_id, row_id,
        "the wake must name the durable row"
    );
    assert_eq!(meta.namespace, ai_memory::inbox_namespace(&recipient));
    assert_eq!(meta.digest.len(), 32, "a digest, never a body");
    assert!(meta.seq_high_watermark > 0);

    assert!(
        !String::from_utf8_lossy(&bytes).contains(secret),
        "the notification body must never reach the wake plane"
    );
    assert_eq!(sink.metrics().snapshot().delivered, 1);
}

/// DENIED, postgres funnel: a wake for another agent never lands on this
/// recipient's queue, on this backend either.
#[tokio::test]
async fn a_postgres_wake_for_another_agent_never_lands_here_3469() {
    let Some(store) = connect().await else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let mine = uid("carol-pg");
    let theirs = uid("mallory-pg");
    let (router, mut queue) = hub_probe(&mine);
    let sink = InProcessWakeSink::for_router(Arc::clone(&router));
    let mut rx = subscribe();

    let ctx = CallerContext::for_agent("ai:alice");
    store
        .notify(&ctx, &theirs, "ping", "body", Some(5), None, None)
        .await
        .expect("pg notify");

    let event = wake_for(&mut rx, &theirs).await.expect("wake published");
    sink.on_wake(&event);

    assert!(
        queue.try_recv().is_err(),
        "another agent's wake must never be queued here"
    );
    assert_eq!(sink.metrics().snapshot().dropped_unknown, 1);
}
