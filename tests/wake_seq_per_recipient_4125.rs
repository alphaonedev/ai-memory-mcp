// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4125 — the wake-hub `seq_high_watermark` is PER RECIPIENT.
//!
//! Before #4125 the wake sink forwarded the producer's host-wide wake
//! sequence, so the gap between two of one recipient's watermarks counted
//! every OTHER recipient's notifies — the cross-tenant activity-volume
//! signal #4071 removes from the inbox SSE stream. GOD's ruling: not exempt;
//! make it per-recipient while keeping the self-heal contract (a gap in the
//! recipient's OWN sequence still means one catch-up inbox read, including
//! under broadcast lag).
//!
//! Cells:
//! 1. writes to A only — B's watermark must not move (bus level, then
//!    through the real sqlite and postgres notify funnels);
//! 2. a LAGGED receiver must still see a gap (delta > 1) in A's own
//!    sequence, so a counter renumbered in the consumer (which would hand
//!    out contiguous numbers across the drop) can never pass.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use std::time::Duration;

use ai_memory::inbox_wake::{INBOX_WAKE_BROADCAST_CAPACITY, InboxEvent, subscribe};
use ai_memory::wake_client::SeqTracker;
use ai_memory::wake_sink::wake_meta_for;
use ai_memory::write_events::{AgentNotified, agent_notified_wake};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;

fn uid(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn notify_wake(recipient: &str, row: &str) {
    agent_notified_wake(&AgentNotified {
        recipient_agent_id: recipient,
        sender_agent_id: "ai:sender-4125",
        inbox_row_id: row,
        namespace: "_inbox/x",
        content: "body",
    });
}

/// Next wake for `recipient`, skipping other recipients' frames and ring
/// overruns. Returns the watermark the hub would forward.
async fn watermark_for(rx: &mut Receiver<InboxEvent>, recipient: &str) -> u64 {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "no wake for the watched recipient before the deadline"
        );
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(ev)) if ev.recipient_agent_id() == recipient => {
                return wake_meta_for(&ev).seq_high_watermark;
            }
            Ok(Ok(_) | Err(RecvError::Lagged(_))) => {}
            Ok(Err(RecvError::Closed)) | Err(_) => {
                panic!("bus closed waiting for the watched recipient")
            }
        }
    }
}

/// Cell 1 (bus level): wakes to A never move B's watermark, and B's client
/// sees a plain `Wake` (no gap), not a `Gap` sized by A's traffic.
#[tokio::test]
async fn another_recipients_wakes_never_move_my_watermark_4125() {
    let a = uid("ai:a4125");
    let b = uid("ai:b4125");
    let mut rx = subscribe();

    notify_wake(&b, "b-1");
    let b1 = watermark_for(&mut rx, &b).await;
    for i in 0..5 {
        notify_wake(&a, &format!("a-{i}"));
    }
    notify_wake(&b, "b-2");
    let b2 = watermark_for(&mut rx, &b).await;

    assert_eq!(
        b2.checked_sub(b1),
        Some(1),
        "B's watermark moved by A's wakes: {b1} -> {b2} leaks A's notify volume to B"
    );
    let mut tracker = SeqTracker::default();
    assert_eq!(tracker.observe(b1), 0);
    assert_eq!(
        tracker.observe(b2),
        0,
        "B missed nothing, so B must not be told it did"
    );
}

/// Cell 2 (lag): the receiver falls more than the ring capacity behind; the
/// first frame for A it sees afterwards must show a GAP in A's own sequence,
/// and the client tracker must count it as missed wakes (one catch-up read).
#[tokio::test]
async fn a_lagged_receiver_still_sees_the_gap_in_the_recipients_own_sequence_4125() {
    let a = uid("ai:lag4125");
    let mut rx = subscribe();

    notify_wake(&a, "a-0");
    let before = watermark_for(&mut rx, &a).await;

    // Overrun the ring with wakes for A alone, then publish one more.
    for i in 0..=INBOX_WAKE_BROADCAST_CAPACITY + 8 {
        notify_wake(&a, &format!("a-{i}"));
    }
    let mut lagged = false;
    let after = loop {
        match rx.recv().await {
            Err(RecvError::Lagged(_)) => lagged = true,
            Ok(ev) if ev.recipient_agent_id() == a => break wake_meta_for(&ev).seq_high_watermark,
            Ok(_) => {}
            Err(RecvError::Closed) => panic!("bus closed"),
        }
    };
    assert!(
        lagged,
        "the receiver must have lagged for this cell to mean anything"
    );
    assert!(
        after > before.saturating_add(1),
        "a lagged receiver saw CONTIGUOUS watermarks {before} -> {after} across a real drop; \
         the per-recipient number must be assigned at publish time, not in the consumer"
    );
    let mut tracker = SeqTracker::default();
    tracker.observe(before);
    assert!(
        tracker.observe(after) > 0,
        "the client must classify the post-lag wake as a gap (one catch-up read)"
    );
}

/// Cell 1 through the real sqlite notify funnel (`memory_notify` on MCP).
#[tokio::test]
async fn sqlite_notify_to_another_recipient_never_moves_my_watermark_4125() {
    let a = uid("ai:sqa4125");
    let b = uid("ai:sqb4125");
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("wake-4125.db");
    let conn = ai_memory::db::open(&db_path).expect("open");
    let ttl = ai_memory::config::ResolvedTtl::default();
    let notify = |to: &str| {
        ai_memory::mcp::handle_notify(
            &conn,
            &db_path,
            &serde_json::json!({"target_agent_id": to, "title": "t", "payload": "p"}),
            &ttl,
            Some("ai:sender-4125"),
        )
        .expect("notify");
    };
    let mut rx = subscribe();

    notify(&b);
    let b1 = watermark_for(&mut rx, &b).await;
    notify(&a);
    notify(&a);
    notify(&b);
    let b2 = watermark_for(&mut rx, &b).await;
    assert_eq!(
        b2.checked_sub(b1),
        Some(1),
        "sqlite: B's watermark moved by A's notifies: {b1} -> {b2}"
    );
}

/// Cell 1 through the postgres adapter (`PostgresStore::notify`). Skips
/// cleanly when `AI_MEMORY_TEST_POSTGRES_URL` is unset.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_notify_to_another_recipient_never_moves_my_watermark_4125() {
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        return;
    };
    let store = PostgresStore::connect(&url)
        .await
        .expect("connect postgres");
    let ctx = CallerContext::for_agent("ai:pg4125-sender");
    let a = uid("ai:pga4125");
    let b = uid("ai:pgb4125");
    let mut rx = subscribe();

    store
        .notify(&ctx, &b, "t", "p", None, None, None)
        .await
        .expect("pg notify b");
    let b1 = watermark_for(&mut rx, &b).await;
    for _ in 0..2 {
        store
            .notify(&ctx, &a, "t", "p", None, None, None)
            .await
            .expect("pg notify a");
    }
    store
        .notify(&ctx, &b, "t", "p", None, None, None)
        .await
        .expect("pg notify b");
    let b2 = watermark_for(&mut rx, &b).await;
    assert_eq!(
        b2.checked_sub(b1),
        Some(1),
        "postgres: B's watermark moved by A's notifies: {b1} -> {b2}"
    );
}
