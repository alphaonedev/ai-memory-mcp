// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3465 — the in-process agent WAKE bus for `memory_notify`.
//!
//! # The defect this closes
//!
//! `memory_notify` wrote a durable inbox row on every surface and
//! dispatched NOTHING: no subscription event, no push. A recipient had
//! no way to learn it had mail except to poll `memory_inbox` (the
//! current fleet polls every three minutes, spawning a CLI process per
//! poll). The certified daemon already owned the right primitive —
//! `GET /api/v1/approvals/stream` over a process-wide
//! [`tokio::sync::broadcast`] channel — but nothing analogous existed
//! for the inbox.
//!
//! # What this module is
//!
//! A process-wide broadcast channel carrying one frame per committed
//! notify, plus a fire-and-forget [`InboxWakeSink`] seam so an
//! out-of-process consumer (the `ai-memory wake-hub` of #3467/#3469)
//! can attach WITHOUT touching the write path. Publishers call
//! [`crate::write_events::agent_notified`] (or its wake-only sibling);
//! consumers call [`subscribe`] or install a sink.
//!
//! # Deliberately NOT the webhook lane
//!
//! Wakes are NOT sourced from [`crate::subscriptions`]. That lane is
//! operator egress: a 32-permit global semaphore, a 26.2 s worst-case
//! delivery, and a 1000-row subscription-scan cliff on the postgres
//! prefix scan. Sourcing an agent's latency-critical wake from it
//! would make one slow operator webhook the recipient's wake latency.
//! The `agent_notified` event still fires on the webhook lane for
//! operator subscribers — the two lanes are fed from the same emitter
//! and are independent of one another.
//!
//! # Never the body
//!
//! A wake frame carries a CONTENT DIGEST, never the notification body.
//! The bus is process-wide and un-partitioned, so the frame must stay
//! safe to hold in memory next to every other tenant's frames; the
//! recipient reads the body back from its own inbox, through the
//! existing owner-bound `memory_inbox` / `GET /api/v1/inbox` gate.
//!
//! # Degrade, never corrupt
//!
//! Publishing is best-effort and infallible: the durable row is
//! already committed when a wake fires, so a full ring, a lagging
//! subscriber or a missing runtime must never turn a committed notify
//! into a reported failure. A subscriber that falls behind sees
//! [`tokio::sync::broadcast::error::RecvError::Lagged`]; the SSE
//! handler turns that into a synthetic `lagged` frame and the client
//! re-syncs with a catch-up inbox read. Every frame carries a
//! monotonic [`seq`](InboxEvent::seq) so a consumer can size the gap
//! exactly rather than guess.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Capacity of the process-wide inbox wake channel.
///
/// This is the bounded buffer every consumer shares. Sized to match
/// [`crate::approvals::APPROVAL_BROADCAST_CAPACITY`] so the two
/// in-process push lanes have one tuning story. A consumer slower than
/// 1024 wakes behind the writer is dropped-frames-lagged rather than
/// allowed to grow the queue without bound — bounded buffering is what
/// keeps a stalled wake-hub from turning into daemon memory growth.
pub const INBOX_WAKE_BROADCAST_CAPACITY: usize = 1024;

/// Monotonic wake sequence, assigned at publish time.
///
/// Starts at 1 so `0` is unambiguously "no wake seen yet" for a
/// consumer's high-watermark bookkeeping.
static WAKE_SEQ: AtomicU64 = AtomicU64::new(0);

/// One frame on the inbox wake bus.
///
/// Serialised with an external `event` tag so the SSE wire shape
/// matches [`crate::approvals::ApprovalEvent`] (`{"event":
/// "agent_notified", …}`) and a client can demultiplex both streams
/// with the same parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum InboxEvent {
    /// A notification row was committed to `recipient_agent_id`'s inbox.
    AgentNotified {
        /// Monotonic per-process wake sequence (first wake is 1).
        ///
        /// A consumer that observes a `Lagged` — or that reconnects —
        /// compares this against its own high-watermark (see
        /// [`seq_high_watermark`]) to size the gap exactly, then does one
        /// catch-up inbox read. Sequences are per-process and reset on
        /// restart; they order wakes, they do not identify them.
        seq: u64,
        /// Inbox owner. The ONLY agent this frame may ever be shown to.
        recipient_agent_id: String,
        /// Identifies this wake across lanes and hops (SSE frame, sink
        /// delivery, wake-hub forward). Distinct from
        /// [`Self::AgentNotified::inbox_row_id`], which identifies the
        /// durable row.
        correlation_id: String,
        /// Id of the durable inbox memory the recipient reads back.
        inbox_row_id: String,
        /// Namespace the row landed in (`_messages/<agent>` on the MCP
        /// lane, `_inbox/<agent>` on the SAL lane).
        namespace: String,
        /// Authenticated sender, as resolved by the originating surface.
        sender_agent_id: String,
        /// `sha256:<hex>` over the notification BODY. The body itself is
        /// never placed on this bus.
        content_digest: String,
        /// RFC-3339 instant the wake was published.
        notified_at: String,
    },
}

impl InboxEvent {
    /// The inbox owner this frame belongs to.
    ///
    /// The SSE handler and every sink MUST scope delivery by this value:
    /// a caller only ever receives wakes for its own inbox.
    #[must_use]
    pub fn recipient_agent_id(&self) -> &str {
        match self {
            InboxEvent::AgentNotified {
                recipient_agent_id, ..
            } => recipient_agent_id.as_str(),
        }
    }

    /// Monotonic publish sequence of this frame.
    #[must_use]
    pub fn seq(&self) -> u64 {
        match self {
            InboxEvent::AgentNotified { seq, .. } => *seq,
        }
    }

    /// Canonical event name for the SSE `event:` line — the same slug
    /// the webhook lane uses, so one subscriber vocabulary covers both.
    #[must_use]
    pub fn event_name(&self) -> &'static str {
        match self {
            InboxEvent::AgentNotified { .. } => {
                crate::subscriptions::webhook_events::AGENT_NOTIFIED
            }
        }
    }
}

/// Process-wide broadcast channel for [`InboxEvent`]. Lazily
/// initialised on first publish / subscribe.
static INBOX_WAKE_BUS: OnceLock<broadcast::Sender<InboxEvent>> = OnceLock::new();

fn bus() -> &'static broadcast::Sender<InboxEvent> {
    INBOX_WAKE_BUS.get_or_init(|| {
        let (tx, _rx) = broadcast::channel(INBOX_WAKE_BROADCAST_CAPACITY);
        tx
    })
}

/// Allocate the next monotonic wake sequence.
///
/// `Relaxed` is correct here (CONCURRENCY-07): the counter is an
/// independent monotonic ticker and the value is published to consumers
/// through the broadcast channel, which supplies its own ordering.
fn next_seq() -> u64 {
    WAKE_SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
}

/// Highest wake sequence published by this process (0 = none yet).
///
/// A consumer stores this alongside its last processed frame; after a
/// `Lagged` or a reconnect the difference is the exact number of wakes
/// it must catch up on with one inbox read.
#[must_use]
pub fn seq_high_watermark() -> u64 {
    WAKE_SEQ.load(Ordering::Relaxed)
}

/// Build + publish an `agent_notified` wake.
///
/// Returns the frame that was published so the caller can log or mirror
/// its `correlation_id`. Infallible and best-effort: with no
/// subscribers the send is a documented no-op (`broadcast::Sender::send`
/// returns `Err(SendError(_))` when the receiver count is zero), and a
/// committed notify must never fail because nobody was listening.
///
/// `content_digest` is supplied already-digested by
/// [`crate::write_events`] — this function never sees a body.
pub(crate) fn publish_agent_notified(
    recipient_agent_id: &str,
    correlation_id: &str,
    inbox_row_id: &str,
    namespace: &str,
    sender_agent_id: &str,
    content_digest: &str,
) -> InboxEvent {
    let event = InboxEvent::AgentNotified {
        seq: next_seq(),
        recipient_agent_id: recipient_agent_id.to_string(),
        correlation_id: correlation_id.to_string(),
        inbox_row_id: inbox_row_id.to_string(),
        namespace: namespace.to_string(),
        sender_agent_id: sender_agent_id.to_string(),
        content_digest: content_digest.to_string(),
        notified_at: chrono::Utc::now().to_rfc3339(),
    };
    // No receivers is the documented, expected steady state on a daemon
    // with no attached streams — never an error (ERRORS-19: deliberate,
    // commented discard).
    let _ = bus().send(event.clone());
    event
}

/// Subscribe to the process-wide inbox wake bus.
///
/// The receiver sees every wake published AFTER this call; broadcast
/// channels do not replay history, which is exactly why a consumer
/// re-syncs with an inbox read rather than expecting the bus to be
/// durable. The bus is NOT the record of what was delivered — the
/// durable inbox row is.
#[must_use]
pub fn subscribe() -> broadcast::Receiver<InboxEvent> {
    bus().subscribe()
}

/// Fire-and-forget consumer of inbox wakes.
///
/// Implemented by an out-of-process forwarder (the `ai-memory wake-hub`
/// of #3467/#3469 forwards over a Unix domain socket) so the hub can
/// attach to a running daemon without a single line changing on the
/// notify write path. The default consumer is [`NoopInboxWakeSink`].
///
/// # Contract
///
/// * `on_wake` runs on the bus pump task and MUST NOT block
///   (CONCURRENCY-22) — enqueue and return. A blocking sink stalls the
///   pump and lags every wake behind it.
/// * `on_wake` MUST NOT panic; the pump treats a sink as untrusted and
///   a panic there would take the pump task down.
/// * Delivery is best-effort. The bus buffer is bounded
///   ([`INBOX_WAKE_BROADCAST_CAPACITY`]); a sink slower than the writer
///   loses frames and is told so via [`InboxWakeSink::on_lagged`]
///   rather than being allowed to grow the daemon's memory without
///   bound.
pub trait InboxWakeSink: Send + Sync + 'static {
    /// One wake frame. Fire-and-forget; never blocks, never panics.
    fn on_wake(&self, event: &InboxEvent);

    /// `missed` frames were dropped before the next frame this sink
    /// sees, because the sink fell more than
    /// [`INBOX_WAKE_BROADCAST_CAPACITY`] frames behind.
    ///
    /// The default logs. A forwarding sink should propagate the gap to
    /// its downstream so the recipient does one catch-up inbox read
    /// instead of silently missing mail — a dropped wake must degrade
    /// to "poll once", never to "message lost".
    fn on_lagged(&self, missed: u64) {
        tracing::warn!(
            "inbox wake sink lagged: {missed} wake(s) dropped — downstream should \
             re-sync with a catch-up inbox read"
        );
    }
}

/// The default sink: does nothing.
///
/// A daemon with no wake-hub attached runs with this (conceptually —
/// no pump is spawned at all until [`install_sink`] is called), so the
/// sink seam costs the write path exactly nothing when unused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopInboxWakeSink;

impl InboxWakeSink for NoopInboxWakeSink {
    fn on_wake(&self, _event: &InboxEvent) {}
}

/// Guards [`install_sink`] against a second installation.
static SINK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Attach `sink` to the wake bus for the life of the process.
///
/// Spawns one pump task that owns a [`subscribe`] receiver and forwards
/// each frame to the sink. The WRITE PATH IS UNTOUCHED: publishers only
/// ever `send` on the broadcast channel, so installing (or failing to
/// install) a sink cannot affect whether a notify commits.
///
/// Returns `false` — refusing, never replacing — when:
///
/// * a sink is already installed (fail closed: silently swapping the
///   forwarder mid-flight would strand frames in the old one), or
/// * there is no current Tokio runtime to host the pump.
///
/// Both are logged at `warn`. `true` means the pump is running.
#[must_use]
pub fn install_sink(sink: Arc<dyn InboxWakeSink>) -> bool {
    // Check for a runtime BEFORE claiming the slot, so a caller on a
    // non-async thread does not permanently burn the one installation.
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            "inbox wake sink not installed: no Tokio runtime on this thread — \
             wakes still reach SSE subscribers"
        );
        return false;
    };
    if SINK_INSTALLED.swap(true, Ordering::AcqRel) {
        tracing::warn!("inbox wake sink already installed — refusing to replace it");
        return false;
    }
    let mut rx = subscribe();
    handle.spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => sink.on_wake(&event),
                Err(broadcast::error::RecvError::Lagged(missed)) => sink.on_lagged(missed),
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialises the tests that touch the process-wide
    /// `SINK_INSTALLED` / bus statics.
    static LOCK: Mutex<()> = Mutex::new(());

    fn sample() -> InboxEvent {
        InboxEvent::AgentNotified {
            seq: 7,
            recipient_agent_id: "bob".into(),
            correlation_id: "corr-1".into(),
            inbox_row_id: "row-1".into(),
            namespace: "_messages/bob".into(),
            sender_agent_id: "alice".into(),
            content_digest: "sha256:deadbeef".into(),
            notified_at: "2026-09-02T00:00:00Z".into(),
        }
    }

    #[test]
    fn accessors_and_wire_tag_3465() {
        let ev = sample();
        assert_eq!(ev.recipient_agent_id(), "bob");
        assert_eq!(ev.seq(), 7);
        assert_eq!(ev.event_name(), "agent_notified");
        let v = serde_json::to_value(&ev).expect("serialise");
        assert_eq!(v["event"], "agent_notified");
        assert_eq!(v["inbox_row_id"], "row-1");
        // Round-trips, so a UDS forwarder can rebuild the frame verbatim.
        let back: InboxEvent = serde_json::from_value(v).expect("deserialise");
        assert_eq!(back, ev);
    }

    #[tokio::test]
    async fn publish_reaches_subscribers_with_monotonic_seq_3465() {
        let _g = LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut rx = subscribe();
        let first = publish_agent_notified("bob", "c1", "r1", "_messages/bob", "alice", "sha256:a");
        let second =
            publish_agent_notified("bob", "c2", "r2", "_messages/bob", "alice", "sha256:b");
        assert!(
            second.seq() > first.seq(),
            "wake seq must be monotonic: {} then {}",
            first.seq(),
            second.seq()
        );
        assert!(seq_high_watermark() >= second.seq());
        let got_first = rx.recv().await.expect("first wake");
        let got_second = rx.recv().await.expect("second wake");
        assert_eq!(got_first, first);
        assert_eq!(got_second, second);
    }

    #[test]
    fn publish_with_no_subscribers_is_a_no_op_not_a_failure_3465() {
        let _g = LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // No receiver alive: the send errors internally and is swallowed.
        // The committed notify must not care.
        let ev = publish_agent_notified("bob", "c", "r", "_messages/bob", "alice", "sha256:x");
        assert_eq!(ev.recipient_agent_id(), "bob");
    }

    #[test]
    fn noop_sink_is_the_default_and_does_nothing_3465() {
        let sink = NoopInboxWakeSink;
        sink.on_wake(&sample());
        sink.on_lagged(3);
    }

    #[tokio::test]
    async fn sink_installs_once_then_refuses_replacement_3465() {
        use std::sync::atomic::AtomicUsize;

        struct Counting(Arc<AtomicUsize>);
        impl InboxWakeSink for Counting {
            fn on_wake(&self, _event: &InboxEvent) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let _g = LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hits = Arc::new(AtomicUsize::new(0));
        let first = install_sink(Arc::new(Counting(Arc::clone(&hits))));
        // A second install is REFUSED (never a silent swap), whether or
        // not this test won the race to be the first installer.
        assert!(
            !install_sink(Arc::new(NoopInboxWakeSink)),
            "a second sink installation must be refused, not silently swapped"
        );
        if first {
            // Only assert delivery when this test actually owns the pump.
            publish_agent_notified("bob", "c", "r", "_messages/bob", "alice", "sha256:x");
            for _ in 0..200u32 {
                if hits.load(Ordering::Relaxed) > 0 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            assert!(
                hits.load(Ordering::Relaxed) > 0,
                "the installed sink must receive published wakes"
            );
        }
    }
}
