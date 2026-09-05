// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3469 — the CO-HOSTED bridge: `agent_notified` bus → the hub's own
//! router, in one process.
//!
//! # Why the router and not a socket
//!
//! When the hub runs inside the daemon there is no wire between them, so
//! putting one there would mean serialising, framing and re-parsing a frame
//! that never leaves the address space — and, worse, a SECOND injection point
//! into the hub with its own rules. This sink instead hands the encoded frame
//! to [`Router::deliver`], the exact call a hub connection's own `route_wake`
//! makes. A substrate wake therefore obeys the same per-recipient queue depth,
//! the same per-recipient byte cap, the same hub-wide egress budget and the
//! same coalesced offline set as a peer-relayed one, and there is one set of
//! bounds to reason about rather than two.
//!
//! # Legal on the bus pump
//!
//! [`crate::inbox_wake::InboxWakeSink::on_wake`] runs on the bus pump task and
//! must not block (`CONCURRENCY-22`) or hold a lock across an await
//! (`CONCURRENCY-20`). `Router::deliver` takes a shard lock, performs a
//! `try_send` and returns; it has no `.await` at all, and neither does anything
//! else on this path.

use std::sync::Arc;

use bytes::Bytes;

use super::{SinkMetrics, build_substrate_wake, record_refusal};
use crate::inbox_wake::{InboxEvent, InboxWakeSink};
use crate::wake_hub::routing::{Delivery, Router};

/// The one operation a substrate wake needs from the hub.
///
/// A trait rather than a bare [`Router`] so the sink's accounting can be
/// exercised against every [`Delivery`] outcome — including the overflow and
/// unknown-recipient paths, which a live router only reaches under load — while
/// production still injects at exactly one place.
pub trait WakeDelivery: Send + Sync + 'static {
    /// Hand one already-encoded `wake` frame to `recipient`.
    ///
    /// MUST NOT block and MUST NOT `.await`.
    fn deliver_wake(&self, recipient: &str, frame: &Bytes, inbox_row_id: &str) -> Delivery;
}

impl WakeDelivery for Router {
    fn deliver_wake(&self, recipient: &str, frame: &Bytes, inbox_row_id: &str) -> Delivery {
        self.deliver(recipient, frame, inbox_row_id)
    }
}

/// Forwards bus wakes into a co-hosted hub.
#[derive(Clone)]
pub struct InProcessWakeSink {
    delivery: Arc<dyn WakeDelivery>,
    metrics: Arc<SinkMetrics>,
}

impl std::fmt::Debug for InProcessWakeSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessWakeSink")
            .field("metrics", &self.metrics.snapshot())
            .finish_non_exhaustive()
    }
}

impl InProcessWakeSink {
    /// Build a sink over any wake delivery target.
    #[must_use]
    pub fn new(delivery: Arc<dyn WakeDelivery>) -> Self {
        Self {
            delivery,
            metrics: Arc::new(SinkMetrics::default()),
        }
    }

    /// Build a sink over a co-hosted hub's routing table.
    ///
    /// The concrete-typed twin of [`Self::new`], so callers holding an
    /// `Arc<Router>` do not have to spell the trait-object coercion.
    #[must_use]
    pub fn for_router(router: Arc<Router>) -> Self {
        Self::new(router)
    }

    /// This sink's live counters.
    #[must_use]
    pub fn metrics(&self) -> Arc<SinkMetrics> {
        Arc::clone(&self.metrics)
    }
}

impl InboxWakeSink for InProcessWakeSink {
    fn on_wake(&self, event: &InboxEvent) {
        self.metrics.wakes_seen();
        let wake = match build_substrate_wake(event) {
            Ok(wake) => wake,
            Err(refusal) => {
                record_refusal(&self.metrics, event.recipient_agent_id(), &refusal);
                return;
            }
        };
        if wake.shed {
            self.metrics.meta_shed();
        }
        match self
            .delivery
            .deliver_wake(&wake.recipient, &wake.frame, &wake.inbox_row_id)
        {
            Delivery::Delivered => self.metrics.delivered(),
            Delivery::Coalesced => self.metrics.coalesced(),
            Delivery::Overflow => {
                self.metrics.dropped_overflow();
                tracing::warn!(
                    recipient = %wake.recipient,
                    "wake sink: hub queue or egress budget full; hint dropped — the \
                     recipient still finds the row on its backstop poll"
                );
            }
            Delivery::DroppedUnknown => {
                self.metrics.dropped_unknown();
                tracing::debug!(
                    recipient = %wake.recipient,
                    "wake sink: recipient has never authenticated to the hub; nothing to \
                     coalesce onto"
                );
            }
        }
    }

    fn on_lagged(&self, missed: u64) {
        self.metrics.bus_lagged(missed);
        tracing::warn!(
            missed,
            "wake sink: the wake bus dropped frames before this sink saw them; those \
             recipients learn of their mail on the next backstop poll, and the NEXT \
             wake they receive carries a higher seq_high_watermark so they can collapse \
             that wait to one catch-up inbox read"
        );
    }
}

/// Attach a co-hosted hub's router to the process-wide wake bus.
///
/// Returns the sink's counters, or `None` when
/// [`crate::inbox_wake::install_sink`] refused — a sink is already installed,
/// or there is no Tokio runtime on this thread. Refusing (never replacing) is
/// the fail-closed choice: silently swapping the forwarder mid-flight would
/// strand frames in the old one.
///
/// The WRITE PATH IS UNTOUCHED by this call. Publishers only ever `send` on a
/// broadcast channel, so whether a hub is attached cannot affect whether a
/// notify commits.
#[must_use]
pub fn install_in_process(router: Arc<Router>) -> Option<Arc<SinkMetrics>> {
    let sink = InProcessWakeSink::for_router(router);
    let metrics = sink.metrics();
    if crate::inbox_wake::install_sink(Arc::new(sink)) {
        tracing::info!(
            "wake sink: co-hosted wake-hub attached to the agent_notified bus; clients \
             must still poll their inbox at least every {:?}",
            super::BACKSTOP_POLL_MAX
        );
        Some(metrics)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wake_hub::frame::{Frame, Kind, WakeMeta};
    use std::sync::Mutex;

    /// Records what it was handed and answers with a scripted outcome.
    #[derive(Debug)]
    struct ScriptedDelivery {
        outcome: Delivery,
        seen: Mutex<Vec<(String, Bytes, String)>>,
    }

    impl ScriptedDelivery {
        fn new(outcome: Delivery) -> Arc<Self> {
            Arc::new(Self {
                outcome,
                seen: Mutex::new(Vec::new()),
            })
        }

        fn taken(&self) -> Vec<(String, Bytes, String)> {
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl WakeDelivery for ScriptedDelivery {
        fn deliver_wake(&self, recipient: &str, frame: &Bytes, inbox_row_id: &str) -> Delivery {
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((recipient.to_owned(), frame.clone(), inbox_row_id.to_owned()));
            self.outcome
        }
    }

    fn event(recipient: &str) -> InboxEvent {
        InboxEvent::AgentNotified {
            seq: 9,
            recipient_agent_id: recipient.into(),
            correlation_id: "sha256:corr".into(),
            inbox_row_id: "row-9".into(),
            namespace: "_inbox/bob".into(),
            sender_agent_id: "ai:alice".into(),
            content_digest: format!("sha256:{}", "11".repeat(32)),
            notified_at: "2026-09-05T00:00:00Z".into(),
        }
    }

    /// ALLOWED: a bus wake reaches the router as a hub `wake` frame naming the
    /// durable row, stamped with the reserved producer id.
    #[test]
    fn a_bus_wake_reaches_the_router_as_a_wake_frame_3469() {
        let target = ScriptedDelivery::new(Delivery::Delivered);
        let sink = InProcessWakeSink::new(Arc::clone(&target) as Arc<dyn WakeDelivery>);
        sink.on_wake(&event("bob"));

        let taken = target.taken();
        assert_eq!(taken.len(), 1);
        let (recipient, frame, row) = &taken[0];
        assert_eq!(recipient, "bob");
        assert_eq!(row, "row-9", "the coalescing key comes from the metadata");
        let decoded = Frame::decode(frame).expect("decode");
        assert_eq!(decoded.kind, Kind::Wake);
        assert_eq!(decoded.to, "bob");
        assert_eq!(decoded.from, crate::identity::sentinels::WAKE_HUB_PRODUCER);
        let meta = WakeMeta::decode(&decoded.payload).expect("meta");
        assert_eq!(meta.inbox_row_id, "row-9");
        assert_eq!(meta.digest.len(), 32);
        assert_eq!(meta.seq_high_watermark, 9);
        assert_eq!(sink.metrics().snapshot().delivered, 1);
    }

    /// DENIED: an unaddressable recipient never reaches the router at all.
    #[test]
    fn an_unaddressable_recipient_never_reaches_the_router_3469() {
        let target = ScriptedDelivery::new(Delivery::Delivered);
        let sink = InProcessWakeSink::new(Arc::clone(&target) as Arc<dyn WakeDelivery>);
        sink.on_wake(&event("#_inbox/bob"));
        assert!(
            target.taken().is_empty(),
            "a topic must never be routed as an inbox owner"
        );
        let s = sink.metrics().snapshot();
        assert_eq!(s.wakes_seen, 1);
        assert_eq!(s.dropped_unaddressable, 1);
        assert_eq!(s.delivered, 0);
    }

    #[test]
    fn each_delivery_outcome_lands_on_its_own_counter_3469() {
        for (outcome, read) in [
            (Delivery::Delivered, 0usize),
            (Delivery::Coalesced, 1),
            (Delivery::Overflow, 2),
            (Delivery::DroppedUnknown, 3),
        ] {
            let sink = InProcessWakeSink::new(ScriptedDelivery::new(outcome));
            sink.on_wake(&event("bob"));
            let s = sink.metrics().snapshot();
            let counts = [
                s.delivered,
                s.coalesced,
                s.dropped_overflow,
                s.dropped_unknown,
            ];
            assert_eq!(counts[read], 1, "outcome {outcome:?} miscounted: {s:?}");
            assert_eq!(counts.iter().sum::<u64>(), 1);
        }
    }

    #[test]
    fn bus_lag_is_counted_not_swallowed_3469() {
        let sink = InProcessWakeSink::new(ScriptedDelivery::new(Delivery::Delivered));
        sink.on_lagged(5);
        sink.on_lagged(2);
        assert_eq!(sink.metrics().snapshot().bus_lagged, 7);
    }

    #[test]
    fn debug_renders_counters_not_the_delivery_target_3469() {
        let sink = InProcessWakeSink::new(ScriptedDelivery::new(Delivery::Delivered));
        let rendered = format!("{sink:?}");
        assert!(rendered.contains("InProcessWakeSink"), "{rendered}");
        assert!(!rendered.contains("ScriptedDelivery"), "{rendered}");
    }
}
