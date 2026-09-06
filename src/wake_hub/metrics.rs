// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `wake-hub` counters, gauges and latency histograms (issues
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467) — the
//! counter substrate — and
//! [#3471](https://github.com/alphaonedev/ai-memory-mcp/issues/3471) — the ops
//! surface built on it).
//!
//! Every refusal path in the hub increments something here, so "the hub is
//! degrading" is observable rather than inferred from a quiet log. #3471 adds
//! the four things an operator actually pages on: WHY a delivery was dropped
//! (a per-cause counter, not one aggregate `overflow`), HOW MUCH is queued and
//! for whom (bytes AND frames, the two independent bounds), WHO is falling
//! behind (the slow-consumer signal that precedes a drop), and HOW LONG the
//! plane is taking (bounded fan-out and wake-latency histograms).
//!
//! # Bounded by construction
//!
//! Nothing here grows. Counters are fixed atomics; the histograms are
//! [`crate::wake_hub::histogram::LatencyHistogram`], a fixed bucket array; the
//! per-recipient queue census is COMPUTED on demand from the routing table
//! rather than retained, so the hub keeps no per-agent metrics map that a
//! churn of agent ids could grow. A metrics subsystem that can be made to
//! allocate without bound is a denial-of-service surface, not observability.
//!
//! All counters are `Relaxed` (`CONCURRENCY-07`): they are independent
//! statistics, nothing is published through them, and `SeqCst` would buy
//! ordering no reader needs.
//!
//! # Stable JSON shape
//!
//! [`MetricsSnapshot::to_json`] is the ONE place the wire names live, so
//! `wake-hub --posture --json`, `wake-hub --health --json` and any future
//! exporter cannot drift into different key spellings for the same counter.
//! Keys are added, never renamed or removed.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::histogram::{LatencyHistogram, LatencySnapshot};

/// Per-recipient queue gauges, computed from the routing table at snapshot
/// time and handed to [`HubMetrics::snapshot_with`].
///
/// Supplied by the caller because the metrics module deliberately owns no
/// reference to the router: a metrics type that could reach into the routing
/// tables would be a second lock-ordering hazard on the delivery path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HubCensus {
    /// Bytes currently reserved in the hub-wide egress budget.
    pub egress_bytes_current: usize,
    /// Recipients holding a live route (i.e. authenticated sessions).
    pub recipients_current: usize,
    /// Bytes queued across every recipient, summed.
    pub queued_bytes_current: usize,
    /// Frames queued across every recipient, summed.
    pub queued_frames_current: usize,
    /// Recipients at or above [`crate::wake_hub::limits::SLOW_CONSUMER_PERCENT`]
    /// of their per-recipient byte cap right now.
    pub slow_consumers_current: usize,
}

/// Snapshot of the hub's counters, gauges and histograms at one instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Connections accepted by the listener.
    pub accepted: u64,
    /// Connections refused by the peer-credential gate.
    pub denied_peer_cred: u64,
    /// Connections refused because the hub was at its connection ceiling.
    pub denied_ceiling: u64,
    /// Handshakes refused by the identity verifier.
    pub denied_hello: u64,
    /// Frames refused as malformed / over-size / a removed payload kind.
    pub denied_malformed: u64,
    /// Frames refused because `from` was not the authenticated identity.
    pub denied_forged_from: u64,
    /// Frames refused by a token bucket.
    pub rate_limited: u64,
    /// Deliveries refused because a queue or the egress budget was full.
    /// The aggregate; [`Self::drop_recipient_queue_full`],
    /// [`Self::drop_global_egress_full`] and [`Self::drop_channel_full`] say
    /// WHICH bound refused.
    pub overflow: u64,
    /// Deliveries refused by the per-recipient BYTE cap (#3471).
    pub drop_recipient_queue_full: u64,
    /// Deliveries refused by the hub-wide egress budget (#3471).
    pub drop_global_egress_full: u64,
    /// Deliveries refused by the per-recipient FRAME-count channel (#3471).
    pub drop_channel_full: u64,
    /// Frames dropped by the writer because the socket write failed or the
    /// frame could not be re-encoded on the way out (#3471).
    pub drop_write_failed: u64,
    /// Frames read from peers.
    pub frames_in: u64,
    /// Frames written to peers.
    pub frames_out: u64,
    /// Wake frames routed (once per source frame, not per recipient).
    pub wakes_routed: u64,
    /// Total per-recipient deliveries produced by those routes.
    pub fanout_deliveries: u64,
    /// Wakes coalesced into an offline agent's pending set.
    pub pending_coalesced: u64,
    /// Wakes dropped because the recipient was offline and unknown.
    pub pending_dropped_unknown: u64,
    /// Sessions displaced by a later hello for the same agent id.
    pub sessions_replaced: u64,
    /// Times a delivery landed on a recipient already at or above the
    /// slow-consumer watermark (#3471). The leading indicator of the drop that
    /// follows, counted BEFORE anything is lost.
    pub slow_consumer_events: u64,
    /// Connections currently established.
    pub connections_current: usize,
    /// Bytes currently reserved in the hub-wide egress budget.
    pub egress_bytes_current: usize,
    /// Recipients holding a live route (#3471).
    pub recipients_current: usize,
    /// Bytes queued across every recipient (#3471).
    pub queued_bytes_current: usize,
    /// Frames queued across every recipient (#3471).
    pub queued_frames_current: usize,
    /// Recipients over the slow-consumer watermark right now (#3471).
    pub slow_consumers_current: usize,
    /// Time from the start of a routed wake to the last per-recipient
    /// hand-off, i.e. what fan-out costs INSIDE the hub (#3471).
    pub fanout_latency: LatencySnapshot,
    /// Time from a wake's MINT stamp (the producer's clock when the hint was
    /// created) to its hand-off to the recipient's writer (#3471).
    pub wake_latency: LatencySnapshot,
}

/// Live counters shared by every hub task.
#[derive(Debug, Default)]
pub struct HubMetrics {
    accepted: AtomicU64,
    denied_peer_cred: AtomicU64,
    denied_ceiling: AtomicU64,
    denied_hello: AtomicU64,
    denied_malformed: AtomicU64,
    denied_forged_from: AtomicU64,
    rate_limited: AtomicU64,
    overflow: AtomicU64,
    drop_recipient_queue_full: AtomicU64,
    drop_global_egress_full: AtomicU64,
    drop_channel_full: AtomicU64,
    drop_write_failed: AtomicU64,
    frames_in: AtomicU64,
    frames_out: AtomicU64,
    wakes_routed: AtomicU64,
    fanout_deliveries: AtomicU64,
    pending_coalesced: AtomicU64,
    pending_dropped_unknown: AtomicU64,
    sessions_replaced: AtomicU64,
    slow_consumer_events: AtomicU64,
    connections_current: AtomicUsize,
    fanout_latency: LatencyHistogram,
    wake_latency: LatencyHistogram,
}

macro_rules! counter {
    ($($name:ident),+ $(,)?) => {
        $(
            /// Increment this counter by one.
            pub fn $name(&self) {
                self.$name.fetch_add(1, Ordering::Relaxed);
            }
        )+
    };
}

impl HubMetrics {
    counter!(
        accepted,
        denied_peer_cred,
        denied_ceiling,
        denied_hello,
        denied_malformed,
        denied_forged_from,
        rate_limited,
        overflow,
        drop_recipient_queue_full,
        drop_global_egress_full,
        drop_channel_full,
        drop_write_failed,
        frames_in,
        frames_out,
        wakes_routed,
        pending_coalesced,
        pending_dropped_unknown,
        sessions_replaced,
        slow_consumer_events,
    );

    /// Add `n` per-recipient deliveries from one routed wake.
    pub fn add_fanout(&self, n: u64) {
        self.fanout_deliveries.fetch_add(n, Ordering::Relaxed);
    }

    /// Add `n` written frames.
    pub fn add_frames_out(&self, n: u64) {
        self.frames_out.fetch_add(n, Ordering::Relaxed);
    }

    /// Record how long one routed wake took to reach every recipient's writer.
    pub fn record_fanout_latency(&self, elapsed: Duration) {
        self.fanout_latency.record(elapsed);
    }

    /// Record the mint-to-delivery latency of one wake from its wire stamp.
    ///
    /// `mint_ts_ms` is the producer's WALL-CLOCK stamp, so this crosses a clock
    /// boundary. It is therefore treated as advisory and fails SAFE in both
    /// directions: a `0` stamp (the frame carried none) records nothing, and a
    /// stamp in the future — a peer whose clock runs ahead — records `0` rather
    /// than an underflowed enormous value. A skewed clock may make the hub look
    /// slower than it is; it can never make it look faster.
    pub fn record_wake_latency_from_mint(&self, mint_ts_ms: u64) {
        if mint_ts_ms == 0 {
            return;
        }
        let Some(now_ms) = unix_epoch_millis() else {
            return;
        };
        let delta_ms = now_ms.saturating_sub(mint_ts_ms);
        self.wake_latency
            .record_us(delta_ms.saturating_mul(MICROS_PER_MILLI));
    }

    /// Record a connection opening.
    pub fn connection_opened(&self) {
        self.connections_current.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection closing. Saturating: an accounting slip must not
    /// wrap the gauge to `usize::MAX`.
    pub fn connection_closed(&self) {
        let _ =
            self.connections_current
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                    Some(cur.saturating_sub(1))
                });
    }

    /// Connections currently established.
    #[must_use]
    pub fn connections_current(&self) -> usize {
        self.connections_current.load(Ordering::Relaxed)
    }

    /// Read every counter, with only the hub-wide egress reservation supplied.
    ///
    /// The per-recipient queue gauges read zero: this entry point exists for
    /// callers that hold the metrics handle but not the routing table. Use
    /// [`Self::snapshot_with`] for the full ops view.
    #[must_use]
    pub fn snapshot(&self, egress_bytes_current: usize) -> MetricsSnapshot {
        self.snapshot_with(HubCensus {
            egress_bytes_current,
            ..HubCensus::default()
        })
    }

    /// Read every counter, gauge and histogram.
    #[must_use]
    pub fn snapshot_with(&self, census: HubCensus) -> MetricsSnapshot {
        MetricsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            denied_peer_cred: self.denied_peer_cred.load(Ordering::Relaxed),
            denied_ceiling: self.denied_ceiling.load(Ordering::Relaxed),
            denied_hello: self.denied_hello.load(Ordering::Relaxed),
            denied_malformed: self.denied_malformed.load(Ordering::Relaxed),
            denied_forged_from: self.denied_forged_from.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            overflow: self.overflow.load(Ordering::Relaxed),
            drop_recipient_queue_full: self.drop_recipient_queue_full.load(Ordering::Relaxed),
            drop_global_egress_full: self.drop_global_egress_full.load(Ordering::Relaxed),
            drop_channel_full: self.drop_channel_full.load(Ordering::Relaxed),
            drop_write_failed: self.drop_write_failed.load(Ordering::Relaxed),
            frames_in: self.frames_in.load(Ordering::Relaxed),
            frames_out: self.frames_out.load(Ordering::Relaxed),
            wakes_routed: self.wakes_routed.load(Ordering::Relaxed),
            fanout_deliveries: self.fanout_deliveries.load(Ordering::Relaxed),
            pending_coalesced: self.pending_coalesced.load(Ordering::Relaxed),
            pending_dropped_unknown: self.pending_dropped_unknown.load(Ordering::Relaxed),
            sessions_replaced: self.sessions_replaced.load(Ordering::Relaxed),
            slow_consumer_events: self.slow_consumer_events.load(Ordering::Relaxed),
            connections_current: self.connections_current.load(Ordering::Relaxed),
            egress_bytes_current: census.egress_bytes_current,
            recipients_current: census.recipients_current,
            queued_bytes_current: census.queued_bytes_current,
            queued_frames_current: census.queued_frames_current,
            slow_consumers_current: census.slow_consumers_current,
            fanout_latency: self.fanout_latency.snapshot(),
            wake_latency: self.wake_latency.snapshot(),
        }
    }
}

/// Milliseconds-to-microseconds factor. Named so the conversion has one
/// definition rather than a bare `1_000` on the latency path.
const MICROS_PER_MILLI: u64 = 1_000;

/// Wall-clock milliseconds since the Unix epoch, or `None` when the clock is
/// before the epoch (which degrades to "record nothing", never to a panic).
fn unix_epoch_millis() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
}

impl MetricsSnapshot {
    /// Render the snapshot in the hub's STABLE JSON shape.
    ///
    /// One definition, read by every ops surface, so a posture report and a
    /// health probe can never name the same counter differently. Latency is
    /// reported in microseconds throughout — one unit, no per-field suffix to
    /// misread — and a quantile with no observations behind it reports `null`
    /// rather than `0`, because "no traffic yet" and "instantaneous" are
    /// different facts and an alert rule must be able to tell them apart.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "connections_current": self.connections_current,
            "connections_accepted_total": self.accepted,
            "recipients_current": self.recipients_current,
            "queue": {
                "queued_bytes_current": self.queued_bytes_current,
                "queued_frames_current": self.queued_frames_current,
                "egress_bytes_current": self.egress_bytes_current,
                "slow_consumers_current": self.slow_consumers_current,
                "slow_consumer_events_total": self.slow_consumer_events,
            },
            "denied": {
                "peer_credential": self.denied_peer_cred,
                "connection_ceiling": self.denied_ceiling,
                "hello": self.denied_hello,
                "malformed": self.denied_malformed,
                "forged_from": self.denied_forged_from,
                "rate_limited": self.rate_limited,
            },
            "drops": {
                "overflow_total": self.overflow,
                "recipient_queue_full": self.drop_recipient_queue_full,
                "global_egress_full": self.drop_global_egress_full,
                "channel_full": self.drop_channel_full,
                "write_failed": self.drop_write_failed,
                "offline_unknown": self.pending_dropped_unknown,
            },
            "traffic": {
                "frames_in_total": self.frames_in,
                "frames_out_total": self.frames_out,
                "wakes_routed_total": self.wakes_routed,
                "fanout_deliveries_total": self.fanout_deliveries,
                "pending_coalesced_total": self.pending_coalesced,
                "sessions_replaced_total": self.sessions_replaced,
            },
            "fanout_latency_us": latency_json(&self.fanout_latency),
            "wake_latency_us": latency_json(&self.wake_latency),
        })
    }
}

/// The stable JSON shape of one latency histogram.
fn latency_json(s: &LatencySnapshot) -> serde_json::Value {
    let quantile = |q: u8| -> serde_json::Value {
        if s.count == 0 {
            serde_json::Value::Null
        } else {
            serde_json::Value::from(s.quantile_us(q))
        }
    };
    serde_json::json!({
        "count": s.count,
        "mean": s.mean_us(),
        "max": s.max_us,
        "p50": quantile(50),
        "p99": quantile(99),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero_and_increment() {
        let m = HubMetrics::default();
        assert_eq!(m.snapshot(0), MetricsSnapshot::default());
        m.accepted();
        m.denied_peer_cred();
        m.add_fanout(64);
        m.connection_opened();
        let s = m.snapshot(17);
        assert_eq!(s.accepted, 1);
        assert_eq!(s.denied_peer_cred, 1);
        assert_eq!(s.fanout_deliveries, 64);
        assert_eq!(s.connections_current, 1);
        assert_eq!(s.egress_bytes_current, 17);
    }

    #[test]
    fn the_connection_gauge_saturates_instead_of_wrapping() {
        let m = HubMetrics::default();
        m.connection_closed();
        assert_eq!(m.connections_current(), 0);
        m.connection_opened();
        m.connection_closed();
        assert_eq!(m.connections_current(), 0);
    }

    #[test]
    fn every_drop_cause_has_its_own_counter() {
        let m = HubMetrics::default();
        m.drop_recipient_queue_full();
        m.drop_global_egress_full();
        m.drop_global_egress_full();
        m.drop_channel_full();
        m.drop_write_failed();
        m.pending_dropped_unknown();
        let s = m.snapshot(0);
        assert_eq!(s.drop_recipient_queue_full, 1);
        assert_eq!(s.drop_global_egress_full, 2);
        assert_eq!(s.drop_channel_full, 1);
        assert_eq!(s.drop_write_failed, 1);
        assert_eq!(s.pending_dropped_unknown, 1);
    }

    #[test]
    fn the_census_gauges_reach_the_snapshot() {
        let m = HubMetrics::default();
        let s = m.snapshot_with(HubCensus {
            egress_bytes_current: 11,
            recipients_current: 3,
            queued_bytes_current: 2_048,
            queued_frames_current: 7,
            slow_consumers_current: 1,
        });
        assert_eq!(s.egress_bytes_current, 11);
        assert_eq!(s.recipients_current, 3);
        assert_eq!(s.queued_bytes_current, 2_048);
        assert_eq!(s.queued_frames_current, 7);
        assert_eq!(s.slow_consumers_current, 1);
    }

    #[test]
    fn a_zero_mint_stamp_records_no_wake_latency() {
        let m = HubMetrics::default();
        m.record_wake_latency_from_mint(0);
        assert_eq!(
            m.snapshot(0).wake_latency.count,
            0,
            "an absent wire stamp must not be recorded as zero latency"
        );
    }

    #[test]
    fn a_future_mint_stamp_records_zero_rather_than_underflowing() {
        let m = HubMetrics::default();
        let far_future = unix_epoch_millis().expect("clock after the epoch") + 60_000;
        m.record_wake_latency_from_mint(far_future);
        let s = m.snapshot(0);
        assert_eq!(s.wake_latency.count, 1);
        assert_eq!(
            s.wake_latency.max_us, 0,
            "a peer whose clock runs ahead must never produce a huge latency"
        );
    }

    #[test]
    fn a_past_mint_stamp_records_a_positive_latency() {
        let m = HubMetrics::default();
        let a_second_ago = unix_epoch_millis().expect("clock after the epoch") - 1_000;
        m.record_wake_latency_from_mint(a_second_ago);
        let s = m.snapshot(0);
        assert_eq!(s.wake_latency.count, 1);
        assert!(
            s.wake_latency.max_us >= 1_000_000,
            "a one-second-old mint must record at least one second, got {}",
            s.wake_latency.max_us
        );
    }

    #[test]
    fn fanout_latency_is_recorded_in_microseconds() {
        let m = HubMetrics::default();
        m.record_fanout_latency(Duration::from_micros(320));
        let s = m.snapshot(0);
        assert_eq!(s.fanout_latency.count, 1);
        assert_eq!(s.fanout_latency.max_us, 320);
        assert_eq!(s.fanout_latency.quantile_us(99), 500, "the 500 us bucket");
    }

    #[test]
    fn the_json_shape_is_stable_and_nests_every_family() {
        let m = HubMetrics::default();
        m.accepted();
        m.overflow();
        m.drop_channel_full();
        m.connection_opened();
        let doc = m
            .snapshot_with(HubCensus {
                egress_bytes_current: 5,
                recipients_current: 1,
                queued_bytes_current: 64,
                queued_frames_current: 2,
                slow_consumers_current: 0,
            })
            .to_json();
        assert_eq!(doc["connections_current"], 1);
        assert_eq!(doc["connections_accepted_total"], 1);
        assert_eq!(doc["recipients_current"], 1);
        assert_eq!(doc["queue"]["queued_bytes_current"], 64);
        assert_eq!(doc["queue"]["queued_frames_current"], 2);
        assert_eq!(doc["queue"]["egress_bytes_current"], 5);
        assert_eq!(doc["drops"]["overflow_total"], 1);
        assert_eq!(doc["drops"]["channel_full"], 1);
        assert_eq!(doc["denied"]["hello"], 0);
        assert_eq!(doc["traffic"]["frames_in_total"], 0);
    }

    #[test]
    fn a_quantile_with_no_observations_is_null_not_zero() {
        let doc = HubMetrics::default().snapshot(0).to_json();
        assert!(
            doc["fanout_latency_us"]["p99"].is_null(),
            "no traffic must not read as instantaneous"
        );
        assert_eq!(doc["fanout_latency_us"]["count"], 0);
        let m = HubMetrics::default();
        m.record_fanout_latency(Duration::from_micros(10));
        assert_eq!(m.snapshot(0).to_json()["fanout_latency_us"]["p99"], 50);
    }
}
