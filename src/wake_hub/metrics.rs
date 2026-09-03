// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `wake-hub` counters (issue
//! [#3467](https://github.com/alphaonedev/ai-memory-mcp/issues/3467)).
//!
//! Every refusal path in the hub increments something here, so "the hub is
//! degrading" is observable rather than inferred from a quiet log. The full
//! metrics/health surface (exposition format, `doctor --posture` check) lands
//! with the ops sub-issue
//! [#3471](https://github.com/alphaonedev/ai-memory-mcp/issues/3471); this is
//! the counter substrate it will read.
//!
//! All counters are `Relaxed` (`CONCURRENCY-07`): they are independent
//! statistics, nothing is published through them, and `SeqCst` would buy
//! ordering no reader needs.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Snapshot of the hub's counters at one instant.
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
    pub overflow: u64,
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
    /// Connections currently established.
    pub connections_current: usize,
    /// Bytes currently reserved in the hub-wide egress budget.
    pub egress_bytes_current: usize,
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
    frames_in: AtomicU64,
    frames_out: AtomicU64,
    wakes_routed: AtomicU64,
    fanout_deliveries: AtomicU64,
    pending_coalesced: AtomicU64,
    pending_dropped_unknown: AtomicU64,
    sessions_replaced: AtomicU64,
    connections_current: AtomicUsize,
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
        frames_in,
        frames_out,
        wakes_routed,
        pending_coalesced,
        pending_dropped_unknown,
        sessions_replaced,
    );

    /// Add `n` per-recipient deliveries from one routed wake.
    pub fn add_fanout(&self, n: u64) {
        self.fanout_deliveries.fetch_add(n, Ordering::Relaxed);
    }

    /// Add `n` written frames.
    pub fn add_frames_out(&self, n: u64) {
        self.frames_out.fetch_add(n, Ordering::Relaxed);
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

    /// Read every counter. `egress_bytes_current` is supplied by the caller,
    /// which owns the budget.
    #[must_use]
    pub fn snapshot(&self, egress_bytes_current: usize) -> MetricsSnapshot {
        MetricsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            denied_peer_cred: self.denied_peer_cred.load(Ordering::Relaxed),
            denied_ceiling: self.denied_ceiling.load(Ordering::Relaxed),
            denied_hello: self.denied_hello.load(Ordering::Relaxed),
            denied_malformed: self.denied_malformed.load(Ordering::Relaxed),
            denied_forged_from: self.denied_forged_from.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            overflow: self.overflow.load(Ordering::Relaxed),
            frames_in: self.frames_in.load(Ordering::Relaxed),
            frames_out: self.frames_out.load(Ordering::Relaxed),
            wakes_routed: self.wakes_routed.load(Ordering::Relaxed),
            fanout_deliveries: self.fanout_deliveries.load(Ordering::Relaxed),
            pending_coalesced: self.pending_coalesced.load(Ordering::Relaxed),
            pending_dropped_unknown: self.pending_dropped_unknown.load(Ordering::Relaxed),
            sessions_replaced: self.sessions_replaced.load(Ordering::Relaxed),
            connections_current: self.connections_current.load(Ordering::Relaxed),
            egress_bytes_current,
        }
    }
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
}
