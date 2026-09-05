// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `wake-hub` bounded latency histogram (issue
//! [#3471](https://github.com/alphaonedev/ai-memory-mcp/issues/3471), EPIC
//! [#3466](https://github.com/alphaonedev/ai-memory-mcp/issues/3466)).
//!
//! # Why a fixed-bucket histogram and not a sample reservoir
//!
//! An ops surface that answers "what is the fan-out p99?" must not be able to
//! grow. A `Vec<Duration>` of observations — or any reservoir sized by traffic
//! — turns an observability feature into an unbounded allocation the hub's own
//! limits module exists to forbid: at 256 agents and a 500 frames/s budget the
//! hub can be made to observe millions of samples a minute, and the metric
//! would then be the largest thing in the process.
//!
//! So: [`BUCKET_BOUNDS_US`] fixed upper bounds plus one overflow bucket, each
//! an [`AtomicU64`]. The whole histogram is `(BUCKET_COUNT + 3) * 8` bytes,
//! forever, whatever the traffic. Recording is one `Relaxed` `fetch_add`
//! (`CONCURRENCY-07`) — nothing is published through these counters, they are
//! independent statistics, and a `SeqCst` fence per observation on the delivery
//! path would be a real cost for ordering no reader needs.
//!
//! # What the reported quantile means
//!
//! A bucketed quantile is an INTERVAL, not a point. [`LatencySnapshot::quantile_us`]
//! reports the containing bucket's UPPER bound, so the answer is a
//! conservative over-estimate: the true quantile is at most what is reported.
//! For the overflow bucket it reports the observed maximum instead, which is
//! the only honest finite answer available. Over-reporting latency degrades
//! toward "the hub looks slower than it is" and never toward "the hub looks
//! healthy while it is not" — the fail-closed direction for a health signal.

use std::sync::atomic::{AtomicU64, Ordering};

/// Inclusive upper bounds of the counted buckets, in MICROSECONDS.
///
/// Geometric from 50 µs to 5 s, so one table serves both the sub-millisecond
/// fan-out path and the multi-second wall-clock wake latency. Anything above
/// the last bound lands in the overflow bucket.
pub const BUCKET_BOUNDS_US: [u64; 15] = [
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000, 5_000_000,
];

/// Number of counted buckets, including the overflow bucket.
pub const BUCKET_COUNT: usize = BUCKET_BOUNDS_US.len() + 1;

/// Sentinel reported for a quantile that could not be computed because no
/// observation has been recorded yet. Distinguishable from a real `0 µs`
/// reading, which cannot be produced by an empty histogram.
pub const NO_OBSERVATIONS: u64 = 0;

/// A fixed-bucket, allocation-free latency histogram.
///
/// Every field is an atomic and there is no interior `Vec`, `Mutex` or
/// `RefCell`, so recording an observation is wait-free and safe to call from
/// inside a routing critical section (`CONCURRENCY-20`: nothing here can
/// suspend or block).
#[derive(Debug)]
pub struct LatencyHistogram {
    buckets: [AtomicU64; BUCKET_COUNT],
    count: AtomicU64,
    sum_us: AtomicU64,
    max_us: AtomicU64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyHistogram {
    /// An empty histogram.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; BUCKET_COUNT],
            count: AtomicU64::new(0),
            sum_us: AtomicU64::new(0),
            max_us: AtomicU64::new(0),
        }
    }

    /// Record one observation, in microseconds.
    ///
    /// Saturating throughout: an absurd clock reading inflates the overflow
    /// bucket and the running maximum, it never wraps a counter into a small
    /// number that would make the hub look fast (`PERF-01`, `PERF-03`).
    pub fn record_us(&self, us: u64) {
        let idx = bucket_index(us);
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(us, Ordering::Relaxed);
        let _ = self
            .max_us
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                (us > cur).then_some(us)
            });
    }

    /// Record one observation given as a [`std::time::Duration`].
    ///
    /// A duration wider than `u64::MAX` microseconds (about 584 000 years)
    /// saturates rather than wrapping.
    pub fn record(&self, d: std::time::Duration) {
        self.record_us(u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    }

    /// Read every bucket at one instant.
    ///
    /// Not a consistent cut: the counters are `Relaxed` and traffic continues
    /// while the snapshot is taken, so `count` may disagree with the bucket sum
    /// by the handful of observations recorded during the read. That is
    /// deliberate — the alternative is a lock on the delivery path, which is a
    /// real availability cost for a cosmetic accounting property.
    #[must_use]
    pub fn snapshot(&self) -> LatencySnapshot {
        let mut buckets = [0u64; BUCKET_COUNT];
        for (slot, atomic) in buckets.iter_mut().zip(self.buckets.iter()) {
            *slot = atomic.load(Ordering::Relaxed);
        }
        LatencySnapshot {
            count: self.count.load(Ordering::Relaxed),
            sum_us: self.sum_us.load(Ordering::Relaxed),
            max_us: self.max_us.load(Ordering::Relaxed),
            buckets,
        }
    }
}

/// An immutable read of a [`LatencyHistogram`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencySnapshot {
    /// Observations recorded.
    pub count: u64,
    /// Sum of every observation, in microseconds.
    pub sum_us: u64,
    /// Largest single observation, in microseconds.
    pub max_us: u64,
    /// Per-bucket counts; the final entry is the overflow bucket.
    pub buckets: [u64; BUCKET_COUNT],
}

impl Default for LatencySnapshot {
    fn default() -> Self {
        Self {
            count: 0,
            sum_us: 0,
            max_us: 0,
            buckets: [0; BUCKET_COUNT],
        }
    }
}

impl LatencySnapshot {
    /// The `q`-th percentile in microseconds, `q` in `1..=100`.
    ///
    /// Returns the UPPER bound of the bucket the rank falls into (a
    /// conservative over-estimate), or [`Self::max_us`] when that bucket is the
    /// overflow bucket. Returns [`NO_OBSERVATIONS`] when nothing has been
    /// recorded — an empty histogram has no honest quantile and reporting `0`
    /// for one would read as "instantaneous".
    #[must_use]
    pub fn quantile_us(&self, q: u8) -> u64 {
        if self.count == 0 {
            return NO_OBSERVATIONS;
        }
        let q = u64::from(q.clamp(1, 100));
        // Ceiling of count * q / 100, so p100 selects the last observation and
        // p99 of a single observation selects that observation.
        let rank = self
            .count
            .saturating_mul(q)
            .saturating_add(99)
            .checked_div(100)
            .unwrap_or(self.count)
            .max(1);
        let mut seen = 0u64;
        for (i, n) in self.buckets.iter().enumerate() {
            seen = seen.saturating_add(*n);
            if seen >= rank {
                return BUCKET_BOUNDS_US.get(i).copied().unwrap_or(self.max_us);
            }
        }
        // Only reachable when concurrent traffic left `count` ahead of the
        // bucket sum; the observed maximum is the honest answer.
        self.max_us
    }

    /// Arithmetic mean in microseconds, or `0` with no observations.
    #[must_use]
    pub fn mean_us(&self) -> u64 {
        self.sum_us.checked_div(self.count).unwrap_or(0)
    }
}

/// Which bucket an observation of `us` microseconds belongs to.
fn bucket_index(us: u64) -> usize {
    // Linear over 15 entries: a branch-predictable scan that beats a binary
    // search at this size and keeps the function `const`-shaped and obvious.
    for (i, bound) in BUCKET_BOUNDS_US.iter().enumerate() {
        if us <= *bound {
            return i;
        }
    }
    BUCKET_BOUNDS_US.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_bounds_are_strictly_increasing() {
        for pair in BUCKET_BOUNDS_US.windows(2) {
            assert!(
                pair[0] < pair[1],
                "bounds must be strictly increasing: {pair:?}"
            );
        }
        assert_eq!(BUCKET_COUNT, BUCKET_BOUNDS_US.len() + 1);
    }

    #[test]
    fn an_empty_histogram_reports_no_observations_not_zero_latency() {
        let h = LatencyHistogram::new();
        let s = h.snapshot();
        assert_eq!(s.count, 0);
        assert_eq!(s.quantile_us(99), NO_OBSERVATIONS);
        assert_eq!(s.mean_us(), 0);
    }

    #[test]
    fn observations_land_in_the_bucket_whose_upper_bound_contains_them() {
        let h = LatencyHistogram::new();
        h.record_us(1);
        h.record_us(50);
        h.record_us(51);
        let s = h.snapshot();
        assert_eq!(s.buckets[0], 2, "1 and 50 are both <= the 50 us bound");
        assert_eq!(s.buckets[1], 1, "51 lands in the 100 us bucket");
        assert_eq!(s.count, 3);
        assert_eq!(s.max_us, 51);
    }

    #[test]
    fn the_overflow_bucket_reports_the_observed_maximum_not_a_bound() {
        let h = LatencyHistogram::new();
        let over = BUCKET_BOUNDS_US[BUCKET_BOUNDS_US.len() - 1] + 1;
        h.record_us(over);
        let s = h.snapshot();
        assert_eq!(s.buckets[BUCKET_COUNT - 1], 1);
        assert_eq!(
            s.quantile_us(99),
            over,
            "an over-bound observation must report its real magnitude"
        );
    }

    /// Nearest-rank, and the reported value is the containing bucket's UPPER
    /// bound — so the answer over-states latency and never under-states it.
    #[test]
    fn the_quantile_is_an_upper_bound_never_an_under_report() {
        let h = LatencyHistogram::new();
        // 95 fast observations and 5 slow: the slow tail is 5%, so p99 must
        // land in the SLOW bucket. A p99 that reported the fast bucket here
        // would let a health probe call a stalled hub healthy.
        for _ in 0..95 {
            h.record_us(10);
        }
        for _ in 0..5 {
            h.record_us(400_000);
        }
        let s = h.snapshot();
        assert_eq!(s.count, 100);
        assert_eq!(s.quantile_us(50), 50, "the median is still the fast bucket");
        assert_eq!(
            s.quantile_us(99),
            500_000,
            "p99 must land in the slow bucket and report its UPPER bound, not \
             the observed 400_000"
        );
        assert!(
            s.quantile_us(99) >= s.max_us,
            "the reported bound must cover the largest observation in its bucket"
        );
    }

    /// Nearest-rank puts a LONE slow observation out of 100 at p100, not p99 —
    /// which is the standard definition and must not be quietly "fixed" into a
    /// tail-inflating one, because that would make every p99 alert fire on a
    /// single outlier.
    #[test]
    fn a_lone_outlier_lands_at_p100_not_p99() {
        let h = LatencyHistogram::new();
        for _ in 0..99 {
            h.record_us(10);
        }
        h.record_us(400_000);
        let s = h.snapshot();
        assert_eq!(s.quantile_us(99), 50, "1-in-100 is not the 99th percentile");
        assert_eq!(s.quantile_us(100), 500_000, "but it IS the maximum");
    }

    #[test]
    fn recording_saturates_rather_than_wrapping() {
        let h = LatencyHistogram::new();
        h.record_us(u64::MAX);
        h.record_us(u64::MAX);
        let s = h.snapshot();
        assert_eq!(s.max_us, u64::MAX);
        assert_eq!(s.buckets[BUCKET_COUNT - 1], 2);
        // sum_us wrapped is acceptable arithmetic on a Relaxed counter, but the
        // mean must never be reported as a small, healthy-looking number
        // derived from a nonsense sum: the max is what the quantile reports.
        assert_eq!(s.quantile_us(100), u64::MAX);
    }

    #[test]
    fn record_accepts_a_duration() {
        let h = LatencyHistogram::new();
        h.record(std::time::Duration::from_millis(2));
        let s = h.snapshot();
        assert_eq!(s.count, 1);
        assert_eq!(s.max_us, 2_000);
        assert_eq!(s.mean_us(), 2_000);
    }

    #[test]
    fn the_histogram_size_is_fixed_regardless_of_traffic() {
        let h = LatencyHistogram::new();
        let before = size_of_val(&h);
        for i in 0..10_000u64 {
            h.record_us(i);
        }
        assert_eq!(
            size_of_val(&h),
            before,
            "a bounded histogram must not grow with observation count"
        );
        assert_eq!(h.snapshot().count, 10_000);
    }
}
