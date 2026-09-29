// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared visibility for advisory failures on both storage backends.

use std::sync::{
    LazyLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::Instant;

const WARN_INTERVAL_SECONDS: u64 = 60;
static START: LazyLock<Instant> = LazyLock::new(Instant::now);
static LAST_WRITE_WARN: AtomicU64 = AtomicU64::new(0);
static LAST_RECALL_WARN: AtomicU64 = AtomicU64::new(0);
static LAST_ROLLUP_WARN: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(super) enum MeteringKind {
    Write,
    Recall,
    Rollup,
}

impl MeteringKind {
    fn label(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Recall => "recall",
            Self::Rollup => "rollup",
        }
    }

    fn last_warn(self) -> &'static AtomicU64 {
        match self {
            Self::Write => &LAST_WRITE_WARN,
            Self::Recall => &LAST_RECALL_WARN,
            Self::Rollup => &LAST_ROLLUP_WARN,
        }
    }
}

// Zero means no warning yet; callers pass elapsed seconds + 1. Relaxed is
// sufficient: this controls only log frequency, never publishes other data.
fn claim_warning(last: &AtomicU64, now: u64) -> bool {
    last.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |previous| {
        (previous == 0 || now.saturating_sub(previous) >= WARN_INTERVAL_SECONDS).then_some(now)
    })
    .is_ok()
}

pub(super) fn note_failure(
    kind: MeteringKind,
    backend: &'static str,
    error: &dyn std::fmt::Display,
) {
    crate::metrics::registry()
        .cost_metering_dropped_total
        .with_label_values(&[kind.label()])
        .inc();
    let now = START.elapsed().as_secs().saturating_add(1);
    if claim_warning(kind.last_warn(), now) {
        tracing::warn!(target: "cost", kind = kind.label(), backend, %error,
            "advisory cost metering incomplete; counters are a lower bound under contention; \
             see ai_memory_cost_metering_dropped_total (warnings limited to one per kind per minute)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_window_reopens_without_sleep() {
        let last = AtomicU64::new(0);
        assert!(claim_warning(&last, 1));
        assert!(!claim_warning(&last, 1));
        assert!(!claim_warning(&last, WARN_INTERVAL_SECONDS));
        assert!(claim_warning(&last, WARN_INTERVAL_SECONDS + 1));
        assert!(!claim_warning(&last, 1));
    }

    #[test]
    fn concurrent_failures_claim_only_one_warning() {
        let last = AtomicU64::new(0);
        let emitted = AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..32 {
                scope.spawn(|| {
                    if claim_warning(&last, 1) {
                        emitted.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(emitted.load(Ordering::Relaxed), 1);
    }
}
