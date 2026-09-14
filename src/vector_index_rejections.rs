// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3665 — vector-index insert rejections, classified (audit #3645 F19).
//!
//! Every backend (`hnsw` default, `vectorlite` opt-in) refuses an insert
//! at three boundaries: a vector whose dimension disagrees with the index,
//! an empty vector, and an index at capacity in hard-fail mode. Pre-#3665
//! all three emitted `tracing::error!` per item, at the same severity as a
//! backend that cannot load or has degraded. A caller (or a mis-configured
//! embedder) sending malformed vectors is NOT an infrastructure incident —
//! the index did exactly what it should — but it paged like one, and a
//! flood of such items could bury the one ERROR that meant the index was
//! actually lost.
//!
//! The classification:
//!
//! | rejection | class | per-item log | counter cause |
//! |---|---|---|---|
//! | dimension mismatch | invalid input | WARN | `invalid_dim` |
//! | empty vector | invalid input | WARN | `empty_embedding` |
//! | at capacity (hard-fail) | actionable | ERROR | `capacity` |
//!
//! Invalid input still escalates when it is SUSTAINED: once
//! [`INVALID_INPUT_DRIFT_THRESHOLD`] invalid-input rejections land inside
//! one [`INVALID_INPUT_DRIFT_WINDOW_SECS`] window, ONE ERROR names the
//! likely cause — embedder dimension drift (a model swap under a live
//! index), not a caller typo — and the window re-arms. Backend failures
//! (extension load, hard-failure degrade) keep their ERROR and gain a
//! counter of their own so "index lost" is a series, not just a line.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Tracing target for every rejection line.
pub const TRACE_TARGET: &str = "ai_memory::vector_index::rejection";

/// Invalid-input rejections inside one window that count as sustained.
pub const INVALID_INPUT_DRIFT_THRESHOLD: u64 = 10;

/// The drift window, in seconds.
pub const INVALID_INPUT_DRIFT_WINDOW_SECS: u64 = crate::SECS_PER_MINUTE.unsigned_abs();

/// Backend names, for the log line only (never a metric label).
pub const BACKEND_HNSW: &str = "hnsw";
/// See [`BACKEND_HNSW`].
pub const BACKEND_VECTORLITE: &str = "vectorlite";

/// Why an insert was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertRejection {
    /// The vector's dimension disagrees with the index's established one.
    InvalidDim { expected: usize, actual: usize },
    /// A zero-length vector.
    EmptyEmbedding,
    /// The index is at `max_entries` and hard-fail-at-cap is on.
    Capacity { max_entries: usize },
}

/// The operator-facing class of a rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionClass {
    /// The caller's (or embedder's) data was wrong; the index is healthy.
    InvalidInput,
    /// The index cannot accept a VALID vector: an operator has to act.
    Actionable,
}

impl InsertRejection {
    /// Closed metric-label spelling.
    #[must_use]
    pub const fn cause(self) -> &'static str {
        match self {
            Self::InvalidDim { .. } => "invalid_dim",
            Self::EmptyEmbedding => "empty_embedding",
            Self::Capacity { .. } => "capacity",
        }
    }

    /// Every cause, for pre-touching the labelled family at registration.
    pub const ALL_CAUSES: [&'static str; 3] = ["invalid_dim", "empty_embedding", "capacity"];

    /// See [`RejectionClass`].
    #[must_use]
    pub const fn class(self) -> RejectionClass {
        match self {
            Self::InvalidDim { .. } | Self::EmptyEmbedding => RejectionClass::InvalidInput,
            Self::Capacity { .. } => RejectionClass::Actionable,
        }
    }
}

/// What a backend failure was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexFailure {
    /// The opt-in extension could not be loaded / smoke-verified.
    ExtensionLoad,
    /// A live backend hit a hard failure and degraded to the default.
    BackendDegraded,
}

impl IndexFailure {
    /// Closed metric-label spelling.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::ExtensionLoad => "extension_load",
            Self::BackendDegraded => "backend_degraded",
        }
    }

    /// Every kind, for pre-touching the labelled family at registration.
    pub const ALL_KINDS: [&'static str; 2] = ["extension_load", "backend_degraded"];
}

/// Outcome of recording one rejection — what was logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escalation {
    /// Invalid input: one WARN, no page.
    Warned,
    /// Invalid input, and this rejection crossed the sustained threshold:
    /// the WARN plus ONE ERROR for the window.
    DriftEscalated,
    /// Actionable: ERROR, as before.
    Errored,
}

/// The sustained-invalid-input window: `(window_start_secs, count,
/// escalated_this_window)`. An instance type so the window arithmetic is
/// testable on a private window; the process uses [`DRIFT_WINDOW`].
#[derive(Debug)]
pub struct DriftWindow(Mutex<(u64, u64, bool)>);

impl DriftWindow {
    /// A fresh, un-started window.
    #[must_use]
    pub const fn new() -> Self {
        Self(Mutex::new((0, 0, false)))
    }

    /// Advance the window at `now` and say whether THIS rejection is the
    /// one that crosses the threshold (exactly once per window).
    pub fn note(&self, now: u64) -> bool {
        let mut w = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if now.saturating_sub(w.0) >= INVALID_INPUT_DRIFT_WINDOW_SECS {
            *w = (now, 0, false);
        }
        w.1 += 1;
        if w.1 >= INVALID_INPUT_DRIFT_THRESHOLD && !w.2 {
            w.2 = true;
            return true;
        }
        false
    }
}

impl Default for DriftWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// The process-wide window every real rejection advances.
static DRIFT_WINDOW: DriftWindow = DriftWindow::new();

/// Invalid-input rejections since boot (all causes in the class).
static INVALID_INPUT_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Sustained-invalid-input escalations since boot.
static DRIFT_ESCALATIONS_TOTAL: AtomicU64 = AtomicU64::new(0);

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Advance the process window at `now`; count the rejection and, when
/// this one crosses the threshold, the escalation.
fn note_invalid_input_at(now: u64) -> bool {
    INVALID_INPUT_TOTAL.fetch_add(1, Ordering::Relaxed);
    let crossed = DRIFT_WINDOW.note(now);
    if crossed {
        DRIFT_ESCALATIONS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    crossed
}

/// Record one refused insert: counter by cause, and a log line at the
/// class's severity. `memory_id` is the caller's row id (already logged by
/// the pre-#3665 lines; it is not a metric label).
pub fn record_rejection(
    backend: &'static str,
    memory_id: &str,
    rejection: InsertRejection,
) -> Escalation {
    record_rejection_at(unix_now_secs(), backend, memory_id, rejection)
}

/// [`record_rejection`] with the clock injected (testable window).
pub fn record_rejection_at(
    now: u64,
    backend: &'static str,
    memory_id: &str,
    rejection: InsertRejection,
) -> Escalation {
    crate::metrics::registry()
        .vector_index_insert_rejected_total
        .with_label_values(&[rejection.cause()])
        .inc();
    match rejection.class() {
        RejectionClass::InvalidInput => {
            match rejection {
                InsertRejection::InvalidDim { expected, actual } => tracing::warn!(
                    target: TRACE_TARGET,
                    backend,
                    memory_id = %memory_id,
                    cause = rejection.cause(),
                    expected_dim = expected,
                    actual_dim = actual,
                    "vector index rejected an insert: the vector's dimension disagrees with the \
                     index (caller/embedder data, not an index fault; index unchanged, #3665)"
                ),
                _ => tracing::warn!(
                    target: TRACE_TARGET,
                    backend,
                    memory_id = %memory_id,
                    cause = rejection.cause(),
                    "vector index rejected an insert: empty vector (caller/embedder data, not an \
                     index fault; index unchanged, #3665)"
                ),
            }
            if note_invalid_input_at(now) {
                tracing::error!(
                    target: TRACE_TARGET,
                    backend,
                    threshold = INVALID_INPUT_DRIFT_THRESHOLD,
                    window_secs = INVALID_INPUT_DRIFT_WINDOW_SECS,
                    "sustained invalid-vector rejections: {} in {} s — this is the embedder \
                     dimension-drift shape (model swapped under a live index), not a caller \
                     typo; check the configured embedder against the index dimension (#3665)",
                    INVALID_INPUT_DRIFT_THRESHOLD,
                    INVALID_INPUT_DRIFT_WINDOW_SECS,
                );
                Escalation::DriftEscalated
            } else {
                Escalation::Warned
            }
        }
        RejectionClass::Actionable => {
            let InsertRejection::Capacity { max_entries } = rejection else {
                unreachable!("only Capacity is Actionable");
            };
            tracing::error!(
                target: TRACE_TARGET,
                backend,
                memory_id = %memory_id,
                cause = rejection.cause(),
                max_entries,
                "vector index at capacity: rejecting insert (hard-fail-at-cap mode); increase \
                 vector_index_capacity or move to dedicated vector DB (#1005 G2)"
            );
            Escalation::Errored
        }
    }
}

/// Count one backend failure (the ERROR line stays at the call site: it
/// carries backend-specific context this module does not have).
pub fn record_index_failure(failure: IndexFailure) {
    crate::metrics::registry()
        .vector_index_failure_total
        .with_label_values(&[failure.kind()])
        .inc();
}

/// Invalid-input rejections since boot (test / doctor accessor).
#[must_use]
pub fn invalid_input_total() -> u64 {
    INVALID_INPUT_TOTAL.load(Ordering::Relaxed)
}

/// Sustained-invalid-input escalations since boot.
#[must_use]
pub fn drift_escalations_total() -> u64 {
    DRIFT_ESCALATIONS_TOTAL.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::{
        BACKEND_HNSW, DriftWindow, Escalation, INVALID_INPUT_DRIFT_THRESHOLD,
        INVALID_INPUT_DRIFT_WINDOW_SECS, IndexFailure, InsertRejection, RejectionClass,
        invalid_input_total, record_index_failure, record_rejection_at,
    };

    fn rejected(cause: &str) -> u64 {
        crate::metrics::registry()
            .vector_index_insert_rejected_total
            .with_label_values(&[cause])
            .get()
    }

    #[test]
    fn causes_and_classes_are_closed_and_stable_3665() {
        assert_eq!(
            InsertRejection::ALL_CAUSES,
            ["invalid_dim", "empty_embedding", "capacity"]
        );
        assert_eq!(
            IndexFailure::ALL_KINDS,
            ["extension_load", "backend_degraded"]
        );
        assert_eq!(
            InsertRejection::InvalidDim {
                expected: 4,
                actual: 3
            }
            .class(),
            RejectionClass::InvalidInput
        );
        assert_eq!(
            InsertRejection::EmptyEmbedding.class(),
            RejectionClass::InvalidInput
        );
        assert_eq!(
            InsertRejection::Capacity { max_entries: 1 }.class(),
            RejectionClass::Actionable
        );
    }

    #[test]
    fn capacity_is_actionable_and_errored_3665() {
        let before = rejected("capacity");
        let e = record_rejection_at(
            1_000_000,
            BACKEND_HNSW,
            "m-cap",
            InsertRejection::Capacity { max_entries: 3 },
        );
        assert_eq!(e, Escalation::Errored);
        // A global series other tests also drive: at-least, not exact.
        assert!(rejected("capacity") >= before + 1);
    }

    #[test]
    fn invalid_input_is_warned_and_counted_by_cause_3665() {
        let dim_before = rejected("invalid_dim");
        let empty_before = rejected("empty_embedding");
        let total_before = invalid_input_total();
        // One call each: classified as invalid input (Warned or, if this
        // process happens to be mid-burst, DriftEscalated — never Errored).
        let a = record_rejection_at(
            7,
            BACKEND_HNSW,
            "m-dim",
            InsertRejection::InvalidDim {
                expected: 8,
                actual: 4,
            },
        );
        let b = record_rejection_at(7, BACKEND_HNSW, "m-empty", InsertRejection::EmptyEmbedding);
        assert_ne!(a, Escalation::Errored);
        assert_ne!(b, Escalation::Errored);
        assert!(rejected("invalid_dim") >= dim_before + 1);
        assert!(rejected("empty_embedding") >= empty_before + 1);
        assert!(invalid_input_total() >= total_before + 2);
    }

    #[test]
    fn drift_window_escalates_exactly_once_per_window_then_rearms_3665() {
        // A private window: deterministic, no other test can touch it.
        let w = DriftWindow::new();
        let t0 = 5_000_000;
        // Below the threshold nothing crosses.
        for i in 0..(INVALID_INPUT_DRIFT_THRESHOLD - 1) {
            assert!(!w.note(t0 + i), "rejection {i} must not escalate");
        }
        // The threshold crossing escalates exactly once ...
        assert!(w.note(t0 + 20));
        // ... and further rejections inside the same window do not re-page.
        assert!(!w.note(t0 + 30));
        assert!(!w.note(t0 + INVALID_INPUT_DRIFT_WINDOW_SECS - 1));
        // A new window re-arms the escalation.
        let t1 = t0 + INVALID_INPUT_DRIFT_WINDOW_SECS + 1;
        for i in 0..(INVALID_INPUT_DRIFT_THRESHOLD - 1) {
            assert!(!w.note(t1 + i));
        }
        assert!(w.note(t1 + 40));
        // A slow trickle (one per window) never escalates.
        let w2 = DriftWindow::new();
        for k in 0..(INVALID_INPUT_DRIFT_THRESHOLD * 2) {
            assert!(!w2.note(t0 + k * INVALID_INPUT_DRIFT_WINDOW_SECS));
        }
    }

    #[test]
    fn index_failures_are_counted_by_kind_3665() {
        let before = crate::metrics::registry()
            .vector_index_failure_total
            .with_label_values(&["backend_degraded"])
            .get();
        record_index_failure(IndexFailure::BackendDegraded);
        assert!(
            crate::metrics::registry()
                .vector_index_failure_total
                .with_label_values(&["backend_degraded"])
                .get()
                >= before + 1
        );
    }
}
