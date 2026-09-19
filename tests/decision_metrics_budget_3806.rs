// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #3806 W2 — the #3654 `/metrics` budget measurement for the three
//! `[decision]` series, in its OWN process and DETERMINISTICALLY.
//!
//! Split from `tests/decision_seam_metrics_3806.rs` on 2026-09-19 for a
//! reason that matters to the number: that file drives REAL seam calls,
//! whose observed latencies are arbitrary floats, and a float's rendered
//! width varies run to run. Measuring an exposition budget against a
//! body containing one is measuring the clock. Everything here records a
//! FIXED latency, so `added` below is the same integer on every run and
//! on every host — which is the only kind of number a ceiling can be
//! held against.
//!
//! What is measured is the WORST case: all four `CalibrationSeam` values
//! by all five `outcome` values and all six `AbstainReason` values. W2
//! wires two seams, so nothing this deployment can do produces more.

use ai_memory::decision_clients::calibration::CalibrationSeam;
use ai_memory::metrics;

/// The closed `outcome` vocabulary.
const OUTCOMES: [&str; 5] = [
    "decided",
    "fallback",
    "timeout",
    "egress_refused",
    "abstained",
];

/// The closed `reason` vocabulary — `AbstainReason::as_str()`.
const REASONS: [&str; 6] = [
    "no_provider",
    "timeout",
    "egress_refused",
    "unavailable",
    "unusable",
    "unsupported",
];

/// A FIXED observation.
///
/// **Do not replace this with a real timing to make the test "more
/// realistic".** That is the defect this constant exists to prevent, and
/// it already happened once: the first version of this measurement ran
/// against a body carrying two real observed latencies.
///
/// An observed latency is an arbitrary float, and its rendered width in
/// the exposition varies run to run — up to ~20 bytes on the histogram
/// `_sum` line alone. Against the ~50 bytes of headroom this budget has,
/// that is a pin that reds on a slow afternoon and greens on a fast one,
/// and nobody would know which. Worse, the figure it reports is not
/// REPRODUCIBLE: a measurement contaminated by the clock reports a
/// slightly different right-looking number every time, which is harder
/// to catch than a gate that is simply wrong, and easier to trust.
///
/// The VALUE here is irrelevant. Its determinism is the whole point —
/// `added` must be the same integer on every run and every host, because
/// that is the only kind of number a ceiling can be held against.
const FIXED_LATENCY_SECONDS: f64 = 0.042;

/// The `/metrics` cap the HTTP surface reads the body under (#3654):
/// `axum::body::to_bytes(body, 64 * 1024)`. `metrics::render()` IS that
/// body, so the two numbers below are the same quantity — byte length of
/// the Prometheus text exposition — and comparing them is not a
/// coincidence of units.
const METRICS_CAP_BYTES: usize = 64 * 1024;

/// What the WORST case may add to the exposition.
///
/// NOT raised for #3806 W2. The measured worst case grew from 5,663
/// bytes (two series) to the figure this test prints (three series), and
/// it still fits: the existing ceiling holds the line, and the headroom
/// it leaves is a signal rather than a problem. A ceiling widened
/// because a number got close, rather than because it crossed, is how a
/// budget stops meaning anything.
const DECISION_SERIES_BUDGET_BYTES: usize = 8 * 1024;

#[test]
fn the_decision_series_worst_case_fits_the_3654_budget() {
    // PRESENCE self-check: a fresh process has none of the children, so
    // the delta below is the series' whole contribution and not a
    // measurement of whatever ran first.
    let baseline = metrics::render();
    assert!(
        !baseline.contains("ai_memory_decision_"),
        "this test owns its process; a decision series here means it does not"
    );

    let seams = [
        CalibrationSeam::ClassifyKind,
        CalibrationSeam::DetectContradiction,
        CalibrationSeam::SynthesisVerdict,
        CalibrationSeam::ConsolidationMerge,
    ];
    for seam in seams {
        for outcome in OUTCOMES {
            metrics::record_decision(seam.as_str(), outcome, None, FIXED_LATENCY_SECONDS);
        }
        for reason in REASONS {
            metrics::record_decision(
                seam.as_str(),
                "abstained",
                Some(reason),
                FIXED_LATENCY_SECONDS,
            );
        }
    }
    let full = metrics::render();

    // PRESENCE: the worst case really was created, so the size below is
    // a measurement of something rather than of nothing.
    assert!(
        full.contains("ai_memory_decision_latency_seconds")
            && full.contains("ai_memory_decision_outcome_total")
            && full.contains("ai_memory_decision_abstain_total"),
        "all three series must render before their size is asserted"
    );

    let added = full.len() - baseline.len();
    assert!(
        added <= DECISION_SERIES_BUDGET_BYTES,
        "the WORST-CASE decision series added {added} bytes to the exposition, over the \
         {DECISION_SERIES_BUDGET_BYTES}-byte budget. Do NOT widen this to accommodate a \
         label set: the {METRICS_CAP_BYTES}-byte `/metrics` read cap (#3654) is the outer \
         bound and this is the inner one, and a ceiling raised because a number got close \
         stops being a ceiling."
    );
    assert!(
        full.len() < METRICS_CAP_BYTES,
        "this process's whole exposition is {} bytes, at or over the \
         {METRICS_CAP_BYTES}-byte cap (#3654)",
        full.len()
    );
    println!(
        "#3654 measurement (deterministic): baseline {} bytes; WORST-CASE decision series \
         add {added} bytes of {DECISION_SERIES_BUDGET_BYTES} budget ({} spare); total {} of \
         {METRICS_CAP_BYTES}",
        baseline.len(),
        DECISION_SERIES_BUDGET_BYTES - added,
        full.len()
    );
}
