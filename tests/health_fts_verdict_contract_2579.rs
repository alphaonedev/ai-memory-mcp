// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#2579](https://github.com/alphaonedev/ai-memory-mcp/issues/2579) —
//! CONTRACT PINS for what `GET /api/v1/health` still guarantees after the
//! per-request FTS5 integrity check was replaced by a paced background check
//! whose cached verdict the endpoint renders.
//!
//! Split out from `tests/health_metrics_constant_cost_2579_2583.rs` on
//! purpose: these cells reference the new surface, and that file must stay
//! compilable at the parent commit to carry its R-203 fail-at-parent evidence.
//!
//! The property under pin is the one #2444/#2445 care about — a cheaper
//! control must not become a control that reports success while doing nothing:
//! a CONFIRMED corruption still takes the node out of rotation, a verdict that
//! stops being refreshed expires on its own, and "not checked yet" is never
//! rendered or treated as a pass.

// ---------------------------------------------------------------------------
// CELL F (contract pin) — what /health STILL guarantees after the change.
// ---------------------------------------------------------------------------

#[test]
fn f_a_failed_deep_verdict_still_takes_the_node_out_of_rotation() {
    use ai_memory::background::fts_integrity::{IntegrityStatus, Verdict};

    let s = IntegrityStatus::new(3_600);
    // No verdict yet: NOT unhealthy. 503-ing here would deadlock a rolling
    // fleet restart before any node had run its first check.
    assert_eq!(s.verdict_at(0), Verdict::Pending);
    assert!(!s.verdict_at(0).is_unhealthy());

    // A corrupt index is still a 503 — the pre-#2579 fail-closed contract,
    // now sourced from the cached verdict instead of a per-probe scan.
    s.record_failure(1_000);
    assert_eq!(s.verdict_at(1_000), Verdict::Failed);
    assert!(s.verdict_at(1_000).is_unhealthy());

    // And it does not decay into silence: an aged-out failure stays a failure.
    assert!(s.verdict_at(1_000 + 3_600 * 1_000).is_unhealthy());
}

#[test]
fn g_a_dead_checker_cannot_re_present_its_last_pass_forever() {
    use ai_memory::background::fts_integrity::{IntegrityStatus, Verdict};

    let s = IntegrityStatus::new(3_600);
    s.record_ok(0);
    assert_eq!(s.verdict_at(3_600), Verdict::Ok);
    assert_eq!(
        s.verdict_at(3_600 * 4),
        Verdict::Stale,
        "an Ok verdict must age out on its own — otherwise a dead checker reports success \
         while doing nothing (#2444)"
    );
}
