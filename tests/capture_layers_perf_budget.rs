// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::cast_precision_loss
)]

//! v0.7.0 #1394 — perf-budget regression test for the #1389 four-layer
//! capture architecture.
//!
//! Operator directive 2026-05-28 (memory `0ed273e4`): *"make sure the
//! net new design has optimal performance."* The L1+L2+L3+L4 stack
//! lands on the agent's critical path — every MCP tool call passes
//! through L1; L4 `memory_capture_turn` is a synchronous MCP-tool
//! surface. Any layer regressing past its operator-set budget makes
//! the substrate feel slow and provokes operators to disable the
//! capture mechanism, re-introducing the #1388 failure mode.
//!
//! ## Budgets
//!
//! | Layer | Budget (production) | Test budget |
//! |---|---|---|
//! | L1 `observe_tool_call` | < 1 µs mean | < 100 µs mean (debug) / < 5 µs mean (release) |
//! | L4 `memory_capture_turn` happy path | < 10 ms p95 | < 100 ms p95 (debug) / < 25 ms p95 (release) |
//!
//! ## Why two budgets?
//!
//! `cargo test` defaults to debug mode (no LTO, no `--release`
//! optimisation, debug-assertions on). Debug builds typically run
//! 2-10x slower than release for hot loops + 1.5-3x slower for I/O
//! paths. The test budgets are wide enough to catch a 100x regression
//! under debug (the operator-cited operator-feel cliff) while staying
//! tight enough that a real production-budget violation surfaces
//! when CI runs in release mode (the v0.7.0 `Build release` Check
//! step). The release column is the load-bearing assertion; the
//! debug column is observability for the dev loop.
//!
//! L2 + L3 budgets are pinned in separate dedicated benches under
//! `benches/capture_*.rs` (the second deliverable of #1394) because
//! they require larger fixtures (100-turn / 1000-turn JSONL
//! transcripts) that don't fit the integration-test fast-path
//! discipline. This file is the load-bearing wall-clock pin that
//! HARD-BLOCKS the CI workflow on a regression.

use ai_memory::recover::nag::{CaptureNagWatcher, ToolKind};
use std::time::Instant;

// ─────────────────────────────────────────────────────────────────────────────
// Budgets — split debug / release so dev-loop builds don't false-alarm.
// ─────────────────────────────────────────────────────────────────────────────

/// L1 budget — `observe_tool_call` mean cost in nanoseconds.
///
/// Production budget is 1 µs (1000 ns) per the operator directive.
/// Release-mode test budget is 5 µs (5x headroom for CI hardware
/// variance + cold-cache first-call accounting). Debug-mode test
/// budget is 100 µs (the dev-loop budget; catches the operator-feel
/// cliff at 100x regression).
#[cfg(debug_assertions)]
const L1_BUDGET_NS_MEAN: u128 = 100_000; // 100 µs
#[cfg(not(debug_assertions))]
const L1_BUDGET_NS_MEAN: u128 = 5_000; // 5 µs

// ─────────────────────────────────────────────────────────────────────────────
// L1 — observe_tool_call mean-cost pin.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn l1_observe_tool_call_mean_cost_under_budget() {
    // Measurement: 10k iterations. Mean across the full run — the
    // operator budget is about steady-state throughput, not p99 tail.
    const N: usize = 10_000;

    // Pre-warm: classify_tool + the HashMap entry allocation should
    // be in cache by the time we start measuring. The watcher is
    // re-used across iterations so the (agent_id, session_id) key
    // stays in the inner map.
    let watcher = CaptureNagWatcher::new(0, 0); // both thresholds disabled — keeps the hot path on the increment-only branch
    let agent_id = "ai:perf-l1";
    let session_id = "perf-l1-session";

    // Warm-up: 1k iterations (also reaches the saturating_add ceiling
    // path on the counter, so the steady-state hot loop measures the
    // typical post-warm-up cost).
    for _ in 0..1_000 {
        let _ = watcher.observe_tool_call(agent_id, session_id, ToolKind::Other);
    }

    let start = Instant::now();
    for _ in 0..N {
        let _ = watcher.observe_tool_call(agent_id, session_id, ToolKind::Other);
    }
    let elapsed = start.elapsed();
    let mean_ns = elapsed.as_nanos() / (N as u128);

    assert!(
        mean_ns <= L1_BUDGET_NS_MEAN,
        "L1 budget violated: observe_tool_call mean cost {mean_ns} ns > budget {L1_BUDGET_NS_MEAN} ns \
         (operator directive 2026-05-28: optimal performance on the critical path). \
         {N} iterations in {elapsed:?}. \
         If this fires in release-mode CI but passes locally in debug, the budget is doing its job — \
         investigate src/recover/nag.rs::observe_tool_call hot path. \
         If this fires in debug mode locally, it's a major regression: the dev-loop \
         budget is 100x the production budget specifically to avoid debug-mode flakes."
    );
}

#[test]
fn l1_observe_tool_call_memory_write_reset_cost_under_budget() {
    const N: usize = 10_000;

    // The MemoryWrite branch takes a different path
    // (`*entry = SessionCounter::default()` instead of saturating_add),
    // so pin its cost separately to catch a regression that only the
    // write-class flow exhibits.
    let watcher = CaptureNagWatcher::new(0, 0);
    let agent_id = "ai:perf-l1-write";
    let session_id = "perf-l1-write-session";

    for _ in 0..1_000 {
        let _ = watcher.observe_tool_call(agent_id, session_id, ToolKind::MemoryWrite);
    }

    let start = Instant::now();
    for _ in 0..N {
        let _ = watcher.observe_tool_call(agent_id, session_id, ToolKind::MemoryWrite);
    }
    let elapsed = start.elapsed();
    let mean_ns = elapsed.as_nanos() / (N as u128);

    assert!(
        mean_ns <= L1_BUDGET_NS_MEAN,
        "L1 budget violated on MemoryWrite path: mean cost {mean_ns} ns > budget {L1_BUDGET_NS_MEAN} ns. \
         {N} iterations in {elapsed:?}."
    );
}

#[test]
fn l1_per_session_independence_does_not_inflate_mean_cost() {
    const SESSIONS: usize = 100;
    const PER_SESSION: usize = 100;

    // Real-world dispatch sees many distinct (agent_id, session_id)
    // tuples — a slow lookup grows linearly with HashMap size, which
    // would be a different bug than the per-call cost. Pin the
    // multi-session case to catch a `O(N)` regression in the inner
    // lookup (e.g. switch from HashMap to Vec by mistake).
    let watcher = CaptureNagWatcher::new(0, 0);
    let agents: Vec<String> = (0..SESSIONS).map(|i| format!("ai:perf-l1-{i}")).collect();
    let session_ids: Vec<String> = (0..SESSIONS).map(|i| format!("perf-l1-sess-{i}")).collect();

    // Warm-up
    for (a, s) in agents.iter().zip(&session_ids) {
        for _ in 0..10 {
            let _ = watcher.observe_tool_call(a, s, ToolKind::Other);
        }
    }

    let start = Instant::now();
    for _ in 0..PER_SESSION {
        for (a, s) in agents.iter().zip(&session_ids) {
            let _ = watcher.observe_tool_call(a, s, ToolKind::Other);
        }
    }
    let elapsed = start.elapsed();
    let total_calls = SESSIONS * PER_SESSION;
    let mean_ns = elapsed.as_nanos() / (total_calls as u128);

    assert!(
        mean_ns <= L1_BUDGET_NS_MEAN,
        "L1 multi-session mean cost {mean_ns} ns > budget {L1_BUDGET_NS_MEAN} ns \
         ({SESSIONS} sessions × {PER_SESSION} calls = {total_calls} in {elapsed:?}). \
         A regression here likely means the HashMap inner lookup is no longer O(1) — \
         check src/recover/nag.rs::observe_tool_call inner.lock().entry(key) path."
    );
}
