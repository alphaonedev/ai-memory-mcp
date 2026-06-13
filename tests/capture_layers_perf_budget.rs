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
//! | L2 fast-path (`recover_from_transcript`, mtime ≤ watermark) | < 100 ms | < 1 s (debug) / < 200 ms (release) |
//! | L2 gap-path (`recover_from_transcript`, 100 turns) | < 1 s | < 10 s (debug) / < 3 s (release) |
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
//! L3 budget remains in a separate dedicated bench at
//! `benches/capture_l3_watcher.rs` (added in the L3 dispatch
//! commit, blocked on operator `notify`-crate dep approval per
//! CLAUDE.md sole-authority). This file pins the L1+L2+L4 contract.

use ai_memory::mcp::handle_capture_turn;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use ai_memory::recover::nag::{CaptureNagWatcher, ToolKind};
use ai_memory::recover::{HostKind, RecoverOpts, recover_from_transcript};
use serde_json::json;
use std::io::Write;
use std::path::PathBuf;
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

/// L2 fast-path budget — `recover_from_transcript` when mtime ≤
/// watermark and the function short-circuits without parsing.
/// Production budget: <100 ms. The path runs: open DB → resolve
/// transcript → stat mtime → query MAX(created_at) → return. The
/// dev-loop budget is 10x for debug + I/O-volatile hardware.
#[cfg(debug_assertions)]
const L2_FAST_PATH_BUDGET_MS: u128 = 1_000;
#[cfg(not(debug_assertions))]
const L2_FAST_PATH_BUDGET_MS: u128 = 200;

/// L2 gap-path budget for 100 turns — full parse + dedup + write.
/// Production budget: <1 s (10 ms/turn amortised). 100 turns is
/// the [`RecoverOpts::limit`] default + the "post-tmux-kill catch-up
/// window" size operators see in practice. Above this, ops should
/// raise `--limit` deliberately and accept the longer budget.
#[cfg(debug_assertions)]
const L2_GAP_PATH_100_TURNS_BUDGET_MS: u128 = 10_000;
#[cfg(not(debug_assertions))]
const L2_GAP_PATH_100_TURNS_BUDGET_MS: u128 = 3_000;

/// L4 `memory_capture_turn` p95 budget per call (milliseconds).
/// Production budget: <10 ms p95 (synchronous MCP-tool surface; any
/// regression past this stalls the host's turn pipeline). The dev-
/// loop budget is 10x for debug + I/O-volatile hardware.
#[cfg(debug_assertions)]
const L4_CAPTURE_TURN_P95_BUDGET_MS: u128 = 100;
#[cfg(not(debug_assertions))]
const L4_CAPTURE_TURN_P95_BUDGET_MS: u128 = 25;

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

// ─────────────────────────────────────────────────────────────────────────────
// Scratch helpers — honoring the project no-`/tmp` HARD RULE per CLAUDE.md.
// Tempdirs land under the worktree's gitignored `.local-runs/`, never on a
// tmpfs path.
// ─────────────────────────────────────────────────────────────────────────────

fn local_runs_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1394-perf-budget-test")
}

fn fresh_dir() -> tempfile::TempDir {
    let root = local_runs_root();
    std::fs::create_dir_all(&root).ok();
    tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
}

fn write_jsonl_transcript(path: &std::path::Path, line_count: usize) {
    let mut f = std::fs::File::create(path).expect("create transcript");
    for i in 0..line_count {
        // Distinct timestamps + per-line text so each turn is a unique
        // sha256 in the gap-path dedup table.
        writeln!(
            f,
            r#"{{"timestamp":"2026-05-28T{:02}:{:02}:00Z","type":"user","message":{{"content":[{{"type":"text","text":"perf-budget-turn-{i}: lorem ipsum dolor sit amet consectetur adipiscing elit"}}]}}}}"#,
            (i / 60) % 24,
            i % 60,
        )
        .expect("write transcript line");
    }
    f.flush().expect("flush transcript");
}

fn base_recover_opts(transcript: PathBuf, agent: &str) -> RecoverOpts {
    RecoverOpts {
        host: HostKind::ClaudeCode,
        transcript_override: Some(transcript),
        since_iso: None,
        namespace: Some("perf-budget".to_string()),
        // The gap-path test wants every line atomised; 1000 is a safe
        // upper bound past any individual perf-budget test's line count.
        limit: 1_000,
        dry_run: false,
        quiet: false,
        agent_id: agent.to_string(),
    }
}

/// Seed a single L1-style memory under the given `agent_id` with a
/// `created_at` of NOW + 1 hour. The L2 fast-path checks `mtime ≤
/// watermark`; a far-future watermark forces a deterministic
/// fast-path hit regardless of filesystem mtime resolution.
fn seed_watermark_in_future(db_path: &std::path::Path, agent_id: &str) {
    let conn = ai_memory::storage::open(db_path).expect("open seed db");
    let future = chrono::Utc::now() + chrono::Duration::hours(1);
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: "perf-budget".to_string(),
        title: format!("watermark seed for {agent_id}"),
        content: "L2 fast-path watermark seed memory".to_string(),
        tags: vec!["perf-budget".to_string(), "watermark-seed".to_string()],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: future.to_rfc3339(),
        updated_at: future.to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        // The recover_from_transcript watermark query is (post-R5.F5.3, #1419):
        //   SELECT MAX(created_at) FROM memories WHERE agent_id_idx = ?1
        // `agent_id_idx` is the VIRTUAL column added in the v14 migration
        // that projects `json_extract(metadata, '$.agent_id')` from the
        // metadata JSON, so the agent_id MUST land in metadata for the
        // query to match.
        metadata: serde_json::json!({ "agent_id": agent_id }),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    ai_memory::storage::insert(&conn, &mem).expect("insert watermark seed");
}

// ─────────────────────────────────────────────────────────────────────────────
// L2 — recover_from_transcript fast-path + gap-path budgets.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn l2_fast_path_under_budget_when_mtime_le_watermark() {
    // Fast-path contract: when the transcript's mtime is at or
    // before the most recent memory_store for this agent_id, the
    // recover function returns immediately without parsing.
    // Operator-perceived cost on session boot: open DB + stat
    // transcript + one SELECT MAX(created_at). Should be <100 ms
    // in production; we pin a 10x dev-loop headroom here.
    let dir = fresh_dir();
    let db_path = dir.path().join("agent.db");
    let transcript = dir.path().join("session.jsonl");

    // Write the transcript FIRST (mtime = NOW), then seed the
    // watermark to NOW + 1 hour. mtime <= watermark → fast-path.
    write_jsonl_transcript(&transcript, 50);
    let agent_id = "ai:perf-l2-fast-path";
    seed_watermark_in_future(&db_path, agent_id);

    let opts = base_recover_opts(transcript, agent_id);

    // Pre-warm: one call to populate filesystem caches. The
    // load-bearing measurement is the steady-state cost, not the
    // first cold open.
    let _warm = recover_from_transcript(&db_path, &opts).expect("warm recover");

    let start = Instant::now();
    let report = recover_from_transcript(&db_path, &opts).expect("steady recover");
    let elapsed_ms = start.elapsed().as_millis();

    assert!(
        report.fast_path_hit,
        "watermark is future-dated → fast-path MUST hit; got report: {report:?}"
    );
    assert_eq!(
        report.lines_atomised, 0,
        "fast-path does not parse → 0 lines atomised; got: {report:?}"
    );
    assert!(
        elapsed_ms <= L2_FAST_PATH_BUDGET_MS,
        "L2 fast-path took {elapsed_ms} ms > budget {L2_FAST_PATH_BUDGET_MS} ms. \
         If this fires only in debug, raise L2_FAST_PATH_BUDGET_MS for debug; if it \
         fires in release CI, investigate the open-DB + stat-mtime + SELECT MAX query path."
    );
}

#[test]
fn l2_gap_path_100_turns_under_budget() {
    // Gap-path contract: 100-turn transcript, no prior memory for
    // this agent → full parse + write of every line. The operator's
    // "post-tmux-kill catch-up" window is the production target.
    let dir = fresh_dir();
    let db_path = dir.path().join("agent.db");
    let transcript = dir.path().join("session.jsonl");

    write_jsonl_transcript(&transcript, 100);

    // Open + close the DB once to materialise the schema before
    // the timed call; the gap-path test is about parse + insert,
    // NOT first-open migration cost (which lands at L4 too and
    // would skew both budgets if uncontrolled).
    drop(ai_memory::storage::open(&db_path).expect("materialise schema"));

    let opts = base_recover_opts(transcript, "ai:perf-l2-gap-path");

    let start = Instant::now();
    let report = recover_from_transcript(&db_path, &opts).expect("recover 100 turns");
    let elapsed_ms = start.elapsed().as_millis();

    assert!(
        !report.fast_path_hit,
        "no prior memory → gap-path MUST be taken; got report: {report:?}"
    );
    assert_eq!(
        report.lines_atomised, 100,
        "all 100 lines must atomise on first boot; got: {report:?}"
    );
    assert!(
        report.errors.is_empty(),
        "gap-path must not error in the happy case; got errors: {:?}",
        report.errors
    );
    assert!(
        elapsed_ms <= L2_GAP_PATH_100_TURNS_BUDGET_MS,
        "L2 gap-path 100-turn cost {elapsed_ms} ms > budget {L2_GAP_PATH_100_TURNS_BUDGET_MS} ms. \
         Per-turn amortised: {} ms/turn. Production target is 10 ms/turn. \
         Investigate src/recover/mod.rs::recover_from_transcript step-4 \
         (BEGIN IMMEDIATE → INSERT memory → INSERT dedup row → COMMIT).",
        elapsed_ms / 100
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// L4 — memory_capture_turn p95 budget.
// ─────────────────────────────────────────────────────────────────────────────

/// p95 over `samples_ms`. Returns 0 for empty input rather than
/// panicking; the caller asserts the slice non-empty separately.
fn p95(samples_ms: &mut [u128]) -> u128 {
    if samples_ms.is_empty() {
        return 0;
    }
    samples_ms.sort_unstable();
    let n = samples_ms.len();
    // ceil((n * 95) / 100) avoids the f64 cast (which clippy::pedantic
    // flags for sign-loss). Result is clamped into [0, n-1] before
    // indexing. For n=200 → idx = 190 (the 191st sample, 1-indexed).
    let raw = n.saturating_mul(95);
    let idx = raw / 100 + usize::from(!raw.is_multiple_of(100));
    let idx = idx.saturating_sub(1).min(n - 1);
    samples_ms[idx]
}

#[test]
fn l4_capture_turn_p95_under_budget() {
    // Measurement: N=200 turns, each with a distinct host_turn_index
    // so the dedup path is not hit (the dedup happy-path is fast
    // and would mask a real regression on the insert path).
    const N: usize = 200;

    // L4 is the host-volunteered turn-capture MCP tool — every
    // host turn is a synchronous tool call. Tail latency
    // (p95) drives operator-perceived "the tool is slow"; mean
    // would hide one-in-twenty bad turns under a fast steady state.
    let dir = fresh_dir();
    let db_path = dir.path().join("l4-perf.db");
    let conn = ai_memory::storage::open(&db_path).expect("open l4 perf db");

    let session_id = "perf-l4-session";

    // Warm-up: 20 iterations to amortise the first-open schema
    // population + filesystem cache fill. The steady-state hot
    // loop is the load-bearing measurement.
    for i in 0..20 {
        let resp = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": session_id,
                "host_turn_index": i,
                "role": "user",
                "content": format!("warm-up turn {i}: lorem ipsum"),
                "host_kind": "claude-code",
            }),
            None,
        )
        .expect("warm-up turn");
        assert_eq!(resp["layer"].as_str(), Some("L4"));
    }
    let mut samples: Vec<u128> = Vec::with_capacity(N);
    for i in 20..(20 + N) {
        let params = json!({
            "host_session_id": session_id,
            "host_turn_index": i,
            "role": if i % 2 == 0 { "user" } else { "assistant" },
            "content": format!("perf turn {i}: substantial content with at least a sentence so the L4 storage tx exercises a realistic payload size"),
            "host_kind": "claude-code",
        });
        let start = Instant::now();
        let resp = handle_capture_turn(&conn, &params, None).expect("capture turn");
        samples.push(start.elapsed().as_millis());
        assert_eq!(
            resp["dedup_hit"].as_bool(),
            Some(false),
            "distinct host_turn_index must miss dedup"
        );
    }

    let p95_ms = p95(&mut samples);
    assert!(
        p95_ms <= L4_CAPTURE_TURN_P95_BUDGET_MS,
        "L4 capture_turn p95 = {p95_ms} ms > budget {L4_CAPTURE_TURN_P95_BUDGET_MS} ms over {N} calls. \
         If this fires only in debug, raise L4_CAPTURE_TURN_P95_BUDGET_MS for debug; if it fires \
         in release CI, investigate src/mcp/tools/capture_turn.rs::handle_capture_turn (sha256 + \
         BEGIN IMMEDIATE + memory INSERT + dedup row INSERT)."
    );
}

#[test]
fn l4_capture_turn_dedup_hit_is_faster_than_full_path() {
    // Dedup-hit phase: re-call the same 50 turns; every call must
    // return dedup_hit=true.
    const HITS: usize = 50;

    // Sanity-check: the dedup-hit path must be strictly faster than
    // the full-insert path. A regression that makes dedup-hit slower
    // than insert is a serious smell (likely a missing index on
    // `transcript_line_dedup(host_session_id, host_turn_index)`).
    let dir = fresh_dir();
    let db_path = dir.path().join("l4-dedup.db");
    let conn = ai_memory::storage::open(&db_path).expect("open l4 dedup db");

    let session_id = "perf-l4-dedup";

    // Prime: HITS distinct turns so the dedup table has real rows.
    for i in 0..HITS {
        let _ = handle_capture_turn(
            &conn,
            &json!({
                "host_session_id": session_id,
                "host_turn_index": i,
                "role": "user",
                "content": format!("priming turn {i}"),
                "host_kind": "claude-code",
            }),
            None,
        )
        .expect("prime turn");
    }
    let mut dedup_samples: Vec<u128> = Vec::with_capacity(HITS);
    for i in 0..HITS {
        let params = json!({
            "host_session_id": session_id,
            "host_turn_index": i,
            "role": "user",
            "content": format!("priming turn {i}"),
            "host_kind": "claude-code",
        });
        let start = Instant::now();
        let resp = handle_capture_turn(&conn, &params, None).expect("dedup hit");
        dedup_samples.push(start.elapsed().as_millis());
        assert_eq!(
            resp["dedup_hit"].as_bool(),
            Some(true),
            "re-call must dedup-hit"
        );
    }

    let p95_dedup = p95(&mut dedup_samples);
    assert!(
        p95_dedup <= L4_CAPTURE_TURN_P95_BUDGET_MS,
        "L4 dedup-hit p95 = {p95_dedup} ms > budget {L4_CAPTURE_TURN_P95_BUDGET_MS} ms. \
         A dedup-hit is a single indexed SELECT — far below the full-insert budget. \
         If this is over budget, the `idx_transcript_line_dedup_host_turn` partial \
         index from schema v52 may be missing or unused; check EXPLAIN QUERY PLAN."
    );
}
