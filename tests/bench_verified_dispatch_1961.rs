// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1961 (R23/R7) — coverage for the `ai-memory bench --verified` dispatch
//! path in `src/daemon_runtime.rs` (`Command::Bench` → `cmd_bench`, incl. the
//! new verified-path attested ops), driven through the real binary so the
//! CLI seam is exercised (`daemon_runtime` is integration-only per
//! `coverage/policy.md`). The bench workload runs against an in-memory DB, so
//! a 1-iteration run is fast and touches no operator state.

use std::process::Output;

/// Run `ai-memory bench <args...>` with the process env pinned to
/// `AI_MEMORY_NO_CONFIG=1`.
fn run_bench(args: &[&str]) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.arg("bench");
    for a in args {
        cmd.arg(a);
    }
    cmd.env("AI_MEMORY_NO_CONFIG", "1");
    cmd.output().expect("spawn ai-memory bench")
}

#[test]
fn bench_verified_json_emits_verified_ops() {
    // Minimal run: 1 measured iteration, no warmup, JSON output, verified path.
    // NOTE: the process exit code is NOT asserted — a debug/unoptimized bench
    // binary under a loaded test host legitimately exceeds the p95 budgets and
    // bails non-zero. The JSON payload is emitted on stdout BEFORE that budget
    // bail, so it is always parseable; this test exercises the daemon_runtime
    // `cmd_bench` verified-path dispatch, not the latency contract.
    let out = run_bench(&["--iterations", "1", "--warmup", "0", "--verified", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "bench --json parses (e={e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(v["verified"], serde_json::Value::Bool(true), "got: {v}");
    // The verified path appends verified_store + verified_recall ops; assert
    // the results array carries at least one verified-labeled op.
    let results = v["results"].as_array().expect("results array");
    let has_verified = results
        .iter()
        .filter_map(|r| r["operation"].as_str())
        .any(|op| op.starts_with("verified_"));
    assert!(has_verified, "expected a verified_* op in results: {v}");
}

#[test]
fn bench_plain_json_emits_no_verified_ops() {
    // The non-verified path stays exercised too (verified=false). Exit code
    // likewise not asserted (budget-sensitive under debug/loaded CI).
    let out = run_bench(&["--iterations", "1", "--warmup", "0", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("bench --json parses");
    assert_eq!(v["verified"], serde_json::Value::Bool(false), "got: {v}");
    let results = v["results"].as_array().expect("results array");
    let no_verified = results
        .iter()
        .filter_map(|r| r["operation"].as_str())
        .all(|op| !op.starts_with("verified_"));
    assert!(no_verified, "plain bench must not emit verified_* ops: {v}");
}
