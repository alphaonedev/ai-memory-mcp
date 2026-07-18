// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #1987 — regression guard for the committed `performance/baseline.json`.
//!
//! The CI-job wiring (`.github/workflows/bench.yml` advisory compare +
//! `regenerate-baseline`) reads `performance/baseline.json` through the shipped
//! `ai_memory::bench::load_baseline`. This test pins that the committed file
//! stays loadable (so a hand-edit or a regeneration can't silently break the
//! advisory gate) and that it self-describes its runner class + bootstrap state.

#![allow(clippy::missing_panics_doc)]

use std::path::PathBuf;

fn baseline_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("performance/baseline.json")
}

#[test]
fn committed_baseline_loads_via_the_shipped_loader() {
    let path = baseline_path();
    // The exact loader the `bench --baseline` CI step uses — a superset JSON
    // (self-describing metadata) must still deserialize to the records.
    let records = ai_memory::bench::load_baseline(&path)
        .unwrap_or_else(|e| panic!("load_baseline({}) failed: {e}", path.display()));
    assert!(
        !records.is_empty(),
        "baseline must carry at least one operation record"
    );
    // Every record has a usable p95 for the regression compare.
    for r in &records {
        assert!(
            r.measured_p95_ms >= 0.0,
            "operation {:?}: measured_p95_ms must be non-negative",
            r.operation
        );
    }
}

#[test]
fn committed_baseline_is_self_describing() {
    // The #1987 recipe requires the baseline to pin its runner class +
    // bootstrap state so the advisory step can decide whether to compare.
    let raw = std::fs::read_to_string(baseline_path()).expect("read baseline");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("baseline is valid JSON");
    assert!(
        v.get("runner_class")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "baseline must pin its runner_class"
    );
    assert!(
        v.get("bootstrap")
            .and_then(serde_json::Value::as_bool)
            .is_some(),
        "baseline must carry an explicit bootstrap flag (the advisory CI step keys off it)"
    );
    assert!(
        v.get("generated_at_binary_rev").is_some(),
        "baseline must pin the binary rev it was generated against"
    );
}
