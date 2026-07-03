// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 task E1 — minimal harness check on the `ai-memory-t0`
//! cross-platform orchestrator binary.
//!
//! Originally `scripts/t0-orchestrate.sh` was a bash script, so this
//! test was gated `#![cfg(unix)]` to keep Windows CI green. The
//! orchestrator now lives in `tools/t0-orchestrate/` as a standalone
//! Rust crate — the Unix gate is gone and the dry-run harness check
//! runs on every platform CI covers.
//!
//! The orchestrator fans the Discovery Gate questions out to four
//! live LLMs (see `docs/v0.7/T0-ORCHESTRATION.md`). Live runs cost
//! API budget and require keys, so CI exercises it in `--dry-run`
//! mode and asserts:
//!
//! 1. `--dry-run` exits 0 without making API calls.
//! 2. The plan output names all four LLMs (claude / gpt5 / gemini / grok).
//! 3. The plan output names every Discovery Gate question id pinned
//!    in `tests/calibration_t0.rs`.
//! 4. The dry-run advertises the result-file template paths.
//!
//! If any of these go red, the orchestration harness has drifted from
//! the calibration cells it wraps — fix the binary (or the cell ids)
//! before merging.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// #1742 — these e2e tests cold-build (`cargo build --release`) and spawn a
/// SEPARATE workspace tool crate (`ai-memory-t0`). Under `cargo llvm-cov`
/// that child build inherits the coverage RUSTFLAGS (3-4× slower) and trips
/// the #1492 hung-test watchdog — while adding ZERO `ai-memory` coverage
/// (the spawned binary is a different crate). So skip the build+spawn under
/// coverage; the tests still run on every normal `Check` job for the e2e
/// assurance. cargo-llvm-cov sets `CARGO_LLVM_COV` in the test environment.
fn skip_under_llvm_cov() -> bool {
    if std::env::var_os("CARGO_LLVM_COV").is_some() {
        eprintln!(
            "#1742: skipping subprocess-tool e2e under llvm-cov (adds no ai-memory \
             coverage; avoids the instrumented cold-build watchdog hang)"
        );
        true
    } else {
        false
    }
}

/// v0.9.0 pre-GA (#1853) — CI hands the test a PREBUILT `ai-memory-t0`
/// binary through this env var so the resource-constrained macOS runner
/// never runs the nested `cargo build --release` inside the test process
/// (that nested build intermittently failed there, false-redding the
/// suite). Unset (every local run) the test falls back to building the
/// tool itself, so the e2e coverage is unchanged.
const PREBUILT_BIN_ENV: &str = "AI_MEMORY_T0_ORCHESTRATOR_BIN";

/// Resolve the orchestrator binary once per `cargo test` run and
/// return the absolute path to it: the CI-prebuilt artifact if
/// [`PREBUILT_BIN_ENV`] names an existing file, else a nested build.
///
/// Historically (when this was a bash script) each test fn invoked
/// `bash scripts/t0-orchestrate.sh` directly. With the Rust port,
/// `--test-threads > 1` would otherwise race parallel `cargo build`
/// invocations against the shared `--target-dir`. A process-wide
/// `OnceLock` lets the first thread to reach `orchestrator_bin()`
/// resolve the binary; every other thread blocks, then re-uses the
/// cached `PathBuf`. Same pattern `tests/g11_auto_link_detector.rs`
/// and `tests/transcript_extractor.rs` use for their sibling crates.
fn orchestrator_bin() -> &'static PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| prebuilt_orchestrator().unwrap_or_else(build_orchestrator_once))
}

/// #1853 — the CI-prebuilt artifact path, if advertised AND present.
/// A set-but-missing path falls back to the nested build (with a stderr
/// note) rather than failing: the env var is a fast-path hint, never a
/// correctness input.
fn prebuilt_orchestrator() -> Option<PathBuf> {
    let bin = PathBuf::from(std::env::var_os(PREBUILT_BIN_ENV)?);
    if bin.is_file() {
        eprintln!(
            "E1 (#1853): using CI-prebuilt orchestrator at {}",
            bin.display()
        );
        Some(bin)
    } else {
        eprintln!(
            "E1 (#1853): {PREBUILT_BIN_ENV} set but {} is not a file — \
             falling back to the nested build",
            bin.display()
        );
        None
    }
}

fn build_orchestrator_once() -> PathBuf {
    let manifest_path = repo_root().join("tools/t0-orchestrate/Cargo.toml");
    assert!(
        manifest_path.exists(),
        "E1: orchestrator manifest missing at {}",
        manifest_path.display()
    );

    // Per-test target dir scoped by PID so two concurrent `cargo
    // test` driver processes (e.g. CI sharding) cannot stomp each
    // other's target/.
    // #1721 — project-local scratch (no /tmp writes; CLAUDE.md hard rule).
    let scratch_root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("e1-orchestration-dry-run");
    std::fs::create_dir_all(&scratch_root).ok();
    let target_dir = scratch_root.join(format!(
        "ai-memory-t0-orchestrate-target-{}",
        std::process::id()
    ));

    // #1853 — one bounded retry: on the resource-constrained macOS CI
    // runner this nested build intermittently failed on transient
    // resource pressure. CI now prefers the prebuilt artifact (see
    // `PREBUILT_BIN_ENV`), so this path is local-dev / fallback only —
    // but keep it robust rather than single-shot.
    let build_once = || {
        Command::new("cargo")
            .args([
                "build",
                "--quiet",
                "--release",
                "--manifest-path",
                manifest_path.to_str().expect("utf-8 manifest path"),
                "--target-dir",
                target_dir.to_str().expect("utf-8 target dir"),
            ])
            .status()
            .expect("invoke cargo build for ai-memory-t0")
    };
    let mut status = build_once();
    if !status.success() {
        eprintln!(
            "E1 (#1853): nested cargo build for ai-memory-t0 failed \
             (status={:?}); retrying once",
            status.code()
        );
        status = build_once();
    }
    assert!(
        status.success(),
        "cargo build for ai-memory-t0 failed twice"
    );

    let bin = target_dir.join("release").join(if cfg!(windows) {
        "ai-memory-t0.exe"
    } else {
        "ai-memory-t0"
    });
    assert!(
        bin.exists(),
        "E1: ai-memory-t0 binary missing at {}",
        bin.display()
    );
    bin
}

fn run_dry_run() -> String {
    let bin = orchestrator_bin();
    let output = Command::new(bin)
        .arg("--dry-run")
        .current_dir(repo_root())
        .output()
        .expect("spawn ai-memory-t0 --dry-run");

    assert!(
        output.status.success(),
        "E1: --dry-run exited non-zero (status={:?})\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("dry-run stdout is UTF-8")
}

#[test]
fn e1_dry_run_exits_clean_and_names_all_four_llms() {
    if skip_under_llvm_cov() {
        return;
    }
    let out = run_dry_run();

    for llm in &["claude", "gpt5", "gemini", "grok"] {
        assert!(
            out.contains(&format!("llm:      {llm}")),
            "E1: dry-run plan missing llm={llm}\nfull output:\n{out}"
        );
    }
}

#[test]
fn e1_dry_run_covers_every_calibration_cell_id() {
    if skip_under_llvm_cov() {
        return;
    }
    let out = run_dry_run();

    // Question ids must match the calibration cells in
    // tests/calibration_t0.rs. If a new cell lands there, add the id
    // to QUESTIONS in tools/t0-orchestrate/src/main.rs and to this list.
    for qid in &[
        "T0-A2-CORE",
        "T0-A2-FULL",
        "T0-A2-GRAPH",
        "T0-A2-NJG",
        "T0-A1-CORE",
        "T0-CONTRACT",
    ] {
        assert!(
            out.contains(qid),
            "E1: dry-run plan missing calibration cell id={qid}\nfull output:\n{out}"
        );
    }
}

#[test]
fn e1_dry_run_advertises_result_file_template() {
    if skip_under_llvm_cov() {
        return;
    }
    let out = run_dry_run();

    assert!(
        out.contains("results_template:"),
        "E1: dry-run missing results_template line\nfull output:\n{out}"
    );
    assert!(
        out.contains("summary_template:"),
        "E1: dry-run missing summary_template line\nfull output:\n{out}"
    );
    // Windows uses '\' as a path separator; the `results: ...` line in
    // dry-run output reproduces the OS-native separator without a
    // trailing separator. Match either form, with or without trailing
    // separator (the prior `results/t0/` form was Linux/macOS only).
    assert!(
        out.contains("results/t0") || out.contains("results\\t0"),
        "E1: dry-run results path should sit under results/t0\nfull output:\n{out}"
    );
}

#[test]
fn e1_dry_run_makes_no_api_calls() {
    // Sanity: dry-run must terminate with the explicit marker so we
    // never confuse a silent abort with a clean dry-run.
    if skip_under_llvm_cov() {
        return;
    }
    let out = run_dry_run();
    assert!(
        out.contains("dry-run complete (no API calls made)"),
        "E1: dry-run did not print completion marker\nfull output:\n{out}"
    );
}
