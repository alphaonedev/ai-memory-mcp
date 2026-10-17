// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// v0.7 I5 (R5) — integration test for the reference
// `transcript-extractor` pre_store hook in
// `tools/transcript-extractor/`.
//
// The reference binary lives in a sibling crate (not part of the
// `ai-memory` cargo package) so this test builds it on the fly via
// `cargo build --manifest-path tools/transcript-extractor/Cargo.toml`
// and then exercises the same stdio contract the production
// executor (`src/hooks/executor.rs::FireEnvelope`) writes.
//
// We also assert the namespace opt-in flag the I5 task added —
// `TranscriptsConfig::auto_extract_for` — so a regression that
// breaks the gate trips this test before the hook ever runs.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use ai_memory::config::{TranscriptNamespaceConfig, TranscriptsConfig};
use serde_json::{Value, json};

/// v1.0.0 #3140 — ceiling on the nested `cargo build` for the sibling crate.
///
/// Generous: on a cold CI runner this compiles a small crate plus its
/// dependencies, and it may first have to wait out the outer cargo's
/// package-cache lock. The point is that a bound EXISTS.
const EXTRACTOR_BUILD_BUDGET: std::time::Duration = std::time::Duration::from_mins(5);

/// v1.0.0 #3140 — ceiling on ONE extractor invocation. The binary reads one
/// envelope from stdin and writes one decision line; a healthy run is
/// milliseconds.
const EXTRACTOR_RUN_BUDGET: std::time::Duration = std::time::Duration::from_mins(1);

/// v1.0.0 #3140 — poll cadence while waiting on a child.
const CHILD_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(25);

/// v1.0.0 #3140 — disambiguates the per-invocation capture files when several
/// test threads run the extractor concurrently.
static RUN_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Build the reference extractor binary and return the absolute
/// path to it.
///
/// Historically each test fn invoked `cargo build` directly. With
/// `--test-threads > 1`, several test threads in the same process
/// raced parallel `cargo build` invocations against a shared
/// `--target-dir`. On macOS that triggered two distinct flakes:
///
/// 1. `Command::spawn()` failed with `ETXTBSY` because one thread
///    was rewriting `target/debug/transcript-extractor` while
///    another tried to exec it.
/// 2. `cargo` itself occasionally bailed when its build-graph
///    lockfile (`.cargo-lock`) was contended, leaving the binary
///    half-linked and `bin.exists()` momentarily false.
///
/// The fix is a process-wide `OnceLock`: the first test thread to
/// reach `extractor_bin()` builds the binary; every other thread
/// blocks on the `OnceLock`, then re-uses the cached `PathBuf`.
/// All subsequent spawns observe a fully-linked, immutable
/// executable.
fn extractor_bin() -> &'static PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(build_extractor_once)
}

fn build_extractor_once() -> PathBuf {
    let manifest_path = std::env::current_dir()
        .expect("cwd")
        .join("tools/transcript-extractor/Cargo.toml");
    assert!(
        manifest_path.exists(),
        "extractor manifest missing at {}",
        manifest_path.display()
    );

    // Build into a dedicated target dir, separate from the main crate's so a
    // parallel `cargo test` against `ai-memory` doesn't race the sibling-crate
    // build cache.
    // #1721 — project-local scratch (no /tmp writes; CLAUDE.md hard rule).
    //
    // v1.0.0 #3140 — this used to be scoped by PID. Cargo already takes an
    // exclusive lock on a target dir, so two concurrent driver processes were
    // never at risk of stomping each other; all the PID suffix bought was a
    // COLD full rebuild per test-runner process, each leaving its own multi-
    // gigabyte tree behind under `.local-runs/`. One shared dir is both
    // correct and an order of magnitude cheaper on disk and time.
    let scratch_root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("transcript-extractor");
    std::fs::create_dir_all(&scratch_root).ok();
    let target_dir = scratch_root.join("ai-memory-transcript-extractor-target");

    // v1.0.0 #3140 — bounded. A nested `cargo build` blocks on the OUTER
    // cargo's package-cache lock, so an unbounded `.status()` here can park
    // the whole test binary indefinitely — indistinguishable from a hang, and
    // charged to the CI job cap.
    let mut child = Command::new("cargo")
        .args([
            "build",
            "--quiet",
            "--manifest-path",
            manifest_path.to_str().expect("utf-8 manifest path"),
            "--target-dir",
            target_dir.to_str().expect("utf-8 target dir"),
        ])
        .spawn()
        .expect("invoke cargo build");
    let deadline = std::time::Instant::now() + EXTRACTOR_BUILD_BUDGET;
    let status = loop {
        match child.try_wait().expect("try_wait on cargo build") {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "`cargo build` for the transcript extractor did not finish within \
                     {EXTRACTOR_BUILD_BUDGET:?} — most likely blocked on the outer cargo's \
                     package-cache lock (#3140)"
                );
            }
            None => std::thread::sleep(CHILD_POLL_INTERVAL),
        }
    };
    assert!(status.success(), "cargo build for extractor failed");

    let bin = target_dir.join("debug").join("transcript-extractor");
    assert!(
        bin.exists(),
        "extractor binary missing at {}",
        bin.display()
    );
    bin
}

/// Pipe `envelope` to the extractor in one-shot mode and return
/// the parsed decision JSON.
fn run_once(bin: &Path, envelope: &Value) -> Value {
    use std::io::Write;
    // v1.0.0 #3140 — stdout/stderr go to FILES, not pipes. `wait_with_output`
    // reads both pipes to EOF with no deadline, so an extractor that never
    // exits (or one that fills a pipe nobody drains) parks the test forever.
    // With files the child can always make progress, which makes `try_wait` a
    // truthful liveness signal and the deadline below real.
    let capture_root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("transcript-extractor");
    std::fs::create_dir_all(&capture_root).ok();
    let stem = capture_root.join(format!(
        "run-{}-{}",
        std::process::id(),
        RUN_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let out_path = stem.with_extension("stdout");
    let err_path = stem.with_extension("stderr");
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(
            std::fs::File::create(&out_path).expect("create stdout capture"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(&err_path).expect("create stderr capture"),
        ))
        .spawn()
        .expect("spawn extractor");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin
            .write_all(envelope.to_string().as_bytes())
            .expect("write envelope");
    }
    // Close stdin so the extractor sees EOF and can exit.
    drop(child.stdin.take());

    let deadline = std::time::Instant::now() + EXTRACTOR_RUN_BUDGET;
    let status = loop {
        match child.try_wait().expect("try_wait on extractor") {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("extractor still running after {EXTRACTOR_RUN_BUDGET:?} (#3140)");
            }
            None => std::thread::sleep(CHILD_POLL_INTERVAL),
        }
    };
    let stdout_bytes = std::fs::read(&out_path).unwrap_or_default();
    let stderr_bytes = std::fs::read(&err_path).unwrap_or_default();
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);
    assert!(
        status.success(),
        "extractor exited non-zero: stderr={}",
        String::from_utf8_lossy(&stderr_bytes)
    );
    let stdout = String::from_utf8(stdout_bytes).expect("utf-8 stdout");
    let line = stdout
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .expect("at least one decision line");
    serde_json::from_str(line).expect("decision parses")
}

// ---------------------------------------------------------------------------
// End-to-end: enabled hook + transcript memory → extracted memories
// ---------------------------------------------------------------------------

/// The R5 acceptance test from the task brief: when the
/// extractor is wired in and a transcript is stored, the extracted
/// memories appear on the resulting decision.
#[test]
fn enabled_hook_extracts_memories_from_transcript() {
    let bin = extractor_bin();

    let content = "User: how does v0.7 hooks chain ordering work?\n\
        Assistant: G5 sorts by priority, ties broken by file order, first deny wins.\n\n\
        User: what's the per-event-class timeout?\n\
        Assistant: G6 lets operators name a timeout per event family in hooks.toml.\n\n\
        User: where does the daemon executor live?\n\
        Assistant: src/hooks/executor.rs houses both ExecExecutor and DaemonExecutor.";

    let envelope = json!({
        "event": "pre_store",
        "payload": {
            "namespace": "transcript/agent",
            "title": "v0.7 hooks Q&A",
            "content": content,
            "metadata": { "kind": "transcript" },
        }
    });

    let decision = run_once(bin, &envelope);
    assert_eq!(decision["action"], "modify");

    let extracted = &decision["delta"]["metadata"]["extracted_memories"];
    assert!(extracted.is_array(), "extracted_memories must be an array");
    let arr = extracted.as_array().unwrap();
    assert!(
        !arr.is_empty(),
        "at least one paragraph should survive the heuristic"
    );
    for entry in arr {
        assert!(entry["title"].is_string());
        assert!(entry["content"].is_string());
        assert!(entry["score"].is_number());
        assert!(entry["span_start"].is_number());
        assert!(entry["span_end"].is_number());
    }
}

/// Non-transcript memory in a non-transcript namespace must NOT
/// trigger extraction, even when the hook is wired in. This
/// guards the substrate from misfiring on every `pre_store` fire.
#[test]
fn non_transcript_memory_returns_allow() {
    let bin = extractor_bin();
    let envelope = json!({
        "event": "pre_store",
        "payload": {
            "namespace": "team/eng",
            "title": "rollback note",
            "content": "Reverted PR #555 because it broke v3 capabilities.",
        }
    });
    let decision = run_once(bin, &envelope);
    assert_eq!(decision["action"], "allow");
}

/// The wrong event class must fall through to `Allow` so the
/// extractor is safe to attach to multiple chains.
#[test]
fn post_store_event_falls_through_to_allow() {
    let bin = extractor_bin();
    let envelope = json!({
        "event": "post_store",
        "payload": {
            "namespace": "transcript/agent",
            "content": "User: x\nAssistant: y\n\nUser: z\nAssistant: w",
        }
    });
    let decision = run_once(bin, &envelope);
    assert_eq!(decision["action"], "allow");
}

// ---------------------------------------------------------------------------
// #7342 - cross-process serialisation of the nested `cargo build`
// ---------------------------------------------------------------------------

/// #7342 - number of concurrent test processes the race test launches.
const CONCURRENT_PROCESSES_7342: usize = 4;

/// #7342 - how long each child polls the binary path after its own build, so a
/// child that finished early keeps checking while the others still build.
const CHILD_POLL_WINDOW_7342: std::time::Duration = std::time::Duration::from_secs(4);

/// #7342 - env marker that turns `concurrent_child_7342` from a no-op into the
/// per-process workload.
const CHILD_MARKER_ENV_7342: &str = "AI_MEMORY_TRANSCRIPT_EXTRACTOR_7342_CHILD";

/// #7342 - the per-process workload. Under a plain `cargo test` run the marker
/// is absent and this is a no-op; the parent test below re-executes this test
/// binary with the marker set, once per child.
#[test]
fn concurrent_child_7342() {
    if std::env::var_os(CHILD_MARKER_ENV_7342).is_none() {
        return;
    }
    let bin = extractor_bin();
    let envelope = json!({
        "event": "post_store",
        "payload": { "namespace": "transcript/agent", "content": "User: x\nAssistant: y" }
    });
    let deadline = std::time::Instant::now() + CHILD_POLL_WINDOW_7342;
    let mut missing = 0_u64;
    while std::time::Instant::now() < deadline {
        if !bin.exists() {
            missing += 1;
        }
    }
    assert_eq!(
        missing,
        0,
        "extractor binary missing at {} on {missing} polls (#7342)",
        bin.display()
    );
    let decision = run_once(bin, &envelope);
    assert_eq!(decision["action"], "allow");
}

/// #7342 - `cargo nextest` runs every test in its OWN process, so the
/// in-process `OnceLock` in `extractor_bin()` serialises nothing: N processes
/// run the nested `cargo build` against one target dir, and cargo re-uplifts
/// `debug/transcript-extractor` (remove, then hardlink) on each build, so a
/// sibling process can see the binary missing or hit ETXTBSY/ENOENT on spawn.
/// This test launches `CONCURRENT_PROCESSES_7342` such processes at once and
/// fails if any of them observed a missing or unspawnable binary.
#[test]
fn concurrent_builds_never_lose_the_uplifted_binary_7342() {
    if std::env::var_os(CHILD_MARKER_ENV_7342).is_some() {
        return;
    }
    let exe = std::env::current_exe().expect("current_exe");
    let capture_root = std::env::current_dir()
        .expect("cwd")
        .join(".local-runs")
        .join("transcript-extractor");
    std::fs::create_dir_all(&capture_root).expect("create capture root");
    let mut children = Vec::new();
    for i in 0..CONCURRENT_PROCESSES_7342 {
        let log_path = capture_root.join(format!("race-7342-{}-{i}.log", std::process::id()));
        let log = std::fs::File::create(&log_path).expect("child log");
        let log_err = log.try_clone().expect("clone child log");
        let child = Command::new(&exe)
            .args([
                "--exact",
                "concurrent_child_7342",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD_MARKER_ENV_7342, "1")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn child test process");
        children.push((child, log_path));
    }
    let mut failures = Vec::new();
    for (mut child, log_path) in children {
        let status = child.wait().expect("wait child");
        let text = std::fs::read_to_string(&log_path).unwrap_or_default();
        if status.success() {
            let _ = std::fs::remove_file(&log_path);
        } else {
            let tail: Vec<&str> = text.lines().rev().take(12).collect();
            failures.push(format!("{status}: {tail:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {CONCURRENT_PROCESSES_7342} processes lost the extractor binary (#7342): {failures:#?}",
        failures.len()
    );
}

// ---------------------------------------------------------------------------
// Opt-in resolver — exercises the config knob the hook chain consults
// before it ever fires the extractor.
// ---------------------------------------------------------------------------

#[test]
fn auto_extract_resolver_gates_namespace_correctly() {
    let mut nss = std::collections::HashMap::new();
    nss.insert(
        "transcript/agent".into(),
        TranscriptNamespaceConfig {
            auto_extract: Some(true),
            ..Default::default()
        },
    );
    nss.insert(
        "team/legal/*".into(),
        TranscriptNamespaceConfig {
            auto_extract: Some(false),
            ..Default::default()
        },
    );
    let cfg = TranscriptsConfig {
        namespaces: Some(nss),
        ..Default::default()
    };

    // Exact match wins.
    assert!(cfg.auto_extract_for("transcript/agent"));
    // Prefix opt-out fires under the `/*` pattern.
    assert!(!cfg.auto_extract_for("team/legal/contracts"));
    // Anything else: default off.
    assert!(!cfg.auto_extract_for("anything/else"));
}

#[test]
fn auto_extract_resolver_default_off_when_no_block() {
    let cfg = TranscriptsConfig::default();
    assert!(!cfg.auto_extract_for("transcript/agent"));
}
