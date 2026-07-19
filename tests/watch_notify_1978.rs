// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1978 — hermetic tests for the OPT-IN `fs-notify`-backed L3 watch
//! path (the inotify/FSEvents/ReadDirectoryChangesW event loop that runs
//! ALONGSIDE the std-only poll fallback). The whole file is gated on the
//! `fs-notify` feature so the default build is byte-identical without it.
//!
//! All tests are hermetic: they point the watcher at a `tempfile` temp
//! directory under `.local-runs/` (honouring the project no-`/tmp` HARD
//! RULE), inject a PURE resolver so no real `$HOME` walk happens, and —
//! by returning `Ok(None)` from the injected resolver — never open the
//! recovery DB, so a triggered tick is fully observable without any
//! ambient state.
#![cfg(feature = "fs-notify")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ai_memory::recover::HostKind;
use ai_memory::recover::transcript_paths::ResolveError;
use ai_memory::recover::watcher::{self, WatchConfig, notify_backed_watch};

/// In-tree scratch root honouring the project no-`/tmp` HARD RULE.
fn local_runs_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("watch-notify-1978");
    std::fs::create_dir_all(&root).expect("create .local-runs scratch root");
    root
}

/// A pure resolver that resolves no candidate — the tick runs the change
/// detector, observes `NoCandidate`, and touches ZERO filesystem metadata
/// / DB state, so every triggered tick is fully hermetic. The `Result`
/// wrap is REQUIRED by `notify_backed_watch`'s injected-resolver bound
/// (`Fn(..) -> Result<Option<PathBuf>, ResolveError>`), so the
/// always-`Ok` shape here is deliberate, not a smell.
#[allow(clippy::unnecessary_wraps)]
fn no_candidate(_host: HostKind, _cwd: &Path) -> Result<Option<PathBuf>, ResolveError> {
    Ok(None)
}

fn base_cfg(poll_interval: Duration) -> WatchConfig {
    WatchConfig {
        hosts: vec![HostKind::ClaudeCode],
        poll_interval,
        agent_id: "ai:test:notify".to_string(),
        namespace: Some("test-watch".to_string()),
        limit: watcher::DEFAULT_WATCH_LIMIT,
        dry_run: true,
    }
}

/// A filesystem event inside a watched directory triggers the SAME
/// [`poll_once`] recovery funnel (an additional tick beyond the initial
/// catch-up tick). Uses a huge backstop interval so any tick past the
/// initial one is unambiguously event-driven, not the periodic backstop.
#[test]
fn fs_event_triggers_recovery_tick() {
    let tmp = tempfile::tempdir_in(local_runs_root()).expect("tempdir");
    let watch_path = tmp.path().to_path_buf();

    // 1h backstop → the periodic poll never fires during the test window,
    // so a second tick can only come from the filesystem event.
    let cfg = base_cfg(Duration::from_hours(1));
    let shutdown = Arc::new(AtomicBool::new(false));
    let ticks = Arc::new(AtomicUsize::new(0));

    let db = watch_path.join("unused.db");
    let dirs = vec![watch_path.clone()];
    let cfg_t = cfg.clone();
    let shutdown_t = shutdown.clone();
    let ticks_t = ticks.clone();
    let handle = std::thread::spawn(move || {
        notify_backed_watch(&db, &cfg_t, &shutdown_t, &dirs, no_candidate, |_o| {
            ticks_t.fetch_add(1, Ordering::SeqCst);
        })
    });

    // Wait for the watcher to arm + run its initial catch-up tick.
    let mut initial = 0;
    for _ in 0..200 {
        initial = ticks.load(Ordering::SeqCst);
        if initial >= 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(initial >= 1, "initial catch-up tick did not run");

    // Trigger a filesystem event inside the watched directory.
    std::fs::write(watch_path.join("session.jsonl"), b"{}\n").expect("write transcript");

    // The event should drive at least one additional recovery tick.
    let mut got = false;
    for _ in 0..300 {
        if ticks.load(Ordering::SeqCst) > initial {
            got = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    shutdown.store(true, Ordering::SeqCst);
    let ran = handle.join().expect("watch thread join");

    assert!(
        got,
        "fs event did not trigger an additional recovery tick (stuck at {initial})"
    );
    assert!(
        ran,
        "the notify loop should have run to shutdown (returned true)"
    );
}

/// Init failure (no watchable directory) reports `false` so the caller
/// falls back to the poll loop — capture must never silently stop.
#[test]
fn no_watchable_dir_reports_fallback() {
    let cfg = base_cfg(Duration::from_secs(1));
    let shutdown = Arc::new(AtomicBool::new(false));
    // A path whose parent also does not exist → no watchable target → the
    // notify core cannot arm and MUST return false (fall back to poll).
    let bogus = PathBuf::from("/nonexistent-ai-memory-1978/deeper/none");
    let db = PathBuf::from("unused.db");

    let ran = notify_backed_watch(
        &db,
        &cfg,
        &shutdown,
        std::slice::from_ref(&bogus),
        no_candidate,
        |_o| {},
    );

    assert!(
        !ran,
        "no watchable directory must report false so the caller falls back to the poll loop"
    );
}

/// End-to-end fallback wiring: `run_watch_daemon` with the `fs-notify`
/// feature ON but an EMPTY host set computes zero watch dirs, so the
/// notify core returns false and control falls through to the std-only
/// poll loop. A pre-set shutdown flag proves the fallback loop still
/// honours the same `Arc<AtomicBool>` contract and returns promptly.
/// Empty hosts keep it fully hermetic (no `$HOME` walk, no DB access).
#[test]
fn run_watch_daemon_falls_back_and_honors_preset_shutdown() {
    let cfg = WatchConfig {
        hosts: Vec::new(),
        poll_interval: watcher::clamp_poll_interval(1),
        agent_id: "ai:test:notify".to_string(),
        namespace: None,
        limit: watcher::DEFAULT_WATCH_LIMIT,
        dry_run: true,
    };
    let shutdown = Arc::new(AtomicBool::new(true));
    // Must return promptly via the poll-fallback path (notify sees zero
    // dirs → false → poll loop → pre-set shutdown → immediate return).
    watcher::run_watch_daemon(PathBuf::from("unused.db"), cfg, shutdown);
}
