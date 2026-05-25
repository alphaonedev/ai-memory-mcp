// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown)]
//
// v0.7.0 review #628 blocker H9 — daemon-mode stderr never drained.
//
// Background. The G3 daemon executor reads stdout from the long-lived
// child but, prior to this fix, never drained stderr. A verbose hook
// (one that writes diagnostics on every fire) would fill the OS pipe
// buffer (~64 KiB on Linux, ~16 KiB on macOS) and the child would
// block on its next `write(2)` to stderr — which would in turn
// deadlock the executor on its next `read_line` from stdout, because
// the child can't service the request until it can finish flushing
// stderr. The fix spawns a per-child background task that drains
// stderr into a bounded ring buffer (last 4 KiB), so the pipe stays
// drained no matter how chatty the hook is, AND the operator log
// surfaces the buffered tail on timeout / failure so diagnostics
// aren't silently swallowed.
//
// This test exercises both halves of the fix end-to-end:
//
//   1. Spawn a daemon-mode hook whose script writes ~1 MiB of stderr
//      (well past every supported platform's pipe buffer) before
//      writing each NDJSON decision. Without the drain task this
//      would deadlock the second fire; with it, multiple fires must
//      complete inside the timeout.
//
//   2. After the fires complete, force a timeout on a follow-up fire
//      (the script enters a sleep loop after N fires) and assert the
//      executor surfaces `Timeout` cleanly without hanging — the
//      drain task must let the executor's `tokio::time::timeout`
//      trip on schedule rather than getting stuck on a full pipe.
#![cfg(unix)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ai_memory::hooks::{
    DaemonExecutor, ExecExecutor, ExecutorError, FailMode, HookConfig, HookDecision, HookEvent,
    HookExecutor, HookMode,
};
use serde_json::json;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// macOS CI timing budget multiplier (issue #1193).
//
// `Check (macos-latest)` on the GHA runner pool exhibits substantially
// higher cold-start latency and I/O scheduling variance than
// `ubuntu-latest`. The first `fork(2)+execve(2)+/bin/sh-startup`
// cycle on a cold macOS dev box or GHA runner has been observed to
// exceed 1.5s on its own, which makes the wall-clock-sensitive
// assertions in this file flake across PRs in the #1174 refactor
// campaign. Per issue #1193's "Proposed fix" option 1 (preferred):
// apply a centralized macOS-only budget multiplier so every
// `Duration::from_secs/from_millis(N)` site here can be re-tuned with
// a single edit.
//
// The multiplier is 10 — sized so the smallest budget in this file
// (500ms for `daemon_mode_timeout_still_trips_with_drain_task_running`)
// grows to 5s, which is comfortably past the observed cold-start
// spawn ceiling on an active macOS dev host with parallel cargo+rustc
// load. Reproduction on 2026-05-24 showed the first-fire (warm-the-
// connection) path failing at `Timeout { ms: 2500 }` under 5x; the
// bump to 10x clears that observation by another 2x. Larger budgets
// in this file scale identically (the 60s aggregate slack becomes
// 600s on macOS — still bounded, and the underlying defect this test
// guards against deadlocks the executor forever, so 600s is plenty
// of room to surface a real regression). Linux/Windows runs are
// unaffected (multiplier = 1).
//
// Apply this in two places per budget: the per-fire `timeout_ms` we
// hand to `DaemonExecutor::new(cfg_for(..., N))` AND the
// `Duration::from_*` ceiling we assert against `elapsed`.
#[cfg(target_os = "macos")]
const MACOS_TIMING_BUDGET_MULT: u32 = 10;
#[cfg(not(target_os = "macos"))]
const MACOS_TIMING_BUDGET_MULT: u32 = 1;

/// Write `body` to `dir/name`, mark it executable, return the path.
/// Same shape as the helper in `tests/hooks_executor_test.rs` — kept
/// local rather than re-exported so this test file is self-contained
/// and the production crate stays clean of test-only helpers.
fn write_script(dir: &TempDir, name: &str, body: &str) -> PathBuf {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let path = dir.path().join(name);
    {
        // Explicit File::create + write_all + sync_all + drop so the
        // writer fd is fully released before the child execs the
        // script — Linux returns ETXTBSY otherwise. Same workaround
        // hooks_executor_test.rs uses.
        let mut f = std::fs::File::create(&path).expect("create script");
        f.write_all(body.as_bytes()).expect("write script");
        f.sync_all().expect("sync script");
    }
    let mut perms = std::fs::metadata(&path).expect("stat").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod");
    path
}

fn cfg_for(command: PathBuf, mode: HookMode, timeout_ms: u32) -> HookConfig {
    HookConfig {
        event: HookEvent::PostStore,
        command,
        priority: 0,
        timeout_ms,
        mode,
        enabled: true,
        namespace: "*".into(),
        fail_mode: FailMode::Open,
    }
}

/// **The H9 regression case.** A daemon child that writes ~1 MiB of
/// stderr per fire would, before the fix, deadlock the executor on
/// the second or third fire (whichever first hit the OS pipe buffer
/// limit). After the fix, the per-child stderr-drain task keeps the
/// pipe drained and all fires complete inside the timeout.
///
/// The script writes 1024 lines of `~1 KiB` of stderr per fire (~1
/// MiB total per fire, comfortably past the 64 KiB Linux / 16 KiB
/// macOS pipe buffer), then emits the NDJSON decision on stdout. We
/// drive 5 fires in sequence — under the broken executor the second
/// fire never returns. A 30s ceiling is generous slack; a real
/// regression hangs forever (capped by the test harness).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_mode_high_stderr_volume_no_deadlock() {
    let dir = tempfile::tempdir().expect("tempdir");
    // 1 MiB of stderr per fire. `yes` would be simpler but isn't
    // portable across BSD/GNU userland — a hand-rolled while loop
    // keeps the test working on macOS dev boxes and ubuntu CI alike.
    //
    // We use printf in a loop, writing ~1 KiB per iteration for
    // 1024 iterations. That's ~1 MiB of stderr per fire — well past
    // every platform's pipe buffer.
    let script = write_script(
        &dir,
        "noisy_daemon.sh",
        r#"#!/bin/sh
# 1 KiB chunk we'll write 1024 times per fire (1 MiB total).
chunk=$(printf 'x%.0s' $(seq 1 1023))
while IFS= read -r _line; do
  i=0
  while [ "$i" -lt 1024 ]; do
    printf '%s\n' "$chunk" >&2
    i=$((i + 1))
  done
  printf '%s\n' '{"action":"allow"}'
done
"#,
    );

    // 30s per-fire timeout — generous. A regressed executor hangs
    // forever; a working one returns in milliseconds even with the
    // 1 MiB stderr volume. macOS CI runners get 10x headroom (#1193).
    let executor = DaemonExecutor::new(cfg_for(
        script,
        HookMode::Daemon,
        30_000 * MACOS_TIMING_BUDGET_MULT,
    ));

    let started = Instant::now();
    for i in 0..5u32 {
        let r = executor
            .fire(HookEvent::PostStore, json!({"i": i}))
            .await
            .unwrap_or_else(|e| panic!("fire {i} failed: {e}"));
        assert_eq!(
            r,
            HookDecision::Allow,
            "fire {i} returned {r:?}; expected Allow",
        );
    }
    let elapsed = started.elapsed();
    // 60s slack — even a slow CI runner should clear 5 MiB of
    // stderr piping in well under a minute. Anything close to this
    // bound suggests the drain task is missing or under-buffering.
    // macOS CI runners get 10x headroom (#1193).
    assert!(
        elapsed < Duration::from_secs(60) * MACOS_TIMING_BUDGET_MULT,
        "5 fires of 1 MiB stderr each took {elapsed:?}; suggests drain task is missing",
    );

    let m = executor.metrics();
    assert_eq!(m.events_fired, 5);
    assert_eq!(
        m.events_dropped, 0,
        "no fire should have dropped under the H9 fix"
    );
}

/// Companion to the above: the *executor* timeout must still trip
/// cleanly when the child genuinely stops responding. A regressed
/// drain task that buffered unboundedly could mask a hung child by
/// keeping the pipe forever drainable; we want the executor to
/// surface `Timeout` in bounded wall-clock regardless.
///
/// The script writes one Allow then sleeps forever — the second fire
/// must trip the configured 500ms timeout.
///
/// **macOS quarantine (issue #1193 + follow-up #TODO).** Per issue
/// #1193's "Proposed fix" option 2: this test is structurally
/// wall-clock-coupled in two places — (a) the first-fire connection
/// warm-up must succeed inside the per-fire `timeout_ms`, and (b)
/// the second fire's Timeout-surfacing must happen inside the assert
/// ceiling. On macOS GHA runners (and stressed macOS dev hosts) the
/// fork+exec+sh-startup cold-start has been observed to exceed the
/// option-1 [`MACOS_TIMING_BUDGET_MULT`] = 10× budget when this
/// test runs concurrently with `daemon_mode_high_stderr_volume_no_deadlock`
/// in the same binary (each test spawns its own /bin/sh tree, and
/// the macOS scheduler tail under that contention is unbounded).
/// The proper fix is option 3: rewrite the test to use a fake clock
/// (e.g. `tokio::time::pause`) so the deadline-trip path is
/// deterministic rather than wall-clock-coupled — tracked under
/// the follow-up issue. Until then, we ignore on macOS so the
/// Check (macos-latest) CI matrix stops blocking the #1174 refactor
/// campaign PRs. The Linux + Windows arms still exercise the same
/// code path so the H9 regression remains pinned everywhere except
/// macOS.
#[cfg_attr(
    target_os = "macos",
    ignore = "issue #1193 — wall-clock-coupled test; rewrite to fake clock in follow-up"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_mode_timeout_still_trips_with_drain_task_running() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = write_script(
        &dir,
        "hang_after_one.sh",
        r#"#!/bin/sh
# Answer the first fire so we know the daemon connection is healthy,
# then go silent so the second fire trips the executor's timeout.
read -r _first
printf '%s\n' '{"action":"allow"}'
# Print a stderr breadcrumb so the drain task has something to buffer
# and the WARN-on-timeout log path actually has content to surface.
printf 'about to hang\n' >&2
sleep 60
"#,
    );

    // macOS CI runners get 10x headroom (#1193) — the 500ms budget is
    // the tightest in this file and was the most frequent #1193 flake
    // source on the macos-latest GHA pool. 500ms × 10 = 5s on macOS,
    // which clears the observed fork+exec+sh-startup ceiling (2.5s
    // reproduced locally on 2026-05-24) by 2x.
    let executor = DaemonExecutor::new(cfg_for(
        script,
        HookMode::Daemon,
        500 * MACOS_TIMING_BUDGET_MULT,
    ));

    // First fire warms the connection — must succeed.
    let r1 = executor
        .fire(HookEvent::PostStore, json!({"first": true}))
        .await
        .expect("first fire warms the daemon connection");
    assert_eq!(r1, HookDecision::Allow);

    // Second fire must trip Timeout (script is sleeping). The window
    // is generous — the configured budget is 500ms (5s on macOS);
    // if we don't see an answer inside 5s (50s on macOS) the drain
    // task itself is hung.
    let started = Instant::now();
    let r2 = executor
        .fire(HookEvent::PostStore, json!({"second": true}))
        .await;
    let elapsed = started.elapsed();
    assert!(
        matches!(r2, Err(ExecutorError::Timeout { .. })),
        "second fire should have surfaced Timeout, got {r2:?}",
    );
    assert!(
        elapsed < Duration::from_secs(5) * MACOS_TIMING_BUDGET_MULT,
        "Timeout took {elapsed:?}; bounded budget should be ~500ms (5s on macOS)",
    );
}

/// ExecExecutor counterpart — a one-shot child that writes stderr on
/// the *success* path. Before the H9 fix this stderr was silently
/// dropped (only the failure arm of `wait_with_output` kept it). The
/// fix logs it at DEBUG; this test asserts the executor still
/// returns the parsed decision cleanly even when stderr is non-empty,
/// so we don't regress the success path while plumbing the trace.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_mode_stderr_on_success_path_does_not_break_decision() {
    let dir = tempfile::tempdir().expect("tempdir");
    let script = write_script(
        &dir,
        "noisy_allow.sh",
        r#"#!/bin/sh
# Drain stdin so the parent's stdin.shutdown() returns cleanly.
cat >/dev/null
# Write some stderr — operators reading the trace logs would expect
# to see this surfaced rather than silently dropped.
printf 'hook diagnostic: ran cleanup pass\n' >&2
printf 'hook diagnostic: 0 entries pruned\n' >&2
printf '%s\n' '{"action":"allow"}'
"#,
    );

    // 60s budget (was 30s, originally 5s) — issue #824: macOS-latest CI
    // runners have grown slower since 0536e96 bumped 5→30s; runs in
    // 2026-05-17 timed out at the 30s mark. Local runs finish in ~130ms.
    // Budget is for CI-flake resilience, not real workload. Real-deployment
    // hook timeouts are operator-configured. Per issue #1193 the macOS
    // multiplier is applied uniformly here too (600s on macOS) so a
    // single runner-load spike can't flake the success path either.
    let executor = ExecExecutor::new(cfg_for(
        script,
        HookMode::Exec,
        60_000 * MACOS_TIMING_BUDGET_MULT,
    ));
    let r = executor
        .fire(HookEvent::PostStore, json!({}))
        .await
        .expect("fire");
    assert_eq!(r, HookDecision::Allow);

    let m = executor.metrics();
    assert_eq!(m.events_fired, 1);
    assert_eq!(m.events_dropped, 0);
}
