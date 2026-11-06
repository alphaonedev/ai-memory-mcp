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

/// #7342 - lock file, under the scratch root, that serialises the nested
/// `cargo build` + existence check + binary copy ACROSS processes.
const BUILD_LOCK_FILE: &str = "build.lock";

/// #7342 - prefix of the per-process copy of the uplifted binary
/// (`bin-<pid>`); the tests spawn the copy, never cargo's uplifted file.
const BIN_COPY_PREFIX: &str = "bin-";

/// #7342 - gitignored project-local scratch directory (no /tmp writes).
const LOCAL_RUNS_DIR: &str = ".local-runs";

/// #7342 - subdirectory of [`LOCAL_RUNS_DIR`] holding the lock, the build
/// target dir, the per-process binary copies and the capture files.
const SCRATCH_SUBDIR: &str = "transcript-extractor";

/// #7342 - suffix of the temporary name a copy is written to before the
/// atomic rename onto `bin-<pid>`.
const BIN_COPY_TMP_SUFFIX: &str = ".tmp";

/// #7342 - a `bin-<pid>` copy older than this is pruned even when its pid
/// looks alive (pid reuse by an unrelated process). The bound is far above the
/// longest legitimate lifetime of a test process: `EXTRACTOR_BUILD_BUDGET`
/// (5 min) plus the largest nextest slow-timeout (`.config/nextest.toml`, ci
/// profile 120 s x 3 = 6 min) is 11 min, so 1 h leaves a 5.4x margin.
const STALE_BIN_COPY_AGE: std::time::Duration = std::time::Duration::from_hours(1);

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
///
/// #7342 - under `cargo nextest` every test is its own process, so the
/// `OnceLock` serialises nothing across processes and cargo's re-uplift of
/// `debug/transcript-extractor` (remove, then hardlink) races every other
/// process. The returned path is therefore a per-process COPY made while an
/// exclusive cross-process file lock is held around build + exists + copy;
/// no later cargo build can touch it.
fn extractor_bin() -> &'static PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(build_extractor_once)
}

/// #7342 - the one scratch root (`<cwd>/.local-runs/transcript-extractor`).
fn scratch_root() -> PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(LOCAL_RUNS_DIR)
        .join(SCRATCH_SUBDIR)
}

/// #7342 - pid encoded in a `bin-<digits>` or `bin-<digits>.tmp` file name,
/// `None` for any other name.
fn bin_copy_pid(name: &str) -> Option<u32> {
    let rest = name.strip_prefix(BIN_COPY_PREFIX)?;
    let digits = rest.strip_suffix(BIN_COPY_TMP_SUFFIX).unwrap_or(rest);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// #7342 (N1) - `kill -0 <pid>`: `Ok(true)` when the process exists,
/// `Ok(false)` when it does not, `Err` when the probe itself could not run
/// (fail closed: the caller must not treat that as dead). The caller logs the
/// error with the copy path (ERRORS-07). No new dependency.
fn pid_probe(pid: u32) -> std::io::Result<bool> {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
}

/// #7342 (N1) - prune decision. An unrunnable probe (`None`) counts as ALIVE,
/// so only the age rule can remove the copy; a live pid's copy is never
/// deleted on a probe error (ENOENT on spawn is #7342 again).
fn should_prune(too_old: bool, alive: Option<bool>) -> bool {
    too_old || !alive.unwrap_or(true)
}

/// #7342 (M1) - prune stale `bin-<pid>` / `bin-<pid>.tmp` files directly under
/// `dir`. Only REGULAR files (`symlink_metadata`, never followed) are
/// candidates. A file goes when its owner pid is dead, or when it is older than
/// [`STALE_BIN_COPY_AGE`]; the copy of a live pid is kept, since that process
/// may be about to spawn it (ENOENT on spawn is #7342 again). Callers hold the
/// build lock. A failure on one entry is logged and skipped (ERRORS-19).
fn prune_stale_bin_copies(dir: &Path) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("prune: read_dir {}: {e}", dir.display());
            return;
        }
    };
    let mut probe_failure_logged = false;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(pid) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(bin_copy_pid)
        else {
            continue;
        };
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_file() => meta,
            Ok(_) => continue,
            Err(e) => {
                eprintln!("prune: stat {}: {e}", path.display());
                continue;
            }
        };
        let too_old = meta
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age > STALE_BIN_COPY_AGE);
        let alive = if too_old {
            None
        } else {
            match pid_probe(pid) {
                Ok(alive) => Some(alive),
                Err(e) => {
                    // Only the first failure of a prune pass is logged (ERRORS-07: names the copy).
                    if !probe_failure_logged {
                        probe_failure_logged = true;
                        eprintln!(
                            "prune: liveness probe for pid {pid} ({}) could not run: {e}",
                            path.display()
                        );
                    }
                    None
                }
            }
        };
        if should_prune(too_old, alive)
            && let Err(e) = std::fs::remove_file(&path)
        {
            eprintln!("prune: remove {}: {e}", path.display());
        }
    }
}

/// #7342 (S1) - write a private copy of `src` as `<dir>/bin-<pid>`: a fresh
/// `create_new` (`O_EXCL`) temp file, then an atomic rename. `create_new` refuses
/// an existing path or symlink and `rename` replaces a symlink instead of
/// following it, so a planted link is never written through and a stale
/// same-pid file becomes a fresh inode.
fn install_private_copy(src: &Path, dir: &Path, pid: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin_copy = dir.join(format!("{BIN_COPY_PREFIX}{pid}"));
    let tmp = dir.join(format!("{BIN_COPY_PREFIX}{pid}{BIN_COPY_TMP_SUFFIX}"));
    // A same-pid leftover (or planted link) at the temp name: unlink the NAME.
    if let Err(e) = std::fs::remove_file(&tmp)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        panic!("remove stale {}: {e}", tmp.display());
    }
    let mut input = std::fs::File::open(src)
        .unwrap_or_else(|e| panic!("open extractor {}: {e}", src.display()));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .unwrap_or_else(|e| panic!("create {}: {e}", tmp.display()));
    std::io::copy(&mut input, &mut output)
        .unwrap_or_else(|e| panic!("copy extractor {} to {}: {e}", src.display(), tmp.display()));
    // fchmod on the open handle (N2): never re-resolve the temp name by path.
    output
        .set_permissions(std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", tmp.display()));
    drop(output);
    std::fs::rename(&tmp, &bin_copy)
        .unwrap_or_else(|e| panic!("rename {} to {}: {e}", tmp.display(), bin_copy.display()));
    bin_copy
}

/// #7342 - prune stale copies, then install this process's copy.
fn prepare_private_copy(src: &Path, dir: &Path) -> PathBuf {
    prune_stale_bin_copies(dir);
    install_private_copy(src, dir, std::process::id())
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
    let scratch_root = scratch_root();
    std::fs::create_dir_all(&scratch_root).ok();
    let target_dir = scratch_root.join("ai-memory-transcript-extractor-target");

    // #7342 - exclusive cross-process lock around the WHOLE sequence (build,
    // existence check, copy). `File::lock` is stable since Rust 1.89; the
    // lock is released by `unlock` below or by drop on any panic path.
    let lock_path = scratch_root.join(BUILD_LOCK_FILE);
    let build_lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .unwrap_or_else(|e| panic!("open build lock {}: {e}", lock_path.display()));
    build_lock
        .lock()
        .unwrap_or_else(|e| panic!("lock build lock {}: {e}", lock_path.display()));

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

    // #7342 - spawn a private copy: cargo may re-uplift `bin` the moment the
    // lock is released. Stale copies of dead processes are pruned first (M1),
    // the copy is written create_new + rename (S1); both run under the lock.
    let bin_copy = prepare_private_copy(&bin, &scratch_root);
    build_lock
        .unlock()
        .unwrap_or_else(|e| panic!("unlock build lock {}: {e}", lock_path.display()));
    bin_copy
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
    let capture_root = scratch_root();
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

/// #7342 - how many trailing log lines of a failed child the report keeps.
const CHILD_TAIL_LINES_7342: usize = 12;

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
    let capture_root = scratch_root();
    std::fs::create_dir_all(&capture_root)
        .unwrap_or_else(|e| panic!("create {}: {e}", capture_root.display()));
    let mut children = Vec::new();
    for i in 0..CONCURRENT_PROCESSES_7342 {
        let log_path = capture_root.join(format!("race-7342-{}-{i}.log", std::process::id()));
        // S1: O_EXCL; unlink the NAME first so a leftover or planted link is
        // never written through.
        if let Err(e) = std::fs::remove_file(&log_path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            panic!("remove stale {}: {e}", log_path.display());
        }
        let log = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&log_path)
            .unwrap_or_else(|e| panic!("create {}: {e}", log_path.display()));
        let log_err = log
            .try_clone()
            .unwrap_or_else(|e| panic!("clone {}: {e}", log_path.display()));
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
        if status.success() {
            let _ = std::fs::remove_file(&log_path);
            continue;
        }
        match std::fs::read_to_string(&log_path) {
            Ok(text) => {
                let lines: Vec<&str> = text.lines().collect();
                let tail = &lines[lines.len().saturating_sub(CHILD_TAIL_LINES_7342)..];
                failures.push(format!("{status}: {tail:?}"));
            }
            Err(e) => failures.push(format!("{status}: log {}: {e}", log_path.display())),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {CONCURRENT_PROCESSES_7342} processes lost the extractor binary (#7342): {failures:#?}",
        failures.len()
    );
}

/// #7342 - a private test directory under the scratch root. Pruning only
/// looks at regular files directly under the scratch root, so a real run never
/// touches it, and the tests never touch a live process's copy.
fn test_dir_7342(tag: &str) -> TestDir7342 {
    let dir = scratch_root().join(format!("test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
    TestDir7342(dir)
}

/// #7342 (N4) - RAII guard: the private test directory is removed on drop, so
/// a failing (panicking) test does not leak it.
struct TestDir7342(PathBuf);

impl std::ops::Deref for TestDir7342 {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir7342 {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("cleanup {}: {e}", self.0.display());
        }
    }
}

/// #7342 (N1) - every branch of the prune decision, including a probe that
/// could not run (`None`), which must never select the destructive branch
/// for a young copy.
#[test]
fn prune_decision_fails_closed_when_probe_unavailable_7342() {
    assert!(should_prune(false, Some(false)), "dead and young is pruned");
    assert!(!should_prune(false, Some(true)), "alive and young is kept");
    assert!(
        should_prune(true, Some(true)),
        "alive but too old is pruned"
    );
    assert!(
        should_prune(true, Some(false)),
        "dead and too old is pruned"
    );
    assert!(
        !should_prune(false, None),
        "probe unavailable and young is kept"
    );
    assert!(
        should_prune(true, None),
        "probe unavailable but too old is pruned"
    );
}

/// #7342 - the pid of a child that has already exited (dead, not reused yet).
fn dead_pid_7342() -> u32 {
    let mut child = Command::new("true").spawn().expect("spawn true");
    let pid = child.id();
    child.wait().expect("wait true");
    pid
}

/// #7342 (M1) - stale copies of dead processes are pruned, the copy of a live
/// pid (the parent's) is kept, symlinks and foreign names are never touched.
#[test]
fn stale_bin_copies_are_pruned_and_live_ones_kept_7342() {
    let dir = test_dir_7342("prune");
    let dead = dead_pid_7342();
    let stale = dir.join(format!("{BIN_COPY_PREFIX}{dead}"));
    let stale_tmp = dir.join(format!("{BIN_COPY_PREFIX}{dead}{BIN_COPY_TMP_SUFFIX}"));
    let live = dir.join(format!(
        "{BIN_COPY_PREFIX}{}",
        std::os::unix::process::parent_id()
    ));
    let foreign = dir.join(format!("{BIN_COPY_PREFIX}notapid"));
    let link = dir.join(format!("{BIN_COPY_PREFIX}{}", u32::MAX));
    let victim = dir.join("victim");
    for p in [&stale, &stale_tmp, &live, &foreign, &victim] {
        std::fs::write(p, b"x").unwrap_or_else(|e| panic!("write {}: {e}", p.display()));
    }
    let old = std::time::SystemTime::now() - STALE_BIN_COPY_AGE * 2;
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .and_then(|f| f.set_modified(old))
        .unwrap_or_else(|e| panic!("set mtime {}: {e}", stale.display()));
    std::os::unix::fs::symlink(&victim, &link)
        .unwrap_or_else(|e| panic!("symlink {}: {e}", link.display()));

    let copy = prepare_private_copy(extractor_bin(), &dir);

    assert!(
        !stale.exists(),
        "stale dead-pid copy kept: {}",
        stale.display()
    );
    // N1: a young dead-pid copy goes only when the probe can run; with `kill`
    // unavailable it is kept (fail closed), never the other way round.
    let probe_runs = pid_probe(std::os::unix::process::parent_id()).is_ok();
    assert_eq!(
        stale_tmp.exists(),
        !probe_runs,
        "stale tmp (probe runs: {probe_runs}): {}",
        stale_tmp.display()
    );
    assert!(live.exists(), "live pid copy pruned: {}", live.display());
    assert!(
        foreign.exists(),
        "foreign name pruned: {}",
        foreign.display()
    );
    assert!(
        std::fs::symlink_metadata(&link).is_ok() && victim.exists(),
        "symlink entry pruned: {}",
        link.display()
    );
    assert!(copy.is_file(), "own copy missing: {}", copy.display());
}

/// #7342 (S1) - a symlink planted at the own `bin-<pid>` path is replaced, not
/// written through: the victim keeps its content and mode.
#[test]
fn private_copy_never_writes_through_a_planted_symlink_7342() {
    use std::os::unix::fs::PermissionsExt;
    let dir = test_dir_7342("symlink");
    let victim = dir.join("victim");
    std::fs::write(&victim, b"precious")
        .unwrap_or_else(|e| panic!("write {}: {e}", victim.display()));
    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", victim.display()));
    let own = dir.join(format!("{BIN_COPY_PREFIX}{}", std::process::id()));
    std::os::unix::fs::symlink(&victim, &own)
        .unwrap_or_else(|e| panic!("symlink {}: {e}", own.display()));

    let copy = prepare_private_copy(extractor_bin(), &dir);

    assert_eq!(copy, own, "copy path");
    assert_eq!(std::fs::read(&victim).expect("read victim"), b"precious");
    let mode = std::fs::metadata(&victim)
        .expect("victim meta")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644, "victim mode changed");
    let meta = std::fs::symlink_metadata(&own).expect("own meta");
    assert!(meta.file_type().is_file(), "own copy is not a regular file");
    assert_eq!(meta.permissions().mode() & 0o777, 0o755, "own copy mode");
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
