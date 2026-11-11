// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8779 class ratchet: no process-global stdout/stderr lock is held by a CLI
//! dispatch arm.
//!
//! `curator --once` held `std::io::stderr().lock()` across the
//! `spawn_blocking` sweep. The worker thread's first tracing event (the
//! subscriber writes to stderr) then blocked on the reentrant mutex owned by
//! the dispatch thread, which was itself waiting on the worker: a deadlock
//! that never ends. Every other dispatch arm used the same
//! `let mut so = stdout.lock(); let mut se = stderr.lock();` shape around an
//! `.await`, so the whole class is locked here: a `Stdout` / `Stderr` handle
//! (which takes the lock per write) is the only accepted form, and the few
//! synchronous sites that take the lock for one bounded write are named below
//! with their exact count. A new lock site fails this test with its
//! `file:line`.

use std::path::{Path, PathBuf};

/// Every spelling that acquires a process-global stdio lock.
const LOCK_NEEDLES: [&str; 4] = [
    "stdout.lock()",
    "stderr.lock()",
    "stdout().lock()",
    "stderr().lock()",
];

/// Reviewed synchronous sites: the lock is taken for one bounded write and
/// dropped before any tracing, await or thread hand-off. The count per file
/// is exact; growing it needs a new review entry here.
const ALLOWED_LOCK_SITES: [(&str, usize, &str); 3] = [
    (
        "src/storage/escalation_deferral.rs",
        1,
        "write_open_report: raw fd write, lock dropped before the caller traces",
    ),
    (
        "src/storage/escalation_frame_reporting_8184_tests.rs",
        1,
        "test: holds the lock to prove the report writer serialises",
    ),
    (
        "src/daemon_runtime.rs",
        2,
        "cmd_bench: synchronous one-line stderr notices, no await",
    ),
];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Returns `(relative path, [line numbers])` for every file with a lock site.
fn lock_sites(root: &Path) -> Vec<(String, Vec<usize>)> {
    let mut files = Vec::new();
    rust_sources(&root.join("src"), &mut files);
    files.sort();
    let mut sites = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(root)
            .expect("under manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&file).expect("read source");
        let lines: Vec<usize> = text
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim_start().starts_with("//"))
            .filter(|(_, line)| LOCK_NEEDLES.iter().any(|needle| line.contains(needle)))
            .map(|(idx, _)| idx + 1)
            .collect();
        if !lines.is_empty() {
            sites.push((rel, lines));
        }
    }
    sites
}

#[test]
fn no_stdio_lock_outside_reviewed_sync_sites_8779() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for (rel, lines) in lock_sites(root) {
        let allowed = ALLOWED_LOCK_SITES
            .iter()
            .find(|(path, _, _)| *path == rel)
            .map_or(0, |(_, count, _)| *count);
        if lines.len() > allowed {
            offenders.push(format!(
                "{rel}: {} lock site(s), {allowed} reviewed, lines {lines:?}",
                lines.len()
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "#8779: a process-global stdout/stderr lock held by a dispatch arm \
         deadlocks any worker thread that traces; pass the unlocked handle \
         instead: {offenders:?}"
    );
}

/// The allowlist only shrinks: an entry whose file no longer has that many
/// sites must be lowered, so a removed site cannot be silently re-added.
#[test]
fn reviewed_stdio_lock_allowlist_is_exact_8779() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sites = lock_sites(root);
    let mut stale = Vec::new();
    for (path, count, why) in ALLOWED_LOCK_SITES {
        let found = sites
            .iter()
            .find(|(rel, _)| rel == path)
            .map_or(0, |(_, lines)| lines.len());
        if found != count {
            stale.push(format!("{path}: allowlist {count}, found {found} ({why})"));
        }
    }
    assert!(
        stale.is_empty(),
        "#8779: lower the reviewed stdio lock allowlist to the real count: {stale:?}"
    );
}
