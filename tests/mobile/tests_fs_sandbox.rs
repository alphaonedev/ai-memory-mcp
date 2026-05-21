// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// v0.7.0 Posture-1a (issue #1068 Layer 3) — file-system / sandboxing
// tests for the iOS Simulator + Android emulator runs.
//
// Tests in this file exercise primitives that BEHAVE DIFFERENTLY on
// the mobile sandbox vs. a typical server distro:
//
//   - Writable-path discovery (sandbox root resolution)
//   - File creation + deletion under the sandbox
//   - Delete-while-open semantics (Android tolerates, iOS doesn't on
//     some sqlite versions)
//   - WAL + SHM sibling cleanup
//
// Each test calls into the harness module's `sandbox_db_path` so the
// same test body works against the iOS Documents/ directory, the
// Android filesDir, AND the host fallback under .local-runs/.

use super::harness::{cleanup, sandbox_db_path};

#[test]
fn fs_sandbox_create_and_delete_file() {
    let p = sandbox_db_path("fs_create_delete");
    std::fs::write(&p, b"hello sandbox").expect("write into sandbox");
    assert!(p.exists(), "sandbox file should exist after write");
    cleanup(&p);
    assert!(!p.exists(), "sandbox file should not exist after cleanup");
}

#[test]
fn fs_sandbox_sqlite_wal_siblings_cleanup() {
    // Simulate the sqlite WAL mode siblings (-wal, -shm). Verifies
    // that the harness's cleanup() helper removes them too — relevant
    // because the iOS sandbox enforces strict per-file lifecycle and
    // a leaked -shm file across test runs causes intermittent
    // "database is locked" errors that don't reproduce on linux.
    let p = sandbox_db_path("fs_sqlite_wal_cleanup");
    std::fs::write(&p, b"db").unwrap();
    std::fs::write(format!("{}-wal", p.display()), b"wal").unwrap();
    std::fs::write(format!("{}-shm", p.display()), b"shm").unwrap();

    cleanup(&p);

    assert!(!p.exists());
    assert!(!std::path::Path::new(&format!("{}-wal", p.display())).exists());
    assert!(!std::path::Path::new(&format!("{}-shm", p.display())).exists());
}

#[test]
fn fs_sandbox_path_is_under_writable_root() {
    let p = sandbox_db_path("fs_writable_root");
    let parent = p.parent().expect("sandbox path has a parent");
    assert!(parent.is_dir(), "sandbox parent dir must exist");
    // Round-trip a small write to confirm the path is actually
    // writable in this process's effective UID context. On iOS this
    // is the simulator's per-app sandbox; on Android it's filesDir.
    let probe = parent.join(".writable-probe");
    std::fs::write(&probe, b"probe").expect("parent dir should be writable");
    std::fs::remove_file(&probe).ok();
}

// TODO #1068 Layer 3 follow-up: add tests for
//   - rename across sandbox boundary (Android scoped-storage)
//   - fsync(2) under iOS background suspension
//   - delete-while-open (mobile differs from glibc)
//   - permission-denied path outside the sandbox
