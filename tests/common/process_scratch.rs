// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8634 class A: a process-wide scratch path that is removed when the test
//! process exits.
//!
//! A `tempfile::TempDir` removes itself on drop, but a fixture that must live
//! for the whole process (a `OnceLock` / `static` shared by every case, such as
//! the auto-atomise shared database or the shared TLS leaf) is never dropped:
//! Rust does not run destructors of statics. Such a fixture takes a directory
//! from [`process_scratch_dir`] instead, which hands out a fresh directory
//! under the system temp root and removes it, with everything inside it
//! (SQLite `-wal` / `-shm` / `-journal` sidecars included), from an `atexit`
//! hook. The libtest harness catches a failing case and exits normally, so the
//! hook runs after a pass, after an assertion failure and after a panic; only
//! an abort or a kill signal skips it.
//!
//! Declare it as a leaf, like the other `tests/common/*` helpers:
//!
//! ```ignore
//! #[path = "common/process_scratch.rs"]
//! mod process_scratch;
//! ```

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};

/// Directories to remove at process exit.
static PENDING: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
static REGISTER: Once = Once::new();

/// Remove every registered directory. Runs from `atexit`: it must not panic,
/// and a removal error is ignored (the directory is already gone, or the
/// process is exiting and there is nobody to report to).
extern "C" fn remove_registered() {
    let dirs = match PENDING.lock() {
        Ok(mut guard) => std::mem::take(&mut *guard),
        Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
    };
    for dir in dirs {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Arrange for `dir` (and everything inside it) to be removed at process exit.
pub fn remove_at_exit(dir: &Path) {
    PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(dir.to_path_buf());
    REGISTER.call_once(|| {
        #[cfg(unix)]
        {
            // SAFETY: `atexit` only records the function pointer; the handler
            // is a plain `extern "C" fn` that never unwinds.
            let rc = unsafe { libc::atexit(remove_registered) };
            assert_eq!(rc, 0, "atexit could not register the scratch cleanup");
        }
    });
}

/// A fresh directory under the system temp root (`TMPDIR`), removed with its
/// contents at process exit.
///
/// # Panics
/// When the directory cannot be created.
pub fn process_scratch_dir(prefix: &str) -> PathBuf {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .expect("create the process scratch dir")
        .keep();
    remove_at_exit(&dir);
    dir
}
