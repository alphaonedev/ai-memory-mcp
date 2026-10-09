// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6266 — remove process-lifetime scratch directories when the test binary
//! exits.
//!
//! A `static OnceLock<tempfile::TempDir>` is never dropped: Rust runs no
//! destructor for a `static` at process exit, so every lib-test process (and
//! every env-isolated child the suite spawns) orphaned one directory in
//! `TMPDIR` (`identity::test_key_dir::DIRECTORY`, `POSTURE_AUDIT_DIR`).
//!
//! [`remove_dir_at_exit`] records the path and registers one `atexit`
//! handler (unix) that removes every recorded directory. The `TempDir` stays
//! in its static so the directory remains valid for the whole process; the
//! handler only deletes it after the last test has finished.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once, PoisonError};

static EXIT_DIRS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
static REGISTER: Once = Once::new();

/// Remove every directory recorded by [`remove_dir_at_exit`] (best effort;
/// a missing directory is the normal case when the `TempDir` already dropped).
fn run_exit_cleanup() {
    let dirs = EXIT_DIRS.lock().unwrap_or_else(PoisonError::into_inner);
    for dir in dirs.iter() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(unix)]
extern "C" fn exit_trampoline() {
    run_exit_cleanup();
}

/// Arrange for `dir` to be removed (recursively) when the process exits.
pub(crate) fn remove_dir_at_exit(dir: &Path) {
    EXIT_DIRS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(dir.to_path_buf());
    REGISTER.call_once(|| {
        #[cfg(unix)]
        {
            // SAFETY: `exit_trampoline` is an `extern "C" fn()` with no
            // captures that touches only a `Mutex`-guarded static and the
            // filesystem; `atexit` requires exactly that signature. A
            // registration failure (nonzero return) only means the
            // directory is left behind, which is the pre-#6266 state.
            let _registered = unsafe { libc::atexit(exit_trampoline) };
        }
    });
}
