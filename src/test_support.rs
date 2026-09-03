//! Crate-internal, test-only environment-isolation helpers shared across the
//! unit-test modules that mutate process-global environment variables.
//!
//! `std::env::set_var`/`remove_var` mutate the single process-wide environment
//! table and are unsound if any other thread accesses the environment
//! concurrently (rust-1.98 UNSAFE-01/03). The libtest harness runs `#[test]`
//! functions on several threads by default, so every in-process test that
//! mutates an env var must:
//!
//! 1. hold the process-wide [`env_lock`] for the whole test body, so no two
//!    such tests run concurrently. This upholds `set_var`'s single-threaded
//!    contract AND prevents one test from observing another's transient value
//!    — the TOCTOU that leaked the at-rest encryption gate and reddened
//!    `Check (macos-fed)` / `Per-Module Coverage Thresholds` (#3301, #2905
//!    test-isolation class); and
//! 2. mutate through an [`EnvGuard`], which snapshots the prior value on
//!    construction and restores it on `Drop`. Because `Drop` also runs during
//!    unwinding, a panic mid-test can never leak the mutation into a sibling
//!    test in the same binary.
//!
//! One guard and one lock are reused by every in-process env-mutating unit-test
//! module (`log_paths`, `encryption`) so the whole in-process test surface is
//! serialised against itself.

use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Create a temporary directory whose mode is explicitly 0700 on Unix.
///
/// `tempfile` creates directories subject to the process umask. Tests that use
/// a tempdir as an identity key directory must not accidentally inherit 0775
/// under a collaborative `umask 002`, because the production key-directory
/// guard correctly refuses group-writable paths (#3439).
///
/// # Panics
///
/// Panics if the temporary directory cannot be created or its Unix mode cannot
/// be changed to 0700.
pub(crate) fn secure_tempdir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("secure tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod secure tempdir to 0700");
    }
    dir
}

#[cfg(unix)]
#[test]
fn secure_tempdir_is_mode_0700_3439() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = secure_tempdir();
    let mode = std::fs::metadata(dir.path())
        .expect("secure tempdir metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
}

/// Process-wide lock serialising every test that mutates an environment
/// variable in-process, so `set_var`'s single-threaded contract holds and no
/// test observes another's transient env state.
///
/// A poisoned lock is recovered rather than propagated: a panic in one
/// env-mutating test must not wedge the others, and the panicking test's
/// [`EnvGuard`] already restored the environment on its way out.
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Snapshot+restore guard for a single process-wide environment variable, so a
/// test never leaks its mutation into a sibling test in the same binary.
///
/// Hold [`env_lock`] for the enclosing test body while this guard is live.
pub(crate) struct EnvGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvGuard {
    /// Capture `key`'s current value; it is restored on `Drop`.
    pub(crate) fn capture(key: &'static str) -> Self {
        Self {
            key,
            prev: std::env::var_os(key),
        }
    }

    /// Set `key` to `v`. The caller must hold [`env_lock`].
    pub(crate) fn set(&self, v: &str) {
        // SAFETY: the enclosing test holds `env_lock()`, so no other thread is
        // reading or writing the environment concurrently (UNSAFE-01/03).
        unsafe {
            std::env::set_var(self.key, v);
        }
    }

    /// Remove `key`. The caller must hold [`env_lock`].
    pub(crate) fn unset(&self) {
        // SAFETY: same as `set` — serialised by `env_lock()`.
        unsafe {
            std::env::remove_var(self.key);
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // SAFETY: same as `set` — serialised by `env_lock()`. Runs during
        // unwinding on panic, so the variable is always restored to its
        // pre-test value.
        unsafe {
            if let Some(v) = &self.prev {
                std::env::set_var(self.key, v);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }
}
