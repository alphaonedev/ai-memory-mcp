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
//! One guard and ONE lock are reused by every in-process env-mutating unit-test
//! module so the whole in-process test surface is serialised against itself.
//! Since #3523 that lock is literally one `Mutex<()>` crate-wide:
//! [`env_lock`] DELEGATES to [`crate::config::test_env_lock`], which is the
//! same name the `config` / `reranker` / `egress` / `security_profile` /
//! `cli::commands::config` cohort already used. Before #3523 the two were
//! independent `OnceLock<Mutex<()>>` statics over the same process-global
//! writes — a fourth instance of the $HOME per-module-mutex defect
//! (#1998 -> #2115 -> #2127).

use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};

/// Process-wide lock serialising every test that mutates an environment
/// variable in-process, so `set_var`'s single-threaded contract holds and no
/// test observes another's transient env state.
///
/// # #3523 — this is a DELEGATE, not a second mutex
///
/// Until #3523 this function declared its OWN
/// `static LOCK: OnceLock<Mutex<()>>`, so the crate held TWO independent
/// mutexes over the SAME process-global environment table: this one (taken by
/// `log_paths`, `encryption`, `daemon_runtime`) and
/// [`crate::config::test_env_lock`] (taken by `config`, `reranker`, `egress`,
/// `security_profile`, `cli::commands::config`, `recover::transcript_paths`,
/// `enterprise_federation_posture`). Holding either excluded only its own
/// users, so a `log_paths` test setting `HOME` and a `config` test reading
/// `~/.config/ai-memory/config.toml` could run at literally the same instant
/// — the identical per-module-mutex defect $HOME already suffered three times
/// (#1998 -> #2115 -> #2127) before `config::test_env_lock` unified the first
/// cohort.
///
/// Both names survive so NO call site had to move; they now resolve to the
/// one [`crate::config::test_env_mutex`]. `tests/env_lock_singleton_gate_3523.rs`
/// pins that structurally, and this module's
/// `tests::the_two_env_lock_paths_are_one_mutex_3523` pins it by OBSERVATION.
///
/// A poisoned lock is recovered rather than propagated: a panic in one
/// env-mutating test must not wedge the others, and the panicking test's
/// [`EnvGuard`] already restored the environment on its way out — the
/// recovery lives in `config::test_env_lock`.
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    crate::config::test_env_lock()
}

/// The raw process-env mutex behind [`env_lock`] — the SAME
/// [`crate::config::test_env_mutex`] the `config` cohort acquires (#3523).
///
/// Exposed so the singleton can be proven by OBSERVATION (a probe thread's
/// `try_lock` must fail while a wrapper guard is held) rather than only by
/// reading the source.
pub(crate) fn env_mutex() -> &'static Mutex<()> {
    crate::config::test_env_mutex()
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

#[cfg(test)]
mod tests {
    use super::{EnvGuard, env_lock, env_mutex};

    /// #3523 — the OBSERVED singleton pin: `test_support::env_lock()` and
    /// `config::test_env_lock()` are ONE mutex, not two.
    ///
    /// A source-walk (`tests/env_lock_singleton_gate_3523.rs`) can be fooled
    /// by a delegate that is spelled correctly but resolves elsewhere; this
    /// asserts the runtime fact. Holding the `test_support` wrapper, a PROBE
    /// THREAD must fail to acquire the `config` path. Two independent mutexes
    /// would let it succeed — which is exactly the pre-#3523 state.
    ///
    /// The probe runs on another thread on purpose: a same-thread `try_lock`
    /// of a mutex this thread already holds also returns `Err`, so it could
    /// not distinguish "one mutex" from "self-conflict"
    /// (`std::sync::Mutex` is not reentrant — rust-1.98 CONCURRENCY-04).
    #[test]
    fn the_two_env_lock_paths_are_one_mutex_3523() {
        let _held = env_lock();
        let probe_acquired =
            std::thread::spawn(|| crate::config::test_env_mutex().try_lock().is_ok())
                .join()
                .expect("probe thread must not panic");
        assert!(
            !probe_acquired,
            "#3523: a probe thread acquired `config::test_env_mutex()` while \
             `test_support::env_lock()` was held — the two paths are TWO \
             independent mutexes again, so a $HOME mutation in one cohort can \
             interleave with the other (the #1998 -> #2115 -> #2127 defect)"
        );
        assert!(
            std::ptr::eq(env_mutex(), crate::config::test_env_mutex()),
            "#3523: `test_support::env_mutex()` and `config::test_env_mutex()` \
             must be the SAME `Mutex<()>` allocation"
        );
    }

    /// The `EnvGuard` RAII contract: the pre-guard value is restored on drop,
    /// including the "was absent" case. Without this the guard could silently
    /// leak a mutation into a sibling test in the same binary — the failure
    /// mode the one lock cannot cover.
    #[test]
    fn env_guard_restores_the_pre_guard_state_3523() {
        const KEY: &str = "AI_MEMORY_TEST_SUPPORT_PROBE_3523";
        let _lock = env_lock();
        assert!(
            std::env::var_os(KEY).is_none(),
            "probe key must start absent"
        );
        {
            let guard = EnvGuard::capture(KEY);
            guard.set("value-a");
            assert_eq!(std::env::var(KEY).ok().as_deref(), Some("value-a"));
            guard.unset();
            assert!(std::env::var_os(KEY).is_none());
            guard.set("value-b");
        }
        assert!(
            std::env::var_os(KEY).is_none(),
            "#3523: `EnvGuard` must restore the ABSENT pre-guard state on drop"
        );
    }
}
