// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared key-directory sandbox for unit and integration tests.
//! Armed test processes use it as their default; an explicit environment
//! override is still checked and panics if it resolves under HOME.
//!
//! [`install`] is authoritative for `AI_MEMORY_KEY_DIR` (#3584): it points
//! that variable at the sandbox it created, so an ambient harness override
//! cannot leak into a test that asked for isolation. The previous value is
//! restored when the process-lifetime bind drops. Child processes inherit
//! the sandbox path unless the spawner `env_remove`s it (the #3355 pin) or
//! `env_clear()`s; a clearer must pass `AI_MEMORY_KEY_DIR` = [`install`]
//! and, when the child is meant to be guarded, [`TEST_KEY_GUARD_ENV`].
//!
//! # The guard is ARMED per PROCESS, never inferred from a Cargo feature (#3516)
//!
//! `Cargo.toml` carries a self dev-dependency
//! (`ai-memory = { path = ".", features = ["test-support"] }`), so EVERY
//! `cargo test` unifies `test-support` into the whole build — including the
//! `ai-memory` BIN compiled for the integration tests, which overwrites
//! `target/{debug,release}/ai-memory`. A binary produced that way is an
//! ordinary operator binary in every other respect, so
//! `cfg(feature = "test-support")` cannot stand in for "this process is a
//! test": on 87f86a0a the #3355 assertion fired inside the released binary
//! and panicked on the DEFAULT operator key location
//! (`~/.config/ai-memory/keys`), taking down the Batman Mode acceptance gate
//! and any operator run from a target where `cargo test` had run.
//!
//! Both halves of the guard — the HOME assertion in [`assert_isolated`] and
//! the sandbox default in [`armed_sandbox`] — are therefore inert unless this
//! PROCESS armed them:
//!
//! * `cfg(test)` — the crate's own unit-test harness, always armed;
//! * a call to [`install`] in this process — integration tests and the
//!   library fixtures they share;
//! * the [`TEST_KEY_GUARD_ENV`] marker in the process environment — children
//!   of an armed test, which inherit it because [`install`] exports it.
//!
//! An operator binary, a CI step, or any other non-test process carries none
//! of the three, so it resolves the real `dirs::config_dir()` key store
//! exactly as production intends and can never panic on the #3355 message.

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Marker environment variable that arms the #3355 key-directory guard in a
/// process that is not the crate's own `cfg(test)` harness.
///
/// [`install`] exports it, so every child of an armed test inherits the
/// sandbox discipline with no call-site change. A spawner that calls
/// `env_clear()` must pass it explicitly next to `AI_MEMORY_KEY_DIR` when the
/// child is meant to be guarded.
pub const TEST_KEY_GUARD_ENV: &str = "AI_MEMORY_TEST_KEY_GUARD";

static DIRECTORY: OnceLock<tempfile::TempDir> = OnceLock::new();
static ARMED: AtomicBool = AtomicBool::new(false);
static KEY_DIR_BIND: OnceLock<KeyDirEnvBind> = OnceLock::new();

/// Snapshot+restore of `AI_MEMORY_KEY_DIR` for the process lifetime of
/// [`install`] (#3584, OWNERSHIP-24 / OWNERSHIP-25).
///
/// Field `prev` is restored on drop so an ambient harness value does not
/// leak out of a test binary that asked for isolation. [`Drop`] is infallible.
struct KeyDirEnvBind {
    prev: Option<OsString>,
}

impl Drop for KeyDirEnvBind {
    fn drop(&mut self) {
        // Restore is the EnvGuard pattern (#3539 / #3577): the value
        // captured at bind time is written back, including `None` → unset.
        // Drop runs at process teardown of a test binary (the bind lives in
        // a `OnceLock`). No production path constructs it.
        match &self.prev {
            Some(v) => set_env(super::keypair::KEY_DIR_ENV, v),
            None => unset_env(super::keypair::KEY_DIR_ENV),
        }
    }
}

/// Whether the #3355 key-directory guard is armed for THIS process (#3516).
#[must_use]
pub fn armed() -> bool {
    if cfg!(test) || ARMED.load(Ordering::Acquire) {
        return true;
    }
    // The marker is inherited at `exec` time and nothing but `install` (which
    // sets `ARMED` first, above) ever writes it, so a single probe is both
    // sufficient and stable — and caching it keeps `install`'s one
    // environment write out of every later reader's way.
    static INHERITED: OnceLock<bool> = OnceLock::new();
    *INHERITED.get_or_init(|| std::env::var_os(TEST_KEY_GUARD_ENV).is_some_and(|v| !v.is_empty()))
}

/// Arm the process sandbox and return its path.
///
/// Call this from test setup. It exports [`TEST_KEY_GUARD_ENV`] and points
/// `AI_MEMORY_KEY_DIR` at the sandbox (#3584) so an ambient override cannot
/// leak into `default_key_dir()`. The previous `AI_MEMORY_KEY_DIR` value is
/// restored when the process-lifetime bind drops.
///
/// # Panics
/// Panics if a private temporary directory cannot be allocated outside HOME.
#[must_use]
pub fn install() -> &'static Path {
    let path = DIRECTORY
        .get_or_init(|| {
            arm();
            let root = std::env::temp_dir()
                .canonicalize()
                .expect("#3355 resolve temporary root");
            let dir = tempfile::tempdir_in(root).expect("#3355 allocate isolated key directory");
            assert_isolated(dir.path());
            bind_key_dir_env(dir.path());
            dir
        })
        .path();
    // Integration-test binaries compile this module without `cfg(test)`.
    // Re-assert so an ambient override set after the first `install()` still
    // cannot defeat the helper. Lib tests (`cfg(test)`) leave `AI_MEMORY_KEY_DIR`
    // to the tests that hold `key_dir_env_lock` (`default_key_dir_honours_env_override`).
    #[cfg(not(test))]
    bind_key_dir_env(path);
    path
}

/// The shared sandbox, but ONLY for a process that armed the guard (#3516).
///
/// An unarmed process gets `None` and falls through to the production
/// `dirs::config_dir()` resolution — the operator's real key store.
pub(crate) fn armed_sandbox() -> Option<&'static Path> {
    armed().then(install)
}

// Runs exactly once per process, inside `DIRECTORY`'s `OnceLock` initializer.
fn arm() {
    ARMED.store(true, Ordering::Release);
    // OnceLock-gated: at most once per process, test-setup window only.
    set_env(TEST_KEY_GUARD_ENV, "1");
}

/// Point `AI_MEMORY_KEY_DIR` at `path` (the sandbox), capturing the previous
/// value for restore-on-drop (#3584).
fn bind_key_dir_env(path: &Path) {
    KEY_DIR_BIND.get_or_init(|| {
        let prev = std::env::var_os(super::keypair::KEY_DIR_ENV);
        set_key_dir_env(path);
        KeyDirEnvBind { prev }
    });
    #[cfg(not(test))]
    if std::env::var_os(super::keypair::KEY_DIR_ENV).as_deref() != Some(path.as_os_str()) {
        set_key_dir_env(path);
    }
}

fn set_key_dir_env(path: &Path) {
    set_env(super::keypair::KEY_DIR_ENV, path);
}

fn set_env(key: &str, value: impl AsRef<OsStr>) {
    // SAFETY: `std::env::set_var` is `unsafe` on the 2024 edition because the
    // environment is process-global. Every caller is test-only (`install` /
    // its Drop bind). The first `AI_MEMORY_KEY_DIR` write is OnceLock-gated
    // (one thread, once per process); integration-test re-asserts run in a
    // binary whose parent tests do not concurrently mutate this key; the
    // #3584 ambient-override pin runs in a child process. Values are the
    // sandbox path, the captured previous value, or the `TEST_KEY_GUARD_ENV`
    // literal — never caller- or attacker-controlled. No production path
    // reaches `install`.
    unsafe {
        std::env::set_var(key, value);
    }
}

fn unset_env(key: &str) {
    // SAFETY: same contract as `set_env` — test-only restore of the
    // captured previous `AI_MEMORY_KEY_DIR` (absent → remove).
    unsafe {
        std::env::remove_var(key);
    }
}

// Lexical normalization happens BEFORE any filesystem access: a rejected path
// must not even stat the operator's keys. Existing isolated paths are then
// canonicalized to reject aliases into HOME, including macOS's /var alias.
fn absolute(path: &Path) -> PathBuf {
    let path = std::path::absolute(path).expect("#3355 resolve absolute test key path");
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => result.push(other.as_os_str()),
        }
    }
    result
}

pub(crate) fn assert_isolated(path: &Path) {
    // #3516 — an unarmed process is an operator process: never panic there.
    if !armed() {
        return;
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .or_else(|| dirs::home_dir().map(PathBuf::into_os_string))
        .expect("#3355 test key isolation requires an identifiable home directory");
    let home = absolute(Path::new(&home));
    let path = absolute(path);
    assert!(
        !path.starts_with(&home),
        "#3355 test key directory resolves under HOME; use identity::test_key_dir::install() or an isolated AI_MEMORY_KEY_DIR"
    );
    let canonical_home = home.canonicalize().unwrap_or(home);
    let mut ancestor = path.as_path();
    loop {
        if let Ok(canonical) = ancestor.canonicalize() {
            assert!(
                !canonical.starts_with(&canonical_home),
                "#3355 test key directory resolves under HOME through an alias"
            );
            break;
        }
        let Some(parent) = ancestor.parent() else {
            break;
        };
        ancestor = parent;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_agrees_with_default_key_dir() {
        // Serialise against `default_key_dir_honours_env_override`, which
        // mutates the same key. `install` itself does not take this lock
        // (a caller already holding it would deadlock on a std Mutex —
        // CONCURRENCY-04).
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = install();
        assert_eq!(
            crate::identity::keypair::default_key_dir().expect("resolve"),
            dir
        );
    }

    /// #3584 — `KeyDirEnvBind` restores the captured `AI_MEMORY_KEY_DIR`
    /// even when the holder panics (OWNERSHIP-24 / OWNERSHIP-25). The
    /// process-lifetime `OnceLock` bind is not dropped here; this pin
    /// constructs a local bind so Drop is observable in-process.
    #[test]
    fn key_dir_env_bind_restores_prior_on_panic_3584() {
        let _g = crate::identity::keypair::key_dir_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prior = std::env::var_os(crate::identity::keypair::KEY_DIR_ENV);
        let panicked = std::panic::catch_unwind(|| {
            let _bind = KeyDirEnvBind {
                prev: std::env::var_os(crate::identity::keypair::KEY_DIR_ENV),
            };
            set_key_dir_env(Path::new("/nonexistent-ai-memory-3584-probe"));
            panic!("3584-restore-probe");
        });
        assert!(
            panicked.is_err(),
            "#3584 restore pin must take the panic path"
        );
        assert_eq!(
            std::env::var_os(crate::identity::keypair::KEY_DIR_ENV),
            prior,
            "#3584: KeyDirEnvBind must restore AI_MEMORY_KEY_DIR on drop"
        );
    }
}
