// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared key-directory sandbox for unit and integration tests.
//! Armed test processes use it as their default; an explicit environment
//! override is still checked and panics if it resolves under HOME.
//! Child processes must receive `AI_MEMORY_KEY_DIR` with [`install`] as its
//! value (and, when the spawner calls `env_clear()`, the
//! [`TEST_KEY_GUARD_ENV`] marker alongside it).
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
/// Call this from test setup. It exports [`TEST_KEY_GUARD_ENV`] once so child
/// processes stay guarded; nothing else in the process environment is touched.
///
/// # Panics
/// Panics if a private temporary directory cannot be allocated outside HOME.
#[must_use]
pub fn install() -> &'static Path {
    DIRECTORY
        .get_or_init(|| {
            arm();
            let root = std::env::temp_dir()
                .canonicalize()
                .expect("#3355 resolve temporary root");
            let dir = tempfile::tempdir_in(root).expect("#3355 allocate isolated key directory");
            assert_isolated(dir.path());
            dir
        })
        .path()
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
    // SAFETY: `std::env::set_var` is `unsafe` on the 2024 edition because the
    // environment is process-global. This write happens at most ONCE per
    // process (it is inside the `OnceLock` initializer) and only from
    // `install`, whose contract is "call from test setup", i.e. the same
    // window in which `cli::test_utils::ensure_no_config_env` and
    // `tests/common/mod.rs::ensure_no_config_env` already perform their
    // `Once`-gated `AI_MEMORY_NO_CONFIG` write — this adds no new hazard
    // class. The value is a fixed literal, never caller- or
    // attacker-controlled, and no production code path reaches `install`.
    unsafe { std::env::set_var(TEST_KEY_GUARD_ENV, "1") };
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
