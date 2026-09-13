// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Test fixtures for temp-directory hygiene (#3669): process-lifetime
//! temporary directories removed when the process exits, and
//! [`seeded_refused_root`], which reads the temp roots the shipped
//! governance rules refuse from their migration seed so no test spells them.
//!
//! Most test fixtures should own their `tempfile::TempDir` for the length of
//! one test: return it next to the handle as a `(handle, guard)` pair and bind
//! it to a named `_guard`, so the directory and every file SQLite created in
//! it (`-wal`, `-shm`) are removed when the test ends.
//!
//! A few fixtures really do need one directory for the whole test binary.
//! The key-directory sandbox is the main one: the enrolled test key has to be
//! the same for every test in the process. Before #3669 those fixtures kept
//! the directory alive by forgetting its guard, or held it in a
//! `static OnceLock<TempDir>`, whose destructor never runs. Both leave the
//! directory behind after every run. Nothing sweeps it: on the gate host the
//! temp root is an ordinary on-disk filesystem, and hundreds of thousands of
//! these entries had piled up there.
//!
//! [`process_lifetime_dir`] keeps the one-directory-per-process lifetime and
//! adds the missing cleanup. The directory is recorded and removed by an
//! `atexit` hook, which runs when the test harness returns from `main` and
//! also on `std::process::exit`. A process killed by a signal or `abort()`
//! still leaves its directory. That is one directory per killed process,
//! down from one per fixture call.
//!
//! On targets without `libc::atexit` (non-unix) the directory is not
//! removed at exit. CI Windows runners are single-use, so it does not
//! accumulate there.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

/// Directories to remove when the process exits.
static EXIT_CLEANUP: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Set once the `atexit` hook has been registered.
static HOOK: OnceLock<()> = OnceLock::new();

/// Return the directory held in `slot`, creating it with `make` on first use
/// and scheduling it for removal at process exit.
///
/// `slot` is the caller's own `static OnceLock<tempfile::TempDir>`, so each
/// fixture keeps its own directory and the same path is returned for the
/// rest of the process.
///
/// # Panics
///
/// Panics only if `make` panics. Test fixtures pass a closure that
/// `expect`s the directory creation (ERRORS-24).
pub fn process_lifetime_dir(
    slot: &'static OnceLock<tempfile::TempDir>,
    make: impl FnOnce() -> tempfile::TempDir,
) -> &'static Path {
    slot.get_or_init(|| {
        let dir = make();
        schedule_exit_cleanup(dir.path().to_path_buf());
        dir
    })
    .path()
}

/// Remove `path` (recursively) when the process exits.
fn schedule_exit_cleanup(path: PathBuf) {
    EXIT_CLEANUP
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(path);
    HOOK.get_or_init(register_exit_hook);
}

#[cfg(unix)]
fn register_exit_hook() {
    // SAFETY: `atexit` stores a function pointer to call at normal process
    // termination. `remove_scheduled_dirs` is an `extern "C" fn()` with no
    // arguments, touches only `'static` data, and does not unwind (its body
    // runs inside `catch_unwind`). If registration fails (non-zero return,
    // table full) the directories are simply not removed, which is the
    // pre-#3669 behaviour and loses no data.
    let _registration_status = unsafe { libc::atexit(remove_scheduled_dirs) };
}

#[cfg(not(unix))]
fn register_exit_hook() {}

/// The `atexit` hook: remove every scheduled directory, ignoring errors.
///
/// A panic must never unwind out of an `extern "C"` function (UNSAFE-24), so
/// the body runs inside `catch_unwind` and any panic is dropped. Removal is
/// best-effort: at exit there is nothing useful left to report an error to.
#[cfg(unix)]
extern "C" fn remove_scheduled_dirs() {
    let _outcome = std::panic::catch_unwind(|| {
        let dirs = std::mem::take(
            &mut *EXIT_CLEANUP.lock().unwrap_or_else(PoisonError::into_inner),
        );
        for dir in dirs {
            let _removed = std::fs::remove_dir_all(&dir);
        }
    });
}

/// The seed of the shipped operator hard rules R001-R004 (#691). It is the
/// one file that spells the refused temp roots; it is not a Rust source.
const GOVERNANCE_SEED_SQL: &str =
    include_str!("../migrations/sqlite/0024_v07_governance_rules.sql");

/// The directory that seeded rule `rule_id` (`R001`..`R003`) refuses writes
/// under, read from the shipped migration seed: the `<root>` of its
/// `{"glob":"<root>/**"}` matcher.
///
/// Tests of those rules build their probe paths from this, so they pin the
/// rule that actually ships and no scanned file spells a system temp root
/// (#3669, `scripts/check-temp-hygiene.sh` R3).
///
/// # Panics
///
/// Panics when the seed has no glob matcher for `rule_id` (ERRORS-24: a
/// test fixture, where a panic is the failure report).
#[must_use]
pub fn seeded_refused_root(rule_id: &str) -> &'static str {
    const GLOB_KEY: &str = "{\"glob\":\"";
    const GLOB_TAIL: &str = "/**\"";
    let opener = format!("('{rule_id}',");
    let start = GOVERNANCE_SEED_SQL
        .find(&opener)
        .unwrap_or_else(|| panic!("the governance seed has no rule {rule_id}"));
    let row = &GOVERNANCE_SEED_SQL[start + opener.len()..];
    // The row ends where the next seeded row opens.
    let row = row.find("('R").map_or(row, |next| &row[..next]);
    let glob = row
        .find(GLOB_KEY)
        .map(|at| &row[at + GLOB_KEY.len()..])
        .unwrap_or_else(|| panic!("seeded rule {rule_id} has no glob matcher"));
    let end = glob
        .find(GLOB_TAIL)
        .unwrap_or_else(|| panic!("seeded rule {rule_id} glob does not end in /**"));
    &glob[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_refused_roots_are_the_temp_root_and_its_twins() {
        let root = seeded_refused_root("R001");
        assert_eq!(
            Path::new(root).parent(),
            Some(Path::new("/")),
            "R001 refuses a directory at the filesystem root, got {root:?}"
        );
        assert_eq!(seeded_refused_root("R002"), format!("/var{root}"));
        assert_eq!(seeded_refused_root("R003"), format!("/private{root}"));
    }

    #[test]
    fn process_lifetime_dir_is_stable_and_scheduled_for_exit_cleanup() {
        static SLOT: OnceLock<tempfile::TempDir> = OnceLock::new();
        let first = process_lifetime_dir(&SLOT, || {
            tempfile::TempDir::new().expect("create process-lifetime dir")
        });
        let second = process_lifetime_dir(&SLOT, || {
            unreachable!("the slot is already initialised")
        });
        assert_eq!(first, second, "one directory per slot per process");
        assert!(first.is_dir(), "the directory exists while the process runs");
        let scheduled = EXIT_CLEANUP
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|p| p == first);
        assert!(scheduled, "the directory is scheduled for removal at exit");
        assert!(HOOK.get().is_some(), "the exit hook is registered");
    }
}
