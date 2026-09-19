// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3859 — `identity::test_key_dir::isolated_temp_root()` must REFUSE a
//! HOME-rooted `$TMPDIR` and fall back off HOME.
//!
//! WHY A SEPARATE TEST BINARY (the control, not a style choice). This pin SETS
//! `$TMPDIR`, and eleven files under `src/` resolve their temp root through
//! `std::env::temp_dir()` (which reads `$TMPDIR`). In the shared `src/**`
//! `#[cfg(test)]` lib-test binary those readers run on parallel threads and take
//! no lock, so a `set_var("TMPDIR", ...)` there flips every concurrent reader's
//! temp root for the duration of the window — and restoring it afterwards does
//! not help, because the damage happens INSIDE the window and the victims are
//! the unlocked READERS (#3475 / `scripts/check-test-env-lock.sh` arm (d), a
//! wider blast radius than the `AI_MEMORY_AGENT_ID` case that gate documents).
//! The sound control is PROCESS isolation: a `tests/*.rs` file compiles to its
//! own binary and therefore its own process, so nothing here is observable by
//! the lib cohort no matter how either side is scheduled. This binary holds a
//! SINGLE test, so within its own process there is no concurrent reader either;
//! `$TMPDIR` is saved and restored regardless (RAII-style hygiene).
//!
//! `test_key_dir` is reachable here because integration tests link `ai-memory`
//! as a dev-dependency with `features = ["test-support"]` (Cargo.toml), the
//! same path `tests/key_dir_isolation_3355.rs` uses.

use ai_memory::identity::test_key_dir::{isolated_temp_root, resolved_home};
use std::path::{Path, PathBuf};

#[test]
fn isolated_temp_root_refuses_a_home_rooted_tmpdir_3859() {
    // Pin `isolated_temp_root()` DIRECTLY, never through `install()` (whose
    // `DIRECTORY` OnceLock caches the first sandbox, so a second call under a
    // different `$TMPDIR` returns the first answer and pins nothing). SET
    // `$TMPDIR` here rather than inherit it, so the contract holds on any runner
    // — including one whose `TMPDIR` is already off HOME (the MODLEG leg's
    // pinned env, and the reason this fix was otherwise UNPINNED where it
    // matters).
    let home = resolved_home();
    let saved = std::env::var_os("TMPDIR");
    // Positive: a HOME-rooted `$TMPDIR` is REFUSED; the root falls off HOME.
    // SAFETY: this binary's only test, its own process — no concurrent env reader.
    unsafe {
        std::env::set_var("TMPDIR", &home);
    }
    let under_home = isolated_temp_root();
    // Negative control: an off-HOME `$TMPDIR` is PREFERRED, not skipped — pins
    // the preference ORDER, not just the safety property.
    let off = PathBuf::from("/tmp");
    // SAFETY: same single-test own-process window.
    unsafe {
        std::env::set_var("TMPDIR", &off);
    }
    let off_home_root = isolated_temp_root();
    // Restore the caller's `$TMPDIR` BEFORE asserting so a failure cannot leak it.
    // SAFETY: same window.
    unsafe {
        match saved {
            Some(v) => std::env::set_var("TMPDIR", v),
            None => std::env::remove_var("TMPDIR"),
        }
    }
    assert!(
        !under_home.starts_with(&home),
        "#3859 a HOME-rooted $TMPDIR must be refused; isolated_temp_root returned {under_home:?} under HOME {home:?}"
    );
    let tmp = Path::new("/tmp").canonicalize().ok();
    let var_tmp = Path::new("/var/tmp").canonicalize().ok();
    assert!(
        Some(&under_home) == tmp.as_ref() || Some(&under_home) == var_tmp.as_ref(),
        "#3859 with a HOME-rooted $TMPDIR the root must be a canonical fallback (/tmp or /var/tmp); got {under_home:?}"
    );
    assert_eq!(
        off_home_root,
        off.canonicalize().expect("/tmp canonicalizes"),
        "#3859 an off-HOME $TMPDIR must be preferred as-is, not skipped to a fallback"
    );
}
