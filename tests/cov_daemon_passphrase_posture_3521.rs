// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3521 — the at-rest passphrase file's permission posture (#1055 / #1790).
//!
//! A group- or world-readable passphrase file is a readable CORPUS: anything
//! that can read it can decrypt every sealed row. The loader therefore
//! REFUSES such a file by default and accepts it only under an explicit,
//! documented legacy opt-out. Both halves are pinned here, plus the property
//! the #1790 fix exists for: the bytes returned come from the SAME handle
//! that was permission-checked, so a decoy cannot be swapped in between the
//! check and the read.
//!
//! These cases mutate the process-global environment, so per
//! `scripts/check-test-env-lock.sh` arm (d) (#3475) they live in their own
//! test binary rather than in the shared lib test binary whose cases run on
//! parallel threads.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;

use ai_memory::daemon_runtime::passphrase_from_file;

const ALLOW_LAX_ENV: &str = "AI_MEMORY_PASSPHRASE_FILE_ALLOW_LAX_PERMS";
const SECRET: &str = "correct horse battery staple";

/// SAFETY: this binary's cases are the only writers of this variable and
/// they run in one process; each clears it before returning.
unsafe fn set_allow_lax(on: bool) {
    unsafe {
        if on {
            std::env::set_var(ALLOW_LAX_ENV, "1");
        } else {
            std::env::remove_var(ALLOW_LAX_ENV);
        }
    }
}

fn write_passphrase(dir: &std::path::Path, mode: u32) -> std::path::PathBuf {
    let path = dir.join("passphrase-3521");
    std::fs::write(&path, format!("{SECRET}\n")).expect("write passphrase file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    path
}

/// A `0400` file is the intended posture and reads back exactly, trimmed.
#[test]
fn a_tight_passphrase_file_is_accepted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = write_passphrase(tmp.path(), 0o400);
    // SAFETY: see the helper's contract.
    unsafe { set_allow_lax(false) };
    let got = passphrase_from_file(&path).expect("a 0400 passphrase file is accepted");
    assert_eq!(got.trim(), SECRET);
}

/// A group/world-readable file is REFUSED by default, and the refusal names
/// the posture problem rather than failing opaquely.
#[test]
fn a_lax_passphrase_file_is_refused_by_default() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = write_passphrase(tmp.path(), 0o644);
    // SAFETY: see the helper's contract.
    unsafe { set_allow_lax(false) };
    let err = passphrase_from_file(&path)
        .expect_err("a group/world-readable passphrase file must be refused")
        .to_string();
    assert!(
        err.contains("lax permissions") || err.contains("chmod"),
        "the refusal must name the posture problem; got: {err}"
    );
}

/// The documented legacy opt-out accepts the same lax file — and returns the
/// bytes of the handle it checked, not of a path re-opened afterwards.
#[test]
fn the_legacy_opt_out_accepts_a_lax_passphrase_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = write_passphrase(tmp.path(), 0o644);
    // SAFETY: see the helper's contract.
    unsafe { set_allow_lax(true) };
    let got = passphrase_from_file(&path);
    // SAFETY: same contract; clear before asserting so a panic cannot leak
    // the opt-out into the sibling cases.
    unsafe { set_allow_lax(false) };
    assert_eq!(
        got.expect("the explicit legacy opt-out accepts").trim(),
        SECRET,
        "the opt-out must read the SAME handle it permission-checked"
    );
}
