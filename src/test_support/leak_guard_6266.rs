// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6266 — lib-test scratch-leak guard (follow-on to the #6122 integration
//! guard `tests/tmp_leak_guard_6122.rs`).
//!
//! Re-runs a representative set of the lib tests that used to orphan scratch
//! state, in a child copy of this very test binary with a private `TMPDIR`,
//! and asserts the directory is EMPTY afterwards. The leak classes pinned:
//!
//! * `identity::test_key_dir::DIRECTORY` and `POSTURE_AUDIT_DIR` are `static`
//!   `TempDir`s that no destructor ever removed (one `.tmp*` / `ef-posture-audit-*`
//!   directory per test process, plus one per env-isolated child);
//! * sqlite scratch databases whose `-wal` / `-shm` / `.pre-migration-*.bak`
//!   siblings outlived the `NamedTempFile` that owned the main file.

use std::path::Path;

/// Exact test paths; each one is known to leave scratch behind on the carrier.
const LEAKING_TESTS: [&str; 4] = [
    // TestEnv::fresh() arms the process-wide key-dir sandbox (static TempDir).
    "cli::governance_migrate::tests::run_errors_when_input_missing",
    // Static key dir + POSTURE_AUDIT_DIR, in an env-isolated child process.
    "enterprise_federation_posture::tests::trust_domain_unset_fails",
    // NamedTempFile database + migration backup sibling.
    "storage::connection::tests::open_succeeds_on_legacy_pre_v36_memories_shape",
    // NamedTempFile database + static key dir.
    "storage::connection::tests::encrypt_at_rest_on_non_sqlcipher_opens_s1",
];

fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn issue_6266_lib_tests_leave_no_scratch_in_tmpdir() {
    let exe = std::env::current_exe().expect("current_exe for #6266 leak guard");
    let scratch = tempfile::tempdir().expect("#6266 private TMPDIR");
    for exact in LEAKING_TESTS {
        let output =
            crate::spawn_audit::audited_command(exe.clone(), "test_support::leak_guard_6266")
                .args(["--exact", exact, "--test-threads=1"])
                .env("TMPDIR", scratch.path())
                .env("AI_MEMORY_NO_CONFIG", "1")
                .output()
                .expect("spawn #6266 leak-guard child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "#6266 guard child {exact} did not pass:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let left = leftovers(scratch.path());
    assert!(
        left.is_empty(),
        "#6266: lib tests left {} entries in TMPDIR: {left:?}",
        left.len()
    );
}
