// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3206 — end-to-end wiring of the NON-argv capability-token channel
//! `AI_MEMORY_CAPABILITY_FILE`.
//!
//! **Why this lives in its own integration binary with exactly ONE test.**
//! `std::env::set_var` is process-global. `governance::capability::resolve_capability`
//! is called unconditionally by `cli::store::run`, `cli::crud::cmd_delete` and
//! `cli::promote::cmd_promote`, so a unit test that exported this variable inside
//! the `--lib` binary would change the governance outcome of any CLI test running
//! concurrently in the same process — the #2905 env-leak class, and the reason
//! `src/governance/capability.rs` tests the resolution ORDER through the
//! env-value-as-parameter form instead. Cargo gives each integration binary its own
//! process, and one `#[test]` per binary means nothing else is running while the
//! variable is set.
//!
//! The property under test is the one the unit tests structurally cannot reach:
//! that `resolve_capability` reads *this exact variable name*, and that a
//! NAMED-but-unusable env file refuses fail-closed rather than silently
//! downgrading to "no token presented" (ERRORS-19).

use ai_memory::governance::capability::{CAPABILITY_FILE_ENV, resolve_capability};

fn write_0600(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write token file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600");
    }
    path
}

#[test]
fn capability_file_env_is_read_and_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let good = write_0600(tmp.path(), "cap.tok", "cap1:from-env\n");
    let missing = tmp.path().join("does-not-exist.tok");

    // Baseline: with the variable unset, argv is the only channel and an
    // absent token stays absent (the pre-#3206 behaviour, unchanged).
    // SAFETY: single-test integration binary — no other thread reads or writes
    // the environment for the duration of this test (see the module docs).
    unsafe { std::env::remove_var(CAPABILITY_FILE_ENV) };
    assert_eq!(
        resolve_capability(Some("cap1:from-argv"), None).expect("argv resolves"),
        Some("cap1:from-argv".to_string())
    );
    assert_eq!(
        resolve_capability(None, None).expect("nothing presented"),
        None
    );

    // The env channel is read, trimmed, and outranks argv.
    // SAFETY: as above.
    unsafe { std::env::set_var(CAPABILITY_FILE_ENV, good.as_os_str()) };
    assert_eq!(
        resolve_capability(Some("cap1:from-argv"), None).expect("env file resolves"),
        Some("cap1:from-env".to_string()),
        "{CAPABILITY_FILE_ENV} must outrank the argv token"
    );

    // An explicit --capability-file still outranks the env channel.
    assert_eq!(
        resolve_capability(None, Some(good.as_path())).expect("flag resolves"),
        Some("cap1:from-env".to_string())
    );

    // FAIL-CLOSED: a named-but-unreadable env file is an error, never a silent
    // downgrade to the argv token or to "no token presented".
    // SAFETY: as above.
    unsafe { std::env::set_var(CAPABILITY_FILE_ENV, missing.as_os_str()) };
    let err = resolve_capability(Some("cap1:from-argv"), None)
        .expect_err("a named-but-unreadable capability file must refuse");
    assert!(
        err.to_string().contains("capability file"),
        "expected a contextualised refusal, got: {err}"
    );

    // FAIL-CLOSED (ERRORS-19): a set-but-non-UTF-8 named env channel must
    // never silently become None → argv/anonymous. `var_os` + PathBuf
    // needs no UTF-8.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let non_utf8 = std::ffi::OsString::from_vec(vec![0xff, 0xfe, 0x2f, b'x']);
        // SAFETY: as above.
        unsafe { std::env::set_var(CAPABILITY_FILE_ENV, &non_utf8) };
        let err = resolve_capability(Some("cap1:from-argv"), None)
            .expect_err("a set-but-non-UTF-8 named env channel must refuse");
        assert!(
            err.to_string().contains("capability file"),
            "expected a contextualised refusal, got: {err}"
        );
    }

    // Clearing the variable restores the argv-only behaviour.
    // SAFETY: as above.
    unsafe { std::env::remove_var(CAPABILITY_FILE_ENV) };
    assert_eq!(
        resolve_capability(Some("cap1:from-argv"), None).expect("argv resolves again"),
        Some("cap1:from-argv".to_string())
    );
}
