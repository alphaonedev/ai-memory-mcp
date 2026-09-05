// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3516 — the #3355 key-directory guard MUST NOT be reachable from a plain
//! `ai-memory` process.
//!
//! `Cargo.toml` carries a self dev-dependency
//! (`ai-memory = { path = ".", features = ["test-support"] }`), so every
//! `cargo test` unifies `test-support` into the whole build — including the
//! `ai-memory` BIN compiled for these integration tests, which overwrites
//! `target/{debug,release}/ai-memory`. Before the fix, the guard was gated on
//! `cfg(any(test, feature = "test-support"))`, so THAT binary — the one the
//! `Batman Mode acceptance gate` runs after `cargo test --release`, and the
//! one an operator runs out of a developer target — panicked with
//! `#3355 test key directory resolves under HOME` whenever the key directory
//! resolved under HOME, i.e. at the DEFAULT operator location.
//!
//! `CARGO_BIN_EXE_ai-memory` is exactly that binary: cargo builds the `bin`
//! target for this integration test with the unified feature set, so this
//! suite reproduces the shipped defect and pins the fix.
//!
//! Leg 1 (the regression): an UNMARKED child — `env_clear()`, an isolated
//! HOME, `AI_MEMORY_KEY_DIR` UNDER that HOME, no `TEST_KEY_GUARD_ENV` — runs
//! `rules keygen` and `doctor --json` to completion. It never panics and the
//! `#3355` text never appears.
//!
//! Leg 2 (the protection is intact): the SAME command with the marker set is
//! still refused by the guard, so #3355's isolation for test processes is
//! preserved rather than deleted.

use ai_memory::identity::test_key_dir::TEST_KEY_GUARD_ENV;
use std::path::{Path, PathBuf};
use std::process::Command;

const GUARD_MESSAGE: &str = "#3355 test key directory resolves under HOME";

/// A scratch HOME under the repo's gitignored `.local-runs/` (project
/// no-`/tmp` HARD RULE). Each call makes a fresh unique subdir.
fn scratch_home(leg: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("key-guard-3516");
    std::fs::create_dir_all(&root).expect("create .local-runs scratch root");
    let dir = root.join(format!(
        "{leg}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).expect("create scratch home");
    dir
}

/// #3198 — the key directory must be `0700`; `umask 0002`/`0022` would
/// otherwise leave it group-readable/writable and the posture gate (rightly)
/// refuses it, which would mask the panic this suite is looking for.
fn key_dir_0700(home: &Path) -> PathBuf {
    let keys = home.join("keys");
    std::fs::create_dir_all(&keys).expect("create key dir under HOME");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 key dir");
    }
    keys
}

/// The shipped binary with a CLEAN environment: an operator process, holding
/// a key directory that resolves UNDER HOME — the DEFAULT operator shape.
fn operator_cmd(home: &Path, keys: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear();
    // Minimal env a plain process has. Deliberately NO `TEST_KEY_GUARD_ENV`:
    // that marker is what a test child would carry, and this is not one.
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    cmd.env("HOME", home);
    cmd.env("XDG_CONFIG_HOME", home.join(".config"));
    cmd.env("AI_MEMORY_KEY_DIR", keys);
    // Do not read the developer host's config; nothing else about the run
    // depends on it.
    cmd.env("AI_MEMORY_NO_CONFIG", "1");
    cmd
}

/// `rules keygen --key-dir <keys> --out <keys>/operator.key` — the exact
/// shape the Batman acceptance gate runs against the built binary.
fn keygen_args(keys: &Path) -> [std::ffi::OsString; 6] {
    [
        "rules".into(),
        "keygen".into(),
        "--key-dir".into(),
        keys.as_os_str().to_os_string(),
        "--out".into(),
        keys.join("operator.key").into_os_string(),
    ]
}

fn assert_no_guard_panic(label: &str, out: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("#3355"),
        "{label}: the plain binary must never reach the #3355 key-dir guard \
         (#3516)\nstatus: {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );
    assert_ne!(
        out.status.code(),
        Some(101),
        "{label}: the plain binary panicked (#3516)\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
fn unmarked_binary_never_reaches_the_key_dir_guard() {
    let home = scratch_home("plain");
    let keys = key_dir_0700(&home);

    // 1. `rules keygen` — the exact call the Batman acceptance gate makes
    //    right after `cargo test --release` overwrites `target/release/ai-memory`.
    let out = operator_cmd(&home, &keys)
        .args(keygen_args(&keys))
        .output()
        .expect("spawn ai-memory rules keygen");
    assert_no_guard_panic("rules keygen", &out);
    assert!(
        out.status.success(),
        "rules keygen must succeed for an operator whose key dir is under \
         HOME\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // 2. `doctor` — resolves the key directory for its Identity section, so it
    //    hit the same guard. Warnings keep exit 0; only a CRITICAL exits 2.
    let db = home.join("m.db");
    let out = operator_cmd(&home, &keys)
        .arg("--db")
        .arg(&db)
        .args(["doctor", "--json"])
        .output()
        .expect("spawn ai-memory doctor");
    assert_no_guard_panic("doctor --json", &out);
    assert!(
        out.status.success(),
        "doctor must run to completion for an operator whose key dir is under \
         HOME\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn marked_child_still_refuses_a_key_dir_under_home() {
    let home = scratch_home("marked");
    let keys = key_dir_0700(&home);

    let out = operator_cmd(&home, &keys)
        .env(TEST_KEY_GUARD_ENV, "1")
        .args(keygen_args(&keys))
        .output()
        .expect("spawn ai-memory rules keygen (marked)");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "#3355 must still refuse a marked TEST child whose key dir is under \
         HOME\nstdout:\n{}\nstderr:\n{stderr}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        stderr.contains(GUARD_MESSAGE),
        "expected the #3355 guard message on a marked child, got:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&home);
}
