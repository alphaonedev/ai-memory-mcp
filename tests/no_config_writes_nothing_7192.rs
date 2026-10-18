// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7192 (regression of #3606) — `AI_MEMORY_NO_CONFIG=1` must not write a
//! default `config.toml` into the caller's HOME.
//!
//! #3603 made `config_path()` quiet under the escape hatch but left the
//! boot-time `AppConfig::write_default_if_missing()` call in `src/main.rs`
//! unguarded, so every `NO_CONFIG` child still created
//! `~/.config/ai-memory/config.toml`. This drives the REAL binary with a
//! scratch HOME and a cleared environment (the harness shape of
//! `tests/boot_fail_closed_config_3166.rs`) and walks the whole HOME.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Scratch root under the repo's gitignored `.local-runs/` (project no-`/tmp`
/// HARD RULE), mirroring `tests/boot_fail_closed_config_3166.rs`.
fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-7192-no-config-writes-nothing");
    std::fs::create_dir_all(&root).ok();
    root
}

/// Every file or directory path below `dir`, depth-first.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        out.push(p.clone());
        if p.is_dir() {
            walk(&p, out);
        }
    }
}

/// Run `identity generate` against a fresh scratch layout and return the
/// fake HOME plus every entry found below it. The audit directory is pinned
/// OUTSIDE the fake HOME (`AI_MEMORY_AUDIT_DIR`, precedence in
/// `src/log_paths.rs`), so the walk is identical on macOS and Linux.
fn boot_in_fresh_home(no_config: bool) -> (tempfile::TempDir, PathBuf, Vec<PathBuf>) {
    let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir under .local-runs");
    let home = dir.path().join("home");
    let key_dir = dir.path().join("keys");
    let audit_dir = dir.path().join("audit");
    std::fs::create_dir_all(&home).expect("mkdir home");
    std::fs::create_dir_all(&key_dir).expect("mkdir key dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 key dir");
    }

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.args(["identity", "generate", "--agent-id", "x", "--key-dir"])
        .arg(&key_dir)
        .current_dir(dir.path())
        .env_clear()
        .env("HOME", &home)
        .env("AI_MEMORY_AUDIT_DIR", &audit_dir)
        .env("AI_MEMORY_KEY_DIR", &key_dir);
    if no_config {
        cmd.env("AI_MEMORY_NO_CONFIG", "1");
    } else {
        cmd.env_remove("AI_MEMORY_NO_CONFIG");
    }
    let out = cmd.output().expect("spawn ai-memory");
    assert!(
        out.status.success(),
        "identity generate exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let mut found = Vec::new();
    walk(&home, &mut found);
    (dir, home, found)
}

#[test]
fn no_config_boot_writes_no_config_toml_7192() {
    let (_dir, home, found) = boot_in_fresh_home(true);
    if let Some(p) = found
        .iter()
        .find(|p| p.file_name().is_some_and(|n| n == "config.toml"))
    {
        panic!(
            "#7192: AI_MEMORY_NO_CONFIG=1 must not write a config.toml, found {}",
            p.display()
        );
    }
    // `identity generate` is a key-provisioning verb (no boot key ensure,
    // src/main.rs `is_key_provisioning_verb`) and gets an explicit
    // `--key-dir`, so with the audit directory pinned outside HOME this
    // NO_CONFIG boot leaves HOME empty on every OS; other verbs legitimately
    // create the host signing key under HOME.
    assert!(
        found.is_empty(),
        "#7192: NO_CONFIG boot left entries under {}: {found:?}",
        home.display()
    );
}

/// #3606 control leg: the same boot WITHOUT the escape hatch creates the
/// default config, so the test above cannot pass vacuously (a mutant that
/// drops the writer call entirely fails here).
#[test]
fn unflagged_boot_still_writes_default_config_7192() {
    let (_dir, home, _found) = boot_in_fresh_home(false);
    let expected = home.join(".config").join("ai-memory").join("config.toml");
    assert!(
        expected.exists(),
        "#7192 control: an unflagged boot must create {}",
        expected.display()
    );
}
