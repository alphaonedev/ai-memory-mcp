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

#[test]
fn no_config_boot_writes_no_config_toml_7192() {
    let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir under .local-runs");
    let home = dir.path().join("home");
    let key_dir = dir.path().join("keys");
    std::fs::create_dir_all(&home).expect("mkdir home");
    std::fs::create_dir_all(&key_dir).expect("mkdir key dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 key dir");
    }

    let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args(["identity", "generate", "--agent-id", "x", "--key-dir"])
        .arg(&key_dir)
        .current_dir(dir.path())
        .env_clear()
        .env("HOME", &home)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .output()
        .expect("spawn ai-memory");
    assert!(
        out.status.success(),
        "identity generate exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    let mut found = Vec::new();
    walk(&home, &mut found);
    if let Some(p) = found
        .iter()
        .find(|p| p.file_name().is_some_and(|n| n == "config.toml"))
    {
        panic!(
            "#7192: AI_MEMORY_NO_CONFIG=1 must not write a config.toml, found {}",
            p.display()
        );
    }
    // The only entries the subcommand legitimately creates: the (empty)
    // audit log directory chain `Library/Logs/ai-memory/audit` on macOS.
    let allowed: [&[&str]; 4] = [
        &["Library"],
        &["Library", "Logs"],
        &["Library", "Logs", "ai-memory"],
        &["Library", "Logs", "ai-memory", "audit"],
    ];
    let unexpected: Vec<&PathBuf> = found
        .iter()
        .filter(|p| {
            let rel: Vec<String> = p
                .strip_prefix(&home)
                .map(|r| r.iter().map(|c| c.to_string_lossy().into_owned()).collect())
                .unwrap_or_default();
            !allowed
                .iter()
                .any(|a| a.len() == rel.len() && a.iter().zip(&rel).all(|(x, y)| x == y))
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "#7192: unexpected entries under HOME: {unexpected:?}"
    );
}
