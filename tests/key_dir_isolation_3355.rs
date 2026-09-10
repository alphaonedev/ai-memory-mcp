// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3355 key-directory isolation, re-armed explicitly per child (#3516).
//! #3584 — `install()` also binds `AI_MEMORY_KEY_DIR` to the sandbox so an
//! ambient harness override cannot defeat the helper.
//!
//! The guard is armed per PROCESS — `cfg(test)`, a call to
//! `test_key_dir::install()`, or the `TEST_KEY_GUARD_ENV` marker — never by
//! the `test-support` feature, which `cargo test` unifies into the shipped
//! `ai-memory` binary as well. Every probe child below is a TEST child, so it
//! carries the marker; `tests/key_dir_guard_not_in_binary_3516.rs` pins the
//! other half (an unmarked binary never sees the guard at all).

use ai_memory::identity::test_key_dir::TEST_KEY_GUARD_ENV;
use std::process::Command;

#[test]
fn resolver_probe() {
    if std::env::var_os("KEY_ISOLATION_PROBE_3355").is_none() {
        return;
    }
    let dir = ai_memory::identity::keypair::default_key_dir().expect("resolve key dir");
    let key = ai_memory::identity::keypair::generate("fixture-3355").unwrap();
    ai_memory::identity::keypair::save(&key, &dir).unwrap();
}

#[test]
fn resolver_panics_under_temporary_home_and_accepts_isolated_override() {
    let home = tempfile::tempdir().unwrap();
    let keys = tempfile::tempdir().unwrap();
    for (path, allowed) in [
        (home.path().join("keys"), false),
        (keys.path().to_path_buf(), true),
    ] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "resolver_probe", "--nocapture"])
            .env("KEY_ISOLATION_PROBE_3355", "1")
            .env(TEST_KEY_GUARD_ENV, "1")
            .env("HOME", home.path())
            .env("AI_MEMORY_KEY_DIR", &path)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            allowed,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if allowed {
            assert!(path.join("fixture-3355.priv").is_file());
        } else {
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("#3355 test key directory resolves under HOME")
            );
            assert!(
                !path.exists(),
                "guard must panic before creating a key directory"
            );
        }
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn ambient_override_probe() {
    if std::env::var_os("AMBIENT_KEY_DIR_PROBE_3584").is_none() {
        return;
    }
    let dir = ai_memory::identity::test_key_dir::install();
    let resolved = ai_memory::identity::keypair::default_key_dir().expect("resolve key dir");
    assert_eq!(
        resolved, dir,
        "install() must neutralize an ambient AI_MEMORY_KEY_DIR"
    );
    let ambient = std::env::var_os("AMBIENT_KEY_DIR_EXPECT_NOT").expect("ambient path");
    assert_ne!(
        resolved.as_os_str(),
        ambient.as_os_str(),
        "resolved key dir must not be the ambient override"
    );
    ai_memory::identity::keypair::save(
        &ai_memory::identity::keypair::generate("ambient-3584").unwrap(),
        dir,
    )
    .unwrap();
    assert!(dir.join("ambient-3584.priv").is_file());
}

/// Denied pin (#3584): with ambient `AI_MEMORY_KEY_DIR` set to a *different*
/// isolated directory, `install()` still owns `default_key_dir()`. The child
/// is a fresh process so the helper's `OnceLock` bind runs against the
/// inherited override. Product behaviour (explicit env beats the derived
/// default) is unchanged; the helper is what must not be defeatable.
#[test]
fn install_neutralises_ambient_key_dir_3584() {
    let ambient = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "ambient_override_probe", "--nocapture"])
        .env("AMBIENT_KEY_DIR_PROBE_3584", "1")
        .env(TEST_KEY_GUARD_ENV, "1")
        .env("AI_MEMORY_KEY_DIR", ambient.path())
        .env("AMBIENT_KEY_DIR_EXPECT_NOT", ambient.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !ambient.path().join("ambient-3584.priv").exists(),
        "writes must land in the sandbox, not the ambient override"
    );
}

#[test]
fn shared_helper_isolates_x25519_and_ed25519_writes() {
    let dir = ai_memory::identity::test_key_dir::install();
    assert_eq!(
        ai_memory::identity::keypair::default_key_dir().unwrap(),
        dir
    );
    ai_memory::encryption::get_or_create_keypair("isolated-x25519-3355").unwrap();
    ai_memory::identity::keypair::save(
        &ai_memory::identity::keypair::generate("isolated-ed25519-3355").unwrap(),
        dir,
    )
    .unwrap();
    assert!(dir.join("isolated-x25519-3355.x25519.priv").is_file());
    assert!(dir.join("isolated-ed25519-3355.priv").is_file());
}

#[test]
fn guarded_child_without_override_uses_the_shared_sandbox_instead_of_home() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "resolver_probe", "--nocapture"])
        .env("KEY_ISOLATION_PROBE_3355", "1")
        .env(TEST_KEY_GUARD_ENV, "1")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env_remove("AI_MEMORY_KEY_DIR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn resolver_rejects_a_symlink_alias_into_temporary_home() {
    let home = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let alias = outside.path().join("alias");
    std::os::unix::fs::symlink(home.path(), &alias).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "resolver_probe", "--nocapture"])
        .env("KEY_ISOLATION_PROBE_3355", "1")
        .env(TEST_KEY_GUARD_ENV, "1")
        .env("HOME", home.path())
        .env("AI_MEMORY_KEY_DIR", alias.join("keys"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("#3355 test key directory resolves under HOME through an alias")
    );
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}
