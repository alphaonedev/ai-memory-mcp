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
    // #3705 review — the ALLOWED key dir must not inherit the ambient umask
    // (0002 on this host yields 0775, which the #3198 check refuses — the
    // refusal is the product being right; the fixture is what was wrong).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(keys.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
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

#[test]
fn witness_resolver_probe_10156() {
    if std::env::var_os("WITNESS_ISOLATION_PROBE_10156").is_none() {
        return;
    }
    let dir = ai_memory::governance::audit::witness_key_dir().expect("resolve witness dir");
    let home = std::env::var_os("WITNESS_HOME_FORBIDDEN_10156").map(std::path::PathBuf::from);
    if let Some(h) = home {
        assert!(
            !dir.starts_with(&h),
            "witness_key_dir resolved under HOME: {} (HOME={})",
            dir.display(),
            h.display()
        );
    }
    if std::env::var_os("WITNESS_EXPECT_DISTINCT_FROM_KEYS_10156").is_some() {
        let key_dir = ai_memory::identity::keypair::default_key_dir().expect("resolve key dir");
        assert_ne!(
            dir, key_dir,
            "witness custody sandbox must stay distinct from daemon key sandbox"
        );
    }
    std::fs::create_dir_all(&dir).expect("create isolated witness dir");
    std::fs::write(dir.join("probe-10156"), b"ok").expect("write probe");
}

#[test]
fn witness_dir_panics_under_temporary_home_and_accepts_isolated_override_10156() {
    let home = tempfile::tempdir().unwrap();
    let witness = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(witness.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for (path, allowed) in [
        (home.path().join("witness-keys"), false),
        (witness.path().to_path_buf(), true),
    ] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "witness_resolver_probe_10156", "--nocapture"])
            .env("WITNESS_ISOLATION_PROBE_10156", "1")
            .env(TEST_KEY_GUARD_ENV, "1")
            .env("HOME", home.path())
            .env("AI_MEMORY_WITNESS_KEY_DIR", &path)
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            allowed,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if allowed {
            assert!(path.join("probe-10156").is_file());
        } else {
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("#10156 test witness custody directory resolves under HOME"),
                "stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !path.exists(),
                "guard must panic before touching witness dir under HOME"
            );
        }
    }
    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
}

#[test]
fn guarded_child_witness_without_override_uses_sandbox_instead_of_home_10156() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "witness_resolver_probe_10156", "--nocapture"])
        .env("WITNESS_ISOLATION_PROBE_10156", "1")
        .env("WITNESS_HOME_FORBIDDEN_10156", home.path())
        .env("WITNESS_EXPECT_DISTINCT_FROM_KEYS_10156", "1")
        .env(TEST_KEY_GUARD_ENV, "1")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env_remove("AI_MEMORY_WITNESS_KEY_DIR")
        .env_remove("AI_MEMORY_KEY_DIR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn witness_resolver_rejects_symlink_alias_into_temporary_home_10156() {
    let home = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let alias = outside.path().join("witness-alias");
    std::os::unix::fs::symlink(home.path(), &alias).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "witness_resolver_probe_10156", "--nocapture"])
        .env("WITNESS_ISOLATION_PROBE_10156", "1")
        .env(TEST_KEY_GUARD_ENV, "1")
        .env("HOME", home.path())
        .env("AI_MEMORY_WITNESS_KEY_DIR", alias.join("witness-keys"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("#10156 test witness custody directory resolves under HOME through an alias"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
}
