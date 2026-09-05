// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

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
fn unarmed_library_uses_the_shared_sandbox_instead_of_home() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "resolver_probe", "--nocapture"])
        .env("KEY_ISOLATION_PROBE_3355", "1")
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
