// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 slice 1 (K-8): the repository cargo config arms the test key
//! sandbox for EVERY process cargo starts, so an integration test binary that
//! never calls `identity::test_key_dir::install()` still resolves its daemon
//! key directory inside an isolated private sandbox, never under HOME.
//!
//! This binary deliberately never calls `install()`: arming must come from
//! the `.cargo/config.toml` `[env]` table alone.
//!
//! Why the table sets the guard and not a key directory path: the #3355 guard
//! (`test_key_dir::assert_isolated`) panics on any key directory under HOME,
//! and a CI checkout (`/home/runner/work/...`) and a developer checkout both
//! sit under HOME, so a repository-relative key directory would panic every
//! armed test. The guard alone routes an armed process to `install()`'s
//! off-HOME `0700` private sandbox, which is the existing helper K-8 names.

use std::path::{Path, PathBuf};

use ai_memory::identity::test_key_dir::{TEST_KEY_GUARD_ENV, resolved_home};

/// The tracked cargo config that carries the `[env]` table.
const CARGO_CONFIG_REL: &str = ".cargo/config.toml";
/// The exact value the table must give the guard variable.
const GUARD_VALUE: &str = "1";
/// The key directory override variable (`identity::keypair::KEY_DIR_ENV`).
const KEY_DIR_ENV: &str = "AI_MEMORY_KEY_DIR";

fn cargo_config_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(CARGO_CONFIG_REL)
}

/// (a) red-first: a binary that never called `install()` is armed by the
/// cargo config and its default key directory resolves outside HOME.
#[test]
fn an_unarmed_test_binary_resolves_an_isolated_key_dir_10108() {
    assert_eq!(
        std::env::var(TEST_KEY_GUARD_ENV).ok().as_deref(),
        Some(GUARD_VALUE),
        "cargo must export {TEST_KEY_GUARD_ENV}={GUARD_VALUE} from {CARGO_CONFIG_REL} [env]"
    );
    assert!(
        ai_memory::identity::test_key_dir::armed(),
        "the guard must be armed without install()"
    );
    let dir = ai_memory::identity::keypair::default_key_dir()
        .expect("the armed sandbox key directory resolves");
    let home = resolved_home();
    assert!(
        !dir.starts_with(&home),
        "key directory {} must not resolve under HOME {}",
        dir.display(),
        home.display()
    );
    let canonical_home = home.canonicalize().unwrap_or(home);
    let canonical_dir = dir.canonicalize().expect("sandbox exists");
    assert!(
        !canonical_dir.starts_with(&canonical_home),
        "key directory {} must not alias into HOME",
        canonical_dir.display()
    );
}

/// (a) second half: the config entry is present with the exact value, and the
/// table carries no key directory path (a path would be under HOME on CI and
/// panic the #3355 guard; `install()` stays authoritative, #3584).
#[test]
fn the_cargo_config_env_entry_is_pinned_10108() {
    let text = std::fs::read_to_string(cargo_config_path())
        .expect("the tracked .cargo/config.toml is readable");
    let table: toml::Table = toml::from_str(&text).expect(".cargo/config.toml parses");
    let env = table
        .get("env")
        .and_then(toml::Value::as_table)
        .expect("[env] table present");
    assert_eq!(
        env.get(TEST_KEY_GUARD_ENV).and_then(toml::Value::as_str),
        Some(GUARD_VALUE),
        "[env] {TEST_KEY_GUARD_ENV} must be the plain string {GUARD_VALUE:?}"
    );
    assert!(
        env.get(KEY_DIR_ENV).is_none(),
        "[env] must not set {KEY_DIR_ENV}: install() picks the off-HOME sandbox"
    );
    let allowed = [TEST_KEY_GUARD_ENV];
    for key in env.keys() {
        assert!(
            allowed.contains(&key.as_str()),
            "[env] key {key} is not on the allowlist {allowed:?}"
        );
    }
}
