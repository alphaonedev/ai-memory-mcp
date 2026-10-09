// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4074 — the #1048 `hmac_secret` boot validator must REFUSE a non-hex
//! value with a typed error, never panic.
//!
//! The hex decoder behind `validate_hmac_secret_hex` checked only that the
//! value's BYTE length was even, then sliced the `&str` two bytes at a time.
//! A value whose byte length is even but which carries a multi-byte UTF-8
//! code point (a single 4-byte emoji, `a€`, `éé`) made the slice cut inside
//! the code point, which panics. The boot validator unwound instead of
//! returning its `Err`, so `main` never printed the `boot refused` diagnostic
//! and exited 101 instead of `EX_CONFIG` (78). `u8::from_str_radix` also
//! accepts a leading `+`, so `+f+f` passed as hex.
//!
//! The library cells call the validator under `catch_unwind` so a panic is a
//! test FAILURE with a message, not a harness abort. The binary cell drives
//! the shipped entry point in a subprocess with its own `$HOME` (never
//! `std::env::set_var` in this process).

use std::path::PathBuf;
use std::process::{Command, Output};

/// `sysexits.h` `EX_CONFIG` — mirrored on purpose: the test pins the
/// externally observable contract, so it must not import the constant.
const EX_CONFIG: i32 = 78;

/// Even-byte-length values that are not hex. Each one used to panic the
/// pair slicer (multi-byte code points) or be accepted (`+f+f`).
const INVALID_SECRETS: &[&str] = &[
    "\u{1F600}",     // one 4-byte code point
    "a\u{20AC}",     // `a€`: 1 + 3 bytes
    "\u{E9}\u{E9}",  // `éé`: 2 + 2 bytes
    "+f+f",          // sign prefix accepted by `from_str_radix`
    "abc",           // odd length ASCII
    "zz",            // non-hex ASCII
    "00\u{1F600}00", // valid pairs around a multi-byte code point
];

/// Run the validator, turning a panic into an observable value.
fn validate(secret: &str) -> std::thread::Result<Result<(), String>> {
    let owned = secret.to_owned();
    std::panic::catch_unwind(move || {
        ai_memory::subscriptions::validate_hmac_secret_hex(Some(owned.as_str()))
    })
}

#[test]
fn validator_refuses_every_non_hex_secret_without_panicking_4074() {
    for secret in INVALID_SECRETS {
        let outcome = validate(secret);
        let verdict = outcome.unwrap_or_else(|_| {
            panic!("#4074: the validator PANICKED on {secret:?} instead of returning Err")
        });
        assert!(
            verdict.is_err(),
            "#4074: a non-hex hmac_secret {secret:?} must be refused, got Ok"
        );
    }
}

#[test]
fn validator_still_accepts_valid_hex_4074() {
    for secret in [
        "deadbeef",
        "DEADBEEF",
        "00ff",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ] {
        let verdict = validate(secret).expect("valid hex must not panic");
        assert!(verdict.is_ok(), "valid hex {secret:?} refused: {verdict:?}");
    }
}

/// Scratch root under the repo's gitignored `.local-runs/` (project
/// no-`/tmp` rule), mirroring `tests/boot_fail_closed_config_3166.rs`.
fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-4074-hmac-non-ascii");
    std::fs::create_dir_all(&root).ok();
    root
}

/// Run `ai-memory stats --json` against a sandbox whose `config.toml`
/// carries `hmac_secret`. Returns the output and the sandbox (kept alive).
fn boot_with_secret(secret: &str) -> (Output, tempfile::TempDir) {
    let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir under .local-runs");
    let home = dir.path().join("home");
    let config_dir = home.join(".config").join("ai-memory");
    let cwd = dir.path().join("cwd");
    std::fs::create_dir_all(&config_dir).expect("mkdir config dir");
    std::fs::create_dir_all(&cwd).expect("mkdir cwd");
    let db = dir.path().join("boot-4074.db");
    let body = format!(
        "db = \"{}\"\ntier = \"keyword\"\n\n[hooks.subscription]\nhmac_secret = \"{secret}\"\n",
        db.display()
    );
    std::fs::write(config_dir.join("config.toml"), body).expect("write config.toml");
    let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args(["stats", "--json"])
        .current_dir(&cwd)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env_remove("AI_MEMORY_DB")
        .env_remove("AI_MEMORY_NO_CONFIG")
        .output()
        .expect("spawn ai-memory");
    (out, dir)
}

#[test]
fn binary_refuses_non_ascii_hmac_secret_with_ex_config_4074() {
    for secret in ["\u{1F600}", "a\u{20AC}", "\u{E9}\u{E9}"] {
        let (out, _sandbox) = boot_with_secret(secret);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("panicked"),
            "#4074: boot PANICKED on hmac_secret {secret:?}; stderr={stderr}"
        );
        assert_eq!(
            out.status.code(),
            Some(EX_CONFIG),
            "#4074: a non-hex hmac_secret {secret:?} must refuse boot with EX_CONFIG; \
             stderr={stderr}"
        );
        assert!(
            stderr.contains("boot refused") && stderr.contains("hmac_secret"),
            "#4074: expected the #1048 boot-refusal diagnostic; stderr={stderr}"
        );
    }
}

#[test]
fn binary_boots_with_valid_hex_hmac_secret_4074() {
    let (out, _sandbox) =
        boot_with_secret("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    assert!(
        out.status.success(),
        "a valid hex hmac_secret must boot; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}
