// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4074 — the #1048 `hmac_secret` boot validator must REFUSE a non-ASCII
//! value with `EX_CONFIG`, never panic.
//!
//! Pre-fix, `subscriptions::hex_decode` checked only that the BYTE length
//! was even and then sliced the `&str` in two-byte steps. A value whose byte
//! length is even but which contains a multi-byte code point (a single
//! 4-byte emoji, `a€`) made `&s[i..i + 2]` cut inside the code point, so the
//! validator unwound instead of returning its documented `Err`: `main` never
//! printed the `boot refused` diagnostic and the process died with the
//! panic exit code (101) instead of the sysexits `EX_CONFIG` (78) that
//! supervisors and installers key on.
//!
//! Every cell drives the REAL binary in a subprocess with its own `$HOME`
//! and working directory (never `std::env::set_var` in this process), the
//! same harness shape as `tests/boot_fail_closed_config_3166.rs`.

use std::path::PathBuf;
use std::process::{Command, Output};

/// `sysexits.h` `EX_CONFIG`, mirrored on purpose: the test pins the
/// externally observable contract, so it must not import the constant.
const EX_CONFIG: i32 = 78;

/// Scratch root under the repo's gitignored `.local-runs/` (no `/tmp`).
fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-4074-hmac-non-ascii");
    std::fs::create_dir_all(&root).ok();
    root
}

struct Sandbox {
    _dir: tempfile::TempDir,
    home: PathBuf,
    cwd: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir under .local-runs");
        let home = dir.path().join("home");
        let cwd = dir.path().join("cwd");
        std::fs::create_dir_all(home.join(".config").join("ai-memory")).expect("mkdir config");
        std::fs::create_dir_all(&cwd).expect("mkdir cwd");
        Self {
            _dir: dir,
            home,
            cwd,
        }
    }

    /// Write a config whose only non-default knob is the server-wide
    /// webhook `hmac_secret`, then run `stats --json` against it.
    fn run_with_secret(&self, secret: &str) -> Output {
        let db = self.cwd.join("configured.db");
        let body = format!(
            "db = \"{}\"\ntier = \"keyword\"\n\n[hooks.subscription]\nhmac_secret = \"{secret}\"\n",
            db.display()
        );
        std::fs::write(
            self.home
                .join(".config")
                .join("ai-memory")
                .join("config.toml"),
            body,
        )
        .expect("write config.toml");
        Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .args(["stats", "--json"])
            .current_dir(&self.cwd)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env_remove("AI_MEMORY_DB")
            .env_remove("AI_MEMORY_NO_CONFIG")
            .output()
            .expect("spawn ai-memory")
    }
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A non-ASCII `hmac_secret` whose byte length is even must take the #1048
/// refusal path: exit `EX_CONFIG`, print the `boot refused` diagnostic, and
/// never reach a panic.
#[test]
fn non_ascii_hmac_secret_refuses_boot_with_ex_config_4074() {
    // "\u{1F600}" is one 4-byte code point; "a\u{20AC}" is 1 + 3 bytes.
    // Both have an EVEN byte length, so the pre-fix length guard let them
    // reach the byte-pair slice.
    for secret in ["\u{1F600}", "a\u{20AC}", "\u{e9}\u{e9}"] {
        let sb = Sandbox::new();
        let out = sb.run_with_secret(secret);
        let stderr = stderr_of(&out);
        assert!(
            !stderr.contains("panicked"),
            "#4074: a non-ASCII hmac_secret must not panic the boot validator; \
             secret={secret:?} stderr={stderr}"
        );
        assert_eq!(
            out.status.code(),
            Some(EX_CONFIG),
            "#4074: a non-ASCII hmac_secret must refuse boot with EX_CONFIG (78); \
             secret={secret:?} stderr={stderr}"
        );
        assert!(
            stderr.contains("boot refused") && stderr.contains("invalid hmac_secret"),
            "#4074: the #1048 refusal diagnostic must be printed; stderr={stderr}"
        );
        assert!(
            !stderr.contains(secret),
            "the refusal diagnostic must not echo the secret value; stderr={stderr}"
        );
    }
}

/// Control: a valid hex `hmac_secret` still boots.
#[test]
fn valid_hex_hmac_secret_still_boots_4074() {
    let sb = Sandbox::new();
    let out = sb.run_with_secret(&"ab".repeat(32));
    assert!(
        out.status.success(),
        "a valid hex hmac_secret must boot; exit={:?} stderr={}",
        out.status.code(),
        stderr_of(&out)
    );
}
