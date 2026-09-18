// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3781 — `agents bind-api-key` must not accept the api-key token on argv
//! (`--token`), because argv is world-readable via `/proc/<pid>/cmdline` and
//! `ps auxww`. The token is read from a `0600` file named by `--token-file` or
//! the owner-only `AI_MEMORY_AGENT_API_KEY_FILE` env var (the #1927 non-argv
//! channel class). Both the refusal and the allowed file channels are pinned.
//!
//! CLI-spawn tests (their own process): the only env they set is on the CHILD
//! (`cmd.env`), never the test process, so they neither race the lib tests nor
//! trip check-test-env-lock.

use std::path::Path;
use std::process::{Command, Output};

const AGENT_ID: &str = "ai:apikey-3781";

struct Sandbox {
    _root: tempfile::TempDir,
    home: std::path::PathBuf,
    keys: std::path::PathBuf,
    db: std::path::PathBuf,
}

fn sandbox() -> Sandbox {
    let root = tempfile::tempdir().expect("tempdir under TMPDIR");
    let home = root.path().join("home");
    let keys = root.path().join("keys");
    std::fs::create_dir_all(home.join(".config")).expect("home");
    std::fs::create_dir_all(&keys).expect("keys");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).expect("0700");
    }
    let db = root.path().join("store.db");
    Sandbox {
        _root: root,
        home,
        keys,
        db,
    }
}

fn command(sb: &Sandbox) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", &sb.home)
        .env("XDG_CONFIG_HOME", sb.home.join(".config"))
        .env("AI_MEMORY_KEY_DIR", &sb.keys)
        .env("AI_MEMORY_DB", &sb.db)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", AGENT_ID);
    cmd
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}
fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn write_token_file(sb: &Sandbox, name: &str, mode: u32) -> std::path::PathBuf {
    let p = sb.db.parent().unwrap().join(name);
    std::fs::write(&p, "the-api-key-token-3781").expect("write token file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }
    p
}

#[test]
fn argv_token_is_refused_naming_the_file_channels_3781() {
    let sb = sandbox();
    let out = command(&sb)
        .args([
            "agents",
            "bind-api-key",
            "--agent-id",
            AGENT_ID,
            "--token",
            "argv-secret",
        ])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "an argv --token must be refused");
    let err = stderr_of(&out);
    assert!(
        err.contains("--token-file"),
        "refusal must name --token-file: {err}"
    );
    assert!(
        err.contains("AI_MEMORY_AGENT_API_KEY_FILE"),
        "refusal must name the env channel: {err}"
    );
    assert!(
        err.to_ascii_uppercase().contains("REFUSED"),
        "refusal must say it is refused: {err}"
    );
}

#[test]
fn token_file_0600_binds_3781() {
    let sb = sandbox();
    let tf = write_token_file(&sb, "apikey.tok", 0o600);
    let out = command(&sb)
        .args([
            "agents",
            "bind-api-key",
            "--agent-id",
            AGENT_ID,
            "--token-file",
            tf.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "0600 --token-file must bind: {}",
        stderr_of(&out)
    );
    assert!(
        stdout_of(&out).contains("bound api-key"),
        "expected a bind confirmation: {}",
        stdout_of(&out)
    );
}

#[test]
fn env_agent_api_key_file_binds_3781() {
    let sb = sandbox();
    let tf = write_token_file(&sb, "apikey-env.tok", 0o600);
    let out = command(&sb)
        .env("AI_MEMORY_AGENT_API_KEY_FILE", &tf)
        .args(["agents", "bind-api-key", "--agent-id", AGENT_ID])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "AI_MEMORY_AGENT_API_KEY_FILE must bind: {}",
        stderr_of(&out)
    );
    assert!(
        stdout_of(&out).contains("bound api-key"),
        "expected a bind: {}",
        stdout_of(&out)
    );
}

#[test]
fn lax_perms_token_file_is_refused_3781() {
    let sb = sandbox();
    let tf = write_token_file(&sb, "apikey-lax.tok", 0o644);
    let out = command(&sb)
        .args([
            "agents",
            "bind-api-key",
            "--agent-id",
            AGENT_ID,
            "--token-file",
            tf.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    // On unix a group/world-readable token file is refused fail-closed.
    if cfg!(unix) {
        assert!(!out.status.success(), "0644 token file must be refused");
        assert!(
            stderr_of(&out).contains("lax permissions"),
            "refusal must name lax permissions: {}",
            stderr_of(&out)
        );
    }
    let _ = Path::new(&tf);
}

#[test]
fn argv_token_with_a_file_channel_is_still_refused_3781() {
    // #3781 re-cut (rules o+s): passing BOTH `--token` AND a 0600 `--token-file`
    // must be REFUSED, not silently accepted through the file channel. The argv
    // token has ALREADY leaked through /proc/<pid>/cmdline and `ps auxww`;
    // honouring the file channel would accept that leak with no refusal. This
    // is RED on the file-first ordering (bind succeeds) and GREEN once the argv
    // refusal is the resolver's first act.
    let sb = sandbox();
    let tf = write_token_file(&sb, "apikey-both.tok", 0o600);
    let out = command(&sb)
        .args([
            "agents",
            "bind-api-key",
            "--agent-id",
            AGENT_ID,
            "--token",
            "argv-secret",
            "--token-file",
            tf.to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    assert!(
        !out.status.success(),
        "an argv --token alongside a file channel must STILL be refused: {}",
        stdout_of(&out)
    );
    let err = stderr_of(&out);
    assert!(
        err.to_ascii_uppercase().contains("REFUSED"),
        "refusal must say it is refused even with a file channel present: {err}"
    );
    assert!(
        err.contains("--token-file"),
        "refusal must still name the file-channel remedy: {err}"
    );
}
