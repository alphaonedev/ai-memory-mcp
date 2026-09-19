// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3409 — `ai-memory store --sign` with a local keypair whose public key is
//! NOT bound in the store used to exit 0 and land `attest_level="claimed"`:
//! the caller asked for a signed write and got an unsigned one. The compiled
//! binary must now REFUSE (non-zero exit, message naming the bind command and
//! the `--allow-claimed` override); with the override it stores `claimed`
//! and warns; after binding it stores `agent_attested`.
//!
//! The CLI `store` verb is sqlite-only at this head (`cli::backup::refuse_pg_store`
//! refuses a postgres store URL before the sign path runs), so the postgres
//! half of the family lives in the HTTP/MCP surfaces, not here.

use std::path::Path;
use std::process::{Command, Output};

const AGENT: &str = "ai:signer-3409";

fn command(root: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("AI_MEMORY_KEY_DIR", root.join("keys"))
        .env("AI_MEMORY_DB", root.join("store.db"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", AGENT)
        // #1751 — pin the permissive posture so the only gate under test is
        // the #3409 bound-key check.
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    cmd
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Construct the state #3409 is about — a local keypair that EXISTS and is
/// NOT BOUND in the store — deliberately, on both trees this test runs on.
///
/// EXISTS: `<key_dir>/<agent>.priv` + `.pub`. On this branch's own base
/// `identity generate` mints it here. On any tree carrying #3354 the
/// process's OWN boot ensures the resolved id's key before the verb
/// dispatches (`main.rs::init_forensic_audit` →
/// `ensure_daemon_signing_key`), so `identity generate` then correctly
/// refuses to overwrite it ("already exists … pass --force"); that refusal
/// is accepted here because the key the boot minted is exactly the key this
/// fixture wants (rotating it with `--force` would be a different fixture).
/// Either way the `.priv` is asserted present afterwards.
///
/// NOT BOUND: #3354 writes files only; the binding is the
/// `metadata.agent_pubkey` row `agents bind-key` writes, read through
/// `db::agent_pubkey`. Asserted absent explicitly, so the unbound half of
/// the premise is stated rather than assumed.
fn generate_key(root: &Path) {
    std::fs::create_dir_all(root.join("keys")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.join("keys"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
    }
    let out = command(root)
        .args(["identity", "generate", "--agent-id", AGENT])
        .output()
        .unwrap();
    let err = stderr(&out);
    assert!(
        out.status.success() || err.contains("already exists"),
        "identity generate must mint the key or find the boot-ensured one (#3354): {err}"
    );
    assert!(
        root.join("keys").join(format!("{AGENT}.priv")).is_file(),
        "the local keypair EXISTS"
    );
    let conn = ai_memory::db::open(&root.join("store.db")).unwrap();
    assert_eq!(
        ai_memory::db::agent_pubkey(&conn, AGENT).unwrap(),
        None,
        "the key is NOT BOUND in the store — the state #3409 refuses --sign in"
    );
}

fn store_signed(root: &Path, extra: &[&str]) -> Output {
    let mut cmd = command(root);
    cmd.args([
        "store",
        "--title",
        "signed write 3409",
        "--content",
        "A body long enough to read as real prose for the #3409 signed-store probe.",
        "--namespace",
        "sign-3409",
        "--json",
        "--sign",
    ]);
    cmd.args(extra);
    cmd.output().unwrap()
}

/// FAILS on the pre-fix head: the store exits 0 with `claimed`.
#[test]
fn store_sign_without_bound_key_refuses_and_names_the_fix_3409() {
    let root = tempfile::tempdir().unwrap();
    generate_key(root.path());
    let out = store_signed(root.path(), &[]);
    assert!(
        !out.status.success(),
        "--sign without a bound key must refuse; stdout: {}",
        stdout(&out)
    );
    let err = stderr(&out);
    assert!(err.contains("#3409"), "{err}");
    assert!(err.contains("no public key is bound"), "{err}");
    assert!(
        err.contains(&format!("agents bind-key --agent-id {AGENT}")),
        "{err}"
    );
    assert!(err.contains("--allow-claimed"), "{err}");
    // Nothing was stored.
    let conn = ai_memory::db::open(&root.path().join("store.db")).unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE namespace = 'sign-3409'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 0);
}

/// The deliberate override stores `claimed` and says so.
#[test]
fn store_sign_with_allow_claimed_stores_claimed_and_warns_3409() {
    let root = tempfile::tempdir().unwrap();
    generate_key(root.path());
    let out = store_signed(root.path(), &["--allow-claimed"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["metadata"]["attest_level"], "claimed");
    let err = stderr(&out);
    assert!(err.contains("WARN") && err.contains("#3409"), "{err}");
}

/// After binding through the CLI, `--sign` lands `agent_attested` with no
/// override and no WARN (the command the refusal names actually works).
#[test]
fn store_sign_after_cli_bind_is_agent_attested_3409() {
    let root = tempfile::tempdir().unwrap();
    generate_key(root.path());
    let out = command(root.path())
        .args([
            "agents",
            "register",
            "--agent-id",
            AGENT,
            "--agent-type",
            "ai:test",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "agents register: {}", stderr(&out));
    let out = command(root.path())
        .args(["identity", "export-pub", "--agent-id", AGENT])
        .output()
        .unwrap();
    assert!(out.status.success(), "export-pub: {}", stderr(&out));
    let pubkey = stdout(&out).trim().to_string();
    assert!(!pubkey.is_empty());
    let out = command(root.path())
        .args([
            "agents",
            "bind-key",
            "--agent-id",
            AGENT,
            "--pubkey",
            &pubkey,
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "agents bind-key: {}", stderr(&out));

    let out = store_signed(root.path(), &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).unwrap();
    assert_eq!(v["metadata"]["attest_level"], "agent_attested");
    assert!(!stderr(&out).contains("#3409"), "{}", stderr(&out));
}
