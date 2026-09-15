// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3743 — the #3354 boot ensure must not pre-empt the provisioning verbs.
//!
//! Since #3354 every process ensures the resolved agent id's signing key
//! before its verb dispatches. Run ahead of `identity generate` for that
//! very id, the boot minted the key first and the verb then refused to
//! overwrite it ("already exists … pass --force") — so the command the #3354
//! refusal named as its remedy could never succeed for the resolved id, and
//! its `--force` suggestion would ROTATE a key that was already signing.
//!
//! Two halves, both pinned so the fix cannot be over-applied into reopening
//! #3354:
//! 1. a fresh key directory + the resolved id + `identity generate` exits 0
//!    and mints the pair — FAILS ON THE PARENT (refused "already exists");
//! 2. a LEDGER-WRITING verb (`capture-turn`) on an equally fresh key
//!    directory STILL ensures the key (#3354's contract, unchanged).
//!
//! Plus: the #3354 refusal names the ACTIONABLE remedy (make the key
//! directory writable) before the explicit provisioning verb — FAILS ON THE
//! PARENT, whose remedy led with a command that fails the same way.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const AGENT_ID: &str = "ai:provision-3743";

struct Sandbox {
    _root: tempfile::TempDir,
    home: PathBuf,
    keys: PathBuf,
    db: PathBuf,
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
        .env("AI_MEMORY_AGENT_ID", AGENT_ID)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0");
    cmd
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn priv_path(sb: &Sandbox) -> PathBuf {
    sb.keys.join(format!("{AGENT_ID}.priv"))
}

fn key_dir_listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("list key dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn capture_turn(sb: &Sandbox) -> Output {
    let params = serde_json::json!({
        "host_session_id": "sess-3743",
        "host_turn_index": 1,
        "role": "assistant",
        "content": "one turn — a ledger-writing verb still ensures the key (#3743)",
        "host_kind": "claude-code",
    });
    let mut child = command(sb)
        .args(["capture-turn", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn capture-turn");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(params.to_string().as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("capture-turn output")
}

/// Half 1 — FAILS ON THE PARENT: `identity generate` for the resolved id on
/// a fresh key directory is refused because the boot ensured the key first.
#[test]
fn identity_generate_for_the_resolved_id_mints_on_a_fresh_key_dir_3743() {
    let sb = sandbox();
    assert!(key_dir_listing(&sb.keys).is_empty(), "a fresh key dir");
    let out = command(&sb)
        .args(["identity", "generate", "--agent-id", AGENT_ID])
        .output()
        .expect("run identity generate");
    let err = stderr_of(&out);
    assert!(
        out.status.success(),
        "#3743: identity generate for the resolved id must succeed on a fresh key dir — the \
         boot must not have minted it first: {err}"
    );
    assert!(
        !err.contains("already exists") && !err.contains("--force"),
        "no pre-emption, no rotation suggestion: {err}"
    );
    assert!(priv_path(&sb).is_file(), "the verb minted the private key");
    assert!(
        sb.keys.join(format!("{AGENT_ID}.pub")).is_file(),
        "and its public half"
    );
    // The verb's own refuse-on-existing contract is untouched: a second
    // generate without --force still refuses, naming --force.
    let out = command(&sb)
        .args(["identity", "generate", "--agent-id", AGENT_ID])
        .output()
        .expect("run identity generate again");
    assert!(
        !out.status.success(),
        "a second generate refuses to overwrite"
    );
    assert!(stderr_of(&out).contains("--force"), "{}", stderr_of(&out));
}

/// Half 2 — the control that keeps half 1 from being over-applied: a
/// ledger-writing verb on an equally fresh key directory STILL ensures the
/// resolved id's key at boot (#3354), and its row is signed.
#[test]
fn ledger_writing_verb_on_a_fresh_key_dir_still_ensures_the_key_3743() {
    let sb = sandbox();
    assert!(key_dir_listing(&sb.keys).is_empty(), "a fresh key dir");
    let out = capture_turn(&sb);
    assert!(
        out.status.success(),
        "capture-turn must run: {}",
        stderr_of(&out)
    );
    assert!(
        priv_path(&sb).is_file(),
        "#3354: the ledger writer ensured the resolved id's key at boot — the #3743 skip \
         is scoped to the provisioning verbs only"
    );
    let conn = rusqlite::Connection::open(&sb.db).expect("open sqlite");
    let unsigned: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE attest_level = 'unsigned'",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(unsigned, 0, "no unsigned ledger row was appended");
}

/// The #3354 refusal names what is ACTIONABLE when the key directory cannot
/// be written — make it writable — BEFORE the explicit provisioning verb,
/// which fails the same way in that state. FAILS ON THE PARENT (the remedy
/// led with `identity generate`).
#[cfg(unix)]
#[test]
fn unwritable_key_dir_refusal_names_the_actionable_remedy_first_3743() {
    use std::os::unix::fs::PermissionsExt as _;
    let sb = sandbox();
    std::fs::set_permissions(&sb.keys, std::fs::Permissions::from_mode(0o500)).expect("0500");
    let out = capture_turn(&sb);
    std::fs::set_permissions(&sb.keys, std::fs::Permissions::from_mode(0o700)).expect("0700");
    assert!(!out.status.success(), "must refuse: {}", stderr_of(&out));
    let err = stderr_of(&out);
    let writable = err
        .find("make the key directory writable")
        .unwrap_or_else(|| panic!("the remedy names the writable-directory fix: {err}"));
    let generate = err
        .find(&format!(
            "ai-memory identity generate --agent-id {AGENT_ID}"
        ))
        .unwrap_or_else(|| panic!("the explicit verb is still named as the alternative: {err}"));
    assert!(
        writable < generate,
        "the actionable remedy comes first; the verb that would fail the same way is the \
         alternative: {err}"
    );
    assert!(!priv_path(&sb).exists(), "nothing was minted");
}
