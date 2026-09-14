// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3354 (rescoped to the WRITE PATH) — a fresh store whose resolved agent
//! id has no signing key must never append an UNSIGNED `signed_events` row.
//! The fix ensures the key at boot (generated when absent — automatic
//! generation is not automatic trust) so the ledger is signed from its
//! first row; a ledger-writing verb whose key cannot be ensured refuses to
//! start, naming the real provisioning verb; read-only verbs stay
//! reachable. Doctor is untouched (its masking was already fixed on the
//! head); the epoch-seal ask lives at #3479.
//!
//! The producer is `capture-turn` — the hook-driven verb that appends one
//! ledger row per turn, which is where the reporting host's 109,396
//! unsigned rows came from.
//!
//! FAILS ON THE PARENT: the first test finds `attest_level = unsigned`
//! rows and no generated `<agent>.priv`; the second finds the write
//! accepted (rows appended unsigned) instead of refused.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const AGENT_ID: &str = "ai:ledger-3354";
const ISSUE: &str = "#3354";
const REMEDY: &str = "ai-memory identity generate --agent-id ai:ledger-3354";

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
    chmod(&keys, 0o700);
    let db = root.path().join("store.db");
    Sandbox {
        _root: root,
        home,
        keys,
        db,
    }
}

fn chmod(p: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }
    #[cfg(not(unix))]
    {
        let _ = (p, mode);
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

/// One hook-shaped turn through the real binary: the body on stdin, the
/// index explicit. This is the ledger producer under test.
fn capture_turn(sb: &Sandbox, index: u32) -> Output {
    let params = serde_json::json!({
        "host_session_id": "sess-3354",
        "host_turn_index": index,
        "role": "assistant",
        "content": format!("turn {index} — the ledger row for this turn must be signed"),
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

/// `attest_level -> count` over the whole ledger.
fn ledger_levels(db: &Path) -> Vec<(String, i64)> {
    let conn = rusqlite::Connection::open(db).expect("open sqlite");
    let mut stmt = conn
        .prepare("SELECT attest_level, COUNT(*) FROM signed_events GROUP BY attest_level")
        .expect("prepare");
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows")
}

/// THE regression: an empty key directory, a resolved id nobody
/// provisioned, one turn — the row is `self_signed`, the key was
/// generated (0600) for exactly that id, and NO row is `unsigned`.
#[test]
fn fresh_store_signs_the_ledger_from_its_first_row_3354() {
    let sb = sandbox();
    assert!(
        std::fs::read_dir(&sb.keys).expect("list").next().is_none(),
        "the key directory starts empty"
    );

    let out = capture_turn(&sb, 1);
    assert!(out.status.success(), "capture-turn: {}", stderr_of(&out));

    let priv_path = sb.keys.join(format!("{AGENT_ID}.priv"));
    let pub_path = sb.keys.join(format!("{AGENT_ID}.pub"));
    assert!(
        priv_path.is_file(),
        "the signing key was generated for the resolved id"
    );
    assert!(pub_path.is_file(), "with its public half");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&priv_path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "a generated private key is owner-only");
    }

    let levels = ledger_levels(&sb.db);
    assert!(
        !levels.is_empty(),
        "capture-turn appends at least one ledger row"
    );
    assert!(
        levels.iter().all(|(level, _)| level != "unsigned"),
        "{ISSUE}: no row may be unsigned on a fresh store: {levels:?}"
    );
    assert!(
        levels
            .iter()
            .any(|(level, n)| level == "self_signed" && *n >= 1),
        "{ISSUE}: the turn's row is self_signed (L4: the capture-turn row is signed by the resolved agent`s own key): {levels:?}"
    );

    // A second turn re-uses the generated key: still signed, still no
    // unsigned row, no second key generation.
    let out = capture_turn(&sb, 2);
    assert!(
        out.status.success(),
        "second capture-turn: {}",
        stderr_of(&out)
    );
    let levels = ledger_levels(&sb.db);
    assert!(
        levels.iter().all(|(level, _)| level != "unsigned"),
        "{levels:?}"
    );
    let entries = std::fs::read_dir(&sb.keys).expect("list").count();
    assert_eq!(
        entries, 2,
        "exactly one keypair (pub + priv) under the key dir"
    );
}

/// When the key cannot be generated (read-only key directory), a
/// ledger-writing verb REFUSES to start, names the real provisioning verb,
/// and appends NOTHING — an unsigned row is never the fallback.
#[cfg(unix)]
#[test]
fn ledger_writer_without_a_key_it_cannot_generate_refuses_3354() {
    let sb = sandbox();
    chmod(&sb.keys, 0o500);
    let out = capture_turn(&sb, 1);
    // Restore so the tempdir can be removed.
    chmod(&sb.keys, 0o700);
    assert!(!out.status.success(), "must refuse: {}", stderr_of(&out));
    let err = stderr_of(&out);
    assert!(err.contains(ISSUE), "{err}");
    assert!(
        err.contains(REMEDY),
        "the remedy names the real verb: {err}"
    );
    assert!(err.contains("refusing to start"), "{err}");
    assert!(!sb.keys.join(format!("{AGENT_ID}.priv")).exists());
    if sb.db.exists() {
        let levels = ledger_levels(&sb.db);
        assert!(levels.is_empty(), "nothing was appended: {levels:?}");
    }
}

/// Review blocker (#3354): the EGRESS verbs — the ones that take the
/// operator's data OUT — and the remediation verbs stay reachable under the
/// same condition. A posture that diagnoses an unwritable key dir must never
/// disable the operator's ability to get their data out; `export` and
/// `backup` run to completion while `capture-turn` (above) is refused.
#[cfg(unix)]
#[test]
fn egress_verb_without_a_key_it_cannot_generate_still_runs_3354() {
    let sb = sandbox();
    let out = capture_turn(&sb, 1);
    assert!(out.status.success(), "{}", stderr_of(&out));
    std::fs::remove_file(sb.keys.join(format!("{AGENT_ID}.priv"))).expect("lose the key");
    std::fs::remove_file(sb.keys.join(format!("{AGENT_ID}.pub"))).expect("lose the key");
    let backups = sb.home.join("backups-3354");
    chmod(&sb.keys, 0o500);
    let export = command(&sb).arg("export").output().expect("export");
    let backup = command(&sb)
        .args(["backup", "--to"])
        .arg(&backups)
        .output()
        .expect("backup");
    chmod(&sb.keys, 0o700);
    assert!(
        export.status.success(),
        "`export` is an egress verb and must not be refused for a key it cannot mint: {}",
        stderr_of(&export)
    );
    assert!(
        !String::from_utf8_lossy(&export.stdout).trim().is_empty(),
        "`export` still produced the data"
    );
    assert!(
        backup.status.success(),
        "`backup` is an egress verb and must not be refused for a key it cannot mint: {}",
        stderr_of(&backup)
    );
    assert!(
        std::fs::read_dir(&backups)
            .map(|d| d.count() > 0)
            .unwrap_or(false),
        "`backup` still wrote a snapshot under {}",
        backups.display()
    );
    assert!(
        !sb.keys.join(format!("{AGENT_ID}.priv")).exists(),
        "no key was minted by an egress verb"
    );
}

/// Read-only verbs stay reachable under the same condition, so the posture
/// can be diagnosed and fixed from them (`doctor` itself is untouched by
/// this change; `stats` stands in for the class).
#[cfg(unix)]
#[test]
fn read_only_verb_without_a_key_still_runs_3354() {
    let sb = sandbox();
    // Seed the store with one signed turn, then take the key dir away.
    let out = capture_turn(&sb, 1);
    assert!(out.status.success(), "{}", stderr_of(&out));
    std::fs::remove_file(sb.keys.join(format!("{AGENT_ID}.priv"))).expect("lose the key");
    std::fs::remove_file(sb.keys.join(format!("{AGENT_ID}.pub"))).expect("lose the key");
    chmod(&sb.keys, 0o500);
    let out = command(&sb).arg("stats").output().expect("stats");
    chmod(&sb.keys, 0o700);
    assert!(
        out.status.success(),
        "a read-only verb is not a ledger writer and must not be refused: {}",
        stderr_of(&out)
    );
}
