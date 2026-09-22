// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3717 — the at-rest KEY ESCROW and its recovery, end to end through the
//! REAL binary on the sqlite backend (env supplied ONLY to the child):
//!
//! 1. `keys init --recovery-key-out <file>` mints the deployment recovery
//!    keypair (private half in the operator's 0600 file, public half
//!    enrolled) and every role, the at-rest key WITH its escrow;
//! 2. `store` seals a row; `get` opens it;
//! 3. the `.x25519.priv` is DESTROYED — `get` fails with the typed
//!    `key_absent` class and mints nothing (#3718);
//! 4. `keys recover --recovery-key <file>` UNWRAPS the escrow and restores
//!    the private half, byte-identical;
//! 5. `get` reads the SAME row back with the same content.
//!
//! Plus: `keys status --json` reports the typed states before and after,
//! `keys init --dry-run` writes nothing, and a second `keys init` is
//! idempotent (byte-identical key directory).
//!
//! FAILS ON THE PARENT (436459898): `keys` has only `prune`, so `keys init`
//! stops at clap's `unrecognized subcommand 'init'` (exit 2); the postgres
//! twin is `tests/keys_escrow_recovery_3717_pg.rs`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

const AGENT: &str = "ai:escrow-3717";
const CONTENT: &str = "sealed content that must survive the loss of its key — #3717";

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::create_dir_all(root.join("off-node")).unwrap();
        key_dir_sandbox::mkdir_0700(&root.join("keys"));
        Self { _tmp: tmp, root }
    }

    fn keys(&self) -> PathBuf {
        self.root.join("keys")
    }

    fn recovery_file(&self) -> PathBuf {
        self.root.join("off-node").join("recovery.key")
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("home/.config"))
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_KEY_DIR", self.keys())
            .env("AI_MEMORY_AGENT_ID", AGENT)
            .env("AI_MEMORY_DB", self.root.join("store.db"))
            .env("AI_MEMORY_AUDIT_DIR", self.root.join("audit"))
            .env("AI_MEMORY_ENCRYPT_AT_REST", "1")
            .env("RUST_LOG", "error");
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().expect("spawn ai-memory")
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("json: {e}: {}", text(o)))
}

/// Every regular file under `dir` with its bytes.
fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let name = format!("{prefix}{}", e.file_name().to_string_lossy());
            if e.file_type().unwrap().is_dir() {
                walk(&e.path(), &format!("{name}/"), out);
            } else {
                out.insert(name, std::fs::read(e.path()).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, "", &mut out);
    out
}

fn role_state<'a>(status: &'a serde_json::Value, role: &str) -> &'a serde_json::Value {
    status["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == role)
        .unwrap_or_else(|| panic!("role {role} listed: {status}"))
}

#[test]
fn keys_init_escrows_the_at_rest_key_and_keys_recover_restores_it_end_to_end_3717() {
    let fx = Fixture::new();
    let keys = fx.keys();
    let priv_path = keys.join(format!("{AGENT}.x25519.priv"));
    let escrow_path = keys.join(format!("{AGENT}.x25519.escrow"));

    // Dry run: the plan names what it WOULD mint and writes nothing.
    let out = fx.run(&["--json", "keys", "init", "--dry-run"]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(!t.contains("unrecognized subcommand"), "{t}");
    let dry = json(&out);
    assert_eq!(dry["dry_run"], true);
    assert_eq!(
        snapshot(&keys).len(),
        0,
        "keys init --dry-run writes nothing: {t}"
    );
    let anchor = dry["plan"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["role"] == "recovery-anchor")
        .unwrap();
    assert_eq!(
        anchor["action"], "cannot-mint",
        "no --recovery-key-out: the escrow is mandatory, so nothing at-rest can be minted: {dry}"
    );

    // 1. Init with the recovery key: every role, the at-rest key WITH escrow.
    let recovery = fx.recovery_file();
    let out = fx.run(&[
        "--json",
        "keys",
        "init",
        "--recovery-key-out",
        recovery.to_str().unwrap(),
        "--host",
        "10.1.2.3",
    ]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    let init = json(&out);
    assert_eq!(init["recovery_enrolled"], true, "{init}");
    for role in [
        "recovery-anchor",
        "identity",
        "daemon-signer",
        "at-rest-wrap",
        "tls",
        "capability-owner",
    ] {
        let o = init["outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["role"] == role)
            .unwrap();
        assert_eq!(o["outcome"], "minted", "{role}: {init}");
    }
    assert!(priv_path.is_file(), "at-rest private half minted");
    assert!(escrow_path.is_file(), "escrow written at mint");
    assert!(keys.join("recovery.x25519.pub").is_file());
    assert!(
        recovery.is_file(),
        "recovery private half in the operator's file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&recovery), 0o600);
        assert_eq!(mode(&escrow_path), 0o600);
        assert_eq!(mode(&priv_path), 0o600);
    }
    let back_up: Vec<String> = init["back_up"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap().to_string())
        .collect();
    assert!(
        back_up.iter().any(|p| p.ends_with(".x25519.escrow")),
        "the escrow is on the BACK UP list: {back_up:?}"
    );
    let distribute: Vec<String> = init["distribute"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap().to_string())
        .collect();
    assert!(
        distribute
            .iter()
            .any(|p| p.ends_with("recovery.x25519.pub")),
        "the recovery public key is on the DISTRIBUTE list: {distribute:?}"
    );
    let complete = snapshot(&keys);
    let priv_bytes = complete[&format!("{AGENT}.x25519.priv")].clone();

    // Idempotent: a second init writes nothing.
    let out = fx.run(&["--json", "keys", "init"]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert_eq!(
        snapshot(&keys),
        complete,
        "second keys init is byte-identical"
    );

    // status: every role present.
    let out = fx.run(&["--json", "keys", "status"]);
    let status = json(&out);
    assert_eq!(
        role_state(&status, "at-rest-wrap")["state"]["state"],
        "complete"
    );
    assert_eq!(
        status["missing_required"].as_array().unwrap().len(),
        0,
        "{status}"
    );

    // 2. Seal a row and read it back.
    let out = fx.run(&["--json", "store", "-T", "escrow-row", "-c", CONTENT]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    let id = json(&out)["id"].as_str().unwrap().to_string();
    let out = fx.run(&["--json", "get", &id]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert_eq!(json(&out)["memory"]["content"], CONTENT);
    {
        let conn = rusqlite::Connection::open(fx.root.join("store.db")).unwrap();
        let sealed: Option<Vec<u8>> = conn
            .query_row(
                "SELECT encrypted_envelope FROM memories WHERE id = ?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(sealed.is_some(), "the row is sealed under the at-rest key");
    }

    // 3. Destroy the private half: the read fails typed, nothing is minted.
    std::fs::remove_file(&priv_path).unwrap();
    let out = fx.run(&["--json", "get", &id]);
    let t = text(&out);
    assert!(!out.status.success(), "a lost key must fail the read: {t}");
    assert!(t.contains("key_absent"), "typed class: {t}");
    assert!(!priv_path.exists(), "the read minted nothing (#3718)");
    let out = fx.run(&["--json", "keys", "status"]);
    let status = json(&out);
    let at_rest = role_state(&status, "at-rest-wrap");
    assert_eq!(at_rest["state"]["state"], "partial", "{status}");
    assert_eq!(at_rest["state"]["partial"], "lost-private", "{status}");
    assert!(
        at_rest["detail"]
            .as_str()
            .unwrap()
            .contains("keys recover --recovery-key"),
        "the remedy names keys recover: {status}"
    );
    // keys init REFUSES over the half-state (F2) and writes nothing.
    let before = snapshot(&keys);
    let out = fx.run(&["keys", "init"]);
    let t = text(&out);
    assert!(!out.status.success(), "F2: keys init refuses: {t}");
    assert!(t.contains("refusing before any write"), "{t}");
    assert_eq!(snapshot(&keys), before, "F2: nothing written");

    // 4. Recover from the escrow with the wrong file first (refused), then
    //    the right one (restored, byte-identical).
    let wrong = fx.root.join("off-node").join("wrong.key");
    std::fs::write(&wrong, [9u8; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let out = fx.run(&["keys", "recover", "--recovery-key", wrong.to_str().unwrap()]);
    let t = text(&out);
    assert!(
        !out.status.success(),
        "a wrong recovery key is refused: {t}"
    );
    assert!(t.contains("not the enrolled recovery key"), "{t}");
    assert!(!priv_path.exists());
    let out = fx.run(&[
        "--json",
        "keys",
        "recover",
        "--recovery-key",
        recovery.to_str().unwrap(),
    ]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    let recovered = json(&out);
    assert_eq!(recovered["agent_id"], AGENT);
    assert_eq!(recovered["pub_rewritten"], false);
    assert_eq!(
        std::fs::read(&priv_path).unwrap(),
        priv_bytes,
        "the restored private half is byte-identical"
    );
    assert_eq!(
        snapshot(&keys),
        complete,
        "the key directory is exactly as before the loss"
    );

    // 5. The SAME row reads back with the same content.
    let out = fx.run(&["--json", "get", &id]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    let back = json(&out);
    assert_eq!(back["memory"]["id"], id.as_str());
    assert_eq!(back["memory"]["content"], CONTENT);
    let out = fx.run(&["--json", "keys", "status"]);
    assert_eq!(
        role_state(&json(&out), "at-rest-wrap")["state"]["state"],
        "complete"
    );
    // A second recover has nothing to do and says so.
    let out = fx.run(&[
        "keys",
        "recover",
        "--recovery-key",
        recovery.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(text(&out).contains("nothing to recover"), "{}", text(&out));
}

/// The doctor renders the key posture from the same table, naming the fix.
#[test]
fn doctor_reports_key_posture_with_the_fix_3717() {
    let fx = Fixture::new();
    // Doctor exits non-zero here (no database yet — Storage is Critical);
    // the report still renders and the key posture is database-independent.
    let out = fx.run(&["--json", "doctor"]);
    let report = json(&out);
    let section = report["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "Key posture (#3717)")
        .unwrap_or_else(|| panic!("section listed: {report}"));
    assert_eq!(section["severity"], "warning", "{section}");
    let note = section["note"].as_str().unwrap_or_default();
    assert!(
        note.contains("at-rest-wrap is MISSING") && note.contains("--recovery-key-out"),
        "the note names the missing role and its fix: {note}"
    );
    assert!(note.contains("tls is MISSING"), "{note}");
    // After init the section is clean.
    let recovery = fx.recovery_file();
    let out = fx.run(&[
        "keys",
        "init",
        "--recovery-key-out",
        recovery.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let out = fx.run(&["--json", "doctor"]);
    let report = json(&out);
    let section = report["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "Key posture (#3717)")
        .unwrap();
    assert_eq!(section["severity"], "info", "{section}");
    let facts: BTreeMap<String, String> = section["facts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f[0].as_str().unwrap().to_string(),
                f[1].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(facts["recovery_enrolled"], "yes");
    assert!(facts["at-rest-wrap"].starts_with("present"), "{facts:?}");
    assert!(facts["tls"].starts_with("present, expires in"), "{facts:?}");
}
