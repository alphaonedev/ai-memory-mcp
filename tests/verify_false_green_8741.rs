// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8741 class: a verify command must never print green when it did not
//! check. Absence (a stripped signature, an unknown signer, a missing store,
//! an empty chain, a removed sequence mark, an emptied or deleted trail) is a
//! finding with ONE exact non-zero exit and its own reason code; a rewrite is
//! a finding with its position.
//!
//! Issues: #8851 (bundle signature), #9046 (signed-events chain on the wrong
//! store), #8867 (flat audit trail), #9009 (forensic window), #8852 / #9008
//! (signed-events chain coverage).
//!
//! The tamper table is crossed with every verify command of the CLI; the
//! registry test at the bottom fails when a new `verify*` command appears
//! without a tamper row here.
//!
//! All scratch lives in per-test `TempDir`s under `TMPDIR` (never `/tmp`
//! when run by the lane; CI points `TMPDIR` at its own scratch).

#![allow(clippy::doc_markdown)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ai_memory::forensic::bundle::{pack_to_vec, read_ustar};
use ai_memory::governance::audit::{
    CHAIN_HEAD_PREV_HASH, FORENSIC_FILE_PREFIX, ForensicDecision, VerifyFailureKind, verify_since,
};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use tempfile::TempDir;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

// ─────────────────────────────────────────────────────────────────────
// Reason codes and exit codes (the contract under test)
// ─────────────────────────────────────────────────────────────────────

/// `verify-forensic-bundle` failure exit.
const EXIT_BUNDLE_FAIL: i32 = 2;
/// `verify-signed-events-chain` / `verify-audit-trail` failure exit.
const EXIT_CHAIN_FAIL: i32 = 1;
/// `audit verify` failure exit.
const EXIT_AUDIT_FAIL: i32 = 2;
/// `verify-reflection-chain` failure exit (missing root).
const EXIT_REFLECTION_FAIL: i32 = 1;
const EXIT_OK: i32 = 0;

const REASON_SIGNATURE_ABSENT: &str = "manifest_signature_absent";
const REASON_SIGNER_UNKNOWN: &str = "manifest_signer_unknown";
const REASON_STORE_IS_POSTGRES: &str = "store_is_postgres";
const REASON_STORE_MISSING: &str = "store_missing";
const REASON_EMPTY_CHAIN: &str = "empty_chain";
const REASON_AUDIT_LOG_MISSING: &str = "audit_log_missing";
const REASON_AUDIT_LOG_EMPTY: &str = "audit_log_empty";
const REASON_SEQ_MARK_MISSING: &str = "seq_mark_missing";
/// Forensic: an unsigned row after a signed one (a signature downgrade).
const REASON_FORENSIC_SIGNATURE_ABSENT: &str = "signature_absent";

const MANIFEST_FILE: &str = "manifest.json";
const SIGNER_AGENT: &str = "ai:bundle-signer-8741";
const UNKNOWN_SIGNER: &str = "ai:nobody-8741";
/// A postgres DSN with no password that is never dialled: the verb must
/// refuse it before any connect.
const PG_URL_NEVER_DIALLED: &str = "postgres://verify8741@127.0.0.1:1/never";
const STORE_URL_ENV: &str = "AI_MEMORY_STORE_URL";
/// Audit-enabled store operations that write the flat trail.
const TRAIL_WRITES: usize = 3;
const FORENSIC_SEED: [u8; 32] = [7u8; 32];

// ─────────────────────────────────────────────────────────────────────
// Process fixture: an isolated HOME, its own key dir, explicit --db
// ─────────────────────────────────────────────────────────────────────

struct Home {
    dir: TempDir,
}

impl Home {
    fn new(audit_enabled: Option<bool>) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let cfg = dir.path().join(".config").join("ai-memory");
        std::fs::create_dir_all(&cfg).expect("config dir");
        // The key loader refuses a group- or world-writable key directory.
        key_dir_sandbox::mkdir_0700(&dir.path().join("keys"));
        if let Some(enabled) = audit_enabled {
            std::fs::write(
                cfg.join("config.toml"),
                format!(
                    "schema_version = 2\ntier = \"keyword\"\n\n[audit]\nenabled = {enabled}\npath = \"{}\"\n",
                    dir.path().join("audit").display()
                ),
            )
            .expect("write config");
        }
        Self { dir }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn db(&self) -> PathBuf {
        self.path().join("store.db")
    }

    fn trail(&self) -> PathBuf {
        self.path().join("audit").join("audit.log")
    }

    fn run(&self, env: &[(&str, &str)], args: &[&str]) -> Output {
        self.run_db(&self.db(), env, args)
    }

    fn run_db(&self, db: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.path())
            .env("XDG_CONFIG_HOME", self.path().join(".config"))
            .env("AI_MEMORY_KEY_DIR", self.path().join("keys"));
        if !self.path().join(".config/ai-memory/config.toml").exists() {
            cmd.env("AI_MEMORY_NO_CONFIG", "1");
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.current_dir(self.path())
            .arg("--db")
            .arg(db)
            .args(args)
            .output()
            .expect("spawn ai-memory")
    }
}

fn both(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[track_caller]
fn assert_finding(out: &Output, exit: i32, reason: &str) {
    let text = both(out);
    assert_eq!(
        out.status.code(),
        Some(exit),
        "expected exit {exit} with reason {reason}; got {:?}: {text}",
        out.status.code()
    );
    assert!(
        text.contains(reason),
        "expected reason code {reason} in the output: {text}"
    );
}

#[track_caller]
fn assert_ok(out: &Output) {
    assert_eq!(
        out.status.code(),
        Some(EXIT_OK),
        "expected green: {}",
        both(out)
    );
}

// ─────────────────────────────────────────────────────────────────────
// verify-forensic-bundle (#8851)
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum BundleTamper {
    None,
    StripSignature,
    RenameSigner,
}

fn signed_bundle(home: &Home) -> PathBuf {
    let gen_out = home.run(&[], &["identity", "generate", "--agent-id", SIGNER_AGENT]);
    assert_ok(&gen_out);
    let stored = home.run(
        &[],
        &[
            "--json",
            "store",
            "--title",
            "bundle-8741",
            "--content",
            "c",
        ],
    );
    assert_ok(&stored);
    let v: serde_json::Value = serde_json::from_slice(&stored.stdout).expect("store --json output");
    let id = v["id"].as_str().expect("stored id").to_string();
    let bundle = home.path().join("bundle.tar");
    let exported = home.run(
        &[],
        &[
            "export-forensic-bundle",
            "--memory-id",
            &id,
            "--output",
            bundle.to_str().expect("utf8 path"),
        ],
    );
    assert_ok(&exported);
    bundle
}

fn tamper_bundle(bundle: &Path, tamper: BundleTamper) {
    let bytes = std::fs::read(bundle).expect("read bundle");
    let mut files = read_ustar(&bytes).expect("read ustar");
    let manifest = files.get_mut(MANIFEST_FILE).expect("manifest present");
    let mut m: serde_json::Value = serde_json::from_slice(manifest).expect("manifest json");
    assert!(
        m.get("signature").is_some_and(serde_json::Value::is_string),
        "fixture bundle must be signed: {m}"
    );
    match tamper {
        BundleTamper::None => return,
        BundleTamper::StripSignature => {
            let obj = m.as_object_mut().expect("manifest object");
            obj.remove("signature");
            obj.remove("signer_agent_id");
        }
        BundleTamper::RenameSigner => {
            m["signer_agent_id"] = serde_json::Value::String(UNKNOWN_SIGNER.to_string());
        }
    }
    *manifest = serde_json::to_vec_pretty(&m).expect("manifest bytes");
    std::fs::write(bundle, pack_to_vec(&files).expect("repack")).expect("write bundle");
}

#[test]
fn bundle_tamper_table_8851() {
    let table: [(BundleTamper, Option<&str>); 3] = [
        (BundleTamper::None, None),
        (BundleTamper::StripSignature, Some(REASON_SIGNATURE_ABSENT)),
        (BundleTamper::RenameSigner, Some(REASON_SIGNER_UNKNOWN)),
    ];
    for (tamper, reason) in table {
        let home = Home::new(None);
        let bundle = signed_bundle(&home);
        tamper_bundle(&bundle, tamper);
        let out = home.run(
            &[],
            &["verify-forensic-bundle", bundle.to_str().expect("utf8")],
        );
        match reason {
            None => assert_ok(&out),
            Some(r) => assert_finding(&out, EXIT_BUNDLE_FAIL, r),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// verify-signed-events-chain (#9046, #8852/#9008 coverage) and
// verify-audit-trail (empty chain)
// ─────────────────────────────────────────────────────────────────────

fn store_with_empty_chain(home: &Home) {
    assert_ok(&home.run(&[], &["store", "--title", "t", "--content", "c"]));
    let conn = rusqlite::Connection::open(home.db()).expect("open db");
    conn.execute("DELETE FROM signed_events", [])
        .expect("empty signed_events");
}

#[test]
fn signed_events_chain_refuses_postgres_store_9046() {
    let home = Home::new(None);
    assert_ok(&home.run(&[], &["store", "--title", "t", "--content", "c"]));
    let out = home.run(
        &[(STORE_URL_ENV, PG_URL_NEVER_DIALLED)],
        &["verify-signed-events-chain"],
    );
    assert_finding(&out, EXIT_CHAIN_FAIL, REASON_STORE_IS_POSTGRES);
}

#[test]
fn signed_events_chain_missing_store_is_a_finding_and_not_created_9046() {
    let home = Home::new(None);
    let absent = home.path().join("absent.db");
    for format in ["text", "json"] {
        let out = home.run_db(
            &absent,
            &[],
            &["verify-signed-events-chain", "--format", format],
        );
        assert_finding(&out, EXIT_CHAIN_FAIL, REASON_STORE_MISSING);
        assert!(!absent.exists(), "a verify must never create the store");
    }
}

#[test]
fn chain_verifiers_empty_chain_is_a_finding_8741() {
    let table: [&[&str]; 3] = [
        &["verify-signed-events-chain"],
        &["verify-signed-events-chain", "--format", "json"],
        &["verify-audit-trail"],
    ];
    for args in table {
        let home = Home::new(None);
        store_with_empty_chain(&home);
        let out = home.run(&[], args);
        assert_finding(&out, EXIT_CHAIN_FAIL, REASON_EMPTY_CHAIN);
    }
}

#[test]
fn chain_verifiers_clean_store_is_green_8741() {
    for args in [
        &["verify-signed-events-chain"][..],
        &["verify-audit-trail"][..],
    ] {
        let home = Home::new(None);
        assert_ok(&home.run(&[], &["store", "--title", "t", "--content", "c"]));
        assert_ok(&home.run(&[], args));
    }
}

// ─────────────────────────────────────────────────────────────────────
// audit verify, flat trail (#8867)
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum TrailTamper {
    None,
    /// Remove the last line and the sequence mark.
    TailCutMarkRemoved,
    /// Keep only the first line and remove the sequence mark.
    AllButHeadMarkRemoved,
    /// Zero bytes, mark removed.
    ZeroBytesMarkRemoved,
    /// Trail and mark deleted.
    Deleted,
    /// Trail deleted, mark kept.
    DeletedMarkKept,
}

fn seq_mark(trail: &Path) -> PathBuf {
    ai_memory::audit::seq_mark_path(trail)
}

fn tamper_trail(trail: &Path, tamper: TrailTamper) {
    let text = std::fs::read_to_string(trail).expect("read trail");
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        lines.len() >= 2,
        "fixture trail needs >= 2 lines: {}",
        lines.len()
    );
    let rm_mark = || std::fs::remove_file(seq_mark(trail)).expect("remove mark");
    match tamper {
        TrailTamper::None => {}
        TrailTamper::TailCutMarkRemoved => {
            let keep = lines[..lines.len() - 1].join("\n") + "\n";
            std::fs::write(trail, keep).expect("cut tail");
            rm_mark();
        }
        TrailTamper::AllButHeadMarkRemoved => {
            std::fs::write(trail, format!("{}\n", lines[0])).expect("keep head");
            rm_mark();
        }
        TrailTamper::ZeroBytesMarkRemoved => {
            std::fs::write(trail, b"").expect("zero bytes");
            rm_mark();
        }
        TrailTamper::Deleted => {
            std::fs::remove_file(trail).expect("delete trail");
            rm_mark();
        }
        TrailTamper::DeletedMarkKept => {
            std::fs::remove_file(trail).expect("delete trail");
        }
    }
}

#[test]
fn audit_trail_tamper_table_8867() {
    let table: [(TrailTamper, Option<&str>); 6] = [
        (TrailTamper::None, None),
        (
            TrailTamper::TailCutMarkRemoved,
            Some(REASON_SEQ_MARK_MISSING),
        ),
        (
            TrailTamper::AllButHeadMarkRemoved,
            Some(REASON_SEQ_MARK_MISSING),
        ),
        (
            TrailTamper::ZeroBytesMarkRemoved,
            Some(REASON_AUDIT_LOG_EMPTY),
        ),
        (TrailTamper::Deleted, Some(REASON_AUDIT_LOG_MISSING)),
        (TrailTamper::DeletedMarkKept, Some(REASON_AUDIT_LOG_MISSING)),
    ];
    for (tamper, reason) in table {
        let home = Home::new(Some(true));
        for i in 0..TRAIL_WRITES {
            let title = format!("trail-{i}");
            assert_ok(&home.run(&[], &["store", "--title", &title, "--content", "c"]));
        }
        assert!(
            seq_mark(&home.trail()).exists(),
            "writer keeps a sequence mark"
        );
        tamper_trail(&home.trail(), tamper);
        for json in [false, true] {
            let mut args = vec!["audit", "verify"];
            if json {
                args.push("--json");
            }
            let out = home.run(&[], &args);
            match reason {
                None => assert_ok(&out),
                Some(r) => assert_finding(&out, EXIT_AUDIT_FAIL, r),
            }
        }
    }
}

#[test]
fn audit_verify_disabled_trail_says_so_8867() {
    let home = Home::new(Some(false));
    let out = home.run(&[], &["audit", "verify", "--json"]);
    assert_ok(&out);
    assert!(both(&out).contains("disabled"), "{}", both(&out));
}

// ─────────────────────────────────────────────────────────────────────
// audit verify --since, forensic window (#9009) — library funnel
// ─────────────────────────────────────────────────────────────────────

const DAY_OLD: &str = "2026-01-01";
const DAY_MID: &str = "2026-01-02";
const DAY_NEW: &str = "2026-01-03";
const ROWS_PER_DAY: usize = 3;

fn forensic_row(prev: &str, n: usize, key: Option<&SigningKey>) -> ForensicDecision {
    let mut row = ForensicDecision {
        ts: format!("2026-01-01T00:00:{n:02}Z"),
        actor: "ai:forensic-8741".to_string(),
        decision: "allow".to_string(),
        kind: "probe".to_string(),
        rule_id: format!("r{n}"),
        payload: serde_json::json!({ "n": n }),
        prev_hash: prev.to_string(),
        sig: String::new(),
    };
    if let Some(k) = key {
        let sig = k.sign(&row.canonical_bytes());
        row.sig = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    }
    row
}

/// Write `days` day files chained from the head. `signed(day, row)` picks
/// which rows carry a signature.
fn write_forensic(
    dir: &Path,
    days: &[&str],
    key: &SigningKey,
    signed: impl Fn(usize, usize) -> bool,
) -> Vec<PathBuf> {
    let mut prev = CHAIN_HEAD_PREV_HASH.to_string();
    let mut n = 0;
    let mut paths = Vec::new();
    for (d, day) in days.iter().enumerate() {
        let mut body = String::new();
        for r in 0..ROWS_PER_DAY {
            let row = forensic_row(&prev, n, signed(d, r).then_some(key));
            prev = row.self_hash();
            body.push_str(&serde_json::to_string(&row).expect("row json"));
            body.push('\n');
            n += 1;
        }
        let p = dir.join(format!("{FORENSIC_FILE_PREFIX}{day}.jsonl"));
        std::fs::write(&p, body).expect("write day file");
        paths.push(p);
    }
    paths
}

#[test]
fn forensic_window_tamper_table_9009() {
    let key = SigningKey::from_bytes(&FORENSIC_SEED);
    let pk = key.verifying_key();
    let days = [DAY_OLD, DAY_MID, DAY_NEW];

    // Clean, all signed: green.
    let clean = TempDir::new().expect("tempdir");
    write_forensic(clean.path(), &days, &key, |_, _| true);
    let r = verify_since(clean.path(), DAY_NEW, Some(&pk)).expect("verify");
    assert_eq!(r.first_failure, None, "clean chain is green");

    // A rewritten row BEFORE the window: the pre-window walk must check
    // links, so the break is reported with its position.
    let pre = TempDir::new().expect("tempdir");
    let files = write_forensic(pre.path(), &days, &key, |_, _| true);
    let text = std::fs::read_to_string(&files[0]).expect("read");
    std::fs::write(&files[0], text.replacen("\"r0\"", "\"rX\"", 1)).expect("rewrite");
    let r = verify_since(pre.path(), DAY_NEW, Some(&pk)).expect("verify");
    let f = r.first_failure.expect("pre-window rewrite is a finding");
    assert_eq!(f.kind, VerifyFailureKind::ChainBreak);
    assert_eq!(f.file, files[0]);
    assert_eq!(f.line_number, 2, "the row after the rewritten one breaks");

    // Signature downgrade: an unsigned row after a signed one.
    let down = TempDir::new().expect("tempdir");
    let files = write_forensic(down.path(), &days, &key, |d, r| !(d == 2 && r == 1));
    let r = verify_since(down.path(), DAY_OLD, Some(&pk)).expect("verify");
    let f = r.first_failure.expect("downgrade is a finding");
    assert_eq!(f.kind, VerifyFailureKind::Signature);
    assert_eq!(f.file, files[2]);
    assert_eq!(f.line_number, 2);
    assert!(
        f.detail.contains(REASON_FORENSIC_SIGNATURE_ABSENT),
        "{}",
        f.detail
    );

    // A legitimate unsigned prefix (rows written before a key existed)
    // stays green.
    let prefix = TempDir::new().expect("tempdir");
    write_forensic(prefix.path(), &days, &key, |d, _| d > 0);
    let r = verify_since(prefix.path(), DAY_OLD, Some(&pk)).expect("verify");
    assert_eq!(
        r.first_failure, None,
        "unsigned prefix then signed is green"
    );
}

// ─────────────────────────────────────────────────────────────────────
// verify-reflection-chain: missing root is a finding
// ─────────────────────────────────────────────────────────────────────

#[test]
fn reflection_chain_missing_root_is_a_finding() {
    let home = Home::new(None);
    assert_ok(&home.run(&[], &["store", "--title", "t", "--content", "c"]));
    let out = home.run(
        &[],
        &[
            "verify-reflection-chain",
            "00000000-0000-4000-8000-000000008741",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(EXIT_REFLECTION_FAIL),
        "{}",
        both(&out)
    );
}

// ─────────────────────────────────────────────────────────────────────
// Registry: every verify command has a tamper row in this file
// ─────────────────────────────────────────────────────────────────────

/// Every verify command of the default CLI, each with the test above that
/// tampers it. A new `verify*` command fails `every_verify_command_has_a_tamper_row`
/// until it is added here WITH a tamper row.
const VERIFY_COMMANDS_WITH_TAMPER_ROW: &[(&str, &str)] = &[
    ("verify-forensic-bundle", "bundle_tamper_table_8851"),
    (
        "verify-signed-events-chain",
        "chain_verifiers_empty_chain_is_a_finding_8741",
    ),
    (
        "verify-audit-trail",
        "chain_verifiers_empty_chain_is_a_finding_8741",
    ),
    (
        "verify-reflection-chain",
        "reflection_chain_missing_root_is_a_finding",
    ),
];

/// `audit` subcommands that verify, each with its tamper row.
const AUDIT_VERIFY_SUBCOMMANDS: &[(&str, &str)] = &[("verify", "audit_trail_tamper_table_8867")];

fn help_commands(out: &Output) -> Vec<String> {
    let text = String::from_utf8_lossy(&out.stdout);
    let mut in_cmds = false;
    let mut cmds = Vec::new();
    for line in text.lines() {
        if line.trim_end() == "Commands:" {
            in_cmds = true;
            continue;
        }
        if in_cmds {
            if !line.starts_with("  ") {
                break;
            }
            if let Some(name) = line.split_whitespace().next() {
                cmds.push(name.to_string());
            }
        }
    }
    cmds
}

#[test]
fn every_verify_command_has_a_tamper_row() {
    let home = Home::new(None);
    let top = help_commands(&home.run(&[], &["--help"]));
    assert!(top.len() > 10, "help parse found commands: {top:?}");
    for cmd in top.iter().filter(|c| c.starts_with("verify")) {
        assert!(
            VERIFY_COMMANDS_WITH_TAMPER_ROW
                .iter()
                .any(|(c, _)| c == cmd),
            "verify command {cmd} has no tamper row in tests/verify_false_green_8741.rs"
        );
    }
    for (cmd, _) in VERIFY_COMMANDS_WITH_TAMPER_ROW {
        assert!(
            top.contains(&(*cmd).to_string()),
            "{cmd} is not a CLI command"
        );
    }
    let audit = help_commands(&home.run(&[], &["audit", "--help"]));
    for sub in audit.iter().filter(|c| c.contains("verify")) {
        assert!(
            AUDIT_VERIFY_SUBCOMMANDS.iter().any(|(c, _)| c == sub),
            "audit {sub} has no tamper row"
        );
    }
}
