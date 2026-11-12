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
const REASON_DAY_FILE_MISSING: &str = "day_file_missing";
const REASON_FORENSIC_LOG_MISSING: &str = "forensic_log_missing";
const REASON_FORENSIC_WINDOW_EMPTY: &str = "forensic_window_empty";
const REASON_FORENSIC_SIGNATURE_UNVERIFIED: &str = "signature_unverified";
/// Forensic: a verifying key that exists on disk but does not load (F3).
const REASON_FORENSIC_KEY_LOAD_FAILED: &str = "key_load_failed";
const REASON_HEAD_BELOW_SINCE: &str = "head_below_since";
const REASON_STORE_URL_UNRECOGNISED: &str = "store_url_unrecognised";
const STORE_URL_FILE_ENV: &str = "AI_MEMORY_STORE_URL_FILE";
const FAR_FUTURE_RFC3339: &str = "2999-01-01T00:00:00Z";

const MANIFEST_FILE: &str = "manifest.json";
const SIGNER_AGENT: &str = "ai:bundle-signer-8741";
const UNKNOWN_SIGNER: &str = "ai:nobody-8741";
/// A signer whose `.pub` file exists but is not a 32-byte Ed25519 key.
const UNLOADABLE_SIGNER: &str = "ai:broken-key-8741";
/// Bytes of the truncated `.pub` file (any length other than 32).
const UNLOADABLE_PUB_BYTES: &[u8] = b"not-a-key";
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
        let out = home.run(&[], args);
        assert_ok(&out);
        // #9179 r1 — green states its coverage: the tail is not protected yet.
        assert!(
            both(&out).contains("unanchored_tail="),
            "{args:?}: {}",
            both(&out)
        );
    }
}

fn write_url_file(home: &Home, url: &str) -> PathBuf {
    let p = home.path().join("store.url");
    std::fs::write(&p, url).expect("write url file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    p
}

/// #9179 r1 security F1 / Decision 3 — the store-URL channels of
/// verify-signed-events-chain: a configured store is never ignored in
/// favour of `--db`, and a Postgres URL VALUE is refused.
#[test]
fn signed_events_chain_store_url_table_9179() {
    // A sqlite:// URL in the environment opens THAT file, here an empty chain,
    // while --db holds a populated one.
    let home = Home::new(None);
    assert_ok(&home.run(&[], &["store", "--title", "t", "--content", "c"]));
    let other = Home::new(None);
    store_with_empty_chain(&other);
    let other_url = format!("sqlite://{}", other.db().display());
    let out = home.run(
        &[(STORE_URL_ENV, &other_url)],
        &["verify-signed-events-chain"],
    );
    assert_finding(&out, EXIT_CHAIN_FAIL, REASON_EMPTY_CHAIN);
    // The same through --store-url-file and through the URL-file env.
    let url_file = write_url_file(&home, &other_url);
    let url_file_s = url_file.to_str().expect("utf-8 path");
    let out = home.run(
        &[],
        &["verify-signed-events-chain", "--store-url-file", url_file_s],
    );
    assert_finding(&out, EXIT_CHAIN_FAIL, REASON_EMPTY_CHAIN);
    let out = home.run(
        &[(STORE_URL_FILE_ENV, url_file_s)],
        &["verify-signed-events-chain"],
    );
    assert_finding(&out, EXIT_CHAIN_FAIL, REASON_EMPTY_CHAIN);
    // An unknown scheme is a finding, never a walk of --db.
    for url in ["bogus://h/x", "mysql://h/db"] {
        let out = home.run(&[(STORE_URL_ENV, url)], &["verify-signed-events-chain"]);
        assert_finding(&out, EXIT_CHAIN_FAIL, REASON_STORE_URL_UNRECOGNISED);
    }
    // A Postgres URL value (env) is refused with the URL-file hint.
    for url in [
        PG_URL_NEVER_DIALLED,
        "postgresql://verify8741@127.0.0.1:1/never",
    ] {
        let out = home.run(&[(STORE_URL_ENV, url)], &["verify-signed-events-chain"]);
        assert_finding(&out, EXIT_CHAIN_FAIL, REASON_STORE_IS_POSTGRES);
        assert!(both(&out).contains("--store-url-file"), "{}", both(&out));
    }
}

/// #9179 r1 code F5 / security F6 — a window that checks no row is
/// `head_below_since` on both chain verifiers; a negative --since is refused.
#[test]
fn chain_verifiers_since_past_head_is_a_finding_9179() {
    let home = Home::new(None);
    assert_ok(&home.run(&[], &["store", "--title", "t", "--content", "c"]));
    let table: [&[&str]; 4] = [
        &["verify-signed-events-chain", "--since", "999999"],
        &[
            "verify-signed-events-chain",
            "--since",
            "999999",
            "--format",
            "json",
        ],
        &["verify-audit-trail", "--since", FAR_FUTURE_RFC3339],
        &[
            "verify-audit-trail",
            "--since",
            FAR_FUTURE_RFC3339,
            "--json",
        ],
    ];
    for args in table {
        let out = home.run(&[], args);
        assert_finding(&out, EXIT_CHAIN_FAIL, REASON_HEAD_BELOW_SINCE);
    }
    let out = home.run(&[], &["verify-signed-events-chain", "--since=-1"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "clap usage error: {}",
        both(&out)
    );
}

/// #9179 r1 code F4 / F10c — absence in JSON mode is a JSON body with the
/// reason on stdout, the same shape on both chain verifiers.
#[test]
fn chain_verifiers_json_absence_shape_9179() {
    let home = Home::new(None);
    store_with_empty_chain(&home);
    for args in [
        &["verify-signed-events-chain", "--format", "json"][..],
        &["verify-audit-trail", "--json"][..],
    ] {
        let out = home.run(&[], args);
        assert_eq!(out.status.code(), Some(EXIT_CHAIN_FAIL), "{}", both(&out));
        let v: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("JSON body on stdout");
        assert_eq!(v["status"], "fail", "{args:?}: {v}");
        assert_eq!(v["reason"], REASON_EMPTY_CHAIN, "{args:?}: {v}");
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

/// `(day index, row index) -> signed?` for a [`write_forensic`] fixture.
type SignedRowPredicate = fn(usize, usize) -> bool;

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

    // #9179 r1 code F1 (HIGH) / security F2 — the signature is outside the
    // hash chain, so with a verifying key present EVERY in-window unsigned row
    // is a finding. No anchored pre-key boundary exists, so no exemption:
    // all-stripped and prefix-stripped are both `signature_absent` at the
    // first unsigned row.
    let stripped: [(&str, SignedRowPredicate); 3] = [
        ("all-stripped", |_, _| false),
        ("prefix-stripped", |d, _| d > 0),
        ("one-row-prefix-stripped", |d, r| d > 0 || r > 0),
    ];
    for (name, signed) in stripped {
        let dir = TempDir::new().expect("tempdir");
        let files = write_forensic(dir.path(), &days, &key, signed);
        let r = verify_since(dir.path(), DAY_OLD, Some(&pk)).expect("verify");
        let f = r.first_failure.expect(name);
        assert_eq!(f.kind, VerifyFailureKind::Signature, "{name}");
        assert_eq!(f.reason, REASON_FORENSIC_SIGNATURE_ABSENT, "{name}");
        assert_eq!(f.file, files[0], "{name}");
        assert_eq!(f.line_number, 1, "{name}");
    }

    // #9179 r1 Decision 2 — a removed middle day file breaks the link into
    // the next file: `day_file_missing`, at line 1 of that next file.
    let gap = TempDir::new().expect("tempdir");
    let files = write_forensic(gap.path(), &days, &key, |_, _| true);
    std::fs::remove_file(&files[1]).expect("remove middle day file");
    let r = verify_since(gap.path(), DAY_OLD, Some(&pk)).expect("verify");
    let f = r.first_failure.expect("removed day file is a finding");
    assert_eq!(f.reason, REASON_DAY_FILE_MISSING);
    assert_eq!(f.file, files[2]);
    assert_eq!(f.line_number, 1);
}

/// #9179 r1 code F2 / F3 / F8 — the CLI funnel of the forensic mode
/// (`audit verify --since`): absence and an unverifiable signature are
/// findings with exit 2 and their reason, in text and JSON.
#[test]
fn forensic_since_cli_absence_table_9179() {
    let key = SigningKey::from_bytes(&FORENSIC_SEED);
    let days = [DAY_OLD, DAY_MID, DAY_NEW];
    let cases: [(&str, &str); 4] = [
        ("no-day-file", REASON_FORENSIC_LOG_MISSING),
        ("window-past-every-file", REASON_FORENSIC_WINDOW_EMPTY),
        ("signed-rows-no-key", REASON_FORENSIC_SIGNATURE_UNVERIFIED),
        ("key-exists-but-unloadable", REASON_FORENSIC_KEY_LOAD_FAILED),
    ];
    for (case, reason) in cases {
        let home = Home::new(Some(true));
        let audit_dir = home.path().join("audit");
        std::fs::create_dir_all(&audit_dir).expect("audit dir");
        let since = match case {
            "no-day-file" => DAY_OLD,
            "window-past-every-file" => {
                write_forensic(&audit_dir, &days, &key, |_, _| true);
                "2999-01-01"
            }
            _ => {
                // Signed with a key the verifier does not hold.
                write_forensic(&audit_dir, &days, &key, |_, _| true);
                DAY_OLD
            }
        };
        // #9179 F3 — a key file that exists but does not load is a finding,
        // never treated as "no key" (which would skip every signature check).
        let signer = if case == "key-exists-but-unloadable" {
            std::fs::write(
                home.path()
                    .join("keys")
                    .join(format!("{UNLOADABLE_SIGNER}.pub")),
                UNLOADABLE_PUB_BYTES,
            )
            .expect("write unloadable pub");
            UNLOADABLE_SIGNER
        } else {
            UNKNOWN_SIGNER
        };
        for json in [false, true] {
            let mut args = vec!["audit", "verify", "--since", since];
            // A signer id with no key on this host: the boot never mints
            // one for it, so the verifier holds no key for these rows.
            args.extend(["--forensic-agent-id", signer]);
            if json {
                args.push("--json");
            }
            let out = home.run(&[], &args);
            assert_finding(&out, EXIT_AUDIT_FAIL, reason);
            assert!(!both(&out).contains("verify OK"), "{case}: {}", both(&out));
        }
    }
}

/// #9179 r1 F11 — `audit verify --path <copy>` of an archived trail: green
/// with its sequence mark, `seq_mark_missing` without it. No acknowledgement
/// flag exists (b29 ruling: no escape hatch on a verifier).
#[test]
fn audit_verify_path_copy_table_9179() {
    let home = Home::new(Some(true));
    for i in 0..TRAIL_WRITES {
        let title = format!("copy-{i}");
        assert_ok(&home.run(&[], &["store", "--title", &title, "--content", "c"]));
    }
    let archive = home.path().join("archive");
    std::fs::create_dir_all(&archive).expect("archive dir");
    let copy = archive.join("audit.log");
    std::fs::copy(home.trail(), &copy).expect("copy trail");
    let copy_s = copy.to_str().expect("utf-8 path").to_string();
    // Without the sequence mark the copy is not provably whole.
    let out = home.run(&[], &["audit", "verify", "--path", &copy_s]);
    assert_finding(&out, EXIT_AUDIT_FAIL, REASON_SEQ_MARK_MISSING);
    std::fs::copy(seq_mark(&home.trail()), seq_mark(&copy)).expect("copy mark");
    assert_ok(&home.run(&[], &["audit", "verify", "--path", &copy_s]));
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

/// #9179 r1 code F8 — flags that switch a verify command to another code
/// path (another store, another log). Each (command, flag) pair the CLI
/// offers needs its own absence or tamper row.
const MODE_FLAGS: &[&str] = &["--since", "--store-url", "--store-url-file", "--path"];

/// (command path, mode flag, test fn) rows. `audit verify --since` is the
/// forensic walk, a different verifier from the flat trail.
const VERIFY_MODE_ROWS: &[(&str, &str, &str)] = &[
    (
        "audit verify",
        "--since",
        "forensic_since_cli_absence_table_9179",
    ),
    (
        "audit verify",
        "--path",
        "audit_verify_path_copy_table_9179",
    ),
    (
        "verify-signed-events-chain",
        "--since",
        "chain_verifiers_since_past_head_is_a_finding_9179",
    ),
    (
        "verify-signed-events-chain",
        "--store-url-file",
        "signed_events_chain_store_url_table_9179",
    ),
    (
        "verify-audit-trail",
        "--since",
        "chain_verifiers_since_past_head_is_a_finding_9179",
    ),
    (
        "verify-audit-trail",
        "--store-url",
        "store_url_pg_empty_chain_is_a_finding_8741",
    ),
];

/// The long flags a `--help` page DEFINES: only option lines (a trimmed line
/// that starts with `-`) count, so a flag named inside another flag's prose
/// (the global `--db` doc mentions `serve --store-url`) is not a mode flag.
fn help_flags(out: &Output) -> Vec<String> {
    let text = String::from_utf8_lossy(&out.stdout);
    let mut flags = Vec::new();
    for line in text.lines().map(str::trim_start) {
        if !line.starts_with('-') {
            continue;
        }
        for word in line.split_whitespace() {
            let word = word.trim_end_matches(',');
            if !word.starts_with('-') {
                break;
            }
            if let Some(long) = word.strip_prefix("--").filter(|w| !w.is_empty()) {
                let name = long.split('=').next().unwrap_or(long);
                flags.push(format!("--{name}"));
            }
        }
    }
    flags
}

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
    // (command, mode) registry: every mode flag a verify command offers has
    // a row, and every row names a test fn that exists in a test file.
    let mut paths: Vec<String> = top
        .iter()
        .filter(|c| c.starts_with("verify"))
        .cloned()
        .collect();
    paths.extend(
        audit
            .iter()
            .filter(|c| c.contains("verify"))
            .map(|c| format!("audit {c}")),
    );
    for path in &paths {
        let mut argv: Vec<&str> = path.split(' ').collect();
        argv.push("--help");
        let flags = help_flags(&home.run(&[], &argv));
        for flag in MODE_FLAGS.iter().filter(|f| flags.iter().any(|g| g == *f)) {
            assert!(
                VERIFY_MODE_ROWS
                    .iter()
                    .any(|(c, m, _)| c == path && m == flag),
                "{path} {flag} has no (command, mode) row in tests/verify_false_green_8741.rs"
            );
        }
    }
    let sources = [
        include_str!("verify_false_green_8741.rs"),
        include_str!("verify_audit_trail_store_url_prb.rs"),
    ];
    for (cmd, flag, test) in VERIFY_MODE_ROWS {
        let needle = format!("fn {test}(");
        assert!(
            sources.iter().any(|src| src.contains(&needle)),
            "row ({cmd}, {flag}) names {test}, which is not a test fn"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────
// PostgreSQL cell: verify-signed-events-chain through --store-url-file
// ─────────────────────────────────────────────────────────────────────

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

/// #9179 r1 (backend parity) — `verify-signed-events-chain --store-url-file`
/// on a live Postgres store: a populated chain is green, a broken link is a
/// red finding (never green), and the credentialed URL never reaches the
/// output. Runs on a scratch database it creates and drops.
#[cfg(feature = "sal-postgres")]
mod postgres_store_url_file {
    use super::{EXIT_CHAIN_FAIL, EXIT_OK, Home, both, pg_barrier, write_url_file};
    use ai_memory::store::postgres::PostgresStore;

    /// Scratch database name prefix for this file.
    const SCRATCH_PREFIX: &str = "ai_memory_9179vsec";
    /// Rows appended before the walk (more than one, so a break has a
    /// predecessor to disagree with).
    const CHAIN_ROWS: i64 = 4;
    /// The JSON field that carries the walk's verdict.
    const CHAIN_HOLDS_TRUE: &str = "\"chain_holds\": true";
    const CHAIN_HOLDS_FALSE: &str = "\"chain_holds\": false";

    async fn pg_head(pg: &PostgresStore) -> i64 {
        sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) FROM signed_events")
            .fetch_one(pg.pool())
            .await
            .expect("read pg head")
    }

    #[track_caller]
    fn assert_no_secret(text: &str, url: &str) {
        assert!(
            !text.contains(url),
            "the store URL must never be echoed verbatim"
        );
        // The userinfo (`user:password`) between `://` and `@`.
        let userinfo = url
            .split_once("://")
            .and_then(|(_, rest)| rest.split_once('@'))
            .map(|(info, _)| info);
        if let Some(pw) = userinfo
            .and_then(|info| info.split_once(':'))
            .map(|(_, pw)| pw)
            .filter(|pw| !pw.is_empty())
        {
            assert!(
                !text.contains(pw),
                "the store password must never be echoed"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_signed_events_chain_store_url_file_cell_9179() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
            .await
            .expect("create scratch database");
        let scratch_url = scratch.url();
        let pg = PostgresStore::connect(&scratch_url)
            .await
            .expect("connect scratch database");
        let mut n = 0;
        while pg_head(&pg).await < CHAIN_ROWS {
            n += 1;
            pg.emit_spawn_audit(&format!("argv0-{n}"), "9179-pg-cell")
                .await;
        }
        let home = Home::new(None);
        let url_file = write_url_file(&home, &scratch_url);
        let url_file_s = url_file.to_str().expect("utf-8 path").to_string();
        let argv = [
            "verify-signed-events-chain",
            "--store-url-file",
            url_file_s.as_str(),
            "--format",
            "json",
        ];

        // Green: the populated Postgres chain walks and holds.
        let out = tokio::task::spawn_blocking({
            let argv: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
            let home_dir = home.path().to_path_buf();
            move || run_in(&home_dir, &argv)
        })
        .await
        .expect("join");
        let text = both(&out);
        assert_no_secret(&text, &scratch_url);
        assert_eq!(out.status.code(), Some(EXIT_OK), "green pg chain: {text}");
        assert!(text.contains(CHAIN_HOLDS_TRUE), "green pg chain: {text}");

        // Red: break the link of the head row (prev_hash no longer names its
        // predecessor). Triggers are bypassed for this one tamper statement.
        let mut tx = pg.pool().begin().await.expect("begin");
        sqlx::query("SET LOCAL session_replication_role = replica")
            .execute(&mut *tx)
            .await
            .expect("bypass append-only triggers");
        sqlx::query(
            "UPDATE signed_events SET prev_hash = decode(repeat('ab', 32), 'hex') \
             WHERE sequence = (SELECT MAX(sequence) FROM signed_events)",
        )
        .execute(&mut *tx)
        .await
        .expect("tamper head link");
        tx.commit().await.expect("commit tamper");

        let out = tokio::task::spawn_blocking({
            let argv: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
            let home_dir = home.path().to_path_buf();
            move || run_in(&home_dir, &argv)
        })
        .await
        .expect("join");
        let text = both(&out);
        assert_no_secret(&text, &scratch_url);
        assert_eq!(
            out.status.code(),
            Some(EXIT_CHAIN_FAIL),
            "a broken pg chain is red: {text}"
        );
        assert!(text.contains(CHAIN_HOLDS_FALSE), "broken pg chain: {text}");
        pg.pool().close().await;
        drop(scratch);
    }

    /// `Home::run` without borrowing the `Home` across the blocking task.
    fn run_in(home_dir: &std::path::Path, argv: &[String]) -> std::process::Output {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", home_dir)
            .env("XDG_CONFIG_HOME", home_dir.join(".config"))
            .env("AI_MEMORY_KEY_DIR", home_dir.join("keys"))
            .env("AI_MEMORY_NO_CONFIG", "1")
            .current_dir(home_dir)
            .arg("--db")
            .arg(home_dir.join("store.db"))
            .args(argv);
        cmd.output().expect("spawn ai-memory")
    }
}
