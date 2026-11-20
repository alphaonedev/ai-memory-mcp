// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioural impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! #9505 / #9507 — `verify-reflection-chain` decides the root content-id
//! check BEFORE it prints anything, and that check feeds the one final `ok`
//! and the exit code (3-agent vote (71472661), B + J1).
//!
//! The root's content-id state is one of four, and every state has a cell in
//! BOTH output modes (text and `--format json`):
//!
//! | state      | fixture                         | `ok`  | exit |
//! |------------|---------------------------------|-------|------|
//! | verified   | the genesis the insert wrote    | true  | 0    |
//! | mismatch   | a well-typed but wrong genesis  | false | 2    |
//! | unreadable | a genesis that does not decode  | false | 2    |
//! | absent     | NULL genesis (nothing to check) | true  | 0    |
//!
//! Every cell pins the exact exit code, that stdout carries no passing
//! summary line when `ok` is false, that JSON stdout is ONE parseable
//! document, that the error class is named, and that neither the database
//! path nor the raw stored bytes reach either stream. Two binary-level cells
//! drive the built `ai-memory` so the exit code is the real process status,
//! not the library return (W-4: exit 2 must not leave through the generic
//! `Err` path, which `main` turns into exit 1 = NOT FOUND's code).
//!
//! The forensic-bundle builder calls the report builder directly and must
//! keep `verification.json` byte-identical (W-3), and the operator doc must
//! list the codes the verb really returns (#9507).

use std::path::{Path, PathBuf};
use std::process::Output;

use ai_memory::cli::CliOutput;
use ai_memory::cli::verify::{self as cli_verify, VerifyChainArgs};
use ai_memory::db;
use ai_memory::forensic::bundle::{self, ExportForensicBundleArgs};
use ai_memory::models::{Memory, Tier};
use rusqlite::Connection;
use serde_json::{Value, json};

/// Scratch root under the crate (the project's no-`/tmp` rule).
const RUNS_DIR: &str = ".local-runs/verify-chain-genesis-exit-code-9505";
const NAMESPACE: &str = "verify-chain-9505";
const ROOT_ID: &str = "root-9505";
const PARENT_ID: &str = "parent-9505";
const CREATED_AT: &str = "2026-06-30T00:00:00Z";
const PARENT_CREATED_AT: &str = "2026-01-01T00:00:00Z";
const PINNED_GENERATED_AT: &str = "2026-11-18T00:00:00Z";

/// Exit codes of the verb (#3436 NOT FOUND = 1, #709 FAILED = 2).
const EXIT_OK: i32 = 0;
const EXIT_NOT_FOUND: i32 = 1;
const EXIT_FAILED: i32 = 2;

/// A well-typed genesis that is not the pre-image of the stored cid.
const MISMATCH_GENESIS_SQL: &str = "X'DEADBEEFCAFE0102'";
/// The raw bytes of [`MISMATCH_GENESIS_SQL`], lower-cased: never printed.
const MISMATCH_RAW_HEX: &str = "deadbeefcafe0102";
/// Genesis values that do not decode as a BLOB, each with a marker of its
/// stored content that must never be printed.
const UNREADABLE_GENESIS: &[(&str, &str)] = &[
    ("'not-a-blob'", "not-a-blob"),
    ("424242", "424242"),
    ("1.5e300", "1.5e300"),
];
/// The class the verb names for a genesis that does not decode.
const CLASS_DECODE: &str = "decode_error";

const SUMMARY_PREFIX: &str = "verify-reflection-chain: root=";
const CID_LINE: &str = "cid_verified:   ";
const STDERR_MISMATCH: &str = "root content-id mismatch";
const STDERR_UNREADABLE: &str = "root content-id genesis unreadable";
/// The prefix `main`'s generic `Err` path prints (std `Termination`).
const GENERIC_ERR_PREFIX: &str = "Error:";

// ---- fixtures --------------------------------------------------------------

fn scratch_dir(test: &str) -> tempfile::TempDir {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(RUNS_DIR);
    std::fs::create_dir_all(&root).expect("create runs dir");
    tempfile::Builder::new()
        .prefix(&format!("{test}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn mem(id: &str, created_at: &str, depth: i32) -> Memory {
    Memory {
        id: id.to_string(),
        title: format!("title {id}"),
        content: format!("content {id}"),
        namespace: NAMESPACE.to_string(),
        tier: Tier::Long,
        reflection_depth: depth,
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        metadata: json!({ "agent_id": "ai:test@host" }),
        ..Default::default()
    }
}

fn set_genesis(conn: &Connection, value_sql: &str) {
    conn.execute(
        &format!("UPDATE memories SET cid_genesis = {value_sql} WHERE id = ?1"),
        [ROOT_ID],
    )
    .expect("set genesis");
}

/// A fresh database holding the root; `genesis_sql` overwrites its genesis.
fn seeded_db(dir: &Path, genesis_sql: Option<&str>) -> PathBuf {
    let path = dir.join("scratch.db");
    let conn = db::open(&path).expect("open scratch db");
    db::insert(&conn, &mem(ROOT_ID, CREATED_AT, 0)).expect("insert root");
    if let Some(sql) = genesis_sql {
        set_genesis(&conn, sql);
    }
    path
}

fn root_cid(path: &Path) -> String {
    let conn = db::open(path).expect("reopen scratch db");
    db::get(&conn, ROOT_ID)
        .expect("get root")
        .expect("root exists")
        .cid
        .expect("insert stamps a cid")
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_lib(path: &Path, format: &str) -> Run {
    run_lib_with(path, format, false)
}

/// The library entry point; `cid` adds the fleet-wide `--cid` sweep.
fn run_lib_with(path: &Path, format: &str, cid: bool) -> Run {
    let args = VerifyChainArgs {
        memory_id: ROOT_ID.to_string(),
        format: format.to_string(),
        include_signed_events: false,
        cid,
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let res = {
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        cli_verify::run(path, &args, &mut out)
    };
    let stdout = String::from_utf8(stdout).expect("utf8 stdout");
    let stderr = String::from_utf8(stderr).expect("utf8 stderr");
    let code = res.unwrap_or_else(|e| {
        panic!("verify must return an exit code, not Err: {e:#}\nstdout: {stdout}")
    });
    Run {
        code,
        stdout,
        stderr,
    }
}

fn run_bin(dir: &Path, path: &Path, json_mode: bool) -> Output {
    run_bin_with(dir, path, json_mode, false)
}

/// The built binary; `cid` adds the fleet-wide `--cid` sweep.
fn run_bin_with(dir: &Path, path: &Path, json_mode: bool, cid: bool) -> Output {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(dir)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .arg("--db")
        .arg(path)
        .args(["verify-reflection-chain", ROOT_ID]);
    if json_mode {
        cmd.args(["--format", "json"]);
    }
    if cid {
        cmd.arg("--cid");
    }
    cmd.output().expect("spawn ai-memory")
}

// ---- shared assertions -----------------------------------------------------

/// Neither stream carries the database path or a marker of the raw bytes.
fn assert_no_leak(run: &Run, path: &Path, raw_marker: &str) {
    let path_text = path.display().to_string();
    let dir_text = path
        .parent()
        .expect("db has a parent")
        .display()
        .to_string();
    for (name, stream) in [("stdout", &run.stdout), ("stderr", &run.stderr)] {
        let lower = stream.to_ascii_lowercase();
        assert!(
            !stream.contains(&path_text) && !stream.contains(&dir_text),
            "{name} leaks the database path:\n{stream}"
        );
        assert!(
            !lower.contains(&raw_marker.to_ascii_lowercase()),
            "{name} leaks the stored bytes ({raw_marker}):\n{stream}"
        );
    }
}

/// The text summary line carries the ONE final verdict.
fn assert_text_summary(run: &Run, ok: bool) {
    let summaries: Vec<&str> = run
        .stdout
        .lines()
        .filter(|l| l.starts_with(SUMMARY_PREFIX))
        .collect();
    assert_eq!(summaries.len(), 1, "one summary line:\n{}", run.stdout);
    assert!(
        summaries[0].ends_with(&format!(" ok={ok}")),
        "the summary line must carry ok={ok}:\n{}",
        run.stdout
    );
    if !ok {
        assert!(
            !run.stdout.contains("ok=true"),
            "no passing summary when ok is false:\n{}",
            run.stdout
        );
    }
}

/// JSON stdout is ONE document; returns it.
fn one_json_doc(run: &Run) -> Value {
    let mut docs = serde_json::Deserializer::from_str(&run.stdout).into_iter::<Value>();
    let first = docs
        .next()
        .expect("one document")
        .unwrap_or_else(|e| panic!("stdout must parse as JSON: {e}\n{}", run.stdout));
    assert!(
        docs.next().is_none(),
        "stdout must hold exactly one JSON document:\n{}",
        run.stdout
    );
    first
}

// ---- verified ----------------------------------------------------------------

#[test]
fn verified_root_text_exits_0_with_true_line_9505() {
    let dir = scratch_dir("verified-text");
    let path = seeded_db(dir.path(), None);
    let cid = root_cid(&path);
    let run = run_lib(&path, "text");
    assert_eq!(run.code, EXIT_OK, "stdout: {}", run.stdout);
    assert_text_summary(&run, true);
    assert!(
        run.stdout.contains(&format!("{CID_LINE}true ({cid})")),
        "verified line:\n{}",
        run.stdout
    );
    assert!(run.stderr.is_empty(), "stderr: {}", run.stderr);
}

#[test]
fn verified_root_json_exits_0_with_verified_state_9505() {
    let dir = scratch_dir("verified-json");
    let path = seeded_db(dir.path(), None);
    let cid = root_cid(&path);
    let run = run_lib(&path, "json");
    assert_eq!(run.code, EXIT_OK, "stdout: {}", run.stdout);
    let v = one_json_doc(&run);
    assert_eq!(v["ok"], json!(true), "{}", run.stdout);
    assert_eq!(
        v["root_cid"],
        json!({ "state": "verified", "cid": cid }),
        "{}",
        run.stdout
    );
}

// ---- mismatch ----------------------------------------------------------------

#[test]
fn mismatch_root_text_exits_2_without_passing_summary_9505() {
    let dir = scratch_dir("mismatch-text");
    let path = seeded_db(dir.path(), Some(MISMATCH_GENESIS_SQL));
    let cid = root_cid(&path);
    let run = run_lib(&path, "text");
    assert_eq!(run.code, EXIT_FAILED, "stdout: {}", run.stdout);
    assert_text_summary(&run, false);
    assert!(
        run.stdout.contains(&format!("{CID_LINE}false ({cid})")),
        "mismatch line:\n{}",
        run.stdout
    );
    assert!(
        run.stderr.contains(STDERR_MISMATCH),
        "stderr names the class: {}",
        run.stderr
    );
    assert_no_leak(&run, &path, MISMATCH_RAW_HEX);
}

#[test]
fn mismatch_root_json_is_ok_false_exit_2_9505() {
    let dir = scratch_dir("mismatch-json");
    let path = seeded_db(dir.path(), Some(MISMATCH_GENESIS_SQL));
    let cid = root_cid(&path);
    let run = run_lib(&path, "json");
    assert_eq!(run.code, EXIT_FAILED, "stdout: {}", run.stdout);
    let v = one_json_doc(&run);
    assert_eq!(v["ok"], json!(false), "{}", run.stdout);
    assert_eq!(
        v["root_cid"],
        json!({ "state": "mismatch", "cid": cid }),
        "{}",
        run.stdout
    );
    assert!(run.stderr.contains(STDERR_MISMATCH), "{}", run.stderr);
    assert_no_leak(&run, &path, MISMATCH_RAW_HEX);
}

// ---- unreadable --------------------------------------------------------------

#[test]
fn unreadable_root_text_exits_2_naming_the_class_9505() {
    for (sql, raw) in UNREADABLE_GENESIS {
        let dir = scratch_dir("unreadable-text");
        let path = seeded_db(dir.path(), Some(sql));
        let run = run_lib(&path, "text");
        assert_eq!(run.code, EXIT_FAILED, "{sql}: stdout: {}", run.stdout);
        assert_text_summary(&run, false);
        assert!(
            run.stdout
                .contains(&format!("{CID_LINE}unreadable ({CLASS_DECODE})")),
            "{sql}: unreadable line:\n{}",
            run.stdout
        );
        assert!(
            run.stderr
                .contains(&format!("{STDERR_UNREADABLE} ({CLASS_DECODE})")),
            "{sql}: stderr names the class: {}",
            run.stderr
        );
        assert_no_leak(&run, &path, raw);
    }
}

#[test]
fn unreadable_root_json_is_ok_false_exit_2_9505() {
    for (sql, raw) in UNREADABLE_GENESIS {
        let dir = scratch_dir("unreadable-json");
        let path = seeded_db(dir.path(), Some(sql));
        let run = run_lib(&path, "json");
        assert_eq!(run.code, EXIT_FAILED, "{sql}: stdout: {}", run.stdout);
        let v = one_json_doc(&run);
        assert_eq!(v["ok"], json!(false), "{sql}: {}", run.stdout);
        assert_eq!(
            v["root_cid"],
            json!({ "state": "unreadable", "error_class": CLASS_DECODE }),
            "{sql}: {}",
            run.stdout
        );
        assert!(
            run.stderr
                .contains(&format!("{STDERR_UNREADABLE} ({CLASS_DECODE})")),
            "{sql}: {}",
            run.stderr
        );
        assert_no_leak(&run, &path, raw);
    }
}

// ---- absent ------------------------------------------------------------------

#[test]
fn absent_genesis_text_exits_0_with_no_cid_output_9505() {
    let dir = scratch_dir("absent-text");
    let path = seeded_db(dir.path(), Some("NULL"));
    let run = run_lib(&path, "text");
    assert_eq!(run.code, EXIT_OK, "stdout: {}", run.stdout);
    assert_text_summary(&run, true);
    assert!(
        !run.stdout.contains(CID_LINE),
        "no cid line: {}",
        run.stdout
    );
    assert!(run.stderr.is_empty(), "stderr: {}", run.stderr);
}

#[test]
fn absent_genesis_json_exits_0_with_field_omitted_9505() {
    let dir = scratch_dir("absent-json");
    let path = seeded_db(dir.path(), Some("NULL"));
    let run = run_lib(&path, "json");
    assert_eq!(run.code, EXIT_OK, "stdout: {}", run.stdout);
    let v = one_json_doc(&run);
    assert_eq!(v["ok"], json!(true), "{}", run.stdout);
    assert!(
        v.get("root_cid").is_none(),
        "not checked = field absent:\n{}",
        run.stdout
    );
}

#[test]
fn absent_cid_with_genesis_exits_0_with_no_cid_output_9505() {
    let dir = scratch_dir("absent-cid");
    let path = seeded_db(dir.path(), None);
    {
        let conn = db::open(&path).expect("reopen");
        conn.execute("UPDATE memories SET cid = NULL WHERE id = ?1", [ROOT_ID])
            .expect("null cid");
    }
    for format in ["text", "json"] {
        let run = run_lib(&path, format);
        assert_eq!(run.code, EXIT_OK, "{format}: stdout: {}", run.stdout);
        assert!(!run.stdout.contains(CID_LINE), "{format}: {}", run.stdout);
        assert!(!run.stdout.contains("root_cid"), "{format}: {}", run.stdout);
    }
}

// ---- the real process status (W-4) -------------------------------------------

/// The binary exits 2 for both failing states in both modes, and never
/// through `main`'s generic `Err` path (which prints `Error:` and exits 1).
#[test]
fn binary_failing_states_exit_2_not_the_generic_err_path_9505() {
    let cases = [
        ("mismatch", MISMATCH_GENESIS_SQL),
        ("unreadable", UNREADABLE_GENESIS[0].0),
    ];
    for (label, sql) in cases {
        for json_mode in [false, true] {
            let dir = scratch_dir(&format!("bin-{label}"));
            let path = seeded_db(dir.path(), Some(sql));
            let out = run_bin(dir.path(), &path, json_mode);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(
                out.status.code(),
                Some(EXIT_FAILED),
                "{label} json={json_mode}\nstdout: {stdout}\nstderr: {stderr}"
            );
            assert!(
                !stderr.contains(GENERIC_ERR_PREFIX),
                "{label} json={json_mode}: left through the generic Err path: {stderr}"
            );
            if json_mode {
                let v: Value = serde_json::from_str(stdout.trim())
                    .unwrap_or_else(|e| panic!("{label}: one JSON doc: {e}\n{stdout}"));
                assert_eq!(v["ok"], json!(false), "{label}: {stdout}");
            }
        }
    }
}

/// An unknown root still exits 1 NOT FOUND, distinct from 2.
#[test]
fn binary_unknown_root_still_exits_1_9505() {
    let dir = scratch_dir("bin-unknown");
    let path = seeded_db(dir.path(), None);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .current_dir(dir.path())
        .env("AI_MEMORY_NO_CONFIG", "1")
        .arg("--db")
        .arg(&path)
        .args(["verify-reflection-chain", "no-such-root-9505"])
        .output()
        .expect("spawn ai-memory");
    assert_eq!(out.status.code(), Some(EXIT_NOT_FOUND));
}

// ---- W-3: the forensic bundle's verification.json is unchanged ----------------

/// `verification.json` for a fixed two-memory chain with a pinned timestamp,
/// byte for byte as the chain tip writes it (captured at the Base).
const GOLDEN_VERIFICATION_JSON: &str = r#"{
  "ok": true,
  "root_id": "root-9505",
  "n_memories": 2,
  "chain_depth": 1,
  "edges_verified": 1,
  "edges_failed": 0,
  "edges": [
    {
      "source_id": "root-9505",
      "target_id": "parent-9505",
      "signature_hex": null,
      "attest_level": "unsigned",
      "verified": true
    }
  ],
  "max_reflection_depth_per_namespace": {
    "verify-chain-9505": 1
  },
  "bounded_status": "no_cap_configured",
  "generated_at": "2026-11-18T00:00:00Z"
}"#;

fn bundle_db(dir: &Path, genesis_sql: Option<&str>) -> Connection {
    let conn = db::open(&dir.join("bundle.db")).expect("open bundle db");
    db::insert(&conn, &mem(PARENT_ID, PARENT_CREATED_AT, 0)).expect("insert parent");
    db::insert(&conn, &mem(ROOT_ID, CREATED_AT, 1)).expect("insert root");
    conn.execute(
        "INSERT INTO memory_links (source_id, target_id, relation, created_at, attest_level) \
         VALUES (?1, ?2, 'reflects_on', ?3, 'unsigned')",
        [ROOT_ID, PARENT_ID, CREATED_AT],
    )
    .expect("link");
    if let Some(sql) = genesis_sql {
        set_genesis(&conn, sql);
    }
    conn
}

fn verification_json(conn: &Connection) -> String {
    let args = ExportForensicBundleArgs {
        memory_id: ROOT_ID.to_string(),
        include_reflections: true,
        include_transcripts: false,
        include_atomisation_chain: false,
        output: None,
    };
    let files = bundle::build_files(conn, &args, Some(PINNED_GENERATED_AT)).expect("build");
    let body = files.get("verification.json").expect("verification.json");
    String::from_utf8(body.clone()).expect("utf8 verification.json")
}

#[test]
fn bundle_verification_json_is_byte_identical_9505() {
    let dir = scratch_dir("bundle-golden");
    let conn = bundle_db(dir.path(), None);
    let got = verification_json(&conn);
    assert_eq!(
        got, GOLDEN_VERIFICATION_JSON,
        "verification.json drifted:\n{got}"
    );
}

/// The bundle path never runs the root content-id check: a mismatched root
/// genesis leaves `verification.json` identical to the clean build.
#[test]
fn bundle_verification_json_never_carries_root_cid_9505() {
    let dir = scratch_dir("bundle-mismatch");
    let conn = bundle_db(dir.path(), Some(MISMATCH_GENESIS_SQL));
    let got = verification_json(&conn);
    assert!(!got.contains("root_cid"), "{got}");
    assert_eq!(
        got, GOLDEN_VERIFICATION_JSON,
        "verification.json drifted:\n{got}"
    );
}

// ---- #9507: the operator doc lists the codes the verb returns ------------------

const FORENSIC_DOC: &str = "docs/forensic-export.md";
const EXIT_SECTION: &str = "### Exit codes";

#[test]
fn forensic_export_doc_lists_exit_codes_0_1_2_9507() {
    let doc = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FORENSIC_DOC))
        .expect("read forensic-export.md");
    let start = doc.find(EXIT_SECTION).expect("exit-code section");
    let rest = &doc[start + EXIT_SECTION.len()..];
    let section = &rest[..rest.find("\n### ").unwrap_or(rest.len())];
    // One row per bullet, its indented continuation lines joined on.
    let mut rows: Vec<String> = Vec::new();
    for line in section.lines() {
        if line.starts_with("- `") {
            rows.push(line.to_string());
        } else if line.starts_with("  ")
            && let Some(row) = rows.last_mut()
        {
            row.push(' ');
            row.push_str(line.trim());
        }
    }
    let codes: Vec<&str> = rows
        .iter()
        .map(|l| l[3..].split('`').next().unwrap_or_default())
        .collect();
    assert_eq!(codes, ["0", "1", "2"], "rows: {rows:#?}");
    assert!(rows[1].contains("not found"), "1 = NOT FOUND: {}", rows[1]);
    for needle in ["signature", "max_reflection_depth", "content-id", "--cid"] {
        assert!(rows[2].contains(needle), "2 names {needle}: {}", rows[2]);
    }
    assert!(
        !rows[1].contains("signature"),
        "1 is not verification failure: {}",
        rows[1]
    );
    // Ruling fe96bc17: 1 keeps its old meaning (a caller error); an input
    // that cannot be read is UNREADABLE under 2, with the class named.
    for widened in ["storage", "computed", "could not be read"] {
        assert!(
            !rows[1].contains(widened),
            "1 must not cover {widened}: {}",
            rows[1]
        );
    }
    for needle in ["could not be read", "unreadable", "error_class"] {
        assert!(rows[2].contains(needle), "2 names {needle}: {}", rows[2]);
    }
}

// ---- #9634: the `--cid` sweep decides before anything prints -------------------

/// A second memory, so a sweep can find a bad row that is not the root.
const OTHER_ID: &str = "other-9505";
const OTHER_CREATED_AT: &str = "2026-03-01T00:00:00Z";
const SWEEP_LINE: &str = "cid sweep: ";
const STDERR_SWEEP_FAILED: &str = "cid sweep failed";
/// The two output modes, by their `--format` value.
const FORMATS: [&str; 2] = ["text", "json"];

/// One root content-id state, with what `--cid` must count for it.
struct SweepCase {
    label: &'static str,
    /// `None` keeps the genesis the insert wrote (verified).
    genesis_sql: Option<&'static str>,
    code: i32,
    checked: u64,
    verified: u64,
    mismatched: u64,
    unreadable: u64,
    unverifiable: u64,
}

const SWEEP_CASES: [SweepCase; 4] = [
    SweepCase {
        label: "verified",
        genesis_sql: None,
        code: EXIT_OK,
        checked: 1,
        verified: 1,
        mismatched: 0,
        unreadable: 0,
        unverifiable: 0,
    },
    SweepCase {
        label: "mismatch",
        genesis_sql: Some(MISMATCH_GENESIS_SQL),
        code: EXIT_FAILED,
        checked: 1,
        verified: 0,
        mismatched: 1,
        unreadable: 0,
        unverifiable: 0,
    },
    SweepCase {
        label: "unreadable",
        genesis_sql: Some(UNREADABLE_GENESIS[0].0),
        code: EXIT_FAILED,
        checked: 0,
        verified: 0,
        mismatched: 0,
        unreadable: 1,
        unverifiable: 0,
    },
    SweepCase {
        label: "absent",
        genesis_sql: Some("NULL"),
        code: EXIT_OK,
        checked: 0,
        verified: 0,
        mismatched: 0,
        unreadable: 0,
        unverifiable: 1,
    },
];

fn set_genesis_of(conn: &Connection, id: &str, value_sql: &str) {
    conn.execute(
        &format!("UPDATE memories SET cid_genesis = {value_sql} WHERE id = ?1"),
        [id],
    )
    .expect("set genesis");
}

/// A good root plus a second row whose genesis is `other_genesis_sql`.
fn seeded_db_with_other(dir: &Path, other_genesis_sql: &str) -> PathBuf {
    let path = seeded_db(dir, None);
    let conn = db::open(&path).expect("reopen scratch db");
    db::insert(&conn, &mem(OTHER_ID, OTHER_CREATED_AT, 0)).expect("insert other");
    set_genesis_of(&conn, OTHER_ID, other_genesis_sql);
    path
}

/// The text sweep line the verb prints for these counts.
fn sweep_line(case: &SweepCase) -> String {
    format!(
        "{SWEEP_LINE}checked={} verified={} mismatched={} unreadable={} unverifiable={}",
        case.checked, case.verified, case.mismatched, case.unreadable, case.unverifiable
    )
}

/// The JSON `cid_sweep` object carries exactly these counts.
fn assert_sweep_counts(v: &Value, case: &SweepCase) {
    let s = &v["cid_sweep"];
    for (field, want) in [
        ("checked", case.checked),
        ("cid_verified", case.verified),
        ("cid_mismatched", case.mismatched),
        ("cid_unreadable", case.unreadable),
        ("cid_unverifiable", case.unverifiable),
    ] {
        assert_eq!(
            s[field],
            json!(want),
            "{}: cid_sweep.{field}: {v}",
            case.label
        );
    }
}

/// Mode x state x with and without `--cid`, library entry point. Without
/// `--cid` there is no sweep output; with it the sweep is ONE part of the one
/// report: one summary line in text, one JSON document with `cid_sweep`.
#[test]
fn cid_sweep_state_matrix_both_modes_9634() {
    for case in &SWEEP_CASES {
        for format in FORMATS {
            for cid in [false, true] {
                let ctx = format!("{} {format} cid={cid}", case.label);
                let dir = scratch_dir(&format!("sweep-{}-{format}", case.label));
                let path = seeded_db(dir.path(), case.genesis_sql);
                let run = run_lib_with(&path, format, cid);
                assert_eq!(run.code, case.code, "{ctx}\nstdout: {}", run.stdout);
                assert_no_leak(&run, &path, MISMATCH_RAW_HEX);
                assert_no_leak(&run, &path, UNREADABLE_GENESIS[0].1);
                let ok = case.code == EXIT_OK;
                if format == "text" {
                    assert_text_summary(&run, ok);
                    let lines: Vec<&str> = run
                        .stdout
                        .lines()
                        .filter(|l| l.starts_with(SWEEP_LINE))
                        .collect();
                    if cid {
                        assert_eq!(lines, [sweep_line(case)], "{ctx}:\n{}", run.stdout);
                    } else {
                        assert!(lines.is_empty(), "{ctx}: no sweep:\n{}", run.stdout);
                    }
                } else {
                    let v = one_json_doc(&run);
                    assert_eq!(v["ok"], json!(ok), "{ctx}: {v}");
                    if cid {
                        assert_sweep_counts(&v, case);
                    } else {
                        assert!(v.get("cid_sweep").is_none(), "{ctx}: no sweep: {v}");
                    }
                }
                let sweep_failed = cid && !ok;
                assert_eq!(
                    run.stderr.contains(STDERR_SWEEP_FAILED),
                    sweep_failed,
                    "{ctx}: stderr: {}",
                    run.stderr
                );
            }
        }
    }
}

/// The sweep names each failing row: the mismatch detail and the unreadable
/// row with its class, in both modes.
#[test]
fn cid_sweep_names_the_failing_root_row_and_class_9634() {
    for format in FORMATS {
        let dir = scratch_dir(&format!("sweep-detail-mismatch-{format}"));
        let path = seeded_db(dir.path(), Some(MISMATCH_GENESIS_SQL));
        let run = run_lib_with(&path, format, true);
        assert_eq!(run.code, EXIT_FAILED, "{format}: {}", run.stdout);
        if format == "text" {
            assert!(
                run.stdout
                    .contains(&format!("  MISMATCH {ROOT_ID}: cid mismatch: stored ")),
                "{}",
                run.stdout
            );
        } else {
            let v = one_json_doc(&run);
            let detail = v["cid_sweep"]["mismatches"][0].as_str().unwrap_or_default();
            assert!(detail.starts_with(&format!("{ROOT_ID}: ")), "{v}");
        }

        let dir = scratch_dir(&format!("sweep-detail-unreadable-{format}"));
        let path = seeded_db(dir.path(), Some(UNREADABLE_GENESIS[0].0));
        let run = run_lib_with(&path, format, true);
        assert_eq!(run.code, EXIT_FAILED, "{format}: {}", run.stdout);
        if format == "text" {
            assert!(
                run.stdout
                    .contains(&format!("  UNREADABLE {ROOT_ID} ({CLASS_DECODE})")),
                "{}",
                run.stdout
            );
        } else {
            let v = one_json_doc(&run);
            assert_eq!(
                v["cid_sweep"]["unreadable"],
                json!([{ "id": ROOT_ID, "error_class": CLASS_DECODE }]),
                "{v}"
            );
        }
    }
}

/// A good root and ONE other row whose genesis does not decode: `--cid`
/// fails the verification (exit 2, never `Err`), names the row and the class,
/// and no `ok=true` line is anywhere on stdout. Every undecodable form.
#[test]
fn cid_sweep_unreadable_non_root_row_fails_both_modes_9634() {
    for (sql, marker) in UNREADABLE_GENESIS {
        for format in FORMATS {
            let ctx = format!("{sql} {format}");
            let dir = scratch_dir(&format!("sweep-other-unreadable-{format}"));
            let path = seeded_db_with_other(dir.path(), sql);
            let run = run_lib_with(&path, format, true);
            assert_eq!(run.code, EXIT_FAILED, "{ctx}\nstdout: {}", run.stdout);
            assert_no_leak(&run, &path, marker);
            assert!(
                run.stderr.contains(STDERR_SWEEP_FAILED),
                "{ctx}: {}",
                run.stderr
            );
            if format == "text" {
                assert_text_summary(&run, false);
                assert!(
                    run.stdout
                        .contains(&format!("  UNREADABLE {OTHER_ID} ({CLASS_DECODE})")),
                    "{ctx}:\n{}",
                    run.stdout
                );
            } else {
                let v = one_json_doc(&run);
                assert_eq!(v["ok"], json!(false), "{ctx}: {v}");
                assert_eq!(v["root_cid"]["state"], json!("verified"), "{ctx}: {v}");
                assert_eq!(v["cid_sweep"]["cid_verified"], json!(1), "{ctx}: {v}");
                assert_eq!(v["cid_sweep"]["cid_unreadable"], json!(1), "{ctx}: {v}");
                assert_eq!(
                    v["cid_sweep"]["unreadable"],
                    json!([{ "id": OTHER_ID, "error_class": CLASS_DECODE }]),
                    "{ctx}: {v}"
                );
            }
        }
    }
}

/// A good root and ONE other row with a mismatched genesis: `--cid` fails.
#[test]
fn cid_sweep_mismatch_non_root_row_fails_both_modes_9634() {
    for format in FORMATS {
        let dir = scratch_dir(&format!("sweep-other-mismatch-{format}"));
        let path = seeded_db_with_other(dir.path(), MISMATCH_GENESIS_SQL);
        let run = run_lib_with(&path, format, true);
        assert_eq!(run.code, EXIT_FAILED, "{format}\nstdout: {}", run.stdout);
        assert_no_leak(&run, &path, MISMATCH_RAW_HEX);
        assert!(run.stderr.contains(STDERR_SWEEP_FAILED), "{}", run.stderr);
        if format == "text" {
            assert_text_summary(&run, false);
            assert!(
                run.stdout.contains(&format!("  MISMATCH {OTHER_ID}: ")),
                "{}",
                run.stdout
            );
        } else {
            let v = one_json_doc(&run);
            assert_eq!(v["ok"], json!(false), "{v}");
            assert_eq!(v["cid_sweep"]["cid_mismatched"], json!(1), "{v}");
        }
    }
}

/// Without `--cid` a bad non-root row is not looked at: the root verdict alone.
#[test]
fn no_cid_flag_leaves_non_root_rows_unchecked_9634() {
    for format in FORMATS {
        let dir = scratch_dir(&format!("no-sweep-other-{format}"));
        let path = seeded_db_with_other(dir.path(), UNREADABLE_GENESIS[0].0);
        let run = run_lib_with(&path, format, false);
        assert_eq!(run.code, EXIT_OK, "{format}\nstdout: {}", run.stdout);
    }
}

/// The built binary, `--cid`, every state plus both bad non-root rows, both
/// modes: the exact exit code, never `main`'s generic `Err` path, one JSON
/// document, and no passing summary line when the verdict fails.
#[test]
fn binary_cid_sweep_cells_exit_codes_9634() {
    enum Fixture {
        Root(Option<&'static str>),
        Other(&'static str),
    }
    let mut cases: Vec<(&str, Fixture, i32)> = SWEEP_CASES
        .iter()
        .map(|c| (c.label, Fixture::Root(c.genesis_sql), c.code))
        .collect();
    cases.push((
        "other-unreadable",
        Fixture::Other(UNREADABLE_GENESIS[0].0),
        EXIT_FAILED,
    ));
    cases.push((
        "other-mismatch",
        Fixture::Other(MISMATCH_GENESIS_SQL),
        EXIT_FAILED,
    ));
    for (label, fixture, code) in &cases {
        for json_mode in [false, true] {
            let ctx = format!("{label} json={json_mode}");
            let dir = scratch_dir(&format!("bin-sweep-{label}"));
            let path = match fixture {
                Fixture::Root(sql) => seeded_db(dir.path(), *sql),
                Fixture::Other(sql) => seeded_db_with_other(dir.path(), sql),
            };
            let out = run_bin_with(dir.path(), &path, json_mode, true);
            let run = Run {
                code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            };
            assert_eq!(
                run.code, *code,
                "{ctx}\nstdout: {}\nstderr: {}",
                run.stdout, run.stderr
            );
            assert!(
                !run.stderr.contains(GENERIC_ERR_PREFIX),
                "{ctx}: left through the generic Err path: {}",
                run.stderr
            );
            let ok = *code == EXIT_OK;
            if json_mode {
                let v = one_json_doc(&run);
                assert_eq!(v["ok"], json!(ok), "{ctx}: {v}");
                assert!(v["cid_sweep"].is_object(), "{ctx}: {v}");
            } else {
                assert_text_summary(&run, ok);
            }
        }
    }
}

// ---- #9636: no stored value reaches a text line unescaped or unbounded ----------

/// A forged passing summary line an attacker would smuggle in a stored cid.
const FORGED_SUMMARY: &str =
    "verify-reflection-chain: root=forged memories=1 depth=0 edges=0 failed=0 ok=true";
/// Characters that reorder or hide text on a terminal (bidi controls, zero
/// width and line separators); none may reach a stream unescaped.
const HIDDEN_CHARS: &[char] = &[
    '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{2028}', '\u{2029}', '\u{202a}',
    '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    '\u{feff}',
];
/// Length of the oversized stored cid (above the 100K floor for scanners).
const LARGE_CID_CHARS: usize = 120_000;
/// Longest line either stream may print: the verb's per-field bound (512
/// printed chars) plus each line's fixed text, far below the stored value.
const MAX_LINE_CHARS: usize = 2_048;
/// Wall-clock ceiling for one verification of the oversized value.
const LARGE_INPUT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

/// Stored cids that try to forge lines or drive the terminal.
fn hostile_cids() -> Vec<String> {
    vec![
        format!("bafy-newline\n{FORGED_SUMMARY}"),
        format!("bafy-cr\r{FORGED_SUMMARY}"),
        format!("bafy-esc\u{1b}[2J\u{1b}[1;1H{FORGED_SUMMARY}"),
        format!("bafy-csi\u{9b}2J{FORGED_SUMMARY}"),
        "bafy-bidi\u{202e}eurt=ko\u{2066}x\u{feff}".to_string(),
        format!("bafy-nul\0{FORGED_SUMMARY}"),
    ]
}

fn set_root_cid(path: &Path, cid: &str) {
    let conn = db::open(path).expect("reopen scratch db");
    conn.execute(
        "UPDATE memories SET cid = ?1 WHERE id = ?2",
        rusqlite::params![cid, ROOT_ID],
    )
    .expect("set cid");
}

/// No control character but the line feed, and no hidden character, on
/// either stream.
fn assert_clean_streams(run: &Run, ctx: &str) {
    for (name, stream) in [("stdout", &run.stdout), ("stderr", &run.stderr)] {
        for c in stream.chars() {
            assert!(
                c == '\n' || (!c.is_control() && !HIDDEN_CHARS.contains(&c)),
                "{ctx}: {name} prints U+{:04X} unescaped:\n{stream:?}",
                u32::from(c)
            );
        }
    }
}

/// Exactly ONE line starts the summary, and it carries the final verdict.
fn assert_one_summary_line(run: &Run, ok: bool, ctx: &str) {
    let summaries: Vec<&str> = run
        .stdout
        .lines()
        .filter(|l| l.starts_with(SUMMARY_PREFIX))
        .collect();
    assert_eq!(
        summaries.len(),
        1,
        "{ctx}: one summary line:\n{}",
        run.stdout
    );
    assert!(
        summaries[0].ends_with(&format!(" ok={ok}")),
        "{ctx}: {}",
        run.stdout
    );
}

/// A hostile stored cid, with and without `--cid`: one summary line ending
/// `ok=false`, no control or hidden character on either stream, and the cid
/// shown in its escaped form.
#[test]
fn hostile_root_cid_text_is_escaped_with_one_summary_line_9636() {
    for cid_value in hostile_cids() {
        for sweep in [false, true] {
            let ctx = format!("{cid_value:?} cid={sweep}");
            let dir = scratch_dir("hostile-text");
            let path = seeded_db(dir.path(), None);
            set_root_cid(&path, &cid_value);
            let run = run_lib_with(&path, "text", sweep);
            assert_eq!(run.code, EXIT_FAILED, "{ctx}\nstdout: {}", run.stdout);
            assert_one_summary_line(&run, false, &ctx);
            assert_clean_streams(&run, &ctx);
            assert!(
                run.stdout.contains(&format!("{CID_LINE}false (bafy-")),
                "{ctx}:\n{}",
                run.stdout
            );
            assert!(
                run.stderr.contains(STDERR_MISMATCH),
                "{ctx}: {}",
                run.stderr
            );
        }
    }
}

/// JSON mode carries the full value, escaped by the JSON encoder, in ONE
/// document; stderr is escaped like text mode.
#[test]
fn hostile_root_cid_json_is_one_document_with_clean_stderr_9636() {
    for cid_value in hostile_cids() {
        for sweep in [false, true] {
            let ctx = format!("{cid_value:?} cid={sweep}");
            let dir = scratch_dir("hostile-json");
            let path = seeded_db(dir.path(), None);
            set_root_cid(&path, &cid_value);
            let run = run_lib_with(&path, "json", sweep);
            assert_eq!(run.code, EXIT_FAILED, "{ctx}\nstdout: {}", run.stdout);
            let v = one_json_doc(&run);
            assert_eq!(v["ok"], json!(false), "{ctx}: {v}");
            assert_eq!(v["root_cid"]["cid"], json!(cid_value), "{ctx}: {v}");
            assert_clean_streams(&run, &ctx);
        }
    }
}

/// A 120K stored cid that also carries a forged line: every printed line on
/// both streams stays under the named bound, and the run is fast.
#[test]
fn oversized_root_cid_is_bounded_on_every_line_9636() {
    let cid_value = format!("bafy{}\n{FORGED_SUMMARY}", "x".repeat(LARGE_CID_CHARS));
    for format in FORMATS {
        for sweep in [false, true] {
            let ctx = format!("{format} cid={sweep}");
            let dir = scratch_dir("oversized");
            let path = seeded_db(dir.path(), None);
            set_root_cid(&path, &cid_value);
            let started = std::time::Instant::now();
            let run = run_lib_with(&path, format, sweep);
            let took = started.elapsed();
            assert!(took < LARGE_INPUT_DEADLINE, "{ctx}: took {took:?}");
            assert_eq!(run.code, EXIT_FAILED, "{ctx}");
            assert_clean_streams(&run, &ctx);
            let streams: Vec<(&str, &String)> = if format == "text" {
                vec![("stdout", &run.stdout), ("stderr", &run.stderr)]
            } else {
                vec![("stderr", &run.stderr)]
            };
            for (name, stream) in streams {
                for line in stream.lines() {
                    let n = line.chars().count();
                    assert!(n <= MAX_LINE_CHARS, "{ctx}: {name} line of {n} chars");
                }
            }
            if format == "text" {
                assert_one_summary_line(&run, false, &ctx);
            }
        }
    }
}
