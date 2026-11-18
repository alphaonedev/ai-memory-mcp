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
    let args = VerifyChainArgs {
        memory_id: ROOT_ID.to_string(),
        format: format.to_string(),
        include_signed_events: false,
        cid: false,
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
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.current_dir(dir)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .arg("--db")
        .arg(path)
        .args(["verify-reflection-chain", ROOT_ID]);
    if json_mode {
        cmd.args(["--format", "json"]);
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
    for needle in ["signature", "max_reflection_depth", "content-id"] {
        assert!(rows[2].contains(needle), "2 names {needle}: {}", rows[2]);
    }
    assert!(
        !rows[1].contains("signature"),
        "1 is not verification failure: {}",
        rows[1]
    );
}
