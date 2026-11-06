// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 QW-1 — integration tests for `ai-memory export-reflections`
//! and the companion MCP tool + post_reflect substrate hook.
//!
//! Cargo autodiscovers `tests/cli.rs` as a single test binary; the
//! `#[path]` includes mount these submodules from this directory
//! the same way `tests/forensic.rs` mounts `forensic/bundle_test.rs`.

#![allow(clippy::doc_markdown)]

use ai_memory::cli::CliOutput;
use ai_memory::cli::commands::export_reflections::{self, ExportReflectionsArgs};
use ai_memory::db;
use ai_memory::models::{
    ApproverType, CorePolicy, ExportPolicy, GovernanceLevel, GovernancePolicy, Memory, MemoryKind,
    Tier,
};
use chrono::Utc;
use serde_json::json;
use std::path::Path;
use tempfile::TempDir;

// ─────────────────────────────────────────────────────────────────────
// Fixture helpers — local copies so the tests stay self-contained.
// ─────────────────────────────────────────────────────────────────────

fn open(p: &Path) -> rusqlite::Connection {
    db::open(p).expect("db::open")
}

fn seed_observation(conn: &rusqlite::Connection, ns: &str, title: &str) -> String {
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("body for {title}"),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": "ai:test"}),
        ..Default::default()
    };
    db::insert(conn, &mem).expect("insert")
}

fn drive_reflect(
    conn: &rusqlite::Connection,
    db_path: &Path,
    ns: &str,
    src: &str,
    title: &str,
) -> String {
    let input = db::ReflectInput {
        source_ids: vec![src.to_string()],
        title: title.to_string(),
        content: format!("reflection body for {title}"),
        namespace: Some(ns.to_string()),
        tier: Tier::Mid,
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "cli".into(),
        agent_id: "ai:test".into(),
        metadata: json!({}),
    };
    let _ = db_path;
    let outcome = db::reflect(conn, &input).expect("reflect");
    outcome.id
}

fn make_args(out_dir: &Path) -> ExportReflectionsArgs {
    ExportReflectionsArgs {
        namespace: None,
        out_dir: Some(out_dir.to_path_buf()),
        format: "md".into(),
        since: None,
        quiet: true,
    }
}

fn run_cli(db_path: &Path, args: &ExportReflectionsArgs) -> i32 {
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let mut out = CliOutput {
        stdout: &mut stdout,
        stderr: &mut stderr,
    };
    export_reflections::run(db_path, args, &mut out).expect("run")
}

#[derive(Clone, Copy)]
enum NamespaceExportWriter {
    Cli,
    Automatic,
}

fn assert_stored_namespace_refused(namespace: &str, writer: NamespaceExportWriter) {
    use ai_memory::hooks::post_reflect::auto_export::{AutoExportConfig, run_auto_export};

    const VALID_NAMESPACE: &str = "export-path-regression";
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);
    enable_auto_export(&conn, VALID_NAMESPACE);
    let source_id = seed_observation(&conn, VALID_NAMESPACE, "source");
    let reflection_id = drive_reflect(
        &conn,
        &db_path,
        VALID_NAMESPACE,
        &source_id,
        "path regression",
    );
    // Bypass ingestion validation only in the fixture: export must defend
    // against dot-only namespace components already present in durable input.
    conn.execute(
        "UPDATE memories SET namespace = ?1 WHERE id = ?2",
        rusqlite::params![namespace, reflection_id],
    )
    .unwrap();
    let root = tmp.path().join("fixture-root");
    let out_dir = root.join("exports");
    let result = match writer {
        NamespaceExportWriter::Cli => {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut output = CliOutput {
                stdout: &mut stdout,
                stderr: &mut stderr,
            };
            export_reflections::run(&db_path, &make_args(&out_dir), &mut output).map(|_| ())
        }
        NamespaceExportWriter::Automatic => run_auto_export(
            &db_path,
            &reflection_id,
            VALID_NAMESPACE,
            &AutoExportConfig {
                out_dir: out_dir.clone(),
                format: export_reflections::ExportFormat::Markdown,
            },
        ),
    };
    assert!(
        !root.join("escaped").exists(),
        "export must not create a path outside its output directory"
    );
    let error = result.expect_err("dot-only namespace component must be refused");
    assert_eq!(
        error.root_cause().to_string(),
        "namespace path cannot contain dot-only components"
    );
    if matches!(writer, NamespaceExportWriter::Cli) {
        assert_eq!(
            error.to_string(),
            format!("memory {reflection_id:?} namespace {namespace:?}: refusing export path")
        );
    }
    if out_dir.exists() {
        assert!(
            std::fs::read_dir(&out_dir).unwrap().next().is_none(),
            "refused namespace must not create an export subtree"
        );
    }
}

#[test]
fn cli_namespace_refusal_escapes_stored_id_8605() {
    const STORED_ID: &str = "stored\nid\t";
    const REFUSED_NAMESPACE: &str = "..";
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);
    let original_id = seed_observation(&conn, "export-id-diagnostic", "source");
    // Durable rows can bypass ingestion checks; exercise the actual CLI
    // error boundary with a stored control character, without linked rows.
    conn.execute(
        "UPDATE memories SET id = ?1, namespace = ?2, memory_kind = 'reflection' WHERE id = ?3",
        rusqlite::params![STORED_ID, REFUSED_NAMESPACE, original_id],
    )
    .unwrap();
    db::checkpoint(&conn).expect("checkpoint before subprocess read");
    drop(conn);

    let out_dir = tmp.path().join("exports");
    let assert = assert_cmd::Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .arg("--db")
        .arg(&db_path)
        .arg("export-reflections")
        .arg("--out-dir")
        .arg(&out_dir)
        .arg("--quiet")
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains(&format!(
            "memory {STORED_ID:?} namespace {REFUSED_NAMESPACE:?}: refusing export id"
        )),
        "CLI refusal must identify the row with escaped stored values: {stderr:?}"
    );
    assert!(
        !stderr.contains(STORED_ID),
        "CLI stderr must not include the raw stored control characters"
    );
    assert!(
        !out_dir.exists(),
        "invalid ID must leave the destination absent"
    );
}

#[test]
fn cli_namespace_refusal_bounds_stored_values_8605() {
    const OVERSIZED_CHARS: usize = 1024 * 1024;
    const STDERR_MAX_BYTES: usize = 4096;
    let cases = [
        ("\u{1}".repeat(OVERSIZED_CHARS), "..".to_string()),
        (
            "short-id".to_string(),
            format!("{}/..", "é".repeat(OVERSIZED_CHARS)),
        ),
    ];
    for (stored_id, namespace) in cases {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("ai-memory.db");
        let conn = open(&db_path);
        let original_id = seed_observation(&conn, "bounded-export-diagnostic", "source");
        conn.execute(
            "UPDATE memories SET id = ?1, namespace = ?2, memory_kind = 'reflection' WHERE id = ?3",
            rusqlite::params![stored_id, namespace, original_id],
        )
        .unwrap();
        db::checkpoint(&conn).expect("checkpoint before subprocess read");
        drop(conn);
        let output = assert_cmd::Command::cargo_bin("ai-memory")
            .unwrap()
            .env("AI_MEMORY_NO_CONFIG", "1")
            .arg("--db")
            .arg(&db_path)
            .arg("export-reflections")
            .arg("--out-dir")
            .arg(tmp.path().join("exports"))
            .arg("--quiet")
            .assert()
            .failure();
        let stderr = std::str::from_utf8(&output.get_output().stderr).unwrap();
        assert!(
            stderr.len() <= STDERR_MAX_BYTES,
            "refusal stderr must be bounded, got {} bytes",
            stderr.len()
        );
        let original_bytes = stored_id.len().max(namespace.len());
        assert!(stderr.contains(&format!("[truncated; original_bytes={original_bytes}]")));
        if ai_memory::validate::validate_id(&stored_id).is_err() {
            assert!(stderr.contains("refusing export id"));
            assert!(!tmp.path().join("exports").exists());
        } else {
            assert!(stderr.contains("refusing export path"));
        }
        assert!(!stderr.contains('\u{1}'));
    }
}

fn export_output_with_stored_id_8605(stored_id: &str) -> std::process::Output {
    const NAMESPACE: &str = "export-output-diagnostic";
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);
    let original_id = seed_observation(&conn, NAMESPACE, "source");
    conn.execute(
        "UPDATE memories SET id = ?1, memory_kind = 'reflection' WHERE id = ?2",
        rusqlite::params![stored_id, original_id],
    )
    .unwrap();
    db::checkpoint(&conn).expect("checkpoint before subprocess read");
    drop(conn);
    let out_dir = tmp.path().join("exports");
    let output = assert_cmd::Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .arg("--db")
        .arg(&db_path)
        .arg("export-reflections")
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run export CLI");
    if output.status.success() {
        assert!(
            out_dir
                .join(NAMESPACE)
                .join(format!("{stored_id}.md"))
                .is_file()
        );
    } else {
        assert!(
            !out_dir.exists(),
            "invalid ID must leave the destination absent"
        );
    }
    output
}

#[test]
fn cli_export_write_failure_escapes_stored_id_8605() {
    const STORED_ID: &str = "missing/\u{1b}[2Jid\r";
    let output = export_output_with_stored_id_8605(STORED_ID);
    assert!(!output.status.success());
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(stderr.contains("refusing export id"));
    assert!(stderr.contains(&format!("{STORED_ID:?}")));
    assert!(!stderr.contains('\u{1b}') && !stderr.contains('\r'));
}

#[test]
fn cli_export_wrote_escapes_stored_id_8605() {
    const STORED_ID: &str = "\u{1b}[2Jid\r";
    let output = export_output_with_stored_id_8605(STORED_ID);
    assert!(!output.status.success());
    assert_eq!(output.stdout.as_slice(), b"");
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(stderr.contains("refusing export id"));
    assert!(stderr.contains(&format!("{STORED_ID:?}")));
    assert!(!stderr.contains('\u{1b}') && !stderr.contains('\r'));
}

#[test]
fn cli_export_write_failure_bounds_stored_id_8605() {
    const OVERSIZED_WRITE_ID_CHARS: usize = 1024 * 1024;
    const MAX_WRITE_ERROR_BYTES: usize = 4096;
    let stored_id = format!("\u{1b}\r{}", "x".repeat(OVERSIZED_WRITE_ID_CHARS));
    let output = export_output_with_stored_id_8605(&stored_id);
    assert!(!output.status.success());
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(
        stderr.len() <= MAX_WRITE_ERROR_BYTES,
        "write-failure stderr must be bounded, got {} bytes",
        stderr.len()
    );
    assert!(stderr.contains(&format!("[truncated; original_bytes={}]", stored_id.len())));
    assert!(stderr.contains("refusing export id"));
    assert!(stderr.contains("\\u{1b}\\r"));
    assert!(!stderr.contains('\u{1b}') && !stderr.contains('\r'));
}

#[derive(Clone, Copy)]
enum PlainExportDestination {
    Absent,
    Directory,
}

fn plain_export_output_8605(
    destination: PlainExportDestination,
) -> (TempDir, std::path::PathBuf, std::process::Output) {
    const NAMESPACE: &str = "plain-export-output";
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);
    let id = seed_observation(&conn, NAMESPACE, "source");
    conn.execute(
        "UPDATE memories SET memory_kind = 'reflection' WHERE id = ?1",
        [&id],
    )
    .unwrap();
    db::checkpoint(&conn).unwrap();
    drop(conn);
    let out_dir = tmp.path().join("exports");
    let path = out_dir.join(NAMESPACE).join(format!("{id}.md"));
    if matches!(destination, PlainExportDestination::Directory) {
        std::fs::create_dir_all(&path).unwrap();
    }
    let output = assert_cmd::Command::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .arg("--db")
        .arg(&db_path)
        .arg("export-reflections")
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .unwrap();
    (tmp, path, output)
}

#[test]
fn cli_export_wrote_plain_path_8605_r5() {
    let (_tmp, expected, output) = plain_export_output_8605(PlainExportDestination::Absent);
    assert!(output.status.success());
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    let printed = stdout
        .lines()
        .find_map(|line| line.strip_prefix("wrote "))
        .unwrap();
    assert_eq!(Path::new(printed), expected);
    assert!(std::fs::metadata(printed).unwrap().is_file());
}

#[test]
fn cli_export_write_failure_plain_path_8605_r5() {
    let (_tmp, expected, output) = plain_export_output_8605(PlainExportDestination::Directory);
    assert!(!output.status.success());
    let stderr = std::str::from_utf8(&output.stderr).unwrap();
    assert!(
        stderr.contains(&format!("writing {}", expected.display())),
        "{stderr:?}"
    );
}

fn markdown_with_edge_values_8605(
    title: &str,
    target_id: &str,
    attest_level: &str,
    created_at: &str,
) -> String {
    const NAMESPACE: &str = "yaml-export";
    const TIMESTAMP: &str = "2026-01-01T00:00:00Z";
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);
    let id = seed_observation(&conn, NAMESPACE, "source");
    // This fixture models durable fields that bypassed ingestion validation.
    conn.execute_batch("PRAGMA foreign_keys = OFF").unwrap();
    conn.execute(
        "UPDATE memories SET id = 'plain-id', memory_kind = 'reflection', title = ?1, \
         created_at = ?2 WHERE id = ?3",
        rusqlite::params![title, TIMESTAMP, id],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO memory_links (source_id, target_id, relation, created_at, attest_level) \
         VALUES ('plain-id', ?1, 'reflects_on', ?2, ?3)",
        rusqlite::params![target_id, created_at, attest_level],
    )
    .unwrap();
    db::checkpoint(&conn).unwrap();
    drop(conn);
    let out_dir = tmp.path().join("exports");
    assert_eq!(run_cli(&db_path, &make_args(&out_dir)), 0);
    std::fs::read_to_string(out_dir.join(NAMESPACE).join("plain-id.md")).unwrap()
}

#[test]
fn cli_export_yaml_stored_scalars_8605_r5() {
    let controls: String = ('\0'..='\u{1f}').chain('\u{7f}'..='\u{9f}').collect();
    let payload = format!(
        "value\n    attest_level: signed\n    forged_key: added\"\\{controls}\u{2028}\u{2029}"
    );
    let document = markdown_with_edge_values_8605(&payload, &payload, "unsigned", &payload);
    let header = document
        .strip_prefix("---\n")
        .unwrap()
        .split_once("\n---\n")
        .unwrap()
        .0;
    let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(header).unwrap();
    let keys: std::collections::BTreeSet<_> = parsed
        .as_mapping()
        .unwrap()
        .keys()
        .map(|key| key.as_str().unwrap())
        .collect();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([
            "memory_id",
            "namespace",
            "title",
            "reflection_depth",
            "attest_level",
            "created_at",
            "agent_id",
            "reflects_on",
        ])
    );
    assert_eq!(parsed["title"].as_str(), Some(payload.as_str()));
    let edge = &parsed["reflects_on"][0];
    let edge_keys: std::collections::BTreeSet<_> = edge
        .as_mapping()
        .unwrap()
        .keys()
        .map(|key| key.as_str().unwrap())
        .collect();
    assert_eq!(
        edge_keys,
        std::collections::BTreeSet::from(["target_id", "attest_level", "created_at",])
    );
    assert_eq!(edge["attest_level"].as_str(), Some("unsigned"));
    for key in ["target_id", "created_at"] {
        assert_eq!(edge[key].as_str(), Some(payload.as_str()), "field {key}");
    }
    assert!(!header.chars().any(|c| c.is_control() && c != '\n'));
}

#[test]
fn cli_export_yaml_plain_bytes_8605_r5() {
    let document = markdown_with_edge_values_8605(
        "plain title",
        "source-id",
        "unsigned",
        "2026-01-01T00:00:00Z",
    );
    assert_eq!(
        document,
        concat!(
            "---\nmemory_id: plain-id\nnamespace: yaml-export\ntitle: plain title\n",
            "reflection_depth: 0\nattest_level: unsigned\ncreated_at: 2026-01-01T00:00:00Z\n",
            "agent_id: \"ai:test\"\nreflects_on:\n  - target_id: source-id\n",
            "    attest_level: unsigned\n    created_at: 2026-01-01T00:00:00Z\n",
            "---\n\nbody for source\n",
        )
    );
}

#[test]
fn cli_export_yaml_format_characters_8605_r6() {
    // Unicode 18 DerivedGeneralCategory.txt: one row per Cf range, including
    // supplementary-plane format controls requiring YAML's eight-digit escape.
    let classes = [
        ('\u{ad}', '\u{ad}'),
        ('\u{600}', '\u{605}'),
        ('\u{61c}', '\u{61c}'),
        ('\u{6dd}', '\u{6dd}'),
        ('\u{70f}', '\u{70f}'),
        ('\u{890}', '\u{891}'),
        ('\u{8e2}', '\u{8e2}'),
        ('\u{180e}', '\u{180e}'),
        ('\u{200b}', '\u{200f}'),
        ('\u{202a}', '\u{202e}'),
        ('\u{2060}', '\u{2064}'),
        ('\u{2066}', '\u{206f}'),
        ('\u{feff}', '\u{feff}'),
        ('\u{fff9}', '\u{fffb}'),
        ('\u{110bd}', '\u{110bd}'),
        ('\u{110cd}', '\u{110cd}'),
        ('\u{13430}', '\u{1343f}'),
        ('\u{1bca0}', '\u{1bca3}'),
        ('\u{1d173}', '\u{1d17a}'),
        ('\u{e0001}', '\u{e0001}'),
        ('\u{e0020}', '\u{e007f}'),
    ];
    let mut raw_classes = Vec::new();
    for (first, last) in classes {
        let controls: String = (first..=last).collect();
        let value = format!("before{controls}after");
        let document = markdown_with_edge_values_8605(&value, &value, "unsigned", &value);
        let header = document
            .strip_prefix("---\n")
            .unwrap()
            .split_once("\n---\n")
            .unwrap()
            .0;
        let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(header).unwrap();
        assert_eq!(parsed["title"].as_str(), Some(value.as_str()));
        for key in ["target_id", "created_at"] {
            assert_eq!(parsed["reflects_on"][0][key].as_str(), Some(value.as_str()));
        }
        if (first..=last).any(|c| header.contains(c)) {
            raw_classes.push(format!(
                "U+{:04X}..U+{:04X}",
                u32::from(first),
                u32::from(last)
            ));
        }
    }
    assert!(
        raw_classes.is_empty(),
        "raw format classes: {raw_classes:?}"
    );
}

#[test]
fn cli_export_yaml_string_types_8605_r6() {
    let values = [
        "",
        "~",
        "null",
        "NULL",
        "NuLl",
        "true",
        "FALSE",
        "TrUe",
        "yes",
        "NO",
        "oN",
        "Off",
        "2026",
        "0",
        "01",
        "184467440737095516160",
        "1.0",
        ".5",
        "5.",
        "0x1f",
        "0o17",
        "1e3",
        "1E-3",
        ".inf",
        ".INF",
        ".nan",
        ".NaN",
        "+1",
        "-1",
        "+word",
        "-word",
    ];
    let mut unquoted = Vec::new();
    for value in values {
        let document = markdown_with_edge_values_8605(value, value, "unsigned", value);
        let header = document
            .strip_prefix("---\n")
            .unwrap()
            .split_once("\n---\n")
            .unwrap()
            .0;
        let Ok(parsed) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(header) else {
            unquoted.push(value);
            continue;
        };
        // Check explicit quoting too: YAML 1.1 readers resolve legacy booleans.
        if !header.lines().any(|line| line.starts_with("title: \""))
            || parsed["title"].as_str() != Some(value)
            || parsed["reflects_on"][0]["target_id"].as_str() != Some(value)
            || parsed["reflects_on"][0]["created_at"].as_str() != Some(value)
        {
            unquoted.push(value);
        }
        assert_eq!(parsed["reflection_depth"].as_i64(), Some(0));
    }
    assert!(
        unquoted.is_empty(),
        "stored strings lost quoting/type: {unquoted:?}"
    );
}

#[test]
fn cli_export_yaml_binary_string_8605_r7() {
    const BINARY_SHAPED_STRING: &str = "0b101";
    let document = markdown_with_edge_values_8605(
        BINARY_SHAPED_STRING,
        BINARY_SHAPED_STRING,
        "unsigned",
        BINARY_SHAPED_STRING,
    );
    let header = document
        .strip_prefix("---\n")
        .unwrap()
        .split_once("\n---\n")
        .unwrap()
        .0;
    let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(header).unwrap();
    assert_eq!(parsed["title"].as_str(), Some(BINARY_SHAPED_STRING));
    for key in ["target_id", "created_at"] {
        assert_eq!(
            parsed["reflects_on"][0][key].as_str(),
            Some(BINARY_SHAPED_STRING)
        );
    }
}

#[test]
fn cli_namespace_path_8591_refuses_traversal() {
    assert_stored_namespace_refused("team/../../escaped", NamespaceExportWriter::Cli);
}

#[test]
fn cli_namespace_path_8591_reports_row_with_escaped_namespace_r2() {
    assert_stored_namespace_refused("line\nbreak/..", NamespaceExportWriter::Cli);
}

#[test]
fn auto_namespace_path_8591_refuses_traversal() {
    assert_stored_namespace_refused("team/../../escaped", NamespaceExportWriter::Automatic);
}

#[test]
fn cli_namespace_path_8591_refuses_dot_only_components() {
    for namespace in ["...", ".", "..", "....", "team/./member", "team/../member"] {
        assert_stored_namespace_refused(namespace, NamespaceExportWriter::Cli);
    }
}

#[test]
fn auto_namespace_path_8591_refuses_dot_only_components() {
    for namespace in ["...", ".", "..", "....", "team/./member", "team/../member"] {
        assert_stored_namespace_refused(namespace, NamespaceExportWriter::Automatic);
    }
}

// ─────────────────────────────────────────────────────────────────────
// test_export_reflections_writes_md_files
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_export_reflections_writes_md_files() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);

    let src = seed_observation(&conn, "rfl-md", "obs");
    let rfl_id = drive_reflect(&conn, &db_path, "rfl-md", &src, "lesson");

    let out_dir = tmp.path().join("out");
    let args = make_args(&out_dir);
    let rc = run_cli(&db_path, &args);
    assert_eq!(rc, 0);

    let f = out_dir.join("rfl-md").join(format!("{rfl_id}.md"));
    assert!(f.exists(), "expected {}", f.display());
    let body = std::fs::read_to_string(&f).unwrap();
    assert!(body.starts_with("---\n"));
    assert!(body.contains(&format!("memory_id: {rfl_id}\n")));
    assert!(body.contains("namespace: rfl-md\n"));
    assert!(body.contains("reflection_depth: 1\n"));
    assert!(body.contains("reflects_on:\n"));
    assert!(
        body.contains(&format!("    target_id: {src}\n"))
            || body.contains(&format!("- target_id: {src}\n"))
            || body.contains(&format!("  - target_id: {src}\n"))
    );
    assert!(body.contains("reflection body for lesson"));
}

// ─────────────────────────────────────────────────────────────────────
// test_export_reflections_namespace_filter
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_export_reflections_namespace_filter() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);

    let src_a = seed_observation(&conn, "ns-a", "obs-a");
    let src_b = seed_observation(&conn, "ns-b", "obs-b");
    let rfl_a = drive_reflect(&conn, &db_path, "ns-a", &src_a, "ra");
    let rfl_b = drive_reflect(&conn, &db_path, "ns-b", &src_b, "rb");

    let out_dir = tmp.path().join("out");
    let mut args = make_args(&out_dir);
    args.namespace = Some("ns-a".into());
    let rc = run_cli(&db_path, &args);
    assert_eq!(rc, 0);

    let f_a = out_dir.join("ns-a").join(format!("{rfl_a}.md"));
    let f_b = out_dir.join("ns-b").join(format!("{rfl_b}.md"));
    assert!(f_a.exists(), "ns-a reflection must be exported");
    assert!(
        !f_b.exists(),
        "ns-b reflection must NOT be exported when --namespace=ns-a"
    );
}

// ─────────────────────────────────────────────────────────────────────
// test_export_reflections_json_format
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_export_reflections_json_format() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);

    let src = seed_observation(&conn, "json-ns", "obs");
    let rfl_id = drive_reflect(&conn, &db_path, "json-ns", &src, "lesson");

    let out_dir = tmp.path().join("out");
    let mut args = make_args(&out_dir);
    args.format = "json".into();
    let rc = run_cli(&db_path, &args);
    assert_eq!(rc, 0);

    let f = out_dir.join("json-ns").join(format!("{rfl_id}.json"));
    assert!(f.exists());
    let parsed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
    assert_eq!(parsed["memory_id"].as_str().unwrap(), rfl_id);
    assert_eq!(parsed["namespace"].as_str().unwrap(), "json-ns");
    assert_eq!(parsed["reflection_depth"].as_i64().unwrap(), 1);
    assert_eq!(parsed["reflects_on"][0].as_str().unwrap(), src);
    assert!(
        parsed["content"]
            .as_str()
            .unwrap()
            .contains("reflection body")
    );
}

// ─────────────────────────────────────────────────────────────────────
// test_export_reflections_since_filter
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_export_reflections_since_filter() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);

    let src = seed_observation(&conn, "since-ns", "obs");

    // Land an "old" reflection by directly inserting a row with a
    // backdated `created_at`. Going through `reflect()` is simpler but
    // would stamp `Utc::now()` and we couldn't distinguish "old" from
    // "new" without sleeping.
    let old_now = "2026-01-01T00:00:00Z".to_string();
    let old_id = uuid::Uuid::new_v4().to_string();
    let old_mem = Memory {
        id: old_id.clone(),
        tier: Tier::Mid,
        namespace: "since-ns".into(),
        title: "old".into(),
        content: "old body".into(),
        memory_kind: MemoryKind::Reflection,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        reflection_depth: 1,
        created_at: old_now.clone(),
        updated_at: old_now,
        metadata: json!({"agent_id": "ai:test"}),
        ..Default::default()
    };
    db::insert(&conn, &old_mem).expect("insert old");
    conn.execute(
        "INSERT INTO memory_links (source_id, target_id, relation, created_at, attest_level) \
         VALUES (?1, ?2, 'reflects_on', ?3, 'unsigned')",
        rusqlite::params![old_id, src, "2026-01-01T00:00:00Z"],
    )
    .unwrap();

    // Land a "new" reflection through the normal path.
    let new_id = drive_reflect(&conn, &db_path, "since-ns", &src, "new");

    let out_dir = tmp.path().join("out");
    let mut args = make_args(&out_dir);
    args.since = Some("2026-03-01T00:00:00Z".into());
    let rc = run_cli(&db_path, &args);
    assert_eq!(rc, 0);

    assert!(
        out_dir
            .join("since-ns")
            .join(format!("{new_id}.md"))
            .exists(),
        "new reflection must be exported"
    );
    assert!(
        !out_dir
            .join("since-ns")
            .join(format!("{old_id}.md"))
            .exists(),
        "old reflection must be filtered out by --since"
    );
}

// ─────────────────────────────────────────────────────────────────────
// test_memory_export_reflection_mcp_tool
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_memory_export_reflection_mcp_tool() {
    // Drive the MCP tool over a real stdio JSON-RPC round-trip — same
    // shape every other MCP integration test uses (forensic, reflect,
    // skill_promote, etc.).
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);
    let src = seed_observation(&conn, "mcp-ns", "obs");
    let rfl_id = drive_reflect(&conn, &db_path, "mcp-ns", &src, "lesson");
    // This is the only test in the module that reads the seeded DB from a
    // SEPARATE process (the spawned `ai-memory mcp` subprocess below) rather
    // than an in-process `db::open`. `db::open` opens WAL with
    // `synchronous=NORMAL`, and rusqlite's `Drop`->`sqlite3_close`
    // checkpoint-on-close is best-effort — so on macOS (APFS + WAL) the
    // reflection row can still be sitting in the `-wal` sidecar when the
    // subprocess opens the DB, surfacing as an intermittent
    // `memory not found` (issue #2764). Force a full checkpoint into the
    // main DB file BEFORE dropping the writer so the reader process is
    // guaranteed to see the committed row. This is a durability barrier,
    // not a timing hack.
    db::checkpoint(&conn).expect("wal checkpoint before subprocess read");
    drop(conn);

    let request = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\
         \"params\":{{\"name\":\"memory_export_reflection\",\
         \"arguments\":{{\"memory_id\":\"{rfl_id}\",\"format\":\"md\"}}}}}}\n"
    );

    let mut cmd = assert_cmd::Command::cargo_bin("ai-memory").unwrap();
    let assert = cmd
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "mcp",
            "--tier",
            "semantic",
            "--profile",
            "full",
        ])
        .write_stdin(request)
        .timeout(std::time::Duration::from_secs(30))
        .assert()
        .success();

    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // The MCP server emits the response as a JSON-RPC envelope on
    // stdout. The "content" array's text payload should contain the
    // rendered markdown.
    assert!(
        stdout.contains("memory_id: ") || stdout.contains("\\\"memory_id\\\":"),
        "expected MCP response to carry the rendered content; got:\n{stdout}"
    );
    assert!(
        stdout.contains(&rfl_id) || stdout.contains(&rfl_id.replace('-', "")),
        "expected MCP response to mention the reflection id"
    );
    assert!(stdout.contains("suggested_filename"));
}

// ─────────────────────────────────────────────────────────────────────
// test_auto_export_namespace_policy_triggers
// ─────────────────────────────────────────────────────────────────────

fn enable_auto_export(conn: &rusqlite::Connection, ns: &str) {
    let policy = GovernancePolicy {
        core: CorePolicy {
            write: GovernanceLevel::Any,
            promote: GovernanceLevel::Any,
            delete: GovernanceLevel::Owner,
            approver: ApproverType::Human,
            inherit: true,
            max_reflection_depth: None,
            required_scope: None,
        },
        export: ExportPolicy {
            auto_export_reflections_to_filesystem: Some(true),
        },
        ..Default::default()
    };
    let gov_meta = json!({
        "agent_id": "ai:test",
        "governance": serde_json::to_value(&policy).unwrap(),
    });
    let now = Utc::now().to_rfc3339();
    let std_mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: format!("__std_{ns}"),
        content: "standard".into(),
        created_at: now.clone(),
        updated_at: now,
        metadata: gov_meta,
        ..Default::default()
    };
    let id = db::insert(conn, &std_mem).unwrap();
    db::set_namespace_standard(conn, ns, &id, None).unwrap();
}

#[test]
fn test_auto_export_namespace_policy_triggers() {
    // Exercise the substrate hook directly — driving it through the
    // MCP handle_reflect goes via HOME, which we cannot deterministically
    // override across platforms. The hook factory is the load-bearing
    // unit; the MCP wire-up reuses it verbatim.
    use ai_memory::cli::commands::export_reflections::ExportFormat;
    use ai_memory::hooks::post_reflect::{AutoExportConfig, build_post_reflect_hook};

    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);
    enable_auto_export(&conn, "auto-on");
    let src = seed_observation(&conn, "auto-on", "obs");

    let out_dir = tmp.path().join("out");
    let hooks = build_post_reflect_hook(
        db_path.clone(),
        AutoExportConfig {
            out_dir: out_dir.clone(),
            format: ExportFormat::Markdown,
        },
    );

    let input = db::ReflectInput {
        source_ids: vec![src.clone()],
        title: "reflection".into(),
        content: "body".into(),
        namespace: Some("auto-on".into()),
        tier: Tier::Mid,
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "cli".into(),
        agent_id: "ai:test".into(),
        metadata: json!({}),
    };
    let outcome = db::reflect_with_hooks(&conn, &input, &hooks).expect("reflect");

    // Hook fires on a background thread; poll briefly for the file.
    let f = out_dir.join("auto-on").join(format!("{}.md", outcome.id));
    let mut found = false;
    for _ in 0..50 {
        if f.exists() {
            found = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        found,
        "post_reflect hook must write {} within 2.5s",
        f.display()
    );
    let body = std::fs::read_to_string(&f).unwrap();
    assert!(body.contains(&format!("memory_id: {}", outcome.id)));
}

// ─────────────────────────────────────────────────────────────────────
// test_auto_export_does_not_block_reflect_response
// ─────────────────────────────────────────────────────────────────────

#[test]
fn test_auto_export_does_not_block_reflect_response() {
    use ai_memory::cli::commands::export_reflections::ExportFormat;
    use ai_memory::hooks::post_reflect::{AutoExportConfig, build_post_reflect_hook};

    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open(&db_path);
    enable_auto_export(&conn, "nonblock-ns");
    let src = seed_observation(&conn, "nonblock-ns", "obs");

    // Use a deliberately weird out_dir to ensure the hook actually
    // tries to do work (we don't want a no-op masquerading as a "fast"
    // response). The directory is created inside the hook.
    let out_dir = tmp.path().join("deep").join("nested").join("path");
    let hooks = build_post_reflect_hook(
        db_path.clone(),
        AutoExportConfig {
            out_dir: out_dir.clone(),
            format: ExportFormat::Markdown,
        },
    );

    let input = db::ReflectInput {
        source_ids: vec![src.clone()],
        title: "rfl".into(),
        content: "rfl body".into(),
        namespace: Some("nonblock-ns".into()),
        tier: Tier::Mid,
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "cli".into(),
        agent_id: "ai:test".into(),
        metadata: json!({}),
    };
    let started = std::time::Instant::now();
    let outcome = db::reflect_with_hooks(&conn, &input, &hooks).expect("reflect");
    let reflect_elapsed = started.elapsed();

    // The reflect call must return well before the background thread
    // finishes its disk write. We use 250ms as a generous CI-safe
    // ceiling — the actual reflect_with_hooks call should take well
    // under 50ms; we leave headroom for slow VMs.
    assert!(
        reflect_elapsed < std::time::Duration::from_millis(250),
        "reflect_with_hooks must not block on auto-export (took {reflect_elapsed:?})"
    );

    // Confirm the disk write does eventually happen so we're sure the
    // "fast" path wasn't fast because the hook was a no-op.
    let f = out_dir
        .join("nonblock-ns")
        .join(format!("{}.md", outcome.id));
    let mut found = false;
    for _ in 0..50 {
        if f.exists() {
            found = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        found,
        "expected eventual on-disk artefact at {}",
        f.display()
    );
}
