// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Durable-ID validation at both reflection filesystem writers (#8598).
//! SQLite fixtures bypass ingestion, then exercise the real export entry points.

use ai_memory::cli::CliOutput;
use ai_memory::cli::commands::export_reflections::{self, ExportFormat, ExportReflectionsArgs};
use ai_memory::db;
use ai_memory::hooks::post_reflect::auto_export::{AutoExportConfig, run_auto_export};
use ai_memory::models::{ExportPolicy, GovernancePolicy, Memory, Tier};
use chrono::Utc;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const NAMESPACE: &str = "id-containment";
const OVERSIZE_ID_BYTES: usize = 129;
const MAX_REFUSAL_BYTES: usize = 2048;

#[derive(Clone, Copy)]
enum Writer {
    Cli,
    Automatic,
}

#[derive(Clone, Copy)]
enum IdShape {
    Slash,
    Backslash,
    DotDot,
    Absolute,
    Nul,
    Control,
    Oversize,
    Valid,
}

fn fixture(db_path: &Path, id: &str) {
    let conn = db::open(db_path).unwrap();
    let now = Utc::now().to_rfc3339();
    let policy = GovernancePolicy {
        export: ExportPolicy {
            auto_export_reflections_to_filesystem: Some(true),
        },
        ..Default::default()
    };
    let standard = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NAMESPACE.into(),
        title: "namespace standard".into(),
        content: "standard".into(),
        created_at: now.clone(),
        updated_at: now.clone(),
        metadata: json!({"governance": policy}),
        ..Default::default()
    };
    let standard_id = db::insert(&conn, &standard).unwrap();
    db::set_namespace_standard(&conn, NAMESPACE, &standard_id, None).unwrap();
    let memory = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: NAMESPACE.into(),
        title: "reflection".into(),
        content: "reflection body".into(),
        created_at: now.clone(),
        updated_at: now,
        ..Default::default()
    };
    let original = db::insert(&conn, &memory).unwrap();
    // Model a durable row that bypassed validate_id at ingestion.
    conn.execute(
        "UPDATE memories SET id = ?1, memory_kind = 'reflection' WHERE id = ?2",
        rusqlite::params![id, original],
    )
    .unwrap();
    db::checkpoint(&conn).unwrap();
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut result = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            if entry.file_type().unwrap().is_dir() {
                result.insert(relative, None);
                pending.push(path);
            } else {
                result.insert(relative, Some(fs::read(path).unwrap()));
            }
        }
    }
    result
}

fn batch_fixture(db_path: &Path, middle_id: &str, middle_namespace: &str) {
    let conn = db::open(db_path).unwrap();
    let rows = [
        ("aaa-valid", "team", "2026-01-03T00:00:00Z"),
        (middle_id, middle_namespace, "2026-01-02T00:00:00Z"),
        ("zzz-valid", "team", "2026-01-01T00:00:00Z"),
    ];
    for (id, namespace, timestamp) in rows {
        let memory = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: "team".into(),
            title: "batch reflection".into(),
            content: "batch reflection body".into(),
            created_at: timestamp.into(),
            updated_at: timestamp.into(),
            ..Default::default()
        };
        let original = db::insert(&conn, &memory).unwrap();
        conn.execute(
            "UPDATE memories SET id = ?1, namespace = ?2, memory_kind = 'reflection' \
             WHERE id = ?3",
            rusqlite::params![id, namespace, original],
        )
        .unwrap();
    }
    let selected = db::list(
        &conn,
        None,
        None,
        rows.len(),
        0,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        selected
            .iter()
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>(),
        ["aaa-valid", middle_id, "zzz-valid"],
        "the refused row must be selected between two valid rows"
    );
    db::checkpoint(&conn).unwrap();
}

fn assert_batch_refusal(existing: bool, invalid_namespace: bool) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("batch-root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("protected"), b"unchanged").unwrap();
    let out_dir = root.join("exports");
    if existing {
        fs::create_dir(&out_dir).unwrap();
        fs::write(out_dir.join("keep"), b"existing export").unwrap();
    }
    let (id, namespace, refusal) = if invalid_namespace {
        ("bbb-valid", "team/...", "refusing export path")
    } else {
        ("mmm/../evil", "team", "refusing export id")
    };
    let db_path = tmp.path().join("batch.db");
    batch_fixture(&db_path, id, namespace);
    let before = tree(&root);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let error = export_reflections::run(
        &db_path,
        &ExportReflectionsArgs {
            namespace: None,
            out_dir: Some(out_dir),
            format: "md".into(),
            since: None,
            quiet: false,
        },
        &mut CliOutput {
            stdout: &mut stdout,
            stderr: &mut stderr,
        },
    )
    .expect_err("a refused middle row aborts the entire batch");
    let diagnostic = error.to_string();
    assert!(diagnostic.contains(refusal));
    assert!(diagnostic.contains(id));
    assert!(diagnostic.contains(namespace));
    assert_eq!(tree(&root), before, "no earlier row may modify the tree");
    assert_eq!(stdout.as_slice(), b"");
}

#[test]
fn cli_batch_invalid_id_absent_8598() {
    assert_batch_refusal(false, false);
}

#[test]
fn cli_batch_invalid_id_existing_8598() {
    assert_batch_refusal(true, false);
}

#[test]
fn cli_batch_invalid_namespace_absent_8598() {
    assert_batch_refusal(false, true);
}

#[test]
fn cli_batch_invalid_namespace_existing_8598() {
    assert_batch_refusal(true, true);
}

fn assert_writer(writer: Writer, shape: IdShape) {
    // Both an absent output directory and an existing tree must survive refusal.
    for existing in [false, true] {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("writer-root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("protected"), b"unchanged").unwrap();
        let out_dir = root.join("exports");
        if existing {
            fs::create_dir(&out_dir).unwrap();
            fs::write(out_dir.join("keep"), b"existing export").unwrap();
        }
        let id = match shape {
            IdShape::Slash => "nested/escaped".into(),
            IdShape::Backslash => "nested\\escaped".into(),
            IdShape::DotDot => "../../escaped".into(),
            IdShape::Absolute => root.join("absolute-escaped").to_str().unwrap().to_owned(),
            IdShape::Nul => "stored\0id".into(),
            IdShape::Control => "stored\u{1b}\rid".into(),
            IdShape::Oversize => "x".repeat(OVERSIZE_ID_BYTES),
            IdShape::Valid => "valid-id_01".into(),
        };
        let db_path = tmp.path().join("fixture.db");
        fixture(&db_path, &id);
        let before = tree(&root);
        let result = match writer {
            Writer::Cli => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let mut output = CliOutput {
                    stdout: &mut stdout,
                    stderr: &mut stderr,
                };
                export_reflections::run(
                    &db_path,
                    &ExportReflectionsArgs {
                        namespace: Some(NAMESPACE.into()),
                        out_dir: Some(out_dir.clone()),
                        format: "md".into(),
                        since: None,
                        quiet: true,
                    },
                    &mut output,
                )
                .map(|_| ())
            }
            Writer::Automatic => run_auto_export(
                &db_path,
                &id,
                NAMESPACE,
                &AutoExportConfig {
                    out_dir: out_dir.clone(),
                    format: ExportFormat::Markdown,
                },
            ),
        };
        if matches!(shape, IdShape::Valid) {
            result.unwrap();
            let contents =
                fs::read_to_string(out_dir.join(NAMESPACE).join(format!("{id}.md"))).unwrap();
            assert!(contents.contains("reflection body"));
        } else {
            let error = result.expect_err("stored invalid ID must be refused");
            let expected = ai_memory::validate::validate_id(&id).unwrap_err();
            assert_eq!(error.root_cause().to_string(), expected.to_string());
            assert_eq!(
                tree(&root),
                before,
                "refusal must not create directories or files"
            );
            let diagnostic = error.to_string();
            assert!(diagnostic.contains("refusing export id"));
            assert!(diagnostic.len() <= MAX_REFUSAL_BYTES);
            assert!(!diagnostic.chars().any(char::is_control));
        }
    }
}

#[test]
fn cli_slash_8598() {
    assert_writer(Writer::Cli, IdShape::Slash);
}
#[test]
fn cli_backslash_8598() {
    assert_writer(Writer::Cli, IdShape::Backslash);
}
#[test]
fn cli_dotdot_8598() {
    assert_writer(Writer::Cli, IdShape::DotDot);
}
#[test]
fn cli_absolute_8598() {
    assert_writer(Writer::Cli, IdShape::Absolute);
}
#[test]
fn cli_nul_8598() {
    assert_writer(Writer::Cli, IdShape::Nul);
}
#[test]
fn cli_control_8598() {
    assert_writer(Writer::Cli, IdShape::Control);
}
#[test]
fn cli_oversize_8598() {
    assert_writer(Writer::Cli, IdShape::Oversize);
}
#[test]
fn cli_valid_8598() {
    assert_writer(Writer::Cli, IdShape::Valid);
}
#[test]
fn auto_slash_8598() {
    assert_writer(Writer::Automatic, IdShape::Slash);
}
#[test]
fn auto_backslash_8598() {
    assert_writer(Writer::Automatic, IdShape::Backslash);
}
#[test]
fn auto_dotdot_8598() {
    assert_writer(Writer::Automatic, IdShape::DotDot);
}
#[test]
fn auto_absolute_8598() {
    assert_writer(Writer::Automatic, IdShape::Absolute);
}
#[test]
fn auto_nul_8598() {
    assert_writer(Writer::Automatic, IdShape::Nul);
}
#[test]
fn auto_control_8598() {
    assert_writer(Writer::Automatic, IdShape::Control);
}
#[test]
fn auto_oversize_8598() {
    assert_writer(Writer::Automatic, IdShape::Oversize);
}
#[test]
fn auto_valid_8598() {
    assert_writer(Writer::Automatic, IdShape::Valid);
}
