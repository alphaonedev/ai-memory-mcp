// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10061 — the reflection exporters must never write a row sealed at
//! rest out as plaintext and must never drop it.
//!
//! The defect: `ai-memory export-reflections` and the post-reflect
//! auto-export hook read reflections through the decrypting projection, so a
//! reflection sealed at rest was decrypted into a plaintext file on disk (or
//! skipped when the key was absent, with the count line still reporting
//! success). No reflection export format carries the at-rest envelope, so the
//! only correct answer is to refuse with `SEALED_EXPORT_REFUSED` before the
//! first file is written (decision recorded on #10028; #10056 tracks carrying
//! the envelope). The MCP `memory_export_reflection` tool renders the same
//! export payload and is held to the same refusal.
//!
//! Every cell asserts the exact refusal text, that no file was written and
//! that the sealed plaintext reaches no output. A control cell proves a store
//! with encryption off exports exactly as before.

#![allow(clippy::doc_markdown)]

use std::path::{Path, PathBuf};

use ai_memory::cli::CliOutput;
use ai_memory::cli::commands::export_reflections::{self, ExportFormat, ExportReflectionsArgs};
use ai_memory::db;
use ai_memory::hooks::post_reflect::auto_export::{AutoExportConfig, run_auto_export};
use ai_memory::models::{ExportPolicy, GovernancePolicy, Memory, MemoryKind, Tier};

/// Namespace of every seeded row.
const NS: &str = "sealed-reflections-10061";

/// Plaintext of the reflection. When the row is sealed this text must reach
/// no file, response or error.
const SEALED_MARKER: &str = "sealed reflection marker 10061 \u{1f512}";

/// Agent id the encryption keypair is minted for.
const KEY_AGENT: &str = "ai:reflections-sealed-10061";

/// The exact refusal for one sealed row of `memories`, written out here
/// rather than taken from the code under test.
fn expected_refusal(id: &str) -> String {
    format!(
        "SEALED_EXPORT_REFUSED: 1 row(s) of memories are sealed at rest (first id {id}); no \
         export format carries the at-rest envelope, so the export is refused and nothing was \
         written. Move an encrypted store with backup/restore (#10028)"
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    out_dir: PathBuf,
    reflection_id: String,
}

impl Fixture {
    /// One namespace whose standard blesses auto-export, one reflection;
    /// sealed at rest when `sealed`.
    fn new(sealed: bool) -> Self {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_path = dir.path().join("memory.db");
        let conn = db::open(&db_path).expect("open db");
        let now = chrono::Utc::now().to_rfc3339();
        let policy = GovernancePolicy {
            export: ExportPolicy {
                auto_export_reflections_to_filesystem: Some(true),
            },
            ..Default::default()
        };
        let standard = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: NS.into(),
            tier: Tier::Long,
            title: "export standard".into(),
            content: "standard".into(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: serde_json::json!({"agent_id": "ai:test", "governance": policy}),
            ..Default::default()
        };
        let standard_id = db::insert(&conn, &standard).expect("insert standard");
        db::set_namespace_standard(&conn, NS, &standard_id, None).expect("set standard");
        let reflection = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: NS.into(),
            tier: Tier::Mid,
            memory_kind: MemoryKind::Reflection,
            title: "sealed reflection".into(),
            content: SEALED_MARKER.into(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({"agent_id": "ai:test"}),
            ..Default::default()
        };
        let reflection_id = db::insert(&conn, &reflection).expect("insert reflection");
        if sealed {
            let changed = conn
                .execute(
                    "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
                    rusqlite::params![sealed_envelope(), reflection_id],
                )
                .expect("seal the reflection");
            assert_eq!(changed, 1, "one row sealed");
        }
        db::checkpoint(&conn).expect("checkpoint");
        let out_dir = dir.path().join("out");
        Self {
            _dir: dir,
            db_path,
            out_dir,
            reflection_id,
        }
    }

    fn cli(&self) -> (anyhow::Result<i32>, String) {
        let args = ExportReflectionsArgs {
            namespace: Some(NS.into()),
            out_dir: Some(self.out_dir.clone()),
            format: "md".into(),
            since: None,
            quiet: false,
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = {
            let mut output = CliOutput {
                stdout: &mut stdout,
                stderr: &mut stderr,
            };
            export_reflections::run(&self.db_path, &args, &mut output)
        };
        stdout.extend_from_slice(&stderr);
        (result, String::from_utf8_lossy(&stdout).into_owned())
    }

    fn auto(&self) -> anyhow::Result<()> {
        run_auto_export(
            &self.db_path,
            &self.reflection_id,
            NS,
            &AutoExportConfig {
                out_dir: self.out_dir.clone(),
                format: ExportFormat::Markdown,
            },
        )
    }

    fn mcp(&self) -> Result<serde_json::Value, String> {
        let conn = db::open(&self.db_path).expect("open db");
        ai_memory::mcp::handle_export_reflection(
            &conn,
            &serde_json::json!({"memory_id": self.reflection_id, "format": "md"}),
        )
    }
}

fn sealed_envelope() -> Vec<u8> {
    let _ = ai_memory::identity::test_key_dir::install();
    let kp = ai_memory::encryption::get_or_create_keypair(KEY_AGENT).expect("x25519 keypair");
    ai_memory::encryption::encrypt(SEALED_MARKER, &kp.public)
        .expect("seal marker")
        .to_bytes()
}

/// Every regular file under `root` (none when `root` is absent).
fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

fn assert_no_file_written(fx: &Fixture, cell: &str) {
    assert_eq!(
        files_under(&fx.out_dir),
        Vec::<PathBuf>::new(),
        "{cell}: a refused export writes no file"
    );
}

#[test]
fn export_reflections_cli_refuses_a_sealed_reflection_10061() {
    let fx = Fixture::new(true);
    let (result, output) = fx.cli();
    let err = result.expect_err("a sealed reflection must refuse the CLI export");
    assert_eq!(
        format!("{err:#}"),
        expected_refusal(&fx.reflection_id),
        "cli: exact refusal"
    );
    assert!(
        !output.contains(SEALED_MARKER),
        "cli: no plaintext on output"
    );
    assert!(
        !format!("{err:?}").contains(SEALED_MARKER),
        "cli: no plaintext in error"
    );
    assert_no_file_written(&fx, "cli");
}

#[test]
fn post_reflect_auto_export_refuses_a_sealed_reflection_10061() {
    let fx = Fixture::new(true);
    let err = fx
        .auto()
        .expect_err("a sealed reflection must refuse the auto-export");
    assert_eq!(
        format!("{err:#}"),
        expected_refusal(&fx.reflection_id),
        "auto-export: exact refusal"
    );
    assert!(
        !format!("{err:?}").contains(SEALED_MARKER),
        "auto-export: no plaintext in error"
    );
    assert_no_file_written(&fx, "auto-export");
}

#[test]
fn mcp_export_reflection_refuses_a_sealed_reflection_10061() {
    let fx = Fixture::new(true);
    let err = fx
        .mcp()
        .expect_err("a sealed reflection must refuse the MCP export");
    assert_eq!(
        err,
        expected_refusal(&fx.reflection_id),
        "mcp: exact refusal"
    );
    assert!(!err.contains(SEALED_MARKER), "mcp: no plaintext in error");
}

/// Control: with encryption off every exporter writes the reflection exactly
/// as before.
#[test]
fn unsealed_reflection_exports_as_before_10061() {
    let fx = Fixture::new(false);
    let (result, _) = fx.cli();
    assert_eq!(result.expect("cli export"), 0);
    let files = files_under(&fx.out_dir);
    assert_eq!(
        files,
        vec![fx.out_dir.join(NS).join(format!("{}.md", fx.reflection_id))],
        "cli: one file per reflection"
    );
    let body = std::fs::read_to_string(&files[0]).expect("read export");
    assert!(body.contains(SEALED_MARKER), "cli: the content is exported");

    let fx = Fixture::new(false);
    fx.auto().expect("auto export");
    let files = files_under(&fx.out_dir);
    assert_eq!(files.len(), 1, "auto-export: one file");
    assert!(
        std::fs::read_to_string(&files[0])
            .expect("read export")
            .contains(SEALED_MARKER),
        "auto-export: the content is exported"
    );

    let fx = Fixture::new(false);
    let value = fx.mcp().expect("mcp export");
    assert!(
        value.to_string().contains(SEALED_MARKER),
        "mcp: the content is rendered"
    );
}
