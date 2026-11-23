// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10063 — `ai-memory export-forensic-bundle` must never write a
//! memory sealed at rest into the bundle as plaintext and must never drop it.
//!
//! The defect: the bundle read every in-scope memory through the decrypting
//! `db::get`, so a row sealed at rest was decrypted into
//! `memories/<id>.json` inside the tar. No bundle format carries the at-rest
//! envelope, so the only correct answer is to refuse the whole bundle with
//! `SEALED_EXPORT_REFUSED` before the output file is created (decision
//! recorded on #10028; #10056 tracks carrying the envelope).
//!
//! The command reads a SQLite `Connection` only (`db::open`), so there is no
//! Postgres cell. Every refusal cell asserts the exact text, that no output
//! file exists and that the sealed plaintext reaches no output. A control
//! cell proves an unsealed store bundles exactly as before.

#![allow(clippy::doc_markdown)]

use std::path::PathBuf;

use ai_memory::cli::CliOutput;
use ai_memory::db;
use ai_memory::forensic::bundle::{ExportForensicBundleArgs, run_export};
use ai_memory::models::{Memory, MemoryKind, Tier};

/// Namespace of every seeded row.
const NS: &str = "sealed-forensic-10063";

/// Plaintext of the sealed row. When the row is sealed this text must reach
/// no file, stdout, stderr or error.
const SEALED_MARKER: &str = "sealed forensic marker 10063";

/// Agent id the encryption keypair is minted for.
const KEY_AGENT: &str = "ai:forensic-sealed-10063";

/// The exact refusal for one sealed row of `memories`, written out here
/// rather than taken from the code under test.
fn expected_refusal(id: &str) -> String {
    format!(
        "SEALED_EXPORT_REFUSED: 1 row(s) of memories are sealed at rest (first id {id}); no \
         export format carries the at-rest envelope, so the export is refused and nothing was \
         written. Move an encrypted store with backup/restore (#10028)"
    )
}

fn sealed_envelope() -> Vec<u8> {
    let _ = ai_memory::identity::test_key_dir::install();
    let kp = ai_memory::encryption::get_or_create_keypair(KEY_AGENT).expect("x25519 keypair");
    ai_memory::encryption::encrypt(SEALED_MARKER, &kp.public)
        .expect("seal marker")
        .to_bytes()
}

struct Fixture {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    output: PathBuf,
    /// The memory whose chain is bundled (a reflection).
    target_id: String,
    /// The memory the target reflects on.
    source_id: String,
}

/// Which row of the two-row chain is sealed at rest.
#[derive(Clone, Copy)]
enum Sealed {
    None,
    Target,
    Source,
}

impl Fixture {
    /// A source observation and a reflection on it, linked `reflects_on`.
    /// The sealed row (if any) carries `SEALED_MARKER` as its plaintext.
    fn new(sealed: Sealed) -> Self {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let db_path = dir.path().join("memory.db");
        let conn = db::open(&db_path).expect("open db");
        let now = chrono::Utc::now().to_rfc3339();
        let row = |kind: MemoryKind, depth: i32, content: &str| Memory {
            id: uuid::Uuid::new_v4().to_string(),
            namespace: NS.into(),
            tier: Tier::Mid,
            memory_kind: kind,
            reflection_depth: depth,
            title: format!("forensic row {depth}"),
            content: content.into(),
            created_at: now.clone(),
            updated_at: now.clone(),
            metadata: serde_json::json!({"agent_id": "ai:test"}),
            ..Default::default()
        };
        let source_text = match sealed {
            Sealed::Source | Sealed::None => SEALED_MARKER,
            Sealed::Target => "source body",
        };
        let target_text = match sealed {
            Sealed::Target => SEALED_MARKER,
            Sealed::Source | Sealed::None => "target body",
        };
        let source_id = db::insert(&conn, &row(MemoryKind::Observation, 0, source_text))
            .expect("insert source");
        let target_id =
            db::insert(&conn, &row(MemoryKind::Reflection, 1, target_text)).expect("insert target");
        conn.execute(
            "INSERT INTO memory_links (source_id, target_id, relation, created_at, attest_level) \
             VALUES (?1, ?2, 'reflects_on', ?3, 'unsigned')",
            rusqlite::params![target_id, source_id, now],
        )
        .expect("link reflects_on");
        let sealed_id = match sealed {
            Sealed::None => None,
            Sealed::Target => Some(&target_id),
            Sealed::Source => Some(&source_id),
        };
        if let Some(id) = sealed_id {
            let changed = conn
                .execute(
                    "UPDATE memories SET content = '', encrypted_envelope = ?1 WHERE id = ?2",
                    rusqlite::params![sealed_envelope(), id],
                )
                .expect("seal the row");
            assert_eq!(changed, 1, "one row sealed");
        }
        db::checkpoint(&conn).expect("checkpoint");
        let output = dir.path().join("bundle.tar");
        Self {
            _dir: dir,
            db_path,
            output,
            target_id,
            source_id,
        }
    }

    fn export(&self, include_reflections: bool) -> (anyhow::Result<i32>, String) {
        let args = ExportForensicBundleArgs {
            memory_id: self.target_id.clone(),
            include_reflections,
            include_transcripts: false,
            include_atomisation_chain: true,
            output: Some(self.output.clone()),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            run_export(&self.db_path, &args, &mut out)
        };
        stdout.extend_from_slice(&stderr);
        (result, String::from_utf8_lossy(&stdout).into_owned())
    }
}

fn assert_refused(fx: &Fixture, include_reflections: bool, sealed_id: &str, cell: &str) {
    let (result, output) = fx.export(include_reflections);
    let err = result.expect_err("a sealed in-scope row must refuse the bundle");
    assert_eq!(
        format!("{err:#}"),
        expected_refusal(sealed_id),
        "{cell}: exact refusal"
    );
    assert!(
        !format!("{err:?}").contains(SEALED_MARKER),
        "{cell}: no plaintext in error"
    );
    assert!(
        !output.contains(SEALED_MARKER),
        "{cell}: no plaintext on output"
    );
    assert!(
        !output.contains("forensic bundle written"),
        "{cell}: no success line"
    );
    assert!(
        !fx.output.exists(),
        "{cell}: a refused bundle creates no output file"
    );
}

#[test]
fn forensic_bundle_refuses_a_sealed_target_10063() {
    for include_reflections in [false, true] {
        let fx = Fixture::new(Sealed::Target);
        let cell = format!("sealed target, include_reflections={include_reflections}");
        assert_refused(&fx, include_reflections, &fx.target_id, &cell);
    }
}

#[test]
fn forensic_bundle_refuses_a_sealed_ancestor_under_include_reflections_10063() {
    let fx = Fixture::new(Sealed::Source);
    assert_refused(&fx, true, &fx.source_id, "sealed ancestor");
}

/// Control: with encryption off the bundle is written exactly as before and
/// carries both rows of the chain.
#[test]
fn unsealed_chain_bundles_as_before_10063() {
    let fx = Fixture::new(Sealed::None);
    let (result, output) = fx.export(true);
    assert_eq!(result.expect("bundle export"), 0);
    assert!(
        output.contains("forensic bundle written"),
        "success line printed"
    );
    let bytes = std::fs::read(&fx.output).expect("read bundle");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.contains(&format!("memories/{}.json", fx.target_id)),
        "target envelope bundled"
    );
    assert!(
        text.contains(&format!("memories/{}.json", fx.source_id)),
        "source envelope bundled"
    );
    assert!(text.contains(SEALED_MARKER), "source content bundled");
}
