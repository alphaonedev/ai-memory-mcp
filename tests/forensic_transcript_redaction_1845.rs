// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1845 (security review S3, CWE-312) — forensic-transcript egress
//! redaction regression test.
//!
//! The fix lives in `src/forensic/bundle.rs` (~lines 591-604): when a
//! forensic bundle is generated with `include_transcripts:true`, the raw
//! transcript body fetched from `transcripts::storage::fetch` is passed
//! through `secret_screen::redact_for_storage` BEFORE it is written into
//! the bundle as `transcripts/{id}.content`. A credential pasted into a
//! captured turn must NOT leak verbatim into the signed evidence bundle
//! handed to an auditor.
//!
//! The CHANGELOG claimed this was "tested", but the only pre-existing
//! `include_transcripts` test (`transcripts_flag_includes_replay_union`
//! in `tests/forensic/bundle_test.rs`) uses a benign body and asserts
//! only file *presence* — it would still pass if a future refactor
//! dropped the `redact_for_storage` call and re-introduced the leak.
//!
//! This test PINS the redaction: it stores a transcript whose body
//! carries a real, detectable credential (verbatim) plus benign
//! surrounding prose, generates a bundle with `include_transcripts:true`,
//! and asserts that the egressed `transcripts/{id}.content` bytes contain
//! the redaction mask and NOT the verbatim credential — while the benign
//! prose survives (proving it is a redaction, not a blanket drop). It
//! also confirms the underlying transcript row is still stored RAW, so
//! the bundle egress is demonstrably the redaction point.

#![allow(clippy::doc_markdown)]

use ai_memory::cli::CliOutput;
use ai_memory::db;
use ai_memory::forensic::bundle::{self, ExportForensicBundleArgs, read_ustar};
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::secret_screen::{REDACTION_PLACEHOLDER, SecretScreenMode, set_screen_mode};
use ai_memory::transcripts::storage as ts;
use chrono::Utc;
use rusqlite::params;
use tempfile::TempDir;

// A known-detected AWS access-key id. The G29 acceptance suite
// (`tests/secret_screen_g29.rs`) uses this exact value as a credential
// that the screener REFUSES, so it is guaranteed to be detected here too.
const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
// Benign prose that wraps the credential — must survive redaction intact.
const BENIGN_PREFIX: &str = "Investigating the prod outage on 2026-06-29.";
const BENIGN_SUFFIX: &str = "The above key must be rotated immediately.";

fn open_db(p: &std::path::Path) -> rusqlite::Connection {
    db::open(p).expect("db::open")
}

fn insert_memory(conn: &rusqlite::Connection, ns: &str, depth: i32, kind: MemoryKind) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Mid,
        namespace: ns.to_string(),
        title: format!("t-{depth}"),
        content: format!("c-{depth}"),
        reflection_depth: depth,
        created_at: now.clone(),
        updated_at: now,
        memory_kind: kind,
        ..Default::default()
    };
    db::insert(conn, &mem).expect("insert");
    id
}

fn link_unsigned(conn: &rusqlite::Connection, src: &str, tgt: &str) {
    conn.execute(
        "INSERT OR IGNORE INTO memory_links \
         (source_id, target_id, relation, created_at, attest_level) \
         VALUES (?1, ?2, 'reflects_on', ?3, 'unsigned')",
        params![src, tgt, Utc::now().to_rfc3339()],
    )
    .expect("link_unsigned");
}

/// #1845 — a credential in a transcript body is redacted on forensic
/// bundle egress, not leaked verbatim into `transcripts/{id}.content`.
#[test]
fn transcript_credential_is_redacted_in_forensic_bundle_1845() {
    // `redact_for_storage` (the egress mask wired into bundle.rs) is a
    // no-op only when the process screen mode is `Off`, and a fresh test
    // binary defaults to `Off`. Seed a non-`Off` mode so the egress path
    // actually screens — `Redact` mirrors the storage-funnel semantics.
    set_screen_mode(SecretScreenMode::Redact);

    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("ai-memory.db");
    let conn = open_db(&db_path);

    // (a) fresh store + a depth-1 reflection over a depth-0 observation.
    let d0 = insert_memory(&conn, "fb-1845", 0, MemoryKind::Observation);
    let d1 = insert_memory(&conn, "fb-1845", 1, MemoryKind::Reflection);
    link_unsigned(&conn, &d1, &d0);

    // (b) store a transcript whose body carries a verbatim credential
    // wrapped in benign prose, linked to the depth-0 memory so the
    // include-transcripts replay union picks it up for the d1 bundle.
    let body = format!("{BENIGN_PREFIX} The leaked key was {AWS_KEY}. {BENIGN_SUFFIX}");
    let t = ts::store(&conn, "fb-1845", &body, None).expect("store transcript");
    ts::link_transcript(&conn, &d0, &t.id, None, None).expect("link transcript");

    // Sanity: the underlying transcript row is stored RAW (transcript
    // storage does not screen), so the bundle egress is demonstrably the
    // sole redaction point being exercised below.
    let stored = ts::fetch(&conn, &t.id)
        .expect("fetch")
        .expect("transcript row present");
    assert!(
        stored.contains(AWS_KEY),
        "precondition: the stored transcript body must retain the verbatim \
         credential (redaction happens on egress, not on store); got: {stored:?}"
    );
    drop(conn);

    // (c) generate the forensic bundle with include_transcripts:true.
    let bundle_path = tmp.path().join("bundle.tar");
    let args = ExportForensicBundleArgs {
        memory_id: d1.clone(),
        include_reflections: true,
        include_transcripts: true,
        include_atomisation_chain: true,
        output: Some(bundle_path.clone()),
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    {
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        bundle::run_export(&db_path, &args, &mut out).expect("export");
    }

    // (d) locate the emitted transcripts/{id}.content entry.
    let bytes = std::fs::read(&bundle_path).expect("read bundle");
    let files = read_ustar(&bytes).expect("parse bundle tar");
    let content_key = format!("transcripts/{}.content", t.id);
    let egressed = files
        .get(&content_key)
        .unwrap_or_else(|| panic!("bundle must contain {content_key}; keys: {:?}", files.keys()));
    let egressed = String::from_utf8(egressed.clone()).expect("content is utf-8");

    // (e) the verbatim credential is ABSENT and the mask token PRESENT.
    assert!(
        !egressed.contains(AWS_KEY),
        "#1845 REGRESSION: the verbatim credential leaked into the forensic \
         bundle transcript content; egressed bytes = {egressed:?}"
    );
    assert!(
        egressed.contains(REDACTION_PLACEHOLDER),
        "#1845: the redaction mask {REDACTION_PLACEHOLDER:?} must be present in \
         the egressed transcript content; got: {egressed:?}"
    );

    // (f) the benign surrounding prose survives — proving this is a
    // targeted redaction, not a blanket drop of the whole transcript.
    assert!(
        egressed.contains(BENIGN_PREFIX) && egressed.contains(BENIGN_SUFFIX),
        "#1845: benign surrounding text must survive redaction; got: {egressed:?}"
    );
}
