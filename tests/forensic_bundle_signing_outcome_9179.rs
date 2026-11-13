// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8851 / #9179 — the signing outcome of a forensic bundle is pinned in BOTH
//! directions, in a test binary of its own.
//!
//! `bundle::build` signs through `identity::keypair::default_key_dir()` and
//! `bundle::verify` resolves the signer through the same store, so whether a
//! bundle comes out signed depends on which keys that store holds. The
//! unsigned pin therefore has to build its own key directory instead of
//! trusting whatever a sibling test (or the runner) enrolled. Isolating it
//! needs a process-wide `AI_MEMORY_KEY_DIR` override, and the lib test binary
//! runs its tests on parallel threads, so the override lives here (one
//! process, serialised by [`KeyDirScope`]) rather than in `src/` (#3475).
//!
//! * no enrolled key  -> `SignatureStatus::Absent`, `manifest_signature_absent`,
//!   `run_verify` exit 2;
//! * one enrolled key -> `SignatureStatus::Verified`, that exact signer,
//!   `run_verify` exit 0.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};

use ai_memory::cli::CliOutput;
use ai_memory::db;
use ai_memory::forensic::bundle::{
    self, ExportForensicBundleArgs, REASON_MANIFEST_SIGNATURE_ABSENT, SignatureStatus,
    VerifyForensicBundleArgs,
};
use ai_memory::identity::keypair as kp;
use ai_memory::models::{Memory, MemoryKind, Tier};
use chrono::Utc;
use rusqlite::params;
use tempfile::TempDir;

/// Serialises every test in this binary that touches `AI_MEMORY_KEY_DIR`.
static KEY_DIR_LOCK: Mutex<()> = Mutex::new(());

/// Signer enrolled by the signed-outcome test.
const SIGNER: &str = "bundle-signer-9179";

/// A fresh key directory bound to `AI_MEMORY_KEY_DIR` for one test.
///
/// Rooted under the isolated sandbox (outside HOME by construction, #3859)
/// with a unique child per scope, so exactly the keys the test enrols exist.
struct KeyDirScope {
    _lock: MutexGuard<'static, ()>,
    prev: Option<OsString>,
    dir: PathBuf,
}

impl KeyDirScope {
    fn new() -> Self {
        let lock = KEY_DIR_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let dir =
            key_dir_sandbox::pin().join(format!("bundle-9179-{}", uuid::Uuid::new_v4().simple()));
        key_dir_sandbox::mkdir_0700(&dir);
        let prev = std::env::var_os(kp::KEY_DIR_ENV);
        // SAFETY: `KEY_DIR_LOCK` is held for the scope's life and this binary
        // runs no other thread that reads or writes the environment.
        unsafe { std::env::set_var(kp::KEY_DIR_ENV, &dir) };
        Self {
            _lock: lock,
            prev,
            dir,
        }
    }

    /// No enrolled key: a built bundle must be unsigned.
    fn empty() -> Self {
        Self::new()
    }

    /// Exactly one enrolled signing key, `agent_id`.
    fn with_key(agent_id: &str) -> Self {
        let scope = Self::new();
        let keypair = kp::generate(agent_id).expect("generate test key");
        kp::save(&keypair, &scope.dir).expect("save test key");
        scope
    }
}

impl Drop for KeyDirScope {
    fn drop(&mut self) {
        // SAFETY: still holding `_lock` (fields drop after this body).
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var(kp::KEY_DIR_ENV, v),
                None => std::env::remove_var(kp::KEY_DIR_ENV),
            }
        }
    }
}

fn insert_mem(conn: &rusqlite::Connection, ns: &str, depth: i32, kind: MemoryKind) -> String {
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
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
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

/// Build a depth-1 reflection bundle into `tmp` and return its path.
fn build_bundle(tmp: &TempDir, name: &str) -> PathBuf {
    let p = tmp.path().join("ai-memory.db");
    let conn = db::open(&p).expect("db::open");
    let d0 = insert_mem(&conn, "ns", 0, MemoryKind::Observation);
    let d1 = insert_mem(&conn, "ns", 1, MemoryKind::Reflection);
    link_unsigned(&conn, &d1, &d0);
    let args = ExportForensicBundleArgs {
        memory_id: d1,
        include_reflections: true,
        include_transcripts: false,
        include_atomisation_chain: true,
        output: None,
    };
    let bundle_path = tmp.path().join(name);
    bundle::build(&conn, &args, &bundle_path, Some("2026-01-01T00:00:00Z")).expect("build");
    bundle_path
}

fn run_verify(bundle_path: PathBuf) -> (i32, String) {
    let vargs = VerifyForensicBundleArgs { bundle_path };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let code = {
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        bundle::run_verify(&vargs, &mut out).expect("run_verify")
    };
    (code, String::from_utf8(stdout).expect("utf8 stdout"))
}

#[test]
fn verify_clean_unsigned_bundle_is_intact_but_unattested_8851() {
    let _keys = KeyDirScope::empty();
    let tmp = TempDir::new().unwrap();
    let bundle_path = build_bundle(&tmp, "bundle.tar");
    let report = bundle::verify(&bundle_path).expect("verify");
    // #8851: integrity holds, but an unsigned manifest is not attested, so
    // the roll-up is a finding with its own reason.
    assert_eq!(report.tampered_files, Vec::<String>::new());
    assert_eq!(report.missing_files, Vec::<String>::new());
    assert_eq!(report.signature_status, SignatureStatus::Absent);
    assert!(
        !report.ok,
        "unsigned bundle must not roll up ok: {report:#?}"
    );
    assert_eq!(
        bundle::failure_reason(&report),
        Some(REASON_MANIFEST_SIGNATURE_ABSENT)
    );
}

/// Mirror of the unsigned pin: with exactly one enrolled key the same bundle
/// is signed by THAT signer and rolls up green.
#[test]
fn verify_signed_bundle_is_attested_by_enrolled_signer_8851() {
    let _keys = KeyDirScope::with_key(SIGNER);
    let tmp = TempDir::new().unwrap();
    let bundle_path = build_bundle(&tmp, "signed.tar");
    let report = bundle::verify(&bundle_path).expect("verify");
    assert_eq!(report.signature_status, SignatureStatus::Verified);
    assert_eq!(report.signer_agent_id.as_deref(), Some(SIGNER));
    assert_eq!(bundle::failure_reason(&report), None);
    assert!(report.ok, "{report:#?}");

    let (code, printed) = run_verify(bundle_path);
    assert_eq!(code, 0, "{printed}");
    assert!(printed.contains("verification OK"), "{printed}");
}

/// #8851: `run_verify` returns exit 2 on an intact but unsigned bundle and
/// names the `manifest_signature_absent` reason.
#[test]
fn run_verify_unsigned_bundle_exits_two_signature_absent_8851() {
    let _keys = KeyDirScope::empty();
    let tmp = TempDir::new().unwrap();
    let bundle_path = build_bundle(&tmp, "ok.tar");
    let (code, printed) = run_verify(bundle_path);
    assert_eq!(code, 2, "{printed}");
    assert!(
        printed.contains(&format!(
            "verification FAILED: {REASON_MANIFEST_SIGNATURE_ABSENT}"
        )),
        "{printed}"
    );
}
