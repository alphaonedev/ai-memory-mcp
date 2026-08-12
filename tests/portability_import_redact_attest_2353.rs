// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2353 (sibling of #2340) — the v2 bundle import must redact an imported
//! row to its TO-BE-PERSISTED form BEFORE re-deriving attestation, so a
//! bundle row whose `write_signature` covers RAW secret-bearing bytes can
//! never land `agent_attested` over redacted (different) stored bytes.
//!
//! Isolated test binary because the credential screen mode is a
//! process-global `OnceLock` (`set_screen_mode`) — every test here runs
//! under `Redact` mode (the only mode where #2353 manifests: the default
//! `refuse` mode refuses secret-bearing bundle rows at the L1-parity
//! `validate_memory` gate instead).

use std::collections::BTreeMap;
use std::path::PathBuf;

use ai_memory::identity::attest;
use ai_memory::models::{Memory, MemoryKind, field_names::WRITE_SIGNATURE};
use ai_memory::portability::emit::{ExportEnvelope, SPEC_VERSION_V2};
use ai_memory::portability::import::{ImportOptions, import_full_envelope};
use ai_memory::secret_screen::{SecretScreenMode, set_screen_mode};
use base64::Engine as _;
use rusqlite::Connection;

/// A GitHub PAT the credential detector reliably flags (mirrors
/// `tests/federation_write_sig_emit_1801.rs`).
const SECRET_TOKEN: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

const AUTHOR: &str = "ai:bundle-author";

fn fresh_db(tag: &str) -> Connection {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-2353-import-redact");
    std::fs::create_dir_all(&root).ok();
    let dir = tempfile::Builder::new()
        .prefix(tag)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");
    let path = dir.path().join("db.sqlite");
    drop(ai_memory::db::open(&path).expect("init db"));
    std::mem::forget(dir); // keep the file alive for the connection's lifetime
    ai_memory::db::open(&path).expect("open db")
}

/// A bundle memory authored + SIGNED by `AUTHOR` over its CURRENT bytes,
/// with the signature emitted into `metadata.write_signature` — the shape an
/// exporting node ships.
fn signed_bundle_memory(
    id: &str,
    content: &str,
    kp: &ai_memory::identity::keypair::AgentKeypair,
) -> Memory {
    let now = "2026-07-20T00:00:00Z".to_string();
    let mut mem = Memory {
        id: id.into(),
        namespace: "portability".into(),
        title: "deployment runbook".into(),
        content: content.into(),
        source: "system".into(),
        created_at: now.clone(),
        updated_at: now,
        expires_at: Some("2099-01-01T00:00:00Z".into()),
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": AUTHOR }),
        ..Memory::default()
    };
    let sig = attest::sign_memory_write(kp, &mem, AUTHOR).expect("sign");
    attest::persist_write_signature(&mut mem, &sig);
    mem
}

fn envelope_with(memories: Vec<Memory>) -> ExportEnvelope {
    let count = memories.len();
    ExportEnvelope {
        spec_version: SPEC_VERSION_V2.to_string(),
        // 0 <= any migrated destination schema, so the fail-closed
        // newer-producer gate never fires for this hand-built bundle.
        db_schema_version: 0,
        source: "issue-2353-test".into(),
        exported_at: "2026-07-20T00:00:00Z".into(),
        memories,
        links: Vec::new(),
        signed_events: Vec::new(),
        memory_revisions: Vec::new(),
        forget_tombstones: Vec::new(),
        agent_lineage: Vec::new(),
        model_attestations: Vec::new(),
        governance_rules: Vec::new(),
        trust_anchors: Vec::new(),
        archived_memories: Vec::new(),
        namespace_meta: Vec::new(),
        archived_memory_links: Vec::new(),
        portability_complete: false,
        conformance_level: "L1".into(),
        conformance_by_class: BTreeMap::new(),
        count,
    }
}

/// Destination with the bundle author's Ed25519 key ENROLLED, so a valid
/// presented signature is verifiable (the precondition of the pre-fix
/// false-`agent_attested` defect).
fn dest_with_enrolled_author() -> (Connection, ai_memory::identity::keypair::AgentKeypair) {
    let conn = fresh_db("dest");
    ai_memory::db::register_agent(&conn, AUTHOR, "ai:generic", &[]).expect("register");
    let kp = ai_memory::identity::keypair::generate(AUTHOR).expect("keypair");
    ai_memory::db::bind_agent_pubkey(&conn, AUTHOR, &kp.public_base64()).expect("bind");
    (conn, kp)
}

fn trust_source_opts() -> ImportOptions {
    ImportOptions {
        trust_source: true,
        caller_agent_id: "ai:importer".into(),
        ..ImportOptions::default()
    }
}

/// #2353 — a bundle row signed over RAW secret-bearing bytes, imported by a
/// `redact`-mode destination with the author's key enrolled, must land with
/// REDACTED content and must NOT be labeled `agent_attested` (pre-fix it
/// was: the raw signature verified, the stamp landed, and only THEN did the
/// storage funnel redact the persisted bytes).
#[test]
fn import_redacts_before_attestation_so_raw_signed_secret_lands_claimed_2353() {
    set_screen_mode(SecretScreenMode::Redact);
    let (conn, kp) = dest_with_enrolled_author();
    let mem = signed_bundle_memory(
        "mem-2353-secret",
        &format!("deploy with {SECRET_TOKEN} then restart"),
        &kp,
    );
    let report = import_full_envelope(&conn, &envelope_with(vec![mem]), &trust_source_opts())
        .expect("import");
    assert_eq!(
        report.memories, 1,
        "the row must land (never a forged-skip)"
    );

    let landed = ai_memory::db::get(&conn, "mem-2353-secret")
        .expect("get")
        .expect("row present");
    assert!(
        !landed.content.contains(SECRET_TOKEN),
        "persisted content must be redacted"
    );
    assert!(
        landed.metadata.get(WRITE_SIGNATURE).is_none(),
        "the stale raw-bytes write_signature must not persist"
    );
    let attest_level = landed
        .metadata
        .get("attest_level")
        .and_then(serde_json::Value::as_str);
    assert_ne!(
        attest_level,
        Some("agent_attested"),
        "a redacted row must NOT carry agent_attested over bytes the \
         signature does not cover (got {attest_level:?})"
    );
}

/// Control proving the enrollment + verification plumbing is live (so the
/// test above is load-bearing): a CLEAN signed bundle row imports as
/// `agent_attested` under the same destination + options.
#[test]
fn import_clean_signed_row_still_lands_agent_attested_2353() {
    set_screen_mode(SecretScreenMode::Redact);
    let (conn, kp) = dest_with_enrolled_author();
    let mem = signed_bundle_memory(
        "mem-2353-clean",
        "scale the deployment to three replicas",
        &kp,
    );
    let report = import_full_envelope(&conn, &envelope_with(vec![mem]), &trust_source_opts())
        .expect("import");
    assert_eq!(report.memories, 1);

    let landed = ai_memory::db::get(&conn, "mem-2353-clean")
        .expect("get")
        .expect("row present");
    assert_eq!(
        landed
            .metadata
            .get("attest_level")
            .and_then(serde_json::Value::as_str),
        Some("agent_attested"),
        "clean signed traffic must keep verifying to agent_attested"
    );
    // The retained signature still covers the persisted bytes.
    let sig_b64 = landed
        .metadata
        .get(WRITE_SIGNATURE)
        .and_then(serde_json::Value::as_str)
        .expect("signature retained");
    base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .expect("valid base64 signature");
}
