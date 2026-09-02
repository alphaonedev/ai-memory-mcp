// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3150 — the Portability-v2 `archived_memories[]` import lane must run the
//! SAME three admission gates as the live `memories[]` lane.
//!
//! ## The defect this pins closed
//!
//! The live lane ran `redact_inbound_before_attestation` (#2353),
//! `apply_import_attestation` (pre-ship 3x7 HIGH-1 — "NEVER trust wire
//! attestation") and `validate::validate_memory` (HIGH-2). The archived lane
//! went DTO → liveness probe → `seal_content` → raw INSERT, justified only by
//! an in-code comment ("an archived row was already vetted when originally
//! stored") — i.e. it trusted the PRODUCER, while the importer's own threat
//! model declares bundles "UNAUTHENTICATED input … earns no implicit trust
//! (fail-closed, #2211)". A crafted bundle could land a forged
//! `attest_level=agent_attested` plus oversized / secret-bearing content
//! through `archived_memories[]` that the SAME row was refused or downgraded
//! for through `memories[]`.
//!
//! These tests mirror the live-lane gate tests
//! (`forged_wire_attest_level_lands_claimed_preship_3x7`,
//! `forged_write_signature_is_skipped_preship_3x7`,
//! `invalid_rows_are_refused_not_persisted_preship_3x7` in
//! `src/portability/import.rs`) against the archived lane.
//!
//! Own test binary because the credential-screen mode is a process-global
//! `OnceLock` (`set_screen_mode`, first-writer-wins): this suite seeds it to
//! `Refuse` — the COMPILED default a real daemon/CLI boot resolves to, and
//! the posture the L1-parity `validate_memory` secret screen is active under.
//! Unseeded (a raw library embedder) it reads `Off`, so the seeding has to be
//! explicit here.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ai_memory::models::{Memory, MemoryKind, Tier, field_names};
use ai_memory::portability::dto::ArchivedMemoryDto;
use ai_memory::portability::emit::{ExportEnvelope, SPEC_VERSION_V2};
use ai_memory::portability::import::{ImportOptions, import_full_envelope};
use ai_memory::secret_screen::{SecretScreenMode, set_screen_mode};
use rusqlite::Connection;

/// A GitHub PAT the credential detector reliably flags (the same fixture
/// `tests/portability_import_redact_attest_2353.rs` uses).
const SECRET_TOKEN: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
const AUTHOR: &str = "ai:archived-author-3150";
const CALLER: &str = "ai:importer-3150";

fn fresh_db(tag: &str) -> Connection {
    // Seed the process-global screen mode on EVERY entry point of this binary
    // so the posture is the same whichever test the harness runs first
    // (`set_screen_mode` is idempotent, first-writer-wins).
    set_screen_mode(SecretScreenMode::Refuse);
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-3150-archived-gates");
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

fn archived_memory(id: &str, content: &str) -> Memory {
    let now = "2026-07-20T00:00:00+00:00".to_string();
    Memory {
        id: id.into(),
        tier: Tier::Long,
        namespace: "portability".into(),
        title: format!("archived snapshot {id}"),
        content: content.into(),
        source: "system".into(),
        priority: 5,
        confidence: 1.0,
        created_at: now.clone(),
        updated_at: now,
        memory_kind: MemoryKind::Observation,
        metadata: serde_json::json!({ "agent_id": AUTHOR }),
        version: 1,
        ..Memory::default()
    }
}

fn archived_dto(mem: Memory) -> ArchivedMemoryDto {
    ArchivedMemoryDto {
        memory: mem,
        archived_at: "2026-07-21T00:00:00+00:00".into(),
        archive_reason: "ttl_expired".into(),
        original_tier: None,
        original_expires_at: None,
        embedding: None,
        embedding_dim: None,
        embedding_space: None,
        atomised_into: None,
        atom_of: None,
        mentioned_entity_id: None,
        kind_provenance: None,
    }
}

fn envelope_with_archived(rows: Vec<ArchivedMemoryDto>) -> ExportEnvelope {
    ExportEnvelope {
        spec_version: SPEC_VERSION_V2.to_string(),
        // 0 <= any migrated destination schema, so the fail-closed
        // newer-producer gate never fires for this hand-built bundle.
        db_schema_version: 0,
        source: "issue-3150-test".into(),
        exported_at: "2026-07-21T00:00:00+00:00".into(),
        memories: Vec::new(),
        links: Vec::new(),
        signed_events: Vec::new(),
        memory_revisions: Vec::new(),
        forget_tombstones: Vec::new(),
        agent_lineage: Vec::new(),
        model_attestations: Vec::new(),
        governance_rules: Vec::new(),
        trust_anchors: Vec::new(),
        archived_memories: rows,
        namespace_meta: Vec::new(),
        archived_memory_links: Vec::new(),
        portability_complete: false,
        conformance_level: "L1".into(),
        conformance_by_class: BTreeMap::new(),
        count: 0,
    }
}

fn opts_trusted() -> ImportOptions {
    ImportOptions {
        trust_source: true,
        caller_agent_id: CALLER.into(),
        ..ImportOptions::default()
    }
}

fn opts_default() -> ImportOptions {
    ImportOptions {
        trust_source: false,
        caller_agent_id: CALLER.into(),
        ..ImportOptions::default()
    }
}

fn archived_metadata(conn: &Connection, id: &str) -> Option<serde_json::Value> {
    conn.query_row(
        "SELECT metadata FROM archived_memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get::<_, String>(0),
    )
    .ok()
    .and_then(|s| serde_json::from_str(&s).ok())
}

fn archived_row_count(conn: &Connection, id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM archived_memories WHERE id = ?1",
        rusqlite::params![id],
        |r| r.get(0),
    )
    .expect("count archived rows")
}

/// ★ #3150 (HIGH-1 twin): a bundle archived row asserting
/// `attest_level=agent_attested` that the destination cannot verify lands
/// `claimed` and is COUNTED as a downgrade — under BOTH postures. Fails on
/// pre-fix code, which persisted the wire claim verbatim.
#[test]
fn archived_forged_attest_level_lands_claimed_3150() {
    let mut mem = archived_memory("arch-attest-3150", "durable archived text");
    mem.metadata.as_object_mut().expect("object").insert(
        field_names::ATTEST_LEVEL.to_string(),
        serde_json::json!("agent_attested"),
    );
    let env = envelope_with_archived(vec![archived_dto(mem)]);

    // Trusted posture (identity preserved): still re-derived, never copied.
    let dst = fresh_db("attest-trusted-");
    let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
    assert_eq!(report.archived_memories, 1, "the row still lands");
    assert_eq!(
        report.attestation_downgraded, 1,
        "the archived-lane downgrade is counted"
    );
    let meta = archived_metadata(&dst, "arch-attest-3150").expect("row landed");
    assert_eq!(
        meta.get(field_names::ATTEST_LEVEL).and_then(|v| v.as_str()),
        Some("claimed"),
        "a wire agent_attested claim MUST land claimed on the archived lane too"
    );

    // Default restamp posture: re-attributed ⇒ claimed as well.
    let dst2 = fresh_db("attest-default-");
    let report2 = import_full_envelope(&dst2, &env, &opts_default()).expect("import");
    assert_eq!(report2.attestation_downgraded, 1);
    let meta2 = archived_metadata(&dst2, "arch-attest-3150").expect("row landed");
    assert_eq!(
        meta2
            .get(field_names::ATTEST_LEVEL)
            .and_then(|v| v.as_str()),
        Some("claimed")
    );
}

/// ★ #3150 (HIGH-1 twin, #1464 invariant): a PRESENTED but FORGED
/// `write_signature` SKIPS the archived row — never downgraded to `claimed`,
/// never persisted. Fails on pre-fix code (the forged signature persisted
/// verbatim).
#[test]
fn archived_forged_write_signature_is_skipped_3150() {
    use base64::Engine as _;

    let dst = fresh_db("forged-sig-");
    ai_memory::db::register_agent(&dst, AUTHOR, "ai:generic", &[]).expect("register");
    let kp = ai_memory::identity::keypair::generate(AUTHOR).expect("keypair");
    ai_memory::db::bind_agent_pubkey_with_keypair(&dst, AUTHOR, &kp).expect("bind");

    let mut mem = archived_memory("arch-forged-3150", "durable archived text");
    let obj = mem.metadata.as_object_mut().expect("object");
    obj.insert(
        field_names::ATTEST_LEVEL.to_string(),
        serde_json::json!("agent_attested"),
    );
    obj.insert(
        field_names::WRITE_SIGNATURE.to_string(),
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode([0xABu8; 64])),
    );
    let env = envelope_with_archived(vec![archived_dto(mem)]);

    // `trust_source` keeps the claimed author, so the presented signature is
    // actually VERIFIED against the enrolled key (the re-attribution rule
    // would otherwise short-circuit to `claimed`).
    let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
    assert_eq!(
        report.forged_signature_skipped, 1,
        "the forged archived row is counted as skipped"
    );
    assert_eq!(report.archived_memories, 0, "no archived row was staged");
    assert_eq!(
        archived_row_count(&dst, "arch-forged-3150"),
        0,
        "a presented-but-forged signature must never launder into the archive"
    );
}

/// ★ #3150 (HIGH-2 twin): the archived lane now runs the SAME two content
/// gates the live `memories[]` lane runs, in the SAME order, so a bundle can
/// no longer launder past them by routing a row through `archived_memories[]`:
///
/// 1. `redact_inbound_before_attestation` (#2353) — under any non-`off`
///    screen mode credential material in the bundle row is MASKED before the
///    row is sealed and inserted. Pre-fix a PAT in an archived snapshot
///    landed VERBATIM in a cleartext-indexed column.
/// 2. `validate::validate_memory` (L1 parity) — an oversize row is refused
///    per-row (skip + WARN + counted) and the REST of the bundle still lands.
///
/// Both assertions fail on pre-fix code, which ran neither gate on this lane.
#[test]
fn archived_secret_is_redacted_and_oversize_is_refused_3150() {
    let secret_row = archived_memory(
        "arch-secret-3150",
        &format!("deployment runbook token {SECRET_TOKEN}"),
    );
    let oversize_row = archived_memory(
        "arch-oversize-3150",
        &"x".repeat(ai_memory::models::MAX_CONTENT_SIZE + 1),
    );
    let good_row = archived_memory("arch-good-3150", "an ordinary archived snapshot");
    let env = envelope_with_archived(vec![
        archived_dto(secret_row),
        archived_dto(oversize_row),
        archived_dto(good_row),
    ]);

    let dst = fresh_db("validate-");
    let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");

    // Gate 2 — the oversize row is the only REFUSAL, and it is accounted for.
    assert_eq!(
        report.invalid_skipped, 1,
        "the oversize archived row is refused and counted: {:?}",
        report.warnings
    );
    assert_eq!(archived_row_count(&dst, "arch-oversize-3150"), 0);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("archived memory arch-oversize-3150")),
        "the refusal carries a WARN naming the archived row, got: {:?}",
        report.warnings
    );

    // A per-row skip must never drop the rest of the bundle.
    assert_eq!(report.archived_memories, 2, "the other two rows landed");
    assert_eq!(archived_row_count(&dst, "arch-good-3150"), 1);

    // Gate 1 — the secret-bearing row LANDS (the screen never refuses; it
    // masks, preserving capture-first) but the RAW credential is gone from the
    // durable archive. Read back through the decrypting mapper, because the
    // insert re-seals content against the destination's at-rest policy.
    let landed = ai_memory::portability::read::read_archived_memory(&dst, "arch-secret-3150")
        .expect("read archived row")
        .expect("the redacted row landed");
    assert!(
        !landed.memory.content.contains(SECRET_TOKEN),
        "the raw credential must never reach the archive, got: {}",
        landed.memory.content
    );
}

/// ★ #3150: under the DEFAULT (non-`--trust-source`) posture an archived
/// row's `metadata.agent_id` is RESTAMPED with the caller's id, exactly like
/// the live lane. This matters because
/// `storage::restore_archived_for_caller` gates ownership on that very field
/// — pre-fix a bundle chose who could promote its archived rows back to LIVE.
#[test]
fn archived_identity_is_restamped_by_default_3150() {
    let env = envelope_with_archived(vec![archived_dto(archived_memory(
        "arch-restamp-3150",
        "durable archived text",
    ))]);

    let dst = fresh_db("restamp-");
    let report = import_full_envelope(&dst, &env, &opts_default()).expect("import");
    assert_eq!(report.archived_memories, 1);
    assert_eq!(report.restamped, 1, "the archived restamp is counted");
    let meta = archived_metadata(&dst, "arch-restamp-3150").expect("row landed");
    assert_eq!(
        meta.get("agent_id").and_then(|v| v.as_str()),
        Some(CALLER),
        "the archived row is attributed to the importing caller"
    );
    assert_eq!(
        meta.get(field_names::IMPORTED_FROM_AGENT_ID)
            .and_then(|v| v.as_str()),
        Some(AUTHOR),
        "the original claim is preserved, never destroyed"
    );

    // Control: `--trust-source` preserves the claimed author verbatim.
    let dst2 = fresh_db("restamp-trusted-");
    let report2 = import_full_envelope(&dst2, &env, &opts_trusted()).expect("import");
    assert_eq!(report2.restamped, 0);
    let meta2 = archived_metadata(&dst2, "arch-restamp-3150").expect("row landed");
    assert_eq!(meta2.get("agent_id").and_then(|v| v.as_str()), Some(AUTHOR));
}
