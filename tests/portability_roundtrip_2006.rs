// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2006 (Portability-v2, vote 34bbf781) — end-to-end integrity
//! round-trip: build a source DB carrying every signed record class, export the
//! full v2 envelope, serialize it through JSON, import into a FRESH destination,
//! and assert each class round-tripped BYTE-EXACT + the audit chain re-verifies.
//!
//! This is the L2 conformance proof the spec (§V2-6) requires: the signed
//! classes cross the envelope with signatures byte-preserved and re-verifiable,
//! and the importer never re-signs.

#![allow(clippy::missing_panics_doc)]
// The `src_*` / `dst_*` binding pairs (src_ev/dst_ev, src_rev/dst_rev, …) are a
// deliberate source-vs-destination naming convention across the round-trip
// assertions; the pedantic `similar_names` lint is noise here.
#![allow(clippy::similar_names)]

use std::path::PathBuf;

use ai_memory::governance::rules_store::{self, Rule};
use ai_memory::models::{Memory, MemoryKind};
use ai_memory::portability::{emit, import, read};
use ai_memory::revisions::{RecordKind, RevisionLeaf, append_revision_leaf};
use ai_memory::signed_events::{
    SignedEvent, append_signed_event, list_signed_events, payload_hash,
};
use ai_memory::storage::model_attest;
use rusqlite::{Connection, params};

/// The id of the durable memory `seed_all_classes` plants.
const SEED_MEMORY_ID: &str = "mem-round-1";

/// Build a fully-populated durable memory (the source-of-truth TEXT lane).
fn durable_memory() -> Memory {
    let now = "2026-07-14T00:00:00Z".to_string();
    Memory {
        id: SEED_MEMORY_ID.into(),
        namespace: "portability".into(),
        title: "durable title".into(),
        content: "the durable source-of-truth text that must round-trip losslessly".into(),
        tags: vec!["alpha".into(), "beta".into()],
        priority: 7,
        confidence: 0.9,
        // Pre-ship 3x7 HIGH-2: must be a `validate::VALID_SOURCES` member —
        // the v2 importer now runs the L1-parity `validate_memory` gate,
        // and the historical `"test"` value was only importable because
        // the v2 route ran zero validation.
        source: "system".into(),
        created_at: now.clone(),
        updated_at: now,
        memory_kind: MemoryKind::Decision,
        metadata: serde_json::json!({ "agent_id": "alice" }),
        // #1834/#2204 — claim-bitemporal VALID-time bounds are part of the
        // durable truth and must round-trip losslessly through the envelope.
        valid_from: Some("2026-01-01T00:00:00Z".into()),
        valid_until: Some("2027-01-01T00:00:00Z".into()),
        ..Memory::default()
    }
}

fn fresh_db(tag: &str) -> Connection {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-2006-roundtrip");
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

/// Populate `conn` with a row in every signed class the exporter carries.
fn seed_all_classes(conn: &Connection) {
    // memories — the durable source-of-truth TEXT lane.
    ai_memory::db::insert(conn, &durable_memory()).expect("insert durable memory");
    // signed_events — a real hash-linked chain.
    for i in 0..4 {
        let ev = SignedEvent {
            id: format!("evt-{i}"),
            agent_id: "alice".into(),
            event_type: "memory_link.created".into(),
            payload_hash: payload_hash(format!("p{i}").as_bytes()),
            attest_level: "unsigned".into(),
            timestamp: "2026-07-14T00:00:00Z".into(),
            ..SignedEvent::default()
        };
        append_signed_event(conn, &ev).expect("append signed_event");
    }
    // memory_revisions — an append-only leaf.
    let leaf = RevisionLeaf::new(
        "rev-1",
        "mem-1",
        RecordKind::Supersede,
        Some(1),
        "ns",
        Some("alice".into()),
        "2026-07-14T00:00:00Z",
    );
    append_revision_leaf(conn, &leaf).expect("append revision leaf");
    // forget_tombstones — a signed erasure receipt (raw insert for the fixture).
    conn.execute(
        "INSERT INTO forget_tombstones (memory_id, namespace, forgotten_at, agent_id, signature) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            "mem-forgotten",
            "ns",
            "2026-07-14T00:00:00Z",
            Some("alice"),
            Some(vec![0x11_u8; 64])
        ],
    )
    .expect("insert tombstone");
    // model_attestations — a loader-observed TOFU record.
    model_attest::record_loader_observed(conn, "openrouter", "google/gemma-4-31b", "gemma")
        .expect("model attest");
    // governance_rules — an unsigned rule (no operator key needed to round-trip).
    rules_store::insert(
        conn,
        &Rule {
            id: "R-1".into(),
            kind: "namespace_deny".into(),
            matcher: "secret/*".into(),
            severity: "refuse".into(),
            reason: "no secrets".into(),
            namespace: "*".into(),
            created_by: "op".into(),
            created_at: 1_700_000_000,
            enabled: true,
            signature: None,
            attest_level: "unsigned".into(),
        },
    )
    .expect("insert governance rule");
}

#[test]
fn full_envelope_round_trips_every_signed_class_byte_exact() {
    let src = fresh_db("src-");
    seed_all_classes(&src);

    // Export → serialize through JSON (the real wire form) → deserialize.
    let envelope = emit::build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
    let json = serde_json::to_string(&envelope).expect("serialize envelope");
    let parsed: emit::ExportEnvelope = serde_json::from_str(&json).expect("deserialize envelope");

    // Import into a FRESH destination.
    let dst = fresh_db("dst-");
    // `trust_source: true` is the explicit
    // operator-trusted-backup posture (#2211): the byte-exact identity
    // round-trip below (`agent_id` preserved verbatim) is EARNED by the
    // flag, not granted by default — the default restamps like L1.
    let report = import::import_full_envelope(
        &dst,
        &parsed,
        &import::ImportOptions {
            trust_source: true,
            caller_agent_id: "importer".into(),
            ..import::ImportOptions::default()
        },
    )
    .expect("import");

    // Every class landed.
    assert_eq!(report.memories, 1, "memories count");
    assert!(report.committed, "the fail-closed import committed");
    assert_eq!(report.signed_events, 4, "signed_events count");
    assert_eq!(report.memory_revisions, 1, "memory_revisions count");
    assert_eq!(report.forget_tombstones, 1, "forget_tombstones count");
    assert_eq!(report.model_attestations, 1, "model_attestations count");
    assert_eq!(report.governance_rules, 1, "governance_rules count");
    assert_eq!(report.governance_rejected, 0, "no rule dropped");

    // ── byte-exact per class ──
    let src_ev = list_signed_events(&src, None, usize::MAX, 0).unwrap();
    let dst_ev = list_signed_events(&dst, None, usize::MAX, 0).unwrap();
    assert_eq!(src_ev.len(), dst_ev.len());
    for (a, b) in src_ev.iter().zip(dst_ev.iter()) {
        assert_eq!(a.payload_hash, b.payload_hash, "payload_hash preserved");
        assert_eq!(a.prev_hash, b.prev_hash, "prev_hash preserved");
        assert_eq!(a.sequence, b.sequence, "sequence preserved");
        assert_eq!(a.signature, b.signature, "signature preserved");
        assert_eq!(a.cause_hash, b.cause_hash, "cause_hash preserved");
    }

    let src_rev = read::read_all_memory_revisions(&src).unwrap();
    let dst_rev = read::read_all_memory_revisions(&dst).unwrap();
    assert_eq!(src_rev, dst_rev, "memory_revisions byte-exact");

    let src_tomb = read::read_all_forget_tombstones(&src).unwrap();
    let dst_tomb = read::read_all_forget_tombstones(&dst).unwrap();
    assert_eq!(src_tomb, dst_tomb, "forget_tombstones byte-exact");

    let src_ma = model_attest::list(&src).unwrap();
    let dst_ma = model_attest::list(&dst).unwrap();
    assert_eq!(src_ma, dst_ma, "model_attestations byte-exact");

    let src_rules = rules_store::list(&src).unwrap();
    let dst_rules = rules_store::list(&dst).unwrap();
    assert_eq!(src_rules, dst_rules, "governance_rules byte-exact");

    // ── memory (source-of-truth TEXT) round-trips losslessly ──
    let src_mem = ai_memory::db::get(&src, SEED_MEMORY_ID)
        .unwrap()
        .expect("src memory present");
    let dst_mem = ai_memory::db::get(&dst, SEED_MEMORY_ID)
        .unwrap()
        .expect("dst memory present");
    assert_eq!(dst_mem.title, src_mem.title, "title preserved");
    assert_eq!(dst_mem.content, src_mem.content, "content preserved");
    assert_eq!(dst_mem.namespace, src_mem.namespace, "namespace preserved");
    assert_eq!(dst_mem.tags, src_mem.tags, "tags preserved");
    assert_eq!(dst_mem.priority, src_mem.priority, "priority preserved");
    assert_eq!(dst_mem.memory_kind, src_mem.memory_kind, "kind preserved");
    assert_eq!(
        dst_mem.created_at, src_mem.created_at,
        "created_at preserved"
    );
    assert_eq!(
        dst_mem.metadata["agent_id"], src_mem.metadata["agent_id"],
        "agent_id preserved"
    );
    // #1834/#2204 — the claim-bitemporal VALID-time bounds round-trip (the
    // fixture pins both to Some; a silent drop here would be a durable-truth
    // data-loss of exactly the class the N3 sweep covered).
    assert_eq!(
        dst_mem.valid_from, src_mem.valid_from,
        "valid_from preserved"
    );
    assert!(src_mem.valid_from.is_some(), "fixture carries valid_from");
    assert_eq!(
        dst_mem.valid_until, src_mem.valid_until,
        "valid_until preserved"
    );
    assert!(src_mem.valid_until.is_some(), "fixture carries valid_until");
    // #1825 cid: content-addressed + DETERMINISTICALLY re-derived from the
    // genesis fields on import, so it is byte-identical without being exported.
    assert!(src_mem.cid.is_some(), "source stamped a cid");
    assert_eq!(
        dst_mem.cid, src_mem.cid,
        "cid re-derives byte-identically on import (v85 #1825 composition)"
    );

    // The imported audit chain re-verifies (internally sound).
    assert!(report.reverify_chain_ok, "imported chain re-verifies");
}

#[test]
fn tampering_a_source_signed_event_downgrades_conformance() {
    let src = fresh_db("tamper-");
    seed_all_classes(&src);
    // A clean chain re-verifies → at least L2.
    let clean = emit::build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").unwrap();
    assert!(
        matches!(clean.conformance_level.as_str(), "L2" | "L3"),
        "clean source is >= L2, got {}",
        clean.conformance_level
    );

    // Break the chain with an interior delete → the exporter's computed marker
    // honestly downgrades to L1 (the marker tracks a real re-verify, not a const).
    src.execute("DELETE FROM signed_events WHERE sequence = 2", [])
        .expect("interior delete");
    let broken = emit::build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").unwrap();
    assert_eq!(
        broken.conformance_level, "L1",
        "a broken source chain downgrades the export to L1; by_class={:?}",
        broken.conformance_by_class
    );
    assert!(!broken.portability_complete);
}
