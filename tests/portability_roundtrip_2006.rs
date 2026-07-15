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

use std::path::PathBuf;

use ai_memory::governance::rules_store::{self, Rule};
use ai_memory::portability::{emit, import, read};
use ai_memory::revisions::{RecordKind, RevisionLeaf, append_revision_leaf};
use ai_memory::signed_events::{
    SignedEvent, append_signed_event, list_signed_events, payload_hash,
};
use ai_memory::storage::model_attest;
use rusqlite::{Connection, params};

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
    let report = import::import_full_envelope(&dst, &parsed).expect("import");

    // Every signed class landed.
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
