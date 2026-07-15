// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2006 — the symmetric Portability-v2 importer (spec §V2-1 L2/L3).
//!
//! Re-inserts every class from an [`ExportEnvelope`] and re-verifies the signed
//! spine at the destination. The load-bearing L2 rule: the importer NEVER
//! re-signs — it preserves the original signed bytes so the V-4 chain + every
//! per-row signature still verify. That forces RAW inserts for `signed_events`
//! and `memory_revisions` (their `append_*` helpers RECOMPUTE `prev_hash` +
//! `sequence`, which would rewrite the signed pre-image); the other classes'
//! insert helpers preserve their bytes.
//!
//! Ordering is deliberate (spec §V2-5a + the #2006 vote's lineage finding):
//! 1. `forget_tombstones` FIRST — tombstone-before-admit, so a forgotten row
//!    can never resurrect through the memory insert;
//! 2. `memories` (tombstoned ids skipped) + `links`;
//! 3. `signed_events` before `agent_lineage` — `verify_lineage` reconciles
//!    against a witness set drawn from the audit chain, so the chain must land
//!    first;
//! 4. `governance_rules` verify-or-drop (an unverifiable operator signature is
//!    dropped with a WARN, never silently imported);
//! 5. `trust_anchors` are ADVISORY — recorded in the report, never adopted as a
//!    trust root (the destination K1-pins its own out-of-band keys).

use std::collections::HashSet;

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::Serialize;

use crate::portability::emit::ExportEnvelope;

/// Per-class outcome of an integrity import.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ImportReport {
    pub memories: usize,
    pub links: usize,
    pub signed_events: usize,
    pub memory_revisions: usize,
    pub forget_tombstones: usize,
    pub agent_lineage: usize,
    pub model_attestations: usize,
    pub governance_rules: usize,
    /// Governance rules dropped because their operator signature did not
    /// verify against the enrolled operator key.
    pub governance_rejected: usize,
    /// Trust anchors seen in the envelope (advisory — never adopted).
    pub trust_anchors_seen: usize,
    /// Memory rows skipped because a tombstone forbade re-admission.
    pub tombstoned_skipped: usize,
    /// `true` when the post-import audit chain re-verifies (internally sound:
    /// chain-linked, no gaps, no detected truncation).
    pub reverify_chain_ok: bool,
    /// Human-readable non-fatal warnings (dropped rules, lineage re-verify
    /// failures, per-row insert errors).
    pub warnings: Vec<String>,
}

/// Import the full v2 envelope into `conn`. Returns a per-class [`ImportReport`].
///
/// Idempotent at the row level (every raw insert is `INSERT OR IGNORE` on the
/// primary key), so re-importing the same envelope is a no-op. Never re-signs;
/// preserves every signed byte.
///
/// # Errors
/// A fatal DB error (a non-`OR IGNORE` failure). Per-row problems (a dropped
/// governance rule, a lineage re-verify failure) are collected as warnings, not
/// errors — one bad row never aborts the import.
pub fn import_full_envelope(conn: &Connection, env: &ExportEnvelope) -> Result<ImportReport> {
    let mut report = ImportReport::default();

    // (1) forget_tombstones FIRST — tombstone-before-admit.
    let mut tombstoned: HashSet<String> = HashSet::new();
    for t in &env.forget_tombstones {
        conn.execute(
            "INSERT OR IGNORE INTO forget_tombstones \
                (memory_id, namespace, forgotten_at, agent_id, signature) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                t.memory_id,
                t.namespace,
                t.forgotten_at,
                t.agent_id,
                t.signature
            ],
        )?;
        tombstoned.insert(t.memory_id.clone());
        report.forget_tombstones += 1;
    }

    // (2) memories (skip tombstoned) + links.
    for mem in &env.memories {
        if tombstoned.contains(&mem.id) {
            report.tombstoned_skipped += 1;
            continue;
        }
        match crate::storage::insert_with_conflict(conn, mem, crate::db::ConflictMode::Version) {
            Ok(_) => report.memories += 1,
            Err(e) => report.warnings.push(format!("memory {}: {e}", mem.id)),
        }
    }
    for link in &env.links {
        match crate::storage::create_link(
            conn,
            &link.source_id,
            &link.target_id,
            link.relation.as_str(),
        ) {
            Ok(()) => report.links += 1,
            Err(e) => report
                .warnings
                .push(format!("link {}->{}: {e}", link.source_id, link.target_id)),
        }
    }

    // (3) signed_events — RAW insert (byte-preserve prev_hash/sequence/cause_hash).
    for dto in &env.signed_events {
        let ev: crate::signed_events::SignedEvent = dto.clone().into();
        conn.execute(
            "INSERT OR IGNORE INTO signed_events \
                (id, agent_id, event_type, payload_hash, signature, attest_level, \
                 timestamp, prev_hash, sequence, cause_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                ev.id,
                ev.agent_id,
                ev.event_type,
                ev.payload_hash,
                ev.signature,
                ev.attest_level,
                ev.timestamp,
                ev.prev_hash,
                ev.sequence,
                ev.cause_hash,
            ],
        )?;
        report.signed_events += 1;
    }

    // (4) memory_revisions — RAW insert (byte-preserve prev_hash/sequence).
    for dto in &env.memory_revisions {
        let row = match dto.clone().try_into_domain() {
            Ok(r) => r,
            Err(e) => {
                report.warnings.push(format!("revision {}: {e}", dto.id));
                continue;
            }
        };
        conn.execute(
            "INSERT OR IGNORE INTO memory_revisions \
                (id, memory_id, kind, prior_version, namespace, agent_id, created_at, \
                 signature, prev_hash, sequence) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                row.leaf.id,
                row.leaf.memory_id,
                row.leaf.kind.as_str(),
                row.leaf.prior_version,
                row.leaf.namespace,
                row.leaf.agent_id,
                row.leaf.created_at,
                row.leaf.signature,
                row.prev_hash,
                row.sequence,
            ],
        )?;
        report.memory_revisions += 1;
    }

    // (5) agent_lineage — after signed_events (witness-set coupling).
    // `append_lineage_record` preserves prev_record_hash + signature and
    // RE-VERIFIES the succession chain; a re-verify failure is a warning.
    for dto in &env.agent_lineage {
        let export = match dto.clone().try_into_domain() {
            Ok(e) => e,
            Err(e) => {
                report
                    .warnings
                    .push(format!("lineage {}: {e}", dto.agent_id));
                continue;
            }
        };
        match crate::storage::append_lineage_record(
            conn,
            &export.agent_id,
            &export.record,
            &export.signature,
        ) {
            Ok(()) => report.agent_lineage += 1,
            Err(e) => report.warnings.push(format!(
                "lineage {} epoch {}: {e}",
                export.agent_id, export.record.epoch
            )),
        }
    }

    // (6) model_attestations — RAW insert (write-once TOFU; preserve verbatim).
    for dto in &env.model_attestations {
        let m: crate::storage::model_attest::ModelAttestation = dto.clone().into();
        conn.execute(
            "INSERT OR IGNORE INTO model_attestations \
                (id, provider, model_ref, model_digest, model_family, attest_level, \
                 agent_id, signature, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                m.id,
                m.provider,
                m.model_ref,
                m.model_digest,
                m.model_family,
                m.attest_level,
                m.agent_id,
                m.signature,
                m.created_at,
            ],
        )?;
        report.model_attestations += 1;
    }

    // (7) governance_rules — verify-or-drop (L3).
    let operator_pubkey = crate::governance::rules_store::resolve_operator_pubkey();
    for dto in &env.governance_rules {
        let rule: crate::governance::rules_store::Rule = dto.clone().into();
        // Verify the operator signature when the rule is signed AND an operator
        // key is enrolled; an unverifiable signed rule is DROPPED with a WARN.
        if rule.signature.is_some() {
            if let Some(pk) = operator_pubkey.as_ref() {
                if crate::governance::rules_store::verify_rule_signature(&rule, pk).is_err() {
                    report.governance_rejected += 1;
                    report.warnings.push(format!(
                        "governance rule {} dropped: operator signature invalid",
                        rule.id
                    ));
                    continue;
                }
            }
        }
        match crate::governance::rules_store::insert(conn, &rule) {
            Ok(()) => report.governance_rules += 1,
            Err(e) => report
                .warnings
                .push(format!("governance rule {}: {e}", rule.id)),
        }
    }

    // (8) trust_anchors — ADVISORY only. Recorded, never adopted (the
    // destination K1-pins its OWN out-of-band enrolled keys).
    report.trust_anchors_seen = env.trust_anchors.len();

    // (9) re-verify the imported audit chain (internally sound?).
    let audit = crate::signed_events::verify_audit_trail(conn, None)?;
    report.reverify_chain_ok = audit.chain_intact
        && audit.sequence_gaps.is_empty()
        && !matches!(
            audit.truncation,
            crate::signed_events::TruncationCheck::Detected { .. }
        );

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portability::emit::build_full_envelope;
    use crate::signed_events::{
        SignedEvent, append_signed_event, list_signed_events, payload_hash,
    };

    fn fresh_conn(tag: &str) -> Connection {
        let root = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(".local-runs")
            .join("issue-2006-import");
        std::fs::create_dir_all(&root).ok();
        let dir = tempfile::Builder::new()
            .prefix(tag)
            .tempdir_in(&root)
            .expect("tempdir");
        let path = dir.path().join("db.sqlite");
        drop(crate::db::open(&path).expect("init"));
        std::mem::forget(dir);
        crate::db::open(&path).expect("open")
    }

    fn append_row(conn: &Connection, i: usize) {
        let ev = SignedEvent {
            id: format!("evt-{i}"),
            agent_id: "alice".into(),
            event_type: "memory_link.created".into(),
            payload_hash: payload_hash(format!("p{i}").as_bytes()),
            attest_level: "unsigned".into(),
            timestamp: "2026-07-14T00:00:00Z".into(),
            ..SignedEvent::default()
        };
        append_signed_event(conn, &ev).expect("append");
    }

    #[test]
    fn signed_events_round_trip_byte_exact_and_reverify() {
        // Source DB with a real audit chain.
        let src = fresh_conn("src-");
        for i in 0..5 {
            append_row(&src, i);
        }
        let src_rows = list_signed_events(&src, None, usize::MAX, 0).expect("src rows");
        let env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        assert_eq!(env.signed_events.len(), 5);

        // Import into a FRESH DB.
        let dst = fresh_conn("dst-");
        let report = import_full_envelope(&dst, &env).expect("import");
        assert_eq!(report.signed_events, 5);

        // Byte-exact: every signed_events row survives with identical bytes
        // (prev_hash / payload_hash / sequence / cause_hash), so the chain
        // re-verifies at the destination.
        let dst_rows = list_signed_events(&dst, None, usize::MAX, 0).expect("dst rows");
        assert_eq!(dst_rows.len(), src_rows.len());
        for (a, b) in src_rows.iter().zip(dst_rows.iter()) {
            assert_eq!(a.id, b.id);
            assert_eq!(
                a.payload_hash, b.payload_hash,
                "payload_hash byte-preserved"
            );
            assert_eq!(a.prev_hash, b.prev_hash, "prev_hash byte-preserved");
            assert_eq!(a.sequence, b.sequence, "sequence preserved");
            assert_eq!(a.signature, b.signature);
            assert_eq!(a.cause_hash, b.cause_hash);
        }
        assert!(report.reverify_chain_ok, "imported chain re-verifies");
    }

    #[test]
    fn import_is_idempotent() {
        let src = fresh_conn("idem-src-");
        for i in 0..3 {
            append_row(&src, i);
        }
        let env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        let dst = fresh_conn("idem-dst-");
        let first = import_full_envelope(&dst, &env).expect("import 1");
        let second = import_full_envelope(&dst, &env).expect("import 2");
        // Re-import inserts nothing new (INSERT OR IGNORE on the PK) but still
        // reports the class as present + the chain still re-verifies.
        assert_eq!(first.signed_events, 3);
        assert_eq!(second.signed_events, 3);
        let rows = list_signed_events(&dst, None, usize::MAX, 0).expect("rows");
        assert_eq!(rows.len(), 3, "no duplicate rows on re-import");
        assert!(second.reverify_chain_ok);
    }
}
