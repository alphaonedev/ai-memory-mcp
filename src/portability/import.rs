// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2006 — the symmetric Portability-v2 importer (spec §V2-1 L2/L3).
//!
//! ## Data-integrity contract (the highest-order constraint)
//!
//! The importer is a BULK WRITE into the source-of-truth memory TEXT, so it is
//! **FAIL-CLOSED and ALL-OR-NOTHING**:
//!
//! - **One transaction.** Every class is applied inside ONE
//!   [`rusqlite::Connection::unchecked_transaction`]. A fatal per-row error (a
//!   malformed DTO, a DB fault) short-circuits via `?`, the [`rusqlite::Transaction`]
//!   drops WITHOUT commit, and SQLite rolls the whole import back — so a rejected
//!   bundle applies **ZERO rows**. There is no partial apply.
//! - **The signed spine is re-verified before commit.** After the rows are
//!   staged in the transaction, [`crate::signed_events::verify_audit_trail`] runs
//!   over the STAGED state. If the imported audit chain is not internally sound
//!   (a broken hash link from a tampered row, a sequence gap from a truncated
//!   bundle, or detected tail-truncation) the transaction is rolled back and the
//!   import is REFUSED with a loud error. A malformed / tampered / truncated
//!   bundle can never land.
//! - **Verbatim, never re-signed.** The signed classes cross byte-preserved and
//!   are RAW-inserted (their `append_*` helpers would recompute
//!   `prev_hash`/`sequence`/`record_bytes` and rewrite the signed pre-image); the
//!   destination re-verify therefore sees the ORIGINAL signatures. This IS the L2
//!   guarantee: the integrity guarantee is verbatim preservation.
//!
//! ## Ordering (spec §V2-5a + the #2006 vote's lineage finding)
//! 1. `forget_tombstones` FIRST — tombstone-before-admit, so a forgotten row
//!    can never resurrect through the memory insert;
//! 2. `memories` (tombstoned ids skipped, id-keyed idempotent) + `links`;
//! 3. `signed_events` (the audit spine) — RAW, byte-preserved;
//! 4. `memory_revisions` — RAW, byte-preserved;
//! 5. `agent_lineage` — RAW, byte-preserved (the record body + its ORIGINAL
//!    signature; `record_bytes` is recomputed byte-identically via the record's
//!    own canonical-CBOR encoder, and the succession WITNESSES ride the
//!    `signed_events` array — so the importer never re-witnesses / re-signs and
//!    never double-anchors). The `metadata.agent_pubkey` binding is NOT
//!    auto-synced on import (advisory, like the trust anchors — the destination
//!    keeps its own enrolled keys);
//! 6. `model_attestations` — RAW, write-once TOFU;
//! 7. `governance_rules` — verify-or-drop (an unverifiable operator signature is
//!    dropped with a WARN + counted, never silently trusted);
//! 8. `trust_anchors` — ADVISORY only, recorded in the report, never adopted as a
//!    trust root (the destination K1-pins its own out-of-band keys).
//!
//! ## v85 schema composition (#1825 cid, #2167 embedding_space, #1834 valid-time)
//! `memories` cross via the screened [`crate::models::Memory`] path, so their
//! DURABLE truth (title/content/tags/namespace/kind/metadata/created_at/…)
//! round-trips losslessly. The v85 columns compose as follows and are NOT a
//! data-loss: the `cid` content-address is content-addressed and
//! DETERMINISTICALLY re-derived by `db::insert` from the genesis fields (which
//! round-trip); `kind_provenance` is re-denormalised from `metadata`;
//! `embedding_space` is a DERIVED-artifact tag on the (unexported, regenerable)
//! embedding vector and is CORRECTLY re-stamped when the destination re-embeds
//! the durable text — carrying the source tag without the vector would falsely
//! label a non-existent vector (a fail-closed violation); the `memories`
//! `valid_from`/`valid_until` v79 columns have no sqlite writer (always NULL).

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::Serialize;

use crate::portability::emit::ExportEnvelope;
use crate::signed_events::TruncationCheck;

/// Per-class outcome of an integrity import.
///
/// A returned `ImportReport` always has `committed == true`: the function
/// returns `Err` (and applies zero rows) on any fail-closed rejection, so a
/// report can only exist for a bundle that fully landed.
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
    /// verify against the enrolled operator key (verify-or-drop, L3).
    pub governance_rejected: usize,
    /// Trust anchors seen in the envelope (advisory — never adopted).
    pub trust_anchors_seen: usize,
    /// Memory rows skipped because a tombstone forbade re-admission.
    pub tombstoned_skipped: usize,
    /// `true` when the imported audit spine re-verified in the transaction.
    pub reverify_chain_ok: bool,
    /// `true` iff the transaction committed (always `true` on the `Ok` path).
    pub committed: bool,
    /// Human-readable non-fatal notes (dropped governance rules).
    pub warnings: Vec<String>,
}

/// Import the full v2 envelope into `conn`, FAIL-CLOSED and ALL-OR-NOTHING.
///
/// Returns a per-class [`ImportReport`] ONLY when the whole bundle landed and
/// the imported signed spine re-verified. Idempotent at the row level (every
/// raw insert is `INSERT OR IGNORE` on the primary key; memories are id-keyed
/// skip-if-present), so re-importing the same envelope is a no-op. Never
/// re-signs; preserves every signed byte.
///
/// # Errors
/// Returns `Err` (and applies ZERO rows — the transaction rolls back) when:
/// - a DTO cannot be reconstructed (a closed-vocabulary slug outside its enum —
///   a malformed / tampered bundle);
/// - a row insert hits a DB fault;
/// - the imported audit spine does not re-verify (a tampered / truncated /
///   malformed bundle) — the fail-closed spine gate.
pub fn import_full_envelope(conn: &Connection, env: &ExportEnvelope) -> Result<ImportReport> {
    // ── ALL-OR-NOTHING: one transaction wraps the entire apply. ──
    // `unchecked_transaction` issues BEGIN DEFERRED on `&Connection`; every
    // helper below is either a raw `execute` or a transaction-free storage
    // primitive (`storage::insert` / `storage::get` open no inner tx), so no
    // nested-transaction hazard arises. On any `?` below the `Transaction`
    // drops here without commit → SQLite ROLLBACK → zero rows applied.
    let tx = conn
        .unchecked_transaction()
        .context("portability import: could not open the atomic import transaction")?;

    let mut report = apply_all_classes(&tx, env)?;

    // ── FAIL-CLOSED spine gate ──
    // Re-verify the STAGED audit spine with the substrate's own authoritative
    // verifier. A tampered interior row breaks the next row's `prev_hash` link;
    // a truncated/removed interior row opens a sequence gap; a detected
    // tail-truncation trips `TruncationCheck::Detected`. Any of these ⇒ REFUSE
    // and roll the whole import back.
    let audit = crate::signed_events::verify_audit_trail(&tx, None)
        .context("portability import: could not re-verify the imported audit spine")?;
    let chain_ok = audit.chain_intact
        && audit.sequence_gaps.is_empty()
        && !matches!(audit.truncation, TruncationCheck::Detected { .. });
    if !chain_ok {
        // The `Transaction` drops on this early return → full ROLLBACK.
        anyhow::bail!(
            "portability import REJECTED (fail-closed): the imported signed audit spine \
             did not re-verify (chain_intact={}, sequence_gaps={}, truncation={:?}) — the \
             bundle is malformed, tampered, or truncated; NO rows were applied",
            audit.chain_intact,
            audit.sequence_gaps.len(),
            audit.truncation
        );
    }
    report.reverify_chain_ok = true;

    tx.commit()
        .context("portability import: transaction commit failed")?;
    report.committed = true;
    Ok(report)
}

/// Stage every class into `conn` (a live transaction). Any `?` here aborts the
/// whole import (the caller's transaction rolls back).
fn apply_all_classes(conn: &Connection, env: &ExportEnvelope) -> Result<ImportReport> {
    let mut report = ImportReport::default();

    // (1) forget_tombstones FIRST — tombstone-before-admit.
    let mut tombstoned: std::collections::HashSet<String> = std::collections::HashSet::new();
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
        )
        .with_context(|| format!("import forget_tombstone for memory {}", t.memory_id))?;
        tombstoned.insert(t.memory_id.clone());
        report.forget_tombstones += 1;
    }

    // (2) memories (tombstoned skipped; id-keyed idempotent) + links.
    for mem in &env.memories {
        if tombstoned.contains(&mem.id) {
            report.tombstoned_skipped += 1;
            continue;
        }
        // Idempotent: skip a memory already present (a re-import is a no-op).
        // Fresh rows go through `storage::insert` (screening + FTS trigger + the
        // deterministic cid re-derivation); it opens no inner transaction.
        if crate::storage::get(conn, &mem.id)
            .with_context(|| format!("import: probing existing memory {}", mem.id))?
            .is_some()
        {
            report.memories += 1;
            continue;
        }
        crate::storage::insert(conn, mem).with_context(|| format!("import memory {}", mem.id))?;
        report.memories += 1;
    }
    for link in &env.links {
        // RAW, byte-preserving (`create_link` would re-derive the signature +
        // attest_level — a loss). `OR IGNORE` is idempotent on the natural key
        // and silently skips an edge whose endpoint memory is absent (e.g. a
        // link to a tombstoned row), so it never spuriously aborts the import.
        let n = conn
            .execute(
                "INSERT OR IGNORE INTO memory_links \
                    (source_id, target_id, relation, created_at, valid_from, valid_until, \
                     observed_by, signature, attest_level) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    link.source_id,
                    link.target_id,
                    link.relation.as_str(),
                    link.created_at,
                    link.valid_from,
                    link.valid_until,
                    link.observed_by,
                    link.signature,
                    link.attest_level,
                ],
            )
            .with_context(|| format!("import link {}->{}", link.source_id, link.target_id))?;
        report.links += n;
    }

    // (3) signed_events — RAW (byte-preserve prev_hash/sequence/cause_hash).
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
        )
        .with_context(|| format!("import signed_event {}", ev.id))?;
        report.signed_events += 1;
    }

    // (4) memory_revisions — RAW (byte-preserve prev_hash/sequence). A DTO that
    // fails to reconstruct (an unknown `kind` slug) is a MALFORMED bundle →
    // fatal (the whole import rolls back), never a silent skip.
    for dto in &env.memory_revisions {
        let row = dto
            .clone()
            .try_into_domain()
            .with_context(|| format!("import memory_revision {}", dto.id))?;
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
        )
        .with_context(|| format!("import memory_revision {}", row.leaf.id))?;
        report.memory_revisions += 1;
    }

    // (5) agent_lineage — RAW, byte-preserved. `record_bytes` (NOT NULL) is
    // recomputed BYTE-IDENTICALLY via the record's own canonical-CBOR encoder;
    // the ORIGINAL detached signature crosses verbatim; the succession
    // witnesses already rode the `signed_events` array (step 3), so the importer
    // NEVER re-witnesses or re-signs. A DTO that fails to reconstruct (an
    // unknown `reason`/`custody_class` slug) is a MALFORMED bundle → fatal.
    for dto in &env.agent_lineage {
        let export = dto
            .clone()
            .try_into_domain()
            .with_context(|| format!("import agent_lineage for {}", dto.agent_id))?;
        let record = &export.record;
        let record_bytes = record
            .canonical_bytes()
            .with_context(|| format!("import: canonicalising lineage for {}", record.agent_id))?;
        conn.execute(
            "INSERT OR IGNORE INTO agent_lineage \
                (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey, \
                 recovery_pubkey, not_before, prev_record_hash, signature, \
                 record_bytes, created_at, custody_class, suspected_compromise_from_seq, \
                 guardian_set_id, recovery_threshold) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                record.agent_id,
                i64::try_from(record.epoch).context("lineage epoch exceeds i64")?,
                record.reason.as_str(),
                record.predecessor_pubkey_b64,
                record.successor_pubkey_b64,
                record.recovery_pubkey_b64,
                record.not_before,
                record.prev_record_hash,
                export.signature,
                record_bytes,
                // `created_at` is an un-verified local stamp (not in the signed
                // body / not exported); anchor it to the record's own
                // `not_before` so the import is deterministic + byte-stable.
                record.not_before,
                record.custody_class.as_str(),
                record
                    .suspected_compromise_from_seq
                    .map(|s| i64::try_from(s).unwrap_or(i64::MAX)),
                record.guardian_set_id.as_deref(),
                record
                    .recovery_threshold
                    .map(|m| i64::try_from(m).unwrap_or(i64::MAX)),
            ],
        )
        .with_context(|| {
            format!(
                "import agent_lineage {} epoch {}",
                record.agent_id, record.epoch
            )
        })?;
        report.agent_lineage += 1;
    }

    // (6) model_attestations — RAW (write-once TOFU; preserve verbatim).
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
        )
        .with_context(|| format!("import model_attestation {}", m.id))?;
        report.model_attestations += 1;
    }

    // (7) governance_rules — verify-or-drop (L3). An operator-signed rule whose
    // signature does not verify against the enrolled operator key is DROPPED
    // (counted + WARN), never silently trusted — this is a deliberate trust
    // decision on advisory policy, not memory-text data-loss. RAW
    // `INSERT OR IGNORE` (not `rules_store::insert`, a plain INSERT) is idempotent
    // on the id PK, so re-importing the substrate's default L1-6 rules that the
    // destination ALSO seeds at `db::open` is a byte-preserving no-op rather than
    // a UNIQUE-constraint abort; the count reflects rows actually added.
    let operator_pubkey = crate::governance::rules_store::resolve_operator_pubkey();
    for dto in &env.governance_rules {
        let rule: crate::governance::rules_store::Rule = dto.clone().into();
        if rule.signature.is_some()
            && let Some(pk) = operator_pubkey.as_ref()
            && crate::governance::rules_store::verify_rule_signature(&rule, pk).is_err()
        {
            report.governance_rejected += 1;
            report.warnings.push(format!(
                "governance rule {} dropped: operator signature did not verify",
                rule.id
            ));
            continue;
        }
        let n = conn
            .execute(
                "INSERT OR IGNORE INTO governance_rules \
                    (id, kind, matcher, severity, reason, namespace, \
                     created_by, created_at, enabled, signature, attest_level) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    rule.id,
                    rule.kind,
                    rule.matcher,
                    rule.severity,
                    rule.reason,
                    rule.namespace,
                    rule.created_by,
                    rule.created_at,
                    rule.enabled,
                    rule.signature,
                    rule.attest_level,
                ],
            )
            .with_context(|| format!("import governance rule {}", rule.id))?;
        report.governance_rules += n;
    }

    // (8) trust_anchors — ADVISORY only. Recorded, never adopted (the
    // destination K1-pins its OWN out-of-band enrolled keys).
    report.trust_anchors_seen = env.trust_anchors.len();

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
        let src = fresh_conn("src-");
        for i in 0..5 {
            append_row(&src, i);
        }
        let src_rows = list_signed_events(&src, None, usize::MAX, 0).expect("src rows");
        let env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        assert_eq!(env.signed_events.len(), 5);

        let dst = fresh_conn("dst-");
        let report = import_full_envelope(&dst, &env).expect("import");
        assert_eq!(report.signed_events, 5);
        assert!(report.committed, "the fail-closed import committed");

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
        assert_eq!(first.signed_events, 3);
        assert_eq!(second.signed_events, 3);
        let rows = list_signed_events(&dst, None, usize::MAX, 0).expect("rows");
        assert_eq!(rows.len(), 3, "no duplicate rows on re-import");
        assert!(second.reverify_chain_ok);
        assert!(second.committed);
    }

    /// ★ FAIL-CLOSED: a TAMPERED bundle (an interior signed_events row whose
    /// bytes were altered) is REJECTED and applies ZERO rows — no partial apply.
    #[test]
    fn tampered_bundle_is_rejected_with_zero_rows_applied() {
        let src = fresh_conn("tamper-src-");
        for i in 0..5 {
            append_row(&src, i);
        }
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        // Tamper an INTERIOR row's payload_hash: the next row's `prev_hash` was
        // computed over the ORIGINAL bytes, so the imported chain no longer links.
        env.signed_events[1].payload_hash = vec![0xba, 0xad];

        let dst = fresh_conn("tamper-dst-");
        let err = import_full_envelope(&dst, &env).expect_err("tampered bundle must be rejected");
        assert!(
            err.to_string().contains("REJECTED"),
            "loud fail-closed error, got: {err}"
        );
        // NO partial apply: the destination is untouched.
        assert!(
            list_signed_events(&dst, None, usize::MAX, 0)
                .expect("rows")
                .is_empty(),
            "a rejected import must leave ZERO rows"
        );
    }

    /// ★ FAIL-CLOSED: a TRUNCATED bundle (an interior signed_events row removed,
    /// opening a sequence gap) is REJECTED and applies ZERO rows.
    #[test]
    fn truncated_bundle_is_rejected_with_zero_rows_applied() {
        let src = fresh_conn("trunc-src-");
        for i in 0..5 {
            append_row(&src, i);
        }
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        // Drop an interior row → the surviving chain has a sequence gap AND a
        // broken hash link.
        env.signed_events.remove(2);

        let dst = fresh_conn("trunc-dst-");
        let err = import_full_envelope(&dst, &env).expect_err("truncated bundle must be rejected");
        assert!(err.to_string().contains("REJECTED"), "got: {err}");
        assert!(
            list_signed_events(&dst, None, usize::MAX, 0)
                .expect("rows")
                .is_empty(),
            "a rejected import must leave ZERO rows"
        );
    }
}
