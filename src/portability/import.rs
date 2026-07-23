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
//!   `BEGIN IMMEDIATE` [`rusqlite::Transaction`]. A fatal per-row error (a
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
//! `valid_from`/`valid_until` v79 claim-bitemporal columns (#1834/#2204) are
//! [`crate::models::Memory`] fields, so they ride the envelope and land through
//! `insert_imported`'s column bindings — a lossless round-trip (pinned by
//! `tests/portability_roundtrip_2006.rs`).

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::Serialize;

use crate::identity::lineage::LineageCheck;
use crate::portability::emit::{ExportEnvelope, SPEC_VERSION_V2};
use crate::signed_events::TruncationCheck;
use crate::storage::ConflictMode;

/// `tracing` target for every importer WARN (the
/// `federation_receive::ATTESTATION_TRACE_TARGET` const precedent —
/// pm-v3.1 no-hardcoded-literals).
const IMPORT_TRACE_TARGET: &str = "portability::import";

/// Caller-supplied dispositions for a v2 integrity import (#2211).
///
/// The v2 route previously ignored `ImportArgs` entirely — always preserving
/// `metadata.agent_id` verbatim and always taking the silent `(title,
/// namespace)` upsert-merge. That silently bypassed the L1
/// restamp-by-default provenance hygiene (one attacker-controlled
/// `spec_version` key flipped the identity posture of the whole import) and
/// could CLOBBER a destination row's content on a title collision. These
/// options replicate the L1 `ImportArgs` semantics on the v2 path.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// Preserve `metadata.agent_id` VERBATIM (the operator explicitly
    /// passed `--trust-source`). Default `false` = restamp with the
    /// caller's id, exactly like the L1 import path.
    ///
    /// Verbatim identity is gated EXCLUSIVELY on this explicit operator
    /// flag — deliberately NOT on "the bundle carries a re-verified
    /// signed_events spine": with no enrolled verifier an UNSIGNED chain
    /// is hash-link-consistent by construction and trivially forgeable,
    /// so an intact spine is NOT identity attestation and earns no
    /// implicit trust (fail-closed, #2211).
    pub trust_source: bool,
    /// The caller identity used to restamp `metadata.agent_id` when
    /// [`Self::trust_source`] is `false` (the L1 restamp parity).
    pub caller_agent_id: String,
    /// Disposition on a `(title, namespace)` collision between an imported
    /// memory and an EXISTING destination row with a DIFFERENT id —
    /// replicating the L1 `--on-conflict` semantics: `Version` (default —
    /// auto-suffix the incoming title, never clobber), `Merge` (legacy
    /// silent upsert-merge), `Error` (refuse + skip the colliding row,
    /// counted + warned, the rest of the bundle continues).
    pub on_conflict: ConflictMode,
}

impl Default for ImportOptions {
    /// The L1-parity secure default: restamp identity, never clobber.
    fn default() -> Self {
        Self {
            trust_source: false,
            caller_agent_id: String::new(),
            on_conflict: ConflictMode::Version,
        }
    }
}

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
    /// Memory rows skipped because a tombstone forbade re-admission —
    /// counting BOTH the bundle's own tombstones AND the DESTINATION's
    /// pre-existing `forget_tombstones` (#2208: a destination-forgotten
    /// memory must never resurrect through an import).
    pub tombstoned_skipped: usize,
    /// Bundle `forget_tombstones` NOT staged because their id is currently
    /// LIVE at the destination (#2208 re-audit N2: an unauthenticated bundle
    /// tombstone must not suppress a live destination row — it would plant a
    /// contradictory live-row+tombstone state and permanently block the id's
    /// future admission; only the destination's own forget funnel erases).
    pub tombstones_skipped_live: usize,
    /// Memory rows skipped because the DESTINATION holds the id in
    /// `archived_memories` (#2208 adjacent: re-admitting it live would
    /// leave the id in BOTH tables; the sanctioned way back to live is
    /// `memory_archive_restore`).
    pub archived_skipped: usize,
    /// Memory rows whose `metadata.agent_id` was restamped with the
    /// caller's id (the L1-parity default; `--trust-source` disables).
    pub restamped: usize,
    /// Memory rows skipped under `--on-conflict error` because their
    /// `(title, namespace)` collided with an existing destination row.
    pub conflicts_skipped: usize,
    /// Memory rows skipped because they failed the L1-parity input
    /// validation ([`crate::validate::validate_memory`]) — size / range /
    /// RFC3339 (incl. the #1834 `valid_from`/`valid_until`) / refuse-mode
    /// secret screen (pre-ship 3x7 HIGH-2; the `cli::io` L1 import has run
    /// this per-row gate since #1780 — the v2 route ran ZERO validation).
    pub invalid_skipped: usize,
    /// Link rows skipped because they failed
    /// [`crate::validate::validate_link`] (id shape / relation / self-link).
    pub invalid_links_skipped: usize,
    /// Link rows skipped because an endpoint memory is ABSENT at insert
    /// time (skipped earlier in this import — tombstoned / archived /
    /// invalid / forged / conflict-refused — or never present at the
    /// destination). `memory_links` carries `REFERENCES memories(id)`
    /// FKs and `db::open` sets `PRAGMA foreign_keys=ON`; SQLite's
    /// `OR IGNORE` conflict resolution does NOT apply to FK constraints,
    /// so without this probe one dangling edge would FK-error and roll
    /// back the WHOLE all-or-nothing transaction (pre-ship 3x7 F1).
    pub links_skipped_missing_endpoint: usize,
    /// Memory rows whose wire-asserted attestation was NOT honoured: the
    /// bundle claimed `attest_level=agent_attested` (or presented a
    /// signature) but the DESTINATION could not verify it (re-attributed
    /// under restamp, no destination-enrolled author key, or no signature),
    /// so the row landed `attest_level=claimed` (pre-ship 3x7 HIGH-1 — the
    /// wire `attest_level` is NEVER trusted).
    pub attestation_downgraded: usize,
    /// Memory rows SKIPPED because they presented a `write_signature` that
    /// FAILED verification against the destination-enrolled author key — a
    /// presented-but-invalid signature is always rejected, never downgraded
    /// to `claimed` (the #1464 invariant; mirrors the federation receive
    /// path's per-row skip disposition).
    pub forged_signature_skipped: usize,
    /// `true` when the imported audit spine re-verified in the transaction.
    pub reverify_chain_ok: bool,
    /// `true` when the staged `memory_revisions` chain replayed cleanly
    /// (contiguous unique sequences, linked `prev_hash`es — #2209).
    pub reverify_revisions_ok: bool,
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
/// - the envelope's `spec_version` is not the supported `"2"`, or its
///   `db_schema_version` is NEWER than the destination's applied schema
///   (#2210 — a newer-producer bundle must refuse loudly, never partially
///   ingest);
/// - a DTO cannot be reconstructed (a closed-vocabulary slug outside its enum —
///   a malformed / tampered bundle);
/// - a row insert hits a DB fault;
/// - the imported audit spine does not re-verify (a tampered / truncated /
///   malformed bundle) — the fail-closed spine gate;
/// - the staged `memory_revisions` chain does not replay (#2209 — a tampered
///   revision row, a duplicate/gapped sequence from merging a foreign chain
///   into a non-empty destination, or a broken `prev_hash` link);
/// - the staged `agent_lineage` succession chains verify as FORGED (#2209 —
///   a tampered lineage record, or a bundle chain that forks the
///   destination's existing key-succession history).
pub fn import_full_envelope(
    conn: &Connection,
    env: &ExportEnvelope,
    opts: &ImportOptions,
) -> Result<ImportReport> {
    // ── FAIL-CLOSED envelope gate (#2210) ──
    // Defense-in-depth twin of the parse-time checks in `cli::io` (this
    // function is the funnel — every caller must be covered).
    if env.spec_version != SPEC_VERSION_V2 {
        anyhow::bail!(
            "portability import REJECTED (fail-closed): unsupported spec_version {:?} — this \
             node understands spec_version {SPEC_VERSION_V2:?}; the bundle was produced by a \
             newer/unknown spec, so importing it here could silently drop signed record \
             classes. Upgrade this node instead; NO rows were applied",
            env.spec_version
        );
    }
    let dest_schema = crate::portability::emit::db_schema_version(conn)
        .context("portability import: could not read the destination's applied schema version")?;
    if env.db_schema_version > dest_schema {
        anyhow::bail!(
            "portability import REJECTED (fail-closed): the bundle was exported from \
             db_schema_version {} but this destination is at {dest_schema} — a newer producer \
             may carry record shapes this node cannot faithfully ingest. Upgrade this node \
             first; NO rows were applied",
            env.db_schema_version
        );
    }
    // ── Pre-ship 3x7 advisory — the explicit-trust posture is LOUD. ──
    // Under `--trust-source` wire identity claims (metadata.agent_id /
    // agent_pubkey) are preserved VERBATIM by design (operator-trusted
    // backup restore), which includes `_agents` registration rows that can
    // ENROLL key material consulted by future write/federation
    // verification (`db::agent_pubkey`). That is the accepted risk of
    // explicit operator trust — never import an untrusted bundle under
    // this flag (see #2264 for the v1-wire-form sibling).
    if opts.trust_source {
        tracing::warn!(
            target: IMPORT_TRACE_TARGET,
            "--trust-source: wire identity claims (metadata.agent_id / agent_pubkey) are \
             preserved VERBATIM — imported _agents registration rows can enroll key material \
             for future verification; accepted risk of explicit operator trust (#2264)"
        );
    }
    // ── ALL-OR-NOTHING: one transaction wraps the entire apply. ──
    // Take the write reservation BEFORE the destination trust snapshot.
    // BEGIN DEFERRED allowed another writer to commit after that snapshot,
    // making verification use a stale/revoked key and the later write upgrade
    // fail with un-retried SQLITE_BUSY_SNAPSHOT (#2250). IMMEDIATE either
    // acquires the reservation before any trust read or returns retriable busy
    // without applying any rows.
    let tx = begin_atomic_import(conn)?;
    // ── Pre-ship 3x7 HIGH-1: snapshot the DESTINATION-enrolled author keys
    // AFTER reserving the writer but BEFORE staging any bundle row. Verifying against a
    // lookup made INSIDE the transaction would let a crafted bundle
    // self-enroll (stage an `_agents` registration row carrying an
    // attacker `agent_pubkey`, then have a later row in the SAME bundle
    // "verify" against it). The snapshot pins verification to the keys the
    // destination trusted at this transaction's serialization point.
    let enrolled_keys = snapshot_dest_enrolled_keys(&tx, env, opts)?;

    let mut report = apply_all_classes(&tx, env, opts, &enrolled_keys)?;

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

    // ── FAIL-CLOSED revisions gate (#2209) ──
    // The `signed_events` gate above covers ONE of the three signed spine
    // classes. `memory_revisions` rows cross RAW with their own
    // `prev_hash`/`sequence` chain and (pre-#2209) committed UNVERIFIED —
    // and `memory_revisions.sequence` carries no UNIQUE constraint, so a
    // non-empty-destination merge could commit duplicate/forked revision
    // sequences into the tamper-evidence lane. Replay the WHOLE staged
    // chain (destination + bundle rows, post-`INSERT OR IGNORE`) from the
    // stored columns alone: sequences must be 1..=N, strictly contiguous and
    // UNIQUE (the uniqueness guard), and every row's `prev_hash` must equal
    // SHA-256 of its predecessor's canonical chain bytes.
    if let Some(defect) = verify_staged_revision_chain(&tx)
        .context("portability import: could not replay the staged memory_revisions chain")?
    {
        anyhow::bail!(
            "portability import REJECTED (fail-closed): the staged memory_revisions chain \
             did not replay ({defect}) — the bundle is tampered/forked, or it conflicts with \
             this destination's existing revision chain; NO rows were applied"
        );
    }
    report.reverify_revisions_ok = true;

    // ── FAIL-CLOSED lineage gate (#2209) ──
    // `verify_audit_trail` already computed the identity-lineage verdict
    // (the `agent_lineage` genesis→head walk reconciled against its
    // `signed_events` witnesses) — but the pre-#2209 gate ignored it, so a
    // bundle whose lineage records were tampered, or whose epochs fork the
    // destination's existing key-succession chain (`prev_record_hash`
    // pointing at the BUNDLE's predecessor while the destination kept its
    // own rows at the overlapping epochs), committed a poisoned identity
    // history. A `Forged` walk refuses the whole import.
    if matches!(audit.lineage, LineageCheck::Forged { .. }) {
        anyhow::bail!(
            "portability import REJECTED (fail-closed): the staged agent_lineage succession \
             chain verifies as FORGED ({:?}) — the bundle's lineage records are tampered or \
             fork this destination's existing key-succession history; NO rows were applied",
            audit.lineage
        );
    }

    tx.commit()
        .context("portability import: transaction commit failed")?;
    report.committed = true;
    Ok(report)
}

fn begin_atomic_import(conn: &Connection) -> Result<rusqlite::Transaction<'_>> {
    rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)
        .context("portability import: could not open the atomic BEGIN IMMEDIATE transaction")
}

/// Stage every class into `conn` (a live transaction). Any `?` here aborts the
/// whole import (the caller's transaction rolls back).
fn apply_all_classes(
    conn: &Connection,
    env: &ExportEnvelope,
    opts: &ImportOptions,
    enrolled_keys: &std::collections::HashMap<String, Option<String>>,
) -> Result<ImportReport> {
    let mut report = ImportReport::default();

    // (1) forget_tombstones FIRST — tombstone-before-admit. The bundle's
    // tombstones are staged into the SAME `forget_tombstones` table the
    // step-(2) destination probe reads, so one probe covers both the
    // bundle's tombstones and the destination's pre-existing ones (#2208).
    for t in &env.forget_tombstones {
        // #2208 re-audit N2 — a bundle tombstone is UNAUTHENTICATED input,
        // and the substrate's resurrection guard is EXISTENCE-based. If the
        // id is currently LIVE at the destination, staging the tombstone
        // would plant the contradictory live-row+tombstone state AND
        // permanently suppress the id's future federation/import admission
        // — an erasure the destination operator never ordered. Refuse to
        // plant it: skip + WARN, keep the destination's live truth (the
        // dest's own `memory_forget` funnel is the only sanctioned eraser
        // of a live dest row). A tombstone for a NOT-live id still stages
        // (the legitimate erasure-receipt transfer).
        if crate::storage::get(conn, &t.memory_id)
            .with_context(|| format!("import: live probe for tombstone {}", t.memory_id))?
            .is_some()
        {
            report.tombstones_skipped_live += 1;
            report.warnings.push(format!(
                "forget_tombstone for {} skipped: the id is LIVE at the destination — a \
                 bundle tombstone cannot suppress a live destination row (erase it via \
                 memory_forget at the destination if intended)",
                t.memory_id
            ));
            tracing::warn!(
                target: IMPORT_TRACE_TARGET,
                memory_id = %t.memory_id,
                "bundle forget_tombstone skipped: id is live at the destination"
            );
            continue;
        }
        conn.execute(
            "INSERT OR IGNORE INTO forget_tombstones \
                (memory_id, namespace, forgotten_at, agent_id, signature) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                t.memory_id,
                t.namespace,
                t.forgotten_at,
                t.agent_id,
                t.signature.as_ref().map(|h| h.0.as_slice())
            ],
        )
        .with_context(|| format!("import forget_tombstone for memory {}", t.memory_id))?;
        report.forget_tombstones += 1;
    }

    // (2) memories (tombstoned/archived skipped; id-keyed idempotent) + links.
    for mem in &env.memories {
        // #2208 — the forget covenant: a signed forget receipt is a promise.
        // The DESTINATION's `forget_tombstones` (now also holding the
        // bundle's own tombstones from step 1) is authoritative — a
        // dest-forgotten row probes `None` on `storage::get` (it was
        // erased), so without this gate a re-import RESURRECTED it and left
        // a live row alongside its own FORGET tombstone. Same structural
        // prevention `insert_if_newer` applies on the federation funnel.
        if crate::storage::memory_is_tombstoned(conn, &mem.id)
            .with_context(|| format!("import: tombstone probe for memory {}", mem.id))?
        {
            report.tombstoned_skipped += 1;
            continue;
        }
        // #2208 adjacent — a row the destination ARCHIVED also probes `None`
        // on `storage::get`; re-admitting it live would leave the id in
        // BOTH `memories` and `archived_memories` (dual residency). The
        // sanctioned way back to live is `memory_archive_restore`.
        if crate::storage::memory_is_archived(conn, &mem.id)
            .with_context(|| format!("import: archive probe for memory {}", mem.id))?
        {
            report.archived_skipped += 1;
            continue;
        }
        // Idempotent: skip a memory already present (a re-import is a no-op).
        if crate::storage::get(conn, &mem.id)
            .with_context(|| format!("import: probing existing memory {}", mem.id))?
            .is_some()
        {
            report.memories += 1;
            continue;
        }
        let mut staged = mem.clone();
        // #2211 — the L1 restamp-by-default provenance hygiene, replicated
        // (verbatim identity ONLY under the operator's explicit
        // `--trust-source`; see `ImportOptions::trust_source`). Mirrors the
        // L1 path byte-for-byte: the caller's id replaces
        // `metadata.agent_id` and the original claim is preserved under
        // `imported_from_agent_id`. The ORIGINAL claim is hoisted so the
        // attestation re-derivation below can apply the federation
        // re-attribution rule (`apply_inbound_write_attestation`).
        let original_claim = staged
            .metadata
            .get(crate::META_KEY_AGENT_ID)
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string);
        if !opts.trust_source {
            if let Some(obj) = staged.metadata.as_object_mut() {
                obj.insert(
                    crate::META_KEY_AGENT_ID.to_string(),
                    serde_json::Value::String(opts.caller_agent_id.clone()),
                );
                if let Some(orig) = original_claim.as_ref()
                    && orig.as_str() != opts.caller_agent_id
                {
                    obj.insert(
                        crate::models::field_names::IMPORTED_FROM_AGENT_ID.to_string(),
                        serde_json::Value::String(orig.clone()),
                    );
                    report.restamped += 1;
                }
            }
        }
        // #2353 (sibling of #2340) — redact to the TO-BE-PERSISTED form
        // BEFORE the attestation re-derivation below, so the stamp covers
        // exactly the bytes `storage::insert_imported`'s origin-blind screen
        // will persist. Under `redact` mode a bundle row whose signature
        // covers RAW secret-bearing bytes would otherwise land
        // `agent_attested` with mutated stored bytes (the #2340
        // stamp-then-redact class); the helper drops the now-uncoverable
        // signature so the row lands honestly `claimed`. (Under the default
        // `refuse` mode the L1-parity `validate_memory` below refuses
        // secret-bearing rows outright, so this only changes `redact`-mode
        // outcomes.)
        crate::federation::receive_auth::redact_inbound_before_attestation(&mut staged);
        // ── Pre-ship 3x7 HIGH-1 — NEVER trust wire attestation. ──
        // Bundles are UNAUTHENTICATED input (this module's own threat
        // model), yet pre-fix the wire-supplied `metadata.attest_level` /
        // `write_signature` / `agent_pubkey` persisted VERBATIM — a crafted
        // bundle minted `attest_level=agent_attested` rows this node's
        // trust surfaces (`row_is_agent_attested`, quarantine routing,
        // forensics) then believed. Re-derive the attestation from what the
        // DESTINATION can verify, mirroring the federation
        // `apply_inbound_write_attestation` discipline (reused via the same
        // `stamp_attestation` gate). A presented-but-FORGED signature skips
        // the row (per-row skip + WARN, the federation caller's
        // disposition); everything else lands `claimed` at worst.
        if !apply_import_attestation(
            &mut staged,
            original_claim.as_deref(),
            opts.trust_source,
            enrolled_keys,
            &mut report,
        )? {
            continue;
        }
        // ── Pre-ship 3x7 HIGH-2 — L1-parity input validation. ──
        // The `cli::io` L1 wire-form has validated every imported row since
        // #1780 (`validate::validate_memory` at src/cli/io.rs); the v2
        // route ran ZERO validation, landing rows that violate every write
        // invariant (MAX_CONTENT_SIZE, priority/confidence ranges, RFC3339
        // timestamps incl. #1834 valid_from/valid_until, refuse-mode secret
        // screen). Per-row skip + WARN — the bundle continues, matching the
        // tombstone/conflict disposition posture; never a silent accept.
        if let Err(e) = crate::validate::validate_memory(&staged) {
            report.invalid_skipped += 1;
            report.warnings.push(format!(
                "memory {} skipped: failed input validation: {e}",
                staged.id
            ));
            tracing::warn!(
                target: IMPORT_TRACE_TARGET,
                memory_id = %staged.id,
                error = %e,
                "bundle memory skipped: failed L1-parity input validation (pre-ship 3x7)"
            );
            continue;
        }
        // #2211 — honour the operator's `(title, namespace)` collision
        // disposition (the L1 `--on-conflict` semantics). Pre-#2211 the v2
        // path always took `storage::insert`'s silent upsert-merge, which
        // CLOBBERED an existing destination row's content whenever an
        // imported memory (different id) collided on `(title, namespace)`.
        if let Some(existing_id) =
            crate::storage::find_by_title_namespace(conn, &staged.title, &staged.namespace)
                .with_context(|| format!("import: collision probe for memory {}", staged.id))?
        {
            match opts.on_conflict {
                // Legacy silent upsert-merge — the operator opted in.
                ConflictMode::Merge => {}
                // Default: auto-suffix the INCOMING title so both rows
                // persist — never clobber the destination's durable text.
                ConflictMode::Version => {
                    staged.title = crate::storage::next_versioned_title(
                        conn,
                        &staged.title,
                        &staged.namespace,
                    )?;
                }
                // Refuse + skip the colliding row, continue the bundle
                // (the documented L1 `--on-conflict error` semantics).
                ConflictMode::Error => {
                    report.conflicts_skipped += 1;
                    report.warnings.push(format!(
                        "memory {} skipped: (title, namespace) collision with existing {existing_id}",
                        staged.id
                    ));
                    continue;
                }
            }
        }
        // Fresh rows go through `storage::insert_imported` (same screening +
        // FTS trigger + deterministic cid re-derivation funnel as
        // `storage::insert`, but WITHOUT advancing this node's vector-clock
        // component — remote-admission semantics mirroring `insert_if_newer`,
        // #2211: the destination did not author these rows). It opens no
        // inner transaction.
        crate::storage::insert_imported(conn, &staged)
            .with_context(|| format!("import memory {}", staged.id))?;
        report.memories += 1;
    }
    for link in &env.links {
        // Pre-ship 3x7 HIGH-2 (link lane) — L1 parity with the `cli::io`
        // per-link `validate::validate_link` gate: id shape, closed
        // relation vocabulary, and the self-link refusal. Per-row skip +
        // WARN; the bundle continues.
        if let Err(e) =
            crate::validate::validate_link(&link.source_id, &link.target_id, link.relation.as_str())
        {
            report.invalid_links_skipped += 1;
            report.warnings.push(format!(
                "link {}->{} skipped: failed input validation: {e}",
                link.source_id, link.target_id
            ));
            tracing::warn!(
                target: IMPORT_TRACE_TARGET,
                source_id = %link.source_id,
                target_id = %link.target_id,
                error = %e,
                "bundle link skipped: failed L1-parity input validation (pre-ship 3x7)"
            );
            continue;
        }
        // ── Pre-ship 3x7 F1 — endpoint-presence gate (FK-abort trap). ──
        // `memory_links.source_id`/`target_id` carry `REFERENCES
        // memories(id)` FKs and `db::open` sets `PRAGMA foreign_keys=ON`.
        // SQLite's ON-CONFLICT resolution does NOT apply to FOREIGN KEY
        // constraints, so `INSERT OR IGNORE` does NOT skip a dangling edge
        // — it raises an FK error that `?`-aborts the whole all-or-nothing
        // transaction (zero rows land, the report/WARNs never surface),
        // directly contradicting the per-row skip disposition. Probe both
        // endpoints against the STAGED state (the memories loop above ran
        // in this same transaction) and skip + WARN + count any edge whose
        // endpoint is absent: skipped earlier in this import (tombstoned /
        // archived / invalid / forged / conflict-refused) or simply never
        // present at the destination.
        if !memory_row_exists(conn, &link.source_id)? || !memory_row_exists(conn, &link.target_id)?
        {
            report.links_skipped_missing_endpoint += 1;
            report.warnings.push(format!(
                "link {}->{} skipped: an endpoint memory is absent at the destination \
                 (skipped earlier in this import, or never present)",
                link.source_id, link.target_id
            ));
            tracing::warn!(
                target: IMPORT_TRACE_TARGET,
                source_id = %link.source_id,
                target_id = %link.target_id,
                "bundle link skipped: endpoint memory absent — inserting it would FK-abort \
                 the whole import transaction (pre-ship 3x7 F1)"
            );
            continue;
        }
        // #2215 — repopulate the schema-v75 lineage-DAG cid mirror
        // (`source_cid` / `target_cid`) so an imported edge keeps its
        // tombstone-resilient node identity (pre-fix the raw INSERT dropped
        // both columns, so EVERY imported edge landed NULL — a #2006 residual
        // fidelity gap). Resolution, gated on `lineage_dag_enabled()` for
        // byte-parity with the native `create_link_signed` write path (COND;
        // when the DAG is OFF the mirror binds NULL — the legacy shape):
        //   1. PREFER the value the bundle carried (a fresh exporter round-trips
        //      the source's real cid via `MemoryLink.source_cid`/`target_cid`);
        //   2. else BACKFILL by probing the just-staged endpoint's `memories.cid`
        //      (an older bundle that predates the exporter twin fix carries no
        //      cids — the memories loop above re-derived them deterministically,
        //      so the mirror resolves from the live endpoint);
        //   3. else leave NULL — the pre-v75 legacy state (endpoint has no cid).
        //      DEGRADE, do not INVENT: a NULL mirror still resolves via the
        //      query layer's live LEFT JOIN while both endpoints are present.
        let (source_cid, target_cid): (Option<String>, Option<String>) =
            if crate::config::lineage_dag_enabled() {
                (
                    link.source_cid
                        .clone()
                        .or_else(|| crate::storage::read_memory_cid(conn, &link.source_id)),
                    link.target_cid
                        .clone()
                        .or_else(|| crate::storage::read_memory_cid(conn, &link.target_id)),
                )
            } else {
                (None, None)
            };
        // RAW, byte-preserving (`create_link` would re-derive the signature +
        // attest_level — a loss). `OR IGNORE` is idempotent on the natural
        // key (UNIQUE constraint) ONLY — it does NOT cover FK violations
        // (SQLite ON CONFLICT never applies to FK constraints; the pre-F1
        // comment here claimed otherwise), which is why the endpoint probe
        // above must run before this INSERT.
        let n = conn
            .execute(
                "INSERT OR IGNORE INTO memory_links \
                    (source_id, target_id, relation, created_at, valid_from, valid_until, \
                     observed_by, signature, attest_level, source_cid, target_cid) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                    source_cid,
                    target_cid,
                ],
            )
            .with_context(|| format!("import link {}->{}", link.source_id, link.target_id))?;
        report.links += n;
    }

    // (3) signed_events — RAW (byte-preserve prev_hash/sequence/cause_hash).
    for dto in &env.signed_events {
        let ev: crate::signed_events::SignedEvent = dto.clone().into();
        let n = conn
            .execute(
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
        // #2209 — an `OR IGNORE` that IGNORED is legitimate ONLY for an
        // idempotent re-import (the surviving row is byte-identical). An
        // ignore caused by a DIFFERENT surviving row at this id — or by the
        // `idx_signed_events_sequence` UNIQUE index when a different row
        // already occupies this sequence (a non-empty-destination chain
        // merge) — would SILENTLY DROP part of the bundle's signed spine
        // while the destination's own clean chain still passed the
        // re-verify: exactly the silent-spine-drop class #2006 exists to
        // kill. Refuse instead.
        if n == 0 {
            let identical: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM signed_events \
                     WHERE id = ?1 AND agent_id = ?2 AND event_type = ?3 \
                       AND payload_hash = ?4 AND signature IS ?5 AND attest_level = ?6 \
                       AND timestamp = ?7 AND prev_hash = ?8 AND sequence = ?9 \
                       AND cause_hash IS ?10)",
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
                    |r| r.get(0),
                )
                .with_context(|| format!("import: identity probe for signed_event {}", ev.id))?;
            if !identical {
                anyhow::bail!(
                    "import signed_event {} (sequence {}): a DIFFERENT row already occupies \
                     this id/sequence in the destination — the bundle's audit chain forks the \
                     destination's; refusing rather than silently dropping part of the signed \
                     spine",
                    ev.id,
                    ev.sequence
                );
            }
        }
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
        let n = conn
            .execute(
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
        // #2209 — same identical-or-refuse discipline as the signed_events
        // loop: an ignore from the `idx_memory_revisions_sequence` UNIQUE
        // index (a foreign chain merged into a non-empty destination) or a
        // same-id-different-bytes row is a FORK; silently keeping the
        // destination row while counting the bundle row as imported would
        // silently drop part of the revisions spine.
        if n == 0 {
            let identical: bool = conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM memory_revisions \
                     WHERE id = ?1 AND memory_id = ?2 AND kind = ?3 \
                       AND prior_version IS ?4 AND namespace = ?5 AND agent_id IS ?6 \
                       AND created_at = ?7 AND signature IS ?8 AND prev_hash = ?9 \
                       AND sequence = ?10)",
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
                    |r| r.get(0),
                )
                .with_context(|| {
                    format!("import: identity probe for memory_revision {}", row.leaf.id)
                })?;
            if !identical {
                anyhow::bail!(
                    "import memory_revision {} (sequence {}): a DIFFERENT row already occupies \
                     this id/sequence in the destination — the bundle's revision chain forks \
                     the destination's; refusing rather than silently dropping part of the \
                     revisions spine",
                    row.leaf.id,
                    row.sequence
                );
            }
        }
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
                i64::try_from(record.epoch).context("import: agent_lineage epoch exceeds i64")?,
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
        // #2209 — identical-or-refuse on the `(agent_id, epoch)` composite
        // PK (the C5 anti-equivocation constraint): an ignore whose
        // surviving row differs from the bundle's record is EQUIVOCATION —
        // two different succession records claiming the same epoch. The
        // canonical `record_bytes` + detached signature pin the whole
        // record, so one byte-comparison covers every signed field.
        {
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM agent_lineage \
                     WHERE agent_id = ?1 AND epoch = ?2 \
                       AND record_bytes = ?3 AND signature = ?4",
                    params![
                        record.agent_id,
                        i64::try_from(record.epoch)
                            .context("import: agent_lineage epoch exceeds i64")?,
                        record_bytes,
                        export.signature,
                    ],
                    |r| r.get(0),
                )
                .with_context(|| {
                    format!(
                        "import: identity probe for agent_lineage {}",
                        record.agent_id
                    )
                })?;
            if n == 0 {
                anyhow::bail!(
                    "import agent_lineage {} epoch {}: a DIFFERENT succession record already \
                     occupies this (agent_id, epoch) in the destination (equivocation) — \
                     refusing rather than silently dropping the bundle's lineage record",
                    record.agent_id,
                    record.epoch
                );
            }
        }
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

/// Pre-ship 3x7 F1 — lightweight existence probe for a link endpoint
/// against the STAGED transaction state. Deliberately NOT
/// [`crate::storage::get`] (full row read + decrypt path) — one
/// `EXISTS` per endpoint is all the FK gate needs.
///
/// # Errors
///
/// Surfaces underlying query failures.
fn memory_row_exists(conn: &Connection, id: &str) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM memories WHERE id = ?1)",
        params![id],
        |r| r.get(0),
    )
    .with_context(|| format!("import: endpoint-presence probe for memory {id}"))
}

/// Pre-ship 3x7 HIGH-1 — resolve the DESTINATION-enrolled Ed25519 key for
/// every author the bundle's memories will be attributed to, BEFORE the
/// import transaction stages any bundle row.
///
/// The lookup ([`crate::storage::agent_pubkey`]) reads the flat
/// `metadata.agent_pubkey` off the `_agents` registration row — a row shape
/// an unauthenticated bundle can itself carry. Snapshotting pre-transaction
/// structurally prevents in-bundle self-enrollment: a crafted registration
/// row staged earlier in the SAME bundle can never supply the key a later
/// row "verifies" against.
///
/// Under the default restamp posture the only attributed author is the
/// caller; under `--trust-source` each memory keeps its own claimed author.
///
/// # Errors
///
/// Surfaces underlying key-lookup query failures.
fn snapshot_dest_enrolled_keys(
    conn: &Connection,
    env: &ExportEnvelope,
    opts: &ImportOptions,
) -> Result<std::collections::HashMap<String, Option<String>>> {
    let mut keys = std::collections::HashMap::new();
    for mem in &env.memories {
        let author: Option<String> = if opts.trust_source {
            mem.metadata
                .get(crate::META_KEY_AGENT_ID)
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
        } else {
            Some(opts.caller_agent_id.clone())
        };
        let Some(author) = author.filter(|a| !a.is_empty()) else {
            continue;
        };
        if !keys.contains_key(&author) {
            let bound = crate::storage::agent_pubkey(conn, &author).with_context(|| {
                format!("portability import: resolving enrolled key for author {author}")
            })?;
            keys.insert(author, bound);
        }
    }
    Ok(keys)
}

/// Pre-ship 3x7 HIGH-1 — re-derive a staged memory's attestation from what
/// the DESTINATION can verify, never from the wire (the federation
/// [`crate::handlers::federation_receive`] `apply_inbound_write_attestation`
/// discipline, reused through the same
/// [`crate::identity::attest::stamp_attestation`] gate).
///
/// Behaviour, in order:
/// 1. Under the default restamp posture the wire `metadata.agent_pubkey`
///    identity-key claim is STRIPPED (unauthenticated input must not seed
///    the destination's enrolled-key lookup surface).
/// 2. A byte-preserving fast path: a row that neither asserts an
///    `attest_level` nor presents a `write_signature` is left untouched
///    (absent reads as `claimed` on every trust surface).
/// 3. The re-attribution rule: a row whose identity was restamped
///    (`original_claim != attributed`) can never verify the ORIGINAL
///    claimant's signature against the new attribution — land `claimed`,
///    skip verification (mirrors `apply_inbound_write_attestation`).
/// 4. Otherwise verify any presented `metadata.write_signature` against the
///    pre-transaction snapshot of the author's DESTINATION-enrolled key:
///    valid → `agent_attested`; absent signature or unenrolled author →
///    `claimed`; presented-but-FORGED → the row is SKIPPED (`Ok(false)`),
///    never downgraded — the #1464 invariant that a deliberately bad
///    signature cannot launder into a stored row.
///
/// Returns `Ok(true)` to keep the row, `Ok(false)` to skip it (forged).
///
/// # Errors
///
/// None currently beyond the `Result` plumbing shared with the loop; forged
/// signatures are a counted per-row skip, not a batch abort.
fn apply_import_attestation(
    staged: &mut crate::models::Memory,
    original_claim: Option<&str>,
    trust_source: bool,
    enrolled_keys: &std::collections::HashMap<String, Option<String>>,
    report: &mut ImportReport,
) -> Result<bool> {
    use crate::models::field_names;

    let wire_asserted_attested = staged
        .metadata
        .get(field_names::ATTEST_LEVEL)
        .and_then(serde_json::Value::as_str)
        == Some(crate::identity::verify::AttestLevel::AgentAttested.as_str());
    let wire_has_attest_level = staged.metadata.get(field_names::ATTEST_LEVEL).is_some();
    // (1) Strip the wire identity-key claim under the restamp posture.
    if !trust_source
        && let Some(obj) = staged.metadata.as_object_mut()
        && obj.remove(field_names::AGENT_PUBKEY).is_some()
    {
        tracing::warn!(
            target: IMPORT_TRACE_TARGET,
            memory_id = %staged.id,
            "bundle memory carried a wire agent_pubkey identity-key claim — stripped \
             (unauthenticated input must not seed the enrolled-key surface; pre-ship 3x7)"
        );
    }
    let wire_signature = staged.metadata.get(field_names::WRITE_SIGNATURE);
    let presented_sig: Option<Vec<u8>> = match wire_signature {
        None => None,
        Some(serde_json::Value::String(encoded)) => {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(encoded.trim()) {
                Ok(signature) if signature.len() == crate::identity::verify::SIGNATURE_LEN => {
                    Some(signature)
                }
                Ok(_) | Err(_) => {
                    report.forged_signature_skipped += 1;
                    report.warnings.push(format!(
                        "memory {} skipped: presented write_signature is malformed",
                        staged.id
                    ));
                    tracing::warn!(
                        target: IMPORT_TRACE_TARGET,
                        memory_id = %staged.id,
                        "bundle memory skipped: presented write_signature is malformed \
                         (invalid base64 or not exactly 64 bytes; never treated as absent)"
                    );
                    return Ok(false);
                }
            }
        }
        Some(_) => {
            report.forged_signature_skipped += 1;
            report.warnings.push(format!(
                "memory {} skipped: presented write_signature has a non-string shape",
                staged.id
            ));
            tracing::warn!(
                target: IMPORT_TRACE_TARGET,
                memory_id = %staged.id,
                "bundle memory skipped: presented write_signature has a non-string shape \
                 (never treated as absent)"
            );
            return Ok(false);
        }
    };
    // (2) Byte-preserving fast path: nothing asserted, nothing presented.
    if !wire_has_attest_level && presented_sig.is_none() {
        return Ok(true);
    }
    let land_claimed = |staged: &mut crate::models::Memory, report: &mut ImportReport| {
        if let Some(obj) = staged.metadata.as_object_mut() {
            obj.remove(field_names::WRITE_SIGNATURE);
            obj.insert(
                field_names::ATTEST_LEVEL.to_string(),
                serde_json::Value::String(
                    crate::identity::verify::AttestLevel::Claimed
                        .as_str()
                        .to_string(),
                ),
            );
        }
        if wire_asserted_attested {
            report.attestation_downgraded += 1;
            tracing::warn!(
                target: IMPORT_TRACE_TARGET,
                memory_id = %staged.id,
                "bundle memory asserted attest_level=agent_attested but the destination \
                 could not verify it — landed claimed (wire attestation is never trusted; \
                 pre-ship 3x7)"
            );
        }
    };
    let attributed = staged
        .metadata
        .get(crate::META_KEY_AGENT_ID)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let Some(attributed) = attributed.filter(|a| !a.is_empty()) else {
        land_claimed(staged, report);
        return Ok(true);
    };
    // (3) The re-attribution rule.
    if original_claim.is_some_and(|c| c != attributed) {
        land_claimed(staged, report);
        return Ok(true);
    }
    // (4) Verify against the pre-transaction DESTINATION-enrolled key.
    let bound: Option<&str> = enrolled_keys.get(&attributed).and_then(|k| k.as_deref());
    match crate::identity::attest::stamp_attestation(
        staged,
        &attributed,
        bound,
        presented_sig.as_deref(),
        false,
    ) {
        Ok(level) => {
            if level != crate::identity::verify::AttestLevel::AgentAttested
                && let Some(obj) = staged.metadata.as_object_mut()
            {
                obj.remove(field_names::WRITE_SIGNATURE);
            }
            if wire_asserted_attested
                && level != crate::identity::verify::AttestLevel::AgentAttested
            {
                report.attestation_downgraded += 1;
                tracing::warn!(
                    target: IMPORT_TRACE_TARGET,
                    memory_id = %staged.id,
                    author = %attributed,
                    "bundle memory asserted attest_level=agent_attested but the destination \
                     verified only 'claimed' (no enrolled author key / no signature) — \
                     wire attestation is never trusted (pre-ship 3x7)"
                );
            }
            Ok(true)
        }
        Err(e) => {
            report.forged_signature_skipped += 1;
            report.warnings.push(format!(
                "memory {} skipped: presented write_signature failed verification against \
                 the destination-enrolled key for {attributed} (forged; never downgraded)",
                staged.id
            ));
            tracing::warn!(
                target: IMPORT_TRACE_TARGET,
                memory_id = %staged.id,
                author = %attributed,
                error = %e,
                "bundle memory skipped: presented write_signature is FORGED against the \
                 destination-enrolled author key (pre-ship 3x7; #1464 invariant)"
            );
            Ok(false)
        }
    }
}

/// #2209 — replay-verify the WHOLE staged `memory_revisions` chain from the
/// stored columns alone (the revisions-chain verifier the pre-commit gate
/// lacked; `signed_events` has `verify_audit_trail`, this is its
/// `memory_revisions` mirror).
///
/// Invariants asserted, in walk order over `ORDER BY sequence ASC`:
/// - sequences are UNIQUE (the uniqueness guard — the table carries no
///   `UNIQUE(sequence)` constraint, so merging a foreign chain into a
///   non-empty destination would otherwise commit duplicate sequences);
/// - sequences are contiguous `1..=N` (a gap = a truncated/forked chain);
/// - row 1's `prev_hash` is the zero hash, and every later row's `prev_hash`
///   equals `SHA-256(canonical_revision_chain_bytes(predecessor))` — the
///   exact link `revisions::append_revision_leaf` writes, so a tampered
///   interior row (any identity field OR its `prev_hash`) breaks the replay.
///
/// Returns `Ok(None)` on a clean (or empty) chain, `Ok(Some(defect))` naming
/// the first defect. Signature verification is deliberately NOT attempted
/// here (parity with the `signed_events` gate: with no enrolled verifier the
/// integrity guarantee is the byte-preserved chain replay).
///
/// # Errors
/// A revision row cannot be read/reconstructed (fail-closed — an unknown
/// `kind` slug in the STORED state is itself a defect surfaced by
/// `read_all_memory_revisions`).
fn verify_staged_revision_chain(conn: &Connection) -> Result<Option<String>> {
    use sha2::{Digest, Sha256};

    let rows = crate::portability::read::read_all_memory_revisions(conn)?;
    let mut expected_prev: [u8; 32] = crate::signed_events::ZERO_HASH;
    let mut prev_seq: i64 = 0;
    for row in &rows {
        let seq = row.sequence;
        if seq == prev_seq {
            return Ok(Some(format!(
                "duplicate sequence {seq} (id {}) — two distinct revision rows claim the same \
                 chain position",
                row.leaf.id
            )));
        }
        if seq != prev_seq + 1 {
            return Ok(Some(format!(
                "sequence gap: expected {}, found {seq} (id {})",
                prev_seq + 1,
                row.leaf.id
            )));
        }
        if row.prev_hash.as_slice() != expected_prev.as_slice() {
            return Ok(Some(format!(
                "broken prev_hash link at sequence {seq} (id {})",
                row.leaf.id
            )));
        }
        let mut hasher = Sha256::new();
        hasher.update(crate::revisions::canonical_revision_chain_bytes(
            &row.leaf, seq,
        ));
        expected_prev.copy_from_slice(&hasher.finalize());
        prev_seq = seq;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portability::emit::build_full_envelope;
    use crate::signed_events::{
        SignedEvent, append_signed_event, list_signed_events, payload_hash,
    };
    use std::sync::Mutex;

    static IMPORT_TRACE_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static IMPORT_TRACE_GUARD: Mutex<()> = Mutex::new(());

    fn import_trace_callback(statement: &str) {
        IMPORT_TRACE_LOG
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(statement.to_string());
    }

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

    #[test]
    fn atomic_import_reserves_the_writer_up_front_2250() {
        let conn = fresh_conn("begin-immediate-2250");
        conn.execute_batch("CREATE TABLE import_lock_probe (value INTEGER NOT NULL)")
            .unwrap();
        let db_path = conn
            .path()
            .expect("file-backed test connection")
            .to_string();
        let competitor = Connection::open(db_path).unwrap();
        competitor.busy_timeout(std::time::Duration::ZERO).unwrap();

        let tx = begin_atomic_import(&conn).expect("BEGIN IMMEDIATE");
        let err = competitor
            .execute("INSERT INTO import_lock_probe (value) VALUES (1)", [])
            .expect_err("a competing writer must not enter during import staging");
        assert!(
            matches!(
                err,
                rusqlite::Error::SqliteFailure(ref inner, _)
                    if matches!(
                        inner.code,
                        rusqlite::ErrorCode::DatabaseBusy
                            | rusqlite::ErrorCode::DatabaseLocked
                    )
            ),
            "expected SQLite busy/locked from the reserved writer, got {err:?}"
        );

        drop(tx);
        competitor
            .execute("INSERT INTO import_lock_probe (value) VALUES (1)", [])
            .expect("writer proceeds after import rollback");
    }

    #[test]
    fn import_entrypoint_reserves_writer_before_enrolled_key_snapshot_2250() {
        let _trace_guard = IMPORT_TRACE_GUARD
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        IMPORT_TRACE_LOG
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();

        let src = fresh_conn("entrypoint-order-src-2250-");
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        env.memories.push(memory_fixture(
            "mem-entrypoint-order-2250",
            "transaction ordering",
            "ai:source-2250",
        ));
        let mut dst = fresh_conn("entrypoint-order-dst-2250-");
        dst.trace(Some(import_trace_callback));
        let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
        dst.trace(None);
        assert_eq!(report.memories, 1);

        let trace = IMPORT_TRACE_LOG
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let begin = trace
            .iter()
            .position(|statement| statement.trim_start().starts_with("BEGIN IMMEDIATE"))
            .expect("entrypoint must open BEGIN IMMEDIATE");
        let snapshot = trace
            .iter()
            .position(|statement| {
                statement.contains("json_extract(metadata, '$.agent_pubkey')")
                    && statement.contains("WHERE namespace")
            })
            .expect("entrypoint must query the destination-enrolled author key");
        assert!(
            begin < snapshot,
            "writer reservation must precede trust snapshot; trace={trace:?}"
        );
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

    /// The explicit operator-trusted-backup posture (#2211) — the legacy
    /// verbatim behaviour the byte-exact round-trip tests exercise.
    fn opts_trusted() -> ImportOptions {
        ImportOptions {
            trust_source: true,
            caller_agent_id: "importer".into(),
            ..ImportOptions::default()
        }
    }

    /// The DEFAULT (L1-parity) posture: restamp identity, never clobber.
    fn opts_default() -> ImportOptions {
        ImportOptions {
            trust_source: false,
            caller_agent_id: "importer".into(),
            ..ImportOptions::default()
        }
    }

    /// A minimal durable memory fixture carrying a (claimed) author id.
    fn memory_fixture(id: &str, title: &str, agent_id: &str) -> crate::models::Memory {
        let now = "2026-07-14T00:00:00Z".to_string();
        crate::models::Memory {
            id: id.into(),
            namespace: "portability".into(),
            title: title.into(),
            content: format!("durable content of {id}"),
            created_at: now.clone(),
            updated_at: now,
            expires_at: Some("2099-01-01T00:00:00Z".into()),
            metadata: serde_json::json!({ "agent_id": agent_id }),
            ..crate::models::Memory::default()
        }
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
        let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
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
        let first = import_full_envelope(&dst, &env, &opts_trusted()).expect("import 1");
        let second = import_full_envelope(&dst, &env, &opts_trusted()).expect("import 2");
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
        env.signed_events[1].payload_hash =
            crate::portability::hex_bytes::HexBytes(vec![0xba, 0xad]);

        let dst = fresh_conn("tamper-dst-");
        let err = import_full_envelope(&dst, &env, &opts_trusted())
            .expect_err("tampered bundle must be rejected");
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
        let err = import_full_envelope(&dst, &env, &opts_trusted())
            .expect_err("truncated bundle must be rejected");
        assert!(err.to_string().contains("REJECTED"), "got: {err}");
        assert!(
            list_signed_events(&dst, None, usize::MAX, 0)
                .expect("rows")
                .is_empty(),
            "a rejected import must leave ZERO rows"
        );
    }

    /// ★ #2208 FORGET COVENANT: a memory the DESTINATION forgot (row erased +
    /// dest tombstone recorded) must NOT resurrect on a re-import of a bundle
    /// that still carries it. Fails on pre-#2208 code (only the BUNDLE's
    /// tombstones were consulted; `storage::insert` re-admitted the row).
    #[test]
    fn dest_forgotten_memory_is_not_resurrected_2208() {
        let src = fresh_conn("forget-src-");
        let mem = memory_fixture("mem-forget-2208", "forgettable", "alice");
        crate::storage::insert_imported(&src, &mem).expect("seed unsigned source row");
        let env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");

        let dst = fresh_conn("forget-dst-");
        import_full_envelope(&dst, &env, &opts_trusted()).expect("first import");
        assert!(
            crate::storage::get(&dst, "mem-forget-2208")
                .expect("get")
                .is_some(),
            "first import landed the row"
        );

        // The destination operator forgets it — the durable erasure receipt.
        let forgotten = crate::storage::forget(&dst, Some("portability"), None, None, false)
            .expect("dest forget");
        assert_eq!(forgotten, 1, "dest forgot the row");
        assert!(
            crate::storage::memory_is_tombstoned(&dst, "mem-forget-2208").expect("probe"),
            "dest recorded a forget tombstone"
        );

        // Re-import the SAME bundle: the forgotten content must stay gone.
        let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("re-import");
        assert!(
            crate::storage::get(&dst, "mem-forget-2208")
                .expect("get")
                .is_none(),
            "the forgotten memory must NOT resurrect through the import"
        );
        assert_eq!(report.tombstoned_skipped, 1, "the skip is counted");
        assert!(
            crate::storage::memory_is_tombstoned(&dst, "mem-forget-2208").expect("probe"),
            "the tombstone survives the import"
        );
    }

    /// #2208 adjacent: a memory the DESTINATION archived must not be
    /// re-admitted LIVE (dual residency in `memories` + `archived_memories`).
    #[test]
    fn dest_archived_memory_is_not_readmitted_live_2208() {
        let src = fresh_conn("arch-src-");
        let mem = memory_fixture("mem-arch-2208", "archivable", "alice");
        crate::storage::insert_imported(&src, &mem).expect("seed unsigned source row");
        let env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");

        let dst = fresh_conn("arch-dst-");
        import_full_envelope(&dst, &env, &opts_trusted()).expect("first import");
        assert!(
            crate::storage::archive_memory(&dst, "mem-arch-2208", Some("test")).expect("archive"),
            "dest archived the row"
        );

        let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("re-import");
        assert_eq!(report.archived_skipped, 1, "the archived skip is counted");
        assert!(
            crate::storage::get(&dst, "mem-arch-2208")
                .expect("get")
                .is_none(),
            "the archived memory must NOT be re-admitted live"
        );
        assert!(
            crate::storage::memory_is_archived(&dst, "mem-arch-2208").expect("probe"),
            "the archived row is untouched"
        );
    }

    /// ★ #2209: a bundle whose `memory_revisions` chain was TAMPERED (an
    /// identity field mutated after export) is REJECTED with zero rows.
    /// Fails on pre-#2209 code (revisions committed with no chain walk).
    #[test]
    fn tampered_revision_chain_is_rejected_with_zero_rows_2209() {
        use crate::revisions::{RecordKind, RevisionLeaf, append_revision_leaf};
        let src = fresh_conn("rev-tamper-src-");
        for i in 0..3 {
            let leaf = RevisionLeaf::new(
                format!("rev-{i}"),
                format!("mem-{i}"),
                RecordKind::Supersede,
                Some(1),
                "ns",
                Some("alice".into()),
                "2026-07-14T00:00:00Z",
            );
            append_revision_leaf(&src, &leaf).expect("append leaf");
        }
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        assert_eq!(env.memory_revisions.len(), 3);
        // Tamper an INTERIOR row's identity field: the NEXT row's prev_hash
        // was computed over the ORIGINAL bytes, so the replay must break.
        env.memory_revisions[1].namespace = "tampered-ns".into();

        let dst = fresh_conn("rev-tamper-dst-");
        let err = import_full_envelope(&dst, &env, &opts_trusted())
            .expect_err("tampered revision chain must be rejected");
        assert!(
            err.to_string().contains("REJECTED"),
            "loud fail-closed error, got: {err}"
        );
        let n: i64 = dst
            .query_row("SELECT COUNT(*) FROM memory_revisions", [], |r| r.get(0))
            .expect("count");
        assert_eq!(n, 0, "a rejected import must leave ZERO revision rows");
    }

    /// ★ #2209 uniqueness guard: importing a bundle with its OWN revision
    /// chain into a destination that already carries a DIFFERENT chain would
    /// commit duplicate/forked sequences (`memory_revisions.sequence` has no
    /// UNIQUE constraint) — the staged replay must refuse. Fails on
    /// pre-#2209 code (both chains committed interleaved).
    #[test]
    fn diverging_dest_revision_chain_refuses_merge_2209() {
        use crate::revisions::{RecordKind, RevisionLeaf, append_revision_leaf};
        let src = fresh_conn("rev-fork-src-");
        append_revision_leaf(
            &src,
            &RevisionLeaf::new(
                "rev-src",
                "mem-src",
                RecordKind::Supersede,
                Some(1),
                "ns",
                Some("alice".into()),
                "2026-07-14T00:00:00Z",
            ),
        )
        .expect("src leaf");
        let env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");

        let dst = fresh_conn("rev-fork-dst-");
        append_revision_leaf(
            &dst,
            &RevisionLeaf::new(
                "rev-dst",
                "mem-dst",
                RecordKind::Tombstone,
                Some(2),
                "other-ns",
                Some("bob".into()),
                "2026-07-15T00:00:00Z",
            ),
        )
        .expect("dst leaf");

        let err = import_full_envelope(&dst, &env, &opts_trusted())
            .expect_err("a forked revision merge must refuse");
        assert!(
            format!("{err:#}").contains("DIFFERENT row"),
            "loud fail-closed fork error, got: {err:#}"
        );
        // The destination keeps EXACTLY its own pre-existing chain.
        let n: i64 = dst
            .query_row("SELECT COUNT(*) FROM memory_revisions", [], |r| r.get(0))
            .expect("count");
        assert_eq!(n, 1, "the destination chain is untouched");
    }

    /// ★ #2209: a bundle carrying a FORGED `agent_lineage` record (garbage
    /// signature) is REJECTED with zero rows. Fails on pre-#2209 code (the
    /// gate ignored `audit.lineage`, committing the forged succession row).
    #[test]
    fn forged_agent_lineage_is_rejected_with_zero_rows_2209() {
        use base64::Engine as _;
        let src = fresh_conn("lin-forge-src-");
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        let pk_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42_u8; 32].as_slice());
        env.agent_lineage.push(crate::portability::dto::LineageDto {
            agent_id: "mallory".into(),
            epoch: 0,
            reason: "genesis".into(),
            predecessor_pubkey_b64: pk_b64.clone(),
            successor_pubkey_b64: pk_b64,
            recovery_pubkey_b64: None,
            not_before: "2026-07-14T00:00:00Z".into(),
            prev_record_hash: crate::portability::hex_bytes::HexBytes(vec![0u8; 32]),
            custody_class: "software-file".into(),
            suspected_compromise_from_seq: None,
            guardian_set_id: None,
            recovery_threshold: None,
            signature: crate::portability::hex_bytes::HexBytes(vec![0xab_u8; 64]),
        });

        let dst = fresh_conn("lin-forge-dst-");
        let err = import_full_envelope(&dst, &env, &opts_trusted())
            .expect_err("a forged lineage record must be rejected");
        assert!(
            err.to_string().contains("REJECTED"),
            "loud fail-closed error, got: {err}"
        );
        let n: i64 = dst
            .query_row("SELECT COUNT(*) FROM agent_lineage", [], |r| r.get(0))
            .expect("count");
        assert_eq!(n, 0, "a rejected import must leave ZERO lineage rows");
    }

    /// ★ #2211: a SPINE-LESS v2 bundle (empty `signed_events` — the empty
    /// chain passes the audit gate trivially) must NOT import forged
    /// `agent_id` claims verbatim: without `--trust-source` the identity is
    /// RESTAMPED exactly like the L1 path. Fails on pre-#2211 code (verbatim
    /// preservation with zero verification).
    #[test]
    fn spine_less_bundle_restamps_identity_by_default_2211() {
        let src = fresh_conn("restamp-src-");
        let mem = memory_fixture("mem-restamp-2211", "claimed", "forged-agent");
        crate::storage::insert_imported(&src, &mem).expect("seed unsigned source row");
        let env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        assert!(
            env.signed_events.is_empty(),
            "fixture: the bundle is spine-less"
        );

        let dst = fresh_conn("restamp-dst-");
        let report = import_full_envelope(&dst, &env, &opts_default()).expect("import");
        assert_eq!(report.restamped, 1, "the restamp is counted: {report:?}");
        let got = crate::storage::get(&dst, "mem-restamp-2211")
            .expect("get")
            .expect("row landed");
        assert_eq!(
            got.metadata.get("agent_id").and_then(|v| v.as_str()),
            Some("importer"),
            "the forged agent_id must be restamped with the caller's id"
        );
        assert_eq!(
            got.metadata
                .get(crate::models::field_names::IMPORTED_FROM_AGENT_ID)
                .and_then(|v| v.as_str()),
            Some("forged-agent"),
            "the original claim is preserved as provenance, not honoured"
        );

        // The explicit operator flag restores the verbatim posture.
        let dst2 = fresh_conn("restamp-dst2-");
        import_full_envelope(&dst2, &env, &opts_trusted()).expect("trusted import");
        let got2 = crate::storage::get(&dst2, "mem-restamp-2211")
            .expect("get")
            .expect("row landed");
        assert_eq!(
            got2.metadata.get("agent_id").and_then(|v| v.as_str()),
            Some("forged-agent"),
            "--trust-source preserves the source identity verbatim"
        );
    }

    /// #2211: imported rows are REMOTE-ADMITTED — the destination's own
    /// vector-clock component is NOT advanced (mirrors `insert_if_newer`).
    /// Fails on pre-#2211 code (`storage::insert` stamped the local clock).
    #[test]
    fn imported_rows_do_not_bump_local_vector_clock_2211() {
        use crate::models::field_names;
        let src = fresh_conn("clock-src-");
        // Seed WITHOUT the local-authorship stamp so the exported metadata
        // carries NO version vector at all.
        crate::storage::insert_imported(
            &src,
            &memory_fixture("mem-clock-2211", "clockless", "alice"),
        )
        .expect("seed src");
        let env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");

        let dst = fresh_conn("clock-dst-");
        import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
        let got = crate::storage::get(&dst, "mem-clock-2211")
            .expect("get")
            .expect("row landed");
        assert!(
            got.metadata.get(field_names::VERSION_VECTOR).is_none(),
            "a remote-admitted row must not gain a destination clock component, got: {}",
            got.metadata
        );
    }

    /// ★ #2211: a `(title, namespace)` collision with an EXISTING destination
    /// row (different id) must NOT silently clobber the destination's durable
    /// text — the default `Version` disposition suffixes the INCOMING title.
    /// Fails on pre-#2211 code (`storage::insert`'s upsert-merge overwrote
    /// the destination row's content).
    #[test]
    fn title_collision_does_not_clobber_dest_row_2211() {
        let src = fresh_conn("clobber-src-");
        let mut incoming = memory_fixture("mem-incoming-2211", "shared title", "alice");
        incoming.content = "bundle content".into();
        crate::storage::insert_imported(&src, &incoming).expect("seed unsigned source row");
        let env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");

        let dst = fresh_conn("clobber-dst-");
        let mut existing = memory_fixture("mem-existing-2211", "shared title", "bob");
        existing.content = "destination content".into();
        crate::storage::insert(&dst, &existing).expect("seed dst");

        let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
        assert_eq!(report.memories, 1);
        let kept = crate::storage::get(&dst, "mem-existing-2211")
            .expect("get")
            .expect("dest row survives");
        assert_eq!(
            kept.content, "destination content",
            "the destination row's durable text must NOT be clobbered"
        );
        let landed = crate::storage::get(&dst, "mem-incoming-2211")
            .expect("get")
            .expect("incoming row landed");
        assert_eq!(
            landed.title, "shared title (2)",
            "the incoming title is version-suffixed (never-clobber default)"
        );

        // `--on-conflict error` refuses + skips the colliding row.
        let dst2 = fresh_conn("clobber-dst2-");
        crate::storage::insert(&dst2, &existing).expect("seed dst2");
        let mut opts = opts_trusted();
        opts.on_conflict = ConflictMode::Error;
        let report2 = import_full_envelope(&dst2, &env, &opts).expect("import");
        assert_eq!(report2.conflicts_skipped, 1, "the skip is counted");
        assert!(
            crate::storage::get(&dst2, "mem-incoming-2211")
                .expect("get")
                .is_none(),
            "the colliding row is refused under error mode"
        );
    }

    /// ★ #2208 re-audit N2: a bundle `forget_tombstone` for an id that is
    /// currently LIVE at the destination is NOT staged (skip + WARN) — an
    /// unauthenticated bundle tombstone must not plant the contradictory
    /// live-row+tombstone state or suppress the id's future admission.
    /// Fails on pre-N2 code (the tombstone raw-inserted unconditionally).
    #[test]
    fn bundle_tombstone_for_live_dest_row_is_not_staged_n2() {
        let src = fresh_conn("tomb-live-src-");
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        env.forget_tombstones
            .push(crate::portability::dto::ForgetTombstoneDto {
                memory_id: "mem-live-n2".into(),
                namespace: "portability".into(),
                forgotten_at: "2026-07-14T00:00:00Z".into(),
                agent_id: Some("mallory".into()),
                signature: None,
            });

        let dst = fresh_conn("tomb-live-dst-");
        crate::storage::insert(&dst, &memory_fixture("mem-live-n2", "alive", "bob"))
            .expect("seed live dest row");

        let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
        assert_eq!(report.tombstones_skipped_live, 1, "the skip is counted");
        assert_eq!(report.forget_tombstones, 0, "the tombstone was NOT staged");
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("mem-live-n2") && w.contains("LIVE")),
            "a WARN names the suppressed tombstone, got: {:?}",
            report.warnings
        );
        assert!(
            !crate::storage::memory_is_tombstoned(&dst, "mem-live-n2").expect("probe"),
            "no tombstone row landed for the live id"
        );
        assert!(
            crate::storage::get(&dst, "mem-live-n2")
                .expect("get")
                .is_some(),
            "the live destination row is untouched"
        );

        // Control: a tombstone for a NOT-live id still stages (the
        // legitimate erasure-receipt transfer path is unchanged).
        let dst2 = fresh_conn("tomb-live-dst2-");
        let report2 = import_full_envelope(&dst2, &env, &opts_trusted()).expect("import 2");
        assert_eq!(report2.forget_tombstones, 1, "not-live tombstone staged");
        assert_eq!(report2.tombstones_skipped_live, 0);
        assert!(
            crate::storage::memory_is_tombstoned(&dst2, "mem-live-n2").expect("probe"),
            "the erasure receipt transferred on the empty destination"
        );
    }

    /// ★ #2210: the envelope gate refuses a NEWER `db_schema_version` and a
    /// non-"2" `spec_version` loudly (fail-closed) instead of partially
    /// ingesting. Fails on pre-#2210 code (neither value was checked).
    #[test]
    fn newer_producer_envelope_is_refused_2210() {
        let src = fresh_conn("newer-src-");
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        env.db_schema_version += 1_000;
        let dst = fresh_conn("newer-dst-");
        let err = import_full_envelope(&dst, &env, &opts_trusted())
            .expect_err("a newer-schema bundle must be refused");
        assert!(err.to_string().contains("db_schema_version"), "got: {err}");

        let mut env2 = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        env2.spec_version = "3".into();
        let err2 = import_full_envelope(&dst, &env2, &opts_trusted())
            .expect_err("a spec_version-3 bundle must be refused");
        assert!(err2.to_string().contains("spec_version"), "got: {err2}");
    }

    /// ★ #2210: the strict envelope parse refuses an unknown top-level
    /// record class (a future spec's class array must never be silently
    /// dropped). Fails on pre-#2210 code (no `deny_unknown_fields`).
    #[test]
    fn unknown_record_class_is_refused_at_parse_2210() {
        let src = fresh_conn("unknown-src-");
        let env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        let mut value = serde_json::to_value(&env).expect("to_value");
        value
            .as_object_mut()
            .expect("object")
            .insert("future_class".into(), serde_json::json!([{"x": 1}]));
        let parsed: std::result::Result<ExportEnvelope, _> = serde_json::from_value(value);
        assert!(
            parsed.is_err(),
            "an unknown top-level class must refuse to parse, not be dropped"
        );
    }

    // -----------------------------------------------------------------
    // Pre-ship 3x7 battery — HIGH-1 (wire attestation never trusted) +
    // HIGH-2 (L1-parity input validation). Each ★ test FAILS on the
    // pre-fix code (verbatim wire attest_level / zero validation).
    // -----------------------------------------------------------------

    /// ★ HIGH-1: a bundle asserting `attest_level=agent_attested` for an
    /// author with NO destination-enrolled key must land `claimed` — the
    /// wire value is NEVER trusted. Fails pre-fix (the wire metadata
    /// persisted verbatim, so `row_is_agent_attested` believed it).
    #[test]
    fn forged_wire_attest_level_lands_claimed_preship_3x7() {
        use crate::models::field_names;
        let src = fresh_conn("attest-wire-src-");
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        let mut mem = memory_fixture("mem-wire-attest-3x7", "forged attestation", "mallory");
        mem.metadata.as_object_mut().unwrap().insert(
            field_names::ATTEST_LEVEL.to_string(),
            serde_json::json!("agent_attested"),
        );
        env.memories.push(mem);

        // Trusted posture (identity preserved): still re-derived, not copied.
        let dst = fresh_conn("attest-wire-dst-");
        let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
        assert_eq!(report.memories, 1);
        assert_eq!(report.attestation_downgraded, 1, "the downgrade is counted");
        let got = crate::storage::get(&dst, "mem-wire-attest-3x7")
            .expect("get")
            .expect("row landed");
        assert_eq!(
            got.metadata
                .get(field_names::ATTEST_LEVEL)
                .and_then(|v| v.as_str()),
            Some("claimed"),
            "wire agent_attested MUST land claimed when the destination cannot verify"
        );

        // Default restamp posture: re-attributed → claimed as well.
        let dst2 = fresh_conn("attest-wire-dst2-");
        let report2 = import_full_envelope(&dst2, &env, &opts_default()).expect("import");
        assert_eq!(report2.attestation_downgraded, 1);
        let got2 = crate::storage::get(&dst2, "mem-wire-attest-3x7")
            .expect("get")
            .expect("row landed");
        assert_eq!(
            got2.metadata
                .get(field_names::ATTEST_LEVEL)
                .and_then(|v| v.as_str()),
            Some("claimed"),
            "restamped rows can never carry the wire attestation"
        );
    }

    /// ★ HIGH-1: a presented `write_signature` that FAILS verification
    /// against the destination-enrolled author key SKIPS the row (never
    /// downgraded to claimed — the #1464 invariant). Fails pre-fix (the
    /// forged signature persisted verbatim with the wire attest_level).
    #[test]
    fn forged_write_signature_is_skipped_preship_3x7() {
        use crate::models::field_names;
        use base64::Engine as _;
        let dst = fresh_conn("attest-forged-dst-");
        crate::storage::register_agent(&dst, "ai:author-3x7", "ai:generic", &[]).expect("register");
        let kp = crate::identity::keypair::generate("ai:author-3x7").expect("keygen");
        crate::storage::bind_agent_pubkey(&dst, "ai:author-3x7", &kp.public_base64())
            .expect("bind");

        let src = fresh_conn("attest-forged-src-");
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        let mut mem = memory_fixture("mem-forged-sig-3x7", "forged signature", "ai:author-3x7");
        let obj = mem.metadata.as_object_mut().unwrap();
        obj.insert(
            field_names::ATTEST_LEVEL.to_string(),
            serde_json::json!("agent_attested"),
        );
        obj.insert(
            field_names::WRITE_SIGNATURE.to_string(),
            serde_json::json!(
                base64::engine::general_purpose::STANDARD.encode([0xAB_u8; 64].as_slice())
            ),
        );
        env.memories.push(mem);

        let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
        assert_eq!(report.forged_signature_skipped, 1, "the skip is counted");
        assert_eq!(report.memories, 0, "the forged row did NOT land");
        assert!(
            crate::storage::get(&dst, "mem-forged-sig-3x7")
                .expect("get")
                .is_none(),
            "a presented-but-forged signature must skip the row, never launder to claimed"
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("mem-forged-sig-3x7")),
            "a WARN names the skipped row, got: {:?}",
            report.warnings
        );
    }

    #[test]
    fn malformed_presented_write_signatures_are_skipped_2264() {
        use crate::models::field_names;
        use base64::Engine as _;

        let malformed = [
            ("invalid-base64", serde_json::json!("%%%not-base64%%%")),
            ("non-string", serde_json::json!({"bytes": [1, 2, 3]})),
            ("empty", serde_json::json!("")),
            (
                "one-byte",
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode([0_u8; 1])),
            ),
            (
                "63-bytes",
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode([0_u8; 63])),
            ),
            (
                "65-bytes",
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode([0_u8; 65])),
            ),
        ];
        for (case, wire_value) in malformed {
            let src = fresh_conn(&format!("attest-malformed-src-{case}-"));
            let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
            let id = format!("mem-malformed-sig-{case}");
            let mut mem = memory_fixture(&id, "malformed signature", "ai:author-3x7");
            mem.metadata
                .as_object_mut()
                .unwrap()
                .insert(field_names::WRITE_SIGNATURE.to_string(), wire_value);
            env.memories.push(mem);

            let dst = fresh_conn(&format!("attest-malformed-dst-{case}-"));
            let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
            assert_eq!(report.forged_signature_skipped, 1, "case={case}");
            assert_eq!(report.memories, 0, "case={case}");
            assert!(
                crate::storage::get(&dst, &id).unwrap().is_none(),
                "case={case}"
            );
            assert!(
                report.warnings.iter().any(|warning| warning.contains(&id)),
                "case={case}; warnings={:?}",
                report.warnings
            );
        }
    }

    #[test]
    fn restamping_removes_signature_bound_to_original_agent_2264() {
        use crate::models::field_names;
        use base64::Engine as _;

        let original_agent = "ai:original-signer-2264";
        let kp = crate::identity::keypair::generate(original_agent).expect("keygen");
        let mut mem = memory_fixture("mem-restamped-sig-2264", "signed row", original_agent);
        let signature = crate::identity::attest::sign_memory_write(&kp, &mem, original_agent)
            .expect("sign original attribution");
        mem.metadata.as_object_mut().unwrap().insert(
            field_names::WRITE_SIGNATURE.to_string(),
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(signature)),
        );
        let src = fresh_conn("attest-restamp-src-2264-");
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        env.memories.push(mem);

        let dst = fresh_conn("attest-restamp-dst-2264-");
        crate::storage::register_agent(&dst, original_agent, "ai:generic", &[])
            .expect("register original signer");
        crate::storage::bind_agent_pubkey(&dst, original_agent, &kp.public_base64())
            .expect("bind original key");
        let report = import_full_envelope(&dst, &env, &opts_default()).expect("import");
        assert_eq!(report.memories, 1);

        let got = crate::storage::get(&dst, "mem-restamped-sig-2264")
            .unwrap()
            .expect("row landed claimed");
        assert_eq!(
            got.metadata
                .get(crate::META_KEY_AGENT_ID)
                .and_then(serde_json::Value::as_str),
            Some("importer")
        );
        assert_eq!(
            got.metadata
                .get(field_names::ATTEST_LEVEL)
                .and_then(serde_json::Value::as_str),
            Some("claimed")
        );
        assert!(
            got.metadata.get(field_names::WRITE_SIGNATURE).is_none(),
            "a signature bound to the original attribution must not survive restamping"
        );
    }

    /// HIGH-1 positive control: a VALID `write_signature` against the
    /// destination-enrolled author key upgrades to `agent_attested` — the
    /// re-derivation never falsely downgrades a legitimate attestation.
    #[test]
    fn valid_write_signature_verifies_agent_attested_preship_3x7() {
        use crate::models::field_names;
        use base64::Engine as _;
        let dst = fresh_conn("attest-ok-dst-");
        crate::storage::register_agent(&dst, "ai:signer-3x7", "ai:generic", &[]).expect("register");
        let kp = crate::identity::keypair::generate("ai:signer-3x7").expect("keygen");
        crate::storage::bind_agent_pubkey(&dst, "ai:signer-3x7", &kp.public_base64())
            .expect("bind");

        let mut mem = memory_fixture("mem-valid-sig-3x7", "signed row", "ai:signer-3x7");
        let sig =
            crate::identity::attest::sign_memory_write(&kp, &mem, "ai:signer-3x7").expect("sign");
        mem.metadata.as_object_mut().unwrap().insert(
            field_names::WRITE_SIGNATURE.to_string(),
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(&sig)),
        );
        let src = fresh_conn("attest-ok-src-");
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        env.memories.push(mem);

        let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
        assert_eq!(report.memories, 1);
        assert_eq!(report.forged_signature_skipped, 0);
        assert_eq!(report.attestation_downgraded, 0);
        let got = crate::storage::get(&dst, "mem-valid-sig-3x7")
            .expect("get")
            .expect("row landed");
        assert_eq!(
            got.metadata
                .get(field_names::ATTEST_LEVEL)
                .and_then(|v| v.as_str()),
            Some("agent_attested"),
            "a destination-verified signature earns agent_attested"
        );
    }

    /// ★ HIGH-1 (identity-key surface): under the default restamp posture a
    /// wire `metadata.agent_pubkey` claim is STRIPPED so an unauthenticated
    /// bundle can never seed the destination's enrolled-key lookup
    /// (`db::agent_pubkey` reads the flat metadata key off `_agents` rows).
    #[test]
    fn wire_agent_pubkey_is_stripped_by_default_preship_3x7() {
        use crate::models::field_names;
        let src = fresh_conn("pubkey-strip-src-");
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        let mut mem = memory_fixture("mem-pubkey-3x7", "identity plant", "mallory");
        mem.metadata.as_object_mut().unwrap().insert(
            field_names::AGENT_PUBKEY.to_string(),
            serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        );
        env.memories.push(mem);

        let dst = fresh_conn("pubkey-strip-dst-");
        import_full_envelope(&dst, &env, &opts_default()).expect("import");
        let got = crate::storage::get(&dst, "mem-pubkey-3x7")
            .expect("get")
            .expect("row landed");
        assert!(
            got.metadata.get(field_names::AGENT_PUBKEY).is_none(),
            "the wire identity-key claim must be stripped under restamp, got: {}",
            got.metadata
        );
    }

    /// ★ HIGH-2: rows violating the write invariants (over-MAX_CONTENT_SIZE,
    /// out-of-range priority, non-RFC3339 #1834 valid_from) are refused
    /// per-row (skip + WARN + counted) and NOT persisted; the rest of the
    /// bundle continues. An invalid link (self-link) is likewise skipped.
    /// Fails pre-fix (the v2 route ran ZERO input validation).
    #[test]
    fn invalid_rows_are_refused_not_persisted_preship_3x7() {
        let src = fresh_conn("invalid-src-");
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");

        let mut oversize = memory_fixture("mem-oversize-3x7", "oversize", "alice");
        oversize.content = "x".repeat(crate::models::MAX_CONTENT_SIZE + 1);
        env.memories.push(oversize);

        let mut bad_priority = memory_fixture("mem-priority-3x7", "bad priority", "alice");
        bad_priority.priority = 9999;
        env.memories.push(bad_priority);

        let mut bad_valid_from = memory_fixture("mem-validfrom-3x7", "bad valid_from", "alice");
        bad_valid_from.valid_from = Some("not-a-timestamp".into());
        env.memories.push(bad_valid_from);

        env.memories
            .push(memory_fixture("mem-good-3x7", "good row", "alice"));

        // Invalid link: self-link on the good row.
        env.links.push(crate::models::MemoryLink {
            source_id: "mem-good-3x7".into(),
            target_id: "mem-good-3x7".into(),
            relation: crate::models::MemoryLinkRelation::RelatedTo,
            created_at: "2026-07-14T00:00:00Z".into(),
            signature: None,
            observed_by: None,
            valid_from: None,
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        });

        let dst = fresh_conn("invalid-dst-");
        let report = import_full_envelope(&dst, &env, &opts_trusted()).expect("import");
        assert_eq!(report.invalid_skipped, 3, "all three invalid rows counted");
        assert_eq!(report.memories, 1, "only the good row landed");
        assert_eq!(report.invalid_links_skipped, 1, "the self-link is refused");
        for id in ["mem-oversize-3x7", "mem-priority-3x7", "mem-validfrom-3x7"] {
            assert!(
                crate::storage::get(&dst, id).expect("get").is_none(),
                "invalid row {id} must NOT be persisted"
            );
        }
        assert!(
            crate::storage::get(&dst, "mem-good-3x7")
                .expect("get")
                .is_some(),
            "the valid row still lands (per-row skip, never a batch drop)"
        );
        let links: i64 = dst
            .query_row("SELECT COUNT(*) FROM memory_links", [], |r| r.get(0))
            .expect("count");
        assert_eq!(links, 0, "the invalid link must NOT be persisted");
        assert_eq!(
            report.warnings.len(),
            4,
            "each refusal carries a WARN, got: {:?}",
            report.warnings
        );
    }

    /// ★ F1 (audit finding on the HIGH-2 fix): a bundle link whose endpoint
    /// memory was SKIPPED earlier in the import (here: an invalid row the
    /// HIGH-2 gate refused) must be skipped + counted — NOT reach the raw
    /// INSERT, whose `REFERENCES memories(id)` FK (with
    /// `PRAGMA foreign_keys=ON`, and `OR IGNORE` NOT covering FK
    /// violations) would abort the WHOLE all-or-nothing transaction with
    /// zero rows landed. Fails pre-fix (the whole import errors and the
    /// good row never lands).
    #[test]
    fn link_to_skipped_memory_does_not_fk_abort_the_import_preship_3x7_f1() {
        let src = fresh_conn("fk-link-src-");
        let mut env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");

        // A row the HIGH-2 validation gate will SKIP (priority out of range)…
        let mut bad = memory_fixture("mem-bad-f1", "bad endpoint", "alice");
        bad.priority = 9999;
        env.memories.push(bad);
        // …and a good row that must still land.
        env.memories
            .push(memory_fixture("mem-good-f1", "good endpoint", "alice"));

        let mk_link = |source: &str, target: &str| crate::models::MemoryLink {
            source_id: source.into(),
            target_id: target.into(),
            relation: crate::models::MemoryLinkRelation::RelatedTo,
            created_at: "2026-07-14T00:00:00Z".into(),
            signature: None,
            observed_by: None,
            valid_from: None,
            valid_until: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        };
        // Edge referencing the SKIPPED row (the F1 FK trap)…
        env.links.push(mk_link("mem-bad-f1", "mem-good-f1"));
        // …an edge to an id never present anywhere…
        env.links
            .push(mk_link("mem-good-f1", "mem-never-existed-f1"));
        // …and a control edge between two PRESENT rows (a second good
        // neighbour — a self-link would trip the validity gate instead).
        env.memories
            .push(memory_fixture("mem-good2-f1", "good endpoint 2", "alice"));
        env.links.push(mk_link("mem-good-f1", "mem-good2-f1"));

        let dst = fresh_conn("fk-link-dst-");
        let report = import_full_envelope(&dst, &env, &opts_trusted())
            .expect("the import must COMMIT — a dangling link is a per-row skip, not an abort");
        assert!(report.committed);
        assert_eq!(report.invalid_skipped, 1, "the bad endpoint row skipped");
        assert_eq!(report.memories, 2, "both good rows landed");
        assert_eq!(
            report.links_skipped_missing_endpoint, 2,
            "both dangling edges skipped + counted"
        );
        assert_eq!(report.links, 1, "the control edge landed");
        assert!(
            crate::storage::get(&dst, "mem-good-f1")
                .expect("get")
                .is_some(),
            "the rest of the bundle still commits"
        );
        let links: i64 = dst
            .query_row("SELECT COUNT(*) FROM memory_links", [], |r| r.get(0))
            .expect("count");
        assert_eq!(links, 1, "only the control edge persisted");
        assert!(
            report
                .warnings
                .iter()
                .filter(|w| w.contains("endpoint memory is absent"))
                .count()
                == 2,
            "each dangling edge carries a WARN, got: {:?}",
            report.warnings
        );
    }
}
