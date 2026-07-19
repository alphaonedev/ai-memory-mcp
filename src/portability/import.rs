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
    // ── ALL-OR-NOTHING: one transaction wraps the entire apply. ──
    // `unchecked_transaction` issues BEGIN DEFERRED on `&Connection`; every
    // helper below is either a raw `execute` or a transaction-free storage
    // primitive (`storage::insert` / `storage::get` open no inner tx), so no
    // nested-transaction hazard arises. On any `?` below the `Transaction`
    // drops here without commit → SQLite ROLLBACK → zero rows applied.
    let tx = conn
        .unchecked_transaction()
        .context("portability import: could not open the atomic import transaction")?;

    let mut report = apply_all_classes(&tx, env, opts)?;

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

/// Stage every class into `conn` (a live transaction). Any `?` here aborts the
/// whole import (the caller's transaction rolls back).
fn apply_all_classes(
    conn: &Connection,
    env: &ExportEnvelope,
    opts: &ImportOptions,
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
                target: "portability::import",
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
        // `imported_from_agent_id`.
        if !opts.trust_source {
            let original = staged
                .metadata
                .get("agent_id")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string);
            if let Some(obj) = staged.metadata.as_object_mut() {
                obj.insert(
                    "agent_id".to_string(),
                    serde_json::Value::String(opts.caller_agent_id.clone()),
                );
                if let Some(orig) = original.as_ref()
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
        // attest_level — a loss). `OR IGNORE` is idempotent on the natural key
        // and silently skips an edge whose endpoint memory is absent (e.g. a
        // link to a tombstoned row), so it never spuriously aborts the import.
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
        crate::storage::insert(&src, &mem).expect("seed src");
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
        crate::storage::insert(&src, &mem).expect("seed src");
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
        crate::storage::insert(&src, &mem).expect("seed src");
        let env = build_full_envelope(&src, "src", "2026-07-14T00:00:00Z").expect("export");
        assert!(
            env.signed_events.is_empty(),
            "fixture: the bundle is spine-less"
        );

        let dst = fresh_conn("restamp-dst-");
        let report = import_full_envelope(&dst, &env, &opts_default()).expect("import");
        assert_eq!(report.restamped, 1, "the restamp is counted");
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
        crate::storage::insert(&src, &incoming).expect("seed src");
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
}
