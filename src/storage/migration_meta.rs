// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! ARCH-8 (FX-C4-batch2, 2026-05-26) — per-migration metadata matrix.
//!
//! The substrate ships a 95-step migration ladder (v2 → v96) whose
//! "reversible? data-loss-risk? idempotent?" contract an operator needs
//! BEFORE they plan a rollback — restore-from-backup is the only
//! fallback for an irreversible arm, and they must know which arms
//! those are. The matrix below makes that contract explicit per
//! migration so `ai-memory migrate --plan` can read it, release notes
//! can quote it, and the `arch_8_*` tests can assert every ladder step
//! has a populated, ARM-DERIVED entry.
//!
//! # #3161-adjacent honesty note (#3158, v1.0.0)
//!
//! Before #3158 this matrix was GUESSED, not derived: 40+ rows named a
//! migration that does not exist (v43 was `ADD_RECURSIVE_LEARNING_LEDGER`
//! — `grep recursive_learning src/storage/migrations.rs` has no match —
//! while the real v43 arm applies
//! `migrations/sqlite/0037_v07_persona_signing_atomicity.sql`, whose first
//! statement is an IRREVERSIBLE `UPDATE memory_links SET attest_level =
//! 'unsigned' …`), and there were NO rows at all for v54–v88 because the
//! tail row was keyed to `current_schema_version()` — so `meta_for(54)`
//! returned `None`, `meta_for(89)` returned v54's semantics, and the
//! lockstep gate `arch_8_ladder_terminates_at_current_schema_version`
//! passed BY CONSTRUCTION and could never fail. Every row below is now
//! derived from the arm's actual SQL by the rule in
//! [`MIGRATION_LADDER`]'s docs, keyed to a LITERAL version, and pinned by
//! tests that read `migrations.rs` itself.
//!
//! Adding a migration: extend [`MIGRATION_LADDER`] in lockstep with the
//! `if version < N` arm in `migrations.rs`. The `arch_8_*` tests in this
//! module catch ladder/matrix drift, and
//! `scripts/check-migration-ladder.sh` rule (g) enforces the same
//! one-row-per-arm coverage from the shell lane.

/// Data-loss class of a migration — what CALLER-VISIBLE data the arm
/// destroys, at apply time or on a revert.
///
/// `None` = nothing caller-visible is destroyed. No table or column is
/// dropped, and every write either creates a value where none existed
/// (a `NULL` → value backfill) or preserves the value's meaning (a
/// rendering normalization). An arm can be `None` here and still
/// `reversible: false` — see [`MigrationMeta::reversible`].
///
/// `Column` = the contents of one or more PRE-EXISTING columns are
/// destroyed or become unreachable: a destructive overwrite of
/// caller-supplied non-`NULL` values (v43), a dropped column, or a
/// re-shaping whose revert would collapse a dimension (v50's
/// `(agent_id)` → `(agent_id, namespace)` PK widening).
///
/// `Table` = an entire table's rows are dropped WITHOUT being carried
/// forward. Highest tier. No arm in the current ladder is `Table` —
/// every full-table rebuild (v33/v36/v50/v63/v66/v80) copies every row
/// with an explicit `INSERT … SELECT` before the `DROP`.
///
/// DERIVED-ARTIFACT CARVE-OUT (North Star): dropping an index, an FTS5
/// shadow table, or a `GENERATED … STORED` column is NOT a data-loss
/// event at any tier — those are disposable artifacts regenerable from
/// the durable memory TEXT, which is the source of truth. The postgres
/// v57 (`DROP INDEX memories_content_fts`) and v89 (`DROP COLUMN tsv`
/// then re-add with `tags` folded in) arms are `None` for that reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLossRisk {
    None,
    Column,
    Table,
}

/// Which adapter's ladder carries the arm for a given schema version.
///
/// Every version number is shared by BOTH adapters (they must agree on
/// `CURRENT_SCHEMA_VERSION`), but a step's DDL does not have to exist on
/// both — several versions are a real change on one backend and a
/// version-stamp no-op on the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LadderArm {
    /// The sqlite ladder carries an `if version < N` arm for this step
    /// (`storage::migrations::migrate`). The flags describe THAT arm.
    /// (The postgres twin may be a version-stamp no-op — e.g. v53's FTS5
    /// trigger rescope, v55's `updated_at` index — which cannot make the
    /// sqlite-derived flags less safe.)
    Sqlite,
    /// NO sqlite arm exists: the schema change is postgres-only and
    /// sqlite reaches the number via the unconditional stamp at the end
    /// of `migrate`. The flags describe the POSTGRES `migrate_vN` arm.
    PostgresOnly,
}

/// Per-migration metadata record.
#[derive(Debug, Clone, Copy)]
pub struct MigrationMeta {
    /// Target schema version this migration produces (i.e. the
    /// `CURRENT_SCHEMA_VERSION` value reached AFTER it runs). ALWAYS a
    /// LITERAL — never `current_schema_version()`, which would make the
    /// tail row silently re-key itself on every version bump and defeat
    /// the lockstep gate (#3158).
    pub version: i64,
    /// Short human-readable name. Convention: SCREAMING_SNAKE
    /// summarising the schema delta, using identifiers that actually
    /// appear in the arm (or in the migration `.sql` filename it
    /// sources) — pinned by
    /// `arch_8_meta_row_names_are_grounded_in_their_arm`.
    pub name: &'static str,
    /// `true` when re-applying the arm's statements against a DB already
    /// at/above this version is a NO-OP: every DDL is `IF NOT EXISTS` /
    /// `DROP … IF EXISTS`+recreate or gated by a Rust
    /// column/table/trigger-existence probe, and every DML is
    /// `INSERT OR IGNORE` or an `UPDATE` whose `WHERE` predicate is
    /// self-extinguishing (matches zero rows on the second pass).
    pub idempotent: bool,
    /// `true` when a revert is EXACTLY "lower the `schema_version` row".
    ///
    /// `false` when the arm (a) DROPs or REBUILDs a table, or (b) writes
    /// row data (`UPDATE` / `INSERT` / `DELETE`) into a table that
    /// EXISTED BEFORE the arm — those writes are not undone by lowering
    /// the version, so the pre-migration row state is unrecoverable
    /// without the pre-migration snapshot `migrate` takes.
    ///
    /// `reversible: false` does NOT imply data loss: see
    /// [`DataLossRisk`], which is the separate axis. Most irreversible
    /// arms here are `NULL` → value backfills that destroy nothing.
    pub reversible: bool,
    /// Data-loss class. See [`DataLossRisk`].
    pub data_loss_risk: DataLossRisk,
    /// Which adapter's ladder the flags above describe. See
    /// [`LadderArm`].
    pub arm: LadderArm,
}

use self::DataLossRisk::{Column as ColumnLoss, None as NoLoss};
use self::LadderArm::{PostgresOnly, Sqlite};

/// Table constructor — keeps the 89-row matrix scannable as a table
/// rather than 700 lines of struct literals.
///
/// Argument order: `version, name, idempotent, reversible,
/// data_loss_risk, arm`.
const fn meta(
    version: i64,
    name: &'static str,
    idempotent: bool,
    reversible: bool,
    data_loss_risk: DataLossRisk,
    arm: LadderArm,
) -> MigrationMeta {
    MigrationMeta {
        version,
        name,
        idempotent,
        reversible,
        data_loss_risk,
        arm,
    }
}

/// Canonical migration matrix. Every sqlite `if version < N` arm in
/// `migrations.rs::apply_migrations` MUST have exactly one entry here,
/// and every postgres-only step MUST have one flagged
/// [`LadderArm::PostgresOnly`]. The `arch_8_*` tests assert (a) exact
/// one-to-one coverage against the arms parsed out of `migrations.rs`,
/// (b) gap-free strict monotonicity from v2 to `CURRENT_SCHEMA_VERSION`,
/// (c) a LITERAL tail key, and (d) that each row's name is grounded in
/// its arm's source text.
///
/// # Classification rule (#3158) — applied uniformly to every arm
///
/// Read the arm's executed SQL (its inline statements PLUS the
/// `migrations/<backend>/NNNN_*.sql` file it sources) and classify:
///
/// 1. `idempotent` — TRUE iff re-applying the statements against an
///    already-at-target DB changes nothing (see
///    [`MigrationMeta::idempotent`]). The two FALSE rows (v33, v66) are
///    the two full-table rebuilds that carry NO
///    already-rebuilt probe: their `CREATE TABLE <shadow>` /
///    `INSERT … SELECT` / `DROP` / `RENAME` dance would re-run and drop
///    the table's triggers a second time. Both are safe in practice ONLY
///    because the `if version < N` guard fires once.
/// 2. `reversible` — TRUE iff purely structural-additive with no row
///    write into a pre-existing table (see
///    [`MigrationMeta::reversible`]).
/// 3. `data_loss_risk` — see [`DataLossRisk`], including the
///    derived-artifact carve-out.
///
/// The rule is deliberately CONSERVATIVE on `reversible`: a `NULL` →
/// value backfill into a column the arm itself added (v15, v18, v23,
/// v31) destroys nothing, but it is still not undone by lowering the
/// version, so it is recorded as irreversible. Over-warning costs an
/// operator one snapshot; under-warning costs them their data.
#[rustfmt::skip]
pub const MIGRATION_LADDER: &[MigrationMeta] = &[
    meta(2, "ADD_CONFIDENCE_AND_SOURCE_COLUMNS", true, true, NoLoss, Sqlite),
    meta(3, "ADD_EMBEDDING_COLUMN", true, true, NoLoss, Sqlite),
    meta(4, "ADD_ARCHIVED_MEMORIES_TABLE", true, true, NoLoss, Sqlite),
    meta(5, "ADD_NAMESPACE_META_TABLE", true, true, NoLoss, Sqlite),
    meta(6, "ADD_NAMESPACE_PARENT_NAMESPACE", true, true, NoLoss, Sqlite),
    meta(7, "ADD_METADATA_COLUMNS", true, true, NoLoss, Sqlite),
    meta(8, "ADD_PENDING_ACTIONS_TABLE", true, true, NoLoss, Sqlite),
    meta(9, "ADD_PENDING_ACTION_APPROVALS", true, true, NoLoss, Sqlite),
    meta(10, "ADD_SCOPE_IDX_GENERATED_COLUMN", true, true, NoLoss, Sqlite),
    meta(11, "ADD_SYNC_STATE_TABLE", true, true, NoLoss, Sqlite),
    meta(12, "ADD_SYNC_STATE_LAST_PUSHED_AT", true, true, NoLoss, Sqlite),
    meta(13, "ADD_SUBSCRIPTIONS_TABLE", true, true, NoLoss, Sqlite),
    meta(14, "ADD_AGENT_ID_IDX_GENERATED_COLUMN", true, true, NoLoss, Sqlite),
    // v15 backfills `memory_links.valid_from` from the source memory's
    // `created_at` — a row write into the PRE-EXISTING `memory_links`
    // table, hence irreversible; the column is new, so nothing is lost.
    meta(15, "ADD_MEMORY_LINKS_TEMPORAL_COLUMNS", true, false, NoLoss, Sqlite),
    // v16 emits NO sqlite DDL — it exists so the postgres peers'
    // `text_pattern_ops` prefix index lands in the same generation.
    meta(16, "NOOP_NAMESPACE_PREFIX_INDEX_PARITY", true, true, NoLoss, Sqlite),
    // v17 rewrites the PRE-EXISTING `memories.metadata` JSON
    // (`json_set($.governance.inherit)`) — irreversible. Instant/meaning
    // preserving (it only ADDS an absent key), so no data loss.
    meta(17, "BACKFILL_GOVERNANCE_INHERIT", true, false, NoLoss, Sqlite),
    // v18 backfills `memories.embedding_dim` and
    // `archived_memories.original_tier` — both columns THIS arm adds, but
    // the writes land in pre-existing tables.
    meta(18, "ADD_EMBEDDING_DIM_AND_ARCHIVE_PRESERVATION", true, false, NoLoss, Sqlite),
    meta(19, "ADD_SUBSCRIPTION_EVENT_TYPES", true, true, NoLoss, Sqlite),
    meta(20, "ADD_AUDIT_LOG_TABLE", true, true, NoLoss, Sqlite),
    meta(21, "ADD_PENDING_ACTION_TIMEOUTS", true, true, NoLoss, Sqlite),
    meta(22, "ADD_MEMORY_TRANSCRIPTS_TABLE", true, true, NoLoss, Sqlite),
    // v23 backfills the new `memory_links.attest_level` to 'unsigned'
    // WHERE NULL — pre-existing table, so irreversible; nothing lost.
    meta(23, "ADD_MEMORY_LINKS_ATTEST_LEVEL", true, false, NoLoss, Sqlite),
    meta(24, "ADD_MEMORY_TRANSCRIPT_LINKS_TABLE", true, true, NoLoss, Sqlite),
    meta(25, "ADD_TRANSCRIPT_ARCHIVED_AT", true, true, NoLoss, Sqlite),
    meta(26, "ADD_SIGNED_EVENTS_TABLE", true, true, NoLoss, Sqlite),
    meta(27, "ADD_SUBSCRIPTION_DLQ_AND_CORRELATION_ID", true, true, NoLoss, Sqlite),
    meta(28, "ADD_AGENT_QUOTAS_TABLE", true, true, NoLoss, Sqlite),
    meta(29, "ADD_REFLECTION_DEPTH", true, true, NoLoss, Sqlite),
    // v30's `INSERT OR IGNORE` seeds land in the `governance_rules` table
    // THIS arm creates, so a revert drops nothing an older binary knew.
    meta(30, "ADD_GOVERNANCE_RULES_TABLE", true, true, NoLoss, Sqlite),
    meta(31, "ADD_MEMORY_KIND", true, false, NoLoss, Sqlite),
    meta(32, "ADD_SKILLS_TABLES", true, true, NoLoss, Sqlite),
    // v33 = the FIRST `memory_links` full-table rebuild (0027), promoting
    // the v23 relation RAISE triggers to a column CHECK. NOT idempotent:
    // unlike v36/v63 it has NO already-rebuilt probe, so re-applying its
    // batch would rebuild again — and drop the table's triggers again
    // (the v63 -> v65 lesson). Every row is carried by an explicit
    // `INSERT … SELECT`, so no data is lost.
    meta(33, "REBUILD_MEMORY_LINKS_RELATION_CHECK", false, false, NoLoss, Sqlite),
    // v34 assigns the `signed_events` prev_hash/sequence chain over the
    // PRE-EXISTING rows (`migrate_v34_backfill_chain`) — irreversible; the
    // backfill skips already-sequenced rows, so it is idempotent.
    meta(34, "BACKFILL_SIGNED_EVENTS_CHAIN", true, false, NoLoss, Sqlite),
    meta(35, "ADD_OFFLOADED_BLOBS_TABLE", true, true, NoLoss, Sqlite),
    // v36 rebuilds `memory_links` a second time (admit `derives_from`);
    // probe-guarded on the declared SQL containing the new relation.
    meta(36, "ADD_ATOMISATION_COLUMNS_AND_REBUILD_LINKS", true, false, NoLoss, Sqlite),
    meta(37, "ADD_PERSONA_ENTITY_COLUMNS", true, true, NoLoss, Sqlite),
    meta(38, "ADD_FORM4_PROVENANCE_COLUMNS", true, true, NoLoss, Sqlite),
    meta(39, "ADD_CONFIDENCE_CALIBRATION_COLUMNS", true, true, NoLoss, Sqlite),
    meta(40, "ADD_SIGNED_EVENTS_DLQ_TABLE", true, true, NoLoss, Sqlite),
    // v41 adds `confidence_shadow_observations.source` and backfills it
    // from the joined memories row — pre-existing table (created at v39).
    meta(41, "ADD_SHADOW_OBSERVATION_SOURCE", true, false, NoLoss, Sqlite),
    // v42 adds `memories.mentioned_entity_id` and backfills it from
    // `metadata.entity_id` + `[entity:X]` title markers.
    meta(42, "ADD_MENTIONED_ENTITY_ID", true, false, NoLoss, Sqlite),
    // v43 (#3158 headline) — `0037_v07_persona_signing_atomicity.sql`
    // opens with `UPDATE memory_links SET attest_level = 'unsigned' WHERE
    // attest_level IN ('self_signed','peer_attested') AND (signature IS
    // NULL OR length(signature) != 64)`. That DESTROYS the caller-supplied
    // non-NULL attest_level of every phantom-signed edge — the only
    // destructive overwrite in the ladder — then installs the
    // BEFORE INSERT/UPDATE trigger pair that refuses future ones. The old
    // matrix claimed `ADD_RECURSIVE_LEARNING_LEDGER / reversible: true /
    // DataLossRisk::None`: wrong on all three.
    meta(43, "PERSONA_SIGNING_ATOMICITY", true, false, ColumnLoss, Sqlite),
    meta(44, "ADD_ENCRYPTED_ENVELOPE_COLUMN", true, true, NoLoss, Sqlite),
    meta(45, "ADD_VERSION_OPTIMISTIC_CONCURRENCY", true, true, NoLoss, Sqlite),
    // v46 backfills `memories.source_uri` (a column that shipped at v38)
    // from `metadata.source_uri` / `citations[0].uri` — the NULL state of
    // a PRE-EXISTING column is overwritten, so irreversible.
    meta(46, "BACKFILL_SOURCE_URI", true, false, NoLoss, Sqlite),
    meta(47, "ADD_RECALL_OBSERVATIONS_TABLE", true, true, NoLoss, Sqlite),
    meta(48, "ADD_FEDERATION_PUSH_DLQ_TABLE", true, true, NoLoss, Sqlite),
    meta(49, "EXTEND_ARCHIVED_MEMORIES_COLUMNS", true, true, NoLoss, Sqlite),
    // v50 widens the `agent_quotas` PK from `(agent_id)` to
    // `(agent_id, namespace)` via the shadow-table swap. Rows are carried
    // verbatim onto the `_global` sentinel, but a revert to the
    // single-column PK would COLLAPSE per-namespace rows — the namespace
    // dimension's data becomes unreachable, hence `Column`.
    meta(50, "EXPAND_AGENT_QUOTAS_PK", true, false, ColumnLoss, Sqlite),
    meta(51, "ADD_FEDERATION_NONCE_CACHE", true, true, NoLoss, Sqlite),
    meta(52, "ADD_TRANSCRIPT_LINE_DEDUP", true, true, NoLoss, Sqlite),
    // v53 DROP/CREATEs the `memories_au` FTS5 sync trigger to scope it to
    // (title, content, tags). A trigger swap, not a table rebuild; the
    // FTS5 shadow it governs is a derived artifact. Postgres: no-op.
    meta(53, "SCOPE_MEMORIES_AU_TRIGGER_TO_FTS_COLUMNS", true, true, NoLoss, Sqlite),
    // v54 stamps `created_at + Tier::default_ttl_secs()` onto every
    // NULL-expiry mid/short row. Only NULL-expiry rows match (idempotent),
    // nothing is dropped (NoLoss), but the original NULL set is
    // unrecoverable once stamped — irreversible. Applied by BOTH adapters.
    meta(54, "BACKFILL_NULL_EXPIRY_TIER_DEFAULT", true, false, NoLoss, Sqlite),
    meta(55, "ADD_IDX_MEMORIES_UPDATED_AT", true, true, NoLoss, Sqlite),
    meta(56, "ADD_LIST_ORDER_COMPOSITE_INDEXES", true, true, NoLoss, Sqlite),
    // v57 is POSTGRES-ONLY: `ADD COLUMN IF NOT EXISTS tsv tsvector
    // GENERATED ALWAYS AS (…) STORED` + `memories_tsv_gin`, then
    // `DROP INDEX IF EXISTS memories_content_fts`. SQLite has no arm —
    // its FTS5 virtual table already materialises the indexed text — so
    // it reaches v57 via the unconditional stamp. The dropped index and
    // the generated column are derived artifacts (carve-out above).
    meta(57, "ADD_TSV_GENERATED_COLUMN", true, true, NoLoss, PostgresOnly),
    meta(58, "ADD_RECALL_OBSERVATIONS_IDENTITY", true, true, NoLoss, Sqlite),
    meta(59, "ADD_ACTION_SUBSTRATE_TABLES", true, true, NoLoss, Sqlite),
    meta(60, "ADD_SIGNED_SIGNALS_TABLE", true, true, NoLoss, Sqlite),
    meta(61, "ADD_ATTESTED_CHECKPOINTS_TABLE", true, true, NoLoss, Sqlite),
    meta(62, "ADD_ROUTINES_TABLES", true, true, NoLoss, Sqlite),
    // v63 = the third `memory_links` rebuild (6 -> 9 relations).
    // Probe-guarded, so idempotent; it is the arm that DROPPED the
    // signature triggers v65 had to restore (the project's rebuild
    // lesson) — triggers are enforcement, not data, so still NoLoss.
    meta(63, "REBUILD_MEMORY_LINKS_TYPED_COGNITION_RELATIONS", true, false, NoLoss, Sqlite),
    meta(64, "ADD_LIFECYCLE_STATE", true, true, NoLoss, Sqlite),
    meta(65, "RESTORE_MEMORY_LINKS_SIGNATURE_TRIGGERS", true, true, NoLoss, Sqlite),
    // v66 rebuilds `governance_rules` to widen the severity CHECK. Gated
    // only on the TABLE existing — there is NO already-rebuilt probe, so
    // like v33 a re-apply would redo the whole dance: NOT idempotent.
    // Every column (including the operator signature + attest_level) is
    // carried by an explicit `INSERT … SELECT`, so NoLoss.
    meta(66, "REBUILD_GOVERNANCE_RULES_ESCALATE_SEVERITY", false, false, NoLoss, Sqlite),
    meta(67, "ADD_TARGET_AGENT_ID_IDX", true, true, NoLoss, Sqlite),
    meta(68, "ADD_ARCHIVED_ENCRYPTED_ENVELOPE", true, true, NoLoss, Sqlite),
    // v69 is POSTGRES-ONLY (`kg_projection_outbox` backs the staggered
    // Apache-AGE cold path; AGE is postgres-only). SQLite stamps it.
    meta(69, "ADD_KG_PROJECTION_OUTBOX_TABLE", true, true, NoLoss, PostgresOnly),
    meta(70, "ADD_ARCHIVED_MEMORY_LINKS_TABLE", true, true, NoLoss, Sqlite),
    meta(71, "ADD_FORGET_TOMBSTONES_TABLE", true, true, NoLoss, Sqlite),
    meta(72, "ADD_MEMORY_REVISIONS_TABLE", true, true, NoLoss, Sqlite),
    meta(73, "ADD_SIGNED_EVENTS_CAUSE_HASH", true, true, NoLoss, Sqlite),
    // v74 adds `memories.cid` / `.cid_genesis` and then runs
    // `backfill_memory_cids` over the PRE-EXISTING rows — irreversible;
    // the sweep only touches `cid IS NULL` rows, so idempotent.
    meta(74, "ADD_MEMORIES_CID_AND_BACKFILL", true, false, NoLoss, Sqlite),
    meta(75, "ADD_MEMORY_LINKS_LINEAGE_CID", true, true, NoLoss, Sqlite),
    meta(76, "ADD_AGENT_LINEAGE_TABLE", true, true, NoLoss, Sqlite),
    // v77 adds `recall_observations.folded` and marks every pre-existing
    // row folded (they were already sync-touched at recall time).
    meta(77, "ADD_RECALL_OBSERVATIONS_FOLDED", true, false, NoLoss, Sqlite),
    meta(78, "ADD_MODEL_ATTESTATIONS_TABLE", true, true, NoLoss, Sqlite),
    meta(79, "ADD_CRYPTO_CORE_COLUMNS_AND_SUBKEY_CERTS", true, true, NoLoss, Sqlite),
    // v80 rebuilds `agent_lineage` to widen the reason CHECK ('revocation')
    // and add the two custody columns. Probe-guarded (idempotent); every
    // row is carried verbatim; `agent_lineage` has no triggers and no
    // secondary indexes, so the rebuild drops nothing to recreate.
    meta(80, "REBUILD_AGENT_LINEAGE_CUSTODY_REVOCATION", true, false, NoLoss, Sqlite),
    meta(81, "ADD_LINEAGE_RECOVERY_QUORUM", true, true, NoLoss, Sqlite),
    meta(82, "ADD_SKILL_RETIRE_COLUMNS", true, true, NoLoss, Sqlite),
    meta(83, "ADD_AGENT_API_KEYS_TABLE", true, true, NoLoss, Sqlite),
    meta(84, "ADD_EMBEDDING_SPACE", true, true, NoLoss, Sqlite),
    meta(85, "ADD_ARCHIVED_VALID_TIME", true, true, NoLoss, Sqlite),
    // v86 rewrites legacy `valid_from`/`valid_until` RENDERINGS on
    // `memories` + `archived_memories` to the one canonical fixed-UTC
    // form. Instant-preserving and fail-safe (an unparseable value keeps
    // its exact bytes) — NoLoss — but the original rendering is gone, and
    // the writes land in pre-existing tables: irreversible.
    meta(86, "CANONICALIZE_VALID_TIME_RENDERINGS", true, false, NoLoss, Sqlite),
    // v87 mirrors `kind_provenance` onto the archive (additive) AND
    // canonicalizes legacy `expires_at` / `original_expires_at`
    // renderings — same contract as v86.
    meta(87, "ADD_ARCHIVED_KIND_PROVENANCE_AND_CANONICALIZE_EXPIRY", true, false, NoLoss, Sqlite),
    // v88 is POSTGRES-ONLY: the v56 composite list/archive ordering
    // indexes, finally on postgres, built `CONCURRENTLY` + FAIL-OPEN.
    // SQLite has carried them since v56, so there is no sqlite v88 arm.
    meta(88, "ADD_LIST_ORDER_COMPOSITE_INDEXES_PG", true, true, NoLoss, PostgresOnly),
    // v89 is POSTGRES-ONLY: DROP + re-ADD the STORED generated `tsv`
    // column with `tags` folded in, then reindex `memories_tsv_gin`.
    // Dropping a generated column regenerable from the durable
    // title/content/tags TEXT is the derived-artifact carve-out, not data
    // loss. SQLite's FTS5 already indexes tags, so it stamps a no-op.
    meta(89, "REBUILD_TSV_INCLUDE_TAGS", true, true, NoLoss, PostgresOnly),
    // v90 (#2385, v1.0.0) — ARCHIVE CID PARITY. Additive `cid` TEXT +
    // `cid_genesis` BLOB/BYTEA on `archived_memories`, probe-guarded,
    // no backfill, no full-table rebuild. Settled (literal arm).
    // Postgres twin is `PostgresStore::migrate_v90`.
    meta(90, "ARCHIVED_CID_PARITY", true, true, NoLoss, Sqlite),
    // v91 (#3250, v1.0.0) — ARCHIVE-LINK CID PARITY. Additive `source_cid`
    // TEXT + `target_cid` TEXT on `archived_memory_links`. Literal tail:
    // MUST equal CURRENT_SCHEMA_VERSION. Postgres twin is
    // `PostgresStore::migrate_v91`.
    meta(91, "ARCHIVED_MEMORY_LINKS_CID_PARITY", true, true, NoLoss, Sqlite),
    // v92 (#2555, v1.0.0) — SCHEMA_VERSION BOUND. Adds the
    // `version <= MAX_SCHEMA_VERSION` upper CHECK so an unconstrained
    // fleet kill-switch write (`INSERT ... VALUES (2147483647)`) is rejected at
    // the boundary. SQLite: full-table rebuild (no indexes/triggers → lossless,
    // idempotent — applied only when the CHECK is absent). Literal tail: MUST
    // equal CURRENT_SCHEMA_VERSION. Postgres twin is
    // `PostgresStore::migrate_v92` (ADD CONSTRAINT).
    meta(92, "SCHEMA_VERSION_BOUND", true, true, NoLoss, Sqlite),
    // v93 (#3323, v1.0.0) — PER-LINEAGE + PER-NAMESPACE TOKEN/COST
    // ACCOUNTING. Additive standalone advisory `token_cost_counters` table
    // (`CREATE TABLE IF NOT EXISTS`), idempotent, revert = lower the stamp
    // (no pre-existing row is rewritten), no data loss. Postgres twin is
    // `PostgresStore::migrate_v93`.
    meta(93, "TOKEN_COST_COUNTERS", true, true, NoLoss, Sqlite),
    // v94 (#3324, #3266 MVG, v1.0.0) — LIFECYCLE_STATE INDEX. Additive
    // `idx_memories_lifecycle_state` supporting the system-only (hidden)
    // lifecycle-state listings, shipped with the new `contaminated`
    // auto-propagated invalidation-taint vocabulary (the value itself is
    // migration-free — no column/CHECK change). `IF NOT EXISTS`-idempotent,
    // reversible (revert is DROP INDEX), NoLoss. Literal tail: MUST equal
    // CURRENT_SCHEMA_VERSION. Slots after #3323's settled v93. Postgres twin
    // is `PostgresStore::migrate_v94`.
    meta(94, "LIFECYCLE_STATE_INDEX", true, true, NoLoss, Sqlite),
    // v95 (#3419, v1.0.0) — ATTESTED-WRITE REPLAY LEDGER. Additive standalone
    // `attested_write_ledger` table (`CREATE TABLE IF NOT EXISTS`), one row per
    // accepted signed-write envelope, keyed on the SHA-256
    // `(agent_id, created_at, signature)` fingerprint as the PRIMARY KEY so the
    // admit-once decision is the uniqueness constraint itself. Idempotent; no
    // backfill and no pre-existing row is read or rewritten, so revert is DROP
    // TABLE + lowering the stamp (NoLoss — the ledger is derived
    // replay-protection state, regenerable by simply starting to record again,
    // never durable memory truth). Literal tail: MUST equal
    // CURRENT_SCHEMA_VERSION at the time it landed; v97 (#3464) is the tail now.
    // Postgres twin is `PostgresStore::migrate_v95`.
    meta(95, "ATTESTED_WRITE_REPLAY_LEDGER", true, true, NoLoss, Sqlite),
    // v96 (#3344, v1.0.0) — DURABLE EMBED SKIP LIST. Additive standalone
    // `embed_skip` table (CREATE TABLE IF NOT EXISTS + content/embed
    // clear triggers) so boot/backfill remember undecryptable and oversize
    // rows keyed by id + encryption-key fingerprint. Idempotent, revert =
    // DROP TABLE/TRIGGER, NoLoss (derived cache, not durable memory truth).
    // Settled literal rung after #3419's v95. Postgres twin is
    // `PostgresStore::migrate_v96`.
    meta(96, "EMBED_SKIP", true, true, NoLoss, Sqlite),
    // v97 (#3464, v1.0.0, security-high) — APPEND-ONLY AGENT PUBKEY HISTORY.
    // Creates `agent_pubkey_history` (composite PK `(agent_id, version)`), the
    // durable single-use bind-challenge table, their ladder-owned indexes, and
    // BACKFILLS every live `metadata.agent_pubkey` as version 1 under the
    // `legacy_unproven` authority. Two triggers then make history authoritative
    // over the flat key mirrors on every future generic write; explicit bind
    // and lineage update history first in the same transaction. Reversibility
    // is drop-trigger then drop-table; the flat mirror an operator rolls back
    // to remains in `memories` — NoLoss. `CREATE TABLE IF NOT EXISTS` +
    // `CREATE INDEX IF NOT EXISTS` + `INSERT OR IGNORE` on the composite PK make
    // the whole batch re-runnable, so a crash mid-arm self-heals on the next
    // open — idempotent. No full-table rebuild. Literal tail: MUST equal
    // CURRENT_SCHEMA_VERSION.
    // Postgres twin is `PostgresStore::migrate_v97`.
    meta(97, "AGENT_PUBKEY_HISTORY", true, true, NoLoss, Sqlite),
];

/// Look up the metadata for a target schema version.
#[must_use]
pub fn meta_for(version: i64) -> Option<&'static MigrationMeta> {
    MIGRATION_LADDER.iter().find(|m| m.version == version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// The sqlite ladder source, embedded at compile time so the coverage
    /// tests below can never drift from the arms they check (the same
    /// device `migrations.rs::current_schema_version_matches_module_docstring`
    /// uses).
    const LADDER_SRC: &str = include_str!("migrations.rs");

    /// One parsed sqlite ladder arm: its target version and its source
    /// text (from the `if version < …` line to the start of the next arm).
    struct Arm {
        version: i64,
        body: String,
    }

    /// Parse every REAL sqlite ladder arm out of `migrations.rs`.
    ///
    /// Anchored on a code line that OPENS an arm block (leading
    /// whitespace, then `if version < <key> {`) so a doc-comment that
    /// merely MENTIONS an arm ("the `if version < 34` arm only on a
    /// downgrade-replay path") is never mistaken for one — the same
    /// anchoring `scripts/check-migration-ladder.sh` uses.
    ///
    /// A `<key>` of `CURRENT_SCHEMA_VERSION` (the house convention for
    /// the tip cohort) is resolved from the MANDATORY `// vNN` comment
    /// that must open the arm body; an arm that carries neither a literal
    /// key nor that comment FAILS the parse loudly rather than being
    /// silently skipped (fail-closed: a skipped arm is a missing meta row
    /// nobody would ever notice).
    fn sqlite_arms() -> Vec<Arm> {
        let lines: Vec<&str> = LADDER_SRC.lines().collect();
        let mut opens: Vec<(usize, Option<i64>)> = Vec::new();
        for (i, raw) in lines.iter().enumerate() {
            let line = raw.trim();
            let Some(rest) = line.strip_prefix("if version < ") else {
                continue;
            };
            let Some(key) = rest.strip_suffix(" {") else {
                continue;
            };
            if key == "CURRENT_SCHEMA_VERSION" {
                opens.push((i, None));
            } else if let Ok(v) = key.parse::<i64>() {
                opens.push((i, Some(v)));
            }
        }
        assert!(
            !opens.is_empty(),
            "ARCH-8: no `if version < N {{` arms found in migrations.rs — the \
             parser lost its anchor; fix the parser before trusting any \
             coverage assertion below."
        );

        let mut arms = Vec::with_capacity(opens.len());
        for (idx, (start, literal)) in opens.iter().enumerate() {
            let end = opens.get(idx + 1).map_or(lines.len(), |(next, _)| *next);
            let body = lines[*start..end].join("\n");
            let version = match literal {
                Some(v) => *v,
                None => version_from_arm_comment(&body).unwrap_or_else(|| {
                    panic!(
                        "ARCH-8: the const-phrased arm at migrations.rs:{} does not \
                         open with the mandatory `// vNN …` comment, so its schema \
                         version cannot be derived. Add the comment (house \
                         convention for every const-phrased tip arm) or LITERALIZE \
                         the guard (`if version < N`) now that the arm has settled.",
                        start + 1,
                    )
                }),
            };
            arms.push(Arm { version, body });
        }
        arms
    }

    /// Pull `N` out of the first `// vN` comment in an arm body.
    fn version_from_arm_comment(body: &str) -> Option<i64> {
        body.lines()
            .map(str::trim)
            .filter_map(|l| l.strip_prefix("// v"))
            .find_map(|rest| {
                let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                digits.parse::<i64>().ok()
            })
    }

    /// Append the definition of every `MIGRATION_V*` const the arm
    /// references, so a name grounded in the migration FILENAME (e.g. v20
    /// `ADD_AUDIT_LOG_TABLE` -> `0014_v064_audit_log.sql`) still resolves.
    fn arm_haystack(body: &str) -> String {
        let mut haystack = body.to_ascii_lowercase();
        let mut consts: BTreeSet<String> = BTreeSet::new();
        let bytes: Vec<char> = body.chars().collect();
        let needle: Vec<char> = "MIGRATION_V".chars().collect();
        let mut i = 0usize;
        while i + needle.len() <= bytes.len() {
            if bytes[i..i + needle.len()] == needle[..] {
                let mut j = i;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == '_') {
                    j += 1;
                }
                consts.insert(bytes[i..j].iter().collect());
                i = j;
            } else {
                i += 1;
            }
        }
        for name in consts {
            let marker = format!("const {name}:");
            if let Some(pos) = LADDER_SRC.find(&marker) {
                let tail = &LADDER_SRC[pos..];
                let end = tail.find(";\n").map_or(tail.len(), |e| e + 1);
                haystack.push('\n');
                haystack.push_str(&tail[..end].to_ascii_lowercase());
            }
        }
        haystack
    }

    #[test]
    fn arch_8_ladder_versions_strictly_monotonic() {
        let mut prev = 1_i64;
        for meta in MIGRATION_LADDER {
            assert!(
                meta.version > prev,
                "ARCH-8: migration ladder is not strictly monotonic at version {}; prev={prev}",
                meta.version,
            );
            prev = meta.version;
        }
    }

    /// #3158 — the lockstep gate that USED to pass by construction.
    ///
    /// The pre-#3158 tail row was `version:
    /// crate::storage::migrations::current_schema_version()`, so
    /// `last().version == current_schema_version()` was a tautology: the
    /// row re-keyed itself on every bump and the assertion could never
    /// fail. This test now (a) asserts the tail equals
    /// `CURRENT_SCHEMA_VERSION`, and (b) REFUSES a symbolic tail key by
    /// reading this module's own source — the only way to make (a)
    /// load-bearing again.
    #[test]
    fn arch_8_ladder_tail_is_a_literal_at_current_schema_version() {
        let last = MIGRATION_LADDER
            .last()
            .expect("MIGRATION_LADDER is non-empty")
            .version;
        let current = crate::storage::current_schema_version_for_tests();
        assert_eq!(
            last, current,
            "ARCH-8: MIGRATION_LADDER tail = {last}, but CURRENT_SCHEMA_VERSION = {current}; \
             when bumping the ladder add a meta row in lockstep.",
        );

        let src = include_str!("migration_meta.rs");
        let table_start = src
            .find("pub const MIGRATION_LADDER:")
            .expect("MIGRATION_LADDER table must be present in this file");
        let table = &src[table_start..];
        let table_end = table
            .find("\n];")
            .expect("MIGRATION_LADDER table must terminate with `];`");
        let table = &table[..table_end];
        assert!(
            !table.contains("current_schema_version()"),
            "ARCH-8 (#3158): a MIGRATION_LADDER row is keyed to \
             `current_schema_version()`. A symbolic tail key makes the \
             equality above a TAUTOLOGY (the row follows the const), silently \
             re-labels the new tip with the OLD arm's semantics, and leaves \
             `meta_for(<the literal version>)` returning None. Key EVERY row \
             to a literal — the postgres `record_schema_version(&mut tx, 88)` \
             literalize-on-settle convention.",
        );
    }

    /// #3158 — one meta row per sqlite ladder arm, and no meta row
    /// without an arm (except the documented postgres-only steps).
    #[test]
    fn arch_8_every_sqlite_ladder_arm_has_exactly_one_meta_row() {
        let arms = sqlite_arms();
        let mut arm_versions: BTreeMap<i64, usize> = BTreeMap::new();
        for arm in &arms {
            *arm_versions.entry(arm.version).or_default() += 1;
        }
        for (v, n) in &arm_versions {
            assert_eq!(
                *n, 1,
                "ARCH-8: migrations.rs declares {n} arms for schema v{v} — a \
                 duplicate arm corrupts the ladder (guardrail-D rule (b))."
            );
        }

        let mut meta_versions: BTreeMap<i64, usize> = BTreeMap::new();
        for meta in MIGRATION_LADDER {
            *meta_versions.entry(meta.version).or_default() += 1;
        }
        for (v, n) in &meta_versions {
            assert_eq!(
                *n, 1,
                "ARCH-8: MIGRATION_LADDER carries {n} rows for v{v}; exactly one \
                 row per schema version."
            );
        }

        let missing: Vec<i64> = arm_versions
            .keys()
            .filter(|v| !meta_versions.contains_key(v))
            .copied()
            .collect();
        assert!(
            missing.is_empty(),
            "ARCH-8 (#3158): sqlite ladder arms with NO MIGRATION_LADDER row: \
             {missing:?}. Every arm's reversibility / data-loss contract is \
             operator-facing truth — add the row, derived from the arm's SQL."
        );

        for meta in MIGRATION_LADDER {
            let has_arm = arm_versions.contains_key(&meta.version);
            match meta.arm {
                LadderArm::Sqlite => assert!(
                    has_arm,
                    "ARCH-8: MIGRATION_LADDER v{} claims `LadderArm::Sqlite` but \
                     migrations.rs has no `if version < {}` arm. Either the arm \
                     was removed (drop or re-key the row) or the step is \
                     postgres-only (mark it `LadderArm::PostgresOnly`).",
                    meta.version, meta.version,
                ),
                LadderArm::PostgresOnly => assert!(
                    !has_arm,
                    "ARCH-8: MIGRATION_LADDER v{} is flagged `PostgresOnly` but \
                     migrations.rs DOES carry an `if version < {}` arm — the \
                     flags below describe the wrong adapter.",
                    meta.version, meta.version,
                ),
            }
        }
    }

    /// #3158 — the matrix must cover v2..=`CURRENT_SCHEMA_VERSION` with
    /// no holes. A hole is exactly the shape the pre-fix matrix had
    /// (v54–v88 absent), and it makes `meta_for` answer `None` for a real
    /// ladder step an operator is planning a rollback around.
    #[test]
    fn arch_8_ladder_is_gap_free_from_v2_to_current() {
        let current = crate::storage::current_schema_version_for_tests();
        let have: BTreeSet<i64> = MIGRATION_LADDER.iter().map(|m| m.version).collect();
        let missing: Vec<i64> = (2..=current).filter(|v| !have.contains(v)).collect();
        assert!(
            missing.is_empty(),
            "ARCH-8 (#3158): MIGRATION_LADDER has holes at {missing:?} — every \
             schema version from 2 to CURRENT_SCHEMA_VERSION ({current}) is a \
             real ladder step on at least one adapter and needs a row."
        );
        let extra: Vec<i64> = have.iter().copied().filter(|v| *v > current).collect();
        assert!(
            extra.is_empty(),
            "ARCH-8: MIGRATION_LADDER rows above CURRENT_SCHEMA_VERSION \
             ({current}): {extra:?}."
        );
    }

    /// #3158 — every row's `name` must be GROUNDED in its arm.
    ///
    /// This is the check that would have caught the headline defect: v43's
    /// `ADD_RECURSIVE_LEARNING_LEDGER` names a migration that does not
    /// exist anywhere in `migrations.rs` (`grep recursive_learning` → no
    /// match). At least one significant token of the name must appear in
    /// the arm's source text or in the migration `.sql` file it sources.
    /// Postgres-only steps have no sqlite arm to ground against and are
    /// covered instead by the `LadderArm` correspondence assertion above.
    #[test]
    fn arch_8_meta_row_names_are_grounded_in_their_arm() {
        /// Words that carry no identifying signal on their own.
        const GENERIC: &[&str] = &[
            "add", "new", "the", "and", "for", "table", "tables", "column", "columns",
        ];
        let arms: BTreeMap<i64, String> = sqlite_arms()
            .into_iter()
            .map(|a| (a.version, arm_haystack(&a.body)))
            .collect();

        let mut ungrounded: Vec<String> = Vec::new();
        for meta in MIGRATION_LADDER {
            if meta.arm == LadderArm::PostgresOnly {
                continue;
            }
            let Some(haystack) = arms.get(&meta.version) else {
                continue; // covered by the coverage test above
            };
            let lowered = meta.name.to_ascii_lowercase();
            let grounded = lowered
                .split('_')
                .filter(|t| t.len() >= 4 && !GENERIC.contains(t))
                .any(|t| haystack.contains(t));
            if !grounded {
                ungrounded.push(format!("v{} = {}", meta.version, meta.name));
            }
        }
        assert!(
            ungrounded.is_empty(),
            "ARCH-8 (#3158): MIGRATION_LADDER rows whose NAME appears nowhere in \
             the arm they describe (nor in the migration .sql it sources): \
             {ungrounded:?}. A matrix row that names a migration which does not \
             exist is worse than no row — it is a FALSE operator-facing claim \
             about reversibility and data loss. Re-derive the name from the arm."
        );
    }

    #[test]
    fn arch_8_every_meta_row_has_a_non_empty_name() {
        for meta in MIGRATION_LADDER {
            assert!(
                !meta.name.is_empty(),
                "ARCH-8: migration v{} has an empty `name`",
                meta.version,
            );
        }
    }

    /// #3158 — the exact repro from the issue.
    #[test]
    fn arch_8_meta_for_round_trip() {
        assert!(meta_for(2).is_some());
        assert!(meta_for(51).is_some());
        // The three lookups that returned None / the wrong row pre-#3158.
        assert_eq!(
            meta_for(43).expect("v43 must have a row").name,
            "PERSONA_SIGNING_ATOMICITY"
        );
        assert!(meta_for(54).is_some(), "#3158: meta_for(54) must resolve");
        assert!(meta_for(63).is_some(), "#3158: meta_for(63) must resolve");
        assert!(meta_for(9999).is_none());
        assert!(meta_for(0).is_none());
    }

    /// #3158 — the destructive-overwrite rows are the ones an operator
    /// MUST see before planning a rollback; pin them by value so a future
    /// edit cannot quietly downgrade the claim.
    #[test]
    fn arch_8_destructive_arms_are_flagged_irreversible() {
        let persona_signing = meta_for(43).expect("persona-signing arm must have a row");
        assert!(
            !persona_signing.reversible,
            "#3158: persona-signing arm rewrites pre-existing `memory_links.attest_level` values"
        );
        assert_eq!(persona_signing.data_loss_risk, DataLossRisk::Column);
        for v in [33, 36, 50, 63, 66, 80] {
            let row = meta_for(v).unwrap_or_else(|| panic!("v{v} row"));
            assert!(
                !row.reversible,
                "v{v} is a full-table rebuild — lowering the schema_version row \
                 cannot restore the pre-rebuild table definition"
            );
        }
        for v in [33, 66] {
            assert!(
                !meta_for(v).unwrap_or_else(|| panic!("v{v} row")).idempotent,
                "v{v} is the rebuild WITHOUT an already-rebuilt probe — \
                 re-applying its batch would rebuild (and drop triggers) again"
            );
        }
    }
}
