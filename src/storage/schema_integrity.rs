// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (#3113) — core-relation integrity for the sqlite migration ladder.
//!
//! # The fail-open hole this closes
//!
//! Several ladder arms in [`super::migrations::migrate`] are gated on an
//! existence probe rather than applied unconditionally, e.g. the v34
//! `signed_events` chain columns, the v66 `governance_rules` severity-CHECK
//! widening, and the v73 `signed_events.cause_hash` column:
//!
//! ```text
//! let has_governance_rules = conn.prepare("SELECT 1 FROM governance_rules LIMIT 0").is_ok();
//! if has_governance_rules { conn.execute_batch(MIGRATION_V66_SQLITE)?; }
//! ```
//!
//! Those probes exist for a real and benign reason: a test fixture may stamp
//! `schema_version` to a high value over a database bootstrapped from the
//! `SCHEMA` constant alone, and `SCHEMA` deliberately omits the later-added
//! ladder-only relations. Skipping is correct there.
//!
//! What was missing is the OTHER reading of the same observation. After every
//! such skip the tail of `migrate` unconditionally stamps
//! `CURRENT_SCHEMA_VERSION` and returns `Ok(())`, so a POPULATED database that
//! LOST one of these relations (corruption, a partial file-level restore, an
//! operator `DROP`) "upgrades successfully" to the tip while the integrity
//! constraints that version claims — the signature-atomicity triggers, the
//! relation CHECK, the widened severity CHECK — were never applied. Subsequent
//! writes then bypass constraints the stamp asserts are in force. That is
//! fail-OPEN exactly where the project's north star requires fail-CLOSED.
//!
//! # The discriminator
//!
//! Every relation listed in [`CORE_TABLES`] is created UNCONDITIONALLY by its
//! ladder arm — `if version < N { CREATE TABLE ... }` with no probe in front
//! of the create itself. So for a database stamped at version `V`, a relation
//! whose `introduced_at <= V` is ABSENT can only mean the create arm never ran
//! against this file: either it was never a real ladder upgrade (the benign
//! fixture case) or the relation was lost after the fact (the corruption
//! case). The two are indistinguishable from inside the file, which is
//! precisely why this module REPORTS rather than guesses.
//!
//! # Posture
//!
//! * ALWAYS: a loud, structured `WARN` naming each missing relation, the
//!   version that introduced it, and the integrity control that is therefore
//!   not in force, plus the live-corpus row count so an operator can tell a
//!   populated database from an empty fixture at a glance.
//! * ALWAYS: a `doctor` signal — [`crate::cli::doctor`] runs the same probe
//!   against the stored stamp and raises the Storage section to `Critical`.
//! * OPT-IN: [`crate::config::migration_require_core_tables`]
//!   (`AI_MEMORY_MIGRATION_REQUIRE_CORE_TABLES=1`) turns the report into a
//!   REFUSAL when a core relation is missing AND the corpus is not the
//!   documented empty fixture (`COUNT(*) = 0`). An unreadable corpus
//!   (failed `COUNT(*)`) also refuses under enforcement — unreadability is
//!   not emptiness (#3246). The check runs inside the migrate transaction
//!   and BEFORE the `schema_version` stamp, so a refusal rolls the whole
//!   ladder back and leaves the database exactly as found, still stamped at
//!   its old version and still fully readable — the stamp is never written
//!   over a database whose integrity controls could not be applied.
//!
//! The refusal is opt-in rather than the default deliberately. Defaulting to
//! refuse would convert every pre-existing high-stamp fixture and every
//! archive-less deployment into a hard boot failure — an availability
//! regression across a fleet, with no data-integrity gain, since this module
//! MUTATES NOTHING. Reporting is unconditional; enforcement is a fleet
//! decision. This module reads `sqlite_master` and `COUNT(*)`; it issues no
//! DDL and no DML, so it can neither lose nor corrupt data.

use anyhow::{Context, Result};
use rusqlite::Connection;

/// Structured-log target for every event emitted by this module.
pub const TRACE_TARGET: &str = "ai_memory::storage::schema_integrity";

/// Existence probe against `sqlite_master`. Bound parameter, never
/// interpolated — the table name still comes from the [`CORE_TABLES`]
/// compile-time SSOT, never from caller input.
const SQL_TABLE_PRESENT: &str =
    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)";

/// Live-corpus size. `Ok(0)` is the documented no-brick empty-fixture path;
/// `Err` is unreadability (corruption / I/O / BUSY / missing relation) and
/// is an input to the refusal predicate — never coerced to "no corpus".
const SQL_MEMORIES_COUNT: &str = "SELECT COUNT(*) FROM memories";

/// Storage-layer SSOT for the ladder-created core relation NAMES.
///
/// These are referenced by the [`CORE_TABLES`] entries, by the migration
/// ladder's own probes, and by the tests, so the name of a relation whose
/// existence is a data-integrity invariant is typed ONCE (the operator's
/// no-hardcoded-literals directive, `scripts/check-hardcoded-literals.sh`).
///
/// Deliberately NOT reusing the same-valued consts elsewhere in the tree:
/// `export_scope::OMITTED_CLASS_*` is a portability omission LABEL,
/// `erasure::archive_sync::ARCHIVED_TABLE` selects an erasure-store table, and
/// `store::postgres::TABLE_ARCHIVED_MEMORIES` is postgres-local and private.
/// Binding a schema invariant to any of those would couple this check to an
/// unrelated subsystem's naming.
pub const TABLE_ARCHIVED_MEMORIES: &str = "archived_memories";
/// See [`TABLE_ARCHIVED_MEMORIES`].
pub const TABLE_NAMESPACE_META: &str = "namespace_meta";
/// See [`TABLE_ARCHIVED_MEMORIES`].
pub const TABLE_SIGNED_EVENTS: &str = "signed_events";
/// See [`TABLE_ARCHIVED_MEMORIES`].
pub const TABLE_AGENT_QUOTAS: &str = "agent_quotas";
/// See [`TABLE_ARCHIVED_MEMORIES`].
pub const TABLE_GOVERNANCE_RULES: &str = "governance_rules";

/// One ladder-created relation whose presence is implied by a schema stamp.
///
/// A relation qualifies for this table only when BOTH hold:
///
/// 1. Its ladder arm creates it UNCONDITIONALLY (no existence probe wrapping
///    the `CREATE TABLE`), so every genuine upgrade through that version has
///    it; and
/// 2. it is NOT in the bootstrap `SCHEMA` constant, which `db::open` replays
///    on every single open — a `SCHEMA` relation is re-created (empty) before
///    `migrate` ever runs, so its absence is unobservable here and this probe
///    would be dead weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoreTable {
    /// The sqlite relation name.
    pub name: &'static str,
    /// The schema version whose ladder arm creates it unconditionally.
    pub introduced_at: i64,
    /// The integrity control that is NOT in force while it is absent. Quoted
    /// verbatim into the operator-facing diagnostic.
    pub integrity_note: &'static str,
}

/// SSOT of ladder-created core relations. Verified against
/// [`super::migrations::migrate`] at schema v89.
///
/// Each `introduced_at` below was read off the arm that creates the relation:
/// `if version < 4` / `< 5` / `< 26` / `< 30`, each an unconditional
/// `CREATE TABLE IF NOT EXISTS` (or `execute_batch` of a create-only SQL
/// file). None of the four appears in the bootstrap `SCHEMA` constant.
///
/// When a future arm adds another ladder-only core relation, add it here in
/// the same commit — that is what keeps the stamp honest.
pub const CORE_TABLES: &[CoreTable] = &[
    CoreTable {
        name: TABLE_ARCHIVED_MEMORIES,
        introduced_at: 4,
        integrity_note: "archive/restore has no destination relation: archiving a memory \
                         (GC, supersede, in-place edit) cannot preserve the prior row",
    },
    CoreTable {
        name: TABLE_NAMESPACE_META,
        introduced_at: 5,
        integrity_note: "namespace standards and parent-namespace inheritance cannot be \
                         recorded or resolved",
    },
    CoreTable {
        name: TABLE_SIGNED_EVENTS,
        introduced_at: 26,
        integrity_note: "the append-only audit chain is absent, so the v34 prev_hash/sequence \
                         chain columns and the v73 cause_hash column were never applied",
    },
    CoreTable {
        // #3159 — the v50 arm skips a per-namespace PRIMARY KEY widening when
        // this relation is absent. NOTE the version: the SSOT records where a
        // relation is CREATED (v28, an unconditional `CREATE TABLE IF NOT
        // EXISTS` batch), not where a later arm SKIPS over it (v50). Recording
        // 50 would silently under-report every database stamped 28..49.
        name: TABLE_AGENT_QUOTAS,
        introduced_at: 28,
        integrity_note: "per-agent quota rows cannot be stored, so the K8 write-path blast-radius \
                         caps (memories/day, storage bytes, links/day) cannot bind and the v50 \
                         per-namespace PRIMARY KEY widening was never applied",
    },
    CoreTable {
        name: TABLE_GOVERNANCE_RULES,
        introduced_at: 30,
        integrity_note: "governance rules cannot be stored or evaluated, and the v66 widened \
                         severity CHECK was never applied",
    },
];

/// Probe whether `table` exists in this database.
///
/// # Errors
///
/// Propagates the `sqlite_master` read failure. A failed READ is deliberately
/// NOT coerced to "absent" (nor to "present"): an unreadable catalogue is a
/// different fact from a missing relation, and collapsing the two is the same
/// mistake #2445 fixed on the `schema_version` stamp read.
pub fn table_present(conn: &Connection, table: &str) -> Result<bool> {
    conn.query_row(SQL_TABLE_PRESENT, [table], |r| r.get::<_, bool>(0))
        .with_context(|| format!("probe sqlite_master for the {table} relation"))
}

/// Every [`CORE_TABLES`] entry that a database stamped at `effective_version`
/// must contain but does not.
///
/// Entries introduced ABOVE `effective_version` are not expected yet and are
/// skipped, so this is safe to call at any point on the ladder.
///
/// # Errors
///
/// Propagates a `sqlite_master` probe failure (see [`table_present`]).
pub fn missing_core_tables(conn: &Connection, effective_version: i64) -> Result<Vec<CoreTable>> {
    let mut missing = Vec::new();
    for entry in CORE_TABLES {
        if entry.introduced_at <= effective_version && !table_present(conn, entry.name)? {
            missing.push(*entry);
        }
    }
    Ok(missing)
}

/// Live-corpus row count.
///
/// `Ok(0)` is the documented no-brick empty-fixture path (no lost data,
/// because there is no data). `Err` is a failed `COUNT(*)` — corruption,
/// I/O, `BUSY`, or a missing `memories` relation. `memories` ships in the
/// bootstrap `SCHEMA` and is replayed by `db::open` before `migrate`, so a
/// failed count is never "a fixture without a corpus"; collapsing `Err` to
/// "no corpus" is the same unknown-as-a-value mistake #2445 fixed on the
/// `sqlite_master` probe and #3246 closes here (ERRORS-19).
///
/// # Errors
///
/// Propagates the `COUNT(*)` failure. Callers that only colour a diagnostic
/// (see [`report`]) may discard with `.ok()`; the refusal predicate must not.
pub fn corpus_row_count(conn: &Connection) -> Result<i64> {
    conn.query_row(SQL_MEMORIES_COUNT, [], |r| r.get::<_, i64>(0))
        .context("count memories rows for the core-relation integrity gate")
}

/// Render the missing-relation list into the one-line operator diagnostic.
#[must_use]
pub fn describe(missing: &[CoreTable]) -> String {
    missing
        .iter()
        .map(|t| {
            format!(
                "{} (introduced at v{}: {})",
                t.name, t.introduced_at, t.integrity_note
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Probe for missing core relations and, when any are missing, emit the loud
/// structured WARN. Returns the list so the caller can decide whether to
/// refuse.
///
/// # Errors
///
/// Propagates a `sqlite_master` probe failure (see [`table_present`]).
pub fn report(conn: &Connection, effective_version: i64) -> Result<Vec<CoreTable>> {
    let missing = missing_core_tables(conn, effective_version)?;
    if !missing.is_empty() {
        // Diagnostic only: a failed count must not promote this WARN into an
        // error. The refusal predicate ([`refusal_required`]) is what fails
        // closed on unreadability (#3246).
        let rows = corpus_row_count(conn).ok();
        tracing::warn!(
            target: TRACE_TARGET,
            effective_version,
            missing_count = missing.len(),
            missing = %describe(&missing),
            // Recorded as the Option itself (`Some(n)` / `None`), NOT flattened
            // to a sentinel: "the corpus could not be read" is a different fact
            // from "the corpus is empty", and collapsing the two into `-1` (or
            // worse, `0`) is the same unknown-as-a-value mistake this whole
            // check exists to remove. It is also the input to the refusal
            // predicate, so the log must show exactly what that predicate saw.
            corpus_rows = ?rows,
            // The knob NAME is a structured field, not prose, so it is typed
            // once (at its const) and a rename cannot leave this message stale.
            enforce_env = crate::config::ENV_MIGRATION_REQUIRE_CORE_TABLES,
            "core relations are ABSENT from a database at this schema version — the ladder \
             arms that create them were skipped, so the integrity controls this stamp implies \
             are NOT in force. A database with rows here indicates relation LOSS (corruption / \
             partial restore), not a fresh fixture. Run `ai-memory doctor`; set the \
             `enforce_env` knob above to 1 to refuse the stamp instead of warning."
        );
    }
    Ok(missing)
}

/// Pure refusal predicate: should a missing-relation report REFUSE the schema
/// stamp? Takes the enforcement flag and the corpus size explicitly so the
/// decision is testable without mutating process-global env.
///
/// Refusal requires ALL THREE:
///
/// 1. at least one core relation is missing;
/// 2. enforcement is engaged (`AI_MEMORY_MIGRATION_REQUIRE_CORE_TABLES=1`, or
///    the `asi-hard` pin); and
/// 3. the corpus is NOT the documented no-brick empty fixture (`Some(0)`).
///
/// Condition 3 is the load-bearing anti-brick invariant. An EMPTY database
/// with a high stamp is the ordinary fixture / archive-less shape — there is
/// no lost data there, because there is no data. Refusing it would brick a
/// fresh deployment for nothing, and since `asi-hard` PINS enforcement on,
/// that would make the hardened posture strictly more fragile than the
/// standard one with no integrity gain.
///
/// `corpus_rows == None` (the count could not be read) DOES refuse under
/// enforcement. `memories` ships in the bootstrap `SCHEMA`, so `None` is
/// never "a fixture without a corpus" — it is a failed `COUNT(*)`
/// (corruption / I/O / `BUSY`). Coercing that to "no refusal" was the #3246
/// fail-open: a database with missing core relations AND an unreadable
/// corpus stamped the tip with only a WARN. Unreadable is not empty.
#[must_use]
pub fn refusal_required_with(
    missing: &[CoreTable],
    enforced: bool,
    corpus_rows: Option<i64>,
) -> bool {
    // `Some(0)` is the sole no-brick observation. `None` (unreadability) and
    // `Some(n > 0)` (demonstrable loss) both refuse under enforcement.
    enforced && !missing.is_empty() && corpus_rows != Some(0)
}

/// [`refusal_required_with`] resolved against this process's enforcement flag
/// and this database's corpus size.
///
/// # Errors
///
/// Propagates a failed `COUNT(*)` (see [`corpus_row_count`]). A failed count
/// is unreadability, not emptiness: `migrate` must not stamp integrity as
/// intact on the strength of a failed read (#2445 / #3246 / ERRORS-19).
pub fn refusal_required(conn: &Connection, missing: &[CoreTable]) -> Result<bool> {
    // Short-circuit BEFORE the corpus count. `refusal_required_with` would
    // return false for an empty `missing` anyway, but Rust evaluates call
    // arguments EAGERLY — so without this guard every migration pays a full
    // `SELECT COUNT(*) FROM memories` inside the `BEGIN EXCLUSIVE` ladder
    // transaction to compute a value that cannot change the answer. The
    // healthy database (nothing missing) is the overwhelmingly common case,
    // and it is also the one whose corpus is largest, so the cost lands
    // exactly where it is least affordable. Mirrors `report`'s own emptiness
    // guard; semantics are identical.
    if missing.is_empty() {
        return Ok(false);
    }
    let corpus_rows = match corpus_row_count(conn) {
        Ok(n) => Some(n),
        Err(e) => {
            // Fail closed always: unreadability is not "no corpus". Under
            // enforcement this is a refusal (`Ok(true)` → `refusal_message`);
            // without enforcement it still aborts the stamp (`Err`) rather
            // than letting the tail write a version whose integrity we could
            // not even measure. `Some(0)` is the only no-brick path.
            if crate::config::migration_require_core_tables() {
                tracing::warn!(
                    target: TRACE_TARGET,
                    error = %e,
                    "memories COUNT(*) failed — unreadable is not empty; refusing the stamp under enforcement"
                );
                return Ok(true);
            }
            return Err(e).context(
                "memories COUNT(*) unreadable — refusing to stamp schema integrity as intact. \
                 The database is UNCHANGED (the migration rolled back)",
            );
        }
    };
    Ok(refusal_required_with(
        missing,
        crate::config::migration_require_core_tables(),
        corpus_rows,
    ))
}

/// The typed refusal raised when enforcement is enabled and relations are
/// missing. Kept separate from [`report`] so the message has ONE definition
/// shared by the migrate refusal and the doctor note.
#[must_use]
pub fn refusal_message(missing: &[CoreTable], effective_version: i64) -> String {
    format!(
        "refusing to stamp schema v{effective_version}: {} core relation(s) absent — {}. \
         The database is UNCHANGED (the migration rolled back) and remains readable at its \
         current version. Restore from a backup that contains these relations, or unset \
         {env} to proceed with a warning instead.",
        missing.len(),
        describe(missing),
        env = crate::config::ENV_MIGRATION_REQUIRE_CORE_TABLES,
    )
}

// ---------------------------------------------------------------------------
// v1.0.0 (#3172) — SCHEMA-masked data-loss gate for APPEND-ONLY bootstrap
// relations.
//
// The [`CORE_TABLES`] gate above covers relations that are LADDER-ONLY (absent
// from the bootstrap `SCHEMA` constant), so their disappearance is directly
// observable as a missing relation. This section covers the OTHER, strictly
// harder class the same north star demands: relations that DO ship in the
// bootstrap `SCHEMA` and are therefore re-created (EMPTY) by `db::open`'s
// `execute_batch(SCHEMA)` replay on EVERY open, BEFORE the ladder runs. A
// table-existence probe can never see the loss — the table always exists again
// by the time anything looks. `agent_lineage` (the identity-succession chain)
// is the load-bearing member: dropped by an operator, zeroed by a corrupt
// page, or omitted by a partial restore, it is silently re-created empty and
// the v80 rebuild arm then "succeeds" over zero rows, erasing the whole
// lineage chain with NO skip logged (issue #3172, the SCHEMA-masks-data-loss
// class distinct from #3113/#3159's ladder-only probe-skip class).
//
// The discriminator here is a persisted HIGH-WATER MARK. `agent_lineage` is
// APPEND-ONLY (a succession record is never deleted; the chain only grows), so
// a live row count BELOW a count this database has previously observed is
// unambiguous loss — there is no benign "empty fixture" reading of a COUNT
// that went DOWN. That sharper discriminator is why this gate FAILS CLOSED by
// DEFAULT (refuses), where the ambiguous #3113 core-relation gate must default
// to warn-only: a recorded mark of N>0 is proof THIS database once held N rows,
// so refusing a drop below it can never brick a genuinely fresh or
// archive-less deployment (their mark is absent / zero). The mark itself is a
// DERIVED integrity artifact — regenerable purely by re-observation, never the
// durable truth — so recording it can neither corrupt nor lose data.

/// The append-only, bootstrap-`SCHEMA` relation whose identity-lineage chain is
/// the load-bearing member of the SCHEMA-masks-loss class (#3172).
pub const TABLE_AGENT_LINEAGE: &str = "agent_lineage";

/// The durable high-water-mark side table (bootstrap-`SCHEMA`, both backends).
/// One row per watermarked relation: the max live row count ever observed.
pub const TABLE_LINEAGE_WATERMARK: &str = "lineage_integrity_watermark";

/// One append-only bootstrap-`SCHEMA` relation guarded by a high-water mark.
///
/// A relation qualifies only when ALL hold: (1) it ships in the bootstrap
/// `SCHEMA` (so `db::open` re-creates it empty before the ladder — [`CORE_TABLES`]
/// cannot cover it); (2) it is APPEND-ONLY in normal operation (a live count
/// below a recorded mark is therefore always loss, never a legitimate delete);
/// and (3) its loss is silent and integrity-critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WatermarkedRelation {
    /// The sqlite/postgres relation name.
    pub name: &'static str,
    /// The integrity control lost when its rows vanish. Quoted verbatim into
    /// the operator-facing refusal.
    pub integrity_note: &'static str,
}

/// SSOT of watermarked append-only bootstrap relations.
///
/// When a future append-only bootstrap-`SCHEMA` relation joins this class, add
/// it here in the same commit — that is what keeps the guard honest across the
/// whole class rather than one hand-picked table.
pub const WATERMARKED_RELATIONS: &[WatermarkedRelation] = &[WatermarkedRelation {
    name: TABLE_AGENT_LINEAGE,
    integrity_note: "the identity-succession lineage chain (genesis → rotation → recovery → \
                     revocation records keyed by (agent_id, epoch)) is gone — every agent's \
                     cryptographic provenance back to genesis, and the v80 custody/revocation \
                     history, cannot be verified",
}];

/// The verdict of comparing a watermarked relation's live row count against its
/// stored high-water mark. Modelled as a total enum so the caller MUST handle
/// the loss arm — it cannot be dropped by an omitted branch (ERRORS-09,
/// make-illegal-states-unrepresentable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatermarkVerdict {
    /// Live count is at or above the recorded mark. `advance_to` is `Some(n)`
    /// when the mark must move UP to the new live count `n`; `None` when the
    /// mark is already current (no write needed).
    Intact { advance_to: Option<i64> },
    /// The stored mark strictly EXCEEDS the live count: an append-only relation
    /// has LOST rows. `high_water` were once observed; only `current` remain.
    /// This is schema-masked data loss and, absent an operator override, refuses.
    Regressed { high_water: i64, current: i64 },
}

/// Pure classification of a live count against a stored mark. No I/O, no env —
/// fully testable in isolation. A `None` stored mark reads as 0 (never
/// observed → nothing to have lost), so a fresh/upgrade database is always
/// [`WatermarkVerdict::Intact`] and can never be bricked by this gate.
#[must_use]
pub fn classify_watermark(stored: Option<i64>, current: i64) -> WatermarkVerdict {
    let high_water = stored.unwrap_or(0);
    if high_water > current {
        WatermarkVerdict::Regressed {
            high_water,
            current,
        }
    } else if current > high_water {
        WatermarkVerdict::Intact {
            advance_to: Some(current),
        }
    } else {
        WatermarkVerdict::Intact { advance_to: None }
    }
}

/// The operator-facing refusal raised when a watermarked relation regressed and
/// the override is NOT set. One definition, shared by the sqlite migrate gate
/// and the postgres connect gate, so both backends refuse with the same words.
#[must_use]
pub fn lineage_loss_message(
    relation: &str,
    integrity_note: &str,
    high_water: i64,
    current: i64,
) -> String {
    format!(
        "refusing to open: the append-only relation `{relation}` REGRESSED from a \
         previously-recorded high-water mark of {high_water} row(s) to {current} — {integrity_note}. \
         This is schema-masked data loss: the bootstrap schema re-creates `{relation}` EMPTY on \
         every open, so the drop is invisible to table-existence checks and would otherwise be \
         rebuilt over zero rows and stamped as success. The database is UNCHANGED and remains \
         readable at its current version. Restore `{relation}` from a backup that contains its \
         rows, or set {env}=1 to ACKNOWLEDGE the loss and proceed — which RESETS the high-water \
         mark to {current} and is not reversible.",
        env = crate::config::ENV_ALLOW_LINEAGE_REGRESSION,
    )
}

/// Live row count for a bootstrap-`SCHEMA` relation.
///
/// A relation that is ABSENT counts as a clean `Ok(0)`: the bootstrap replay
/// would re-create it empty, so "no live rows" is the true, non-erroneous fact,
/// and it still trips the regression arm when a positive mark was recorded. A
/// failed `COUNT(*)` on a PRESENT relation is unreadability (corruption / I/O /
/// `BUSY`) and stays `Err` — never coerced to 0 (the #2445/#3246 unknown-as-a-
/// value discipline, ERRORS-19). The relation name comes from the
/// [`WATERMARKED_RELATIONS`] compile-time SSOT, never caller input, so
/// interpolating it into the `COUNT` is not an injection surface (identifiers
/// cannot be bound parameters in sqlite).
///
/// # Errors
///
/// Propagates the `sqlite_master` probe failure or a failed `COUNT(*)`.
pub fn live_relation_count(conn: &Connection, relation: &str) -> Result<i64> {
    if !table_present(conn, relation)? {
        return Ok(0);
    }
    conn.query_row(&format!("SELECT COUNT(*) FROM {relation}"), [], |r| {
        r.get::<_, i64>(0)
    })
    .with_context(|| format!("count rows in the {relation} watermarked relation"))
}

/// Read the stored high-water mark for `relation`, or `None` when no mark has
/// been recorded yet. Callers MUST ensure [`TABLE_LINEAGE_WATERMARK`] exists
/// (see [`enforce_lineage_watermarks`]) — a missing mark ROW is `None`, but a
/// missing mark TABLE is a caller error, not silently `None`.
///
/// # Errors
///
/// Propagates the read failure. A failed read is unreadability, not "no mark".
pub fn read_lineage_watermark(conn: &Connection, relation: &str) -> Result<Option<i64>> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT high_water FROM lineage_integrity_watermark WHERE relation = ?1",
        [relation],
        |r| r.get::<_, i64>(0),
    )
    .optional()
    .with_context(|| format!("read the recorded high-water mark for {relation}"))
}

/// Upsert the high-water mark for `relation` to `value`. Used both to ADVANCE
/// the mark on growth and to RESET it downward under an explicit operator
/// override.
///
/// # Errors
///
/// Propagates the write failure.
pub fn record_lineage_watermark(conn: &Connection, relation: &str, value: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO lineage_integrity_watermark (relation, high_water, observed_at) \
         VALUES (?1, ?2, ?3) \
         ON CONFLICT(relation) DO UPDATE SET high_water = excluded.high_water, \
                                             observed_at = excluded.observed_at",
        rusqlite::params![relation, value, chrono::Utc::now().to_rfc3339()],
    )
    .with_context(|| format!("record the high-water mark for {relation}"))?;
    Ok(())
}

/// Enforce the append-only high-water invariant for every
/// [`WATERMARKED_RELATIONS`] entry.
///
/// For each relation: on GROWTH, advance the mark; on a match, do nothing; on a
/// REGRESSION (live count below the recorded mark), emit a loud structured WARN
/// and REFUSE — unless the operator override
/// ([`crate::config::allow_lineage_regression`]) is set, in which case it WARNs,
/// resets the mark to the current count (explicit acknowledgement), and
/// proceeds. No-op when [`TABLE_LINEAGE_WATERMARK`] is absent (a partial test
/// fixture that never carried the meta relation — mirrors the ladder arms'
/// tolerance of synthetic fixtures).
///
/// Called INSIDE the migrate transaction and BEFORE the `schema_version` stamp,
/// so a refusal rolls the whole ladder back and leaves the database exactly as
/// found — still readable at its current version, with no empty relation
/// masquerading as intact.
///
/// # Errors
///
/// Returns the [`lineage_loss_message`] error on a detected regression without
/// the override, or propagates any probe/count/read/write failure (all of which
/// abort the stamp — fail closed).
pub fn enforce_lineage_watermarks(conn: &Connection) -> Result<()> {
    if !table_present(conn, TABLE_LINEAGE_WATERMARK)? {
        return Ok(());
    }
    for relation in WATERMARKED_RELATIONS {
        let current = live_relation_count(conn, relation.name)?;
        let stored = read_lineage_watermark(conn, relation.name)?;
        match classify_watermark(stored, current) {
            WatermarkVerdict::Regressed {
                high_water,
                current,
            } => {
                let acknowledged = crate::config::allow_lineage_regression();
                tracing::warn!(
                    target: TRACE_TARGET,
                    relation = relation.name,
                    high_water,
                    current,
                    acknowledged,
                    override_env = crate::config::ENV_ALLOW_LINEAGE_REGRESSION,
                    "APPEND-ONLY RELATION REGRESSED — schema-masked data loss: the bootstrap \
                     schema re-created this relation with FEWER rows than were previously \
                     observed. This is silent identity-lineage loss unless restored from backup. \
                     Set the `override_env` knob to 1 to acknowledge the loss and proceed \
                     (resets the mark)."
                );
                if acknowledged {
                    record_lineage_watermark(conn, relation.name, current)?;
                } else {
                    return Err(anyhow::anyhow!(lineage_loss_message(
                        relation.name,
                        relation.integrity_note,
                        high_water,
                        current,
                    )));
                }
            }
            WatermarkVerdict::Intact {
                advance_to: Some(n),
            } => record_lineage_watermark(conn, relation.name, n)?,
            WatermarkVerdict::Intact { advance_to: None } => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn_with(tables: &[&str]) -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        for t in tables {
            conn.execute(&format!("CREATE TABLE {t} (id TEXT PRIMARY KEY)"), [])
                .expect("create fixture table");
        }
        conn
    }

    #[test]
    fn every_core_table_entry_is_distinct_and_ordered_by_introduction() {
        // SSOT hygiene: no duplicate relation, and the table reads in ladder
        // order so a reviewer can diff it against `migrate` top-to-bottom.
        let mut names: Vec<&str> = CORE_TABLES.iter().map(|t| t.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            CORE_TABLES.len(),
            "duplicate CORE_TABLES entry"
        );
        let versions: Vec<i64> = CORE_TABLES.iter().map(|t| t.introduced_at).collect();
        let mut sorted = versions.clone();
        sorted.sort_unstable();
        assert_eq!(versions, sorted, "CORE_TABLES must read in ladder order");
    }

    #[test]
    fn a_fresh_database_expects_nothing() {
        // effective_version 0: nothing has been introduced yet, so an empty
        // database is NOT missing anything. This is what keeps a genuinely
        // fresh bootstrap silent.
        let conn = conn_with(&[]);
        assert!(missing_core_tables(&conn, 0).expect("probe").is_empty());
    }

    #[test]
    fn relations_above_the_stamp_are_not_yet_expected() {
        // At v4 only `archived_memories` is due; signed_events (v26) and
        // governance_rules (v30) are correctly not reported.
        let conn = conn_with(&[TABLE_ARCHIVED_MEMORIES]);
        assert!(missing_core_tables(&conn, 4).expect("probe").is_empty());
        assert!(
            missing_core_tables(&conn, 5)
                .expect("probe")
                .iter()
                .any(|t| t.name == TABLE_NAMESPACE_META)
        );
    }

    #[test]
    fn agent_quotas_is_expected_from_v28_not_v50() {
        // #3159 boundary. The finding cites the v50 SKIP site; the SSOT must
        // record the v28 CREATE site. Getting this wrong is silent and
        // one-directional: every database stamped 28..49 would stop being
        // checked at all. Pin both sides of the boundary.
        let conn = conn_with(&[]);
        assert!(
            !missing_core_tables(&conn, 27)
                .expect("probe")
                .iter()
                .any(|t| t.name == TABLE_AGENT_QUOTAS),
            "agent_quotas must not be expected below its v28 create arm"
        );
        assert!(
            missing_core_tables(&conn, 28)
                .expect("probe")
                .iter()
                .any(|t| t.name == TABLE_AGENT_QUOTAS),
            "agent_quotas must be expected from v28 on, NOT only from v50"
        );
    }

    #[test]
    fn a_tip_stamped_database_missing_the_audit_chain_is_reported() {
        // The finding's exact shape: a database claiming the tip whose
        // ladder-only relations were skipped.
        let conn = conn_with(&[TABLE_ARCHIVED_MEMORIES, TABLE_NAMESPACE_META]);
        let missing = missing_core_tables(&conn, 89).expect("probe");
        let names: Vec<&str> = missing.iter().map(|t| t.name).collect();
        assert_eq!(
            names,
            vec![
                TABLE_SIGNED_EVENTS,
                TABLE_AGENT_QUOTAS,
                TABLE_GOVERNANCE_RULES
            ]
        );
    }

    #[test]
    fn a_complete_database_at_the_tip_reports_nothing() {
        let conn = conn_with(&[
            TABLE_ARCHIVED_MEMORIES,
            TABLE_NAMESPACE_META,
            TABLE_SIGNED_EVENTS,
            TABLE_AGENT_QUOTAS,
            TABLE_GOVERNANCE_RULES,
        ]);
        assert!(missing_core_tables(&conn, 89).expect("probe").is_empty());
    }

    #[test]
    fn corpus_row_count_errors_without_a_memories_relation() {
        // #3246: a missing `memories` relation is a failed COUNT, not "no
        // corpus". `report` may still discard this for the WARN colouring;
        // the refusal predicate must not.
        let conn = conn_with(&[]);
        assert!(
            corpus_row_count(&conn).is_err(),
            "COUNT(*) against a missing memories relation must be Err, not Ok(0)/None"
        );
    }

    #[test]
    fn corpus_row_count_reads_a_populated_corpus() {
        let conn = conn_with(&["memories"]);
        conn.execute("INSERT INTO memories (id) VALUES ('m1')", [])
            .expect("seed");
        assert_eq!(corpus_row_count(&conn).expect("count"), 1);
    }

    #[test]
    fn corpus_row_count_reads_an_empty_corpus() {
        let conn = conn_with(&["memories"]);
        assert_eq!(
            corpus_row_count(&conn).expect("count"),
            0,
            "an empty memories table is Ok(0), the documented no-brick path"
        );
    }

    #[test]
    fn describe_names_the_relation_and_its_integrity_control() {
        let missing = missing_core_tables(&conn_with(&[]), 89).expect("probe");
        let text = describe(&missing);
        assert!(
            text.contains(TABLE_SIGNED_EVENTS),
            "must name the relation: {text}"
        );
        assert!(
            text.contains("append-only audit chain"),
            "must name the control: {text}"
        );
    }

    #[test]
    fn refusal_message_states_the_database_is_unchanged() {
        // The operator-facing guarantee: a refusal is not a mutation.
        let missing = missing_core_tables(&conn_with(&[]), 89).expect("probe");
        let msg = refusal_message(&missing, 89);
        assert!(msg.contains("UNCHANGED"), "{msg}");
        assert!(
            msg.contains(crate::config::ENV_MIGRATION_REQUIRE_CORE_TABLES),
            "{msg}"
        );
    }

    // --- refusal predicate: the populated-corpus gate ---

    fn one_missing() -> Vec<CoreTable> {
        missing_core_tables(&conn_with(&[]), 89).expect("probe")
    }

    #[test]
    fn an_empty_corpus_never_refuses_even_when_enforced() {
        // THE anti-brick invariant. `asi-hard` PINS enforcement on, so a fresh
        // or archive-less deployment with an empty corpus MUST still open. Loss
        // is only demonstrable when rows exist alongside a relation that should
        // have been created before them.
        assert!(!refusal_required_with(&one_missing(), true, Some(0)));
    }

    #[test]
    fn an_unreadable_corpus_refuses_when_enforced() {
        // #3246: `None` is a failed COUNT, not "no corpus". Under enforcement
        // (asi-hard pins this ON) an unreadable corpus MUST refuse — the same
        // fail-closed the sqlite_master probe already has (#2445).
        assert!(refusal_required_with(&one_missing(), true, None));
    }

    #[test]
    fn an_unreadable_corpus_does_not_refuse_when_enforcement_is_off() {
        // Default posture stays report-only at the predicate: the live
        // `refusal_required` still propagates the COUNT error so migrate
        // does not stamp, but the pure predicate itself does not refuse.
        assert!(!refusal_required_with(&one_missing(), false, None));
    }

    #[test]
    fn a_populated_corpus_refuses_when_enforced() {
        assert!(refusal_required_with(&one_missing(), true, Some(1)));
    }

    #[test]
    fn a_populated_corpus_reports_only_when_enforcement_is_off() {
        // The default posture: detect and warn, never refuse.
        assert!(!refusal_required_with(
            &one_missing(),
            false,
            Some(1_000_000)
        ));
    }

    #[test]
    fn a_complete_schema_never_refuses() {
        assert!(!refusal_required_with(&[], true, Some(1_000_000)));
    }

    #[test]
    fn refusal_required_propagates_a_failed_count_when_unenforced() {
        // Default posture: a failed COUNT must not be coerced to "no corpus"
        // and then stamped. Propagating the error rolls the ladder back.
        let conn = conn_with(&[]);
        let missing = one_missing();
        let err = refusal_required(&conn, &missing).expect_err("failed COUNT must propagate");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("UNCHANGED"),
            "the operator-facing guarantee must survive a failed COUNT: {msg}"
        );
    }

    #[test]
    fn refusal_required_is_false_on_an_empty_readable_corpus() {
        let conn = conn_with(&["memories"]);
        let missing = one_missing();
        assert!(
            !refusal_required(&conn, &missing).expect("readable empty corpus"),
            "Ok(0) stays the documented no-brick path even with relations missing"
        );
    }

    #[test]
    fn report_returns_the_same_list_it_warns_about() {
        let conn = conn_with(&[
            TABLE_ARCHIVED_MEMORIES,
            TABLE_NAMESPACE_META,
            TABLE_SIGNED_EVENTS,
            TABLE_AGENT_QUOTAS,
        ]);
        let missing = report(&conn, 89).expect("report");
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].name, TABLE_GOVERNANCE_RULES);
    }

    // --- #3172: append-only high-water-mark gate ---------------------------

    /// Build a connection carrying `agent_lineage` (append-only shape) and the
    /// watermark meta relation, plus `memories`, mirroring the bootstrap set.
    fn conn_with_lineage() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        conn.execute_batch(
            "CREATE TABLE agent_lineage (agent_id TEXT NOT NULL, epoch INTEGER NOT NULL, \
                 PRIMARY KEY (agent_id, epoch)); \
             CREATE TABLE lineage_integrity_watermark (relation TEXT NOT NULL PRIMARY KEY, \
                 high_water INTEGER NOT NULL, observed_at TEXT NOT NULL);",
        )
        .expect("create lineage + watermark fixtures");
        conn
    }

    fn seed_lineage_rows(conn: &Connection, n: i64) {
        for epoch in 0..n {
            conn.execute(
                "INSERT INTO agent_lineage (agent_id, epoch) VALUES ('ai:x', ?1)",
                [epoch],
            )
            .expect("seed lineage row");
        }
    }

    #[test]
    fn classify_none_mark_is_always_intact() {
        // A never-observed relation (fresh / upgrade) can NEVER be classified
        // as loss — this is the anti-brick invariant of the whole gate.
        assert_eq!(
            classify_watermark(None, 0),
            WatermarkVerdict::Intact { advance_to: None }
        );
        assert_eq!(
            classify_watermark(None, 5),
            WatermarkVerdict::Intact {
                advance_to: Some(5)
            }
        );
    }

    #[test]
    fn classify_growth_advances_and_match_is_noop() {
        assert_eq!(
            classify_watermark(Some(3), 7),
            WatermarkVerdict::Intact {
                advance_to: Some(7)
            }
        );
        assert_eq!(
            classify_watermark(Some(4), 4),
            WatermarkVerdict::Intact { advance_to: None }
        );
    }

    #[test]
    fn classify_regression_including_drop_to_zero_is_loss() {
        // The exact #3172 signal: a recorded mark of N>0 and a live count that
        // fell below it — including the schema-mask's drop-to-EMPTY.
        assert_eq!(
            classify_watermark(Some(5), 0),
            WatermarkVerdict::Regressed {
                high_water: 5,
                current: 0
            }
        );
        assert_eq!(
            classify_watermark(Some(9), 4),
            WatermarkVerdict::Regressed {
                high_water: 9,
                current: 4
            }
        );
    }

    #[test]
    fn live_relation_count_reads_zero_for_absent_relation() {
        // A DROPPED bootstrap relation counts as 0 live rows (it would be
        // re-created empty), not an error — so a recorded mark still trips.
        let conn = conn_with(&[]);
        assert_eq!(
            live_relation_count(&conn, TABLE_AGENT_LINEAGE).expect("absent => 0"),
            0
        );
    }

    #[test]
    fn enforce_is_a_noop_without_the_watermark_table() {
        // A partial fixture without the meta relation must not brick.
        let conn = conn_with(&[TABLE_AGENT_LINEAGE]);
        enforce_lineage_watermarks(&conn).expect("no watermark table => no-op");
    }

    #[test]
    fn enforce_advances_then_holds_the_mark() {
        let conn = conn_with_lineage();
        seed_lineage_rows(&conn, 3); // epochs 0..3
        enforce_lineage_watermarks(&conn).expect("first pass records the mark");
        assert_eq!(
            read_lineage_watermark(&conn, TABLE_AGENT_LINEAGE).expect("read"),
            Some(3)
        );
        // Append two more distinct epochs → the mark advances to 5.
        for epoch in 3..5 {
            conn.execute(
                "INSERT INTO agent_lineage (agent_id, epoch) VALUES ('ai:x', ?1)",
                [epoch],
            )
            .expect("append epoch");
        }
        enforce_lineage_watermarks(&conn).expect("second pass advances");
        assert_eq!(
            read_lineage_watermark(&conn, TABLE_AGENT_LINEAGE).expect("read"),
            Some(5)
        );
        // A no-op re-run holds the mark steady.
        enforce_lineage_watermarks(&conn).expect("third pass holds");
        assert_eq!(
            read_lineage_watermark(&conn, TABLE_AGENT_LINEAGE).expect("read"),
            Some(5)
        );
    }

    #[test]
    fn enforce_refuses_on_a_drop_to_zero() {
        // Seed rows, record the mark, then EMPTY the relation (the schema-mask
        // outcome) and assert the gate refuses with the operator-facing message.
        let conn = conn_with_lineage();
        seed_lineage_rows(&conn, 4);
        enforce_lineage_watermarks(&conn).expect("record mark = 4");
        conn.execute("DELETE FROM agent_lineage", [])
            .expect("simulate schema-masked drop-to-empty");
        let err = enforce_lineage_watermarks(&conn).expect_err("must refuse the emptied relation");
        let msg = format!("{err:#}");
        assert!(msg.contains(TABLE_AGENT_LINEAGE), "{msg}");
        assert!(msg.contains("UNCHANGED"), "{msg}");
        assert!(
            msg.contains(crate::config::ENV_ALLOW_LINEAGE_REGRESSION),
            "{msg}"
        );
        // Refusal is not a mutation: the mark is untouched at its prior value.
        assert_eq!(
            read_lineage_watermark(&conn, TABLE_AGENT_LINEAGE).expect("read"),
            Some(4)
        );
    }
}
