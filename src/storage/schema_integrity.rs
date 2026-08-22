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
//!   REFUSAL. The check runs inside the migrate transaction and BEFORE the
//!   `schema_version` stamp, so a refusal rolls the whole ladder back and
//!   leaves the database exactly as found, still stamped at its old version
//!   and still fully readable — the stamp is never written over a database
//!   whose integrity controls could not be applied.
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

/// Live-corpus size, used ONLY to colour the diagnostic (populated database
/// vs empty fixture). Never a gate.
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

/// Live-corpus row count, for colouring the diagnostic only.
///
/// Returns `None` when the count cannot be read — a bare fixture connection
/// with no `memories` relation is the ordinary case. DELIBERATE discard: this
/// value never gates anything, and a diagnostic that fails to render must not
/// convert a warning into an error.
#[must_use]
pub fn corpus_row_count(conn: &Connection) -> Option<i64> {
    conn.query_row(SQL_MEMORIES_COUNT, [], |r| r.get::<_, i64>(0))
        .ok()
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
        let rows = corpus_row_count(conn);
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
/// 3. the corpus is POSITIVELY OBSERVED to hold rows.
///
/// Condition 3 is the load-bearing one. The whole reason the ladder's
/// existence probes skip rather than fail is that an EMPTY database with a
/// high stamp is the ordinary fixture / archive-less shape — there is no lost
/// data there, because there is no data. Refusing it would brick a fresh
/// deployment for nothing, and since `asi-hard` PINS enforcement on, that
/// would make the hardened posture strictly more fragile than the standard one
/// with no integrity gain. Loss is only DEMONSTRABLE when rows exist alongside
/// a relation that should have been created before them.
///
/// `corpus_rows == None` (the count could not be read) also does NOT refuse:
/// the check refuses only on a fact it positively established, never on an
/// absence of information. An unreadable corpus surfaces through the WARN and
/// the `doctor` signal instead.
#[must_use]
pub fn refusal_required_with(
    missing: &[CoreTable],
    enforced: bool,
    corpus_rows: Option<i64>,
) -> bool {
    enforced && !missing.is_empty() && matches!(corpus_rows, Some(n) if n > 0)
}

/// [`refusal_required_with`] resolved against this process's enforcement flag
/// and this database's corpus size.
#[must_use]
pub fn refusal_required(conn: &Connection, missing: &[CoreTable]) -> bool {
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
        return false;
    }
    refusal_required_with(
        missing,
        crate::config::migration_require_core_tables(),
        corpus_row_count(conn),
    )
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
    fn corpus_row_count_is_none_without_a_memories_relation() {
        // Diagnostic-only: a bare fixture connection must not turn the WARN
        // path into an error.
        let conn = conn_with(&[]);
        assert_eq!(corpus_row_count(&conn), None);
    }

    #[test]
    fn corpus_row_count_reads_a_populated_corpus() {
        let conn = conn_with(&["memories"]);
        conn.execute("INSERT INTO memories (id) VALUES ('m1')", [])
            .expect("seed");
        assert_eq!(corpus_row_count(&conn), Some(1));
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
    fn an_unreadable_corpus_never_refuses_even_when_enforced() {
        // Refuse only on a positively established fact, never on an absence of
        // information. An unreadable corpus surfaces via the WARN + doctor.
        assert!(!refusal_required_with(&one_missing(), true, None));
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
}
