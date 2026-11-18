// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v102 (#8341, #9259, #9260) — the authoritative `_agents` public-key
//! projection, written by the Rust write funnels instead of a trigger.
//!
//! Schema v97 kept the flat `agent_pubkey` / `pubkey_bound_at` mirrors of an
//! `_agents` registration row equal to the open `agent_pubkey_history` row by
//! an AFTER trigger that ran a nested `UPDATE memories SET content = ...`.
//! That rewrite landed after the `memories_fts` sync had indexed the original
//! text, so the external-content FTS5 index disagreed with its table and
//! `'integrity-check'` failed with `SQLITE_CORRUPT_VTAB` (267).
//!
//! Design A (3-agent vote 71472661, tally 3-0 A): no trigger on `memories`
//! changes title, content or tags. Every Rust funnel that writes a whole
//! `_agents` row computes the projection here, BEFORE its statement and
//! inside its write transaction, with the exact v97 SQL expressions; the v102
//! guards (`migrations/sqlite/0086_v102_fts_projection_guard.sql`) only
//! `RAISE(ABORT)` when a write does not carry it. A funnel that forgets the
//! projection therefore fails with the guard's `MISMATCH_MESSAGE` instead of being
//! silently rewritten.
//!
//! The SQL lives once, as `NEW.`-qualified templates; [`with_row`] re-targets
//! them at the guard (`NEW.`), the projection query (`row_in.`), the
//! restore `INSERT ... SELECT` (`archived_memories.`) and the migration's
//! reconcile `UPDATE` (`memories.`). The migration file's text is pinned to
//! these templates by a unit test, so the two cannot drift.

use crate::models::{AGENTS_NAMESPACE, Memory};
use anyhow::{Context as _, Result};
use rusqlite::{Connection, params};
use std::sync::LazyLock;

/// The guard's error when a write omits the authoritative projection.
#[cfg(test)]
pub(crate) const MISMATCH_MESSAGE: &str = "agent_projection_guard: _agents write does not carry the authoritative agent_pubkey_history projection (metadata and content agent_pubkey/pubkey_bound_at must equal the open history row)";

/// The guard's error (#9260) when a BOUND agent's registration content is not
/// a JSON object, so no projection can be written into its content mirror.
/// Repair: `register_agent` rebuilds the registration row as an object.
#[cfg(test)]
pub(crate) const NON_OBJECT_MESSAGE: &str = "agent_projection_guard: bound _agents registration content is not a JSON object; re-register the agent (register_agent) to rebuild it";

/// #9405 - the refusal when the projection is read on an autocommit
/// connection, i.e. outside the write transaction that writes the row.
pub(crate) const PROJECTION_OUTSIDE_TXN_MESSAGE: &str = "agent projection read outside a write transaction (#9405): the projection and the row write must share one transaction";

/// Guard trigger names (v102). They replace the v97
/// `agent_pubkey_history_authoritative_{insert,update}_v97` rewriters.
#[cfg(test)]
pub(crate) const GUARD_INSERT_TRIGGER: &str = "agent_pubkey_history_projection_guard_insert";
/// See `GUARD_INSERT_TRIGGER`.
#[cfg(test)]
pub(crate) const GUARD_UPDATE_TRIGGER: &str = "agent_pubkey_history_projection_guard_update";

/// The row qualifier every template is written against.
const TEMPLATE_ROW: &str = "NEW.";

macro_rules! open_row {
    () => {
        "FROM agent_pubkey_history WHERE agent_id = substr(NEW.title, length('agent:') + 1) AND superseded_at IS NULL"
    };
}
macro_rules! open_key {
    () => {
        concat!("(SELECT pubkey_b64 ", open_row!(), ")")
    };
}
macro_rules! open_bound {
    () => {
        concat!("(SELECT bound_at ", open_row!(), ")")
    };
}
macro_rules! open_exists {
    () => {
        concat!("EXISTS (SELECT 1 ", open_row!(), ")")
    };
}
macro_rules! mirror_body {
    ($column:literal) => {
        concat!(
            "json_set(json_remove(CASE WHEN ",
            open_exists!(),
            " THEN json_set(json_remove(NEW.",
            $column,
            ", '$.agent_pubkey', '$.pubkey_bound_at'), '$.agent_pubkey', ",
            open_key!(),
            ", '$.pubkey_bound_at', ",
            open_bound!(),
            ") ELSE json_remove(NEW.",
            $column,
            ", '$.agent_pubkey', '$.pubkey_bound_at') END, '$.write_signature'), '$.attest_level', 'claimed')"
        )
    };
}

/// The full v97 WHEN clause (key and `pubkey_bound_at`, metadata and content
/// mirrors), scoped to `_agents` (voter condition 1).
pub(crate) const PREDICATE: &str = concat!(
    "(NEW.namespace = '_agents' AND (json_extract(NEW.metadata, '$.agent_pubkey') IS NOT ",
    open_key!(),
    " OR json_extract(NEW.metadata, '$.pubkey_bound_at') IS NOT ",
    open_bound!(),
    " OR json_extract(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE '{}' END, '$.agent_pubkey') IS NOT ",
    open_key!(),
    " OR json_extract(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE '{}' END, '$.pubkey_bound_at') IS NOT ",
    open_bound!(),
    "))"
);

/// A sealed row (at-rest encryption: content `''` plus an envelope) has no
/// SQL-readable content mirror; it passes when its metadata pair equals the
/// open history row (Rust projected the plaintext before sealing it).
#[cfg(test)]
pub(crate) const SEALED_EXEMPT: &str = concat!(
    "(NEW.encrypted_envelope IS NOT NULL AND NEW.content = '' AND json_extract(NEW.metadata, '$.agent_pubkey') IS ",
    open_key!(),
    " AND json_extract(NEW.metadata, '$.pubkey_bound_at') IS ",
    open_bound!(),
    ")"
);

/// The v97 metadata rewrite: project the open history row (or remove a
/// binding that has none), drop `write_signature`, force `claimed`.
pub(crate) const META_BODY: &str = mirror_body!("metadata");

/// The v97 content rewrite: the same projection over a JSON content mirror;
/// non-JSON content is left as it is.
pub(crate) const CONTENT_BODY: &str = concat!(
    "CASE WHEN json_valid(NEW.content) THEN ",
    mirror_body!("content"),
    " ELSE NEW.content END"
);

/// The #9260 non-object check inside the guard body.
#[cfg(test)]
pub(crate) const NON_OBJECT_CHECK: &str = concat!(
    "NEW.encrypted_envelope IS NULL AND ",
    open_exists!(),
    " AND json_type(CASE WHEN json_valid(NEW.content) THEN NEW.content ELSE 'null' END) IS NOT 'object'"
);

/// Re-target a `NEW.`-qualified template at another row qualifier.
pub(crate) fn with_row(template: &str, qualifier: &str) -> String {
    template.replace(TEMPLATE_ROW, qualifier)
}

const PROJECTION_ROW: &str = "row_in.";

static PROJECTION_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT {pred}, {meta}, {content} FROM (SELECT ?1 AS namespace, ?2 AS title, ?3 AS metadata, ?4 AS content) AS row_in",
        pred = with_row(PREDICATE, PROJECTION_ROW),
        meta = with_row(META_BODY, PROJECTION_ROW),
        content = with_row(CONTENT_BODY, PROJECTION_ROW),
    )
});

const ARCHIVED_ROW: &str = "archived_memories.";

fn archived_column(body: &str, column: &str) -> String {
    // CASE evaluates its WHEN arms in order, so a non-`_agents` row never
    // reaches the predicate's `json_extract` (a corrupt archived metadata
    // blob on an ordinary row stays restorable, the legacy behaviour).
    format!(
        "CASE WHEN {row}namespace <> '_agents' THEN {row}{column} WHEN {pred} THEN {body} ELSE {row}{column} END",
        row = ARCHIVED_ROW,
        column = column,
        pred = with_row(PREDICATE, ARCHIVED_ROW),
        body = with_row(body, ARCHIVED_ROW),
    )
}

/// The projected `metadata` column for a restore `INSERT ... SELECT FROM
/// archived_memories`.
pub(crate) static RESTORE_METADATA: LazyLock<String> =
    LazyLock::new(|| archived_column(META_BODY, "metadata"));

/// The projected `content` column for a restore `INSERT ... SELECT FROM
/// archived_memories`.
pub(crate) static RESTORE_CONTENT: LazyLock<String> =
    LazyLock::new(|| archived_column(CONTENT_BODY, "content"));

/// `Some(projected copy)` when `mem` is an `_agents` row whose binding
/// mirrors differ from the open history row; `None` when it already carries
/// the projection (or is not an `_agents` row). Reads the ledger on `conn`,
/// so a caller inside its write transaction projects against the state it
/// will commit.
///
/// # Errors
/// The projection query fails (for example malformed JSON metadata), or the
/// projected metadata does not parse.
pub(crate) fn projected(conn: &Connection, mem: &Memory) -> Result<Option<Memory>> {
    if mem.namespace != AGENTS_NAMESPACE {
        return Ok(None);
    }
    // #9405 - the projection is only sound under the write transaction that
    // writes the row; on an autocommit connection a bind / rebind / revoke
    // could commit between this read and the write. Fail closed.
    if conn.is_autocommit() {
        anyhow::bail!(PROJECTION_OUTSIDE_TXN_MESSAGE);
    }
    let metadata = serde_json::to_string(&mem.metadata).context("agent projection: metadata")?;
    let (mismatch, meta, content): (i64, String, String) = conn
        .query_row(
            &PROJECTION_SQL,
            params![mem.namespace, mem.title, metadata, mem.content],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .context("agent projection: query")?;
    if mismatch == 0 {
        return Ok(None);
    }
    let mut out = mem.clone();
    out.metadata = serde_json::from_str(&meta).context("agent projection: projected metadata")?;
    out.content = content;
    Ok(Some(out))
}

/// [`super::pubkey_history::strip_unproven_agent_pubkey_binding`] then
/// [`projected`]: the generic-write path. A caller-supplied binding is never
/// trusted; the ledger's is written instead. `None` means `mem` is written
/// as given.
///
/// # Errors
/// See [`projected`].
pub(crate) fn sanitized_projected(conn: &Connection, mem: &Memory) -> Result<Option<Memory>> {
    if mem.namespace != AGENTS_NAMESPACE {
        return Ok(None);
    }
    let mut sanitized = mem.clone();
    super::pubkey_history::strip_unproven_agent_pubkey_binding(&mut sanitized);
    Ok(Some(projected(conn, &sanitized)?.unwrap_or(sanitized)))
}

// v102 (#8341): the v97 rewriting triggers become abort guards. One ladder
// transaction: drop the rewriters, rebuild the FTS index, reconcile rows
// already out of step with the ledger, install the guards, rebuild again.
// Idempotent. The postgres twin is `PostgresStore::migrate_v102` (a
// version-stamp no-op: its BEFORE trigger corrects NEW and its tsvector is a
// generated column, so it cannot drift).
const MIGRATION_V102_SQLITE: &str =
    include_str!("../../migrations/sqlite/0086_v102_fts_projection_guard.sql");

/// The FTS rebuild statement 0086 carries (twice).
const FTS_REBUILD_SQL: &str = "INSERT INTO memories_fts(memories_fts) VALUES('rebuild');";

pub(super) fn migrate_v102(conn: &Connection) -> Result<()> {
    // Same gate as the v53 arm: every deployed path creates `memories_fts`
    // through `SCHEMA` before `migrate`; only fixtures that stamp a version
    // without `SCHEMA` lack it, and they carry no FTS triggers to rebuild for.
    let fts_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'memories_fts')",
        [],
        |r| r.get(0),
    )?;
    if fts_exists {
        conn.execute_batch(MIGRATION_V102_SQLITE)?;
    } else {
        conn.execute_batch(&MIGRATION_V102_SQLITE.replace(FTS_REBUILD_SQL, ""))?;
    }
    conn.execute(super::migrations::SQL_CLEAR_SCHEMA_VERSION, [])?;
    conn.execute("INSERT INTO schema_version (version) VALUES (102)", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V97_SQLITE: &str =
        include_str!("../../migrations/sqlite/0081_v97_agent_pubkey_history.sql");

    /// Collapse whitespace and drop it just inside parentheses, so two SQL
    /// texts that differ only in layout compare equal.
    fn normalize(sql: &str) -> String {
        sql.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .replace("( ", "(")
            .replace(" )", ")")
    }

    fn v97_when(trigger: &str) -> String {
        let start = V97_SQLITE
            .find(&format!("CREATE TRIGGER IF NOT EXISTS {trigger}"))
            .and_then(|at| {
                V97_SQLITE[at..]
                    .find("WHEN ")
                    .map(|w| at + w + "WHEN ".len())
            })
            .expect("v97 trigger WHEN");
        let end = V97_SQLITE[start..].find("\nBEGIN").expect("v97 BEGIN") + start;
        format!("({})", &V97_SQLITE[start..end])
    }

    #[test]
    fn guard_predicate_is_the_full_v97_when_clause_8341() {
        for trigger in [
            "agent_pubkey_history_authoritative_insert_v97",
            "agent_pubkey_history_authoritative_update_v97",
        ] {
            assert_eq!(
                normalize(&v97_when(trigger)),
                normalize(PREDICATE),
                "{trigger}"
            );
        }
    }

    #[test]
    fn migration_file_carries_the_templates_8341() {
        let file = normalize(MIGRATION_V102_SQLITE);
        for (what, text) in [
            ("guard predicate", with_row(PREDICATE, TEMPLATE_ROW)),
            ("sealed exemption", with_row(SEALED_EXEMPT, TEMPLATE_ROW)),
            ("non-object check", with_row(NON_OBJECT_CHECK, TEMPLATE_ROW)),
            ("reconcile predicate", with_row(PREDICATE, "memories.")),
            ("reconcile exemption", with_row(SEALED_EXEMPT, "memories.")),
            ("reconcile metadata", with_row(META_BODY, "memories.")),
            ("reconcile content", with_row(CONTENT_BODY, "memories.")),
        ] {
            assert!(
                file.contains(&normalize(&text)),
                "0086 must carry the {what}: {text}"
            );
        }
        for text in [
            MISMATCH_MESSAGE,
            NON_OBJECT_MESSAGE,
            GUARD_INSERT_TRIGGER,
            GUARD_UPDATE_TRIGGER,
        ] {
            assert!(
                MIGRATION_V102_SQLITE.contains(text),
                "0086 must carry {text}"
            );
        }
        assert_eq!(
            MIGRATION_V102_SQLITE.matches(MISMATCH_MESSAGE).count(),
            2,
            "one mismatch abort per guard"
        );
        // `migrate_v102` strips exactly this text on a fixture with no FTS table.
        assert_eq!(
            MIGRATION_V102_SQLITE.matches(FTS_REBUILD_SQL).count(),
            2,
            "0086 rebuilds memories_fts before and after the reconcile"
        );
    }

    /// #9405 structural cell. Rule: `projected` (and so `sanitized_projected`)
    /// refuses an `_agents` row on an autocommit connection, so no funnel can
    /// read the projection outside a write transaction. Limit: it detects ANY
    /// open transaction (`!is_autocommit`), not that the transaction is
    /// IMMEDIATE or is the one the row write commits in; the two-connection
    /// race cells in tests/agent_projection_txn_9405_9406.rs hold that half.
    #[test]
    fn projection_outside_a_write_txn_is_refused_9405() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).expect("open");
        let agent = "ai:projection-txn-9405";
        let id = crate::storage::register_agent(&conn, agent, "test", &[]).expect("register");
        let row = crate::storage::get(&conn, &id)
            .expect("get")
            .expect("registration row");
        assert!(conn.is_autocommit());
        for (what, outcome) in [
            ("projected", projected(&conn, &row).map(|_| ())),
            (
                "sanitized_projected",
                sanitized_projected(&conn, &row).map(|_| ()),
            ),
        ] {
            assert_eq!(
                outcome.map_err(|e| e.to_string()),
                Err(PROJECTION_OUTSIDE_TXN_MESSAGE.to_string()),
                "{what} on an autocommit connection"
            );
        }
        let mut other = row.clone();
        other.namespace = "not-agents".to_string();
        assert!(
            projected(&conn, &other).expect("non-_agents row").is_none(),
            "a non-_agents row needs no projection and no transaction"
        );
        let inside = crate::storage::in_write_txn(&conn, || {
            assert!(!conn.is_autocommit());
            projected(&conn, &row).map(|p| p.is_none())
        })
        .expect("projection inside a write transaction");
        assert!(
            inside,
            "a freshly registered row already carries the projection"
        );
    }

    /// `RESTORE_METADATA` at c73ea912, the head before alert 881's fix.
    const RESTORE_METADATA_AT_C73EA912: &str = "CASE WHEN archived_memories.namespace <> '_agents' THEN archived_memories.metadata WHEN (archived_memories.namespace = '_agents' AND (json_extract(archived_memories.metadata, '$.agent_pubkey') IS NOT (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL) OR json_extract(archived_memories.metadata, '$.pubkey_bound_at') IS NOT (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL) OR json_extract(CASE WHEN json_valid(archived_memories.content) THEN archived_memories.content ELSE '{}' END, '$.agent_pubkey') IS NOT (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL) OR json_extract(CASE WHEN json_valid(archived_memories.content) THEN archived_memories.content ELSE '{}' END, '$.pubkey_bound_at') IS NOT (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL))) THEN json_set(json_remove(CASE WHEN EXISTS (SELECT 1 FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL) THEN json_set(json_remove(archived_memories.metadata, '$.agent_pubkey', '$.pubkey_bound_at'), '$.agent_pubkey', (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL), '$.pubkey_bound_at', (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL)) ELSE json_remove(archived_memories.metadata, '$.agent_pubkey', '$.pubkey_bound_at') END, '$.write_signature'), '$.attest_level', 'claimed') ELSE archived_memories.metadata END";

    /// `RESTORE_CONTENT` at c73ea912, the head before alert 881's fix.
    const RESTORE_CONTENT_AT_C73EA912: &str = "CASE WHEN archived_memories.namespace <> '_agents' THEN archived_memories.content WHEN (archived_memories.namespace = '_agents' AND (json_extract(archived_memories.metadata, '$.agent_pubkey') IS NOT (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL) OR json_extract(archived_memories.metadata, '$.pubkey_bound_at') IS NOT (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL) OR json_extract(CASE WHEN json_valid(archived_memories.content) THEN archived_memories.content ELSE '{}' END, '$.agent_pubkey') IS NOT (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL) OR json_extract(CASE WHEN json_valid(archived_memories.content) THEN archived_memories.content ELSE '{}' END, '$.pubkey_bound_at') IS NOT (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL))) THEN CASE WHEN json_valid(archived_memories.content) THEN json_set(json_remove(CASE WHEN EXISTS (SELECT 1 FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL) THEN json_set(json_remove(archived_memories.content, '$.agent_pubkey', '$.pubkey_bound_at'), '$.agent_pubkey', (SELECT pubkey_b64 FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL), '$.pubkey_bound_at', (SELECT bound_at FROM agent_pubkey_history WHERE agent_id = substr(archived_memories.title, length('agent:') + 1) AND superseded_at IS NULL)) ELSE json_remove(archived_memories.content, '$.agent_pubkey', '$.pubkey_bound_at') END, '$.write_signature'), '$.attest_level', 'claimed') ELSE archived_memories.content END ELSE archived_memories.content END";

    /// #9273 (code-scanning alert 881) pin. Rule: the restore columns built by
    /// `archived_column` are byte-equal to their text at c73ea912, so the
    /// explicit format argument that makes `column`'s use visible to the
    /// scanner changes no SQL. Limit: it pins the two built strings, not their
    /// behaviour; `restore_archived_projects_a_tampered_archive_8341` and the
    /// `restore_archived` cells in tests/fts_corrupt_vtab_9273.rs hold that.
    #[test]
    fn restore_columns_are_byte_equal_to_c73ea912_9273() {
        assert_eq!(
            RESTORE_METADATA.as_str(),
            RESTORE_METADATA_AT_C73EA912,
            "RESTORE_METADATA drifted from c73ea912"
        );
        assert_eq!(
            RESTORE_CONTENT.as_str(),
            RESTORE_CONTENT_AT_C73EA912,
            "RESTORE_CONTENT drifted from c73ea912"
        );
    }
}
