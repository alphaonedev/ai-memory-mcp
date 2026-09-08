// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3520 — CATALOG pre-check for the idempotent bootstrap DDL, so an
//! already-migrated database takes NO relation-level DDL lock on connect.
//!
//! # The defect this closes
//!
//! `INIT_SCHEMA` (`postgres_schema.sql`) is replayed on EVERY
//! `PostgresStore::connect`, by design — it is how a partially-created schema
//! self-heals. But `IF NOT EXISTS` is not free: PostgreSQL's `CREATE INDEX`
//! takes a relation-level `ShareLock` on the table BEFORE it discovers the
//! index already exists, so the ~70 `CREATE INDEX IF NOT EXISTS` statements
//! in the bundled script lock ~40 tables on every boot of every daemon,
//! forever, for nothing. `ShareLock` conflicts with the `RowExclusiveLock`
//! every ordinary write holds, and two sessions acquiring two relation locks
//! in opposite orders is a deadlock — which is exactly what #3520 observed:
//! `size_gc`'s DELETE holding R1 and needing R2 while a peer's bootstrap held
//! R2 and needed R1.
//!
//! The retry funnel (`super::tx_retry`) makes the DML side SURVIVE that
//! collision. This module removes the collision.
//!
//! # What it does
//!
//! Splits the bundled script into top-level statements, asks the catalog ONE
//! question about all of them at once, and re-emits only the statements whose
//! object is genuinely absent. On a fully-migrated database the surviving
//! batch contains no `CREATE TABLE` and no `CREATE INDEX` at all, so it takes
//! no `ShareLock` and no `AccessExclusiveLock` on ANY application table.
//!
//! # What it deliberately does NOT do
//!
//! * It does not change what a FRESH database ends up with. A statement is
//!   dropped only when the catalog says its object is already there, so the
//!   union of (kept statements) and (already-present objects) is the whole
//!   script, every time.
//! * It does not touch the migration ladder. No rung is added, moved or
//!   skipped; `migrate_locked` runs exactly as before.
//! * It does not filter the statements that are NOT existence-gated —
//!   `CREATE OR REPLACE FUNCTION` / `CREATE OR REPLACE VIEW` and the `DO`
//!   block always run, because "the object exists" does not mean "its
//!   definition is current", and a stale view would return WRONG rows. Those
//!   statements are also not part of the deadlock class: replacing a view
//!   takes `AccessExclusiveLock` on the VIEW (which no DML path touches) and
//!   only `AccessShareLock` on the tables it reads, and `AccessShareLock`
//!   does not conflict with the `RowExclusiveLock` a writer holds.
//! * It never invents a skip. Any statement shape the classifier does not
//!   recognise — a schema-qualified name, an `ALTER`, anything new — is kept.
//!   The classifier fails SAFE toward running the DDL, which is the
//!   pre-#3520 behaviour.
//!
//! A probe that itself fails degrades to the unfiltered script: worst case
//! the boot is exactly as slow and as lock-hungry as it was before.

use std::collections::HashSet;

use sqlx::PgPool;

use crate::store::StoreResult;

/// The SQL that names the schema an unqualified `CREATE TABLE` /
/// `CREATE INDEX` in the bundled script would actually create into.
///
/// v1.0.0 #3520 push-gate regression fix. The first cut of this module bound
/// the literal `public`, on the premise that "the adapter demotes
/// `search_path` to this schema before the bootstrap runs (#3055)". **That
/// premise was wrong, and the mistake was a data-isolation defect, not a
/// tuning one.** `normalize_app_search_path` deliberately KEEPS a
/// caller-supplied first schema, so a connection opened with
/// `options=-c search_path=<fresh>,public` creates into `<fresh>` — while the
/// probe asked about `public`. On any database whose `public` was already
/// bootstrapped, EVERY relation statement was therefore filtered out as
/// "already present" and the connect finished with NO tables in its own
/// schema (`42P01` on first use). Any role or connection with a non-public
/// first `search_path` on a host that also has a public bootstrap silently
/// lost its schema isolation.
///
/// `current_schema()` is the exact answer to the question the filter must
/// ask: PostgreSQL creates an unqualified relation in the first EXISTING
/// schema on `search_path`, and `current_schema()` returns precisely that
/// schema. Asking the catalog about any other namespace is asking a
/// different question than the one `CREATE ... IF NOT EXISTS` will answer.
const EFFECTIVE_SCHEMA_SQL: &str = "current_schema()";

/// One top-level statement's classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StatementKind {
    /// `CREATE [UNIQUE] INDEX IF NOT EXISTS <name>` or
    /// `CREATE TABLE IF NOT EXISTS <name>` — skippable when `<name>` is a
    /// relation in the connection's EFFECTIVE schema (see
    /// [`EFFECTIVE_SCHEMA_SQL`]), i.e. the one an unqualified `CREATE` would
    /// target on THIS connection.
    Relation(String),
    /// `CREATE EXTENSION IF NOT EXISTS <name>` — skippable when installed.
    Extension(String),
    /// Everything else. Always emitted.
    AlwaysRun,
}

/// A top-level statement: its verbatim source text and what it creates.
#[derive(Debug, Clone)]
pub(crate) struct Statement {
    /// Source text INCLUDING the terminating `;`, comments stripped from the
    /// front only (the interior is untouched, so dollar-quoted bodies survive
    /// byte-for-byte).
    pub(crate) text: String,
    pub(crate) kind: StatementKind,
}

/// Splits `sql` into top-level statements.
///
/// Aware of `--` line comments, `/* */` block comments (PostgreSQL nests
/// them), `'...'` strings with `''` escapes, `"..."` quoted identifiers, and
/// `$tag$...$tag$` dollar quoting — which is what makes the `CREATE OR
/// REPLACE FUNCTION` bodies and the `DO $$ ... $$` block come out whole
/// instead of being cut at the first `;` inside them.
pub(crate) fn split_statements(sql: &str) -> Vec<String> {
    let bytes = sql.as_bytes();
    let mut out = Vec::new();
    let mut start = 0_usize;
    let mut i = 0_usize;
    let mut block_depth = 0_u32;

    while i < bytes.len() {
        let rest = &sql[i..];
        if block_depth > 0 {
            if rest.starts_with("/*") {
                block_depth += 1;
                i += 2;
            } else if rest.starts_with("*/") {
                block_depth -= 1;
                i += 2;
            } else {
                i += next_char_len(sql, i);
            }
            continue;
        }
        if rest.starts_with("--") {
            i += rest.find('\n').unwrap_or(rest.len());
            continue;
        }
        if rest.starts_with("/*") {
            block_depth = 1;
            i += 2;
            continue;
        }
        if let Some(end) = scan_quoted(sql, i) {
            i = end;
            continue;
        }
        if bytes[i] == b';' {
            let text = sql[start..=i].trim();
            if !is_comment_only(text) {
                out.push(text.to_string());
            }
            i += 1;
            start = i;
            continue;
        }
        i += next_char_len(sql, i);
    }

    let tail = sql[start..].trim();
    if !is_comment_only(tail) {
        out.push(tail.to_string());
    }
    out
}

/// Byte length of the char at `i`, so the scanner never splits a multi-byte
/// code point (the bundled script carries UTF-8 box-drawing separators).
fn next_char_len(sql: &str, i: usize) -> usize {
    sql[i..].chars().next().map_or(1, char::len_utf8)
}

/// If a quoted region starts at `i`, returns the byte index just past it.
///
/// Handles `'...'` (with `''` escape), `"..."` (with `""` escape) and
/// `$tag$...$tag$`. Returns `None` when `i` is not the start of one.
fn scan_quoted(sql: &str, i: usize) -> Option<usize> {
    let bytes = sql.as_bytes();
    match bytes[i] {
        b'\'' => Some(scan_simple_quote(sql, i, b'\'')),
        b'"' => Some(scan_simple_quote(sql, i, b'"')),
        b'$' => {
            let tag_end = sql[i + 1..].find('$')? + i + 1;
            // A dollar-quote tag is empty or an identifier; anything else
            // (e.g. `$1` binds, which this script does not use) is not one.
            let tag = &sql[i + 1..tag_end];
            if !tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            let delim = &sql[i..=tag_end];
            let body_start = tag_end + 1;
            let close = sql[body_start..].find(delim)? + body_start;
            Some(close + delim.len())
        }
        _ => None,
    }
}

/// Scans a `'`- or `"`-delimited literal starting at `i`, honouring the
/// doubled-delimiter escape. Returns the byte index just past the closer, or
/// the end of input when the literal is unterminated (a malformed script then
/// yields one statement, which the classifier keeps — fail-safe).
fn scan_simple_quote(sql: &str, i: usize, delim: u8) -> usize {
    let bytes = sql.as_bytes();
    let mut j = i + 1;
    while j < bytes.len() {
        if bytes[j] == delim {
            if bytes.get(j + 1) == Some(&delim) {
                j += 2;
                continue;
            }
            return j + 1;
        }
        j += next_char_len(sql, j);
    }
    bytes.len()
}

/// Classifies one statement. Unrecognised shapes are [`StatementKind::AlwaysRun`].
pub(crate) fn classify(statement: &str) -> StatementKind {
    let head = strip_leading_comments(statement);
    let mut tokens = head.split_whitespace();
    if !eq_ignore_case(tokens.next(), "CREATE") {
        return StatementKind::AlwaysRun;
    }
    let mut next = tokens.next();
    if eq_ignore_case(next, "UNIQUE") {
        next = tokens.next();
    }
    let object = match next {
        Some(word) if word.eq_ignore_ascii_case("INDEX") => Object::Relation,
        Some(word) if word.eq_ignore_ascii_case("TABLE") => Object::Relation,
        Some(word) if word.eq_ignore_ascii_case("EXTENSION") => Object::Extension,
        _ => return StatementKind::AlwaysRun,
    };
    let mut next = tokens.next();
    if eq_ignore_case(next, "CONCURRENTLY") {
        next = tokens.next();
    }
    // The `IF NOT EXISTS` guard is REQUIRED for a skip: without it the
    // statement is not idempotent and its presence means the author intended
    // it to run (or to fail loudly).
    if !eq_ignore_case(next, "IF")
        || !eq_ignore_case(tokens.next(), "NOT")
        || !eq_ignore_case(tokens.next(), "EXISTS")
    {
        return StatementKind::AlwaysRun;
    }
    let Some(raw) = tokens.next() else {
        return StatementKind::AlwaysRun;
    };
    let Some(name) = leading_identifier(raw) else {
        // Schema-qualified, quoted, or otherwise not a bare identifier: the
        // catalog probe could not answer it faithfully, so keep the
        // statement (fail SAFE toward running the DDL).
        return StatementKind::AlwaysRun;
    };
    match object {
        Object::Relation => StatementKind::Relation(name),
        Object::Extension => StatementKind::Extension(name),
    }
}

enum Object {
    Relation,
    Extension,
}

/// The bare identifier at the start of `raw`, when the ONLY thing that can
/// follow it is a statement terminator or a column list.
///
/// The tokeniser is whitespace-based, so the object name arrives glued to
/// whatever punctuation the author wrote: `vector;`, `memories`, `t(x`. This
/// accepts exactly the shapes the probe can answer — a bare
/// `[A-Za-z0-9_]` identifier optionally followed by `(` or `;` — and rejects
/// everything else, including a schema-qualified `public.t` (a `.` is not in
/// the identifier set and is not an accepted terminator) and a quoted
/// `"T"` (a `"` is not either).
fn leading_identifier(raw: &str) -> Option<String> {
    let end = raw
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(raw.len());
    if end == 0 {
        return None;
    }
    let rest = &raw[end..];
    if !(rest.is_empty() || rest.starts_with('(') || rest.starts_with(';')) {
        return None;
    }
    Some(raw[..end].to_ascii_lowercase())
}

/// `true` when `chunk` carries no SQL at all — only comments and whitespace.
///
/// The bundled script ends with a comment block after its last `;`; emitting
/// that as a "statement" would make the splitter report an unterminated tail
/// and would put a comment-only fragment into the filtered batch.
fn is_comment_only(chunk: &str) -> bool {
    let mut s = chunk.trim();
    loop {
        if s.starts_with("--") {
            s = s.find('\n').map_or("", |nl| s[nl + 1..].trim_start());
        } else if s.starts_with("/*") {
            match s.find("*/") {
                Some(close) => s = s[close + 2..].trim_start(),
                None => return true,
            }
        } else {
            return s.is_empty();
        }
    }
}

fn eq_ignore_case(token: Option<&str>, want: &str) -> bool {
    token.is_some_and(|t| t.eq_ignore_ascii_case(want))
}

/// Drops leading `--` line comments and whitespace so the classifier sees the
/// statement's first real keyword. Only the FRONT is stripped; the body is
/// left byte-identical because it is what gets executed.
fn strip_leading_comments(statement: &str) -> &str {
    let mut s = statement.trim_start();
    while s.starts_with("--") {
        s = s.find('\n').map_or("", |nl| s[nl + 1..].trim_start());
    }
    s
}

/// Parses the bundled script into classified statements.
pub(crate) fn parse(sql: &str) -> Vec<Statement> {
    split_statements(sql)
        .into_iter()
        .map(|text| {
            let kind = classify(&text);
            Statement { text, kind }
        })
        .collect()
}

/// What the catalog says is already there.
#[derive(Debug, Default, Clone)]
pub(crate) struct CatalogInventory {
    /// The schema the probe actually asked about — the connection's effective
    /// first `search_path` schema. Carried so the boot log names it and so a
    /// regression test can assert WHICH namespace was consulted, rather than
    /// only that the counts came out right.
    pub(crate) schema: String,
    pub(crate) relations: HashSet<String>,
    pub(crate) extensions: HashSet<String>,
}

/// Asks the catalog, in TWO round trips, which of the named relations and
/// extensions already exist.
///
/// Catalog reads only — `pg_class` / `pg_namespace` / `pg_extension` — so
/// this takes no lock on any application relation and cannot itself join the
/// deadlock cycle it exists to prevent.
///
/// # Errors
///
/// Propagates a probe failure. The caller treats that as "inventory unknown"
/// and runs the unfiltered script.
pub(crate) async fn probe(
    pool: &PgPool,
    relations: &[String],
    extensions: &[String],
) -> StoreResult<CatalogInventory> {
    let mut inventory = CatalogInventory::default();
    inventory.schema = effective_schema(pool).await?;
    if !relations.is_empty() {
        // `current_schema()` is evaluated BY THE SERVER on THIS connection, so
        // the namespace filter is always the one an unqualified `CREATE` on
        // this same connection would target. Binding a schema NAME from the
        // client — a constant, or even a value read earlier — reintroduces the
        // regression the moment the two disagree.
        let found: Vec<(String,)> = sqlx::query_as(
            "SELECT c.relname FROM pg_class c \
               JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = current_schema() AND c.relname = ANY($1)",
        )
        .bind(relations)
        .fetch_all(pool)
        .await
        .map_err(|e| super::to_store_err("bootstrap catalog probe (relations)", e))?;
        inventory.relations = found.into_iter().map(|(name,)| name).collect();
    }
    if !extensions.is_empty() {
        let found: Vec<(String,)> =
            sqlx::query_as("SELECT extname FROM pg_extension WHERE extname = ANY($1)")
                .bind(extensions)
                .fetch_all(pool)
                .await
                .map_err(|e| super::to_store_err("bootstrap catalog probe (extensions)", e))?;
        inventory.extensions = found.into_iter().map(|(name,)| name).collect();
    }
    Ok(inventory)
}

/// The schema an unqualified `CREATE` would target on `pool`'s connection.
///
/// # Errors
///
/// Propagates a probe failure; the caller then runs the unfiltered script.
pub(crate) async fn effective_schema(pool: &PgPool) -> StoreResult<String> {
    let (schema,): (String,) = sqlx::query_as(&format!("SELECT {EFFECTIVE_SCHEMA_SQL}"))
        .fetch_one(pool)
        .await
        .map_err(|e| super::to_store_err("bootstrap effective-schema probe", e))?;
    Ok(schema)
}

/// The outcome of filtering the bundled script against the catalog.
#[derive(Debug, Clone)]
pub(crate) struct FilteredDdl {
    /// The statements that still need to run, joined for one `raw_sql` batch
    /// so the bootstrap keeps its all-or-nothing transactional shape.
    pub(crate) sql: String,
    /// How many statements the catalog let us drop.
    pub(crate) skipped: usize,
    /// How many statements the script has in total.
    pub(crate) total: usize,
}

impl FilteredDdl {
    /// `true` when no statement was dropped, i.e. running the filtered text
    /// buys nothing over running the original.
    pub(crate) const fn is_unfiltered(&self) -> bool {
        self.skipped == 0
    }
}

/// Re-emits `statements`, dropping the existence-gated ones whose object the
/// catalog reports as already present.
pub(crate) fn filter(statements: &[Statement], inventory: &CatalogInventory) -> FilteredDdl {
    let mut kept: Vec<&str> = Vec::with_capacity(statements.len());
    for st in statements {
        let present = match &st.kind {
            StatementKind::Relation(name) => inventory.relations.contains(name),
            StatementKind::Extension(name) => inventory.extensions.contains(name),
            StatementKind::AlwaysRun => false,
        };
        if !present {
            kept.push(st.text.as_str());
        }
    }
    FilteredDdl {
        skipped: statements.len() - kept.len(),
        total: statements.len(),
        sql: kept.join("\n"),
    }
}

/// The relation / extension names the script would create, for [`probe`].
pub(crate) fn wanted(statements: &[Statement]) -> (Vec<String>, Vec<String>) {
    let mut relations = Vec::new();
    let mut extensions = Vec::new();
    for st in statements {
        match &st.kind {
            StatementKind::Relation(name) => relations.push(name.clone()),
            StatementKind::Extension(name) => extensions.push(name.clone()),
            StatementKind::AlwaysRun => {}
        }
    }
    relations.sort_unstable();
    relations.dedup();
    extensions.sort_unstable();
    extensions.dedup();
    (relations, extensions)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bundled script this module has to parse correctly. Parsing the
    /// REAL artefact (not a fixture) is the point: a future edit that adds a
    /// statement shape the splitter mishandles fails here.
    const SCHEMA: &str = include_str!("../postgres_schema.sql");

    fn inv(relations: &[&str], extensions: &[&str]) -> CatalogInventory {
        CatalogInventory {
            schema: "public".to_string(),
            relations: relations.iter().map(|s| (*s).to_string()).collect(),
            extensions: extensions.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn dollar_quoted_bodies_are_not_cut_at_their_inner_semicolons_3520() {
        // The `DO $$ ... $$` block and the `CREATE OR REPLACE FUNCTION`
        // bodies both contain `;`. A naive split would shatter them into
        // fragments and the bootstrap would fail on a syntax error — the
        // loudest possible way to get this wrong, but a way that only shows
        // up against a live server, so it is pinned here.
        let sql = "CREATE TABLE IF NOT EXISTS a (x int);\n\
                   DO $$ BEGIN IF true THEN RAISE NOTICE 'hi; there'; END IF; END $$;\n\
                   CREATE INDEX IF NOT EXISTS i_a ON a(x);";
        let out = split_statements(sql);
        assert_eq!(out.len(), 3, "got {out:#?}");
        assert!(out[1].starts_with("DO $$"));
        assert!(out[1].ends_with("$$;"));
    }

    #[test]
    fn comments_and_string_literals_never_terminate_a_statement_3520() {
        let sql = "-- a; comment\n\
                   CREATE TABLE IF NOT EXISTS t (c text DEFAULT 'a;b''c');\n\
                   /* block ; comment */ CREATE INDEX IF NOT EXISTS i ON t(c);";
        let out = split_statements(sql);
        assert_eq!(out.len(), 2, "got {out:#?}");
        assert!(out[0].contains("'a;b''c'"));
    }

    #[test]
    fn only_if_not_exists_creates_are_classified_as_skippable_3520() {
        assert_eq!(
            classify("CREATE INDEX IF NOT EXISTS idx_foo ON foo(bar);"),
            StatementKind::Relation("idx_foo".to_string())
        );
        assert_eq!(
            classify("CREATE UNIQUE INDEX IF NOT EXISTS uq_foo\n    ON foo(bar);"),
            StatementKind::Relation("uq_foo".to_string())
        );
        assert_eq!(
            classify("CREATE TABLE IF NOT EXISTS memories (\n id TEXT\n);"),
            StatementKind::Relation("memories".to_string())
        );
        assert_eq!(
            classify("CREATE EXTENSION IF NOT EXISTS vector;"),
            StatementKind::Extension("vector".to_string())
        );
        // A leading comment must not hide the keyword.
        assert_eq!(
            classify("-- note\n-- more\nCREATE TABLE IF NOT EXISTS t (x int);"),
            StatementKind::Relation("t".to_string())
        );
    }

    #[test]
    fn every_unrecognised_shape_fails_safe_to_always_run_3520() {
        for stmt in [
            // No IF NOT EXISTS: not idempotent, so never skipped.
            "CREATE INDEX idx_foo ON foo(bar);",
            "CREATE TABLE t (x int);",
            // Definition-carrying: existence does not imply currency.
            "CREATE OR REPLACE VIEW kg_query_view AS SELECT 1;",
            "CREATE OR REPLACE FUNCTION f() RETURNS int LANGUAGE SQL AS $$ SELECT 1 $$;",
            "DO $$ BEGIN END $$;",
            // Shapes the probe could not answer faithfully.
            "CREATE TABLE IF NOT EXISTS public.t (x int);",
            "CREATE TABLE IF NOT EXISTS \"T\" (x int);",
            "ALTER TABLE memories ADD COLUMN IF NOT EXISTS x int;",
            "DROP INDEX IF EXISTS memories_content_fts;",
        ] {
            assert_eq!(
                classify(stmt),
                StatementKind::AlwaysRun,
                "must fail safe: {stmt}"
            );
        }
    }

    #[test]
    fn the_bundled_schema_parses_into_whole_statements_3520() {
        let statements = parse(SCHEMA);
        assert!(
            statements.len() > 100,
            "expected the full bundled script, got {}",
            statements.len()
        );
        // Every statement must be terminated: a truncated tail would mean the
        // splitter dropped bytes the server needs to see.
        for st in &statements {
            assert!(
                st.text.ends_with(';'),
                "unterminated statement: {}",
                &st.text[..st.text.len().min(80)]
            );
        }
        let (relations, extensions) = wanted(&statements);
        assert!(
            relations.contains(&"memories".to_string()),
            "the memories table must be recognised as existence-gated"
        );
        assert_eq!(extensions, vec!["vector".to_string()]);
    }

    #[test]
    fn a_fully_migrated_database_emits_no_relation_ddl_3520() {
        let statements = parse(SCHEMA);
        let (relations, extensions) = wanted(&statements);
        let present = inv(
            &relations.iter().map(String::as_str).collect::<Vec<_>>(),
            &extensions.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let filtered = filter(&statements, &present);
        assert!(filtered.skipped > 0, "nothing was skippable");
        assert_eq!(filtered.skipped, relations.len() + extensions.len());
        // The whole point: no CREATE TABLE / CREATE INDEX survives, so the
        // boot takes no ShareLock on any application table.
        for line in filtered.sql.lines() {
            let upper = line.trim_start().to_ascii_uppercase();
            assert!(
                !upper.starts_with("CREATE TABLE")
                    && !upper.starts_with("CREATE INDEX")
                    && !upper.starts_with("CREATE UNIQUE INDEX")
                    && !upper.starts_with("CREATE EXTENSION"),
                "existence-gated DDL survived the filter: {line}"
            );
        }
        // …but the definition-carrying statements DO survive, so a view whose
        // body changed is still replaced.
        assert!(
            filtered
                .sql
                .contains("CREATE OR REPLACE VIEW kg_query_view"),
            "a view replacement must never be skipped"
        );
        assert!(
            filtered.sql.contains("DO $$"),
            "the corruption-refusal DO block must never be skipped"
        );
    }

    #[test]
    fn an_empty_catalog_keeps_the_script_whole_3520() {
        let statements = parse(SCHEMA);
        let filtered = filter(&statements, &CatalogInventory::default());
        assert!(filtered.is_unfiltered());
        assert_eq!(filtered.total, statements.len());
        // A fresh database must still receive every statement — this is the
        // "no change to what a fresh database ends up with" invariant.
        for st in &statements {
            assert!(
                filtered.sql.contains(st.text.as_str()),
                "a fresh install lost a statement: {}",
                &st.text[..st.text.len().min(80)]
            );
        }
    }

    #[test]
    fn a_partially_present_schema_still_heals_the_missing_objects_3520() {
        let statements = parse(SCHEMA);
        let (relations, _) = wanted(&statements);
        // Everything present EXCEPT one index: the self-heal must still emit
        // exactly that statement.
        let missing = relations
            .iter()
            .find(|r| r.starts_with("idx_"))
            .expect("the bundled script defines idx_* indexes")
            .clone();
        let present: Vec<&str> = relations
            .iter()
            .filter(|r| **r != missing)
            .map(String::as_str)
            .collect();
        let filtered = filter(&statements, &inv(&present, &["vector"]));
        assert!(
            filtered.sql.contains(&missing),
            "the missing index {missing} was not re-emitted"
        );
        assert_eq!(filtered.skipped, relations.len(), "one relation + vector");
    }

    // ------------------------------------------------------------------
    // v1.0.0 #3520 push-gate regression — SCHEMA-SCOPED BOOTSTRAP.
    //
    // Runs iff AI_MEMORY_TEST_POSTGRES_URL is set; otherwise self-skips. No
    // shape guard: the test creates and drops its OWN uuid-suffixed schema
    // and touches nothing else, so it is safe against any store (the same
    // reasoning as `tx_retry`'s live cell, and the reason the 2026-09-07
    // lane rule needs no name/port guard here).
    // ------------------------------------------------------------------

    /// The exact defect the first cut of this module shipped: a probe that
    /// asks about the LITERAL `public` instead of the connection's effective
    /// schema.
    ///
    /// Kept as an explicit oracle so the regression below asserts the DEFECT
    /// and not merely the fix. A test that only checked "the tables exist"
    /// would also pass on a build where the filter was disabled outright, and
    /// would tell a reviewer nothing about WHY it now passes.
    async fn relations_present_in_literal_public(
        pool: &sqlx::PgPool,
        relations: &[String],
    ) -> Vec<String> {
        let found: Vec<(String,)> = sqlx::query_as(
            "SELECT c.relname FROM pg_class c \
               JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = 'public' AND c.relname = ANY($1)",
        )
        .bind(relations)
        .fetch_all(pool)
        .await
        .expect("legacy literal-public probe");
        found.into_iter().map(|(n,)| n).collect()
    }

    /// A connect pinned at a FRESH schema must create the full relation set
    /// in THAT schema, even when `public` is already fully bootstrapped.
    ///
    /// This is the push-gate regression: `public` bootstrapped first, then a
    /// `options=-c search_path=<fresh>,public` connect. Pre-fix the probe
    /// asked about `public`, saw everything, filtered every `CREATE TABLE` /
    /// `CREATE INDEX` out, and left `<fresh>` EMPTY — `42P01` on first use,
    /// i.e. a silent loss of schema isolation for any role whose search_path
    /// does not start at `public`.
    #[tokio::test]
    async fn a_schema_scoped_connect_creates_its_own_relations_3520() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let raw = match sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("skip: cannot reach AI_MEMORY_TEST_POSTGRES_URL: {e}");
                return;
            }
        };

        // STEP 1 — `public` must be fully bootstrapped, because that is the
        // precondition that turns the bug on. A fresh database HIDES it.
        crate::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("plain connect bootstraps public");

        let schema = format!("bootstrap_3520_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&raw)
            .await
            .expect("create isolated schema");

        // Keep `public` on the path so the pgvector type still resolves,
        // exactly as tests/lineage_schema_masks_loss_3172.rs does; unqualified
        // CREATE then lands in `{schema}` because it is FIRST.
        let scoped_url = if url.contains('?') {
            format!("{url}&options=-c%20search_path%3D{schema}%2Cpublic")
        } else {
            format!("{url}?options=-c%20search_path%3D{schema}%2Cpublic")
        };
        let scoped = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&scoped_url)
            .await
            .expect("scoped pool");

        // The bundled script itself: `parse` only reads statement SHAPES, and the
        // `vector({EMBEDDING_DIM})` placeholder never appears in a relation name.
        let statements = parse(SCHEMA);
        let (relations, extensions) = wanted(&statements);
        assert!(
            !relations.is_empty(),
            "the bundled script defines relations"
        );

        // ASSERTION 1 — the probe consults the CONNECTION's schema, not a
        // constant. This is the fix, stated directly.
        let inventory = probe(&scoped, &relations, &extensions)
            .await
            .expect("probe on the scoped connection");
        assert_eq!(
            inventory.schema, schema,
            "the probe must ask about the schema an unqualified CREATE targets"
        );

        // ASSERTION 2 — on the FRESH schema the probe finds nothing, so
        // nothing is filtered and the whole script runs.
        assert!(
            inventory.relations.is_empty(),
            "a fresh schema holds none of the script's relations, but the probe \
             reported {} of them present",
            inventory.relations.len()
        );
        let filtered = filter(&statements, &inventory);
        // The ONLY admissible skip on a fresh schema is the `CREATE EXTENSION`
        // half: `pg_extension.extname` is database-GLOBAL, so an extension
        // installed for `public` is installed for `{schema}` too and
        // re-issuing it would be the redundant work the filter exists to drop.
        // Every RELATION statement must survive — that is the regression.
        assert_eq!(
            filtered.skipped,
            inventory.extensions.len(),
            "on a fresh schema only the already-installed extensions may be \
             skipped, but {} statements were dropped ({} extensions present)",
            filtered.skipped,
            inventory.extensions.len()
        );
        // Structural, not textual: every RELATION-kind statement must still be
        // in the batch. (Counting by text prefix would be wrong — a statement's
        // text carries its leading comments.)
        let relation_statements: Vec<&Statement> = statements
            .iter()
            .filter(|s| matches!(s.kind, StatementKind::Relation(_)))
            .collect();
        assert_eq!(
            relation_statements.len(),
            relations.len(),
            "every relation the script names must have a statement"
        );
        for st in &relation_statements {
            assert!(
                filtered.sql.contains(st.text.as_str()),
                "a relation statement was dropped for a fresh schema: {}",
                &st.text[..st.text.len().min(80)]
            );
        }

        // ASSERTION 3 — the DEFECT oracle: the pre-fix literal-`public` probe
        // WOULD have reported these same relations present, and would
        // therefore have skipped every one of them. Without this the test
        // could not distinguish the fix from a disabled filter.
        let legacy = relations_present_in_literal_public(&scoped, &relations).await;
        assert_eq!(
            legacy.len(),
            relations.len(),
            "precondition: public must be fully bootstrapped for this regression \
             to be meaningful (found {} of {})",
            legacy.len(),
            relations.len()
        );

        // STEP 2 — the real connect through the adapter.
        crate::store::postgres::PostgresStore::connect(&scoped_url)
            .await
            .expect("schema-scoped connect");

        // ASSERTION 4 — the full relation set now exists IN `{schema}`.
        // Counted against the catalog, keyed on the isolated namespace.
        let present: Vec<(String,)> = sqlx::query_as(
            "SELECT c.relname FROM pg_class c \
               JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = $1 AND c.relname = ANY($2)",
        )
        .bind(&schema)
        .bind(&relations)
        .fetch_all(&raw)
        .await
        .expect("census of the isolated schema");
        let present: std::collections::HashSet<String> =
            present.into_iter().map(|(n,)| n).collect();
        let missing: Vec<&String> = relations.iter().filter(|r| !present.contains(*r)).collect();
        assert!(
            missing.is_empty(),
            "the schema-scoped connect left {} of {} relations missing from {schema}: {:?}",
            missing.len(),
            relations.len(),
            &missing[..missing.len().min(10)]
        );

        let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
            .execute(&raw)
            .await;
    }
}
