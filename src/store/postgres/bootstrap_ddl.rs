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

/// Schema the bootstrap creates into. The adapter demotes `search_path` to
/// this schema before the bootstrap runs (#3055), and the existing pgvector
/// `atttypmod` probe already pins the same value, so a relation found here is
/// the relation `CREATE ... IF NOT EXISTS` would have found.
const BOOTSTRAP_SCHEMA: &str = "public";

/// One top-level statement's classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StatementKind {
    /// `CREATE [UNIQUE] INDEX IF NOT EXISTS <name>` or
    /// `CREATE TABLE IF NOT EXISTS <name>` — skippable when `<name>` is a
    /// relation in [`BOOTSTRAP_SCHEMA`].
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
    if !relations.is_empty() {
        let found: Vec<(String,)> = sqlx::query_as(
            "SELECT c.relname FROM pg_class c \
               JOIN pg_namespace n ON n.oid = c.relnamespace \
              WHERE n.nspname = $1 AND c.relname = ANY($2)",
        )
        .bind(BOOTSTRAP_SCHEMA)
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
