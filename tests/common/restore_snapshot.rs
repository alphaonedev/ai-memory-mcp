// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #9944 — the ONE typed full-store snapshot and the ONE comparison
//! every restore-fidelity cell uses, on both backends.
//!
//! A backend reader (rusqlite in `tests/restore_fidelity_9944.rs`, sqlx in
//! `tests/restore_fidelity_9944_pg.rs`) fills a [`StoreSnapshot`] with EVERY
//! table, EVERY column and EVERY schema object it finds in the live store;
//! [`compare`] then checks the restored snapshot against the source under a
//! per-path [`Classification`]. Nothing is compared by a hand-written column
//! list: a new column is compared by default, and a new table is a "not
//! classified" difference until the path names its disposition.
//!
//! The source side of a comparison is a [`SourceStore`], whose only
//! constructor refuses a corpus that would let a cell pass vacuously
//! (#10014, #10015): an `Exact` table with fewer than [`MIN_SOURCE_ROWS`]
//! rows, or a compared column that is NULL on every row, is refused unless the
//! path lists it with a tracked reason. A count-only or vacuous cell is
//! therefore not representable: `compare` takes no bare snapshot as its
//! source.
//!
//! Included with `#[path]` by each binary, so not every item is used by every
//! includer.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

/// The fewest source rows an `Exact` table may hold (#10014): one row cannot
/// tell "every row carried" from "the first row carried".
pub const MIN_SOURCE_ROWS: usize = 2;

/// The prefix of a reason that names a by-design disposition instead of an
/// issue number (#10020).
pub const BY_DESIGN: &str = "by design:";

/// One stored value, keeping its storage class. REAL compares by bit pattern
/// (PERF-25: never `==` on floats for logic), TEXT and BLOB byte by byte
/// (#10018: TEXT is never decoded lossily before it is compared). `Bool` is
/// the PostgreSQL boolean (#10019).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SqlValue {
    Null,
    Integer(i64),
    Real(u64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
    Bool(bool),
}

impl SqlValue {
    /// A TEXT value holding `s`.
    #[must_use]
    pub fn text(s: &str) -> Self {
        Self::Text(s.as_bytes().to_vec())
    }

    /// A REAL value holding `f` (compared by bit pattern).
    #[must_use]
    pub fn real(f: f64) -> Self {
        Self::Real(f.to_bits())
    }

    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// The TEXT bytes as UTF-8, or `None` (not TEXT, or not valid UTF-8).
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(bytes) => std::str::from_utf8(bytes).ok(),
            _ => None,
        }
    }

    /// Render for a diff report only. TEXT is shown lossily here and nowhere
    /// else, with a marker when the bytes are not UTF-8.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::Null => "NULL".to_string(),
            Self::Integer(i) => format!("INTEGER {i}"),
            Self::Real(bits) => format!("REAL {:?}", f64::from_bits(*bits)),
            Self::Text(bytes) => match std::str::from_utf8(bytes) {
                Ok(s) => format!("TEXT {s:?}"),
                Err(_) => format!(
                    "TEXT {:?} (not UTF-8: {} bytes)",
                    String::from_utf8_lossy(bytes),
                    bytes.len()
                ),
            },
            Self::Blob(bytes) => {
                let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                format!("BLOB x'{hex}'")
            }
            Self::Bool(b) => format!("BOOLEAN {b}"),
        }
    }
}

/// One row: column name to value, in column-name order.
pub type Row = BTreeMap<String, SqlValue>;

/// One table: its column list and its rows in canonical (sorted) order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSnapshot {
    pub columns: Vec<String>,
    pub rows: Vec<Row>,
}

/// One schema object (#10017): on SQLite one `sqlite_master` row (type, name,
/// tbl_name, sql); on PostgreSQL one table, column or index definition.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SchemaObject {
    pub kind: String,
    pub name: String,
    pub table: String,
    pub sql: SqlValue,
}

/// Every table and every schema object of a store.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoreSnapshot {
    pub tables: BTreeMap<String, TableSnapshot>,
    /// Sorted.
    pub schema: Vec<SchemaObject>,
}

impl StoreSnapshot {
    /// Rows of `table` (0 when the table is absent).
    #[must_use]
    pub fn row_count(&self, table: &str) -> usize {
        self.tables.get(table).map_or(0, |t| t.rows.len())
    }

    /// Rows of `table` whose `column` equals the text `value`.
    #[must_use]
    pub fn rows_where(&self, table: &str, column: &str, value: &str) -> Vec<Row> {
        let want = SqlValue::text(value);
        self.tables.get(table).map_or_else(Vec::new, |t| {
            t.rows
                .iter()
                .filter(|r| r.get(column) == Some(&want))
                .cloned()
                .collect()
        })
    }
}

/// What a path promises about one table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carry {
    /// Every row and every column (minus the lossy and re-derived columns)
    /// equals the source; the row multisets are equal.
    Exact,
    /// The path does not carry this table; the reason names why.
    NotCarried(&'static str),
}

/// One `(table, column, reason)` entry of a [`Classification`] column list.
pub type ColumnEntry = (&'static str, &'static str, &'static str);

/// One `(table, reason)` entry: an `Exact` table allowed fewer than
/// [`MIN_SOURCE_ROWS`] source rows.
pub type TableEntry = (&'static str, &'static str);

/// The value a re-derived column must hold on EVERY restored row, written out
/// (never computed from the code under test).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Exactly this TEXT.
    Text(&'static str),
    /// An RFC 3339 timestamp the destination stamped itself: it parses and
    /// differs from the paired source row's value.
    Restamped,
}

impl Expect {
    fn holds(self, source: &SqlValue, restored: &SqlValue) -> bool {
        match self {
            Self::Text(want) => restored.as_str() == Some(want),
            Self::Restamped => {
                restored != source
                    && restored
                        .as_str()
                        .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok())
            }
        }
    }

    fn describe(self) -> String {
        match self {
            Self::Text(want) => format!("TEXT {want:?}"),
            Self::Restamped => "an RFC 3339 stamp other than the source value".to_string(),
        }
    }
}

/// One re-derived column: the destination writes it itself.
#[derive(Debug, Clone, Copy)]
pub struct Rederived {
    pub table: &'static str,
    pub column: &'static str,
    pub reason: &'static str,
    pub expect: Expect,
}

/// Which schema the restored store must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaBaseline {
    /// Exactly the source schema (a byte copy of the store).
    Source,
    /// Exactly the schema the destination held before the import (a fresh
    /// store): the import must not change it.
    Destination,
}

/// A path's full disposition: one [`Carry`] per table; the columns of a
/// carried table the path does not keep (`lossy`: the restored store holds
/// NULL on every row); the columns the destination writes itself
/// (`rederived`); the `Exact` tables a corpus may leave sparse (`sparse`);
/// the compared columns a corpus may leave NULL on every row
/// (`null_columns`); and which schema the restored store must hold. Every
/// reason names an issue (`#<n>`) or starts with [`BY_DESIGN`].
pub struct Classification {
    pub path: &'static str,
    pub tables: &'static [(&'static str, Carry)],
    pub lossy: &'static [ColumnEntry],
    pub rederived: &'static [Rederived],
    pub sparse: &'static [TableEntry],
    pub null_columns: &'static [ColumnEntry],
    pub schema: SchemaBaseline,
}

/// A reason names a tracked issue (`#` then digits) or starts with
/// [`BY_DESIGN`] followed by text (#10020).
#[must_use]
pub fn reason_is_tracked(reason: &str) -> bool {
    if let Some(rest) = reason.strip_prefix(BY_DESIGN) {
        return rest.trim().chars().count() >= 10;
    }
    let bytes = reason.as_bytes();
    bytes
        .windows(2)
        .any(|w| w[0] == b'#' && w[1].is_ascii_digit())
}

impl Classification {
    #[must_use]
    pub fn carry(&self, table: &str) -> Option<Carry> {
        self.tables
            .iter()
            .find(|(t, _)| *t == table)
            .map(|(_, c)| *c)
    }

    #[must_use]
    pub fn lossy_columns(&self, table: &str) -> BTreeSet<&'static str> {
        columns_of(self.lossy, table)
    }

    #[must_use]
    pub fn rederived_columns(&self, table: &str) -> BTreeSet<&'static str> {
        self.rederived
            .iter()
            .filter(|r| r.table == table)
            .map(|r| r.column)
            .collect()
    }

    fn is_sparse_allowed(&self, table: &str) -> bool {
        self.sparse.iter().any(|(t, _)| *t == table)
    }

    fn is_null_allowed(&self, table: &str, column: &str) -> bool {
        self.null_columns
            .iter()
            .any(|(t, c, _)| *t == table && *c == column)
    }

    /// The ratchet: every live table is classified exactly once, no stale
    /// table is classified, every reason is tracked, and every column entry
    /// names a live column of a carried table. Returns the problems (empty =
    /// in step).
    #[must_use]
    pub fn ratchet(&self, live: &StoreSnapshot) -> Vec<String> {
        let mut problems = Vec::new();
        let names: BTreeSet<&str> = live.tables.keys().map(String::as_str).collect();
        let classified: BTreeSet<&str> = self.tables.iter().map(|(t, _)| *t).collect();
        if classified.len() != self.tables.len() {
            problems.push(format!("{}: a table is classified twice", self.path));
        }
        for t in names.difference(&classified) {
            problems.push(format!(
                "{}: live table {t} is not classified (columns {:?})",
                self.path, live.tables[*t].columns
            ));
        }
        for t in classified.difference(&names) {
            problems.push(format!(
                "{}: classified table {t} is not in the live schema",
                self.path
            ));
        }
        for (table, carry) in self.tables {
            if let Carry::NotCarried(why) = carry
                && !reason_is_tracked(why)
            {
                problems.push(format!(
                    "{}: {table}: reason {why:?} names no issue (#<n>) and is not `{BY_DESIGN}`",
                    self.path
                ));
            }
        }
        for (table, column, _) in self.lossy {
            if self
                .rederived
                .iter()
                .any(|r| r.table == *table && r.column == *column)
            {
                problems.push(format!(
                    "{}: {table}.{column} is listed both lossy and re-derived",
                    self.path
                ));
            }
        }
        let column_entries = self
            .lossy
            .iter()
            .chain(self.null_columns)
            .copied()
            .chain(self.rederived.iter().map(|r| (r.table, r.column, r.reason)));
        for (table, column, reason) in column_entries {
            if !reason_is_tracked(reason) {
                problems.push(format!(
                    "{}: {table}.{column}: reason {reason:?} names no issue (#<n>) and is not `{BY_DESIGN}`",
                    self.path
                ));
            }
            match live.tables.get(table) {
                Some(t) if t.columns.iter().any(|c| c == column) => {}
                _ => problems.push(format!(
                    "{}: column entry {table}.{column} names no live column",
                    self.path
                )),
            }
            if self.carry(table) != Some(Carry::Exact) {
                problems.push(format!(
                    "{}: column entry {table}.{column} is on a table the path does not carry",
                    self.path
                ));
            }
        }
        for (table, reason) in self.sparse {
            if !reason_is_tracked(reason) {
                problems.push(format!(
                    "{}: sparse {table}: reason {reason:?} names no issue (#<n>) and is not `{BY_DESIGN}`",
                    self.path
                ));
            }
            if self.carry(table) != Some(Carry::Exact) {
                problems.push(format!(
                    "{}: sparse entry {table} is on a table the path does not carry",
                    self.path
                ));
            }
        }
        problems
    }
}

fn columns_of(entries: &[ColumnEntry], table: &str) -> BTreeSet<&'static str> {
    entries
        .iter()
        .filter(|(t, _, _)| *t == table)
        .map(|(_, c, _)| *c)
        .collect()
}

/// The validated source side of a comparison (CBC-03): the only way to build
/// one is [`SourceStore::new`], which refuses a corpus under which a cell
/// could pass vacuously.
#[derive(Debug, Clone)]
pub struct SourceStore {
    snapshot: StoreSnapshot,
}

impl SourceStore {
    /// Accept `snapshot` as the source of `class` only when every `Exact`
    /// table holds at least [`MIN_SOURCE_ROWS`] rows (unless listed sparse)
    /// and every compared column of it is set on some row (unless listed in
    /// `null_columns`), the ratchet is in step, and no allowlist entry is
    /// stale. Returns every refusal.
    ///
    /// # Errors
    /// The list of refusals, one line each.
    pub fn new(class: &Classification, snapshot: StoreSnapshot) -> Result<Self, Vec<String>> {
        let mut problems = class.ratchet(&snapshot);
        for (table, carry) in class.tables {
            if *carry != Carry::Exact {
                continue;
            }
            let Some(t) = snapshot.tables.get(*table) else {
                continue; // reported by the ratchet
            };
            let rows = t.rows.len();
            let sparse_ok = class.is_sparse_allowed(table);
            if rows < MIN_SOURCE_ROWS && !sparse_ok {
                problems.push(format!(
                    "{}: {table}: {rows} source rows; an Exact table needs at least \
                     {MIN_SOURCE_ROWS} (seed it, or list it sparse with a tracked reason)",
                    class.path
                ));
            }
            if rows >= MIN_SOURCE_ROWS && sparse_ok {
                problems.push(format!(
                    "{}: {table}: listed sparse but the corpus holds {rows} rows; drop the entry",
                    class.path
                ));
            }
            if rows == 0 {
                continue;
            }
            let lossy = class.lossy_columns(table);
            for col in &t.columns {
                let set = t
                    .rows
                    .iter()
                    .any(|r| r.get(col).is_some_and(|v| !v.is_null()));
                let allowed = class.is_null_allowed(table, col);
                if !set && !allowed && !lossy.contains(col.as_str()) {
                    problems.push(format!(
                        "{}: {table}.{col}: NULL on every source row; a compared column \
                         must be set on some row (seed it, or list it in null_columns \
                         with a tracked reason)",
                        class.path
                    ));
                }
                if set && allowed {
                    problems.push(format!(
                        "{}: {table}.{col}: listed in null_columns but the corpus sets it; \
                         drop the entry",
                        class.path
                    ));
                }
            }
        }
        if problems.is_empty() {
            Ok(Self { snapshot })
        } else {
            Err(problems)
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> &StoreSnapshot {
        &self.snapshot
    }
}

/// Strip the `drop` columns from every row and sort.
fn project(rows: &[Row], drop: &BTreeSet<&str>) -> Vec<Row> {
    let mut out: Vec<Row> = rows.iter().map(|r| project_row(r, drop)).collect();
    out.sort();
    out
}

fn project_row(row: &Row, drop: &BTreeSet<&str>) -> Row {
    row.iter()
        .filter(|(c, _)| !drop.contains(c.as_str()))
        .map(|(c, v)| (c.clone(), v.clone()))
        .collect()
}

/// How many differing rows a diff report names before it stops.
const DIFF_ROWS_SHOWN: usize = 3;
/// How many characters of one value a diff report quotes.
const DIFF_VALUE_CHARS: usize = 96;

/// Quote a value for a diff report, cut on a char boundary.
fn quote(v: Option<&SqlValue>) -> String {
    let text = v.map_or_else(|| "absent".to_string(), SqlValue::render);
    if text.chars().count() <= DIFF_VALUE_CHARS {
        return text;
    }
    let cut: String = text.chars().take(DIFF_VALUE_CHARS).collect();
    format!("{cut}…")
}

/// The columns in which `a` and `b` differ, with both values quoted.
fn column_diff(a: &Row, b: &Row) -> Vec<String> {
    let cols: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    cols.into_iter()
        .filter(|c| a.get(*c) != b.get(*c))
        .map(|c| {
            format!(
                "{c}: source {} restored {}",
                quote(a.get(c)),
                quote(b.get(c))
            )
        })
        .collect()
}

/// The row of `pool` sharing the most column values with `row`.
fn closest<'a>(row: &Row, pool: &'a [Row]) -> Option<&'a Row> {
    pool.iter()
        .max_by_key(|r| row.iter().filter(|(c, v)| r.get(*c) == Some(*v)).count())
}

/// Multiset difference `a - b` (both sorted).
fn multiset_minus<'a>(a: &'a [Row], b: &[Row]) -> Vec<&'a Row> {
    let mut counts: BTreeMap<&Row, usize> = BTreeMap::new();
    for r in b {
        *counts.entry(r).or_insert(0) += 1;
    }
    let mut out = Vec::new();
    for r in a {
        match counts.get_mut(r) {
            Some(n) if *n > 0 => *n -= 1,
            _ => out.push(r),
        }
    }
    out
}

/// Name the source rows the restored table lacks (each against its closest
/// restored row, every differing column with both values) and the restored
/// rows the source lacks.
fn describe_row_diff(table: &str, src: &[Row], dst: &[Row]) -> String {
    let missing = multiset_minus(src, dst);
    let extra = multiset_minus(dst, src);
    let mut out = format!(
        "{table}: {} source rows, {} restored rows, {} source rows not reproduced, \
         {} restored rows not in the source",
        src.len(),
        dst.len(),
        missing.len(),
        extra.len()
    );
    for row in missing.iter().take(DIFF_ROWS_SHOWN) {
        match closest(row, dst) {
            Some(peer) => {
                for line in column_diff(row, peer) {
                    out.push_str("\n      ");
                    out.push_str(&line);
                }
            }
            None => out.push_str("\n      the restored table is empty"),
        }
        out.push_str("\n      --");
    }
    if missing.is_empty() {
        for row in extra.iter().take(DIFF_ROWS_SHOWN) {
            out.push_str("\n      extra restored row:");
            for (c, v) in *row {
                out.push_str(&format!(" {c}={}", quote(Some(v))));
            }
        }
    }
    out
}

/// Compare the restored schema with the baseline, object by object.
fn compare_schema(path: &str, baseline: &[SchemaObject], restored: &[SchemaObject]) -> Vec<String> {
    let key = |o: &SchemaObject| (o.kind.clone(), o.name.clone());
    let base: BTreeMap<_, &SchemaObject> = baseline.iter().map(|o| (key(o), o)).collect();
    let dst: BTreeMap<_, &SchemaObject> = restored.iter().map(|o| (key(o), o)).collect();
    let mut diffs = Vec::new();
    for ((kind, name), o) in &base {
        match dst.get(&(kind.clone(), name.clone())) {
            None => diffs.push(format!(
                "schema: {kind} {name} on {} missing from the restored store ({path})",
                o.table
            )),
            Some(d) if d != o => diffs.push(format!(
                "schema: {kind} {name} differs ({path}): source table {} sql {} restored table {} sql {}",
                o.table,
                quote(Some(&o.sql)),
                d.table,
                quote(Some(&d.sql))
            )),
            Some(_) => {}
        }
    }
    for ((kind, name), o) in &dst {
        if !base.contains_key(&(kind.clone(), name.clone())) {
            diffs.push(format!(
                "schema: {kind} {name} on {} only in the restored store ({path})",
                o.table
            ));
        }
    }
    diffs
}

/// The one shared comparison: `restored` equals `source` under `class`, every
/// lossy column really is lost, every re-derived column holds its written-out
/// value on every restored row, and the schema equals its baseline
/// (`destination_schema` is the destination's schema before the restore, used
/// for [`SchemaBaseline::Destination`]). Returns every difference (empty =
/// exact).
#[must_use]
pub fn compare(
    class: &Classification,
    source: &SourceStore,
    restored: &StoreSnapshot,
    destination_schema: &[SchemaObject],
) -> Vec<String> {
    let source = source.snapshot();
    let mut diffs = Vec::new();
    let baseline = match class.schema {
        SchemaBaseline::Source => source.schema.as_slice(),
        SchemaBaseline::Destination => destination_schema,
    };
    if baseline.is_empty() {
        diffs.push(format!("{}: the schema baseline is empty", class.path));
    }
    diffs.extend(compare_schema(class.path, baseline, &restored.schema));
    for table in restored.tables.keys() {
        if !source.tables.contains_key(table) {
            diffs.push(format!("{table}: table only in the restored store"));
        }
    }
    for (table, src) in &source.tables {
        let Some(carry) = class.carry(table) else {
            diffs.push(format!(
                "{}: live table {table} is not classified",
                class.path
            ));
            continue;
        };
        if matches!(carry, Carry::NotCarried(_)) {
            continue;
        }
        let Some(dst) = restored.tables.get(table) else {
            diffs.push(format!("{table}: missing from the restored store"));
            continue;
        };
        let lossy = class.lossy_columns(table);
        let rederived = class.rederived_columns(table);
        let drop: BTreeSet<&str> = lossy.union(&rederived).copied().collect();
        let src_rows = project(&src.rows, &drop);
        let dst_rows = project(&dst.rows, &drop);
        if src.columns != dst.columns {
            diffs.push(format!(
                "{table}: column list differs: {:?} vs {:?}",
                src.columns, dst.columns
            ));
        }
        if src_rows != dst_rows {
            diffs.push(describe_row_diff(table, &src_rows, &dst_rows));
        }
        for entry in class.rederived.iter().filter(|r| r.table == table) {
            diffs.extend(check_rederived(
                class.path, entry, &drop, &src.rows, &dst.rows,
            ));
        }
        for col in &lossy {
            let set = |rows: &[Row]| {
                rows.iter()
                    .any(|r| r.get(*col).is_some_and(|v| !v.is_null()))
            };
            if !set(&src.rows) {
                diffs.push(format!(
                    "{table}.{col}: lossy entry is vacuous: the corpus never sets it"
                ));
            }
            if set(&dst.rows) {
                diffs.push(format!(
                    "{table}.{col}: listed lossy for {} but the restore carried it; \
                     drop the lossy entry",
                    class.path
                ));
            }
        }
    }
    diffs
}

/// A re-derived column, row by row (#10023): the corpus sets it, and every
/// restored row, paired with its source row by the compared columns, holds
/// the entry's written-out value.
fn check_rederived(
    path: &str,
    entry: &Rederived,
    drop: &BTreeSet<&str>,
    src: &[Row],
    dst: &[Row],
) -> Vec<String> {
    let (table, col) = (entry.table, entry.column);
    let mut diffs = Vec::new();
    if src.iter().all(|r| r.get(col).is_none_or(SqlValue::is_null)) {
        diffs.push(format!(
            "{table}.{col}: re-derived entry is vacuous: the corpus never sets it"
        ));
    }
    let null = SqlValue::Null;
    let mut shown = 0;
    for row in dst {
        let key = project_row(row, drop);
        let peer = src.iter().find(|s| project_row(s, drop) == key);
        let restored = row.get(col).unwrap_or(&null);
        let source = peer.and_then(|p| p.get(col)).unwrap_or(&null);
        if peer.is_none() || !entry.expect.holds(source, restored) {
            if shown < DIFF_ROWS_SHOWN {
                diffs.push(format!(
                    "{table}.{col}: listed re-derived for {path} as {}; a restored row holds {} \
                     (source {})",
                    entry.expect.describe(),
                    quote(Some(restored)),
                    peer.map_or_else(|| "row absent".to_string(), |_| quote(Some(source)))
                ));
            }
            shown += 1;
        }
    }
    diffs
}

/// Panic with every difference when `restored` is not `source` under `class`.
#[track_caller]
pub fn assert_restored(
    class: &Classification,
    source: &SourceStore,
    restored: &StoreSnapshot,
    destination_schema: &[SchemaObject],
) {
    let diffs = compare(class, source, restored, destination_schema);
    assert!(
        diffs.is_empty(),
        "{} did not restore its source exactly:\n  {}",
        class.path,
        diffs.join("\n  ")
    );
}

/// Build the [`SourceStore`] of `class`, panicking with every refusal.
#[track_caller]
#[must_use]
pub fn source_store(class: &Classification, snapshot: StoreSnapshot) -> SourceStore {
    match SourceStore::new(class, snapshot) {
        Ok(store) => store,
        Err(problems) => panic!(
            "{}: the corpus cannot prove this path (#10014/#10015):\n  {}",
            class.path,
            problems.join("\n  ")
        ),
    }
}
