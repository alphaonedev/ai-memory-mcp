// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #9944 — the ONE typed full-store snapshot and the ONE comparison
//! every restore-fidelity cell uses, on both backends.
//!
//! A backend reader (rusqlite in `tests/restore_fidelity_9944.rs`, sqlx in
//! `tests/restore_fidelity_9944_pg.rs`) fills a [`StoreSnapshot`] with EVERY
//! table and EVERY column it finds in the live schema; [`compare`] then checks
//! the restored snapshot against the source under a per-path
//! [`Classification`]. Nothing is compared by a hand-written column list: a
//! new column is compared by default, and a new table is a "not classified"
//! difference until the path names its disposition.
//!
//! Included with `#[path]` by each binary, so not every item is used by every
//! includer.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

/// One stored value, keeping its storage class. REAL compares by bit pattern
/// (PERF-25: never `==` on floats for logic), BLOB byte by byte.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SqlValue {
    Null,
    Integer(i64),
    Real(u64),
    Text(String),
    Blob(Vec<u8>),
}

impl SqlValue {
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
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

/// Every table of a store.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoreSnapshot {
    pub tables: BTreeMap<String, TableSnapshot>,
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
        let want = SqlValue::Text(value.to_string());
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
    /// Every row and every column (minus the lossy columns) equals the source.
    Exact,
    /// Every source row is present byte-exact (minus the lossy columns); the
    /// destination may hold extra rows the restore itself wrote (its own
    /// audit or bootstrap rows). The reason names those extra rows.
    SourceRowsKept(&'static str),
    /// The path does not carry this table; the reason names why.
    NotCarried(&'static str),
}

/// One `(table, column, reason)` entry of a [`Classification`] column list.
pub type ColumnEntry = (&'static str, &'static str, &'static str);

/// A path's full disposition: one [`Carry`] per table, plus the columns of a
/// carried table the path does not keep (`lossy`: the restored store holds
/// NULL on every row) and the columns the destination writes itself
/// (`rederived`: set on every restored row, but not to the source values),
/// each with its reason.
pub struct Classification {
    pub path: &'static str,
    pub tables: &'static [(&'static str, Carry)],
    pub lossy: &'static [ColumnEntry],
    pub rederived: &'static [ColumnEntry],
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
        columns_of(self.rederived, table)
    }

    /// The ratchet: every live table is classified exactly once, no stale
    /// table is classified, and every lossy entry names a live column of a
    /// carried table with a reason. Returns the problems (empty = in step).
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
        for (_, carry) in self.tables {
            if let Carry::SourceRowsKept(why) | Carry::NotCarried(why) = carry
                && why.len() < 10
            {
                problems.push(format!("{}: a disposition needs a reason", self.path));
            }
        }
        for (table, column, _) in self.lossy {
            if self
                .rederived
                .iter()
                .any(|(t, c, _)| t == table && c == column)
            {
                problems.push(format!(
                    "{}: {table}.{column} is listed both lossy and re-derived",
                    self.path
                ));
            }
        }
        for (table, column, reason) in self.lossy.iter().chain(self.rederived) {
            if reason.len() < 10 {
                problems.push(format!(
                    "{}: {table}.{column} column entry needs a reason",
                    self.path
                ));
            }
            match live.tables.get(*table) {
                Some(t) if t.columns.iter().any(|c| c == column) => {}
                _ => problems.push(format!(
                    "{}: lossy entry {table}.{column} names no live column",
                    self.path
                )),
            }
            if !matches!(
                self.carry(table),
                Some(Carry::Exact | Carry::SourceRowsKept(_))
            ) {
                problems.push(format!(
                    "{}: lossy entry {table}.{column} is on a table the path does not carry",
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

/// Strip the `drop` columns from every row and sort.
fn project(rows: &[Row], drop: &BTreeSet<&str>) -> Vec<Row> {
    let mut out: Vec<Row> = rows
        .iter()
        .map(|r| {
            r.iter()
                .filter(|(c, _)| !drop.contains(c.as_str()))
                .map(|(c, v)| (c.clone(), v.clone()))
                .collect()
        })
        .collect();
    out.sort();
    out
}

/// How many differing source rows a diff report names before it stops.
const DIFF_ROWS_SHOWN: usize = 3;
/// How many characters of one value a diff report quotes.
const DIFF_VALUE_CHARS: usize = 96;

/// Quote a value for a diff report, cut on a char boundary.
fn quote(v: Option<&SqlValue>) -> String {
    let text = format!("{v:?}");
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

/// The restored row sharing the most column values with `row`.
fn closest<'a>(row: &Row, dst: &'a [Row]) -> Option<&'a Row> {
    dst.iter()
        .max_by_key(|r| row.iter().filter(|(c, v)| r.get(*c) == Some(*v)).count())
}

/// Name the source rows the restored table lacks, each against its closest
/// restored row, with every differing column and both values.
fn describe_row_diff(table: &str, src: &[Row], dst: &[Row]) -> String {
    let have: BTreeSet<&Row> = dst.iter().collect();
    let missing: Vec<&Row> = src.iter().filter(|r| !have.contains(r)).collect();
    let mut out = format!(
        "{table}: {} source rows, {} restored rows, {} source rows not reproduced",
        src.len(),
        dst.len(),
        missing.len()
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
    out
}

/// The one shared comparison: `restored` equals `source` under `class`, and
/// every lossy column really is lost (the source sets it on some row, the
/// restored store sets it on none). Returns every difference (empty = exact).
#[must_use]
pub fn compare(
    class: &Classification,
    source: &StoreSnapshot,
    restored: &StoreSnapshot,
) -> Vec<String> {
    let mut diffs = class.ratchet(source);
    for (table, src) in &source.tables {
        let Some(carry) = class.carry(table) else {
            continue; // reported by the ratchet above
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
        if carry == Carry::Exact {
            if src_rows != dst_rows {
                diffs.push(describe_row_diff(table, &src_rows, &dst_rows));
            }
        } else {
            let have: BTreeSet<&Row> = dst_rows.iter().collect();
            let missing = src_rows.iter().filter(|r| !have.contains(r)).count();
            if missing > 0 {
                let first = src_rows.iter().find(|r| !have.contains(r));
                diffs.push(format!(
                    "{table}: {missing} source rows not kept; first: {:?}",
                    first.map(|r| describe_missing(r, &dst_rows))
                ));
            }
        }
        for col in &rederived {
            diffs.extend(check_rederived(
                class.path, table, col, &src.rows, &dst.rows,
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

/// A re-derived column is real: the corpus sets it, the destination sets it on
/// every restored row, and the restored values are not the source values.
fn check_rederived(path: &str, table: &str, col: &str, src: &[Row], dst: &[Row]) -> Vec<String> {
    let values = |rows: &[Row]| -> Vec<SqlValue> {
        let mut v: Vec<SqlValue> = rows
            .iter()
            .map(|r| r.get(col).cloned().unwrap_or(SqlValue::Null))
            .collect();
        v.sort();
        v
    };
    let (src_vals, dst_vals) = (values(src), values(dst));
    let mut diffs = Vec::new();
    if src_vals.iter().all(SqlValue::is_null) {
        diffs.push(format!(
            "{table}.{col}: re-derived entry is vacuous: the corpus never sets it"
        ));
    }
    if dst_vals.iter().any(SqlValue::is_null) {
        diffs.push(format!(
            "{table}.{col}: listed re-derived for {path} but a restored row holds NULL"
        ));
    }
    if src_vals == dst_vals {
        diffs.push(format!(
            "{table}.{col}: listed re-derived for {path} but the restore carried it; drop the entry"
        ));
    }
    diffs
}

/// For a source row not found in `dst`: the columns in which it differs from
/// the destination row with the same `id` (or the whole row when none has it).
fn describe_missing(row: &Row, dst: &[Row]) -> String {
    let id = row.get("id");
    match dst.iter().find(|r| id.is_some() && r.get("id") == id) {
        Some(peer) => {
            let cols: BTreeSet<&str> = row
                .keys()
                .chain(peer.keys())
                .filter(|c| row.get(*c) != peer.get(*c))
                .map(String::as_str)
                .collect();
            format!("id {id:?} differs in columns {cols:?}")
        }
        None => format!("no restored row matches {row:?}"),
    }
}

/// Panic with every difference when `restored` is not `source` under `class`.
#[track_caller]
pub fn assert_restored(class: &Classification, source: &StoreSnapshot, restored: &StoreSnapshot) {
    let diffs = compare(class, source, restored);
    assert!(
        diffs.is_empty(),
        "{} did not restore its source exactly:\n  {}",
        class.path,
        diffs.join("\n  ")
    );
}
