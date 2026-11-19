// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8341 / #9406 class lock: a SQLite migration after 0086 may not drop,
//! rename or rebuild a column or table that a guard trigger names unless the
//! same migration file drops that guard BEFORE the change and creates it again
//! AFTER it.
//!
//! Why: SQLite re-checks every trigger body on `ALTER TABLE ... DROP COLUMN`
//! and `RENAME COLUMN` (the v0.6.4 fixture hit exactly this on
//! `encrypted_envelope`), and `DROP TABLE` / `RENAME TO` silently take the
//! table's triggers with them. A migration that rebuilds `memories` without
//! re-installing the v102 projection guards would ship a store whose agent
//! binding projection is no longer enforced, with every test that only checks
//! the ladder's stamp still green.
//!
//! SSOT: the guarded names are DERIVED, never listed by hand. A guard is every
//! trigger in a freshly opened store whose body calls `RAISE(`; its guarded
//! tables are its `ON` table plus every table it reads (`FROM` / `JOIN` /
//! `INTO` / `UPDATE`), and its guarded columns are the columns of those tables
//! (`PRAGMA table_info`) whose names occur as identifiers in its body.
//!
//! One transaction: `migrate()` runs the whole ladder inside one
//! `WriteTxn::begin_exclusive`, so "same file" is "same transaction"; the
//! cell `migrate_runs_the_ladder_in_one_exclusive_transaction_8341` pins that.

#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The migration that installed the v102 guards. Files numbered above it are
/// scanned; earlier files predate the guards.
const GUARD_MIGRATION_8341: u32 = 86;
const SQLITE_MIGRATIONS_DIR_8341: &str = "migrations/sqlite";
const MIGRATIONS_RS_8341: &str = "src/storage/migrations.rs";
const MIGRATE_FN_8341: &str = "pub(crate) fn migrate(conn: &Connection) -> Result<()> {";
const EXCLUSIVE_BEGIN_8341: &str = "WriteTxn::begin_exclusive(conn)?";
const GUARD_INSERT_8341: &str = "agent_pubkey_history_projection_guard_insert";
const GUARD_UPDATE_8341: &str = "agent_pubkey_history_projection_guard_update";
/// The 0086 `UPDATE OF` list (#9406): every one of them is a guarded column.
const UPDATE_OF_COLUMNS_8341: [&str; 5] = [
    "metadata",
    "content",
    "title",
    "namespace",
    "encrypted_envelope",
];
/// Minimum scanner input for the size bound (engineering-process rule 2).
const BIG_INPUT_BYTES_8341: usize = 100 * 1024;
/// Wall-clock ceiling for scanning the big input (debug build).
const BIG_INPUT_CEILING_8341: Duration = Duration::from_secs(2);

/// One derived guard trigger.
#[derive(Debug, Clone)]
struct Guard {
    name: String,
    tables: BTreeSet<String>,
    columns: BTreeMap<String, BTreeSet<String>>,
}

/// One flagged change: (guard, reason).
type Violation = (String, String);
/// Token positions of every `DROP TRIGGER` / `CREATE TRIGGER`, by trigger name.
type TriggerPositions = BTreeMap<String, Vec<usize>>;

/// Lower-cased identifier and punctuation tokens of `sql`, with `--` and
/// `/* */` comments and `'...'` string literals removed. Quoted identifiers
/// (`"x"`, `` `x` ``, `[x]`) become plain identifier tokens. Linear in the
/// input length; works on `char`s, so no byte slice can split a code point.
fn tokens(sql: &str) -> Vec<String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '-' && chars.get(i + 1) == Some(&'-') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                i += 1;
            }
            i += 2;
        } else if c == '\'' {
            i += 1;
            while i < chars.len() {
                if chars[i] == '\'' {
                    if chars.get(i + 1) == Some(&'\'') {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            i += 1;
        } else if c == '"' || c == '`' || c == '[' {
            let close = if c == '[' { ']' } else { c };
            let start = i + 1;
            i = start;
            while i < chars.len() && chars[i] != close {
                i += 1;
            }
            let end = i.min(chars.len());
            out.push(chars[start..end].iter().collect::<String>().to_lowercase());
            i += 1;
        } else if c.is_alphanumeric() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(chars[start..i].iter().collect::<String>().to_lowercase());
        } else {
            if !c.is_whitespace() {
                out.push(c.to_string());
            }
            i += 1;
        }
    }
    out
}

fn is_ident(tok: &str) -> bool {
    tok.chars().all(|c| c.is_alphanumeric() || c == '_') && !tok.is_empty()
}

/// The object name at `i` (skipping an optional `schema.` prefix) and the
/// index after it.
fn object_name(toks: &[String], i: usize) -> Option<(String, usize)> {
    let first = toks.get(i)?;
    if !is_ident(first) {
        return None;
    }
    if toks.get(i + 1).map(String::as_str) == Some(".") {
        let second = toks.get(i + 2)?;
        return Some((second.clone(), i + 3));
    }
    Some((first.clone(), i + 1))
}

fn at(toks: &[String], i: usize, word: &str) -> bool {
    toks.get(i).map(String::as_str) == Some(word)
}

/// Skip `IF EXISTS` / `IF NOT EXISTS` at `i`.
fn skip_if_exists(toks: &[String], mut i: usize) -> usize {
    if at(toks, i, "if") {
        i += 1;
        if at(toks, i, "not") {
            i += 1;
        }
        if at(toks, i, "exists") {
            i += 1;
        }
    }
    i
}

/// A schema change that can break or drop a trigger.
#[derive(Debug)]
enum Change {
    Column {
        table: String,
        column: String,
        what: &'static str,
    },
    Table {
        table: String,
        what: &'static str,
    },
}

/// Every guard-breaking change in `sql` with its token position, plus the
/// positions of every `DROP TRIGGER` and `CREATE TRIGGER` by trigger name.
fn changes(toks: &[String]) -> (Vec<(usize, Change)>, TriggerPositions, TriggerPositions) {
    let mut found = Vec::new();
    let mut dropped = TriggerPositions::new();
    let mut created = TriggerPositions::new();
    let mut i = 0;
    while i < toks.len() {
        if at(toks, i, "alter") && at(toks, i + 1, "table") {
            if let Some((table, j)) = object_name(toks, i + 2) {
                if at(toks, j, "drop") {
                    let k = if at(toks, j + 1, "column") {
                        j + 2
                    } else {
                        j + 1
                    };
                    if let Some((column, _)) = object_name(toks, k) {
                        found.push((
                            i,
                            Change::Column {
                                table,
                                column,
                                what: "drop column",
                            },
                        ));
                    }
                } else if at(toks, j, "rename") && at(toks, j + 1, "to") {
                    if let Some((target, _)) = object_name(toks, j + 2) {
                        found.push((
                            i,
                            Change::Table {
                                table,
                                what: "rename table",
                            },
                        ));
                        found.push((
                            i,
                            Change::Table {
                                table: target,
                                what: "rename into",
                            },
                        ));
                    }
                } else if at(toks, j, "rename") {
                    let k = if at(toks, j + 1, "column") {
                        j + 2
                    } else {
                        j + 1
                    };
                    if let Some((column, _)) = object_name(toks, k) {
                        found.push((
                            i,
                            Change::Column {
                                table,
                                column,
                                what: "rename column",
                            },
                        ));
                    }
                }
            }
        } else if at(toks, i, "drop") && at(toks, i + 1, "table") {
            if let Some((table, _)) = object_name(toks, skip_if_exists(toks, i + 2)) {
                found.push((
                    i,
                    Change::Table {
                        table,
                        what: "drop table",
                    },
                ));
            }
        } else if at(toks, i, "drop") && at(toks, i + 1, "trigger") {
            if let Some((name, _)) = object_name(toks, skip_if_exists(toks, i + 2)) {
                dropped.entry(name).or_default().push(i);
            }
        } else if at(toks, i, "create") {
            let mut j = i + 1;
            if at(toks, j, "temp") || at(toks, j, "temporary") {
                j += 1;
            }
            if at(toks, j, "trigger")
                && let Some((name, _)) = object_name(toks, skip_if_exists(toks, j + 1))
            {
                created.entry(name).or_default().push(i);
            }
        }
        i += 1;
    }
    (found, dropped, created)
}

/// The class check over one migration's SQL. A change that touches a guard is
/// a violation unless the same SQL drops that guard before the change and
/// creates it after the change.
fn scan(sql: &str, guards: &[Guard]) -> Vec<Violation> {
    let toks = tokens(sql);
    let (found, dropped, created) = changes(&toks);
    let mut out = Vec::new();
    for (pos, change) in &found {
        for guard in guards {
            let (touches, reason) = match change {
                Change::Column {
                    table,
                    column,
                    what,
                } => (
                    guard
                        .columns
                        .get(table)
                        .is_some_and(|cols| cols.contains(column)),
                    format!("{what} {table}.{column}"),
                ),
                Change::Table { table, what } => {
                    (guard.tables.contains(table), format!("{what} {table}"))
                }
            };
            if !touches {
                continue;
            }
            let dropped_before = dropped
                .get(&guard.name)
                .is_some_and(|v| v.iter().any(|p| p < pos));
            let created_after = created
                .get(&guard.name)
                .is_some_and(|v| v.iter().any(|p| p > pos));
            if !(dropped_before && created_after) {
                out.push((guard.name.clone(), reason));
            }
        }
    }
    out
}

/// The tables a trigger body names: its `ON` table plus every identifier after
/// `FROM`, `JOIN`, `INTO` or `UPDATE`.
fn trigger_tables(toks: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (i, tok) in toks.iter().enumerate() {
        if matches!(tok.as_str(), "on" | "from" | "join" | "into" | "update")
            && let Some((name, _)) = object_name(toks, i + 1)
        {
            out.insert(name);
        }
    }
    out
}

/// Derive every guard trigger from a freshly opened store (SSOT).
fn derive_guards(conn: &rusqlite::Connection) -> Vec<Guard> {
    let mut stmt = conn
        .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'trigger' AND sql IS NOT NULL ORDER BY name")
        .expect("prepare triggers");
    let rows: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .expect("query triggers")
        .collect::<Result<_, _>>()
        .expect("read triggers");
    let mut guards = Vec::new();
    for (name, sql) in rows {
        if !sql.to_ascii_uppercase().contains("RAISE(") {
            continue;
        }
        let toks = tokens(&sql);
        let words: BTreeSet<&str> = toks.iter().map(String::as_str).collect();
        let mut tables = BTreeSet::new();
        let mut columns = BTreeMap::new();
        for table in trigger_tables(&toks) {
            let cols = table_columns(conn, &table);
            if cols.is_empty() {
                continue;
            }
            let named: BTreeSet<String> = cols
                .into_iter()
                .filter(|c| words.contains(c.as_str()))
                .collect();
            columns.insert(table.clone(), named);
            tables.insert(table);
        }
        guards.push(Guard {
            name: name.to_lowercase(),
            tables,
            columns,
        });
    }
    guards
}

fn table_columns(conn: &rusqlite::Connection, table: &str) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info(?1)")
        .expect("prepare table_info");
    stmt.query_map([table], |r| r.get::<_, String>(0))
        .expect("query table_info")
        .collect::<Result<Vec<_>, _>>()
        .expect("read table_info")
        .into_iter()
        .map(|c| c.to_lowercase())
        .collect()
}

fn fresh_guards() -> Vec<Guard> {
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    derive_guards(&conn)
}

/// Only the two v102 guards, so the table-driven cells pin exact output even
/// when another `RAISE` trigger also names a column.
fn v102_guards(guards: &[Guard]) -> Vec<Guard> {
    [GUARD_INSERT_8341, GUARD_UPDATE_8341]
        .iter()
        .map(|n| guard(guards, n).clone())
        .collect()
}

/// Every user table of a fresh store.
fn fresh_tables(conn: &rusqlite::Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .expect("prepare tables");
    stmt.query_map([], |r| r.get::<_, String>(0))
        .expect("query tables")
        .collect::<Result<Vec<_>, _>>()
        .expect("read tables")
        .into_iter()
        .map(|t| t.to_lowercase())
        .collect()
}

fn guard<'a>(guards: &'a [Guard], name: &str) -> &'a Guard {
    guards
        .iter()
        .find(|g| g.name == name)
        .unwrap_or_else(|| panic!("guard {name} not derived from a fresh store"))
}

fn manifest_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Every `migrations/sqlite/NNNN_*.sql` numbered above `GUARD_MIGRATION_8341`.
fn later_migrations() -> Vec<PathBuf> {
    let dir = manifest_path(SQLITE_MIGRATIONS_DIR_8341);
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("read migrations dir")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("sql"))
        .filter(|p| {
            let stem = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let digits: String = stem.chars().take_while(char::is_ascii_digit).collect();
            digits
                .parse::<u32>()
                .is_ok_and(|n| n > GUARD_MIGRATION_8341)
        })
        .collect();
    out.sort();
    out
}

/// The derivation is not vacuous: both v102 guards come out of a fresh store,
/// they guard `memories` and `agent_pubkey_history`, and every column of the
/// 0086 `UPDATE OF` list is a guarded `memories` column of both.
#[test]
fn guarded_names_are_derived_from_the_trigger_definitions_8341() {
    let guards = fresh_guards();
    for name in [GUARD_INSERT_8341, GUARD_UPDATE_8341] {
        let g = guard(&guards, name);
        assert!(
            g.tables.contains("memories"),
            "{name} tables: {:?}",
            g.tables
        );
        assert!(
            g.tables.contains("agent_pubkey_history"),
            "{name} tables: {:?}",
            g.tables
        );
        assert!(
            !g.tables.contains("_agents"),
            "a string literal is not a table: {:?}",
            g.tables
        );
        let mem = &g.columns["memories"];
        for col in UPDATE_OF_COLUMNS_8341 {
            assert!(
                mem.contains(col),
                "{name} must guard memories.{col}; got {mem:?}"
            );
        }
        let hist = &g.columns["agent_pubkey_history"];
        for col in ["agent_id", "pubkey_b64", "bound_at", "superseded_at"] {
            assert!(
                hist.contains(col),
                "{name} must guard agent_pubkey_history.{col}; got {hist:?}"
            );
        }
    }
}

/// The production cell: no migration after 0086 breaks a guard.
#[test]
fn no_later_migration_breaks_a_guard_trigger_8341() {
    let guards = fresh_guards();
    let mut all = Vec::new();
    for path in later_migrations() {
        let sql = std::fs::read_to_string(&path).expect("read migration");
        for (g, reason) in scan(&sql, &guards) {
            all.push(format!("{}: {reason} breaks {g}", path.display()));
        }
    }
    assert!(
        all.is_empty(),
        "a migration after 0086 changes a guarded name without DROP TRIGGER before and \
         CREATE TRIGGER after it in the same file: {all:#?}"
    );
}

/// "Same file" is "same transaction": `migrate()` opens one exclusive write
/// transaction before the ladder.
#[test]
fn migrate_runs_the_ladder_in_one_exclusive_transaction_8341() {
    let src = std::fs::read_to_string(manifest_path(MIGRATIONS_RS_8341)).expect("migrations.rs");
    let start = src.find(MIGRATE_FN_8341).expect("fn migrate signature");
    let body = &src[start..];
    let end = body.find("\n}\n").expect("end of fn migrate");
    assert!(
        body[..end].contains(EXCLUSIVE_BEGIN_8341),
        "migrate() must open {EXCLUSIVE_BEGIN_8341} around the ladder"
    );
}

/// Table-driven cells over the class. `expect` is the exact sorted
/// (guard, reason) list.
#[test]
#[allow(clippy::too_many_lines)]
fn scanner_flags_every_guard_breaking_form_8341() {
    let guards = v102_guards(&fresh_guards());
    let both = |reason: &str| -> Vec<Violation> {
        let mut v = vec![
            (GUARD_INSERT_8341.to_string(), reason.to_string()),
            (GUARD_UPDATE_8341.to_string(), reason.to_string()),
        ];
        v.sort();
        v
    };
    let recreate = |change: &str| -> String {
        format!(
            "DROP TRIGGER IF EXISTS {GUARD_INSERT_8341};\nDROP TRIGGER IF EXISTS {GUARD_UPDATE_8341};\n\
             {change}\nCREATE TRIGGER IF NOT EXISTS {GUARD_INSERT_8341} AFTER INSERT ON memories BEGIN SELECT RAISE(ABORT, 'x'); END;\n\
             CREATE TRIGGER IF NOT EXISTS {GUARD_UPDATE_8341} AFTER UPDATE OF metadata ON memories BEGIN SELECT RAISE(ABORT, 'x'); END;\n"
        )
    };
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    let unguarded_col = table_columns(&conn, "memories")
        .into_iter()
        .find(|c| {
            guards
                .iter()
                .all(|g| g.columns.get("memories").is_none_or(|m| !m.contains(c)))
        })
        .expect("memories has at least one column no v102 guard names");
    let unguarded_table = fresh_tables(&conn)
        .into_iter()
        .find(|t| guards.iter().all(|g| !g.tables.contains(t)))
        .expect("a fresh store has at least one table no v102 guard names");

    let cases: Vec<(&str, String, Vec<Violation>)> = vec![
        ("flag drop column", "ALTER TABLE memories DROP COLUMN encrypted_envelope;".into(),
         both("drop column memories.encrypted_envelope")),
        ("flag drop without COLUMN keyword", "ALTER TABLE memories DROP metadata;".into(),
         both("drop column memories.metadata")),
        ("flag quoted and mixed case", "alter Table \"memories\" drop column `Title`;".into(),
         both("drop column memories.title")),
        ("flag schema-qualified", "ALTER TABLE main.memories DROP COLUMN namespace;".into(),
         both("drop column memories.namespace")),
        ("flag history column", "ALTER TABLE agent_pubkey_history DROP COLUMN superseded_at;".into(),
         both("drop column agent_pubkey_history.superseded_at")),
        ("flag rename column", "ALTER TABLE memories RENAME COLUMN content TO body;".into(),
         both("rename column memories.content")),
        ("flag rename table", "ALTER TABLE memories RENAME TO memories_old;".into(),
         both("rename table memories")),
        ("flag drop table", "DROP TABLE IF EXISTS agent_pubkey_history;".into(),
         both("drop table agent_pubkey_history")),
        ("flag rebuild",
         "CREATE TABLE memories_new (id TEXT);\nINSERT INTO memories_new SELECT id FROM memories;\n\
          DROP TABLE memories;\nALTER TABLE memories_new RENAME TO memories;".into(),
         { let mut v = both("drop table memories"); v.extend(both("rename into memories")); v.sort(); v }),
        ("flag guard dropped but never recreated",
         format!("DROP TRIGGER {GUARD_INSERT_8341};\nDROP TRIGGER {GUARD_UPDATE_8341};\nALTER TABLE memories DROP COLUMN metadata;"),
         both("drop column memories.metadata")),
        ("flag only one guard recreated",
         format!("DROP TRIGGER {GUARD_INSERT_8341};\nDROP TRIGGER {GUARD_UPDATE_8341};\nALTER TABLE memories DROP COLUMN metadata;\n\
                  CREATE TRIGGER {GUARD_INSERT_8341} AFTER INSERT ON memories BEGIN SELECT RAISE(ABORT, 'x'); END;"),
         vec![(GUARD_UPDATE_8341.to_string(), "drop column memories.metadata".to_string())]),
        ("flag recreate placed before the change",
         format!("DROP TRIGGER {GUARD_INSERT_8341};\nDROP TRIGGER {GUARD_UPDATE_8341};\n\
                  CREATE TRIGGER {GUARD_INSERT_8341} AFTER INSERT ON memories BEGIN SELECT 1; END;\n\
                  CREATE TRIGGER {GUARD_UPDATE_8341} AFTER UPDATE ON memories BEGIN SELECT 1; END;\n\
                  ALTER TABLE memories DROP COLUMN metadata;"),
         both("drop column memories.metadata")),
        ("ok drop and recreate", recreate("ALTER TABLE memories DROP COLUMN encrypted_envelope;"), vec![]),
        ("ok rebuild with recreate",
         recreate("CREATE TABLE memories_new (id TEXT);\nDROP TABLE memories;\nALTER TABLE memories_new RENAME TO memories;"),
         vec![]),
        ("ok unguarded column", format!("ALTER TABLE memories DROP COLUMN {unguarded_col};"), vec![]),
        ("ok unguarded table",
         format!("DROP TABLE IF EXISTS {unguarded_table};\nALTER TABLE {unguarded_table} RENAME TO {unguarded_table}_old;"),
         vec![]),
        ("ok add column", "ALTER TABLE memories ADD COLUMN extra TEXT;".into(), vec![]),
        ("ok line comment", "-- ALTER TABLE memories DROP COLUMN metadata;\nSELECT 1;".into(), vec![]),
        ("ok block comment", "/* ALTER TABLE memories\n DROP COLUMN metadata; */ SELECT 1;".into(), vec![]),
        ("ok string literal", "SELECT 'ALTER TABLE memories DROP COLUMN metadata', 'it''s';".into(), vec![]),
        ("ok non-ascii text", "-- ünïcödé ✓\nSELECT 'ДРОП';".into(), vec![]),
    ];
    for (label, sql, expect) in cases {
        let mut got = scan(&sql, &guards);
        got.sort();
        assert_eq!(got, expect, "case `{label}`");
    }
}

/// Size and time bound: a 100K+ migration scans in linear time, and a
/// violation buried at its end is still found.
#[test]
fn scanner_is_linear_on_a_100k_migration_8341() {
    let guards = v102_guards(&fresh_guards());
    let filler = "-- padding comment line for the size bound\nSELECT 'x', 1 FROM memory_links WHERE id = 'y';\n";
    let mut sql = String::new();
    while sql.len() < BIG_INPUT_BYTES_8341 {
        sql.push_str(filler);
    }
    sql.push_str("ALTER TABLE memories DROP COLUMN encrypted_envelope;\n");
    let started = Instant::now();
    let got = scan(&sql, &guards);
    let elapsed = started.elapsed();
    assert!(sql.len() >= BIG_INPUT_BYTES_8341);
    assert!(
        elapsed < BIG_INPUT_CEILING_8341,
        "scan of {} bytes took {elapsed:?}",
        sql.len()
    );
    assert_eq!(got.len(), 2, "both guards flagged: {got:?}");
    let unterminated = format!("{sql}/* never closed {}", "x".repeat(BIG_INPUT_BYTES_8341));
    let started = Instant::now();
    let tail = scan(&unterminated, &guards);
    assert!(
        started.elapsed() < BIG_INPUT_CEILING_8341,
        "unterminated comment scan bound"
    );
    assert_eq!(
        tail.len(),
        2,
        "a change before an unterminated comment is still found: {tail:?}"
    );
}
