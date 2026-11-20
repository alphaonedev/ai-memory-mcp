// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9557 (issues #9504, #9564) — every operator-facing repair text names a
//! command that exists in the real CLI definition.
//!
//! Class: a repair text that names an action which does not exist (or does not
//! work) on the backend the operator runs. Invariant: every backticked
//! `ai-memory ...` command in a repair text parses with
//! [`ai_memory::daemon_runtime::Cli`], in every feature set that can print it.
//!
//! The corpus is found by SCRIPT, not by a list written by hand:
//! * every backticked `ai-memory ...` command on a line of `src/`, `tests/`
//!   (`*.rs`) that mentions a repair, and on a line of `docs/CLI_REFERENCE.md`
//!   that mentions a repair or a schema that is behind this binary;
//! * every text the schema guard renders at runtime for each backend.
//!
//! The same file runs under the default feature set and under `--features
//! sal`. The PostgreSQL repair command (`schema-init`) is a `sal` subcommand:
//! a PostgreSQL store exists only with `sal-postgres`, which implies `sal`, so
//! in the default set that one command is checked to be the PostgreSQL arm's
//! own text and nothing else may be unparsable.

use ai_memory::daemon_runtime::Cli;
use ai_memory::storage::schema_guard::{
    BACKEND_POSTGRES, BACKEND_SQLITE, SchemaBehindReadOnly, schema_behind_repair_clause,
};
use assert_cmd::Command as ChildCommand;
use clap::Parser;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PROGRAM: &str = "ai-memory";
const SCAN_DIRS: &[&str] = &["src", "tests"];
const DOC_FILE: &str = "docs/CLI_REFERENCE.md";
/// A line is a repair text when it matches one of these (lower-cased).
const RUST_MARKERS: &[&str] = &["repair"];
const DOC_MARKERS: &[&str] = &["repair", "behind this binary"];
/// Placeholder fillers: `<N>` is a number, `<url>` a store URL, any other
/// `<..>` a plain word.
const FILL_NUMBER: &str = "1";
const FILL_URL: &str = "sqlite:///x";
const FILL_WORD: &str = "x";
/// This file's own corpus lines are not repair texts of the product.
const THIS_FILE: &str = "tests/repair_text_cli_parse_9557.rs";
/// The corpus must not shrink to nothing: a floor on what the scan finds.
const MIN_SCANNED_COMMANDS: usize = 6;
/// `CLI_REFERENCE` has two schema-behind rows that name the command (#9564).
const MIN_DOC_ROWS: usize = 2;
/// The placeholder the sqlite clause keeps literally for the database path.
const PATH_PLACEHOLDER: &str = "<path>";
/// A schema stamp strictly behind this binary (the fixture is stamped back to it).
const OLD_STAMP: i64 = 17;
const STAMP_SQL: &str = "SELECT COALESCE(MAX(version), 0) FROM schema_version";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Backticked spans of `line` that start with the program name.
fn commands_in(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, span) in line.split('`').enumerate() {
        if i % 2 == 1 && span.starts_with(&format!("{PROGRAM} ")) {
            out.push(span.to_string());
        }
    }
    out
}

/// Turn a documented command into argv: drop `[optional]` groups, fill
/// placeholders.
fn argv_of(cmd: &str) -> Vec<String> {
    let mut flat = String::new();
    let mut depth = 0usize;
    for c in cmd.chars() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 => flat.push(c),
            _ => {}
        }
    }
    flat.split_whitespace()
        .map(|w| match w {
            "<N>" => FILL_NUMBER.to_string(),
            "<url>" => FILL_URL.to_string(),
            w if w.starts_with('<') && w.ends_with('>') => FILL_WORD.to_string(),
            w => w.to_string(),
        })
        .collect()
}

struct Found {
    origin: String,
    command: String,
}

fn scan_corpus() -> Vec<Found> {
    let root = root();
    let mut found = Vec::new();
    let mut files = Vec::new();
    for d in SCAN_DIRS {
        rs_files(&root.join(d), &mut files);
    }
    for f in files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel == THIS_FILE {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        for (n, line) in text.lines().enumerate() {
            let low = line.to_lowercase();
            if RUST_MARKERS.iter().any(|m| low.contains(m)) {
                for c in commands_in(line) {
                    found.push(Found {
                        origin: format!("{rel}:{}", n + 1),
                        command: c,
                    });
                }
            }
        }
    }
    let doc = std::fs::read_to_string(root.join(DOC_FILE)).expect("read CLI_REFERENCE");
    for (n, line) in doc.lines().enumerate() {
        let low = line.to_lowercase();
        if DOC_MARKERS.iter().any(|m| low.contains(m)) {
            for c in commands_in(line) {
                found.push(Found {
                    origin: format!("{DOC_FILE}:{}", n + 1),
                    command: c,
                });
            }
        }
    }
    found
}

/// The single command the PostgreSQL arm names.
fn postgres_command() -> String {
    commands_in(&schema_behind_repair_clause(BACKEND_POSTGRES))
        .pop()
        .expect("the postgres clause names a command")
}

fn parse_error(command: &str) -> Option<String> {
    Cli::try_parse_from(argv_of(command))
        .err()
        .map(|e| format!("{:?}", e.kind()))
}

/// Parse `command`; in the default feature set the PostgreSQL command is
/// exempt (see the module docs), every other command must parse.
fn check(origin: &str, command: &str, bad: &mut Vec<String>) {
    let exempt = !cfg!(feature = "sal") && command == postgres_command();
    if exempt {
        return;
    }
    if let Some(kind) = parse_error(command) {
        bad.push(format!("{origin}: `{command}` does not parse ({kind})"));
    }
}

#[test]
fn every_script_found_repair_command_parses_with_the_real_cli_9557() {
    let found = scan_corpus();
    assert!(
        found.len() >= MIN_SCANNED_COMMANDS,
        "the scan found only {} repair commands",
        found.len()
    );
    let mut bad = Vec::new();
    for f in &found {
        check(&f.origin, &f.command, &mut bad);
    }
    assert!(
        bad.is_empty(),
        "unparsable repair commands:\n{}",
        bad.join("\n")
    );
}

#[test]
fn every_rendered_schema_guard_repair_command_parses_with_the_real_cli_9557() {
    let supported = ai_memory::storage::migrations::current_schema_version();
    let mut bad = Vec::new();
    let mut seen = 0usize;
    for backend in [BACKEND_SQLITE, BACKEND_POSTGRES] {
        let clause = schema_behind_repair_clause(backend);
        let detail = SchemaBehindReadOnly::new(supported - 1, backend, "/db").detail;
        assert!(detail.contains(&clause), "{backend}: {detail}");
        for c in commands_in(&clause) {
            seen += 1;
            check(&format!("clause({backend})"), &c, &mut bad);
        }
    }
    assert_eq!(seen, 2, "one command per real backend");
    assert!(
        bad.is_empty(),
        "unparsable repair commands:\n{}",
        bad.join("\n")
    );
}

#[test]
fn an_unknown_backend_label_names_no_command_9557() {
    for label in ["", "SQLite", "sqlite ", "postgresql", "mysql"] {
        let clause = schema_behind_repair_clause(label);
        assert!(commands_in(&clause).is_empty(), "{label:?}: {clause}");
        assert!(
            clause.contains("backend is not known"),
            "{label:?}: {clause}"
        );
    }
}

/// The docs rows (`docs/CLI_REFERENCE.md`) state the SAME sqlite command the
/// one function renders, not their own copy.
#[test]
fn cli_reference_rows_state_the_command_of_the_one_function_9557() {
    let want = commands_in(&schema_behind_repair_clause(BACKEND_SQLITE))
        .pop()
        .expect("the sqlite clause names a command");
    let doc = std::fs::read_to_string(root().join(DOC_FILE)).expect("read CLI_REFERENCE");
    // A row is a schema-behind row when the line says so AND names a command
    // (a wrapped sentence can carry the words on the previous line).
    let rows: Vec<(usize, &str)> = doc
        .lines()
        .enumerate()
        .filter(|(_, l)| {
            let low = l.to_lowercase();
            (low.contains("not migrated") || low.contains("behind this binary"))
                && !commands_in(l).is_empty()
        })
        .collect();
    assert!(
        rows.len() >= MIN_DOC_ROWS,
        "the schema-behind rows must exist: {rows:?}"
    );
    for (n, row) in rows {
        assert!(
            row.contains(&format!("`{want}`")),
            "{DOC_FILE}:{} does not state `{want}`: {row}",
            n + 1
        );
    }
}

/// An old-stamp fixture store, made inside a test-owned temp directory (never a
/// live database): a real store whose `schema_version` is rolled back to
/// [`OLD_STAMP`].
struct Fixture {
    _dir: TempDir,
    db: PathBuf,
}

impl Fixture {
    fn old_stamp() -> Self {
        let dir = TempDir::new().expect("fixture dir");
        let db = dir.path().join("behind.db");
        let conn = ai_memory::db::open(&db).expect("fixture open");
        conn.execute("DELETE FROM schema_version", []).unwrap();
        conn.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            [OLD_STAMP],
        )
        .unwrap();
        drop(conn);
        let f = Self { _dir: dir, db };
        assert_eq!(f.stamp(), OLD_STAMP, "the fixture must start behind");
        f
    }

    /// The stamp as a NEW connection reads it.
    fn stamp(&self) -> i64 {
        rusqlite::Connection::open(&self.db)
            .expect("new connection")
            .query_row(STAMP_SQL, [], |r| r.get(0))
            .expect("read stamp")
    }

    /// Run the product binary with `args` on the fixture only (empty HOME, no config).
    fn run(&self, args: &[&str]) -> std::process::Output {
        let home = TempDir::new().expect("empty home");
        ChildCommand::cargo_bin("ai-memory")
            .expect("product binary")
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("HOME", home.path())
            .args(["--db", self.db.to_str().unwrap()])
            .args(args)
            .output()
            .expect("spawn")
    }
}

/// The sqlite repair command of the one function.
fn sqlite_command() -> String {
    commands_in(&schema_behind_repair_clause(BACKEND_SQLITE))
        .pop()
        .expect("the sqlite clause names a command")
}

/// PROOF-2 (#9557 B1): the TEXT is bound to the BEHAVIOUR. The cell takes the
/// sqlite command from the one function, substitutes the fixture path for the
/// placeholder, parses it with the product parser (this file runs under the
/// default and the `sal` feature set), runs it as the product binary on an
/// old-stamp fixture, then reads the stamp from a NEW connection and asserts
/// the current version. A later change that makes the verb open read-only
/// turns this cell red, so the text cannot go stale silently.
#[test]
fn the_sqlite_repair_command_migrates_an_old_stamp_fixture_9557() {
    let fx = Fixture::old_stamp();
    let command = sqlite_command();
    assert!(command.contains(PATH_PLACEHOLDER), "{command}");
    let line = command.replace(PATH_PLACEHOLDER, fx.db.to_str().unwrap());
    let words: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    Cli::try_parse_from(&words).unwrap_or_else(|e| panic!("`{line}` must parse: {e}"));
    let child_args: Vec<&str> = words.iter().skip(1).map(String::as_str).collect();
    let home = TempDir::new().expect("empty home");
    let out = ChildCommand::cargo_bin("ai-memory")
        .unwrap()
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("HOME", home.path())
        .args(&child_args)
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "`{line}` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fx.stamp(),
        ai_memory::storage::migrations::current_schema_version(),
        "the repair command must leave the CURRENT stamp"
    );
}

/// Condition (5): `boot` and `doctor` keep refusing on a schema that is behind,
/// their refusal text carries the clause of the one function, and neither
/// migrates (the stamp is unchanged after each).
#[test]
fn boot_and_doctor_refuse_with_the_clause_and_do_not_migrate_9557() {
    const VERBS: &[(&str, &[&str])] = &[
        ("boot", &["boot", "--namespace", "n"]),
        ("doctor", &["doctor"]),
    ];
    let clause = schema_behind_repair_clause(BACKEND_SQLITE);
    // `boot` gets an explicit namespace: without one the stamp is migrated by
    // the namespace resolution before the read-only open (a pre-existing
    // defect at the base, reported in the lane READY, not fixed here).
    for (verb, args) in VERBS {
        let fx = Fixture::old_stamp();
        let out = fx.run(args);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            text.contains(&clause),
            "{verb} must carry `{clause}`: {text}"
        );
        assert_eq!(fx.stamp(), OLD_STAMP, "{verb} must not migrate");
    }
}
