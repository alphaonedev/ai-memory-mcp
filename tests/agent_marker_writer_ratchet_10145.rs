// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10145 (`3-agent vote (71472661) V2-10108-KEYLESS-MARKER`, K-5 / K-6 lock,
//! R3 guard) — source ratchet: the agent cutover marker and the v103 stamp
//! are written only by the one signed writer.
//!
//! The construct is "a site that can write a cutover marker, write a chain
//! row, or stamp a schema version". The ratchet is an ALLOWLIST of the exact
//! sites over every `.rs` file under `src/` (walked recursively, so a file in
//! any directory is scanned), never a list of forbidden spellings. Each row
//! is `(file, needle, exact count)`; a new site, a higher count, a new file or
//! a stale row (a lower count) each fail, so the table stays the boundary.
//!
//! Needles, matched over the file text after [`flatten`] (lower case, with
//! whitespace, quotes, backslashes, commas, `+`, brackets and backticks
//! dropped, so a string split across lines, a `concat!` of halves or a quoted
//! identifier reads as one word):
//!
//! - `agent_cutover`: the marker event type as a literal
//!   (`signed_events.agent_cutover`), its constant `AGENT_CUTOVER_EVENT_TYPE`,
//!   and every path, import or alias into the `agent_cutover` module;
//! - `build_signed_marker`, `write_sqlite_signed_marker`: the signed builder
//!   and the one sqlite writer;
//! - `build_marker`: the UNSIGNED builder;
//! - `resolve`: the UNSIGNED resolver, counted as every whole-word `resolve`
//!   inside the `agent_cutover` module files, and outside them every
//!   whole-word `resolve` in a `;`-separated statement that names the module
//!   (an import, an alias or a qualified call);
//! - `stamp`: `INSERT|REPLACE INTO schema_version` or `UPDATE schema_version`,
//!   schema-qualified or not, whatever value is bound (a literal `103`, the
//!   `CURRENT_SCHEMA_VERSION` constant or a parameter);
//! - `chain_write`: the same two forms over `signed_events`, so a raw marker
//!   insert whose event type is not spelled in the file is a site too.
//!
//! `stamp` and `chain_write` are matched over [`spaced`] text instead (the
//! same drops, but each whitespace run kept as one blank so SQL words stay
//! apart); a longer table name (`signed_events_dlq`) or a column reference
//! (`signed_events.id`) is another object and is not a site.
//!
//! Comments are counted, not stripped: a stripper would be a second lexer to
//! prove, and counting a comment can only make the ratchet stricter. Left out,
//! with the reason: a type string assembled at run time from pieces that are
//! not adjacent in the source (`format!` of two variables); the behaviour
//! tests in `tests/agent_cutover_v103_10108.rs` (`append` refuses the marker
//! type, an import refuses a second marker) hold that path.
//!
//! Postgres (#10108 lane o): `src/store/postgres/agent_cutover_v103.rs` builds
//! the marker with the same signed constructor and judges it with the same
//! verifier as sqlite. The unsigned `build_marker` / `resolve` pair is gone
//! from the tree: no row of either needle is allowed in any file, and the
//! needles stay so a return of either is a site.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The source tree the ratchet scans.
const SRC_DIR: &str = "src";
/// The module that owns the marker (its files are "inside").
const MODULE_DIR: &str = "src/signed_events";
/// The file-name prefix of the module's own files.
const MODULE_PREFIX: &str = "agent_cutover";
/// The floor of scanned files, so a broken walk cannot pass empty.
const MIN_SOURCE_FILES: usize = 500;

/// What a needle counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Needle {
    MarkerType,
    SignedBuilder,
    SignedWriter,
    UnsignedBuilder,
    UnsignedResolve,
    Stamp,
    ChainWrite,
}

impl Needle {
    const ALL: [Self; 7] = [
        Self::MarkerType,
        Self::SignedBuilder,
        Self::SignedWriter,
        Self::UnsignedBuilder,
        Self::UnsignedResolve,
        Self::Stamp,
        Self::ChainWrite,
    ];
}

/// Every allowed site, by exact count.
const ALLOWED: &[(&str, Needle, usize)] = &[
    ("src/cli/boot.rs", Needle::Stamp, 2),
    ("src/cli/doctor.rs", Needle::Stamp, 2),
    ("src/cli/verify_signed_events.rs", Needle::ChainWrite, 3),
    ("src/daemon_runtime.rs", Needle::ChainWrite, 2),
    ("src/governance/daemon_signer.rs", Needle::MarkerType, 1),
    ("src/governance/deferred_audit.rs", Needle::ChainWrite, 6),
    ("src/portability/import.rs", Needle::MarkerType, 1),
    ("src/portability/import.rs", Needle::ChainWrite, 1),
    // #10145 W-10: +2 for the chain-level CutoverMarkerMissing failure.
    ("src/signed_events.rs", Needle::MarkerType, 13),
    ("src/signed_events.rs", Needle::ChainWrite, 11),
    // #10145 W-10: +4 for Missing, chain_failure and without_marker.
    ("src/signed_events/agent_cutover.rs", Needle::MarkerType, 30),
    (
        "src/signed_events/agent_cutover.rs",
        Needle::SignedBuilder,
        2,
    ),
    (
        "src/signed_events/agent_cutover.rs",
        Needle::SignedWriter,
        1,
    ),
    (
        "src/signed_events/agent_cutover.rs",
        Needle::UnsignedBuilder,
        1,
    ),
    (
        "src/signed_events/agent_cutover.rs",
        Needle::UnsignedResolve,
        3,
    ),
    ("src/signed_events/agent_cutover.rs", Needle::ChainWrite, 1),
    (
        "src/signed_events/agent_cutover_signed_tests.rs",
        Needle::SignedBuilder,
        4,
    ),
    ("src/signed_events/agent_era.rs", Needle::MarkerType, 1),
    ("src/storage/a2a_tasks.rs", Needle::Stamp, 1),
    ("src/storage/agent_cutover_v103.rs", Needle::MarkerType, 2),
    ("src/storage/agent_cutover_v103.rs", Needle::SignedWriter, 1),
    ("src/storage/agent_cutover_v103.rs", Needle::Stamp, 1),
    ("src/storage/agent_projection.rs", Needle::Stamp, 1),
    ("src/storage/connection.rs", Needle::Stamp, 3),
    ("src/storage/migration_meta.rs", Needle::MarkerType, 1),
    ("src/storage/migrations.rs", Needle::MarkerType, 3),
    ("src/storage/migrations.rs", Needle::Stamp, 29),
    ("src/storage/migrations.rs", Needle::ChainWrite, 1),
    ("src/storage/mod.rs", Needle::MarkerType, 1),
    ("src/storage/mod.rs", Needle::Stamp, 1),
    ("src/storage/title_slot_archive.rs", Needle::Stamp, 1),
    ("src/store/postgres.rs", Needle::MarkerType, 8),
    ("src/store/postgres.rs", Needle::Stamp, 3),
    ("src/store/postgres.rs", Needle::ChainWrite, 2),
    ("src/store/postgres/chain_append.rs", Needle::MarkerType, 2),
    ("src/store/postgres/chain_append.rs", Needle::ChainWrite, 1),
    (
        "src/store/postgres/legacy_cutoff_10074.rs",
        Needle::ChainWrite,
        1,
    ),
    ("src/store/postgres_inbox_tests.rs", Needle::Stamp, 1),
];

/// The characters a split or quoted spelling leaves between its halves.
const DROPPED: &[char] = &[
    ' ', '\t', '\r', '\n', '"', '\'', '\\', ',', '+', '[', ']', '`',
];

/// Lower case, with the [`DROPPED`] characters removed.
fn flatten(text: &str) -> String {
    text.chars()
        .filter(|c| !DROPPED.contains(c))
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Whole-word occurrences of `word` in `text`.
fn word_count(text: &str, word: &str) -> usize {
    text.match_indices(word)
        .filter(|(at, _)| {
            let before = text[..*at].chars().next_back();
            let after = text[at + word.len()..].chars().next();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .count()
}

/// Lower case with the [`DROPPED`] characters removed, except that every
/// run of whitespace (and every `\n`, `\t`, `\r` escape) becomes one blank,
/// so SQL words stay apart while a split or quoted literal still joins.
fn spaced(text: &str) -> String {
    let text = text
        .replace("\\n", " ")
        .replace("\\t", " ")
        .replace("\\r", " ");
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_whitespace() {
            if !out.ends_with(' ') {
                out.push(' ');
            }
        } else if !DROPPED.contains(&c) {
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// `word` ends `head` as a whole word.
fn ends_with_word(head: &str, word: &str) -> bool {
    head.strip_suffix(word)
        .is_some_and(|rest| !rest.chars().next_back().is_some_and(is_ident))
}

/// Occurrences of the table `table` written to by `INSERT|REPLACE INTO` or
/// `UPDATE`, with or without a schema qualifier, in [`spaced`] text. A
/// longer name (`signed_events_dlq`) or a column (`signed_events.id`) is
/// another object and is not counted.
fn write_count(text: &str, table: &str) -> usize {
    text.match_indices(table)
        .filter(|(at, _)| {
            let after = text[at + table.len()..].chars().next();
            if after.is_some_and(|c| is_ident(c) || c == '.') {
                return false;
            }
            let mut head = &text[..*at];
            if head.chars().next_back().is_some_and(is_ident) {
                return false;
            }
            if let Some(q) = head.strip_suffix('.') {
                head = q.trim_end_matches(is_ident);
            }
            let head = head.trim_end_matches(' ');
            ends_with_word(head, "into") || ends_with_word(head, "update")
        })
        .count()
}

/// Every needle's count in one file.
fn file_counts(path: &str, text: &str) -> BTreeMap<Needle, usize> {
    let flat = flatten(text);
    let sql = spaced(text);
    let inside = Path::new(path)
        .parent()
        .is_some_and(|p| p == Path::new(MODULE_DIR))
        && Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(MODULE_PREFIX));
    let resolve = if inside {
        word_count(text, "resolve")
    } else {
        text.split(';')
            .filter(|s| flatten(s).contains(MODULE_PREFIX))
            .map(|s| word_count(s, "resolve"))
            .sum()
    };
    let mut out = BTreeMap::new();
    for needle in Needle::ALL {
        let n = match needle {
            Needle::MarkerType => flat.matches("agent_cutover").count(),
            Needle::SignedBuilder => flat.matches("build_signed_marker").count(),
            Needle::SignedWriter => flat.matches("write_sqlite_signed_marker").count(),
            Needle::UnsignedBuilder => flat.matches("build_marker").count(),
            Needle::UnsignedResolve => resolve,
            Needle::Stamp => write_count(&sql, "schema_version"),
            Needle::ChainWrite => write_count(&sql, "signed_events"),
        };
        if n > 0 {
            out.insert(needle, n);
        }
    }
    out
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// `(file, needle) -> count` over the whole of `src/`, and the file count.
fn census() -> (BTreeMap<(String, Needle), usize>, usize) {
    let base = root();
    let mut files = Vec::new();
    rust_files(&base.join(SRC_DIR), &mut files);
    let mut sites = BTreeMap::new();
    for path in &files {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let rel = path
            .strip_prefix(&base)
            .expect("under the root")
            .to_string_lossy()
            .replace('\\', "/");
        for (needle, n) in file_counts(&rel, &text) {
            sites.insert((rel.clone(), needle), n);
        }
    }
    (sites, files.len())
}

fn expected() -> BTreeMap<(String, Needle), usize> {
    ALLOWED
        .iter()
        .map(|(f, n, c)| (((*f).to_string(), *n), *c))
        .collect()
}

/// Every difference between the tree and the table, one line each.
fn drift(actual: &BTreeMap<(String, Needle), usize>) -> Vec<String> {
    let want = expected();
    let mut out = Vec::new();
    for (key, n) in actual {
        match want.get(key) {
            Some(w) if w == n => {}
            Some(w) => out.push(format!("{} {:?}: {n} sites, allowlisted {w}", key.0, key.1)),
            None => out.push(format!("{} {:?}: {n} sites, not allowlisted", key.0, key.1)),
        }
    }
    for (key, w) in &want {
        if !actual.contains_key(key) {
            out.push(format!(
                "{} {:?}: 0 sites, allowlisted {w} (stale)",
                key.0, key.1
            ));
        }
    }
    out
}

/// K-5 / K-6 lock, R3 — the tree holds exactly the allowlisted sites.
#[test]
fn marker_and_stamp_sites_are_exactly_the_allowlist_10145() {
    let (actual, files) = census();
    assert!(
        files >= MIN_SOURCE_FILES,
        "scanned {files} files under {SRC_DIR}/, below the floor {MIN_SOURCE_FILES}"
    );
    let diffs = drift(&actual);
    assert!(
        diffs.is_empty(),
        "marker / stamp sites drifted from the allowlist:\n{}",
        diffs.join("\n")
    );
}

/// #10108 lane o — no file names the unsigned `build_marker` / `resolve`
/// pair: both backends build and judge the marker with the signed pair, and
/// the allowlist holds no row of either needle.
#[test]
fn no_file_names_the_unsigned_marker_pair_10108() {
    let (actual, _) = census();
    let unsigned =
        |needle: &Needle| matches!(needle, Needle::UnsignedBuilder | Needle::UnsignedResolve);
    let offenders: Vec<String> = actual
        .iter()
        .filter(|((_, needle), _)| unsigned(needle))
        .map(|((file, needle), n)| format!("{file} {needle:?} {n}"))
        .collect();
    assert_eq!(offenders, Vec::<String>::new());
    let rows: Vec<&str> = ALLOWED
        .iter()
        .filter(|(_, needle, _)| unsigned(needle))
        .map(|(file, _, _)| *file)
        .collect();
    assert_eq!(
        rows,
        Vec::<&str>::new(),
        "no allowlist row of the unsigned pair"
    );
}

/// One form of the construct and the needle it must raise.
struct Form {
    name: &'static str,
    path: &'static str,
    code: &'static str,
    needle: Needle,
}

/// Every form the construct can take, each in a file the allowlist does not
/// name (one outside the directories the table lists).
const FORMS: &[Form] = &[
    Form {
        name: "literal insert of the marker type",
        path: "src/storage/agent_projection.rs",
        code: "conn.execute(\"INSERT INTO signed_events (event_type) VALUES ('signed_events.agent_cutover')\", [])?;",
        needle: Needle::MarkerType,
    },
    Form {
        name: "raw chain insert with a bound type",
        path: "src/storage/agent_projection.rs",
        code: "conn.execute(\"insert   into\n main.signed_events (event_type) values (?1)\", [t])?;",
        needle: Needle::ChainWrite,
    },
    Form {
        name: "the type constant",
        path: "src/storage/agent_projection.rs",
        code: "let t = crate::signed_events::AGENT_CUTOVER_EVENT_TYPE;",
        needle: Needle::MarkerType,
    },
    Form {
        name: "a split literal",
        path: "src/storage/agent_projection.rs",
        code: "let t = concat!(\"signed_events.agent_\", \"cutover\");",
        needle: Needle::MarkerType,
    },
    Form {
        name: "an alias of the unsigned builder",
        path: "src/storage/agent_projection.rs",
        code: "use crate::signed_events::agent_cutover::build_marker as bm;",
        needle: Needle::UnsignedBuilder,
    },
    Form {
        name: "an import of the unsigned resolver",
        path: "src/storage/agent_projection.rs",
        code: "use crate::signed_events::agent_cutover::{AgentCutover, resolve};",
        needle: Needle::UnsignedResolve,
    },
    Form {
        name: "a qualified call of the unsigned resolver",
        path: "src/storage/agent_projection.rs",
        code: "let c = crate::signed_events::agent_cutover::resolve(&m, None, 0);",
        needle: Needle::UnsignedResolve,
    },
    Form {
        name: "a second call of the signed writer",
        path: "src/storage/agent_projection.rs",
        code: "crate::signed_events::agent_cutover::write_sqlite_signed_marker(conn, s, o)?;",
        needle: Needle::SignedWriter,
    },
    Form {
        name: "a signed builder call through a glob import",
        path: "src/storage/agent_projection.rs",
        code: "let m = build_signed_marker(s, None, 0, o, id, ts);",
        needle: Needle::SignedBuilder,
    },
    Form {
        name: "a literal stamp of 103",
        path: "src/storage/agent_projection.rs",
        code: "conn.execute(\"INSERT INTO schema_version (version) VALUES (103)\", [])?;",
        needle: Needle::Stamp,
    },
    Form {
        name: "a stamp of the version constant",
        path: "src/storage/agent_projection.rs",
        code: "conn.execute(\"REPLACE INTO schema_version (version) VALUES (?1)\", [CURRENT_SCHEMA_VERSION])?;",
        needle: Needle::Stamp,
    },
    Form {
        name: "a stamp in another container form",
        path: "src/storage/agent_projection.rs",
        code: "const STAMPS: [&str; 1] = [\"UPDATE `schema_version` SET version = 103\"];",
        needle: Needle::Stamp,
    },
    Form {
        name: "a stamp in a file outside the listed directories",
        path: "src/hooks/new_stamp.rs",
        code: "conn.execute(concat!(\"INSERT INTO \", \"schema_version\"), [])?;",
        needle: Needle::Stamp,
    },
    Form {
        name: "a marker in a file outside the listed directories",
        path: "src/hooks/new_marker.rs",
        code: "const T: &str = \"Signed_Events.Agent_Cutover\";",
        needle: Needle::MarkerType,
    },
];

/// Every form raises its needle, and each one, added to the real tree,
/// makes the allowlist check red.
#[test]
fn ratchet_catches_every_form_of_the_construct_10145() {
    let (tree, _) = census();
    assert!(drift(&tree).is_empty(), "the tree itself is clean");
    for form in FORMS {
        let key = (form.path.to_string(), form.needle);
        let before = tree.get(&key).copied().unwrap_or(0);
        let text = std::fs::read_to_string(root().join(form.path)).unwrap_or_default();
        let mutated = format!("{text}\n{}\n", form.code);
        let after = file_counts(form.path, &mutated)
            .get(&form.needle)
            .copied()
            .unwrap_or(0);
        assert!(
            after > before,
            "{}: {:?} stayed at {before}",
            form.name,
            form.needle
        );
        let mut mutant = tree.clone();
        mutant.insert(key, after);
        assert!(
            !drift(&mutant).is_empty(),
            "{}: the allowlist check stays green",
            form.name
        );
    }
}

/// A look-alike that is not the construct raises no needle.
#[test]
fn look_alikes_raise_no_needle_10145() {
    let rows = [
        "SELECT MAX(version) FROM schema_version",
        "DELETE FROM signed_events WHERE sequence = 0",
        "let into_schema_versioned = 1;",
        "RowEra::resolve(cutover, &event)",
        "fn resolver() {}",
    ];
    for row in rows {
        assert_eq!(
            file_counts("src/storage/agent_projection.rs", row),
            BTreeMap::new(),
            "{row}"
        );
    }
}
