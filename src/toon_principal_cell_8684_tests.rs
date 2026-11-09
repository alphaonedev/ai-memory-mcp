//! Issue #8443 / PR #8684 r3: the TOON `content_principal` cell, table-driven
//! over row shapes x formats x reader.
//!
//! Class invariant: in every TOON format (`memories_to_toon`,
//! `memories_to_toon_for`, `search_to_toon_for`; compact and full) the cell
//! is exactly the effective principal the formation fold assigns the row
//! ([`crate::role_grounding::effective_principals_with`] with the reader as
//! the owner hint). It is empty only for the reader's own unmarked row, and a
//! row whose provenance is unknowable (no metadata object, no author) is
//! `unknown`, never empty.

use super::{escape_toon, memories_to_toon, memories_to_toon_for, search_to_toon_for};
use crate::role_grounding::{META_CONTENT_PRINCIPAL, PRINCIPAL_UNKNOWN};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

const ALICE: &str = "ai:alice";
const BOB: &str = "ai:bob";
const PUBLISHER: &str = "ai:pub";
/// Readers in table column order.
const READERS: [Option<&str>; 4] = [None, Some(ALICE), Some(BOB), Some(PUBLISHER)];
/// Size of the long-author input for the linear-size bound.
const LONG_AUTHOR_BYTES: usize = 256 * 1024;
/// Each escaped input byte renders as at most two output bytes.
const ESCAPE_EXPANSION: usize = 2;
/// Generous wall-clock ceiling for rendering one 256 KiB row (debug build).
const LONG_ROW_CEILING: Duration = Duration::from_secs(10);

/// Expected cell per reader for one row shape. `U` is `unknown`, `E` empty.
#[derive(Clone, Copy)]
enum Cell {
    U,
    E,
    P(&'static str),
}

fn expect(cell: Cell) -> String {
    match cell {
        Cell::U => PRINCIPAL_UNKNOWN.to_string(),
        Cell::E => String::new(),
        Cell::P(p) => escape_toon(p),
    }
}

/// `(name, metadata or None for an absent key, expected cell per READERS)`.
fn shapes() -> Vec<(&'static str, Option<Value>, [Cell; 4])> {
    use Cell::{E, P, U};
    vec![
        ("metadata absent", None, [U, U, U, U]),
        ("metadata null", Some(Value::Null), [U, U, U, U]),
        ("metadata string", Some(json!("x")), [U, U, U, U]),
        ("metadata array", Some(json!([ALICE])), [U, U, U, U]),
        ("metadata empty object", Some(json!({})), [U, U, U, U]),
        ("empty author", Some(json!({"agent_id": ""})), [U, U, U, U]),
        (
            "author only",
            Some(json!({"agent_id": ALICE})),
            [P(ALICE), E, P(ALICE), P(ALICE)],
        ),
        (
            "author, null marker",
            Some(json!({"agent_id": ALICE, META_CONTENT_PRINCIPAL: null})),
            [P(ALICE), E, P(ALICE), P(ALICE)],
        ),
        (
            "author, non-string marker",
            Some(json!({"agent_id": ALICE, META_CONTENT_PRINCIPAL: 42})),
            [P(ALICE), E, P(ALICE), P(ALICE)],
        ),
        (
            "author, foreign marker",
            Some(json!({"agent_id": ALICE, META_CONTENT_PRINCIPAL: PUBLISHER})),
            [P(PUBLISHER), P(PUBLISHER), P(PUBLISHER), U],
        ),
        (
            "share marker",
            Some(json!({"agent_id": BOB, "shared_from_agent_id": PUBLISHER})),
            [P(PUBLISHER), P(PUBLISHER), P(PUBLISHER), U],
        ),
        (
            "role-word author",
            Some(json!({"agent_id": "owner"})),
            [U, U, U, U],
        ),
    ]
}

fn row(metadata: Option<&Value>) -> Value {
    let mut mem = json!({
        "id": "m-1", "title": "t", "tier": "mid", "namespace": "n/p",
        "priority": 5, "score": 0.5, "tags": [],
    });
    if let Some(m) = metadata {
        mem["metadata"] = m.clone();
    }
    mem
}

/// The `content_principal` cell of the single data row, located by the
/// header column (not by position) so a column-order change cannot hide it.
fn cell_of(toon: &str) -> String {
    let lines: Vec<&str> = toon.lines().collect();
    let header_at = lines
        .iter()
        .position(|l| l.starts_with("memories["))
        .unwrap_or_else(|| panic!("no header: {toon}"));
    let header = lines[header_at]
        .trim_start_matches("memories[")
        .trim_end_matches("]:");
    let col = header
        .split('|')
        .position(|c| c == META_CONTENT_PRINCIPAL)
        .unwrap_or_else(|| panic!("no content_principal column: {toon}"));
    let data = lines
        .get(header_at + 1)
        .unwrap_or_else(|| panic!("no data row: {toon}"));
    // No cell in these fixtures contains an escaped pipe before this column.
    data.split('|').nth(col).unwrap_or_default().to_string()
}

/// Every format renders the reader-relative cell for every shape.
fn render_all(mem: &Value, reader: Option<&str>) -> Vec<(String, String)> {
    let memories = json!({"memories": [mem], "count": 1});
    let results = json!({"results": [mem], "count": 1});
    let mut out = Vec::new();
    for compact in [true, false] {
        out.push((
            format!("memories_to_toon_for compact={compact}"),
            cell_of(&memories_to_toon_for(&memories, compact, reader)),
        ));
        out.push((
            format!("search_to_toon_for compact={compact}"),
            cell_of(&search_to_toon_for(&results, compact, reader)),
        ));
        if reader.is_none() {
            out.push((
                format!("memories_to_toon compact={compact}"),
                cell_of(&memories_to_toon(&memories, compact)),
            ));
        }
    }
    out
}

#[test]
fn principal_cell_is_the_effective_principal_for_every_shape_format_reader_8684() {
    let mut failures = Vec::new();
    for (name, metadata, expected) in shapes() {
        let mem = row(metadata.as_ref());
        for (reader, cell) in READERS.iter().zip(expected) {
            let want = expect(cell);
            for (format, got) in render_all(&mem, *reader) {
                if got != want {
                    failures.push(format!(
                        "{name} / {format} / reader {reader:?}: got {got:?}, want {want:?}"
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn unknowable_provenance_is_never_an_empty_cell_8684() {
    // The fail-open direction: no shape without a reader-own author may
    // render the empty (owner) cell, for any reader and any format.
    for (name, metadata, expected) in shapes() {
        let mem = row(metadata.as_ref());
        for (reader, cell) in READERS.iter().zip(expected) {
            if matches!(cell, Cell::E) {
                continue;
            }
            for (format, got) in render_all(&mem, *reader) {
                assert!(
                    !got.is_empty(),
                    "{name} / {format} / reader {reader:?} rendered owner content"
                );
            }
        }
    }
}

#[test]
fn long_author_cell_is_linear_in_size_and_time_8684() {
    // A 256 KiB author made of escapable characters: not a valid principal,
    // so the cell is `unknown`; the agent_id cell is escaped once.
    let author = "a:".repeat(LONG_AUTHOR_BYTES / 2);
    let mem = row(Some(&json!({"agent_id": author})));
    let body = json!({"memories": [mem], "count": 1});
    for reader in READERS {
        let start = Instant::now();
        let toon = memories_to_toon_for(&body, true, reader);
        let elapsed = start.elapsed();
        assert!(elapsed < LONG_ROW_CEILING, "took {elapsed:?}");
        assert!(
            toon.len() <= ESCAPE_EXPANSION * author.len() + 1024,
            "output {} bytes for a {} byte author",
            toon.len(),
            author.len()
        );
        assert_eq!(cell_of(&toon), PRINCIPAL_UNKNOWN, "reader {reader:?}");
    }
}

#[test]
fn hand_table_matches_the_formation_fold_8684() {
    // The table is checked against the fold itself, so the TOON cell and the
    // fold cannot drift apart. A metadata value that is not an object carries
    // no author and no marker: the fold reads it as an empty object.
    let empty = json!({});
    for (name, metadata, expected) in shapes() {
        let meta = metadata
            .as_ref()
            .filter(|m| m.is_object())
            .unwrap_or(&empty);
        for (reader, cell) in READERS.iter().zip(expected) {
            let (_, principals) =
                crate::role_grounding::effective_principals_with(&[meta], *reader, None);
            let fold = principals
                .into_iter()
                .next()
                .flatten()
                .map_or_else(String::new, |p| escape_toon(p.as_str()));
            assert_eq!(fold, expect(cell), "{name} / reader {reader:?}");
        }
    }
}
