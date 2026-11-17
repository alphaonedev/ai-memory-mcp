// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9273 — the sqlite versioned-update funnel
//! (`db::update_with_expected_version`) keeps its #1955 record-stop gate
//! in the SAME fn span as its write SQL, and the gate runs BEFORE the
//! write transaction opens.
//!
//! - Behaviour: a stopped store refuses the versioned update with the
//!   exact `RecordStopped` text, zero rows changed and no transaction left
//!   open; an unreadable stop state refuses with the exact
//!   `RecordStopIndeterminate` text the same way.
//! - Caller-held transaction (the synthesis merge shape): the refusal
//!   leaves the caller's transaction open, neither committed nor rolled
//!   back; the caller's rollback leaves the row and its version unchanged.
//! - Order: with a second connection holding the write lock, a stopped
//!   store still refuses with `RecordStopped` (not a busy / lock error
//!   after the busy timeout), so the gate cannot have moved inside the
//!   transaction.
//! - Structure: in `src/storage/versioned_update_txn.rs` the gate is an
//!   executed top-level statement, the first statement of
//!   `update_with_expected_version_gated`, before `in_write_txn(` and the
//!   `UPDATE memories` (`gate_shape_verdict`, comments and string literals
//!   masked, nested blocks rejected, with a table-driven self-test), and
//!   the `storage/mod.rs` funnel delegates to that fn (the
//!   `qual_pg_record_stop_gate_parity_3175` ssot pair reads mod.rs only).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ai_memory::models::{Memory, Tier};
use ai_memory::storage::StorageError;
use ai_memory::storage::record_stop::{SCOPE_RECORD_PLANE, actuate_sqlite};
use rusqlite::{OpenFlags, params};
use serde_json::json;
use tempfile::{NamedTempFile, TempDir};

const NS: &str = "versioned-update-9273";
const OPERATOR: &str = "ai:operator";
const SEED_CONTENT: &str = "seed content";
const HOSTILE_CONTENT: &str = "write attempted under record-stop";
const SEED_VERSION: i64 = 1;
const SEED_PRIORITY: i64 = 5;
/// Priority the caller writes inside its own transaction before the call.
const CALLER_PRIORITY: i64 = 9;
/// Exact `RecordStopped` Display text for the engage call below.
const STOPPED_TEXT: &str = "substrate record plane stopped by ai:operator (scope=record-plane); mutating operations refused until resume";
/// Exact `RecordStopIndeterminate` Display text when `signed_events` cannot
/// be read (the reason is the outer context of `read_state_sqlite`).
const INDETERMINATE_TEXT: &str = "substrate record-stop state could not be read (fail-closed; mutating operation refused, retry): record_stop::read_state_sqlite";
/// The caller's own error, returned to roll its transaction back.
const CALLER_ROLLBACK: &str = "caller rolls its transaction back after the refusal (9273)";
/// Name `signed_events` is moved to so the stop state cannot be read.
const UNREADABLE_CHAIN_TABLE: &str = "signed_events_unreadable_9273";
/// The gate is a read of the stop flag; it must answer well inside the
/// 5 s sqlite busy timeout a gate behind `BEGIN IMMEDIATE` would wait.
const GATE_BEFORE_LOCK_CEILING: Duration = Duration::from_secs(3);
const CHILD_SRC: &str = "src/storage/versioned_update_txn.rs";
const ROOT_SRC: &str = "src/storage/mod.rs";
const ROOT_FN: &str = "pub fn update_with_expected_version(";
const TXN_CALL: &str = "in_write_txn(";
const DELEGATE_CALL: &str = "versioned_update_txn::update_with_expected_version_gated(";

fn seed_memory() -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: NS.to_string(),
        title: "versioned-update-9273".to_string(),
        content: SEED_CONTENT.to_string(),
        tags: vec!["r9273".to_string()],
        priority: i32::try_from(SEED_PRIORITY).expect("seed priority fits i32"),
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id": OPERATOR}),
        version: SEED_VERSION,
        ..Memory::default()
    }
}

/// Fresh file store with one seeded row, then the record-stop engaged.
fn stopped_store_with_row() -> (rusqlite::Connection, NamedTempFile, String) {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("open");
    let id = ai_memory::db::insert(&conn, &seed_memory()).expect("seed row");
    assert!(
        actuate_sqlite(&conn, true, OPERATOR, SCOPE_RECORD_PLANE).expect("engage record-stop"),
        "first engage must report a state change"
    );
    (conn, f, id)
}

/// A store at a path this process never gated, whose `signed_events`
/// table is moved away so the record-stop state cannot be read. The row is
/// seeded through a first store and copied with `VACUUM INTO`, so the copy's
/// path has no cached stop flag and the gate's first touch reads the chain.
fn unreadable_stop_store_with_row() -> (rusqlite::Connection, TempDir, PathBuf, String) {
    let dir = TempDir::new().expect("tempdir");
    let seed_path = dir.path().join("seed-9273.db");
    let copy_path = dir.path().join("unreadable-stop-9273.db");
    let seed = ai_memory::db::open(&seed_path).expect("open seed store");
    let id = ai_memory::db::insert(&seed, &seed_memory()).expect("seed row");
    seed.execute(
        "VACUUM INTO ?1",
        params![copy_path.to_str().expect("utf-8 path")],
    )
    .expect("copy the seeded store");
    drop(seed);
    let conn = ai_memory::db::open(&copy_path).expect("open the copy");
    conn.execute_batch(&format!(
        "ALTER TABLE signed_events RENAME TO {UNREADABLE_CHAIN_TABLE}"
    ))
    .expect("move the record-stop chain away");
    (conn, dir, copy_path, id)
}

fn versioned_update(conn: &rusqlite::Connection, id: &str) -> anyhow::Result<(bool, bool)> {
    ai_memory::db::update_with_expected_version(
        conn,
        id,
        None,
        Some(HOSTILE_CONTENT),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(SEED_VERSION),
        None,
    )
}

fn storage_error(err: &anyhow::Error) -> &StorageError {
    err.downcast_ref::<StorageError>()
        .unwrap_or_else(|| panic!("typed StorageError in the anyhow chain, got {err:#}"))
}

fn assert_record_stopped(err: &anyhow::Error) {
    let se = storage_error(err);
    assert!(
        matches!(se, StorageError::RecordStopped { .. }),
        "versioned update must refuse with RecordStopped, got {se:?}"
    );
    assert_eq!(se.to_string(), STOPPED_TEXT, "exact RecordStopped text");
}

fn assert_record_stop_indeterminate(err: &anyhow::Error) {
    let se = storage_error(err);
    assert!(
        matches!(se, StorageError::RecordStopIndeterminate { .. }),
        "an unreadable stop state must refuse with RecordStopIndeterminate, got {se:?}"
    );
    assert_eq!(
        se.to_string(),
        INDETERMINATE_TEXT,
        "exact RecordStopIndeterminate text"
    );
}

/// `(content, version, priority)` of the row.
fn row_state(conn: &rusqlite::Connection, id: &str) -> (String, i64, i64) {
    conn.query_row(
        "SELECT content, version, priority FROM memories WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .expect("read row")
}

fn assert_row_unchanged(conn: &rusqlite::Connection, id: &str) {
    let (content, version, priority) = row_state(conn, id);
    assert_eq!(
        content, SEED_CONTENT,
        "stopped update must not change content"
    );
    assert_eq!(
        version, SEED_VERSION,
        "stopped update must not bump version"
    );
    assert_eq!(priority, SEED_PRIORITY, "the row's priority is the seed");
}

fn assert_refused_in_autocommit(conn: &rusqlite::Connection, id: &str, check: fn(&anyhow::Error)) {
    assert!(conn.is_autocommit(), "no transaction before the call");
    let changes_before = conn.total_changes();
    let err = versioned_update(conn, id).expect_err("the gate must refuse");
    check(&err);
    assert!(
        conn.is_autocommit(),
        "a refusal must leave no transaction open on the connection"
    );
    assert_eq!(
        conn.total_changes(),
        changes_before,
        "a refused versioned update changes zero rows"
    );
    assert_row_unchanged(conn, id);
}

/// The synthesis merge shape: the caller holds a write transaction (and has
/// written in it) when it calls the update. The refusal must neither commit
/// nor roll back the caller's transaction; the caller's rollback then leaves
/// the row and its version unchanged.
fn assert_refused_inside_caller_txn(
    conn: &rusqlite::Connection,
    path: &Path,
    id: &str,
    check: fn(&anyhow::Error),
) {
    let out: anyhow::Result<()> = ai_memory::db::in_write_txn(conn, || {
        assert!(
            !conn.is_autocommit(),
            "the caller holds a write transaction"
        );
        conn.execute(
            "UPDATE memories SET priority = ?1 WHERE id = ?2",
            params![CALLER_PRIORITY, id],
        )?;
        let err = versioned_update(conn, id).expect_err("the gate must refuse");
        check(&err);
        assert!(
            !conn.is_autocommit(),
            "the refusal must leave the caller's transaction open"
        );
        assert_eq!(
            row_state(conn, id).2,
            CALLER_PRIORITY,
            "the caller's own write survives the refusal: nothing was rolled back"
        );
        let reader = rusqlite::Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        assert_eq!(
            row_state(&reader, id).2,
            SEED_PRIORITY,
            "nothing was committed: a second connection still reads the seed row"
        );
        Err(anyhow::anyhow!(CALLER_ROLLBACK))
    });
    let err = out.expect_err("the caller rolls back");
    assert_eq!(err.to_string(), CALLER_ROLLBACK, "the caller's own error");
    assert!(
        conn.is_autocommit(),
        "the caller's rollback ends its transaction"
    );
    assert_row_unchanged(conn, id);
}

#[test]
fn versioned_update_refuses_under_record_stop_9273() {
    let (conn, _f, id) = stopped_store_with_row();
    assert_refused_in_autocommit(&conn, &id, assert_record_stopped);
}

#[test]
fn versioned_update_refusal_keeps_caller_txn_open_9273() {
    let (conn, f, id) = stopped_store_with_row();
    assert_refused_inside_caller_txn(&conn, f.path(), &id, assert_record_stopped);
}

#[test]
fn versioned_update_refuses_on_unreadable_stop_state_9273() {
    let (conn, _dir, _path, id) = unreadable_stop_store_with_row();
    assert_refused_in_autocommit(&conn, &id, assert_record_stop_indeterminate);
    // The error path caches nothing, so the caller-held shape re-probes and
    // refuses the same way.
    let (conn, _dir, path, id) = unreadable_stop_store_with_row();
    assert_refused_inside_caller_txn(&conn, &path, &id, assert_record_stop_indeterminate);
}

#[test]
fn versioned_update_gate_runs_before_write_lock_9273() {
    let (conn, f, id) = stopped_store_with_row();
    let holder = ai_memory::db::open(f.path()).expect("open lock holder");
    holder
        .execute_batch("BEGIN IMMEDIATE")
        .expect("holder takes the write lock");
    let started = Instant::now();
    let result = versioned_update(&conn, &id);
    let elapsed = started.elapsed();
    holder.execute_batch("ROLLBACK").expect("holder releases");
    let err = result.expect_err("stopped store must refuse while the lock is held");
    assert_record_stopped(&err);
    assert!(
        conn.is_autocommit(),
        "a refusal must leave no transaction open on the connection"
    );
    assert!(
        elapsed < GATE_BEFORE_LOCK_CEILING,
        "gate must answer before the write lock is requested; took {elapsed:?}"
    );
    assert_row_unchanged(&conn, &id);
}

// ---------------------------------------------------------------------------
// Structural pin: the gate is an executed top-level first statement.
// ---------------------------------------------------------------------------

/// Signature of the fn that holds the write SQL.
const GATED_FN_SIG: &str = "fn update_with_expected_version_gated(";
/// The gate statement, form 1 (a bare `?` statement).
const GATE_STMT: &str = "crate::storage::record_stop::gate_storage_conn(conn)?;";
/// Indent of a top-level statement in the fn body.
const BODY_INDENT: &str = "    ";
const WRITE_SQL: &str = "UPDATE memories";

const REASON_NO_SIG: &str = "the gated fn signature is not in the source";
const REASON_DUP_SIG: &str = "the gated fn signature appears more than once";
const REASON_NO_BODY: &str = "the gated fn has no complete body";
const REASON_SIG_LINE: &str = "the body must open on the closing line of the signature";
const REASON_IN_COMMENT: &str = "the gate appears only inside a comment";
const REASON_IN_STRING: &str = "the gate appears only inside a string literal";
const REASON_OTHER_FN: &str = "the gate is in a different fn, not the fn that holds the write SQL";
const REASON_ABSENT: &str = "the gate statement is absent from the source";
const REASON_NESTED_FN: &str = "the gate is inside a nested fn";
const REASON_INSIDE_TXN: &str = "the gate is inside the write transaction closure";
const REASON_CLOSURE: &str = "the gate is inside a closure";
const REASON_CONDITIONAL: &str = "the gate is inside a conditional or loop block";
const REASON_NESTED_BLOCK: &str = "the gate is inside a nested block";
const REASON_NOT_LINE: &str = "the gate is not a whole statement line at body indent";
const REASON_ATTRIBUTE: &str = "the gate statement carries an attribute";
const REASON_AFTER_TXN: &str = "the gate runs after the write transaction";
const REASON_NOT_FIRST: &str = "the gate is not the first statement of the fn body";
const REASON_NO_TXN: &str = "the gated fn opens no write transaction after the gate";
const REASON_NO_WRITE: &str = "the gated fn holds no write SQL after the gate";

/// Words that open a conditional or loop block.
const CONDITIONAL_HEADS: &[&str] = &["if", "else", "match", "while", "for", "loop"];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Code,
    Comment,
    Str,
}

/// Source with every comment and string / char literal byte replaced by a
/// space (newlines kept, so byte offsets and lines match the input), plus
/// the kind of each byte.
struct Masked {
    code: String,
    kinds: Vec<Kind>,
}

fn charge(ops: &mut u64, n: usize) {
    *ops = ops.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// End (exclusive) of the comment or literal starting at `i`, and its kind,
/// or `None` when `i` starts code. Unterminated forms run to the end.
fn literal_end(b: &[u8], i: usize) -> Option<(usize, Kind)> {
    let at = |k: usize| b.get(k).copied();
    match (b[i], at(i + 1)) {
        (b'/', Some(b'/')) => {
            let end = b[i..]
                .iter()
                .position(|&c| c == b'\n')
                .map_or(b.len(), |p| i + p);
            Some((end, Kind::Comment))
        }
        (b'/', Some(b'*')) => {
            let (mut k, mut depth) = (i + 2, 1_usize);
            while k < b.len() && depth > 0 {
                match (b[k], at(k + 1)) {
                    (b'/', Some(b'*')) => (depth, k) = (depth + 1, k + 2),
                    (b'*', Some(b'/')) => (depth, k) = (depth - 1, k + 2),
                    _ => k += 1,
                }
            }
            Some((k.min(b.len()), Kind::Comment))
        }
        (b'"', _) => {
            let mut k = i + 1;
            while k < b.len() && b[k] != b'"' {
                k += if b[k] == b'\\' { 2 } else { 1 };
            }
            Some(((k + 1).min(b.len()), Kind::Str))
        }
        (b'r', Some(b'#' | b'"')) if i == 0 || !is_ident(b[i - 1]) || raw_prefixed(b, i) => {
            let hashes = b[i + 1..].iter().take_while(|&&c| c == b'#').count();
            if at(i + 1 + hashes) != Some(b'"') {
                return None;
            }
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            let body = i + 2 + hashes;
            let end = b[body..]
                .windows(close.len())
                .position(|w| w == close.as_slice())
                .map_or(b.len(), |p| body + p + close.len());
            Some((end, Kind::Str))
        }
        (b'\'', Some(b'\\')) => {
            let end = b[i + 2..]
                .iter()
                .position(|&c| c == b'\'')
                .map_or(b.len(), |p| i + 3 + p);
            Some((end, Kind::Str))
        }
        (b'\'', Some(lead)) => {
            let width = utf8_width(lead);
            (at(i + 1 + width) == Some(b'\'')).then_some((i + 2 + width, Kind::Str))
        }
        _ => None,
    }
}

/// `br"..."` / `br#"..."#`: the `r` follows a `b` that starts the token.
fn raw_prefixed(b: &[u8], i: usize) -> bool {
    b[i - 1] == b'b' && (i == 1 || !is_ident(b[i - 2]))
}

fn utf8_width(lead: u8) -> usize {
    match lead {
        0xF0..=0xFF => 4,
        0xE0..=0xEF => 3,
        0xC0..=0xDF => 2,
        _ => 1,
    }
}

fn mask(src: &str, ops: &mut u64) -> Masked {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let mut kinds = vec![Kind::Code; b.len()];
    let mut i = 0;
    while i < b.len() {
        charge(ops, 1);
        let Some((end, kind)) = literal_end(b, i) else {
            i += 1;
            continue;
        };
        charge(ops, end - i);
        for k in i..end {
            kinds[k] = kind;
            if out[k] != b'\n' {
                out[k] = b' ';
            }
        }
        i = end;
    }
    // Every replaced byte is a whole char (literal and comment bounds are
    // ASCII delimiters), so the result stays valid UTF-8.
    let code = String::from_utf8(out).expect("masked source is UTF-8");
    Masked { code, kinds }
}

/// `(open, close)` byte offsets of the body braces of the fn whose
/// signature starts at `sig`: the first `{` after the parameter list at
/// paren depth 0, and its matching `}`.
fn body_span(code: &str, sig: usize, ops: &mut u64) -> Option<(usize, usize)> {
    let b = code.as_bytes();
    let (mut parens, mut seen_params, mut open) = (0_i64, false, None);
    for (k, &c) in b.iter().enumerate().skip(sig) {
        charge(ops, 1);
        match c {
            b'(' => (parens, seen_params) = (parens + 1, true),
            b')' => parens -= 1,
            b'{' if seen_params && parens == 0 => {
                open = Some(k);
                break;
            }
            _ => {}
        }
    }
    let open = open?;
    let mut depth = 0_i64;
    for (k, &c) in b.iter().enumerate().skip(open) {
        charge(ops, 1);
        match c {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open, k));
                }
            }
            _ => {}
        }
    }
    None
}

fn line_start(code: &str, at: usize) -> usize {
    code[..at].rfind('\n').map_or(0, |p| p + 1)
}

fn line_end(code: &str, at: usize) -> usize {
    code[at..].find('\n').map_or(code.len(), |p| at + p)
}

/// Why a gate at `at` (code offset) inside the body `open..close` sits in a
/// nested block, or `None` when it is at the top level of the body.
fn nesting_reason(code: &str, open: usize, at: usize, ops: &mut u64) -> Option<&'static str> {
    let mut stack = Vec::new();
    for (k, c) in code.bytes().enumerate().take(at).skip(open + 1) {
        charge(ops, 1);
        match c {
            b'{' => stack.push(k),
            b'}' => {
                stack.pop();
            }
            _ => {}
        }
    }
    let inner = *stack.last()?;
    let from = code[..inner].rfind([';', '{', '}']).map_or(0, |p| p + 1);
    charge(ops, inner - from);
    let header = code[from..inner].trim();
    let first = header.split_whitespace().next().unwrap_or_default();
    Some(if header.split_whitespace().any(|w| w == "fn") {
        REASON_NESTED_FN
    } else if header.contains('|') && header.contains(TXN_CALL) {
        REASON_INSIDE_TXN
    } else if header.contains('|') {
        REASON_CLOSURE
    } else if CONDITIONAL_HEADS.contains(&first) {
        REASON_CONDITIONAL
    } else {
        REASON_NESTED_BLOCK
    })
}

/// Why the source has no executed gate statement in the gated fn body.
fn absent_reason(src: &str, m: &Masked, open: usize, close: usize) -> &'static str {
    if let Some(p) = src[open + 1..close].find(GATE_STMT) {
        return match m.kinds[open + 1 + p] {
            Kind::Comment => REASON_IN_COMMENT,
            Kind::Str => REASON_IN_STRING,
            Kind::Code => REASON_ABSENT,
        };
    }
    if m.code.contains(GATE_STMT) {
        REASON_OTHER_FN
    } else {
        REASON_ABSENT
    }
}

/// Ok only when the gate is an executed top-level statement of
/// `update_with_expected_version_gated`: a whole line at body indent, the
/// first statement of the body (only blank or comment lines between it and
/// the closing line of the signature), before the write transaction and
/// the write SQL. Every other shape is an `Err` with its reason.
fn gate_shape_verdict(src: &str) -> Result<(), &'static str> {
    gate_shape_verdict_counted(src, &mut 0)
}

fn gate_shape_verdict_counted(src: &str, ops: &mut u64) -> Result<(), &'static str> {
    let m = mask(src, ops);
    let code = m.code.as_str();
    charge(ops, code.len());
    let mut sigs = code.match_indices(GATED_FN_SIG).map(|(p, _)| p);
    let sig = sigs.next().ok_or(REASON_NO_SIG)?;
    if sigs.next().is_some() {
        return Err(REASON_DUP_SIG);
    }
    let (open, close) = body_span(code, sig, ops).ok_or(REASON_NO_BODY)?;
    let sig_line = code[line_start(code, open)..line_end(code, open)].trim();
    if !(sig_line.starts_with(')') && sig_line.ends_with('{')) {
        return Err(REASON_SIG_LINE);
    }
    charge(ops, close - open);
    let Some(rel) = code[open + 1..close].find(GATE_STMT) else {
        charge(ops, src.len());
        return Err(absent_reason(src, &m, open, close));
    };
    let at = open + 1 + rel;
    if let Some(reason) = nesting_reason(code, open, at, ops) {
        return Err(reason);
    }
    let start = line_start(code, at);
    if code[start..line_end(code, at)].trim_end() != format!("{BODY_INDENT}{GATE_STMT}") {
        return Err(REASON_NOT_LINE);
    }
    let before = &code[open + 1..start];
    charge(ops, before.len());
    if let Some(last) = before.lines().rev().map(str::trim).find(|l| !l.is_empty()) {
        return Err(if last.starts_with("#[") {
            REASON_ATTRIBUTE
        } else if before.contains(TXN_CALL) {
            REASON_AFTER_TXN
        } else {
            REASON_NOT_FIRST
        });
    }
    charge(ops, 2 * (close - at));
    if !code[at..close].contains(TXN_CALL) {
        return Err(REASON_NO_TXN);
    }
    if !src[at..close].contains(WRITE_SQL) {
        return Err(REASON_NO_WRITE);
    }
    Ok(())
}

fn read_src(rel: &str) -> String {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), rel].iter().collect();
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn versioned_update_gate_precedes_txn_and_write_sql_in_one_span_9273() {
    assert_eq!(
        gate_shape_verdict(&read_src(CHILD_SRC)),
        Ok(()),
        "{CHILD_SRC}: the gate must be the executed first statement, before the transaction opens"
    );

    let root = mask(&read_src(ROOT_SRC), &mut 0).code;
    let sig = root
        .find(ROOT_FN)
        .unwrap_or_else(|| panic!("{ROOT_SRC}: signature {ROOT_FN} present"));
    let (open, close) =
        body_span(&root, sig, &mut 0).unwrap_or_else(|| panic!("{ROOT_SRC}: body of {ROOT_FN}"));
    let root_body = &root[open..close];
    assert!(
        root_body.contains(DELEGATE_CALL),
        "{ROOT_SRC}: the funnel must delegate to the gated fn"
    );
    assert!(
        !root_body.contains(TXN_CALL),
        "{ROOT_SRC}: the funnel must not open the transaction ahead of the gated child"
    );
}

/// Shape template: `@GATE@` is the gate position (first statement),
/// `@INNER@` the first statement inside the transaction closure, `@TAIL@`
/// items after the fn.
const SHAPE_TEMPLATE: &str = r#"use super::*;

/// The gated body.
#[allow(clippy::too_many_arguments)]
pub(super) fn update_with_expected_version_gated(
    conn: &Connection,
    id: &str,
    content: Option<&str>,
) -> Result<(bool, bool)> {
    // #1955 R45 - record-stop fence; it runs before the transaction opens.
@GATE@
    connection::in_write_txn(conn, || {
@INNER@        conn.execute("UPDATE memories SET content = ?1 WHERE id = ?2", params![content, id])?;
        Ok((true, true))
    })
}
@TAIL@"#;

const SHAPE_REAL_GATE: &str = "    crate::storage::record_stop::gate_storage_conn(conn)?;";

/// `(name, @GATE@, @INNER@, @TAIL@, expected verdict)`.
type Shape = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Result<(), &'static str>,
);

const GATE_SHAPES_9273: &[Shape] = &[
    ("real shape", SHAPE_REAL_GATE, "", "", Ok(())),
    (
        "real shape with a trailing comment",
        "    crate::storage::record_stop::gate_storage_conn(conn)?; // fence",
        "",
        "",
        Ok(()),
    ),
    ("gate removed", "", "", "", Err(REASON_ABSENT)),
    (
        "gate in a line comment",
        "    // crate::storage::record_stop::gate_storage_conn(conn)?;",
        "",
        "",
        Err(REASON_IN_COMMENT),
    ),
    (
        "gate in a doc comment",
        "    /// crate::storage::record_stop::gate_storage_conn(conn)?;",
        "",
        "",
        Err(REASON_IN_COMMENT),
    ),
    (
        "gate in a block comment",
        "    /* crate::storage::record_stop::gate_storage_conn(conn)?; */",
        "",
        "",
        Err(REASON_IN_COMMENT),
    ),
    (
        "gate in a string literal",
        "    let _s = \"crate::storage::record_stop::gate_storage_conn(conn)?;\";",
        "",
        "",
        Err(REASON_IN_STRING),
    ),
    (
        "gate in a raw string literal",
        "    let _s = r#\"crate::storage::record_stop::gate_storage_conn(conn)?;\"#;",
        "",
        "",
        Err(REASON_IN_STRING),
    ),
    (
        "gate inside if false",
        "    if false {\n        crate::storage::record_stop::gate_storage_conn(conn)?;\n    }",
        "",
        "",
        Err(REASON_CONDITIONAL),
    ),
    (
        "gate inside an else branch",
        "    if conn.is_autocommit() {\n    } else {\n        crate::storage::record_stop::gate_storage_conn(conn)?;\n    }",
        "",
        "",
        Err(REASON_CONDITIONAL),
    ),
    (
        "gate inside an uncalled closure",
        "    let _gate = || -> Result<()> {\n        crate::storage::record_stop::gate_storage_conn(conn)?;\n        Ok(())\n    };",
        "",
        "",
        Err(REASON_CLOSURE),
    ),
    (
        "gate inside a nested block",
        "    {\n        crate::storage::record_stop::gate_storage_conn(conn)?;\n    }",
        "",
        "",
        Err(REASON_NESTED_BLOCK),
    ),
    (
        "gate under cfg(test)",
        "    #[cfg(test)]\n    crate::storage::record_stop::gate_storage_conn(conn)?;",
        "",
        "",
        Err(REASON_ATTRIBUTE),
    ),
    (
        "gate moved after in_write_txn (inside the transaction)",
        "",
        "        crate::storage::record_stop::gate_storage_conn(conn)?;\n",
        "",
        Err(REASON_INSIDE_TXN),
    ),
    (
        "gate inside a nested fn",
        "    fn _inner(conn: &Connection) -> Result<()> {\n        crate::storage::record_stop::gate_storage_conn(conn)?;\n        Ok(())\n    }",
        "",
        "",
        Err(REASON_NESTED_FN),
    ),
    (
        "gate only in a different fn of the file",
        "",
        "",
        "\nfn other(conn: &Connection) -> Result<()> {\n    crate::storage::record_stop::gate_storage_conn(conn)?;\n    Ok(())\n}\n",
        Err(REASON_OTHER_FN),
    ),
    (
        "gate as second statement after a write",
        "    conn.execute(\"UPDATE memories SET priority = 1\", [])?;\n    crate::storage::record_stop::gate_storage_conn(conn)?;",
        "",
        "",
        Err(REASON_NOT_FIRST),
    ),
    (
        "gate after a char literal brace (masking proof)",
        "    let _c = '{';\n    crate::storage::record_stop::gate_storage_conn(conn)?;",
        "",
        "",
        Err(REASON_NOT_FIRST),
    ),
    (
        "gate bound with let",
        "    let () = crate::storage::record_stop::gate_storage_conn(conn)?;",
        "",
        "",
        Err(REASON_NOT_LINE),
    ),
    (
        "gate at the wrong indent",
        "crate::storage::record_stop::gate_storage_conn(conn)?;",
        "",
        "",
        Err(REASON_NOT_LINE),
    ),
    (
        "signature appears twice",
        SHAPE_REAL_GATE,
        "",
        "\nfn update_with_expected_version_gated(conn: &Connection) {}\n",
        Err(REASON_DUP_SIG),
    ),
];

fn shape_source(gate: &str, inner: &str, tail: &str) -> String {
    SHAPE_TEMPLATE
        .replace("@GATE@", gate)
        .replace("@INNER@", inner)
        .replace("@TAIL@", tail)
}

#[test]
fn gate_shape_verdict_table_9273() {
    for &(name, gate, inner, tail, expected) in GATE_SHAPES_9273 {
        assert_eq!(
            gate_shape_verdict(&shape_source(gate, inner, tail)),
            expected,
            "shape `{name}`"
        );
    }
}

#[test]
fn gate_shape_verdict_rejects_missing_txn_and_sig_forms_9273() {
    let no_txn =
        shape_source(SHAPE_REAL_GATE, "", "").replace("connection::in_write_txn(conn, ", "run(");
    assert_eq!(gate_shape_verdict(&no_txn), Err(REASON_NO_TXN));
    let no_write =
        shape_source(SHAPE_REAL_GATE, "", "").replace(WRITE_SQL, "SELECT 1 FROM memories");
    assert_eq!(gate_shape_verdict(&no_write), Err(REASON_NO_WRITE));
    let one_line_sig = shape_source(SHAPE_REAL_GATE, "", "").replace(
        "    content: Option<&str>,\n) -> Result<(bool, bool)> {",
        "    content: Option<&str>) -> Result<(bool, bool)> {",
    );
    assert_eq!(gate_shape_verdict(&one_line_sig), Err(REASON_SIG_LINE));
    assert_eq!(gate_shape_verdict(""), Err(REASON_NO_SIG));
    let unclosed =
        format!("{GATED_FN_SIG}conn: &Connection) -> Result<()> {{\n{SHAPE_REAL_GATE}\n");
    assert_eq!(gate_shape_verdict(&unclosed), Err(REASON_NO_BODY));
}

/// Input size for the scan bound.
const SCAN_BOUND_BYTES: usize = 100_000;
/// Op ceiling per input byte. The scan is a constant number of linear
/// passes (mask, body match, nesting walk, and about eight substring
/// searches), measured at 2.0 to 6.1 ops per byte on the five inputs below
/// (the cell prints each count); 16 leaves a 2.6x margin over the largest,
/// and any per-line or per-occurrence rescan grows with the input and
/// blows it at this size.
const OPS_PER_BYTE_CEILING: u64 = 16;

fn assert_linear(name: &str, src: &str, expected: Result<(), &'static str>) {
    assert!(
        src.len() >= SCAN_BOUND_BYTES,
        "{name}: input is {} bytes",
        src.len()
    );
    let mut ops = 0;
    assert_eq!(
        gate_shape_verdict_counted(src, &mut ops),
        expected,
        "{name}"
    );
    let ceiling = OPS_PER_BYTE_CEILING * u64::try_from(src.len()).expect("len fits u64");
    println!("{name}: {} bytes, {ops} ops, ceiling {ceiling}", src.len());
    assert!(
        ops <= ceiling,
        "{name}: {ops} ops over the linear ceiling {ceiling}"
    );
}

#[test]
fn gate_shape_verdict_is_linear_on_100k_inputs_9273() {
    let filler_line = "        let _x = \"{ } /* // \"; // { } \"\n";
    let filler = filler_line.repeat(SCAN_BOUND_BYTES / filler_line.len() + 1);
    let padded = shape_source(SHAPE_REAL_GATE, &filler, "");
    assert_linear("real shape with a 100K transaction body", &padded, Ok(()));

    let comment_chunk = "    // crate::storage::record_stop::gate_storage_conn(conn)?;\n";
    let comments = comment_chunk.repeat(SCAN_BOUND_BYTES / comment_chunk.len() + 1);
    let late_gate = shape_source(&format!("{comments}{SHAPE_REAL_GATE}"), "", "");
    assert_linear("gate after 100K of comment lines", &late_gate, Ok(()));

    let open_comments = "/*".repeat(SCAN_BOUND_BYTES / 2 + 1);
    assert_linear(
        "100K unterminated nested comment",
        &open_comments,
        Err(REASON_NO_SIG),
    );

    let braces = format!("{GATED_FN_SIG}) {}", "{".repeat(SCAN_BOUND_BYTES));
    assert_linear("100K unclosed braces", &braces, Err(REASON_NO_BODY));

    let nested = shape_source(
        &format!(
            "{}{SHAPE_REAL_GATE}{}",
            "{\n".repeat(SCAN_BOUND_BYTES / 4),
            "\n}".repeat(SCAN_BOUND_BYTES / 4)
        ),
        "",
        "",
    );
    assert_linear(
        "gate under 25K nested blocks",
        &nested,
        Err(REASON_NESTED_BLOCK),
    );
}
