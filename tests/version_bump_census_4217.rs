// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4217 — CENSUS GATE: every production statement that mutates an EXISTING
//! `memories` row either bumps `memories.version` or is on the justified
//! allow-list below. This is the successor of the hand-kept #1036 list
//! (`tests/non_version_bumping_sites_1036.rs`, which still pins the decay
//! behaviour): a new writer that changes a row without bumping cannot land
//! silently any more.
//!
//! Why it matters: optimistic concurrency (Gap-1 #884 `If-Match` /
//! `update_with_expected_version`) and the #4045 version-checked
//! consolidation (5-agent vote 4d3ea1c5, memory 656eb5ff) both assume that a
//! change to a row's user data changes its `version`. A writer that skips the
//! bump lets a reader holding the pre-write version pass the compare-and-set
//! and silently overwrite (or consume) the change.
//!
//! How: a std-only scan of `src/**/*.rs` (test modules excluded). Every string
//! literal carrying `UPDATE memories`, or an `INSERT ... INTO memories` whose
//! Rust statement has a `DO UPDATE` / `OR REPLACE` arm, is one site. It is
//! "bumping" when the statement assigns `version = version + 1` or
//! `version = memories.version + 1`. Non-bumping sites are grouped by
//! (file, enclosing fn/const) and must match the allow-list EXACTLY: a new
//! unlisted site fails, and so does a stale entry. Fixing a site means
//! deleting its entry, so the list only ever shrinks.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// (file, enclosing item, non-bumping statement count, justification).
const ALLOWED_NON_BUMPING: &[(&str, &str, usize, &str)] = &[
    // --- #1036 sanctioned system bookkeeping (no user reader acts on it) ---
    (
        "src/confidence/decay.rs",
        "apply_decay_touch",
        1,
        "#1036: confidence decay is monotonic system bookkeeping; bumping would \
         raise spurious VersionConflicts on the next user edit",
    ),
    (
        "src/store/postgres.rs",
        "apply_confidence_decay_stamp",
        2,
        "#1036 postgres twin of the sanctioned confidence decay",
    ),
    (
        "src/atomisation/mod.rs",
        "write_atom",
        1,
        "#1036: atom_of back-fill on a row inserted in the same operation",
    ),
    // --- same-operation finalization of a freshly minted row ---
    (
        "src/storage/mod.rs",
        "SQL_UPDATE_METADATA_AND_UPDATED_AT_BY_ID",
        1,
        "persona metadata patch, same transaction as the persona row's own insert",
    ),
    (
        "src/storage/mod.rs",
        "set_row_metadata",
        1,
        "#2860 (vote 4d3ea1c5): federated-consolidate finalize stamps the freshly \
         minted summary row; the stored row must byte-match the broadcast copy",
    ),
    (
        "src/store/postgres.rs",
        "set_row_metadata",
        1,
        "#2860 postgres twin of the freshly-minted consolidate finalize stamp",
    ),
    (
        "src/handlers/consolidate_federation.rs",
        "sqlite_finalize_and_disposition",
        1,
        "#2860 sqlite federated-consolidate finalize of the freshly minted row",
    ),
    // --- re-seal / erase: same plaintext, or the row is about to be deleted ---
    (
        "src/storage/mod.rs",
        "reconcile_envelope_owner",
        1,
        "re-seals the SAME plaintext to the surviving owner key inside the bumping \
         insert/merge transaction",
    ),
    (
        "src/store/postgres.rs",
        "reconcile_envelope_owner_known",
        1,
        "postgres twin of the same-plaintext envelope re-seal inside the bumping upsert",
    ),
    (
        "src/store/postgres.rs",
        "pg_apply_entitled_attestation_in_tx",
        1,
        "attestation metadata stamped in the same transaction as the bumping update",
    ),
    (
        "src/storage/mod.rs",
        "crypto_erase_record_envelope",
        1,
        "crypto-erasure immediately before the row is deleted",
    ),
    // --- access-driven bookkeeping: access_count / last_accessed_at and the
    //     recall TTL floor (never shortens a row's life, never user data) ---
    (
        "src/storage/mod.rs",
        "touch",
        1,
        "recall access bookkeeping + TTL floor",
    ),
    (
        "src/storage/mod.rs",
        "touch_many",
        1,
        "recall access bookkeeping + TTL floor",
    ),
    (
        "src/storage/mod.rs",
        "fold_recall_accesses",
        1,
        "recall access fold + TTL floor",
    ),
    (
        "src/store/postgres.rs",
        "touch_after_recall",
        1,
        "recall access bookkeeping + TTL floor",
    ),
    (
        "src/store/postgres.rs",
        "fold_recall_accesses",
        1,
        "recall access fold + TTL floor",
    ),
    // --- crypto-erasure: the envelope is destroyed on the way to deletion ---
    (
        "src/store/postgres.rs",
        "SQL_CRYPTO_ERASE_ENVELOPE_BY_ID",
        1,
        "crypto-erasure immediately before the row is deleted",
    ),
    (
        "src/store/postgres.rs",
        "forget",
        1,
        "forget crypto-erasure before the delete",
    ),
    (
        "src/store/postgres_parity.rs",
        "evict_tombstone_and_erase_in_tx",
        1,
        "eviction crypto-erasure before the delete",
    ),
    // --- one-shot schema migrations (run before any reader holds a version) ---
    (
        "src/storage/migrations.rs",
        "migrate",
        5,
        "one-shot schema migration backfills",
    ),
    (
        "src/store/postgres.rs",
        "migrate_v17",
        1,
        "one-shot governance-inherit backfill",
    ),
    (
        "src/store/postgres.rs",
        "migrate_v54",
        1,
        "one-shot tier-default expiry backfill",
    ),
    (
        "src/store/postgres.rs",
        "migrate_v86",
        1,
        "one-shot valid_from/valid_until backfill",
    ),
    // --- promote: a no-op after the bumping db::update ---
    (
        "src/handlers/memories.rs",
        "promote_memory",
        1,
        "clears expires_at right after db::update, which already bumped and already \
         nulls expires_at for tier=long (#2331)",
    ),
    // --- #4216: federation merge semantics (needs its own 5-agent vote) ---
    (
        "src/storage/mod.rs",
        "INSERT_IF_NEWER_SQL",
        1,
        "tracked by #4216 (federation merge keeps version = MAX)",
    ),
    (
        "src/storage/mod.rs",
        "overwrite_full_row_by_id",
        1,
        "tracked by #4216 (federation merge copies the merged version)",
    ),
    (
        "src/store/postgres.rs",
        "SQL_MERGE_INBOUND_FULL_ROW_UPDATE",
        1,
        "tracked by #4216 (federation merge copies the merged version)",
    ),
    (
        "src/store/postgres.rs",
        "apply_remote_memory",
        1,
        "tracked by #4216 (federation merge keeps version = GREATEST)",
    ),
];

/// Allow-listed statements held in a shared `const`/`static` are keyed by the
/// const, so a NEW caller of one would inherit its exemption unseen. Pin the
/// production reference count (definition included) of each such const.
const ALLOWED_CONST_REFERENCES: &[(&str, usize)] = &[
    ("SQL_UPDATE_METADATA_AND_UPDATED_AT_BY_ID", 2), // def + persona
    ("INSERT_IF_NEWER_SQL", 2),                      // def + insert_if_newer (#4216)
    ("SQL_MERGE_INBOUND_FULL_ROW_UPDATE", 2),        // def + merge_inbound (#4216)
    ("SQL_CRYPTO_ERASE_ENVELOPE_BY_ID", 2),          // def + the erase-before-delete helper
];

/// A positive canary: the user edit funnel must be seen AND seen as bumping,
/// so a scanner that silently stops matching cannot pass vacuously.
const BUMPING_CANARIES: &[(&str, &str)] = &[
    ("src/storage/mod.rs", "update_with_expected_version"),
    ("src/store/postgres.rs", "update"),
];

/// Floors against a vacuous scan (the census found ~85 sites when written).
const MIN_SITES: usize = 40;
const MIN_BUMPING_SITES: usize = 20;

#[derive(Debug)]
struct Site {
    file: String,
    item: String,
    line: usize,
    bumps: bool,
    excerpt: String,
}

// ------------------------------------------------------------------ lexer

struct Lexed {
    /// Source with every string literal and comment blanked (newlines kept),
    /// so structural searches never match inside SQL or prose.
    code: Vec<u8>,
    /// (start offset, raw literal body) for every string literal.
    strings: Vec<(usize, String)>,
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn blank(code: &mut [u8], from: usize, to: usize) {
    for b in &mut code[from..to] {
        if *b != b'\n' {
            *b = b' ';
        }
    }
}

fn lex(src: &str) -> Lexed {
    let bytes = src.as_bytes();
    let mut code = bytes.to_vec();
    let mut strings = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let cur = bytes[i];
        if cur == b'/' && bytes.get(i + 1) == Some(&b'/') {
            let end = bytes[i..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(bytes.len(), |p| i + p);
            blank(&mut code, i, end);
            i = end;
        } else if cur == b'/' && bytes.get(i + 1) == Some(&b'*') {
            let (mut depth, mut j) = (1, i + 2);
            while j < bytes.len() && depth > 0 {
                if bytes[j] == b'/' && bytes.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if bytes[j] == b'*' && bytes.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut code, i, j);
            i = j;
        } else if cur == b'r'
            && (i == 0 || !is_ident(bytes[i - 1]) || matches!(bytes[i - 1], b'b' | b'c'))
            && matches!(bytes.get(i + 1), Some(b'"' | b'#'))
        {
            let mut j = i + 1;
            let mut hashes = 0;
            while bytes.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if bytes.get(j) != Some(&b'"') {
                i += 1;
                continue;
            }
            let body = j + 1;
            let mut k = body;
            loop {
                if k >= bytes.len() {
                    break;
                }
                if bytes[k] == b'"'
                    && bytes[k + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|&&b| b == b'#')
                        .count()
                        == hashes
                {
                    break;
                }
                k += 1;
            }
            strings.push((
                i,
                String::from_utf8_lossy(&bytes[body..k.min(bytes.len())]).into_owned(),
            ));
            let end = (k + 1 + hashes).min(bytes.len());
            blank(&mut code, i, end);
            i = end;
        } else if cur == b'"' {
            let mut k = i + 1;
            while k < bytes.len() && bytes[k] != b'"' {
                if bytes[k] == b'\\' {
                    k += 1;
                }
                k += 1;
            }
            strings.push((
                i,
                String::from_utf8_lossy(&bytes[i + 1..k.min(bytes.len())]).into_owned(),
            ));
            let end = (k + 1).min(bytes.len());
            blank(&mut code, i, end);
            i = end;
        } else if cur == b'\'' {
            // char literal ('x', '\n', '\u{..}', multi-byte) vs lifetime ('a).
            if bytes.get(i + 1) == Some(&b'\\') {
                let mut k = i + 2;
                while k < bytes.len() && bytes[k] != b'\'' {
                    k += 1;
                }
                blank(&mut code, i, (k + 1).min(bytes.len()));
                i = k + 1;
            } else {
                let ch_len = src[i + 1..].chars().next().map_or(1, char::len_utf8);
                if bytes.get(i + 1 + ch_len) == Some(&b'\'') {
                    blank(&mut code, i, i + 2 + ch_len);
                    i += 2 + ch_len;
                } else {
                    i += 1;
                }
            }
        } else {
            i += 1;
        }
    }
    Lexed { code, strings }
}

/// Offset of the byte matching the opener at `open` (`{`/`[`/`(`).
fn matching(code: &[u8], open: usize) -> usize {
    let (o, c) = match code[open] {
        b'{' => (b'{', b'}'),
        b'[' => (b'[', b']'),
        _ => (b'(', b')'),
    };
    let mut depth = 0usize;
    for (k, &b) in code.iter().enumerate().skip(open) {
        if b == o {
            depth += 1;
        } else if b == c {
            depth -= 1;
            if depth == 0 {
                return k;
            }
        }
    }
    code.len() - 1
}

fn skip_ws(code: &[u8], mut i: usize) -> usize {
    while i < code.len() && code[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Byte ranges of `#[cfg(test)]` items, plus the names (and `#[path]`s) of
/// out-of-line `#[cfg(test)] mod x;` children.
/// Byte ranges (inclusive) of `#[cfg(test)]` items.
type TestRanges = Vec<(usize, usize)>;
/// Out-of-line `#[cfg(test)] mod name;` children: (name, `#[path]`).
type TestChildren = Vec<(String, Option<String>)>;

fn test_items(code: &[u8], src: &str) -> (TestRanges, TestChildren) {
    let text = String::from_utf8_lossy(code);
    let mut ranges = Vec::new();
    let mut children = Vec::new();
    for pat in ["#[cfg(test)]", "#[cfg(all(test"] {
        let mut from = 0;
        while let Some(p) = text[from..].find(pat) {
            let start = from + p;
            from = start + pat.len();
            let mut i = matching(code, start + 1) + 1;
            let mut path_attr = None;
            loop {
                i = skip_ws(code, i);
                if code.get(i) == Some(&b'#') && code.get(i + 1) == Some(&b'[') {
                    let end = matching(code, i + 1);
                    let attr = &src[i..=end];
                    if let Some(q) = attr.find("path") {
                        let rest = &attr[q..];
                        if let (Some(a), Some(b)) = (rest.find('"'), rest.rfind('"'))
                            && b > a
                        {
                            path_attr = Some(rest[a + 1..b].to_string());
                        }
                    }
                    i = end + 1;
                } else {
                    break;
                }
            }
            let mut j = i;
            let mut depth = 0i32;
            while j < code.len() {
                match code[j] {
                    b'(' | b'[' => depth += 1,
                    b')' | b']' => depth -= 1,
                    b'{' if depth == 0 => {
                        ranges.push((start, matching(code, j)));
                        break;
                    }
                    b';' if depth == 0 => {
                        let head: Vec<&str> = text[i..j].split_whitespace().collect();
                        if let Some(m) = head.iter().position(|w| *w == "mod")
                            && let Some(name) = head.get(m + 1)
                        {
                            children.push(((*name).to_string(), path_attr.clone()));
                        }
                        break;
                    }
                    _ => {}
                }
                j += 1;
            }
        }
    }
    (ranges, children)
}

/// Sorted (offset, name) of every `fn`/`const`/`static` item head.
fn item_heads(code: &[u8]) -> Vec<(usize, String)> {
    let mut heads = Vec::new();
    let mut i = 0;
    while i < code.len() {
        if is_ident(code[i]) && (i == 0 || !is_ident(code[i - 1])) {
            let mut e = i;
            while e < code.len() && is_ident(code[e]) {
                e += 1;
            }
            let word = &code[i..e];
            if matches!(word, b"fn" | b"const" | b"static") {
                let n0 = skip_ws(code, e);
                let mut n1 = n0;
                while n1 < code.len() && is_ident(code[n1]) {
                    n1 += 1;
                }
                if n1 > n0 {
                    heads.push((i, String::from_utf8_lossy(&code[n0..n1]).into_owned()));
                }
            }
            i = e;
        } else {
            i += 1;
        }
    }
    heads
}

// ---------------------------------------------------------------- matching

/// Collapse a literal body into upper-case SQL tokens: identifiers, single
/// punctuation chars; `\`-newline continuations and whitespace vanish.
fn sql_tokens(sql: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in sql.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch.to_ascii_uppercase());
        } else {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            if !ch.is_whitespace() && ch != '\\' {
                out.push(ch.to_string());
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn has_seq(toks: &[String], seq: &[&str]) -> bool {
    toks.windows(seq.len())
        .any(|w| w.iter().zip(seq).all(|(a, b)| a == b))
}

fn bumps(toks: &[String]) -> bool {
    has_seq(toks, &["VERSION", "=", "VERSION", "+", "1"])
        || has_seq(
            toks,
            &["VERSION", "=", "MEMORIES", ".", "VERSION", "+", "1"],
        )
}

/// Columns that are DERIVED or disposable (regenerable from the text, or
/// access statistics). A write that assigns ONLY these is not a data change.
const DERIVED_COLUMNS: &[&str] = &[
    "EMBEDDING",
    "EMBEDDING_DIM",
    "EMBEDDING_SPACE",
    "CID",
    "CID_GENESIS",
];

/// Columns assigned by the first `SET` list (depth-0 `col =` pairs). Empty
/// when it cannot be parsed, which the caller treats as a data write.
fn assigned_columns(toks: &[String]) -> Vec<String> {
    let Some(set) = toks.iter().position(|t| t == "SET") else {
        return Vec::new();
    };
    let mut cols = Vec::new();
    let mut depth = 0i32;
    for i in set + 1..toks.len() {
        match toks[i].as_str() {
            "(" => depth += 1,
            ")" => depth -= 1,
            "WHERE" | "RETURNING" | "FROM" if depth == 0 => break,
            t if depth == 0
                && toks.get(i + 1).is_some_and(|n| n == "=")
                && (i == set + 1 || toks[i - 1] == ",") =>
            {
                cols.push(t.to_string());
            }
            _ => {}
        }
    }
    cols
}

fn derived_only(toks: &[String]) -> bool {
    let cols = assigned_columns(toks);
    !cols.is_empty() && cols.iter().all(|c| DERIVED_COLUMNS.contains(&c.as_str()))
}

fn is_existing_row_write(first: &[String], stmt: &[String]) -> bool {
    if has_seq(first, &["UPDATE", "MEMORIES"]) {
        return true;
    }
    let insert = has_seq(first, &["INTO", "MEMORIES"]) && first.iter().any(|t| t == "INSERT");
    insert && (has_seq(stmt, &["DO", "UPDATE"]) || has_seq(first, &["OR", "REPLACE"]))
}

// ------------------------------------------------------------------- scan

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The directory an out-of-line child of `file` lives in.
fn module_dir(file: &Path) -> PathBuf {
    let dir = file.parent().unwrap_or(Path::new("")).to_path_buf();
    match file.file_stem().and_then(|s| s.to_str()) {
        Some("mod" | "lib" | "main") | None => dir,
        Some(stem) => dir.join(stem),
    }
}

/// Word-boundary occurrences of `name` in blanked (string/comment-free) code.
fn count_word(code: &[u8], name: &str) -> usize {
    String::from_utf8_lossy(code)
        .match_indices(name)
        .filter(|&(k, _)| {
            (k == 0 || !is_ident(code[k - 1]))
                && code.get(k + name.len()).is_none_or(|&b| !is_ident(b))
        })
        .count()
}

fn census(root: &Path) -> (Vec<Site>, Vec<Vec<u8>>) {
    let mut files = Vec::new();
    rs_files(&root.join("src"), &mut files);
    files.sort();
    let mut lexed = BTreeMap::new();
    let mut test_only_files: Vec<PathBuf> = Vec::new();
    for f in &files {
        let src = fs::read_to_string(f).unwrap_or_default();
        let lx = lex(&src);
        let (ranges, children) = test_items(&lx.code, &src);
        for (name, path_attr) in children {
            if let Some(p) = path_attr {
                test_only_files.push(f.parent().unwrap_or(root).join(p));
            } else {
                let base = module_dir(f);
                test_only_files.push(base.join(format!("{name}.rs")));
                test_only_files.push(base.join(&name).join("mod.rs"));
            }
        }
        lexed.insert(f.clone(), (src, lx, ranges));
    }
    // A test-only module's own children are test-only too.
    let test_dirs: Vec<PathBuf> = test_only_files.iter().map(|f| module_dir(f)).collect();
    let mut sites = Vec::new();
    let mut prod_code = Vec::new();
    for (f, (src, lx, ranges)) in &lexed {
        if test_only_files.contains(f) || test_dirs.iter().any(|d| f.starts_with(d)) {
            continue;
        }
        let mut code = lx.code.clone();
        let len = code.len();
        for &(a, b) in ranges {
            blank(&mut code, a, (b + 1).min(len));
        }
        prod_code.push(code);
        let heads = item_heads(&lx.code);
        let rel = f
            .strip_prefix(root)
            .unwrap_or(f)
            .to_string_lossy()
            .replace('\\', "/");
        for (idx, (start, body)) in lx.strings.iter().enumerate() {
            if ranges.iter().any(|&(a, b)| *start >= a && *start <= b) {
                continue;
            }
            let first = sql_tokens(body);
            if !has_seq(&first, &["MEMORIES"]) {
                continue;
            }
            // The Rust statement: this literal up to the next `;` in code.
            let end = lx.code[*start..]
                .iter()
                .position(|&b| b == b';')
                .map_or(lx.code.len(), |p| start + p);
            let mut stmt = String::new();
            for (s2, b2) in &lx.strings[idx..] {
                if *s2 > end {
                    break;
                }
                stmt.push_str(b2);
                stmt.push(' ');
            }
            let toks = sql_tokens(&stmt);
            if !is_existing_row_write(&first, &toks) || derived_only(&toks) {
                continue;
            }
            let item = heads
                .iter()
                .take_while(|(o, _)| o < start)
                .last()
                .map_or_else(|| "<module>".to_string(), |(_, n)| n.clone());
            sites.push(Site {
                file: rel.clone(),
                item,
                line: src[..*start].matches('\n').count() + 1,
                bumps: bumps(&toks),
                excerpt: first.join(" ").chars().take(90).collect(),
            });
        }
    }
    (sites, prod_code)
}

#[test]
fn every_existing_row_memories_write_bumps_version_or_is_allow_listed_4217() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = std::env::var("CENSUS_4217_ROOT").map_or(root, PathBuf::from);
    let (sites, prod_code) = census(&root);

    let bumping = sites.iter().filter(|s| s.bumps).count();
    assert!(
        sites.len() >= MIN_SITES && bumping >= MIN_BUMPING_SITES,
        "census is vacuous: {} sites, {bumping} bumping (floors {MIN_SITES}/{MIN_BUMPING_SITES})",
        sites.len()
    );
    for (file, item) in BUMPING_CANARIES {
        assert!(
            sites
                .iter()
                .any(|s| s.file == *file && s.item == *item && s.bumps),
            "canary {file}::{item} must be found as a version-bumping write"
        );
    }

    let mut groups: BTreeMap<(String, String), Vec<&Site>> = BTreeMap::new();
    for s in sites.iter().filter(|s| !s.bumps) {
        groups
            .entry((s.file.clone(), s.item.clone()))
            .or_default()
            .push(s);
    }
    let mut failures = Vec::new();
    for ((file, item), list) in &groups {
        match ALLOWED_NON_BUMPING
            .iter()
            .find(|(f, i, _, _)| f == file && i == item)
        {
            Some((_, _, n, _)) if *n == list.len() => {}
            Some((_, _, n, _)) => failures.push(format!(
                "{file}::{item}: {} non-bumping writes, allow-list says {n}",
                list.len()
            )),
            None => {
                for s in list {
                    failures.push(format!(
                        "{}:{} ({}) writes an existing memories row without bumping version: {}",
                        s.file, s.line, s.item, s.excerpt
                    ));
                }
            }
        }
    }
    for (name, expected) in ALLOWED_CONST_REFERENCES {
        let found: usize = prod_code.iter().map(|c| count_word(c, name)).sum();
        if found != *expected {
            failures.push(format!(
                "allow-listed const {name} has {found} production references, expected \
                 {expected}: a new caller must be reviewed (bump, or justify it here)"
            ));
        }
    }
    for (file, item, _, _) in ALLOWED_NON_BUMPING {
        if !groups.contains_key(&((*file).to_string(), (*item).to_string())) {
            failures.push(format!(
                "stale allow-list entry {file}::{item}: no non-bumping write found (delete it)"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "#4217 version-bump census ({} sites, {bumping} bumping):\n  {}\n\
         Bump `version` in the statement, or add a justified ALLOWED_NON_BUMPING entry.",
        sites.len(),
        failures.join("\n  ")
    );
}
