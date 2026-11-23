//! #10037 (#9996) — source ratchet over the federation PULL READ.
//!
//! Every byte the `/sync/since` serve path hands a peer comes from one store
//! read: `memories_updated_since[_counted]` (SQLite free functions) or
//! `list_memories_updated_since[_counted]` (the `MemoryStore` trait). A new
//! caller of that read is a new way to hand federation rows to a peer, and it
//! must go through the outbound-scope funnel
//! (`federation::outbound_scope_serve::admit_rows` on the pull side,
//! `outbound_scope::admit_recorded` on the push side) or be a store / test
//! site.
//!
//! The ratchet is an ALLOWLIST: it walks the WHOLE repository tree, lexes
//! every `.rs` file (comments, string and char literals blanked, so a
//! mention in prose or in a string is not a call and a call after a string
//! holding `//` is not hidden), and counts every identifier that contains
//! [`READ_TOKEN`]. The map of (file, count) must equal [`PINNED_READ_SITES`]
//! exactly, so each of these is red:
//! - a new caller in a file not on the list (another file, any directory);
//! - a new caller in a listed file (a new handler next to the old one);
//! - an alias (`use … memories_updated_since as pull;`): the `use` line names
//!   the token, so the file shows up;
//! - a function-pointer table (`&[db::memories_updated_since]`), a const or
//!   static holding it, a match arm calling it: each names the token;
//! - a new variant of the read (`memories_updated_since_paged`): it contains
//!   the token.
//!
//! The serve file is also pinned to one `admit_rows(` per read call, so a
//! second read without a second funnel call is red.
//!
//! Left out of the walk, each with its reason ([`SKIPPED_DIRS`]): build output,
//! VCS metadata, lane scratch, the CodeGraph index and the vendored
//! third-party crates (they do not depend on this crate, so they cannot call
//! it). Files that are not `.rs` are not compiled Rust and cannot call the
//! read. Known limit: an identifier spliced together by a token-pasting macro
//! (`paste!`) carries no whole token; the behavioural funnel tests in
//! `tests/federation_outbound_scope_9996.rs` (mod `serve`) cover that path.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

/// The identifier fragment every pull-read entry point carries.
const READ_TOKEN: &str = "memories_updated_since";

/// The outbound funnel call the serve file must make once per read.
const SERVE_FUNNEL_CALL: &str = "admit_rows(";

/// The one HTTP serve file of the pull path.
const SERVE_FILE: &str = "src/handlers/federation_sync_since.rs";

/// Directories the walk does not enter, each with its reason.
const SKIPPED_DIRS: &[(&str, &str)] = &[
    (".git", "VCS metadata, not source"),
    ("target", "cargo build output, regenerated"),
    (".local-runs", "gitignored lane scratch, never compiled"),
    (".codegraph", "the CodeGraph index, not source"),
    (
        "vendor",
        "vendored third-party crates; none depends on ai-memory",
    ),
];

/// Every file that names the pull read, with its exact count of identifier
/// occurrences outside comments and literals, and why the site is allowed.
const PINNED_READ_SITES: &[(&str, usize, &str)] = &[
    // --- serve (funnelled through admit_rows) ---
    (
        SERVE_FILE,
        2,
        "the /sync/since serve path; PG and SQLite reads, each admitted by admit_rows",
    ),
    // --- push (funnelled through admit_recorded) ---
    (
        "src/federation/sync_daemon_push.rs",
        1,
        "sync-daemon push batch; the body is admitted by outbound_scope::admit_recorded",
    ),
    // --- store definitions ---
    (
        "src/storage/mod.rs",
        14,
        "the SQLite read definitions and their unit tests",
    ),
    (
        "src/store/mod.rs",
        5,
        "the MemoryStore trait methods and their default arms",
    ),
    ("src/store/sqlite.rs", 6, "the SQLite adapter delegates"),
    ("src/store/postgres.rs", 3, "the Postgres adapter"),
    // --- tests (each calls the read to check what the store returns) ---
    (
        "tests/cov_postgres_core.rs",
        2,
        "test: Postgres adapter coverage",
    ),
    (
        "tests/cov_store_default_arms_3521.rs",
        1,
        "test: trait default-arm coverage",
    ),
    (
        "tests/encryption_at_rest.rs",
        1,
        "test: the send read decrypts content",
    ),
    (
        "tests/federation_catchup_column_fidelity_2384.rs",
        3,
        "test: catch-up column fidelity of the read",
    ),
    (
        "tests/store_parity_gaps.rs",
        2,
        "test: SQLite/Postgres parity of the read",
    ),
];

/// Lex `src` into a copy with every comment, string literal and char literal
/// blanked to spaces (newlines kept), so only code identifiers remain.
fn blank_non_code(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let keep_nl = |c: u8| if c == b'\n' { b'\n' } else { b' ' };
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') {
            while i < b.len() && b[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else if c == b'/' && next == Some(b'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(keep_nl(b[i]));
                    i += 1;
                }
            }
        } else if c == b'r'
            && (next == Some(b'"') || next == Some(b'#'))
            && (i == 0 || !is_ident_byte(b[i - 1]))
        {
            // Raw string r"…" / r#"…"#; a bare `r#ident` is a raw identifier.
            let mut j = i + 1;
            let mut hashes = 0usize;
            while b.get(j) == Some(&b'#') {
                hashes += 1;
                j += 1;
            }
            if b.get(j) != Some(&b'"') {
                out.push(c);
                i += 1;
                continue;
            }
            j += 1;
            while j < b.len() {
                let closes = b[j] == b'"'
                    && b.len() >= j + 1 + hashes
                    && b[j + 1..j + 1 + hashes].iter().all(|&h| h == b'#');
                j += if closes { 1 + hashes } else { 1 };
                if closes {
                    break;
                }
            }
            for &x in &b[i..j.min(b.len())] {
                out.push(keep_nl(x));
            }
            i = j.min(b.len());
        } else if c == b'"' {
            out.push(b' ');
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' && i + 1 < b.len() {
                    out.push(b' ');
                    i += 1;
                }
                out.push(keep_nl(b[i]));
                i += 1;
            }
            if i < b.len() {
                out.push(b' ');
                i += 1;
            }
        } else if c == b'\'' {
            // A char literal ('x', '\n', '\u{..}') or a lifetime ('a).
            let close = if next == Some(b'\\') {
                b[i + 2..]
                    .iter()
                    .position(|&x| x == b'\'')
                    .map(|p| i + 2 + p)
            } else {
                let ch_len = src[i + 1..].chars().next().map_or(0, char::len_utf8);
                (b.get(i + 1 + ch_len) == Some(&b'\'')).then_some(i + 1 + ch_len)
            };
            match close {
                Some(end) => {
                    for &x in &b[i..=end] {
                        out.push(keep_nl(x));
                    }
                    i = end + 1;
                }
                None => {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    // Only ASCII bytes were replaced by ASCII; multibyte runs are copied whole
    // or blanked whole, so the result is valid UTF-8 for valid input.
    String::from_utf8_lossy(&out).into_owned()
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Count the identifiers of `code` that contain [`READ_TOKEN`].
fn count_read_idents(code: &str) -> usize {
    code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|ident| ident.contains(READ_TOKEN))
        .count()
}

fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, usize>, problems: &mut Vec<String>) {
    let mut entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(Result::ok).collect(),
        Err(e) => {
            problems.push(format!("cannot read dir {}: {e}", dir.display()));
            return;
        }
    };
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            problems.push(format!("cannot stat {}", path.display()));
            continue;
        };
        if meta.is_dir() {
            if SKIPPED_DIRS.iter().any(|(d, _)| *d == name) {
                continue;
            }
            walk(&path, root, out, problems);
            continue;
        }
        if !name.ends_with(".rs") {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        if meta.file_type().is_symlink() {
            problems.push(format!(
                "{rel}: a symlinked .rs file cannot be scanned (fail closed)"
            ));
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let n = count_read_idents(&blank_non_code(&text));
                if n > 0 {
                    out.insert(rel, n);
                }
            }
            Err(e) => problems.push(format!("{rel}: unreadable ({e}) (fail closed)")),
        }
    }
}

fn scan_tree() -> (BTreeMap<String, usize>, Vec<String>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = BTreeMap::new();
    let mut problems = Vec::new();
    walk(root, root, &mut out, &mut problems);
    (out, problems)
}

#[test]
fn pull_read_sites_match_the_allowlist_10037() {
    let (found, problems) = scan_tree();
    assert!(problems.is_empty(), "scan problems: {problems:#?}");
    let pinned: BTreeMap<String, usize> = PINNED_READ_SITES
        .iter()
        .map(|(f, n, _)| ((*f).to_string(), *n))
        .collect();
    assert_eq!(
        found, pinned,
        "a pull-read site was added, removed or moved. Route a new one through \
         admit_rows / admit_recorded and pin it here with its reason."
    );
}

#[test]
fn the_serve_file_admits_every_read_10037() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let code = blank_non_code(&std::fs::read_to_string(root.join(SERVE_FILE)).expect("serve file"));
    let reads = count_read_idents(&code);
    let admits = code.matches(SERVE_FUNNEL_CALL).count();
    assert!(
        reads > 0,
        "the serve file no longer reads: re-pin the ratchet"
    );
    assert_eq!(
        admits, reads,
        "every pull read in {SERVE_FILE} goes through {SERVE_FUNNEL_CALL}"
    );
}

/// Mutation proof: each form the construct can take is counted; prose and
/// string mentions are not.
#[test]
fn every_form_of_the_read_is_counted_10037() {
    // (form, source, expected count)
    let rows: &[(&str, &str, usize)] = &[
        (
            "direct call",
            "fn h(c: &C) { db::memories_updated_since(c, None, 1); }",
            1,
        ),
        (
            "trait method",
            "async fn h(s: &S) { s.list_memories_updated_since_counted(None, 1).await; }",
            1,
        ),
        (
            "alias import",
            "use crate::storage::memories_updated_since as pull;\nfn h() { pull(); }",
            1,
        ),
        (
            "fn-pointer table",
            "const READS: &[fn()] = &[db::memories_updated_since];",
            1,
        ),
        (
            "static",
            "static R: fn() = crate::storage::memories_updated_since_counted;",
            1,
        ),
        (
            "match arm",
            "match k { K::A => db::memories_updated_since(c, s, l), _ => x }",
            1,
        ),
        ("new variant", "fn memories_updated_since_paged() {}", 1),
        (
            "call after a // string",
            "let u = \"http://x\"; db::memories_updated_since(c, None, 1);",
            1,
        ),
        (
            "call after a char quote",
            "let q = '\"'; db::memories_updated_since(c, None, 1);",
            1,
        ),
        (
            "call after a lifetime",
            "fn f<'a>(c: &'a C) { db::memories_updated_since(c, None, 1); }",
            1,
        ),
        ("line comment", "// db::memories_updated_since(c)", 0),
        (
            "doc comment",
            "/// see memories_updated_since\nfn x() {}",
            0,
        ),
        (
            "block comment",
            "/* memories_updated_since /* nested */ */ fn x() {}",
            0,
        ),
        ("string literal", "let s = \"memories_updated_since\";", 0),
        (
            "raw string",
            "let s = r#\"memories_updated_since \" still\"#;",
            0,
        ),
        (
            "escaped quote string",
            "let s = \"a\\\"memories_updated_since\";",
            0,
        ),
    ];
    for (form, src, want) in rows {
        assert_eq!(
            count_read_idents(&blank_non_code(src)),
            *want,
            "form `{form}`: {src}"
        );
    }
}

/// The lexer is linear: a 200K+ input scans well inside the ceiling.
#[test]
fn the_scan_is_bounded_on_large_input_10037() {
    let mut src = String::new();
    while src.len() < 200_000 {
        src.push_str(
            "let s = \"//\"; /* x */ fn f<'a>() { db::memories_updated_since(c); } // y\n",
        );
    }
    let lines = src.lines().count();
    let t = Instant::now();
    let n = count_read_idents(&blank_non_code(&src));
    assert_eq!(n, lines);
    assert!(
        t.elapsed().as_millis() < 2_000,
        "scan took {:?}",
        t.elapsed()
    );
}
