// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3990 — `docs/telemetry.md` promises that tracing events never carry a
//! memory's `title`, `content` or `metadata`. That promise was false: four
//! production `warn!` sites logged the memory title (consolidation rollback
//! conflict, the `why_trace` write-provenance warning, and the two
//! `sync_push` rejected-memory skips). Titles are tenant content, and the
//! stderr / file / syslog sinks are not cleared for tenant content.
//!
//! This is a source census over `src/**/*.rs`: no tracing / log macro
//! invocation may read `.title`, `.content` or `.metadata` as a value. Reads
//! that yield only a length or emptiness (`.title.len()`,
//! `.content.is_empty()`) are allowed, and so is `&x.metadata` passed as a
//! function argument (the attestation-downgrade bool). RED at 57014b067 on
//! the four sites above.

use std::fs;
use std::path::{Path, PathBuf};

/// The logging macros whose arguments reach a subscriber.
const MACROS: &[&str] = &[
    "trace!(", "debug!(", "info!(", "warn!(", "error!(", "event!(",
];

/// Payload fields of `models::Memory` that must never reach a log line.
const PAYLOAD_FIELDS: &[&str] = &["title", "content", "metadata"];

/// Longest macro body the scanner follows before it gives up, so an
/// unbalanced literal cannot swallow the rest of a file silently.
const MAX_BODY: usize = 8_000;

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Byte index one past the `)` that closes the macro whose `(` sits at
/// `open`. String literals are skipped so a `(` inside a message does not
/// unbalance the scan. `None` when no close is found within [`MAX_BODY`].
fn macro_end(src: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open;
    let limit = src.len().min(open + MAX_BODY);
    while i < limit {
        match src[i] {
            b'"' => {
                i += 1;
                while i < limit && src[i] != b'"' {
                    if src[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// True when `.field` at `at` (index of the dot) is a payload read rather
/// than a length / emptiness probe or a `&x.metadata` argument.
fn is_payload_read(body: &[u8], at: usize, field: &str) -> bool {
    let after = at + 1 + field.len();
    if body.get(after).copied().is_some_and(is_ident_byte) {
        return false; // `.title_hash`, `.content_len`, ...
    }
    let rest = &body[after..];
    if rest.starts_with(b".len()") || rest.starts_with(b".is_empty()") {
        return false;
    }
    if field == "metadata" {
        // Walk back over the receiver path (`existing`, `self.row`) to see
        // whether the whole place expression is borrowed as an argument.
        let mut j = at;
        while j > 0 && (is_ident_byte(body[j - 1]) || body[j - 1] == b'.') {
            j -= 1;
        }
        if j > 0 && body[j - 1] == b'&' {
            return false;
        }
    }
    true
}

fn violations_in(path: &Path, src: &str) -> Vec<String> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    for mac in MACROS {
        let mut from = 0;
        while let Some(rel) = src[from..].find(mac) {
            let start = from + rel;
            from = start + mac.len();
            if start > 0 && is_ident_byte(bytes[start - 1]) {
                continue; // `eprintln!(`-style neighbours, `my_warn!(`
            }
            let open = start + mac.len() - 1;
            let line = src[..start].matches('\n').count() + 1;
            let Some(end) = macro_end(bytes, open) else {
                out.push(format!("{}:{line}: unterminated {mac}", path.display()));
                continue;
            };
            let body = &bytes[open..end];
            for field in PAYLOAD_FIELDS {
                let needle = format!(".{field}");
                let text = &src[open..end];
                let mut k = 0;
                while let Some(r) = text[k..].find(&needle) {
                    let at = k + r;
                    k = at + needle.len();
                    if is_payload_read(body, at, field) {
                        out.push(format!(
                            "{}:{line}: `{mac}` reads `.{field}`: {}",
                            path.display(),
                            text.split_whitespace().collect::<Vec<_>>().join(" ")
                        ));
                    }
                }
            }
        }
    }
    out
}

#[test]
fn issue_3990_no_tracing_macro_logs_a_memory_payload_field() {
    let mut files = Vec::new();
    rust_files(Path::new("src"), &mut files);
    files.sort();
    assert!(
        files.len() > 100,
        "census found too few files: {}",
        files.len()
    );
    let mut bad = Vec::new();
    for f in &files {
        let src = fs::read_to_string(f).expect("read source");
        bad.extend(violations_in(f, &src));
    }
    assert!(
        bad.is_empty(),
        "#3990: tracing events must not carry memory title/content/metadata \
         (docs/telemetry.md §1, §4). Log the id and namespace instead:\n{}",
        bad.join("\n")
    );
}

/// The census must see a payload read it is meant to catch, and must pass
/// the shapes it is meant to allow; otherwise a green run proves nothing.
#[test]
fn issue_3990_census_is_not_vacuous() {
    let p = Path::new("fixture.rs");
    let caught = [
        "tracing::warn!(title = %m.title, \"x\");",
        "warn!(\"skip {} ({})\", mem.id, mem.title);",
        "tracing::info!(body = ?row.content);",
        "tracing::debug!(meta = ?mem.metadata, \"(paren in msg\");",
    ];
    for src in caught {
        assert_eq!(violations_in(p, src).len(), 1, "should flag: {src}");
    }
    let allowed = [
        "tracing::warn!(memory_id = %m.id, namespace = %m.namespace);",
        "tracing::info!(len = m.content.len(), empty = m.title.is_empty());",
        "tracing::warn!(downgrade = e.is_downgrade_from(&existing.metadata));",
        "tracing::warn!(h = %m.title_hash);",
        "eprintln!(\"{}\", m.title);",
    ];
    for src in allowed {
        assert!(violations_in(p, src).is_empty(), "should allow: {src}");
    }
}
