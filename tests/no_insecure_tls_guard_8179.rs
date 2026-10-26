// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8179 source guard: no certificate-verification bypass may be (re)introduced.
//!
//! `CodeQL` flags `danger_accept_invalid_certs`, but `CodeQL` is not a required
//! check, so a re-added bypass would otherwise survive every test. This guard
//! scans every compiled `.rs` file (`src/`, `tests/`, `benches/`, `examples/`,
//! `build.rs`, plus every `include!` / `#[path]` target resolved from them; a
//! missing target is a failure) with comments (line and block) stripped, and
//! fails with every `file:line` that
//!
//! - calls `danger_accept_invalid_certs` or `danger_accept_invalid_hostnames`;
//! - calls a rustls `danger()` / `dangerous()` config builder or
//!   `set_certificate_verifier`;
//! - implements `ServerCertVerifier` with a `verify_server_cert` that returns
//!   `Ok` unconditionally; or
//! - names an accept-any verifier type (`DangerousAnyServerVerifier`,
//!   `NoCertificateVerification`, and similar).
//!
//! The reqwest bypass has exactly ONE permitted site: `src/cli/sync.rs`, the
//! operator opt-in `--insecure-skip-server-verify`. It is pinned by file AND by
//! enclosing match arm: the matching code line must sit inside the
//! `SyncTlsMode::AcceptAny` arm (one of the 8 preceding non-blank CODE lines
//! opens it; comments are stripped first, so a comment naming the arm neither
//! satisfies nor shifts the window) and may occur only once in that file.
//!
//! The rustls patterns are legitimate in a small explicit allow-list (file plus
//! reason, [`RUSTLS_ALLOW`]); every row must name a file that exists, so a stale
//! row fails the guard. Tests use the pinned-root helper in `tests/common/tls.rs`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const BYPASS_CALLS: [&str; 2] = [
    "danger_accept_invalid_certs",
    "danger_accept_invalid_hostnames",
];
/// The single permitted production file (`--insecure-skip-server-verify`).
const PERMITTED_FILE: &str = "src/cli/sync.rs";
/// The match arm that must enclose the permitted call.
const PERMITTED_ARM: &str = "SyncTlsMode::AcceptAny";
/// How many preceding non-blank code lines may separate the arm from the call.
const ARM_LOOKBACK_LINES: usize = 8;
/// Directories whose `.rs` files are compiled (recursively).
const SCANNED_DIRS: [&str; 4] = ["src", "tests", "benches", "examples"];
/// Single compiled files at the crate root.
const SCANNED_FILES: [&str; 1] = ["build.rs"];
/// This guard holds the patterns as fixtures, so it does not scan itself.
const GUARD_FILE: &str = "tests/no_insecure_tls_guard_8179.rs";

/// Method names that open a rustls dangerous-configuration builder.
const DANGER_CALLS: [&str; 3] = ["danger", "dangerous", "set_certificate_verifier"];
/// Identifier fragments that name an accept-any verifier type.
const VERIFIER_TYPE_FRAGMENTS: [&str; 6] = [
    "DangerousAny",
    "NoCertificateVerification",
    "NoServerVerifier",
    "AnyServerVerifier",
    "InsecureVerifier",
    "SkipServerVerif",
];
/// Control-flow tokens whose presence means a verifier body can reject.
const CONTROL_TOKENS: [&str; 8] = [
    "Err", "?", "if ", "match ", "else", "while ", "for ", "loop",
];

/// One allow-list row: a file where the rustls patterns are legitimate.
struct AllowRow {
    file: &'static str,
    reason: &'static str,
}

/// Files allowed to use the rustls verifier-override patterns.
const RUSTLS_ALLOW: [AllowRow; 2] = [
    AllowRow {
        file: "src/tls.rs",
        reason: "defines the fingerprint-pinning verifier builder and the accept-any \
                 DangerousAnyServerVerifier (no production caller) with their unit tests",
    },
    AllowRow {
        file: "tests/mtls_nodelay_acceptor.rs",
        reason: "test-only acceptor clients that drive the TLS acceptor with the accept-any \
                 verifier; no production path",
    },
];

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Copy a (possibly raw) string literal starting at `i`, returning the index
/// after it.
fn copy_string(c: &[char], mut i: usize, out: &mut String, blank: bool) -> usize {
    let push = |out: &mut String, ch: char| {
        if blank && ch != '\n' {
            // same UTF-8 width, so byte offsets match the unblanked text
            out.extend(std::iter::repeat_n(' ', ch.len_utf8()));
        } else {
            out.push(ch);
        }
    };
    let mut hashes = 0;
    let raw = c[i] == 'r';
    if raw {
        out.push('r');
        i += 1;
        while c.get(i) == Some(&'#') {
            hashes += 1;
            out.push('#');
            i += 1;
        }
    }
    // c[i] is the opening quote.
    out.push('"');
    i += 1;
    while i < c.len() {
        let ch = c[i];
        i += 1;
        if !raw && ch == '\\' {
            push(out, ch);
            if let Some(&esc) = c.get(i) {
                push(out, esc);
                i += 1;
            }
        } else if ch == '"' {
            out.push(ch);
            let closes = (0..hashes).all(|k| c.get(i + k) == Some(&'#'));
            if closes {
                for _ in 0..hashes {
                    out.push('#');
                }
                return i + hashes;
            }
        } else {
            push(out, ch);
        }
    }
    i
}

/// Does a raw string literal (`r"`, `r#"`) start at `i`?
fn raw_string_at(c: &[char], i: usize) -> bool {
    if c[i] != 'r' {
        return false;
    }
    if i > 0 && (c[i - 1].is_alphanumeric() || c[i - 1] == '_') && c[i - 1] != 'b' {
        return false;
    }
    let mut k = i + 1;
    while c.get(k) == Some(&'#') {
        k += 1;
    }
    c.get(k) == Some(&'"')
}

/// Replace every line comment (`//`, `///`, `//!`) and block comment (nested)
/// with blanks, keeping newlines so line numbers survive. String and char
/// literals are copied verbatim, so `"https://x"` is not a comment.
fn strip_comments(src: &str) -> String {
    lex(src, false)
}

/// Like [`strip_comments`] but with string-literal CONTENT blanked (delimiters
/// and byte offsets kept), so a marker named inside a string is not code.
fn mask_strings(src: &str) -> String {
    lex(src, true)
}

fn lex(src: &str, blank: bool) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < c.len() {
        let next = c.get(i + 1).copied();
        match c[i] {
            '/' if next == Some('/') => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '/' if next == Some('*') => {
                let mut depth = 0usize;
                while i < c.len() {
                    if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                    } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                        depth = depth.saturating_sub(1);
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        if c[i] == '\n' {
                            out.push('\n');
                        }
                        i += 1;
                    }
                }
                out.push(' ');
            }
            '"' => i = copy_string(&c, i, &mut out, blank),
            'r' if raw_string_at(&c, i) => i = copy_string(&c, i, &mut out, blank),
            '\'' => {
                if next == Some('\\') {
                    // escaped char literal: copy through the closing quote
                    out.push('\'');
                    i += 1;
                    // the backslash and the escaped char, then any `u{..}` / `x41` tail
                    out.extend(c.iter().skip(i).take(2));
                    i = (i + 2).min(c.len());
                    while i < c.len() && c[i] != '\'' {
                        out.push(c[i]);
                        i += 1;
                    }
                    if i < c.len() {
                        out.push('\'');
                        i += 1;
                    }
                } else if c.get(i + 2) == Some(&'\'') {
                    out.extend(&c[i..i + 3]);
                    i += 3;
                } else {
                    // a lifetime
                    out.push('\'');
                    i += 1;
                }
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    out
}

fn is_ident_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

/// Does `line` call `name` (preceded by a non-identifier char, followed by an
/// optional `(`)? `needs_paren` demands the `(`.
fn has_call(line: &str, name: &str, needs_paren: bool) -> bool {
    let mut from = 0;
    while let Some(pos) = line[from..].find(name) {
        let start = from + pos;
        let end = start + name.len();
        let before_ok = line[..start]
            .chars()
            .next_back()
            .is_none_or(|b| !is_ident_char(b));
        let rest = line[end..].trim_start();
        let after_ok = if needs_paren {
            rest.starts_with('(')
        } else {
            !rest.chars().next().is_some_and(is_ident_char)
        };
        if before_ok && after_ok {
            return true;
        }
        from = end;
    }
    false
}

fn has_bypass(line: &str) -> bool {
    BYPASS_CALLS.iter().any(|c| line.contains(c))
}

/// Does any identifier on `line` look like an accept-any verifier type?
fn names_accept_any_verifier(line: &str) -> bool {
    line.split(|ch: char| !is_ident_char(ch))
        .any(|ident| VERIFIER_TYPE_FRAGMENTS.iter().any(|f| ident.contains(f)))
}

/// Index of the `}` matching the `{` at `open` in `code` (byte offsets).
fn matching_brace(code: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (off, ch) in code[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + off);
                }
            }
            _ => {}
        }
    }
    None
}

fn line_of(code: &str, byte: usize) -> usize {
    code[..byte].matches('\n').count() + 1
}

/// `file:line` strings for every `ServerCertVerifier` impl in `code` whose
/// `verify_server_cert` returns `Ok` with no way to reject.
fn unconditional_verifier_lines(code: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = code[from..].find("ServerCertVerifier") {
        let at = from + pos;
        from = at + "ServerCertVerifier".len();
        let header_start = code[..at].rfind('\n').map_or(0, |n| n + 1);
        let tail = code[from..].trim_start();
        if !code[header_start..at].contains("impl") || !tail.starts_with("for") {
            continue;
        }
        let Some(open) = code[from..].find('{').map(|o| from + o) else {
            continue;
        };
        let Some(close) = matching_brace(code, open) else {
            continue;
        };
        let body = &code[open..close];
        let Some(fpos) = body.find("fn verify_server_cert") else {
            continue;
        };
        let Some(fopen) = body[fpos..].find('{').map(|o| open + fpos + o) else {
            continue;
        };
        let fclose = matching_brace(code, fopen).unwrap_or(close);
        let fbody = &code[fopen + 1..fclose];
        if fbody.contains("Ok(") && !CONTROL_TOKENS.iter().any(|t| fbody.contains(t)) {
            out.push(line_of(code, open + fpos));
        }
    }
    out
}

fn rustls_allowed(rel: &str) -> bool {
    RUSTLS_ALLOW.iter().any(|r| r.file == rel)
}

/// Offending `file:line` strings for one file's text; `rel` is the
/// repo-relative path with `/` separators.
fn violations_in(rel: &str, text: &str) -> Vec<String> {
    let code = strip_comments(text);
    let lines: Vec<&str> = code.lines().collect();
    let mut out = Vec::new();
    let hits: Vec<usize> = (0..lines.len()).filter(|&i| has_bypass(lines[i])).collect();
    for (n, &i) in hits.iter().enumerate() {
        let in_arm = rel == PERMITTED_FILE
            && n == 0
            && lines[..i]
                .iter()
                .rev()
                .filter(|l| !l.trim().is_empty())
                .take(ARM_LOOKBACK_LINES)
                .any(|l| l.contains(PERMITTED_ARM) && l.contains("=>"));
        if !in_arm {
            out.push(format!(
                "{rel}:{}: reqwest certificate-verification bypass",
                i + 1
            ));
        }
    }
    if !rustls_allowed(rel) {
        for (i, line) in lines.iter().enumerate() {
            let danger = DANGER_CALLS
                .iter()
                .any(|n| has_call(line, n, *n != "set_certificate_verifier"));
            if danger {
                out.push(format!("{rel}:{}: rustls verifier override", i + 1));
            }
            if names_accept_any_verifier(line) {
                out.push(format!("{rel}:{}: accept-any verifier type", i + 1));
            }
        }
        for line in unconditional_verifier_lines(&code) {
            out.push(format!(
                "{rel}:{line}: ServerCertVerifier::verify_server_cert returns Ok unconditionally"
            ));
        }
    }
    out
}

/// The quoted target following `marker` (`include!(` or `#[path =`), if the
/// text after the marker is a string literal.
fn literal_after(code: &str, marker_end: usize, open: Option<char>) -> Option<String> {
    let mut rest = code[marker_end..].trim_start();
    if let Some(o) = open {
        rest = rest.strip_prefix(o)?.trim_start();
    }
    let rest = rest.strip_prefix('"')?;
    rest.find('"').map(|e| rest[..e].to_string())
}

/// Every `include!("..")` and `#[path = ".."]` target in comment-stripped
/// `code` (markers are located in `masked`, where string contents are blank);
/// `Err(line)` for one whose argument is not a plain literal.
fn include_targets(code: &str, masked: &str) -> Vec<Result<String, usize>> {
    let mut out = Vec::new();
    for (marker, open, eq) in [("include!", Some('('), false), ("#[path", None, true)] {
        let mut from = 0;
        while let Some(pos) = masked[from..].find(marker) {
            let at = from + pos;
            from = at + marker.len();
            let mut end = from;
            if eq {
                let after = code[end..].trim_start();
                let Some(stripped) = after.strip_prefix('=') else {
                    continue;
                };
                end = code.len() - stripped.len();
            }
            out.push(literal_after(code, end, open).ok_or_else(|| line_of(code, at)));
        }
    }
    out
}

/// Scan every compiled `.rs` under `root` (and each include target).
fn scan_tree(root: &Path) -> Vec<String> {
    let root_c = root.canonicalize().expect("canonical root");
    let mut queue: Vec<PathBuf> = Vec::new();
    for d in SCANNED_DIRS {
        if root.join(d).is_dir() {
            collect_rs(&root.join(d), &mut queue);
        }
    }
    for f in SCANNED_FILES {
        if root.join(f).is_file() {
            queue.push(root.join(f));
        }
    }
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    let mut out = Vec::new();
    while let Some(p) = queue.pop() {
        let Ok(canon) = p.canonicalize() else {
            out.push(format!("{}: unreadable scan target", p.display()));
            continue;
        };
        if !seen.insert(canon.clone()) {
            continue;
        }
        let rel = canon
            .strip_prefix(&root_c)
            .unwrap_or(&canon)
            .to_string_lossy()
            .replace('\\', "/");
        if rel == GUARD_FILE {
            continue;
        }
        let text = match std::fs::read_to_string(&canon) {
            Ok(t) => t,
            Err(e) => {
                out.push(format!("{rel}: unreadable: {e}"));
                continue;
            }
        };
        out.extend(violations_in(&rel, &text));
        let dir = canon.parent().unwrap_or(&root_c).to_path_buf();
        for target in include_targets(&strip_comments(&text), &mask_strings(&text)) {
            match target {
                Ok(t) if dir.join(&t).is_file() => queue.push(dir.join(&t)),
                Ok(t) => out.push(format!("{rel}: include target missing: {t}")),
                Err(line) => out.push(format!(
                    "{rel}:{line}: include!/#[path] argument is not a string literal \
                     (cannot resolve, fail closed)"
                )),
            }
        }
    }
    out.sort();
    out
}

/// Stale or empty allow-list rows (each must name an existing file and a reason).
fn allow_list_problems(root: &Path, rows: &[AllowRow]) -> Vec<String> {
    let mut out = Vec::new();
    for r in rows {
        if !root.join(r.file).is_file() {
            out.push(format!(
                "allow-list row {}: file does not exist (stale row)",
                r.file
            ));
        }
        if r.reason.trim().is_empty() {
            out.push(format!("allow-list row {}: reason is empty", r.file));
        }
    }
    out
}

/// A scratch crate tree under `CARGO_TARGET_TMPDIR` (never the system temp).
fn fixture_tree(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("guard-8179-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("fixture tempdir");
    for (rel, body) in files {
        let path = dir.path().join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir fixture");
        std::fs::write(&path, body).expect("write fixture");
    }
    dir
}

const ARM_FIXTURE: &str = "match m {\n    SyncTlsMode::AcceptAny => {\n        b.danger_accept_invalid_certs(true);\n    }\n}\n";
const ACCEPT_ANY_VERIFIER: &str = "struct Trusting;\nimpl rustls::client::danger::ServerCertVerifier for Trusting {\n    fn verify_server_cert(&self) -> Result<Verified, Error> {\n        Ok(Verified::assertion())\n    }\n}\n";

#[test]
fn no_certificate_verification_bypass_in_compiled_rs_8179() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut bad = allow_list_problems(root, &RUSTLS_ALLOW);
    bad.extend(scan_tree(root));
    assert!(
        bad.is_empty(),
        "certificate-verification bypass found (use the pinned-root helper in tests/common/tls.rs; \
         the only permitted reqwest site is the {PERMITTED_ARM} arm for --insecure-skip-server-verify in \
         {PERMITTED_FILE}; rustls overrides only in the RUSTLS_ALLOW files):\n{}",
        bad.join("\n")
    );
}

#[test]
fn guard_pins_the_single_sync_arm_8179() {
    assert!(violations_in(PERMITTED_FILE, ARM_FIXTURE).is_empty());
    // moved out of the arm
    let moved = "fn f() {\n    b.danger_accept_invalid_certs(true);\n}\n";
    let got = violations_in(PERMITTED_FILE, moved);
    assert_eq!(got.len(), 1);
    assert!(got[0].starts_with(&format!("{PERMITTED_FILE}:2")));
    // a second occurrence in the permitted file
    let twice = format!("{ARM_FIXTURE}{ARM_FIXTURE}");
    assert_eq!(violations_in(PERMITTED_FILE, &twice).len(), 1);
    // the arm text in any other file does not excuse it
    assert_eq!(violations_in("src/other.rs", ARM_FIXTURE).len(), 1);
    // comments are ignored
    assert!(
        violations_in(
            "tests/x.rs",
            "// danger_accept_invalid_certs(true)\n//! danger_accept_invalid_hostnames\n/* danger_accept_invalid_certs */\n"
        )
        .is_empty()
    );
}

/// Code r2 (6388326855): a comment naming the arm must not satisfy the pin or
/// shift the window, so the real arm's insecure body is still inspected.
#[test]
fn comment_naming_the_arm_does_not_excuse_or_hide_8179() {
    let decoy_line = "// SyncTlsMode::AcceptAny is the opt-in\nfn helper(b: B) {\n    b.danger_accept_invalid_certs(true);\n}\n";
    let got = violations_in(PERMITTED_FILE, decoy_line);
    assert_eq!(got.len(), 1, "decoy line comment excused the call: {got:?}");
    let decoy_block = "/* SyncTlsMode::AcceptAny => */\nfn helper(b: B) {\n    b.danger_accept_invalid_certs(true);\n}\n";
    assert_eq!(violations_in(PERMITTED_FILE, decoy_block).len(), 1);
    // a comment above the REAL arm whose body is insecure: the body is inspected
    let real = "// SyncTlsMode::AcceptAny: opt-in\nmatch m {\n    SyncTlsMode::AcceptAny => {\n        b.danger_accept_invalid_certs(true);\n        cfg.dangerous().with_custom_certificate_verifier(v);\n    }\n}\n";
    let got = violations_in(PERMITTED_FILE, real);
    assert!(
        got.iter().any(|v| v.contains(":5:")),
        "insecure arm body not inspected: {got:?}"
    );
}

/// Security r2 (c): comment lines inside the located arm are not counted
/// against the look-back window.
#[test]
fn comment_lines_inside_the_arm_are_not_counted_8179() {
    let mut text = String::from("match m {\n    SyncTlsMode::AcceptAny => {\n");
    text.push_str(&"        // rationale line\n".repeat(ARM_LOOKBACK_LINES + 4));
    text.push_str("        /* block\n           comment */\n");
    text.push_str("        b.danger_accept_invalid_certs(true);\n    }\n}\n");
    assert!(
        violations_in(PERMITTED_FILE, &text).is_empty(),
        "comment lines shifted the arm window"
    );
}

/// Security r2 (a): the rustls accept-any shapes.
#[test]
fn rustls_accept_any_shapes_are_flagged_8179() {
    let named = "let v = Arc::new(tls::DangerousAnyServerVerifier);\n";
    assert_eq!(violations_in("src/other.rs", named).len(), 1);
    let unconditional = violations_in("src/other.rs", ACCEPT_ANY_VERIFIER);
    assert!(
        unconditional
            .iter()
            .any(|v| v.contains("returns Ok unconditionally")),
        "an innocuously named accept-any verifier slipped through: {unconditional:?}"
    );
    let builder = "let c = rustls::ClientConfig::builder()\n    .dangerous()\n    .with_custom_certificate_verifier(v)\n    .with_no_client_auth();\n";
    assert!(!violations_in("src/other.rs", builder).is_empty());
    let setter = "cfg.dangerous().set_certificate_verifier(v);\n";
    assert!(!violations_in("tests/x.rs", setter).is_empty());
    let danger = "let b = ClientBuilder::new().danger();\n";
    assert!(!violations_in("tests/x.rs", danger).is_empty());
    // a verifier that can reject is fine, and `dangerous_op()` is not the builder
    let strict = "impl ServerCertVerifier for Pin {\n    fn verify_server_cert(&self) -> R {\n        if ok { Ok(V) } else { Err(E) }\n    }\n}\nfn is_dangerous(x: u8) {}\nlet z = dangerous_op();\n";
    assert!(violations_in("src/other.rs", strict).is_empty());
    // the allow-listed files may use the rustls shapes, but not the reqwest bypass
    assert!(violations_in("tests/mtls_nodelay_acceptor.rs", ACCEPT_ANY_VERIFIER).is_empty());
    assert!(violations_in("tests/mtls_nodelay_acceptor.rs", named).is_empty());
    assert_eq!(
        violations_in(
            "tests/mtls_nodelay_acceptor.rs",
            "b.danger_accept_invalid_certs(true);\n"
        )
        .len(),
        1
    );
}

/// Security r2 (b): every compiled `.rs`, not only `src/` and `tests/`.
#[test]
fn examples_benches_and_build_rs_are_scanned_8179() {
    for rel in ["examples/demo.rs", "benches/b.rs", "build.rs"] {
        let tree = fixture_tree(&[(rel, ACCEPT_ANY_VERIFIER)]);
        let bad = scan_tree(tree.path());
        assert!(
            bad.iter().any(|v| v.starts_with(rel)),
            "{rel} with an accept-any verifier passed: {bad:?}"
        );
    }
}

#[test]
fn include_targets_are_followed_and_must_exist_8179() {
    let tree = fixture_tree(&[
        ("src/lib.rs", "include!(\"../extra/hidden.rs\");\n"),
        (
            "extra/hidden.rs",
            "static V: DangerousAnyServerVerifier = X;\n",
        ),
    ]);
    let bad = scan_tree(tree.path());
    assert!(
        bad.iter().any(|v| v.starts_with("extra/hidden.rs:1")),
        "include! target not scanned: {bad:?}"
    );
    let missing = fixture_tree(&[("src/lib.rs", "include!(\"../extra/nope.rs\");\n")]);
    let bad = scan_tree(missing.path());
    assert!(
        bad.iter().any(|v| v.contains("include target missing")),
        "missing include! target passed: {bad:?}"
    );
    let path_attr = fixture_tree(&[
        ("benches/b.rs", "#[path = \"../benchmarks/m.rs\"]\nmod m;\n"),
        ("benchmarks/m.rs", "cfg.dangerous();\n"),
    ]);
    let bad = scan_tree(path_attr.path());
    assert!(
        bad.iter().any(|v| v.starts_with("benchmarks/m.rs:1")),
        "{bad:?}"
    );
    // a marker named inside a string literal is not an include
    let in_string = fixture_tree(&[(
        "src/lib.rs",
        "const S: &str = \"include!(\\\"nope.rs\\\") and #[path = \\\"nope.rs\\\"]\";\n",
    )]);
    assert!(scan_tree(in_string.path()).is_empty());
    // a clean include passes
    let clean = fixture_tree(&[
        ("src/lib.rs", "include!(\"gen.rs\");\n"),
        ("src/gen.rs", "fn ok() {}\n"),
    ]);
    assert!(scan_tree(clean.path()).is_empty());
}

#[test]
fn stale_allow_list_row_fails_8179() {
    let tree = fixture_tree(&[("src/real.rs", "fn f() {}\n")]);
    let rows = [
        AllowRow {
            file: "src/real.rs",
            reason: "exists",
        },
        AllowRow {
            file: "src/gone.rs",
            reason: "file was deleted",
        },
    ];
    let bad = allow_list_problems(tree.path(), &rows);
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(bad[0].contains("src/gone.rs"));
    // the real allow-list names only files that exist
    assert!(allow_list_problems(Path::new(env!("CARGO_MANIFEST_DIR")), &RUSTLS_ALLOW).is_empty());
}
