// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10074 S-4 (`3-agent vote (71472661) V1-SIGNED-EVENTS-FALLBACK`) — source
//! ratchet: no daemon signature can be produced without a `DaemonDomain`.
//!
//! The construct this holds is "the daemon key reached outside the typed
//! signer `src/governance/daemon_signer.rs`". It is an ALLOWLIST of permitted
//! sites over every tracked file of the repository (`git ls-files`), never a
//! list of forbidden spellings:
//!
//! - **R1** the private key static `DAEMON_AUDIT_KEY` is named only in the
//!   typed signer (and in this ratchet, which names it to forbid it);
//! - **R2** every `static` / `const` / `thread_local!` item whose type holds a
//!   `SigningKey` (directly, through a container, a fully qualified path, a
//!   `use ... as` alias or a `type` alias) is an allowlisted site;
//! - **R3** the daemon key loaders (`load_daemon_signing_key`,
//!   `ensure_daemon_signing_key`) are named in Rust code only at allowlisted
//!   files, each with its reason; an alias `use ... as` names the loader too,
//!   so it is caught;
//! - **R4** the removed bytes-only signer symbol `try_sign_audit_payload` is
//!   named nowhere outside the listed historical records, and the typed signer
//!   makes exactly one `.sign(` call, over `preimage(domain, body)`.
//!
//! A stale allowlist entry (an allowed site that no longer exists) fails too,
//! so the list stays the exact boundary spec. Comments (`//`, `/* */`) are
//! stripped from `.rs` files by a literal-aware lexer before matching; every
//! other file is matched raw for R1 and R4. Left-out paths, each with its
//! reason: files that are not valid UTF-8 (binary fixtures, which cannot hold
//! Rust code), counted and reported; and, for R2 and R3 only, every non-`.rs`
//! file (only Rust code can declare a key static or call a loader; prose that
//! names a loader calls nothing).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

#[path = "common/home_sandbox.rs"]
mod home_sandbox;

/// #10007 — the `git` child this ratchet spawns runs under the sandbox HOME
/// (no global git config of the real HOME is read), and the process itself
/// resolves no writable path under the real HOME.
#[test]
fn test_process_resolves_no_path_under_the_real_home_10007() {
    let _ = home_sandbox::real_home();
    let sandbox = home_sandbox::install();
    home_sandbox::assert_outside_real_home("git child HOME", &sandbox.home());
    home_sandbox::assert_process_isolated();
}

/// The tree listing must be at least this large, so an empty or broken git
/// listing cannot pass vacuously.
const MIN_TREE_FILES: usize = 1000;

/// Longest escape body of a char literal (`\u{10FFFF}` is 9 bytes after the
/// backslash and the escaped char).
const MAX_ESCAPE_LEN: usize = 10;

/// The typed signer: the one home of the daemon key.
const TYPED_SIGNER: &str = "src/governance/daemon_signer.rs";

/// This ratchet names every forbidden symbol to forbid it.
const SELF: &str = "tests/daemon_signer_ratchet_10074.rs";

/// The private key static.
const KEY_STATIC: &str = "DAEMON_AUDIT_KEY";

/// The removed bytes-only signer.
const BYTES_ONLY_SIGNER: &str = "try_sign_audit_payload";

/// The daemon key loaders (they return the daemon `SigningKey` itself).
const LOADERS: [&str; 2] = ["load_daemon_signing_key", "ensure_daemon_signing_key"];

/// R2 allowlist: `(file, static name, reason)`.
const KEY_STATICS: &[(&str, &str, &str)] = &[
    (
        TYPED_SIGNER,
        KEY_STATIC,
        "the daemon key itself, private to the typed signer",
    ),
    (
        "src/governance/audit.rs",
        "RECORDER_KEY",
        "the recorder ROLE key (a separate key, never the daemon key); it signs only \
         `recorder_signing_preimage`, which carries its own domain tag",
    ),
    (
        "tests/signed_events_domain_cutoff_10074.rs",
        "KEY",
        "test fixture: a fixed-seed test key installed through the boot API \
         (`init_audit_signers`), never a production key",
    ),
];

/// R4 allowlist: `(file, reason)` for historical records that name the
/// removed signer as it existed when they were written.
const BYTES_ONLY_HISTORICAL: &[(&str, &str)] = &[(
    "docs/v0.7.0/audit/sections/05-governance-policy-audit.md",
    "the v0.7.0 governance audit snapshot, accurate at v0.7.0 when the symbol \
     existed; a dated audit record is not rewritten",
)];

/// R3 allowlist: `(file, reason)` for every file that names a daemon key
/// loader in code.
const LOADER_SITES: &[(&str, &str)] = &[
    (
        "src/governance/audit.rs",
        "defines the loaders (identity keypair load + ensure at boot)",
    ),
    (
        "src/main.rs",
        "boot: loads / ensures the key and installs it into the typed signer",
    ),
    (
        "src/enterprise_federation_posture.rs",
        "posture row: checks only that a key is enrolled (`is_some`), signs nothing",
    ),
    (
        "src/daemon_runtime.rs",
        "federation pull/push request signing (`federation::signing`, wire format \
         `body || 0x00 || nonce` / `method\\npath\\nquery`); follow-up issue for a \
         federation domain tag",
    ),
    (
        "src/federation/peer.rs",
        "federation POST request signing (same wire format and follow-up issue)",
    ),
    (
        "tests/wake_hub_readonly_modes_9562.rs",
        "string inventory of key-loading symbols a read-only mode must not reach",
    ),
    (
        "tests/wake_sink_3469.rs",
        "test fixture: wake sink signs with the enrolled key",
    ),
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every tracked file plus every untracked file git does not ignore (so a
/// new, not yet committed file is held too). Fails closed when git cannot
/// list the tree.
fn tracked_files() -> Vec<String> {
    let sandbox = home_sandbox::install();
    let out = Command::new("git")
        .env("HOME", sandbox.home())
        .env("XDG_CONFIG_HOME", sandbox.home().join(".config"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .arg("-C")
        .arg(root())
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .output()
        .unwrap_or_else(|e| panic!("git ls-files could not run: {e}"));
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let files: BTreeSet<String> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    assert!(
        files.len() > MIN_TREE_FILES,
        "tracked tree too small: {}",
        files.len()
    );
    files.into_iter().collect()
}

/// Byte index just past a raw string starting at `i` (`r"`, `r#"`, `br#"`
/// ...), or `None` when `i` does not start one.
fn raw_string_end(b: &[u8], i: usize) -> Option<usize> {
    if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
        return None;
    }
    let mut j = i;
    if b.get(j) == Some(&b'b') {
        j += 1;
    }
    if b.get(j) != Some(&b'r') {
        return None;
    }
    j += 1;
    let hashes_start = j;
    while b.get(j) == Some(&b'#') {
        j += 1;
    }
    let hashes = j - hashes_start;
    if b.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    while j < b.len() {
        if b[j] == b'"'
            && b[j + 1..]
                .iter()
                .take(hashes)
                .filter(|c| **c == b'#')
                .count()
                == hashes
        {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
    Some(b.len())
}

/// Byte index just past a char literal starting at `i` (`'x'`, `'\n'`,
/// `'\u{..}'`, `'é'`), or `None` for a lifetime / label.
fn char_literal_end(src: &str, i: usize) -> Option<usize> {
    let rest = &src[i + 1..];
    let mut chars = rest.char_indices();
    let (_, first) = chars.next()?;
    if first == '\\' {
        // An escape: skip the escaped char (it may itself be `'`), then the
        // literal closes at the next `'` within a short span (`\u{10FFFF}`).
        let close = rest.get(2..)?.find('\'')?;
        return (close <= MAX_ESCAPE_LEN).then_some(i + 1 + 2 + close + 1);
    }
    let (next_i, next) = chars.next()?;
    (next == '\'' && first != '\'').then_some(i + 1 + next_i + 1)
}

/// Strip `//` and `/* */` comments from Rust source with a lexer that knows
/// string, raw-string, byte-string and char literals, so text inside a literal
/// is kept (a symbol named in a string still counts) and a quote inside a
/// char or raw literal can never turn later code into a "comment". An
/// unterminated literal keeps the rest of the file (fail closed: more text is
/// matched, never less).
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if (c == b'r' || c == b'b')
            && let Some(end) = raw_string_end(b, i)
        {
            out.push_str(&src[i..end]);
            i = end;
            continue;
        }
        if c == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(b.len());
            out.push_str(&src[i..end]);
            i = end;
            continue;
        }
        if c == b'\''
            && let Some(end) = char_literal_end(src, i)
        {
            out.push_str(&src[i..end]);
            i = end;
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            out.push(' ');
            continue;
        }
        let ch_len = src[i..].chars().next().map_or(1, char::len_utf8);
        out.push_str(&src[i..i + ch_len]);
        i += ch_len;
    }
    out
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `true` when `word` occurs in `text` as a whole identifier.
fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + word.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// The identifiers that denote `SigningKey` in `flat`: `SigningKey` itself
/// plus every `use ... SigningKey as X` and `type X = ...SigningKey...` alias.
fn signing_key_names(flat: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::from(["SigningKey".to_string()]);
    for (i, _) in flat.match_indices("SigningKey as ") {
        let rest = &flat[i + "SigningKey as ".len()..];
        let alias: String = rest.chars().take_while(|c| is_ident(*c)).collect();
        if !alias.is_empty() {
            names.insert(alias);
        }
    }
    for stmt in flat.split(';') {
        let s = stmt.trim_start();
        let s = s.strip_prefix("pub ").unwrap_or(s);
        if let Some(rest) = s.strip_prefix("type ")
            && let Some((name, ty)) = rest.split_once('=')
            && has_word(ty, "SigningKey")
        {
            let name: String = name.trim().chars().take_while(|c| is_ident(*c)).collect();
            names.insert(name);
        }
    }
    names
}

/// Every `static` / `const` item (including inside `thread_local!`) whose type
/// names a `SigningKey` alias, as its item name. A `'static` lifetime and a
/// `static` path segment (`static ::x`) are not items.
fn key_statics(code: &str) -> Vec<String> {
    let flat: String = code.split_whitespace().collect::<Vec<_>>().join(" ");
    let names = signing_key_names(&flat);
    let mut found = Vec::new();
    for kw in ["static ", "const "] {
        for (i, _) in flat.match_indices(kw) {
            if flat[..i]
                .chars()
                .next_back()
                .is_some_and(|c| is_ident(c) || c == '\'')
            {
                continue;
            }
            let rest = &flat[i + kw.len()..];
            let rest = rest.strip_prefix("mut ").unwrap_or(rest);
            let name: String = rest.chars().take_while(|c| is_ident(*c)).collect();
            if name.is_empty() {
                continue;
            }
            let after = rest[name.len()..].trim_start();
            let Some(ty_part) = after.strip_prefix(':') else {
                continue;
            };
            if ty_part.starts_with(':') {
                continue;
            }
            let end = ty_part.find(['=', ';']).unwrap_or(ty_part.len());
            let ty = &ty_part[..end];
            if names.iter().any(|n| has_word(ty, n)) {
                found.push(name);
            }
        }
    }
    found
}

/// What one file contributes to the ratchet.
#[derive(Clone, Default)]
struct Facts {
    key_static: bool,
    bytes_only: bool,
    loader: bool,
    statics: Vec<String>,
}

fn facts(path: &str, raw: &str) -> Facts {
    let is_rs = Path::new(path).extension().is_some_and(|e| e == "rs");
    let code = if is_rs {
        strip_comments(raw)
    } else {
        raw.to_string()
    };
    Facts {
        key_static: has_word(&code, KEY_STATIC),
        bytes_only: has_word(&code, BYTES_ONLY_SIGNER),
        // R3 holds Rust code: only a `.rs` file can call a loader; prose
        // (docs, changelogs, scripts, evidence dumps) that names one calls
        // nothing.
        loader: is_rs && LOADERS.iter().any(|l| has_word(&code, l)),
        statics: if is_rs {
            key_statics(&code)
        } else {
            Vec::new()
        },
    }
}

#[derive(Clone)]
struct Scan {
    files: BTreeMap<String, Facts>,
    skipped_non_utf8: usize,
}

impl Scan {
    /// Replace (or add) one file's text, as a mutant or an edit would.
    fn with_file(&self, path: &str, text: &str) -> Scan {
        let mut s = self.clone();
        s.files.insert(path.to_string(), facts(path, text));
        s
    }
}

fn read_tracked(f: &str) -> Option<String> {
    std::fs::read(root().join(f))
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

/// The scan of the real tree, computed once per test binary.
fn base_scan() -> &'static Scan {
    static BASE: OnceLock<Scan> = OnceLock::new();
    BASE.get_or_init(|| {
        let mut s = Scan {
            files: BTreeMap::new(),
            skipped_non_utf8: 0,
        };
        for f in tracked_files() {
            if f == SELF {
                continue;
            }
            match read_tracked(&f) {
                Some(raw) => {
                    s.files.insert(f.clone(), facts(&f, &raw));
                }
                None => s.skipped_non_utf8 += 1,
            }
        }
        s
    })
}

fn violations(s: &Scan) -> Vec<String> {
    let mut v = Vec::new();
    let mut statics = BTreeSet::new();
    for (f, fx) in &s.files {
        if fx.key_static && f != TYPED_SIGNER {
            v.push(format!(
                "R1: {f} names {KEY_STATIC} outside the typed signer"
            ));
        }
        if fx.bytes_only && !BYTES_ONLY_HISTORICAL.iter().any(|(h, _)| h == f) {
            v.push(format!(
                "R4: {f} names the bytes-only signer {BYTES_ONLY_SIGNER}"
            ));
        }
        if fx.loader && !LOADER_SITES.iter().any(|(l, _)| l == f) {
            v.push(format!(
                "R3: {f} names a daemon key loader outside the allowlist"
            ));
        }
        for name in &fx.statics {
            statics.insert((f.clone(), name.clone()));
        }
    }
    if !s.files.get(TYPED_SIGNER).is_some_and(|fx| fx.key_static) {
        v.push(format!(
            "R1 stale: {TYPED_SIGNER} no longer holds {KEY_STATIC}"
        ));
    }
    for (h, _) in BYTES_ONLY_HISTORICAL {
        if !s.files.get(*h).is_some_and(|fx| fx.bytes_only) {
            v.push(format!(
                "R4 stale: historical record {h} no longer names it"
            ));
        }
    }
    let allowed: BTreeSet<(String, String)> = KEY_STATICS
        .iter()
        .map(|(f, n, _)| ((*f).to_string(), (*n).to_string()))
        .collect();
    for site in statics.difference(&allowed) {
        v.push(format!(
            "R2: {} declares static `{}` holding a SigningKey outside the allowlist",
            site.0, site.1
        ));
    }
    for site in allowed.difference(&statics) {
        v.push(format!(
            "R2 stale: allowlisted static {} `{}` not found",
            site.0, site.1
        ));
    }
    for (l, _) in LOADER_SITES {
        if !s.files.get(*l).is_some_and(|fx| fx.loader) {
            v.push(format!(
                "R3 stale: allowlisted loader site {l} no longer names a loader"
            ));
        }
    }
    v
}

#[test]
fn daemon_key_is_reached_only_through_the_typed_signer_10074() {
    let s = base_scan();
    let v = violations(s);
    assert!(
        v.is_empty(),
        "daemon signer ratchet (#10074 S-4) violations:\n{}\n(non-UTF-8 files skipped: {})",
        v.join("\n"),
        s.skipped_non_utf8
    );
}

#[test]
fn typed_signer_signs_once_over_the_domain_preimage_10074() {
    let code = strip_comments(&read_tracked(TYPED_SIGNER).unwrap_or_default());
    let prod = code.split("#[cfg(test)]").next().unwrap_or_default();
    let calls: Vec<_> = prod.match_indices(".sign(").collect();
    assert_eq!(
        calls.len(),
        1,
        "the typed signer must make exactly one .sign( call"
    );
    assert!(
        prod.contains("key.sign(&preimage(domain, body))"),
        "the one daemon .sign( call is over preimage(domain, body)"
    );
    assert!(
        prod.contains("pub fn sign(domain: DaemonDomain, body: &[u8])"),
        "the only public signer takes a DaemonDomain"
    );
    assert!(
        prod.contains("static DAEMON_AUDIT_KEY: OnceLock<SigningKey>")
            && !prod.contains("pub static"),
        "the daemon key static is private"
    );
}

/// The lexer keeps code that follows a literal holding a quote or a comment
/// opener, so no literal form can hide code as a "comment" (fail open).
#[test]
fn comment_stripper_never_hides_code_behind_a_literal_10074() {
    let cases: &[(&str, &str)] = &[
        (
            "char literal quote",
            "let q = '\"'; let k = &DAEMON_AUDIT_KEY; // \"\n",
        ),
        (
            "escaped char quote",
            "let q = '\\''; let s = \"//\"; DAEMON_AUDIT_KEY\n",
        ),
        (
            "raw string with quote",
            "let s = r#\"a\"b//\"#; DAEMON_AUDIT_KEY\n",
        ),
        (
            "byte raw string",
            "let s = br##\"\"#/*\"##; DAEMON_AUDIT_KEY\n",
        ),
        (
            "comment opener in string",
            "let s = \"/*\"; DAEMON_AUDIT_KEY; let e = \"*/\";\n",
        ),
        (
            "lifetime then quote",
            "fn f<'a>(x: &'a str) -> char { '\"' } DAEMON_AUDIT_KEY\n",
        ),
        ("unicode escape", "let c = '\\u{1F600}'; DAEMON_AUDIT_KEY\n"),
        (
            "non-ascii char",
            "let c = 'é'; let d = \"//\"; DAEMON_AUDIT_KEY\n",
        ),
    ];
    for (label, src) in cases {
        assert!(
            has_word(&strip_comments(src), KEY_STATIC),
            "`{label}`: code after the literal was stripped: {:?}",
            strip_comments(src)
        );
    }
    let commented = "// DAEMON_AUDIT_KEY\n/* outer /* DAEMON_AUDIT_KEY */ still */ x\n";
    assert!(
        !has_word(&strip_comments(commented), KEY_STATIC),
        "line and nested block comments are stripped"
    );
}

/// Mutation proof of the scanner: each form the construct can take, placed in
/// a synthetic file, is a violation. Run against the real tree's scan with
/// one file added, so the proof is deterministic and needs no source edit.
#[test]
fn ratchet_catches_every_form_of_the_construct_10074() {
    let base = base_scan();
    let mutants: &[(&str, &str, &str)] = &[
        (
            "literal key name outside signer",
            "src/governance/mutant_a.rs",
            "fn f() { let _ = &super::daemon_signer::DAEMON_AUDIT_KEY; }",
        ),
        (
            "second OnceLock<SigningKey> static",
            "src/governance/mutant_b.rs",
            "static SECOND_KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();",
        ),
        (
            "fully qualified type in another container",
            "src/governance/mutant_c.rs",
            "static K: std::sync::Mutex<Vec<ed25519_dalek::SigningKey>> =\n    std::sync::Mutex::new(Vec::new());",
        ),
        (
            "use-as alias",
            "src/governance/mutant_d.rs",
            "use ed25519_dalek::SigningKey as Sk;\nstatic K: std::sync::OnceLock<Sk> = std::sync::OnceLock::new();",
        ),
        (
            "type alias",
            "src/governance/mutant_e.rs",
            "type DaemonK = Option<ed25519_dalek::SigningKey>;\nstatic K: std::sync::Mutex<DaemonK> = std::sync::Mutex::new(None);",
        ),
        (
            "thread_local container",
            "src/governance/mutant_f.rs",
            "thread_local! { static K: std::cell::RefCell<Option<SigningKey>> = const { std::cell::RefCell::new(None) }; }",
        ),
        (
            "const table form",
            "src/governance/mutant_g.rs",
            "const KEYS: &[SigningKey] = &[];",
        ),
        (
            "static mut slice form",
            "src/governance/mutant_g2.rs",
            "static mut KEYS: [Option<SigningKey>; 1] = [None];",
        ),
        (
            "loader via another call form (alias import)",
            "src/handlers/mutant_h.rs",
            "use crate::governance::audit::load_daemon_signing_key as lk;\nfn f() { let _ = lk(\"a\"); }",
        ),
        (
            "loader in a file outside src",
            "examples/mutant_i.rs",
            "fn main() { let _ = ai_memory::governance::audit::ensure_daemon_signing_key(\"a\"); }",
        ),
        (
            "bytes-only signer restored",
            "src/governance/mutant_j.rs",
            "pub fn try_sign_audit_payload(b: &[u8]) -> Option<Vec<u8>> { None }",
        ),
        (
            "key name in a non-Rust tracked file",
            "scripts/mutant_k.py",
            "DAEMON_AUDIT_KEY = 1\n",
        ),
        (
            "key name after a quote char literal",
            "src/governance/mutant_l.rs",
            "fn f() -> char { let _ = &DAEMON_AUDIT_KEY; '\"' } // \"\n",
        ),
        (
            "key name after a raw string holding a comment opener",
            "src/governance/mutant_m.rs",
            "const S: &str = r#\"/*\"#; fn f() { let _ = &DAEMON_AUDIT_KEY; }\n",
        ),
    ];
    for (label, path, body) in mutants {
        let v = violations(&base.with_file(path, body));
        assert!(
            v.iter().any(|m| m.contains(path)),
            "mutant `{label}` was NOT caught; violations: {v:?}"
        );
    }
    // A comment that names the symbol is not code and is allowed.
    let commented = base.with_file(
        "src/governance/mutant_comment.rs",
        "// DAEMON_AUDIT_KEY is private\n/* load_daemon_signing_key */\n",
    );
    assert_eq!(
        violations(&commented),
        Vec::<String>::new(),
        "comments are not code"
    );
    // Prose that names a loader calls nothing.
    let prose = base.with_file(
        "docs/mutant_prose.md",
        "`load_daemon_signing_key` loads it\n",
    );
    assert_eq!(
        violations(&prose),
        Vec::<String>::new(),
        "prose is not a call site"
    );
    // A stale allowlist entry is a violation: rename audit.rs RECORDER_KEY.
    let audit = read_tracked("src/governance/audit.rs")
        .unwrap_or_default()
        .replace("static RECORDER_KEY", "static RENAMED_KEY");
    let v = violations(&base.with_file("src/governance/audit.rs", &audit));
    assert!(
        v.iter().any(|m| m.contains("R2 stale")) && v.iter().any(|m| m.contains("RENAMED_KEY")),
        "a renamed static is both stale and unlisted: {v:?}"
    );
    // The typed signer losing the key is a stale R1 entry.
    let signer = read_tracked(TYPED_SIGNER)
        .unwrap_or_default()
        .replace(KEY_STATIC, "OTHER_KEY");
    let v = violations(&base.with_file(TYPED_SIGNER, &signer));
    assert!(
        v.iter().any(|m| m.starts_with("R1 stale")),
        "the signer losing the key static is stale: {v:?}"
    );
}
