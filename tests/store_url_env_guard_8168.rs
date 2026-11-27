// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8168 R3-3 — the store-url test env lock has ONE order, enforced by type.
//!
//! The crate has two test locks over the process environment: the
//! crate-wide env lock and the store-url env lock. Before this change the
//! store-url lock was a free `pub(crate)` function any test could call, with
//! or without the outer lock, in either order (a nested take at one site, a
//! lone take at about eighty). Now the function is private to
//! `src/store_url.rs` and the only way to take it is
//! `StoreUrlEnvGuard::acquire(&EnvLockGuard)`, which borrows a held outer
//! guard: the wrong order and a lone take do not compile.
//!
//! This ratchet keeps that true. It is an allowlist over every `.rs` file
//! of the source tree (the whole manifest directory; `target`, `.git`,
//! `.local-runs`, `.codegraph` and `node_modules` are left out because they
//! hold build output, VCS data or scratch, not tracked source). The lock
//! function's name may appear in code in exactly three lines of
//! `src/store_url.rs`: its definition, the call inside the guard
//! constructor and the held-probe. The constructor's signature is pinned too, so a constructor
//! that stops taking the outer proof fails here. Comment text is ignored.

use std::fs;
use std::path::{Path, PathBuf};

/// The lock function's name, built from parts so this file never holds the
/// token itself (the census would otherwise count its own constants).
fn token() -> String {
    ["store_url_", "env_lock"].concat()
}

/// The one file allowed to name the lock function in code.
const ALLOWED_FILE: &str = "src/store_url.rs";

/// The three code lines of [`ALLOWED_FILE`] that may name it, trimmed.
fn allowed_lines() -> [String; 3] {
    [
        format!("fn {}() -> &'static std::sync::Mutex<()> {{", token()),
        format!("_store_url: {}()", token()),
        format!("{}().try_lock().is_err()", token()),
    ]
}

/// The constructor shape, whitespace collapsed: it takes the outer proof.
const CTOR_SIGNATURE: &str = "pub(crate) fn acquire(_env: &'env OuterEnvLock) -> Self {";
/// The proof type, whitespace collapsed.
const PROOF_ALIAS: &str = "type OuterEnvLock = crate::enterprise_federation_posture::hardened_env_fixture::EnvLockGuard<'static>;";
/// The guard struct carries the borrow of the outer proof.
const GUARD_BORROW: &str = "_env: std::marker::PhantomData<&'env OuterEnvLock>,";

/// Directories left out of the census, each with its reason.
const SKIPPED_DIRS: &[(&str, &str)] = &[
    ("target", "build output"),
    (".git", "version-control data"),
    (".local-runs", "agent scratch, gitignored"),
    (".codegraph", "per-developer index, gitignored"),
    ("node_modules", "vendored JS, not Rust source"),
];

#[derive(Debug, PartialEq, Eq)]
enum Violation {
    /// The name appears in code in a file other than [`ALLOWED_FILE`].
    OutsideFile { file: String, line: usize },
    /// The name appears in an allowed file on a line that is not allowed.
    UnlistedLine { line: usize, text: String },
    /// An allowed line is missing (the definition or the constructor call).
    MissingAllowedLine { text: String },
    /// An allowed line appears more than once.
    DuplicateAllowedLine { text: String },
    /// A shape pin of the guard is gone.
    ShapeMissing { pin: &'static str },
}

/// Code lines of `src` with `//` comments and `/* */` blocks removed.
fn code_lines(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_block = false;
    for (i, raw) in src.lines().enumerate() {
        let mut rest = raw;
        let mut kept = String::new();
        loop {
            if in_block {
                match rest.find("*/") {
                    Some(e) => {
                        rest = &rest[e + 2..];
                        in_block = false;
                    }
                    None => break,
                }
            } else {
                let line_c = rest.find("//");
                let block_c = rest.find("/*");
                match (line_c, block_c) {
                    (Some(l), Some(b)) if b < l => {
                        kept.push_str(&rest[..b]);
                        rest = &rest[b + 2..];
                        in_block = true;
                    }
                    (Some(l), _) => {
                        kept.push_str(&rest[..l]);
                        break;
                    }
                    (None, Some(b)) => {
                        kept.push_str(&rest[..b]);
                        rest = &rest[b + 2..];
                        in_block = true;
                    }
                    (None, None) => {
                        kept.push_str(rest);
                        break;
                    }
                }
            }
        }
        out.push((i + 1, kept));
    }
    out
}

fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The census over `(relative path, text)` pairs of the whole tree.
fn census(files: &[(String, String)]) -> Vec<Violation> {
    let tok = token();
    let allowed = allowed_lines();
    let mut v = Vec::new();
    let mut seen = [0usize; 3];
    for (path, text) in files {
        for (line, code) in code_lines(text) {
            if !code.contains(&tok) {
                continue;
            }
            if path != ALLOWED_FILE {
                v.push(Violation::OutsideFile {
                    file: path.clone(),
                    line,
                });
                continue;
            }
            let t = collapse(code.trim());
            match allowed.iter().position(|a| t.contains(a.as_str())) {
                Some(k) => seen[k] += 1,
                None => v.push(Violation::UnlistedLine { line, text: t }),
            }
        }
    }
    for (k, a) in allowed.iter().enumerate() {
        match seen[k] {
            0 => v.push(Violation::MissingAllowedLine { text: a.clone() }),
            1 => {}
            _ => v.push(Violation::DuplicateAllowedLine { text: a.clone() }),
        }
    }
    if let Some((_, text)) = files.iter().find(|(p, _)| p == ALLOWED_FILE) {
        let flat = collapse(text);
        for pin in [CTOR_SIGNATURE, PROOF_ALIAS, GUARD_BORROW] {
            if !flat.contains(pin) {
                v.push(Violation::ShapeMissing { pin });
            }
        }
    } else {
        v.push(Violation::ShapeMissing { pin: ALLOWED_FILE });
    }
    v
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let rd = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in rd {
        let entry = entry.expect("dir entry");
        let path: PathBuf = entry.path();
        let ft = entry.file_type().expect("file type");
        if ft.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if SKIPPED_DIRS.iter().any(|(d, _)| *d == name) {
                continue;
            }
            walk(&path, root, out);
        } else if ft.is_file() && path.extension().is_some_and(|e| e == "rs") {
            let rel = path
                .strip_prefix(root)
                .expect("under root")
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            out.push((rel, text));
        }
    }
}

fn tree() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files
}

/// A good copy of the allowed file, for the mutant tests below.
fn good_allowed() -> String {
    format!(
        "{}\n    static LOCK: u8 = 0;\n}}\n\ntype OuterEnvLock = crate::enterprise_federation_posture::hardened_env_fixture::EnvLockGuard<'static>;\n\n\
         pub(crate) struct StoreUrlEnvGuard<'env> {{\n    _store_url: u8,\n    _env: std::marker::PhantomData<&'env OuterEnvLock>,\n}}\n\n\
         impl<'env> StoreUrlEnvGuard<'env> {{\n    pub(crate) fn acquire(_env: &'env OuterEnvLock) -> Self {{\n        Self {{\n            _store_url: {}()\n                .lock(),\n        }}\n    }}\n    fn held() -> bool {{\n        {}().try_lock().is_err()\n    }}\n}}\n",
        allowed_lines()[0],
        token(),
        token()
    )
}

fn with(file: &str, text: &str) -> Vec<(String, String)> {
    vec![
        (ALLOWED_FILE.to_string(), good_allowed()),
        (file.to_string(), text.to_string()),
    ]
}

/// 8168 R3-3: the whole tree names the lock function in code only inside
/// the guard module. Red at the base commit (about eighty outside sites),
/// green at the head.
#[test]
fn store_url_env_lock_is_reachable_only_through_the_guard_8168() {
    let files = tree();
    assert!(
        files.iter().any(|(p, _)| p == ALLOWED_FILE),
        "the allowed file must be in the census"
    );
    assert!(files.len() > 100, "the census must cover the whole tree");
    let v = census(&files);
    assert_eq!(
        v,
        Vec::<Violation>::new(),
        "store-url lock order is not enforced"
    );
}

/// The synthetic good tree is clean (so each mutant below is red for its
/// own reason).
#[test]
fn good_tree_is_clean_8168() {
    assert_eq!(
        census(&with("src/a.rs", "fn x() {}")),
        Vec::<Violation>::new()
    );
}

/// Mutant: a direct call from another file (the lone take, or the wrong
/// order at a site that takes the store-url lock first).
#[test]
fn mutant_direct_call_in_another_file_is_red_8168() {
    let call = format!("let _g = crate::store_url::{}().lock();", token());
    assert_eq!(
        census(&with(
            "src/cli/x.rs",
            &format!("fn t() {{\n    {call}\n}}\n")
        )),
        vec![Violation::OutsideFile {
            file: "src/cli/x.rs".into(),
            line: 2
        }]
    );
}

/// Mutant: an alias (`use ... as`) and a constant holding the name.
#[test]
fn mutant_alias_forms_are_red_8168() {
    let t = token();
    for body in [
        format!("use crate::store_url::{t} as lock_it;"),
        format!("const F: fn() -> u8 = {t};"),
        format!("static T: [fn(); 1] = [{t}];"),
        format!("fn t() {{ match 0 {{ _ => {t}() }}; }}"),
    ] {
        assert_eq!(
            census(&with("tests/y.rs", &body)),
            vec![Violation::OutsideFile {
                file: "tests/y.rs".into(),
                line: 1
            }],
            "{body}"
        );
    }
}

/// Mutant: a second lock call inside the allowed file (a test in the
/// module that takes the store-url lock directly).
#[test]
fn mutant_extra_call_in_allowed_file_is_red_8168() {
    let mut text = good_allowed();
    text.push_str(&format!(
        "#[test]\nfn t() {{\n    let _g = {}().lock();\n}}\n",
        token()
    ));
    let v = census(&[(ALLOWED_FILE.to_string(), text)]);
    assert_eq!(
        v,
        vec![Violation::UnlistedLine {
            line: good_allowed().lines().count() + 3,
            text: format!("let _g = {}().lock();", token())
        }]
    );
}

/// Mutant: the guard is built without the outer lock (the constructor
/// stops taking the proof).
#[test]
fn mutant_constructor_without_outer_lock_is_red_8168() {
    let text = good_allowed().replace(
        "pub(crate) fn acquire(_env: &'env OuterEnvLock) -> Self {",
        "pub(crate) fn acquire() -> Self {",
    );
    assert_eq!(
        census(&[(ALLOWED_FILE.to_string(), text)]),
        vec![Violation::ShapeMissing {
            pin: CTOR_SIGNATURE
        }]
    );
}

/// Mutant: the proof type is weakened to a plain mutex guard, or the
/// borrow is dropped from the guard.
#[test]
fn mutant_weak_proof_or_dropped_borrow_is_red_8168() {
    let weak = good_allowed().replace(
        "crate::enterprise_federation_posture::hardened_env_fixture::EnvLockGuard<'static>",
        "std::sync::MutexGuard<'static, ()>",
    );
    assert_eq!(
        census(&[(ALLOWED_FILE.to_string(), weak)]),
        vec![Violation::ShapeMissing { pin: PROOF_ALIAS }]
    );
    let unborrowed = good_allowed().replace(
        "_env: std::marker::PhantomData<&'env OuterEnvLock>,",
        "_env: std::marker::PhantomData<&'env ()>,",
    );
    assert_eq!(
        census(&[(ALLOWED_FILE.to_string(), unborrowed)]),
        vec![Violation::ShapeMissing { pin: GUARD_BORROW }]
    );
}

/// Comment text and block comments never count; a name inside a block
/// comment that closes mid-line leaves later code visible.
#[test]
fn comments_are_ignored_but_code_after_them_is_not_8168() {
    let t = token();
    assert_eq!(
        census(&with(
            "src/z.rs",
            &format!("// {t}\n/* {t}\n{t} */\nfn ok() {{}}\n")
        )),
        Vec::<Violation>::new()
    );
    assert_eq!(
        census(&with("src/z.rs", &format!("/* c */ {t}();"))),
        vec![Violation::OutsideFile {
            file: "src/z.rs".into(),
            line: 1
        }]
    );
}
