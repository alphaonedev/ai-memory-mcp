// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8168 R3-3 — the store-url test env lock has ONE order, enforced by type.
//!
//! The crate has two test locks over the process environment: the
//! crate-wide env lock and the store-url env lock. Before this change the
//! store-url lock was a free `pub(crate)` function any test could call, with
//! or without the outer lock, in either order (a nested take at one site, a
//! lone take at about eighty). Now the function is private to
//! `src/store_url/env_guard.rs` and the only way to take it is
//! `StoreUrlEnvGuard::acquire(&EnvLockGuard)`, which borrows a held outer
//! guard: the wrong order and a lone take do not compile.
//!
//! This ratchet keeps that true. It is an allowlist over every `.rs` file
//! of the source tree (the whole manifest directory; `target`, `.git`,
//! `.local-runs`, `.codegraph` and `node_modules` are left out because they
//! hold build output, VCS data or scratch, not tracked source). The lock
//! function's name may appear in code in exactly three lines of
//! `src/store_url/env_guard.rs`: its definition, the call inside the guard
//! constructor and the held-probe. The constructor's signature is pinned too, so a constructor
//! that stops taking the outer proof fails here. Comment text is judged as text, not skipped.
//!
//! #10208 adds a census of whole item sets, because text pins of chosen
//! lines let a new item through. `census_all` runs four parts:
//!
//! 1. the line census above;
//! 2. the item census: every item of the guard file, nested items of `impl`
//!    and `mod` blocks included, must equal one row of `ENV_GUARD_ITEMS`
//!    token for token (attributes, visibility and fn bodies included), and
//!    the item count must be `ENV_GUARD_ITEM_COUNT`. A new item, a new
//!    method, a new impl, a changed field or a changed body is red;
//! 3. the use census: outside the guard file the guard type may be named
//!    only as `StoreUrlEnvGuard::acquire(` (which needs the outer proof) or
//!    in the exact statements of `GUARD_USES`. A new impl block, a `Deref`
//!    impl or an alias in another file is red;
//! 4. the static census: in the guard file and in every file that names the
//!    store-url variables, each `static` item (inside a fn body or a macro
//!    such as `thread_local!` too) must be a row of `STORE_URL_STATICS`.
//!
//! The lexer is std only and fails closed (an unterminated string or
//! comment is a finding). Its limits: it does not expand macros, so an item
//! or a static built by a macro from pieces is not seen; it does not resolve
//! names, so a lock static in a file that never names the store-url
//! variables but is taken by code in one that does is not seen by part 4
//! (tracked as issue 10213); `concat!` or escaped spellings of the
//! variable names are not decoded.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// The lock function's name, built from parts so this file never holds the
/// token itself (the census would otherwise count its own constants).
fn token() -> String {
    ["store_url_", "env_lock"].concat()
}

/// The one file allowed to name the lock function in code.
const ALLOWED_FILE: &str = "src/store_url/env_guard.rs";

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

#[derive(Debug, Clone, PartialEq, Eq)]
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
        for (i, raw) in text.lines().enumerate() {
            let line = i + 1;
            let hits = raw.matches(tok.as_str()).count();
            if hits == 0 {
                continue;
            }
            if path != ALLOWED_FILE {
                // Comments count too: no parser can be blinded by a string
                // that holds a comment opener.
                v.push(Violation::OutsideFile {
                    file: path.clone(),
                    line,
                });
                continue;
            }
            let t = collapse(raw.trim());
            if t.starts_with("//") {
                continue;
            }
            match allowed
                .iter()
                .position(|a| hits == 1 && t.starts_with(a.as_str()))
            {
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
fn store_url_lock_is_reachable_only_through_the_guard_8168() {
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
    write!(
        text,
        "#[test]\nfn t() {{\n    let _g = {}().lock();\n}}\n",
        token()
    )
    .expect("write to String");
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

/// A comment opener inside a string literal must not blind the census: the
/// name after it is still seen (the failure mode of a comment stripper).
#[test]
fn comment_opener_in_a_string_cannot_hide_a_call_8168() {
    let t = token();
    let body = format!("const G: &str = \"/*\";\nfn t() {{ {t}(); }}\n");
    assert_eq!(
        census(&with("src/z.rs", &body)),
        vec![Violation::OutsideFile {
            file: "src/z.rs".into(),
            line: 2
        }]
    );
}

/// Outside the guard module even a comment naming the function is a
/// violation; inside it a comment-only line is allowed, a trailing comment
/// after other code is not, and two names on one line are not.
#[test]
fn comments_are_judged_as_text_8168() {
    let t = token();
    assert_eq!(
        census(&with("src/z.rs", &format!("// {t}\n"))),
        vec![Violation::OutsideFile {
            file: "src/z.rs".into(),
            line: 1
        }]
    );
    let mut ok = good_allowed();
    writeln!(ok, "// {t} is private").expect("write to String");
    assert_eq!(
        census(&[(ALLOWED_FILE.to_string(), ok)]),
        Vec::<Violation>::new()
    );
    let mut trailing = good_allowed();
    writeln!(trailing, "fn x() {{ {t}(); }} // _store_url: {t}()").expect("write to String");
    let found = census(&[(ALLOWED_FILE.to_string(), trailing)]);
    assert!(
        matches!(found.as_slice(), [Violation::UnlistedLine { .. }]),
        "a call hidden behind a trailing comment is one unlisted line: {found:?}"
    );
}

/// The live text of one tree file, the base of the #10208 text mutants.
fn live(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The live text of [`ALLOWED_FILE`].
fn live_guard_file() -> String {
    live(ALLOWED_FILE)
}

/// The live tree with `rel` replaced by `text` (or added when absent).
fn tree_with(rel: &str, text: String) -> Vec<(String, String)> {
    let mut files = tree();
    match files.iter_mut().find(|(p, _)| p == rel) {
        Some(entry) => entry.1 = text,
        None => files.push((rel.to_string(), text)),
    }
    files
}

/// The live tree with `tail` appended to `rel`; returns the tree and the
/// line number of the first appended line.
fn tree_appended(rel: &str, tail: &str) -> (Vec<(String, String)>, usize) {
    let mut text = live(rel);
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let first = text.lines().count() + 1;
    text.push_str(tail);
    (tree_with(rel, text), first)
}

/// The opening of the real constructor, the anchor every mutant edits.
const ACQUIRE_HEAD: &str =
    "    pub(crate) fn acquire(_env: &'env OuterEnvLock) -> Self {\n        Self {\n";

/// `text` with `from` replaced once; panics when the anchor is gone, so a
/// mutant can never be a silent no-op.
fn mutate(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "mutant anchor: {from}");
    text.replacen(from, to, 1)
}

/// #10208 form 1: a second constructor with no outer proof, which
/// `acquire` delegates to.
fn mutant_second_constructor() -> String {
    mutate(
        &live_guard_file(),
        ACQUIRE_HEAD,
        "    pub(crate) fn acquire(_env: &'env OuterEnvLock) -> Self {\n        Self::lone()\n    }\n\n    pub(crate) fn lone() -> Self {\n        Self {\n",
    )
}

/// #10208 form 2: a method that hands out the inner guard by value.
fn mutant_by_value_accessor() -> String {
    mutate(
        &live_guard_file(),
        "    /// Test probe:",
        "    pub(crate) fn into_inner(self) -> std::sync::MutexGuard<'static, ()> {\n        self._store_url\n    }\n\n    /// Test probe:",
    )
}

/// #10208 form 3: `acquire` delegates to a private helper that takes the
/// lock with no proof.
fn mutant_unproven_helper() -> String {
    let text = mutate(
        &live_guard_file(),
        ACQUIRE_HEAD,
        "    pub(crate) fn acquire(_env: &'env OuterEnvLock) -> Self {\n        take()\n    }\n}\n\nfn take<'a>() -> StoreUrlEnvGuard<'a> {\n    {\n        StoreUrlEnvGuard {\n",
    );
    mutate(
        &text,
        "    /// Test probe:",
        "}\n\nimpl StoreUrlEnvGuard<'_> {\n    /// Test probe:",
    )
}

/// #10208 form 4: a second mutex static under another name that serialises
/// the store-url variables in another file.
fn mutant_second_static() -> (String, String) {
    (
        "src/cli/backup.rs".to_string(),
        SECOND_STATIC_TAIL.to_string(),
    )
}

/// The module form 4 appends: its static is on the third line.
const SECOND_STATIC_TAIL: &str = "#[cfg(test)]\nmod t {\n    static STORE_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());\n    #[test]\n    fn t() {\n        let _g = STORE_ENV.lock();\n        unsafe { std::env::remove_var(crate::store_url::STORE_URL_ENV) };\n    }\n}\n";

/// The parent label of the guard's one impl block, as the census spells it.
const GUARD_IMPL: &str = "impl<'env> StoreUrlEnvGuard<'env>";

fn unlisted(parent: &str, kind: ItemKind, name: &str) -> Finding {
    Finding::Item(ItemFinding::Unlisted {
        parent: norm(parent),
        kind,
        name: norm(name),
    })
}

fn changed(parent: &str, kind: ItemKind, name: &str) -> Finding {
    Finding::Item(ItemFinding::Changed {
        parent: norm(parent),
        kind,
        name: norm(name),
    })
}

fn missing(parent: &str, kind: ItemKind, name: &str) -> Finding {
    Finding::Item(ItemFinding::Missing {
        parent: norm(parent),
        kind,
        name: norm(name),
    })
}

fn count(found: usize) -> Finding {
    Finding::Item(ItemFinding::CountMismatch {
        expected: ENV_GUARD_ITEM_COUNT,
        found,
    })
}

/// #10208: the whole live tree passes all four parts of the census.
#[test]
fn whole_tree_census_is_clean_10208() {
    let found = census_all(&tree());
    assert_eq!(found, Vec::<Finding>::new(), "{found:#?}");
}

/// #10208 form 1: a second constructor without the proof is red.
#[test]
fn mutant_second_constructor_is_red_10208() {
    assert_eq!(
        census_all(&tree_with(ALLOWED_FILE, mutant_second_constructor())),
        vec![
            count(ENV_GUARD_ITEM_COUNT + 1),
            changed(GUARD_IMPL, ItemKind::Fn, "acquire"),
            unlisted(GUARD_IMPL, ItemKind::Fn, "lone"),
        ]
    );
}

/// #10208 form 2: a method handing out the inner guard is red.
#[test]
fn mutant_by_value_accessor_is_red_10208() {
    assert_eq!(
        census_all(&tree_with(ALLOWED_FILE, mutant_by_value_accessor())),
        vec![
            count(ENV_GUARD_ITEM_COUNT + 1),
            unlisted(GUARD_IMPL, ItemKind::Fn, "into_inner"),
        ]
    );
}

/// #10208 form 3: `acquire` delegating to an unproven free helper is red.
#[test]
fn mutant_unproven_helper_is_red_10208() {
    let second = "impl StoreUrlEnvGuard<'_>";
    assert_eq!(
        census_all(&tree_with(ALLOWED_FILE, mutant_unproven_helper())),
        vec![
            count(ENV_GUARD_ITEM_COUNT + 2),
            changed(GUARD_IMPL, ItemKind::Fn, "acquire"),
            unlisted("", ItemKind::Fn, "take"),
            unlisted("", ItemKind::Impl, "StoreUrlEnvGuard<'_>"),
            unlisted(second, ItemKind::Fn, "store_lock_is_held"),
            missing(GUARD_IMPL, ItemKind::Fn, "store_lock_is_held"),
        ]
    );
}

/// #10208 form 4: a second lock static for the store-url variables in
/// another file is red.
#[test]
fn mutant_second_static_is_red_10208() {
    let (file, tail) = mutant_second_static();
    let (files, first) = tree_appended(&file, &tail);
    assert_eq!(
        census_all(&files),
        vec![Finding::Static(StaticFinding::Unlisted {
            file,
            name: "STORE_ENV".into(),
            line: first + 2,
        })]
    );
}

/// Evasion 1: a new impl block for the guard in another file of the module
/// (the parent `src/store_url.rs`).
#[test]
fn evasion_impl_block_in_parent_module_is_red_10208() {
    let tail = "#[cfg(test)]\nimpl StoreUrlEnvGuard<'_> {\n    pub(crate) fn lone() -> Self {\n        unimplemented!()\n    }\n}\n";
    let (files, first) = tree_appended("src/store_url.rs", tail);
    assert_eq!(
        census_all(&files),
        vec![Finding::Use(UseFinding::Unlisted {
            file: "src/store_url.rs".into(),
            line: first + 1,
            statement: norm("} #[cfg(test)] impl StoreUrlEnvGuard<'_> {"),
        })]
    );
}

/// Evasion 2: a `Deref` impl that hands out the inner guard by reference.
#[test]
fn evasion_deref_to_inner_guard_is_red_10208() {
    let text = mutate(
        &live_guard_file(),
        "#[cfg(test)]\nmod tests {",
        "impl std::ops::Deref for StoreUrlEnvGuard<'_> {\n    type Target = std::sync::MutexGuard<'static, ()>;\n    fn deref(&self) -> &Self::Target {\n        &self._store_url\n    }\n}\n\n#[cfg(test)]\nmod tests {",
    );
    let deref = "impl std::ops::Deref for StoreUrlEnvGuard<'_>";
    assert_eq!(
        census_all(&tree_with(ALLOWED_FILE, text)),
        vec![
            count(ENV_GUARD_ITEM_COUNT + 3),
            unlisted(
                "",
                ItemKind::Impl,
                "std::ops::Deref for StoreUrlEnvGuard<'_>"
            ),
            unlisted(deref, ItemKind::Type, "Target"),
            unlisted(deref, ItemKind::Fn, "deref"),
        ]
    );
}

/// Evasion 3: the inner guard field made `pub(crate)`.
#[test]
fn evasion_pub_crate_field_is_red_10208() {
    let text = mutate(
        &live_guard_file(),
        "    _store_url: std::sync::MutexGuard",
        "    pub(crate) _store_url: std::sync::MutexGuard",
    );
    assert_eq!(
        census_all(&tree_with(ALLOWED_FILE, text)),
        vec![changed("", ItemKind::Struct, "StoreUrlEnvGuard")]
    );
}

/// Evasion 4: a lock static inside a fn body of a file that names the
/// store-url variables, and one inside `thread_local!` in a test binary.
#[test]
fn evasion_static_in_fn_body_or_macro_is_red_10208() {
    let tail = "#[cfg(test)]\nfn serialise() {\n    static STORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());\n    drop(STORE_LOCK.lock());\n}\n";
    let (files, first) = tree_appended("src/store_url.rs", tail);
    assert_eq!(
        census_all(&files),
        vec![Finding::Static(StaticFinding::Unlisted {
            file: "src/store_url.rs".into(),
            name: "STORE_LOCK".into(),
            line: first + 2,
        })]
    );
    let file = "tests/cov_backup_store_url_3521.rs";
    let tail = "thread_local! {\n    static HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };\n}\n";
    let (files, first) = tree_appended(file, tail);
    assert_eq!(
        census_all(&files),
        vec![Finding::Static(StaticFinding::Unlisted {
            file: file.into(),
            name: "HELD".into(),
            line: first + 1,
        })]
    );
}

/// Evasion 5: an alias of the guard type, and a raw-identifier spelling of
/// it, in another file.
#[test]
fn evasion_alias_and_raw_identifier_are_red_10208() {
    let (files, first) = tree_appended(
        "src/cli/backup.rs",
        "use crate::store_url::StoreUrlEnvGuard as G;\n",
    );
    assert_eq!(
        census_all(&files),
        vec![Finding::Use(UseFinding::Unlisted {
            file: "src/cli/backup.rs".into(),
            line: first,
            statement: norm("} use crate::store_url::StoreUrlEnvGuard as G;"),
        })]
    );
    let (files, first) = tree_appended("src/store_url.rs", "impl r#StoreUrlEnvGuard<'_> {}\n");
    assert_eq!(
        census_all(&files),
        vec![Finding::Use(UseFinding::Unlisted {
            file: "src/store_url.rs".into(),
            line: first,
            statement: norm("} impl StoreUrlEnvGuard<'_> {"),
        })]
    );
}

/// Fail closed: a file the lexer cannot read is a finding, never a pass,
/// and its allowlist rows are then reported missing.
#[test]
fn unlexable_file_is_red_10208() {
    let (files, first) = tree_appended("src/store_url.rs", "const BAD: &str = \"open;\n");
    let error = LexError::Unterminated {
        what: "string",
        line: first,
    };
    assert_eq!(
        census_all(&files),
        vec![
            Finding::Use(UseFinding::Lex {
                file: "src/store_url.rs".into(),
                error: error.clone(),
            }),
            Finding::Use(UseFinding::Missing {
                file: "src/store_url.rs".into(),
                statement: norm(GUARD_USES[0].statement),
            }),
            Finding::Static(StaticFinding::Lex {
                file: "src/store_url.rs".into(),
                error,
            }),
        ]
    );
    let mut guard = live_guard_file();
    guard.push_str("/* open\n");
    assert_eq!(
        item_census(&[(ALLOWED_FILE.to_string(), guard)]),
        vec![ItemFinding::Lex(LexError::Unterminated {
            what: "block comment",
            line: live_guard_file().lines().count() + 1,
        })]
    );
    assert_eq!(item_census(&[]), vec![ItemFinding::FileMissing]);
}

/// The store-url lock itself lives only in the guard file; a test binary's
/// own lock serialises only that binary's threads.
#[test]
fn only_the_guard_file_holds_the_store_url_lock_10208() {
    let mut locks = Vec::new();
    for row in &STORE_URL_STATICS {
        match row.role {
            StaticRole::StoreUrlEnvLock => locks.push((row.file, row.name)),
            StaticRole::OwnBinaryLock => assert!(row.file.starts_with("tests/"), "{}", row.file),
            StaticRole::Unrelated => {}
        }
    }
    assert_eq!(locks, vec![(ALLOWED_FILE, "LOCK")]);
}

/// The lexer: each token form it must tell apart, by kind and text.
#[test]
fn lexer_token_forms_10208() {
    use TokKind::{Char, Ident, Lifetime, Num, Punct, Str};
    let rows: &[(&str, &[(TokKind, &str)])] = &[
        (
            "'a 'b' '\\'' '\\\\'",
            &[
                (Lifetime, "'a"),
                (Char, "'b'"),
                (Char, "'\\''"),
                (Char, "'\\\\'"),
            ],
        ),
        (
            "r#\"x\"# r\"y\" br#\"z\"#",
            &[(Str, "r#\"x\"#"), (Str, "r\"y\""), (Str, "br#\"z\"#")],
        ),
        (
            "b\"q\" c\"w\" b'e'",
            &[(Str, "b\"q\""), (Str, "c\"w\""), (Char, "b'e'")],
        ),
        (
            "r#type x /* a /* b */ c */ y // z",
            &[(Ident, "type"), (Ident, "x"), (Ident, "y")],
        ),
        (
            "\"a\\\"b\" 1.5f32 x.0",
            &[
                (Str, "\"a\\\"b\""),
                (Num, "1.5f32"),
                (Ident, "x"),
                (Punct, "."),
                (Num, "0"),
            ],
        ),
        ("\"/*\" k", &[(Str, "\"/*\""), (Ident, "k")]),
    ];
    for (src, want) in rows {
        let got: Vec<(TokKind, String)> = lex(src)
            .unwrap_or_else(|e| panic!("{src}: {e:?}"))
            .into_iter()
            .map(|t| (t.kind, t.text))
            .collect();
        let want: Vec<(TokKind, String)> =
            want.iter().map(|(k, t)| (*k, (*t).to_string())).collect();
        assert_eq!(got, want, "{src}");
    }
    for (src, error) in [
        (
            "\"x",
            LexError::Unterminated {
                what: "string",
                line: 1,
            },
        ),
        (
            "a\n/* x",
            LexError::Unterminated {
                what: "block comment",
                line: 2,
            },
        ),
        (
            "r#\"x\"",
            LexError::Unterminated {
                what: "string",
                line: 1,
            },
        ),
        ("' ", LexError::BareQuote { line: 1 }),
    ] {
        assert_eq!(lex(src), Err(error), "{src}");
    }
}

// ---------------------------------------------------------------------------
// #10208 census machinery: a std-only lexer, an item parser and three
// allowlists that are closed sets (every row named, every count pinned).
// ---------------------------------------------------------------------------

/// The kind of one token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokKind {
    Ident,
    Lifetime,
    Str,
    Char,
    Num,
    Punct,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tok {
    kind: TokKind,
    text: String,
    line: usize,
}

/// Why a text does not lex; the census reports it instead of passing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LexError {
    Unterminated { what: &'static str, line: usize },
    BareQuote { line: usize },
}

fn is_ident_start(ch: char) -> bool {
    ch == '_' || ch.is_alphabetic()
}

fn is_ident_char(ch: char) -> bool {
    ch == '_' || ch.is_alphanumeric()
}

struct Lexer {
    chars: Vec<char>,
    i: usize,
    line: usize,
    out: Vec<Tok>,
}

impl Lexer {
    fn at(&self, k: usize) -> Option<char> {
        self.chars.get(k).copied()
    }

    fn push(&mut self, kind: TokKind, from: usize, line: usize) {
        let text = self.chars[from..self.i].iter().collect();
        self.out.push(Tok { kind, text, line });
    }

    /// A nested block comment opening at `self.i`.
    fn block_comment(&mut self) -> Result<(), LexError> {
        let line = self.line;
        let mut depth = 0usize;
        loop {
            match (self.at(self.i), self.at(self.i + 1)) {
                (Some('/'), Some('*')) => {
                    depth += 1;
                    self.i += 2;
                }
                (Some('*'), Some('/')) => {
                    depth -= 1;
                    self.i += 2;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                (Some(ch), _) => {
                    if ch == '\n' {
                        self.line += 1;
                    }
                    self.i += 1;
                }
                (None, _) => {
                    return Err(LexError::Unterminated {
                        what: "block comment",
                        line,
                    });
                }
            }
        }
    }

    /// A string whose opening `"` is at `self.i`; the token starts at
    /// `from` (its prefix). A raw string has no escapes and closes on `"`
    /// followed by `hashes` hash marks.
    fn quoted(&mut self, from: usize, escapes: Escapes, hashes: usize) -> Result<(), LexError> {
        let line = self.line;
        self.i += 1;
        loop {
            match (self.at(self.i), escapes) {
                (None, _) => {
                    return Err(LexError::Unterminated {
                        what: "string",
                        line,
                    });
                }
                (Some('\\'), Escapes::Cooked) => {
                    if self.at(self.i + 1) == Some('\n') {
                        self.line += 1;
                    }
                    self.i += 2;
                }
                (Some('"'), _) if (1..=hashes).all(|h| self.at(self.i + h) == Some('#')) => {
                    self.i += 1 + hashes;
                    self.push(TokKind::Str, from, line);
                    return Ok(());
                }
                (Some(ch), _) => {
                    if ch == '\n' {
                        self.line += 1;
                    }
                    self.i += 1;
                }
            }
        }
    }

    /// A char literal or a lifetime whose `'` is at `self.i`.
    fn quote(&mut self, from: usize) -> Result<(), LexError> {
        let line = self.line;
        let q = self.i;
        if self.at(q + 1) == Some('\\') {
            let mut k = q + 3;
            while self.at(k).is_some_and(|ch| ch != '\'' && ch != '\n') {
                k += 1;
            }
            if self.at(k) != Some('\'') {
                return Err(LexError::Unterminated { what: "char", line });
            }
            self.i = k + 1;
            self.push(TokKind::Char, from, line);
            return Ok(());
        }
        if self.at(q + 2) == Some('\'') && self.at(q + 1).is_some_and(|ch| ch != '\n') {
            self.i = q + 3;
            self.push(TokKind::Char, from, line);
            return Ok(());
        }
        if self.at(q + 1).is_some_and(is_ident_start) {
            let mut k = q + 1;
            while self.at(k).is_some_and(is_ident_char) {
                k += 1;
            }
            self.i = k;
            self.push(TokKind::Lifetime, from, line);
            return Ok(());
        }
        Err(LexError::BareQuote { line })
    }

    /// An identifier, a keyword, a raw identifier or a prefixed literal.
    fn word(&mut self) -> Result<(), LexError> {
        let from = self.i;
        let line = self.line;
        while self.at(self.i).is_some_and(is_ident_char) {
            self.i += 1;
        }
        let word: String = self.chars[from..self.i].iter().collect();
        match (word.as_str(), self.at(self.i)) {
            ("r" | "br" | "cr", Some('"' | '#')) => {
                let mut hashes = 0;
                while self.at(self.i + hashes) == Some('#') {
                    hashes += 1;
                }
                if self.at(self.i + hashes) == Some('"') {
                    self.i += hashes;
                    return self.quoted(from, Escapes::Raw, hashes);
                }
                if word == "r" && hashes == 1 && self.at(self.i + 1).is_some_and(is_ident_start) {
                    // `r#name` is the identifier `name`.
                    self.i += 1;
                    let start = self.i;
                    while self.at(self.i).is_some_and(is_ident_char) {
                        self.i += 1;
                    }
                    self.push(TokKind::Ident, start, line);
                    return Ok(());
                }
                self.push(TokKind::Ident, from, line);
                Ok(())
            }
            ("b" | "c", Some('"')) => self.quoted(from, Escapes::Cooked, 0),
            ("b", Some('\'')) => self.quote(from),
            _ => {
                self.push(TokKind::Ident, from, line);
                Ok(())
            }
        }
    }

    fn number(&mut self) {
        let from = self.i;
        let line = self.line;
        loop {
            match self.at(self.i) {
                Some(ch) if is_ident_char(ch) => self.i += 1,
                Some('.') if self.at(self.i + 1).is_some_and(|d| d.is_ascii_digit()) => {
                    self.i += 1;
                }
                _ => break,
            }
        }
        self.push(TokKind::Num, from, line);
    }
}

/// Whether a string form takes backslash escapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Escapes {
    Cooked,
    Raw,
}

/// Tokens of `src`, comments dropped. Fails closed on an unterminated
/// string, char or block comment and on a bare quote.
fn lex(src: &str) -> Result<Vec<Tok>, LexError> {
    let mut lx = Lexer {
        chars: src.chars().collect(),
        i: 0,
        line: 1,
        out: Vec::new(),
    };
    while let Some(ch) = lx.at(lx.i) {
        match (ch, lx.at(lx.i + 1)) {
            ('\n', _) => {
                lx.line += 1;
                lx.i += 1;
            }
            ('/', Some('/')) => {
                while lx.at(lx.i).is_some_and(|c| c != '\n') {
                    lx.i += 1;
                }
            }
            ('/', Some('*')) => lx.block_comment()?,
            ('"', _) => lx.quoted(lx.i, Escapes::Cooked, 0)?,
            ('\'', _) => lx.quote(lx.i)?,
            _ if ch.is_whitespace() => lx.i += 1,
            _ if ch.is_ascii_digit() => lx.number(),
            _ if is_ident_start(ch) => lx.word()?,
            _ => {
                let from = lx.i;
                let line = lx.line;
                lx.i += 1;
                lx.push(TokKind::Punct, from, line);
            }
        }
    }
    Ok(lx.out)
}

fn join(t: &[Tok]) -> String {
    t.iter()
        .map(|k| k.text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The token form of an allowlist row written as natural Rust, with the
/// lock function's placeholder filled in.
fn norm(src: &str) -> String {
    let toks = lex(&src.replace(LOCK_FN_PLACEHOLDER, &token()))
        .unwrap_or_else(|e| panic!("allowlist row does not lex: {e:?}: {src}"));
    join(&toks)
}

fn is_p(t: &[Tok], i: usize, p: &str) -> bool {
    t.get(i)
        .is_some_and(|k| k.kind == TokKind::Punct && k.text == p)
}

fn is_w(t: &[Tok], i: usize, w: &str) -> bool {
    t.get(i)
        .is_some_and(|k| k.kind == TokKind::Ident && k.text == w)
}

fn line_at(t: &[Tok], i: usize) -> usize {
    t.get(i).or(t.last()).map_or(0, |k| k.line)
}

/// The kind of one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemKind {
    Fn,
    Const,
    Static,
    Type,
    Struct,
    Enum,
    Union,
    Impl,
    Trait,
    Mod,
    Use,
    MacroRules,
    MacroCall,
    ExternCrate,
    ExternBlock,
}

/// One parsed item: its parent label, kind, name and token text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Item {
    parent: String,
    kind: ItemKind,
    name: String,
    text: String,
}

/// Why the guard file does not parse as items; reported, never passed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseError {
    Unbalanced { line: usize },
    UnexpectedEnd { line: usize },
    NotAnItem { line: usize, text: String },
}

fn not_an_item(t: &[Tok], i: usize) -> ParseError {
    ParseError::NotAnItem {
        line: line_at(t, i),
        text: t.get(i).map_or_else(String::new, |k| k.text.clone()),
    }
}

/// Index just past the delimited group that opens at `i`.
fn skip_group(t: &[Tok], i: usize) -> Result<usize, ParseError> {
    let mut stack = Vec::new();
    let mut k = i;
    while let Some(tok) = t.get(k) {
        if tok.kind == TokKind::Punct {
            match tok.text.as_str() {
                "(" => stack.push(")"),
                "[" => stack.push("]"),
                "{" => stack.push("}"),
                close @ (")" | "]" | "}") => {
                    if stack.pop() != Some(close) {
                        return Err(ParseError::Unbalanced { line: tok.line });
                    }
                    if stack.is_empty() {
                        return Ok(k + 1);
                    }
                }
                _ => {}
            }
        }
        if stack.is_empty() {
            return Err(not_an_item(t, k));
        }
        k += 1;
    }
    Err(ParseError::UnexpectedEnd {
        line: line_at(t, i),
    })
}

/// Where an item head ends: at its `{` body or at its `;`.
enum End {
    Brace(usize),
    Semi(usize),
}

fn find_end(t: &[Tok], mut k: usize) -> Result<End, ParseError> {
    while let Some(tok) = t.get(k) {
        if tok.kind == TokKind::Punct {
            match tok.text.as_str() {
                "(" | "[" => {
                    k = skip_group(t, k)?;
                    continue;
                }
                "{" => return Ok(End::Brace(k)),
                ";" => return Ok(End::Semi(k)),
                _ => {}
            }
        }
        k += 1;
    }
    Err(ParseError::UnexpectedEnd {
        line: line_at(t, k),
    })
}

fn find_semi(t: &[Tok], mut k: usize) -> Result<usize, ParseError> {
    while let Some(tok) = t.get(k) {
        if tok.kind == TokKind::Punct {
            match tok.text.as_str() {
                "(" | "[" | "{" => {
                    k = skip_group(t, k)?;
                    continue;
                }
                ";" => return Ok(k),
                _ => {}
            }
        }
        k += 1;
    }
    Err(ParseError::UnexpectedEnd {
        line: line_at(t, k),
    })
}

fn ident_at(t: &[Tok], i: usize) -> Result<String, ParseError> {
    match t.get(i) {
        Some(k) if k.kind == TokKind::Ident => Ok(k.text.clone()),
        _ => Err(not_an_item(t, i)),
    }
}

/// Qualifier keywords that may precede an item keyword.
fn skip_qualifiers(t: &[Tok], mut i: usize) -> usize {
    const ITEM_WORDS: [&str; 10] = [
        "fn", "unsafe", "async", "extern", "impl", "trait", "const", "type", "mod", "static",
    ];
    let next_is_item = |k: usize| ITEM_WORDS.iter().any(|w| is_w(t, k, w));
    loop {
        let lead = ["unsafe", "async", "default", "safe", "auto"]
            .iter()
            .any(|w| is_w(t, i, w))
            && next_is_item(i + 1);
        let const_fn = is_w(t, i, "const")
            && ["fn", "unsafe", "async", "extern"]
                .iter()
                .any(|w| is_w(t, i + 1, w));
        if lead || const_fn {
            i += 1;
        } else if is_w(t, i, "extern")
            && t.get(i + 1).is_some_and(|k| k.kind == TokKind::Str)
            && is_w(t, i + 2, "fn")
        {
            i += 2;
        } else if is_w(t, i, "extern") && is_w(t, i + 1, "fn") {
            i += 1;
        } else {
            return i;
        }
    }
}

/// A parsed item head: where its text ends, where the next item starts and
/// the body to recurse into (`impl`, `trait` and inline `mod`).
struct Parsed {
    kind: ItemKind,
    name: String,
    text_end: usize,
    next: usize,
    body: Option<Body>,
}

struct Body {
    from: usize,
    to: usize,
    label: String,
}

fn after_group(t: &[Tok], open: usize) -> Result<usize, ParseError> {
    let close = skip_group(t, open)?;
    Ok(if is_p(t, close, ";") {
        close + 1
    } else {
        close
    })
}

/// The item whose keyword is at `i`.
fn classify(t: &[Tok], i: usize) -> Result<Parsed, ParseError> {
    let word = ident_at(t, i)?;
    let simple = |kind, name, end| Parsed {
        kind,
        name,
        text_end: end,
        next: end,
        body: None,
    };
    match word.as_str() {
        "fn" | "struct" | "enum" | "union" => {
            let kind = match word.as_str() {
                "fn" => ItemKind::Fn,
                "struct" => ItemKind::Struct,
                "enum" => ItemKind::Enum,
                _ => ItemKind::Union,
            };
            let name = ident_at(t, i + 1)?;
            let end = match find_end(t, i + 1)? {
                End::Brace(b) => skip_group(t, b)?,
                End::Semi(s) => s + 1,
            };
            Ok(simple(kind, name, end))
        }
        "impl" | "trait" | "mod" => {
            let kind = match word.as_str() {
                "impl" => ItemKind::Impl,
                "trait" => ItemKind::Trait,
                _ => ItemKind::Mod,
            };
            let name = if kind == ItemKind::Impl {
                String::new()
            } else {
                ident_at(t, i + 1)?
            };
            match find_end(t, i + 1)? {
                End::Brace(b) => {
                    let close = skip_group(t, b)?;
                    let (name, label) = if kind == ItemKind::Impl {
                        (join(&t[i + 1..b]), join(&t[i..b]))
                    } else {
                        let label = format!("{word} {name}");
                        (name, label)
                    };
                    Ok(Parsed {
                        kind,
                        name,
                        text_end: b,
                        next: close,
                        body: Some(Body {
                            from: b + 1,
                            to: close - 1,
                            label,
                        }),
                    })
                }
                End::Semi(s) => Ok(simple(kind, name, s + 1)),
            }
        }
        "const" | "static" | "type" | "use" => {
            let s = find_semi(t, i + 1)?;
            let (kind, name) = match word.as_str() {
                "use" => (ItemKind::Use, join(&t[i + 1..s])),
                "static" if is_w(t, i + 1, "mut") => (ItemKind::Static, ident_at(t, i + 2)?),
                "static" => (ItemKind::Static, ident_at(t, i + 1)?),
                "const" => (ItemKind::Const, ident_at(t, i + 1)?),
                _ => (ItemKind::Type, ident_at(t, i + 1)?),
            };
            Ok(simple(kind, name, s + 1))
        }
        "macro_rules" if is_p(t, i + 1, "!") => {
            let name = ident_at(t, i + 2)?;
            Ok(simple(ItemKind::MacroRules, name, after_group(t, i + 3)?))
        }
        "extern" if is_w(t, i + 1, "crate") => {
            let s = find_semi(t, i + 1)?;
            Ok(simple(ItemKind::ExternCrate, ident_at(t, i + 2)?, s + 1))
        }
        "extern" => match find_end(t, i + 1)? {
            End::Brace(b) => Ok(simple(
                ItemKind::ExternBlock,
                join(&t[i + 1..b]),
                skip_group(t, b)?,
            )),
            End::Semi(s) => Err(not_an_item(t, s)),
        },
        _ => {
            let mut k = i;
            while t.get(k).is_some_and(|x| {
                x.kind == TokKind::Ident || (x.kind == TokKind::Punct && x.text == ":")
            }) {
                k += 1;
            }
            if !is_p(t, k, "!") {
                return Err(not_an_item(t, i));
            }
            Ok(simple(
                ItemKind::MacroCall,
                join(&t[i..k]),
                after_group(t, k + 1)?,
            ))
        }
    }
}

/// Every item of `t`, nested `impl`, `trait` and `mod` bodies included.
fn parse_items(t: &[Tok], parent: &str, out: &mut Vec<Item>) -> Result<(), ParseError> {
    let mut i = 0;
    while i < t.len() {
        let start = i;
        while is_p(t, i, "#") {
            i += 1;
            if is_p(t, i, "!") {
                i += 1;
            }
            if !is_p(t, i, "[") {
                return Err(not_an_item(t, i));
            }
            i = skip_group(t, i)?;
        }
        if is_w(t, i, "pub") {
            i += 1;
            if is_p(t, i, "(") {
                i = skip_group(t, i)?;
            }
        }
        i = skip_qualifiers(t, i);
        let parsed = classify(t, i)?;
        out.push(Item {
            parent: parent.to_string(),
            kind: parsed.kind,
            name: parsed.name,
            text: join(&t[start..parsed.text_end]),
        });
        if let Some(body) = parsed.body {
            let label = if parent.is_empty() {
                body.label
            } else {
                format!("{parent} / {}", body.label)
            };
            parse_items(&t[body.from..body.to], &label, out)?;
        }
        i = parsed.next;
    }
    Ok(())
}

/// The lock function's name inside the allowlist rows below, filled in by
/// [`norm`] so this file never holds the token itself.
const LOCK_FN_PLACEHOLDER: &str = "__LOCK_FN__";

/// One permitted item of [`ALLOWED_FILE`], written as natural Rust.
struct AllowedItem {
    parent: &'static str,
    kind: ItemKind,
    name: &'static str,
    source: &'static str,
}

/// How many items [`ALLOWED_FILE`] holds, nested ones included.
const ENV_GUARD_ITEM_COUNT: usize = 9;

/// Every item of [`ALLOWED_FILE`]. A tenth item, or any change to one of
/// these, is a finding.
const ENV_GUARD_ITEMS: [AllowedItem; ENV_GUARD_ITEM_COUNT] = [
    AllowedItem {
        parent: "",
        kind: ItemKind::Fn,
        name: LOCK_FN_PLACEHOLDER,
        source: "fn __LOCK_FN__() -> &'static std::sync::Mutex<()> { static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(()); &LOCK }",
    },
    AllowedItem {
        parent: "",
        kind: ItemKind::Type,
        name: "OuterEnvLock",
        source: "type OuterEnvLock = crate::enterprise_federation_posture::hardened_env_fixture::EnvLockGuard<'static>;",
    },
    AllowedItem {
        parent: "",
        kind: ItemKind::Struct,
        name: "StoreUrlEnvGuard",
        source: "#[must_use = \"the store-url env lock is released when this guard drops\"] pub(crate) struct StoreUrlEnvGuard<'env> { _store_url: std::sync::MutexGuard<'static, ()>, _env: std::marker::PhantomData<&'env OuterEnvLock>, }",
    },
    AllowedItem {
        parent: "",
        kind: ItemKind::Impl,
        name: "<'env> StoreUrlEnvGuard<'env>",
        source: GUARD_IMPL,
    },
    AllowedItem {
        parent: GUARD_IMPL,
        kind: ItemKind::Fn,
        name: "acquire",
        source: "pub(crate) fn acquire(_env: &'env OuterEnvLock) -> Self { Self { _store_url: __LOCK_FN__().lock().unwrap_or_else(std::sync::PoisonError::into_inner), _env: std::marker::PhantomData, } }",
    },
    AllowedItem {
        parent: GUARD_IMPL,
        kind: ItemKind::Fn,
        name: "store_lock_is_held",
        source: "pub(crate) fn store_lock_is_held() -> bool { __LOCK_FN__().try_lock().is_err() }",
    },
    AllowedItem {
        parent: "",
        kind: ItemKind::Mod,
        name: "tests",
        source: "#[cfg(test)] mod tests",
    },
    AllowedItem {
        parent: "mod tests",
        kind: ItemKind::Use,
        name: "super::*",
        source: "use super::*;",
    },
    AllowedItem {
        parent: "mod tests",
        kind: ItemKind::Fn,
        name: "store_url_env_guard_holds_both_locks_8168",
        source: "#[test] fn store_url_env_guard_holds_both_locks_8168() { \
            let outer = crate::enterprise_federation_posture::hardened_env_fixture::EnvLockGuard::acquire(); \
            let probe = || { std::thread::scope(|s| { s.spawn(|| { ( \
            crate::test_support::env_mutex().try_lock().is_err(), \
            StoreUrlEnvGuard::store_lock_is_held(), ) }).join().expect(\"probe thread\") }) }; \
            { let _g = StoreUrlEnvGuard::acquire(&outer); \
            assert_eq!(probe(), (true, true), \"both locks are held under the guard\"); } \
            assert_eq!(probe(), (true, false)); }",
    },
];

/// A finding of the item census of [`ALLOWED_FILE`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum ItemFinding {
    FileMissing,
    Lex(LexError),
    Parse(ParseError),
    CountMismatch {
        expected: usize,
        found: usize,
    },
    Unlisted {
        parent: String,
        kind: ItemKind,
        name: String,
    },
    Changed {
        parent: String,
        kind: ItemKind,
        name: String,
    },
    Missing {
        parent: String,
        kind: ItemKind,
        name: String,
    },
    Duplicate {
        parent: String,
        kind: ItemKind,
        name: String,
    },
}

fn same_key(a: &Item, b: &Item) -> bool {
    a.parent == b.parent && a.kind == b.kind && a.name == b.name
}

fn item_census(files: &[(String, String)]) -> Vec<ItemFinding> {
    let Some((_, text)) = files.iter().find(|(p, _)| p == ALLOWED_FILE) else {
        return vec![ItemFinding::FileMissing];
    };
    let toks = match lex(text) {
        Ok(t) => t,
        Err(e) => return vec![ItemFinding::Lex(e)],
    };
    let mut items = Vec::new();
    if let Err(e) = parse_items(&toks, "", &mut items) {
        return vec![ItemFinding::Parse(e)];
    }
    let rows: Vec<Item> = ENV_GUARD_ITEMS
        .iter()
        .map(|r| Item {
            parent: norm(r.parent),
            kind: r.kind,
            name: norm(r.name),
            text: norm(r.source),
        })
        .collect();
    let mut found = Vec::new();
    if items.len() != ENV_GUARD_ITEM_COUNT {
        found.push(ItemFinding::CountMismatch {
            expected: ENV_GUARD_ITEM_COUNT,
            found: items.len(),
        });
    }
    for it in &items {
        let (parent, kind, name) = (it.parent.clone(), it.kind, it.name.clone());
        match rows.iter().find(|r| same_key(r, it)) {
            None => found.push(ItemFinding::Unlisted { parent, kind, name }),
            Some(r) if r.text != it.text => found.push(ItemFinding::Changed { parent, kind, name }),
            Some(_) => {}
        }
    }
    for r in &rows {
        let (parent, kind, name) = (r.parent.clone(), r.kind, r.name.clone());
        match items.iter().filter(|it| same_key(r, it)).count() {
            0 => found.push(ItemFinding::Missing { parent, kind, name }),
            1 => {}
            _ => found.push(ItemFinding::Duplicate { parent, kind, name }),
        }
    }
    found
}

/// The guard type's name.
const GUARD_TYPE: &str = "StoreUrlEnvGuard";

/// One statement outside [`ALLOWED_FILE`] that may name the guard type
/// other than as a call of `acquire`.
struct GuardUse {
    file: &'static str,
    statement: &'static str,
}

/// How many such statements the tree holds.
const GUARD_USE_COUNT: usize = 2;

const GUARD_USES: [GuardUse; GUARD_USE_COUNT] = [
    // The re-export the test modules name the guard by.
    GuardUse {
        file: "src/store_url.rs",
        statement: "; #[cfg(test)] pub(crate) use env_guard::StoreUrlEnvGuard;",
    },
    // A fixture that returns a guard it took with `acquire`.
    GuardUse {
        file: "src/cli/backup/tests/signed_manifest_3199.rs",
        statement: "; fn lock<'env>(env: &'env crate::enterprise_federation_posture::hardened_env_fixture::EnvLockGuard<'static>,) -> crate::store_url::StoreUrlEnvGuard<'env> {",
    },
];

/// A finding of the use census.
#[derive(Debug, Clone, PartialEq, Eq)]
enum UseFinding {
    Lex {
        file: String,
        error: LexError,
    },
    Unlisted {
        file: String,
        line: usize,
        statement: String,
    },
    Missing {
        file: String,
        statement: String,
    },
    Duplicate {
        file: String,
        statement: String,
    },
}

/// The tokens from the previous `;`, `{` or `}` to the next one, inclusive
/// of the closing one: the statement or item head around token `k`.
fn statement_at(t: &[Tok], k: usize) -> String {
    let boundary =
        |tok: &Tok| tok.kind == TokKind::Punct && matches!(tok.text.as_str(), ";" | "{" | "}");
    let from = t[..k].iter().rposition(boundary).unwrap_or(0);
    let to = t[k..]
        .iter()
        .position(boundary)
        .map_or(t.len(), |b| k + b + 1);
    join(&t[from..to])
}

fn use_census(files: &[(String, String)]) -> Vec<UseFinding> {
    let rows: Vec<(&str, String)> = GUARD_USES
        .iter()
        .map(|r| (r.file, norm(r.statement)))
        .collect();
    let mut seen = vec![0usize; rows.len()];
    let mut found = Vec::new();
    for (path, text) in files {
        if path == ALLOWED_FILE || !text.contains(GUARD_TYPE) {
            continue;
        }
        let toks = match lex(text) {
            Ok(t) => t,
            Err(error) => {
                found.push(UseFinding::Lex {
                    file: path.clone(),
                    error,
                });
                continue;
            }
        };
        for (k, tok) in toks.iter().enumerate() {
            if tok.kind != TokKind::Ident || tok.text != GUARD_TYPE {
                continue;
            }
            if is_p(&toks, k + 1, ":")
                && is_p(&toks, k + 2, ":")
                && is_w(&toks, k + 3, "acquire")
                && is_p(&toks, k + 4, "(")
            {
                continue;
            }
            let statement = statement_at(&toks, k);
            match rows.iter().position(|(f, s)| f == path && *s == statement) {
                Some(r) => seen[r] += 1,
                None => found.push(UseFinding::Unlisted {
                    file: path.clone(),
                    line: tok.line,
                    statement,
                }),
            }
        }
    }
    for ((file, statement), n) in rows.into_iter().zip(seen) {
        match n {
            0 => found.push(UseFinding::Missing {
                file: file.to_string(),
                statement,
            }),
            1 => {}
            _ => found.push(UseFinding::Duplicate {
                file: file.to_string(),
                statement,
            }),
        }
    }
    found
}

/// What a listed static is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StaticRole {
    /// The one lock over the store-url variables in the library tests.
    StoreUrlEnvLock,
    /// A test binary's own lock: a `tests/` binary is its own process, so
    /// it serialises only that binary's threads.
    OwnBinaryLock,
    /// Not a lock over the process environment.
    Unrelated,
}

/// One permitted static in a file that names the store-url variables.
struct StaticRow {
    file: &'static str,
    name: &'static str,
    role: StaticRole,
}

/// How many such statics the tree holds.
const STORE_URL_STATIC_COUNT: usize = 12;

const STORE_URL_STATICS: [StaticRow; STORE_URL_STATIC_COUNT] = [
    StaticRow {
        file: "src/enterprise_federation_posture/hardened_env_fixture.rs",
        name: "POSTURE_AUDIT_DIR",
        role: StaticRole::Unrelated,
    },
    StaticRow {
        file: "src/security_profile.rs",
        name: "BOOT_ENFORCEMENT",
        role: StaticRole::Unrelated,
    },
    StaticRow {
        file: "src/store/postgres.rs",
        name: "PG_BOOTSTRAP_TEST_LOCK",
        role: StaticRole::Unrelated,
    },
    StaticRow {
        file: "src/store/postgres.rs",
        name: "SQL_SELECT_MEMORY_ROW_BY_ID",
        role: StaticRole::Unrelated,
    },
    StaticRow {
        file: "src/store/postgres.rs",
        name: "SQL_SELECT_MEMORY_ROW_BY_ID_FOR_UPDATE",
        role: StaticRole::Unrelated,
    },
    StaticRow {
        file: "src/store/postgres.rs",
        name: "SQL_MERGE_INBOUND_FULL_ROW_UPDATE",
        role: StaticRole::Unrelated,
    },
    StaticRow {
        file: "src/store/postgres.rs",
        name: "RECORD_STOP_REFRESH_EPOCH",
        role: StaticRole::Unrelated,
    },
    StaticRow {
        file: "src/store/postgres/tx_retry.rs",
        name: "TX_RETRIES_TOTAL",
        role: StaticRole::Unrelated,
    },
    StaticRow {
        file: ALLOWED_FILE,
        name: "LOCK",
        role: StaticRole::StoreUrlEnvLock,
    },
    StaticRow {
        file: "tests/cov_backup_store_url_3521.rs",
        name: "STORE_URL_ENV_LOCK",
        role: StaticRole::OwnBinaryLock,
    },
    StaticRow {
        file: "tests/doctor_over_depth_4715.rs",
        name: "SERIAL",
        role: StaticRole::Unrelated,
    },
    StaticRow {
        file: "tests/lax_perms_hatches_doctor_sink_3813.rs",
        name: "LOCK",
        role: StaticRole::OwnBinaryLock,
    },
];

/// A file is in the static census when an identifier or a string literal in
/// its code holds this text: every store-url variable constant
/// (`STORE_URL_ENV`, `STORE_URL_FILE_ENV`, the lax-perms hatch) and every
/// spelled-out variable name does. Comments do not count.
const STORE_URL_TEXT: &str = "STORE_URL";

fn names_store_url(t: &[Tok]) -> bool {
    t.iter().any(|k| match k.kind {
        TokKind::Ident | TokKind::Str => k.text.contains(STORE_URL_TEXT),
        TokKind::Lifetime | TokKind::Char | TokKind::Num | TokKind::Punct => false,
    })
}

/// A finding of the static census.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StaticFinding {
    Lex {
        file: String,
        error: LexError,
    },
    Unlisted {
        file: String,
        name: String,
        line: usize,
    },
    Missing {
        file: String,
        name: String,
    },
    Duplicate {
        file: String,
        name: String,
    },
}

fn static_census(files: &[(String, String)]) -> Vec<StaticFinding> {
    let mut seen = [0usize; STORE_URL_STATIC_COUNT];
    let mut found = Vec::new();
    for (path, text) in files {
        if path != ALLOWED_FILE && !text.contains(STORE_URL_TEXT) {
            continue;
        }
        let toks = match lex(text) {
            Ok(t) => t,
            Err(error) => {
                found.push(StaticFinding::Lex {
                    file: path.clone(),
                    error,
                });
                continue;
            }
        };
        if path != ALLOWED_FILE && !names_store_url(&toks) {
            continue;
        }
        for k in (0..toks.len()).filter(|&k| is_w(&toks, k, "static")) {
            let mut n = k + 1;
            while is_w(&toks, n, "mut") || is_w(&toks, n, "ref") {
                n += 1;
            }
            let Some(name) = toks.get(n).filter(|x| x.kind == TokKind::Ident) else {
                continue;
            };
            if !is_p(&toks, n + 1, ":") {
                continue;
            }
            match STORE_URL_STATICS
                .iter()
                .position(|r| r.file == path && r.name == name.text)
            {
                Some(r) => seen[r] += 1,
                None => found.push(StaticFinding::Unlisted {
                    file: path.clone(),
                    name: name.text.clone(),
                    line: name.line,
                }),
            }
        }
    }
    for (r, n) in STORE_URL_STATICS.iter().zip(seen) {
        let (file, name) = (r.file.to_string(), r.name.to_string());
        match n {
            0 => found.push(StaticFinding::Missing { file, name }),
            1 => {}
            _ => found.push(StaticFinding::Duplicate { file, name }),
        }
    }
    found
}

/// One finding of [`census_all`], tagged by the part that found it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Finding {
    Line(Violation),
    Item(ItemFinding),
    Use(UseFinding),
    Static(StaticFinding),
}

/// All four parts of the census over the whole tree.
fn census_all(files: &[(String, String)]) -> Vec<Finding> {
    census(files)
        .into_iter()
        .map(Finding::Line)
        .chain(item_census(files).into_iter().map(Finding::Item))
        .chain(use_census(files).into_iter().map(Finding::Use))
        .chain(static_census(files).into_iter().map(Finding::Static))
        .collect()
}

// ---------------------------------------------------------------------
// #10213 / #10204 r2: mutants the text-match static census lets through.
// Each mutant edits the live tree in memory only; the census must report it.
// ---------------------------------------------------------------------

/// One in-memory mutant: tails appended to tree files.
struct Mutant {
    /// Test-facing name.
    id: &'static str,
    /// `(file, tail)` pairs appended in order.
    edits: &'static [(&'static str, &'static str)],
}

/// The file the lock-static mutants land in: it names no store-url
/// variable, so the text-match census never lexed it (#10213).
const SUPPORT: &str = "src/test_support.rs";

/// #10213: a lock static in `src/test_support.rs` and a store-url test that
/// takes it around an env write.
const M_SUPPORT_LOCK: Mutant = Mutant {
    id: "support-lock-taken-by-store-url-test",
    edits: &[
        (
            SUPPORT,
            "#[cfg(test)]\npub(crate) static STORE_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());\n",
        ),
        (
            "src/store_url.rs",
            "#[cfg(test)]\nmod serial_taker {\n    #[test]\n    fn takes_the_support_lock() {\n        let _g = crate::test_support::STORE_SERIAL.lock();\n        unsafe { std::env::remove_var(super::STORE_URL_ENV) };\n    }\n}\n",
        ),
    ],
};

const M_DIRECT: Mutant = Mutant {
    id: "direct-mutex",
    edits: &[(
        SUPPORT,
        "static FORM_DIRECT: std::sync::Mutex<()> = std::sync::Mutex::new(());\n",
    )],
};

const M_ALIAS: Mutant = Mutant {
    id: "type-alias",
    edits: &[(
        SUPPORT,
        "type FormLock = std::sync::Mutex<()>;\nstatic FORM_ALIAS: FormLock = FormLock::new(());\n",
    )],
};

const M_LAZY: Mutant = Mutant {
    id: "lazy-lock",
    edits: &[(
        SUPPORT,
        "static FORM_LAZY: std::sync::LazyLock<std::sync::Mutex<()>> =\n    std::sync::LazyLock::new(|| std::sync::Mutex::new(()));\n",
    )],
};

const M_ONCE_IN_FN: Mutant = Mutant {
    id: "once-lock-rwlock-in-fn-body",
    edits: &[(
        SUPPORT,
        "fn form_once() -> &'static std::sync::RwLock<()> {\n    static FORM_ONCE: std::sync::OnceLock<std::sync::RwLock<()>> = std::sync::OnceLock::new();\n    FORM_ONCE.get_or_init(|| std::sync::RwLock::new(()))\n}\n",
    )],
};

const M_THREAD_LOCAL: Mutant = Mutant {
    id: "thread-local",
    edits: &[(
        SUPPORT,
        "thread_local! {\n    static FORM_LOCAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };\n}\n",
    )],
};

const M_STATIC_REF: Mutant = Mutant {
    id: "lazy-static-ref",
    edits: &[(
        SUPPORT,
        "lazy_static::lazy_static! {\n    static ref FORM_REF: std::sync::Mutex<()> = std::sync::Mutex::new(());\n}\n",
    )],
};

const M_STATIC_MUT: Mutant = Mutant {
    id: "static-mut",
    edits: &[(SUPPORT, "static mut FORM_MUT: bool = false;\n")],
};

const M_MACRO: Mutant = Mutant {
    id: "macro-built-static",
    edits: &[(
        SUPPORT,
        "macro_rules! form_lock {\n    ($n:ident) => {\n        static $n: std::sync::Mutex<()> = std::sync::Mutex::new(());\n    };\n}\nform_lock!(FORM_MACRO);\n",
    )],
};

const M_DUPLICATE: Mutant = Mutant {
    id: "second-static-with-a-listed-name",
    edits: &[(
        SUPPORT,
        "fn second_lock() -> &'static std::sync::Mutex<()> {\n    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());\n    &LOCK\n}\n",
    )],
};

const M_TESTS_DIR: Mutant = Mutant {
    id: "tests-dir",
    edits: &[(
        "tests/auto_atomise/core.rs",
        "static FORM_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());\n",
    )],
};

const M_BENCHES_DIR: Mutant = Mutant {
    id: "benches-dir",
    edits: &[(
        "benches/harness_bench.rs",
        "static FORM_BENCH: std::sync::Mutex<()> = std::sync::Mutex::new(());\n",
    )],
};

/// The guard file compiled a second time through `#[path]`.
const M_PATH: Mutant = Mutant {
    id: "path-attr",
    edits: &[(
        SUPPORT,
        "#[cfg(test)]\n#[path = \"store_url/env_guard.rs\"]\nmod env_guard_dup;\n",
    )],
};

const M_CFG_ATTR_PATH: Mutant = Mutant {
    id: "cfg-attr-path",
    edits: &[(
        SUPPORT,
        "#[cfg_attr(test, path = \"store_url/env_guard.rs\")]\nmod env_guard_dup;\n",
    )],
};

const M_PATH_UPPER: Mutant = Mutant {
    id: "path-upper-case",
    edits: &[(
        SUPPORT,
        "#[path = \"store_url/ENV_GUARD.RS\"]\nmod env_guard_dup;\n",
    )],
};

const M_PATH_ESCAPED: Mutant = Mutant {
    id: "path-escaped",
    edits: &[(
        SUPPORT,
        "#[path = \"store_url/env\\x5fguard.rs\"]\nmod env_guard_dup;\n",
    )],
};

const M_PATH_RAW: Mutant = Mutant {
    id: "path-raw-string",
    edits: &[(
        SUPPORT,
        "#[path = r#\"store_url/env_guard.rs\"#]\nmod env_guard_dup;\n",
    )],
};

const M_PATH_BACKSLASH: Mutant = Mutant {
    id: "path-backslash",
    edits: &[(
        SUPPORT,
        "#[path = \"store_url\\\\env_guard.rs\"]\nmod env_guard_dup;\n",
    )],
};

/// The parent module compiled again: it declares `mod env_guard;`.
const M_PATH_PARENT: Mutant = Mutant {
    id: "path-parent-module",
    edits: &[(SUPPORT, "#[path = \"store_url.rs\"]\nmod store_url_dup;\n")],
};

const M_INCLUDE: Mutant = Mutant {
    id: "include",
    edits: &[(SUPPORT, "include!(\"store_url/env_guard.rs\");\n")],
};

const M_INCLUDE_CONCAT: Mutant = Mutant {
    id: "include-concat-env",
    edits: &[(
        SUPPORT,
        "include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/src/store_url/env_guard.rs\"));\n",
    )],
};

const M_INCLUDE_SPLIT: Mutant = Mutant {
    id: "include-split-concat",
    edits: &[(
        SUPPORT,
        "include!(concat!(\"store_url/env_\", \"guard.rs\"));\n",
    )],
};

const M_INCLUDE_NOT_LITERAL: Mutant = Mutant {
    id: "include-not-literal",
    edits: &[(SUPPORT, "include!(env!(\"GUARD_PATH\"));\n")],
};

const M_MOD_ELSEWHERE: Mutant = Mutant {
    id: "mod-store-url-in-a-second-root",
    edits: &[("src/main.rs", "mod store_url;\n")],
};

/// The live tree with every edit of `m` applied; also returns the line of
/// the first appended line of each edit, in edit order.
fn apply(m: &Mutant) -> (Vec<(String, String)>, Vec<usize>) {
    let mut files = tree();
    let mut firsts = Vec::new();
    for (rel, tail) in m.edits {
        let entry = files
            .iter_mut()
            .find(|(p, _)| p == rel)
            .unwrap_or_else(|| panic!("{}: mutant target {rel} is not in the tree", m.id));
        if !entry.1.ends_with('\n') {
            entry.1.push('\n');
        }
        firsts.push(entry.1.lines().count() + 1);
        entry.1.push_str(tail);
    }
    (files, firsts)
}

/// Red-first form: the census must find something in the mutant.
fn assert_mutant_red(m: &Mutant) {
    let (files, _) = apply(m);
    let found = census_all(&files);
    assert!(!found.is_empty(), "mutant {} passed the census", m.id);
}

#[test]
fn mutant_support_lock_taken_by_store_url_test_is_red_10213() {
    assert_mutant_red(&M_SUPPORT_LOCK);
}

#[test]
fn mutant_static_direct_mutex_is_red_10213() {
    assert_mutant_red(&M_DIRECT);
}

#[test]
fn mutant_static_type_alias_is_red_10213() {
    assert_mutant_red(&M_ALIAS);
}

#[test]
fn mutant_static_lazy_lock_is_red_10213() {
    assert_mutant_red(&M_LAZY);
}

#[test]
fn mutant_static_once_lock_in_fn_body_is_red_10213() {
    assert_mutant_red(&M_ONCE_IN_FN);
}

#[test]
fn mutant_static_thread_local_is_red_10213() {
    assert_mutant_red(&M_THREAD_LOCAL);
}

#[test]
fn mutant_static_ref_is_red_10213() {
    assert_mutant_red(&M_STATIC_REF);
}

#[test]
fn mutant_static_mut_is_red_10213() {
    assert_mutant_red(&M_STATIC_MUT);
}

#[test]
fn mutant_static_built_by_macro_is_red_10213() {
    assert_mutant_red(&M_MACRO);
}

#[test]
fn mutant_static_second_listed_name_is_red_10213() {
    assert_mutant_red(&M_DUPLICATE);
}

#[test]
fn mutant_static_in_tests_dir_is_red_10213() {
    assert_mutant_red(&M_TESTS_DIR);
}

#[test]
fn mutant_static_in_benches_dir_is_red_10213() {
    assert_mutant_red(&M_BENCHES_DIR);
}

#[test]
fn mutant_guard_file_path_reinclusion_is_red_10204() {
    assert_mutant_red(&M_PATH);
}

#[test]
fn mutant_guard_file_cfg_attr_path_is_red_10204() {
    assert_mutant_red(&M_CFG_ATTR_PATH);
}

#[test]
fn mutant_guard_file_path_upper_case_is_red_10204() {
    assert_mutant_red(&M_PATH_UPPER);
}

#[test]
fn mutant_guard_file_path_escaped_is_red_10204() {
    assert_mutant_red(&M_PATH_ESCAPED);
}

#[test]
fn mutant_guard_file_path_raw_string_is_red_10204() {
    assert_mutant_red(&M_PATH_RAW);
}

#[test]
fn mutant_guard_file_path_backslash_is_red_10204() {
    assert_mutant_red(&M_PATH_BACKSLASH);
}

#[test]
fn mutant_guard_parent_module_path_is_red_10204() {
    assert_mutant_red(&M_PATH_PARENT);
}

#[test]
fn mutant_guard_file_include_is_red_10204() {
    assert_mutant_red(&M_INCLUDE);
}

#[test]
fn mutant_guard_file_include_concat_env_is_red_10204() {
    assert_mutant_red(&M_INCLUDE_CONCAT);
}

#[test]
fn mutant_guard_file_include_split_concat_is_red_10204() {
    assert_mutant_red(&M_INCLUDE_SPLIT);
}

#[test]
fn mutant_include_not_literal_is_red_10204() {
    assert_mutant_red(&M_INCLUDE_NOT_LITERAL);
}

#[test]
fn mutant_mod_store_url_in_second_root_is_red_10204() {
    assert_mutant_red(&M_MOD_ELSEWHERE);
}
