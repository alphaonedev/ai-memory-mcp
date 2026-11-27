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
//! lines let a new item through. `census_all` runs five parts:
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
//! 4. the static census (#10213): every `static` item of every walked Rust
//!    file (src/, tests/, benches/, examples/; inside a fn body, an `impl`
//!    or a macro such as `thread_local!` or `lazy_static!` too, `static mut`
//!    and `static ref` included, whatever the type is spelled as) must have
//!    its own row `path<TAB>name<TAB>reason` in
//!    `tests/store_url_env_guard_8168_statics.tsv`. A static with no row
//!    left is `Unlisted` with its path, name and line; a row with no static
//!    is `Missing`; a bad row is refused with its line; `static $x` in a
//!    macro body is `MacroStatic`, because its name is unknown until
//!    expansion. The table may only shrink, each row with its reason;
//! 5. the inclusion census (#10204): the guard file may be compiled once.
//!    `#[path = …]` (in `cfg_attr` too) and `include!`, `include_str!` or
//!    `include_bytes!` naming `env_guard.rs` or its parent `store_url.rs`
//!    (any case, `/` or `\`, escapes and raw strings decoded, `concat!` of
//!    literals and `env!("CARGO_MANIFEST_DIR")` joined) are red; a path or
//!    include argument that is not such a literal is red; `mod env_guard;`
//!    and `mod store_url;` must each occur exactly once, in
//!    `src/store_url.rs` and `src/lib.rs`.
//!
//! The walk refuses a symbolic link in the tree. The lexer is std only and
//! fails closed (an unterminated string or comment is a finding). A file it
//! cannot lex is reported once by the static census and skipped by the
//! inclusion census. Its limits: it does not expand macros, so an item
//! built by a macro from pieces is not seen by parts 2 and 3 (part 4 reports
//! `static $x`), and `concat!` or escaped spellings of the variable names
//! are not decoded by part 1.

use std::collections::{BTreeMap, BTreeSet};
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

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>, links: &mut Vec<String>) {
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
            walk(&path, root, out, links);
        } else if ft.is_symlink() {
            // A link is refused, never followed or skipped: what it names
            // could be compiled without the census reading it.
            links.push(rel_of(&path, root));
        } else if ft.is_file() && path.extension().is_some_and(|e| e == "rs") {
            let rel = rel_of(&path, root);
            let text = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            out.push((rel, text));
        }
    }
}

fn tree() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let mut links = Vec::new();
    walk(root, root, &mut files, &mut links);
    assert_eq!(links, Vec::<String>::new(), "{SYMLINK_REFUSAL}");
    files
}

/// The refusal for a symbolic link in the source tree.
const SYMLINK_REFUSAL: &str =
    "symbolic links in the source tree are refused: the census cannot judge what they name";

fn rel_of(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .expect("under root")
        .to_string_lossy()
        .replace('\\', "/")
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
            Finding::Include(IncludeFinding::ModCount {
                file: "src/store_url.rs",
                name: "env_guard",
                found: 0,
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
    let (rows, bad) = parse_table(STATICS_TABLE);
    assert_eq!(bad, Vec::<TableFinding>::new());
    let pick = |keep: &dyn Fn(&StaticRow) -> bool| -> Vec<(String, String)> {
        rows.iter()
            .filter(|r| keep(r))
            .map(|r| (r.path.clone(), r.name.clone()))
            .collect()
    };
    let want = vec![(ALLOWED_FILE.to_string(), "LOCK".to_string())];
    assert_eq!(pick(&|r| r.path == ALLOWED_FILE), want);
    assert_eq!(pick(&|r| r.reason.starts_with(STORE_URL_LOCK_REASON)), want);
}

/// The reason text of the one store-url env lock row.
const STORE_URL_LOCK_REASON: &str = "the store-url env lock;";

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

/// #10213: the allowlist of every `static` item of the walked tree, one row
/// per static: `path<TAB>name<TAB>reason`. Lines that start with `#` are
/// comments. A key that occurs twice in one file has two rows.
const STATICS_TABLE: &str = include_str!("store_url_env_guard_8168_statics.tsv");

/// The roots a table row's path may name.
const STATIC_ROOTS: [&str; 4] = ["src/", "tests/", "benches/", "examples/"];

/// The shortest reason a row may give, in visible characters.
const MIN_REASON_CHARS: usize = 10;

/// #10251: the number of rows of [`STATICS_TABLE`], pinned exactly, so a
/// row cannot be swapped or added without a change to this file.
const STATICS_TABLE_ROWS: usize = 627;

/// #10251: the closed vocabulary a row's reason starts with, as
/// `<category>: <reason>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    /// The static is or holds a `Mutex`, `RwLock`, `Condvar`, a reentrant
    /// lock or a `Semaphore`.
    Lock,
    /// An atomic value.
    Atomic,
    /// A value computed once that holds no lock.
    Once,
    /// A `thread_local!` value.
    ThreadLocal,
    /// Immutable data.
    Immutable,
    /// A value of a crate type that holds no lock.
    CrateType,
}

impl Category {
    const ALL: [Self; 6] = [
        Self::Lock,
        Self::Atomic,
        Self::Once,
        Self::ThreadLocal,
        Self::Immutable,
        Self::CrateType,
    ];

    const fn word(self) -> &'static str {
        match self {
            Self::Lock => "lock",
            Self::Atomic => "atomic",
            Self::Once => "once",
            Self::ThreadLocal => "thread-local",
            Self::Immutable => "immutable",
            Self::CrateType => "crate-type",
        }
    }
}

/// One parsed row of [`STATICS_TABLE`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticRow {
    path: String,
    name: String,
    category: Category,
    reason: String,
}

/// A row of the table that cannot be a row.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TableFinding {
    /// The row does not have exactly three tab-separated fields.
    Fields { line: usize, found: usize },
    /// The path is not a relative `.rs` path under one of [`STATIC_ROOTS`].
    BadPath { line: usize, path: String },
    /// The name is not a Rust identifier.
    BadName { line: usize, name: String },
    /// The reason has fewer than [`MIN_REASON_CHARS`] visible characters.
    ShortReason { line: usize },
    /// #10251: the reason does not start with `<category>: ` for a word of
    /// [`Category::ALL`]; `word` is the text before the first `:`, or the
    /// whole reason when it has none.
    Category { line: usize, word: String },
}

fn is_rust_ident(s: &str) -> bool {
    let mut cs = s.chars();
    cs.next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && cs.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn is_row_path(p: &str) -> bool {
    STATIC_ROOTS.iter().any(|r| p.starts_with(r))
        // Exact case on purpose: the walk takes `.rs` files only.
        && Path::new(p).extension().is_some_and(|e| e == "rs")
        && !p.contains("..")
        && !p.contains("//")
        && !p.contains('\\')
        && !p.chars().any(char::is_whitespace)
}

/// Parse the table; every line that is not a comment must be a good row.
fn parse_table(text: &str) -> (Vec<StaticRow>, Vec<TableFinding>) {
    let mut rows = Vec::new();
    let mut bad = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i + 1;
        if raw.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = raw.split('\t').collect();
        let [path, name, reason] = fields[..] else {
            bad.push(TableFinding::Fields {
                line,
                found: fields.len(),
            });
            continue;
        };
        let mut ok = true;
        if !is_row_path(path) {
            bad.push(TableFinding::BadPath {
                line,
                path: path.to_string(),
            });
            ok = false;
        }
        if !is_rust_ident(name) {
            bad.push(TableFinding::BadName {
                line,
                name: name.to_string(),
            });
            ok = false;
        }
        let visible = reason
            .chars()
            .filter(|c| !c.is_whitespace() && !c.is_control())
            .count();
        if visible < MIN_REASON_CHARS {
            bad.push(TableFinding::ShortReason { line });
            ok = false;
        }
        if ok {
            rows.push(StaticRow {
                path: path.to_string(),
                name: name.to_string(),
                category: Category::CrateType,
                reason: reason.to_string(),
            });
        }
    }
    (rows, bad)
}

/// A finding of the static census.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StaticFinding {
    /// A bad row of the table.
    Table(TableFinding),
    /// A file the lexer cannot read; the inclusion census skips it too.
    Lex { file: String, error: LexError },
    /// A static with no row left for its `(file, name)`.
    Unlisted {
        file: String,
        name: String,
        line: usize,
    },
    /// `static $name` inside a macro: the name is not known until expansion.
    MacroStatic { file: String, line: usize },
    /// A row with no static.
    Missing { file: String, name: String },
    /// #10251: a static whose type names a lock, with a row of its key whose
    /// category is not `lock`.
    LockNotLabelled {
        file: String,
        name: String,
        line: usize,
    },
}

/// Every `static` item of a lexed file: `(name, line)`, plus the lines of
/// `static $x` macro forms.
fn statics_of(t: &[Tok]) -> (Vec<(String, usize)>, Vec<usize>) {
    let mut named = Vec::new();
    let mut macros = Vec::new();
    for k in (0..t.len()).filter(|&k| is_w(t, k, "static")) {
        let mut n = k + 1;
        while is_w(t, n, "mut") || is_w(t, n, "ref") {
            n += 1;
        }
        if is_p(t, n, "$") {
            macros.push(t[k].line);
            continue;
        }
        let Some(name) = t.get(n).filter(|x| x.kind == TokKind::Ident) else {
            continue;
        };
        if is_p(t, n + 1, ":") {
            named.push((name.text.clone(), name.line));
        }
    }
    (named, macros)
}

/// The names the guard file can be compiled under: the file itself and its
/// parent module, which declares `mod env_guard;`.
const GUARDED_FILE_NAMES: [&str; 2] = ["env_guard.rs", "store_url.rs"];

/// `(module name, the one file allowed to declare it, as `mod NAME;`)`.
const GUARDED_MODS: [(&str, &str); 2] = [
    ("env_guard", "src/store_url.rs"),
    ("store_url", "src/lib.rs"),
];

/// The macros that paste a file into the current one.
const INCLUDE_MACROS: [&str; 3] = ["include", "include_str", "include_bytes"];

/// The one `env!` variable an include path may use: it names this crate.
const MANIFEST_DIR_VAR: &str = "CARGO_MANIFEST_DIR";

/// A finding of the inclusion census: the guard file may be compiled once.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IncludeFinding {
    /// `path = "…"` in an attribute names a guarded file.
    PathAttr {
        file: String,
        line: usize,
        value: String,
    },
    /// `path =` in an attribute is followed by something other than a literal.
    PathNotLiteral { file: String, line: usize },
    /// A string literal the census cannot decode (an unknown escape).
    Undecodable {
        file: String,
        line: usize,
        literal: String,
    },
    /// `include!`, `include_str!` or `include_bytes!` names a guarded file.
    Include {
        file: String,
        line: usize,
        value: String,
    },
    /// An include macro whose argument is not a literal, `concat!` of
    /// literals, or `env!("CARGO_MANIFEST_DIR")`.
    IncludeNotLiteral { file: String, line: usize },
    /// `mod NAME;` for a guarded module outside its one file.
    ModElsewhere {
        file: String,
        line: usize,
        name: &'static str,
    },
    /// #10250: `#[path]` or `include!` names a file that does not end in
    /// `.rs` (exact case), so the walk never reads it.
    NotRustFile {
        file: String,
        line: usize,
        value: String,
    },
    /// #10250: `#[path]` or `include!` names a `.rs` file the walk did not
    /// read: absolute, out of the root, under a skipped directory, or absent.
    Unwalked {
        file: String,
        line: usize,
        value: String,
    },
    /// #10250: `#[path]` inside an inline `mod NAME { … }` block, where the
    /// file it names depends on the module tree, which the census does not
    /// model; refused rather than guessed.
    PathInInlineMod {
        file: String,
        line: usize,
        value: String,
    },
    /// The guarded module is declared other than exactly once in its file.
    ModCount {
        file: &'static str,
        name: &'static str,
        found: usize,
    },
}

/// Why an include or path value is not judged.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ValueError {
    NotLiteral,
    Undecodable(String),
}

/// The value of a string literal token, escapes decoded.
fn decode_str(lit: &str) -> Result<String, ValueError> {
    let undecodable = || ValueError::Undecodable(lit.to_string());
    let body = lit.strip_prefix(['b', 'c']).unwrap_or(lit);
    if let Some(raw) = body.strip_prefix('r') {
        let hashes = raw.len() - raw.trim_start_matches('#').len();
        let fence = "#".repeat(hashes);
        return raw
            .strip_prefix(fence.as_str())
            .and_then(|s| s.strip_prefix('"'))
            .and_then(|s| s.strip_suffix(fence.as_str()))
            .and_then(|s| s.strip_suffix('"'))
            .map(str::to_string)
            .ok_or_else(undecodable);
    }
    let inner = body
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(undecodable)?;
    let mut out = String::new();
    let mut cs = inner.chars().peekable();
    while let Some(c) = cs.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match cs.next().ok_or_else(undecodable)? {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            '\\' => out.push('\\'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            '\n' => {
                while cs.peek().is_some_and(|c| c.is_whitespace()) {
                    cs.next();
                }
            }
            'x' => {
                let hex: String = [cs.next(), cs.next()].into_iter().flatten().collect();
                let v = u8::from_str_radix(&hex, 16).map_err(|_| undecodable())?;
                if hex.len() != 2 {
                    return Err(undecodable());
                }
                out.push(char::from(v));
            }
            'u' => {
                if cs.next() != Some('{') {
                    return Err(undecodable());
                }
                let hex: String = cs.by_ref().take_while(|&c| c != '}').collect();
                let v =
                    u32::from_str_radix(&hex.replace('_', ""), 16).map_err(|_| undecodable())?;
                out.push(char::from_u32(v).ok_or_else(undecodable)?);
            }
            _ => return Err(undecodable()),
        }
    }
    Ok(out)
}

/// Whether a path value names a guarded file: its last component, case
/// folded, with `/` and `\` both taken as separators.
fn names_guarded_file(value: &str) -> bool {
    value
        .split(['/', '\\'])
        .rfind(|c| !c.is_empty())
        .is_some_and(|last| {
            GUARDED_FILE_NAMES
                .iter()
                .any(|g| last.eq_ignore_ascii_case(g))
        })
}

/// The index of the token that closes the bracket opened at `open`.
fn close_of(t: &[Tok], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, k) in t.iter().enumerate().skip(open) {
        if k.kind != TokKind::Punct {
            continue;
        }
        match k.text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// One piece of an include argument: a literal or the manifest dir.
fn piece_value(t: &[Tok]) -> Result<String, ValueError> {
    match t {
        [s] if s.kind == TokKind::Str => decode_str(&s.text),
        [e, bang, open, var, close]
            if e.kind == TokKind::Ident
                && e.text == "env"
                && bang.text == "!"
                && open.text == "("
                && close.text == ")"
                && var.kind == TokKind::Str =>
        {
            if decode_str(&var.text)? == MANIFEST_DIR_VAR {
                Ok(String::new())
            } else {
                Err(ValueError::NotLiteral)
            }
        }
        _ => Err(ValueError::NotLiteral),
    }
}

/// The value of an include macro's argument tokens (inside its parens).
fn include_value(t: &[Tok]) -> Result<String, ValueError> {
    let is_concat = t.len() >= 4
        && is_w(t, 0, "concat")
        && is_p(t, 1, "!")
        && is_p(t, 2, "(")
        && close_of(t, 2) == Some(t.len() - 1);
    if !is_concat {
        return piece_value(t);
    }
    let inner = &t[3..t.len() - 1];
    let mut out = String::new();
    let mut from = 0;
    let mut depth = 0usize;
    for (i, k) in inner.iter().enumerate() {
        match (k.kind, k.text.as_str()) {
            (TokKind::Punct, "(" | "[" | "{") => depth += 1,
            (TokKind::Punct, ")" | "]" | "}") => depth = depth.saturating_sub(1),
            (TokKind::Punct, ",") if depth == 0 => {
                out.push_str(&piece_value(&inner[from..i])?);
                from = i + 1;
            }
            _ => {}
        }
    }
    if from < inner.len() {
        out.push_str(&piece_value(&inner[from..])?);
    }
    Ok(out)
}

fn undecodable(file: &str, line: usize, literal: String) -> IncludeFinding {
    IncludeFinding::Undecodable {
        file: file.to_string(),
        line,
        literal,
    }
}

/// The inclusion census of one lexed file; `mods` counts the guarded
/// module declarations met in their own files.
fn inclusions_of(
    path: &str,
    t: &[Tok],
    _walked: &BTreeSet<&str>,
    mods: &mut [usize; 2],
    found: &mut Vec<IncludeFinding>,
) {
    let file = || path.to_string();
    let (close, in_attr) = brackets(t);
    for (k, tok) in t.iter().enumerate() {
        if tok.kind != TokKind::Ident {
            continue;
        }
        // `path = <value>` inside an attribute, `cfg_attr` included.
        if tok.text == "path" && is_p(t, k + 1, "=") && in_attr[k] {
            match t.get(k + 2).filter(|v| v.kind == TokKind::Str) {
                None => found.push(IncludeFinding::PathNotLiteral {
                    file: file(),
                    line: tok.line,
                }),
                Some(v) => match decode_str(&v.text) {
                    Ok(value) if names_guarded_file(&value) => {
                        found.push(IncludeFinding::PathAttr {
                            file: file(),
                            line: tok.line,
                            value,
                        });
                    }
                    Ok(_) => {}
                    Err(_) => found.push(undecodable(path, tok.line, v.text.clone())),
                },
            }
        }
        if INCLUDE_MACROS.contains(&tok.text.as_str()) && is_p(t, k + 1, "!") && is_p(t, k + 2, "(")
        {
            let value =
                close[k + 2].map_or(Err(ValueError::NotLiteral), |c| include_value(&t[k + 3..c]));
            match value {
                Ok(value) if names_guarded_file(&value) => found.push(IncludeFinding::Include {
                    file: file(),
                    line: tok.line,
                    value,
                }),
                Ok(_) => {}
                Err(ValueError::NotLiteral) => found.push(IncludeFinding::IncludeNotLiteral {
                    file: file(),
                    line: tok.line,
                }),
                Err(ValueError::Undecodable(lit)) => found.push(undecodable(path, tok.line, lit)),
            }
        }
        if tok.text == "mod" && is_p(t, k + 2, ";") {
            for (m, (name, home)) in GUARDED_MODS.iter().enumerate() {
                if !is_w(t, k + 1, name) {
                    continue;
                }
                if path == *home {
                    mods[m] += 1;
                } else {
                    found.push(IncludeFinding::ModElsewhere {
                        file: file(),
                        line: tok.line,
                        name,
                    });
                }
            }
        }
    }
}

/// One pass over a file's brackets: the index of the closer of each
/// opener, and whether each token sits inside a `#[…]` or `#![…]`
/// attribute. Linear in the token count.
fn brackets(t: &[Tok]) -> (Vec<Option<usize>>, Vec<bool>) {
    let mut close = vec![None; t.len()];
    let mut in_attr = vec![false; t.len()];
    let mut stack: Vec<(usize, bool)> = Vec::new();
    let mut inside = 0usize;
    for (i, k) in t.iter().enumerate() {
        in_attr[i] = inside > 0;
        if k.kind != TokKind::Punct {
            continue;
        }
        match k.text.as_str() {
            "(" | "{" => stack.push((i, false)),
            "[" => {
                let attr = is_p(t, i.wrapping_sub(1), "#")
                    || (is_p(t, i.wrapping_sub(1), "!") && is_p(t, i.wrapping_sub(2), "#"));
                inside += usize::from(attr);
                stack.push((i, attr));
            }
            ")" | "]" | "}" => {
                if let Some((open, attr)) = stack.pop() {
                    close[open] = Some(i);
                    inside -= usize::from(attr);
                }
            }
            _ => {}
        }
    }
    (close, in_attr)
}

/// #10213 and #10204: the static census against [`STATICS_TABLE`] and the
/// inclusion census, over one lex of every walked file.
fn token_census(
    files: &[(String, String)],
    table: &str,
) -> (Vec<StaticFinding>, Vec<IncludeFinding>) {
    let (rows, bad) = parse_table(table);
    let mut statics: Vec<StaticFinding> = bad.into_iter().map(StaticFinding::Table).collect();
    let mut includes = Vec::new();
    // Rows left per file, then per name: a static takes one row.
    let mut left: BTreeMap<&str, BTreeMap<&str, usize>> = BTreeMap::new();
    for r in &rows {
        *left
            .entry(r.path.as_str())
            .or_default()
            .entry(r.name.as_str())
            .or_default() += 1;
    }
    let walked: BTreeSet<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    let mut mods = [0usize; 2];
    for (path, text) in files {
        let toks = match lex(text) {
            Ok(t) => t,
            Err(error) => {
                statics.push(StaticFinding::Lex {
                    file: path.clone(),
                    error,
                });
                continue;
            }
        };
        let (named, macros) = statics_of(&toks);
        for (name, line) in named {
            match left
                .get_mut(path.as_str())
                .and_then(|m| m.get_mut(name.as_str()))
            {
                Some(n) if *n > 0 => *n -= 1,
                _ => statics.push(StaticFinding::Unlisted {
                    file: path.clone(),
                    name,
                    line,
                }),
            }
        }
        for line in macros {
            statics.push(StaticFinding::MacroStatic {
                file: path.clone(),
                line,
            });
        }
        inclusions_of(path, &toks, &walked, &mut mods, &mut includes);
    }
    for r in &rows {
        if let Some(n) = left
            .get_mut(r.path.as_str())
            .and_then(|m| m.get_mut(r.name.as_str()))
            && *n > 0
        {
            *n -= 1;
            statics.push(StaticFinding::Missing {
                file: r.path.clone(),
                name: r.name.clone(),
            });
        }
    }
    for ((name, home), n) in GUARDED_MODS.iter().zip(mods) {
        if n != 1 {
            includes.push(IncludeFinding::ModCount {
                file: home,
                name,
                found: n,
            });
        }
    }
    (statics, includes)
}

/// One finding of [`census_all`], tagged by the part that found it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Finding {
    Line(Violation),
    Item(ItemFinding),
    Use(UseFinding),
    Static(StaticFinding),
    Include(IncludeFinding),
}

/// All five parts of the census over the whole tree.
fn census_all(files: &[(String, String)]) -> Vec<Finding> {
    let (statics, includes) = token_census(files, STATICS_TABLE);
    census(files)
        .into_iter()
        .map(Finding::Line)
        .chain(item_census(files).into_iter().map(Finding::Item))
        .chain(use_census(files).into_iter().map(Finding::Use))
        .chain(statics.into_iter().map(Finding::Static))
        .chain(includes.into_iter().map(Finding::Include))
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

fn st_unlisted(file: &str, name: &str, line: usize) -> Finding {
    Finding::Static(StaticFinding::Unlisted {
        file: file.into(),
        name: name.into(),
        line,
    })
}

fn path_attr(line: usize, value: &str) -> Finding {
    Finding::Include(IncludeFinding::PathAttr {
        file: SUPPORT.into(),
        line,
        value: value.into(),
    })
}

fn include_hit(line: usize, value: &str) -> Finding {
    Finding::Include(IncludeFinding::Include {
        file: SUPPORT.into(),
        line,
        value: value.into(),
    })
}

/// The census of mutant `m`, with the first appended line of each edit.
fn run(m: &Mutant) -> (Vec<Finding>, Vec<usize>) {
    let (files, firsts) = apply(m);
    (census_all(&files), firsts)
}

#[test]
fn mutant_support_lock_taken_by_store_url_test_is_red_10213() {
    let (got, f) = run(&M_SUPPORT_LOCK);
    assert_eq!(
        got,
        vec![st_unlisted(SUPPORT, "STORE_SERIAL", f[0] + 1)],
        "{}",
        M_SUPPORT_LOCK.id
    );
}

#[test]
fn mutant_static_direct_mutex_is_red_10213() {
    let (got, f) = run(&M_DIRECT);
    assert_eq!(
        got,
        vec![st_unlisted(SUPPORT, "FORM_DIRECT", f[0])],
        "{}",
        M_DIRECT.id
    );
}

#[test]
fn mutant_static_type_alias_is_red_10213() {
    let (got, f) = run(&M_ALIAS);
    assert_eq!(
        got,
        vec![st_unlisted(SUPPORT, "FORM_ALIAS", f[0] + 1)],
        "{}",
        M_ALIAS.id
    );
}

#[test]
fn mutant_static_lazy_lock_is_red_10213() {
    let (got, f) = run(&M_LAZY);
    assert_eq!(
        got,
        vec![st_unlisted(SUPPORT, "FORM_LAZY", f[0])],
        "{}",
        M_LAZY.id
    );
}

#[test]
fn mutant_static_once_lock_in_fn_body_is_red_10213() {
    let (got, f) = run(&M_ONCE_IN_FN);
    assert_eq!(
        got,
        vec![st_unlisted(SUPPORT, "FORM_ONCE", f[0] + 1)],
        "{}",
        M_ONCE_IN_FN.id
    );
}

#[test]
fn mutant_static_thread_local_is_red_10213() {
    let (got, f) = run(&M_THREAD_LOCAL);
    assert_eq!(
        got,
        vec![st_unlisted(SUPPORT, "FORM_LOCAL", f[0] + 1)],
        "{}",
        M_THREAD_LOCAL.id
    );
}

#[test]
fn mutant_static_ref_is_red_10213() {
    let (got, f) = run(&M_STATIC_REF);
    assert_eq!(
        got,
        vec![st_unlisted(SUPPORT, "FORM_REF", f[0] + 1)],
        "{}",
        M_STATIC_REF.id
    );
}

#[test]
fn mutant_static_mut_is_red_10213() {
    let (got, f) = run(&M_STATIC_MUT);
    assert_eq!(
        got,
        vec![st_unlisted(SUPPORT, "FORM_MUT", f[0])],
        "{}",
        M_STATIC_MUT.id
    );
}

#[test]
fn mutant_static_built_by_macro_is_red_10213() {
    let (got, f) = run(&M_MACRO);
    assert_eq!(
        got,
        vec![Finding::Static(StaticFinding::MacroStatic {
            file: SUPPORT.into(),
            line: f[0] + 2,
        })],
        "{}",
        M_MACRO.id
    );
}

#[test]
fn mutant_static_second_listed_name_is_red_10213() {
    let (got, f) = run(&M_DUPLICATE);
    assert_eq!(
        got,
        vec![st_unlisted(SUPPORT, "LOCK", f[0] + 1)],
        "{}",
        M_DUPLICATE.id
    );
}

#[test]
fn mutant_static_in_tests_dir_is_red_10213() {
    let (got, f) = run(&M_TESTS_DIR);
    assert_eq!(
        got,
        vec![st_unlisted(
            "tests/auto_atomise/core.rs",
            "FORM_TESTS",
            f[0]
        )],
        "{}",
        M_TESTS_DIR.id
    );
}

#[test]
fn mutant_static_in_benches_dir_is_red_10213() {
    let (got, f) = run(&M_BENCHES_DIR);
    assert_eq!(
        got,
        vec![st_unlisted("benches/harness_bench.rs", "FORM_BENCH", f[0])],
        "{}",
        M_BENCHES_DIR.id
    );
}

#[test]
fn mutant_guard_file_path_reinclusion_is_red_10204() {
    let (got, f) = run(&M_PATH);
    assert_eq!(
        got,
        vec![path_attr(f[0] + 1, "store_url/env_guard.rs")],
        "{}",
        M_PATH.id
    );
}

#[test]
fn mutant_guard_file_cfg_attr_path_is_red_10204() {
    let (got, f) = run(&M_CFG_ATTR_PATH);
    assert_eq!(
        got,
        vec![path_attr(f[0], "store_url/env_guard.rs")],
        "{}",
        M_CFG_ATTR_PATH.id
    );
}

#[test]
fn mutant_guard_file_path_upper_case_is_red_10204() {
    let (got, f) = run(&M_PATH_UPPER);
    assert_eq!(
        got,
        vec![path_attr(f[0], "store_url/ENV_GUARD.RS")],
        "{}",
        M_PATH_UPPER.id
    );
}

#[test]
fn mutant_guard_file_path_escaped_is_red_10204() {
    let (got, f) = run(&M_PATH_ESCAPED);
    assert_eq!(
        got,
        vec![path_attr(f[0], "store_url/env_guard.rs")],
        "{}",
        M_PATH_ESCAPED.id
    );
}

#[test]
fn mutant_guard_file_path_raw_string_is_red_10204() {
    let (got, f) = run(&M_PATH_RAW);
    assert_eq!(
        got,
        vec![path_attr(f[0], "store_url/env_guard.rs")],
        "{}",
        M_PATH_RAW.id
    );
}

#[test]
fn mutant_guard_file_path_backslash_is_red_10204() {
    let (got, f) = run(&M_PATH_BACKSLASH);
    assert_eq!(
        got,
        vec![path_attr(f[0], "store_url\\env_guard.rs")],
        "{}",
        M_PATH_BACKSLASH.id
    );
}

#[test]
fn mutant_guard_parent_module_path_is_red_10204() {
    let (got, f) = run(&M_PATH_PARENT);
    assert_eq!(
        got,
        vec![path_attr(f[0], "store_url.rs")],
        "{}",
        M_PATH_PARENT.id
    );
}

#[test]
fn mutant_guard_file_include_is_red_10204() {
    let (got, f) = run(&M_INCLUDE);
    assert_eq!(
        got,
        vec![include_hit(f[0], "store_url/env_guard.rs")],
        "{}",
        M_INCLUDE.id
    );
}

#[test]
fn mutant_guard_file_include_concat_env_is_red_10204() {
    let (got, f) = run(&M_INCLUDE_CONCAT);
    assert_eq!(
        got,
        vec![include_hit(f[0], "/src/store_url/env_guard.rs")],
        "{}",
        M_INCLUDE_CONCAT.id
    );
}

#[test]
fn mutant_guard_file_include_split_concat_is_red_10204() {
    let (got, f) = run(&M_INCLUDE_SPLIT);
    assert_eq!(
        got,
        vec![include_hit(f[0], "store_url/env_guard.rs")],
        "{}",
        M_INCLUDE_SPLIT.id
    );
}

#[test]
fn mutant_include_not_literal_is_red_10204() {
    let (got, f) = run(&M_INCLUDE_NOT_LITERAL);
    assert_eq!(
        got,
        vec![Finding::Include(IncludeFinding::IncludeNotLiteral {
            file: SUPPORT.into(),
            line: f[0],
        })],
        "{}",
        M_INCLUDE_NOT_LITERAL.id
    );
}

#[test]
fn mutant_mod_store_url_in_second_root_is_red_10204() {
    let (got, f) = run(&M_MOD_ELSEWHERE);
    assert_eq!(
        got,
        vec![Finding::Include(IncludeFinding::ModElsewhere {
            file: "src/main.rs".into(),
            line: f[0],
            name: "store_url",
        })],
        "{}",
        M_MOD_ELSEWHERE.id
    );
}

/// A second `mod store_url;` in its own file is red too.
#[test]
fn mod_store_url_twice_in_lib_is_red_10204() {
    let (files, _) = tree_appended("src/lib.rs", "pub mod store_url;\n");
    assert_eq!(
        census_all(&files),
        vec![Finding::Include(IncludeFinding::ModCount {
            file: "src/lib.rs",
            name: "store_url",
            found: 2,
        })]
    );
}

/// A row with no static is refused, and a bad row is refused with its line.
#[test]
fn table_rows_are_refused_exactly_10213() {
    let ghost = format!("{STATICS_TABLE}src/test_support.rs\tGHOST\tno such static anywhere\n");
    let (statics, includes) = token_census(&tree(), &ghost);
    assert_eq!(
        statics,
        vec![StaticFinding::Missing {
            file: SUPPORT.into(),
            name: "GHOST".into(),
        }]
    );
    assert_eq!(includes, Vec::<IncludeFinding>::new());
    let text = "# comment\n\
                src/a.rs\tA\tatomic: a reason long enough\n\
                src/a.rs\tB\n\
                \n\
                src/a.rs\tC\tr\textra\n\
                src/../x.rs\tD\tatomic: a reason long enough\n\
                lib/a.rs\tE\tatomic: a reason long enough\n\
                src/a.txt\tF\tatomic: a reason long enough\n\
                src/a b.rs\tG\tatomic: a reason long enough\n\
                src\\a.rs\tH\tatomic: a reason long enough\n\
                src/a.rs\t9x\tatomic: a reason long enough\n\
                src/a.rs\tI-J\tatomic: a reason long enough\n\
                src/a.rs\tK\tlock:   short  \n\
                src/a.rs\t\tatomic: a reason long enough\n";
    let (rows, bad) = parse_table(text);
    assert_eq!(
        rows,
        vec![StaticRow {
            path: "src/a.rs".into(),
            name: "A".into(),
            category: Category::Atomic,
            reason: "a reason long enough".into(),
        }]
    );
    assert_eq!(
        bad,
        vec![
            TableFinding::Fields { line: 3, found: 2 },
            TableFinding::Fields { line: 4, found: 1 },
            TableFinding::Fields { line: 5, found: 4 },
            TableFinding::BadPath {
                line: 6,
                path: "src/../x.rs".into()
            },
            TableFinding::BadPath {
                line: 7,
                path: "lib/a.rs".into()
            },
            TableFinding::BadPath {
                line: 8,
                path: "src/a.txt".into()
            },
            TableFinding::BadPath {
                line: 9,
                path: "src/a b.rs".into()
            },
            TableFinding::BadPath {
                line: 10,
                path: "src\\a.rs".into()
            },
            TableFinding::BadName {
                line: 11,
                name: "9x".into()
            },
            TableFinding::BadName {
                line: 12,
                name: "I-J".into()
            },
            TableFinding::ShortReason { line: 13 },
            TableFinding::BadName {
                line: 14,
                name: String::new()
            },
        ]
    );
    let (statics, _) = token_census(&[], "src/a.rs\tA\tshort\n");
    assert_eq!(
        statics,
        vec![
            StaticFinding::Table(TableFinding::Category {
                line: 1,
                word: "short".into()
            }),
            StaticFinding::Table(TableFinding::ShortReason { line: 1 }),
        ]
    );
}

/// #10251: the table holds exactly [`STATICS_TABLE_ROWS`] good rows.
#[test]
fn statics_table_row_count_is_pinned_10251() {
    let (rows, bad) = parse_table(STATICS_TABLE);
    assert_eq!(bad, Vec::<TableFinding>::new());
    assert_eq!(rows.len(), STATICS_TABLE_ROWS);
}

/// #10251: a reason outside the closed vocabulary is refused with its word;
/// every word of the vocabulary is accepted.
#[test]
fn category_outside_the_vocabulary_is_refused_10251() {
    let refused: &[(&str, &str)] = &[
        ("shared-state: a reason long enough", "shared-state"),
        ("Lock: a reason long enough", "Lock"),
        (" lock: a reason long enough", " lock"),
        ("lock:a reason long enough", "lock:a reason long enough"),
        ("a reason with no category", "a reason with no category"),
        ("locks: a reason long enough", "locks"),
        ("thread_local: a reason long enough", "thread_local"),
    ];
    for (reason, word) in refused {
        let (rows, bad) = parse_table(&format!("src/a.rs\tA\t{reason}\n"));
        assert_eq!(rows, Vec::<StaticRow>::new(), "{reason}");
        assert_eq!(
            bad,
            vec![TableFinding::Category {
                line: 1,
                word: (*word).to_string()
            }],
            "{reason}"
        );
    }
    let words: [(&str, Category); 6] = [
        ("lock", Category::Lock),
        ("atomic", Category::Atomic),
        ("once", Category::Once),
        ("thread-local", Category::ThreadLocal),
        ("immutable", Category::Immutable),
        ("crate-type", Category::CrateType),
    ];
    assert_eq!(words.len(), Category::ALL.len());
    for (word, category) in words {
        let (rows, bad) = parse_table(&format!("src/a.rs\tA\t{word}: a reason long enough\n"));
        assert_eq!(bad, Vec::<TableFinding>::new(), "{word}");
        assert_eq!(
            rows,
            vec![StaticRow {
                path: "src/a.rs".into(),
                name: "A".into(),
                category,
                reason: "a reason long enough".into(),
            }],
            "{word}"
        );
    }
}

/// #10251: the `(path, name)` keys of the `lock` rows, written by hand from
/// an independent reading of each static's type (every static whose type
/// is or holds a `Mutex`, `RwLock`, `Condvar`, `ReentrantLock`,
/// `ReentrantMutex` or `Semaphore`, directly or through a type of its own
/// file). A row relabelled away from `lock`, or a lock row added, is red.
const LOCK_ROWS: &[(&str, &str)] = &[
    ("src/approvals.rs", "EXECUTION_EXEMPTIONS"),
    ("src/approvals.rs", "LOCK"),
    ("src/approvals.rs", "SYNTHETIC_RULES"),
    ("src/audit.rs", "CRASH_SNAPSHOT_DIR"),
    ("src/audit.rs", "LOCK"),
    ("src/audit.rs", "VERIFY_AFTER_SNAPSHOT_FOR_TEST"),
    ("src/background/atomise_worker.rs", "LOCK"),
    ("src/cli/boot.rs", "LOCK"),
    ("src/cli/governance_install_defaults.rs", "LOCK"),
    ("src/cli/helpers.rs", "LOCK"),
    ("src/cli/install.rs", "LOCK"),
    ("src/cli/install.rs", "PATH_LOCK"),
    ("src/cli/shell.rs", "STDIN_LOCK"),
    ("src/config.rs", "ACTIVE_CAPABILITY_CONFIG"),
    ("src/config.rs", "ACTIVE_PERMISSIONS_MODE"),
    ("src/config.rs", "CAP_LOCK"),
    ("src/config.rs", "CONFIGURED_DEFAULT_NAMESPACE"),
    ("src/config.rs", "GATE_LOCK"),
    ("src/config.rs", "LOCK"),
    ("src/config/shape/detector.rs", "BOOT_ASSESSMENT"),
    ("src/embeddings.rs", "ACTIVE_EMBEDDING_SPACE"),
    ("src/embeddings.rs", "QUERY_EMBED_CACHE"),
    ("src/embeddings/test_hold_hook.rs", "HOLDS"),
    ("src/erasure/archive_sync.rs", "CURSORS"),
    ("src/erasure/archive_sync.rs", "FRONTIER"),
    ("src/erasure/archive_sync.rs", "REG"),
    ("src/erasure/mod.rs", "LOCK"),
    ("src/federation/freshness.rs", "LOOPS"),
    ("src/federation/freshness.rs", "TABLE"),
    ("src/federation/identity/outbound.rs", "GLOBAL"),
    ("src/federation/identity/resolver.rs", "M"),
    ("src/federation/peer_attestation.rs", "ENV_GUARD"),
    ("src/federation/peer_posture.rs", "BOOT_REPORT"),
    ("src/federation/push_dlq.rs", "LOCK"),
    ("src/federation/signing.rs", "M"),
    ("src/governance/audit.rs", "CHAIN"),
    ("src/governance/audit.rs", "DEFERRED_FORENSIC_OUTAGES"),
    ("src/governance/audit.rs", "LOCK"),
    ("src/governance/audit.rs", "SINK"),
    ("src/governance/mod.rs", "ACTIVE_PERMISSION_RULES"),
    ("src/handlers/agent_api_key.rs", "MINT_LIMITER"),
    ("src/handlers/approvals.rs", "CACHE"),
    (
        "src/handlers/federation_receive.rs",
        "QUARANTINE_METRIC_LOCK",
    ),
    ("src/handlers/mod.rs", "LOCK"),
    ("src/handlers/read_pool.rs", "REGISTRY"),
    ("src/handlers/tests.rs", "APPROVE_HMAC_TEST_LOCK"),
    ("src/handlers/tests.rs", "LOCK"),
    ("src/hnsw.rs", "EVICTION_RATE_RING"),
    ("src/hooks/timeouts.rs", "LOCK"),
    ("src/identity/keypair.rs", "LOCK"),
    ("src/identity/mod.rs", "LOCK"),
    ("src/inbox_wake.rs", "LOCK"),
    ("src/inbox_wake.rs", "RECIPIENT_SEQS"),
    ("src/llm.rs", "ENV_GUARD_1143"),
    ("src/main.rs", "LOCK"),
    ("src/mcp/mod.rs", "PRE_EVENT_ENFORCE_GATE"),
    ("src/mcp/mod.rs", "PRE_SIGNAL_SEND_GATE"),
    ("src/mcp/mod.rs", "SHARED_PERMISSION_RULES_GUARD"),
    ("src/mcp/registry.rs", "CACHE"),
    ("src/mcp/tools/capture_turn.rs", "LOCK"),
    ("src/mcp/tools/recall.rs", "M"),
    ("src/mcp/tools/rule_list.rs", "ENV_LOCK"),
    ("src/portability/import.rs", "IMPORT_TRACE_GUARD"),
    ("src/portability/import.rs", "IMPORT_TRACE_LOG"),
    ("src/recover/durability.rs", "LOCK"),
    ("src/recover/in_tx_fault.rs", "ARMED"),
    ("src/reranker.rs", "BUDGET_LOCK"),
    ("src/runtime_context.rs", "GLOBAL"),
    ("src/storage/connection.rs", "DB_PASSPHRASE"),
    ("src/storage/mod.rs", "CACHE"),
    ("src/storage/record_stop.rs", "SQLITE_FLAGS"),
    ("src/storage/schema_guard.rs", "LOCK"),
    ("src/store/postgres.rs", "PG_BOOTSTRAP_TEST_LOCK"),
    ("src/store/sqlite.rs", "OWNER_GATE_TEST_HOOK"),
    ("src/store_url/env_guard.rs", "LOCK"),
    ("src/subscriptions.rs", "DISPATCH_SEMAPHORE"),
    ("src/subscriptions.rs", "SSRF_ENV_GUARD"),
    ("src/subscriptions/unstarted.rs", "REGISTRY"),
    ("src/test_support.rs", "LOCK"),
    ("src/tls.rs", "LOCK"),
    ("tests/acyclicity_equal_instant_3041.rs", "FLAG_LOCK"),
    ("tests/admin_action_forensic_audit.rs", "LOCK"),
    ("tests/admin_audit_chain_913.rs", "LOCK"),
    ("tests/admin_header_pubkey_bind_8494.rs", "LOCK"),
    ("tests/admin_header_trust_credential_routes_8574.rs", "LOCK"),
    ("tests/agent_api_key_admin_route_3474.rs", "ENROLLED_ADMINS"),
    ("tests/agent_api_key_admin_route_3474.rs", "LOCK"),
    ("tests/agent_api_key_mint_principal_8535.rs", "LOCK"),
    ("tests/agent_attestation_integrity.rs", "ENV_LOCK"),
    ("tests/agent_attestation_postgres.rs", "ENV_LOCK"),
    ("tests/agent_key_hot_enroll_3418.rs", "ENV_LOCK"),
    ("tests/agent_key_stale_refresh_4066.rs", "LOCK"),
    ("tests/append_only_spine_flagon_g6.rs", "FLAG_LOCK"),
    ("tests/append_only_upsert_supersede_2948.rs", "FLAG_LOCK"),
    ("tests/approval_approver_hmac_8495.rs", "LOCK_8495"),
    ("tests/atomisation/core.rs", "M"),
    ("tests/atomisation/core.rs", "SLOT"),
    ("tests/audit_exoneration_asymmetry_l7.rs", "LOCK"),
    ("tests/audit_truncation_anchor_1850.rs", "LOCK"),
    ("tests/audit_watermark_after_commit_7241.rs", "CELL_LOCK"),
    ("tests/audit_watermark_db_id_scope_2955.rs", "LOCK"),
    (
        "tests/audit_watermark_requires_genesis_7228.rs",
        "CELL_LOCK",
    ),
    ("tests/audit_witness_rollback_7241.rs", "CELL_LOCK"),
    ("tests/audit_witness_truncation_1822.rs", "LOCK"),
    ("tests/auto_atomise/core.rs", "M"),
    ("tests/auto_atomise/core.rs", "SLOT"),
    ("tests/b4_config_cleanup.rs", "LOCK"),
    ("tests/batman_atomise_wiring_2983.rs", "LOCK"),
    ("tests/bias_displacement_invariants_2_6.rs", "M"),
    ("tests/bind_chain_depth_4492.rs", "SERIAL"),
    (
        "tests/bulk_post_commit_stages_2724.rs",
        "DISPATCH_CELL_LOCK",
    ),
    ("tests/capture_turn_security_integrity.rs", "ENV_LOCK"),
    ("tests/child_stdin_write_report_8734.rs", "SPAWN_LOCK"),
    ("tests/claim_bitemporal_recall_1834.rs", "M"),
    ("tests/claim_validtime_canonical_1834.rs", "M"),
    ("tests/cli_install_pretool_hook.rs", "ENV_LOCK"),
    ("tests/cli_pending_reject_3448.rs", "LOCK"),
    ("tests/cli_surface_cluster_r405.rs", "ENV_GUARD"),
    ("tests/cluster_f_perf_regressions.rs", "TRACE_GUARD"),
    ("tests/cluster_f_perf_regressions.rs", "TRACE_LOG"),
    ("tests/common/mod.rs", "ENV_LOCK"),
    ("tests/common/pg_isolate.rs", "PROCESS_CLONE"),
    ("tests/corrupt_governance_escape_4285.rs", "SERIAL"),
    ("tests/corrupt_governance_severed_4285.rs", "STAR"),
    ("tests/cov3_handlers_postgres.rs", "FED_ENV_LOCK"),
    ("tests/cov_backup_store_url_3521.rs", "STORE_URL_ENV_LOCK"),
    (
        "tests/cov_daemon_passphrase_posture_3521.rs",
        "ALLOW_LAX_ENV_LOCK",
    ),
    ("tests/cov_fupb_approvals.rs", "APPROVALS_GLOBAL_LOCK"),
    ("tests/cov_fupb_fed_signing.rs", "FED_SIGNING_ENV_LOCK"),
    ("tests/cov_ga2_federation.rs", "FED_ENV_LOCK"),
    ("tests/cov_ga2_handlers_b.rs", "GA2_LOCK"),
    ("tests/cov_ga2_pg_federation.rs", "FED_ENV_LOCK"),
    ("tests/cov_ga2_pg_handlers_2.rs", "ADMIN_ENV_LOCK"),
    ("tests/cov_ga2_r4_federation.rs", "FED_ENV_LOCK"),
    ("tests/cov_ga2_r4_handlers.rs", "LOCK"),
    ("tests/cov_handlers_gov_admin_1660.rs", "HMAC_LOCK"),
    ("tests/cov_postgres_lineage.rs", "FLAG_LOCK"),
    ("tests/cov_postgres_recovery.rs", "ENV_LOCK"),
    ("tests/cov_sal_refusal_arms_3521.rs", "FED_ENV_LOCK"),
    ("tests/cross_build_db_compat_8677.rs", "LOCK"),
    ("tests/curator_conserves_contradiction_g7.rs", "FLAG_LOCK"),
    ("tests/dispatch_integration.rs", "AUDIT_INIT_LOCK"),
    ("tests/doctor_over_depth_4715.rs", "SERIAL"),
    (
        "tests/embedding_space_provenance_2167.rs",
        "ACTIVE_SPACE_TEST_LOCK",
    ),
    (
        "tests/embedding_space_provenance_2167.rs",
        "STRICT_FLAG_GUARD",
    ),
    (
        "tests/embedding_space_provenance_2167_pg.rs",
        "PG_HEAL_ENV_LOCK",
    ),
    ("tests/embeddings_backfill_batch_config_1260.rs", "L"),
    ("tests/encryption_at_rest.rs", "ENV_GATE_LOCK"),
    ("tests/encryption_key_absent_3718.rs", "ENV_GATE_LOCK"),
    ("tests/encryption_upsert_key_2383.rs", "ENV_GATE_LOCK"),
    ("tests/erasure_cold_tier_2064.rs", "LOCK"),
    ("tests/f53_claimed_vs_attested_e2e.rs", "ENV_LOCK"),
    ("tests/fed_archive_restore_lane_3075.rs", "ENV_LOCK"),
    ("tests/fed_archive_restore_lane_3075_pg.rs", "FED_ENV_LOCK"),
    ("tests/fed_checkpoint_lane_3075_pg.rs", "FED_ENV_LOCK"),
    (
        "tests/fed_consolidate_source_attest_parity_2863.rs",
        "ENV_LOCK",
    ),
    ("tests/fed_inbound_stamp_3624.rs", "ENV_LOCK"),
    ("tests/fed_owner_floor_4285.rs", "ENV_LOCK"),
    ("tests/fed_pending_identity_quorum_2710_2720.rs", "ENV_LOCK"),
    ("tests/fed_require_server_verify_2448.rs", "LOCK"),
    ("tests/fed_rq_03_policy_refuse_stale.rs", "ENV_LOCK"),
    ("tests/federation_1566_embed_ship.rs", "LOCK"),
    ("tests/federation_1936_checkpoint_fed.rs", "ENV_LOCK"),
    ("tests/federation_2168_embed_fingerprint.rs", "LOCK"),
    (
        "tests/federation_by_id_scope_recheck_4447.rs",
        "SQLITE_CELLS",
    ),
    ("tests/federation_catchup_posture_3582.rs", "ENV_LOCK"),
    ("tests/federation_causal_order_3699.rs", "FED_ENV_LOCK"),
    ("tests/federation_checkpoint_ns_scope_2708.rs", "ENV_LOCK"),
    (
        "tests/federation_confine_ns_scope_2711_pg.rs",
        "FED_ENV_LOCK",
    ),
    ("tests/federation_delete_ns_scope_2488.rs", "ENV_LOCK"),
    (
        "tests/federation_delete_ns_scope_2488_pg.rs",
        "FED_ENV_LOCK",
    ),
    (
        "tests/federation_dequarantine_crossid_3901.rs",
        "FED_ENV_LOCK",
    ),
    ("tests/federation_inbox_wake_3631.rs", "FED_ENV_LOCK"),
    ("tests/federation_legacy_row_visibility_978.rs", "ENV_LOCK"),
    (
        "tests/federation_merge_scope_recheck_4023.rs",
        "FED_ENV_LOCK",
    ),
    (
        "tests/federation_namespace_meta_descendant_2536.rs",
        "ENV_LOCK",
    ),
    ("tests/federation_nonce_replay_922.rs", "LOCK"),
    ("tests/federation_ns_meta_ancestor_gate_4478.rs", "ENV_LOCK"),
    ("tests/federation_ns_meta_scope_2479.rs", "ENV_LOCK"),
    ("tests/federation_ns_meta_scope_2479_pg.rs", "FED_ENV_LOCK"),
    ("tests/federation_peer_enrolled_2912.rs", "ENV_LOCK"),
    ("tests/federation_pending_ns_scope_2478.rs", "ENV_LOCK"),
    (
        "tests/federation_pending_ns_scope_2478_pg.rs",
        "FED_ENV_LOCK",
    ),
    ("tests/federation_pending_reject_ns_2532.rs", "ENV_LOCK"),
    ("tests/federation_pending_resurrection_2529.rs", "ENV_LOCK"),
    ("tests/federation_plaintext_peer_2477.rs", "ENV_LOCK"),
    ("tests/federation_receive_coord_screen_3049.rs", "LOCK"),
    ("tests/federation_signal_authorship_1843.rs", "LOCK"),
    ("tests/federation_sync_push_catchup_sig_2297.rs", "LOCK"),
    ("tests/federation_sync_push_tofu_1056.rs", "LOCK"),
    ("tests/federation_sync_since_sig_1031.rs", "LOCK"),
    ("tests/federation_sync_since_watermark_2441.rs", "ENV_LOCK"),
    ("tests/federation_sync_state_merge_1709.rs", "LOCK"),
    ("tests/federation_write_ns_scope_2447.rs", "ENV_LOCK"),
    ("tests/federation_write_ns_scope_2447_pg.rs", "FED_ENV_LOCK"),
    ("tests/forensic/wt1e_chain_test.rs", "M"),
    ("tests/forensic_audit_log.rs", "LOCK"),
    ("tests/form_1_synthesis.rs", "LOCK"),
    ("tests/form_2_synchronous_atomise.rs", "M"),
    ("tests/form_4_provenance.rs", "M"),
    ("tests/fts_corrupt_vtab_9273.rs", "TRACE_9273"),
    (
        "tests/g3_postgres_verify_link_signature_roundtrip.rs",
        "LOCK",
    ),
    ("tests/g_issue_238_sender_attestation.rs", "ENV_LOCK"),
    ("tests/g_issue_239_sync_scope.rs", "ENV_LOCK"),
    ("tests/governance_audit_verdict_2634.rs", "LOCK"),
    ("tests/governance_chain_depth_4477.rs", "SERIAL"),
    ("tests/governance_l16_activation.rs", "LOCK"),
    ("tests/governance_policy_attribution_4044.rs", "LOCK"),
    ("tests/governance_policy_attribution_4044.rs", "TRIGGER_DB"),
    ("tests/governance_policy_attribution_4044.rs", "TRIGGER_SQL"),
    ("tests/governance_policy_read_fault_4043.rs", "ENV_LOCK"),
    ("tests/governance_policy_read_fault_4043_pg.rs", "ENV_LOCK"),
    ("tests/governance_pre_write_fxc5_sqlite.rs", "HOOK_MODE"),
    ("tests/governance_pre_write_fxc5_sqlite.rs", "M"),
    (
        "tests/governance_pre_write_postgres_parity.rs",
        "HOOK_VERDICT",
    ),
    ("tests/governance_pre_write_postgres_parity.rs", "M"),
    ("tests/governance_seed_ceremony_3430.rs", "LOCK"),
    ("tests/governance_storage_insert_hook.rs", "HOOK_MODE"),
    ("tests/governance_storage_insert_hook.rs", "M"),
    ("tests/governance_update_hook_1451.rs", "M"),
    ("tests/h2_invalidate_link_signed.rs", "ENV_GUARD"),
    (
        "tests/health_metrics_constant_cost_2579_2583.rs",
        "TRACE_LOG",
    ),
    ("tests/hot_swap_llm_2166.rs", "LOCK"),
    ("tests/http_capture_attestation_3406.rs", "TEST_LOCK"),
    ("tests/i4_memory_replay_authz.rs", "RULES_GUARD"),
    ("tests/identity_e2e.rs", "ENV_GUARD"),
    ("tests/inference_egress_proxy_redirect_4193.rs", "ENV_LOCK"),
    ("tests/issue_1213_atttypmod_age_schema_scope.rs", "LOCK"),
    ("tests/issue_1234_daemon_sentinel_bootstrap.rs", "LOCK"),
    ("tests/issue_2059_2060_covenant_pg.rs", "LOCK"),
    ("tests/issue_2059_2060_covenant_write_gates.rs", "LOCK"),
    ("tests/issue_2121_2122_2123_covenant_funnels.rs", "LOCK"),
    ("tests/issue_2122_synthesis_provenance_enforce.rs", "LOCK"),
    ("tests/issue_3627_retired_llm_alias.rs", "LOCK"),
    ("tests/issue_4357_reflect_approval_gate_parity.rs", "SERIAL"),
    ("tests/issue_800_batman_mode.rs", "ENV_LOCK"),
    ("tests/k10_approval_http.rs", "K10_HTTP_LOCK"),
    (
        "tests/k10_approval_postgres_dispatch_1618.rs",
        "K10_PG_DISPATCH_LOCK",
    ),
    ("tests/k10_approval_security.rs", "K10_SECURITY_LOCK"),
    ("tests/k10_remember_forever.rs", "REMEMBER_LOCK"),
    ("tests/k7_hmac.rs", "K7_HMAC_GLOBAL_LOCK"),
    ("tests/k9_kg_invalidate_governance_gate.rs", "LOCK"),
    ("tests/key_dir_posture_3198.rs", "LOCK"),
    ("tests/kg_query_visibility_3386.rs", "ENV_GUARD"),
    ("tests/l07_3_chunk_d_http_surface.rs", "HMAC_LOCK"),
    ("tests/lax_perms_hatches_doctor_sink_3813.rs", "LOCK"),
    (
        "tests/lifecycle_hidden_rows_unit1_3691_3693_3626.rs",
        "FLAG_LOCK",
    ),
    ("tests/lifecycle_owner_lock_pg_4053.rs", "SERIAL"),
    ("tests/lineage_boot_seed_2233.rs", "BOOT_LOCK"),
    ("tests/lineage_dag_g13.rs", "FLAG_LOCK"),
    ("tests/lineage_schema_masks_loss_3172.rs", "ENV_LOCK"),
    ("tests/mcp_agent_id_env_isolation_3475.rs", "LOCK"),
    ("tests/memory_verify.rs", "ENV_GUARD"),
    ("tests/migrate_lineage_roundtrip_3435.rs", "FLAG_LOCK"),
    ("tests/mtls_agent_binding_8357.rs", "LOCK"),
    ("tests/mtls_cert_peer_binding_2045.rs", "LOCK"),
    (
        "tests/node_local_containment_item3_r2_3266.rs",
        "FED_ENV_LOCK",
    ),
    ("tests/owner_gate_toctou_pg_3953.rs", "SERIAL"),
    ("tests/pg_lock_order_4209_4210.rs", "SERIAL"),
    ("tests/pg_lock_order_4329_4330.rs", "SERIAL"),
    ("tests/pg_sever_audit_event_3290.rs", "LOCK"),
    ("tests/pillar4_4d_age_unprojection_on_delete_1783.rs", "L"),
    ("tests/portability_lineage_cid_2215.rs", "FLAG_LOCK"),
    ("tests/postgres_cross_build_db_compat_8677.rs", "LOCK"),
    ("tests/postgres_schema_downgrade_guard_2445.rs", "LOCK"),
    ("tests/principal_binding_3363.rs", "ENV_GUARD"),
    ("tests/provenance_read_error_surfaces_9435.rs", "FLAG_LOCK"),
    ("tests/quarantine_operator_surface_2402.rs", "LOCK"),
    ("tests/query_embed_cache_2577.rs", "CACHE_TEST_LOCK"),
    ("tests/r40_airgapped_approval.rs", "ENV_LOCK"),
    ("tests/r40_approval_chokepoint.rs", "GLOBAL_LOCK"),
    ("tests/reanchor_ceremony_2004.rs", "LOCK"),
    ("tests/recall/wt1e.rs", "M"),
    ("tests/recall_purity_p01.rs", "LOCK"),
    ("tests/recall_purity_p01_postgres.rs", "LOCK"),
    ("tests/reflect_owner_env_binding_3423.rs", "LOCK"),
    ("tests/reflect_read_visibility_caller_3282.rs", "ENV_GUARD"),
    ("tests/retired_provider_aliases.rs", "LOCK"),
    ("tests/role_separation_1826.rs", "LOCK"),
    ("tests/rollback_evidence_1946.rs", "LOCK"),
    ("tests/schema_downgrade_guard_2445.rs", "LOCK"),
    ("tests/security_admin_wildcard_980.rs", "ENV_LOCK"),
    ("tests/security_authz_isolation_cluster.rs", "ENV_LOCK"),
    ("tests/serve_postgres_continuation2.rs", "HMAC_SECRET_LOCK"),
    ("tests/ship_gate/grand_slam_composition.rs", "LOCK"),
    ("tests/signal_recipient_validation_4408.rs", "ENV_LOCK"),
    ("tests/skill_scope_integrity_8832_8834.rs", "ENV_GUARD"),
    ("tests/skills_jail_caller_text_3762.rs", "SERIAL"),
    ("tests/sync_since_visibility_gate_948.rs", "ENV_LOCK"),
    ("tests/synthesis_ownership_gate_3173.rs", "LOCK"),
    ("tests/tls_import_daemon_3709.rs", "SANDBOX_LOCK"),
    ("tests/transit_encryption_3709_lib.rs", "ENV_LOCK"),
    ("tests/trust_propagation_1958_1959.rs", "FLAG_LOCK"),
    ("tests/unit_escape_4356_4357_4285.rs", "SERIAL"),
    ("tests/v070_a1_authn.rs", "A1_HMAC_LOCK"),
    ("tests/wake_hub_write_authority_3578.rs", "TEST_LOCK"),
    ("tests/webhook_terminal_refusal_3790.rs", "KNOB"),
    ("tests/wt1c_mcp_atomise.rs", "M"),
    ("tests/wt1c_mcp_atomise.rs", "SLOT"),
];

#[test]
fn lock_rows_are_the_hand_written_set_10251() {
    let (rows, _) = parse_table(STATICS_TABLE);
    let got: BTreeSet<(&str, &str)> = rows
        .iter()
        .filter(|r| r.category == Category::Lock)
        .map(|r| (r.path.as_str(), r.name.as_str()))
        .collect();
    let want: BTreeSet<(&str, &str)> = LOCK_ROWS.iter().copied().collect();
    assert_eq!(want.len(), LOCK_ROWS.len(), "LOCK_ROWS holds a duplicate");
    let extra: Vec<_> = got.difference(&want).collect();
    let lost: Vec<_> = want.difference(&got).collect();
    assert_eq!((extra, lost), (Vec::new(), Vec::new()));
}

/// #10251: a static whose type is or holds a lock, listed with a category
/// other than `lock`, is red in every form the type can name the lock.
#[test]
fn lock_static_not_labelled_lock_is_red_10251() {
    let forms: &[(&str, &str, usize)] = &[
        (
            "direct-mutex",
            "static FORM_L: std::sync::Mutex<()> = std::sync::Mutex::new(());\n",
            0,
        ),
        (
            "rwlock-in-once-lock",
            "static FORM_L: std::sync::OnceLock<std::sync::RwLock<u8>> = std::sync::OnceLock::new();\n",
            0,
        ),
        (
            "mutex-in-lazy-lock",
            "static FORM_L: std::sync::LazyLock<Mutex<u8>> =\n    std::sync::LazyLock::new(|| Mutex::new(0));\n",
            0,
        ),
        (
            "condvar",
            "static FORM_L: std::sync::Condvar = std::sync::Condvar::new();\n",
            0,
        ),
        (
            "type-alias",
            "type FormLockA = std::sync::Mutex<()>;\nstatic FORM_L: FormLockA = FormLockA::new(());\n",
            1,
        ),
        (
            "alias-of-alias",
            "type FormLockB = std::sync::RwLock<()>;\ntype FormLockC = FormLockB;\nstatic FORM_L: std::sync::OnceLock<FormLockC> = std::sync::OnceLock::new();\n",
            2,
        ),
        (
            "struct-wrapper",
            "struct FormWrap {\n    m: std::sync::Mutex<()>,\n}\nstatic FORM_L: std::sync::OnceLock<FormWrap> = std::sync::OnceLock::new();\n",
            3,
        ),
        (
            "tuple-struct-wrapper",
            "struct FormTuple(tokio::sync::Semaphore);\nstatic FORM_L: std::sync::OnceLock<FormTuple> = std::sync::OnceLock::new();\n",
            1,
        ),
        (
            "enum-wrapper",
            "enum FormEnum {\n    A(std::sync::Mutex<u8>),\n}\nstatic FORM_L: std::sync::OnceLock<FormEnum> = std::sync::OnceLock::new();\n",
            3,
        ),
        (
            "use-as-rename",
            "use std::sync::Mutex as FormM;\nstatic FORM_L: FormM<()> = FormM::new(());\n",
            1,
        ),
        (
            "reentrant",
            "static FORM_L: std::sync::ReentrantLock<()> = std::sync::ReentrantLock::new(());\n",
            0,
        ),
        (
            "static-mut",
            "static mut FORM_L: Option<std::sync::Mutex<()>> = None;\n",
            0,
        ),
        (
            "generic-assoc-binding",
            "static FORM_L: std::sync::OnceLock<Box<dyn Iterator<Item = u8> + Send>> = std::sync::OnceLock::new();\nstatic FORM_M: std::sync::OnceLock<(Box<dyn Fn() -> u8 + Sync>, std::sync::Mutex<u8>)> = std::sync::OnceLock::new();\n",
            1,
        ),
    ];
    for (id, tail, at) in forms {
        let (files, first) = tree_appended(SUPPORT, tail);
        let name = if *id == "generic-assoc-binding" {
            "FORM_M"
        } else {
            "FORM_L"
        };
        let mut table =
            format!("{STATICS_TABLE}{SUPPORT}\t{name}\tatomic: an atomic value of the form\n");
        if *id == "generic-assoc-binding" {
            // `Box<dyn Iterator<Item = u8>>` holds no lock: an `atomic` row
            // is accepted for it, and the `=` of the binding does not end the
            // type of the next static early.
            table.push_str(&format!(
                "{SUPPORT}\tFORM_L\tonce: a value computed once, no lock\n"
            ));
        }
        let (statics, includes) = token_census(&files, &table);
        assert_eq!(
            statics,
            vec![StaticFinding::LockNotLabelled {
                file: SUPPORT.into(),
                name: name.into(),
                line: first + at,
            }],
            "{id}"
        );
        assert_eq!(includes, Vec::<IncludeFinding>::new(), "{id}");
    }
    // The same statics labelled `lock` are clean.
    for (id, tail, _) in forms {
        let (files, _) = tree_appended(SUPPORT, tail);
        let mut table = format!("{STATICS_TABLE}{SUPPORT}\tFORM_L\tlock: a lock of the form\n");
        if *id == "generic-assoc-binding" {
            table.push_str(&format!("{SUPPORT}\tFORM_M\tlock: a lock of the form\n"));
        }
        let (statics, _) = token_census(&files, &table);
        assert_eq!(statics, Vec::<StaticFinding>::new(), "{id}");
    }
}

/// #10251: a live lock row relabelled `atomic` is red.
#[test]
fn live_lock_row_relabelled_is_red_10251() {
    let (key_path, key_name) = LOCK_ROWS[0];
    let table: String = STATICS_TABLE
        .lines()
        .map(|l| {
            let mut f = l.splitn(3, '\t');
            match (f.next(), f.next(), f.next()) {
                (Some(p), Some(n), Some(r)) if p == key_path && n == key_name => {
                    format!("{p}\t{n}\tatomic: {}\n", r.trim_start_matches("lock: "))
                }
                _ => format!("{l}\n"),
            }
        })
        .collect();
    let (statics, _) = token_census(&tree(), &table);
    assert!(
        !statics.is_empty()
            && statics.iter().all(|f| matches!(
                f,
                StaticFinding::LockNotLabelled { file, name, .. }
                    if file == key_path && name == key_name
            )),
        "{statics:?}"
    );
}

/// The literal decoder, each escape form by hand.
#[test]
fn decode_str_forms_10204() {
    let ok: &[(&str, &str)] = &[
        ("\"a/b.rs\"", "a/b.rs"),
        ("\"env\\x5fguard\"", "env_guard"),
        ("\"\\u{65}nv\"", "env"),
        ("\"a\\\\b\"", "a\\b"),
        ("\"a\\\"b\"", "a\"b"),
        ("\"a\\\n    b\"", "ab"),
        ("\"\\n\\t\\r\\0\\'\"", "\n\t\r\0'"),
        ("r\"a\\b\"", "a\\b"),
        ("r#\"a\"b\"#", "a\"b"),
        ("br##\"x\"##", "x"),
        ("b\"x\"", "x"),
        ("c\"x\"", "x"),
    ];
    for (lit, want) in ok {
        assert_eq!(decode_str(lit), Ok((*want).to_string()), "{lit}");
    }
    for lit in [
        "\"\\q\"",
        "\"\\x5\"",
        "\"\\xzz\"",
        "\"\\u{zz}\"",
        "\"\\u{d800}\"",
        "\"\\u65\"",
        "\"x",
    ] {
        assert_eq!(
            decode_str(lit),
            Err(ValueError::Undecodable(lit.to_string())),
            "{lit}"
        );
    }
    let names: &[(&str, bool)] = &[
        ("store_url/env_guard.rs", true),
        ("ENV_GUARD.RS", true),
        ("a\\store_url.rs", true),
        ("store_url.rs/", true),
        ("env_guard.rs.bak", false),
        ("my_env_guard.rs", false),
        ("store_url/mod.rs", false),
        ("", false),
    ];
    for (v, want) in names {
        assert_eq!(names_guarded_file(v), *want, "{v}");
    }
}

/// An undecodable literal in `#[path]` or an include is a finding, never a
/// pass, and so is an include macro with a non-literal piece.
#[test]
fn undecodable_and_not_literal_are_red_10204() {
    let rows: &[(&str, &[IncludeFinding])] = &[
        (
            "#[path = \"a\\qb.rs\"]\nmod m;\n",
            &[IncludeFinding::Undecodable {
                file: String::new(),
                line: 1,
                literal: String::new(),
            }],
        ),
        (
            "#[path = MOD_PATH]\nmod m;\n",
            &[IncludeFinding::PathNotLiteral {
                file: String::new(),
                line: 1,
            }],
        ),
        (
            "include_str!(concat!(env!(\"OUT_DIR\"), \"/x\"));\n",
            &[IncludeFinding::IncludeNotLiteral {
                file: String::new(),
                line: 1,
            }],
        ),
        (
            "include_bytes!(concat!(\"a\", X));\n",
            &[IncludeFinding::IncludeNotLiteral {
                file: String::new(),
                line: 1,
            }],
        ),
        (
            "include!($p);\n",
            &[IncludeFinding::IncludeNotLiteral {
                file: String::new(),
                line: 1,
            }],
        ),
        (
            "include_str!(\"readme.md\");\nlet path = 1;\nf(path = 2);\n",
            &[],
        ),
        (
            "#[doc = include_str!(\"../env_guard.rs\")]\nfn f() {}\n",
            &[IncludeFinding::Include {
                file: String::new(),
                line: 1,
                value: String::new(),
            }],
        ),
    ];
    for (src, want) in rows {
        let toks = lex(src).unwrap_or_else(|e| panic!("{src}: {e:?}"));
        let mut mods = [0usize; 2];
        let mut got = Vec::new();
        inclusions_of("src/x.rs", &toks, &BTreeSet::new(), &mut mods, &mut got);
        let shape: Vec<IncludeFinding> = got
            .into_iter()
            .map(|f| match f {
                IncludeFinding::Undecodable { line, .. } => IncludeFinding::Undecodable {
                    file: String::new(),
                    line,
                    literal: String::new(),
                },
                IncludeFinding::PathNotLiteral { line, .. } => IncludeFinding::PathNotLiteral {
                    file: String::new(),
                    line,
                },
                IncludeFinding::IncludeNotLiteral { line, .. } => {
                    IncludeFinding::IncludeNotLiteral {
                        file: String::new(),
                        line,
                    }
                }
                IncludeFinding::Include { line, .. } => IncludeFinding::Include {
                    file: String::new(),
                    line,
                    value: String::new(),
                },
                other => other,
            })
            .collect();
        assert_eq!(shape, *want, "{src}");
    }
    let toks = lex("#[path = \"a\\qb.rs\"]\nmod m;\n").expect("lexes");
    let mut got = Vec::new();
    inclusions_of("src/x.rs", &toks, &BTreeSet::new(), &mut [0; 2], &mut got);
    assert_eq!(
        got,
        vec![IncludeFinding::Undecodable {
            file: "src/x.rs".into(),
            line: 1,
            literal: "\"a\\qb.rs\"".into(),
        }]
    );
}

/// A symbolic link in the tree is refused by the walk, never followed.
#[test]
fn symlink_in_tree_is_refused_10204() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("store_url_env_guard_8168_links");
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear scratch");
    }
    fs::create_dir_all(root.join("src")).expect("scratch dir");
    fs::write(root.join("src/a.rs"), "static A: u8 = 0;\n").expect("write");
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("src/a.rs"), root.join("src/b.rs")).expect("symlink");
    let mut files = Vec::new();
    let mut links = Vec::new();
    walk(&root, &root, &mut files, &mut links);
    assert_eq!(
        files,
        vec![("src/a.rs".to_string(), "static A: u8 = 0;\n".to_string())]
    );
    #[cfg(unix)]
    assert_eq!(links, vec!["src/b.rs".to_string()]);
    fs::remove_dir_all(&root).expect("clean scratch");
}

/// #10250: a directory named like a skipped one is left out only as a
/// direct child of the root; at any other depth it is walked. The walked
/// set is written out by hand.
#[test]
fn skip_named_dirs_below_the_root_are_walked_10250() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("store_url_env_guard_8168_skips");
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear scratch");
    }
    let names = [
        "target",
        ".git",
        ".local-runs",
        ".codegraph",
        "node_modules",
    ];
    assert_eq!(
        names.len(),
        SKIPPED_DIRS.len(),
        "the fixture names every skipped directory"
    );
    for (name, _) in SKIPPED_DIRS {
        assert!(names.contains(name), "{name} is in the fixture");
    }
    for name in names {
        let nested = root.join("src/n").join(name);
        fs::create_dir_all(&nested).expect("nested dir");
        fs::write(nested.join("x.rs"), "static X: u8 = 0;\n").expect("write nested");
        let top = root.join(name);
        fs::create_dir_all(&top).expect("top dir");
        fs::write(top.join("y.rs"), "static Y: u8 = 0;\n").expect("write top");
    }
    let mut files = Vec::new();
    let mut links = Vec::new();
    walk(&root, &root, &mut files, &mut links);
    let mut got: Vec<String> = files.into_iter().map(|(p, _)| p).collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            "src/n/.codegraph/x.rs".to_string(),
            "src/n/.git/x.rs".to_string(),
            "src/n/.local-runs/x.rs".to_string(),
            "src/n/node_modules/x.rs".to_string(),
            "src/n/target/x.rs".to_string(),
        ]
    );
    assert_eq!(links, Vec::<String>::new());
    fs::remove_dir_all(&root).expect("clean scratch");
}

fn inc(line: usize, kind: fn(String, usize, String) -> IncludeFinding, value: &str) -> Finding {
    Finding::Include(kind(SUPPORT.into(), line, value.into()))
}

fn not_rust(file: String, line: usize, value: String) -> IncludeFinding {
    IncludeFinding::NotRustFile { file, line, value }
}

fn unwalked(file: String, line: usize, value: String) -> IncludeFinding {
    IncludeFinding::Unwalked { file, line, value }
}

fn in_inline(file: String, line: usize, value: String) -> IncludeFinding {
    IncludeFinding::PathInInlineMod { file, line, value }
}

/// #10250: every form a `#[path]` or `include!` can take to name a file the
/// walk never read, each with its exact finding; and the forms that name a
/// walked file, each clean. The expected column is written by hand.
#[test]
fn inclusion_of_an_unread_file_is_red_10250() {
    type Kind = fn(String, usize, String) -> IncludeFinding;
    let red: &[(&str, &str, usize, Kind, &str)] = &[
        (
            "path-under-skipped-dir",
            "#[path = \"../node_modules/x/lock.rs\"]\nmod lock_nm;\n",
            0,
            unwalked,
            "../node_modules/x/lock.rs",
        ),
        (
            "path-under-target",
            "#[path = \"../target/debug/build/x/out/lock.rs\"]\nmod lock_tgt;\n",
            0,
            unwalked,
            "../target/debug/build/x/out/lock.rs",
        ),
        (
            "path-escapes-root",
            "#[path = \"../../x.rs\"]\nmod lock_up;\n",
            0,
            unwalked,
            "../../x.rs",
        ),
        (
            "path-absolute",
            "#[path = \"/srv/x/lock.rs\"]\nmod lock_abs;\n",
            0,
            unwalked,
            "/srv/x/lock.rs",
        ),
        (
            "path-absent-file",
            "#[path = \"absent_10250.rs\"]\nmod lock_absent;\n",
            0,
            unwalked,
            "absent_10250.rs",
        ),
        (
            "path-wrong-case",
            "#[path = \"Test_Support.rs\"]\nmod lock_case;\n",
            0,
            unwalked,
            "Test_Support.rs",
        ),
        (
            "path-backslash",
            "#[path = \"store\\\\sqlite.rs\"]\nmod lock_bs;\n",
            0,
            unwalked,
            "store\\sqlite.rs",
        ),
        (
            "path-cfg-attr",
            "#[cfg_attr(test, path = \"../.codegraph/lock.rs\")]\nmod lock_cfg;\n",
            0,
            unwalked,
            "../.codegraph/lock.rs",
        ),
        (
            "path-not-rs",
            "#[path = \"lock.txt\"]\nmod lock_txt;\n",
            0,
            not_rust,
            "lock.txt",
        ),
        (
            "path-upper-ext",
            "#[path = \"lock.RS\"]\nmod lock_up_ext;\n",
            0,
            not_rust,
            "lock.RS",
        ),
        (
            "path-no-ext",
            "#[path = \"lock\"]\nmod lock_dir {}\n",
            0,
            not_rust,
            "lock",
        ),
        (
            "path-in-inline-mod",
            "mod inline_10250 {\n    #[path = \"test_support.rs\"]\n    mod again;\n}\n",
            1,
            in_inline,
            "test_support.rs",
        ),
        (
            "include-not-rs",
            "include!(\"lock.in\");\n",
            0,
            not_rust,
            "lock.in",
        ),
        (
            "include-under-skipped-dir",
            "include!(\"../.local-runs/lock.rs\");\n",
            0,
            unwalked,
            "../.local-runs/lock.rs",
        ),
        (
            "include-manifest-target",
            "include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/target/x.rs\"));\n",
            0,
            unwalked,
            "/target/x.rs",
        ),
        (
            "include-manifest-no-slash",
            "include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"src/lib.rs\"));\n",
            0,
            unwalked,
            "src/lib.rs",
        ),
        (
            "include-split-not-rs",
            "include!(concat!(\"lock\", \".in\"));\n",
            0,
            not_rust,
            "lock.in",
        ),
    ];
    for (id, tail, at, kind, value) in red {
        let (files, first) = tree_appended(SUPPORT, tail);
        let got: Vec<Finding> = census_all(&files)
            .into_iter()
            .filter(|f| matches!(f, Finding::Include(_)))
            .collect();
        assert_eq!(got, vec![inc(first + at, *kind, value)], "{id}");
    }
    let clean: &[(&str, &str)] = &[
        ("path-sibling", "#[path = \"lib.rs\"]\nmod again_lib;\n"),
        (
            "path-dot",
            "#[path = \"./store/sqlite.rs\"]\nmod again_sqlite;\n",
        ),
        (
            "path-parent-back",
            "#[path = \"../src/lib.rs\"]\nmod again_up;\n",
        ),
        (
            "path-double-slash",
            "#[path = \"store//sqlite.rs\"]\nmod again_ds;\n",
        ),
        ("include-sibling", "include!(\"lib.rs\");\n"),
        (
            "include-manifest",
            "include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/src/lib.rs\"));\n",
        ),
        (
            "include-str-any",
            "const T: &str = include_str!(\"../README.md\");\n",
        ),
        (
            "include-bytes-any",
            "const B: &[u8] = include_bytes!(\"/srv/x.bin\");\n",
        ),
    ];
    for (id, tail) in clean {
        let (files, _) = tree_appended(SUPPORT, tail);
        let got: Vec<Finding> = census_all(&files)
            .into_iter()
            .filter(|f| matches!(f, Finding::Include(_)))
            .collect();
        assert_eq!(got, Vec::<Finding>::new(), "{id}");
    }
}

/// #10250: `env!("CARGO_MANIFEST_DIR")` anchors a value only as the first
/// piece of `concat!`; anywhere else the value is not a literal.
#[test]
fn manifest_dir_after_the_first_piece_is_not_literal_10250() {
    let tail = "include!(concat!(\"src/\", env!(\"CARGO_MANIFEST_DIR\"), \"/src/lib.rs\"));\n";
    let (files, first) = tree_appended(SUPPORT, tail);
    let got: Vec<Finding> = census_all(&files)
        .into_iter()
        .filter(|f| matches!(f, Finding::Include(_)))
        .collect();
    assert_eq!(
        got,
        vec![Finding::Include(IncludeFinding::IncludeNotLiteral {
            file: SUPPORT.into(),
            line: first,
        })]
    );
}

/// The token census is linear: a 200 000-line file of every form it parses
/// is judged in well under the ceiling, with every hit reported.
#[test]
fn token_census_cost_is_bounded_10213() {
    const LINES: usize = 200_000;
    const CEILING_SECS: u64 = 20;
    let mut big = String::new();
    for i in 0..LINES / 4 {
        let _ = writeln!(big, "static S{i}: u8 = 0;");
        big.push_str("let path = x;\n");
        big.push_str("#[path = \"other.rs\"]\n");
        big.push_str("const X: &str = include_str!(\"y.md\");\n");
    }
    // `#[path = "other.rs"]` resolves to a walked file, so it is no finding.
    let files = vec![
        ("src/big.rs".to_string(), big),
        ("src/other.rs".to_string(), String::new()),
    ];
    let start = std::time::Instant::now();
    let (statics, includes) = token_census(&files, "");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(CEILING_SECS),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(statics.len(), LINES / 4);
    assert_eq!(
        statics[7],
        StaticFinding::Unlisted {
            file: "src/big.rs".into(),
            name: "S7".into(),
            line: 29
        }
    );
    assert_eq!(
        includes,
        vec![
            IncludeFinding::ModCount {
                file: "src/store_url.rs",
                name: "env_guard",
                found: 0
            },
            IncludeFinding::ModCount {
                file: "src/lib.rs",
                name: "store_url",
                found: 0
            },
        ]
    );
}
