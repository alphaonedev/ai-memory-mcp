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
//! of the source tree (the whole manifest directory; the root directories
//! `target`, `.git`, `.local-runs`, `.codegraph` and `node_modules` are left
//! out because they hold build output, VCS data or scratch, not tracked
//! source; #10250: a directory of one of those names below the root is
//! walked like any other). The lock
//! function's name may appear in code in exactly three lines of
//! `src/store_url/env_guard.rs`: its definition, the call inside the guard
//! constructor and the held-probe. The constructor's signature is pinned too, so a constructor
//! that stops taking the outer proof fails here. Comment text is judged as text, not skipped.
//!
//! #10208 adds a census of whole item sets, because text pins of chosen
//! lines let a new item through. `census_all` runs six parts:
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
//!    is `Missing`; a bad row is refused with its line. #10285: a static
//!    inside a `macro_rules!` body never takes a row: it is
//!    `MacroBodyStatic` unless `EXCEPTIONS` names it, and `static $x`
//!    outside such a body is `MacroStatic`, because its name is unknown
//!    until expansion. #10251: a reason starts with `<category>: `, the
//!    category one word of `Category::ALL`, or the row is refused; the row
//!    count is pinned to `STATICS_TABLE_ROWS` (627) and the `lock` keys to
//!    the hand-written `LOCK_ROWS` (307), both exact: a change that adds or
//!    removes a row moves the pin under a `Count-Declared` trailer, and a
//!    new static needs a new row with its reason. #10275, #10283, #10293:
//!    every name in the type of a static resolves through its own scope
//!    only: a definition in the same module (a fn body also sees its
//!    enclosing scope), an explicit `use` (renames and chains followed), a
//!    full `crate::`/`self::`/`super::`/crate-name path to one walked
//!    definition, or a std/core/alloc path; never a same-named type
//!    elsewhere in the tree. A name a glob supplies (`Glob`), bound twice
//!    (`Ambiguous`), a prelude name shadowed by a generic or a definition
//!    (`Shadowed`), a path into another crate (`Foreign`), a path that
//!    lands on no walked item (`PathNotLanded`), a type made by a macro
//!    and an import cycle are each unresolvable with that reason; a
//!    prelude name is clean only when nothing in scope shadows it. The
//!    definitions are judged by one linear strongly-connected-component
//!    walk, generic defaults included. A type is one of three values:
//!    a lock (it is or holds one of `LOCK_TYPES`: std, tokio and
//!    `parking_lot`, fair and raw locks and their guards included), proven
//!    clean (every leaf is a std type of `LEAF_TYPES` or a crate type
//!    built only from them), or unresolvable (a `dyn` or `impl` type, a
//!    type made by a macro, a raw pointer, a `<T as Tr>::Out` projection,
//!    a name with no definition, a std or foreign type not proven, or an
//!    alias cycle). Where definitions disagree, lock wins. A lock static
//!    whose row is not `lock` is `LockNotLabelled`; an unresolvable static
//!    whose row is not `lock` is `Unresolvable` with the reason, unless
//!    `EXCEPTIONS` names it with a reason and a pinned digest. An exception
//!    that matches nothing (`ExceptionStale`), a second one
//!    (`ExceptionDuplicate`), one with a short reason (`ExceptionReasonless`)
//!    or one whose pinned digest is not the live one (`ExceptionDigest`,
//!    naming the first changed entry: `type` or a definition path) is red.
//!    #10295: the digest is a 32-bit FNV-1a hash of the static's written
//!    type tokens plus one hash of the tokens of each walked definition the
//!    type reaches. It proves that the text judged by hand has not changed
//!    since the pin; it is not a cryptographic commitment (a deliberate
//!    collision is possible) and it does not cover a foreign or std type's
//!    own source or a macro's expansion;
//! 5. the inclusion census (#10204): the guard file may be compiled once.
//!    `#[path = …]` (in `cfg_attr` too) and `include!`, `include_str!` or
//!    `include_bytes!` naming `env_guard.rs` or its parent `store_url.rs`
//!    (any case, `/` or `\`, escapes and raw strings decoded, `concat!` of
//!    literals joined, `env!("CARGO_MANIFEST_DIR")` as its first piece
//!    only) are red; a path or include argument that is not such a literal
//!    is red; `mod env_guard;` and `mod store_url;` must each occur exactly
//!    once, in `src/store_url.rs` and `src/lib.rs`. #10250: every other
//!    `#[path]` or `include!` must name a walked `.rs` file, resolved from
//!    the declaring file's directory (from the root after the manifest
//!    dir): a value that is not `.rs` is `NotRustFile`, a `#[path]` inside
//!    an inline `mod NAME { … }` is `PathInInlineMod` (its base would be
//!    the module's directory, which this census does not model), and
//!    anything else that names no walked file (absolute, a backslash, a
//!    `..` out of the root, a skipped directory, an absent file) is
//!    `Unwalked`. #10276: an include macro is recognised in every call
//!    form (`!(…)`, `![…]`, `!{…}`, a path such as `core::include!`, a raw
//!    `r#include` and a `use … as` rename), and the identifier `include`
//!    is counted per file against `INCLUDE_ROWS`: a count that differs
//!    from its row (no row means zero) is `IncludeCount`, and a stale,
//!    duplicate or bad row is red;
//! 6. the build-target census (#10277): `Cargo.toml` is read (never
//!    written) and every target it compiles must be a walked `.rs` file:
//!    the library, each `[[bin]]`, `[[test]]`, `[[bench]]` and
//!    `[[example]]` (its `path`, or Cargo's default places for its name),
//!    `package.build` and every `path =` dependency. A target that does not
//!    end in `.rs` (exact case) is `NotRs`, one the walk did not read is
//!    `Unwalked`, and a manifest that cannot be read or parsed, a value of
//!    the wrong type, a `[workspace]` table or a `[lib] name` that is not
//!    the crate's is red.
//!
//! The walk refuses a symbolic link in the tree. The lexer is std only and
//! fails closed (an unterminated string or comment is a finding). A file it
//! cannot lex is reported once by the static census and skipped by the
//! inclusion census. #10284: every scan for the end of a type, a generic
//! list or an item body stops at the next item keyword (`ITEM_STOPS`), and
//! the type graph is settled by one linear walk, so the census is linear in
//! the tree (the cost tests hold 100 000-unit inputs under 20 s). Its limits: it does not expand macros, so an item
//! built by a macro from pieces is not seen by parts 2 and 3 (part 4 reports
//! `static $x` and every macro-body static); `concat!` or escaped spellings
//! of the variable names are not decoded by part 1.

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
            // #10250: only a direct child of the root is skipped; a
            // directory of the same name deeper in the tree is source.
            let rel = rel_of(&path, root);
            if SKIPPED_DIRS.iter().any(|(d, _)| *d == rel) {
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
    // #10323: `read_dir` order is not specified; every census sees the
    // files sorted by path.
    files.sort_by(|a, b| a.0.cmp(&b.0));
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

/// #10251: split a reason into its category and the text after `": "`.
/// The word must equal one of [`Category::ALL`] exactly (case, blanks and
/// all); otherwise the error is the text before the first `": "`, or the
/// whole reason when it has none.
fn parse_category(reason: &str) -> Result<(Category, &str), String> {
    let Some((word, rest)) = reason.split_once(": ") else {
        return Err(reason.to_string());
    };
    Category::ALL
        .into_iter()
        .find(|c| c.word() == word)
        .map(|c| (c, rest))
        .ok_or_else(|| word.to_string())
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
        let (category, reason) = match parse_category(reason) {
            Ok(split) => (Some(split.0), split.1),
            Err(word) => {
                bad.push(TableFinding::Category { line, word });
                ok = false;
                (None, reason)
            }
        };
        let visible = reason
            .chars()
            .filter(|c| !c.is_whitespace() && !c.is_control())
            .count();
        if visible < MIN_REASON_CHARS {
            bad.push(TableFinding::ShortReason { line });
            ok = false;
        }
        if let (true, Some(category)) = (ok, category) {
            rows.push(StaticRow {
                path: path.to_string(),
                name: name.to_string(),
                category,
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
    /// #10275, #10283: a static with a row that is not `lock`, whose type
    /// does not resolve completely to [`LEAF_TYPES`] and is not in
    /// [`EXCEPTIONS`]; `why` is the first reason in [`Why`] order.
    Unresolvable {
        file: String,
        name: String,
        line: usize,
        why: Why,
    },
    /// #10285: a `static` item inside a `macro_rules!` body, whose count
    /// is not known until expansion; `name` is the literal name, or `$x`
    /// for a metavariable. Red unless the key is in [`EXCEPTIONS`].
    MacroBodyStatic {
        file: String,
        name: String,
        line: usize,
    },
    /// An [`EXCEPTIONS`] row no static used.
    ExceptionStale { file: String, name: String },
    /// An [`EXCEPTIONS`] key written twice.
    ExceptionDuplicate { file: String, name: String },
    /// An [`EXCEPTIONS`] row with fewer than [`MIN_REASON_CHARS`] visible
    /// characters of reason.
    ExceptionReasonless { file: String, name: String },
    /// #10295: an [`EXCEPTIONS`] row whose pinned digest no longer matches
    /// the static's type: `ty` is the type whose definition changed (its
    /// module path and name, or `type` for the static's own written type).
    ExceptionDigest {
        file: String,
        name: String,
        ty: String,
    },
}

/// #10275, #10283: why a type is not proven to hold no lock. The order is
/// the order of report when a type has more than one reason.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Why {
    /// `dyn Trait`: the value behind it is not known.
    TraitObject,
    /// `impl Trait` in a type alias.
    OpaqueType,
    /// A macro in type position, by its name.
    MacroType(String),
    /// `*const T` or `*mut T`.
    RawPointer,
    /// `<T as Trait>::Out` or `Self::Out`: an associated type.
    Projection,
    /// A crate type name with no definition in the walked tree.
    NoDef(String),
    /// #10294: a name reached only through a glob import (`use x::*`),
    /// of this crate or another: what it names is not read.
    Glob(String),
    /// #10293: a name with more than one definition in reach.
    Ambiguous(String),
    /// #10293: a name a local definition or a generic parameter shadows,
    /// where the name is a lock, a proven type or a prelude type.
    Shadowed(String),
    /// #10293: a `self`, `super` or `crate` path that lands on no walked
    /// definition. #10322: also a name only a glob of an unread module (a
    /// `#[path]` module, a declared module with no walked file) can supply.
    PathNotLanded(String),
    /// A `std`, `core` or `alloc` type that is not in [`LEAF_TYPES`].
    StdNotProven(String),
    /// A type of another crate that is not in [`LEAF_TYPES`].
    Foreign { root: String, name: String },
    /// A cycle of aliases with no struct, enum or union in it.
    Cycle(String),
    /// An associated `type NAME;` with no value.
    NoValue(String),
}

/// One `static` item of a lexed file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticItem {
    /// The name, or `$x` for a metavariable name.
    name: String,
    line: usize,
    /// #10251: the token range of its declared type.
    ty: (usize, usize),
    /// #10285: whether it sits inside a `macro_rules!` body.
    in_macro: bool,
}

/// Whether `t[i]` opens a bracket group.
fn is_open(t: &[Tok], i: usize) -> bool {
    is_p(t, i, "(") || is_p(t, i, "[") || is_p(t, i, "{")
}

/// #10284: keywords that start an item and never occur inside a type, a
/// `use` tree or a `where` clause. A scan for the end of one item stops at
/// the first of them outside every group, so every scan ends where the next
/// item starts and the scans of a file are linear in its length together.
const ITEM_STOPS: [&str; 9] = [
    "enum", "let", "mod", "pub", "static", "struct", "trait", "type", "use",
];

/// Whether `t[i]` is one of [`ITEM_STOPS`].
fn is_item_stop(t: &[Tok], i: usize) -> bool {
    t.get(i)
        .is_some_and(|x| x.kind == TokKind::Ident && ITEM_STOPS.contains(&x.text.as_str()))
}

/// The end of the type that starts at `from`: the first `=` or `;`
/// outside every group and every `<…>` (`->` is not a closer), the first
/// unmatched closer, the first of [`ITEM_STOPS`] outside every group, or
/// the end. Groups are jumped through `close`, so the scan is linear in the
/// span, and the span never reaches past the next item.
fn type_end(t: &[Tok], close: &[Option<usize>], from: usize) -> usize {
    let mut angle = 0usize;
    let mut i = from;
    while let Some(k) = t.get(i) {
        if is_item_stop(t, i) {
            return i;
        }
        if k.kind == TokKind::Punct {
            match k.text.as_str() {
                "(" | "[" | "{" => match close[i] {
                    Some(c) => {
                        i = c + 1;
                        continue;
                    }
                    None => return i,
                },
                "<" => angle += 1,
                ">" if is_p(t, i.wrapping_sub(1), "-") => {}
                ">" => match angle.checked_sub(1) {
                    Some(a) => angle = a,
                    None => return i,
                },
                ")" | "]" | "}" => return i,
                ";" | "=" if angle == 0 => return i,
                _ => {}
            }
        }
        i += 1;
    }
    i
}

/// #10285: for each token, whether it sits inside the body of a
/// `macro_rules!` definition. One pass, linear in the token count.
fn macro_bodies(t: &[Tok], close: &[Option<usize>]) -> Vec<bool> {
    let mut opens = vec![0usize; t.len() + 1];
    let mut ends = vec![0usize; t.len() + 1];
    for k in 0..t.len() {
        if is_w(t, k, "macro_rules")
            && is_p(t, k + 1, "!")
            && t.get(k + 2).is_some_and(|x| x.kind == TokKind::Ident)
            && is_open(t, k + 3)
            && let Some(c) = close[k + 3]
        {
            opens[k + 4] += 1;
            ends[c] += 1;
        }
    }
    let mut depth = 0usize;
    (0..t.len())
        .map(|i| {
            depth = depth + opens[i] - ends[i].min(depth + opens[i]);
            depth > 0
        })
        .collect()
}

/// For the `;` of each `[T; N]`, the index of its `]`: the length `N` is an
/// expression, not a type. One pass with a stack.
fn array_lengths(t: &[Tok], close: &[Option<usize>]) -> Vec<Option<usize>> {
    let mut out = vec![None; t.len()];
    let mut stack: Vec<(usize, bool)> = Vec::new();
    for (i, k) in t.iter().enumerate() {
        if k.kind != TokKind::Punct {
            continue;
        }
        match k.text.as_str() {
            "(" | "{" => stack.push((i, false)),
            "[" => stack.push((i, true)),
            ")" | "]" | "}" => {
                stack.pop();
            }
            ";" => {
                if let Some(top) = stack.last_mut()
                    && top.1
                {
                    top.1 = false;
                    out[i] = close[top.0];
                }
            }
            _ => {}
        }
    }
    out
}

/// Every `static` item of a lexed file, plus the lines of `static $x`
/// forms outside a `macro_rules!` body.
fn statics_of(
    t: &[Tok],
    close: &[Option<usize>],
    in_macro: &[bool],
) -> (Vec<StaticItem>, Vec<usize>) {
    let mut named = Vec::new();
    let mut macros = Vec::new();
    for k in (0..t.len()).filter(|&k| is_w(t, k, "static")) {
        let mut n = k + 1;
        while is_w(t, n, "mut") || is_w(t, n, "ref") {
            n += 1;
        }
        let meta = is_p(t, n, "$");
        let name_at = n + usize::from(meta);
        let Some(name) = t.get(name_at).filter(|x| x.kind == TokKind::Ident) else {
            continue;
        };
        let name = if meta {
            format!("${}", name.text)
        } else {
            name.text.clone()
        };
        if in_macro[k] {
            named.push(StaticItem {
                name,
                line: t[k].line,
                ty: (k, k),
                in_macro: true,
            });
        } else if meta {
            macros.push(t[k].line);
        } else if is_p(t, name_at + 1, ":") {
            let from = name_at + 2;
            named.push(StaticItem {
                name,
                line: t[name_at].line,
                ty: (from, type_end(t, close, from)),
                in_macro: false,
            });
        }
    }
    (named, macros)
}

/// #10251, #10279: the final path segments that name a lock, a lock guard
/// or a lock-built primitive, in std, tokio and `parking_lot` (fair and
/// raw forms included). A name here makes the static a lock whatever crate
/// it comes from; a lock type missing here is still not a pass, because it
/// is not in [`LEAF_TYPES`] either.
const LOCK_TYPES: [&str; 23] = [
    "Mutex",
    "RwLock",
    "Condvar",
    "ReentrantLock",
    "ReentrantMutex",
    "Semaphore",
    "Barrier",
    "Notify",
    "OnceCell",
    "SetOnce",
    "FairMutex",
    "RawMutex",
    "RawFairMutex",
    "RawRwLock",
    "RawReentrantMutex",
    "MutexGuard",
    "RwLockReadGuard",
    "RwLockWriteGuard",
    "MappedMutexGuard",
    "ReentrantMutexGuard",
    "OwnedMutexGuard",
    "SemaphorePermit",
    "OwnedSemaphorePermit",
];

/// #10275, #10283: the closed set of leaf types proven to hold no lock of
/// their own (a container's arguments are judged in their own right). A
/// type outside it, and outside the crate's own definitions, is
/// unresolvable.
const LEAF_TYPES: [&str; 58] = [
    "bool",
    "char",
    "str",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "f32",
    "f64",
    "String",
    "Vec",
    "VecDeque",
    "Box",
    "Option",
    "Result",
    "Arc",
    "Rc",
    "Weak",
    "HashMap",
    "HashSet",
    "BTreeMap",
    "BTreeSet",
    "BinaryHeap",
    "LinkedList",
    "PathBuf",
    "Path",
    "OsString",
    "OsStr",
    "Duration",
    "Instant",
    "SystemTime",
    "Cell",
    "RefCell",
    "Once",
    "OnceLock",
    "LazyLock",
    "LazyCell",
    "AtomicBool",
    "AtomicU8",
    "AtomicU16",
    "AtomicU32",
    "AtomicU64",
    "AtomicUsize",
    "AtomicI8",
    "AtomicI16",
    "AtomicI32",
    "AtomicI64",
    "AtomicIsize",
    "PhantomData",
    "Cow",
];

/// Keywords in type position that name no type unless a path follows.
const NEUTRAL_WORDS: [&str; 15] = [
    "fn", "unsafe", "extern", "mut", "const", "pub", "crate", "super", "self", "Self", "for",
    "where", "in", "as", "ref",
];

/// The path roots of the standard library.
const STD_ROOTS: [&str; 3] = ["std", "core", "alloc"];

/// One piece of a type before resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Atom {
    /// A name of [`LOCK_TYPES`].
    Lock,
    /// A form that names no knowable type.
    Unres(Why),
    /// #10293: a path as written, resolved later through the scope that
    /// wrote it; `global` when it starts with a leading `::`.
    Path { segs: Vec<String>, global: bool },
    /// #10293: a single-segment name of a generic parameter in scope.
    Param(String),
}

/// What a type holds, ordered: a lock wins, then an unresolvable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Res {
    Clean,
    Unres(Why),
    Lock,
}

impl Res {
    fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Lock, _) | (_, Self::Lock) => Self::Lock,
            (Self::Unres(a), Self::Unres(b)) => Self::Unres(a.min(b)),
            (Self::Unres(a), Self::Clean) | (Self::Clean, Self::Unres(a)) => Self::Unres(a),
            (Self::Clean, Self::Clean) => Self::Clean,
        }
    }
}

/// The atoms of the type tokens `t[from..to]`, appended to `out`. `params`
/// are the generic parameters in scope, which name no type of their own
/// (their arguments are judged where the type is used). Every token is
/// visited at most once: linear in the span.
fn type_atoms(
    t: &[Tok],
    close: &[Option<usize>],
    lens: &[Option<usize>],
    span: (usize, usize),
    params: &BTreeSet<&str>,
    out: &mut Vec<Atom>,
) {
    let ident = |i: usize| t.get(i).filter(|x| x.kind == TokKind::Ident);
    let (mut i, to) = span;
    while i < to {
        if let Some(c) = lens[i] {
            i = c + 1;
            continue;
        }
        let k = &t[i];
        match k.kind {
            TokKind::Lifetime | TokKind::Str | TokKind::Char | TokKind::Num => i += 1,
            TokKind::Punct => match k.text.as_str() {
                "#" if is_p(t, i + 1, "[") => i = close[i + 1].map_or(to, |c| c + 1),
                "*" if is_w(t, i + 1, "const") || is_w(t, i + 1, "mut") => {
                    out.push(Atom::Unres(Why::RawPointer));
                    i += 2;
                }
                ">" if is_p(t, i + 1, ":") && is_p(t, i + 2, ":") => {
                    out.push(Atom::Unres(Why::Projection));
                    i += 3;
                }
                _ => i += 1,
            },
            TokKind::Ident => {
                let word = k.text.as_str();
                let colon2 = |j: usize| is_p(t, j, ":") && is_p(t, j + 1, ":");
                if is_p(t, i + 1, "!") && !is_p(t, i + 2, "=") {
                    out.push(Atom::Unres(Why::MacroType(word.to_string())));
                    i = if is_open(t, i + 2) {
                        close[i + 2].map_or(to, |c| c + 1)
                    } else {
                        i + 2
                    };
                } else if word == "fn" && is_p(t, i + 1, "(") {
                    // A function pointer holds code, not its argument or
                    // return types.
                    i = close[i + 1].map_or(to, |c| c + 1);
                    if is_p(t, i, "-") && is_p(t, i + 1, ">") {
                        i = fn_return_end(t, close, i + 2).min(to);
                    }
                } else if word == "dyn" {
                    out.push(Atom::Unres(Why::TraitObject));
                    i += 1;
                } else if word == "impl" {
                    out.push(Atom::Unres(Why::OpaqueType));
                    i += 1;
                } else if i + 1 < to
                    && (is_p(t, i + 1, "=") || (is_p(t, i + 1, ":") && !colon2(i + 1)))
                {
                    // An associated binding name, a field name or a bound
                    // parameter inside the span: the type follows it. The
                    // `=` that ends the span is the static's initialiser.
                    i += 1;
                } else if NEUTRAL_WORDS.contains(&word) && !colon2(i + 1) {
                    i += 1;
                } else {
                    let mut j = i;
                    while colon2(j + 1) && ident(j + 3).is_some() {
                        j += 3;
                    }
                    let last = t[j].text.as_str();
                    if j > i && (word == "Self" || params.contains(word)) {
                        out.push(Atom::Unres(Why::Projection));
                    } else if j == i && params.contains(word) {
                        out.push(Atom::Param(word.to_string()));
                    } else if LOCK_TYPES.contains(&last) {
                        out.push(Atom::Lock);
                    } else {
                        // A leading `::` (not one that follows a path or a
                        // closing `>`) roots the path at the extern prelude.
                        let global = i >= 2
                            && colon2(i - 2)
                            && (i < 3 || !matches!(t[i - 3].kind, TokKind::Ident))
                            && (i < 3 || !is_p(t, i - 3, ">"));
                        out.push(Atom::Path {
                            segs: (i..=j).step_by(3).map(|x| t[x].text.clone()).collect(),
                            global,
                        });
                    }
                    i = j + 1;
                }
            }
        }
    }
}

/// The end of a function pointer's return type that starts at `from`: the
/// first `,`, `;` or `=` outside angle brackets, or the bracket that closes
/// the enclosing group.
fn fn_return_end(t: &[Tok], close: &[Option<usize>], from: usize) -> usize {
    let mut angle = 0usize;
    let mut i = from;
    while let Some(k) = t.get(i) {
        if k.kind == TokKind::Punct {
            match k.text.as_str() {
                "(" | "[" | "{" => match close[i] {
                    Some(c) => {
                        i = c + 1;
                        continue;
                    }
                    None => return i,
                },
                "<" => angle += 1,
                ">" if is_p(t, i.wrapping_sub(1), "-") => {}
                ">" => match angle.checked_sub(1) {
                    Some(a) => angle = a,
                    None => return i,
                },
                ")" | "]" | "}" => return i,
                "," | ";" | "=" if angle == 0 => return i,
                _ => {}
            }
        }
        i += 1;
    }
    i
}

/// The generic parameter list that opens at `open` (a `<`): the index after
/// its `>`, the type parameter names and the token range of each default.
/// An unclosed list ends at the first of [`ITEM_STOPS`] outside every group.
fn generics(
    t: &[Tok],
    close: &[Option<usize>],
    open: usize,
) -> (usize, Vec<String>, Vec<(usize, usize)>) {
    let mut names = Vec::new();
    let mut defaults = Vec::new();
    let mut param = |seg: usize, end: usize, eq: Option<usize>| {
        if let Some(x) = t
            .get(seg)
            .filter(|x| x.kind == TokKind::Ident && x.text != "const")
        {
            names.push(x.text.clone());
            if let Some(e) = eq {
                defaults.push((e + 1, end));
            }
        }
    };
    let mut depth = 1usize;
    let mut i = open + 1;
    let mut seg = i;
    let mut eq = None;
    while let Some(k) = t.get(i) {
        if is_item_stop(t, i) {
            // #10284: an unclosed list ends where the next item starts.
            param(seg, i, eq);
            return (i, names, defaults);
        }
        if k.kind == TokKind::Punct {
            match k.text.as_str() {
                "(" | "[" | "{" => {
                    i = close[i].map_or(i + 1, |c| c + 1);
                    continue;
                }
                "<" => depth += 1,
                ">" if is_p(t, i.wrapping_sub(1), "-") => {}
                ">" => {
                    depth -= 1;
                    if depth == 0 {
                        param(seg, i, eq);
                        return (i + 1, names, defaults);
                    }
                }
                "," if depth == 1 => {
                    param(seg, i, eq);
                    seg = i + 1;
                    eq = None;
                }
                "=" if depth == 1 => eq = Some(i),
                _ => {}
            }
        }
        i += 1;
    }
    (t.len(), names, defaults)
}

/// The body group of a struct, enum or union whose generics end before
/// `j`: `{…}` or `(…)`, skipping a `where` clause. `None` for a unit form
/// and where the next item starts first (#10284: [`ITEM_STOPS`]).
fn adt_body(t: &[Tok], close: &[Option<usize>], mut j: usize) -> Option<(usize, usize)> {
    if is_p(t, j, "(") || is_p(t, j, "{") {
        return close[j].map(|c| (j, c));
    }
    while let Some(k) = t.get(j) {
        if is_item_stop(t, j) {
            return None;
        }
        if k.kind == TokKind::Punct {
            match k.text.as_str() {
                "{" => return close[j].map(|c| (j, c)),
                ";" => return None,
                "(" | "[" => {
                    j = close[j].map_or(j + 1, |c| c + 1);
                    continue;
                }
                _ => {}
            }
        }
        j += 1;
    }
    None
}

/// The scope of the files under `src/` outside `src/bin/`, which
/// [`CRATE_NAME`] names.
const LIB_SCOPE: &str = "src";

/// #10293: the types a bare name means when nothing in scope binds it.
const PRELUDE_TYPES: [&str; 5] = ["Box", "Option", "Result", "String", "Vec"];

/// #10293: the primitive type names.
const PRIMITIVES: [&str; 17] = [
    "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64",
    "i128", "isize", "f32", "f64",
];

/// Whether a bare name means a std type when nothing in scope binds it.
fn is_prelude(name: &str) -> bool {
    PRELUDE_TYPES.contains(&name) || PRIMITIVES.contains(&name)
}

/// The FNV-1a 64-bit offset basis and prime (#10295 digests).
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// FNV-1a over `bytes`, continuing from `h`. Modular by design (per
/// PERF-04): a digest, not a count.
fn fnv(mut h: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// The digest of the token texts `t[from..to]`, each followed by a 0 byte
/// so that token boundaries count.
fn token_hash(t: &[Tok], (from, to): (usize, usize)) -> u64 {
    t.get(from..to.min(t.len()))
        .unwrap_or_default()
        .iter()
        .fold(FNV_OFFSET, |h, k| fnv(fnv(h, k.text.as_bytes()), &[0]))
}

/// The root key and module path of a walked file: every file under `src/`
/// (outside `src/bin/` and the binary root `src/main.rs`) is a module of
/// the one crate [`LIB_SCOPE`]; a file in a subdirectory of another top
/// directory (`tests/common/mod.rs`) is a module of that directory; every
/// other file is a crate root of its own.
fn module_of(path: &str) -> (String, Vec<String>) {
    let file = path.strip_suffix(".rs").unwrap_or(path);
    let parts: Vec<&str> = file.split('/').collect();
    let cut = match parts.as_slice() {
        // #10293: the binary's root is a crate of its own; its imports
        // (`use ai_memory::config`) never bind in the library's root.
        ["src", "main"] => return (path.to_string(), Vec::new()),
        ["src", "bin", _, ..] => 3,
        ["src", ..] => 1,
        [_, _, _, ..] => 2,
        _ => parts.len(),
    };
    let root = if cut == parts.len() && !matches!(parts.as_slice(), ["src", ..]) {
        path.to_string()
    } else if cut == 1 {
        LIB_SCOPE.to_string()
    } else {
        parts[..cut].join("/")
    };
    let mut segs: Vec<String> = parts[cut..].iter().map(|s| (*s).to_string()).collect();
    if matches!(
        segs.last().map(String::as_str),
        Some("mod" | "lib" | "main")
    ) {
        segs.pop();
    }
    (root, segs)
}

/// #10323: the walked paths `mod NAME;` can name, written in `file` inside
/// the inline modules `inline` (`""` or `::a::b`), by the Rust rules for
/// that file kind: a `mod.rs`, `lib.rs` or `main.rs` file reads `DIR/NAME`,
/// any other module file `DIR/STEM/NAME`, and a crate root of another name
/// (`tests/foo.rs`) both. Each base gives `NAME.rs` and `NAME/mod.rs`.
fn decl_candidates(file: &str, inline: &str, name: &str) -> Vec<String> {
    if !inline.is_empty() && !inline.starts_with("::") {
        return Vec::new();
    }
    let (dir, fname) = file.rsplit_once('/').unwrap_or(("", file));
    let stem = fname.strip_suffix(".rs").unwrap_or(fname);
    let stem_dir = if dir.is_empty() {
        stem.to_string()
    } else {
        format!("{dir}/{stem}")
    };
    let bases: Vec<String> = if matches!(stem, "mod" | "lib" | "main") {
        vec![dir.to_string()]
    } else if module_of(file).1.is_empty() {
        vec![dir.to_string(), stem_dir]
    } else {
        vec![stem_dir]
    };
    let mut out = Vec::with_capacity(2 * bases.len());
    for base in bases {
        let mut parts: Vec<&str> = Vec::new();
        if !base.is_empty() {
            parts.push(&base);
        }
        parts.extend(inline.split("::").filter(|s| !s.is_empty()));
        parts.push(name);
        let stub = parts.join("/");
        out.push(format!("{stub}.rs"));
        out.push(format!("{stub}/mod.rs"));
    }
    out
}

/// #10293: the bindings of one name kept in a scope: one resolves, a second
/// makes the name `Ambiguous`, and a third changes nothing.
const MAX_BINDINGS: usize = 2;

/// #10293: how a `use` leaf names what it imports.
enum Rename {
    /// No `as`: the leaf's own last segment.
    Keep,
    /// `as name`.
    As(String),
    /// `as` followed by no name: binds nothing.
    Unnamed,
}

/// #10293: one binding of a name in a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bind {
    /// A module: a walked file, an inline `mod`, or a `mod` declaration.
    Module(usize),
    /// A type definition: its node.
    Def(usize),
    /// An explicit import: its leaf in [`TypeGraph::uses`].
    Use(usize),
}

/// #10293: a module or a function body of the walked tree.
#[derive(Debug, Default)]
struct Scope {
    /// For a function body, the scope a name it does not bind is looked up
    /// in; `None` for a module, which sees no name of an outer module.
    outer: Option<usize>,
    /// For a module, its parent (`super`); `None` for a crate root.
    parent: Option<usize>,
    /// The display path: the root key, then `::` and each module name.
    path: String,
    /// Every binding of each name written here.
    items: BTreeMap<String, Vec<Bind>>,
    /// #10294: every glob import (`use x::*`) written here: the last
    /// segment of its prefix (`None`: no prefix) and whether it starts
    /// with `::`.
    globs: Vec<(Option<usize>, bool)>,
    /// The module each glob of [`Scope::globs`] reads, once settled;
    /// `None` for std, another crate or a prefix that lands nowhere, whose
    /// names are not known.
    glob_to: Vec<Option<usize>>,
    /// #10322: whether the census read this module's body (a walked file
    /// or an inline `mod NAME { … }`). A `#[path]` module, a declared module
    /// that links to no walked file and a directory made only as a parent
    /// are unread: a glob of one supplies names the census cannot see.
    read: bool,
}

/// #10322: what the glob imports of a scope can supply for one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Supply {
    /// No glob in reach can bind the name.
    No,
    /// A glob of a read module, or of std or another crate, may bind it.
    Glob,
    /// A glob of a module the census did not read is in reach.
    Unread,
}

/// #10323: one `mod NAME;` declaration, linked once every file is read.
#[derive(Debug)]
struct Decl {
    /// The scope the declaration is written in.
    scope: usize,
    /// The scope of the declaring file.
    top: usize,
    /// The walked path of the declaring file.
    file: String,
    name: String,
}

/// #10293: one leaf of a `use` tree.
#[derive(Debug)]
struct UseLeaf {
    /// The scope the `use` is written in, where its path is resolved.
    scope: usize,
    /// The last segment of its path in [`TypeGraph::segs`].
    tail: usize,
    /// Whether the path starts with `::`.
    global: bool,
    /// The name it binds.
    alias: String,
}

/// One named type of the walked tree: every definition of the name in one
/// scope, merged (a `cfg` split defines one name twice).
#[derive(Debug)]
struct Node {
    scope: usize,
    name: String,
    atoms: Vec<Atom>,
    /// Whether some definition is a struct, enum or union, so a cycle
    /// through it is recursion, not an alias loop.
    adt: bool,
    /// #10295: FNV-1a of the tokens of every definition, in file path order
    /// (#10323: the graph is built over the files sorted by path).
    hash: u64,
}

/// #10293: where a path lands.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Scope(usize),
    Node(usize),
    /// A std, core or alloc path, by its last segment.
    Std(String),
    Foreign {
        root: String,
        name: String,
    },
    /// A value known without a definition.
    Done(Res),
}

/// The value of an unresolvable reason as a target.
fn unres(why: Why) -> Target {
    Target::Done(Res::Unres(why))
}

/// One step of a path walk.
enum Hop {
    To(Target),
    /// An import whose target is needed first.
    Use(usize),
}

/// What a name looks up to in a scope.
enum Look {
    Bound(Bind),
    Many,
    Glob,
    /// #10322: only a glob of an unread module can supply the name.
    Unread,
    Empty,
}

/// A path walk in progress: `segs[pos..]` are left, from `at` (`None`: the
/// first segment is looked up in `scope`).
struct Walk {
    scope: usize,
    segs: Vec<String>,
    global: bool,
    pos: usize,
    at: Option<Target>,
    /// The import this walk resolves, if any.
    leaf: Option<usize>,
}

/// #10293: the scopes, imports and type definitions of the whole tree.
/// Every type name is resolved through the scope that wrote it; no name is
/// looked up across the tree.
#[derive(Debug, Default)]
struct TypeGraph {
    scopes: Vec<Scope>,
    /// Module display path to its scope.
    modules: BTreeMap<String, usize>,
    nodes: Vec<Node>,
    uses: Vec<UseLeaf>,
    /// The segments of every `use` path: `(parent segment, text)`; a leaf's
    /// path is read back from its tail, so a nested tree costs one entry
    /// per segment written.
    segs: Vec<(Option<usize>, String)>,
    /// The resolved target of each import, once known.
    memo: std::cell::RefCell<BTreeMap<usize, Target>>,
    /// #10276: a local name `use`d for one of [`INCLUDE_MACROS`].
    include_aliases: BTreeMap<String, &'static str>,
    /// #10323: every `mod NAME;` of the tree, linked by
    /// [`TypeGraph::link_modules`] after the last file.
    decls: Vec<Decl>,
    /// #10323: each walked path to the scope of its file.
    files: BTreeMap<String, usize>,
    /// #10324: every scope visit of [`TypeGraph::glob_supplies`], read by
    /// the cost test through [`token_census_counted`].
    glob_visits: std::cell::Cell<u64>,
    /// #10324: the answer of [`TypeGraph::glob_supplies`] through a scope,
    /// per name, then per scope; cleared once the globs are settled.
    glob_memo: std::cell::RefCell<BTreeMap<String, BTreeMap<usize, Supply>>>,
}

/// #10324: one scope of the glob walk of [`TypeGraph::glob_supplies`]: the
/// globs of `scope` left to follow (`next` down to 0) and the lowest depth of
/// a scope in progress that its walk met (its own depth when none).
#[derive(Debug, Clone, Copy)]
struct GlobFrame {
    scope: usize,
    next: usize,
    low: usize,
}

/// One keyword position of a lexed file, for [`TypeGraph::item`].
struct At<'t> {
    t: &'t [Tok],
    close: &'t [Option<usize>],
    lens: &'t [Option<usize>],
    k: usize,
    scope: usize,
    binds: bool,
    /// #10323: the walked path of the file and the scope of its file.
    file: &'t str,
    top: usize,
}

impl TypeGraph {
    fn new_scope(&mut self, outer: Option<usize>, parent: Option<usize>, path: String) -> usize {
        self.scopes.push(Scope {
            outer,
            parent,
            path,
            ..Scope::default()
        });
        self.scopes.len() - 1
    }

    /// The module `name` under the module `parent`, made and bound once.
    fn child(&mut self, parent: usize, name: &str) -> usize {
        let key = format!("{}::{name}", self.scopes[parent].path);
        let id = self.module_scope(key, Some(parent));
        self.bind(parent, name, Bind::Module(id));
        id
    }

    /// The scope of the module keyed `key`, made once under `parent`.
    fn module_scope(&mut self, key: String, parent: Option<usize>) -> usize {
        if let Some(&m) = self.modules.get(&key) {
            return m;
        }
        let m = self.new_scope(None, parent, key.clone());
        self.modules.insert(key, m);
        m
    }

    /// Binds `name` in `scope`, once per distinct binding. Two distinct
    /// bindings already make the name `Ambiguous`, so at most
    /// [`MAX_BINDINGS`] are kept and each bind costs O(1), whatever the
    /// count of `use` lines naming one name.
    fn bind(&mut self, scope: usize, name: &str, b: Bind) {
        let v = self.scopes[scope]
            .items
            .entry(name.to_string())
            .or_default();
        if v.len() < MAX_BINDINGS && !v.contains(&b) {
            v.push(b);
        }
    }

    /// The module of a walked file, with every parent module made.
    fn file_module(&mut self, path: &str) -> usize {
        let (root, segs) = module_of(path);
        let mut m = self.module_scope(root, None);
        for s in &segs {
            m = self.child(m, s);
        }
        m
    }

    /// The node of `name` defined in `scope`: one node per name and scope.
    fn define(&mut self, scope: usize, name: &str) -> usize {
        let found = self.scopes[scope].items.get(name).and_then(|bs| {
            bs.iter().find_map(|b| match b {
                Bind::Def(n) => Some(*n),
                _ => None,
            })
        });
        if let Some(n) = found {
            return n;
        }
        self.nodes.push(Node {
            scope,
            name: name.to_string(),
            atoms: Vec::new(),
            adt: false,
            hash: FNV_OFFSET,
        });
        let n = self.nodes.len() - 1;
        self.bind(scope, name, Bind::Def(n));
        n
    }

    /// Collects the scopes, imports and definitions of one lexed file,
    /// outside `macro_rules!` bodies, and returns the scope of each token
    /// as `(first token, scope)` spans in token order. A function body is
    /// a scope that falls back to its enclosing one; an `impl` or `trait`
    /// body binds no type name. Linear in the token count.
    fn file(
        &mut self,
        path: &str,
        t: &[Tok],
        close: &[Option<usize>],
        lens: &[Option<usize>],
        in_macro: &[bool],
    ) -> Vec<(usize, usize)> {
        let top = self.file_module(path);
        self.scopes[top].read = true;
        self.files.insert(path.to_string(), top);
        let mut spans = vec![(0, top)];
        // (index of the closing brace, scope inside, whether types bind).
        let mut stack: Vec<(usize, usize, bool)> = Vec::new();
        let mut opens: BTreeMap<usize, (usize, bool)> = BTreeMap::new();
        let mut path_attr = false;
        for k in 0..t.len() {
            while stack.last().is_some_and(|&(end, _, _)| k > end) {
                stack.pop();
                spans.push((k, stack.last().map_or(top, |e| e.1)));
            }
            if let Some((s, binds)) = opens.remove(&k) {
                stack.push((close[k].unwrap_or(t.len()), s, binds));
                spans.push((k, s));
            }
            if in_macro[k] {
                continue;
            }
            if is_p(t, k, "#") && is_p(t, k + 1, "[") && is_w(t, k + 2, "path") {
                path_attr = true;
                continue;
            }
            if t[k].kind != TokKind::Ident {
                continue;
            }
            let (scope, binds) = stack.last().map_or((top, true), |e| (e.1, e.2));
            let at = At {
                t,
                close,
                lens,
                k,
                scope,
                binds,
                file: path,
                top,
            };
            self.item(&at, &mut opens, &mut path_attr);
        }
        spans
    }

    /// One keyword of [`TypeGraph::file`].
    fn item(&mut self, at: &At, opens: &mut BTreeMap<usize, (usize, bool)>, path_attr: &mut bool) {
        let At {
            t, close, k, scope, ..
        } = *at;
        let ident = |i: usize| {
            t.get(i)
                .filter(|x| x.kind == TokKind::Ident)
                .map(|x| x.text.clone())
        };
        let word = t[k].text.as_str();
        match word {
            "use" => self.use_tree(scope, t, close, k + 1),
            "mod" => {
                if let Some(name) = ident(k + 1) {
                    if is_p(t, k + 2, "{") {
                        let m = self.child(scope, &name);
                        self.scopes[m].read = true;
                        opens.entry(k + 2).or_insert((m, true));
                    } else if *path_attr {
                        // #10293: a `#[path]` module is not followed; a
                        // path through it lands nowhere.
                        let key = format!("{}::{name}#path", self.scopes[scope].path);
                        let m = self.new_scope(None, Some(scope), key);
                        self.bind(scope, &name, Bind::Module(m));
                    } else {
                        // #10323: linked after the last file is read.
                        self.decls.push(Decl {
                            scope,
                            top: at.top,
                            file: at.file.to_string(),
                            name,
                        });
                    }
                }
                *path_attr = false;
            }
            "fn" => {
                // The body follows the generics and the parameter list.
                let mut from = k + 2;
                if is_p(t, from, "<") {
                    from = generics(t, close, from).0;
                }
                if is_p(t, from, "(") {
                    from = close[from].map_or(from + 1, |c| c + 1);
                }
                if let Some(name) = ident(k + 1)
                    && let Some((open, _)) = adt_body(t, close, from)
                    && !opens.contains_key(&open)
                {
                    let key = format!("{}::{{fn {name}}}", self.scopes[scope].path);
                    let b = self.new_scope(Some(scope), None, key);
                    opens.insert(open, (b, true));
                }
                *path_attr = false;
            }
            "impl" | "trait" => {
                let from = if word == "trait" { k + 2 } else { k + 1 };
                if let Some((open, _)) = adt_body(t, close, from) {
                    opens.entry(open).or_insert((scope, false));
                }
                *path_attr = false;
            }
            "type" | "struct" | "enum" | "union" => {
                if at.binds {
                    self.definition(at);
                }
                *path_attr = false;
            }
            _ => {}
        }
    }

    /// #10323: links every `mod NAME;` once every file is read, so no link
    /// depends on the order the files were walked in. A declaration binds
    /// the scope of each walked file [`decl_candidates`] names (two make the
    /// name `Ambiguous`); with none walked it binds the module under its
    /// scope, which stays unread (#10322) unless a walked file is that
    /// module. Linear in the declarations.
    fn link_modules(&mut self) {
        let decls = std::mem::take(&mut self.decls);
        for d in &decls {
            let inline = self.scopes[d.scope]
                .path
                .strip_prefix(self.scopes[d.top].path.as_str())
                .filter(|_| self.scopes[d.scope].outer.is_none());
            let found: Vec<usize> = inline
                .map(|rest| decl_candidates(&d.file, rest, &d.name))
                .unwrap_or_default()
                .iter()
                .filter_map(|c| self.files.get(c).copied())
                .collect();
            if found.is_empty() {
                self.child(d.scope, &d.name);
            }
            for m in found {
                self.bind(d.scope, &d.name, Bind::Module(m));
            }
        }
    }

    /// A `type`, `struct`, `enum` or `union` definition at `at.k`.
    fn definition(&mut self, at: &At) {
        let At {
            t,
            close,
            lens,
            k,
            scope,
            ..
        } = *at;
        let w = t[k].text.as_str();
        let Some(name) = t
            .get(k + 1)
            .filter(|x| x.kind == TokKind::Ident)
            .map(|x| x.text.clone())
        else {
            return;
        };
        if w == "union" && !(is_p(t, k + 2, "{") || is_p(t, k + 2, "<")) {
            return;
        }
        let (j, params, defaults) = if is_p(t, k + 2, "<") {
            generics(t, close, k + 2)
        } else {
            (k + 2, Vec::new(), Vec::new())
        };
        let ps: BTreeSet<&str> = params.iter().map(String::as_str).collect();
        let mut atoms = Vec::new();
        for d in defaults {
            type_atoms(t, close, lens, d, &ps, &mut atoms);
        }
        let end = if w == "type" {
            if is_p(t, j, "=") {
                let e = type_end(t, close, j + 1);
                type_atoms(t, close, lens, (j + 1, e), &ps, &mut atoms);
                e
            } else {
                atoms.push(Atom::Unres(Why::NoValue(name.clone())));
                j
            }
        } else if let Some((open, c)) = adt_body(t, close, j) {
            if w == "enum" {
                enum_atoms(t, close, lens, (open, c), &ps, &mut atoms);
            } else {
                type_atoms(t, close, lens, (open + 1, c), &ps, &mut atoms);
            }
            c + 1
        } else {
            j
        };
        let h = token_hash(t, (k, end));
        let n = self.define(scope, &name);
        let node = &mut self.nodes[n];
        node.adt |= w != "type";
        node.atoms.extend(atoms);
        node.hash = fnv(node.hash, &h.to_le_bytes());
    }

    /// Records every leaf of the `use` tree that starts at `from` in
    /// `scope`. An explicit stack keeps any nesting depth off the call
    /// stack; each segment written is stored once, so the walk is linear.
    fn use_tree(&mut self, scope: usize, t: &[Tok], close: &[Option<usize>], from: usize) {
        let end = type_end(t, close, from);
        let global = is_p(t, from, ":") && is_p(t, from + 1, ":");
        // (position, end of this level, the prefix's last segment).
        let mut stack: Vec<(usize, usize, Option<usize>)> = vec![(from, end, None)];
        while let Some((mut i, end, base)) = stack.pop() {
            while is_p(t, i, ",") && i < end {
                i += 1;
            }
            if i >= end {
                continue;
            }
            let start = i;
            if is_p(t, i, ":") && is_p(t, i + 1, ":") {
                i += 2;
            }
            let mut tail = base;
            while let Some(x) = t.get(i).filter(|x| x.kind == TokKind::Ident && i < end) {
                if x.text == "as" {
                    break;
                }
                self.segs.push((tail, x.text.clone()));
                tail = Some(self.segs.len() - 1);
                i += 1;
                if is_p(t, i, ":") && is_p(t, i + 1, ":") {
                    i += 2;
                } else {
                    break;
                }
            }
            if is_p(t, i, "{") {
                let c = close[i].unwrap_or(end);
                stack.push((c + 1, end, base));
                stack.push((i + 1, c, tail));
                continue;
            }
            if is_p(t, i, "*") {
                self.scopes[scope].globs.push((tail, global));
                stack.push((i + 1, end, base));
                continue;
            }
            let renamed = if is_w(t, i, "as") {
                i += 2;
                t.get(i - 1)
                    .filter(|x| x.kind == TokKind::Ident)
                    .map_or(Rename::Unnamed, |x| Rename::As(x.text.clone()))
            } else {
                Rename::Keep
            };
            if let Some(leaf) = tail {
                self.use_leaf(scope, leaf, global, renamed);
            }
            stack.push((i.max(start + 1), end, base));
        }
    }

    /// Binds one `use` leaf whose last segment is `segs[leaf]`. A trailing
    /// `self` names its prefix; `_` binds nothing.
    fn use_leaf(&mut self, scope: usize, leaf: usize, global: bool, renamed: Rename) {
        let (parent, text) = &self.segs[leaf];
        let (tail, last) = if text == "self" {
            match parent {
                Some(p) => (*p, self.segs[*p].1.clone()),
                None => return,
            }
        } else {
            (leaf, text.clone())
        };
        let alias = match renamed {
            Rename::As(a) => a,
            Rename::Unnamed => return,
            Rename::Keep => last.clone(),
        };
        if alias == "_" {
            return;
        }
        if let Some(m) = INCLUDE_MACROS.iter().find(|m| **m == last)
            && alias != last
        {
            self.include_aliases.insert(alias.clone(), m);
        }
        self.uses.push(UseLeaf {
            scope,
            tail,
            global,
            alias: alias.clone(),
        });
        let u = self.uses.len() - 1;
        self.bind(scope, &alias, Bind::Use(u));
    }

    /// The path of an import, read back from its tail.
    fn use_path(&self, tail: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut at = Some(tail);
        while let Some(i) = at {
            out.push(self.segs[i].1.clone());
            at = self.segs[i].0;
        }
        out.reverse();
        out
    }

    /// The module a scope belongs to: a function body's enclosing module.
    fn module_of_scope(&self, mut s: usize) -> usize {
        while let Some(o) = self.scopes[s].outer {
            s = o;
        }
        s
    }

    /// The crate root of a scope.
    fn crate_of(&self, s: usize) -> usize {
        let mut m = self.module_of_scope(s);
        while let Some(p) = self.scopes[m].parent {
            m = self.module_of_scope(p);
        }
        m
    }

    /// The parent module of a module, or why `super` lands nowhere.
    fn super_of(&self, m: usize) -> Target {
        self.scopes[m].parent.map_or_else(
            || unres(Why::PathNotLanded("super".to_string())),
            |p| Target::Scope(self.module_of_scope(p)),
        )
    }

    /// `name` in `scope` and, for a function body, the scopes around it.
    /// A glob import in a scope that binds the name explicitly is shadowed
    /// there; one that does not may supply it.
    fn look(&self, scope: usize, name: &str, outward: bool) -> Look {
        let mut at = Some(scope);
        while let Some(id) = at {
            let s = &self.scopes[id];
            if let Some(bs) = s.items.get(name) {
                return match bs.as_slice() {
                    [b] => Look::Bound(*b),
                    _ => Look::Many,
                };
            }
            match self.glob_supplies(id, name) {
                Supply::Glob => return Look::Glob,
                Supply::Unread => return Look::Unread,
                Supply::No => {}
            }
            at = if outward { s.outer } else { None };
        }
        Look::Empty
    }

    /// #10294: whether a glob import of `scope` can supply `name`: a glob
    /// whose module is not known (std, another crate, not settled) can
    /// supply any name; one of a walked module supplies the names that
    /// module binds, and the names its own globs can supply. #10322: a glob
    /// of a module the census did not read is [`Supply::Unread`] for every
    /// name, never [`Supply::No`].
    ///
    /// #10324: the closure is walked depth first, in the order of the
    /// former stack walk (the last glob first), and the answer through each
    /// scope other than `scope` is memoised per `(scope, name)` once it does
    /// not depend on a scope still in progress (a cycle back to one), so a
    /// glob chain is walked once, not once per lookup.
    fn glob_supplies(&self, scope: usize, name: &str) -> Supply {
        // Each scope met: `Some(depth)` while its frame is on the stack.
        let mut seen: BTreeMap<usize, Option<usize>> = BTreeMap::new();
        let mut frames: Vec<GlobFrame> = Vec::new();
        seen.insert(scope, Some(0));
        self.glob_visit();
        if let Some(r) = self.glob_own(scope, name, true) {
            return r;
        }
        frames.push(GlobFrame {
            scope,
            next: self.scopes[scope].glob_to.len(),
            low: 0,
        });
        while let Some(top) = frames.last_mut() {
            if top.next == 0 {
                let done = *top;
                frames.pop();
                let depth = frames.len();
                if let Some(parent) = frames.last_mut() {
                    if done.low >= depth {
                        self.glob_memo_put(done.scope, name, Supply::No);
                    }
                    parent.low = parent.low.min(done.low);
                }
                seen.insert(done.scope, None);
                continue;
            }
            top.next -= 1;
            let Some(child) = self.scopes[top.scope].glob_to[top.next] else {
                return Supply::Glob;
            };
            if let Some(r) = self.glob_memo_get(child, name) {
                self.glob_visit();
                if r == Supply::No {
                    continue;
                }
                return self.glob_found(&frames, name, r);
            }
            if let Some(&at) = seen.get(&child) {
                // A cycle back to a scope in progress, or a scope finished
                // under one: whatever reaches it is not memoised.
                top.low = top.low.min(at.unwrap_or(0));
                continue;
            }
            let depth = frames.len();
            seen.insert(child, Some(depth));
            self.glob_visit();
            if let Some(r) = self.glob_own(child, name, false) {
                self.glob_memo_put(child, name, r);
                return self.glob_found(&frames, name, r);
            }
            frames.push(GlobFrame {
                scope: child,
                next: self.scopes[child].glob_to.len(),
                low: depth,
            });
        }
        Supply::No
    }

    /// #10324: what `s` itself supplies for `name` before its globs are
    /// followed; `root` is the scope looked up in, whose own items and
    /// reading are judged by [`TypeGraph::look`].
    fn glob_own(&self, s: usize, name: &str, root: bool) -> Option<Supply> {
        let sc = &self.scopes[s];
        if !root && sc.items.contains_key(name) {
            return Some(Supply::Glob);
        }
        if !root && !sc.read {
            return Some(Supply::Unread);
        }
        if sc.glob_to.len() != sc.globs.len() || sc.glob_to.iter().any(Option::is_none) {
            return Some(Supply::Glob);
        }
        None
    }

    /// #10324: `r`, found below every frame of `frames`, is the answer of
    /// each frame other than the root; it is memoised for each frame whose
    /// walk met no scope in progress above it.
    fn glob_found(&self, frames: &[GlobFrame], name: &str, r: Supply) -> Supply {
        let mut low = usize::MAX;
        for (depth, f) in frames.iter().enumerate().skip(1).rev() {
            low = low.min(f.low);
            if low >= depth {
                self.glob_memo_put(f.scope, name, r);
            }
        }
        r
    }

    /// #10324: the memoised answer through `s` for `name`, if any.
    fn glob_memo_get(&self, s: usize, name: &str) -> Option<Supply> {
        self.glob_memo
            .borrow()
            .get(name)
            .and_then(|m| m.get(&s))
            .copied()
    }

    /// #10324: memoises the answer through `s` for `name`.
    fn glob_memo_put(&self, s: usize, name: &str, r: Supply) {
        self.glob_memo
            .borrow_mut()
            .entry(name.to_string())
            .or_default()
            .insert(s, r);
    }

    /// #10324: counts one scope visit of [`TypeGraph::glob_supplies`].
    fn glob_visit(&self) {
        self.glob_visits
            .set(self.glob_visits.get().saturating_add(1));
    }

    /// #10294: settles the module of every glob import once every file is
    /// walked. A glob met while settling counts as unknown (it can supply
    /// any name), and the import targets found meanwhile are dropped after.
    fn settle_globs(&mut self) {
        let mut settled = Vec::with_capacity(self.scopes.len());
        for s in 0..self.scopes.len() {
            let to: Vec<Option<usize>> = self.scopes[s]
                .globs
                .iter()
                .map(|&(tail, global)| {
                    let segs = tail.map(|t| self.use_path(t)).unwrap_or_default();
                    match self.resolve(s, &segs, global) {
                        Target::Scope(m) if !segs.is_empty() => Some(m),
                        _ => None,
                    }
                })
                .collect();
            settled.push(to);
        }
        for (s, to) in settled.into_iter().enumerate() {
            self.scopes[s].glob_to = to;
        }
        self.memo.get_mut().clear();
        // #10324: an answer memoised while settling read unsettled globs.
        self.glob_memo.get_mut().clear();
    }

    /// A path root that nothing in scope binds: std, this crate's library,
    /// or another crate.
    fn root_target(&self, root: &str) -> Target {
        if STD_ROOTS.contains(&root) {
            Target::Std(root.to_string())
        } else if root == CRATE_NAME {
            self.modules.get(LIB_SCOPE).map_or_else(
                || unres(Why::PathNotLanded(root.to_string())),
                |&m| Target::Scope(m),
            )
        } else {
            Target::Foreign {
                root: root.to_string(),
                name: root.to_string(),
            }
        }
    }

    /// The step a binding takes. A bare prelude or primitive name bound
    /// to a local definition is shadowed.
    fn hop(b: Bind, name: &str, bare: bool) -> Hop {
        match b {
            Bind::Module(m) => Hop::To(Target::Scope(m)),
            Bind::Def(_) if bare && is_prelude(name) => {
                Hop::To(unres(Why::Shadowed(name.to_string())))
            }
            Bind::Def(n) => Hop::To(Target::Node(n)),
            Bind::Use(u) => Hop::Use(u),
        }
    }

    /// The first segment of a path written in `scope`.
    fn first(&self, scope: usize, seg: &str, global: bool, last: bool) -> Hop {
        if global {
            return Hop::To(self.root_target(seg));
        }
        match seg {
            "crate" => return Hop::To(Target::Scope(self.crate_of(scope))),
            "self" => return Hop::To(Target::Scope(self.module_of_scope(scope))),
            "super" => return Hop::To(self.super_of(self.module_of_scope(scope))),
            _ => {}
        }
        match self.look(scope, seg, true) {
            Look::Bound(b) => Self::hop(b, seg, last),
            Look::Many => Hop::To(unres(Why::Ambiguous(seg.to_string()))),
            Look::Glob => Hop::To(unres(Why::Glob(seg.to_string()))),
            Look::Unread => Hop::To(unres(Why::PathNotLanded(seg.to_string()))),
            // P6: `use Mutex as Gatekeeper` names a lock by its bare name.
            Look::Empty if last && LOCK_TYPES.contains(&seg) => Hop::To(Target::Done(Res::Lock)),
            Look::Empty if last && is_prelude(seg) => Hop::To(Target::Done(Res::Clean)),
            Look::Empty if last => Hop::To(unres(Why::NoDef(seg.to_string()))),
            Look::Empty => Hop::To(self.root_target(seg)),
        }
    }

    /// A later segment of a path, from the module `m`.
    fn inner(&self, m: usize, seg: &str) -> Hop {
        match seg {
            "super" => return Hop::To(self.super_of(m)),
            "self" => return Hop::To(Target::Scope(m)),
            _ => {}
        }
        match self.look(m, seg, false) {
            Look::Bound(b) => Self::hop(b, seg, false),
            Look::Many => Hop::To(unres(Why::Ambiguous(seg.to_string()))),
            Look::Glob => Hop::To(unres(Why::Glob(seg.to_string()))),
            Look::Unread | Look::Empty => Hop::To(unres(Why::PathNotLanded(seg.to_string()))),
        }
    }

    /// Walks `w` until it lands or needs an import not yet resolved.
    fn step(&self, w: &mut Walk, memo: &BTreeMap<usize, Target>) -> Result<Target, usize> {
        while let Some(seg) = w.segs.get(w.pos) {
            let last = w.pos + 1 == w.segs.len();
            let hop = match &w.at {
                None => self.first(w.scope, seg, w.global, last),
                Some(Target::Scope(m)) => self.inner(*m, seg),
                Some(Target::Std(_)) => Hop::To(Target::Std(seg.clone())),
                Some(Target::Foreign { root, .. }) => Hop::To(Target::Foreign {
                    root: root.clone(),
                    name: seg.clone(),
                }),
                Some(Target::Node(_) | Target::Done(Res::Clean)) => Hop::To(unres(Why::Projection)),
                Some(Target::Done(r)) => return Ok(Target::Done(r.clone())),
            };
            match hop {
                Hop::To(t) => w.at = Some(t),
                Hop::Use(u) => match memo.get(&u) {
                    Some(t) => w.at = Some(t.clone()),
                    None => return Err(u),
                },
            }
            w.pos += 1;
        }
        Ok(w.at.take().unwrap_or(Target::Done(Res::Clean)))
    }

    /// Where the path `segs` written in `scope` lands. Imports are followed
    /// on an explicit stack and each is resolved once (memoised), so a long
    /// rename chain costs its length once; an import met again while it is
    /// being resolved is a cycle.
    fn resolve(&self, scope: usize, segs: &[String], global: bool) -> Target {
        let mut memo = self.memo.borrow_mut();
        let mut on: BTreeSet<usize> = BTreeSet::new();
        let mut stack = vec![Walk {
            scope,
            segs: segs.to_vec(),
            global,
            pos: 0,
            at: None,
            leaf: None,
        }];
        while let Some(w) = stack.last_mut() {
            match self.step(w, &memo) {
                Err(u) if on.contains(&u) => {
                    w.at = Some(unres(Why::Cycle(self.uses[u].alias.clone())));
                    w.pos = w.segs.len();
                }
                Err(u) => {
                    on.insert(u);
                    let leaf = &self.uses[u];
                    stack.push(Walk {
                        scope: leaf.scope,
                        segs: self.use_path(leaf.tail),
                        global: leaf.global,
                        pos: 0,
                        at: None,
                        leaf: Some(u),
                    });
                }
                Ok(t) => {
                    let done = stack.pop().and_then(|w| w.leaf);
                    if let Some(u) = done {
                        on.remove(&u);
                        memo.insert(u, t.clone());
                    }
                    match stack.last_mut() {
                        Some(p) => {
                            p.at = Some(t);
                            p.pos += 1;
                        }
                        None => return t,
                    }
                }
            }
        }
        Target::Done(Res::Clean)
    }

    /// One atom written in `scope`: its value now, or the node it waits on.
    fn atom(&self, scope: usize, a: &Atom) -> Result<Res, usize> {
        match a {
            Atom::Lock => Ok(Res::Lock),
            Atom::Unres(w) => Ok(Res::Unres(w.clone())),
            Atom::Param(n) => {
                // #10293: a parameter that hides a name the scope binds,
                // a lock name or a std name is refused.
                let bound = matches!(self.look(scope, n, true), Look::Bound(_) | Look::Many);
                let known = [&LOCK_TYPES[..], &LEAF_TYPES[..]]
                    .iter()
                    .any(|set| set.contains(&n.as_str()));
                if bound || known || is_prelude(n) {
                    Ok(Res::Unres(Why::Shadowed(n.clone())))
                } else {
                    Ok(Res::Clean)
                }
            }
            Atom::Path { segs, global } => {
                let last = segs.last().cloned().unwrap_or_default();
                match self.resolve(scope, segs, *global) {
                    Target::Node(n) => Err(n),
                    Target::Scope(_) => Ok(Res::Unres(Why::PathNotLanded(last))),
                    Target::Std(name) | Target::Foreign { name, .. }
                        if LOCK_TYPES.contains(&name.as_str()) =>
                    {
                        Ok(Res::Lock)
                    }
                    Target::Std(name) if LEAF_TYPES.contains(&name.as_str()) => Ok(Res::Clean),
                    Target::Std(name) => Ok(Res::Unres(Why::StdNotProven(name))),
                    Target::Foreign { root, name } => Ok(Res::Unres(Why::Foreign { root, name })),
                    Target::Done(r) => Ok(r),
                }
            }
        }
    }

    /// The value of every node: strongly connected components by an
    /// iterative Tarjan walk (no recursion), each settled after the ones it
    /// reaches. Linear in nodes plus atoms. A cycle with no struct, enum or
    /// union in it is an alias loop: [`Why::Cycle`].
    fn values(&self) -> Resolved<'_> {
        let n = self.nodes.len();
        let mut base = vec![Res::Clean; n];
        let mut edges: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (v, node) in self.nodes.iter().enumerate() {
            for a in &node.atoms {
                match self.atom(node.scope, a) {
                    Ok(r) => base[v] = std::mem::replace(&mut base[v], Res::Clean).join(r),
                    Err(w) => edges[v].push(w),
                }
            }
        }
        let unset = usize::MAX;
        let mut order = vec![unset; n];
        let mut low = vec![0usize; n];
        let mut on = vec![false; n];
        let mut comp = vec![unset; n];
        let mut comp_val: Vec<Res> = Vec::new();
        let mut stack: Vec<usize> = Vec::new();
        let mut counter = 0usize;
        for s in 0..n {
            if order[s] != unset {
                continue;
            }
            let mut call: Vec<(usize, usize)> = vec![(s, 0)];
            order[s] = counter;
            low[s] = counter;
            counter += 1;
            stack.push(s);
            on[s] = true;
            while let Some(&(v, e)) = call.last() {
                if let Some(&w) = edges[v].get(e) {
                    if let Some(top) = call.last_mut() {
                        top.1 += 1;
                    }
                    if order[w] == unset {
                        order[w] = counter;
                        low[w] = counter;
                        counter += 1;
                        stack.push(w);
                        on[w] = true;
                        call.push((w, 0));
                    } else if on[w] {
                        low[v] = low[v].min(order[w]);
                    }
                    continue;
                }
                call.pop();
                if let Some(&(u, _)) = call.last() {
                    low[u] = low[u].min(low[v]);
                }
                if low[v] != order[v] {
                    continue;
                }
                let id = comp_val.len();
                let mut members = Vec::new();
                while let Some(w) = stack.pop() {
                    on[w] = false;
                    comp[w] = id;
                    members.push(w);
                    if w == v {
                        break;
                    }
                }
                let val = self.component(&members, &base, &edges, (&comp, &comp_val), id);
                comp_val.push(val);
            }
        }
        Resolved {
            graph: self,
            value: comp.iter().map(|&c| comp_val[c].clone()).collect(),
            edges,
        }
    }

    /// The value of the strongly connected component `id`: its members'
    /// own atoms joined with every component it reaches, all settled.
    fn component(
        &self,
        members: &[usize],
        base: &[Res],
        edges: &[Vec<usize>],
        (comp, comp_val): (&[usize], &[Res]),
        id: usize,
    ) -> Res {
        let mut val = Res::Clean;
        let mut cyclic = members.len() > 1;
        for &m in members {
            val = val.join(base[m].clone());
            for &w in &edges[m] {
                if comp[w] == id {
                    cyclic = true;
                } else {
                    val = val.join(comp_val[comp[w]].clone());
                }
            }
        }
        if cyclic && !members.iter().any(|&m| self.nodes[m].adt) {
            let first = members
                .iter()
                .map(|&m| self.nodes[m].name.as_str())
                .min()
                .unwrap_or_default();
            val = val.join(Res::Unres(Why::Cycle(first.to_string())));
        }
        val
    }
}

/// The settled value of every named type, and the edges between them.
struct Resolved<'g> {
    graph: &'g TypeGraph,
    value: Vec<Res>,
    edges: Vec<Vec<usize>>,
}

/// #10295: the digest entry key of a static's own written type.
const OWN_TYPE_KEY: &str = "type";

/// A 64-bit hash shown as 8 hex digits: the two halves folded together.
fn hex8(h: u64) -> String {
    let folded = (h >> 32) ^ (h & 0xffff_ffff);
    format!("{folded:08x}")
}

impl Resolved<'_> {
    /// What the type with these atoms, written in `scope`, holds.
    fn of(&self, scope: usize, atoms: &[Atom]) -> Res {
        atoms.iter().fold(Res::Clean, |acc, a| {
            acc.join(match self.graph.atom(scope, a) {
                Ok(r) => r,
                Err(n) => self.value[n].clone(),
            })
        })
    }

    /// #10295: the digest of a static's type: `type=<hash>` of its own
    /// written tokens, then `<module path>::<name>=<hash>` of every
    /// definition reached from it, each once, sorted. Linear in the nodes
    /// and edges reached.
    fn digest(&self, scope: usize, atoms: &[Atom], own: u64) -> String {
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        let mut todo: Vec<usize> = atoms
            .iter()
            .filter_map(|a| self.graph.atom(scope, a).err())
            .collect();
        while let Some(n) = todo.pop() {
            if seen.insert(n) {
                todo.extend(self.edges[n].iter().copied().filter(|w| !seen.contains(w)));
            }
        }
        let g = self.graph;
        let mut entries: Vec<String> = seen
            .iter()
            .map(|&n| {
                let node = &g.nodes[n];
                format!(
                    "{}::{}={}",
                    g.scopes[node.scope].path,
                    node.name,
                    hex8(node.hash)
                )
            })
            .collect();
        entries.sort();
        entries.insert(0, format!("{OWN_TYPE_KEY}={}", hex8(own)));
        entries.join(" ")
    }
}

/// #10295: the key of the first entry of `live`, in written order (the
/// `type` entry first), that `pinned` does not hold with the same hash,
/// else of the first entry of `pinned` that `live` lacks: the type whose
/// definition changed. `None` when they are equal.
fn digest_change(pinned: &str, live: &str) -> Option<String> {
    let set = |s: &str| -> BTreeSet<String> { s.split_whitespace().map(str::to_string).collect() };
    let (p, l) = (set(pinned), set(live));
    live.split_whitespace()
        .chain(pinned.split_whitespace())
        .find(|e| !p.contains(*e) || !l.contains(*e))
        .map(str::to_string)
        .map(|e| {
            e.rsplit_once('=')
                .map_or_else(|| e.clone(), |(k, _)| k.to_string())
        })
}

/// #10293: the scope of token `k` from the `(first token, scope)` spans
/// [`TypeGraph::file`] returns, which are in token order.
fn scope_at(spans: &[(usize, usize)], k: usize) -> usize {
    let i = spans.partition_point(|s| s.0 <= k);
    spans[i.saturating_sub(1)].1
}

/// #10295: the [`StaticFinding::ExceptionDigest`] of a taken exception row
/// whose pinned digest is not the live one. An empty pin never matches.
fn digest_finding(file: &str, name: &str, pinned: &str, live: &str) -> Option<StaticFinding> {
    digest_change(pinned, live).map(|ty| StaticFinding::ExceptionDigest {
        file: file.to_string(),
        name: name.to_string(),
        ty,
    })
}

/// The atoms of an enum body `t[open..=c]`: variant names and
/// discriminants are skipped, each variant's fields are judged.
fn enum_atoms(
    t: &[Tok],
    close: &[Option<usize>],
    lens: &[Option<usize>],
    (open, c): (usize, usize),
    params: &BTreeSet<&str>,
    out: &mut Vec<Atom>,
) {
    let mut i = open + 1;
    while i < c {
        if is_p(t, i, "#") && is_p(t, i + 1, "[") {
            i = close[i + 1].map_or(c, |e| e + 1);
        } else if t[i].kind == TokKind::Ident {
            i += 1;
            if (is_p(t, i, "(") || is_p(t, i, "{"))
                && let Some(e) = close[i]
            {
                type_atoms(t, close, lens, (i + 1, e), params, out);
                i = e + 1;
            }
        } else if is_p(t, i, "=") {
            i += 1;
            while i < c && !is_p(t, i, ",") {
                i = close[i].map_or(i + 1, |e| e + 1);
            }
        } else {
            i += 1;
        }
    }
}

/// Visible characters of a reason: letters, digits and ASCII punctuation.
fn visible(s: &str) -> usize {
    s.chars()
        .filter(|c| c.is_alphanumeric() || c.is_ascii_punctuation())
        .count()
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
    /// #10276: a walked file whose count of identifier tokens `ident` (one
    /// of [`COUNTED_IDENTS`]) differs from its [`INCLUDE_ROWS`] row; a file
    /// with no row has `rowed: 0`.
    IncludeCount {
        file: String,
        ident: String,
        rowed: usize,
        found: usize,
    },
    /// An [`INCLUDE_ROWS`] row for a file the walk did not read.
    IncludeRowStale { file: String, ident: String },
    /// An [`INCLUDE_ROWS`] key written twice.
    IncludeRowDuplicate { file: String, ident: String },
    /// An [`INCLUDE_ROWS`] row with a short reason, a zero count or an
    /// identifier outside [`COUNTED_IDENTS`].
    IncludeRowBad { file: String, ident: String },
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

/// One piece of an include argument.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    /// A string literal, escapes decoded.
    Lit(String),
    /// `env!("CARGO_MANIFEST_DIR")`: the crate root.
    ManifestDir,
}

/// One piece of an include argument: a literal or the manifest dir.
fn piece_value(t: &[Tok]) -> Result<Piece, ValueError> {
    match t {
        [s] if s.kind == TokKind::Str => decode_str(&s.text).map(Piece::Lit),
        [e, bang, open, var, close]
            if e.kind == TokKind::Ident
                && e.text == "env"
                && bang.text == "!"
                && open.text == "("
                && close.text == ")"
                && var.kind == TokKind::Str =>
        {
            if decode_str(&var.text)? == MANIFEST_DIR_VAR {
                Ok(Piece::ManifestDir)
            } else {
                Err(ValueError::NotLiteral)
            }
        }
        _ => Err(ValueError::NotLiteral),
    }
}

/// The value of an include macro's argument tokens (inside its parens),
/// and whether it is anchored at the crate root: #10250, the manifest dir
/// counts only as the first piece; anywhere else the value is not a
/// literal, because what it names cannot be resolved.
fn include_value(t: &[Tok]) -> Result<(String, bool), ValueError> {
    let is_concat = t.len() >= 4
        && is_w(t, 0, "concat")
        && is_p(t, 1, "!")
        && is_p(t, 2, "(")
        && close_of(t, 2) == Some(t.len() - 1);
    let pieces: Vec<&[Tok]> = if is_concat {
        let inner = &t[3..t.len() - 1];
        let mut out = Vec::new();
        let mut from = 0;
        let mut depth = 0usize;
        for (i, k) in inner.iter().enumerate() {
            match (k.kind, k.text.as_str()) {
                (TokKind::Punct, "(" | "[" | "{") => depth += 1,
                (TokKind::Punct, ")" | "]" | "}") => depth = depth.saturating_sub(1),
                (TokKind::Punct, ",") if depth == 0 => {
                    out.push(&inner[from..i]);
                    from = i + 1;
                }
                _ => {}
            }
        }
        if from < inner.len() {
            out.push(&inner[from..]);
        }
        out
    } else {
        vec![t]
    };
    let mut value = String::new();
    let mut anchored = false;
    for (n, p) in pieces.into_iter().enumerate() {
        match piece_value(p)? {
            Piece::Lit(s) => value.push_str(&s),
            Piece::ManifestDir if n == 0 => anchored = true,
            Piece::ManifestDir => return Err(ValueError::NotLiteral),
        }
    }
    Ok((value, anchored))
}

/// #10250: the root-relative path a `#[path]` or `include!` value names,
/// resolved lexically from `base` (the declaring file's directory, or the
/// root when anchored). `None` when it cannot name a walked file: a
/// backslash (not a separator on every host), an absolute value, or a
/// `..` that leaves the root.
fn resolve(base: &str, value: &str) -> Option<String> {
    if value.contains('\\') || value.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = base.split('/').filter(|c| !c.is_empty()).collect();
    for c in value.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(c),
        }
    }
    Some(parts.join("/"))
}

/// The directory part of a root-relative file path (`""` at the root).
fn dir_of(path: &str) -> &str {
    path.rfind('/').map_or("", |i| &path[..i])
}

/// Which construct names a file: `#[path]` or `include!` (the two that
/// compile what they name as Rust).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Names {
    PathAttr,
    Include,
}

/// #10250: the finding for a decoded `#[path]` or `include!` value that
/// does not name a guarded file, or `None` when it names a walked `.rs`
/// file. `anchored` means the value follows `env!("CARGO_MANIFEST_DIR")`.
fn unread_inclusion(
    path: &str,
    line: usize,
    names: Names,
    value: String,
    anchored: bool,
    in_inline_mod: bool,
    walked: &BTreeSet<&str>,
) -> Option<IncludeFinding> {
    let file = path.to_string();
    // Exact, case-sensitive, as the walk reads only `.rs` files.
    if Path::new(&value).extension().is_none_or(|e| e != "rs") {
        return Some(IncludeFinding::NotRustFile { file, line, value });
    }
    if names == Names::PathAttr && in_inline_mod {
        return Some(IncludeFinding::PathInInlineMod { file, line, value });
    }
    let target = if anchored {
        value.strip_prefix('/').and_then(|v| resolve("", v))
    } else {
        resolve(dir_of(path), &value)
    };
    match target {
        Some(t) if walked.contains(t.as_str()) => None,
        _ => Some(IncludeFinding::Unwalked { file, line, value }),
    }
}

/// For each token, whether it sits inside the braces of an inline
/// `mod NAME { … }` block. Linear in the token count.
fn inside_inline_mod(t: &[Tok]) -> Vec<bool> {
    let mut out = vec![false; t.len()];
    let mut stack: Vec<bool> = Vec::new();
    let mut open_mods = 0usize;
    for (i, k) in t.iter().enumerate() {
        out[i] = open_mods > 0;
        if k.kind != TokKind::Punct {
            continue;
        }
        match k.text.as_str() {
            "{" => {
                let is_mod = i >= 2 && t[i - 1].kind == TokKind::Ident && is_w(t, i - 2, "mod");
                open_mods += usize::from(is_mod);
                stack.push(is_mod);
            }
            "(" | "[" => stack.push(false),
            ")" | "]" | "}" => {
                if let Some(is_mod) = stack.pop() {
                    open_mods -= usize::from(is_mod);
                }
            }
            _ => {}
        }
    }
    out
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
    walked: &BTreeSet<&str>,
    aliases: &BTreeMap<String, &'static str>,
    mods: &mut [usize; 2],
    found: &mut Vec<IncludeFinding>,
) {
    let file = || path.to_string();
    let (close, in_attr) = brackets(t);
    let inline = inside_inline_mod(t);
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
                    Ok(value) => found.extend(unread_inclusion(
                        path,
                        tok.line,
                        Names::PathAttr,
                        value,
                        false,
                        inline[k],
                        walked,
                    )),
                    Err(_) => found.push(undecodable(path, tok.line, v.text.clone())),
                },
            }
        }
        // #10276: any of the three delimiters, and a name `use`d as one of
        // the include macros.
        let mac = INCLUDE_MACROS
            .iter()
            .copied()
            .find(|m| *m == tok.text)
            .or_else(|| aliases.get(&tok.text).copied());
        if let Some(mac) = mac
            && is_p(t, k + 1, "!")
            && is_open(t, k + 2)
        {
            let value =
                close[k + 2].map_or(Err(ValueError::NotLiteral), |c| include_value(&t[k + 3..c]));
            match value {
                Ok((value, _)) if names_guarded_file(&value) => {
                    found.push(IncludeFinding::Include {
                        file: file(),
                        line: tok.line,
                        value,
                    });
                }
                // `include_str!` and `include_bytes!` yield a literal, not
                // code: only `include!` must name a walked `.rs` file.
                Ok((value, anchored)) if mac == "include" => found.extend(unread_inclusion(
                    path,
                    tok.line,
                    Names::Include,
                    value,
                    anchored,
                    inline[k],
                    walked,
                )),
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

/// #10275, #10285, #10295: `(path, static name, digest, reason)` for each
/// static whose type does not resolve to [`LEAF_TYPES`], or that sits in a
/// `macro_rules!` body, and is judged by hand. Every row must be used. The
/// digest is `type=<hex8>` (the FNV-1a hash of the written type tokens)
/// then `<module path>::<Name>=<hex8>` for each walked definition the type
/// reaches, sorted; a macro-body static has the `type` entry only. It
/// proves the judged text is unchanged since the pin, not that the text is
/// safe, and it is not collision-resistant against a deliberate edit; a
/// foreign or std type's source and a macro's expansion are not in it. A change shows as `ExceptionDigest` naming the first changed entry;
/// re-judge the static, then pin the new digest.
const EXCEPTIONS: &[(&str, &str, &str, &str)] = &[
    (
        "src/approvals.rs",
        "APPROVAL_BUS",
        "type=54574677 src::approvals::ApprovalEvent=551a13b1",
        "a tokio broadcast Sender: a channel handle, never acquired as a lock",
    ),
    (
        "src/config.rs",
        "DISABLED",
        "type=381fd1dd src::governance::capability::CapabilityConfig=1c73fcb7 src::governance::capability::IssuerConfig=4a856305 src::governance::capability::OpLevel=985b095c",
        "an Arc of CapabilityConfig whose only foreign leaf is an ed25519 VerifyingKey (key bytes)",
    ),
    (
        "src/config/unknown_keys.rs",
        "SCHEMA",
        "type=d42394ee",
        "a schemars RootSchema: plain schema data built once",
    ),
    (
        "src/enterprise_federation_posture/hardened_env_fixture.rs",
        "POSTURE_AUDIT_DIR",
        "type=69062c13",
        "a tempfile TempDir: a path that is removed on drop, no lock",
    ),
    (
        "src/governance/audit.rs",
        "DAEMON_AUDIT_KEY",
        "type=feacdeed",
        "an ed25519 SigningKey: key bytes, no lock",
    ),
    (
        "src/governance/audit.rs",
        "RECORDER_KEY",
        "type=feacdeed",
        "an ed25519 SigningKey: key bytes, no lock",
    ),
    (
        "src/governance/audit.rs",
        "WRITER",
        "type=3e57fb9c src::governance::audit::PendingRow=120d9247 src::governance::audit::WriteOp=3c1463d5",
        "a std mpsc Sender of WriteOp: a channel handle, never acquired as a lock",
    ),
    (
        "src/governance/wire_check.rs",
        "GOVERNANCE_PRE_ACTION",
        "type=71217376 src::governance::agent_action::AgentAction=39cefa84 src::governance::wire_check::WireCheckHook=a65c2e63",
        "a boxed dyn Fn hook installed once by serve; the closures read config, they hold no lock",
    ),
    (
        "src/handlers/federation_signing_check.rs",
        "BUNDLE",
        "type=948eda2d src::federation::identity::trust_bundle::TrustBundle=64fb7356",
        "a TrustBundle whose only foreign leaf is an ed25519 VerifyingKey (key bytes)",
    ),
    (
        "src/identity/session_signer.rs",
        "SESSION_SIGNER",
        "type=ee355834 src::identity::keypair::AgentKeypair=e5642726 src::identity::session_signer::SessionSigner=7c8667f6",
        "an ed25519 SigningKey: key bytes, no lock",
    ),
    (
        "src/identity/test_key_dir.rs",
        "DIRECTORY",
        "type=69062c13",
        "a tempfile TempDir: a path that is removed on drop, no lock",
    ),
    (
        "src/inbox_wake.rs",
        "INBOX_WAKE_BUS",
        "type=deb19289 src::inbox_wake::InboxEvent=109e5130",
        "a tokio broadcast Sender: a channel handle, never acquired as a lock",
    ),
    (
        "src/logging.rs",
        "CENSUS_DUMMY_METADATA_3650",
        "type=4b4bb898",
        "a tracing Metadata: static callsite data",
    ),
    (
        "src/logging.rs",
        "INSTALLED_PIPELINE",
        "type=5ea7aa50 src::config::LogSink=bf13c837 src::logging::DeliveryStats=b3b0a375 src::logging::InstalledPipeline=f096f93a",
        "the log pipeline; its foreign leaf is a tracing_appender ErrorCounter, an atomic count",
    ),
    (
        "src/mcp/mod.rs",
        "POST_SIGNAL_ACK_SINK",
        "type=1c9aa41e",
        "a tokio UnboundedSender of serde_json Value: a channel handle",
    ),
    (
        "src/mcp/shutdown.rs",
        "GATE_STUCK",
        "type=d5eb792a",
        "a ShutdownGate named through `use super::*`: one AtomicU8 state, no lock",
    ),
    (
        "src/mcp/shutdown.rs",
        "GATE_UNDER_TEST",
        "type=d5eb792a",
        "a ShutdownGate named through `use super::*`: one AtomicU8 state, no lock",
    ),
    (
        "src/metrics.rs",
        "HANDLE",
        "type=0b452c42 src::metrics::Metrics=bc17d7d2",
        "the prometheus Metrics handle; its vectors are updated through their own API, never held",
    ),
    (
        "src/storage/escalation_deferral.rs",
        "TXN_FRAMES",
        "type=4af0ce2f src::governance::audit::PendingAuditAnchor=10c2b32e src::governance::audit::PendingWatermark=7061bdc8 src::storage::escalation_deferral::DeferredEscalation=75a03a25 src::storage::escalation_deferral::Frames=a5a77e15 src::storage::escalation_deferral::TxnFrame=13954030",
        "a thread-local RefCell of frames; the foreign leaf is a serde_json Value",
    ),
    (
        "src/storage/escalation_frame_reporting_8184_tests.rs",
        "WRITE_PAUSE",
        "type=dc90c7c0 src::storage::escalation_frame_reporting_8184_tests::WritePause=0a6b82f0",
        "a thread-local pair of std mpsc channel ends: a test pause, not a lock",
    ),
    (
        "src/storage/mod.rs",
        "BPE",
        "type=16315d13",
        "a tiktoken CoreBPE: tokenizer tables built once",
    ),
    (
        "src/storage/mod.rs",
        "GOVERNANCE_PRE_WRITE",
        "type=d6b472da",
        "a boxed dyn Fn hook installed once by serve; the closures read config, they hold no lock",
    ),
    (
        "src/storage/snapshot_file.rs",
        "HOOK",
        "type=71d95840 src::storage::snapshot_file::seam::Hook=8a434667 src::storage::snapshot_file::seam::Point=3f4c9617",
        "a thread-local boxed dyn FnMut test seam, set by one test on its own thread",
    ),
    (
        "src/storage/txn_immediate_5084_tests.rs",
        "HOOK_5084",
        "type=e9493773",
        "a thread-local boxed dyn FnOnce test seam, set by one test on its own thread",
    ),
    (
        "src/subscriptions.rs",
        "DISPATCH_ROOT_CA",
        "type=9f706e3e",
        "a reqwest Certificate: certificate bytes, no lock",
    ),
    (
        "src/subscriptions/webhook_ssrf_8203_tests.rs",
        "DNS_ANSWER",
        "type=d3c053c6 src::subscriptions::webhook_ssrf_8203_tests::DnsAnswer=4a0413d0",
        "a thread-local one-shot DNS answer: a String and an io Result of SocketAddr",
    ),
    (
        "src/test_support.rs",
        "TLS_TEST_PKI",
        "type=486b0f1c src::test_support::TlsTestPki=bf02fb43",
        "the test PKI paths; its foreign leaf is a tempfile TempDir",
    ),
    (
        "tests/agent_projection_txn_9405_9406.rs",
        "RACE",
        "type=188bdf73 tests/agent_projection_txn_9405_9406.rs::Outcome=600430fe tests/agent_projection_txn_9405_9406.rs::Race=490373cf",
        "a thread-local RefCell of Race: std mpsc channel ends and an Outcome",
    ),
    (
        "tests/append_only_spine_flagon_g6.rs",
        "AUDIT_DIR",
        "type=69062c13",
        "a tempfile TempDir: a path that is removed on drop, no lock",
    ),
    (
        "tests/append_only_upsert_supersede_2948.rs",
        "AUDIT_DIR",
        "type=69062c13",
        "a tempfile TempDir: a path that is removed on drop, no lock",
    ),
    (
        "tests/auto_atomise/core.rs",
        "Q",
        "type=6877f3c7 src::background::atomise_worker::AtomiseJob=3c9ace28 src::background::atomise_worker::AtomiseQueue=e38c5ba8",
        "an AtomiseQueue: a std mpsc SyncSender, a channel handle",
    ),
    (
        "tests/common/mod.rs",
        "CLIENT",
        "type=d258f2f9",
        "a reqwest Client: a connection pool handle, never acquired as a lock",
    ),
    (
        "tests/curator_conserves_contradiction_g7.rs",
        "AUDIT_DIR",
        "type=69062c13",
        "a tempfile TempDir: a path that is removed on drop, no lock",
    ),
    (
        "tests/entity_register_owner_8497.rs",
        "TRAIL",
        "type=ce0988eb",
        "a tempfile TempDir: a path that is removed on drop, no lock",
    ),
    (
        "tests/fed_checkpoint_lane_3075_pg.rs",
        "DIR",
        "type=2f6c6e47 src::identity::keypair::AgentKeypair=e5642726",
        "a PathBuf and an AgentKeypair whose foreign leaf is an ed25519 SigningKey",
    ),
    (
        "tests/federation_1936_checkpoint_fed.rs",
        "DIR",
        "type=2f6c6e47 src::identity::keypair::AgentKeypair=e5642726",
        "a PathBuf and an AgentKeypair whose foreign leaf is an ed25519 SigningKey",
    ),
    (
        "tests/federation_checkpoint_ns_scope_2708.rs",
        "DIR",
        "type=2f6c6e47 src::identity::keypair::AgentKeypair=e5642726",
        "a PathBuf and an AgentKeypair whose foreign leaf is an ed25519 SigningKey",
    ),
    (
        "tests/form_1_synthesis.rs",
        "RT",
        "type=74e759ab",
        "a tokio Runtime: a caller cannot acquire it as a lock",
    ),
    (
        "tests/form_1_synthesis_verdict_matrix.rs",
        "RT",
        "type=74e759ab",
        "a tokio Runtime: a caller cannot acquire it as a lock",
    ),
    (
        "tests/issue_2122_synthesis_provenance_enforce.rs",
        "RT",
        "type=74e759ab",
        "a tokio Runtime: a caller cannot acquire it as a lock",
    ),
    (
        "tests/store_legacy_classifier_paths.rs",
        "RT",
        "type=74e759ab",
        "a tokio Runtime: a caller cannot acquire it as a lock",
    ),
    (
        "tests/store_synthesis_error_paths.rs",
        "RT",
        "type=74e759ab",
        "a tokio Runtime: a caller cannot acquire it as a lock",
    ),
];

/// #10276: the identifiers counted per walked file.
const COUNTED_IDENTS: [&str; 1] = ["include"];

/// #10276: `(path, identifier, count, reason)` for each walked file that
/// holds an identifier of [`COUNTED_IDENTS`]; every other file holds none.
const INCLUDE_ROWS: &[(&str, &str, usize, &str)] = &[(
    "src/store/postgres.rs",
    "include",
    1,
    "include! of the walked src/store/postgres_inbox_tests.rs, judged by part 5",
)];

/// The hand-written tables the token census judges against.
struct Tables<'a> {
    statics: &'a str,
    exceptions: &'a [(&'a str, &'a str, &'a str, &'a str)],
    includes: &'a [(&'a str, &'a str, usize, &'a str)],
}

/// The statics table `statics` with no exception and no include row, for
/// synthetic trees.
fn bare(statics: &str) -> Tables<'_> {
    Tables {
        statics,
        exceptions: &[],
        includes: &[],
    }
}

/// The token census of a tree with the live [`EXCEPTIONS`] and
/// [`INCLUDE_ROWS`] and the statics table `table`.
fn token_census(
    files: &[(String, String)],
    table: &str,
) -> (Vec<StaticFinding>, Vec<IncludeFinding>) {
    token_census_with(
        files,
        &Tables {
            statics: table,
            exceptions: EXCEPTIONS,
            includes: INCLUDE_ROWS,
        },
    )
}

/// One lexed file with the maps every part of the token census reads.
struct Lexed<'f> {
    path: &'f str,
    toks: Vec<Tok>,
    close: Vec<Option<usize>>,
    in_macro: Vec<bool>,
    lens: Vec<Option<usize>>,
}

/// #10213 and #10204: the static census against [`STATICS_TABLE`] and the
/// inclusion census, over one lex of every walked file. #10275: the types
/// are resolved across the whole tree before any static is judged.
fn token_census_with(
    files: &[(String, String)],
    tables: &Tables,
) -> (Vec<StaticFinding>, Vec<IncludeFinding>) {
    let (statics, includes, _) = token_census_counted(files, tables);
    (statics, includes)
}

/// #10324: [`token_census_with`], with the number of scope visits that
/// [`TypeGraph::glob_supplies`] made.
fn token_census_counted(
    files: &[(String, String)],
    tables: &Tables,
) -> (Vec<StaticFinding>, Vec<IncludeFinding>, u64) {
    let (rows, bad) = parse_table(tables.statics);
    let mut statics: Vec<StaticFinding> = bad.into_iter().map(StaticFinding::Table).collect();
    let mut includes = Vec::new();
    let mut lexed = Vec::new();
    for (path, text) in files {
        match lex(text) {
            Ok(toks) => {
                let close = brackets(&toks).0;
                let in_macro = macro_bodies(&toks, &close);
                let lens = array_lengths(&toks, &close);
                lexed.push(Lexed {
                    path,
                    toks,
                    close,
                    in_macro,
                    lens,
                });
            }
            Err(error) => statics.push(StaticFinding::Lex {
                file: path.clone(),
                error,
            }),
        }
    }
    let mut graph = TypeGraph::default();
    // #10323: the graph is built over the files sorted by path, so no
    // scope, binding or digest depends on the walk order; the spans keep
    // the walk order of `lexed`.
    let mut order: Vec<usize> = (0..lexed.len()).collect();
    order.sort_by(|&a, &b| lexed[a].path.cmp(lexed[b].path));
    let mut spans: Vec<Vec<(usize, usize)>> = vec![Vec::new(); lexed.len()];
    for i in order {
        let f = &lexed[i];
        spans[i] = graph.file(f.path, &f.toks, &f.close, &f.lens, &f.in_macro);
    }
    graph.link_modules();
    graph.settle_globs();
    let resolved = graph.values();
    // Rows left per file, then per name: a static takes one row.
    let mut left: BTreeMap<&str, BTreeMap<&str, usize>> = BTreeMap::new();
    for r in &rows {
        *left
            .entry(r.path.as_str())
            .or_default()
            .entry(r.name.as_str())
            .or_default() += 1;
    }
    // #10251: the keys with a row whose category is not `lock`.
    let not_lock: BTreeSet<(String, String)> = rows
        .iter()
        .filter(|r| r.category != Category::Lock)
        .map(|r| (r.path.clone(), r.name.clone()))
        .collect();
    // #10295: each row, whether a static took it, and its pinned digest.
    let mut excepted: BTreeMap<(String, String), (bool, &str)> = BTreeMap::new();
    for &(file, name, digest, reason) in tables.exceptions {
        let key = (file.to_string(), name.to_string());
        if excepted.insert(key, (false, digest)).is_some() {
            statics.push(StaticFinding::ExceptionDuplicate {
                file: file.to_string(),
                name: name.to_string(),
            });
        }
        if visible(reason) < MIN_REASON_CHARS {
            statics.push(StaticFinding::ExceptionReasonless {
                file: file.to_string(),
                name: name.to_string(),
            });
        }
    }
    let walked: BTreeSet<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    let mut mods = [0usize; 2];
    let none = BTreeSet::new();
    for (f, sp) in lexed.iter().zip(&spans) {
        let path = f.path;
        let (named, macros) = statics_of(&f.toks, &f.close, &f.in_macro);
        for StaticItem {
            name,
            line,
            ty,
            in_macro,
        } in named
        {
            let key = (path.to_string(), name.clone());
            let scope = scope_at(sp, ty.0);
            let mut atoms = Vec::new();
            if !in_macro {
                type_atoms(&f.toks, &f.close, &f.lens, ty, &none, &mut atoms);
            }
            // #10295: taking a row checks its pin against the live digest; a
            // macro-body static's digest is its own written type only.
            // `None` when no row names the static, else the digest finding.
            let take = |excepted: &mut BTreeMap<(String, String), (bool, &str)>| {
                let (used, pinned) = excepted.get_mut(&key)?;
                *used = true;
                let own = token_hash(&f.toks, ty);
                let live = if in_macro {
                    format!("{OWN_TYPE_KEY}={}", hex8(own))
                } else {
                    resolved.digest(scope, &atoms, own)
                };
                Some(digest_finding(path, &name, pinned, &live))
            };
            if in_macro {
                // #10285: never a row; judged only by hand.
                match take(&mut excepted) {
                    Some(stale) => statics.extend(stale),
                    None => statics.push(StaticFinding::MacroBodyStatic {
                        file: path.to_string(),
                        name,
                        line,
                    }),
                }
                continue;
            }
            match resolved.of(scope, &atoms) {
                // #10251: a lock static's rows must all say `lock`.
                Res::Lock if not_lock.contains(&key) => {
                    statics.push(StaticFinding::LockNotLabelled {
                        file: path.to_string(),
                        name: name.clone(),
                        line,
                    });
                }
                // #10275, #10283: a static not proven lock-free.
                Res::Unres(why) if not_lock.contains(&key) => match take(&mut excepted) {
                    Some(stale) => statics.extend(stale),
                    None => statics.push(StaticFinding::Unresolvable {
                        file: path.to_string(),
                        name: name.clone(),
                        line,
                        why,
                    }),
                },
                _ => {}
            }
            match left.get_mut(path).and_then(|m| m.get_mut(name.as_str())) {
                Some(n) if *n > 0 => *n -= 1,
                _ => statics.push(StaticFinding::Unlisted {
                    file: path.to_string(),
                    name,
                    line,
                }),
            }
        }
        for line in macros {
            statics.push(StaticFinding::MacroStatic {
                file: path.to_string(),
                line,
            });
        }
        inclusions_of(
            path,
            &f.toks,
            &walked,
            &graph.include_aliases,
            &mut mods,
            &mut includes,
        );
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
    for ((file, name), (used, _)) in excepted {
        if !used {
            statics.push(StaticFinding::ExceptionStale { file, name });
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
    includes.extend(include_counts(&lexed, tables.includes));
    (statics, includes, graph.glob_visits.get())
}

/// #10276: every identifier token of [`COUNTED_IDENTS`] (a raw `r#` form
/// lexes to the same token), counted per lexed file and held against the
/// hand-written rows. A file with no row must hold none.
fn include_counts(lexed: &[Lexed], table: &[(&str, &str, usize, &str)]) -> Vec<IncludeFinding> {
    let mut out = Vec::new();
    let mut rowed: BTreeMap<(&str, &str), (usize, bool)> = BTreeMap::new();
    for &(file, ident, count, reason) in table {
        let finding =
            |f: fn(String, String) -> IncludeFinding| f(file.to_string(), ident.to_string());
        if rowed.insert((file, ident), (count, false)).is_some() {
            out.push(finding(|file, ident| IncludeFinding::IncludeRowDuplicate {
                file,
                ident,
            }));
        }
        if count == 0 || visible(reason) < MIN_REASON_CHARS || !COUNTED_IDENTS.contains(&ident) {
            out.push(finding(|file, ident| IncludeFinding::IncludeRowBad {
                file,
                ident,
            }));
        }
    }
    for f in lexed {
        for ident in COUNTED_IDENTS {
            let found = f
                .toks
                .iter()
                .filter(|k| k.kind == TokKind::Ident && k.text == ident)
                .count();
            let row = rowed.get_mut(&(f.path, ident));
            let want = row.map_or(0, |(n, seen)| {
                *seen = true;
                *n
            });
            if found != want {
                out.push(IncludeFinding::IncludeCount {
                    file: f.path.to_string(),
                    ident: ident.to_string(),
                    rowed: want,
                    found,
                });
            }
        }
    }
    for ((file, ident), (_, seen)) in rowed {
        if !seen {
            out.push(IncludeFinding::IncludeRowStale {
                file: file.to_string(),
                ident: ident.to_string(),
            });
        }
    }
    out
}

/// One finding of [`census_all`], tagged by the part that found it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Finding {
    Line(Violation),
    Item(ItemFinding),
    Use(UseFinding),
    Static(StaticFinding),
    Include(IncludeFinding),
    Cargo(CargoFinding),
}

/// The name `[lib]` must compile this crate under.
const CRATE_NAME: &str = "ai_memory";

/// #10277: a finding of the build-target census of `Cargo.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CargoFinding {
    /// The manifest cannot be read.
    Unreadable(String),
    /// The manifest is not TOML.
    Unparseable(String),
    /// A key the census reads holds a value of a type Cargo does not take there.
    BadType { key: String },
    /// A target source that does not end in `.rs` (exact case).
    NotRs {
        kind: &'static str,
        name: String,
        path: String,
    },
    /// A target source the walk did not read.
    Unwalked {
        kind: &'static str,
        name: String,
        path: String,
    },
    /// A `[workspace]` table: members are not modelled.
    Workspace,
    /// A `path =` dependency directory that holds no walked file.
    DependencyPathUnwalked { key: String, path: String },
    /// `[lib] name` is not [`CRATE_NAME`].
    LibName { found: String },
}

impl std::fmt::Display for CargoFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(e) => write!(f, "Cargo.toml cannot be read: {e}"),
            Self::Unparseable(e) => write!(f, "Cargo.toml does not parse: {e}"),
            Self::BadType { key } => {
                write!(f, "Cargo.toml `{key}` is not of the type Cargo reads there")
            }
            Self::NotRs { kind, name, path } => write!(
                f,
                "Cargo.toml {kind} target `{name}` names `{path}`, which does not end in `.rs` (exact case), so the census never reads it"
            ),
            Self::Unwalked { kind, name, path } => write!(
                f,
                "Cargo.toml {kind} target `{name}` names `{path}`, which the census did not read"
            ),
            Self::Workspace => write!(
                f,
                "Cargo.toml has a [workspace] table, whose members the census does not model"
            ),
            Self::DependencyPathUnwalked { key, path } => write!(
                f,
                "Cargo.toml `{key}` names the directory `{path}`, which holds no file the census read"
            ),
            Self::LibName { found } => {
                write!(f, "Cargo.toml [lib] name is `{found}`, not `{CRATE_NAME}`")
            }
        }
    }
}

/// #10277: the build-target kinds of a manifest, as `(array key, the
/// word in a finding, the directory of its default sources)`.
const TARGET_KINDS: [(&str, &str, &str); 4] = [
    ("bin", "bin", "src/bin"),
    ("test", "test", "tests"),
    ("bench", "bench", "benches"),
    ("example", "example", "examples"),
];

/// The dependency tables whose `path =` entries Cargo compiles.
const DEPENDENCY_TABLES: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

/// #10277: one target source against the walked set.
fn target_source(
    kind: &'static str,
    name: &str,
    path: &str,
    walked: &BTreeSet<&str>,
) -> Option<CargoFinding> {
    let rel = path.strip_prefix("./").unwrap_or(path);
    if Path::new(rel).extension().is_none_or(|e| e != "rs") {
        return Some(CargoFinding::NotRs {
            kind,
            name: name.to_string(),
            path: path.to_string(),
        });
    }
    (!walked.contains(rel)).then(|| CargoFinding::Unwalked {
        kind,
        name: name.to_string(),
        path: path.to_string(),
    })
}

/// The string at `key` of `table`: `Ok(None)` when absent, a finding when
/// it is there but not a string.
fn string_key<'t>(
    table: &'t toml::Table,
    key: &str,
    full: &str,
) -> Result<Option<&'t str>, CargoFinding> {
    match table.get(key) {
        None => Ok(None),
        Some(toml::Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(CargoFinding::BadType {
            key: full.to_string(),
        }),
    }
}

/// The table at `key` of `doc`: `None` when absent, and a finding when it
/// is there but not a table (#10277: never read as an empty table).
fn table_key<'t>(
    doc: &'t toml::Table,
    key: &str,
    out: &mut Vec<CargoFinding>,
) -> Option<&'t toml::Table> {
    if let toml::Value::Table(t) = doc.get(key)? {
        Some(t)
    } else {
        out.push(CargoFinding::BadType {
            key: key.to_string(),
        });
        None
    }
}

/// #10277: every `path =` entry of one dependency table.
fn dependency_paths(
    deps: &toml::Value,
    prefix: &str,
    walked: &BTreeSet<&str>,
    out: &mut Vec<CargoFinding>,
) {
    let Some(deps) = deps.as_table() else {
        out.push(CargoFinding::BadType {
            key: prefix.to_string(),
        });
        return;
    };
    for (dep, spec) in deps {
        let Some(spec) = spec.as_table() else {
            continue;
        };
        let key = format!("{prefix}.{dep}.path");
        match string_key(spec, "path", &key) {
            Ok(Some(dir)) => {
                let dir = dir.strip_prefix("./").unwrap_or(dir).trim_end_matches('/');
                // `.` is this package itself: its root is walked when any
                // file of it is.
                let under = if dir.is_empty() || dir == "." {
                    String::new()
                } else {
                    format!("{dir}/")
                };
                if !walked.iter().any(|w| w.starts_with(&under)) {
                    out.push(CargoFinding::DependencyPathUnwalked {
                        key,
                        path: dir.to_string(),
                    });
                }
            }
            Ok(None) => {}
            Err(f) => out.push(f),
        }
    }
}

/// #10277: the build targets of a manifest against the walked set: the
/// library, every `[[bin]]`, `[[test]]`, `[[bench]]` and `[[example]]`
/// (its `path`, or else Cargo's default places for its name), the build
/// script and every `path =` entry (dependencies, `[target.*]`, `[patch.*]`
/// and `[replace]`). A key the census reads that holds a value of another
/// type is a finding, never skipped. The auto-discovered directories are
/// walked whole (see `auto_target_dirs_are_walked_10277`).
fn cargo_census(manifest: Result<String, String>, walked: &BTreeSet<&str>) -> Vec<CargoFinding> {
    let text = match manifest {
        Ok(t) => t,
        Err(e) => return vec![CargoFinding::Unreadable(e)],
    };
    let doc = match text.parse::<toml::Table>() {
        Ok(d) => d,
        Err(e) => return vec![CargoFinding::Unparseable(e.message().to_string())],
    };
    let mut out = Vec::new();
    if doc.contains_key("workspace") {
        out.push(CargoFinding::Workspace);
    }
    let empty = toml::Table::new();
    let lib = table_key(&doc, "lib", &mut out).unwrap_or(&empty);
    match string_key(lib, "name", "lib.name") {
        Ok(Some(n)) if n != CRATE_NAME => out.push(CargoFinding::LibName {
            found: n.to_string(),
        }),
        Ok(_) => {}
        Err(f) => out.push(f),
    }
    match string_key(lib, "path", "lib.path") {
        Ok(p) => out.extend(target_source(
            "lib",
            CRATE_NAME,
            p.unwrap_or("src/lib.rs"),
            walked,
        )),
        Err(f) => out.push(f),
    }
    for (key, kind, dir) in TARGET_KINDS {
        let Some(list) = doc.get(key) else {
            continue;
        };
        let Some(list) = list.as_array() else {
            out.push(CargoFinding::BadType {
                key: key.to_string(),
            });
            continue;
        };
        for (i, entry) in list.iter().enumerate() {
            let Some(entry) = entry.as_table() else {
                out.push(CargoFinding::BadType {
                    key: format!("{key}[{i}]"),
                });
                continue;
            };
            let name = match string_key(entry, "name", &format!("{key}[{i}].name")) {
                Ok(n) => n.unwrap_or_default(),
                Err(f) => {
                    out.push(f);
                    continue;
                }
            };
            match string_key(entry, "path", &format!("{key}[{i}].path")) {
                Ok(Some(p)) => out.extend(target_source(kind, name, p, walked)),
                Ok(None) => {
                    let flat = format!("{dir}/{name}.rs");
                    let nested = format!("{dir}/{name}/main.rs");
                    let main = (kind == "bin").then_some("src/main.rs");
                    let found = [Some(flat.as_str()), Some(nested.as_str()), main]
                        .into_iter()
                        .flatten()
                        .any(|c| walked.contains(c));
                    if !found {
                        out.push(CargoFinding::Unwalked {
                            kind,
                            name: name.to_string(),
                            path: flat,
                        });
                    }
                }
                Err(f) => out.push(f),
            }
        }
    }
    let package = table_key(&doc, "package", &mut out).unwrap_or(&empty);
    match package.get("build") {
        None | Some(toml::Value::Boolean(false)) => {}
        Some(toml::Value::Boolean(true)) => {
            out.extend(target_source("build", "build", "build.rs", walked));
        }
        Some(toml::Value::String(p)) => out.extend(target_source("build", "build", p, walked)),
        Some(toml::Value::Array(a)) => {
            for (i, p) in a.iter().enumerate() {
                match p.as_str() {
                    Some(p) => out.extend(target_source("build", "build", p, walked)),
                    None => out.push(CargoFinding::BadType {
                        key: format!("package.build[{i}]"),
                    }),
                }
            }
        }
        Some(_) => out.push(CargoFinding::BadType {
            key: "package.build".to_string(),
        }),
    }
    for t in DEPENDENCY_TABLES {
        if let Some(d) = doc.get(t) {
            dependency_paths(d, t, walked, &mut out);
        }
    }
    // `[replace]` entries take `path =` as a dependency does.
    if let Some(d) = doc.get("replace") {
        dependency_paths(d, "replace", walked, &mut out);
    }
    if let Some(targets) = table_key(&doc, "target", &mut out) {
        for (cfg, body) in targets {
            let Some(body) = body.as_table() else {
                out.push(CargoFinding::BadType {
                    key: format!("target.{cfg}"),
                });
                continue;
            };
            for t in DEPENDENCY_TABLES {
                if let Some(d) = body.get(t) {
                    dependency_paths(d, &format!("target.{cfg}.{t}"), walked, &mut out);
                }
            }
        }
    }
    if let Some(patches) = table_key(&doc, "patch", &mut out) {
        for (source, body) in patches {
            dependency_paths(body, &format!("patch.{source}"), walked, &mut out);
        }
    }
    out
}

/// The live manifest text, or why it cannot be read.
fn live_manifest() -> Result<String, String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    fs::read_to_string(&path).map_err(|e| e.kind().to_string())
}

/// All six parts of the census over the whole tree.
fn census_all(files: &[(String, String)]) -> Vec<Finding> {
    let (statics, includes) = token_census(files, STATICS_TABLE);
    let walked: BTreeSet<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    let cargo = cargo_census(live_manifest(), &walked);
    census(files)
        .into_iter()
        .map(Finding::Line)
        .chain(item_census(files).into_iter().map(Finding::Item))
        .chain(use_census(files).into_iter().map(Finding::Use))
        .chain(statics.into_iter().map(Finding::Static))
        .chain(includes.into_iter().map(Finding::Include))
        .chain(cargo.into_iter().map(Finding::Cargo))
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
        vec![Finding::Static(StaticFinding::MacroBodyStatic {
            file: SUPPORT.into(),
            name: "$n".into(),
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

/// #10276: the [`COUNTED_IDENTS`] finding of one `include` token added to
/// [`SUPPORT`], which has no row.
fn support_include_count(found: usize) -> Finding {
    Finding::Include(IncludeFinding::IncludeCount {
        file: SUPPORT.into(),
        ident: "include".into(),
        rowed: 0,
        found,
    })
}

#[test]
fn mutant_guard_file_include_is_red_10204() {
    let (got, f) = run(&M_INCLUDE);
    assert_eq!(
        got,
        vec![
            include_hit(f[0], "store_url/env_guard.rs"),
            support_include_count(1)
        ],
        "{}",
        M_INCLUDE.id
    );
}

#[test]
fn mutant_guard_file_include_concat_env_is_red_10204() {
    let (got, f) = run(&M_INCLUDE_CONCAT);
    assert_eq!(
        got,
        vec![
            include_hit(f[0], "/src/store_url/env_guard.rs"),
            support_include_count(1)
        ],
        "{}",
        M_INCLUDE_CONCAT.id
    );
}

#[test]
fn mutant_guard_file_include_split_concat_is_red_10204() {
    let (got, f) = run(&M_INCLUDE_SPLIT);
    assert_eq!(
        got,
        vec![
            include_hit(f[0], "store_url/env_guard.rs"),
            support_include_count(1)
        ],
        "{}",
        M_INCLUDE_SPLIT.id
    );
}

#[test]
fn mutant_include_not_literal_is_red_10204() {
    let (got, f) = run(&M_INCLUDE_NOT_LITERAL);
    assert_eq!(
        got,
        vec![
            Finding::Include(IncludeFinding::IncludeNotLiteral {
                file: SUPPORT.into(),
                line: f[0],
            }),
            support_include_count(1)
        ],
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
    let ghost =
        format!("{STATICS_TABLE}src/test_support.rs\tGHOST\tatomic: no such static anywhere\n");
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
    let (statics, _) = token_census_with(&[], &bare("src/a.rs\tA\tshort\n"));
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
/// is or holds a lock of [`LOCK_TYPES`] (std, tokio or `parking_lot`, a
/// tokio `OnceCell` included), directly or through a type of the tree).
/// A row relabelled away from `lock`, or a lock row added, is red.
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
    ("src/mcp/mod.rs", "MCP_EMBED_SKIP_AMORT"),
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
    ("src/subscriptions.rs", "DISPATCH_IDLE"),
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
    ("tests/auto_atomise/core.rs", "A"),
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
    ("tests/containment_relational_3946.rs", "WARMED"),
    (
        "tests/contaminated_stamp_f1_fixes_pg_item3_3266.rs",
        "WARMED",
    ),
    ("tests/contaminated_stamp_pg_item3_3266.rs", "WARMED"),
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
    ("tests/swarm_rewind_pg_item3_3266.rs", "WARMED"),
    ("tests/swarm_rewind_route_item3_3266.rs", "WARMED"),
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
        let mut want = Vec::new();
        if *id == "generic-assoc-binding" {
            // #10283: `Box<dyn Iterator<Item = u8>>` is a trait object, not
            // proven lock-free, so a `once` row is `Unresolvable`; the `=`
            // of the binding does not end the type of the next static early.
            table.push_str(SUPPORT);
            table.push_str("\tFORM_L\tonce: a value computed once, no lock\n");
            want.push(StaticFinding::Unresolvable {
                file: SUPPORT.into(),
                name: "FORM_L".into(),
                line: first,
                why: Why::TraitObject,
            });
        }
        want.push(StaticFinding::LockNotLabelled {
            file: SUPPORT.into(),
            name: name.into(),
            line: first + at,
        });
        let (statics, includes) = token_census(&files, &table);
        assert_eq!(statics, want, "{id}");
        assert_eq!(includes, Vec::<IncludeFinding>::new(), "{id}");
    }
    // The same statics labelled `lock` are clean.
    for (id, tail, _) in forms {
        let (files, _) = tree_appended(SUPPORT, tail);
        let mut table = format!("{STATICS_TABLE}{SUPPORT}\tFORM_L\tlock: a lock of the form\n");
        if *id == "generic-assoc-binding" {
            table.push_str(SUPPORT);
            table.push_str("\tFORM_M\tlock: a lock of the form\n");
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
    // #10281: the exact finding, its line read by hand from
    // src/approvals.rs (one static of that name, one row).
    assert_eq!(
        (key_path, key_name),
        ("src/approvals.rs", "EXECUTION_EXEMPTIONS")
    );
    let (statics, _) = token_census(&tree(), &table);
    assert_eq!(
        statics,
        vec![StaticFinding::LockNotLabelled {
            file: "src/approvals.rs".into(),
            name: "EXECUTION_EXEMPTIONS".into(),
            line: 1131,
        }]
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
        inclusions_of(
            "src/x.rs",
            &toks,
            &BTreeSet::new(),
            &BTreeMap::new(),
            &mut mods,
            &mut got,
        );
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
    inclusions_of(
        "src/x.rs",
        &toks,
        &BTreeSet::new(),
        &BTreeMap::new(),
        &mut [0; 2],
        &mut got,
    );
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
        let mut want = vec![inc(first + at, *kind, value)];
        if id.starts_with("include-") {
            // #10276: the added `include` token is also off its row.
            want.push(support_include_count(1));
        }
        assert_eq!(got, want, "{id}");
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
        // #10276: a clean `include!` is still one more `include` token than
        // the file's row allows; `include_str!` and `include_bytes!` are not
        // counted.
        let want = if matches!(*id, "include-sibling" | "include-manifest") {
            vec![support_include_count(1)]
        } else {
            Vec::new()
        };
        assert_eq!(got, want, "{id}");
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
        vec![
            Finding::Include(IncludeFinding::IncludeNotLiteral {
                file: SUPPORT.into(),
                line: first,
            }),
            support_include_count(1)
        ]
    );
}

/// The two [`GUARDED_MODS`] findings of a synthetic tree with no
/// store-url module.
fn no_store_url() -> Vec<IncludeFinding> {
    vec![
        IncludeFinding::ModCount {
            file: "src/store_url.rs",
            name: "env_guard",
            found: 0,
        },
        IncludeFinding::ModCount {
            file: "src/lib.rs",
            name: "store_url",
            found: 0,
        },
    ]
}

/// The `once` row every form static of the tables below carries.
const FORM_ROW: &str = "\tFORM\tonce: a value computed once, no lock\n";

/// A reason long enough for an exception or an include row.
const FORM_WHY: &str = "judged by hand for the form table";

/// #10295: the pinned digest of `static FORM: Unknown = X;` in `src/b.rs`.
const D_UNRES: &str = "type=57dcbc6c";

/// #10295: the pinned digest of the macro-body `INNER` static's type.
const D_INNER: &str = "type=4fd0bfc1";

/// What the deny-by-default census must decide for one form.
#[derive(Debug)]
enum Want {
    /// The type holds a lock: a `once` row is `LockNotLabelled`.
    Lock,
    /// The type is proven lock-free: no finding.
    Clean,
    /// The type is not proven: a `once` row is `Unresolvable` for this reason.
    Unres(Why),
}

/// The types `src/a.rs` defines for the forms that name a type in another
/// file of the library (#10275).
const FORM_DEFS: &str = "pub struct Gate {\n    m: std::sync::Mutex<u8>,\n}\n\
pub type One = Two;\npub type Two = std::sync::RwLock<u8>;\npub struct S;\n\
pub trait Tr {\n    type Out;\n}\npub type Erased = Box<dyn Fn() + Sync>;\n\
pub struct Plain {\n    v: u8,\n}\n";

/// An exception row as the tests write it: `(file, name, digest, reason)`.
type ExceptionRow<'a> = (&'a str, &'a str, &'a str, &'a str);

/// One exception case: `(id, text, exceptions, findings written by hand)`.
type ExceptionCase<'a> = (&'a str, &'a str, Vec<ExceptionRow<'a>>, Vec<StaticFinding>);

/// One macro-body case: `(id, text, table, exceptions, findings)`.
type MacroBodyCase<'a> = (
    &'a str,
    &'a str,
    &'a str,
    Vec<ExceptionRow<'a>>,
    Vec<StaticFinding>,
);

/// One include-row case: `(id, rows (file, ident, count, reason), findings)`.
type IncludeRowCase<'a> = (
    &'a str,
    Vec<(&'a str, &'a str, usize, &'a str)>,
    Vec<IncludeFinding>,
);

/// One form: `(id, file, text, the decision written by hand)`.
type Form = (&'static str, &'static str, &'static str, Want);

/// #10275, #10278, #10279, #10283: every type form, with its decision
/// written by hand. Reviewer forms, then invented ones.
fn type_forms() -> Vec<Form> {
    let b = "src/b.rs";
    let foreign = |root: &str, name: &str| {
        Want::Unres(Why::Foreign {
            root: root.into(),
            name: name.into(),
        })
    };
    let mut forms = vec![
        // #10275: types defined in another file of the library.
        // #10293: a bare name another file defines is not in this
        // file's scope.
        (
            "cross-file-bare",
            b,
            "static FORM: Gate = X;\n",
            Want::Unres(Why::NoDef("Gate".into())),
        ),
        (
            "cross-file-path",
            b,
            "static FORM: crate::a::Gate = X;\n",
            Want::Lock,
        ),
        (
            "cross-file-use-rename",
            b,
            "use crate::a::Gate as Door;\nstatic FORM: Door = X;\n",
            Want::Lock,
        ),
        (
            "cross-file-alias-chain",
            b,
            "static FORM: crate::a::One = X;\n",
            Want::Lock,
        ),
        (
            "cross-file-clean",
            b,
            "static FORM: crate::a::Plain = X;\n",
            Want::Clean,
        ),
        (
            "tests-crate-path",
            "tests/x.rs",
            "static FORM: ai_memory::a::Gate = X;\n",
            Want::Lock,
        ),
        (
            "tests-own-scope",
            "tests/x.rs",
            "struct Gate {\n    v: u8,\n}\nstatic FORM: Gate = X;\n",
            Want::Clean,
        ),
        (
            "import-overrides-scope",
            b,
            "use other::Thing as Gate;\nstatic FORM: Gate = X;\n",
            foreign("other", "Thing"),
        ),
        // #10283: type-erased, opaque, macro and boxed forms.
        (
            "dyn-boxed",
            b,
            "static FORM: Box<dyn std::any::Any + Sync> = X;\n",
            Want::Unres(Why::TraitObject),
        ),
        (
            "dyn-lazy-boxed",
            b,
            "static FORM: std::sync::LazyLock<Box<dyn Send + Sync>> = X;\n",
            Want::Unres(Why::TraitObject),
        ),
        (
            "dyn-cross-file-alias",
            b,
            "static FORM: crate::a::Erased = X;\n",
            Want::Unres(Why::TraitObject),
        ),
        (
            "impl-alias",
            b,
            "type Hidden = impl Sized;\nstatic FORM: Hidden = X;\n",
            Want::Unres(Why::OpaqueType),
        ),
        (
            "impl-arg",
            b,
            "static FORM: Box<impl Sized> = X;\n",
            Want::Unres(Why::OpaqueType),
        ),
        (
            "macro-type",
            b,
            "static FORM: my_type!() = X;\n",
            Want::Unres(Why::MacroType("my_type".into())),
        ),
        (
            "raw-pointer",
            b,
            "struct SendPtr(*const u8);\nstatic FORM: SendPtr = X;\n",
            Want::Unres(Why::RawPointer),
        ),
        (
            "projection",
            b,
            "static FORM: <crate::a::S as crate::a::Tr>::Out = X;\n",
            Want::Unres(Why::Projection),
        ),
        (
            "atomic-ptr",
            b,
            "static FORM: std::sync::atomic::AtomicPtr<u8> = X;\n",
            Want::Unres(Why::StdNotProven("AtomicPtr".into())),
        ),
        (
            "unsafe-cell",
            b,
            "static FORM: std::cell::UnsafeCell<u8> = X;\n",
            Want::Unres(Why::StdNotProven("UnsafeCell".into())),
        ),
        (
            "mpsc-sender",
            b,
            "static FORM: std::sync::mpsc::Sender<u8> = X;\n",
            Want::Unres(Why::StdNotProven("Sender".into())),
        ),
        (
            "foreign-path",
            b,
            "static FORM: other_crate::Mutexy = X;\n",
            foreign("other_crate", "Mutexy"),
        ),
        (
            "foreign-import",
            b,
            "use dashmap::DashMap;\nstatic FORM: DashMap<u8, u8> = X;\n",
            foreign("dashmap", "DashMap"),
        ),
        (
            "no-def",
            b,
            "static FORM: Unknown = X;\n",
            Want::Unres(Why::NoDef("Unknown".into())),
        ),
        (
            "alias-no-value",
            b,
            "type Nv;\nstatic FORM: Nv = X;\n",
            Want::Unres(Why::NoValue("Nv".into())),
        ),
    ];
    forms.extend(type_forms_rest());
    forms
}

/// The rest of [`type_forms`]: alias cycles, recursive types and the forms
/// that are proven clean or read through another crate.
fn type_forms_rest() -> Vec<Form> {
    let b = "src/b.rs";
    vec![
        // #10284: a cycle is unresolvable, never clean.
        (
            "alias-cycle",
            b,
            "type C0 = C1;\ntype C1 = C0;\nstatic FORM: C0 = X;\n",
            Want::Unres(Why::Cycle("C0".into())),
        ),
        (
            "adt-recursive-clean",
            b,
            "struct List {\n    next: Option<Box<List>>,\n    v: u8,\n}\nstatic FORM: List = X;\n",
            Want::Clean,
        ),
        (
            "adt-recursive-lock",
            b,
            "struct Node {\n    next: Option<Box<Node>>,\n    m: std::sync::Mutex<u8>,\n}\nstatic FORM: Node = X;\n",
            Want::Lock,
        ),
        // #10278: a lock in a generic default.
        (
            "generic-default",
            b,
            "struct Holder<T = std::sync::Mutex<u8>>(T);\nstatic FORM: Holder = X;\n",
            Want::Lock,
        ),
        (
            "generic-alias",
            b,
            "type L<T> = std::sync::Mutex<T>;\nstatic FORM: L<u8> = X;\n",
            Want::Lock,
        ),
        (
            "generic-arg",
            b,
            "struct Wrap<T>(T);\nstatic FORM: Wrap<std::sync::Mutex<u8>> = X;\n",
            Want::Lock,
        ),
        // #10279: fair and raw locks.
        (
            "parking-lot-fair",
            b,
            "static FORM: parking_lot::FairMutex<u8> = X;\n",
            Want::Lock,
        ),
        (
            "lock-api-raw",
            b,
            "static FORM: lock_api::Mutex<parking_lot::RawMutex, u8> = X;\n",
            Want::Lock,
        ),
        (
            "parking-lot-raw-rwlock",
            b,
            "static FORM: parking_lot::RawRwLock = X;\n",
            Want::Lock,
        ),
        (
            "parking-lot-raw-fair",
            b,
            "static FORM: parking_lot::RawFairMutex = X;\n",
            Want::Lock,
        ),
        ("spin", b, "static FORM: spin::Mutex<u8> = X;\n", Want::Lock),
        // Invented forms.
        (
            "bare-notify-init",
            b,
            "static FORM: tokio::sync::Notify = tokio::sync::Notify::const_new();\n",
            Want::Lock,
        ),
        (
            "imported-notify",
            b,
            "use tokio::sync::Notify;\nstatic FORM: Notify = Notify::const_new();\n",
            Want::Lock,
        ),
        (
            "use-std-rename",
            b,
            "use std::sync::Barrier as B;\nstatic FORM: B = X;\n",
            Want::Lock,
        ),
        (
            "enum-struct-variant",
            b,
            "enum E {\n    V { m: std::sync::Mutex<u8> },\n}\nstatic FORM: E = X;\n",
            Want::Lock,
        ),
        (
            "union",
            b,
            "union U {\n    m: std::mem::ManuallyDrop<std::sync::Mutex<u8>>,\n}\nstatic FORM: U = X;\n",
            Want::Lock,
        ),
        (
            "array",
            b,
            "static FORM: [std::sync::Mutex<u8>; 4] = X;\n",
            Want::Lock,
        ),
        (
            "tuple",
            b,
            "static FORM: (u8, std::sync::Condvar) = X;\n",
            Want::Lock,
        ),
        (
            "static-ref",
            b,
            "static FORM: &'static std::sync::Mutex<u8> = X;\n",
            Want::Lock,
        ),
        (
            "absolute-path",
            b,
            "static FORM: ::std::sync::Mutex<u8> = X;\n",
            Want::Lock,
        ),
        (
            "nested-generic",
            b,
            "static FORM: std::sync::Arc<Vec<Option<std::sync::Mutex<u8>>>> = X;\n",
            Want::Lock,
        ),
        (
            "inline-mod",
            b,
            "mod inner {\n    pub type T = std::sync::Mutex<u8>;\n}\nstatic FORM: inner::T = X;\n",
            Want::Lock,
        ),
        (
            "self-path",
            b,
            "type T2 = std::sync::Mutex<u8>;\nstatic FORM: self::T2 = X;\n",
            Want::Lock,
        ),
        (
            "once-lock-of-tokio-mutex",
            b,
            "static FORM: std::sync::OnceLock<tokio::sync::Mutex<u8>> = X;\n",
            Want::Lock,
        ),
        (
            "fn-pointer",
            b,
            "static FORM: fn(std::sync::Mutex<u8>) -> u8 = X;\n",
            Want::Clean,
        ),
        (
            "once-lock-of-string",
            b,
            "static FORM: std::sync::OnceLock<String> = X;\n",
            Want::Clean,
        ),
        (
            "core-atomic",
            b,
            "static FORM: core::sync::atomic::AtomicBool = X;\n",
            Want::Clean,
        ),
        // #10293: a file reads only the names its own scope binds; a bare
        // name another crate defines is not one of them.
        (
            "other-crate-bare-lock",
            "tests/b.rs",
            "static FORM: Gate = X;\n",
            Want::Unres(Why::NoDef("Gate".into())),
        ),
        (
            "other-crate-bare-clean",
            "tests/b.rs",
            "static FORM: Plain = X;\n",
            Want::Unres(Why::NoDef("Plain".into())),
        ),
    ]
}

/// #10275, #10278, #10279, #10283: deny by default. A static whose type is
/// not proven lock-free is `Unresolvable` with its reason, a lock is never
/// accepted under a `once` row, and only a proven type is clean. Every form
/// that misses is listed, so one red run shows them all.
#[test]
fn type_forms_are_judged_deny_by_default_10283() {
    let mut miss = Vec::new();
    for (id, file, text, want) in type_forms() {
        let line = text
            .lines()
            .position(|l| l.contains("static FORM"))
            .expect("form static")
            + 1;
        let files = vec![
            ("src/a.rs".to_string(), FORM_DEFS.to_string()),
            (file.to_string(), text.to_string()),
        ];
        let table = format!("{file}{FORM_ROW}");
        let (statics, includes) = token_census_with(&files, &bare(&table));
        let expect = match want {
            Want::Lock => vec![StaticFinding::LockNotLabelled {
                file: file.into(),
                name: "FORM".into(),
                line,
            }],
            Want::Clean => vec![],
            Want::Unres(why) => vec![StaticFinding::Unresolvable {
                file: file.into(),
                name: "FORM".into(),
                line,
                why,
            }],
        };
        if statics != expect || includes != no_store_url() {
            miss.push(format!(
                "{id}: got {statics:?} {includes:?}, want {expect:?}"
            ));
        }
    }
    assert_eq!(miss, Vec::<String>::new());
}

/// #10275: an exception is taken only by the static it names that is not
/// proven; a stale, duplicate or reasonless exception is red, and a lock is
/// never excepted.
#[test]
fn exceptions_are_judged_exactly_10275() {
    const UNRES: &str = "static FORM: Unknown = X;\n";
    const LOCK: &str = "static FORM: std::sync::Mutex<u8> = X;\n";
    const CLEAN: &str = "static FORM: u8 = 0;\n";
    let b = "src/b.rs";
    let named = |f: fn(String, String) -> StaticFinding, file: &str, name: &str| {
        f(file.into(), name.into())
    };
    let stale = |file: String, name: String| StaticFinding::ExceptionStale { file, name };
    let dup = |file: String, name: String| StaticFinding::ExceptionDuplicate { file, name };
    let reasonless = |file: String, name: String| StaticFinding::ExceptionReasonless { file, name };
    let unres = StaticFinding::Unresolvable {
        file: b.into(),
        name: "FORM".into(),
        line: 1,
        why: Why::NoDef("Unknown".into()),
    };
    let rows: Vec<ExceptionCase<'_>> = vec![
        ("taken", UNRES, vec![(b, "FORM", D_UNRES, FORM_WHY)], vec![]),
        ("absent", UNRES, vec![], vec![unres.clone()]),
        (
            "other-file",
            UNRES,
            vec![("src/c.rs", "FORM", D_UNRES, FORM_WHY)],
            vec![unres.clone(), named(stale, "src/c.rs", "FORM")],
        ),
        (
            "other-name",
            CLEAN,
            vec![(b, "OTHER", D_UNRES, FORM_WHY)],
            vec![named(stale, b, "OTHER")],
        ),
        (
            "on-a-clean-static",
            CLEAN,
            vec![(b, "FORM", D_UNRES, FORM_WHY)],
            vec![named(stale, b, "FORM")],
        ),
        (
            "duplicate",
            UNRES,
            vec![
                (b, "FORM", D_UNRES, FORM_WHY),
                (b, "FORM", D_UNRES, FORM_WHY),
            ],
            vec![named(dup, b, "FORM")],
        ),
        (
            "short-reason",
            UNRES,
            vec![(b, "FORM", D_UNRES, "too short")],
            vec![named(reasonless, b, "FORM")],
        ),
        (
            "blank-reason",
            UNRES,
            vec![(b, "FORM", D_UNRES, "            ")],
            vec![named(reasonless, b, "FORM")],
        ),
        (
            "on-a-lock",
            LOCK,
            vec![(b, "FORM", D_UNRES, FORM_WHY)],
            vec![
                StaticFinding::LockNotLabelled {
                    file: b.into(),
                    name: "FORM".into(),
                    line: 1,
                },
                named(stale, b, "FORM"),
            ],
        ),
    ];
    let table = format!("{b}{FORM_ROW}");
    let mut miss = Vec::new();
    for (id, text, exceptions, want) in rows {
        let files = vec![(b.to_string(), text.to_string())];
        let tables = Tables {
            statics: &table,
            exceptions: &exceptions,
            includes: &[],
        };
        let (statics, includes) = token_census_with(&files, &tables);
        if statics != want || includes != no_store_url() {
            miss.push(format!("{id}: got {statics:?} {includes:?}, want {want:?}"));
        }
    }
    assert_eq!(miss, Vec::<String>::new());
}

/// #10285: a static in a `macro_rules!` body is red whatever its type, a
/// row never accepts it, and only an exception does.
#[test]
fn static_in_a_macro_body_is_red_10285() {
    const LOCK_BODY: &str = "macro_rules! m {\n    () => {\n        static INNER: std::sync::Mutex<u8> = X;\n    };\n}\n";
    const CLEAN_BODY: &str =
        "macro_rules! m {\n    () => {\n        static INNER: u8 = 0;\n    };\n}\n";
    const LOCK_ROW: &str = "src/b.rs\tINNER\tlock: a lock written in the macro body\n";
    let b = "src/b.rs";
    let body = StaticFinding::MacroBodyStatic {
        file: b.into(),
        name: "INNER".into(),
        line: 3,
    };
    let missing = StaticFinding::Missing {
        file: b.into(),
        name: "INNER".into(),
    };
    let rows: Vec<MacroBodyCase<'_>> = vec![
        ("lock", LOCK_BODY, "", vec![], vec![body.clone()]),
        ("clean", CLEAN_BODY, "", vec![], vec![body.clone()]),
        (
            "with-a-row",
            LOCK_BODY,
            LOCK_ROW,
            vec![],
            vec![body.clone(), missing],
        ),
        (
            "excepted",
            LOCK_BODY,
            "",
            vec![(b, "INNER", D_INNER, FORM_WHY)],
            vec![],
        ),
    ];
    let mut miss = Vec::new();
    for (id, text, table, exceptions, want) in rows {
        let files = vec![(b.to_string(), text.to_string())];
        let tables = Tables {
            statics: table,
            exceptions: &exceptions,
            includes: &[],
        };
        let (statics, _) = token_census_with(&files, &tables);
        if statics != want {
            miss.push(format!("{id}: got {statics:?}, want {want:?}"));
        }
    }
    assert_eq!(miss, Vec::<String>::new());
}

/// #10276: every spelling of an `include!` of a file the walk did not read
/// is red, and each leaves an `include` token the per-file count holds
/// against its row, so a spelling the recogniser misses is still red.
#[test]
fn include_forms_are_red_10276() {
    let b = "src/b.rs";
    let forms: [(&str, &str, Option<usize>); 9] = [
        ("plain", "include!(\"missing.rs\");\n", Some(1)),
        ("raw-ident", "r#include!(\"missing.rs\");\n", Some(1)),
        ("core-path", "core::include!(\"missing.rs\");\n", Some(1)),
        (
            "std-absolute-path",
            "::std::include!(\"missing.rs\");\n",
            Some(1),
        ),
        ("brackets", "include![\"missing.rs\"];\n", Some(1)),
        ("braces", "include! {\"missing.rs\"}\n", Some(1)),
        (
            "use-rename",
            "use std::include as pull;\npull!(\"missing.rs\");\n",
            Some(2),
        ),
        (
            "in-macro-body",
            "macro_rules! m {\n    () => {\n        include!(\"missing.rs\")\n    };\n}\n",
            Some(3),
        ),
        (
            "macro-argument",
            "macro_rules! m {\n    ($i:ident) => {\n        $i!(\"missing.rs\")\n    };\n}\nm!(include);\n",
            None,
        ),
    ];
    let mut miss = Vec::new();
    for (id, text, hit) in forms {
        let files = vec![(b.to_string(), text.to_string())];
        let (_, includes) = token_census_with(&files, &bare(""));
        let mut want: Vec<IncludeFinding> = hit
            .map(|line| IncludeFinding::Unwalked {
                file: b.into(),
                line,
                value: "missing.rs".into(),
            })
            .into_iter()
            .collect();
        want.extend(no_store_url());
        want.push(IncludeFinding::IncludeCount {
            file: b.into(),
            ident: "include".into(),
            rowed: 0,
            found: 1,
        });
        if includes != want {
            miss.push(format!("{id}: got {includes:?}, want {want:?}"));
        }
    }
    assert_eq!(miss, Vec::<String>::new());
}

/// #10276: the include-count rows are judged exactly: a wrong count, a
/// duplicate, a zero count, a short reason, an identifier not counted and a
/// row for a file with none are each red.
#[test]
fn include_rows_are_judged_exactly_10276() {
    let b = "src/b.rs";
    let files = vec![
        (b.to_string(), "include!(\"x.rs\");\n".to_string()),
        ("src/x.rs".to_string(), String::new()),
    ];
    let count = |file: &str, rowed: usize, found: usize| IncludeFinding::IncludeCount {
        file: file.into(),
        ident: "include".into(),
        rowed,
        found,
    };
    let bad = |file: &str, ident: &str| IncludeFinding::IncludeRowBad {
        file: file.into(),
        ident: ident.into(),
    };
    let stale = |file: &str, ident: &str| IncludeFinding::IncludeRowStale {
        file: file.into(),
        ident: ident.into(),
    };
    let rows: Vec<IncludeRowCase<'_>> = vec![
        ("exact", vec![(b, "include", 1, FORM_WHY)], vec![]),
        ("no-row", vec![], vec![count(b, 0, 1)]),
        (
            "wrong-count",
            vec![(b, "include", 2, FORM_WHY)],
            vec![count(b, 2, 1)],
        ),
        (
            "duplicate",
            vec![(b, "include", 1, FORM_WHY), (b, "include", 1, FORM_WHY)],
            vec![IncludeFinding::IncludeRowDuplicate {
                file: b.into(),
                ident: "include".into(),
            }],
        ),
        (
            "zero",
            vec![(b, "include", 0, FORM_WHY)],
            vec![bad(b, "include"), count(b, 0, 1)],
        ),
        (
            "short-reason",
            vec![(b, "include", 1, "short")],
            vec![bad(b, "include")],
        ),
        (
            "not-counted",
            vec![(b, "include_str", 1, FORM_WHY)],
            vec![
                bad(b, "include_str"),
                count(b, 0, 1),
                stale(b, "include_str"),
            ],
        ),
        (
            "stale",
            vec![
                (b, "include", 1, FORM_WHY),
                ("src/gone.rs", "include", 1, FORM_WHY),
            ],
            vec![stale("src/gone.rs", "include")],
        ),
    ];
    let mut miss = Vec::new();
    for (id, table, extra) in rows {
        let tables = Tables {
            statics: "",
            exceptions: &[],
            includes: &table,
        };
        let (_, includes) = token_census_with(&files, &tables);
        let mut want = no_store_url();
        want.extend(extra);
        if includes != want {
            miss.push(format!("{id}: got {includes:?}, want {want:?}"));
        }
    }
    assert_eq!(miss, Vec::<String>::new());
}

/// #10277: every manifest form that names a source the census did not
/// read, or a value it cannot read, is red with its exact finding.
#[test]
fn cargo_manifest_forms_are_red_10277() {
    let walked: BTreeSet<&str> = [
        "src/lib.rs",
        "src/main.rs",
        "build.rs",
        "tests/t.rs",
        "vendored/x/src/lib.rs",
    ]
    .into_iter()
    .collect();
    let bad = |k: &str| CargoFinding::BadType { key: k.into() };
    let unwalked = |kind: &'static str, name: &str, path: &str| CargoFinding::Unwalked {
        kind,
        name: name.into(),
        path: path.into(),
    };
    let not_rs = |kind: &'static str, name: &str, path: &str| CargoFinding::NotRs {
        kind,
        name: name.into(),
        path: path.into(),
    };
    let dep = |k: &str, p: &str| CargoFinding::DependencyPathUnwalked {
        key: k.into(),
        path: p.into(),
    };
    let rows: Vec<(&str, &str, Vec<CargoFinding>)> = vec![
        ("clean", "[package]\nname = \"ai-memory\"\n", vec![]),
        ("lib-dot-slash", "[lib]\npath = \"./src/lib.rs\"\n", vec![]),
        (
            "lib-upper-ext",
            "[lib]\npath = \"src/lib.RS\"\n",
            vec![not_rs("lib", CRATE_NAME, "src/lib.RS")],
        ),
        (
            "lib-no-ext",
            "[lib]\npath = \"src/lib\"\n",
            vec![not_rs("lib", CRATE_NAME, "src/lib")],
        ),
        (
            "lib-in-target",
            "[lib]\npath = \"target/gen/lib.rs\"\n",
            vec![unwalked("lib", CRATE_NAME, "target/gen/lib.rs")],
        ),
        (
            "lib-parent",
            "[lib]\npath = \"../x/src/lib.rs\"\n",
            vec![unwalked("lib", CRATE_NAME, "../x/src/lib.rs")],
        ),
        (
            "lib-absolute",
            "[lib]\npath = \"/abs/lib.rs\"\n",
            vec![unwalked("lib", CRATE_NAME, "/abs/lib.rs")],
        ),
        (
            "lib-name",
            "[lib]\nname = \"other\"\n",
            vec![CargoFinding::LibName {
                found: "other".into(),
            }],
        ),
        ("lib-name-type", "[lib]\nname = 3\n", vec![bad("lib.name")]),
        ("lib-path-type", "[lib]\npath = 3\n", vec![bad("lib.path")]),
        ("lib-not-table", "lib = \"src/lib.rs\"\n", vec![bad("lib")]),
        (
            "bin-path",
            "[[bin]]\nname = \"x\"\npath = \"gen/x.rs\"\n",
            vec![unwalked("bin", "x", "gen/x.rs")],
        ),
        (
            "bin-walked",
            "[[bin]]\nname = \"ai-memory\"\npath = \"src/main.rs\"\n",
            vec![],
        ),
        (
            "test-default-absent",
            "[[test]]\nname = \"nope\"\n",
            vec![unwalked("test", "nope", "tests/nope.rs")],
        ),
        ("test-default-walked", "[[test]]\nname = \"t\"\n", vec![]),
        (
            "bench-not-rs",
            "[[bench]]\nname = \"b\"\npath = \"benches/b.RS\"\n",
            vec![not_rs("bench", "b", "benches/b.RS")],
        ),
        (
            "example-default-absent",
            "[[example]]\nname = \"e\"\n",
            vec![unwalked("example", "e", "examples/e.rs")],
        ),
        ("bin-not-array", "bin = 3\n", vec![bad("bin")]),
        ("bin-entry-not-table", "bin = [3]\n", vec![bad("bin[0]")]),
        (
            "bin-name-type",
            "[[bin]]\nname = 3\n",
            vec![bad("bin[0].name")],
        ),
        (
            "bin-path-type",
            "[[bin]]\nname = \"x\"\npath = 3\n",
            vec![bad("bin[0].path")],
        ),
        ("build-true", "[package]\nbuild = true\n", vec![]),
        ("build-false", "[package]\nbuild = false\n", vec![]),
        (
            "build-string",
            "[package]\nbuild = \"gen/build.rs\"\n",
            vec![unwalked("build", "build", "gen/build.rs")],
        ),
        (
            "build-not-rs",
            "[package]\nbuild = \"build.RS\"\n",
            vec![not_rs("build", "build", "build.RS")],
        ),
        (
            "build-array",
            "[package]\nbuild = [\"build.rs\", \"gen/b.rs\", 3]\n",
            vec![
                unwalked("build", "build", "gen/b.rs"),
                bad("package.build[2]"),
            ],
        ),
        (
            "build-type",
            "[package]\nbuild = 3\n",
            vec![bad("package.build")],
        ),
        ("package-not-table", "package = 3\n", vec![bad("package")]),
        (
            "dep-path-out",
            "[dependencies]\nx = { path = \"../x\" }\n",
            vec![dep("dependencies.x.path", "../x")],
        ),
        (
            "dep-path-walked",
            "[dependencies]\nx = { path = \"vendored/x\" }\n",
            vec![],
        ),
        (
            "dep-path-type",
            "[dependencies]\nx = { path = 3 }\n",
            vec![bad("dependencies.x.path")],
        ),
        (
            "deps-not-table",
            "dependencies = 3\n",
            vec![bad("dependencies")],
        ),
        (
            "dev-dep",
            "[dev-dependencies]\nx = { path = \"gen/x\" }\n",
            vec![dep("dev-dependencies.x.path", "gen/x")],
        ),
        (
            "build-dep-slash",
            "[build-dependencies]\nx = { path = \"gen/x/\" }\n",
            vec![dep("build-dependencies.x.path", "gen/x")],
        ),
        (
            "target-cfg",
            "[target.'cfg(unix)'.dependencies]\nx = { path = \"../x\" }\n",
            vec![dep("target.cfg(unix).dependencies.x.path", "../x")],
        ),
        ("target-not-table", "target = 3\n", vec![bad("target")]),
        (
            "target-cfg-not-table",
            "[target]\nunix = 3\n",
            vec![bad("target.unix")],
        ),
        (
            "patch",
            "[patch.crates-io]\nx = { path = \"../x\" }\n",
            vec![dep("patch.crates-io.x.path", "../x")],
        ),
        ("patch-not-table", "patch = 3\n", vec![bad("patch")]),
        (
            "patch-source-not-table",
            "[patch]\ncrates-io = 3\n",
            vec![bad("patch.crates-io")],
        ),
        (
            "replace",
            "[replace]\n\"x:0.1.0\" = { path = \"../x\" }\n",
            vec![dep("replace.x:0.1.0.path", "../x")],
        ),
        ("replace-not-table", "replace = 3\n", vec![bad("replace")]),
        ("workspace", "[workspace]\n", vec![CargoFinding::Workspace]),
        (
            "unparseable",
            "[package\n",
            vec![CargoFinding::Unparseable(
                "invalid table header\nexpected `.`, `]`".into(),
            )],
        ),
    ];
    let mut miss = Vec::new();
    for (id, manifest, want) in rows {
        let got = cargo_census(Ok(manifest.to_string()), &walked);
        if got != want {
            miss.push(format!("{id}: got {got:?}, want {want:?}"));
        }
    }
    assert_eq!(miss, Vec::<String>::new());
    assert_eq!(
        cargo_census(Err("permission denied".into()), &walked),
        vec![CargoFinding::Unreadable("permission denied".into())]
    );
}

/// #10277: each census finding prints its exact message.
#[test]
fn cargo_findings_print_exactly_10277() {
    let rows = [
        (
            CargoFinding::Unreadable("permission denied".into()),
            "Cargo.toml cannot be read: permission denied",
        ),
        (
            CargoFinding::Unparseable("bad".into()),
            "Cargo.toml does not parse: bad",
        ),
        (
            CargoFinding::BadType { key: "lib".into() },
            "Cargo.toml `lib` is not of the type Cargo reads there",
        ),
        (
            CargoFinding::NotRs {
                kind: "lib",
                name: CRATE_NAME.into(),
                path: "src/lib.RS".into(),
            },
            "Cargo.toml lib target `ai_memory` names `src/lib.RS`, which does not end in `.rs` (exact case), so the census never reads it",
        ),
        (
            CargoFinding::Unwalked {
                kind: "bin",
                name: "x".into(),
                path: "gen/x.rs".into(),
            },
            "Cargo.toml bin target `x` names `gen/x.rs`, which the census did not read",
        ),
        (
            CargoFinding::Workspace,
            "Cargo.toml has a [workspace] table, whose members the census does not model",
        ),
        (
            CargoFinding::DependencyPathUnwalked {
                key: "dependencies.x.path".into(),
                path: "../x".into(),
            },
            "Cargo.toml `dependencies.x.path` names the directory `../x`, which holds no file the census read",
        ),
        (
            CargoFinding::LibName {
                found: "other".into(),
            },
            "Cargo.toml [lib] name is `other`, not `ai_memory`",
        ),
    ];
    for (finding, text) in rows {
        assert_eq!(finding.to_string(), text);
    }
}

/// #10277: the directories Cargo discovers targets in are walked whole, so
/// a default target source is always read; the walked set is written out.
#[test]
fn auto_target_dirs_are_walked_10277() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("store_url_env_guard_8168_autodirs");
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear scratch");
    }
    let made = [
        "benches/c.rs",
        "build.rs",
        "examples/e/main.rs",
        "src/bin/a.rs",
        "src/bin/b/main.rs",
        "src/lib.rs",
        "tests/d/m.rs",
        "tests/t.rs",
    ];
    for rel in made {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        fs::write(&path, "").expect("write");
    }
    let mut files = Vec::new();
    let mut links = Vec::new();
    walk(&root, &root, &mut files, &mut links);
    let mut got: Vec<String> = files.into_iter().map(|(p, _)| p).collect();
    got.sort();
    assert_eq!(got, made.map(String::from).to_vec());
    let walked: BTreeSet<&str> = got.iter().map(String::as_str).collect();
    let manifest = "[package]\nbuild = true\n[[bin]]\nname = \"a\"\n[[bin]]\nname = \"b\"\n\
                    [[test]]\nname = \"t\"\n[[bench]]\nname = \"c\"\n[[example]]\nname = \"e\"\n";
    assert_eq!(cargo_census(Ok(manifest.into()), &walked), vec![]);
    assert_eq!(links, Vec::<String>::new());
    fs::remove_dir_all(&root).expect("clean scratch");
}

/// The types `src/a.rs` defines for the round-2 reviewer forms (#10275).
const R2_DEFS: &str = "pub struct Gate {\n    m: std::sync::Mutex<u8>,\n}\n\
pub type One = Two;\npub type Two = std::sync::RwLock<u8>;\npub type Erased = Box<dyn Fn() + Sync>;\n";

/// Round-2 reviewer forms of a static under a `once` row: each is a lock or
/// a type the census cannot prove lock-free, so the census must report it.
const R2_STATIC_FORMS: &[(&str, &str)] = &[
    (
        "10275-cross-file-path",
        "static FORM: crate::a::Gate = X;\n",
    ),
    ("10275-cross-file-bare", "static FORM: Gate = X;\n"),
    (
        "10275-cross-file-alias",
        "static FORM: crate::a::One = X;\n",
    ),
    (
        "10283-dyn-boxed",
        "static FORM: Box<dyn std::any::Any + Sync> = X;\n",
    ),
    (
        "10283-dyn-lazy-boxed",
        "static FORM: std::sync::LazyLock<Box<dyn Send + Sync>> = X;\n",
    ),
    ("10283-erased-alias", "static FORM: crate::a::Erased = X;\n"),
    ("10283-macro-type", "static FORM: my_type!() = X;\n"),
    (
        "10283-impl-alias",
        "type Hidden = impl Sized;\nstatic FORM: Hidden = X;\n",
    ),
    (
        "10278-generic-default",
        "struct Holder<T = std::sync::Mutex<u8>>(T);\nstatic FORM: Holder = X;\n",
    ),
    (
        "10279-fair",
        "static FORM: parking_lot::FairMutex<u8> = X;\n",
    ),
    (
        "10279-raw",
        "static FORM: lock_api::Mutex<parking_lot::RawMutex, u8> = X;\n",
    ),
    (
        "10279-raw-rwlock",
        "static FORM: parking_lot::RawRwLock = X;\n",
    ),
    (
        "10285-macro-body",
        "macro_rules! m {\n    () => {\n        static INNER: u8 = 0;\n    };\n}\n",
    ),
];

/// Round-2 reviewer forms of an `include!` of a file the walk did not read.
const R2_INCLUDE_FORMS: &[(&str, &str)] = &[
    (
        "10276-use-rename",
        "use std::include as pull;\npull!(\"missing.rs\");\n",
    ),
    ("10276-brackets", "include![\"missing.rs\"];\n"),
    ("10276-braces", "include! {\"missing.rs\"}\n"),
    ("10276-core-path", "core::include!(\"missing.rs\");\n"),
];

/// #10274 round 2: every reviewer form leaves a finding naming `src/b.rs`.
/// Red where the census was silent (fail-open); the exact findings are
/// pinned by the form tables that follow the fix.
#[test]
fn review_r1_forms_are_red_10274() {
    let names_b = |dbg: String| dbg.contains("\"src/b.rs\"");
    let mut silent = Vec::new();
    for (id, text) in R2_STATIC_FORMS {
        let files = vec![
            ("src/a.rs".to_string(), R2_DEFS.to_string()),
            ("src/b.rs".to_string(), (*text).to_string()),
        ];
        let table = "src/b.rs\tFORM\tonce: a value computed once, no lock\n";
        let (statics, _) = token_census(&files, table);
        let hit = statics
            .iter()
            .any(|f| names_b(format!("{f:?}")) && !matches!(f, StaticFinding::Missing { .. }));
        if !hit {
            silent.push(format!("{id}: {statics:?}"));
        }
    }
    for (id, text) in R2_INCLUDE_FORMS {
        let files = vec![("src/b.rs".to_string(), (*text).to_string())];
        let (_, includes) = token_census(&files, "");
        if !includes.iter().any(|f| names_b(format!("{f:?}"))) {
            silent.push(format!("{id}: {includes:?}"));
        }
    }
    assert_eq!(silent, Vec::<String>::new());
}

/// #10284: the definition scan is linear for every lexable input, including
/// one that does not compile: 100 000 repetitions of each item keyword left
/// without the tokens that would end its scan are judged under the ceiling
/// (the round-1 scan took 22 s to 76 s at 50 000, and the round-2 struct
/// body scan 74 s at 100 000).
#[test]
fn type_definition_cost_is_bounded_10284() {
    const REPS: usize = 100_000;
    const CEILING_SECS: u64 = 20;
    const UNITS: [&str; 9] = [
        "type x ",
        "struct x ",
        "struct x { ",
        "enum x < ",
        "struct x < ",
        "type x = < ",
        "struct x where < ",
        "use x < ",
        "type x = ( ",
    ];
    for unit in UNITS {
        let files = vec![("src/hostile.rs".to_string(), unit.repeat(REPS))];
        let start = std::time::Instant::now();
        let (statics, _) = token_census_with(&files, &bare(""));
        let took = start.elapsed();
        assert!(
            took < std::time::Duration::from_secs(CEILING_SECS),
            "{unit:?}: {took:?}"
        );
        assert_eq!(statics, Vec::<StaticFinding>::new(), "{unit:?}");
    }
}

/// #10284: the token census is linear in the tree. 100K+ lines of alias
/// chains, wrappers and enums 20 000 deep across files, an alias cycle and
/// 10 000 statics that name them are judged under the ceiling, with every
/// finding exact (a quadratic definition table took minutes here).
#[test]
fn token_census_cost_is_bounded_10213() {
    const DEPTH: usize = 20_000;
    const STATICS: usize = 10_000;
    const CEILING_SECS: u64 = 20;
    let mut types = String::new();
    for i in 0..DEPTH {
        let _ = writeln!(types, "pub type A{i} = A{};", i + 1);
        let _ = writeln!(types, "pub type L{i} = L{};", i + 1);
        let _ = writeln!(types, "pub struct W{i}(A{i});");
        let _ = writeln!(types, "pub enum E{i} {{ V(W{i}) }}");
    }
    let _ = writeln!(types, "pub type A{DEPTH} = u8;");
    let _ = writeln!(types, "pub type L{DEPTH} = std::sync::Mutex<u8>;");
    types.push_str("pub type C0 = C1;\npub type C1 = C0;\n");
    let mut statics = String::new();
    let mut table = String::new();
    for i in 0..STATICS {
        let _ = writeln!(statics, "static S{i}: crate::types::E{i} = X;");
        statics.push_str("#[path = \"other.rs\"]\n");
        statics.push_str("const X: &str = include_str!(\"y.md\");\n");
        let _ = write!(table, "src/statics.rs\tS{i}{}", &FORM_ROW[5..]);
    }
    statics.push_str("static K: crate::types::L0 = X;\nstatic Y: crate::types::C0 = X;\n");
    let _ = write!(table, "src/statics.rs\tK{}", &FORM_ROW[5..]);
    let _ = write!(table, "src/statics.rs\tY{}", &FORM_ROW[5..]);
    let lines = types.lines().count() + statics.lines().count();
    assert!(lines > 100_000, "{lines} lines");
    let files = vec![
        ("src/types.rs".to_string(), types),
        ("src/statics.rs".to_string(), statics),
        ("src/other.rs".to_string(), String::new()),
    ];
    let start = std::time::Instant::now();
    let (found, includes) = token_census_with(&files, &bare(&table));
    let took = start.elapsed();
    assert!(
        took < std::time::Duration::from_secs(CEILING_SECS),
        "{took:?}"
    );
    assert_eq!(
        found,
        vec![
            StaticFinding::LockNotLabelled {
                file: "src/statics.rs".into(),
                name: "K".into(),
                line: 3 * STATICS + 1,
            },
            StaticFinding::Unresolvable {
                file: "src/statics.rs".into(),
                name: "Y".into(),
                line: 3 * STATICS + 2,
                why: Why::Cycle("C0".into()),
            },
        ]
    );
    assert_eq!(includes, no_store_url());
}

// ---------------------------------------------------------------------------
// #10274 round 3 (#10293, #10294, #10295): a name is judged by where it
// resolves in the scope that wrote it, and an exception by the content of
// the definitions behind it.
// ---------------------------------------------------------------------------

/// One round-3 case: the id, the files as (path, text), the static
/// findings, and the include findings (`None` for exactly
/// [`no_store_url`]).
type R3Case = (
    &'static str,
    Vec<(&'static str, &'static str)>,
    Vec<StaticFinding>,
    Option<Vec<IncludeFinding>>,
);

/// `LockNotLabelled` for the `FORM` static at `line` of `file`.
fn r3_lock(file: &str, line: usize) -> StaticFinding {
    StaticFinding::LockNotLabelled {
        file: file.into(),
        name: "FORM".into(),
        line,
    }
}

/// `Unresolvable` for the `FORM` static at `line` of `file`.
fn r3_unres(file: &str, line: usize, why: Why) -> StaticFinding {
    StaticFinding::Unresolvable {
        file: file.into(),
        name: "FORM".into(),
        line,
        why,
    }
}

/// `Foreign` for a type of another crate.
fn r3_foreign(root: &str, name: &str) -> Why {
    Why::Foreign {
        root: root.into(),
        name: name.into(),
    }
}

/// The census of `files`, every file that writes `static FORM` carrying a
/// `once` row for it.
fn r3_census(files: &[(&str, &str)]) -> (Vec<StaticFinding>, Vec<IncludeFinding>) {
    let (statics, includes, _) = r3_census_counted(files);
    (statics, includes)
}

/// #10324: [`r3_census`], with the scope visits of the glob resolver.
fn r3_census_counted(files: &[(&str, &str)]) -> (Vec<StaticFinding>, Vec<IncludeFinding>, u64) {
    let mut table = String::new();
    for (file, text) in files {
        if text.contains("static FORM") {
            table.push_str(file);
            table.push_str(FORM_ROW);
        }
    }
    let owned: Vec<(String, String)> = files
        .iter()
        .map(|(f, t)| ((*f).to_string(), (*t).to_string()))
        .collect();
    token_census_counted(&owned, &bare(&table))
}

/// Runs every case and returns one line per case whose findings differ.
fn r3_misses(cases: Vec<R3Case>) -> Vec<String> {
    let mut miss = Vec::new();
    for (id, files, want, inc) in cases {
        let (statics, includes) = r3_census(&files);
        let want_inc = inc.unwrap_or_else(no_store_url);
        if statics != want || includes != want_inc {
            miss.push(format!(
                "{id}: got {statics:?} {includes:?}, want {want:?} {want_inc:?}"
            ));
        }
    }
    miss
}

/// A macro that writes a lock-holding struct `W` in `src/a.rs` (#10293 P1).
const R3_MACRO_W: &str = "macro_rules! mk {\n    () => {\n        pub struct W {\n            m: std::sync::Mutex<u8>,\n        }\n    };\n}\nmk!();\n";

/// #10293, #10294: the six round-2 review probes. A clean homonym elsewhere
/// in the tree never vouches for a name, and a glob never supplies one.
#[test]
fn review_r2_probes_are_red_10293() {
    let b = "src/b.rs";
    let reexport = "pub use dashmap::DashMap;\n";
    let user = "use crate::a::DashMap;\nstatic FORM: DashMap<u8, u8> = X;\n";
    let homonym = "pub struct DashMap;\n";
    let cases: Vec<R3Case> = vec![
        (
            "P1-macro-holder-and-homonym",
            vec![
                ("src/a.rs", R3_MACRO_W),
                ("tests/c.rs", "pub struct W;\n"),
                (b, "static FORM: W = X;\n"),
            ],
            vec![r3_unres(b, 1, Why::NoDef("W".into()))],
            None,
        ),
        (
            "P2-reexport-and-tests-homonym",
            vec![("src/a.rs", reexport), (b, user), ("tests/c.rs", homonym)],
            vec![r3_unres(b, 2, r3_foreign("dashmap", "DashMap"))],
            None,
        ),
        (
            "P2b-reexport-and-src-homonym",
            vec![("src/a.rs", reexport), (b, user), ("src/c.rs", homonym)],
            vec![r3_unres(b, 2, r3_foreign("dashmap", "DashMap"))],
            None,
        ),
        (
            "P2-control-reexport-alone",
            vec![("src/a.rs", reexport), (b, user)],
            vec![r3_unres(b, 2, r3_foreign("dashmap", "DashMap"))],
            None,
        ),
        (
            "P1-control-macro-type-alone",
            vec![("src/a.rs", R3_MACRO_W), (b, "static FORM: W = X;\n")],
            vec![r3_unres(b, 1, Why::NoDef("W".into()))],
            None,
        ),
        (
            "P13-foreign-glob-bare-leaf",
            vec![(b, "use foreign::*;\nstatic FORM: Cell<u8> = X;\n")],
            vec![r3_unres(b, 2, Why::Glob("Cell".into()))],
            None,
        ),
        (
            "P13b-reexported-glob-path",
            vec![
                ("src/a.rs", "pub use foreign::*;\n"),
                (b, "static FORM: crate::a::Cell<u8> = X;\n"),
            ],
            vec![r3_unres(b, 1, Why::Glob("Cell".into()))],
            None,
        ),
    ];
    assert_eq!(r3_misses(cases), Vec::<String>::new());
}

/// #10293: the earlier review forms, rewritten, each with its exact finding
/// under scoped resolution.
#[test]
fn earlier_review_forms_stay_red_10293() {
    let b = "src/b.rs";
    let count = IncludeFinding::IncludeCount {
        file: b.into(),
        ident: "include".into(),
        rowed: 0,
        found: 1,
    };
    let with = |pre: Vec<IncludeFinding>, post: Vec<IncludeFinding>| {
        let mut v = pre;
        v.extend(no_store_url());
        v.extend(post);
        Some(v)
    };
    let unwalked = |line: usize, value: &str| IncludeFinding::Unwalked {
        file: "src/b.rs".into(),
        line,
        value: value.into(),
    };
    let cases: Vec<R3Case> = vec![
        (
            "P1b-macro-named-struct",
            vec![(
                b,
                "macro_rules! mk {\n    ($n:ident) => {\n        struct $n(std::sync::Mutex<u8>);\n    };\n}\nmk!(W);\nstatic FORM: W = X;\n",
            )],
            vec![r3_unres(b, 7, Why::NoDef("W".into()))],
            None,
        ),
        (
            "P2c-foreign-rename",
            vec![(b, "use parking::Gate as G;\nstatic FORM: G = X;\n")],
            vec![r3_unres(b, 2, r3_foreign("parking", "Gate"))],
            None,
        ),
        (
            "P3-three-file-alias-chain",
            vec![
                ("src/a.rs", "pub type A = crate::c::C;\n"),
                (
                    "src/c.rs",
                    "pub type C = Option<(u8, [parking_lot::Mutex<u8>; 2])>;\n",
                ),
                (b, "static FORM: crate::a::A = X;\n"),
            ],
            vec![r3_lock(b, 1)],
            None,
        ),
        (
            "P4-qualified-projection",
            vec![(
                b,
                "trait T {\n    type X;\n}\nstatic FORM: <u8 as T>::X = X;\n",
            )],
            vec![r3_unres(b, 4, Why::Projection)],
            None,
        ),
        (
            "P5-const-generic",
            vec![(
                b,
                "struct Buf<const N: usize>([std::sync::Mutex<u8>; N]);\nstatic FORM: Buf<4> = X;\n",
            )],
            vec![r3_lock(b, 2)],
            None,
        ),
        (
            "P6-pub-use-rename",
            vec![
                (
                    "src/a.rs",
                    "use std::sync::Mutex;\npub use Mutex as Gatekeeper;\n",
                ),
                (b, "static FORM: crate::a::Gatekeeper = X;\n"),
            ],
            vec![r3_lock(b, 1)],
            None,
        ),
        (
            "P6b-bare-lock-rename",
            vec![
                ("src/a.rs", "pub use Mutex as Gatekeeper;\n"),
                (b, "static FORM: crate::a::Gatekeeper = X;\n"),
            ],
            vec![r3_lock(b, 1)],
            None,
        ),
        (
            "P7-macro-body-static",
            vec![(
                b,
                "macro_rules! mk {\n    ($n:ident) => {\n        static $n: u8 = 0;\n    };\n}\n",
            )],
            vec![StaticFinding::MacroBodyStatic {
                file: b.into(),
                name: "$n".into(),
                line: 3,
            }],
            None,
        ),
        (
            "P8-enum-boxed-tokio-lock",
            vec![(
                b,
                "enum Slot {\n    Held(Option<Box<tokio::sync::Mutex<u8>>>),\n    Empty,\n}\nstatic FORM: Slot = X;\n",
            )],
            vec![r3_lock(b, 5)],
            None,
        ),
        (
            "P9-cfg-split-alias",
            vec![(
                b,
                "#[cfg(unix)]\ntype Guard = u8;\n#[cfg(not(unix))]\ntype Guard = std::sync::Mutex<u8>;\nstatic FORM: Guard = X;\n",
            )],
            vec![r3_lock(b, 5)],
            None,
        ),
        (
            "P9b-cfg-attr-path",
            vec![(
                b,
                "#[cfg_attr(unix, path = \"elsewhere.rs\")]\nmod inner;\n",
            )],
            vec![],
            with(vec![unwalked(1, "elsewhere.rs")], vec![]),
        ),
        (
            "P10-foreign-map",
            vec![(b, "static FORM: dashmap::DashMap<u8, u8> = X;\n")],
            vec![r3_unres(b, 1, r3_foreign("dashmap", "DashMap"))],
            None,
        ),
        (
            "P10b-std-sender",
            vec![(b, "static FORM: std::sync::mpsc::Sender<u8> = X;\n")],
            vec![r3_unres(b, 1, Why::StdNotProven("Sender".into()))],
            None,
        ),
        (
            "P11-include-in-macro-body",
            vec![(
                b,
                "macro_rules! m {\n    ($p:expr) => {\n        include!($p)\n    };\n}\n",
            )],
            vec![],
            with(
                vec![IncludeFinding::IncludeNotLiteral {
                    file: b.into(),
                    line: 3,
                }],
                vec![count.clone()],
            ),
        ),
        (
            "P11b-raw-include",
            vec![(b, "// raw\nr#include!(\"gone.rs\");\n")],
            vec![],
            with(vec![unwalked(2, "gone.rs")], vec![count.clone()]),
        ),
        (
            "P12-path-out-of-root",
            vec![(b, "#[path = \"../../outside.rs\"]\nmod outside;\n")],
            vec![],
            with(vec![unwalked(1, "../../outside.rs")], vec![]),
        ),
        (
            "P15-union-manually-drop-lock",
            vec![(
                b,
                "union U {\n    a: std::mem::ManuallyDrop<std::sync::Mutex<u8>>,\n    b: u8,\n}\nstatic FORM: U = X;\n",
            )],
            vec![r3_lock(b, 5)],
            None,
        ),
        (
            "P15b-union-of-lock-holder",
            vec![(
                b,
                "struct Gate {\n    m: std::sync::RwLock<u8>,\n}\nunion W {\n    a: std::mem::ManuallyDrop<Gate>,\n}\nstatic FORM: W = X;\n",
            )],
            vec![r3_lock(b, 7)],
            None,
        ),
        (
            "P17-struct-in-fn-body",
            vec![(
                b,
                "fn make() {\n    struct Hidden(std::sync::Mutex<u8>);\n    static FORM: Hidden = X;\n}\n",
            )],
            vec![r3_lock(b, 3)],
            None,
        ),
        (
            "P18-inline-mod-homonym",
            vec![(
                b,
                "mod inner {\n    pub struct Gate(std::sync::Mutex<u8>);\n}\nstruct Gate(u8);\nstatic FORM: inner::Gate = X;\n",
            )],
            vec![r3_lock(b, 5)],
            None,
        ),
        (
            "silent-include-bytes",
            vec![(b, "const B: &[u8] = include_bytes!(\"blob.bin\");\n")],
            vec![],
            None,
        ),
        (
            "silent-fn-pointer-guard",
            vec![(
                b,
                "static FORM: fn() -> std::sync::MutexGuard<'static, u8> = X;\n",
            )],
            vec![],
            None,
        ),
    ];
    assert_eq!(r3_misses(cases), Vec::<String>::new());
}

/// #10293 rules A and B: each name is judged by its own definition, and a
/// glob, a second binding, a shadowing parameter or definition and a path
/// that lands nowhere are each refused with their reason.
#[test]
fn names_resolve_in_their_own_scope_10293() {
    let b = "src/b.rs";
    let twin_a = ("src/a.rs", "pub struct Twin(u8);\npub struct Plain(u8);\n");
    let twin_c = (
        "src/c.rs",
        "pub struct Twin(std::sync::Mutex<u8>);\npub struct Inner(std::sync::Mutex<u8>);\n",
    );
    let cases: Vec<R3Case> = vec![
        (
            "A-same-name-clean-module",
            vec![twin_a, twin_c, (b, "static FORM: crate::a::Twin = X;\n")],
            vec![],
            None,
        ),
        (
            "A-same-name-lock-module",
            vec![twin_a, twin_c, (b, "static FORM: crate::c::Twin = X;\n")],
            vec![r3_lock(b, 1)],
            None,
        ),
        (
            "A-imported-clean-twin",
            vec![
                twin_a,
                twin_c,
                (b, "use crate::a::Twin;\nstatic FORM: Twin = X;\n"),
            ],
            vec![],
            None,
        ),
        (
            "A-imported-lock-twin",
            vec![
                twin_a,
                twin_c,
                (b, "use crate::c::Twin;\nstatic FORM: Twin = X;\n"),
            ],
            vec![r3_lock(b, 2)],
            None,
        ),
        (
            "A-inline-twins",
            vec![(
                b,
                "mod x {\n    pub struct Twin(u8);\n}\nmod y {\n    pub struct Twin(std::sync::Mutex<u8>);\n}\nstatic FORM: y::Twin = X;\n",
            )],
            vec![r3_lock(b, 7)],
            None,
        ),
        (
            "A-outer-clean-over-inline-lock",
            vec![(
                b,
                "mod inner {\n    pub struct Gate(std::sync::Mutex<u8>);\n}\nstruct Gate(u8);\nstatic FORM: Gate = X;\n",
            )],
            vec![],
            None,
        ),
        (
            "B-own-crate-glob",
            vec![twin_a, (b, "use crate::a::*;\nstatic FORM: Plain = X;\n")],
            vec![r3_unres(b, 2, Why::Glob("Plain".into()))],
            None,
        ),
        (
            "B-two-bindings",
            vec![
                twin_a,
                (
                    b,
                    "use crate::a::Plain;\nstruct Plain(u8);\nstatic FORM: Plain = X;\n",
                ),
            ],
            vec![r3_unres(b, 3, Why::Ambiguous("Plain".into()))],
            None,
        ),
        (
            "B-generic-shadows-prelude",
            vec![(
                b,
                "struct Wrap<String>(String);\nstatic FORM: Wrap<u8> = X;\n",
            )],
            vec![r3_unres(b, 2, Why::Shadowed("String".into()))],
            None,
        ),
        (
            "B-local-def-shadows-prelude",
            vec![(b, "struct Vec(u8);\nstatic FORM: Vec = X;\n")],
            vec![r3_unres(b, 2, Why::Shadowed("Vec".into()))],
            None,
        ),
        (
            "B-crate-path-lands-nowhere",
            vec![(b, "static FORM: crate::nowhere::Thing = X;\n")],
            vec![r3_unres(b, 1, Why::PathNotLanded("nowhere".into()))],
            None,
        ),
        (
            "B-super-path-lands-nowhere",
            vec![(b, "static FORM: super::Thing = X;\n")],
            vec![r3_unres(b, 1, Why::PathNotLanded("Thing".into()))],
            None,
        ),
    ];
    assert_eq!(r3_misses(cases), Vec::<String>::new());
}

/// #10293: invented forms of the scoped-resolution class: std globs, rename
/// chains, use cycles, fn-body and module scopes, aliases, nested groups,
/// `#[path]` modules, generic aliases, the binary's own crate root, a glob
/// prefix met while settling, a projection off a type, a module named as a
/// type, `super` above the root and the crate name with no library walked.
#[test]
fn invented_scope_forms_are_judged_10293() {
    let b = "src/b.rs";
    let twin_a = ("src/a.rs", "pub struct Twin(u8);\npub struct Plain(u8);\n");
    let twin_c = (
        "src/c.rs",
        "pub struct Twin(std::sync::Mutex<u8>);\npub struct Inner(std::sync::Mutex<u8>);\n",
    );
    let cases: Vec<R3Case> = vec![
        (
            "I1-std-glob-lock",
            vec![(b, "use std::sync::*;\nstatic FORM: Mutex<u8> = X;\n")],
            vec![r3_lock(b, 2)],
            None,
        ),
        (
            "I2-rename-chain",
            vec![
                ("src/a.rs", "pub use crate::c::Inner as Middle;\n"),
                twin_c,
                (
                    b,
                    "use crate::a::Middle as Outer;\nstatic FORM: Outer = X;\n",
                ),
            ],
            vec![r3_lock(b, 2)],
            None,
        ),
        (
            "I3-use-cycle",
            vec![(
                b,
                "use crate::b::Q as P;\nuse crate::b::P as Q;\nstatic FORM: P = X;\n",
            )],
            vec![r3_unres(b, 3, Why::Cycle("P".into()))],
            None,
        ),
        (
            "I4-fn-body-homonym-not-seen",
            vec![(
                b,
                "struct Gate(u8);\nfn f() {\n    struct Gate(std::sync::Mutex<u8>);\n}\nstatic FORM: Gate = X;\n",
            )],
            vec![],
            None,
        ),
        (
            "I5-fn-body-sees-outer",
            vec![(
                b,
                "struct Gate(std::sync::Mutex<u8>);\nfn f() {\n    static FORM: Gate = X;\n}\n",
            )],
            vec![r3_lock(b, 3)],
            None,
        ),
        (
            "I6-module-does-not-see-outer",
            vec![(
                b,
                "struct Gate(std::sync::Mutex<u8>);\nmod m {\n    static FORM: Gate = X;\n}\n",
            )],
            vec![r3_unres(b, 3, Why::NoDef("Gate".into()))],
            None,
        ),
        (
            "I7-tests-module-alias",
            vec![
                ("src/a.rs", FORM_DEFS),
                (
                    "tests/t.rs",
                    "use ai_memory::a as m;\nstatic FORM: m::Gate = X;\n",
                ),
            ],
            vec![r3_lock("tests/t.rs", 2)],
            None,
        ),
        (
            "I8-global-foreign-alias",
            vec![(
                b,
                "use ::dashmap as dm;\nstatic FORM: dm::DashMap<u8, u8> = X;\n",
            )],
            vec![r3_unres(b, 2, r3_foreign("dashmap", "DashMap"))],
            None,
        ),
        (
            "I9-self-use-into-inline-mod",
            vec![(
                b,
                "use self::inner::Gate;\nmod inner {\n    pub struct Gate(std::sync::Mutex<u8>);\n}\nstatic FORM: Gate = X;\n",
            )],
            vec![r3_lock(b, 5)],
            None,
        ),
        (
            "I10-glob-in-fn-body",
            vec![
                twin_a,
                (
                    b,
                    "fn f() {\n    use crate::a::*;\n    static FORM: Plain = X;\n}\n",
                ),
            ],
            vec![r3_unres(b, 3, Why::Glob("Plain".into()))],
            None,
        ),
        (
            "I11-nested-use-group",
            vec![
                ("src/a.rs", FORM_DEFS),
                twin_c,
                (
                    b,
                    "use crate::{a::Gate as G, c::Twin};\nstatic FORM: (Twin, G) = X;\n",
                ),
            ],
            vec![r3_lock(b, 2)],
            None,
        ),
        (
            "I12-path-attr-module",
            vec![
                ("src/x.rs", "pub struct Thing(u8);\n"),
                (
                    b,
                    "#[path = \"x.rs\"]\nmod px;\nstatic FORM: px::Thing = X;\n",
                ),
            ],
            vec![r3_unres(b, 3, Why::PathNotLanded("Thing".into()))],
            None,
        ),
        (
            "I13-generic-alias-to-lock",
            vec![(
                b,
                "type M<T> = std::sync::Mutex<T>;\nstatic FORM: M<u8> = X;\n",
            )],
            vec![r3_lock(b, 2)],
            None,
        ),
        (
            "I14-binary-root-imports-stay-in-the-binary",
            vec![
                twin_a,
                ("src/main.rs", "use ai_memory::a;\n"),
                (b, "static FORM: crate::a::Plain = X;\n"),
            ],
            vec![],
            None,
        ),
        (
            "I15-binary-root-sees-the-library-by-name",
            vec![
                twin_c,
                ("src/main.rs", "use ai_memory::c;\n"),
                (b, "static FORM: crate::c::Inner = X;\n"),
            ],
            vec![r3_lock(b, 1)],
            None,
        ),
        (
            // A glob's prefix is looked up while globs are being settled,
            // when any glob may still supply it, so it stays unknown.
            "I16-glob-prefix-met-while-settling",
            vec![
                ("src/a.rs", "pub struct Other;\n"),
                (b, "use ai_memory::a::*;\nstatic FORM: Plain = X;\n"),
            ],
            vec![r3_unres(b, 2, Why::Glob("Plain".into()))],
            None,
        ),
        (
            "I17-path-runs-on-past-a-type",
            vec![twin_a, (b, "static FORM: crate::a::Plain::Inner = X;\n")],
            vec![r3_unres(b, 1, Why::Projection)],
            None,
        ),
        (
            "I18-module-named-as-a-type",
            vec![twin_a, (b, "static FORM: crate::a = X;\n")],
            vec![r3_unres(b, 1, Why::PathNotLanded("a".into()))],
            None,
        ),
        (
            "I19-super-above-the-crate-root",
            vec![(b, "static FORM: super::super::Thing = X;\n")],
            vec![r3_unres(b, 1, Why::PathNotLanded("super".into()))],
            None,
        ),
        (
            "I20-crate-name-with-no-library-walked",
            vec![("tests/t.rs", "static FORM: ai_memory::Thing = X;\n")],
            vec![r3_unres(
                "tests/t.rs",
                1,
                Why::PathNotLanded("ai_memory".into()),
            )],
            None,
        ),
    ];
    assert_eq!(r3_misses(cases), Vec::<String>::new());
}

/// #10295: a struct reached from `Bus`, then `Bus` itself.
const R3_BUS: &str = "pub struct Inner {\n    v: Unknown,\n}\npub struct Bus {\n    tx: Inner,\n}\nstatic FORM: Bus = X;\n";

/// #10295 P14b: `Bus` gains a foreign field after its exception was pinned.
const R3_BUS_FIELD: &str = "pub struct Inner {\n    v: Unknown,\n}\npub struct Bus {\n    tx: Inner,\n    m: dashmap::DashMap<u8, u8>,\n}\nstatic FORM: Bus = X;\n";

/// #10295: `Inner`, reached from `Bus`, gains a field.
const R3_INNER_FIELD: &str = "pub struct Inner {\n    v: Unknown,\n    w: u16,\n}\npub struct Bus {\n    tx: Inner,\n}\nstatic FORM: Bus = X;\n";

/// #10295: the static's own written type changes.
const R3_OWN_TYPE: &str = "pub struct Inner {\n    v: Unknown,\n}\npub struct Bus {\n    tx: Inner,\n}\nstatic FORM: (Bus, u8) = X;\n";

/// #10295: the pinned digest of `FORM` in [`R3_BUS`].
const D_BUS: &str = "type=ce1d7f3c src::b::Bus=364aa5fe src::b::Inner=a250aabb";

/// #10295: an exception holds only while every definition behind the
/// static is the one it was pinned against; a change names the type.
#[test]
fn exceptions_are_pinned_by_content_10295() {
    let b = "src/b.rs";
    let digest = |name: &str, ty: &str| StaticFinding::ExceptionDigest {
        file: b.into(),
        name: name.into(),
        ty: ty.into(),
    };
    let lock_body = "macro_rules! m {\n    () => {\n        static INNER: std::sync::Mutex<u8> = X;\n    };\n}\n";
    let rows: Vec<ExceptionCase<'_>> = vec![
        ("same", R3_BUS, vec![(b, "FORM", D_BUS, FORM_WHY)], vec![]),
        (
            "P14b-field-added",
            R3_BUS_FIELD,
            vec![(b, "FORM", D_BUS, FORM_WHY)],
            vec![digest("FORM", "src::b::Bus")],
        ),
        (
            "reached-definition-changed",
            R3_INNER_FIELD,
            vec![(b, "FORM", D_BUS, FORM_WHY)],
            vec![digest("FORM", "src::b::Inner")],
        ),
        (
            "own-type-changed",
            R3_OWN_TYPE,
            vec![(b, "FORM", D_BUS, FORM_WHY)],
            vec![digest("FORM", "type")],
        ),
        (
            "empty-digest",
            R3_BUS,
            vec![(b, "FORM", "", FORM_WHY)],
            vec![digest("FORM", "type")],
        ),
        (
            "macro-body-wrong-digest",
            lock_body,
            vec![(b, "INNER", "type=00000000", FORM_WHY)],
            vec![digest("INNER", "type")],
        ),
    ];
    let mut miss = Vec::new();
    for (id, text, exceptions, want) in rows {
        let files = vec![(b.to_string(), text.to_string())];
        let table = if text.contains("static FORM") {
            format!("{b}{FORM_ROW}")
        } else {
            String::new()
        };
        let tables = Tables {
            statics: &table,
            exceptions: &exceptions,
            includes: &[],
        };
        let (statics, _) = token_census_with(&files, &tables);
        if statics != want {
            miss.push(format!("{id}: got {statics:?}, want {want:?}"));
        }
    }
    assert_eq!(miss, Vec::<String>::new());
}

/// #10293: scoped resolution stays linear: a 100 000-step import rename
/// chain, a 100 000-struct type cycle, 100 000 glob imports, 100 000
/// imports of one name and 100 000 `#[path]` modules of one name are each
/// judged exactly under the ceiling.
#[test]
fn scoped_resolution_cost_is_bounded_10293() {
    const REPS: usize = 100_000;
    const CEILING_SECS: u64 = 20;
    let mut chain = String::new();
    let mut cycle = String::new();
    let mut globs = String::new();
    let mut same_use = String::new();
    let mut same_mod = String::new();
    for i in 0..REPS {
        let _ = writeln!(chain, "pub use crate::a::R{} as R{i};", i + 1);
        let _ = writeln!(cycle, "pub struct T{i}(Box<T{}>);", i + 1);
        let _ = writeln!(globs, "use crate::m{i}::*;");
        let _ = writeln!(same_use, "use crate::m{i}::Plain;");
        same_mod.push_str("#[path = \"x.rs\"]\nmod px;\n");
    }
    let _ = writeln!(chain, "pub struct R{REPS}(std::sync::Mutex<u8>);");
    let _ = writeln!(cycle, "pub struct T{REPS}(Box<T0>);");
    globs.push_str("static FORM: Plain = X;\n");
    same_use.push_str("static FORM: Plain = X;\n");
    same_mod.push_str("static FORM: px::Plain = X;\n");
    let chain: &'static str = chain.leak();
    let cycle: &'static str = cycle.leak();
    let globs: &'static str = globs.leak();
    let same_use: &'static str = same_use.leak();
    let same_mod: &'static str = same_mod.leak();
    let b = "src/b.rs";
    let cases: Vec<R3Case> = vec![
        (
            "rename-chain",
            vec![("src/a.rs", chain), (b, "static FORM: crate::a::R0 = X;\n")],
            vec![r3_lock(b, 1)],
            None,
        ),
        (
            "type-cycle",
            vec![("src/a.rs", cycle), (b, "static FORM: crate::a::T0 = X;\n")],
            vec![],
            None,
        ),
        (
            "many-globs",
            vec![(b, globs)],
            vec![r3_unres(b, REPS + 1, Why::Glob("Plain".into()))],
            None,
        ),
        (
            "one-name-imported-many-times",
            vec![(b, same_use)],
            vec![r3_unres(b, REPS + 1, Why::Ambiguous("Plain".into()))],
            None,
        ),
        (
            "one-module-name-many-path-attrs",
            vec![("src/x.rs", "pub struct Plain(u8);\n"), (b, same_mod)],
            vec![r3_unres(b, 2 * REPS + 1, Why::Ambiguous("px".into()))],
            None,
        ),
    ];
    for case in cases {
        let id = case.0;
        let start = std::time::Instant::now();
        let miss = r3_misses(vec![case]);
        let took = start.elapsed();
        assert!(
            took < std::time::Duration::from_secs(CEILING_SECS),
            "{id}: {took:?}"
        );
        assert_eq!(miss, Vec::<String>::new());
    }
}

// ---------------------------------------------------------------------------
// #10322 and #10323: a glob of a module the census did not read refuses
// every name that module does not bind itself, and `mod NAME;` links to the
// walked file by the Rust rules for the declaring file, after every file is
// read, so no verdict depends on the walk order.
// ---------------------------------------------------------------------------

/// A walked module that binds a lock type, for the #10323 link cases.
const LINKED_GATE: &str = "pub struct Gate(std::sync::Mutex<u8>);\n";

/// #10322: a glob import of an unread module (a `#[path]` module, a declared
/// module with no walked file) never supplies nothing: a name it may bind,
/// a prelude name included, is `PathNotLanded`, the refusal the same module
/// gives when named by path. A glob of a read module stays exact.
#[test]
fn unread_module_glob_refuses_10322() {
    let b = "src/b.rs";
    let x = ("src/x.rs", "pub struct Thing(u8);\n");
    let cases: Vec<R3Case> = vec![
        (
            "U1-path-module-glob-vec",
            vec![
                x,
                (
                    b,
                    "#[path = \"x.rs\"]\nmod px;\nuse px::*;\nstatic FORM: Vec<u8> = X;\n",
                ),
            ],
            vec![r3_unres(b, 4, Why::PathNotLanded("Vec".into()))],
            None,
        ),
        (
            "U2-path-module-glob-result",
            vec![
                x,
                (
                    b,
                    "#[path = \"x.rs\"]\nmod px;\nuse px::*;\nstatic FORM: Result<u8, u8> = X;\n",
                ),
            ],
            vec![r3_unres(b, 4, Why::PathNotLanded("Result".into()))],
            None,
        ),
        (
            "U3-declared-no-file-glob-vec",
            vec![(
                b,
                "mod nofile;\nuse nofile::*;\nstatic FORM: Vec<u8> = X;\n",
            )],
            vec![r3_unres(b, 3, Why::PathNotLanded("Vec".into()))],
            None,
        ),
        (
            "U4-declared-no-file-glob-result",
            vec![(
                b,
                "mod nofile;\nuse nofile::*;\nstatic FORM: Result<u8, u8> = X;\n",
            )],
            vec![r3_unres(b, 3, Why::PathNotLanded("Result".into()))],
            None,
        ),
        (
            "U5-glob-of-read-module-that-globs-unread",
            vec![
                x,
                ("src/a.rs", "#[path = \"x.rs\"]\nmod px;\npub use px::*;\n"),
                (b, "use crate::a::*;\nstatic FORM: Vec<u8> = X;\n"),
            ],
            vec![r3_unres(b, 2, Why::PathNotLanded("Vec".into()))],
            None,
        ),
        (
            "U6-control-glob-of-read-module",
            vec![
                ("src/a.rs", "pub struct Plain(u8);\n"),
                (b, "use crate::a::*;\nstatic FORM: Vec<u8> = X;\n"),
            ],
            vec![],
            None,
        ),
        (
            "U7-control-declared-no-file-by-path",
            vec![(b, "mod nofile;\nstatic FORM: nofile::Thing = X;\n")],
            vec![r3_unres(b, 2, Why::PathNotLanded("Thing".into()))],
            None,
        ),
    ];
    assert_eq!(r3_misses(cases), Vec::<String>::new());
}

/// #10323: one case run with its files in the order written and reversed.
fn both_orders(case: R3Case) -> Vec<String> {
    let (id, files, want, inc) = case;
    let mut back = files.clone();
    back.reverse();
    let fwd_id: &'static str = format!("{id}/written").leak();
    let back_id: &'static str = format!("{id}/reversed").leak();
    r3_misses(vec![
        (fwd_id, files, want.clone(), inc.clone()),
        (back_id, back, want, inc),
    ])
}

/// #10323: `mod NAME;` links to the walked file the Rust rules name for the
/// declaring file, in either walk order; a declared module whose file was
/// not walked is unread (#10322).
#[test]
fn module_link_ignores_walk_order_10323() {
    let a = "tests/a.rs";
    let cases: Vec<R3Case> = vec![
        (
            "L1-dir-mod-rs-by-name",
            vec![
                (
                    a,
                    "mod common;\nuse common::Gate;\nstatic FORM: Gate = X;\n",
                ),
                ("tests/common/mod.rs", LINKED_GATE),
            ],
            vec![r3_lock(a, 3)],
            None,
        ),
        (
            "L2-sibling-file",
            vec![
                (
                    a,
                    "mod common;\nuse common::Gate;\nstatic FORM: Gate = X;\n",
                ),
                ("tests/common.rs", LINKED_GATE),
            ],
            vec![r3_lock(a, 3)],
            None,
        ),
        (
            "L3-foo-rs-with-foo-dir-helper",
            vec![
                (
                    "tests/foo.rs",
                    "mod helper;\nuse helper::Gate;\nstatic FORM: Gate = X;\n",
                ),
                ("tests/foo/helper.rs", LINKED_GATE),
            ],
            vec![r3_lock("tests/foo.rs", 3)],
            None,
        ),
        (
            "L4-glob-of-linked-module",
            vec![
                (
                    a,
                    "mod common;\nuse common::*;\nstatic FORM: Vec<Gate> = X;\n",
                ),
                ("tests/common/mod.rs", LINKED_GATE),
            ],
            vec![r3_unres(a, 3, Why::Glob("Gate".into()))],
            None,
        ),
        (
            "L5-live-shape-glob-prelude-name",
            vec![
                (
                    a,
                    "mod common;\nuse common::*;\nstatic FORM: Vec<u8> = X;\n",
                ),
                ("tests/common/mod.rs", "pub fn helper() {}\n"),
            ],
            vec![],
            None,
        ),
        (
            "L6-nested-dir-module",
            vec![
                (
                    a,
                    "mod common;\nuse common::inner::Gate;\nstatic FORM: Gate = X;\n",
                ),
                ("tests/common/mod.rs", "pub mod inner;\n"),
                ("tests/common/inner.rs", LINKED_GATE),
            ],
            vec![r3_lock(a, 3)],
            None,
        ),
        (
            "L7-declared-module-not-walked",
            vec![
                (a, "mod gone;\nuse gone::*;\nstatic FORM: Vec<u8> = X;\n"),
                ("tests/common/mod.rs", LINKED_GATE),
            ],
            vec![r3_unres(a, 3, Why::PathNotLanded("Vec".into()))],
            None,
        ),
    ];
    let mut miss = Vec::new();
    for case in cases {
        miss.extend(both_orders(case));
    }
    assert_eq!(miss, Vec::<String>::new());
}

/// #10323 (mutant A2): `tree()` hands every census the files sorted by
/// path, strictly ascending, so no census depends on the `read_dir` order.
#[test]
fn tree_is_sorted_by_path_10323() {
    let files = tree();
    let unsorted: Vec<String> = files
        .windows(2)
        .filter(|w| w[0].0 >= w[1].0)
        .map(|w| format!("{} then {}", w[0].0, w[1].0))
        .collect();
    assert_eq!(unsorted, Vec::<String>::new());
}

/// #10323: `T` is defined in both `src/a.rs` and `src/a/mod.rs`, so its
/// node folds two bodies; `FORM` in `src/b.rs` reaches it.
const TWO_FILE_T: [(&str, &str); 3] = [
    ("src/a.rs", "pub struct T(Unknown);\n"),
    ("src/a/mod.rs", "pub struct T(Unknown, u16);\n"),
    ("src/b.rs", "use crate::a::T;\nstatic FORM: T = X;\n"),
];

/// #10323: the pinned digest of `FORM` in [`TWO_FILE_T`], taken from one
/// green run with the files in path order.
const D_TWO_FILE_T: &str = "type=bcf2301e src::a::T=5fc443f0";

/// #10295: the static findings of `files` with one exception row for
/// `FORM` in `src/b.rs` pinned at `pin`.
fn pinned_census(files: &[(&str, &str)], pin: &str) -> Vec<StaticFinding> {
    let b = "src/b.rs";
    let owned: Vec<(String, String)> = files
        .iter()
        .map(|(p, t)| ((*p).to_string(), (*t).to_string()))
        .collect();
    let table = format!("{b}{FORM_ROW}");
    let exceptions: Vec<ExceptionRow<'_>> = vec![(b, "FORM", pin, FORM_WHY)];
    let tables = Tables {
        statics: &table,
        exceptions: &exceptions,
        includes: &[],
    };
    token_census_with(&owned, &tables).0
}

/// #10323 (mutant A2): a node folded from two files keeps one digest in
/// either walk order, so its pinned exception holds in both.
#[test]
fn merged_node_digest_ignores_walk_order_10323() {
    let mut back = TWO_FILE_T.to_vec();
    back.reverse();
    let mut miss = Vec::new();
    for (id, files) in [("written", TWO_FILE_T.to_vec()), ("reversed", back)] {
        let got = pinned_census(&files, D_TWO_FILE_T);
        if !got.is_empty() {
            miss.push(format!("{id}: got {got:?}, want []"));
        }
    }
    assert_eq!(miss, Vec::<String>::new());
}

/// #10325 (mutant X1): a pinned entry the live digest no longer holds is
/// reported by its key, even when every live entry is pinned.
#[test]
fn pinned_entry_gone_from_live_digest_is_reported_10325() {
    let pin = format!("{D_BUS} src::b::Gone=0badc0de");
    let got = pinned_census(&[("src/b.rs", R3_BUS)], &pin);
    let want = vec![StaticFinding::ExceptionDigest {
        file: "src/b.rs".into(),
        name: "FORM".into(),
        ty: "src::b::Gone".into(),
    }];
    assert_eq!(got, want);
}

/// #10325 (mutant X7): a type parameter that hides a type the scope
/// itself defines is refused as shadowed.
#[test]
fn parameter_hiding_a_bound_name_is_shadowed_10325() {
    let b = "src/b.rs";
    let cases: Vec<R3Case> = vec![(
        "X7-param-hides-local-struct",
        vec![(
            b,
            "pub struct Plain(u8);\nstruct Wrap<Plain>(Plain);\nstatic FORM: Wrap<u8> = X;\n",
        )],
        vec![r3_unres(b, 3, Why::Shadowed("Plain".into()))],
        None,
    )];
    assert_eq!(r3_misses(cases), Vec::<String>::new());
}

/// #10325 (mutant X8): an import first resolved while the globs are being
/// settled (here by the glob of `src/e.rs`, while the glob of `src/b.rs` is
/// not settled and so may supply any name) is resolved again once every
/// glob is settled: `crate::d` binds no `Mutex`, so the bare `Mutex` that
/// `Gate` renames is the lock.
#[test]
fn import_through_glob_resolves_after_settle_10325() {
    let b = "src/b.rs";
    let cases: Vec<R3Case> = vec![(
        "X8-import-resolved-again-after-settle",
        vec![
            ("src/d.rs", "pub struct Other(u8);\n"),
            ("src/e.rs", "use crate::b::Gate::*;\n"),
            (
                b,
                "use crate::d::*;\nuse Mutex as Gate;\nstatic FORM: Gate = X;\n",
            ),
        ],
        vec![r3_lock(b, 3)],
        None,
    )];
    assert_eq!(r3_misses(cases), Vec::<String>::new());
}

/// #10324: the scope visits of the glob resolver over a chain of `n` walked
/// modules, each globbing the next and writing `static FORM: Plain`, the
/// last binding `Plain`, and one hub module globbing every link. Every
/// static is judged exactly: `Plain` is glob-supplied in each of them.
/// With `cycle` the last module globs the first instead and nothing binds
/// `Plain`: a glob cycle with no definition, where every bare `Plain` has
/// no definition.
fn glob_chain_visits(n: usize, cycle: bool) -> u64 {
    let mut files: Vec<(String, String)> = Vec::with_capacity(n + 2);
    let mut paths: Vec<String> = Vec::with_capacity(n);
    let mut hub = String::new();
    for i in 0..n {
        let path = format!("src/m{i}.rs");
        let next = i + 1;
        files.push((
            path.clone(),
            format!("use crate::m{next}::*;\nstatic FORM: Plain = X;\n"),
        ));
        paths.push(path);
        let _ = writeln!(hub, "use crate::m{i}::*;");
    }
    let (last, why) = if cycle {
        ("use crate::m0::*;\n", Why::NoDef("Plain".into()))
    } else {
        ("pub struct Plain(u8);\n", Why::Glob("Plain".into()))
    };
    files.push((format!("src/m{n}.rs"), last.to_string()));
    hub.push_str("static FORM: Plain = X;\n");
    files.push(("src/hub.rs".to_string(), hub));
    let mut want: Vec<String> = paths
        .iter()
        .map(|p| format!("{:?}", r3_unres(p, 2, why.clone())))
        .collect();
    want.push(format!("{:?}", r3_unres("src/hub.rs", n + 1, why)));
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let (statics, includes, visits) = r3_census_counted(&refs);
    let mut got: Vec<String> = statics.iter().map(|f| format!("{f:?}")).collect();
    got.sort();
    want.sort();
    assert_eq!(got, want, "glob chain of {n} modules, cycle {cycle}");
    assert_eq!(
        includes,
        no_store_url(),
        "glob chain of {n} modules, cycle {cycle}"
    );
    visits
}

/// #10324: each scope's glob closure is walked once, not once per lookup:
/// at four times the modules of a glob chain with fan-out, the resolver
/// makes at most four times the scope visits, plus a constant, for a chain
/// that ends in a definition and for a glob cycle with none. The bound is
/// on operation counts, never on wall-clock time.
#[test]
fn glob_chain_resolution_cost_is_linear_10324() {
    const CHAIN_SMALL: usize = 250;
    const GROWTH: usize = 4;
    const SLACK: u64 = 64;
    let growth = u64::try_from(GROWTH).expect("GROWTH fits u64");
    let floor = u64::try_from(CHAIN_SMALL).expect("CHAIN_SMALL fits u64");
    for cycle in [false, true] {
        let small = glob_chain_visits(CHAIN_SMALL, cycle);
        let large = glob_chain_visits(CHAIN_SMALL * GROWTH, cycle);
        // Each static is looked up through at least one glob: a counter
        // that counts nothing proves nothing.
        assert!(
            small >= floor,
            "cycle {cycle}: glob visits: {small} at {CHAIN_SMALL} modules"
        );
        assert!(
            large <= growth * small + SLACK,
            "cycle {cycle}: glob visits: {small} at {CHAIN_SMALL} modules, {large} at {} modules",
            CHAIN_SMALL * GROWTH
        );
    }
}

/// #10324: a cycle of globs terminates and resolves as before. Through the
/// cycle `ca` <-> `cb`, with `cb` globbing `cd` that binds `Plain`, both
/// statics are glob-supplied; the cycle `ce` <-> `cf` binds no `Plain`, so
/// its bare `Plain` has no definition and its bare `Mutex` is the lock; `cg`
/// globs `ch`, which binds no `Plain`. One name looked up from scopes whose
/// glob closures differ resolves per scope.
#[test]
fn glob_cycle_terminates_and_resolves_10324() {
    let cases: Vec<R3Case> = vec![(
        "glob-cycles",
        vec![
            ("src/ca.rs", "use crate::cb::*;\nstatic FORM: Plain = X;\n"),
            (
                "src/cb.rs",
                "use crate::ca::*;\nuse crate::cd::*;\nstatic FORM: Plain = X;\n",
            ),
            ("src/cd.rs", "pub struct Plain(u8);\n"),
            ("src/ce.rs", "use crate::cf::*;\nstatic FORM: Plain = X;\n"),
            ("src/cf.rs", "use crate::ce::*;\nstatic FORM: Mutex = X;\n"),
            ("src/cg.rs", "use crate::ch::*;\nstatic FORM: Plain = X;\n"),
            ("src/ch.rs", "pub struct Other(u8);\n"),
        ],
        vec![
            r3_unres("src/ca.rs", 2, Why::Glob("Plain".into())),
            r3_unres("src/cb.rs", 3, Why::Glob("Plain".into())),
            r3_unres("src/ce.rs", 2, Why::NoDef("Plain".into())),
            r3_lock("src/cf.rs", 2),
            r3_unres("src/cg.rs", 2, Why::NoDef("Plain".into())),
        ],
        None,
    )];
    assert_eq!(r3_misses(cases), Vec::<String>::new());
}
