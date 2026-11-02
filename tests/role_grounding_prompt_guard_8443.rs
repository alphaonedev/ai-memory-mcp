// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8443 (arXiv 2610.38209) - prompt coverage guard.
//!
//! Every prompt that forms or rewrites a memory must carry the shared
//! role-grounding block, so a new formation prompt cannot ship without it.
//!
//! Detector (source scan, no compilation of the scanned files): in the
//! non-test region of every `src/**/*.rs` file, find each `const NAME: &str =
//! "...";` item. A const is PROMPT-BEARING when its name ends with `_PROMPT` or
//! `_SYSTEM`, or its text contains `You are `. A prompt-bearing const must
//! contain the `{role_grounding}` placeholder, or be listed in [`EXEMPT`]
//! with the reason it never forms memory content. Inline prompt literals that
//! are not consts are pinned in [`INLINE_GROUNDED`] and must reference the
//! `role_grounding` module. The set of grounded consts is pinned in
//! [`GROUNDED`]; adding or removing one is a deliberate edit of this list.
//! This is a text scan: a prompt assembled from `format!` pieces in a
//! function body is covered only through [`INLINE_GROUNDED`].

use std::fs;
use std::path::{Path, PathBuf};

const PLACEHOLDER: &str = "{role_grounding}";

/// Consts that carry the block, pinned.
const GROUNDED: &[&str] = &[
    "CURATOR_SYSTEM_PROMPT",
    "SUMMARIZE_PROMPT",
    "SYNTHESIS_SYSTEM",
];

/// Inline prompt literals: (file suffix, marker that must appear in the file).
const INLINE_GROUNDED: &[(&str, &str)] = &[("multistep_ingest/cache.rs", "role_grounding::")];

/// Minimum length of a trimmed exemption reason.
const MIN_REASON_CHARS: usize = 20;

/// Words that are not a reason.
const PLACEHOLDER_REASONS: &[&str] = &["todo", "tbd", "none", "n/a", "na", "fixme", "xxx", "wip"];

/// Prompt-bearing consts that never form memory content: (file suffix under
/// `src/`, const name, reason). Keyed by file AND name, so a same-named const
/// in another file is not silently exempt.
const EXEMPT: &[(&str, &str, &str)] = &[
    (
        "llm.rs",
        "QUERY_EXPANSION_PROMPT",
        "read-side query rewrite, writes nothing to the store",
    ),
    (
        "llm.rs",
        "CLASSIFY_KIND_SYSTEM",
        "closed-vocabulary label output, no free text stored",
    ),
    (
        "llm.rs",
        "CONTRADICTION_PROMPT",
        "yes or no verdict only, no content stored",
    ),
    (
        "llm.rs",
        "AUTO_TAG_PROMPT",
        "short tags only, no memory content stored",
    ),
    (
        "storage/mod.rs",
        "WHY_TRACE_SUBSTRATE_SYSTEM",
        "provenance marker string, never sent to a model",
    ),
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `text` with every `#[cfg(test)] mod name { ... }` block removed. Only the
/// braced test module is dropped, so production code that follows it (or a
/// `#[cfg(test)]` on a single item) stays in the scanned region.
fn non_test_region(text: &str) -> String {
    // `all(test, feature = "sal")` gates a test module too.
    const MARKS: [&str; 2] = ["#[cfg(test)]", "#[cfg(all(test, feature = \"sal\"))]"];
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((i, mark)) = MARKS
        .iter()
        .filter_map(|m| rest.find(m).map(|i| (i, *m)))
        .min_by_key(|(i, _)| *i)
    {
        out.push_str(&rest[..i]);
        let after = &rest[i + mark.len()..];
        let head = after.trim_start();
        let is_mod = head.starts_with("mod ") || head.starts_with("pub mod ");
        let brace = head.find(['{', ';']);
        match (is_mod, brace) {
            (true, Some(b)) if head.as_bytes()[b] == b'{' => {
                let body = &head[b..];
                let mut depth = 0usize;
                let mut end = body.len();
                for (k, c) in body.char_indices() {
                    if c == '{' {
                        depth += 1;
                    } else if c == '}' {
                        depth -= 1;
                        if depth == 0 {
                            end = k + 1;
                            break;
                        }
                    }
                }
                rest = &body[end..];
            }
            _ => {
                // A `#[cfg(test)]` on some other item: keep scanning after it.
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The item keywords whose items are scanned: `const` and `static` both
/// declare an item a prompt can live in.
const ITEM_KEYWORDS: [&str; 2] = ["const", "static"];

/// The string types a prompt item is normally declared with.
const STR_TYPES: [&str; 2] = ["&str", "&'static str"];

/// One `const` / `static` item: its name, its declared type text and the body
/// text up to (not including) the first top-level semicolon.
struct Item {
    name: String,
    ty: String,
    body: String,
}

impl Item {
    fn is_str(&self) -> bool {
        STR_TYPES.contains(&self.ty.trim())
    }
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Byte offset just past the string literal that starts at `i` (a `"`), or the
/// end of input when it never closes.
fn skip_string(b: &[u8], i: usize) -> usize {
    let mut k = i + 1;
    while k < b.len() {
        match b[k] {
            b'\\' => k += 2,
            b'"' => return k + 1,
            _ => k += 1,
        }
    }
    b.len()
}

/// Byte offset just past the raw string literal whose `r` is at `i`, or `None`
/// when `r` does not start a raw string.
fn skip_raw_string(b: &[u8], i: usize) -> Option<usize> {
    if i > 0 && is_ident_byte(b[i - 1]) && b[i - 1] != b'b' {
        return None;
    }
    let mut k = i + 1;
    let mut hashes = 0usize;
    while k < b.len() && b[k] == b'#' {
        hashes += 1;
        k += 1;
    }
    if k >= b.len() || b[k] != b'"' {
        return None;
    }
    k += 1;
    while k < b.len() {
        let close = k + 1 + hashes;
        if b[k] == b'"' && close <= b.len() && b[k + 1..close].iter().all(|&c| c == b'#') {
            return Some(close);
        }
        k += 1;
    }
    Some(b.len())
}

/// Offset of the first top-level `;` in `s`: outside string, raw-string and
/// char literals, outside comments, and outside any bracket pair.
fn body_end(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut depth = 0i32;
    while i < b.len() {
        match b[i] {
            b'"' => {
                i = skip_string(b, i);
                continue;
            }
            b'r' => {
                if let Some(next) = skip_raw_string(b, i) {
                    i = next;
                    continue;
                }
            }
            b'\'' => {
                if b.get(i + 1) == Some(&b'\\') {
                    if let Some(off) = b[i + 2..].iter().position(|&c| c == b'\'') {
                        i += 2 + off + 1;
                        continue;
                    }
                } else if let Some(ch) = s[i + 1..].chars().next()
                    && b.get(i + 1 + ch.len_utf8()) == Some(&b'\'')
                {
                    i += 1 + ch.len_utf8() + 1;
                    continue;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
                continue;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b';' if depth <= 0 => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Every `const` / `static` item with an upper-case name in `text`, of ANY
/// type. Any ASCII whitespace may follow the keyword, and the body ends at the
/// first top-level semicolon, so a literal that contains `";`, a `concat!`, a
/// closure or a block cannot cut the body short or hide the placeholder.
fn items(text: &str) -> Vec<Item> {
    let b = text.as_bytes();
    let mut found = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let Some(kw) = ITEM_KEYWORDS.iter().find(|k| {
            b[i..].starts_with(k.as_bytes())
                && (i == 0 || !is_ident_byte(b[i - 1]))
                && b.get(i + k.len()).is_some_and(u8::is_ascii_whitespace)
        }) else {
            i += 1;
            continue;
        };
        let mut k = i + kw.len();
        i = k;
        while b.get(k).is_some_and(u8::is_ascii_whitespace) {
            k += 1;
        }
        if b[k..].starts_with(b"mut") && b.get(k + 3).is_some_and(u8::is_ascii_whitespace) {
            k += 3;
            while b.get(k).is_some_and(u8::is_ascii_whitespace) {
                k += 1;
            }
        }
        let name_start = k;
        while b.get(k).is_some_and(|c| is_ident_byte(*c)) {
            k += 1;
        }
        let name = &text[name_start..k];
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        while b.get(k).is_some_and(u8::is_ascii_whitespace) {
            k += 1;
        }
        if b.get(k) != Some(&b':') {
            continue;
        }
        let ty_start = k + 1;
        let Some(eq) = text[ty_start..].find(['=', ';']) else {
            continue;
        };
        if b[ty_start + eq] != b'=' {
            continue;
        }
        let ty = &text[ty_start..ty_start + eq];
        let body_start = ty_start + eq + 1;
        let Some(end) = body_end(&text[body_start..]) else {
            continue;
        };
        found.push(Item {
            name: name.to_string(),
            ty: ty.trim().to_string(),
            body: text[body_start..body_start + end].to_string(),
        });
        i = body_start;
    }
    found
}

/// `(name, body)` for every `const`/`static` item of type `&str` or
/// `&'static str` in `text`.
fn str_consts(text: &str) -> Vec<(String, String)> {
    items(text)
        .into_iter()
        .filter(Item::is_str)
        .map(|it| (it.name, it.body))
        .collect()
}

/// A prompt item is grounded when its body carries the placeholder, the
/// placeholder macro, or calls into the `role_grounding` module.
fn is_grounded(body: &str) -> bool {
    body.contains(PLACEHOLDER)
        || body.contains("role_grounding_placeholder!")
        || body.contains("role_grounding::")
}

fn is_exempt(file: &Path, name: &str) -> bool {
    let p = file.to_string_lossy().replace('\\', "/");
    EXEMPT
        .iter()
        .any(|(suffix, n, _)| *n == name && p.ends_with(&format!("/src/{suffix}")))
}

fn is_prompt_bearing(name: &str, body: &str) -> bool {
    name.ends_with("_PROMPT")
        || name.ends_with("_SYSTEM")
        || name == "SYSTEM_PROMPT"
        || body.contains("You are ")
}

#[test]
fn every_prompt_const_carries_the_role_grounding_block_8443() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut missing = Vec::new();
    let mut grounded = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("read source");
        for Item { name, body, .. } in items(&non_test_region(&text)) {
            if !is_prompt_bearing(&name, &body) {
                continue;
            }
            if is_grounded(&body) {
                grounded.push(name);
            } else if !is_exempt(file, &name) {
                missing.push(format!("{} ({})", name, file.display()));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "prompt consts without the {PLACEHOLDER} block (add it or list the const in EXEMPT with a reason): {missing:?}"
    );
    grounded.sort();
    grounded.dedup();
    assert_eq!(
        grounded,
        GROUNDED.to_vec(),
        "the set of grounded prompt consts changed; update GROUNDED deliberately"
    );
}

#[test]
fn inline_prompt_literals_reference_the_role_grounding_module_8443() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for (suffix, marker) in INLINE_GROUNDED {
        let path = src.join(suffix);
        let text = fs::read_to_string(&path).expect("read inline prompt source");
        assert!(
            non_test_region(&text).contains(marker),
            "{suffix} builds an inline prompt and must reference {marker}"
        );
    }
}

#[test]
fn exempt_entries_still_exist_and_are_prompt_bearing_8443() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut found: Vec<(PathBuf, String)> = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("read source");
        for Item { name, body, .. } in items(&non_test_region(&text)) {
            if is_prompt_bearing(&name, &body) {
                found.push((file.clone(), name));
            }
        }
    }
    for (suffix, exempt, _) in EXEMPT {
        assert!(
            found
                .iter()
                .any(|(f, n)| n == exempt && is_exempt(f, n) && f.ends_with(suffix)),
            "stale EXEMPT entry {suffix}::{exempt}: remove it from the list"
        );
    }
}

#[test]
fn exempt_reasons_are_real_and_unique_8443() {
    let mut seen: Vec<String> = Vec::new();
    for (suffix, name, reason) in EXEMPT {
        let r = reason.trim();
        assert!(
            r.chars().count() >= MIN_REASON_CHARS,
            "{suffix}::{name}: reason shorter than {MIN_REASON_CHARS} characters"
        );
        assert!(
            !PLACEHOLDER_REASONS.contains(&r.to_ascii_lowercase().as_str()),
            "{suffix}::{name}: placeholder reason"
        );
        assert!(
            !seen.iter().any(|s| s == r),
            "{suffix}::{name}: reason duplicated across entries"
        );
        seen.push(r.to_string());
    }
}

#[test]
fn non_test_region_strips_only_the_test_module_8443() {
    let text = "const A: &str = \"a\";\n#[cfg(test)]\nmod tests {\n    const B: &str = \"b\";\n    fn f() { if true { } }\n}\nconst C: &str = \"c\";\n";
    let kept = non_test_region(text);
    assert!(kept.contains("const A"));
    assert!(
        kept.contains("const C"),
        "code after the test module is scanned"
    );
    assert!(!kept.contains("const B"));
    let single = "#[cfg(test)]\nconst T: &str = \"t\";\nconst D: &str = \"d\";\n";
    assert!(non_test_region(single).contains("const D"));
}

fn names_of(text: &str) -> Vec<String> {
    str_consts(text).into_iter().map(|(n, _)| n).collect()
}

/// #8443 round 3 (sec LOW-1): one self-test per declaration shape, so a prompt
/// declared as a `static`, with an explicit `'static` lifetime, or with a
/// visibility modifier cannot slip past the scan.
#[test]
fn str_consts_finds_every_declaration_shape_8443() {
    let shapes = [
        ("const A_PROMPT: &str = \"x\";", "A_PROMPT"),
        ("const B_PROMPT: &'static str = \"x\";", "B_PROMPT"),
        ("static C_PROMPT: &str = \"x\";", "C_PROMPT"),
        ("static D_PROMPT: &'static str = \"x\";", "D_PROMPT"),
        ("pub const E_SYSTEM: &str = \"x\";", "E_SYSTEM"),
        (
            "pub(crate) static F_SYSTEM: &'static str = \"x\";",
            "F_SYSTEM",
        ),
        ("const G_PROMPT: &str = r#\"x\"#;", "G_PROMPT"),
        (
            "const H_PROMPT: &'static str = concat!(\n\"x\",\n);",
            "H_PROMPT",
        ),
    ];
    for (text, name) in shapes {
        assert_eq!(
            names_of(text),
            vec![name.to_string()],
            "shape not found: {text}"
        );
    }
    // Non-string items and fn signatures are not prompt items.
    assert_eq!(
        names_of("const N: usize = 4;\nfn f(x: &str) -> &str { x }"),
        Vec::<String>::new()
    );
}

/// #8443 round 4 (code L8): any whitespace may follow the keyword.
#[test]
fn items_accept_any_whitespace_after_the_keyword_8443() {
    let shapes = [
        ("const\tT_PROMPT: &str = \"x\";", "T_PROMPT"),
        ("const\n    N_PROMPT: &str = \"x\";", "N_PROMPT"),
        ("static  \t S_SYSTEM: &str = \"x\";", "S_SYSTEM"),
        ("pub(crate)   const   W_PROMPT : &str = \"x\";", "W_PROMPT"),
        ("static mut  M_PROMPT: &str = \"x\";", "M_PROMPT"),
    ];
    for (text, name) in shapes {
        assert_eq!(
            names_of(text),
            vec![name.to_string()],
            "shape not found: {text}"
        );
    }
}

/// #8443 round 4 (code L8): the body ends at the first TOP-LEVEL semicolon, so
/// a literal that contains `";`, a `concat!` or a raw string cannot cut it short.
#[test]
fn item_body_ends_at_the_first_top_level_semicolon_8443() {
    let cut =
        "const A_PROMPT: &str = \"head \\\"; {role_grounding} tail\";\nconst B: &str = \"b\";";
    let all = str_consts(cut);
    assert_eq!(all.len(), 2, "both items are found: {all:?}");
    assert!(
        is_grounded(&all[0].1),
        "an escaped quote and semicolon inside the literal must not end the body: {:?}",
        all[0].1
    );
    let raw = "const R_PROMPT: &str = r#\"a \"; {role_grounding} b\"#;";
    assert!(is_grounded(&str_consts(raw)[0].1), "raw string body");
    let cat = "const C_PROMPT: &str = concat!(\"a; \", \"{role_grounding}\");";
    assert!(is_grounded(&str_consts(cat)[0].1), "concat! body");
    let blk = "const G_PROMPT: &str = { let a = 1; \"{role_grounding}\" };";
    assert!(
        is_grounded(&str_consts(blk)[0].1),
        "a semicolon inside a block must not end the body"
    );
    let chr = "const D_PROMPT: &str = \"x\";\nstatic E: char = ';';\nconst F_PROMPT: &str = \"y\";";
    let names: Vec<String> = items(chr).into_iter().map(|i| i.name).collect();
    assert_eq!(names, vec!["D_PROMPT", "E", "F_PROMPT"], "char literal ';'");
}

/// #8443 round 4 (code L8 / sec LOW-5): a prompt item that is not a `&str`
/// literal (a `LazyLock<String>`, a `fn` pointer, a `&[&str]`) is still seen
/// and must be grounded or exempt.
#[test]
fn non_literal_prompt_items_are_scanned_8443() {
    let text = "static L_PROMPT: LazyLock<String> = LazyLock::new(|| format!(\"a; {}\", 1));\n\
                const F_SYSTEM: fn() -> String = build;\n\
                const S_PROMPT: &[&str] = &[\"a\", \"b; c\"];\n\
                static G_PROMPT: LazyLock<String> = LazyLock::new(|| role_grounding::block());";
    let found = items(text);
    let names: Vec<&str> = found.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, vec!["L_PROMPT", "F_SYSTEM", "S_PROMPT", "G_PROMPT"]);
    assert!(found.iter().all(|i| !i.is_str()), "none is a &str item");
    assert!(!is_grounded(&found[0].body), "ungrounded lazy prompt");
    assert!(!is_grounded(&found[1].body), "ungrounded fn prompt");
    assert!(!is_grounded(&found[2].body), "ungrounded slice prompt");
    assert!(is_grounded(&found[3].body), "calls role_grounding::");
}

/// #8443 round 4 (code I2): across `src/`, no `*_PROMPT` / `*_SYSTEM` item has a
/// type other than `&str` unless it is grounded or exempt; a prompt cannot dodge
/// the scan by changing its type.
#[test]
fn no_prompt_named_item_has_a_non_str_type_unless_grounded_8443() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut bad = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("read source");
        for it in items(&non_test_region(&text)) {
            let named = it.name.ends_with("_PROMPT") || it.name.ends_with("_SYSTEM");
            if named && !it.is_str() && !is_grounded(&it.body) && !is_exempt(file, &it.name) {
                bad.push(format!("{} ({}) : {}", it.name, file.display(), it.ty));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "non-&str prompt items without the block (ground them or list them in EXEMPT): {bad:?}"
    );
}

/// #8443 round 3 (code INFO-I): an exemption is keyed by file AND name, so a
/// same-named const in a different file is still reported.
#[test]
fn exempt_is_keyed_by_file_and_name_8443() {
    let name = "QUERY_EXPANSION_PROMPT";
    assert!(is_exempt(Path::new("/repo/src/llm.rs"), name));
    assert!(
        !is_exempt(Path::new("/repo/src/other.rs"), name),
        "other file is not exempt"
    );
    assert!(
        !is_exempt(Path::new("/repo/src/deep/llm.rs"), name),
        "a nested llm.rs is not exempt"
    );
    assert!(
        !is_exempt(Path::new("/repo/mysrc/llm.rs"), name),
        "a look-alike dir is not exempt"
    );
    assert!(!is_exempt(
        Path::new("/repo/src/llm.rs"),
        "SOME_OTHER_PROMPT"
    ));
}

/// Security L1 class lock: an `AutonomyLlm` impl that overrides
/// `summarize_memories` must also override `summarize_memories_grounded`;
/// otherwise the trait default silently drops the owner and the block.
#[test]
fn autonomy_llm_impls_forward_the_grounded_summariser_8443() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut bad = Vec::new();
    let mut seen = 0usize;
    for file in &files {
        let text = non_test_region(&fs::read_to_string(file).expect("read source"));
        for chunk in text.split("impl AutonomyLlm for ").skip(1) {
            seen += 1;
            let end = chunk.find("\nimpl ").unwrap_or(chunk.len());
            let block = &chunk[..end];
            if block.contains("fn summarize_memories(")
                && !block.contains("fn summarize_memories_grounded(")
            {
                bad.push(file.display().to_string());
            }
        }
    }
    assert!(seen > 0, "no AutonomyLlm impl found; the scan is stale");
    assert!(
        bad.is_empty(),
        "impls missing the grounded override: {bad:?}"
    );
}
