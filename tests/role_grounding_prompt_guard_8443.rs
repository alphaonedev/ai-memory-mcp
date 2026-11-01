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

/// `(name, body)` for every `const NAME: &str = ...;` in `text`.
fn str_consts(text: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("const ") {
        let after = &rest[i + "const ".len()..];
        rest = after;
        let Some(colon) = after.find(": &str") else {
            continue;
        };
        let name = after[..colon].trim();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        let Some(eq) = after[colon..].find('=') else {
            continue;
        };
        let body_start = colon + eq + 1;
        let tail = &after[body_start..];
        // A const ends at the closing quote and semicolon, the raw-string
        // form, or the closing line of a `concat!(...)` call.
        let Some(end) = ["\";", "\"#;", "\n);"]
            .iter()
            .filter_map(|t| tail.find(t))
            .min()
        else {
            continue;
        };
        found.push((
            name.to_string(),
            after[body_start..body_start + end].to_string(),
        ));
    }
    found
}

fn is_exempt(file: &Path, name: &str) -> bool {
    let p = file.to_string_lossy().replace('\\', "/");
    EXEMPT
        .iter()
        .any(|(suffix, n, _)| *n == name && p.ends_with(&format!("src/{suffix}")))
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
        for (name, body) in str_consts(&non_test_region(&text)) {
            if !is_prompt_bearing(&name, &body) {
                continue;
            }
            if body.contains(PLACEHOLDER) || body.contains("role_grounding_placeholder!") {
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
        for (name, body) in str_consts(&non_test_region(&text)) {
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
