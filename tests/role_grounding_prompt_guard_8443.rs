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

/// Prompt-bearing consts that never form memory content, with the reason.
const EXEMPT: &[(&str, &str)] = &[
    (
        "QUERY_EXPANSION_PROMPT",
        "read-side query rewrite, writes nothing",
    ),
    (
        "CLASSIFY_KIND_SYSTEM",
        "closed-vocabulary label, no free text stored",
    ),
    ("CONTRADICTION_PROMPT", "yes/no verdict, no content stored"),
    ("AUTO_TAG_PROMPT", "tags only, no content stored"),
    (
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

/// Source text before the first test module marker.
fn non_test_region(text: &str) -> &str {
    text.find("#[cfg(test)]").map_or(text, |i| &text[..i])
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
        for (name, body) in str_consts(non_test_region(&text)) {
            if !is_prompt_bearing(&name, &body) {
                continue;
            }
            if body.contains(PLACEHOLDER) || body.contains("role_grounding_placeholder!") {
                grounded.push(name);
            } else if !EXEMPT.iter().any(|(n, _)| *n == name) {
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
    let mut names = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("read source");
        for (name, body) in str_consts(non_test_region(&text)) {
            if is_prompt_bearing(&name, &body) {
                names.push(name);
            }
        }
    }
    for (exempt, reason) in EXEMPT {
        assert!(!reason.is_empty());
        assert!(
            names.iter().any(|n| n == exempt),
            "stale EXEMPT entry {exempt}: remove it from the list"
        );
    }
}
