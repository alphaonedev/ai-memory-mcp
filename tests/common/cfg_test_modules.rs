// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4200 — ONE resolver for "which `src/` files are test-only", shared by
//! every Rust structural gate that scans `src/`: B7 (#4149) and the #2445
//! raw-open funnel ceiling. Each gate once read files standalone and
//! trusted only an in-file `#[cfg(test)]`. So an out-of-line module declared
//! test-only by its PARENT (`#[cfg(test)] mod owner_gate_txn_3957;`) was
//! scanned as production, first by B7 (#4149) and then by #2445 (#4200). Two
//! copies of this rule could disagree, which is how the second gate stayed
//! red after the first was fixed. Included with `#[path]`, never copied.

#![allow(dead_code)]

use std::collections::HashSet;

/// Whether a `#[cfg(...)]` attribute makes its item TEST-ONLY: `cfg(test)`,
/// or `cfg(all(..))` with `test` as a top-level member. `any(test, ..)` and
/// `not(test)` are production. Erring here scans more, which can only
/// false-red a gate, never hide production code.
pub fn cfg_requires_test(attr: &str) -> bool {
    let Some(pred) = attr
        .strip_prefix("#[cfg(")
        .and_then(|r| r.strip_suffix(")]"))
    else {
        return false;
    };
    let pred = pred.trim();
    if pred == "test" {
        return true;
    }
    let Some(inner) = pred.strip_prefix("all(").and_then(|r| r.strip_suffix(')')) else {
        return false;
    };
    let (mut depth, mut member, mut members) = (0i32, String::new(), Vec::new());
    for c in inner.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                members.push(std::mem::take(&mut member));
                continue;
            }
            _ => {}
        }
        member.push(c);
    }
    members.push(member);
    members.iter().any(|m| m.trim() == "test")
}

/// Strip a leading visibility modifier from a trimmed declaration line.
fn strip_visibility(t: &str) -> &str {
    if t.starts_with("pub(") {
        return t.find(')').map_or(t, |close| t[close + 1..].trim_start());
    }
    t.strip_prefix("pub ").map_or(t, str::trim_start)
}

/// #4149 — the files that are compiled ONLY under `cfg(test)` because their
/// MODULE DECLARATION says so: `#[cfg(test)]` immediately followed by an
/// out-of-line `mod NAME;` (any visibility) in a parent file. Test-ness is
/// decided by the DECLARATION, never by a test-looking file name (the #4054
/// rule: a name proves nothing, and an undeclared file is production). A
/// declared test-only module's own children are test-only too.
///
/// `files` are `(rel path under the crate root, source)` pairs; the result
/// holds rel paths such as `src/store/sqlite/owner_gate_txn_3957.rs`.
pub fn cfg_test_declared_files(files: &[(String, String)]) -> HashSet<String> {
    let known: HashSet<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    let mut out: HashSet<String> = HashSet::new();
    for (rel, src) in files {
        // The directory a child module of `rel` lives in.
        let dir =
            if rel.ends_with("/mod.rs") || rel.ends_with("/lib.rs") || rel.ends_with("/main.rs") {
                rel.rsplit_once('/')
                    .map_or_else(String::new, |(d, _)| d.to_string())
            } else {
                rel.trim_end_matches(".rs").to_string()
            };
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !cfg_requires_test(line.trim()) {
                continue;
            }
            let Some(next) = lines
                .iter()
                .skip(i + 1)
                .map(|l| l.trim())
                .find(|l| !l.is_empty())
            else {
                continue;
            };
            let decl = strip_visibility(next);
            let Some(rest) = decl.strip_prefix("mod ") else {
                continue;
            };
            let Some(name) = rest.strip_suffix(';') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            for cand in [format!("{dir}/{name}.rs"), format!("{dir}/{name}/mod.rs")] {
                if known.contains(cand.as_str()) {
                    out.insert(cand);
                }
            }
        }
    }
    // Children of a test-only module are test-only: a file under the
    // module's directory (`src/a/x.rs` declared -> `src/a/x/**`).
    let roots: Vec<String> = out
        .iter()
        .map(|p| {
            p.trim_end_matches("/mod.rs")
                .trim_end_matches(".rs")
                .to_string()
                + "/"
        })
        .collect();
    for (rel, _) in files {
        if roots.iter().any(|r| rel.starts_with(r.as_str())) {
            out.insert(rel.clone());
        }
    }
    out
}
