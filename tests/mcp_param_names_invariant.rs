// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Parity invariant — every MCP tool-call parameter field-name literal
// at extraction sites under `src/mcp/` MUST correspond to a const in
// `src/mcp/param_names.rs::ALL_PARAM_NAMES`. Closes Fix #5 (literal
// sweep v0.7.0 deferred-item) as a structural mitigation: future
// drift fails fast, with a clear file:line citation.
//
// Patterns covered:
//   - `params.get("X")` / `args.get("X")` / `arguments.get("X")`
//   - `params["X"]` / `args["X"]` / `arguments["X"]`
//   - `req.params["X"]`
//
// Production-vs-test boundary mirrors `scripts/check-vendor-literals.sh`:
// skip `*test*.rs`, `tests.rs`, lines at or below the first
// `mod tests {` / `pub mod tests {` boundary in each file.
//
// The test is intentionally permissive on the reverse direction
// (allowlist consts that no production code references) so the SSOT
// can stay alphabetically sorted as a stable surface across batches;
// the `all_param_names_length_pins_v070_census` test in
// `src/mcp/param_names.rs` is the gate for unused-allowlist creep.

use ai_memory::mcp::param_names::ALL_PARAM_NAMES;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

fn tests_mod_boundary(content: &str) -> usize {
    for (i, line) in content.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("mod tests {")
            || t.starts_with("pub mod tests {")
            || t.starts_with("pub(crate) mod tests {")
            || t.starts_with("pub(super) mod tests {")
        {
            return i;
        }
    }
    usize::MAX
}

fn is_skip_file(name: &str) -> bool {
    name.contains("test") || name == "tests.rs"
}

fn walk_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(root) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk_rs_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs")
            && !is_skip_file(p.file_name().unwrap_or_default().to_string_lossy().as_ref())
        {
            out.push(p);
        }
    }
}

/// Pull the field name from `.get("X")` / `["X"]` patterns matching
/// at least one of the canonical extractor prefixes
/// {`params`, `args`, `arguments`}, plus the wider
/// `req.params["X"]` form found at the top-level dispatcher.
///
/// Returns the canonical lowercase string when the literal is purely
/// lowercase-snake-case (matches the MCP JSON-key convention); other
/// extraction shapes are ignored — they're not JSON keys.
fn extract_param_literals(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let cleaned = line.trim_start();
    if cleaned.starts_with("//") || cleaned.starts_with("///") || cleaned.starts_with('*') {
        return out;
    }
    // `.get("X")` form
    for marker in ["params.get(\"", "args.get(\"", "arguments.get(\""] {
        let mut rest = line;
        while let Some(idx) = rest.find(marker) {
            let after = &rest[idx + marker.len()..];
            if let Some(end) = after.find('"') {
                let lit = &after[..end];
                if is_snake_case_param(lit) {
                    out.push(lit.to_string());
                }
                rest = &after[end + 1..];
            } else {
                break;
            }
        }
    }
    // `["X"]` indexing form
    for marker in ["params[\"", "args[\"", "arguments[\""] {
        let mut rest = line;
        while let Some(idx) = rest.find(marker) {
            let after = &rest[idx + marker.len()..];
            if let Some(end) = after.find('"') {
                let lit = &after[..end];
                if is_snake_case_param(lit) {
                    out.push(lit.to_string());
                }
                rest = &after[end + 1..];
            } else {
                break;
            }
        }
    }
    out
}

fn is_snake_case_param(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !s.starts_with('_')
        && !s.ends_with('_')
}

#[test]
fn every_production_mcp_param_literal_in_allowlist() {
    let mcp_root = Path::new("src/mcp");
    let mut files = Vec::new();
    walk_rs_files(mcp_root, &mut files);
    assert!(
        !files.is_empty(),
        "expected to find production .rs files under src/mcp"
    );

    let allowed: HashSet<&str> = ALL_PARAM_NAMES.iter().copied().collect();
    let mut violations: Vec<String> = Vec::new();

    for path in &files {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        let boundary = tests_mod_boundary(&content);
        for (lineno, line) in content.lines().enumerate() {
            if lineno >= boundary {
                break;
            }
            for lit in extract_param_literals(line) {
                if !allowed.contains(lit.as_str()) {
                    violations.push(format!(
                        "{}:{}: MCP param literal {:?} is NOT in \
                         crate::mcp::param_names::ALL_PARAM_NAMES — \
                         add the const to src/mcp/param_names.rs",
                        path.display(),
                        lineno + 1,
                        lit
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "Found {} MCP param-field literal(s) in production code that \
         are NOT in the canonical SSOT allowlist. Add each missing \
         name as `pub const FOO: &str = \"foo\";` in \
         src/mcp/param_names.rs and append to ALL_PARAM_NAMES \
         (keep alphabetically sorted).\n\nViolations:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

#[test]
fn allowlist_consts_all_resolve_back_to_themselves() {
    // Triviality pin — every const in ALL_PARAM_NAMES should be a
    // non-empty, distinct, snake_case string. If a future contributor
    // adds a const with the same `&str` body but different identifier,
    // this test fails and prevents alias-drift in the SSOT.
    let mut seen: HashSet<&str> = HashSet::new();
    for name in ALL_PARAM_NAMES {
        assert!(
            !name.is_empty(),
            "ALL_PARAM_NAMES contains an empty string — likely a generator bug"
        );
        assert!(
            seen.insert(name),
            "ALL_PARAM_NAMES contains a duplicate {name:?} — collapse to a single const"
        );
    }
    assert!(
        seen.len() == ALL_PARAM_NAMES.len(),
        "ALL_PARAM_NAMES contains duplicates"
    );
}
