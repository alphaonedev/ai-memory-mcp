// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3171 — **handler-reads ⊆ declared-schema** guard.
//!
//! ## The defect class this closes
//!
//! Every MCP tool's `inputSchema` is derived by `schemars` from a
//! `*Request` struct, but no handler ever deserializes that struct: each
//! one reaches into the raw `arguments` bag with `params["key"]` /
//! `params.get(key)`. Nothing couples the two, and there is **no runtime
//! JSON-Schema validation on the MCP path** — so the advertised contract
//! and the enforced contract drift silently in both directions:
//!
//! - a key the handler HONOURS but the schema never declares is
//!   undiscoverable to a schema-conformant client, and — when it names an
//!   authz subject, an escalation switch, or an owner stamp — it is a
//!   parameter that only an attacker who read the source knows exists;
//! - a key the schema declares but no handler reads is a documented lie.
//!
//! The #3171 audit found 20+ instances across 103 tools. The existing
//! pins could not see any of them: `assert_property_set_parity` compares
//! schema-vs-SNAPSHOT (schema against its own past self), never
//! schema-against-handler.
//!
//! ## What this test does
//!
//! It parses the handler sources under `src/mcp/tools/` for every literal
//! and `param_names::`-const key read out of a `params` / `arguments`
//! JSON bag, resolves the const names against the `param_names` SSOT, and
//! asserts that set is a SUBSET of the properties declared by the tools
//! implemented in the same module unit (a file, or a directory such as
//! `store/`, so a validator split across `store/validation.rs` and
//! `store/mod.rs` is judged as one unit).
//!
//! Anything genuinely read-but-not-declared belongs in [`ALLOWED_READS`]
//! with a reason — the point is that adding it is a deliberate, reviewed
//! act rather than an invisible drift.
//!
//! ## Why source-text analysis
//!
//! The alternative — a runtime probe — cannot work: a handler's key reads
//! are data-dependent (a `kind`-specific branch reads `command` only for
//! `kind: "bash"`), so no finite set of probe calls enumerates them. The
//! parse is deliberately conservative: it only matches receivers literally
//! named `params` / `arguments` (so `metadata.get(...)` and
//! `row.get(...)` are ignored), and comments are stripped first.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Keys a handler legitimately reads that are NOT (and should not be)
/// declared properties of the tool's own input schema. Every entry needs a
/// reason; an entry that stops being read is itself a failure (the test
/// asserts the allowlist is not stale).
const ALLOWED_READS: &[(&str, &str)] = &[
    // Sub-object traversal: the handler reads the bag, then a nested key of
    // a DECLARED object-typed property. The nested key is part of that
    // property's value shape, not a top-level input.
    ("governance", "nested key of the declared `metadata` object"),
    ("scope", "nested key of the declared `metadata` object (#151)"),
    // Dispatcher plumbing in `src/mcp/mod.rs`: read across all tools.
    ("name", "tools/call envelope field, not a tool input"),
];

/// Resolve `pub const NAME: &str = "value";` declarations from a SSOT
/// module into a `NAME -> value` map.
fn const_map(src: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in src.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, tail)) = rest.split_once(':') else {
            continue;
        };
        let Some((_, value)) = tail.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_end_matches(';').trim();
        if let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            out.insert(name.trim().to_string(), inner.to_string());
        }
    }
    out
}

/// Strip `//`-to-EOL and `/* … */` comments so prose that happens to
/// contain `params["x"]` never registers as a read.
fn strip_comments(src: &str) -> String {
    let bytes: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let (mut in_str, mut in_line, mut in_block) = (false, false, false);
    while i < bytes.len() {
        let c = bytes[i];
        let next = bytes.get(i + 1).copied();
        if in_line {
            if c == '\n' {
                in_line = false;
                out.push(c);
            }
            i += 1;
        } else if in_block {
            if c == '*' && next == Some('/') {
                in_block = false;
                i += 2;
            } else {
                if c == '\n' {
                    out.push(c);
                }
                i += 1;
            }
        } else if in_str {
            if c == '\\' {
                out.push(c);
                if let Some(n) = next {
                    out.push(n);
                }
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            out.push(c);
            i += 1;
        } else if c == '/' && next == Some('/') {
            in_line = true;
            i += 2;
        } else if c == '/' && next == Some('*') {
            in_block = true;
            i += 2;
        } else {
            if c == '"' {
                in_str = true;
            }
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Extract every key read out of a `params` / `arguments` JSON bag.
///
/// Matches the four shapes the handlers actually use:
/// `params["k"]`, `params[param_names::K]`, `params.get("k")`,
/// `params.get(param_names::K)` — with any amount of whitespace, and with
/// an arbitrary receiver prefix (`ctx.arguments.get(..)`) as long as the
/// last path segment is `params` or `arguments`.
fn read_keys(src: &str, params: &BTreeMap<String, String>) -> BTreeSet<String> {
    let cleaned = strip_comments(src);
    let mut out = BTreeSet::new();
    for (idx, _) in cleaned.match_indices("params").chain(cleaned.match_indices("arguments")) {
        // Reject a longer identifier that merely ENDS in `params`
        // (e.g. `extra_params`) — only a path segment counts.
        let before = cleaned[..idx].chars().next_back();
        if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        let tail = &cleaned[idx..];
        let tail = tail.trim_start_matches("params").trim_start_matches("arguments");
        let tail = tail.trim_start();
        let inner = if let Some(rest) = tail.strip_prefix('[') {
            let Some(end) = rest.find(']') else { continue };
            rest[..end].trim().to_string()
        } else if let Some(rest) = tail.strip_prefix(".get(") {
            let Some(end) = rest.find(')') else { continue };
            rest[..end].trim().to_string()
        } else {
            continue;
        };
        if let Some(lit) = inner.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            out.insert(lit.to_string());
        } else if let Some(cname) = inner.strip_prefix("param_names::") {
            if let Some(v) = params.get(cname.trim()) {
                out.insert(v.clone());
            }
        } else if let Some(cname) = inner.rsplit("::").next() {
            if let Some(v) = params.get(cname.trim()) {
                out.insert(v.clone());
            }
        }
    }
    out
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// The module unit a source file belongs to: the sub-directory when the
/// file lives in one (`store/`), else the file itself. A tool whose
/// validation is split across several files in one module directory is
/// judged as a single unit.
fn module_unit(root: &Path, file: &Path) -> String {
    let rel = file.strip_prefix(root).unwrap_or(file);
    let mut comps: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if comps.len() > 1 {
        comps.truncate(1);
    }
    comps.join("/")
}

#[test]
fn handler_param_reads_are_declared_in_the_tool_schema_3171() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let param_names = const_map(
        &std::fs::read_to_string(manifest.join("src/mcp/param_names.rs"))
            .expect("param_names.rs must be readable"),
    );
    let tool_names = const_map(
        &std::fs::read_to_string(manifest.join("src/mcp/registry.rs"))
            .expect("registry.rs must be readable"),
    );
    assert!(
        param_names.len() > 100 && tool_names.len() > 100,
        "SSOT const extraction failed (param_names={}, tool_names={}); the guard \
         would silently pass on an empty map",
        param_names.len(),
        tool_names.len()
    );

    // name -> declared property keys, straight from the live catalog.
    let catalog = ai_memory::mcp::tool_definitions();
    let mut props: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for tool in catalog["tools"].as_array().expect("tools array") {
        let name = tool["name"].as_str().expect("tool name").to_string();
        let keys: BTreeSet<String> = tool
            .pointer("/inputSchema/properties")
            .and_then(serde_json::Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        props.insert(name, keys);
    }
    let all_props: BTreeSet<String> = props.values().flatten().cloned().collect();
    assert!(
        props.len() > 100,
        "tool catalog looks empty ({} tools)",
        props.len()
    );

    let tools_root = manifest.join("src/mcp/tools");
    let allowed: BTreeSet<&str> = ALLOWED_READS.iter().map(|(k, _)| *k).collect();

    // Accumulate per module unit: reads, and the union of the properties of
    // every tool whose `tool_names::` const is referenced in that unit.
    let mut unit_reads: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut unit_declared: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut seen_allowed: BTreeSet<String> = BTreeSet::new();

    for file in rust_files(&tools_root) {
        let src = std::fs::read_to_string(&file).expect("source readable");
        let unit = module_unit(&tools_root, &file);
        let cleaned = strip_comments(&src);
        unit_reads
            .entry(unit.clone())
            .or_default()
            .extend(read_keys(&src, &param_names));
        let declared = unit_declared.entry(unit).or_default();
        for (cname, tname) in &tool_names {
            if cleaned.contains(&format!("tool_names::{cname}"))
                && let Some(keys) = props.get(tname)
            {
                declared.extend(keys.iter().cloned());
            }
        }
    }

    let mut failures: Vec<String> = Vec::new();
    for (unit, reads) in &unit_reads {
        let declared = unit_declared.get(unit).cloned().unwrap_or_default();
        // A unit that declares NO tool is pure plumbing (shared helpers,
        // zstd bounds, the D1.4 test helpers) — judge it against the whole
        // catalog rather than skipping it, so a typo'd key is still caught.
        let declared = if declared.is_empty() {
            all_props.clone()
        } else {
            declared
        };
        for key in reads {
            if declared.contains(key) {
                continue;
            }
            if allowed.contains(key.as_str()) {
                seen_allowed.insert(key.clone());
                continue;
            }
            failures.push(format!("  {unit}: reads `{key}`, which no tool in that unit declares"));
        }
    }

    assert!(
        failures.is_empty(),
        "#3171 — {} MCP handler param read(s) are NOT declared on the tool's \
         input schema:\n{}\n\n\
         A handler that honours an undeclared key advertises one contract and \
         enforces another: a schema-conformant client cannot discover the key, \
         while a caller that read the source can reach behaviour the schema \
         never promised (the #3171 audit found an undeclared `agent_id` \
         disarming an owner gate, and an undeclared `as_admin` escalating an \
         irreversible purge across tenants). Fix by DECLARING the field on the \
         tool's `*Request` struct — and, if it is an authz subject, binding it \
         to the resolved caller. Only add to `ALLOWED_READS` when the key is \
         genuinely not a top-level tool input.",
        failures.len(),
        failures.join("\n")
    );

    let stale: Vec<&str> = ALLOWED_READS
        .iter()
        .map(|(k, _)| *k)
        .filter(|k| !seen_allowed.contains(*k))
        .collect();
    assert!(
        stale.is_empty(),
        "ALLOWED_READS has stale entries no handler reads any more: {stale:?} — \
         remove them so the allowlist keeps naming only real exceptions"
    );
}
