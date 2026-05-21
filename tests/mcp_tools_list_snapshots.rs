// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #972 D1.7 (#988) — per-profile `tools/list` snapshot tests.
//!
//! After D1.6 (#987) collapsed the hand-coded `tool_definitions()`
//! macro to iterate over per-tool `McpTool` impls, the wire shape of
//! `tools/list` is derived from each request struct's schemars
//! `JsonSchema` impl. Schemars-driven schemas are sensitive to
//! upstream version bumps (property order, `additionalProperties`,
//! schema sub-document layout), so a casual `Cargo.toml` bump on
//! `schemars` could silently re-shape the payload that every MCP
//! host depends on. These snapshot tests pin the per-profile
//! `tools/list` payload byte-for-byte against a committed snapshot
//! under `tests/snapshots/tools_list_<profile>.json`.
//!
//! Five profiles are covered — `core`, `graph`, `admin`, `power`,
//! `full` — matching the named profiles defined in
//! [`ai_memory::profile::Profile`]. The snapshot is the canonical
//! 2-space-indented JSON with **sorted object keys** (so schemars'
//! property-ordering choice is the canonical one — a future schemars
//! bump that changes insertion order won't flip every line).
//!
//! Snapshot regeneration: run with `AI_MEMORY_BLESS_SNAPSHOTS=1` to
//! rewrite the snapshot files in place when an intentional change
//! lands.
//!
//! ```sh
//! AI_MEMORY_BLESS_SNAPSHOTS=1 cargo test --no-default-features \
//!   --features sqlite-bundled --test mcp_tools_list_snapshots
//! ```

use ai_memory::mcp::tool_definitions_for_profile;
use ai_memory::profile::Profile;
use serde_json::Value;
use std::path::PathBuf;

/// Render a `serde_json::Value` as canonical JSON: 2-space indent,
/// sorted object keys at every level, trailing newline. The `Value`
/// type already deduplicates keys (`Map` is a `BTreeMap` under the
/// `preserve_order` flag's absence — but we re-canonicalise here to
/// be explicit, so the snapshot is stable regardless of the upstream
/// `serde_json` feature flag posture).
fn canonical_json(v: &Value) -> String {
    let canonical = sort_keys(v);
    let mut out = serde_json::to_string_pretty(&canonical).expect("to_string_pretty");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Recursively re-build a JSON value with every object's keys
/// inserted in sorted order. Arrays preserve insertion order
/// (semantic ordering is load-bearing for `required` and `enum`
/// arrays in the schema, and for the top-level `tools` array — the
/// snapshot's job is to pin that order, not flip it).
fn sort_keys(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            // Collect keys, sort lexicographically, re-insert in order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::with_capacity(map.len());
            for k in keys {
                out.insert(k.clone(), sort_keys(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_keys).collect()),
        other => other.clone(),
    }
}

fn snapshot_path(profile_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("snapshots")
        .join(format!("tools_list_{profile_name}.json"))
}

fn assert_snapshot_matches(profile_name: &str, profile: &Profile) {
    let actual = canonical_json(&tool_definitions_for_profile(profile));
    let path = snapshot_path(profile_name);
    let bless = std::env::var("AI_MEMORY_BLESS_SNAPSHOTS")
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    if bless {
        std::fs::create_dir_all(path.parent().unwrap()).expect("create snapshot dir");
        std::fs::write(&path, &actual)
            .unwrap_or_else(|e| panic!("failed to bless snapshot at {}: {e}", path.display()));
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing snapshot at {}: {e}; \
             regenerate with AI_MEMORY_BLESS_SNAPSHOTS=1 cargo test \
             --test mcp_tools_list_snapshots",
            path.display()
        )
    });
    assert!(
        actual == expected,
        "tools/list snapshot drift for profile `{profile_name}`. \
         If this change is intentional, re-bless with \
         AI_MEMORY_BLESS_SNAPSHOTS=1 cargo test --test \
         mcp_tools_list_snapshots. \n\
         Hint: the snapshot is canonicalised with sorted object keys, \
         so schemars-property-order diffs are absorbed; any visible \
         diff is a real change to the wire shape (added/removed/renamed \
         field, type widening, default changed, etc.).\n\
         First divergence:\n{}",
        first_divergence(&expected, &actual)
    );
}

/// Pretty-print the first byte-level divergence between two snapshot
/// strings so the assertion message points at the line that drifted
/// without dumping multi-thousand-line full snapshots into the failure
/// output.
fn first_divergence(expected: &str, actual: &str) -> String {
    let mut line = 1usize;
    let mut col = 1usize;
    let mut last_newline_offset = 0usize;
    for (offset, (a, b)) in expected.bytes().zip(actual.bytes()).enumerate() {
        if a != b {
            let exp_line = expected[last_newline_offset..]
                .split('\n')
                .next()
                .unwrap_or("");
            let act_line = actual[last_newline_offset..]
                .split('\n')
                .next()
                .unwrap_or("");
            return format!(
                "  line {line}, col {col} (offset {offset}):\n    expected: {exp_line:?}\n    actual:   {act_line:?}"
            );
        }
        if a == b'\n' {
            line += 1;
            col = 1;
            last_newline_offset = offset + 1;
        } else {
            col += 1;
        }
    }
    if expected.len() == actual.len() {
        "  (no byte-level divergence detected — should not reach here)".to_string()
    } else {
        format!(
            "  length differs (expected {} bytes, actual {} bytes); \
             tail divergence not character-level",
            expected.len(),
            actual.len()
        )
    }
}

#[test]
fn d1_7_988_tools_list_snapshot_core() {
    assert_snapshot_matches("core", &Profile::core());
}

#[test]
fn d1_7_988_tools_list_snapshot_graph() {
    assert_snapshot_matches("graph", &Profile::graph());
}

#[test]
fn d1_7_988_tools_list_snapshot_admin() {
    assert_snapshot_matches("admin", &Profile::admin());
}

#[test]
fn d1_7_988_tools_list_snapshot_power() {
    assert_snapshot_matches("power", &Profile::power());
}

#[test]
fn d1_7_988_tools_list_snapshot_full() {
    assert_snapshot_matches("full", &Profile::full());
}
