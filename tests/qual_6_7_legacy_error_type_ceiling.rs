// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! QUAL-6 + QUAL-7 (FX-C4-batch2, 2026-05-26) — `Result<Value,
//! String>` / `Result<(), String>` legacy ceiling.
//!
//! The v0.7.0 v2 review identified 81 `Result<Value, String>`
//! signatures in `src/mcp/tools/` (QUAL-6) and 6+ `Result<(),
//! String>` legacy validation helpers in `src/subscriptions.rs` /
//! `src/config.rs` / `src/atomisation/curator.rs` /
//! `src/daemon_runtime.rs` (QUAL-7). Both shapes collapse typed
//! errors into a single `String` bucket, losing HTTP-status /
//! audit-event / structured-trace context at the layer transition.
//!
//! Full migration of every handler is a multi-PR Wave-3 candidate;
//! what we lock in here is the CEILING — a future commit cannot
//! add NEW `Result<Value, String>` / `Result<(), String>`
//! signatures without explicitly raising the ceiling, which
//! surfaces the regression in code review.
//!
//! When a handler family migrates to `MemoryError` / `StoreError`,
//! the contributor lowers the ceiling in the same commit so the
//! discipline ratchets toward zero.

use std::fs;
use std::path::Path;

/// Walk a directory recursively for .rs files (matches the
/// pattern in `feature_flag_audit_arch_11.rs`).
fn walk_rs(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_rs(&path));
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    out
}

fn count_matches(root: &Path, needle: &str) -> usize {
    let files = walk_rs(root);
    let mut count = 0usize;
    for path in &files {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        // Count needle occurrences across the file. Each match
        // counts once; consecutive overlapping matches (e.g.
        // accidental nesting) are not expected and would inflate
        // the count, which is the right direction for the ceiling
        // gate.
        let mut idx = 0;
        while let Some(found) = content[idx..].find(needle) {
            count += 1;
            idx += found + needle.len();
        }
    }
    count
}

/// QUAL-6 ceiling: 81 sites at v2-review time + slack for in-batch
/// additions. Tighten in lockstep with handler-family migration.
const QUAL_6_CEILING: usize = 90;

/// QUAL-7 ceiling: 6+ sites at v2-review time + slack.
const QUAL_7_CEILING: usize = 25;

#[test]
fn qual_6_result_value_string_count_below_ceiling() {
    // QUAL-6: production MCP handlers under `src/mcp/tools/` carry
    // 81 `Result<Value, String>` signatures at v2-review time. The
    // ceiling locks this in so a regression that adds a NEW
    // legacy-typed handler fails the gate.
    let count = count_matches(Path::new("src/mcp/tools"), "Result<Value, String>");
    assert!(
        count <= QUAL_6_CEILING,
        "QUAL-6: src/mcp/tools/ has {count} `Result<Value, String>` signatures \
         (ceiling {QUAL_6_CEILING}). New handlers MUST use `MemoryError` (typed) \
         or anyhow::Error (untyped). Lower the ceiling when migrating an existing \
         family.",
    );
}

#[test]
fn qual_7_result_unit_string_count_below_ceiling() {
    // QUAL-7: 6+ `Result<(), String>` validation helpers across
    // src/subscriptions.rs / src/config.rs / src/atomisation /
    // src/daemon_runtime. Pin the count.
    let count = count_matches(Path::new("src"), "Result<(), String>");
    assert!(
        count <= QUAL_7_CEILING,
        "QUAL-7: `Result<(), String>` count in src/ = {count} (ceiling {QUAL_7_CEILING}). \
         New validation helpers should return `Result<(), MemoryError>` or anyhow. \
         Lower the ceiling when migrating.",
    );
}
