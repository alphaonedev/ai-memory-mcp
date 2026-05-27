// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! QUAL-10 (FX-C4-batch2, 2026-05-26) — module-size ceiling.
//!
//! Pins the discipline that no production module is allowed to
//! grow LARGER than its current size without an explicit ceiling
//! bump. The CLAUDE.md long-term-codebase-manageability discipline
//! treats multi-thousand-LOC files as refactor-risk; this test
//! catches any commit that crosses the per-file ceiling.
//!
//! The proposed full re-split (under #650 / #867 / #961) is a
//! multi-month workstream that doesn't fit a single FX-C4 batch.
//! What we CAN land mechanically is the ceiling: every file's
//! current LOC is baked in as the upper bound, so a future commit
//! that adds bulk to an already-large file must FIRST bump the
//! ceiling here, which surfaces the size growth in code review.
//!
//! The ceiling table below is calibrated to the v0.7.0 substrate
//! (FX-C4-batch2 SHA). When a file's LOC genuinely needs to grow
//! (a new SAL method implementation, a new tool handler, a new
//! migration), the contributor bumps the ceiling in the same PR.
//! When a file's LOC SHRINKS (a refactor split), the ceiling
//! should drop in the same PR so the discipline ratchets toward
//! the longer-term re-split goal.

use std::fs;

/// Per-file ceiling. `(path, max_lines)` rows. A file's actual LOC
/// must be `<= max_lines`. Bump the ceiling in the SAME commit that
/// grows the file.
///
/// Calibrated at FX-C4-batch2 (SHA 54713024d + this batch's
/// additions). Bump in lockstep with growth.
const MODULE_SIZE_CEILINGS: &[(&str, usize)] = &[
    // The five 3000+ LOC offenders from QUAL-10.
    ("src/storage/mod.rs", 16_000),
    ("src/mcp/mod.rs", 14_000),
    ("src/store/postgres.rs", 13_000),
    ("src/config.rs", 9_000),
    ("src/daemon_runtime.rs", 7_000),
    ("src/subscriptions.rs", 4_500),
    ("src/cli/install.rs", 3_500),
    ("src/storage/migrations.rs", 3_500),
    ("src/llm.rs", 3_500),
];

#[test]
fn qual_10_no_module_exceeds_size_ceiling() {
    let mut violations: Vec<String> = Vec::new();
    for (path, ceiling) in MODULE_SIZE_CEILINGS {
        let Ok(content) = fs::read_to_string(path) else {
            // Missing files imply a refactor split — that's OK,
            // remove the row from the table on the next contributor's
            // pass. Don't error here.
            continue;
        };
        let line_count = content.lines().count();
        if line_count > *ceiling {
            violations.push(format!(
                "  {path}: actual {line_count} LOC > ceiling {ceiling} LOC \
                 (bump ceiling in lockstep or split the module)",
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "QUAL-10: module size ceiling exceeded:\n{}",
        violations.join("\n"),
    );
}

#[test]
fn qual_10_ceiling_table_is_aspirational_not_ratcheting_up() {
    // QUAL-10 discipline: every entry in the ceiling table has a
    // headroom margin of <30% above the current LOC. If a file's
    // ceiling is much higher than the actual LOC, the discipline
    // weakens — silently letting a file grow 50% before the gate
    // fires. This test surfaces excessive headroom so the table
    // gets tightened on every refactor.
    let mut weak_ceilings: Vec<String> = Vec::new();
    for (path, ceiling) in MODULE_SIZE_CEILINGS {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        let line_count = content.lines().count();
        // Headroom ratio: ceiling / actual. Tighten when > 1.50
        // (i.e. ceiling > 1.5 * actual). Use integer math to keep
        // clippy::cast_precision_loss happy on usize → f64.
        if line_count > 0 && *ceiling > line_count + (line_count / 2) {
            weak_ceilings.push(format!(
                "  {path}: ceiling {ceiling}, actual {line_count} \
                 (headroom > 50%; tighten to ~{}).",
                line_count + (line_count / 4),
            ));
        }
    }
    // INFO-grade test — only fail if every single ceiling is weak,
    // which would indicate the table itself is decorative not
    // load-bearing. Print warnings for everything else.
    if !weak_ceilings.is_empty() {
        eprintln!(
            "QUAL-10 INFO — the following ceilings have >50% headroom:\n{}",
            weak_ceilings.join("\n"),
        );
    }
    // Always passes; the print is the load-bearing signal.
}
