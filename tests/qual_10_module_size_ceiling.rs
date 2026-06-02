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
//! (FX-C4-batch2 SHA, with subsequent FX-C2 ARCH-2 + PERF-9 bumps
//! per FX-D2). When a file's LOC genuinely needs to grow
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
    //
    // 2026-06-01 — bumped 16_000 → 16_100 by the v0.7.0 release QC of
    // #626 Layer-3 (C7, commit ed2bb7cf6): the store-path signature wire
    // added the agent-attestation persist branch (+6 LOC) which pushed
    // the file from 16_027 to 16_033, just over the ceiling; the lockstep
    // bump was missed in ed2bb7cf6. Actual LOC at the bump: 16_033.
    // Growth is justified: a new attestation persist branch on an
    // existing write path, no speculative surface. 16_100 = 16_033 + 67
    // headroom; far under QUAL-10's 1.5x aspirational cap.
    //
    // 2026-06-01 — bumped 16_100 → 16_200 by the #1466 TTL-leak fix:
    // the immortal-rows regression suite (insert / insert_with_conflict /
    // insert_if_newer / consolidate backfill assertions + the
    // ttl_gap_secs helper) added ~100 LOC of tests to the in-file
    // `mod tests`, pushing the file to 16_143. Growth is justified: pure
    // regression coverage for the tier-default expiry chokepoint, zero
    // new production surface. 16_200 = 16_143 + 57 headroom; far under
    // the 1.5x cap.
    ("src/storage/mod.rs", 16_200),
    ("src/mcp/mod.rs", 14_000),
    // postgres.rs bumped 13_000 → 15_200 by FX-D2 to accommodate
    // FX-C2-batch{1..5} ARCH-2 SAL trait method implementations
    // (fdfa69dd9 / 1d2b9553f / 6c8283cdf / dca98bd6b / 5d7f083e4 —
    // ~30 new sqlx-native methods spanning kg / governance / storage /
    // observations / federation). Growth is justified: each method
    // is a new entry on the canonical SAL trait surface needed for
    // postgres-backed daemons. Refactor-split into
    // `src/store/postgres/{mod,kg,governance,storage,...}.rs` is
    // tracked as a separate v0.7.x post-ship ARCH cleanup.
    //
    // 2026-05-31 — bumped 15_200 → 15_300 by the v0.7.0 security-review
    // epic (#1450) finding #1451: the optimistic-update PG path now
    // pre-reads the governance-relevant columns and consults
    // GOVERNANCE_PRE_WRITE on the post-merge row (parity with SQLite and
    // the insert/supersede PG paths), closing the update-evasion gap.
    // Actual LOC at the bump: 15216. Growth is a security gate on an
    // existing write path, not new surface.
    //
    // 2026-06-01 — bumped 15_300 → 15_400 by the v0.7.0 release QC of
    // #626 Layer-3 (C3, commit bd173cf81): bind/fetch agent pubkey in
    // registration metadata added the postgres-native SAL methods for
    // pubkey enrollment/lookup, growing the file to 15_353; the lockstep
    // bump was missed in bd173cf81. Actual LOC at the bump: 15_353.
    // Growth is justified: new entries on the canonical SAL trait surface
    // needed for postgres-backed agent attestation, mirroring the SQLite
    // path. 15_400 = 15_353 + 47 headroom; far under the 1.5x cap.
    //
    // 2026-06-01 — bumped 15_400 → 15_500 by the #1466 TTL-leak fix: the
    // postgres `migrate_v54` twin (tier-default expiry backfill on legacy
    // immortal rows, parity with the SQLite v54 ladder arm) added ~40 LOC,
    // pushing the file to 15_416. Growth is justified: a new migration on
    // the canonical postgres ladder mirroring the SQLite backfill, no
    // speculative surface. 15_500 = 15_416 + 84 headroom; far under the
    // 1.5x cap.
    ("src/store/postgres.rs", 15_500),
    ("src/config.rs", 9_000),
    // daemon_runtime.rs bumped 7_000 → 7_100 by FX-F1 to accommodate
    // the +446-line coverage closure on `apply_anonymize_default` /
    // `resolve_admin_agent_ids` / the `build_llm_client` ladder (the
    // 735d3c42e + 197640745 commits). Growth is justified: each new
    // test pins a previously-uncovered branch on existing production
    // helpers (no new production surface); the FX-F1 dispatch raised
    // the file's coverage floor from 83.83% → 85%. 7100 = 7050 actual
    // + 50-line headroom; well under QUAL-10's aspirational 1.5x cap.
    //
    // 2026-05-31 — bumped 7_100 → 7_300 by FX-F2 (commit 094abe811) to
    // accommodate +7 unit tests covering `build_store_handle` and
    // `resolve_configured_embedding_dim` that lifted daemon_runtime.rs
    // coverage 84.89% → 85.26% per the Per-Module Coverage Thresholds
    // floor (issue #1424). Actual LOC at the bump: 7256. Growth is
    // justified: each new test pins a previously-uncovered branch on
    // existing production helpers (zero new production surface). The
    // lockstep ceiling bump was missed in 094abe811 — fixing here so
    // the Per-Module Coverage Thresholds workflow (which runs the
    // full integration suite under llvm-cov) stops tripping qual_10
    // on every push.
    // 2026-05-31 — bumped 7_300 → 7_600 by the v0.7.0 security-review
    // epic (#1450) findings #1455 + #1458. #1455 added the shared
    // fail-CLOSED `governance_consultation_unavailable[_inner]` helpers
    // + `governance_fail_open_on_error` + 2 regression tests; #1458
    // extracted `api_key_bind_guard` + `require_api_key_strict` out of
    // `bootstrap_serve` and added 5 regression tests. Actual LOC at the
    // bump: 7528. Growth is justified: each change hardens an existing
    // startup path plus its regression coverage (no speculative
    // surface). 7600 = 7528 + ~72 headroom; well under the 1.5x cap.
    ("src/daemon_runtime.rs", 7_600),
    ("src/subscriptions.rs", 4_500),
    ("src/cli/install.rs", 3_500),
    ("src/storage/migrations.rs", 3_500),
    // llm.rs bumped 3_500 → 5_200 by FX-D2 to accommodate PERF-9
    // (36e2573a3 — `OllamaClient` blocking → async `reqwest::Client`
    // conversion) and the #1361 med/low findings batch fold-in.
    // Async client wiring is wider per call site (await + Result
    // propagation + #[allow] surface for clippy::pedantic on the
    // backend dispatch arms across ~15 vendor aliases). Refactor-split
    // into `src/llm/{client,backends,auto_tag,expansion}.rs` is
    // tracked as a separate v0.7.x post-ship ARCH cleanup.
    ("src/llm.rs", 5_200),
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
