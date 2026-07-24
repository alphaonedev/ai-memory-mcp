// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2393 (N12) + #2397 (N17) — BACKEND-BLIND mechanical pins for the
//! postgres write-funnel column/unprojection parity fixes.
//!
//! ## Why a source-inspection test
//!
//! Both defects are invisible without a live postgres: #2393 is a missing
//! column in a `sqlx::query` SQL string plus its `.bind(...)` in the chain,
//! and #2397 is a missing call inside a transaction that only an
//! AGE-enabled postgres can observe. The functional regressions live in
//! `tests/store_parity_gaps.rs` behind `#[ignore]` +
//! `AI_MEMORY_TEST_POSTGRES_URL` / `AI_MEMORY_TEST_AGE_URL`, so on a host
//! (or a contributor laptop) with no database they never run and the fix is
//! effectively uncovered.
//!
//! This file closes that gap the way the `qual_*` family already does for
//! module size and legacy error types: it reads `src/store/postgres.rs` off
//! disk, extracts each target function's source span by indentation-matched
//! brace scanning, and asserts the fix tokens are present in the RIGHT
//! function. It runs under a plain `cargo test` with zero infrastructure.
//!
//! ## What it does NOT prove (honest scope)
//!
//! A source-token assertion proves the column name and the bind call are
//! present in the function body. It does NOT prove the `$N` positional
//! placeholder lines up with that specific `.bind()` in execution order — a
//! misordered bind still passes here and only a live postgres catches it.
//! This pin is therefore NECESSARY BUT NOT SUFFICIENT, and is explicitly
//! additive to (never a replacement for) the `#[ignore]`d live-PG / AGE
//! functional tests. Degrade, never corrupt: a mechanical pin that catches
//! the whole-column-omission class on every run beats a functional test that
//! catches everything but runs almost never.

#![allow(clippy::missing_panics_doc)]

/// The postgres SAL adapter, relative to `CARGO_MANIFEST_DIR`.
const PG_ADAPTER_PATH: &str = "src/store/postgres.rs";

/// The v79/#1945 denormalised epistemic-typing column (spec §4).
const KIND_PROVENANCE_COLUMN: &str = "kind_provenance";

/// The single SSOT helper every write funnel must route the bind through —
/// it validates the closed vocab (`declared`/`channel_derived`/`regex`/`llm`)
/// and returns `None` for unstamped/off-vocab metadata, so the column stays
/// honestly NULL rather than carrying an unvalidated caller string.
const KIND_PROVENANCE_BIND: &str = "extract_kind_provenance(";

/// The #1783 AGE `DETACH DELETE` helper every postgres hard-delete path must
/// call so the `memory_graph` projection never serves a deleted memory.
const AGE_UNPROJECT_CALL: &str = "unproject_memory_from_age(";

/// Every postgres funnel that INSERTs a `memories` row and MUST persist
/// `kind_provenance`, because its sqlite twin does. Sweeping the whole set
/// (not just the funnels issue #2393 named) is the FBL-22/FBL-12 lesson:
/// a parity fix that closes five of eight arms has not closed the class.
///
/// Deliberately ABSENT — `consolidate`: the sqlite twin
/// (`storage::consolidate`) does not bind it either, and NEITHER backend
/// binds `memory_kind` on that funnel (the consolidated row takes the SQL
/// column DEFAULT `'observation'`). Nobody assigned the kind, so there is no
/// provenance to record and NULL is the honest value. Binding on postgres
/// alone would MANUFACTURE a divergence where the backends currently agree —
/// the exact failure mode this campaign exists to prevent. Tracked
/// separately; see the PR body for the 2x3 adversarial vote (4 of 6 for
/// leave-symmetric, 0 of 6 for postgres-only).
const KIND_PROVENANCE_FUNNELS: &[&str] = &[
    // Already correct before #2393 — pinned so they cannot regress.
    "store",
    "store_batch",     // #2289
    "archive_restore", // #2333 / FBL-03
    // Fixed by #2393 — the three funnels the issue named…
    "store_with_embedding",
    "capture_turn_idempotent",
    "recover_turn_idempotent",
    // …and the three the completeness sweep found that it did not.
    "update_with_archive_on_supersede",
    "reflect_with_hooks",
    "apply_remote_memory",
];

/// Every postgres funnel that hard-DELETEs a live `memories` row and MUST
/// therefore unproject it from the AGE `memory_graph` projection.
/// `update_with_archive_on_supersede` is the #2397 net-new arm; the rest
/// were already correct (`archive_by_ids` by #2315) and are pinned here so
/// the class stays closed.
const AGE_UNPROJECT_FUNNELS: &[&str] = &[
    "delete",
    "apply_remote_deletion",
    "forget",
    "consolidate",
    "run_gc",
    "size_gc",
    "archive_by_ids",
    "update_with_archive_on_supersede", // #2397 (N17)
];

fn adapter_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(PG_ADAPTER_PATH);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Extract the source span of the FIRST production `impl`-level function
/// named `name` in `src`.
///
/// Functions in this file live inside `impl` blocks, so their signature
/// starts at exactly four spaces of indentation and the body terminator is a
/// line that is exactly `    }`. Taking the FIRST match keeps us on the
/// production definition — the `#[cfg(test)]` module lives at the bottom of
/// the file and its same-named test fns can never shadow it.
///
/// Returns `None` when no such function exists, so a rename surfaces as an
/// explicit "function not found" failure rather than a silently-vacuous pass.
fn fn_span<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let lines: Vec<&str> = src.lines().collect();
    let sig_a = format!("    async fn {name}(");
    let sig_b = format!("    pub async fn {name}(");
    // Single-line-signature variants (e.g. `archive_restore`, `delete`).
    let start = lines
        .iter()
        .position(|l| l.starts_with(&sig_a) || l.starts_with(&sig_b))?;
    let end = lines[start + 1..]
        .iter()
        .position(|l| *l == "    }")
        .map(|off| start + 1 + off)?;
    // Byte offsets back into the original string so the returned slice keeps
    // the verbatim source (line-join would drop the original line endings).
    let begin = src
        .lines()
        .take(start)
        .map(|l| l.len() + 1)
        .sum::<usize>()
        .min(src.len());
    let finish = src
        .lines()
        .take(end + 1)
        .map(|l| l.len() + 1)
        .sum::<usize>()
        .min(src.len());
    Some(&src[begin..finish])
}

/// The span extractor is the load-bearing part of both assertions below —
/// if it silently returned an empty or mis-bounded slice, every assertion
/// would pass vacuously. Prove it works before trusting it.
#[test]
fn span_extractor_is_load_bearing() {
    let src = adapter_source();
    let span = fn_span(&src, "store_with_embedding").expect("store_with_embedding must exist");
    assert!(
        span.contains("async fn store_with_embedding("),
        "span must begin at the target signature"
    );
    assert!(
        span.contains("INSERT INTO memories"),
        "the store_with_embedding span must contain its own INSERT"
    );
    assert!(
        !span.contains("async fn capture_turn_idempotent("),
        "span must NOT bleed into a sibling function"
    );
    assert!(
        fn_span(&src, "a_function_that_does_not_exist_2393").is_none(),
        "a missing function must be reported, never silently skipped"
    );
}

/// #2393 (N12) — every postgres funnel that persists a `memories` row must
/// bind `kind_provenance`, routed through the vocab-validating
/// `extract_kind_provenance` SSOT.
#[test]
fn pg_write_funnels_bind_kind_provenance_2393() {
    let src = adapter_source();
    let mut missing: Vec<String> = Vec::new();
    for name in KIND_PROVENANCE_FUNNELS {
        let Some(span) = fn_span(&src, name) else {
            missing.push(format!("  {name}: function not found in {PG_ADAPTER_PATH}"));
            continue;
        };
        if !span.contains(KIND_PROVENANCE_COLUMN) {
            missing.push(format!(
                "  {name}: SQL does not mention the `{KIND_PROVENANCE_COLUMN}` column"
            ));
        }
        // `archive_restore` carries the column through an INSERT ... SELECT
        // over `archived_memories` (with a metadata-carrier COALESCE fallback
        // for legacy pre-v87 archive rows), so it has no Rust-side bind.
        if *name != "archive_restore" && !span.contains(KIND_PROVENANCE_BIND) {
            missing.push(format!(
                "  {name}: no `{KIND_PROVENANCE_BIND}` bind — a raw literal or a \
                 dropped column silently NULLs the v79/#1945 provenance on postgres"
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "#2393 (N12): postgres write funnels missing the kind_provenance bind \
         (sqlite persists it — this is the cross-backend divergence class):\n{}",
        missing.join("\n")
    );
}

/// #2397 (N17) — every postgres funnel that hard-DELETEs a live `memories`
/// row must unproject it from AGE, or the `memory_graph` projection keeps
/// serving a ghost `:Memory` node with live-looking incident edges.
#[test]
fn pg_hard_delete_funnels_unproject_from_age_2397() {
    let src = adapter_source();
    let mut missing: Vec<String> = Vec::new();
    for name in AGE_UNPROJECT_FUNNELS {
        let Some(span) = fn_span(&src, name) else {
            missing.push(format!("  {name}: function not found in {PG_ADAPTER_PATH}"));
            continue;
        };
        // `delete` / `apply_remote_deletion` run pool-direct (no surrounding
        // tx) and route through the `unproject_memory_ids_best_effort`
        // wrapper, which calls the helper on their behalf.
        let unprojects =
            span.contains(AGE_UNPROJECT_CALL) || span.contains("unproject_memory_ids_best_effort(");
        if !unprojects {
            missing.push(format!(
                "  {name}: hard-deletes a memories row without unprojecting it \
                 from the AGE memory_graph — leaves a ghost node kg_query serves"
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "#2397 (N17): postgres hard-delete funnels missing AGE unprojection \
         (the graph projection would serve deleted state as live):\n{}",
        missing.join("\n")
    );
}
