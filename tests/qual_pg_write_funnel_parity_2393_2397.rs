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
    // #2771 — `store_with_embedding` was refactored into a thin delegator to the
    // shared inherent `store_with_embedding_inner`, which now holds the INSERT +
    // every column bind. BOTH create funnels (`store_with_embedding` merge +
    // `store_with_embedding_no_overwrite` fail-closed) delegate to it, so the
    // provenance-bind guard follows the INSERT to `_inner` — strictly stronger,
    // since it now also covers the no-overwrite arm's bind.
    "store_with_embedding_inner",
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
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    // Normalise CRLF -> LF once, at the single ingest point, so no downstream
    // consumer in this file has to reason about line endings. On a Windows
    // checkout with `core.autocrlf=true` every line arrives with a two-byte
    // terminator; `fn_span` below is independently CRLF-correct, but keeping
    // the source LF-only here means a future token/offset scan added to this
    // file inherits the immunity instead of re-discovering the bug on the one
    // platform none of us runs locally.
    raw.replace("\r\n", "\n")
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
/// Line terminators are NEVER reconstructed by arithmetic here. The original
/// implementation summed `line.len() + 1` to rebuild byte offsets, which
/// assumes a ONE-byte terminator; `str::lines()` strips `\r\n` as well as
/// `\n`, so on a CRLF checkout every line under-counted by one byte and the
/// error ACCUMULATED — by the time the scan reached a function late in this
/// 31k-line file the returned slice was thousands of bytes off and landed in
/// a DIFFERENT function, silently reporting the fix as missing. Offsets now
/// come from the real slice lengths via `split_inclusive('\n')`, which keeps
/// each terminator, so LF, CRLF, and a final line with no terminator are all
/// exact.
fn fn_span<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let sig_a = format!("    async fn {name}(");
    let sig_b = format!("    pub async fn {name}(");

    // (byte_start, byte_end_past_terminator, content_without_terminator)
    let mut lines: Vec<(usize, usize, &str)> = Vec::new();
    let mut offset = 0usize;
    for raw in src.split_inclusive('\n') {
        let start = offset;
        offset += raw.len();
        let content = raw.strip_suffix('\n').unwrap_or(raw);
        let content = content.strip_suffix('\r').unwrap_or(content);
        lines.push((start, offset, content));
    }

    // Single-line-signature variants (e.g. `archive_restore`, `delete`).
    let start = lines
        .iter()
        .position(|(_, _, l)| l.starts_with(&sig_a) || l.starts_with(&sig_b))?;
    let end = lines[start + 1..]
        .iter()
        .position(|(_, _, l)| *l == "    }")
        .map(|off| start + 1 + off)?;
    // Verbatim slice of the original source (line-join would drop the
    // original line endings).
    Some(&src[lines[start].0..lines[end].1])
}

/// The span extractor is the load-bearing part of both assertions below —
/// if it silently returned an empty or mis-bounded slice, every assertion
/// would pass vacuously. Prove it works before trusting it.
///
/// Probes an EARLY and a LATE function deliberately. The original version of
/// this guard probed only `store_with_embedding`, which sits early enough in
/// the file that the CRLF offset drift had not yet exceeded one span length —
/// so the slice still landed inside the right body and the guard passed while
/// four LATE funnels were being mis-read on Windows. A drift bug is
/// proportional to how far into the file the scan has walked, so the guard has
/// to assert at the far end of the file to be meaningful.
#[test]
fn span_extractor_is_load_bearing() {
    let src = adapter_source();

    // --- EARLY function -------------------------------------------------
    // #2771 — `store_with_embedding` is now a thin delegator; the INSERT + all
    // column binds moved to the inherent `store_with_embedding_inner` that both
    // create funnels share. Probe BOTH: the delegator (proves it still exists +
    // forwards, so the parity guards can't silently stop covering this funnel)
    // and `_inner` (proves it carries the INSERT the guards below scan). Keep
    // the exact-start anchoring — a `contains` cannot detect offset drift.
    let span = fn_span(&src, "store_with_embedding").expect("store_with_embedding must exist");
    assert!(
        span.starts_with("    async fn store_with_embedding(")
            || span.starts_with("    pub async fn store_with_embedding("),
        "span must begin EXACTLY at the target signature line, got: {:?}",
        &span[..span.len().min(80)]
    );
    assert!(
        span.contains("store_with_embedding_inner("),
        "the thin store_with_embedding must DELEGATE to store_with_embedding_inner \
         (#2771) — if the delegation vanishes the parity guards stop covering it"
    );
    assert!(
        !span.contains("async fn store_with_embedding_no_overwrite("),
        "span must NOT bleed into the sibling function"
    );

    let inner =
        fn_span(&src, "store_with_embedding_inner").expect("store_with_embedding_inner must exist");
    assert!(
        inner.starts_with("    async fn store_with_embedding_inner(")
            || inner.starts_with("    pub async fn store_with_embedding_inner("),
        "the inner span must begin EXACTLY at its own signature, got: {:?}",
        &inner[..inner.len().min(80)]
    );
    assert!(
        inner.contains("INSERT INTO memories"),
        "the store_with_embedding_inner span must contain the INSERT (#2771 moved \
         it here from the thin delegator)"
    );
    assert!(
        !inner.contains("async fn list_archived_pg("),
        "the inner span must NOT bleed into the following function"
    );

    // --- LATE function (the accumulated-drift detector) -----------------
    // `apply_remote_memory` is one of the funnels the CRLF drift actually
    // mis-read; it lives near the end of the adapter, so any offset error
    // that accumulates per line is maximal here.
    let late = fn_span(&src, "apply_remote_memory").expect("apply_remote_memory must exist");
    assert!(
        late.starts_with("    async fn apply_remote_memory(")
            || late.starts_with("    pub async fn apply_remote_memory("),
        "the LATE span must begin EXACTLY at its own signature — this is the \
         assertion that catches per-line offset drift (e.g. a CRLF checkout, \
         where the accumulated error is maximal this deep into the file) \
         before Windows CI does. Got: {:?}",
        &late[..late.len().min(80)]
    );
    assert!(
        late.contains("apply_remote_memory upsert"),
        "the LATE span must contain apply_remote_memory's own error label"
    );
    assert!(
        late.contains("redact_memory_for_receive"),
        "Wave-2 B4: apply_remote_memory must receive-redact (ReceiveAttestationLeaves), \
         not TrustedByName storage-screen"
    );
    assert!(
        !late.contains("let screened = screen_storage_memory"),
        "Wave-2 B4: apply_remote_memory must not call the TrustedByName \
         storage-screen helper (local store / store_batch keep that path)"
    );
    assert!(
        !late.contains("async fn merge_inbound("),
        "the LATE span must NOT bleed into the following function"
    );

    assert!(
        fn_span(&src, "a_function_that_does_not_exist_2393").is_none(),
        "a missing function must be reported, never silently skipped"
    );
}

/// Regression pin for the CRLF offset-drift bug that red-ded Windows CI while
/// Linux stayed green (`\n` is genuinely one byte there, so the faulty
/// `len() + 1` arithmetic was accidentally correct).
///
/// Constructs a synthetic adapter with `\r\n` terminators and asserts
/// `fn_span` still returns the CORRECT body. The two functions are ordered so
/// that a one-byte-per-line under-count would push the second span's start
/// backwards into the first function's body — the exact production symptom.
#[test]
fn fn_span_is_crlf_correct() {
    let lf = concat!(
        "impl PostgresStore {\n",
        "    async fn early_funnel(&self) -> Result<()> {\n",
        "        // padding line to build up offset drift\n",
        "        // padding line to build up offset drift\n",
        "        let marker = \"EARLY_ONLY_MARKER\";\n",
        "        Ok(())\n",
        "    }\n",
        "\n",
        "    async fn late_funnel(&self) -> Result<()> {\n",
        "        let marker = \"LATE_ONLY_MARKER\";\n",
        "        Ok(())\n",
        "    }\n",
        "}\n",
    );
    let crlf = lf.replace('\n', "\r\n");

    for (label, src) in [("LF", lf), ("CRLF", crlf.as_str())] {
        // `starts_with`, NOT `contains`. The accumulated drift over a fixture
        // this small is only a handful of bytes — far too little to reach a
        // neighbouring marker — so a `contains`-based assertion passes even
        // against the buggy arithmetic and pins NOTHING. (Verified: an earlier
        // draft of this very test did exactly that.) Anchoring the exact start
        // byte is what detects a one-byte-per-line error.
        let early = fn_span(src, "early_funnel")
            .unwrap_or_else(|| panic!("{label}: early_funnel span must be found"));
        assert!(
            early.starts_with("    async fn early_funnel("),
            "{label}: early span must begin EXACTLY at its own signature, got: {:?}",
            &early[..early.len().min(60)]
        );
        assert!(
            early.contains("EARLY_ONLY_MARKER"),
            "{label}: early span must contain its own body"
        );
        assert!(
            !early.contains("LATE_ONLY_MARKER"),
            "{label}: early span must not bleed into the later function"
        );

        let late = fn_span(src, "late_funnel")
            .unwrap_or_else(|| panic!("{label}: late_funnel span must be found"));
        assert!(
            late.starts_with("    async fn late_funnel("),
            "{label}: late span must begin EXACTLY at its OWN signature — under \
             the old `len() + 1` arithmetic this drifted backwards by one byte \
             per preceding line on CRLF. Got: {:?}",
            &late[..late.len().min(60)]
        );
        assert!(
            late.contains("LATE_ONLY_MARKER"),
            "{label}: late span must contain its own body"
        );
        assert!(
            !late.contains("EARLY_ONLY_MARKER"),
            "{label}: late span must NOT contain the earlier function's body"
        );
        // The span must also END exactly at its closing brace line.
        assert!(
            late.trim_end().ends_with("    }"),
            "{label}: late span must end at its own closing brace"
        );
    }
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
