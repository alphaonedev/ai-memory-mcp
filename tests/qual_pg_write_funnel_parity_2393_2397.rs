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

// #4023: ONE shared loader reads `postgres.rs` AND every child module under
// `src/store/postgres/` (fail closed on an empty / short file set).
#[path = "common/pg_sources.rs"]
mod pg_sources;

/// The postgres SAL adapter root, relative to `CARGO_MANIFEST_DIR`. The
/// scanned source is the root PLUS every child module (see `pg_sources`).
const PG_ADAPTER_PATH: &str = pg_sources::PG_ROOT_REL;

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

/// #9018 — the archive-first consolidate-source helper. It is itself an
/// `AGE_UNPROJECT_FUNNELS` entry (so its own span must call
/// [`AGE_UNPROJECT_CALL`]); a funnel whose hard-DELETE is delegated to it
/// unprojects through it.
const ARCHIVE_CONSOLIDATE_ROUTE: &str = "archive_consolidate_source_in_tx(";

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
///
/// #9178 A — each entry pins the EXACT [`InsertOps`] of its span (equality,
/// not `contains`), so a second `INSERT INTO memories` added beside the
/// provenance-bound one is red even though the column and bind still appear.
const KIND_PROVENANCE_FUNNELS: &[(&str, InsertOps)] = &[
    // Already correct before #2393 — pinned so they cannot regress.
    ("store", InsertOps::BOUND_ONCE),
    ("store_batch", InsertOps::BOUND_ONCE), // #2289
    // #4447 — `archive_restore` is now a thin delegator to the inherent
    // `archive_restore_inner` (moved verbatim to
    // `postgres/federation_by_id_4447.rs` to gain the in-transaction peer-scope
    // re-check). The guard follows the INSERT..SELECT to the function that owns
    // it, the same move as `store_with_embedding_inner` above (#2771).
    ("archive_restore_inner", InsertOps::CARRIED_ONCE), // #2333 / FBL-03
    // Fixed by #2393 — the three funnels the issue named…
    // #2771 — `store_with_embedding` was refactored into a thin delegator to the
    // shared inherent `store_with_embedding_inner`, which now holds the INSERT +
    // every column bind. BOTH create funnels (`store_with_embedding` merge +
    // `store_with_embedding_no_overwrite` fail-closed) delegate to it, so the
    // provenance-bind guard follows the INSERT to `_inner` — strictly stronger,
    // since it now also covers the no-overwrite arm's bind.
    ("store_with_embedding_inner", InsertOps::BOUND_ONCE),
    ("capture_turn_idempotent", InsertOps::BOUND_ONCE),
    ("recover_turn_idempotent", InsertOps::BOUND_ONCE),
    // …and the three the completeness sweep found that it did not.
    ("update_with_archive_on_supersede", InsertOps::BOUND_ONCE),
    ("reflect_with_hooks", InsertOps::BOUND_ONCE),
    ("apply_remote_memory", InsertOps::BOUND_ONCE),
];

/// #9178 A — the `memories` INSERTs of one function span, counted in code
/// with comments stripped (SQL string text kept).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InsertOps {
    /// `INSERT INTO memories` statements.
    inserts: usize,
    /// `extract_kind_provenance(` bind calls.
    provenance_binds: usize,
}

impl InsertOps {
    /// One INSERT, provenance bound through the vocab-validating SSOT.
    const BOUND_ONCE: Self = Self {
        inserts: 1,
        provenance_binds: 1,
    };
    /// One `INSERT ... SELECT` that carries the column from the archive row.
    const CARRIED_ONCE: Self = Self {
        inserts: 1,
        provenance_binds: 0,
    };
    const NONE: Self = Self {
        inserts: 0,
        provenance_binds: 0,
    };
}

/// #9178 A — the hard-DELETE routes of one function span (comments
/// stripped, the signature line excluded so a function never counts itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeleteOps {
    /// `DELETE FROM memories` statements plus `SQL_DELETE_MEMORY_BY_ID` uses.
    bare_deletes: usize,
    /// In-transaction [`AGE_UNPROJECT_CALL`] calls.
    in_tx_unprojects: usize,
    /// Pool-direct `unproject_memory_ids_best_effort(` calls.
    best_effort_unprojects: usize,
    /// Delegations to the #9018 helper ([`ARCHIVE_CONSOLIDATE_ROUTE`]).
    archive_routes: usize,
}

impl DeleteOps {
    /// One bare DELETE unprojected in the same transaction.
    const IN_TX_ONCE: Self = Self {
        bare_deletes: 1,
        in_tx_unprojects: 1,
        best_effort_unprojects: 0,
        archive_routes: 0,
    };
    const NONE: Self = Self {
        bare_deletes: 0,
        in_tx_unprojects: 0,
        best_effort_unprojects: 0,
        archive_routes: 0,
    };

    /// Every bare DELETE has an unprojection, and the span deletes somehow.
    fn unprojects_every_delete(self) -> bool {
        self.bare_deletes <= self.in_tx_unprojects + self.best_effort_unprojects
            && self.bare_deletes + self.best_effort_unprojects + self.archive_routes > 0
    }
}

/// Funnels that persist `kind_provenance` through an `INSERT ... SELECT` over
/// the archive table rather than a Rust-side bind (they still must name the
/// column). One list for the named-funnel pin AND the child-module sweep.
const INSERT_SELECT_CARRIERS: &[&str] = &["archive_restore", "archive_restore_inner"];

/// Every postgres funnel that hard-DELETEs a live `memories` row and MUST
/// therefore unproject it from the AGE `memory_graph` projection.
/// `update_with_archive_on_supersede` is the #2397 net-new arm; the rest
/// were already correct (`archive_by_ids` by #2315) and are pinned here so
/// the class stays closed.
///
/// #9178 A — each entry pins the EXACT [`DeleteOps`] of its span (equality,
/// not `contains`): a bare `DELETE FROM memories` added beside an
/// unprojecting route changes the tuple and is red.
const AGE_UNPROJECT_FUNNELS: &[(&str, DeleteOps)] = &[
    (
        "delete",
        DeleteOps {
            best_effort_unprojects: 2,
            ..DeleteOps::NONE
        },
    ),
    // #4447 — `apply_remote_deletion` is a thin delegator to
    // `apply_remote_deletion_inner` (moved to `postgres/federation_by_id_4447.rs`);
    // the guard follows the DELETE to the function that owns it.
    (
        "apply_remote_deletion_inner",
        DeleteOps {
            best_effort_unprojects: 1,
            ..DeleteOps::NONE
        },
    ),
    ("forget", DeleteOps::IN_TX_ONCE),
    // #4045/#4046/#4047 — `consolidate` was refactored into a thin delegator to
    // `consolidate_with_expected_versions`, which now holds the hard-DELETE of
    // the source rows and their AGE unprojection. The guard follows the DELETE
    // to the function that owns it (same move as `store_with_embedding_inner`
    // above for #2771); the wrapper deletes nothing itself.
    (
        "consolidate_with_expected_versions",
        DeleteOps {
            archive_routes: 1,
            ..DeleteOps::NONE
        },
    ),
    // #9018 — the legacy (tombstone sub-flag OFF) source disposition moved
    // into the archive-first helper in `postgres/consolidate_archive_9018.rs`,
    // which now owns the `DELETE FROM memories` and its AGE unprojection.
    // The guard follows the DELETE to the helper, and the caller above must
    // route through it (`ARCHIVE_CONSOLIDATE_ROUTE`).
    ("archive_consolidate_source_in_tx", DeleteOps::IN_TX_ONCE),
    ("run_gc", DeleteOps::IN_TX_ONCE),
    ("size_gc", DeleteOps::IN_TX_ONCE),
    // #4447 — `archive_by_ids` delegates to `archive_by_ids_inner` (moved).
    ("archive_by_ids_inner", DeleteOps::IN_TX_ONCE),
    ("update_with_archive_on_supersede", DeleteOps::IN_TX_ONCE), // #2397 (N17)
];

/// #9178 A (sibling) — the EXACT set of child-module functions that write a
/// `memories` row, with their exact ops. Before #9178 the child sweep only
/// checked `contains` per function and its doc claimed no child wrote at all.
const CHILD_MEMORIES_WRITERS: &[(&str, &str, InsertOps, DeleteOps)] = &[
    (
        "src/store/postgres/consolidate_archive_9018.rs",
        "archive_consolidate_source_in_tx",
        InsertOps::NONE,
        DeleteOps::IN_TX_ONCE,
    ),
    (
        "src/store/postgres/federation_by_id_4447.rs",
        "archive_by_ids_inner",
        InsertOps::NONE,
        DeleteOps::IN_TX_ONCE,
    ),
    (
        "src/store/postgres/federation_by_id_4447.rs",
        "archive_restore_inner",
        InsertOps::CARRIED_ONCE,
        DeleteOps::NONE,
    ),
];

fn adapter_source() -> String {
    // Every adapter file (root first, then each child module), CRLF
    // normalised to LF at the single ingest point inside the shared loader,
    // so no downstream consumer in this file has to reason about line endings.
    // `fn_span` below is independently CRLF-correct. Taking the FIRST match
    // keeps `postgres.rs` ahead of any child.
    pg_sources::pg_adapter_concat()
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
    // #4447 — methods moved into child modules are `pub(super)` / `pub(crate)`.
    let sig_c = format!("    pub(super) async fn {name}(");
    let sig_d = format!("    pub(crate) async fn {name}(");

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
    let start = lines.iter().position(|(_, _, l)| {
        l.starts_with(&sig_a)
            || l.starts_with(&sig_b)
            || l.starts_with(&sig_c)
            || l.starts_with(&sig_d)
    })?;
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
    for (name, pinned) in KIND_PROVENANCE_FUNNELS {
        let Some(span) = fn_span(&src, name) else {
            missing.push(format!("  {name}: function not found in {PG_ADAPTER_PATH}"));
            continue;
        };
        let code = strip_comments(span);
        if !code.contains(KIND_PROVENANCE_COLUMN) {
            missing.push(format!(
                "  {name}: SQL does not mention the `{KIND_PROVENANCE_COLUMN}` column"
            ));
        }
        // #9178 A: the exact op tuple, never a `contains` — an extra INSERT
        // beside the bound one is red. `archive_restore` carries the column
        // through an INSERT ... SELECT over `archived_memories` (with a
        // metadata-carrier COALESCE fallback for legacy pre-v87 archive rows),
        // so its pin is `CARRIED_ONCE` (no Rust-side bind).
        let observed = insert_ops(&code);
        if observed != *pinned {
            missing.push(format!(
                "  {name}: memories INSERT ops {observed:?}, pinned {pinned:?} — every \
                 INSERT needs its `{KIND_PROVENANCE_BIND}` bind or the v79/#1945 \
                 provenance is silently NULL on postgres"
            ));
        }
        let carrier = INSERT_SELECT_CARRIERS.contains(name);
        if observed.provenance_binds != if carrier { 0 } else { observed.inserts } {
            missing.push(format!(
                "  {name}: binds do not match INSERTs ({observed:?})"
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
    for (name, pinned) in AGE_UNPROJECT_FUNNELS {
        let Some(span) = fn_span(&src, name) else {
            missing.push(format!("  {name}: function not found in {PG_ADAPTER_PATH}"));
            continue;
        };
        // `delete` / `apply_remote_deletion` run pool-direct (no surrounding
        // tx) and route through the `unproject_memory_ids_best_effort`
        // wrapper, which calls the helper on their behalf. `consolidate`'s
        // legacy arm delegates its DELETE to the #9018 archive-first helper,
        // which is checked as its own funnel in this same loop. #9178 A: the
        // whole route tuple must EQUAL the pin, so a bare DELETE added beside
        // an unprojecting route is red (a `contains` accepted it).
        let observed = delete_ops(span);
        if observed != *pinned || !observed.unprojects_every_delete() {
            missing.push(format!(
                "  {name}: hard-delete ops {observed:?}, pinned {pinned:?} — a memories \
                 DELETE without its AGE unprojection leaves a ghost node kg_query serves"
            ));
        }
    }
    for (name, pinned) in AGE_UNPROJECT_FUNNELS {
        if !pinned.unprojects_every_delete() {
            missing.push(format!(
                "  {name}: the pin itself {pinned:?} leaves a DELETE bare"
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

/// Split one adapter file into `(fn name, body)` spans at every `fn` item
/// (any indentation), cutting the file at its first `#[cfg(test)]` item so
/// test fixtures are never swept.
fn child_fn_spans(text: &str) -> Vec<(String, String)> {
    let prod = text.split("\n#[cfg(test)]").next().unwrap_or(text);
    let mut out: Vec<(String, String)> = Vec::new();
    let mut cur: Option<(String, String)> = None;
    for line in prod.lines() {
        let t = line.trim_start();
        let t = t
            .strip_prefix("pub(crate) ")
            .or_else(|| t.strip_prefix("pub(super) "))
            .or_else(|| t.strip_prefix("pub "))
            .unwrap_or(t);
        let t = t.strip_prefix("async ").unwrap_or(t);
        if let Some(rest) = t.strip_prefix("fn ")
            && let Some(end) = rest.find(['(', '<'])
            && rest[..end].chars().all(|c| c.is_alphanumeric() || c == '_')
        {
            if let Some(done) = cur.take() {
                out.push(done);
            }
            cur = Some((rest[..end].to_string(), String::new()));
        }
        if let Some((_, body)) = cur.as_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(done) = cur.take() {
        out.push(done);
    }
    out
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// #9178 A — `src` with every `//` and (nested) `/* */` comment blanked to
/// spaces, newlines kept. String, raw-string and char literals are copied
/// verbatim (the SQL lives in them), so a `//` inside a string is not a
/// comment and a commented-out DELETE never counts.
fn strip_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let len = chars.len();
    let mut out = String::with_capacity(src.len());
    let mut pos = 0;
    let blank = |ch: char| if ch == '\n' { '\n' } else { ' ' };
    while pos < len {
        let next = chars.get(pos + 1).copied();
        if chars[pos] == '/' && next == Some('/') {
            while pos < len && chars[pos] != '\n' {
                out.push(' ');
                pos += 1;
            }
            continue;
        }
        if chars[pos] == '/' && next == Some('*') {
            let mut depth = 0usize;
            while pos < len {
                if chars[pos] == '/' && chars.get(pos + 1) == Some(&'*') {
                    depth += 1;
                    out.push_str("  ");
                    pos += 2;
                } else if chars[pos] == '*' && chars.get(pos + 1) == Some(&'/') {
                    depth -= 1;
                    out.push_str("  ");
                    pos += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(chars[pos]));
                    pos += 1;
                }
            }
            continue;
        }
        let after_ident = pos > 0 && is_ident_char(chars[pos - 1]);
        if chars[pos] == 'r' && !after_ident {
            let mut scan = pos + 1;
            while scan < len && chars[scan] == '#' {
                scan += 1;
            }
            if scan < len && chars[scan] == '"' {
                let hashes = scan - pos - 1;
                let mut close_at = scan + 1;
                while close_at < len
                    && !(chars[close_at] == '"'
                        && chars[close_at + 1..].iter().take(hashes).all(|h| *h == '#'))
                {
                    close_at += 1;
                }
                let end = (close_at + 1 + hashes).min(len);
                out.extend(&chars[pos..end]);
                pos = end;
                continue;
            }
        }
        if chars[pos] == '"' {
            let mut scan = pos + 1;
            while scan < len && chars[scan] != '"' {
                scan += if chars[scan] == '\\' { 2 } else { 1 };
            }
            let end = (scan + 1).min(len);
            out.extend(&chars[pos..end]);
            pos = end;
            continue;
        }
        if chars[pos] == '\'' && !after_ident {
            // A char literal (`'"'`, `'\''`); a lifetime falls through.
            let close = if next == Some('\\') {
                chars[pos + 2..]
                    .iter()
                    .position(|ch| *ch == '\'')
                    .map(|p| pos + 2 + p)
            } else {
                (chars.get(pos + 2) == Some(&'\'')).then_some(pos + 2)
            };
            if let Some(close) = close {
                out.extend(&chars[pos..=close]);
                pos = close + 1;
                continue;
            }
        }
        out.push(chars[pos]);
        pos += 1;
    }
    out
}

/// How often the SQL fragment `needle` occurs in `body` (whitespace-collapsed,
/// case-insensitive, whole word on the right).
fn count_sql(body: &str, needle: &str) -> usize {
    let norm = body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_uppercase();
    let needle = needle.to_uppercase();
    norm.match_indices(&needle)
        .filter(|(at, _)| {
            norm[at + needle.len()..]
                .chars()
                .next()
                .is_none_or(|c| !is_ident_char(c))
        })
        .count()
}

/// How often the identifier `ident` occurs in `body` as a whole token.
fn count_ident(body: &str, ident: &str) -> usize {
    body.match_indices(ident)
        .filter(|(at, _)| {
            let before = body[..*at].chars().next_back();
            let after = body[at + ident.len()..].chars().next();
            before.is_none_or(|c| !is_ident_char(c)) && after.is_none_or(|c| !is_ident_char(c))
        })
        .count()
}

/// The body of a span without its first (signature) line, comments stripped.
fn span_code(span: &str) -> String {
    strip_comments(span.split_once('\n').map_or("", |(_, rest)| rest))
}

/// The exact `memories` INSERT tuple of comment-stripped code.
fn insert_ops(code: &str) -> InsertOps {
    InsertOps {
        inserts: count_sql(code, "INSERT INTO memories"),
        provenance_binds: code.matches(KIND_PROVENANCE_BIND).count(),
    }
}

/// The exact hard-DELETE tuple of one function span.
fn delete_ops(span: &str) -> DeleteOps {
    let code = span_code(span);
    DeleteOps {
        bare_deletes: count_sql(&code, "DELETE FROM memories")
            + count_ident(&code, "SQL_DELETE_MEMORY_BY_ID"),
        in_tx_unprojects: code.matches(AGE_UNPROJECT_CALL).count(),
        best_effort_unprojects: code.matches("unproject_memory_ids_best_effort(").count(),
        archive_routes: code.matches(ARCHIVE_CONSOLIDATE_ROUTE).count(),
    }
}

/// #4023 — child modules are NOT a blind spot. The two named-funnel lists
/// above pin specific `postgres.rs` functions; a write funnel added to (or
/// moved into) a `src/store/postgres/*.rs` child module would never be named
/// there. So every function in a child module that INSERTs a `memories` row
/// must bind `kind_provenance` (#2393), and every one that hard-DELETEs a
/// `memories` row must unproject it from AGE (#2397). #9178 A: the set of
/// child functions that write a `memories` row, with their exact op tuples,
/// must EQUAL [`CHILD_MEMORIES_WRITERS`] (three today), so a new writer, an
/// extra bare DELETE or a dropped bind is red. The loader asserts the child
/// set is non-empty and contains the expected modules, so this cannot pass
/// vacuously.
#[test]
fn pg_child_module_memories_writes_obey_2393_2397_4023() {
    let sources = pg_sources::pg_adapter_sources();
    let children: Vec<&pg_sources::PgSource> = sources
        .iter()
        .filter(|s| s.rel != PG_ADAPTER_PATH)
        .collect();
    assert!(
        children.len() >= pg_sources::EXPECTED_CHILDREN.len(),
        "child scan saw only {} files — the sweep would be vacuous",
        children.len()
    );
    let mut observed: Vec<(String, String, InsertOps, DeleteOps)> = Vec::new();
    let mut violations: Vec<String> = Vec::new();
    for child in children {
        for (name, body) in child_fn_spans(&child.text) {
            let code = span_code(&body);
            let ins = insert_ops(&code);
            let del = delete_ops(&body);
            if ins.inserts == 0 && del.bare_deletes == 0 {
                continue;
            }
            let carrier = INSERT_SELECT_CARRIERS.contains(&name.as_str());
            if ins.inserts > 0
                && !(code.contains(KIND_PROVENANCE_COLUMN)
                    && ins.provenance_binds == if carrier { 0 } else { ins.inserts })
            {
                violations.push(format!(
                    "  {}::{name}: INSERTs a memories row without the kind_provenance \
                     column + `{KIND_PROVENANCE_BIND}` bind (#2393): {ins:?}",
                    child.rel
                ));
            }
            if del.bare_deletes > 0 && !del.unprojects_every_delete() {
                violations.push(format!(
                    "  {}::{name}: hard-DELETEs a memories row without AGE \
                     unprojection (#2397): {del:?}",
                    child.rel
                ));
            }
            observed.push((child.rel.clone(), name, ins, del));
        }
    }
    let pinned: Vec<(String, String, InsertOps, DeleteOps)> = CHILD_MEMORIES_WRITERS
        .iter()
        .map(|(rel, name, ins, del)| ((*rel).to_string(), (*name).to_string(), *ins, *del))
        .collect();
    observed.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    assert_eq!(
        observed, pinned,
        "#9178 A: the child-module memories writers must equal CHILD_MEMORIES_WRITERS \
         exactly (a new writer or an extra INSERT/DELETE is red)"
    );
    assert!(
        violations.is_empty(),
        "#4023: child-module write funnels violate the #2393/#2397 parity pins:\n{}",
        violations.join("\n")
    );
}

/// #4447 — `fn_span` finds methods whose visibility is `pub(super)` /
/// `pub(crate)` (the moved federation by-id bodies), and still bounds them.
#[test]
fn fn_span_matches_restricted_visibility_methods_4447() {
    let src = concat!(
        "impl PostgresStore {\n",
        "    pub(super) async fn moved_funnel(\n",
        "        &self,\n",
        "    ) -> Result<()> {\n",
        "        let marker = \"MOVED_ONLY_MARKER\";\n",
        "        Ok(())\n",
        "    }\n",
        "\n",
        "    pub(crate) async fn next_funnel(&self) -> Result<()> {\n",
        "        Ok(())\n",
        "    }\n",
        "}\n",
    );
    let span = fn_span(src, "moved_funnel").expect("pub(super) method must be found");
    assert!(span.contains("MOVED_ONLY_MARKER"));
    assert!(!span.contains("next_funnel"), "span must not bleed");
    assert!(
        fn_span(src, "next_funnel").is_some(),
        "pub(crate) method must be found"
    );
}
