// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #2567 — the postgres daemon-bootstrap auto-migrate must NOT NULL
//! stored embeddings when no embedder is constructible to regenerate them.
//!
//! ## Why a source-inspection test
//!
//! The live behavioural proof lives in `tests/embedding_dim_migration.rs`
//! (`auto_migrate_preserves_embeddings_without_embedder_2567` /
//! `auto_migrate_nulls_embeddings_with_embedder_2567`), gated behind
//! `feature = "sal-postgres"` + `AI_MEMORY_TEST_POSTGRES_URL`, so on a host
//! with no live `Postgres` they self-skip and the fix is effectively
//! uncovered. This file closes that gap the way the `qual_*` family already
//! does (`tests/qual_pg_write_funnel_parity_2393_2397.rs`): it reads the
//! adapter source off disk and asserts, on EVERY `cargo test` run with zero
//! infrastructure, that
//!
//! 1. the destructive `migrate_embedding_dim(dim, true)` in the
//!    `connect_with_dim_and_timeout_auto_migrate` funnel is GATED behind an
//!    `embedder_available` check that PRESERVES the vectors + WARNs when no
//!    embedder exists (the #2567 fix, defense-in-depth AT the funnel), and
//! 2. the `SQLite` adapter has NO destructive embedding-dim-migrate path at
//!    all — the cross-backend invariant (#2488 "assert both backends"):
//!    `SQLite` stores embeddings dim-agnostically as a BLOB and must never
//!    gain a boot-time "NULL every embedding on a dim mismatch" funnel.
//!
//! ## What it does NOT prove (honest scope)
//!
//! A source-token assertion proves the guard is present and ordered before
//! the destructive call; it does NOT prove the runtime boolean threaded from
//! `build_store_handle` is the correct one on every boot topology — that is
//! the live-PG test's job. This pin is NECESSARY BUT NOT SUFFICIENT, and is
//! explicitly ADDITIVE to (never a replacement for) the `sal-postgres`
//! functional tests. Degrade, never corrupt: a mechanical pin that catches
//! the whole gate-removal class on every run beats a functional test that
//! catches everything but runs almost never.

#![allow(clippy::missing_panics_doc)]

/// The postgres SAL adapter, relative to `CARGO_MANIFEST_DIR`.
const PG_ADAPTER_PATH: &str = "src/store/postgres.rs";

/// The sqlite SAL adapter, relative to `CARGO_MANIFEST_DIR`.
const SQLITE_ADAPTER_PATH: &str = "src/store/sqlite.rs";

/// The daemon-bootstrap auto-migrate funnel whose destructive branch #2567
/// gates on embedder-constructibility.
const AUTO_MIGRATE_FN: &str = "connect_with_dim_and_timeout_auto_migrate";

/// The new #2567 gate parameter.
const EMBEDDER_AVAILABLE_PARAM: &str = "embedder_available";

/// The destructive call the gate must guard.
const DESTRUCTIVE_CALL: &str = "migrate_embedding_dim(dim, true)";

/// The early-return guard that skips the destructive migrate.
const PRESERVE_GUARD: &str = "if !embedder_available";

/// A distinctive token from the preserve WARN so the degrade path stays
/// loud (an operator MUST see WHY recall degraded).
const PRESERVE_WARN_TOKEN: &str = "PRESERVING stored embeddings";

fn read_source(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    // Normalise CRLF -> LF once at ingest so downstream token/offset scans
    // are line-ending-immune (the `qual_pg_write_funnel_parity` lesson).
    raw.replace("\r\n", "\n")
}

/// Extract the source span of the FIRST `impl`-level `pub async fn` named
/// `name`. Signatures start at exactly four spaces; the body terminator is a
/// line that is exactly `    }`. Returns `None` on a rename so it fails loud
/// rather than vacuously. Byte offsets come from real slice lengths
/// (`split_inclusive('\n')`) so LF / CRLF / final-line-no-terminator are all
/// exact (the `qual_pg_write_funnel_parity` CRLF-drift lesson).
fn fn_span<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let sig_a = format!("    async fn {name}(");
    let sig_b = format!("    pub async fn {name}(");

    let mut lines: Vec<(usize, usize, &str)> = Vec::new();
    let mut offset = 0usize;
    for raw in src.split_inclusive('\n') {
        let start = offset;
        offset += raw.len();
        let content = raw.strip_suffix('\n').unwrap_or(raw);
        let content = content.strip_suffix('\r').unwrap_or(content);
        lines.push((start, offset, content));
    }

    let start = lines
        .iter()
        .position(|(_, _, l)| l.starts_with(&sig_a) || l.starts_with(&sig_b))?;
    let end = lines[start + 1..]
        .iter()
        .position(|(_, _, l)| *l == "    }")
        .map(|off| start + 1 + off)?;
    Some(&src[lines[start].0..lines[end].1])
}

/// The span extractor is load-bearing — prove it works before trusting it,
/// else every assertion below could pass vacuously.
#[test]
fn fn_span_extracts_the_auto_migrate_funnel() {
    let pg = read_source(PG_ADAPTER_PATH);
    let span = fn_span(&pg, AUTO_MIGRATE_FN).unwrap_or_else(|| {
        panic!("#2567: could not locate `{AUTO_MIGRATE_FN}` in {PG_ADAPTER_PATH} — renamed?")
    });
    assert!(
        span.contains(DESTRUCTIVE_CALL),
        "#2567: the extracted `{AUTO_MIGRATE_FN}` span must still contain the destructive \
         `{DESTRUCTIVE_CALL}` call; if not, the span bounds are wrong and every gate assertion \
         below is vacuous"
    );
}

/// #2567 — the destructive migrate MUST be gated on embedder-availability,
/// and the no-embedder branch MUST preserve + WARN. The gate is defense in
/// depth AT the funnel: no present or future caller can NULL the stored
/// embeddings without a proven regeneration path.
#[test]
fn pg_auto_migrate_gates_destructive_null_on_embedder_available_2567() {
    let pg = read_source(PG_ADAPTER_PATH);
    let span = fn_span(&pg, AUTO_MIGRATE_FN)
        .unwrap_or_else(|| panic!("#2567: `{AUTO_MIGRATE_FN}` not found in {PG_ADAPTER_PATH}"));

    assert!(
        span.contains(EMBEDDER_AVAILABLE_PARAM),
        "#2567: `{AUTO_MIGRATE_FN}` must take/consult `{EMBEDDER_AVAILABLE_PARAM}` — the gate is gone"
    );
    assert!(
        span.contains(PRESERVE_GUARD),
        "#2567: `{AUTO_MIGRATE_FN}` must carry the `{PRESERVE_GUARD}` preserve guard"
    );
    assert!(
        span.contains(PRESERVE_WARN_TOKEN),
        "#2567: the no-embedder preserve branch must WARN loudly (token `{PRESERVE_WARN_TOKEN}`) so \
         an operator sees why recall degraded"
    );

    // Ordering: the preserve guard MUST precede the destructive call, i.e.
    // the code checks `!embedder_available` and returns BEFORE it could ever
    // reach `migrate_embedding_dim(dim, true)`. A guard that sits AFTER the
    // destructive call would be no guard at all.
    let guard_at = span
        .find(PRESERVE_GUARD)
        .expect("guard token presence already asserted");
    let destructive_at = span
        .find(DESTRUCTIVE_CALL)
        .expect("destructive call presence already asserted (fn_span probe)");
    assert!(
        guard_at < destructive_at,
        "#2567: the `{PRESERVE_GUARD}` guard (offset {guard_at}) MUST precede the destructive \
         `{DESTRUCTIVE_CALL}` (offset {destructive_at}) so the no-embedder path returns before it \
         can NULL any vector"
    );
}

/// #2567 cross-backend invariant (#2488 "assert BOTH backends"). `SQLite`
/// stores embeddings dim-agnostically as a BLOB and has NO destructive
/// dim-migrate funnel — so it can NEVER NULL embeddings on a boot-time dim
/// mismatch without an embedder (the pg-only defect this issue fixes). Pin
/// that asymmetry structurally: if a future change adds a
/// `migrate_embedding_dim` / auto-migrate destructive path to the `SQLite`
/// adapter, it must carry the SAME embedder-availability gate (and this
/// test must be extended to assert it), not silently regress the class onto
/// the second backend.
#[test]
fn sqlite_has_no_destructive_embedding_dim_migrate_2567() {
    let sqlite = read_source(SQLITE_ADAPTER_PATH);
    assert!(
        !sqlite.contains("migrate_embedding_dim"),
        "#2567/#2488: the SQLite adapter ({SQLITE_ADAPTER_PATH}) must NOT contain a \
         `migrate_embedding_dim` destructive-dim path — SQLite stores embeddings as a \
         dim-agnostic BLOB and must never gain a boot-time 'NULL every embedding on a dim \
         mismatch' funnel. If one is added, it MUST be gated on embedder-availability the same \
         way the postgres funnel is, and this guard extended to assert it."
    );
    assert!(
        !sqlite.contains(AUTO_MIGRATE_FN),
        "#2567/#2488: the SQLite adapter ({SQLITE_ADAPTER_PATH}) must NOT grow an \
         `{AUTO_MIGRATE_FN}` funnel — the destructive auto-migrate is a postgres-only path by \
         design (SqliteStore::open takes no dim and never mass-mutates the embedding column)."
    );
}
