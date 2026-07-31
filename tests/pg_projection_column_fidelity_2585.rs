// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2585 — the postgres `memories` READ-projection drift gate.
//!
//! # The defect this closes
//!
//! Every postgres read that maps a `memories` row into a [`Memory`] used
//! `SELECT *`, fetching all 43 columns and discarding 12. Two are large:
//! `embedding` (a `vector(N)`; 3,082 B/row at 768 dims, and the fleet has run
//! 3072-dim models) and `tsv` (a `GENERATED ALWAYS … STORED` tsvector,
//! measured at **459 B/row in the binary wire format on the live corpus —
//! larger than `content`**). Real wire bytes measured with `COPY … BINARY`
//! (n=500): **4,527 → 1,016 B/row (−77.6%)** with embeddings present and
//! **2,008 → 1,269 B/row (−36%)** on a corpus with none.
//!
//! That second number is why #2585's own framing — "latent, zero measured
//! impact on an unembedded corpus" — was too kind to the defect: the `tsv`
//! waste is paid today, on every row of every list / search / recall.
//!
//! # What this file guards
//!
//! `MEMORY_READ_COLUMNS` and `row_to_memory_with_policy` can drift apart in
//! BOTH directions, and each direction is a distinct data-integrity bug:
//!
//!   * a column in the MAPPER but not the PROJECTION → the read fails at
//!     runtime with `42703 undefined_column` (loud, but only in production);
//!   * a column added to the TABLE and to the MAPPER but not the PROJECTION →
//!     same;
//!   * a column silently DROPPED from the projection → the mapper's
//!     `.unwrap_or(...)` tolerance turns it into a **silently wrong value**
//!     presented as fact, which is the shape that must never ship.
//!
//! The guards below need NO live database and NO network — they parse the
//! shipped DDL and compare it against the shipped constant — so they run
//! wherever the `sal-postgres` feature is compiled (CI's "Postgres feature
//! gate" leg), on every PR, in milliseconds. They are modelled on the sqlite
//! twin `tests/federation_catchup_column_fidelity_2384.rs`, which pins the
//! identical 31-column list for `storage::memories_updated_since`.
//!
//! R-203: at the parent commit `MEMORY_READ_COLUMNS` does not exist, so this
//! file does not compile there — the fail-at-parent evidence is the
//! projection-vs-DDL census in `projection_is_subset_of_live_ddl`, which goes
//! red the moment a name is dropped or mistyped.

#![cfg(feature = "sal-postgres")]

use std::collections::BTreeSet;

/// The postgres bootstrap DDL — the authoritative column list for `memories`.
/// Anchoring the census to the DDL (not to the mapper) is deliberate: an
/// author who adds a column and typos it IDENTICALLY in the projection and the
/// mapper would satisfy any projection-vs-mapper comparison and fail only at
/// runtime. The DDL is the one artifact postgres itself agrees with.
const PG_SCHEMA_SQL: &str = include_str!("../src/store/postgres_schema.sql");

/// The 31 columns [`ai_memory::store::postgres::MEMORY_READ_COLUMNS`] projects,
/// restated here so the test is not a tautology over the constant it guards.
/// 30 `Memory` struct fields + `encrypted_envelope` (the #2303 at-rest decrypt
/// input, not a struct field).
const PROJECTED_COLUMNS: &[&str] = &[
    "id",
    "tier",
    "namespace",
    "title",
    "content",
    "tags",
    "priority",
    "confidence",
    "source",
    "access_count",
    "created_at",
    "updated_at",
    "last_accessed_at",
    "expires_at",
    "metadata",
    "reflection_depth",
    "memory_kind",
    "entity_id",
    "persona_version",
    "citations",
    "source_uri",
    "source_span",
    "confidence_source",
    "confidence_signals",
    "confidence_decayed_at",
    "version",
    "lifecycle_state",
    "cid",
    "valid_from",
    "valid_until",
    "encrypted_envelope",
];

/// Every `memories` column deliberately EXCLUDED from the read projection,
/// each with the reason it is safe to omit. A new column MUST be classified
/// into this list or into [`PROJECTED_COLUMNS`] — the census below fails
/// otherwise, which is the whole point: a future migration's column cannot
/// escape the decision by default.
const DERIVED_OR_INTERNAL_COLUMNS: &[(&str, &str)] = &[
    (
        "embedding",
        "derived + regenerable from the durable text (North Star); the semantic \
         pool scores it SERVER-side via `embedding <=> $1` and never reads the \
         raw column, the mapper never touches it. 3,082 B/row at 768 dims.",
    ),
    (
        "embedding_dim",
        "storage-internal write-boundary guard; not a `Memory` field.",
    ),
    (
        "embedding_space",
        "#2167 provenance stamp; consumed as the SQL predicate \
         `embedding_space = $fp`, never mapped into `Memory`.",
    ),
    (
        "tsv",
        "GENERATED ALWAYS … STORED tsvector, re-derivable from title+content; \
         consumed as `tsv @@ …` / `ts_rank(tsv, …)` SERVER-side. 459 B/row on \
         the wire — the single largest saving on an unembedded corpus.",
    ),
    (
        "scope_idx",
        "GENERATED STORED projection of `metadata->>'scope'`; `metadata` itself \
         IS projected, so the value is not lost.",
    ),
    (
        "agent_id_idx",
        "GENERATED STORED projection of `metadata->>'agent_id'`; `metadata` is \
         projected.",
    ),
    (
        "target_agent_id_idx",
        "GENERATED STORED projection of `metadata->>'target_agent_id'`; \
         `metadata` is projected.",
    ),
    (
        "atomised_into",
        "storage-internal atomisation counter; not a `Memory` field.",
    ),
    (
        "atom_of",
        "storage-internal atom→parent pointer; not a `Memory` field.",
    ),
    (
        "mentioned_entity_id",
        "storage-internal reflection index; re-derived from the mapped `Memory` \
         by `extract_mentioned_entity_id`, never read off the row.",
    ),
    (
        "cid_genesis",
        "#1825 verify-path-only pre-image, read on demand by `verify`; NULLed on \
         erasure. Not a `Memory` field.",
    ),
    (
        "kind_provenance",
        "#1945 denormalised copy whose durable home is the `metadata` carrier, \
         which IS projected.",
    ),
];

/// Parse the `memories` column names out of the postgres bootstrap DDL.
fn ddl_memories_columns() -> BTreeSet<String> {
    let start = PG_SCHEMA_SQL
        .find("CREATE TABLE IF NOT EXISTS memories (")
        .expect("#2585: postgres_schema.sql must declare `memories`");
    let body = &PG_SCHEMA_SQL[start..];
    let end = body
        .find("\n);")
        .expect("#2585: unterminated `memories` CREATE TABLE");
    let body = &body[..end];

    let mut cols = BTreeSet::new();
    // Track parenthesis depth so a column-list inside a GENERATED / CHECK
    // expression cannot be mistaken for a column declaration.
    let mut depth: i32 = 0;
    for raw in body.lines().skip(1) {
        let line = raw.trim();
        let opens = i32::try_from(line.matches('(').count()).unwrap_or(0);
        let closes = i32::try_from(line.matches(')').count()).unwrap_or(0);
        let depth_at_line_start = depth;
        depth += opens - closes;

        if depth_at_line_start != 0 || line.is_empty() || line.starts_with("--") {
            continue;
        }
        let Some(first) = line.split_whitespace().next() else {
            continue;
        };
        // Skip table-level constraint clauses.
        if first.eq_ignore_ascii_case("CONSTRAINT")
            || first.eq_ignore_ascii_case("CHECK")
            || first.eq_ignore_ascii_case("PRIMARY")
            || first.eq_ignore_ascii_case("UNIQUE")
            || first.eq_ignore_ascii_case("FOREIGN")
        {
            continue;
        }
        if first
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            && !first.is_empty()
        {
            cols.insert(first.to_string());
        }
    }
    cols
}

/// G1 — COLUMN CENSUS. Every `memories` column must be classified as either
/// projected or documented-derived. A migration that adds a 44th column and
/// forgets the projection turns this red and forces an explicit decision.
#[test]
fn every_memories_column_is_projected_or_documented_derived() {
    let ddl = ddl_memories_columns();
    assert!(
        ddl.len() > 30,
        "#2585: parsed only {} columns out of the memories DDL — the parser is \
         broken, which would make this census vacuously pass. Fail closed.",
        ddl.len()
    );

    let projected: BTreeSet<&str> = PROJECTED_COLUMNS.iter().copied().collect();
    let derived: BTreeSet<&str> = DERIVED_OR_INTERNAL_COLUMNS
        .iter()
        .map(|(c, _)| *c)
        .collect();

    let unclassified: Vec<&String> = ddl
        .iter()
        .filter(|c| !projected.contains(c.as_str()) && !derived.contains(c.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "#2585: these `memories` columns are neither in the read projection nor \
         documented as derived/internal: {unclassified:?}.\n\
         Add each to PROJECTED_COLUMNS **and** to \
         `store::postgres::MEMORY_READ_COLUMNS` (if the row mapper reads it), or \
         to DERIVED_OR_INTERNAL_COLUMNS with the reason it is safe to omit. A \
         column that is mapped but not projected fails at runtime with 42703; a \
         column silently dropped from the projection surfaces the mapper's \
         `.unwrap_or(...)` default as if it were the stored fact."
    );
}

/// G2 — the projection is a SUBSET of the real schema. Catches a typo in the
/// projection alone, which G1 cannot see (an unknown name is simply absent
/// from the DDL set, so it never shows up as "unclassified").
#[test]
fn projection_is_subset_of_live_ddl() {
    let ddl = ddl_memories_columns();
    let bogus: Vec<&&str> = PROJECTED_COLUMNS
        .iter()
        .filter(|c| !ddl.contains(**c))
        .collect();
    assert!(
        bogus.is_empty(),
        "#2585: the read projection names columns that do not exist on \
         `memories`: {bogus:?}. Postgres would reject every list / search / \
         recall / get with 42703."
    );
}

/// G3 — the constant IS the list. Keeps the test data and the shipped SQL from
/// drifting apart, which would make G1/G2 assert about something the adapter
/// does not actually execute.
#[test]
fn constant_matches_the_documented_projection() {
    let from_const: Vec<String> = ai_memory::store::postgres::MEMORY_READ_COLUMNS
        .split(',')
        .map(|c| c.trim().to_string())
        .collect();
    let expected: Vec<String> = PROJECTED_COLUMNS.iter().map(|c| (*c).to_string()).collect();
    assert_eq!(
        from_const, expected,
        "#2585: `MEMORY_READ_COLUMNS` and this file's PROJECTED_COLUMNS have \
         drifted. They must be updated together."
    );
    assert_eq!(
        PROJECTED_COLUMNS.len(),
        31,
        "#2585: the projection is 31 columns — the 30 `Memory` fields plus \
         `encrypted_envelope`, the #2303 decrypt input."
    );
}

/// G4 — `Memory::FIELD_COUNT` pin. This is the guard that fires on the exact
/// drift scenario: adding a field to `Memory` reds HERE, which forces the
/// author to the projection and to G1. Without it, a new field could be mapped
/// from a new column that nobody added to the projection.
#[test]
fn memory_field_count_pin() {
    assert_eq!(
        ai_memory::models::Memory::FIELD_COUNT,
        30,
        "#2585: `Memory` gained or lost a field. If it is backed by a new \
         `memories` column, that column MUST be added to \
         `store::postgres::MEMORY_READ_COLUMNS`, to PROJECTED_COLUMNS here, and \
         to the sqlite twin `storage::memories_updated_since`'s COLS — otherwise \
         the read projection drops it and the mapper reports its default as \
         fact."
    );
}

/// G5 — `encrypted_envelope` is load-bearing and must never be "tidied" out of
/// the projection as a non-`Memory`-field. Without it the #2303 decrypt cannot
/// run, and a sealed row reads (and, on the federation SEND path, RELAYS) as
/// the `content = ""` sentinel — silent, unrecoverable content loss.
#[test]
fn encrypted_envelope_stays_in_the_projection() {
    assert!(
        ai_memory::store::postgres::MEMORY_READ_COLUMNS.contains("encrypted_envelope"),
        "#2585/#2303: `encrypted_envelope` MUST stay in the read projection. It \
         is not a `Memory` field, but it is the at-rest decrypt input: without \
         it every sealed row maps to the empty-content sentinel instead of its \
         plaintext, and `list_memories_updated_since` would relay that sentinel \
         to federation peers, who would re-seal an empty string under their own \
         key."
    );
    // The columns the projection must NOT carry, for the reason it exists.
    for omitted in ["embedding", "tsv"] {
        assert!(
            !ai_memory::store::postgres::MEMORY_READ_COLUMNS.contains(omitted),
            "#2585: `{omitted}` is back in the read projection — that is the \
             defect this constant exists to prevent. It is derived, \
             regenerable, never read by the row mapper, and the single largest \
             per-row wire cost."
        );
    }
}
