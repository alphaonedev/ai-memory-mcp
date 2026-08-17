// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #3014 — the attestation FUNNEL ceiling.
//!
//! # The defect this closes
//!
//! The agent-attestation gate (`require_agent_attestation_for` +
//! `stamp_attestation_*`) guarded ONLY the `store` funnels. Every OTHER
//! tenant-facing memory-CREATING funnel — `entity_register`, `reflect`,
//! `consolidate` — wrote its row via `db::*` WITHOUT crossing the gate, so
//! under `AI_MEMORY_REQUIRE_AGENT_ATTESTATION=1` an unsigned write landed a
//! provenance-less durable row while the store path was fail-closed.
//!
//! Adding a gate to three funnels while leaving the inventory implicit
//! reproduces the class INSIDE the fix: the coverage is true for exactly one
//! merge, then rots. So the inventory is MECHANICAL — a NEW memory-creating
//! tenant surface that skips the gate, or a REMOVED gate on an existing one,
//! fails this test.
//!
//! # The contract
//!
//! Each production tenant memory-creating funnel appears in [`INVENTORY`] with
//! its attestation-gate marker and the exact number of gate call sites in its
//! file. A removed gate drops the count (fail); a new gate raises it (fail
//! until the pin is bumped with a dated comment). The disposition column is
//! the human-readable audit of WHY each funnel is gated (or exempt).
//!
//! ## Dispositions (the audit)
//!
//! GATED (cross the no-signature attestation gate
//! `identity::attest::gate_unsigned_surface_attestation` — refuse under
//! global-strict, else stamp `attest_level="claimed"`):
//! - `storage::entity_register` (sqlite; MCP + CLI + HTTP-sqlite)
//! - `PostgresStore::entity_register` (HTTP-pg)
//! - `mcp::handle_reflect` (MCP + HTTP-sqlite, which delegates to it)
//! - `SqliteStore::reflect` tenant branch (defense-in-depth; `bypass_visibility`
//!   curator pass exempt)
//! - `PostgresStore::reflect` tenant branch (HTTP-pg; `bypass_visibility` exempt)
//!
//! GATED via the refuse-const path (`consolidate` mints the row's metadata
//! itself, so it refuses under global-strict + stamps `claimed` for the
//! `!substrate_authored` tenant path):
//! - `storage::consolidate` (sqlite; MCP + HTTP-sqlite)
//! - `PostgresStore::consolidate` (HTTP-pg; keyed on `!ctx.bypass_visibility`)
//!
//! GATED already (pre-#3014, cross `stamp_attestation_{sync,async}`):
//! - `store` — MCP `handle_store`, CLI `cmd_store`, HTTP `create`/`bulk`.
//!
//! EXEMPT (never gated, BY DESIGN):
//! - Curator / autonomy self-writes (`CallerContext::for_admin` /
//!   `bypass_visibility`) through the SAL `store()` / trait surfaces — env #48.
//! - The federation RECEIVE funnels (`db::insert_if_newer`,
//!   `PostgresStore::merge_inbound`), which attest via the per-peer authorship
//!   allowlist (`resolve_inbound_attribution`, #1464), NOT this gate.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

// NOTE: the gate markers below are PRODUCTION-UNIQUE helper/const names that
// appear nowhere in test code, so the inventory counts over the WHOLE file. A
// `production_prefix`-style first-`#[cfg(test)]` cut is WRONG for these files
// (storage/mod.rs, postgres.rs, mcp store) because they carry `#[cfg(test)]`
// helper blocks INTERSPERSED with production code, which would truncate the
// scan before the gate sites.

/// `(file, gate-marker, expected production count, disposition)`.
const INVENTORY: &[(&str, &str, usize, &str)] = &[
    (
        "src/storage/mod.rs",
        "gate_unsigned_surface_attestation(",
        1,
        "sqlite entity_register — MCP + CLI + HTTP-sqlite (#3014).",
    ),
    (
        "src/store/postgres.rs",
        "gate_unsigned_surface_attestation(",
        2,
        "PostgresStore::entity_register + PostgresStore::reflect tenant branch \
         (HTTP-pg); curator bypass_visibility exempt (#3014).",
    ),
    (
        "src/mcp/tools/reflect.rs",
        "gate_unsigned_surface_attestation(",
        1,
        "handle_reflect — MCP + HTTP-sqlite (which delegates to it) (#3014).",
    ),
    (
        "src/store/sqlite.rs",
        "gate_unsigned_surface_attestation(",
        1,
        "SqliteStore::reflect tenant branch — defense-in-depth; the production \
         tenant reflect surfaces route through handle_reflect, curator \
         bypass_visibility exempt (#3014).",
    ),
    (
        "src/storage/mod.rs",
        "ATTESTATION_REFUSED_UNSIGNED_SURFACE",
        1,
        "sqlite consolidate refuse under global-strict; substrate_authored \
         curator pass exempt; !substrate_authored tenant rows land claimed (#3014).",
    ),
    (
        "src/store/postgres.rs",
        "ATTESTATION_REFUSED_UNSIGNED_SURFACE",
        1,
        "PostgresStore::consolidate refuse under global-strict; \
         !ctx.bypass_visibility tenant rows land claimed (#3014).",
    ),
];

#[test]
fn every_tenant_memory_creating_funnel_crosses_the_attestation_gate_3014() {
    for (file, marker, expected, note) in INVENTORY {
        let src = read(file);
        let count = src.matches(marker).count();
        assert_eq!(
            count, *expected,
            "attestation funnel ceiling drift in {file}: found {count} production \
             `{marker}` site(s), inventory pins {expected}.\n  disposition: {note}\n\
             A NEW tenant memory-creating funnel MUST cross \
             `identity::attest::gate_unsigned_surface_attestation` (or refuse via \
             `ATTESTATION_REFUSED_UNSIGNED_SURFACE`) and be added here; a REMOVED \
             gate re-opens the #3014 bypass. If this change is intentional, bump \
             the pin with a dated comment."
        );
    }
}

/// The store funnels (gated pre-#3014 via `stamp_attestation_{sync,async}`)
/// stay gated — a regression that drops the stamp from a store surface would
/// also re-open a provenance-less-write hole, so pin their presence too.
#[test]
fn store_funnels_still_cross_the_attestation_gate_3014() {
    for (file, marker) in [
        ("src/mcp/tools/store/mod.rs", "stamp_attestation_sync"),
        ("src/cli/store.rs", "stamp_attestation_sync"),
        ("src/handlers/create.rs", "stamp_attestation_async"),
        ("src/handlers/bulk.rs", "stamp_attestation_sync"),
    ] {
        let src = read(file);
        assert!(
            src.contains(marker),
            "{file} no longer crosses the store attestation gate (`{marker}`) — \
             a store surface that stops stamping attestation re-opens the \
             provenance-less-write class (#3014)."
        );
    }
}

/// The gate primitive itself must remain the single decision point: the
/// refuse string carries the `ATTESTATION_FAILED` slug so HTTP handlers map it
/// to `403` exactly like the store path, and the tri-state helper is the ONE
/// distinguisher of global-strict from the surface default.
#[test]
fn gate_primitive_shape_is_stable_3014() {
    let attest = read("src/identity/attest.rs");
    assert!(
        attest.contains("pub fn gate_unsigned_surface_attestation("),
        "the #3014 no-signature-surface gate helper must exist in attest.rs"
    );
    assert!(
        attest.contains("pub fn global_strict_attestation_enabled("),
        "the #3014/#3024 global-strict tri-state helper must exist in attest.rs"
    );
    assert!(
        attest.contains("ATTESTATION_FAILED"),
        "the #3014 refusal string must carry the ATTESTATION_FAILED slug so \
         HTTP handlers map it to 403 like the store path"
    );
}
