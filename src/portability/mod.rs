// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2006 — the integrity-complete Portability-v2 exporter + importer.
//!
//! `ai-memory export --full` emits the full v2 envelope (spec
//! `docs/spec/PORTABILITY-V2.md`): the v1 data classes PLUS the signed /
//! governance record classes (§V2-2) byte-preserved so the destination can
//! RE-VERIFY them (the V-4 audit chain, revision spine, tombstones, lineage,
//! model attestations, governance rules + trust anchors). The symmetric
//! importer re-inserts each class WITHOUT re-signing (L2) and re-runs the
//! substrate's existing verifiers.
//!
//! This module owns the envelope DTOs + the emit/import logic so
//! `src/cli/io.rs` stays a thin CLI handler. The default (no-`--full`) JSON
//! export is untouched — it remains the memories + links convenience view of
//! `src/export_scope.rs`, and only `--full` produces the v2 envelope + the
//! `conformance_level` marker.
//!
//! ## Conformance levels (spec §V2-1)
//! - **L1** — the v1 data classes round-trip.
//! - **L2** — additionally the signed classes round-trip byte-preserved AND
//!   re-verify at the destination; a conforming importer NEVER re-signs.
//! - **L3** — additionally `governance_rules` + the operator/witness/recorder/
//!   judge/stopper PUBLIC trust anchors round-trip (never private keys).
//!
//! The achieved level is COMPUTED from an in-export re-verify pass (never a
//! hard-coded constant), surfaced per-class so a mixed export reports the
//! honest minimum. See [`hex_bytes`] for the byte-field codec that makes L2
//! byte-preservation possible.

pub mod hex_bytes;
