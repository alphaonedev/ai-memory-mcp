// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Integration-test entry point for curator helpers (v0.7.0 L1-7 + L2-1).
//!
//! Cargo autodiscovers `tests/curator.rs` as a single test binary; the
//! `mod` declarations below pull in the per-pass acceptance tests.
//!
//! * `compaction_test` (v0.7.0 L1-7) — `CompactionPass` trait surface
//!   and the consolidation pass's hook-event classification.
//! * `reflection_pass_test` (v0.7.0 L2-1, issue #666) — the
//!   reflection-pass curator mode: 30-observation → 3-cluster →
//!   3-reflection acceptance, depth-cap refusal, chain across passes,
//!   signature-verified `reflects_on` edges.

#[path = "curator/compaction_test.rs"]
mod compaction_test;

// Issue #1548 — `run_reflection_pass` now operates over the SAL
// `MemoryStore` trait (`SqliteStore`), which is `sal`-gated. Compile the
// acceptance suite only when the trait surface is available.
#[cfg(feature = "sal")]
#[path = "curator/reflection_pass_test.rs"]
mod reflection_pass_test;
