// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Integration-test entry point for curator helpers (v0.7.0 L1-7).
//!
//! Cargo autodiscovers `tests/curator.rs` as a single test binary; the
//! `mod compaction_test` declaration below pulls in the compaction-pipeline
//! acceptance tests from `tests/curator/compaction_test.rs`.

#[path = "curator/compaction_test.rs"]
mod compaction_test;
