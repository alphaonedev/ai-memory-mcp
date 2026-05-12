// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Reflection-pass curator mode.
//!
//! Empty placeholder for v0.7.0 Layer 2 Task L2-1 (per
//! `_v070_grand_slam/layer_0_5/discovery` playbook §2). The
//! Layer 2 work implements the autonomous engine that clusters
//! observations by recall co-occurrence + namespace + temporal
//! proximity, calls an LLM for pattern summary, and writes
//! reflection memories via `db::reflect_with_hooks`.
//!
//! Depends on L1-1 (typed MemoryKind::Reflection), L1-6 (Goal
//! kind + supersede protection), L1-7 (compaction pipeline
//! trait).
