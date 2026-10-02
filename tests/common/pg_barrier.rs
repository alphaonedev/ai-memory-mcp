// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared wall-clock budget for the live-Postgres lock-barrier suites (#4336).
//!
//! The interleaving suites park a writer behind a held lock and then poll
//! `pg_blocking_pids` until the writer is observed waiting. The writer cannot
//! reach its lock wait before it owns a connection, and a brand-new backend on
//! a freshly created database (cold catalog and plan caches, TLS handshake,
//! `after_connect` GUCs) can take far longer than a warm one under host load.
//! The production pool tolerates that for `acquire_timeout_secs` (30 s) and
//! then lets the statement wait `lock_timeout` (5 s). A barrier that gives up
//! sooner than the pool does fails on a perfectly healthy run: the first run
//! against a fresh database on a busy host panicked with `barrier not reached`
//! after exactly the old 20 s literal (#4336).
//!
//! So the barrier budget is DERIVED from those production constants instead of
//! being a free-standing literal. It is a ceiling only: every barrier returns
//! the moment its condition holds, and no assertion is weakened.
//!
//! Take it with the `#[path]` leaf idiom (no `mod common;` weight):
//!
//! ```ignore
//! #[path = "common/pg_barrier.rs"]
//! mod pg_barrier;
//! ```

#![allow(dead_code)]

use std::time::Duration;

use ai_memory::store::PoolConfig;
use ai_memory::store::postgres::DEFAULT_LOCK_TIMEOUT_SECS;

/// Budget for a lock barrier to be reached: twice the sum of the pool's
/// connection-acquire timeout and the per-statement lock timeout.
#[must_use]
pub fn barrier_budget() -> Duration {
    let acquire = Duration::from_secs(PoolConfig::default().acquire_timeout_secs);
    let lock = Duration::from_secs(DEFAULT_LOCK_TIMEOUT_SECS);
    acquire.saturating_add(lock).saturating_mul(2)
}

/// Async deadline for a barrier poll loop.
#[must_use]
pub fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + barrier_budget()
}
