// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #5035 (5-agent vote `4d3ea1c5` = A) — hold the #2445 schema-ahead
//! refusal for the LIFETIME of a postgres pool, not only at connect.
//!
//! The schema of a postgres cluster is shared by every daemon on it, so a
//! newer binary on another node can migrate the cluster while this pool is
//! live. The connect-time guard never re-runs, and this binary's writes then
//! hit tables whose shape it does not know (a raw `ON CONFLICT` mismatch at
//! best, rows the newer schema owns silently rewritten at worst).
//!
//! # Cadence
//!
//! The re-probe rides the #3276 record-stop refresh: the single writer that
//! wins the per-window compare-exchange in
//! `PostgresStore::refresh_record_stop_if_stale` also re-reads
//! `MAX(schema_version)` and publishes it here; every other write evaluates
//! the cached version with one atomic load. A remote migration is therefore
//! refused within one `RECORD_STOP_REFRESH_TTL_MS` window, with no per-write
//! round-trip.
//!
//! # Fail-closed
//!
//! A probe that cannot complete keeps the LAST observed version (an ahead
//! verdict is never downgraded by a transient read failure; the next window's
//! winner retries). The verdict itself is the shared
//! [`crate::storage::schema_guard::live_write_verdict`] the sqlite gate uses,
//! so the two backends refuse with one rendering and one hatch rule.
//!
//! # Why it is its own module
//!
//! `src/store/postgres.rs` sits near its `qual_10_module_size_ceiling` budget;
//! the `forensic_outage_4199.rs` precedent.

use std::sync::atomic::{AtomicI64, Ordering};

use super::{CURRENT_SCHEMA_VERSION, PostgresStore, SELECT_SCHEMA_VERSION_BIGINT_SQL};
use crate::storage::schema_guard::{BACKEND_POSTGRES, LIVE_TARGET_LABEL, live_write_verdict};
use crate::store::{StoreError, StoreResult};

/// The shared, pool-clone-wide cache of the last observed schema version.
pub(super) type SchemaObserved = std::sync::Arc<AtomicI64>;

/// Seed the cache with the version the connect-time guard just read.
pub(super) fn seed(observed: i64) -> SchemaObserved {
    std::sync::Arc::new(AtomicI64::new(observed))
}

impl PostgresStore {
    /// #5035 — re-read the recorded schema version and publish it to the
    /// shared cache. Called only by the elected refresher of a TTL window.
    /// A read error keeps the last value (fail-closed, see module docs).
    pub(super) async fn refresh_schema_observed(&self) {
        match sqlx::query_scalar::<_, i64>(SELECT_SCHEMA_VERSION_BIGINT_SQL)
            .fetch_one(&self.pool)
            .await
        {
            // Release publishes the version to every writer that Acquire-loads
            // it in `gate_schema_live` (CONCURRENCY-08).
            Ok(v) => self.schema_observed.store(v, Ordering::Release),
            Err(e) => tracing::debug!(
                target: crate::storage::schema_guard::TRACE_TARGET,
                error = %e,
                "schema lifetime re-probe failed; keeping the last observed version"
            ),
        }
    }

    /// #5035 — evaluate the cached schema version for a write. One atomic
    /// load; no I/O.
    ///
    /// # Errors
    ///
    /// [`StoreError::SchemaAheadOfBinary`] (path-free, rendered against
    /// [`LIVE_TARGET_LABEL`]) when the cluster schema moved past this
    /// binary's tip and no exact-version hatch authorises it.
    pub(super) fn gate_schema_live(&self) -> StoreResult<()> {
        let observed = self.schema_observed.load(Ordering::Acquire);
        let supported = i64::from(CURRENT_SCHEMA_VERSION);
        live_write_verdict(observed, supported, BACKEND_POSTGRES).map_err(|refusal| {
            tracing::warn!(
                target: crate::storage::schema_guard::TRACE_TARGET,
                observed,
                supported,
                target_label = LIVE_TARGET_LABEL,
                "schema-downgrade guard REFUSED a write on a live postgres pool — the \
                 cluster schema moved ahead of this binary after connect (#5035)"
            );
            StoreError::SchemaAheadOfBinary {
                detail: refusal.detail,
            }
        })
    }
}
