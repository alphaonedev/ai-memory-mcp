// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Track D #933 — federation push DLQ + replay worker.
//!
//! ## What this module owns
//!
//! - The [`FederationDlqSink`] trait — abstract interface that
//!   `broadcast_store_quorum` calls into on per-peer fanout failure to
//!   record a `federation_push_dlq` row.
//! - The [`spawn_replay_federation_push_dlq`] task — spawned alongside
//!   the catchup loop in
//!   `daemon_runtime::spawn_catchup_loop_with_store`. Polls the DLQ
//!   every N seconds, re-attempts `post_once` against each peer, and
//!   stamps `replayed_at` (or DELETEs) on Ack.
//! - The [`federation_push_dlq_depth`] Prometheus gauge mirror — kept
//!   live by the replay worker.
//!
//! ## Why a DLQ
//!
//! Pre-#933 the per-peer push tasks inside `broadcast_store_quorum`
//! had no audit surface: if the leader's local commit succeeded but a
//! peer was unreachable (or slow past the deadline), nothing recorded
//! the missed push. On the peer's recovery the catchup loop pulled
//! rows the peer was behind on but the leader never re-attempted the
//! original push. Cross-recall consistency only worked when both
//! daemons shared a postgres store (Track B finding #925 masked the
//! gap). See the issue body for the full RCA.
//!
//! ## Contract surface
//!
//! - On a `Fail(reason)` or no-Ack-before-deadline per-peer outcome,
//!   `broadcast_store_quorum` calls
//!   [`FederationDlqSink::enqueue_push_failure`] with the memory id,
//!   peer id, payload body, and the failure reason.
//! - The sink writes a `federation_push_dlq` row (CREATE-or-bump-
//!   attempt_count via the partial unique index).
//! - The replay worker polls
//!   [`FederationDlqSink::take_pending_dlq_rows`] every N seconds and
//!   re-issues `post_once`. Successful Acks stamp `replayed_at` via
//!   [`FederationDlqSink::mark_dlq_row_replayed`].
//!
//! ## What this module deliberately does NOT do
//!
//! - No reverse direction. The DLQ is leader → peer. Peer → leader is
//!   covered by the existing catchup loop in `federation::receive`.
//! - No retry budget. The replay worker keeps trying forever; the
//!   `federation_push_dlq_depth` gauge is the operator alert surface.
//!   A future enhancement may add an `attempt_count` watermark + DLQ-
//!   parking lot, but for v0.7.0 GA the unbounded retry posture is
//!   correct: silent data loss is a worse failure mode than
//!   unbounded-DLQ growth (operators alert on the gauge well before
//!   the column overflows).

use std::sync::Arc;
use std::time::Duration;

use super::FederationConfig;
use super::sync::{AckOutcome, post_once};

/// A single pending DLQ row, surfaced to the replay worker.
///
/// `payload_json` is captured as the exact body the leader originally
/// POSTed (so the replay re-POSTs the same shape regardless of whether
/// the source memory row has been updated since), and `attempt_count`
/// is the persisted retry counter (advisory only — the replay worker
/// keeps trying regardless).
#[derive(Debug, Clone)]
pub struct FederationPushDlqRow {
    pub id: i64,
    pub memory_id: String,
    pub peer_id: String,
    pub payload_json: serde_json::Value,
    pub attempt_count: i32,
    pub last_error: String,
}

/// Abstract dead-letter-queue interface backing the
/// `federation_push_dlq` table.
///
/// Concrete impls live in `src/db.rs` (sqlite legacy path) and
/// `src/store/postgres.rs` (postgres SAL path). Both adapters were
/// extended at v48 with the migration that ships this table.
///
/// The trait is intentionally small — three methods cover the full
/// happy path (enqueue on failure, list pending for replay, mark
/// success). Operator tooling (`ai-memory federation dlq list`,
/// future) can layer on top via direct SQL.
#[async_trait::async_trait]
pub trait FederationDlqSink: Send + Sync {
    /// Insert a new pending row OR bump `attempt_count` + refresh
    /// `last_error` on an existing pending row for the same
    /// `(memory_id, peer_id)`. Implementations MUST be safe to call
    /// concurrently (the production call path inside
    /// `broadcast_store_quorum` runs in a per-fanout task).
    async fn enqueue_push_failure(
        &self,
        memory_id: &str,
        peer_id: &str,
        payload_json: &serde_json::Value,
        last_error: &str,
    ) -> Result<(), String>;

    /// Return up to `limit` pending rows ordered by `failed_at` ASC
    /// (oldest first so the replay worker drains the tail before
    /// fresh failures). Empty vector = nothing to replay.
    async fn take_pending_dlq_rows(
        &self,
        limit: usize,
    ) -> Result<Vec<FederationPushDlqRow>, String>;

    /// Mark a DLQ row as replayed (the peer Acked). Implementations
    /// may either DELETE the row or stamp `replayed_at`; the worker
    /// doesn't care which.
    async fn mark_dlq_row_replayed(&self, id: i64) -> Result<(), String>;

    /// Bump `attempt_count` + refresh `last_error` on an existing
    /// pending row. Used by the replay worker when a retry attempt
    /// itself fails (so operators can tell from `attempt_count` how
    /// long the row has been stuck).
    async fn bump_dlq_attempt(&self, id: i64, last_error: &str) -> Result<(), String>;

    /// Return the current number of pending DLQ rows. Used by the
    /// replay worker to maintain the `federation_push_dlq_depth`
    /// Prometheus gauge.
    async fn pending_dlq_count(&self) -> Result<i64, String>;
}

/// Spawn the federation push DLQ replay worker.
///
/// Runs alongside the catchup loop (also in `daemon_runtime`). Every
/// `interval` ticks it:
///
/// 1. Reads up to `REPLAY_BATCH_SIZE` pending rows from the sink.
/// 2. For each row, attempts `post_once` against the matching peer's
///    `sync_push_url`. On `AckOutcome::Ack` it stamps `replayed_at`
///    via `mark_dlq_row_replayed`. On any other outcome it bumps the
///    row's `attempt_count` so operators alerting on the
///    `federation_push_dlq_depth` gauge can tell which rows are
///    repeatedly failing.
/// 3. Updates the `ai_memory_federation_push_dlq_depth` Prometheus
///    gauge to the current pending count.
///
/// Errors are logged at `tracing::warn` but never propagated — the
/// worker is best-effort by design (same posture as the catchup
/// loop).
///
/// Returns a `JoinHandle` so the bootstrap can hold it for the
/// lifetime of the daemon (it intentionally never terminates).
#[must_use]
pub fn spawn_replay_federation_push_dlq(
    config: FederationConfig,
    sink: Arc<dyn FederationDlqSink>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Same upfront delay as the catchup loop so the first replay
        // tick doesn't fire before the daemon's HTTP server has bound
        // — avoids spurious "connection refused" on a fresh cluster
        // boot if the peer is also coming up.
        tokio::time::sleep(Duration::from_secs(5)).await;
        loop {
            replay_once(&config, sink.as_ref()).await;
            tokio::time::sleep(interval).await;
        }
    })
}

/// Default batch size for one replay tick. Tuned high enough to drain
/// a steady-state backlog quickly (a peer down for an hour with a
/// 100/min ingest rate accumulates ~6000 rows) but low enough that a
/// single tick won't monopolise the runtime if every replay attempt
/// itself succeeds against a peer that's now healthy.
pub const REPLAY_BATCH_SIZE: usize = 64;

/// Drive one replay pass. Public so the integration test in
/// `tests/federation_dlq_replay.rs` can advance the worker manually
/// without waiting on the `tokio::time::sleep` cadence.
pub async fn replay_once(config: &FederationConfig, sink: &dyn FederationDlqSink) {
    let rows = match sink.take_pending_dlq_rows(REPLAY_BATCH_SIZE).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                target: "ai_memory::federation::push_dlq",
                "replay_federation_push_dlq: failed to load pending rows: {e}"
            );
            return;
        }
    };

    if rows.is_empty() {
        // Still refresh the gauge — operators alert on it sitting at
        // 0 long-term; an unreachable sink would otherwise leave the
        // gauge stale.
        refresh_depth_gauge(sink).await;
        return;
    }

    tracing::info!(
        target: "ai_memory::federation::push_dlq",
        rows = rows.len(),
        "federation: replay_federation_push_dlq draining {} row(s)",
        rows.len(),
    );

    for row in rows {
        // Resolve the peer URL via the live FederationConfig. If the
        // peer has been removed from the config since the DLQ row was
        // written, log + bump attempt_count + leave the row for the
        // operator to drain manually.
        let Some(peer) = config.peers.iter().find(|p| p.id == row.peer_id) else {
            let _ = sink
                .bump_dlq_attempt(row.id, "peer no longer in FederationConfig")
                .await;
            tracing::warn!(
                target: "ai_memory::federation::push_dlq",
                row_id = row.id,
                peer_id = %row.peer_id,
                "replay: peer {} not in FederationConfig — leaving row pending",
                row.peer_id,
            );
            continue;
        };

        let outcome = post_once(
            &config.client,
            &peer.sync_push_url,
            &row.payload_json,
            &row.memory_id,
            Some(&row.memory_id),
            config.api_key.as_deref(),
            config.signing_key.as_deref(),
        )
        .await;

        match outcome {
            AckOutcome::Ack => {
                if let Err(e) = sink.mark_dlq_row_replayed(row.id).await {
                    tracing::warn!(
                        target: "ai_memory::federation::push_dlq",
                        row_id = row.id,
                        "replay: peer {} acked but mark_dlq_row_replayed failed: {e}",
                        row.peer_id,
                    );
                } else {
                    tracing::info!(
                        target: "ai_memory::federation::push_dlq",
                        row_id = row.id,
                        memory_id = %row.memory_id,
                        peer_id = %row.peer_id,
                        "replay: peer {} acked for {} (DLQ row {} cleared)",
                        row.peer_id,
                        row.memory_id,
                        row.id,
                    );
                }
            }
            AckOutcome::IdDrift => {
                // Peer received the row but rewrote the id —
                // operator-visible divergence. Bump and keep row so
                // the audit trail captures the drift.
                let _ = sink
                    .bump_dlq_attempt(row.id, "replay observed id_drift on peer ack")
                    .await;
                tracing::warn!(
                    target: "ai_memory::federation::push_dlq",
                    row_id = row.id,
                    "replay: peer {} returned id_drift on row {} — leaving pending",
                    row.peer_id,
                    row.id,
                );
            }
            AckOutcome::Fail(reason) => {
                let _ = sink.bump_dlq_attempt(row.id, &reason).await;
                tracing::debug!(
                    target: "ai_memory::federation::push_dlq",
                    row_id = row.id,
                    "replay: peer {} still failing on row {}: {reason}",
                    row.peer_id,
                    row.id,
                );
            }
        }
    }

    refresh_depth_gauge(sink).await;
}

/// Refresh the `ai_memory_federation_push_dlq_depth` Prometheus gauge
/// from the sink's live pending count.
async fn refresh_depth_gauge(sink: &dyn FederationDlqSink) {
    match sink.pending_dlq_count().await {
        Ok(depth) => {
            crate::metrics::registry()
                .federation_push_dlq_depth
                .set(depth);
        }
        Err(e) => {
            tracing::warn!(
                target: "ai_memory::federation::push_dlq",
                "replay: failed to refresh federation_push_dlq_depth: {e}"
            );
        }
    }
}

/// Sqlite implementation of [`FederationDlqSink`] backed by the
/// shared `handlers::Db` mutex-wrapped `rusqlite::Connection`.
///
/// All methods acquire the mutex for the duration of one SQL call so
/// the sink stays compatible with the legacy single-connection
/// posture. Concurrent callers serialise on the mutex; for v0.7.0 GA
/// loads the per-failure SQL is microseconds so this is acceptable.
pub struct SqliteDlqSink {
    db: crate::handlers::Db,
}

impl SqliteDlqSink {
    /// Build a new sink over the daemon's shared sqlite connection.
    #[must_use]
    pub fn new(db: crate::handlers::Db) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl FederationDlqSink for SqliteDlqSink {
    async fn enqueue_push_failure(
        &self,
        memory_id: &str,
        peer_id: &str,
        payload_json: &serde_json::Value,
        last_error: &str,
    ) -> Result<(), String> {
        let now = chrono::Utc::now().to_rfc3339();
        let payload_str = payload_json.to_string();
        let conn = self.db.lock().await;
        // Use `ON CONFLICT(memory_id, peer_id) WHERE replayed_at IS
        // NULL DO UPDATE` so a flapping peer doesn't stack duplicate
        // pending rows — bumps attempt_count + refreshes last_error
        // instead. Partial unique index from the v48 migration backs
        // this conflict target.
        conn.0
            .execute(
                "INSERT INTO federation_push_dlq \
                 (memory_id, peer_id, payload_json, attempt_count, last_error, failed_at) \
                 VALUES (?1, ?2, ?3, 1, ?4, ?5) \
                 ON CONFLICT(memory_id, peer_id) WHERE replayed_at IS NULL \
                 DO UPDATE SET \
                   attempt_count = attempt_count + 1, \
                   last_error    = excluded.last_error",
                rusqlite::params![memory_id, peer_id, payload_str, last_error, now],
            )
            .map_err(|e| format!("sqlite enqueue_push_failure: {e}"))?;
        Ok(())
    }

    async fn take_pending_dlq_rows(
        &self,
        limit: usize,
    ) -> Result<Vec<FederationPushDlqRow>, String> {
        let conn = self.db.lock().await;
        let mut stmt = conn
            .0
            .prepare(
                "SELECT id, memory_id, peer_id, payload_json, attempt_count, last_error \
                 FROM federation_push_dlq \
                 WHERE replayed_at IS NULL \
                 ORDER BY failed_at ASC \
                 LIMIT ?1",
            )
            .map_err(|e| format!("sqlite take_pending_dlq_rows prepare: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![limit as i64], |row| {
                let payload_str: String = row.get(3)?;
                let payload_json =
                    serde_json::from_str(&payload_str).unwrap_or(serde_json::json!({}));
                Ok(FederationPushDlqRow {
                    id: row.get(0)?,
                    memory_id: row.get(1)?,
                    peer_id: row.get(2)?,
                    payload_json,
                    attempt_count: row.get(4)?,
                    last_error: row.get(5)?,
                })
            })
            .map_err(|e| format!("sqlite take_pending_dlq_rows query: {e}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("sqlite take_pending_dlq_rows collect: {e}"))?;
        Ok(rows)
    }

    async fn mark_dlq_row_replayed(&self, id: i64) -> Result<(), String> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.db.lock().await;
        conn.0
            .execute(
                "UPDATE federation_push_dlq SET replayed_at = ?1 WHERE id = ?2",
                rusqlite::params![now, id],
            )
            .map_err(|e| format!("sqlite mark_dlq_row_replayed: {e}"))?;
        Ok(())
    }

    async fn bump_dlq_attempt(&self, id: i64, last_error: &str) -> Result<(), String> {
        let conn = self.db.lock().await;
        conn.0
            .execute(
                "UPDATE federation_push_dlq \
                 SET attempt_count = attempt_count + 1, last_error = ?1 \
                 WHERE id = ?2 AND replayed_at IS NULL",
                rusqlite::params![last_error, id],
            )
            .map_err(|e| format!("sqlite bump_dlq_attempt: {e}"))?;
        Ok(())
    }

    async fn pending_dlq_count(&self) -> Result<i64, String> {
        let conn = self.db.lock().await;
        conn.0
            .query_row(
                "SELECT COUNT(*) FROM federation_push_dlq WHERE replayed_at IS NULL",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| format!("sqlite pending_dlq_count: {e}"))
    }
}

/// Postgres implementation of [`FederationDlqSink`] backed by the
/// `PostgresStore`'s connection pool.
///
/// Only available under `--features sal-postgres` (which transitively
/// enables `sal`).
#[cfg(feature = "sal-postgres")]
pub struct PostgresDlqSink {
    store: std::sync::Arc<crate::store::postgres::PostgresStore>,
}

#[cfg(feature = "sal-postgres")]
impl PostgresDlqSink {
    /// Build a new sink over the daemon's `PostgresStore` handle.
    #[must_use]
    pub fn new(store: std::sync::Arc<crate::store::postgres::PostgresStore>) -> Self {
        Self { store }
    }
}

#[cfg(feature = "sal-postgres")]
#[async_trait::async_trait]
impl FederationDlqSink for PostgresDlqSink {
    async fn enqueue_push_failure(
        &self,
        memory_id: &str,
        peer_id: &str,
        payload_json: &serde_json::Value,
        last_error: &str,
    ) -> Result<(), String> {
        let pool = self.store.pool();
        sqlx::query(
            "INSERT INTO federation_push_dlq \
             (memory_id, peer_id, payload_json, attempt_count, last_error) \
             VALUES ($1, $2, $3::jsonb, 1, $4) \
             ON CONFLICT (memory_id, peer_id) WHERE replayed_at IS NULL \
             DO UPDATE SET \
               attempt_count = federation_push_dlq.attempt_count + 1, \
               last_error    = EXCLUDED.last_error",
        )
        .bind(memory_id)
        .bind(peer_id)
        .bind(payload_json.to_string())
        .bind(last_error)
        .execute(pool)
        .await
        .map_err(|e| format!("postgres enqueue_push_failure: {e}"))?;
        Ok(())
    }

    async fn take_pending_dlq_rows(
        &self,
        limit: usize,
    ) -> Result<Vec<FederationPushDlqRow>, String> {
        let pool = self.store.pool();
        let limit_i64: i64 = limit.try_into().unwrap_or(i64::MAX);
        let rows: Vec<(i64, String, String, serde_json::Value, i32, String)> = sqlx::query_as(
            "SELECT id, memory_id, peer_id, payload_json, attempt_count, last_error \
             FROM federation_push_dlq \
             WHERE replayed_at IS NULL \
             ORDER BY failed_at ASC \
             LIMIT $1",
        )
        .bind(limit_i64)
        .fetch_all(pool)
        .await
        .map_err(|e| format!("postgres take_pending_dlq_rows: {e}"))?;
        Ok(rows
            .into_iter()
            .map(
                |(id, memory_id, peer_id, payload_json, attempt_count, last_error)| {
                    FederationPushDlqRow {
                        id,
                        memory_id,
                        peer_id,
                        payload_json,
                        attempt_count,
                        last_error,
                    }
                },
            )
            .collect())
    }

    async fn mark_dlq_row_replayed(&self, id: i64) -> Result<(), String> {
        let pool = self.store.pool();
        sqlx::query("UPDATE federation_push_dlq SET replayed_at = now() WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| format!("postgres mark_dlq_row_replayed: {e}"))?;
        Ok(())
    }

    async fn bump_dlq_attempt(&self, id: i64, last_error: &str) -> Result<(), String> {
        let pool = self.store.pool();
        sqlx::query(
            "UPDATE federation_push_dlq \
             SET attempt_count = attempt_count + 1, last_error = $1 \
             WHERE id = $2 AND replayed_at IS NULL",
        )
        .bind(last_error)
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| format!("postgres bump_dlq_attempt: {e}"))?;
        Ok(())
    }

    async fn pending_dlq_count(&self) -> Result<i64, String> {
        let pool = self.store.pool();
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM federation_push_dlq WHERE replayed_at IS NULL")
                .fetch_one(pool)
                .await
                .map_err(|e| format!("postgres pending_dlq_count: {e}"))?;
        Ok(row.0)
    }
}
