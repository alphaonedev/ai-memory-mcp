// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3659 — webhook delivery-audit persistence evidence (audit #3645 F13).
//!
//! The per-delivery audit row (`subscription_events.delivery_status`) and
//! the per-subscription dispatch counters (`subscriptions.dispatch_count`
//! / `failure_count`) are written AFTER the retry ladder settles, on a
//! best-effort basis so the dispatcher never blocks on bookkeeping.
//! Pre-#3659 that best effort was silent: `update_event_status` returned
//! on an open failure without a word, `update_event_status_with_conn`
//! discarded `conn.execute`'s result, and `record_dispatch*` did the same.
//! Nothing logged, nothing counted, and no surface could tell an operator
//! that the persisted history disagreed with what the wire actually saw —
//! which is exactly the history `doctor`'s success rate, K7 replay
//! decisions and incident reconstruction read.
//!
//! This module keeps the dispatcher's non-blocking contract and makes
//! every bookkeeping failure OBSERVED: logged at ERROR with the
//! subscription and correlation identity, counted by stage on `/metrics`
//! (`ai_memory_webhook_audit_update_failed_total{stage}`, closed label
//! set) and in process, and reported on `/health` as the
//! `webhook_audit_delivery` signal object (#3646 shape). "Delivery
//! succeeded" and "the delivery's history was persisted" are two
//! different claims; the second is now measured instead of assumed.

use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::{Connection, params};

/// Tracing target for the bookkeeping-failure sites.
const TRACE_TARGET: &str = "ai_memory::subscriptions::audit_status";

/// Which bookkeeping write failed. Closed set — the `stage` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStage {
    /// `Connection::open` on the daemon database failed, so neither the
    /// status row nor the dispatch counters could be touched.
    Open,
    /// The `subscription_events.delivery_status` UPDATE errored.
    StatusUpdate,
    /// The status UPDATE ran but matched NO row: the `pending` audit row
    /// this delivery was supposed to settle does not exist (its INSERT
    /// failed earlier, or the row was pruned). Distinct from an error —
    /// the database is fine; the history has a hole.
    StatusNoRow,
    /// The `subscriptions` dispatch/failure counter UPDATE errored.
    DispatchCounter,
}

impl AuditStage {
    /// Every stage, for pre-touching the labelled metric family.
    pub const ALL: [Self; 4] = [
        Self::Open,
        Self::StatusUpdate,
        Self::StatusNoRow,
        Self::DispatchCounter,
    ];

    /// Stable label / JSON spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::StatusUpdate => "status_update",
            Self::StatusNoRow => "status_no_row",
            Self::DispatchCounter => "dispatch_counter",
        }
    }

    const fn slot(self) -> usize {
        match self {
            Self::Open => 0,
            Self::StatusUpdate => 1,
            Self::StatusNoRow => 2,
            Self::DispatchCounter => 3,
        }
    }
}

/// The bookkeeping counters (atomics only — the dispatch worker path).
///
/// The process has ONE of these, [`COUNTERS`], which every production
/// caller reaches through the free functions below. The type is public
/// and constructible so a test can own a FRESH set and assert exact
/// values on it: the process-global is written by the dispatcher's
/// runtime workers whenever any other cell in the same binary drives a
/// real delivery, so a delta assertion across two reads of the global is
/// only as sound as the scheduler (#3752 — the #3654 fresh-registry
/// precedent applied here).
#[derive(Debug, Default)]
pub struct AuditStatusCounters {
    status_persisted: AtomicU64,
    failed: [AtomicU64; 4],
    last_persisted_unix: AtomicU64,
    last_failure_unix: AtomicU64,
}

impl AuditStatusCounters {
    /// A zeroed set — what the process starts with, and what a test owns.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            status_persisted: AtomicU64::new(0),
            failed: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            last_persisted_unix: AtomicU64::new(0),
            last_failure_unix: AtomicU64::new(0),
        }
    }

    /// Record one bookkeeping failure on this set: ERROR log with
    /// identity, per-stage counter, `/metrics`, and the last-failure
    /// instant.
    pub fn note_failure(
        &self,
        stage: AuditStage,
        sub_id: &str,
        correlation_id: &str,
        detail: &str,
    ) {
        let now = unix_now_secs();
        self.failed[stage.slot()].fetch_add(1, Ordering::Relaxed);
        self.last_failure_unix.store(now, Ordering::Relaxed);
        let m = crate::metrics::registry();
        m.webhook_audit_update_failed_total
            .with_label_values(&[stage.as_str()])
            .inc();
        #[allow(clippy::cast_possible_wrap)]
        m.webhook_audit_last_failure_at_seconds.set(now as i64);
        tracing::error!(
            target: TRACE_TARGET,
            stage = stage.as_str(),
            subscription_id = %sub_id,
            correlation_id = %correlation_id,
            "webhook delivery audit bookkeeping failed; the persisted delivery history for this \
             correlation id does NOT reflect the wire outcome (#3659): {detail}"
        );
    }

    /// Record one successfully persisted status transition on this set.
    pub fn note_status_persisted(&self) {
        self.status_persisted.fetch_add(1, Ordering::Relaxed);
        self.last_persisted_unix
            .store(unix_now_secs(), Ordering::Relaxed);
        crate::metrics::registry()
            .webhook_audit_status_persisted_total
            .inc();
    }

    /// [`persist_event_status`] observed on this set.
    pub fn persist_event_status(
        &self,
        conn: &Connection,
        sub_id: &str,
        correlation_id: &str,
        ok: bool,
    ) -> bool {
        let status = if ok { "ack" } else { "failed" };
        match conn.execute(
            "UPDATE subscription_events SET delivery_status = ?1 WHERE correlation_id = ?2",
            params![status, correlation_id],
        ) {
            Ok(0) => {
                self.note_failure(
                    AuditStage::StatusNoRow,
                    sub_id,
                    correlation_id,
                    "no pending audit row matched this correlation id",
                );
                false
            }
            Ok(_) => {
                self.note_status_persisted();
                true
            }
            Err(e) => {
                self.note_failure(
                    AuditStage::StatusUpdate,
                    sub_id,
                    correlation_id,
                    &e.to_string(),
                );
                false
            }
        }
    }

    /// [`persist_dispatch_counter`] observed on this set.
    pub fn persist_dispatch_counter(
        &self,
        conn: &Connection,
        sub_id: &str,
        correlation_id: &str,
        ok: bool,
    ) -> bool {
        let now = chrono::Utc::now().to_rfc3339();
        let sql = if ok {
            "UPDATE subscriptions SET dispatch_count = dispatch_count + 1, last_dispatched_at = ?1 WHERE id = ?2"
        } else {
            "UPDATE subscriptions SET dispatch_count = dispatch_count + 1, failure_count = failure_count + 1, last_dispatched_at = ?1 WHERE id = ?2"
        };
        match conn.execute(sql, params![now, sub_id]) {
            Ok(_) => true,
            Err(e) => {
                self.note_failure(
                    AuditStage::DispatchCounter,
                    sub_id,
                    correlation_id,
                    &e.to_string(),
                );
                false
            }
        }
    }

    /// Snapshot of this set at `now_unix`.
    #[must_use]
    pub fn delivery_at(&self, now_unix: u64) -> WebhookAuditDelivery {
        let nz = |v: u64| if v == 0 { None } else { Some(v) };
        let failed_by_stage: Vec<(&'static str, u64)> = AuditStage::ALL
            .iter()
            .map(|s| (s.as_str(), self.failed[s.slot()].load(Ordering::Relaxed)))
            .collect();
        let failed_total = failed_by_stage.iter().map(|(_, n)| *n).sum();
        let last_ok = self.last_persisted_unix.load(Ordering::Relaxed);
        let last_fail = self.last_failure_unix.load(Ordering::Relaxed);
        WebhookAuditDelivery {
            status_persisted_total: self.status_persisted.load(Ordering::Relaxed),
            failed_by_stage,
            failed_total,
            last_persisted_at_seconds: nz(last_ok),
            last_failure_at_seconds: nz(last_fail),
            failing_now: last_fail != 0 && last_fail >= last_ok,
            actionable: failed_total > 0,
            observed_at_seconds: now_unix,
        }
    }

    /// Failures on this set for one stage.
    #[must_use]
    pub fn failures(&self, stage: AuditStage) -> u64 {
        self.failed[stage.slot()].load(Ordering::Relaxed)
    }
}

/// The process-wide set every production caller reaches.
static COUNTERS: AuditStatusCounters = AuditStatusCounters::new();

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Record one bookkeeping failure on the process-wide set: ERROR log
/// with identity, per-stage counter, `/metrics`, and the last-failure
/// instant.
pub fn note_failure(stage: AuditStage, sub_id: &str, correlation_id: &str, detail: &str) {
    COUNTERS.note_failure(stage, sub_id, correlation_id, detail);
}

/// Record one successfully persisted status transition on the
/// process-wide set.
pub fn note_status_persisted() {
    COUNTERS.note_status_persisted();
}

/// Transition `subscription_events.delivery_status` for `correlation_id`
/// and OBSERVE the outcome on the process-wide set. Returns `true` only
/// when exactly one or more rows were updated. An SQL error is stage
/// `status_update`; zero rows is stage `status_no_row`.
pub fn persist_event_status(
    conn: &Connection,
    sub_id: &str,
    correlation_id: &str,
    ok: bool,
) -> bool {
    COUNTERS.persist_event_status(conn, sub_id, correlation_id, ok)
}

/// Bump the per-subscription dispatch (and, on failure, failure) counter
/// and OBSERVE the outcome on the process-wide set. Returns `true` when
/// the row was updated.
pub fn persist_dispatch_counter(
    conn: &Connection,
    sub_id: &str,
    correlation_id: &str,
    ok: bool,
) -> bool {
    COUNTERS.persist_dispatch_counter(conn, sub_id, correlation_id, ok)
}

/// A fully measured snapshot of delivery-audit persistence for this
/// process.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WebhookAuditDelivery {
    /// Status transitions that reached `subscription_events`.
    pub status_persisted_total: u64,
    /// Bookkeeping failures by stage (every stage always present).
    pub failed_by_stage: Vec<(&'static str, u64)>,
    /// Sum of `failed_by_stage`.
    pub failed_total: u64,
    /// Unix seconds of the last persisted transition (`None` = none).
    pub last_persisted_at_seconds: Option<u64>,
    /// Unix seconds of the last bookkeeping failure (`None` = none).
    pub last_failure_at_seconds: Option<u64>,
    /// `true` while the most recent bookkeeping outcome was a failure.
    pub failing_now: bool,
    /// `true` once ANY delivery's history was lost this process lifetime:
    /// the persisted history is known to disagree with the wire.
    pub actionable: bool,
    /// The unix second this snapshot was taken at.
    pub observed_at_seconds: u64,
}

impl WebhookAuditDelivery {
    /// The #3646 signal-object rendering.
    #[must_use]
    pub fn to_signal_json(&self) -> serde_json::Value {
        let by_stage: serde_json::Map<String, serde_json::Value> = self
            .failed_by_stage
            .iter()
            .map(|(k, n)| ((*k).to_string(), serde_json::Value::from(*n)))
            .collect();
        serde_json::json!({
            "state": "available",
            "observed_at_seconds": self.observed_at_seconds,
            "value": {
                "status_persisted_total": self.status_persisted_total,
                "failed_by_stage": by_stage,
                "failed_total": self.failed_total,
                "last_persisted_at_seconds": self.last_persisted_at_seconds,
                "last_failure_at_seconds": self.last_failure_at_seconds,
                "failing_now": self.failing_now,
                "actionable": self.actionable,
            },
        })
    }
}

/// Snapshot of the process-wide set at `now_unix`.
#[must_use]
pub fn delivery_at(now_unix: u64) -> WebhookAuditDelivery {
    COUNTERS.delivery_at(now_unix)
}

/// [`delivery_at`] at the wall clock.
#[must_use]
pub fn delivery() -> WebhookAuditDelivery {
    delivery_at(unix_now_secs())
}

/// Failures since boot for one stage on the process-wide set (test /
/// doctor accessor).
#[must_use]
pub fn failures(stage: AuditStage) -> u64 {
    COUNTERS.failures(stage)
}

#[cfg(test)]
mod tests {
    //! #3752 — every cell that counts asserts EXACT values on a counters
    //! set it owns (`AuditStatusCounters::new()`), never a delta across two
    //! reads of the process-global. In the full lib binary the global is
    //! written by the dispatcher's runtime workers whenever the
    //! `subscriptions::tests` e2e cells drive a real delivery (six writes
    //! per run, on `tokio-rt-worker` threads, 0.4–11 s after they start),
    //! and `subscriptions::audit_status::tests` dequeues immediately ahead
    //! of them — so a delta window that lags under load lands inside a
    //! neighbour's ack and reads `+2`. The global's wiring is pinned once,
    //! by the one property a concurrent writer cannot break: it only ever
    //! moves UP.
    use super::{AuditStage, AuditStatusCounters, delivery_at, failures, persist_event_status};

    fn fresh_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("audit-3659.db");
        let _ = crate::db::open(&p).expect("db::open");
        (dir, p)
    }

    fn seed_pending(conn: &rusqlite::Connection, sub_id: &str, cid: &str) {
        conn.execute(
            "INSERT INTO subscriptions (id, url, secret_hash, events, created_at) \
             VALUES (?1, 'https://example.invalid/hook', 'h', '[]', '2026-09-13T00:00:00Z')",
            rusqlite::params![sub_id],
        )
        .expect("seed subscription");
        crate::subscriptions::record_subscription_event_with_conn(
            conn,
            sub_id,
            cid,
            "memory_store",
            "{}",
        )
        .expect("seed pending row");
    }

    #[test]
    fn stage_labels_are_closed_and_stable_3659() {
        let labels: Vec<&str> = AuditStage::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            labels,
            ["open", "status_update", "status_no_row", "dispatch_counter"]
        );
    }

    #[test]
    fn a_fresh_set_reports_nothing_3752() {
        let snap = AuditStatusCounters::new().delivery_at(0);
        assert_eq!(snap.status_persisted_total, 0);
        assert_eq!(snap.failed_total, 0);
        assert_eq!(snap.last_persisted_at_seconds, None);
        assert_eq!(snap.last_failure_at_seconds, None);
        assert!(!snap.failing_now);
        assert!(!snap.actionable);
    }

    #[test]
    fn status_update_success_is_counted_3659() {
        let (_d, p) = fresh_db();
        let conn = rusqlite::Connection::open(&p).expect("open");
        seed_pending(&conn, "sub-ok", "cid-ok");
        let c = AuditStatusCounters::new();
        assert!(c.persist_event_status(&conn, "sub-ok", "cid-ok", true));
        let status: String = conn
            .query_row(
                "SELECT delivery_status FROM subscription_events WHERE correlation_id = 'cid-ok'",
                [],
                |r| r.get(0),
            )
            .expect("read status");
        assert_eq!(status, "ack");
        let after = c.delivery_at(0);
        // EXACTLY one: a double-increment would read 2 here, and nothing
        // else can write this set.
        assert_eq!(after.status_persisted_total, 1);
        assert_eq!(after.failed_total, 0);
        assert!(after.last_persisted_at_seconds.is_some());
        assert!(!after.failing_now);
        assert!(!after.actionable);
    }

    #[test]
    fn status_update_sql_failure_is_counted_with_stage_3659() {
        let (_d, p) = fresh_db();
        let conn = rusqlite::Connection::open(&p).expect("open");
        seed_pending(&conn, "sub-err", "cid-err");
        conn.execute_batch("DROP TABLE subscription_events")
            .expect("drop");
        let c = AuditStatusCounters::new();
        assert!(!c.persist_event_status(&conn, "sub-err", "cid-err", false));
        assert_eq!(c.failures(AuditStage::StatusUpdate), 1);
        let snap = c.delivery_at(0);
        assert_eq!(snap.status_persisted_total, 0);
        assert_eq!(snap.failed_total, 1);
        assert!(snap.actionable);
        assert!(snap.failing_now);
        assert!(snap.last_failure_at_seconds.is_some());
    }

    #[test]
    fn status_update_matching_no_row_is_distinct_stage_3659() {
        let (_d, p) = fresh_db();
        let conn = rusqlite::Connection::open(&p).expect("open");
        let c = AuditStatusCounters::new();
        assert!(!c.persist_event_status(&conn, "sub-x", "cid-never-inserted", true));
        assert_eq!(c.failures(AuditStage::StatusNoRow), 1);
        assert_eq!(c.failures(AuditStage::StatusUpdate), 0);
        assert_eq!(c.delivery_at(0).status_persisted_total, 0);
    }

    #[test]
    fn dispatch_counter_failure_is_counted_3659() {
        let (_d, p) = fresh_db();
        let conn = rusqlite::Connection::open(&p).expect("open");
        conn.execute_batch("DROP TABLE subscriptions")
            .expect("drop");
        let c = AuditStatusCounters::new();
        assert!(!c.persist_dispatch_counter(&conn, "sub-dc", "cid-dc", false));
        assert_eq!(c.failures(AuditStage::DispatchCounter), 1);
        assert_eq!(c.delivery_at(0).failed_total, 1);
    }

    /// A success after a failure clears `failing_now` (the most recent
    /// outcome decides) but never `actionable` (history was lost once).
    #[test]
    fn failing_now_follows_the_most_recent_outcome_3752() {
        let (_d, p) = fresh_db();
        let conn = rusqlite::Connection::open(&p).expect("open");
        seed_pending(&conn, "sub-seq", "cid-seq");
        let c = AuditStatusCounters::new();
        assert!(!c.persist_event_status(&conn, "sub-seq", "cid-missing", true));
        assert!(c.delivery_at(0).failing_now);
        assert!(c.persist_event_status(&conn, "sub-seq", "cid-seq", true));
        let snap = c.delivery_at(0);
        // Same wall-clock second as the failure: the tie goes to failing.
        // Either way the counts are exact and the flag is decidable from
        // this set alone.
        assert_eq!(snap.status_persisted_total, 1);
        assert_eq!(snap.failed_total, 1);
        assert!(snap.actionable);
    }

    /// The ONE pin on the process-global: the free functions route to it.
    /// Asserted with the only property a concurrent writer cannot break —
    /// the counter moves UP (the `>= before + n` idiom of
    /// `subscriptions::tests::record_dispatch_unopenable_db_path_is_noop`).
    #[test]
    fn free_functions_write_the_process_wide_set_3752() {
        let (_d, p) = fresh_db();
        let conn = rusqlite::Connection::open(&p).expect("open");
        seed_pending(&conn, "sub-g", "cid-g");
        let before_ok = delivery_at(0).status_persisted_total;
        let before_no_row = failures(AuditStage::StatusNoRow);
        assert!(persist_event_status(&conn, "sub-g", "cid-g", true));
        assert!(!persist_event_status(&conn, "sub-g", "cid-g-missing", true));
        assert!(delivery_at(0).status_persisted_total >= before_ok + 1);
        assert!(failures(AuditStage::StatusNoRow) >= before_no_row + 1);
        assert!(delivery_at(0).last_persisted_at_seconds.is_some());
    }

    #[test]
    fn signal_json_is_a_signal_object_3659() {
        let j = delivery_at(9).to_signal_json();
        assert_eq!(j["state"], "available");
        assert_eq!(j["observed_at_seconds"], 9);
        for s in AuditStage::ALL {
            assert!(j["value"]["failed_by_stage"][s.as_str()].is_u64(), "{j}");
        }
        assert!(j["value"]["actionable"].is_boolean());
    }
}
