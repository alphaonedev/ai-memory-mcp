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

/// Process-wide counters (atomics only — the dispatch worker path).
#[derive(Debug, Default)]
pub struct AuditStatusCounters {
    status_persisted: AtomicU64,
    failed: [AtomicU64; 4],
    last_persisted_unix: AtomicU64,
    last_failure_unix: AtomicU64,
}

static COUNTERS: AuditStatusCounters = AuditStatusCounters {
    status_persisted: AtomicU64::new(0),
    failed: [
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
        AtomicU64::new(0),
    ],
    last_persisted_unix: AtomicU64::new(0),
    last_failure_unix: AtomicU64::new(0),
};

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Record one bookkeeping failure: ERROR log with identity, per-stage
/// counter, `/metrics`, and the last-failure instant.
pub fn note_failure(stage: AuditStage, sub_id: &str, correlation_id: &str, detail: &str) {
    let now = unix_now_secs();
    COUNTERS.failed[stage.slot()].fetch_add(1, Ordering::Relaxed);
    COUNTERS.last_failure_unix.store(now, Ordering::Relaxed);
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

/// Record one successfully persisted status transition.
pub fn note_status_persisted() {
    COUNTERS.status_persisted.fetch_add(1, Ordering::Relaxed);
    COUNTERS
        .last_persisted_unix
        .store(unix_now_secs(), Ordering::Relaxed);
    crate::metrics::registry()
        .webhook_audit_status_persisted_total
        .inc();
}

/// Transition `subscription_events.delivery_status` for `correlation_id`
/// and OBSERVE the outcome. Returns `true` only when exactly one or more
/// rows were updated. An SQL error is stage `status_update`; zero rows is
/// stage `status_no_row`.
pub fn persist_event_status(
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
            note_failure(
                AuditStage::StatusNoRow,
                sub_id,
                correlation_id,
                "no pending audit row matched this correlation id",
            );
            false
        }
        Ok(_) => {
            note_status_persisted();
            true
        }
        Err(e) => {
            note_failure(
                AuditStage::StatusUpdate,
                sub_id,
                correlation_id,
                &e.to_string(),
            );
            false
        }
    }
}

/// Bump the per-subscription dispatch (and, on failure, failure) counter
/// and OBSERVE the outcome. Returns `true` when the row was updated.
pub fn persist_dispatch_counter(
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
            note_failure(
                AuditStage::DispatchCounter,
                sub_id,
                correlation_id,
                &e.to_string(),
            );
            false
        }
    }
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

/// Snapshot at `now_unix`.
#[must_use]
pub fn delivery_at(now_unix: u64) -> WebhookAuditDelivery {
    let nz = |v: u64| if v == 0 { None } else { Some(v) };
    let failed_by_stage: Vec<(&'static str, u64)> = AuditStage::ALL
        .iter()
        .map(|s| {
            (
                s.as_str(),
                COUNTERS.failed[s.slot()].load(Ordering::Relaxed),
            )
        })
        .collect();
    let failed_total = failed_by_stage.iter().map(|(_, n)| *n).sum();
    let last_ok = COUNTERS.last_persisted_unix.load(Ordering::Relaxed);
    let last_fail = COUNTERS.last_failure_unix.load(Ordering::Relaxed);
    WebhookAuditDelivery {
        status_persisted_total: COUNTERS.status_persisted.load(Ordering::Relaxed),
        failed_by_stage,
        failed_total,
        last_persisted_at_seconds: nz(last_ok),
        last_failure_at_seconds: nz(last_fail),
        failing_now: last_fail != 0 && last_fail >= last_ok,
        actionable: failed_total > 0,
        observed_at_seconds: now_unix,
    }
}

/// [`delivery_at`] at the wall clock.
#[must_use]
pub fn delivery() -> WebhookAuditDelivery {
    delivery_at(unix_now_secs())
}

/// Failures since boot for one stage (test / doctor accessor).
#[must_use]
pub fn failures(stage: AuditStage) -> u64 {
    COUNTERS.failed[stage.slot()].load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::{
        AuditStage, delivery_at, failures, persist_dispatch_counter, persist_event_status,
    };

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
    fn status_update_success_is_counted_3659() {
        let (_d, p) = fresh_db();
        let conn = rusqlite::Connection::open(&p).expect("open");
        seed_pending(&conn, "sub-ok", "cid-ok");
        let before = delivery_at(0);
        assert!(persist_event_status(&conn, "sub-ok", "cid-ok", true));
        let status: String = conn
            .query_row(
                "SELECT delivery_status FROM subscription_events WHERE correlation_id = 'cid-ok'",
                [],
                |r| r.get(0),
            )
            .expect("read status");
        assert_eq!(status, "ack");
        let after = delivery_at(0);
        assert_eq!(
            after.status_persisted_total,
            before.status_persisted_total + 1
        );
        assert_eq!(after.failed_total, before.failed_total);
        assert!(after.last_persisted_at_seconds.is_some());
    }

    #[test]
    fn status_update_sql_failure_is_counted_with_stage_3659() {
        let (_d, p) = fresh_db();
        let conn = rusqlite::Connection::open(&p).expect("open");
        seed_pending(&conn, "sub-err", "cid-err");
        conn.execute_batch("DROP TABLE subscription_events")
            .expect("drop");
        let before = failures(AuditStage::StatusUpdate);
        assert!(!persist_event_status(&conn, "sub-err", "cid-err", false));
        assert_eq!(failures(AuditStage::StatusUpdate), before + 1);
        let snap = delivery_at(0);
        assert!(snap.actionable);
        assert!(snap.failing_now);
        assert!(snap.last_failure_at_seconds.is_some());
    }

    #[test]
    fn status_update_matching_no_row_is_distinct_stage_3659() {
        let (_d, p) = fresh_db();
        let conn = rusqlite::Connection::open(&p).expect("open");
        let before_no_row = failures(AuditStage::StatusNoRow);
        let before_update = failures(AuditStage::StatusUpdate);
        assert!(!persist_event_status(
            &conn,
            "sub-x",
            "cid-never-inserted",
            true
        ));
        assert_eq!(failures(AuditStage::StatusNoRow), before_no_row + 1);
        assert_eq!(failures(AuditStage::StatusUpdate), before_update);
    }

    #[test]
    fn dispatch_counter_failure_is_counted_3659() {
        let (_d, p) = fresh_db();
        let conn = rusqlite::Connection::open(&p).expect("open");
        conn.execute_batch("DROP TABLE subscriptions")
            .expect("drop");
        let before = failures(AuditStage::DispatchCounter);
        assert!(!persist_dispatch_counter(&conn, "sub-dc", "cid-dc", false));
        assert_eq!(failures(AuditStage::DispatchCounter), before + 1);
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
