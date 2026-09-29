// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3979 — webhook deliveries that were admitted but whose worker has not
//! started yet.
//!
//! A delivery's `subscription_events` audit row is written by its worker,
//! and the worker runs only once the delivery holds a `DISPATCH_SEMAPHORE`
//! permit AND the tokio blocking pool has started it. Admission itself
//! persists nothing. Before #3979, a delivery still waiting at the shutdown
//! drain deadline was dropped with the runtime: no audit row, no
//! `subscription_dlq` row, invisible to `memory_subscription_replay` and to
//! `memory_subscription_dlq_list`.
//!
//! Every admitted delivery is now registered in [`REGISTRY`] until one of
//! two parties takes it:
//!
//! * its worker, which [`claim`]s the entry as its first act and from then
//!   on owns the delivery (the audit row, the send, the DLQ row);
//! * the shutdown drain, which, when the deadline is hit, records every
//!   entry still here to the DLQ ([`sweep_to_dlq`]).
//!
//! Removal from the table is the single ownership hand-off, done under the
//! table's lock, so a delivery is recorded by exactly one of the two and
//! never by both. An entry whose DLQ write fails STAYS in the table: the
//! sweep never drops what it could not record, so if the runtime survives
//! the deadline (a one-shot CLI still finishing), the worker can still claim
//! and deliver it.
//!
//! **Not covered: a crash.** The table lives in process memory. A SIGKILL,
//! an OOM kill or a panic-abort before the drain loses every delivery that
//! had not started, exactly as before. Closing that needs the audit row
//! persisted at admission, on the dispatching caller's connection (#3979
//! follow-up, #3980).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Tracing target for the shutdown sweep.
const TRACE_TARGET: &str = "ai_memory::subscriptions::unstarted";

/// Everything the DLQ row needs, captured at admission.
pub(super) struct UnstartedDelivery {
    /// The sqlite audit-mirror path the worker would have written to. On a
    /// postgres-backed daemon this is still the sqlite sidecar: both the
    /// DLQ writer and `memory_subscription_dlq_list` use it.
    pub(super) db_path: PathBuf,
    pub(super) sub_id: String,
    pub(super) correlation_id: String,
    pub(super) event: String,
    pub(super) body: String,
}

/// Registration handle a worker redeems with [`claim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Ticket(u64);

/// Admitted deliveries whose worker has not claimed them. A type (not two
/// bare statics) so the unit tests can drive a private instance: sweeping
/// the process-wide one would record sibling tests' live deliveries.
struct Registry {
    next_ticket: AtomicU64,
    /// `BTreeMap` so the sweep records deliveries in admission order.
    table: Mutex<BTreeMap<u64, UnstartedDelivery>>,
}

static REGISTRY: Registry = Registry::new();

impl Registry {
    const fn new() -> Self {
        Self {
            next_ticket: AtomicU64::new(0),
            table: Mutex::new(BTreeMap::new()),
        }
    }

    /// Every operation on the table is a single insert or remove, so a
    /// panic while the lock was held cannot leave an entry half-written;
    /// recovering the guard is sound (CONCURRENCY-18).
    fn table(&self) -> MutexGuard<'_, BTreeMap<u64, UnstartedDelivery>> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self, delivery: UnstartedDelivery) -> Ticket {
        // Relaxed: the counter only has to hand out distinct values
        // (CONCURRENCY-07); the table's mutex orders the entries.
        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        self.table().insert(ticket, delivery);
        Ticket(ticket)
    }

    fn claim(&self, ticket: Ticket) -> bool {
        self.table().remove(&ticket.0).is_some()
    }
}

/// Register an admitted delivery. Called on the dispatching thread before
/// the worker is spawned, so no worker can look for an entry that is not
/// there yet.
pub(super) fn register(delivery: UnstartedDelivery) -> Ticket {
    REGISTRY.register(delivery)
}

/// Take ownership of the delivery. `true`: the worker owns it and must run
/// it. `false`: the shutdown sweep already recorded it to the DLQ, and the
/// worker must NOT send it (it would be delivered AND sit in the DLQ).
pub(super) fn claim(ticket: Ticket) -> bool {
    REGISTRY.claim(ticket)
}

/// What [`sweep_to_dlq`] did with the deliveries it found.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct UnstartedSweep {
    /// Recorded to `subscription_dlq` with reason
    /// [`super::dlq_reason::SHUTDOWN_UNSTARTED`].
    pub recorded: usize,
    /// The DLQ write failed (each one is logged at ERROR with its identity).
    /// These stay registered; if the process exits now they are lost.
    pub unrecorded: usize,
}

/// Record every delivery whose worker has not started to the DLQ, at the
/// shutdown drain deadline.
///
/// This is synchronous SQLite I/O and it holds the table lock across it, on
/// purpose. It runs once, after the drain deadline, and is bounded by the
/// number of queued deliveries. Holding the lock is what keeps the hand-off
/// exact: a worker that reaches [`claim`] during the sweep waits, then finds
/// its entry either gone (recorded, so it does nothing) or still present
/// (the DLQ write failed, so it delivers).
pub(super) fn sweep_to_dlq() -> UnstartedSweep {
    REGISTRY.sweep_to_dlq()
}

impl Registry {
    fn sweep_to_dlq(&self) -> UnstartedSweep {
        let mut table = self.table();
        if table.is_empty() {
            return UnstartedSweep::default();
        }
        let now = chrono::Utc::now().to_rfc3339();
        let mut sweep = UnstartedSweep::default();
        table.retain(|_, d| {
            // `record_dlq` opens its own connection per row: one open per
            // stranded delivery, once, at shutdown. It is the same capped,
            // atomic insert every other DLQ row goes through (#1253, #3191 F-4).
            let result = super::record_dlq(
                &d.db_path,
                &d.sub_id,
                &d.correlation_id,
                &d.event,
                &d.body,
                0,
                super::dlq_reason::SHUTDOWN_UNSTARTED,
                &now,
                &now,
            );
            match result {
                Ok(()) => {
                    sweep.recorded += 1;
                    false
                }
                Err(e) => {
                    sweep.unrecorded += 1;
                    tracing::error!(
                        target: TRACE_TARGET,
                        subscription_id = %d.sub_id,
                        correlation_id = %d.correlation_id,
                        event_type = %d.event,
                        error = %e,
                        "shutdown DLQ sweep: could not record a not-yet-started webhook \
                         delivery; it is LOST if the process exits now (#3979)"
                    );
                    true
                }
            }
        });
        sweep
    }
}

/// What [`drain_dispatches_with_report`] saw at the deadline.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct DispatchDrainReport {
    /// Every admitted delivery finished within the budget.
    pub drained: bool,
    /// Deliveries whose worker had started and was still running at the
    /// deadline. Each has its `subscription_events` audit row (written
    /// before the first send), so replay-from-cursor re-delivers it.
    pub started_in_flight: usize,
    /// Deliveries whose worker had not started, and what the DLQ sweep
    /// did with them.
    pub unstarted: UnstartedSweep,
}

/// [`super::drain_dispatches`] with the counts the shutdown log reports.
///
/// #3979 — on a miss, the deliveries still queued for a
/// `DISPATCH_SEMAPHORE` permit or a blocking-pool slot have no audit row
/// (their worker writes it), so dropping the runtime would lose them
/// silently. They are recorded to `subscription_dlq` with reason
/// [`super::dlq_reason::SHUTDOWN_UNSTARTED`] before this returns, and their
/// workers will not send them if they run later. The sweep is synchronous
/// on the calling task: it happens once, after the deadline, and must not
/// wait on the blocking pool whose backlog it is recording.
pub async fn drain_dispatches_with_report(timeout: std::time::Duration) -> DispatchDrainReport {
    if tokio::time::timeout(timeout, super::wait_dispatch_idle())
        .await
        .is_ok()
    {
        return DispatchDrainReport {
            drained: true,
            ..DispatchDrainReport::default()
        };
    }
    let unstarted = sweep_to_dlq();
    // Recorded deliveries still hold their in-flight slot until their
    // async task is dropped, so subtract both halves of the sweep.
    let started_in_flight =
        super::dispatch_in_flight().saturating_sub(unstarted.recorded + unstarted.unrecorded);
    DispatchDrainReport {
        drained: false,
        started_in_flight,
        unstarted,
    }
}

impl DispatchDrainReport {
    /// Log a drain miss with its counts; silent when the fan-out drained.
    /// `surface` names the caller ("one-shot CLI", "daemon") so the line
    /// says which shutdown it was.
    pub fn log_miss(&self, surface: &str) {
        if self.drained {
            return;
        }
        let Self {
            started_in_flight: started,
            unstarted:
                UnstartedSweep {
                    recorded,
                    unrecorded,
                },
            ..
        } = *self;
        tracing::warn!(
            target: TRACE_TARGET,
            started_in_flight = started,
            unstarted_dlq_recorded = recorded,
            unstarted_unrecorded = unrecorded,
            "{surface} shutdown: webhook fan-out did not drain within the budget; the \
             write(s) are durable. {started} delivery(ies) had started and have an audit \
             row (replay from the subscription cursor re-delivers them); {recorded} had \
             not started and were recorded to the subscription DLQ with reason \
             `shutdown_unstarted` (memory_subscription_dlq_list); {unrecorded} had not \
             started and could NOT be recorded, so they are lost when the process exits \
             (#3979)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_db() -> (tempfile::NamedTempFile, PathBuf) {
        let f = tempfile::NamedTempFile::new().expect("tempfile");
        let p = f.path().to_path_buf();
        let _ = crate::db::open(&p).expect("db::open");
        (f, p)
    }

    fn delivery(db_path: &std::path::Path, n: u8) -> UnstartedDelivery {
        UnstartedDelivery {
            db_path: db_path.to_path_buf(),
            sub_id: format!("sub-{n}"),
            correlation_id: format!("corr-{n}"),
            event: "memory_store".into(),
            body: format!("{{\"n\":{n}}}"),
        }
    }

    fn dlq_rows(db_path: &std::path::Path) -> Vec<(String, String, i64, String, String)> {
        let conn = rusqlite::Connection::open(db_path).expect("open");
        let mut stmt = conn
            .prepare(
                "SELECT subscription_id, correlation_id, retry_count, last_error, payload \
                 FROM subscription_dlq ORDER BY id",
            )
            .expect("prepare");
        stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .expect("query")
        .map(|r| r.expect("row"))
        .collect()
    }

    /// The hand-off is exact: a delivery its worker claimed is not swept, a
    /// swept delivery cannot be claimed (so it is never sent late), and the
    /// DLQ row carries the full payload with the closed-vocabulary reason.
    #[test]
    fn sweep_records_only_unclaimed_and_a_swept_delivery_is_never_claimed_3979() {
        let (_keep, db) = fresh_db();
        let registry = Registry::new();
        let started = registry.register(delivery(&db, 1));
        let queued = registry.register(delivery(&db, 2));
        assert!(
            registry.claim(started),
            "a registered delivery is claimable"
        );

        let sweep = registry.sweep_to_dlq();
        assert_eq!(
            sweep,
            UnstartedSweep {
                recorded: 1,
                unrecorded: 0
            }
        );
        assert!(
            !registry.claim(queued),
            "a swept delivery must not be claimable: its worker would send a \
             delivery that already sits in the DLQ"
        );
        assert!(registry.table().is_empty());
        assert_eq!(
            dlq_rows(&db),
            vec![(
                "sub-2".to_owned(),
                "corr-2".to_owned(),
                0,
                crate::subscriptions::dlq_reason::SHUTDOWN_UNSTARTED.to_owned(),
                "{\"n\":2}".to_owned(),
            )]
        );
        assert_eq!(
            registry.sweep_to_dlq(),
            UnstartedSweep::default(),
            "a second sweep finds nothing"
        );
    }

    /// Fail closed: a delivery the sweep could not record stays registered,
    /// so a runtime that outlives the deadline can still deliver it.
    #[test]
    fn sweep_keeps_a_delivery_it_could_not_record_3979() {
        let dir = tempfile::tempdir().expect("tempdir");
        let unwritable = dir.path().join("no-such-dir").join("db.sqlite");
        let registry = Registry::new();
        let queued = registry.register(delivery(&unwritable, 3));

        let sweep = registry.sweep_to_dlq();
        assert_eq!(
            sweep,
            UnstartedSweep {
                recorded: 0,
                unrecorded: 1
            }
        );
        assert_eq!(registry.table().len(), 1, "the unrecorded entry is kept");
        assert!(
            registry.claim(queued),
            "the worker still owns a delivery the sweep could not record"
        );
    }

    /// Both arms of the shutdown log line run (the miss arm formats every
    /// count into the operator-facing WARN).
    #[test]
    fn log_miss_is_silent_when_drained_and_counts_on_a_miss_3979() {
        DispatchDrainReport {
            drained: true,
            ..DispatchDrainReport::default()
        }
        .log_miss("test");
        DispatchDrainReport {
            drained: false,
            started_in_flight: 1,
            unstarted: UnstartedSweep {
                recorded: 2,
                unrecorded: 3,
            },
        }
        .log_miss("test");
    }
}
