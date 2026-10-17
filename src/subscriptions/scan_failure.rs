// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #7366 — a subscriber-LOOKUP failure at dispatch must not drop the
//! lifecycle event of a committed row.
//!
//! Dispatch has two funnels that look the subscribers up before anything is
//! admitted: `dispatch_event_with_details` (SQLite, `list_by_event`) and
//! `dispatch_event_postgres` (SAL `list_by_namespace_prefix`). Every failure
//! AFTER admission routes to `subscription_dlq` (#3191 F-5); a failure of the
//! lookup itself used to log a WARN and return, so a transient backend error
//! (the postgres XX000 bursts of #7130, a locked sqlite file) lost the event
//! with nothing `memory_subscription_dlq_list` could show.
//!
//! The fix has two steps, shared by both funnels:
//!
//! 1. [`retry_lookup`] / [`retry_lookup_async`] retry the lookup on the
//!    existing [`super::RETRY_BACKOFFS`] ladder (bounded: one initial attempt
//!    plus one retry per step);
//! 2. when the final attempt still fails, [`record_dispatch_scan_failure`]
//!    writes a durable `subscription_dlq` row under
//!    [`DISPATCH_SCAN_FAILED_SUB_ID`] that carries everything needed to
//!    re-dispatch the event (event, memory id, namespace, writer, details).
//!
//! It mirrors `record_dispatch_scan_truncation` (#2592): the record goes to
//! the sqlite audit-mirror DLQ on both backends, because that is the one
//! store `memory_subscription_dlq_list` reads.

use std::time::Duration;

use super::{DlqEntry, RETRY_BACKOFFS, record_dlq};

/// Reserved `subscription_dlq.subscription_id` under which a failed
/// subscriber lookup is recorded. Not a real subscription id: the lookup
/// failed, so the subscribers the event was owed to are unknown. The leading
/// `_` cannot collide with a UUID subscription id. The #1253 per-id depth cap
/// applies, so a sustained outage cannot fill the disk.
pub const DISPATCH_SCAN_FAILED_SUB_ID: &str = "_dispatch_scan_failed";

/// Closed vocabulary for the stored error class. The receiver-controlled or
/// driver-controlled text of the failure goes to the operator log only; the
/// stored `last_error` carries a class from this set (same posture as
/// [`super::dlq_reason`]).
pub mod error_class {
    /// A SQLite lookup failed because the database was busy or locked.
    pub const SQLITE_CONTENDED: &str = "sqlite_contended";
    /// Any other SQLite lookup failure.
    pub const SQLITE_ERROR: &str = "sqlite_error";
    /// A SAL store lookup failure without a backend SQLSTATE.
    pub const STORE_ERROR: &str = "store_error";
    /// Prefix of `store_sqlstate_<code>`: a SAL store failure that carried a
    /// well-formed five-character SQLSTATE.
    pub const STORE_SQLSTATE_PREFIX: &str = "store_sqlstate_";
}

/// Length of a SQLSTATE code.
const SQLSTATE_LEN: usize = 5;

/// Attempts a bounded lookup makes before it gives up: the first try plus one
/// retry per backoff step.
#[must_use]
pub fn lookup_attempts() -> usize {
    RETRY_BACKOFFS.len() + 1
}

/// Class a SQLite lookup error for the stored record.
#[must_use]
pub fn classify_sqlite_error(err: &anyhow::Error) -> &'static str {
    let contended = err.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(code, _))
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                )
        )
    });
    if contended {
        error_class::SQLITE_CONTENDED
    } else {
        error_class::SQLITE_ERROR
    }
}

/// Class a SAL lookup failure by its SQLSTATE, when it carries a well-formed
/// one (five ASCII alphanumerics); otherwise the generic store class.
#[must_use]
pub fn classify_sqlstate(sqlstate: Option<&str>) -> String {
    match sqlstate {
        Some(code)
            if code.len() == SQLSTATE_LEN && code.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            format!("{}{code}", error_class::STORE_SQLSTATE_PREFIX)
        }
        _ => error_class::STORE_ERROR.to_string(),
    }
}

/// Run `op`, retrying a failure on `backoffs` with a blocking pause. Returns
/// the last error once the ladder is exhausted.
///
/// # Errors
///
/// The error of the final attempt.
pub fn retry_lookup<T, E: std::fmt::Display>(
    backoffs: &[Duration],
    mut op: impl FnMut() -> Result<T, E>,
) -> Result<T, E> {
    let mut retried = 0;
    loop {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => match backoffs.get(retried) {
                Some(pause) => {
                    tracing::warn!(
                        attempt = retried + 1,
                        error = %e,
                        "subscriber lookup failed during dispatch; retrying (#7366)"
                    );
                    std::thread::sleep(*pause);
                    retried += 1;
                }
                None => return Err(e),
            },
        }
    }
}

/// Async twin of [`retry_lookup`]: the pause is a `tokio::time::sleep`, so the
/// executor thread is never blocked.
///
/// # Errors
///
/// The error of the final attempt.
pub async fn retry_lookup_async<T, E, F, Fut>(backoffs: &[Duration], mut op: F) -> Result<T, E>
where
    E: std::fmt::Display,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut retried = 0;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => match backoffs.get(retried) {
                Some(pause) => {
                    tracing::warn!(
                        attempt = retried + 1,
                        error = %e,
                        "subscriber lookup failed during dispatch; retrying (#7366)"
                    );
                    tokio::time::sleep(*pause).await;
                    retried += 1;
                }
                None => return Err(e),
            },
        }
    }
}

/// The dispatch inputs of the event whose lookup failed. Everything here is
/// stored in the record's payload so the event can be re-dispatched.
pub struct ScanFailure<'a> {
    pub event: &'a str,
    pub memory_id: &'a str,
    pub namespace: &'a str,
    pub agent_id: Option<&'a str>,
    pub details: Option<&'a serde_json::Value>,
}

/// Record one failed subscriber lookup: WARN (with the error class) plus a
/// durable `subscription_dlq` row under [`DISPATCH_SCAN_FAILED_SUB_ID`].
///
/// Best-effort and never panics: a DLQ write failure is itself logged at
/// ERROR; the WARN fires regardless.
pub fn record_dispatch_scan_failure(
    db_path: &std::path::Path,
    failure: &ScanFailure<'_>,
    error_class: &str,
) {
    let attempts = lookup_attempts();
    tracing::warn!(
        event_type = %failure.event,
        memory_id = %failure.memory_id,
        namespace = %failure.namespace,
        error_class = %error_class,
        attempts = attempts,
        "subscriber lookup FAILED after retries; the event was recorded to the \
         subscription DLQ for re-dispatch instead of being dropped (#7366)"
    );
    let now = chrono::Utc::now().to_rfc3339();
    let correlation_id = uuid::Uuid::new_v4().to_string();
    let payload = serde_json::json!({
        "memory_id": failure.memory_id,
        "namespace": failure.namespace,
        "agent_id": failure.agent_id,
        "details": failure.details,
        "attempts": attempts,
        "error_class": error_class,
    })
    .to_string();
    if let Err(e) = record_dlq(
        db_path,
        DISPATCH_SCAN_FAILED_SUB_ID,
        &correlation_id,
        failure.event,
        &payload,
        i64::try_from(attempts).unwrap_or(i64::MAX),
        &format!(
            "subscriber lookup failed after {attempts} attempts ({error_class}); \
             event deferred for re-dispatch (#7366)"
        ),
        &now,
        &now,
    ) {
        tracing::error!(
            correlation_id = %correlation_id,
            error = %e,
            "could not record the failed-lookup DLQ row: the event is lost (#7366)"
        );
    }
}

/// Whether `row` may be shown to `caller` by the DLQ inspector.
///
/// A failed-lookup row belongs to no subscription, so the owner gate that
/// guards every other row (#1118) cannot apply. It is attributed to the
/// agent whose committed write the event was for: the payload's `agent_id`.
/// A row without a writer (anonymous) is shown to nobody, and every other
/// row is not this function's business (`false`).
#[must_use]
pub fn scan_failure_visible_to(row: &DlqEntry, caller: &str) -> bool {
    row.subscription_id == DISPATCH_SCAN_FAILED_SUB_ID
        && serde_json::from_str::<serde_json::Value>(&row.payload)
            .ok()
            .and_then(|p| {
                p.get("agent_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            })
            .is_some_and(|writer| writer == caller)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn retry_lookup_returns_first_success_without_pausing_7366() {
        let calls = Cell::new(0);
        let got: Result<u32, String> = retry_lookup(&[Duration::from_secs(60)], || {
            calls.set(calls.get() + 1);
            Ok(7)
        });
        assert_eq!(got, Ok(7));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn retry_lookup_recovers_on_a_transient_failure_7366() {
        let calls = Cell::new(0);
        let got: Result<u32, String> = retry_lookup(&[Duration::ZERO, Duration::ZERO], || {
            calls.set(calls.get() + 1);
            if calls.get() < 3 {
                Err("boom".into())
            } else {
                Ok(9)
            }
        });
        assert_eq!(got, Ok(9));
        assert_eq!(calls.get(), 3, "initial + two retries");
    }

    #[test]
    fn retry_lookup_is_bounded_by_the_ladder_7366() {
        let calls = Cell::new(0);
        let got: Result<u32, String> = retry_lookup(&[Duration::ZERO; 3], || {
            calls.set(calls.get() + 1);
            Err("still down".into())
        });
        assert_eq!(got, Err("still down".to_string()));
        assert_eq!(calls.get(), 4, "initial + one retry per step, never more");
    }

    #[tokio::test]
    async fn retry_lookup_async_is_bounded_and_recovers_7366() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let got: Result<u32, String> = retry_lookup_async(&[Duration::ZERO; 2], || {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            async move {
                if n < 2 {
                    Err("boom".to_string())
                } else {
                    Ok(1)
                }
            }
        })
        .await;
        assert_eq!(got, Ok(1));
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let got: Result<u32, String> = retry_lookup_async(&[Duration::ZERO; 2], || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err("down".to_string()) }
        })
        .await;
        assert!(got.is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn sqlstate_class_accepts_only_well_formed_codes_7366() {
        assert_eq!(classify_sqlstate(Some("XX000")), "store_sqlstate_XX000");
        assert_eq!(
            classify_sqlstate(Some("bad code!")),
            error_class::STORE_ERROR
        );
        assert_eq!(classify_sqlstate(None), error_class::STORE_ERROR);
    }

    #[test]
    fn visibility_is_attributed_to_the_writer_only_7366() {
        let row = |payload: &str, sub: &str| DlqEntry {
            id: 1,
            subscription_id: sub.to_string(),
            correlation_id: "c".into(),
            event_type: "memory_store".into(),
            payload: payload.to_string(),
            retry_count: 4,
            last_error: String::new(),
            first_failed_at: String::new(),
            last_failed_at: String::new(),
        };
        let mine = row(r#"{"agent_id":"ai:a"}"#, DISPATCH_SCAN_FAILED_SUB_ID);
        assert!(scan_failure_visible_to(&mine, "ai:a"));
        assert!(!scan_failure_visible_to(&mine, "ai:b"));
        assert!(!scan_failure_visible_to(
            &row(r#"{"agent_id":null}"#, DISPATCH_SCAN_FAILED_SUB_ID),
            "ai:a"
        ));
        assert!(!scan_failure_visible_to(
            &row(r#"{"agent_id":"ai:a"}"#, "some-real-sub"),
            "ai:a"
        ));
    }
}
