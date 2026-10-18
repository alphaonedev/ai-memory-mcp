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
//! 1. the first failure is recorded at once ([`record_scan_failure_first`],
//!    #7498/#7499), then the lookup is retried on the existing
//!    [`super::RETRY_BACKOFFS`] ladder off the request path (bounded: one
//!    initial attempt plus one retry per step); a recovered retry dispatches
//!    and deletes the record ([`clear_scan_failure`]);
//! 2. when the final attempt still fails, [`settle_scan_failure`] updates the
//!    durable `subscription_dlq` row under
//!    [`DISPATCH_SCAN_FAILED_SUB_ID`] that carries everything needed to
//!    re-dispatch the event (event, memory id, namespace, writer, details).
//!
//! It mirrors `record_dispatch_scan_truncation` (#2592): the record goes to
//! the sqlite audit-mirror DLQ on both backends, because that is the one
//! store `memory_subscription_dlq_list` reads.

use std::time::Duration;

use super::{DlqEntry, RETRY_BACKOFFS};

/// Prefix of the reserved `subscription_dlq.subscription_id` under which a
/// failed subscriber lookup is recorded. Not a real subscription id: the
/// lookup failed, so the subscribers the event was owed to are unknown. The
/// leading `_` cannot collide with a UUID subscription id. The full id is
/// [`scan_failure_sub_id`]: one bucket PER NAMESPACE (#7409), so the #1253
/// per-id depth cap bounds each namespace on its own and a flood from one
/// cannot starve another's records.
pub const DISPATCH_SCAN_FAILED_SUB_ID: &str = "_dispatch_scan_failed";

/// Most failed-lookup rows one namespace may retain (#7409).
pub const SCAN_FAILURE_MAX_PER_NAMESPACE: i64 = 1_000;

/// Most failed-lookup rows retained across ALL namespaces (#7430): the
/// namespace is writer-chosen, so the per-namespace cap alone does not bound
/// the total.
pub const SCAN_FAILURE_MAX_TOTAL: i64 = super::MAX_SUBSCRIPTION_DLQ_ROWS;

/// Most failed-lookup rows one writer (`agent_id`; every anonymous writer
/// shares one bucket) may retain across ALL its namespaces (#7503). Below the
/// total cap, so one writer inventing namespaces cannot starve another tenant.
pub const SCAN_FAILURE_MAX_PER_WRITER: i64 = 2_500;

/// Most detached sqlite lookup-retry workers alive at once (#7410). Past it a
/// failure is recorded at once, without the ladder, instead of spawning.
pub const MAX_BACKGROUND_LOOKUP_RETRIES: usize = 32;

static BACKGROUND_RETRIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// The per-namespace `subscription_id` bucket for a failed lookup.
#[must_use]
pub fn scan_failure_sub_id(namespace: &str) -> String {
    format!("{DISPATCH_SCAN_FAILED_SUB_ID}:{namespace}")
}

/// Whether `sub_id` is a failed-lookup bucket.
#[must_use]
pub fn is_scan_failure_sub_id(sub_id: &str) -> bool {
    sub_id.starts_with(DISPATCH_SCAN_FAILED_SUB_ID)
}

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
fn classify_sqlite_error(err: &anyhow::Error) -> &'static str {
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

/// The first lookup attempt already failed with `first`: pause on `backoffs`
/// with a `tokio::time::sleep` (the executor thread is never blocked) and
/// retry `op` once per step. Returns the first success, or the error of the
/// final attempt once the ladder is exhausted.
///
/// # Errors
///
/// The error of the final attempt (`first` when `backoffs` is empty).
pub async fn retry_after_failure_async<T, E, F, Fut>(
    backoffs: &[Duration],
    first: E,
    mut op: F,
) -> Result<T, E>
where
    E: std::fmt::Display,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut last = first;
    for (n, pause) in backoffs.iter().enumerate() {
        tracing::warn!(
            attempt = n + 1,
            error = %last,
            "subscriber lookup failed during dispatch; retrying (#7366)"
        );
        tokio::time::sleep(*pause).await;
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) => last = e,
        }
    }
    Err(last)
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
/// ERROR; the WARN fires regardless. The row is final: it states that the
/// whole retry ladder was spent. See [`record_scan_failure_first`] for the
/// record written BEFORE the ladder.
pub fn record_dispatch_scan_failure(
    db_path: &std::path::Path,
    failure: &ScanFailure<'_>,
    error_class: &str,
) {
    let _ = write_record(db_path, failure, error_class, lookup_attempts());
}

/// Record-first (#7498, #7499): write the durable row for a lookup that has
/// failed ONCE, before the retry ladder runs, so a process exit or a cancelled
/// future inside the ladder window never loses the event. Returns the row id
/// to hand to [`clear_scan_failure`] (a retry recovered) or
/// [`settle_scan_failure`] (the ladder was spent or skipped); `None` when the
/// row could not be written (already logged at ERROR).
#[must_use]
pub fn record_scan_failure_first(
    db_path: &std::path::Path,
    failure: &ScanFailure<'_>,
    error_class: &str,
) -> Option<i64> {
    write_record(db_path, failure, error_class, 1)
}

fn write_record(
    db_path: &std::path::Path,
    failure: &ScanFailure<'_>,
    error_class: &str,
    attempts: usize,
) -> Option<i64> {
    let ladder_spent = attempts >= lookup_attempts();
    tracing::warn!(
        event_type = %failure.event,
        memory_id = %failure.memory_id,
        namespace = %failure.namespace,
        error_class = %error_class,
        attempts = attempts,
        ladder_spent = ladder_spent,
        "subscriber lookup FAILED; the event is recorded to the subscription \
         DLQ for re-dispatch instead of being dropped (#7366)"
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
    let last_error = settled_text(attempts, error_class);
    match insert_capped(
        db_path,
        &scan_failure_sub_id(failure.namespace),
        &correlation_id,
        failure.event,
        &payload,
        &last_error,
        &now,
        attempts,
    ) {
        Ok(id) => Some(id),
        Err(e) => {
            tracing::error!(
                correlation_id = %correlation_id,
                memory_id = %failure.memory_id,
                event_type = %failure.event,
                namespace = %failure.namespace,
                error = %e,
                "could not record the failed-lookup DLQ row: the event is lost (#7366)"
            );
            None
        }
    }
}

/// The stored `last_error` of a failed-lookup row after `attempts` attempts.
fn settled_text(attempts: usize, error_class: &str) -> String {
    if attempts >= lookup_attempts() {
        format!(
            "subscriber lookup failed after {attempts} attempts ({error_class}); \
             event deferred for re-dispatch (#7366)"
        )
    } else {
        format!(
            "subscriber lookup failed ({error_class}); recorded before the retry \
             ladder, removed if a retry recovers (#7366)"
        )
    }
}

/// A retry recovered and the event was dispatched: delete the record that
/// [`record_scan_failure_first`] wrote. Logged, never panics; a row that stays
/// behind is a stale record, never a lost event.
pub fn clear_scan_failure(db_path: &std::path::Path, row_id: i64) {
    let prefix_len = i64::try_from(DISPATCH_SCAN_FAILED_SUB_ID.len()).unwrap_or(i64::MAX);
    let cleared = crate::db::open(db_path)
        .map_err(anyhow::Error::from)
        .and_then(|conn| {
            conn.execute(
                "DELETE FROM subscription_dlq \
                 WHERE id = ?1 AND substr(subscription_id, 1, ?2) = ?3",
                rusqlite::params![row_id, prefix_len, DISPATCH_SCAN_FAILED_SUB_ID],
            )
            .map_err(anyhow::Error::from)
        });
    if let Err(e) = cleared {
        tracing::warn!(
            row_id = row_id,
            error = %e,
            "could not delete the recovered failed-lookup DLQ row; it stays as a stale record (#7498)"
        );
    }
}

/// The ladder was spent (`attempts` = [`lookup_attempts`]) or skipped
/// (`attempts` = 1, no worker available): update the record written by
/// [`record_scan_failure_first`] so it states what actually happened.
pub fn settle_scan_failure(
    db_path: &std::path::Path,
    row_id: i64,
    attempts: usize,
    error_class: &str,
) {
    let text = if attempts >= lookup_attempts() {
        settled_text(attempts, error_class)
    } else {
        format!(
            "subscriber lookup failed ({error_class}); no retry worker was available, \
             event deferred for re-dispatch (#7366)"
        )
    };
    let now = chrono::Utc::now().to_rfc3339();
    let attempts = i64::try_from(attempts).unwrap_or(i64::MAX);
    let settled = crate::db::open(db_path)
        .map_err(anyhow::Error::from)
        .and_then(|conn| {
            conn.execute(
                "UPDATE subscription_dlq \
                 SET retry_count = ?2, last_error = ?3, last_failed_at = ?4 WHERE id = ?1",
                rusqlite::params![row_id, attempts, text, now],
            )
            .map_err(anyhow::Error::from)
        });
    if let Err(e) = settled {
        tracing::warn!(row_id = row_id, error = %e, "could not settle the failed-lookup DLQ row (#7498)");
    }
}

/// Owned copy of a [`ScanFailure`], movable onto a worker thread or task.
#[derive(Clone)]
pub struct OwnedFailure {
    event: String,
    memory_id: String,
    namespace: String,
    agent_id: Option<String>,
    details: Option<serde_json::Value>,
}

impl OwnedFailure {
    /// Build the owned copy from the dispatch inputs.
    #[must_use]
    pub fn new(
        event: &str,
        memory_id: &str,
        namespace: &str,
        agent_id: Option<&str>,
        details: Option<serde_json::Value>,
    ) -> Self {
        Self {
            event: event.to_string(),
            memory_id: memory_id.to_string(),
            namespace: namespace.to_string(),
            agent_id: agent_id.map(str::to_string),
            details,
        }
    }

    /// Copy `f` so it can move onto a worker.
    #[must_use]
    pub fn of(f: &ScanFailure<'_>) -> Self {
        Self {
            event: f.event.to_string(),
            memory_id: f.memory_id.to_string(),
            namespace: f.namespace.to_string(),
            agent_id: f.agent_id.map(str::to_string),
            details: f.details.cloned(),
        }
    }

    /// Borrow the copy back as a [`ScanFailure`].
    #[must_use]
    pub fn borrowed(&self) -> ScanFailure<'_> {
        ScanFailure {
            event: &self.event,
            memory_id: &self.memory_id,
            namespace: &self.namespace,
            agent_id: self.agent_id.as_deref(),
            details: self.details.as_ref(),
        }
    }
}

/// Releases a [`BACKGROUND_RETRIES`] slot when the worker ends.
pub struct Slot;

impl Drop for Slot {
    fn drop(&mut self) {
        BACKGROUND_RETRIES.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Claim one of the [`MAX_BACKGROUND_LOOKUP_RETRIES`] worker slots.
#[must_use]
pub fn take_slot() -> Option<Slot> {
    let taken = BACKGROUND_RETRIES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if taken >= MAX_BACKGROUND_LOOKUP_RETRIES {
        BACKGROUND_RETRIES.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        None
    } else {
        Some(Slot)
    }
}

/// The sqlite funnel's inline lookup failed: WARN with the error class, then
/// either record (when this already is the retry worker) or retry off-lock.
pub(super) fn on_sqlite_lookup_failure(
    err: &anyhow::Error,
    retried: bool,
    db_path: &std::path::Path,
    failure: &ScanFailure<'_>,
) {
    let class = classify_sqlite_error(err);
    tracing::warn!(
        error_class = class,
        "subscription list failed during dispatch: {err}"
    );
    if retried {
        record_dispatch_scan_failure(db_path, failure, class);
    } else {
        retry_off_lock(db_path, failure, class);
    }
}

/// The first, inline sqlite lookup failed (#7410). The caller holds the
/// shared connection lock, so it must not sleep: hand the retries to a
/// bounded detached worker that owns its connection, pauses on the
/// [`RETRY_BACKOFFS`] ladder with no lock held, re-dispatches when the lookup
/// recovers and records the failure when the ladder is exhausted. With every
/// worker slot busy, or the worker unspawnable, record at once.
pub(super) fn retry_off_lock(db_path: &std::path::Path, failure: &ScanFailure<'_>, class: &str) {
    // Record-first (#7498): the durable row exists before the ladder starts.
    let row = record_scan_failure_first(db_path, failure, class);
    let Some(slot) = take_slot() else {
        settle_or_record(db_path, failure, class, row, 1);
        return;
    };
    let owned = OwnedFailure::of(failure);
    let path = db_path.to_path_buf();
    let class_owned = class.to_string();
    let spawned = std::thread::Builder::new()
        .name("dispatch-lookup-retry".to_string())
        .spawn(move || {
            let _slot = slot;
            let conn = open_for_retry(&path);
            for pause in RETRY_BACKOFFS {
                std::thread::sleep(*pause);
                let Some(c) = conn.as_ref() else { continue };
                if super::list_by_event(c, &owned.event).is_ok() {
                    let f = owned.borrowed();
                    super::dispatch_inner(
                        c,
                        f.event,
                        f.memory_id,
                        f.namespace,
                        f.agent_id,
                        &path,
                        owned.details.clone(),
                        true,
                    );
                    // Dispatched first, then the record goes: a crash in
                    // between leaves a stale record, never a lost event.
                    if let Some(id) = row {
                        clear_scan_failure(&path, id);
                    }
                    return;
                }
            }
            settle_or_record(
                &path,
                &owned.borrowed(),
                &class_owned,
                row,
                lookup_attempts(),
            );
        });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "could not spawn the lookup-retry worker; settling the record at once (#7410)");
        settle_or_record(db_path, failure, class, row, 1);
    }
}

/// The retry worker's own connection.
fn open_for_retry(path: &std::path::Path) -> Option<rusqlite::Connection> {
    match crate::db::open(path) {
        Ok(conn) => Some(conn),
        Err(e) => {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "lookup-retry worker could not open the database; the retry ladder is skipped and the record stays (#7505)"
            );
            None
        }
    }
}

/// The ladder is spent or was skipped: settle the record written first, or
/// write it now when the first write failed.
pub fn settle_or_record(
    db_path: &std::path::Path,
    failure: &ScanFailure<'_>,
    class: &str,
    row: Option<i64>,
    attempts: usize,
) {
    match row {
        Some(id) => settle_scan_failure(db_path, id, attempts, class),
        None => {
            let _ = write_record(db_path, failure, class, attempts);
        }
    }
}

/// Insert one failed-lookup row, refusing it past the per-namespace cap or the
/// total cap. Both compares live INSIDE the single `INSERT ... SELECT ...
/// WHERE`, so a concurrent writer cannot race past either (#7430).
fn insert_capped(
    db_path: &std::path::Path,
    sub_id: &str,
    correlation_id: &str,
    event: &str,
    payload: &str,
    last_error: &str,
    now: &str,
    attempts: usize,
) -> anyhow::Result<i64> {
    let conn = crate::db::open(db_path)?;
    let prefix_len = i64::try_from(DISPATCH_SCAN_FAILED_SUB_ID.len()).unwrap_or(i64::MAX);
    let inserted = conn.execute(
        "INSERT INTO subscription_dlq \
         (subscription_id, correlation_id, event_type, payload, retry_count, last_error, \
          first_failed_at, last_failed_at) \
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7 \
         WHERE (SELECT COUNT(*) FROM subscription_dlq WHERE subscription_id = ?1) < ?8 \
           AND (SELECT COUNT(*) FROM subscription_dlq \
                WHERE substr(subscription_id, 1, ?9) = ?10) < ?11 \
           AND (SELECT COUNT(*) FROM subscription_dlq \
                WHERE CASE WHEN substr(subscription_id, 1, ?9) = ?10 \
                           THEN COALESCE(json_extract(payload, '$.agent_id'), '') END \
                      = COALESCE(json_extract(?4, '$.agent_id'), '')) < ?12",
        rusqlite::params![
            sub_id,
            correlation_id,
            event,
            payload,
            i64::try_from(attempts).unwrap_or(i64::MAX),
            last_error,
            now,
            SCAN_FAILURE_MAX_PER_NAMESPACE,
            prefix_len,
            DISPATCH_SCAN_FAILED_SUB_ID,
            SCAN_FAILURE_MAX_TOTAL,
            SCAN_FAILURE_MAX_PER_WRITER,
        ],
    )?;
    if inserted == 0 {
        crate::metrics::record_subscription_dlq_overflow();
        anyhow::bail!(
            "failed-lookup DLQ at cap (per-namespace {SCAN_FAILURE_MAX_PER_NAMESPACE}, per-writer {SCAN_FAILURE_MAX_PER_WRITER}, total {SCAN_FAILURE_MAX_TOTAL})"
        );
    }
    Ok(conn.last_insert_rowid())
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
    scan_failure_visible(row, caller, &[])
}

/// [`scan_failure_visible_to`] plus the operator view (#7501): a member of the
/// admin allowlist (`AppState.admin_agent_ids`, or the process allowlist on
/// MCP/CLI) sees EVERY failed-lookup row, anonymous ones included; everyone
/// else keeps the owner-scoped view. Only failed-lookup rows are widened.
#[must_use]
pub fn scan_failure_visible(row: &DlqEntry, caller: &str, admin_ids: &[String]) -> bool {
    if !is_scan_failure_sub_id(&row.subscription_id) {
        return false;
    }
    crate::identity::is_admin_agent_in(caller, admin_ids)
        || serde_json::from_str::<serde_json::Value>(&row.payload)
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

    #[tokio::test]
    async fn retry_after_failure_async_is_bounded_and_recovers_7366() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let got: Result<u32, String> =
            retry_after_failure_async(&[Duration::ZERO; 2], "first".to_string(), || {
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
        let got: Result<u32, String> =
            retry_after_failure_async(&[Duration::ZERO; 2], "first".to_string(), || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { Err("down".to_string()) }
            })
            .await;
        assert!(got.is_err());
        // The first failure was already taken by the caller: one retry per pause.
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// Captures tracing output so a test can assert what an ERROR line carries.
    #[derive(Clone, Default)]
    struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Ok(mut g) = self.0.lock() {
                g.extend_from_slice(buf);
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured<F: FnOnce()>(f: F) -> String {
        let cap = Capture::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(cap.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::with_default(sub, f);
        let bytes = cap.0.lock().map(|g| g.clone()).unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn double_failure_error_names_the_event_and_never_the_payload_7504() {
        if crate::config::run_env_isolated_child_or_spawn(
            "subscriptions::scan_failure::tests::double_failure_error_names_the_event_and_never_the_payload_7504",
        ) {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        // The directory does not exist, so the sqlite open fails: both the
        // lookup and its record failed.
        let path = dir.path().join("missing-dir").join("x.db");
        let details = serde_json::json!({"secret": "PAYLOAD-SECRET-7504"});
        let out = captured(|| {
            record_dispatch_scan_failure(
                &path,
                &ScanFailure {
                    event: "memory_store",
                    memory_id: "mem-7504",
                    namespace: "team/ns-7504",
                    agent_id: Some("ai:writer"),
                    details: Some(&details),
                },
                "sqlite_error",
            );
        });
        let line = out
            .lines()
            .find(|l| l.contains("ERROR"))
            .unwrap_or_default()
            .to_string();
        assert!(
            line.contains("mem-7504"),
            "memory_id on the ERROR line: {line}"
        );
        assert!(
            line.contains("memory_store"),
            "event kind on the ERROR line: {line}"
        );
        assert!(
            line.contains("team/ns-7504"),
            "namespace on the ERROR line: {line}"
        );
        assert!(
            !out.contains("PAYLOAD-SECRET-7504"),
            "the payload must never be logged"
        );
    }

    #[test]
    fn worker_open_failure_is_logged_at_error_with_the_path_7505() {
        if crate::config::run_env_isolated_child_or_spawn(
            "subscriptions::scan_failure::tests::worker_open_failure_is_logged_at_error_with_the_path_7505",
        ) {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing-dir").join("w.db");
        let out = captured(|| {
            assert!(open_for_retry(&path).is_none());
        });
        let line = out
            .lines()
            .find(|l| l.contains("ERROR"))
            .unwrap_or_default()
            .to_string();
        assert!(line.contains("w.db"), "the path on the ERROR line: {line}");
    }

    #[test]
    fn recorder_migrates_a_fresh_database_through_the_open_funnel_7507() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fresh.db");
        // A file with no schema at all: the raw open this replaced failed
        // with "no such table: subscription_dlq".
        let id = record_scan_failure_first(
            &path,
            &ScanFailure {
                event: "memory_store",
                memory_id: "m",
                namespace: "team/x",
                agent_id: None,
                details: None,
            },
            "sqlite_error",
        );
        assert!(id.is_some(), "the funnel opens and migrates the database");
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
