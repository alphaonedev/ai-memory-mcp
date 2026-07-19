// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 Policy-Engine Item 3 — deferred audit-log queue for the
//! storage governance pre-write hook.
//!
//! # The gap this closes
//!
//! The substrate's `GOVERNANCE_PRE_WRITE` hook (installed in
//! `daemon_runtime::bootstrap_serve`, consulted from every
//! `storage::insert*` call) ran
//! [`super::agent_action::check_agent_action_no_audit`] — the
//! `_no_audit` suffix is there because emitting a `signed_events` row
//! from INSIDE the in-flight INSERT transaction would re-enter the
//! same `Connection` and deadlock under the substrate's
//! `Arc<Mutex<Connection>>` lock.
//!
//! Consequence: **storage refusals were typed-but-not-cryptographically-logged**.
//! Other paths (the audited [`super::agent_action::check_agent_action`]
//! variant) DO chain-log via `signed_events`. That asymmetry was the
//! known gap in the bypass-impossibility audit story.
//!
//! # The fix — deferred chain-log
//!
//! This module ships a process-wide `DeferredAuditQueue`:
//!
//! 1. The storage hook captures the refusal verdict + agent identity
//!    + canonical action payload as a [`DeferredAuditEvent`] and
//!    submits it to the queue via [`DeferredAuditQueue::submit`]
//!    (non-blocking, never panics).
//! 2. A background drainer task ([`spawn_drainer_task`]) owns a FRESH
//!    `Connection` (opened against the same `db_path` but NOT the
//!    substrate writer's connection — SQLite WAL allows parallel
//!    readers and the drainer's writes don't contend with the
//!    in-flight `storage::insert` transaction because it has
//!    already released its lock by the time the drainer runs).
//! 3. For every received event, the drainer appends a
//!    `governance.refusal` row to `signed_events`. The chain-log
//!    property closes.
//!
//! # Supervisor pattern
//!
//! The drainer task is wrapped by [`spawn_supervised_drainer`], which
//! keeps ownership of the receiver while catching sink panics. It can
//! therefore rebuild the sink and retry the in-flight event without
//! dropping the receiver or the queued audit chain.
//!
//! # Backpressure / lossiness
//!
//! The channel is `tokio::sync::mpsc::unbounded_channel` by design:
//!
//! - Refusals are rare (a properly-configured fleet refuses
//!   << 1% of writes).
//! - A bounded channel would silently drop on full — and a silent
//!   audit drop IS a security regression we cannot accept.
//! - Memory pressure under attack is bounded by the rate at which the
//!   drainer can append `signed_events` rows; on macOS / Linux a
//!   single SQLite append in WAL mode is ~25-100 microseconds, so a
//!   sustained 100k refusals/second saturates one core but never
//!   blocks the storage write path.
//!
//! # Graceful shutdown
//!
//! [`DeferredAuditQueue::close_and_flush`] drops the sender and
//! awaits the supervisor task to terminate. The drainer drains every
//! still-buffered event before exiting; pending events MUST land in
//! `signed_events` before the daemon's tokio runtime is torn down,
//! or the chain-log property is broken.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::governance::agent_action::{AgentAction, Decision};
use crate::signed_events::{SignedEvent, append_signed_event, payload_hash};

/// Cluster-C SEC-3 (issue #767) — maximum number of times a sink will
/// retry a single audit append after a `SQLITE_CONSTRAINT_UNIQUE` race
/// (concurrent writer beat us to the same `sequence` value on the
/// `idx_signed_events_sequence` UNIQUE index). The BEGIN IMMEDIATE wrap
/// in `append_signed_event` should make true contention rare; this
/// retry budget is the safety belt. After exhausting it the event
/// lands in `signed_events_dlq` so the audit drop is never silent.
const APPEND_UNIQUE_RACE_MAX_RETRIES: usize = 5;

/// Delay the first panic retry by this many milliseconds. Retrying a
/// persistently panicking sink without a suspension point can monopolize a
/// Tokio worker and amplify panic-hook/log output.
const PANIC_RETRY_BACKOFF_BASE_MS: u64 = 10;

/// Cap panic-retry backoff so a transiently repaired sink is retried while
/// persistent failure remains scheduler-friendly and operationally visible.
const PANIC_RETRY_BACKOFF_MAX_MS: u64 = 1_000;

/// Defensive upper bound for one journal frame. Refusal payloads are normally
/// only a few KiB; bounding recovery prevents a corrupt length prefix from
/// driving an unbounded allocation.
const JOURNAL_MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Suffix for the per-occurrence crash spool used by new-format records.
const JOURNAL_SPOOL_SUFFIX: &str = ".spool";
const JOURNAL_SPOOL_MAX_ENTRIES: usize = 4_096;
const JOURNAL_SPOOL_MAX_BYTES: u64 = 32 * 1024 * 1024;
const JOURNAL_LEGACY_REPLAY_MAX_BYTES: u64 = 32 * 1024 * 1024;
const JOURNAL_OVERFLOW_MARKER_LIMIT: usize = 256;
const JOURNAL_OVERFLOW_PREFIX: &str = ".overflow-";
const JOURNAL_OVERFLOW_SATURATED: &str = ".overflow-saturated";
/// Stable fail-closed reason propagated when a blocking verdict cannot be
/// durably admitted to the deferred audit path.
pub const AUDIT_ADMISSION_FAILED: &str =
    "governance refusal audit admission failed; action remains blocked";

/// Wire-name for the deferred refusal audit row. Audit-side dashboards
/// filter on this string to surface storage-hook refusals separate
/// from the existing `governance.check` rows produced by the audited
/// `check_agent_action` path.
pub const GOVERNANCE_REFUSAL_EVENT_TYPE: &str = "governance.refusal";

/// One refusal captured by the storage hook, awaiting flush to the
/// `signed_events` chain.
///
/// All fields are owned (no borrows) so the event can cross the mpsc
/// channel boundary without lifetime gymnastics. `payload_bytes` is
/// the canonical-JSON encoding of `{action, decision}` — the same
/// shape the audited path commits to via
/// `agent_action::emit_check_event`. The drainer hashes this on the
/// way to `signed_events.payload_hash`.
#[derive(Debug, Clone)]
pub struct DeferredAuditEvent {
    /// Stable identity for one queue submission. [`DeferredAuditQueue::submit`]
    /// replaces this with a fresh UUID for every call, so submitting the same
    /// cloned event twice still represents two audit occurrences. The ID is
    /// journaled and reused as `signed_events.id`, which makes panic retry and
    /// crash recovery unambiguous. `None` is accepted only for legacy journal
    /// records written before occurrence IDs were introduced.
    pub occurrence_id: Option<String>,
    /// Agent identity at the moment of refusal (resolved from request
    /// or process context). Lands in `signed_events.agent_id`.
    pub agent_id: String,
    /// The action that was refused. Cloned from the hook input.
    pub action: AgentAction,
    /// The verdict — must be a BLOCKING variant (`Refuse` or
    /// `Escalate`, §22 PE-5); non-blocking events (Allow / Warn) do
    /// not enter the queue (the submit helpers gate on
    /// `Decision::is_blocking`).
    pub decision: Decision,
    /// Wall-clock timestamp of refusal. Lands in
    /// `signed_events.timestamp` as RFC3339.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl DeferredAuditEvent {
    /// Build a deferred event from the hook's three inputs. Returns
    /// `None` when `decision` does not BLOCK the action — callers
    /// should only submit blocking verdicts to the queue (Allow /
    /// Warn paths do not chain-log a row). A blocking verdict is a
    /// `Refuse` OR an `Escalate` (§22 PE-5): both halt the action,
    /// so both chain-log here. The non-blocking Allow / Warn paths
    /// still return `None`.
    #[must_use]
    pub fn from_refusal(agent_id: &str, action: &AgentAction, decision: &Decision) -> Option<Self> {
        if !decision.is_blocking() {
            return None;
        }
        Some(Self {
            occurrence_id: Some(uuid::Uuid::new_v4().to_string()),
            agent_id: agent_id.to_string(),
            action: action.clone(),
            decision: decision.clone(),
            timestamp: chrono::Utc::now(),
        })
    }

    /// Extract the rule_id from the refusal verdict. Used by the
    /// drainer to surface the firing rule in the audit row's
    /// canonical payload.
    #[must_use]
    pub fn rule_id(&self) -> Option<&str> {
        match &self.decision {
            Decision::Refuse { rule_id, .. } | Decision::Escalate { rule_id, .. } => {
                Some(rule_id.as_str())
            }
            _ => None,
        }
    }

    /// Extract the refusal reason from the verdict (verbatim
    /// operator-authored string).
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match &self.decision {
            Decision::Refuse { reason, .. } | Decision::Escalate { reason, .. } => {
                Some(reason.as_str())
            }
            _ => None,
        }
    }

    /// Canonical JSON shape the drainer hashes for
    /// `signed_events.payload_hash`. Stable across versions: a
    /// flat object with `action`, `decision`, `agent_id`,
    /// `timestamp` keys — same outline as
    /// `agent_action::emit_check_event` plus the agent + timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error only if `serde_json` cannot serialize the
    /// action variant (in practice never happens for the canonical
    /// AgentAction shapes).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut canonical = serde_json::json!({
            "action": self.action,
            "decision": self.decision,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp.to_rfc3339(),
        });
        if let Some(occurrence_id) = &self.occurrence_id {
            canonical["occurrence_id"] = serde_json::Value::String(occurrence_id.clone());
        }
        serde_json::to_vec(&canonical).context("DeferredAuditEvent::canonical_bytes")
    }

    /// v0.8.0 PE-4 (#1732) — inverse of [`Self::canonical_bytes`]:
    /// decode a journal record's payload back into a
    /// `DeferredAuditEvent`. `AgentAction` / `Decision` are both
    /// `Deserialize`, so the flat `{action, decision, agent_id,
    /// timestamp}` object round-trips. Used by [`recover_deferred_audit`]
    /// to replay crash-durable journal records on boot.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not the canonical JSON shape
    /// (missing field, undecodable variant, malformed timestamp) — the
    /// replay loop treats that as a corrupt trailing record and stops.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let v: serde_json::Value =
            serde_json::from_slice(bytes).context("from_canonical_bytes: parse json")?;
        let action: AgentAction = serde_json::from_value(
            v.get("action")
                .cloned()
                .context("from_canonical_bytes: missing action")?,
        )
        .context("from_canonical_bytes: decode action")?;
        let decision: Decision = serde_json::from_value(
            v.get("decision")
                .cloned()
                .context("from_canonical_bytes: missing decision")?,
        )
        .context("from_canonical_bytes: decode decision")?;
        let agent_id = v
            .get("agent_id")
            .and_then(serde_json::Value::as_str)
            .context("from_canonical_bytes: missing agent_id")?
            .to_string();
        let ts_str = v
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .context("from_canonical_bytes: missing timestamp")?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(ts_str)
            .context("from_canonical_bytes: parse timestamp")?
            .with_timezone(&chrono::Utc);
        Ok(Self {
            occurrence_id: v
                .get("occurrence_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            agent_id,
            action,
            decision,
            timestamp,
        })
    }
}

/// Shared counters surfaced for observability. Cloning is cheap
/// (just `Arc` bumps); the public read path is on the queue handle.
#[derive(Debug, Clone, Default)]
pub struct DeferredAuditMetrics {
    /// Number of events submitted into the queue. Includes events
    /// that were later dropped because the receiver was already
    /// closed.
    pub submitted: Arc<AtomicU64>,
    /// Number of events the drainer successfully appended to
    /// `signed_events`.
    pub appended: Arc<AtomicU64>,
    /// Number of submit attempts that failed because the receiver
    /// was already closed (drainer dropped / shutdown raced).
    pub send_failures: Arc<AtomicU64>,
    /// Number of drainer iterations that failed the sink append, landed in
    /// the DLQ, or terminated after exhausting the panic-restart budget. A
    /// non-zero value indicates degraded audit delivery; the supervisor
    /// surfaces the exact cause in tracing logs.
    pub append_failures: Arc<AtomicU64>,
    /// Number of sink panics observed by the supervisor. This includes a
    /// terminal panic that exhausts the configured restart budget.
    /// Should be zero in healthy operation.
    pub drainer_panics: Arc<AtomicU64>,
    /// Cluster-C SEC-3 (issue #767) — number of events that landed in
    /// the `signed_events_dlq` table after exhausting the
    /// `SQLITE_CONSTRAINT_UNIQUE` retry budget or hitting an
    /// unrecoverable non-race error. Surfaced via the capabilities-v3
    /// envelope's `approval.deferred_audit_dlq_size` field (live count
    /// query) and via this counter (cumulative since process boot).
    pub dlq_landed: Arc<AtomicU64>,
    /// Cluster-C SEC-3 (issue #767) — cumulative number of
    /// `SQLITE_CONSTRAINT_UNIQUE` race retries observed by the
    /// production sink. Every retry indicates the chain-head read
    /// raced a sibling-connection writer; a sustained non-zero value
    /// hints at write-contention pressure on the audit chain (e.g. a
    /// burst of refusals while the substrate writer is also churning
    /// out `memory_link.created` rows).
    pub unique_race_retries: Arc<AtomicU64>,
}

impl DeferredAuditMetrics {
    /// Number of events submitted since process boot.
    #[must_use]
    pub fn submitted_count(&self) -> u64 {
        self.submitted.load(Ordering::Relaxed)
    }

    /// Number of events successfully chain-logged since process boot.
    #[must_use]
    pub fn appended_count(&self) -> u64 {
        self.appended.load(Ordering::Relaxed)
    }

    /// Number of submit failures (receiver dropped).
    #[must_use]
    pub fn send_failure_count(&self) -> u64 {
        self.send_failures.load(Ordering::Relaxed)
    }

    /// Number of append failures (SQLite error).
    #[must_use]
    pub fn append_failure_count(&self) -> u64 {
        self.append_failures.load(Ordering::Relaxed)
    }

    /// Number of supervisor-observed drainer panics.
    #[must_use]
    pub fn panic_count(&self) -> u64 {
        self.drainer_panics.load(Ordering::Relaxed)
    }

    /// Cluster-C SEC-3 — cumulative number of events that landed in
    /// `signed_events_dlq` since process boot.
    #[must_use]
    pub fn dlq_landed_count(&self) -> u64 {
        self.dlq_landed.load(Ordering::Relaxed)
    }

    /// Cluster-C SEC-3 — cumulative number of UNIQUE-constraint race
    /// retries observed by the production sink since process boot.
    #[must_use]
    pub fn unique_race_retry_count(&self) -> u64 {
        self.unique_race_retries.load(Ordering::Relaxed)
    }
}

/// v0.8.0 PE-4 (#1732) — crash-durable shadow of the in-memory queue.
///
/// The in-memory [`DeferredAuditQueue`] mpsc loses any submitted-but-
/// not-yet-drained refusal on a SIGKILL (the `signed_events_dlq` only
/// covers an append FAILURE after the drainer has the event, not the
/// pre-drain window). This journal plus per-occurrence spool closes that hole:
/// [`DeferredAuditQueue::submit`] durably `write()+fsync`-es each event
/// here BEFORE handing it to the live drainer, and [`recover_deferred_audit`]
/// replays un-drained records into `signed_events` at boot.
///
/// **Why a file, not a DB table (5-agent vote 4d3ea1c5):** `submit`
/// fires INSIDE `storage::insert` while it holds the substrate's
/// `Connection` (a `BEGIN IMMEDIATE` write txn). A second connection
/// writing to the same SQLite file would block on that write lock —
/// which cannot release until the hook returns — a self-deadlock. A
/// raw file append touches no `Connection`, exactly the re-entrancy-safe
/// property the deferred design exists to preserve. Refusals are rare
/// (only blocking verdicts enqueue) so the per-record fsync is cheap.
///
/// **Frame:** `[u32-LE payload_len][payload = DeferredAuditEvent::canonical_bytes][32-byte sha256(payload)]`.
/// New records are atomically published as one private spool file per
/// occurrence and removed only after durable chain/DLQ residence. Entry and
/// byte quotas fail closed before disk/inode exhaustion. The original stream
/// is replayed only for legacy records. A short
/// trailing legacy write is ignored; complete corrupt frames fail closed.
pub struct DeferredAuditJournal {
    path: PathBuf,
    file: Mutex<File>,
    spool_dir: PathBuf,
    spool_usage: Mutex<SpoolUsage>,
    spool_lock: File,
}

#[derive(Default)]
struct SpoolUsage {
    entries: usize,
    bytes: u64,
}

/// Panic message when the journal mutex is poisoned (a prior holder
/// panicked while holding the lock). One named const referenced at every
/// lock site — pm-v3.1 no-hardcoded-duplication discipline.
const JOURNAL_MUTEX_POISONED: &str = "deferred-audit journal mutex poisoned";

impl DeferredAuditJournal {
    /// Open (creating if absent) the journal at `path`, tightening to
    /// mode 0600 on unix.
    ///
    /// Opened `read + write` (NOT append-mode): on Windows an append-only
    /// handle grants `FILE_APPEND_DATA` but not the general write access
    /// `set_len`/`SetEndOfFile` (used by [`Self::truncate`]) requires, so
    /// truncate would fail with `os error 5`. [`Self::append`] seeks to
    /// end before each write — single-process daemon writes serialized by
    /// the `Mutex` make this equivalent to append without the Windows
    /// truncate hazard.
    ///
    /// # Errors
    /// Propagates the open / chmod IO error.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let spool_dir = journal_spool_dir(&path);
        let spool_existed = spool_dir.exists();
        std::fs::create_dir_all(&spool_dir)
            .with_context(|| format!("create deferred-audit spool {}", spool_dir.display()))?;
        let mut journal_options = OpenOptions::new();
        journal_options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            journal_options.mode(0o600);
        }
        let file = journal_options
            .open(&path)
            .with_context(|| format!("open deferred-audit journal {}", path.display()))?;
        let lock_path = spool_dir.join(".lock");
        let mut lock_options = OpenOptions::new();
        lock_options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600);
        }
        let spool_lock = lock_options
            .open(&lock_path)
            .context("open deferred-audit spool lock")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))
                .context("tighten deferred-audit spool lock permissions")?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .context("tighten deferred-audit journal permissions")?;
            std::fs::set_permissions(&spool_dir, std::fs::Permissions::from_mode(0o700))
                .context("tighten deferred-audit spool permissions")?;
        }
        if !spool_existed && let Some(parent) = spool_dir.parent() {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            sync_directory(parent).context("fsync deferred-audit spool parent")?;
        }
        fs2::FileExt::lock_exclusive(&spool_lock)
            .context("lock deferred-audit spool during open")?;
        let mut usage = SpoolUsage::default();
        let mut overflow_markers = 0_usize;
        for entry in std::fs::read_dir(&spool_dir).context("scan deferred-audit spool")? {
            let entry = entry.context("read deferred-audit spool entry")?;
            let entry_path = entry.path();
            if entry_path.extension().is_some_and(|ext| ext == "pending") {
                let frame =
                    std::fs::read(&entry_path).context("read deferred-audit pending frame")?;
                let expected_len = frame.get(..4).and_then(|prefix| {
                    let payload_len = usize::try_from(u32::from_le_bytes([
                        prefix[0], prefix[1], prefix[2], prefix[3],
                    ]))
                    .ok()?;
                    (payload_len <= JOURNAL_MAX_PAYLOAD_BYTES)
                        .then_some(4_usize)
                        .and_then(|prefix_len| prefix_len.checked_add(payload_len))
                        .and_then(|framed_len| framed_len.checked_add(32))
                });
                if expected_len != Some(frame.len()) {
                    std::fs::remove_file(&entry_path)
                        .context("remove torn deferred-audit pending frame")?;
                    continue;
                }
                let event = parse_complete_journal_frame(&frame)
                    .context("validate complete deferred-audit pending frame")?;
                let occurrence_id = event
                    .occurrence_id
                    .as_deref()
                    .context("pending deferred-audit frame lacks occurrence ID")?;
                let published = spool_dir.join(format!(
                    "{}.event",
                    hex::encode(payload_hash(occurrence_id.as_bytes()))
                ));
                match std::fs::hard_link(&entry_path, &published) {
                    Ok(()) => sync_directory(&spool_dir)?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        if std::fs::read(&published)? != frame {
                            anyhow::bail!("pending deferred-audit occurrence collision");
                        }
                    }
                    Err(error) => {
                        return Err(error).context("publish pending deferred-audit frame");
                    }
                }
                std::fs::remove_file(&entry_path)
                    .context("remove reconciled deferred-audit pending frame")?;
                sync_directory(&spool_dir)?;
                continue;
            }
            if entry_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(JOURNAL_OVERFLOW_PREFIX))
            {
                overflow_markers += 1;
            }
            if entry_path.extension().is_some_and(|ext| ext == "event") {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&entry_path, std::fs::Permissions::from_mode(0o600))
                        .context("tighten deferred-audit spool entry permissions")?;
                }
                usage.entries = usage.entries.saturating_add(1);
                usage.bytes = usage.bytes.saturating_add(entry.metadata()?.len());
            }
        }
        if overflow_markers > 0 {
            tracing::error!(overflow_markers, path = %spool_dir.display(), "deferred-audit spool contains durable overflow evidence; prior refusals were blocked because audit admission was unavailable");
        }
        sync_directory(&spool_dir).context("fsync reconciled deferred-audit spool")?;
        validate_atomic_publication(&spool_dir)?;
        usage = scan_spool_usage(&spool_dir)?;
        if usage.entries > JOURNAL_SPOOL_MAX_ENTRIES || usage.bytes > JOURNAL_SPOOL_MAX_BYTES {
            anyhow::bail!("deferred-audit spool exceeds configured safety bounds");
        }
        fs2::FileExt::unlock(&spool_lock).context("unlock deferred-audit spool after open")?;
        Ok(Self {
            path,
            file: Mutex::new(file),
            spool_dir,
            spool_usage: Mutex::new(usage),
            spool_lock,
        })
    }

    /// Durably append one event (`write_all` + `sync_all`). This is the
    /// crash-durability point — the fsync returns only once the frame is
    /// on stable storage.
    ///
    /// # Errors
    /// Propagates the serialize / write / fsync IO error.
    pub fn append(&self, event: &DeferredAuditEvent) -> Result<()> {
        let payload = event
            .canonical_bytes()
            .context("journal append: canonical_bytes")?;
        let frame = journal_frame(&payload)?;

        if let Some(occurrence_id) = &event.occurrence_id {
            let spool_path = self.spool_path(occurrence_id);
            let mut usage = self.spool_usage.lock().expect(JOURNAL_MUTEX_POISONED);
            let _spool_guard = self.lock_spool()?;
            *usage = scan_spool_usage(&self.spool_dir)?;
            if spool_path.exists() {
                let existing = std::fs::read(&spool_path)
                    .context("journal spool append: read existing occurrence")?;
                if existing == frame {
                    return Ok(());
                }
                anyhow::bail!(
                    "journal spool occurrence-id collision at {}",
                    spool_path.display()
                );
            }
            let frame_len = u64::try_from(frame.len()).context("journal spool frame length")?;
            if usage.entries >= JOURNAL_SPOOL_MAX_ENTRIES
                || usage.bytes.saturating_add(frame_len) > JOURNAL_SPOOL_MAX_BYTES
            {
                self.record_overflow(event, &payload)?;
                anyhow::bail!("deferred-audit spool quota exhausted; refusing unjournaled event");
            }
            let staging_path = self
                .spool_dir
                .join(format!(".{}.pending", uuid::Uuid::new_v4()));
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut staging = options
                .open(&staging_path)
                .context("journal spool append: create staging")?;
            let staged = (|| -> Result<()> {
                staging
                    .write_all(&frame)
                    .context("journal spool append: write staging")?;
                staging
                    .sync_all()
                    .context("journal spool append: fsync staging")?;
                std::fs::hard_link(&staging_path, &spool_path)
                    .context("journal spool append: publish occurrence")?;
                usage.entries += 1;
                usage.bytes += frame_len;
                self.sync_spool_dir()?;
                match std::fs::remove_file(&staging_path) {
                    Ok(()) => self.sync_spool_dir(),
                    Err(error) => {
                        usage.entries += 1;
                        usage.bytes += frame_len;
                        tracing::error!(%error, path = %staging_path.display(), "deferred-audit staging cleanup failed; artifact remains quota-accounted");
                        Ok(())
                    }
                }
            })();
            if staged.is_err() {
                let _ = std::fs::remove_file(&staging_path);
            }
            staged?;
            return Ok(());
        }

        // Legacy records without occurrence IDs retain the v1 frame stream.
        let mut f = self.file.lock().expect(JOURNAL_MUTEX_POISONED);
        // Seek to end before writing — the handle is read+write (not
        // append-mode, for Windows truncate compatibility), and the Mutex
        // serializes all writers in this single-process daemon.
        f.seek(SeekFrom::End(0))
            .context("journal append: seek-to-end")?;
        f.write_all(&frame).context("journal append: write_all")?;
        f.sync_all().context("journal append: fsync")?;
        Ok(())
    }

    /// Replay every intact record in order, stopping at the first torn
    /// or corrupt (necessarily trailing) record. A trailing partial
    /// frame is discarded — it was never fully fsync'd, so by contract
    /// it is not a recoverable event.
    ///
    /// # Errors
    /// Propagates the seek / read IO error.
    pub fn replay(&self) -> Result<Vec<DeferredAuditEvent>> {
        let _spool_guard = self.lock_spool()?;
        let mut f = self.file.lock().expect(JOURNAL_MUTEX_POISONED);
        f.seek(SeekFrom::Start(0)).context("journal replay: seek")?;
        let mut out = replay_legacy_stream(&mut f)?;
        drop(f);

        let mut spool_paths = Vec::new();
        for entry in std::fs::read_dir(&self.spool_dir)
            .with_context(|| format!("journal replay: read spool {}", self.spool_dir.display()))?
        {
            let path = entry.context("journal replay: read spool entry")?.path();
            if path.extension().is_some_and(|ext| ext == "event") {
                spool_paths.push(path);
            }
        }
        spool_paths.sort();
        for path in spool_paths {
            let metadata = std::fs::metadata(&path)
                .with_context(|| format!("journal replay: stat {}", path.display()))?;
            let max_frame = u64::try_from(JOURNAL_MAX_PAYLOAD_BYTES + 36).unwrap_or(u64::MAX);
            if metadata.len() > max_frame {
                anyhow::bail!("journal spool frame too large: {}", path.display());
            }
            let frame = std::fs::read(&path)
                .with_context(|| format!("journal replay: read {}", path.display()))?;
            out.push(parse_complete_journal_frame(&frame).with_context(|| {
                format!("journal replay: corrupt spool frame {}", path.display())
            })?);
        }
        Ok(out)
    }

    /// Remove the crash-spool record for an occurrence after it is durably
    /// represented in either `signed_events` or `signed_events_dlq`.
    ///
    /// # Errors
    ///
    /// Returns an error on canonicalization, identity mismatch, removal, or
    /// directory-fsync failure. Missing records are accepted because the live
    /// path may be running without a successfully journaled occurrence.
    pub fn acknowledge(&self, event: &DeferredAuditEvent) -> Result<()> {
        let Some(occurrence_id) = &event.occurrence_id else {
            return Ok(());
        };
        let mut usage = self.spool_usage.lock().expect(JOURNAL_MUTEX_POISONED);
        let _spool_guard = self.lock_spool()?;
        let spool_path = self.spool_path(occurrence_id);
        let existing = match std::fs::read(&spool_path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).context("journal acknowledge: read occurrence"),
        };
        let expected = journal_frame(&event.canonical_bytes()?)?;
        if existing != expected {
            anyhow::bail!(
                "journal acknowledge occurrence-id/payload collision at {}",
                spool_path.display()
            );
        }
        std::fs::remove_file(&spool_path).context("journal acknowledge: remove occurrence")?;
        self.sync_spool_dir()?;
        *usage = scan_spool_usage(&self.spool_dir)?;
        Ok(())
    }

    fn spool_path(&self, occurrence_id: &str) -> PathBuf {
        let name = format!(
            "{}.event",
            hex::encode(payload_hash(occurrence_id.as_bytes()))
        );
        self.spool_dir.join(name)
    }

    fn sync_spool_dir(&self) -> Result<()> {
        sync_directory(&self.spool_dir).context("journal spool: fsync directory")
    }

    fn lock_spool(&self) -> Result<SpoolLockGuard<'_>> {
        fs2::FileExt::lock_exclusive(&self.spool_lock).context("lock deferred-audit spool")?;
        Ok(SpoolLockGuard(&self.spool_lock))
    }

    fn record_overflow(&self, event: &DeferredAuditEvent, payload: &[u8]) -> Result<()> {
        let evidence = format!(
            "timestamp={} occurrence_id={} payload_hash={}\n",
            chrono::Utc::now().to_rfc3339(),
            event.occurrence_id.as_deref().unwrap_or("legacy"),
            hex::encode(payload_hash(payload))
        );
        for index in 0..JOURNAL_OVERFLOW_MARKER_LIMIT {
            let marker = self
                .spool_dir
                .join(format!("{JOURNAL_OVERFLOW_PREFIX}{index:03}"));
            if create_private_marker(&marker, evidence.as_bytes())? {
                return self.sync_spool_dir();
            }
        }
        let saturated = self.spool_dir.join(JOURNAL_OVERFLOW_SATURATED);
        if create_private_marker(&saturated, b"overflow evidence saturated\n")? {
            self.sync_spool_dir()?;
        }
        Ok(())
    }

    /// Truncate the journal to empty + fsync. Called after a successful
    /// replay-and-drain at boot (every recovered event is now durably in
    /// `signed_events`), so the file only ever holds the current run's
    /// un-drained refusals.
    ///
    /// # Errors
    /// Propagates the truncate / fsync IO error.
    pub fn truncate(&self) -> Result<()> {
        let mut f = self.file.lock().expect(JOURNAL_MUTEX_POISONED);
        f.set_len(0).context("journal truncate: set_len(0)")?;
        f.seek(SeekFrom::Start(0))
            .context("journal truncate: seek")?;
        f.sync_all().context("journal truncate: fsync")?;
        Ok(())
    }

    /// The on-disk path (diagnostics).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn journal_spool_dir(journal_path: &Path) -> PathBuf {
    let mut spool_os = journal_path.as_os_str().to_os_string();
    spool_os.push(JOURNAL_SPOOL_SUFFIX);
    PathBuf::from(spool_os)
}

struct SpoolLockGuard<'a>(&'a File);

impl Drop for SpoolLockGuard<'_> {
    fn drop(&mut self) {
        if let Err(error) = fs2::FileExt::unlock(self.0) {
            tracing::error!(%error, "failed to unlock deferred-audit spool");
        }
    }
}

fn scan_spool_usage(spool_dir: &Path) -> Result<SpoolUsage> {
    let mut usage = SpoolUsage::default();
    for entry in std::fs::read_dir(spool_dir).context("scan deferred-audit spool usage")? {
        let entry = entry.context("read deferred-audit spool usage entry")?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "event")
            || path.extension().is_some_and(|ext| ext == "pending")
        {
            usage.entries = usage.entries.saturating_add(1);
            usage.bytes = usage.bytes.saturating_add(entry.metadata()?.len());
        }
    }
    Ok(usage)
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
        return Ok(());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_WRITE_THROUGH)
            .open(path)?
            .sync_all()?;
        return Ok(());
    }
    #[cfg(not(any(unix, windows)))]
    anyhow::bail!("directory durability is unsupported on this platform");
}

fn validate_atomic_publication(spool_dir: &Path) -> Result<()> {
    let probe_id = uuid::Uuid::new_v4();
    let staging = spool_dir.join(format!(".{probe_id}.pending"));
    let published = spool_dir.join(format!(".{probe_id}.probe"));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        options.open(&staging)?.sync_all()?;
        std::fs::hard_link(&staging, &published)
            .context("deferred-audit spool lacks atomic no-replace publication")?;
        std::fs::remove_file(&published)?;
        std::fs::remove_file(&staging)?;
        sync_directory(spool_dir)
    })();
    let _ = std::fs::remove_file(&published);
    let _ = std::fs::remove_file(&staging);
    result
}

fn create_private_marker(path: &Path, content: &[u8]) -> Result<bool> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(content)?;
            file.sync_all()?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error).context("create deferred-audit overflow marker"),
    }
}

fn journal_frame(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > JOURNAL_MAX_PAYLOAD_BYTES {
        anyhow::bail!("journal payload exceeds {JOURNAL_MAX_PAYLOAD_BYTES} bytes");
    }
    let len = u32::try_from(payload.len()).context("journal frame: payload too large")?;
    let hash = payload_hash(payload);
    let mut frame = Vec::with_capacity(4 + payload.len() + hash.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&hash);
    Ok(frame)
}

fn replay_legacy_stream(file: &mut File) -> Result<Vec<DeferredAuditEvent>> {
    let mut out = Vec::new();
    let mut frame_index = 0_u64;
    let mut aggregate_bytes = 0_u64;
    loop {
        let mut len_bytes = [0_u8; 4];
        let first = file
            .read(&mut len_bytes[..1])
            .context("journal replay: read length prefix")?;
        if first == 0 {
            break;
        }
        if !read_exact_or_torn(file, &mut len_bytes[1..])? {
            break;
        }
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len > JOURNAL_MAX_PAYLOAD_BYTES {
            anyhow::bail!("journal replay: frame {frame_index} length {len} exceeds limit");
        }
        aggregate_bytes = aggregate_bytes
            .saturating_add(u64::try_from(len).unwrap_or(u64::MAX).saturating_add(36));
        if aggregate_bytes > JOURNAL_LEGACY_REPLAY_MAX_BYTES {
            anyhow::bail!("journal replay: legacy aggregate exceeds safety limit");
        }
        let mut payload = vec![0_u8; len];
        if !read_exact_or_torn(file, &mut payload)? {
            break;
        }
        let mut stored_hash = [0_u8; 32];
        if !read_exact_or_torn(file, &mut stored_hash)? {
            break;
        }
        if payload_hash(&payload).as_slice() != stored_hash {
            anyhow::bail!("journal replay: hash mismatch at frame {frame_index}");
        }
        out.push(
            DeferredAuditEvent::from_canonical_bytes(&payload)
                .with_context(|| format!("journal replay: decode frame {frame_index}"))?,
        );
        frame_index += 1;
    }
    Ok(out)
}

fn read_exact_or_torn(reader: &mut File, buf: &mut [u8]) -> Result<bool> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e).context("journal replay: read frame"),
    }
}

fn parse_complete_journal_frame(frame: &[u8]) -> Result<DeferredAuditEvent> {
    if frame.len() < 36 {
        anyhow::bail!("journal frame is truncated");
    }
    let len = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if len > JOURNAL_MAX_PAYLOAD_BYTES {
        anyhow::bail!("journal frame payload exceeds limit");
    }
    let expected_len = 4_usize
        .checked_add(len)
        .and_then(|n| n.checked_add(32))
        .context("journal frame length overflow")?;
    if frame.len() != expected_len {
        anyhow::bail!("journal frame length mismatch");
    }
    let payload = &frame[4..4 + len];
    if payload_hash(payload).as_slice() != &frame[4 + len..] {
        anyhow::bail!("journal frame hash mismatch");
    }
    DeferredAuditEvent::from_canonical_bytes(payload).context("journal frame decode")
}

fn occurrence_residence(
    conn: &rusqlite::Connection,
    occurrence_id: &str,
    expected_hash: &[u8],
) -> Result<Option<AppendOutcome>> {
    use rusqlite::OptionalExtension as _;
    let chained: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload_hash FROM signed_events WHERE event_type = ?1 AND id = ?2",
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, occurrence_id],
            |row| row.get(0),
        )
        .optional()
        .context("deferred-audit occurrence residence: chain query")?;
    let mut stmt = conn
        .prepare("SELECT payload_hash FROM signed_events_dlq WHERE event_type = ?1 AND id = ?2")
        .context("deferred-audit occurrence residence: prepare DLQ query")?;
    let dlq_hashes = stmt
        .query_map(
            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, occurrence_id],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if chained.as_deref().is_some_and(|hash| hash != expected_hash)
        || dlq_hashes.iter().any(|hash| hash != expected_hash)
    {
        anyhow::bail!("deferred-audit occurrence-id collision with different payload");
    }
    match (chained.is_some(), dlq_hashes.is_empty()) {
        (true, false) => anyhow::bail!("deferred-audit occurrence has dual chain/DLQ residence"),
        (true, true) => Ok(Some(AppendOutcome::Appended)),
        (false, false) => Ok(Some(AppendOutcome::DlqLanded)),
        (false, true) => Ok(None),
    }
}

/// v0.8.0 PE-4 (#1732) — boot drain-on-recovery. Replays every intact
/// record in the journal at `journal_path` into `signed_events` (via a
/// fresh-`Connection` [`SqliteSignedEventsSink`]). **Idempotent:** new-format
/// records use their stable per-submission occurrence ID. Legacy records that
/// lack an occurrence ID use cardinality-aware payload-hash credits so two
/// identical journal frames remain two audit occurrences.
///
/// MUST run BEFORE the live governance hooks are installed (replay-all-
/// then-go-live) so recovered refusals chain ahead of new ones. Wired
/// into both the `serve` and `mcp` boot paths.
///
/// Returns the count of records freshly appended (excludes deduped).
///
/// # Errors
/// Propagates journal IO or DB-open errors. If any record cannot reach the
/// chain or durable DLQ, its spool record is retained for a later retry;
/// already-persisted records are content-checked and acknowledged.
pub fn recover_deferred_audit(journal_path: &Path, db_path: &Path) -> Result<usize> {
    if !journal_path.exists() && !journal_spool_dir(journal_path).exists() {
        return Ok(0);
    }
    let journal = Arc::new(DeferredAuditJournal::open(journal_path)?);
    let events = journal.replay()?;
    if events.is_empty() {
        journal.truncate()?;
        return Ok(0);
    }
    let conn = crate::db::open(db_path).context("recover_deferred_audit: open db for dedup")?;
    let mut sink = SqliteSignedEventsSink {
        db_path: db_path.to_path_buf(),
        conn: None,
        metrics: None,
        journal: Some(Arc::clone(&journal)),
    };
    let mut recovered = 0usize;
    let mut unresolved = false;
    let mut legacy_credits: HashMap<Vec<u8>, i64> = HashMap::new();
    for ev in &events {
        let hash = match ev.canonical_bytes() {
            Ok(b) => payload_hash(&b),
            Err(e) => {
                unresolved = true;
                tracing::warn!("recover_deferred_audit: retaining undecodable record: {e:#}");
                continue;
            }
        };
        let already_chained = if let Some(occurrence_id) = &ev.occurrence_id {
            match occurrence_residence(&conn, occurrence_id, &hash) {
                Ok(Some(_)) => {
                    journal.acknowledge(ev)?;
                    true
                }
                Ok(None) => false,
                Err(error) => {
                    unresolved = true;
                    tracing::error!(%occurrence_id, %error, "recovery occurrence-id collision");
                    continue;
                }
            }
        } else {
            let credits = match legacy_credits.entry(hash.clone()) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let chain_count = conn
                        .query_row(
                            "SELECT COUNT(*) FROM signed_events \
                             WHERE event_type = ?1 AND payload_hash = ?2",
                            rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, &hash],
                            |r| r.get::<_, i64>(0),
                        )
                        .context("recover_deferred_audit: legacy cardinality query")?;
                    let dlq_count = conn.query_row(
                        "SELECT COUNT(*) FROM signed_events_dlq WHERE event_type = ?1 AND payload_hash = ?2",
                        rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, &hash],
                        |r| r.get::<_, i64>(0),
                    ).context("recover_deferred_audit: legacy DLQ cardinality query")?;
                    entry.insert(chain_count + dlq_count)
                }
            };
            if *credits > 0 {
                *credits -= 1;
                true
            } else {
                false
            }
        };
        if already_chained {
            continue;
        }
        match sink.append(ev) {
            Ok(AppendOutcome::Appended) => recovered += 1,
            Ok(AppendOutcome::DlqLanded) => {
                tracing::warn!(
                    occurrence_id = ?ev.occurrence_id,
                    "recover_deferred_audit: event durably landed in DLQ"
                );
            }
            Err(e) => {
                unresolved = true;
                tracing::warn!(
                    occurrence_id = ?ev.occurrence_id,
                    "recover_deferred_audit: sink append failed; retaining journal: {e:#}"
                );
            }
        }
    }
    if unresolved {
        tracing::warn!(
            path = %journal_path.display(),
            "recover_deferred_audit: one or more records remain unresolved; journal retained"
        );
    } else {
        journal.truncate()?;
    }
    if recovered > 0 {
        tracing::info!(
            "recover_deferred_audit: replayed {recovered} pre-crash refusal(s) into signed_events"
        );
    }
    Ok(recovered)
}

/// Producer-side handle. Cloneable so multiple callsites (HTTP
/// handler, MCP handler, internal substrate writer) all share one
/// queue.
#[derive(Clone)]
pub struct DeferredAuditQueue {
    sender: UnboundedSender<DeferredAuditEvent>,
    metrics: DeferredAuditMetrics,
    /// v0.8.0 PE-4 (#1732) — crash-durable shadow. When `Some`, every
    /// `submit` durably journals the event before the mpsc send.
    journal: Option<Arc<DeferredAuditJournal>>,
}

impl DeferredAuditQueue {
    /// Create a fresh queue + uninstalled receiver. The receiver
    /// MUST be passed to [`spawn_drainer_task`] (or
    /// [`spawn_supervised_drainer`]) for events to land — submits
    /// against an unspawned receiver accumulate in the channel
    /// buffer indefinitely until the receiver is consumed or
    /// dropped.
    #[must_use]
    pub fn new() -> (Self, UnboundedReceiver<DeferredAuditEvent>) {
        Self::new_with_journal(None)
    }

    /// v0.8.0 PE-4 (#1732) — construct with an optional crash-durable
    /// [`DeferredAuditJournal`]. When `Some`, every [`Self::submit`]
    /// durably journals the event before the mpsc send so a SIGKILL
    /// before drain does not lose it (recovered by
    /// [`recover_deferred_audit`] on next boot). `None` reproduces the
    /// pre-#1732 in-memory-only behaviour (the `new()` default + the
    /// test path).
    #[must_use]
    pub fn new_with_journal(
        journal: Option<Arc<DeferredAuditJournal>>,
    ) -> (Self, UnboundedReceiver<DeferredAuditEvent>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let queue = Self {
            sender,
            metrics: DeferredAuditMetrics::default(),
            journal,
        };
        (queue, receiver)
    }

    /// Submit a refusal event.
    ///
    /// **Blocking semantics (#1912 — doc corrected to match behaviour):**
    /// when a crash-durable journal is configured
    /// (`new_with_journal(Some(_))`), this performs a durable `write_all`
    /// + `sync_all` (fsync) on the CALLING thread BEFORE the channel send.
    /// That is the #1732 PE-4 durability contract: the event must be on
    /// stable storage before it is observable to the drainer, so a SIGKILL
    /// after `submit` returns cannot lose it. The fsync can block for the
    /// duration of the disk sync, and on the storage-refusal path this
    /// runs inside the `GOVERNANCE_PRE_WRITE` hook while the substrate's
    /// writer `Mutex<Connection>` is held, so a slow disk stalls the
    /// shared writer for that window. It is therefore NOT non-blocking
    /// when a journal is attached; without a journal (the `new()` / test
    /// default) it only does the channel send and never blocks on IO.
    /// Moving the fsync off this thread is intentionally NOT done — it
    /// would break the durable-before-observable guarantee above.
    ///
    /// The delivery channel is an unbounded mpsc; the per-event fsync
    /// self-throttles the producer, applying implicit backpressure rather
    /// than growing without bound in practice.
    ///
    /// Never panics — if the receiver is closed the metric counter is
    /// bumped and a `tracing::warn` is emitted, but the caller path is
    /// unaffected. Returns `true` when the event was queued, `false` when
    /// the receiver was already closed.
    pub fn submit(&self, mut event: DeferredAuditEvent) -> bool {
        // Identity belongs to the delivery occurrence, not to the cloneable
        // payload. Reassign on every submit so two submissions of the same
        // DeferredAuditEvent remain two independently durable chain rows.
        event.occurrence_id = Some(uuid::Uuid::new_v4().to_string());
        self.metrics.submitted.fetch_add(1, Ordering::Relaxed);
        // v0.8.0 PE-4 (#1732) — durability point: journal the event
        // (write+fsync, NO DB Connection — re-entrancy-safe) BEFORE the
        // mpsc send, so a SIGKILL before the drainer processes it is
        // recoverable at next boot. Fail closed if durability cannot be
        // established: enqueueing an unjournaled event would silently reopen
        // the crash-loss window and let a hostile refusal stream exhaust disk.
        if let Some(journal) = &self.journal
            && let Err(e) = journal.append(&event)
        {
            self.metrics.send_failures.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                "deferred_audit_queue: journal append failed; refusing unjournaled delivery: {e:#}"
            );
            return false;
        }
        match self.sender.send(event) {
            Ok(()) => true,
            Err(_) => {
                self.metrics.send_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    "deferred_audit_queue: submit failed (drainer receiver closed); \
                     audit chain row LOST for this refusal"
                );
                false
            }
        }
    }

    /// Convenience: build + submit a refusal from the three hook
    /// inputs. Returns `true` when an event was actually enqueued
    /// (i.e. the verdict was a refusal AND the receiver was open).
    pub fn submit_refusal(
        &self,
        agent_id: &str,
        action: &AgentAction,
        decision: &Decision,
    ) -> bool {
        let Some(event) = DeferredAuditEvent::from_refusal(agent_id, action, decision) else {
            return false;
        };
        self.submit(event)
    }

    /// Observability handle. Clone-cheap; safe to expose to readers
    /// (Prometheus scrape, MCP `governance_state` tool, etc.).
    #[must_use]
    pub fn metrics(&self) -> DeferredAuditMetrics {
        self.metrics.clone()
    }

    /// True when the drainer receiver is still attached. False when
    /// the supervisor task and its receiver have both terminated
    /// (shutdown complete).
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.sender.is_closed()
    }
}

// ---------------------------------------------------------------------------
// Drainer / supervisor
// ---------------------------------------------------------------------------

/// Outcome of one drainer-side append attempt.
///
/// Cluster-C SEC-3 (issue #767) — splits a sink's per-event verdict
/// into three buckets so the drainer's metrics + DLQ accounting line
/// up with the operator-facing semantics:
///
/// * [`AppendOutcome::Appended`] — row landed in `signed_events`,
///   chain advanced one step. Increments `appended`.
/// * [`AppendOutcome::DlqLanded`] — append exhausted its race-retry
///   budget or hit an unrecoverable non-race error; the sink wrote
///   the event into `signed_events_dlq` with the failure reason
///   captured. Increments `dlq_landed`. The audit chain itself does
///   NOT advance, but the row is recoverable post-mortem.
/// * Returning `Err(_)` from `append` means the sink could not even
///   land in the DLQ (e.g. DB file gone, schema mismatch). Increments
///   `append_failures` — the chain-log property has truly broken for
///   this event and an operator must intervene.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    /// Event landed in `signed_events`.
    Appended,
    /// Event landed in `signed_events_dlq` after exhausting retries
    /// or hitting an unrecoverable non-race error.
    DlqLanded,
}

/// Sink trait: an abstraction over "where the drainer writes the
/// audit row". The production wiring opens a fresh SQLite
/// `Connection` per drainer task and writes through `signed_events`
/// with DLQ fallback; tests substitute a mock sink to assert
/// per-event behavior or inject panics for supervisor-recovery
/// coverage.
///
/// `append` MUST be `&mut` so a test sink can record events into an
/// owned `Vec` without interior mutability. Production sinks
/// (SQLite-backed) hold their state behind the impl.
///
pub trait DeferredAuditSink: Send + 'static {
    /// Persist one event.
    ///
    /// # Errors
    ///
    /// Returns `Err` only when the sink cannot even land the event in
    /// its DLQ surface — a genuinely unrecoverable case (DB file gone,
    /// schema mismatch). Soft failures (race retries, unrecoverable
    /// `signed_events` INSERT followed by successful DLQ land) are
    /// reported via [`AppendOutcome::DlqLanded`].
    fn append(&mut self, event: &DeferredAuditEvent) -> Result<AppendOutcome>;

    /// Retry an event after the preceding [`Self::append`] panicked.
    ///
    /// A panic can occur after persistence but before `append` returns, so
    /// production sinks should make this retry idempotent. Keeping retry
    /// provenance in this separate method is load-bearing: ordinary duplicate
    /// submissions are distinct audit occurrences and MUST each advance the
    /// chain. The default preserves compatibility for sinks that cannot
    /// distinguish the post-commit case.
    ///
    /// # Errors
    ///
    /// Identical to [`Self::append`].
    fn append_retry(&mut self, event: &DeferredAuditEvent) -> Result<AppendOutcome> {
        self.append(event)
    }
}

/// Production sink: opens a fresh SQLite `Connection` against the
/// daemon's database path and appends a `governance.refusal` row to
/// `signed_events` for each event.
///
/// One `Connection` per drainer task — NOT shared with the substrate
/// writer. SQLite WAL mode lets the drainer's appends proceed in
/// parallel with the writer's INSERTs without lock contention.
///
/// # Cluster-C SEC-3 (issue #767) — race-retry + DLQ
///
/// The sink wraps `append_signed_event` in a bounded retry loop. A
/// `SQLITE_CONSTRAINT_UNIQUE` failure on the `idx_signed_events_sequence`
/// UNIQUE index is the recoverable race-only signal (two writers
/// computed the same `next_seq` simultaneously); the sink re-runs
/// `append_signed_event` (which re-reads the chain head) up to
/// [`APPEND_UNIQUE_RACE_MAX_RETRIES`] times. Any other rusqlite
/// error, or a retry budget exhaustion, lands the event in
/// `signed_events_dlq` and returns `Ok(AppendOutcome::DlqLanded)` so
/// the drainer can update its counters without crashing.
pub struct SqliteSignedEventsSink {
    db_path: PathBuf,
    conn: Option<rusqlite::Connection>,
    metrics: Option<DeferredAuditMetrics>,
    journal: Option<Arc<DeferredAuditJournal>>,
}

impl SqliteSignedEventsSink {
    /// Construct without opening — the connection is opened lazily
    /// on first `append`. This pattern lets the supervisor restart
    /// the sink across drainer respawns without holding a closed
    /// `Connection` handle.
    ///
    /// Built without a metrics handle; race-retry + DLQ-land events
    /// will not increment any external counters. Use
    /// [`Self::with_metrics`] (or [`spawn_supervised_drainer`] which
    /// threads the metrics handle automatically) for full
    /// observability.
    #[must_use]
    pub fn new(db_path: impl Into<PathBuf>) -> Self {
        Self {
            db_path: db_path.into(),
            conn: None,
            metrics: None,
            journal: None,
        }
    }

    /// Construct a sink wired to a metrics handle. The handle's
    /// `dlq_landed` and `unique_race_retries` counters are bumped as
    /// the sink observes those outcomes.
    #[must_use]
    pub fn with_metrics(db_path: impl Into<PathBuf>, metrics: DeferredAuditMetrics) -> Self {
        Self {
            db_path: db_path.into(),
            conn: None,
            metrics: Some(metrics),
            journal: None,
        }
    }

    fn with_metrics_and_journal(
        db_path: impl Into<PathBuf>,
        metrics: DeferredAuditMetrics,
        journal: Option<Arc<DeferredAuditJournal>>,
    ) -> Self {
        Self {
            db_path: db_path.into(),
            conn: None,
            metrics: Some(metrics),
            journal,
        }
    }

    fn acknowledge(&self, event: &DeferredAuditEvent) -> Result<()> {
        if let Some(journal) = &self.journal {
            journal.acknowledge(event)?;
        }
        Ok(())
    }

    fn ensure_conn(&mut self) -> Result<&rusqlite::Connection> {
        if self.conn.is_none() {
            let conn = crate::db::open(&self.db_path).with_context(|| {
                format!(
                    "SqliteSignedEventsSink: open {} for deferred-audit drainer",
                    self.db_path.display()
                )
            })?;
            self.conn = Some(conn);
        }
        // We just inserted Some — unwrap is safe.
        Ok(self.conn.as_ref().expect("conn populated above"))
    }

    fn bump_dlq(&self) {
        if let Some(m) = &self.metrics {
            m.dlq_landed.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn bump_race_retry(&self) {
        if let Some(m) = &self.metrics {
            m.unique_race_retries.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl DeferredAuditSink for SqliteSignedEventsSink {
    fn append(&mut self, event: &DeferredAuditEvent) -> Result<AppendOutcome> {
        let bytes = event
            .canonical_bytes()
            .context("SqliteSignedEventsSink: canonical_bytes")?;
        let hash = payload_hash(&bytes);
        self.append_hashed(event, hash)
    }

    fn append_retry(&mut self, event: &DeferredAuditEvent) -> Result<AppendOutcome> {
        let bytes = event
            .canonical_bytes()
            .context("SqliteSignedEventsSink::append_retry: canonical_bytes")?;
        let hash = payload_hash(&bytes);

        // This probe is intentionally retry-only and occurrence-scoped.
        // Payload equality cannot distinguish a post-commit panic from a
        // pre-commit panic when an older identical occurrence already exists.
        // New queue/journal events therefore reuse their occurrence UUID as
        // signed_events.id. Payload-hash fallback exists only for legacy
        // journal records that predate occurrence IDs.
        if let Some(occurrence_id) = &event.occurrence_id {
            let residence = occurrence_residence(self.ensure_conn()?, occurrence_id, &hash)?;
            if let Some(outcome) = residence {
                self.acknowledge(event)?;
                return Ok(outcome);
            }
        } else {
            let query = (
                "SELECT EXISTS(SELECT 1 FROM signed_events \
                     WHERE event_type = ?1 AND payload_hash = ?2)",
                &hash as &dyn rusqlite::ToSql,
            );
            match self.ensure_conn()?.query_row(
                query.0,
                rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, query.1],
                |row| row.get::<_, bool>(0),
            ) {
                Ok(true) => {
                    tracing::warn!(
                        agent_id = %event.agent_id,
                        "deferred_audit sink: retry found the canonical event already chained; \
                         treating the append as idempotently complete"
                    );
                    return Ok(AppendOutcome::Appended);
                }
                Ok(false) => {}
                Err(e) => {
                    // A damaged/mismatched table can make the dedup probe
                    // fail. Continue into the normal append path so its
                    // established failure handling can land the event in
                    // the DLQ instead of losing it at this advisory probe.
                    tracing::warn!(
                        error = %e,
                        agent_id = %event.agent_id,
                        "deferred_audit sink: idempotency probe failed; continuing to \
                         append so the normal DLQ fallback remains available"
                    );
                }
            }
        }

        self.append_hashed(event, hash)
    }
}

impl SqliteSignedEventsSink {
    fn append_hashed(
        &mut self,
        event: &DeferredAuditEvent,
        hash: Vec<u8>,
    ) -> Result<AppendOutcome> {
        // v0.7.0 #1035 — sign the payload_hash with the daemon's
        // process-wide audit key when installed. The forensic JSONL
        // sink and this SQL sink share the same key (installed by
        // `audit::init`); a downstream auditor with the daemon's
        // verifying key validates both chains uniformly.
        let (signature, attest_level) =
            match crate::governance::audit::try_sign_audit_payload(&hash) {
                Some((sig, level)) => (Some(sig), level.to_string()),
                None => (
                    None,
                    crate::models::AttestLevel::Unsigned.as_str().to_string(),
                ),
            };
        let signed = SignedEvent {
            id: event
                .occurrence_id
                .clone()
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            agent_id: event.agent_id.clone(),
            event_type: GOVERNANCE_REFUSAL_EVENT_TYPE.to_string(),
            payload_hash: hash,
            signature,
            attest_level,
            timestamp: event.timestamp.to_rfc3339(),
            ..SignedEvent::default()
        };

        // Race-retry loop: SQLITE_CONSTRAINT_UNIQUE on the
        // `idx_signed_events_sequence` index is the race-only failure
        // mode. Every other rusqlite error path bails to DLQ.
        let conn_path = self.db_path.clone();
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..=APPEND_UNIQUE_RACE_MAX_RETRIES {
            let conn = self.ensure_conn()?;
            match append_signed_event(conn, &signed) {
                Ok(()) => {
                    self.acknowledge(event)?;
                    return Ok(AppendOutcome::Appended);
                }
                Err(e) => {
                    if is_unique_constraint_race(&e) && attempt < APPEND_UNIQUE_RACE_MAX_RETRIES {
                        self.bump_race_retry();
                        tracing::warn!(
                            attempt = attempt + 1,
                            db = %conn_path.display(),
                            "deferred_audit sink: SQLITE_CONSTRAINT_UNIQUE on signed_events.sequence — \
                             chain-head race; retrying (budget {APPEND_UNIQUE_RACE_MAX_RETRIES})"
                        );
                        last_err = Some(e);
                        continue;
                    }
                    last_err = Some(e);
                    break;
                }
            }
        }

        // Either the retry budget was exhausted on UNIQUE races OR
        // the first attempt produced a non-race error. Land in DLQ.
        //
        // v0.7.0 #1046 (Agent-6 #7) — chain-log property advisory.
        // At v0.7.0 the audit-chain delivery contract is:
        //
        //   **chain-log emission is "exactly-once OR DLQ-recoverable"**
        //
        // Specifically:
        //   - On the happy path, every refusal lands exactly one
        //     `governance.refusal` row in `signed_events` (the
        //     append-only chain advances by one).
        //   - On the DLQ-landing path (this branch), the refusal
        //     row does NOT advance the chain — instead a row lands
        //     in `signed_events_dlq` with the same `id`,
        //     `agent_id`, `payload_hash`, and `failure_reason`.
        //     The DLQ row preserves enough state to replay back
        //     into the chain.
        //   - There is NO boot-time DLQ→chain replay path at
        //     v0.7.0. Operators with non-zero `dlq_landed_count`
        //     should run the operator-side replay tooling (or
        //     manual SQL: copy DLQ rows into `signed_events` after
        //     resolving the chain-head race condition that caused
        //     the DLQ landing).
        //
        // A future v0.8 change can wire a boot-time DLQ replay
        // sweep that retries every `signed_events_dlq` entry into
        // `signed_events` via `append_signed_event`. The current
        // chain-log property is the load-bearing contract: the
        // cryptographic chain never carries a "phantom" refusal
        // (every chain row is a real append), and DLQ rows are
        // recoverable via operator action.
        let err = last_err.unwrap_or_else(|| anyhow::anyhow!("unknown drainer sink error"));
        let failure_reason = format!("{err:#}");
        let conn = self.ensure_conn()?;
        conn.execute(
            "INSERT INTO signed_events_dlq \
             (id, agent_id, event_type, payload_hash, signature, attest_level, \
              timestamp, failure_reason, failed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                signed.id,
                signed.agent_id,
                signed.event_type,
                signed.payload_hash,
                signed.signature,
                signed.attest_level,
                signed.timestamp,
                failure_reason,
                chrono::Utc::now().to_rfc3339(),
            ],
        )
        .context("SqliteSignedEventsSink: DLQ insert")?;
        tracing::error!(
            failure_reason = %failure_reason,
            agent_id = %signed.agent_id,
            event_id = %signed.id,
            "deferred_audit sink: append exhausted retries or hit non-race error — \
             event landed in signed_events_dlq (chain row NOT advanced; replay needed)"
        );
        self.bump_dlq();
        self.acknowledge(event)?;
        Ok(AppendOutcome::DlqLanded)
    }
}

/// Cluster-C SEC-3 (issue #767) — classify an `anyhow::Error` produced
/// by `append_signed_event` as a recoverable `SQLITE_CONSTRAINT_UNIQUE`
/// chain-head race vs everything else.
///
/// The classification walks the chain of causes and matches on
/// `rusqlite::Error::SqliteFailure` with extended code
/// `SQLITE_CONSTRAINT_UNIQUE` (2067). We deliberately use the typed
/// matcher rather than string-matching the rendered error so a future
/// rusqlite version that tweaks the `Display` impl doesn't silently
/// flip every race into a DLQ-land.
fn is_unique_constraint_race(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(rusqlite::Error::SqliteFailure(code, message)) =
            cause.downcast_ref::<rusqlite::Error>()
        {
            if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                && message.as_deref().is_some_and(|message| {
                    message.contains("signed_events.sequence")
                        || message.contains("idx_signed_events_sequence")
                })
            {
                return true;
            }
        }
    }
    false
}

/// Cluster-C SEC-3 (issue #767) — live count of rows in
/// `signed_events_dlq`.
///
/// Surfaced via the capabilities-v3 envelope's
/// `approval.deferred_audit_dlq_size` field so operator dashboards
/// see the current DLQ depth without scraping logs. Returns `0` on
/// query failure (a missing table or transient lock); callers that
/// want hard-fail behavior should query the table directly.
///
/// # Errors
///
/// Returns the underlying `rusqlite` error if the SELECT fails for a
/// reason other than `SQLITE_NOMEM` (which we treat as transient).
/// The capabilities pathway treats this as best-effort and falls
/// through to 0 on error.
pub fn dlq_size(conn: &rusqlite::Connection) -> Result<u64> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM signed_events_dlq", [], |r| r.get(0))
        .context("dlq_size: SELECT COUNT")?;
    Ok(u64::try_from(count).unwrap_or(0))
}

/// Spawn a single drainer iteration. The returned `JoinHandle`
/// completes (Ok) when the channel sender is dropped AND the
/// receiver has been fully drained — graceful shutdown. A panic in
/// the sink propagates through this bare task's `JoinHandle`.
///
/// Use [`spawn_supervised_drainer`] in production. This bare entry
/// point is exposed for tests that want one-shot drainer behavior
/// without supervisor restart.
#[must_use]
pub fn spawn_drainer_task<S: DeferredAuditSink + 'static>(
    mut receiver: UnboundedReceiver<DeferredAuditEvent>,
    mut sink: S,
    metrics: DeferredAuditMetrics,
) -> JoinHandle<UnboundedReceiver<DeferredAuditEvent>> {
    tokio::spawn(async move {
        while let Some(event) = receiver.recv().await {
            match sink.append(&event) {
                Ok(AppendOutcome::Appended) => {
                    metrics.appended.fetch_add(1, Ordering::Relaxed);
                }
                Ok(AppendOutcome::DlqLanded) => {
                    // Cluster-C SEC-3: the sink already captured the
                    // event in `signed_events_dlq` and bumped its
                    // own dlq_landed metric (if wired). We also bump
                    // `append_failures` so existing dashboards that
                    // alert on a non-zero append_failures count
                    // still surface DLQ landings — operators read
                    // the SAME signal regardless of which bucket
                    // the row went into.
                    metrics.append_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        "deferred_audit drainer: event landed in DLQ \
                         (audit chain row NOT advanced; operator replay needed)"
                    );
                }
                Err(e) => {
                    metrics.append_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(
                        "deferred_audit drainer: sink.append failed (no DLQ landing either): {:#}",
                        e
                    );
                    // We don't requeue — the channel is single-consumer.
                    // The supervisor's panic-restart path is for sink
                    // PANICS (poisoned state); soft errors here are
                    // recorded and the loop continues.
                }
            }
        }
        // Sender dropped + channel drained → graceful shutdown. Return
        // the receiver so the supervisor (which owns the sender
        // ultimately via the queue handle) can drop it cleanly.
        receiver
    })
}

/// Supervisor: drains events while retaining ownership of the
/// receiver across sink panics. A caught panic rebuilds a FRESH sink
/// (`make_sink()`) and retries the in-flight event, preserving both
/// the receiver and the metrics handle.
///
/// The supervisor task returns when either:
///   - The channel sender is dropped and the channel is fully
///     drained (graceful shutdown).
///   - A sink exhausts `max_restarts` while retrying one in-flight event, in
///     which case the supervisor panics so [`close_and_flush`] returns a
///     `JoinError` instead of falsely reporting a complete drain.
///
/// Panic retries use capped exponential backoff. This gives Tokio a
/// suspension point even under a persistently panicking sink and prevents a
/// tight panic-hook/log-amplification loop from monopolizing a runtime worker.
///
/// The returned `JoinHandle` resolves when the supervisor exits.
#[must_use]
pub fn spawn_supervised_drainer<F, S>(
    mut receiver: UnboundedReceiver<DeferredAuditEvent>,
    make_sink: F,
    metrics: DeferredAuditMetrics,
    max_restarts: u32,
) -> JoinHandle<()>
where
    F: Fn() -> S + Send + 'static,
    S: DeferredAuditSink + 'static,
{
    tokio::spawn(async move {
        let mut sink = make_sink();
        let mut consecutive_restarts = 0_u32;

        while let Some(event) = receiver.recv().await {
            let mut is_retry = false;
            loop {
                let append_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if is_retry {
                        sink.append_retry(&event)
                    } else {
                        sink.append(&event)
                    }
                }));

                match append_result {
                    Ok(Ok(AppendOutcome::Appended)) => {
                        metrics.appended.fetch_add(1, Ordering::Relaxed);
                        consecutive_restarts = 0;
                        break;
                    }
                    Ok(Ok(AppendOutcome::DlqLanded)) => {
                        metrics.append_failures.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            "deferred_audit drainer: event landed in DLQ \
                             (audit chain row NOT advanced; operator replay needed)"
                        );
                        consecutive_restarts = 0;
                        break;
                    }
                    Ok(Err(e)) => {
                        metrics.append_failures.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(
                            "deferred_audit drainer: sink.append failed \
                             (no DLQ landing either): {e:#}"
                        );
                        consecutive_restarts = 0;
                        break;
                    }
                    Err(_) => {
                        metrics.drainer_panics.fetch_add(1, Ordering::Relaxed);
                        if consecutive_restarts == max_restarts {
                            metrics.append_failures.fetch_add(1, Ordering::Relaxed);
                            panic!(
                                "deferred_audit supervisor: sink panicked and exhausted \
                                 max_restarts={max_restarts}; drain is incomplete and the \
                                 in-flight event is unflushed (journal recovery is available \
                                 only when journaling was successfully enabled)"
                            );
                        }

                        consecutive_restarts += 1;
                        is_retry = true;
                        tracing::error!(
                            restart = consecutive_restarts,
                            max_restarts,
                            "deferred_audit supervisor: sink panicked; rebuilding sink \
                             and retrying the in-flight event"
                        );
                        sink = make_sink();
                        tokio::time::sleep(panic_retry_backoff(consecutive_restarts)).await;
                    }
                }
            }
        }
    })
}

fn panic_retry_backoff(restart: u32) -> std::time::Duration {
    let exponent = restart.saturating_sub(1).min(10);
    let millis = PANIC_RETRY_BACKOFF_BASE_MS
        .saturating_mul(1_u64 << exponent)
        .min(PANIC_RETRY_BACKOFF_MAX_MS);
    std::time::Duration::from_millis(millis)
}

/// Close the queue and wait for the supervisor task to account for every
/// pending event. `Ok(())` means each submission either advanced
/// `signed_events` or reached an explicitly counted failure/DLQ outcome; callers
/// that require a fully advanced chain must additionally require zero
/// [`DeferredAuditMetrics::append_failure_count`] and
/// [`DeferredAuditMetrics::send_failure_count`].
///
/// # Errors
///
/// Returns the `tokio::task::JoinError` if the supervisor itself panics or if
/// the sink exhausts its configured panic-restart budget. An `Ok(())` result
/// therefore continues to mean that the queue drained completely.
pub async fn close_and_flush(
    queue: DeferredAuditQueue,
    supervisor: JoinHandle<()>,
) -> std::result::Result<(), tokio::task::JoinError> {
    // Drop the producer-side sender — once every clone is dropped,
    // the receiver's `recv().await` returns None and the drainer
    // exits gracefully.
    drop(queue);
    supervisor.await
}

/// Default bounded wait for [`drain_pending`] — how long the daemon's
/// shutdown path waits for the drainer to flush every submitted refusal
/// into `signed_events` before giving up and proceeding to WAL checkpoint
/// + exit. Five seconds comfortably covers a multi-thousand-event backlog
/// at the sink's ~25-100 microsecond-per-append rate while still bounding
/// shutdown latency if the drainer is genuinely wedged.
pub const DEFAULT_SHUTDOWN_DRAIN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(SHUTDOWN_DRAIN_TIMEOUT_SECS);

/// Whole-seconds component of [`DEFAULT_SHUTDOWN_DRAIN_TIMEOUT`]. Named so
/// the magnitude is not an inline literal inside the `Duration` const.
const SHUTDOWN_DRAIN_TIMEOUT_SECS: u64 = 5;

/// Poll cadence for [`drain_pending`]. The drainer advances its atomic
/// counters from another task, so the shutdown path samples them on this
/// interval rather than busy-spinning.
const DRAIN_POLL_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(DRAIN_POLL_INTERVAL_MILLIS);

/// Whole-milliseconds component of [`DRAIN_POLL_INTERVAL`].
const DRAIN_POLL_INTERVAL_MILLIS: u64 = 10;

/// Wait (bounded) until every event submitted to the queue has been
/// accounted for by the drainer — appended to `signed_events`, landed in
/// the DLQ / counted as an append failure, or recorded as a send failure.
///
/// This is the daemon shutdown-path counterpart to [`close_and_flush`].
/// Unlike `close_and_flush`, it does NOT require the producer-side senders
/// to be dropped: the daemon installs the queue's sender clones inside
/// process-wide `OnceLock` governance hooks
/// (`storage::GOVERNANCE_PRE_WRITE`, `wire_check::GOVERNANCE_PRE_ACTION`)
/// that live for the entire process lifetime, so the channel never closes
/// and the drainer's `recv().await` never returns `None`. Awaiting the
/// supervisor would therefore block forever. Instead we wait for the
/// drainer to catch up to the submitted count by polling the shared atomic
/// metrics.
///
/// MUST be called only after every write path that can submit a refusal
/// has quiesced (i.e. after the HTTP server's graceful-shutdown future has
/// resolved). At that point `submitted` is final, so the loop terminates
/// as soon as the drainer finishes the backlog.
///
/// Returns `true` when the queue fully drained within `timeout`, `false`
/// when the timeout elapsed with events still in flight (the caller should
/// log the residual so the audit gap is visible to operators).
pub async fn drain_pending(metrics: &DeferredAuditMetrics, timeout: std::time::Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if drain_accounted(metrics) >= metrics.submitted_count() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
    }
}

/// Number of submitted events the drainer has finished with — every
/// received event bumps exactly one of `appended` / `append_failures`
/// (the latter also covers DLQ landings), and a closed receiver bumps
/// `send_failures`. The sum equalling `submitted` means the backlog is
/// fully processed.
#[must_use]
fn drain_accounted(metrics: &DeferredAuditMetrics) -> u64 {
    metrics
        .appended_count()
        .saturating_add(metrics.append_failure_count())
        .saturating_add(metrics.send_failure_count())
}

// ---------------------------------------------------------------------------
// Convenience installer for the daemon path
// ---------------------------------------------------------------------------

/// Build a queue + spawn a supervised drainer in one call. Returns
/// the producer handle and the supervisor `JoinHandle` — the daemon
/// stashes the queue on `AppState` and the join handle in
/// `task_handles` so `serve` aborts it on shutdown.
///
/// The drainer opens a FRESH `Connection` per its sink (via
/// `SqliteSignedEventsSink::new(db_path)`); on respawn after panic
/// the sink is rebuilt verbatim. No connection is shared with the
/// substrate writer.
#[must_use]
pub fn install_deferred_audit_drainer(db_path: &Path) -> (DeferredAuditQueue, JoinHandle<()>) {
    let (queue, receiver) = DeferredAuditQueue::new();
    let metrics = queue.metrics();
    let db_path_buf = db_path.to_path_buf();
    let metrics_for_factory = metrics.clone();
    let supervisor = spawn_supervised_drainer(
        receiver,
        move || {
            SqliteSignedEventsSink::with_metrics(db_path_buf.clone(), metrics_for_factory.clone())
        },
        metrics,
        u32::MAX,
    );
    (queue, supervisor)
}

/// v0.8.0 PE-4 (#1732) — filename suffix for the crash-durable journal,
/// appended to the resolved db path (e.g. `ai-memory.db` →
/// `ai-memory.db.deferred-audit.journal`).
const DEFERRED_AUDIT_JOURNAL_SUFFIX: &str = ".deferred-audit.journal";

/// Resolve the journal path that sits beside the db file.
#[must_use]
pub fn deferred_audit_journal_path(db_path: &Path) -> PathBuf {
    let mut s = db_path.as_os_str().to_os_string();
    s.push(DEFERRED_AUDIT_JOURNAL_SUFFIX);
    PathBuf::from(s)
}

/// v0.8.0 PE-4 (#1732) — crash-durable variant of
/// [`install_deferred_audit_drainer`]. Used by the `serve` + `mcp` boot
/// paths. Performs **boot drain-on-recovery FIRST** (replay any pre-crash
/// journal records into `signed_events`, idempotently, then truncate),
/// then opens the journal and builds the queue WITH it so every
/// subsequent `submit` is durable before the mpsc send. Recovery runs
/// synchronously before this returns, so the caller installing the live
/// governance hooks afterward gets replay-all-then-go-live ordering.
///
/// If the journal cannot be opened, returns a closed queue so every attempted
/// submission fails visibly; production never downgrades to volatile audit
/// delivery under corruption or resource exhaustion.
#[must_use]
pub fn install_deferred_audit_drainer_with_journal(
    db_path: &Path,
) -> (DeferredAuditQueue, JoinHandle<()>) {
    let journal_path = deferred_audit_journal_path(db_path);
    // Boot recovery FIRST (replay-all-then-go-live): chain any pre-crash
    // refusals into signed_events before the live queue/hooks exist.
    if let Err(e) = recover_deferred_audit(&journal_path, db_path) {
        tracing::error!(
            "deferred-audit boot recovery failed for {}; audit delivery is FAIL-CLOSED: {e:#}",
            journal_path.display()
        );
        let (queue, receiver) = DeferredAuditQueue::new();
        drop(receiver);
        return (queue, tokio::spawn(async {}));
    }
    let journal = match DeferredAuditJournal::open(&journal_path) {
        Ok(j) => Arc::new(j),
        Err(e) => {
            tracing::error!(
                "deferred-audit journal open failed for {}; audit delivery is FAIL-CLOSED: {e:#}",
                journal_path.display()
            );
            let (queue, receiver) = DeferredAuditQueue::new();
            drop(receiver);
            return (queue, tokio::spawn(async {}));
        }
    };
    let (queue, receiver) = DeferredAuditQueue::new_with_journal(Some(journal));
    let metrics = queue.metrics();
    let db_path_buf = db_path.to_path_buf();
    let metrics_for_factory = metrics.clone();
    let journal_for_factory = queue.journal.clone();
    let supervisor = spawn_supervised_drainer(
        receiver,
        move || {
            SqliteSignedEventsSink::with_metrics_and_journal(
                db_path_buf.clone(),
                metrics_for_factory.clone(),
                journal_for_factory.clone(),
            )
        },
        metrics,
        u32::MAX,
    );
    (queue, supervisor)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // -----------------------------------------------------------------
    // DeferredAuditEvent shape + canonical bytes
    // -----------------------------------------------------------------

    fn refusal_action() -> AgentAction {
        AgentAction::Custom {
            custom_kind: "memory_write".to_string(),
            payload: serde_json::json!({"namespace": "secrets/api"}),
        }
    }

    fn refusal_decision() -> Decision {
        Decision::Refuse {
            rule_id: "R001".to_string(),
            reason: "no writes to secrets/*".to_string(),
        }
    }

    #[test]
    fn from_refusal_returns_some_for_refuse() {
        let event =
            DeferredAuditEvent::from_refusal("agent:alice", &refusal_action(), &refusal_decision())
                .expect("must be Some for Refuse verdict");
        assert_eq!(event.agent_id, "agent:alice");
        assert_eq!(event.rule_id(), Some("R001"));
        assert_eq!(event.reason(), Some("no writes to secrets/*"));
    }

    #[test]
    fn from_refusal_returns_none_for_allow() {
        let event =
            DeferredAuditEvent::from_refusal("agent:alice", &refusal_action(), &Decision::Allow);
        assert!(event.is_none(), "Allow verdict must not enqueue an event");
    }

    #[test]
    fn from_refusal_returns_none_for_warn() {
        let warn = Decision::Warn {
            rule_id: "W001".to_string(),
            reason: "warning only".to_string(),
        };
        let event = DeferredAuditEvent::from_refusal("agent:alice", &refusal_action(), &warn);
        assert!(event.is_none(), "Warn verdict must not enqueue a refusal");
    }

    #[test]
    fn canonical_bytes_includes_rule_and_action() {
        let event =
            DeferredAuditEvent::from_refusal("agent:alice", &refusal_action(), &refusal_decision())
                .unwrap();
        let bytes = event.canonical_bytes().unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("R001"), "canonical payload must include rule_id");
        assert!(
            s.contains("memory_write"),
            "canonical payload must include action kind"
        );
        assert!(
            s.contains("agent:alice"),
            "canonical payload must include agent id"
        );
    }

    #[test]
    fn rule_id_returns_none_for_non_refusal() {
        let event = DeferredAuditEvent {
            occurrence_id: Some(uuid::Uuid::new_v4().to_string()),
            agent_id: "x".into(),
            action: refusal_action(),
            decision: Decision::Allow,
            timestamp: chrono::Utc::now(),
        };
        assert!(event.rule_id().is_none());
        assert!(event.reason().is_none());
    }

    // -----------------------------------------------------------------
    // DeferredAuditQueue submit + non-blocking semantics
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn queue_new_returns_open_handle() {
        let (queue, _rx) = DeferredAuditQueue::new();
        assert!(queue.is_open());
        assert_eq!(queue.metrics().submitted_count(), 0);
    }

    #[tokio::test]
    async fn submit_with_receiver_attached_succeeds() {
        let (queue, mut rx) = DeferredAuditQueue::new();
        let event =
            DeferredAuditEvent::from_refusal("agent:t", &refusal_action(), &refusal_decision())
                .unwrap();
        assert!(queue.submit(event.clone()));
        assert_eq!(queue.metrics().submitted_count(), 1);
        let received = rx.recv().await.unwrap();
        assert_eq!(received.agent_id, event.agent_id);
        assert_eq!(received.rule_id(), Some("R001"));
    }

    #[tokio::test]
    async fn submit_after_receiver_dropped_records_send_failure() {
        let (queue, rx) = DeferredAuditQueue::new();
        drop(rx);
        // sender knows its peer is gone
        assert!(!queue.is_open());
        let event =
            DeferredAuditEvent::from_refusal("agent:t", &refusal_action(), &refusal_decision())
                .unwrap();
        let ok = queue.submit(event);
        assert!(!ok, "submit must return false when receiver is closed");
        assert_eq!(queue.metrics().submitted_count(), 1);
        assert_eq!(queue.metrics().send_failure_count(), 1);
    }

    #[tokio::test]
    async fn submit_refusal_helper_skips_non_refusals() {
        let (queue, mut rx) = DeferredAuditQueue::new();
        // Allow does NOT enqueue
        let enq = queue.submit_refusal("agent:t", &refusal_action(), &Decision::Allow);
        assert!(!enq);
        // Try receiving — should timeout (channel empty)
        let recv = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(recv.is_err(), "no event should have been enqueued");
        // Refusal DOES enqueue
        let enq2 = queue.submit_refusal("agent:t", &refusal_action(), &refusal_decision());
        assert!(enq2);
        let event = rx.recv().await.unwrap();
        assert_eq!(event.agent_id, "agent:t");
    }

    #[tokio::test]
    async fn queue_clone_shares_underlying_channel() {
        let (queue, mut rx) = DeferredAuditQueue::new();
        let clone = queue.clone();
        let event1 =
            DeferredAuditEvent::from_refusal("agent:a", &refusal_action(), &refusal_decision())
                .unwrap();
        let event2 =
            DeferredAuditEvent::from_refusal("agent:b", &refusal_action(), &refusal_decision())
                .unwrap();
        queue.submit(event1);
        clone.submit(event2);
        let r1 = rx.recv().await.unwrap();
        let r2 = rx.recv().await.unwrap();
        let agents: Vec<_> = vec![r1.agent_id, r2.agent_id];
        assert!(agents.contains(&"agent:a".to_string()));
        assert!(agents.contains(&"agent:b".to_string()));
        // Both sides share the same metrics handle
        assert_eq!(queue.metrics().submitted_count(), 2);
        assert_eq!(clone.metrics().submitted_count(), 2);
    }

    // -----------------------------------------------------------------
    // Drainer task behavior with mock sink
    // -----------------------------------------------------------------

    /// Mock sink: stores every received event in an owned Vec for
    /// post-condition assertions; optionally panics on the Nth
    /// event to drive supervisor-recovery tests.
    #[derive(Clone, Default)]
    struct MockSink {
        // Recorded events, behind a mutex so the test can read while
        // the drainer writes.
        recorded: Arc<Mutex<Vec<DeferredAuditEvent>>>,
        // Optional: panic on the Nth append (zero-indexed).
        panic_on: Option<usize>,
        // Optional: error on the Nth append (zero-indexed).
        error_on: Option<usize>,
        // Counter (shared across clones for supervisor-restart
        // counting).
        call_count: Arc<AtomicU64>,
    }

    impl DeferredAuditSink for MockSink {
        fn append(&mut self, event: &DeferredAuditEvent) -> Result<AppendOutcome> {
            let prior = self.call_count.fetch_add(1, Ordering::SeqCst) as usize;
            if Some(prior) == self.panic_on {
                panic!("mock sink: configured panic at call {prior}");
            }
            if Some(prior) == self.error_on {
                return Err(anyhow::anyhow!(
                    "mock sink: configured error at call {prior}"
                ));
            }
            self.recorded.lock().unwrap().push(event.clone());
            Ok(AppendOutcome::Appended)
        }
    }

    #[derive(Clone, Copy)]
    struct AlwaysPanicSink;

    impl DeferredAuditSink for AlwaysPanicSink {
        fn append(&mut self, _event: &DeferredAuditEvent) -> Result<AppendOutcome> {
            panic!("always-panic sink")
        }
    }

    struct PanicAfterCommitSqliteSink {
        inner: SqliteSignedEventsSink,
        calls: Arc<AtomicU64>,
    }

    struct PanicBeforeCommitSqliteSink {
        inner: SqliteSignedEventsSink,
        calls: Arc<AtomicU64>,
    }

    impl DeferredAuditSink for PanicBeforeCommitSqliteSink {
        fn append(&mut self, event: &DeferredAuditEvent) -> Result<AppendOutcome> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("injected panic before SQLite commit");
            }
            self.inner.append(event)
        }

        fn append_retry(&mut self, event: &DeferredAuditEvent) -> Result<AppendOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.append_retry(event)
        }
    }

    impl DeferredAuditSink for PanicAfterCommitSqliteSink {
        fn append(&mut self, event: &DeferredAuditEvent) -> Result<AppendOutcome> {
            let outcome = self.inner.append(event)?;
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("injected panic after durable SQLite commit");
            }
            Ok(outcome)
        }

        fn append_retry(&mut self, event: &DeferredAuditEvent) -> Result<AppendOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.append_retry(event)
        }
    }

    #[tokio::test]
    async fn drainer_appends_every_submitted_event() {
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let sink = MockSink::default();
        let recorded = sink.recorded.clone();
        let handle = spawn_drainer_task(rx, sink, metrics.clone());

        for i in 0..5 {
            let mut event = DeferredAuditEvent::from_refusal(
                &format!("agent:{i}"),
                &refusal_action(),
                &refusal_decision(),
            )
            .unwrap();
            event.timestamp = chrono::Utc::now();
            queue.submit(event);
        }

        // Drop the queue (sender) to terminate the drainer.
        drop(queue);
        let _returned_rx = handle.await.unwrap();

        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.len(), 5);
        for (i, ev) in recorded.iter().enumerate() {
            assert_eq!(ev.agent_id, format!("agent:{i}"));
        }
        assert_eq!(metrics.appended_count(), 5);
    }

    #[tokio::test]
    async fn drainer_continues_after_sink_error() {
        // Sink errors on the second call; the drainer should
        // record the error in metrics and proceed to handle
        // subsequent events.
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let mut sink = MockSink::default();
        sink.error_on = Some(1);
        let recorded = sink.recorded.clone();
        let handle = spawn_drainer_task(rx, sink, metrics.clone());

        for i in 0..3 {
            let event = DeferredAuditEvent::from_refusal(
                &format!("agent:{i}"),
                &refusal_action(),
                &refusal_decision(),
            )
            .unwrap();
            queue.submit(event);
        }
        drop(queue);
        let _ = handle.await.unwrap();
        // Event 0 and 2 landed; event 1 hit the error.
        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(metrics.appended_count(), 2);
        assert_eq!(metrics.append_failure_count(), 1);
    }

    // -----------------------------------------------------------------
    // Supervisor: panic recovery + graceful shutdown
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn supervisor_records_panic_metric_on_drainer_panic() {
        // The first sink panics on its first call. The supervisor must
        // retain the receiver, rebuild the sink, retry that event, and
        // then drain an event submitted after recovery.
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let recorded: Arc<Mutex<Vec<DeferredAuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_for_factory = recorded.clone();
        let call_count = Arc::new(AtomicU64::new(0));
        let call_count_for_factory = call_count.clone();
        let supervisor = spawn_supervised_drainer(
            rx,
            move || MockSink {
                recorded: recorded_for_factory.clone(),
                panic_on: Some(0),
                error_on: None,
                call_count: call_count_for_factory.clone(),
            },
            metrics.clone(),
            1,
        );

        for agent_id in ["agent:panic", "agent:after-restart"] {
            let event =
                DeferredAuditEvent::from_refusal(agent_id, &refusal_action(), &refusal_decision())
                    .unwrap();
            assert!(queue.submit(event));
        }

        close_and_flush(queue, supervisor)
            .await
            .expect("supervisor must recover and drain after one allowed restart");
        assert_eq!(
            metrics.panic_count(),
            1,
            "supervisor must record exactly one drainer panic"
        );
        assert_eq!(metrics.appended_count(), 2);
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].agent_id, "agent:panic");
        assert_eq!(recorded[1].agent_id, "agent:after-restart");
    }

    #[tokio::test]
    async fn supervisor_exhaustion_makes_close_and_flush_fail() {
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let supervisor = spawn_supervised_drainer(rx, || AlwaysPanicSink, metrics.clone(), 0);
        let event = DeferredAuditEvent::from_refusal(
            "agent:exhaust",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        assert!(queue.submit(event));

        let err = close_and_flush(queue, supervisor)
            .await
            .expect_err("restart exhaustion must not report a complete drain");
        assert!(err.is_panic());
        assert_eq!(metrics.panic_count(), 1);
        assert_eq!(metrics.append_failure_count(), 1);
        assert_eq!(metrics.appended_count(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn persistent_sink_panic_yields_to_runtime_between_retries() {
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let supervisor =
            spawn_supervised_drainer(rx, || AlwaysPanicSink, metrics.clone(), u32::MAX);
        let event = DeferredAuditEvent::from_refusal(
            "agent:persistent-panic",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        assert!(queue.submit(event));

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while metrics.panic_count() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("persistent panic retries must not starve timers or sibling tasks");

        drop(queue);
        supervisor.abort();
        let err = supervisor
            .await
            .expect_err("aborted supervisor must cancel");
        assert!(err.is_cancelled());
    }

    #[tokio::test]
    async fn supervisor_retry_after_commit_is_exactly_once() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("def-audit-panic-after-commit.db");
        let _ = crate::db::open(&db_path).expect("init db");
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let calls = Arc::new(AtomicU64::new(0));
        let calls_for_factory = calls.clone();
        let db_for_factory = db_path.clone();
        let supervisor = spawn_supervised_drainer(
            rx,
            move || PanicAfterCommitSqliteSink {
                inner: SqliteSignedEventsSink::new(db_for_factory.clone()),
                calls: calls_for_factory.clone(),
            },
            metrics.clone(),
            1,
        );
        let event = DeferredAuditEvent::from_refusal(
            "agent:post-commit",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        assert!(queue.submit(event));

        close_and_flush(queue, supervisor)
            .await
            .expect("post-commit panic retry must drain successfully");
        assert_eq!(metrics.panic_count(), 1);
        assert_eq!(metrics.appended_count(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let conn = crate::db::open(&db_path).expect("reopen db");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
                rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:post-commit"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "post-commit retry must not duplicate chain row");
    }

    #[tokio::test]
    async fn precommit_panic_does_not_collapse_prior_identical_occurrence() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("def-audit-panic-before-commit.db");
        let _ = crate::db::open(&db_path).expect("init db");
        let event = DeferredAuditEvent::from_refusal(
            "agent:pre-commit",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        let mut first_sink = SqliteSignedEventsSink::new(db_path.clone());
        assert_eq!(first_sink.append(&event).unwrap(), AppendOutcome::Appended);

        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let calls = Arc::new(AtomicU64::new(0));
        let calls_for_factory = calls.clone();
        let db_for_factory = db_path.clone();
        let supervisor = spawn_supervised_drainer(
            rx,
            move || PanicBeforeCommitSqliteSink {
                inner: SqliteSignedEventsSink::new(db_for_factory.clone()),
                calls: calls_for_factory.clone(),
            },
            metrics.clone(),
            1,
        );
        assert!(queue.submit(event.clone()));

        close_and_flush(queue, supervisor)
            .await
            .expect("pre-commit panic retry must drain successfully");
        assert_eq!(metrics.panic_count(), 1);
        assert_eq!(metrics.appended_count(), 1);

        let conn = crate::db::open(&db_path).expect("reopen db");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
                rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:pre-commit"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 2,
            "both identical occurrences must advance the chain"
        );
    }

    #[tokio::test]
    async fn supervisor_graceful_shutdown_drains_buffered_events() {
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let recorded: Arc<Mutex<Vec<DeferredAuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_for_factory = recorded.clone();
        let supervisor = spawn_supervised_drainer(
            rx,
            move || MockSink {
                recorded: recorded_for_factory.clone(),
                panic_on: None,
                error_on: None,
                call_count: Arc::new(AtomicU64::new(0)),
            },
            metrics.clone(),
            u32::MAX,
        );

        // Submit 50 events.
        for i in 0..50 {
            let event = DeferredAuditEvent::from_refusal(
                &format!("agent:{i}"),
                &refusal_action(),
                &refusal_decision(),
            )
            .unwrap();
            queue.submit(event);
        }

        // Initiate shutdown — close_and_flush drops the queue and
        // awaits the supervisor.
        close_and_flush(queue, supervisor)
            .await
            .expect("supervisor must terminate cleanly");

        let recorded = recorded.lock().unwrap();
        assert_eq!(
            recorded.len(),
            50,
            "shutdown must drain every buffered event"
        );
        assert_eq!(metrics.appended_count(), 50);
    }

    // -----------------------------------------------------------------
    // drain_pending — shutdown drain that does NOT require the senders to
    // be dropped (the daemon's governance hooks hold OnceLock-resident
    // sender clones that live for the whole process, so the channel never
    // closes — `close_and_flush` would block forever; `drain_pending`
    // polls the metrics instead).
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn drain_pending_completes_without_closing_channel() {
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let recorded: Arc<Mutex<Vec<DeferredAuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_for_factory = recorded.clone();
        let supervisor = spawn_supervised_drainer(
            rx,
            move || MockSink {
                recorded: recorded_for_factory.clone(),
                panic_on: None,
                error_on: None,
                call_count: Arc::new(AtomicU64::new(0)),
            },
            metrics.clone(),
            u32::MAX,
        );

        for i in 0..50 {
            let event = DeferredAuditEvent::from_refusal(
                &format!("agent:{i}"),
                &refusal_action(),
                &refusal_decision(),
            )
            .unwrap();
            queue.submit(event);
        }

        // Simulate the daemon's OnceLock-held sender by keeping a clone
        // alive across the drain — the channel MUST stay open the whole
        // time (this is exactly the scenario that wedges close_and_flush).
        let hook_held_sender = queue.clone();

        let drained = drain_pending(&metrics, std::time::Duration::from_secs(5)).await;
        assert!(
            drained,
            "drain_pending must complete while the channel is open"
        );
        assert!(
            hook_held_sender.is_open(),
            "channel must still be open — drain_pending must not depend on sender drop"
        );
        assert_eq!(metrics.appended_count(), 50);
        assert_eq!(recorded.lock().unwrap().len(), 50);

        // Cleanup: drop both producer handles so the drainer can exit.
        drop(hook_held_sender);
        drop(queue);
        let _ = supervisor.await;
    }

    #[tokio::test]
    async fn drain_pending_times_out_when_drainer_absent() {
        // No drainer spawned: submitted events sit in the channel buffer
        // forever, so the metrics never advance and drain_pending must
        // report a timeout (false) rather than hang.
        let (queue, _rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        for i in 0..3 {
            let event = DeferredAuditEvent::from_refusal(
                &format!("agent:{i}"),
                &refusal_action(),
                &refusal_decision(),
            )
            .unwrap();
            queue.submit(event);
        }
        let drained = drain_pending(&metrics, std::time::Duration::from_millis(100)).await;
        assert!(
            !drained,
            "drain_pending must return false when events never get accounted"
        );
        assert_eq!(metrics.submitted_count(), 3);
        assert_eq!(metrics.appended_count(), 0);
    }

    #[tokio::test]
    async fn drain_pending_returns_immediately_when_already_drained() {
        let (queue, _rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        // Nothing submitted → already drained → returns true at once.
        let drained = drain_pending(&metrics, std::time::Duration::from_secs(5)).await;
        assert!(drained);
    }

    #[tokio::test]
    async fn drain_pending_counts_append_failures_as_accounted() {
        // A sink that always errors still "accounts" for the event via
        // append_failures, so drain_pending must terminate (the audit row
        // is lost/DLQ'd but the shutdown path must not hang on it).
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        // Factory yields a sink that errors on its first (only) call, so
        // the event is "accounted" via append_failures rather than appended.
        let supervisor = spawn_supervised_drainer(
            rx,
            move || MockSink {
                recorded: Arc::new(Mutex::new(Vec::new())),
                panic_on: None,
                error_on: Some(0),
                call_count: Arc::new(AtomicU64::new(0)),
            },
            metrics.clone(),
            u32::MAX,
        );
        let event =
            DeferredAuditEvent::from_refusal("agent:err", &refusal_action(), &refusal_decision())
                .unwrap();
        queue.submit(event);
        let hook_held = queue.clone();
        let drained = drain_pending(&metrics, std::time::Duration::from_secs(5)).await;
        assert!(
            drained,
            "append failures count as accounted — must not hang"
        );
        assert_eq!(metrics.append_failure_count(), 1);
        drop(hook_held);
        drop(queue);
        let _ = supervisor.await;
    }

    #[tokio::test]
    async fn close_and_flush_works_with_zero_events() {
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let supervisor =
            spawn_supervised_drainer(rx, move || MockSink::default(), metrics.clone(), u32::MAX);
        close_and_flush(queue, supervisor).await.unwrap();
        assert_eq!(metrics.appended_count(), 0);
        assert_eq!(metrics.submitted_count(), 0);
    }

    // -----------------------------------------------------------------
    // High-volume / backpressure-edge — drainer slow, many submits
    // queued, all drain eventually
    // -----------------------------------------------------------------

    /// Slow sink: artificial 1 ms delay per append to simulate a
    /// busy fsync path.
    struct SlowSink {
        recorded: Arc<Mutex<Vec<DeferredAuditEvent>>>,
    }

    impl DeferredAuditSink for SlowSink {
        fn append(&mut self, event: &DeferredAuditEvent) -> Result<AppendOutcome> {
            std::thread::sleep(std::time::Duration::from_millis(1));
            self.recorded.lock().unwrap().push(event.clone());
            Ok(AppendOutcome::Appended)
        }
    }

    #[tokio::test]
    async fn unbounded_queue_handles_burst_no_drops() {
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let recorded: Arc<Mutex<Vec<DeferredAuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded_for_factory = recorded.clone();
        let supervisor = spawn_supervised_drainer(
            rx,
            move || SlowSink {
                recorded: recorded_for_factory.clone(),
            },
            metrics.clone(),
            u32::MAX,
        );

        // Burst 200 events (drainer is ~1 ms/event so this will
        // accumulate before draining).
        for i in 0..200 {
            let event = DeferredAuditEvent::from_refusal(
                &format!("agent:{i}"),
                &refusal_action(),
                &refusal_decision(),
            )
            .unwrap();
            assert!(
                queue.submit(event),
                "unbounded queue must never refuse a submit"
            );
        }
        assert_eq!(metrics.submitted_count(), 200);
        assert_eq!(metrics.send_failure_count(), 0);

        close_and_flush(queue, supervisor).await.unwrap();
        let recorded = recorded.lock().unwrap();
        assert_eq!(recorded.len(), 200);
        assert_eq!(metrics.appended_count(), 200);
    }

    // -----------------------------------------------------------------
    // Production-sink (SqliteSignedEventsSink) integration — opens a
    // real SQLite Connection against a temp file and asserts the row
    // lands.
    // -----------------------------------------------------------------

    fn fresh_tempdir() -> tempfile::TempDir {
        // Honor project hard rule: no /tmp writes by name. The
        // tempfile crate honors TMPDIR (exported at session
        // bootstrap to .local-runs/tmp), so this resolves under the
        // project-local scratch tree.
        tempfile::tempdir().expect("tempdir")
    }

    #[tokio::test]
    async fn sqlite_sink_appends_governance_refusal_row() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("def-audit-test.db");
        // Pre-create the schema via crate::db::open (applies
        // migrations including signed_events).
        let _ = crate::db::open(&db_path).expect("init db");

        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        let db_path_buf = db_path.clone();
        let supervisor = spawn_supervised_drainer(
            rx,
            move || SqliteSignedEventsSink::new(db_path_buf.clone()),
            metrics.clone(),
            u32::MAX,
        );

        let event =
            DeferredAuditEvent::from_refusal("agent:int", &refusal_action(), &refusal_decision())
                .unwrap();
        queue.submit(event);

        close_and_flush(queue, supervisor).await.unwrap();
        assert_eq!(metrics.appended_count(), 1);

        // Verify the row landed with event_type=governance.refusal.
        let conn = crate::db::open(&db_path).expect("reopen db");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
                rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:int"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "drainer must have written the row");
    }

    #[test]
    fn sqlite_sink_duplicate_live_submissions_each_advance_chain() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("def-audit-duplicate-live.db");
        let _ = crate::db::open(&db_path).expect("init db");
        let mut sink = SqliteSignedEventsSink::new(db_path.clone());
        let event = DeferredAuditEvent::from_refusal(
            "agent:duplicate",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        let mut second_occurrence = event.clone();
        second_occurrence.occurrence_id = Some(uuid::Uuid::new_v4().to_string());

        assert_eq!(sink.append(&event).unwrap(), AppendOutcome::Appended);
        assert_eq!(
            sink.append(&second_occurrence).unwrap(),
            AppendOutcome::Appended
        );

        let conn = crate::db::open(&db_path).expect("reopen db");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
                rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:duplicate"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2, "two live submissions are two audit occurrences");
    }

    #[test]
    fn sqlite_sink_retry_is_idempotent_by_canonical_payload() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("def-audit-idempotent-retry.db");
        let _ = crate::db::open(&db_path).expect("init db");
        let mut sink = SqliteSignedEventsSink::new(db_path.clone());
        let event =
            DeferredAuditEvent::from_refusal("agent:retry", &refusal_action(), &refusal_decision())
                .unwrap();

        assert_eq!(sink.append(&event).unwrap(), AppendOutcome::Appended);
        assert_eq!(sink.append_retry(&event).unwrap(), AppendOutcome::Appended);

        let conn = crate::db::open(&db_path).expect("reopen db");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
                rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:retry"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "panic retry must not duplicate the chain row");
    }

    #[test]
    fn sqlite_sink_retry_rejects_occurrence_id_payload_collision() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("retry-id-collision.db");
        let _ = crate::db::open(&db_path).expect("init db");
        let mut sink = SqliteSignedEventsSink::new(db_path);
        let first =
            DeferredAuditEvent::from_refusal("agent:first", &refusal_action(), &refusal_decision())
                .unwrap();
        let mut collision = DeferredAuditEvent::from_refusal(
            "agent:different",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        collision.occurrence_id.clone_from(&first.occurrence_id);
        assert_eq!(sink.append(&first).unwrap(), AppendOutcome::Appended);
        assert!(sink.append_retry(&collision).is_err());
    }

    #[test]
    fn sqlite_sink_retry_recognizes_matching_dlq_residence() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("retry-dlq-residence.db");
        let conn = crate::db::open(&db_path).expect("init db");
        let event = DeferredAuditEvent::from_refusal(
            "agent:retry-dlq",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        let hash = payload_hash(&event.canonical_bytes().unwrap());
        conn.execute(
            "INSERT INTO signed_events_dlq (id, agent_id, event_type, payload_hash, attest_level, timestamp, failure_reason, failed_at) VALUES (?1, ?2, ?3, ?4, 'unsigned', ?5, 'injected', ?5)",
            rusqlite::params![event.occurrence_id, event.agent_id, GOVERNANCE_REFUSAL_EVENT_TYPE, hash, event.timestamp.to_rfc3339()],
        ).unwrap();
        drop(conn);
        let mut sink = SqliteSignedEventsSink::new(db_path.clone());
        assert_eq!(sink.append_retry(&event).unwrap(), AppendOutcome::DlqLanded);
        let conn = crate::db::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM signed_events_dlq", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn sqlite_sink_lazy_open_only_on_first_append() {
        // Construct a sink against a path that doesn't exist yet; if
        // we never call append, ensure_conn must never run.
        let nonexistent = std::path::PathBuf::from("/this/path/does/not/exist/db.sqlite");
        let sink = SqliteSignedEventsSink::new(nonexistent);
        // Just verifying construction doesn't open the DB — no
        // assertion needed; if `new` opened eagerly, this would
        // already have errored.
        drop(sink);
    }

    #[tokio::test]
    async fn sqlite_sink_append_fails_on_bad_path_metrics_increments() {
        let (queue, rx) = DeferredAuditQueue::new();
        let metrics = queue.metrics();
        // Build a sink pointing at a path that can't be opened (a
        // directory that doesn't exist + a non-creatable subdir
        // would do it; under macOS/Linux we use a path under /sys
        // which is read-only).
        let bad_path =
            std::path::PathBuf::from("/nonexistent-readonly-dir-for-deferred-audit-test/db.sqlite");
        let supervisor = spawn_supervised_drainer(
            rx,
            move || SqliteSignedEventsSink::new(bad_path.clone()),
            metrics.clone(),
            u32::MAX,
        );
        let event =
            DeferredAuditEvent::from_refusal("agent:bad", &refusal_action(), &refusal_decision())
                .unwrap();
        queue.submit(event);
        // Allow the drainer to attempt the append.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        close_and_flush(queue, supervisor).await.unwrap();
        assert!(
            metrics.append_failure_count() >= 1,
            "append failure on bad path must be recorded; got {}",
            metrics.append_failure_count()
        );
        assert_eq!(metrics.appended_count(), 0);
    }

    // -----------------------------------------------------------------
    // install_deferred_audit_drainer end-to-end (the daemon-facing
    // installer)
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn installer_returns_open_queue_and_running_supervisor() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("installer-test.db");
        let _ = crate::db::open(&db_path).expect("init db");

        let (queue, supervisor) = install_deferred_audit_drainer(&db_path);
        assert!(queue.is_open());

        let event = DeferredAuditEvent::from_refusal(
            "agent:installer",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        queue.submit(event);

        close_and_flush(queue, supervisor).await.unwrap();

        let conn = crate::db::open(&db_path).expect("reopen db");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn journaled_installer_acknowledges_live_spool_after_durable_append() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("journaled-installer.db");
        let _ = crate::db::open(&db_path).expect("init db");
        let journal_path = deferred_audit_journal_path(&db_path);
        let (queue, supervisor) = install_deferred_audit_drainer_with_journal(&db_path);
        assert!(queue.submit_refusal("agent:ack", &refusal_action(), &refusal_decision()));
        close_and_flush(queue, supervisor).await.unwrap();
        assert!(
            DeferredAuditJournal::open(journal_path)
                .unwrap()
                .replay()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn journal_open_failure_returns_closed_queue_not_volatile_fallback() {
        let dir = fresh_tempdir();
        let blocker = dir.path().join("not-a-directory");
        std::fs::write(&blocker, b"block").unwrap();
        let (queue, supervisor) =
            install_deferred_audit_drainer_with_journal(&blocker.join("db.sqlite"));
        assert!(!queue.is_open());
        assert!(!queue.submit_refusal("agent:closed", &refusal_action(), &refusal_decision()));
        supervisor.await.unwrap();
    }

    // -----------------------------------------------------------------
    // Cluster-C SEC-3 (issue #767) — DLQ + race-retry coverage
    // -----------------------------------------------------------------

    /// When the sink hits a non-race rusqlite error on the
    /// `signed_events` INSERT, the event MUST land in
    /// `signed_events_dlq` (NOT silently dropped) and the
    /// `dlq_landed` counter MUST bump.
    ///
    /// Failure injection: pre-fill `signed_events` with a row whose
    /// `id` collides with the next UUIDv4 the sink will mint. We can't
    /// predict UUIDs, so we instead break the table at the schema
    /// level: drop the `event_type` column. The next `append_signed_event`
    /// fails on the INSERT (column not found) — an unrecoverable
    /// non-race error that triggers DLQ land.
    #[tokio::test]
    async fn sqlite_sink_lands_event_in_dlq_on_unrecoverable_error() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("dlq-test.db");
        let _ = crate::db::open(&db_path).expect("init db");

        // Inject the fault: drop the NOT-NULL `event_type` column from
        // signed_events. Subsequent inserts fail with a constraint
        // error (NULL into NOT NULL slot) — an unrecoverable non-race
        // error. We do this by rebuilding the table without the
        // column; the DLQ table stays intact.
        {
            let conn = crate::db::open(&db_path).expect("open for fault inject");
            conn.execute_batch(
                "DROP TABLE signed_events; \
                 CREATE TABLE signed_events ( \
                    id TEXT PRIMARY KEY, \
                    agent_id TEXT NOT NULL, \
                    payload_hash BLOB NOT NULL, \
                    signature BLOB, \
                    attest_level TEXT NOT NULL DEFAULT 'unsigned', \
                    timestamp TEXT NOT NULL, \
                    prev_hash BLOB, \
                    sequence INTEGER, cause_hash BLOB \
                 ); \
                 CREATE UNIQUE INDEX idx_signed_events_sequence \
                    ON signed_events(sequence);",
            )
            .expect("fault-inject schema rewrite");
        }

        // Spawn drainer + submit one event. The sink will fail the
        // append (column missing → schema mismatch is unrecoverable)
        // and land it in DLQ.
        let (queue, supervisor) = install_deferred_audit_drainer(&db_path);
        let metrics = queue.metrics();
        let event = DeferredAuditEvent::from_refusal(
            "agent:dlq-test",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        queue.submit(event);
        close_and_flush(queue, supervisor).await.unwrap();

        // Assert: chain row NOT written, DLQ row present, counters
        // reflect the outcome.
        let conn = crate::db::open(&db_path).expect("reopen db");
        let chain_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM signed_events", [], |r| r.get(0))
            .unwrap_or(0);
        assert_eq!(
            chain_count, 0,
            "signed_events chain MUST NOT advance when sink fails"
        );
        let dlq_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM signed_events_dlq", [], |r| r.get(0))
            .unwrap();
        assert_eq!(dlq_count, 1, "exactly one DLQ row expected");
        let dlq_size_live = dlq_size(&conn).expect("dlq_size");
        assert_eq!(dlq_size_live, 1, "dlq_size helper must reflect live count");
        assert!(
            metrics.dlq_landed_count() >= 1,
            "dlq_landed metric must bump on DLQ landing"
        );
    }

    /// `is_unique_constraint_race` MUST return true for a synthetic
    /// `SQLITE_CONSTRAINT_UNIQUE` error and false for other rusqlite
    /// errors. Pins the classification helper against rusqlite
    /// version drift.
    #[test]
    fn is_unique_constraint_race_classifies_correctly() {
        let unique_err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE),
            Some("UNIQUE constraint failed: signed_events.sequence".to_string()),
        );
        let id_unique_err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE),
            Some("UNIQUE constraint failed: signed_events.id".to_string()),
        );
        let other_err = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("database is locked".to_string()),
        );
        let wrapped_unique: anyhow::Error =
            anyhow::Error::from(unique_err).context("append signed_event");
        let wrapped_other: anyhow::Error =
            anyhow::Error::from(other_err).context("append signed_event");
        assert!(is_unique_constraint_race(&wrapped_unique));
        assert!(!is_unique_constraint_race(&wrapped_other));
        assert!(!is_unique_constraint_race(&anyhow::Error::from(
            id_unique_err
        )));

        // Non-rusqlite errors are never UNIQUE races.
        let plain: anyhow::Error = anyhow::anyhow!("plain error");
        assert!(!is_unique_constraint_race(&plain));
    }

    /// `dlq_size` MUST return 0 on a fresh DB (no DLQ rows).
    #[tokio::test]
    async fn dlq_size_returns_zero_on_fresh_db() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("dlq-empty.db");
        let conn = crate::db::open(&db_path).expect("init db");
        assert_eq!(dlq_size(&conn).expect("dlq_size on fresh"), 0);
    }

    // -----------------------------------------------------------------
    // Metrics — getter coverage
    // -----------------------------------------------------------------

    #[test]
    fn metrics_default_returns_zeroes() {
        let m = DeferredAuditMetrics::default();
        assert_eq!(m.submitted_count(), 0);
        assert_eq!(m.appended_count(), 0);
        assert_eq!(m.send_failure_count(), 0);
        assert_eq!(m.append_failure_count(), 0);
        assert_eq!(m.panic_count(), 0);
        assert_eq!(m.dlq_landed_count(), 0);
        assert_eq!(m.unique_race_retry_count(), 0);
    }

    #[test]
    fn metrics_clone_shares_counters() {
        let m1 = DeferredAuditMetrics::default();
        let m2 = m1.clone();
        m1.submitted.fetch_add(7, Ordering::Relaxed);
        // m2 sees the same counter — Arc<Atomic> semantics.
        assert_eq!(m2.submitted_count(), 7);
    }

    // -----------------------------------------------------------------
    // GOVERNANCE_REFUSAL_EVENT_TYPE is a stable wire string
    // -----------------------------------------------------------------

    #[test]
    fn governance_refusal_event_type_is_stable() {
        assert_eq!(GOVERNANCE_REFUSAL_EVENT_TYPE, "governance.refusal");
    }

    // ── PE-4 (#1732) crash-durable journal ───────────────────────────────

    #[test]
    fn journal_submit_then_crash_recovers_on_boot_1732() {
        // Refusal durably journaled → SIGKILL before the drainer processed
        // it (journal dropped without draining) → recover_deferred_audit on
        // next boot chains it into signed_events.
        let dir = fresh_tempdir();
        let db_path = dir.path().join("crash-recover.db");
        let _ = crate::db::open(&db_path).expect("init db schema");
        let journal_path = deferred_audit_journal_path(&db_path);

        {
            let journal = DeferredAuditJournal::open(&journal_path).expect("open journal");
            let ev = DeferredAuditEvent::from_refusal(
                "agent:crash",
                &refusal_action(),
                &refusal_decision(),
            )
            .unwrap();
            journal.append(&ev).expect("durable append");
            // journal dropped here = process SIGKILL'd; event never drained.
        }

        let recovered = recover_deferred_audit(&journal_path, &db_path).expect("recover");
        assert_eq!(recovered, 1, "the pre-crash refusal must be recovered");

        let conn = crate::db::open(&db_path).expect("reopen");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
                rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:crash"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "recovered refusal must be chained into signed_events"
        );

        // Journal truncated after recovery.
        let after = DeferredAuditJournal::open(&journal_path)
            .unwrap()
            .replay()
            .unwrap();
        assert!(after.is_empty(), "journal must be truncated post-recovery");
    }

    #[test]
    fn recovery_replays_surviving_spool_when_legacy_journal_is_missing() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("orphan-spool.db");
        let _ = crate::db::open(&db_path).expect("init db schema");
        let journal_path = deferred_audit_journal_path(&db_path);
        let event = DeferredAuditEvent::from_refusal(
            "agent:orphan-spool",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        let journal = DeferredAuditJournal::open(&journal_path).unwrap();
        journal.append(&event).unwrap();
        drop(journal);
        std::fs::remove_file(&journal_path).unwrap();

        assert_eq!(recover_deferred_audit(&journal_path, &db_path).unwrap(), 1);
        let conn = crate::db::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE agent_id = ?1",
                ["agent:orphan-spool"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn submit_with_journal_is_durable_before_return_1912() {
        // #1912 — the corrected `submit` doc states that when a journal is
        // configured the event is durably fsync'd BEFORE `submit` returns
        // (it is NOT the "non-blocking" fire-and-forget the old doc
        // claimed). Lock that contract: after `submit` returns, replaying
        // the journal from an INDEPENDENT handle must already observe the
        // event — i.e. it hit stable storage synchronously on this thread,
        // before the channel send, with no drainer involved.
        let dir = fresh_tempdir();
        let journal_path = dir.path().join("durable-submit.journal");
        let journal = Arc::new(DeferredAuditJournal::open(&journal_path).expect("open journal"));
        let (queue, _rx) = DeferredAuditQueue::new_with_journal(Some(journal));

        let queued = queue.submit_refusal("agent:durable", &refusal_action(), &refusal_decision());
        assert!(queued, "submit must enqueue while the receiver is alive");

        // Independent handle → proves the bytes are on disk, not merely in
        // the writer's in-process buffer.
        let replayed = DeferredAuditJournal::open(&journal_path)
            .expect("reopen journal")
            .replay()
            .expect("replay");
        assert_eq!(
            replayed.len(),
            1,
            "the refusal must be durably journaled before submit() returns"
        );
        assert_eq!(replayed[0].agent_id, "agent:durable");
    }

    #[test]
    fn journal_torn_trailing_record_discarded_1732() {
        // Two intact records + a torn trailing frame (crash mid-write) →
        // replay returns the 2 intact, discards the torn tail.
        let dir = fresh_tempdir();
        let journal_path = dir.path().join("torn.journal");
        let journal = DeferredAuditJournal::open(&journal_path).unwrap();
        let mut ev =
            DeferredAuditEvent::from_refusal("agent:a", &refusal_action(), &refusal_decision())
                .unwrap();
        ev.occurrence_id = None;
        journal.append(&ev).unwrap();
        journal.append(&ev).unwrap();
        // Append a TORN frame: a u32 length header claiming 999 bytes but
        // only a few payload bytes present (the crash-mid-append shape).
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&journal_path)
                .unwrap();
            f.write_all(&999u32.to_le_bytes()).unwrap();
            f.write_all(b"partial").unwrap();
            f.sync_all().unwrap();
        }
        let recovered = journal.replay().unwrap();
        assert_eq!(
            recovered.len(),
            2,
            "the 2 intact records replay; the torn trailing frame is discarded"
        );
    }

    #[test]
    fn journal_corrupt_complete_frame_fails_closed() {
        let dir = fresh_tempdir();
        let journal_path = dir.path().join("corrupt.journal");
        let journal = DeferredAuditJournal::open(&journal_path).unwrap();
        let mut ev =
            DeferredAuditEvent::from_refusal("agent:a", &refusal_action(), &refusal_decision())
                .unwrap();
        ev.occurrence_id = None;
        journal.append(&ev).unwrap();
        drop(journal);
        let mut bytes = std::fs::read(&journal_path).unwrap();
        bytes[4] ^= 1;
        std::fs::write(&journal_path, bytes).unwrap();
        assert!(
            DeferredAuditJournal::open(&journal_path)
                .unwrap()
                .replay()
                .is_err()
        );
    }

    #[test]
    fn journal_ignores_incomplete_staging_files() {
        let dir = fresh_tempdir();
        let journal_path = dir.path().join("staging.journal");
        let journal = DeferredAuditJournal::open(&journal_path).unwrap();
        let ev =
            DeferredAuditEvent::from_refusal("agent:valid", &refusal_action(), &refusal_decision())
                .unwrap();
        journal.append(&ev).unwrap();
        let pending = journal.spool_dir.join(".crash.pending");
        std::fs::write(&pending, b"partial").unwrap();
        drop(journal);
        let reopened = DeferredAuditJournal::open(&journal_path).unwrap();
        assert!(
            !pending.exists(),
            "torn staging is reclaimed under the spool lock"
        );
        assert_eq!(reopened.spool_usage.lock().unwrap().entries, 1);
        let replayed = reopened.replay().unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].agent_id, "agent:valid");
    }

    #[test]
    fn journal_reconciles_complete_pending_frame_on_open() {
        let dir = fresh_tempdir();
        let journal_path = dir.path().join("pending-reconcile.journal");
        let journal = DeferredAuditJournal::open(&journal_path).unwrap();
        let event = DeferredAuditEvent::from_refusal(
            "agent:pending",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        let pending = journal.spool_dir.join(".crash.pending");
        std::fs::write(
            &pending,
            journal_frame(&event.canonical_bytes().unwrap()).unwrap(),
        )
        .unwrap();
        drop(journal);
        let reopened = DeferredAuditJournal::open(&journal_path).unwrap();
        assert!(!pending.exists());
        assert_eq!(reopened.spool_usage.lock().unwrap().entries, 1);
        let replayed = reopened.replay().unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].occurrence_id, event.occurrence_id);
    }

    #[cfg(unix)]
    #[test]
    fn journal_spool_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_tempdir();
        let journal_path = dir.path().join("private.journal");
        let journal = DeferredAuditJournal::open(&journal_path).unwrap();
        let ev = DeferredAuditEvent::from_refusal(
            "agent:private",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        journal.append(&ev).unwrap();
        assert_eq!(
            std::fs::metadata(&journal.spool_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let event_path = journal.spool_path(ev.occurrence_id.as_deref().unwrap());
        assert_eq!(
            std::fs::metadata(event_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(windows)]
    #[test]
    fn journal_windows_publish_ack_and_reopen_runtime() {
        let dir = fresh_tempdir();
        let path = dir.path().join("windows-durability.journal");
        let event = DeferredAuditEvent::from_refusal(
            "agent:windows",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        let journal = DeferredAuditJournal::open(&path).unwrap();
        journal.append(&event).unwrap();
        let replayed = journal.replay().unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].occurrence_id, event.occurrence_id);
        journal.acknowledge(&event).unwrap();
        drop(journal);
        assert!(
            DeferredAuditJournal::open(path)
                .unwrap()
                .replay()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn journal_quota_refuses_unjournaled_queue_delivery() {
        let dir = fresh_tempdir();
        let journal =
            Arc::new(DeferredAuditJournal::open(dir.path().join("quota.journal")).unwrap());
        // Populate the filesystem itself because admission deliberately rescans
        // under the OS lock instead of trusting the process-local cache.
        let quota_filler = journal.spool_dir.join("quota-filler.event");
        let filler = File::create(&quota_filler).unwrap();
        filler.set_len(JOURNAL_SPOOL_MAX_BYTES).unwrap();
        filler.sync_all().unwrap();
        journal.sync_spool_dir().unwrap();
        let (queue, mut receiver) =
            DeferredAuditQueue::new_with_journal(Some(Arc::clone(&journal)));
        assert!(!queue.submit_refusal("agent:quota", &refusal_action(), &refusal_decision()));
        assert!(receiver.try_recv().is_err());
        assert_eq!(queue.metrics().send_failure_count(), 1);
        assert!(
            journal
                .spool_dir
                .join(format!("{JOURNAL_OVERFLOW_PREFIX}000"))
                .exists()
        );
    }

    #[test]
    fn journal_handles_rescan_authoritative_usage_under_os_lock() {
        let dir = fresh_tempdir();
        let path = dir.path().join("multi-handle.journal");
        let first_handle = DeferredAuditJournal::open(&path).unwrap();
        let second_handle = DeferredAuditJournal::open(&path).unwrap();
        let first =
            DeferredAuditEvent::from_refusal("agent:first", &refusal_action(), &refusal_decision())
                .unwrap();
        let second = DeferredAuditEvent::from_refusal(
            "agent:second",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        first_handle.append(&first).unwrap();
        second_handle.append(&second).unwrap();
        assert_eq!(second_handle.spool_usage.lock().unwrap().entries, 2);
        first_handle.acknowledge(&first).unwrap();
        assert_eq!(first_handle.spool_usage.lock().unwrap().entries, 1);
    }

    #[test]
    fn journal_recovery_is_idempotent_no_duplicate_1732() {
        // A refusal already chained pre-crash must NOT be re-appended on a
        // second recovery pass (dedup on stable occurrence ID).
        let dir = fresh_tempdir();
        let db_path = dir.path().join("idem.db");
        let _ = crate::db::open(&db_path).expect("init db");
        let journal_path = deferred_audit_journal_path(&db_path);
        let ev =
            DeferredAuditEvent::from_refusal("agent:idem", &refusal_action(), &refusal_decision())
                .unwrap();

        DeferredAuditJournal::open(&journal_path)
            .unwrap()
            .append(&ev)
            .unwrap();
        assert_eq!(
            recover_deferred_audit(&journal_path, &db_path).unwrap(),
            1,
            "first recovery chains the refusal"
        );

        // Same event re-journaled (stale/duplicate) → recovery dedups.
        DeferredAuditJournal::open(&journal_path)
            .unwrap()
            .append(&ev)
            .unwrap();
        assert_eq!(
            recover_deferred_audit(&journal_path, &db_path).unwrap(),
            0,
            "an already-chained occurrence must not be re-appended"
        );

        let conn = crate::db::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
                rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:idem"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "exactly one row despite two recovery passes");
    }

    #[test]
    fn journal_recovery_preserves_identical_occurrence_multiplicity() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("journal-occurrence-multiplicity.db");
        let _ = crate::db::open(&db_path).expect("init db");
        let journal_path = deferred_audit_journal_path(&db_path);
        let first =
            DeferredAuditEvent::from_refusal("agent:multi", &refusal_action(), &refusal_decision())
                .unwrap();
        let mut second = first.clone();
        second.occurrence_id = Some(uuid::Uuid::new_v4().to_string());
        let journal = DeferredAuditJournal::open(&journal_path).unwrap();
        journal.append(&first).unwrap();
        journal.append(&second).unwrap();
        drop(journal);

        assert_eq!(recover_deferred_audit(&journal_path, &db_path).unwrap(), 2);
        let conn = crate::db::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
                rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:multi"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn legacy_journal_recovery_uses_cardinality_not_existence() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("journal-legacy-cardinality.db");
        let _ = crate::db::open(&db_path).expect("init db");
        let journal_path = deferred_audit_journal_path(&db_path);
        let mut legacy = DeferredAuditEvent::from_refusal(
            "agent:legacy-multi",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        legacy.occurrence_id = None;
        let journal = DeferredAuditJournal::open(&journal_path).unwrap();
        journal.append(&legacy).unwrap();
        journal.append(&legacy).unwrap();
        drop(journal);

        assert_eq!(recover_deferred_audit(&journal_path, &db_path).unwrap(), 2);
        let conn = crate::db::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1 AND agent_id = ?2",
                rusqlite::params![GOVERNANCE_REFUSAL_EVENT_TYPE, "agent:legacy-multi"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn legacy_journal_recovery_counts_matching_dlq_as_terminal() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("journal-legacy-dlq.db");
        let conn = crate::db::open(&db_path).expect("init db");
        let journal_path = deferred_audit_journal_path(&db_path);
        let mut legacy = DeferredAuditEvent::from_refusal(
            "agent:legacy-dlq",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        legacy.occurrence_id = None;
        let hash = payload_hash(&legacy.canonical_bytes().unwrap());
        conn.execute(
            "INSERT INTO signed_events_dlq (id, agent_id, event_type, payload_hash, attest_level, timestamp, failure_reason, failed_at) VALUES ('legacy-id', ?1, ?2, ?3, 'unsigned', ?4, 'injected', ?4)",
            rusqlite::params![legacy.agent_id, GOVERNANCE_REFUSAL_EVENT_TYPE, hash, legacy.timestamp.to_rfc3339()],
        ).unwrap();
        drop(conn);
        DeferredAuditJournal::open(&journal_path)
            .unwrap()
            .append(&legacy)
            .unwrap();
        assert_eq!(recover_deferred_audit(&journal_path, &db_path).unwrap(), 0);
        let conn = crate::db::open(&db_path).unwrap();
        let chained: i64 = conn
            .query_row("SELECT COUNT(*) FROM signed_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(chained, 0);
    }

    #[test]
    fn journal_recovery_retains_records_after_unrecoverable_sink_error() {
        let dir = fresh_tempdir();
        let db_path = dir.path().join("journal-retain-on-error.db");
        let conn = crate::db::open(&db_path).expect("init db");
        conn.execute_batch(
            "CREATE TRIGGER reject_signed_event BEFORE INSERT ON signed_events \
             BEGIN SELECT RAISE(FAIL, 'injected signed event failure'); END; \
             CREATE TRIGGER reject_signed_dlq BEFORE INSERT ON signed_events_dlq \
             BEGIN SELECT RAISE(FAIL, 'injected dlq failure'); END;",
        )
        .unwrap();
        drop(conn);
        let journal_path = deferred_audit_journal_path(&db_path);
        let event = DeferredAuditEvent::from_refusal(
            "agent:retain",
            &refusal_action(),
            &refusal_decision(),
        )
        .unwrap();
        DeferredAuditJournal::open(&journal_path)
            .unwrap()
            .append(&event)
            .unwrap();

        assert_eq!(recover_deferred_audit(&journal_path, &db_path).unwrap(), 0);
        let replayed = DeferredAuditJournal::open(&journal_path)
            .unwrap()
            .replay()
            .unwrap();
        assert_eq!(replayed.len(), 1, "unresolved event must remain durable");
        assert_eq!(replayed[0].occurrence_id, event.occurrence_id);
    }
}
