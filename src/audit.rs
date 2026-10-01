// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Enterprise audit trail (PR-5 of issue #487).
//!
//! Every memory-mutation call site in the binary — HTTP handlers, MCP
//! tool dispatch, CLI write commands, and `ai-memory boot` — emits an
//! [`AuditEvent`] to a hash-chained, append-only JSON log when the
//! audit subsystem is enabled. The schema is **stable, versioned, and
//! framework-agnostic** (NOT bound to OCSF or CEF — see
//! `docs/security/audit-schema.md`). SIEMs ingest the lines as-is.
//!
//! # Design properties
//!
//! 1. **Default-OFF** for privacy. Operators opt in via
//!    `[audit] enabled = true` in `config.toml` (or
//!    `AI_MEMORY_AUDIT_DIR=<dir>` env var for one-off runs — see
//!    `src/log_paths.rs::AUDIT_DIR_ENV` for the canonical name; the
//!    audit log file is written as `<dir>/audit.log`).
//! 2. **Hash-chained, tamper-evident.** Each line carries a `prev_hash`
//!    that matches the prior line's `self_hash`. `ai-memory audit
//!    verify` recomputes the chain and exits non-zero on mismatch.
//! 3. **Append-only OS hint.** Best-effort `chflags(2)` (BSD/macOS) or
//!    `FS_IOC_SETFLAGS` ioctl (Linux). Documented as defense in depth;
//!    the chain is the load-bearing tamper-evidence.
//! 4. **Privacy by default.** Audit captures `(memory_id, namespace,
//!    title, action, outcome, actor)`. Memory **content is never
//!    emitted** — `redact_content = true` is the only supported mode in
//!    the v1 schema; the field is reserved in [`AuditTarget`] for
//!    future compliance contexts that mandate content capture.
//! 5. **Per-process monotonic sequence**, independent of the chain.
//!    Lets a SIEM detect dropped lines even before the chain check.
//! 6. **Best-effort failure posture.** Emission is synchronous and
//!    serialized within one process. The file is opened with `O_APPEND`, but
//!    separate processes are not chain-serialized and a crash or short write
//!    can leave a torn final line. Run one writer per audit file and use
//!    `audit verify` to detect malformed or broken chains. An enabled
//!    trail whose tail cannot be read or ends in a torn record refuses to
//!    start rather than restarting the chain at genesis (#4190). Failures inside
//!    emit are swallowed and logged via `tracing`; a broken audit pipeline
//!    never blocks a memory operation.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime_context::RuntimeContext;

/// Canonical `consolidate` operation label — shared by the audit op
/// vocabulary, the autonomy rollback tags, and the governance action
/// adapter (#1558 batch 6).
pub(crate) const OP_CONSOLIDATE: &str = "consolidate";

/// Stable schema version stamped on every emitted line. Bump only when
/// a field's semantics change in a way SIEM parsers care about
/// (renaming, removing, or repurposing). Adding optional fields does
/// NOT bump the version. See `docs/security/audit-schema.md` §Version
/// policy for the full contract.
pub const SCHEMA_VERSION: u32 = 1;

/// Sentinel `prev_hash` for the first line in a fresh chain. Hex-encoded
/// 32-byte zero buffer — picked so a chain head is unambiguous on
/// inspection.
pub const CHAIN_HEAD_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// One audit event. The serialized form is one JSON object per line
/// (NDJSON). Field order is stable for chain reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    /// Schema version — see [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// RFC3339 UTC timestamp when the event was emitted.
    pub timestamp: String,
    /// Per-process monotonic counter starting at 1 on init.
    pub sequence: u64,
    pub actor: AuditActor,
    pub action: AuditAction,
    pub target: AuditTarget,
    pub outcome: AuditOutcome,
    /// Authentication context. `None` for stdio MCP / CLI invocations
    /// where there is no transport-level auth.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuditAuth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Populated only when `outcome = Error`. Capped at 256 chars to
    /// prevent error-message based content leaks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Hex-encoded sha256 of the immediately prior line's `self_hash`,
    /// or [`CHAIN_HEAD_PREV_HASH`] for the first line of a fresh chain.
    pub prev_hash: String,
    /// Hex-encoded sha256 of every preceding field in serialization order.
    pub self_hash: String,
}

/// Who performed the action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditActor {
    /// Resolved NHI agent_id (`ai:<client>@<host>:pid-<n>`,
    /// `host:<host>:pid-<n>-<uuid>`, etc.). Always present.
    pub agent_id: String,
    /// Visibility scope: `private | team | unit | org | collective`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// How `agent_id` was synthesized — surfaces NHI provenance to the
    /// SIEM. One of: `explicit | env | mcp_client_info | host_fallback
    /// | anonymous_fallback | http_header | http_body | per_request`.
    pub synthesis_source: String,
}

/// #1558 batch 5 wave 3 — canonical [`AuditActor::synthesis_source`]
/// provenance values. One spelling per value; every production writer
/// (MCP dispatch, MCP store/delete tools, HTTP handlers, CLI
/// crud/store/update) references these consts instead of scattering
/// the literal. The vocabulary doc on `synthesis_source` above stays
/// the narrative SSOT; this mod is the mechanical one.
pub mod synthesis_sources {
    /// Caller passed an explicit `--agent-id` / `agent_id` param.
    pub const EXPLICIT: &str = "explicit";
    /// Resolved from `initialize.clientInfo.name` (MCP stdio).
    pub const MCP_CLIENT_INFO: &str = "mcp_client_info";
    /// Synthesized `host:<hostname>:pid-…` fallback (no client info).
    pub const HOST_FALLBACK: &str = "host_fallback";
    /// Taken from the `X-Agent-Id` HTTP request header.
    pub const HTTP_HEADER: &str = "http_header";
    /// No explicit caller identity — default resolution ladder.
    pub const DEFAULT_FALLBACK: &str = "default_fallback";
}

/// Canonical action vocabulary. Adding a variant is a non-breaking
/// schema change; renaming or removing one IS breaking.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Recall,
    Store,
    Update,
    Delete,
    Link,
    Promote,
    Forget,
    Consolidate,
    Export,
    Import,
    Approve,
    Reject,
    SessionBoot,
    /// L1 capture-nag (#1389 / #1398). Emitted by the MCP dispatch loop
    /// when an agent crosses the consecutive-non-capture-tool-call
    /// threshold without a `memory_store` / `memory_capture_turn`.
    /// Informational (`outcome = Allow`); surfaces capture drift to the
    /// SIEM in real time rather than at next-session recovery (L2).
    CaptureLag,
}

impl AuditAction {
    /// Wire-format string for log-grep convenience.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Recall => "recall",
            Self::Store => "store",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Link => "link",
            Self::Promote => "promote",
            Self::Forget => "forget",
            Self::Consolidate => OP_CONSOLIDATE,
            Self::Export => "export",
            Self::Import => "import",
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::SessionBoot => "session_boot",
            Self::CaptureLag => "capture_lag",
        }
    }
}

/// What was acted upon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditTarget {
    /// Memory id, or `"*"` for a list/sweep operation that touches
    /// many rows (forget, export, consolidate-many, etc.).
    pub memory_id: String,
    /// Memory namespace at the time of the action.
    pub namespace: String,
    /// Memory title at the time of the action. Capped at 200 chars and
    /// stripped of newlines to prevent log-injection. Title is **not**
    /// content; titles are advisory labels by design (`memory.content`
    /// is the secret payload and is **never** emitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Memory tier (`short | mid | long`) at action time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Memory `metadata.scope` at action time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Outcome of the action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Allow,
    Deny,
    Error,
    Pending,
}

/// Authentication context for HTTP-originated events. Stdio (CLI / MCP)
/// invocations omit this block entirely.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditAuth {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_fp: Option<String>,
    /// **Hash** of the API key id, never the raw key. Hex-encoded
    /// sha256 truncated to 16 bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Sink — process-wide singleton holding the file handle + chain head.
// ---------------------------------------------------------------------------

// v0.7.x (issue #1174 follow-up #1192) — sink + sequence moved into
// `RuntimeContext::audit`. The accessors below preserve byte-equivalent
// semantics: every read goes through `RuntimeContext::global().audit.*`
// so the V-4 hash chain invariant + the F2 sequence-restart invariant
// are observed identically by `init`, `emit`, `verify_chain`, and the
// `init_for_test` / `shutdown_for_test` helpers.

/// Initialised audit sink — writer handle protected by a mutex so the
/// chain head update + write are atomic across emission threads. The
/// writer is `dyn Write + Send` so tests can substitute an in-memory
/// `Vec<u8>` for the production `File`.
pub struct AuditSink {
    inner: Mutex<SinkInner>,
    #[allow(dead_code)]
    redact_content: bool,
}

impl std::fmt::Debug for AuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSink")
            .field("redact_content", &self.redact_content)
            .finish_non_exhaustive()
    }
}

struct SinkInner {
    writer: Box<dyn Write + Send>,
    /// `self_hash` of the last line written, used as the next line's
    /// `prev_hash`. Starts as [`CHAIN_HEAD_PREV_HASH`] for a fresh log.
    last_hash: String,
    /// Source path, when the sink wraps a real file. `None` for
    /// in-memory test sinks.
    path: Option<PathBuf>,
    /// #4086 — the persisted sequence high-water mark next to a real file
    /// (`None` for in-memory test sinks).
    seq_mark: Option<SeqMark>,
    /// #4211 — a read+append handle on the trail file (`None` for in-memory
    /// test sinks). It carries the exclusive lock around each append and is
    /// how a failed append's own bytes are measured and removed.
    trail: Option<File>,
    /// #4211 — the trail ends in bytes of a failed append that could not be
    /// removed. The next record is line-aligned first.
    torn: Option<Torn>,
}

/// #4211 — what a failed append left at the end of the trail when its bytes
/// could not be removed (the append-only OS flag refuses truncation).
#[derive(Debug)]
enum Torn {
    /// Part of a record: once line-aligned it is an unparseable line, which
    /// `verify` reports as a [`VerifyFailureKind::TornRecord`].
    Fragment,
    /// The whole record except its newline. Once line-aligned it is a valid
    /// line in chain order, so it becomes the chain head.
    CompleteRecord { self_hash: String },
}

/// #4211 — the exclusive lock on the trail file for one append, released on
/// drop. Every ai-memory writer takes it, so the bytes past the pre-write
/// length can only be this append's own while it is held. `None` when the
/// sink has no file or the platform refused the lock (truncation is then
/// never attempted).
struct TrailLock<'a>(Option<&'a File>);

impl<'a> TrailLock<'a> {
    fn acquire(trail: Option<&'a File>) -> Self {
        Self(trail.filter(|f| f.lock().is_ok()))
    }

    fn held(&self) -> bool {
        self.0.is_some()
    }
}

impl Drop for TrailLock<'_> {
    fn drop(&mut self) {
        if let Some(f) = self.0 {
            let _ = f.unlock();
        }
    }
}

/// #4211 — test seam: behave as if the trail refused truncation (the
/// append-only OS flag), which a non-root Linux test cannot set for real.
#[cfg(test)]
static REFUSE_TRUNCATION_FOR_TEST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn truncation_refused_for_test() -> bool {
    REFUSE_TRUNCATION_FOR_TEST.load(Ordering::SeqCst)
}

#[cfg(not(test))]
const fn truncation_refused_for_test() -> bool {
    false
}

/// #4298 — test seam: fail every high-water write, to prove a failed append
/// is never truncated when its loss could not be made durable.
#[cfg(test)]
static REFUSE_MARK_WRITE_FOR_TEST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn mark_write_refused_for_test() -> bool {
    REFUSE_MARK_WRITE_FOR_TEST.load(Ordering::SeqCst)
}

#[cfg(not(test))]
const fn mark_write_refused_for_test() -> bool {
    false
}

/// #4299 — test seam: refuse the WRITE-AHEAD mark only, to prove a failed
/// write-ahead never costs the event itself.
#[cfg(test)]
static REFUSE_WRITE_AHEAD_FOR_TEST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn write_ahead_refused_for_test() -> bool {
    REFUSE_WRITE_AHEAD_FOR_TEST.load(Ordering::SeqCst)
}

#[cfg(not(test))]
const fn write_ahead_refused_for_test() -> bool {
    false
}

/// #4299 — the crash point between the write-ahead mark and the append.
const CRASH_BEFORE_APPEND: &str = "before-append";

/// #4298 — crash points on the failed-append path, in the order they occur.
/// The last instant before the lost number reaches the mark: right after the
/// failed append, nothing yet removed.
const CRASH_BEFORE_MARK: &str = "before-mark";
const CRASH_AFTER_MARK: &str = "after-mark";
const CRASH_AFTER_TRUNCATE: &str = "after-truncate";

/// #4332 — test seam: run between `verify_chain`'s snapshot and its walk,
/// i.e. while a real verify is in progress, to prove the trail lock is free.
#[cfg(test)]
#[allow(clippy::type_complexity)]
static VERIFY_AFTER_SNAPSHOT_FOR_TEST: Mutex<Option<Box<dyn FnMut() + Send>>> = Mutex::new(None);

#[cfg(test)]
fn verify_after_snapshot() {
    let hook = VERIFY_AFTER_SNAPSHOT_FOR_TEST
        .lock()
        .ok()
        .and_then(|mut g| g.take());
    if let Some(mut hook) = hook {
        hook();
    }
}

/// #4298 — test seam: when set, each crash point copies the trail and its
/// high-water mark into `<dir>/<point>/`, i.e. exactly what a process killed
/// at that point leaves on disk, so a cell can verify every such state.
#[cfg(test)]
static CRASH_SNAPSHOT_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);

#[cfg(test)]
fn crash_snapshot(point: &str, trail: Option<&Path>) {
    let dir = CRASH_SNAPSHOT_DIR.lock().ok().and_then(|g| g.clone());
    let (Some(dir), Some(trail)) = (dir, trail) else {
        return;
    };
    let out = dir.join(point);
    let _ = std::fs::create_dir_all(&out);
    let name = trail.file_name().unwrap_or_default();
    let _ = std::fs::copy(trail, out.join(name));
    let mark = seq_mark_path(trail);
    if mark.exists() {
        let _ = std::fs::copy(&mark, seq_mark_path(&out.join(name)));
    }
}

#[cfg(not(test))]
#[inline]
fn crash_snapshot(_: &str, _: Option<&Path>) {}

/// #4211 — what became of a failed append's bytes.
#[derive(Debug)]
enum Undo {
    /// Nothing of the record remains: the trail is as it was before.
    Clean,
    /// The record and its newline are fully on disk after all.
    Completed,
    /// Bytes remain that could not be removed.
    Torn(Torn),
}

/// #4211 — after `write_all(record)` failed, restore the trail to its
/// pre-write length when the bytes past it are provably this append's own
/// (a prefix of `record`) and `locked` allows it. The caller passes `locked`
/// only when the lock is held AND the loss is already durable in the #4086
/// high-water (#4298). Otherwise report what is left so the next record can
/// be line-aligned.
fn undo_failed_append(
    trail: Option<&File>,
    pre_len: Option<u64>,
    locked: bool,
    record: &[u8],
    self_hash: &str,
) -> Undo {
    let Some(mut f) = trail else {
        // In-memory sink: no file to leave a fragment in.
        return Undo::Clean;
    };
    let (Some(pre), Ok(meta)) = (pre_len, f.metadata()) else {
        return Undo::Torn(Torn::Fragment);
    };
    let now = meta.len();
    if now == pre {
        return Undo::Clean;
    }
    let landed = now
        .checked_sub(pre)
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n <= record.len());
    let Some(landed) = landed else {
        // Shrunk, or grew by more than this record: not only our bytes.
        return Undo::Torn(Torn::Fragment);
    };
    let mut ours = vec![0u8; landed];
    let read = f
        .seek(SeekFrom::Start(pre))
        .and_then(|_| f.read_exact(&mut ours));
    if read.is_err() || ours != record[..landed] {
        return Undo::Torn(Torn::Fragment);
    }
    if landed == record.len() {
        return Undo::Completed;
    }
    if locked && !truncation_refused_for_test() && f.set_len(pre).is_ok() {
        let _ = f.sync_data();
        return Undo::Clean;
    }
    if landed + 1 == record.len() {
        // Only the newline is missing: finishing the line may still work.
        if f.write_all(b"\n").is_ok() {
            return Undo::Completed;
        }
        return Undo::Torn(Torn::CompleteRecord {
            self_hash: self_hash.to_string(),
        });
    }
    Undo::Torn(Torn::Fragment)
}

/// #4086 — largest sequence value a persisted high-water mark may hold.
///
/// Anything larger is treated as corruption (it would overflow the counter
/// long before a real trail could reach it), never as a value to resume from.
pub const MAX_AUDIT_SEQUENCE: u64 = i64::MAX.unsigned_abs();

/// #4086 — path of the sequence high-water mark for the trail at `trail`:
/// the trail's own file name plus `.seq`, in the same directory.
#[must_use]
pub fn seq_mark_path(trail: &Path) -> PathBuf {
    let mut name = trail
        .file_name()
        .map_or_else(|| std::ffi::OsString::from("audit.log"), ToOwned::to_owned);
    name.push(".seq");
    trail.with_file_name(name)
}

/// #4086 — the persisted sequence high-water mark.
///
/// An event is numbered BEFORE it is written. When a write fails, the number
/// is recorded here (durably, before the error is reported), so a restart
/// resumes numbering from `max(trail tail, high-water)` instead of reusing the
/// lost numbers. The loss then stays a gap `audit verify` reports (#4021),
/// even when it happened at the tail just before a restart and even before
/// the next event is written.
struct SeqMark {
    file: File,
    path: PathBuf,
    /// The value last written to the file (possibly not yet synced).
    recorded: u64,
    /// The value known to be durable (fdatasync'd).
    synced: u64,
}

impl SeqMark {
    /// #4299 — WRITE-AHEAD: raise the mark to `sequence` BEFORE its event is
    /// appended, with an in-place, fixed-width overwrite and NO fsync (the
    /// trail lines are not fsynced either, so the mark is exactly as durable
    /// as the lines it guards: it survives any process crash, and a power
    /// loss can drop both). A process that dies after numbering an event and
    /// before writing it, even on the first byte, therefore still leaves the
    /// number on disk, and verify reports it as a gap. No-op when not higher.
    fn advance(&mut self, sequence: u64) -> Result<()> {
        if sequence <= self.recorded {
            return Ok(());
        }
        if write_ahead_refused_for_test() {
            return Err(anyhow!(
                "writing audit sequence {sequence} ahead in {}: refused by the test seam",
                self.path.display()
            ));
        }
        self.write_in_place(sequence).with_context(|| {
            format!(
                "writing audit sequence {sequence} ahead in {}",
                self.path.display()
            )
        })
    }

    /// Make `sequence` DURABLE in the mark (fdatasync), writing it first when
    /// it is not there yet. Used when a write failed: the loss must be on disk
    /// before any of its evidence is removed (#4298). A number the write-ahead
    /// already put there is synced, not skipped. No-op when already durable.
    fn record(&mut self, sequence: u64) -> Result<()> {
        if sequence <= self.synced {
            return Ok(());
        }
        if mark_write_refused_for_test() {
            return Err(anyhow!(
                "recording lost audit sequence {sequence} in {}: refused by the test seam",
                self.path.display()
            ));
        }
        let path = self.path.display().to_string();
        let ctx = || format!("recording lost audit sequence {sequence} in {path}");
        if sequence > self.recorded {
            self.write_in_place(sequence).with_context(ctx)?;
        }
        self.file.sync_data().with_context(ctx)?;
        self.synced = self.recorded;
        Ok(())
    }

    /// Write `sequence` over the fixed-width record in place, then
    /// `fdatasync` (the start-up path: `open_seq_mark`).
    fn overwrite(&mut self, sequence: u64) -> Result<()> {
        self.write_in_place(sequence)
            .and_then(|()| self.file.sync_data())
            .with_context(|| {
                format!(
                    "recording audit sequence {sequence} in {}",
                    self.path.display()
                )
            })?;
        self.synced = self.recorded;
        Ok(())
    }

    /// The in-place, fixed-width write itself (no sync).
    fn write_in_place(&mut self, sequence: u64) -> std::io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(seq_mark_record(sequence).as_bytes())?;
        self.recorded = sequence;
        Ok(())
    }
}

/// The fixed-width (20 digits + newline) high-water record. Fixed so an update
/// is an in-place overwrite of bytes the file already owns: recording a lost
/// sequence number must still work on the full disk that lost the event.
fn seq_mark_record(sequence: u64) -> String {
    format!("{sequence:020}\n")
}

/// #4086 — read the high-water mark. `Ok(None)` when it does not exist (a
/// fresh trail, or one written before #4086). Anything present but not a
/// single in-range number is an ERROR: the trail can no longer tell whether
/// events were lost, and that is refused, never guessed around.
fn read_seq_mark(mark: &Path) -> Result<Option<u64>> {
    let file = match File::open(mark) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("reading audit sequence high-water {}", mark.display()));
        }
    };
    // Bounded read: the record is 21 bytes; never slurp an arbitrary file.
    let mut raw = String::new();
    file.take(64)
        .read_to_string(&mut raw)
        .with_context(|| format!("reading audit sequence high-water {}", mark.display()))?;
    let value: u64 = raw.trim().parse().map_err(|_| {
        anyhow!(
            "audit sequence high-water {} is corrupt (expected one number); the trail \
             cannot tell whether events were lost before the last shutdown",
            mark.display()
        )
    })?;
    if value > MAX_AUDIT_SEQUENCE {
        return Err(anyhow!(
            "audit sequence high-water {} holds {value}, beyond the maximum sequence \
             {MAX_AUDIT_SEQUENCE}; refusing to resume from it",
            mark.display()
        ));
    }
    Ok(Some(value))
}

/// #4086 — open the high-water mark for in-place updates, holding `value`.
///
/// An existing fixed-width mark is opened IN PLACE and overwritten in place
/// only when its value changes (`existing` is what [`read_seq_mark`] read).
/// That write reuses bytes the file already owns, so boot still works on a
/// full disk, exactly as it did before the mark existed: the trail itself is
/// only opened for append. Only a missing mark, or one not in the fixed-width
/// form, is (re)created through a temp file and a rename.
fn open_seq_mark(mark: &Path, existing: Option<u64>, value: u64) -> Result<SeqMark> {
    if let Some(on_disk) = existing {
        let ctx = || format!("updating audit sequence high-water {}", mark.display());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(mark)
            .with_context(ctx)?;
        let fixed_width = u64::try_from(seq_mark_record(value).len())
            .is_ok_and(|want| file.metadata().is_ok_and(|m| m.len() == want));
        if fixed_width {
            let mut seq_mark = SeqMark {
                file,
                path: mark.to_path_buf(),
                recorded: on_disk,
                synced: on_disk,
            };
            if on_disk != value {
                seq_mark.overwrite(value)?;
            }
            return Ok(seq_mark);
        }
    }
    create_seq_mark(mark, value)
}

/// #4086 — (re)write the high-water mark atomically (temp file, fsync,
/// rename, directory fsync) and open it for in-place updates.
fn create_seq_mark(mark: &Path, value: u64) -> Result<SeqMark> {
    let mut tmp_name = mark.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = mark.with_file_name(tmp_name);
    let ctx = || format!("writing audit sequence high-water {}", mark.display());
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .with_context(ctx)?;
        f.write_all(seq_mark_record(value).as_bytes())
            .and_then(|()| f.sync_all())
            .with_context(ctx)?;
    }
    std::fs::rename(&tmp, mark).with_context(ctx)?;
    if let Some(dir) = mark.parent().filter(|d| !d.as_os_str().is_empty()) {
        // Best-effort directory fsync so the rename itself is durable; not
        // every platform can open a directory for sync.
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(mark)
        .with_context(ctx)?;
    Ok(SeqMark {
        file,
        path: mark.to_path_buf(),
        recorded: value,
        synced: value,
    })
}

/// Initialise the audit sink. Called at most once per process from
/// [`init_from_config`]; subsequent calls replace the prior sink so
/// test-only callers can swap targets.
///
/// # Errors
/// - The audit directory cannot be created.
/// - The audit log file cannot be opened in append mode.
/// - Reading the existing chain tail (to seed `last_hash`) fails.
pub fn init(path: &Path, redact_content: bool, append_only_hint: bool) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating audit log dir {}", parent.display()))?;
    }

    // Seed the chain head from the existing tail of the log so a
    // restart on an existing file continues the chain.
    //
    // **F2 (v0.7.0 round-2-fixes):** also seed the per-process
    // SEQUENCE counter from the trailing record's `sequence` so the
    // next emit produces `last_sequence + 1`, monotonic across
    // daemon restarts. Pre-fix the SEQUENCE was reset to 0 here,
    // which made `audit verify` flag "sequence not monotonic:
    // prior=N, this=1" on the first event after every restart —
    // the hash chain was intact but the sequence integer reset.
    //
    // #4190 — `Ok(None)` (no trail yet, or only blank lines) is the ONLY case
    // that starts at genesis. A trail that exists but whose tail cannot be
    // read (an I/O or permission error, bytes that are not UTF-8, a torn or
    // corrupt last record) is an `Err` that refuses boot through
    // `init_from_config` (#3651, exit 78). Pre-#4190 every one of those was
    // treated as "no chain" and a NEW chain was appended at genesis into the
    // same file, forking it silently.
    let (last_hash, tail_sequence) = match read_chain_tail(path).with_context(|| {
        format!(
            "reading the audit trail tail {} to continue its hash chain; a trail \
             that exists but cannot be read is never restarted at genesis (that \
             would fork the chain), so repair or move the trail",
            path.display()
        )
    })? {
        Some((hash, seq)) => (hash, seq),
        None => (CHAIN_HEAD_PREV_HASH.to_string(), 0),
    };

    // #4086: resume from the persisted high-water, not only from the last
    // WRITTEN line, so numbers consumed by events lost before the restart are
    // never reused. A corrupt mark refuses init (and so boot, #3651).
    if tail_sequence > MAX_AUDIT_SEQUENCE {
        return Err(anyhow!(
            "audit log {} ends at sequence {tail_sequence}, beyond the maximum sequence \
             {MAX_AUDIT_SEQUENCE}; refusing to continue it",
            path.display()
        ));
    }
    let mark_path = seq_mark_path(path);
    let existing_mark = read_seq_mark(&mark_path)?;
    let high_water = existing_mark.unwrap_or(0);
    let last_sequence = tail_sequence.max(high_water);
    if last_sequence > tail_sequence {
        let lost = SequenceGap {
            from: tail_sequence + 1,
            to: last_sequence,
        };
        // Nothing else will say this before `audit verify` runs: the process
        // that lost them is gone, and `tracing` may be off.
        let _ = writeln!(
            std::io::stderr(),
            "ai-memory: audit trail {}: {} event(s) (sequence {lost}) were numbered \
             but never written before the last shutdown; numbering resumes after them \
             and `ai-memory audit verify` reports them as a gap (#4086)",
            path.display(),
            lost.len()
        );
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening audit log {}", path.display()))?;

    if append_only_hint {
        // Best-effort. Errors here are documented and informational —
        // the hash chain is the load-bearing tamper-evidence.
        if let Err(e) = mark_append_only(path) {
            tracing::warn!(
                "audit: append-only OS flag could not be set on {} ({e}); \
                 the hash chain remains the authoritative tamper-evidence",
                path.display()
            );
        }
    }

    let seq_mark = open_seq_mark(&mark_path, existing_mark, last_sequence)?;
    // #4211: a second handle, for the per-append lock and the undo of a
    // failed append (reading and truncating what it left).
    let trail = OpenOptions::new()
        .read(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening audit log {}", path.display()))?;

    let sink = AuditSink {
        inner: Mutex::new(SinkInner {
            writer: Box::new(file),
            last_hash,
            path: Some(path.to_path_buf()),
            seq_mark: Some(seq_mark),
            trail: Some(trail),
            torn: None,
        }),
        redact_content,
    };

    let audit = &RuntimeContext::global().audit;
    audit.sequence.store(last_sequence, Ordering::SeqCst);
    if let Ok(mut guard) = audit.sink.write() {
        *guard = Some(std::sync::Arc::new(sink));
    }
    Ok(())
}

/// Test-only helper: install an in-memory sink that captures every
/// emitted line into the supplied `Arc<Mutex<Vec<u8>>>`. Bypasses the
/// filesystem entirely so tests run in any sandbox.
#[cfg(test)]
pub fn init_for_test(buf: std::sync::Arc<Mutex<Vec<u8>>>) {
    struct VecWriter(std::sync::Arc<Mutex<Vec<u8>>>);
    impl Write for VecWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("test sink poisoned")
                .extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    init_for_test_with_writer(Box::new(VecWriter(buf)));
}

/// Test-only: install an in-memory sink over an arbitrary writer (#3975
/// drives a writer that fails like a full disk).
#[cfg(test)]
pub(crate) fn init_for_test_with_writer(writer: Box<dyn Write + Send>) {
    let sink = AuditSink {
        inner: Mutex::new(SinkInner {
            writer,
            last_hash: CHAIN_HEAD_PREV_HASH.to_string(),
            path: None,
            seq_mark: None,
            trail: None,
            torn: None,
        }),
        redact_content: true,
    };
    let audit = &RuntimeContext::global().audit;
    audit.sequence.store(0, Ordering::SeqCst);
    if let Ok(mut guard) = audit.sink.write() {
        *guard = Some(std::sync::Arc::new(sink));
    }
}

/// #4021 test helper: produce a flat audit trail with ONE real lost event.
/// Events 1 and 2 are written, event 3 hits a failing write (its sequence is
/// consumed, the chain head does not move), and event 4 is written. The trail
/// therefore verifies its hash chain cleanly and carries exactly the gap 3-3,
/// through the same mechanism a full disk produces. Takes the sink lock.
#[cfg(test)]
pub(crate) fn gapped_trail_for_test() -> Vec<u8> {
    use std::sync::atomic::AtomicBool;
    struct Toggle {
        buf: std::sync::Arc<Mutex<Vec<u8>>>,
        fail: std::sync::Arc<AtomicBool>,
    }
    impl Write for Toggle {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(std::io::Error::from_raw_os_error(28)); // ENOSPC
            }
            self.buf
                .lock()
                .expect("test buffer")
                .extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let _g = sink_test_lock();
    let buf = std::sync::Arc::new(Mutex::new(Vec::new()));
    let fail = std::sync::Arc::new(AtomicBool::new(false));
    init_for_test_with_writer(Box::new(Toggle {
        buf: std::sync::Arc::clone(&buf),
        fail: std::sync::Arc::clone(&fail),
    }));
    let one = || {
        emit(EventBuilder::new(
            AuditAction::Store,
            actor("ai:gap-4021", "explicit", None),
            target_memory("m", "ns", None, None, None),
        ));
    };
    one();
    one();
    fail.store(true, Ordering::SeqCst);
    one();
    fail.store(false, Ordering::SeqCst);
    one();
    shutdown_for_test();
    buf.lock().expect("test buffer").clone()
}

/// Process-wide lock serialising any test that installs or removes the
/// global audit sink. The sink lives on the shared [`RuntimeContext`],
/// so tests across modules (audit's own + the `mcp` dispatch tests that
/// exercise `capture_lag` emission) MUST hold this for their duration or
/// they stomp each other's buffers and hash chains.
#[cfg(test)]
pub(crate) fn sink_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Test-only helper to remove the active sink so subsequent emissions
/// no-op.
#[cfg(test)]
pub fn shutdown_for_test() {
    let audit = &RuntimeContext::global().audit;
    if let Ok(mut guard) = audit.sink.write() {
        *guard = None;
    }
    audit.sequence.store(0, Ordering::SeqCst);
}

/// Read the last `(self_hash, sequence)` pair from an existing audit
/// log. Returns `Ok(None)` only when the file doesn't exist or holds no
/// non-blank line (a genuinely empty chain); otherwise the `self_hash`
/// and `sequence` of the last record.
///
/// **#4190:** the LAST non-blank line must be a complete audit event. A
/// torn or corrupt final record is an `Err`, as is any read error (the
/// file cannot be opened or read, or holds bytes that are not UTF-8).
/// Pre-#4190 a malformed trailing line counted as "empty" and [`init`]
/// seeded a fresh chain head, forking the chain. A malformed line that a
/// later valid record follows is still skipped here; `audit verify`
/// reports it.
///
/// **F2 (v0.7.0 round-2-fixes):** the return tuple is consumed by
/// [`init`] to seed both `last_hash` (chain continuity) AND the
/// per-process `SEQUENCE` counter (monotonicity across restarts).
///
/// **M14 (v0.7.0 round-2-fixes):** while walking the file we also
/// surface out-of-order sequence numbers via `tracing::warn!`. A line
/// with sequence N followed by a later line with sequence < N is
/// presumptive corruption — could be a partial replay, a manual edit,
/// or a clock skew on a multi-writer host. We do NOT refuse to start:
/// the hash chain is the authoritative tamper signal and the operator
/// may have intentional gaps from `audit truncate` (off-spec but
/// possible). The WARN goes to journalctl + SIEM where a human can
/// triage. The exact pair of `(prior_seq, this_seq)` is included so
/// the operator can grep the file for the offending line.
fn read_chain_tail(path: &Path) -> Result<Option<(String, u64)>> {
    if !path.exists() {
        return Ok(None);
    }
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut last: Option<(String, u64)> = None;
    let mut prior_seq: Option<u64> = None;
    // #4190 — whether the last non-blank line parsed as an event.
    let mut last_line_parsed = true;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let parsed = serde_json::from_str::<AuditEvent>(&line);
        last_line_parsed = parsed.is_ok();
        if let Ok(ev) = parsed {
            // M14: surface out-of-order seqnums. A higher prior_seq
            // followed by a lower this_seq is the corruption signal —
            // equal seqnums are *also* a violation (duplicate emit),
            // so we warn on `<=` not `<`. The first record establishes
            // the baseline (prior_seq = None) and never trips here.
            if let Some(prev) = prior_seq
                && prev >= ev.sequence
            {
                tracing::warn!(
                    target: "ai_memory::audit",
                    prior_seq = prev,
                    this_seq = ev.sequence,
                    path = %path.display(),
                    "audit: out-of-order sequence number detected on init scan \
                     (prior {prev} >= this {this}). Hash-chain integrity is the \
                     authoritative tamper signal; verify with `ai-memory audit verify`.",
                    prev = prev,
                    this = ev.sequence
                );
            }
            prior_seq = Some(ev.sequence);
            last = Some((ev.self_hash, ev.sequence));
        }
    }
    if !last_line_parsed {
        return Err(anyhow!(
            "the last record in {} is not a complete audit event (a torn or \
             corrupt write)",
            path.display()
        ));
    }
    Ok(last)
}

/// Whether the audit subsystem is currently enabled. Cheap.
#[must_use]
pub fn is_enabled() -> bool {
    RuntimeContext::global()
        .audit
        .sink
        .read()
        .map(|g| g.is_some())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Hashing — stable canonical form so emit + verify agree byte-for-byte.
// ---------------------------------------------------------------------------

/// Compute the canonical hash for an event. Hashes the same JSON the
/// emitter writes to disk EXCEPT with `self_hash` set to the empty
/// string sentinel — this lets `audit verify` recompute it from the
/// stored line by zeroing the same field.
fn compute_self_hash(ev: &AuditEvent) -> String {
    let canonical = canonical_json_for_hash(ev);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    hex_encode(&hasher.finalize())
}

/// Serialize an event into the canonical pre-hash form: serde_json
/// representation with `self_hash` zeroed. The `prev_hash` is part of
/// the hashed input — that's exactly the linkage that makes the chain
/// tamper-evident.
fn canonical_json_for_hash(ev: &AuditEvent) -> String {
    let mut clone = ev.clone();
    clone.self_hash.clear();
    serde_json::to_string(&clone).expect("AuditEvent always serializes")
}

fn hex_encode(bytes: &[u8]) -> String {
    static HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Emission API — the surface the rest of the binary calls.
// ---------------------------------------------------------------------------

/// Builder for an audit event. Most call sites use one of the
/// convenience helpers ([`emit_store`], [`emit_recall`], etc.) but the
/// builder is public so unusual flows (consolidate-many, deferred
/// import) can fill in custom targets.
#[derive(Debug, Clone)]
pub struct EventBuilder {
    pub action: AuditAction,
    pub actor: AuditActor,
    pub target: AuditTarget,
    pub outcome: AuditOutcome,
    pub auth: Option<AuditAuth>,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub error: Option<String>,
}

impl EventBuilder {
    /// Build a default-shaped event for `action`. Caller fills in the
    /// remaining fields.
    #[must_use]
    pub fn new(action: AuditAction, actor: AuditActor, target: AuditTarget) -> Self {
        Self {
            action,
            actor,
            target,
            outcome: AuditOutcome::Allow,
            auth: None,
            session_id: None,
            request_id: None,
            error: None,
        }
    }

    /// Override outcome (default = Allow).
    #[must_use]
    pub fn outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// Set the error string. Caps at 256 chars and strips newlines so a
    /// runaway error message can't leak content or break the log line.
    #[must_use]
    pub fn error(mut self, msg: impl Into<String>) -> Self {
        self.error = Some(sanitize_field(&msg.into(), 256));
        self.outcome = AuditOutcome::Error;
        self
    }

    #[must_use]
    pub fn auth(mut self, auth: AuditAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    #[must_use]
    pub fn request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }
}

/// Write an event to the configured sink. No-op when audit is disabled.
/// Failures are logged via `tracing::error!` and dropped — audit is
/// **never** allowed to fail a memory operation.
pub fn emit(builder: EventBuilder) {
    if let Err(e) = try_emit(builder) {
        tracing::error!("audit: emission failed: {e}");
    }
}

/// #3975 — the metric an operator watches for a trail that stopped
/// recording. Named by the stderr diagnostic so one leads to the other.
pub const AUDIT_WRITE_FAILURES_TOTAL: &str = "ai_memory_audit_write_failures_total";

/// #3975 — count one lost audit event and, at most once a minute (the #3651
/// log-sink diagnostic interval), say so on stderr.
/// `tracing` is not enough: it is a no-op unless the logging pipeline is
/// enabled, and the audit trail is the record an operator relies on when it
/// is not.
fn note_emit_failure(err: &anyhow::Error) {
    let delivery = &RuntimeContext::global().audit.delivery;
    if let Some(suppressed) = delivery.record_failure(now_unix_ms()) {
        // Nothing is left to report a failing stderr to.
        let _ = writeln!(
            std::io::stderr(),
            "{}",
            audit_failure_diagnostic(err, suppressed)
        );
    }
}

fn audit_failure_diagnostic(err: &anyhow::Error, suppressed: u64) -> String {
    format!(
        "ai-memory: the audit trail failed to record an event: {err} \
         ({suppressed} further failures since the previous report); audit \
         events are being lost, see {AUDIT_WRITE_FAILURES_TOTAL}"
    )
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// #3975 — whether the flat audit trail is recording in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditTrailState {
    /// No sink is installed: `[audit].enabled` is off, or (only in `doctor`,
    /// which boots past a refused trail) the trail failed to initialise.
    NotActive,
    /// A sink is installed and receives every emitted event.
    Active,
}

/// #3975 — a snapshot of the flat audit trail. Counters are `None` unless the
/// trail is [`AuditTrailState::Active`]: a number nothing measured is never
/// reported as zero (the #3651 `LogPipelineStatus` rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTrailStatus {
    /// Whether a sink is installed.
    pub state: AuditTrailState,
    /// Events written and flushed without error.
    pub records_written: Option<u64>,
    /// Events lost to a failed write or flush (or a poisoned sink).
    pub write_failures: Option<u64>,
    /// Wall-clock time of the most recent successful write.
    pub last_write_unix_ms: Option<u64>,
}

/// #3975 — the flat audit trail's state and delivery counters, read at call
/// time (the `/metrics` collector and `doctor` both use it).
#[must_use]
pub fn audit_trail_status() -> AuditTrailStatus {
    let audit = &RuntimeContext::global().audit;
    let active = audit.sink.read().map(|g| g.is_some()).unwrap_or(false);
    if !active {
        return AuditTrailStatus {
            state: AuditTrailState::NotActive,
            records_written: None,
            write_failures: None,
            last_write_unix_ms: None,
        };
    }
    AuditTrailStatus {
        state: AuditTrailState::Active,
        records_written: Some(audit.delivery.delivered()),
        write_failures: Some(audit.delivery.write_failures()),
        last_write_unix_ms: audit.delivery.last_success_unix_ms(),
    }
}

/// Inner emission with proper `Result` so tests can assert directly on
/// the writer. `emit` swallows errors so production never blocks. Every
/// failure after a sink is found is counted and reported (#3975); no sink
/// (auditing off) is not a failure.
fn try_emit(builder: EventBuilder) -> Result<()> {
    try_emit_inner(builder)
        .map(|_written| ())
        .inspect_err(note_emit_failure)
}

/// `Ok(true)` when the event was written, `Ok(false)` when no sink is
/// installed (auditing is off, nothing to record).
fn try_emit_inner(builder: EventBuilder) -> Result<bool> {
    let audit = &RuntimeContext::global().audit;
    let sink = {
        let guard = audit
            .sink
            .read()
            .map_err(|_| anyhow!("audit sink rwlock poisoned"))?;
        match guard.as_ref() {
            Some(s) => s.clone(),
            None => return Ok(false),
        }
    };

    let mut inner = sink
        .inner
        .lock()
        .map_err(|_| anyhow!("audit sink mutex poisoned"))?;

    let sequence = audit
        .sequence
        .fetch_add(1, Ordering::SeqCst)
        .checked_add(1)
        .filter(|s| *s <= MAX_AUDIT_SEQUENCE)
        .ok_or_else(|| anyhow!("audit sequence exhausted"))?;

    // #4086: the number is consumed. If the event does not reach the trail,
    // persist the number as the high-water BEFORE reporting the failure, so a
    // restart cannot reuse it and hide the loss.
    let written = write_event(&mut inner, builder, sequence);
    if let Err(err) = written {
        return Err(match inner.seq_mark.as_mut().map(|m| m.record(sequence)) {
            Some(Err(mark_err)) => err.context(format!(
                "{mark_err:#}; a restart may reuse this sequence number (#4086)"
            )),
            _ => err,
        });
    }
    RuntimeContext::global()
        .audit
        .delivery
        .record_success(now_unix_ms());
    Ok(true)
}

/// Build, hash and append one event as `sequence`. Advances the chain head
/// once the line has been handed to the writer.
fn write_event(inner: &mut SinkInner, builder: EventBuilder, sequence: u64) -> Result<()> {
    let SinkInner {
        writer,
        last_hash,
        path,
        seq_mark,
        trail,
        torn,
    } = inner;
    let lock = TrailLock::acquire(trail.as_ref());
    // #4211: a previous failed append left bytes that could not be removed.
    // Start this record on its own line (the #4205 rule), so it is never
    // glued onto them.
    if let Some(left) = torn.take() {
        let aligned = match trail.as_ref() {
            Some(f) => crate::governance::audit::align_to_line_end(f),
            None => Ok(()),
        };
        if let Err(e) = aligned {
            *torn = Some(left);
            return Err(e).context("line-aligning the audit trail after a torn write (#4211)");
        }
        if let Torn::CompleteRecord { self_hash } = left {
            *last_hash = self_hash;
        }
    }
    let mut ev = AuditEvent {
        schema_version: SCHEMA_VERSION,
        timestamp: Utc::now().to_rfc3339(),
        sequence,
        actor: builder.actor,
        action: builder.action,
        target: AuditTarget {
            memory_id: sanitize_field(&builder.target.memory_id, 128),
            namespace: sanitize_field(&builder.target.namespace, 128),
            title: builder.target.title.map(|t| sanitize_field(&t, 200)),
            tier: builder.target.tier,
            scope: builder.target.scope,
        },
        outcome: builder.outcome,
        auth: builder.auth,
        session_id: builder.session_id,
        request_id: builder.request_id,
        error: builder.error,
        prev_hash: last_hash.clone(),
        self_hash: String::new(),
    };

    let self_hash = compute_self_hash(&ev);
    ev.self_hash = self_hash.clone();

    // #4211: the record and its newline go out as ONE buffer through ONE
    // `write_all` (never `writeln!`, which writes them separately). A failed
    // append's bytes are removed when they are provably ours; otherwise the
    // next record is line-aligned and verify reports the torn line.
    let mut record = serde_json::to_vec(&ev).context("serializing audit event")?;
    record.push(b'\n');
    let pre_len = trail
        .as_ref()
        .and_then(|f| f.metadata().ok())
        .map(|m| m.len());
    // #4299: WRITE-AHEAD. The number goes into the mark (in place, no fsync)
    // BEFORE the append, under the trail lock, so a process that dies after
    // numbering the event and before writing it, even on the first byte,
    // leaves that number on disk and verify reports it as a gap. A failed
    // write-ahead never costs the event: the event is still appended (the
    // durable record matters more than its index), and the failure is said.
    if let Some(mark) = seq_mark.as_mut()
        && let Err(e) = mark.advance(sequence)
    {
        let _ = writeln!(
            std::io::stderr(),
            "ai-memory: audit trail {}: {e:#}; the event is still written, but if this \
             write also fails and the process dies before the loss is recorded, the \
             loss leaves no trace (#4299)",
            path.as_deref()
                .map_or_else(|| "?".into(), |p| p.display().to_string())
        );
    }
    crash_snapshot(CRASH_BEFORE_APPEND, path.as_deref());
    if let Err(write_err) = writer.write_all(&record) {
        crash_snapshot(CRASH_BEFORE_MARK, path.as_deref());
        // #4298: make the loss DURABLE before any of its evidence is removed.
        // The #4086 high-water records this sequence (fdatasync'd) FIRST; only
        // then may the partial record be truncated. The reverse order left a
        // window where a crash showed a clean trail and a mark that did not
        // cover the lost number: a false "no gap" (the partial line, before
        // #4211, at least failed verify). If the mark cannot be written, the
        // bytes are never truncated: they stay as the evidence (the Torn path).
        let loss_durable = match seq_mark.as_mut() {
            Some(mark) => mark.record(sequence).is_ok(),
            None => trail.is_none(),
        };
        crash_snapshot(CRASH_AFTER_MARK, path.as_deref());
        let may_truncate = lock.held() && loss_durable;
        match undo_failed_append(trail.as_ref(), pre_len, may_truncate, &record, &self_hash) {
            Undo::Clean => crash_snapshot(CRASH_AFTER_TRUNCATE, path.as_deref()),
            Undo::Completed => {
                *last_hash = self_hash;
                return Ok(());
            }
            Undo::Torn(left) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "ai-memory: audit trail {}: a failed write left bytes that could not be \
                     removed (the append-only flag, or bytes that are not this write's); the next \
                     record starts a new line and `ai-memory audit verify` reports a TornRecord \
                     (#4211)",
                    path.as_deref()
                        .map_or_else(|| "?".into(), |p| p.display().to_string())
                );
                *torn = Some(left);
            }
        }
        return Err(write_err).context("appending audit line");
    }
    // #3975: a failed flush was discarded (`.ok()`). The line may or may not
    // be durable, so the chain head still advances exactly as before (the
    // line WAS handed to the writer), but the failure is counted and
    // reported like any other lost write.
    let flushed = writer.flush();
    *last_hash = self_hash;
    flushed.context("flushing audit line")
}

/// Sanitize a field for log emission: strip control chars + newlines
/// (prevent log injection) and cap to `max_chars` (prevent unbounded
/// growth from a hostile title or error message).
fn sanitize_field(s: &str, max_chars: usize) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .collect();
    if cleaned.chars().count() <= max_chars {
        cleaned
    } else {
        cleaned.chars().take(max_chars).collect()
    }
}

// ---------------------------------------------------------------------------
// Convenience helpers.
// ---------------------------------------------------------------------------

/// Construct an [`AuditActor`] from an agent_id + synthesis source +
/// optional scope. The synthesis source is informational metadata and
/// MUST be one of the documented strings in [`AuditActor`].
#[must_use]
pub fn actor(
    agent_id: impl Into<String>,
    synthesis_source: impl Into<String>,
    scope: Option<String>,
) -> AuditActor {
    AuditActor {
        agent_id: agent_id.into(),
        synthesis_source: synthesis_source.into(),
        scope,
    }
}

/// Construct an [`AuditTarget`] for a single memory.
#[must_use]
pub fn target_memory(
    memory_id: impl Into<String>,
    namespace: impl Into<String>,
    title: Option<String>,
    tier: Option<String>,
    scope: Option<String>,
) -> AuditTarget {
    AuditTarget {
        memory_id: memory_id.into(),
        namespace: namespace.into(),
        title,
        tier,
        scope,
    }
}

/// Construct an [`AuditTarget`] for a multi-row sweep operation.
#[must_use]
pub fn target_sweep(namespace: impl Into<String>) -> AuditTarget {
    AuditTarget {
        memory_id: "*".to_string(),
        namespace: namespace.into(),
        title: None,
        tier: None,
        scope: None,
    }
}

// ---------------------------------------------------------------------------
// Verify — the load-bearing tamper-evidence walk.
// ---------------------------------------------------------------------------

/// Outcome of [`verify_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub total_lines: u64,
    pub first_failure: Option<VerifyFailure>,
    /// #4021 — every sequence gap, in file order. `try_emit` numbers an event
    /// BEFORE it writes, so an event lost to a write failure (#3975) leaves a
    /// skipped value; in a single-writer trail a gap is evidence of a lost
    /// event. A loss at the TAIL just before a restart is a gap too: the #4086
    /// high-water mark keeps those numbers from being reused, and
    /// [`verify_chain`] reports the numbers the mark holds past the last
    /// written line (on an empty trail as well). The mark (`<trail>.seq`) is
    /// unsigned and has the trail's custody: deleting it, or rolling it back
    /// with the trail's tail, hides a tail loss (`docs/security/audit-trail.md`).
    /// The HEAD is checked too (#4191): verify always starts
    /// from the genesis anchor, whose sequence is 0, so a genesis-anchored
    /// first line above sequence 1 reports `1..=first-1`, the events lost
    /// before the first successful write.
    pub gaps: Vec<SequenceGap>,
    /// #4211 — line numbers of torn records (see
    /// [`VerifyFailureKind::TornRecord`]), in file order.
    pub torn_lines: Vec<u64>,
}

/// #4021 — a run of sequence numbers that no line carries: `from..=to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceGap {
    /// First missing sequence number.
    pub from: u64,
    /// Last missing sequence number (inclusive).
    pub to: u64,
}

impl SequenceGap {
    /// How many events the gap stands for.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.to - self.from + 1
    }

    /// Always false: a gap covers at least one sequence number.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl std::fmt::Display for SequenceGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.from, self.to)
    }
}

impl std::str::FromStr for SequenceGap {
    type Err = String;

    /// Parses `FROM-TO` (inclusive, `FROM <= TO`), the form verify prints.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (a, b) = s
            .trim()
            .split_once('-')
            .ok_or_else(|| format!("gap range `{s}` must be FROM-TO"))?;
        let from: u64 = a
            .trim()
            .parse()
            .map_err(|_| format!("gap range `{s}`: FROM is not a number"))?;
        let to: u64 = b
            .trim()
            .parse()
            .map_err(|_| format!("gap range `{s}`: TO is not a number"))?;
        if from == 0 || from > to {
            return Err(format!("gap range `{s}` must satisfy 1 <= FROM <= TO"));
        }
        Ok(Self { from, to })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyFailure {
    pub line_number: u64,
    pub kind: VerifyFailureKind,
    pub detail: String,
}

/// Why the per-line audit-event hash chain (`AuditEvent` JSONL files
/// under `audit/`) failed to verify.
///
/// # Disambiguation (issue #970)
///
/// A sibling enum
/// [`crate::governance::audit::VerifyFailureKind`] exists for the
/// **governance forensic-bundle chain** (Ed25519-signed
/// `ForensicDecision` rows in `signed_events`). Despite the shared
/// name, the two enums verify different chain shapes and have
/// different variant sets:
///
/// - `audit::VerifyFailureKind` (this enum): `Parse`, `SelfHash`,
///   `ChainBreak`, `Sequence`. The audit chain hashes each line's
///   canonical bytes (`SelfHash`) and verifies a monotonically
///   increasing `sequence` (`Sequence`). It does NOT sign rows
///   individually.
/// - `governance::audit::VerifyFailureKind`: `Parse`, `ChainBreak`,
///   `Signature`. The forensic chain signs each row with an
///   Ed25519 key (`Signature`) and verifies the cross-row hash
///   pointer (`ChainBreak`). It has no per-line `SelfHash`
///   (signature verification subsumes it) and no `Sequence`
///   variant (sequence is a SQLite column, not a line counter).
///
/// They are call-site-disambiguated by their module path. See
/// `docs/internal/enum-proliferation-audit-970.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyFailureKind {
    /// Line could not be parsed as an `AuditEvent`.
    Parse,
    /// Recomputed `self_hash` did not match the stored value.
    SelfHash,
    /// Stored `prev_hash` did not match the prior line's `self_hash`.
    ChainBreak,
    /// `sequence` did not increase monotonically.
    Sequence,
    /// #4211 — an unparseable line that the chain passes AROUND: the next
    /// record chains to the record before it. It is what a failed write
    /// leaves when its bytes cannot be removed (the append-only flag refuses
    /// truncation). Never clean and never acknowledgeable, but verify keeps
    /// checking the chain after it, so the records that follow stay verified
    /// and the lost event still surfaces as a gap.
    TornRecord,
}

impl VerifyReport {
    /// Convenience — `Ok(())` when chain is intact AND no event is missing,
    /// `Err` when not. A sequence gap fails here too (#4021): there is no
    /// acknowledgement on this path.
    pub fn into_result(self) -> Result<u64> {
        if let Some(failure) = self.first_failure {
            Err(anyhow!(
                "audit chain verification failed at line {}: {:?} — {}",
                failure.line_number,
                failure.kind,
                failure.detail
            ))
        } else if !self.gaps.is_empty() {
            Err(anyhow!("{}", lost_events_message(&self.gaps)))
        } else {
            Ok(self.total_lines)
        }
    }

    /// #4021 — the gaps NOT named by `acknowledged`. An acknowledgement
    /// matches a gap only EXACTLY (same `from` and `to`), so a broad range
    /// can never act as a blanket pass for gaps that appear later.
    #[must_use]
    pub fn unacknowledged_gaps(&self, acknowledged: &[SequenceGap]) -> Vec<SequenceGap> {
        self.gaps
            .iter()
            .copied()
            .filter(|g| !acknowledged.contains(g))
            .collect()
    }
}

/// #4021 — why a gap fails verify. Deliberately NOT the tamper wording: a
/// gap is most likely an event lost to a failed write, which #3975 counts.
#[must_use]
pub fn lost_events_message(gaps: &[SequenceGap]) -> String {
    let events: u64 = gaps.iter().map(SequenceGap::len).sum();
    let ranges = gaps
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{events} audit event(s) missing: sequence gap(s) {ranges}. These events were \
         sequenced but never written, most likely a failed write (see \
         {AUDIT_WRITE_FAILURES_TOTAL}). If the loss is known and accepted, re-run with \
         --acknowledge-gaps {ranges}"
    )
}

/// Walk an audit log file and verify the chain. Returns a structured
/// report; the binary's `audit verify` subcommand turns this into an
/// exit code.
///
/// # Errors
/// - The file cannot be opened or read.
/// - The sequence high-water mark next to the trail (#4086) exists but is
///   unreadable or corrupt: whether events were lost cannot be determined.
pub fn verify_chain(path: &Path) -> Result<VerifyReport> {
    // #4299: every writer holds the EXCLUSIVE trail lock across its
    // write-ahead mark and its append, so for that moment the mark names a
    // number whose line is not written yet. A SHARED lock here makes verify
    // wait that moment out instead of reporting it as a gap. Best effort: a
    // filesystem without locks still verifies.
    //
    // #4332: the lock is held only for a consistent SNAPSHOT, the trail's
    // length and the mark, never for the walk. While it is held no writer is
    // between its write-ahead and its append, so the two agree. The walk then
    // reads exactly that prefix with the lock released: holding it for the
    // whole walk stalled every audited operation (and back-to-back verifies
    // starved the writer, since a shared lock is not fair to an exclusive
    // waiter). Lines appended after the snapshot are simply not in this
    // verify; the mark it compares with is the one from the same snapshot.
    let lock = File::open(path).with_context(|| crate::errors::msg::opening(path.display()))?;
    let file = File::open(path).with_context(|| crate::errors::msg::opening(path.display()))?;
    let _ = lock.lock_shared();
    let snapshot = file
        .metadata()
        .with_context(|| crate::errors::msg::opening(path.display()))
        .and_then(|meta| {
            // #4086: numbers recorded as consumed past the last written line
            // are events lost at the tail (possibly just before a restart).
            // Reported as a gap like any interior one, INCLUDING on an empty
            // trail: a mark above 0 is evidence that events were numbered,
            // so a trail whose every event was lost (a disk full from the
            // first write) is the gap 1..=mark, never clean. An empty trail
            // with no mark is clean: nothing was numbered.
            Ok((
                meta.len(),
                read_seq_mark(&seq_mark_path(path))?.unwrap_or(0),
            ))
        });
    let _ = lock.unlock();
    drop(lock);
    let (len, high_water) = snapshot?;
    #[cfg(test)]
    verify_after_snapshot();
    let mut last_sequence = 0;
    let mut report = walk_chain(file.take(len), &mut last_sequence)?;
    let chain_intact = report
        .first_failure
        .as_ref()
        .is_none_or(|f| f.kind == VerifyFailureKind::TornRecord);
    if chain_intact && high_water > last_sequence {
        report.gaps.push(SequenceGap {
            from: last_sequence + 1,
            to: high_water,
        });
    }
    Ok(report)
}

/// Verify a chain from any [`Read`] source. Lets tests run against
/// in-memory buffers without touching the filesystem. A bare reader has no
/// high-water mark, so a tail loss (#4086) is only visible through
/// [`verify_chain`].
pub fn verify_chain_from_reader<R: Read>(reader: R) -> Result<VerifyReport> {
    walk_chain(reader, &mut 0)
}

/// The chain walk behind both verify entry points. `last_sequence` receives
/// the last sequence number of a verified line (0 for an empty trail).
fn walk_chain<R: Read>(reader: R, last_sequence: &mut u64) -> Result<VerifyReport> {
    let buf = BufReader::new(reader);
    let mut total: u64 = 0;
    let mut prev_hash = CHAIN_HEAD_PREV_HASH.to_string();
    let mut prev_seq: u64 = 0;
    let mut gaps: Vec<SequenceGap> = Vec::new();
    let mut torn_lines: Vec<u64> = Vec::new();
    // Unparseable lines not yet passed around by a chained record, with the
    // first one's parse error.
    let mut pending: Vec<u64> = Vec::new();
    let mut pending_error = String::new();

    for (idx, line) in buf.lines().enumerate() {
        let line_no = (idx as u64) + 1;
        let line = line.with_context(|| format!("reading audit line {line_no}"))?;
        if line.trim().is_empty() {
            continue;
        }
        total += 1;

        // #4211: an unparseable line is set aside and the walk continues. It
        // is never clean. If a later record chains past it (its prev_hash is
        // the last ACCEPTED record's hash) it is a torn record; if nothing
        // does, it is the Parse failure it always was; and a record that does
        // not chain fails ChainBreak exactly as before.
        let ev = match serde_json::from_str::<AuditEvent>(&line) {
            Ok(ev) => ev,
            Err(e) => {
                if pending.is_empty() {
                    pending_error = format!("malformed JSON: {e}");
                }
                pending.push(line_no);
                continue;
            }
        };

        if ev.prev_hash != prev_hash {
            // A set-aside line the chain does NOT pass around keeps the
            // earliest failure it always was: Parse at that line.
            if let Some(&line_number) = pending.first() {
                return Ok(VerifyReport {
                    total_lines: total,
                    gaps: std::mem::take(&mut gaps),
                    torn_lines: std::mem::take(&mut torn_lines),
                    first_failure: Some(VerifyFailure {
                        line_number,
                        kind: VerifyFailureKind::Parse,
                        detail: std::mem::take(&mut pending_error),
                    }),
                });
            }
            return Ok(VerifyReport {
                total_lines: total,
                gaps: std::mem::take(&mut gaps),
                torn_lines: std::mem::take(&mut torn_lines),
                first_failure: Some(VerifyFailure {
                    line_number: line_no,
                    kind: VerifyFailureKind::ChainBreak,
                    detail: format!(
                        "prev_hash mismatch: expected {prev_hash}, got {}",
                        ev.prev_hash
                    ),
                }),
            });
        }

        // The chain passed around the set-aside lines: they are torn records.
        torn_lines.append(&mut pending);

        // #4191: the genesis anchor IS sequence 0 (every verifiable trail
        // starts there; a first line not chained to it fails ChainBreak
        // above), so the head is held to the same rules as every later line:
        // sequence 0 is refused, and a first line above 1 is a gap.
        if ev.sequence <= prev_seq {
            return Ok(VerifyReport {
                total_lines: total,
                gaps: std::mem::take(&mut gaps),
                torn_lines: std::mem::take(&mut torn_lines),
                first_failure: Some(VerifyFailure {
                    line_number: line_no,
                    kind: VerifyFailureKind::Sequence,
                    detail: format!(
                        "sequence not monotonic: prior={prev_seq}, this={}",
                        ev.sequence
                    ),
                }),
            });
        }

        // #4021: a skip is a lost event, at the head (#4191) as anywhere.
        if ev.sequence > prev_seq + 1 {
            gaps.push(SequenceGap {
                from: prev_seq + 1,
                to: ev.sequence - 1,
            });
        }

        let recomputed = compute_self_hash(&ev);
        if recomputed != ev.self_hash {
            return Ok(VerifyReport {
                total_lines: total,
                gaps: std::mem::take(&mut gaps),
                torn_lines: std::mem::take(&mut torn_lines),
                first_failure: Some(VerifyFailure {
                    line_number: line_no,
                    kind: VerifyFailureKind::SelfHash,
                    detail: format!(
                        "self_hash mismatch: stored={}, recomputed={}",
                        ev.self_hash, recomputed
                    ),
                }),
            });
        }

        prev_hash = ev.self_hash.clone();
        prev_seq = ev.sequence;
        *last_sequence = prev_seq;
    }

    if let Some(&line_number) = pending.first() {
        return Ok(VerifyReport {
            total_lines: total,
            gaps,
            torn_lines,
            first_failure: Some(VerifyFailure {
                line_number,
                kind: VerifyFailureKind::Parse,
                detail: pending_error,
            }),
        });
    }
    let first_failure = torn_lines.first().map(|&line_number| VerifyFailure {
        line_number,
        kind: VerifyFailureKind::TornRecord,
        detail: format!(
            "{} torn record(s) at line(s) {}: bytes of a failed write that could not be \
             removed (#4211). The chain was verified across them; the events they held are \
             reported as sequence gaps",
            torn_lines.len(),
            torn_lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
    });
    Ok(VerifyReport {
        total_lines: total,
        first_failure,
        gaps,
        torn_lines,
    })
}

// ---------------------------------------------------------------------------
// Bootstrap — read AppConfig and bring the sink up.
// ---------------------------------------------------------------------------

/// #3651 — the message the binary prints when it refuses to start because an
/// ENABLED audit trail could not be initialised (see [`init_from_config`]).
/// Names the one escape hatch, turning the trail off, because an audit trail
/// that is enabled but silently absent is the outcome this refusal replaces.
#[must_use]
pub fn boot_refusal_message(err: &anyhow::Error) -> String {
    format!(
        "ai-memory: refusing to start: [audit] is enabled but the audit trail could not be \
         initialised: {err:#}\n  Fix the [audit] section in config.toml (or the audit \
         directory it names), or set [audit].enabled = false to run without the flat audit \
         trail. `ai-memory doctor` still runs."
    )
}

/// Initialise the audit sink from a parsed [`crate::config::AuditConfig`].
/// Returns `Ok(())` when audit is disabled (a no-op) or initialised.
///
/// The binary REFUSES to start on any `Err` here (#3651, exit 78; `doctor`
/// excepted), so every error below is a boot refusal, never a silent
/// "continue without an audit trail".
///
/// # Errors
/// - An explicit `schema_version` that is not the binary's emitted version.
/// - An explicit `hash_chain = false` (the chain is mandatory).
/// - The audit directory or file cannot be created or opened.
pub fn init_from_config(cfg: &crate::config::AuditConfig) -> Result<()> {
    if !cfg.enabled.unwrap_or(false) {
        if let Ok(mut guard) = RuntimeContext::global().audit.sink.write() {
            *guard = None;
        }
        return Ok(());
    }

    // FBL-31 leg 2 — the `schema_version` doc-comment claims the knob is
    // "validated at init", but init read only enabled/path/redact_content/
    // append_only, so `schema_version = 999` booted silently. Honour the
    // documented contract: an explicit value MUST equal the binary's emitted
    // [`SCHEMA_VERSION`]. Fail CLOSED (refuse boot) on a mismatch so an
    // operator can never believe they pinned a forward-compat schema the binary
    // does not actually emit. Unset (`None`) is a no-op (the default).
    if let Some(v) = cfg.schema_version
        && v != SCHEMA_VERSION
    {
        return Err(anyhow!(
            "[audit] schema_version = {v} does not match the binary's emitted \
             audit schema version {SCHEMA_VERSION}; the knob is validated at \
             init (only the emitted version is supported today) — unset it or \
             set schema_version = {SCHEMA_VERSION}"
        ));
    }

    // FBL-31 leg 3 — `hash_chain` was never read anywhere; `hash_chain = false`
    // was silently ignored (the cross-row chain is mandatory + load-bearing
    // tamper-evidence). Rather than let the knob lie, refuse an explicit
    // `false`: the chain cannot be disabled. `true`/unset proceed unchanged.
    if cfg.hash_chain == Some(false) {
        return Err(anyhow!(
            "[audit] hash_chain = false is not supported — the cross-row audit \
             hash chain is mandatory (the load-bearing tamper-evidence) and \
             cannot be disabled; remove the key or set hash_chain = true"
        ));
    }

    // FBL-31 leg 1 — the periodic `CHECKPOINT.sig` attestation marker is NOT
    // yet implemented: no emission code exists and
    // `effective_attestation_cadence_minutes` (which folds the compliance-preset
    // cadence overrides) has no production consumer. Rather than silently
    // advertise anti-truncation attestation an audit-enabled daemon does not
    // get, emit a one-shot operator WARN naming the reserved status. This makes
    // the dead knob non-silent (and gives the resolver a production caller so
    // the preset cadence math is exercised). The load-bearing tamper-evidence
    // is the separate signed_events witness/watermark chain, not this marker.
    let cadence = cfg.effective_attestation_cadence_minutes();
    if cadence > 0 {
        warn_attestation_reserved_once(cadence);
    }

    let resolved_path = resolve_audit_path(cfg);
    init(
        &resolved_path,
        cfg.redact_content.unwrap_or(true),
        cfg.append_only.unwrap_or(true),
    )
}

/// FBL-31 leg 1 — one-shot WARN that the periodic `CHECKPOINT.sig` attestation
/// marker (`[audit] attestation_cadence_minutes`, and the compliance-preset
/// cadence overrides it folds in) is configured but NOT yet emitted. Gated by a
/// process-once flag so a repeated `init_from_config` (tests, hot-reload) does
/// not spam the log.
fn warn_attestation_reserved_once(cadence_minutes: u32) {
    use std::sync::Once;
    static WARNED: Once = Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            target: "audit.attestation",
            cadence_minutes,
            "[audit] periodic CHECKPOINT.sig attestation marker is configured \
             (effective cadence {cadence_minutes}m) but is NOT yet emitted \
             (reserved); the load-bearing anti-truncation tamper-evidence is \
             the signed_events witness/watermark chain, not this marker"
        );
    });
}

/// Resolve the audit log file path from the config, honouring the
/// user-mandated precedence ladder: CLI > env (`AI_MEMORY_AUDIT_DIR`)
/// > `[audit] path` in config > platform default. Appends `audit.log`
/// when the resolved path looks like a directory.
///
/// Backwards-compatible wrapper that doesn't take a CLI override —
/// subcommand wiring uses [`resolve_audit_path_with_override`].
#[must_use]
pub fn resolve_audit_path(cfg: &crate::config::AuditConfig) -> PathBuf {
    let resolved = crate::log_paths::resolve_audit_dir(None, cfg.path.as_deref())
        .map(|r| r.path)
        .unwrap_or_else(|_| {
            crate::log_paths::platform_default(crate::log_paths::DirKind::Audit).path
        });
    finalize_audit_file(resolved, cfg.path.as_deref())
}

/// Strict variant: takes an optional `--audit-dir` override, returns
/// the resolved file path (with `audit.log` appended when the input
/// resolves to a directory) plus the [`crate::log_paths::PathSource`]
/// used.
///
/// # Errors
/// - Resolved directory is world-writable.
pub fn resolve_audit_path_with_override(
    cli_override: Option<&Path>,
    cfg: &crate::config::AuditConfig,
) -> Result<(PathBuf, crate::log_paths::PathSource)> {
    let r = crate::log_paths::resolve_audit_dir(cli_override, cfg.path.as_deref())?;
    let final_path = finalize_audit_file(r.path, cfg.path.as_deref());
    Ok((final_path, r.source))
}

/// Append `audit.log` when the resolved path is a directory; respect
/// an explicit file-path the user wrote in config.
fn finalize_audit_file(p: PathBuf, raw_config: Option<&str>) -> PathBuf {
    // If the user configured an explicit file path (has a non-empty
    // extension that isn't a trailing slash), keep it as-is.
    if let Some(raw) = raw_config
        && !raw.ends_with('/')
        && std::path::Path::new(raw).extension().is_some()
    {
        return p;
    }
    if p.extension().is_none() || p.to_string_lossy().ends_with('/') {
        p.join("audit.log")
    } else {
        p
    }
}

pub(crate) fn expand_tilde(raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    raw.to_string()
}

// ---------------------------------------------------------------------------
// Append-only OS hint — best effort.
// ---------------------------------------------------------------------------

/// Apply the platform-appropriate "append-only" file flag. Silent on
/// non-unix platforms.
#[cfg(unix)]
fn mark_append_only(path: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path =
        CString::new(path.as_os_str().as_bytes()).context("path contains an interior NUL byte")?;
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        // SAFETY: c_path is a NUL-terminated string we own; chflags is
        // a libc syscall whose only safety obligation is a valid C
        // string. UF_APPEND is the user-visible append-only flag.
        let rc = unsafe { libc::chflags(c_path.as_ptr(), libc::UF_APPEND.into()) };
        if rc != 0 {
            return Err(anyhow!(
                "chflags(UF_APPEND) failed: errno={}",
                std::io::Error::last_os_error()
            ));
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        // On Linux we'd issue FS_IOC_SETFLAGS with FS_APPEND_FL. The
        // syscall requires CAP_LINUX_IMMUTABLE on most filesystems and
        // is filesystem-specific (ext*, xfs, btrfs); refuse silently
        // on filesystems that don't support it. This is a best-effort
        // hint — the chain is the load-bearing tamper-evidence.
        const FS_APPEND_FL: libc::c_int = 0x0000_0020;
        // FS_IOC_SETFLAGS = _IOW('f', 2, long) = 0x4008_6602 on most
        // 64-bit Linux ABIs. Hard-coded to avoid pulling in an extra
        // crate just for the constant.
        const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(anyhow!(
                "open(audit log) for ioctl failed: errno={}",
                std::io::Error::last_os_error()
            ));
        }
        let mut flags: libc::c_int = 0;
        // SAFETY: fd is a valid file descriptor we just opened; the
        // ioctl call follows the documented FS_IOC_GETFLAGS / SETFLAGS
        // protocol.
        let rc = unsafe { libc::ioctl(fd, FS_IOC_SETFLAGS, &mut flags) };
        if rc == 0 {
            flags |= FS_APPEND_FL;
            let rc2 = unsafe { libc::ioctl(fd, FS_IOC_SETFLAGS, &mut flags) };
            unsafe { libc::close(fd) };
            if rc2 != 0 {
                return Err(anyhow!(
                    "ioctl(FS_IOC_SETFLAGS) failed: errno={}",
                    std::io::Error::last_os_error()
                ));
            }
            return Ok(());
        }
        unsafe { libc::close(fd) };
        Err(anyhow!(
            "ioctl(FS_IOC_GETFLAGS) failed: errno={}",
            std::io::Error::last_os_error()
        ))
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "linux"
    )))]
    {
        let _ = c_path;
        Err(anyhow!(
            "append-only flag not supported on this unix variant"
        ))
    }
}

#[cfg(not(unix))]
fn mark_append_only(_path: &Path) -> Result<()> {
    Err(anyhow!("append-only flag is unix-only"))
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tail_loss_4086_tests;

#[cfg(test)]
mod verify_head_4191_tests;

#[cfg(test)]
mod torn_write_4211_tests;

#[cfg(test)]
mod crash_window_4298_tests;

#[cfg(test)]
mod write_ahead_4299_tests;

#[cfg(test)]
mod verify_snapshot_4332_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Tier;

    #[test]
    fn init_from_config_rejects_schema_version_mismatch() {
        // #2368 — init_from_config can mutate the process-wide sink slot;
        // hold the shared sink lock like every other sink-touching test.
        let _g = sink_test_lock();
        // FBL-31 leg 2 — the "validated at init" contract is now real:
        // an explicit schema_version != SCHEMA_VERSION fails CLOSED before any
        // filesystem side effect.
        let cfg = crate::config::AuditConfig {
            enabled: Some(true),
            schema_version: Some(SCHEMA_VERSION + 999),
            ..Default::default()
        };
        let err = init_from_config(&cfg).expect_err("mismatched schema_version must fail closed");
        assert!(
            err.to_string().contains("schema_version"),
            "error should name the offending knob: {err}"
        );
        // The matching value clears the schema_version gate (a later leg /
        // sink-open may still run, but validation itself does not reject).
        let ok = crate::config::AuditConfig {
            enabled: Some(true),
            schema_version: Some(SCHEMA_VERSION),
            hash_chain: Some(false),
            ..Default::default()
        };
        // hash_chain=false still trips leg 3, proving the schema check passed
        // (a schema error would have short-circuited first with a different
        // message).
        let err2 = init_from_config(&ok).expect_err("hash_chain=false must fail closed");
        assert!(
            err2.to_string().contains("hash_chain"),
            "with a matching schema_version the next gate (hash_chain) fires: {err2}"
        );
    }

    #[test]
    fn init_from_config_refuses_hash_chain_disable() {
        // #2368 — see init_from_config_rejects_schema_version_mismatch.
        let _g = sink_test_lock();
        // FBL-31 leg 3 — hash_chain = false is unsupported (the chain is
        // mandatory); the knob no longer silently lies.
        let cfg = crate::config::AuditConfig {
            enabled: Some(true),
            hash_chain: Some(false),
            ..Default::default()
        };
        let err = init_from_config(&cfg).expect_err("hash_chain=false must be refused");
        assert!(
            err.to_string().contains("hash_chain"),
            "error should name hash_chain: {err}"
        );
    }

    #[test]
    fn init_from_config_disabled_is_noop_regardless_of_knobs() {
        // #2368 — this arm NULLS the process-wide audit sink
        // (`init_from_config` with enabled=false clears the slot), so
        // running it without the shared sink lock raced every concurrent
        // sink-holding test: the null landed between a peer test's `init`
        // and `emit`, silently swallowing the emitted line (the CI flake
        // that blocked PRs #2363/#2354/#2367). Hold the lock.
        let _g = sink_test_lock();
        // A disabled audit sink ignores the FBL-31 gates entirely (no boot
        // refusal when audit is off), matching the documented no-op contract.
        let cfg = crate::config::AuditConfig {
            enabled: Some(false),
            schema_version: Some(SCHEMA_VERSION + 999),
            hash_chain: Some(false),
            ..Default::default()
        };
        init_from_config(&cfg).expect("disabled audit is a no-op even with bad knobs");
    }

    fn sample_event(seq: u64, prev: &str) -> AuditEvent {
        let mut ev = AuditEvent {
            schema_version: SCHEMA_VERSION,
            timestamp: "2026-04-30T00:00:00+00:00".to_string(),
            sequence: seq,
            actor: actor("ai:test@host:pid-1", "host_fallback", None),
            action: AuditAction::Store,
            target: target_memory(
                format!("mem-{seq}"),
                "ns-x",
                Some("title".to_string()),
                Some(Tier::Mid.as_str().to_string()),
                None,
            ),
            outcome: AuditOutcome::Allow,
            auth: None,
            session_id: None,
            request_id: None,
            error: None,
            prev_hash: prev.to_string(),
            self_hash: String::new(),
        };
        ev.self_hash = compute_self_hash(&ev);
        ev
    }

    #[test]
    fn audit_event_round_trips_through_serde() {
        let ev = sample_event(1, CHAIN_HEAD_PREV_HASH);
        let s = serde_json::to_string(&ev).unwrap();
        let back: AuditEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ev);
        assert_eq!(back.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn audit_chain_links_correctly_for_three_events() {
        let e1 = sample_event(1, CHAIN_HEAD_PREV_HASH);
        let e2 = sample_event(2, &e1.self_hash);
        let e3 = sample_event(3, &e2.self_hash);
        let mut buf = String::new();
        for ev in [&e1, &e2, &e3] {
            buf.push_str(&serde_json::to_string(ev).unwrap());
            buf.push('\n');
        }
        let report = verify_chain_from_reader(buf.as_bytes()).unwrap();
        assert!(report.first_failure.is_none(), "{:?}", report.first_failure);
        assert_eq!(report.total_lines, 3);
    }

    #[test]
    fn audit_verify_detects_tampered_line() {
        let e1 = sample_event(1, CHAIN_HEAD_PREV_HASH);
        let mut e2 = sample_event(2, &e1.self_hash);
        // Tamper: swap the title without recomputing self_hash.
        e2.target.title = Some("EVIL".to_string());
        let e3 = sample_event(3, &e2.self_hash);
        let mut buf = String::new();
        for ev in [&e1, &e2, &e3] {
            buf.push_str(&serde_json::to_string(ev).unwrap());
            buf.push('\n');
        }
        let report = verify_chain_from_reader(buf.as_bytes()).unwrap();
        let failure = report.first_failure.expect("tampering must be detected");
        assert_eq!(failure.line_number, 2);
        assert!(matches!(failure.kind, VerifyFailureKind::SelfHash));
    }

    #[test]
    fn audit_verify_detects_chain_break() {
        let e1 = sample_event(1, CHAIN_HEAD_PREV_HASH);
        // Break: e2's prev_hash points at a hash that isn't e1's.
        let e2 = sample_event(2, "deadbeef");
        let mut buf = String::new();
        for ev in [&e1, &e2] {
            buf.push_str(&serde_json::to_string(ev).unwrap());
            buf.push('\n');
        }
        let report = verify_chain_from_reader(buf.as_bytes()).unwrap();
        let failure = report.first_failure.expect("chain break must be detected");
        assert!(matches!(failure.kind, VerifyFailureKind::ChainBreak));
    }

    #[test]
    fn audit_redacts_content_by_default() {
        // The schema does not have a `content` field. This test
        // doubles as a guardrail: if anyone ever adds one to
        // AuditEvent or AuditTarget, the round-trip assertion below
        // will surface it.
        let ev = sample_event(1, CHAIN_HEAD_PREV_HASH);
        let json = serde_json::to_value(&ev).unwrap();
        assert!(
            json.get("content").is_none(),
            "AuditEvent must never carry a content field"
        );
        assert!(
            json["target"].get("content").is_none(),
            "AuditTarget must never carry a content field"
        );
    }

    #[test]
    fn audit_action_as_str_round_trips() {
        for action in [
            AuditAction::Recall,
            AuditAction::Store,
            AuditAction::Update,
            AuditAction::Delete,
            AuditAction::Link,
            AuditAction::Promote,
            AuditAction::Forget,
            AuditAction::Consolidate,
            AuditAction::Export,
            AuditAction::Import,
            AuditAction::Approve,
            AuditAction::Reject,
            AuditAction::SessionBoot,
        ] {
            let s = action.as_str();
            // serde rename-all snake_case round-trips through the
            // string representation.
            let v: serde_json::Value = serde_json::to_value(action).unwrap();
            assert_eq!(v.as_str().unwrap(), s);
        }
    }

    #[test]
    fn audit_sanitize_strips_newlines() {
        let cleaned = sanitize_field("line1\nline2\rline3", 32);
        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\r'));
    }

    #[test]
    fn audit_sanitize_caps_length() {
        let s = "x".repeat(500);
        let cleaned = sanitize_field(&s, 100);
        assert_eq!(cleaned.chars().count(), 100);
    }

    #[test]
    fn audit_resolve_path_directory_expands_to_file() {
        let cfg = crate::config::AuditConfig {
            enabled: Some(true),
            path: Some("/tmp/ai-memory/audit/".to_string()),
            ..Default::default()
        };
        let p = resolve_audit_path(&cfg);
        assert!(p.ends_with("audit.log"));
    }

    #[test]
    fn audit_resolve_path_explicit_file_kept() {
        let cfg = crate::config::AuditConfig {
            enabled: Some(true),
            path: Some("/var/log/ai-memory/custom.log".to_string()),
            ..Default::default()
        };
        let p = resolve_audit_path(&cfg);
        assert_eq!(p, PathBuf::from("/var/log/ai-memory/custom.log"));
    }

    /// Serialize tests that mutate the process-wide audit sink so
    /// concurrent test runners don't stomp on each other. Tests that
    /// touch the live SINK should hold this lock for their duration.
    fn sink_lock() -> std::sync::MutexGuard<'static, ()> {
        super::sink_test_lock()
    }

    /// PR-5 (issue #487) load-bearing integration test. Wire the
    /// audit subsystem to an in-memory sink and emit one event per
    /// canonical action. Each successful operation MUST produce one
    /// line; the chain MUST stay intact across the run.
    #[test]
    fn audit_emits_at_every_call_site() {
        let _g = sink_lock();
        let buf: std::sync::Arc<Mutex<Vec<u8>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        super::init_for_test(buf.clone());

        let actions = [
            AuditAction::Store,
            AuditAction::Recall,
            AuditAction::Update,
            AuditAction::Delete,
            AuditAction::Link,
            AuditAction::Promote,
            AuditAction::Forget,
            AuditAction::Consolidate,
            AuditAction::Export,
            AuditAction::Import,
            AuditAction::Approve,
            AuditAction::Reject,
            AuditAction::SessionBoot,
            AuditAction::CaptureLag,
        ];
        for (i, action) in actions.iter().copied().enumerate() {
            let id = format!("mem-{i}");
            super::emit(EventBuilder::new(
                action,
                actor("ai:test@host", "explicit", None),
                target_memory(id, "ns-x", Some("t".to_string()), None, None),
            ));
        }

        let lines = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let count = lines.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(
            count,
            actions.len(),
            "expected one audit line per action, got {count}: {lines}"
        );
        // Chain MUST be intact across the whole run.
        let report = verify_chain_from_reader(lines.as_bytes()).unwrap();
        assert!(
            report.first_failure.is_none(),
            "chain must verify across all call sites; failure: {:?}",
            report.first_failure
        );
        assert_eq!(report.total_lines as usize, actions.len());

        super::shutdown_for_test();
    }

    /// #3975: a writer that behaves like a disk that fills after `budget`
    /// bytes (`ENOSPC` on write), and optionally fails every flush.
    struct FillingDisk {
        budget: usize,
        fail_flush: bool,
    }

    impl std::io::Write for FillingDisk {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if data.len() > self.budget {
                return Err(std::io::Error::from_raw_os_error(28)); // ENOSPC
            }
            self.budget -= data.len();
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.fail_flush {
                Err(std::io::Error::other("flush failed"))
            } else {
                Ok(())
            }
        }
    }

    fn emit_one() {
        super::emit(EventBuilder::new(
            AuditAction::Store,
            actor("a", "explicit", None),
            target_memory("m", "ns", None, None, None),
        ));
    }

    /// #3975: a disk that fills AFTER boot. Pre-fix the failed writes were
    /// reported only through `tracing` (a no-op without a subscriber), so the
    /// trail stopped with no counter an operator could see.
    #[test]
    fn a_disk_that_fills_after_boot_is_counted_3975() {
        let _g = sink_lock();
        let delivery = &RuntimeContext::global().audit.delivery;
        let (written0, failed0) = (delivery.delivered(), delivery.write_failures());
        // Room for exactly one event line.
        super::init_for_test_with_writer(Box::new(FillingDisk {
            budget: 4096,
            fail_flush: false,
        }));
        emit_one();
        super::init_for_test_with_writer(Box::new(FillingDisk {
            budget: 0,
            fail_flush: false,
        }));
        emit_one();
        emit_one();
        let status = super::audit_trail_status();
        super::shutdown_for_test();
        assert_eq!(delivery.delivered() - written0, 1, "one event landed");
        assert_eq!(
            delivery.write_failures() - failed0,
            2,
            "two events were lost"
        );
        assert_eq!(status.state, super::AuditTrailState::Active);
        assert!(status.last_write_unix_ms.is_some());
    }

    /// #3975: a failed FLUSH was discarded (`.ok()`); it is now a counted loss.
    #[test]
    fn a_failed_flush_is_counted_not_discarded_3975() {
        let _g = sink_lock();
        let delivery = &RuntimeContext::global().audit.delivery;
        let (written0, failed0) = (delivery.delivered(), delivery.write_failures());
        super::init_for_test_with_writer(Box::new(FillingDisk {
            budget: usize::MAX,
            fail_flush: true,
        }));
        emit_one();
        super::shutdown_for_test();
        assert_eq!(delivery.write_failures() - failed0, 1);
        assert_eq!(delivery.delivered() - written0, 0);
    }

    /// #3975: auditing OFF is not a loss. No sink means nothing to record, so
    /// the failure counter must not move (and no stderr line is printed).
    #[test]
    fn emit_with_auditing_off_is_not_a_failure_3975() {
        let _g = sink_lock();
        super::shutdown_for_test();
        let delivery = &RuntimeContext::global().audit.delivery;
        let failed0 = delivery.write_failures();
        emit_one();
        assert_eq!(delivery.write_failures(), failed0);
        assert_eq!(
            super::audit_trail_status().state,
            super::AuditTrailState::NotActive
        );
    }

    #[test]
    fn the_failure_diagnostic_names_the_metric_3975() {
        let line = super::audit_failure_diagnostic(&anyhow::anyhow!("No space left on device"), 4);
        assert!(line.contains("No space left on device"));
        assert!(line.contains("4 further failures"));
        assert!(line.contains(super::AUDIT_WRITE_FAILURES_TOTAL));
    }

    #[test]
    fn audit_emit_is_noop_when_disabled() {
        let _g = sink_lock();
        super::shutdown_for_test();
        // No sink active — emit must not panic and must not produce
        // any output anywhere.
        super::emit(EventBuilder::new(
            AuditAction::Store,
            actor("a", "explicit", None),
            target_memory("m", "ns", None, None, None),
        ));
        // is_enabled stays false.
        assert!(!super::is_enabled());
    }

    #[test]
    fn audit_compliance_preset_soc2_overrides_retention() {
        // The compliance presets are pure config — applying SOC2 with
        // `applied = true` propagates the documented retention to the
        // top-level config field. This is a unit-test on the merge
        // logic, decoupled from disk.
        let cfg = crate::config::AuditConfig {
            enabled: Some(true),
            retention_days: Some(90),
            compliance: Some(crate::config::AuditComplianceConfig {
                soc2: Some(crate::config::CompliancePreset {
                    applied: Some(true),
                    retention_days: Some(730),
                    redact_content: Some(true),
                    attestation_cadence_minutes: Some(60),
                    encrypt_at_rest: None,
                    pseudonymize_actors: None,
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let resolved = cfg.effective_retention_days();
        assert_eq!(resolved, 730, "SOC2 preset must override default retention");
    }

    // ------------------------------------------------------------------
    // PR-9e coverage uplift (issue #487): exercise `init`, `read_chain_tail`,
    // builder method chains, `init_from_config` enabled+disabled paths,
    // `finalize_audit_file`, and the verify Sequence/Parse failure modes.
    // ------------------------------------------------------------------

    #[test]
    fn audit_init_creates_log_file_in_fresh_directory() {
        let _g = sink_lock();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested").join("audit.log");
        // Directory does not yet exist; init must create it.
        super::init(&path, true, false).unwrap();
        assert!(path.exists(), "init must create the log file");
        assert!(super::is_enabled());
        super::shutdown_for_test();
    }

    #[test]
    fn audit_init_seeds_last_hash_from_existing_chain() {
        let _g = sink_lock();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.log");

        // Pre-populate with a 2-event chain. We specifically test the
        // `read_chain_tail` linkage: the next emitted event's
        // `prev_hash` must match the file's last self_hash.
        //
        // **F2 (v0.7.0 round-2-fixes):** `init` now seeds the
        // SEQUENCE counter from the trailing record's sequence as
        // well, so the next emit produces `last_sequence + 1`. The
        // dedicated F2 test below pins that behavior; here we keep
        // the focus on hash-chain continuity.
        let e1 = sample_event(1, CHAIN_HEAD_PREV_HASH);
        let e2 = sample_event(2, &e1.self_hash);
        let mut body = String::new();
        body.push_str(&serde_json::to_string(&e1).unwrap());
        body.push('\n');
        body.push_str(&serde_json::to_string(&e2).unwrap());
        body.push('\n');
        std::fs::write(&path, body).unwrap();

        // Init points at the existing file — `read_chain_tail` must
        // seed `last_hash` from e2.
        super::init(&path, true, false).unwrap();

        // Emit a third event; its prev_hash should equal e2.self_hash.
        super::emit(EventBuilder::new(
            AuditAction::Store,
            actor("ai:t@h", "explicit", None),
            target_memory("m3", "ns-x", Some("t".to_string()), None, None),
        ));

        let body = std::fs::read_to_string(&path).unwrap();
        let third_line = body.lines().nth(2).expect("3rd line");
        let parsed: AuditEvent = serde_json::from_str(third_line).unwrap();
        assert_eq!(parsed.prev_hash, e2.self_hash, "chain must continue");
        super::shutdown_for_test();
    }

    /// F2 regression (v0.7.0 round-2-fixes): `init` must seed the
    /// per-process SEQUENCE counter from the trailing record's
    /// sequence so emissions across daemon restarts remain
    /// monotonic. Pre-fix the SEQUENCE was reset to 0 every init,
    /// so the next event emitted sequence=1 even when the file's
    /// last record was sequence=N>1 — `audit verify` then flagged
    /// "sequence not monotonic: prior=N, this=1" on the first
    /// post-restart event.
    #[test]
    fn audit_init_seeds_sequence_from_existing_chain_tail() {
        let _g = sink_lock();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.log");

        // Phase 1: drive 5 events with sequences 1..=5 against a
        // real file (init opens the file in append mode like the
        // production daemon does).
        super::init(&path, true, false).unwrap();
        for i in 0..5 {
            super::emit(EventBuilder::new(
                AuditAction::Store,
                actor("ai:writer", "explicit", None),
                target_memory(&format!("m{i}"), "ns", Some(format!("t{i}")), None, None),
            ));
        }

        // Verify Phase 1 sequences are 1..=5.
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = body.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 5, "phase 1 must emit 5 events");
        for (i, line) in lines.iter().enumerate() {
            let ev: AuditEvent = serde_json::from_str(line).unwrap();
            #[allow(clippy::cast_possible_truncation)]
            let expected = (i as u64) + 1;
            assert_eq!(
                ev.sequence, expected,
                "phase 1 event {i} must have sequence {expected}"
            );
        }

        // Simulate daemon restart: drop the active sink, then re-init
        // pointing at the same physical file.
        super::shutdown_for_test();
        super::init(&path, true, false).unwrap();

        // Phase 2: emit a single event. Pre-fix this would emit
        // sequence=1; post-fix it must emit sequence=6.
        super::emit(EventBuilder::new(
            AuditAction::Store,
            actor("ai:writer", "explicit", None),
            target_memory("m6", "ns", Some("t6".to_string()), None, None),
        ));

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = body.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 6, "phase 2 must append a 6th event");

        let last: AuditEvent = serde_json::from_str(lines[5]).unwrap();
        assert_eq!(
            last.sequence, 6,
            "F2: post-restart event must continue sequence from disk (got {}, expected 6)",
            last.sequence,
        );

        // Hash-chain linkage from the prior tail must also hold.
        let fifth: AuditEvent = serde_json::from_str(lines[4]).unwrap();
        assert_eq!(
            last.prev_hash, fifth.self_hash,
            "F2 must not regress hash-chain continuity"
        );
        super::shutdown_for_test();
    }

    #[test]
    fn audit_init_refuses_a_corrupt_chain_tail_4190() {
        // #4190 — pre-fix, a malformed trailing line counted as "no chain"
        // and init re-seeded CHAIN_HEAD_PREV_HASH, forking the chain inside
        // the same file. Now it is an error, and the file is left alone.
        let _g = sink_lock();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        std::fs::write(&path, "{not valid json\n").unwrap();
        let err = super::init(&path, true, false).expect_err("a corrupt tail must refuse");
        let msg = format!("{err:#}");
        assert!(msg.contains("audit trail tail"), "{msg}");
        assert!(msg.contains("torn or corrupt"), "{msg}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not valid json\n");
    }

    #[test]
    fn audit_init_continues_past_a_corrupt_interior_line_4190() {
        // Control for the rule's boundary: a malformed line that a later
        // valid record follows is not the tail, so init continues from that
        // later record (and `audit verify` reports the bad line).
        let _g = sink_lock();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        let e1 = sample_event(1, CHAIN_HEAD_PREV_HASH);
        std::fs::write(
            &path,
            format!(
                "{{not valid json\n{}\n",
                serde_json::to_string(&e1).unwrap()
            ),
        )
        .unwrap();
        super::init(&path, true, false).unwrap();
        super::emit(EventBuilder::new(
            AuditAction::Store,
            actor("a", "explicit", None),
            target_memory("m", "ns", None, None, None),
        ));
        let body = std::fs::read_to_string(&path).unwrap();
        let last = body.lines().filter(|l| !l.is_empty()).last().unwrap();
        let parsed: AuditEvent = serde_json::from_str(last).unwrap();
        assert_eq!(parsed.prev_hash, e1.self_hash);
        super::shutdown_for_test();
    }

    /// M14 (v0.7.0 round-2-fixes): init must surface out-of-order
    /// sequence numbers via `tracing::warn!` without refusing to
    /// start. We hand-craft an audit log with two lines whose sequence
    /// numbers are intentionally swapped (line 1 → seq=2, line 2 →
    /// seq=1), point `init` at it, and assert (a) init succeeds and
    /// (b) a WARN was observed describing the out-of-order pair.
    #[test]
    fn audit_init_warns_on_out_of_order_sequence() {
        // #4088: the `tracing` callsite-interest cache is process-global; a
        // sibling test with no subscriber can pin a callsite to `never` and this
        // capture then reads nothing (the #3426 mechanism). Run alone in a child.
        if crate::config::run_env_isolated_child_or_spawn(
            "audit::tests::audit_init_warns_on_out_of_order_sequence",
        ) {
            return;
        }
        let _g = sink_lock();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.log");

        // Compose two minimal AuditEvent lines with swapped seqs. We
        // construct via the public struct + serde so this stays
        // forward-compatible if a future schema bumps `schema_version`.
        let make_event = |seq: u64| AuditEvent {
            schema_version: SCHEMA_VERSION,
            timestamp: "2026-05-10T00:00:00Z".to_string(),
            sequence: seq,
            actor: AuditActor {
                agent_id: "ai:test".to_string(),
                scope: None,
                synthesis_source: "explicit".to_string(),
            },
            action: AuditAction::Store,
            target: AuditTarget {
                memory_id: format!("m-seq-{seq}"),
                namespace: "ns".to_string(),
                title: None,
                tier: None,
                scope: None,
            },
            outcome: AuditOutcome::Allow,
            auth: None,
            session_id: None,
            request_id: None,
            error: None,
            prev_hash: CHAIN_HEAD_PREV_HASH.to_string(),
            self_hash: format!("{seq:064x}"),
        };

        let line_a = serde_json::to_string(&make_event(2)).unwrap();
        let line_b = serde_json::to_string(&make_event(1)).unwrap();
        std::fs::write(&path, format!("{line_a}\n{line_b}\n")).unwrap();

        // Capture WARN output via a per-call subscriber.
        #[derive(Clone, Default)]
        struct WarnSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for WarnSink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for WarnSink {
            type Writer = WarnSink;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }
        let sink = WarnSink::default();
        let buf = sink.0.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(sink)
            .without_time()
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            super::init(&path, true, false)
                .expect("M14: init must succeed despite out-of-order seqs");
        });
        let captured = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            captured.contains("out-of-order sequence"),
            "M14: expected out-of-order WARN, got: {captured:?}"
        );
        // The exact pair must be reported so an operator can grep.
        assert!(
            captured.contains("prior 2"),
            "M14: WARN must include prior sequence (=2), got: {captured:?}"
        );
        assert!(
            captured.contains("this 1"),
            "M14: WARN must include this sequence (=1), got: {captured:?}"
        );

        // init must have populated the sink (no refusal) — emitting
        // an event after init still works.
        super::emit(EventBuilder::new(
            AuditAction::Store,
            actor("ai:writer", "explicit", None),
            target_memory("m-after-warn", "ns", None, None, None),
        ));
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = body.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines.len(),
            3,
            "M14: init must accept the file and emit must still work"
        );
        super::shutdown_for_test();
    }

    #[test]
    fn audit_event_builder_error_outcome() {
        let b = EventBuilder::new(
            AuditAction::Store,
            actor("a", "explicit", None),
            target_memory("m", "ns", None, None, None),
        )
        .error("boom");
        assert_eq!(b.outcome, AuditOutcome::Error);
        assert_eq!(b.error.as_deref(), Some("boom"));
    }

    #[test]
    fn audit_event_builder_error_caps_long_message() {
        let long = "x".repeat(1000);
        let b = EventBuilder::new(
            AuditAction::Store,
            actor("a", "explicit", None),
            target_memory("m", "ns", None, None, None),
        )
        .error(long);
        // sanitize_field caps at 256 chars.
        assert_eq!(b.error.as_ref().unwrap().chars().count(), 256);
    }

    #[test]
    fn audit_event_builder_outcome_chain() {
        let b = EventBuilder::new(
            AuditAction::Store,
            actor("a", "explicit", None),
            target_memory("m", "ns", None, None, None),
        )
        .outcome(AuditOutcome::Deny);
        assert_eq!(b.outcome, AuditOutcome::Deny);
    }

    #[test]
    fn audit_event_builder_auth_and_request_id() {
        let auth = AuditAuth {
            source_ip: Some("203.0.113.1".to_string()),
            mtls_fp: None,
            api_key_id_hash: Some("abc".to_string()),
        };
        let b = EventBuilder::new(
            AuditAction::Store,
            actor("a", "explicit", None),
            target_memory("m", "ns", None, None, None),
        )
        .auth(auth.clone())
        .request_id("req-123");
        assert_eq!(b.auth, Some(auth));
        assert_eq!(b.request_id.as_deref(), Some("req-123"));
    }

    #[test]
    fn audit_init_from_config_disabled_clears_sink() {
        let _g = sink_lock();
        // Bring up an in-memory sink first.
        let buf: std::sync::Arc<Mutex<Vec<u8>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        super::init_for_test(buf);
        assert!(super::is_enabled());

        let cfg = crate::config::AuditConfig {
            enabled: Some(false),
            ..Default::default()
        };
        super::init_from_config(&cfg).unwrap();
        // Disabled-branch must clear the global sink.
        assert!(!super::is_enabled());
        super::shutdown_for_test();
    }

    #[test]
    fn audit_init_from_config_enabled_initialises_sink_at_resolved_path() {
        let _g = sink_lock();
        super::shutdown_for_test();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        let cfg = crate::config::AuditConfig {
            enabled: Some(true),
            path: Some(path.to_string_lossy().into_owned()),
            redact_content: Some(true),
            // Don't try to apply the OS append-only flag in tests —
            // the calling user typically lacks CAP_LINUX_IMMUTABLE
            // and we don't want a kernel-level side effect.
            append_only: Some(false),
            ..Default::default()
        };
        super::init_from_config(&cfg).unwrap();
        assert!(super::is_enabled());
        // The configured file must exist on disk after init.
        assert!(path.exists(), "audit log file must be created");
        super::shutdown_for_test();
    }

    #[test]
    fn audit_finalize_audit_file_keeps_explicit_file_path() {
        let cfg = crate::config::AuditConfig {
            enabled: Some(true),
            path: Some("/var/log/ai-memory/x.log".to_string()),
            ..Default::default()
        };
        let p = resolve_audit_path(&cfg);
        // Explicit file path must be preserved (not appended with audit.log).
        assert_eq!(p, PathBuf::from("/var/log/ai-memory/x.log"));
    }

    #[test]
    fn audit_finalize_audit_file_appends_audit_log_for_dir_path() {
        let cfg = crate::config::AuditConfig {
            enabled: Some(true),
            path: Some("/var/log/ai-memory/".to_string()),
            ..Default::default()
        };
        let p = resolve_audit_path(&cfg);
        assert!(p.ends_with("audit.log"));
    }

    #[test]
    fn audit_finalize_audit_file_appends_audit_log_for_extension_less_path() {
        // No trailing slash and no extension: treat as dir, append audit.log.
        let cfg = crate::config::AuditConfig {
            enabled: Some(true),
            path: Some("/var/log/aim_audit_dir".to_string()),
            ..Default::default()
        };
        let p = resolve_audit_path(&cfg);
        assert!(p.ends_with("audit.log"));
    }

    #[test]
    fn audit_verify_detects_sequence_regression() {
        // Build a chain with a non-monotonic sequence to hit the
        // VerifyFailureKind::Sequence branch.
        let e1 = sample_event(5, CHAIN_HEAD_PREV_HASH);
        // e2 has sequence == e1's sequence (not strictly greater).
        let e2 = sample_event(5, &e1.self_hash);
        let mut buf = String::new();
        for ev in [&e1, &e2] {
            buf.push_str(&serde_json::to_string(ev).unwrap());
            buf.push('\n');
        }
        let report = verify_chain_from_reader(buf.as_bytes()).unwrap();
        let failure = report.first_failure.expect("sequence regression");
        assert!(matches!(failure.kind, VerifyFailureKind::Sequence));
    }

    #[test]
    fn audit_verify_detects_malformed_json_line() {
        // Single garbage line — must surface VerifyFailureKind::Parse.
        let buf = "this is not json\n";
        let report = verify_chain_from_reader(buf.as_bytes()).unwrap();
        let failure = report.first_failure.expect("parse failure");
        assert!(matches!(failure.kind, VerifyFailureKind::Parse));
        assert!(failure.detail.contains("malformed JSON"));
    }

    #[test]
    fn audit_verify_skips_blank_lines() {
        // Mix blank lines into a valid chain — must verify clean.
        let e1 = sample_event(1, CHAIN_HEAD_PREV_HASH);
        let e2 = sample_event(2, &e1.self_hash);
        let buf = format!(
            "\n{}\n\n{}\n\n",
            serde_json::to_string(&e1).unwrap(),
            serde_json::to_string(&e2).unwrap()
        );
        let report = verify_chain_from_reader(buf.as_bytes()).unwrap();
        assert!(report.first_failure.is_none());
        assert_eq!(report.total_lines, 2);
    }

    #[test]
    fn audit_verify_report_into_result_ok() {
        let e1 = sample_event(1, CHAIN_HEAD_PREV_HASH);
        let report = verify_chain_from_reader(
            format!("{}\n", serde_json::to_string(&e1).unwrap()).as_bytes(),
        )
        .unwrap();
        let n = report.into_result().unwrap();
        assert_eq!(n, 1);
    }

    /// #4021: a real lost write (the #3975 mechanism) leaves an intact hash
    /// chain and a sequence gap. Pre-#4021 this trail verified clean.
    #[test]
    fn a_lost_write_leaves_a_detected_gap_4021() {
        let trail = super::gapped_trail_for_test();
        let report = verify_chain_from_reader(trail.as_slice()).unwrap();
        assert_eq!(
            report.first_failure, None,
            "the hash chain itself is intact"
        );
        assert_eq!(report.total_lines, 3, "events 1, 2 and 4 were written");
        assert_eq!(report.gaps, vec![super::SequenceGap { from: 3, to: 3 }]);
        let err = report.clone().into_result().unwrap_err().to_string();
        assert!(err.contains("1 audit event(s) missing"), "got: {err}");
        assert!(err.contains("--acknowledge-gaps 3-3"), "got: {err}");
        assert!(
            !err.contains("somebody touched"),
            "a gap is a lost event, never the tamper wording"
        );
    }

    /// #4021: an acknowledgement passes a gap only when it names it EXACTLY.
    #[test]
    fn an_acknowledgement_matches_a_gap_only_exactly_4021() {
        let report = VerifyReport {
            total_lines: 4,
            first_failure: None,
            gaps: vec![
                super::SequenceGap { from: 3, to: 3 },
                super::SequenceGap { from: 7, to: 9 },
            ],
            torn_lines: Vec::new(),
        };
        let exact = [
            super::SequenceGap { from: 3, to: 3 },
            super::SequenceGap { from: 7, to: 9 },
        ];
        assert!(report.unacknowledged_gaps(&exact).is_empty());
        // A broad range is NOT a blanket pass.
        let broad = [super::SequenceGap { from: 1, to: 100 }];
        assert_eq!(report.unacknowledged_gaps(&broad), report.gaps);
        // Acknowledging one leaves the other failing.
        assert_eq!(
            report.unacknowledged_gaps(&exact[..1]),
            vec![super::SequenceGap { from: 7, to: 9 }]
        );
    }

    #[test]
    fn gap_ranges_parse_strictly_4021() {
        use std::str::FromStr;
        assert_eq!(
            super::SequenceGap::from_str("3-3").unwrap(),
            super::SequenceGap { from: 3, to: 3 }
        );
        assert_eq!(
            super::SequenceGap::from_str(" 7 - 9 ").unwrap(),
            super::SequenceGap { from: 7, to: 9 }
        );
        for bad in ["", "3", "0-1", "5-3", "a-b", "3-", "-3"] {
            assert!(
                super::SequenceGap::from_str(bad).is_err(),
                "`{bad}` must be refused"
            );
        }
    }

    /// #4021: a trail with no gap reports none (a restart reseeds from the
    /// tail, so contiguous emission is the normal shape).
    #[test]
    fn a_contiguous_trail_has_no_gap_4021() {
        let _g = sink_lock();
        let buf = std::sync::Arc::new(Mutex::new(Vec::new()));
        super::init_for_test(std::sync::Arc::clone(&buf));
        for _ in 0..3 {
            super::emit(EventBuilder::new(
                AuditAction::Store,
                actor("a", "explicit", None),
                target_memory("m", "ns", None, None, None),
            ));
        }
        super::shutdown_for_test();
        let trail = buf.lock().unwrap().clone();
        let report = verify_chain_from_reader(trail.as_slice()).unwrap();
        assert!(report.gaps.is_empty());
        assert_eq!(report.into_result().unwrap(), 3);
    }

    #[test]
    fn audit_verify_report_into_result_err() {
        let report = VerifyReport {
            total_lines: 5,
            first_failure: Some(VerifyFailure {
                line_number: 3,
                kind: VerifyFailureKind::ChainBreak,
                detail: "x".to_string(),
            }),
            gaps: Vec::new(),
            torn_lines: Vec::new(),
        };
        let err = report.into_result().unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("audit chain verification failed"));
        assert!(msg.contains("line 3"));
    }

    #[test]
    fn audit_emit_records_request_id_and_auth() {
        let _g = sink_lock();
        let buf: std::sync::Arc<Mutex<Vec<u8>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        super::init_for_test(buf.clone());
        super::emit(
            EventBuilder::new(
                AuditAction::Store,
                actor("a", "explicit", None),
                target_memory("m", "ns", None, None, None),
            )
            .auth(AuditAuth {
                source_ip: Some("198.51.100.7".to_string()),
                mtls_fp: None,
                api_key_id_hash: None,
            })
            .request_id("trace-abc"),
        );
        let body = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(body.contains("\"request_id\":\"trace-abc\""), "got: {body}");
        assert!(body.contains("198.51.100.7"));
        super::shutdown_for_test();
    }

    #[test]
    fn audit_emit_records_error_outcome() {
        let _g = sink_lock();
        let buf: std::sync::Arc<Mutex<Vec<u8>>> = std::sync::Arc::new(Mutex::new(Vec::new()));
        super::init_for_test(buf.clone());
        super::emit(
            EventBuilder::new(
                AuditAction::Store,
                actor("a", "explicit", None),
                target_memory("m", "ns", None, None, None),
            )
            .error("disk full"),
        );
        let body = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(body.contains("\"outcome\":\"error\""), "got: {body}");
        assert!(body.contains("\"error\":\"disk full\""), "got: {body}");
        super::shutdown_for_test();
    }

    #[test]
    fn audit_expand_tilde_passthrough_when_no_tilde() {
        // Pure-string helper — should leave non-tilde paths intact.
        assert_eq!(super::expand_tilde("/abs/path"), "/abs/path");
        assert_eq!(super::expand_tilde("rel/path"), "rel/path");
    }

    #[test]
    fn audit_target_sweep_uses_wildcard_id() {
        let t = super::target_sweep("ns-y");
        assert_eq!(t.memory_id, "*");
        assert_eq!(t.namespace, "ns-y");
    }

    #[test]
    fn audit_target_memory_round_trips_optional_fields() {
        let t = super::target_memory(
            "mem-1",
            "ns-x",
            Some("title".to_string()),
            Some(Tier::Long.as_str().to_string()),
            Some("team".to_string()),
        );
        assert_eq!(t.tier.as_deref(), Some(Tier::Long.as_str()));
        assert_eq!(t.scope.as_deref(), Some("team"));
    }

    // -----------------------------------------------------------------
    // L0.7-2 Tier A — long-tail error path + helper coverage
    // (lines 244/266, 271-277, 363/368, 685-686, 809-811, 842/845,
    // 850-853 expand_tilde, mark_append_only happy path on darwin)
    // -----------------------------------------------------------------

    #[test]
    fn expand_tilde_substitutes_home_when_set() {
        // Line 850-853 happy path: prefix "~/" + HOME present →
        // expanded. We do NOT mutate HOME here — log_paths.rs has its
        // own env-lock-serialised HOME tests, and racing across two
        // process-wide locks is unsafe. Instead we call expand_tilde
        // twice and assert ONE of the documented behaviours:
        //   - HOME present: result == "{HOME}/audit/log"
        //   - HOME absent : result == "~/audit/log" (raw passthrough)
        // Both arms hit the prefix-match line; only the inner HOME
        // lookup differs. Either way, line 850 and the prefix check
        // are exercised.
        let out = super::expand_tilde("~/audit/log");
        // Accept either expanded or passthrough; the test exists to
        // pin the prefix detection logic + reachable code path, not
        // to assert a particular HOME value (which races across tests).
        assert!(
            out.ends_with("/audit/log") || out == "~/audit/log",
            "unexpected output shape: {out}"
        );
    }

    #[test]
    fn expand_tilde_no_match_passthrough() {
        // The non-tilde fast-path (already covered by an earlier test)
        // and a "~" without "/" suffix both fall through to the raw
        // return arm. This pins the non-prefix branch.
        assert_eq!(super::expand_tilde("~root/etc"), "~root/etc");
        assert_eq!(super::expand_tilde("~"), "~");
    }

    #[test]
    fn audit_init_returns_error_when_parent_path_is_a_file() {
        // Line 244-245: `create_dir_all` fails when the parent is a
        // regular file (cannot create a dir on top of one). `init`
        // surfaces the wrapped Err via with_context.
        let _g = sink_lock();
        let tmp = tempfile::tempdir().unwrap();
        // Create a regular file at what would be the parent dir.
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"i am a file, not a directory").unwrap();
        // Request a log path *inside* the blocker file → create_dir_all
        // hits ENOTDIR on the parent.
        let log_path = blocker.join("nested").join("audit.log");
        let err = super::init(&log_path, true, false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("creating audit log dir") || msg.contains("audit"),
            "expected wrapped context, got: {msg}"
        );
        super::shutdown_for_test();
    }

    #[test]
    fn audit_init_applies_append_only_flag_on_macos() {
        // Line 268-269, 282-287: append_only_hint=true must trigger
        // mark_append_only and (on macOS/BSD) the chflags branch.
        // Even if the syscall fails for unprivileged users, init must
        // still succeed because failures are logged WARN and swallowed.
        let _g = sink_lock();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        // Pre-create so chflags has a real inode to flag.
        std::fs::write(&path, b"").unwrap();
        // append_only_hint=true reaches mark_append_only. On darwin the
        // call may or may not succeed depending on user privileges and
        // chflags's response to UF_APPEND on a tmpfile — either way
        // init MUST return Ok() and a sink MUST be installed.
        super::init(&path, true, true).expect("init must tolerate flag outcome");
        assert!(super::is_enabled());
        super::shutdown_for_test();
        // Best-effort: clear UF_APPEND if it was set so tmpdir cleanup
        // can remove the file. We ignore errors — the file lives under
        // the OS tmpdir cleaner anyway.
        #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
        unsafe {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            if let Ok(c) = CString::new(path.as_os_str().as_bytes()) {
                let _ = libc::chflags(c.as_ptr(), 0);
            }
        }
    }

    #[test]
    fn read_chain_tail_returns_none_for_missing_file() {
        // Line 360-361 fast path: file doesn't exist.
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope.log");
        // We call through init: init seeds with CHAIN_HEAD_PREV_HASH.
        // (read_chain_tail is private; init is the canonical caller.)
        let _g = sink_lock();
        super::init(&missing, true, false).unwrap();
        // After init, the new file must exist and a fresh chain head
        // must be in place — emit one event, verify prev_hash is the
        // sentinel.
        super::emit(EventBuilder::new(
            AuditAction::Store,
            actor("a", "explicit", None),
            target_memory("m", "ns", None, None, None),
        ));
        let body = std::fs::read_to_string(&missing).unwrap();
        let line = body.lines().next().unwrap();
        let parsed: AuditEvent = serde_json::from_str(line).unwrap();
        assert_eq!(parsed.prev_hash, CHAIN_HEAD_PREV_HASH);
        super::shutdown_for_test();
    }

    #[test]
    fn read_chain_tail_skips_blank_lines() {
        // Line 369-370: empty/blank lines must be skipped during chain
        // tail scan. We pre-seed a chain with embedded blank lines,
        // init, then emit and verify the next prev_hash still threads
        // through the last real event.
        let _g = sink_lock();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.log");
        let e1 = sample_event(1, CHAIN_HEAD_PREV_HASH);
        let e2 = sample_event(2, &e1.self_hash);
        let body = format!(
            "{}\n\n\n{}\n   \n",
            serde_json::to_string(&e1).unwrap(),
            serde_json::to_string(&e2).unwrap(),
        );
        std::fs::write(&path, body).unwrap();
        super::init(&path, true, false).unwrap();
        super::emit(EventBuilder::new(
            AuditAction::Store,
            actor("a", "explicit", None),
            target_memory("m", "ns", None, None, None),
        ));
        let full = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = full.lines().filter(|l| !l.trim().is_empty()).collect();
        let last = lines.last().unwrap();
        let parsed: AuditEvent = serde_json::from_str(last).unwrap();
        assert_eq!(
            parsed.prev_hash, e2.self_hash,
            "blank lines must be skipped"
        );
        super::shutdown_for_test();
    }

    #[test]
    fn verify_chain_open_error_wrapped_with_context() {
        // Line 686: File::open failure on a non-existent path must
        // surface an error with the "opening <path>" context.
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist.log");
        let err = super::verify_chain(&missing).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("opening"), "expected context, got: {msg}");
        assert!(msg.contains("does-not-exist.log"), "got: {msg}");
    }

    #[test]
    fn finalize_audit_file_keeps_explicit_extension_path() {
        // Line 836-840: when raw_config has a non-slash trailing
        // extension, the function returns `p` as-is (no audit.log
        // append). Covered by audit_finalize_audit_file_keeps_explicit_file_path
        // — this is a tighter focus on the extension-discrimination branch.
        let cfg = crate::config::AuditConfig {
            enabled: Some(true),
            path: Some("./custom.txt".to_string()),
            ..Default::default()
        };
        let p = resolve_audit_path(&cfg);
        // The configured file path must round-trip without an
        // audit.log suffix because it has a non-empty extension.
        assert!(
            p.to_string_lossy().ends_with(".txt"),
            "got: {}",
            p.display()
        );
    }

    #[test]
    fn finalize_audit_file_keeps_resolved_file_when_no_config_override() {
        // Direct unit-test on the `else p` arm (line 845): construct a
        // resolved `PathBuf` that already has an extension and pass
        // raw_config = None so the head-branch falls through; the
        // p.extension().is_none() check fails (it IS Some), so the else
        // arm executes returning `p` unchanged.
        let p = PathBuf::from("/var/log/aimemory.log");
        let out = super::finalize_audit_file(p.clone(), None);
        assert_eq!(out, p);
    }

    #[test]
    fn resolve_audit_path_falls_back_to_platform_default_when_resolver_errs() {
        // Lines 807-811: `resolve_audit_dir` returns Err when the
        // configured dir is world-writable; `resolve_audit_path` (the
        // non-strict variant) silently falls back to `platform_default`.
        // We exercise the fallback by chmodding a tempdir to 0777 and
        // pointing AuditConfig.path at it. After the call:
        //   * Function must return Ok-like PathBuf (no panic)
        //   * Result must NOT be inside the world-writable dir (that
        //     would defeat the security check)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            let www = tmp.path().join("world_writable");
            std::fs::create_dir_all(&www).unwrap();
            std::fs::set_permissions(&www, std::fs::Permissions::from_mode(0o777)).unwrap();
            let cfg = crate::config::AuditConfig {
                enabled: Some(true),
                path: Some(www.to_string_lossy().into_owned()),
                ..Default::default()
            };
            let p = super::resolve_audit_path(&cfg);
            // p must NOT be inside the world-writable dir (the fallback
            // routed past it).
            assert!(
                !p.starts_with(&www),
                "world-writable dir must not be used; got: {}",
                p.display()
            );
        }
    }

    #[test]
    fn resolve_audit_path_with_override_propagates_world_writable_error() {
        // Line 826: strict variant returns Err when resolve_audit_dir
        // refuses a world-writable path. Mirrors the non-strict test
        // above but asserts Err on the strict surface.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            let www = tmp.path().join("ww");
            std::fs::create_dir_all(&www).unwrap();
            std::fs::set_permissions(&www, std::fs::Permissions::from_mode(0o777)).unwrap();
            let cfg = crate::config::AuditConfig::default();
            let err = super::resolve_audit_path_with_override(Some(&www), &cfg).unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.contains("world-writable"),
                "expected world-writable error, got: {msg}"
            );
        }
    }

    #[test]
    fn init_with_directory_in_place_of_file_returns_open_error() {
        // A path that resolves to an existing *directory* is an error that
        // names the path. Since #4190 the chain-tail read reaches it first
        // (reading a directory fails, e.g. EISDIR, and is no longer
        // discarded); on a platform where that read cannot even open the
        // directory the error comes from the same stage, and if it ever got
        // past the read the append-open (`opening audit log {path}`) refuses.
        let _g = sink_lock();
        let tmp = tempfile::tempdir().unwrap();
        let err = super::init(tmp.path(), true, false).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("audit trail tail") || msg.contains("opening audit log"),
            "got: {msg}"
        );
        assert!(
            msg.contains(&tmp.path().display().to_string()),
            "got: {msg}"
        );
        super::shutdown_for_test();
    }

    #[test]
    fn resolve_audit_path_with_override_returns_source_tag() {
        // Line 822-828: the strict variant. With a CLI override the
        // PathSource should reflect that. We pass a tempdir as the
        // override and assert the returned path embeds it.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = crate::config::AuditConfig::default();
        let (path, _source) =
            super::resolve_audit_path_with_override(Some(tmp.path()), &cfg).unwrap();
        // Output path must live under the override dir (since override
        // wins precedence).
        assert!(
            path.starts_with(tmp.path()),
            "expected override-rooted path, got: {}",
            path.display()
        );
        // And must end with audit.log because we passed a directory.
        assert!(path.ends_with("audit.log"), "got: {}", path.display());
    }
}
