// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3661 — durable evidence for a restore that no verified manifest
//! vouched for (`--skip-verify`, `--allow-unsigned-manifest`).
//!
//! # The defect this closes (audit #3645 finding F15)
//!
//! `restore` used to record such a restore with a stderr `WARNING` and a
//! fire-and-forget forensic row (`governance::audit::record_decision`, which
//! swallows writer failures). The forensic JSONL is off-database on purpose —
//! it survives the file swap — but nothing acknowledged that the row landed,
//! nothing durable existed when that sink was disabled, and the restored
//! database's own `signed_events` spine never learned that its bytes had
//! been accepted unverified. A restore bypass could complete with its only
//! evidence in terminal output or a rotated file.
//!
//! # What this module provides
//!
//! 1. **A journal beside the database path**, `<db>.restore-evidence.jsonl`
//!    ([`journal_path`]). `restore` appends an `intent` entry before it stages
//!    a byte and an `outcome` entry after it publishes; each append is
//!    `fsync`ed and reported back, so the caller can say whether it landed.
//!    The journal is a sibling FILE, not content of the database, so it
//!    survives the swap AND a rollback copy-back of the previous database.
//! 2. **Import into the signed-events spine at the next open**
//!    ([`import_at_open`], called from `storage::connection::open`): every
//!    entry not yet imported becomes one `backup.restore_unverified`
//!    signed event in whichever database is live at that path — the restored
//!    one, or the rolled-back one — with the entry's canonical bytes as the
//!    payload hash, so the spine row is bound to the journal line and to the
//!    acknowledged forensic row it names. The entry is then stamped
//!    `imported_at` (atomic rewrite), so a second open imports nothing.
//!
//! The import never refuses an open: a database must stay openable after a
//! disaster-recovery restore, and a refused open would destroy the evidence
//! path it exists to protect. Failures are logged at `error` and the entry
//! stays un-imported for the next open.
//!
//! Why not append into the restored database during `restore`? Because the
//! published file must be byte-identical to the snapshot (#3131), and
//! opening it there would create sidecars the publish guards against
//! (#3550). The next open is the first moment the database is legitimately
//! written, and it is a funnel every interface crosses.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// `tracing` target for every line this module emits.
const TRACE_TARGET: &str = "ai_memory::restore_evidence";

/// File-name suffix of the journal, appended to the database file name.
pub const JOURNAL_SUFFIX: &str = ".restore-evidence.jsonl";
/// Journal entry schema version, bumped only on an incompatible change.
pub const JOURNAL_SCHEMA: u32 = 1;
/// `phase` of the entry written before any byte is staged.
pub const PHASE_INTENT: &str = "intent";
/// `phase` of the entry written after the publish.
pub const PHASE_OUTCOME: &str = "outcome";
/// Sink outcome: the write was acknowledged.
pub const SINK_PERSISTED: &str = "persisted";
/// Sink outcome: the forensic sink is not configured in this process.
pub const SINK_DISABLED: &str = "disabled";
/// Sink outcome prefix: the write failed; the reason follows.
pub const SINK_FAILED_PREFIX: &str = "failed: ";
/// Envelope value for the spine until the next open imports the journal.
pub const SPINE_PENDING_IMPORT: &str = "pending_import_at_next_open";

/// One journal line. `imported_at` is the only field that changes after the
/// line is written; [`Self::entry_hash`] excludes it, so the hash a spine
/// row commits to is the hash of the line as `restore` wrote it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreEvidenceEntry {
    pub schema: u32,
    pub phase: String,
    pub ts: String,
    pub actor: String,
    pub snapshot: String,
    pub target: String,
    pub verification: String,
    pub detail: String,
    /// Self-hash of the ACKNOWLEDGED forensic row, when that sink persisted it.
    pub forensic_row: Option<String>,
    /// [`SINK_PERSISTED`], [`SINK_DISABLED`] or `failed: <reason>`.
    pub forensic_sink: String,
    /// Outcome entries: [`Self::entry_hash`] of the intent they complete.
    #[serde(default)]
    pub intent_ref: Option<String>,
    #[serde(default)]
    pub rollback: Option<String>,
    #[serde(default)]
    pub durable_publish: Option<bool>,
    #[serde(default)]
    pub imported_at: Option<String>,
}

impl RestoreEvidenceEntry {
    /// Canonical bytes: the entry with `imported_at` cleared.
    ///
    /// # Panics
    ///
    /// Never in practice — every field serialises; the `expect` documents
    /// that invariant (ERRORS-07).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut clone = self.clone();
        clone.imported_at = None;
        serde_json::to_vec(&clone).expect("RestoreEvidenceEntry always serialises")
    }

    /// Hex sha256 of [`Self::canonical_bytes`].
    #[must_use]
    pub fn entry_hash(&self) -> String {
        crate::signed_events::hex_lower(&crate::signed_events::payload_hash(
            &self.canonical_bytes(),
        ))
    }
}

/// `<db>.restore-evidence.jsonl` beside `target_db`.
#[must_use]
pub fn journal_path(target_db: &Path) -> PathBuf {
    let mut name = target_db
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(JOURNAL_SUFFIX);
    target_db.with_file_name(name)
}

/// Append one entry, `fsync` the file and its directory, and return the
/// journal path. Nothing is acknowledged before both syncs return.
///
/// # Errors
///
/// Serialisation, the open, the write, or either sync.
pub fn append(target_db: &Path, entry: &RestoreEvidenceEntry) -> Result<PathBuf> {
    let path = journal_path(target_db);
    let line = serde_json::to_string(entry).context("serialising restore evidence")?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening restore evidence journal {}", path.display()))?;
    writeln!(file, "{line}")
        .with_context(|| format!("appending to restore evidence journal {}", path.display()))?;
    file.sync_data()
        .with_context(|| format!("fsyncing restore evidence journal {}", path.display()))?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("fsyncing {} after the journal append", dir.display()))?;
    Ok(path)
}

/// Every parseable entry, plus how many lines were not parseable. A damaged
/// line is reported, never silently dropped — and never fatal, so one bad
/// byte cannot hide the good entries around it.
///
/// # Errors
///
/// The file exists but cannot be read.
pub fn read_journal(path: &Path) -> Result<(Vec<RestoreEvidenceEntry>, usize)> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading restore evidence journal {}", path.display()))?;
    let mut entries = Vec::new();
    let mut malformed = 0usize;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<RestoreEvidenceEntry>(line) {
            Ok(e) => entries.push(e),
            Err(_) => malformed = malformed.saturating_add(1),
        }
    }
    Ok((entries, malformed))
}

/// What one [`import_journal`] pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ImportSummary {
    /// Entries turned into signed events on this pass.
    pub imported: usize,
    /// Entries whose spine append failed (left un-imported for next time).
    pub failed: usize,
    /// Entries already imported by an earlier open.
    pub already_imported: usize,
    /// Lines that did not parse.
    pub malformed: usize,
}

/// Import every not-yet-imported entry of the journal beside `db_path` into
/// `conn`'s `signed_events` spine, then stamp the imported entries.
///
/// # Errors
///
/// The journal cannot be read or rewritten. A single failed spine append is
/// NOT an error: it is counted in [`ImportSummary::failed`] and the entry is
/// retried at the next open.
pub fn import_journal(conn: &rusqlite::Connection, db_path: &Path) -> Result<ImportSummary> {
    let path = journal_path(db_path);
    let mut summary = ImportSummary::default();
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(summary);
    }
    let (mut entries, malformed) = read_journal(&path)?;
    summary.malformed = malformed;
    let now = chrono::Utc::now().to_rfc3339();
    let mut changed = false;
    for entry in &mut entries {
        if entry.imported_at.is_some() {
            summary.already_imported = summary.already_imported.saturating_add(1);
            continue;
        }
        let event = crate::signed_events::SignedEvent::with_daemon_signature(
            crate::signed_events::payload_hash(&entry.canonical_bytes()),
            entry.actor.clone(),
            crate::signed_events::event_types::BACKUP_RESTORE_UNVERIFIED.to_string(),
            entry.ts.clone(),
            None,
        );
        match crate::signed_events::append_signed_event(conn, &event) {
            Ok(()) => {
                entry.imported_at = Some(now.clone());
                summary.imported = summary.imported.saturating_add(1);
                changed = true;
            }
            Err(e) => {
                summary.failed = summary.failed.saturating_add(1);
                tracing::error!(
                    target: TRACE_TARGET,
                    phase = %entry.phase,
                    snapshot = %entry.snapshot,
                    "restore evidence: could not append {} entry to the signed_events spine \
                     (left in the journal for the next open): {e:#}",
                    entry.phase,
                );
            }
        }
    }
    if changed {
        rewrite_journal(&path, &entries)?;
    }
    Ok(summary)
}

/// Atomic rewrite: temp file in the same directory, fsync, rename, dir fsync.
/// Malformed lines are dropped by construction here — they were counted and
/// reported by the read, and a rewrite that carried them forward could not
/// stamp them.
fn rewrite_journal(path: &Path, entries: &[RestoreEvidenceEntry]) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = path.with_extension(format!("jsonl.{}.tmp", std::process::id()));
    {
        let mut file =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        for entry in entries {
            let line = serde_json::to_string(entry).context("serialising restore evidence")?;
            writeln!(file, "{line}").with_context(|| format!("writing {}", tmp.display()))?;
        }
        file.sync_data()
            .with_context(|| format!("fsyncing {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} over {}", tmp.display(), path.display()))?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("fsyncing {} after the journal rewrite", dir.display()))?;
    Ok(())
}

/// The open-time hook: import, log, never refuse. One `stat` when there is
/// no journal, which is every open on every host that never restored
/// unverified bytes.
pub fn import_at_open(conn: &rusqlite::Connection, db_path: &Path) {
    match import_journal(conn, db_path) {
        Ok(summary) if summary.imported > 0 || summary.failed > 0 || summary.malformed > 0 => {
            tracing::warn!(
                target: TRACE_TARGET,
                imported = summary.imported,
                failed = summary.failed,
                malformed = summary.malformed,
                "restore evidence: {} unverified-restore entr(y/ies) imported into the \
                 signed_events spine of {} ({} failed, {} malformed line(s)) — #3661",
                summary.imported,
                db_path.display(),
                summary.failed,
                summary.malformed,
            );
        }
        Ok(_) => {}
        Err(e) => tracing::error!(
            target: TRACE_TARGET,
            "restore evidence: journal beside {} could not be imported (the open continues; \
             the evidence stays in the journal): {e:#}",
            db_path.display(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(phase: &str) -> RestoreEvidenceEntry {
        RestoreEvidenceEntry {
            schema: JOURNAL_SCHEMA,
            phase: phase.to_string(),
            ts: "2026-09-12T00:00:00+00:00".to_string(),
            actor: "ai:test".to_string(),
            snapshot: "/snap.db".to_string(),
            target: "/live.db".to_string(),
            verification: "skipped".to_string(),
            detail: "--skip-verify".to_string(),
            forensic_row: None,
            forensic_sink: SINK_DISABLED.to_string(),
            intent_ref: None,
            rollback: None,
            durable_publish: None,
            imported_at: None,
        }
    }

    #[test]
    fn journal_path_is_a_sibling_of_the_database_3661() {
        let p = journal_path(Path::new("/var/lib/ai-memory/ai-memory.db"));
        assert_eq!(
            p,
            PathBuf::from("/var/lib/ai-memory/ai-memory.db.restore-evidence.jsonl")
        );
    }

    #[test]
    fn entry_hash_ignores_the_import_stamp_3661() {
        let a = entry(PHASE_INTENT);
        let mut b = a.clone();
        b.imported_at = Some("later".to_string());
        assert_eq!(a.entry_hash(), b.entry_hash());
        let mut c = a.clone();
        c.detail.push('!');
        assert_ne!(a.entry_hash(), c.entry_hash());
    }

    #[test]
    fn import_is_idempotent_and_survives_a_malformed_line_3661() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("live.db");
        let conn = crate::db::open(&db).unwrap();
        append(&db, &entry(PHASE_INTENT)).unwrap();
        append(&db, &entry(PHASE_OUTCOME)).unwrap();
        // A damaged line between two good ones.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(journal_path(&db))
                .unwrap();
            writeln!(f, "{{not json").unwrap();
        }
        let before = crate::signed_events::list_signed_events(&conn, None, 100, 0)
            .unwrap()
            .len();
        let first = import_journal(&conn, &db).unwrap();
        assert_eq!(
            first,
            ImportSummary {
                imported: 2,
                failed: 0,
                already_imported: 0,
                malformed: 1
            }
        );
        let events = crate::signed_events::list_signed_events(&conn, None, 100, 0).unwrap();
        assert_eq!(events.len(), before + 2);
        assert!(
            events
                .iter()
                .any(|e| e.event_type
                    == crate::signed_events::event_types::BACKUP_RESTORE_UNVERIFIED)
        );
        let second = import_journal(&conn, &db).unwrap();
        assert_eq!(second.imported, 0);
        assert_eq!(second.already_imported, 2);
        assert_eq!(second.malformed, 0, "the rewrite dropped the damaged line");
        let (entries, _) = read_journal(&journal_path(&db)).unwrap();
        assert!(entries.iter().all(|e| e.imported_at.is_some()));
    }

    #[test]
    fn no_journal_is_a_no_op_3661() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("live.db");
        let conn = crate::db::open(&db).unwrap();
        assert_eq!(
            import_journal(&conn, &db).unwrap(),
            ImportSummary::default()
        );
    }
}
