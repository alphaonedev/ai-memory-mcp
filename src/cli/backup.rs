// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_backup` and `cmd_restore` migrations. See `cli::store` for the
//! design pattern.

use crate::cli::CliOutput;
use crate::db;
use anyhow::{Context, Result};
use clap::Args;
use std::path::{Path, PathBuf};

/// `<stem>.manifest.json` — sidecar manifest name for a snapshot stem
/// (#1558 batch 6).
fn manifest_file_name(stem: &str) -> String {
    format!("{stem}.manifest.json")
}

/// Timestamp format used for snapshot filenames. RFC3339-compatible but
/// filesystem-safe: no colons, no slashes.
const BACKUP_TS_FMT: &str = "%Y-%m-%dT%H%M%SZ";

/// Verb name threaded into the #2444 store-guard diagnostics so the refusal
/// names the command the operator actually typed.
const VERB_BACKUP: &str = "backup";
/// See [`VERB_BACKUP`].
const VERB_RESTORE: &str = "restore";

/// Backend tag stamped into [`BackupManifest::backend`]. `backup` snapshots a
/// local SQLite file via `VACUUM INTO` and refuses every other store (#2444),
/// so this is the only value it ever writes; the field exists so a restore can
/// refuse a snapshot whose backend disagrees with the resolved target.
const BACKEND_SQLITE: &str = "sqlite";

/// SQLite sidecar suffixes. A restore that publishes a new `<db>` while the
/// PREVIOUS database's `-wal` / `-shm` still sit beside it lets SQLite replay
/// stale frames INTO the restored file (#2444 — silent corruption of the
/// restored corpus); a leftover hot `-journal` is rolled back into it the same
/// way. v1.0.0 #3550 adds `-journal` to the set.
const SQLITE_SIDECAR_SUFFIXES: [&str; 3] = ["-wal", SQLITE_SHM_SUFFIX, "-journal"];

/// The WAL-index sidecar: rebuilt by SQLite from the `-wal`, so it is never
/// part of a rollback copy (a copy of it can only be stale).
const SQLITE_SHM_SUFFIX: &str = "-shm";

/// Append a byte suffix to a path without going through `to_string_lossy`,
/// so a non-UTF-8 database path keeps its exact bytes.
fn sidecar_path(base: &Path, suffix: &str) -> PathBuf {
    let mut raw = base.as_os_str().to_os_string();
    raw.push(suffix);
    PathBuf::from(raw)
}

/// Is anything — file, directory, dangling symlink — present at `path`?
/// `Path::exists` follows symlinks and answers `false` for a dangling one,
/// which would let a planted link survive beside the published database.
fn path_present(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// v1.0.0 #3550 — the publish steps a restore passes through, in order.
///
/// `PublishIo::at` is told each one as it is reached; the crash-injection
/// tests stop the restore at every step and check what is left on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishStep {
    /// The replacement is staged, fsynced and verified; nothing live touched.
    Staged,
    /// The old database is exclusively locked, checkpointed and fsynced.
    Locked,
    /// The old database is copied aside and the staged file is locked too.
    AsideCopied,
    /// The live sidecars are gone; the old database is still at the target.
    SidecarsCleared,
    /// The directory holding the unlinks + staged entry is fsynced; next is
    /// the rename.
    PrePublishSynced,
    /// The rename landed: the verified replacement is at the target.
    Published,
    /// The directory entry of the rename is fsynced (or reported not to be).
    PostPublishSynced,
}

/// v1.0.0 #3550 — the filesystem operations whose failure changes what the
/// restore does, behind a seam so tests can inject each failure. Production
/// uses [`RealPublishIo`], which is exactly the std call.
trait PublishIo {
    /// Unlink one live sidecar before the publish.
    fn remove_sidecar(&mut self, path: &Path) -> std::io::Result<()> {
        std::fs::remove_file(path)
    }
    /// Fsync the directory `dir`.
    fn sync_dir(&mut self, dir: &Path) -> std::io::Result<()> {
        sync_dir(dir)
    }
    /// Observation point: `step` has just been reached.
    fn at(&mut self, _step: PublishStep, _target: &Path) {}
}

/// The production [`PublishIo`]: no hooks, real syscalls.
struct RealPublishIo;

impl PublishIo for RealPublishIo {}

/// v1.0.0 #3550 — remove the live `-wal` / `-shm` / `-journal` BEFORE the
/// replacement is published, and REFUSE the publish if any of them cannot be
/// removed.
///
/// Before #3550 this ran after the rename and only warned on failure, so for
/// the whole window between the two a daemon starting on the new file would
/// replay the old database's WAL into it — and on an unlink failure it did so
/// indefinitely. Nothing is lost by removing them first: the caller has
/// already checkpointed the old database under its exclusive lock (so the
/// `-wal` holds no frames the main file lacks) and copied the whole set
/// aside, and the `-shm` is a rebuildable index.
///
/// # Errors
/// A sidecar could not be removed, or something is still there afterwards.
fn clear_live_sidecars(target_db: &Path, io: &mut dyn PublishIo) -> Result<()> {
    for suffix in SQLITE_SIDECAR_SUFFIXES {
        let live_sidecar = sidecar_path(target_db, suffix);
        if !path_present(&live_sidecar) {
            continue;
        }
        io.remove_sidecar(&live_sidecar).with_context(|| {
            format!(
                "could not remove the SQLite sidecar {} — refusing to publish the \
                 restore: a leftover sidecar beside the restored database would replay \
                 the old database's frames into it. Nothing was published: the \
                 previous database is still in place (its rollback copy was taken \
                 first). Remove the sidecar and re-run (#3550)",
                live_sidecar.display()
            )
        })?;
        if path_present(&live_sidecar) {
            anyhow::bail!(
                "the SQLite sidecar {} is still present after it was removed — refusing \
                 to publish the restore; nothing was published (#3550)",
                live_sidecar.display()
            );
        }
    }
    Ok(())
}

/// v1.0.0 #3131 — filename infix of the pre-restore rollback copy
/// (`<db>.pre-restore-<ts>.db`). Named so the operator can find it, and
/// so the rollback line printed by `restore` and the `--json`
/// `rollback` field are single-sourced.
const PRE_RESTORE_INFIX: &str = "pre-restore";

/// v1.0.0 #3131 — filename infix of the same-directory staging file the
/// verified replacement is written to before the atomic rename.
const RESTORE_TMP_INFIX: &str = "restore-tmp";

/// v1.0.0 #3131 — `restore --json` cannot prompt: an interactive question
/// on the JSON path would corrupt the envelope the caller is parsing.
pub const RESTORE_JSON_REQUIRES_YES: &str = "restore: --json requires --yes (restore REPLACES the live database; \
     a confirmation prompt would corrupt the JSON envelope)";

/// v1.0.0 #3131 — nobody is there to answer a prompt when stdin is not a
/// terminal (cron, CI, a pipe), and a destructive verb must not proceed on
/// silence.
pub const RESTORE_NON_INTERACTIVE_REQUIRES_YES: &str = "restore: --yes is required when stdin is not a terminal (restore \
     REPLACES the live database and there is nobody to confirm)";

/// v1.0.0 #3131 — does this invocation still need operator confirmation?
///
/// Pulled out as a predicate (the shape `cli::forget` already uses for its
/// `--confirm-global` safety rail) so the contract is testable without
/// driving stdin.
#[must_use]
pub fn restore_requires_confirmation(args: &RestoreArgs) -> bool {
    !args.yes
}

/// v1.0.0 #3131 — refuse the restore while anything still holds the target
/// database open.
///
/// This deployment model has no daemon pidfile or lockfile — `cli::doctor`
/// says so in as many words ("the CLI process is *not* the running daemon")
/// — so the authoritative liveness signal is SQLite's own locking. Opening
/// the target read-write (never CREATE) under `locking_mode = EXCLUSIVE`
/// and starting a transaction takes the exclusive database/shm lock, which
/// answers `SQLITE_BUSY` / `SQLITE_LOCKED` while ANY other connection —
/// daemon, MCP server, curator, a second CLI — has the file open. The
/// transaction is rolled back, so the probe writes nothing of its own.
///
/// Only a POSITIVE liveness signal refuses. Any other failure (a corrupt or
/// unreadable target, a permissions problem) is WARNed and allowed to
/// proceed on purpose: restoring over a database nothing can open any more
/// is precisely the disaster-recovery case this verb exists for, and
/// refusing there would strand the operator.
///
/// v1.0.0 #3550 — on success the probe's connection is RETURNED instead of
/// dropped: it keeps holding the exclusive lock, and the caller holds it
/// through the aside copy and the publish, so a writer that starts
/// mid-restore is refused by SQLite instead of writing into the file being
/// copied and replaced. `None` means there was nothing to lock (no target)
/// or the probe could not run (the warn-and-proceed arms above).
///
/// # Errors
/// The target is open in another connection.
fn refuse_if_target_in_use(
    target_db: &Path,
    out: &mut CliOutput<'_>,
) -> Result<Option<rusqlite::Connection>> {
    if !target_db.exists() {
        return Ok(None);
    }
    match lock_exclusive(target_db) {
        Ok(conn) => {
            // #2445 — this raw open is off `db::open` on purpose (a
            // liveness probe must not run the bootstrap/ladder against
            // the live file). Guard the schema-downgrade / rollback-
            // evidence checks immediately after the exclusive lock is
            // held so the bypass is not a silent #2488.
            crate::storage::assert_schema_not_ahead(&conn, &target_db.display().to_string())?;
            Ok(Some(conn))
        }
        Err(LockError::Busy(e)) => anyhow::bail!(
            "{} is open in another process — refusing to restore over a live \
             database (a daemon / MCP server writing into the file being replaced \
             produces mixed pages plus an orphaned WAL). Stop it and re-run. \
             (#3131: {e})",
            target_db.display()
        ),
        Err(LockError::Open(e)) => {
            writeln!(
                out.stderr,
                "warning: cannot open {} to check whether it is in use ({e}); \
                 proceeding — stop any daemon/MCP server on this database first (#3131)",
                target_db.display()
            )?;
            Ok(None)
        }
        Err(LockError::Probe(e)) => {
            writeln!(
                out.stderr,
                "warning: liveness probe on {} was inconclusive ({e}); proceeding — \
                 stop any daemon/MCP server on this database first (#3131)",
                target_db.display()
            )?;
            Ok(None)
        }
    }
}

/// Why [`lock_exclusive`] did not return a held lock (each carries the
/// underlying error's message).
enum LockError {
    /// The file could not be opened read-write at all.
    Open(String),
    /// Another connection holds the database — a POSITIVE liveness signal.
    Busy(String),
    /// The lock could not be taken for any other reason (not a database,
    /// wrong key, unreadable WAL).
    Probe(String),
}

/// Open `path` read-write (never CREATE), and take and KEEP SQLite's
/// exclusive lock on it: `locking_mode = EXCLUSIVE` before the first access,
/// then `BEGIN EXCLUSIVE; ROLLBACK;`. The transaction writes nothing, and in
/// exclusive locking mode the lock is retained until the connection closes,
/// so the returned connection IS the lock. Any other opener meanwhile gets
/// `SQLITE_BUSY` before it can read a page or create a sidecar.
///
/// This is the one raw (off-`db::open`) connection site in this module; the
/// target probe and the staged-file lock both go through it.
fn lock_exclusive(path: &Path) -> std::result::Result<rusqlite::Connection, LockError> {
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
        | rusqlite::OpenFlags::SQLITE_OPEN_URI
        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = rusqlite::Connection::open_with_flags(path, flags)
        .map_err(|e| LockError::Open(e.to_string()))?;
    // Answer immediately rather than queueing behind a live writer. A
    // failure to set it only means the probe below may wait; it is not a
    // reason to stop.
    let _ = conn.busy_timeout(std::time::Duration::from_millis(0));
    // v1.0.0 #3550 — a SQLCipher database must be keyed before its pages can
    // be read, or the lock below could never be taken and held (the probe
    // would read as inconclusive on every encrypted deployment).
    crate::storage::connection::apply_sqlcipher_key(&conn)
        .map_err(|e| LockError::Probe(format!("{e:#}")))?;
    conn.pragma_update(None, "locking_mode", "exclusive")
        .and_then(|()| conn.execute_batch("BEGIN EXCLUSIVE; ROLLBACK;"))
        .map_err(|e| {
            if is_busy(&e) {
                LockError::Busy(e.to_string())
            } else {
                LockError::Probe(e.to_string())
            }
        })?;
    Ok(conn)
}

/// v1.0.0 #3550 — fold every committed frame of the old database's WAL into
/// the main file, under the exclusive lock, before its `-wal` is removed.
/// Anything short of a complete checkpoint is a refusal: removing a `-wal`
/// that still carries frames the main file lacks would lose them.
///
/// # Errors
/// The checkpoint fails or reports frames it could not move.
fn checkpoint_before_sidecar_removal(conn: &rusqlite::Connection, target_db: &Path) -> Result<()> {
    // The checkpoint fsyncs the database file before it truncates the WAL
    // only at `synchronous >= NORMAL`; ask for FULL rather than inherit.
    conn.pragma_update(None, crate::storage::connection::PRAGMA_SYNCHRONOUS, "FULL")
        .with_context(|| format!("setting synchronous=FULL on {}", target_db.display()))?;
    // (busy, frames in the WAL, frames checkpointed); -1 when not in WAL mode.
    let (busy, log, checkpointed): (i64, i64, i64) = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .with_context(|| {
            format!(
                "checkpointing {} before the restore replaces it — refusing to \
                 remove a WAL that may hold frames the database file lacks (#3550)",
                target_db.display()
            )
        })?;
    if busy != 0 || log != checkpointed {
        anyhow::bail!(
            "could not fully checkpoint {} (busy={busy}, wal frames={log}, \
             checkpointed={checkpointed}) — refusing to restore: removing its WAL \
             would lose committed frames. The live database is untouched (#3550)",
            target_db.display()
        );
    }
    Ok(())
}

/// Is this rusqlite error a POSITIVE "someone else holds the lock" signal
/// (as opposed to corruption / permissions / anything else)?
fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::DatabaseBusy
                || err.code == rusqlite::ErrorCode::DatabaseLocked
    )
}

/// v1.0.0 #3550 — fsync the directory `dir`, so a rename / unlink inside it
/// survives a power cut, and SAY whether it worked.
///
/// This used to be a deliberately infallible `let _ = handle.sync_all()`. A
/// lost directory fsync after power loss brings the OLD directory entry back
/// — the replaced database reappears in place of the verified restore — so
/// the result is reported (`durable_publish` in `--json`) and, under
/// `asi-hard`, enforced. On a platform where a directory cannot be opened as
/// a file the answer is an honest `Unsupported`, never a silent pass (the
/// `governance::deferred_audit::sync_directory` precedent).
///
/// # Errors
/// The directory cannot be opened, the fsync fails, or the platform has no
/// directory fsync.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "directory fsync is unsupported on this platform",
        ))
    }
}

/// The directory a restore publishes into: the target's parent, or `.` for
/// a bare relative file name (`Path::parent` answers `""` there).
fn publish_dir(target_db: &Path) -> &Path {
    match target_db.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// Size of the SQLite database file header.
#[cfg(unix)]
const SQLITE_HEADER_BYTES: usize = 100;

/// v1.0.0 #3550 — make the orphaned OLD database inode unusable after the
/// rename has replaced it, so a process that opened the target path during
/// the restore (and was held off by the exclusive lock) fails loudly with
/// "file is not a database" once the lock is released, instead of carrying
/// on against the orphan and creating `<target>-wal` BY NAME beside the
/// restored database — a WAL SQLite would then replay into the restore,
/// silently reverting it. (Measured on SQLite 3.53: without this, a reader of
/// the restored file afterwards sees the OLD rows plus the stray write.)
///
/// Only an inode with ZERO remaining links is touched: `old` was opened on
/// the target path before the rename, the rename unlinked it, and the aside
/// copy is a separate file. If anything else still links the inode (an
/// operator's hard link), it is a live database somewhere and is left alone.
/// Returns whether the header was overwritten.
///
/// # Errors
/// The fstat, the write, or its fsync fails.
#[cfg(unix)]
fn poison_orphaned_inode(old: &std::fs::File) -> std::io::Result<bool> {
    use std::os::unix::fs::{FileExt, MetadataExt};
    if old.metadata()?.nlink() != 0 {
        return Ok(false);
    }
    // The whole 100-byte database header: the magic ("SQLite format 3\0", or
    // a SQLCipher file's salt) so a cold opener fails, AND the file change
    // counter at bytes 24..28, so a connection holding a warm page cache sees
    // the file changed and re-reads page 1 instead of trusting its cache.
    old.write_all_at(&[0u8; SQLITE_HEADER_BYTES], 0)?;
    old.sync_all()?;
    Ok(true)
}

/// Test helper: [`stage_snapshot`] then [`verify_staged_integrity`] — the
/// production sequence runs the manifest and schema checks between the two.
#[cfg(test)]
fn stage_and_verify(
    snapshot: &Path,
    staged: &Path,
    out: &mut CliOutput<'_>,
    json_out: bool,
) -> Result<()> {
    stage_snapshot(snapshot, staged)?;
    verify_staged_integrity(staged, out, json_out)
}

/// Owner-only mode for a file restore creates before it knows better (the
/// staged replacement, a rollback copy of a target that had no mode to copy).
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;

/// v1.0.0 #3550 — copy `src` into a file that did NOT exist at `dest`, then
/// fsync it through the same handle.
///
/// `create_new` (O_CREAT|O_EXCL) refuses a pre-existing file AND a symlink
/// planted at the predictable name — `std::fs::copy` would truncate the
/// first and write through the second. The file starts owner-only; the
/// caller widens it deliberately when it must match another file.
///
/// # Errors
/// `dest` exists, or the copy or the fsync fails.
fn copy_into_new_file(src: &mut impl std::io::Read, dest: &Path) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, PRIVATE_FILE_MODE);
    let mut file = options
        .open(dest)
        .with_context(|| format!("creating {}", dest.display()))?;
    let written = std::io::copy(src, &mut file)
        .with_context(|| format!("writing {}", dest.display()))
        .and_then(|_| {
            file.sync_all()
                .with_context(|| format!("fsyncing {}", dest.display()))
        });
    if written.is_err() {
        // This call created the file, so a partial one is ours to remove.
        drop(file);
        let _ = std::fs::remove_file(dest);
    }
    written
}

/// v1.0.0 #3131/#3550 — copy the snapshot to the staging path beside the
/// target and make it durable. Durability BEFORE verification: a check that
/// passes on page-cached bytes proves nothing about what survives a power
/// cut.
///
/// # Errors
/// The snapshot cannot be read, or the staged file cannot be created
/// (including because something already sits at its name), written or
/// fsynced.
fn stage_snapshot(snapshot: &Path, staged: &Path) -> Result<()> {
    let mut src = std::fs::File::open(snapshot)
        .with_context(|| format!("opening snapshot {}", snapshot.display()))?;
    copy_into_new_file(&mut src, staged).with_context(|| {
        format!(
            "staging the restore at {} (the live database is untouched)",
            staged.display()
        )
    })
}

/// v1.0.0 #3131 — REFUSE the staged replacement unless the whole file
/// verifies.
///
/// `staged` lives in the same directory as the target, so the caller's
/// `rename` is an atomic, same-filesystem swap. A partial copy (ENOSPC, an
/// interrupt) or a structurally damaged snapshot therefore fails HERE, while
/// the operator's original is still the file at the target path — the live
/// corpus is never the thing left truncated.
///
/// v1.0.0 #3508/#3510 — the verdict comes from
/// [`crate::storage::sqlite_integrity::check`], the ONE implementation of the
/// whole-database check: `PRAGMA integrity_check` answering `ok` stopped
/// meaning "every page was examined" the moment a root-less schema object
/// (the v98 `inbox_namespace_aliases` VIEW, `memories_fts`) could head the
/// schema hash, and the shared helper re-asserts the page accounting SQLite
/// then skips. Which control carried the verdict is PRINTED rather than
/// logged: the #3508 residual was a `tracing::warn!` no CLI surface could
/// see, and a disaster-recovery gate that cannot say what it checked is not
/// a gate an operator can rely on.
///
/// # Errors
/// The staged file cannot be opened, it fails the integrity verdict, or this
/// build cannot COMPLETE the check (no `dbstat`, an unreadable auto-vacuum
/// geometry) — in which case it refuses rather than publishing a replacement
/// it could not verify.
fn verify_staged_integrity(staged: &Path, out: &mut CliOutput<'_>, json_out: bool) -> Result<()> {
    let probe = db::open_read_only(staged).with_context(|| {
        format!(
            "the staged restore {} is not a readable SQLite database — refusing to \
             publish it over the live corpus (#3131)",
            staged.display()
        )
    })?;
    let soundness = crate::storage::sqlite_integrity::check(&probe).with_context(|| {
        format!(
            "running the whole-database integrity check (PRAGMA integrity_check \
             plus the #3508 page accounting) on the staged restore {} — refusing \
             to publish a replacement this build cannot verify (#3131/#3510)",
            staged.display()
        )
    })?;
    match soundness {
        crate::storage::sqlite_integrity::Soundness::Unsound(reason) => anyhow::bail!(
            "the staged restore {} {reason} — refusing to publish it; the live \
             database is untouched (#3131)",
            staged.display()
        ),
        crate::storage::sqlite_integrity::Soundness::Sound(coverage) => {
            report_integrity_coverage(staged, coverage, out, json_out)
        }
    }
}

/// v1.0.0 #3510 — say, on the operator's own output, HOW MUCH of the staged
/// restore was actually verified.
///
/// The #3508 control could only WARN through `tracing`, which the CLI has no
/// subscriber for, so a restore whose coverage was carried by the
/// page-accounting fallback looked identical to one SQLite checked in full.
/// Routed through [`CliOutput::human_line`] so the line goes to stderr under
/// `--json` and never breaks the envelope.
fn report_integrity_coverage(
    staged: &Path,
    coverage: crate::storage::sqlite_integrity::Coverage,
    out: &mut CliOutput<'_>,
    json_out: bool,
) -> Result<()> {
    use crate::storage::sqlite_integrity::Coverage;
    match coverage {
        // SQLite examined the whole file itself; nothing to qualify.
        Coverage::WholeFileBySqlite => Ok(()),
        Coverage::WholeFileByPageAccounting(census) => {
            out.human_line(
                json_out,
                format_args!(
                    "Verified all {declared} pages of {path} (b-tree {reachable} + \
                     freelist {freelist} + pointer-map {pointer_map} + pending-byte \
                     {pending_byte}): a root-less object in the schema makes SQLite \
                     run PRAGMA integrity_check as a PARTIAL check, so the page \
                     accounting is what covered this file (#3508/#3510).",
                    declared = census.page_count,
                    path = staged.display(),
                    reachable = census.reachable,
                    freelist = census.freelist,
                    pointer_map = census.pointer_map,
                    pending_byte = census.pending_byte,
                ),
            )?;
            Ok(())
        }
    }
}

/// v1.0.0 #3131 — the interactive `[y/N]` gate. Mirrors
/// `cli::governance_install_defaults::confirm_proceed` so every destructive
/// verb asks the same question the same way.
fn confirm_restore(out: &mut CliOutput<'_>) -> Result<bool> {
    write!(out.stdout, "Proceed? [y/N]: ")?;
    // Deliberate discard: a failed flush on the prompt is not a reason to
    // refuse — the read below is what decides.
    let _ = out.stdout.flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("restore: read stdin")?;
    let trimmed = answer.trim().to_ascii_lowercase();
    Ok(matches!(trimmed.as_str(), "y" | "yes"))
}

#[derive(Args)]
pub struct BackupArgs {
    /// Directory where the snapshot and manifest are written. Created if
    /// missing.
    #[arg(long, default_value = "./backups")]
    pub to: PathBuf,
    /// Retention: after writing a new snapshot, delete the oldest
    /// snapshots so that at most this many remain. 0 disables rotation.
    #[arg(long, default_value_t = 48)]
    pub keep: usize,
    /// Store URL this deployment serves, in the same grammar `serve` /
    /// `curator` accept (`sqlite:///path` or `postgres://…`). Declaring it
    /// makes `backup` REFUSE a store it cannot capture instead of snapshotting
    /// an unrelated local file (#2444). Also read, without this flag, from
    /// `AI_MEMORY_STORE_URL_FILE` / `AI_MEMORY_STORE_URL`.
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,
}

#[derive(Args)]
pub struct RestoreArgs {
    /// Path to a snapshot file OR a backup directory. When a directory is
    /// supplied, pass `--snapshot` to name the snapshot; without it the
    /// newest snapshot BY MODIFICATION TIME is used, with a warning.
    #[arg(long)]
    pub from: PathBuf,
    /// v1.0.0 #3550 — the snapshot to restore from a `--from` DIRECTORY:
    /// its file name (`ai-memory-<ts>.db`), its id (`ai-memory-<ts>`, the
    /// name without the extension, shared with its manifest), or its
    /// manifest's file name (`ai-memory-<ts>.manifest.json`). A plain name,
    /// never a path. Without it the newest snapshot by mtime is used, which
    /// is not an integrity signal — anyone who can write the directory can
    /// set it.
    #[arg(long, value_name = "NAME")]
    pub snapshot: Option<String>,
    /// Skip sha256 verification against the manifest. Not recommended.
    #[arg(long)]
    pub skip_verify: bool,
    /// Store URL this deployment serves — see `backup --store-url`. Restoring
    /// a SQLite snapshot onto a Postgres-backed deployment would report
    /// success while leaving the real corpus untouched, so it is REFUSED
    /// (#2444).
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,
    /// v1.0.0 #3131 — skip the interactive confirmation. `restore` REPLACES
    /// the live database, so without this it asks `Proceed? [y/N]` first;
    /// it is REQUIRED with `--json` and whenever stdin is not a terminal.
    #[arg(long)]
    pub yes: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BackupManifest {
    pub snapshot: String,
    pub sha256: String,
    pub bytes: u64,
    pub source_db: String,
    pub version: String,
    pub created_at: String,
    /// #2444 — which backend produced this snapshot ([`BACKEND_SQLITE`]).
    /// `#[serde(default)]` so a pre-#2444 manifest still deserialises; a
    /// `None` here means "written before the field existed", NOT "unknown
    /// backend", and is therefore accepted by restore.
    #[serde(default)]
    pub backend: Option<String>,
    /// #2444 — the applied migration-ladder version of the captured database,
    /// so a restore can refuse a snapshot from a NEWER binary whose extra
    /// columns this build would silently drop on the next write.
    #[serde(default)]
    pub schema_version: Option<i64>,
    /// #2444 — live `memories` row count at capture time. Recorded (not
    /// enforced) so an operator reading the manifest can see at a glance that
    /// a snapshot captured nothing.
    #[serde(default)]
    pub memory_count: Option<i64>,
}

/// #2444 — resolve the local SQLite file a `backup` / `restore` invocation is
/// allowed to act on, or REFUSE.
///
/// `ai-memory backup` is a SQLite-only control: it snapshots via SQLite's
/// `VACUUM INTO`. Before #2444 it took the `--db` path unconditionally, and
/// [`crate::db::open`] CREATES a missing file (running the full bootstrap +
/// migration ladder on it), so on a Postgres-backed deployment the command
/// manufactured an empty SQLite database, VACUUMed it into a timestamped
/// snapshot, wrote a VALID sha256 manifest, rotated `--keep`, and exited 0.
/// Every signal the operator had said the backup succeeded; the DR restore
/// returned nothing. This resolves the CONFIGURED store first and refuses
/// anything it cannot capture.
///
/// Resolution mirrors the daemon exactly — [`crate::daemon_runtime::resolve_store_url`]
/// (`AI_MEMORY_STORE_URL_FILE` > `AI_MEMORY_STORE_URL` > the `--store-url`
/// argument, #1927) — so `backup` reads the store from the same channels
/// `serve` does rather than re-deriving its own notion of it.
/// v1.0.0 #2490 — what [`resolve_sqlite_store`] does when a `sqlite://`
/// store URL names a DIFFERENT file than `--db`.
///
/// The #2444 disposition (kept for `backup` / `restore` / `export`) is to
/// act on the CONFIGURED store and say so loudly, because the store URL is
/// authoritative for `serve`. That is right for a READ: the worst case is
/// snapshotting the wrong file, which costs time.
///
/// It is NOT right for a WRITE. `docs/postgres-age-guide.md` and
/// `docs/production-deployment.md` both instruct operators to `export
/// AI_MEMORY_STORE_URL` at shell/cron scope, so an ambient sqlite store URL
/// would silently redirect `ai-memory --db ./scratch.db import < bundle.json`
/// into the deployment's REAL database — turning a scratch import into a
/// production write behind a one-line `note:`. A write verb REFUSES the
/// disagreement instead (5-agent vote 4d3ea1c5, falsification-lens F5, the
/// single biggest risk identified in the review).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreDisagreement {
    /// READ verbs: act on the configured store, note it on stderr (#2444).
    RedirectWithNote,
    /// WRITE verbs: refuse rather than write to a file the operator did not
    /// name on the command line.
    Refuse,
}

/// `backup` / `restore` entry point — the #2444 read-verb disposition.
fn resolve_sqlite_source(
    db_path: &Path,
    store_url_arg: Option<&str>,
    verb: &str,
    out: &mut CliOutput<'_>,
) -> Result<PathBuf> {
    resolve_sqlite_store(
        db_path,
        store_url_arg,
        verb,
        StoreDisagreement::RedirectWithNote,
        None,
        out,
    )
}

/// v1.0.0 #2572 — HTTP-daemon remedy hint threaded into the Postgres refusal
/// for the class-(a) CLI write/read verbs (see [`refuse_pg_store`]).
pub(crate) const PG_CLI_ALTERNATIVE: &str = "the local SQLite CLI cannot reach a \
    Postgres store — a write would land in a throwaway SQLite file the Postgres \
    deployment never reads (reported as success while the data is silently LOST), \
    and a read would return an empty conjured database. Route this operation \
    through the HTTP daemon (`ai-memory serve`) or MCP-over-HTTP instead; see \
    docs/production-deployment.md";

/// v1.0.0 #2572 — the shared Postgres-refusal funnel for the class-(a) CLI
/// verbs (`store` / `link` / `update` / `promote` / `forget` / `delete` / `gc`
/// / `archive` / `consolidate` / `namespace` / `reown` / `share` / `offload` /
/// `reflect` / `atomise` / `reembed` / `mine` / `sync` / `calibrate confidence`).
///
/// Each of those verbs opens the local SQLite `--db` directly; on a
/// Postgres-served deployment (`AI_MEMORY_STORE_URL=postgres://…`, the #1927
/// non-argv channel, or `--store-url`) that write phantom-lands in a throwaway
/// SQLite file the served store never reads — reporting success while the data
/// is LOST (the exact #2490 class PR #2568 closed for the durability verbs).
/// This gate resolves the configured store BEFORE `db::open` and REFUSES a
/// Postgres URL (5-agent vote `4d3ea1c5`, UNANIMOUS REFUSE). The Route-through-
/// SAL capability is deferred to #2772.
///
/// Returns the resolved local SQLite path (byte-identical to `db_path` in every
/// `Ok` case) so the caller opens exactly what it would have, or the typed
/// Postgres / ambiguous-store refusal. `store_url_arg` is `None` because no
/// class-(a) verb carries a `--store-url` flag; the env channels
/// (`AI_MEMORY_STORE_URL_FILE` > `AI_MEMORY_STORE_URL`) are still consulted.
///
/// # Errors
///
/// Refuses on a Postgres store URL, an unrecognised scheme, an argv/env
/// store-URL disagreement, an empty `sqlite://` path, or a `sqlite://` path that
/// disagrees with `--db` (WRITE disposition — never a silent redirect).
pub(crate) fn refuse_pg_store(
    db_path: &Path,
    verb: &str,
    out: &mut CliOutput<'_>,
) -> Result<PathBuf> {
    resolve_sqlite_store(
        db_path,
        None,
        verb,
        StoreDisagreement::Refuse,
        Some(PG_CLI_ALTERNATIVE),
        out,
    )
}

/// v1.0.0 #2490 — the shared store-resolution gate, reused verbatim by
/// `export` / `export --full` / `import` so the refusal SET cannot drift
/// between the durability verbs.
///
/// # Errors
///
/// Refuses (never falls back to `--db`) on: a Postgres store URL, an
/// unrecognised scheme, an argv/env store-URL disagreement, an empty
/// `sqlite://` path, and — under [`StoreDisagreement::Refuse`] — a
/// `sqlite://` path that disagrees with `--db`.
///
/// v1.0.0 #2572 — `pg_alternative` names the store-appropriate remedy in the
/// Postgres-refusal message. `None` (backup / restore / export / import) keeps
/// the #2444/#2490 pg-native-dump guidance verbatim; `Some(hint)` (the class-(a)
/// CLI write/read verbs) points the operator at the HTTP daemon instead, since a
/// local-SQLite write cannot reach a Postgres store.
pub(crate) fn resolve_sqlite_store(
    db_path: &Path,
    store_url_arg: Option<&str>,
    verb: &str,
    disagreement: StoreDisagreement,
    pg_alternative: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<PathBuf> {
    use crate::daemon_runtime::{SQLITE_URL_SCHEME, is_postgres_url, resolve_store_url};
    use crate::logging::redact_url_password;

    // Ambiguity is REFUSED, never silently resolved. `resolve_store_url` gives
    // the env channels precedence over the argv flag (#1927), so an explicit
    // `--store-url` that DISAGREES with an exported AI_MEMORY_STORE_URL would
    // otherwise capture a store the operator did not name — on a durability
    // command "which store did I actually snapshot?" must never be a guess.
    if let Some(arg) = store_url_arg {
        if let Some(env_url) = resolve_store_url(None)? {
            if env_url.trim() != arg.trim() {
                anyhow::bail!(
                    "ambiguous store: --store-url names {} but the environment \
                     (AI_MEMORY_STORE_URL / AI_MEMORY_STORE_URL_FILE) names {}. \
                     Refusing to guess which store `{verb}` should act on — \
                     unset one of them (#2444).",
                    redact_url_password(arg),
                    redact_url_password(&env_url),
                );
            }
        }
    }

    let Some(url) = resolve_store_url(store_url_arg)? else {
        // No store URL on any channel: the configured store IS the local
        // sqlite `--db` path. Unchanged pre-#2444 behaviour.
        return Ok(db_path.to_path_buf());
    };

    if is_postgres_url(&url) {
        if let Some(alt) = pg_alternative {
            anyhow::bail!(
                "`ai-memory {verb}` operates on a local SQLite database only, but this \
                 deployment's configured store is Postgres ({}). Refusing — {alt} (#2572).",
                redact_url_password(&url)
            );
        }
        anyhow::bail!(
            "`ai-memory {verb}` acts on a local SQLite database only, but this \
             deployment's configured store is Postgres ({}). Refusing — a SQLite \
             artifact would NOT contain the corpus, and a restore from it would \
             silently return nothing. Use `pg_dump` (or `pg_basebackup` + WAL \
             archiving) instead; see docs/production-deployment.md (#2444, #2490).",
            redact_url_password(&url)
        );
    }

    if let Some(path) = url.strip_prefix(SQLITE_URL_SCHEME) {
        // `sqlite:///abs` → `/abs`; `sqlite://./rel` → `./rel`. Same
        // normalisation `migrate::open_store` applies, so the two agree on
        // which file a given URL names.
        let clean = path
            .strip_prefix('/')
            .map_or(path, |p| if p.starts_with('/') { p } else { path });
        if clean.is_empty() {
            anyhow::bail!(
                "store URL {SQLITE_URL_SCHEME} names no path — refusing to guess \
                 which database `{verb}` should act on (#2444)"
            );
        }
        let resolved = PathBuf::from(clean);
        if resolved != db_path {
            match disagreement {
                StoreDisagreement::RedirectWithNote => {
                    // The store URL is authoritative for `serve`
                    // (`build_store_handle` takes it over `--db`), so it is
                    // authoritative here too. Say so loudly rather than
                    // silently capturing a different file.
                    writeln!(
                        out.stderr,
                        "note: acting on the configured store {} (the --db path {} is not the store)",
                        resolved.display(),
                        db_path.display()
                    )?;
                }
                StoreDisagreement::Refuse => {
                    // #2490 — `{verb}` WRITES. Redirecting a write to a file
                    // the operator did not name is worse than refusing it.
                    anyhow::bail!(
                        "ambiguous target: the configured store is {} but --db names {}. \
                         Refusing — `ai-memory {verb}` WRITES, and an ambient \
                         AI_MEMORY_STORE_URL (the documented cron/shell posture) would \
                         otherwise redirect this write into a database you did not name \
                         on the command line. Point --db at the configured store, or \
                         unset the store URL for this invocation (#2490).",
                        resolved.display(),
                        db_path.display()
                    );
                }
            }
        }
        return Ok(resolved);
    }

    anyhow::bail!(
        "unrecognised store URL: {} (expected sqlite:///path or postgres://...). \
         Refusing to fall back to the local --db file, because that would produce \
         a snapshot of a database this deployment does not serve (#2444).",
        redact_url_password(&url)
    )
}

/// `backup` handler.
pub fn run_backup(
    db_path: &Path,
    args: &BackupArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    use std::io::Read;
    // #2444 — resolve (and where necessary REFUSE) the configured store BEFORE
    // anything is created on disk. A backup that cannot capture the configured
    // store must ERROR, never produce an artifact.
    let source_db = resolve_sqlite_source(db_path, args.store_url.as_deref(), VERB_BACKUP, out)?;
    // #2444 — `db::open` CREATES the file when absent (src/storage/connection.rs)
    // and then runs the bootstrap schema + the whole migration ladder on it, so
    // the created file is NOT distinguishable from a real database by any
    // schema probe. The only honest discriminator is that it did not exist, so
    // check that before the open can bring it into being.
    if !source_db.exists() {
        anyhow::bail!(
            "no SQLite database at {} — refusing to create one and snapshot it. \
             A backup of a database that does not exist would produce an empty \
             artifact carrying a VALID checksum, and the DR restore from it \
             would silently return nothing (#2444).",
            source_db.display()
        );
    }
    std::fs::create_dir_all(&args.to)
        .with_context(|| format!("creating backup dir {}", args.to.display()))?;
    // SQLite VACUUM INTO is hot-backup-safe and produces a defragmented
    // file. Equivalent to `sqlite3 source '.backup dest'` in effect but
    // runs in-process via our existing connection.
    // v1.0.0 #2445 — EGRESS FALLBACK. `db::open` now REFUSES a database whose
    // schema is ahead of this binary, and that refusal must never cost the
    // operator their backup: snapshotting the durable text is the FIRST thing
    // a competent operator does in exactly this incident, and `VACUUM INTO`
    // copies bytes it does not have to understand. So on that ONE typed error
    // we re-open through the unmigrated funnel (no bootstrap DDL, no ladder,
    // no trigger install) and proceed. Every other open failure still
    // propagates. `open_read_only` cannot serve this path — `PRAGMA
    // query_only = ON` refuses `VACUUM INTO` (verified, not assumed).
    //
    // v1.0.0 #2564 — the ZEROED-stamp refusal takes the SAME fallback, and it
    // needs it even more urgently. That refusal's operator message states
    // "`ai-memory backup` continues to operate against this database, so
    // snapshot it before doing anything else"; without this arm that sentence
    // would be a lie and the one instruction we give the operator in a
    // destroyed-stamp incident would fail. The two refusals share the exact
    // property that makes the fallback sound: neither says the BYTES are
    // untrustworthy, only that this binary must not MIGRATE them, and
    // `VACUUM INTO` copies bytes it does not have to understand.
    let conn = match db::open(&source_db) {
        Ok(conn) => conn,
        Err(e)
            if crate::storage::schema_guard::schema_ahead_of(&e).is_some()
                || crate::storage::schema_guard::schema_stamp_zeroed(&e).is_some() =>
        {
            tracing::warn!(
                target: crate::storage::schema_guard::TRACE_TARGET,
                error = %e,
                "this binary refuses to MIGRATE this database (schema ahead of the \
                 binary, or a destroyed version stamp) — taking the snapshot anyway \
                 through the read-oriented funnel so the durable text is preserved"
            );
            db::open_unmigrated(&source_db)
                .context("opening source DB for backup (schema-refusal fallback)")?
        }
        Err(e) => return Err(e.context("opening source DB for backup")),
    };
    // #2444 — provenance recorded INTO the manifest so the artifact is
    // self-describing: which backend produced it, which migration ladder it is
    // on, and how many memories it actually contains.
    let memory_count: i64 = conn
        .query_row(
            crate::storage::index_coverage::SQL_TOTAL_MEMORIES,
            [],
            |r| r.get(0),
        )
        .context("counting memories in the source DB")?;
    let schema_version: i64 = conn
        .query_row(
            crate::storage::migrations::SELECT_SCHEMA_VERSION_SQL,
            [],
            |r| r.get(0),
        )
        .context("reading the source DB schema version")?;
    let ts = chrono::Utc::now().format(BACKUP_TS_FMT).to_string();
    let snapshot_name = format!("ai-memory-{ts}.db");
    let snapshot_path = args.to.join(&snapshot_name);
    if snapshot_path.exists() {
        anyhow::bail!(
            "refusing to overwrite existing snapshot {}",
            snapshot_path.display()
        );
    }
    conn.execute(
        "VACUUM INTO ?1",
        rusqlite::params![snapshot_path.to_string_lossy()],
    )
    .context("VACUUM INTO failed")?;
    drop(conn);

    let bytes = std::fs::metadata(&snapshot_path)?.len();
    let sha = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        let mut f = std::fs::File::open(&snapshot_path)?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        format!("{:x}", hasher.finalize())
    };

    let manifest = BackupManifest {
        snapshot: snapshot_name.clone(),
        sha256: sha.clone(),
        bytes,
        source_db: source_db.to_string_lossy().into_owned(),
        version: crate::PKG_VERSION.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        backend: Some(BACKEND_SQLITE.to_string()),
        schema_version: Some(schema_version),
        memory_count: Some(memory_count),
    };
    let manifest_path = args.to.join(format!("ai-memory-{ts}.manifest.json"));
    let manifest_text = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(&manifest_path, manifest_text.as_bytes())?;

    // Rotation — newest-first listing, drop everything past `keep`.
    if args.keep > 0 {
        prune_old_snapshots(&args.to, args.keep)?;
    }

    // #2444 — an empty corpus is REPORTED, not refused. A row count cannot
    // tell a legitimately-fresh SQLite deployment apart from a wrong-store
    // capture (and on a Postgres host the local sqlite sidecar legitimately
    // holds 0 memories while carrying the only copy of the governance audit
    // spine), so refusing here would both miss the migrated-host case and
    // false-refuse real data. The store guard above is the structural control;
    // this is the honest signal. (3x3 adversarial vote, this session.)
    if memory_count == 0 {
        writeln!(
            out.stderr,
            "WARNING: this snapshot contains 0 memories (source {}). If this \
             deployment's corpus lives in Postgres, `ai-memory backup` did NOT \
             capture it — use pg_dump / pg_basebackup, and pass --store-url so \
             the command can refuse instead of guessing. See \
             docs/production-deployment.md (#2444).",
            source_db.display()
        )?;
    }

    if json_out {
        writeln!(out.stdout, "{}", serde_json::to_string(&manifest)?)?;
    } else {
        writeln!(out.stdout, "Snapshot: {}", snapshot_path.display())?;
        writeln!(out.stdout, "Manifest: {}", manifest_path.display())?;
        writeln!(out.stdout, "SHA-256 : {sha}")?;
        writeln!(out.stdout, "Bytes   : {bytes}")?;
        writeln!(out.stdout, "Memories: {memory_count}")?;
    }
    Ok(())
}

/// Enumerate existing `ai-memory-*.db` snapshot files newest-first and
/// delete everything past `keep`. Also deletes the matching manifest
/// for each removed snapshot.
fn prune_old_snapshots(dir: &Path, keep: usize) -> Result<()> {
    let snaps = snapshots_newest_first(dir)?;
    for (_, path) in snaps.into_iter().skip(keep) {
        let _ = std::fs::remove_file(&path);
        // Matching manifest (same stem, .manifest.json extension pattern)
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            let manifest = dir.join(manifest_file_name(stem));
            let _ = std::fs::remove_file(manifest);
        }
    }
    Ok(())
}

/// v1.0.0 #3550 — how the snapshot being restored was chosen, reported as
/// `selected_by` under `--json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotSelection {
    /// `--from` named the snapshot file, or `--snapshot` named it inside the
    /// `--from` directory.
    Explicit,
    /// `--from` was a directory, no `--snapshot` was given, and the newest
    /// snapshot by modification time was taken.
    Mtime,
}

impl SnapshotSelection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Mtime => "mtime",
        }
    }
}

/// The snapshot a restore will read, its manifest, and how it was chosen.
struct SelectedSnapshot {
    snapshot: PathBuf,
    manifest: PathBuf,
    selected_by: SnapshotSelection,
}

/// Filename prefix every `backup` snapshot (and manifest) carries.
const SNAPSHOT_FILE_PREFIX: &str = "ai-memory-";

/// Snapshot file extension, compared case-insensitively.
const SNAPSHOT_FILE_EXT: &str = "db";

/// Suffix of a manifest file name (`<id>.manifest.json`); see
/// [`manifest_file_name`].
const MANIFEST_FILE_SUFFIX: &str = ".manifest.json";

/// Every `ai-memory-*.db` snapshot in `dir`, with its mtime, newest first.
fn snapshots_newest_first(dir: &Path) -> Result<Vec<(std::time::SystemTime, PathBuf)>> {
    let mut snaps: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?.to_owned();
            let is_snapshot = name.starts_with(SNAPSHOT_FILE_PREFIX)
                && path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case(SNAPSHOT_FILE_EXT));
            if is_snapshot {
                let mtime = entry.metadata().ok()?.modified().ok()?;
                Some((mtime, path))
            } else {
                None
            }
        })
        .collect();
    snaps.sort_by_key(|b| std::cmp::Reverse(b.0));
    Ok(snaps)
}

/// v1.0.0 #3550 — the snapshot id `--snapshot` names: the file name, the id
/// (stem) or the manifest file name all reduce to the stem. `None` when
/// `name` is not a single plain path component (a path, `.`, `..`, empty).
fn snapshot_id(name: &str) -> Option<&str> {
    let mut components = Path::new(name).components();
    let single_normal = matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(_)), None)
    );
    if !single_normal || name.contains(['/', '\\']) {
        return None;
    }
    let id = if let Some(id) = name.strip_suffix(MANIFEST_FILE_SUFFIX) {
        id
    } else {
        let path = Path::new(name);
        match path.extension() {
            Some(ext) if ext.eq_ignore_ascii_case(SNAPSHOT_FILE_EXT) => {
                path.file_stem().and_then(|s| s.to_str()).unwrap_or(name)
            }
            _ => name,
        }
    };
    (!id.is_empty() && id != "." && id != "..").then_some(id)
}

/// v1.0.0 #3550 — pick the snapshot and manifest a restore reads.
///
/// * `--from <file>` — that file; `--snapshot` alongside it is refused
///   (it only selects inside a directory).
/// * `--from <dir> --snapshot <name>` — `<dir>/<id>.db`, which must be a
///   regular file (not a symlink) directly in `<dir>`.
/// * `--from <dir>` alone — the newest snapshot by modification time. That
///   is not an integrity signal (anyone who can write the directory, or a
///   `cp` without `-p`, sets it), so the choice is WARNed with the pin to
///   use, and under `asi-hard` it is REFUSED with the candidates listed.
///
/// # Errors
/// See above; also an unreadable directory or an empty one.
fn select_snapshot(
    from: &Path,
    snapshot: Option<&str>,
    policy: RestorePolicy,
    out: &mut CliOutput<'_>,
) -> Result<SelectedSnapshot> {
    if !from.is_dir() {
        if snapshot.is_some() {
            anyhow::bail!(
                "--snapshot selects a snapshot inside a --from DIRECTORY, but --from {} \
                 is not a directory; pass the directory, or drop --snapshot (#3550)",
                from.display()
            );
        }
        let stem = from.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let parent = from.parent().unwrap_or_else(|| Path::new("."));
        return Ok(SelectedSnapshot {
            snapshot: from.to_path_buf(),
            manifest: parent.join(manifest_file_name(stem)),
            selected_by: SnapshotSelection::Explicit,
        });
    }
    if let Some(name) = snapshot {
        let id = snapshot_id(name).ok_or_else(|| {
            anyhow::anyhow!(
                "--snapshot {name:?} is not a snapshot name — pass the file name \
                 (ai-memory-<ts>.db), its id (ai-memory-<ts>) or its manifest's file \
                 name, never a path (#3550)"
            )
        })?;
        let path = from.join(format!("{id}.{SNAPSHOT_FILE_EXT}"));
        let meta = std::fs::symlink_metadata(&path).with_context(|| {
            format!(
                "--snapshot {name:?}: no snapshot {} in {} (#3550)",
                path.display(),
                from.display()
            )
        })?;
        if !meta.is_file() {
            anyhow::bail!(
                "--snapshot {name:?}: {} is not a regular file (a symlink or a \
                 directory is refused) (#3550)",
                path.display()
            );
        }
        return Ok(SelectedSnapshot {
            snapshot: path,
            manifest: from.join(manifest_file_name(id)),
            selected_by: SnapshotSelection::Explicit,
        });
    }
    let snaps = snapshots_newest_first(from)?;
    let Some((_, newest)) = snaps.first() else {
        anyhow::bail!("no snapshots found in {}", from.display());
    };
    let newest = newest.clone();
    let stem = newest
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_owned();
    if policy.asi_hard {
        let candidates: Vec<String> = snaps
            .iter()
            .filter_map(|(_, p)| p.file_stem().and_then(|s| s.to_str()).map(str::to_owned))
            .collect();
        anyhow::bail!(
            "restore: --from {} is a directory and no --snapshot was given; the asi-hard \
             posture refuses to pick a snapshot by modification time, which anyone who \
             can write the directory controls. Pass --snapshot <id>. Candidates, newest \
             mtime first: {} (#3550)",
            from.display(),
            candidates.join(", ")
        );
    }
    writeln!(
        out.stderr,
        "warning: --from {} is a directory and no --snapshot was given: restoring {}, \
         the newest snapshot by MODIFICATION TIME. mtime is not an integrity signal — \
         anyone who can write that directory can set it. Pass --snapshot {stem} to pin \
         this choice (#3550)",
        from.display(),
        newest.display()
    )?;
    Ok(SelectedSnapshot {
        manifest: from.join(manifest_file_name(&stem)),
        snapshot: newest,
        selected_by: SnapshotSelection::Mtime,
    })
}

/// v1.0.0 #3550 — the posture inputs `restore` enforces, resolved once by
/// [`run_restore`] and passed down so tests can drive both postures without
/// mutating the process environment.
#[derive(Debug, Clone, Copy)]
struct RestorePolicy {
    /// `AI_MEMORY_SECURITY_PROFILE=asi-hard`: a directory fsync that fails
    /// is a refusal (before the publish) or a non-zero exit (after it), and
    /// the mtime snapshot pick is refused.
    asi_hard: bool,
}

/// v1.0.0 #3550 — what a restore holds on the old and the new database
/// file while it publishes.
///
/// FIELD ORDER IS RELEASE ORDER (Rust drops fields in declaration order), on
/// the success path AND on every early return or unwind, and each step of it
/// is load-bearing:
///
/// 1. `old_lock` first. Closing it makes SQLite delete `<target>-wal` /
///    `-shm` BY NAME; after the rename that name belongs to the restored
///    database, which `new_lock` still holds, so nothing can have created
///    them.
/// 2. `old_file` after the connection: closing ANY descriptor on a file
///    drops every POSIX lock the process holds on it, so closing this one
///    first would release the old lock early.
/// 3. `new_lock` last.
struct HeldLocks {
    old_lock: Option<rusqlite::Connection>,
    old_file: Option<std::fs::File>,
    new_lock: Option<rusqlite::Connection>,
}

/// v1.0.0 #3550 — the staged replacement, removed on every path that does
/// not publish it (an error, a refusal, an unwind). Disarmed by the rename.
struct StagedFile {
    path: PathBuf,
    armed: bool,
}

impl StagedFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if self.armed {
            // Never panic in Drop; a leftover temp file is a disk-space
            // nuisance, not a correctness problem, and carries the restore
            // infix so the operator can find it.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Best-effort removal of sidecars SQLite may leave beside the STAGED
/// file's name (a verification open of a WAL-mode snapshot). They are named
/// after the temp file, never after the target, so they cannot be replayed
/// into the restored database; this only keeps the directory tidy.
fn remove_staged_sidecars(staged: &Path) {
    for suffix in SQLITE_SIDECAR_SUFFIXES {
        let _ = std::fs::remove_file(sidecar_path(staged, suffix));
    }
}

/// `restore` handler.
pub fn run_restore(
    db_path: &Path,
    args: &RestoreArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let policy = RestorePolicy {
        asi_hard: crate::security_profile::is_asi_hard(),
    };
    run_restore_with(db_path, args, json_out, out, policy, &mut RealPublishIo)
}

/// SHA-256 of the file at `path`, lowercase hex.
fn sha256_hex(path: &Path) -> Result<String> {
    use sha2::Digest;
    use std::io::Read;
    let mut hasher = sha2::Sha256::new();
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// [`run_restore`] with the posture and the publish I/O injected.
#[allow(clippy::too_many_lines)]
fn run_restore_with(
    db_path: &Path,
    args: &RestoreArgs,
    json_out: bool,
    out: &mut CliOutput<'_>,
    policy: RestorePolicy,
    io: &mut dyn PublishIo,
) -> Result<()> {
    // #2444 — a restore onto a Postgres-backed deployment would copy a SQLite
    // snapshot to a placeholder path, print "Restored", and exit 0 while the
    // real corpus was never touched. That is the false-assurance half of the
    // same defect, and it lands at the exact moment it cannot be fixed.
    let target_db = resolve_sqlite_source(db_path, args.store_url.as_deref(), VERB_RESTORE, out)?;
    let SelectedSnapshot {
        snapshot: snapshot_path,
        manifest: manifest_path,
        selected_by,
    } = select_snapshot(&args.from, args.snapshot.as_deref(), policy, out)?;

    if !snapshot_path.exists() {
        anyhow::bail!("snapshot {} does not exist", snapshot_path.display());
    }

    // Manifest pre-checks that need no bytes: cross-backend and
    // forward-schema. The sha256 itself is checked on the STAGED copy below.
    let manifest = if args.skip_verify {
        None
    } else {
        if !manifest_path.exists() {
            anyhow::bail!(
                "manifest {} not found; pass --skip-verify to restore anyway",
                manifest_path.display()
            );
        }
        let manifest_text = std::fs::read_to_string(&manifest_path)?;
        let manifest: BackupManifest = serde_json::from_str(&manifest_text)
            .with_context(|| format!("parsing manifest {}", manifest_path.display()))?;
        // #2444 — cross-backend refusal. The manifest field is `Option` so a
        // pre-#2444 manifest (no `backend` key) still restores; a snapshot that
        // POSITIVELY declares a non-sqlite origin is refused rather than copied
        // onto a SQLite path.
        if let Some(backend) = manifest.backend.as_deref() {
            if backend != BACKEND_SQLITE {
                anyhow::bail!(
                    "snapshot {} declares backend `{backend}`, but `restore` writes a \
                     local SQLite database. Refusing a cross-backend restore (#2444).",
                    snapshot_path.display()
                );
            }
        }
        // #2444 — forward-schema refusal. Restoring a snapshot taken by a NEWER
        // binary onto this one opens cleanly (the ladder only ever migrates
        // FORWARD) and then writes rows that silently drop the newer columns.
        // Refuse: degrade loudly rather than corrupt quietly.
        if let Some(snap_version) = manifest.schema_version {
            let ours = crate::storage::migrations::current_schema_version();
            if snap_version > ours {
                anyhow::bail!(
                    "snapshot {} is on schema v{snap_version} but this binary \
                     understands v{ours}. Refusing — restoring it would open cleanly \
                     and then silently drop the newer columns on the next write. \
                     Restore with ai-memory >= the version that took the snapshot \
                     (#2444).",
                    snapshot_path.display()
                );
            }
        }
        Some(manifest)
    };

    // v1.0.0 #3131 — EXPLICIT INTENT. `restore` REPLACES the operator's live
    // corpus. The confirmation takes the same posture as the substrate's
    // other destructive verbs (`forget --confirm-global`, `governance
    // install-defaults --yes`): an interactive `[y/N]`, overridden by
    // `--yes`, REQUIRED under `--json` (a prompt would corrupt the envelope)
    // and whenever stdin is not a terminal (nobody is there to answer, and a
    // destructive verb must not proceed on silence). The two refusals that
    // need no answer run first, before any work.
    let needs_confirmation = restore_requires_confirmation(args);
    if needs_confirmation {
        if json_out {
            anyhow::bail!(RESTORE_JSON_REQUIRES_YES);
        }
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            anyhow::bail!(RESTORE_NON_INTERACTIVE_REQUIRES_YES);
        }
    }

    // v1.0.0 #3131 — STAGE, then VERIFY WHAT WILL BE PUBLISHED. The
    // replacement is copied to a new file in the SAME directory (so the
    // publish is an atomic, same-filesystem rename) and fsynced.
    //
    // v1.0.0 #3550 — every check below reads the STAGED copy, not the
    // snapshot. Before, the sha256 and the structural probes read the
    // snapshot, and the bytes were copied later — after a confirmation prompt
    // that can wait indefinitely — so a snapshot swapped in that window was
    // published unverified.
    let ts = chrono::Utc::now().format(BACKUP_TS_FMT).to_string();
    let staged_path = sidecar_path(&target_db, &format!(".{RESTORE_TMP_INFIX}-{ts}"));
    stage_snapshot(&snapshot_path, &staged_path)?;
    let mut staged = StagedFile::new(staged_path.clone());

    if let Some(manifest) = manifest.as_ref() {
        let observed = sha256_hex(&staged_path)?;
        if observed != manifest.sha256 {
            anyhow::bail!(
                "sha256 mismatch — manifest says {}, snapshot is {}",
                manifest.sha256,
                observed
            );
        }
    }

    // #2444 — STRUCTURAL validation before the live database is touched. The
    // sha256 above proves only that the bytes match the manifest WE wrote over
    // whatever `VACUUM INTO` produced (and `--skip-verify` proves nothing at
    // all), so a truncated / foreign / non-SQLite file passes it. Probe the
    // staged copy read-only: if it is not an ai-memory database this query
    // fails, and we refuse BEFORE the operator's live corpus is touched.
    {
        let probe = db::open_read_only(&staged_path).with_context(|| {
            format!(
                "snapshot {} is not a readable SQLite database — refusing to restore \
                 it over the live corpus (#2444)",
                snapshot_path.display()
            )
        })?;
        let _: i64 = probe
            .query_row(
                crate::storage::index_coverage::SQL_TOTAL_MEMORIES,
                [],
                |r| r.get(0),
            )
            .with_context(|| {
                format!(
                    "snapshot {} has no `memories` table — it is not an ai-memory \
                     database. Refusing to restore it over the live corpus (#2444)",
                    snapshot_path.display()
                )
            })?;
        // v1.0.0 #2445 — MANIFEST-INDEPENDENT forward-schema refusal. The
        // #2444 check above reads `manifest.schema_version`, and the whole
        // manifest block is skipped under `--skip-verify` — the ONLY way to
        // restore the manifest-less pre-migration snapshot that
        // `snapshot_before_migration` writes — so re-derive the truth from the
        // FILE; it costs one query and cannot be skipped.
        let stamp = crate::storage::probe_schema_stamp(&probe).with_context(|| {
            format!(
                "cannot read the schema version of snapshot {} — refusing to \
                 restore it over the live corpus (#2445)",
                snapshot_path.display()
            )
        })?;
        // v1.0.0 #2564 — `operable_version`, never `version()`. A snapshot
        // whose `schema_version` row was deleted / zeroed / set negative reads
        // as 0 and would sail through the ceiling check below, then be PLANTED
        // over the live corpus — where the next open replays the entire ladder
        // with the pre-migration snapshot suppressed. Refuse the plant.
        let observed = stamp.operable_version(
            crate::storage::schema_guard::BACKEND_SQLITE,
            &snapshot_path.display().to_string(),
        )?;
        crate::storage::schema_guard::evaluate(
            observed,
            crate::storage::migrations::current_schema_version(),
            crate::storage::schema_guard::BACKEND_SQLITE,
            &snapshot_path.display().to_string(),
        )?;
    }

    // #3508/#3510 — the whole-database integrity verdict (PRAGMA
    // integrity_check plus the page census that pragma skips on this schema).
    verify_staged_integrity(&staged_path, out, json_out)?;
    remove_staged_sidecars(&staged_path);
    io.at(PublishStep::Staged, &target_db);

    if needs_confirmation {
        writeln!(
            out.stdout,
            "About to REPLACE {} with {}.",
            target_db.display(),
            snapshot_path.display()
        )?;
        writeln!(
            out.stdout,
            "The current database is copied to <db>.{PRE_RESTORE_INFIX}-<ts>.db first. \
             The replacement has been staged and passed PRAGMA integrity_check AND the \
             whole-file page accounting that check skips on this schema (#3508/#3510)."
        )?;
        if !confirm_restore(out)? {
            writeln!(out.stdout, "Aborted. The database was not modified.")?;
            return Ok(());
        }
    }

    // v1.0.0 #3131 — LIVENESS. The probe opens the target READ_WRITE (it may
    // roll back a hot journal), so it runs ONLY after consent. A daemon / MCP
    // server holding the database open is refused.
    //
    // v1.0.0 #3550 — and the lock it takes is now HELD, through the aside
    // copy and the publish, so a writer that starts mid-restore is refused by
    // SQLite instead of writing into the file being copied and replaced.
    // Closing ANY descriptor on a file drops every POSIX lock this process
    // holds on it, so from here until the lock is released the old database
    // is read only through `old_file`, and `old_lock` is dropped before it.
    let mut held = HeldLocks {
        old_lock: refuse_if_target_in_use(&target_db, out)?,
        old_file: None,
        new_lock: None,
    };
    held.old_file = if target_db.exists() {
        // Read-write so the orphan can be invalidated after the publish; a
        // read-only database file still gets its rollback copy.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&target_db)
            .or_else(|_| std::fs::File::open(&target_db))
            .with_context(|| {
                format!(
                    "opening {} to copy it aside — refusing to restore without a \
                     rollback copy (#3131)",
                    target_db.display()
                )
            })?;
        Some(file)
    } else {
        None
    };
    if let (Some(conn), Some(file)) = (held.old_lock.as_ref(), held.old_file.as_ref()) {
        match checkpoint_before_sidecar_removal(conn, &target_db) {
            // The checkpointed pages must be durable BEFORE the `-wal` that
            // also holds them is removed below.
            Ok(()) => file.sync_all().with_context(|| {
                format!(
                    "fsyncing {} after its checkpoint — refusing to remove a WAL whose \
                     frames may not be durable in the database file (#3550)",
                    target_db.display()
                )
            })?,
            // A WAL SQLite cannot fold (a damaged database is exactly the
            // disaster-recovery case) must not strand the restore: the
            // rollback copy below carries the `-wal` with it.
            Err(e) => writeln!(
                out.stderr,
                "warning: {e:#}; the rollback copy keeps the old WAL beside it, so the \
                 frames stay recoverable from there"
            )?,
        }
    }
    io.at(PublishStep::Locked, &target_db);

    // v1.0.0 #3131 — REVERSIBILITY FIRST. The pre-restore safety copy is taken
    // by COPY, not by renaming the live file out of the way: a rename leaves NO
    // database at the target path for the whole window of the copy, so an
    // interrupt / ENOSPC there left the operator with a vanished corpus.
    //
    // #2444 — the `-wal` (and a `-journal`) are copied WITH it so the aside set
    // is a self-consistent database. v1.0.0 #3550 — the `-shm` is not: it is
    // an index of the `-wal` that SQLite rebuilds, and a copy can only be
    // stale.
    let aside = target_db.with_extension(format!("{PRE_RESTORE_INFIX}-{ts}.db"));
    let rollback = if let Some(mut file) = held.old_file.as_ref() {
        std::io::Seek::rewind(&mut file)
            .with_context(|| format!("rewinding {}", target_db.display()))?;
        copy_into_new_file(&mut file, &aside)
            .with_context(|| format!("copying the current DB aside to {}", aside.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = file.metadata()?.permissions().mode() & 0o7777;
            std::fs::set_permissions(&aside, std::fs::Permissions::from_mode(mode))?;
        }
        for suffix in SQLITE_SIDECAR_SUFFIXES {
            if suffix == SQLITE_SHM_SUFFIX {
                continue;
            }
            let live_sidecar = sidecar_path(&target_db, suffix);
            if !path_present(&live_sidecar) {
                continue;
            }
            let mut src = std::fs::File::open(&live_sidecar).with_context(|| {
                format!(
                    "copying SQLite sidecar {} aside — the rollback copy has to be a \
                     self-consistent database (#2444)",
                    live_sidecar.display()
                )
            })?;
            copy_into_new_file(&mut src, &sidecar_path(&aside, suffix)).with_context(|| {
                format!(
                    "copying SQLite sidecar {} aside — the rollback copy has to be a \
                     self-consistent database (#2444)",
                    live_sidecar.display()
                )
            })?;
        }
        if !json_out {
            writeln!(out.stdout, "Previous DB copied to {}", aside.display())?;
        }
        Some(aside)
    } else {
        None
    };

    // The replacement takes the permissions of the database it replaces (the
    // staged copy was created owner-only); with no database there it stays
    // owner-only. `std::fs::copy` used to carry the SNAPSHOT's mode over, so a
    // world-writable snapshot published a world-writable corpus.
    #[cfg(unix)]
    if let Some(file) = held.old_file.as_ref() {
        use std::os::unix::fs::PermissionsExt;
        let mode = file.metadata()?.permissions().mode() & 0o7777;
        std::fs::set_permissions(&staged_path, std::fs::Permissions::from_mode(mode))?;
    }

    // v1.0.0 #3550 — lock the replacement too, so the instant the rename lands
    // the new file is already held and nothing can open it mid-publish. Where
    // the lock cannot be taken (a filesystem without byte-range locks) the
    // publish proceeds with a warning: this lock narrows a race, it does not
    // gate correctness. On non-unix the locks are released instead — Windows
    // refuses to unlink or rename over a file that is open, which itself
    // refuses a racing opener.
    #[cfg(unix)]
    {
        held.new_lock = match lock_exclusive(&staged_path) {
            Ok(conn) => Some(conn),
            Err(LockError::Open(e) | LockError::Busy(e) | LockError::Probe(e)) => {
                writeln!(
                    out.stderr,
                    "warning: could not lock the staged restore {} ({e}); publishing without \
                 it — make sure no daemon/MCP server starts on {} until this finishes \
                 (#3550)",
                    staged_path.display(),
                    target_db.display()
                )?;
                None
            }
        };
    }
    #[cfg(not(unix))]
    {
        // Field order: the connection before the descriptor.
        held.old_lock = None;
        held.old_file = None;
    }
    io.at(PublishStep::AsideCopied, &target_db);

    // v1.0.0 #3550 — the old database's sidecars go BEFORE the publish, and a
    // failure to remove one is a refusal (the #3131 behaviour warned and kept
    // going, AFTER the rename).
    clear_live_sidecars(&target_db, io)?;
    io.at(PublishStep::SidecarsCleared, &target_db);

    // v1.0.0 #3550 — make the unlinks and the staged directory entry durable
    // before the rename, then the rename itself after it. A lost directory
    // fsync after a power cut can bring the replaced database back, so the
    // outcome is reported (`durable_publish`) and, under asi-hard, enforced.
    let dir = publish_dir(&target_db);
    let pre_sync = io.sync_dir(dir);
    if let Err(e) = pre_sync.as_ref() {
        if policy.asi_hard {
            anyhow::bail!(
                "could not fsync {} before publishing the restore ({e}); the asi-hard \
                 posture refuses a publish it cannot make durable. Nothing was \
                 published: the previous database is still at {}{} (#3550)",
                dir.display(),
                target_db.display(),
                rollback
                    .as_ref()
                    .map(|p| format!(", and its rollback copy is {}", p.display()))
                    .unwrap_or_default()
            );
        }
        writeln!(
            out.stderr,
            "warning: could not fsync {} before publishing ({e}); continuing, but the \
             restore will be reported as not durable (#3550)",
            dir.display()
        )?;
    }
    io.at(PublishStep::PrePublishSynced, &target_db);

    std::fs::rename(&staged_path, &target_db).with_context(|| {
        format!(
            "publishing the verified restore over {}",
            target_db.display()
        )
    })?;
    staged.armed = false;
    io.at(PublishStep::Published, &target_db);

    let post_sync = io.sync_dir(dir);
    if let Err(e) = post_sync.as_ref() {
        writeln!(
            out.stderr,
            "warning: restored {} but could not fsync {} ({e}); after a power loss the \
             previous database may reappear in its place (#3550)",
            target_db.display(),
            dir.display()
        )?;
    }
    io.at(PublishStep::PostPublishSynced, &target_db);

    // Defence in depth: with the old sidecars removed and the new file
    // locked, nothing can have created one. If something did, say so rather
    // than hand a daemon a WAL to replay.
    let reappeared: Vec<PathBuf> = SQLITE_SIDECAR_SUFFIXES
        .iter()
        .map(|suffix| sidecar_path(&target_db, suffix))
        .filter(|p| path_present(p))
        .collect();

    // v1.0.0 #3550 — poison the orphaned old inode (see
    // `poison_orphaned_inode`), but only once the rename is known durable: if
    // the directory entry were lost, a power cut would put THAT inode back at
    // the target path, and it must still open.
    #[cfg(unix)]
    if let Some(file) = held.old_file.as_ref()
        && post_sync.is_ok()
    {
        let regular = file.metadata().is_ok_and(|m| m.is_file());
        match regular.then(|| poison_orphaned_inode(file)) {
            Some(Ok(true)) => {}
            Some(Ok(false)) | None => writeln!(
                out.stderr,
                "warning: the database {} replaced is still linked elsewhere (a hard \
                 link) or is not a regular file, so it was left intact; anything using \
                 that other path is still using the OLD database (#3550)",
                target_db.display()
            )?,
            Some(Err(e)) => writeln!(
                out.stderr,
                "warning: could not invalidate the replaced database file ({e}); a \
                 process that opened {} during the restore could still write to it — \
                 restart any daemon/MCP server on this database (#3550)",
                target_db.display()
            )?,
        }
    }

    drop(held);
    remove_staged_sidecars(&staged_path);

    if !reappeared.is_empty() {
        let names: Vec<String> = reappeared.iter().map(|p| p.display().to_string()).collect();
        anyhow::bail!(
            "restored {} but SQLite sidecars appeared beside it during the publish ({}) — \
             something opened the database while it was being replaced. Remove them and \
             stop that process before starting a daemon, or replay the rollback copy \
             (#3550)",
            target_db.display(),
            names.join(", ")
        );
    }

    let durable_publish = pre_sync.is_ok() && post_sync.is_ok();
    if json_out {
        writeln!(
            out.stdout,
            "{}",
            serde_json::json!({
                "status": "restored",
                "from": snapshot_path.to_string_lossy(),
                "to": target_db.to_string_lossy(),
                // v1.0.0 #3131 — the rollback path, so an automated caller can
                // put the previous corpus back without guessing the filename.
                // `null` only when there was no database at the target before.
                "rollback": rollback.as_ref().map(|p| p.to_string_lossy()),
                // v1.0.0 #3550 — whether both directory fsyncs of the publish
                // succeeded, i.e. whether the restore survives a power cut.
                "durable_publish": durable_publish,
                // v1.0.0 #3550 — `explicit` or `mtime` (see `--snapshot`).
                "selected_by": selected_by.as_str(),
            })
        )?;
    } else {
        writeln!(
            out.stdout,
            "Restored {} → {}",
            snapshot_path.display(),
            target_db.display()
        )?;
        if let Some(path) = rollback.as_ref() {
            writeln!(
                out.stdout,
                "Rollback: cp {} {}",
                path.display(),
                target_db.display()
            )?;
        } else {
            writeln!(
                out.stdout,
                "No rollback copy: {} did not exist before this restore",
                target_db.display()
            )?;
        }
    }
    if !durable_publish && policy.asi_hard {
        anyhow::bail!(
            "restored {} but the directory entry could not be made durable; the asi-hard \
             posture reports this as a failure — a power loss may bring the previous \
             database back (#3550)",
            target_db.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};

    /// v1.0.0 #2572 — the shared class-(a) funnel returns the typed Postgres
    /// refusal (naming the HTTP-daemon remedy, DSN-redacted) on a `postgres://`
    /// store URL, and is byte-transparent (returns the `--db` path unchanged)
    /// when no store URL is configured. In-process env mutation is serialised
    /// through the shared `store_url_env_lock` (#2146).
    #[test]
    fn refuse_pg_store_typed_refusal_on_postgres_url_2572() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: env mutation is serialized by `store_url_env_lock`; these keys
        // are read only by `resolve_store_url`, held for this whole test.
        unsafe {
            std::env::remove_var(crate::store_url::STORE_URL_ENV);
            std::env::remove_var(crate::store_url::STORE_URL_FILE_ENV);
        }

        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();

        // 1) No store URL → transparent pass-through of the --db path.
        {
            let mut out = env.output();
            let resolved =
                refuse_pg_store(&db, "store", &mut out).expect("no store URL → pass-through");
            assert_eq!(
                resolved, db,
                "with no store URL the guard must return the --db path unchanged (#2572)"
            );
        }

        // 2) postgres:// → typed refusal, HTTP-daemon remedy, password redacted.
        // SAFETY: see above.
        unsafe {
            std::env::set_var(
                crate::store_url::STORE_URL_ENV,
                "postgres://ai_memory:hunter2@127.0.0.1:5432/ai_memory",
            );
        }
        {
            let mut out = env.output();
            let err = refuse_pg_store(&db, "store", &mut out)
                .expect_err("postgres:// must refuse (#2572)");
            let msg = err.to_string();
            assert!(msg.contains("#2572"), "refusal must cite #2572: {msg}");
            assert!(
                msg.contains("HTTP daemon"),
                "refusal must name the HTTP-daemon remedy, not pg_dump: {msg}"
            );
            assert!(
                !msg.contains("hunter2"),
                "refusal must redact the DSN password: {msg}"
            );
        }
        // SAFETY: see above.
        unsafe {
            std::env::remove_var(crate::store_url::STORE_URL_ENV);
        }
    }

    #[test]
    fn test_backup_happy_path_creates_snapshot_and_manifest() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x1");
        let args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &args, false, &mut out).unwrap();
        }
        // At least one snapshot + manifest must exist.
        let mut snap_count = 0;
        let mut manifest_count = 0;
        for entry in std::fs::read_dir(&backup_dir).unwrap().flatten() {
            let name = entry.file_name();
            let s = name.to_string_lossy();
            if s.starts_with("ai-memory-") && s.ends_with(".db") {
                snap_count += 1;
            }
            if s.ends_with(".manifest.json") {
                manifest_count += 1;
            }
        }
        assert!(snap_count >= 1, "expected at least one snapshot");
        assert!(manifest_count >= 1, "expected at least one manifest");
        assert!(env.stdout_str().contains("Snapshot:"));
    }

    #[test]
    fn test_backup_json_emits_manifest_with_sha256() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x2");
        let args = BackupArgs {
            to: backup_dir,
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["sha256"].is_string());
        let sha = v["sha256"].as_str().unwrap();
        assert_eq!(sha.len(), 64); // hex sha256
    }

    #[test]
    fn test_restore_from_directory_picks_newest() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "before-backup", "stuff");
        let backup_dir = db.parent().unwrap().join("backups-x3");
        let backup_args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &backup_args, false, &mut out).unwrap();
        }
        env.stdout.clear();
        env.stderr.clear();
        let restore_args = RestoreArgs {
            from: backup_dir,
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: true,
        };
        {
            let mut out = env.output();
            run_restore(&db, &restore_args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("Restored"));
    }

    #[test]
    fn test_restore_from_explicit_file_path() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x4");
        let backup_args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &backup_args, true, &mut out).unwrap();
        }
        let manifest: BackupManifest = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let snap_path = backup_dir.join(&manifest.snapshot);
        env.stdout.clear();
        env.stderr.clear();
        let restore_args = RestoreArgs {
            from: snap_path,
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: true,
        };
        {
            let mut out = env.output();
            run_restore(&db, &restore_args, true, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["status"].as_str().unwrap(), "restored");
    }

    #[test]
    fn test_restore_with_skip_verify_succeeds_without_manifest() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x5");
        let backup_args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &backup_args, true, &mut out).unwrap();
        }
        let manifest: BackupManifest = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let snap_path = backup_dir.join(&manifest.snapshot);
        // Delete manifest file so verification would fail; skip_verify = true should still pass.
        let manifest_path = backup_dir.join(format!(
            "{}.manifest.json",
            snap_path.file_stem().unwrap().to_string_lossy()
        ));
        std::fs::remove_file(&manifest_path).unwrap();
        env.stdout.clear();
        env.stderr.clear();
        let restore_args = RestoreArgs {
            from: snap_path,
            snapshot: None,
            skip_verify: true,
            store_url: None,
            yes: true,
        };
        {
            let mut out = env.output();
            run_restore(&db, &restore_args, false, &mut out).unwrap();
        }
        assert!(env.stdout_str().contains("Restored"));
    }

    #[test]
    fn test_restore_bad_sha256_errors() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x6");
        let backup_args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &backup_args, true, &mut out).unwrap();
        }
        let manifest: BackupManifest = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let manifest_path = backup_dir.join(format!(
            "{}.manifest.json",
            std::path::Path::new(&manifest.snapshot)
                .file_stem()
                .unwrap()
                .to_string_lossy()
        ));
        // Corrupt sha in manifest.
        let mut bad = manifest;
        bad.sha256 = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        std::fs::write(&manifest_path, serde_json::to_string(&bad).unwrap()).unwrap();
        let snap_path = backup_dir.join(&bad.snapshot);
        let restore_args = RestoreArgs {
            from: snap_path,
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: true,
        };
        let mut out = env.output();
        let res = run_restore(&db, &restore_args, false, &mut out);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("sha256 mismatch"));
    }

    #[test]
    fn test_backup_retention_prunes_old_snapshots() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-x7");
        // Take a few backups in succession; with `keep=1` only the newest must remain.
        for _ in 0..3 {
            // Sleep 1 second to avoid filename collision (BACKUP_TS_FMT is per-second).
            std::thread::sleep(std::time::Duration::from_secs(1));
            let args = BackupArgs {
                to: backup_dir.clone(),
                keep: 1,
                store_url: None,
            };
            let mut out = env.output();
            run_backup(&db, &args, true, &mut out).unwrap();
            drop(out);
            env.stdout.clear();
            env.stderr.clear();
        }
        let snaps: Vec<_> = std::fs::read_dir(&backup_dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                let name = e.file_name();
                let s = name.to_string_lossy();
                s.starts_with("ai-memory-") && s.ends_with(".db")
            })
            .collect();
        assert_eq!(snaps.len(), 1, "retention should keep exactly 1 snapshot");
    }

    // ------------------------------------------------------------------
    // #2444 — fail-closed store guard + restore hardening.
    //
    // These complement `tests/backup_fail_closed_2444.rs`, which carries the
    // R-203 before/after evidence by driving the real binary through the env
    // channel. The unit tests below exercise the arms that are awkward to
    // reach through a subprocess (a forward-schema manifest, a corrupt
    // snapshot, WAL sidecar handling) and the `--store-url` ARGUMENT channel.
    // ------------------------------------------------------------------

    /// A postgres store declared on the flag is refused, and the message names
    /// the supported path. The credential in the DSN is redacted.
    #[test]
    fn backup_refuses_a_postgres_store_url_argument_2444() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let args = BackupArgs {
            to: db.parent().unwrap().join("backups-2444-pg"),
            keep: 48,
            store_url: Some("postgres://ai_memory:hunter2@127.0.0.1:5432/ai_memory".to_string()),
        };
        let mut out = env.output();
        let err = run_backup(&db, &args, false, &mut out)
            .expect_err("a postgres store must be refused")
            .to_string();
        assert!(err.contains("pg_dump"), "got: {err}");
        assert!(!err.contains("hunter2"), "DSN password leaked: {err}");
    }

    /// `restore` refuses the same store — the false-assurance half of #2444.
    #[test]
    fn restore_refuses_a_postgres_store_url_argument_2444() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = RestoreArgs {
            from: db.parent().unwrap().join("backups-2444-pg-restore"),
            snapshot: None,
            skip_verify: false,
            store_url: Some("postgresql://ai_memory:hunter2@127.0.0.1:5432/ai".to_string()),
            yes: true,
        };
        let mut out = env.output();
        let err = run_restore(&db, &args, false, &mut out)
            .expect_err("restoring onto a postgres store must be refused")
            .to_string();
        assert!(err.contains("pg_dump"), "got: {err}");
        assert!(!err.contains("hunter2"), "DSN password leaked: {err}");
    }

    /// An unrecognised scheme must NOT fall back to the local `--db` file —
    /// that fallback is precisely how a snapshot of the wrong database gets a
    /// valid manifest.
    #[test]
    fn backup_refuses_an_unrecognised_store_url_scheme_2444() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-2444-scheme");
        let args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: Some("mysql://localhost/ai_memory".to_string()),
        };
        {
            let mut out = env.output();
            let err = run_backup(&db, &args, false, &mut out)
                .expect_err("an unrecognised scheme must be refused")
                .to_string();
            assert!(err.contains("unrecognised store URL"), "got: {err}");
        }
        assert_eq!(
            snapshot_count(&backup_dir),
            0,
            "a refused backup must leave no snapshot"
        );
    }

    /// `backup` must not CREATE the database it claims to capture. `db::open`
    /// would have created AND fully migrated it, so the resulting file is
    /// indistinguishable from a real one by any schema probe — the existence
    /// check has to happen first.
    #[test]
    fn backup_refuses_to_create_a_missing_source_database_2444() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let missing = db.parent().unwrap().join("never-created-2444.db");
        let backup_dir = db.parent().unwrap().join("backups-2444-missing");
        let args = BackupArgs {
            to: backup_dir.clone(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            let err = run_backup(&missing, &args, false, &mut out)
                .expect_err("a missing source DB must be refused")
                .to_string();
            assert!(err.contains("refusing to create"), "got: {err}");
        }
        assert!(!missing.exists(), "backup created the source database");
        assert_eq!(snapshot_count(&backup_dir), 0);
    }

    /// The manifest is self-describing: backend, applied schema version, and
    /// the row count actually captured.
    #[test]
    fn backup_manifest_records_backend_schema_and_memory_count_2444() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let args = BackupArgs {
            to: db.parent().unwrap().join("backups-2444-manifest"),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &args, true, &mut out).unwrap();
        }
        let manifest: BackupManifest = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(manifest.backend.as_deref(), Some(BACKEND_SQLITE));
        assert_eq!(
            manifest.schema_version,
            Some(crate::storage::migrations::current_schema_version())
        );
        assert_eq!(manifest.memory_count, Some(1));
    }

    /// A zero-memory snapshot is WARNed, never refused: a row count cannot
    /// tell a legitimately fresh deployment from a wrong-store capture, and
    /// refusing would strand the sqlite governance sidecar on a pg host.
    #[test]
    fn backup_warns_but_succeeds_on_an_empty_corpus_2444() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Bring the database into existence WITHOUT storing any memory.
        drop(db::open(&db).unwrap());
        let args = BackupArgs {
            to: db.parent().unwrap().join("backups-2444-empty"),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(&db, &args, false, &mut out).expect("an empty corpus still backs up");
        }
        assert!(
            env.stderr_str().contains("0 memories"),
            "an empty snapshot must be reported; stderr was: {}",
            env.stderr_str()
        );
    }

    /// A manifest that POSITIVELY declares a non-sqlite origin is refused
    /// rather than copied onto a SQLite path.
    #[test]
    fn restore_refuses_a_cross_backend_manifest_2444() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-2444-xbackend");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let manifest_path = manifest_path_for(&backup_dir, &manifest.snapshot);
        let mut tampered = manifest;
        tampered.backend = Some("postgres".to_string());
        let snap = backup_dir.join(&tampered.snapshot);
        std::fs::write(&manifest_path, serde_json::to_string(&tampered).unwrap()).unwrap();

        let args = RestoreArgs {
            from: snap,
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: true,
        };
        let mut out = env.output();
        let err = run_restore(&db, &args, false, &mut out)
            .expect_err("a cross-backend snapshot must be refused")
            .to_string();
        assert!(err.contains("cross-backend"), "got: {err}");
    }

    /// A snapshot from a NEWER binary opens cleanly (the ladder only migrates
    /// forward) and then silently drops the newer columns on the next write.
    /// Refuse instead.
    #[test]
    fn restore_refuses_a_forward_schema_snapshot_2444() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-2444-forward");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let manifest_path = manifest_path_for(&backup_dir, &manifest.snapshot);
        let mut tampered = manifest;
        tampered.schema_version = Some(crate::storage::migrations::current_schema_version() + 1);
        let snap = backup_dir.join(&tampered.snapshot);
        std::fs::write(&manifest_path, serde_json::to_string(&tampered).unwrap()).unwrap();

        let args = RestoreArgs {
            from: snap,
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: true,
        };
        let mut out = env.output();
        let err = run_restore(&db, &args, false, &mut out)
            .expect_err("a forward-schema snapshot must be refused")
            .to_string();
        assert!(err.contains("understands v"), "got: {err}");
    }

    /// A pre-#2444 manifest carries none of the new keys; it must still
    /// restore (`#[serde(default)]`), because refusing every artifact an
    /// operator already holds would be its own data-loss event.
    #[test]
    fn restore_accepts_a_legacy_manifest_without_the_new_fields_2444() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-2444-legacy");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let manifest_path = manifest_path_for(&backup_dir, &manifest.snapshot);
        // Re-serialise WITHOUT the #2444 keys, exactly as v0.9 would have.
        let legacy = serde_json::json!({
            "snapshot": manifest.snapshot,
            "sha256": manifest.sha256,
            "bytes": manifest.bytes,
            "source_db": manifest.source_db,
            "version": manifest.version,
            "created_at": manifest.created_at,
        });
        std::fs::write(&manifest_path, serde_json::to_string(&legacy).unwrap()).unwrap();

        let args = RestoreArgs {
            from: backup_dir.join(&manifest.snapshot),
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: true,
        };
        let mut out = env.output();
        run_restore(&db, &args, false, &mut out).expect("a legacy manifest must still restore");
    }

    /// The sha256 only proves the bytes match a manifest WE wrote over
    /// whatever was produced — and `--skip-verify` proves nothing at all. A
    /// foreign / truncated file must be refused BEFORE the live corpus is
    /// moved aside.
    #[test]
    fn restore_refuses_a_snapshot_that_is_not_an_ai_memory_database_2444() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "survivor", "must not be clobbered");
        let backup_dir = db.parent().unwrap().join("backups-2444-garbage");
        std::fs::create_dir_all(&backup_dir).unwrap();
        let bogus = backup_dir.join("ai-memory-2026-01-01T000000Z.db");
        std::fs::write(&bogus, b"this is not a sqlite database at all").unwrap();

        let live_before = std::fs::metadata(&db).unwrap().len();
        let args = RestoreArgs {
            from: bogus,
            snapshot: None,
            skip_verify: true,
            store_url: None,
            yes: true,
        };
        {
            let mut out = env.output();
            let err = run_restore(&db, &args, false, &mut out)
                .expect_err("a non-ai-memory snapshot must be refused")
                .to_string();
            assert!(
                err.contains("not an ai-memory database"),
                "refusal must say it will not clobber the live corpus; got: {err}"
            );
        }
        assert_eq!(
            std::fs::metadata(&db).unwrap().len(),
            live_before,
            "a refused restore must not touch the live database"
        );
    }

    /// Renaming `<db>` aside without its `-wal` / `-shm` left the PREVIOUS
    /// database's write-ahead log beside the freshly copied snapshot, where
    /// SQLite can replay stale frames INTO the restored corpus.
    ///
    /// v1.0.0 #3131 restated the second half of this contract, and made it
    /// STRONGER. The old assertion counted two `pre-restore-*-wal` /
    /// `-shm` files beside the safety copy — i.e. it proved stale sidecar
    /// BYTES were preserved. With the #3131 liveness probe SQLite now opens
    /// and cleanly closes the target first, which checkpoints and removes
    /// those sidecars, so what the safety copy has to be is a
    /// self-consistent database that needs no sidecars at all. This test
    /// therefore asserts the property the file-count was a proxy for: the
    /// live sidecars do not survive beside the restored corpus, and the
    /// rollback copy OPENS and still holds the pre-restore row.
    #[test]
    fn restore_moves_the_wal_and_shm_sidecars_aside_2444() {
        // #2970 — serialize the process-global store-url env read (resolve_store_url).
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-2444-wal");
        let manifest = take_backup(&mut env, &db, &backup_dir);

        // Plant sidecars that must not survive next to the restored file.
        let live_wal = sidecar_path(&db, "-wal");
        let live_shm = sidecar_path(&db, "-shm");
        std::fs::write(&live_wal, b"stale wal frames").unwrap();
        std::fs::write(&live_shm, b"stale shm").unwrap();

        let args = RestoreArgs {
            from: backup_dir.join(&manifest.snapshot),
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: true,
        };
        {
            let mut out = env.output();
            run_restore(&db, &args, false, &mut out).unwrap();
        }
        assert!(
            !live_wal.exists(),
            "a stale -wal beside the restored DB can be replayed into it"
        );
        assert!(!live_shm.exists(), "a stale -shm must not survive either");

        // v1.0.0 #3131 — and the safety copy is RECOVERABLE, not just
        // present: it opens as an ai-memory database and still holds the
        // row that was there before the restore.
        let aside = find_pre_restore_copy(db.parent().unwrap());
        let conn = db::open_read_only(&aside).expect("the rollback copy must open");
        let rows: i64 = conn
            .query_row(
                crate::storage::index_coverage::SQL_TOTAL_MEMORIES,
                [],
                |r| r.get(0),
            )
            .expect("the rollback copy must be queryable");
        assert_eq!(
            rows, 1,
            "the rollback copy must hold the pre-restore corpus"
        );
    }

    // ==================================================================
    // v1.0.0 #3131 — `restore` publishes safely: liveness-gated, staged,
    // integrity-verified, atomically swapped, reversible.
    // ==================================================================

    /// A daemon / MCP server holding the target open is the failure mode
    /// that turned `fs::copy` onto a live database into corruption: the
    /// holder keeps writing into the file being overwritten. Refuse — and
    /// leave the target byte-for-byte as it was.
    #[test]
    fn restore_refuses_a_locked_target_and_leaves_it_intact_3131() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "live-row", "must survive");
        let backup_dir = db.parent().unwrap().join("backups-3131-locked");
        let manifest = take_backup(&mut env, &db, &backup_dir);

        // Stand in for the running daemon: a second connection holding the
        // exclusive lock, exactly what the liveness probe tests for.
        let holder = db::open(&db).expect("holder connection");
        holder
            .execute_batch("PRAGMA locking_mode = exclusive; BEGIN EXCLUSIVE;")
            .expect("hold the exclusive lock");

        let before = std::fs::read(&db).expect("read live db");
        let args = RestoreArgs {
            from: backup_dir.join(&manifest.snapshot),
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: true,
        };
        {
            let mut out = env.output();
            let err = run_restore(&db, &args, false, &mut out)
                .expect_err("a live target must be refused");
            let msg = err.to_string();
            assert!(msg.contains("open in another process"), "got: {msg}");
            assert!(msg.contains("#3131"), "got: {msg}");
        }
        assert_eq!(
            std::fs::read(&db).expect("read live db"),
            before,
            "a refused restore must not touch a single byte of the live database"
        );
        assert!(
            !db.parent()
                .unwrap()
                .join(format!("{}", db.file_name().unwrap().to_string_lossy()))
                .with_extension(format!("{PRE_RESTORE_INFIX}-x.db"))
                .exists(),
            "a refused restore must not leave artefacts"
        );
        drop(holder);
    }

    /// The staging + `PRAGMA integrity_check` gate stands between a damaged
    /// replacement and the operator's corpus. The snapshot below passes the
    /// #2444 structural probe and the #2445 schema stamp (its schema reads
    /// fine) but carries unreferenced pages, which `integrity_check`
    /// catches — and the live database must still be the original.
    #[test]
    fn restore_refuses_an_integrity_check_failure_and_leaves_the_original_intact_3131() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "live-row", "must survive");
        let backup_dir = db.parent().unwrap().join("backups-3131-integrity");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let snap = backup_dir.join(&manifest.snapshot);
        damage_page_accounting(&snap);

        let before = std::fs::read(&db).expect("read live db");
        let args = RestoreArgs {
            from: snap,
            snapshot: None,
            // The bytes no longer match the manifest sha; this test is about
            // the integrity gate, so skip the checksum and let the structural
            // probe + integrity_check do the refusing.
            skip_verify: true,
            store_url: None,
            yes: true,
        };
        {
            let mut out = env.output();
            let err = run_restore(&db, &args, false, &mut out)
                .expect_err("a snapshot that fails integrity_check must be refused");
            let msg = err.to_string();
            assert!(msg.contains("integrity_check"), "got: {msg}");
        }
        assert_eq!(
            std::fs::read(&db).expect("read live db"),
            before,
            "the live database must be untouched when the replacement fails verification"
        );
        let leftovers = std::fs::read_dir(db.parent().unwrap())
            .expect("read dir")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(RESTORE_TMP_INFIX))
            .count();
        assert_eq!(
            leftovers, 0,
            "the staged file must be cleaned up on refusal"
        );
    }

    /// Success path: the target ends up byte-identical to the snapshot, the
    /// pre-restore rollback copy exists and still holds what was replaced,
    /// and the rollback path is printed (and surfaced in `--json`).
    #[test]
    fn restore_publishes_identical_bytes_and_leaves_a_rollback_copy_3131() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "in-the-snapshot", "a");
        let backup_dir = db.parent().unwrap().join("backups-3131-ok");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        // Diverge the live corpus from the snapshot so the rollback copy is
        // distinguishable from the restored file.
        seed_memory(&db, "ns", "added-after-the-backup", "b");
        let snap = backup_dir.join(&manifest.snapshot);
        let snapshot_bytes = std::fs::read(&snap).expect("read snapshot");

        let args = RestoreArgs {
            from: snap,
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: true,
        };
        {
            let mut out = env.output();
            run_restore(&db, &args, false, &mut out).expect("restore must succeed");
        }
        assert_eq!(
            std::fs::read(&db).expect("read restored db"),
            snapshot_bytes,
            "the published database must be byte-identical to the snapshot"
        );
        assert!(
            env.stdout_str().contains(PRE_RESTORE_INFIX),
            "the rollback path must be printed; stdout was: {}",
            env.stdout_str()
        );

        let aside = find_pre_restore_copy(db.parent().unwrap());
        let conn = db::open_read_only(&aside).expect("the rollback copy must open");
        let rows: i64 = conn
            .query_row(
                crate::storage::index_coverage::SQL_TOTAL_MEMORIES,
                [],
                |r| r.get(0),
            )
            .expect("query the rollback copy");
        assert_eq!(
            rows, 2,
            "the rollback copy must hold the corpus as it was BEFORE the restore"
        );
    }

    /// `--json` carries the rollback path so an automated caller never has
    /// to guess the filename.
    #[test]
    fn restore_json_reports_the_rollback_path_3131() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-3131-json");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let args = RestoreArgs {
            from: backup_dir.join(&manifest.snapshot),
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: true,
        };
        {
            let mut out = env.output();
            run_restore(&db, &args, true, &mut out).expect("restore must succeed");
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).expect("json");
        assert_eq!(v["status"].as_str(), Some("restored"));
        let rollback = v["rollback"].as_str().expect("rollback path in --json");
        assert!(rollback.contains(PRE_RESTORE_INFIX), "got: {rollback}");
        assert!(
            Path::new(rollback).exists(),
            "the reported rollback path must exist: {rollback}"
        );
    }

    /// A destructive verb must not proceed on silence. `--json` cannot
    /// prompt (it would corrupt the envelope), so it REQUIRES `--yes`.
    #[test]
    fn restore_json_without_yes_is_refused_3131() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-3131-noyes");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let before = std::fs::read(&db).expect("read live db");
        let args = RestoreArgs {
            from: backup_dir.join(&manifest.snapshot),
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: false,
        };
        {
            let mut out = env.output();
            let err = run_restore(&db, &args, true, &mut out)
                .expect_err("--json without --yes must be refused");
            assert_eq!(err.to_string(), RESTORE_JSON_REQUIRES_YES);
        }
        assert_eq!(
            std::fs::read(&db).expect("read live db"),
            before,
            "a refused restore must not touch the live database"
        );
    }

    /// The confirmation predicate itself — asserted directly so the
    /// contract is pinned without driving stdin (the shape
    /// `cli::forget::requires_global_confirmation` established).
    #[test]
    fn restore_confirmation_predicate_is_lifted_only_by_yes_3131() {
        let base = RestoreArgs {
            from: PathBuf::from("/nonexistent"),
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: false,
        };
        assert!(restore_requires_confirmation(&base));
        let confirmed = RestoreArgs {
            yes: true,
            ..RestoreArgs {
                from: PathBuf::from("/nonexistent"),
                snapshot: None,
                skip_verify: false,
                store_url: None,
                yes: false,
            }
        };
        assert!(!restore_requires_confirmation(&confirmed));
    }

    /// The exclusive liveness probe is a production raw open (#2445). On an
    /// idle current-schema database it must succeed AND run
    /// `assert_schema_not_ahead` (the Ok arm added with the funnel
    /// allowlist). A schema-ahead target would refuse here rather than
    /// proceeding to rewrite the live file.
    #[test]
    fn refuse_if_target_in_use_missing_path_is_ok_3131() {
        let mut env = TestEnv::fresh();
        let missing = env
            .db_path
            .parent()
            .unwrap()
            .join("no-such-restore-target.db");
        {
            let mut out = env.output();
            refuse_if_target_in_use(&missing, &mut out)
                .expect("a missing target is the empty-corpus restore case");
        }
    }

    #[test]
    fn refuse_if_target_in_use_idle_current_schema_is_ok_3131() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "idle", "row");
        {
            let mut out = env.output();
            refuse_if_target_in_use(&db, &mut out)
                .expect("an idle current-schema database must pass the liveness probe");
        }
        assert!(
            !env.stderr_str().contains("warning:"),
            "idle probe must not warn; stderr was: {}",
            env.stderr_str()
        );
    }

    /// `--json` without `--yes` is refused BEFORE the RW probe, so it must
    /// not leave a restore-tmp artefact (consent-first, Fable gate).
    #[test]
    fn restore_json_without_yes_leaves_no_restore_tmp_3131() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-3131-noyes-tmp");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let args = RestoreArgs {
            from: backup_dir.join(&manifest.snapshot),
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: false,
        };
        {
            let mut out = env.output();
            let _ = run_restore(&db, &args, true, &mut out);
        }
        let leftovers = std::fs::read_dir(db.parent().unwrap())
            .expect("read dir")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(RESTORE_TMP_INFIX))
            .count();
        assert_eq!(leftovers, 0, "consent refusal must not leave restore-tmp");
    }

    // ==================================================================
    // v1.0.0 #3550 — sidecars before the publish (fail closed), durable
    // publish reported, `--snapshot` selection, lock held through publish.
    // ==================================================================

    /// v1.0.0 #3550 — REPLACES the #3131 pin
    /// `remove_stale_sidecars_warns_when_unlink_fails_and_does_not_err_3131`,
    /// which asserted that an unlink failure only WARNED. A sidecar that
    /// cannot be removed now refuses the publish.
    #[test]
    fn clear_live_sidecars_refuses_when_a_sidecar_cannot_be_removed_3550() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let wal = sidecar_path(&db, "-wal");
        std::fs::create_dir(&wal).expect("plant a directory as the -wal sidecar");
        let err = clear_live_sidecars(&db, &mut RealPublishIo)
            .expect_err("an unremovable sidecar must refuse the publish");
        let msg = format!("{err:#}");
        assert!(msg.contains("refusing to publish"), "got: {msg}");
        assert!(msg.contains("#3550"), "got: {msg}");
        assert!(wal.is_dir(), "the planted directory must still be there");
        let _ = std::fs::remove_dir(&wal);
    }

    /// Every sidecar kind goes, including a DANGLING symlink (which
    /// `Path::exists` reports as absent).
    #[test]
    fn clear_live_sidecars_removes_every_sidecar_kind_3550() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        for suffix in ["-wal", "-shm"] {
            std::fs::write(sidecar_path(&db, suffix), b"stale").expect("plant sidecar");
        }
        let journal = sidecar_path(&db, "-journal");
        #[cfg(unix)]
        std::os::unix::fs::symlink(db.with_extension("gone"), &journal)
            .expect("plant a dangling -journal symlink");
        #[cfg(not(unix))]
        std::fs::write(&journal, b"stale").expect("plant sidecar");
        clear_live_sidecars(&db, &mut RealPublishIo).expect("regular sidecars must unlink");
        for suffix in SQLITE_SIDECAR_SUFFIXES {
            assert!(
                !path_present(&sidecar_path(&db, suffix)),
                "{suffix} must be gone"
            );
        }
    }

    /// Injectable publish I/O: fail the sidecar unlink, fail either
    /// directory fsync, run an observer at every step, or "crash" (panic) at
    /// one of them.
    #[derive(Default)]
    struct FaultIo {
        fail_remove: bool,
        fail_sync_before_publish: bool,
        fail_sync_after_publish: bool,
        crash_at: Option<PublishStep>,
        remove_calls: usize,
        sync_calls: usize,
        steps: Vec<PublishStep>,
        observe: Option<Box<dyn FnMut(PublishStep, &Path)>>,
    }

    impl PublishIo for FaultIo {
        fn remove_sidecar(&mut self, path: &Path) -> std::io::Result<()> {
            self.remove_calls += 1;
            if self.fail_remove {
                return Err(std::io::Error::other("injected unlink failure"));
            }
            std::fs::remove_file(path)
        }
        fn sync_dir(&mut self, dir: &Path) -> std::io::Result<()> {
            self.sync_calls += 1;
            let fail = if self.sync_calls == 1 {
                self.fail_sync_before_publish
            } else {
                self.fail_sync_after_publish
            };
            if fail {
                return Err(std::io::Error::other("injected directory fsync failure"));
            }
            sync_dir(dir)
        }
        fn at(&mut self, step: PublishStep, target: &Path) {
            self.steps.push(step);
            if let Some(observe) = self.observe.as_mut() {
                observe(step, target);
            }
            assert!(self.crash_at != Some(step), "injected crash at {step:?}");
        }
    }

    const STANDARD: RestorePolicy = RestorePolicy { asi_hard: false };
    const ASI_HARD: RestorePolicy = RestorePolicy { asi_hard: true };

    const ALL_STEPS: [PublishStep; 7] = [
        PublishStep::Staged,
        PublishStep::Locked,
        PublishStep::AsideCopied,
        PublishStep::SidecarsCleared,
        PublishStep::PrePublishSynced,
        PublishStep::Published,
        PublishStep::PostPublishSynced,
    ];

    fn restore_args_3550(from: PathBuf) -> RestoreArgs {
        RestoreArgs {
            from,
            snapshot: None,
            skip_verify: false,
            store_url: None,
            yes: true,
        }
    }

    fn memory_rows(path: &Path) -> i64 {
        let conn = db::open_read_only(path).expect("database must open");
        conn.query_row(
            crate::storage::index_coverage::SQL_TOTAL_MEMORIES,
            [],
            |r| r.get(0),
        )
        .expect("count memories")
    }

    fn restore_tmp_leftovers(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .expect("read dir")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(RESTORE_TMP_INFIX))
            .count()
    }

    /// A live database holding 2 rows and a snapshot holding 1, so which one
    /// sits at the target is observable. Returns `(db, snapshot path)`.
    fn two_row_live_one_row_snapshot(env: &mut TestEnv, tag: &str) -> (PathBuf, PathBuf) {
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "in-the-snapshot", "a");
        let backup_dir = db.parent().unwrap().join(format!("backups-3550-{tag}"));
        let manifest = take_backup(env, &db, &backup_dir);
        seed_memory(&db, "ns", "added-after-the-backup", "b");
        (db, backup_dir.join(&manifest.snapshot))
    }

    /// Acceptance: an unlink failure is a NON-ZERO exit (an `Err` out of the
    /// handler), nothing is published, and the live corpus is still the old
    /// one.
    #[test]
    fn restore_refuses_to_publish_when_a_sidecar_unlink_fails_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "unlink");
        // Guarantee a sidecar exists at unlink time whatever the journal mode.
        std::fs::write(sidecar_path(&db, "-journal"), b"").expect("plant -journal");
        let mut io = FaultIo {
            fail_remove: true,
            ..FaultIo::default()
        };
        let err = {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                false,
                &mut out,
                STANDARD,
                &mut io,
            )
            .expect_err("an unlink failure must refuse the restore")
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("refusing to publish"), "got: {msg}");
        assert!(
            io.remove_calls >= 1,
            "the unlink must actually have been attempted"
        );
        assert!(
            !io.steps.contains(&PublishStep::Published),
            "nothing may be published after a failed unlink: {:?}",
            io.steps
        );
        assert_eq!(memory_rows(&db), 2, "the live corpus must be the old one");
        assert_eq!(restore_tmp_leftovers(db.parent().unwrap()), 0);
    }

    /// Acceptance: at the instant the replacement is at `target_db`, no
    /// `-wal` / `-shm` / `-journal` exists beside it — and the unlink
    /// happened while the OLD database was still the target.
    #[test]
    fn no_sidecar_exists_at_the_instant_the_restore_is_published_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "ordering");
        std::fs::write(sidecar_path(&db, "-journal"), b"").expect("plant -journal");
        let snapshot_len = std::fs::metadata(&snap).expect("snapshot").len();
        let old_len = std::fs::metadata(&db).expect("live db").len();
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let seen_in = std::rc::Rc::clone(&seen);
        let mut io = FaultIo {
            observe: Some(Box::new(move |step, target| {
                let present: Vec<&str> = SQLITE_SIDECAR_SUFFIXES
                    .into_iter()
                    .filter(|s| path_present(&sidecar_path(target, s)))
                    .collect();
                // `metadata` is a stat: it opens no descriptor, so it cannot
                // drop the restore's POSIX locks.
                let len = std::fs::metadata(target).map(|m| m.len()).unwrap_or(0);
                seen_in.borrow_mut().push((step, present.join(","), len));
            })),
            ..FaultIo::default()
        };
        {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap.clone()),
                false,
                &mut out,
                STANDARD,
                &mut io,
            )
            .expect("restore must succeed");
        }
        let seen = seen.borrow();
        let at = |step: PublishStep| {
            seen.iter()
                .find(|(s, _, _)| *s == step)
                .cloned()
                .unwrap_or_else(|| panic!("step {step:?} never reached: {seen:?}"))
        };
        let (_, cleared_sidecars, cleared_len) = at(PublishStep::SidecarsCleared);
        assert_eq!(
            cleared_sidecars, "",
            "sidecars must be gone before the rename"
        );
        assert_eq!(
            cleared_len, old_len,
            "the OLD database must still be the target then"
        );
        let (_, published_sidecars, published_len) = at(PublishStep::Published);
        assert_eq!(
            published_sidecars, "",
            "no sidecar may exist at the instant the new file is at target_db"
        );
        assert_eq!(
            published_len, snapshot_len,
            "the replacement must be the target"
        );
        assert_eq!(
            std::fs::read(&db).expect("read restored db"),
            std::fs::read(&snap).expect("read snapshot"),
            "the published database must be byte-identical to the snapshot"
        );
    }

    /// Cert battery: "writer during restore". From the moment the old
    /// database is locked until the locks are released, another connection
    /// can neither write the old file nor open the new one.
    #[test]
    fn a_writer_starting_mid_restore_is_refused_at_every_locked_step_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "writer");
        let refused = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let refused_in = std::rc::Rc::clone(&refused);
        let mut io = FaultIo {
            observe: Some(Box::new(move |step, target| {
                if step == PublishStep::Staged {
                    return; // the old database is not locked yet
                }
                let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
                let writer = rusqlite::Connection::open_with_flags(target, flags)
                    .expect("opening is not locking");
                writer
                    .busy_timeout(std::time::Duration::ZERO)
                    .expect("busy_timeout");
                let outcome = writer.execute_batch("BEGIN IMMEDIATE; ROLLBACK;");
                refused_in
                    .borrow_mut()
                    .push((step, outcome.as_ref().is_err_and(is_busy)));
            })),
            ..FaultIo::default()
        };
        {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                false,
                &mut out,
                STANDARD,
                &mut io,
            )
            .expect("restore must succeed");
        }
        let refused = refused.borrow();
        assert_eq!(
            refused.len(),
            ALL_STEPS.len() - 1,
            "every locked step observed"
        );
        for (step, was_busy) in refused.iter() {
            assert!(
                was_busy,
                "a writer must get SQLITE_BUSY at {step:?}: {refused:?}"
            );
        }
        assert_eq!(memory_rows(&db), 1, "the restore must have landed intact");
    }

    /// A process that opened the target DURING the restore (held off by the
    /// lock) must not carry on against the replaced, orphaned inode — where
    /// it would create `<target>-wal` by name beside the restored database
    /// and have SQLite replay it into the restore. It fails loudly instead.
    #[cfg(unix)]
    #[test]
    fn a_connection_opened_mid_restore_cannot_use_the_replaced_file_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "ghost");
        let ghost = std::rc::Rc::new(std::cell::RefCell::new(None));
        let ghost_in = std::rc::Rc::clone(&ghost);
        let mut io = FaultIo {
            observe: Some(Box::new(move |step, target| {
                if step == PublishStep::PrePublishSynced {
                    *ghost_in.borrow_mut() =
                        Some(rusqlite::Connection::open(target).expect("open the old path"));
                }
            })),
            ..FaultIo::default()
        };
        {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                false,
                &mut out,
                STANDARD,
                &mut io,
            )
            .expect("restore must succeed");
        }
        let ghost = ghost.borrow_mut().take().expect("ghost opened");
        let write = ghost.execute_batch(
            "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
             VALUES ('ghost', 'long', 'ns', 'ghost', 'ghost', 'x', 'x')",
        );
        assert!(write.is_err(), "the orphaned inode must not accept a write");
        drop(ghost);
        for suffix in SQLITE_SIDECAR_SUFFIXES {
            assert!(
                !path_present(&sidecar_path(&db, suffix)),
                "no {suffix} may appear beside the restored database"
            );
        }
        assert_eq!(memory_rows(&db), 1, "the restored corpus must be untouched");
    }

    /// Crash injection at EVERY publish step: whatever the step, the target
    /// is a whole, verified database — the old one before the rename, the
    /// snapshot after it — with no sidecar that could replay foreign frames
    /// into it, and the rollback copy is intact once it has been taken.
    /// (Restore is SQLite-only; there is no Postgres leg.)
    #[test]
    fn a_crash_at_any_publish_step_leaves_old_or_new_never_a_mix_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for crash_at in ALL_STEPS {
            let mut env = TestEnv::fresh();
            let (db, snap) = two_row_live_one_row_snapshot(&mut env, "crash");
            let snapshot_bytes = std::fs::read(&snap).expect("read snapshot");
            let mut io = FaultIo {
                crash_at: Some(crash_at),
                ..FaultIo::default()
            };
            let unwound = {
                let mut out = env.output();
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_restore_with(
                        &db,
                        &restore_args_3550(snap.clone()),
                        false,
                        &mut out,
                        STANDARD,
                        &mut io,
                    )
                }))
            };
            assert!(
                unwound.is_err(),
                "the injected crash at {crash_at:?} must fire"
            );
            let published = matches!(
                crash_at,
                PublishStep::Published | PublishStep::PostPublishSynced
            );
            if published {
                assert_eq!(
                    std::fs::read(&db).expect("read target"),
                    snapshot_bytes,
                    "after the rename the target is exactly the snapshot ({crash_at:?})"
                );
                assert_eq!(memory_rows(&db), 1, "{crash_at:?}");
            } else {
                assert_eq!(
                    memory_rows(&db),
                    2,
                    "before the rename the old DB stays ({crash_at:?})"
                );
            }
            let probe = db::open_read_only(&db).expect("target opens");
            assert!(
                matches!(
                    crate::storage::sqlite_integrity::check(&probe).expect("integrity runs"),
                    crate::storage::sqlite_integrity::Soundness::Sound(_)
                ),
                "the target must be sound after a crash at {crash_at:?}"
            );
            drop(probe);
            if !matches!(crash_at, PublishStep::Staged | PublishStep::Locked) {
                let aside = find_pre_restore_copy(db.parent().unwrap());
                assert_eq!(
                    memory_rows(&aside),
                    2,
                    "rollback copy intact ({crash_at:?})"
                );
            }
        }
    }

    fn json_envelope(env: &TestEnv) -> serde_json::Value {
        serde_json::from_str(env.stdout_str().trim()).expect("one JSON document on stdout")
    }

    /// Standard posture: a failed directory fsync (before or after the
    /// rename) still publishes, and `durable_publish: false` says so.
    #[test]
    fn standard_reports_a_failed_directory_fsync_as_not_durable_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (before, after) in [(true, false), (false, true)] {
            let mut env = TestEnv::fresh();
            let (db, snap) = two_row_live_one_row_snapshot(&mut env, "fsync-std");
            let mut io = FaultIo {
                fail_sync_before_publish: before,
                fail_sync_after_publish: after,
                ..FaultIo::default()
            };
            {
                let mut out = env.output();
                run_restore_with(
                    &db,
                    &restore_args_3550(snap),
                    true,
                    &mut out,
                    STANDARD,
                    &mut io,
                )
                .expect("Standard publishes despite a failed directory fsync");
            }
            let v = json_envelope(&env);
            assert_eq!(
                v["durable_publish"],
                serde_json::json!(false),
                "{before}/{after}"
            );
            assert!(
                env.stderr_str().contains("fsync"),
                "must warn: {}",
                env.stderr_str()
            );
            assert_eq!(memory_rows(&db), 1, "published ({before}/{after})");
        }
    }

    /// A clean run reports `durable_publish: true` and `selected_by`.
    #[test]
    fn restore_json_reports_a_durable_explicit_publish_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "durable");
        {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                true,
                &mut out,
                STANDARD,
                &mut FaultIo::default(),
            )
            .expect("restore must succeed");
        }
        let v = json_envelope(&env);
        assert_eq!(v["durable_publish"], serde_json::json!(true));
        assert_eq!(v["selected_by"], serde_json::json!("explicit"));
    }

    /// asi-hard: a directory fsync that fails BEFORE the rename refuses with
    /// nothing published; one that fails AFTER it is a non-zero exit with the
    /// envelope still saying `durable_publish: false`.
    #[test]
    fn asi_hard_enforces_a_durable_publish_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Before the rename: refused, the old corpus stays.
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "fsync-hard-pre");
        let mut io = FaultIo {
            fail_sync_before_publish: true,
            ..FaultIo::default()
        };
        let err = {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                true,
                &mut out,
                ASI_HARD,
                &mut io,
            )
            .expect_err("asi-hard must refuse a publish it cannot make durable")
        };
        assert!(format!("{err:#}").contains("asi-hard"), "got: {err:#}");
        assert!(!io.steps.contains(&PublishStep::Published));
        assert_eq!(memory_rows(&db), 2, "nothing published");
        assert_eq!(restore_tmp_leftovers(db.parent().unwrap()), 0);

        // After the rename: published, reported, non-zero.
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "fsync-hard-post");
        let mut io = FaultIo {
            fail_sync_after_publish: true,
            ..FaultIo::default()
        };
        let err = {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                true,
                &mut out,
                ASI_HARD,
                &mut io,
            )
            .expect_err("asi-hard must exit non-zero on a non-durable publish")
        };
        assert!(format!("{err:#}").contains("durable"), "got: {err:#}");
        assert_eq!(
            json_envelope(&env)["durable_publish"],
            serde_json::json!(false)
        );
        assert_eq!(memory_rows(&db), 1, "the restore itself was published");
    }

    /// Move a second, DIFFERENT snapshot into `dir` under the id `id`
    /// (so two snapshots share one directory without waiting a second for a
    /// distinct `backup` timestamp).
    fn plant_snapshot(env: &mut TestEnv, dir: &Path, id: &str, rows: usize) -> PathBuf {
        let scratch = TestEnv::fresh();
        let db = scratch.db_path.clone();
        for i in 0..rows {
            seed_memory(&db, "ns", &format!("planted-{i}"), "p");
        }
        let staging = dir.with_extension(format!("plant-{id}"));
        let manifest = take_backup(env, &db, &staging);
        let snap = dir.join(format!("{id}.{SNAPSHOT_FILE_EXT}"));
        std::fs::rename(staging.join(&manifest.snapshot), &snap).expect("move snapshot");
        let m = BackupManifest {
            snapshot: format!("{id}.{SNAPSHOT_FILE_EXT}"),
            ..manifest
        };
        std::fs::write(
            dir.join(manifest_file_name(id)),
            serde_json::to_string(&m).expect("manifest json"),
        )
        .expect("write manifest");
        snap
    }

    /// Cert battery: "misleading mtimes". The older snapshot is given the
    /// newest mtime. Without `--snapshot` it is what the fallback picks — and
    /// the operator is told so; with `--snapshot` the named one is restored
    /// whatever the mtimes say.
    #[test]
    fn snapshot_flag_beats_a_misleading_mtime_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "live", "l");
        let dir = db.parent().unwrap().join("backups-3550-mtime");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let old = plant_snapshot(&mut env, &dir, "ai-memory-2026-01-01T000000Z", 3);
        plant_snapshot(&mut env, &dir, "ai-memory-2026-06-01T000000Z", 1);
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .and_then(|f| f.set_modified(future))
            .expect("give the OLD snapshot the newest mtime");

        // Fallback: follows the mtime, and says so.
        let mut args = restore_args_3550(dir.clone());
        {
            let mut out = env.output();
            run_restore_with(
                &db,
                &args,
                true,
                &mut out,
                STANDARD,
                &mut FaultIo::default(),
            )
            .expect("fallback restore");
        }
        assert_eq!(
            json_envelope(&env)["selected_by"],
            serde_json::json!("mtime")
        );
        assert!(
            env.stderr_str().contains("MODIFICATION TIME"),
            "{}",
            env.stderr_str()
        );
        assert_eq!(
            memory_rows(&db),
            3,
            "the mtime pick is the (older) 3-row snapshot"
        );

        // Every accepted spelling of the id restores the named snapshot.
        for name in [
            "ai-memory-2026-06-01T000000Z",
            "ai-memory-2026-06-01T000000Z.db",
            "ai-memory-2026-06-01T000000Z.manifest.json",
        ] {
            env.stdout.clear();
            env.stderr.clear();
            // Each restore leaves a rollback copy; distinct timestamps are not
            // guaranteed within one second, so clear the previous one.
            for e in std::fs::read_dir(db.parent().unwrap())
                .expect("dir")
                .flatten()
            {
                if e.file_name().to_string_lossy().contains(PRE_RESTORE_INFIX) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
            args.snapshot = Some(name.to_owned());
            {
                let mut out = env.output();
                run_restore_with(
                    &db,
                    &args,
                    true,
                    &mut out,
                    STANDARD,
                    &mut FaultIo::default(),
                )
                .unwrap_or_else(|e| panic!("--snapshot {name}: {e:#}"));
            }
            assert_eq!(
                json_envelope(&env)["selected_by"],
                serde_json::json!("explicit")
            );
            assert!(!env.stderr_str().contains("MODIFICATION TIME"), "{name}");
            assert_eq!(
                memory_rows(&db),
                1,
                "--snapshot {name} restores the named snapshot"
            );
        }
    }

    /// asi-hard refuses the mtime pick outright and lists the candidates.
    #[test]
    fn asi_hard_refuses_the_mtime_pick_and_lists_candidates_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "live", "l");
        let dir = db.parent().unwrap().join("backups-3550-hard-mtime");
        std::fs::create_dir_all(&dir).expect("mkdir");
        plant_snapshot(&mut env, &dir, "ai-memory-2026-01-01T000000Z", 1);
        let before = std::fs::read(&db).expect("read live db");
        let err = {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(dir),
                false,
                &mut out,
                ASI_HARD,
                &mut FaultIo::default(),
            )
            .expect_err("asi-hard must refuse the mtime pick")
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("--snapshot"), "got: {msg}");
        assert!(
            msg.contains("ai-memory-2026-01-01T000000Z"),
            "candidates listed: {msg}"
        );
        assert_eq!(
            std::fs::read(&db).expect("read live db"),
            before,
            "untouched"
        );
    }

    #[test]
    fn snapshot_id_accepts_names_and_refuses_paths_3550() {
        for (name, want) in [
            ("ai-memory-x", Some("ai-memory-x")),
            ("ai-memory-x.db", Some("ai-memory-x")),
            ("ai-memory-x.DB", Some("ai-memory-x")),
            ("ai-memory-x.manifest.json", Some("ai-memory-x")),
            ("", None),
            (".", None),
            ("..", None),
            ("../ai-memory-x", None),
            ("dir/ai-memory-x", None),
            ("/abs/ai-memory-x", None),
            ("..\\ai-memory-x", None),
            (".manifest.json", None),
        ] {
            assert_eq!(snapshot_id(name), want, "{name:?}");
        }
    }

    /// `--snapshot` refuses a path, a `--from` that is a file, and a
    /// snapshot that is a symlink.
    #[test]
    fn snapshot_flag_refusals_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "live", "l");
        let dir = db.parent().unwrap().join("backups-3550-refusals");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let snap = plant_snapshot(&mut env, &dir, "ai-memory-2026-01-01T000000Z", 1);
        let before = std::fs::read(&db).expect("read live db");
        let mut cases: Vec<(PathBuf, String, &str)> = vec![
            (dir.clone(), "../escape".into(), "not a snapshot name"),
            (
                snap.clone(),
                "ai-memory-2026-01-01T000000Z".into(),
                "not a directory",
            ),
            (dir.clone(), "ai-memory-missing".into(), "no snapshot"),
        ];
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&snap, dir.join("ai-memory-link.db")).expect("symlink");
            cases.push((dir.clone(), "ai-memory-link".into(), "not a regular file"));
        }
        for (from, name, want) in cases {
            let mut args = restore_args_3550(from);
            args.snapshot = Some(name.clone());
            let err = {
                let mut out = env.output();
                run_restore_with(
                    &db,
                    &args,
                    false,
                    &mut out,
                    STANDARD,
                    &mut FaultIo::default(),
                )
                .expect_err("must refuse")
            };
            let msg = format!("{err:#}");
            assert!(
                msg.contains(want),
                "--snapshot {name}: want {want:?}, got: {msg}"
            );
        }
        assert_eq!(
            std::fs::read(&db).expect("read live db"),
            before,
            "untouched"
        );
    }

    /// The restored database keeps the permissions of the one it replaced,
    /// never the snapshot's — a world-writable snapshot used to publish a
    /// world-writable corpus.
    #[cfg(unix)]
    #[test]
    fn restore_keeps_the_replaced_databases_permissions_3550() {
        use std::os::unix::fs::PermissionsExt;
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "mode");
        std::fs::set_permissions(&snap, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                false,
                &mut out,
                STANDARD,
                &mut FaultIo::default(),
            )
            .expect("restore must succeed");
        }
        let mode = std::fs::metadata(&db).expect("stat").permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640, "the replaced database's mode is kept");
    }

    /// A hard link keeps the old database alive under another name: it must
    /// NOT be invalidated, and the operator is told it is still the old one.
    #[cfg(unix)]
    #[test]
    fn a_hard_linked_old_database_is_left_intact_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "hardlink");
        let link = db.with_extension("hardlink.db");
        std::fs::hard_link(&db, &link).expect("hard link");
        {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                false,
                &mut out,
                STANDARD,
                &mut FaultIo::default(),
            )
            .expect("restore must succeed");
        }
        assert_eq!(
            memory_rows(&link),
            2,
            "the linked old database must still open"
        );
        assert!(
            env.stderr_str().contains("hard"),
            "must warn: {}",
            env.stderr_str()
        );
        assert_eq!(memory_rows(&db), 1);
    }

    /// Defence in depth: a sidecar that appears beside the restored database
    /// during the publish is reported as a failure, not handed to a daemon.
    #[test]
    fn a_sidecar_appearing_during_the_publish_is_reported_3550() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let (db, snap) = two_row_live_one_row_snapshot(&mut env, "reappear");
        let mut io = FaultIo {
            observe: Some(Box::new(|step, target| {
                if step == PublishStep::Published {
                    std::fs::write(sidecar_path(target, "-journal"), b"x").expect("plant");
                }
            })),
            ..FaultIo::default()
        };
        let err = {
            let mut out = env.output();
            run_restore_with(
                &db,
                &restore_args_3550(snap),
                false,
                &mut out,
                STANDARD,
                &mut io,
            )
            .expect_err("a sidecar that appeared must fail the restore")
        };
        assert!(format!("{err:#}").contains("appeared"), "got: {err:#}");
        let _ = std::fs::remove_file(sidecar_path(&db, "-journal"));
    }

    /// `stage_and_verify` never touches the target: that is the whole point
    /// of staging. Pinned directly so a future refactor cannot quietly move
    /// the verification after the swap.
    #[test]
    fn stage_and_verify_refuses_a_damaged_file_without_publishing_it_3131() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-3131-stage");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let snap = backup_dir.join(&manifest.snapshot);
        damage_page_accounting(&snap);

        let before = std::fs::read(&db).expect("read live db");
        let staged = sidecar_path(&db, ".stage-probe-3131");
        let err = {
            let mut out = env.output();
            stage_and_verify(&snap, &staged, &mut out, false)
                .expect_err("damaged file must be refused")
        };
        assert!(err.to_string().contains("integrity_check"), "got: {err}");
        assert_eq!(
            std::fs::read(&db).expect("read live db"),
            before,
            "staging must never write to the target"
        );
        let _ = std::fs::remove_file(&staged);
    }

    /// v1.0.0 #3508 — the control that stands where `PRAGMA integrity_check`
    /// stopped standing.
    ///
    /// From schema v98 (#3401) the `inbox_namespace_aliases` VIEW heads the
    /// schema hash with root page 0, which makes SQLite run
    /// `integrity_check` as a PARTIAL check: it skips the freelist scan and
    /// the "every page in the file is referenced" pass, and answers `ok` on a
    /// snapshot carrying unaccounted pages. Before this control `run_restore`
    /// PUBLISHED such a snapshot over the live corpus. The test asserts on
    /// the OBSERVED verdict rather than hard-coding SQLite's behaviour, so a
    /// future SQLite (or a schema shuffle) that restores the full pass makes
    /// the primary gate fire instead — and the file is refused either way.
    #[test]
    fn stage_and_verify_refuses_pages_integrity_check_no_longer_reports_3508() {
        let _g = crate::store_url::store_url_env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns", "t", "c");
        let backup_dir = db.parent().unwrap().join("backups-3508-accounting");
        let manifest = take_backup(&mut env, &db, &backup_dir);
        let snap = backup_dir.join(&manifest.snapshot);

        // A sound snapshot must PASS both gates: this control may never
        // refuse a restore the operator is entitled to.
        let clean_staged = sidecar_path(&db, ".stage-clean-3508");
        {
            let mut out = env.output();
            stage_and_verify(&snap, &clean_staged, &mut out, false)
                .expect("a sound snapshot must verify");
        }
        let _ = std::fs::remove_file(&clean_staged);

        damage_page_accounting(&snap);
        let verdict: String = {
            let probe = db::open_read_only(&snap).expect("open damaged snapshot");
            probe
                .query_row("PRAGMA integrity_check", [], |r| r.get(0))
                .expect("integrity_check answers")
        };
        let staged = sidecar_path(&db, ".stage-accounting-3508");
        let err = {
            let mut out = env.output();
            stage_and_verify(&snap, &staged, &mut out, false)
                .expect_err("a snapshot with unaccounted pages must be refused")
        };
        let msg = err.to_string();
        if verdict == crate::storage::sqlite_integrity::SQLITE_INTEGRITY_OK {
            assert!(
                msg.contains("are accounted for") && msg.contains("#3508"),
                "integrity_check answered `ok` on a damaged file, so the #3508 \
                 page-accounting control must be the one refusing; got: {msg}"
            );
        } else {
            assert!(msg.contains("FAILED PRAGMA integrity_check"), "got: {msg}");
        }
        let _ = std::fs::remove_file(&staged);
    }

    // -- helpers -------------------------------------------------------

    /// v1.0.0 #3131 — make a real SQLite file fail `PRAGMA integrity_check`
    /// while still opening and answering schema/count queries.
    ///
    /// Appends five unreferenced pages and raises the header's page-count
    /// field (offset 28), stamping the "version-valid-for" counter
    /// (offset 92) to match the change counter (offset 24) so SQLite trusts
    /// the declared size. `integrity_check` then reports the orphaned pages
    /// ("Page N is never used"), which is deterministic — unlike flipping
    /// bytes in a page whose role depends on the layout of the day.
    fn damage_page_accounting(path: &Path) {
        let mut bytes = std::fs::read(path).expect("read db file");
        let page_size = match u16::from_be_bytes([bytes[16], bytes[17]]) {
            1 => 65_536_usize,
            n => n as usize,
        };
        let pages = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        bytes.extend(std::iter::repeat_n(0u8, page_size * 5));
        bytes[28..32].copy_from_slice(&(pages + 5).to_be_bytes());
        // Make the declared size authoritative: version-valid-for == change counter.
        let change_counter = [bytes[24], bytes[25], bytes[26], bytes[27]];
        bytes[92..96].copy_from_slice(&change_counter);
        std::fs::write(path, &bytes).expect("write damaged db file");
    }

    fn snapshot_count(dir: &Path) -> usize {
        std::fs::read_dir(dir).map_or(0, |entries| {
            entries
                .flatten()
                .filter(|e| {
                    let n = e.file_name();
                    let n = n.to_string_lossy();
                    n.starts_with("ai-memory-") && n.ends_with(".db")
                })
                .count()
        })
    }

    /// v1.0.0 #3131 — locate the single `<db>.pre-restore-<ts>.db` rollback
    /// copy `restore` leaves beside the target.
    fn find_pre_restore_copy(dir: &Path) -> PathBuf {
        let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
            .expect("read dir")
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                let name = p.file_name().unwrap_or_default().to_string_lossy();
                name.contains(PRE_RESTORE_INFIX) && name.ends_with(".db")
            })
            .collect();
        assert_eq!(
            found.len(),
            1,
            "restore must leave exactly one rollback copy; found {found:?}"
        );
        found.remove(0)
    }

    fn manifest_path_for(dir: &Path, snapshot: &str) -> PathBuf {
        let stem = Path::new(snapshot).file_stem().unwrap().to_string_lossy();
        dir.join(manifest_file_name(&stem))
    }

    /// Take a real backup and return the parsed manifest, clearing the
    /// captured buffers so the caller's assertions see only their own output.
    fn take_backup(env: &mut TestEnv, db: &Path, backup_dir: &Path) -> BackupManifest {
        let args = BackupArgs {
            to: backup_dir.to_path_buf(),
            keep: 48,
            store_url: None,
        };
        {
            let mut out = env.output();
            run_backup(db, &args, true, &mut out).unwrap();
        }
        let manifest: BackupManifest = serde_json::from_str(env.stdout_str().trim()).unwrap();
        env.stdout.clear();
        env.stderr.clear();
        manifest
    }
}

/// #3521 — durability-verb refusal arms (per-module coverage floor).
///
/// `restore` REPLACES the live database, so both of the guards below are
/// data-integrity gates rather than ergonomics:
///
/// * [`refuse_if_target_in_use`] refuses only on a POSITIVE liveness
///   signal. Its two other arms — the target cannot be opened at all, and
///   the probe was inconclusive — must WARN and PROCEED, because
///   restoring over a database nothing can open any more is exactly the
///   disaster-recovery case the verb exists for. A regression that turned
///   either into a refusal would strand an operator mid-recovery.
/// The sibling `resolve_sqlite_store` ambiguity refusals live in
/// `tests/cov_backup_store_url_3521.rs`: they mutate the process-global
/// store-URL environment, which `scripts/check-test-env-lock.sh` arm (d)
/// (issue #3475) requires to happen in its OWN test binary rather than in
/// the shared lib test binary whose cases run on parallel threads.
#[cfg(test)]
mod cov_backup_refusal_arms_3521 {
    use super::{CliOutput, refuse_if_target_in_use};

    fn capture<T>(f: impl FnOnce(&mut CliOutput<'_>) -> T) -> (T, String) {
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let value = {
            let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
            f(&mut out)
        };
        (value, String::from_utf8_lossy(&stderr).into_owned())
    }

    /// A target that EXISTS but cannot be opened read-write (here: a
    /// directory) is WARNed about and allowed through. Refusing would
    /// block the recovery this verb exists for.
    #[test]
    fn unopenable_target_warns_and_proceeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target-is-a-directory.db");
        std::fs::create_dir(&target).expect("mkdir");
        let (res, stderr) = capture(|out| refuse_if_target_in_use(&target, out));
        res.expect("an unopenable target must not refuse the restore");
        assert!(
            stderr.contains("cannot open") && stderr.contains("proceeding"),
            "the operator must be told the probe could not run; stderr was: {stderr}"
        );
    }

    /// A target that opens but is not a SQLite database at all makes the
    /// liveness probe INCONCLUSIVE (not `SQLITE_BUSY`). Same contract:
    /// warn, proceed — never a false "in use" refusal.
    #[test]
    fn inconclusive_probe_warns_and_proceeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("not-a-database.db");
        std::fs::write(&target, b"this is not a sqlite header at all\n").expect("write");
        let (res, stderr) = capture(|out| refuse_if_target_in_use(&target, out));
        res.expect("an inconclusive probe must not refuse the restore");
        assert!(
            stderr.contains("inconclusive") && stderr.contains("proceeding"),
            "the operator must be told the probe was inconclusive; stderr was: {stderr}"
        );
    }
}
