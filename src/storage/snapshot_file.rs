// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8679 - file-mode discipline for the pre-migration snapshot.
//!
//! `VACUUM INTO` creates its target with the process umask, so a snapshot of an
//! owner-only (0600) database could land world-readable. The snapshot is a
//! full copy of the durable tier and must be exactly as private as its source.
//! [`vacuum_into_private`] therefore fills an owner-only file staged in a
//! private (0700) directory ([`stage_beside`]), settles the source's permission
//! bits through the staged HANDLE, and publishes it by a no-replace link. Any
//! failure removes the staged file and surfaces as an error so the migration
//! does not proceed without a private snapshot (fail closed).
//!
//! #8950 - the same module is the ONE no-follow write path for a file the
//! product creates at a predictable name ([`stage_beside`] then
//! [`NoFollowStage::publish`]): nothing that sits at the destination name, a
//! symlink above all, is ever followed, chmod-ed or replaced. Nothing here
//! writes or chmods a final name BY NAME.

use anyhow::{Context, Result};
use std::path::Path;

/// Owner read/write only: the mode of a snapshot whose source mode is unknown.
#[cfg(unix)]
const OWNER_ONLY_MODE: u32 = 0o600;
/// Permission bits copied from the source (no setuid/setgid/sticky).
#[cfg(unix)]
const PERMISSION_BITS: u32 = 0o777;

/// The `what` of the pre-migration snapshot in every refusal.
const PRE_MIGRATION_WHAT: &str = "pre-migration snapshot";

/// `VACUUM INTO` the database behind `conn` as a NEW snapshot at `dest`
/// (#8679 mode, #8950 no-follow): staged privately beside `dest`, filled by
/// name only inside the private staging directory, the staged name proven to
/// still be the staged file, the source's mode set through the handle,
/// fsynced, then published without replacing anything at `dest`.
///
/// # Errors
/// Something sits at `dest`, the stage, `VACUUM INTO`, mode, fsync or
/// identity check fails, or the publish is refused.
pub(super) fn vacuum_into_private(
    conn: &rusqlite::Connection,
    dest: &Path,
    source: &Path,
) -> Result<()> {
    let stage = stage_beside(dest, PRE_MIGRATION_WHAT)?;
    #[cfg(test)]
    seam::fire(seam::Point::Fill, dest);
    // Single-quote-escape the target for the SQL string literal (the path is
    // crate-derived, but doubling quotes is the correct hygiene).
    let staged = stage.path().to_string_lossy().replace('\'', "''");
    conn.execute(&format!("VACUUM INTO '{staged}'"), [])
        .with_context(|| format!("VACUUM INTO the staged {}", stage.path().display()))?;
    #[cfg(test)]
    seam::fire(seam::Point::Filled, dest);
    stage.verify_identity()?;
    settle_mode_to_source(stage.file(), source)?;
    stage.sync_file()?;
    let (file, durability) = stage.publish()?;
    drop(file);
    // #10214: a snapshot not confirmed durable is no safety net, so the
    // migration does not proceed (fail closed); the snapshot stays on disk.
    require_durable(durability)
}

/// #10214 — the outcome of a publish whose new file IS in place at its final
/// name. `Err` from the funnel always means "not written"; a written file
/// whose directory fsync failed is [`Durability::NotDurable`], so no caller
/// can read it as "not written" (CBC-02, CBC-05). Every caller matches it
/// exhaustively, never removes the file, finishes its multi-file sequence and
/// then reports the outcome as an error.
#[must_use = "a NotDurable outcome must be reported: the file is written but not confirmed durable"]
#[derive(Debug)]
pub(crate) enum Durability {
    /// The new file and its directory entry are fsynced.
    Durable,
    /// The new file is in place; its directory fsync failed.
    NotDurable(NotDurable),
}

/// #10214 — "written, not confirmed durable": the complete new file is at
/// `dest`, the fsync of `dir` failed with `source`. Its `Display` names all
/// three, so [`std::error::Error::source`] is `None` (ERRORS-11).
#[derive(Debug)]
pub(crate) struct NotDurable {
    what: String,
    dest: std::path::PathBuf,
    dir: std::path::PathBuf,
    source: std::io::Error,
}

impl NotDurable {
    /// `what` at `dest` is written; the fsync of `dir` failed with `source`.
    pub(crate) fn new(what: &str, dest: &Path, dir: &Path, source: std::io::Error) -> Self {
        Self {
            what: what.to_owned(),
            dest: dest.to_path_buf(),
            dir: dir.to_path_buf(),
            source,
        }
    }

    /// The written file.
    #[cfg(test)]
    pub(crate) fn dest(&self) -> &Path {
        &self.dest
    }

    /// The OS error code of the failed directory fsync, when it has one.
    #[cfg(test)]
    pub(crate) fn raw_os_error(&self) -> Option<i32> {
        self.source.raw_os_error()
    }
}

/// #10214 — turn a single publish outcome into the caller's result: `Ok` when
/// durable, else the [`NotDurable`] report as the error (the file stays).
///
/// # Errors
/// The file is written but not confirmed durable.
pub(crate) fn require_durable(durability: Durability) -> Result<()> {
    match durability {
        Durability::Durable => Ok(()),
        Durability::NotDurable(not_durable) => Err(anyhow::Error::new(not_durable)),
    }
}

impl std::fmt::Display for NotDurable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} is written but not confirmed durable: the fsync of its directory {} failed \
             ({}), so it may not survive a crash (#10214)",
            self.what,
            self.dest.display(),
            self.dir.display(),
            self.source
        )
    }
}

impl std::error::Error for NotDurable {}

impl From<NotDurable> for std::io::Error {
    fn from(not_durable: NotDurable) -> Self {
        Self::new(not_durable.source.kind(), not_durable)
    }
}

/// #10214 — the not-durable outcomes of a multi-file sequence, collected
/// while the sequence runs to its end and reported once at the end, so a
/// failed directory fsync never stops a later file from being written.
#[must_use = "finish() the report: a NotDurable outcome must reach the caller"]
#[derive(Debug, Default)]
pub(crate) struct NotDurableReport(Vec<NotDurable>);

impl NotDurableReport {
    /// An empty report.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record one publish outcome.
    pub(crate) fn note(&mut self, durability: Durability) {
        match durability {
            Durability::Durable => {}
            Durability::NotDurable(not_durable) => self.0.push(not_durable),
        }
    }

    /// Whether every file noted so far is durable (#10291).
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `Ok` when every file is durable; otherwise the report as the error
    /// (every file named is written).
    ///
    /// # Errors
    /// At least one file is not confirmed durable.
    pub(crate) fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(anyhow::Error::new(self))
        }
    }

    /// #10310 — keep this report on a LATER error of the same sequence:
    /// `err` unchanged when every file noted so far is durable, otherwise
    /// `err` with the report as text context (precedent: the records of
    /// `scope::store` written before a failed audit line). The context is a
    /// `String`, never this type, so the combined error never downcasts to a
    /// [`NotDurableReport`] and is never read as "complete but not durable".
    pub(crate) fn context_on(self, err: anyhow::Error) -> anyhow::Error {
        if self.0.is_empty() {
            err
        } else {
            err.context(format!("{WRITTEN_BEFORE_THE_ERROR}: {self}"))
        }
    }
}

/// #10310 — the head of the context [`NotDurableReport::context_on`] puts on
/// a later error: the files it names are on disk, not confirmed durable.
pub(crate) const WRITTEN_BEFORE_THE_ERROR: &str =
    "files written before this error are kept on disk";

impl std::fmt::Display for NotDurableReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.as_slice() {
            [] => f.write_str("every file is written and durable"),
            [one] => one.fmt(f),
            many => {
                write!(
                    f,
                    "{} files are written but not confirmed durable: ",
                    many.len()
                )?;
                for (i, not_durable) in many.iter().enumerate() {
                    if i > 0 {
                        f.write_str("; ")?;
                    }
                    not_durable.fmt(f)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for NotDurableReport {}

/// Give the staged snapshot the source database's permission bits, through
/// its HANDLE (`fchmod`), never by name. An unreadable source mode yields
/// owner-only (the stricter answer). Non-unix: a no-op, the platform has no
/// permission bits to copy (the file keeps the mode its create gave it).
fn settle_mode_to_source(file: &std::fs::File, source: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(source).map_or(OWNER_ONLY_MODE, |meta| {
            meta.permissions().mode() & PERMISSION_BITS
        });
        file.set_permissions(std::fs::Permissions::from_mode(mode))
            .context("set pre-migration snapshot mode through its handle")?;
    }
    #[cfg(not(unix))]
    {
        let _ = (file, source);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// v1.0.0 #8950 — the ONE no-follow write path for a file the product creates
// at a predictable name (backup snapshot + manifest, doctor repair snapshot).
// ---------------------------------------------------------------------------

/// The tail of every refusal of a symlink planted at a destination.
pub(crate) const SYMLINK_REFUSAL_TAIL: &str =
    "a symlink sits at that path and would be followed (#8950)";

/// The exact refusal for a symlink at `dest`.
pub(crate) fn symlink_refusal(dest: &Path) -> String {
    format!(
        "refusing to write {}: {SYMLINK_REFUSAL_TAIL}",
        dest.display()
    )
}

/// Refuse `dest` when ANY entry sits at its final component, inspected with
/// `symlink_metadata` (never follows): a symlink — dangling, to a file or to a
/// directory — gets [`symlink_refusal`]; anything else gets
/// `refusing to overwrite existing <what> <dest>`. A symlinked PARENT is
/// followed: the class covers the final component only.
///
/// # Errors
/// Something sits at `dest`, or it cannot be inspected.
pub(crate) fn refuse_occupied(dest: &Path, what: &str) -> Result<()> {
    match std::fs::symlink_metadata(dest) {
        Ok(meta) if meta.file_type().is_symlink() => anyhow::bail!(symlink_refusal(dest)),
        Ok(_) => anyhow::bail!("refusing to overwrite existing {what} {}", dest.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("inspecting {}", dest.display()))),
    }
}

/// Open a NEW owner-only file for read and write: `create_new` (`O_EXCL`,
/// which also refuses a symlink, dangling or not) plus `O_NOFOLLOW`.
fn open_new_private(path: &Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(OWNER_ONLY_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))
}

/// The ONE `link(2)` call of the publish (the test seam sees every call).
fn link_no_replace(staged: &Path, dest: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(injected) = seam::on_link(dest) {
        return Err(injected);
    }
    std::fs::hard_link(staged, dest)
}

/// Test-only seam (`cfg(test)`, absent from every non-test build): a hook a
/// test runs at a named point of a snapshot write, a `link(2)` errno to
/// inject, and the log of every link call. All three are per thread.
#[cfg(test)]
pub(crate) mod seam {
    use std::cell::{Cell, RefCell};
    use std::path::{Path, PathBuf};

    /// Where the hook runs: before the writer fills the snapshot, after, and
    /// (with the STAGING name as the path) right after a successful link.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Point {
        Fill,
        Filled,
        Linked,
    }

    /// #10214 — the steps of a durable replace a test can fail: the staged
    /// file's fsync, the rename over the destination, and the fsync of the
    /// destination's directory.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Step {
        FileSync,
        Rename,
        DirSync,
    }

    type Hook = Box<dyn FnMut(Point, &Path)>;

    thread_local! {
        static HOOK: RefCell<Option<Hook>> = RefCell::new(None);
        static LINK_ERRNO: Cell<Option<i32>> = const { Cell::new(None) };
        static LINK_CALLS: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
        static STEP_ERRNO: Cell<Option<(Step, i32)>> = const { Cell::new(None) };
        static DIR_SYNCS: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
        static STEP_AT: Cell<Option<(Step, i32, u32)>> = const { Cell::new(None) };
    }

    /// Fail every later `step` of this thread with `errno` (#10214).
    pub(crate) fn inject_step_errno(step: Step, errno: i32) {
        STEP_ERRNO.with(|e| e.set(Some((step, errno))));
    }

    /// Fail only the `nth` (1-based) later `step` of this thread with
    /// `errno`; every other one succeeds (#10253: a failure point inside a
    /// multi-file sequence).
    pub(crate) fn inject_step_errno_at(step: Step, errno: i32, nth: u32) {
        STEP_AT.with(|e| e.set(Some((step, errno, nth))));
    }

    /// The one-shot failure of [`inject_step_errno_at`], counted down.
    fn step_at(step: Step) -> Option<std::io::Error> {
        let (failing, errno, nth) = STEP_AT.with(Cell::get)?;
        if failing != step {
            return None;
        }
        if nth > 1 {
            STEP_AT.with(|e| e.set(Some((failing, errno, nth - 1))));
            return None;
        }
        STEP_AT.with(|e| e.set(None));
        Some(std::io::Error::from_raw_os_error(errno))
    }

    /// The directories fsynced so far on this thread (and forget them).
    pub(crate) fn take_dir_syncs() -> Vec<PathBuf> {
        DIR_SYNCS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    /// Record `step` at `path` and return the injected failure, if any.
    pub(crate) fn on_step(step: Step, path: &Path) -> Option<std::io::Error> {
        if step == Step::DirSync {
            DIR_SYNCS.with(|c| c.borrow_mut().push(path.to_path_buf()));
        }
        if let Some(injected) = step_at(step) {
            return Some(injected);
        }
        match STEP_ERRNO.with(Cell::get) {
            Some((failing, errno)) if failing == step => {
                Some(std::io::Error::from_raw_os_error(errno))
            }
            _ => None,
        }
    }

    /// Run `hook(point, dest)` at every [`fire`] of this thread.
    pub(crate) fn set_hook(hook: impl FnMut(Point, &Path) + 'static) {
        HOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
    }

    /// Fail every later link call of this thread with `errno`.
    pub(crate) fn inject_link_errno(errno: Option<i32>) {
        LINK_ERRNO.with(|e| e.set(errno));
    }

    /// The destinations of the link calls so far (and forget them).
    pub(crate) fn take_link_calls() -> Vec<PathBuf> {
        LINK_CALLS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    /// Clear the hook, the injected errno and the call log.
    pub(crate) fn reset() {
        HOOK.with(|h| h.borrow_mut().take());
        inject_link_errno(None);
        drop(take_link_calls());
        STEP_ERRNO.with(|e| e.set(None));
        STEP_AT.with(|e| e.set(None));
        drop(take_dir_syncs());
    }

    pub(crate) fn fire(point: Point, dest: &Path) {
        let hook = HOOK.with(|h| h.borrow_mut().take());
        if let Some(mut hook) = hook {
            hook(point, dest);
            HOOK.with(|h| *h.borrow_mut() = Some(hook));
        }
    }

    pub(super) fn on_link(dest: &Path) -> Option<std::io::Error> {
        LINK_CALLS.with(|c| c.borrow_mut().push(dest.to_path_buf()));
        LINK_ERRNO
            .with(Cell::get)
            .map(std::io::Error::from_raw_os_error)
    }
}

/// The "name taken" answer of a publish: a symlink there is refused with
/// [`symlink_refusal`], anything else means try the next name.
fn name_taken(dest: &Path) -> Result<PublishAt> {
    refuse_symlink(dest)?;
    Ok(PublishAt::Taken)
}

/// The answer of one [`NoFollowStage::publish_at`] that did not fail.
enum PublishAt {
    /// The staged file is at the name; its directory fsync gave this.
    Published(Durability),
    /// Something already holds the name; nothing was replaced.
    Taken,
}

/// A `link(2)` failure that means the filesystem has no hard links, the only
/// one that may fall back (to [`rename_no_replace`]). Non-unix: none does.
fn no_hard_links(err: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            err.raw_os_error(),
            Some(libc::EPERM | libc::EOPNOTSUPP | libc::ENOSYS)
        )
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}

/// Rename `staged` to `dest` ATOMICALLY refusing an existing `dest` (`EEXIST`):
/// Linux `renameat2(RENAME_NOREPLACE)`, macOS `renamex_np(RENAME_EXCL)`. Any
/// other platform has no such call and refuses (`Unsupported`).
fn rename_no_replace(staged: &Path, dest: &Path) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::unix::ffi::OsStrExt;
        let c_path = |p: &Path| {
            std::ffi::CString::new(p.as_os_str().as_bytes())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        };
        let (from, to) = (c_path(staged)?, c_path(dest)?);
        // SAFETY: `from` and `to` are NUL-terminated C strings that outlive
        // the call; the call reads them and touches no Rust memory.
        #[cfg(target_os = "linux")]
        let rc = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        // SAFETY: as above.
        #[cfg(target_os = "macos")]
        let rc = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (staged, dest);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no atomic no-replace rename on this platform",
        ))
    }
}

/// Owner-only directory mode for the private staging directory.
#[cfg(unix)]
const OWNER_ONLY_DIR_MODE: u32 = 0o700;

/// Create a NEW owner-only directory (`mkdir(2)` fails on any existing entry,
/// a symlink included, and never follows it).
fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(OWNER_ONLY_DIR_MODE);
    }
    builder
        .create(path)
        .with_context(|| format!("creating the staging directory {}", path.display()))
}

/// The private staging directory and the staged file inside it; both are
/// removed on drop (the file only while the publish has not taken it over).
struct StagedName {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
    armed: bool,
}

impl Drop for StagedName {
    fn drop(&mut self) {
        if self.armed {
            // Removing by name removes only a link if one was swapped in.
            let _ = std::fs::remove_file(&self.path);
        }
        // Empty by now; a non-empty directory (an entry planted by the
        // owner) is left in place rather than walked.
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// A private file staged beside its destination, published without ever
/// following or replacing what sits at the destination name.
pub(crate) struct NoFollowStage {
    name: StagedName,
    dest: std::path::PathBuf,
    what: &'static str,
    file: std::fs::File,
}

/// Stage a new owner-only file beside `dest`: inside a freshly created
/// owner-only (0700) directory in `dest`'s directory, so no other account can
/// plant anything at the staged name while a writer that opens BY NAME
/// (`VACUUM INTO`, which takes no `O_NOFOLLOW`) fills it. The directory sits
/// on `dest`'s filesystem, so the publish is a link, not a copy.
///
/// # Errors
/// Something already sits at `dest` ([`refuse_occupied`]), `dest` has no file
/// name, or the staging directory or file cannot be created.
pub(crate) fn stage_beside(dest: &Path, what: &'static str) -> Result<NoFollowStage> {
    refuse_occupied(dest, what)?;
    stage_in_private_dir(dest, what)
}

/// Refuse `dest` when a symlink (dangling or not) sits at its final
/// component; an absent name or any other entry passes.
///
/// # Errors
/// A symlink sits at `dest`, or it cannot be inspected.
pub(crate) fn refuse_symlink(dest: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dest) {
        Ok(meta) if meta.file_type().is_symlink() => anyhow::bail!(symlink_refusal(dest)),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("inspecting {}", dest.display()))),
    }
}

/// How many numbered names [`write_new_private_unique`] tries after `dest`.
pub(crate) const UNIQUE_NAME_ATTEMPTS: u32 = 1000;

/// `dest` with `.{n}` appended to its file name.
fn numbered(dest: &Path, n: u32) -> std::path::PathBuf {
    let mut name = dest.as_os_str().to_owned();
    name.push(format!(".{n}"));
    std::path::PathBuf::from(name)
}

/// A NEW owner-only fsynced file at the first FREE name of `dest`, `dest.1`,
/// `dest.2`, ...: two backups taken in the same clock tick keep both copies
/// instead of the second failing (or, before #8950, overwriting the first).
/// A symlink at any tried name is refused, never skipped. Returns the name
/// written and its [`Durability`] (#10214: a failed directory fsync is
/// [`Durability::NotDurable`] with the file in place, never an `Err`).
///
/// # Errors
/// Nothing is written: a symlink sits at a tried name, all
/// [`UNIQUE_NAME_ATTEMPTS`] numbered names are taken, or the stage, write,
/// fsync or publish fails.
pub(crate) fn write_new_private_unique(
    dest: &Path,
    what: &'static str,
    bytes: &[u8],
) -> Result<(std::path::PathBuf, Durability)> {
    let mut stage = stage_in_private_dir(dest, what)?;
    stage.write_all(bytes)?;
    stage.sync_file()?;
    for n in 0..=UNIQUE_NAME_ATTEMPTS {
        let candidate = if n == 0 {
            dest.to_path_buf()
        } else {
            numbered(dest, n)
        };
        match stage.publish_at(&candidate)? {
            PublishAt::Published(durability) => return Ok((candidate, durability)),
            PublishAt::Taken => {}
        }
    }
    anyhow::bail!(
        "refusing to write {what} {}: it and {UNIQUE_NAME_ATTEMPTS} numbered names beside it are taken",
        dest.display()
    )
}

/// Replace the product-owned file at `dest` with `bytes` (owner-only,
/// fsynced) by a rename, refusing a symlink at the name instead of following
/// or replacing it. A regular file there is replaced; an absent one created.
/// #10214: the rename is made durable by an fsync of `dest`'s directory.
///
/// `dest` holds exactly the before or the after bytes. An `Err` means NOT
/// written: a failure up to and including the rename leaves the old file (or
/// none) and removes the stage. After the rename the new file is in place and
/// the directory fsync's outcome is returned as [`Durability`]; a failure
/// there is [`Durability::NotDurable`], never swallowed and never an `Err`.
///
/// # Errors
/// Not written: a symlink sits at `dest`, or the stage, write, fsync or
/// rename fails.
pub(crate) fn write_replacing(dest: &Path, what: &'static str, bytes: &[u8]) -> Result<Durability> {
    refuse_symlink(dest)?;
    let mut stage = stage_in_private_dir(dest, what)?;
    stage.write_all(bytes)?;
    stage.sync_file()?;
    stage.verify_identity()?;
    refuse_symlink(dest)?;
    rename_replacing(&stage.name.path, dest)
        .with_context(|| format!("replacing {what} {} (#10214)", dest.display()))?;
    stage.name.armed = false;
    Ok(sync_parent_dir(dest, what))
}

/// The ONE staged-file fsync of the funnel (the test seam sees it).
fn sync_staged(file: &std::fs::File, staged: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(injected) = seam::on_step(seam::Step::FileSync, staged) {
        return Err(injected);
    }
    #[cfg(not(test))]
    let _ = staged;
    file.sync_all()
}

/// The ONE replacing `rename(2)` of the funnel (the test seam sees it).
fn rename_replacing(staged: &Path, dest: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(injected) = seam::on_step(seam::Step::Rename, dest) {
        return Err(injected);
    }
    std::fs::rename(staged, dest)
}

/// The directory that holds `dest` (`.` for a bare file name).
fn parent_dir(dest: &Path) -> &Path {
    match dest.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// #10214 — the ONE directory fsync of the product: a rename or link is
/// durable only once the directory that holds the new name is synced. Unix
/// opens the directory read-only (`O_DIRECTORY`, so a non-directory is
/// refused) and `fsync`s it. Every error is returned, `EINVAL` from a
/// filesystem that cannot sync a directory included (fail closed: a rename
/// lost to a crash is lost data). Non-unix has no directory handle to sync
/// and returns `Ok(())`, as `erasure::store::fsync_dir` does.
///
/// # Errors
/// The directory cannot be opened or its fsync fails.
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(dir)?;
        fsync_dir_handle(&handle, dir)
    }
    #[cfg(not(unix))]
    {
        #[cfg(test)]
        if let Some(injected) = seam::on_step(seam::Step::DirSync, dir) {
            return Err(injected);
        }
        let _ = dir;
        Ok(())
    }
}

/// The directory `fsync(2)` itself. The test seam stands in for this one
/// syscall (the open before it is real), so an injected errno, `EINVAL`
/// included, takes exactly the path a real one takes (#10265).
#[cfg(unix)]
fn fsync_dir_handle(handle: &std::fs::File, dir: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if let Some(injected) = seam::on_step(seam::Step::DirSync, dir) {
        return Err(injected);
    }
    #[cfg(not(test))]
    let _ = dir;
    handle.sync_all()
}

/// Fsync the directory of the just-published `dest` ([`sync_dir`]). The new
/// file is in place whatever the answer: a failure is
/// [`Durability::NotDurable`] ("written, not confirmed durable"), and the
/// caller must not remove the file.
pub(crate) fn sync_parent_dir(dest: &Path, what: &str) -> Durability {
    let dir = parent_dir(dest);
    match sync_dir(dir) {
        Ok(()) => Durability::Durable,
        Err(source) => Durability::NotDurable(NotDurable::new(what, dest, dir, source)),
    }
}

/// The staging step shared by [`stage_beside`] and [`write_replacing`].
fn stage_in_private_dir(dest: &Path, what: &'static str) -> Result<NoFollowStage> {
    let name = dest
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", dest.display()))?;
    let dir = parent_dir(dest);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let stage_dir = dir.join(format!(
        ".{}.stage-{}-{nonce}",
        name.to_string_lossy(),
        std::process::id()
    ));
    create_private_dir(&stage_dir)?;
    let mut staged_name = StagedName {
        path: stage_dir.join(name),
        dir: stage_dir,
        armed: false,
    };
    let file = open_new_private(&staged_name.path)?;
    staged_name.armed = true;
    Ok(NoFollowStage {
        name: staged_name,
        dest: dest.to_path_buf(),
        what,
        file,
    })
}

impl NoFollowStage {
    /// The private staging path (what `VACUUM INTO` is pointed at).
    pub(crate) fn path(&self) -> &Path {
        &self.name.path
    }

    /// The destination the publish creates.
    pub(crate) fn dest(&self) -> &Path {
        &self.dest
    }

    /// The staged file's handle: hash, size and fsync come from HERE, never
    /// from a name.
    pub(crate) fn file(&self) -> &std::fs::File {
        &self.file
    }

    /// Fsync the staged file through its handle (#10214: the one file-sync
    /// step of the funnel, seen by the test seam).
    ///
    /// # Errors
    /// The fsync fails.
    pub(crate) fn sync_file(&self) -> Result<()> {
        sync_staged(&self.file, &self.name.path).with_context(|| {
            format!(
                "fsync the staged {} for {} (#10214)",
                self.what,
                self.dest.display()
            )
        })
    }

    /// Write `bytes` through the handle.
    ///
    /// # Errors
    /// The write fails.
    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        self.file
            .write_all(bytes)
            .with_context(|| format!("staging {} {}", self.what, self.name.path.display()))
    }

    /// Prove the staging NAME still names the staged handle's file. `VACUUM
    /// INTO` writes by name, so a name swapped for a symlink (or another file)
    /// after the create must not be published. Unix compares the
    /// (device, inode) pair of the name and the handle. Non-unix has no inode
    /// to compare: it checks only that the name is a regular file (not a
    /// symlink), so a swapped regular file there is not detected.
    ///
    /// # Errors
    /// The name is gone, is a symlink, or names a different file.
    pub(crate) fn verify_identity(&self) -> Result<()> {
        let path = &self.name.path;
        let by_name = std::fs::symlink_metadata(path)
            .with_context(|| format!("inspecting the staged file {}", path.display()))?;
        if by_name.file_type().is_symlink() {
            anyhow::bail!(symlink_refusal(path));
        }
        #[cfg(unix)]
        let same = {
            use std::os::unix::fs::MetadataExt;
            let by_handle = self
                .file
                .metadata()
                .with_context(|| format!("fstat of {}", path.display()))?;
            (by_name.dev(), by_name.ino()) == (by_handle.dev(), by_handle.ino())
        };
        #[cfg(not(unix))]
        let same = by_name.file_type().is_file();
        if !same {
            anyhow::bail!(
                "refusing to publish {}: the staged file {} was replaced while it was written (#8950)",
                self.dest.display(),
                path.display()
            );
        }
        Ok(())
    }

    /// Publish the staged file at the destination WITHOUT replacing anything
    /// there: a hard link (`link(2)` fails on any existing entry, a dangling
    /// symlink included, and never follows it), then the staging name is
    /// dropped (best effort). Only a link failure that means "no hard links
    /// here" (`EPERM`, `EOPNOTSUPP`, `ENOSYS`) falls back, and only to an
    /// atomic no-replace rename ([`rename_no_replace`]); a platform without
    /// one, and every other errno, is refused. #10214: the publish then
    /// fsyncs the destination's directory ([`sync_parent_dir`]). Returns the
    /// handle and that fsync's [`Durability`].
    ///
    /// # Errors
    /// Not published: the identity check fails, something sits at the
    /// destination, or the link (or its no-replace fallback) fails; the
    /// staging name is removed. A failed directory fsync is not an `Err`: it
    /// is [`Durability::NotDurable`] with the complete new file in place.
    pub(crate) fn publish(mut self) -> Result<(std::fs::File, Durability)> {
        let dest = self.dest.clone();
        match self.publish_at(&dest)? {
            PublishAt::Published(durability) => Ok((self.file, durability)),
            PublishAt::Taken => anyhow::bail!(
                "refusing to overwrite existing {} {}",
                self.what,
                dest.display()
            ),
        }
    }

    /// ONE no-follow, create-new `link(2)` at `dest`. I-2: nothing that
    /// exists at `dest` is replaced, for any errno. A publish fsyncs `dest`'s
    /// directory and carries the outcome (#10214).
    fn publish_at(&mut self, dest: &Path) -> Result<PublishAt> {
        self.verify_identity()?;
        match link_no_replace(&self.name.path, dest) {
            Ok(()) => {
                // X-5: the file is published; a staging name that will not go
                // away now is retried by Drop and never fails the publish.
                #[cfg(test)]
                seam::fire(seam::Point::Linked, &self.name.path);
                if std::fs::remove_file(&self.name.path).is_ok() {
                    self.name.armed = false;
                }
                Ok(PublishAt::Published(sync_parent_dir(dest, self.what)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => name_taken(dest),
            Err(e) if no_hard_links(&e) => match rename_no_replace(&self.name.path, dest) {
                Ok(()) => {
                    self.name.armed = false;
                    Ok(PublishAt::Published(sync_parent_dir(dest, self.what)))
                }
                Err(r) if r.kind() == std::io::ErrorKind::AlreadyExists => name_taken(dest),
                Err(r) => Err(anyhow::Error::new(r).context(format!(
                    "refusing to publish {} {}: no hard links here (the link failed: {e}) \
                     and the no-replace rename failed (#8950)",
                    self.what,
                    dest.display()
                ))),
            },
            Err(e) => Err(anyhow::Error::new(e).context(format!(
                "refusing to publish {} {}: the link failed and no fallback applies (#8950)",
                self.what,
                dest.display()
            ))),
        }
    }
}
