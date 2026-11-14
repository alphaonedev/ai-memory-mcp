// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8679 - file-mode discipline for the pre-migration snapshot.
//!
//! `VACUUM INTO` creates its target with the process umask, so a snapshot of an
//! owner-only (0600) database could land world-readable. The snapshot is a
//! full copy of the durable tier and must be exactly as private as its source.
//! The target is therefore created first, owner-only, with `create_new`
//! (`O_EXCL`: never follows a planted symlink, never reuses a file), handed to
//! `VACUUM INTO` as the empty file SQLite accepts, and only then settled to the
//! source's permission bits. Any failure removes the file and surfaces as an
//! error so the migration does not proceed without a private snapshot (fail
//! closed). The same backup precedent is `backup.rs` `PRIVATE_FILE_MODE`.
//!
//! #8950 - the same module is the ONE no-follow write path for a file the
//! product creates at a predictable name ([`stage_beside`] then
//! [`NoFollowStage::publish`]): nothing that sits at the destination name, a
//! symlink above all, is ever followed or replaced.

use anyhow::{Context, Result};
use std::path::Path;

/// Owner read/write only: the mode of a snapshot whose source mode is unknown.
#[cfg(unix)]
const OWNER_ONLY_MODE: u32 = 0o600;
/// Permission bits copied from the source (no setuid/setgid/sticky).
#[cfg(unix)]
const PERMISSION_BITS: u32 = 0o777;

/// Create the empty snapshot target, owner-only, failing if it already exists.
pub(super) fn create_private_target(target: &Path) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(OWNER_ONLY_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
        .open(target)
        .map(drop)
        .with_context(|| format!("create pre-migration snapshot target {}", target.display()))
}

/// Give the finished snapshot the source database's permission bits.
///
/// An unreadable source mode yields owner-only (the stricter answer).
pub(super) fn settle_mode_to_source(target: &Path, source: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(source).map_or(OWNER_ONLY_MODE, |meta| {
            meta.permissions().mode() & PERMISSION_BITS
        });
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("set pre-migration snapshot mode on {}", target.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (target, source);
    }
    Ok(())
}

/// Best-effort removal of a half-made snapshot after a failure.
pub(super) fn discard(target: &Path) {
    // The error that made us discard is the one reported; a failed remove
    // leaves at worst an owner-only empty or partial file (never world-readable).
    let _ = std::fs::remove_file(target);
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

/// Create a NEW owner-only file at `dest` holding `bytes`, fsynced, without
/// following or replacing anything at the name (a timestamped backup of a
/// config, say).
///
/// # Errors
/// Something sits at `dest`, or the stage, write, fsync or publish fails.
pub(crate) fn write_new_private(dest: &Path, what: &'static str, bytes: &[u8]) -> Result<()> {
    let mut stage = stage_beside(dest, what)?;
    stage.write_all(bytes)?;
    stage
        .file()
        .sync_all()
        .with_context(|| format!("fsync {}", stage.path().display()))?;
    drop(stage.publish()?);
    Ok(())
}

/// Replace the product-owned file at `dest` with `bytes` (owner-only,
/// fsynced) by a rename, refusing a symlink at the name instead of following
/// or replacing it. A regular file there is replaced; an absent one created.
///
/// # Errors
/// A symlink sits at `dest`, or the stage, write, fsync or rename fails.
pub(crate) fn write_replacing(dest: &Path, what: &'static str, bytes: &[u8]) -> Result<()> {
    refuse_symlink(dest)?;
    let mut stage = stage_in_private_dir(dest, what)?;
    stage.write_all(bytes)?;
    stage
        .file()
        .sync_all()
        .with_context(|| format!("fsync {}", stage.path().display()))?;
    stage.verify_identity()?;
    refuse_symlink(dest)?;
    std::fs::rename(&stage.name.path, dest)
        .with_context(|| format!("replacing {}", dest.display()))?;
    stage.name.armed = false;
    Ok(())
}

/// The staging step shared by [`stage_beside`] and [`write_replacing`].
fn stage_in_private_dir(dest: &Path, what: &'static str) -> Result<NoFollowStage> {
    let name = dest
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", dest.display()))?;
    let dir = match dest.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
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

    /// Write `bytes` through the handle.
    ///
    /// # Errors
    /// The write fails.
    pub(crate) fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        self.file
            .write_all(bytes)
            .with_context(|| format!("writing {}", self.name.path.display()))
    }

    /// Prove the staging NAME still names the staged handle's file. `VACUUM
    /// INTO` writes by name, so a name swapped for a symlink (or another file)
    /// after the create must not be published.
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
    /// dropped. A filesystem with no hard links falls back to a re-checked
    /// rename. The caller fsyncs the directory. Returns the handle.
    ///
    /// # Errors
    /// The identity check fails, something sits at the destination, or the
    /// link, rename or unlink fails (the staging name is then removed).
    pub(crate) fn publish(mut self) -> Result<std::fs::File> {
        self.verify_identity()?;
        match std::fs::hard_link(&self.name.path, &self.dest) {
            Ok(()) => {
                std::fs::remove_file(&self.name.path).with_context(|| {
                    format!("removing the staging name {}", self.name.path.display())
                })?;
                self.name.armed = false;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                refuse_occupied(&self.dest, self.what)?;
                return Err(
                    anyhow::Error::new(e).context(format!("publishing {}", self.dest.display()))
                );
            }
            Err(_) => {
                refuse_occupied(&self.dest, self.what)?;
                std::fs::rename(&self.name.path, &self.dest)
                    .with_context(|| format!("publishing {}", self.dest.display()))?;
                self.name.armed = false;
            }
        }
        Ok(self.file)
    }
}
