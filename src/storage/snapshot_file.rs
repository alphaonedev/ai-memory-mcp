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
        options.mode(OWNER_ONLY_MODE);
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
