// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6266 — crate-internal copy of the #6122 `tests/common/sqlite_tempfile.rs`
//! helper (copying the precedent is the decision; no vote needed) for the
//! `cfg(test)` unit tests under `src/`.
//!
//! A sqlite scratch file that owns its WAL side files.
//!
//! `tempfile::NamedTempFile` unlinks only the main database path when it
//! drops. A test binds the file, opens WAL-mode connections on it and (by
//! reverse declaration order) drops the file BEFORE the router / store that
//! owns the connections. SQLite refuses to delete the `-wal` on close once
//! the main file has moved, so every such test orphaned a `.tmp*-wal` and a
//! `.tmp*-shm` in `TMPDIR` for good.
//!
//! [`SqliteTempFile`] is the drop-in owner: it derefs to the inner
//! `NamedTempFile` (`path()`, `as_file()`, ...) and, when it drops, removes
//! the `-wal`, `-shm` and `-journal` siblings next to the main file, plus the
//! `<name>.pre-migration-*.bak` backups the schema migrator writes beside a
//! database it upgrades.

use std::ops::Deref;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

/// The sqlite side-file suffixes a WAL / rollback-journal database can leave.
pub(crate) const SIDE_FILE_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

/// The side-file paths for `db`.
pub(crate) fn side_files(db: &Path) -> Vec<PathBuf> {
    SIDE_FILE_SUFFIXES
        .iter()
        .map(|suffix| {
            let mut name = db.as_os_str().to_os_string();
            name.push(suffix);
            PathBuf::from(name)
        })
        .collect()
}

/// Remove the `<db-name>.pre-migration-*` backups next to `db` (best effort).
fn remove_migration_backups(db: &Path) {
    let (Some(dir), Some(name)) = (db.parent(), db.file_name()) else {
        return;
    };
    let mut prefix = name.to_os_string();
    prefix.push(".pre-migration-");
    let prefix = prefix.to_string_lossy().into_owned();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// A `NamedTempFile` that also removes the sqlite side files on drop.
#[derive(Debug)]
pub(crate) struct SqliteTempFile {
    inner: NamedTempFile,
}

impl SqliteTempFile {
    /// Create the scratch file in the process temp dir (drop-in for
    /// `NamedTempFile::new`).
    ///
    /// # Errors
    ///
    /// Any I/O error from `NamedTempFile::new`.
    pub(crate) fn new() -> std::io::Result<Self> {
        Ok(Self {
            inner: NamedTempFile::new()?,
        })
    }

    /// Create the scratch file inside `dir` (drop-in for
    /// `NamedTempFile::new_in`).
    ///
    /// # Errors
    ///
    /// Any I/O error from `NamedTempFile::new_in`.
    pub(crate) fn new_in<P: AsRef<Path>>(dir: P) -> std::io::Result<Self> {
        Ok(Self {
            inner: NamedTempFile::new_in(dir)?,
        })
    }
}

impl Deref for SqliteTempFile {
    type Target = NamedTempFile;
    fn deref(&self) -> &NamedTempFile {
        &self.inner
    }
}

impl Drop for SqliteTempFile {
    fn drop(&mut self) {
        // Best-effort teardown (OWNERSHIP-25: never panic in Drop). A missing
        // side file is the normal case when the connection closed cleanly.
        for side in side_files(self.inner.path()) {
            let _ = std::fs::remove_file(side);
        }
        remove_migration_backups(self.inner.path());
    }
}
