// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6122 — a sqlite scratch file that owns its WAL side files.
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
//! the `-wal`, `-shm` and `-journal` siblings next to the main file.
//!
//! Include with `#[path = "common/sqlite_tempfile.rs"] mod sqlite_tempfile;`
//! (the same leaf-helper idiom as `common/key_dir_sandbox.rs`).

#![allow(dead_code)]

use std::ops::Deref;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

/// The sqlite side-file suffixes a WAL / rollback-journal database can leave.
pub const SIDE_FILE_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

/// The side-file paths for `db`.
pub fn side_files(db: &Path) -> Vec<PathBuf> {
    SIDE_FILE_SUFFIXES
        .iter()
        .map(|suffix| {
            let mut name = db.as_os_str().to_os_string();
            name.push(suffix);
            PathBuf::from(name)
        })
        .collect()
}

/// A `NamedTempFile` that also removes the sqlite side files on drop.
#[derive(Debug)]
pub struct SqliteTempFile {
    inner: NamedTempFile,
}

impl SqliteTempFile {
    /// Create the scratch file in the process temp dir.
    ///
    /// # Errors
    ///
    /// Any I/O error from `NamedTempFile::new`.
    pub fn try_new() -> std::io::Result<Self> {
        Ok(Self {
            inner: NamedTempFile::new()?,
        })
    }

    /// Create the scratch file inside `dir`.
    ///
    /// # Errors
    ///
    /// Any I/O error from `Builder::tempfile_in`.
    pub fn try_new_in(dir: &Path) -> std::io::Result<Self> {
        Ok(Self {
            inner: tempfile::Builder::new().tempfile_in(dir)?,
        })
    }

    /// Create the scratch file inside `dir`; panics on I/O failure (test code).
    pub fn new_in(dir: &Path) -> Self {
        Self::try_new_in(dir).expect("tempfile_in")
    }

    /// Create the scratch file; panics on I/O failure (test code).
    pub fn new() -> Self {
        Self::try_new().expect("tempfile")
    }
}

impl Default for SqliteTempFile {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for SqliteTempFile {
    type Target = NamedTempFile;
    fn deref(&self) -> &NamedTempFile {
        &self.inner
    }
}
