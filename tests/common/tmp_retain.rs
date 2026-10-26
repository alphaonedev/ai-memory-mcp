// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Sidecar-clean sqlite temp files and exit-time retention (#6122).
//!
//! Test fixtures back a sqlite store with `tempfile::NamedTempFile`. Dropping a
//! `NamedTempFile` unlinks only the primary file: the `-wal` / `-shm` /
//! `-journal` sidecars the store created next to it were never removed, so each
//! suite run left 140+ `.tmp*` entries in `TMPDIR`. Helpers that cannot hand
//! the guard back to the caller used `std::mem::forget(tmp)`, which leaked the
//! whole file by design.
//!
//! * [`SidecarTempFile`] is a drop-in for `NamedTempFile` (it derefs to it)
//!   whose `Drop` also removes the sqlite sidecars.
//! * [`retain`] parks any guard until the process exits, then drops it through
//!   one `atexit` hook, so a fixture helper can keep the file alive for every
//!   connection and still leave nothing behind.
//!
//! Take it with the `#[path]` leaf idiom, no other module is pulled in:
//!
//! ```ignore
//! #[path = "common/tmp_retain.rs"]
//! mod tmp_retain;
//! ```

#![allow(dead_code)]

use std::any::Any;
use std::io;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::Once;

use tempfile::{NamedTempFile, TempDir};

/// SQLite side files created next to a database file.
const SIDECAR_SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

/// A `NamedTempFile` whose drop also unlinks the sqlite sidecars.
#[derive(Debug)]
pub struct SidecarTempFile {
    inner: Option<NamedTempFile>,
    base: PathBuf,
}

impl SidecarTempFile {
    /// Create the file in the system temp directory.
    pub fn new() -> io::Result<Self> {
        NamedTempFile::new().map(Self::wrap)
    }

    /// Create the file inside `dir`.
    pub fn new_in<P: AsRef<Path>>(dir: P) -> io::Result<Self> {
        NamedTempFile::new_in(dir).map(Self::wrap)
    }

    fn wrap(inner: NamedTempFile) -> Self {
        let base = inner.path().to_path_buf();
        Self {
            inner: Some(inner),
            base,
        }
    }
}

impl Deref for SidecarTempFile {
    type Target = NamedTempFile;

    fn deref(&self) -> &NamedTempFile {
        // `inner` is `Some` for the whole life of the value; `Drop` is the only taker.
        self.inner.as_ref().expect("SidecarTempFile inner present")
    }
}

impl DerefMut for SidecarTempFile {
    fn deref_mut(&mut self) -> &mut NamedTempFile {
        self.inner.as_mut().expect("SidecarTempFile inner present")
    }
}

impl io::Write for SidecarTempFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut **self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut **self)
    }
}

impl io::Read for SidecarTempFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut **self, buf)
    }
}

impl io::Seek for SidecarTempFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        io::Seek::seek(&mut **self, pos)
    }
}

impl Drop for SidecarTempFile {
    fn drop(&mut self) {
        drop(self.inner.take());
        remove_sidecars(&self.base);
    }
}

fn remove_sidecars(base: &Path) {
    for suffix in SIDECAR_SUFFIXES {
        let mut name = base.as_os_str().to_os_string();
        name.push(suffix);
        // Best effort: an already-absent sidecar is the goal state.
        let _ = std::fs::remove_file(PathBuf::from(name));
    }
    remove_dotted_siblings(base);
}

/// Remove `<file>.<anything>` siblings the code under test derives from a
/// database path (`.pre-migration-*.bak` backups, `.deferred-audit.journal`
/// and its `.spool`, `.tls3705` material). The random `.tmpXXXXXX` stem makes a
/// collision with an unrelated file impossible.
fn remove_dotted_siblings(base: &Path) {
    let (Some(dir), Some(stem)) = (base.parent(), base.file_name()) else {
        return;
    };
    let mut prefix = stem.to_os_string();
    prefix.push(".");
    let prefix = prefix.to_string_lossy().into_owned();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        let path = entry.path();
        // Best effort: a vanished entry is the goal state.
        let _ = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
    }
}

/// Removes a database file path (and sidecars and derived siblings) when dropped.
///
/// For tests that build a `uuid`-named db path by hand instead of holding a
/// temp-file handle.
#[derive(Debug)]
pub struct DbFiles(PathBuf);

impl DbFiles {
    #[must_use]
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self(path.into())
    }
}

impl Drop for DbFiles {
    fn drop(&mut self) {
        // Best effort: an already-absent file is the goal state.
        let _ = std::fs::remove_file(&self.0);
        remove_sidecars(&self.0);
    }
}

impl Retainable for DbFiles {}

/// Removes a directory tree when dropped (a hand-built `uuid`-named scratch dir).
#[derive(Debug)]
pub struct RemoveTree(PathBuf);

impl RemoveTree {
    #[must_use]
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self(path.into())
    }
}

impl Drop for RemoveTree {
    fn drop(&mut self) {
        // Best effort: an already-absent tree is the goal state.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Retainable for RemoveTree {}

static REGISTRY: Mutex<Vec<Box<dyn Any + Send>>> = Mutex::new(Vec::new());
static HOOK: Once = Once::new();

/// A guard [`retain`] can park until process exit.
pub trait Retainable: Any + Send {}

impl Retainable for TempDir {}
impl Retainable for SidecarTempFile {}

extern "C" fn cleanup_at_exit() {
    let parked = match REGISTRY.lock() {
        Ok(mut g) => std::mem::take(&mut *g),
        Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
    };
    drop(parked);
}

/// [`retain`] a [`TempDir`] that a `static` would otherwise never drop, and
/// hand back its path for the `static` to hold (#6122).
pub fn retain_keep_path(dir: TempDir) -> PathBuf {
    let path = dir.path().to_path_buf();
    retain(dir);
    path
}

/// Keep `guard` (and the file or directory it owns) alive until the process
/// exits, then delete it together with any sqlite sidecars.
pub fn retain<T: Retainable>(guard: T) {
    #[cfg(unix)]
    HOOK.call_once(|| {
        // SAFETY: `cleanup_at_exit` is an `extern "C" fn()` as `atexit`
        // requires and touches only process-owned statics.
        unsafe {
            libc::atexit(cleanup_at_exit);
        }
    });
    #[cfg(not(unix))]
    HOOK.call_once(|| {});
    REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(Box::new(guard));
}
