// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 K-4 — the cross-process key-directory lock.
//!
//! `serve`, `curator`, MCP stdio and every CLI invocation on a host share one
//! key directory, and several can start at once. An in-process mutex only
//! serialises the threads of ONE process; two processes that both find the
//! directory empty each read the other's half-written pair as a partial key.
//! [`KeyDirLock`] is an OS advisory lock (std [`std::fs::File::lock`], `flock`
//! on unix) on [`KEY_DIR_LOCK_FILE`] at the root of the key directory, held
//! across every check-then-write of the key files, so for any number of
//! processes exactly one creates the key and every other one loads it.
//!
//! The lock file holds no key material and is never read. Taking the lock has
//! a deadline: a lock that cannot be taken is a typed [`KeyDirLockError`],
//! never an unlocked write (fail closed).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The lock file at the root of a key directory. A dotfile, so it never
/// matches the `<agent>.pub` / `<agent>.priv` key-file shapes.
pub(crate) const KEY_DIR_LOCK_FILE: &str = ".keystore.lock";
/// How long [`KeyDirLock::acquire`] waits for another process to release the
/// lock before it refuses. Key provisioning holds the lock for one key
/// generation and two small writes, so a holder past this is wedged.
const KEY_DIR_LOCK_WAIT: Duration = Duration::from_secs(30);
/// The pause between two attempts while another process holds the lock.
const KEY_DIR_LOCK_POLL: Duration = Duration::from_millis(10);
/// The lock file's mode: owner read and write, like a private key.
#[cfg(unix)]
const KEY_DIR_LOCK_MODE: u32 = 0o600;

/// Why a [`KeyDirLock`] could not be taken. Each kind keeps its own cause.
#[derive(Debug)]
pub enum KeyDirLockError {
    /// The key directory could not be created, or is insecure.
    KeyDir(anyhow::Error),
    /// The lock file could not be opened, or the lock call failed.
    Lock {
        /// The lock file.
        path: PathBuf,
        /// The I/O failure.
        source: io::Error,
    },
    /// Another process held the lock past the deadline.
    TimedOut {
        /// The lock file.
        path: PathBuf,
        /// How long this process waited.
        waited: Duration,
    },
}

impl std::fmt::Display for KeyDirLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyDir(_) => f.write_str("the key directory cannot hold a lock file"),
            Self::Lock { path, .. } => {
                write!(
                    f,
                    "the key directory lock {} cannot be taken",
                    path.display()
                )
            }
            Self::TimedOut { path, waited } => write!(
                f,
                "the key directory lock {} was held by another process for {}s",
                path.display(),
                waited.as_secs()
            ),
        }
    }
}

impl std::error::Error for KeyDirLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyDir(e) => Some(e.as_ref()),
            Self::Lock { source, .. } => Some(source),
            Self::TimedOut { .. } => None,
        }
    }
}

/// The exclusive lock on one key directory. It is the only way to reach the
/// key-file writes ([`super::save_locked`], [`super::ensure_keypair_locked`]
/// take it), and it is released when it drops.
#[must_use = "the key directory lock is released when the guard drops"]
#[derive(Debug)]
pub struct KeyDirLock {
    dir: PathBuf,
    _file: fs::File,
}

impl KeyDirLock {
    /// Take the lock on `dir`, creating `dir` (mode 0700) and the lock file
    /// when absent, waiting up to [`KEY_DIR_LOCK_WAIT`] for another holder.
    ///
    /// # Errors
    /// [`KeyDirLockError`]: the directory is unusable, the lock file cannot be
    /// opened or locked, or the deadline passed.
    pub fn acquire(dir: &Path) -> Result<Self, KeyDirLockError> {
        Self::acquire_within(dir, KEY_DIR_LOCK_WAIT)
    }

    fn acquire_within(dir: &Path, wait: Duration) -> Result<Self, KeyDirLockError> {
        let path = dir.join(KEY_DIR_LOCK_FILE);
        super::ensure_parent(&path).map_err(KeyDirLockError::KeyDir)?;
        super::enforce_key_path_chain_secure(dir, &path).map_err(KeyDirLockError::KeyDir)?;
        let file = open_lock_file(&path).map_err(|source| KeyDirLockError::Lock {
            path: path.clone(),
            source,
        })?;
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => {
                    return Ok(Self {
                        dir: dir.to_path_buf(),
                        _file: file,
                    });
                }
                Err(fs::TryLockError::WouldBlock) => {
                    let waited = started.elapsed();
                    if waited >= wait {
                        return Err(KeyDirLockError::TimedOut { path, waited });
                    }
                    std::thread::sleep(KEY_DIR_LOCK_POLL);
                }
                Err(fs::TryLockError::Error(source)) => {
                    return Err(KeyDirLockError::Lock { path, source });
                }
            }
        }
    }

    /// `Ok` iff this guard locks `dir`; a guard for another directory never
    /// authorises a write here.
    ///
    /// # Errors
    /// When `dir` is not the directory this guard locks.
    pub(crate) fn check_guards(&self, dir: &Path) -> anyhow::Result<()> {
        if self.dir == dir {
            Ok(())
        } else {
            anyhow::bail!(
                "the key directory lock held is for {}, not {}",
                self.dir.display(),
                dir.display()
            )
        }
    }
}

/// Open (or create) the lock file without following a symlink.
fn open_lock_file(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(KEY_DIR_LOCK_MODE);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(".local-runs")
            .join("k4-10108-lock")
            .join(format!("{tag}-{}-{nanos}", std::process::id()))
    }

    /// A held lock is a typed `TimedOut` at the deadline, never an unlocked
    /// guard; once released it is taken.
    #[test]
    fn a_held_lock_times_out_typed_then_is_taken_10108() {
        let dir = run_dir("held");
        let first = KeyDirLock::acquire(&dir).expect("first lock");
        let err = KeyDirLock::acquire_within(&dir, Duration::from_millis(50))
            .expect_err("a second guard must not be granted while the first is held");
        assert!(
            matches!(err, KeyDirLockError::TimedOut { .. }),
            "expected TimedOut, got {err:?}"
        );
        drop(first);
        let again = KeyDirLock::acquire_within(&dir, Duration::from_millis(50))
            .expect("the released lock is taken");
        again.check_guards(&dir).expect("guards its own dir");
        assert!(
            again.check_guards(&dir.join("other")).is_err(),
            "a guard never authorises another directory"
        );
        drop(again);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A lock path that cannot be opened as a file is a typed `Lock` error.
    #[test]
    fn an_unopenable_lock_file_is_a_typed_lock_error_10108() {
        let dir = run_dir("dir");
        fs::create_dir_all(dir.join(KEY_DIR_LOCK_FILE)).expect("plant a directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        let err = KeyDirLock::acquire(&dir).expect_err("a directory is not a lock file");
        assert!(
            matches!(err, KeyDirLockError::Lock { .. }),
            "expected Lock, got {err:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
