// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #5752 — a test that lets the audit sink mark its log append-only must hand
//! the file back removable. A flagged file cannot be unlinked, even by its
//! owner, so a leftover one under a tempdir poisons the next `actions/checkout`
//! on a self-hosted runner (#5657). [`AppendOnlyScratch`] clears the platform
//! flag on drop, so the file is removable on every exit path, a panicking
//! assertion included. Production keeps its append-only default untouched.

use std::path::{Path, PathBuf};

/// Clear the platform append-only flag on `path`. Best effort and infallible
/// for the caller: a missing file, an unsupported filesystem or a platform
/// without the flag all mean there is nothing to clear (`Drop` must not panic,
/// per OWNERSHIP-25).
pub(crate) fn clear_append_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
            return;
        };
        #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
        {
            // SAFETY: `c_path` is a NUL-terminated string owned for the call;
            // chflags(2) has no other obligation. Flags 0 drops UF_APPEND.
            let _ = unsafe { libc::chflags(c_path.as_ptr(), 0) };
        }
        #[cfg(target_os = "linux")]
        {
            const FS_APPEND_FL: libc::c_int = 0x0000_0020;
            // _IOR('f', 1, long) and _IOW('f', 2, long) on 64-bit Linux ABIs,
            // the same constants `mark_append_only` uses for the SET side.
            const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
            const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
            // SAFETY: `c_path` is a valid C string for the call.
            let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                return;
            }
            let mut flags: libc::c_int = 0;
            // SAFETY: `fd` is the descriptor opened above; GETFLAGS/SETFLAGS
            // read and write one `int` through the pointer to `flags`.
            unsafe {
                if libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) == 0 && flags & FS_APPEND_FL != 0 {
                    flags &= !FS_APPEND_FL;
                    let _ = libc::ioctl(fd, FS_IOC_SETFLAGS, &mut flags);
                }
                libc::close(fd);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Clears the append-only flag on the guarded path when dropped. Declare it
/// BEFORE the tempdir so it drops first (reverse declaration order,
/// OWNERSHIP-24), or hold it next to the path it covers.
pub(crate) struct AppendOnlyScratch {
    path: PathBuf,
}

impl AppendOnlyScratch {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Drop for AppendOnlyScratch {
    fn drop(&mut self) {
        clear_append_only(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #5752 — after the guard drops, the file the sink flagged is removable.
    /// Where the process may not set the flag (an unprivileged Linux user
    /// cannot) the sink only warns and the file is plain, so removal holds
    /// either way; where it can (macOS, root) the flag is really set first.
    #[test]
    fn guard_leaves_an_append_only_file_removable_5752() {
        let _lock = super::super::sink_test_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.log");
        std::fs::write(&path, b"").expect("seed");
        {
            let _scratch = AppendOnlyScratch::new(path.clone());
            super::super::init(&path, true, true).expect("init tolerates the flag outcome");
            super::super::shutdown_for_test();
        }
        std::fs::remove_file(&path).expect("a guarded audit.log must be removable");
        dir.close().expect("the scratch dir must be removable");
    }

    /// The guard is infallible on a path that never existed.
    #[test]
    fn guard_on_a_missing_path_is_a_noop_5752() {
        let dir = tempfile::tempdir().expect("tempdir");
        drop(AppendOnlyScratch::new(dir.path().join("never-created.log")));
    }
}
