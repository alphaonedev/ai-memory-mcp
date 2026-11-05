// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Private export directories and atomic publication (#8592, #8593).
//! Existing directories are validated, never chmodded. Directory descriptors
//! anchor every namespace and publication operation against path substitution.

use std::io;
use std::path::Path;

/// Name an operator-selected namespace directory while callers preserve the cause.
pub(crate) fn namespace_context(path: &Path) -> String {
    format!("opening private namespace dir {}", path.display())
}

/// Validate a single component, rejecting empty names, dot names, and separators.
pub(crate) fn validate_component(component: &str) -> io::Result<()> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains(['/', '\0'])
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe export path component",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
thread_local! {
    static DIRECTORY_SYNC_CALLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static STAGING_SWEEP_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static FAIL_STALE_REMOVAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static STALE_REMOVAL_ATTEMPTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_DIRECTORY_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_BEFORE_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_STAGE_CLEANUP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(unix)]
mod stale;

#[cfg(unix)]
mod platform {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs::{DirBuilder, File, OpenOptions};
    use std::io::Write;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::Component;

    const DIRECTORY_MODE: u32 = 0o700;
    const MKDIR_MODE: libc::mode_t = 0o700;
    const FILE_MODE: libc::c_uint = 0o600;
    const PERMISSION_MASK: u32 = 0o777;
    const OPEN_DIRECTORY: libc::c_int =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    pub(crate) struct PrivateExportDir(File);

    fn name(value: &str) -> io::Result<CString> {
        validate_component(value)?;
        CString::new(value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in export name"))
    }

    fn owned_fd(fd: libc::c_int) -> io::Result<File> {
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY (UNSAFE-01/02): callers pass only fresh successful openat
        // descriptors; ownership is transferred exactly once to File.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn sync_directory(directory: &File) -> io::Result<()> {
        #[cfg(test)]
        DIRECTORY_SYNC_CALLED.set(true);
        #[cfg(test)]
        if FAIL_DIRECTORY_SYNC.get() {
            return Err(io::Error::other(
                "private export directory sync injected failure",
            ));
        }
        directory.sync_all()
    }

    fn remove_stage(directory: &File, stage: &CStr) -> io::Result<()> {
        #[cfg(test)]
        if FAIL_STAGE_CLEANUP.get() {
            return Err(io::Error::other(
                "private export stage cleanup injected failure",
            ));
        }
        // SAFETY (UNSAFE-01/02): removes only our O_EXCL-owned staging
        // entry relative to its original live directory; never follows links.
        if unsafe { libc::unlinkat(directory.as_raw_fd(), stage.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    impl PrivateExportDir {
        pub(crate) fn open(root: &Path) -> io::Result<Self> {
            // Remove trailing separators and normalized dot segments so a
            // root written as "link/" cannot bypass final-component NOFOLLOW.
            let root: std::path::PathBuf = root.components().collect();
            DirBuilder::new()
                .recursive(true)
                .mode(DIRECTORY_MODE)
                .create(&root)?;
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(OPEN_DIRECTORY)
                .open(&root)?;
            Self::checked(directory)
        }

        fn checked(directory: File) -> io::Result<Self> {
            let metadata = directory.metadata()?;
            // SAFETY (UNSAFE-01): geteuid has no arguments or memory preconditions.
            let uid = unsafe { libc::geteuid() };
            if !metadata.is_dir()
                || metadata.mode() & PERMISSION_MASK != DIRECTORY_MODE
                || metadata.uid() != uid
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "export directory must be owned by the current user with mode 0700; choose a private root or repair its permissions explicitly",
                ));
            }
            Ok(Self(directory))
        }

        pub(crate) fn namespace(&self, relative: &Path) -> io::Result<Self> {
            let mut current = Self::checked(self.0.try_clone()?)?;
            for component in relative.components() {
                let Component::Normal(component) = component else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unsafe export namespace",
                    ));
                };
                let component = component.to_str().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "non-UTF8 export namespace")
                })?;
                let component = name(component)?;
                // SAFETY (UNSAFE-01/02): valid live directory fd and NUL-terminated
                // single component; mkdirat retains no pointers.
                let result =
                    unsafe { libc::mkdirat(current.0.as_raw_fd(), component.as_ptr(), MKDIR_MODE) };
                if result != 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                } else {
                    sync_directory(&current.0)?;
                }
                // SAFETY (UNSAFE-01/02): same fd/name lifetime; O_NOFOLLOW rejects
                // symlinks and O_DIRECTORY requires an actual directory.
                let fd = unsafe {
                    libc::openat(current.0.as_raw_fd(), component.as_ptr(), OPEN_DIRECTORY)
                };
                current = Self::checked(owned_fd(fd)?)?;
            }
            Ok(current)
        }

        fn check_destination(&self, destination: &CStr) -> io::Result<()> {
            let mut metadata = MaybeUninit::<libc::stat>::uninit();
            // SAFETY (UNSAFE-01/02): valid directory fd, C string and writable
            // stat storage. No symlink traversal; output read only on success.
            let result = unsafe {
                libc::fstatat(
                    self.0.as_raw_fd(),
                    destination.as_ptr(),
                    metadata.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result != 0 {
                let error = io::Error::last_os_error();
                return if error.kind() == io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(error)
                };
            }
            // SAFETY (UNSAFE-02): successful fstatat initialized the stat object.
            let metadata = unsafe { metadata.assume_init() };
            if metadata.st_mode & libc::S_IFMT == libc::S_IFLNK {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private_export_symlink_refused",
                ));
            }
            if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private_export_non_regular_refused",
                ));
            }
            Ok(())
        }

        /// Best-effort cleanup through this checked directory descriptor.
        /// Call once per destination directory per export operation, before writes.
        pub(crate) fn sweep_stale_staging(&self) {
            stale::sweep(&self.0);
        }

        /// Replaces the inode, never truncates an existing file or follows links.
        /// A directory-sync error is reported after publication without rollback.
        pub(crate) fn write(&self, filename: &str, body: &[u8]) -> io::Result<()> {
            let destination = name(filename)?;
            self.check_destination(&destination)?;
            let stage = name(&format!(".private-export-{}.stage", uuid::Uuid::new_v4()))?;
            // SAFETY (UNSAFE-01/02): live directory fd, valid single component,
            // required mode argument supplied with O_CREAT. O_EXCL owns this stage.
            let fd = unsafe {
                libc::openat(
                    self.0.as_raw_fd(),
                    stage.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    FILE_MODE,
                )
            };
            let mut file = owned_fd(fd)?;
            let publish = (|| {
                file.write_all(body)?;
                file.sync_all()?;
                // OWNERSHIP-24: close the staging descriptor before publication.
                drop(file);
                #[cfg(test)]
                if FAIL_BEFORE_RENAME.get() {
                    return Err(io::Error::other(
                        "private export before rename injected failure",
                    ));
                }
                self.check_destination(&destination)?;
                // SAFETY (UNSAFE-01/02): both names are valid single components
                // within the same live directory; renameat follows neither leaf.
                if unsafe {
                    libc::renameat(
                        self.0.as_raw_fd(),
                        stage.as_ptr(),
                        self.0.as_raw_fd(),
                        destination.as_ptr(),
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            })();
            if let Err(error) = publish {
                if let Err(cleanup) = remove_stage(&self.0, &stage) {
                    return Err(io::Error::other(format!(
                        "{error}; removing private export stage: {cleanup}"
                    )));
                }
                return Err(error);
            }
            sync_directory(&self.0)
        }
    }
}

#[cfg(unix)]
pub(crate) use platform::PrivateExportDir;

#[cfg(all(test, unix))]
mod tests;

#[cfg(not(unix))]
pub(crate) struct PrivateExportDir;

#[cfg(not(unix))]
impl PrivateExportDir {
    pub(crate) fn open(_: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private exports require Unix file permissions",
        ))
    }
    pub(crate) fn namespace(&self, _: &Path) -> io::Result<Self> {
        Self::open(Path::new(""))
    }
    pub(crate) fn sweep_stale_staging(&self) {}
    pub(crate) fn write(&self, _: &str, _: &[u8]) -> io::Result<()> {
        Self::open(Path::new("")).map(|_| ())
    }
}
