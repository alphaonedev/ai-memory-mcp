// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Private export directories and atomic publication (#8592, #8593).
//! Existing directories are validated, never chmodded. Directory descriptors
//! anchor every namespace and publication operation against path substitution.

use std::io;
use std::path::Path;

/// Reject dot segments before `Path::components` can normalize them away.
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
    const PERMISSION_MASK: u32 = 0o7777;
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
                    current.0.sync_all()?;
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
            if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "export destination must be a regular file, never a symlink",
                ));
            }
            Ok(())
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
                // SAFETY (UNSAFE-01/02): removes only our O_EXCL-owned staging
                // entry, relative to its original directory; never follows links.
                if unsafe { libc::unlinkat(self.0.as_raw_fd(), stage.as_ptr(), 0) } != 0 {
                    return Err(io::Error::other(format!(
                        "{error}; removing private export stage: {}",
                        io::Error::last_os_error()
                    )));
                }
                return Err(error);
            }
            self.0.sync_all()
        }
    }
}

#[cfg(unix)]
pub(crate) use platform::PrivateExportDir;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    const PRIVATE_FILE_MODE: u32 = 0o600;
    const MODE_MASK: u32 = 0o777;

    fn scratch() -> tempfile::TempDir {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/private-export-8592-8593");
        fs::create_dir_all(&root).unwrap();
        tempfile::tempdir_in(root).unwrap()
    }

    #[test]
    fn publication_stays_in_opened_directory_after_root_and_namespace_replacement() {
        let scratch = scratch();
        let root_path = scratch.path().join("root");
        let root = PrivateExportDir::open(&root_path).unwrap();
        let namespace = root.namespace(Path::new("team")).unwrap();
        let outside = scratch.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let moved_root = scratch.path().join("moved-root");
        fs::rename(&root_path, &moved_root).unwrap();
        symlink(&outside, &root_path).unwrap();
        fs::rename(moved_root.join("team"), moved_root.join("moved-team")).unwrap();
        symlink(&outside, moved_root.join("team")).unwrap();
        namespace.write("persona.md", b"private").unwrap();
        assert_eq!(
            fs::read(moved_root.join("moved-team/persona.md")).unwrap(),
            b"private"
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        assert!(root.namespace(Path::new("team")).is_err());
    }

    #[test]
    fn root_symlinks_with_trailing_separators_are_refused() {
        let scratch = scratch();
        let outside = scratch.path().join("outside");
        PrivateExportDir::open(&outside).unwrap();
        let link = scratch.path().join("link");
        symlink(&outside, &link).unwrap();
        for suffix in ["", "/", "/."] {
            assert!(
                PrivateExportDir::open(Path::new(&format!("{}{suffix}", link.display()))).is_err()
            );
        }
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
    }

    #[test]
    fn nonregular_destination_and_unsafe_names_are_refused_without_staging() {
        let scratch = scratch();
        let root_path = scratch.path().join("root");
        let root = PrivateExportDir::open(&root_path).unwrap();
        fs::create_dir(root_path.join("directory.md")).unwrap();
        for name in ["directory.md", "", ".", "..", "../outside", "nul\0name"] {
            assert!(root.write(name, b"private").is_err());
        }
        assert_eq!(fs::read_dir(root_path).unwrap().count(), 1);
    }

    #[test]
    fn hardlinked_existing_file_is_replaced_without_modifying_the_other_link() {
        let scratch = scratch();
        let root_path = scratch.path().join("root");
        let root = PrivateExportDir::open(&root_path).unwrap();
        let outside = scratch.path().join("operator-file");
        fs::write(&outside, b"operator content").unwrap();
        fs::hard_link(&outside, root_path.join("persona.md")).unwrap();
        root.write("persona.md", b"private").unwrap();
        assert_eq!(fs::read(outside).unwrap(), b"operator content");
        assert_eq!(
            fs::metadata(root_path.join("persona.md")).unwrap().mode() & MODE_MASK,
            PRIVATE_FILE_MODE
        );
        assert_eq!(fs::read_dir(root_path).unwrap().count(), 1);
    }

    #[test]
    fn existing_private_directory_can_be_reopened_without_permission_changes() {
        let scratch = scratch();
        let path = scratch.path().join("root");
        PrivateExportDir::open(&path).unwrap();
        let permissions = fs::metadata(&path).unwrap().permissions().mode();
        let root = PrivateExportDir::open(&path).unwrap();
        root.namespace(Path::new("team/alpha"))
            .unwrap()
            .write("reflection.md", b"private")
            .unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode(),
            permissions
        );
    }
}

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
    pub(crate) fn write(&self, _: &str, _: &[u8]) -> io::Result<()> {
        Self::open(Path::new("")).map(|_| ())
    }
}
