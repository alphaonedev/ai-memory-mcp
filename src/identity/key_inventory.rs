// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Orphan-key inventory. Registry failures refuse the operation; even expired
//! registrations protect their keys. Key material is never read or reported.

use anyhow::{Context as _, Result, bail};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Default, serde::Serialize)]
pub struct Inventory {
    pub orphan_files: Vec<String>,
    /// Public-only peer/guardian verification material; retained by default.
    pub enrolled_public_keys: Vec<String>,
    pub protected_files: Vec<String>,
    pub skipped_symlinks: Vec<String>,
    pub deleted_files: Vec<String>,
}

pub(crate) fn registered_ids(
    metadata: impl IntoIterator<Item = String>,
) -> Result<BTreeSet<String>> {
    metadata
        .into_iter()
        .map(|raw| {
            let value: serde_json::Value = serde_json::from_str(&raw)?;
            let id = value
                .get("agent_id")
                .and_then(serde_json::Value::as_str)
                .filter(|id| !id.is_empty())
                .context("registry row has no agent_id; refusing key pruning")?;
            crate::validate::validate_agent_id_shape(id)?;
            Ok(id.to_owned())
        })
        .collect()
}

/// Scan regular key files; optionally remove unregistered files. The caller
/// must hold a registry write-excluding transaction throughout deletion.
pub(crate) fn inspect(
    dir: &Path,
    registered: &BTreeSet<String>,
    delete: bool,
    include_public_only: bool,
) -> Result<Inventory> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::inspect(dir, registered, delete, include_public_only)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (dir, registered, delete, include_public_only);
        bail!("key inventory requires descriptor-relative filesystem support on this platform")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use super::*;
    use std::ffi::{CStr, CString, OsString};
    use std::fs::File;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::Component;

    // Open each component relative to an already pinned descriptor. O_NOFOLLOW
    // applies at EVERY level, including the supplied key root's ancestors.
    fn child(parent: &File, name: &std::ffi::OsStr) -> Result<File> {
        let name = CString::new(name.as_bytes())?;
        // SAFETY: parent owns a live fd; name is a NUL-terminated CString.
        // openat returns a new fd, owned solely by the File below (UNSAFE-01).
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: successful openat transferred a fresh, valid descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn root(path: &Path) -> Result<File> {
        let path = std::path::absolute(path)?;
        let mut dir = File::open("/")?;
        for part in path.components() {
            match part {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => dir = child(&dir, name)?,
                _ => bail!("key directory must not contain parent traversal"),
            }
        }
        Ok(dir)
    }

    struct DirectoryStream(std::ptr::NonNull<libc::DIR>);

    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns the successful fdopendir result.
            // closedir also closes its transferred descriptor; Drop never panics.
            unsafe {
                libc::closedir(self.0.as_ptr());
            }
        }
    }

    fn names(dir: &File) -> Result<Vec<OsString>> {
        let fd = dir.try_clone()?.into_raw_fd();
        // SAFETY: fd is an owned, open directory descriptor; fdopendir takes
        // ownership on success only. Every arm below owns its cleanup.
        let stream = unsafe { libc::fdopendir(fd) };
        let Some(stream) = std::ptr::NonNull::new(stream) else {
            let error = std::io::Error::last_os_error();
            // SAFETY: fdopendir failed and did not consume the valid fd.
            drop(unsafe { File::from_raw_fd(fd) });
            return Err(error.into());
        };
        let stream = DirectoryStream(stream);
        let mut result = Vec::new();
        loop {
            // SAFETY: errno accessors return a valid thread-local pointer.
            #[cfg(target_os = "macos")]
            let errno = unsafe { libc::__error() };
            #[cfg(not(target_os = "macos"))]
            let errno = unsafe { libc::__errno_location() };
            // SAFETY: live thread-local errno, and uniquely owned stream.
            // readdir's entry remains valid until the next call on this stream.
            let entry = unsafe {
                *errno = 0;
                libc::readdir(stream.0.as_ptr())
            };
            if entry.is_null() {
                // SAFETY: errno is still the same live thread-local pointer.
                if unsafe { *errno } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                break;
            }
            // SAFETY: successful readdir initializes d_name as a NUL-terminated
            // string; copy it before the next call can invalidate the pointer.
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes != b"." && bytes != b".." {
                result.push(OsString::from_vec(bytes.to_vec()));
            }
        }
        Ok(result)
    }

    fn file_kind(dir: &File, name: &std::ffi::OsStr) -> Result<libc::mode_t> {
        let name = CString::new(name.as_bytes())?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the fd and CString are live, stat points to writable space
        // of the required size, and success fully initializes it (UNSAFE-15).
        if unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: fstatat returned success, fully initializing stat.
        Ok(unsafe { stat.assume_init() }.st_mode & libc::S_IFMT)
    }

    fn walk(
        dir: &File,
        prefix: &Path,
        ids: &BTreeSet<String>,
        delete: bool,
        include_public_only: bool,
        out: &mut Inventory,
    ) -> Result<()> {
        // Snapshot file kinds before unlinking: readdir order must not make a
        // paired public key appear enrolled after its private sibling is pruned.
        let entries = names(dir)?
            .into_iter()
            .map(|name| file_kind(dir, &name).map(|kind| (name, kind)))
            .collect::<Result<Vec<_>>>()?;
        let private_files: BTreeSet<_> = entries
            .iter()
            .filter(|(name, kind)| *kind == libc::S_IFREG && name.as_bytes().ends_with(b".priv"))
            .map(|(name, _)| name.clone())
            .collect();
        for (name, kind) in entries {
            let relative = prefix.join(&name);
            let label = relative
                .to_str()
                .context("non-UTF-8 key filename; refusing pruning")?;
            if kind == libc::S_IFLNK {
                out.skipped_symlinks.push(label.to_owned());
                continue;
            }
            if kind == libc::S_IFDIR {
                if !name.as_bytes().starts_with(b".") {
                    walk(
                        &child(dir, &name)?,
                        &relative,
                        ids,
                        delete,
                        include_public_only,
                        out,
                    )?;
                }
                continue;
            }
            if kind != libc::S_IFREG {
                continue;
            }
            let Some(stem) = label
                .strip_suffix(".priv")
                .or_else(|| label.strip_suffix(".pub"))
            else {
                continue;
            };
            let owner = stem.strip_suffix(".x25519").unwrap_or(stem);
            let system_key = [
                super::super::keypair::DAEMON_KEYPAIR_LABEL,
                crate::governance::audit::WITNESS_KEY_LABEL,
                crate::governance::capability::OWNER_ISSUER,
            ]
            .contains(&owner)
                || [
                    crate::governance::rules_store::OPERATOR_PUBKEY_KEYGEN_FILE,
                    crate::governance::rules_store::OPERATOR_PUBKEY_LEGACY_FILE,
                ]
                .iter()
                .any(|file| file.strip_suffix(".pub") == Some(owner));
            if system_key || ids.contains(stem) || ids.contains(owner) {
                out.protected_files.push(label.to_owned());
                continue;
            }
            let public_only = label.ends_with(".pub")
                && !private_files.contains(Path::new(&name).with_extension("priv").as_os_str());
            if public_only {
                out.enrolled_public_keys.push(label.to_owned());
                if !include_public_only {
                    continue;
                }
            } else {
                out.orphan_files.push(label.to_owned());
            }
            if delete {
                let name = CString::new(name.as_bytes())?;
                // SAFETY: live pinned parent fd and valid CString; flags=0
                // unlinks this entry only, never a symlink target or directory.
                if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                    return Err(std::io::Error::last_os_error()).context("unlink orphan key");
                }
                out.deleted_files.push(label.to_owned());
            }
        }
        Ok(())
    }

    pub(super) fn inspect(
        path: &Path,
        ids: &BTreeSet<String>,
        delete: bool,
        include_public_only: bool,
    ) -> Result<Inventory> {
        let dir = match root(path) {
            Ok(dir) => dir,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(Inventory::default());
            }
            Err(e) => return Err(e).context("open key directory without following symlinks"),
        };
        let mut result = Inventory::default();
        walk(
            &dir,
            Path::new(""),
            ids,
            delete,
            include_public_only,
            &mut result,
        )?;
        result.orphan_files.sort();
        result.enrolled_public_keys.sort();
        result.protected_files.sort();
        result.skipped_symlinks.sort();
        result.deleted_files.sort();
        Ok(result)
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn paired_keys_prune_independent_of_creation_order() {
        for private_first in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().canonicalize().unwrap();
            std::fs::create_dir(dir.join("nested")).unwrap();
            for stem in ["pair", "nested/pair.x25519"] {
                let suffixes = if private_first {
                    ["priv", "pub"]
                } else {
                    ["pub", "priv"]
                };
                for suffix in suffixes {
                    std::fs::write(dir.join(format!("{stem}.{suffix}")), b"fixture").unwrap();
                }
            }
            let result = inspect(&dir, &BTreeSet::new(), true, false).unwrap();
            assert_eq!(result.orphan_files.len(), 4);
            assert_eq!(result.deleted_files, result.orphan_files);
            assert!(result.enrolled_public_keys.is_empty());
            for name in result.deleted_files {
                assert!(!dir.join(name).exists());
            }
        }
    }

    #[test]
    fn public_keys_require_regular_private_siblings_in_the_same_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().canonicalize().unwrap();
        std::fs::create_dir(dir.join("nested")).unwrap();
        std::fs::write(dir.join("peer.priv"), b"fixture").unwrap();
        std::fs::write(dir.join("nested/peer.pub"), b"fixture").unwrap();
        std::fs::write(dir.join("guardian.x25519.pub"), b"fixture").unwrap();
        std::os::unix::fs::symlink("peer.priv", dir.join("guardian.x25519.priv")).unwrap();
        let result = inspect(&dir, &BTreeSet::new(), true, false).unwrap();
        assert_eq!(
            result.enrolled_public_keys,
            ["guardian.x25519.pub", "nested/peer.pub"]
        );
        assert_eq!(result.deleted_files, ["peer.priv"]);
        assert_eq!(result.skipped_symlinks, ["guardian.x25519.priv"]);
        for name in &result.enrolled_public_keys {
            assert_eq!(std::fs::read(dir.join(name)).unwrap(), b"fixture");
        }
        let preview = inspect(&dir, &BTreeSet::new(), false, true).unwrap();
        assert!(preview.deleted_files.is_empty());
        let removed = inspect(&dir, &BTreeSet::new(), true, true).unwrap();
        assert_eq!(removed.deleted_files, result.enrolled_public_keys);
    }
}
