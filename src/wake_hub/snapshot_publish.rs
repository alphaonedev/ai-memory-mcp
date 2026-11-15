// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3971 / #3637 (M4) — the privileged hand-off of the refreshed
//! allowlist snapshot into the hub's runtime directory.
//!
//! # Why this exists
//!
//! The refresher derives the snapshot as `User=ai-memory` (it opens the store)
//! into `/var/lib/ai-memory/hub-allow.json`. The hub runs as
//! `User=ai-memory-hub` and only accepts a snapshot owned by ITS uid at exact
//! mode 0600, inside a 0700 runtime directory the refresher cannot write. So a
//! root step has to move the file across the uid boundary.
//!
//! That step used to be `ExecStartPost=+/usr/bin/install …`, which had two
//! defects:
//!
//! * **CWE-59.** Root copied from a path the `ai-memory` uid can rewrite, and
//!   `install(1)` dereferences its source, so the less-privileged writer chose
//!   what root read.
//! * **Not atomic.** `install(1)` unlinks the destination and re-creates it,
//!   so the hub could find no snapshot, or a partial root-owned one.
//!
//! # The invariant
//!
//! No step that runs with more privilege than the writer of its input opens
//! that input through a path the writer can redirect, and a refusal publishes
//! nothing.
//!
//! [`publish_snapshot`] walks both parent directories from `/` one component
//! at a time with `O_NOFOLLOW | O_DIRECTORY`, so no symlink at any level is
//! followed. It refuses unless the source directory belongs to a non-root uid,
//! the destination directory belongs to a DIFFERENT uid, and neither directory
//! is group- or world-writable (#3971 W-8). It opens the source relative to
//! its pinned directory with `O_NOFOLLOW | O_NONBLOCK` and proves through
//! `fstat` on that same descriptor that it is a regular, single-link, 0600
//! file owned by the directory's owner and within the byte ceiling. It fully
//! validates the snapshot with the hub's own reader, then writes a canonical
//! re-encoding to an `O_EXCL` temp file in the destination directory, hands
//! that inode to the directory's owner at mode 0600, `fsync`s it, `renameat`s
//! it over the old snapshot and `fsync`s the directory. A hub reading
//! concurrently sees the whole old snapshot or the whole new one.
//!
//! Every refusal is one line naming its exact reason; the CLI prefixes it with
//! `wake-hub: --publish-snapshot refused:` and exits
//! [`crate::cli::wake_hub::EXIT_PUBLISH_REFUSED`].

use std::path::Path;

use anyhow::Result;

/// What a successful hand-off published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishReport {
    /// Number of agents in the published snapshot.
    pub agents: usize,
    /// Uid that owns the published inode (the destination directory's owner).
    pub owner_uid: u32,
}

/// Publish the snapshot at `source` to `dest` without following symlinks and
/// with an atomic rename. See the module docs for every check.
///
/// # Errors
///
/// One error, never a chain, naming the exact reason: a relative or
/// traversing path; a symlink anywhere on either path; a source directory that
/// is root-owned or group/world-writable; a source that is not a single-link
/// 0600 regular file owned by its directory's owner, or is over the byte
/// ceiling; a snapshot that fails the hub's validation; a destination
/// directory that is group/world-writable or shares the source directory's
/// owner; and any I/O failure. Nothing is published on any error.
pub fn publish_snapshot(source: &Path, dest: &Path) -> Result<PublishReport> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::publish(source, dest)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (source, dest);
        anyhow::bail!("this platform has no descriptor-relative filesystem support")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use super::PublishReport;
    use crate::wake_hub::delegation_verifier::{AllowlistCache, MAX_ALLOWLIST_BYTES};
    use anyhow::{Result, anyhow, bail};
    use std::ffi::{CString, OsStr, OsString};
    use std::fs::File;
    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Component, Path, PathBuf};

    /// Mode of the published inode, and the only source mode accepted.
    const SNAPSHOT_MODE: u32 = 0o600;
    /// Permission bits that let a group or other uid write a directory.
    const GROUP_OR_WORLD_WRITE: u32 = 0o022;
    /// Permission and special bits compared on a mode.
    const MODE_BITS: u32 = 0o7777;
    /// The superuser's uid.
    const ROOT_UID: u32 = 0;

    fn cstr(name: &OsStr) -> Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| anyhow!("a path component contains NUL"))
    }

    /// `openat(parent, name, flags | O_NOFOLLOW | O_CLOEXEC, mode)`.
    fn open_at(
        parent: &File,
        name: &CString,
        flags: libc::c_int,
        mode: libc::c_uint,
    ) -> std::io::Result<File> {
        // SAFETY: `parent` owns a live descriptor for the whole call and
        // `name` is a NUL-terminated CString that outlives it. On success
        // openat returns a fresh descriptor owned solely by the File below
        // (UNSAFE-01).
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a successful openat transferred a fresh, valid descriptor
        // that nothing else owns (UNSAFE-02).
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// True when `name` under `parent` is itself a symlink. Used only to
    /// NAME a refusal the no-follow open already made; nothing is opened on
    /// its answer.
    fn is_symlink_at(parent: &File, name: &CString) -> bool {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `parent` is a live descriptor, `name` a NUL-terminated
        // CString and `st` a writable stat buffer, all alive for the call.
        let rc = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return false;
        }
        // SAFETY: fstatat returned 0, so it initialised the whole buffer.
        let st = unsafe { st.assume_init() };
        st.st_mode & libc::S_IFMT == libc::S_IFLNK
    }

    /// Refuse a relative path or one with a `..` component, whole.
    fn check_path(path: &Path) -> Result<()> {
        if !path.is_absolute() {
            bail!("{} must be an absolute path", path.display());
        }
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            bail!("{} must not contain parent traversal", path.display());
        }
        Ok(())
    }

    /// Pin `path` (a directory) by walking it from `/` one component at a
    /// time with `O_NOFOLLOW | O_DIRECTORY`, so a symlink at ANY level is
    /// refused rather than followed.
    fn pin_dir(path: &Path) -> Result<File> {
        let mut dir = File::open("/").map_err(|e| anyhow!("cannot open /: {e}"))?;
        let mut reached = PathBuf::from("/");
        for part in path.components() {
            let Component::Normal(name) = part else {
                continue;
            };
            reached.push(name);
            let c = cstr(name)?;
            dir = match open_at(&dir, &c, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
                Ok(next) => next,
                Err(_) if is_symlink_at(&dir, &c) => {
                    bail!(
                        "directory {} is reached through a symlink",
                        reached.display()
                    )
                }
                Err(e) => bail!("cannot open directory {}: {e}", reached.display()),
            };
        }
        Ok(dir)
    }

    /// The parent directory and final name of a checked path.
    fn split(path: &Path) -> Result<(&Path, &OsStr)> {
        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("{} names no file", path.display()))?;
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
        Ok((parent, name))
    }

    /// Owner uid and gid of a pinned directory, after refusing one that a
    /// group or other uid can write. `role` is `source` or `destination`.
    fn dir_owner(dir: &File, path: &Path, role: &str) -> Result<(u32, u32)> {
        let meta = dir
            .metadata()
            .map_err(|e| anyhow!("cannot stat {role} directory {}: {e}", path.display()))?;
        let mode = meta.permissions().mode() & MODE_BITS;
        if mode & GROUP_OR_WORLD_WRITE != 0 {
            bail!(
                "{role} directory {} is group- or world-writable (mode {mode:04o})",
                path.display()
            );
        }
        Ok((meta.uid(), meta.gid()))
    }

    /// Open and prove the writer's staging file. Every property is read from
    /// the descriptor that will be read, so nothing can be swapped between
    /// the check and the use.
    fn open_source(dir: &File, dir_uid: u32, source: &Path, name: &OsStr) -> Result<File> {
        let c = cstr(name)?;
        // O_NONBLOCK so a FIFO planted at the name cannot wedge the root step;
        // the regular-file check below then refuses it.
        let file = match open_at(
            dir,
            &c,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
            0,
        ) {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                bail!("source {} is a symlink", source.display())
            }
            Err(e) => bail!("cannot open source {}: {e}", source.display()),
        };
        let meta = file
            .metadata()
            .map_err(|e| anyhow!("cannot stat source {}: {e}", source.display()))?;
        if !meta.is_file() {
            bail!("source {} is not a regular file", source.display());
        }
        // A hard link could alias a file the writer does not own; a
        // single-link inode owned by the directory's owner cannot.
        if meta.nlink() != 1 {
            bail!(
                "source {} has {} hard links; exactly 1 is required",
                source.display(),
                meta.nlink()
            );
        }
        if meta.uid() != dir_uid {
            bail!(
                "source {} is owned by uid {}, not by its directory's owner (uid {dir_uid})",
                source.display(),
                meta.uid()
            );
        }
        let mode = meta.permissions().mode() & MODE_BITS;
        if mode != SNAPSHOT_MODE {
            bail!(
                "source {} must be mode 0600, found {mode:04o}",
                source.display()
            );
        }
        if meta.len() > MAX_ALLOWLIST_BYTES {
            bail!(
                "source {} is {} bytes, over the {MAX_ALLOWLIST_BYTES} byte ceiling",
                source.display(),
                meta.len()
            );
        }
        Ok(file)
    }

    /// Removes the temp file unless the rename consumed it. Drop never panics
    /// (OWNERSHIP-25); a failed unlink leaves only an inert dot-file.
    struct TempGuard<'a> {
        dir: &'a File,
        name: CString,
        armed: bool,
    }

    impl Drop for TempGuard<'_> {
        fn drop(&mut self) {
            if self.armed {
                // SAFETY: `dir` is a live directory descriptor and `name` a
                // NUL-terminated CString; unlinkat has no memory effects. The
                // result is deliberately ignored: best-effort cleanup.
                unsafe {
                    libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0);
                }
            }
        }
    }

    fn os_result(rc: libc::c_int, what: impl FnOnce() -> String) -> Result<()> {
        if rc == 0 {
            Ok(())
        } else {
            let e = std::io::Error::last_os_error();
            Err(anyhow!("{}: {e}", what()))
        }
    }

    /// Write `bytes` as `name` inside the pinned `dir`, owned by
    /// `owner` at mode 0600, through an `O_EXCL` temp file, `renameat` and a
    /// directory `fsync`. On any error the temp file is removed and the old
    /// `name` is untouched.
    pub(super) fn write_into(
        dir: &File,
        dest: &Path,
        name: &OsStr,
        owner: (u32, u32),
        bytes: &[u8],
    ) -> Result<()> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let mut tmp_name = OsString::from(".");
        tmp_name.push(name);
        tmp_name.push(format!(".publish-{}-{nanos}", std::process::id()));
        let tmp_c = cstr(&tmp_name)?;
        let mut tmp = open_at(
            dir,
            &tmp_c,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            SNAPSHOT_MODE,
        )
        .map_err(|e| anyhow!("cannot create a temp file beside {}: {e}", dest.display()))?;
        let guard = TempGuard {
            dir,
            name: tmp_c,
            armed: true,
        };
        let tmp_meta = tmp
            .metadata()
            .map_err(|e| anyhow!("cannot stat the temp file beside {}: {e}", dest.display()))?;
        // Hand the inode to the destination directory's owner BEFORE it is
        // visible under the published name. Only a privileged caller can
        // change the owner; without that privilege fchown fails and the
        // hand-off is refused.
        if (tmp_meta.uid(), tmp_meta.gid()) != owner {
            // SAFETY: `tmp` owns a live descriptor for this call; fchown has
            // no memory effects.
            let rc = unsafe { libc::fchown(tmp.as_raw_fd(), owner.0, owner.1) };
            os_result(rc, || {
                format!(
                    "cannot hand {} to uid {} gid {}",
                    dest.display(),
                    owner.0,
                    owner.1
                )
            })?;
        }
        tmp.set_permissions(std::fs::Permissions::from_mode(SNAPSHOT_MODE))
            .map_err(|e| anyhow!("cannot set mode 0600 on {}: {e}", dest.display()))?;
        tmp.write_all(bytes)
            .and_then(|()| tmp.sync_all())
            .map_err(|e| anyhow!("cannot write the snapshot for {}: {e}", dest.display()))?;
        drop(tmp);

        let final_c = cstr(name)?;
        // SAFETY: `dir` is a live directory descriptor; both names are
        // NUL-terminated CStrings alive for the call. renameat replaces a
        // symlink at the target name rather than following it.
        let rc = unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                guard.name.as_ptr(),
                dir.as_raw_fd(),
                final_c.as_ptr(),
            )
        };
        os_result(rc, || {
            format!("cannot rename the snapshot into {}", dest.display())
        })?;
        let mut guard = guard;
        guard.armed = false;
        dir.sync_all()
            .map_err(|e| anyhow!("cannot sync the directory of {}: {e}", dest.display()))?;
        Ok(())
    }

    pub(super) fn publish(source: &Path, dest: &Path) -> Result<PublishReport> {
        check_path(source)?;
        check_path(dest)?;
        let (src_dir_path, src_name) = split(source)?;
        let (dst_dir_path, dst_name) = split(dest)?;

        // 1. The source directory: pinned, owner-only writable, not root's.
        let src_dir = pin_dir(src_dir_path)?;
        let (src_uid, _) = dir_owner(&src_dir, src_dir_path, "source")?;
        if src_uid == ROOT_UID {
            bail!(
                "source directory {} is owned by root; the staging directory must belong to the unprivileged writer",
                src_dir_path.display()
            );
        }

        // 2. The source file, proven through its own descriptor, then FULLY
        //    validated with the hub's reader before the hub dir is touched.
        let file = open_source(&src_dir, src_uid, source, src_name)?;
        let invalid = |e: anyhow::Error| {
            anyhow!(
                "snapshot source {} failed validation: {e:#}",
                source.display()
            )
        };
        let snapshot = AllowlistCache::read_checked(file, source).map_err(invalid)?;
        let bytes = serde_json::to_vec(&snapshot).map_err(|e| invalid(e.into()))?;
        let (cache, _refreshed) = AllowlistCache::from_file_parts(snapshot).map_err(invalid)?;

        // 3. The destination directory: pinned, owner-only writable, and a
        //    DIFFERENT owner, so the hand-off really crosses a uid boundary.
        let dst_dir = pin_dir(dst_dir_path)?;
        let owner = dir_owner(&dst_dir, dst_dir_path, "destination")?;
        if owner.0 == src_uid {
            bail!(
                "destination directory {} has the same owner (uid {src_uid}) as the source directory; the hand-off must cross a uid boundary",
                dst_dir_path.display()
            );
        }

        // 4. Atomic, durable replace owned by the destination's owner.
        write_into(&dst_dir, dest, dst_name, owner, &bytes)?;
        Ok(PublishReport {
            agents: cache.len(),
            owner_uid: owner.0,
        })
    }

    /// Pin a directory for the unit tests of [`write_into`].
    #[cfg(test)]
    pub(super) fn pin_for_test(path: &Path) -> Result<File> {
        pin_dir(path)
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod tests {
    //! The success path needs two uids and root, so it is proven in the
    //! privileged CI step. Here [`unix::write_into`] (the atomic, owner-handing
    //! write) is driven directly as the directory's own uid; the refusals are
    //! pinned end to end in `tests/wake_hub_publish_snapshot_3971.rs`.
    use super::unix;
    use crate::wake_hub::delegation_verifier::{
        ALLOWLIST_FILE_VERSION, AllowlistCache, AllowlistEntry, AllowlistFile,
    };
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    fn snapshot_json() -> Vec<u8> {
        // RFC 8032 test vector 1 public key: a valid Ed25519 point.
        const PUBKEY_B64: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
        let now = chrono::Utc::now().to_rfc3339();
        let file = AllowlistFile {
            version: ALLOWLIST_FILE_VERSION,
            refreshed_at: Some(now.clone()),
            agents: vec![AllowlistEntry {
                agent_id: "ai:alice".to_owned(),
                pubkey_b64: PUBKEY_B64.to_owned(),
                bind_authority: "possession_proof".to_owned(),
                bound_at: now,
                revoked_keys: Vec::new(),
                readable_prefixes: Vec::new(),
            }],
        };
        serde_json::to_vec(&file).expect("encode")
    }

    fn hub_dir() -> (tempfile::TempDir, PathBuf) {
        let root = tempfile::tempdir().expect("tempdir");
        let hub = std::fs::canonicalize(root.path())
            .expect("canon")
            .join("hub");
        std::fs::create_dir(&hub).expect("hub");
        std::fs::set_permissions(&hub, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        (root, hub)
    }

    fn me() -> (u32, u32) {
        // SAFETY: getuid/getgid take no arguments, have no memory effects and
        // cannot fail.
        unsafe { (libc::getuid(), libc::getgid()) }
    }

    fn owner_of(path: &Path) -> (u32, u32) {
        let m = std::fs::metadata(path).expect("meta");
        (m.uid(), m.gid())
    }

    #[test]
    fn write_into_replaces_by_rename_at_0600_and_the_hub_admits_it_3971() {
        let (_root, hub) = hub_dir();
        let dst = hub.join("hub-allow.json");
        std::fs::write(&dst, b"old").expect("old");
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let old_ino = std::fs::metadata(&dst).expect("meta").ino();
        let dir = unix::pin_for_test(&hub).expect("pin");

        let owner = owner_of(&hub);
        unix::write_into(
            &dir,
            &dst,
            std::ffi::OsStr::new("hub-allow.json"),
            owner,
            &snapshot_json(),
        )
        .expect("write");

        let meta = std::fs::metadata(&dst).expect("meta");
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
        assert_eq!((meta.uid(), meta.gid()), owner);
        assert_ne!(meta.ino(), old_ino, "a NEW inode is renamed into place");
        AllowlistCache::load_from_file(&dst).expect("the hub admits the published file");
        assert_eq!(
            std::fs::read_dir(&hub).expect("ls").count(),
            1,
            "no temp left"
        );
    }

    #[test]
    fn write_into_refuses_and_removes_its_temp_when_the_rename_fails_3971() {
        let (_root, hub) = hub_dir();
        // A non-empty directory at the final name: renameat fails.
        let blocker = hub.join("hub-allow.json");
        std::fs::create_dir(&blocker).expect("blocker");
        std::fs::write(blocker.join("keep"), b"k").expect("keep");
        let dir = unix::pin_for_test(&hub).expect("pin");
        let err = unix::write_into(
            &dir,
            &blocker,
            std::ffi::OsStr::new("hub-allow.json"),
            owner_of(&hub),
            &snapshot_json(),
        )
        .expect_err("rename over a non-empty dir must fail");
        assert!(
            format!("{err:#}").starts_with(&format!(
                "cannot rename the snapshot into {}:",
                blocker.display()
            )),
            "{err:#}"
        );
        let names: Vec<_> = std::fs::read_dir(&hub)
            .expect("ls")
            .map(|e| e.expect("e").file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("hub-allow.json")]);
    }

    #[test]
    fn write_into_refuses_a_hand_off_it_has_no_privilege_for_3971() {
        let (_root, hub) = hub_dir();
        let (uid, gid) = me();
        if uid == 0 {
            // As root fchown succeeds by design; this row pins the unprivileged case.
            return;
        }
        let dst = hub.join("hub-allow.json");
        let dir = unix::pin_for_test(&hub).expect("pin");
        let err = unix::write_into(
            &dir,
            &dst,
            std::ffi::OsStr::new("hub-allow.json"),
            (0, gid),
            &snapshot_json(),
        )
        .expect_err("fchown to root without privilege must fail");
        assert!(
            format!("{err:#}").starts_with(&format!(
                "cannot hand {} to uid 0 gid {gid}:",
                dst.display()
            )),
            "{err:#}"
        );
        assert_eq!(
            std::fs::read_dir(&hub).expect("ls").count(),
            0,
            "nothing published"
        );
    }
}
