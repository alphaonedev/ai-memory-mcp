// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3637 (M4) — the privileged hand-off of the refreshed allowlist
//! snapshot into the hub's runtime directory.
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
//!   `install(1)` dereferences its source. A symlink swapped into
//!   `/var/lib/ai-memory/hub-allow.json` made root copy any file it can read
//!   (or an endless device such as `/dev/zero`) into the hub directory.
//! * **Not atomic.** `install(1)` unlinks the destination and re-creates it,
//!   so the hub could find no snapshot, or a partial root-owned one, and
//!   refuse every session revalidation in that window.
//!
//! [`publish_snapshot`] replaces it. It walks both parent directories from `/`
//! one component at a time with `O_NOFOLLOW`, so no symlink anywhere on either
//! path is followed. It opens the source relative to its pinned directory and
//! proves, through that same descriptor, that it is a regular, single-link,
//! 0600 file owned by the directory's owner (the refresher). It then fully
//! validates the snapshot, including key decoding and the freshness ceiling,
//! with the same code the hub admits against. Finally it writes a canonical
//! re-encoding to an `O_EXCL` temp file in the destination directory, hands
//! that inode to the directory's owner at mode 0600, `fsync`s it, and
//! `renameat`s it over the old snapshot. A hub reading concurrently sees the
//! whole old snapshot or the whole new one. Any refusal publishes nothing, so
//! the previous snapshot stays in place and ages out — the fail-closed
//! direction.

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
/// Refuses a relative path, a symlink anywhere on either path, a source that
/// is not a single-link 0600 regular file owned by its directory's owner, an
/// oversized, malformed, expired or otherwise invalid snapshot, a destination
/// directory that is group- or world-writable, and (when not running as root)
/// a destination directory owned by another uid. Any I/O failure is returned
/// after the temp file is removed; nothing is published.
pub fn publish_snapshot(source: &Path, dest: &Path) -> Result<PublishReport> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::publish(source, dest)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (source, dest);
        anyhow::bail!(
            "wake-hub: --publish-snapshot requires descriptor-relative filesystem support on this platform"
        )
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use super::PublishReport;
    use crate::wake_hub::delegation_verifier::AllowlistCache;
    use anyhow::{Context as _, Result, bail};
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io::Write as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Component, Path};

    /// Mode of the published inode, and the only source mode accepted.
    const SNAPSHOT_MODE: u32 = 0o600;

    fn cstr(name: &OsStr) -> Result<CString> {
        CString::new(name.as_bytes()).context("wake-hub: path component contains NUL")
    }

    /// `openat(parent, name, flags, mode)` into an owned [`File`].
    fn open_at(
        parent: &File,
        name: &OsStr,
        flags: libc::c_int,
        mode: libc::c_uint,
    ) -> Result<File> {
        let name = cstr(name)?;
        // SAFETY: `parent` owns a live descriptor for the whole call and `name`
        // is a NUL-terminated CString that outlives it. On success openat
        // returns a fresh descriptor owned solely by the File below
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
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: a successful openat transferred a fresh, valid descriptor
        // that nothing else owns.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Pin `path` (a directory) by walking it from `/` one component at a
    /// time with `O_NOFOLLOW | O_DIRECTORY`, so a symlink at ANY level is
    /// refused rather than followed.
    fn pin_dir(path: &Path) -> Result<File> {
        if !path.is_absolute() {
            bail!(
                "wake-hub: {} must be an absolute path (symlink-free, canonical)",
                path.display()
            );
        }
        let mut dir = File::open("/")?;
        for part in path.components() {
            match part {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => {
                    dir = open_at(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0).with_context(
                        || {
                            format!(
                                "wake-hub: cannot pin directory {} without following a symlink",
                                path.display()
                            )
                        },
                    )?;
                }
                _ => bail!(
                    "wake-hub: {} must not contain parent traversal",
                    path.display()
                ),
            }
        }
        Ok(dir)
    }

    /// Split `path` into its pinned parent directory and final file name.
    fn split(path: &Path) -> Result<(File, &OsStr)> {
        let name = path
            .file_name()
            .with_context(|| format!("wake-hub: {} names no file", path.display()))?;
        let parent = path
            .parent()
            .with_context(|| format!("wake-hub: {} has no parent directory", path.display()))?;
        Ok((pin_dir(parent)?, name))
    }

    /// Open and prove the refresher's staging file. Every property is read
    /// from the descriptor that will be read, so nothing can be swapped
    /// between the check and the use.
    fn open_source(source: &Path) -> Result<File> {
        let (dir, name) = split(source)?;
        let dir_meta = dir.metadata()?;
        // O_NONBLOCK so a FIFO planted at the name cannot wedge the root step;
        // the regular-file check below then refuses it.
        let file = open_at(
            &dir,
            name,
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
            0,
        )
        .with_context(|| {
            format!(
                "wake-hub: cannot open snapshot source {} (a symlink is refused)",
                source.display()
            )
        })?;
        let meta = file.metadata()?;
        let mode = meta.permissions().mode() & 0o7777;
        if !meta.is_file() {
            bail!(
                "wake-hub: snapshot source {} is not a regular file",
                source.display()
            );
        }
        // A hard link could alias a file the refresher does not own; a
        // single-link inode owned by the directory's owner cannot.
        if meta.nlink() != 1 {
            bail!(
                "wake-hub: snapshot source {} has {} hard links; exactly 1 is required",
                source.display(),
                meta.nlink()
            );
        }
        if meta.uid() != dir_meta.uid() {
            bail!(
                "wake-hub: snapshot source {} is owned by uid {}, not by its directory's owner (uid {})",
                source.display(),
                meta.uid(),
                dir_meta.uid()
            );
        }
        if mode != SNAPSHOT_MODE {
            bail!(
                "wake-hub: snapshot source {} must be mode 0600, found {mode:04o}",
                source.display()
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
                // result is deliberately ignored: this is best-effort cleanup.
                unsafe {
                    libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), 0);
                }
            }
        }
    }

    fn check(rc: libc::c_int) -> Result<()> {
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().into())
        }
    }

    pub(super) fn publish(source: &Path, dest: &Path) -> Result<PublishReport> {
        // 1. Read and FULLY validate the source before touching the hub dir.
        let file = open_source(source)?;
        let snapshot = AllowlistCache::read_checked(file, source)?;
        let (cache, _refreshed) =
            AllowlistCache::from_file_parts(snapshot.clone()).with_context(|| {
                format!(
                    "wake-hub: snapshot source {} failed validation; nothing published",
                    source.display()
                )
            })?;
        // Publish exactly what was validated, re-encoded canonically.
        let bytes = serde_json::to_vec(&snapshot)?;

        // 2. Pin the destination directory and learn whom to hand it to.
        let (dir, name) = split(dest)?;
        let dir_meta = dir.metadata()?;
        if !dir_meta.is_dir() || dir_meta.permissions().mode() & 0o022 != 0 {
            bail!(
                "wake-hub: destination directory of {} must be a directory writable by its owner only",
                dest.display()
            );
        }
        let (owner_uid, owner_gid) = (dir_meta.uid(), dir_meta.gid());
        // SAFETY: geteuid has no arguments or memory effects and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 && euid != owner_uid {
            bail!(
                "wake-hub: destination directory of {} belongs to uid {owner_uid}; only root may hand a snapshot to another uid",
                dest.display()
            );
        }

        // 3. O_EXCL temp file in the SAME directory (O_NOFOLLOW is added by
        //    open_at), so the rename below is atomic and never crosses a
        //    filesystem.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(name);
        tmp_name.push(format!(".publish-{}-{nanos}", std::process::id()));
        let mut tmp = open_at(
            &dir,
            &tmp_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            SNAPSHOT_MODE,
        )
        .with_context(|| {
            format!(
                "wake-hub: cannot create a temp file beside {}",
                dest.display()
            )
        })?;
        let mut guard = TempGuard {
            dir: &dir,
            name: cstr(&tmp_name)?,
            armed: true,
        };

        // 4. Hand the new inode to the hub uid at exact mode 0600 BEFORE it is
        //    visible under the published name, then make it durable.
        if euid == 0 {
            // SAFETY: `tmp` owns a live descriptor for this call; fchown has no
            // memory effects.
            check(unsafe { libc::fchown(tmp.as_raw_fd(), owner_uid, owner_gid) })?;
        }
        tmp.set_permissions(std::fs::Permissions::from_mode(SNAPSHOT_MODE))?;
        tmp.write_all(&bytes)?;
        tmp.sync_all()?;
        drop(tmp);

        // 5. Atomic replace, then make the directory entry durable.
        let final_name = cstr(name)?;
        // SAFETY: `dir` is a live directory descriptor; both names are
        // NUL-terminated CStrings alive for the call. renameat replaces a
        // symlink at the target name rather than following it.
        check(unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                guard.name.as_ptr(),
                dir.as_raw_fd(),
                final_name.as_ptr(),
            )
        })
        .with_context(|| {
            format!(
                "wake-hub: cannot rename the snapshot into {}",
                dest.display()
            )
        })?;
        guard.armed = false;
        dir.sync_all()?;

        Ok(PublishReport {
            agents: cache.len(),
            owner_uid,
        })
    }
}

#[cfg(test)]
mod tests {
    #![cfg(any(target_os = "linux", target_os = "macos"))]
    use super::*;
    use crate::wake_hub::delegation_verifier::{
        ALLOWLIST_FILE_VERSION, AllowlistCache, AllowlistEntry, AllowlistFile,
    };
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    fn snapshot_json() -> Vec<u8> {
        // RFC 8032 test vector 1 public key: a valid Ed25519 point, so the
        // snapshot passes the hub's key decoding without minting a key here.
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

    struct Sandbox {
        _root: tempfile::TempDir,
        stage: std::path::PathBuf,
        hub: std::path::PathBuf,
    }

    fn sandbox() -> Sandbox {
        let root = tempfile::tempdir().expect("tempdir");
        // Canonicalise: the pin walk refuses symlinks anywhere, and a CI temp
        // root can sit under one (macOS /var -> /private/var).
        let base = std::fs::canonicalize(root.path()).expect("canon");
        let stage = base.join("stage");
        let hub = base.join("hub");
        std::fs::create_dir(&stage).expect("stage");
        std::fs::create_dir(&hub).expect("hub");
        std::fs::set_permissions(&hub, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        Sandbox {
            _root: root,
            stage,
            hub,
        }
    }

    fn write_0600(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("write");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }

    #[test]
    fn a_valid_snapshot_is_published_0600_by_rename_3637() {
        let sb = sandbox();
        let src = sb.stage.join("hub-allow.json");
        let dst = sb.hub.join("hub-allow.json");
        write_0600(&src, &snapshot_json());
        write_0600(&dst, b"old");
        let old_ino = std::fs::metadata(&dst).expect("meta").ino();

        let report = publish_snapshot(&src, &dst).expect("publish");
        assert_eq!(report.agents, 1);
        let meta = std::fs::metadata(&dst).expect("meta");
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
        assert_ne!(meta.ino(), old_ino, "a NEW inode is renamed into place");
        // The published file passes the hub's own admission gate.
        AllowlistCache::load_from_file(&dst).expect("hub accepts it");
        // No temp file is left behind.
        assert_eq!(std::fs::read_dir(&sb.hub).expect("ls").count(), 1);
    }

    #[test]
    fn denied_a_symlinked_source_is_refused_and_nothing_published_3637() {
        let sb = sandbox();
        let secret = sb.stage.join("secret");
        write_0600(&secret, &snapshot_json());
        let src = sb.stage.join("hub-allow.json");
        std::os::unix::fs::symlink(&secret, &src).expect("symlink");
        let dst = sb.hub.join("hub-allow.json");
        write_0600(&dst, b"old");

        let err = publish_snapshot(&src, &dst).expect_err("symlink must be refused");
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        assert_eq!(std::fs::read(&dst).expect("read"), b"old");
        assert_eq!(std::fs::read_dir(&sb.hub).expect("ls").count(), 1);
    }

    #[test]
    fn denied_a_symlinked_source_directory_is_refused_3637() {
        let sb = sandbox();
        let src_real = sb.stage.join("hub-allow.json");
        write_0600(&src_real, &snapshot_json());
        let link_dir = sb.hub.parent().expect("base").join("stage-link");
        std::os::unix::fs::symlink(&sb.stage, &link_dir).expect("symlink");
        let dst = sb.hub.join("hub-allow.json");
        publish_snapshot(&link_dir.join("hub-allow.json"), &dst)
            .expect_err("a symlinked ancestor must be refused");
        assert!(!dst.exists());
    }

    #[test]
    fn denied_a_hard_linked_source_is_refused_3637() {
        let sb = sandbox();
        let other = sb.stage.join("other");
        write_0600(&other, &snapshot_json());
        let src = sb.stage.join("hub-allow.json");
        std::fs::hard_link(&other, &src).expect("hard link");
        let dst = sb.hub.join("hub-allow.json");
        let err = publish_snapshot(&src, &dst).expect_err("nlink 2 must be refused");
        assert!(format!("{err:#}").contains("hard links"), "{err:#}");
        assert!(!dst.exists());
    }

    #[test]
    fn denied_a_fifo_source_is_refused_without_blocking_3637() {
        let sb = sandbox();
        let src = sb.stage.join("hub-allow.json");
        let c = std::ffi::CString::new(src.as_os_str().as_encoded_bytes()).expect("cstr");
        // SAFETY: c is a valid NUL-terminated path for the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let dst = sb.hub.join("hub-allow.json");
        let err = publish_snapshot(&src, &dst).expect_err("fifo must be refused");
        assert!(format!("{err:#}").contains("regular file"), "{err:#}");
    }

    #[test]
    fn denied_a_widened_source_mode_and_invalid_json_are_refused_3637() {
        let sb = sandbox();
        let src = sb.stage.join("hub-allow.json");
        let dst = sb.hub.join("hub-allow.json");
        write_0600(&src, &snapshot_json());
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        publish_snapshot(&src, &dst).expect_err("0644 must be refused");
        write_0600(&src, b"{not json");
        publish_snapshot(&src, &dst).expect_err("malformed must be refused");
        assert!(!dst.exists());
        assert_eq!(std::fs::read_dir(&sb.hub).expect("ls").count(), 0);
    }

    #[test]
    fn denied_a_world_writable_destination_dir_and_relative_paths_3637() {
        let sb = sandbox();
        let src = sb.stage.join("hub-allow.json");
        write_0600(&src, &snapshot_json());
        std::fs::set_permissions(&sb.hub, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        publish_snapshot(&src, &sb.hub.join("hub-allow.json"))
            .expect_err("a world-writable hub dir must be refused");
        publish_snapshot(Path::new("stage/hub-allow.json"), &sb.hub.join("x"))
            .expect_err("a relative path must be refused");
    }
}
