// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9620 — the default config write (`AppConfig::write_default_at`).
//!
//! Invariant: the write has two outcomes and no third. Either the complete
//! default file exists at the path as a regular file, or the path is byte for
//! byte as it was and the caller gets one named error. No run treats a
//! partial file or a non-regular path as the user's config.

#[cfg(test)]
mod tests {
    use crate::config::AppConfig;
    use std::io::ErrorKind;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    /// A hang longer than this means the call opened a FIFO (an open for
    /// writing blocks until a reader arrives), which the invariant forbids.
    const FIFO_DEADLINE: Duration = Duration::from_secs(20);

    /// Rounds of the concurrent first-run pair; each round is a fresh path.
    const CONCURRENT_ROUNDS: usize = 40;

    /// Body of the file an outside symlink points at; must survive unchanged.
    const OUTSIDE_BODY: &str = "# outside 9620 - must survive byte for byte\n";

    /// Entry names directly under `dir`, sorted (a temp file left behind
    /// shows up here).
    fn entries(dir: &Path) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.expect("dir entry").file_name().to_string_lossy().into_owned())
            .collect();
        out.sort();
        out
    }

    /// The complete default template, as a fresh write produces it.
    fn complete_template() -> String {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.toml");
        AppConfig::write_default_at(&path).expect("fresh write");
        std::fs::read_to_string(&path).expect("read fresh write")
    }

    /// How a row plants a non-regular entry at the config path.
    #[derive(Clone, Copy, Debug)]
    enum Plant {
        DanglingSymlink,
        SymlinkToOutsideFile,
        Directory,
        Fifo,
    }

    impl Plant {
        const ALL: [Self; 4] = [
            Self::DanglingSymlink,
            Self::SymlinkToOutsideFile,
            Self::Directory,
            Self::Fifo,
        ];
    }

    /// Expected error text per row, written out by hand (not derived from the
    /// code under test).
    fn expected_message(plant: Plant) -> &'static str {
        match plant {
            Plant::DanglingSymlink | Plant::SymlinkToOutsideFile => {
                "config path exists and is a symbolic link, not a regular file; it was left unchanged"
            }
            Plant::Directory => {
                "config path exists and is a directory, not a regular file; it was left unchanged"
            }
            Plant::Fifo => {
                "config path exists and is a FIFO, not a regular file; it was left unchanged"
            }
        }
    }

    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("no NUL in path");
        // SAFETY: `c` is a valid NUL-terminated C string that outlives the call.
        let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo: {}", std::io::Error::last_os_error());
    }

    /// Plant the row's entry; returns the outside target (symlink rows).
    fn plant(plant: Plant, root: &Path, path: &Path) -> Option<PathBuf> {
        match plant {
            Plant::DanglingSymlink => {
                let target = root.join("no-such-target-9620.toml");
                std::os::unix::fs::symlink(&target, path).unwrap();
                Some(target)
            }
            Plant::SymlinkToOutsideFile => {
                let target = root.join("outside").join("dotfile.toml");
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::write(&target, OUTSIDE_BODY).unwrap();
                std::os::unix::fs::symlink(&target, path).unwrap();
                Some(target)
            }
            Plant::Directory => {
                std::fs::create_dir(path).unwrap();
                None
            }
            Plant::Fifo => {
                mkfifo(path);
                None
            }
        }
    }

    /// Run the write on another thread so a call that opens a FIFO (and
    /// blocks) is a red row, not a hung suite.
    fn write_with_deadline(path: &Path) -> Option<std::io::Result<()>> {
        let (tx, rx) = std::sync::mpsc::channel();
        let p = path.to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(AppConfig::write_default_at(&p));
        });
        rx.recv_timeout(FIFO_DEADLINE).ok()
    }

    /// #9620 finding 2 — every non-regular entry at the config path is
    /// refused with the one named error, and the path is left as it was: a
    /// symlink keeps its target and the target is unchanged (or still
    /// absent), a directory stays an empty directory, a FIFO is never opened,
    /// and no temp file is left beside it.
    #[cfg(unix)]
    #[test]
    fn write_default_at_refuses_every_non_regular_path_9620() {
        use std::os::unix::fs::FileTypeExt;
        let mut bad = Vec::new();
        for row in Plant::ALL {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("ai-memory");
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("config.toml");
            let target = plant(row, tmp.path(), &path);
            let link_before = std::fs::read_link(&path).ok();
            let Some(result) = write_with_deadline(&path) else {
                bad.push(format!("{row:?}: no answer in {FIFO_DEADLINE:?} (the path was opened)"));
                continue;
            };
            match result {
                Ok(()) => bad.push(format!("{row:?}: Ok(()), expected the named error")),
                Err(e) => {
                    if e.kind() != ErrorKind::AlreadyExists || e.to_string() != expected_message(row)
                    {
                        bad.push(format!("{row:?}: got {:?} {e:?}", e.kind()));
                    }
                }
            }
            let ft = std::fs::symlink_metadata(&path).expect("entry still there").file_type();
            let same_kind = match row {
                Plant::DanglingSymlink | Plant::SymlinkToOutsideFile => ft.is_symlink(),
                Plant::Directory => ft.is_dir() && entries(&path).is_empty(),
                Plant::Fifo => ft.is_fifo(),
            };
            if !same_kind || std::fs::read_link(&path).ok() != link_before {
                bad.push(format!("{row:?}: the entry at the path changed"));
            }
            match (row, &target) {
                (Plant::DanglingSymlink, Some(t)) if t.exists() => {
                    bad.push(format!("{row:?}: the dangling target was created"));
                }
                (Plant::SymlinkToOutsideFile, Some(t))
                    if std::fs::read_to_string(t).ok().as_deref() != Some(OUTSIDE_BODY) =>
                {
                    bad.push(format!("{row:?}: the outside target was changed"));
                }
                _ => {}
            }
            if entries(&dir) != vec!["config.toml".to_string()] {
                bad.push(format!("{row:?}: left {:?} beside the path", entries(&dir)));
            }
        }
        assert!(bad.is_empty(), "#9620 non-regular config path rows: {bad:#?}");
    }

    /// #9620 finding 1 — a concurrent pair of first runs ends with one
    /// complete file, and each caller that returns `Ok` already sees the
    /// complete file (never a partial one another writer is still filling).
    #[test]
    fn write_default_at_concurrent_first_runs_end_with_one_complete_file_9620() {
        let expected = complete_template();
        for round in 0..CONCURRENT_ROUNDS {
            let tmp = tempfile::tempdir().unwrap();
            let dir = tmp.path().join("ai-memory");
            let path = dir.join("config.toml");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let (p, b) = (path.clone(), std::sync::Arc::clone(&barrier));
                    std::thread::spawn(move || {
                        b.wait();
                        let r = AppConfig::write_default_at(&p).map_err(|e| e.to_string());
                        (r, std::fs::read_to_string(&p).map_err(|e| e.to_string()))
                    })
                })
                .collect();
            for h in handles {
                let (r, seen) = h.join().expect("writer thread");
                assert_eq!(r, Ok(()), "round {round}: a first run must succeed");
                assert_eq!(
                    seen.as_deref(),
                    Ok(expected.as_str()),
                    "round {round}: a caller saw a partial default config"
                );
            }
            assert_eq!(
                entries(&dir),
                vec!["config.toml".to_string()],
                "round {round}: exactly one file, no temp file"
            );
        }
    }
}
