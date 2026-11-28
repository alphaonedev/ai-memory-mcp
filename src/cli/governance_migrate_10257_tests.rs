// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10257 (GA standard 1) — atomic replace + pre-replace backup tests
//! for `ai-memory governance migrate-to-permissions`.
//!
//! Every write site in `src/cli/governance_migrate.rs` (`run` and
//! `run_with_paths`, both in-place merge and `--config-out`) must route
//! through `snapshot_file::write_replacing` with a prior
//! `snapshot_file::write_new_private_unique` backup when replacing an existing
//! file, refusing symlinks at the final name and reporting `NotDurable` when
//! the directory fsync fails without printing a success line.

use super::*;
use crate::storage::snapshot_file::{NotDurable, SYMLINK_REFUSAL_TAIL, seam, symlink_refusal};
use std::path::{Path, PathBuf};
use std::time::Instant;

const INJECTED_ERRNO: i32 = libc::EIO;
const NOT_DURABLE_FRAGMENT: &str = "is written but not confirmed durable";
const CONFIG_WHAT: &str = "config";
const BACKUP_WHAT: &str = "config backup";
const ORIGINAL_CFG: &str = "# original operator config\ntier = \"semantic\"\n\n[governance]\n\n[[governance.policy]]\nscope = \"team/eng/*\"\naction = \"write\"\nrole = \"engineer\"\ndecision = \"allow\"\n";
const PREEXISTING_OUT: &str =
    "# pre-existing standalone output\n[permissions]\nmode = \"enforce\"\n";
const EXPECTED_MERGED_SUBSTR: &str = "# --- migrated from [governance] (v0.7.0 K11) ---\n";
const EXPECTED_RULE_SUBSTR: &str = "namespace_pattern = \"team/eng/*\"\n";
const ONE_MIB: usize = 1024 * 1024;
const LARGE_CONFIG_MERGE_CEILING_SECS: u64 = 10;

#[cfg(unix)]
const MODE_WORLD_READABLE: u32 = 0o644;
#[cfg(unix)]
const MODE_OWNER_ONLY: u32 = 0o600;
#[cfg(unix)]
const PERMISSION_MASK: u32 = 0o777;

/// Clears the thread-local test seam on every exit path.
struct SeamReset;

impl Drop for SeamReset {
    fn drop(&mut self) {
        seam::reset();
    }
}

fn armed() -> SeamReset {
    seam::reset();
    SeamReset
}

fn scratch() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("create scratch dir under TMPDIR")
}

fn sorted_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read scratch dir")
        .map(|entry| {
            entry
                .expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn root_errno(err: &anyhow::Error) -> Option<i32> {
    err.root_cause()
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::raw_os_error)
}

fn file_sync_refusal(dest: &Path) -> String {
    format!(
        "fsync the staged {CONFIG_WHAT} for {} (#10214)",
        dest.display()
    )
}

fn rename_refusal(dest: &Path) -> String {
    format!("replacing {CONFIG_WHAT} {} (#10214)", dest.display())
}

fn dir_sync_refusal(what: &str, dir: &Path, dest: &Path) -> String {
    format!(
        "{what} {} is written but not confirmed durable: the fsync of its directory {} failed \
         ({}), so it may not survive a crash (#10214)",
        dest.display(),
        dir.display(),
        std::io::Error::from_raw_os_error(INJECTED_ERRNO)
    )
}

/// Find the single `<base>.bak.<YYYYMMDD-HHMMSS>` backup in `dir` and assert
/// its filename grammar matches `<file>.bak.<UTC %Y%m%d-%H%M%S>`.
fn find_single_backup(dir: &Path, base_name: &str) -> PathBuf {
    let prefix = format!("{base_name}.bak.");
    let matches: Vec<String> = sorted_entries(dir)
        .into_iter()
        .filter(|name| name.starts_with(&prefix))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one backup starting with {prefix:?} in {}: got {matches:?}",
        dir.display()
    );
    let stamp = &matches[0][prefix.len()..];
    // UTC %Y%m%d-%H%M%S -> 8 digits, '-', 6 digits (15 chars total).
    assert_eq!(
        stamp.len(),
        15,
        "backup timestamp must match %Y%m%d-%H%M%S, got {stamp:?}"
    );
    let bytes = stamp.as_bytes();
    assert_eq!(bytes[8], b'-', "expected '-' separator in {stamp:?}");
    assert!(
        bytes[..8].iter().all(u8::is_ascii_digit) && bytes[9..].iter().all(u8::is_ascii_digit),
        "expected digits around '-' in {stamp:?}"
    );
    dir.join(&matches[0])
}

#[derive(Debug, Clone, Copy)]
enum Entrypoint {
    Run,
    RunWithPaths,
}

fn invoke(
    ep: Entrypoint,
    in_path: &Path,
    out_path: &Path,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
) -> Result<()> {
    let mut out = CliOutput::from_std(stdout, stderr);
    match ep {
        Entrypoint::Run => run(
            MigrateToPermissionsArgs {
                dry_run: false,
                config_out: Some(out_path.to_path_buf()),
                config_in: Some(in_path.to_path_buf()),
            },
            &mut out,
        ),
        Entrypoint::RunWithPaths => {
            run_with_paths(in_path, Some(out_path), false, &mut out).map(|_| ())
        }
    }
}

fn assert_no_success_line(stdout: &[u8], context: &str) {
    let text = String::from_utf8_lossy(stdout);
    assert!(
        !text.contains("merged ") && !text.contains("wrote "),
        "{context}: success line must not be printed on failure, got stdout={text:?}"
    );
}

#[test]
fn governance_migrate_in_place_failure_leaves_original_byte_identical_10257() {
    let rows: [(seam::Step, u32, Entrypoint); 4] = [
        // 1st FileSync is the backup; 2nd FileSync is the replacing config write.
        (seam::Step::FileSync, 2, Entrypoint::Run),
        (seam::Step::FileSync, 2, Entrypoint::RunWithPaths),
        // Backup uses hard_link, so 1st Rename is the replacing config write.
        (seam::Step::Rename, 1, Entrypoint::Run),
        (seam::Step::Rename, 1, Entrypoint::RunWithPaths),
    ];

    for (step, nth, ep) in rows {
        let _reset = armed();
        let dir = scratch();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, ORIGINAL_CFG).expect("seed config");

        seam::inject_step_errno_at(step, INJECTED_ERRNO, nth);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err = invoke(ep, &cfg, &cfg, &mut stdout, &mut stderr)
            .expect_err(&format!("{step:?}/{ep:?}: replace failure must return Err"));

        let expected = match step {
            seam::Step::FileSync => file_sync_refusal(&cfg),
            seam::Step::Rename => rename_refusal(&cfg),
            seam::Step::DirSync => unreachable!(),
        };
        assert_eq!(err.to_string(), expected, "{step:?}/{ep:?}");
        assert_eq!(root_errno(&err), Some(INJECTED_ERRNO), "{step:?}/{ep:?}");
        assert_eq!(
            std::fs::read(&cfg).expect("read original"),
            ORIGINAL_CFG.as_bytes(),
            "{step:?}/{ep:?}: original config must remain byte-identical"
        );
        let backup = find_single_backup(dir.path(), "config.toml");
        assert_eq!(
            std::fs::read(&backup).expect("read backup"),
            ORIGINAL_CFG.as_bytes(),
            "{step:?}/{ep:?}: backup must equal original bytes"
        );
        let mut expected_entries = vec![
            "config.toml".to_string(),
            backup
                .file_name()
                .expect("backup name")
                .to_string_lossy()
                .into_owned(),
        ];
        expected_entries.sort();
        assert_eq!(
            sorted_entries(dir.path()),
            expected_entries,
            "{step:?}/{ep:?}: no staging leftovers permitted"
        );
        assert_no_success_line(&stdout, &format!("{step:?}/{ep:?}"));
    }
}

#[test]
fn governance_migrate_dirsync_failure_keeps_new_file_and_reports_not_durable_10257() {
    for ep in [Entrypoint::Run, Entrypoint::RunWithPaths] {
        let _reset = armed();
        let dir = scratch();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, ORIGINAL_CFG).expect("seed config");

        // 1st DirSync is the backup; 2nd DirSync is the replaced config.
        seam::inject_step_errno_at(seam::Step::DirSync, INJECTED_ERRNO, 2);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err = invoke(ep, &cfg, &cfg, &mut stdout, &mut stderr)
            .expect_err(&format!("{ep:?}: DirSync failure must return Err"));

        assert!(
            err.downcast_ref::<NotDurable>().is_some(),
            "{ep:?}: error must carry typed NotDurable, got {err:#}"
        );
        assert_eq!(
            err.to_string(),
            dir_sync_refusal(CONFIG_WHAT, dir.path(), &cfg),
            "{ep:?}: Display must be exact NotDurable text"
        );
        let after = std::fs::read_to_string(&cfg).expect("new file stays in place");
        assert!(
            after.starts_with(ORIGINAL_CFG),
            "{ep:?}: merged file must keep original prefix"
        );
        assert!(
            after.contains(EXPECTED_MERGED_SUBSTR),
            "{ep:?}: merged file must hold migration separator"
        );
        assert!(
            after.contains(EXPECTED_RULE_SUBSTR),
            "{ep:?}: merged file must hold migrated rule"
        );
        let backup = find_single_backup(dir.path(), "config.toml");
        assert_eq!(
            std::fs::read(&backup).expect("read backup"),
            ORIGINAL_CFG.as_bytes(),
            "{ep:?}: backup stays intact"
        );
        let mut expected_entries = vec![
            "config.toml".to_string(),
            backup
                .file_name()
                .expect("backup name")
                .to_string_lossy()
                .into_owned(),
        ];
        expected_entries.sort();
        assert_eq!(sorted_entries(dir.path()), expected_entries, "{ep:?}");
        assert_no_success_line(&stdout, &format!("dirsync/{ep:?}"));
    }
}

#[test]
fn governance_migrate_backup_taken_before_replace_10257() {
    // 1. Replace fails at Rename -> backup already exists with exact original bytes.
    for ep in [Entrypoint::Run, Entrypoint::RunWithPaths] {
        let _reset = armed();
        let dir = scratch();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, ORIGINAL_CFG).expect("seed config");

        seam::inject_step_errno_at(seam::Step::Rename, INJECTED_ERRNO, 1);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err =
            invoke(ep, &cfg, &cfg, &mut stdout, &mut stderr).expect_err("rename failure must fail");
        assert_eq!(err.to_string(), rename_refusal(&cfg));
        let backup = find_single_backup(dir.path(), "config.toml");
        assert_eq!(
            std::fs::read(&backup).expect("read backup"),
            ORIGINAL_CFG.as_bytes(),
            "{ep:?}: backup taken before replace must equal original"
        );
        assert_eq!(
            std::fs::read(&cfg).expect("read cfg"),
            ORIGINAL_CFG.as_bytes(),
            "{ep:?}: original config untouched"
        );
    }

    // 2. Backup FileSync Err -> command fails with `could not write backup <path>: <err>`,
    //    original untouched, no backup left behind.
    for ep in [Entrypoint::Run, Entrypoint::RunWithPaths] {
        let _reset = armed();
        let dir = scratch();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, ORIGINAL_CFG).expect("seed config");

        seam::inject_step_errno_at(seam::Step::FileSync, INJECTED_ERRNO, 1);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err = invoke(ep, &cfg, &cfg, &mut stdout, &mut stderr)
            .expect_err("backup FileSync failure must fail");
        let full = format!("{err:#}");
        let expected_prefix = format!("could not write backup {}.bak.", cfg.display());
        assert!(
            full.starts_with(&expected_prefix) && full.contains(": fsync the staged config backup"),
            "{ep:?}: expected `{expected_prefix}<ts>: <err>`, got {full:?}"
        );
        assert_eq!(root_errno(&err), Some(INJECTED_ERRNO), "{ep:?}");
        assert_eq!(
            std::fs::read(&cfg).expect("original"),
            ORIGINAL_CFG.as_bytes(),
            "{ep:?}: original untouched on backup Err"
        );
        assert_eq!(
            sorted_entries(dir.path()),
            vec!["config.toml".to_string()],
            "{ep:?}: no backup or stage left on backup FileSync Err"
        );
        assert_no_success_line(&stdout, &format!("backup-err/{ep:?}"));
    }

    // 3. Backup NotDurable -> refuses to replace, original untouched, error names
    //    backup and contains "is written but not confirmed durable".
    for ep in [Entrypoint::Run, Entrypoint::RunWithPaths] {
        let _reset = armed();
        let dir = scratch();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, ORIGINAL_CFG).expect("seed config");

        seam::inject_step_errno_at(seam::Step::DirSync, INJECTED_ERRNO, 1);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err = invoke(ep, &cfg, &cfg, &mut stdout, &mut stderr)
            .expect_err("backup NotDurable must refuse replace");
        let backup = find_single_backup(dir.path(), "config.toml");
        assert!(
            err.downcast_ref::<NotDurable>().is_some(),
            "{ep:?}: error must carry NotDurable, got {err:#}"
        );
        assert_eq!(
            err.to_string(),
            dir_sync_refusal(BACKUP_WHAT, dir.path(), &backup),
            "{ep:?}: backup NotDurable text must name backup and directory"
        );
        assert!(err.to_string().contains(NOT_DURABLE_FRAGMENT));
        assert_eq!(
            std::fs::read(&cfg).expect("original"),
            ORIGINAL_CFG.as_bytes(),
            "{ep:?}: original untouched when backup is not durable"
        );
        assert_eq!(
            std::fs::read(&backup).expect("backup"),
            ORIGINAL_CFG.as_bytes(),
            "{ep:?}: backup bytes stay whole"
        );
        assert_no_success_line(&stdout, &format!("backup-not-durable/{ep:?}"));
    }
}

#[test]
fn governance_migrate_config_out_existing_file_survives_failure_10257() {
    let rows: [(seam::Step, u32, Entrypoint); 4] = [
        (seam::Step::FileSync, 2, Entrypoint::Run),
        (seam::Step::FileSync, 2, Entrypoint::RunWithPaths),
        (seam::Step::Rename, 1, Entrypoint::Run),
        (seam::Step::Rename, 1, Entrypoint::RunWithPaths),
    ];

    for (step, nth, ep) in rows {
        let _reset = armed();
        let dir = scratch();
        let in_path = dir.path().join("in.toml");
        let out_path = dir.path().join("out.toml");
        std::fs::write(&in_path, ORIGINAL_CFG).expect("seed in");
        std::fs::write(&out_path, PREEXISTING_OUT).expect("seed existing out");

        seam::inject_step_errno_at(step, INJECTED_ERRNO, nth);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err = invoke(ep, &in_path, &out_path, &mut stdout, &mut stderr)
            .expect_err(&format!("{step:?}/{ep:?}: replace must fail"));

        let expected = match step {
            seam::Step::FileSync => file_sync_refusal(&out_path),
            seam::Step::Rename => rename_refusal(&out_path),
            seam::Step::DirSync => unreachable!(),
        };
        assert_eq!(err.to_string(), expected, "{step:?}/{ep:?}");
        assert_eq!(root_errno(&err), Some(INJECTED_ERRNO), "{step:?}/{ep:?}");
        assert_eq!(
            std::fs::read(&out_path).expect("read existing out"),
            PREEXISTING_OUT.as_bytes(),
            "{step:?}/{ep:?}: pre-existing --config-out must remain byte-identical"
        );
        let backup = find_single_backup(dir.path(), "out.toml");
        assert_eq!(
            std::fs::read(&backup).expect("read backup"),
            PREEXISTING_OUT.as_bytes(),
            "{step:?}/{ep:?}: backup of pre-existing --config-out must hold its prior bytes"
        );
        let mut expected_entries = vec![
            "in.toml".to_string(),
            "out.toml".to_string(),
            backup
                .file_name()
                .expect("backup name")
                .to_string_lossy()
                .into_owned(),
        ];
        expected_entries.sort();
        assert_eq!(sorted_entries(dir.path()), expected_entries);
        assert_no_success_line(&stdout, &format!("existing-out/{step:?}/{ep:?}"));
    }

    // DirSync failure on existing --config-out keeps new rendered bytes and reports NotDurable.
    for ep in [Entrypoint::Run, Entrypoint::RunWithPaths] {
        let _reset = armed();
        let dir = scratch();
        let in_path = dir.path().join("in.toml");
        let out_path = dir.path().join("out.toml");
        std::fs::write(&in_path, ORIGINAL_CFG).expect("seed in");
        std::fs::write(&out_path, PREEXISTING_OUT).expect("seed existing out");

        seam::inject_step_errno_at(seam::Step::DirSync, INJECTED_ERRNO, 2);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err = invoke(ep, &in_path, &out_path, &mut stdout, &mut stderr)
            .expect_err("DirSync failure must fail");
        assert_eq!(
            err.to_string(),
            dir_sync_refusal(CONFIG_WHAT, dir.path(), &out_path)
        );
        let after = std::fs::read_to_string(&out_path).expect("new file stays");
        assert!(after.contains(EXPECTED_RULE_SUBSTR));
        let backup = find_single_backup(dir.path(), "out.toml");
        assert_eq!(
            std::fs::read(&backup).expect("backup"),
            PREEXISTING_OUT.as_bytes()
        );
        assert_no_success_line(&stdout, &format!("existing-out-dirsync/{ep:?}"));
    }
}

#[test]
fn governance_migrate_config_out_absent_stays_absent_10257() {
    let rows: [(seam::Step, Entrypoint); 4] = [
        (seam::Step::FileSync, Entrypoint::Run),
        (seam::Step::FileSync, Entrypoint::RunWithPaths),
        (seam::Step::Rename, Entrypoint::Run),
        (seam::Step::Rename, Entrypoint::RunWithPaths),
    ];

    for (step, ep) in rows {
        let _reset = armed();
        let dir = scratch();
        let in_path = dir.path().join("in.toml");
        let out_path = dir.path().join("absent-out.toml");
        std::fs::write(&in_path, ORIGINAL_CFG).expect("seed in");

        // No backup is taken for an absent destination, so 1st step is the replace.
        seam::inject_step_errno_at(step, INJECTED_ERRNO, 1);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err = invoke(ep, &in_path, &out_path, &mut stdout, &mut stderr)
            .expect_err(&format!("{step:?}/{ep:?}: must fail"));

        let expected = match step {
            seam::Step::FileSync => file_sync_refusal(&out_path),
            seam::Step::Rename => rename_refusal(&out_path),
            seam::Step::DirSync => unreachable!(),
        };
        assert_eq!(err.to_string(), expected, "{step:?}/{ep:?}");
        assert!(
            std::fs::symlink_metadata(&out_path).is_err(),
            "{step:?}/{ep:?}: absent --config-out must stay absent"
        );
        assert_eq!(
            sorted_entries(dir.path()),
            vec!["in.toml".to_string()],
            "{step:?}/{ep:?}: no backup or stage entry may remain"
        );
        assert_no_success_line(&stdout, &format!("absent-out/{step:?}/{ep:?}"));
    }

    // Parent creation failure leaves no file and preserves the blocking entry.
    {
        let _reset = armed();
        let dir = scratch();
        let in_path = dir.path().join("in.toml");
        let blocker = dir.path().join("not-a-dir");
        let nested = blocker.join("sub").join("out.toml");
        std::fs::write(&in_path, ORIGINAL_CFG).expect("seed in");
        std::fs::write(&blocker, b"blocker-bytes").expect("seed blocker");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err = invoke(
            Entrypoint::RunWithPaths,
            &in_path,
            &nested,
            &mut stdout,
            &mut stderr,
        )
        .expect_err("create_dir_all under regular file must fail");
        assert!(
            err.to_string().contains("create parent of"),
            "expected parent-creation context, got {err:#}"
        );
        assert_eq!(
            std::fs::read(&blocker).expect("blocker intact"),
            b"blocker-bytes"
        );
        assert_eq!(
            sorted_entries(dir.path()),
            vec!["in.toml".to_string(), "not-a-dir".to_string()]
        );
        assert_no_success_line(&stdout, "parent-create-fail");
    }

    // Parent creation success (A9) writes through write_replacing and syncs parent dir.
    {
        let _reset = armed();
        let dir = scratch();
        let in_path = dir.path().join("in.toml");
        let nested_parent = dir.path().join("nested").join("child");
        let nested_out = nested_parent.join("permissions.toml");
        std::fs::write(&in_path, ORIGINAL_CFG).expect("seed in");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        invoke(
            Entrypoint::RunWithPaths,
            &in_path,
            &nested_out,
            &mut stdout,
            &mut stderr,
        )
        .expect("nested parent creation must succeed");
        assert_eq!(seam::take_dir_syncs(), vec![nested_parent]);
        let written = std::fs::read_to_string(&nested_out).expect("read nested out");
        assert!(written.contains(EXPECTED_RULE_SUBSTR));
    }
}

#[cfg(unix)]
#[test]
fn governance_migrate_refuses_symlinked_config_10257() {
    use std::os::unix::fs::symlink;

    #[derive(Debug, Clone, Copy)]
    enum LinkKind {
        /// Symlink at `--config-out` pointing to `in_path` (in-place via symlink).
        ToInput,
        /// Symlink at `--config-out` pointing to a separate target file.
        ToOther,
        /// Dangling symlink at `--config-out`.
        Dangling,
    }

    for kind in [LinkKind::ToInput, LinkKind::ToOther, LinkKind::Dangling] {
        for ep in [Entrypoint::Run, Entrypoint::RunWithPaths] {
            let _reset = armed();
            let dir = scratch();
            let in_path = dir.path().join("real-config.toml");
            let other_target = dir.path().join("other-target.toml");
            let link_path = dir.path().join("link-config.toml");
            std::fs::write(&in_path, ORIGINAL_CFG).expect("seed real config");

            match kind {
                LinkKind::ToInput => symlink(&in_path, &link_path).expect("symlink to input"),
                LinkKind::ToOther => {
                    std::fs::write(&other_target, PREEXISTING_OUT).expect("seed other");
                    symlink(&other_target, &link_path).expect("symlink to other");
                }
                LinkKind::Dangling => {
                    let missing = dir.path().join("nonexistent.toml");
                    symlink(&missing, &link_path).expect("dangling symlink");
                }
            }

            let in_arg = match kind {
                LinkKind::ToInput => link_path.as_path(),
                LinkKind::ToOther | LinkKind::Dangling => in_path.as_path(),
            };
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let err = invoke(ep, in_arg, &link_path, &mut stdout, &mut stderr).expect_err(
                &format!("{kind:?}/{ep:?}: symlink at final name must refuse"),
            );

            assert_eq!(
                err.to_string(),
                symlink_refusal(&link_path),
                "{kind:?}/{ep:?}"
            );
            assert!(err.to_string().ends_with(SYMLINK_REFUSAL_TAIL));
            assert!(
                std::fs::symlink_metadata(&link_path)
                    .expect("link still exists")
                    .file_type()
                    .is_symlink(),
                "{kind:?}/{ep:?}: symlink itself must remain untouched"
            );
            assert_eq!(
                std::fs::read(&in_path).expect("real config intact"),
                ORIGINAL_CFG.as_bytes(),
                "{kind:?}/{ep:?}: input target must remain byte-identical"
            );
            if matches!(kind, LinkKind::ToOther) {
                assert_eq!(
                    std::fs::read(&other_target).expect("other target intact"),
                    PREEXISTING_OUT.as_bytes(),
                    "{kind:?}/{ep:?}: other symlink target must remain byte-identical"
                );
            }
            // No backup and no stage entry created when symlink is refused.
            for name in sorted_entries(dir.path()) {
                assert!(
                    !name.contains(".bak.") && !name.contains(".stage-"),
                    "{kind:?}/{ep:?}: unexpected entry {name:?} after symlink refusal"
                );
            }
            assert_no_success_line(&stdout, &format!("symlink/{kind:?}/{ep:?}"));
        }
    }
}

#[cfg(unix)]
#[test]
fn governance_migrate_mode_of_replaced_config_10257() {
    use std::os::unix::fs::PermissionsExt;

    for start_mode in [MODE_WORLD_READABLE, MODE_OWNER_ONLY] {
        for ep in [Entrypoint::Run, Entrypoint::RunWithPaths] {
            let _reset = armed();
            let dir = scratch();
            let cfg = dir.path().join("config.toml");
            std::fs::write(&cfg, ORIGINAL_CFG).expect("seed config");
            std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(start_mode))
                .expect("set start mode");

            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            invoke(ep, &cfg, &cfg, &mut stdout, &mut stderr)
                .expect(&format!("{start_mode:o}/{ep:?}: migrate must succeed"));

            let mode = std::fs::symlink_metadata(&cfg)
                .expect("stat replaced config")
                .permissions()
                .mode()
                & PERMISSION_MASK;
            assert_eq!(
                mode, MODE_OWNER_ONLY,
                "{start_mode:o}/{ep:?}: replaced config must be 0600, got {mode:o}"
            );
            let backup = find_single_backup(dir.path(), "config.toml");
            let bak_mode = std::fs::symlink_metadata(&backup)
                .expect("stat backup")
                .permissions()
                .mode()
                & PERMISSION_MASK;
            assert_eq!(
                bak_mode, MODE_OWNER_ONLY,
                "{start_mode:o}/{ep:?}: backup must be 0600, got {bak_mode:o}"
            );
            assert_eq!(
                seam::take_dir_syncs(),
                vec![dir.path().to_path_buf(), dir.path().to_path_buf()],
                "{start_mode:o}/{ep:?}: backup and replace must each fsync parent dir"
            );
        }
    }
}

#[test]
fn governance_migrate_one_mib_config_merges_under_ceiling_10257() {
    let _reset = armed();
    let dir = scratch();
    let cfg = dir.path().join("large-config.toml");

    // Build a valid >= 1 MiB TOML config carrying a real [governance] section.
    let mut big = String::with_capacity(ONE_MIB + 4096);
    big.push_str(ORIGINAL_CFG);
    big.push_str("\n[extra]\n");
    let pad_line = "# padding-comment-0123456789abcdef0123456789abcdef0123456789abcdef\n";
    while big.len() < ONE_MIB {
        big.push_str(pad_line);
    }
    assert!(big.len() >= ONE_MIB);
    std::fs::write(&cfg, &big).expect("seed 1 MiB config");

    let started = Instant::now();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    invoke(Entrypoint::Run, &cfg, &cfg, &mut stdout, &mut stderr)
        .expect("1 MiB in-place merge must succeed");
    let elapsed = started.elapsed();

    assert!(
        elapsed.as_secs() < LARGE_CONFIG_MERGE_CEILING_SECS,
        "1 MiB merge took {elapsed:?}, exceeding {LARGE_CONFIG_MERGE_CEILING_SECS}s ceiling"
    );
    assert_eq!(
        seam::take_dir_syncs(),
        vec![dir.path().to_path_buf(), dir.path().to_path_buf()],
        "1 MiB merge must take durable backup and atomic replace through snapshot_file"
    );
    let backup = find_single_backup(dir.path(), "large-config.toml");
    assert_eq!(
        std::fs::read(&backup).expect("read 1 MiB backup").len(),
        big.len()
    );
    let after = std::fs::read_to_string(&cfg).expect("read merged 1 MiB config");
    assert!(after.starts_with(&big));
    assert!(after.contains(EXPECTED_MERGED_SUBSTR));
    assert!(after.contains(EXPECTED_RULE_SUBSTR));
}
