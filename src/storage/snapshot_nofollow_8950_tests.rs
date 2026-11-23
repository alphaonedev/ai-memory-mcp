// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #8950 — the shared no-follow write helper (`snapshot_file`) and the
//! ratchet that keeps every new raw write primitive visible.

use super::snapshot_file::{
    SYMLINK_REFUSAL_TAIL, UNIQUE_NAME_ATTEMPTS, refuse_occupied, refuse_symlink, stage_beside,
    symlink_refusal, write_new_private_unique, write_replacing,
};
use std::path::{Path, PathBuf};

/// Scratch directory for one test (under `TMPDIR`, removed on drop).
fn scratch() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("scratch dir")
}

/// What a row plants at the destination.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
enum Plant {
    Dangling,
    OutsideFile,
    Directory,
}

#[cfg(unix)]
fn plant(dir: &Path, link: &Path, plant: Plant) -> PathBuf {
    let target = match plant {
        Plant::Dangling => dir.join("gone"),
        Plant::OutsideFile => {
            let f = dir.join("outside");
            std::fs::write(&f, b"outside-sentinel").expect("outside file");
            f
        }
        Plant::Directory => {
            let d = dir.join("outside-dir");
            std::fs::create_dir(&d).expect("outside dir");
            d
        }
    };
    std::os::unix::fs::symlink(&target, link).expect("plant symlink");
    target
}

#[cfg(unix)]
fn assert_target_untouched(target: &Path, plant: Plant, row: &str) {
    match plant {
        Plant::Dangling => assert!(
            std::fs::symlink_metadata(target).is_err(),
            "{row}: the dangling target was created"
        ),
        Plant::OutsideFile => assert_eq!(
            std::fs::read(target).expect("outside"),
            b"outside-sentinel",
            "{row}: the outside file changed"
        ),
        Plant::Directory => assert_eq!(
            std::fs::read_dir(target).expect("dir").count(),
            0,
            "{row}: the linked directory gained an entry"
        ),
    }
}

/// Entries in `dir` other than `keep`.
fn others(dir: &Path, keep: &[&Path]) -> Vec<String> {
    std::fs::read_dir(dir)
        .expect("read dir")
        .flatten()
        .filter(|e| !keep.iter().any(|k| e.path() == *k))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect()
}

#[cfg(unix)]
const ROWS: [Plant; 3] = [Plant::Dangling, Plant::OutsideFile, Plant::Directory];

/// Row table, destination planted BEFORE the stage: refused at the stage
/// with the exact error, nothing staged.
#[cfg(unix)]
#[test]
fn stage_refuses_planted_destination_rows_8950() {
    for p in ROWS {
        let row = format!("{p:?}");
        let tmp = scratch();
        let dir = tmp.path();
        let dest = dir.join("snap.db");
        let target = plant(dir, &dest, p);
        let err = stage_beside(&dest, "snapshot")
            .err()
            .unwrap_or_else(|| panic!("{row}: stage must refuse"));
        assert_eq!(err.to_string(), symlink_refusal(&dest), "{row}");
        assert!(err.to_string().ends_with(SYMLINK_REFUSAL_TAIL), "{row}");
        assert_target_untouched(&target, p, &row);
        assert_eq!(
            others(dir, &[&dest, &target]),
            Vec::<String>::new(),
            "{row}"
        );
    }
}

/// Row table, destination planted AFTER the stage (the race): the publish
/// refuses with the exact error, the link survives, the staging name is gone.
#[cfg(unix)]
#[test]
fn publish_refuses_destination_planted_after_stage_rows_8950() {
    for p in ROWS {
        let row = format!("{p:?}");
        let tmp = scratch();
        let dir = tmp.path();
        let dest = dir.join("snap.db");
        let mut stage = stage_beside(&dest, "snapshot").expect("stage");
        stage.write_all(b"payload").expect("write");
        let target = plant(dir, &dest, p);
        let err = stage.publish().expect_err("publish must refuse");
        assert_eq!(err.to_string(), symlink_refusal(&dest), "{row}");
        assert_target_untouched(&target, p, &row);
        assert!(
            std::fs::symlink_metadata(&dest)
                .expect("link")
                .file_type()
                .is_symlink(),
            "{row}: the planted link was replaced"
        );
        assert_eq!(
            others(dir, &[&dest, &target]),
            Vec::<String>::new(),
            "{row}"
        );
    }
}

/// Symlinked SOURCE row: the staging name is swapped for a link to an
/// outside file after the write (what `VACUUM INTO` writes through by
/// name). The publish refuses with the exact error; nothing is published and
/// the outside file is unchanged.
#[cfg(unix)]
#[test]
fn publish_refuses_symlinked_staging_source_8950() {
    let tmp = scratch();
    let dir = tmp.path();
    let dest = dir.join("snap.db");
    let mut stage = stage_beside(&dest, "snapshot").expect("stage");
    stage.write_all(b"payload").expect("write");
    let staged = stage.path().to_path_buf();
    std::fs::remove_file(&staged).expect("unlink staged");
    let outside = dir.join("outside");
    std::fs::write(&outside, b"outside-sentinel").expect("outside");
    std::os::unix::fs::symlink(&outside, &staged).expect("swap in link");
    let err = stage.publish().expect_err("a symlinked source must refuse");
    assert_eq!(err.to_string(), symlink_refusal(&staged));
    assert!(
        std::fs::symlink_metadata(&dest).is_err(),
        "nothing published"
    );
    assert_eq!(
        std::fs::read(&outside).expect("outside"),
        b"outside-sentinel"
    );
    assert!(
        std::fs::symlink_metadata(&staged).is_err(),
        "staging name cleaned"
    );
}

/// The staging name swapped for a different REGULAR file is refused too.
#[cfg(unix)]
#[test]
fn publish_refuses_replaced_staging_file_8950() {
    let tmp = scratch();
    let dir = tmp.path();
    let dest = dir.join("snap.db");
    let mut stage = stage_beside(&dest, "snapshot").expect("stage");
    stage.write_all(b"payload").expect("write");
    let staged = stage.path().to_path_buf();
    std::fs::remove_file(&staged).expect("unlink staged");
    std::fs::write(&staged, b"impostor").expect("impostor");
    let err = stage.publish().expect_err("a replaced source must refuse");
    assert_eq!(
        err.to_string(),
        format!(
            "refusing to publish {}: the staged file {} was replaced while it was written (#8950)",
            dest.display(),
            staged.display()
        )
    );
    assert!(
        std::fs::symlink_metadata(&dest).is_err(),
        "nothing published"
    );
}

/// Happy path: a regular, owner-only file with the full content at the
/// destination, no staging name left.
#[test]
fn publish_creates_private_regular_file_8950() {
    let tmp = scratch();
    let dir = tmp.path();
    let dest = dir.join("snap.db");
    let mut stage = stage_beside(&dest, "snapshot").expect("stage");
    stage.write_all(b"payload").expect("write");
    stage.file().sync_all().expect("fsync");
    drop(stage.publish().expect("publish"));
    let meta = std::fs::symlink_metadata(&dest).expect("dest");
    assert!(meta.file_type().is_file());
    assert_eq!(std::fs::read(&dest).expect("read"), b"payload");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(others(dir, &[&dest]), Vec::<String>::new());
}

/// A regular file at the destination keeps the plain overwrite refusal.
#[test]
fn refuse_occupied_regular_file_names_it_8950() {
    let tmp = scratch();
    let dir = tmp.path();
    let dest = dir.join("m.json");
    std::fs::write(&dest, b"x").expect("plant");
    let err = refuse_occupied(&dest, "manifest").expect_err("occupied");
    assert_eq!(
        err.to_string(),
        format!("refusing to overwrite existing manifest {}", dest.display())
    );
}

/// Row table for the derived-name sites (config / install backups):
/// `write_new_private_unique` refuses every plant with the exact error, writes
/// nothing through it and leaves no staging entry.
#[cfg(unix)]
#[test]
fn write_new_private_refuses_planted_rows_8950() {
    for p in ROWS {
        let row = format!("{p:?}");
        let tmp = scratch();
        let dir = tmp.path();
        let dest = dir.join("config.toml.bak.20261114-000000");
        let target = plant(dir, &dest, p);
        let err = write_new_private_unique(&dest, "config backup", b"secret-config")
            .expect_err("a planted link must refuse");
        assert_eq!(err.to_string(), symlink_refusal(&dest), "{row}");
        assert_target_untouched(&target, p, &row);
        assert_eq!(
            others(dir, &[&dest, &target]),
            Vec::<String>::new(),
            "{row}"
        );
    }
}

/// Row table for the product-owned replace site (install snippet):
/// `write_replacing` refuses every plant with the exact error and leaves the
/// link in place; a regular file is replaced with private, full content.
#[cfg(unix)]
#[test]
fn write_replacing_refuses_planted_rows_and_replaces_files_8950() {
    for p in ROWS {
        let row = format!("{p:?}");
        let tmp = scratch();
        let dir = tmp.path();
        let dest = dir.join("system-prompt-claude.md");
        let target = plant(dir, &dest, p);
        let err = write_replacing(&dest, "snippet", b"snippet-body")
            .expect_err("a planted link must refuse");
        assert_eq!(err.to_string(), symlink_refusal(&dest), "{row}");
        assert_target_untouched(&target, p, &row);
        assert!(
            std::fs::symlink_metadata(&dest)
                .expect("link")
                .file_type()
                .is_symlink(),
            "{row}: the planted link was replaced"
        );
        assert_eq!(
            others(dir, &[&dest, &target]),
            Vec::<String>::new(),
            "{row}"
        );
    }
    let tmp = scratch();
    let dir = tmp.path();
    let dest = dir.join("system-prompt-claude.md");
    std::fs::write(&dest, b"old").expect("old snippet");
    write_replacing(&dest, "snippet", b"new-body").expect("replace a regular file");
    let meta = std::fs::symlink_metadata(&dest).expect("dest");
    assert!(meta.file_type().is_file());
    assert_eq!(std::fs::read(&dest).expect("read"), b"new-body");
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(others(dir, &[&dest]), Vec::<String>::new());
}

/// `refuse_symlink` passes an absent name and a regular file.
#[test]
fn refuse_symlink_passes_absent_and_regular_8950() {
    let tmp = scratch();
    let dir = tmp.path();
    let dest = dir.join("f");
    refuse_symlink(&dest).expect("absent passes");
    std::fs::write(&dest, b"x").expect("file");
    refuse_symlink(&dest).expect("regular passes");
}

// ---------------------------------------------------------------------------
// Ratchet: raw write primitives per production file.
// ---------------------------------------------------------------------------

/// The primitives that create or replace a file by name and can follow a
/// symlink at the final component (or, for `VACUUM INTO`, always do).
const RAW_WRITE_PRIMITIVES: [&str; 6] = [
    "fs::write(",
    "File::create(",
    "fs::copy(",
    "OpenOptions::new()",
    VACUUM_INTO_STATEMENTS[0],
    VACUUM_INTO_STATEMENTS[1],
];

/// The SQL shapes of a `VACUUM INTO` statement (bound or quoted target), so
/// prose that merely names the statement is not counted.
const VACUUM_INTO_STATEMENTS: [&str; 2] = ["\"VACUUM INTO ?", "\"VACUUM INTO '"];

/// Every production file that runs a `VACUUM INTO` statement must fill a
/// private stage (`stage_beside(`), and these are all of them (r1: the
/// pre-migration snapshot runs inside `snapshot_file.rs`).
const VACUUM_INTO_FILES: [&str; 3] = [
    "src/cli/backup.rs",
    "src/cli/doctor.rs",
    "src/storage/snapshot_file.rs",
];

/// Census of raw write primitives (lines) per production file at #8950. A NEW
/// file, or a higher count, fails the ratchet: route the new site through
/// `snapshot_file::stage_beside` (or another no-follow open) and, only when
/// it is guarded, raise the row here with the guard named in the commit.
/// Regenerate with `write_site_census.py` (rules mirrored in
/// [`production_census`]).
const RAW_WRITE_CENSUS_8950: &[(&str, usize)] = &[
    // #9367: the one site is the READ-only key-file open of
    // `read_checked_key_file` (src/agent_key_file.rs:95, `.read(true)`, no
    // create/truncate/write flag): it creates and replaces nothing, so the
    // no-follow write primitive does not fit. Guard:
    // `agent_key_file::k1_shared_checks_9367_tests::key_file_open_is_read_only_8950_9367`.
    ("src/agent_key_file.rs", 1),
    ("src/audit.rs", 14),
    ("src/background/fts_integrity.rs", 4),
    ("src/bench.rs", 2),
    ("src/cli/agents.rs", 5),
    ("src/cli/audit.rs", 5),
    ("src/cli/backup.rs", 10),
    ("src/cli/commands/config.rs", 15),
    ("src/cli/commands/export_reflections/private_file.rs", 1),
    ("src/cli/commands/skill.rs", 2),
    ("src/cli/doctor.rs", 8),
    ("src/cli/governance_migrate.rs", 14),
    ("src/cli/identity.rs", 8),
    ("src/cli/identity_delegate.rs", 1),
    ("src/cli/install.rs", 4),
    ("src/cli/io.rs", 4),
    ("src/cli/logs.rs", 25),
    ("src/cli/offload.rs", 5),
    ("src/cli/rules.rs", 13),
    ("src/cli/wake_hub.rs", 1),
    ("src/config.rs", 19),
    ("src/daemon_runtime.rs", 8),
    ("src/embeddings.rs", 1),
    ("src/encryption/escrow.rs", 3),
    ("src/encryption/mod.rs", 8),
    ("src/encryption/scope/store.rs", 3),
    ("src/enterprise_federation_posture.rs", 2),
    ("src/erasure/archive_sync.rs", 1),
    ("src/erasure/store.rs", 8),
    ("src/federation/erasure_outbox.rs", 1),
    ("src/federation/identity/chain.rs", 2),
    ("src/federation/identity/credential.rs", 2),
    ("src/federation/identity/trust_bundle.rs", 3),
    ("src/federation/mod.rs", 1),
    ("src/federation/peer.rs", 1),
    ("src/federation/peer_posture.rs", 1),
    ("src/forensic/bundle.rs", 6),
    ("src/governance/audit.rs", 37),
    ("src/governance/capability.rs", 3),
    ("src/governance/deferred_audit.rs", 21),
    ("src/governance/rules_store.rs", 2),
    ("src/hooks/config.rs", 1),
    ("src/hooks/post_reflect/auto_export.rs", 2),
    ("src/hooks/pre_store/auto_atomise.rs", 1),
    ("src/identity/key_inventory.rs", 4),
    ("src/identity/keypair.rs", 20),
    ("src/inference/mod.rs", 3),
    ("src/keys/roles.rs", 1),
    ("src/log_paths.rs", 5),
    ("src/logging.rs", 2),
    ("src/main.rs", 2),
    ("src/mcp/shutdown.rs", 1),
    ("src/mcp/tools/skill_export.rs", 3),
    ("src/mcp/tools/skill_register.rs", 8),
    ("src/mine.rs", 10),
    ("src/recover/in_tx_fault.rs", 1),
    ("src/recover/line_file.rs", 9),
    ("src/recover/mod.rs", 3),
    ("src/recover/transcript_paths.rs", 7),
    ("src/recover/watcher.rs", 2),
    ("src/reranker.rs", 3),
    // r1 (X-1): the pre-migration VACUUM INTO moved into snapshot_file.rs
    // (migrations.rs 1 -> 0); create_private_target and the by-name settle
    // are gone (snapshot_file.rs 3 -> 2: open_new_private + the VACUUM).
    ("src/storage/snapshot_file.rs", 2),
    ("src/storage/sqlite_integrity.rs", 1),
    ("src/store_url.rs", 1),
    ("src/test_support.rs", 6),
    // #9954: 7 -> 8. The new site is the READ-only pin-file open of
    // `read_pin_file_capped` (`.read(true)` + O_NONBLOCK, no create/truncate/
    // write flag): it creates and replaces nothing. Guard:
    // `tls::tests::pin_file_open_is_read_only_8950_9954`.
    ("src/tls.rs", 8),
    // #9954: the one site is the `std::fs::write` of the cfg(test)-only
    // fixture writer `write` (the module is `#[cfg(test)]` in tls.rs; its
    // name does not end in `_tests`, so the walk counts it).
    ("src/tls/pin_file_cases.rs", 1),
    ("src/tls_bootstrap.rs", 1),
    ("src/wake_client/bundle.rs", 4),
    ("src/wake_client/session.rs", 1),
    ("src/wake_hub/allowlist_reload.rs", 2),
    ("src/wake_hub/delegation_verifier.rs", 1),
    ("src/wake_hub/health.rs", 1),
    ("src/wake_hub/server.rs", 1),
    ("src/wake_hub/startup.rs", 1),
];

fn is_test_path(rel: &str) -> bool {
    let p = Path::new(rel);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
    stem.ends_with("_tests")
        || stem == "tests"
        || p.parent()
            .is_some_and(|d| d.components().any(|c| c.as_os_str() == "tests"))
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir").flatten() {
        let path = entry.path();
        if entry.file_type().expect("file type").is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `(relative path, primitive lines)` for every production file under `src/`.
fn production_census() -> Vec<(String, usize, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    let mut rows = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .expect("under the manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_path(&rel) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source");
        let n = text
            .lines()
            .filter(|l| RAW_WRITE_PRIMITIVES.iter().any(|p| l.contains(p)))
            .count();
        if n > 0 {
            rows.push((rel, n, text));
        }
    }
    rows.sort();
    rows
}

#[test]
fn raw_write_primitives_do_not_grow_8950() {
    let mut violations = Vec::new();
    for (rel, n, _) in production_census() {
        match RAW_WRITE_CENSUS_8950.iter().find(|(p, _)| *p == rel) {
            None => violations.push(format!(
                "{rel}: {n} raw write site(s), file not in the census"
            )),
            Some((_, ceiling)) if n > *ceiling => {
                violations.push(format!("{rel}: {n} raw write site(s) > census {ceiling}"));
            }
            Some(_) => {}
        }
    }
    assert!(
        violations.is_empty(),
        "#8950 ratchet: a new raw write site bypasses the no-follow helper \
         (route it through snapshot_file::stage_beside or an O_NOFOLLOW open):\n{}",
        violations.join("\n")
    );
}

#[test]
fn vacuum_into_routes_through_the_no_follow_helper_8950() {
    let census = production_census();
    let users: Vec<&str> = census
        .iter()
        .filter(|(_, _, text)| VACUUM_INTO_STATEMENTS.iter().any(|s| text.contains(s)))
        .map(|(rel, _, _)| rel.as_str())
        .collect();
    assert_eq!(
        users, VACUUM_INTO_FILES,
        "#8950: the VACUUM INTO sites changed"
    );
    for (rel, _, text) in &census {
        if VACUUM_INTO_FILES.contains(&rel.as_str()) {
            // r1 (X-1): naming the module is not enough; the file must stage.
            assert!(
                text.contains("stage_beside("),
                "#8950: {rel} runs VACUUM INTO without snapshot_file::stage_beside"
            );
        }
    }
}

/// A backup taken twice in the same tick keeps both copies: the second takes
/// the next numbered name and the first is never replaced.
#[test]
fn unique_backup_keeps_both_same_tick_copies_8950() {
    let dir = scratch();
    let dest = dir.path().join("config.toml.bak.20261114T183444.962Z");
    let first = write_new_private_unique(&dest, "install backup", b"one").expect("first");
    let second = write_new_private_unique(&dest, "install backup", b"two").expect("second");
    assert_eq!(first, dest);
    let mut numbered = dest.as_os_str().to_owned();
    numbered.push(".1");
    assert_eq!(second, PathBuf::from(numbered));
    assert_eq!(std::fs::read(&first).expect("first bytes"), b"one");
    assert_eq!(std::fs::read(&second).expect("second bytes"), b"two");
    for written in [&first, &second] {
        let meta = std::fs::symlink_metadata(written).expect("meta");
        assert!(
            meta.file_type().is_file(),
            "{}: not a regular file",
            written.display()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }
}

/// A symlink planted at the wanted name or at a numbered name is refused with
/// the exact refusal, and its target is untouched.
#[cfg(unix)]
#[test]
fn unique_backup_refuses_planted_symlink_rows_8950() {
    for row in ROWS {
        for numbered_slot in [false, true] {
            let dir = scratch();
            let dest = dir.path().join("config.toml.bak.20261114-183444");
            let link = if numbered_slot {
                std::fs::write(&dest, b"taken").expect("taken");
                let mut n = dest.as_os_str().to_owned();
                n.push(".1");
                PathBuf::from(n)
            } else {
                dest.clone()
            };
            let target = plant(dir.path(), &link, row);
            let err = write_new_private_unique(&dest, "config backup", b"new")
                .expect_err("a planted symlink must be refused");
            let msg = format!("{err:#}");
            assert_eq!(msg, symlink_refusal(&link), "{row:?}/{numbered_slot}");
            assert!(msg.ends_with(SYMLINK_REFUSAL_TAIL));
            assert_target_untouched(&target, row, &format!("{row:?}/{numbered_slot}"));
        }
    }
}

/// S-1: a symlink swapped in at the snapshot name is refused with the exact
/// error, and the link target's mode is unchanged (fchmod, never by name).
#[cfg(unix)]
/// S-4: the name and all numbered names taken, the next one is refused with
/// the exact error; nothing is written and no staging entry is left.
#[test]
fn unique_backup_refuses_name_past_the_last_numbered_8950() {
    let dir = scratch();
    let dest = dir.path().join("config.toml.bak");
    let name = |n: u32| PathBuf::from(format!("{}.{n}", dest.display()));
    std::fs::write(&dest, b"taken").expect("taken");
    for n in 1..=UNIQUE_NAME_ATTEMPTS {
        std::fs::write(name(n), b"taken").expect("taken");
    }
    let err = write_new_private_unique(&dest, "install backup", b"new").expect_err("all taken");
    let tail = format!("it and {UNIQUE_NAME_ATTEMPTS} numbered names beside it are taken");
    let shown = dest.display();
    let want = format!("refusing to write install backup {shown}: {tail}");
    assert_eq!(format!("{err:#}"), want);
    assert!(std::fs::symlink_metadata(name(UNIQUE_NAME_ATTEMPTS + 1)).is_err());
    let entries = u32::try_from(std::fs::read_dir(dir.path()).expect("dir").count());
    assert_eq!(entries.expect("fits"), UNIQUE_NAME_ATTEMPTS + 1);
}
