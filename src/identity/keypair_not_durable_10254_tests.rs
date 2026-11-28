// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10254 — the two-file key writers under a failed directory fsync.
//!
//! After a rename or link the published key file IS in place; only its
//! durability is unproven (#10214). So a sync failure on the first file of a
//! pair never stops the second: the writer finishes the pair, then reports
//! the not-durable outcome. The pair on disk is always complete and
//! consistent, so [`load`] adopts the new identity, and the report says
//! "written, not confirmed durable", never "not written".
//!
//! Each table runs the operation once clean to count its directory fsyncs,
//! then once per failure point (the nth fsync fails with a real `EIO` from
//! the test seam).

use super::*;
use crate::storage::snapshot_file::seam;
use tempfile::TempDir;

/// The words every not-durable report carries (the funnel's message).
const NOT_DURABLE: &str = "is written but not confirmed durable";

/// Clears the thread's seam state on every exit of a test.
struct SeamReset;

impl Drop for SeamReset {
    fn drop(&mut self) {
        seam::reset();
    }
}

/// How many directory fsyncs `op` makes on a clean run.
fn dir_syncs_of(op: impl FnOnce()) -> u32 {
    seam::reset();
    op();
    let n = seam::take_dir_syncs().len();
    u32::try_from(n).expect("a handful of directory syncs")
}

/// The public-key bytes of the pair on disk, through the real loader.
fn loaded_public(agent: &str, dir: &Path) -> [u8; 32] {
    load(agent, dir)
        .unwrap_or_else(|e| panic!("the pair on disk must load: {e:#}"))
        .public
        .to_bytes()
}

/// `save` over an existing pair (a rotation's write): a sync failure after
/// the `.priv` publish still writes the `.pub`, so the pair is the new one.
#[test]
fn save_dir_sync_failure_finishes_the_pair_10254() {
    let agent = "agent-10254-save";
    let clean = dir_syncs_of(|| {
        let dir = TempDir::new().expect("tempdir");
        save(&generate(agent).expect("old"), dir.path()).expect("old pair");
        seam::reset();
        save(&generate(agent).expect("new"), dir.path()).expect("clean save");
    });
    assert!(
        clean >= 2,
        "a save publishes two files, synced {clean} times"
    );
    for nth in 1..=clean {
        let _reset = SeamReset;
        let dir = TempDir::new().expect("tempdir");
        save(&generate(agent).expect("old"), dir.path()).expect("old pair");
        let new = generate(agent).expect("new");
        seam::reset();
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
        let err = save(&new, dir.path()).expect_err("a failed sync is reported");
        seam::reset();
        assert!(
            format!("{err:#}").contains(NOT_DURABLE),
            "row {nth}: the report says written, not durable: {err:#}"
        );
        assert_eq!(
            loaded_public(agent, dir.path()),
            new.public.to_bytes(),
            "row {nth}: the complete new pair is on disk"
        );
    }
}

/// `rotate`: a sync failure after the archive publish does not abort the
/// rotation; the new pair is written, the archive holds the old key, and the
/// outcome is reported.
#[test]
fn rotate_dir_sync_failure_completes_the_rotation_10254() {
    let agent = "agent-10254-rotate";
    let clean = dir_syncs_of(|| {
        let dir = TempDir::new().expect("tempdir");
        save(&generate(agent).expect("old"), dir.path()).expect("old pair");
        seam::reset();
        drop(rotate(agent, dir.path()).expect("clean rotate"));
    });
    assert!(
        clean >= 3,
        "a rotation publishes three files, synced {clean} times"
    );
    for nth in 1..=clean {
        let _reset = SeamReset;
        let dir = TempDir::new().expect("tempdir");
        let old = generate(agent).expect("old");
        save(&old, dir.path()).expect("old pair");
        seam::reset();
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
        let err = rotate(agent, dir.path()).expect_err("a failed sync is reported");
        seam::reset();
        assert!(
            format!("{err:#}").contains(NOT_DURABLE),
            "row {nth}: the report says written, not durable: {err:#}"
        );
        assert_ne!(
            loaded_public(agent, dir.path()),
            old.public.to_bytes(),
            "row {nth}: the rotation completed"
        );
        let archived: Vec<_> = std::fs::read_dir(dir.path())
            .expect("list")
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("{agent}{PUB_SUFFIX}."))
            })
            .map(|e| std::fs::read(e.path()).expect("read archive"))
            .collect();
        assert_eq!(
            archived,
            vec![old.public.to_bytes().to_vec()],
            "row {nth}: one archive, holding the old public key"
        );
    }
}

/// `ensure_keypair` first run: a sync failure after the `.priv` claim still
/// writes the `.pub`, then reports.
#[test]
fn ensure_keypair_claim_dir_sync_failure_writes_the_pub_10254() {
    let agent = "agent-10254-claim";
    let clean = dir_syncs_of(|| {
        let dir = TempDir::new().expect("tempdir");
        drop(ensure_keypair(agent, dir.path(), false).expect("clean first run"));
    });
    assert!(
        clean >= 2,
        "a first run publishes two files, synced {clean} times"
    );
    for nth in 1..=clean {
        let _reset = SeamReset;
        let dir = TempDir::new().expect("tempdir");
        seam::reset();
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
        let err = ensure_keypair(agent, dir.path(), false).expect_err("a failed sync is reported");
        seam::reset();
        assert!(
            format!("{err:#}").contains(NOT_DURABLE),
            "row {nth}: the report says written, not durable: {err:#}"
        );
        assert!(
            agent_pub_path(dir.path(), agent).exists(),
            "row {nth}: the .pub is written"
        );
        let kp = load(agent, dir.path()).expect("the pair loads");
        assert!(kp.can_sign(), "row {nth}: the pair is complete");
    }
}

/// The bytes a #10265 row writes.
const ROW_BYTES_10265: &[u8] = b"key-bytes-10265";

/// The not-durable report of an outcome that must be `NotDurable`.
fn not_durable_of(outcome: Durability, row: &str) -> NotDurable {
    match outcome {
        Durability::NotDurable(not_durable) => not_durable,
        Durability::Durable => panic!("{row}: a failed directory fsync must be NotDurable"),
    }
}

/// The exact report of a failed directory fsync of `path` (#10214 wording).
fn report_for(what: &str, path: &Path, dir: &Path) -> String {
    format!(
        "{what} {} is written but not confirmed durable: the fsync of its directory {} failed \
         ({}), so it may not survive a crash (#10214)",
        path.display(),
        dir.display(),
        io::Error::from_raw_os_error(libc::EIO)
    )
}

/// One row per create-new key writer (#10265): a clean run is `Durable` and
/// syncs the directory once; a failed directory fsync is `NotDurable` with
/// the exact report and the complete file left in place. A mutant that
/// swallows the fsync (`let _ = sync_dir(..)`, then `Durable`) is red.
#[test]
fn create_and_claim_dir_sync_failure_is_not_durable_10265() {
    type Writer = fn(&Path, &[u8], u32) -> io::Result<Durability>;
    let rows: [(&str, Writer, &str); 2] = [
        ("create_new_with_mode", create_new_with_mode, ARCHIVE_WHAT),
        ("claim_new_with_mode", claim_new_with_mode, PRIVATE_KEY_WHAT),
    ];
    for (row, write, what) in rows {
        let _reset = SeamReset;
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("clean.key");
        seam::reset();
        match write(&path, ROW_BYTES_10265, 0o600).expect("clean write") {
            Durability::Durable => {}
            Durability::NotDurable(nd) => panic!("{row}: clean run not durable: {nd}"),
        }
        assert_eq!(
            seam::take_dir_syncs(),
            vec![dir.path().to_path_buf()],
            "{row}"
        );

        let path = dir.path().join("failing.key");
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, 1);
        let outcome = write(&path, ROW_BYTES_10265, 0o600).expect("the file is written");
        seam::reset();
        let not_durable = not_durable_of(outcome, row);
        assert_eq!(
            not_durable.to_string(),
            report_for(what, &path, dir.path()),
            "{row}"
        );
        assert_eq!(not_durable.raw_os_error(), Some(libc::EIO), "{row}");
        assert_eq!(
            fs::read(&path).expect("the complete file stays"),
            ROW_BYTES_10265,
            "{row}"
        );
    }
}

/// The head of the context a later error carries (#10310; written out here,
/// not taken from the code under test).
const WRITTEN_BEFORE_10310: &str = "files written before this error are kept on disk";

/// #10310 — `ensure_generate`: the `.priv` claim is written but not
/// confirmed durable, then the `.pub` write fails. The error names both, the
/// claimed `.priv` stays, and the error never reads as written-but-not-durable.
#[test]
fn pub_failure_keeps_priv_claim_report_10310() {
    let _reset = SeamReset;
    let agent = "agent-10310-generate";
    let dir = TempDir::new().expect("tempdir");
    let pub_path = agent_pub_path(dir.path(), agent);
    std::fs::create_dir(&pub_path).expect("the blocking directory");
    seam::reset();
    seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, 1);
    let err = ensure_generate(agent, dir.path(), pub_path.clone())
        .err()
        .expect("a .pub name that is a directory fails the generate");
    seam::reset();
    let priv_path = agent_priv_path(dir.path(), agent);
    let mut report = NotDurableReport::new();
    report.note(Durability::NotDurable(NotDurable::new(
        "private key",
        &priv_path,
        dir.path(),
        io::Error::from_raw_os_error(libc::EIO),
    )));
    let later: Vec<String> = err.chain().skip(1).map(ToString::to_string).collect();
    assert_eq!(
        format!("{err:#}"),
        format!(
            "{WRITTEN_BEFORE_10310}: {report}: writing public key {}: {}",
            pub_path.display(),
            io::Error::from_raw_os_error(libc::EISDIR)
        ),
        "later layers: {later:?}"
    );
    assert!(priv_path.is_file(), "the claimed .priv is kept");
    assert!(err.downcast_ref::<NotDurableReport>().is_none(), "{err:#}");
    assert!(err.downcast_ref::<NotDurable>().is_none(), "{err:#}");
}
