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
