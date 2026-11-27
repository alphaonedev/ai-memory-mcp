// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10253 / #10262 — the backup PAIR (snapshot + manifest) under a
//! failed directory fsync. After the rename or link the published file IS in
//! place; only its durability is unproven (#10214). So a sync failure after
//! the snapshot publish still writes the manifest, a sync failure after the
//! manifest publish removes nothing, and the result is the reported
//! not-durable outcome (#3605): never a snapshot without its manifest, never
//! a manifest without its snapshot.
//!
//! The failure is a real `EIO` from the funnel's one directory fsync, made
//! by the test seam at the named failure point (1 = after the snapshot
//! publish, 2 = after the manifest publish).

#![cfg(test)]

use crate::storage::snapshot_file::{self, seam};
use std::path::Path;

const SNAPSHOT_NAME: &str = "ai-memory-10253.db";
const MANIFEST_NAME: &str = "ai-memory-10253.manifest.json";
const SNAPSHOT_BYTES: &[u8] = b"snapshot-10253";
const MANIFEST_TEXT: &str = "{\"manifest\":10253}";

/// Clears the thread's seam state on every exit of a test.
struct SeamReset;

impl Drop for SeamReset {
    fn drop(&mut self) {
        seam::reset();
    }
}

/// The caller's own directory fsync (not the funnel's): always succeeds, so
/// only the funnel's failure points are exercised.
fn sync_ok(_: &Path) -> std::io::Result<()> {
    Ok(())
}

/// The bytes at `path`, `None` when nothing is there.
fn bytes_at(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => panic!("reading {}: {e}", path.display()),
    }
}

/// One row per failure point: the pair is complete, nothing was removed,
/// and the result is the reported not-durable outcome naming the failure.
#[test]
fn backup_pair_dir_sync_failure_keeps_a_complete_pair_10253() {
    for nth in [1_u32, 2] {
        seam::reset();
        let _reset = SeamReset;
        let dir = tempfile::TempDir::new().expect("scratch dir");
        let snapshot_path = dir.path().join(SNAPSHOT_NAME);
        let manifest_path = dir.path().join(MANIFEST_NAME);
        let mut stage =
            snapshot_file::stage_beside(&snapshot_path, "backup snapshot").expect("stage");
        stage.write_all(SNAPSHOT_BYTES).expect("fill stage");
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);

        let failures = crate::cli::backup::write_backup_pair_durably(
            stage,
            &manifest_path,
            MANIFEST_TEXT,
            sync_ok,
        )
        .unwrap_or_else(|e| panic!("row {nth}: the pair is written, not refused: {e:#}"));

        assert_eq!(
            bytes_at(&snapshot_path).as_deref(),
            Some(SNAPSHOT_BYTES),
            "row {nth}: the snapshot stays"
        );
        assert_eq!(
            bytes_at(&manifest_path).as_deref(),
            Some(MANIFEST_TEXT.as_bytes()),
            "row {nth}: the manifest is written"
        );
        let published = if nth == 1 {
            &snapshot_path
        } else {
            &manifest_path
        };
        assert_eq!(
            failures.len(),
            1,
            "row {nth}: one failure, got {failures:?}"
        );
        assert!(
            failures[0].contains(&published.display().to_string())
                && failures[0].contains("is written but not confirmed durable"),
            "row {nth}: the failure names the not-durable file, got {failures:?}"
        );
    }
}

/// The durable row: no failure, a complete pair.
#[test]
fn backup_pair_all_syncs_succeed_is_durable_10253() {
    seam::reset();
    let _reset = SeamReset;
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let snapshot_path = dir.path().join(SNAPSHOT_NAME);
    let manifest_path = dir.path().join(MANIFEST_NAME);
    let mut stage = snapshot_file::stage_beside(&snapshot_path, "backup snapshot").expect("stage");
    stage.write_all(SNAPSHOT_BYTES).expect("fill stage");

    let failures = crate::cli::backup::write_backup_pair_durably(
        stage,
        &manifest_path,
        MANIFEST_TEXT,
        sync_ok,
    )
    .expect("durable pair");

    assert_eq!(failures, Vec::<String>::new());
    assert_eq!(bytes_at(&snapshot_path).as_deref(), Some(SNAPSHOT_BYTES));
    assert_eq!(
        bytes_at(&manifest_path).as_deref(),
        Some(MANIFEST_TEXT.as_bytes())
    );
}
