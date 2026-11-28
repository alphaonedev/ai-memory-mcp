// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #10292 — boot-time TLS material under a failed directory fsync.
//!
//! Local TLS material written but not confirmed durable is the complete
//! after-state (#10214): the listener serves it and the durability is
//! reported on its own, never as "could not generate the certificate".
//! The table runs a first boot once clean to count its directory fsyncs,
//! then once per failure point (the nth fsync fails with a real `EIO`).

use super::*;
use crate::storage::snapshot_file::seam;

/// Clears the thread's seam state on every exit of a test.
struct SeamReset;

impl Drop for SeamReset {
    fn drop(&mut self) {
        seam::reset();
    }
}

#[test]
fn local_material_not_durable_is_served_10292() {
    let _reset = SeamReset;
    let clean = {
        let tmp = tempfile::tempdir().expect("tempdir");
        seam::reset();
        let m = resolve_local_material(tmp.path(), "127.0.0.1").expect("clean first boot");
        assert!(m.managed);
        seam::take_dir_syncs().len()
    };
    assert!(clean >= 4, "a first boot publishes four files, synced {clean} times");
    for nth in 1..=u32::try_from(clean).expect("a handful of directory syncs") {
        let tmp = tempfile::tempdir().expect("tempdir");
        seam::reset();
        seam::inject_step_errno_at(seam::Step::DirSync, libc::EIO, nth);
        let got = resolve_local_material(tmp.path(), "127.0.0.1");
        seam::reset();
        let m = got.unwrap_or_else(|e| panic!("sync {nth}: serves the material, got {e:#}"));
        assert!(m.managed, "sync {nth}: the local leaf stays managed");
        assert!(m.cert_path.is_file(), "sync {nth}: the leaf is on disk");
        assert!(m.key_path.is_file(), "sync {nth}: the key is on disk");
        let ca = m.ca_cert_path.expect("a managed leaf names its CA");
        assert!(ca.is_file(), "sync {nth}: the CA is on disk");
        let again = resolve_local_material(tmp.path(), "127.0.0.1").expect("next boot");
        assert_eq!(again.cert_path, m.cert_path, "sync {nth}");
        assert_eq!(
            std::fs::read(&again.cert_path).expect("read leaf"),
            std::fs::read(&m.cert_path).expect("read leaf"),
            "sync {nth}: the next boot reuses the leaf on disk"
        );
    }
}
