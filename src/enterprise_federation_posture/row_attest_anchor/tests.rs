// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Tests and the test-only key fixture of check #23 (#10086), kept out of the
//! production file so the #8950 raw-write census counts no test write as a
//! production site (#10040).

use super::super::tests::{EnvGuard, clear_all, env_lock, find, set_fully_hardened_env};
use super::super::{all_pass, evaluate};
use super::{CONTROL, row_from};
use crate::config::AppConfig;
use crate::storage::row_attest::anchor::TrustAnchor;

/// Test fixture for `set_fully_hardened_env`: one agent public key in the
/// key directory, so check #23 loads anchored.
pub(crate) fn seed_anchor_key(dir: &std::path::Path) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
    std::fs::write(dir.join("ai:posture-10086.pub"), key.to_bytes()).expect("anchor key");
}

/// A 0700 scratch directory under `.local-runs/` (never a tmpfs path).
fn scratch_dir() -> tempfile::TempDir {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/posture_10086");
    std::fs::create_dir_all(&root).expect("scratch");
    let mut b = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        b.permissions(std::fs::Permissions::from_mode(0o700));
    }
    b.prefix("keys-").tempdir_in(&root).expect("tempdir")
}

/// A-4: every unusable anchor is a FAIL row naming `unanchored` and its
/// exact reason; a key directory holding an agent key is a PASS row.
#[test]
fn unanchored_is_a_failing_posture_row_10086() {
    let dir = scratch_dir();
    let missing = dir.path().join("absent");
    let row = row_from(&TrustAnchor::load_dir(&missing));
    assert!(!row.pass, "{row:?}");
    assert_eq!(
        row.actual,
        format!(
            "unanchored: key directory {} does not exist",
            missing.display()
        ),
        "{row:?}"
    );
    assert!(!row.remediation.is_empty(), "{row:?}");
    let row = row_from(&TrustAnchor::load_dir(dir.path()));
    assert!(!row.pass, "{row:?}");
    assert_eq!(
        row.actual,
        format!(
            "unanchored: key directory {} holds no public key",
            dir.path().display()
        ),
        "{row:?}"
    );
    seed_anchor_key(dir.path());
    let row = row_from(&TrustAnchor::load_dir(dir.path()));
    assert!(row.pass, "{row:?}");
    assert_eq!(
        row.actual,
        format!("anchored at {} (1 key(s))", dir.path().display()),
        "{row:?}"
    );
}

/// A-4 through `evaluate`: the hardened env with its key directory
/// emptied of keys FAILs exactly this row, and `all_pass` is false.
#[test]
fn evaluate_fails_the_anchor_row_when_the_key_dir_has_no_key_10086() {
    if crate::config::run_env_isolated_child_or_spawn(
        "enterprise_federation_posture::row_attest_anchor::tests::evaluate_fails_the_anchor_row_when_the_key_dir_has_no_key_10086",
    ) {
        return;
    }
    let _g = env_lock();
    unsafe { clear_all() };
    let _cleanup = EnvGuard;
    let _fp_file = set_fully_hardened_env();
    assert!(
        find(&evaluate(&AppConfig::default()), CONTROL).pass,
        "control"
    );
    let dir = scratch_dir();
    unsafe {
        std::env::set_var(crate::identity::keypair::KEY_DIR_ENV, dir.path());
    }
    let checks = evaluate(&AppConfig::default());
    let c = find(&checks, CONTROL);
    assert!(!c.pass, "{c:?}");
    assert!(c.actual.starts_with("unanchored: "), "{c:?}");
    assert!(!all_pass(&checks));
}
