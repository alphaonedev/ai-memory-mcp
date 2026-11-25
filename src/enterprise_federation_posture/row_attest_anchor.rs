// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10086 A-4 — check #23 of the certified enterprise-federation posture: the
//! row-attestation verifier has an out-of-database trust anchor.
//!
//! Split out of `enterprise_federation_posture.rs` under the QUAL-10
//! submodule-over-bump rule (the #3553 `synchronous.rs` precedent). The
//! predicate is `TrustAnchor::from_key_dir`, the one source
//! `row_attest::sqlite::verify_sqlite` takes its verifying keys from, so a
//! green row proves the verifier runs anchored. The row reads only the key
//! directory: it opens no database and needs no schema migration.

use super::{PostureCheck, check};
use crate::storage::row_attest::anchor::{AnchorLoad, TrustAnchor};

/// Control label of check #23 (the doctor report line).
pub(super) const CONTROL: &str = "row attestation trust anchor";

/// Check #23 over the deployment's key directory.
pub(super) fn check_row_attest_anchor() -> PostureCheck {
    row_from(&TrustAnchor::from_key_dir())
}

/// Render the row from `load`. `Unanchored` FAILs with its exact reason:
/// without an anchor no attestation signature can be checked, so the
/// hardened profile never treats such a store as verified.
fn row_from(load: &AnchorLoad) -> PostureCheck {
    let (pass, actual) = match load {
        AnchorLoad::Anchored(a) => (
            true,
            format!(
                "anchored at {} ({} key(s))",
                a.source().display(),
                a.fingerprints().len()
            ),
        ),
        AnchorLoad::Unanchored(why) => (false, format!("unanchored: {why}")),
    };
    check(
        CONTROL,
        "the key directory loads as the row-attestation trust anchor (anchored)",
        actual,
        pass,
        "provision the agent public keys in the key directory (AI_MEMORY_KEY_DIR or the default \
         key directory) so row attestations verify against an out-of-database anchor",
    )
}

/// Test fixture for `set_fully_hardened_env`: one agent public key in the
/// key directory, so check #23 loads anchored.
#[cfg(test)]
pub(super) fn seed_anchor_key(dir: &std::path::Path) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]).verifying_key();
    std::fs::write(dir.join("ai:posture-10086.pub"), key.to_bytes()).expect("anchor key");
}

#[cfg(test)]
mod tests {
    use super::super::tests::{EnvGuard, clear_all, env_lock, find, set_fully_hardened_env};
    use super::super::{all_pass, evaluate};
    use super::{CONTROL, row_from, seed_anchor_key};
    use crate::config::AppConfig;
    use crate::storage::row_attest::anchor::TrustAnchor;

    /// A 0700 scratch directory under `.local-runs/` (never a tmpfs path).
    fn scratch_dir() -> tempfile::TempDir {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/posture_10086");
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
}
