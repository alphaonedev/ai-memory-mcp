// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10086 A-4 — check #23 of the certified enterprise-federation posture: the
//! row-attestation verifier has an out-of-database trust anchor.

/// Control label of check #23 (the doctor report line).
#[cfg(test)]
pub(super) const CONTROL: &str = "row attestation trust anchor";

#[cfg(test)]
mod tests {
    use super::super::tests::{EnvGuard, clear_all, env_lock, find, set_fully_hardened_env};
    use super::super::{all_pass, evaluate};
    use super::CONTROL;
    use crate::config::AppConfig;

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
        let dir = tempfile::tempdir().expect("tempdir");
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
