// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3199 — check #22 of the certified enterprise-federation posture: backup
//! manifests verify against the operator key.
//!
//! Split out of `enterprise_federation_posture.rs` under the QUAL-10
//! submodule-over-bump rule (the #3553 `synchronous.rs` precedent): the parent
//! keeps only the `out.push(...)` wiring that must sit in
//! `evaluate_with_live`'s ordered check sequence; the row and its test live
//! here. The predicate itself is `crate::cli::backup::signing_posture`, the
//! same resolution `backup` and `restore` use, so a green row proves the
//! exact key `restore` will verify against.

use super::{PostureCheck, check};

/// Render the backup-manifest-signing posture row (check #22).
///
/// `backup` is SQLite-only, so a postgres node has nothing to check and the
/// row passes as `N/A`.
pub(super) fn check_backup_signing(backend_is_postgres: bool) -> PostureCheck {
    let (pass, actual) = crate::cli::backup::signing_posture(backend_is_postgres);
    check(
        "backup manifest signing",
        "operator public key resolves AND any local operator signing key matches it",
        actual,
        pass,
        "provision the operator public key (AI_MEMORY_OPERATOR_PUBKEY or operator.key.pub in \
         the key directory); a local operator.key must be its private half",
    )
}

#[cfg(test)]
mod tests {
    use super::super::tests::{EnvGuard, clear_all, env_lock, find, set_fully_hardened_env};
    use super::super::{all_pass, evaluate};
    use crate::config::AppConfig;

    /// #3199 check #22 — no operator public key: restore could not verify a
    /// signed backup, so the row FAILs.
    #[test]
    fn no_operator_pubkey_fails_backup_signing_check_22() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::backup_signing::tests::no_operator_pubkey_fails_backup_signing_check_22",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe { clear_all() };
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        let _no_pk = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, "backup manifest signing");
        assert!(!c.pass, "{c:?}");
        assert!(c.actual.contains("no operator public key"), "{c:?}");
        assert!(!all_pass(&checks));
    }
}
