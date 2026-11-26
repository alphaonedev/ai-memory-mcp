// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10121 — the ONE definition of the certified enterprise-federation posture
//! environment for tests.
//!
//! Before #10121 the "fully hardened" environment was written twice: once in
//! `enterprise_federation_posture::tests::set_fully_hardened_env` and once by
//! hand in `cli::doctor::tests`. Check #23 (row-attestation trust anchor,
//! commit 44598c23f) seeded its key in the first copy only, so the doctor
//! proof test of GA standard 5 went red while the posture suite stayed green.
//! Every consumer now builds its environment through [`PostureEnv`], so a new
//! posture check turns every consumer red or green together.
//!
//! [`PostureEnv`] owns everything it creates (the peer-fingerprints file and
//! a private 0700 key directory) and restores every variable it touched to its
//! prior value on drop (class #8168). Its constructors take the crate-wide
//! env-lock guard, so a fixture cannot outlive the lock that serialises it.
//! The ratchet `doctor_holds_no_hand_rolled_posture_env` keeps a second copy
//! out of `src/cli/doctor.rs`.

use std::ffi::OsString;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::{MutexGuard, OnceLock};

use super::{
    ENV_PG_AT_REST_ATTESTED, ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE, PEER_ATTESTATION_ENV,
};
use crate::config::AppConfig;
use crate::identity::keypair::KEY_DIR_ENV;

/// Every env var the posture module (beyond the `asi-hard` knobs) reads, so a
/// fixture starts from, and restores, a known state. The 22 `asi-hard` knobs
/// and the profile selector come from `security_profile` (single source).
pub(super) const FED_ENV_VARS: &[&str] = &[
    crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
    crate::handlers::federation_signing_check::ALLOW_UNENROLLED_PEERS_ENV,
    crate::federation::signing::REQUIRE_SIG_ENV,
    crate::federation::signing::REQUIRE_NONCE_ENV,
    crate::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
    crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
    AppConfig::ENV_PERMISSIONS_MODE,
    crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN,
    crate::federation::identity::trust_bundle::TRUST_DOMAIN_ENV,
    crate::tls::FED_PEER_FINGERPRINTS_ENV,
    PEER_ATTESTATION_ENV,
    crate::federation::peer_attestation::SYNC_TRUST_PEER_ENV,
    crate::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
    crate::encryption::ENV_ENCRYPT_AT_REST,
    crate::tls::FED_ALLOW_PLAINTEXT_PEERS_ENV,
    ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
    // #2954 — check #19 append-only spine flag.
    crate::config::ENV_APPEND_ONLY,
    // #3061 — check #15 resolves the store URL through these two channels and,
    // on a postgres:// DSN, reads the pg at-rest attestation.
    crate::store_url::STORE_URL_ENV,
    crate::store_url::STORE_URL_FILE_ENV,
    ENV_PG_AT_REST_ATTESTED,
    // #2991 check #20 — the escalate-producer approver-key enrollment.
    crate::approvals::signed::APPROVER_PUBKEYS_ENV,
    // #3199 check #22 — the env channel of the operator public key.
    "AI_MEMORY_OPERATOR_PUBKEY",
];

/// File name of the operator public key restore verifies backups against.
pub(super) const OPERATOR_PUBKEY_FILE: &str = "operator.key.pub";

/// Every posture variable: the profile selector, its pinned knobs and
/// [`FED_ENV_VARS`]. The key-directory override is not one of them (the
/// per-process test key sandbox owns it); [`PostureEnv::fully_hardened`]
/// snapshots and restores it separately.
pub(super) fn posture_env_vars() -> Vec<&'static str> {
    let mut vars = vec![crate::security_profile::ENV_SECURITY_PROFILE];
    vars.extend(
        crate::security_profile::pinned_knobs()
            .iter()
            .map(|(env, _)| *env),
    );
    vars.extend_from_slice(FED_ENV_VARS);
    vars
}

/// Remove every posture variable.
///
/// # Safety
/// The caller holds `crate::config::test_env_lock()`.
pub(super) unsafe fn clear_posture_env() {
    for env in posture_env_vars() {
        // SAFETY: the caller holds the crate-wide env lock.
        unsafe { std::env::remove_var(env) };
    }
}

/// A deterministic, valid base64 Ed25519 approver public key (#2991 check
/// #20, #3199 check #22). Fixed seed: stable and never RNG-dependent.
pub(super) fn approver_pubkey_b64() -> String {
    use base64::Engine as _;
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())
}

/// #2954 check #19 — keeps the installed daemon-audit-key directory alive for
/// the whole (env-isolated child) process. The key install is process-global
/// and first-install-wins, so it is the one part a drop cannot restore.
static POSTURE_AUDIT_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();

/// What a [`PostureEnv`] created and must keep alive while it lives.
struct HardenedParts {
    /// Held only so the fingerprints file outlives the fixture's assertions.
    _fp_file: tempfile::NamedTempFile,
    key_dir: tempfile::TempDir,
}

/// The posture environment of one test: the bare env or the certified,
/// fully hardened one. Restores every variable it touched on drop.
#[must_use = "the environment is restored when this value drops"]
pub(crate) struct PostureEnv<'lock> {
    saved: Vec<(&'static str, Option<OsString>)>,
    hardened: Option<HardenedParts>,
    _lock: PhantomData<&'lock MutexGuard<'static, ()>>,
}

impl<'lock> PostureEnv<'lock> {
    /// Every posture variable unset.
    pub(crate) fn bare(_lock: &'lock MutexGuard<'static, ()>) -> Self {
        // SAFETY: `_lock` proves the caller holds the crate-wide env lock for
        // at least `'lock`, which outlives the returned value.
        unsafe { Self::bare_unchecked() }
    }

    /// The certified enterprise-federation posture: `asi-hard` pinned through
    /// the real `enforce_at_boot`, every federation addition set, and a
    /// private key directory holding the operator public key (check #22) and
    /// one agent public key (check #23). Only the at-rest-encryption row
    /// depends on the build (`--features sqlcipher`).
    pub(crate) fn fully_hardened(_lock: &'lock MutexGuard<'static, ()>) -> Self {
        // SAFETY: as in `bare`.
        unsafe { Self::fully_hardened_unchecked() }
    }

    /// # Safety
    /// The caller holds `crate::config::test_env_lock()` until the value drops.
    pub(super) unsafe fn bare_unchecked() -> Self {
        let saved = snapshot(posture_env_vars());
        // SAFETY: forwarded caller contract.
        unsafe { clear_posture_env() };
        Self {
            saved,
            hardened: None,
            _lock: PhantomData,
        }
    }

    /// # Safety
    /// The caller holds `crate::config::test_env_lock()` until the value drops.
    pub(super) unsafe fn fully_hardened_unchecked() -> Self {
        let mut vars = posture_env_vars();
        vars.push(KEY_DIR_ENV);
        let saved = snapshot(vars);
        // SAFETY: forwarded caller contract.
        unsafe { clear_posture_env() };
        // From here on a panic still restores `saved` through `Drop`.
        let mut env = Self {
            saved,
            hardened: None,
            _lock: PhantomData,
        };
        // SAFETY: forwarded caller contract.
        unsafe { set_var(crate::security_profile::ENV_SECURITY_PROFILE, "asi-hard") };
        // Pins the asi-hard knobs via the REAL enforcement fn.
        crate::security_profile::enforce_at_boot().expect("asi-hard pins cleanly from a clean env");

        let fp_file = tempfile::NamedTempFile::new().expect("fingerprints file");
        std::fs::write(fp_file.path(), "example.org abc123\n").expect("write fingerprints");
        // Owner-only from creation (`tempfile::Builder` mode 0700), so the
        // #3198 key-directory check passes under umask 022 and 0002 alike.
        let key_dir = crate::identity::test_key_dir::private_tempdir();
        let pubkey = approver_pubkey_b64();
        std::fs::write(key_dir.path().join(OPERATOR_PUBKEY_FILE), &pubkey).expect("operator key");
        super::row_attest_anchor::seed_anchor_key(key_dir.path()); // #10086 check #23
        let fp_path = fp_file.path().to_str().expect("utf-8 temp path").to_owned();
        let settings: [(&str, &std::ffi::OsStr); 8] = [
            (
                crate::federation::identity::trust_bundle::TRUST_DOMAIN_ENV,
                "test-fleet".as_ref(),
            ),
            (crate::tls::FED_PEER_FINGERPRINTS_ENV, fp_path.as_ref()),
            (
                PEER_ATTESTATION_ENV,
                r#"{"peer-1":{"allowed_namespaces":["public/*"]}}"#.as_ref(),
            ),
            (crate::encryption::ENV_ENCRYPT_AT_REST, "1".as_ref()),
            // #2911 check #17 — the boot-refusal env defaults OFF; unset FAILs.
            (ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE, "1".as_ref()),
            // #2954 check #19 — arm the append-only audit spine.
            (crate::config::ENV_APPEND_ONLY, "1".as_ref()),
            // #2991 check #20 — a SATISFIABLE signed-approval gate.
            (
                crate::approvals::signed::APPROVER_PUBKEYS_ENV,
                pubkey.as_ref(),
            ),
            (KEY_DIR_ENV, key_dir.path().as_os_str()),
        ];
        for (name, value) in settings {
            // SAFETY: forwarded caller contract.
            unsafe { set_var(name, value) };
        }
        env.hardened = Some(HardenedParts {
            _fp_file: fp_file,
            key_dir,
        });
        // #2954 check #19 — a process-wide daemon audit signing key, so the
        // append-only leaves would be SIGNED.
        POSTURE_AUDIT_DIR.get_or_init(|| {
            let dir = tempfile::Builder::new()
                .prefix("ef-posture-audit-")
                .tempdir()
                .expect("audit tempdir");
            let signing = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            crate::governance::audit::init(dir.path(), Some(signing)).expect("install audit key");
            dir
        });
        // The remaining federation knobs stay UNSET on purpose: each already
        // defaults to the certified-compliant state, which is part of what a
        // passing posture proves.
        env
    }

    /// The fixture's key directory, or `None` for a bare env.
    pub(crate) fn key_dir(&self) -> Option<&Path> {
        self.hardened.as_ref().map(|h| h.key_dir.path())
    }

    /// Remove every agent public key (each `.pub` but the operator key) from
    /// the fixture's key directory, so check #23 loads unanchored while check
    /// #22 keeps its operator key. Returns how many keys it removed.
    pub(crate) fn remove_agent_keys(&self) -> usize {
        let Some(dir) = self.key_dir() else {
            return 0;
        };
        let mut removed = 0;
        for entry in std::fs::read_dir(dir).expect("read fixture key dir") {
            let path = entry.expect("key dir entry").path();
            let is_agent_key = path.extension().is_some_and(|e| e == "pub")
                && path.file_name().is_some_and(|n| n != OPERATOR_PUBKEY_FILE);
            if is_agent_key {
                std::fs::remove_file(&path).expect("remove agent key");
                removed += 1;
            }
        }
        removed
    }
}

impl Drop for PostureEnv<'_> {
    fn drop(&mut self) {
        for (name, prior) in &self.saved {
            // SAFETY: the value never outlives the env lock its constructor
            // was given (or, for the `_unchecked` constructors, promised).
            unsafe {
                match prior {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

fn snapshot(vars: Vec<&'static str>) -> Vec<(&'static str, Option<OsString>)> {
    vars.into_iter().map(|v| (v, std::env::var_os(v))).collect()
}

/// # Safety
/// The caller holds `crate::config::test_env_lock()`.
unsafe fn set_var(name: &str, value: impl AsRef<std::ffi::OsStr>) {
    // SAFETY: forwarded caller contract.
    unsafe { std::env::set_var(name, value) };
}
