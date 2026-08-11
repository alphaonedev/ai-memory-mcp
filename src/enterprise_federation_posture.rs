// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 §5.3 — the certified ENTERPRISE-FEDERATION posture.
//!
//! Ruling: `docs/audit/3x7-v1-cutline-ruling-2026-08-01.md` §5.3
//! "Required enterprise posture (concrete, machine-checked)":
//!
//! > Ship as a checked-in profile the daemon **validates and refuses to
//! > boot against**, with a boot banner echoing the *effective* posture.
//! > Prose checklists are unfalsifiable; a non-zero exit is falsifiable.
//!
//! and §5.4(2): "`ai-memory doctor --posture enterprise-federation` —
//! exits non-zero on any deviation of the running process."
//!
//! This module is the SINGLE SOURCE OF TRUTH both consumers share:
//!
//! - `ai-memory doctor --posture enterprise-federation`
//!   ([`crate::cli::doctor::run_posture`]) calls [`evaluate`] read-only
//!   and renders PASS/FAIL per requirement with exact remediation.
//! - The opt-in boot-refusing gate ([`enforce_at_boot_pre_runtime`]),
//!   consulted from the binary's synchronous pre-runtime `fn main()`
//!   phase (the same #1889/#2386 contract as
//!   [`crate::security_profile::enforce_at_boot_pre_runtime`]), refuses
//!   to boot when [`evaluate`] reports ANY failing control.
//!
//! ## NO NEW KNOB-LIST SSOT
//!
//! The certified posture is the UNION of:
//!
//! 1. The existing 17-knob `asi-hard` hardened set
//!    ([`crate::security_profile::KNOBS`], reused via
//!    [`crate::security_profile::is_asi_hard`] +
//!    [`crate::security_profile::asi_hard_below_floor`] — no knob name
//!    or floor value is re-declared here).
//! 2. A SMALL set of federation-certification-specific additions the
//!    ruling names that are NOT part of the generic `asi-hard` set
//!    (peer enrollment / per-message sig / nonce / push-namespace-scope
//!    / governance permissions mode / governance fail-open / trust
//!    domain / peer fingerprints / peer attestation JSON+glob shape /
//!    the two "must be UNSET" federation trust bypasses / at-rest
//!    encryption). Every env-var-name literal below is a named `ENV_*`
//!    const imported from its ONE existing declaration site — none are
//!    redeclared here.
//!
//! ## Ruling-vs-code reconciliation (quoted, so the drift is auditable)
//!
//! The ruling's §5.3 code block writes two knob names that do not exist
//! anywhere in `src/` verbatim; both are reconciled here to the real
//! SSOT rather than invented as new dead env vars:
//!
//! - `AI_MEMORY_FED_PERMISSIONS_MODE=enforce` — no `AI_MEMORY_FED_*`
//!   permissions-mode knob exists. The real K3/K9 governance gate is
//!   `AI_MEMORY_PERMISSIONS_MODE` (CLAUDE.md env-table row #10,
//!   `crate::config::AppConfig::effective_permissions_mode`), which
//!   this module checks resolves to [`crate::config::PermissionsMode::Enforce`].
//! - `AI_MEMORY_FED_GOVERNANCE_FAIL_OPEN_ON_ERROR=0` — no `FED_`-prefixed
//!   variant exists. The real knob is
//!   `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` (env-table row #39,
//!   [`crate::daemon_runtime::governance_fail_open_on_error`]), checked
//!   here directly.

use crate::config::{AppConfig, PermissionsMode};
use crate::federation::peer_attestation::{PEER_ATTESTATION_ENV, PeerScope};
use std::collections::HashMap;

/// The one certified posture name this module (and `doctor --posture`)
/// recognises. Additional certified postures would each get their own
/// name here — deliberately not a free-form string so a typo in
/// `--posture` is a loud "unknown posture" refusal, not a silent no-op.
pub const POSTURE_ENTERPRISE_FEDERATION: &str = "enterprise-federation";

/// Opt-in boot-refusing gate (§5.3 "validates and refuses to boot
/// against"). Default `false` — byte-identical legacy boot for every
/// deployment that has not opted into enterprise-federation
/// certification. Mirrors the truthy grammar + `AI_MEMORY_REQUIRE_*`
/// naming convention of the existing K2-style require-mode gates
/// (`AI_MEMORY_REQUIRE_WITNESS`, `AI_MEMORY_REQUIRE_ROLLBACK_CHECK`, …).
pub const ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE: &str =
    "AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE";

/// One §5.3 requirement's evaluated outcome.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PostureCheck {
    /// Short stable identifier for the control (also the doctor report
    /// line label).
    pub control: String,
    /// The required value/state per §5.3.
    pub required: String,
    /// The RESOLVED value/state observed in THIS process.
    pub actual: String,
    /// Whether `actual` satisfies `required`.
    pub pass: bool,
    /// Exact remediation — what to change to clear a FAIL. Empty on a
    /// PASS.
    pub remediation: String,
}

/// Shared "actual" rendering for an unset default-ON `AI_MEMORY_FED_REQUIRE_*`
/// env (checks #3-#6) — hoisted to a named const per the pm-v3.1
/// hardcoded-literal-duplication gate (repeated on >= 3 production sites).
const MSG_UNSET_DEFAULTS_STRICT: &str = "(unset — defaults strict)";

fn check(
    control: &str,
    required: &str,
    actual: String,
    pass: bool,
    remediation: &str,
) -> PostureCheck {
    PostureCheck {
        control: control.to_string(),
        required: required.to_string(),
        actual,
        pass,
        remediation: if pass {
            String::new()
        } else {
            remediation.to_string()
        },
    }
}

/// The house truthy grammar (`1`/`true`/`yes`/`on`, case-insensitive,
/// trimmed) shared by every `AI_MEMORY_*` boolean knob in this crate.
fn is_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// The house falsy grammar (`0`/`false`/`no`/`off`) used by the
/// default-ON `AI_MEMORY_FED_REQUIRE_*` knobs (env-table rows #29/#30):
/// UNSET or any non-falsy value stays strict; only an EXPLICIT falsy
/// token opts out.
fn is_falsy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// A default-ON `AI_MEMORY_FED_REQUIRE_*`-shaped env: compliant when
/// unset OR set to anything that is not an explicit falsy token.
fn default_on_env_compliant(env: &str) -> (bool, String) {
    match std::env::var(env) {
        Ok(v) if is_falsy(&v) => (false, v),
        Ok(v) => (true, v),
        Err(_) => (true, MSG_UNSET_DEFAULTS_STRICT.to_string()),
    }
}

/// A "must be UNSET" env: compliant when absent OR set to a non-truthy
/// value (mirrors `crate::tls::plaintext_peers_allowed`'s own
/// disposition — an unrecognised token never silently opens the hatch).
fn must_be_unset_env(env: &str) -> (bool, String) {
    match std::env::var(env) {
        Ok(v) if is_truthy(&v) => (false, v),
        Ok(v) => (true, format!("{v:?} (not truthy)")),
        Err(_) => (true, "(unset)".to_string()),
    }
}

/// Evaluate the RESOLVED process configuration against the certified
/// enterprise-federation posture. Pure / read-only: mutates no env var,
/// touches no database. Safe to call from any live process (the
/// `doctor` CLI, a running daemon's boot gate, or a test).
#[must_use]
pub fn evaluate(app_config: &AppConfig) -> Vec<PostureCheck> {
    let mut out = Vec::with_capacity(16);

    // ---- 1. asi-hard engaged --------------------------------------
    let asi_hard = crate::security_profile::is_asi_hard();
    out.push(check(
        "AI_MEMORY_SECURITY_PROFILE",
        "asi-hard",
        std::env::var(crate::security_profile::ENV_SECURITY_PROFILE)
            .unwrap_or_else(|_| "(unset -> standard)".to_string()),
        asi_hard,
        "set AI_MEMORY_SECURITY_PROFILE=asi-hard",
    ));

    // ---- 2. every asi-hard pinned knob (17) at its hard floor ------
    // Reuses `security_profile::KNOBS` via the read-only accessor — NO
    // knob name or floor value is re-declared here (see module docs).
    let below_floor = crate::security_profile::asi_hard_below_floor();
    let knob_count = crate::security_profile::pinned_knobs().len();
    out.push(check(
        "asi-hard pinned knobs",
        &format!("all {knob_count} at hard floor (security_profile::KNOBS)"),
        if below_floor.is_empty() {
            format!("{knob_count}/{knob_count} at floor")
        } else {
            below_floor
                .iter()
                .map(|(env, current, hard)| format!("{env}={current:?} (required {hard:?})"))
                .collect::<Vec<_>>()
                .join("; ")
        },
        below_floor.is_empty(),
        "remove the override(s) named in `actual` (asi-hard pins them) or raise each to its \
         hard floor; see `src/security_profile.rs::KNOBS`",
    ));

    // ---- 3. AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT ------------------
    out.push(check(
        crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
        "not explicitly disabled (peer enrollment required)",
        std::env::var(crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV)
            .unwrap_or_else(|_| MSG_UNSET_DEFAULTS_STRICT.to_string()),
        crate::handlers::federation_signing_check::require_peer_enrollment_enabled(),
        "unset AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT or set it to 1",
    ));

    // ---- 4. AI_MEMORY_FED_REQUIRE_SIG ------------------------------
    let (sig_ok, sig_actual) =
        default_on_env_compliant(crate::federation::signing::REQUIRE_SIG_ENV);
    out.push(check(
        crate::federation::signing::REQUIRE_SIG_ENV,
        "not explicitly disabled (per-message Ed25519 signatures required)",
        sig_actual,
        sig_ok,
        "unset AI_MEMORY_FED_REQUIRE_SIG or set it to 1",
    ));

    // ---- 5. AI_MEMORY_FED_REQUIRE_NONCE -----------------------------
    let (nonce_ok, nonce_actual) =
        default_on_env_compliant(crate::federation::signing::REQUIRE_NONCE_ENV);
    out.push(check(
        crate::federation::signing::REQUIRE_NONCE_ENV,
        "not explicitly disabled (per-message nonce freshness required)",
        nonce_actual,
        nonce_ok,
        "unset AI_MEMORY_FED_REQUIRE_NONCE or set it to 1",
    ));

    // ---- 6. AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE -------------
    out.push(check(
        crate::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
        "not explicitly disabled (inbound-write namespace confinement required)",
        std::env::var(crate::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV)
            .unwrap_or_else(|_| MSG_UNSET_DEFAULTS_STRICT.to_string()),
        crate::federation::receive_auth::require_push_namespace_scope_enabled(),
        "unset AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE or set it to 1",
    ));

    // ---- 7. AI_MEMORY_PERMISSIONS_MODE=enforce ---------------------
    // Ruling §5.3 literal `AI_MEMORY_FED_PERMISSIONS_MODE=enforce`
    // reconciled to the real K3/K9 governance gate (see module docs).
    let mode = app_config.effective_permissions_mode();
    out.push(check(
        "AI_MEMORY_PERMISSIONS_MODE (ruling: AI_MEMORY_FED_PERMISSIONS_MODE)",
        "enforce",
        mode.as_str().to_string(),
        mode == PermissionsMode::Enforce,
        "set AI_MEMORY_PERMISSIONS_MODE=enforce (or [permissions].mode = \"enforce\")",
    ));

    // ---- 8. AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=0 --------------
    // Ruling §5.3 literal `AI_MEMORY_FED_GOVERNANCE_FAIL_OPEN_ON_ERROR=0`
    // reconciled to the real knob (see module docs).
    let fail_open = crate::daemon_runtime::governance_fail_open_on_error();
    out.push(check(
        crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN,
        "0 (fail-CLOSED on governance rule-consultation error)",
        std::env::var(crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN)
            .unwrap_or_else(|_| "(unset -> 0)".to_string()),
        !fail_open,
        "unset AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR or set it to 0",
    ));

    // ---- 9. AI_MEMORY_FED_TRUST_DOMAIN=<set> -----------------------
    let trust_domain = std::env::var(crate::federation::identity::trust_bundle::TRUST_DOMAIN_ENV)
        .unwrap_or_default();
    out.push(check(
        crate::federation::identity::trust_bundle::TRUST_DOMAIN_ENV,
        "<set> (scopes the trust bundle to one fleet)",
        if trust_domain.trim().is_empty() {
            "(unset)".to_string()
        } else {
            trust_domain.clone()
        },
        !trust_domain.trim().is_empty(),
        "set AI_MEMORY_FED_TRUST_DOMAIN to this deployment's fleet identifier",
    ));

    // ---- 10. AI_MEMORY_FED_PEER_FINGERPRINTS=<set> -----------------
    let fp_path = std::env::var(crate::tls::FED_PEER_FINGERPRINTS_ENV).unwrap_or_default();
    let fp_set = !fp_path.trim().is_empty();
    let fp_readable = fp_set && std::path::Path::new(fp_path.trim()).is_file();
    out.push(check(
        crate::tls::FED_PEER_FINGERPRINTS_ENV,
        "<set> to a readable peer server-cert pin file",
        if !fp_set {
            "(unset)".to_string()
        } else if fp_readable {
            fp_path.clone()
        } else {
            format!("{fp_path} (not a readable file)")
        },
        fp_readable,
        "set AI_MEMORY_FED_PEER_FINGERPRINTS to a `<host> <sha256-hex>` pin file (#1678)",
    ));

    // ---- 11 + 12. AI_MEMORY_FED_PEER_ATTESTATION -------------------
    let attestation_raw = std::env::var(PEER_ATTESTATION_ENV).unwrap_or_default();
    let attestation_set = !attestation_raw.trim().is_empty();
    let parsed: Option<HashMap<String, PeerScope>> = if attestation_set {
        serde_json::from_str(&attestation_raw).ok()
    } else {
        None
    };
    out.push(check(
        PEER_ATTESTATION_ENV,
        "<set>; valid JSON (MALFORMED must refuse, never silently fall back)",
        if !attestation_set {
            "(unset)".to_string()
        } else if parsed.is_some() {
            format!("valid JSON, {} peer(s) enrolled", parsed.as_ref().map(HashMap::len).unwrap_or(0))
        } else {
            "PRESENT BUT MALFORMED JSON".to_string()
        },
        attestation_set && parsed.is_some(),
        "set AI_MEMORY_FED_PEER_ATTESTATION to valid JSON per \
         `PeerAttestationConfig::from_env` (peer-id -> {allowed_sender_agent_ids, allowed_namespaces})",
    ));
    let allow_all_globs: Vec<String> = parsed
        .as_ref()
        .map(|peers| {
            peers
                .iter()
                .filter(|(_, scope)| scope.allowed_namespaces.iter().any(|p| p == "**"))
                .map(|(peer_id, _)| peer_id.clone())
                .collect()
        })
        .unwrap_or_default();
    out.push(check(
        &format!("{PEER_ATTESTATION_ENV} (no `**` allow-all glob)"),
        "no peer scope's allowed_namespaces contains a literal `**`",
        if !attestation_set {
            "(unset — nothing to check)".to_string()
        } else if parsed.is_none() {
            "(malformed JSON — nothing to check)".to_string()
        } else if allow_all_globs.is_empty() {
            "none".to_string()
        } else {
            format!("`**` on peer(s): {}", allow_all_globs.join(", "))
        },
        attestation_set && parsed.is_some() && allow_all_globs.is_empty(),
        "replace the `**` allow-all glob with an explicit per-namespace allowlist for the \
         named peer(s) — enterprise-federation confinement forbids a deliberate allow-all scope",
    ));

    // ---- 13. AI_MEMORY_FED_SYNC_TRUST_PEER — MUST BE UNSET ---------
    let (sync_trust_ok, sync_trust_actual) =
        must_be_unset_env(crate::federation::peer_attestation::SYNC_TRUST_PEER_ENV);
    out.push(check(
        crate::federation::peer_attestation::SYNC_TRUST_PEER_ENV,
        "UNSET (or non-truthy)",
        sync_trust_actual,
        sync_trust_ok,
        "unset AI_MEMORY_FED_SYNC_TRUST_PEER",
    ));

    // ---- 14. AI_MEMORY_FED_TRUST_BODY_AGENT_ID — MUST BE UNSET -----
    let (trust_body_ok, trust_body_actual) =
        must_be_unset_env(crate::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV);
    out.push(check(
        crate::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
        "UNSET (or non-truthy)",
        trust_body_actual,
        trust_body_ok,
        "unset AI_MEMORY_FED_TRUST_BODY_AGENT_ID",
    ));

    // ---- 15. AI_MEMORY_ENCRYPT_AT_REST=1 (sqlcipher build) ---------
    let sqlcipher_build = crate::build_features::has_feature("sqlcipher");
    let encrypt_env_truthy = crate::encryption::encryption_enabled(None);
    out.push(check(
        crate::encryption::ENV_ENCRYPT_AT_REST,
        "1, on a binary built with --features sqlcipher",
        format!(
            "env={} sqlcipher_build={sqlcipher_build}",
            std::env::var(crate::encryption::ENV_ENCRYPT_AT_REST)
                .unwrap_or_else(|_| "(unset)".to_string())
        ),
        sqlcipher_build && encrypt_env_truthy,
        "rebuild with --features sqlcipher AND set AI_MEMORY_ENCRYPT_AT_REST=1 \
         (or [encryption].at_rest = true)",
    ));

    // ---- 16. peer URLs https-only ------------------------------------
    // Same underlying knob as one of the 17 asi-hard pins (#154) —
    // named separately here because §5.3 calls it out as its own
    // enumerated requirement ("peer URLs: https:// only").
    let plaintext_allowed = crate::tls::plaintext_peers_allowed();
    out.push(check(
        &format!(
            "{} (https-only peers)",
            crate::tls::FED_ALLOW_PLAINTEXT_PEERS_ENV
        ),
        "not truthy (the plaintext-peer refusal stays in force)",
        std::env::var(crate::tls::FED_ALLOW_PLAINTEXT_PEERS_ENV)
            .unwrap_or_else(|_| "(unset)".to_string()),
        !plaintext_allowed,
        "unset AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS — same knob as the asi-hard pin above; \
         every non-loopback peer URL must be https://",
    ));

    out
}

/// `true` iff every [`PostureCheck`] in `checks` passed.
#[must_use]
pub fn all_pass(checks: &[PostureCheck]) -> bool {
    checks.iter().all(|c| c.pass)
}

/// `true` when the operator has opted into the boot-refusing
/// enterprise-federation posture gate.
#[must_use]
pub fn enterprise_federation_posture_required() -> bool {
    std::env::var(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE)
        .map(|v| is_truthy(&v))
        .unwrap_or(false)
}

/// Pre-runtime boot gate (§5.3 "validates and refuses to boot
/// against"). No-op (`Ok(())`, byte-identical legacy boot) unless
/// [`ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE`] is truthy.
///
/// MUST be called from the SAME synchronous, still-single-threaded
/// pre-runtime phase of the binary's `fn main()` as
/// `security_profile::enforce_at_boot_pre_runtime` (#1889/#2386) —
/// AFTER it, so the asi-hard pins it may have applied are already
/// reflected in the environment this function reads. This function
/// itself only READS the environment ([`evaluate`] is pure); it never
/// calls `std::env::set_var`, so — unlike `security_profile`'s pin step
/// — it would in fact be safe to call from async context too, but is
/// kept in the pre-runtime phase for a single boot-refusal call site.
///
/// # Errors
/// Returns an aggregated error naming EVERY failing [`PostureCheck`]
/// (not merely the first) — an operator standing up a certified
/// deployment gets the complete remediation list in one refusal
/// instead of a fix-one-fail-again loop.
pub fn enforce_at_boot_pre_runtime(app_config: &AppConfig) -> anyhow::Result<()> {
    if !enterprise_federation_posture_required() {
        return Ok(());
    }
    let checks = evaluate(app_config);
    let failing: Vec<&PostureCheck> = checks.iter().filter(|c| !c.pass).collect();
    if failing.is_empty() {
        return Ok(());
    }
    let mut msg = format!(
        "enterprise-federation certified posture (3x7 ruling §5.3, \
         docs/audit/3x7-v1-cutline-ruling-2026-08-01.md) refuses to boot — \
         {} required control(s) missing or below floor:\n",
        failing.len()
    );
    for c in &failing {
        msg.push_str(&format!(
            "  - {}: required {:?}, actual {:?}. Fix: {}\n",
            c.control, c.required, c.actual, c.remediation
        ));
    }
    msg.push_str(&format!(
        "Run `ai-memory doctor --posture {POSTURE_ENTERPRISE_FEDERATION}` for the full report, \
         or unset {ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE} to boot without this cert gate."
    ));
    anyhow::bail!(msg);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every env var this module (or the `asi-hard` KNOBS it reuses)
    /// reads or pins, for test isolation. Delegates the 17 `asi-hard`
    /// knobs + the profile selector to `security_profile::pinned_knobs`
    /// / `ENV_SECURITY_PROFILE` rather than re-listing them (single
    /// source of truth even inside the test cleanup).
    const FED_ENV_VARS: &[&str] = &[
        crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
        crate::federation::signing::REQUIRE_SIG_ENV,
        crate::federation::signing::REQUIRE_NONCE_ENV,
        crate::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
        "AI_MEMORY_PERMISSIONS_MODE",
        crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN,
        crate::federation::identity::trust_bundle::TRUST_DOMAIN_ENV,
        crate::tls::FED_PEER_FINGERPRINTS_ENV,
        PEER_ATTESTATION_ENV,
        crate::federation::peer_attestation::SYNC_TRUST_PEER_ENV,
        crate::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
        crate::encryption::ENV_ENCRYPT_AT_REST,
        crate::tls::FED_ALLOW_PLAINTEXT_PEERS_ENV,
        ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
    ];

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::config::test_env_lock()
    }

    /// # Safety
    /// Caller must hold [`env_lock`].
    unsafe fn clear_all() {
        unsafe {
            std::env::remove_var(crate::security_profile::ENV_SECURITY_PROFILE);
            for (env, _) in crate::security_profile::pinned_knobs() {
                std::env::remove_var(env);
            }
            for env in FED_ENV_VARS {
                std::env::remove_var(env);
            }
        }
    }

    /// RAII guard mirroring `security_profile::tests::KnobsGuard` — a
    /// mid-test panic still restores the baseline for whatever `--lib`
    /// test runs next in the same process.
    struct EnvGuard;
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: constructed only while the caller holds `env_lock()`.
            unsafe { clear_all() };
        }
    }

    fn find<'a>(checks: &'a [PostureCheck], control_prefix: &str) -> &'a PostureCheck {
        checks
            .iter()
            .find(|c| c.control.starts_with(control_prefix))
            .unwrap_or_else(|| panic!("no check with control prefix {control_prefix:?}"))
    }

    /// Sets every certified-posture env var to its compliant value
    /// (asi-hard engaged + pinned via the real `enforce_at_boot`, plus
    /// every federation-specific addition). Does NOT — cannot — compile
    /// in the `sqlcipher` feature, so the at-rest-encryption check is
    /// asserted separately per the build's actual compiled features.
    ///
    /// Returns the peer-fingerprints tempfile so it stays alive for the
    /// duration of the caller's assertions (dropped = file removed).
    fn set_fully_hardened_env() -> tempfile::NamedTempFile {
        unsafe {
            std::env::set_var(crate::security_profile::ENV_SECURITY_PROFILE, "asi-hard");
        }
        // Pins the 17 asi-hard knobs via the REAL enforcement fn — the
        // single source of truth for what "compliant" means for that set.
        crate::security_profile::enforce_at_boot().expect("asi-hard pins cleanly from a clean env");

        let fp_file = tempfile::NamedTempFile::new().expect("tempfile");
        std::fs::write(fp_file.path(), "example.org abc123\n").expect("write fp file");

        unsafe {
            std::env::set_var(TRUST_DOMAIN_ENV_FOR_TEST, "test-fleet");
            std::env::set_var(
                crate::tls::FED_PEER_FINGERPRINTS_ENV,
                fp_file.path().to_str().unwrap(),
            );
            std::env::set_var(
                PEER_ATTESTATION_ENV,
                r#"{"peer-1":{"allowed_namespaces":["public/*"]}}"#,
            );
            std::env::set_var(crate::encryption::ENV_ENCRYPT_AT_REST, "1");
        }
        // AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT / _SIG / _NONCE /
        // _PUSH_NAMESPACE_SCOPE / AI_MEMORY_PERMISSIONS_MODE /
        // AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR / _SYNC_TRUST_PEER /
        // _TRUST_BODY_AGENT_ID / _ALLOW_PLAINTEXT_PEERS are all
        // deliberately left UNSET — every one of them already defaults
        // to the certified-compliant state (see each check's
        // `default_on_env_compliant` / `must_be_unset_env` arm), which
        // is itself part of what this test proves.
        fp_file
    }

    // Alias so the const import above stays readable without a `use`
    // that would collide with the module's own `TRUST_DOMAIN_ENV`
    // re-export ambiguity across `crate::federation::identity::trust_bundle`.
    use crate::federation::identity::trust_bundle::TRUST_DOMAIN_ENV as TRUST_DOMAIN_ENV_FOR_TEST;

    #[test]
    fn fully_hardened_env_passes_every_check_except_possibly_sqlcipher_build() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();

        let app_config = AppConfig::default();
        let checks = evaluate(&app_config);

        let sqlcipher_compiled = crate::build_features::has_feature("sqlcipher");
        for c in &checks {
            let is_sqlcipher_check = c.control == crate::encryption::ENV_ENCRYPT_AT_REST;
            if is_sqlcipher_check && !sqlcipher_compiled {
                assert!(
                    !c.pass,
                    "encrypt-at-rest check must FAIL on a non-sqlcipher build even with the \
                     env var set — sqlcipher is not compiled in"
                );
                assert!(c.remediation.contains("sqlcipher"));
            } else {
                assert!(
                    c.pass,
                    "expected PASS for {:?}: required={:?} actual={:?} remediation={:?}",
                    c.control, c.required, c.actual, c.remediation
                );
            }
        }
        assert_eq!(
            all_pass(&checks),
            sqlcipher_compiled,
            "overall posture PASS must track whether sqlcipher is compiled in"
        );
    }

    #[test]
    fn asi_hard_not_engaged_fails_that_check() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let app_config = AppConfig::default();
        let checks = evaluate(&app_config);
        let c = find(&checks, "AI_MEMORY_SECURITY_PROFILE");
        assert!(!c.pass);
        assert!(c.remediation.contains("asi-hard"));
        assert!(!all_pass(&checks));
    }

    #[test]
    fn asi_hard_knob_below_floor_fails_that_check() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        // Loosen ONE of the 17 pinned knobs after the fact.
        unsafe {
            std::env::set_var("AI_MEMORY_SECRET_SCREEN_MODE", "off");
        }
        let app_config = AppConfig::default();
        let checks = evaluate(&app_config);
        let c = find(&checks, "asi-hard pinned knobs");
        assert!(!c.pass);
        assert!(c.actual.contains("AI_MEMORY_SECRET_SCREEN_MODE"));
        assert!(!all_pass(&checks));
    }

    #[test]
    fn peer_enrollment_explicitly_disabled_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(
                crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
                "0",
            );
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(
            &checks,
            crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
        );
        assert!(!c.pass);
        assert!(!all_pass(&checks));
    }

    #[test]
    fn require_sig_explicitly_disabled_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(crate::federation::signing::REQUIRE_SIG_ENV, "false");
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, crate::federation::signing::REQUIRE_SIG_ENV);
        assert!(!c.pass);
    }

    #[test]
    fn require_nonce_explicitly_disabled_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(crate::federation::signing::REQUIRE_NONCE_ENV, "off");
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, crate::federation::signing::REQUIRE_NONCE_ENV);
        assert!(!c.pass);
    }

    #[test]
    fn push_namespace_scope_explicitly_disabled_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(
                crate::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
                "0",
            );
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(
            &checks,
            crate::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
        );
        assert!(!c.pass);
    }

    #[test]
    fn permissions_mode_not_enforce_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var("AI_MEMORY_PERMISSIONS_MODE", "advisory");
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, "AI_MEMORY_PERMISSIONS_MODE");
        assert!(!c.pass);
        assert_eq!(c.actual, "advisory");
    }

    #[test]
    fn governance_fail_open_enabled_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN, "1");
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN);
        assert!(!c.pass);
    }

    #[test]
    fn trust_domain_unset_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::remove_var(TRUST_DOMAIN_ENV_FOR_TEST);
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, TRUST_DOMAIN_ENV_FOR_TEST);
        assert!(!c.pass);
    }

    #[test]
    fn peer_fingerprints_unset_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::remove_var(crate::tls::FED_PEER_FINGERPRINTS_ENV);
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, crate::tls::FED_PEER_FINGERPRINTS_ENV);
        assert!(!c.pass);
    }

    #[test]
    fn peer_fingerprints_pointing_at_missing_file_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(
                crate::tls::FED_PEER_FINGERPRINTS_ENV,
                "/nonexistent/does-not-exist.pins",
            );
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, crate::tls::FED_PEER_FINGERPRINTS_ENV);
        assert!(!c.pass);
    }

    #[test]
    fn peer_attestation_unset_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::remove_var(PEER_ATTESTATION_ENV);
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, PEER_ATTESTATION_ENV);
        assert!(!c.pass);
        assert!(!all_pass(&checks));
    }

    #[test]
    fn peer_attestation_malformed_json_fails_and_refuses_not_falls_back() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(PEER_ATTESTATION_ENV, "not json{{");
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, PEER_ATTESTATION_ENV);
        assert!(!c.pass);
        assert!(c.actual.contains("MALFORMED"));
        // The `**` glob check must ALSO fail-safe (cannot verify), not
        // silently pass because parsing failed.
        let glob_check = find(&checks, &format!("{PEER_ATTESTATION_ENV} (no"));
        assert!(!glob_check.pass);
    }

    #[test]
    fn peer_attestation_allow_all_glob_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(
                PEER_ATTESTATION_ENV,
                r#"{"peer-wide-open":{"allowed_namespaces":["**"]}}"#,
            );
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, &format!("{PEER_ATTESTATION_ENV} (no"));
        assert!(!c.pass);
        assert!(c.actual.contains("peer-wide-open"));
        // The presence+valid-JSON check itself must still PASS — this is
        // specifically the glob-shape requirement, not a parse failure.
        let presence_check = find(&checks, PEER_ATTESTATION_ENV);
        assert!(presence_check.pass);
    }

    #[test]
    fn sync_trust_peer_set_truthy_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(
                crate::federation::peer_attestation::SYNC_TRUST_PEER_ENV,
                "1",
            );
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(
            &checks,
            crate::federation::peer_attestation::SYNC_TRUST_PEER_ENV,
        );
        assert!(!c.pass);
    }

    #[test]
    fn trust_body_agent_id_set_truthy_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(
                crate::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
                "1",
            );
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(
            &checks,
            crate::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
        );
        assert!(!c.pass);
    }

    #[test]
    fn encrypt_at_rest_env_falsy_fails_even_on_sqlcipher_build() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(crate::encryption::ENV_ENCRYPT_AT_REST, "0");
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, crate::encryption::ENV_ENCRYPT_AT_REST);
        assert!(!c.pass);
    }

    #[test]
    fn plaintext_peers_hatch_open_fails() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(crate::tls::FED_ALLOW_PLAINTEXT_PEERS_ENV, "1");
        }
        let checks = evaluate(&AppConfig::default());
        // #2477's KNOB is ALSO one of the 17 asi-hard pins, so BOTH
        // the aggregate knobs row and the dedicated https-only row must
        // go red — never silently absorbed into only one.
        let knobs_row = find(&checks, "asi-hard pinned knobs");
        assert!(!knobs_row.pass);
        let https_row = find(&checks, crate::tls::FED_ALLOW_PLAINTEXT_PEERS_ENV);
        assert!(!https_row.pass);
        assert!(https_row.control.contains("https-only peers"));
    }

    // ------------------------------------------------------------------
    // Boot gate
    // ------------------------------------------------------------------

    #[test]
    fn boot_gate_is_a_noop_when_not_required() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        // Deliberately leave the posture unsatisfied AND the require
        // flag unset — must still boot (byte-identical legacy).
        let app_config = AppConfig::default();
        assert!(enforce_at_boot_pre_runtime(&app_config).is_ok());
    }

    #[test]
    fn boot_gate_refuses_when_required_and_posture_unsatisfied() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        unsafe {
            std::env::set_var(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE, "1");
        }
        let app_config = AppConfig::default();
        let err = enforce_at_boot_pre_runtime(&app_config).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("refuses to boot"));
        assert!(msg.contains("AI_MEMORY_SECURITY_PROFILE"));
    }

    #[test]
    fn boot_gate_passes_when_required_and_posture_satisfied_or_only_sqlcipher_missing() {
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE, "1");
        }
        let app_config = AppConfig::default();
        let result = enforce_at_boot_pre_runtime(&app_config);
        if crate::build_features::has_feature("sqlcipher") {
            assert!(result.is_ok(), "expected boot to proceed: {result:?}");
        } else {
            let err = result.unwrap_err();
            assert!(format!("{err}").contains("sqlcipher"));
        }
    }
}
