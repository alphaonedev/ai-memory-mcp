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
//! 1. The existing 21-knob `asi-hard` hardened set
//!    ([`crate::security_profile::KNOBS`], reused via
//!    [`crate::security_profile::is_asi_hard`] +
//!    [`crate::security_profile::asi_hard_below_floor`] — no knob name
//!    or floor value is re-declared here).
//! 2. A SMALL set of federation-certification-specific additions that
//!    are NOT part of the generic `asi-hard` set. Most are named by the
//!    §5.3 ruling (peer enrollment / per-message sig / nonce /
//!    push-namespace-scope / governance permissions mode / governance
//!    fail-open / trust domain / peer fingerprints / peer attestation
//!    JSON+glob shape / the two "must be UNSET" federation trust
//!    bypasses / at-rest encryption). THREE are BEYOND-RULING additions,
//!    not from the ruling: from #2911 items 1-2, the
//!    stale-governance-policy refusal (FED-RQ-03, check #18) and the
//!    boot-refusal env itself (check #17 — so `doctor --posture` cannot
//!    PASS a deployment whose daemon would not refuse boot on later
//!    drift); and from #2954, the append-only-audit-spine-armed pairing
//!    (check #19 — append-only spine ON *and* the daemon audit signing
//!    key armed, so a federation newer-wins supersede leaf is SIGNED, not
//!    unsigned theater). Every env-var-name literal below is a named
//!    `ENV_*` const imported from its ONE existing declaration site —
//!    none are redeclared here.
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
//!
//! And the inverse direction, recorded here so the ruling-vs-code delta
//! stays auditable BOTH ways: checks #17 (boot-refusal env
//! self-attestation) and #18 (`AI_MEMORY_FED_REQUIRE_POLICY_CURRENT`
//! not explicitly falsy) appear in NO §5.3 ruling code block — they are
//! BEYOND-RULING additions from #2911 items 1-2 (cert §2 doctor-caveat
//! remediation), not reconciliations of anything the ruling wrote.
//!
//! A third reconciliation, on the `**` allow-all-glob check (§5.3's "no
//! peer scope's `allowed_namespaces` contains a bare `**` allow-all
//! glob"): the check below matches ONLY the literal string `"**"`,
//! mirroring `crate::federation::peer_attestation`'s own `glob_match`,
//! for which a bare `"**"` is the SOLE unconditional match-any-namespace
//! token (#1902 — a bare `*` matches exactly one top-level segment, NOT
//! "everything", to avoid silently widening a `["*"]` allowlist to the
//! whole tree). A scoped pattern like `"team-x/**"` PASSES this check —
//! it is a deliberate, prefix-CONFINED allow-all under `team-x/`, not
//! the substrate-wide allow-all `§5.3` forbids, so flagging it would be
//! a false positive against a legitimate per-team wildcard scope.

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

/// Number of [`PostureCheck`]s [`evaluate`] returns. Pinned so a
/// dropped or added check is a loud test failure rather than a silent
/// `doctor --posture` shape change (#2911). #2954 raised it 18 → 19 (the
/// append-only-audit-spine-armed pairing, check #19) — a DELIBERATE, ratified
/// re-cert, not a silent drift.
pub const ENTERPRISE_FEDERATION_CHECK_COUNT: usize = 19;

/// `tracing` target for the §5.3 boot-banner rows
/// (`daemon_runtime::run`, the B2 fix — see module docs). Hoisted to a
/// named const (pm-v3.1 hardcoded-literal-duplication gate: the target
/// string is used at 3 call sites — one per PASS row, FAIL row, and the
/// closing ENGAGED summary) so the banner and any future consumer (e.g.
/// a `RUST_LOG` filter target) share one spelling.
pub const TRACING_TARGET: &str = "security.posture.enterprise_federation";

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

/// The RESOLVED security-posture token, for the #2923 pins-row `actual`.
///
/// Reuses [`crate::security_profile::SecurityPosture`] rather than
/// re-deriving a name from the raw env value. An UNRECOGNISED token is
/// a `resolve()` error (fail-loud at boot) which
/// [`crate::security_profile::is_asi_hard`] reads as NOT hardened, so it
/// renders as `unrecognised` — the row must never name a posture the
/// process does not actually have.
fn resolved_security_profile_label() -> &'static str {
    match crate::security_profile::SecurityPosture::resolve() {
        Ok(posture) => posture.as_str(),
        Err(_) => "unrecognised",
    }
}

/// Evaluate the RESOLVED process configuration against the certified
/// enterprise-federation posture. Pure / read-only: mutates no env var,
/// touches no database. Safe to call from any live process (the
/// `doctor` CLI, a running daemon's boot gate, or a test).
#[must_use]
pub fn evaluate(app_config: &AppConfig) -> Vec<PostureCheck> {
    let mut out = Vec::with_capacity(ENTERPRISE_FEDERATION_CHECK_COUNT);

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

    // ---- 2. every asi-hard pinned knob (21) at its hard floor ------
    // Reuses `security_profile::KNOBS` via the read-only accessor — NO
    // knob name or floor value is re-declared here (see module docs).
    //
    // #2923 — this row must never read as a SATISFIED hardened-floor
    // check when the pins are not in force. `asi_hard_below_floor()`
    // reports only knobs a HARDENED process would pin below their floor,
    // so under `standard` it is VACUOUSLY empty and the row rendered
    // `[PASS] … 21/21 at floor` for a deployment where not one knob is
    // pinned — false assurance in committed, publicly-auditable cert
    // evidence. The floor is only EVALUABLE once the posture engages, so
    // a non-`asi-hard` profile now FAILS with an `actual` that says the
    // floor was not evaluated rather than claiming it was met. Under
    // `asi-hard` the rendered `actual` / `pass` / `fix` are byte-identical
    // to pre-#2923; only the `required` text gained its (always-true,
    // previously implicit) engagement precondition.
    let below_floor = crate::security_profile::asi_hard_below_floor();
    let knob_count = crate::security_profile::pinned_knobs().len();
    let pins_at_floor = asi_hard && below_floor.is_empty();
    out.push(check(
        "asi-hard pinned knobs",
        &format!("asi-hard engaged AND all {knob_count} at hard floor (security_profile::KNOBS)"),
        if !asi_hard {
            format!(
                "(profile={} — asi-hard pins not in force; the {knob_count}-knob hard floor was \
                 not evaluated)",
                resolved_security_profile_label()
            )
        } else if below_floor.is_empty() {
            format!("{knob_count}/{knob_count} at floor")
        } else {
            below_floor
                .iter()
                .map(|(env, current, hard)| format!("{env}={current:?} (required {hard:?})"))
                .collect::<Vec<_>>()
                .join("; ")
        },
        pins_at_floor,
        if asi_hard {
            "remove the override(s) named in `actual` (asi-hard pins them) or raise each to its \
             hard floor; see `src/security_profile.rs::KNOBS`"
        } else {
            "set AI_MEMORY_SECURITY_PROFILE=asi-hard so the hardened pins are in force, then \
             re-run this check to evaluate the hard floor; see `src/security_profile.rs::KNOBS`"
        },
    ));

    // ---- 3. AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT (COMBINED with the
    // AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS escape hatch) -------------
    // B1 fix (Fable review, 2026-08-11): the LIVE receive gate on both
    // `/sync/push` and `/sync/since` is the combined predicate
    // `require_peer_enrollment_enabled() && !allow_unenrolled_peers_enabled()`
    // (`src/handlers/federation_signing_check.rs:1614,1935`), NOT
    // `require_peer_enrollment_enabled()` alone. Checking only the first
    // half was a false-green: a fully-hardened env with
    // `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1` set made the daemon accept
    // unenrolled-peer attribution on BOTH receive lanes while this check
    // reported PASS. Reuses both real gate functions verbatim.
    let peer_enrollment_required =
        crate::handlers::federation_signing_check::require_peer_enrollment_enabled();
    let unenrolled_peers_allowed =
        crate::handlers::federation_signing_check::allow_unenrolled_peers_enabled();
    out.push(check(
        crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
        "not explicitly disabled (peer enrollment required) AND \
         AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS not truthy (no rollout hatch open)",
        format!(
            "{}={:?}; {}={:?}",
            crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
            std::env::var(crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV)
                .unwrap_or_else(|_| MSG_UNSET_DEFAULTS_STRICT.to_string()),
            crate::handlers::federation_signing_check::ALLOW_UNENROLLED_PEERS_ENV,
            std::env::var(crate::handlers::federation_signing_check::ALLOW_UNENROLLED_PEERS_ENV)
                .unwrap_or_else(|_| "(unset)".to_string()),
        ),
        peer_enrollment_required && !unenrolled_peers_allowed,
        "unset AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT (or set it to 1) AND unset \
         AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS",
    ));

    // ---- 4. AI_MEMORY_FED_REQUIRE_SIG ------------------------------
    // NB1 fix (Fable review, 2026-08-11): call the REAL reader
    // (`crate::federation::signing::require_sig`, which delegates to the
    // case-SENSITIVE `receive_auth::env_flag_default_on`) instead of
    // re-deriving falsy grammar with a lowercasing local helper. The
    // local `is_falsy` helper lowercased before matching, so e.g.
    // `AI_MEMORY_FED_REQUIRE_SIG=FALSE` read as non-compliant here while
    // the live gate (exact-lowercase match only) stayed strict —
    // fail-closed drift, but WRONG relative to the process's real
    // behaviour, which is exactly the false-green/false-red class this
    // module exists to prevent.
    let (sig_ok, sig_actual) = (
        crate::federation::signing::require_sig(),
        std::env::var(crate::federation::signing::REQUIRE_SIG_ENV)
            .unwrap_or_else(|_| MSG_UNSET_DEFAULTS_STRICT.to_string()),
    );
    out.push(check(
        crate::federation::signing::REQUIRE_SIG_ENV,
        "not explicitly disabled (per-message Ed25519 signatures required)",
        sig_actual,
        sig_ok,
        "unset AI_MEMORY_FED_REQUIRE_SIG or set it to 1",
    ));

    // ---- 5. AI_MEMORY_FED_REQUIRE_NONCE -----------------------------
    // NB1 fix — same real-reader substitution as check #4.
    let (nonce_ok, nonce_actual) = (
        crate::federation::signing::require_nonce(),
        std::env::var(crate::federation::signing::REQUIRE_NONCE_ENV)
            .unwrap_or_else(|_| MSG_UNSET_DEFAULTS_STRICT.to_string()),
    );
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
    // `AppConfig::ENV_PERMISSIONS_MODE` is the hoisted const both this
    // label and `effective_permissions_mode()` read from (pm-v3.1
    // hardcoded-literal-duplication gate) — no bare literal here.
    let mode = app_config.effective_permissions_mode();
    out.push(check(
        &format!(
            "{} (ruling: AI_MEMORY_FED_PERMISSIONS_MODE)",
            AppConfig::ENV_PERMISSIONS_MODE
        ),
        "enforce",
        mode.as_str().to_string(),
        mode == PermissionsMode::Enforce,
        &format!(
            "set {}=enforce (or [permissions].mode = \"enforce\")",
            AppConfig::ENV_PERMISSIONS_MODE
        ),
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
    // NB1 fix — call the REAL reader (`peer_attestation::sync_trust_peer_bypass`,
    // exact-literal `"1"` match, `src/federation/peer_attestation.rs:366`)
    // instead of the broader local `is_truthy` grammar (`1`/`true`/`yes`/`on`).
    // The real gate trips ONLY on the literal `1`, so e.g. `=true` never
    // opens the bypass in production but `must_be_unset_env`'s truthy
    // grammar would have false-FAILED this check against a compliant env.
    let sync_trust_bypassed = crate::federation::peer_attestation::sync_trust_peer_bypass();
    out.push(check(
        crate::federation::peer_attestation::SYNC_TRUST_PEER_ENV,
        "UNSET (or not the literal `1` — the real gate's exact-match grammar)",
        std::env::var(crate::federation::peer_attestation::SYNC_TRUST_PEER_ENV)
            .map_or_else(|_| "(unset)".to_string(), |v| format!("{v:?}")),
        !sync_trust_bypassed,
        "unset AI_MEMORY_FED_SYNC_TRUST_PEER",
    ));

    // ---- 14. AI_MEMORY_FED_TRUST_BODY_AGENT_ID — MUST BE UNSET -----
    // NB1 fix — same real-reader substitution as check #13
    // (`peer_attestation::trust_body_agent_id_bypass`, exact `"1"` match).
    let trust_body_bypassed = crate::federation::peer_attestation::trust_body_agent_id_bypass();
    out.push(check(
        crate::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV,
        "UNSET (or not the literal `1` — the real gate's exact-match grammar)",
        std::env::var(crate::federation::peer_attestation::TRUST_BODY_AGENT_ID_ENV)
            .map_or_else(|_| "(unset)".to_string(), |v| format!("{v:?}")),
        !trust_body_bypassed,
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
        // NB3 fix (Fable review, 2026-08-11): the parenthetical
        // "(or [encryption].at_rest = true)" was dropped — `evaluate`
        // (matching EVERY production call site of `encryption_enabled`,
        // not merely this one) passes `config_flag: None`, so setting
        // `[encryption].at_rest = true` in config.toml would NOT clear
        // this FAIL; only the env var is a live remediation here.
        "rebuild with --features sqlcipher AND set AI_MEMORY_ENCRYPT_AT_REST=1",
    ));

    // ---- 16. peer URLs https-only ------------------------------------
    // Same underlying knob as one of the 21 asi-hard pins (#154) —
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

    // ---- 17. boot-refusal env armed (#2911 item 1) -------------------
    // Appended (not inserted) so existing check numbers 1-16 stay
    // stable for the cert doc + #2911 item 3 (check #10 pin-file parse).
    // `evaluate` previously never read this knob, so `doctor --posture`
    // could PASS a process whose daemon would NOT refuse boot on later
    // drift (`enforce_at_boot_pre_runtime` returns Ok when unset).
    // Reuses the real reader — the same `is_truthy` grammar the boot
    // gate itself uses.
    let boot_gate_armed = enterprise_federation_posture_required();
    out.push(check(
        ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE,
        "truthy (boot-refusal gate armed so future posture drift cannot silently boot)",
        std::env::var(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE)
            .unwrap_or_else(|_| "(unset — boot gate inert)".to_string()),
        boot_gate_armed,
        "set AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1",
    ));

    // ---- 18. AI_MEMORY_FED_REQUIRE_POLICY_CURRENT (#2911 item 2) ------
    // FED-RQ-03 stale-governance-policy refusal (receive_auth.rs:479-494
    // at 580d8427). Default-ON via `env_flag_default_on`; an explicit
    // falsy token (`0`/`false`/`no`/`off`) escaped BOTH this posture
    // table and `security_profile::KNOBS`. A dedicated posture check
    // (not a KNOBS pin) keeps the certified set off the cert-expiry
    // watch list: this module is not watched, and the identifier is
    // already declared in receive_auth. Crossroads: generic `asi-hard`
    // without this enterprise posture still permits `=0`; that is the
    // generic-vs-certified-set boundary — operators who want the
    // certified guarantee arm check #17, which then refuses `=0` at
    // boot via this row.
    out.push(check(
        crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
        "not explicitly disabled (detected-stale inbound policy_version refused)",
        std::env::var(crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV)
            .unwrap_or_else(|_| MSG_UNSET_DEFAULTS_STRICT.to_string()),
        crate::federation::receive_auth::require_policy_current_enabled(),
        "unset AI_MEMORY_FED_REQUIRE_POLICY_CURRENT or set it to 1",
    ));

    // ---- 19. append-only audit spine armed (#2954) -----------------
    // The federation newer-wins overwrite (`insert_if_newer` /
    // `apply_remote_memory`) appends an identity-only SUPERSEDE leaf ONLY when
    // the append-only spine is ON, and that leaf is tamper-EVIDENT only when the
    // daemon audit signing key is installed to SIGN it. The certified posture
    // therefore requires BOTH — an unsigned leaf is theater (the #2954 reviewer
    // killer objection). Both halves are CONFIG/DISK-resolvable, which is
    // load-bearing: this module's boot gate runs in `fn main()` BEFORE
    // `set_append_only` and `audit::init` (src/main.rs), so it reads the RESOLVED
    // storage flag (env > `[storage]` > compiled, the same value boot will seed)
    // and probes the daemon signing key the same way `init_forensic_audit` will
    // (an already-installed process key OR a loadable key file). A doctor run
    // (post-init) also PASSes via the installed-key arm.
    let append_only_resolved = app_config.resolve_storage().append_only;
    let audit_signer_armed = crate::governance::audit::audit_key_is_installed() || {
        let agent_id = crate::identity::resolve_agent_id(None, None)
            .unwrap_or_else(|_| "ai-memory".to_string());
        crate::governance::audit::load_daemon_signing_key(&agent_id)
            .ok()
            .flatten()
            .is_some()
    };
    out.push(check(
        "append-only audit spine",
        "append-only spine ON (AI_MEMORY_APPEND_ONLY / [storage].append_only) AND the daemon \
         audit signing key armed (federation supersede leaves are SIGNED, not unsigned)",
        format!(
            "append_only={append_only_resolved}; audit_signing_key={}",
            if audit_signer_armed {
                "armed"
            } else {
                "absent"
            }
        ),
        append_only_resolved && audit_signer_armed,
        "set AI_MEMORY_APPEND_ONLY=1 (or [storage].append_only = true) AND provision the daemon \
         audit signing key (see `governance::audit::load_daemon_signing_key`) so the append-only \
         federation supersede leaves are signed",
    ));

    debug_assert_eq!(
        out.len(),
        ENTERPRISE_FEDERATION_CHECK_COUNT,
        "evaluate() check count drifted from ENTERPRISE_FEDERATION_CHECK_COUNT"
    );

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
    /// reads or pins, for test isolation. Delegates the 21 `asi-hard`
    /// knobs + the profile selector to `security_profile::pinned_knobs`
    /// / `ENV_SECURITY_PROFILE` rather than re-listing them (single
    /// source of truth even inside the test cleanup).
    const FED_ENV_VARS: &[&str] = &[
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
    ];

    /// #2954 — keeps the installed daemon-audit-key temp dir alive for the
    /// whole (env-isolated child) process so check #19's signing-key half stays
    /// armed. First-install-wins (`OnceLock`), mirroring the flag-on suite's
    /// `AUDIT_DIR`.
    static POSTURE_AUDIT_DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();

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
        // Pins the 21 asi-hard knobs via the REAL enforcement fn — the
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
            // #2911 check #17 — unlike the default-ON `AI_MEMORY_FED_REQUIRE_*`
            // knobs below, the boot-refusal env defaults OFF. Unset is now
            // a FAIL (doctor must not PASS a process whose daemon would
            // not refuse boot on later drift).
            std::env::set_var(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE, "1");
            // #2954 check #19 — the append-only audit spine must be armed for
            // the certified posture (else a federation supersede leaf is
            // unsigned theater). The signing-key half is armed just below.
            std::env::set_var(crate::config::ENV_APPEND_ONLY, "1");
        }
        // #2954 check #19 — install a process-wide daemon audit signing key so
        // the append-only leaves would be SIGNED. Process-global `OnceLock`
        // install, isolated per env-isolated child
        // (`run_env_isolated_child_or_spawn`), kept alive for the test in a
        // module-static tempdir (first-install-wins, like the flag-on suite).
        POSTURE_AUDIT_DIR.get_or_init(|| {
            let dir = tempfile::Builder::new()
                .prefix("ef-posture-audit-")
                .tempdir()
                .expect("audit tempdir");
            let signing = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            crate::governance::audit::init(dir.path(), Some(signing))
                .expect("install daemon audit key");
            dir
        });
        // AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT / _SIG / _NONCE /
        // _PUSH_NAMESPACE_SCOPE / _POLICY_CURRENT /
        // AI_MEMORY_PERMISSIONS_MODE /
        // AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR / _SYNC_TRUST_PEER /
        // _TRUST_BODY_AGENT_ID / _ALLOW_PLAINTEXT_PEERS /
        // _ALLOW_UNENROLLED_PEERS are all deliberately left UNSET — every
        // one of them already defaults to the certified-compliant state
        // (each check now calls the real production reader function
        // directly, per the B1/NB1 fixes), which is itself part of what
        // this test proves.
        fp_file
    }

    // Alias so the const import above stays readable without a `use`
    // that would collide with the module's own `TRUST_DOMAIN_ENV`
    // re-export ambiguity across `crate::federation::identity::trust_bundle`.
    use crate::federation::identity::trust_bundle::TRUST_DOMAIN_ENV as TRUST_DOMAIN_ENV_FOR_TEST;

    #[test]
    fn fully_hardened_env_passes_every_check_except_possibly_sqlcipher_build() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::fully_hardened_env_passes_every_check_except_possibly_sqlcipher_build",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();

        let app_config = AppConfig::default();
        let checks = evaluate(&app_config);
        assert_eq!(
            checks.len(),
            ENTERPRISE_FEDERATION_CHECK_COUNT,
            "evaluate() must return exactly {ENTERPRISE_FEDERATION_CHECK_COUNT} checks (#2911)"
        );

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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::asi_hard_not_engaged_fails_that_check",
        ) {
            return;
        }
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

    /// #2923 — under a NON-`asi-hard` profile the pins row must not read
    /// as a satisfied hardened-floor check. `asi_hard_below_floor()` is
    /// vacuously empty there (its own docs say to pair it with
    /// `is_asi_hard`), so the pre-fix row printed
    /// `[PASS] … 21/21 at floor` while NOT ONE knob was pinned.
    #[test]
    fn pins_row_fails_and_states_floor_unevaluated_under_standard_profile_2923() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::pins_row_fails_and_states_floor_unevaluated_under_standard_profile_2923",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;

        // Arrange: the bare cert-evidence leg — no profile, no knobs set.
        // Act
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, "asi-hard pinned knobs");

        // Assert: FAILS, and says WHY without claiming a met floor.
        assert!(
            !c.pass,
            "the pins row must not PASS while the resolved profile is not asi-hard: {c:?}"
        );
        let knob_count = crate::security_profile::pinned_knobs().len();
        assert!(
            !c.actual
                .contains(&format!("{knob_count}/{knob_count} at floor")),
            "the vacuous all-at-floor rendering is the #2923 defect: {:?}",
            c.actual
        );
        assert!(
            c.actual.contains("profile=standard"),
            "actual must name the resolved profile: {:?}",
            c.actual
        );
        assert!(
            c.actual.contains("not in force") && c.actual.contains("not evaluated"),
            "actual must say the pins are not in force and the floor was not evaluated: {:?}",
            c.actual
        );
        assert!(
            c.required.contains("asi-hard engaged"),
            "required must state the engagement precondition: {:?}",
            c.required
        );
        assert!(
            c.remediation
                .contains(crate::security_profile::ENV_SECURITY_PROFILE),
            "remediation must name the profile knob, not a knob list that is empty here: {:?}",
            c.remediation
        );
        assert!(!all_pass(&checks));
    }

    /// #2923 companion — under an `asi-hard` hardened env the row is
    /// UNCHANGED: it passes and still renders the all-at-floor verdict
    /// derived from `asi_hard_below_floor()`.
    #[test]
    fn pins_row_passes_with_all_at_floor_under_hardened_profile_2923() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::pins_row_passes_with_all_at_floor_under_hardened_profile_2923",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();

        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, "asi-hard pinned knobs");

        assert!(c.pass, "hardened env must PASS the pins row: {c:?}");
        let knob_count = crate::security_profile::pinned_knobs().len();
        assert_eq!(
            c.actual,
            format!("{knob_count}/{knob_count} at floor"),
            "the hardened-leg rendering must stay byte-identical to pre-#2923"
        );
        assert!(
            c.remediation.is_empty(),
            "a passing check carries no remediation"
        );
    }

    /// #2923 — an UNRECOGNISED profile token is a `SecurityPosture::resolve`
    /// error, which `is_asi_hard()` reads as NOT hardened. The row must
    /// still fail and must NOT name a posture the process does not have.
    /// (A live daemon never reaches here — `enforce_at_boot_pre_runtime`
    /// aborts on the typo — but `evaluate` is a public library entry
    /// point, so the arm is real.)
    #[test]
    fn pins_row_fails_and_labels_unrecognised_profile_2923() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::pins_row_fails_and_labels_unrecognised_profile_2923",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        unsafe {
            std::env::set_var(crate::security_profile::ENV_SECURITY_PROFILE, "asi-hardd");
        }

        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, "asi-hard pinned knobs");

        assert!(!c.pass);
        assert!(
            c.actual.contains("profile=unrecognised"),
            "an unresolvable profile must not be rendered as `standard` or `asi-hard`: {:?}",
            c.actual
        );
    }

    #[test]
    fn asi_hard_knob_below_floor_fails_that_check() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::asi_hard_knob_below_floor_fails_that_check",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        // Loosen ONE of the 21 pinned knobs after the fact.
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::peer_enrollment_explicitly_disabled_fails",
        ) {
            return;
        }
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
    fn allow_unenrolled_peers_hatch_open_fails_even_with_enrollment_required() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::allow_unenrolled_peers_hatch_open_fails_even_with_enrollment_required",
        ) {
            return;
        }
        // B1 (Fable review, 2026-08-11): a fully-hardened env with
        // AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT left at its strict
        // default PLUS AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS=1 made the
        // LIVE daemon accept unenrolled-peer attribution on BOTH
        // `/sync/push` and `/sync/since` (the combined predicate in
        // `federation_signing_check.rs:1614,1935`), while the
        // pre-fix check #3 (which read only
        // `require_peer_enrollment_enabled()`) reported PASS — a
        // false-green. This is the regression test proving the fix:
        // the same env now FAILS check #3.
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            // Deliberately confirm the strict knob is untouched (unset ->
            // strict per its own default) so the FAIL is attributable
            // ONLY to the escape hatch, not to a loosened enrollment knob.
            std::env::remove_var(
                crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
            );
            std::env::set_var(
                crate::handlers::federation_signing_check::ALLOW_UNENROLLED_PEERS_ENV,
                "1",
            );
        }
        assert!(
            crate::handlers::federation_signing_check::require_peer_enrollment_enabled(),
            "precondition: enrollment must still read as required"
        );
        assert!(
            crate::handlers::federation_signing_check::allow_unenrolled_peers_enabled(),
            "precondition: the escape hatch must be open"
        );
        let checks = evaluate(&AppConfig::default());
        let c = find(
            &checks,
            crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
        );
        assert!(
            !c.pass,
            "check #3 must FAIL when the unenrolled-peers rollout hatch is open, \
             even though peer enrollment itself is still required — this is the exact \
             false-green Fable proved live on the built binary"
        );
        assert!(
            c.actual
                .contains(crate::handlers::federation_signing_check::ALLOW_UNENROLLED_PEERS_ENV)
        );
        assert!(!all_pass(&checks));
    }

    #[test]
    fn require_sig_explicitly_disabled_fails() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::require_sig_explicitly_disabled_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::require_nonce_explicitly_disabled_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::push_namespace_scope_explicitly_disabled_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::permissions_mode_not_enforce_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::governance_fail_open_enabled_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::trust_domain_unset_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::peer_fingerprints_unset_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::peer_fingerprints_pointing_at_missing_file_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::peer_attestation_unset_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::peer_attestation_malformed_json_fails_and_refuses_not_falls_back",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::peer_attestation_allow_all_glob_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::sync_trust_peer_set_truthy_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::trust_body_agent_id_set_truthy_fails",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::encrypt_at_rest_env_falsy_fails_even_on_sqlcipher_build",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::plaintext_peers_hatch_open_fails",
        ) {
            return;
        }
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
        // #2477's KNOB is ALSO one of the 21 asi-hard pins, so BOTH
        // the aggregate knobs row and the dedicated https-only row must
        // go red — never silently absorbed into only one.
        let knobs_row = find(&checks, "asi-hard pinned knobs");
        assert!(!knobs_row.pass);
        let https_row = find(&checks, crate::tls::FED_ALLOW_PLAINTEXT_PEERS_ENV);
        assert!(!https_row.pass);
        assert!(https_row.control.contains("https-only peers"));
    }

    // ------------------------------------------------------------------
    // #2954 check #19 — append-only audit spine (append-only ON AND the
    // daemon audit signing key armed) — else a federation supersede leaf is
    // unsigned theater.
    // ------------------------------------------------------------------

    #[test]
    fn append_only_disarmed_fails_check_19() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::append_only_disarmed_fails_check_19",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        // Fully hardened (which arms BOTH halves), then strip the append-only
        // flag: the spine is off, so no leaf is written at all — check #19 FAILs
        // even though the signing key is armed.
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::remove_var(crate::config::ENV_APPEND_ONLY);
        }
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, "append-only audit spine");
        assert!(
            !c.pass,
            "check #19 must FAIL when the append-only spine is disarmed: {c:?}"
        );
        assert!(
            c.actual.contains("append_only=false"),
            "actual must name the disarmed spine: {:?}",
            c.actual
        );
        assert!(c.remediation.contains(crate::config::ENV_APPEND_ONLY));
        assert!(!all_pass(&checks));
    }

    #[test]
    fn audit_signing_disarmed_fails_check_19() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::audit_signing_disarmed_fails_check_19",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        // Arm the append-only spine but deliberately DO NOT install a daemon
        // audit key (never call set_fully_hardened_env, which would), and point
        // the key dir at an EMPTY temp dir so `load_daemon_signing_key` finds no
        // key on disk either — the leaf would store UNSIGNED, so check #19 FAILs.
        let empty_key_dir = tempfile::tempdir().expect("empty key dir");
        unsafe {
            std::env::set_var(crate::config::ENV_APPEND_ONLY, "1");
            std::env::set_var(crate::identity::keypair::KEY_DIR_ENV, empty_key_dir.path());
        }
        assert!(
            !crate::governance::audit::audit_key_is_installed(),
            "precondition: no process audit key installed in this child"
        );

        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, "append-only audit spine");
        assert!(
            !c.pass,
            "check #19 must FAIL when the audit signing key is disarmed: {c:?}"
        );
        assert!(
            c.actual.contains("append_only=true") && c.actual.contains("audit_signing_key=absent"),
            "actual must show the spine armed but the signer absent: {:?}",
            c.actual
        );
        assert!(!all_pass(&checks));

        unsafe {
            std::env::remove_var(crate::identity::keypair::KEY_DIR_ENV);
        }
    }

    // ------------------------------------------------------------------
    // #2911 items 1-2 — boot-gate self-attestation + policy-current
    // ------------------------------------------------------------------

    #[test]
    fn evaluate_fails_when_require_enterprise_federation_posture_unset() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::evaluate_fails_when_require_enterprise_federation_posture_unset",
        ) {
            return;
        }
        // Arrange: fully hardened except the boot-refusal env, which
        // the helper now sets — strip it so doctor --posture sees the
        // pre-#2911 "PASS while daemon would not refuse boot" shape.
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::remove_var(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE);
        }

        // Act
        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE);

        // Assert
        assert!(
            !c.pass,
            "check #17 must FAIL when the boot-refusal env is unset"
        );
        assert!(c.actual.contains("unset"));
        assert!(
            c.remediation
                .contains(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE)
        );
        assert!(!all_pass(&checks));
    }

    #[test]
    fn evaluate_fails_when_require_enterprise_federation_posture_explicitly_off() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::evaluate_fails_when_require_enterprise_federation_posture_explicitly_off",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE, "0");
        }

        let checks = evaluate(&AppConfig::default());
        let c = find(&checks, ENV_REQUIRE_ENTERPRISE_FEDERATION_POSTURE);
        assert!(!c.pass);
        assert_eq!(c.actual, "0");
        assert!(!all_pass(&checks));
    }

    #[test]
    fn evaluate_fails_when_require_policy_current_explicitly_disabled() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::evaluate_fails_when_require_policy_current_explicitly_disabled",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = EnvGuard;
        let _fp_file = set_fully_hardened_env();
        unsafe {
            std::env::set_var(
                crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
                "0",
            );
        }
        assert!(
            !crate::federation::receive_auth::require_policy_current_enabled(),
            "precondition: the real FED-RQ-03 reader must see the hatch open"
        );

        let checks = evaluate(&AppConfig::default());
        let c = find(
            &checks,
            crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
        );
        assert!(
            !c.pass,
            "check #18 must FAIL when AI_MEMORY_FED_REQUIRE_POLICY_CURRENT=0 — \
             this is the exact escape #2911 item 2 names"
        );
        assert_eq!(c.actual, "0");
        assert!(!all_pass(&checks));
    }

    // ------------------------------------------------------------------
    // Boot gate
    // ------------------------------------------------------------------

    #[test]
    fn boot_gate_is_a_noop_when_not_required() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::boot_gate_is_a_noop_when_not_required",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::boot_gate_refuses_when_required_and_posture_unsatisfied",
        ) {
            return;
        }
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
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::tests::boot_gate_passes_when_required_and_posture_satisfied_or_only_sqlcipher_missing",
        ) {
            return;
        }
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
