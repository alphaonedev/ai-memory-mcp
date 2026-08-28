// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #1961 (R23/R7) — the `asi-hard` hardened, no-disable security
//! posture.
//!
//! A **security posture** is a single named knob an operator selects for a
//! hardened deployment (`AI_MEMORY_SECURITY_PROFILE=asi-hard`) that PINS the
//! individual fail-closed security knobs ON and REFUSES any attempt to
//! loosen them. It is the opposite of the per-knob escape hatches scattered
//! across the env table: instead of the operator having to know and set
//! every hardening flag correctly, one posture pins the whole set.
//!
//! ## Resolution
//!
//! `AI_MEMORY_SECURITY_PROFILE` env > compiled default [`SecurityPosture::Standard`].
//! `standard` / unset keeps every knob at its own default (byte-identical
//! legacy). `asi-hard` engages the pin-and-refuse enforcement in
//! [`enforce_at_boot`].
//!
//! ## Enforcement contract (the "no-disable" guarantee)
//!
//! For each pinned knob, at daemon boot under `asi-hard`:
//!
//! - **unset** → the daemon PINS it to the hard value (overrides the
//!   per-knob default so every downstream read site honours the hard
//!   posture without any change at the read site);
//! - **already at-or-above the hard floor** → accepted unchanged;
//! - **set to a value BELOW the hard floor** (an attempt to loosen) →
//!   the daemon REFUSES to boot (fail-closed) with a clear error naming
//!   the offending knob.
//!
//! This is the "REFUSES to disable them" contract from the issue: under
//! `asi-hard` you cannot run with a weakened security knob — either it is
//! at the hard floor or the daemon will not start.
//!
//! ## Pinned knobs (the documented hardened set)
//!
//! | Env knob | Hard floor | What it forces |
//! |---|---|---|
//! | `AI_MEMORY_SECRET_SCREEN_MODE` | `refuse` | pre-write credential screen refuses secrets (not `off`/`redact`) |
//! | `AI_MEMORY_ALLOW_SCHEMA_AHEAD` | (unset) | the #2445 schema-downgrade hatch is refused — an older binary may not open/write a newer database |
//! | `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` | `1` | unsigned direct writes refused on EVERY surface |
//! | `AI_MEMORY_FED_REQUIRE_WRITE_SIG` | `1` | inbound relayed memories must carry a verified per-write signature |
//! | `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` | `1` | inbound relayed signals must verify against the enrolled author key |
//! | `AI_MEMORY_FED_REQUIRE_TRANSITION_SIG` | `1` | inbound relayed lifecycle transitions must verify against the enrolled author key |
//! | `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG` | `1` | inbound relayed checkpoints must verify against the enrolled author key |
//! | `AI_MEMORY_FED_REQUIRE_SIG` | `1` | inbound federation requests must carry a verified per-message Ed25519 signature (#3033 outer-transport gate) |
//! | `AI_MEMORY_FED_REQUIRE_NONCE` | `1` | inbound federation requests must carry a fresh per-message nonce (#3033 outer-transport gate) |
//! | `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT` | `1` | an inbound peer's `X-Peer-Id` must resolve to an enrolled Ed25519 key (#3033 outer-transport gate) |
//! | `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE` | `1` | inbound `/sync/push` writes are confined to the peer's declared `allowed_namespaces` (#3033 outer-transport gate) |
//! | `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED` | `1` | provenance-less inbound writes are quarantined, not accepted-visible |
//! | `AI_MEMORY_CID_ENFORCE` | `1` | content-id mismatch is WARN-enforced, not detect-only |
//! | `AI_MEMORY_REQUIRE_ROLLBACK_CHECK` | `1` | open-time rollback-evidence check fail-closed |
//! | `AI_MEMORY_REQUIRE_WITNESS` | `1` | audit-head witness required (fail-closed) |
//! | `AI_MEMORY_REQUIRE_CAUSE_BINDING` | `1` | audit rows must carry a bound cause |
//! | `AI_MEMORY_REQUIRE_ROLE_SEPARATION` | `1` | three-key governance role separation required |
//! | `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE` | `1` | identity-lineage succession chain required |
//! | `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY` | `1` | outbound federation TLS must verify the PEER SERVER cert — `--insecure-skip-server-verify` is refused (#2448) |
//! | `AI_MEMORY_FED_ALLOW_PLAINTEXT_PEERS` | *(unset)* | the plaintext-peer hatch is NOT in force — an `http://` peer on a non-loopback host is refused (#2477) |
//! | `AI_MEMORY_DB_SYNCHRONOUS` | `FULL` | power-loss durability (fsync every commit) — #1961 part C |
//! | `AI_MEMORY_MIGRATION_REQUIRE_CORE_TABLES` | `1` | a migration REFUSES to stamp a schema version whose ladder-created core relations were lost, instead of warning (#3113) |
//! | `AI_MEMORY_PERMISSIONS_MODE` | `enforce` | the K3/K9 governance gate is ON — `off`/`advisory` refuse boot (#3168). Certified deployments already required this; plain `asi-hard` was the hole |
//! | `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` | *(unset)* | PERMISSIVE-shaped: the fail-OPEN hatch is NOT in force — a rule-consultation error stays fail-CLOSED (#3168) |
//! | `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT` | `1` | inbound federated push with a DETECTED-stale `policy_version` is refused (#3168; live name `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT` — the unprefixed `REQUIRE_POLICY_CURRENT` does not exist) |
//! | `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS` | *(unset)* | PERMISSIVE-shaped: the unenrolled-peer hatch of the already-pinned `REQUIRE_PEER_ENROLLMENT` is NOT in force (#3201) |
//! | `AI_MEMORY_FED_CERT_PEER_BINDING` | `enforce` | mTLS cert↔`X-Peer-Id` cross-check mode is `enforce`; `off`/`warn` refuse boot. Inert without `AI_MEMORY_FED_CERT_PEER_BINDING_MAP`. The documented `standard` unset default stays `warn` (#3201 / #3289) |
//!
//! In addition, `asi-hard` forces the config-backed governance knob
//! `[governance].require_operator_pubkey` to `true` (see
//! [`is_asi_hard`], consulted at the governance boot check).
//!
//! The federation transition + checkpoint signature knobs
//! (`AI_MEMORY_FED_REQUIRE_TRANSITION_SIG`, `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG`)
//! already default fail-closed (`1`); `asi-hard` still refuses a loosening
//! override on them so the posture is complete.
//!
//! The four OUTER federation-transport gates (`AI_MEMORY_FED_REQUIRE_SIG`,
//! `AI_MEMORY_FED_REQUIRE_NONCE`, `AI_MEMORY_FED_REQUIRE_PEER_ENROLLMENT`,
//! `AI_MEMORY_FED_REQUIRE_PUSH_NAMESPACE_SCOPE`) likewise default ON;
//! `asi-hard` pins them so the "no-disable" contract covers the outermost
//! network access-control gates, not only the inner per-object attestation
//! (#3033). Because these gates use the DEFAULT-ON grammar (enabled unless an
//! explicit falsy token), their `meets_floor` predicates delegate to the same
//! value-level readers the runtime resolves through
//! ([`crate::federation::receive_auth::flag_value_default_on`] /
//! [`crate::handlers::federation_signing_check::peer_enrollment_value_enabled`]),
//! never a re-derived truthy grammar that would false-refuse a boot the live
//! gate treats as compliant.
//!
//! ## Call site (#2386 — pre-runtime ONLY)
//!
//! The environment-MUTATING enforcement ([`enforce_at_boot`], via
//! [`enforce_at_boot_pre_runtime`]) runs in the synchronous,
//! still-single-threaded phase of the binary's `fn main()` — BEFORE the
//! tracing appender worker or any tokio runtime worker thread exists —
//! because `std::env::set_var` on a live multi-threaded process is a data
//! race (the closed-#1889 class). The async dispatch body
//! (`daemon_runtime::run`) consumes the READ-ONLY [`runtime_boot_report`]
//! to log the posture; it never mutates the environment.

use std::sync::OnceLock;

use anyhow::{Result, bail};

/// Env var selecting the process-wide security posture.
pub const ENV_SECURITY_PROFILE: &str = "AI_MEMORY_SECURITY_PROFILE";

/// #3146/#3147 (pm-v3.1 hardcoded-literal gate) — the ONE spelling of the
/// `asi-hard` refusal preamble. Every boot refusal attributed to this posture
/// (here, and [`crate::identity::keypair::public_only_refusal`]) opens with it,
/// so operators can grep one phrase for "the posture stopped my boot" and a
/// rename can never leave half the fleet's messages behind.
pub const ASI_HARD_REFUSAL_PREFIX: &str = "security posture \"asi-hard\"";

/// The named security posture. `Standard` is the compiled default (every
/// knob keeps its own default); `AsiHard` engages the pin-and-refuse set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPosture {
    /// Every security knob keeps its individual default (legacy).
    Standard,
    /// The hardened, no-disable posture — pins the fail-closed set ON and
    /// refuses any loosening override.
    AsiHard,
}

impl SecurityPosture {
    /// The canonical wire token for this posture.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::AsiHard => "asi-hard",
        }
    }

    /// Parse a posture token (case-insensitive, trimmed). `standard` /
    /// `default` / empty → [`Self::Standard`]; `asi-hard` (with `-`, `_`,
    /// or no separator) → [`Self::AsiHard`]. Any other token is an error
    /// so a typo in the hardened posture selector fails LOUDLY rather than
    /// silently booting Standard.
    ///
    /// # Errors
    /// Returns an error for an unrecognised posture token.
    pub fn parse(token: &str) -> Result<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "" | "standard" | "default" | "normal" => Ok(Self::Standard),
            "asi-hard" | "asi_hard" | "asihard" | "hard" => Ok(Self::AsiHard),
            other => bail!(
                "unrecognised {ENV_SECURITY_PROFILE} value {other:?} \
                 (expected \"standard\" or \"asi-hard\")"
            ),
        }
    }

    /// Resolve the posture from [`ENV_SECURITY_PROFILE`]. An unset var is
    /// [`Self::Standard`]; an unrecognised value is an error (fail-loud).
    ///
    /// # Errors
    /// Propagates the parse error for an unrecognised token.
    pub fn resolve() -> Result<Self> {
        match std::env::var(ENV_SECURITY_PROFILE) {
            Ok(v) => Self::parse(&v),
            Err(_) => Ok(Self::Standard),
        }
    }
}

impl std::fmt::Display for SecurityPosture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether the process is running under the `asi-hard` posture. Cheap
/// env read; consulted by boot-time checks that must behave fail-closed
/// under the hardened posture even for config-backed (non-env) knobs —
/// e.g. the governance `require_operator_pubkey` boot check treats
/// `asi-hard` as `require_operator_pubkey = true`.
#[must_use]
pub fn is_asi_hard() -> bool {
    matches!(SecurityPosture::resolve(), Ok(SecurityPosture::AsiHard))
}

/// One pinned knob: its env var, the hard-floor value the posture pins it
/// to, and a predicate that answers "does `current` already meet-or-exceed
/// the hard floor?" (so an operator who has ALREADY set the knob to the
/// hard value — or something stronger — is accepted unchanged).
struct KnobSpec {
    env: &'static str,
    hard_value: &'static str,
    /// True iff `current` (the operator-set value) satisfies the hard floor.
    meets_floor: fn(&str) -> bool,
}

/// A truthy env token (the affirmative half of the substrate-wide
/// `1`/`true`/`yes`/`on` convention).
///
/// #3167 — exposed crate-wide so `config::skip_config` resolves
/// `AI_MEMORY_NO_CONFIG` through the SAME grammar as every other
/// `AI_MEMORY_*` boolean knob instead of a bare presence check.
pub(crate) fn is_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// `AI_MEMORY_SECRET_SCREEN_MODE` floor: only `refuse` clears it.
fn secret_screen_meets_floor(v: &str) -> bool {
    v.trim().eq_ignore_ascii_case("refuse")
}

/// `AI_MEMORY_DB_SYNCHRONOUS` floor: `FULL` or the stronger `EXTRA`.
fn synchronous_meets_floor(v: &str) -> bool {
    matches!(v.trim().to_ascii_uppercase().as_str(), "FULL" | "EXTRA")
}

/// v1.0.0 #2445 — `AI_MEMORY_ALLOW_SCHEMA_AHEAD` floor: it must be UNSET (or
/// blank). This is the first PERMISSIVE knob in the table, so its floor is the
/// inverse shape of the others — "hard" means the hatch is not in force.
///
/// Without this entry an `asi-hard` deployment would still permit an older
/// binary to open and write a newer database, i.e. the hardened PROCUREMENT
/// posture would be silently weaker than the no-disable contract advertises —
/// the exact defect #2448 fixed for `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY`.
fn schema_ahead_hatch_meets_floor(v: &str) -> bool {
    v.trim().is_empty()
}

/// #2477 — floor for the plaintext-federation-peer hatch. The SECOND
/// PERMISSIVE knob in this table (after the schema-ahead hatch), so "hard"
/// again means the hatch is NOT in force. Any non-truthy value clears the
/// floor, because [`crate::tls::plaintext_peers_allowed`] only opens on an
/// explicit truthy token — so a knob left unset, empty, or set to `0` is
/// already at the hard posture and must not refuse boot.
///
/// Without this entry an `asi-hard` deployment could still replicate
/// memory CONTENT in the clear to a non-loopback peer, i.e. the hardened
/// PROCUREMENT posture would be silently weaker than the no-disable
/// contract advertises — the exact defect #2448 fixed for
/// `AI_MEMORY_FED_REQUIRE_SERVER_VERIFY`, one door over.
fn plaintext_peers_hatch_meets_floor(v: &str) -> bool {
    !matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// #3168 — `AI_MEMORY_PERMISSIONS_MODE` floor: only a token the live
/// reader ([`crate::config::AppConfig::permissions_mode_from_env_token`])
/// resolves as [`crate::config::PermissionsMode::Enforce`]. The live env
/// arm lowercases WITHOUT trimming, so `" enforce "` is NOT Enforce
/// (it falls through to config) and must not pass the floor.
fn permissions_mode_meets_floor(v: &str) -> bool {
    matches!(
        crate::config::AppConfig::permissions_mode_from_env_token(v),
        Some(crate::config::PermissionsMode::Enforce)
    )
}

/// #3168 — `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` floor: the hatch
/// is NOT in force. Delegates to the live value-level reader so a token
/// that would not arm fail-OPEN (`yes`/`on`/`false`/`0`) cannot refuse
/// boot (NB1). Inverse of [`crate::daemon_runtime::governance_fail_open_value_enabled`].
fn governance_fail_open_hatch_meets_floor(v: &str) -> bool {
    !crate::daemon_runtime::governance_fail_open_value_enabled(v)
}

/// #3201 — `AI_MEMORY_FED_ALLOW_UNENROLLED_PEERS` floor: the hatch is
/// NOT in force. Inverse of the live receive-path reader
/// ([`crate::handlers::federation_signing_check::allow_unenrolled_peers_value_enabled`]).
fn unenrolled_peers_hatch_meets_floor(v: &str) -> bool {
    !crate::handlers::federation_signing_check::allow_unenrolled_peers_value_enabled(v)
}

/// #3201 / #3289 — `AI_MEMORY_FED_CERT_PEER_BINDING` floor: only the
/// exact `enforce` token (case-insensitive, trimmed) meets it. A typo
/// such as `enforc` is NOT `enforce`, so `asi-hard` refuses boot
/// (fail-loud). Runtime parse is also fail-loud (`Result`) — empty /
/// unknown tokens are no longer silently Enforce.
fn cert_peer_binding_meets_floor(v: &str) -> bool {
    v.trim().eq_ignore_ascii_case("enforce")
}

/// The pinned-knob table. SSOT for the module docs table above and the
/// [`pinned_knobs`] accessor; the `asi_hard_pins_documented_set` test pins
/// the two in agreement.
const KNOBS: &[KnobSpec] = &[
    KnobSpec {
        env: "AI_MEMORY_SECRET_SCREEN_MODE",
        hard_value: "refuse",
        meets_floor: secret_screen_meets_floor,
    },
    KnobSpec {
        env: crate::storage::schema_guard::ENV_ALLOW_SCHEMA_AHEAD,
        hard_value: "",
        meets_floor: schema_ahead_hatch_meets_floor,
    },
    KnobSpec {
        env: "AI_MEMORY_REQUIRE_AGENT_ATTESTATION",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: "AI_MEMORY_FED_REQUIRE_WRITE_SIG",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: "AI_MEMORY_FED_REQUIRE_SIGNAL_SIG",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: "AI_MEMORY_FED_REQUIRE_TRANSITION_SIG",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: "AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    // #3033 — the FOUR OUTER federation-TRANSPORT gates. The sig-lane rows
    // above pin the INNER per-object attestation (write/signal/transition/
    // checkpoint); these pin the gates the receive path applies to the
    // request ITSELF before any object is inspected: per-message Ed25519
    // signature + nonce freshness, enrolled-peer identity, and inbound-write
    // namespace confinement. All FOUR already default fail-closed (ON) at
    // v1.0.0, so pinning them is a NO-OP for a compliant deployment — it only
    // removes the ability to DISABLE them under `asi-hard`, closing the
    // #3033 defect where the "no-disable" contract silently excluded the
    // outermost network access-control gates.
    //
    // Each `meets_floor` delegates to the SAME value-level grammar helper the
    // live runtime reader uses (NOT `is_truthy`, which would false-RED a value
    // the live default-ON gate treats as enabled — the NB1 lesson): the three
    // `env_flag_default_on` gates share
    // `receive_auth::flag_value_default_on` (case-sensitive), and the
    // peer-enrollment gate shares
    // `federation_signing_check::peer_enrollment_value_enabled`
    // (case-insensitive) — the identical predicate
    // `require_sig`/`require_nonce`/`require_push_namespace_scope_enabled`/
    // `require_peer_enrollment_enabled` resolve through.
    KnobSpec {
        env: crate::federation::signing::REQUIRE_SIG_ENV,
        hard_value: "1",
        meets_floor: crate::federation::receive_auth::flag_value_default_on,
    },
    KnobSpec {
        env: crate::federation::signing::REQUIRE_NONCE_ENV,
        hard_value: "1",
        meets_floor: crate::federation::receive_auth::flag_value_default_on,
    },
    KnobSpec {
        env: crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
        hard_value: "1",
        meets_floor: crate::handlers::federation_signing_check::peer_enrollment_value_enabled,
    },
    KnobSpec {
        env: crate::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
        hard_value: "1",
        meets_floor: crate::federation::receive_auth::flag_value_default_on,
    },
    KnobSpec {
        env: "AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: "AI_MEMORY_CID_ENFORCE",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: "AI_MEMORY_REQUIRE_ROLLBACK_CHECK",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: "AI_MEMORY_REQUIRE_WITNESS",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: "AI_MEMORY_REQUIRE_CAUSE_BINDING",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: "AI_MEMORY_REQUIRE_ROLE_SEPARATION",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: "AI_MEMORY_REQUIRE_IDENTITY_LINEAGE",
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: crate::tls::FED_REQUIRE_SERVER_VERIFY_ENV,
        hard_value: "1",
        meets_floor: is_truthy,
    },
    KnobSpec {
        env: crate::tls::FED_ALLOW_PLAINTEXT_PEERS_ENV,
        hard_value: "",
        meets_floor: plaintext_peers_hatch_meets_floor,
    },
    KnobSpec {
        env: crate::storage::ENV_DB_SYNCHRONOUS,
        hard_value: "FULL",
        meets_floor: synchronous_meets_floor,
    },
    // #3113 — the migration ladder's core-relation gate. The sqlite ladder's
    // existence-probe arms SKIP a relation that is absent and the tail stamps
    // the tip regardless, so a POPULATED database that LOST a core relation
    // (corruption / partial file-level restore / operator DROP) "upgrades
    // successfully" with the integrity controls that stamp implies never
    // applied. Detection is unconditional in every posture; this pin makes a
    // CERTIFIED deployment REFUSE the stamp rather than warn — the #3033
    // "asi-hard no-disable" contract applied to schema integrity.
    //
    // Safe to pin ON: refusal treats `Some(0)` (empty corpus) as no-brick, so
    // a fresh or archive-less hardened deployment is never refused, and the
    // refusal itself mutates nothing — it rolls the ladder back and leaves
    // the database readable at its old version. An *unreadable* corpus
    // (`None` / failed COUNT) does refuse under this pin (#3246).
    KnobSpec {
        env: crate::config::ENV_MIGRATION_REQUIRE_CORE_TABLES,
        hard_value: "1",
        meets_floor: is_truthy,
    },
    // #3168 — three residual #3033 knobs that #3094 left un-pinned.
    // Certified deployments already refuse them via
    // `enterprise_federation_posture` (checks #7 / #8 / #18) when
    // `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` is set; plain
    // `asi-hard` is the hole: `PERMISSIONS_MODE=off` boots with
    // `db::enforce_governance` OFF, `GOVERNANCE_FAIL_OPEN_ON_ERROR` can
    // arm fail-OPEN, and `FED_REQUIRE_POLICY_CURRENT` can be disabled.
    // Each `meets_floor` delegates to the SAME grammar the live reader
    // uses (NB1 / #3033 lesson — never a naive `is_truthy`).
    KnobSpec {
        env: crate::config::AppConfig::ENV_PERMISSIONS_MODE,
        hard_value: "enforce",
        meets_floor: permissions_mode_meets_floor,
    },
    KnobSpec {
        env: crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN,
        hard_value: "",
        meets_floor: governance_fail_open_hatch_meets_floor,
    },
    KnobSpec {
        env: crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
        hard_value: "1",
        meets_floor: crate::federation::receive_auth::flag_value_default_on,
    },
    // #3201 — two federation escape hatches that the already-pinned
    // outer-transport gates do not cover. `REQUIRE_PEER_ENROLLMENT` is
    // pinned ON, but `ALLOW_UNENROLLED_PEERS=1` still opens the
    // `(None,None)` arm (`require_peer_enrollment_enabled() &&
    // !allow_unenrolled_peers_enabled()`). `FED_CERT_PEER_BINDING` still
    // defaulted to Warn and fail-opened to Warn on a typo. Certified
    // deployments refuse the unenrolled hatch via
    // `enterprise_federation_posture` check #3 only when
    // `AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE` is set; plain
    // `asi-hard` is the hole. The documented `standard` unset default
    // for cert-peer-binding stays Warn — only this pin tightens it.
    KnobSpec {
        env: crate::handlers::federation_signing_check::ALLOW_UNENROLLED_PEERS_ENV,
        hard_value: "",
        meets_floor: unenrolled_peers_hatch_meets_floor,
    },
    KnobSpec {
        env: crate::tls::FED_CERT_PEER_BINDING_ENV,
        hard_value: "enforce",
        meets_floor: cert_peer_binding_meets_floor,
    },
];

/// The number of env knobs `asi-hard` pins — ONE named SSOT for a count that
/// the module doc table, `docs/deploy/asi-hard.env`, the enterprise-federation
/// certification doc, `scripts/check-bootstrap-cert-gate.sh` and
/// `src/enterprise_federation_posture.rs` all quote in prose.
///
/// Derived from [`KNOBS`], so adding a knob moves it automatically. The prose
/// sites cannot derive it, which is exactly how they drifted (the table sat two
/// rows behind for an entire release); `scripts/check-docs-vs-ssot.sh` resolves
/// this same count from source and fails the build when a prose site disagrees.
pub const PINNED_KNOB_COUNT: usize = KNOBS.len();

/// What happened to one knob during enforcement (for the boot log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinAction {
    /// The knob was unset; the posture pinned it to the hard value.
    PinnedFromUnset,
    /// The operator had already set the knob at-or-above the hard floor.
    AlreadyCompliant,
}

/// One knob's enforcement outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinReport {
    /// The env var pinned.
    pub env: &'static str,
    /// The effective (hard) value now in force.
    pub effective: &'static str,
    /// Whether it was pinned from unset or was already compliant.
    pub action: PinAction,
}

/// The pinned-knob set as `(env, hard_value)` pairs — for docs / tests /
/// operator tooling that wants to enumerate the hardened posture.
#[must_use]
pub fn pinned_knobs() -> Vec<(&'static str, &'static str)> {
    KNOBS.iter().map(|k| (k.env, k.hard_value)).collect()
}

/// v1.0.0 §5.3 (3x7 cutline ruling, `docs/audit/3x7-v1-cutline-ruling-2026-08-01.md`)
/// — READ-ONLY enumeration of pinned `asi-hard` knobs currently set BELOW
/// their hard floor. An unset knob is never reported here (it is
/// compliant-by-pin-on-boot under [`enforce_at_boot`]; a caller that
/// needs "is asi-hard actually engaged AND every knob compliant" should
/// pair this with [`is_asi_hard`]).
///
/// Deliberately does **not** mutate the environment — unlike
/// [`enforce_at_boot`], which may only run in the synchronous
/// pre-runtime phase of `fn main()` (#2386), this is safe to call from
/// any live process (e.g. `ai-memory doctor --posture
/// enterprise-federation`, which reuses this as ONE SSOT for the 27
/// `asi-hard` pinned knobs rather than re-deriving the KNOBS table).
///
/// Returns `(env, current_value, hard_value)` triples.
#[must_use]
pub fn asi_hard_below_floor() -> Vec<(&'static str, String, &'static str)> {
    KNOBS
        .iter()
        .filter_map(|k| match std::env::var(k.env) {
            Ok(current) if !(k.meets_floor)(&current) => Some((k.env, current, k.hard_value)),
            _ => None,
        })
        .collect()
}

/// Enforce the resolved posture at daemon boot.
///
/// Under [`SecurityPosture::Standard`] this is a no-op returning an empty
/// report. Under [`SecurityPosture::AsiHard`] it applies the
/// pin-and-refuse contract described in the module docs and returns the
/// per-knob [`PinReport`]s (for the boot log). A loosening attempt (a knob
/// set BELOW its hard floor) is a hard error — the daemon must not boot.
///
/// # Errors
/// - The posture token is unrecognised (fail-loud).
/// - Under `asi-hard`, any pinned knob is set to a value below its hard
///   floor (the "no-disable" refusal).
pub fn enforce_at_boot() -> Result<(SecurityPosture, Vec<PinReport>)> {
    let posture = SecurityPosture::resolve()?;
    if posture == SecurityPosture::Standard {
        return Ok((posture, Vec::new()));
    }
    let mut reports = Vec::with_capacity(KNOBS.len());
    for knob in KNOBS {
        match std::env::var(knob.env) {
            Ok(current) => {
                if (knob.meets_floor)(&current) {
                    reports.push(PinReport {
                        env: knob.env,
                        effective: knob.hard_value,
                        action: PinAction::AlreadyCompliant,
                    });
                } else {
                    // The "no-disable" refusal — an operator selected the
                    // hardened posture AND tried to loosen a pinned knob.
                    // Fail CLOSED: refuse to boot rather than silently
                    // honour either the weak value or override it.
                    return Err(loosening_refusal(knob, &current));
                }
            }
            Err(_) => {
                // Unset → pin it. All the downstream read sites resolve the
                // knob from this same env var, so setting it here makes the
                // hard posture take effect everywhere without touching any
                // read site.
                //
                // SAFETY: called ONLY from the synchronous single-threaded
                // pre-runtime phase of the binary's `fn main()` (via
                // `enforce_at_boot_pre_runtime`, the same #1889 contract as
                // `apply_startup_env`) — BEFORE the tracing appender worker
                // or any tokio runtime worker thread exists — so no other
                // thread can be reading the environment concurrently
                // (#2386; the pre-fix call site inside the async
                // `daemon_runtime::run` body ran on the LIVE multi-threaded
                // runtime and re-introduced the #1889 data-race class). The
                // async body re-checks READ-ONLY via `runtime_boot_report`.
                unsafe {
                    std::env::set_var(knob.env, knob.hard_value);
                }
                reports.push(PinReport {
                    env: knob.env,
                    effective: knob.hard_value,
                    action: PinAction::PinnedFromUnset,
                });
            }
        }
    }
    Ok((posture, reports))
}

/// The "no-disable" refusal for a pinned knob set below its hard floor.
/// Single message-construction site shared by [`enforce_at_boot`] and the
/// read-only [`runtime_boot_report`] re-derivation so the operator-facing
/// refusal text cannot drift between the two paths (#2386).
fn loosening_refusal(knob: &KnobSpec, current: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{ASI_HARD_REFUSAL_PREFIX} refuses to disable {knob}: \
         it is set to {current:?} which is below the required hard \
         floor {hard:?}. Remove the {knob} override (asi-hard pins \
         it) or raise it to {hard:?}.",
        knob = knob.env,
        hard = knob.hard_value,
    )
}

/// The boot enforcement outcome stashed by [`enforce_at_boot_pre_runtime`]
/// so the async dispatch body can LOG it without re-running the
/// environment-mutating enforcement on the live runtime (#2386).
static BOOT_ENFORCEMENT: OnceLock<(SecurityPosture, Vec<PinReport>)> = OnceLock::new();

/// Pre-runtime entry point for the posture enforcement (#2386).
///
/// MUST be called from the synchronous, still-single-threaded phase of the
/// binary's `fn main()` — before the tracing appender worker or the tokio
/// runtime is built — because [`enforce_at_boot`]'s knob pinning writes
/// the process environment (`std::env::set_var`), which is a data race the
/// moment any other thread exists (the closed-#1889 class). Stashes the
/// report for [`runtime_boot_report`] to log later. Idempotent — first
/// writer wins, mirroring the other boot-seeded process-wide knobs.
///
/// # Errors
/// Propagates every [`enforce_at_boot`] refusal: an unrecognised posture
/// token, or (under `asi-hard`) a pinned knob set below its hard floor.
pub fn enforce_at_boot_pre_runtime() -> Result<()> {
    let report = enforce_at_boot()?;
    let _ = BOOT_ENFORCEMENT.set(report);
    Ok(())
}

/// READ-ONLY posture report for the async dispatch body (#2386).
///
/// Returns the report stashed by [`enforce_at_boot_pre_runtime`] when the
/// process booted through the binary's `fn main()`. For a direct library
/// caller of `daemon_runtime::run` (where no pre-runtime phase ran) it
/// re-derives the report WITHOUT touching the environment — every knob is
/// only READ, so this is safe on a live multi-threaded runtime. In that
/// fallback, fail CLOSED: under `asi-hard` a knob that is still UNSET here
/// means the pre-runtime pin never ran and cannot be applied safely from
/// async context, so refuse to boot rather than silently run with a
/// weakened posture (degrade loudly, never a silent security downgrade).
///
/// # Errors
/// - The posture token is unrecognised (fail-loud).
/// - Under `asi-hard`, a pinned knob is set below its hard floor.
/// - Under `asi-hard`, a pinned knob is UNSET and the pre-runtime
///   enforcement did not run (pinning from async context is the #1889
///   data-race class, so it is refused instead).
pub fn runtime_boot_report() -> Result<(SecurityPosture, Vec<PinReport>)> {
    if let Some((posture, pins)) = BOOT_ENFORCEMENT.get() {
        return Ok((*posture, pins.clone()));
    }
    let posture = SecurityPosture::resolve()?;
    if posture == SecurityPosture::Standard {
        return Ok((posture, Vec::new()));
    }
    let mut reports = Vec::with_capacity(KNOBS.len());
    for knob in KNOBS {
        match std::env::var(knob.env) {
            Ok(current) if (knob.meets_floor)(&current) => reports.push(PinReport {
                env: knob.env,
                effective: knob.hard_value,
                action: PinAction::AlreadyCompliant,
            }),
            Ok(current) => return Err(loosening_refusal(knob, &current)),
            Err(_) => bail!(
                "{ASI_HARD_REFUSAL_PREFIX} requires {knob} to be pinned before \
                 the async runtime starts, but the pre-runtime enforcement never ran \
                 (direct `daemon_runtime::run` caller?). Boot through the ai-memory \
                 binary, or set {knob}={hard:?} explicitly before starting (#2386).",
                knob = knob.env,
                hard = knob.hard_value,
            ),
        }
    }
    Ok((posture, reports))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize env mutations against every other `AI_MEMORY_*`-mutating
    /// test in the crate, not just this module's own tests (#2159, residual
    /// of the #1998→#2115→#2127 env-isolation class). A module-local mutex
    /// only covers this module's own `--test-threads>1` races; it still
    /// races the shared `test_env_lock` cohort in `src/embeddings.rs` /
    /// `src/reranker.rs` / `src/config.rs` / `src/cli/commands/config.rs` /
    /// `src/cli/rules.rs` / `src/recover/transcript_paths.rs`, so this
    /// delegates to the single crate-canonical
    /// [`crate::config::test_env_lock`]. Every knob this module pins
    /// (including `AI_MEMORY_REQUIRE_ROLLBACK_CHECK`) is a process-global
    /// env var a concurrently-running test elsewhere in the `--lib` binary
    /// (e.g. `routines::tests`) can observe mid-mutation without this.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::config::test_env_lock()
    }

    /// Clear every knob env var + the profile selector so a test starts
    /// from a known-unset baseline.
    ///
    /// # Safety
    /// Caller must hold [`env_lock`].
    unsafe fn clear_all() {
        unsafe {
            std::env::remove_var(ENV_SECURITY_PROFILE);
            for (env, _) in pinned_knobs() {
                std::env::remove_var(env);
            }
        }
    }

    /// RAII guard: on drop, clears every knob + the profile selector.
    /// Installed immediately after the entry-state `clear_all()` in every
    /// test below so a mid-test panic (an `assert!`/`unwrap()` failure)
    /// still restores the baseline instead of leaking a pinned knob (e.g.
    /// `AI_MEMORY_REQUIRE_ROLLBACK_CHECK=1`) into whatever test runs next
    /// in the same `--lib` process (#2159). Must be declared AFTER the
    /// `env_lock()` guard in each test so it drops (and clears) BEFORE the
    /// lock releases.
    struct KnobsGuard;
    impl Drop for KnobsGuard {
        fn drop(&mut self) {
            // SAFETY: constructed only while the caller holds `env_lock()`.
            unsafe { clear_all() };
        }
    }

    #[test]
    fn parse_accepts_known_tokens_rejects_typos() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::parse_accepts_known_tokens_rejects_typos",
        ) {
            return;
        }
        assert_eq!(
            SecurityPosture::parse("").unwrap(),
            SecurityPosture::Standard
        );
        assert_eq!(
            SecurityPosture::parse("standard").unwrap(),
            SecurityPosture::Standard
        );
        assert_eq!(
            SecurityPosture::parse("ASI-HARD").unwrap(),
            SecurityPosture::AsiHard
        );
        assert_eq!(
            SecurityPosture::parse("asi_hard").unwrap(),
            SecurityPosture::AsiHard
        );
        assert!(SecurityPosture::parse("asi-hardx").is_err());
    }

    #[test]
    fn standard_posture_is_a_noop() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::standard_posture_is_a_noop",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe { clear_all() };
        let _cleanup = KnobsGuard;
        let (posture, reports) = enforce_at_boot().unwrap();
        assert_eq!(posture, SecurityPosture::Standard);
        assert!(reports.is_empty(), "standard posture must pin nothing");
        // No knob was set.
        for (env, _) in pinned_knobs() {
            assert!(std::env::var(env).is_err(), "{env} must remain unset");
        }
    }

    #[test]
    fn asi_hard_actually_enables_the_migration_core_relation_gate() {
        // #3113 END-TO-END. `asi_hard_pins_documented_set` proves the knob is
        // in the KNOBS table; this proves the pin has its INTENDED EFFECT —
        // that after boot enforcement the migration ladder's own reader
        // returns true, so a certified deployment really does refuse to stamp
        // a schema version whose core relations were lost. The reader is a
        // DIRECT env read (the ladder runs before the boot-seeded config
        // globals exist), so "pinned in a table" and "in force at the read
        // site" are genuinely separate claims and the second is the one the
        // cert language rests on.
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_actually_enables_the_migration_core_relation_gate",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = KnobsGuard;

        // Baseline: with no posture the gate reports only, never refuses.
        assert!(
            !crate::config::migration_require_core_tables(),
            "the default posture must be report-only"
        );

        unsafe {
            std::env::set_var(ENV_SECURITY_PROFILE, "asi-hard");
        }
        let (posture, _reports) = enforce_at_boot().unwrap();
        assert_eq!(posture, SecurityPosture::AsiHard);
        assert!(
            crate::config::migration_require_core_tables(),
            "asi-hard must leave the migration core-relation gate ENFORCING at its \
             read site, not merely listed in KNOBS (#3113)"
        );
    }

    #[test]
    fn asi_hard_pins_every_unset_knob() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_pins_every_unset_knob",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = KnobsGuard;
        unsafe {
            std::env::set_var(ENV_SECURITY_PROFILE, "asi-hard");
        }
        let (posture, reports) = enforce_at_boot().unwrap();
        assert_eq!(posture, SecurityPosture::AsiHard);
        assert_eq!(reports.len(), pinned_knobs().len());
        for (env, hard) in pinned_knobs() {
            assert_eq!(
                std::env::var(env).ok().as_deref(),
                Some(hard),
                "{env} must be pinned to {hard}"
            );
        }
        // Durability is pinned to FULL (part C tie-in).
        assert_eq!(
            crate::storage::db_synchronous(),
            "FULL",
            "asi-hard must pin PRAGMA synchronous to FULL"
        );
        assert!(is_asi_hard());
    }

    #[test]
    fn asi_hard_accepts_already_compliant_values() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_accepts_already_compliant_values",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = KnobsGuard;
        unsafe {
            std::env::set_var(ENV_SECURITY_PROFILE, "asi-hard");
            // Operator already set the hard value (and a STRONGER one for
            // synchronous) — must be accepted, not refused.
            std::env::set_var("AI_MEMORY_SECRET_SCREEN_MODE", "refuse");
            std::env::set_var("AI_MEMORY_DB_SYNCHRONOUS", "EXTRA");
        }
        let (_p, reports) = enforce_at_boot().unwrap();
        let screen = reports
            .iter()
            .find(|r| r.env == "AI_MEMORY_SECRET_SCREEN_MODE")
            .unwrap();
        assert_eq!(screen.action, PinAction::AlreadyCompliant);
        let sync = reports
            .iter()
            .find(|r| r.env == crate::storage::ENV_DB_SYNCHRONOUS)
            .unwrap();
        assert_eq!(sync.action, PinAction::AlreadyCompliant);
        // EXTRA (stronger than FULL) is preserved, not overwritten.
        assert_eq!(std::env::var("AI_MEMORY_DB_SYNCHRONOUS").unwrap(), "EXTRA");
    }

    #[test]
    fn asi_hard_refuses_a_loosening_override() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_refuses_a_loosening_override",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = KnobsGuard;
        unsafe {
            std::env::set_var(ENV_SECURITY_PROFILE, "asi-hard");
            // Attempt to DISABLE the credential screen under asi-hard.
            std::env::set_var("AI_MEMORY_SECRET_SCREEN_MODE", "off");
        }
        let err = enforce_at_boot().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("asi-hard") && msg.contains("AI_MEMORY_SECRET_SCREEN_MODE"),
            "refusal must name the posture + knob: {msg}"
        );
    }

    #[test]
    fn asi_hard_refuses_a_falsy_boolean_override() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_refuses_a_falsy_boolean_override",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = KnobsGuard;
        unsafe {
            std::env::set_var(ENV_SECURITY_PROFILE, "asi-hard");
            std::env::set_var("AI_MEMORY_REQUIRE_WITNESS", "0");
        }
        let err = enforce_at_boot().unwrap_err();
        assert!(format!("{err}").contains("AI_MEMORY_REQUIRE_WITNESS"));
    }

    /// The env-knob names listed in this module's own `## Pinned knobs`
    /// markdown table, in table order.
    ///
    /// Parsed out of this file's SOURCE rather than a hand-maintained copy, so
    /// the assertion below cannot drift from the table it is checking.
    /// `include_str!` embeds the file at compile time and cargo tracks it as a
    /// build input, so editing a row re-runs this test.
    fn documented_pinned_knob_names() -> Vec<&'static str> {
        const SRC: &str = include_str!("security_profile.rs");
        SRC.lines()
            .filter_map(|line| {
                // A table DATA row is ``//! | `AI_MEMORY_X` | ... |``. The
                // header (`| Env knob | ...`) and the `|---|---|---|`
                // separator have no backticked first cell, so they drop out
                // here. Deliberately NOT filtered on an `AI_MEMORY_` prefix: a
                // typo'd row must surface as set-difference drift, not be
                // silently skipped.
                let rest = line.strip_prefix("//! |")?.trim_start();
                let (name, _) = rest.strip_prefix('`')?.split_once('`')?;
                Some(name)
            })
            .collect()
    }

    #[test]
    fn pinned_knobs_doc_table_matches_the_knobs_ssot_exactly() {
        // #3113 — the DURABLE fix for the drift this branch found by hand: the
        // `## Pinned knobs` table had silently fallen TWO rows behind `KNOBS`
        // (missing FED_REQUIRE_TRANSITION_SIG + FED_REQUIRE_CHECKPOINT_SIG),
        // and nothing failed. A count-only check would not have caught it
        // either, because the count lives in prose that drifted with it. This
        // asserts SET EQUALITY in BOTH directions, so a knob added to `KNOBS`
        // without a row — or a row for a knob that is not actually pinned,
        // which is the more dangerous direction (the docs would advertise a
        // hardening guarantee the binary does not enforce) — fails here.
        use std::collections::BTreeSet;

        let rows = documented_pinned_knob_names();
        let documented: BTreeSet<&str> = rows.iter().copied().collect();
        let actual: BTreeSet<&str> = KNOBS.iter().map(|k| k.env).collect();

        // A name listed twice would let the sets match while the table
        // over-states the pinned set.
        assert_eq!(
            rows.len(),
            documented.len(),
            "duplicate row in the `## Pinned knobs` table: {rows:?}"
        );

        let undocumented: Vec<&str> = actual.difference(&documented).copied().collect();
        assert!(
            undocumented.is_empty(),
            "pinned by KNOBS but MISSING a `## Pinned knobs` table row: {undocumented:?} \
             — add the row in the same commit that adds the knob"
        );

        let phantom: Vec<&str> = documented.difference(&actual).copied().collect();
        assert!(
            phantom.is_empty(),
            "documented as pinned but ABSENT from KNOBS: {phantom:?} — the docs would \
             advertise a hardening guarantee the binary does not enforce"
        );

        // Implied by set equality, but pins the NUMBER the module docstrings,
        // `docs/deploy/asi-hard.env` and the cert doc quote.
        assert_eq!(documented.len(), KNOBS.len());
    }

    /// The env-knob names in `PERFORMANCE.md`'s `## Hardened \`asi-hard\`
    /// security posture` "Pinned knobs" table, in table order.
    ///
    /// SECTION-SCOPED deliberately. `PERFORMANCE.md` carries OTHER tables
    /// whose first cell is a backticked `AI_MEMORY_*` name (the read-path
    /// degrade-budget table a few sections up), so a whole-file scan would
    /// fold those in and report phantom drift against `KNOBS`. The parse
    /// starts at this section's heading and stops at the next `## ` heading.
    ///
    /// FAILS CLOSED in both no-data directions: a missing heading panics and
    /// an empty row set panics, rather than yielding an empty set. An empty
    /// set would make the set-equality assertion below silently VACUOUS the
    /// moment the section is renamed or the table reformatted — which is
    /// exactly the "reports success while doing nothing" shape this change
    /// exists to remove, and it would be indistinguishable from a pass.
    fn performance_md_pinned_knob_names() -> Vec<&'static str> {
        const SRC: &str = include_str!("../PERFORMANCE.md");
        const HEADING: &str = "## Hardened `asi-hard` security posture";

        let Some(start) = SRC.lines().position(|l| l.starts_with(HEADING)) else {
            panic!(
                "PERFORMANCE.md has no `{HEADING}` section — the pinned-knob table \
                 cannot be located, so this gate would be vacuous"
            )
        };

        let rows: Vec<&'static str> = SRC
            .lines()
            .skip(start + 1)
            .take_while(|l| !l.starts_with("## "))
            .filter_map(|line| {
                // A DATA row is ``| `AI_MEMORY_X` | ... |``. The header
                // (`| Env knob | ...`) has no backticked first cell and the
                // `|---|---|` separator has no space after the pipe, so both
                // drop out here. Deliberately NOT filtered on an
                // `AI_MEMORY_` prefix: a typo'd row must surface as
                // set-difference drift, not be silently skipped.
                let rest = line.strip_prefix("| ")?;
                let (name, _) = rest.strip_prefix('`')?.split_once('`')?;
                Some(name)
            })
            .collect();

        assert!(
            !rows.is_empty(),
            "the `{HEADING}` section carries no `| `ENV` |` table rows — refusing \
             to report a vacuous pass"
        );
        rows
    }

    #[test]
    fn performance_md_pinned_knobs_table_matches_the_knobs_ssot_exactly() {
        // #3113 — the SECOND documented pinned-knob table, pinned the same way
        // as the module doc table above. `PERFORMANCE.md`'s §"Hardened
        // `asi-hard` security posture" table is what CLAUDE.md env row #130
        // sends an operator to by name, and it had fallen SEVEN rows behind
        // `KNOBS` (no row for the four #3033 outer-transport gates, neither
        // PERMISSIVE-shaped pin, nor the #3113 schema-integrity pin) with
        // nothing failing — a procurement-facing document describing a WEAKER
        // hardened posture than the binary actually enforces.
        use std::collections::BTreeSet;

        let rows = performance_md_pinned_knob_names();
        let documented: BTreeSet<&str> = rows.iter().copied().collect();
        let actual: BTreeSet<&str> = KNOBS.iter().map(|k| k.env).collect();

        // A name listed twice would let the sets match while the table
        // over-states the pinned set.
        assert_eq!(
            rows.len(),
            documented.len(),
            "duplicate row in the PERFORMANCE.md pinned-knobs table: {rows:?}"
        );

        let undocumented: Vec<&str> = actual.difference(&documented).copied().collect();
        assert!(
            undocumented.is_empty(),
            "pinned by KNOBS but MISSING a PERFORMANCE.md pinned-knobs row: \
             {undocumented:?} — add the row in the same commit that adds the knob"
        );

        let phantom: Vec<&str> = documented.difference(&actual).copied().collect();
        assert!(
            phantom.is_empty(),
            "documented in PERFORMANCE.md as pinned but ABSENT from KNOBS: \
             {phantom:?} — the docs would advertise a hardening guarantee the \
             binary does not enforce"
        );

        assert_eq!(documented.len(), PINNED_KNOB_COUNT);
    }

    #[test]
    fn asi_hard_pins_documented_set() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_pins_documented_set",
        ) {
            return;
        }
        // The pinned set must match the documented count so the module
        // docs table and the KNOBS SSOT cannot silently drift. Asserting
        // against [`PINNED_KNOB_COUNT`] rather than a literal is deliberate:
        // the literal was the ONE place the count had to be hand-bumped, and
        // a hand-bumped number is exactly what drifted (#3113). The pin is
        // not weakened by dropping it — the count is enforced against the
        // module doc TABLE on the next line, against the table by SET
        // equality in `pinned_knobs_doc_table_matches_the_knobs_ssot_exactly`,
        // and against every PROSE site by the ASI_HARD_PINNED_KNOB_COUNT rule
        // in `scripts/check-docs-vs-ssot.sh`.
        let pins = pinned_knobs();
        assert_eq!(
            pins.len(),
            PINNED_KNOB_COUNT,
            "pinned_knobs() must enumerate every KNOBS entry, unfiltered"
        );
        assert_eq!(
            documented_pinned_knob_names().len(),
            PINNED_KNOB_COUNT,
            "the `## Pinned knobs` module doc table must carry one row per KNOBS entry"
        );
        // Every pin's env name is non-empty and the durability pin is FULL.
        assert!(pins.iter().all(|(e, _)| !e.is_empty()));
        assert!(
            pins.iter()
                .any(|(e, v)| *e == crate::storage::ENV_DB_SYNCHRONOUS && *v == "FULL")
        );
        // #2448 — the hardened posture pins a NETWORK access-control knob:
        // outbound federation TLS must verify the peer's SERVER cert. Before
        // #2448 the pinned set was 100% crypto/attestation/durability, so an
        // `asi-hard` deployment could still run `ai-memory sync-daemon
        // --insecure-skip-server-verify` and push plaintext memory content to
        // an unauthenticated server.
        assert!(
            pins.iter()
                .any(|(e, v)| *e == crate::tls::FED_REQUIRE_SERVER_VERIFY_ENV && *v == "1"),
            "asi-hard must pin outbound server-cert verification (#2448)"
        );
        // #3113 — the first SCHEMA-INTEGRITY pin. The migration ladder's
        // existence-probe arms fail OPEN: a populated database that lost a
        // core relation stamps the tip anyway, with the integrity controls
        // that stamp implies never applied. A certified deployment must
        // REFUSE that stamp, not merely warn about it.
        assert!(
            pins.iter()
                .any(|(e, v)| *e == crate::config::ENV_MIGRATION_REQUIRE_CORE_TABLES && *v == "1"),
            "asi-hard must pin the migration core-relation gate (#3113)"
        );
        // #2477 — the SECOND network access-control pin, and the second
        // PERMISSIVE one (hard floor = the hatch is NOT in force). Without
        // it, `docs/deploy/asi-hard.env` verbatim still permitted
        // `--quorum-peers http://peer:9077`, replicating memory CONTENT in
        // the clear — strictly weaker than the accept-any-cert case #2448
        // closed one door over.
        assert!(
            pins.iter()
                .any(|(e, v)| *e == crate::tls::FED_ALLOW_PLAINTEXT_PEERS_ENV && v.is_empty()),
            "asi-hard must pin the plaintext-peer hatch OFF (#2477)"
        );
        // #3168 — three residual #3033 knobs. Certified deployments already
        // refuse them via enterprise_federation_posture; plain asi-hard is
        // the hole. PERMISSIONS_MODE pins to enforce (not a naive truthy
        // floor — only the live token `enforce` meets it). The
        // GOVERNANCE_FAIL_OPEN hatch pins CLOSED (hard_value empty).
        // REQUIRE_POLICY_CURRENT pins ON via the live default-ON grammar
        // (the live name is `AI_MEMORY_FED_REQUIRE_POLICY_CURRENT`).
        assert!(
            pins.iter().any(
                |(e, v)| *e == crate::config::AppConfig::ENV_PERMISSIONS_MODE && *v == "enforce"
            ),
            "asi-hard must pin AI_MEMORY_PERMISSIONS_MODE to enforce (#3168)"
        );
        assert!(
            pins.iter().any(
                |(e, v)| *e == crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN && v.is_empty()
            ),
            "asi-hard must pin the governance fail-OPEN hatch OFF (#3168)"
        );
        assert!(
            pins.iter().any(|(e, v)| {
                *e == crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV && *v == "1"
            }),
            "asi-hard must pin AI_MEMORY_FED_REQUIRE_POLICY_CURRENT ON (#3168)"
        );
        // #3201 — unenrolled-peer hatch of the already-pinned
        // REQUIRE_PEER_ENROLLMENT, and cert↔peer-id binding Enforce.
        assert!(
            pins.iter().any(|(e, v)| {
                *e == crate::handlers::federation_signing_check::ALLOW_UNENROLLED_PEERS_ENV
                    && v.is_empty()
            }),
            "asi-hard must pin the unenrolled-peer hatch OFF (#3201)"
        );
        assert!(
            pins.iter()
                .any(|(e, v)| *e == crate::tls::FED_CERT_PEER_BINDING_ENV && *v == "enforce"),
            "asi-hard must pin AI_MEMORY_FED_CERT_PEER_BINDING to enforce (#3201)"
        );
        // #3033 — the FOUR OUTER federation-transport gates are pinned ON, so
        // the "no-disable" contract covers the outermost network
        // access-control gates (per-message sig + nonce, enrolled-peer
        // identity, inbound-write namespace confinement), not only the inner
        // per-object attestation. Before #3033 an `asi-hard` deployment could
        // still set e.g. `AI_MEMORY_FED_REQUIRE_SIG=0` and accept UNSIGNED
        // inbound federation requests while advertising the no-disable posture.
        for env in [
            crate::federation::signing::REQUIRE_SIG_ENV,
            crate::federation::signing::REQUIRE_NONCE_ENV,
            crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
            crate::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
        ] {
            assert!(
                pins.iter().any(|(e, v)| *e == env && *v == "1"),
                "asi-hard must pin the outer-transport gate {env} ON (#3033)"
            );
        }
    }

    /// #3033 — `asi-hard` REFUSES to boot when an operator tries to DISABLE
    /// any of the four outer federation-transport gates. Exercises the
    /// default-ON grammar delegation directly: a case-sensitive falsy token
    /// (`0`) loosens the `env_flag_default_on` gates, and a case-INSENSITIVE
    /// falsy token (`FALSE`) loosens the peer-enrollment gate — each must be
    /// caught as a below-floor override and refuse boot.
    #[test]
    fn asi_hard_refuses_disabling_outer_transport_gates() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_refuses_disabling_outer_transport_gates",
        ) {
            return;
        }
        // Each case: (env var, a value that DISABLES the live gate).
        let cases = [
            (crate::federation::signing::REQUIRE_SIG_ENV, "0"),
            (crate::federation::signing::REQUIRE_NONCE_ENV, "off"),
            (
                crate::federation::receive_auth::REQUIRE_PUSH_NAMESPACE_SCOPE_ENV,
                "false",
            ),
            // Case-INSENSITIVE for the peer-enrollment gate: `FALSE` disables
            // the live reader, so it must refuse boot (a case-sensitive
            // `flag_value_default_on` would MISS this — the grammars differ).
            (
                crate::handlers::federation_signing_check::REQUIRE_PEER_ENROLLMENT_ENV,
                "FALSE",
            ),
        ];
        for (env, disabling_value) in cases {
            let _g = env_lock();
            unsafe {
                clear_all();
            }
            let _cleanup = KnobsGuard;
            unsafe {
                std::env::set_var(ENV_SECURITY_PROFILE, "asi-hard");
                std::env::set_var(env, disabling_value);
            }
            let err = enforce_at_boot().unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.contains("asi-hard") && msg.contains(env),
                "refusal must name the posture + the loosened gate {env}: {msg}"
            );
            // And the read-only accessor reports the same violation.
            let below = asi_hard_below_floor();
            assert!(
                below.iter().any(|(e, _, _)| *e == env),
                "asi_hard_below_floor must report the loosened gate {env}"
            );
        }
    }

    /// #3168 — `asi-hard` REFUSES to boot when an operator tries to turn
    /// governance OFF (`PERMISSIONS_MODE=off`), arm the fail-OPEN hatch,
    /// or disable the stale-policy refusal. Exercises the live-reader
    /// grammars: `off` is the exact live Off token (not a truthy invert);
    /// `"1"` arms fail-OPEN (the live `== "1"` arm); `"0"` disables the
    /// default-ON policy-current gate (the live `flag_value_default_on`
    /// falsy token).
    #[test]
    fn asi_hard_refuses_governance_loosening_3168() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_refuses_governance_loosening_3168",
        ) {
            return;
        }
        let cases = [
            (crate::config::AppConfig::ENV_PERMISSIONS_MODE, "off"),
            (crate::config::AppConfig::ENV_PERMISSIONS_MODE, "advisory"),
            (crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN, "1"),
            (crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN, "TRUE"),
            (
                crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
                "0",
            ),
            (
                crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
                "false",
            ),
        ];
        for (env, disabling_value) in cases {
            let _g = env_lock();
            unsafe {
                clear_all();
            }
            let _cleanup = KnobsGuard;
            unsafe {
                std::env::set_var(ENV_SECURITY_PROFILE, "asi-hard");
                std::env::set_var(env, disabling_value);
            }
            let err = enforce_at_boot().unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.contains("asi-hard") && msg.contains(env),
                "refusal must name the posture + the loosened knob {env}={disabling_value:?}: {msg}"
            );
            let below = asi_hard_below_floor();
            assert!(
                below.iter().any(|(e, _, _)| *e == env),
                "asi_hard_below_floor must report the loosened knob {env}"
            );
        }
    }

    /// #3168 — a value the LIVE reader would NOT treat as loosening must
    /// still boot. `PERMISSIONS_MODE=ENFORCE` (case-insensitive live
    /// match); `GOVERNANCE_FAIL_OPEN=yes` does NOT arm the live hatch
    /// (exact `"1"` / case-insensitive `"true"` only); `FED_REQUIRE_POLICY_CURRENT=FALSE`
    /// stays ON under the case-sensitive default-ON grammar.
    #[test]
    fn asi_hard_accepts_live_compliant_governance_values_3168() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_accepts_live_compliant_governance_values_3168",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = KnobsGuard;
        unsafe {
            std::env::set_var(ENV_SECURITY_PROFILE, "asi-hard");
            std::env::set_var(crate::config::AppConfig::ENV_PERMISSIONS_MODE, "ENFORCE");
            std::env::set_var(crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN, "yes");
            std::env::set_var(
                crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV,
                "FALSE",
            );
        }
        let (posture, reports) = enforce_at_boot().unwrap();
        assert_eq!(posture, SecurityPosture::AsiHard);
        assert!(
            reports.iter().any(|r| {
                r.env == crate::config::AppConfig::ENV_PERMISSIONS_MODE
                    && r.action == PinAction::AlreadyCompliant
            }),
            "ENFORCE must meet the permissions-mode floor"
        );
        assert!(
            reports.iter().any(|r| {
                r.env == crate::daemon_runtime::ENV_GOVERNANCE_FAIL_OPEN
                    && r.action == PinAction::AlreadyCompliant
            }),
            "yes must NOT be treated as arming the fail-OPEN hatch (live grammar)"
        );
        assert!(
            reports.iter().any(|r| {
                r.env == crate::federation::receive_auth::REQUIRE_POLICY_CURRENT_ENV
                    && r.action == PinAction::AlreadyCompliant
            }),
            "FALSE must keep the default-ON policy-current gate enabled (live grammar)"
        );
    }

    /// #3168 END-TO-END. Pinning the env is not the claim; the claim is
    /// that after boot enforcement the LIVE readers report the hard
    /// posture, so a certified (or plain-asi-hard) deployment really
    /// does enforce governance, keep fail-OPEN disarmed, and refuse a
    /// DETECTED-stale inbound policy_version.
    #[test]
    fn asi_hard_actually_enables_governance_floors_3168() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_actually_enables_governance_floors_3168",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = KnobsGuard;
        unsafe {
            std::env::set_var(ENV_SECURITY_PROFILE, "asi-hard");
        }
        let (posture, _reports) = enforce_at_boot().unwrap();
        assert_eq!(posture, SecurityPosture::AsiHard);
        assert_eq!(
            crate::config::AppConfig::default().effective_permissions_mode(),
            crate::config::PermissionsMode::Enforce,
            "asi-hard must leave the K3/K9 governance gate ENFORCING at its read site"
        );
        assert!(
            !crate::daemon_runtime::governance_fail_open_on_error(),
            "asi-hard must leave the governance fail-OPEN hatch DISARMED at its read site"
        );
        assert!(
            crate::federation::receive_auth::require_policy_current_enabled(),
            "asi-hard must leave the stale-policy refusal ON at its read site"
        );
    }

    /// #3201 — `asi-hard` REFUSES to boot when the unenrolled-peer hatch
    /// is armed, or when cert-peer-binding is anything other than
    /// `enforce` (including the typo `enforc` that previously fail-opened
    /// to Warn, and the documented `standard` default `warn`).
    #[test]
    fn asi_hard_refuses_federation_hatches_3201() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_refuses_federation_hatches_3201",
        ) {
            return;
        }
        let cases = [
            (
                crate::handlers::federation_signing_check::ALLOW_UNENROLLED_PEERS_ENV,
                "1",
            ),
            (
                crate::handlers::federation_signing_check::ALLOW_UNENROLLED_PEERS_ENV,
                "true",
            ),
            (crate::tls::FED_CERT_PEER_BINDING_ENV, "off"),
            (crate::tls::FED_CERT_PEER_BINDING_ENV, "warn"),
            (crate::tls::FED_CERT_PEER_BINDING_ENV, "enforc"),
        ];
        for (env, disabling_value) in cases {
            let _g = env_lock();
            unsafe {
                clear_all();
            }
            let _cleanup = KnobsGuard;
            unsafe {
                std::env::set_var(ENV_SECURITY_PROFILE, "asi-hard");
                std::env::set_var(env, disabling_value);
            }
            let err = enforce_at_boot().unwrap_err();
            let msg = format!("{err}");
            assert!(
                msg.contains("asi-hard") && msg.contains(env),
                "refusal must name the posture + the loosened knob {env}={disabling_value:?}: {msg}"
            );
            let below = asi_hard_below_floor();
            assert!(
                below.iter().any(|(e, _, _)| *e == env),
                "asi_hard_below_floor must report the loosened knob {env}"
            );
        }
    }

    /// #3201 END-TO-END. After pinning, the live unenrolled-peer hatch
    /// is CLOSED and cert-peer-binding resolves Enforce.
    #[test]
    fn asi_hard_actually_closes_federation_hatches_3201() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_actually_closes_federation_hatches_3201",
        ) {
            return;
        }
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = KnobsGuard;
        unsafe {
            std::env::set_var(ENV_SECURITY_PROFILE, "asi-hard");
        }
        let (posture, _reports) = enforce_at_boot().unwrap();
        assert_eq!(posture, SecurityPosture::AsiHard);
        assert!(
            !crate::handlers::federation_signing_check::allow_unenrolled_peers_enabled(),
            "asi-hard must leave the unenrolled-peer hatch CLOSED at its read site"
        );
        assert_eq!(
            crate::tls::cert_peer_binding_mode(),
            crate::tls::CertPeerBindingMode::Enforce,
            "asi-hard must leave cert↔peer-id binding ENFORCING at its read site"
        );
    }

    #[test]
    fn asi_hard_below_floor_is_read_only_and_reports_violations() {
        if crate::config::run_env_isolated_child_or_spawn(
            "security_profile::tests::asi_hard_below_floor_is_read_only_and_reports_violations",
        ) {
            return;
        }
        // v1.0.0 §5.3 cutline ruling — `enterprise_federation_posture`
        // reuses this accessor as the SSOT for the 27-knob asi-hard set
        // rather than re-deriving KNOBS; pin its own read-only contract
        // directly (in addition to the exhaustive coverage the
        // `enterprise_federation_posture::tests` module gives it
        // end-to-end).
        let _g = env_lock();
        unsafe {
            clear_all();
        }
        let _cleanup = KnobsGuard;
        // No posture engaged, no knobs set: nothing below floor (an
        // unset knob is compliant-by-pin-on-boot, never a violation).
        assert!(asi_hard_below_floor().is_empty());

        unsafe {
            std::env::set_var("AI_MEMORY_SECRET_SCREEN_MODE", "off");
        }
        let below = asi_hard_below_floor();
        assert_eq!(below.len(), 1, "exactly one knob was loosened: {below:?}");
        assert_eq!(below[0].0, "AI_MEMORY_SECRET_SCREEN_MODE");
        assert_eq!(below[0].1, "off");
        assert_eq!(below[0].2, "refuse");
        // Read-only: the call itself must never engage/pin the posture.
        assert!(std::env::var(ENV_SECURITY_PROFILE).is_err());
        assert!(!is_asi_hard());
    }
}
