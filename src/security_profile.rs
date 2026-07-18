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
//! | `AI_MEMORY_REQUIRE_AGENT_ATTESTATION` | `1` | unsigned direct writes refused on EVERY surface |
//! | `AI_MEMORY_FED_REQUIRE_WRITE_SIG` | `1` | inbound relayed memories must carry a verified per-write signature |
//! | `AI_MEMORY_FED_REQUIRE_SIGNAL_SIG` | `1` | inbound relayed signals must verify against the enrolled author key |
//! | `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED` | `1` | provenance-less inbound writes are quarantined, not accepted-visible |
//! | `AI_MEMORY_CID_ENFORCE` | `1` | content-id mismatch is WARN-enforced, not detect-only |
//! | `AI_MEMORY_REQUIRE_ROLLBACK_CHECK` | `1` | open-time rollback-evidence check fail-closed |
//! | `AI_MEMORY_REQUIRE_WITNESS` | `1` | audit-head witness required (fail-closed) |
//! | `AI_MEMORY_REQUIRE_CAUSE_BINDING` | `1` | audit rows must carry a bound cause |
//! | `AI_MEMORY_REQUIRE_ROLE_SEPARATION` | `1` | three-key governance role separation required |
//! | `AI_MEMORY_REQUIRE_IDENTITY_LINEAGE` | `1` | identity-lineage succession chain required |
//! | `AI_MEMORY_DB_SYNCHRONOUS` | `FULL` | power-loss durability (fsync every commit) — #1961 part C |
//!
//! In addition, `asi-hard` forces the config-backed governance knob
//! `[governance].require_operator_pubkey` to `true` (see
//! [`is_asi_hard`], consulted at the governance boot check).
//!
//! The federation transition + checkpoint signature knobs
//! (`AI_MEMORY_FED_REQUIRE_TRANSITION_SIG`, `AI_MEMORY_FED_REQUIRE_CHECKPOINT_SIG`)
//! already default fail-closed (`1`); `asi-hard` still refuses a loosening
//! override on them so the posture is complete.

use anyhow::{Result, bail};

/// Env var selecting the process-wide security posture.
pub const ENV_SECURITY_PROFILE: &str = "AI_MEMORY_SECURITY_PROFILE";

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
fn is_truthy(v: &str) -> bool {
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
        env: crate::storage::ENV_DB_SYNCHRONOUS,
        hard_value: "FULL",
        meets_floor: synchronous_meets_floor,
    },
];

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
                    bail!(
                        "security posture \"asi-hard\" refuses to disable {knob}: \
                         it is set to {current:?} which is below the required hard \
                         floor {hard:?}. Remove the {knob} override (asi-hard pins \
                         it) or raise it to {hard:?}.",
                        knob = knob.env,
                        hard = knob.hard_value,
                    );
                }
            }
            Err(_) => {
                // Unset → pin it. All the downstream read sites resolve the
                // knob from this same env var, so setting it here makes the
                // hard posture take effect everywhere without touching any
                // read site.
                //
                // SAFETY: called once at daemon boot from the single-threaded
                // configuration-resolution phase (before `serve` spawns the
                // HTTP task pool / background sweeps), so no other thread can
                // be reading the environment concurrently. Mirrors the
                // existing `unsafe { std::env::set_var(...) }` boot/test
                // sites in `daemon_runtime.rs`.
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
    fn asi_hard_pins_every_unset_knob() {
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

    #[test]
    fn asi_hard_pins_documented_set() {
        // The pinned set must match the documented count so the module
        // docs table and the KNOBS SSOT cannot silently drift.
        let pins = pinned_knobs();
        assert_eq!(pins.len(), 14, "documented asi-hard knob count");
        // Every pin's env name is non-empty and the durability pin is FULL.
        assert!(pins.iter().all(|(e, _)| !e.is_empty()));
        assert!(
            pins.iter()
                .any(|(e, v)| *e == crate::storage::ENV_DB_SYNCHRONOUS && *v == "FULL")
        );
    }
}
