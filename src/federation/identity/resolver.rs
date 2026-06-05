// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Federation identity resolution.
//!
//! Resolves the `sender_agent_id` a federation node signs and presents
//! itself as on the wire. Historically this was hardcoded at the daemon
//! bootstrap as `format!("host:{}", gethostname())`, coupling federation
//! identity to the OS hostname. That is unworkable for fleets that need
//! stable, trust-domain-scoped, rotatable identities (see ADR-001).
//!
//! This module makes the identity resolvable from explicit operator
//! configuration or the environment, **defaulting to the historical
//! `host:<hostname>` form** so existing single- and multi-node
//! deployments are byte-for-byte unaffected until they opt in.

use std::ffi::OsStr;

/// Environment variable that overrides the federation identity. Highest
/// precedence. Part of the `AI_MEMORY_FED_*` family (cf.
/// [`crate::federation::signing::REQUIRE_SIG_ENV`]).
pub const FED_IDENTITY_ENV: &str = "AI_MEMORY_FED_IDENTITY";

/// Prefix applied to the OS hostname when synthesising the default
/// identity. Preserves the historical `host:<hostname>` wire form so a
/// node that has not opted into explicit identity keeps the exact
/// identity it presented before this module existed.
pub const HOSTNAME_IDENTITY_PREFIX: &str = "host:";

/// Deterministic stand-in when the OS hostname cannot be read or is
/// empty (degenerate environments — e.g. a minimal container with no UTS
/// hostname). Keeps the daemon bootable with a stable identity rather
/// than emitting a bare `host:` that no peer can attribute.
pub const UNKNOWN_HOSTNAME_FALLBACK: &str = "unknown-host";

/// Resolve the federation identity using a fixed precedence:
///
/// 1. The [`FED_IDENTITY_ENV`] environment variable (non-empty after trim).
/// 2. `configured` — an operator-supplied identity (config file / the
///    declarative inventory introduced in a later phase).
/// 3. `host:<hostname>` — the historical default (behaviour-preserving).
///
/// Blank / whitespace-only candidates at a higher precedence are skipped
/// so an accidentally-empty override can never collapse the identity to
/// an empty string.
#[must_use]
pub fn resolve_federation_identity(configured: Option<&str>) -> String {
    if let Some(id) = env_identity() {
        return id;
    }
    if let Some(id) = non_empty(configured) {
        return id.to_string();
    }
    default_hostname_identity()
}

/// The historical default identity: `host:<hostname>`. Exposed so other
/// call sites (and tests) can assert behaviour-preservation against the
/// pre-resolver bootstrap expression.
#[must_use]
pub fn default_hostname_identity() -> String {
    let raw = gethostname::gethostname();
    format!("{HOSTNAME_IDENTITY_PREFIX}{}", hostname_component(&raw))
}

/// Read + sanitise the [`FED_IDENTITY_ENV`] override.
fn env_identity() -> Option<String> {
    let raw = std::env::var(FED_IDENTITY_ENV).ok()?;
    non_empty(Some(&raw)).map(str::to_string)
}

/// Render an OS hostname into the identity component, falling back to
/// [`UNKNOWN_HOSTNAME_FALLBACK`] when it is empty/whitespace.
fn hostname_component(host: &OsStr) -> String {
    let lossy = host.to_string_lossy();
    match non_empty(Some(&lossy)) {
        Some(name) => name.to_string(),
        None => UNKNOWN_HOSTNAME_FALLBACK.to_string(),
    }
}

/// `Some(trimmed)` when `s` is present and non-blank, else `None`.
fn non_empty(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the process-global env mutation across the env-var
    /// tests in this module (mirrors the lock discipline used by
    /// `federation::signing` and `governance::audit` tests).
    fn fed_identity_env_lock() -> &'static std::sync::Mutex<()> {
        static M: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        M.get_or_init(|| std::sync::Mutex::new(()))
    }

    struct EnvGuard {
        prior: Option<String>,
    }
    impl EnvGuard {
        fn set(value: &str) -> Self {
            let prior = std::env::var(FED_IDENTITY_ENV).ok();
            // SAFETY: process-wide env mutation serialised behind
            // `fed_identity_env_lock()` so concurrent tests cannot
            // observe a half-written override.
            unsafe { std::env::set_var(FED_IDENTITY_ENV, value) };
            Self { prior }
        }
        fn cleared() -> Self {
            let prior = std::env::var(FED_IDENTITY_ENV).ok();
            unsafe { std::env::remove_var(FED_IDENTITY_ENV) };
            Self { prior }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => unsafe { std::env::set_var(FED_IDENTITY_ENV, v) },
                None => unsafe { std::env::remove_var(FED_IDENTITY_ENV) },
            }
        }
    }

    #[test]
    fn default_matches_legacy_hostname_expression() {
        let _g = fed_identity_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::cleared();
        // The exact expression daemon_runtime used before this module.
        let legacy = format!("host:{}", gethostname::gethostname().to_string_lossy());
        assert_eq!(resolve_federation_identity(None), legacy);
        assert_eq!(default_hostname_identity(), legacy);
    }

    #[test]
    fn env_override_takes_precedence_over_config_and_default() {
        let _g = fed_identity_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::set("spiffe://fleet/region/nyc/node-7");
        assert_eq!(
            resolve_federation_identity(Some("config-identity")),
            "spiffe://fleet/region/nyc/node-7"
        );
    }

    #[test]
    fn blank_env_is_skipped_in_favour_of_config() {
        let _g = fed_identity_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::set("   ");
        assert_eq!(
            resolve_federation_identity(Some("config-identity")),
            "config-identity"
        );
    }

    #[test]
    fn config_used_when_env_absent() {
        let _g = fed_identity_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::cleared();
        assert_eq!(
            resolve_federation_identity(Some("  region/sfo/node-3  ")),
            "region/sfo/node-3"
        );
    }

    #[test]
    fn blank_config_falls_through_to_hostname_default() {
        let _g = fed_identity_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::cleared();
        let resolved = resolve_federation_identity(Some("   "));
        assert!(resolved.starts_with(HOSTNAME_IDENTITY_PREFIX));
        assert_eq!(resolved, default_hostname_identity());
    }

    #[test]
    fn env_value_is_trimmed() {
        let _g = fed_identity_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _env = EnvGuard::set("  trimmed-id  ");
        assert_eq!(resolve_federation_identity(None), "trimmed-id");
    }

    #[test]
    fn hostname_component_falls_back_when_empty() {
        assert_eq!(
            hostname_component(OsStr::new("   ")),
            UNKNOWN_HOSTNAME_FALLBACK
        );
        assert_eq!(hostname_component(OsStr::new("host-a")), "host-a");
    }
}
