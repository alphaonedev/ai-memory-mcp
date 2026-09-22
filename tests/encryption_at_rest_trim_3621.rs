// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3621 — `AI_MEMORY_ENCRYPT_AT_REST` is trimmed before it is matched.
//!
//! `encryption_enabled` lowercased the value but did not `trim()` it, while
//! its three sibling truthy parsers (`security_profile`,
//! `enterprise_federation_posture`, `erasure`) all
//! `trim().to_ascii_lowercase()`. That made it the ONE truthy knob that fails
//! OPEN: a value it does not recognise leaves at-rest content encryption OFF,
//! so a whitespace-padded value — a shell heredoc, an env file with a trailing
//! space, a copy-paste — silently shipped plaintext for data the operator
//! asked to encrypt.
//!
//! The pin lives in its OWN test binary, not the lib's `mod tests`: it
//! mutates a process-global env var, and the lib binary runs every other
//! test in the same process (the #3523 test-env-lock arm (e) ratchet exists
//! to keep such mutations out of that shared process). Here the process is
//! this file's alone, and the ONE `#[test]` runs its legs sequentially, so
//! there is no reader the mutation can race.
//!
//! Both legs read the same sink, `encryption_enabled(None)`.

use ai_memory::encryption::{ENV_ENCRYPT_AT_REST, encryption_enabled, set_config_at_rest};

/// Set the knob for one probe. This binary is single-test, so the write is
/// never observed by another thread (the reason the pin is out of the lib).
fn with_env(value: &str) -> bool {
    // SAFETY: this binary holds exactly one test and no other thread reads or
    // writes the process environment while it runs.
    unsafe { std::env::set_var(ENV_ENCRYPT_AT_REST, value) };
    encryption_enabled(None)
}

#[test]
fn encryption_enabled_trims_surrounding_whitespace_3621() {
    set_config_at_rest(false);

    // THE PIN — RED on the untrimmed pre-fix code: a truthy value with
    // surrounding whitespace (and mixed case) MUST enable. Untrimmed, each
    // keeps its padding after `to_ascii_lowercase` and misses the
    // `"1"|"true"|"yes"|"on"` set, so at-rest encryption stays off.
    for v in ["  1  ", "\t1\n", " true ", " TrUe ", "  YES\t", " on "] {
        assert!(
            with_env(v),
            "a whitespace-padded / mixed-case truthy value must enable \
             at-rest encryption (it fails OPEN otherwise): {v:?}"
        );
    }

    // ALLOWED-PATH CONTROL — the trim must not change the recognised set:
    // plain truthy still enables; falsy / empty / whitespace-only / unknown
    // still disables.
    for v in ["1", "true", "yes", "on", "TRUE"] {
        assert!(with_env(v), "plain truthy must still enable: {v:?}");
    }
    for v in ["0", "false", "no", "off", "", "   ", "nonsense", " maybe "] {
        assert!(
            !with_env(v),
            "falsy / empty / whitespace-only / unknown must still disable: {v:?}"
        );
    }

    // SAFETY: same single-test binary; leave the process as it was found.
    unsafe { std::env::remove_var(ENV_ENCRYPT_AT_REST) };
    set_config_at_rest(false);
}
