// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! v1.0.0 #3418 — per-agent api-key enrollment takes effect WITHOUT a restart.
//!
//! # The defect
//!
//! The enrolled `sha256(token) -> agent_id` map was captured ONCE at boot and
//! cloned into `AppState` + `ApiKeyState`. Everything downstream was correct;
//! the map was a photograph. So:
//!
//! * a fleet that mints agents dynamically could not bind them without
//!   restarting the data tier per enrollment — leaving `advisory`
//!   (self-asserted identity) as the only workable posture, which is exactly
//!   what `enforce` exists to refuse; and
//! * **a REVOKED key kept authenticating until the next restart** — a
//!   credential the operator has been told is dead.
//!
//! # What is pinned here
//!
//! DENIED and ALLOWED for both halves, against the LIVE registry:
//!
//! * enroll → the key resolves and `enforce` admits the caller, with no
//!   restart and no rebuild of the state;
//! * revoke → the same key stops resolving and `enforce` refuses, again with
//!   no restart;
//! * a failed refresh KEEPS the last known snapshot (degrade, never disarm);
//! * the refresh-interval resolver fails safe on garbage input.
//!
//! The STORE-backed half — an enrollment written through the SAL on sqlite AND
//! on the certified postgres tier reaching this registry — lives in the sibling
//! binary `agent_key_hot_enroll_store_3418.rs`, which is `sal`-gated; this one
//! stays feature-free so the registry contract is pinned on every leg.

use std::collections::HashMap;

use ai_memory::handlers::identity_binding::{
    AgentKeyRefresh, AuthLevel, EnrolledAgentKeys, api_key_sha256_hex, apply_agent_key_refresh,
    enforce_for_request, refresh_posture_note, resolve_agent_key_refresh_interval,
    resolve_auth_level,
};
use axum::http::HeaderMap;

/// Serialises the env-mutating refresh-interval case against anything else in
/// this binary that reads the same variable.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn headers_with_key(token: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-api-key", token.parse().expect("header value"));
    h
}

fn enrolled_map(token: &str, agent: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(api_key_sha256_hex(token), agent.to_string());
    m
}

// ---------------------------------------------------------------------------
// The registry itself — enrollment and revocation without a restart
// ---------------------------------------------------------------------------

/// ALLOWED: a key enrolled AFTER the registry was built resolves immediately.
/// Pre-#3418 this required rebuilding `AppState`, i.e. a daemon restart.
#[test]
fn enrollment_takes_effect_without_rebuilding_state_3418() {
    let registry = EnrolledAgentKeys::empty();
    let headers = headers_with_key("alice-token");

    // Before enrollment the gate is inert (empty map) and the caller is Claimed.
    assert_eq!(
        resolve_auth_level(&registry, &headers, "alice"),
        AuthLevel::Claimed
    );
    assert!(
        enforce_for_request(
            &registry,
            ai_memory::config::HttpIdentityMode::Enforce,
            &headers,
            "alice",
            "get_memory"
        )
        .is_none(),
        "an empty registry is inert in every mode (the #1985 trap)"
    );

    // Enroll — the SAME registry instance, as a live refresh would.
    assert!(
        registry.install(enrolled_map("alice-token", "alice")),
        "installing a different map must report a change"
    );

    assert_eq!(
        resolve_auth_level(&registry, &headers, "alice"),
        AuthLevel::KeyAuthenticated,
        "the freshly enrolled key must resolve with NO restart"
    );
    assert_eq!(
        registry.generation(),
        1,
        "an installed change bumps generation"
    );
}

/// DENIED — the security half: once revoked, the key stops authenticating and
/// `enforce` refuses the caller, again with no restart.
#[test]
fn revocation_takes_effect_without_a_restart_3418() {
    let registry = EnrolledAgentKeys::from_map(enrolled_map("alice-token", "alice"));
    let headers = headers_with_key("alice-token");
    assert_eq!(
        resolve_auth_level(&registry, &headers, "alice"),
        AuthLevel::KeyAuthenticated
    );

    // Revoke every binding — what `agents revoke-api-key` writes, as the
    // refresh loop would then observe it.
    assert!(registry.install(HashMap::new()), "revocation is a change");

    assert_eq!(
        resolve_auth_level(&registry, &headers, "alice"),
        AuthLevel::Claimed,
        "a REVOKED key must stop authenticating immediately — a revocation that \
         waits for a restart is a credential the operator believes is dead"
    );
}

/// With another agent still enrolled, the registry is non-empty, so `enforce`
/// is armed and the revoked caller is actively REFUSED rather than merely
/// downgraded. This is the arm that proves revocation reaches the gate.
#[test]
fn enforce_refuses_a_revoked_caller_while_others_stay_enrolled_3418() {
    let mut both = enrolled_map("alice-token", "alice");
    both.extend(enrolled_map("bob-token", "bob"));
    let registry = EnrolledAgentKeys::from_map(both);
    let alice = headers_with_key("alice-token");

    assert!(
        enforce_for_request(
            &registry,
            ai_memory::config::HttpIdentityMode::Enforce,
            &alice,
            "alice",
            "get_memory"
        )
        .is_none(),
        "alice is key-authenticated while enrolled"
    );

    // Revoke ONLY alice; bob keeps the registry armed.
    registry.install(enrolled_map("bob-token", "bob"));

    assert!(
        enforce_for_request(
            &registry,
            ai_memory::config::HttpIdentityMode::Enforce,
            &alice,
            "alice",
            "get_memory"
        )
        .is_some(),
        "after revocation alice is merely Claimed, and enforce must REFUSE her"
    );
}

/// An installed map with identical contents is not a change — so the refresh
/// loop logs transitions, not every poll.
#[test]
fn reinstalling_the_same_map_is_not_a_change_3418() {
    let registry = EnrolledAgentKeys::from_map(enrolled_map("alice-token", "alice"));
    assert!(!registry.install(enrolled_map("alice-token", "alice")));
    assert_eq!(registry.generation(), 0);
}

/// DEGRADE, never disarm — driven through the REAL funnel the daemon uses.
///
/// [`apply_agent_key_refresh`] is the single place a read result becomes
/// registry state, so this pins the rule for BOTH backends at once: a failed
/// read must retain the last known snapshot. Installing an empty map on a
/// transient store error would make `enforce_for_request` inert in every mode
/// (an empty registry is the #1985 unsatisfiable-default escape hatch), i.e. a
/// blip on the data tier would silently downgrade an `enforce` deployment to
/// self-asserted identity. Staleness is a bounded, observable degrade;
/// disarming is a silent one.
#[test]
fn a_failed_refresh_keeps_the_last_known_snapshot_3418() {
    let registry = EnrolledAgentKeys::from_map(enrolled_map("alice-token", "alice"));
    let headers = headers_with_key("alice-token");
    let generation_before = registry.generation();

    let outcome = apply_agent_key_refresh(
        &registry,
        Err::<Vec<(String, String)>, _>("store unreachable"),
    );

    assert_eq!(
        outcome,
        AgentKeyRefresh::KeptLastKnown(1),
        "a failed read must report that it KEPT the previous set"
    );
    assert_eq!(
        registry.generation(),
        generation_before,
        "a failed read installs nothing, so the generation must not move"
    );
    assert_eq!(
        resolve_auth_level(&registry, &headers, "alice"),
        AuthLevel::KeyAuthenticated,
        "the previously enrolled key must keep working across a failed refresh"
    );
    assert!(
        !registry.is_empty(),
        "an empty registry would disarm the identity gate entirely — the one \
         outcome worse than a stale one"
    );
}

/// The funnel reports Installed vs Unchanged, so the refresh loop logs real
/// transitions instead of one line per poll on a fleet of daemons.
#[test]
fn the_refresh_funnel_distinguishes_a_change_from_a_no_op_3418() {
    let registry = EnrolledAgentKeys::empty();
    let rows = vec![(api_key_sha256_hex("alice-token"), "alice".to_string())];

    assert_eq!(
        apply_agent_key_refresh(&registry, Ok::<_, String>(rows.clone())),
        AgentKeyRefresh::Installed(1)
    );
    assert_eq!(
        apply_agent_key_refresh(&registry, Ok::<_, String>(rows)),
        AgentKeyRefresh::Unchanged(1),
        "re-reading the same set must NOT be reported as a change"
    );
    assert_eq!(
        apply_agent_key_refresh(&registry, Ok::<_, String>(Vec::new())),
        AgentKeyRefresh::Installed(0),
        "a revocation that empties the set is still a change"
    );
}

// ---------------------------------------------------------------------------
// Refresh-interval policy — fail safe, never widen the window
// ---------------------------------------------------------------------------

#[test]
fn refresh_interval_defaults_and_fails_safe_3418() {
    // Serialise: this MUTATES a process-global env var, and cargo runs the
    // tests in this binary as threads of one process.
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key = ai_memory::handlers::identity_binding::ENV_AGENT_KEY_REFRESH_SECS;
    let prev = std::env::var(key).ok();

    // SAFETY: serialised by the lock above; restored before it drops.
    unsafe { std::env::remove_var(key) };
    assert_eq!(
        resolve_agent_key_refresh_interval().map(|d| d.as_secs()),
        Some(ai_memory::handlers::identity_binding::DEFAULT_AGENT_KEY_REFRESH_SECS),
        "unset must use the compiled default, not disable the loop"
    );

    unsafe { std::env::set_var(key, "not-a-number") };
    assert_eq!(
        resolve_agent_key_refresh_interval().map(|d| d.as_secs()),
        Some(ai_memory::handlers::identity_binding::DEFAULT_AGENT_KEY_REFRESH_SECS),
        "garbage must fall back to the default — never silently widen the \
         revocation window"
    );

    unsafe { std::env::set_var(key, "0") };
    assert!(
        resolve_agent_key_refresh_interval().is_none(),
        "0 is the explicit opt-out"
    );
    // ...and the posture note SAYS the restart requirement is back.
    let note = refresh_posture_note(None);
    assert!(note.contains("DISABLED"), "{note}");
    assert!(
        note.contains("restart"),
        "the disabled posture must state the consequence: {note}"
    );

    unsafe { std::env::set_var(key, "5") };
    assert_eq!(
        resolve_agent_key_refresh_interval().map(|d| d.as_secs()),
        Some(5)
    );
    let note = refresh_posture_note(resolve_agent_key_refresh_interval());
    assert!(note.contains("REVOCATION"), "{note}");

    unsafe {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}
