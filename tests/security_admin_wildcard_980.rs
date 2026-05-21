// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioural
// impact on the regression we pin.
#![allow(clippy::doc_markdown)]

//! v0.7.0 #980 — admin wildcard sentinel closure.
//!
//! Pre-#980 the `is_admin_caller` predicate at
//! `src/handlers/admin_role.rs:92-94` admitted any non-empty caller
//! when `admin_agent_ids` contained the literal `"*"`. The wildcard
//! was originally added for the lib's own unit-test fixture (`vec!["*"]`
//! at `src/handlers/tests.rs:362`), but `daemon_runtime::resolve_admin_agent_ids`
//! ALSO explicitly carved out `"*"` from the `AI_MEMORY_ADMIN_AGENT_IDS`
//! env var, so a production operator who set
//! `AI_MEMORY_ADMIN_AGENT_IDS=*` (or any path that smuggled `"*"` into
//! the allowlist) opened every admin endpoint to every caller. The
//! 6-agent v0.7.0 release review flagged the wildcard as reachable in
//! production code (security agent H7).
//!
//! The fix splits the two paths:
//!
//! 1. **Production `is_admin_caller`** — the wildcard arm is now
//!    `#[cfg(test)]`-gated. Production builds CANNOT admit `"*"`
//!    regardless of how the allowlist is populated; a config-loader
//!    regression that lets `"*"` slip past
//!    `crate::validate::validate_agent_id` (which already rejects it
//!    for shape) cannot open every admin endpoint.
//! 2. **`resolve_admin_agent_ids`** — the `AI_MEMORY_ADMIN_AGENT_IDS=*`
//!    env var carve-out is REMOVED. `"*"` is now rejected by
//!    `validate_agent_id` (shape: `*` is not in the allowed char class)
//!    and dropped with a WARN, just like any other invalid entry.
//!    Operators wanting permissive admin posture enumerate explicit
//!    agent ids.
//!
//! This file pins both behaviours from the integration-test surface.

use ai_memory::daemon_runtime::resolve_admin_agent_ids;

/// Process-wide guard for env-var mutations under parallel cargo test.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn admin_agent_ids_env_var_wildcard_is_rejected_980() {
    let _g = ENV_LOCK.lock().await;
    unsafe {
        std::env::set_var("AI_MEMORY_ADMIN_AGENT_IDS", "*");
    }
    let resolved = resolve_admin_agent_ids(None);
    unsafe {
        std::env::remove_var("AI_MEMORY_ADMIN_AGENT_IDS");
    }
    assert!(
        resolved.is_empty(),
        "AI_MEMORY_ADMIN_AGENT_IDS=* MUST resolve to an empty allowlist (no wildcard carve-out per #980); got: {resolved:?}",
    );
}

#[tokio::test]
async fn admin_agent_ids_env_var_mixed_wildcard_and_principal_drops_wildcard_only_980() {
    let _g = ENV_LOCK.lock().await;
    unsafe {
        std::env::set_var("AI_MEMORY_ADMIN_AGENT_IDS", "ai:alice,*,ai:bob");
    }
    let resolved = resolve_admin_agent_ids(None);
    unsafe {
        std::env::remove_var("AI_MEMORY_ADMIN_AGENT_IDS");
    }
    assert!(
        resolved.contains(&"ai:alice".to_string()),
        "explicit principal ai:alice MUST be admitted; got {resolved:?}",
    );
    assert!(
        resolved.contains(&"ai:bob".to_string()),
        "explicit principal ai:bob MUST be admitted; got {resolved:?}",
    );
    assert!(
        !resolved.contains(&"*".to_string()),
        "wildcard `*` MUST be dropped (validate_agent_id rejects it for shape); got {resolved:?}",
    );
    assert_eq!(
        resolved.len(),
        2,
        "exactly 2 principals admitted (wildcard dropped); got {resolved:?}",
    );
}

#[tokio::test]
async fn admin_agent_ids_env_var_documented_shapes_still_pass_980() {
    let _g = ENV_LOCK.lock().await;
    unsafe {
        std::env::set_var(
            "AI_MEMORY_ADMIN_AGENT_IDS",
            "ai:claude-code@host-1:pid-123,host:dev-1:pid-9-deadbeef,anonymous:req-abcdef01",
        );
    }
    let resolved = resolve_admin_agent_ids(None);
    unsafe {
        std::env::remove_var("AI_MEMORY_ADMIN_AGENT_IDS");
    }
    assert_eq!(
        resolved.len(),
        3,
        "canonical NHI shapes MUST be admitted intact; got {resolved:?}",
    );
}
