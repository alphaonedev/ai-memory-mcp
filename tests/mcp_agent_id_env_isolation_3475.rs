// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3475 — process-isolated home for every test that INSTALLS a value into
//! the process-global `AI_MEMORY_AGENT_ID`.
//!
//! WHY A SEPARATE TEST BINARY (the control, not a style choice).
//! `AI_MEMORY_AGENT_ID` is the single process-global input to
//! `identity::resolve_read_visibility_caller()`, which every MCP read
//! dispatch consults, and `visibility::is_visible_by_fields` treats a row
//! with NO `metadata.scope` as `private` and therefore OWNER-KEYED. So the
//! instant ANY test installs a shape-valid value into that variable, every
//! CONCURRENT reader in the same process stops seeing rows that carry no
//! `metadata.agent_id` — `memory_get` masks them as not-found and
//! `memory_get_links` filters the neighbours away.
//!
//! `identity::agent_id_env_test_lock()` cannot fix that: it serialises the
//! MUTATORS against each other, but the hundreds of lib tests that merely
//! READ identity never take it, and annotating every one of them is neither
//! reviewable nor stable. #3475 is exactly that failure — #3356 added two
//! `agent_id_env_set_guard("test-bot")` lib tests to `src/mcp/mod.rs`, and
//! `mcp::tests::handle_get_happy_returns_memory`,
//! `handle_get_resolves_by_prefix_and_includes_links` and
//! `handle_get_links_returns_outbound_and_inbound` (unlocked readers, rows
//! inserted with `metadata: {}`) began failing nondeterministically on the
//! `macos-fed,sqlite` leg of CI run 33662095277.
//!
//! The sound control is PROCESS isolation. A `tests/*.rs` file compiles to
//! its own test binary and therefore its own process, so nothing here can
//! be observed by the `src/**`-embedded `#[cfg(test)]` cohort no matter how
//! either side is scheduled. `scripts/check-test-env-lock.sh` enforces the
//! rule mechanically (arm (d)) so the class cannot come back.
//!
//! Tests INSIDE this binary still share one process, so they serialise on
//! [`env_lock`] and restore the previous value on drop (RAII, so a panicking
//! test cannot leak a value into its siblings).

use ai_memory::config::{AppConfig, FeatureTier};
use ai_memory::identity::resolve_mcp_read_visibility_caller;
use ai_memory::mcp::run_mcp_server;
use ai_memory::profile::Profile;
use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

/// The env var #3356 fails closed on and #3475 confines to this binary.
const ENV_AGENT_ID: &str = "AI_MEMORY_AGENT_ID";

/// Binary-local serialisation for the tests below. Cargo runs the test fns
/// of ONE binary in parallel threads, so the same `set_var` unsoundness that
/// motivates this file applies within it; every mutation here happens under
/// this lock.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// RAII fixture: install (or clear) `AI_MEMORY_AGENT_ID` for the lifetime of
/// the guard and restore the pre-guard state on drop, holding [`env_lock`]
/// throughout. Mirrors `identity::agent_id_env_set_guard`, which is
/// `pub(crate)` and therefore unreachable from an integration test binary.
struct AgentIdEnv {
    prev: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl AgentIdEnv {
    fn set(value: &str) -> Self {
        let lock = env_lock();
        let prev = std::env::var_os(ENV_AGENT_ID);
        // SAFETY: this binary's only env mutations happen under `env_lock`,
        // which the returned guard holds until it is dropped, and no other
        // process shares this environment.
        unsafe { std::env::set_var(ENV_AGENT_ID, value) };
        Self { prev, _lock: lock }
    }

    fn unset() -> Self {
        let lock = env_lock();
        let prev = std::env::var_os(ENV_AGENT_ID);
        // SAFETY: serialised by `env_lock`, held by the returned guard.
        unsafe { std::env::remove_var(ENV_AGENT_ID) };
        Self { prev, _lock: lock }
    }
}

impl Drop for AgentIdEnv {
    fn drop(&mut self) {
        match self.prev.take() {
            // SAFETY: `_lock` still serialises this restore.
            Some(value) => unsafe { std::env::set_var(ENV_AGENT_ID, value) },
            // SAFETY: `_lock` still serialises this restore.
            None => unsafe { std::env::remove_var(ENV_AGENT_ID) },
        }
    }
}

/// DENIED PATH (#3356, moved verbatim from `mcp::tests` by #3475): a
/// configured-but-shape-invalid identity aborts MCP boot instead of
/// collapsing into the unset / single-tenant posture.
#[test]
fn mcp_server_refuses_shape_invalid_agent_identity_before_serving_3356() {
    let _env = AgentIdEnv::set("bad id with spaces");
    let result = run_mcp_server(
        std::path::Path::new(":memory:"),
        FeatureTier::Keyword,
        &AppConfig::default(),
        &Profile::core(),
    );
    let error = result
        .expect_err("boot must refuse an invalid identity")
        .to_string();
    assert!(
        error.starts_with("AI_MEMORY_AGENT_ID is invalid:"),
        "unexpected startup error: {error}"
    );
}

/// DENIED PATH (#3356): an EMPTY configured identity is operator
/// configuration, not absence, and is refused by the same boot gate.
#[test]
fn mcp_server_refuses_empty_agent_identity_before_serving_3356() {
    let _env = AgentIdEnv::set("");
    let result = run_mcp_server(
        std::path::Path::new(":memory:"),
        FeatureTier::Keyword,
        &AppConfig::default(),
        &Profile::core(),
    );
    let error = result
        .expect_err("boot must refuse an empty identity")
        .to_string();
    assert_eq!(error, "AI_MEMORY_AGENT_ID must not be empty");
}

/// ALLOWED PATH (#3356): a shape-VALID configured identity resolves, and an
/// ABSENT one is a legitimate `None` — the two cases the boot gate must let
/// through. Asserted against `resolve_mcp_read_visibility_caller`, the exact
/// function `run_mcp_server` consults before it serves (a full
/// `run_mcp_server` call on the allowed path would go on to read stdin).
#[test]
fn mcp_read_visibility_caller_accepts_valid_and_absent_identity_3356() {
    {
        let _env = AgentIdEnv::set("ai:isolation-probe-3475");
        assert_eq!(
            resolve_mcp_read_visibility_caller().expect("valid identity must resolve"),
            Some("ai:isolation-probe-3475".to_string())
        );
    }
    let _env = AgentIdEnv::unset();
    assert_eq!(
        resolve_mcp_read_visibility_caller().expect("absent identity is a legitimate None"),
        None
    );
}
