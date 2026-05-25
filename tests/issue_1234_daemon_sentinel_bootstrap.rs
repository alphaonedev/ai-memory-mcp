// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// Regression tests for issue #1234 — daemon-sentinel bootstrap rejection.
//
// Pre-fix bug: two production code paths used the wire-side validator
// `validate::validate_agent_id` (which ALSO rejects RESERVED_AGENT_IDS
// per #977) instead of the shape-only `validate::validate_agent_id_shape`,
// breaking the daemon's own self-signing keypair bootstrap.
//
// The two sites:
//
// 1. `src/identity/mod.rs::resolve_agent_id` env-var path — rejected
//    `AI_MEMORY_AGENT_ID=daemon` (or any reserved sentinel), which is
//    the legitimate daemon-boot scenario.
//
// 2. `src/cli/identity.rs::generate` — rejected `ai-memory identity
//    generate --agent-id daemon`, which is exactly what
//    `entrypoint.plan-c.sh:30` runs to bootstrap the daemon's
//    self-signing keypair on container start.
//
// Per validate.rs:319-321 doc-comment carve-out: internal callers
// that legitimately need reserved-sentinel labels (the daemon's own
// `DAEMON_KEYPAIR_LABEL = "daemon"` at src/daemon_runtime.rs:1887)
// can opt into the looser shape-only check. The fix is to USE that
// carve-out at the two miss-migrated sites.

use ai_memory::{identity, validate};

const RESERVED_SENTINELS: &[&str] = &["daemon", "system", "federation-catchup"];

/// Probe 1 — `identity::resolve_agent_id` MUST accept reserved
/// sentinels via the env-var path (internal-bootstrap surface).
#[test]
fn issue_1234_resolve_agent_id_env_accepts_daemon_sentinel() {
    // Serialize env-var manipulation across this test file — env is
    // process-global state.
    let _guard = env_lock();
    for sentinel in RESERVED_SENTINELS {
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", sentinel) };
        let resolved = identity::resolve_agent_id(None, None)
            .unwrap_or_else(|e| panic!("resolve_agent_id for sentinel {sentinel:?}: {e}"));
        assert_eq!(
            resolved, *sentinel,
            "env-var path must return the reserved sentinel verbatim"
        );
    }
    unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
}

/// Probe 2 — `validate::validate_agent_id_shape` MUST accept
/// reserved sentinels (the carve-out semantics).
#[test]
fn issue_1234_validate_agent_id_shape_accepts_reserved_sentinels() {
    for sentinel in RESERVED_SENTINELS {
        validate::validate_agent_id_shape(sentinel)
            .unwrap_or_else(|e| panic!("validate_agent_id_shape({sentinel:?}) must accept: {e}"));
    }
}

/// Probe 3 — `validate::validate_agent_id` (wire-strict) MUST still
/// reject reserved sentinels. The carve-out at the internal surfaces
/// does NOT loosen the wire posture.
#[test]
fn issue_1234_validate_agent_id_wire_strict_still_rejects_reserved() {
    for sentinel in RESERVED_SENTINELS {
        let result = validate::validate_agent_id(sentinel);
        assert!(
            result.is_err(),
            "wire-strict validate_agent_id({sentinel:?}) must reject — found Ok"
        );
    }
}

/// Probe 4 — env-var path with an invalid SHAPE (not just reserved)
/// must still reject. Shape rules: max 128 chars, regex
/// `^[A-Za-z0-9_\-:@./]+$`. We exercise the shape-rejection branch
/// to prove we didn't accidentally bypass shape validation when
/// we relaxed the reserved-sentinel rejection.
#[test]
fn issue_1234_env_var_path_still_rejects_invalid_shape() {
    let _guard = env_lock();
    // Note: null bytes are refused by `std::env::set_var` itself
    // before reaching our validator, so they cannot be tested here.
    // The shape rules in validate.rs forbid them at the validator
    // level too, but the env-var path is short-circuited by libc.
    let bad_shapes: &[&str] = &[
        " ",             // whitespace
        "with space",    // internal whitespace
        "with\nnewline", // control char
        "with`backtick", // shell metachar
        "with$dollar",   // shell metachar
    ];
    for bad in bad_shapes {
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", bad) };
        let result = identity::resolve_agent_id(None, None);
        assert!(
            result.is_err(),
            "shape-invalid env-var {bad:?} must reject — found Ok({:?})",
            result.ok(),
        );
    }
    unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
}

/// Probe 5 — explicit-caller path (the FIRST arm of
/// `resolve_agent_id`) MUST still wire-strict-reject reserved
/// sentinels. This is the carve-out boundary: env-var path is
/// internal-bootstrap, explicit-caller is wire-side.
#[test]
fn issue_1234_explicit_caller_still_wire_strict_rejects_reserved() {
    let _guard = env_lock();
    unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
    for sentinel in RESERVED_SENTINELS {
        let result = identity::resolve_agent_id(Some(sentinel), None);
        assert!(
            result.is_err(),
            "explicit-caller path is wire-strict; {sentinel:?} must reject — found Ok({:?})",
            result.ok(),
        );
    }
}

/// Cross-test mutex — env-var state is process-global; serialize
/// every test that touches `AI_MEMORY_AGENT_ID` so they don't race
/// each other under `cargo test`'s default parallel scheduler.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock, PoisonError};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}
