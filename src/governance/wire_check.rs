// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Substrate-level agent-action wire-point helper (issue #691 fold-1).
//!
//! L1-6 Deliverable E wired the `Custom("memory_write")` action into
//! `storage::insert*` via the [`crate::storage::GOVERNANCE_PRE_WRITE`]
//! `OnceLock`. The other four agent-external action variants
//! ([`AgentAction::Bash`], [`AgentAction::FilesystemWrite`],
//! [`AgentAction::NetworkRequest`], [`AgentAction::ProcessSpawn`])
//! ship with rule-engine support in
//! [`crate::governance::agent_action::check_agent_action`] but no
//! production wire-points consult that engine outside the storage
//! write path. This module closes the gap.
//!
//! # Wire shape
//!
//! Every production wire-point — the skill exporter's filesystem
//! writes, the federation client's outbound HTTPS POST, the hooks
//! executor's child-process spawn, and the LLM client's Ollama HTTP
//! — calls a single uniform helper (`check` or `check_governed`):
//!
//! ```ignore
//! use crate::governance::wire_check;
//! wire_check::check(&action)?;            // CLI-reachable sinks
//! wire_check::check_governed(&action)?;   // daemon/MCP-only sinks
//! ```
//!
//! The helper consults the process-wide [`GOVERNANCE_PRE_ACTION`]
//! `OnceLock`. When set, the closure runs and an `Err(reason)` wraps
//! into a [`crate::storage::GovernanceRefusal`] propagated up the
//! `anyhow` chain — the same typed error the storage hook produces, so
//! the existing `MemoryError::from(anyhow::Error)` impl in `errors.rs`
//! handles the 403 / `GOVERNANCE_REFUSED` mapping uniformly.
//!
//! # Two entry points: `check` (CLI-exempt) vs `check_governed` (fail-closed)
//!
//! [`check`] keeps the documented CLI exemption: when the hook is unset
//! (CLI one-shot mode) the call is a zero-cost no-op `Ok(())`. That is a
//! deliberate operator-facing design (rationale 3 below) and applies ONLY
//! to sinks a CLI one-shot can actually reach.
//!
//! [`check_governed`] is the FAIL-CLOSED variant for wire-points that are
//! structurally daemon/MCP-only — every production caller of those sinks
//! reaches them after `serve` / `run_mcp_server` has installed the hook.
//! There, "hook unset" is not the CLI exemption, it is a broken bootstrap,
//! and a security gate that cannot consult its policy must REFUSE rather
//! than wave the action through (ERRORS-01/ERRORS-09; the same direction
//! the installed hook itself already takes for an unavailable consultation
//! connection, #1455).
//!
//! # Layering rationale (mirrors `storage::GOVERNANCE_PRE_WRITE`)
//!
//! 1. **Operator standing directive**: "rules and standards can NEVER
//!    be bypassed by AI/AI Agents — 100% of the time". A `OnceLock`
//!    enforces installation-is-one-shot at the type level — no reset,
//!    no override, no test-only escape hatch reachable from production
//!    code.
//! 2. **Hot path**: hook closure is read on every external action; an
//!    `RwLock` would add contention. `OnceLock::get()` is lock-free.
//! 3. **CLI exemption preserved**: CLI one-shot binaries
//!    (`ai-memory store …`, `ai-memory mine …`, …) MUST NOT install
//!    the hook — the operator's direct ops stay unimpeded. `OnceLock`
//!    defaults to empty, so the CLI path is the no-op default; only
//!    the daemon's `serve` boot reaches the `.set` callsite.
//! 4. **Modular**: every wire-point becomes one line. Adding a new
//!    wire-point (`AgentAction::Bash` for a future shell harness)
//!    needs zero changes here — the helper already dispatches by
//!    `kind()`.

use crate::governance::agent_action::AgentAction;
use crate::storage::GovernanceRefusal;

/// The wire-point hook signature. Returns `Ok(())` on Allow (the
/// action proceeds); `Err(reason)` on Refuse (the wire-point caller
/// surfaces `GovernanceRefusal { reason }` and aborts the action).
///
/// `Warn` and `Log` rule severities map to `Ok(())` — the hook does
/// not block, the audit chain (if installed) captures the warning.
pub type WireCheckHook = Box<dyn Fn(&AgentAction) -> std::result::Result<(), String> + Send + Sync>;

/// Process-wide agent-action wire-point hook. When `Some`, every
/// non-storage agent-external action consults the closure BEFORE the
/// action proceeds; an `Err(reason)` short-circuits the call site
/// with a [`GovernanceRefusal`].
///
/// Installation is one-shot (`OnceLock::set`); the daemon `serve`
/// bootstrap is the only caller in production. CLI one-shot binaries
/// MUST leave this empty.
///
/// See module-level comment for the full layering rationale.
pub static GOVERNANCE_PRE_ACTION: std::sync::OnceLock<WireCheckHook> = std::sync::OnceLock::new();

/// Consult the [`GOVERNANCE_PRE_ACTION`] hook for `action`. When the
/// hook is unset (CLI mode or pre-hook-install daemon path), this is
/// a zero-cost no-op `Ok(())`. When set, the closure runs and an
/// `Err(reason)` wraps into a [`GovernanceRefusal`] propagated up the
/// `anyhow` chain.
///
/// The function is hot-path; avoid heap allocation on the Allow leg.
///
/// # Errors
///
/// Returns [`GovernanceRefusal`] when the installed hook refuses
/// `action`. The `reason` field carries the operator-authored
/// explanation from the matched rule.
#[inline]
pub fn check(action: &AgentAction) -> std::result::Result<(), GovernanceRefusal> {
    if let Some(hook) = GOVERNANCE_PRE_ACTION.get() {
        if let Err(reason) = hook(action) {
            return Err(GovernanceRefusal { reason });
        }
    }
    Ok(())
}

/// Refusal reason emitted by [`check_governed`] when the wire-action hook
/// is not installed. One const (pm-v3.1 no-scattered-literals discipline)
/// shared by every daemon-side wire-point.
pub const HOOK_NOT_INSTALLED_REASON: &str = "governance wire-action hook is not installed — refusing this daemon-side action \
     (fail-closed). This sink is reachable only from `ai-memory serve` / `ai-memory mcp`, \
     both of which install the hook during bootstrap, so an uninstalled hook means the \
     governance bootstrap did not complete: check the daemon start-up log for the \
     pre-action hook install line and restart the daemon";

/// FAIL-CLOSED variant of [`check`] for wire-points that are structurally
/// daemon/MCP-only.
///
/// Identical to [`check`] when the hook IS installed. The difference is the
/// unset-hook leg: [`check`] returns `Ok(())` (the documented CLI
/// exemption), whereas this refuses.
///
/// # When to use which
///
/// Use `check_governed` when EVERY production caller of the sink runs
/// inside `ai-memory serve` or `ai-memory mcp` (both install the hook
/// during bootstrap, before any request is dispatched), so an unset hook
/// can only mean a broken bootstrap — never the operator's own hands-on
/// CLI ops. Use [`check`] for sinks a CLI one-shot can reach (e.g. the
/// LLM egress in `llm.rs`, reached by `ai-memory curator` / `atomise` /
/// `expand`), where refusing would break the documented exemption.
///
/// # Errors
///
/// Returns [`GovernanceRefusal`] when the installed hook refuses `action`,
/// OR when no hook is installed at all ([`HOOK_NOT_INSTALLED_REASON`]).
#[inline]
pub fn check_governed(action: &AgentAction) -> std::result::Result<(), GovernanceRefusal> {
    let Some(hook) = GOVERNANCE_PRE_ACTION.get() else {
        tracing::error!(
            target: crate::governance::GOVERNANCE_TRACE_TARGET,
            action = action.kind(),
            "wire_check: REFUSING a daemon-side action because the GOVERNANCE_PRE_ACTION \
             hook is not installed (fail-closed)"
        );
        return Err(GovernanceRefusal {
            reason: HOOK_NOT_INSTALLED_REASON.to_string(),
        });
    };
    if let Err(reason) = hook(action) {
        return Err(GovernanceRefusal { reason });
    }
    Ok(())
}

/// Anyhow-chained variant of [`check`] for call sites whose error type
/// is already `anyhow::Error`. Promotes a [`GovernanceRefusal`] into
/// an `anyhow::Error` so the upstream `MemoryError::from(anyhow::Error)`
/// impl in `errors.rs` can downcast and surface 403 / `GOVERNANCE_REFUSED`.
///
/// # Errors
///
/// Returns the same refusal as [`check`], boxed into `anyhow::Error`.
#[inline]
pub fn check_anyhow(action: &AgentAction) -> anyhow::Result<()> {
    if let Err(refusal) = check(action) {
        return Err(anyhow::Error::new(refusal));
    }
    Ok(())
}

/// Test-only helper: install a custom closure into the
/// [`GOVERNANCE_PRE_ACTION`] hook. Returns `Err(())` if the OnceLock
/// is already populated (production must never call this).
///
/// Hidden behind `#[doc(hidden)]` and `#[cfg(any(test, feature = "...
/// test-helpers"))]` to keep production binaries from reaching this
/// surface accidentally. Tests in `tests/governance_wire_points.rs`
/// install a fresh process via `std::process::Command` or rely on the
/// OnceLock's first-write-wins semantics (one test owns the install
/// for the cargo test process; siblings re-use the same hook).
#[doc(hidden)]
#[cfg(test)]
pub fn install_for_test(hook: WireCheckHook) -> std::result::Result<(), ()> {
    GOVERNANCE_PRE_ACTION.set(hook).map_err(|_| ())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Note on the OnceLock pattern: GOVERNANCE_PRE_ACTION is a process-wide
// `OnceLock` — only one hook can be installed per cargo test binary, and
// other unit tests in the same binary (notably the daemon_runtime tests
// that call `bootstrap_serve` and install the real check_agent_action_no_audit
// closure) may win the install race. The unit tests below therefore
// avoid asserting against `check()` directly. Instead they exercise the
// `check` / `check_anyhow` plumbing through a per-test mock hook
// invoked manually — the public path is verified end-to-end by
// `tests/governance_wire_points.rs` (a SEPARATE cargo test binary
// whose OnceLock is independent).

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Local mock that emulates the dispatch logic of [`check`] without
    /// reading the process-wide [`GOVERNANCE_PRE_ACTION`] OnceLock.
    /// Keeps the unit tests isolated from other tests in the same
    /// binary that might have already installed a real hook (e.g. the
    /// daemon_runtime test suite calling `bootstrap_serve`).
    fn mock_dispatch(
        hook: &WireCheckHook,
        action: &AgentAction,
    ) -> std::result::Result<(), GovernanceRefusal> {
        match hook(action) {
            Ok(()) => Ok(()),
            Err(reason) => Err(GovernanceRefusal { reason }),
        }
    }

    fn refuse_sentinel_hook() -> WireCheckHook {
        Box::new(|action: &AgentAction| match action {
            AgentAction::Bash { command, .. } if command.contains("__refuse__") => {
                Err("bash sentinel".to_string())
            }
            AgentAction::FilesystemWrite { path, .. }
                if path.to_string_lossy().contains("__refuse__") =>
            {
                Err("fs sentinel".to_string())
            }
            AgentAction::NetworkRequest { host, .. } if host.contains("__refuse__") => {
                Err("net sentinel".to_string())
            }
            AgentAction::ProcessSpawn { binary, .. } if binary.contains("__refuse__") => {
                Err("spawn sentinel".to_string())
            }
            AgentAction::Custom { custom_kind, .. } if custom_kind.contains("__refuse__") => {
                Err("custom sentinel".to_string())
            }
            _ => Ok(()),
        })
    }

    #[test]
    fn mock_dispatch_bash_refuse() {
        let hook = refuse_sentinel_hook();
        let action = AgentAction::Bash {
            command: "echo __refuse__".into(),
            cwd: None,
        };
        let err = mock_dispatch(&hook, &action).expect_err("expected refuse");
        assert_eq!(err.reason, "bash sentinel");
        assert!(format!("{err}").contains("governance-refused"));
    }

    #[test]
    fn mock_dispatch_filesystem_write_refuse() {
        let hook = refuse_sentinel_hook();
        let action = AgentAction::FilesystemWrite {
            path: PathBuf::from("/scratch/__refuse__.txt"),
            byte_estimate: None,
        };
        let err = mock_dispatch(&hook, &action).expect_err("expected refuse");
        assert_eq!(err.reason, "fs sentinel");
    }

    #[test]
    fn mock_dispatch_network_request_refuse() {
        let hook = refuse_sentinel_hook();
        let action = AgentAction::NetworkRequest {
            host: "__refuse__.example.com".into(),
            scheme: "https".into(),
        };
        let err = mock_dispatch(&hook, &action).expect_err("expected refuse");
        assert_eq!(err.reason, "net sentinel");
    }

    #[test]
    fn mock_dispatch_process_spawn_refuse() {
        let hook = refuse_sentinel_hook();
        let action = AgentAction::ProcessSpawn {
            binary: "__refuse__".into(),
            args: vec!["build".into()],
        };
        let err = mock_dispatch(&hook, &action).expect_err("expected refuse");
        assert_eq!(err.reason, "spawn sentinel");
    }

    #[test]
    fn mock_dispatch_custom_refuse() {
        let hook = refuse_sentinel_hook();
        let action = AgentAction::Custom {
            custom_kind: "__refuse__-deploy".into(),
            payload: serde_json::json!({}),
        };
        let err = mock_dispatch(&hook, &action).expect_err("expected refuse");
        assert_eq!(err.reason, "custom sentinel");
    }

    #[test]
    fn mock_dispatch_allow_non_sentinel() {
        let hook = refuse_sentinel_hook();
        let actions = [
            AgentAction::Bash {
                command: "true".into(),
                cwd: None,
            },
            AgentAction::FilesystemWrite {
                path: PathBuf::from("/Users/x/safe.txt"),
                byte_estimate: Some(0),
            },
            AgentAction::NetworkRequest {
                host: "good.example.com".into(),
                scheme: "https".into(),
            },
            AgentAction::ProcessSpawn {
                binary: "cargo".into(),
                args: vec![],
            },
            AgentAction::Custom {
                custom_kind: "memory_write".into(),
                payload: serde_json::json!({}),
            },
        ];
        for a in &actions {
            assert!(
                mock_dispatch(&hook, a).is_ok(),
                "expected allow for {:?}",
                a.kind()
            );
        }
    }

    #[test]
    fn check_no_hook_branch_allow() {
        // Direct cover of the early-return branch in [`check`] when the
        // OnceLock holds no hook. We can't unconditionally guarantee
        // that branch in this binary (another test may have installed
        // the daemon hook), so we only assert: IF `GOVERNANCE_PRE_ACTION`
        // happens to be empty, the public `check` returns Ok. If it's
        // populated, that hook governs the result and this assertion is
        // skipped. The full no-hook-installed path is covered by
        // `tests/governance_wire_points.rs` running in a fresh binary.
        if GOVERNANCE_PRE_ACTION.get().is_none() {
            let action = AgentAction::Bash {
                command: "ls".into(),
                cwd: None,
            };
            assert!(check(&action).is_ok());
            assert!(check_anyhow(&action).is_ok());
        }
    }

    #[test]
    fn check_anyhow_wraps_refusal_into_downcastable_error() {
        // Direct unit cover for the [`check_anyhow`] wrapper. Build a
        // refusal manually (matches the same type returned by [`check`]
        // when the hook fires) and verify the anyhow chain preserves
        // the `GovernanceRefusal` downcast contract that
        // `MemoryError::from(anyhow::Error)` in `src/errors.rs`
        // depends on for the 403 / `GOVERNANCE_REFUSED` HTTP mapping.
        let refusal = GovernanceRefusal {
            reason: "unit test reason".to_string(),
        };
        let e = anyhow::Error::new(refusal);
        let downcast = e
            .downcast_ref::<GovernanceRefusal>()
            .expect("downcast to GovernanceRefusal");
        assert_eq!(downcast.reason, "unit test reason");
        assert!(format!("{e}").contains("governance-refused"));
    }

    #[test]
    fn install_for_test_idempotent_after_first_call() {
        // Whichever test grabs the OnceLock first wins the install;
        // every subsequent attempt must report Err(()). This shape is
        // the test-helper contract that lets sibling tests in the
        // governance_wire_points integration suite call
        // `install_routing_hook` repeatedly without panicking.
        let first = install_for_test(Box::new(|_| Ok(())));
        let second = install_for_test(Box::new(|_| Err("late".into())));
        // First may have succeeded OR another test (daemon_runtime)
        // beat us to it — either way, the SECOND attempt must fail.
        // We assert the harder property: once installed, no further
        // install succeeds.
        if first.is_ok() {
            assert!(second.is_err(), "double-install must fail");
        } else {
            assert!(
                second.is_err(),
                "if first failed (already installed), second must also fail"
            );
        }
    }
}
