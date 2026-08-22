// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! REGRESSION — `wire_check::check_governed` must FAIL CLOSED when the
//! process-wide `GOVERNANCE_PRE_ACTION` hook is not installed.
//!
//! This crate deliberately NEVER installs a hook. Cargo runs each
//! integration-test crate in its own binary, so the `OnceLock` is
//! guaranteed empty here for the binary's whole lifetime — the only shape
//! in which the unset-hook leg is observable (`tests/governance_wire_points.rs`
//! installs a routing hook, and the unit tests in `src/governance/wire_check.rs`
//! race the daemon bootstrap for the install).
//!
//! Pre-fix EVERY daemon-side wire-point consulted `check`, whose unset-hook
//! leg is `Ok(())` — so a daemon whose governance bootstrap had not run (or
//! had failed) executed filesystem writes, outbound HTTPS and child-process
//! spawns with the agent-action rule engine consulting nothing. `check`
//! keeps that leg for the documented CLI one-shot exemption; the daemon/MCP
//! sinks now use `check_governed`, which refuses.

use ai_memory::governance::agent_action::AgentAction;
use ai_memory::governance::wire_check::{self, GOVERNANCE_PRE_ACTION, HOOK_NOT_INSTALLED_REASON};
use std::path::PathBuf;

fn every_variant() -> Vec<AgentAction> {
    vec![
        AgentAction::Bash {
            command: "true".into(),
            cwd: None,
        },
        AgentAction::FilesystemWrite {
            path: PathBuf::from("/scratch/skill/SKILL.md"),
            byte_estimate: Some(64),
        },
        AgentAction::NetworkRequest {
            host: "peer.example.com".into(),
            scheme: "https".into(),
        },
        AgentAction::ProcessSpawn {
            binary: "hook-binary".into(),
            args: Vec::new(),
        },
        AgentAction::Custom {
            custom_kind: "memory_write".into(),
            payload: serde_json::json!({}),
        },
    ]
}

/// Guard: if this ever fails, the rest of the file proves nothing — some
/// other test in this binary installed a hook.
#[test]
fn hook_is_never_installed_in_this_binary() {
    assert!(
        GOVERNANCE_PRE_ACTION.get().is_none(),
        "this crate must never install GOVERNANCE_PRE_ACTION — the unset-hook \
         leg is exactly what it exists to pin"
    );
}

/// THE FAIL-OPEN REPRODUCTION: `check` (the CLI-exempt entry point) still
/// allows every action with no hook installed. This is the pre-fix
/// behaviour of every daemon-side wire-point, preserved here deliberately
/// and ONLY for the documented CLI one-shot exemption.
#[test]
fn check_still_allows_with_no_hook_installed_cli_exemption() {
    assert!(GOVERNANCE_PRE_ACTION.get().is_none());
    for action in every_variant() {
        assert!(
            wire_check::check(&action).is_ok(),
            "check() keeps the CLI exemption for {:?}",
            action.kind()
        );
        assert!(wire_check::check_anyhow(&action).is_ok());
    }
}

/// THE FIX: `check_governed` refuses every variant when the hook is unset.
#[test]
fn check_governed_refuses_every_variant_with_no_hook_installed() {
    assert!(GOVERNANCE_PRE_ACTION.get().is_none());
    for action in every_variant() {
        let refusal = wire_check::check_governed(&action).expect_err(
            "check_governed must FAIL CLOSED when GOVERNANCE_PRE_ACTION is not installed",
        );
        assert_eq!(
            refusal.reason,
            HOOK_NOT_INSTALLED_REASON,
            "refusal must carry the shared actionable reason for {:?}",
            action.kind()
        );
        // The refusal must round-trip through the anyhow chain the
        // 403 / GOVERNANCE_REFUSED mapping in `errors.rs` downcasts on.
        let e = anyhow::Error::new(refusal);
        let downcast = e
            .downcast_ref::<ai_memory::storage::GovernanceRefusal>()
            .expect("downcast to GovernanceRefusal");
        assert!(downcast.reason.contains("fail-closed"));
        assert!(format!("{e}").contains("governance-refused"));
    }
}

/// The refusal message must be ACTIONABLE — it names the two entry points
/// that install the hook and the remedy, so an operator reading a 403 can
/// act without reading the source.
#[test]
fn hook_not_installed_reason_is_actionable() {
    assert!(HOOK_NOT_INSTALLED_REASON.contains("serve"));
    assert!(HOOK_NOT_INSTALLED_REASON.contains("mcp"));
    assert!(HOOK_NOT_INSTALLED_REASON.contains("restart the daemon"));
    assert!(HOOK_NOT_INSTALLED_REASON.contains("fail-closed"));
}

/// Fable HIGH (#3133): `ai-memory skill export` is a CLI one-shot
/// (`cli::commands::skill` → `handle_skill_export`) that never installs
/// `GOVERNANCE_PRE_ACTION`. Both filesystem-write sites must use `check`
/// (CLI exemption), not `check_governed` — otherwise a working CLI export
/// hard-refuses with [`HOOK_NOT_INSTALLED_REASON`].
#[test]
fn skill_export_uses_check_not_check_governed() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/mcp/tools/skill_export.rs"
    ));
    assert!(
        src.contains("wire_check::check(&skill_md_action)"),
        "SKILL.md write must use check (CLI exemption)"
    );
    assert!(
        src.contains("wire_check::check(&res_action)"),
        "resource write must use check (CLI exemption)"
    );
    assert!(
        !src.contains("wire_check::check_governed("),
        "skill_export is CLI-reachable; check_governed would refuse `ai-memory skill export`"
    );
}
