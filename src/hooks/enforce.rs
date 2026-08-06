// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! PE-1 (#1734 / #1709 §6.1) — mandatory-hook **presence** enforcement.
//!
//! Per-hook [`FailMode::Open`]`|`[`FailMode::Closed`] fails closed when a
//! configured hook ERRORS or times out — but an ABSENT or disabled hook
//! yields an empty [`super::chain::HookChain`], whose `fire` returns `Allow`
//! from its terminal arm, so an operator relying on a pre-write governance /
//! policy hook gets **silently no enforcement** if that hook is missing.
//! `FailMode` can never fire on an empty chain. PE-1 closes this
//! mandatory-**presence** gap with a tri-state mode + an explicit
//! `required_events` declaration, checked by the pure
//! [`enforce_required_event_presence`] helper at the dispatch layer (NOT
//! inside `fire`, which never runs on an empty chain).
//!
//! Design resolved by the 5-agent adversarial vote (memory `4d3ea1c5`):
//! a tri-state surface mirroring `AI_MEMORY_PERMISSIONS_MODE`; an empty
//! `required_events` set is a hard no-op **even under `enforce`** (self-DOS
//! guard — most daemons run zero hooks); eligible events are pre-* mutation /
//! governance only. Explicitly NOT an `EnforceProfile` type, a parallel
//! enforce engine, a new `ChainResult` variant, or `RuleEngine` integration.

use serde::{Deserialize, Serialize};

use super::chain::ChainResult;
use super::config::{FailMode, HookConfig};
use super::events::HookEvent;

/// Tri-state hook-enforcement posture (#1734). Mirrors
/// [`crate::config::PermissionsMode`]. Resolved via the ladder
/// `AI_MEMORY_HOOKS_ENFORCE_MODE` env > `[hooks].enforce_mode` config >
/// compiled default [`HookEnforceMode::Off`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookEnforceMode {
    /// No presence check — today's behaviour (byte-identical default).
    #[default]
    Off,
    /// WARN (`hooks.enforce.violation`) + Allow when a required event has no
    /// enabled hook. The safe-rollout soak rung.
    Advisory,
    /// `Deny { code: 503 }` when a required event has no enabled hook, AND
    /// force required-event hooks to effective `fail_mode = Closed`.
    Enforce,
}

impl HookEnforceMode {
    /// Lowercase wire string for config / doctor / banner surfaces.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Advisory => "advisory",
            Self::Enforce => "enforce",
        }
    }

    /// Case-insensitive parse of `off` / `advisory` / `enforce`. Returns
    /// `None` for anything else so the resolver ladder falls through to the
    /// next rung (mirrors `AgeProjectionMode::from_str_opt`).
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "advisory" => Some(Self::Advisory),
            "enforce" => Some(Self::Enforce),
            _ => None,
        }
    }
}

/// The pre-* mutation / governance events eligible to appear in
/// `[hooks].required_events`. A `required_events` entry naming any other
/// event (a post-* event or `OnIndexEviction`) is a validation error: a
/// post-event `Deny` is log-only, so "required presence → deny" is
/// meaningless there.
pub const ELIGIBLE_REQUIRED_EVENTS: &[HookEvent] = &[
    HookEvent::PreStore,
    HookEvent::PreDelete,
    HookEvent::PrePromote,
    HookEvent::PreLink,
    HookEvent::PreConsolidate,
    HookEvent::PreGovernanceDecision,
    HookEvent::PreReflect,
    // #1752 — PreSignalSend is a deny-capable pre-event now enforced
    // synchronously on the MCP `memory_signal_send` path, so it is eligible to
    // be a required event (required-presence → deny when absent; the configured
    // hook runs FailMode::Closed so a hook error/timeout → Deny rather than a
    // silently-allowed send).
    HookEvent::PreSignalSend,
    // #2637 — PreCompaction is a deny-capable pre-event now consulted
    // synchronously in `ConsolidationPass::run` (the curator's autonomous
    // hard-DELETE merge) before any destructive op. Declaring it required makes
    // the curator boot install the process-global gate and DENY the merge when
    // no enabled `pre_compaction` hook is present (fail-closed), closing the
    // #2637 configurable-but-inert gate. Eligible on the curator surface; on
    // serve/mcp (which never consult PreCompaction) it is simply never checked.
    HookEvent::PreCompaction,
];

/// `true` when `event` may legally be declared a required event.
#[must_use]
pub fn is_eligible_required_event(event: HookEvent) -> bool {
    ELIGIBLE_REQUIRED_EVENTS.contains(&event)
}

/// Lowercase wire spelling of a `HookEvent` (e.g. `pre_store`) for operator
/// surfaces. Falls back to the `Debug` form if serialization ever fails.
#[must_use]
pub fn event_wire(event: HookEvent) -> String {
    serde_json::to_value(event)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{event:?}"))
}

/// PE-1 presence check (#1734) — the dispatch-layer guard, evaluated
/// *around* (never inside) [`super::chain::HookChain::fire`]. Returns:
///
/// * `None` when the operation may proceed normally — mode is `off`, the
///   event is not in `required`, or a required event HAS an enabled hook (the
///   normal chain then runs and its own `FailMode` governs errors).
/// * `Some(ChainResult::Deny { code: 503 })` under `enforce` when a required
///   event has NO enabled hook.
/// * `None` (after a `hooks.enforce.violation` WARN) under `advisory` when a
///   required event has no enabled hook — the safe-rollout soak rung.
///
/// Pure + total: unit-testable with no live daemon. An empty `required` set ⇒
/// always `None` (the self-DOS guard — most daemons run zero hooks, so
/// `enforce` with no declared required events must be a no-op, never an
/// all-events deny).
#[must_use]
pub fn enforce_required_event_presence(
    hooks: &[HookConfig],
    event: HookEvent,
    mode: HookEnforceMode,
    required: &[HookEvent],
) -> Option<ChainResult> {
    if mode == HookEnforceMode::Off || !required.contains(&event) {
        return None;
    }
    // A required event is satisfied by at least one ENABLED hook for it.
    let present = hooks.iter().any(|h| h.event == event && h.enabled);
    if present {
        return None;
    }
    match mode {
        HookEnforceMode::Enforce => Some(ChainResult::Deny {
            reason: format!(
                "hooks.enforce: required event {} has no enabled hook \
                 (enforce mode → fail-closed)",
                event_wire(event)
            ),
            code: 503,
        }),
        HookEnforceMode::Advisory => {
            tracing::warn!(
                target: "hooks.enforce.violation",
                event = %event_wire(event),
                "hooks.enforce: required event has no enabled hook (advisory → allow); \
                 set [hooks].enforce_mode = enforce to fail-closed"
            );
            None
        }
        // Unreachable (handled above), kept total.
        HookEnforceMode::Off => None,
    }
}

/// #2390 (N9) — fail-closed guard for an UNRESOLVABLE in-flight namespace.
///
/// `HookConfig::matches_namespace(None)` is `false` for a scoped hook, so a
/// pre-event whose namespace could not be resolved would silently SKIP every
/// namespace-scoped hook — the same silent-no-enforcement class `enforce_mode`
/// exists to close, and one a caller can TRIGGER on demand by passing an id that
/// does not resolve (a deleted / nonexistent / prefix-ambiguous memory id).
///
/// Returns:
/// * `None` — proceed. Either the namespace resolved (`!namespaces.is_empty()`)
///   or NO hook for this event is namespace-scoped, in which case the namespace
///   is irrelevant to the firing decision and wildcard hooks run as always.
///   This keeps every unscoped deployment byte-identical.
/// * `Some(ChainResult::Deny { code: 503 })` — a scoped hook exists for this
///   event but cannot be evaluated truthfully. Refuse loudly rather than
///   silently skip a declared control.
///
/// `hooks` is the EFFECTIVE (already event-filtered + enabled) hook list, i.e.
/// the output of [`effective_hooks_for_event`]. Pure + total.
///
/// Staged by `mode`, mirroring [`enforce_required_event_presence`]: `enforce`
/// denies, `advisory` WARNs + allows (the soak rung — an operator gets to SEE
/// how often this fires before it can refuse a write), `off` is a no-op.
#[must_use]
pub fn unresolved_namespace_deny(
    hooks: &[HookConfig],
    event: HookEvent,
    mode: HookEnforceMode,
    namespaces: &[String],
) -> Option<ChainResult> {
    if mode == HookEnforceMode::Off || !namespaces.is_empty() {
        return None;
    }
    if !hooks.iter().any(HookConfig::is_namespace_scoped) {
        return None;
    }
    match mode {
        HookEnforceMode::Enforce => {
            tracing::warn!(
                target: "hooks.enforce.namespace_unresolved",
                event = %event_wire(event),
                "hooks: in-flight namespace could not be resolved and a namespace-scoped \
                 hook is configured for this event → fail-closed deny (a scoped hook must \
                 never be silently skipped)"
            );
            Some(ChainResult::Deny {
                reason: format!(
                    "hooks: cannot resolve the in-flight namespace for scope \
                     evaluation of {} (a namespace-scoped hook is configured; \
                     refusing rather than silently skipping it)",
                    event_wire(event)
                ),
                code: 503,
            })
        }
        HookEnforceMode::Advisory => {
            tracing::warn!(
                target: "hooks.enforce.namespace_unresolved",
                event = %event_wire(event),
                "hooks: in-flight namespace could not be resolved and a namespace-scoped \
                 hook is configured for this event; the scoped hook is being SKIPPED \
                 (advisory → allow). Set [hooks].enforce_mode = enforce to fail-closed"
            );
            None
        }
        // Unreachable (handled above), kept total.
        HookEnforceMode::Off => None,
    }
}

/// PE-1 composition (#1734) — under `enforce`, a present-but-`fail_open`
/// required-event hook would defeat enforcement if it errored (fail-open ⇒
/// the chain Allows). Force required-event hooks to an effective
/// `fail_mode = Closed`. Pure: returns the `FailMode` the chain should use
/// for `cfg`. Outside `enforce`, or for a non-required event, the configured
/// `fail_mode` is returned verbatim.
#[must_use]
pub fn effective_fail_mode(
    cfg: &HookConfig,
    mode: HookEnforceMode,
    required: &[HookEvent],
) -> FailMode {
    if mode == HookEnforceMode::Enforce && required.contains(&cfg.event) {
        FailMode::Closed
    } else {
        cfg.fail_mode
    }
}

/// PE-1 dispatch composition (#1885) — build the effective, priority-unsorted
/// hook list for `event`, threading [`effective_fail_mode`] through every
/// entry. This is the piece the dispatch gate feeds into the chain so that a
/// required-event hook configured `fail_open` is forced to fail **closed**
/// under `enforce` (otherwise a fail-open hook that errored would let the chain
/// Allow, defeating enforcement). Filters to ENABLED hooks matching `event`
/// (mirroring [`super::chain::HookChain::for_event`]) then overrides each
/// entry's `fail_mode` with its effective value.
#[must_use]
pub fn effective_hooks_for_event(
    all_hooks: &[HookConfig],
    event: HookEvent,
    mode: HookEnforceMode,
    required: &[HookEvent],
) -> Vec<HookConfig> {
    all_hooks
        .iter()
        .filter(|h| h.enabled && h.event == event)
        .map(|h| {
            let mut c = h.clone();
            c.fail_mode = effective_fail_mode(h, mode, required);
            c
        })
        .collect()
}

/// PE-1 discoverability (#1734) — produce operator-facing pre-flight lines for
/// the boot banner + `ai-memory doctor`, one per declared required event,
/// flagging any that has no enabled hook (and, under `enforce`, that it WILL
/// DENY). Pure: returns the lines; returns empty when `mode` is `off` or
/// `required` is empty (nothing to surface). The caller prefixes / styles.
#[must_use]
pub fn preflight_report(
    hooks: &[HookConfig],
    mode: HookEnforceMode,
    required: &[HookEvent],
) -> Vec<String> {
    if mode == HookEnforceMode::Off || required.is_empty() {
        return Vec::new();
    }
    required
        .iter()
        .map(|e| {
            let enabled_for_event: Vec<&HookConfig> = hooks
                .iter()
                .filter(|h| h.event == *e && h.enabled)
                .collect();
            let present = !enabled_for_event.is_empty();
            let wire = event_wire(*e);
            if present {
                // #2390 (N9) — presence is namespace-BLIND, but firing is not.
                // When every enabled hook for a required event is namespace-
                // SCOPED, the presence gate is satisfied globally while the hook
                // fires only inside its scope: writes in every OTHER namespace
                // are ungoverned. That is legitimate (the operator scoped it on
                // purpose) but it is exactly the shape that reads as "enforced"
                // and is not, so surface it at boot / `doctor --hooks` where it
                // is free to fix rather than leaving the operator to infer it.
                if enabled_for_event
                    .iter()
                    .all(|h| HookConfig::is_namespace_scoped(h))
                {
                    let scopes = enabled_for_event
                        .iter()
                        .map(|h| h.namespace.trim())
                        .collect::<Vec<_>>()
                        .join(", ");
                    return format!(
                        "{wire}: required, enabled hook present but EVERY hook is \
                         namespace-scoped ({scopes}) → writes OUTSIDE that scope run \
                         UNGOVERNED (presence is namespace-blind; add a `namespace = \
                         \"*\"` hook to cover the rest)"
                    );
                }
                format!("{wire}: required, enabled hook present (OK)")
            } else if mode == HookEnforceMode::Enforce {
                format!("{wire}: REQUIRED but NO enabled hook → WILL DENY (enforce)")
            } else {
                format!("{wire}: required but no enabled hook → WARN+allow (advisory)")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::config::HookMode;
    use std::path::PathBuf;

    fn cfg(event: HookEvent, enabled: bool, fail_mode: FailMode) -> HookConfig {
        HookConfig {
            event,
            command: PathBuf::from("/bin/true"),
            priority: 0,
            timeout_ms: 1000,
            mode: HookMode::Exec,
            enabled,
            namespace: "*".to_string(),
            fail_mode,
        }
    }

    #[test]
    fn mode_parse_and_wire_round_trip() {
        for (s, m) in [
            ("off", HookEnforceMode::Off),
            ("ADVISORY", HookEnforceMode::Advisory),
            ("  Enforce  ", HookEnforceMode::Enforce),
        ] {
            assert_eq!(HookEnforceMode::from_str_opt(s), Some(m));
        }
        assert_eq!(HookEnforceMode::from_str_opt("bogus"), None);
        assert_eq!(HookEnforceMode::Enforce.as_str(), "enforce");
        assert_eq!(HookEnforceMode::default(), HookEnforceMode::Off);
    }

    #[test]
    fn eligibility_is_pre_mutation_only() {
        for e in ELIGIBLE_REQUIRED_EVENTS {
            assert!(is_eligible_required_event(*e), "{e:?} should be eligible");
        }
        assert!(!is_eligible_required_event(HookEvent::PostStore));
        assert!(!is_eligible_required_event(HookEvent::OnIndexEviction));
        assert!(!is_eligible_required_event(HookEvent::PostSignalAck));
    }

    #[test]
    fn off_mode_is_always_noop() {
        // #1734 acceptance: default off = byte-identical to today.
        let req = [HookEvent::PreStore];
        assert!(
            enforce_required_event_presence(&[], HookEvent::PreStore, HookEnforceMode::Off, &req)
                .is_none(),
            "off → no enforcement even with a required event + no hook"
        );
    }

    #[test]
    fn empty_required_is_noop_even_under_enforce() {
        // The self-DOS guard: enforce with NO declared required events must
        // never deny (most daemons run zero hooks).
        assert!(
            enforce_required_event_presence(
                &[],
                HookEvent::PreStore,
                HookEnforceMode::Enforce,
                &[]
            )
            .is_none(),
            "empty required_events → no-op even under enforce"
        );
    }

    #[test]
    fn enforce_denies_when_required_hook_absent() {
        let req = [HookEvent::PreStore];
        let out = enforce_required_event_presence(
            &[],
            HookEvent::PreStore,
            HookEnforceMode::Enforce,
            &req,
        );
        match out {
            Some(ChainResult::Deny { code, reason }) => {
                assert_eq!(code, 503);
                assert!(reason.contains("pre_store"), "names the event: {reason}");
            }
            other => panic!("expected Deny 503, got {other:?}"),
        }
    }

    #[test]
    fn enforce_allows_when_required_hook_present_and_enabled() {
        let req = [HookEvent::PreStore];
        let hooks = [cfg(HookEvent::PreStore, true, FailMode::Open)];
        assert!(
            enforce_required_event_presence(
                &hooks,
                HookEvent::PreStore,
                HookEnforceMode::Enforce,
                &req
            )
            .is_none(),
            "an enabled hook satisfies the required-presence check"
        );
    }

    #[test]
    fn enforce_denies_when_required_hook_present_but_disabled() {
        let req = [HookEvent::PreStore];
        let hooks = [cfg(HookEvent::PreStore, false, FailMode::Closed)];
        assert!(
            matches!(
                enforce_required_event_presence(
                    &hooks,
                    HookEvent::PreStore,
                    HookEnforceMode::Enforce,
                    &req
                ),
                Some(ChainResult::Deny { code: 503, .. })
            ),
            "a DISABLED hook does not satisfy required-presence"
        );
    }

    #[test]
    fn advisory_allows_but_is_distinguishable_from_off() {
        let req = [HookEvent::PreStore];
        // Advisory with the hook absent → Allow (None), but it WARNs (not
        // asserted here — the observable contract is Allow, same as off for
        // the caller, while off short-circuits before the presence scan).
        assert!(
            enforce_required_event_presence(
                &[],
                HookEvent::PreStore,
                HookEnforceMode::Advisory,
                &req
            )
            .is_none(),
            "advisory → allow (soak rung)"
        );
    }

    #[test]
    fn non_required_event_is_noop() {
        let req = [HookEvent::PreStore];
        assert!(
            enforce_required_event_presence(
                &[],
                HookEvent::PreDelete,
                HookEnforceMode::Enforce,
                &req
            )
            .is_none(),
            "an event not in required_events is never enforced"
        );
    }

    #[test]
    fn preflight_report_flags_missing_required_hooks() {
        let req = [HookEvent::PreStore, HookEvent::PreDelete];
        let hooks = [cfg(HookEvent::PreStore, true, FailMode::Open)];
        // Off → nothing to surface.
        assert!(preflight_report(&hooks, HookEnforceMode::Off, &req).is_empty());
        // Enforce → PreStore OK, PreDelete WILL DENY.
        let lines = preflight_report(&hooks, HookEnforceMode::Enforce, &req);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("pre_store") && lines[0].contains("OK"));
        assert!(lines[1].contains("pre_delete") && lines[1].contains("WILL DENY"));
        // Advisory → the missing one is WARN+allow, not WILL DENY.
        let adv = preflight_report(&hooks, HookEnforceMode::Advisory, &req);
        assert!(adv[1].contains("WARN+allow") && !adv[1].contains("WILL DENY"));
    }

    // ---- #2390 (N9) unresolved-namespace fail-closed guard ------------------

    fn scoped(event: HookEvent, namespace: &str) -> HookConfig {
        let mut c = cfg(event, true, FailMode::Open);
        c.namespace = namespace.to_string();
        c
    }

    /// A resolvable namespace never trips the guard, whatever the scoping.
    #[test]
    fn unresolved_ns_allows_when_namespace_resolved_2390() {
        let hooks = [scoped(HookEvent::PreLink, "prod")];
        assert!(
            unresolved_namespace_deny(
                &hooks,
                HookEvent::PreLink,
                HookEnforceMode::Enforce,
                &["prod".to_string()],
            )
            .is_none()
        );
    }

    /// With only WILDCARD hooks the namespace is irrelevant to the firing
    /// decision, so an unresolvable namespace must NOT deny — that would be a
    /// self-DOS for every unscoped deployment (the overwhelming majority).
    #[test]
    fn unresolved_ns_allows_when_no_hook_is_scoped_2390() {
        for pat in ["*", "", "   "] {
            let hooks = [scoped(HookEvent::PreLink, pat)];
            assert!(
                unresolved_namespace_deny(
                    &hooks,
                    HookEvent::PreLink,
                    HookEnforceMode::Enforce,
                    &[]
                )
                .is_none(),
                "pattern {pat:?} is wildcard — an unresolved namespace must not deny"
            );
        }
    }

    /// The fail-closed case: a SCOPED hook exists but the in-flight namespace is
    /// unknown, so the hook would be silently skipped. Under `enforce` that is a
    /// loud 503 refusal instead of a silent bypass — and it closes the vector
    /// where a caller FORCES the skip by passing an id that does not resolve.
    #[test]
    fn unresolved_ns_denies_under_enforce_when_a_scoped_hook_exists_2390() {
        let hooks = [scoped(HookEvent::PreLink, "prod/*")];
        match unresolved_namespace_deny(&hooks, HookEvent::PreLink, HookEnforceMode::Enforce, &[]) {
            Some(ChainResult::Deny { code, reason }) => {
                assert_eq!(code, 503);
                assert!(reason.contains("pre_link"), "names the event: {reason}");
            }
            other => panic!("expected a fail-closed 503 deny, got {other:?}"),
        }
    }

    /// `advisory` is the soak rung (WARN + allow) so an operator sees how often
    /// the guard would fire before it can refuse a write; `off` is a no-op.
    #[test]
    fn unresolved_ns_advisory_and_off_allow_2390() {
        let hooks = [scoped(HookEvent::PreLink, "prod")];
        for mode in [HookEnforceMode::Advisory, HookEnforceMode::Off] {
            assert!(
                unresolved_namespace_deny(&hooks, HookEvent::PreLink, mode, &[]).is_none(),
                "{mode:?} must not deny"
            );
        }
    }

    /// #2390 — `preflight_report` must tell an operator when a required event's
    /// hooks are ALL namespace-scoped: presence is satisfied globally while the
    /// hook fires only inside its scope, so every other namespace is ungoverned.
    /// Pre-#2390 that config printed a bare `(OK)`.
    #[test]
    fn preflight_flags_scoped_only_coverage_for_a_required_event_2390() {
        let req = [HookEvent::PreLink];
        let scoped_only = [scoped(HookEvent::PreLink, "prod/*")];
        let lines = preflight_report(&scoped_only, HookEnforceMode::Enforce, &req);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("UNGOVERNED") && lines[0].contains("prod/*"),
            "scoped-only coverage must be surfaced with its patterns: {}",
            lines[0]
        );

        // A wildcard hook alongside it restores full coverage → plain OK line.
        let mixed = [
            scoped(HookEvent::PreLink, "prod/*"),
            scoped(HookEvent::PreLink, "*"),
        ];
        let lines = preflight_report(&mixed, HookEnforceMode::Enforce, &req);
        assert!(
            lines[0].contains("(OK)") && !lines[0].contains("UNGOVERNED"),
            "a wildcard hook covers the rest: {}",
            lines[0]
        );
    }

    #[test]
    fn effective_hooks_for_event_threads_fail_mode_and_filters() {
        let req = [HookEvent::PreStore];
        let hooks = [
            cfg(HookEvent::PreStore, true, FailMode::Open), // required + fail-open
            cfg(HookEvent::PreStore, false, FailMode::Open), // disabled → filtered out
            cfg(HookEvent::PreDelete, true, FailMode::Open), // other event → filtered out
        ];
        let effective =
            effective_hooks_for_event(&hooks, HookEvent::PreStore, HookEnforceMode::Enforce, &req);
        assert_eq!(
            effective.len(),
            1,
            "only the enabled PreStore hook survives"
        );
        assert_eq!(
            effective[0].fail_mode,
            FailMode::Closed,
            "a required fail-open hook is forced Closed under enforce (#1885 threading)"
        );
        // Outside enforce the configured mode is preserved verbatim.
        let advisory =
            effective_hooks_for_event(&hooks, HookEvent::PreStore, HookEnforceMode::Advisory, &req);
        assert_eq!(advisory[0].fail_mode, FailMode::Open);
    }

    #[test]
    fn effective_fail_mode_forces_closed_for_required_under_enforce() {
        let req = [HookEvent::PreStore];
        let open_required = cfg(HookEvent::PreStore, true, FailMode::Open);
        // Under enforce, a required-event hook is forced Closed.
        assert_eq!(
            effective_fail_mode(&open_required, HookEnforceMode::Enforce, &req),
            FailMode::Closed
        );
        // Outside enforce, the configured mode is preserved.
        assert_eq!(
            effective_fail_mode(&open_required, HookEnforceMode::Advisory, &req),
            FailMode::Open
        );
        // A non-required hook keeps its configured mode even under enforce.
        let open_other = cfg(HookEvent::PreDelete, true, FailMode::Open);
        assert_eq!(
            effective_fail_mode(&open_other, HookEnforceMode::Enforce, &req),
            FailMode::Open
        );
    }
}
