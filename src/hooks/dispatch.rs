// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2426 — the machine-readable registry of which [`HookEvent`]s actually
//! dispatch in a production build.
//!
//! `hooks.toml` accepts every `HookEvent` variant, but not every variant has a
//! production fire site, and the deny-capable pre-events are consulted only
//! through the PE-1 enforcement gate (`crate::mcp::consult_pre_event_gate`),
//! which is installed only when `[hooks].enforce_mode != off` AND
//! `[hooks].required_events` is non-empty. A hook subscribed to an event that
//! cannot fire used to load cleanly and render in `ai-memory doctor --hooks`
//! like any live hook: an operator could believe a gate or notifier was in
//! place when nothing ran (the #1885 / #2233 / #2444 class).
//!
//! [`dispatch_status`] is an exhaustive `match`, so a new variant cannot be
//! added without a verdict here. The source-scan cells in this module keep the
//! verdicts honest against the tree: a `Never` event must have no
//! production `HookEvent::<Variant>` reference outside `src/hooks/`, and every
//! other event must have at least one.

use super::config::HookConfig;
use super::enforce::event_wire;
use super::events::HookEvent;

/// How a [`HookEvent`] reaches its configured hooks in a production build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchStatus {
    /// A configured hook runs whenever its operation happens on the surface
    /// that hosts the fire site.
    Fires,
    /// Consulted only through the PE-1 enforcement gate, which is installed
    /// only when `[hooks].enforce_mode != off` and `required_events` is
    /// non-empty. Without the gate a configured hook never runs.
    EnforceGateOnly,
    /// No production fire site: a configured hook never runs.
    Never,
}

/// The production dispatch status of `event`. See the module doc.
#[must_use]
pub const fn dispatch_status(event: HookEvent) -> DispatchStatus {
    match event {
        // MCP stdio: `memory_signal_send` / `memory_signal_ack` install their
        // own chain whenever such a hook is configured (#1752 / #1714).
        HookEvent::PreSignalSend | HookEvent::PostSignalAck => DispatchStatus::Fires,
        HookEvent::PreStore
        | HookEvent::PreDelete
        | HookEvent::PrePromote
        | HookEvent::PreLink
        | HookEvent::PreConsolidate
        | HookEvent::PreGovernanceDecision
        | HookEvent::PreReflect
        | HookEvent::PreCompaction => DispatchStatus::EnforceGateOnly,
        // `PreRecallExpand`'s only fire site is
        // `crate::mcp::handle_recall_with_pre_recall_hook`, which nothing in
        // production calls.
        HookEvent::PostStore
        | HookEvent::PostRecall
        | HookEvent::PostSearch
        | HookEvent::PostDelete
        | HookEvent::PostPromote
        | HookEvent::PostLink
        | HookEvent::PostConsolidate
        | HookEvent::PostGovernanceDecision
        | HookEvent::OnIndexEviction
        | HookEvent::PreRecallExpand
        | HookEvent::PostReflect
        | HookEvent::OnCompactionRollback => DispatchStatus::Never,
    }
}

/// One enabled hook subscription that will not run in this process
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct InertSubscription {
    /// Wire spelling of the event (`post_store`).
    pub event: String,
    /// Why it will not run.
    pub dispatch: DispatchStatus,
    /// Operator-facing explanation.
    pub message: String,
}

/// Every enabled hook in `hooks` that will not run, given whether the PE-1
/// enforcement gate is installed (`enforce_mode != off` with a non-empty
/// `required_events`). One entry per distinct event, in first-seen order.
#[must_use]
pub fn inert_subscriptions(hooks: &[HookConfig], gate_installed: bool) -> Vec<InertSubscription> {
    let mut out: Vec<InertSubscription> = Vec::new();
    for h in hooks.iter().filter(|h| h.enabled) {
        let dispatch = dispatch_status(h.event);
        let event = event_wire(h.event);
        let message = match dispatch {
            DispatchStatus::Fires => continue,
            DispatchStatus::EnforceGateOnly if gate_installed => continue,
            DispatchStatus::EnforceGateOnly => format!(
                "hook subscribed to `{event}` will not run: this event is consulted only \
                 through the hooks enforce gate, which is installed only when \
                 [hooks].enforce_mode is not off and required_events is non-empty (#2426)"
            ),
            DispatchStatus::Never => format!(
                "hook subscribed to `{event}` will never fire: the event has no \
                 production dispatch site (#2426)"
            ),
        };
        if out.iter().any(|i| i.event == event) {
            continue;
        }
        out.push(InertSubscription {
            event,
            dispatch,
            message,
        });
    }
    out
}

/// Boot-time WARN for every inert subscription, so the operator learns it
/// from the daemon / MCP log and not only from `doctor --hooks`.
pub fn warn_inert_subscriptions(hooks: &[HookConfig], gate_installed: bool) {
    for i in inert_subscriptions(hooks, gate_installed) {
        tracing::warn!(target: "hooks", event = %i.event, "{}", i.message);
    }
}

/// [`warn_inert_subscriptions`] over the operator's default `hooks.toml`,
/// with the gate state derived from the resolved PE-1 posture exactly as the
/// `serve` / `mcp` boot installs it. A missing or unparseable file warns
/// about nothing (the load error is reported by the surfaces that use it).
pub fn warn_inert_subscriptions_at_boot(mode: super::HookEnforceMode, required: &[HookEvent]) {
    let hooks = HookConfig::default_path()
        .filter(|p| p.exists())
        .and_then(|p| HookConfig::load_from_file(&p).ok())
        .unwrap_or_default();
    warn_inert_subscriptions(
        &hooks,
        mode != super::HookEnforceMode::Off && !required.is_empty(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant, spelled out so a new one fails here until it is given a
    /// verdict (the compiler also forces an arm in `dispatch_status`).
    const ALL: [HookEvent; 22] = [
        HookEvent::PreStore,
        HookEvent::PostStore,
        HookEvent::PostRecall,
        HookEvent::PostSearch,
        HookEvent::PreDelete,
        HookEvent::PostDelete,
        HookEvent::PrePromote,
        HookEvent::PostPromote,
        HookEvent::PreLink,
        HookEvent::PostLink,
        HookEvent::PreConsolidate,
        HookEvent::PostConsolidate,
        HookEvent::PreGovernanceDecision,
        HookEvent::PostGovernanceDecision,
        HookEvent::OnIndexEviction,
        HookEvent::PreRecallExpand,
        HookEvent::PreReflect,
        HookEvent::PostReflect,
        HookEvent::PreCompaction,
        HookEvent::OnCompactionRollback,
        HookEvent::PreSignalSend,
        HookEvent::PostSignalAck,
    ];

    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// Production text of a source file: everything before its first test
    /// module, with comment lines dropped.
    fn production_lines(src: &str) -> Vec<&str> {
        let mut lines = Vec::new();
        for l in src.lines() {
            let t = l.trim_start();
            if t.starts_with("mod tests") || t.starts_with("pub mod tests") {
                break;
            }
            if t.starts_with("//") || t.starts_with('*') {
                continue;
            }
            lines.push(l);
        }
        lines
    }

    /// Files outside `src/hooks/` that name `HookEvent::<variant>` in
    /// production code, excluding the two surfaces that only RENDER or
    /// CLASSIFY events (`cli/doctor.rs`, `config.rs`).
    fn production_referencing_files(variant: &str) -> Vec<String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&root, &mut files);
        let needle = format!("HookEvent::{variant}");
        let mut hits = Vec::new();
        for f in files {
            let rel = f
                .strip_prefix(&root)
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            if rel.starts_with("hooks/") || rel == "cli/doctor.rs" || rel == "config.rs" {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&f) else {
                continue;
            };
            let found = production_lines(&src).iter().any(|l| {
                l.match_indices(&needle).any(|(i, _)| {
                    !l[i + needle.len()..]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                })
            });
            if found {
                hits.push(rel);
            }
        }
        hits
    }

    #[test]
    fn dispatch_registry_matches_production_fire_sites_2426() {
        let mut wrong = Vec::new();
        for e in ALL {
            let variant = format!("{e:?}");
            let hits = production_referencing_files(&variant);
            match dispatch_status(e) {
                DispatchStatus::Never if !hits.is_empty() => wrong.push(format!(
                    "{variant} is marked Never but production code names it in {hits:?}"
                )),
                DispatchStatus::Fires | DispatchStatus::EnforceGateOnly if hits.is_empty() => {
                    wrong.push(format!(
                        "{variant} is marked as dispatching but no production fire site names it"
                    ));
                }
                _ => {}
            }
        }
        assert!(
            wrong.is_empty(),
            "#2426 dispatch registry is stale:\n{}",
            wrong.join("\n")
        );
    }

    #[test]
    fn dispatch_registry_counts_2426() {
        let count = |s: DispatchStatus| ALL.iter().filter(|e| dispatch_status(**e) == s).count();
        assert_eq!(count(DispatchStatus::Fires), 2);
        assert_eq!(count(DispatchStatus::EnforceGateOnly), 8);
        assert_eq!(count(DispatchStatus::Never), 12);
    }

    fn hook(event: HookEvent, enabled: bool) -> HookConfig {
        HookConfig {
            event,
            command: std::path::PathBuf::from("/bin/true"),
            priority: 0,
            timeout_ms: 1000,
            mode: crate::hooks::HookMode::Exec,
            enabled,
            namespace: "*".into(),
            fail_mode: crate::hooks::FailMode::Open,
        }
    }

    #[test]
    fn inert_subscriptions_follow_the_gate_and_skip_disabled_hooks_2426() {
        let hooks = vec![
            hook(HookEvent::PostStore, true),
            hook(HookEvent::PostStore, true),
            hook(HookEvent::PreDelete, true),
            hook(HookEvent::PostLink, false),
            hook(HookEvent::PreSignalSend, true),
        ];
        let off: Vec<String> = inert_subscriptions(&hooks, false)
            .into_iter()
            .map(|i| i.event)
            .collect();
        assert_eq!(off, ["post_store", "pre_delete"]);
        let on = inert_subscriptions(&hooks, true);
        assert_eq!(on.len(), 1);
        assert_eq!(on[0].event, "post_store");
        assert_eq!(on[0].dispatch, DispatchStatus::Never);
        assert!(on[0].message.contains("will never fire"));
    }
}
