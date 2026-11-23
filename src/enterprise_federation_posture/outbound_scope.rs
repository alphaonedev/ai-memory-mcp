// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9996 — check #23 of the certified enterprise-federation posture: every
//! federation peer has a narrowed outbound namespace scope.
//!
//! Split out of `enterprise_federation_posture.rs` under the QUAL-10
//! submodule-over-bump rule (the #3553 `synchronous.rs` precedent). In a
//! daemon that configured peers the row reads the scope rows recorded at boot
//! (`federation::outbound_scope::boot_scope_rows`). A process that configured
//! no peer (the `doctor --posture` CLI) cannot see the daemon's peer list, so
//! it judges `AI_MEMORY_FED_PEER_OUTBOUND_SCOPE` itself: unset, malformed,
//! empty, an empty list or the explicit all-namespaces pattern all fail.

use super::{PostureCheck, check};
use crate::federation::outbound_scope::{
    self as scope, OUTBOUND_SCOPE_ENV, PeerOutboundScope, PeerScopeRow, ScopePosture,
};

/// Control name of check #23.
pub(super) const CONTROL_OUTBOUND_SCOPE: &str = "federation outbound scope";

/// The pass verdict and `actual` text for the rows a daemon recorded.
fn judge_rows(rows: &[PeerScopeRow]) -> (bool, String) {
    let count = |p: ScopePosture| rows.iter().filter(|r| r.posture == p).count();
    let (unscoped, all, narrowed) = (
        count(ScopePosture::Unscoped),
        count(ScopePosture::AllNamespaces),
        count(ScopePosture::Narrowed),
    );
    (
        unscoped == 0 && all == 0,
        format!(
            "{} peer(s) at boot: narrowed={narrowed} all_namespaces={all} unscoped={unscoped}",
            rows.len()
        ),
    )
}

/// The pass verdict and `actual` text for the env value, judged in a process
/// that configured no peer.
fn judge_env(
    parsed: Result<
        std::collections::BTreeMap<String, PeerOutboundScope>,
        scope::OutboundScopeConfigError,
    >,
    present: bool,
) -> (bool, String) {
    const UNSEEN: &str = "(peers are not observable from this process)";
    let map = match parsed {
        Ok(map) => map,
        Err(e) => return (false, format!("{e} {UNSEEN}")),
    };
    if !present || map.is_empty() {
        return (
            false,
            format!("{OUTBOUND_SCOPE_ENV} unset or empty: every peer is unscoped {UNSEEN}"),
        );
    }
    let all = map.values().filter(|s| s.is_all()).count();
    let deny = map
        .values()
        .filter(|s| matches!(s, PeerOutboundScope::Deny))
        .count();
    (
        all == 0 && deny == 0,
        format!(
            "{} scoped peer key(s): all_namespaces={all} empty_list={deny} {UNSEEN}",
            map.len()
        ),
    )
}

/// Render check #23.
pub(super) fn check_outbound_scope() -> PostureCheck {
    let (pass, actual) = match scope::boot_scope_rows() {
        Some(rows) => judge_rows(&rows),
        None => judge_env(
            scope::from_env(),
            std::env::var_os(OUTBOUND_SCOPE_ENV).is_some(),
        ),
    };
    check(
        CONTROL_OUTBOUND_SCOPE,
        "every federation peer has a narrowed outbound namespace scope (no unscoped peer, \
         no explicit all-namespaces `**` scope)",
        actual,
        pass,
        "set AI_MEMORY_FED_PEER_OUTBOUND_SCOPE to a JSON object naming, for each peer URL, \
         the namespaces it may receive (`{\"<peer url>\": {\"allowed_namespaces\": [...]}}`); \
         do not use `**`",
    )
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Sets the outbound scope env to one peer with a narrowed scope, the
    /// passing form of check #23. The caller holds the posture env lock and
    /// restores the variable (it is in the parent's isolated-env list).
    pub(in crate::enterprise_federation_posture) fn set_narrowed_scope_env() {
        // SAFETY: the parent's posture tests serialise every env write
        // through their env lock; no other thread reads the variable here.
        unsafe {
            std::env::set_var(
                crate::federation::outbound_scope::OUTBOUND_SCOPE_ENV,
                r#"{"https://peer-1.example.org:9077":{"allowed_namespaces":["public/*"]}}"#,
            );
        }
    }

    fn row(posture: ScopePosture) -> PeerScopeRow {
        PeerScopeRow {
            peer_id: "peer-x".into(),
            posture,
        }
    }

    #[test]
    fn rows_pass_only_when_every_peer_is_narrowed_9996() {
        let cases: [(&[ScopePosture], bool); 6] = [
            (&[], true),
            (&[ScopePosture::Narrowed], true),
            (&[ScopePosture::Narrowed, ScopePosture::Narrowed], true),
            (&[ScopePosture::Unscoped], false),
            (&[ScopePosture::AllNamespaces], false),
            (&[ScopePosture::Narrowed, ScopePosture::Unscoped], false),
        ];
        for (postures, want) in cases {
            let rows: Vec<_> = postures.iter().copied().map(row).collect();
            assert_eq!(judge_rows(&rows).0, want, "{postures:?}");
        }
    }

    #[test]
    fn env_fails_unset_malformed_empty_all_and_empty_list_9996() {
        let parse = scope::parse;
        let cases: [(Option<&str>, bool); 7] = [
            (None, false),
            (Some("not json"), false),
            (Some("{}"), false),
            (
                Some(r#"{"https://peer-a:9077": {"allowed_namespaces": ["**"]}}"#),
                false,
            ),
            (
                Some(r#"{"https://peer-a:9077": {"allowed_namespaces": []}}"#),
                false,
            ),
            (
                Some(r#"{"https://peer-a:9077": {"allowed_namespaces": ["team/*"]}}"#),
                true,
            ),
            (
                Some(
                    r#"{"https://peer-a:9077": {"allowed_namespaces": ["team/*"]},
                        "https://peer-b:9077": {"allowed_namespaces": ["**"]}}"#,
                ),
                false,
            ),
        ];
        for (raw, want) in cases {
            let parsed = raw.map_or_else(|| Ok(Default::default()), parse);
            let (pass, actual) = judge_env(parsed, raw.is_some());
            assert_eq!(pass, want, "{raw:?} -> {actual}");
            assert!(
                !actual.contains("peer-a"),
                "no peer URL in the row: {actual}"
            );
        }
    }
}
