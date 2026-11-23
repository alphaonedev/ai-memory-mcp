// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9996 — check #23 of the certified enterprise-federation posture: every
//! federation peer has a narrowed outbound namespace scope.
//!
//! Split out of `enterprise_federation_posture.rs` under the QUAL-10
//! submodule-over-bump rule (the #3553 `synchronous.rs` precedent). In a
//! daemon that configured peers the row reads the scope rows recorded at boot
//! (`federation::outbound_scope::boot_scope_rows`). A process that configured
//! no peer (the `doctor --posture` CLI) cannot see the daemon's peer list (the
//! `serve --quorum-peers` argument), so the env value alone never passes the
//! row (review #10026 S-F2): it FAILs with [`UNVERIFIABLE`].

use super::{PostureCheck, check};
use crate::federation::outbound_scope::{
    self as scope, OutboundScopeConfigError, PeerOutboundScope, PeerScopeRow, ScopePosture,
};
use std::collections::BTreeMap;

/// Control name of check #23.
pub(super) const CONTROL_OUTBOUND_SCOPE: &str = "federation outbound scope";

/// The `actual` text of check #23 in a process that cannot see the peer list.
/// It names the reason (the scope is not provable from a fresh process) and
/// the live-check issue that gives the row a source of truth.
pub(super) const UNVERIFIABLE: &str =
    "the daemon outbound scope is not provable from a fresh process (live check #10059)";

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

/// The pass verdict and `actual` text for a peer list `peers` (the URLs the
/// daemon would serve with) against the parsed scope map. `None` is a list
/// this process cannot see: FAIL with [`UNVERIFIABLE`], whatever the env
/// holds. Every listed peer needs a narrowed entry; a peer is named by
/// origin and path only, never credentials.
fn judge_peers(
    peers: Option<&[String]>,
    parsed: Result<BTreeMap<String, PeerOutboundScope>, OutboundScopeConfigError>,
) -> (bool, String) {
    let Some(peers) = peers else {
        let env = match &parsed {
            Ok(map) => format!("{} scoped peer key(s) in the env", map.len()),
            Err(e) => e.to_string(),
        };
        return (
            false,
            format!("{UNVERIFIABLE}: the peer list is the `serve --quorum-peers` argument; {env}"),
        );
    };
    let map = match parsed {
        Ok(map) => map,
        Err(e) => return (false, e.to_string()),
    };
    let mut not_narrowed = Vec::new();
    let mut known = 0usize;
    for url in peers {
        let entry = map.get(&crate::federation::peer::stable_peer_id(url));
        if entry.is_some() {
            known = known.saturating_add(1);
        }
        if entry.map(ScopePosture::of) != Some(ScopePosture::Narrowed) {
            not_narrowed.push(crate::url_display::url_origin_and_path(url));
        }
    }
    let unknown = map.len().saturating_sub(known);
    if !not_narrowed.is_empty() {
        return (
            false,
            format!(
                "peer(s) without a narrowed outbound scope: {}",
                not_narrowed.join(", ")
            ),
        );
    }
    if unknown > 0 {
        return (
            false,
            format!("{unknown} scope key(s) name no configured peer"),
        );
    }
    (true, format!("{} peer(s): every one narrowed", peers.len()))
}

/// Render check #23.
pub(super) fn check_outbound_scope() -> PostureCheck {
    let (pass, actual) = match scope::boot_scope_rows() {
        Some(rows) => judge_rows(&rows),
        // No process but `serve` holds the peer list (review #10026 S-F2).
        None => judge_peers(None, scope::from_env()),
    };
    check(
        CONTROL_OUTBOUND_SCOPE,
        "every federation peer has a narrowed outbound namespace scope (no unscoped peer, \
         no explicit all-namespaces `**` scope)",
        actual,
        pass,
        "set AI_MEMORY_FED_PEER_OUTBOUND_SCOPE to a JSON object naming, for each peer URL, \
         the namespaces it may receive (`{\"<peer url>\": {\"allowed_namespaces\": [...]}}`); \
         do not use `**`; judge it in the running daemon (its boot rows)",
    )
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// The peer the passing form of check #23 configures.
    const NARROWED_PEER_URL: &str = "https://peer-1.example.org:9077";

    /// Sets the outbound scope env to one peer with a narrowed scope and
    /// records that peer's boot scope row, the passing form of check #23 (a
    /// daemon that configured the peer). The caller holds the posture env lock,
    /// runs in an env-isolated child and restores the variable (it is in the
    /// parent's isolated-env list).
    pub(in crate::enterprise_federation_posture) fn set_narrowed_scope_env() {
        // SAFETY: the parent's posture tests serialise every env write
        // through their env lock; no other thread reads the variable here.
        unsafe {
            std::env::set_var(
                crate::federation::outbound_scope::OUTBOUND_SCOPE_ENV,
                format!(r#"{{"{NARROWED_PEER_URL}":{{"allowed_namespaces":["public/*"]}}}}"#),
            );
        }
        let narrowed = PeerOutboundScope::Namespaces(vec!["public/*".to_string()]);
        let id = crate::federation::peer::stable_peer_id(NARROWED_PEER_URL);
        scope::record_boot_scopes([(id.as_str(), NARROWED_PEER_URL, &narrowed)]);
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

    const PEER_A: &str = "https://user:pw@peer-a:9077/fed";
    const PEER_B: &str = "https://peer-b:9077";

    fn urls(list: &[&str]) -> Vec<String> {
        list.iter().map(|u| (*u).to_string()).collect()
    }

    #[test]
    fn peers_need_a_narrowed_entry_each_9996() {
        let a = format!(r#""{PEER_A}": {{"allowed_namespaces": ["team/*"]}}"#);
        let b_all = format!(r#""{PEER_B}": {{"allowed_namespaces": ["**"]}}"#);
        let b_deny = format!(r#""{PEER_B}": {{"allowed_namespaces": []}}"#);
        let b_ok = format!(r#""{PEER_B}": {{"allowed_namespaces": ["ops"]}}"#);
        let shown_b = crate::url_display::url_origin_and_path(PEER_B);
        let not_narrowed = format!("peer(s) without a narrowed outbound scope: {shown_b}");
        let cases: Vec<(String, Vec<String>, bool, String)> = vec![
            (
                format!("{{{a}, {b_ok}}}"),
                urls(&[PEER_A, PEER_B]),
                true,
                "2 peer(s): every one narrowed".to_string(),
            ),
            // B omitted from the scope map.
            (
                format!("{{{a}}}"),
                urls(&[PEER_A, PEER_B]),
                false,
                not_narrowed.clone(),
            ),
            (
                format!("{{{a}, {b_all}}}"),
                urls(&[PEER_A, PEER_B]),
                false,
                not_narrowed.clone(),
            ),
            (
                format!("{{{a}, {b_deny}}}"),
                urls(&[PEER_A, PEER_B]),
                false,
                not_narrowed,
            ),
            // A scope key for a peer the list does not hold.
            (
                format!("{{{a}, {b_ok}}}"),
                urls(&[PEER_A]),
                false,
                "1 scope key(s) name no configured peer".to_string(),
            ),
        ];
        for (raw, peers, want, text) in cases {
            let (pass, actual) = judge_peers(Some(&peers), scope::parse(&raw));
            assert_eq!((pass, actual.as_str()), (want, text.as_str()), "{raw}");
            assert!(!actual.contains("pw"), "no credential in the row: {actual}");
        }
        let (pass, actual) = judge_peers(Some(&urls(&[PEER_B])), scope::parse("not json"));
        assert!(!pass);
        assert_eq!(
            actual,
            scope::parse("not json")
                .map(|_| ())
                .unwrap_err()
                .to_string()
        );
    }

    #[test]
    fn unresolvable_peer_list_fails_whatever_the_env_holds_9996() {
        let narrowed = format!(r#"{{"{PEER_B}": {{"allowed_namespaces": ["ops"]}}}}"#);
        let (pass, actual) = judge_peers(None, scope::parse(&narrowed));
        assert!(!pass, "env shape alone never passes");
        assert_eq!(
            actual,
            "the daemon outbound scope is not provable from a fresh process (live check \
             #10059): the peer list is the `serve --quorum-peers` argument; 1 scoped peer \
             key(s) in the env"
        );
        let (pass, actual) = judge_peers(None, Ok(BTreeMap::new()));
        assert!(!pass);
        assert_eq!(
            actual,
            "the daemon outbound scope is not provable from a fresh process (live check \
             #10059): the peer list is the `serve --quorum-peers` argument; 0 scoped peer \
             key(s) in the env"
        );
    }

    /// A process that recorded no boot rows (a fresh `doctor`) fails check
    /// #23 even with a narrowed env value (review #10026 S-F2).
    #[test]
    fn fresh_process_with_narrowed_env_fails_unverifiable_9996() {
        if crate::config::run_env_isolated_child_or_spawn(
            "enterprise_federation_posture::outbound_scope::tests::\
             fresh_process_with_narrowed_env_fails_unverifiable_9996",
        ) {
            return;
        }
        let _g = crate::config::test_env_lock();
        // SAFETY: env-isolated child holding the env lock; no other thread
        // reads the variable.
        unsafe {
            std::env::set_var(
                crate::federation::outbound_scope::OUTBOUND_SCOPE_ENV,
                format!(r#"{{"{PEER_B}": {{"allowed_namespaces": ["ops"]}}}}"#),
            );
        }
        assert!(
            scope::boot_scope_rows().is_none(),
            "fresh child has no boot rows"
        );
        let row = check_outbound_scope();
        assert!(!row.pass, "{row:?}");
        assert!(row.actual.starts_with(UNVERIFIABLE), "{row:?}");
    }
}
