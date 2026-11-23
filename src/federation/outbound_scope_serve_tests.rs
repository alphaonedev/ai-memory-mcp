// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10037 / #10039 unit rows of the pull-path admission funnel.

use super::*;
use crate::federation::outbound_scope::filtered_series;
use crate::federation::peer::stable_peer_id;

const PEER_URL: &str = "https://peer-b.unit-10037:9077";
const PEER_ID: &str = "ai:peer-b-10037";
const NS_IN: &str = "public/alpha";
const NS_OUT: &str = "public/beta";

fn mem(id: &str, ns: &str) -> Memory {
    Memory {
        id: id.to_string(),
        namespace: ns.to_string(),
        title: "t".to_string(),
        content: "c".to_string(),
        created_at: "2026-11-23T00:00:00Z".to_string(),
        ..Memory::default()
    }
}

fn config(patterns: &str, peer_ids: &str) -> String {
    format!("{{\"{PEER_URL}\":{{\"allowed_namespaces\":{patterns},\"peer_ids\":{peer_ids}}}}}")
}

fn peer(id: &str) -> AuthenticatedPullPeer {
    AuthenticatedPullPeer::signature_verified(id, SignatureProof::mint_after_signature_check())
        .unwrap_or_else(|| panic!("non-empty peer id {id} must build"))
}

fn narrowed() -> ServeScope {
    resolve_in(
        Some(&peer(PEER_ID)),
        Ok(config(
            &format!("[\"{NS_IN}\"]"),
            &format!("[\"{PEER_ID}\"]"),
        )),
    )
}

#[test]
fn mapped_peer_resolves_its_entry_under_the_push_lane_label_10039() {
    let scope = narrowed();
    assert_eq!(scope.label(), stable_peer_id(PEER_URL));
    assert_eq!(
        scope.scope(),
        &PeerOutboundScope::Namespaces(vec![NS_IN.to_string()])
    );
    assert!(!scope.is_deny());
}

/// Every degenerate input resolves to Deny under the unresolved label.
#[test]
fn every_degenerate_input_resolves_to_deny_10037() {
    let ok = config(&format!("[\"{NS_IN}\"]"), &format!("[\"{PEER_ID}\"]"));
    let rows: [(
        &str,
        Option<AuthenticatedPullPeer>,
        Result<String, std::env::VarError>,
    ); 7] = [
        ("no authenticated peer", None, Ok(ok.clone())),
        (
            "unset",
            Some(peer(PEER_ID)),
            Err(std::env::VarError::NotPresent),
        ),
        (
            "not unicode",
            Some(peer(PEER_ID)),
            Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
                "x",
            ))),
        ),
        ("empty string", Some(peer(PEER_ID)), Ok(String::new())),
        ("malformed json", Some(peer(PEER_ID)), Ok("{".to_string())),
        ("id no entry names", Some(peer("ai:someone-else")), Ok(ok)),
        (
            "entry without peer_ids",
            Some(peer(PEER_ID)),
            Ok(format!(
                "{{\"{PEER_URL}\":{{\"allowed_namespaces\":[\"{NS_IN}\"]}}}}"
            )),
        ),
    ];
    for (name, p, env) in rows {
        let scope = resolve_in(p.as_ref(), env);
        assert_eq!(
            scope,
            ServeScope {
                label: PULL_UNRESOLVED_PEER_LABEL.to_string(),
                scope: PeerOutboundScope::Deny,
            },
            "row {name}"
        );
    }
}

#[test]
fn empty_peer_ids_and_unbound_certs_prove_no_peer_10037() {
    assert_eq!(
        AuthenticatedPullPeer::signature_verified("", SignatureProof::mint_after_signature_check()),
        None
    );
    assert_eq!(
        AuthenticatedPullPeer::tls_bound(&crate::tls::ClientCertPeerId(None)),
        None
    );
    assert_eq!(
        AuthenticatedPullPeer::tls_bound(&crate::tls::ClientCertPeerId(Some(String::new()))),
        None
    );
    assert_eq!(
        AuthenticatedPullPeer::tls_bound(&crate::tls::ClientCertPeerId(Some(PEER_ID.to_string())))
            .map(|p| p.as_str().to_string()),
        Some(PEER_ID.to_string())
    );
}

/// Exhaustive table: outbound allows x inbound allows -> admitted.
#[test]
fn a_row_is_admitted_only_when_both_scopes_admit_it_10037() {
    let scope = narrowed();
    let rows: [(&str, bool, bool); 4] = [
        (NS_IN, true, true),
        (NS_IN, false, false),
        (NS_OUT, true, false),
        (NS_OUT, false, false),
    ];
    for (ns, inbound, expected) in rows {
        let admitted = admit_rows(vec![mem("m", ns)], &scope, |_| inbound);
        assert_eq!(
            admitted.len(),
            usize::from(expected),
            "ns {ns} inbound {inbound}"
        );
    }
}

#[test]
fn deny_admits_nothing_even_with_a_wide_inbound_test_10037() {
    let deny = resolve_in(None, Ok(String::new()));
    let admitted = admit_rows(vec![mem("a", NS_IN), mem("b", NS_OUT)], &deny, |_| true);
    assert!(admitted.is_empty());
}

#[test]
fn every_filtered_row_is_counted_under_the_configured_label_10039() {
    let scope = narrowed();
    let ns = "public/beta-count-10039";
    let before = count(scope.label(), ns);
    let admitted = admit_rows(
        vec![mem("a", NS_IN), mem("b", ns), mem("c", ns)],
        &scope,
        |_| true,
    );
    assert_eq!(admitted.len(), 1);
    assert_eq!(admitted.first().map(|m| m.id.as_str()), Some("a"));
    assert_eq!(count(scope.label(), ns) - before, 2);
}

fn count(peer_id: &str, ns: &str) -> u64 {
    filtered_series()
        .into_iter()
        .filter(|s| s.peer_id == peer_id && s.namespace == ns)
        .map(|s| s.count)
        .sum()
}

#[test]
fn admitted_rows_serialise_as_the_row_array_10037() {
    let admitted = admit_rows(vec![mem("a", NS_IN)], &narrowed(), |_| true);
    let value = serde_json::to_value(&admitted).unwrap_or_default();
    assert_eq!(value.as_array().map(Vec::len), Some(1));
    assert_eq!(value[0]["namespace"], NS_IN);
}

#[test]
fn a_changed_env_value_is_reparsed_not_served_from_the_cache_10037() {
    let first = narrowed();
    let widened = resolve_in(
        Some(&peer(PEER_ID)),
        Ok(config(
            &format!("[\"{NS_IN}\",\"{NS_OUT}\"]"),
            &format!("[\"{PEER_ID}\"]"),
        )),
    );
    assert_ne!(first.scope(), widened.scope());
    assert!(widened.scope().allows(NS_OUT));
    assert!(!narrowed().scope().allows(NS_OUT));
}
