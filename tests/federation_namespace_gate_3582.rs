// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3582: the same absent-allowlist decision must govern every mutation shape.

use ai_memory::federation::peer_attestation::{PeerAttestationConfig, PeerScope};
use ai_memory::federation::receive_auth::{
    LANE_DELETIONS, LANE_NAMESPACE_META, inbound_by_id_namespace_authorized,
    inbound_namespace_gate_enabled, inbound_namespace_meta_authorized,
    inbound_write_namespace_authorized, inbound_write_needs_existing_namespace,
};

fn verdicts(config: &PeerAttestationConfig, peer: Option<&str>, require: bool) -> [bool; 4] {
    [
        inbound_write_namespace_authorized(
            "memories",
            "id",
            "secure/ops",
            None,
            config,
            peer,
            require,
        ),
        inbound_by_id_namespace_authorized(LANE_DELETIONS, "id", None, config, peer, require),
        inbound_by_id_namespace_authorized(
            LANE_DELETIONS,
            "id",
            Some("secure/ops"),
            config,
            peer,
            require,
        ),
        inbound_namespace_meta_authorized(
            LANE_NAMESPACE_META,
            "secure/ops",
            None,
            config,
            peer,
            require,
        ),
    ]
}

#[test]
fn no_allowlist_requires_explicit_opt_out_on_every_helper_3582() {
    let config = PeerAttestationConfig::default();
    for peer in [None, Some(""), Some("peer")] {
        for require in [true, false] {
            assert_eq!(inbound_namespace_gate_enabled(&config, require), require);
            assert!(!inbound_write_needs_existing_namespace(peer, &config));
            assert_eq!(verdicts(&config, peer, require), [!require; 4]);
        }
    }
}

#[test]
fn configured_empty_allowlist_cannot_use_opt_out_3582() {
    let config = PeerAttestationConfig::from_peers(std::collections::HashMap::new());
    for require in [true, false] {
        assert!(inbound_namespace_gate_enabled(&config, require));
        assert_eq!(verdicts(&config, Some("peer"), require), [false; 4]);
    }
}

#[test]
fn configured_scope_keeps_stored_namespace_requirement_3582() {
    let config = PeerAttestationConfig::from_peers(std::collections::HashMap::from([(
        "peer".to_owned(),
        PeerScope {
            allowed_sender_agent_ids: vec![],
            allowed_namespaces: vec!["secure/**".to_owned()],
        },
    )]));
    for require in [true, false] {
        assert!(inbound_namespace_gate_enabled(&config, require));
        assert!(inbound_write_needs_existing_namespace(
            Some("peer"),
            &config
        ));
        assert_eq!(
            verdicts(&config, Some("peer"), require),
            [true, false, true, true]
        );
        assert_eq!(verdicts(&config, Some("unknown"), require), [false; 4]);
    }
}
