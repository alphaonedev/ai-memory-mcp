// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// #3065 (Wave-2 Cluster B, cert-core) — lane test for the ADMIN_HEADER_TRUST
// identity boot-gate decision (`handlers::admin_role::admin_header_trust_boot_refusal`).
//
// `dangerous_combo_refuses_boot` is the REMOVAL-PROOF lane test cited by
// `scripts/check-cert-removal-proof.sh`: when the harness neutralizes the
// control's body to `None` (always-permit), this test's `.is_some()` assertion
// goes RED — proving the refusal is load-bearing. The remaining tests pin every
// safe branch so the by-the-book single-proxy-cert runbook is never bricked.

use ai_memory::handlers::admin_role::{
    AdminHeaderTrustBootInputs, admin_header_trust_boot_refusal,
};

/// The exact dangerous topology the gate exists to refuse: certified posture
/// engaged, header-trust on, a MULTI-fingerprint inbound mTLS allowlist, and no
/// per-agent binding fallback.
fn dangerous_inputs() -> AdminHeaderTrustBootInputs {
    AdminHeaderTrustBootInputs {
        posture_engaged: true,
        header_trust_enabled: true,
        mtls_allowlist_len: 3,
        attested_identity_enforced: false,
        agent_api_key_count: 0,
    }
}

#[test]
fn dangerous_combo_refuses_boot() {
    let refusal = admin_header_trust_boot_refusal(dangerous_inputs());
    assert!(
        refusal.is_some(),
        "header-trust + multi-fingerprint mTLS allowlist + no per-agent binding under the \
         certified posture MUST refuse boot"
    );
    let msg = refusal.unwrap();
    assert!(
        msg.contains("AI_MEMORY_ADMIN_HEADER_TRUST"),
        "refusal names the offending knob: {msg}"
    );
    assert!(
        msg.contains("SINGLE-fingerprint mTLS proxy"),
        "refusal states the certified topology: {msg}"
    );
}

#[test]
fn standard_posture_never_bites() {
    // Advisory outside certified/asi-hard — single-node dev must not brick.
    let mut i = dangerous_inputs();
    i.posture_engaged = false;
    assert!(admin_header_trust_boot_refusal(i).is_none());
}

#[test]
fn header_trust_off_permits() {
    let mut i = dangerous_inputs();
    i.header_trust_enabled = false;
    assert!(admin_header_trust_boot_refusal(i).is_none());
}

#[test]
fn single_fingerprint_proxy_is_byte_for_byte_unchanged() {
    // The certified runbook: EXACTLY one client-cert fingerprint (the proxy).
    let mut i = dangerous_inputs();
    i.mtls_allowlist_len = 1;
    assert!(
        admin_header_trust_boot_refusal(i).is_none(),
        "a single-fingerprint proxy stand-up must NEVER self-brick"
    );
}

#[test]
fn zero_fingerprints_no_proxy_refuses_boot() {
    // BLOCKER 2 (adversarial review): len == 0 (NO --mtls-allowlist at all)
    // means header-trust with no client-cert layer — strictly MORE exposed than
    // the multi-cert case, and it BOOTS CLEANLY through the 18 posture checks +
    // asi-hard KNOBS (none require an allowlist). It MUST refuse, not permit.
    let mut i = dangerous_inputs();
    i.mtls_allowlist_len = 0;
    let refusal = admin_header_trust_boot_refusal(i);
    assert!(
        refusal.is_some(),
        "header-trust with ZERO inbound mTLS fingerprints and no per-agent backstop under \
         the certified posture MUST refuse boot (no proxy = no client-cert layer)"
    );
    assert!(
        refusal.unwrap().contains("UNSET"),
        "the len==0 refusal must name the unset allowlist"
    );
}

#[test]
fn attested_identity_enforce_backstops_multi_fingerprint() {
    let mut i = dangerous_inputs();
    i.attested_identity_enforced = true;
    assert!(
        admin_header_trust_boot_refusal(i).is_none(),
        "enforce-mode per-agent binding backstops a multi-fingerprint allowlist"
    );
}

#[test]
fn enrolled_agent_keys_backstop_multi_fingerprint() {
    let mut i = dangerous_inputs();
    i.agent_api_key_count = 5;
    assert!(
        admin_header_trust_boot_refusal(i).is_none(),
        "enrolled per-agent api-keys backstop a multi-fingerprint allowlist"
    );
}
