#![no_main]
// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//
// R9 (#1960) capability / governance fuzz target.
//
// Exercises the ATTACKER-FACING capability-token surface — the untrusted
// `cap1:<base64>` wire decode, the fail-closed `verify`, the keyless
// `attenuate` fold, and the re-encode round-trip — plus the small pure
// parsers on the governance edge. The invariant under test is TOTALITY:
// none of these must EVER panic on hostile input; every failure path must
// return a typed `CapReject` / `Err`, never unwind.
//
// Published fuzz budget (ESTIMABLE): 15 minutes CPU per target on the CI
// fuzz lane (`cargo +nightly fuzz run fuzz_capability -- -max_total_time=900`),
// seeded from `fuzz/corpus/fuzz_capability/`. Local soak recommendation:
// 1 core-hour before any change to `src/governance/capability.rs`.

use libfuzzer_sys::fuzz_target;

use ai_memory::governance::capability::{
    CapRequest, CapabilityConfig, CapabilityToken, Caveat, OpLevel, attenuate, caveats_have_expiry,
    op_level_of, parse_capabilities_toggle, verify,
};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Pure governance-edge parsers must never panic on arbitrary text.
    let _ = parse_capabilities_toggle(s);
    let _ = op_level_of(s);
    let _ = OpLevel::parse(s);

    // Untrusted wire-token decode: the size-capped, fail-closed edge.
    if let Ok(tok) = CapabilityToken::from_wire(s) {
        // Re-encode round-trip must not panic.
        let _ = tok.to_wire();
        let _ = caveats_have_expiry(&tok.root_caveats);

        // Verify against an empty (zero-issuer) closed allowlist: the token
        // resolves to UnknownIssuer, but the version + decode + issuer-lookup
        // path all execute. Never panics.
        let cfg = CapabilityConfig::default();
        let req = CapRequest {
            action: s.to_string(),
            namespace: s.to_string(),
            agent_id: s.to_string(),
            now: 0,
        };
        let _ = verify(&tok, &cfg, &req);

        // Keyless attenuation (append-only HMAC fold) over fuzz-derived
        // caveats must be total.
        if let Ok(narrowed) = attenuate(&tok, Caveat::OpCeiling(OpLevel::Read)) {
            let _ = narrowed.to_wire();
            let _ = verify(&narrowed, &cfg, &req);
        }
        let _ = attenuate(&tok, Caveat::ExpiresAt(0));
        let _ = attenuate(&tok, Caveat::NamespacePrefix(s.to_string()));
        let _ = attenuate(&tok, Caveat::Agent(s.to_string()));
    }
});
