// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Regression tests for the two v1.0.0 truth-fixes:
//!
//! - **#2400 (capability under-claim):** `memory_capabilities` reported
//!   `compaction = planned` while the destructive consolidator SHIPPED at
//!   v0.8.0 (#1749 `ConsolidationPass`). It must now report `shipped`
//!   (`planned = false`, at the current package version) carrying the runtime
//!   `enabled` state (opt-in via `AI_MEMORY_COMPACTION_ENABLED` #81).
//!
//! - **#2401 (compliance defaults-lie):** an `applied` SOC2/HIPAA/GDPR/FedRAMP
//!   preset that sets `encrypt_at_rest = true` / `pseudonymize_actors = true`
//!   while the real gate is inactive used to boot SILENT while the docs +
//!   preset templates advertised the control. The pure detector
//!   `AuditComplianceConfig::unenforced_claims` must name each unenforced field
//!   so the boot path can emit a loud WARN (5-agent vote `4d3ea1c5`: WARN, not
//!   hard-refuse).

use ai_memory::config::{
    AuditComplianceConfig, CapabilityCompaction, CompliancePreset, FeatureTier,
};

// ---------------------------------------------------------------------------
// #2400 — capabilities reports compaction = shipped, not planned
// ---------------------------------------------------------------------------

#[test]
fn compaction_shipped_constructor_carries_enabled_state_2400() {
    // The shipped constructor is `planned=false` at the current package version
    // and carries the caller's enabled bit verbatim — the transcripts::shipped
    // precedent, extended to report runtime enablement.
    let off = CapabilityCompaction::shipped(false);
    assert!(!off.status.planned, "#2400: shipped ⇒ planned=false");
    assert!(!off.status.enabled, "#2400: enabled=false threads through");
    assert_eq!(off.status.version, env!("CARGO_PKG_VERSION"));

    let on = CapabilityCompaction::shipped(true);
    assert!(!on.status.planned);
    assert!(on.status.enabled, "#2400: enabled=true threads through");
    assert_eq!(on.status.version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn capabilities_reports_compaction_shipped_not_planned_2400() {
    // Drive the whole seed → reader → capabilities-report chain SERIALLY inside
    // one test fn so the process-global `COMPACTION_ENABLED` cannot race a
    // sibling test's read (integration files are one binary; #[test]s run in
    // parallel threads).

    // Default (unseeded / opt-out) posture: shipped, not enabled.
    ai_memory::config::set_compaction_enabled(false);
    let caps = FeatureTier::Autonomous.config().capabilities();
    let json = serde_json::to_value(&caps).expect("serialize capabilities");
    assert_eq!(
        json["compaction"]["planned"], false,
        "#2400: compaction must NOT be reported as planned — it shipped at v0.8.0 (#1749)"
    );
    assert_eq!(
        json["compaction"]["version"],
        env!("CARGO_PKG_VERSION"),
        "#2400: shipped feature reports the current package version"
    );
    assert_eq!(
        json["compaction"]["enabled"], false,
        "#2400: enabled reflects the opt-in runtime state (off here)"
    );

    // Enabled posture: the report flips `enabled` true (planned stays false).
    ai_memory::config::set_compaction_enabled(true);
    let caps_on = FeatureTier::Autonomous.config().capabilities();
    let json_on = serde_json::to_value(&caps_on).expect("serialize capabilities");
    assert_eq!(json_on["compaction"]["planned"], false);
    assert_eq!(
        json_on["compaction"]["enabled"], true,
        "#2400: capabilities must carry the live compaction-enabled state"
    );

    // Restore the default so no sibling process-global state leaks.
    ai_memory::config::set_compaction_enabled(false);
}

// ---------------------------------------------------------------------------
// #2401 — unenforced compliance-preset claims are detected + named
// ---------------------------------------------------------------------------

fn hipaa_encrypt_at_rest(applied: bool) -> AuditComplianceConfig {
    AuditComplianceConfig {
        hipaa: Some(CompliancePreset {
            applied: Some(applied),
            encrypt_at_rest: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn hipaa_encrypt_at_rest_without_gate_is_named_unenforced_2401() {
    // The exact bet-the-farm case: HIPAA preset applied advertising at-rest
    // encryption, but the real gate (`encryption_enabled`) is NOT active.
    let cfg = hipaa_encrypt_at_rest(true);
    let claims = cfg.unenforced_claims(/* at_rest_content_encryption_active */ false);
    assert_eq!(
        claims.len(),
        1,
        "one unenforced claim expected, got {claims:?}"
    );
    let c = &claims[0];
    assert_eq!(c.preset, "hipaa");
    assert_eq!(c.field, "encrypt_at_rest");
    assert!(
        c.does_not.contains("PLAINTEXT"),
        "message must state content is persisted in plaintext: {}",
        c.does_not
    );
    assert!(
        c.remediation.contains("sqlcipher") && c.remediation.contains("AI_MEMORY_ENCRYPT_AT_REST"),
        "remediation must name the real gate: {}",
        c.remediation
    );
}

#[test]
fn hipaa_encrypt_at_rest_with_active_gate_is_not_flagged_2401() {
    // When at-rest content encryption IS active, the claim is honored → no WARN.
    let cfg = hipaa_encrypt_at_rest(true);
    assert!(
        cfg.unenforced_claims(true).is_empty(),
        "#2401: an active at-rest gate satisfies the encrypt_at_rest claim"
    );
}

#[test]
fn unapplied_preset_never_flags_2401() {
    // `applied = false` means the preset is inert — no claim regardless of flags.
    let cfg = hipaa_encrypt_at_rest(false);
    assert!(
        cfg.unenforced_claims(false).is_empty(),
        "#2401: an un-applied preset advertises nothing"
    );
}

#[test]
fn pseudonymize_actors_is_always_unenforced_at_v1_0_0_2401() {
    // The knob has NO consumer at v1.0.0 (reserved), so an applied GDPR preset
    // asserting it can NEVER be honored — flagged regardless of the at-rest gate.
    let cfg = AuditComplianceConfig {
        gdpr: Some(CompliancePreset {
            applied: Some(true),
            pseudonymize_actors: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    for at_rest in [false, true] {
        let claims = cfg.unenforced_claims(at_rest);
        assert_eq!(claims.len(), 1, "at_rest={at_rest}: {claims:?}");
        assert_eq!(claims[0].preset, "gdpr");
        assert_eq!(claims[0].field, "pseudonymize_actors");
        assert!(
            claims[0].does_not.contains("does NOT pseudonymize"),
            "message must state the daemon does not pseudonymize: {}",
            claims[0].does_not
        );
    }
}

#[test]
fn multiple_applied_presets_accumulate_claims_2401() {
    // Both an unenforced encrypt_at_rest (hipaa) AND pseudonymize_actors (gdpr)
    // must each surface their own named claim.
    let cfg = AuditComplianceConfig {
        hipaa: Some(CompliancePreset {
            applied: Some(true),
            encrypt_at_rest: Some(true),
            ..Default::default()
        }),
        gdpr: Some(CompliancePreset {
            applied: Some(true),
            pseudonymize_actors: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };
    let claims = cfg.unenforced_claims(false);
    assert_eq!(claims.len(), 2, "{claims:?}");
    assert!(
        claims
            .iter()
            .any(|c| c.preset == "hipaa" && c.field == "encrypt_at_rest")
    );
    assert!(
        claims
            .iter()
            .any(|c| c.preset == "gdpr" && c.field == "pseudonymize_actors")
    );
}
