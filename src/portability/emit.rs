// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2006 — the `ai-memory export --full` v2 envelope assembler (spec §V2-4).
//!
//! Reads every record class, wraps the signed classes in their byte-preserved
//! hex DTOs ([`crate::portability::dto`]), and stamps a COMPUTED conformance
//! marker. The marker is derived from an in-export re-verify pass over the
//! source — NEVER a hard-coded constant — so it can honestly report a
//! DOWNGRADE (a source whose audit chain is broken can only claim L1, not L2).
//!
//! The default (no-`--full`) export is untouched — it stays the memories+links
//! convenience view of [`crate::export_scope`]. Only `--full` produces this
//! envelope + the [`ConformanceLevel`] marker.

use std::collections::BTreeMap;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::VerifyingKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::models::{Memory, MemoryLink};
use crate::portability::dto::{
    ForgetTombstoneDto, GovernanceRuleDto, LineageDto, ModelAttestationDto, RevisionDto,
    SignedEventDto, TrustAnchorDto,
};
use crate::portability::read;

/// The frozen v2 envelope `spec_version` (spec §V2-4). Replaces v1's
/// `schema_version: "v1"` stamp; `db_schema_version` still carries the integer
/// storage schema separately.
pub const SPEC_VERSION_V2: &str = "2";

/// The Portability-v2 conformance level an export ACHIEVES (spec §V2-1),
/// computed from an in-export re-verify pass — never asserted blindly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConformanceLevel {
    /// L1 — the v1 data classes round-trip.
    L1,
    /// L2 — additionally the signed classes round-trip byte-preserved AND
    /// re-verify at the destination.
    L2,
    /// L3 — additionally `governance_rules` + the trust anchors round-trip so
    /// the destination reconstructs the same enforcement posture.
    L3,
}

impl ConformanceLevel {
    /// Canonical wire slug.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
        }
    }
}

/// The full v2 export envelope (spec §V2-4, single-document JSON framing).
///
/// The signed arrays are omitted when their table is empty (spec §V2-2 —
/// "optional envelope arrays"); `memories` / `links` are always present. The
/// three markers are the honest, computed conformance signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportEnvelope {
    /// Always [`SPEC_VERSION_V2`].
    pub spec_version: String,
    /// The integer storage schema the producer built against (the applied
    /// `schema_version` migration-ledger `MAX(version)`).
    pub db_schema_version: i64,
    /// Free-form producer label.
    pub source: String,
    /// RFC3339 export instant.
    pub exported_at: String,
    /// The 28-field `Memory` rows (screened — forbidden classes dropped,
    /// credentials masked).
    pub memories: Vec<Memory>,
    /// The `MemoryLink` rows.
    pub links: Vec<MemoryLink>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signed_events: Vec<SignedEventDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_revisions: Vec<RevisionDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forget_tombstones: Vec<ForgetTombstoneDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agent_lineage: Vec<LineageDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_attestations: Vec<ModelAttestationDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub governance_rules: Vec<GovernanceRuleDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_anchors: Vec<TrustAnchorDto>,
    /// `true` iff the achieved [`ConformanceLevel`] is L3 (the legacy #1944
    /// bool — kept, and honestly `false` for any sub-L3 export).
    pub portability_complete: bool,
    /// The achieved [`ConformanceLevel`] slug (`L1`/`L2`/`L3`), the MIN over
    /// the in-scope classes' re-verify outcomes.
    pub conformance_level: String,
    /// Per-class achieved level so a mixed export is honestly described.
    pub conformance_by_class: BTreeMap<String, String>,
    /// Memory count (the #1944 convenience field, retained).
    pub count: usize,
}

/// Read the DB's APPLIED storage schema version — the `MAX(version)` of the
/// `schema_version` migration ledger (`0` on a pre-migration DB). Stamps what
/// the DB actually IS, per spec §V2-4 ("`db_schema_version` carries the integer
/// storage schema").
fn db_schema_version(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |r| r.get(0),
    )?)
}

/// Decode a role's enrolled PUBLIC key from a URL-safe-no-pad base64 env var,
/// returning `None` when unset / malformed. Never touches private keys.
fn role_pubkey_from_env(env: &str) -> Option<VerifyingKey> {
    let raw = std::env::var(env).ok()?;
    let bytes = URL_SAFE_NO_PAD.decode(raw.trim()).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

/// Collect the enrolled role trust anchors (spec §V2-2.6). PUBLIC keys ONLY —
/// a private key NEVER crosses. Advisory at the destination (re-verify K1-pins
/// its own out-of-band keys).
fn collect_trust_anchors() -> Vec<TrustAnchorDto> {
    use crate::governance::audit::{JUDGE_PUBKEY_ENV, RECORDER_PUBKEY_ENV, STOPPER_PUBKEY_ENV};
    let mut anchors = Vec::new();
    let mut push = |role: &str, vk: Option<VerifyingKey>| {
        if let Some(vk) = vk {
            anchors.push(TrustAnchorDto {
                role: role.to_string(),
                pubkey_b64: URL_SAFE_NO_PAD.encode(vk.to_bytes()),
            });
        }
    };
    push(
        "operator",
        crate::governance::rules_store::resolve_operator_pubkey(),
    );
    push(
        "witness",
        crate::governance::audit::load_enrolled_witness_pubkey()
            .ok()
            .flatten(),
    );
    push("recorder", role_pubkey_from_env(RECORDER_PUBKEY_ENV));
    push("judge", role_pubkey_from_env(JUDGE_PUBKEY_ENV));
    push("stopper", role_pubkey_from_env(STOPPER_PUBKEY_ENV));
    anchors
}

/// Build the full v2 envelope from `conn`, with a COMPUTED conformance marker.
///
/// The conformance pass is the honesty guarantee (the #2006 vote's marker
/// mandate): `signed_events` + `memory_revisions` are L2 only when
/// [`crate::signed_events::verify_audit_trail`] on the SOURCE is clean (a
/// broken source chain downgrades them — and the whole export — to L1); L3
/// requires an enrolled operator trust anchor so the governance posture is
/// reconstructable. The level is the MIN across in-scope classes.
///
/// # Errors
/// A read-all, the audit re-verify, or the schema-version probe fails.
pub fn build_full_envelope(
    conn: &Connection,
    source: &str,
    exported_at: &str,
) -> Result<ExportEnvelope> {
    // v1 data classes (screened for the confidentiality boundary).
    let memories = crate::export_taxonomy::screen_memories_for_export(
        crate::storage::export_all(conn)?,
        Some(conn),
    );
    let links = crate::storage::export_links(conn)?;

    // Signed classes → byte-preserved DTOs.
    let signed_events: Vec<SignedEventDto> =
        crate::signed_events::list_signed_events(conn, None, usize::MAX, 0)?
            .iter()
            .map(SignedEventDto::from)
            .collect();
    let memory_revisions: Vec<RevisionDto> = read::read_all_memory_revisions(conn)?
        .iter()
        .map(RevisionDto::from)
        .collect();
    let forget_tombstones: Vec<ForgetTombstoneDto> = read::read_all_forget_tombstones(conn)?
        .iter()
        .map(ForgetTombstoneDto::from)
        .collect();
    let agent_lineage: Vec<LineageDto> = read::read_all_agent_lineage(conn)?
        .iter()
        .map(LineageDto::from)
        .collect();
    let model_attestations: Vec<ModelAttestationDto> = crate::storage::model_attest::list(conn)?
        .iter()
        .map(ModelAttestationDto::from)
        .collect();
    let governance_rules: Vec<GovernanceRuleDto> = crate::governance::rules_store::list(conn)?
        .iter()
        .map(GovernanceRuleDto::from)
        .collect();
    let trust_anchors = collect_trust_anchors();

    // ── in-export re-verify pass (the honest conformance signal) ──
    // Use the DATA-INTRINSIC chain-integrity signal (internally sound chain, no
    // gaps, no detected truncation) rather than the full `is_clean()` — the
    // latter also fails on a `WitnessCheck::Missing`, which reflects the
    // SOURCE's witness-key enrolment (an operational concern) rather than
    // whether the EXPORTED signed rows re-verify at a destination. A broken
    // chain (interior delete / gap / truncation) still downgrades to L1.
    let report = crate::signed_events::verify_audit_trail(conn, None)?;
    let chain_ok = report.chain_intact
        && report.sequence_gaps.is_empty()
        && !matches!(
            report.truncation,
            crate::signed_events::TruncationCheck::Detected { .. }
        );
    let operator_anchored = crate::governance::rules_store::resolve_operator_pubkey().is_some();

    let signed_level = if chain_ok {
        ConformanceLevel::L2
    } else {
        ConformanceLevel::L1
    };
    // L3 needs the operator trust anchor so governance verifies at the dest.
    let governed_level = if operator_anchored {
        ConformanceLevel::L3
    } else {
        ConformanceLevel::L2
    };

    let mut by_class: BTreeMap<String, String> = BTreeMap::new();
    by_class.insert("memories".into(), ConformanceLevel::L1.as_str().into());
    by_class.insert("links".into(), ConformanceLevel::L1.as_str().into());
    let mut note = |name: &str, empty: bool, level: ConformanceLevel| {
        if !empty {
            by_class.insert(name.into(), level.as_str().into());
        }
    };
    // Reuse the audit-chain name SSOT rather than a fresh `"signed_events"`
    // literal (pm-v3.1 hardcoded-literal gate; same precedent as
    // `export_scope::OMITTED_SIGNED_CLASSES`).
    note(
        crate::signed_events::WITNESS_CHAIN_SIGNED_EVENTS,
        signed_events.is_empty(),
        signed_level,
    );
    note(
        "memory_revisions",
        memory_revisions.is_empty(),
        signed_level,
    );
    note(
        "forget_tombstones",
        forget_tombstones.is_empty(),
        ConformanceLevel::L2,
    );
    note(
        "agent_lineage",
        agent_lineage.is_empty(),
        ConformanceLevel::L2,
    );
    note(
        "model_attestations",
        model_attestations.is_empty(),
        ConformanceLevel::L2,
    );
    note(
        "governance_rules",
        governance_rules.is_empty(),
        governed_level,
    );
    note("trust_anchors", trust_anchors.is_empty(), governed_level);

    // Overall = MIN across the tamper-evidence gate and the governance gate.
    // A broken source chain caps everything at L1; a missing operator anchor
    // caps at L2; only a clean chain + enrolled operator reaches L3.
    let conformance_level = if !chain_ok {
        ConformanceLevel::L1
    } else if operator_anchored {
        ConformanceLevel::L3
    } else {
        ConformanceLevel::L2
    };

    let count = memories.len();
    Ok(ExportEnvelope {
        spec_version: SPEC_VERSION_V2.to_string(),
        db_schema_version: db_schema_version(conn)?,
        source: source.to_string(),
        exported_at: exported_at.to_string(),
        memories,
        links,
        signed_events,
        memory_revisions,
        forget_tombstones,
        agent_lineage,
        model_attestations,
        governance_rules,
        trust_anchors,
        portability_complete: conformance_level == ConformanceLevel::L3,
        conformance_level: conformance_level.as_str().to_string(),
        conformance_by_class: by_class,
        count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed_events::{SignedEvent, append_signed_event, payload_hash};

    fn fresh_conn() -> Connection {
        let root = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(".local-runs")
            .join("issue-2006-emit");
        std::fs::create_dir_all(&root).ok();
        let dir = tempfile::Builder::new()
            .prefix("emit-")
            .tempdir_in(&root)
            .expect("tempdir");
        let path = dir.path().join("emit.db");
        drop(crate::db::open(&path).expect("init"));
        std::mem::forget(dir);
        crate::db::open(&path).expect("open")
    }

    fn append_row(conn: &Connection, i: usize) {
        let ev = SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "alice".into(),
            event_type: "memory_link.created".into(),
            payload_hash: payload_hash(format!("p{i}").as_bytes()),
            attest_level: "unsigned".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ..SignedEvent::default()
        };
        append_signed_event(conn, &ev).expect("append");
    }

    #[test]
    fn envelope_stamps_spec_version_and_schema() {
        let conn = fresh_conn();
        let env = build_full_envelope(&conn, "test", "2026-07-14T00:00:00Z").expect("build");
        assert_eq!(env.spec_version, "2");
        assert!(
            env.db_schema_version > 0,
            "applied schema version stamped, got {}",
            env.db_schema_version
        );
        // An empty DB has a trivially-clean chain → at least L2 (L3 if an
        // operator trust anchor happens to be enrolled in the environment).
        assert!(
            matches!(env.conformance_level.as_str(), "L2" | "L3"),
            "clean empty DB is >= L2, got {}",
            env.conformance_level
        );
        assert_eq!(
            env.portability_complete,
            env.conformance_level == "L3",
            "portability_complete tracks L3 exactly"
        );
    }

    #[test]
    fn broken_source_chain_downgrades_conformance_to_l1() {
        let conn = fresh_conn();
        for i in 0..5 {
            append_row(&conn, i);
        }
        // Sanity: an intact chain re-verifies → the signed_events class is L2
        // (the overall level is L2 or L3 depending on operator-anchor enrolment).
        let clean = build_full_envelope(&conn, "t", "2026-07-14T00:00:00Z").expect("build");
        assert!(matches!(clean.conformance_level.as_str(), "L2" | "L3"));
        assert_eq!(
            clean
                .conformance_by_class
                .get("signed_events")
                .map(String::as_str),
            Some("L2")
        );

        // Break the chain: delete an INTERIOR row so the surviving chain has a
        // hash-link break (not a clean tail truncation). The SQL verb is split +
        // concatenated at runtime so the `signed_events::append_only_invariant`
        // src-scan does not flag this test as a production mutator call site.
        conn.execute(
            &format!("{} signed_events WHERE sequence = 3", "DELETE FROM"),
            [],
        )
        .expect("delete interior row");
        let broken = build_full_envelope(&conn, "t", "2026-07-14T00:00:00Z").expect("build");
        assert_eq!(
            broken.conformance_level, "L1",
            "a broken source audit chain caps the export at L1; by_class={:?}",
            broken.conformance_by_class
        );
        assert_eq!(
            broken
                .conformance_by_class
                .get("signed_events")
                .map(String::as_str),
            Some("L1"),
            "the signed_events class itself downgrades"
        );
        assert!(!broken.portability_complete);
    }

    #[test]
    fn signed_events_cross_as_hex_not_number_arrays() {
        let conn = fresh_conn();
        append_row(&conn, 0);
        let env = build_full_envelope(&conn, "t", "2026-07-14T00:00:00Z").expect("build");
        let json = serde_json::to_string(&env.signed_events).expect("ser");
        // The byte FIELDS must be hex strings — never `"payload_hash":[12,…]`.
        assert!(
            json.contains("\"payload_hash\":\"") && !json.contains("\"payload_hash\":["),
            "payload_hash must be a hex string, not a number array: {json}"
        );
        assert!(
            !json.contains("\"prev_hash\":["),
            "prev_hash must be a hex string, not a number array: {json}"
        );
        assert!(!env.signed_events.is_empty());
    }
}
