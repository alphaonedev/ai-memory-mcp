// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 G28 (#1838) — forbidden-export-class taxonomy + fail-closed
//! export-boundary enforcement.
//!
//! ## What this is
//!
//! [`ForbiddenExportClass`] is the CLOSED taxonomy of record / material
//! CLASSES that must NEVER cross an export boundary in the clear:
//!
//! 1. [`ForbiddenExportClass::PrivateKeyMaterial`] — any daemon / witness
//!    / recorder / judge / stopper / recovery **private** signing key
//!    (PEM-armored or a raw secret-key field).
//! 2. [`ForbiddenExportClass::MasterThresholdSecret`] — a master secret or
//!    a threshold / Shamir key share.
//! 3. [`ForbiddenExportClass::SignedPolicyRuleSigningKey`] — the governance
//!    (operator) rule **private** signing key. The DB only ever holds a
//!    rule's public `signature`; the private signing key lives in the
//!    key-dir. This class is the belt-and-suspenders guard against a
//!    signing key that leaked into a memory content / metadata field.
//! 4. [`ForbiddenExportClass::BiometricBehavioralEmbedding`] — a
//!    biometric / behavioral embedding vector, identified by a
//!    **producer-side** class tag (`metadata.embedding_class ∈
//!    {biometric, behavioral}`). See the honest-scope note below.
//!
//! This is the D14-adjacent companion to [`crate::egress::EgressClass`]:
//! that enum names the LANES bytes leave through (webhook / federation /
//! forensic-export / inference); THIS enum names the record CLASSES that a
//! lane must refuse. The two are orthogonal — a forensic-export lane
//! consults BOTH (its lane guard is the secret-screen; its class guard is
//! this taxonomy).
//!
//! ## Honest scope (ATTESTABLE vs ESTIMABLE)
//!
//! - **Structurally impossible to export via a DB egress (already true).**
//!   Private keys, master/threshold secrets, and the governance signing
//!   key all live in the KEY-DIR on the filesystem, NOT in the `memories`
//!   / `memory_links` / `signed_events` tables. The forensic bundle and
//!   the memory-export handler read only DB tables, so a well-formed key
//!   file cannot appear in those artifacts. Biometric / behavioral
//!   embedding VECTORS are likewise absent — neither the forensic-bundle
//!   `MemoryEnvelope` nor the memory-export `Memory` row carries the raw
//!   embedding vector.
//! - **Actively gated (ATTESTABLE, this module).** The real residual risk
//!   is key material / a signing key / a secret that leaked into a memory
//!   ROW's content or `metadata` (a mis-store, a metadata stash) and would
//!   then ride an export in the clear. [`classify_export_value`] inspects
//!   the serialized record and REFUSES it fail-closed, emitting a signed
//!   `export.forbidden_class_refused` audit row. That refusal + its audit
//!   witness are cryptographically attestable.
//! - **ESTIMABLE (producer-side tag).** The substrate does NOT tag an
//!   arbitrary float vector as "biometric" — no classifier can decide that
//!   from the bytes. [`ForbiddenExportClass::BiometricBehavioralEmbedding`]
//!   is therefore keyed on a PRODUCER-side metadata tag
//!   (`metadata.embedding_class`). The taxonomy NAMES the class and ships
//!   the enforcement hook; per-embedding biometric classification is the
//!   producer's obligation to tag. This is the honest boundary.
//!
//! ## Fail-closed disposition
//!
//! An export path that hits a forbidden class SKIPS the record (never
//! bundles it in the clear) and records the refusal. A record that cannot
//! even be serialized for classification is likewise dropped (fail-closed),
//! never emitted unclassified.

use rusqlite::Connection;
use serde_json::Value;

/// The closed taxonomy of record / material classes that must NEVER cross
/// an export boundary. Ordered by severity — [`ForbiddenExportClass::rank`]
/// makes the most-severe class win when a record matches several, so the
/// audit row names the worst offender deterministically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForbiddenExportClass {
    /// Private signing-key material — daemon / witness / recorder / judge /
    /// stopper / recovery keys (PEM-armored or a raw secret-key field).
    PrivateKeyMaterial,
    /// A master secret or a threshold / Shamir key share.
    MasterThresholdSecret,
    /// The governance (operator) rule PRIVATE signing key. Distinct from a
    /// rule's public `signature`, which is safe to export.
    SignedPolicyRuleSigningKey,
    /// A biometric / behavioral embedding, identified by the producer-side
    /// `metadata.embedding_class` tag. ESTIMABLE — see the module docs.
    BiometricBehavioralEmbedding,
}

/// The complete closed set, most-severe first. Any enforcement or
/// documentation surface iterates THIS rather than re-listing the variants.
pub const ALL_FORBIDDEN_EXPORT_CLASSES: [ForbiddenExportClass; 4] = [
    ForbiddenExportClass::PrivateKeyMaterial,
    ForbiddenExportClass::MasterThresholdSecret,
    ForbiddenExportClass::SignedPolicyRuleSigningKey,
    ForbiddenExportClass::BiometricBehavioralEmbedding,
];

// ── Classifier markers (structural; single-use in this module) ─────────
//
// PEM private-key armor is the "-----BEGIN … PRIVATE KEY-----" family. We
// match on the opening sigil plus the "PRIVATE KEY" token so every RSA /
// EC / OPENSSH / ENCRYPTED / PKCS8 spelling trips one check.
const PEM_BEGIN_SIGIL: &str = "-----BEGIN";
const PEM_PRIVATE_KEY_TOKEN: &str = "PRIVATE KEY-----";

/// JSON object-key substrings whose presence marks private key material.
/// Matched case-insensitively as a substring so `daemon_private_key`,
/// `recorder_secret_key`, `ed25519_secret` … all trip.
const PRIVATE_KEY_FIELD_MARKERS: [&str; 6] = [
    "private_key",
    "secret_key",
    "secret_key_bytes",
    "signing_secret",
    "keypair_secret",
    "ed25519_secret",
];

/// JSON object-key substrings whose presence marks a master / threshold
/// secret.
const MASTER_THRESHOLD_FIELD_MARKERS: [&str; 5] = [
    "master_secret",
    "master_key",
    "threshold_share",
    "threshold_secret",
    "shamir_share",
];

/// JSON object-key substrings whose presence marks the governance-rule
/// PRIVATE signing key (never the public `signature`).
const RULE_SIGNING_KEY_FIELD_MARKERS: [&str; 4] = [
    "rule_signing_key",
    "governance_signing_key",
    "policy_signing_key",
    "operator_signing_key",
];

/// The producer-side metadata key that tags an embedding's class, plus the
/// two tag values that mark it forbidden.
const EMBEDDING_CLASS_KEYS: [&str; 3] = ["embedding_class", "embedding_kind", "biometric_class"];
const EMBEDDING_CLASS_BIOMETRIC: &str = "biometric";
const EMBEDDING_CLASS_BEHAVIORAL: &str = "behavioral";

impl ForbiddenExportClass {
    /// Severity rank — lower is more severe. Used to pick the worst class
    /// when a record matches several.
    #[must_use]
    const fn rank(self) -> u8 {
        match self {
            Self::PrivateKeyMaterial => 0,
            Self::MasterThresholdSecret => 1,
            Self::SignedPolicyRuleSigningKey => 2,
            Self::BiometricBehavioralEmbedding => 3,
        }
    }

    /// The canonical wire / audit token for this class.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateKeyMaterial => "private_key_material",
            Self::MasterThresholdSecret => "master_threshold_secret",
            Self::SignedPolicyRuleSigningKey => "signed_policy_rule_signing_key",
            Self::BiometricBehavioralEmbedding => "biometric_behavioral_embedding",
        }
    }

    /// A one-line human-readable description for the audit reason / docs.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::PrivateKeyMaterial => {
                "private signing-key material (daemon/witness/recorder/judge/stopper/recovery)"
            }
            Self::MasterThresholdSecret => "master secret or threshold / Shamir key share",
            Self::SignedPolicyRuleSigningKey => "governance-rule private signing key",
            Self::BiometricBehavioralEmbedding => {
                "biometric / behavioral embedding (producer-tagged)"
            }
        }
    }

    /// Keep `self` if it is at least as severe as `other`, else adopt
    /// `other`. Small helper so the recursive classifier can fold matches.
    #[must_use]
    fn most_severe(self, other: Self) -> Self {
        if other.rank() < self.rank() {
            other
        } else {
            self
        }
    }
}

/// Classify a single JSON value against the forbidden-export taxonomy,
/// returning the most-severe class that matches (or `None` when clean).
///
/// The scan is structural and fail-closed: it walks the value recursively,
/// checking every object KEY against the field-name marker tables, every
/// string VALUE for PEM private-key armor, and the producer-side
/// `embedding_class` tag. It is side-effect-free — the single SSOT for the
/// decision so the enforcement site and any audit re-evaluation agree.
#[must_use]
pub fn classify_export_value(value: &Value) -> Option<ForbiddenExportClass> {
    let mut found: Option<ForbiddenExportClass> = None;
    classify_into(value, &mut found);
    found
}

/// Recursive worker: folds every match into `acc`, keeping the most-severe.
/// Short-circuits once the top-severity class is found (nothing can beat it).
fn classify_into(value: &Value, acc: &mut Option<ForbiddenExportClass>) {
    if *acc == Some(ForbiddenExportClass::PrivateKeyMaterial) {
        return; // already the worst; no need to keep scanning
    }
    match value {
        Value::String(s) => {
            if let Some(c) = classify_text(s) {
                fold(acc, c);
            }
        }
        Value::Array(items) => {
            for item in items {
                classify_into(item, acc);
                if *acc == Some(ForbiddenExportClass::PrivateKeyMaterial) {
                    return;
                }
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                if let Some(c) = classify_key(key, child) {
                    fold(acc, c);
                }
                classify_into(child, acc);
                if *acc == Some(ForbiddenExportClass::PrivateKeyMaterial) {
                    return;
                }
            }
        }
        // Numbers / bools / null carry no forbidden class on their own.
        _ => {}
    }
}

/// Fold one match into the accumulator, keeping the most-severe class.
fn fold(acc: &mut Option<ForbiddenExportClass>, c: ForbiddenExportClass) {
    *acc = Some(match *acc {
        Some(existing) => existing.most_severe(c),
        None => c,
    });
}

/// Classify a bare string value: only PEM private-key armor is detectable
/// in an unkeyed string (a raw base64 blob is indistinguishable from benign
/// high-entropy content — that is the secret-screen's anchored-pattern job,
/// not this class taxonomy's).
#[must_use]
fn classify_text(s: &str) -> Option<ForbiddenExportClass> {
    if s.contains(PEM_BEGIN_SIGIL) && s.contains(PEM_PRIVATE_KEY_TOKEN) {
        return Some(ForbiddenExportClass::PrivateKeyMaterial);
    }
    None
}

/// Classify one object entry by its KEY (and, for the embedding tag, its
/// VALUE). Returns the class the key marks, if any.
#[must_use]
fn classify_key(key: &str, child: &Value) -> Option<ForbiddenExportClass> {
    let lower = key.to_ascii_lowercase();

    // Producer-side biometric / behavioral embedding tag (value-sensitive).
    if EMBEDDING_CLASS_KEYS.iter().any(|k| lower == *k) {
        if let Value::String(v) = child {
            let vv = v.trim().to_ascii_lowercase();
            if vv == EMBEDDING_CLASS_BIOMETRIC || vv == EMBEDDING_CLASS_BEHAVIORAL {
                return Some(ForbiddenExportClass::BiometricBehavioralEmbedding);
            }
        }
    }

    // Field-name markers, most-severe first.
    if PRIVATE_KEY_FIELD_MARKERS.iter().any(|m| lower.contains(m)) {
        return Some(ForbiddenExportClass::PrivateKeyMaterial);
    }
    if MASTER_THRESHOLD_FIELD_MARKERS
        .iter()
        .any(|m| lower.contains(m))
    {
        return Some(ForbiddenExportClass::MasterThresholdSecret);
    }
    if RULE_SIGNING_KEY_FIELD_MARKERS
        .iter()
        .any(|m| lower.contains(m))
    {
        return Some(ForbiddenExportClass::SignedPolicyRuleSigningKey);
    }
    None
}

/// Convenience: classify a [`crate::models::Memory`] by serializing it and
/// running [`classify_export_value`] over the result. A serialize failure
/// (structurally near-impossible for `Memory`) is treated fail-closed as a
/// `PrivateKeyMaterial` hit so a record that cannot be inspected is never
/// silently exported.
#[must_use]
pub fn classify_memory(mem: &crate::models::Memory) -> Option<ForbiddenExportClass> {
    match serde_json::to_value(mem) {
        Ok(v) => classify_export_value(&v),
        Err(_) => Some(ForbiddenExportClass::PrivateKeyMaterial),
    }
}

/// Append a signed refusal row for a forbidden-class export redaction to
/// the append-only `signed_events` chain. Substrate-emitted: daemon-signed
/// when an audit key is enrolled, else `unsigned` — the same posture as
/// [`crate::egress::emit_inference_egress_refusal`]. The `payload_hash`
/// commits the class, the artifact path the record would have occupied, and
/// the reason.
///
/// # Errors
///
/// Propagates the underlying `append_signed_event` error (typically a
/// sqlite failure). Callers treat the audit emission as best-effort and
/// WARN on error rather than failing the export.
pub fn emit_export_refusal(
    conn: &Connection,
    class: ForbiddenExportClass,
    artifact_path: &str,
    agent_id: &str,
    reason: &str,
) -> anyhow::Result<()> {
    use crate::signed_events::{
        SignedEvent, append_signed_event, event_types::EXPORT_FORBIDDEN_CLASS_REFUSED, payload_hash,
    };
    let preimage = format!(
        "export-forbidden|class={}|artifact={}|reason={}",
        class.as_str(),
        artifact_path,
        reason
    );
    let event = SignedEvent::with_daemon_signature(
        payload_hash(preimage.as_bytes()),
        agent_id.to_string(),
        EXPORT_FORBIDDEN_CLASS_REFUSED.to_string(),
        chrono::Utc::now().to_rfc3339(),
        None,
    );
    append_signed_event(conn, &event)
}

/// Screen one candidate export record fail-closed. Classifies `value`; on a
/// forbidden-class hit it emits a signed refusal (best-effort — a WARN on
/// append failure, never fails the export) and returns the class so the
/// caller can SKIP the record. `None` means the record is clean and may be
/// emitted.
///
/// This is the single enforcement primitive every DB export path calls:
/// the forensic-bundle assembler and the memory-export handler both consult
/// it so the decision + the audit row cannot drift.
#[must_use]
pub fn screen_export_value_audited(
    conn: &Connection,
    artifact_path: &str,
    agent_id: &str,
    value: &Value,
) -> Option<ForbiddenExportClass> {
    let class = classify_export_value(value)?;
    let reason = format!(
        "export refused: record classified {} ({}) — not emitted into export artifact",
        class.as_str(),
        class.description()
    );
    if let Err(e) = emit_export_refusal(conn, class, artifact_path, agent_id, &reason) {
        tracing::warn!(
            "forbidden-export-class signed refusal NOT recorded (append failed) for {} \
             artifact={artifact_path}: {e}",
            class.as_str()
        );
    }
    tracing::warn!(
        "export boundary refused a {} record ({}) — artifact={artifact_path} withheld \
         fail-closed",
        class.as_str(),
        class.description()
    );
    Some(class)
}

/// Unified export-egress screen for a corpus of memory ROWS — the single
/// SSOT the CLI `export`, the HTTP admin `export_memories`, and (row-wise)
/// the forensic bundle share so the three egress paths cannot drift (M2:
/// three parallel egress paths previously gated inconsistently). Applies
/// BOTH guards the confidentiality invariant requires, per row, in THIS
/// order (order is load-bearing — see below):
///
/// 1. **Forbidden-class drop** ([`classify_memory`], #1838/G28): a row that
///    classifies into a [`ForbiddenExportClass`] (private-key material /
///    master-threshold secret / governance signing key / producer-tagged
///    biometric embedding) is DROPPED — never emitted in the clear — and a
///    signed `export.forbidden_class_refused` row is emitted when
///    `audit_conn` is `Some` (the sqlite path holds the audit handle; the
///    postgres SAL path passes `None` and WARN-only skips the audit row — the
///    DROP itself always holds). This runs on the UN-redacted row and is
///    INDEPENDENT of the secret-screen mode, so the fail-closed drop cannot be
///    softened into a mere mask by the secret screen having already redacted a
///    PEM block out of `content` (which would otherwise flip a `DROP + audit`
///    into a silent `keep-redacted`, weakening the pre-existing HTTP gate).
/// 2. **Secret redaction** ([`crate::secret_screen::redact_memory_for_storage`]),
///    on the SURVIVORS only: masks credential VALUES (AWS `AKIA…` / GitHub
///    `ghp_` / OpenAI `sk-` / xAI `xai-` keys, `Bearer` tokens, JWTs) in
///    EVERY cleartext-indexed field — `content`, `title`, `tags`, and
///    non-carve-out `metadata` string leaves — so a credential stashed in a
///    metadata field or the title is masked too, not just one in `content`
///    (#1844). No-op unless screening was seeded non-`off`.
#[must_use]
pub fn screen_memories_for_export(
    memories: Vec<crate::models::Memory>,
    audit_conn: Option<&Connection>,
) -> Vec<crate::models::Memory> {
    memories
        .into_iter()
        .filter_map(|m| {
            // (1) forbidden-class fail-closed drop (+ signed refusal, #1838).
            if let Some(class) = classify_memory(&m) {
                let path = format!("memories/{}.json", m.id);
                let reason = format!(
                    "export refused: memory classified {} ({}) — dropped from export artifact",
                    class.as_str(),
                    class.description()
                );
                if let Some(conn) = audit_conn {
                    if let Err(e) = emit_export_refusal(
                        conn,
                        class,
                        &path,
                        crate::identity::sentinels::DAEMON_PRINCIPAL,
                        &reason,
                    ) {
                        tracing::warn!(
                            "forbidden-export-class signed refusal NOT recorded for {path}: {e}"
                        );
                    }
                }
                tracing::warn!(
                    "export boundary dropped a {} memory — {path} withheld fail-closed",
                    class.as_str()
                );
                return None;
            }
            // (2) secret-screen the survivor: content + title + tags + metadata.
            Some(crate::secret_screen::redact_memory_for_storage(&m).unwrap_or(m))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn class_tokens_are_stable() {
        assert_eq!(
            ForbiddenExportClass::PrivateKeyMaterial.as_str(),
            "private_key_material"
        );
        assert_eq!(
            ForbiddenExportClass::MasterThresholdSecret.as_str(),
            "master_threshold_secret"
        );
        assert_eq!(
            ForbiddenExportClass::SignedPolicyRuleSigningKey.as_str(),
            "signed_policy_rule_signing_key"
        );
        assert_eq!(
            ForbiddenExportClass::BiometricBehavioralEmbedding.as_str(),
            "biometric_behavioral_embedding"
        );
    }

    #[test]
    fn all_set_is_complete_and_severity_ordered() {
        assert_eq!(ALL_FORBIDDEN_EXPORT_CLASSES.len(), 4);
        // Ranks strictly increase in declared order.
        for pair in ALL_FORBIDDEN_EXPORT_CLASSES.windows(2) {
            assert!(pair[0].rank() < pair[1].rank());
        }
    }

    #[test]
    fn clean_record_classifies_none() {
        let v = json!({
            "id": "abc",
            "content": "an ordinary memory about a meeting",
            "metadata": {"agent_id": "ai:alice", "scope": "collective"},
            "signature": "cHVibGljLXNpZ25hdHVyZQ", // public sig field is FINE
        });
        assert_eq!(classify_export_value(&v), None);
    }

    #[test]
    fn pem_private_key_in_content_is_refused() {
        let v = json!({
            "content": "here is my key:\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END",
        });
        assert_eq!(
            classify_export_value(&v),
            Some(ForbiddenExportClass::PrivateKeyMaterial)
        );
    }

    #[test]
    fn secret_key_field_marks_private_key_material() {
        let v = json!({"metadata": {"daemon_secret_key": "AAAA"}});
        assert_eq!(
            classify_export_value(&v),
            Some(ForbiddenExportClass::PrivateKeyMaterial)
        );
    }

    #[test]
    fn threshold_share_field_marks_master_threshold() {
        let v = json!({"metadata": {"threshold_share": "1-abc"}});
        assert_eq!(
            classify_export_value(&v),
            Some(ForbiddenExportClass::MasterThresholdSecret)
        );
    }

    #[test]
    fn rule_signing_key_field_marks_governance_signing_key() {
        let v = json!({"operator_signing_key": "AAAA"});
        assert_eq!(
            classify_export_value(&v),
            Some(ForbiddenExportClass::SignedPolicyRuleSigningKey)
        );
    }

    #[test]
    fn public_rule_signature_is_not_forbidden() {
        // A rule row's public `signature` must NOT be classified forbidden.
        let v = json!({"signature": "AAAA", "attest_level": "operator_signed"});
        assert_eq!(classify_export_value(&v), None);
    }

    #[test]
    fn producer_biometric_embedding_tag_is_refused() {
        let v = json!({"metadata": {"embedding_class": "biometric"}});
        assert_eq!(
            classify_export_value(&v),
            Some(ForbiddenExportClass::BiometricBehavioralEmbedding)
        );
        let v2 = json!({"metadata": {"embedding_kind": "Behavioral"}});
        assert_eq!(
            classify_export_value(&v2),
            Some(ForbiddenExportClass::BiometricBehavioralEmbedding)
        );
    }

    #[test]
    fn non_biometric_embedding_class_is_clean() {
        let v = json!({"metadata": {"embedding_class": "semantic"}});
        assert_eq!(classify_export_value(&v), None);
    }

    #[test]
    fn most_severe_class_wins_when_several_match() {
        // A record carrying BOTH a biometric tag AND a private key must
        // report the private key (most severe).
        let v = json!({
            "metadata": {"embedding_class": "biometric", "secret_key": "AAAA"},
        });
        assert_eq!(
            classify_export_value(&v),
            Some(ForbiddenExportClass::PrivateKeyMaterial)
        );
    }

    #[test]
    fn nested_arrays_are_scanned() {
        let v = json!({"items": [{"x": 1}, {"master_secret": "s"}]});
        assert_eq!(
            classify_export_value(&v),
            Some(ForbiddenExportClass::MasterThresholdSecret)
        );
    }

    #[test]
    fn screen_audited_emits_refusal_and_returns_class() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).expect("open");
        let v = json!({"content": "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END"});
        let class = screen_export_value_audited(&conn, "memories/x.json", "daemon", &v);
        assert_eq!(class, Some(ForbiddenExportClass::PrivateKeyMaterial));

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                rusqlite::params![
                    crate::signed_events::event_types::EXPORT_FORBIDDEN_CLASS_REFUSED
                ],
                |r| r.get(0),
            )
            .expect("count refusal rows");
        assert_eq!(count, 1, "exactly one signed refusal row emitted");
    }

    #[test]
    fn screen_audited_clean_record_emits_nothing() {
        let conn = crate::storage::open(std::path::Path::new(":memory:")).expect("open");
        let v = json!({"content": "ordinary memory"});
        assert_eq!(
            screen_export_value_audited(&conn, "memories/y.json", "daemon", &v),
            None
        );
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
                rusqlite::params![
                    crate::signed_events::event_types::EXPORT_FORBIDDEN_CLASS_REFUSED
                ],
                |r| r.get(0),
            )
            .expect("count refusal rows");
        assert_eq!(count, 0, "clean record emits no refusal row");
    }
}
