// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — attested-checkpoint [`Checkpoint`] model.
//! Backs the v61 `checkpoints` table (conditional coordination gates
//! whose resolution is Ed25519-attested). The SAL `checkpoint_*` methods
//! + `memory_checkpoint_*` MCP tools + the signing / verification logic
//! operate over these types in subsequent units; this model is
//! storage-only.

use serde::{Deserialize, Serialize};

/// Condition type of a [`Checkpoint`] (the `checkpoints.condition_type`
/// column).
///
/// The canonical wire/DB spellings are
/// `approval | external_signal | condition_predicate | deadline |
/// audit_head_witness`. The set is enforced by the SAL layer (not a SQL
/// CHECK, so a future type needs no migration). Defaults to
/// [`ConditionType::Approval`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConditionType {
    /// Resolved by an explicit approval (the default).
    #[default]
    Approval,
    /// Resolved by an external signal arriving (e.g. a `Signal` row).
    ExternalSignal,
    /// Resolved when a predicate over substrate state evaluates true.
    ConditionPredicate,
    /// Resolved (as expired) when a deadline passes.
    Deadline,
    /// v0.9.0 G5b (#1822) — an INDEPENDENT audit-head witness anchor.
    /// Not a coordination gate: the substrate itself emits (and
    /// immediately resolves) one of these, signed by the DISTINCT
    /// audit-witness key, on every `WATERMARK_INTERVAL` boundary of the
    /// `signed_events` append chokepoint. Its `resolution` carries the
    /// dual-chain head (both `signed_events` and `memory_revisions`
    /// `MAX(sequence)` + head hash) so `verify_audit_trail` can pin the
    /// witness pubkey (K1) and detect tail-truncation of EITHER chain
    /// against an anchor a `DELETE FROM signed_events` does not touch.
    AuditHeadWitness,
}

impl ConditionType {
    /// Canonical wire/DB spelling.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::ExternalSignal => "external_signal",
            Self::ConditionPredicate => "condition_predicate",
            Self::Deadline => "deadline",
            Self::AuditHeadWitness => "audit_head_witness",
        }
    }

    /// Parse a DB/wire spelling. `None` on an unknown value.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "approval" => Some(Self::Approval),
            "external_signal" => Some(Self::ExternalSignal),
            "condition_predicate" => Some(Self::ConditionPredicate),
            "deadline" => Some(Self::Deadline),
            "audit_head_witness" => Some(Self::AuditHeadWitness),
            _ => None,
        }
    }
}

/// Lifecycle state of a [`Checkpoint`] (the `checkpoints.state` column).
///
/// The canonical wire/DB spellings are
/// `pending | resolved | rejected | expired`. The set is enforced by the
/// SAL layer (not a SQL CHECK). Defaults to [`CheckpointState::Pending`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointState {
    /// Awaiting resolution (the default).
    #[default]
    Pending,
    /// Resolved affirmatively.
    Resolved,
    /// Resolved as rejected.
    Rejected,
    /// Expired (its deadline passed before resolution).
    Expired,
}

impl CheckpointState {
    /// Canonical wire/DB spelling.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Resolved => "resolved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    /// Parse a DB/wire spelling. `None` on an unknown value.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "resolved" => Some(Self::Resolved),
            "rejected" => Some(Self::Rejected),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// A conditional coordination gate — one row in the Pillar-1 `checkpoints`
/// table. Mirrors the v61 `checkpoints` table 1:1.
///
/// `signature` / `resolver_pubkey` carry the Ed25519 attestation over the
/// canonical resolution and are empty until the checkpoint resolves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub id: String,
    pub namespace: String,
    pub title: String,
    pub condition_type: ConditionType,
    /// JSON condition spec.
    pub condition: serde_json::Value,
    pub state: CheckpointState,
    pub created_by: String,
    pub resolved_by: Option<String>,
    pub resolution: Option<String>,
    pub resolution_note: Option<String>,
    /// Ed25519 signature over the canonical resolution.
    pub signature: Vec<u8>,
    /// Resolver's Ed25519 public key.
    pub resolver_pubkey: Vec<u8>,
    /// Epoch seconds.
    pub created_at: i64,
    pub deadline_at: Option<i64>,
    pub resolved_at: Option<i64>,
    pub metadata: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condition_type_roundtrips_str() {
        for c in [
            ConditionType::Approval,
            ConditionType::ExternalSignal,
            ConditionType::ConditionPredicate,
            ConditionType::Deadline,
            ConditionType::AuditHeadWitness,
        ] {
            assert_eq!(ConditionType::from_str(c.as_str()), Some(c));
        }
    }

    #[test]
    fn condition_type_from_str_unknown_is_none() {
        assert_eq!(ConditionType::from_str("bogus"), None);
        assert_eq!(ConditionType::from_str(""), None);
        assert_eq!(ConditionType::from_str("Approval"), None); // case-sensitive
    }

    #[test]
    fn condition_type_default_is_approval() {
        assert_eq!(ConditionType::default(), ConditionType::Approval);
    }

    #[test]
    fn checkpoint_state_roundtrips_str() {
        for s in [
            CheckpointState::Pending,
            CheckpointState::Resolved,
            CheckpointState::Rejected,
            CheckpointState::Expired,
        ] {
            assert_eq!(CheckpointState::from_str(s.as_str()), Some(s));
        }
    }

    #[test]
    fn checkpoint_state_from_str_unknown_is_none() {
        assert_eq!(CheckpointState::from_str("bogus"), None);
        assert_eq!(CheckpointState::from_str(""), None);
        assert_eq!(CheckpointState::from_str("Pending"), None); // case-sensitive
    }

    #[test]
    fn checkpoint_state_default_is_pending() {
        assert_eq!(CheckpointState::default(), CheckpointState::Pending);
    }
}
