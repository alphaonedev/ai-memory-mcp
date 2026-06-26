// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — routine [`Routine`] + [`RoutineRun`] models.
//! Back the v62 `routines` / `routine_runs` tables (parameterised
//! action+edge templates that can be frozen into an immutable,
//! regulatory-hold form, and their per-argument-binding materialisations).
//! The SAL `routine_*` methods + `memory_routine_*` MCP tools + the
//! freeze-attestation signing / verification logic operate over these
//! types in subsequent units; this model is storage-only.

use serde::{Deserialize, Serialize};

/// Lifecycle state of a [`Routine`] (the `routines.state` column).
///
/// The canonical wire/DB spellings are `draft | frozen`. A `frozen`
/// routine is immutable (regulatory hold). The set is enforced by the SAL
/// layer (not a SQL CHECK, so a future state needs no migration). Defaults
/// to [`RoutineState::Draft`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoutineState {
    /// Editable working copy (the default).
    #[default]
    Draft,
    /// Frozen — immutable, regulatory hold.
    Frozen,
}

impl RoutineState {
    /// Canonical wire/DB spelling.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Frozen => "frozen",
        }
    }

    /// Parse a DB/wire spelling. `None` on an unknown value.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "draft" => Some(Self::Draft),
            "frozen" => Some(Self::Frozen),
            _ => None,
        }
    }
}

/// Lifecycle state of a [`RoutineRun`] (the `routine_runs.state` column).
///
/// The canonical wire/DB spellings are
/// `pending | running | completed | failed`. The set is enforced by the
/// SAL layer (not a SQL CHECK). Defaults to [`RoutineRunState::Pending`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoutineRunState {
    /// Materialised but not yet started (the default).
    #[default]
    Pending,
    /// Currently executing.
    Running,
    /// Finished successfully.
    Completed,
    /// Finished with an error.
    Failed,
}

impl RoutineRunState {
    /// Canonical wire/DB spelling.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// Parse a DB/wire spelling. `None` on an unknown value.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// A parameterised action+edge template — one row in the Pillar-1
/// `routines` table. Mirrors the v62 `routines` table 1:1.
///
/// `signature` / `signer_pubkey` carry the future freeze-attestation
/// Ed25519 material and are empty until the routine is frozen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Routine {
    pub id: String,
    pub namespace: String,
    pub name: String,
    /// JSON action + edge declarations carrying `{{parameter}}` placeholders.
    pub template: serde_json::Value,
    /// JSON array of declared parameter names.
    pub parameters: serde_json::Value,
    pub state: RoutineState,
    pub created_by: String,
    /// Epoch seconds.
    pub created_at: i64,
    pub frozen_at: Option<i64>,
    /// Ed25519 freeze-attestation signature.
    pub signature: Vec<u8>,
    /// Freezer's Ed25519 public key.
    pub signer_pubkey: Vec<u8>,
    pub metadata: serde_json::Value,
}

/// One materialisation of a [`Routine`] under a concrete argument binding
/// — one row in the Pillar-1 `routine_runs` table. Mirrors the v62
/// `routine_runs` table 1:1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutineRun {
    pub id: String,
    pub routine_id: String,
    pub namespace: String,
    /// JSON `{{parameter}} -> value` bindings for this run.
    pub arguments: serde_json::Value,
    pub state: RoutineRunState,
    /// JSON array of action ids this run materialised.
    pub created_action_ids: serde_json::Value,
    /// Epoch seconds.
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub error: Option<String>,
    pub metadata: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routine_state_roundtrips_str() {
        for s in [RoutineState::Draft, RoutineState::Frozen] {
            assert_eq!(RoutineState::from_str(s.as_str()), Some(s));
        }
    }

    #[test]
    fn routine_state_from_str_unknown_is_none() {
        assert_eq!(RoutineState::from_str("bogus"), None);
        assert_eq!(RoutineState::from_str(""), None);
        assert_eq!(RoutineState::from_str("Draft"), None); // case-sensitive
    }

    #[test]
    fn routine_state_default_is_draft() {
        assert_eq!(RoutineState::default(), RoutineState::Draft);
    }

    #[test]
    fn routine_run_state_roundtrips_str() {
        for s in [
            RoutineRunState::Pending,
            RoutineRunState::Running,
            RoutineRunState::Completed,
            RoutineRunState::Failed,
        ] {
            assert_eq!(RoutineRunState::from_str(s.as_str()), Some(s));
        }
    }

    #[test]
    fn routine_run_state_from_str_unknown_is_none() {
        assert_eq!(RoutineRunState::from_str("bogus"), None);
        assert_eq!(RoutineRunState::from_str(""), None);
        assert_eq!(RoutineRunState::from_str("Pending"), None); // case-sensitive
    }

    #[test]
    fn routine_run_state_default_is_pending() {
        assert_eq!(RoutineRunState::default(), RoutineRunState::Pending);
    }
}
