// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar 1 (#1709) — coordination [`Action`] model. Backs the v59
//! `actions` table (state machine) + its `action_edges` DAG and `leases`
//! resilience layer. The SAL `action_*` methods + `memory_action_*` MCP
//! tools operate over these types.

use serde::{Deserialize, Serialize};

/// Lifecycle state of a coordination [`Action`].
///
/// The legal transition graph is
/// `pending → claimed → in_progress → done | failed | abandoned`, plus a
/// claim-release edge (`claimed → pending`) and early-abandon edges. Terminal
/// states (`done`/`failed`/`abandoned`) do not transition out. Enforced by
/// [`ActionState::can_transition_to`] at the SAL layer (not a SQL CHECK, so a
/// future state needs no migration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    /// Created, unclaimed.
    #[default]
    Pending,
    /// A holder has claimed it (lease acquired) but work has not begun.
    Claimed,
    /// Work in progress under an active lease.
    InProgress,
    /// Completed successfully (terminal).
    Done,
    /// Completed unsuccessfully (terminal).
    Failed,
    /// Withdrawn before completion (terminal).
    Abandoned,
}

impl ActionState {
    /// Canonical wire/DB spelling.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::InProgress => "in_progress",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Abandoned => "abandoned",
        }
    }

    /// Parse a DB/wire spelling. `None` on an unknown value.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "claimed" => Some(Self::Claimed),
            "in_progress" => Some(Self::InProgress),
            "done" => Some(Self::Done),
            "failed" => Some(Self::Failed),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }

    /// Whether `self → to` is a legal coordination transition.
    #[must_use]
    pub fn can_transition_to(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Pending, Self::Claimed)
                | (Self::Pending, Self::Abandoned)
                | (Self::Claimed, Self::InProgress)
                | (Self::Claimed, Self::Pending)
                | (Self::Claimed, Self::Abandoned)
                | (Self::InProgress, Self::Done)
                | (Self::InProgress, Self::Failed)
                | (Self::InProgress, Self::Abandoned)
        )
    }

    /// Terminal states accept no outbound transition.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Abandoned)
    }
}

/// A coordination action — one node in the Pillar-1 action DAG. Mirrors the
/// v59 `actions` table 1:1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub namespace: String,
    /// Operation kind (caller-defined; the substrate is agnostic to it).
    pub kind: String,
    pub state: ActionState,
    pub title: String,
    /// Caller-supplied JSON payload.
    pub payload: serde_json::Value,
    pub priority: i64,
    /// Creator identity (best-effort NHI marker).
    pub agent_id: Option<String>,
    /// Lease holder while `claimed`/`in_progress`.
    pub claimed_by: Option<String>,
    /// Per-action causal clock for federation merge.
    pub vector_clock: serde_json::Value,
    pub metadata: serde_json::Value,
    /// Epoch seconds.
    pub created_at: i64,
    pub updated_at: i64,
}

/// Typed dependency-DAG edge kind between two coordination actions
/// (the `action_edges.edge_type` column).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    /// `from` requires `to` to complete first.
    Requires,
    /// `from` unlocks `to` on completion.
    Unlocks,
    /// `from` blocks `to` while active.
    Blocks,
    /// `to` is gated by an external condition on `from`.
    GatedBy,
    /// `from` and `to` are siblings (no ordering).
    Sibling,
}

impl EdgeType {
    /// Canonical wire/DB spelling.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requires => "requires",
            Self::Unlocks => "unlocks",
            Self::Blocks => "blocks",
            Self::GatedBy => "gated_by",
            Self::Sibling => "sibling",
        }
    }

    /// Parse a DB/wire spelling. `None` on an unknown value.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "requires" => Some(Self::Requires),
            "unlocks" => Some(Self::Unlocks),
            "blocks" => Some(Self::Blocks),
            "gated_by" => Some(Self::GatedBy),
            "sibling" => Some(Self::Sibling),
            _ => None,
        }
    }
}

/// A typed edge in the action dependency DAG. Mirrors the v59
/// `action_edges` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionEdge {
    pub from_action: String,
    pub to_action: String,
    pub edge_type: EdgeType,
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_state_roundtrips_str() {
        for s in [
            ActionState::Pending,
            ActionState::Claimed,
            ActionState::InProgress,
            ActionState::Done,
            ActionState::Failed,
            ActionState::Abandoned,
        ] {
            assert_eq!(ActionState::from_str(s.as_str()), Some(s));
        }
        assert_eq!(ActionState::from_str("bogus"), None);
    }

    #[test]
    fn transition_graph_is_enforced() {
        use ActionState::*;
        // Legal edges.
        assert!(Pending.can_transition_to(Claimed));
        assert!(Claimed.can_transition_to(InProgress));
        assert!(Claimed.can_transition_to(Pending)); // release claim
        assert!(InProgress.can_transition_to(Done));
        assert!(InProgress.can_transition_to(Failed));
        // Illegal edges.
        assert!(!Pending.can_transition_to(Done)); // can't skip claim/in_progress
        assert!(!Pending.can_transition_to(InProgress));
        assert!(!Done.can_transition_to(InProgress)); // terminal
        assert!(!Failed.can_transition_to(Pending));
        // Terminal classification.
        assert!(Done.is_terminal() && Failed.is_terminal() && Abandoned.is_terminal());
        assert!(!Pending.is_terminal() && !Claimed.is_terminal() && !InProgress.is_terminal());
    }

    #[test]
    fn edge_type_roundtrips_str() {
        for e in [
            EdgeType::Requires,
            EdgeType::Unlocks,
            EdgeType::Blocks,
            EdgeType::GatedBy,
            EdgeType::Sibling,
        ] {
            assert_eq!(EdgeType::from_str(e.as_str()), Some(e));
        }
        assert_eq!(EdgeType::from_str("gated_by"), Some(EdgeType::GatedBy));
        assert_eq!(EdgeType::from_str("bogus"), None);
    }
}
