// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 L1-8 / #4357 — the `require_approval_above_depth` threshold
//! resolver and its shared per-level decision. Split out of `storage/mod.rs`
//! (QUAL-10); re-exported there so every existing path
//! (`db::resolve_require_approval_above_depth`, `storage::ApprovalDepthWalk`,
//! ...) is unchanged.

use super::{
    Connection, GovernancePolicy, Result, build_namespace_governance_chain, get,
    get_namespace_standard,
};

/// v0.7.0 L1-8 — read `governance.require_approval_above_depth` from the
/// namespace's most-specific governance metadata blob, leaf-first.
///
/// This is intentionally a free function (not a field on
/// [`GovernancePolicy`]) to avoid introducing a new required struct field
/// that would need updating at every `GovernancePolicy { … }` literal
/// in the codebase. The existing `GovernancePolicy` struct represents
/// the resolved enforcement policy; this field is a pre-write interception
/// threshold that lives beside it, not inside it.
///
/// Returns `None` when:
/// - no namespace standard is configured at any level of the chain, OR
/// - the standard's `metadata.governance` blob is absent or null, OR
/// - the blob does not contain a `require_approval_above_depth` key, OR
/// - the key is present but `null`.
///
/// Returns `Some(threshold)` when the key is a non-null unsigned integer.
/// Callers in `memory_reflect` compare `proposed_depth > threshold` and
/// queue a `pending_actions` row when the condition is true.
///
/// # Errors
///
/// Reserved for a governance-chain read fault (#4043 / #4285 populate it);
/// today every level that cannot be read classifies as
/// [`ApprovalDepthLevelState::Missing`] and the walk continues.
pub fn resolve_require_approval_above_depth(
    conn: &Connection,
    namespace: &str,
) -> Result<Option<u32>> {
    // #2542 — governance/approver LAYERING follows only explicitly-declared
    // parents; a `-`-inferred ancestor must not inject an approval threshold.
    let chain = build_namespace_governance_chain(conn, namespace);
    let mut walk = ApprovalDepthWalk::default();
    for level in chain.into_iter().rev() {
        // #4357 — classify the level, then let the ONE shared decision fn act
        // on the state. An unresolvable standard is `Missing` today; #4285
        // adds the `Severed` handling here without touching the walk shape.
        let state = match get_namespace_standard(conn, &level) {
            Ok(Some(standard_id)) => match get(conn, &standard_id) {
                Ok(Some(mem)) => approval_depth_level_state(&mem.metadata),
                _ => ApprovalDepthLevelState::Missing,
            },
            _ => ApprovalDepthLevelState::Missing,
        };
        if let Some(n) = walk.step(state) {
            return Ok(Some(n));
        }
    }
    Ok(walk.finish())
}

/// #4357 — what ONE namespace-chain level's standard says about the L1-8
/// `require_approval_above_depth` threshold. The walk itself is
/// backend-specific (each store reads its own chain and standard memory); the
/// classification and the decision below are shared pure functions so the
/// SQLite and PostgreSQL resolvers cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDepthLevelState {
    /// No standard resolves at this level (never bound, or its memory is gone).
    Missing,
    /// A well-formed standard that does NOT state the field (absent or null):
    /// not a policy statement about this threshold, so an ancestor's explicit
    /// value still governs (docs/governance.md: a child inherits until it
    /// opts out).
    OmitsField,
    /// The level states a threshold explicitly. It decides and ends the walk.
    /// An out-of-range value is already saturated to 0 (fail closed).
    Explicit(u32),
    /// The level's governance blob is present but malformed (non-object, a
    /// non-integer threshold, an unparseable policy). #4285 owns the final
    /// rule (Severed: continue to the ancestor, Owner floor applies); until
    /// then it is never LESS strict than the pre-#4357 walk: it continues to
    /// the ancestor instead of ending the walk with no gate.
    Corrupt,
}

/// #4357 — the walk's action for a level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDepthLevel {
    /// This level decides: the threshold governs and the walk ends.
    Threshold(u32),
    /// Nothing decided here: keep walking toward the root. Falling off the end
    /// of the chain is the documented default (no gate).
    Continue,
}

/// #4357 — the shared walk accumulator both backends drive, so the
/// "corrupt seen, nothing explicit" rule lives in ONE place. Feed it each
/// level's [`ApprovalDepthLevelState`] leaf-first via [`Self::step`]; call
/// [`Self::finish`] when the chain is exhausted.
///
/// Fail closed (conductor ruling): a chain that passed at least one
/// `Corrupt` level and found NO explicit value anywhere resolves to
/// `Some(0)` (approval required) rather than "no gate". A corrupt level still
/// continues to the ancestor and an explicit ancestor value still decides;
/// #4285 layers the Owner floor on top.
#[derive(Debug, Default)]
pub struct ApprovalDepthWalk {
    saw_corrupt: bool,
}

impl ApprovalDepthWalk {
    /// Consume one level; `Some(n)` ends the walk with threshold `n`.
    pub fn step(&mut self, state: ApprovalDepthLevelState) -> Option<u32> {
        if state == ApprovalDepthLevelState::Corrupt {
            self.saw_corrupt = true;
        }
        match approval_depth_level_decision(state) {
            ApprovalDepthLevel::Threshold(n) => Some(n),
            ApprovalDepthLevel::Continue => None,
        }
    }

    /// The result when the chain ended without an explicit value.
    #[must_use]
    pub fn finish(self) -> Option<u32> {
        self.saw_corrupt.then_some(0)
    }
}

/// #4357 — classify one level's standard metadata. See
/// [`ApprovalDepthLevelState`].
#[must_use]
pub fn approval_depth_level_state(metadata: &serde_json::Value) -> ApprovalDepthLevelState {
    let gov = match metadata.get(crate::META_KEY_GOVERNANCE) {
        None => return ApprovalDepthLevelState::Missing,
        Some(g) if g.is_null() => return ApprovalDepthLevelState::Missing,
        Some(g) => g,
    };
    // Corruption is decided BEFORE any key is read: a level whose governance
    // blob does not parse as a policy never contributes a raw knob value.
    if matches!(GovernancePolicy::from_metadata(metadata), Some(Err(_))) {
        return ApprovalDepthLevelState::Corrupt;
    }
    let Some(obj) = gov.as_object() else {
        return ApprovalDepthLevelState::Corrupt;
    };
    match obj.get("require_approval_above_depth") {
        None | Some(serde_json::Value::Null) => ApprovalDepthLevelState::OmitsField,
        Some(v) => match v.as_u64() {
            // QUAL-3 (FX-5): operator-controlled metadata. Reject the silent
            // `n as u32` truncation that would let `2^32` land as 0 and
            // DISABLE the gate. Fail-CLOSED on overflow: saturate to 0 so
            // EVERY depth triggers approval (CLAUDE.md K3/K9). Pinned by
            // `tests/governance_metadata_no_silent_truncation.rs`.
            Some(n) => ApprovalDepthLevelState::Explicit(u32::try_from(n).unwrap_or(0)),
            None => ApprovalDepthLevelState::Corrupt,
        },
    }
}

/// #4357 — the shared per-level decision for
/// [`resolve_require_approval_above_depth`] and its postgres twin.
#[must_use]
pub fn approval_depth_level_decision(state: ApprovalDepthLevelState) -> ApprovalDepthLevel {
    match state {
        ApprovalDepthLevelState::Explicit(n) => ApprovalDepthLevel::Threshold(n),
        ApprovalDepthLevelState::Missing
        | ApprovalDepthLevelState::OmitsField
        | ApprovalDepthLevelState::Corrupt => ApprovalDepthLevel::Continue,
    }
}
