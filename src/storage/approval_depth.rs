// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 L1-8 / #4357 — the `require_approval_above_depth` threshold
//! resolver and its shared per-level decision. Split out of `storage/mod.rs`
//! (QUAL-10); re-exported there so every existing path
//! (`db::resolve_require_approval_above_depth`, `storage::ApprovalDepthWalk`,
//! ...) is unchanged.

use anyhow::Context as _;

use super::{
    CTX_READ_NAMESPACE_STANDARD, Connection, Result, StandardMetadata,
    build_namespace_governance_chain, get, governance_read, try_get_namespace_standard,
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
/// Leaf-first, per level (GOD final ruling; #2542 leaf-first-wins): an explicit
/// integer decides; a missing standard, an absent `governance` blob or an
/// explicit `null` key keeps walking; a well-formed policy that OMITS the key
/// means no gate and the walk stops. A corrupt level keeps walking and, if
/// nothing explicit follows, resolves to `Some(0)`.
///
/// Returns `None` when no level states a threshold (no standard anywhere, or a
/// well-formed policy that omits the key ended the walk).
///
/// Returns `Some(threshold)` when a level's key is an unsigned integer.
/// Callers in `memory_reflect` compare `proposed_depth > threshold` and
/// queue a `pending_actions` row when the condition is true.
///
/// # Errors
///
/// #4043 — any read fault on the governance chain walk (a fail-closed decrypt
/// included): the reflect is refused, never "no approval required".
pub fn resolve_require_approval_above_depth(
    conn: &Connection,
    namespace: &str,
) -> Result<Option<u32>> {
    // #2542 — governance/approver LAYERING follows only explicitly-declared
    // parents; a `-`-inferred ancestor must not inject an approval threshold.
    let chain = build_namespace_governance_chain(conn, namespace)?;
    let mut walk = ApprovalDepthWalk::default();
    for level in chain.into_iter().rev() {
        // #4357 — classify the level, then let the ONE shared walk act on the
        // state. #4043 — a read fault is an `Err` (refuse), never a skipped
        // level; only an unbound/vanished standard is Missing. #4285 — the RAW
        // metadata column is classified (the row mapper would default an
        // unparseable cell to `{}`): a corrupt or non-object level is SEVERED
        // (continue to the ancestor, no raw key); the walk accumulator then
        // fails closed to Threshold(0) if nothing explicit is found.
        let state = match try_get_namespace_standard(conn, &level)? {
            Some(standard_id) => {
                match get(conn, &standard_id).context(CTX_READ_NAMESPACE_STANDARD)? {
                    Some(_) => {
                        governance_read::classify_bound_standard(conn, &level, &standard_id)?
                            .map_or(ApprovalDepthLevelState::Missing, |c| {
                                approval_depth_level_state(&c)
                            })
                    }
                    None => ApprovalDepthLevelState::Missing,
                }
            }
            None => ApprovalDepthLevelState::Missing,
        };
        if let Some(n) = walk.step(state) {
            return Ok(Some(n));
        }
        if walk.is_done() {
            break;
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
    /// A well-formed policy that OMITS the key: no gate at this level, and the
    /// walk STOPS (leaf-first-wins, #2542; GOD final ruling). The result is
    /// then [`ApprovalDepthWalk::finish`]: `None`, or `Some(0)` if a `Corrupt`
    /// level was already passed.
    OmitsField,
    /// The key is present with an explicit `null`: no decision at this level,
    /// keep walking (the explicit opt-in to inherit).
    NullKey,
    /// The level states a threshold explicitly. It decides and ends the walk.
    /// An out-of-range or non-integer value is already saturated to 0 (fail
    /// closed, #4398).
    Explicit(u32),
    /// The level's governance blob is present but malformed (non-object, an
    /// unparseable policy). Severed: keep walking (the Owner floor applies
    /// via the policy walk); if nothing explicit follows, the walk resolves
    /// to `Some(0)` (gate on).
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
    /// A well-formed policy that omits the key: no gate here and the walk
    /// STOPS; the result is [`ApprovalDepthWalk::finish`].
    Stop,
}

/// #4357 — the shared walk accumulator both backends drive, so the
/// "corrupt seen, nothing explicit" rule lives in ONE place. Feed it each
/// level's [`ApprovalDepthLevelState`] leaf-first via [`Self::step`]; call
/// [`Self::finish`] when the chain is exhausted.
///
/// Rule (GOD final ruling): an explicit value decides; an explicit `null` or a
/// missing standard keeps walking; a well-formed policy that omits the key
/// STOPS the walk (leaf-first-wins); a `Corrupt` level keeps walking, and a
/// chain that passed one and ends without an explicit value resolves to
/// `Some(0)` (approval required) rather than "no gate". After a stop the walk
/// ignores every further level, so a backend that cannot break out of its own
/// loop (postgres) still gets the same result.
#[derive(Debug, Default)]
pub struct ApprovalDepthWalk {
    saw_corrupt: bool,
    stopped: bool,
}

impl ApprovalDepthWalk {
    /// Consume one level; `Some(n)` ends the walk with threshold `n`.
    pub fn step(&mut self, state: ApprovalDepthLevelState) -> Option<u32> {
        if self.stopped {
            return None;
        }
        if state == ApprovalDepthLevelState::Corrupt {
            self.saw_corrupt = true;
        }
        match approval_depth_level_decision(state) {
            ApprovalDepthLevel::Threshold(n) => Some(n),
            ApprovalDepthLevel::Continue => None,
            ApprovalDepthLevel::Stop => {
                self.stopped = true;
                None
            }
        }
    }

    /// True once a well-formed policy that omits the key ended the walk.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.stopped
    }

    /// The result when the chain ended without an explicit value.
    #[must_use]
    pub fn finish(self) -> Option<u32> {
        self.saw_corrupt.then_some(0)
    }
}

/// #4357 / #4285 — classify one level's standard from the shared #4285
/// classifier ([`StandardMetadata`]). A corrupt or non-object level is
/// `Corrupt` (SEVERED: keep walking, Owner floor via the policy walk) and NEVER
/// contributes a raw knob value.
#[must_use]
pub fn approval_depth_level_state(class: &StandardMetadata) -> ApprovalDepthLevelState {
    match class {
        StandardMetadata::Corrupt(_) => ApprovalDepthLevelState::Corrupt,
        StandardMetadata::NoGovernance => ApprovalDepthLevelState::Missing,
        StandardMetadata::Policy(_, raw) => match raw.get(REQUIRE_APPROVAL_ABOVE_DEPTH_KEY) {
            None => ApprovalDepthLevelState::OmitsField,
            Some(serde_json::Value::Null) => ApprovalDepthLevelState::NullKey,
            // #4398 (composed #4285 x #4357 rule): an EXPLICIT value DECIDES.
            // One that is not a non-negative integer fitting u32 (a string, a
            // negative, a float, a bool, an array, an overflow) fails CLOSED
            // to threshold 0 at THIS level — EVERY depth triggers approval —
            // rather than being severed so a permissive ancestor decides
            // (CLAUDE.md K3/K9). The overflow arm is the pre-existing QUAL-3
            // (FX-5) posture, pinned by
            // `tests/governance_metadata_no_silent_truncation.rs`; the
            // non-integer arm used to classify `Corrupt` (keep walking).
            // `memory_namespace_set_standard` refuses these shapes at write
            // time (`validate::validate_governance_depth_knobs`); this is the
            // read-side floor for rows written before that or out of band.
            Some(v) => ApprovalDepthLevelState::Explicit(
                v.as_u64().and_then(|n| u32::try_from(n).ok()).unwrap_or(0),
            ),
        },
    }
}

/// The off-struct governance knob the L1-8 reflect approval gate reads.
pub const REQUIRE_APPROVAL_ABOVE_DEPTH_KEY: &str = "require_approval_above_depth";
/// The off-struct governance knob `memory_skill_promote_from_reflection` reads.
pub const SKILL_PROMOTION_MIN_DEPTH_KEY: &str = "skill_promotion_min_depth";

/// #4357 — the shared per-level decision for
/// [`resolve_require_approval_above_depth`] and its postgres twin.
#[must_use]
pub fn approval_depth_level_decision(state: ApprovalDepthLevelState) -> ApprovalDepthLevel {
    match state {
        ApprovalDepthLevelState::Explicit(n) => ApprovalDepthLevel::Threshold(n),
        ApprovalDepthLevelState::OmitsField => ApprovalDepthLevel::Stop,
        ApprovalDepthLevelState::Missing
        | ApprovalDepthLevelState::NullKey
        | ApprovalDepthLevelState::Corrupt => ApprovalDepthLevel::Continue,
    }
}
