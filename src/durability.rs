// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1830 (TRACT-gap G16) — the substrate's DURABILITY-MODEL disclosure anchor.
//!
//! # What this is (and is NOT)
//!
//! TRACT L2 wants an (n,k) erasure-coded, no-primary cold tier so any k-of-n
//! shards reconstruct — the substrate does **not** have one (gap G16, #1830,
//! `docs/spec/TRACT-L1-CLAIM-CONTRACT.md` §9). This module ships **no** erasure
//! coding. It does exactly one humble thing: it pins the durability postures the
//! substrate ACTUALLY provides into an enum + a pure resolver over the REAL
//! durability config, so the contract §9 honesty claim cannot silently drift
//! from the code.
//!
//! The deliberate ABSENCE of an erasure-coded / no-primary variant on
//! [`DurabilityModel`] is the machine-checked record of the gap: the enum is
//! `#[non_exhaustive]` and consumed by wildcard-free exhaustive matches
//! ([`DurabilityModel::label`], [`DurabilityModel::is_multi_node`]), so adding
//! such a variant hard-breaks the build until the new tier is consciously wired
//! AND the §9 ledger is updated. It is a genuine (if low-fan-out) drift-gate,
//! not a self-referential boolean — [`resolve_durability_model`] computes the
//! live posture from actual config inputs.
//!
//! The real (n,k) erasure subsystem is v1.x and is BLOCKED on an operator
//! dependency-authorization decision (a vetted erasure crate vs a hand-rolled
//! finite-field codec — the latter was rejected by the #1830 5-agent vote
//! `4d3ea1c5`). Adding a dependency requires operator sign-off (sole-authority
//! rule), so it cannot be done autonomously.

/// The durability postures the substrate ACTUALLY provides today.
///
/// There is deliberately NO erasure-coded / no-primary cold-tier variant — that
/// gap (TRACT G16, #1830) is UNIMPLEMENTED. Adding a variant here breaks every
/// exhaustive match below until the new tier is consciously wired AND the
/// contract §9 ledger is updated (the drift-gate). `#[non_exhaustive]` so
/// out-of-crate matchers must also account for a future tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DurabilityModel {
    /// Default: a single local SQLite DB (WAL). Survives a process crash, but a
    /// power loss can lose the tail of commits not yet checkpoint-fsync'd
    /// (`synchronous = NORMAL`, the compiled default).
    LocalSingleNode,
    /// A single local SQLite DB with fsync-per-commit power-loss durability
    /// (`AI_MEMORY_DB_SYNCHRONOUS = FULL`/`EXTRA`, or the `asi-hard` posture,
    /// #1961). Still single-node — no replication.
    LocalSingleNodePowerLossSafe,
    /// Opt-in W-of-N quorum federation replication (`crate::replication`
    /// `QuorumPolicy` / `AckTracker`), active only under `--quorum-writes > 0`
    /// with configured peers. This is QUORUM, not full-copy-to-N, and does not
    /// change the local power-loss posture.
    QuorumReplicated,
}

impl DurabilityModel {
    /// A short, stable label. EXHAUSTIVE wildcard-free match — the drift-gate: a
    /// new [`DurabilityModel`] variant (e.g. an erasure-coded cold tier)
    /// hard-breaks the build here until deliberately handled.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::LocalSingleNode => "local-single-node",
            Self::LocalSingleNodePowerLossSafe => "local-single-node-power-loss-safe",
            Self::QuorumReplicated => "quorum-replicated",
        }
    }

    /// `true` iff this model survives the loss of a whole node. Only
    /// [`QuorumReplicated`](Self::QuorumReplicated) does today; an erasure-coded
    /// no-primary cold tier WOULD (G16, unimplemented). EXHAUSTIVE wildcard-free
    /// match — a second drift-gate site.
    #[must_use]
    pub fn is_multi_node(self) -> bool {
        match self {
            Self::QuorumReplicated => true,
            Self::LocalSingleNode | Self::LocalSingleNodePowerLossSafe => false,
        }
    }
}

/// Whether a `synchronous` PRAGMA level fsyncs on every commit (power-loss
/// durable). `FULL` and `EXTRA` do; `NORMAL` (the default) and `OFF` do not.
#[must_use]
fn sync_is_power_loss_safe(sync_level: &str) -> bool {
    sync_level.eq_ignore_ascii_case("FULL") || sync_level.eq_ignore_ascii_case("EXTRA")
}

/// #1830 (G16) — resolve the substrate's live [`DurabilityModel`] from the REAL
/// durability config: the resolved `synchronous` PRAGMA level (pass
/// [`crate::storage::connection::db_synchronous`]), the configured
/// `quorum_writes`, and whether federation peers are configured. Pure and
/// total. A genuine consumer of real config — NOT a self-referential constant.
///
/// Quorum replication (when active) is the dominant multi-node guarantee; absent
/// quorum, the posture is local, upgraded to power-loss-safe only when the
/// `synchronous` level fsyncs every commit.
#[must_use]
pub fn resolve_durability_model(
    sync_level: &str,
    quorum_writes: usize,
    peers_configured: bool,
) -> DurabilityModel {
    if quorum_writes > 0 && peers_configured {
        DurabilityModel::QuorumReplicated
    } else if sync_is_power_loss_safe(sync_level) {
        DurabilityModel::LocalSingleNodePowerLossSafe
    } else {
        DurabilityModel::LocalSingleNode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::connection::DEFAULT_DB_SYNCHRONOUS;

    #[test]
    fn default_config_resolves_local_single_node() {
        // The compiled default posture: NORMAL sync, no quorum, no peers.
        let m = resolve_durability_model(DEFAULT_DB_SYNCHRONOUS, 0, false);
        assert_eq!(m, DurabilityModel::LocalSingleNode);
        assert!(!m.is_multi_node(), "default posture is single-node");
    }

    #[test]
    fn full_sync_upgrades_to_power_loss_safe() {
        assert_eq!(
            resolve_durability_model("FULL", 0, false),
            DurabilityModel::LocalSingleNodePowerLossSafe
        );
        assert_eq!(
            resolve_durability_model("extra", 0, false),
            DurabilityModel::LocalSingleNodePowerLossSafe,
            "case-insensitive; EXTRA also fsyncs per commit"
        );
    }

    #[test]
    fn quorum_requires_both_writes_and_peers() {
        // quorum_writes>0 alone is inert without configured peers.
        assert_eq!(
            resolve_durability_model("NORMAL", 3, false),
            DurabilityModel::LocalSingleNode,
            "quorum_writes without peers does not replicate"
        );
        assert_eq!(
            resolve_durability_model("NORMAL", 3, true),
            DurabilityModel::QuorumReplicated
        );
    }

    /// #1830 / G16 honesty pin: multi-node durability is QUORUM-only today.
    /// There is NO erasure-coded no-primary cold-tier model — the gap is real.
    /// If a future edit adds an erasure `DurabilityModel` variant, the exhaustive
    /// matches in `label`/`is_multi_node` break the build and this test must be
    /// revisited alongside the contract §9 ledger.
    #[test]
    fn g16_only_quorum_is_multi_node_no_erasure_tier() {
        let multi: Vec<DurabilityModel> = [
            DurabilityModel::LocalSingleNode,
            DurabilityModel::LocalSingleNodePowerLossSafe,
            DurabilityModel::QuorumReplicated,
        ]
        .into_iter()
        .filter(|m| m.is_multi_node())
        .collect();
        assert_eq!(
            multi,
            vec![DurabilityModel::QuorumReplicated],
            "the ONLY multi-node durability today is quorum replication; \
             an erasure-coded no-primary cold tier (G16) is UNIMPLEMENTED"
        );
    }

    #[test]
    fn labels_are_stable_and_distinct() {
        for m in [
            DurabilityModel::LocalSingleNode,
            DurabilityModel::LocalSingleNodePowerLossSafe,
            DurabilityModel::QuorumReplicated,
        ] {
            assert!(!m.label().is_empty());
        }
        assert_ne!(
            DurabilityModel::LocalSingleNode.label(),
            DurabilityModel::QuorumReplicated.label()
        );
    }
}
