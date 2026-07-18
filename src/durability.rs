// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1830 (TRACT-gap G16) — the substrate's DURABILITY-MODEL disclosure anchor.
//!
//! # What this is (and is NOT)
//!
//! This module pins the durability postures the substrate ACTUALLY provides
//! into an enum + a pure resolver over the REAL durability config, so the
//! contract §9 honesty claim cannot silently drift from the code. The enum is
//! `#[non_exhaustive]` and consumed by wildcard-free exhaustive matches
//! ([`DurabilityModel::label`], [`DurabilityModel::is_multi_node`]), so adding
//! a variant hard-breaks the build until the new tier is consciously wired
//! AND the §9 ledger is updated. It is a genuine (if low-fan-out) drift-gate,
//! not a self-referential boolean — [`resolve_durability_model`] computes the
//! live posture from actual config inputs.
//!
//! # v1.0.0 #2064 — the erasure cold tier EXISTS now (flipped disclosure)
//!
//! The original #1830 slice shipped this enum with DELIBERATELY no erasure
//! variant (the machine-checked record of gap G16) because the erasure
//! subsystem was BLOCKED on an operator dependency-authorization decision
//! (#2064). That decision LANDED (2026-07-18): the vetted
//! `reed-solomon-simd` crate is authorized, and [`crate::erasure`] ships the
//! opt-in archive cold-tier redundancy layer — any k of n = k + m shards
//! reconstruct an archived row's bytes exactly, with per-shard + whole-
//! payload SHA-256 gates so loss/corruption beyond the parity budget fails
//! LOUD (degrade, never corrupt).
//!
//! HONEST RESIDUAL: shard PLACEMENT is single-node (one local directory
//! tree). [`DurabilityModel::ErasureCodedColdTier`] therefore reports
//! `is_multi_node() == false` — the layer protects the cold tier against
//! partial disk corruption / lost shard files, NOT whole-node loss. The
//! TRACT G16 end-state (no-primary placement across nodes) remains tracked
//! work; this enum's exhaustive matches stay the forcing function for that
//! upgrade too.

/// The durability postures the substrate ACTUALLY provides today.
///
/// `#[non_exhaustive]` so out-of-crate matchers must account for future
/// tiers; in-crate matches stay wildcard-free-exhaustive as the drift-gate.
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
    /// v1.0.0 #2064 — opt-in (k, m) Reed-Solomon erasure-coded redundancy for
    /// the archive cold tier (`AI_MEMORY_ERASURE_COLD_TIER`, [`crate::erasure`]):
    /// any k of k + m shards reconstruct an archived row exactly; loss beyond
    /// the m-shard budget fails loud. Shard placement is SINGLE-NODE (local
    /// directory) at v1.0.0 — this posture hardens the cold tier against
    /// partial disk corruption, not whole-node loss (`is_multi_node() ==
    /// false`; the no-primary multi-node placement is the tracked G16
    /// residual). The local power-loss posture is unchanged by this tier.
    ErasureCodedColdTier,
}

impl DurabilityModel {
    /// A short, stable label. EXHAUSTIVE wildcard-free match — the drift-gate: a
    /// new [`DurabilityModel`] variant hard-breaks the build here until
    /// deliberately handled.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::LocalSingleNode => "local-single-node",
            Self::LocalSingleNodePowerLossSafe => "local-single-node-power-loss-safe",
            Self::QuorumReplicated => "quorum-replicated",
            Self::ErasureCodedColdTier => "erasure-coded-cold-tier",
        }
    }

    /// `true` iff this model survives the loss of a whole node. Only
    /// [`QuorumReplicated`](Self::QuorumReplicated) does today. The #2064
    /// erasure cold tier is HONESTLY `false`: its shard placement is
    /// single-node at v1.0.0 (the no-primary multi-node placement is the
    /// tracked G16 residual). EXHAUSTIVE wildcard-free match — a second
    /// drift-gate site.
    #[must_use]
    pub fn is_multi_node(self) -> bool {
        match self {
            Self::QuorumReplicated => true,
            Self::LocalSingleNode
            | Self::LocalSingleNodePowerLossSafe
            | Self::ErasureCodedColdTier => false,
        }
    }
}

/// Whether a `synchronous` PRAGMA level fsyncs on every commit (power-loss
/// durable). `FULL` and `EXTRA` do; `NORMAL` (the default) and `OFF` do not.
#[must_use]
fn sync_is_power_loss_safe(sync_level: &str) -> bool {
    sync_level.eq_ignore_ascii_case("FULL") || sync_level.eq_ignore_ascii_case("EXTRA")
}

/// #1830 (G16) / #2064 — resolve the substrate's live [`DurabilityModel`]
/// from the REAL durability config: the resolved `synchronous` PRAGMA level
/// (pass [`crate::storage::connection::db_synchronous`]), the configured
/// `quorum_writes`, whether federation peers are configured, and whether the
/// #2064 erasure cold tier is enabled (pass
/// [`crate::erasure::erasure_cold_tier_enabled`]). Pure and total.
///
/// Precedence reports the DOMINANT guarantee: active quorum replication (the
/// only multi-node posture) > the erasure cold tier (cold-tier shard
/// redundancy) > the local power-loss posture. The postures compose at
/// runtime (e.g. `synchronous=FULL` + erasure both apply); the resolver
/// discloses the strongest one.
#[must_use]
pub fn resolve_durability_model(
    sync_level: &str,
    quorum_writes: usize,
    peers_configured: bool,
    erasure_cold_tier: bool,
) -> DurabilityModel {
    if quorum_writes > 0 && peers_configured {
        DurabilityModel::QuorumReplicated
    } else if erasure_cold_tier {
        DurabilityModel::ErasureCodedColdTier
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

    /// Every variant, for exhaustive-property tests. Extending this list is
    /// part of consciously wiring a new tier.
    const ALL: [DurabilityModel; 4] = [
        DurabilityModel::LocalSingleNode,
        DurabilityModel::LocalSingleNodePowerLossSafe,
        DurabilityModel::QuorumReplicated,
        DurabilityModel::ErasureCodedColdTier,
    ];

    #[test]
    fn default_config_resolves_local_single_node() {
        // The compiled default posture: NORMAL sync, no quorum, no peers,
        // erasure cold tier OFF (opt-in).
        let m = resolve_durability_model(DEFAULT_DB_SYNCHRONOUS, 0, false, false);
        assert_eq!(m, DurabilityModel::LocalSingleNode);
        assert!(!m.is_multi_node(), "default posture is single-node");
    }

    #[test]
    fn full_sync_upgrades_to_power_loss_safe() {
        assert_eq!(
            resolve_durability_model("FULL", 0, false, false),
            DurabilityModel::LocalSingleNodePowerLossSafe
        );
        assert_eq!(
            resolve_durability_model("extra", 0, false, false),
            DurabilityModel::LocalSingleNodePowerLossSafe,
            "case-insensitive; EXTRA also fsyncs per commit"
        );
    }

    #[test]
    fn quorum_requires_both_writes_and_peers() {
        // quorum_writes>0 alone is inert without configured peers.
        assert_eq!(
            resolve_durability_model("NORMAL", 3, false, false),
            DurabilityModel::LocalSingleNode,
            "quorum_writes without peers does not replicate"
        );
        assert_eq!(
            resolve_durability_model("NORMAL", 3, true, false),
            DurabilityModel::QuorumReplicated
        );
    }

    #[test]
    fn erasure_cold_tier_resolves_and_quorum_dominates() {
        // #2064 — the enabled erasure cold tier IS a disclosed posture now.
        assert_eq!(
            resolve_durability_model("NORMAL", 0, false, true),
            DurabilityModel::ErasureCodedColdTier
        );
        // Erasure discloses over the local power-loss posture (both apply
        // at runtime; the resolver reports the dominant tier)...
        assert_eq!(
            resolve_durability_model("FULL", 0, false, true),
            DurabilityModel::ErasureCodedColdTier
        );
        // ...but active quorum replication (the only multi-node posture)
        // dominates erasure.
        assert_eq!(
            resolve_durability_model("NORMAL", 2, true, true),
            DurabilityModel::QuorumReplicated
        );
    }

    /// #1830 / G16 honesty pin, POST-#2064 form: the erasure cold tier now
    /// EXISTS (the no-erasure disclosure is flipped), but multi-node
    /// durability is STILL quorum-only — the v1.0.0 erasure tier's shard
    /// placement is single-node, so claiming `is_multi_node` for it would be
    /// an overclaim. The G16 residual (no-primary multi-node placement) must
    /// flip THIS assertion consciously when it lands.
    #[test]
    fn g16_erasure_tier_exists_but_multi_node_is_still_quorum_only() {
        let multi: Vec<DurabilityModel> = ALL.into_iter().filter(|m| m.is_multi_node()).collect();
        assert_eq!(
            multi,
            vec![DurabilityModel::QuorumReplicated],
            "the ONLY multi-node durability today is quorum replication; the \
             #2064 erasure cold tier is single-node shard placement (honest \
             disclosure — the no-primary multi-node placement is the tracked \
             G16 residual)"
        );
        assert_eq!(
            DurabilityModel::ErasureCodedColdTier.label(),
            "erasure-coded-cold-tier"
        );
    }

    #[test]
    fn labels_are_stable_and_distinct() {
        let labels: Vec<&str> = ALL.iter().map(|m| m.label()).collect();
        for l in &labels {
            assert!(!l.is_empty());
        }
        let unique: std::collections::HashSet<&&str> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len(), "labels must be distinct");
    }
}
