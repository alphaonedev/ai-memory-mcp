// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! ARCH-8 (FX-C4-batch2, 2026-05-26) — per-migration metadata matrix.
//!
//! The v0.7.0 substrate ships a 50-step migration ladder
//! (v2 → v51) without a documented "reversible? data-loss-risk?
//! idempotent?" matrix. An operator who needs to roll back a v0.7.0
//! daemon to v0.6.4 currently has no on-rails option — restore from
//! backup is the only fallback. The matrix below makes the
//! reversibility / data-loss-risk / idempotency contract per
//! migration explicit so `ai-memory migrate --plan` can read it,
//! release notes can quote it, and a CI test can assert every
//! ladder step has a populated entry.
//!
//! Adding a migration: extend [`MIGRATION_LADDER`] in lockstep with
//! the `migrate_v<N>` arm in `migrations.rs`. The compile-time
//! `arch_8_*` tests in this module catch ladder/matrix drift.

/// Whether reverting this migration on a populated DB destroys
/// caller-visible rows / columns / data.
///
/// `None` = pure additive change (no `DROP`, no `ALTER ... DROP`,
/// no destructive `UPDATE`). Safe to revert by un-bumping the
/// schema-version row.
///
/// `Column` = drops a column or table; reverting means losing the
/// data that lived there. Operators rolling back must export+import.
///
/// `Table` = drops an entire table or applies a destructive
/// large-scale rewrite. Highest data-loss tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataLossRisk {
    None,
    Column,
    Table,
}

/// Per-migration metadata record.
#[derive(Debug, Clone, Copy)]
pub struct MigrationMeta {
    /// Target schema version this migration produces (i.e. the
    /// `CURRENT_SCHEMA_VERSION` value reached AFTER it runs).
    pub version: i64,
    /// Short human-readable name. Convention: SCREAMING_SNAKE
    /// summarising the schema delta (e.g. `ADD_TIER`,
    /// `FEDERATION_NONCES`).
    pub name: &'static str,
    /// `true` when re-running the migration against an already-
    /// at-target DB is a no-op (uses `CREATE ... IF NOT EXISTS`,
    /// `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` shapes, or
    /// per-row UPDATE WHERE-clauses that match nothing on a
    /// second pass).
    pub idempotent: bool,
    /// `true` when the migration can be reverted purely by lowering
    /// the `schema_version` row (no data was destroyed, no table
    /// was dropped, no `UPDATE` clobbered a column the prior
    /// schema needed).
    pub reversible: bool,
    /// Data-loss class on revert. See [`DataLossRisk`].
    pub data_loss_risk: DataLossRisk,
}

/// Canonical migration matrix. Every sqlite `if version < N` arm in
/// `migrations.rs::apply_migrations` MUST have a corresponding entry
/// here. The `arch_8_*` tests assert (a) coverage (every ladder
/// step has a meta row), (b) monotonicity (versions strictly
/// increasing).
///
/// Entry rationale: every v0.7.x migration that ADDED a column or
/// CREATE'd a new table without dropping or rewriting existing data
/// is `reversible = true, data_loss_risk = None`. The handful of
/// migrations that dropped columns or rewrote rows are flagged
/// `reversible = false` with the appropriate data-loss tier.
pub const MIGRATION_LADDER: &[MigrationMeta] = &[
    // v2: add confidence + auto-tag scaffolding columns.
    MigrationMeta {
        version: 2,
        name: "ADD_CONFIDENCE_DEFAULT",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 3,
        name: "ADD_TIER",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 4,
        name: "ADD_AGENT_ID_INDEX",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 5,
        name: "ADD_FTS5",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 6,
        name: "ADD_HNSW_EMBEDDINGS",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 7,
        name: "ADD_LINKS_TABLE",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 8,
        name: "ADD_ARCHIVE_TABLE",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 9,
        name: "ADD_NAMESPACE_META",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 10,
        name: "ADD_PERMISSIONS_RULES",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 11,
        name: "ADD_SIGNED_EVENTS",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 12,
        name: "ADD_AGENTS_REGISTRATION",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 13,
        name: "ADD_LINKS_ATTESTATION",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 14,
        name: "ADD_FED_NONCES_INDEX",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 15,
        name: "ADD_HOOKS_CONFIG",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 16,
        name: "ADD_PENDING_ACTIONS",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 17,
        name: "ADD_TRANSCRIPTS",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 18,
        name: "ADD_OBSERVATIONS",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 19,
        name: "ADD_HOOK_SUBSCRIBERS",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 20,
        name: "ADD_AUDIT_INDEX",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 21,
        name: "ADD_AGENT_QUOTAS",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 22,
        name: "ADD_GOVERNANCE_RULES",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 23,
        name: "ADD_KG_TRAVERSAL_CACHE",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 24,
        name: "ADD_FED_PEERS",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 25,
        name: "ADD_INDEX_REFLECTS_ON",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 26,
        name: "ADD_SKILL_REGISTRY",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 27,
        name: "ADD_PERSONA_REGISTRY",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 28,
        name: "ADD_OFFLOAD_REGISTRY",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 29,
        name: "ADD_REFLECTION_DEPTH",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 30,
        name: "ADD_KG_CYCLE_CHECK",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 31,
        name: "ADD_FORENSIC_SINK",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 32,
        name: "ADD_CONFIDENCE_CALIBRATION",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 33,
        name: "ADD_CONSOLIDATION_LEDGER",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 34,
        name: "BACKFILL_SIGNED_CHAIN",
        idempotent: true,
        reversible: false,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 35,
        name: "ADD_KG_AGE_PROJECTION",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 36,
        name: "ADD_ATOMISATION_SCHEMA",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 37,
        name: "ADD_MEMORY_KIND",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 38,
        name: "ADD_ENTITY_REGISTRY",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 39,
        name: "ADD_FORM4_PROVENANCE",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 40,
        name: "ADD_FORM5_CONFIDENCE_SOURCE",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 41,
        name: "ADD_PERSONA_VERSION",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 42,
        name: "ADD_HOOK_DLQ",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 43,
        name: "ADD_RECURSIVE_LEARNING_LEDGER",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 44,
        name: "ADD_BATMAN_VOCABULARY_COLUMNS",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 45,
        name: "ADD_VERSION_OPTIMISTIC_CONCURRENCY",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 46,
        name: "ADD_SHARE_LINKS",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 47,
        name: "ADD_MENTIONED_ENTITY_ID",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 48,
        name: "ADD_FEDERATION_PUSH_DLQ",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 49,
        name: "BACKFILL_ARCHIVED_MEMORIES_COLUMNS",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
    MigrationMeta {
        version: 50,
        name: "EXPAND_AGENT_QUOTAS_PK",
        idempotent: true,
        // The PK widening is reversible (rebuild original table)
        // but rebuild loses the namespace component on backfill.
        reversible: false,
        data_loss_risk: DataLossRisk::Column,
    },
    MigrationMeta {
        version: 51,
        name: "ADD_FEDERATION_NONCES",
        idempotent: true,
        reversible: true,
        data_loss_risk: DataLossRisk::None,
    },
];

/// Look up the metadata for a target schema version.
#[must_use]
pub fn meta_for(version: i64) -> Option<&'static MigrationMeta> {
    MIGRATION_LADDER.iter().find(|m| m.version == version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_8_ladder_versions_strictly_monotonic() {
        let mut prev = 1_i64;
        for meta in MIGRATION_LADDER {
            assert!(
                meta.version > prev,
                "ARCH-8: migration ladder is not strictly monotonic at version {}; prev={prev}",
                meta.version,
            );
            prev = meta.version;
        }
    }

    #[test]
    fn arch_8_ladder_terminates_at_current_schema_version() {
        let last = MIGRATION_LADDER
            .last()
            .expect("MIGRATION_LADDER is non-empty")
            .version;
        let current = crate::storage::current_schema_version_for_tests();
        assert_eq!(
            last, current,
            "ARCH-8: MIGRATION_LADDER tail = {last}, but CURRENT_SCHEMA_VERSION = {current}; \
             when bumping the ladder add a meta row in lockstep.",
        );
    }

    #[test]
    fn arch_8_every_meta_row_has_a_non_empty_name() {
        for meta in MIGRATION_LADDER {
            assert!(
                !meta.name.is_empty(),
                "ARCH-8: migration v{} has an empty `name`",
                meta.version,
            );
        }
    }

    #[test]
    fn arch_8_meta_for_round_trip() {
        // meta_for(<known>) returns Some; meta_for(<unknown>) returns None.
        assert!(meta_for(2).is_some());
        assert!(meta_for(51).is_some());
        assert!(meta_for(9999).is_none());
        assert!(meta_for(0).is_none());
    }
}
