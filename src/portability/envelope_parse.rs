// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! 3-agent vote (71472661) P-9 / P-10 / P-12 / P-14 — the closed `"2"` field
//! set and the `class_counts` cross-check of the Portability-v2 envelope.
//!
//! The vote decision: the new record classes are ADDITIVE arrays under
//! `spec_version` `"2"`, the envelope keeps `deny_unknown_fields`, and one
//! always-serialized `class_counts` map names how many rows each array class
//! carries. An importer refuses the WHOLE bundle (a named error, zero rows)
//! when a count differs from its array, when the map names an unknown class,
//! or when the map is absent while a new array is present. An old bundle with
//! no `class_counts` and none of the new arrays still imports.
//!
//! Two entry points share one checker:
//! - [`check_raw_envelope`] runs on the parsed `serde_json::Value` BEFORE the
//!   strict typed parse, so the refusal names the unknown field (P-14) instead
//!   of surfacing serde's generic `deny_unknown_fields` text;
//! - [`check_class_counts`] runs on the typed envelope inside
//!   `import_full_envelope`, so every caller of the funnel is covered.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde_json::Value;

use crate::portability::emit::ExportEnvelope;

/// P-12: the always-serialized fields of the closed `"2"` set.
pub const ALWAYS_FIELDS: [&str; 10] = [
    "spec_version",
    "db_schema_version",
    "source",
    "exported_at",
    "memories",
    "links",
    "portability_complete",
    "conformance_level",
    "conformance_by_class",
    "count",
];

// The envelope class names: one constant per array class, the single source
// the field-set arrays below, the emitter's `conformance_by_class` and the
// class readers share (pm-v3.1 hardcoded-literal gate). Existing SSOT
// constants are reused where a class already had one.
/// Array class `memories`.
pub const CLASS_MEMORIES: &str = "memories";
/// Array class `links`.
pub const CLASS_LINKS: &str = "links";
/// Array class `signed_events` (the audit-chain name SSOT).
pub const CLASS_SIGNED_EVENTS: &str = crate::signed_events::WITNESS_CHAIN_SIGNED_EVENTS;
/// Array class `memory_revisions` (the revision-chain name SSOT).
pub const CLASS_MEMORY_REVISIONS: &str = crate::signed_events::WITNESS_CHAIN_MEMORY_REVISIONS;
/// Array class `forget_tombstones`.
pub const CLASS_FORGET_TOMBSTONES: &str = "forget_tombstones";
/// Array class `agent_lineage` (the table-name SSOT).
pub const CLASS_AGENT_LINEAGE: &str = crate::storage::schema_integrity::TABLE_AGENT_LINEAGE;
/// Array class `model_attestations`.
pub const CLASS_MODEL_ATTESTATIONS: &str = "model_attestations";
/// Array class `governance_rules` (the table-name SSOT).
pub const CLASS_GOVERNANCE_RULES: &str = crate::storage::schema_integrity::TABLE_GOVERNANCE_RULES;
/// Array class `trust_anchors`.
pub const CLASS_TRUST_ANCHORS: &str = "trust_anchors";
/// Array class `archived_memories` (the `excludes`-marker SSOT).
pub const CLASS_ARCHIVED_MEMORIES: &str = crate::export_scope::OMITTED_CLASS_ARCHIVED_MEMORIES;
/// Array class `namespace_meta` (the `excludes`-marker SSOT).
pub const CLASS_NAMESPACE_META: &str = crate::export_scope::OMITTED_CLASS_NAMESPACE_META;
/// Array class `archived_memory_links` (the table-name SSOT).
pub const CLASS_ARCHIVED_MEMORY_LINKS: &str = crate::storage::TABLE_ARCHIVED_MEMORY_LINKS;
/// Array class `expired_memories` (#8911).
pub const CLASS_EXPIRED_MEMORIES: &str = "expired_memories";
/// Array class `checkpoints` (#8908).
pub const CLASS_CHECKPOINTS: &str = "checkpoints";
/// Array class `routines` (#8908).
pub const CLASS_ROUTINES: &str = "routines";
/// Array class `routine_runs` (#8908).
pub const CLASS_ROUTINE_RUNS: &str = "routine_runs";
/// Array class `entity_aliases` (#8908).
pub const CLASS_ENTITY_ALIASES: &str = "entity_aliases";
/// Array class `offloaded_blobs` (#8908).
pub const CLASS_OFFLOADED_BLOBS: &str = "offloaded_blobs";

/// P-12: the fields serialized only when non-empty, plus `class_counts`.
pub const OPTIONAL_FIELDS: [&str; 17] = [
    CLASS_SIGNED_EVENTS,
    CLASS_MEMORY_REVISIONS,
    CLASS_FORGET_TOMBSTONES,
    CLASS_AGENT_LINEAGE,
    CLASS_MODEL_ATTESTATIONS,
    CLASS_GOVERNANCE_RULES,
    CLASS_TRUST_ANCHORS,
    CLASS_ARCHIVED_MEMORIES,
    CLASS_NAMESPACE_META,
    CLASS_ARCHIVED_MEMORY_LINKS,
    CLASS_EXPIRED_MEMORIES,
    CLASS_CHECKPOINTS,
    CLASS_ROUTINES,
    CLASS_ROUTINE_RUNS,
    CLASS_ENTITY_ALIASES,
    CLASS_OFFLOADED_BLOBS,
    CLASS_COUNTS_FIELD,
];

/// The envelope field that carries the per-class counts.
pub const CLASS_COUNTS_FIELD: &str = "class_counts";

/// P-9: every array class the `"2"` envelope carries, in envelope order.
pub const ARRAY_CLASSES: [&str; 18] = [
    CLASS_MEMORIES,
    CLASS_LINKS,
    CLASS_SIGNED_EVENTS,
    CLASS_MEMORY_REVISIONS,
    CLASS_FORGET_TOMBSTONES,
    CLASS_AGENT_LINEAGE,
    CLASS_MODEL_ATTESTATIONS,
    CLASS_GOVERNANCE_RULES,
    CLASS_TRUST_ANCHORS,
    CLASS_ARCHIVED_MEMORIES,
    CLASS_NAMESPACE_META,
    CLASS_ARCHIVED_MEMORY_LINKS,
    CLASS_EXPIRED_MEMORIES,
    CLASS_CHECKPOINTS,
    CLASS_ROUTINES,
    CLASS_ROUTINE_RUNS,
    CLASS_ENTITY_ALIASES,
    CLASS_OFFLOADED_BLOBS,
];

/// The arrays added by #8908 / #8911. A bundle carrying any of them must
/// carry `class_counts` too (P-10).
pub const NEW_ARRAY_CLASSES: [&str; 6] = [
    CLASS_EXPIRED_MEMORIES,
    CLASS_CHECKPOINTS,
    CLASS_ROUTINES,
    CLASS_ROUTINE_RUNS,
    CLASS_ENTITY_ALIASES,
    CLASS_OFFLOADED_BLOBS,
];

/// The shared refusal prefix of every check in this module.
const REJECTED: &str = "portability import REJECTED (fail-closed)";

/// The rows each array class of `env` carries, keyed by class name, zeros
/// included (P-9). This is exactly the map the emitter writes.
#[must_use]
pub fn carried_counts(env: &ExportEnvelope) -> BTreeMap<String, usize> {
    let lens: [usize; 18] = [
        env.memories.len(),
        env.links.len(),
        env.signed_events.len(),
        env.memory_revisions.len(),
        env.forget_tombstones.len(),
        env.agent_lineage.len(),
        env.model_attestations.len(),
        env.governance_rules.len(),
        env.trust_anchors.len(),
        env.archived_memories.len(),
        env.namespace_meta.len(),
        env.archived_memory_links.len(),
        env.expired_memories.len(),
        env.checkpoints.len(),
        env.routines.len(),
        env.routine_runs.len(),
        env.entity_aliases.len(),
        env.offloaded_blobs.len(),
    ];
    ARRAY_CLASSES
        .iter()
        .zip(lens)
        .map(|(class, n)| ((*class).to_string(), n))
        .collect()
}

/// The one P-10 checker. `declared` is the bundle's map (`None` = absent);
/// `carried` names the rows each class array actually holds.
fn check_counts(
    declared: Option<&BTreeMap<String, usize>>,
    carried: &BTreeMap<String, usize>,
) -> Result<()> {
    let Some(declared) = declared else {
        if let Some(class) = NEW_ARRAY_CLASSES
            .iter()
            .find(|c| carried.get(**c).copied().unwrap_or(0) > 0)
        {
            bail!(
                "{REJECTED}: class_counts is absent but the bundle carries the {class} array; \
                 NO rows were applied"
            );
        }
        return Ok(());
    };
    if let Some(unknown) = declared
        .keys()
        .find(|k| !ARRAY_CLASSES.contains(&k.as_str()))
    {
        bail!("{REJECTED}: class_counts names unknown class \"{unknown}\"; NO rows were applied");
    }
    for class in ARRAY_CLASSES {
        let rows = carried.get(class).copied().unwrap_or(0);
        match declared.get(class) {
            None => bail!(
                "{REJECTED}: class_counts has no entry for class \"{class}\" (the {class} array \
                 carries {rows} rows); NO rows were applied"
            ),
            Some(&n) if n != rows => bail!(
                "{REJECTED}: class_counts[\"{class}\"] = {n} but the {class} array carries \
                 {rows} rows; NO rows were applied"
            ),
            Some(_) => {}
        }
    }
    Ok(())
}

/// P-10 on the typed envelope (defense in depth inside the import funnel).
///
/// # Errors
///
/// The named P-10 refusal; the caller applies zero rows.
pub fn check_class_counts(env: &ExportEnvelope) -> Result<()> {
    check_counts(env.class_counts.as_ref(), &carried_counts(env))
}

/// P-14 + P-10 on the raw bundle, before the strict typed parse.
///
/// A non-object bundle is left to the strict parse, which names its own
/// error. A class array that is present but not an array counts as zero rows
/// here; the strict parse refuses it right after.
///
/// # Errors
///
/// The named P-14 unknown-field refusal, or a named P-10 refusal.
pub fn check_raw_envelope(bundle: &Value) -> Result<()> {
    let Some(obj) = bundle.as_object() else {
        return Ok(());
    };
    if let Some(unknown) = obj
        .keys()
        .find(|k| !ALWAYS_FIELDS.contains(&k.as_str()) && !OPTIONAL_FIELDS.contains(&k.as_str()))
    {
        bail!(
            "{REJECTED}: unknown top-level field \"{unknown}\" — the bundle comes from a newer \
             build than this node understands; upgrade this node; NO rows were applied"
        );
    }
    let carried: BTreeMap<String, usize> = ARRAY_CLASSES
        .iter()
        .map(|class| {
            let rows = obj
                .get(*class)
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            ((*class).to_string(), rows)
        })
        .collect();
    let declared = match obj.get(CLASS_COUNTS_FIELD) {
        None | Some(Value::Null) => None,
        Some(Value::Object(map)) => {
            let mut parsed = BTreeMap::new();
            for (class, raw) in map {
                let Some(n) = raw.as_u64().and_then(|n| usize::try_from(n).ok()) else {
                    bail!(
                        "{REJECTED}: class_counts[\"{class}\"] is not a non-negative integer; \
                         NO rows were applied"
                    );
                };
                parsed.insert(class.clone(), n);
            }
            Some(parsed)
        }
        Some(_) => bail!("{REJECTED}: class_counts is not an object; NO rows were applied"),
    };
    check_counts(declared.as_ref(), &carried)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full(rows: usize) -> BTreeMap<String, usize> {
        ARRAY_CLASSES
            .iter()
            .map(|c| ((*c).to_string(), rows))
            .collect()
    }

    #[test]
    fn issue_8908_field_sets_are_disjoint_and_cover_every_array_class() {
        for class in ARRAY_CLASSES {
            assert!(
                ALWAYS_FIELDS.contains(&class) || OPTIONAL_FIELDS.contains(&class),
                "{class} is in the closed set"
            );
        }
        for f in ALWAYS_FIELDS {
            assert!(!OPTIONAL_FIELDS.contains(&f), "{f} listed twice");
        }
    }

    #[test]
    fn issue_8908_missing_entry_is_refused_by_name() {
        let mut declared = full(0);
        declared.remove("routines");
        let err = check_counts(Some(&declared), &full(0)).expect_err("refused");
        assert_eq!(
            err.to_string(),
            format!(
                "{REJECTED}: class_counts has no entry for class \"routines\" (the routines \
                 array carries 0 rows); NO rows were applied"
            )
        );
    }

    #[test]
    fn issue_8908_raw_non_integer_count_is_refused_by_name() {
        let bundle = serde_json::json!({ "class_counts": { "memories": -1 } });
        let err = check_raw_envelope(&bundle).expect_err("refused");
        assert_eq!(
            err.to_string(),
            format!(
                "{REJECTED}: class_counts[\"memories\"] is not a non-negative integer; NO rows \
                 were applied"
            )
        );
    }

    #[test]
    fn issue_8908_old_shape_without_counts_or_new_arrays_passes() {
        let mut carried = full(0);
        carried.insert("memories".into(), 3);
        check_counts(None, &carried).expect("an old bundle still imports");
    }
}
