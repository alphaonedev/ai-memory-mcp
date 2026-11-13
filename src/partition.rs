// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8758 — the partition every autonomous pass clusters, prompts and derives
//! within.
//!
//! An autonomous pass (the curator's consolidation, reflection and
//! contradiction passes, the sqlite autonomy Pass-1, the store-time
//! contradiction hook) reads rows of many owners at admin privilege. Before
//! #8758 they grouped by namespace alone, so one owner's private row and
//! another owner's collective row with similar bodies landed in one cluster,
//! one LLM prompt and one derived row. [`PartitionKey`] is the one key those
//! sites group by: `(namespace, owner, visibility arm)`. Two rows may share a
//! cluster, a prompt or a derived record only when their keys are equal.
//!
//! The scope component is the *visibility arm* from
//! [`crate::visibility::scope_arm_of`], not the raw token, so the key agrees
//! with what a reader can actually see: an absent scope, `private` and an
//! unrecognised token are one arm (owner-private), `collective` and the legacy
//! broad spellings are one arm, and `team` / `unit` / `org` are three arms.
//! The key is pure and fails closed: a row whose owner cannot be read is keyed
//! `owner: None`, which never equals a row that names an owner.
//!
//! The helpers are `pub(crate)` so other autonomous LLM surfaces (the
//! `memory_atomise` and `memory_persona_generate` handlers, #8753 / #8754)
//! can group by the same key.

use std::collections::BTreeMap;

use crate::models::Memory;
#[cfg(any(feature = "sal", test))]
use crate::models::namespace::MemoryScope;
use crate::visibility::{ScopeArm, scope_arm_of};

/// The `(namespace, owner, visibility arm)` partition of one row (#8758).
///
/// `Eq`, `Hash` and `Ord` are all derived over the same three fields, so they
/// agree (per API-29) and the key is safe in both hash and ordered maps.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct PartitionKey {
    namespace: String,
    owner: Option<String>,
    scope: ScopeArm,
}

impl PartitionKey {
    /// The partition `memory` belongs to. The owner is the claimed
    /// `metadata.agent_id` (the same field the visibility predicate keys the
    /// private arm on); a missing or non-string value is `None`.
    pub(crate) fn of(memory: &Memory) -> Self {
        Self {
            namespace: memory.namespace.clone(),
            owner: memory
                .metadata
                .get(crate::META_KEY_AGENT_ID)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            scope: scope_arm_of(memory),
        }
    }
}

/// `true` iff `a` and `b` are in one partition and so may share a cluster,
/// an LLM prompt or a derived row.
pub(crate) fn same_partition(a: &Memory, b: &Memory) -> bool {
    PartitionKey::of(a) == PartitionKey::of(b)
}

/// The one partition every row of `rows` belongs to, or `None` when `rows` is
/// empty or spans more than one partition. The eligibility gates call this so
/// a mixed cluster is refused even if a clusterer ever produced one.
pub(crate) fn single_partition<'m>(
    rows: impl IntoIterator<Item = &'m Memory>,
) -> Option<PartitionKey> {
    let mut iter = rows.into_iter();
    let first = PartitionKey::of(iter.next()?);
    iter.all(|m| PartitionKey::of(m) == first).then_some(first)
}

/// Group the indices of `rows` by partition, keeping only rows for which
/// `keep` holds. The map is ordered, so iteration is deterministic.
pub(crate) fn group_indices_by_partition(
    rows: &[Memory],
    mut keep: impl FnMut(&Memory) -> bool,
) -> BTreeMap<PartitionKey, Vec<usize>> {
    let mut groups: BTreeMap<PartitionKey, Vec<usize>> = BTreeMap::new();
    for (idx, row) in rows.iter().enumerate() {
        if keep(row) {
            groups.entry(PartitionKey::of(row)).or_default().push(idx);
        }
    }
    groups
}

// Only the sal-gated reflection pass derives a row from a cluster today.
#[cfg(any(feature = "sal", test))]
/// Breadth rank of a visibility arm: lower is narrower. An out-of-range
/// subtree index ranks with owner-private, the narrowest arm (fail closed).
fn breadth_rank(arm: ScopeArm) -> u8 {
    match arm {
        ScopeArm::Subtree(1) => 1,
        ScopeArm::Subtree(2) => 2,
        ScopeArm::Subtree(3) => 3,
        ScopeArm::Broad => 4,
        ScopeArm::OwnerPrivate | ScopeArm::Subtree(_) => 0,
    }
}

#[cfg(any(feature = "sal", test))]
/// The canonical `metadata.scope` token of the narrowest visibility arm among
/// `rows`, for a row derived from them. Empty input yields `private`.
pub(crate) fn narrowest_scope_token<'m>(
    rows: impl IntoIterator<Item = &'m Memory>,
) -> &'static str {
    let narrowest = rows
        .into_iter()
        .map(scope_arm_of)
        .min_by_key(|arm| breadth_rank(*arm))
        .unwrap_or(ScopeArm::OwnerPrivate);
    match breadth_rank(narrowest) {
        1 => MemoryScope::Team.as_str(),
        2 => MemoryScope::Unit.as_str(),
        3 => MemoryScope::Org.as_str(),
        4 => MemoryScope::Collective.as_str(),
        _ => MemoryScope::Private.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(owner: Option<&str>, scope: Option<&str>) -> Memory {
        let mut metadata = serde_json::json!({});
        if let Some(owner) = owner {
            metadata[crate::META_KEY_AGENT_ID] = serde_json::Value::String(owner.to_string());
        }
        if let Some(scope) = scope {
            metadata[crate::META_KEY_SCOPE] = serde_json::Value::String(scope.to_string());
        }
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "row-8758".to_string(),
            tier: crate::models::Tier::Long,
            namespace: "proj8758/key".to_string(),
            title: "row".to_string(),
            content: "row".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata,
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    #[test]
    fn partition_key_aliases_follow_the_visibility_arm_8758() {
        let a = Some("ai:a");
        assert!(same_partition(&row(a, None), &row(a, Some("private"))));
        assert!(same_partition(
            &row(a, Some("collective")),
            &row(a, Some("shared"))
        ));
        assert!(!same_partition(&row(a, Some("team")), &row(a, Some("org"))));
        assert!(!same_partition(&row(a, None), &row(Some("ai:b"), None)));
        assert!(!same_partition(&row(a, None), &row(None, None)));
    }

    #[test]
    fn single_partition_refuses_empty_and_mixed_8758() {
        let a = Some("ai:a");
        assert!(single_partition(&[] as &[Memory]).is_none());
        assert!(single_partition(&[row(a, None), row(a, Some("collective"))]).is_none());
        assert!(single_partition(&[row(a, None), row(a, Some("private"))]).is_some());
    }

    #[test]
    fn narrowest_scope_token_never_widens_8758() {
        let a = Some("ai:a");
        for (scopes, want) in [
            (vec![Some("collective"), Some("team")], "team"),
            (vec![Some("org"), Some("unit")], "unit"),
            (vec![Some("collective"), None], "private"),
            (vec![Some("shared")], "collective"),
            (vec![Some("no-such-scope")], "private"),
            (vec![], "private"),
        ] {
            let rows: Vec<Memory> = scopes.into_iter().map(|s| row(a, s)).collect();
            assert_eq!(narrowest_scope_token(&rows), want);
        }
    }
}
