// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4216 / #4218 — the replicated meaning of `memories.version` (5-agent vote
//! 4d3ea1c5, memory ea23f404, verdict A as amended by f2r).
//!
//! `version` is the optimistic-concurrency token behind HTTP `If-Match`
//! (Gap-1, #884) and the #4045 consolidation compare-and-set. Both assume that
//! every change to a row's user data changes the version. The federation
//! merge funnels kept `MAX(local, remote)` while REPLACING content, so a
//! client holding the pre-merge version still passed its check and silently
//! overwrote the merged edit (a lost update).
//!
//! # The rule (#4216)
//!
//! A merge that CHANGES the user data of the local row sets
//! `version = GREATEST(local, remote) + 1` ([`bumped_version`]). A replay of
//! the same row, or a losing push that changes nothing, does not bump. A
//! losing push that still raises `priority` / `confidence` / `tier` (the MAX
//! arms) DOES change user data and so bumps. The decision is ONE shared Rust
//! predicate, [`user_data_changed`], evaluated on the merged row against the
//! local row inside the merge transaction by all four apply funnels (sqlite
//! `insert_if_newer` and `merge_inbound`, postgres `apply_remote_memory` and
//! `merge_inbound`); there are no per-SQL copies. `crdt_merge::merge_memory`
//! stays a pure max.
//!
//! The predicate compares content as PLAINTEXT (never envelope bytes, so a
//! row re-sealed under a fresh key does not look changed) and EXCLUDES
//! `access_count`, `last_accessed_at`, `expires_at` (recall / TTL
//! bookkeeping) and, inside `metadata`, the node-local keys
//! ([`crate::models::crdt_merge::NODE_LOCAL_METADATA_KEYS`]),
//! `crdt_field_clocks` and `version_vector`: the last two are merge
//! bookkeeping whose bytes are not convergent across merge groupings, so
//! comparing them would bump with no user edit (f2r amendments 1 and 2).
//!
//! # Documented limitation
//!
//! The version and `If-Match` are a NODE-LOCAL token. Two nodes that both
//! merge and bump independently can hold different versions for the same
//! converged content; the token protects a client against a concurrent write
//! on the node it talks to, not across replicas. The wire format is unchanged.
//!
//! # The bound (#4218)
//!
//! Nothing used to bound the `version` a peer pushes, so one enrolled peer
//! could pin a row at `i64::MAX` on every node (the merge only ever takes the
//! larger value) and overflow the next local `version + 1`. The inbound value
//! is now refused at the shared receive validation above
//! [`MAX_REPLICATED_VERSION`] (per item; the rest of the batch is applied),
//! and every merge funnel that knows the local row clamps it to
//! `local + MAX_INBOUND_VERSION_JUMP` ([`bounded_inbound_version`]). Every
//! `+ 1` is saturating.

use serde_json::{Map, Value};

use crate::models::Memory;
use crate::models::crdt_merge::NODE_LOCAL_METADATA_KEYS;
use crate::models::field_names;

/// Largest `version` a peer may replicate (2^40, about 1.1e12 edits). Far
/// beyond any honest counter, far below the `i64::MAX` overflow edge.
pub const MAX_REPLICATED_VERSION: i64 = 1 << 40;

/// Largest step an inbound `version` may take over the local row's version in
/// one merge (2^32). A peer that is honestly ahead by more than this is
/// clamped to the step, never trusted to pin the counter.
pub const MAX_INBOUND_VERSION_JUMP: i64 = 1 << 32;

/// Metadata keys that are merge bookkeeping, not user data.
const BOOKKEEPING_METADATA_KEYS: [&str; 2] =
    [field_names::CRDT_FIELD_CLOCKS, field_names::VERSION_VECTOR];

/// Refuse an inbound replicated `version` that is negative or above
/// [`MAX_REPLICATED_VERSION`] (#4218). Called from the shared receive
/// validation, so a refusal is per item.
///
/// # Errors
///
/// A distinct `replicated version` error naming the bound.
pub fn validate_replicated_version(version: i64) -> anyhow::Result<()> {
    if !(0..=MAX_REPLICATED_VERSION).contains(&version) {
        anyhow::bail!(
            "replicated version {version} is outside the accepted bound 0..={MAX_REPLICATED_VERSION} (#4218)"
        );
    }
    Ok(())
}

/// Clamp an inbound `version` for a merge (#4218): never above
/// [`MAX_REPLICATED_VERSION`], and, when the local row is known, never more
/// than [`MAX_INBOUND_VERSION_JUMP`] above it. Never below zero.
#[must_use]
pub fn bounded_inbound_version(inbound: i64, local: Option<i64>) -> i64 {
    let ceiling = local.map_or(MAX_REPLICATED_VERSION, |l| {
        l.saturating_add(MAX_INBOUND_VERSION_JUMP)
            .min(MAX_REPLICATED_VERSION.max(l))
    });
    inbound.clamp(0, ceiling.max(0))
}

/// The version a merge that changed user data must land on: one above the
/// merged (GREATEST) counter, saturating (#4218). Never overflows.
#[must_use]
pub fn bumped_version(merged_version: i64) -> i64 {
    merged_version.saturating_add(1)
}

/// `merge_inbound` funnels (same-id field merge, both backends): clamp the
/// prepared inbound row's `version` against the local row it merges into
/// (#4218), BEFORE [`crate::models::merge_memory`].
pub fn bound_inbound_row(inbound: &mut Memory, local: &Memory) {
    inbound.version = bounded_inbound_version(inbound.version, Some(local.version));
}

/// `merge_inbound` funnels: after the pure field merge, apply the #4216 rule to
/// the merged row. `merged.version` is the GREATEST on entry.
pub fn apply_version_rule(local: &Memory, merged: &mut Memory) {
    if user_data_changed(local, merged) {
        merged.version = bumped_version(merged.version);
    }
}

/// `metadata` without its node-local and bookkeeping top-level keys.
fn user_metadata(metadata: &Value) -> Map<String, Value> {
    let Some(map) = metadata.as_object() else {
        return Map::new();
    };
    map.iter()
        .filter(|(k, _)| {
            !NODE_LOCAL_METADATA_KEYS.contains(&k.as_str())
                && !BOOKKEEPING_METADATA_KEYS.contains(&k.as_str())
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn sorted_tags(tags: &[String]) -> Vec<&str> {
    let mut t: Vec<&str> = tags.iter().map(String::as_str).collect();
    t.sort_unstable();
    t
}

fn canonical_time(t: Option<&str>) -> Option<String> {
    crate::validate::canonical_valid_time_opt(t)
}

/// Whether the merge changed the USER DATA of the local row (#4216): the ONE
/// predicate all four apply funnels share. `before` is the local row read
/// inside the merge transaction, `after` the merged row. See the module docs
/// for the exact column set and exclusions.
#[must_use]
pub fn user_data_changed(before: &Memory, after: &Memory) -> bool {
    before.content != after.content
        || before.title != after.title
        || before.namespace != after.namespace
        || sorted_tags(&before.tags) != sorted_tags(&after.tags)
        || user_metadata(&before.metadata) != user_metadata(&after.metadata)
        || before.tier.as_str() != after.tier.as_str()
        || before.priority != after.priority
        || before.confidence.total_cmp(&after.confidence) != std::cmp::Ordering::Equal
        || before.lifecycle_state.as_str() != after.lifecycle_state.as_str()
        || canonical_time(before.valid_from.as_deref())
            != canonical_time(after.valid_from.as_deref())
        || canonical_time(before.valid_until.as_deref())
            != canonical_time(after.valid_until.as_deref())
        || before.memory_kind.as_str() != after.memory_kind.as_str()
        || before.source != after.source
        || before.citations != after.citations
        || before.source_uri != after.source_uri
        || before.source_span != after.source_span
        || before.confidence_source.as_str() != after.confidence_source.as_str()
        || before.confidence_signals != after.confidence_signals
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base() -> Memory {
        serde_json::from_value(json!({
            "id": "m1", "tier": "mid", "namespace": "ns", "title": "t", "content": "c",
            "tags": ["b", "a"], "priority": 5, "confidence": 1.0, "source": "nhi",
            "access_count": 0, "created_at": "2026-09-20T00:00:00Z",
            "updated_at": "2026-09-20T00:00:00Z", "version": 3,
            "metadata": {"agent_id": "a"}
        }))
        .expect("memory")
    }

    #[test]
    fn identical_rows_are_unchanged_4216() {
        assert!(!user_data_changed(&base(), &base()));
    }

    #[test]
    fn every_user_column_trips_the_predicate_4216() {
        let b = base();
        let mut m = b.clone();
        m.content = "x".into();
        assert!(user_data_changed(&b, &m));
        let mut m = b.clone();
        m.priority = 9;
        assert!(user_data_changed(&b, &m));
        let mut m = b.clone();
        m.tags.push("z".into());
        assert!(user_data_changed(&b, &m));
        let mut m = b.clone();
        m.metadata = json!({"agent_id": "a", "k": 1});
        assert!(user_data_changed(&b, &m));
    }

    #[test]
    fn bookkeeping_only_differences_do_not_trip_it_4216() {
        let b = base();
        let mut m = b.clone();
        m.access_count = 99;
        m.last_accessed_at = Some("2026-09-21T00:00:00Z".into());
        m.expires_at = Some("2030-01-01T00:00:00Z".into());
        m.updated_at = "2026-09-22T00:00:00Z".into();
        m.tags.reverse();
        m.metadata = json!({
            "agent_id": "a",
            "crdt_field_clocks": {"row": 7},
            "version_vector": {"entries": {"n": "2026-09-22T00:00:00Z"}},
            "contamination": {"x": 1},
        });
        assert!(!user_data_changed(&b, &m));
    }

    #[test]
    fn bound_refuses_the_i64_max_pin_4218() {
        assert!(validate_replicated_version(i64::MAX).is_err());
        assert!(validate_replicated_version(-1).is_err());
        assert!(validate_replicated_version(MAX_REPLICATED_VERSION + 1).is_err());
        assert!(validate_replicated_version(MAX_REPLICATED_VERSION).is_ok());
        assert!(validate_replicated_version(0).is_ok());
    }

    #[test]
    fn clamp_never_follows_a_far_ahead_peer_4218() {
        assert_eq!(
            bounded_inbound_version(i64::MAX, Some(3)),
            3 + MAX_INBOUND_VERSION_JUMP
        );
        assert_eq!(
            bounded_inbound_version(i64::MAX, None),
            MAX_REPLICATED_VERSION
        );
        assert_eq!(bounded_inbound_version(5, Some(3)), 5);
        assert_eq!(bounded_inbound_version(-7, Some(3)), 0);
        // a legacy row already above the bound is never pulled down or past it
        assert_eq!(bounded_inbound_version(i64::MAX, Some(i64::MAX)), i64::MAX);
    }

    #[test]
    fn bump_saturates_4218() {
        assert_eq!(bumped_version(3), 4);
        assert_eq!(bumped_version(i64::MAX), i64::MAX);
    }
}
