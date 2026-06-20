// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.8.0 Pillar-3 (#1709 / #224) — CRDT-lite per-field memory merge.
//!
//! [`merge_memory`] is a **pure, deterministic** field-wise reconciler:
//! given two divergent same-`id` [`Memory`] rows (a `local` and a
//! `remote`/peer replica) it produces a single merged row by applying
//! the canonical #224 design-table rule to each field independently.
//!
//! ## Why CRDT-lite
//!
//! The substrate's pre-existing federation conflict path
//! (`storage::insert_if_newer`) resolves a `(title, namespace)`
//! collision by whole-column newer-wins inside one SQL `ON CONFLICT`
//! statement: scalar last-write-wins for most columns, with a handful
//! of `MAX(...)` / `COALESCE(...)` arms. That is a *coarse* merge —
//! `tags` are REPLACED, not unioned, and `metadata` is preserved only
//! for `agent_id`. The #224 design table specifies a *finer* merge
//! where each field carries the resolution rule that preserves the
//! most information (union, max, min, deep-JSON-merge), so two agents
//! that each appended a distinct tag both keep their tag after the
//! merge.
//!
//! [`merge_memory`] implements that finer table as a free function over
//! two in-memory [`Memory`] values, with **no I/O and no clock reads**
//! — it never calls `Utc::now()` and never touches the database, so it
//! is trivially testable and replayable. Wiring it into the SQL
//! conflict path is a *separate* unit (the SQL upsert would have to
//! become a read-merge-write transaction); this module lands the pure
//! reconciler + its exhaustive per-rule test suite.
//!
//! ## Determinism / algebraic properties
//!
//! Every "last-write-wins" (LWW) resolution tiebreaks on the total
//! order `(updated_at, id)` — strictly newer `updated_at` wins, and on
//! an `updated_at` tie the lexically-greater `id` wins. Because the
//! tiebreak is a *total order over the two operands* (never "keep the
//! first argument"), `merge_memory` is:
//!
//! * **commutative** — `merge(a, b)` and `merge(b, a)` serialise
//!   identically (max / min / union are order-free; LWW picks the same
//!   `(updated_at, id)`-maximal side regardless of argument position);
//! * **idempotent** — `merge(a, a) == a`;
//! * **associative** on the commutative fields (max/min/union) and on
//!   the LWW fields (which all collapse to the global
//!   `(updated_at, id)`-maximal operand).
//!
//! These are the convergence properties a CRDT needs: peers that
//! receive the same set of replicas in any order reach the same state.
//!
//! ## Metadata sub-rules (#224 + Task 1.8 #196)
//!
//! `metadata` is a deep JSON merge (objects merge key-wise recursively;
//! disjoint keys both survive; non-object collisions fall back to LWW),
//! with three overrides applied AFTER the deep merge:
//!
//! * `metadata.agent_id` — **immutable, original (`local`) wins**
//!   (NHI provenance is write-once; a peer must not rewrite it).
//! * `metadata.scope` — **LWW by `(updated_at, id)`** (a conscious
//!   visibility change, like `title`).
//! * `metadata.governance` — **keep `local`'s** (owner-only override; a
//!   merge must never let a peer rewrite governance).

use serde_json::{Map, Value};

use super::crdt_primitives::{OrSet, PnCounter};
use super::field_names;
use super::memory::Memory;
use crate::mcp::param_names;

/// Delegate a #224 max-merged counter field to the [`PnCounter`] lattice
/// (monotonic — a merge never rolls the value backwards). Used for
/// `priority` / `confidence` / `access_count` / `version` /
/// `reflection_depth`.
fn merge_counter<T: PartialOrd + Clone>(local: T, remote: T) -> T {
    PnCounter::new(local)
        .merge(&PnCounter::new(remote))
        .into_inner()
}

/// Total-order LWW verdict: `true` when `remote` should win the
/// last-write-wins tiebreak over `local`.
///
/// The order is `(updated_at, id)`: a strictly-greater `updated_at`
/// wins; on an `updated_at` tie the lexically-greater `id` wins. Using
/// a total order over BOTH operands (rather than "remote wins only on
/// strict-greater, else keep local") is what makes [`merge_memory`]
/// fully commutative — `merge(a, b)` and `merge(b, a)` pick the same
/// side because the winner is a property of the pair, not of argument
/// position.
fn remote_wins_lww(local: &Memory, remote: &Memory) -> bool {
    (remote.updated_at.as_str(), remote.id.as_str())
        > (local.updated_at.as_str(), local.id.as_str())
}

/// LWW pick of a cloneable field: returns `remote`'s value when it wins
/// the `(updated_at, id)` tiebreak, else `local`'s.
fn lww<T: Clone>(local: &Memory, remote: &Memory, local_val: &T, remote_val: &T) -> T {
    if remote_wins_lww(local, remote) {
        remote_val.clone()
    } else {
        local_val.clone()
    }
}

/// "Prefer non-null, else LWW" pick for an `Option` field (#224
/// provenance / structural fields): a present value beats absence
/// (preservation over loss); when BOTH are present, the
/// `(updated_at, id)` LWW winner's value is taken; when both are absent
/// the result is absent. Deterministic + commutative because the
/// both-present branch defers to the symmetric LWW order.
fn prefer_non_null_else_lww<T: Clone>(
    local: &Memory,
    remote: &Memory,
    local_val: &Option<T>,
    remote_val: &Option<T>,
) -> Option<T> {
    match (local_val, remote_val) {
        (Some(_), Some(_)) => lww(local, remote, local_val, remote_val),
        (Some(_), None) => local_val.clone(),
        (None, Some(_)) => remote_val.clone(),
        (None, None) => None,
    }
}

/// `tags` union with a deterministic, stable order: preserve `local`'s
/// order first, then append the `remote` tags not already seen. Dedup
/// is exact-string. The result is independent of argument order *as a
/// set* (the merge is commutative on tag membership); the surface
/// ordering is local-first by design and is asserted as a set in the
/// commutativity test.
fn merge_tags(local: &[String], remote: &[String]) -> Vec<String> {
    OrSet::new(local.to_vec())
        .merge(&OrSet::new(remote.to_vec()))
        .into_inner()
}

/// `tier` resolution (#224): **max durability** on the total order
/// `short < mid < long` — a merge NEVER downgrades a memory's
/// durability tier. `Tier` deliberately does not derive `Ord` (the
/// enum-proliferation audit #970 keeps the wire enums non-comparable),
/// so the durability rank is matched explicitly here. Commutative +
/// idempotent (it is a `max` over a 3-element chain).
fn merge_tier(local: &super::memory::Tier, remote: &super::memory::Tier) -> super::memory::Tier {
    use super::memory::Tier;
    // Durability rank: Short=0, Mid=1, Long=2. Take the higher.
    fn rank(t: &Tier) -> u8 {
        match t {
            Tier::Short => 0,
            Tier::Mid => 1,
            Tier::Long => 2,
        }
    }
    if rank(remote) > rank(local) {
        remote.clone()
    } else {
        local.clone()
    }
}

/// `expires_at` resolution (#224): **null = never expires, so null WINS
/// over any non-null** (preservation over loss); when both are present,
/// the later (lexically-greater RFC3339) expiry wins. RFC3339 strings
/// in UTC compare lexically in chronological order, matching the
/// substrate's existing `gc()` string-comparison contract.
fn merge_expires_at(local: &Option<String>, remote: &Option<String>) -> Option<String> {
    match (local, remote) {
        // Either side immortal ⇒ result immortal (null wins).
        (None, _) | (_, None) => None,
        (Some(l), Some(r)) => {
            if r > l {
                Some(r.clone())
            } else {
                Some(l.clone())
            }
        }
    }
}

/// Deep JSON merge of two `metadata` objects (#224 `metadata` rule,
/// pre-override pass):
///
/// * two objects merge key-wise, recursing on keys present in both;
/// * a key present on only one side is preserved (unknown keys kept);
/// * a non-object collision (or object-vs-scalar) falls back to LWW by
///   `(updated_at, id)` via the `remote_wins` flag.
///
/// The three metadata sub-rules (`agent_id` immutable→local, `scope`
/// LWW, `governance`→local) are NOT applied here; [`merge_memory`]
/// applies them on the top-level object after this deep merge so the
/// recursion stays a generic value reconciler.
fn deep_merge_json(local: &Value, remote: &Value, remote_wins: bool) -> Value {
    match (local, remote) {
        (Value::Object(lmap), Value::Object(rmap)) => {
            let mut merged: Map<String, Value> = lmap.clone();
            for (key, rval) in rmap {
                match merged.get(key) {
                    Some(lval) => {
                        let combined = deep_merge_json(lval, rval, remote_wins);
                        merged.insert(key.clone(), combined);
                    }
                    None => {
                        merged.insert(key.clone(), rval.clone());
                    }
                }
            }
            Value::Object(merged)
        }
        // Non-object collision: LWW by the caller-supplied tiebreak.
        _ => {
            if remote_wins {
                remote.clone()
            } else {
                local.clone()
            }
        }
    }
}

/// Resolve `metadata`: deep JSON merge, then apply the three #224
/// sub-rules on the top-level object (`agent_id` immutable→local,
/// `scope` LWW, `governance`→local).
fn merge_metadata(local: &Memory, remote: &Memory) -> Value {
    let remote_wins = remote_wins_lww(local, remote);
    let mut merged = deep_merge_json(&local.metadata, &remote.metadata, remote_wins);

    // The three sub-rules only have meaning when the merged result is an
    // object (the substrate's `metadata` is always an object — `{}` by
    // default — but a malformed scalar metadata falls through the deep
    // merge as an LWW scalar, in which case the keys do not apply).
    if let Value::Object(map) = &mut merged {
        // agent_id — immutable, original (local) wins. Write-once NHI
        // provenance (Task 1.8 #196): a peer must never rewrite it.
        match local.metadata.get(param_names::AGENT_ID) {
            Some(local_agent) => {
                map.insert(param_names::AGENT_ID.to_string(), local_agent.clone());
            }
            None => {
                // Local never had agent_id; a remote-introduced agent_id
                // is NOT provenance the local row authored, so drop it to
                // honour "original wins" (absence is the original).
                map.remove(param_names::AGENT_ID);
            }
        }

        // scope — LWW by (updated_at, id), a conscious visibility edit.
        let local_scope = local.metadata.get(param_names::SCOPE);
        let remote_scope = remote.metadata.get(param_names::SCOPE);
        let scope_winner = match (local_scope, remote_scope) {
            (Some(_), Some(_)) => {
                if remote_wins {
                    remote_scope
                } else {
                    local_scope
                }
            }
            (Some(_), None) => local_scope,
            (None, Some(_)) => remote_scope,
            (None, None) => None,
        };
        match scope_winner {
            Some(v) => {
                map.insert(param_names::SCOPE.to_string(), v.clone());
            }
            None => {
                map.remove(param_names::SCOPE);
            }
        }

        // governance — keep local's (owner-only override; a merge must
        // not let a peer rewrite governance).
        match local.metadata.get(field_names::GOVERNANCE) {
            Some(local_gov) => {
                map.insert(field_names::GOVERNANCE.to_string(), local_gov.clone());
            }
            None => {
                map.remove(field_names::GOVERNANCE);
            }
        }
    }

    merged
}

/// v0.8.0 Pillar-3 (#1709 / #224) — pure, deterministic CRDT-lite merge
/// of two divergent same-`id` [`Memory`] rows.
///
/// Resolves every field per the canonical #224 design table (see the
/// module docs). **Precondition:** `local.id == remote.id` (same row);
/// `debug_assert_eq!`-checked. The returned [`Memory`] is constructed
/// field-by-field with NO `..local.clone()` rest-spread, so a future
/// field added to [`Memory`] fails to compile here until an explicit
/// merge rule is chosen for it.
///
/// Pure: no I/O, no clock reads. Commutative + associative (up to the
/// `(updated_at, id)` LWW total order) + idempotent.
#[must_use]
pub fn merge_memory(local: &Memory, remote: &Memory) -> Memory {
    debug_assert_eq!(
        local.id, remote.id,
        "merge_memory precondition: both operands must carry the same id"
    );

    Memory {
        // `id` — equality (precondition above). Both args share it; take
        // local's deterministically.
        id: local.id.clone(),
        // `tier` — max durability (short < mid < long); never downgrade.
        tier: merge_tier(&local.tier, &remote.tier),
        // `namespace` — LWW by updated_at (tiebreak id).
        namespace: lww(local, remote, &local.namespace, &remote.namespace),
        // `title` — LWW by updated_at.
        title: lww(local, remote, &local.title, &remote.title),
        // `content` — LWW by updated_at.
        content: lww(local, remote, &local.content, &remote.content),
        // `tags` — union (dedup, stable local-first order).
        tags: merge_tags(&local.tags, &remote.tags),
        // `priority` — max (PN-Counter).
        priority: merge_counter(local.priority, remote.priority),
        // `confidence` — max (PN-Counter).
        confidence: merge_counter(local.confidence, remote.confidence),
        // `source` — LWW by updated_at.
        source: lww(local, remote, &local.source, &remote.source),
        // `access_count` — max (PN-Counter).
        access_count: merge_counter(local.access_count, remote.access_count),
        // `created_at` — min (earliest creation). RFC3339 UTC strings
        // compare lexically in chronological order.
        created_at: if remote.created_at < local.created_at {
            remote.created_at.clone()
        } else {
            local.created_at.clone()
        },
        // `updated_at` — max (latest update).
        updated_at: if remote.updated_at > local.updated_at {
            remote.updated_at.clone()
        } else {
            local.updated_at.clone()
        },
        // `last_accessed_at` — max; absence is the floor, so a present
        // value beats None (prefer-non-null), and on both-present the
        // later stamp wins.
        last_accessed_at: max_opt_string(&local.last_accessed_at, &remote.last_accessed_at),
        // `expires_at` — max, BUT null (never-expires) wins over any
        // non-null (preservation over loss).
        expires_at: merge_expires_at(&local.expires_at, &remote.expires_at),
        // `metadata` — deep JSON merge + 3 sub-rules (agent_id→local,
        // scope LWW, governance→local).
        metadata: merge_metadata(local, remote),
        // `reflection_depth` — max (PN-Counter; monotonic — the
        // reflection signal must not be lost on merge).
        reflection_depth: merge_counter(local.reflection_depth, remote.reflection_depth),
        // #224: memory_kind not in design table — LWW per table
        // philosophy (a conscious typing choice, like title).
        memory_kind: lww(local, remote, &local.memory_kind, &remote.memory_kind),
        // #224: entity_id not in design table — prefer non-null, else LWW
        // (structural / persona discriminator: preservation over loss).
        entity_id: prefer_non_null_else_lww(local, remote, &local.entity_id, &remote.entity_id),
        // #224: persona_version not in design table — prefer non-null,
        // else LWW (structural).
        persona_version: prefer_non_null_else_lww(
            local,
            remote,
            &local.persona_version,
            &remote.persona_version,
        ),
        // #224: citations not in design table — prefer non-null (a
        // non-empty array beats empty), else LWW (provenance). An empty
        // vec is treated as "absent" so a peer carrying fact-provenance
        // does not get clobbered by a row that recorded none.
        citations: if local.citations.is_empty() {
            remote.citations.clone()
        } else if remote.citations.is_empty() {
            local.citations.clone()
        } else {
            lww(local, remote, &local.citations, &remote.citations)
        },
        // #224: source_uri not in design table — prefer non-null, else
        // LWW (provenance).
        source_uri: prefer_non_null_else_lww(local, remote, &local.source_uri, &remote.source_uri),
        // #224: source_span not in design table — prefer non-null, else
        // LWW (provenance).
        source_span: prefer_non_null_else_lww(
            local,
            remote,
            &local.source_span,
            &remote.source_span,
        ),
        // #224: confidence_source not in design table — LWW per table
        // philosophy (follows the confidence write).
        confidence_source: lww(
            local,
            remote,
            &local.confidence_source,
            &remote.confidence_source,
        ),
        // #224: confidence_signals not in design table — prefer non-null,
        // else LWW (follows the confidence write).
        confidence_signals: prefer_non_null_else_lww(
            local,
            remote,
            &local.confidence_signals,
            &remote.confidence_signals,
        ),
        // #224: confidence_decayed_at not in design table — prefer
        // non-null, else LWW (follows the confidence write).
        confidence_decayed_at: prefer_non_null_else_lww(
            local,
            remote,
            &local.confidence_decayed_at,
            &remote.confidence_decayed_at,
        ),
        // #224: version not in design table — max (PN-Counter; monotonic
        // optimistic-concurrency counter; never roll backwards).
        version: merge_counter(local.version, remote.version),
        // #224: lifecycle_state not in design table — LWW per table
        // philosophy (a conscious state transition, like memory_kind).
        lifecycle_state: lww(
            local,
            remote,
            &local.lifecycle_state,
            &remote.lifecycle_state,
        ),
    }
}

/// `max` of two RFC3339-string `Option`s with absence as the floor: a
/// present value beats `None`, and on both-present the lexically-greater
/// (later) stamp wins. Used for `last_accessed_at`.
fn max_opt_string(local: &Option<String>, remote: &Option<String>) -> Option<String> {
    match (local, remote) {
        (Some(l), Some(r)) => {
            if r > l {
                Some(r.clone())
            } else {
                Some(l.clone())
            }
        }
        (Some(l), None) => Some(l.clone()),
        (None, Some(r)) => Some(r.clone()),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::memory::{ConfidenceSource, LifecycleState, MemoryKind, SourceSpan, Tier};
    use serde_json::json;

    /// A baseline row. `updated_at` / `id` are set so callers can shape
    /// the LWW order deterministically.
    fn base(id: &str, updated_at: &str) -> Memory {
        Memory {
            id: id.to_string(),
            tier: Tier::Short,
            namespace: "ns".to_string(),
            title: "t".to_string(),
            content: "c".to_string(),
            tags: vec![],
            priority: 1,
            confidence: 0.1,
            source: "user".to_string(),
            access_count: 0,
            created_at: "2026-06-16T00:00:00+00:00".to_string(),
            updated_at: updated_at.to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata: json!({}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: vec![],
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: LifecycleState::Open,
        }
    }

    /// Serialise to a JSON value for equality comparison (Memory has no
    /// PartialEq derive).
    fn as_json(m: &Memory) -> Value {
        serde_json::to_value(m).expect("Memory serialises")
    }

    #[test]
    fn merge_memory_tags_union_dedup_both_survive() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.tags = vec!["x".into(), "shared".into()];
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.tags = vec!["shared".into(), "y".into()];

        let merged = merge_memory(&local, &remote);
        // Both agents' tags survive; "shared" deduped once.
        assert_eq!(merged.tags, vec!["x", "shared", "y"]);
    }

    #[test]
    fn merge_memory_priority_max() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.priority = 3;
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.priority = 9;
        assert_eq!(merge_memory(&local, &remote).priority, 9);
        // Order-independent.
        assert_eq!(merge_memory(&remote, &local).priority, 9);
    }

    #[test]
    fn merge_memory_confidence_max() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.confidence = 0.2;
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.confidence = 0.8;
        assert!((merge_memory(&local, &remote).confidence - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn merge_memory_access_count_max() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.access_count = 40;
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.access_count = 7;
        assert_eq!(merge_memory(&local, &remote).access_count, 40);
    }

    #[test]
    fn merge_memory_created_at_min() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.created_at = "2026-06-16T05:00:00+00:00".into();
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.created_at = "2026-06-16T01:00:00+00:00".into();
        // Earliest creation wins.
        assert_eq!(
            merge_memory(&local, &remote).created_at,
            "2026-06-16T01:00:00+00:00"
        );
    }

    #[test]
    fn merge_memory_updated_at_max() {
        let local = base("a", "2026-06-16T00:00:00+00:00");
        let remote = base("a", "2026-06-16T09:00:00+00:00");
        assert_eq!(
            merge_memory(&local, &remote).updated_at,
            "2026-06-16T09:00:00+00:00"
        );
    }

    #[test]
    fn merge_memory_expires_at_null_wins_over_date() {
        // local has an expiry, remote is immortal (null) ⇒ null wins.
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.expires_at = Some("2026-06-17T00:00:00+00:00".into());
        let remote = base("a", "2026-06-16T00:00:01+00:00"); // expires_at None
        assert_eq!(merge_memory(&local, &remote).expires_at, None);
        // Commutative.
        assert_eq!(merge_memory(&remote, &local).expires_at, None);
    }

    #[test]
    fn merge_memory_expires_at_max_when_both_present() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.expires_at = Some("2026-06-17T00:00:00+00:00".into());
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.expires_at = Some("2026-06-20T00:00:00+00:00".into());
        // Later expiry wins.
        assert_eq!(
            merge_memory(&local, &remote).expires_at,
            Some("2026-06-20T00:00:00+00:00".into())
        );
    }

    #[test]
    fn merge_memory_tier_max_durability() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.tier = Tier::Mid;
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.tier = Tier::Long;
        assert_eq!(merge_memory(&local, &remote).tier, Tier::Long);
        // Never downgrade: long + short ⇒ long.
        let mut s = base("a", "2026-06-16T00:00:02+00:00");
        s.tier = Tier::Short;
        let mut l = base("a", "2026-06-16T00:00:00+00:00");
        l.tier = Tier::Long;
        assert_eq!(merge_memory(&s, &l).tier, Tier::Long);
    }

    #[test]
    fn merge_memory_lww_newer_updated_at_wins() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.title = "old".into();
        local.content = "old-c".into();
        local.namespace = "old-ns".into();
        local.memory_kind = MemoryKind::Observation;
        local.lifecycle_state = LifecycleState::Open;

        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.title = "new".into();
        remote.content = "new-c".into();
        remote.namespace = "new-ns".into();
        remote.memory_kind = MemoryKind::Decision;
        remote.lifecycle_state = LifecycleState::Done;

        let merged = merge_memory(&local, &remote);
        assert_eq!(merged.title, "new");
        assert_eq!(merged.content, "new-c");
        assert_eq!(merged.namespace, "new-ns");
        assert_eq!(merged.memory_kind, MemoryKind::Decision);
        assert_eq!(merged.lifecycle_state, LifecycleState::Done);
    }

    #[test]
    fn merge_memory_lww_tie_breaks_on_id_deterministically() {
        // Same updated_at; the lexically-greater id wins the tiebreak.
        let mut low = base("a", "2026-06-16T00:00:00+00:00");
        low.title = "from-a".into();
        let mut high = base("b", "2026-06-16T00:00:00+00:00");
        high.title = "from-b".into();
        // Note: id mismatch would trip the debug_assert; for this test we
        // deliberately use distinct ids to exercise the tiebreak, and the
        // assertion is only that the (updated_at, id)-maximal side wins.
        // `b` > `a`, so "from-b" wins regardless of argument order.
        assert_eq!(merge_lww_title(&low, &high), "from-b");
        assert_eq!(merge_lww_title(&high, &low), "from-b");
    }

    /// Helper exercising only the LWW title pick (bypasses the
    /// same-id debug_assert so the id tiebreak can be tested directly).
    fn merge_lww_title(a: &Memory, b: &Memory) -> String {
        lww(a, b, &a.title, &b.title)
    }

    #[test]
    fn merge_memory_metadata_deep_merge_disjoint_keys_both_survive() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.metadata = json!({"k_local": 1, "nested": {"x": 1}});
        let mut remote = base("a", "2026-06-16T00:00:01+00:00");
        remote.metadata = json!({"k_remote": 2, "nested": {"y": 2}});

        let merged = merge_memory(&local, &remote);
        assert_eq!(merged.metadata["k_local"], json!(1));
        assert_eq!(merged.metadata["k_remote"], json!(2));
        // Nested object merged key-wise.
        assert_eq!(merged.metadata["nested"]["x"], json!(1));
        assert_eq!(merged.metadata["nested"]["y"], json!(2));
    }

    #[test]
    fn merge_memory_metadata_agent_id_immutable_local_wins() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.metadata = json!({"agent_id": "original-owner"});
        // Remote is NEWER and tries to rewrite agent_id.
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.metadata = json!({"agent_id": "peer-impostor"});

        let merged = merge_memory(&local, &remote);
        // Provenance is write-once: local's original agent_id survives
        // even though remote is the newer (LWW) side.
        assert_eq!(merged.metadata["agent_id"], json!("original-owner"));
    }

    #[test]
    fn merge_memory_metadata_scope_lww() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.metadata = json!({"scope": "private"});
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.metadata = json!({"scope": "collective"});
        // Remote newer ⇒ its scope wins.
        assert_eq!(
            merge_memory(&local, &remote).metadata["scope"],
            json!("collective")
        );
        // Local newer ⇒ local scope wins.
        let mut local2 = base("a", "2026-06-16T10:00:00+00:00");
        local2.metadata = json!({"scope": "private"});
        let mut remote2 = base("a", "2026-06-16T01:00:00+00:00");
        remote2.metadata = json!({"scope": "collective"});
        assert_eq!(
            merge_memory(&local2, &remote2).metadata["scope"],
            json!("private")
        );
    }

    #[test]
    fn merge_memory_metadata_governance_keeps_local() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.metadata = json!({"governance": {"write": "owner"}});
        // Remote newer, tries to weaken governance.
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.metadata = json!({"governance": {"write": "any"}});
        let merged = merge_memory(&local, &remote);
        // A merge must not let a peer rewrite governance.
        assert_eq!(merged.metadata["governance"], json!({"write": "owner"}));
    }

    #[test]
    fn merge_memory_version_max() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.version = 7;
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.version = 3;
        // Even though remote is newer by updated_at, version takes max so
        // the optimistic-concurrency counter never rolls backwards.
        assert_eq!(merge_memory(&local, &remote).version, 7);
    }

    #[test]
    fn merge_memory_reflection_depth_max() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.reflection_depth = 4;
        let mut remote = base("a", "2026-06-16T09:00:00+00:00");
        remote.reflection_depth = 1;
        assert_eq!(merge_memory(&local, &remote).reflection_depth, 4);
    }

    #[test]
    fn merge_memory_prefer_non_null_fields() {
        // local has the values, remote has None ⇒ values preserved.
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.entity_id = Some("ent-1".into());
        local.source_uri = Some("uri:doc".into());
        local.source_span = Some(SourceSpan { start: 0, end: 5 });
        local.persona_version = Some(2);
        local.confidence_decayed_at = Some("2026-06-16T00:00:00+00:00".into());

        // Remote NEWER but all None — prefer-non-null keeps local's values.
        let remote = base("a", "2026-06-16T09:00:00+00:00");

        let merged = merge_memory(&local, &remote);
        assert_eq!(merged.entity_id, Some("ent-1".into()));
        assert_eq!(merged.source_uri, Some("uri:doc".into()));
        assert_eq!(merged.source_span, Some(SourceSpan { start: 0, end: 5 }));
        assert_eq!(merged.persona_version, Some(2));
        assert_eq!(
            merged.confidence_decayed_at,
            Some("2026-06-16T00:00:00+00:00".into())
        );

        // And the symmetric case: None local + Some remote ⇒ value.
        let local_none = base("a", "2026-06-16T00:00:00+00:00");
        let mut remote_val = base("a", "2026-06-16T00:00:01+00:00");
        remote_val.entity_id = Some("ent-2".into());
        assert_eq!(
            merge_memory(&local_none, &remote_val).entity_id,
            Some("ent-2".into())
        );
    }

    #[test]
    fn merge_memory_last_accessed_at_max_with_null_floor() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.last_accessed_at = Some("2026-06-16T03:00:00+00:00".into());
        let remote = base("a", "2026-06-16T00:00:01+00:00"); // None
        // Present beats None.
        assert_eq!(
            merge_memory(&local, &remote).last_accessed_at,
            Some("2026-06-16T03:00:00+00:00".into())
        );
        // Both present ⇒ later wins.
        let mut local2 = base("a", "2026-06-16T00:00:00+00:00");
        local2.last_accessed_at = Some("2026-06-16T03:00:00+00:00".into());
        let mut remote2 = base("a", "2026-06-16T00:00:01+00:00");
        remote2.last_accessed_at = Some("2026-06-16T08:00:00+00:00".into());
        assert_eq!(
            merge_memory(&local2, &remote2).last_accessed_at,
            Some("2026-06-16T08:00:00+00:00".into())
        );
    }

    #[test]
    fn merge_memory_citations_prefer_non_empty() {
        let mut local = base("a", "2026-06-16T00:00:00+00:00");
        local.citations = vec![crate::models::memory::Citation {
            uri: "uri:a".into(),
            accessed_at: "2026-06-16T00:00:00+00:00".into(),
            hash: None,
            span: None,
        }];
        // Remote newer but empty citations — provenance preserved.
        let remote = base("a", "2026-06-16T09:00:00+00:00");
        assert_eq!(merge_memory(&local, &remote).citations.len(), 1);
    }

    #[test]
    fn merge_memory_is_idempotent() {
        // A richly-populated row merged with itself is unchanged.
        let mut m = base("a", "2026-06-16T05:00:00+00:00");
        m.tier = Tier::Mid;
        m.tags = vec!["x".into(), "y".into()];
        m.priority = 5;
        m.confidence = 0.6;
        m.access_count = 12;
        m.expires_at = Some("2026-06-20T00:00:00+00:00".into());
        m.last_accessed_at = Some("2026-06-17T00:00:00+00:00".into());
        m.metadata = json!({"agent_id": "owner", "scope": "private", "k": {"n": 1}});
        m.reflection_depth = 2;
        m.memory_kind = MemoryKind::Reflection;
        m.entity_id = Some("e".into());
        m.version = 9;
        m.lifecycle_state = LifecycleState::Active;

        let merged = merge_memory(&m, &m);
        assert_eq!(as_json(&merged), as_json(&m));
    }

    #[test]
    fn merge_memory_is_commutative() {
        // Build two divergent rows; merge(a,b) and merge(b,a) must agree.
        //
        // DESIGN NOTE — the two "keep-local" metadata sub-rules
        // (`agent_id` immutable→local, `governance`→local) are
        // INTENTIONALLY order-sensitive: they bias toward whichever
        // operand is passed as `local`, so they are commutative ONLY when
        // both replicas already agree on the value. That is the realistic
        // case for a same-`id` row (both replicas descend from the same
        // original author / owner-set governance), so this test gives both
        // rows the SAME `agent_id` and NO `governance` key. Every other
        // field resolves through a symmetric rule (max / min / union /
        // (updated_at,id)-total-order LWW / scope-LWW / prefer-non-null)
        // and therefore must be byte-identical regardless of argument
        // order — which this test asserts on the whole row.
        let mut local = base("a", "2026-06-16T02:00:00+00:00");
        local.tier = Tier::Mid;
        local.tags = vec!["x".into(), "shared".into()];
        local.priority = 3;
        local.confidence = 0.4;
        local.access_count = 20;
        local.created_at = "2026-06-16T00:00:00+00:00".into();
        local.expires_at = Some("2026-06-18T00:00:00+00:00".into());
        local.last_accessed_at = Some("2026-06-16T01:00:00+00:00".into());
        local.metadata =
            json!({"agent_id": "owner", "scope": "private", "k_local": 1, "nested": {"x": 1}});
        local.reflection_depth = 1;
        local.version = 5;
        local.entity_id = Some("ent-local".into());

        let mut remote = base("a", "2026-06-16T08:00:00+00:00");
        remote.tier = Tier::Long;
        remote.tags = vec!["shared".into(), "y".into()];
        remote.priority = 9;
        remote.confidence = 0.7;
        remote.access_count = 5;
        remote.created_at = "2026-06-16T03:00:00+00:00".into();
        remote.expires_at = Some("2026-06-25T00:00:00+00:00".into());
        remote.last_accessed_at = Some("2026-06-16T07:00:00+00:00".into());
        remote.metadata =
            json!({"agent_id": "owner", "scope": "collective", "k_remote": 2, "nested": {"y": 2}});
        remote.reflection_depth = 3;
        remote.version = 2;
        remote.title = "remote-title".into();

        let ab = merge_memory(&local, &remote);
        let ba = merge_memory(&remote, &local);

        // Tags: compare as a set (surface order is local-first by design,
        // which differs by argument; membership must match).
        let mut ab_tags = ab.tags.clone();
        let mut ba_tags = ba.tags.clone();
        ab_tags.sort();
        ba_tags.sort();
        assert_eq!(ab_tags, ba_tags);

        // Everything else (the commutative + LWW-total-order fields)
        // must be byte-identical regardless of argument order.
        let mut ab_json = as_json(&ab);
        let mut ba_json = as_json(&ba);
        // Normalise tags ordering inside the JSON for the whole-row compare.
        ab_json["tags"] = json!(ab_tags);
        ba_json["tags"] = json!(ba_tags);
        assert_eq!(ab_json, ba_json);
    }

    #[test]
    fn merge_memory_is_associative_on_max_min_union_fields() {
        // (a ∘ b) ∘ c == a ∘ (b ∘ c) for the convergent fields.
        let mut a = base("a", "2026-06-16T01:00:00+00:00");
        a.priority = 2;
        a.access_count = 3;
        a.version = 1;
        a.tags = vec!["a".into()];
        a.created_at = "2026-06-16T02:00:00+00:00".into();

        let mut b = base("a", "2026-06-16T05:00:00+00:00");
        b.priority = 8;
        b.access_count = 1;
        b.version = 4;
        b.tags = vec!["b".into()];
        b.created_at = "2026-06-16T00:00:00+00:00".into();

        let mut c = base("a", "2026-06-16T09:00:00+00:00");
        c.priority = 5;
        c.access_count = 9;
        c.version = 2;
        c.tags = vec!["c".into()];
        c.created_at = "2026-06-16T01:00:00+00:00".into();

        let left = merge_memory(&merge_memory(&a, &b), &c);
        let right = merge_memory(&a, &merge_memory(&b, &c));

        assert_eq!(left.priority, right.priority);
        assert_eq!(left.priority, 8);
        assert_eq!(left.access_count, right.access_count);
        assert_eq!(left.access_count, 9);
        assert_eq!(left.version, right.version);
        assert_eq!(left.version, 4);
        assert_eq!(left.created_at, right.created_at);
        assert_eq!(left.created_at, "2026-06-16T00:00:00+00:00");

        let mut lt = left.tags.clone();
        let mut rt = right.tags.clone();
        lt.sort();
        rt.sort();
        assert_eq!(lt, rt);
        assert_eq!(lt, vec!["a", "b", "c"]);
    }
}
