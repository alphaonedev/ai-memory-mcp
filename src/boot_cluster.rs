// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3352 — cluster near-duplicate memories in boot / session_start payloads.
//!
//! `ai-memory boot --limit 10` and `memory_session_start` previously listed
//! the N most-recently-updated rows verbatim. Repeated stores of the same
//! fact (different titles, minutes apart) filled the slot budget, so a
//! 10-line payload carried ~5 distinct facts. This module collapses a
//! fetched window into similarity clusters, keeps the newest /
//! highest-priority representative, and annotates `similar_count` so the
//! caller can see that N near-duplicates were folded in.
//!
//! Clustering is **display-only**. It never deletes, merges, or rewrites
//! stored rows (unlike curator consolidation, which requires Jaccard AND
//! cosine and is destructive). Un-embedded corpora still cluster on
//! lexical Jaccard of `title + content` so keyword-tier boot works
//! without loading an embedder.

use crate::curator::cluster::jaccard_similarity;
use crate::embeddings::Embedder;
use crate::models::Memory;
use crate::models::field_names;
use crate::storage::DUPLICATE_THRESHOLD_DEFAULT;
use serde_json::{Value, json};
use std::cmp::Ordering;

/// Hard cap on boot / session_start list windows. Matches the historical
/// `limit.clamp(1, 50)` / `limit.min(50)` on both surfaces.
pub const BOOT_PAYLOAD_LIST_CAP: usize = 50;

/// Over-fetch multiplier so clustering can fill a `--limit` budget with
/// distinct facts after collapsing near-duplicates. `limit=10` → fetch 50
/// (the list cap); `limit=50` → fetch 50 (no extra rows exist in-window).
pub const BOOT_CLUSTER_OVERFETCH_FACTOR: usize = 5;

/// Lexical Jaccard gate for un-embedded (or mixed-space) pairs.
///
/// Slightly below [`DUPLICATE_THRESHOLD_DEFAULT`] (0.85, the
/// `check-duplicate` cosine default) because near-duplicate stores of the
/// same fact often vary the title while keeping the body. 0.70 still
/// rejects distinct topics. Cosine, when both sides carry a comparable
/// vector, uses [`DUPLICATE_THRESHOLD_DEFAULT`] so the boot cluster agrees
/// with `check-duplicate` on an embedded corpus.
pub const BOOT_CLUSTER_JACCARD_THRESHOLD: f64 = 0.70;

/// Lexical clustering is skipped when either `title + content` is shorter
/// than this. Two-token fixtures (`"body for a"` vs `"body for b"`) have
/// Jaccard 1.0 but are not the same fact; the #3352 signal is long,
/// near-duplicate bodies. Cosine can still cluster short rows.
pub const BOOT_CLUSTER_MIN_LEXICAL_CHARS: usize = 64;

/// One payload row after clustering.
#[derive(Debug, Clone)]
pub struct ClusteredMemory {
    /// Newest / highest-priority member of the cluster.
    pub memory: Memory,
    /// Other near-duplicates folded into this representative
    /// (`cluster_len - 1`). Zero when the row is a singleton.
    pub similar_count: usize,
}

/// Window size to fetch before clustering so a `limit`-slot budget can
/// be filled with distinct facts.
#[must_use]
pub fn overfetch_limit(limit: usize) -> usize {
    let cap = limit.min(BOOT_PAYLOAD_LIST_CAP);
    let wanted = cap.saturating_mul(BOOT_CLUSTER_OVERFETCH_FACTOR);
    wanted.clamp(cap, BOOT_PAYLOAD_LIST_CAP)
}

/// Collapse `memories` into at most `limit` representatives.
///
/// `embeddings`, when present, must be aligned 1:1 with `memories`. A
/// pair clusters when:
/// - both vectors are `Some`, same dimension, and cosine ≥
///   [`DUPLICATE_THRESHOLD_DEFAULT`], OR
/// - lexical Jaccard(`title + content`) ≥ [`BOOT_CLUSTER_JACCARD_THRESHOLD`].
///
/// Representatives are chosen by higher `priority`, then newer
/// `updated_at`, then newer `created_at`, then stable `id` (API-29 total
/// order; timestamp parse failures fall back to the RFC3339 string).
#[must_use]
pub fn cluster_payload(
    memories: Vec<Memory>,
    limit: usize,
    embeddings: Option<&[Option<Vec<f32>>]>,
) -> Vec<ClusteredMemory> {
    let limit = limit.min(BOOT_PAYLOAD_LIST_CAP);
    if limit == 0 || memories.is_empty() {
        return Vec::new();
    }
    let n = memories.len();
    let embeddings = embeddings.filter(|e| e.len() == n);

    let texts: Vec<String> = memories
        .iter()
        .map(|m| {
            let mut t = String::with_capacity(m.title.len() + m.content.len() + 1);
            t.push_str(&m.title);
            t.push(' ');
            t.push_str(&m.content);
            t
        })
        .collect();

    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&i, &j| compare_representative(&memories[i], &memories[j]));

    let mut slots: Vec<Option<Memory>> = memories.into_iter().map(Some).collect();
    let mut used = vec![false; n];
    let mut out = Vec::with_capacity(limit.min(n));

    for &i in &order {
        if used[i] {
            continue;
        }
        if out.len() >= limit {
            break;
        }
        used[i] = true;
        let Some(rep) = slots[i].take() else {
            continue;
        };
        let mut similar_count = 0usize;
        for &j in &order {
            if used[j] {
                continue;
            }
            // Never fold across namespaces (curator cluster is the same
            // isolation). A session_start with no namespace filter must
            // still surface one representative per project.
            let same_ns = slots[j]
                .as_ref()
                .is_some_and(|other| other.namespace == rep.namespace);
            if same_ns && pair_similar(i, j, &texts, embeddings) {
                used[j] = true;
                slots[j] = None;
                similar_count = similar_count.saturating_add(1);
            }
        }
        out.push(ClusteredMemory {
            memory: rep,
            similar_count,
        });
    }
    out
}

/// Serialize a memory for a boot / session_start JSON payload, stamping
/// [`field_names::SIMILAR_COUNT`] only when the cluster is not a singleton.
#[must_use]
pub fn memory_json_with_similar(memory: &Memory, similar_count: usize) -> Value {
    match serde_json::to_value(memory) {
        Ok(mut value) => {
            if similar_count > 0
                && let Some(obj) = value.as_object_mut()
            {
                obj.insert(field_names::SIMILAR_COUNT.to_string(), json!(similar_count));
            }
            value
        }
        Err(_) => {
            // `Memory: Serialize` — failure is a programmer bug. Boot /
            // session_start must still return *something* rather than
            // panic on the agent's first turn (ERRORS-06).
            let mut fallback = json!({
                "id": memory.id,
                "title": memory.title,
                "namespace": memory.namespace,
                "priority": memory.priority,
            });
            if similar_count > 0
                && let Some(obj) = fallback.as_object_mut()
            {
                obj.insert(field_names::SIMILAR_COUNT.to_string(), json!(similar_count));
            }
            fallback
        }
    }
}

fn pair_similar(
    i: usize,
    j: usize,
    texts: &[String],
    embeddings: Option<&[Option<Vec<f32>>]>,
) -> bool {
    if let Some(embs) = embeddings
        && let (Some(a), Some(b)) = (embs[i].as_ref(), embs[j].as_ref())
        && a.len() == b.len()
    {
        let cos = Embedder::cosine_similarity(a, b);
        if cos.is_finite() && cos >= DUPLICATE_THRESHOLD_DEFAULT {
            return true;
        }
    }
    if texts[i].len() < BOOT_CLUSTER_MIN_LEXICAL_CHARS
        || texts[j].len() < BOOT_CLUSTER_MIN_LEXICAL_CHARS
    {
        return false;
    }
    jaccard_similarity(&texts[i], &texts[j]) >= BOOT_CLUSTER_JACCARD_THRESHOLD
}

/// Higher priority, then newer updated_at, then newer created_at, then id.
fn compare_representative(a: &Memory, b: &Memory) -> Ordering {
    b.priority
        .cmp(&a.priority)
        .then_with(|| cmp_recency(&b.updated_at, &a.updated_at))
        .then_with(|| cmp_recency(&b.created_at, &a.created_at))
        .then_with(|| a.id.cmp(&b.id))
}

fn cmp_recency(a: &str, b: &str) -> Ordering {
    match (parse_ts(a), parse_ts(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => a.cmp(b),
    }
}

fn parse_ts(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DUP_BODY: &str = "The Grok A2A channel wiring check requires the inbox \
poller to sort messages by created_at rather than priority so that P10 crowding \
cannot hide a P9 mail about the same channel fact.";

    fn mem(title: &str, content: &str, priority: i32, updated_at: &str, id: &str) -> Memory {
        serde_json::from_value(json!({
            "id": id,
            "tier": "mid",
            "namespace": "ns",
            "title": title,
            "content": content,
            "tags": [],
            "priority": priority,
            "confidence": 1.0,
            "source": "test",
            "access_count": 0,
            "created_at": updated_at,
            "updated_at": updated_at,
            "metadata": {},
        }))
        .expect("Memory fixture")
    }

    #[test]
    fn five_near_dupes_plus_five_distinct_yields_six() {
        let mut rows = Vec::with_capacity(10);
        for i in 1..=5 {
            rows.push(mem(
                &format!("Grok A2A channel wiring {i}"),
                DUP_BODY,
                5,
                "2026-09-02T12:00:00Z",
                &format!("dup-{i}"),
            ));
        }
        let distinct = [
            (
                "Rust ownership aliasing",
                "OWNERSHIP-10 many shared references xor one exclusive mutable borrow.",
            ),
            (
                "Postgres pool sizing",
                "Read-path GET links p95 dropped after the handler stopped taking the writer lock.",
            ),
            (
                "Schema ladder v96",
                "embed_skip durable skip markers land as sqlite 0080 and postgres 0053 after v95.",
            ),
            (
                "TLS listener 9077",
                "Do not restart the live mTLS endpoint; tests must never point at production PG 5445.",
            ),
            (
                "Cargo slot flock",
                "Wrap every clippy and test invocation in cargo-slot.sh with CARGO_BUILD_JOBS=4.",
            ),
        ];
        for (i, (title, content)) in distinct.iter().enumerate() {
            rows.push(mem(
                title,
                content,
                5,
                "2026-09-02T12:00:00Z",
                &format!("dist-{i}"),
            ));
        }
        let clustered = cluster_payload(rows, 10, None);
        assert_eq!(
            clustered.len(),
            6,
            "5 near-dupes + 5 distinct must occupy 6 slots, got {:?}",
            clustered
                .iter()
                .map(|c| (&c.memory.title, c.similar_count))
                .collect::<Vec<_>>()
        );
        let similar_marked = clustered.iter().filter(|c| c.similar_count > 0).count();
        assert_eq!(similar_marked, 1);
        assert_eq!(
            clustered
                .iter()
                .find(|c| c.similar_count > 0)
                .map(|c| c.similar_count),
            Some(4)
        );
    }

    #[test]
    fn higher_priority_wins_over_newer() {
        let older_high = mem(
            "Grok A2A channel wiring high",
            DUP_BODY,
            10,
            "2026-09-01T00:00:00Z",
            "old-high",
        );
        let newer_low = mem(
            "Grok A2A channel wiring low",
            DUP_BODY,
            3,
            "2026-09-02T00:00:00Z",
            "new-low",
        );
        let clustered = cluster_payload(vec![newer_low, older_high], 10, None);
        assert_eq!(clustered.len(), 1);
        assert_eq!(clustered[0].memory.id, "old-high");
        assert_eq!(clustered[0].similar_count, 1);
    }

    #[test]
    fn newer_wins_when_priority_ties() {
        let older = mem(
            "Grok A2A channel wiring old",
            DUP_BODY,
            5,
            "2026-09-01T00:00:00Z",
            "older",
        );
        let newer = mem(
            "Grok A2A channel wiring new",
            DUP_BODY,
            5,
            "2026-09-02T00:00:00Z",
            "newer",
        );
        let clustered = cluster_payload(vec![older, newer], 10, None);
        assert_eq!(clustered.len(), 1);
        assert_eq!(clustered[0].memory.id, "newer");
        assert_eq!(clustered[0].similar_count, 1);
    }

    #[test]
    fn cosine_above_duplicate_threshold_clusters_without_lexical_overlap() {
        // Paraphrases share no ≥3-char tokens, so Jaccard is 0; cosine at
        // the check-duplicate default still clusters them (the signal the
        // issue cited).
        let a = mem(
            "alpha unique zebra",
            "qqq xxx yyy",
            5,
            "2026-09-02T00:00:00Z",
            "a",
        );
        let b = mem(
            "beta distinct yak",
            "www uuu vvv",
            5,
            "2026-09-02T00:00:00Z",
            "b",
        );
        assert!(
            jaccard_similarity(
                "alpha unique zebra qqq xxx yyy",
                "beta distinct yak www uuu vvv"
            ) < BOOT_CLUSTER_JACCARD_THRESHOLD
        );
        let v = vec![1.0f32, 0.0, 0.0, 0.0];
        let clustered = cluster_payload(vec![a, b], 10, Some(&[Some(v.clone()), Some(v)]));
        assert_eq!(clustered.len(), 1);
        assert_eq!(clustered[0].similar_count, 1);
    }

    #[test]
    fn short_bodies_do_not_lexical_cluster() {
        let a = mem("a", "body for a", 5, "2026-09-02T00:00:00Z", "a");
        let b = mem("b", "body for b", 5, "2026-09-02T00:00:00Z", "b");
        let clustered = cluster_payload(vec![a, b], 10, None);
        assert_eq!(clustered.len(), 2);
    }

    #[test]
    fn different_namespaces_do_not_cluster() {
        let mut a = mem(
            "Grok A2A channel wiring a",
            DUP_BODY,
            5,
            "2026-09-02T00:00:00Z",
            "a",
        );
        let mut b = mem(
            "Grok A2A channel wiring b",
            DUP_BODY,
            5,
            "2026-09-02T00:00:00Z",
            "b",
        );
        a.namespace = "ns-a".to_string();
        b.namespace = "ns-b".to_string();
        let clustered = cluster_payload(vec![a, b], 10, None);
        assert_eq!(clustered.len(), 2);
    }

    #[test]
    fn empty_and_zero_limit() {
        assert!(cluster_payload(Vec::new(), 10, None).is_empty());
        let one = mem("t", "c", 1, "2026-09-02T00:00:00Z", "id");
        assert!(cluster_payload(vec![one], 0, None).is_empty());
    }

    #[test]
    fn overfetch_clamps_to_list_cap() {
        assert_eq!(overfetch_limit(10), BOOT_PAYLOAD_LIST_CAP);
        assert_eq!(overfetch_limit(50), BOOT_PAYLOAD_LIST_CAP);
        assert_eq!(overfetch_limit(1), BOOT_CLUSTER_OVERFETCH_FACTOR);
        assert_eq!(overfetch_limit(0), 0);
        assert_eq!(overfetch_limit(10_000), BOOT_PAYLOAD_LIST_CAP);
    }

    #[test]
    fn json_omits_similar_count_on_singleton() {
        let m = mem("t", "c", 1, "2026-09-02T00:00:00Z", "id");
        let v = memory_json_with_similar(&m, 0);
        assert!(v.get(field_names::SIMILAR_COUNT).is_none());
        let v = memory_json_with_similar(&m, 4);
        assert_eq!(v[field_names::SIMILAR_COUNT], 4);
    }
}
