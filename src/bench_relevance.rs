// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! L10 (Wave-2) — relevance-at-scale measurement apparatus.
//!
//! # What this measures, and why it is separate from `bench.rs`
//!
//! `src/bench.rs` measures LATENCY at scale (`--scale`, up to 1M rows):
//! p50/p95/p99 against the `PERFORMANCE.md` budgets. What it deliberately
//! does NOT measure is RANKING QUALITY — whether the frecency/priority
//! recall scorer surfaces the truly-relevant rows or drowns them in
//! high-traffic noise as the corpus grows. That is the L10 gap this
//! module closes: an ATTESTED relevance-at-scale harness that runs the
//! real recall pipeline over a SYNTHETIC LABELED corpus and reports
//! `precision@k`, `nDCG@k`, and a frecency-noise contamination rate per
//! corpus scale (10^3 -> 10^6).
//!
//! This is MEASUREMENT APPARATUS. It changes NO production recall
//! scoring — it only exercises [`crate::db::recall`] and scores the
//! ranking it returns against a known ground truth. If the harness
//! reveals that frecency drowns signal, the scorer fix is a SEPARATE,
//! downstream, voted change — this module just reports the finding.
//!
//! # RFC-lite: metric + corpus-design rationale (design decision, recorded inline)
//!
//! **Metric choice — `precision@k` + `nDCG@k`.** These are the two
//! standard, complementary ranking-quality metrics from the IR
//! literature, and they answer different halves of the L10 question:
//!
//! - `precision@k` = (relevant rows in the top-`k`) / `k`. A blunt,
//!   position-insensitive "how much of the top of the list is signal?"
//!   It falls immediately when noise displaces relevant rows out of the
//!   top-`k` — the exact failure the access-count cap exists to prevent.
//! - `nDCG@k` (binary gains, log2 discount) adds POSITION sensitivity:
//!   a relevant row demoted from rank 1 to rank 9 still counts for
//!   `precision@k` but costs `nDCG@k`. It is normalised to `[0, 1]`
//!   against the ideal ordering, so it is comparable across scales even
//!   when the number of relevant rows differs.
//!
//! Together they distinguish "signal fell out of the top-`k` entirely"
//! (precision drops) from "signal is still present but demoted below
//! the noise" (nDCG drops first). A third reported number — the
//! **contamination rate** (designated high-traffic noise rows in the
//! top-`k`, over `k`) — makes the mechanism visible directly: it is the
//! share of the top-`k` occupied by the popular-but-irrelevant rows a
//! naive frecency-heavy ranker floats up.
//!
//! **Labeled-corpus methodology.** For each of [`NUM_PROBE_CLUSTERS`]
//! probe queries we seed:
//!
//! - a FIXED small set of [`SIGNAL_ROWS_PER_CLUSTER`] SIGNAL rows — the
//!   ground-truth relevant answers. Each carries BOTH the cluster's
//!   distinctive token and its common token, so it is the strongest FTS
//!   match, but it is deliberately LOW-traffic (priority
//!   [`SIGNAL_PRIORITY`], `access_count` 0), so it earns its rank on
//!   textual relevance alone.
//! - a set of NOISE rows scaled as [`NOISE_CORPUS_FRACTION`] of the
//!   corpus and distributed across clusters. Each carries ONLY the
//!   cluster's common token (a weaker, single-term FTS match) but is
//!   HIGH-traffic (priority [`NOISE_PRIORITY`], `access_count`
//!   [`NOISE_ACCESS_COUNT`], long tier) — precisely the "popular content"
//!   frecency would float to the top. Scaling noise with the corpus is
//!   what makes the "as noise accumulates" question real: at 10^3 a
//!   cluster has a handful of distractors; at 10^5 it has hundreds, so
//!   whether the fixed signal set survives the top-`k` becomes a genuine
//!   contest.
//! - FILLER rows for the remainder of the corpus (no cluster tokens, so
//!   they never enter a probe's candidate pool but do grow the table).
//!
//! The probe query is `"<signal-token> <common-token>"`. Both signal and
//! noise rows enter the FTS OR-candidate pool; the ranker then decides
//! ordering by blending the FTS rank with the frecency/priority terms.
//! Ground truth is by DESIGN (the labeled signal set), not by term
//! presence, so the metric is a real test of the scorer, not a tautology.
//!
//! **Precedent.** `bench.rs` is the precedent for a synthetic-corpus,
//! in-process, disposable-`SQLite` bench sub-mode; this module follows
//! its shape (deterministic seeding, `:memory:` DB, a render table). No
//! second mutually-exclusive corpus design without precedent arose, so
//! per the crossroads protocol T6 this is decide-and-build, vote-exempt
//! (additive measurement, no wire/posture/representation change).
//!
//! **Determinism.** Row content, roles, priorities, and ids are all
//! INDEX-DERIVED (no `rand`, no `Date::now` — every timestamp is the
//! fixed [`RELEVANCE_FIXED_CREATED_AT`]), so a run is reproducible and
//! score ties break deterministically.
//!
//! **Honest scope.** In the CLI/`cargo` process there is no embedder, so
//! the recall pipeline runs its FTS + frecency blend (the semantic
//! cosine phase is inert). That is exactly the surface the L10 question
//! targets — the frecency/priority terms are what can drown signal — so
//! the measurement is faithful to the phenomenon under test. When an
//! embedder is configured the same harness additionally exercises the
//! semantic phase, with no code change.

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;

use crate::db;
use crate::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};

/// Default top-`k` cutoff for `precision@k` / `nDCG@k` / contamination.
pub const DEFAULT_RELEVANCE_K: usize = 10;

/// Number of probe queries (semantic clusters) in the labeled corpus.
/// Each cluster contributes one probe; the reported metrics are the mean
/// across all probes.
pub const NUM_PROBE_CLUSTERS: usize = 20;

/// Fixed count of ground-truth SIGNAL (relevant) rows per cluster. Kept
/// small and constant (realistic: few true answers) and `> DEFAULT_K` so
/// a perfect ranker can reach `precision@k == 1.0`.
pub const SIGNAL_ROWS_PER_CLUSTER: usize = 15;

/// Fraction of the corpus seeded as HIGH-TRAFFIC NOISE (popular but
/// irrelevant) rows, distributed round-robin across the clusters. Noise
/// grows WITH the corpus so the "as noise accumulates" degradation is
/// observable across scales.
pub const NOISE_CORPUS_FRACTION: f64 = 0.10;

/// `priority` stamped on the high-traffic noise rows (max) — feeds the
/// `priority * 0.5` frecency term.
pub const NOISE_PRIORITY: i32 = 10;

/// `access_count` stamped on the noise rows. Far above the scorer's
/// documented `MIN(access_count, 50)` cap, so it exercises the cap: the
/// harness reveals whether the cap is sufficient to stop popularity from
/// dominating textual relevance.
pub const NOISE_ACCESS_COUNT: i64 = 50_000;

/// `priority` stamped on the SIGNAL rows (low) — the ground-truth answers
/// earn their rank on FTS relevance, not frecency.
pub const SIGNAL_PRIORITY: i32 = 1;

/// `priority` stamped on FILLER rows (neutral mid-range).
pub const FILLER_PRIORITY: i32 = 3;

/// Namespace the labeled corpus is seeded into (a disposable `:memory:`
/// DB, so it never touches an operator corpus).
pub const RELEVANCE_BENCH_NAMESPACE: &str = "ai-memory-relevance-bench";

/// Default corpus scale ladder when `--scale` is not pinned. 10^6 is
/// opt-in via an explicit `--scale 1000000` (bounded by
/// [`crate::bench::MAX_SCALE`]).
pub const DEFAULT_RELEVANCE_SCALES: &[usize] = &[1_000, 10_000, 100_000];

/// Fixed RFC3339 timestamp stamped on every seeded row (`created_at` /
/// `updated_at`). Deterministic (no `Date::now`) and neutral: identical
/// across rows so the recency term is a constant and the contamination
/// signal is driven purely by the priority/access frecency terms.
const RELEVANCE_FIXED_CREATED_AT: &str = "2020-01-01T00:00:00+00:00";

/// The distinctive per-cluster token carried ONLY by that cluster's
/// signal rows (the strong FTS discriminator).
fn cluster_signal_token(cluster: usize) -> String {
    format!("l10signal{cluster:03}")
}

/// The common per-cluster token carried by BOTH the cluster's signal and
/// its noise rows (so both enter the FTS candidate pool for the probe).
fn cluster_common_token(cluster: usize) -> String {
    format!("l10topic{cluster:03}")
}

/// The probe query for a cluster: the signal token plus the common token.
/// Signal rows match both (strong); noise rows match only the common
/// token (weak) but carry the frecency boost.
#[must_use]
pub fn probe_query(cluster: usize) -> String {
    format!(
        "{} {}",
        cluster_signal_token(cluster),
        cluster_common_token(cluster)
    )
}

/// Total FIXED labeled (signal) rows across all clusters.
#[must_use]
pub fn signal_row_count() -> usize {
    NUM_PROBE_CLUSTERS * SIGNAL_ROWS_PER_CLUSTER
}

/// Effective corpus row count actually seeded for a requested `scale`
/// (never fewer than the signal rows the metric needs).
#[must_use]
pub fn effective_corpus_rows(scale: usize) -> usize {
    scale.max(signal_row_count())
}

/// Per-cluster ground truth: the probe query plus the id sets of the
/// designated relevant (signal) and high-traffic noise rows.
struct ClusterTruth {
    query: String,
    relevant: HashSet<String>,
    noise: HashSet<String>,
}

/// One seeded row's fields, before insertion. Small helper so the 30+
/// field `Memory` literal lives at one site.
fn make_row(
    id: String,
    namespace: &str,
    title: String,
    content: String,
    priority: i32,
    access_count: i64,
) -> Memory {
    Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id,
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title,
        content,
        tags: vec![],
        priority,
        confidence: 1.0,
        source: "l10-bench".to_string(),
        access_count,
        created_at: RELEVANCE_FIXED_CREATED_AT.to_string(),
        updated_at: RELEVANCE_FIXED_CREATED_AT.to_string(),
        last_accessed_at: None,
        expires_at: None,
        // scope=collective so the read-path visibility filter never drops
        // these rows under the bench's anonymous (caller=None) recall
        // (mirrors the `handlers::tests` fixture convention).
        metadata: serde_json::json!({"scope": "collective", "agent_id": "l10-bench"}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: LifecycleState::Open,
    }
}

/// Number of NOISE rows to seed for a requested corpus `scale`, capped so
/// signal + noise never exceeds the effective corpus.
#[must_use]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn noise_row_count(scale: usize) -> usize {
    let rows = effective_corpus_rows(scale);
    let noise = (rows as f64 * NOISE_CORPUS_FRACTION) as usize;
    noise.min(rows.saturating_sub(signal_row_count()))
}

/// Seed the synthetic labeled corpus into `conn` and return the per-cluster
/// ground truth. Deterministic: every row's content, role, and id are
/// index-derived.
fn seed_labeled_corpus(
    conn: &Connection,
    namespace: &str,
    scale: usize,
) -> Result<Vec<ClusterTruth>> {
    let mut truths: Vec<ClusterTruth> = (0..NUM_PROBE_CLUSTERS)
        .map(|c| ClusterTruth {
            query: probe_query(c),
            relevant: HashSet::new(),
            noise: HashSet::new(),
        })
        .collect();

    // Signal rows: the ground-truth relevant answers (strong FTS match,
    // low traffic).
    for c in 0..NUM_PROBE_CLUSTERS {
        let sig = cluster_signal_token(c);
        let com = cluster_common_token(c);
        for n in 0..SIGNAL_ROWS_PER_CLUSTER {
            let id = format!("l10-sig-{c:03}-{n:03}");
            let title = format!("l10-signal-{c:03}-{n:03}");
            let content =
                format!("relevant answer document for {sig} discussing {com} in detail entry {n}");
            let mem = make_row(id, namespace, title, content, SIGNAL_PRIORITY, 0);
            let stored = db::insert(conn, &mem).context("l10 bench: insert signal row")?;
            truths[c].relevant.insert(stored);
        }
    }

    // Noise rows: high-traffic distractors that share the common token,
    // distributed round-robin across clusters, scaled with the corpus.
    let noise_total = noise_row_count(scale);
    for j in 0..noise_total {
        let c = j % NUM_PROBE_CLUSTERS;
        let com = cluster_common_token(c);
        let id = format!("l10-noise-{j:09}");
        let title = format!("l10-noise-{j:09}");
        let content =
            format!("popular high traffic distractor about {com} generic trending item {j}");
        let mem = make_row(
            id,
            namespace,
            title,
            content,
            NOISE_PRIORITY,
            NOISE_ACCESS_COUNT,
        );
        let stored = db::insert(conn, &mem).context("l10 bench: insert noise row")?;
        truths[c].noise.insert(stored);
    }

    // Filler rows: no cluster tokens, so they never enter a probe's
    // candidate pool — they only grow the corpus.
    let seeded = signal_row_count() + noise_total;
    let target = effective_corpus_rows(scale);
    for f in 0..target.saturating_sub(seeded) {
        let id = format!("l10-fill-{f:09}");
        let title = format!("l10-filler-{f:09}");
        let content = format!("unrelated filler background material row {f} with generic tokens");
        let mem = make_row(id, namespace, title, content, FILLER_PRIORITY, 0);
        db::insert(conn, &mem).context("l10 bench: insert filler row")?;
    }

    Ok(truths)
}

/// The `precision@k` / `nDCG@k` / contamination for a single probe.
struct ProbeMetrics {
    precision: f64,
    ndcg: f64,
    contamination: f64,
    returned: usize,
}

/// Score one probe's ranked id list against its cluster ground truth.
/// `nDCG` uses binary gains with the standard `1 / log2(rank + 2)`
/// discount, normalised against the ideal ordering.
#[allow(clippy::cast_precision_loss)]
fn evaluate_probe(ranked_ids: &[String], truth: &ClusterTruth, k: usize) -> ProbeMetrics {
    let cut = ranked_ids.len().min(k);
    let topk = &ranked_ids[..cut];
    let mut relevant_hits = 0usize;
    let mut noise_hits = 0usize;
    let mut dcg = 0.0f64;
    for (rank, id) in topk.iter().enumerate() {
        if truth.relevant.contains(id) {
            relevant_hits += 1;
            dcg += 1.0 / ((rank as f64) + 2.0).log2();
        }
        if truth.noise.contains(id) {
            noise_hits += 1;
        }
    }
    // Ideal DCG: the min(relevant, k) top positions all filled by a
    // relevant row.
    let ideal_count = truth.relevant.len().min(k);
    let mut idcg = 0.0f64;
    for rank in 0..ideal_count {
        idcg += 1.0 / ((rank as f64) + 2.0).log2();
    }
    let ndcg = if idcg > 0.0 { dcg / idcg } else { 0.0 };
    ProbeMetrics {
        precision: relevant_hits as f64 / k as f64,
        ndcg,
        contamination: noise_hits as f64 / k as f64,
        returned: topk.len(),
    }
}

/// One row of the relevance-at-scale report: the mean metrics across all
/// probes at a single corpus scale.
#[derive(Debug, Clone, Serialize)]
pub struct ScaleRelevanceResult {
    /// Requested corpus scale (rows).
    pub scale: usize,
    /// Rows actually seeded (`>= scale`; never fewer than the signal set).
    pub effective_rows: usize,
    /// High-traffic noise rows seeded at this scale.
    pub noise_rows: usize,
    /// Top-`k` cutoff used for every metric.
    pub k: usize,
    /// Number of probe queries averaged.
    pub probes: usize,
    /// Mean `precision@k` across probes.
    pub mean_precision_at_k: f64,
    /// Mean `nDCG@k` across probes.
    pub mean_ndcg_at_k: f64,
    /// Mean frecency-noise contamination rate in the top-`k` across probes
    /// (share of the top-`k` occupied by high-traffic noise rows).
    pub mean_noise_contamination_at_k: f64,
    /// Mean number of results the recall pipeline returned per probe
    /// (capped at `k` by the request `limit`).
    pub mean_results_returned: f64,
}

/// Run the relevance harness for a single corpus scale: seed a fresh
/// disposable `:memory:` DB, run the real recall pipeline for every probe,
/// and return the mean ranking-quality metrics.
///
/// # Errors
///
/// Returns the underlying [`db`] error if seeding or recall fails.
#[allow(clippy::cast_precision_loss)]
pub fn run_scale(scale: usize, k: usize) -> Result<ScaleRelevanceResult> {
    let k = k.max(1);
    let namespace = RELEVANCE_BENCH_NAMESPACE;
    let conn = db::open(Path::new(":memory:")).context("l10 bench: open scratch db")?;
    let truths = seed_labeled_corpus(&conn, namespace, scale)?;

    let mut sum_precision = 0.0f64;
    let mut sum_ndcg = 0.0f64;
    let mut sum_contamination = 0.0f64;
    let mut sum_returned = 0.0f64;
    for truth in &truths {
        // The real recall pipeline (FTS + frecency blend; the semantic
        // phase is inert without an embedder). caller=None is safe: the
        // seeded rows are scope=collective. Params mirror the `bench.rs`
        // recall call sites.
        let (results, _) = db::recall(
            &conn,
            &truth.query,
            Some(namespace),
            k,
            None,
            None,
            None,
            0,
            0,
            None,
            None,
            false,
            None,
            None,
            None,
        )?;
        let ranked_ids: Vec<String> = results.into_iter().map(|(m, _)| m.id).collect();
        let m = evaluate_probe(&ranked_ids, truth, k);
        sum_precision += m.precision;
        sum_ndcg += m.ndcg;
        sum_contamination += m.contamination;
        sum_returned += m.returned as f64;
    }

    let probes = truths.len();
    let denom = probes as f64;
    Ok(ScaleRelevanceResult {
        scale,
        effective_rows: effective_corpus_rows(scale),
        noise_rows: noise_row_count(scale),
        k,
        probes,
        mean_precision_at_k: sum_precision / denom,
        mean_ndcg_at_k: sum_ndcg / denom,
        mean_noise_contamination_at_k: sum_contamination / denom,
        mean_results_returned: sum_returned / denom,
    })
}

/// Run the harness across a ladder of corpus scales.
///
/// # Errors
///
/// Propagates any [`run_scale`] error (seed / recall failures).
pub fn run(scales: &[usize], k: usize) -> Result<Vec<ScaleRelevanceResult>> {
    let mut out = Vec::with_capacity(scales.len());
    for &scale in scales {
        let clamped = scale.clamp(1, crate::bench::MAX_SCALE);
        out.push(run_scale(clamped, k)?);
    }
    Ok(out)
}

/// Render the per-scale relevance report as a human-readable table.
#[must_use]
pub fn render_table(rows: &[ScaleRelevanceResult]) -> String {
    let mut out = String::new();
    out.push_str("L10 relevance-at-scale — real recall pipeline (FTS + frecency blend) over a\n");
    out.push_str(
        "synthetic labeled corpus. Higher precision@k / nDCG@k = better; lower noise-contam = better.\n\n",
    );
    out.push_str(
        "Scale        Rows(eff)   Noise     precision@k   nDCG@k    noise-contam@k   returned   probes\n",
    );
    out.push_str(
        "──────────────────────────────────────────────────────────────────────────────────────────────\n",
    );
    for r in rows {
        let line = format!(
            "{:<11}  {:>9}   {:>7}   {:>10.3}   {:>7.3}   {:>13.3}   {:>7.1}   {:>6}\n",
            r.scale,
            r.effective_rows,
            r.noise_rows,
            r.mean_precision_at_k,
            r.mean_ndcg_at_k,
            r.mean_noise_contamination_at_k,
            r.mean_results_returned,
            r.probes,
        );
        out.push_str(&line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_query_carries_both_tokens() {
        let q = probe_query(5);
        assert!(q.contains("l10signal005"));
        assert!(q.contains("l10topic005"));
    }

    #[test]
    fn noise_scales_with_corpus_and_leaves_room_for_signal() {
        assert!(noise_row_count(10_000) > noise_row_count(1_000));
        // signal + noise never exceeds the effective corpus.
        for &scale in &[1_000usize, 10_000, 100_000] {
            assert!(signal_row_count() + noise_row_count(scale) <= effective_corpus_rows(scale));
        }
    }

    #[test]
    fn evaluate_probe_perfect_ranking_scores_one() {
        let mut truth = ClusterTruth {
            query: probe_query(0),
            relevant: HashSet::new(),
            noise: HashSet::new(),
        };
        for n in 0..12 {
            truth.relevant.insert(format!("rel-{n}"));
        }
        truth.noise.insert("noise-0".to_string());
        let ranked: Vec<String> = (0..10).map(|n| format!("rel-{n}")).collect();
        let m = evaluate_probe(&ranked, &truth, 10);
        assert!((m.precision - 1.0).abs() < 1e-9);
        assert!((m.ndcg - 1.0).abs() < 1e-9);
        assert!(m.contamination.abs() < 1e-9);
        assert_eq!(m.returned, 10);
    }

    #[test]
    fn evaluate_probe_counts_noise_contamination() {
        let mut truth = ClusterTruth {
            query: probe_query(0),
            relevant: HashSet::new(),
            noise: HashSet::new(),
        };
        truth.relevant.insert("rel-0".to_string());
        for n in 0..9 {
            truth.noise.insert(format!("noise-{n}"));
        }
        // Top-10: 1 relevant then 9 noise rows.
        let mut ranked = vec!["rel-0".to_string()];
        for n in 0..9 {
            ranked.push(format!("noise-{n}"));
        }
        let m = evaluate_probe(&ranked, &truth, 10);
        assert!((m.precision - 0.1).abs() < 1e-9);
        assert!((m.contamination - 0.9).abs() < 1e-9);
    }

    /// Small end-to-end run against the real recall pipeline: the harness
    /// executes and produces in-range metrics.
    #[test]
    fn run_scale_small_produces_in_range_metrics() {
        let r = run_scale(1_000, DEFAULT_RELEVANCE_K).unwrap();
        assert_eq!(r.k, DEFAULT_RELEVANCE_K);
        assert_eq!(r.probes, NUM_PROBE_CLUSTERS);
        assert!(r.effective_rows >= 1_000);
        assert!((0.0..=1.0).contains(&r.mean_precision_at_k));
        assert!((0.0..=1.0).contains(&r.mean_ndcg_at_k));
        assert!((0.0..=1.0).contains(&r.mean_noise_contamination_at_k));
        assert!(r.mean_results_returned >= 0.0);
    }
}
