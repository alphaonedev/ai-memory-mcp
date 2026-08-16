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
//! **distractor contamination rate** (designated distractor rows in the
//! top-`k`, over `k`) — makes the mechanism visible directly.
//!
//! # RFC-lite addendum (#2964 hardening — 5-agent vote `4d3ea1c5`)
//!
//! The initial single-scenario harness was ONE-SIDED: every relevant row
//! was cold (`priority=1`, `access_count=0`) and every distractor was
//! hot, so frecency was ALWAYS adversarial and the degenerate "best"
//! scorer was one that DELETES the frecency terms. A one-sided harness
//! cannot falsify that overfit. The hardened harness runs FOUR scenarios,
//! each over its own fresh disposable `:memory:` corpus:
//!
//! - [`Scenario::AdversarialBoth`] — the original: relevant rows are
//!   COLD, distractors crank BOTH levers ([`HOT_PRIORITY`] +
//!   [`HOT_ACCESS_COUNT`]).
//! - [`Scenario::AdversarialPriorityOnly`] — distractors crank ONLY
//!   priority (`access_count` held equal to the relevant rows), so the
//!   contamination is attributable to the `priority * 0.5` frecency term.
//! - [`Scenario::AdversarialAccessOnly`] — distractors crank ONLY
//!   `access_count` (`priority` held equal to the relevant rows), so the
//!   contamination is attributable to the `MIN(access_count, 50) * 0.1`
//!   term — this is the term the access-count cap governs, so the row is
//!   the direct test of whether that cap is sufficient. Holding the
//!   relevant-row baseline (COLD) constant across the three adversarial
//!   scenarios and varying ONLY the distractor lever is what makes the
//!   per-lever attribution clean.
//! - [`Scenario::FrecencyPositiveControl`] — the FALSIFICATION CONTROL:
//!   the ground-truth relevant rows ARE the hot rows (a query whose
//!   correct target is legitimately popular), and the cold decoys carry
//!   IDENTICAL text (same tokens, same length) so FTS ranks them equally
//!   and FRECENCY IS THE SOLE DISCRIMINATOR. A healthy scorer floats the
//!   hot relevant rows to the top (high `precision@k`); a scorer that
//!   games the adversarial corpus by gutting frecency CANNOT distinguish
//!   relevant from decoy here and TANKS this scenario. Reported
//!   separately, it is the guard the adversarial-only harness lacked.
//!
//! **Labeled-corpus methodology.** For each of [`NUM_PROBE_CLUSTERS`]
//! probe queries we seed a FIXED small set of [`SIGNAL_ROWS_PER_CLUSTER`]
//! ground-truth relevant rows plus a set of DISTRACTOR rows scaled as
//! [`DISTRACTOR_CORPUS_FRACTION`] of the corpus (so distractors ACCUMULATE
//! with scale — the "as noise grows" axis), plus FILLER rows (no cluster
//! tokens) for the remainder. Ground truth is by DESIGN (the labeled
//! set), not by term presence, so the metric is a real test of the
//! scorer, not a tautology.
//!
//! **Precedent.** `bench.rs` is the precedent for a synthetic-corpus,
//! in-process, disposable-`SQLite` bench sub-mode; this module follows
//! its shape. No second mutually-exclusive corpus design without
//! precedent arose (the control probe + per-lever split are additive
//! scenarios over the same corpus generator), so per the crossroads
//! protocol T6 this is decide-and-build, vote-EXEMPT for the apparatus
//! itself (additive measurement, no wire/posture/representation change);
//! the #2964 hardening scope was itself 5-agent-voted (`4d3ea1c5`).
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
//! the measurement is faithful to the phenomenon under test.

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;

use crate::db;
use crate::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};

/// Default top-`k` cutoff for `precision@k` / `nDCG@k` / contamination.
pub const DEFAULT_RELEVANCE_K: usize = 10;

/// Number of probe queries (semantic clusters) in each scenario's corpus.
/// Each cluster contributes one probe; the reported metrics are the mean
/// across all probes.
pub const NUM_PROBE_CLUSTERS: usize = 20;

/// Fixed count of ground-truth RELEVANT rows per cluster. Kept small and
/// constant (realistic: few true answers) and `> DEFAULT_K` so a perfect
/// ranker can reach `precision@k == 1.0`.
pub const SIGNAL_ROWS_PER_CLUSTER: usize = 15;

/// Fraction of the corpus seeded as DISTRACTOR rows, distributed
/// round-robin across the clusters. Distractors grow WITH the corpus so
/// the "as noise accumulates" degradation is observable across scales.
pub const DISTRACTOR_CORPUS_FRACTION: f64 = 0.10;

/// `priority` value for a HOT row (max) — feeds the `priority * 0.5`
/// frecency term. Stamped on adversarial distractors and on the control
/// scenario's relevant rows.
pub const HOT_PRIORITY: i32 = 10;

/// `access_count` value for a HOT row. Far above the scorer's documented
/// `MIN(access_count, 50)` cap, so the access-only scenario exercises the
/// cap: the harness reveals whether the cap is sufficient to stop
/// popularity from dominating textual relevance.
pub const HOT_ACCESS_COUNT: i64 = 50_000;

/// `priority` value for a COLD row (low). Stamped on adversarial relevant
/// rows and on the control scenario's decoy rows.
pub const COLD_PRIORITY: i32 = 1;

/// `access_count` value for a COLD row.
pub const COLD_ACCESS_COUNT: i64 = 0;

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

/// A measured relevance scenario. Each runs over its own fresh corpus.
/// The adversarial trio hold the RELEVANT-row baseline COLD and vary only
/// the DISTRACTOR lever, so per-lever contamination is attributable; the
/// control inverts the frecency alignment to falsify a frecency-gutting
/// scorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scenario {
    /// Relevant rows COLD; distractors crank BOTH frecency levers.
    AdversarialBoth,
    /// Relevant rows COLD; distractors crank ONLY `priority`.
    AdversarialPriorityOnly,
    /// Relevant rows COLD; distractors crank ONLY `access_count`.
    AdversarialAccessOnly,
    /// Relevant rows HOT; cold decoys share identical text (frecency is
    /// the sole discriminator) — the falsification control.
    FrecencyPositiveControl,
}

impl Scenario {
    /// Every scenario, in report order.
    pub const ALL: [Self; 4] = [
        Self::AdversarialBoth,
        Self::AdversarialPriorityOnly,
        Self::AdversarialAccessOnly,
        Self::FrecencyPositiveControl,
    ];

    /// Stable render/JSON label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::AdversarialBoth => "adversarial-both",
            Self::AdversarialPriorityOnly => "adversarial-priority-only",
            Self::AdversarialAccessOnly => "adversarial-access-only",
            Self::FrecencyPositiveControl => "frecency-positive-control",
        }
    }

    /// Whether this is the frecency-positive control (relevant == hot).
    #[must_use]
    pub fn is_control(self) -> bool {
        matches!(self, Self::FrecencyPositiveControl)
    }

    /// `(priority, access_count)` stamped on this scenario's RELEVANT
    /// (ground-truth) rows.
    #[must_use]
    fn relevant_frecency(self) -> (i32, i64) {
        match self {
            // Adversarial: relevant rows earn rank on FTS relevance alone.
            Self::AdversarialBoth | Self::AdversarialPriorityOnly | Self::AdversarialAccessOnly => {
                (COLD_PRIORITY, COLD_ACCESS_COUNT)
            }
            // Control: the relevant answer IS the hot row.
            Self::FrecencyPositiveControl => (HOT_PRIORITY, HOT_ACCESS_COUNT),
        }
    }

    /// `(priority, access_count)` stamped on this scenario's DISTRACTOR
    /// rows. The adversarial trio share the same COLD relevant baseline
    /// (see [`Self::relevant_frecency`]) and vary ONLY the lever below.
    #[must_use]
    fn distractor_frecency(self) -> (i32, i64) {
        match self {
            // Both levers hot.
            Self::AdversarialBoth => (HOT_PRIORITY, HOT_ACCESS_COUNT),
            // Priority lever only — access held equal to the relevant baseline.
            Self::AdversarialPriorityOnly => (HOT_PRIORITY, COLD_ACCESS_COUNT),
            // Access lever only — priority held equal to the relevant baseline.
            Self::AdversarialAccessOnly => (COLD_PRIORITY, HOT_ACCESS_COUNT),
            // Control: the decoys are cold.
            Self::FrecencyPositiveControl => (COLD_PRIORITY, COLD_ACCESS_COUNT),
        }
    }
}

/// The distinctive per-cluster token carried ONLY by an adversarial
/// cluster's relevant rows (the strong FTS discriminator).
fn cluster_signal_token(cluster: usize) -> String {
    format!("l10signal{cluster:03}")
}

/// The common per-cluster token carried by BOTH the cluster's relevant
/// and its distractor rows (so both enter the FTS candidate pool).
fn cluster_common_token(cluster: usize) -> String {
    format!("l10topic{cluster:03}")
}

/// The probe query for a cluster under a given scenario.
///
/// Adversarial scenarios query `"<signal-token> <common-token>"`:
/// relevant rows match both (strong), distractors match only the common
/// token (weak) but carry the frecency boost. The control queries the
/// common token ALONE, because relevant and decoy rows carry identical
/// text there — frecency, not FTS, must break the tie.
#[must_use]
pub fn probe_query(scenario: Scenario, cluster: usize) -> String {
    if scenario.is_control() {
        cluster_common_token(cluster)
    } else {
        format!(
            "{} {}",
            cluster_signal_token(cluster),
            cluster_common_token(cluster)
        )
    }
}

/// Total FIXED labeled (relevant) rows across all clusters.
#[must_use]
pub fn signal_row_count() -> usize {
    NUM_PROBE_CLUSTERS * SIGNAL_ROWS_PER_CLUSTER
}

/// Effective corpus row count actually seeded for a requested `scale`
/// (never fewer than the relevant rows the metric needs).
#[must_use]
pub fn effective_corpus_rows(scale: usize) -> usize {
    scale.max(signal_row_count())
}

/// Number of DISTRACTOR rows to seed for a requested corpus `scale`,
/// capped so relevant + distractor never exceeds the effective corpus.
#[must_use]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn distractor_row_count(scale: usize) -> usize {
    let rows = effective_corpus_rows(scale);
    let distractors = (rows as f64 * DISTRACTOR_CORPUS_FRACTION) as usize;
    distractors.min(rows.saturating_sub(signal_row_count()))
}

/// Per-cluster ground truth: the probe query plus the id sets of the
/// designated relevant and distractor rows.
struct ClusterTruth {
    query: String,
    relevant: HashSet<String>,
    distractor: HashSet<String>,
}

/// Text carried by BOTH a control cluster's relevant rows AND its decoy
/// rows — identical tokens + length so FTS ranks them equally and only
/// frecency discriminates. One literal site.
fn control_content(common: &str, idx: usize) -> String {
    format!("hot canonical answer about {common} entry {idx}")
}

/// Content for a RELEVANT row.
fn relevant_content(scenario: Scenario, cluster: usize, n: usize) -> String {
    let common = cluster_common_token(cluster);
    if scenario.is_control() {
        control_content(&common, n)
    } else {
        let signal = cluster_signal_token(cluster);
        format!("relevant answer document for {signal} discussing {common} in detail entry {n}")
    }
}

/// Content for a DISTRACTOR row.
fn distractor_content(scenario: Scenario, cluster: usize, j: usize) -> String {
    let common = cluster_common_token(cluster);
    if scenario.is_control() {
        // Identical template to the relevant rows (frecency is the only
        // discriminator in the control).
        control_content(&common, j)
    } else {
        format!("popular high traffic distractor about {common} generic trending item {j}")
    }
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

/// Seed one scenario's synthetic labeled corpus into `conn` and return the
/// per-cluster ground truth. Deterministic: every row's content, role, and
/// id are index-derived.
fn seed_scenario_corpus(
    conn: &Connection,
    namespace: &str,
    scenario: Scenario,
    scale: usize,
) -> Result<Vec<ClusterTruth>> {
    let (rel_priority, rel_access) = scenario.relevant_frecency();
    let (dis_priority, dis_access) = scenario.distractor_frecency();

    let mut truths: Vec<ClusterTruth> = (0..NUM_PROBE_CLUSTERS)
        .map(|c| ClusterTruth {
            query: probe_query(scenario, c),
            relevant: HashSet::new(),
            distractor: HashSet::new(),
        })
        .collect();

    // Relevant rows: the ground-truth answers (fixed count per cluster).
    for c in 0..NUM_PROBE_CLUSTERS {
        for n in 0..SIGNAL_ROWS_PER_CLUSTER {
            let id = format!("l10-rel-{c:03}-{n:03}");
            let title = format!("l10-rel-{c:03}-{n:03}");
            let content = relevant_content(scenario, c, n);
            let mem = make_row(id, namespace, title, content, rel_priority, rel_access);
            let stored = db::insert(conn, &mem).context("l10 bench: insert relevant row")?;
            truths[c].relevant.insert(stored);
        }
    }

    // Distractor rows: scaled with the corpus, distributed round-robin.
    let distractor_total = distractor_row_count(scale);
    for j in 0..distractor_total {
        let c = j % NUM_PROBE_CLUSTERS;
        let id = format!("l10-dis-{j:09}");
        let title = format!("l10-dis-{j:09}");
        let content = distractor_content(scenario, c, j);
        let mem = make_row(id, namespace, title, content, dis_priority, dis_access);
        let stored = db::insert(conn, &mem).context("l10 bench: insert distractor row")?;
        truths[c].distractor.insert(stored);
    }

    // Filler rows: no cluster tokens, so they never enter a probe's
    // candidate pool — they only grow the corpus.
    let seeded = signal_row_count() + distractor_total;
    let target = effective_corpus_rows(scale);
    for f in 0..target.saturating_sub(seeded) {
        let id = format!("l10-fill-{f:09}");
        let title = format!("l10-filler-{f:09}");
        let content = format!("unrelated filler background material row {f} with generic tokens");
        let mem = make_row(
            id,
            namespace,
            title,
            content,
            FILLER_PRIORITY,
            COLD_ACCESS_COUNT,
        );
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
    let mut distractor_hits = 0usize;
    let mut dcg = 0.0f64;
    for (rank, id) in topk.iter().enumerate() {
        if truth.relevant.contains(id) {
            relevant_hits += 1;
            dcg += 1.0 / ((rank as f64) + 2.0).log2();
        }
        if truth.distractor.contains(id) {
            distractor_hits += 1;
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
        contamination: distractor_hits as f64 / k as f64,
        returned: topk.len(),
    }
}

/// One row of the relevance report: the mean metrics across all probes
/// for one scenario at one corpus scale.
#[derive(Debug, Clone, Serialize)]
pub struct ScaleRelevanceResult {
    /// Scenario label (kebab-case).
    pub scenario: &'static str,
    /// Requested corpus scale (rows).
    pub scale: usize,
    /// Rows actually seeded (`>= scale`; never fewer than the relevant set).
    pub effective_rows: usize,
    /// Distractor rows seeded at this scale.
    pub distractor_rows: usize,
    /// Top-`k` cutoff used for every metric.
    pub k: usize,
    /// Number of probe queries averaged.
    pub probes: usize,
    /// Mean `precision@k` across probes.
    pub mean_precision_at_k: f64,
    /// Mean `nDCG@k` across probes.
    pub mean_ndcg_at_k: f64,
    /// Mean distractor contamination rate in the top-`k` across probes.
    /// For the adversarial scenarios this is the frecency-noise rate; for
    /// the control it is the cold-decoy rate (a healthy scorer keeps it
    /// low because the hot relevant rows outrank the cold decoys).
    pub mean_distractor_contamination_at_k: f64,
    /// Mean number of results the recall pipeline returned per probe
    /// (capped at `k` by the request `limit`).
    pub mean_results_returned: f64,
}

/// Run one scenario at one corpus scale: seed a fresh disposable
/// `:memory:` DB, run the real recall pipeline for every probe, and return
/// the mean ranking-quality metrics.
#[allow(clippy::cast_precision_loss)]
fn run_scenario(scenario: Scenario, scale: usize, k: usize) -> Result<ScaleRelevanceResult> {
    let k = k.max(1);
    let namespace = RELEVANCE_BENCH_NAMESPACE;
    let conn = db::open(Path::new(":memory:")).context("l10 bench: open scratch db")?;
    let truths = seed_scenario_corpus(&conn, namespace, scenario, scale)?;

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
        scenario: scenario.label(),
        scale,
        effective_rows: effective_corpus_rows(scale),
        distractor_rows: distractor_row_count(scale),
        k,
        probes,
        mean_precision_at_k: sum_precision / denom,
        mean_ndcg_at_k: sum_ndcg / denom,
        mean_distractor_contamination_at_k: sum_contamination / denom,
        mean_results_returned: sum_returned / denom,
    })
}

/// Run every [`Scenario`] at a single corpus scale.
///
/// # Errors
///
/// Returns the underlying [`db`] error if seeding or recall fails.
pub fn run_scale(scale: usize, k: usize) -> Result<Vec<ScaleRelevanceResult>> {
    let mut rows = Vec::with_capacity(Scenario::ALL.len());
    for scenario in Scenario::ALL {
        rows.push(run_scenario(scenario, scale, k)?);
    }
    Ok(rows)
}

/// Run every scenario across a ladder of corpus scales (rows are grouped
/// by scale, scenarios in [`Scenario::ALL`] order).
///
/// # Errors
///
/// Propagates any [`run_scale`] error (seed / recall failures).
pub fn run(scales: &[usize], k: usize) -> Result<Vec<ScaleRelevanceResult>> {
    let mut out = Vec::with_capacity(scales.len() * Scenario::ALL.len());
    for &scale in scales {
        let clamped = scale.clamp(1, crate::bench::MAX_SCALE);
        out.extend(run_scale(clamped, k)?);
    }
    Ok(out)
}

/// Render the per-scenario relevance report as a human-readable table.
#[must_use]
pub fn render_table(rows: &[ScaleRelevanceResult]) -> String {
    let mut out = String::new();
    out.push_str(
        "L10 relevance-at-scale — real recall pipeline (FTS + frecency blend) over synthetic labeled corpora.\n",
    );
    out.push_str(
        "Adversarial: relevant rows COLD, distractors hot (per-lever). Control: relevant rows HOT, decoys cold+identical-text.\n",
    );
    out.push_str(
        "Higher precision@k / nDCG@k = better. A frecency-gutting scorer TANKS the control row.\n\n",
    );
    out.push_str(
        "Scenario                     Scale     Rows(eff)  Distract  precision@k  nDCG@k   distract@k  returned  probes\n",
    );
    out.push_str(
        "─────────────────────────────────────────────────────────────────────────────────────────────────────────────\n",
    );
    for r in rows {
        let line = format!(
            "{:<28} {:>7}  {:>9}  {:>7}  {:>10.3}  {:>7.3}  {:>10.3}  {:>7.1}  {:>6}\n",
            r.scenario,
            r.scale,
            r.effective_rows,
            r.distractor_rows,
            r.mean_precision_at_k,
            r.mean_ndcg_at_k,
            r.mean_distractor_contamination_at_k,
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
    fn adversarial_probe_carries_both_tokens_control_carries_one() {
        let adv = probe_query(Scenario::AdversarialBoth, 5);
        assert!(adv.contains("l10signal005"));
        assert!(adv.contains("l10topic005"));
        let ctrl = probe_query(Scenario::FrecencyPositiveControl, 5);
        assert!(ctrl.contains("l10topic005"));
        assert!(!ctrl.contains("l10signal005"));
    }

    #[test]
    fn lever_split_holds_relevant_baseline_and_varies_only_distractor() {
        // Relevant baseline is COLD and identical across the adversarial trio.
        for s in [
            Scenario::AdversarialBoth,
            Scenario::AdversarialPriorityOnly,
            Scenario::AdversarialAccessOnly,
        ] {
            assert_eq!(s.relevant_frecency(), (COLD_PRIORITY, COLD_ACCESS_COUNT));
        }
        // Each lever isolates exactly one term.
        assert_eq!(
            Scenario::AdversarialPriorityOnly.distractor_frecency(),
            (HOT_PRIORITY, COLD_ACCESS_COUNT)
        );
        assert_eq!(
            Scenario::AdversarialAccessOnly.distractor_frecency(),
            (COLD_PRIORITY, HOT_ACCESS_COUNT)
        );
        assert_eq!(
            Scenario::AdversarialBoth.distractor_frecency(),
            (HOT_PRIORITY, HOT_ACCESS_COUNT)
        );
        // Control inverts the alignment: relevant hot, decoy cold.
        assert_eq!(
            Scenario::FrecencyPositiveControl.relevant_frecency(),
            (HOT_PRIORITY, HOT_ACCESS_COUNT)
        );
        assert_eq!(
            Scenario::FrecencyPositiveControl.distractor_frecency(),
            (COLD_PRIORITY, COLD_ACCESS_COUNT)
        );
    }

    #[test]
    fn control_relevant_and_decoy_share_identical_text_modulo_index() {
        // Same template + tokens → FTS ranks them equally, frecency decides.
        let rel = relevant_content(Scenario::FrecencyPositiveControl, 3, 7);
        let dec = distractor_content(Scenario::FrecencyPositiveControl, 3, 7);
        assert_eq!(rel, dec);
        assert!(rel.contains("l10topic003"));
        assert!(!rel.contains("l10signal003"));
    }

    #[test]
    fn distractor_scales_with_corpus_and_leaves_room_for_signal() {
        assert!(distractor_row_count(10_000) > distractor_row_count(1_000));
        for &scale in &[1_000usize, 10_000, 100_000] {
            assert!(
                signal_row_count() + distractor_row_count(scale) <= effective_corpus_rows(scale)
            );
        }
    }

    #[test]
    fn evaluate_probe_perfect_ranking_scores_one() {
        let mut truth = ClusterTruth {
            query: probe_query(Scenario::AdversarialBoth, 0),
            relevant: HashSet::new(),
            distractor: HashSet::new(),
        };
        for n in 0..12 {
            truth.relevant.insert(format!("rel-{n}"));
        }
        truth.distractor.insert("dis-0".to_string());
        let ranked: Vec<String> = (0..10).map(|n| format!("rel-{n}")).collect();
        let m = evaluate_probe(&ranked, &truth, 10);
        assert!((m.precision - 1.0).abs() < 1e-9);
        assert!((m.ndcg - 1.0).abs() < 1e-9);
        assert!(m.contamination.abs() < 1e-9);
        assert_eq!(m.returned, 10);
    }

    #[test]
    fn evaluate_probe_counts_distractor_contamination() {
        let mut truth = ClusterTruth {
            query: probe_query(Scenario::AdversarialBoth, 0),
            relevant: HashSet::new(),
            distractor: HashSet::new(),
        };
        truth.relevant.insert("rel-0".to_string());
        for n in 0..9 {
            truth.distractor.insert(format!("dis-{n}"));
        }
        let mut ranked = vec!["rel-0".to_string()];
        for n in 0..9 {
            ranked.push(format!("dis-{n}"));
        }
        let m = evaluate_probe(&ranked, &truth, 10);
        assert!((m.precision - 0.1).abs() < 1e-9);
        assert!((m.contamination - 0.9).abs() < 1e-9);
    }

    /// Small end-to-end run: every scenario executes and produces in-range
    /// metrics, and the control's frecency-positive alignment yields
    /// HIGHER precision than the both-levers adversarial scenario under the
    /// current (frecency-using) scorer.
    #[test]
    fn run_scale_small_all_scenarios_in_range_and_control_beats_adversarial() {
        let rows = run_scale(1_000, DEFAULT_RELEVANCE_K).unwrap();
        assert_eq!(rows.len(), Scenario::ALL.len());
        for r in &rows {
            assert_eq!(r.k, DEFAULT_RELEVANCE_K);
            assert_eq!(r.probes, NUM_PROBE_CLUSTERS);
            assert!(r.effective_rows >= 1_000);
            assert!((0.0..=1.0).contains(&r.mean_precision_at_k));
            assert!((0.0..=1.0).contains(&r.mean_ndcg_at_k));
            assert!((0.0..=1.0).contains(&r.mean_distractor_contamination_at_k));
        }
        let adversarial = rows
            .iter()
            .find(|r| r.scenario == Scenario::AdversarialBoth.label())
            .unwrap();
        let control = rows
            .iter()
            .find(|r| r.scenario == Scenario::FrecencyPositiveControl.label())
            .unwrap();
        // The healthy scorer uses frecency, so the control (where hot ==
        // relevant) must score at least as high as the adversarial corpus
        // (where hot == noise). A frecency-gutting scorer would collapse
        // this gap — the falsification the control exists to provide.
        assert!(control.mean_precision_at_k >= adversarial.mean_precision_at_k);
    }
}
