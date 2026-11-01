// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6043 consolidation benchmark (adopted by the #8458 3-agent vote, 6def5ab6).
//!
//! Runs the EXISTING [`ConsolidationPass`] (unchanged) over a seeded COPY
//! store and reports how far the store shrinks against retrieval recall, LLM
//! calls and wall time, then proves the shrink is reversible by running the
//! rollback path and checking every original row comes back byte-identical.
//!
//! Two arms share one flow ([`run_flow`]):
//!
//! * **R2, deterministic CI arm.** A fixed-seed synthetic corpus (known
//!   near-duplicate clusters plus distinct rows, one stored embedding per
//!   row), a counted in-tree stub [`AutonomyLlm`], no network, no model
//!   download. Runs on SQLite and, when `AI_MEMORY_TEST_POSTGRES_URL` is set,
//!   on Postgres. The result is printed as one TOON-style line.
//! * **R3, operator arm.** `#[ignore]`d: the same seeded flow against the real
//!   LLM named by the `AI_MEMORY_LLM_*` environment variables
//!   ([`crate::llm::OllamaClient::from_env`]), `cosine_threshold` swept over
//!   0.70 / 0.75 / 0.85, QA accuracy before and after, a JSON report under
//!   `.local-runs/`. Skips cleanly when no LLM is configured.
//!
//! The pass is `pub(crate)`, so the benchmark lives in the crate (a
//! `tests/` binary cannot name it without widening production visibility).
//!
//! The synthetic corpus gives a SYNTHETIC result: it measures the mechanism
//! (shrink, call count, reversibility), not task performance, and must not be
//! quoted as a performance claim.

#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::cast_precision_loss
)]

use super::compaction::ConsolidationPass;
use crate::autonomy::{AutonomyLlm, RollbackEntry, reverse_rollback_entry_store};
use crate::embeddings::{Embedder, embedding_space_fingerprint};
use crate::models::{Memory, Tier};
use crate::store::{CallerContext, Filter, MemoryStore};
use anyhow::{Result, anyhow, bail};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// Fixed corpus seed: every run regenerates the identical corpus.
const BENCH_SEED: u64 = 0x6043_C0DE_5EED_0001;
/// Postgres stores `vector(384)`; the synthetic vectors match so one corpus
/// serves both backends.
const EMBEDDING_DIM: usize = 384;
/// Near-duplicate cluster sizes. The LAST cluster is the "loose" one.
const CLUSTER_SIZES: [usize; 6] = [5, 4, 4, 3, 3, 2];
/// Rows that belong to no cluster.
const DISTINCT_ROWS: usize = 20;
/// Distinct rows that also get a recall / QA query.
const DISTINCT_QUERIES: usize = 8;
/// First basis axis used by distinct rows (cluster `k` uses axis `k`).
const DISTINCT_BASE_AXIS: usize = 8;
/// Extra axes that make the loose cluster's members cosine ~0.80 apart.
const LOOSE_AXES: [usize; 2] = [40, 41];
/// Weight of the loose axis (cos = 1 / (1 + w^2) = 0.80).
const LOOSE_WEIGHT: f32 = 0.5;
/// Per-dimension noise amplitude that keeps vectors distinct but near-exact.
const NOISE_SCALE: f32 = 0.004;
/// Distinct tokens shared by every member of one topic.
const BASE_WORDS: usize = 10;
/// Syllables in a topic word / in a fact code word.
const WORD_SYLLABLES: usize = 3;
const FACT_SYLLABLES: usize = 4;
/// Embedding-space model name stamped on every synthetic vector.
const SPACE_MODEL: &str = "bench6043-synthetic";
/// Reserved namespace the pass writes its reversible rollback rows to.
const ROLLBACK_NS: &str = "_curator/rollback";
/// Upper bound for every `list` the benchmark makes.
const LIST_LIMIT: usize = 1000;
/// Fixed timestamp so seeded rows are byte-stable across runs.
const SEED_TIMESTAMP: &str = "2026-01-01T00:00:00+00:00";
/// Agent id the benchmark acts as.
const BENCH_AGENT: &str = "bench-6043";
const COL_ROWS_BEFORE: &str = "rows_before";
const COL_ROWS_AFTER: &str = "rows_after";
const COL_ROLLBACK_IDENTICAL: &str = "rollback_identical";
const FIELD_EMBEDDING_SPACE: &str = "embedding_space";
const SQLITE_OPEN_MSG: &str = "open the sqlite benchmark store";
/// Recall cut-offs reported.
/// Current rollback behaviour for vectors (#8465).
const EMBEDDING_RESTORED_TODAY: bool = false;
const RECALL_SHALLOW_K: usize = 5;
const RECALL_DEEP_K: usize = 10;
/// The pass's default cosine gate (the R2 headline run).
const DEFAULT_THRESHOLD: f32 = 0.75;
/// R3 sweep, the analogue of the paper's `min_cluster_size` sweep.
const THRESHOLD_SWEEP: [f32; 3] = [0.70, 0.75, 0.85];
const CONSONANTS: &[u8] = b"bcdfghjklmnprstvz";
const VOWELS: &[u8] = b"aeiou";

// ---------------------------------------------------------------------------
// Deterministic generator (SplitMix64; no crate, no clock, no OS entropy)
// ---------------------------------------------------------------------------

struct SplitMix(u64);

impl SplitMix {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[-1, 1]`.
    fn unit(&mut self) -> f32 {
        let top = u16::try_from(self.next_u64() >> 48).unwrap_or(0);
        f32::from(top) / f32::from(u16::MAX) * 2.0 - 1.0
    }

    fn pick(&mut self, n: usize) -> usize {
        let bound = u64::try_from(n).unwrap_or(1).max(1);
        usize::try_from(self.next_u64() % bound).unwrap_or(0)
    }

    fn word(&mut self, syllables: usize) -> String {
        let mut w = String::new();
        for _ in 0..syllables {
            w.push(char::from(CONSONANTS[self.pick(CONSONANTS.len())]));
            w.push(char::from(VOWELS[self.pick(VOWELS.len())]));
        }
        w
    }

    fn unique_word(&mut self, syllables: usize, seen: &mut HashSet<String>) -> String {
        loop {
            let w = self.word(syllables);
            if seen.insert(w.clone()) {
                return w;
            }
        }
    }
}

fn normalised(mut v: Vec<f32>) -> Vec<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in &mut v {
            *x /= norm;
        }
    }
    v
}

fn axis_vector(axes: &[(usize, f32)], rng: &mut SplitMix) -> Vec<f32> {
    let mut v: Vec<f32> = (0..EMBEDDING_DIM)
        .map(|_| rng.unit() * NOISE_SCALE)
        .collect();
    for (axis, weight) in axes {
        v[*axis] += *weight;
    }
    normalised(v)
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

struct Row {
    id: String,
    title: String,
    content: String,
    vector: Vec<f32>,
}

/// One retrievable topic: a query vector, the rows that answer it, and the
/// fact a QA question asks for.
struct Topic {
    query: Vec<f32>,
    members: Vec<String>,
    fact: String,
    question: String,
}

struct Corpus {
    namespace: String,
    rows: Vec<Row>,
    topics: Vec<Topic>,
}

fn build_corpus(namespace: &str) -> Corpus {
    let mut rng = SplitMix(BENCH_SEED);
    let mut seen: HashSet<String> = HashSet::new();
    let mut rows: Vec<Row> = Vec::new();
    let mut topics: Vec<Topic> = Vec::new();

    let loose = CLUSTER_SIZES.len() - 1;
    let topic_rows = |idx: usize,
                      label: &str,
                      size: usize,
                      axis: usize,
                      rng: &mut SplitMix,
                      rows: &mut Vec<Row>,
                      seen: &mut HashSet<String>|
     -> Topic {
        let base: Vec<String> = (0..BASE_WORDS)
            .map(|_| rng.unique_word(WORD_SYLLABLES, seen))
            .collect();
        let fact = rng.unique_word(FACT_SYLLABLES, seen);
        let mut members = Vec::new();
        for m in 0..size {
            let id = format!("{namespace}-{label}{idx}m{m}");
            let mut content = format!("{} code {fact}", base.join(" "));
            if size > 1 {
                content.push(' ');
                content.push_str(&rng.unique_word(WORD_SYLLABLES, seen));
            }
            let axes: Vec<(usize, f32)> = if label == "c" && idx == loose {
                vec![
                    (axis, 1.0),
                    (LOOSE_AXES[m % LOOSE_AXES.len()], LOOSE_WEIGHT),
                ]
            } else {
                vec![(axis, 1.0)]
            };
            rows.push(Row {
                title: format!("{label}{idx}-m{m}"),
                vector: axis_vector(&axes, rng),
                id: id.clone(),
                content,
            });
            members.push(id);
        }
        Topic {
            query: axis_vector(&[(axis, 1.0)], &mut SplitMix(BENCH_SEED ^ 0x51)),
            members,
            question: format!(
                "In the notes about {} and {}, what is the recorded code word?",
                base[0], base[1]
            ),
            fact,
        }
    };

    for (k, size) in CLUSTER_SIZES.iter().enumerate() {
        let t = topic_rows(k, "c", *size, k, &mut rng, &mut rows, &mut seen);
        topics.push(t);
    }
    for j in 0..DISTINCT_ROWS {
        let t = topic_rows(
            j,
            "d",
            1,
            DISTINCT_BASE_AXIS + j,
            &mut rng,
            &mut rows,
            &mut seen,
        );
        if j < DISTINCT_QUERIES {
            topics.push(t);
        }
    }
    Corpus {
        namespace: namespace.to_string(),
        rows,
        topics,
    }
}

// ---------------------------------------------------------------------------
// Counted stub LLM
// ---------------------------------------------------------------------------

/// Deterministic [`AutonomyLlm`] that counts `summarize_memories` calls.
struct CountedStubLlm {
    calls: AtomicUsize,
}

impl CountedStubLlm {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl AutonomyLlm for CountedStubLlm {
    fn auto_tag(&self, _title: &str, _content: &str) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn detect_contradiction(&self, _a: &str, _b: &str) -> Result<bool> {
        Ok(false)
    }
    fn summarize_memories(&self, memories: &[(String, String)]) -> Result<String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let first = memories.first().map_or("", |(_, c)| c.as_str());
        Ok(format!("consolidated {} notes: {first}", memories.len()))
    }
}

/// Wraps any [`AutonomyLlm`] with a call counter (used for the real LLM).
struct CountedLlm<'a> {
    inner: &'a dyn AutonomyLlm,
    calls: AtomicUsize,
}

impl AutonomyLlm for CountedLlm<'_> {
    fn auto_tag(&self, title: &str, content: &str) -> Result<Vec<String>> {
        self.inner.auto_tag(title, content)
    }
    fn detect_contradiction(&self, a: &str, b: &str) -> Result<bool> {
        self.inner.detect_contradiction(a, b)
    }
    fn summarize_memories(&self, memories: &[(String, String)]) -> Result<String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.summarize_memories(memories)
    }
}

// ---------------------------------------------------------------------------
// Seed, snapshot, compare
// ---------------------------------------------------------------------------

fn bench_ctx() -> CallerContext {
    CallerContext::for_admin(BENCH_AGENT)
}

fn space() -> String {
    embedding_space_fingerprint(SPACE_MODEL)
}

async fn seed_store(store: &dyn MemoryStore, corpus: &Corpus) -> Result<()> {
    let ctx = bench_ctx();
    for row in &corpus.rows {
        let memory = Memory {
            id: row.id.clone(),
            tier: Tier::Long,
            namespace: corpus.namespace.clone(),
            title: row.title.clone(),
            content: row.content.clone(),
            created_at: SEED_TIMESTAMP.to_string(),
            updated_at: SEED_TIMESTAMP.to_string(),
            source: BENCH_AGENT.to_string(),
            ..Memory::default()
        };
        store.store(&ctx, &memory).await?;
        store
            .update_embedding(&ctx, &row.id, Some(&row.vector), &space())
            .await?;
    }
    Ok(())
}

/// Everything a rollback must restore for one row.
#[derive(Debug, Clone)]
struct RowImage {
    id: String,
    namespace: String,
    title: String,
    content: String,
    metadata: String,
    tags: Vec<String>,
    embedding_bits: Vec<u32>,
    embedding_space: Option<String>,
}

async fn image_of(store: &dyn MemoryStore, id: &str) -> Option<RowImage> {
    let ctx = bench_ctx();
    let m = store.get(&ctx, id).await.ok()?;
    let (vector, embedding_space) = store
        .get_embedding_with_space(&ctx, id)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    Some(RowImage {
        id: m.id,
        namespace: m.namespace,
        title: m.title,
        content: m.content,
        metadata: m.metadata.to_string(),
        tags: m.tags,
        embedding_bits: vector.iter().map(|x| x.to_bits()).collect(),
        embedding_space,
    })
}

async fn snapshot(store: &dyn MemoryStore, corpus: &Corpus) -> Vec<Option<RowImage>> {
    let mut out = Vec::with_capacity(corpus.rows.len());
    for row in &corpus.rows {
        out.push(image_of(store, &row.id).await);
    }
    out
}

/// Why two row images differ.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mismatch(String);

impl From<String> for Mismatch {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// `Ok` only when every `before` row is present in `after` with an identical
/// id, namespace, title, content, metadata, tags and embedding (bit for bit).
fn compare_images(
    before: &[Option<RowImage>],
    after: &[Option<RowImage>],
    with_embedding: bool,
) -> std::result::Result<(), Mismatch> {
    if before.len() != after.len() {
        return Err(format!(
            "image count differs: {} before, {} after",
            before.len(),
            after.len()
        )
        .into());
    }
    for (b, a) in before.iter().zip(after) {
        let Some(b) = b else {
            return Err(Mismatch("a before-image is missing".to_string()));
        };
        let Some(a) = a else {
            return Err(format!("row {} is missing after rollback", b.id).into());
        };
        let diffs = [
            ("id", b.id == a.id),
            ("namespace", b.namespace == a.namespace),
            ("title", b.title == a.title),
            ("content", b.content == a.content),
            ("metadata", b.metadata == a.metadata),
            ("tags", b.tags == a.tags),
            (
                "embedding",
                !with_embedding || b.embedding_bits == a.embedding_bits,
            ),
            (
                FIELD_EMBEDDING_SPACE,
                !with_embedding || b.embedding_space == a.embedding_space,
            ),
        ];
        if let Some((field, _)) = diffs.iter().find(|(_, same)| !same) {
            return Err(format!("row {} differs in {field}", b.id).into());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// `hits / total`, kept as integers so no float is ever compared (PERF-25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ratio {
    hits: usize,
    total: usize,
}

impl Ratio {
    fn value(self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.hits as f64 / self.total as f64
        }
    }
    fn at_least(self, other: Self) -> bool {
        self.hits * other.total >= other.hits * self.total
    }
}

/// Recall@k over the topic set: for each topic the share of its answering
/// rows (mapped through `redirect` after a merge) found in the top `k` by
/// cosine against the stored vectors; summed over topics.
async fn recall_at(
    store: &dyn MemoryStore,
    corpus: &Corpus,
    redirect: &HashMap<String, String>,
    k: usize,
) -> Result<Ratio> {
    let ctx = bench_ctx();
    let filter = Filter {
        namespace: Some(corpus.namespace.clone()),
        limit: LIST_LIMIT,
        ..Filter::default()
    };
    let mut pool: Vec<(String, Vec<f32>)> = Vec::new();
    for m in store.list(&ctx, &filter).await? {
        if let Some((v, _)) = store.get_embedding_with_space(&ctx, &m.id).await? {
            pool.push((m.id, v));
        }
    }
    let (mut hits, mut total) = (0usize, 0usize);
    for topic in &corpus.topics {
        let mut ranked: Vec<(f32, &str)> = pool
            .iter()
            .map(|(id, v)| (Embedder::cosine_similarity(&topic.query, v), id.as_str()))
            .collect();
        ranked.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(b.1)));
        let top: HashSet<&str> = ranked.iter().take(k).map(|(_, id)| *id).collect();
        let relevant: HashSet<&str> = topic
            .members
            .iter()
            .map(|id| redirect.get(id).map_or(id.as_str(), String::as_str))
            .collect();
        total += relevant.len();
        hits += relevant.iter().filter(|id| top.contains(*id)).count();
    }
    Ok(Ratio { hits, total })
}

async fn count_rows(store: &dyn MemoryStore, namespace: &str) -> Result<usize> {
    let filter = Filter {
        namespace: Some(namespace.to_string()),
        limit: LIST_LIMIT,
        ..Filter::default()
    };
    Ok(store.list(&bench_ctx(), &filter).await?.len())
}

/// The reversible `Consolidate` rollback rows this run wrote (one per merge).
async fn consolidate_entries(
    store: &dyn MemoryStore,
    namespace: &str,
) -> Result<Vec<RollbackEntry>> {
    let filter = Filter {
        namespace: Some(ROLLBACK_NS.to_string()),
        limit: LIST_LIMIT,
        ..Filter::default()
    };
    let mut out = Vec::new();
    for row in store.list(&bench_ctx(), &filter).await? {
        let Ok(entry) = serde_json::from_str::<RollbackEntry>(&row.content) else {
            continue;
        };
        if let RollbackEntry::Consolidate { originals, .. } = &entry
            && originals.first().is_some_and(|m| m.namespace == namespace)
        {
            out.push(entry);
        }
    }
    Ok(out)
}

/// Stand-in for the embedding backfill: give each summary the centroid of the
/// vectors it replaced, so recall can be measured with the summary searchable.
async fn backfill_summaries(
    store: &dyn MemoryStore,
    corpus: &Corpus,
    entries: &[RollbackEntry],
) -> Result<()> {
    let by_id: HashMap<&str, &Vec<f32>> = corpus
        .rows
        .iter()
        .map(|r| (r.id.as_str(), &r.vector))
        .collect();
    for entry in entries {
        let RollbackEntry::Consolidate {
            originals,
            result_id,
        } = entry
        else {
            continue;
        };
        let mut sum = vec![0.0f32; EMBEDDING_DIM];
        for m in originals {
            let v = by_id
                .get(m.id.as_str())
                .ok_or_else(|| anyhow!("no seeded vector for {}", m.id))?;
            for (s, x) in sum.iter_mut().zip(v.iter()) {
                *s += *x;
            }
        }
        store
            .update_embedding(&bench_ctx(), result_id, Some(&normalised(sum)), &space())
            .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The flow
// ---------------------------------------------------------------------------

/// What one run measured. Every field is derived from the store or the pass.
#[derive(Debug, Clone)]
struct BenchResult {
    backend: &'static str,
    threshold: f32,
    rows_before: usize,
    rows_after: usize,
    llm_calls: usize,
    wall_ms: u128,
    rollback_entries: usize,
    recall5: (Ratio, Ratio, Ratio),
    recall10: (Ratio, Ratio, Ratio),
    rows_after_rollback: usize,
    rollback_identical: std::result::Result<(), Mismatch>,
    /// Vectors restored too (false today: #8465).
    embedding_restored: bool,
    qa: Option<(Ratio, Ratio)>,
}

impl BenchResult {
    fn shrink_pct(&self) -> f64 {
        if self.rows_before == 0 {
            return 0.0;
        }
        (self.rows_before.saturating_sub(self.rows_after)) as f64 * 100.0 / self.rows_before as f64
    }

    /// One TOON-style line: `bench_6043_result[1]{columns}: values`.
    fn result_line(&self) -> String {
        let columns = [
            "backend",
            "threshold",
            COL_ROWS_BEFORE,
            COL_ROWS_AFTER,
            "shrink_pct",
            "llm_calls",
            "wall_ms",
            "rollback_entries",
            "r5_before",
            "r5_after",
            "r5_after_unembedded",
            "r10_before",
            "r10_after",
            "r10_after_unembedded",
            "rows_after_rollback",
            COL_ROLLBACK_IDENTICAL,
            "embedding_restored",
        ];
        let values = [
            self.backend.to_string(),
            format!("{:.2}", self.threshold),
            self.rows_before.to_string(),
            self.rows_after.to_string(),
            format!("{:.2}", self.shrink_pct()),
            self.llm_calls.to_string(),
            self.wall_ms.to_string(),
            self.rollback_entries.to_string(),
            format!("{:.4}", self.recall5.0.value()),
            format!("{:.4}", self.recall5.1.value()),
            format!("{:.4}", self.recall5.2.value()),
            format!("{:.4}", self.recall10.0.value()),
            format!("{:.4}", self.recall10.1.value()),
            format!("{:.4}", self.recall10.2.value()),
            self.rows_after_rollback.to_string(),
            self.rollback_identical.is_ok().to_string(),
            self.embedding_restored.to_string(),
        ];
        format!(
            "bench_6043_result[1]{{{}}}: {}",
            columns.join(","),
            values.join(",")
        )
    }
}

/// Parse a [`BenchResult::result_line`] back into `column -> value`.
fn parse_result_line(line: &str) -> Result<BTreeMap<String, String>> {
    let rest = line
        .strip_prefix("bench_6043_result[1]{")
        .ok_or_else(|| anyhow!("not a bench_6043_result line: {line}"))?;
    let (cols, vals) = rest
        .split_once("}: ")
        .ok_or_else(|| anyhow!("missing `}}: ` separator: {line}"))?;
    let cols: Vec<&str> = cols.split(',').collect();
    let vals: Vec<&str> = vals.split(',').collect();
    if cols.len() != vals.len() {
        bail!("{} columns but {} values", cols.len(), vals.len());
    }
    Ok(cols
        .into_iter()
        .map(str::to_string)
        .zip(vals.into_iter().map(str::to_string))
        .collect())
}

/// Knobs the negative tests flip to prove the assertions can fail.
#[derive(Clone, Copy)]
struct FlowOptions<'a> {
    /// Real-LLM question answering (R3 only).
    qa: Option<&'a crate::llm::OllamaClient>,
    /// Run the rollback path after measuring. `false` leaves the store
    /// consolidated, so the identity check must report the missing rows.
    rollback: bool,
}

async fn run_flow(
    store: &dyn MemoryStore,
    backend: &'static str,
    llm: &dyn AutonomyLlm,
    llm_calls: &AtomicUsize,
    threshold: f32,
    options: FlowOptions<'_>,
) -> Result<BenchResult> {
    let ns = format!(
        "bench6043-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );
    let corpus = build_corpus(&ns);
    seed_store(store, &corpus).await?;
    let before = snapshot(store, &corpus).await;
    let rows_before = count_rows(store, &ns).await?;
    let no_redirect = HashMap::new();
    let r5_before = recall_at(store, &corpus, &no_redirect, RECALL_SHALLOW_K).await?;
    let r10_before = recall_at(store, &corpus, &no_redirect, RECALL_DEEP_K).await?;

    let qa_before = match options.qa {
        Some(c) => Some(qa_score(store, &corpus, c).await?),
        None => None,
    };
    let ctx = bench_ctx();
    let filter = Filter {
        namespace: Some(ns.clone()),
        limit: LIST_LIMIT,
        ..Filter::default()
    };
    let candidates = store.list(&ctx, &filter).await?;
    let started = Instant::now();
    let report = ConsolidationPass::new(store, llm, false)
        .with_cosine_threshold(threshold)
        .run(&candidates)
        .await?;
    let wall_ms = started.elapsed().as_millis();
    if !report.errors.is_empty() {
        bail!("pass reported errors: {:?}", report.errors);
    }

    let rows_after = count_rows(store, &ns).await?;
    let entries = consolidate_entries(store, &ns).await?;
    let redirect: HashMap<String, String> = entries
        .iter()
        .filter_map(|e| match e {
            RollbackEntry::Consolidate {
                originals,
                result_id,
            } => Some(
                originals
                    .iter()
                    .map(|m| (m.id.clone(), result_id.clone()))
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect();
    let r5_unembedded = recall_at(store, &corpus, &redirect, RECALL_SHALLOW_K).await?;
    let r10_unembedded = recall_at(store, &corpus, &redirect, RECALL_DEEP_K).await?;
    backfill_summaries(store, &corpus, &entries).await?;
    let r5_after = recall_at(store, &corpus, &redirect, RECALL_SHALLOW_K).await?;
    let r10_after = recall_at(store, &corpus, &redirect, RECALL_DEEP_K).await?;

    let qa_after = match options.qa {
        Some(c) => Some(qa_score(store, &corpus, c).await?),
        None => None,
    };
    if options.rollback {
        for entry in &entries {
            reverse_rollback_entry_store(store, &ctx, entry).await?;
        }
    }
    let rows_after_rollback = count_rows(store, &ns).await?;
    let after = snapshot(store, &corpus).await;
    Ok(BenchResult {
        backend,
        threshold,
        rows_before,
        rows_after,
        llm_calls: llm_calls.load(Ordering::SeqCst),
        wall_ms,
        rollback_entries: report.rollback_entries_written,
        recall5: (r5_before, r5_after, r5_unembedded),
        recall10: (r10_before, r10_after, r10_unembedded),
        rows_after_rollback,
        rollback_identical: compare_images(&before, &after, false),
        embedding_restored: compare_images(&before, &after, true).is_ok(),
        qa: qa_before.zip(qa_after),
    })
}

async fn run_stub(
    store: &dyn MemoryStore,
    backend: &'static str,
    threshold: f32,
    options: FlowOptions<'_>,
) -> Result<BenchResult> {
    let llm = CountedStubLlm::new();
    let result = run_flow(store, backend, &llm, &llm.calls, threshold, options).await?;
    Ok(result)
}

/// Assertions every deterministic run must satisfy at `expected_merges`
/// merged clusters of the known corpus.
fn assert_result(r: &BenchResult, expected_merges: usize, expected_rows_after: usize) {
    let total_rows: usize = CLUSTER_SIZES.iter().sum::<usize>() + DISTINCT_ROWS;
    assert_eq!(r.rows_before, total_rows, "{}", r.result_line());
    assert_eq!(r.rows_after, expected_rows_after, "{}", r.result_line());
    assert_eq!(r.llm_calls, expected_merges, "{}", r.result_line());
    assert_eq!(r.rollback_entries, expected_merges, "{}", r.result_line());
    assert_eq!(
        r.rows_after_rollback,
        total_rows,
        "rollback must restore the row count: {}",
        r.result_line()
    );
    assert_eq!(
        r.rollback_identical,
        Ok(()),
        "rollback must restore every original byte-identically: {}",
        r.result_line()
    );
    assert!(
        r.recall5.1.at_least(r.recall5.0) && r.recall10.1.at_least(r.recall10.0),
        "recall with embedded summaries must not fall below the pre-merge recall: {}",
        r.result_line()
    );
    assert!(
        r.recall5.0.at_least(r.recall5.2),
        "unembedded summaries cannot beat the pre-merge recall: {}",
        r.result_line()
    );
    let parsed = parse_result_line(&r.result_line()).expect("result line parses");
    assert_eq!(parsed.keys().count(), 17, "{}", r.result_line());
    assert_eq!(parsed[COL_ROWS_BEFORE], total_rows.to_string());
    assert_eq!(parsed[COL_ROWS_AFTER], expected_rows_after.to_string());
    assert_eq!(parsed["llm_calls"], expected_merges.to_string());
    assert_eq!(parsed[COL_ROLLBACK_IDENTICAL], "true");
    // #8465: rollback restores rows, not vectors. This flips when that is
    // fixed; then fold embeddings into `rollback_identical`.
    assert_eq!(
        parsed["embedding_restored"],
        EMBEDDING_RESTORED_TODAY.to_string()
    );
}

fn sqlite_store() -> Result<(crate::store::sqlite::SqliteStore, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let store = crate::store::sqlite::SqliteStore::open(&dir.path().join("bench6043.db"))?;
    Ok((store, dir))
}

// ---------------------------------------------------------------------------
// R2 — deterministic CI arm
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bench_6043_sqlite_default_threshold_shrinks_and_rolls_back() {
    let (store, _dir) = sqlite_store().expect(SQLITE_OPEN_MSG);
    let r = run_stub(
        &store,
        "sqlite",
        DEFAULT_THRESHOLD,
        FlowOptions {
            rollback: true,
            qa: None,
        },
    )
    .await
    .expect("flow");
    println!("{}", r.result_line());
    // 6 clusters merge: 41 rows -> 6 summaries + 20 distinct = 26 rows.
    assert_result(&r, CLUSTER_SIZES.len(), CLUSTER_SIZES.len() + DISTINCT_ROWS);
}

#[tokio::test]
async fn bench_6043_sqlite_threshold_sweep_matches_known_clusters() {
    // The loose cluster's two members sit at cosine ~0.80: merged at 0.70 and
    // 0.75, kept apart at 0.85.
    for (threshold, merges) in [(0.70_f32, 6usize), (0.75, 6), (0.85, 5)] {
        let (store, _dir) = sqlite_store().expect(SQLITE_OPEN_MSG);
        let r = run_stub(
            &store,
            "sqlite",
            threshold,
            FlowOptions {
                rollback: true,
                qa: None,
            },
        )
        .await
        .expect("flow");
        println!("{}", r.result_line());
        let loose_rows = if merges == 6 { 0 } else { CLUSTER_SIZES[5] };
        assert_result(&r, merges, merges + DISTINCT_ROWS + loose_rows);
    }
    assert_eq!(THRESHOLD_SWEEP.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bench_6043_postgres_default_threshold_shrinks_and_rolls_back() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip bench_6043_postgres: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    #[cfg(feature = "sal-postgres")]
    {
        let store = crate::store::postgres::PostgresStore::connect(&url)
            .await
            .expect("postgres connect");
        let r = run_stub(
            &store,
            "postgres",
            DEFAULT_THRESHOLD,
            FlowOptions {
                rollback: true,
                qa: None,
            },
        )
        .await
        .expect("flow");
        println!("{}", r.result_line());
        assert_result(&r, CLUSTER_SIZES.len(), CLUSTER_SIZES.len() + DISTINCT_ROWS);
    }
    #[cfg(not(feature = "sal-postgres"))]
    let _ = url;
}

#[test]
fn bench_6043_corpus_is_deterministic() {
    let a = build_corpus("ns");
    let b = build_corpus("ns");
    assert_eq!(a.rows.len(), b.rows.len());
    for (x, y) in a.rows.iter().zip(&b.rows) {
        assert_eq!(x.id, y.id);
        assert_eq!(x.content, y.content);
        let bits = |v: &[f32]| v.iter().map(|f| f.to_bits()).collect::<Vec<_>>();
        assert_eq!(bits(&x.vector), bits(&y.vector));
    }
    assert_eq!(
        a.topics.len(),
        CLUSTER_SIZES.len() + DISTINCT_QUERIES,
        "one topic per cluster plus the queried distinct rows"
    );
}

// ---------------------------------------------------------------------------
// The assertions must be able to fail (red-first evidence)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bench_6043_pass_with_rollback_disabled_fails_the_identity_check() {
    let (store, _dir) = sqlite_store().expect(SQLITE_OPEN_MSG);
    let r = run_stub(
        &store,
        "sqlite",
        DEFAULT_THRESHOLD,
        FlowOptions {
            rollback: false,
            qa: None,
        },
    )
    .await
    .expect("flow");
    let err = r
        .rollback_identical
        .expect_err("a consolidated store is not identical");
    assert!(err.0.contains("missing after rollback"), "{err:?}");
    assert_ne!(r.rows_after_rollback, r.rows_before);
}

fn image(id: &str) -> RowImage {
    RowImage {
        id: id.to_string(),
        namespace: "ns".to_string(),
        title: "t".to_string(),
        content: "c".to_string(),
        metadata: "{}".to_string(),
        tags: vec!["a".to_string()],
        embedding_bits: vec![1, 2, 3],
        embedding_space: Some("s".to_string()),
    }
}

#[test]
fn bench_6043_compare_images_detects_every_field() {
    let base = vec![Some(image("x"))];
    assert_eq!(compare_images(&base, &base, true), Ok(()));
    let tamper: [(&str, fn(&mut RowImage)); 6] = [
        ("content", |i| i.content.push('!')),
        ("metadata", |i| i.metadata = "{\"k\":1}".to_string()),
        ("embedding", |i| i.embedding_bits[2] ^= 1),
        (FIELD_EMBEDDING_SPACE, |i| i.embedding_space = None),
        ("tags", |i| i.tags.clear()),
        ("title", |i| i.title.push('x')),
    ];
    for (field, f) in tamper {
        let mut changed = image("x");
        f(&mut changed);
        let err = compare_images(&base, &[Some(changed)], true).expect_err(field);
        assert!(err.0.ends_with(&format!("differs in {field}")), "{err:?}");
    }
    assert!(compare_images(&base, &[None], true).is_err());
    assert!(compare_images(&base, &[], true).is_err());
}

#[test]
fn bench_6043_result_line_rejects_the_wrong_shape() {
    assert!(parse_result_line("rows_before=41").is_err());
    assert!(parse_result_line("bench_6043_result[1]{a,b}: 1").is_err());
    let parsed = parse_result_line("bench_6043_result[1]{a,b}: 1,2").expect("well formed");
    assert_eq!(parsed["b"], "2");
}

#[test]
fn bench_6043_ratio_orders_by_cross_multiplication() {
    let half = Ratio { hits: 1, total: 2 };
    let third = Ratio { hits: 1, total: 3 };
    assert!(half.at_least(third));
    assert!(!third.at_least(half));
    assert!(half.at_least(half));
}

// ---------------------------------------------------------------------------
// R3 — operator arm (real LLM, threshold sweep, JSON report)
// ---------------------------------------------------------------------------

async fn qa_score(
    store: &dyn MemoryStore,
    corpus: &Corpus,
    client: &crate::llm::OllamaClient,
) -> Result<Ratio> {
    let ctx = bench_ctx();
    let filter = Filter {
        namespace: Some(corpus.namespace.clone()),
        limit: LIST_LIMIT,
        ..Filter::default()
    };
    let rows = store.list(&ctx, &filter).await?;
    let mut pool: Vec<(Memory, Vec<f32>)> = Vec::new();
    for m in rows {
        if let Some((v, _)) = store.get_embedding_with_space(&ctx, &m.id).await? {
            pool.push((m, v));
        }
    }
    let (mut hits, mut total) = (0usize, 0usize);
    for topic in &corpus.topics {
        let mut ranked: Vec<(f32, &Memory)> = pool
            .iter()
            .map(|(m, v)| (Embedder::cosine_similarity(&topic.query, v), m))
            .collect();
        ranked.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id)));
        let notes: Vec<&str> = ranked
            .iter()
            .take(RECALL_SHALLOW_K)
            .map(|(_, m)| m.content.as_str())
            .collect();
        let prompt = format!(
            "Notes:\n- {}\n\nQuestion: {}\nAnswer with the code word only.",
            notes.join("\n- "),
            topic.question
        );
        let answer = client
            .generate_async(&prompt, Some("Answer only from the notes."))
            .await?;
        total += 1;
        if answer.to_lowercase().contains(&topic.fact) {
            hits += 1;
        }
    }
    Ok(Ratio { hits, total })
}

fn ratio_json(r: Ratio) -> serde_json::Value {
    serde_json::json!({ "hits": r.hits, "total": r.total, "value": r.value() })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "operator arm: needs a real LLM named by AI_MEMORY_LLM_* and writes .local-runs/"]
async fn bench_6043_real_llm_threshold_sweep() {
    let client = match crate::llm::OllamaClient::from_env() {
        Ok(Some(c)) => c,
        Ok(None) | Err(_) => {
            eprintln!("skip bench_6043_real_llm_threshold_sweep: no LLM configured");
            return;
        }
    };
    let mut runs = Vec::new();
    for threshold in THRESHOLD_SWEEP {
        let (store, _dir) = sqlite_store().expect(SQLITE_OPEN_MSG);
        let counted = CountedLlm {
            inner: &client,
            calls: AtomicUsize::new(0),
        };
        let r = run_flow(
            &store,
            "sqlite",
            &counted,
            &counted.calls,
            threshold,
            FlowOptions {
                rollback: true,
                qa: Some(&client),
            },
        )
        .await
        .expect("flow");
        println!("{}", r.result_line());
        let (qa_before, qa_after) = r.qa.expect("qa ran");
        runs.push(serde_json::json!({
            "cosine_threshold": f64::from(threshold),
            "rows_before": r.rows_before,
            "rows_after": r.rows_after,
            "shrink_pct": r.shrink_pct(),
            "recall_at_5": { "before": ratio_json(r.recall5.0), "after": ratio_json(r.recall5.1) },
            "recall_at_10": { "before": ratio_json(r.recall10.0), "after": ratio_json(r.recall10.1) },
            "qa_accuracy": { "before": ratio_json(qa_before), "after": ratio_json(qa_after) },
            "llm_calls": r.llm_calls,
            "wall_ms": u64::try_from(r.wall_ms).unwrap_or(u64::MAX),
            "rollback_entries": r.rollback_entries,
            "rollback_identical": r.rollback_identical.is_ok(),
        }));
    }
    let report = serde_json::json!({
        "benchmark": "6043-consolidation",
        "seed": BENCH_SEED,
        "synthetic": true,
        "llm_configured": true,
        "runs": runs,
    });
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/bench-6043");
    std::fs::create_dir_all(&dir).expect("create report dir");
    let path = dir.join("consolidation-report.json");
    std::fs::write(&path, serde_json::to_string_pretty(&report).expect("json"))
        .expect("write report");
    println!("bench_6043 report: {}", path.display());
}
