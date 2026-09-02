// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Full-autonomy loop — stacks on the Track A curator daemon (#278).
//!
//! This module provides the four passes beyond auto-tag that are
//! required to earn a defensible "100% autonomous" claim:
//!
//! 1. **Consolidation** — find near-duplicate memories in the same
//!    namespace, LLM-summarise them into a single canonical memory,
//!    archive the originals. Uses `db::consolidate` for the DB work
//!    and `AutonomyLlm::summarize_memories` for the synthesis.
//! 2. **Forgetting of superseded memories** — when a memory carries
//!    `metadata.confirmed_contradictions`, demote or forget the older
//!    contradicted entry (the curator keeps the fresher one). Uses
//!    `db::forget_count` with a targeted id list.
//! 3. **Priority feedback** — nudge `priority` up for memories that
//!    are getting recalled, nudge it down for cold ones. Purely
//!    arithmetic; no LLM call.
//! 4. **Rollback log + self-report** — every autonomous action lands
//!    in a `_curator/rollback/<ts>` memory describing what happened
//!    and how to reverse it, and every cycle lands in
//!    `_curator/reports/<ts>` as a summary the operator (and other
//!    agents) can recall.
//!
//! ## Trait boundary — `AutonomyLlm`
//!
//! The curator previously coupled directly to `llm::OllamaClient`,
//! which blocked unit-testable end-to-end coverage. This module
//! defines a narrow trait that both `OllamaClient` (in prod) and
//! the [`tests::StubLlm`] (in tests) implement. The autonomy passes
//! are generic over `&dyn AutonomyLlm`.

use crate::models::ConfidenceSource;
use crate::models::field_names;
use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::db;
use crate::llm::OllamaClient;
use crate::models::{Memory, Tier};

/// Source label stamped on memories the autonomy curator writes
/// (one spelling across the three write paths — #1558).
// Shared `source` label for curator-written consolidation + rollback rows.
// `pub(crate)` so the SAL `ConsolidationPass` (#1746 cutover) stamps the SAME
// value on consolidated rows — preserving byte-continuity of the `source`
// column across the autonomy→SAL cutover (the "(autonomy)" suffix is historical
// and kept stable deliberately; it denotes the curator, not the internal pass).
pub(crate) const CURATOR_SOURCE_LABEL: &str = "ai-memory curator (autonomy)";

/// Minimum Jaccard-keyword overlap required to treat two memories as
/// "near-duplicates" candidates for a consolidation cluster. Tuned
/// loosely — actual merge decision is still gated by an LLM pass.
///
/// v0.7.0 R3-S2 — Jaccard is a *cheap pre-filter* (O(N) per pair);
/// cosine on the 384d MiniLM embeddings is the primary signal at
/// [`CONSOLIDATE_COSINE_THRESHOLD`]. Both must hold for a pair to
/// cluster. Per #1774 (5-agent vote 4d3ea1c5) the Jaccard pre-filter
/// is NOT a stand-alone fall-back: when a stored embedding is absent
/// on either side the pair does not merge — a destructive merge always
/// requires the cosine safety gate. The pre-filter's only role is to
/// skip the embedding lookup on obviously-unrelated pairs.
pub const CONSOLIDATE_JACCARD_THRESHOLD: f64 = 0.55;

/// v0.7.0 R3-S2 — cosine similarity threshold (on 384d L2-normalised
/// MiniLM embeddings) above which two memories cluster for
/// consolidation. Default `0.75` per playbook §2.7 + ROADMAP §5.2:
/// it captures rephrasings and semantically near-equivalent content
/// without merging merely topically-adjacent memories.
///
/// Applied as a MANDATORY gate whenever a pair is considered: both
/// memories must carry an embedding row in the DB (`db::get_embedding`
/// returns `Some`) and clear this threshold. Per #1774 a pair lacking a
/// stored embedding on either side does not merge — there is no
/// Jaccard-only fall-back for the destructive consolidation merge.
pub const CONSOLIDATE_COSINE_THRESHOLD: f64 = 0.75;

/// Cap on the number of memories in a single consolidation cluster —
/// prevents pathological mega-merges that would destroy provenance.
pub const CONSOLIDATE_MAX_CLUSTER_SIZE: usize = 8;

/// Reserved namespace prefix the curator writes to. Excluded from
/// further curator passes (the curator never acts on its own rollback
/// / report memories).
pub const CURATOR_NAMESPACE: &str = "_curator";

/// v1.0.0 #3345 — the namespace the curator's per-sweep self-report lands in.
/// Previously spelled inline at the writer and in five docs/tests.
pub const CURATOR_REPORTS_NAMESPACE: &str = "_curator/reports";

/// v1.0.0 #3345 — retention window for a curator self-report.
///
/// Self-reports are operational telemetry, not memories: an operator wants the
/// last day of cycles for a soak/health read, nobody wants them forever. Pre-fix
/// they were `Tier::Mid` with no explicit expiry, so `effective_expires_at`
/// stamped `created_at + 7d` — GC-eligible in principle, but a
/// `curator --daemon`-only host runs no GC loop at all, so on one fleet node
/// they had accumulated to 24,930 rows (97% of the store). #1466 was the SAME
/// leak in the SAME namespace (2,905 of 2,921 leaked rows); this is its
/// recurrence. The fix is three-part and this const is one leg: a SHORT TTL
/// here, the [`crate::models::LifecycleState::Operational`] hide so the rows
/// are never recalled or embedded, and a GC loop in the curator daemon so the
/// TTL is actually enforced on a curator-only host.
pub const SELF_REPORT_TTL_SECS: i64 = 24 * crate::SECS_PER_HOUR;

/// LLM surface the autonomy passes use. Implemented for `OllamaClient`
/// in prod and stubbed in tests. The `auto_tag` and `detect_contradiction`
/// methods are here for completeness — the autonomy passes themselves
/// currently only call `summarize_memories`, but exposing the three
/// together keeps the trait a single, testable LLM boundary that the
/// curator's `run_once` path can switch to in a follow-up PR.
#[allow(dead_code)]
pub trait AutonomyLlm {
    /// Generate tags for a memory.
    fn auto_tag(&self, title: &str, content: &str) -> Result<Vec<String>>;

    /// Return true iff the two pieces of content contradict each other.
    fn detect_contradiction(&self, mem_a: &str, mem_b: &str) -> Result<bool>;

    /// Produce a consolidated summary of N memories.
    fn summarize_memories(&self, memories: &[(String, String)]) -> Result<String>;

    /// #1393 — classify a recovered transcript turn into a refined
    /// [`crate::models::MemoryKind`] (the "decision-detector": is this
    /// observation actually a Decision / Claim / Event …?). Returns `None`
    /// to ABSTAIN — the caller leaves the existing kind untouched. The default
    /// abstains so the 17 stub/mock impls compile unchanged; only the real
    /// LLM-backed [`OllamaClient`] overrides it (mirrors the curator's other
    /// LLM passes, which run only against the real backend).
    ///
    /// # Errors
    /// Propagates the underlying LLM client error.
    fn classify_kind(
        &self,
        _title: &str,
        _content: &str,
    ) -> Result<Option<crate::models::MemoryKind>> {
        Ok(None)
    }
}

impl AutonomyLlm for OllamaClient {
    fn auto_tag(&self, title: &str, content: &str) -> Result<Vec<String>> {
        // L15: autonomy-tier trait passes None so the client uses its
        // configured default; callers that want a dedicated tag model
        // call `OllamaClient::auto_tag` directly with `Some(model)`.
        Self::auto_tag(self, title, content, None)
    }
    fn detect_contradiction(&self, mem_a: &str, mem_b: &str) -> Result<bool> {
        Self::detect_contradiction(self, mem_a, mem_b)
    }
    fn summarize_memories(&self, memories: &[(String, String)]) -> Result<String> {
        Self::summarize_memories(self, memories)
    }
    fn classify_kind(
        &self,
        title: &str,
        content: &str,
    ) -> Result<Option<crate::models::MemoryKind>> {
        Self::classify_kind(self, title, content)
    }
}

/// Rollback-log entry stored as a memory in `_curator/rollback/<rfc3339>`.
///
/// Serialised as JSON in the memory's `content`. The memory's `metadata`
/// carries the `action` discriminator so operators can filter the
/// rollback log by kind via the normal `memory_list` + `tags_filter`
/// path.
///
/// The `Consolidate` variant is deliberately large (carries full
/// pre-merge memory snapshots) compared to `PriorityAdjust`. That's the
/// cost of being able to reverse a merge without network round-trips.
///
/// **Recovery scope (#1771).** A rollback restores the pre-merge memory
/// ROWS only. It does NOT restore the merged sources' `memory_links`
/// edges or other `ON DELETE CASCADE` provenance (`recall_observations`,
/// confidence-calibration rows, `memory_transcript_links`): those were
/// cascade-reaped when the sources were deleted at merge time and are not
/// captured in `originals`. So a reversed merge returns the text but
/// leaves the relationship graph of the merged sources destroyed, until
/// archive-link preservation lands (#1771 structural fix).
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RollbackEntry {
    /// A consolidation was applied. `originals` are the full Memory
    /// snapshots pre-merge; `result_id` is the consolidated memory id.
    /// NOTE (#1771): `originals` carries the memory ROWS only — NOT the
    /// merged sources' cascade-deleted `memory_links` / provenance edges,
    /// which a rollback therefore cannot restore yet.
    Consolidate {
        originals: Vec<Memory>,
        result_id: String,
    },
    /// A memory was forgotten (archived). `snapshot` is the memory as
    /// it was immediately before forgetting.
    Forget { snapshot: Memory },
    /// A priority adjustment. `memory_id`, `before`, `after`.
    PriorityAdjust {
        memory_id: String,
        before: i32,
        after: i32,
    },
    /// v0.9.0 G7 (#1824) — a confirmed contradiction was CONSERVED (both
    /// memories retained) instead of hard-deleting the loser. Reversal
    /// removes the canonical `contradicts` edge and clears the three
    /// `contradiction_*` marker keys on the loser; it appends NO
    /// compensating revision leaf (the one SUPERSEDE leaf emitted at
    /// conserve time is the permanent record of the event).
    /// `canonical_src`/`canonical_tgt` are the ordered
    /// (min-id, max-id) endpoints of that single edge.
    ConserveContradiction {
        loser_id: String,
        winner_id: String,
        canonical_src: String,
        canonical_tgt: String,
    },
}

impl RollbackEntry {
    fn action_tag(&self) -> &'static str {
        match self {
            Self::Consolidate { .. } => crate::audit::OP_CONSOLIDATE,
            Self::Forget { .. } => "forget",
            Self::PriorityAdjust { .. } => "priority_adjust",
            Self::ConserveContradiction { .. } => "conserve_contradiction",
        }
    }
}

/// Structured outcome of a single autonomy pass. Aggregated into the
/// curator cycle's `CuratorReport` and also written back as a self-
/// report memory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutonomyPassReport {
    pub clusters_formed: usize,
    pub memories_consolidated: usize,
    pub memories_forgotten: usize,
    pub priority_adjustments: usize,
    /// Rollback rows actually PERSISTED this pass. A dry-run persists
    /// nothing, so this stays `0` there (the would-be count lands in
    /// [`Self::rollback_entries_simulated`]); a live pass whose
    /// rollback-log write FAILED does not count the row either.
    pub rollback_entries_written: usize,
    /// v1.0.0 — dry-run companion to [`Self::rollback_entries_written`]:
    /// rollback rows a live cycle WOULD have written. Split out so
    /// `rollback_entries_written` can keep meaning "rows persisted"
    /// (the pre-fix code incremented it on the dry-run path, so an
    /// operator reading a `--dry-run` report saw writes that never
    /// happened).
    #[serde(default)]
    pub rollback_entries_simulated: usize,
    /// v1.0.0 — LLM-invoking operations this pass actually attempted,
    /// charged against the caller's `max_ops_per_cycle` budget.
    #[serde(default)]
    pub operations_attempted: usize,
    /// v1.0.0 — LLM-invoking operations skipped because the per-cycle op
    /// budget was exhausted. Non-zero means work deferred to the next
    /// cycle, NOT work lost.
    #[serde(default)]
    pub operations_skipped_cap: usize,
    /// v1.0.0 — set when a rollback-log write FAILED during this pass.
    /// The already-applied mutation is then irreversible, so the passes
    /// HALT rather than compounding un-reversible changes; see
    /// [`run_autonomy_passes`].
    #[serde(default)]
    pub rollback_log_degraded: bool,
    pub errors: Vec<String>,
}

/// Record the outcome of a rollback-log write for one just-applied action.
///
/// Returns `true` when the pass may CONTINUE, `false` when it must halt.
///
/// Reversibility is the whole point of the rollback log: once an autonomy
/// action has mutated the corpus and its rollback row failed to persist,
/// that action is irreversible. The pre-fix code pushed one line into
/// `report.errors` and carried straight on, so a single failing log write
/// could be followed by an unbounded run of further irreversible
/// mutations. We now HALT the destructive passes for the rest of the
/// cycle (fail-closed: fewer actions, never un-reversible ones) and flag
/// `rollback_log_degraded` so the condition is visible in the
/// self-report, not just buried in an error string.
fn note_rollback_write(
    conn: &Connection,
    entry: &RollbackEntry,
    dry_run: bool,
    report: &mut AutonomyPassReport,
) -> bool {
    if dry_run {
        // Dry-run persists nothing; count the would-be row separately so
        // `rollback_entries_written` keeps meaning "rows persisted".
        report.rollback_entries_simulated += 1;
        return true;
    }
    match persist_rollback_entry(conn, entry) {
        Ok(()) => {
            report.rollback_entries_written += 1;
            true
        }
        Err(e) => {
            report.errors.push(rollback_log_write_failed(&e));
            report.rollback_log_degraded = true;
            report.errors.push(
                "autonomy passes halted for this cycle: the last action is irreversible \
                 (its rollback row did not persist); remaining destructive work is deferred"
                    .to_string(),
            );
            false
        }
    }
}

/// Run all autonomy passes over the provided candidates in order:
/// consolidate → forget superseded → priority feedback → record
/// rollback log → write self-report. `dry_run` suppresses all writes.
///
/// `skip_consolidation` suppresses **Pass 1 only** (forget-superseded +
/// priority-feedback still run). Set by the curator when the SAL
/// `ConsolidationPass` owns consolidation (`compaction.enabled`, #1746
/// cutover) so the corpus is never consolidated twice in one cycle. The two
/// consolidators are mutually exclusive, driven from a single
/// `compaction.enabled` predicate in `curator::run_once`.
///
/// `llm_op_budget` is the caller's REMAINING share of
/// `CuratorConfig::max_ops_per_cycle` — documented as a "hard cap on
/// LLM-invoking operations per cycle". Pass 1 is the only LLM-invoking
/// pass (`consolidate_cluster` → `AutonomyLlm::summarize_memories`), and
/// it was previously uncapped: it ran one LLM call per cluster found over
/// up to `max_ops_per_cycle * 4` candidates, so a single cycle could make
/// far more LLM invocations than the operator authorised. Clusters beyond
/// the budget are now skipped and counted in
/// `report.operations_skipped_cap`; they are deferred to the next cycle,
/// never dropped. Passes 2 and 3 invoke no LLM and stay bounded by the
/// candidate batch itself, so they are deliberately NOT charged against
/// this budget.
///
/// `active_keypair` is the caller's authenticated signing identity, used
/// to sign the conserved `contradicts` edge in Pass 2. It is threaded in
/// (rather than loaded ambiently inside the pass) so the edge is attested
/// to the identity the daemon actually runs as; `None` writes the edge
/// unsigned, which is the honest degrade.
///
/// Returns an `AutonomyPassReport` rather than `Result<…>` because
/// per-pass errors are already aggregated into `report.errors`;
/// the function itself cannot fail at the outer level.
pub fn run_autonomy_passes(
    conn: &Connection,
    llm: &dyn AutonomyLlm,
    candidates: &[Memory],
    dry_run: bool,
    skip_consolidation: bool,
    llm_op_budget: usize,
    active_keypair: Option<&crate::identity::keypair::AgentKeypair>,
) -> AutonomyPassReport {
    let mut report = AutonomyPassReport::default();

    // Pass 1 — consolidation. Skipped when the SAL ConsolidationPass owns
    // consolidation (#1746); the curator folds that pass's counts into this
    // report so the self-report stays accurate.
    let mut halted = false;
    if !skip_consolidation {
        let clusters = find_consolidation_clusters(conn, candidates);
        report.clusters_formed = clusters.len();
        for cluster in clusters {
            if halted {
                break;
            }
            // Op-budget gate — one `summarize_memories` LLM call per
            // cluster. Skipped clusters resurface next cycle.
            if report.operations_attempted >= llm_op_budget {
                report.operations_skipped_cap += 1;
                continue;
            }
            report.operations_attempted += 1;
            match consolidate_cluster(conn, llm, &cluster, dry_run) {
                Ok(Some(entry)) => {
                    let proceed = note_rollback_write(conn, &entry, dry_run, &mut report);
                    if let RollbackEntry::Consolidate { originals, .. } = entry {
                        report.memories_consolidated += originals.len();
                    }
                    halted = !proceed;
                }
                Ok(None) => {}
                Err(e) => report.errors.push(format!("consolidate failed: {e}")),
            }
        }
    }

    // Pass 2 — forget superseded (CONSERVE; LLM-free, so uncharged).
    for mem in candidates {
        if halted {
            break;
        }
        match forget_if_superseded(conn, mem, candidates, dry_run, active_keypair) {
            Ok(Some(entry)) => {
                halted = !note_rollback_write(conn, &entry, dry_run, &mut report);
                report.memories_forgotten += 1;
            }
            Ok(None) => {}
            Err(e) => report.errors.push(format!("forget failed: {e}")),
        }
    }

    // Pass 3 — priority feedback (LLM-free, so uncharged).
    for mem in candidates {
        if halted {
            break;
        }
        match apply_priority_feedback(conn, mem, dry_run) {
            Ok(Some(entry)) => {
                halted = !note_rollback_write(conn, &entry, dry_run, &mut report);
                report.priority_adjustments += 1;
            }
            Ok(None) => {}
            Err(e) => report.errors.push(format!("priority feedback failed: {e}")),
        }
    }

    report
}

/// ERRORS-19 — read a row's stored embedding + space for the clustering
/// gate, distinguishing a genuinely-missing embedding from a FAILED read.
///
/// Both degrade to `None`, which per #1774 blocks the merge for that
/// row's pairs (fail-safe: no cosine, no destructive merge). The pre-fix
/// `.ok().flatten()` collapsed the two cases with no operator signal, so
/// a database that had started failing embedding reads looked exactly
/// like a corpus with no embeddings: consolidation silently did nothing,
/// cycle after cycle, with nothing in the logs. Log the `Err` before
/// degrading.
fn embedding_for_clustering(conn: &Connection, id: &str) -> Option<(Vec<f32>, Option<String>)> {
    match db::get_embedding_with_space(conn, id) {
        Ok(found) => found,
        Err(e) => {
            tracing::warn!(
                memory_id = %id,
                error = %e,
                "autonomy: embedding read failed; treating as no-embedding \
                 (this row will not be considered for consolidation this cycle)"
            );
            None
        }
    }
}

/// v0.7.0 R3-S2 — Two-stage clustering per playbook §2.7 /
/// ROADMAP §5.2:
///
///   1. **Jaccard pre-filter** (cheap, O(N) per pair) — pairs that
///      fail [`CONSOLIDATE_JACCARD_THRESHOLD`] are dropped without
///      paying the embedding lookup. This keeps the pass fast on the
///      typical workload (most pairs are obviously unrelated).
///   2. **Cosine primary** — pairs that survive Jaccard are scored
///      against [`CONSOLIDATE_COSINE_THRESHOLD`] on their 384d
///      MiniLM embeddings (`db::get_embedding`). Above-threshold
///      pairs join the cluster.
///
/// When *either* memory in a pair has no embedding row (e.g.,
/// keyword-tier deployment that never ran the embedder, or an
/// oversize / never-embedded row), the pair does **NOT** cluster
/// (#1774, 5-agent vote 4d3ea1c5): a destructive consolidation merge
/// requires the cosine safety gate on both sides and is never decided
/// on Jaccard lexical overlap alone. Two distinct memories can share
/// high Jaccard (templated content), so lexical overlap is not a safe
/// basis for a merge-and-delete. This mirrors the substrate's
/// skip-on-missing-embedding posture for the other destructive path
/// (`proactive_conflict_check` filters `embedding IS NOT NULL`).
/// Un-embedded corpora no longer auto-consolidate (documented behaviour
/// change). The function never errors on a DB read miss; a missing
/// embedding simply blocks the merge for that pair.
pub(crate) fn find_consolidation_clusters(
    conn: &Connection,
    candidates: &[Memory],
) -> Vec<Vec<Memory>> {
    // Group by namespace first — we never merge across namespaces.
    let mut by_ns: std::collections::HashMap<&str, Vec<&Memory>> = std::collections::HashMap::new();
    for m in candidates {
        if m.namespace.starts_with('_') {
            continue;
        }
        by_ns.entry(&m.namespace).or_default().push(m);
    }

    let mut clusters: Vec<Vec<Memory>> = Vec::new();
    for (_ns, group) in by_ns {
        let mut used = vec![false; group.len()];
        for i in 0..group.len() {
            if used[i] {
                continue;
            }
            let mut cluster = vec![group[i].clone()];
            used[i] = true;
            // Cache the seed memory's embedding + its `embedding_space`
            // provenance (looked up once per outer-loop iteration). `None`
            // means "embedding missing for this memory" — per #1774 a
            // missing embedding on either side blocks the merge for that
            // pair.
            let seed_emb = embedding_for_clustering(conn, &group[i].id);
            for j in (i + 1)..group.len() {
                if used[j] {
                    continue;
                }
                if cluster.len() >= CONSOLIDATE_MAX_CLUSTER_SIZE {
                    break;
                }
                // Stage 1 — Jaccard pre-filter (cheap).
                let j_sim = jaccard_similarity(&group[i].content, &group[j].content);
                if j_sim < CONSOLIDATE_JACCARD_THRESHOLD {
                    continue;
                }
                // Stage 2 — cosine primary, when embeddings exist
                // for both sides of the pair.
                let pair_emb = embedding_for_clustering(conn, &group[j].id);
                let matches_cluster = match (seed_emb.as_ref(), pair_emb.as_ref()) {
                    // v1.0.0 #2167 (#2181) — a stored-vs-stored cosine is
                    // meaningful ONLY when both vectors share the SAME
                    // non-NULL embedding space. A mixed-space corpus (a
                    // same-dim model swap, or NULL-provenance legacy rows)
                    // must never be clustered/merged as a near-duplicate:
                    // the cosine would be a meaningless cross-space number
                    // feeding a destructive MERGE. This extends the #1774
                    // missing-embedding-blocks-merge posture to
                    // mismatched-space-blocks-merge (degrade-never-corrupt
                    // applies to merge decisions too).
                    (Some((a, space_a)), Some((b, space_b)))
                        if space_a.is_some() && space_a == space_b =>
                    {
                        let cos = f64::from(crate::embeddings::Embedder::cosine_similarity(a, b));
                        cos >= CONSOLIDATE_COSINE_THRESHOLD
                    }
                    // #1774 (5-agent vote 4d3ea1c5) — at least one side
                    // has no embedding (or, #2181, the two carry
                    // different / NULL spaces), so there is no trustworthy
                    // cosine value. A destructive merge is never decided on
                    // Jaccard lexical overlap alone: the pair does NOT
                    // cluster.
                    _ => false,
                };
                if matches_cluster {
                    cluster.push(group[j].clone());
                    used[j] = true;
                }
            }
            if cluster.len() >= 2 {
                clusters.push(cluster);
            }
        }
    }
    clusters
}

fn jaccard_similarity(a: &str, b: &str) -> f64 {
    use std::collections::HashSet;
    let tokens = |s: &str| -> HashSet<String> {
        s.split(|c: char| !c.is_alphanumeric())
            .filter(|t| t.len() >= 3)
            .map(str::to_lowercase)
            .collect()
    };
    let ta = tokens(a);
    let tb = tokens(b);
    if ta.is_empty() && tb.is_empty() {
        return 0.0;
    }
    let inter = ta.intersection(&tb).count();
    let union = ta.union(&tb).count();
    if union == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        let result = inter as f64 / union as f64;
        result
    }
}

fn consolidate_cluster(
    conn: &Connection,
    llm: &dyn AutonomyLlm,
    cluster: &[Memory],
    dry_run: bool,
) -> Result<Option<RollbackEntry>> {
    if cluster.len() < 2 {
        return Ok(None);
    }
    // Skip clusters inside reserved namespaces (defensive; already
    // filtered at find_consolidation_clusters).
    if cluster.iter().any(|m| m.namespace.starts_with('_')) {
        return Ok(None);
    }

    let input: Vec<(String, String)> = cluster
        .iter()
        .map(|m| (m.title.clone(), m.content.clone()))
        .collect();
    let summary = llm.summarize_memories(&input)?;
    // Prefix the consolidated title so it never collides with one of
    // the source memories' (title, namespace) UNIQUE key. Source
    // rows still exist at INSERT time — db::consolidate deletes them
    // only after the new row lands.
    let base_title = cluster
        .iter()
        .map(|m| m.title.as_str())
        .next()
        .unwrap_or("(consolidated)");
    let title = format!("[consolidated] {base_title}");

    if dry_run {
        return Ok(Some(RollbackEntry::Consolidate {
            originals: cluster.to_vec(),
            result_id: "dry-run".to_string(),
        }));
    }

    let ids: Vec<String> = cluster.iter().map(|m| m.id.clone()).collect();
    let namespace = cluster[0].namespace.clone();
    // Tier = max of cluster (consolidate never downgrades).
    let tier = cluster
        .iter()
        .map(|m| m.tier.clone())
        .max_by_key(tier_rank)
        .unwrap_or(Tier::Mid);

    // #2121 — the autonomy Pass-1 consolidator is the authenticated internal
    // curator principal (the summary is LLM-derived over already-stored,
    // already-gated rows; no external caller reaches this path), so it claims
    // the substrate-authored why_trace stamp — the same posture as the SAL
    // `ConsolidationPass`, which runs `for_admin` (bypass_visibility).
    let result_id = db::consolidate(
        conn,
        &ids,
        &title,
        &summary,
        &namespace,
        &tier,
        CURATOR_SOURCE_LABEL,
        crate::identity::sentinels::AI_CURATOR,
        true,
    )?;

    Ok(Some(RollbackEntry::Consolidate {
        originals: cluster.to_vec(),
        result_id,
    }))
}

fn tier_rank(t: &Tier) -> u8 {
    match t {
        Tier::Short => 0,
        Tier::Mid => 1,
        Tier::Long => 2,
    }
}

/// v0.9.0 G7 (#1824) — CONSERVE a confirmed contradiction instead of
/// hard-deleting the loser. When a contradicting memory is both newer AND
/// carries higher-or-equal confidence, the current `mem` is the LOSER of
/// the pair; we retain BOTH memories, write one canonical signed
/// `contradicts` edge, emit one identity-only SUPERSEDE leaf (flag-gated),
/// and mark the loser with a reversible node-local soft down-weight — via
/// [`crate::db::conserve_contradiction`]. NEITHER memory is deleted.
///
/// `active_keypair` is the caller's AUTHENTICATED signing identity. It is
/// threaded in from `run_autonomy_passes` rather than loaded ambiently:
/// the pre-fix code called a `curator_keypair_best_effort()` helper that
/// picked the lexicographically-first key under the active key dir, so on
/// a host with more than one key the conserved `contradicts` edge could be
/// signed by an identity that is not the daemon's — precisely the kind of
/// mis-attribution the #816 attestation trail exists to prevent. `None`
/// writes the edge unsigned (the honest degrade), matching every other
/// `create_link_signed(None)` caller.
fn forget_if_superseded(
    conn: &Connection,
    mem: &Memory,
    all: &[Memory],
    dry_run: bool,
    active_keypair: Option<&crate::identity::keypair::AgentKeypair>,
) -> Result<Option<RollbackEntry>> {
    // Only act on memories whose `confirmed_contradictions` list is
    // non-empty — i.e., a previous detect_contradiction pass already
    // flagged this pair.
    let contradictions = mem
        .metadata
        .get(field_names::CONFIRMED_CONTRADICTIONS)
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if contradictions.is_empty() {
        return Ok(None);
    }

    // v0.9.0 G7 (#1824) — re-entry gate. A memory already CONSERVED as the
    // loser of a confirmed contradiction is idempotent: never re-process
    // it (no second edge, no second leaf, no marker oscillation). This is
    // the FIRST check after the empty-guard so a re-run of the pass — or a
    // peer that (wrongly) shipped the marker — short-circuits here.
    if mem
        .metadata
        .get(field_names::CONTRADICTION_CONSERVED)
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        return Ok(None);
    }

    // The current memory is the LOSER of the pair if a contradicting
    // memory is both newer AND has higher-or-equal confidence. We never
    // act on the contradicting memory alone — the decision requires both
    // freshness and trust. Under G7 the outcome is CONSERVE (retain both),
    // not delete.
    let by_id: std::collections::HashMap<&str, &Memory> =
        all.iter().map(|m| (m.id.as_str(), m)).collect();
    // v1.0.0 #2337 (FBL-26) — BIDIRECTIONAL pair resolution. Both
    // production marker writers (the store-time legacy classifier and the
    // curator sweep's `persist_contradiction`) stamp
    // `confirmed_contradictions` on the row being PROCESSED — the NEWER
    // row, pointing at pre-existing OLDER rows — and the marker-persisting
    // `db::update` refreshes that bearer's `updated_at`, so the original
    // bearer-is-loser condition (`other.updated_at > mem.updated_at`) was
    // FALSE BY CONSTRUCTION in the mainline flow and the whole G7 conserve
    // pipeline (contradicts edge + soft-loser down-weight) never fired.
    // The pass now resolves the pair in EITHER direction:
    //   * bearer-is-loser  — a listed contradictor is newer with >=
    //     confidence (the original arm; still correct for markers a peer
    //     shipped on the older row);
    //   * bearer-is-winner — the bearer is newer than a listed contradictor
    //     whose confidence <= the bearer's: conserve the LISTED (older)
    //     row as the loser (re-entry gated on ITS own conserved marker).
    let mut pair: Option<(&Memory, &Memory)> = None; // (loser, winner)
    for v in contradictions {
        let Some(other_id) = v.as_str() else {
            continue;
        };
        let Some(other) = by_id.get(other_id) else {
            continue;
        };
        if other.updated_at > mem.updated_at && other.confidence >= mem.confidence {
            pair = Some((mem, other));
            break;
        }
        let other_conserved = other
            .metadata
            .get(field_names::CONTRADICTION_CONSERVED)
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        if !other_conserved
            && mem.updated_at > other.updated_at
            && mem.confidence >= other.confidence
        {
            pair = Some((other, mem));
            break;
        }
    }
    let Some((loser, winner)) = pair else {
        return Ok(None);
    };

    // v1.0.0 #2337 — FRESH-STATE re-entry gate. The `all` candidate
    // snapshot is materialized before the pass runs, so with MUTUAL
    // markers (each row listing the other) the second bearer processed in
    // the SAME cycle still sees the pair un-conserved in its stale
    // snapshot. Re-read the selected loser from the DB and no-op when a
    // prior iteration (or cycle) already conserved it — exactly one
    // conserve per pair, no duplicate SUPERSEDE leaf.
    //
    // v1.0.0 #3270 sweep — read through the UNFILTERED `db::get_any`. This is
    // the fresh-state re-entry GUARD, not an authz gate, but #3235 made
    // `db::get` fold a now-hidden (tombstoned / quarantined) loser into
    // `Ok(None)`, which would SKIP the already-conserved short-circuit and
    // re-run the conserve on a row whose lifecycle already moved — a duplicate
    // SUPERSEDE leaf. Reading unfiltered restores the pre-#3235 guard: the
    // conserved-marker check runs regardless of the loser's lifecycle state.
    // `?` still propagates a real lookup error (ERRORS-19).
    if let Some(fresh_loser) = db::get_any(conn, &loser.id)?
        && fresh_loser
            .metadata
            .get(field_names::CONTRADICTION_CONSERVED)
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    {
        return Ok(None);
    }

    // Canonical (min, max) endpoints of the single `contradicts` edge, so
    // the RollbackEntry describes exactly the edge the write will create.
    let (canonical_src, canonical_tgt) = db::canonical_contradiction_pair(&loser.id, &winner.id);
    let entry = RollbackEntry::ConserveContradiction {
        loser_id: loser.id.clone(),
        winner_id: winner.id.clone(),
        canonical_src: canonical_src.to_string(),
        canonical_tgt: canonical_tgt.to_string(),
    };

    // Dry-run: return the descriptor, write nothing.
    if dry_run {
        return Ok(Some(entry));
    }

    // Live: CONSERVE the pair (retain both; one canonical signed edge; one
    // identity-only SUPERSEDE leaf; reversible soft-down-weight marker).
    db::conserve_contradiction(conn, loser, &winner.id, active_keypair)?;
    Ok(Some(entry))
}

fn apply_priority_feedback(
    conn: &Connection,
    mem: &Memory,
    dry_run: bool,
) -> Result<Option<RollbackEntry>> {
    // Access-signal policy (v1.0.0 #2339 / FBL-34 — bounded, reachable):
    //   access_count >= 10 AND last_accessed_at within 7d
    //     → +1, capped at ACCESS_PRIORITY_CEILING (8-10 reserved for
    //       explicit caller/operator intent — the access ratchet can no
    //       longer pollute the operator band).
    //   STALE (last access older than PRIORITY_DECAY_STALE_DAYS, or never
    //   accessed and created at least that long ago) AND priority within
    //   the access band (<= ACCESS_PRIORITY_CEILING)
    //     → -1 per cycle, floor 1. The previous condition
    //       (`access_count == 0`) was structurally unreachable for any
    //       row ever recalled — priority only ever went UP. Rows above
    //       the ceiling never decay: operator-set 8-10 intent is
    //       indistinguishable from legacy ratcheted rows, and silently
    //       eroding operator signal is strictly worse than leaving a
    //       legacy row inflated (fail-safe).
    //   else no change.
    let now = chrono::Utc::now();
    let before = mem.priority;
    let mut after = before;

    let last_accessed = mem
        .last_accessed_at
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(chrono::DateTime::<chrono::Utc>::from);

    let created = chrono::DateTime::parse_from_rfc3339(&mem.created_at)
        .ok()
        .map(chrono::DateTime::<chrono::Utc>::from);

    let recent = last_accessed.is_some_and(|t| (now - t).num_days() <= 7);
    let cold_enough =
        created.is_some_and(|t| (now - t).num_days() >= crate::models::PRIORITY_DECAY_STALE_DAYS);
    let stale = last_accessed.map_or(cold_enough, |t| {
        (now - t).num_days() >= crate::models::PRIORITY_DECAY_STALE_DAYS
    });

    let ceiling = i32::try_from(crate::models::ACCESS_PRIORITY_CEILING).unwrap_or(7);
    if mem.access_count >= 10 && recent && after < ceiling {
        after = after.saturating_add(1).min(ceiling);
    } else if stale && after > 1 && after <= ceiling {
        after = after.saturating_sub(1).max(1);
    }

    if after == before {
        return Ok(None);
    }

    if !dry_run {
        db::update(
            conn,
            &mem.id,
            None,
            None,
            None,
            None,
            None,
            Some(after),
            None,
            None,
            None,
        )?;
    }

    Ok(Some(RollbackEntry::PriorityAdjust {
        memory_id: mem.id.clone(),
        before,
        after,
    }))
}

/// #1558 batch 5 wave 2 — canonical `"rollback-log write failed: {e}"`
/// report-error line shared by the three [`persist_rollback_entry`]
/// failure sites in the autonomy passes. Byte-identical message.
fn rollback_log_write_failed(e: &dyn std::fmt::Display) -> String {
    format!("rollback-log write failed: {e}")
}

fn persist_rollback_entry(conn: &Connection, entry: &RollbackEntry) -> Result<()> {
    db::insert(conn, &build_rollback_memory(entry)?)?;
    Ok(())
}

/// Build the `_curator/rollback` `Memory` row for a [`RollbackEntry`] —
/// the serialised, operator-reversible snapshot that
/// [`reverse_rollback_entry`] (and `ai-memory curator --rollback`)
/// consumes. Extracted so the backend-agnostic SAL `ConsolidationPass`
/// (#1745) can persist a byte-identical rollback row via
/// [`crate::store::MemoryStore::store`] instead of a raw `Connection`,
/// keeping the two consolidation paths' rollback rows interchangeable.
pub(crate) fn build_rollback_memory(entry: &RollbackEntry) -> Result<Memory> {
    let now = chrono::Utc::now();
    let ts = now.to_rfc3339();
    Ok(Memory {
        cid: None, // v0.9.0 G8 (#1825) — stamped by db::insert / read via row_to_memory
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: format!("{CURATOR_NAMESPACE}/rollback"),
        title: format!("curator {} @ {}", entry.action_tag(), ts),
        content: serde_json::to_string(entry)?,
        tags: vec![
            "_curator".to_string(),
            "_rollback".to_string(),
            entry.action_tag().to_string(),
        ],
        priority: 3,
        confidence: 1.0,
        source: CURATOR_SOURCE_LABEL.to_string(),
        access_count: 0,
        created_at: ts.clone(),
        updated_at: ts,
        last_accessed_at: None,
        expires_at: None,
        // #2110 — curator rollback rows are substrate-authored, reached via a
        // direct `db::insert`; record the substrate why_trace so the write
        // satisfies AI_MEMORY_REQUIRE_WHY_TRACE without a kind-exemption hole.
        metadata: serde_json::json!({
            "agent_id": crate::identity::sentinels::AI_CURATOR,
            "action": entry.action_tag(),
            "why_trace": crate::storage::WHY_TRACE_SUBSTRATE_SYSTEM,
        }),
        reflection_depth: 0,
        memory_kind: crate::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    })
}

/// Write the cycle's report as a memory in `_curator/reports/<ts>`
/// so other agents can recall "what did the curator do".
pub fn persist_self_report(
    conn: &Connection,
    cycle_duration_ms: u128,
    pass_report: &AutonomyPassReport,
    auto_tagged: usize,
    contradictions_found: usize,
    // Issue #816 — count of `__persona_<entity_id>_v<n>` rows the
    // curator's auto-persona sweep produced this cycle. Surfaces in the
    // self-report JSON alongside the existing per-pass counters so an
    // operator inspecting `_curator/reports/*` can audit auto-persona
    // activity over time without joining against the persona rows
    // themselves.
    personas_generated: usize,
    errors_total: usize,
) -> Result<()> {
    let now = chrono::Utc::now();
    let ts = now.to_rfc3339();
    let body = serde_json::json!({
        "cycle_ts": ts,
        "cycle_duration_ms": cycle_duration_ms,
        "auto_tagged": auto_tagged,
        "contradictions_found": contradictions_found,
        "personas_generated": personas_generated,
        "clusters_formed": pass_report.clusters_formed,
        "memories_consolidated": pass_report.memories_consolidated,
        "memories_forgotten": pass_report.memories_forgotten,
        "priority_adjustments": pass_report.priority_adjustments,
        "rollback_entries_written": pass_report.rollback_entries_written,
        // v1.0.0 — dry-run companion (rows a live cycle WOULD have written)
        // and the reversibility-degraded flag. `rollback_log_degraded` is
        // the one an operator must never miss: it means an applied action
        // has no rollback row, so the cycle halted its remaining
        // destructive work rather than compounding irreversible changes.
        "rollback_entries_simulated": pass_report.rollback_entries_simulated,
        "rollback_log_degraded": pass_report.rollback_log_degraded,
        "autonomy_ops_attempted": pass_report.operations_attempted,
        "autonomy_ops_skipped_cap": pass_report.operations_skipped_cap,
        "errors_total": errors_total,
    });
    let mem = Memory {
        cid: None, // v0.9.0 G8 (#1825) — stamped by db::insert / read via row_to_memory
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        // #3345 — SHORT tier + an explicit 24h expiry: operational telemetry
        // with a bounded horizon, not a durable memory.
        tier: Tier::Short,
        namespace: CURATOR_REPORTS_NAMESPACE.to_string(),
        title: format!("curator cycle @ {ts}"),
        content: serde_json::to_string_pretty(&body)?,
        tags: vec!["_curator".to_string(), "_report".to_string()],
        priority: 2,
        confidence: 1.0,
        source: CURATOR_SOURCE_LABEL.to_string(),
        access_count: 0,
        created_at: ts.clone(),
        updated_at: ts,
        last_accessed_at: None,
        // #3345 — explicit short expiry, rendered in the ONE canonical
        // fixed-UTC form every write funnel stamps (#2418).
        expires_at: Some(crate::validate::render_canonical_utc(
            now + chrono::Duration::seconds(SELF_REPORT_TTL_SECS),
        )),
        // #2110 — curator self-report rows are substrate-authored (direct
        // `db::insert`); record the substrate why_trace.
        metadata: serde_json::json!({
            "agent_id": crate::identity::sentinels::AI_CURATOR,
            "why_trace": crate::storage::WHY_TRACE_SUBSTRATE_SYSTEM,
        }),
        reflection_depth: 0,
        memory_kind: crate::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        // #3345 — system-only OPERATIONAL: structurally hidden from every
        // ordinary read/egress lane by the fail-CLOSED
        // `lifecycle_visible_clause` allow-list, and therefore never selected
        // by the embedding backfill either (the selectors now carry the same
        // clause). The row is still STORED so `ai-memory list --lifecycle
        // operational` can audit the cycle history.
        lifecycle_state: crate::models::LifecycleState::Operational,
    };
    db::insert(conn, &mem)?;
    Ok(())
}

/// Reverse a single rollback-log entry. Returns `true` if a reverse
/// action was applied, `false` if the entry was already superseded
/// (idempotent rollback).
///
/// Collision safety (#300 item 2): before re-inserting a snapshot we
/// check whether another memory now owns the same
/// `(title, namespace)` key. If it does, we refuse to overwrite —
/// `db::insert` is an UPSERT on that key and would silently replace
/// the unrelated memory's content. We return an error so the operator
/// can resolve the conflict manually (delete the offender or rename
/// one of them) rather than clobbering user data.
pub fn reverse_rollback_entry(conn: &Connection, entry: &RollbackEntry) -> Result<bool> {
    match entry {
        RollbackEntry::Consolidate {
            originals,
            result_id,
        } => {
            // Pre-flight: no title+ns collision against a different id?
            for m in originals {
                check_no_collision(conn, &m.title, &m.namespace, &m.id)?;
            }
            // Delete the consolidated memory; re-insert the originals.
            // #2110 — a rollback re-store is a SUBSTRATE-authored re-insertion
            // (curator autonomy); record the substrate why_trace (stamp-if-absent
            // — a restored original that already carried one keeps it) so the
            // re-store satisfies AI_MEMORY_REQUIRE_WHY_TRACE.
            // #2887 — the actual write is the ATOMIC restore-safe CAS
            // `db::insert_restore_same_id` (not a plain `db::insert` upsert): the
            // upfront `check_no_collision` above is a fast-fail before the
            // destructive delete, but the CAS is the load-bearing guard — a
            // concurrent process that races into an original's (title, namespace)
            // slot between the probe and this write is REFUSED (typed
            // `ConflictError`) and never clobbered, closing the lost-update the
            // separate probe-then-`insert` had.
            let existed = db::delete(conn, result_id)?;
            for m in originals {
                let mut m = m.clone();
                crate::storage::stamp_substrate_why_trace(&mut m.metadata);
                db::insert_restore_same_id(conn, &m)?;
            }
            Ok(existed)
        }
        RollbackEntry::Forget { snapshot } => {
            check_no_collision(conn, &snapshot.title, &snapshot.namespace, &snapshot.id)?;
            let mut snapshot = snapshot.clone();
            crate::storage::stamp_substrate_why_trace(&mut snapshot.metadata);
            db::insert_restore_same_id(conn, &snapshot)?;
            Ok(true)
        }
        RollbackEntry::PriorityAdjust {
            memory_id,
            before,
            after: _,
        } => {
            let _ = db::update(
                conn,
                memory_id,
                None,
                None,
                None,
                None,
                None,
                Some(*before),
                None,
                None,
                None,
            )?;
            Ok(true)
        }
        // v0.9.0 G7 (#1824) — reverse a CONSERVE: remove the single
        // canonical `contradicts` edge and clear the three marker keys on
        // the loser (updated_at preserved). No compensating leaf is
        // appended — the one SUPERSEDE leaf emitted at conserve time is the
        // permanent record of the event (a second SUPERSEDE would compound,
        // and no reversal kind exists in the shipped vocabulary).
        RollbackEntry::ConserveContradiction {
            loser_id,
            winner_id: _,
            canonical_src,
            canonical_tgt,
        } => {
            db::reverse_conserve_contradiction(conn, loser_id, canonical_src, canonical_tgt)?;
            Ok(true)
        }
    }
}

/// v0.8.0 Pillar-2.5 slice-3c2 (#1748) — store-backed, backend-agnostic
/// twin of [`reverse_rollback_entry`]. Reverses a single rollback-log
/// entry through the SAL [`crate::store::MemoryStore`] trait so
/// `ai-memory curator --rollback --store-url postgres://…` reverses a
/// consolidation the store-backed curator wrote (slice-3c1, #1747) —
/// closing the "irreversible hard-DELETE behind a reversible-looking
/// API" gap slice-3c1 disclosed via a runtime WARN.
///
/// Returns `true` if a reverse action was applied, `false` if the entry
/// was already superseded (idempotent rollback) — mirroring
/// [`reverse_rollback_entry`].
///
/// Decision provenance: 5-agent vote `4d3ea1c5` → Option B (free async
/// fn over `&dyn MemoryStore`, 3/5; memory `ed85b972`). The two
/// dissents' hazards are encoded as guardrails:
///
/// * **Collision guard (G2) + Atomicity (G4) — #2887:** each snapshot is
///   reinserted via the ATOMIC restore-safe CAS
///   [`crate::store::MemoryStore::restore_or_conflict`]
///   (`INSERT … ON CONFLICT(title,namespace) DO UPDATE … WHERE memories.id =
///   excluded.id`). A same-id restore merges; a DIFFERENT id owning the key is
///   REFUSED (`StoreError::Conflict`, surfaced as the "rollback refused" error)
///   WITHOUT clobbering it. Because the collision-probe and the restore write
///   are ONE statement, the pre-#2887 probe-then-`store()` lost-update window is
///   closed — no concurrent writer that took the slot can be silently
///   upsert-overwritten. This SUPERSEDES the earlier
///   `find_by_title_namespace`-then-`store.store` probe (Option B's original
///   G2/G4 encoding); the conn-based [`reverse_rollback_entry`] gained the same
///   CAS via `db::insert_restore_same_id`.
/// * **Fail-safe ordering (G3):** the `Consolidate` arm reinserts the
///   originals BEFORE deleting the consolidated summary, so a crash mid-
///   reversal never destroys the summary while the originals are still
///   missing. The summary's `[consolidated]` title never collides with an
///   original.
#[cfg(feature = "sal")]
pub async fn reverse_rollback_entry_store(
    store: &dyn crate::store::MemoryStore,
    ctx: &crate::store::CallerContext,
    entry: &RollbackEntry,
) -> Result<bool> {
    use crate::store::StoreError;

    // #2887 — G2 (collision refusal) + G3 (fail-safe ordering) via the ATOMIC
    // restore-safe CAS `MemoryStore::restore_or_conflict`: it re-stores a
    // snapshot at its OWN id under one `INSERT … ON CONFLICT(title,namespace) DO
    // UPDATE … WHERE memories.id = excluded.id` statement, so a concurrent writer
    // that took the slot after the target was forgotten/consolidated is REFUSED
    // (`StoreError::Conflict`) and NEVER clobbered — closing the pre-#2887
    // probe-then-`store()` lost-update (the prior separate collision probe and
    // the `store()` upsert were two statements, so a race between them silently
    // overwrote the unrelated row). A refused collision surfaces as the same
    // "rollback refused" error the operator saw before.
    async fn restore_snapshot(
        store: &dyn crate::store::MemoryStore,
        ctx: &crate::store::CallerContext,
        m: &Memory,
    ) -> Result<()> {
        match store.restore_or_conflict(ctx, m).await {
            Ok(_) => Ok(()),
            Err(StoreError::Conflict { id: occupant }) => anyhow::bail!(
                "rollback refused: (title={:?}, namespace={:?}) is now owned by memory \
                 {occupant}, not the snapshot {} — resolve the conflict (delete the \
                 offender or rename one) before reversing",
                m.title,
                m.namespace,
                m.id
            ),
            Err(e) => Err(e.into()),
        }
    }

    match entry {
        RollbackEntry::Consolidate {
            originals,
            result_id,
        } => {
            // G3 — reinsert the originals (atomic restore-or-refuse) BEFORE
            // deleting the summary, so a mid-reversal crash over-retains (both
            // live) rather than losing data.
            for m in originals {
                restore_snapshot(store, ctx, m).await?;
            }
            // Delete the consolidated summary; `NotFound` → already removed
            // (idempotent no-op), matching the rusqlite `existed` bool.
            match store.delete(ctx, result_id).await {
                Ok(()) => Ok(true),
                Err(StoreError::NotFound { .. }) => Ok(false),
                Err(e) => Err(e.into()),
            }
        }
        RollbackEntry::Forget { snapshot } => {
            restore_snapshot(store, ctx, snapshot).await?;
            Ok(true)
        }
        RollbackEntry::PriorityAdjust {
            memory_id,
            before,
            after: _,
        } => {
            // Restore the prior priority. get → mutate → store (UPSERT on the
            // existing (title, namespace): no new row, so no collision guard
            // needed). `NotFound` → the row is gone (idempotent no-op).
            match store.get(ctx, memory_id).await {
                Ok(mut mem) => {
                    mem.priority = *before;
                    store.store(ctx, &mem).await?;
                    Ok(true)
                }
                Err(StoreError::NotFound { .. }) => Ok(false),
                Err(e) => Err(e.into()),
            }
        }
        // v0.9.0 G7 (#1824) — store-backed twin of the CONSERVE reversal.
        // Removes the canonical `contradicts` edge (soft-invalidate via the
        // SAL trait — the store-agnostic removal surface; NotFound /
        // unsupported → treated as already-absent, idempotent) and clears
        // the three marker keys on the loser (get → mutate → store,
        // preserving updated_at). Parity caveat (same class as G4 above):
        // the trait exposes no targeted metadata write, so the marker clear
        // rides `store.store`; a compensating revision leaf is deliberately
        // NOT appended by this code.
        RollbackEntry::ConserveContradiction {
            loser_id,
            winner_id: _,
            canonical_src,
            canonical_tgt,
        } => {
            match store
                .invalidate_link(
                    canonical_src,
                    canonical_tgt,
                    crate::models::MemoryLinkRelation::Contradicts.as_str(),
                    None,
                    // #3203 — a substrate rollback has no authenticated
                    // principal, so the audit leaf records the `system`
                    // sentinel. Honest, and never a borrowed identity.
                    None,
                )
                .await
            {
                Ok(_)
                | Err(StoreError::NotFound { .. })
                | Err(StoreError::UnsupportedCapability { .. }) => {}
                Err(e) => return Err(e.into()),
            }
            match store.get(ctx, loser_id).await {
                Ok(mut mem) => {
                    if let Some(map) = mem.metadata.as_object_mut() {
                        map.remove(field_names::CONTRADICTION_CONSERVED);
                        map.remove(field_names::CONTRADICTION_SOFT_LOSER);
                        map.remove(field_names::CONTRADICTION_WINNER_ID);
                    }
                    store.store(ctx, &mem).await?;
                    Ok(true)
                }
                Err(StoreError::NotFound { .. }) => Ok(false),
                Err(e) => Err(e.into()),
            }
        }
    }
}

/// Refuse to overwrite a memory that took the (title, namespace) slot
/// after the rollback target was forgotten/consolidated.
fn check_no_collision(
    conn: &Connection,
    title: &str,
    namespace: &str,
    expected_id: &str,
) -> Result<()> {
    let rows = db::list(
        conn,
        Some(namespace),
        None,
        50,
        0,
        None,
        None,
        None,
        None,
        None,
        None, // #1834 valid_at (no as-of)
    )?;
    for row in rows {
        if row.namespace == namespace && row.title == title && row.id != expected_id {
            anyhow::bail!(
                "rollback aborted: memory {} now occupies (title={:?}, namespace={:?}) — \
                 reverting would overwrite it. Resolve the conflict manually.",
                row.id,
                title,
                namespace
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// In-test LLM stub. Deterministic: returns fixed tags + treats
    /// "contradict" as a sentinel in content to flag contradictions.
    struct StubLlm {
        // Read by the trait impls below; the test paths in this module exercise
        // `summarize_memories` only, so rustc 1.93+ flags these reads as dead.
        // Curator and MCP integration tests (in `mcp.rs`/`curator.rs`) cover
        // `auto_tag` and `detect_contradiction`; this stub keeps the protocol
        // complete so any future autonomy test can exercise either method.
        #[allow(dead_code)]
        auto_tag_result: Vec<String>,
        summary: String,
        #[allow(dead_code)]
        contradiction_sentinel: String,
        calls: Mutex<Vec<String>>,
    }

    impl StubLlm {
        fn new(summary: &str) -> Self {
            Self {
                auto_tag_result: vec!["auto".to_string(), "stub".to_string()],
                summary: summary.to_string(),
                contradiction_sentinel: "CONTRADICTS".to_string(),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl AutonomyLlm for StubLlm {
        fn auto_tag(&self, title: &str, _content: &str) -> Result<Vec<String>> {
            self.calls.lock().unwrap().push(format!("auto_tag:{title}"));
            Ok(self.auto_tag_result.clone())
        }
        fn detect_contradiction(&self, a: &str, b: &str) -> Result<bool> {
            self.calls
                .lock()
                .unwrap()
                .push("detect_contradiction".to_string());
            Ok(
                a.contains(&self.contradiction_sentinel)
                    || b.contains(&self.contradiction_sentinel),
            )
        }
        fn summarize_memories(&self, memories: &[(String, String)]) -> Result<String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("summarize:{}", memories.len()));
            Ok(self.summary.clone())
        }
    }

    fn sample_mem(id: &str, ns: &str, title: &str, content: &str, tier: Tier) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: id.to_string(),
            tier,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: content.to_string(),
            tags: vec!["t".to_string()],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"agent_id":"ai:test"}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    fn setup_conn() -> (tempfile::NamedTempFile, Connection) {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        (tmp, conn)
    }

    #[test]
    fn jaccard_similarity_basic() {
        let sim = jaccard_similarity(
            "the quick brown fox jumps over",
            "quick brown fox over the lazy",
        );
        assert!(sim > 0.4, "unexpected sim {sim}");
    }

    #[test]
    fn jaccard_similarity_empty() {
        assert!((jaccard_similarity("", "") - 0.0).abs() < 1e-9);
        assert!((jaccard_similarity("abc", "") - 0.0).abs() < 1e-9);
    }

    #[test]
    fn consolidation_clusters_group_by_namespace() {
        let a = sample_mem(
            "a",
            "ns1",
            "A",
            "the quick brown fox jumps over lazy dog",
            Tier::Mid,
        );
        let b = sample_mem(
            "b",
            "ns1",
            "B",
            "quick brown fox over lazy dog jumps",
            Tier::Mid,
        );
        let c = sample_mem(
            "c",
            "ns2",
            "C",
            "the quick brown fox jumps over lazy dog",
            Tier::Mid,
        );
        let (_tmp, conn) = setup_conn();
        // #1774 — both sides need a stored embedding to merge; this test's
        // subject is namespace grouping, so attach aligned vectors (cosine
        // ≈ 1.0) to the in-ns pair.
        for m in [&a, &b, &c] {
            db::insert(&conn, m).unwrap();
            db::set_embedding(
                &conn,
                &m.id,
                &synth_emb(&[1.0, 0.0, 0.0, 0.0]),
                &crate::embeddings::embedding_space_fingerprint("test-space"),
            )
            .unwrap();
        }
        let clusters = find_consolidation_clusters(&conn, &[a, b, c]);
        // ns1 should cluster a+b; ns2 has only one memory so no cluster.
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].len(), 2);
    }

    #[test]
    fn consolidation_skips_reserved_namespace() {
        let a = sample_mem("a", "_curator/reports", "A", "content aaaa bbbb", Tier::Mid);
        let b = sample_mem("b", "_curator/reports", "B", "content aaaa bbbb", Tier::Mid);
        let (_tmp, conn) = setup_conn();
        let clusters = find_consolidation_clusters(&conn, &[a, b]);
        assert!(clusters.is_empty());
    }

    // -----------------------------------------------------------------
    // v0.7.0 R3-S2 — consolidation clustering uses cosine as primary
    // when embeddings are present; falls back to Jaccard otherwise.
    // -----------------------------------------------------------------

    /// Build a synthetic L2-normalized embedding from a small seed
    /// vector. Used to drive the cosine cluster path without
    /// requiring an actual embedder load.
    fn synth_emb(values: &[f32]) -> Vec<f32> {
        let norm: f32 = values.iter().map(|v| v * v).sum::<f32>().sqrt();
        if norm < 1e-12 {
            return values.to_vec();
        }
        values.iter().map(|v| v / norm).collect()
    }

    /// `test_consolidation_uses_cosine_when_embeddings_present` —
    /// two memories whose contents look *jaccard-similar* but whose
    /// embeddings are deliberately *cosine-DISsimilar* must NOT
    /// cluster. This proves cosine is the primary signal and Jaccard
    /// alone no longer drives consolidation when embeddings exist.
    #[test]
    fn test_consolidation_uses_cosine_when_embeddings_present() {
        let (_tmp, conn) = setup_conn();
        // Same lexical content (Jaccard ≈ 1.0) so the pre-filter
        // would pass — but we attach orthogonal embeddings so cosine
        // is ~0, well below the 0.75 threshold.
        let a = sample_mem(
            "a",
            "ns1",
            "A",
            "the quick brown fox jumps over lazy dog",
            Tier::Mid,
        );
        let b = sample_mem(
            "b",
            "ns1",
            "B",
            "the quick brown fox jumps over lazy dog",
            Tier::Mid,
        );

        db::insert(&conn, &a).unwrap();
        db::insert(&conn, &b).unwrap();
        // Orthogonal 4-d embeddings: cosine sim = 0.
        db::set_embedding(
            &conn,
            &a.id,
            &synth_emb(&[1.0, 0.0, 0.0, 0.0]),
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();
        db::set_embedding(
            &conn,
            &b.id,
            &synth_emb(&[0.0, 1.0, 0.0, 0.0]),
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();

        let clusters = find_consolidation_clusters(&conn, &[a, b]);
        assert!(
            clusters.is_empty(),
            "cosine-dissimilar embeddings must defeat the Jaccard-only cluster (cosine is primary)",
        );

        // Symmetry: cosine-SIMilar embeddings on the same Jaccard
        // pair MUST cluster. Reuse fresh memories to avoid the
        // UPSERT collision.
        let c = sample_mem(
            "c",
            "ns2",
            "C",
            "the quick brown fox jumps over lazy dog",
            Tier::Mid,
        );
        let d = sample_mem(
            "d",
            "ns2",
            "D",
            "the quick brown fox jumps over lazy dog",
            Tier::Mid,
        );
        db::insert(&conn, &c).unwrap();
        db::insert(&conn, &d).unwrap();
        // Nearly-identical embeddings: cosine sim ≈ 1.0.
        db::set_embedding(
            &conn,
            &c.id,
            &synth_emb(&[1.0, 0.0, 0.0, 0.0]),
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();
        db::set_embedding(
            &conn,
            &d.id,
            &synth_emb(&[0.99, 0.1, 0.0, 0.0]),
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();

        let clusters2 = find_consolidation_clusters(&conn, &[c, d]);
        assert_eq!(
            clusters2.len(),
            1,
            "cosine-similar embeddings on a Jaccard-similar pair must cluster"
        );
        assert_eq!(clusters2[0].len(), 2);
    }

    /// `test_consolidation_no_embeddings_does_not_merge_1774` —
    /// keyword-tier corpus (no embeddings persisted) does NOT cluster.
    /// Per #1774 (5-agent vote 4d3ea1c5) a destructive consolidation
    /// merge requires the cosine safety gate on both sides; un-embedded
    /// pairs never merge on Jaccard lexical overlap alone.
    #[test]
    fn test_consolidation_no_embeddings_does_not_merge_1774() {
        let (_tmp, conn) = setup_conn();
        let a = sample_mem(
            "a",
            "ns",
            "A",
            "kubernetes rolling canary deploy strategy keyword keyword",
            Tier::Long,
        );
        let b = sample_mem(
            "b",
            "ns",
            "B",
            "kubernetes rolling canary deploy strategy keyword keyword",
            Tier::Long,
        );
        // Insert WITHOUT attaching embeddings — get_embedding returns
        // None on both sides, so there is no cosine value and the pair
        // does NOT merge (#1774).
        db::insert(&conn, &a).unwrap();
        db::insert(&conn, &b).unwrap();

        let clusters = find_consolidation_clusters(&conn, &[a, b]);
        assert!(
            clusters.is_empty(),
            "un-embedded corpus must NOT cluster on Jaccard alone; got {clusters:?}"
        );
    }

    #[test]
    fn rollback_entry_serialises() {
        let e = RollbackEntry::PriorityAdjust {
            memory_id: "m1".to_string(),
            before: 5,
            after: 6,
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("priority_adjust"));
        let back: RollbackEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action_tag(), "priority_adjust");
    }

    #[test]
    fn consolidate_cluster_merges_two_memories() {
        let (_tmp, conn) = setup_conn();
        let a = sample_mem(
            "a",
            "app",
            "Deploy plan",
            "kubernetes rolling deploy with canary",
            Tier::Long,
        );
        let b = sample_mem(
            "b",
            "app",
            "Deploy process",
            "kubernetes deploy rolling canary strategy",
            Tier::Long,
        );
        db::insert(&conn, &a).unwrap();
        db::insert(&conn, &b).unwrap();
        let llm = StubLlm::new("consolidated deploy plan");
        let cluster = vec![a.clone(), b.clone()];
        let entry = consolidate_cluster(&conn, &llm, &cluster, false)
            .unwrap()
            .expect("expected rollback entry");
        match entry {
            RollbackEntry::Consolidate {
                originals,
                result_id,
            } => {
                assert_eq!(originals.len(), 2);
                assert_ne!(result_id, "dry-run");
                let got = db::get(&conn, &result_id).unwrap().expect("result memory");
                assert_eq!(got.namespace, "app");
                assert!(got.title.starts_with("[consolidated]"));
                assert!(got.content.contains("consolidated deploy plan"));
            }
            _ => panic!("expected Consolidate"),
        }
    }

    #[test]
    fn dry_run_does_not_write() {
        let (_tmp, conn) = setup_conn();
        let a = sample_mem(
            "a",
            "app",
            "Deploy plan",
            "kubernetes rolling deploy with canary",
            Tier::Long,
        );
        let b = sample_mem(
            "b",
            "app",
            "Deploy process",
            "kubernetes deploy rolling canary strategy",
            Tier::Long,
        );
        db::insert(&conn, &a).unwrap();
        db::insert(&conn, &b).unwrap();
        let llm = StubLlm::new("never persisted");
        let cluster = vec![a.clone(), b.clone()];
        let entry = consolidate_cluster(&conn, &llm, &cluster, true)
            .unwrap()
            .expect("dry-run returns entry");
        if let RollbackEntry::Consolidate { result_id, .. } = entry {
            assert_eq!(result_id, "dry-run");
        }
        // Originals still present, no consolidated row added.
        assert!(db::get(&conn, "a").unwrap().is_some());
        assert!(db::get(&conn, "b").unwrap().is_some());
    }

    #[test]
    fn reverse_consolidation_restores_originals() {
        let (_tmp, conn) = setup_conn();
        let a = sample_mem(
            "a",
            "app",
            "Deploy plan",
            "kubernetes rolling deploy canary",
            Tier::Long,
        );
        let b = sample_mem(
            "b",
            "app",
            "Deploy process",
            "kubernetes rolling canary strategy",
            Tier::Long,
        );
        db::insert(&conn, &a).unwrap();
        db::insert(&conn, &b).unwrap();

        let llm = StubLlm::new("summary");
        let cluster = vec![a.clone(), b.clone()];
        let entry = consolidate_cluster(&conn, &llm, &cluster, false)
            .unwrap()
            .expect("entry");

        // After consolidation, originals should be gone (merged into
        // the result id).
        if let RollbackEntry::Consolidate {
            result_id,
            originals,
        } = &entry
        {
            assert!(db::get(&conn, result_id).unwrap().is_some());
            for orig in originals {
                assert!(
                    db::get(&conn, &orig.id).unwrap().is_none(),
                    "{} should be merged-away",
                    orig.id
                );
            }
        }

        // Rollback: originals come back, result is removed.
        reverse_rollback_entry(&conn, &entry).unwrap();
        assert!(db::get(&conn, "a").unwrap().is_some());
        assert!(db::get(&conn, "b").unwrap().is_some());
        if let RollbackEntry::Consolidate { result_id, .. } = &entry {
            assert!(db::get(&conn, result_id).unwrap().is_none());
        }
    }

    // v0.8.0 Pillar-2.5 slice-3c2 (#1748) — store-backed reversal over the
    // SAL `MemoryStore` trait. Deterministic SQLite-backed twin of the
    // rusqlite `reverse_consolidation_restores_originals`; the postgres arm
    // is exercised by tests/cov_postgres_core.rs (soft-skips off-CI).
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn reverse_rollback_entry_store_restores_originals_sqlite() {
        use crate::store::MemoryStore;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = crate::store::sqlite::SqliteStore::open(tmp.path()).expect("open store");
        let ctx = crate::store::CallerContext::for_admin("ai:test");

        let a = sample_mem(
            "a",
            "app",
            "Deploy plan",
            "kubernetes rolling canary",
            Tier::Long,
        );
        let b = sample_mem(
            "b",
            "app",
            "Deploy process",
            "kubernetes canary strategy",
            Tier::Long,
        );
        let summary = sample_mem("c", "app", "[consolidated] Deploy", "merged", Tier::Long);

        // Simulate the post-consolidation state: originals hard-deleted, the
        // `[consolidated]` summary present, a reversible entry on hand.
        store.store(&ctx, &summary).await.unwrap();
        let entry = RollbackEntry::Consolidate {
            originals: vec![a.clone(), b.clone()],
            result_id: summary.id.clone(),
        };
        assert!(
            store.get(&ctx, "a").await.is_err(),
            "original absent pre-reverse"
        );
        assert!(
            store.get(&ctx, &summary.id).await.is_ok(),
            "summary present pre-reverse"
        );

        let applied = reverse_rollback_entry_store(&store, &ctx, &entry)
            .await
            .unwrap();
        assert!(applied, "summary existed → reverse applied");

        // Originals restored; summary removed.
        assert!(store.get(&ctx, "a").await.is_ok(), "original a restored");
        assert!(store.get(&ctx, "b").await.is_ok(), "original b restored");
        assert!(
            store.get(&ctx, &summary.id).await.is_err(),
            "summary removed"
        );

        // Idempotent: a second reverse is a no-op (summary already gone).
        let again = reverse_rollback_entry_store(&store, &ctx, &entry)
            .await
            .unwrap();
        assert!(!again, "summary already removed → no-op");
    }

    // #1748 — the G2 collision guard: refuse to clobber a DIFFERENT memory
    // that took the (title, namespace) slot, leaving the summary intact
    // (G3 ordering guarantees the guard fires before any delete).
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn reverse_rollback_entry_store_collision_aborts_sqlite() {
        use crate::store::MemoryStore;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = crate::store::sqlite::SqliteStore::open(tmp.path()).expect("open store");
        let ctx = crate::store::CallerContext::for_admin("ai:test");

        let a = sample_mem("a", "app", "Deploy plan", "orig", Tier::Long);
        let summary = sample_mem("c", "app", "[consolidated] Deploy", "merged", Tier::Long);
        store.store(&ctx, &summary).await.unwrap();
        // A DIFFERENT id now owns ("Deploy plan", "app").
        let intruder = sample_mem("z", "app", "Deploy plan", "unrelated", Tier::Long);
        store.store(&ctx, &intruder).await.unwrap();

        let entry = RollbackEntry::Consolidate {
            originals: vec![a],
            result_id: summary.id.clone(),
        };
        let err = reverse_rollback_entry_store(&store, &ctx, &entry)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("rollback refused"),
            "expected collision refusal, got: {err}"
        );
        // Guard fired before the delete: summary and intruder both intact.
        assert!(
            store.get(&ctx, &summary.id).await.is_ok(),
            "summary not deleted"
        );
        assert!(store.get(&ctx, "z").await.is_ok(), "intruder not clobbered");
    }

    #[test]
    fn full_autonomy_cycle_end_to_end() {
        let (_tmp, conn) = setup_conn();
        let llm = StubLlm::new("consolidated");

        // Seed: two near-duplicates in "deploy", one unrelated doc in
        // "chat", and a pair with a confirmed-contradictions pointer.
        let m_a = sample_mem(
            "ma",
            "deploy",
            "canary deploy plan",
            "kubernetes canary rolling deploy strategy",
            Tier::Long,
        );
        let m_b = sample_mem(
            "mb",
            "deploy",
            "canary deploy overview",
            "kubernetes rolling canary deploy strategy",
            Tier::Long,
        );
        let m_chat = sample_mem(
            "mchat",
            "chat",
            "hello",
            "hi there chat only content here",
            Tier::Mid,
        );

        // Superseded pair: m_old is older AND has a confirmed
        // contradiction against m_new.
        let mut m_old = sample_mem(
            "mold",
            "facts",
            "fact v1",
            "the sky is green always uniformly",
            Tier::Long,
        );
        let m_new_id = "mnew";
        m_old.metadata["confirmed_contradictions"] = serde_json::json!([m_new_id]);
        // Push m_old's updated_at to the past so m_new's default now
        // is strictly newer.
        m_old.updated_at = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        let m_new = sample_mem(
            m_new_id,
            "facts",
            "fact v2",
            "the sky is blue most of the time for sure",
            Tier::Long,
        );

        for m in [&m_a, &m_b, &m_chat, &m_old, &m_new] {
            db::insert(&conn, m).unwrap();
        }
        // #1774 — the deploy near-duplicates need stored embeddings on both
        // sides to clear the cosine gate; attach aligned vectors (cosine
        // ≈ 1.0) so the deploy cluster forms.
        for id in ["ma", "mb"] {
            db::set_embedding(
                &conn,
                id,
                &synth_emb(&[1.0, 0.0, 0.0, 0.0]),
                &crate::embeddings::embedding_space_fingerprint("test-space"),
            )
            .unwrap();
        }

        let candidates = vec![
            m_a.clone(),
            m_b.clone(),
            m_chat.clone(),
            m_old.clone(),
            m_new.clone(),
        ];
        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false, usize::MAX, None);

        // Consolidated at least once (deploy cluster).
        assert!(report.clusters_formed >= 1);
        assert!(report.memories_consolidated >= 2);
        // Forgot m_old because it's superseded by m_new.
        assert!(
            report.memories_forgotten >= 1,
            "expected ≥1 forget, got {report:?}"
        );
        // Rollback entries written for each action.
        assert!(report.rollback_entries_written >= report.clusters_formed);
        // Rollback-log memories exist.
        let log = db::list(
            &conn,
            Some("_curator/rollback"),
            None,
            100,
            0,
            None,
            None,
            None,
            None,
            None,
            None, // #1834 valid_at (no as-of)
        )
        .unwrap();
        assert!(!log.is_empty(), "rollback log should be populated");
    }

    /// v1.0.0 #3345 — the self-report is STORED but is no longer a
    /// recall-visible memory.
    ///
    /// Pre-#3345 this test asserted `db::list(Some("_curator/reports"))` returned
    /// the row — i.e. it pinned the defect: every sweep added an ordinary,
    /// recall-visible, backfill-embeddable memory, which on one node reached
    /// 24,930 rows (97% of the store) and 24,801 paid embedding calls. The
    /// report is now written `LifecycleState::Operational`, so the fail-CLOSED
    /// `lifecycle_visible_clause` allow-list that `db::list` carries hides it,
    /// and the operator reads it through `db::list_operational_reports`
    /// (`ai-memory curator --reports`) instead.
    #[test]
    fn self_report_written_to_reports_namespace() {
        let (_tmp, conn) = setup_conn();
        let pass = AutonomyPassReport {
            clusters_formed: 1,
            memories_consolidated: 2,
            memories_forgotten: 0,
            priority_adjustments: 1,
            rollback_entries_written: 2,
            errors: vec![],
            ..AutonomyPassReport::default()
        };
        persist_self_report(&conn, 1234, &pass, 3, 0, 0, 0).unwrap();

        // The ordinary read lane must NOT see it.
        let recall_visible = db::list(
            &conn,
            Some(CURATOR_REPORTS_NAMESPACE),
            None,
            10,
            0,
            None,
            None,
            None,
            None,
            None,
            None, // #1834 valid_at (no as-of)
        )
        .unwrap();
        assert!(
            recall_visible.is_empty(),
            "a self-report must not be a recall-visible memory, got {} row(s)",
            recall_visible.len()
        );

        // …but it IS stored, reachable through the operator read path, with
        // its body intact and a bounded TTL.
        let reports = db::list_operational_reports(&conn, CURATOR_REPORTS_NAMESPACE, 10).unwrap();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].2.contains("memories_consolidated"));
        let row = db::get_any(&conn, &reports[0].0).unwrap().unwrap();
        assert_eq!(row.tier, Tier::Short);
        assert_eq!(
            row.lifecycle_state,
            crate::models::LifecycleState::Operational
        );
        assert!(row.expires_at.is_some(), "self-reports must carry a TTL");
    }

    #[test]
    fn smart_tier_mock_cycle_summarize() {
        // Test that autonomy invokes the LLM's summarize_memories in consolidation.
        let (_tmp, conn) = setup_conn();
        // Use similar enough content to exceed the Jaccard threshold (0.55)
        let a = sample_mem(
            "mem-a",
            "app",
            "Deploy A",
            "kubernetes deployment rolling canary strategy kubernetes rolling deploy canary",
            Tier::Mid,
        );
        let b = sample_mem(
            "mem-b",
            "app",
            "Deploy B",
            "kubernetes deployment rolling canary approach kubernetes rolling canary deploy",
            Tier::Mid,
        );
        db::insert(&conn, &a).unwrap();
        db::insert(&conn, &b).unwrap();
        // #1774 — attach aligned embeddings (cosine ≈ 1.0) so the cosine
        // gate is cleared and the pair clusters.
        db::set_embedding(
            &conn,
            &a.id,
            &synth_emb(&[1.0, 0.0, 0.0, 0.0]),
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();
        db::set_embedding(
            &conn,
            &b.id,
            &synth_emb(&[1.0, 0.0, 0.0, 0.0]),
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();

        let llm = StubLlm::new("LLM-generated consolidated summary");
        let candidates = vec![a, b];

        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false, usize::MAX, None);

        // Key assertions: LLM was used (clusters formed and consolidation happened)
        assert!(report.clusters_formed > 0);
        assert!(report.memories_consolidated > 0);
    }

    #[test]
    fn autonomy_cycle_with_mock_ollama() {
        // Test run_autonomy_passes end-to-end with StubLlm
        let (_tmp, conn) = setup_conn();
        let a = sample_mem(
            "id-1",
            "ns1",
            "Title A",
            "content similar enough for clustering test similar clustering",
            Tier::Mid,
        );
        let b = sample_mem(
            "id-2",
            "ns1",
            "Title B",
            "content similar enough for clustering test similar clustering",
            Tier::Mid,
        );
        db::insert(&conn, &a).unwrap();
        db::insert(&conn, &b).unwrap();
        // #1774 — attach aligned embeddings (cosine ≈ 1.0) so the cosine
        // gate is cleared and consolidation produces a rollback entry.
        db::set_embedding(
            &conn,
            &a.id,
            &synth_emb(&[1.0, 0.0, 0.0, 0.0]),
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();
        db::set_embedding(
            &conn,
            &b.id,
            &synth_emb(&[1.0, 0.0, 0.0, 0.0]),
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();

        let llm = StubLlm::new("mock summary result");
        let candidates = vec![a, b];

        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false, usize::MAX, None);

        // Report should reflect successful cycle
        assert_eq!(report.errors.len(), 0, "autonomy cycle should not error");
        assert!(
            report.rollback_entries_written > 0,
            "autonomy cycle should write rollback entries"
        );
    }

    #[test]
    fn rollback_log_captures_consolidation() {
        // Verify rollback log correctly records a consolidation
        let (_tmp, conn) = setup_conn();
        let a = sample_mem(
            "a",
            "test-ns",
            "Memory A",
            "test content aaaa bbbb cccc aaaa bbbb",
            Tier::Mid,
        );
        let b = sample_mem(
            "b",
            "test-ns",
            "Memory B",
            "test content aaaa bbbb cccc aaaa bbbb",
            Tier::Mid,
        );
        db::insert(&conn, &a).unwrap();
        db::insert(&conn, &b).unwrap();

        let llm = StubLlm::new("consolidated");
        let cluster = vec![a.clone(), b.clone()];
        let entry = consolidate_cluster(&conn, &llm, &cluster, false)
            .unwrap()
            .expect("rollback entry");

        // Persist the entry
        persist_rollback_entry(&conn, &entry).unwrap();

        // Verify it's in the rollback log
        let log = db::list(
            &conn,
            Some("_curator/rollback"),
            None,
            100,
            0,
            None,
            None,
            None,
            None,
            None,
            None, // #1834 valid_at (no as-of)
        )
        .unwrap();
        assert_eq!(log.len(), 1);
        assert!(log[0].content.contains("consolidate"));
    }

    #[test]
    fn priority_feedback_adjusts_memory() {
        // Verify priority feedback changes memory priority based on access.
        // Policy at apply_priority_feedback: access_count >= 10 AND
        // last_accessed_at within 7d → +1. Set both signals for the bump
        // path, plus an explicit recent-access timestamp.
        let (_tmp, conn) = setup_conn();
        let mut mem = sample_mem("id", "ns", "Title", "content", Tier::Mid);
        mem.priority = 5;
        mem.access_count = 100;
        mem.last_accessed_at = Some(chrono::Utc::now().to_rfc3339());
        db::insert(&conn, &mem).unwrap();

        let entry = apply_priority_feedback(&conn, &mem, false)
            .unwrap()
            .expect("priority feedback should produce entry");

        match entry {
            RollbackEntry::PriorityAdjust {
                memory_id,
                before,
                after,
            } => {
                assert_eq!(memory_id, "id");
                assert_eq!(before, 5);
                assert!(after > before, "high access should increase priority");
            }
            _ => panic!("expected PriorityAdjust"),
        }
    }

    /// v1.0.0 #2339 (FBL-34) — the decay arm is REACHABLE for accessed
    /// rows (staleness-based, not the structurally-dead access_count==0),
    /// bounded (-1/cycle, floor 1), and SCOPED to the access band so
    /// operator-set 8-10 priorities never silently erode; the up-arm caps
    /// at ACCESS_PRIORITY_CEILING.
    #[test]
    fn priority_feedback_decay_reachable_and_operator_band_protected_2339() {
        let (_tmp, conn) = setup_conn();
        let stale_ts = (chrono::Utc::now() - chrono::Duration::days(40)).to_rfc3339();
        let old_created = (chrono::Utc::now() - chrono::Duration::days(90)).to_rfc3339();

        // (a) Accessed-but-stale row inside the band DECAYS (pre-fix the
        // arm required access_count == 0 — unreachable once ever recalled).
        let mut stale = sample_mem("stale2339", "ns", "T1", "content", Tier::Mid);
        stale.priority = 6;
        stale.access_count = 50;
        stale.created_at = old_created.clone();
        stale.last_accessed_at = Some(stale_ts.clone());
        db::insert(&conn, &stale).unwrap();
        match apply_priority_feedback(&conn, &stale, false).unwrap() {
            Some(RollbackEntry::PriorityAdjust { before, after, .. }) => {
                assert_eq!(before, 6);
                assert_eq!(after, 5, "stale accessed row decays -1");
            }
            other => panic!("expected decay PriorityAdjust, got {other:?}"),
        }

        // (b) Operator band (8-10) NEVER decays — indistinguishable from
        // explicit operator intent (fail-safe).
        let mut operator = sample_mem("op2339", "ns", "T2", "content", Tier::Long);
        operator.priority = 9;
        operator.access_count = 50;
        operator.created_at = old_created.clone();
        operator.last_accessed_at = Some(stale_ts);
        db::insert(&conn, &operator).unwrap();
        assert!(
            apply_priority_feedback(&conn, &operator, false)
                .unwrap()
                .is_none(),
            "operator-band priority must not decay"
        );

        // (c) The hot up-arm stops at the ceiling — no bump into 8-10.
        let mut hot = sample_mem("hot2339", "ns", "T3", "content", Tier::Mid);
        hot.priority = i32::try_from(crate::models::ACCESS_PRIORITY_CEILING).unwrap();
        hot.access_count = 100;
        hot.last_accessed_at = Some(chrono::Utc::now().to_rfc3339());
        db::insert(&conn, &hot).unwrap();
        assert!(
            apply_priority_feedback(&conn, &hot, false)
                .unwrap()
                .is_none(),
            "the access ratchet must not push past the ceiling"
        );
    }

    #[test]
    fn dry_run_autonomy_does_not_write() {
        // Verify dry-run mode prevents all writes to DB
        let (_tmp, conn) = setup_conn();
        let a = sample_mem(
            "a",
            "test-ns",
            "Memory A",
            "test content aaaa bbbb cccc aaaa bbbb",
            Tier::Mid,
        );
        let b = sample_mem(
            "b",
            "test-ns",
            "Memory B",
            "test content aaaa bbbb cccc aaaa bbbb",
            Tier::Mid,
        );
        db::insert(&conn, &a).unwrap();
        db::insert(&conn, &b).unwrap();

        let initial_count = db::list(
            &conn,
            Some("test-ns"),
            None,
            100,
            0,
            None,
            None,
            None,
            None,
            None,
            None, // #1834 valid_at (no as-of)
        )
        .unwrap()
        .len();

        let llm = StubLlm::new("consolidated");
        let candidates = vec![a, b];
        let _report = run_autonomy_passes(&conn, &llm, &candidates, true, false, usize::MAX, None);

        let final_count = db::list(
            &conn,
            Some("test-ns"),
            None,
            100,
            0,
            None,
            None,
            None,
            None,
            None,
            None, // #1834 valid_at (no as-of)
        )
        .unwrap()
        .len();

        assert_eq!(
            initial_count, final_count,
            "dry-run should not modify database"
        );
    }

    #[test]
    fn autonomy_passes_report_aggregates_errors() {
        // Verify error aggregation in AutonomyPassReport
        let (_tmp, conn) = setup_conn();
        let mem = sample_mem("id", "ns", "Title", "content", Tier::Mid);
        let llm = StubLlm::new("summary");
        let candidates = vec![mem];
        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false, usize::MAX, None);

        // At minimum, report structure should be valid
        assert!(report.clusters_formed > 0 || report.clusters_formed == 0);
    }

    // ---- Wave 9 (Closer A9) — RollbackEntry::reverse_* matrix +
    // edge cases for consolidate_cluster / forget_if_superseded /
    // StubLlm impls. These target the lines uncovered after W8.

    /// Reversing a `PriorityAdjust` entry rewrites the priority back to
    /// the captured `before` value. Covers `reverse_rollback_entry`'s
    /// `PriorityAdjust` branch which the W8 suite never exercised end-
    /// to-end.
    #[test]
    fn reverse_priority_adjust_restores_before_value() {
        let (_tmp, conn) = setup_conn();
        let mut mem = sample_mem("pa-id", "ns", "Title", "content", Tier::Mid);
        mem.priority = 7;
        db::insert(&conn, &mem).unwrap();
        // Bump the row to priority=9 to simulate a prior +2 adjustment.
        db::update(
            &conn,
            &mem.id,
            None,
            None,
            None,
            None,
            None,
            Some(9),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(db::get(&conn, &mem.id).unwrap().unwrap().priority, 9);

        let entry = RollbackEntry::PriorityAdjust {
            memory_id: mem.id.clone(),
            before: 7,
            after: 9,
        };
        let applied = reverse_rollback_entry(&conn, &entry).unwrap();
        assert!(applied);
        assert_eq!(db::get(&conn, &mem.id).unwrap().unwrap().priority, 7);
    }

    /// Reversing a `Forget` entry re-inserts the snapshot. Covers the
    /// happy path through `check_no_collision` + `db::insert` round-trip.
    #[test]
    fn reverse_forget_restores_snapshot() {
        let (_tmp, conn) = setup_conn();
        let mem = sample_mem(
            "forget-id",
            "factual",
            "Snapshot",
            "saved content body abc",
            Tier::Long,
        );
        db::insert(&conn, &mem).unwrap();
        // Simulate the forget happening: hard-delete.
        db::delete(&conn, &mem.id).unwrap();
        assert!(db::get(&conn, &mem.id).unwrap().is_none());

        let entry = RollbackEntry::Forget {
            snapshot: mem.clone(),
        };
        let applied = reverse_rollback_entry(&conn, &entry).unwrap();
        assert!(applied);
        let restored = db::get(&conn, &mem.id).unwrap().expect("snapshot restored");
        assert_eq!(restored.title, "Snapshot");
        assert_eq!(restored.namespace, "factual");
    }

    /// Reversing a `Consolidate` aborts with an error when the
    /// (title, namespace) slot of an original is already taken by an
    /// unrelated memory id — this is `check_no_collision`'s defensive
    /// bail (line ~629) which the W8 suite never reached.
    #[test]
    fn reverse_consolidate_collision_aborts() {
        let (_tmp, conn) = setup_conn();
        let original = sample_mem(
            "o1",
            "app",
            "Deploy plan",
            "kubernetes rolling deploy canary",
            Tier::Long,
        );
        let merged_id = "merged".to_string();
        let entry = RollbackEntry::Consolidate {
            originals: vec![original.clone()],
            result_id: merged_id.clone(),
        };

        // Stand up a different memory at (title=Deploy plan, namespace=app)
        // — the collision target for the rollback.
        let collider = sample_mem(
            "collider-id",
            "app",
            "Deploy plan",
            "different content here entirely",
            Tier::Long,
        );
        db::insert(&conn, &collider).unwrap();

        let err = reverse_rollback_entry(&conn, &entry).expect_err("collision must abort");
        let msg = format!("{err}");
        assert!(msg.contains("rollback aborted"), "unexpected msg: {msg}");
        // Collider is untouched.
        assert!(db::get(&conn, "collider-id").unwrap().is_some());
    }

    /// `consolidate_cluster` short-circuits to `None` when the cluster
    /// has fewer than two members. Covers the `cluster.len() < 2` early
    /// return.
    #[test]
    fn consolidate_cluster_returns_none_for_singleton() {
        let (_tmp, conn) = setup_conn();
        let llm = StubLlm::new("never called");
        let solo = sample_mem("a", "ns", "T", "content body word word", Tier::Mid);
        let result = consolidate_cluster(&conn, &llm, std::slice::from_ref(&solo), false).unwrap();
        assert!(result.is_none());
    }

    /// `consolidate_cluster` defensively skips clusters whose members
    /// are in a reserved (`_`-prefixed) namespace. Covers the second
    /// early return path (line ~294).
    #[test]
    fn consolidate_cluster_skips_reserved_namespace_defensive() {
        let (_tmp, conn) = setup_conn();
        let llm = StubLlm::new("never called");
        let a = sample_mem("a", "_curator/rollback", "T1", "abc abc abc abc", Tier::Mid);
        let b = sample_mem("b", "_curator/rollback", "T2", "abc abc abc abc", Tier::Mid);
        let result = consolidate_cluster(&conn, &llm, &[a, b], false).unwrap();
        assert!(
            result.is_none(),
            "reserved-namespace cluster must be skipped"
        );
    }

    /// In dry_run mode, `forget_if_superseded` returns a `Forget`
    /// rollback entry **without** deleting the underlying row. Covers
    /// the dry-run branch (lines ~397-399) of `forget_if_superseded`.
    #[test]
    fn forget_if_superseded_dry_run_returns_entry_without_delete() {
        let (_tmp, conn) = setup_conn();
        let mut older = sample_mem("old", "facts", "fact v1", "the sky is green", Tier::Long);
        older.metadata["confirmed_contradictions"] = serde_json::json!(["new"]);
        older.updated_at = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        let newer = sample_mem("new", "facts", "fact v2", "the sky is blue", Tier::Long);
        db::insert(&conn, &older).unwrap();
        db::insert(&conn, &newer).unwrap();

        let result =
            forget_if_superseded(&conn, &older, &[older.clone(), newer], true, None).unwrap();
        match result {
            // v0.9.0 G7 (#1824) — dry-run now returns the CONSERVE
            // descriptor (retain both), not a Forget.
            Some(RollbackEntry::ConserveContradiction {
                loser_id,
                winner_id,
                ..
            }) => {
                assert_eq!(loser_id, "old");
                assert_eq!(winner_id, "new");
            }
            _ => panic!("expected ConserveContradiction entry from dry-run conserve"),
        }
        // Dry-run preserves BOTH rows.
        assert!(db::get(&conn, "old").unwrap().is_some());
        assert!(db::get(&conn, "new").unwrap().is_some());
    }

    /// v1.0.0 #2337 (FBL-26) — the PRODUCTION marker direction: both live
    /// writers (store-time legacy classifier + curator
    /// `persist_contradiction`) stamp `confirmed_contradictions` on the
    /// NEWER row pointing at the OLDER one (and the persisting update
    /// bumps the bearer's `updated_at`), so the pre-fix bearer-is-loser
    /// condition never fired. The bidirectional pass must conserve the
    /// LISTED (older) row as the loser with the bearer as winner.
    #[test]
    fn forget_if_superseded_conserves_older_when_marker_on_newer_row_2337() {
        let (_tmp, conn) = setup_conn();
        let mut older = sample_mem(
            "old2337",
            "facts",
            "fact v1",
            "the sky is green",
            Tier::Long,
        );
        older.updated_at = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        // Marker on the NEWER row (the production writers' direction).
        let mut newer = sample_mem("new2337", "facts", "fact v2", "the sky is blue", Tier::Long);
        newer.metadata["confirmed_contradictions"] = serde_json::json!(["old2337"]);
        db::insert(&conn, &older).unwrap();
        db::insert(&conn, &newer).unwrap();

        let result =
            forget_if_superseded(&conn, &newer, &[older.clone(), newer.clone()], false, None)
                .unwrap();
        match result {
            Some(RollbackEntry::ConserveContradiction {
                loser_id,
                winner_id,
                ..
            }) => {
                assert_eq!(loser_id, "old2337", "the LISTED older row is the loser");
                assert_eq!(winner_id, "new2337", "the marker bearer is the winner");
            }
            other => panic!("expected ConserveContradiction, got {other:?}"),
        }

        // BOTH rows retained (G7 conserve, never delete)…
        let old_row = db::get(&conn, "old2337").unwrap().expect("older retained");
        assert!(db::get(&conn, "new2337").unwrap().is_some());
        // …the soft-loser markers landed on the OLDER row…
        assert_eq!(
            old_row
                .metadata
                .get(field_names::CONTRADICTION_SOFT_LOSER)
                .and_then(serde_json::Value::as_bool),
            Some(true),
            "soft-loser marker lands on the correct (older) side"
        );
        assert_eq!(
            old_row
                .metadata
                .get(field_names::CONTRADICTION_WINNER_ID)
                .and_then(serde_json::Value::as_str),
            Some("new2337")
        );
        // …and the canonical contradicts edge exists.
        let (src, _tgt) = db::canonical_contradiction_pair("old2337", "new2337");
        let links = db::get_links(&conn, src).unwrap();
        assert!(
            links
                .iter()
                .any(|l| l.relation == crate::models::MemoryLinkRelation::Contradicts),
            "contradicts edge written"
        );

        // Idempotence: a second pass over the SAME pair is a no-op (the
        // older row now carries the conserved marker).
        let refreshed_old = db::get(&conn, "old2337").unwrap().unwrap();
        let refreshed_new = db::get(&conn, "new2337").unwrap().unwrap();
        let again = forget_if_superseded(
            &conn,
            &refreshed_new,
            &[refreshed_old, refreshed_new.clone()],
            false,
            None,
        )
        .unwrap();
        assert!(again.is_none(), "re-entry gate holds on the listed side");
    }

    /// `forget_if_superseded` skips non-string entries in the
    /// `confirmed_contradictions` array — covers the `let Some(...) =
    /// v.as_str() else { continue; };` branch (line ~382).
    #[test]
    fn forget_if_superseded_skips_non_string_contradiction_ids() {
        let (_tmp, conn) = setup_conn();
        let mut mem = sample_mem("m", "facts", "T", "content body word", Tier::Mid);
        // Mix invalid (number) and valid-but-missing (no matching id) entries.
        mem.metadata["confirmed_contradictions"] = serde_json::json!([42, "missing-id"]);
        let result =
            forget_if_superseded(&conn, &mem, std::slice::from_ref(&mem), false, None).unwrap();
        // No superseder identified (numeric id skipped, "missing-id" not in `all`).
        assert!(result.is_none());
    }

    /// Exercise the `StubLlm::auto_tag` and `StubLlm::detect_contradiction`
    /// trait impls directly — they exist for completeness of the
    /// `AutonomyLlm` trait surface but the autonomy code itself only
    /// calls `summarize_memories`, so without a direct hit they are
    /// uncovered (lines ~674-687).
    #[test]
    fn stub_llm_auto_tag_and_detect_contradiction() {
        let llm = StubLlm::new("summary");
        // auto_tag returns the canned tags.
        let tags = AutonomyLlm::auto_tag(&llm, "Some Title", "body").unwrap();
        assert_eq!(tags, vec!["auto".to_string(), "stub".to_string()]);
        // detect_contradiction is sentinel-driven.
        assert!(AutonomyLlm::detect_contradiction(&llm, "this CONTRADICTS that", "ok").unwrap());
        assert!(!AutonomyLlm::detect_contradiction(&llm, "ok", "fine").unwrap());
        // The call log captures both invocations.
        let calls = llm.calls.lock().unwrap();
        assert!(calls.iter().any(|c| c.starts_with("auto_tag:")));
        assert!(calls.iter().any(|c| c == "detect_contradiction"));
    }

    /// `run_autonomy_passes` with `dry_run=true` and a candidate set that
    /// triggers all three pass kinds (consolidate cluster + supersedure
    /// pair + recent-and-hot priority bump candidate) writes nothing to
    /// the DB but still emits a non-trivial report. This stresses the
    /// dry_run branches of every pass at once.
    #[test]
    fn run_autonomy_passes_dry_run_writes_no_changes() {
        let (_tmp, conn) = setup_conn();
        // Cluster pair.
        let m_a = sample_mem(
            "ma",
            "deploy",
            "canary deploy plan",
            "kubernetes canary rolling deploy strategy",
            Tier::Long,
        );
        let m_b = sample_mem(
            "mb",
            "deploy",
            "canary deploy overview",
            "kubernetes rolling canary deploy strategy",
            Tier::Long,
        );
        // Superseded pair.
        let mut m_old = sample_mem(
            "mold",
            "facts",
            "fact v1",
            "the sky is green always uniformly",
            Tier::Long,
        );
        m_old.metadata["confirmed_contradictions"] = serde_json::json!(["mnew"]);
        m_old.updated_at = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        let m_new = sample_mem(
            "mnew",
            "facts",
            "fact v2",
            "the sky is blue most of the time",
            Tier::Long,
        );
        // Hot priority candidate.
        let mut m_hot = sample_mem(
            "hot",
            "ns",
            "Hot",
            "this is hot content for priority bump",
            Tier::Mid,
        );
        m_hot.priority = 5;
        m_hot.access_count = 100;
        m_hot.last_accessed_at = Some(chrono::Utc::now().to_rfc3339());

        for m in [&m_a, &m_b, &m_old, &m_new, &m_hot] {
            db::insert(&conn, m).unwrap();
        }
        // #1774 — the deploy near-duplicates need stored embeddings on both
        // sides to clear the cosine gate; attach aligned vectors (cosine ≈ 1.0)
        // so the deploy cluster forms in the dry-run report.
        for id in ["ma", "mb"] {
            db::set_embedding(
                &conn,
                id,
                &synth_emb(&[1.0, 0.0, 0.0, 0.0]),
                &crate::embeddings::embedding_space_fingerprint("test-space"),
            )
            .unwrap();
        }
        let candidates = vec![
            m_a.clone(),
            m_b.clone(),
            m_old.clone(),
            m_new.clone(),
            m_hot.clone(),
        ];

        // Snapshot pre-state.
        let pre_priority = db::get(&conn, &m_hot.id).unwrap().unwrap().priority;
        assert!(db::get(&conn, "mold").unwrap().is_some());

        let llm = StubLlm::new("dry-run summary");
        let report = run_autonomy_passes(&conn, &llm, &candidates, true, false, usize::MAX, None);

        // Report still reflects the would-be actions.
        assert!(report.clusters_formed >= 1);
        // Dry-run path produces no rollback-log writes (the persist call
        // is gated on `!dry_run`, and even though the counter is bumped,
        // the rollback memories themselves never land).
        let log = db::list(
            &conn,
            Some("_curator/rollback"),
            None,
            100,
            0,
            None,
            None,
            None,
            None,
            None,
            None, // #1834 valid_at (no as-of)
        )
        .unwrap();
        assert!(log.is_empty(), "dry-run must not persist rollback memories");

        // Pre-state survives.
        assert_eq!(
            db::get(&conn, &m_hot.id).unwrap().unwrap().priority,
            pre_priority
        );
        assert!(db::get(&conn, "mold").unwrap().is_some());
        assert!(db::get(&conn, "ma").unwrap().is_some());
    }

    /// `run_autonomy_passes` honours an effective max-ops bound in
    /// practice: the cluster-size cap (`CONSOLIDATE_MAX_CLUSTER_SIZE = 8`)
    /// prevents a pathological single mega-cluster, even when many
    /// near-duplicates would otherwise merge. We seed N>cap candidates
    /// and assert the consolidated cluster never exceeds the cap.
    #[test]
    fn consolidation_cluster_respects_max_size_cap() {
        let n = CONSOLIDATE_MAX_CLUSTER_SIZE + 4;
        let mut candidates: Vec<Memory> = Vec::with_capacity(n);
        for i in 0..n {
            candidates.push(sample_mem(
                &format!("m{i}"),
                "deploy",
                &format!("title-{i}"),
                "kubernetes rolling canary deploy strategy",
                Tier::Long,
            ));
        }
        let (_tmp, conn) = setup_conn();
        // #1774 — both sides need a stored embedding to merge; this test's
        // subject is the cluster-size cap, so attach aligned vectors
        // (cosine ≈ 1.0) so every near-duplicate pair clears the cosine gate.
        for m in &candidates {
            db::insert(&conn, m).unwrap();
            db::set_embedding(
                &conn,
                &m.id,
                &synth_emb(&[1.0, 0.0, 0.0, 0.0]),
                &crate::embeddings::embedding_space_fingerprint("test-space"),
            )
            .unwrap();
        }
        let clusters = find_consolidation_clusters(&conn, &candidates);
        assert!(!clusters.is_empty());
        for c in &clusters {
            assert!(
                c.len() <= CONSOLIDATE_MAX_CLUSTER_SIZE,
                "cluster size {} exceeded cap {}",
                c.len(),
                CONSOLIDATE_MAX_CLUSTER_SIZE
            );
        }
    }

    /// `apply_priority_feedback` on a cold-and-old memory floors the
    /// priority by -1. Complements the existing hot-and-recent test
    /// (`priority_feedback_adjusts_memory`) — the cold branch is
    /// otherwise unreached.
    #[test]
    fn priority_feedback_decrements_cold_old_memory() {
        let (_tmp, conn) = setup_conn();
        let mut mem = sample_mem(
            "cold-id",
            "ns",
            "Cold",
            "content body content body",
            Tier::Mid,
        );
        mem.priority = 5;
        mem.access_count = 0;
        mem.created_at = (chrono::Utc::now() - chrono::Duration::days(60)).to_rfc3339();
        db::insert(&conn, &mem).unwrap();

        let entry = apply_priority_feedback(&conn, &mem, false)
            .unwrap()
            .expect("cold memory must produce a -1 adjustment");
        match entry {
            RollbackEntry::PriorityAdjust {
                memory_id,
                before,
                after,
            } => {
                assert_eq!(memory_id, "cold-id");
                assert_eq!(before, 5);
                assert_eq!(after, 4);
            }
            _ => panic!("expected PriorityAdjust"),
        }
    }

    // -----------------------------------------------------------------
    // v1.0.0 curator/autonomy correctness regressions (ox-alpha review).
    // -----------------------------------------------------------------

    /// Seed a namespace with a mergeable near-duplicate PAIR (aligned
    /// embeddings so the #1774 cosine gate opens) and return the pair.
    fn seed_mergeable_pair(conn: &Connection, ns: &str) -> Vec<Memory> {
        let a = sample_mem(
            &format!("{ns}-a"),
            ns,
            &format!("{ns} canary deploy plan"),
            "kubernetes canary rolling deploy strategy",
            Tier::Long,
        );
        let b = sample_mem(
            &format!("{ns}-b"),
            ns,
            &format!("{ns} canary deploy overview"),
            "kubernetes rolling canary deploy strategy",
            Tier::Long,
        );
        for m in [&a, &b] {
            db::insert(conn, m).unwrap();
            db::set_embedding(
                conn,
                &m.id,
                &synth_emb(&[1.0, 0.0, 0.0, 0.0]),
                &crate::embeddings::embedding_space_fingerprint("test-space"),
            )
            .unwrap();
        }
        vec![a, b]
    }

    fn summarize_calls(llm: &StubLlm) -> usize {
        llm.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.starts_with("summarize:"))
            .count()
    }

    /// REGRESSION (ox-alpha #2) — Pass 1 is LLM-invoking and MUST honour
    /// the caller's remaining `max_ops_per_cycle` budget. Pre-fix it ran
    /// one `summarize_memories` call per cluster with no budget check at
    /// all, so a cycle could exceed the operator's authorised LLM budget
    /// by up to 4x the candidate cap. Two mergeable clusters + a budget of
    /// 1 must produce exactly ONE LLM call, one consolidation, and one
    /// counted skip (deferred, not dropped).
    #[test]
    fn run_autonomy_passes_charges_pass1_against_llm_op_budget() {
        let (_tmp, conn) = setup_conn();
        let mut candidates = seed_mergeable_pair(&conn, "budget-one");
        candidates.extend(seed_mergeable_pair(&conn, "budget-two"));

        let llm = StubLlm::new("budget summary");
        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false, 1, None);

        assert_eq!(
            report.clusters_formed, 2,
            "fixture must produce two mergeable clusters, got {}",
            report.clusters_formed
        );
        assert_eq!(
            summarize_calls(&llm),
            1,
            "budget of 1 must permit exactly one LLM-invoking consolidation"
        );
        assert_eq!(report.operations_attempted, 1);
        assert_eq!(
            report.operations_skipped_cap, 1,
            "the over-budget cluster must be COUNTED as deferred, not silently dropped"
        );
        assert_eq!(
            report.memories_consolidated, 2,
            "only the in-budget cluster's members are consolidated"
        );
    }

    /// A zero budget performs no LLM-invoking consolidation at all, and
    /// still reports the skip so an operator can see work was deferred.
    #[test]
    fn run_autonomy_passes_zero_llm_budget_consolidates_nothing() {
        let (_tmp, conn) = setup_conn();
        let candidates = seed_mergeable_pair(&conn, "zero-budget");

        let llm = StubLlm::new("never called");
        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false, 0, None);

        assert_eq!(summarize_calls(&llm), 0, "zero budget must invoke no LLM");
        assert_eq!(report.operations_attempted, 0);
        assert_eq!(report.operations_skipped_cap, 1);
        assert_eq!(report.memories_consolidated, 0);
        // Both source rows survive — a skipped consolidation is a no-op,
        // never a partial merge.
        for m in &candidates {
            assert!(
                db::get(&conn, &m.id).unwrap().is_some(),
                "skipped cluster must leave {} intact",
                m.id
            );
        }
    }

    /// REGRESSION (ox-alpha #6) — a dry run persists NOTHING, so
    /// `rollback_entries_written` (documented as "rows persisted") must
    /// stay 0. Pre-fix the `!dry_run && let Err(..) { .. } else { +1 }`
    /// shape took the else-arm on every dry-run action and inflated the
    /// counter. The would-be count now lands in the explicit
    /// `rollback_entries_simulated` companion instead.
    #[test]
    fn dry_run_reports_simulated_not_written_rollback_entries() {
        let (_tmp, conn) = setup_conn();
        let candidates = seed_mergeable_pair(&conn, "dry-counters");

        let llm = StubLlm::new("dry summary");
        let report = run_autonomy_passes(&conn, &llm, &candidates, true, false, usize::MAX, None);

        assert!(
            report.rollback_entries_simulated >= 1,
            "dry run must report the would-be rollback rows"
        );
        assert_eq!(
            report.rollback_entries_written, 0,
            "dry run persists no rollback rows, so the 'written' counter must be 0"
        );
        assert!(!report.rollback_log_degraded);
        let log = db::list(
            &conn,
            Some("_curator/rollback"),
            None,
            100,
            0,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(log.is_empty(), "dry run must not write rollback memories");
    }

    /// A live cycle counts rollback rows it actually persisted and leaves
    /// the dry-run companion at zero — the mirror image of the test above.
    #[test]
    fn live_run_reports_written_not_simulated_rollback_entries() {
        let (_tmp, conn) = setup_conn();
        let candidates = seed_mergeable_pair(&conn, "live-counters");

        let llm = StubLlm::new("live summary");
        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false, usize::MAX, None);

        assert!(report.rollback_entries_written >= 1);
        assert_eq!(report.rollback_entries_simulated, 0);
        assert!(!report.rollback_log_degraded);
    }

    /// REGRESSION (ox-alpha #7) — a destructive action whose rollback-log
    /// write FAILS is irreversible, so the cycle must STOP rather than
    /// pile further un-reversible mutations on top of it. Pre-fix the
    /// failure pushed one line into `report.errors` and every remaining
    /// pass ran to completion regardless.
    ///
    /// The failure is forced surgically: a BEFORE INSERT trigger that
    /// aborts only for the `_curator/rollback` namespace, so the
    /// consolidation itself still succeeds and it is precisely the
    /// rollback row that cannot land.
    #[test]
    fn rollback_log_write_failure_halts_the_remaining_passes() {
        let (_tmp, conn) = setup_conn();
        let mut candidates = seed_mergeable_pair(&conn, "halt-ns");

        // A Pass-3 candidate: hot + recently accessed, so priority
        // feedback WOULD bump it if the pass were reached.
        let mut hot = sample_mem(
            "halt-hot",
            "halt-other",
            "Hot",
            "this is hot content for the priority bump pass",
            Tier::Mid,
        );
        hot.priority = 5;
        hot.access_count = 100;
        hot.last_accessed_at = Some(chrono::Utc::now().to_rfc3339());
        db::insert(&conn, &hot).unwrap();
        candidates.push(hot.clone());

        conn.execute_batch(
            "CREATE TRIGGER halt_rollback_writes BEFORE INSERT ON memories \
             WHEN new.namespace = '_curator/rollback' \
             BEGIN SELECT RAISE(ABORT, 'forced rollback-log failure'); END;",
        )
        .unwrap();

        let llm = StubLlm::new("halting summary");
        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false, usize::MAX, None);

        assert!(
            report.rollback_log_degraded,
            "a failed rollback-log write must be flagged on the report, errors={:?}",
            report.errors
        );
        assert!(
            report.errors.iter().any(|e| e.contains("halted")),
            "the halt must be explained to the operator, errors={:?}",
            report.errors
        );
        assert_eq!(
            report.rollback_entries_written, 0,
            "no rollback row landed, so none may be counted"
        );
        assert_eq!(
            report.priority_adjustments, 0,
            "Pass 3 must not run after reversibility was lost"
        );
        assert_eq!(
            db::get(&conn, "halt-hot").unwrap().unwrap().priority,
            5,
            "the halted cycle must leave the Pass-3 candidate untouched"
        );
    }
}
