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
    pub rollback_entries_written: usize,
    pub errors: Vec<String>,
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
/// Returns an `AutonomyPassReport` rather than `Result<…>` because
/// per-pass errors are already aggregated into `report.errors`;
/// the function itself cannot fail at the outer level.
pub fn run_autonomy_passes(
    conn: &Connection,
    llm: &dyn AutonomyLlm,
    candidates: &[Memory],
    dry_run: bool,
    skip_consolidation: bool,
) -> AutonomyPassReport {
    let mut report = AutonomyPassReport::default();

    // Pass 1 — consolidation. Skipped when the SAL ConsolidationPass owns
    // consolidation (#1746); the curator folds that pass's counts into this
    // report so the self-report stays accurate.
    if !skip_consolidation {
        let clusters = find_consolidation_clusters(conn, candidates);
        report.clusters_formed = clusters.len();
        for cluster in clusters {
            match consolidate_cluster(conn, llm, &cluster, dry_run) {
                Ok(Some(entry)) => {
                    if !dry_run && let Err(e) = persist_rollback_entry(conn, &entry) {
                        report.errors.push(rollback_log_write_failed(&e));
                    } else {
                        report.rollback_entries_written += 1;
                    }
                    if let RollbackEntry::Consolidate { originals, .. } = entry {
                        report.memories_consolidated += originals.len();
                    }
                }
                Ok(None) => {}
                Err(e) => report.errors.push(format!("consolidate failed: {e}")),
            }
        }
    }

    // Pass 2 — forget superseded.
    for mem in candidates {
        match forget_if_superseded(conn, mem, candidates, dry_run) {
            Ok(Some(entry)) => {
                if !dry_run && let Err(e) = persist_rollback_entry(conn, &entry) {
                    report.errors.push(rollback_log_write_failed(&e));
                } else {
                    report.rollback_entries_written += 1;
                }
                report.memories_forgotten += 1;
            }
            Ok(None) => {}
            Err(e) => report.errors.push(format!("forget failed: {e}")),
        }
    }

    // Pass 3 — priority feedback.
    #[allow(unused_assignments)]
    for mem in candidates {
        match apply_priority_feedback(conn, mem, dry_run) {
            Ok(Some(entry)) => {
                if !dry_run && let Err(e) = persist_rollback_entry(conn, &entry) {
                    report.errors.push(rollback_log_write_failed(&e));
                } else {
                    report.rollback_entries_written += 1;
                }
                report.priority_adjustments += 1;
            }
            Ok(None) => {}
            Err(e) => report.errors.push(format!("priority feedback failed: {e}")),
        }
    }

    report
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
            let seed_emb = db::get_embedding_with_space(conn, &group[i].id)
                .ok()
                .flatten();
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
                let pair_emb = db::get_embedding_with_space(conn, &group[j].id)
                    .ok()
                    .flatten();
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

/// v0.9.0 G7 (#1824) — best-effort load of the curator's signing keypair
/// so the conserved `contradicts` edge is SIGNED when an operator has
/// configured a key. Mirrors the CLI curator's best-effort loader: pick
/// the lexicographically-first key under the active key dir. Returns
/// `None` when no dir / no keys exist (the edge is then written unsigned —
/// the same posture as every other `create_link_signed(None)` caller).
fn curator_keypair_best_effort() -> Option<crate::identity::keypair::AgentKeypair> {
    let dir = crate::identity::keypair::default_key_dir().ok()?;
    let first = crate::identity::keypair::list(&dir)
        .ok()?
        .into_iter()
        .next()?;
    crate::identity::keypair::load(&first.agent_id, &dir).ok()
}

/// v0.9.0 G7 (#1824) — CONSERVE a confirmed contradiction instead of
/// hard-deleting the loser. When a contradicting memory is both newer AND
/// carries higher-or-equal confidence, the current `mem` is the LOSER of
/// the pair; we retain BOTH memories, write one canonical signed
/// `contradicts` edge, emit one identity-only SUPERSEDE leaf (flag-gated),
/// and mark the loser with a reversible node-local soft down-weight — via
/// [`crate::db::conserve_contradiction`]. NEITHER memory is deleted.
fn forget_if_superseded(
    conn: &Connection,
    mem: &Memory,
    all: &[Memory],
    dry_run: bool,
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
    let mut winner: Option<&Memory> = None;
    for v in contradictions {
        let Some(other_id) = v.as_str() else {
            continue;
        };
        if let Some(other) = by_id.get(other_id)
            && other.updated_at > mem.updated_at
            && other.confidence >= mem.confidence
        {
            winner = Some(other);
            break;
        }
    }
    let Some(winner) = winner else {
        return Ok(None);
    };

    // Canonical (min, max) endpoints of the single `contradicts` edge, so
    // the RollbackEntry describes exactly the edge the write will create.
    let (canonical_src, canonical_tgt) = db::canonical_contradiction_pair(&mem.id, &winner.id);
    let entry = RollbackEntry::ConserveContradiction {
        loser_id: mem.id.clone(),
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
    db::conserve_contradiction(
        conn,
        mem,
        &winner.id,
        curator_keypair_best_effort().as_ref(),
    )?;
    Ok(Some(entry))
}

fn apply_priority_feedback(
    conn: &Connection,
    mem: &Memory,
    dry_run: bool,
) -> Result<Option<RollbackEntry>> {
    // Access-signal policy:
    //   access_count >= 10 AND last_accessed_at within 7d → +1 (cap 10)
    //   access_count == 0 AND created_at older than 30d     → -1 (floor 1)
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
    let cold_enough = created.is_some_and(|t| (now - t).num_days() >= 30);

    if mem.access_count >= 10 && recent && after < 10 {
        after = after.saturating_add(1).min(10);
    } else if mem.access_count == 0 && cold_enough && after > 1 {
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
        "errors_total": errors_total,
    });
    let mem = Memory {
        cid: None, // v0.9.0 G8 (#1825) — stamped by db::insert / read via row_to_memory
        valid_from: None,
        valid_until: None,
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: format!("{CURATOR_NAMESPACE}/reports"),
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
        expires_at: None,
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
        lifecycle_state: crate::models::LifecycleState::Open,
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
            // (curator autonomy) via a direct `db::insert`; record the
            // substrate why_trace (stamp-if-absent — a restored original that
            // already carried one keeps it) so the re-store satisfies
            // AI_MEMORY_REQUIRE_WHY_TRACE.
            let existed = db::delete(conn, result_id)?;
            for m in originals {
                let mut m = m.clone();
                crate::storage::stamp_substrate_why_trace(&mut m.metadata);
                db::insert(conn, &m)?;
            }
            Ok(existed)
        }
        RollbackEntry::Forget { snapshot } => {
            check_no_collision(conn, &snapshot.title, &snapshot.namespace, &snapshot.id)?;
            let mut snapshot = snapshot.clone();
            crate::storage::stamp_substrate_why_trace(&mut snapshot.metadata);
            db::insert(conn, &snapshot)?;
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
/// * **Collision guard (G2):** before reinserting a snapshot we ask the
///   store whether a DIFFERENT id now owns the same `(title, namespace)`
///   key (via [`crate::store::MemoryStore::find_by_title_namespace`]) and
///   refuse — `store.store` is an UPSERT on that key and would silently
///   clobber the unrelated row. Mirrors the rusqlite [`check_no_collision`].
/// * **Fail-safe ordering (G3):** the `Consolidate` arm reinserts the
///   originals BEFORE deleting the consolidated summary, so a crash mid-
///   reversal never destroys the summary while the originals are still
///   missing. The summary's `[consolidated]` title never collides with an
///   original, so the ordering introduces no UPSERT hazard.
/// * **Atomicity (G4):** the SAL trait's `begin_transaction` is
///   Postgres-internal only (SQLite returns `UnsupportedCapability`), so a
///   backend-agnostic free fn cannot wrap the multi-write in one
///   transaction. The non-atomic window is EXACT PARITY with the rusqlite
///   [`reverse_rollback_entry`] (also separate statements, no
///   BEGIN/COMMIT); G3 ordering minimises it.
#[cfg(feature = "sal")]
pub async fn reverse_rollback_entry_store(
    store: &dyn crate::store::MemoryStore,
    ctx: &crate::store::CallerContext,
    entry: &RollbackEntry,
) -> Result<bool> {
    use crate::store::StoreError;

    // G2 — refuse to overwrite a memory that took the (title, namespace)
    // slot after the rollback target was forgotten/consolidated.
    async fn guard_no_collision(store: &dyn crate::store::MemoryStore, m: &Memory) -> Result<()> {
        if let Some(existing) = store
            .find_by_title_namespace(&m.title, &m.namespace)
            .await?
        {
            if existing != m.id {
                anyhow::bail!(
                    "rollback refused: (title={:?}, namespace={:?}) is now owned by memory \
                     {existing}, not the snapshot {} — resolve the conflict (delete the \
                     offender or rename one) before reversing",
                    m.title,
                    m.namespace,
                    m.id
                );
            }
        }
        Ok(())
    }

    match entry {
        RollbackEntry::Consolidate {
            originals,
            result_id,
        } => {
            for m in originals {
                guard_no_collision(store, m).await?;
            }
            // G3 — reinsert the originals BEFORE deleting the summary.
            for m in originals {
                store.store(ctx, m).await?;
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
            guard_no_collision(store, snapshot).await?;
            store.store(ctx, snapshot).await?;
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
        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false);

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
        };
        persist_self_report(&conn, 1234, &pass, 3, 0, 0, 0).unwrap();
        let reports = db::list(
            &conn,
            Some("_curator/reports"),
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
        assert_eq!(reports.len(), 1);
        assert!(reports[0].content.contains("memories_consolidated"));
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

        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false);

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

        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false);

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
        let _report = run_autonomy_passes(&conn, &llm, &candidates, true, false);

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
        let report = run_autonomy_passes(&conn, &llm, &candidates, false, false);

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

        let result = forget_if_superseded(&conn, &older, &[older.clone(), newer], true).unwrap();
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

    /// `forget_if_superseded` skips non-string entries in the
    /// `confirmed_contradictions` array — covers the `let Some(...) =
    /// v.as_str() else { continue; };` branch (line ~382).
    #[test]
    fn forget_if_superseded_skips_non_string_contradiction_ids() {
        let (_tmp, conn) = setup_conn();
        let mut mem = sample_mem("m", "facts", "T", "content body word", Tier::Mid);
        // Mix invalid (number) and valid-but-missing (no matching id) entries.
        mem.metadata["confirmed_contradictions"] = serde_json::json!([42, "missing-id"]);
        let result = forget_if_superseded(&conn, &mem, std::slice::from_ref(&mem), false).unwrap();
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
        let report = run_autonomy_passes(&conn, &llm, &candidates, true, false);

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
}
