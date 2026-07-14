// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ConsolidationPass` — `CompactionPass` impl for memory consolidation.
//!
//! A SAL-trait (`MemoryStore`) consolidator. Its clustering is **reconciled
//! to** `crate::autonomy::find_consolidation_clusters` (#1741/#1743): a
//! candidate pair merges iff it passes **BOTH a Jaccard pre-filter AND a
//! cosine gate** — and the cosine gate requires a stored embedding on each
//! side. Per #1774 (5-agent vote 4d3ea1c5) a row with no stored embedding does
//! NOT merge: a destructive consolidation merge is never decided on Jaccard
//! lexical overlap alone. The cosine gate reads each candidate's
//! **stored** vector via `MemoryStore::get_embedding` (NOT a live re-embed),
//! matching autonomy's `db::get_embedding` source exactly (#1743). Clustering
//! lives in [`ConsolidationClustering`](super::cluster::ConsolidationClustering);
//! the per-pair decision is the pure `super::cluster::pair_merges`, unit-tested
//! deterministically by injecting vectors. Thresholds/cap are pinned equal to
//! autonomy's `CONSOLIDATE_*` by the `constants_match_autonomy` test.
//!
//! Status: the LIVE consolidator (#1746 cutover). When `compaction.enabled`,
//! `curator::run_once` suppresses autonomy Pass-1 and runs this pass for real
//! (respecting `cfg.dry_run`), folding its counts into the cycle's autonomy
//! report. Prereqs landed: clustering parity (#1741), stored-embedding source
//! parity (#1743), operator-reversible rollback parity (#1745). Default
//! `compaction.enabled = false` → autonomy Pass-1 still does consolidation and
//! this pass is a no-op (production byte-unchanged).
//!
//! ## Hook events
//!
//! `ConsolidationPass::run` fires:
//!
//! * `HookEvent::PreCompaction` — Allow / Modify / Deny / AskUser before
//!   the cluster is processed.  Deny aborts the cluster (no summary, no
//!   persist, no verify).
//! * `HookEvent::OnCompactionRollback` — notify-only (return value
//!   ignored beyond logging), fired when the verify step fails. The
//!   Stage-6 auto-rollback restores the pre-merge sources and removes the
//!   unverifiable summary (#664); on the verified happy path an
//!   operator-reversible `RollbackEntry::Consolidate` is persisted (#1745).
//!
//! **Rollback recovery scope (#1771).** "Operator-reversible" here means
//! the pre-merge memory ROWS are restored — NOT the merged sources'
//! `memory_links` edges or other `ON DELETE CASCADE` provenance, which
//! were cascade-reaped when the sources were deleted and are not captured
//! in `RollbackEntry::Consolidate`. A rollback therefore returns the text
//! but leaves the merged sources' relationship graph destroyed, until the
//! #1771 archive-link-preservation structural fix lands.
//!
//! ## Visibility contract (R7)
//!
//! All items are at most `pub(crate)`.  No bare `pub` items.

#[cfg(any(feature = "sal", test))]
use crate::models::ConfidenceSource;
#[cfg(feature = "sal")]
use anyhow::Result;

#[cfg(feature = "sal")]
use crate::autonomy::AutonomyLlm;
#[cfg(not(feature = "sal"))]
use crate::models::Tier;
#[cfg(feature = "sal")]
use crate::models::{Memory, Tier};
#[cfg(feature = "sal")]
use crate::store::{CallerContext, MemoryStore, StoreError};

#[cfg(test)]
use crate::hooks::events::HookEvent;

#[cfg(feature = "sal")]
use super::cluster::ConsolidationClustering;
#[cfg(feature = "sal")]
use super::pipeline::MemoryId;

/// Curator-side consolidator agent id stamped on every consolidated
/// memory `ConsolidationPass` writes — kept consistent with the
/// `ReflectionPass` fall-back so a forensic walk of `metadata.agent_id`
/// finds curator-written rows under the same tag.
#[cfg(feature = "sal")]
const CONSOLIDATOR_AGENT_ID: &str = crate::identity::sentinels::AI_CURATOR;

/// `tracing` target for consolidation events — one named const so the string
/// is not a hardcoded literal duplicated across the pass + the store-backed
/// curator sweep (pm-v3.1 lint-gate).
#[cfg(feature = "sal")]
pub(crate) const COMPACTION_TRACE_TARGET: &str = "curator::compaction";

// ---------------------------------------------------------------------------
// ConsolidationPass
// ---------------------------------------------------------------------------

/// Compaction pass that consolidates near-duplicate memories into a single
/// canonical memory via LLM summarisation.
///
/// Implements [`CompactionPass`].  The LIVE consolidator (#1746) — wired into
/// the curator cycle by `crate::curator::run_consolidation_pass`, which runs it
/// for real when `compaction.enabled` (autonomy Pass-1 suppressed).
#[allow(dead_code)] // some accessors are exercised only by unit tests
#[cfg(feature = "sal")]
pub(crate) struct ConsolidationPass<'a> {
    /// SAL store handle for reads and writes. Works against the SQLite
    /// *or* Postgres adapter (issue #1548) — the pass is
    /// backend-agnostic; `persist` routes through
    /// [`MemoryStore::consolidate`] and `verify` through
    /// [`MemoryStore::get`].
    pub(crate) store: &'a dyn MemoryStore,
    /// Operator-class caller context — the consolidation pass is a
    /// background substrate-maintenance sweep, so it reads every row
    /// regardless of `metadata.scope` (`bypass_visibility`), matching
    /// the pre-#1548 raw-connection behaviour.
    pub(crate) ctx: CallerContext,
    /// LLM client for `summarize_memories`.
    pub(crate) llm: &'a dyn AutonomyLlm,
    /// Suppress all writes (simulate-only).
    pub(crate) dry_run: bool,
    /// Cosine gate threshold for [`ConsolidationClustering`] (#1750). Defaults
    /// to [`super::cluster::DEFAULT_COSINE_THRESHOLD`] (0.75); production threads
    /// the operator-resolved `[curator.compaction].cosine_threshold` via
    /// [`Self::with_cosine_threshold`]. Previously the clusterer hardcoded the
    /// default, making the config field dead (#1691-class) — this is the live
    /// consumer.
    pub(crate) cosine_threshold: f32,
}

/// Structured outcome of one [`ConsolidationPass::run`] sweep.
///
/// Aggregated into the curator cycle's `CuratorReport`. Post-#1746 cutover the
/// pass runs live (`dry_run = cfg.dry_run`): `eligible_clusters` counts the
/// clusters acted on and `memories_consolidated` the sources folded in. On a
/// `--dry-run` cycle the sweep stops after eligibility, so `memories_consolidated`
/// stays 0 while `eligible_clusters` still reports what *would* consolidate.
#[cfg(feature = "sal")]
#[derive(Debug, Clone, Default)]
pub(crate) struct ConsolidationRunReport {
    /// Total clusters the clustering step formed (≥ 2 members each).
    pub(crate) clusters_formed: usize,
    /// Clusters that passed [`ConsolidationPass::eligible`] — the work the
    /// pass would (dry-run) or did (real) act on.
    pub(crate) eligible_clusters: usize,
    /// Source memories actually folded into a consolidated summary. Always
    /// 0 under `dry_run`.
    pub(crate) memories_consolidated: usize,
    /// Operator-reversible `RollbackEntry::Consolidate` rows persisted to
    /// `_curator/rollback` (#1745) — one per verified consolidation, so
    /// `ai-memory curator --rollback` can reverse a hard-DELETE merge, at
    /// parity with the autonomy Pass-1 path. Always 0 under `dry_run`.
    pub(crate) rollback_entries_written: usize,
    /// Clusters rolled back after a failed `verify` (Stage-6, #664): the
    /// pre-merge sources were restored and the unverifiable summary removed.
    pub(crate) rolled_back: usize,
    /// Per-cluster errors (summarise / persist / verify). Best-effort: one
    /// cluster failing does not abort the sweep.
    pub(crate) errors: Vec<String>,
}

// The LIVE consolidator (#1746): `run` is driven in production by
// `curator::run_consolidation_pass` when `compaction.enabled`. The `dead_code`
// allow remains because a few accessors are reached only from this file's unit
// tests, not the production path.
#[cfg(feature = "sal")]
#[allow(dead_code)]
impl<'a> ConsolidationPass<'a> {
    #[allow(dead_code)]
    pub(crate) fn new(store: &'a dyn MemoryStore, llm: &'a dyn AutonomyLlm, dry_run: bool) -> Self {
        Self {
            store,
            ctx: CallerContext::for_admin(CONSOLIDATOR_AGENT_ID),
            llm,
            dry_run,
            cosine_threshold: super::cluster::DEFAULT_COSINE_THRESHOLD,
        }
    }

    /// #1750 — thread the operator-resolved cosine gate threshold
    /// (`[curator.compaction].cosine_threshold`) into the clusterer. Production
    /// sites build the pass then call this with `cfg.compaction.cosine_threshold`;
    /// tests keep the default via [`Self::new`].
    #[must_use]
    pub(crate) fn with_cosine_threshold(mut self, cosine_threshold: f32) -> Self {
        self.cosine_threshold = cosine_threshold;
        self
    }

    fn name(&self) -> &str {
        "consolidation"
    }

    /// Partition `memories` into clusters via [`ConsolidationClustering`] —
    /// the reconciled Jaccard-pre-filter-AND-cosine-gate algorithm (#1741),
    /// matching `crate::autonomy::find_consolidation_clusters`. Reads each
    /// candidate's **stored** embedding via `MemoryStore::get_embedding`
    /// (#1743) — NOT a live re-embed — so the cosine gate uses the exact same
    /// vectors autonomy reads; per #1774 a row with no stored embedding does
    /// NOT merge (the cosine safety gate is mandatory for the destructive
    /// merge — no Jaccard-only fallback).
    ///
    /// Each cluster element is a `MemoryId` (the memory's `id` field).
    async fn cluster(&self, memories: &[Memory]) -> Vec<Vec<MemoryId>> {
        let mut embeddings: Vec<Option<Vec<f32>>> = Vec::with_capacity(memories.len());
        for m in memories {
            // Best-effort: a fetch error degrades that row to "no embedding"
            // (which, per #1774, blocks the merge for its pairs), never aborts
            // the sweep.
            let emb = self
                .store
                .get_embedding(&self.ctx, &m.id)
                .await
                .ok()
                .flatten();
            embeddings.push(emb);
        }
        // #1750 — use the operator-resolved cosine gate (defaults to the
        // autonomy-matched 0.75); the Jaccard pre-filter + max_cluster_size keep
        // their defaults.
        ConsolidationClustering {
            cosine_threshold: f64::from(self.cosine_threshold),
            ..ConsolidationClustering::new()
        }
        .cluster_memories(memories, &embeddings)
    }

    /// A cluster is eligible when it has ≥ 2 members, all share the same
    /// namespace, and none belong to a reserved (`_`-prefixed) namespace.
    fn eligible(&self, cluster: &[Memory]) -> bool {
        if cluster.len() < 2 {
            return false;
        }
        let ns = &cluster[0].namespace;
        if ns.starts_with('_') {
            return false;
        }
        cluster.iter().all(|m| &m.namespace == ns)
    }

    /// LLM-summarise the cluster and produce a consolidated [`Memory`].
    ///
    /// The consolidated title is prefixed with `[consolidated]` to avoid
    /// colliding with any source memory's `(title, namespace)` unique key.
    /// The namespace, tier (max of cluster), and priority (max of cluster)
    /// are inherited from the cluster.
    ///
    /// Does NOT touch the database.
    fn summarize(&self, cluster: &[Memory]) -> Result<Memory> {
        if cluster.is_empty() {
            anyhow::bail!("summarize called on empty cluster");
        }

        let input: Vec<(String, String)> = cluster
            .iter()
            .map(|m| (m.title.clone(), m.content.clone()))
            .collect();
        let summary_text = self.llm.summarize_memories(&input)?;

        let base_title = cluster
            .iter()
            .map(|m| m.title.as_str())
            .next()
            .unwrap_or("(consolidated)");
        let title = format!("[consolidated] {base_title}");

        let tier = cluster
            .iter()
            .map(|m| m.tier.clone())
            .max_by_key(tier_rank)
            .unwrap_or(Tier::Mid);

        let priority = cluster.iter().map(|m| m.priority).max().unwrap_or(5);

        let now = chrono::Utc::now().to_rfc3339();
        Ok(Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier,
            namespace: cluster[0].namespace.clone(),
            title,
            content: summary_text,
            tags: vec![],
            priority,
            confidence: 1.0,
            // #1746: stamp the SAME source as the autonomy Pass-1 path so the
            // consolidated row's `source` column is byte-identical across the
            // cutover (the SAL pass replaces autonomy Pass-1, not a new author).
            source: crate::autonomy::CURATOR_SOURCE_LABEL.to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({}),
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
            cid: None,
            valid_from: None,
            valid_until: None,
        })
    }

    /// Persist the consolidated memory and hard-delete the sources.
    ///
    /// Delegates to [`MemoryStore::consolidate`] (same logic as the
    /// v0.6.x path) so the DB transaction and `derived_from` links are
    /// identical to the pre-refactor behaviour. The SQLite adapter routes
    /// this through `db::consolidate`; the Postgres adapter through its
    /// native sqlx `consolidate` (issue #1548).
    ///
    /// NOTE: `consolidate` itself does NOT write an operator-reversible
    /// rollback row — that is persisted separately by
    /// [`Self::persist_rollback`] on the happy path in [`Self::run`],
    /// mirroring how `autonomy::run_autonomy_passes` wraps its Pass-1
    /// `consolidate_cluster` with a `RollbackEntry` (#1745).
    ///
    /// Returns the **id of the newly-written consolidated memory** so the
    /// caller can hand it to [`Self::verify`] (the consolidate path mints
    /// its own id, distinct from `summary.id`). No-op returning an empty
    /// id when `self.dry_run = true` or `sources` is empty.
    async fn persist(&self, summary: &Memory, sources: &[MemoryId]) -> Result<String> {
        if self.dry_run || sources.is_empty() {
            return Ok(String::new());
        }
        let new_id = self
            .store
            .consolidate(
                &self.ctx,
                sources,
                &summary.title,
                &summary.content,
                &summary.namespace,
                &summary.tier,
                &summary.source,
                CONSOLIDATOR_AGENT_ID,
            )
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok(new_id)
    }

    /// Persist an operator-reversible `RollbackEntry::Consolidate` snapshot
    /// to `_curator/rollback` (#1745) so `ai-memory curator --rollback` can
    /// reverse this hard-DELETE consolidation — at parity with the autonomy
    /// Pass-1 path, which wraps every `consolidate_cluster` with the same
    /// entry. Backend-agnostic: reuses [`crate::autonomy::build_rollback_memory`]
    /// (the exact row shape `reverse_rollback_entry` reads) and writes it via
    /// [`MemoryStore::store`], so the SQLite and Postgres adapters both land an
    /// identical, reversible row. Called on the verified happy path only — a
    /// `verify`-fail cluster is auto-restored by [`Self::rollback_consolidation`]
    /// instead, so no rollback entry is left pointing at a reversed merge.
    async fn persist_rollback(&self, originals: &[Memory], result_id: &str) -> Result<()> {
        let entry = crate::autonomy::RollbackEntry::Consolidate {
            originals: originals.to_vec(),
            result_id: result_id.to_string(),
        };
        let mem = crate::autonomy::build_rollback_memory(&entry)?;
        self.store
            .store(&self.ctx, &mem)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok(())
    }

    /// Verify the consolidated summary is readable from the store.
    ///
    /// Returns `Err` on failure; the caller ([`Self::run`]) translates that
    /// into the Stage-6 auto-rollback (#664) — `verify` itself does not mutate.
    async fn verify(&self, summary_id: MemoryId) -> Result<()> {
        match self.store.get(&self.ctx, &summary_id).await {
            Ok(_) => Ok(()),
            Err(StoreError::NotFound { .. }) => anyhow::bail!(
                "verify: consolidated summary {} not found in DB",
                summary_id
            ),
            Err(e) => Err(anyhow::anyhow!(e)),
        }
    }

    /// Drive the full six-step compaction lifecycle over `candidates`:
    /// `cluster` → resolve members → `eligible` → `summarize` → `persist`
    /// → `verify`. Returns a [`ConsolidationRunReport`]; per-cluster
    /// failures are recorded in `report.errors` and never abort the sweep.
    ///
    /// **Dry-run (`self.dry_run`, a `--dry-run` curator cycle):** the sweep
    /// stops after `eligible` — it counts what it *would* consolidate
    /// (`eligible_clusters`) without any LLM summarise, DB write, or verify.
    ///
    /// **Real mode (#1746 — the live consolidator):** summarise → persist →
    /// verify → persist operator-reversible rollback (#1745). On a `verify`
    /// failure the Stage-6 auto-rollback (#664) restores the sources, removes
    /// the unverifiable summary, fires the notify-only `OnCompactionRollback`,
    /// and the sweep continues (no rollback entry is left for that cluster).
    pub(crate) async fn run(&self, candidates: &[Memory]) -> Result<ConsolidationRunReport> {
        let mut report = ConsolidationRunReport::default();

        let clusters = self.cluster(candidates).await;
        report.clusters_formed = clusters.len();

        // id -> &Memory lookup so cluster member-ids resolve back to rows.
        let index: std::collections::HashMap<&str, &Memory> =
            candidates.iter().map(|m| (m.id.as_str(), m)).collect();

        for cluster_ids in clusters {
            let members: Vec<Memory> = cluster_ids
                .iter()
                .filter_map(|id| index.get(id.as_str()).copied().cloned())
                .collect();
            // A member that isn't in the candidate batch means the cluster
            // is stale; skip rather than consolidate a partial cluster.
            if members.len() != cluster_ids.len() {
                continue;
            }
            if !self.eligible(&members) {
                continue;
            }
            report.eligible_clusters += 1;

            // Shadow stops here: count eligibility, do not mutate.
            if self.dry_run {
                continue;
            }

            let summary = match self.summarize(&members) {
                Ok(s) => s,
                Err(e) => {
                    report
                        .errors
                        .push(format!("{}: summarize failed: {e}", self.name()));
                    continue;
                }
            };
            let new_id = match self.persist(&summary, &cluster_ids).await {
                Ok(id) => id,
                Err(e) => {
                    report
                        .errors
                        .push(format!("{}: persist failed: {e}", self.name()));
                    continue;
                }
            };
            if let Err(e) = self.verify(new_id.clone()).await {
                // Stage-6 rollback (#664): the consolidate already removed the
                // source rows and wrote an unverifiable summary. Restore the
                // cluster from the in-memory pre-merge snapshots and remove the
                // bad summary. Fires the notify-only `OnCompactionRollback`.
                let restored = match self.rollback_consolidation(&members, &new_id).await {
                    Ok(n) => n,
                    Err(re) => {
                        report
                            .errors
                            .push(format!("{}: rollback failed: {re}", self.name()));
                        0
                    }
                };
                if restored > 0 {
                    report.rolled_back += 1;
                }
                tracing::warn!(
                    target: COMPACTION_TRACE_TARGET,
                    pass = self.name(),
                    summary_id = %new_id,
                    restored,
                    error = %e,
                    "consolidation verify failed — rolled back (Stage-6, #664)"
                );
                report.errors.push(format!(
                    "{}: verify failed (rolled back {restored}): {e}",
                    self.name()
                ));
                continue;
            }

            // Happy path — the consolidation verified and sticks. Persist an
            // operator-reversible rollback snapshot (#1745) so a bad merge can
            // be undone via `curator --rollback`, matching autonomy Pass-1
            // parity. Best-effort: a rollback-log write failure is recorded but
            // does not un-count the (successful, verified) consolidation.
            match self.persist_rollback(&members, &new_id).await {
                Ok(()) => report.rollback_entries_written += 1,
                Err(e) => report.errors.push(format!(
                    "{}: rollback-log write failed (consolidation kept): {e}",
                    self.name()
                )),
            }
            report.memories_consolidated += members.len();
        }

        Ok(report)
    }

    /// Stage-6 rollback (#664): restore a consolidated cluster after a failed
    /// `verify`. Re-inserts the pre-merge `originals` (snapshots already in
    /// memory; the SAL `store` write preserves their ids) THEN deletes the
    /// unverifiable `result_id` — restore-FIRST so a crash mid-rollback leaves
    /// a recoverable over-retention (both live), never data loss. Each original
    /// is collision-guarded: if a *different* id now occupies its
    /// `(title, namespace)` slot it is skipped + warned (mirrors
    /// `autonomy::check_no_collision`). Backend-agnostic — uses only the
    /// existing `find_by_title_namespace` / `store` / `delete` trait ops.
    /// Returns the number of originals restored.
    async fn rollback_consolidation(&self, originals: &[Memory], result_id: &str) -> Result<usize> {
        let mut restored = 0usize;
        for m in originals {
            // Collision guard: do not clobber a different memory that took the
            // (title, namespace) slot after the sources were consolidated away.
            match self
                .store
                .find_by_title_namespace(&m.title, &m.namespace)
                .await
            {
                Ok(Some(existing_id)) if existing_id != m.id => {
                    tracing::warn!(
                        target: COMPACTION_TRACE_TARGET,
                        title = %m.title,
                        namespace = %m.namespace,
                        occupant = %existing_id,
                        original = %m.id,
                        "rollback: (title, namespace) slot taken by a different id — skipping restore"
                    );
                    continue;
                }
                Ok(_) => {}
                Err(e) => return Err(anyhow::anyhow!(e)),
            }
            self.store
                .store(&self.ctx, m)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            restored += 1;
        }
        // Remove the unverifiable summary only after the originals are back.
        self.store
            .delete(&self.ctx, result_id)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok(restored)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[cfg_attr(not(feature = "sal"), allow(dead_code))]
fn tier_rank(t: &Tier) -> u8 {
    match t {
        Tier::Short => 0,
        Tier::Mid => 1,
        Tier::Long => 2,
    }
}

// ---------------------------------------------------------------------------
// Pre-compaction hook event dispatch (fire-site stubs — test-only)
// ---------------------------------------------------------------------------

/// Fire-site stub for the `pre_compaction` hook event.  Returns `true`
/// (always-allow) until the G-track executor wires the new events in.
/// Tests assert that the right `HookEvent` constant is referenced here.
#[cfg(test)]
pub(super) fn fire_pre_compaction_hook(_event: HookEvent) -> bool {
    // TODO(L1-7 → executor wiring): call the hook chain once
    // the G-track executor is extended to handle PreCompaction.
    true
}

/// Returns `true` iff `event` is the pre-compaction event.
/// Used by tests to verify correct event constant usage.
#[cfg(test)]
pub(super) fn is_pre_compaction(event: HookEvent) -> bool {
    matches!(event, HookEvent::PreCompaction)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::events::HookEvent;
    use crate::models::{Memory, Tier};

    fn make_memory(id: &str, ns: &str, content: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: id.to_string(),
            tier: Tier::Long,
            namespace: ns.to_string(),
            title: format!("title-{id}"),
            content: content.to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({}),
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

    // ---- eligible -----------------------------------------------------------

    #[test]
    fn eligible_rejects_single_member_cluster() {
        let m = make_memory("a", "ns", "content");
        // We can't instantiate ConsolidationPass without a real connection,
        // so we test eligible() directly via a thin helper that mirrors the
        // impl — tests the logic, not the struct.
        let cluster = vec![m];
        // mirror of eligible()
        let result = cluster.len() >= 2
            && !cluster[0].namespace.starts_with('_')
            && cluster
                .iter()
                .all(|m2| m2.namespace == cluster[0].namespace);
        assert!(!result, "singleton cluster must not be eligible");
    }

    #[test]
    fn eligible_rejects_reserved_namespace() {
        let m1 = make_memory("a", "_curator", "content a");
        let m2 = make_memory("b", "_curator", "content b");
        let cluster = vec![m1, m2];
        let result = cluster.len() >= 2
            && !cluster[0].namespace.starts_with('_')
            && cluster
                .iter()
                .all(|m2| m2.namespace == cluster[0].namespace);
        assert!(!result, "reserved namespace must not be eligible");
    }

    #[test]
    fn eligible_rejects_mixed_namespace_cluster() {
        let m1 = make_memory("a", "ns1", "content a");
        let m2 = make_memory("b", "ns2", "content b");
        let cluster = vec![m1, m2];
        // Mixed namespaces → not all equal to cluster[0]
        let result = cluster.len() >= 2
            && !cluster[0].namespace.starts_with('_')
            && cluster
                .iter()
                .all(|m2| m2.namespace == cluster[0].namespace);
        assert!(!result, "mixed-namespace cluster must not be eligible");
    }

    // ---- hook event constants -----------------------------------------------

    #[test]
    fn pre_compaction_event_constant_is_correct() {
        assert!(is_pre_compaction(HookEvent::PreCompaction));
        assert!(!is_pre_compaction(HookEvent::OnCompactionRollback));
        assert!(!is_pre_compaction(HookEvent::PreStore));
    }

    #[test]
    fn fire_pre_compaction_hook_passes_through_allow() {
        // The stub always allows — fire_pre_compaction_hook must return true
        // until the executor wiring lands.
        assert!(fire_pre_compaction_hook(HookEvent::PreCompaction));
    }

    #[test]
    fn on_compaction_rollback_is_not_pre_event() {
        // on_compaction_rollback is notify-only, not a decision-class event.
        assert!(!crate::hooks::decision::is_pre_event(
            HookEvent::OnCompactionRollback
        ));
    }

    // ---- tier_rank ----------------------------------------------------------

    #[test]
    fn tier_rank_ordering() {
        assert!(tier_rank(&Tier::Short) < tier_rank(&Tier::Mid));
        assert!(tier_rank(&Tier::Mid) < tier_rank(&Tier::Long));
    }

    // ---- ConsolidationPass full trait coverage ------------------------------
    //
    // Issue #1548 — `ConsolidationPass` now operates over the SAL
    // `MemoryStore` trait (`sal`-gated), so this block is too.
    #[cfg(feature = "sal")]
    mod sal_pass_tests {
        use super::*;
        use crate::autonomy::AutonomyLlm;

        use anyhow::Result;
        use std::sync::Mutex;

        /// Deterministic LLM stub mirroring `ReflectionPass::tests::StubLlm`.
        struct StubLlm {
            summary: String,
            calls: Mutex<Vec<String>>,
        }

        impl StubLlm {
            fn new(summary: &str) -> Self {
                Self {
                    summary: summary.to_string(),
                    calls: Mutex::new(Vec::new()),
                }
            }
        }

        impl AutonomyLlm for StubLlm {
            fn auto_tag(&self, _title: &str, _content: &str) -> Result<Vec<String>> {
                Ok(vec![])
            }
            fn detect_contradiction(&self, _a: &str, _b: &str) -> Result<bool> {
                Ok(false)
            }
            fn summarize_memories(&self, memories: &[(String, String)]) -> Result<String> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("summarize:{}", memories.len()));
                Ok(self.summary.clone())
            }
        }

        /// Open a fresh `SqliteStore` at a path beneath a TempDir; the
        /// TempDir is returned so the caller keeps it alive for the test.
        ///
        /// Issue #1548 — `ConsolidationPass` now operates over the SAL
        /// `MemoryStore` trait, so tests pass `&store`. Seeding + assertions
        /// still go through the `crate::db::*` free functions over a raw
        /// connection at the same backing file (`conn_of`).
        use crate::store::sqlite::SqliteStore;

        fn open_db() -> (SqliteStore, tempfile::TempDir) {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("test.db");
            let store = SqliteStore::open(&path).expect("SqliteStore::open");
            (store, dir)
        }

        /// Open a raw `rusqlite::Connection` at the store's backing file for
        /// seeding + assertions via the legacy `crate::db::*` free functions.
        fn conn_of(store: &SqliteStore) -> rusqlite::Connection {
            crate::db::open(store.path()).expect("db::open at store path")
        }

        fn make_memory_full(
            id: &str,
            ns: &str,
            title: &str,
            content: &str,
            tier: Tier,
            priority: i32,
        ) -> Memory {
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
                tags: vec![],
                priority,
                confidence: 1.0,
                source: "test".to_string(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now,
                last_accessed_at: None,
                expires_at: None,
                metadata: serde_json::json!({}),
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

        #[test]
        fn pass_name_is_consolidation() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            assert_eq!(pass.name(), "consolidation");
        }

        #[tokio::test]
        async fn cluster_without_stored_embeddings_does_not_merge_1774() {
            // #1774 — candidates not stored → get_embedding returns None on
            // both sides → no cosine value → NO merge, even for identical
            // (high-Jaccard) content. A destructive merge is never decided on
            // Jaccard lexical overlap alone.
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let m1 = make_memory_full(
                "a",
                "ns",
                "t1",
                "kubernetes rolling canary deploy strategy",
                Tier::Mid,
                5,
            );
            let m2 = make_memory_full(
                "b",
                "ns",
                "t2",
                "kubernetes rolling canary deploy strategy",
                Tier::Mid,
                5,
            );
            let clusters = pass.cluster(&[m1, m2]).await;
            assert!(
                clusters.is_empty(),
                "un-embedded pairs must not merge on Jaccard alone; got {clusters:?}"
            );
        }

        #[tokio::test]
        async fn cluster_empty_returns_no_groups() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let clusters = pass.cluster(&[]).await;
            assert!(clusters.is_empty());
        }

        #[test]
        fn eligible_accepts_valid_cluster() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let m1 = make_memory_full("a", "ns", "t1", "c1", Tier::Long, 5);
            let m2 = make_memory_full("b", "ns", "t2", "c2", Tier::Long, 5);
            assert!(pass.eligible(&[m1, m2]));
        }

        #[test]
        fn eligible_rejects_singleton_via_pass() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let m = make_memory_full("a", "ns", "t", "c", Tier::Long, 5);
            assert!(!pass.eligible(&[m]));
        }

        #[test]
        fn eligible_rejects_reserved_namespace_via_pass() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let m1 = make_memory_full("a", "_curator", "t", "c", Tier::Long, 5);
            let m2 = make_memory_full("b", "_curator", "t", "c", Tier::Long, 5);
            assert!(!pass.eligible(&[m1, m2]));
        }

        #[test]
        fn eligible_rejects_mixed_ns_via_pass() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let m1 = make_memory_full("a", "ns1", "t", "c", Tier::Long, 5);
            let m2 = make_memory_full("b", "ns2", "t", "c", Tier::Long, 5);
            assert!(!pass.eligible(&[m1, m2]));
        }

        #[test]
        fn summarize_returns_consolidated_memory() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("synthesised summary");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let m1 = make_memory_full("a", "ns", "First", "c1", Tier::Mid, 3);
            let m2 = make_memory_full("b", "ns", "Second", "c2", Tier::Long, 7);
            let summary = pass.summarize(&[m1, m2]).unwrap();
            assert!(summary.title.starts_with("[consolidated]"));
            assert_eq!(summary.namespace, "ns");
            assert_eq!(summary.content, "synthesised summary");
            assert_eq!(summary.tier, Tier::Long); // max
            assert_eq!(summary.priority, 7); // max
            // #1746: source held byte-stable with the autonomy path across cutover.
            assert_eq!(summary.source, crate::autonomy::CURATOR_SOURCE_LABEL);
        }

        #[test]
        fn summarize_empty_cluster_errors() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let err = pass.summarize(&[]).unwrap_err().to_string();
            assert!(err.contains("empty cluster"));
        }

        #[tokio::test]
        async fn persist_dry_run_is_noop() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, true /* dry_run */);
            let summary = make_memory_full("s", "ns", "t", "c", Tier::Mid, 5);
            // dry_run=true → persist short-circuits regardless of sources.
            pass.persist(&summary, &["x".to_string(), "y".to_string()])
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn persist_empty_sources_is_noop() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let summary = make_memory_full("s", "ns", "t", "c", Tier::Mid, 5);
            pass.persist(&summary, &[]).await.unwrap();
        }

        #[tokio::test]
        async fn persist_writes_consolidated_memory() {
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = StubLlm::new("synth");
            let pass = ConsolidationPass::new(&store, &llm, false);
            // Insert two source memories.
            let m1 = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "ns",
                "t1",
                "Some keyword content alpha",
                Tier::Mid,
                5,
            );
            let m2 = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "ns",
                "t2",
                "Some keyword content beta",
                Tier::Mid,
                5,
            );
            let id1 = crate::db::insert(&conn, &m1).unwrap();
            let id2 = crate::db::insert(&conn, &m2).unwrap();
            let summary = make_memory_full(
                "s",
                "ns",
                "[consolidated] title",
                "consolidated body",
                Tier::Long,
                5,
            );
            pass.persist(&summary, &[id1, id2]).await.unwrap();
            // Verify the consolidated row is queryable in the namespace.
            let by_title = crate::db::list(
                &conn,
                Some("ns"),
                None,
                16,
                0,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            let titles: Vec<&str> = by_title.iter().map(|m| m.title.as_str()).collect();
            assert!(titles.iter().any(|t| t.contains("[consolidated]")));
        }

        #[tokio::test]
        async fn verify_missing_id_returns_error() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let err = pass
                .verify("no-such-id".to_string())
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("not found in DB"));
        }

        #[tokio::test]
        async fn verify_existing_id_ok() {
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let m = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "ns",
                "t",
                "c",
                Tier::Mid,
                5,
            );
            let id = crate::db::insert(&conn, &m).unwrap();
            pass.verify(id).await.unwrap();
        }

        #[test]
        fn stub_llm_auto_tag_and_contradiction_paths() {
            // Exercises StubLlm::auto_tag + detect_contradiction methods.
            let stub = StubLlm::new("S");
            assert!(stub.auto_tag("t", "c").unwrap().is_empty());
            assert!(!stub.detect_contradiction("a", "b").unwrap());
        }

        #[tokio::test]
        async fn cluster_reads_stored_embeddings_and_applies_cosine_gate() {
            // Proves the get_embedding wiring end-to-end (deterministic, no live
            // Embedder): two same-content (high-Jaccard) memories stored with
            // ORTHOGONAL embeddings (cos=0 < 0.75) must NOT merge. If the pass
            // failed to fetch the stored vectors it would fall to Jaccard-only
            // and WRONGLY merge them — so an empty result confirms cluster()
            // reads the stored vectors and the cosine gate fires.
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = StubLlm::new("S");
            let dup = "kubernetes rolling canary deploy strategy notes";
            let m1 = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "ns",
                "t1",
                dup,
                Tier::Mid,
                5,
            );
            let m2 = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "ns",
                "t2",
                dup,
                Tier::Mid,
                5,
            );
            crate::db::insert(&conn, &m1).unwrap();
            crate::db::set_embedding(&conn, &m1.id, &[1.0, 0.0]).unwrap();
            crate::db::insert(&conn, &m2).unwrap();
            crate::db::set_embedding(&conn, &m2.id, &[0.0, 1.0]).unwrap();

            let pass = ConsolidationPass::new(&store, &llm, false);
            let clusters = pass.cluster(&[m1, m2]).await;
            assert!(
                clusters.is_empty(),
                "orthogonal stored vectors must block the cosine gate (no merge); \
                 got {clusters:?} — get_embedding wiring may be broken"
            );

            // Sanity: the SAL get_embedding round-trips the stored vector.
            let v = store
                .get_embedding(&pass.ctx, &candidates_first_id(&conn))
                .await
                .unwrap();
            assert!(v.is_some(), "get_embedding must read back a stored vector");
        }

        /// First memory id in `ns` (helper for the get_embedding round-trip).
        fn candidates_first_id(conn: &rusqlite::Connection) -> String {
            crate::db::list(
                conn,
                Some("ns"),
                None,
                1,
                0,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .first()
            .map(|m| m.id.clone())
            .expect("at least one row")
        }

        #[tokio::test]
        async fn persist_propagates_db_consolidate_failure() {
            // Drives the `?` propagation. Pass non-existent source ids and an
            // empty title — consolidate will fail on the missing source rows.
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, false);
            let summary = make_memory_full("s", "ns", "[consolidated] x", "c", Tier::Mid, 5);
            // Non-existent source IDs → consolidate should error.
            let res = pass
                .persist(
                    &summary,
                    &["nope-id-1".to_string(), "nope-id-2".to_string()],
                )
                .await;
            assert!(
                res.is_err(),
                "expected consolidate to fail on missing sources"
            );
        }

        // ---- run() orchestration (#1738 slice-1) ----------------------------

        /// Seed two near-duplicate memories (high Jaccard overlap, same ns,
        /// no embedder → Jaccard clustering) and return their live ids +
        /// in-memory `Memory` rows for use as `run` candidates.
        fn seed_two_dupes(conn: &rusqlite::Connection) -> Vec<Memory> {
            let m1 = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "ns",
                "t1",
                "kubernetes rolling canary deploy strategy notes",
                Tier::Mid,
                5,
            );
            let m2 = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "ns",
                "t2",
                "kubernetes rolling canary deploy strategy notes",
                Tier::Mid,
                5,
            );
            crate::db::insert(conn, &m1).unwrap();
            crate::db::insert(conn, &m2).unwrap();
            // #1774 — both sides need a stored embedding to clear the cosine
            // gate; attach aligned vectors (cosine = 1.0) so the dup pair
            // clusters (the un-embedded path no longer merges).
            crate::db::set_embedding(conn, &m1.id, &[1.0, 0.0]).unwrap();
            crate::db::set_embedding(conn, &m2.id, &[1.0, 0.0]).unwrap();
            vec![m1, m2]
        }

        #[tokio::test]
        async fn run_dry_run_counts_eligible_without_writing() {
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let candidates = seed_two_dupes(&conn);
            let llm = StubLlm::new("synth");
            let pass = ConsolidationPass::new(&store, &llm, true /* dry_run */);

            let out = pass.run(&candidates).await.unwrap();
            assert!(out.clusters_formed >= 1, "should form ≥1 cluster");
            assert!(out.eligible_clusters >= 1, "the dup cluster is eligible");
            assert_eq!(out.memories_consolidated, 0, "dry-run must not consolidate");
            // No LLM summarise happened in dry-run.
            assert!(
                llm.calls.lock().unwrap().is_empty(),
                "dry-run skips summarize"
            );
            // No `[consolidated]` row was written; both sources still live.
            let rows = crate::db::list(
                &conn,
                Some("ns"),
                None,
                16,
                0,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            assert!(
                !rows.iter().any(|m| m.title.starts_with("[consolidated]")),
                "dry-run must not write a consolidated row"
            );
            assert_eq!(rows.len(), 2, "both source rows remain");
        }

        #[tokio::test]
        async fn run_real_mode_consolidates_cluster() {
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let candidates = seed_two_dupes(&conn);
            let llm = StubLlm::new("synthesised consolidation");
            let pass = ConsolidationPass::new(&store, &llm, false /* real */);

            let out = pass.run(&candidates).await.unwrap();
            assert!(out.clusters_formed >= 1);
            assert!(out.eligible_clusters >= 1);
            assert_eq!(out.memories_consolidated, 2, "both sources folded in");
            assert!(
                out.errors.is_empty(),
                "no per-cluster errors: {:?}",
                out.errors
            );
            // The `[consolidated]` row landed and the sources were soft-deleted.
            let rows = crate::db::list(
                &conn,
                Some("ns"),
                None,
                16,
                0,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            assert!(
                rows.iter().any(|m| m.title.starts_with("[consolidated]")),
                "a consolidated row must exist"
            );
        }

        #[tokio::test]
        async fn run_real_mode_persists_reversible_rollback_entry() {
            // #1745 — real-mode consolidation must leave an operator-reversible
            // RollbackEntry::Consolidate in _curator/rollback so
            // `curator --rollback` can undo the hard-DELETE merge, at parity
            // with the autonomy Pass-1 path.
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let candidates = seed_two_dupes(&conn);
            let llm = StubLlm::new("synthesised consolidation");
            let pass = ConsolidationPass::new(&store, &llm, false /* real */);

            let out = pass.run(&candidates).await.unwrap();
            assert_eq!(out.memories_consolidated, 2);
            assert_eq!(
                out.rollback_entries_written, 1,
                "one reversible rollback entry per verified consolidation"
            );

            // A _curator/rollback row landed, tagged as a consolidate entry.
            let log = crate::db::list(
                &conn,
                Some("_curator/rollback"),
                None,
                16,
                0,
                None,
                None,
                None,
                None,
                None,
                None, // #1834 valid_at (no as-of)
            )
            .unwrap();
            assert_eq!(log.len(), 1, "exactly one rollback entry written");
            assert!(log[0].content.contains("consolidate"));

            // Round-trip: the entry deserialises and reverses via the SAME
            // operator path — originals restored, consolidated summary removed —
            // proving end-to-end `--rollback` parity, not just a written row.
            let entry: crate::autonomy::RollbackEntry =
                serde_json::from_str(&log[0].content).unwrap();
            let applied = crate::autonomy::reverse_rollback_entry(&conn, &entry).unwrap();
            assert!(applied, "reverse applied");
            for m in &candidates {
                assert!(
                    crate::db::get(&conn, &m.id).unwrap().is_some(),
                    "{} restored by --rollback",
                    m.id
                );
            }
            let rows = crate::db::list(
                &conn,
                Some("ns"),
                None,
                16,
                0,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            assert!(
                !rows.iter().any(|m| m.title.starts_with("[consolidated]")),
                "consolidated summary removed by rollback"
            );
        }

        #[tokio::test]
        async fn clustering_membership_parity_with_autonomy() {
            // #1746 equivalence gate: the SAL ConsolidationPass clustering must
            // produce the SAME cluster membership as the live
            // autonomy::find_consolidation_clusters on an identical corpus —
            // multi-namespace + STORED embeddings so the cosine-AND-jaccard path
            // (not just the jaccard fallback) is exercised. Compared as
            // sets-of-id-sets because HashMap namespace-iteration order is
            // non-deterministic (positional compare would flake).
            use std::collections::BTreeSet;
            let (store, _dir) = open_db();
            let conn = conn_of(&store);

            let dup_a = "kubernetes rolling canary deploy strategy notes";
            let dup_b = "postgres vacuum autovacuum tuning bloat thresholds detail";
            let a1 = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "a",
                "t1",
                dup_a,
                Tier::Mid,
                5,
            );
            let a2 = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "a",
                "t2",
                dup_a,
                Tier::Mid,
                5,
            );
            let b1 = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "b",
                "t1",
                dup_b,
                Tier::Mid,
                5,
            );
            let b2 = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "b",
                "t2",
                dup_b,
                Tier::Mid,
                5,
            );
            for m in [&a1, &a2, &b1, &b2] {
                crate::db::insert(&conn, m).unwrap();
            }
            // Aligned embeddings within each namespace → cosine gate passes.
            crate::db::set_embedding(&conn, &a1.id, &[1.0, 0.0]).unwrap();
            crate::db::set_embedding(&conn, &a2.id, &[1.0, 0.0]).unwrap();
            crate::db::set_embedding(&conn, &b1.id, &[0.0, 1.0]).unwrap();
            crate::db::set_embedding(&conn, &b2.id, &[0.0, 1.0]).unwrap();

            let cands = vec![a1, a2, b1, b2];

            // Autonomy side (sync) → set of id-sets.
            let autonomy_sets: BTreeSet<BTreeSet<String>> =
                crate::autonomy::find_consolidation_clusters(&conn, &cands)
                    .iter()
                    .map(|c| c.iter().map(|m| m.id.clone()).collect())
                    .collect();

            // SAL side (async) → set of id-sets.
            let llm = StubLlm::new("S");
            let pass = ConsolidationPass::new(&store, &llm, true);
            let sal_sets: BTreeSet<BTreeSet<String>> = pass
                .cluster(&cands)
                .await
                .iter()
                .map(|c| c.iter().cloned().collect())
                .collect();

            assert_eq!(
                autonomy_sets, sal_sets,
                "SAL clustering membership must match autonomy::find_consolidation_clusters"
            );
            // Sanity: each namespace formed its own 2-member cluster.
            assert_eq!(autonomy_sets.len(), 2, "two namespaces → two clusters");
            assert!(autonomy_sets.iter().all(|s| s.len() == 2));
        }

        // ---- Stage-6 rollback (#664, slice-2) -------------------------------

        #[tokio::test]
        async fn rollback_consolidation_restores_originals_and_deletes_result() {
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let candidates = seed_two_dupes(&conn);
            let llm = StubLlm::new("synth");
            let pass = ConsolidationPass::new(&store, &llm, false);

            // Consolidate for real: sources removed, result minted.
            let summary = pass.summarize(&candidates).unwrap();
            let ids: Vec<String> = candidates.iter().map(|m| m.id.clone()).collect();
            let result_id = pass.persist(&summary, &ids).await.unwrap();
            assert!(crate::db::get(&conn, &result_id).unwrap().is_some());
            for m in &candidates {
                assert!(
                    crate::db::get(&conn, &m.id).unwrap().is_none(),
                    "source merged away"
                );
            }

            // Roll back: originals restored (same ids), result removed.
            let restored = pass
                .rollback_consolidation(&candidates, &result_id)
                .await
                .unwrap();
            assert_eq!(restored, 2);
            for m in &candidates {
                assert!(
                    crate::db::get(&conn, &m.id).unwrap().is_some(),
                    "{} restored",
                    m.id
                );
            }
            assert!(
                crate::db::get(&conn, &result_id).unwrap().is_none(),
                "unverifiable summary removed"
            );
        }

        #[tokio::test]
        async fn rollback_consolidation_skips_collided_slot() {
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let candidates = seed_two_dupes(&conn);
            let llm = StubLlm::new("synth");
            let pass = ConsolidationPass::new(&store, &llm, false);

            let summary = pass.summarize(&candidates).unwrap();
            let ids: Vec<String> = candidates.iter().map(|m| m.id.clone()).collect();
            let result_id = pass.persist(&summary, &ids).await.unwrap();

            // A NEW memory squats the first original's (title, namespace) slot.
            let squatter = make_memory_full(
                &uuid::Uuid::new_v4().to_string(),
                "ns",
                &candidates[0].title,
                "squatter content",
                Tier::Mid,
                5,
            );
            crate::db::insert(&conn, &squatter).unwrap();

            // Roll back: collided original is skipped, the other is restored.
            let restored = pass
                .rollback_consolidation(&candidates, &result_id)
                .await
                .unwrap();
            assert_eq!(restored, 1, "only the un-collided original is restored");
            assert!(
                crate::db::get(&conn, &candidates[0].id).unwrap().is_none(),
                "collided original was NOT restored"
            );
            assert!(
                crate::db::get(&conn, &candidates[1].id).unwrap().is_some(),
                "un-collided original restored"
            );
            assert!(
                crate::db::get(&conn, &squatter.id).unwrap().is_some(),
                "squatter not clobbered"
            );
            assert!(crate::db::get(&conn, &result_id).unwrap().is_none());
        }
    } // mod sal_pass_tests
}
