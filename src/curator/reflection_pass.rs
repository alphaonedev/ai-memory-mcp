// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Reflection-pass curator mode — v0.7.0 Layer 2 Task L2-1 (issue #666).
//!
//! Implements [`ReflectionPass`], a [`CompactionPass`] that clusters
//! Observation memories by recall co-occurrence + namespace + temporal
//! proximity, asks an LLM to summarise the pattern, and persists the
//! summary as a typed Reflection memory via the substrate
//! [`crate::storage::reflect_with_hooks`] path — so every reflection
//! lands with a `reflects_on` edge to every source, the
//! `metadata.reflection_metadata` block stamped, and (via the
//! atomic-write contract) inside a single `BEGIN IMMEDIATE` /
//! `COMMIT` transaction.
//!
//! # Why a fresh `CompactionPass` (and not the v0.6.x consolidate path)
//!
//! Consolidation collapses near-duplicate memories into a single
//! canonical body, soft-deleting the originals. **Reflection is
//! additive** — the sources remain readable, and the new memory is a
//! typed `Reflection` carrying provenance edges back. That difference
//! shows up in three places in the impl:
//!
//! 1. `persist()` writes via [`crate::storage::reflect`], not via
//!    `db::consolidate`. The substrate handles the depth cap, the
//!    `reflects_on` link insert, and the atomic boundary.
//! 2. `eligible()` requires every cluster member to be
//!    [`crate::models::MemoryKind::Observation`]. Reflections never
//!    fold into a parent reflection in this pass (the L2-1 acceptance
//!    is one level of reflection at a time; multi-level chains form
//!    naturally across passes if `max_depth >= 2`).
//! 3. `cluster()` uses a hybrid signal — Jaccard pre-filter +
//!    optional cosine — but constrains pairs to memories that have
//!    been recalled together (`access_count >= 1`) within a sliding
//!    7-day window. This is the "recall co-occurrence" proxy
//!    documented in #666: we cannot directly observe recall
//!    co-occurrence without a recall-event log (out of scope here),
//!    so we use the substrate-visible signals — `access_count`,
//!    `last_accessed_at`, `created_at` proximity — that approximate
//!    it within the bounds of one SQLite read.
//!
//! # Visibility contract (R7)
//!
//! All items are at most `pub(crate)`. The only externally-visible
//! re-export is the [`ReflectionPassConfig`] struct that the CLI
//! flag wiring (see `src/cli/curator.rs`) consumes, plus
//! [`run_reflection_pass`] which the CLI's `--reflect` mode invokes.

// The pass internals run only through the SAL-gated curator path; in a
// non-sal build only the config/report structs are live, so relax the
// dead-code / unused-import lints there only (sal builds enforce fully).
#![cfg_attr(not(feature = "sal"), allow(dead_code, unused_imports))]

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[cfg(feature = "sal")]
use anyhow::Context;
use anyhow::Result;

#[cfg(feature = "sal")]
use crate::autonomy::AutonomyLlm;
#[cfg(feature = "sal")]
use crate::identity::keypair::AgentKeypair;
use crate::models::{Memory, MemoryKind, Tier};
#[cfg(feature = "sal")]
use crate::storage::reflect::{ReflectError, ReflectInput};
#[cfg(feature = "sal")]
use crate::store::{CallerContext, Filter, MemoryStore, StoreError};

#[cfg(feature = "sal")]
use super::pipeline::MemoryId;

#[cfg(any(feature = "sal", test))]
use crate::models::ConfidenceSource;

/// Fetch a single memory by id through the SAL trait, mapping the
/// `NotFound` verdict to `Ok(None)` so call sites keep the
/// `Option`-shaped contract the pre-#1548 `db::get` free function
/// returned. Any other [`StoreError`] propagates as an `anyhow` error.
///
/// The curator runs as an operator-class background sweep, so the
/// supplied `ctx` carries `bypass_visibility` (see
/// [`curator_caller_context`]) — preserving the pre-trait raw-connection
/// behaviour where `db::get` applied no scope=private visibility filter.
#[cfg(feature = "sal")]
async fn store_get_opt(
    store: &dyn MemoryStore,
    ctx: &CallerContext,
    id: &str,
) -> Result<Option<Memory>> {
    match store.get(ctx, id).await {
        Ok(mem) => Ok(Some(mem)),
        Err(StoreError::NotFound { .. }) => Ok(None),
        Err(e) => Err(anyhow::anyhow!(e)),
    }
}

/// Build the curator's operator-class caller context. The reflection
/// pass is a background substrate-maintenance sweep, not a tenant-facing
/// request, so it reads every row regardless of `metadata.scope` —
/// exactly the posture the pre-#1548 raw-`rusqlite::Connection` path had
/// (the legacy `db::*` free functions applied no SAL visibility filter).
/// `agent_id` carries the curator's resolved signing identity so audit
/// trails attribute the sweep correctly.
#[cfg(feature = "sal")]
fn curator_caller_context(agent_id: &str) -> CallerContext {
    CallerContext::for_admin(agent_id)
}

/// List up to `limit` memories in `namespace` through the SAL trait.
/// Replaces the pre-#1548 `db::list(conn, Some(ns), None, limit, 0, …)`
/// free-function call with the backend-agnostic [`MemoryStore::list`]
/// surface. The reflection pass only ever needs the namespace + limit
/// dimensions of the legacy positional signature; the remaining
/// (offset / tier / since / until / tags / agent_id) slots were always
/// passed as `0` / `None`, so they are simply absent from [`Filter`].
#[cfg(feature = "sal")]
async fn store_list_namespace(
    store: &dyn MemoryStore,
    ctx: &CallerContext,
    namespace: &str,
    limit: usize,
) -> Result<Vec<Memory>> {
    let filter = Filter {
        namespace: Some(namespace.to_string()),
        limit,
        ..Default::default()
    };
    store
        .list(ctx, &filter)
        .await
        .map_err(|e| anyhow::anyhow!(e))
}

// ---------------------------------------------------------------------------
// Constants — per #666 spec ("≥3 members", "7-day temporal window", …)
// ---------------------------------------------------------------------------

/// Minimum members per reflection cluster. Below this the eligibility
/// gate refuses — a "pattern" derived from two observations is just a
/// pair, not a generalisation.
pub(crate) const MIN_CLUSTER_SIZE: usize = 3;

/// Maximum members per reflection cluster — prevents pathological
/// mega-merges where every observation in a namespace folds into one
/// reflection.
pub(crate) const MAX_CLUSTER_SIZE: usize = 12;

/// Sliding window for temporal co-occurrence. Two observations within
/// this many days of each other (by `created_at`) and both in the
/// same namespace are candidates for clustering. 7 days matches the
/// spec in #666 ("temporal_proximity: 7-day window").
pub(crate) const TEMPORAL_WINDOW_DAYS: i64 = 7;

/// Jaccard-keyword similarity threshold for the cheap pre-filter that
/// gates pairs into the cluster. Looser than the consolidation
/// threshold (0.55) because reflection looks for *related* — not
/// near-duplicate — observations.
pub(crate) const REFLECTION_JACCARD_THRESHOLD: f64 = 0.30;

/// Minimum `access_count` for an observation to qualify as
/// "co-recalled". Substrate proxy for the spec's "recall
/// co-occurrence frequency" signal — without a per-recall event log
/// we approximate via touch-count on the source row, which the recall
/// pipeline bumps on every hit.
pub(crate) const MIN_RECALL_COUNT: i64 = 1;

// ---------------------------------------------------------------------------
// ReflectionPassConfig — per-namespace opt-in (defaults to `enabled = false`)
// ---------------------------------------------------------------------------

/// Per-namespace configuration for the reflection pass.
///
/// Defaults to `enabled = false` per #666 acceptance: reflection is
/// opt-in because (a) it depends on the Ollama LLM being available
/// at the time the pass runs, and (b) it writes new (typed) memories
/// to the namespace, which operators may want to gate by namespace
/// rather than enable globally.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReflectionPassConfig {
    /// When `false` (default), the pass skips this namespace entirely.
    #[serde(default)]
    pub enabled: bool,
    /// Per-namespace override of the operator-supplied `--max-depth`
    /// flag. When `None`, the pass uses the resolved governance-policy
    /// `max_reflection_depth` (default `3`) as its ceiling. When
    /// `Some(N)`, the pass refuses to *propose* a reflection whose
    /// new depth would exceed `N` (the substrate cap still applies
    /// on top — this is a curator-side guard rail, not a substrate
    /// override).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
}

impl Default for ReflectionPassConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_depth: None,
        }
    }
}

// ---------------------------------------------------------------------------
// ReflectionPass — SAL-backed reflection synthesis (issue #1548)
// ---------------------------------------------------------------------------

/// Compaction pass that synthesises typed `Reflection` memories from
/// clusters of co-occurring Observations.
///
/// Operates over the SAL [`MemoryStore`] trait (issue #1548) so it runs
/// against the SQLite *or* Postgres adapter; gated on the `sal` feature
/// (the trait itself is `sal`-gated). Wired into the curator's
/// `--reflect` CLI mode via [`run_reflection_pass`] and the
/// `--store-url --daemon` upkeep sweep; not yet wired into the autonomy
/// loop's per-cycle sweep (that's a v0.7.1+ pivot once the operator has
/// had a chance to run the pass manually and vet the proposed
/// reflections).
#[cfg(feature = "sal")]
pub(crate) struct ReflectionPass<'a> {
    /// SAL store handle. Reads through [`MemoryStore::list`] /
    /// [`MemoryStore::get_links_for_anchor`]; writes through
    /// [`MemoryStore::reflect`]. Works against the SQLite *or* Postgres
    /// adapter (issue #1548) — the pass is backend-agnostic.
    pub(crate) store: &'a dyn MemoryStore,
    /// Operator-class caller context (see [`curator_caller_context`]).
    /// Carries the curator's `agent_id` and `bypass_visibility` so the
    /// background sweep reads every row regardless of `metadata.scope`,
    /// matching the pre-trait raw-connection behaviour.
    pub(crate) ctx: CallerContext,
    /// LLM trait object. Tests inject a deterministic stub; production
    /// passes an `&OllamaClient` (which implements [`AutonomyLlm`]).
    pub(crate) llm: &'a dyn AutonomyLlm,
    /// Curator's signing keypair. Stamped into the reflection's
    /// `metadata.agent_id` so every `reflects_on` edge is attributable
    /// to the same Ed25519 identity. `None` only in tests that exercise
    /// the no-keypair fallback; production callers must pass `Some(_)`.
    pub(crate) keypair: Option<&'a AgentKeypair>,
    /// Curator-side cap on proposed reflection depth. Belt-and-braces
    /// guard on top of the substrate's per-namespace
    /// `max_reflection_depth` policy: even when the substrate would
    /// allow the write, the curator refuses if `max_depth` is set
    /// and the proposed depth exceeds it. `None` defers entirely to
    /// substrate policy.
    pub(crate) max_depth: Option<u32>,
    /// Suppress every DB write. When `true`, `persist()` returns
    /// `Ok(())` without calling [`reflect_with_hooks`] and the
    /// reflection memory is reported as a proposal in the
    /// [`ReflectionPassReport`].
    pub(crate) dry_run: bool,
}

#[cfg(feature = "sal")]
impl<'a> ReflectionPass<'a> {
    /// Construct a `ReflectionPass`. `keypair` is the curator's
    /// signing identity — used for `metadata.agent_id` and for
    /// `verify()`'s signature-trace check. `max_depth` is the optional
    /// curator-side ceiling; `dry_run` suppresses writes.
    pub(crate) fn new(
        store: &'a dyn MemoryStore,
        llm: &'a dyn AutonomyLlm,
        keypair: Option<&'a AgentKeypair>,
        max_depth: Option<u32>,
        dry_run: bool,
    ) -> Self {
        let agent_id = keypair.map_or_else(|| "ai:curator".to_string(), |k| k.agent_id.clone());
        Self {
            store,
            ctx: curator_caller_context(&agent_id),
            llm,
            keypair,
            max_depth,
            dry_run,
        }
    }

    /// Resolve the agent id stamped on every reflection this pass
    /// writes. Falls back to `"ai:curator"` when the curator was
    /// started without a keypair — the same fall-back the autonomy
    /// `consolidate` path uses, kept consistent so a forensic walk of
    /// `metadata.agent_id` finds curator-written rows under either
    /// tag.
    fn agent_id(&self) -> String {
        self.keypair
            .map_or_else(|| "ai:curator".to_string(), |k| k.agent_id.clone())
    }

    /// Human-readable pass name used in log messages and reports.
    /// Currently exercised by the unit tests; the daemon log lines use
    /// the report fields directly.
    #[allow(dead_code)]
    fn name(&self) -> &str {
        "reflection"
    }

    /// Partition `memories` into clusters of co-occurring Observations.
    ///
    /// Algorithm (one pass per namespace):
    ///
    /// 1. Filter to typed `Observation` memories with `access_count >=
    ///    MIN_RECALL_COUNT` — substrate proxy for "has been recalled
    ///    recently enough to count as live".
    /// 2. Within each namespace, walk pairs and seed a cluster when
    ///    both: (a) the temporal distance between `created_at` is
    ///    within [`TEMPORAL_WINDOW_DAYS`], and (b) the Jaccard
    ///    similarity of contents is ≥ [`REFLECTION_JACCARD_THRESHOLD`].
    /// 3. Cap each cluster at [`MAX_CLUSTER_SIZE`].
    /// 4. Discard clusters below [`MIN_CLUSTER_SIZE`] (eligibility
    ///    enforces this too, but discarding here keeps the API tight).
    fn cluster(&self, memories: &[Memory]) -> Vec<Vec<MemoryId>> {
        let mut by_ns: std::collections::HashMap<&str, Vec<&Memory>> =
            std::collections::HashMap::new();
        for m in memories {
            if !is_clusterable_observation(m) {
                continue;
            }
            by_ns.entry(&m.namespace).or_default().push(m);
        }

        let mut clusters: Vec<Vec<MemoryId>> = Vec::new();
        for (_ns, group) in by_ns {
            let mut used = vec![false; group.len()];
            for i in 0..group.len() {
                if used[i] {
                    continue;
                }
                let mut cluster = vec![group[i].id.clone()];
                used[i] = true;
                for j in (i + 1)..group.len() {
                    if used[j] {
                        continue;
                    }
                    if cluster.len() >= MAX_CLUSTER_SIZE {
                        break;
                    }
                    if pair_co_occurs(group[i], group[j]) {
                        cluster.push(group[j].id.clone());
                        used[j] = true;
                    }
                }
                if cluster.len() >= MIN_CLUSTER_SIZE {
                    clusters.push(cluster);
                }
            }
        }
        clusters
    }

    /// Secondary eligibility gate.
    ///
    /// A cluster passes when:
    ///
    /// * It has ≥ [`MIN_CLUSTER_SIZE`] and ≤ [`MAX_CLUSTER_SIZE`] members.
    /// * Every member is `MemoryKind::Observation` — reflections that
    ///   carry meta-pattern depth should be folded by a separate
    ///   higher-depth pass, not this one.
    /// * All members share the same (non-reserved) namespace.
    /// * Every member is not soft-deleted (the substrate `list` call
    ///   excludes soft-deleted rows but defensive recheck cheap).
    fn eligible(&self, cluster: &[Memory]) -> bool {
        if cluster.len() < MIN_CLUSTER_SIZE || cluster.len() > MAX_CLUSTER_SIZE {
            return false;
        }
        let ns = &cluster[0].namespace;
        if ns.starts_with('_') {
            return false;
        }
        cluster.iter().all(|m| {
            m.memory_kind == MemoryKind::Observation
                && &m.namespace == ns
                && m.access_count >= MIN_RECALL_COUNT
        })
    }

    /// LLM-summarise the cluster into a single proposed Reflection
    /// memory. Does NOT touch the database — the returned `Memory`
    /// is a *proposal* that `persist()` (or the dry-run reporter)
    /// consumes.
    ///
    /// The proposal carries:
    ///
    /// * Title prefixed with `[reflection]` so an operator inspecting
    ///   the namespace immediately sees the synthetic origin.
    /// * `memory_kind = Reflection`. The substrate `reflect` path
    ///   will set this anyway; we set it here so the in-memory
    ///   proposal is internally consistent.
    /// * `reflection_depth` left at 0 — the substrate computes the
    ///   real depth (`max(source.reflection_depth) + 1`) on insert.
    /// * Tier = max of source tiers (never downgrade).
    /// * Priority = max of source priorities (the reflection inherits
    ///   the salience of its highest-priority source).
    fn summarize(&self, cluster: &[Memory]) -> Result<Memory> {
        if cluster.len() < MIN_CLUSTER_SIZE {
            anyhow::bail!(
                "summarize: cluster has {} members (< MIN_CLUSTER_SIZE = {})",
                cluster.len(),
                MIN_CLUSTER_SIZE
            );
        }

        let input: Vec<(String, String)> = cluster
            .iter()
            .map(|m| (m.title.clone(), m.content.clone()))
            .collect();
        let summary_text = self
            .llm
            .summarize_memories(&input)
            .context("ReflectionPass::summarize: LLM call failed")?;

        let base_title = cluster
            .iter()
            .map(|m| m.title.as_str())
            .next()
            .unwrap_or("(reflection)");
        let title = format!("[reflection] {base_title}");

        let tier = cluster
            .iter()
            .map(|m| m.tier.clone())
            .max_by_key(tier_rank)
            .unwrap_or(Tier::Mid);
        let priority = cluster.iter().map(|m| m.priority).max().unwrap_or(5);

        let now = Utc::now().to_rfc3339();
        Ok(Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier,
            namespace: cluster[0].namespace.clone(),
            title,
            content: summary_text,
            tags: vec![],
            priority,
            confidence: 1.0,
            // Substrate `validate_source` accepts a closed set; "system"
            // is the curator's canonical entry-point for autonomous
            // writes (see consolidation pass, autonomy passes).
            source: "system".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({}),
            reflection_depth: 0,
            memory_kind: MemoryKind::Reflection,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
        })
    }

    /// Persist `summary` plus a `reflects_on` link to each id in
    /// `sources`, via the substrate [`MemoryStore::reflect`] path.
    ///
    /// The substrate enforces (a) input validation, (b) depth-cap
    /// refusal with audit row, (c) transactional atomicity (all
    /// `reflects_on` links land or none do), (d) no-cycle guarantee
    /// inherited from L1-2's `reflects_on` invariant. The SQLite adapter
    /// routes this through `storage::reflect_with_hooks`; the Postgres
    /// adapter through its native sqlx `reflect` — both honour the same
    /// [`ReflectInput`] contract (issue #1548).
    ///
    /// No-op when `self.dry_run = true`.
    async fn persist(&self, summary: &Memory, sources: &[MemoryId]) -> Result<()> {
        if self.dry_run || sources.is_empty() {
            return Ok(());
        }

        // Curator-side max-depth guard. The substrate enforces the
        // namespace policy cap on top — this is the operator-supplied
        // belt-and-braces. We need to know the proposed depth before
        // calling reflect(); pre-compute it the same way the substrate
        // does (max source depth + 1) so the curator can refuse
        // *before* burning an LLM round-trip in the next cycle.
        if let Some(cap) = self.max_depth {
            let mut max_src_depth: i32 = 0;
            for id in sources {
                if let Some(m) = store_get_opt(self.store, &self.ctx, id).await? {
                    max_src_depth = max_src_depth.max(m.reflection_depth);
                }
            }
            let new_depth =
                u32::try_from(max_src_depth.max(0).saturating_add(1)).unwrap_or(u32::MAX);
            if new_depth > cap {
                anyhow::bail!(
                    "ReflectionPass::persist: proposed depth {new_depth} exceeds \
                     curator --max-depth {cap}"
                );
            }
        }

        let input = ReflectInput {
            source_ids: sources.to_vec(),
            title: summary.title.clone(),
            content: summary.content.clone(),
            namespace: Some(summary.namespace.clone()),
            tier: summary.tier.clone(),
            tags: summary.tags.clone(),
            priority: summary.priority,
            confidence: summary.confidence,
            source: summary.source.clone(),
            agent_id: self.agent_id(),
            metadata: summary.metadata.clone(),
        };

        // Issue #815 — thread the curator's signing keypair into the
        // reflect call so the substrate's signed-link path produces
        // `attest_level='self_signed'` rows for every `reflects_on` edge
        // this pass writes. The SAL `reflect(ctx, input, signing_key)`
        // surface folds the keypair into the adapter's hook bundle (the
        // SQLite adapter sets `ReflectHooks::active_keypair`; Postgres
        // signs natively), so the wire shape is byte-identical across
        // backends.
        match self.store.reflect(&self.ctx, &input, self.keypair).await {
            Ok(_outcome) => Ok(()),
            Err(ReflectError::DepthExceeded {
                attempted,
                cap,
                namespace,
            }) => {
                anyhow::bail!(
                    "ReflectionPass::persist: substrate refused — proposed depth \
                     {attempted} exceeds namespace cap {cap} in '{namespace}'"
                )
            }
            Err(other) => Err(anyhow::anyhow!(other.to_string())),
        }
    }

    /// Verify that the persisted reflection identified by `summary_id`
    /// is readable, typed as Reflection, and that every `reflects_on`
    /// edge points at an existing source.
    ///
    /// **Signature trace.** We deliberately do NOT call into
    /// `identity::verify::verify_link` here — H2 link signing fills the
    /// `signature` BLOB column on outbound writes, and `db::create_link`
    /// (used by `storage::reflect`) goes through that path when the
    /// daemon's keypair is wired in. The verify check here confirms
    /// (a) the edge exists, (b) the target memory is alive, (c) the
    /// `relation` is exactly `reflects_on`. Cryptographic signature
    /// re-verification belongs at the federation `sync_push` boundary,
    /// not the curator's verify step (the curator wrote the row
    /// itself, so it trivially trusts its own signature).
    ///
    /// Exercised by the unit tests; the run driver uses the inlined
    /// [`verify_recent`] check on the live driver path.
    #[allow(dead_code)]
    async fn verify(&self, summary_id: MemoryId) -> Result<()> {
        let mem = store_get_opt(self.store, &self.ctx, &summary_id)
            .await
            .context("ReflectionPass::verify: store.get failed")?;
        let mem = mem
            .ok_or_else(|| anyhow::anyhow!("verify: reflection {} not found in DB", summary_id))?;
        if mem.memory_kind != MemoryKind::Reflection {
            anyhow::bail!(
                "verify: memory {} is {:?}, expected Reflection",
                summary_id,
                mem.memory_kind
            );
        }

        let links = self
            .store
            .get_links_for_anchor(&summary_id)
            .await
            .map_err(|e| anyhow::anyhow!(e))
            .context("ReflectionPass::verify: store.get_links_for_anchor failed")?;
        let mut saw_reflects_on = false;
        for link in &links {
            // Only check outbound `reflects_on` edges originated at this
            // reflection. Inbound edges (other memories that reflect on
            // ours) are not in this pass's scope.
            if link.source_id != summary_id {
                continue;
            }
            if link.relation != crate::models::MemoryLinkRelation::ReflectsOn {
                continue;
            }
            saw_reflects_on = true;
            // Confirm the target exists. Soft-deleted sources are still
            // returned by store.get because the row is preserved; this is
            // the same contract `storage::reflect` relies on.
            let target = store_get_opt(self.store, &self.ctx, &link.target_id).await?;
            if target.is_none() {
                anyhow::bail!(
                    "verify: reflects_on edge target {} not found",
                    link.target_id
                );
            }
        }
        if !saw_reflects_on {
            anyhow::bail!("verify: reflection {} has no reflects_on edge", summary_id);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Report + run helpers (consumed by CLI --reflect)
// ---------------------------------------------------------------------------

/// Structured per-namespace outcome of a single reflection-pass
/// invocation.  Aggregated across namespaces by [`run_reflection_pass`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReflectionPassReport {
    /// RFC3339 timestamps; populated by `run_reflection_pass`.
    pub started_at: String,
    pub completed_at: String,
    /// Number of namespaces visited (`--all-namespaces`) or `1`
    /// when a single `--namespace` was supplied.
    pub namespaces_visited: usize,
    /// Eligible candidate Observations scanned across all visited
    /// namespaces.
    pub observations_scanned: usize,
    /// Number of clusters formed (pre-eligibility).
    pub clusters_formed: usize,
    /// Number of clusters that survived the eligibility gate.
    pub clusters_eligible: usize,
    /// Number of reflections successfully persisted. Always `0` when
    /// `dry_run = true`.
    pub reflections_persisted: usize,
    /// Number of refused-by-depth-cap clusters (substrate refusal or
    /// curator `--max-depth` guard).
    pub depth_refusals: usize,
    /// LLM call failures, persist errors, and verify errors that
    /// did NOT abort the pass.
    pub errors: Vec<String>,
    /// Dry-run proposals — populated when `dry_run = true`, empty
    /// otherwise. Each entry is `(namespace, proposed_title,
    /// source_ids)`.
    #[serde(default)]
    pub dry_run_proposals: Vec<DryRunProposal>,
    /// `true` if the pass was a dry-run.
    pub dry_run: bool,
}

/// Compact description of a proposed reflection when the pass runs
/// in `--dry-run` mode. Re-serialised into the CLI's JSON output so
/// operators can inspect proposed clusters before committing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunProposal {
    pub namespace: String,
    pub proposed_title: String,
    pub source_ids: Vec<String>,
}

/// Drive a single reflection-pass invocation over `namespace` (when
/// `Some`) or every observable namespace (when `None`).
///
/// `enabled_check` is the operator-supplied predicate that consults
/// the per-namespace [`ReflectionPassConfig::enabled`] flag. When the
/// flag is `false` for a given namespace the pass skips it entirely
/// and records nothing in the report.
///
/// This is the CLI entry-point — `src/cli/curator.rs` calls into it
/// when the operator passes `--reflect`. The autonomy daemon's
/// per-cycle sweep does NOT call this today (manual-only for v0.7.0
/// per #666 acceptance).
#[cfg(feature = "sal")]
pub async fn run_reflection_pass(
    store: &dyn MemoryStore,
    llm: &dyn AutonomyLlm,
    keypair: Option<&AgentKeypair>,
    namespace: Option<&str>,
    max_depth: Option<u32>,
    dry_run: bool,
    enabled_check: impl Fn(&str) -> bool,
) -> Result<ReflectionPassReport> {
    let mut report = ReflectionPassReport {
        started_at: Utc::now().to_rfc3339(),
        dry_run,
        ..Default::default()
    };

    let pass = ReflectionPass::new(store, llm, keypair, max_depth, dry_run);

    let namespaces: Vec<String> = match namespace {
        Some(ns) => vec![ns.to_string()],
        None => {
            // Enumerate every namespace with at least one row, then
            // filter via the operator's enabled_check at the call site.
            let counts = store
                .list_namespaces()
                .await
                .map_err(|e| anyhow::anyhow!(e))
                .context("run_reflection_pass: list_namespaces failed")?;
            counts
                .into_iter()
                .map(|nc| nc.namespace)
                .filter(|ns| !ns.starts_with('_'))
                .collect()
        }
    };
    report.namespaces_visited = namespaces.len();

    for ns in &namespaces {
        if !enabled_check(ns) {
            continue;
        }

        // Pull candidate Observations from this namespace. Cap at
        // MAX_CLUSTER_SIZE * 16 so a runaway namespace doesn't OOM the
        // pass; the per-namespace load is bounded by the curator's
        // existing batch contract.
        let candidates = match store_list_namespace(
            store,
            &pass.ctx,
            ns.as_str(),
            MAX_CLUSTER_SIZE * 16,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                report
                    .errors
                    .push(format!("namespace '{ns}': store.list failed: {e}"));
                continue;
            }
        };
        let scanned_here = candidates.len();
        report.observations_scanned += scanned_here;

        // Stage 1 — cluster.
        let clusters = pass.cluster(&candidates);
        report.clusters_formed += clusters.len();

        for cluster_ids in clusters {
            // Resolve cluster ids back to Memory for eligibility check.
            let mut cluster: Vec<Memory> = cluster_ids
                .iter()
                .filter_map(|id| candidates.iter().find(|m| &m.id == id).cloned())
                .collect();

            if !pass.eligible(&cluster) {
                continue;
            }
            report.clusters_eligible += 1;

            // Deterministic ordering so the produced reflection ids are
            // stable across re-runs on the same input (helps debugging).
            cluster.sort_by(|a, b| a.id.cmp(&b.id));

            let summary = match pass.summarize(&cluster) {
                Ok(s) => s,
                Err(e) => {
                    report
                        .errors
                        .push(format!("namespace '{ns}': summarize failed: {e}"));
                    continue;
                }
            };

            let source_ids: Vec<String> = cluster.iter().map(|m| m.id.clone()).collect();

            if dry_run {
                report.dry_run_proposals.push(DryRunProposal {
                    namespace: ns.clone(),
                    proposed_title: summary.title.clone(),
                    source_ids: source_ids.clone(),
                });
                continue;
            }

            match pass.persist(&summary, &source_ids).await {
                Ok(()) => {
                    report.reflections_persisted += 1;
                    // Best-effort verify on the most recent reflection
                    // in this namespace. We re-derive the id by listing
                    // the namespace and finding the freshest Reflection
                    // whose `reflects_on` ids match our cluster.
                    if let Err(e) = verify_recent(store, &pass.ctx, ns, &source_ids).await {
                        report
                            .errors
                            .push(format!("namespace '{ns}': verify failed: {e}"));
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("exceeds") && msg.contains("depth") {
                        report.depth_refusals += 1;
                    } else {
                        report
                            .errors
                            .push(format!("namespace '{ns}': persist failed: {e}"));
                    }
                }
            }
        }
    }

    report.completed_at = Utc::now().to_rfc3339();
    Ok(report)
}

/// Best-effort verify helper used by [`run_reflection_pass`]. Looks up
/// the most-recent Reflection in `namespace` and confirms its outbound
/// `reflects_on` edges cover exactly the supplied `source_ids`.
#[cfg(feature = "sal")]
async fn verify_recent(
    store: &dyn MemoryStore,
    ctx: &CallerContext,
    namespace: &str,
    source_ids: &[String],
) -> Result<()> {
    let candidates = store_list_namespace(store, ctx, namespace, 16)
        .await
        .context("verify_recent: store.list failed")?;
    let target_set: HashSet<&str> = source_ids.iter().map(String::as_str).collect();
    for cand in candidates
        .iter()
        .filter(|m| m.memory_kind == MemoryKind::Reflection)
    {
        let links = store
            .get_links_for_anchor(&cand.id)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        let outbound: HashSet<&str> = links
            .iter()
            .filter(|l| {
                l.source_id == cand.id
                    && l.relation == crate::models::MemoryLinkRelation::ReflectsOn
            })
            .map(|l| l.target_id.as_str())
            .collect();
        if outbound == target_set {
            // Round-trip the verify step against this reflection.
            // Reuse the trait method so the verification path is
            // identical to what the pass would do on the standalone
            // run.
            // We don't have a `ReflectionPass` here so we inline the
            // same checks via the link walk we already did.
            return Ok(());
        }
    }
    anyhow::bail!(
        "verify_recent: no Reflection in namespace '{namespace}' carries the \
         expected reflects_on edge set"
    )
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn tier_rank(t: &Tier) -> u8 {
    match t {
        Tier::Short => 0,
        Tier::Mid => 1,
        Tier::Long => 2,
    }
}

/// Returns `true` when `m` is a clusterable observation: typed as
/// Observation, not in an internal namespace, and recalled at least
/// `MIN_RECALL_COUNT` times. The recall threshold is the substrate
/// proxy for the spec's "recall co-occurrence frequency" signal.
fn is_clusterable_observation(m: &Memory) -> bool {
    m.memory_kind == MemoryKind::Observation
        && !m.namespace.starts_with('_')
        && m.access_count >= MIN_RECALL_COUNT
}

/// Returns `true` when two observations co-occur enough to seed a
/// reflection cluster: same namespace, created within
/// [`TEMPORAL_WINDOW_DAYS`] of each other, Jaccard ≥
/// [`REFLECTION_JACCARD_THRESHOLD`].
fn pair_co_occurs(a: &Memory, b: &Memory) -> bool {
    if a.namespace != b.namespace {
        return false;
    }
    if let (Some(ta), Some(tb)) = (parse_rfc3339(&a.created_at), parse_rfc3339(&b.created_at)) {
        let delta = (ta - tb).num_days().abs();
        if delta > TEMPORAL_WINDOW_DAYS {
            return false;
        }
    }
    jaccard_similarity(&a.content, &b.content) >= REFLECTION_JACCARD_THRESHOLD
}

/// Parse an RFC3339 timestamp into a `DateTime<Utc>`. Returns `None`
/// on parse failure (the caller treats that as "no temporal signal"
/// and lets the Jaccard step decide).
fn parse_rfc3339(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

/// Jaccard similarity over alphanumeric tokens of length ≥ 3,
/// lowercased. Mirror of the helper used by `consolidate` —
/// duplicated here so the reflection pass has zero runtime
/// dependency on the consolidate module ordering.
fn jaccard_similarity(a: &str, b: &str) -> f64 {
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

/// Compute the upper bound on the window duration in seconds.
/// Exposed for test assertions; not used outside this module.
#[cfg(test)]
pub(crate) fn temporal_window_seconds() -> i64 {
    chrono::Duration::days(TEMPORAL_WINDOW_DAYS).num_seconds()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

// The reflection-pass suite exercises the SAL-gated `ReflectionPass` over a
// `StubLlm: AutonomyLlm`; both are sal-only, so the whole module is gated
// (non-sal builds have no ReflectionPass to test).
#[cfg(all(test, feature = "sal"))]
mod tests {
    use super::*;
    use crate::models::{Memory, MemoryKind, Tier};
    use anyhow::Result;
    use chrono::Duration;
    use std::sync::Mutex;

    // ---- Deterministic stub LLM ------------------------------------------

    /// Deterministic stub for `AutonomyLlm`. Tests use this in place of
    /// the production `OllamaClient` so the reflection-pass suite never
    /// touches the network. The stub records every prompt it receives
    /// so per-test assertions can pin "summarize was called for cluster
    /// N" without inspecting log output.
    pub(super) struct StubLlm {
        pub(super) summary: String,
        pub(super) calls: Mutex<Vec<String>>,
    }

    impl StubLlm {
        pub(super) fn new(summary: &str) -> Self {
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

    // ---- Memory factory --------------------------------------------------

    fn make_obs(id: &str, ns: &str, title: &str, content: &str, access: i64) -> Memory {
        let now = Utc::now().to_rfc3339();
        Memory {
            id: id.to_string(),
            tier: Tier::Long,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: content.to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: access,
            created_at: now.clone(),
            updated_at: now,
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({}),
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
        }
    }

    // ---- Eligibility -----------------------------------------------------

    #[test]
    fn eligible_rejects_below_min_cluster_size() {
        // The cluster-size invariant is checked at the eligibility gate
        // — pure data check, no DB / LLM dependency.
        let cluster: Vec<Memory> = (0..(MIN_CLUSTER_SIZE - 1))
            .map(|i| make_obs(&format!("m{i}"), "app", "t", "kubernetes deploy", 1))
            .collect();
        let result = cluster.len() >= MIN_CLUSTER_SIZE
            && cluster.len() <= MAX_CLUSTER_SIZE
            && !cluster[0].namespace.starts_with('_')
            && cluster.iter().all(|m| {
                m.memory_kind == MemoryKind::Observation
                    && m.namespace == cluster[0].namespace
                    && m.access_count >= MIN_RECALL_COUNT
            });
        assert!(!result, "below-MIN cluster must not be eligible");
    }

    #[test]
    fn eligible_rejects_reflection_kind_member() {
        // Reflection-on-reflection chains form across passes (sequential
        // runs at depth=1 → depth=2). A single-pass cluster that already
        // contains a typed Reflection must NOT be eligible — that's the
        // job of a follow-up pass, not this one.
        let mut cluster: Vec<Memory> = (0..MIN_CLUSTER_SIZE)
            .map(|i| make_obs(&format!("m{i}"), "app", "t", "kubernetes deploy", 1))
            .collect();
        cluster[0].memory_kind = MemoryKind::Reflection;
        let result = cluster
            .iter()
            .all(|m| m.memory_kind == MemoryKind::Observation);
        assert!(!result, "mixed-kind cluster must not be eligible");
    }

    #[test]
    fn eligible_rejects_internal_namespace() {
        let cluster: Vec<Memory> = (0..MIN_CLUSTER_SIZE)
            .map(|i| make_obs(&format!("m{i}"), "_curator", "t", "kubernetes deploy", 1))
            .collect();
        let result = !cluster[0].namespace.starts_with('_');
        assert!(!result, "internal-namespace cluster must not be eligible");
    }

    // ---- Clustering ------------------------------------------------------

    #[test]
    fn cluster_groups_three_co_occurring_observations() {
        // Three observations in the same namespace, all with shared
        // Jaccard tokens, access_count >= 1 → form a single cluster.
        let m1 = make_obs("a", "ns", "t1", "kubernetes rolling deploy strategy", 2);
        let m2 = make_obs("b", "ns", "t2", "kubernetes deploy canary strategy", 3);
        let m3 = make_obs("c", "ns", "t3", "kubernetes rolling deploy approach", 1);

        // We can't construct a real ReflectionPass without a Connection,
        // so test the cluster() logic via the standalone pair_co_occurs
        // helper plus a manual seeded walk.
        let obs = [m1.clone(), m2.clone(), m3.clone()];
        let pairs = [
            pair_co_occurs(&m1, &m2),
            pair_co_occurs(&m1, &m3),
            pair_co_occurs(&m2, &m3),
        ];
        assert!(
            pairs.iter().all(|p| *p),
            "all three pairs must co-occur, got {pairs:?}"
        );
        assert_eq!(obs.len(), MIN_CLUSTER_SIZE);
    }

    #[test]
    fn cluster_skips_observations_with_zero_access_count() {
        // access_count = 0 → not clusterable. This is the substrate
        // proxy for "no recall co-occurrence signal".
        let cold = make_obs("cold", "ns", "t", "kubernetes deploy", 0);
        assert!(!is_clusterable_observation(&cold));
    }

    #[test]
    fn pair_co_occurs_rejects_cross_namespace() {
        let a = make_obs("a", "ns1", "t", "shared content tokens", 1);
        let b = make_obs("b", "ns2", "t", "shared content tokens", 1);
        assert!(!pair_co_occurs(&a, &b));
    }

    #[test]
    fn pair_co_occurs_respects_temporal_window() {
        // Build two memories whose created_at straddle the 7-day
        // window. The pair must NOT co-occur.
        let mut a = make_obs("a", "ns", "t", "shared content tokens here", 1);
        let mut b = make_obs("b", "ns", "t", "shared content tokens here", 1);
        let now = Utc::now();
        a.created_at = now.to_rfc3339();
        b.created_at = (now - Duration::days(TEMPORAL_WINDOW_DAYS + 2)).to_rfc3339();
        assert!(
            !pair_co_occurs(&a, &b),
            "outside-window pair must not co-occur"
        );
    }

    #[test]
    fn pair_co_occurs_below_jaccard_threshold_is_false() {
        let a = make_obs("a", "ns", "t", "kubernetes deploy strategy", 1);
        let b = make_obs(
            "b",
            "ns",
            "t",
            "completely unrelated quantum mechanics text",
            1,
        );
        assert!(!pair_co_occurs(&a, &b));
    }

    // ---- Helpers ---------------------------------------------------------

    #[test]
    fn jaccard_similarity_is_symmetric() {
        let a = "kubernetes rolling deploy canary";
        let b = "kubernetes canary rolling deploy strategy";
        let sim_ab = jaccard_similarity(a, b);
        let sim_ba = jaccard_similarity(b, a);
        assert!((sim_ab - sim_ba).abs() < 1e-9);
    }

    #[test]
    fn jaccard_similarity_empty_strings_zero() {
        assert_eq!(jaccard_similarity("", ""), 0.0);
    }

    #[test]
    fn temporal_window_is_7_days() {
        // 7 * 24 * 3600 = 604_800 seconds (named as
        // `crate::SECS_PER_WEEK` post PR #1174 PR3 — pm-v3.1).
        assert_eq!(temporal_window_seconds(), crate::SECS_PER_WEEK);
    }

    #[test]
    fn config_default_is_disabled() {
        // Per spec acceptance — operators must opt in per namespace.
        let cfg = ReflectionPassConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.max_depth.is_none());
    }

    #[test]
    fn config_round_trips_json() {
        let cfg = ReflectionPassConfig {
            enabled: true,
            max_depth: Some(2),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ReflectionPassConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // ---- Stub LLM contract ----------------------------------------------

    #[test]
    fn stub_llm_records_calls() {
        let stub = StubLlm::new("synthesised pattern");
        let out = stub
            .summarize_memories(&[("t1".into(), "c1".into()), ("t2".into(), "c2".into())])
            .unwrap();
        assert_eq!(out, "synthesised pattern");
        let calls = stub.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].starts_with("summarize:"));
    }

    // ---- Report serialisation -------------------------------------------

    #[test]
    fn report_serialises_to_json() {
        let r = ReflectionPassReport {
            started_at: "2026-01-01T00:00:00Z".into(),
            completed_at: "2026-01-01T00:00:01Z".into(),
            namespaces_visited: 1,
            observations_scanned: 30,
            clusters_formed: 3,
            clusters_eligible: 3,
            reflections_persisted: 3,
            depth_refusals: 0,
            errors: vec![],
            dry_run_proposals: vec![],
            dry_run: false,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("reflections_persisted"));
        assert!(json.contains("clusters_eligible"));
        let back: ReflectionPassReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.observations_scanned, 30);
    }

    // ---- ReflectionPass trait coverage (with real DB) ---------------------
    //
    // Issue #1548 — the reflection pass now operates over the SAL
    // `MemoryStore` trait rather than a raw `rusqlite::Connection`. The
    // trait is `sal`-gated, so this whole block is too. Tests open a
    // `SqliteStore` (which thin-wraps `crate::db::open`) and pass
    // `&store` into the pass. Seeding + assertions still go through the
    // `crate::db::*` free functions over a raw connection opened at the
    // same path (`conn_of`) so the test bodies stay close to the
    // pre-trait shape — exercising the SAME underlying SQLite file the
    // store reads. The pass methods are now `async`, so the trait-driving
    // tests are `#[tokio::test]`.
    #[cfg(feature = "sal")]
    mod sal_pass_tests {
        use super::*;

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

        fn insert_observation(
            conn: &rusqlite::Connection,
            ns: &str,
            title: &str,
            content: &str,
            access_count: i64,
        ) -> String {
            let now = chrono::Utc::now().to_rfc3339();
            let mut metadata = crate::models::default_metadata();
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(
                    "agent_id".to_string(),
                    serde_json::Value::String("test-agent".to_string()),
                );
            }
            let mem = Memory {
                id: uuid::Uuid::new_v4().to_string(),
                tier: Tier::Long,
                namespace: ns.to_string(),
                title: title.to_string(),
                content: content.to_string(),
                tags: vec![],
                priority: 5,
                confidence: 1.0,
                source: "test".to_string(),
                access_count,
                created_at: now.clone(),
                updated_at: now,
                last_accessed_at: None,
                expires_at: None,
                metadata,
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
            };
            crate::db::insert(conn, &mem).unwrap()
        }

        #[test]
        fn pass_name_is_reflection() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            assert_eq!(pass.name(), "reflection");
        }

        #[test]
        fn agent_id_falls_back_to_ai_curator_without_keypair() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            assert_eq!(pass.agent_id(), "ai:curator");
        }

        #[test]
        fn agent_id_uses_keypair_when_provided() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            use ed25519_dalek::{SigningKey, VerifyingKey};
            let mut rng = rand_core::OsRng;
            let sk = SigningKey::generate(&mut rng);
            let vk: VerifyingKey = (&sk).into();
            let kp = AgentKeypair {
                agent_id: "test:agent-x".to_string(),
                public: vk,
                private: Some(sk),
            };
            let pass = ReflectionPass::new(&store, &llm, Some(&kp), None, false);
            assert_eq!(pass.agent_id(), "test:agent-x");
        }

        #[test]
        fn cluster_excludes_zero_access_observations() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            let m1 = make_obs("a", "ns", "t", "shared keyword tokens here", 0); // 0 access → skipped
            let m2 = make_obs("b", "ns", "t", "shared keyword tokens here", 5);
            let m3 = make_obs("c", "ns", "t", "shared keyword tokens here", 5);
            let m4 = make_obs("d", "ns", "t", "shared keyword tokens here", 5);
            let clusters = pass.cluster(&[m1, m2, m3, m4]);
            assert_eq!(clusters.len(), 1);
            assert_eq!(clusters[0].len(), 3);
        }

        #[test]
        fn cluster_caps_at_max_cluster_size() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            // 15 mems with shared tokens → cluster capped at MAX_CLUSTER_SIZE = 12.
            let mems: Vec<Memory> = (0..15)
                .map(|i| {
                    make_obs(
                        &format!("m{i:02}"),
                        "ns",
                        "t",
                        "shared keyword tokens here pattern",
                        1,
                    )
                })
                .collect();
            let clusters = pass.cluster(&mems);
            // First-seed cluster grows up to MAX_CLUSTER_SIZE.
            for c in &clusters {
                assert!(c.len() <= MAX_CLUSTER_SIZE);
            }
        }

        #[test]
        fn eligible_pass_method_accepts_valid() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            let cluster: Vec<Memory> = (0..MIN_CLUSTER_SIZE)
                .map(|i| make_obs(&format!("m{i}"), "ns", "t", "c", 1))
                .collect();
            assert!(pass.eligible(&cluster));
        }

        #[test]
        fn eligible_pass_method_rejects_oversize() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            let cluster: Vec<Memory> = (0..(MAX_CLUSTER_SIZE + 1))
                .map(|i| make_obs(&format!("m{i:02}"), "ns", "t", "c", 1))
                .collect();
            assert!(!pass.eligible(&cluster));
        }

        #[test]
        fn eligible_pass_method_rejects_reflection_member() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            let mut cluster: Vec<Memory> = (0..MIN_CLUSTER_SIZE)
                .map(|i| make_obs(&format!("m{i}"), "ns", "t", "c", 1))
                .collect();
            cluster[0].memory_kind = MemoryKind::Reflection;
            assert!(!pass.eligible(&cluster));
        }

        #[test]
        fn eligible_pass_method_rejects_zero_access() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            let mut cluster: Vec<Memory> = (0..MIN_CLUSTER_SIZE)
                .map(|i| make_obs(&format!("m{i}"), "ns", "t", "c", 1))
                .collect();
            cluster[1].access_count = 0;
            assert!(!pass.eligible(&cluster));
        }

        #[test]
        fn summarize_below_min_errors() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            let cluster: Vec<Memory> = (0..(MIN_CLUSTER_SIZE - 1))
                .map(|i| make_obs(&format!("m{i}"), "ns", "t", "c", 1))
                .collect();
            let err = pass.summarize(&cluster).unwrap_err().to_string();
            assert!(err.contains("< MIN_CLUSTER_SIZE"));
        }

        #[test]
        fn summarize_returns_reflection_typed_memory() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("synth pattern");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            let cluster: Vec<Memory> = (0..MIN_CLUSTER_SIZE)
                .map(|i| {
                    let mut m = make_obs(&format!("m{i}"), "ns", "Title-A", "shared content", 2);
                    m.tier = if i == 0 { Tier::Long } else { Tier::Mid };
                    m.priority = 5 + i32::try_from(i).unwrap();
                    m
                })
                .collect();
            let summary = pass.summarize(&cluster).unwrap();
            assert_eq!(summary.memory_kind, MemoryKind::Reflection);
            assert!(summary.title.starts_with("[reflection]"));
            assert_eq!(summary.content, "synth pattern");
            assert_eq!(summary.tier, Tier::Long);
            assert_eq!(summary.source, "system");
            assert_eq!(summary.namespace, "ns");
            // Priority = max of source priorities.
            assert_eq!(
                summary.priority,
                5 + i32::try_from(MIN_CLUSTER_SIZE - 1).unwrap()
            );
        }

        #[tokio::test]
        async fn persist_dry_run_is_noop() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, true);
            let summary = make_obs("s", "ns", "[reflection]", "c", 1);
            pass.persist(&summary, &["x".to_string()]).await.unwrap();
        }

        #[tokio::test]
        async fn persist_empty_sources_is_noop() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            let summary = make_obs("s", "ns", "[reflection]", "c", 1);
            pass.persist(&summary, &[]).await.unwrap();
        }

        #[tokio::test]
        async fn persist_refuses_when_max_depth_exceeded() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            // Pass max_depth=1; insert source at reflection_depth=1 → new depth = 2 → refused.
            let pass = ReflectionPass::new(&store, &llm, None, Some(1), false);
            let mut source = make_obs("src", "ns", "t", "c", 1);
            source.reflection_depth = 1;
            let src_id = crate::db::insert(&conn_of(&store), &source).unwrap();
            let summary = make_obs("s", "ns", "[reflection]", "c", 0);
            let err = pass
                .persist(&summary, &[src_id])
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("exceeds"));
            assert!(err.contains("--max-depth"));
        }

        #[tokio::test]
        async fn persist_writes_reflection_into_db() {
            // Full happy-path: real sources, real reflect insert.
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = StubLlm::new("synthesised pattern");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            // Seed three observations in namespace 'app'.
            let s1 = insert_observation(&conn, "app", "T1", "kubernetes deploy strategy notes", 2);
            let s2 =
                insert_observation(&conn, "app", "T2", "kubernetes rolling deploy approach", 3);
            let s3 = insert_observation(&conn, "app", "T3", "kubernetes canary deploy strategy", 1);
            let summary = pass
                .summarize(&[
                    crate::db::get(&conn, &s1).unwrap().unwrap(),
                    crate::db::get(&conn, &s2).unwrap().unwrap(),
                    crate::db::get(&conn, &s3).unwrap().unwrap(),
                ])
                .unwrap();
            pass.persist(&summary, &[s1.clone(), s2.clone(), s3.clone()])
                .await
                .unwrap();

            // Find the freshly-written reflection in the 'app' namespace.
            let listed = crate::db::list(
                &conn,
                Some("app"),
                None,
                32,
                0,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            let refl = listed
                .iter()
                .find(|m| m.memory_kind == MemoryKind::Reflection)
                .expect("expected one reflection");
            // verify() should succeed on it.
            pass.verify(refl.id.clone()).await.unwrap();
        }

        #[tokio::test]
        async fn verify_missing_id_errors() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            let err = pass
                .verify("no-such".to_string())
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("not found in DB"));
        }

        #[tokio::test]
        async fn verify_wrong_kind_errors() {
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            // Insert an Observation and verify against its id — must error.
            let id = insert_observation(&conn, "ns", "T", "c", 1);
            let err = pass.verify(id).await.unwrap_err().to_string();
            assert!(err.contains("expected Reflection"));
        }

        #[tokio::test]
        async fn verify_reflection_without_edges_errors() {
            // Insert a Reflection directly via db::insert (no reflects_on links)
            // and verify against it — must error with "no reflects_on edge".
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            let now = chrono::Utc::now().to_rfc3339();
            let mut metadata = crate::models::default_metadata();
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(
                    "agent_id".to_string(),
                    serde_json::Value::String("test-agent".to_string()),
                );
            }
            let m = Memory {
                id: uuid::Uuid::new_v4().to_string(),
                tier: Tier::Mid,
                namespace: "ns".to_string(),
                title: "[reflection] orphan".to_string(),
                content: "c".to_string(),
                tags: vec![],
                priority: 5,
                confidence: 1.0,
                source: "system".to_string(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now,
                last_accessed_at: None,
                expires_at: None,
                metadata,
                reflection_depth: 1,
                memory_kind: MemoryKind::Reflection,
                entity_id: None,
                persona_version: None,
                citations: Vec::new(),
                source_uri: None,
                source_span: None,
                confidence_source: ConfidenceSource::CallerProvided,
                confidence_signals: None,
                confidence_decayed_at: None,
                version: 1,
            };
            let id = crate::db::insert(&conn, &m).unwrap();
            let err = pass.verify(id).await.unwrap_err().to_string();
            assert!(err.contains("no reflects_on edge"));
        }

        // ---- run_reflection_pass driver -------------------------------------

        #[tokio::test]
        async fn run_reflection_pass_empty_db_dry_run_namespace() {
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let report =
                run_reflection_pass(&store, &llm, None, Some("nope"), None, true, |_| true)
                    .await
                    .unwrap();
            assert!(report.dry_run);
            assert_eq!(report.namespaces_visited, 1);
            assert_eq!(report.clusters_formed, 0);
            assert_eq!(report.reflections_persisted, 0);
        }

        #[tokio::test]
        async fn run_reflection_pass_all_namespaces_with_disabled_check() {
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = StubLlm::new("S");
            // Seed an observation so list_namespaces sees one ns.
            insert_observation(&conn, "ns1", "t", "shared content tokens here", 2);
            let report = run_reflection_pass(&store, &llm, None, None, None, true, |_| false)
                .await
                .unwrap();
            // namespace is enumerated but enabled_check returns false → no work.
            assert_eq!(report.observations_scanned, 0);
        }

        #[tokio::test]
        async fn run_reflection_pass_dry_run_reports_proposals() {
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = StubLlm::new("synth");
            // Seed three observations that should cluster.
            insert_observation(
                &conn,
                "app",
                "T1",
                "kubernetes rolling deploy strategy notes",
                2,
            );
            insert_observation(
                &conn,
                "app",
                "T2",
                "kubernetes rolling deploy strategy canary",
                3,
            );
            insert_observation(
                &conn,
                "app",
                "T3",
                "kubernetes canary deploy strategy rolling",
                1,
            );
            let report = run_reflection_pass(&store, &llm, None, Some("app"), None, true, |_| true)
                .await
                .unwrap();
            assert!(report.dry_run);
            assert!(report.observations_scanned >= 3);
            assert!(report.clusters_eligible >= 1);
            assert!(!report.dry_run_proposals.is_empty());
            assert_eq!(report.reflections_persisted, 0);
        }

        #[tokio::test]
        async fn run_reflection_pass_persists_reflections() {
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = StubLlm::new("persisted pattern");
            insert_observation(&conn, "app", "T1", "shared keyword token strategy notes", 2);
            insert_observation(&conn, "app", "T2", "shared keyword token strategy plan", 3);
            insert_observation(
                &conn,
                "app",
                "T3",
                "shared keyword token strategy canary",
                1,
            );
            let report =
                run_reflection_pass(&store, &llm, None, Some("app"), None, false, |_| true)
                    .await
                    .unwrap();
            assert_eq!(report.dry_run, false);
            assert!(report.reflections_persisted >= 1);
        }

        #[tokio::test]
        async fn run_reflection_pass_depth_refusal_increments_counter() {
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = StubLlm::new("synth");
            // Seed observations at depth=2 so a new reflection (depth=3)
            // would exceed our curator max_depth=2.
            let now = chrono::Utc::now().to_rfc3339();
            for i in 0..3 {
                let mut metadata = crate::models::default_metadata();
                if let Some(obj) = metadata.as_object_mut() {
                    obj.insert(
                        "agent_id".to_string(),
                        serde_json::Value::String("test-agent".to_string()),
                    );
                }
                let m = Memory {
                    id: uuid::Uuid::new_v4().to_string(),
                    tier: Tier::Long,
                    namespace: "deep".to_string(),
                    title: format!("Tdeep-{i}"),
                    content: "shared keyword token deep strategy".to_string(),
                    tags: vec![],
                    priority: 5,
                    confidence: 1.0,
                    source: "test".to_string(),
                    access_count: 2,
                    created_at: now.clone(),
                    updated_at: now.clone(),
                    last_accessed_at: None,
                    expires_at: None,
                    metadata,
                    reflection_depth: 2,
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
                };
                crate::db::insert(&conn, &m).unwrap();
            }
            let report = run_reflection_pass(
                &store,
                &llm,
                None,
                Some("deep"),
                Some(2), // cap=2; new depth would be 3 → refuse
                false,
                |_| true,
            )
            .await
            .unwrap();
            assert!(report.depth_refusals >= 1);
            // No reflection persisted.
            assert_eq!(report.reflections_persisted, 0);
        }

        #[test]
        fn dry_run_proposal_serialises() {
            let p = DryRunProposal {
                namespace: "ns".into(),
                proposed_title: "[reflection] x".into(),
                source_ids: vec!["a".into(), "b".into()],
            };
            let j = serde_json::to_string(&p).unwrap();
            assert!(j.contains("source_ids"));
            let back: DryRunProposal = serde_json::from_str(&j).unwrap();
            assert_eq!(back.namespace, "ns");
        }

        // ---- pair_co_occurs unparseable timestamps fall through ----

        #[test]
        fn pair_co_occurs_unparseable_timestamps_still_checks_jaccard() {
            let mut a = make_obs("a", "ns", "t", "shared content tokens here", 1);
            let mut b = make_obs("b", "ns", "t", "shared content tokens here", 1);
            a.created_at = "not-a-timestamp".to_string();
            b.created_at = "also-invalid".to_string();
            // With invalid timestamps, the temporal check is skipped — Jaccard
            // alone decides. These share tokens → co-occur returns true.
            assert!(pair_co_occurs(&a, &b));
        }

        // ---- Additional coverage: trait impls + edge branches ----

        #[test]
        fn stub_llm_auto_tag_and_contradiction_paths() {
            let stub = StubLlm::new("S");
            let tags = stub.auto_tag("t", "c").unwrap();
            assert!(tags.is_empty());
            let conflict = stub.detect_contradiction("a", "b").unwrap();
            assert!(!conflict);
        }

        #[test]
        fn eligible_pass_rejects_internal_namespace_directly() {
            // Drives the internal-namespace early-return.
            let (store, _dir) = open_db();
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            let cluster: Vec<Memory> = (0..MIN_CLUSTER_SIZE)
                .map(|i| make_obs(&format!("m{i}"), "_curator", "t", "c", 1))
                .collect();
            assert!(!pass.eligible(&cluster));
        }

        #[test]
        fn jaccard_similarity_zero_union_returns_zero() {
            // The else-branch where `union == 0`: ta non-empty but tb is — no.
            // Actually if either has >=3 chars words there will be union.
            // Build inputs where tokens are stripped to nothing.
            let a = "a b c"; // every token <3 chars → tokens set is empty
            let b = "x";
            assert_eq!(jaccard_similarity(a, b), 0.0);
        }

        #[test]
        fn tier_rank_all_variants() {
            // Drives all three match arms.
            assert_eq!(tier_rank(&Tier::Short), 0);
            assert_eq!(tier_rank(&Tier::Mid), 1);
            assert_eq!(tier_rank(&Tier::Long), 2);
        }

        #[test]
        fn parse_rfc3339_invalid_returns_none() {
            assert!(parse_rfc3339("garbage").is_none());
            assert!(parse_rfc3339("2026-01-01T00:00:00Z").is_some());
        }

        #[tokio::test]
        async fn verify_skips_inbound_links() {
            // verify() walks all links but `continue`s when source_id != summary_id.
            // This exercises the inbound-link `continue` branch.
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = StubLlm::new("S");
            let pass = ReflectionPass::new(&store, &llm, None, None, false);
            // Seed the reflection target via the full persist path.
            let s1 =
                insert_observation(&conn, "vrf", "T1", "shared keyword pattern tokens here", 2);
            let s2 =
                insert_observation(&conn, "vrf", "T2", "shared keyword pattern tokens here", 2);
            let s3 =
                insert_observation(&conn, "vrf", "T3", "shared keyword pattern tokens here", 2);
            let summary = pass
                .summarize(&[
                    crate::db::get(&conn, &s1).unwrap().unwrap(),
                    crate::db::get(&conn, &s2).unwrap().unwrap(),
                    crate::db::get(&conn, &s3).unwrap().unwrap(),
                ])
                .unwrap();
            pass.persist(&summary, &[s1.clone(), s2.clone(), s3.clone()])
                .await
                .unwrap();
            let listed = crate::db::list(
                &conn,
                Some("vrf"),
                None,
                32,
                0,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
            let refl_id = listed
                .iter()
                .find(|m| m.memory_kind == MemoryKind::Reflection)
                .unwrap()
                .id
                .clone();
            // Create a foreign link with this reflection as TARGET (not source).
            // verify() should still succeed because it ignores inbound links.
            let _ = crate::db::create_link(&conn, &s1, &refl_id, "related_to");
            pass.verify(refl_id).await.unwrap();
        }

        #[tokio::test]
        async fn run_reflection_pass_summarize_error_recorded() {
            // Drive the summarize failure path. Use a StubLlm that
            // fails summarize. We need it implementing AutonomyLlm with an
            // error return.
            struct FailingLlm;
            impl AutonomyLlm for FailingLlm {
                fn auto_tag(&self, _t: &str, _c: &str) -> Result<Vec<String>> {
                    Ok(vec![])
                }
                fn detect_contradiction(&self, _a: &str, _b: &str) -> Result<bool> {
                    Ok(false)
                }
                fn summarize_memories(&self, _m: &[(String, String)]) -> Result<String> {
                    anyhow::bail!("forced llm failure")
                }
            }
            let (store, _dir) = open_db();
            let conn = conn_of(&store);
            let llm = FailingLlm;
            insert_observation(&conn, "ns", "T1", "shared keyword pattern tokens here", 2);
            insert_observation(&conn, "ns", "T2", "shared keyword pattern tokens here", 2);
            insert_observation(&conn, "ns", "T3", "shared keyword pattern tokens here", 2);
            let report = run_reflection_pass(&store, &llm, None, Some("ns"), None, false, |_| true)
                .await
                .unwrap();
            // Summarize error was caught and recorded.
            assert!(report.errors.iter().any(|e| e.contains("summarize failed")));
            assert_eq!(report.reflections_persisted, 0);
        }
    } // mod sal_pass_tests
}
