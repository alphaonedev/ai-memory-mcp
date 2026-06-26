// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1393 sub-unit 2 — curator transcript-classify pass.
//!
//! Scans memories L2-recovered from host transcripts (tagged
//! [`crate::recover::RECOVERED_FROM_TRANSCRIPT_TAG`]) that are still the
//! default [`MemoryKind::Observation`], asks the autonomy LLM to classify
//! each ("is this recovered turn actually a `Decision` / `Claim` / `Event`
//! …?"), and — when the LLM returns a refined kind — re-tags the memory's
//! `memory_kind` through the dedicated, audited
//! [`MemoryStore::reclassify_memory_kind`] path (emits a signed
//! `memory.reclassified` audit row; `reflection` / `persona` kinds are
//! protected from being clobbered).
//!
//! Opt-in: gated by `AI_MEMORY_TRANSCRIPT_CLASSIFY_ENABLED` (default
//! `false`) at the CLI wiring layer (`src/cli/curator.rs`). Backend-agnostic
//! via the SAL trait (SQLite *or* Postgres); tests inject a deterministic
//! stub [`AutonomyLlm`]. The whole module is `sal`-gated because it operates
//! exclusively through the [`MemoryStore`] trait.
//!
//! Design (dedicated audited path, NOT a general `UpdatePatch` field):
//! 5-agent vote, memory `4d3ea1c5`.

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::autonomy::AutonomyLlm;
use crate::models::{Memory, MemoryKind};
use crate::recover::RECOVERED_FROM_TRANSCRIPT_TAG;
use crate::store::{CallerContext, Filter, MemoryStore};

/// Default per-cycle ceiling on the number of recovered observations the
/// pass will classify, so a large recovered corpus can never make one
/// cycle issue unbounded LLM calls. A `0` from config resolves to this.
/// The pass is eventually-consistent: each cycle drains up to this many
/// candidates, so the backlog clears across cycles.
pub const DEFAULT_MAX_PER_CYCLE: usize = 200;

/// Structured outcome of one transcript-classify invocation. Aggregated
/// across namespaces by [`TranscriptClassifyPass::run`]; serialised for the
/// curator log / `--json` surface.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TranscriptClassifyReport {
    /// RFC3339 timestamps.
    pub started_at: String,
    pub completed_at: String,
    /// Namespaces visited (`1` for a single `--namespace`, else every
    /// non-`_`-prefixed namespace with rows).
    pub namespaces_visited: usize,
    /// Recovered `Observation` candidates scanned (tag + kind matched).
    pub observations_scanned: usize,
    /// LLM returned a refined (non-`Observation`) kind.
    pub classified: usize,
    /// Memories actually re-tagged. Always `0` under `dry_run`; also less
    /// than `classified` when the store refused (protected kind / no-op).
    pub reclassified: usize,
    /// LLM abstentions (returned `None`) + same-kind no-ops.
    pub abstained: usize,
    /// Non-fatal LLM / store errors that did NOT abort the pass.
    pub errors: Vec<String>,
    /// `true` when the pass suppressed all writes.
    pub dry_run: bool,
}

/// Curator transcript-classify pass. Reads recovered Observations through
/// [`MemoryStore::list`] (tag-filtered) and writes through the audited
/// [`MemoryStore::reclassify_memory_kind`]. Backend-agnostic.
pub(crate) struct TranscriptClassifyPass<'a> {
    store: &'a dyn MemoryStore,
    /// Operator-class caller context so the background sweep reads every
    /// row regardless of `metadata.scope` (mirrors the reflection pass).
    ctx: CallerContext,
    llm: &'a dyn AutonomyLlm,
    /// Suppress every write — `run()` still computes the would-be
    /// classification and reports it, but never calls `reclassify`.
    dry_run: bool,
    /// Per-cycle classify budget (see [`DEFAULT_MAX_PER_CYCLE`]).
    max_per_cycle: usize,
}

impl<'a> TranscriptClassifyPass<'a> {
    /// Construct the pass. `agent_id` is the curator's identity (stamped as
    /// the actor on the `memory.reclassified` audit rows); a `0`
    /// `max_per_cycle` resolves to [`DEFAULT_MAX_PER_CYCLE`].
    pub(crate) fn new(
        store: &'a dyn MemoryStore,
        llm: &'a dyn AutonomyLlm,
        agent_id: &str,
        dry_run: bool,
        max_per_cycle: usize,
    ) -> Self {
        Self {
            store,
            ctx: CallerContext::for_admin(agent_id),
            llm,
            dry_run,
            max_per_cycle: if max_per_cycle == 0 {
                DEFAULT_MAX_PER_CYCLE
            } else {
                max_per_cycle
            },
        }
    }

    /// A reclassification candidate: a recovered-from-transcript memory
    /// still at the default `Observation` kind. The tag is also enforced by
    /// the `list` filter; this guards the kind (already-reclassified rows
    /// are skipped, which is what makes re-runs idempotent).
    fn is_candidate(m: &Memory) -> bool {
        m.memory_kind == MemoryKind::Observation
            && m.tags.iter().any(|t| t == RECOVERED_FROM_TRANSCRIPT_TAG)
    }

    /// Scan `namespace` (when `Some`) or every non-`_` namespace, classify
    /// each recovered Observation, and re-tag those the LLM refines.
    pub(crate) async fn run(&self, namespace: Option<&str>) -> Result<TranscriptClassifyReport> {
        let mut report = TranscriptClassifyReport {
            started_at: Utc::now().to_rfc3339(),
            dry_run: self.dry_run,
            ..Default::default()
        };

        let namespaces: Vec<String> = match namespace {
            Some(ns) => vec![ns.to_string()],
            None => self
                .store
                .list_namespaces()
                .await
                .map_err(|e| anyhow::anyhow!(e))?
                .into_iter()
                .map(|nc| nc.namespace)
                .filter(|ns| !ns.starts_with('_'))
                .collect(),
        };
        report.namespaces_visited = namespaces.len();

        let mut budget = self.max_per_cycle;
        for ns in &namespaces {
            if budget == 0 {
                break;
            }
            // Tag-filter at the store so we only pull recovered rows (the
            // `list` impl honours `tags_any.first()`); cap the pull at the
            // remaining budget.
            let filter = Filter {
                namespace: Some(ns.clone()),
                tags_any: vec![RECOVERED_FROM_TRANSCRIPT_TAG.to_string()],
                limit: budget,
                ..Default::default()
            };
            let memories = match self.store.list(&self.ctx, &filter).await {
                Ok(v) => v,
                Err(e) => {
                    report
                        .errors
                        .push(format!("namespace '{ns}': list failed: {e}"));
                    continue;
                }
            };
            for m in memories {
                if budget == 0 {
                    break;
                }
                if !Self::is_candidate(&m) {
                    continue;
                }
                budget -= 1;
                report.observations_scanned += 1;
                match self.llm.classify_kind(&m.title, &m.content) {
                    Ok(Some(kind)) if kind != MemoryKind::Observation => {
                        report.classified += 1;
                        if self.dry_run {
                            continue;
                        }
                        match self
                            .store
                            .reclassify_memory_kind(&self.ctx, &m.id, kind)
                            .await
                        {
                            Ok(true) => report.reclassified += 1,
                            // protected kind / no-op / not-found — not an error.
                            Ok(false) => {}
                            Err(e) => report
                                .errors
                                .push(format!("memory '{}': reclassify failed: {e}", m.id)),
                        }
                    }
                    // None (abstain) or Observation (no refinement).
                    Ok(_) => report.abstained += 1,
                    Err(e) => report
                        .errors
                        .push(format!("memory '{}': classify_kind failed: {e}", m.id)),
                }
            }
        }

        report.completed_at = Utc::now().to_rfc3339();
        Ok(report)
    }
}

/// Public entry point — construct and run the transcript-classify pass over
/// `namespace` (when `Some`) or every non-`_` namespace. Mirrors
/// [`crate::curator::reflection_pass::run_reflection_pass`] as the
/// CLI / integration-test surface; the [`TranscriptClassifyPass`] struct
/// itself stays crate-private. `agent_id` is stamped as the actor on the
/// `memory.reclassified` audit rows; `max_per_cycle == 0` resolves to
/// [`DEFAULT_MAX_PER_CYCLE`].
///
/// # Errors
///
/// Propagates a fatal store error (e.g. `list_namespaces` failure); per-row
/// LLM / reclassify errors are collected into the report rather than aborting.
pub async fn run_transcript_classify_pass(
    store: &dyn MemoryStore,
    llm: &dyn AutonomyLlm,
    agent_id: &str,
    namespace: Option<&str>,
    dry_run: bool,
    max_per_cycle: usize,
) -> Result<TranscriptClassifyReport> {
    TranscriptClassifyPass::new(store, llm, agent_id, dry_run, max_per_cycle)
        .run(namespace)
        .await
}
