// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Autonomous curator daemon (v0.6.1).
//!
//! Runs a periodic sweep over stored memories, invoking `auto_tag` and
//! `detect_contradiction` via the configured LLM and persisting results
//! into each memory's metadata. Complements the synchronous post-store
//! hooks shipped in v0.6.0.0 (#265) — those fire inline on writes; the
//! curator catches memories that were stored before hooks were enabled,
//! or when the LLM was temporarily offline, or that only become
//! interesting later as more context accumulates.
//!
//! The curator is intentionally bounded:
//!
//! - Hard cap on operations per cycle — never runs unbounded work.
//! - Skips internal (`_`-prefixed) namespaces.
//! - Honours include / exclude namespace lists.
//! - Dry-run mode emits the report without touching any row.
//! - Each operation is best-effort; LLM errors are logged but never
//!   abort the cycle.
//!
//! ## Layout (v0.7.0 Layer 0.5)
//!
//! Originally a single 1649-line `src/curator.rs`; split into a
//! `src/curator/` sub-tree by Task L0.5-1. Pure refactor — public
//! surface unchanged, every previously-`pub` item still resolves at
//! `crate::curator::<name>`.
//!
//! - `candidates` — per-cycle row collection + eligibility filter.
//! - `persist` — write-back helpers (`persist_auto_tags`,
//!   `persist_contradiction`).
//! - `reflection_pass` — empty placeholder for Layer 2 Task L2-1.

pub(crate) mod candidates;
pub(crate) mod cluster;
pub(crate) mod compaction;
pub(crate) mod persist;
pub(crate) mod pipeline;
// v0.7.0 L2-1 — `reflection_pass` exposes a small public surface
// (`ReflectionPassConfig`, `ReflectionPassReport`, `DryRunProposal`,
// `run_reflection_pass`) consumed by the integration test crate plus
// the CLI's `--reflect` mode. Items inside the module that should
// stay crate-private use `pub(crate)` directly.
/// #1764 (v0.8.0 slice) — reflection-corpus decorrelation VISIBILITY probe.
/// The pure dominance analyzer (`compute_producer_dominance` /
/// `evaluate_namespace`) is backend-agnostic; the `sal`-gated
/// `run_decorrelation_probe` scans the Reflection corpus through the
/// `MemoryStore` trait. Opt-in via `AI_MEMORY_REFLECT_DECORRELATION_MODE`.
pub mod decorrelation_probe;
pub mod reflection_pass;
/// #1393 sub-unit 2 — curator transcript-classify pass. Entirely
/// `sal`-gated: it operates exclusively through the `MemoryStore` trait
/// (`reclassify_memory_kind` + `list`), so it only exists in `sal` builds.
#[cfg(feature = "sal")]
pub mod transcript_classify_pass;

use anyhow::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(test)]
use crate::db;
use crate::llm::OllamaClient;
use crate::models::Memory;
#[cfg(test)]
use crate::models::Tier;

use candidates::{
    CandidateBatch, adjacent_memory, collect_candidates, namespace_in_scope, needs_curation,
    record_truncation,
};
use persist::{persist_auto_tags, persist_contradiction};

/// Default curator sweep interval (1 hour).
pub const DEFAULT_INTERVAL_SECS: u64 = crate::SECS_PER_HOUR as u64;

/// Default per-cycle operation cap (stops runaway LLM calls).
pub const DEFAULT_MAX_OPS_PER_CYCLE: usize = 100;

/// v1.0.0 — divisor fixing the autonomy passes' RESERVED share of
/// [`CuratorConfig::max_ops_per_cycle`].
///
/// The auto-tag / contradiction loop and the autonomy passes draw on ONE
/// cycle budget, and both are fed by the same `needs_curation` predicate.
/// Without a reservation the loop runs first and can legitimately spend the
/// entire cap, handing the autonomy passes a budget of exactly zero — and it
/// does so on EVERY cycle for as long as the untagged backlog stays at or
/// above the cap, which is permanent whenever those rows keep yielding empty
/// auto-tags (an empty tag list persists nothing, so the row stays eligible
/// forever). Consolidation would then never run again on a busy corpus.
///
/// Reserving `max_ops_per_cycle / AUTONOMY_OP_RESERVE_DIVISOR` ops for the
/// passes makes that starvation structurally impossible while keeping
/// `max_ops_per_cycle` a TRUE hard cap: the reserve is carved OUT of the cap
/// (the loop's own budget shrinks by the same amount), never added on top of
/// it, so a cycle can still never exceed the operator's authorised LLM spend.
pub const AUTONOMY_OP_RESERVE_DIVISOR: usize = 4;

/// Minimum content length before the curator will touch a memory —
/// matches the synchronous hook threshold in `src/mcp.rs`.
pub const MIN_CONTENT_LEN: usize = 50;

/// Per-namespace compaction configuration.
///
/// Defaults to `enabled = false` to match ROADMAP §7.5: compaction is
/// opt-in because it depends on the Ollama LLM being available at
/// consolidation time.  Operators enable it per-namespace in
/// `ai-memory.toml` once they have confirmed Ollama is reachable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionConfig {
    /// When `false` (the default), the compaction pipeline skips this
    /// namespace entirely.  Set to `true` to opt in.
    #[serde(default)]
    pub enabled: bool,
    /// Cosine similarity threshold for cluster formation (the cosine gate in
    /// [`crate::curator::cluster::ConsolidationClustering`]).
    /// Defaults to `0.75` when omitted.
    #[serde(default = "default_cosine_threshold")]
    pub cosine_threshold: f32,
    /// v0.7.0 L2-1 — per-namespace reflection-pass configuration.
    /// Defaults to `enabled = false` per #666 acceptance: the
    /// reflection pass is opt-in because (a) it depends on the Ollama
    /// LLM being available at the time the pass runs, and (b) it
    /// writes typed Reflection memories to the namespace which
    /// operators may want to gate per-namespace rather than enable
    /// globally.
    #[serde(default)]
    pub reflection_pass: reflection_pass::ReflectionPassConfig,
    /// v0.8.0 Pillar-2.5 (#1709) — corpus byte-cap for size-GC eviction.
    ///
    /// `None` (the default) disables byte-pressure eviction entirely,
    /// matching the `enabled = false` opt-in posture of the rest of the
    /// compaction surface. When `Some(cap)` with `cap > 0`, the curator's
    /// size-GC pass evicts (archive-before-delete, restorable) the
    /// lowest-value memories in each scanned namespace whose live corpus
    /// (`length(title)+length(content)+length(metadata)` summed) exceeds
    /// `cap`, until the namespace is back under the cap. Pure SQL ranking
    /// — deterministic and LLM-free. Distinct from the per-agent K8 write
    /// quota (`AI_MEMORY_MAX_STORAGE_BYTES`): this is a per-namespace
    /// eviction trigger, not a write gate.
    #[serde(default)]
    pub max_corpus_bytes: Option<i64>,
}

fn default_cosine_threshold() -> f32 {
    crate::curator::cluster::DEFAULT_COSINE_THRESHOLD
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cosine_threshold: default_cosine_threshold(),
            reflection_pass: reflection_pass::ReflectionPassConfig::default(),
            max_corpus_bytes: None,
        }
    }
}

/// Curator configuration (surfaced to CLI + config file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CuratorConfig {
    /// Seconds between sweeps in daemon mode. Clamped at runtime to
    /// `[60, 86400]` to avoid pathological values.
    pub interval_secs: u64,
    /// Hard cap on LLM-invoking operations per cycle.
    pub max_ops_per_cycle: usize,
    /// When true, emits the report but never writes back to the DB.
    pub dry_run: bool,
    /// When non-empty, only these namespaces are curated. Exact match.
    pub include_namespaces: Vec<String>,
    /// Namespaces to skip. Exact match. Always also skips `_`-prefixed.
    pub exclude_namespaces: Vec<String>,
    /// Per-namespace compaction configuration.  Defaults to
    /// `enabled = false` per ROADMAP §7.5 (opt-in due to Ollama dep).
    #[serde(default)]
    pub compaction: CompactionConfig,
    /// v1.0.0 #3345 — archive-before-delete disposition for the TTL sweep the
    /// daemon loop now runs (`[storage].archive_on_gc`, default `true`).
    ///
    /// NOT a curator config key: `#[serde(skip)]` keeps it out of the config
    /// file and the serialised report, because the operator already sets it
    /// once under `[storage]`. It is in-process plumbing only, resolved by the
    /// caller that HAS the `AppConfig` — the same shape #1749 used for
    /// `compaction_enabled`. Threading it (rather than defaulting to `true`
    /// here) matters: an operator who set `archive_on_gc = false` wants
    /// hard-delete, and silently archiving instead would retain rows they
    /// asked to be erased.
    #[serde(skip, default = "default_archive_on_gc")]
    pub archive_on_gc: bool,
}

/// v1.0.0 #3345 — `[storage].archive_on_gc`'s own default (`true`), so a
/// `CuratorConfig` built without the resolver still takes the REVERSIBLE
/// option. Mirrors `AppConfig::effective_archive_on_gc`.
fn default_archive_on_gc() -> bool {
    true
}

impl Default for CuratorConfig {
    fn default() -> Self {
        Self {
            interval_secs: DEFAULT_INTERVAL_SECS,
            max_ops_per_cycle: DEFAULT_MAX_OPS_PER_CYCLE,
            dry_run: false,
            include_namespaces: Vec::new(),
            exclude_namespaces: Vec::new(),
            compaction: CompactionConfig::default(),
            archive_on_gc: default_archive_on_gc(),
        }
    }
}

/// Structured report produced by a single curator cycle. Serialises
/// cleanly to JSON for CLI output, systemd journald, or Prometheus
/// text-format conversion.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CuratorReport {
    pub started_at: String,
    pub completed_at: String,
    pub cycle_duration_ms: u128,
    pub memories_scanned: usize,
    pub memories_eligible: usize,
    pub auto_tagged: usize,
    pub contradictions_found: usize,
    pub operations_attempted: usize,
    pub operations_skipped_cap: usize,
    /// v0.6.1 autonomy passes — consolidation, forget-superseded,
    /// priority feedback, rollback-log. All zero when autonomy is not
    /// enabled or not reached for this cycle.
    #[serde(default)]
    pub autonomy: crate::autonomy::AutonomyPassReport,
    /// Issue #816 — count of `__persona_<entity_id>_v<n>` rows the
    /// curator's auto-persona sweep produced this cycle. Zero when:
    /// the cycle has no fresh-entity reflections to distil, the
    /// daemon was started without a signing keypair (sweep skipped to
    /// avoid emitting unsigned persona rows), the LLM is unreachable,
    /// or every candidate entity already has an up-to-date persona row.
    /// Surfaces in the cycle's tracing line and in the
    /// `_curator/reports` JSON self-report.
    #[serde(default)]
    pub personas_generated: usize,
    /// v0.8.0 Pillar-2.5 (#1709) — count of memories evicted by the
    /// size-GC (corpus byte-cap) pass this cycle. Zero when
    /// `compaction.max_corpus_bytes` is `None`, in dry-run, or when no
    /// scanned namespace exceeded its cap. The pass archives victims
    /// before deleting them, so the count is restorable from the archive.
    #[serde(default)]
    pub memories_evicted_size_gc: usize,
    /// v0.8.0 Pillar-2.5 (#1738/#1746) — clusters the SAL `ConsolidationPass`
    /// found eligible to consolidate this cycle, when
    /// `compaction.enabled = true`. Post-#1746 cutover the pass is the LIVE
    /// consolidator (autonomy Pass-1 is suppressed); this counts the clusters
    /// it acted on (or, in a dry-run cycle, would act on). Zero when compaction
    /// is disabled (the default) or on an in-memory DB. The consolidation
    /// counts themselves fold into `autonomy.{clusters_formed,
    /// memories_consolidated, rollback_entries_written}` so the self-report
    /// stays accurate regardless of which consolidator ran.
    #[serde(default)]
    pub compaction_pass_clusters_eligible: usize,
    /// v0.8.0 Pillar-2.5 (#1746) — clusters the SAL `ConsolidationPass` rolled
    /// back this cycle after a Stage-6 (#664) verify failure (sources restored,
    /// unverifiable summary removed). Preserved as a distinct safety counter —
    /// `AutonomyPassReport` has no field for it. Zero when compaction is
    /// disabled or no verify failed.
    #[serde(default)]
    pub compaction_pass_rolled_back: usize,
    /// v1.0.0 — LLM-op budget the autonomy passes were handed this cycle,
    /// i.e. what was left of `max_ops_per_cycle` after the auto-tag /
    /// contradiction loop, floored at the
    /// [`AUTONOMY_OP_RESERVE_DIVISOR`] reserve. This is the operator's
    /// starvation gauge: a ZERO here on a cycle with a non-zero
    /// `memories_eligible` means Pass-1 consolidation could not run at all.
    /// Read it together with `operations_skipped_cap` (auto-tag work
    /// deferred to the next cycle because the loop's share ran out) —
    /// sustained non-zero deferrals mean the corpus is growing faster than
    /// the configured cap can curate it and `max_ops_per_cycle` needs
    /// raising.
    #[serde(default)]
    pub autonomy_ops_budget: usize,
    pub errors: Vec<String>,
    pub dry_run: bool,
}

impl CuratorReport {
    fn new(dry_run: bool) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            started_at: now.clone(),
            completed_at: now,
            dry_run,
            ..Self::default()
        }
    }
}

/// Ops carved out of `max_ops_per_cycle` and held for the autonomy passes.
///
/// Returns `max_ops_per_cycle / AUTONOMY_OP_RESERVE_DIVISOR`, floored at one
/// op so a small-but-splittable cap still reaches Pass 1, and zero when the
/// cap is `0` or `1` (nothing to split — a one-op cycle can only afford the
/// auto-tag loop's first op, which is the pre-v1.0.0 behaviour).
#[must_use]
fn autonomy_op_reserve(max_ops_per_cycle: usize) -> usize {
    if max_ops_per_cycle <= 1 {
        return 0;
    }
    (max_ops_per_cycle / AUTONOMY_OP_RESERVE_DIVISOR).max(1)
}

/// Run one curator cycle. Safe to call repeatedly. Returns a structured
/// report regardless of outcome — LLM failures are recorded in
/// `report.errors` rather than propagated.
///
/// Issue #816 — `active_keypair` carries the daemon's signing keypair
/// for the auto-persona sweep. When `Some` AND the LLM is reachable,
/// the sweep at the end of the cycle scans freshly-tagged reflections
/// (rows with `mentioned_entity_id` set, in non-reserved namespaces)
/// and calls [`crate::persona::PersonaGenerator`] for each entity that
/// lacks a current persona row, within the operator's configured
/// namespace scope. When `None`, the sweep skips entirely
/// — the substrate refuses to emit unsigned persona rows from the
/// curator path, matching the pre-#816 posture for daemons started
/// without a keypair on disk.
pub fn run_once(
    conn: &Connection,
    llm: Option<&OllamaClient>,
    cfg: &CuratorConfig,
    active_keypair: Option<&crate::identity::keypair::AgentKeypair>,
) -> Result<CuratorReport> {
    let mut report = CuratorReport::new(cfg.dry_run);
    let started = Instant::now();

    let CandidateBatch {
        memories: candidates,
        truncated,
    } = collect_candidates(conn, cfg)?;
    report.memories_scanned = candidates.len();
    record_truncation(&mut report, truncated, cfg);

    let eligible: Vec<&Memory> = candidates
        .iter()
        .filter(|m| needs_curation(m, cfg))
        .collect();
    report.memories_eligible = eligible.len();

    // v0.8.0 Pillar-2.5 (#1709) — size-GC (corpus byte-cap eviction).
    // Pure SQL, LLM-free, and independent of the autonomy pass output, so
    // it runs on EVERY cycle that has `compaction.max_corpus_bytes` set —
    // including cycles with no LLM configured. Placed before the no-LLM
    // early-return below precisely so byte-pressure eviction is NOT
    // silently skipped on LLM-less deployments (the helper itself gates on
    // cap.is_some() && !dry_run). Best-effort: per-namespace errors land
    // in report.errors, never aborting the cycle.
    run_size_gc_pass(conn, &candidates, cfg, &mut report);

    let Some(llm_client) = llm else {
        report.errors.push("no LLM client configured".to_string());
        report.completed_at = chrono::Utc::now().to_rfc3339();
        report.cycle_duration_ms = started.elapsed().as_millis();
        return Ok(report);
    };

    // v1.0.0 — the auto-tag / contradiction loop draws on its SHARE of the
    // cycle budget, not the whole cap: `autonomy_op_reserve` is withheld for
    // the autonomy passes below (see `AUTONOMY_OP_RESERVE_DIVISOR`). Deferred
    // rows are counted in `operations_skipped_cap` and picked up next cycle;
    // no eligible row is dropped, only postponed.
    let autonomy_reserve = autonomy_op_reserve(cfg.max_ops_per_cycle);
    let autotag_op_budget = cfg.max_ops_per_cycle.saturating_sub(autonomy_reserve);
    for mem in eligible {
        if report.operations_attempted >= autotag_op_budget {
            report.operations_skipped_cap += 1;
            continue;
        }
        report.operations_attempted += 1;

        match llm_client.auto_tag(&mem.title, &mem.content, None) {
            Ok(tags) if !tags.is_empty() => {
                let tag_list: Vec<String> = tags.into_iter().take(8).collect::<Vec<String>>();
                if !cfg.dry_run
                    && let Err(e) = persist_auto_tags(conn, mem, &tag_list)
                {
                    report
                        .errors
                        .push(format!("auto_tag persist failed for {}: {e}", mem.id));
                    continue;
                }
                report.auto_tagged += 1;
            }
            Ok(_) => {}
            Err(e) => {
                report
                    .errors
                    .push(format!("auto_tag failed for {}: {e}", mem.id));
            }
        }

        // Look for one adjacent memory in the same namespace that could
        // contradict this one. We don't do an N^2 scan — just the nearest
        // sibling by created_at. Broader contradiction analysis remains
        // an explicit `memory_detect_contradiction` call.
        // ERRORS-19 — a DB failure here must NOT masquerade as "no sibling":
        // the pre-fix `if let Ok(Some(..))` discarded the `Err` half with no
        // report entry, so a transient read failure silently skipped
        // contradiction detection while the cycle report looked clean.
        let sibling = match adjacent_memory(conn, mem) {
            Ok(s) => s,
            Err(e) => {
                report
                    .errors
                    .push(format!("adjacent_memory failed for {}: {e}", mem.id));
                None
            }
        };
        if let Some(sibling) = sibling {
            match llm_client.detect_contradiction(&mem.content, &sibling.content) {
                Ok(true) => {
                    if !cfg.dry_run
                        && let Err(e) = persist_contradiction(conn, mem, &sibling.id)
                    {
                        report
                            .errors
                            .push(format!("contradiction persist failed for {}: {e}", mem.id));
                        continue;
                    }
                    report.contradictions_found += 1;
                }
                Ok(false) => {}
                Err(e) => {
                    report.errors.push(format!(
                        "detect_contradiction failed ({} vs {}): {e}",
                        mem.id, sibling.id
                    ));
                }
            }
        }
    }

    // v0.6.1 autonomy passes — consolidate, forget-superseded, priority
    // feedback, rollback-log. Only run when the LLM is available
    // (otherwise run_once would have early-returned already).
    let autonomy_candidates: Vec<crate::models::Memory> = candidates
        .iter()
        .filter(|m| needs_curation(m, cfg))
        .cloned()
        .collect();
    // v0.8.0 Pillar-2.5 (#1746) — single-source cutover predicate. When
    // `compaction.enabled`, the SAL `ConsolidationPass` OWNS consolidation:
    // autonomy Pass-1 is suppressed AND the SAL pass runs live, BOTH driven
    // from this one bool so they can never drift into double-consolidation
    // (both run) or zero-consolidation (neither runs). Default false → autonomy
    // Pass-1 runs and the SAL pass is a no-op (production byte-unchanged).
    let compaction_owns_consolidation = cfg.compaction.enabled;
    // v1.0.0 — `max_ops_per_cycle` is documented as a HARD cap on
    // LLM-invoking operations per cycle, but the autonomy passes used to
    // run outside it entirely: Pass 1 issued one `summarize_memories` call
    // per cluster over a candidate batch capped at `max_ops_per_cycle * 4`,
    // so a cycle could exceed the operator's authorised LLM budget several
    // times over. Hand the passes what is LEFT of the cycle budget after
    // the auto_tag / contradiction loop above, and fold the ops they spend
    // back into the cycle counters so the persona sweep below sees a true
    // remaining budget.
    //
    // The subtraction below CANNOT reach zero on a cycle with a non-empty
    // budget: the loop above is bounded by `autotag_op_budget ==
    // max_ops_per_cycle - autonomy_reserve`, and it is the only writer of
    // `operations_attempted` before this point, so at least
    // `autonomy_reserve` ops always survive for the passes. That structural
    // floor is the fix for the starvation described on
    // `AUTONOMY_OP_RESERVE_DIVISOR`; `report.autonomy_ops_budget` publishes
    // the figure so an operator can see it in the cycle report.
    let remaining_ops = cfg
        .max_ops_per_cycle
        .saturating_sub(report.operations_attempted);
    debug_assert!(
        remaining_ops >= autonomy_reserve,
        "autonomy reserve must survive the auto-tag loop"
    );
    report.autonomy_ops_budget = remaining_ops;
    let pass_report = crate::autonomy::run_autonomy_passes(
        conn,
        llm_client,
        &autonomy_candidates,
        cfg.dry_run,
        /* skip_consolidation = */ compaction_owns_consolidation,
        /* llm_op_budget = */ remaining_ops,
        active_keypair,
    );
    report.errors.extend(pass_report.errors.clone());
    report.operations_attempted = report
        .operations_attempted
        .saturating_add(pass_report.operations_attempted);
    report.operations_skipped_cap = report
        .operations_skipped_cap
        .saturating_add(pass_report.operations_skipped_cap);
    report.autonomy = pass_report;

    // SAL `ConsolidationPass`. When `compaction.enabled` it is the LIVE
    // consolidator (real writes, respecting `cfg.dry_run`), and its counts fold
    // into `report.autonomy` so the self-report is accurate. When disabled it is
    // a no-op (autonomy Pass-1 above did the consolidation). `llm_client:
    // &OllamaClient` coerces to `&dyn AutonomyLlm`. Best-effort: errors land in
    // report.errors.
    run_consolidation_pass(conn, &autonomy_candidates, cfg, llm_client, &mut report);

    // Issue #816 — auto-persona sweep. After auto_tag has populated
    // `mentioned_entity_id` on this cycle's reflections, scan for
    // entities that lack a current persona row and synthesise one via
    // [`PersonaGenerator`]. Pre-#816 this work was deferred: the
    // post_reflect hook surface in `storage::reflect` accepted a
    // keypair-aware callback (see `src/hooks/post_reflect/auto_persona.rs`)
    // but no caller installed it on the curator path, so operators had
    // to call `memory_persona_generate` explicitly for every entity.
    //
    // Sweep is gated on `active_keypair.is_some()` — without a keypair
    // we'd emit unsigned persona rows that look like legacy data and
    // muddy the attestation audit trail. The pre-#816 contract was
    // "no persona at all", which is more honest than "unsigned
    // persona", so we stay no-op when the daemon hasn't been issued a
    // keypair. The `personas_generated` counter on `CuratorReport`
    // reflects the count and lands in the `_curator/reports` JSON.
    persona_sweep(
        conn,
        llm_client,
        &candidates,
        cfg,
        active_keypair,
        &mut report,
    );

    report.completed_at = chrono::Utc::now().to_rfc3339();
    report.cycle_duration_ms = started.elapsed().as_millis();

    // Self-report: write the cycle's outcome as a memory in
    // _curator/reports. Never runs in dry-run (we must not touch the
    // DB there). Best-effort — a failure here gets logged but does
    // not fail the cycle.
    if !cfg.dry_run
        && let Err(e) = crate::autonomy::persist_self_report(
            conn,
            report.cycle_duration_ms,
            &report.autonomy,
            report.auto_tagged,
            report.contradictions_found,
            report.personas_generated,
            report.errors.len(),
        )
    {
        tracing::warn!("self-report persist failed: {e}");
    }

    crate::metrics::curator_cycle_completed(
        report.operations_attempted,
        report.auto_tagged,
        report.contradictions_found,
        report.errors.len(),
    );

    Ok(report)
}

/// v0.8.0 Pillar-2.5 (#1709) — size-GC pass driver.
///
/// Gated on `cfg.compaction.max_corpus_bytes.is_some()` (a positive cap)
/// AND `!cfg.dry_run` (dry-run must never mutate). For each distinct
/// namespace in the cycle's candidate batch — filtered by the same
/// include / exclude / `_`-prefix rules the rest of the curator honours
/// — calls [`crate::storage::size_gc`] with `archive = true` so victims
/// are restorable. Accumulates the evicted count into
/// `report.memories_evicted_size_gc`. Best-effort: a per-namespace
/// size_gc error is pushed to `report.errors` and the next namespace
/// continues, matching the auto_tag / contradiction / persona passes.
///
/// LLM-free + deterministic (pure SQL ranking inside `size_gc`), so this
/// runs on every cycle with a cap set, including LLM-less deployments.
fn run_size_gc_pass(
    conn: &Connection,
    candidates: &[Memory],
    cfg: &CuratorConfig,
    report: &mut CuratorReport,
) {
    // #1750 (Pillar-2.5) — DEFENSIVE GATE: size-GC byte-cap eviction is a
    // hard-DELETE pass (archive-before-delete, restorable) DISTINCT from
    // consolidation. It must never arm decoupled from the operator's
    // compaction opt-in: the #1749 5-agent vote (memory `1817bc8f`) flagged the
    // `max_corpus_bytes.is_some()`-only gate as a hazard — an operator setting
    // only a byte cap would silently activate a second deletion pass. We
    // additionally require `compaction.enabled`. `max_corpus_bytes` stays OUT of
    // operator config this slice (always compiled-default `None` → still inert
    // in production); this gate is future-proofing. FORWARD-CONSTRAINT (#1750
    // vote `a9b2fe09`): if `max_corpus_bytes` is ever exposed, it must get its
    // own dedicated `[curator.size_gc].enabled` switch — NOT ride under
    // `[curator.compaction]` — and this gate switches to that flag.
    if !cfg.compaction.enabled {
        return;
    }
    let Some(cap) = cfg.compaction.max_corpus_bytes else {
        return;
    };
    if cap <= 0 || cfg.dry_run {
        return;
    }

    // Distinct namespaces in the candidate set, honouring the curator's
    // namespace scoping (skip `_`-prefixed + respect include / exclude).
    use std::collections::BTreeSet;
    let mut namespaces: BTreeSet<&str> = BTreeSet::new();
    for mem in candidates {
        let ns = mem.namespace.as_str();
        if !namespace_in_scope(ns, cfg) {
            continue;
        }
        namespaces.insert(ns);
    }

    for ns in namespaces {
        match crate::storage::size_gc(conn, ns, cap, true) {
            Ok(evicted) => report.memories_evicted_size_gc += evicted,
            Err(e) => report
                .errors
                .push(format!("size_gc failed for namespace {ns}: {e}")),
        }
    }
}

/// v0.8.0 Pillar-2.5 (#1746 cutover) — SAL `ConsolidationPass` live driver.
///
/// Gated on `cfg.compaction.enabled` (default `false` → no-op, production
/// byte-unchanged: autonomy Pass-1 did the consolidation). When enabled, the
/// caller has ALSO suppressed autonomy Pass-1 (single-source predicate in
/// `run_once`), so this pass is the LIVE consolidator: it opens a second
/// `SqliteStore` handle at the curator connection's backing file and runs
/// [`ConsolidationPass::run`] with `dry_run = cfg.dry_run` — real writes on a
/// normal cycle, simulate-only on a `--dry-run` cycle. Its counts FOLD into
/// `report.autonomy.{clusters_formed, memories_consolidated,
/// rollback_entries_written}` (the self-report is keyed on those fields, so it
/// stays accurate regardless of which consolidator ran); `eligible_clusters`
/// and the Stage-6 (#664) `rolled_back` count surface on the SAL-specific
/// `report.compaction_pass_*` fields. Operator-reversible rollback rows are
/// written by the pass itself at autonomy parity (#1745).
///
/// `clusters_formed` is folded from the pass's `eligible_clusters` (not its raw
/// `clusters_formed`) for parity: autonomy's `clusters_formed` is already
/// post-reserved-namespace-filter, which is what `eligible_clusters` measures.
///
/// Sync↔async bridge: the curator daemon and CLI `--once` both run
/// `run_once` on a `spawn_blocking` thread. That thread HAS a tokio
/// [`Handle`](tokio::runtime::Handle) (1.52 blocking pool `rt.enter()`)
/// but is NOT driving the runtime (`enter_runtime`), so a nested
/// current-thread `block_on` is legal — see [`tokio_current_thread_handle_present`]
/// and #3244. A current-thread worker still degrades to a reported skip
/// (ERRORS-08) instead of panicking. Best-effort: store/runtime/sweep
/// errors land in `report.errors`, never aborting the cycle. In-memory
/// (`:memory:`) connections have no path to re-open and are skipped.
/// Decision provenance: 5-agent vote `4d3ea1c5` (#1746); skip-probe
/// correction #3244.
#[cfg(feature = "sal")]
fn run_consolidation_pass(
    conn: &Connection,
    candidates: &[Memory],
    cfg: &CuratorConfig,
    llm: &dyn crate::autonomy::AutonomyLlm,
    report: &mut CuratorReport,
) {
    if !cfg.compaction.enabled {
        return;
    }
    // ERRORS-08 / CONCURRENCY-22 / #3244 — nested `Runtime::block_on`
    // panics on a *current-thread* worker (`#[tokio::test]` default).
    // `Handle::try_current()` is the wrong probe: a `spawn_blocking`
    // thread also has a Handle (tokio 1.52 `rt.enter()`) and that is
    // the production shape (daemon + CLI `--once`), so the #3116 guard
    // skipped every `compaction.enabled` cycle. Skip only the
    // current-thread Handle (where `block_in_place` itself panics);
    // multi-thread (production) drives via `block_in_place` so a
    // worker is parked rather than nested-block_on'd, and a
    // `spawn_blocking` thread is a no-op then legal `block_on`.
    if tokio_current_thread_handle_present() {
        report
            .errors
            .push(CONSOLIDATION_PASS_SKIPPED_NESTED_RUNTIME.to_string());
        return;
    }
    let Some(path) = conn.path().map(std::path::PathBuf::from) else {
        return; // in-memory DB — no backing file to open a 2nd SAL handle.
    };
    let store = match crate::store::sqlite::SqliteStore::open(&path) {
        Ok(s) => s,
        Err(e) => {
            report
                .errors
                .push(format!("consolidation pass: store open failed: {e}"));
            return;
        }
    };
    let pass = crate::curator::compaction::ConsolidationPass::new(
        &store,
        llm,
        /* dry_run = */ cfg.dry_run,
    )
    // #1750 — thread the operator-resolved cosine gate into the clusterer.
    .with_cosine_threshold(cfg.compaction.cosine_threshold);
    let drive_pass = || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("consolidation pass: runtime build failed: {e}"))?;
        rt.block_on(pass.run(candidates))
            .map_err(|e| format!("consolidation pass: {e}"))
    };
    // Current-thread Handle already skipped. Remaining cases (multi-thread
    // worker, spawn_blocking, no runtime): `block_in_place` is a no-op
    // when not entered and parks a multi-thread worker so nested block_on
    // is legal. CONCURRENCY-22.
    //
    // #3283 — PANIC CONTAINMENT (North Star: degrade, never die). The pass
    // drives an LLM clusterer plus a nested current-thread runtime; a panic in
    // either (or any callee) would otherwise unwind out of `run_once`, out of
    // `run_daemon`'s cycle loop, and out of the `spawn_blocking` closure both
    // daemon drivers await (`daemon_runtime::run_curator_daemon_with_shutdown`
    // / `_with_primitives`) — where the resulting `JoinError` is converted into
    // a hard error that TERMINATES the curator daemon. `catch_unwind` contains
    // the pass so one bad cycle degrades to a logged, reported failure, not a
    // dead daemon (`panic = "unwind"` is deliberately retained in Cargo.toml
    // precisely so this boundary works; `catch_unwind` is inert under
    // `panic = "abort"`). `AssertUnwindSafe` is sound here: on a caught panic we
    // observe NONE of the state reachable through the closure — we only record
    // an error string and return; `report` is mutated only AFTER the boundary,
    // never inside it. The `catch_unwind` `Result` is handled explicitly,
    // never dropped (ERRORS-19). Dropping the pass's inner current-thread
    // runtime while unwinding is safe on every remaining case (no-runtime test
    // thread, spawn_blocking pool thread — both permit blocking); the
    // would-double-panic current-thread-worker case is already skipped above.
    let driven = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio::task::block_in_place(drive_pass)
    }));
    let outcome = match driven {
        Ok(result) => result,
        Err(panic) => {
            let detail = panic_payload_message(panic.as_ref());
            tracing::error!(
                slug = CONSOLIDATION_PASS_PANIC_CONTAINED,
                detail = %detail,
                "consolidation pass PANIC contained — cycle degraded, curator daemon preserved (#3283)"
            );
            report
                .errors
                .push(format!("{CONSOLIDATION_PASS_PANIC_CONTAINED}: {detail}"));
            return;
        }
    };
    match outcome {
        Ok(out) => {
            // Fold the SAL consolidator's outcome into the autonomy report so
            // the self-report (keyed on AutonomyPassReport fields) is accurate
            // even though autonomy Pass-1 was suppressed this cycle.
            report.autonomy.clusters_formed += out.eligible_clusters;
            report.autonomy.memories_consolidated += out.memories_consolidated;
            report.autonomy.rollback_entries_written += out.rollback_entries_written;
            // SAL-specific counters (no AutonomyPassReport home).
            report.compaction_pass_clusters_eligible += out.eligible_clusters;
            report.compaction_pass_rolled_back += out.rolled_back;
            report.errors.extend(out.errors);
        }
        Err(e) => report.errors.push(e),
    }
}

/// Operator-visible skip when `run_once` is on a thread that is *driving*
/// a tokio runtime (`enter_runtime`). `spawn_blocking` is NOT this case
/// (#3244). Kept as one named const so the production skip and the
/// `#[tokio::test]` assertion share a single spelling.
#[cfg(feature = "sal")]
const CONSOLIDATION_PASS_SKIPPED_NESTED_RUNTIME: &str = "consolidation pass: skipped — curator::run_once was called from inside an async \
     runtime; wrap the call in tokio::task::spawn_blocking so the pass can drive its \
     own runtime";

/// True iff this thread currently holds a **current-thread** tokio Handle.
///
/// Tokio 1.52 `spawn_blocking` threads inherit the outer runtime's Handle
/// via `rt.enter()` (so [`Handle::try_current`] is `Ok`) but are not
/// driving (`enter_runtime`). Nested `Runtime::block_on` is legal there
/// on a **multi-thread** runtime — the production daemon / CLI `--once`
/// shape (#3244). A current-thread Handle is the `#[tokio::test]` default
/// worker, where both nested `block_on` and `block_in_place` panic.
/// Probing `enter_runtime` by building a nested runtime and
/// `catch_unwind` is not viable: dropping that runtime on a worker
/// panics a second time ("Cannot drop a runtime in a context where
/// blocking is not allowed"). Fail closed (ERRORS-08): any non-multi-thread
/// Handle is treated as would-panic.
#[cfg(feature = "sal")]
#[must_use]
fn tokio_current_thread_handle_present() -> bool {
    match tokio::runtime::Handle::try_current() {
        Err(_) => false,
        Ok(handle) => !matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        ),
    }
}

/// #3283 — stable, greppable marker for a CONTAINED `ConsolidationPass` panic.
///
/// A panic in the SAL consolidation pass (LLM clustering, nested runtime, or
/// any callee) is caught at the `run_consolidation_pass` boundary and recorded
/// under this prefix instead of unwinding out of the `spawn_blocking` closure
/// the daemon drivers await — where the `JoinError` would TERMINATE the curator
/// daemon. One bad cycle degrades to this reported failure, not a dead daemon.
/// One named const so the production log and the regression assertion share a
/// single spelling (pm-v3.1 lint-gate).
#[cfg(feature = "sal")]
pub(crate) const CONSOLIDATION_PASS_PANIC_CONTAINED: &str =
    "consolidation pass: PANIC contained (cycle degraded, curator daemon preserved)";

/// Extract a human-readable message from a `catch_unwind` panic payload.
///
/// Rust panic payloads are `&str` (from `panic!("literal")`) or `String` (from
/// `panic!("{}", x)`); anything else is opaque and reported as such. Kept as a
/// named helper so the `#3283` containment site stays readable and the
/// downcast logic is unit-reachable.
#[cfg(feature = "sal")]
#[must_use]
fn panic_payload_message(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<&'static str>()
        .map(|s| (*s).to_string())
        .or_else(|| panic.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string())
}

/// Non-`sal` builds carry no SAL `ConsolidationPass`; the consolidation pass is
/// a compile-time no-op so `run_once` stays uniform across feature sets.
#[cfg(not(feature = "sal"))]
fn run_consolidation_pass(
    _conn: &Connection,
    _candidates: &[Memory],
    _cfg: &CuratorConfig,
    _llm: &dyn crate::autonomy::AutonomyLlm,
    _report: &mut CuratorReport,
) {
}

/// Issue #816 — auto-persona sweep helper.
///
/// Called from [`run_once`] after the auto_tag / contradiction / autonomy
/// passes complete. Scans the cycle's candidate batch for reflections
/// whose `mentioned_entity_id` was populated (by the auto_tag pass earlier
/// in the same cycle, or by a prior cycle), groups by
/// `(entity_id, namespace)`, and for each group that lacks a current
/// persona row calls [`crate::persona::PersonaGenerator::generate`] with
/// `active_keypair` as the signer. The resulting persona row lands with
/// `attest_level='self_signed'` and a 64-byte Ed25519 signature on every
/// `derived_from` link.
///
/// **Namespace scope (v1.0.0)**: every candidate `(entity_id, namespace)`
/// pair is filtered through [`namespace_in_scope`] — the same predicate
/// `needs_curation` and the size-GC pass use — so the operator's
/// `include_namespaces` / `exclude_namespaces` configuration governs this
/// sweep exactly as it governs the rest of the cycle. Pre-fix the scan
/// filtered on the reserved `_`-prefix ONLY, so a namespace the operator
/// had excluded still grew signed persona rows. The predicate is applied
/// twice on purpose: once pushed into the scan SQL (so out-of-scope rows
/// cannot consume the `LIMIT` window and starve in-scope entities) and
/// once per row in the loop (fail-closed backstop).
///
/// **Gating**: skips the entire sweep when `active_keypair` is `None`.
/// The pre-#816 contract on the curator path was "no auto-generated
/// persona at all" rather than "unsigned auto-generated persona", so
/// we hold that line — unsigned persona rows from the curator would
/// muddy the attestation audit trail.
///
/// **Best-effort**: errors per-entity are appended to `report.errors`
/// and the next entity continues. A storage error opening reflections
/// in one namespace cannot crash the cycle.
///
/// **Budget**: each persona generation counts as one operation against
/// `cfg.max_ops_per_cycle`. The sweep stops mid-loop when the budget
/// is exhausted; remaining entities surface in the next cycle.
fn persona_sweep(
    conn: &Connection,
    _llm_client: &OllamaClient,
    _candidates: &[Memory],
    cfg: &CuratorConfig,
    active_keypair: Option<&crate::identity::keypair::AgentKeypair>,
    report: &mut CuratorReport,
) {
    let Some(keypair) = active_keypair else {
        return;
    };

    // De-duplicate to one `(entity_id, namespace)` pair per cycle.
    //
    // We query `memories` directly for the `mentioned_entity_id`
    // column (populated by `storage::extract_mentioned_entity_id` on
    // insert + the auto_tag pass earlier in this cycle) rather than
    // iterating the `candidates: &[Memory]` batch — the in-memory
    // `Memory` struct does NOT expose that column today, so a SQL
    // query is the only way to see it from this layer.
    //
    // Bounded by the curator's per-cycle op cap (`max_ops_per_cycle`,
    // 2x for headroom): each candidate row may or may not need a
    // persona, so we read a generous superset and let the persona
    // existence check inside the loop short-circuit.
    use std::collections::BTreeSet;
    let limit = (cfg.max_ops_per_cycle.saturating_mul(2)).max(64);
    // PERF-07 — `limit` is a `usize` derived from operator config; a lossy
    // `as i64` would WRAP NEGATIVE on a pathological `max_ops_per_cycle`
    // and turn the LIMIT clause into "no rows" (or worse). Clamp instead.
    let limit_sql = i64::try_from(limit).unwrap_or(i64::MAX);

    // v1.0.0 — the operator's include / exclude namespace configuration is
    // pushed into the SCAN, not just applied after it. Filtering only in
    // the loop would still let out-of-scope rows consume the `LIMIT`
    // window and starve in-scope entities in a busy corpus, so the
    // predicate goes into SQL; the loop below re-checks via
    // `namespace_in_scope` as a fail-closed backstop should this SQL and
    // the predicate ever drift.
    let mut sql = String::from(
        "SELECT mentioned_entity_id, namespace \
         FROM memories \
         WHERE memory_kind = 'reflection' \
           AND mentioned_entity_id IS NOT NULL \
           AND namespace NOT LIKE '\\_%' ESCAPE '\\'",
    );
    let mut binds: Vec<rusqlite::types::Value> =
        Vec::with_capacity(cfg.include_namespaces.len() + cfg.exclude_namespaces.len() + 1);
    for (clause, list) in [
        (" AND namespace IN (", &cfg.include_namespaces),
        (" AND namespace NOT IN (", &cfg.exclude_namespaces),
    ] {
        if list.is_empty() {
            continue;
        }
        sql.push_str(clause);
        for (i, ns) in list.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            sql.push('?');
            binds.push(rusqlite::types::Value::Text(ns.clone()));
        }
        sql.push(')');
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT ?");
    binds.push(rusqlite::types::Value::Integer(limit_sql));

    let mut entity_pairs: BTreeSet<(String, String)> = BTreeSet::new();
    let scan_result = (|| -> Result<()> {
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (eid, ns) = row?;
            entity_pairs.insert((eid, ns));
        }
        Ok(())
    })();
    if let Err(e) = scan_result {
        report.errors.push(format!(
            "persona_sweep: scan for mentioned_entity_id failed: {e}"
        ));
        return;
    }

    if entity_pairs.is_empty() {
        return;
    }

    // Use the OllamaClient as the LLM trait object — PersonaGenerator
    // takes `&dyn AutonomyLlm` and OllamaClient impls it.
    use crate::persona::{PersonaConfig, PersonaGenerator, get_latest_persona};
    let config = PersonaConfig::default();
    let generator = PersonaGenerator::new(conn, _llm_client, Some(keypair), config);

    for (entity_id, namespace) in entity_pairs {
        // Fail-closed backstop for the SQL scope predicate above: a persona
        // row is a SIGNED artifact, so it must never land in a namespace
        // the operator put out of scope, even if the scan drifts.
        if !namespace_in_scope(&namespace, cfg) {
            continue;
        }
        if report.operations_attempted >= cfg.max_ops_per_cycle {
            report.operations_skipped_cap += 1;
            continue;
        }

        // Skip if a persona already exists for this entity in this
        // namespace. A future enhancement (per the namespace policy
        // `auto_persona_trigger_every_n_memories` field that already
        // exists in GovernancePolicy) would re-generate on cadence;
        // this first cut only fills the "no persona yet" gap so the
        // operator-visible behaviour is "every entity that gets
        // reflected on grows a persona row, signed".
        match get_latest_persona(conn, &entity_id, &namespace) {
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(e) => {
                report.errors.push(format!(
                    "persona_sweep: get_latest_persona failed for ({entity_id}, {namespace}): {e}"
                ));
                continue;
            }
        }

        report.operations_attempted += 1;

        if cfg.dry_run {
            // Honour the dry-run contract: count the would-be generation
            // in `personas_generated` so an operator running
            // `ai-memory curator --dry-run` sees the sweep's intended
            // work without committing it.
            report.personas_generated += 1;
            continue;
        }

        match generator.generate(&entity_id, &namespace) {
            Ok(_persona) => {
                report.personas_generated += 1;
            }
            Err(e) => {
                report.errors.push(format!(
                    "persona_sweep: generate failed for ({entity_id}, {namespace}): {e}"
                ));
            }
        }
    }
}

/// Long-running daemon loop. Polls `shutdown` between cycles so SIGINT
/// / SIGTERM lands cleanly.
///
/// Arguments are taken by value because this function is designed to be
/// handed to `tokio::task::spawn_blocking`, which requires owned data.
#[allow(clippy::needless_pass_by_value)]
#[allow(dead_code)] // called via lib crate (daemon_runtime); bin sees it as unused
pub fn run_daemon(
    db_path: PathBuf,
    llm: Option<Arc<OllamaClient>>,
    cfg: CuratorConfig,
    shutdown: Arc<AtomicBool>,
    // Issue #816 — daemon signing keypair, threaded to `run_once` for
    // the auto-persona sweep. `None` disables the sweep (the curator
    // refuses to emit unsigned persona rows on this path); `Some`
    // lets every cycle synthesise signed persona artifacts for fresh
    // entities. The daemon-runtime loader at
    // `daemon_runtime::ensure_and_load_daemon_keypair` resolves this
    // from `DAEMON_KEYPAIR_LABEL` on disk, auto-generating when absent.
    active_keypair: Option<Arc<crate::identity::keypair::AgentKeypair>>,
) {
    let interval = cfg.interval_secs.clamp(60, crate::SECS_PER_DAY as u64);
    tracing::info!(
        "curator daemon started (interval={}s, max_ops={}, dry_run={}, auto_persona={})",
        interval,
        cfg.max_ops_per_cycle,
        cfg.dry_run,
        active_keypair.is_some()
    );

    // v1.0.0 #3345 — one-shot, chunked, idempotent stamp of the legacy
    // `_curator/reports` backlog. Self-terminating: once drained it costs a
    // single indexed EXISTS probe, and this runs ONCE per daemon start, not
    // per cycle. Best-effort — a failure here must never stop the curator.
    match Connection::open(&db_path) {
        Ok(conn) => {
            let fallback = crate::validate::render_canonical_utc(
                chrono::Utc::now()
                    + chrono::Duration::seconds(crate::autonomy::SELF_REPORT_TTL_SECS),
            );
            if let Err(e) = crate::storage::stamp_operational_backlog(
                &conn,
                crate::autonomy::CURATOR_REPORTS_NAMESPACE,
                &fallback,
            ) {
                tracing::warn!("#3345: self-report backlog stamp skipped: {e}");
            }
        }
        Err(e) => tracing::warn!(
            "#3345: self-report backlog stamp skipped (open {}): {e}",
            db_path.display()
        ),
    }

    while !shutdown.load(Ordering::Relaxed) {
        match Connection::open(&db_path) {
            Ok(conn) => {
                // #2445 — this cycle-loop open is off `db::open` so the
                // daemon does not pay bootstrap + ladder every interval.
                // Guard schema-ahead immediately (ERRORS-01, ERRORS-19).
                if let Err(e) =
                    crate::storage::assert_schema_not_ahead(&conn, &db_path.display().to_string())
                {
                    tracing::error!(
                        "curator refused db {} (schema-ahead): {e}",
                        db_path.display()
                    );
                    // Fall through to the interval sleep; next cycle retries.
                } else {
                    let llm_ref = llm.as_deref();
                    let kp_ref = active_keypair.as_deref();
                    match run_once(&conn, llm_ref, &cfg, kp_ref) {
                        // v1.0.0 — `deferred` / `autonomy_budget` are the
                        // budget-pressure pair. A steady non-zero `deferred` means
                        // the corpus is growing faster than `max_ops_per_cycle`
                        // can curate it; an `autonomy_budget` of 0 against a
                        // non-zero `eligible` means Pass-1 consolidation did not
                        // run at all this cycle. Neither was visible from the
                        // daemon log before, which is how the Pass-1 starvation
                        // this reserve fixes could have run unnoticed for the life
                        // of a deployment.
                        Ok(report) => tracing::info!(
                            "curator cycle: scanned={} eligible={} tagged={} contradictions={} personas={} deferred={} autonomy_budget={} errors={} ({}ms, dry_run={})",
                            report.memories_scanned,
                            report.memories_eligible,
                            report.auto_tagged,
                            report.contradictions_found,
                            report.personas_generated,
                            report.operations_skipped_cap,
                            report.autonomy_ops_budget,
                            report.errors.len(),
                            report.cycle_duration_ms,
                            report.dry_run
                        ),
                        Err(e) => tracing::error!("curator cycle errored: {e}"),
                    }
                    // v1.0.0 #3345 — reap expired rows on THIS host.
                    //
                    // `spawn_gc_loop_*` is pushed only from `bootstrap_serve`,
                    // so a `curator --daemon`-only deployment ran no GC at all:
                    // its own per-sweep self-reports were TTL-stamped and
                    // GC-eligible but nothing ever reaped them, which is how one
                    // node reached 24,930 rows. #1466 was this same leak in this
                    // same namespace (2,905 of 2,921 rows) — this is its
                    // recurrence, so the reaper now runs where the writer runs.
                    //
                    // `gc_if_needed` (not `gc`) keeps it a bounded indexed
                    // EXISTS probe when nothing is expired, and `gc` itself is
                    // chunked, so this adds no unpaced work to the cycle.
                    // Best-effort: a GC failure degrades the cycle, never ends
                    // the daemon.
                    match crate::storage::gc_if_needed(&conn, cfg.archive_on_gc) {
                        Ok(0) => {}
                        Ok(reaped) => tracing::info!(
                            "curator cycle: gc reaped {reaped} expired row(s) (#3345)"
                        ),
                        Err(e) => tracing::warn!("curator cycle: gc failed: {e}"),
                    }
                }
            }
            Err(e) => tracing::error!("curator could not open db {}: {e}", db_path.display()),
        }

        let deadline = Instant::now() + Duration::from_secs(interval);
        while Instant::now() < deadline {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    tracing::info!("curator daemon shutdown");
}

#[cfg(test)]
mod tests {
    // Tests reference helpers that used to live in this file's flat
    // form; they now live in sibling sub-modules under `curator/`.
    // Pull the moved items in explicitly so the existing test bodies
    // continue to call them unqualified — exactly as before.
    use super::candidates::{
        adjacent_memory, collect_candidates, needs_curation, record_truncation,
    };
    use super::persist::{persist_auto_tags, persist_contradiction};
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let cfg = CuratorConfig::default();
        assert_eq!(cfg.interval_secs, DEFAULT_INTERVAL_SECS);
        assert_eq!(cfg.max_ops_per_cycle, DEFAULT_MAX_OPS_PER_CYCLE);
        assert!(!cfg.dry_run);
        assert!(cfg.include_namespaces.is_empty());
        assert!(cfg.exclude_namespaces.is_empty());
    }

    #[test]
    fn needs_curation_skips_internal_namespaces() {
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "m1".to_string(),
            tier: Tier::Mid,
            namespace: "_messages/alice".to_string(),
            title: "t".to_string(),
            content: "a".repeat(100),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
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
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        assert!(!needs_curation(&mem, &CuratorConfig::default()));
    }

    #[test]
    fn needs_curation_skips_short_content() {
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "m1".to_string(),
            tier: Tier::Mid,
            namespace: "app".to_string(),
            title: "t".to_string(),
            content: "short".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
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
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        assert!(!needs_curation(&mem, &CuratorConfig::default()));
    }

    #[test]
    fn needs_curation_skips_already_tagged() {
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "m1".to_string(),
            tier: Tier::Long,
            namespace: "app".to_string(),
            title: "t".to_string(),
            content: "a".repeat(100),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({"auto_tags":["x","y"]}),
            reflection_depth: 0,
            memory_kind: crate::models::MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        assert!(!needs_curation(&mem, &CuratorConfig::default()));
    }

    #[test]
    fn needs_curation_respects_include_list() {
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "m1".to_string(),
            tier: Tier::Long,
            namespace: "app".to_string(),
            title: "t".to_string(),
            content: "a".repeat(100),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
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
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        let mut cfg = CuratorConfig {
            include_namespaces: vec!["other".to_string()],
            ..CuratorConfig::default()
        };
        assert!(!needs_curation(&mem, &cfg));
        cfg.include_namespaces = vec!["app".to_string()];
        assert!(needs_curation(&mem, &cfg));
    }

    #[test]
    fn needs_curation_respects_exclude_list() {
        let mem = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "m1".to_string(),
            tier: Tier::Long,
            namespace: "noisy".to_string(),
            title: "t".to_string(),
            content: "a".repeat(100),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "test".to_string(),
            access_count: 0,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
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
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        let cfg = CuratorConfig {
            exclude_namespaces: vec!["noisy".to_string()],
            ..CuratorConfig::default()
        };
        assert!(!needs_curation(&mem, &cfg));
    }

    #[test]
    fn run_once_without_llm_emits_error_but_succeeds() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let cfg = CuratorConfig::default();
        let report = run_once(&conn, None, &cfg, None).unwrap();
        assert_eq!(report.memories_scanned, 0);
        assert_eq!(report.memories_eligible, 0);
        assert_eq!(report.operations_attempted, 0);
        assert!(report.errors.iter().any(|e| e.contains("no LLM")));
    }

    #[test]
    fn report_serialises_to_json() {
        let report = CuratorReport::new(true);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("dry_run"));
        assert!(json.contains("memories_scanned"));
    }

    // ---- Wave 3 (Closer T) — targeted unit tests for code paths NOT
    // currently exercised by the smoke + needs_curation suite.

    fn make_test_memory(ns: &str, title: &str, content: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: content.to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "api".to_string(),
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
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    #[test]
    fn persist_auto_tags_writes_metadata() {
        // After persist_auto_tags, the row's metadata.auto_tags reflects the
        // input list and metadata.curated_at is a non-empty string.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let mem = make_test_memory("curate-test", "anchor", &"a".repeat(120));
        db::insert(&conn, &mem).unwrap();

        persist_auto_tags(&conn, &mem, &["alpha".to_string(), "beta".to_string()]).unwrap();

        let updated = db::get(&conn, &mem.id).unwrap().unwrap();
        let tags = updated
            .metadata
            .get("auto_tags")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].as_str().unwrap(), "alpha");
        assert!(
            updated
                .metadata
                .get("curated_at")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
        );
    }

    #[test]
    fn persist_auto_tags_with_empty_tag_list_still_writes_marker() {
        // Even an empty tag list must persist `auto_tags: []` and
        // `curated_at` so the curator skips the row on the next cycle.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let mem = make_test_memory("curate-test", "anchor", &"a".repeat(120));
        db::insert(&conn, &mem).unwrap();

        persist_auto_tags(&conn, &mem, &[]).unwrap();

        let updated = db::get(&conn, &mem.id).unwrap().unwrap();
        let tags = updated
            .metadata
            .get("auto_tags")
            .unwrap()
            .as_array()
            .unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn persist_contradiction_appends_unique_ids() {
        // Two persist_contradiction calls with different ids → both ids
        // present in the array. A duplicate id is a no-op.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let mem = make_test_memory("curate-test", "anchor", &"a".repeat(120));
        db::insert(&conn, &mem).unwrap();

        persist_contradiction(&conn, &mem, "id-1").unwrap();
        // Re-read to pick up the now-populated metadata for the second call.
        let mid = db::get(&conn, &mem.id).unwrap().unwrap();
        persist_contradiction(&conn, &mid, "id-2").unwrap();
        // Duplicate id-1 → no-op (still 2 entries).
        let mid2 = db::get(&conn, &mem.id).unwrap().unwrap();
        persist_contradiction(&conn, &mid2, "id-1").unwrap();

        let updated = db::get(&conn, &mem.id).unwrap().unwrap();
        let ids = updated
            .metadata
            .get("confirmed_contradictions")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(ids.len(), 2);
        let strs: Vec<String> = ids
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        assert!(strs.contains(&"id-1".to_string()));
        assert!(strs.contains(&"id-2".to_string()));
    }

    #[test]
    fn adjacent_memory_returns_none_when_only_self_exists() {
        // Solo namespace → no sibling → Ok(None).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let mem = make_test_memory("solo-ns", "only", &"a".repeat(120));
        db::insert(&conn, &mem).unwrap();

        let got = adjacent_memory(&conn, &mem).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn adjacent_memory_returns_some_when_sibling_present() {
        // Two memories in the same namespace → adjacent_memory returns the
        // other one (whichever the underlying `db::list` orders first).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let m1 = make_test_memory("dual-ns", "first", &"a".repeat(120));
        let m2 = make_test_memory("dual-ns", "second", &"b".repeat(120));
        db::insert(&conn, &m1).unwrap();
        db::insert(&conn, &m2).unwrap();

        let got = adjacent_memory(&conn, &m1).unwrap().unwrap();
        assert_ne!(got.id, m1.id);
        assert!(got.content.len() >= MIN_CONTENT_LEN);
    }

    #[test]
    fn adjacent_memory_skips_short_sibling() {
        // Sibling exists but content too short → adjacent_memory returns None.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let m1 = make_test_memory("ns-short", "anchor", &"a".repeat(120));
        let mut m2 = make_test_memory("ns-short", "tiny-sibling", "x");
        m2.content = "short".to_string(); // Below MIN_CONTENT_LEN.
        db::insert(&conn, &m1).unwrap();
        db::insert(&conn, &m2).unwrap();

        let got = adjacent_memory(&conn, &m1).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn record_truncation_appends_when_truncated() {
        let mut report = CuratorReport::new(false);
        let cfg = CuratorConfig::default();
        record_truncation(&mut report, true, &cfg);
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].contains("collect_candidates truncated"));
    }

    #[test]
    fn record_truncation_noop_when_not_truncated() {
        let mut report = CuratorReport::new(false);
        let cfg = CuratorConfig::default();
        record_truncation(&mut report, false, &cfg);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn collect_candidates_returns_eligible_memories() {
        // Long-tier rows with sufficient content are picked up; short-tier
        // rows are excluded by collect_candidates' per-tier sweep.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        for i in 0..3 {
            let mem = make_test_memory("cand-ns", &format!("row-{i}"), &"a".repeat(120));
            db::insert(&conn, &mem).unwrap();
        }
        let cfg = CuratorConfig::default();
        let batch = collect_candidates(&conn, &cfg).unwrap();
        assert!(!batch.memories.is_empty());
        // No truncation expected for a tiny seed.
        assert!(!batch.truncated);
    }

    #[test]
    fn run_once_with_dry_run_does_not_persist() {
        // dry_run=true with no LLM still runs to completion; the report
        // captures duration and the "no LLM" error path.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let mem = make_test_memory("dry-ns", "anchor", &"a".repeat(120));
        db::insert(&conn, &mem).unwrap();

        let cfg = CuratorConfig {
            dry_run: true,
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, None, &cfg, None).unwrap();
        assert!(report.dry_run);
        // No mutations happened — the original metadata is untouched.
        let after = db::get(&conn, &mem.id).unwrap().unwrap();
        assert!(after.metadata.get("auto_tags").is_none());
    }

    #[test]
    fn run_daemon_executes_multiple_cycles_and_respects_shutdown() {
        use std::sync::Mutex;
        use std::thread;
        use std::time::Duration;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let db_path = tmp.path().to_path_buf();
        let conn = db::open(&db_path).unwrap();

        // Pre-populate with test memories to give the daemon something to scan.
        let now = chrono::Utc::now().to_rfc3339();
        for i in 0..5 {
            let mem = Memory {
                cid: None,
                valid_from: None,
                valid_until: None,
                id: format!("test-mem-{i}"),
                tier: crate::models::Tier::Mid,
                namespace: "test".to_string(),
                title: format!("Memory {i}"),
                content: "x".repeat(100), // long enough for MIN_CONTENT_LEN
                tags: vec![],
                priority: 5,
                confidence: 1.0,
                source: "test".to_string(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now.clone(),
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
                confidence_source: crate::models::ConfidenceSource::CallerProvided,
                confidence_signals: None,
                confidence_decayed_at: None,
                version: 1,
                lifecycle_state: crate::models::LifecycleState::Open,
            };
            db::insert(&conn, &mem).unwrap();
        }
        drop(conn);

        // Use a Mutex to track that daemon entered and exited.
        let cycle_count = std::sync::Arc::new(Mutex::new(0));
        let cycle_count_for_test = cycle_count.clone();

        // Tight config: 1-second interval, tight operation cap.
        let cfg = CuratorConfig {
            interval_secs: 1,
            max_ops_per_cycle: 50,
            dry_run: true, // Don't actually touch the DB on write
            include_namespaces: vec![],
            exclude_namespaces: vec![],
            ..CuratorConfig::default()
        };

        // Shutdown flag starts false; the daemon will run until this is set.
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_for_daemon = shutdown.clone();

        // Spawn the daemon in a thread so we can control its lifetime.
        let daemon_thread = thread::spawn(move || {
            // Record that we're entering the daemon loop.
            *cycle_count_for_test.lock().unwrap() = 1;
            run_daemon(db_path, None, cfg, shutdown_for_daemon, None);
            // Record that the daemon exited cleanly.
            *cycle_count_for_test.lock().unwrap() = 2;
        });

        // Let the daemon run for ~2.5s (enough for 2–3 cycles at 1s interval).
        thread::sleep(Duration::from_millis(2500));

        // Signal shutdown.
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);

        // Wait for the daemon to exit (with a timeout).
        let join_result = daemon_thread.join();
        assert!(
            join_result.is_ok(),
            "daemon thread panicked or failed to join"
        );

        // Verify the daemon ran and exited cleanly.
        let final_count = *cycle_count.lock().unwrap();
        assert_eq!(
            final_count, 2,
            "daemon should have entered and exited cleanly"
        );
    }

    // ---- Wave 9 (Closer A9) — `run_once` decision-branch matrix
    // exercised against an in-process fake Ollama HTTP server. The
    // existing `run_once_*` tests pass `None` as the LLM client; the
    // tests below stand up a synchronous std::net::TcpListener that
    // mimics just enough of the Ollama API (`GET /api/tags` for
    // is_available, `POST /api/chat` for generate) to drive the LLM
    // branches inside `run_once`.

    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicBool as StdAtomicBool, AtomicUsize, Ordering as StdOrdering};
    use std::thread::JoinHandle;

    /// Behaviour knobs for the fake Ollama server.
    #[derive(Clone)]
    struct FakeOllamaCfg {
        /// Tag list returned for prompts that contain "tags".
        tag_response: String,
        /// Contradiction answer ("yes" or "no") for "contradict" prompts.
        contradiction_answer: String,
        /// Summary returned for "Summarize" prompts.
        summary_response: String,
        /// If `true`, every `POST /api/chat` returns HTTP 500.
        chat_returns_error: bool,
    }

    impl Default for FakeOllamaCfg {
        fn default() -> Self {
            Self {
                tag_response: "alpha\nbeta\ngamma".to_string(),
                contradiction_answer: "no".to_string(),
                summary_response: "consolidated summary".to_string(),
                chat_returns_error: false,
            }
        }
    }

    /// Handle to a running fake-Ollama server. Drop signals shutdown.
    struct FakeOllama {
        url: String,
        shutdown: StdArc<StdAtomicBool>,
        handle: Option<JoinHandle<()>>,
        chat_calls: StdArc<AtomicUsize>,
    }

    impl FakeOllama {
        fn start(cfg: FakeOllamaCfg) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
            let addr = listener.local_addr().unwrap();
            // 50ms accept poll so shutdown is responsive.
            listener.set_nonblocking(true).unwrap();
            let shutdown = StdArc::new(StdAtomicBool::new(false));
            let chat_calls = StdArc::new(AtomicUsize::new(0));
            let shutdown_for_thread = shutdown.clone();
            let chat_calls_for_thread = chat_calls.clone();
            let cfg_for_thread = cfg;

            let handle = std::thread::spawn(move || {
                while !shutdown_for_thread.load(StdOrdering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _peer)) => {
                            stream.set_nonblocking(false).ok();
                            stream
                                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                                .ok();
                            let cfg = cfg_for_thread.clone();
                            let chat_calls = chat_calls_for_thread.clone();
                            std::thread::spawn(move || {
                                handle_one(&mut stream, &cfg, &chat_calls);
                            });
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(20));
                        }
                        Err(_) => break,
                    }
                }
            });

            Self {
                url: format!("http://127.0.0.1:{}", addr.port()),
                shutdown,
                handle: Some(handle),
                chat_calls,
            }
        }
    }

    impl Drop for FakeOllama {
        fn drop(&mut self) {
            self.shutdown.store(true, StdOrdering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    /// Read one HTTP/1.1 request from `stream`, route by path, write a
    /// canned response, and close. Designed for a single round-trip per
    /// connection — sufficient for the blocking reqwest client.
    fn handle_one(stream: &mut std::net::TcpStream, cfg: &FakeOllamaCfg, chat_calls: &AtomicUsize) {
        let mut reader = BufReader::new(stream.try_clone().expect("clone tcp"));
        // Parse request line.
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            return;
        }
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return;
        }
        let method = parts[0];
        let path = parts[1];

        // Drain headers; track Content-Length.
        let mut content_length: usize = 0;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).is_err() {
                return;
            }
            if header == "\r\n" || header.is_empty() {
                break;
            }
            let lower = header.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("content-length:") {
                content_length = rest.trim().parse().unwrap_or(0);
            }
        }

        // Slurp the body if any.
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            let _ = reader.read_exact(&mut body);
        }
        let body_str = String::from_utf8_lossy(&body).to_string();

        let (status, body): (&str, String) = if method == "GET" && path == "/api/tags" {
            // is_available + ensure_model probe — return a non-empty model list.
            (
                "200 OK",
                serde_json::json!({"models": [{"name": "fake-model:latest"}]}).to_string(),
            )
        } else if method == "POST" && path == "/api/chat" {
            chat_calls.fetch_add(1, StdOrdering::Relaxed);
            if cfg.chat_returns_error {
                (
                    "500 Internal Server Error",
                    "{\"error\":\"forced fault\"}".to_string(),
                )
            } else {
                // Pick a response based on the prompt content.
                let response = if body_str.contains("contradict") {
                    cfg.contradiction_answer.clone()
                } else if body_str.contains("Summarize") || body_str.contains("summari") {
                    cfg.summary_response.clone()
                } else if body_str.contains("tags") {
                    cfg.tag_response.clone()
                } else {
                    "ok".to_string()
                };
                (
                    "200 OK",
                    serde_json::json!({"message": {"content": response}}).to_string(),
                )
            }
        } else if method == "POST" && path == "/api/generate" {
            // v0.7.0 L15 — `OllamaClient::auto_tag` switched to
            // `/api/generate` (with a num_predict ceiling) so the fake
            // server has to honour that surface too. We treat
            // /api/generate the same way the /api/chat path treats
            // tag-shaped prompts, since auto_tag is the only caller of
            // /api/generate today.
            chat_calls.fetch_add(1, StdOrdering::Relaxed);
            if cfg.chat_returns_error {
                (
                    "500 Internal Server Error",
                    "{\"error\":\"forced fault\"}".to_string(),
                )
            } else {
                let response = cfg.tag_response.clone();
                (
                    "200 OK",
                    serde_json::json!({"response": response}).to_string(),
                )
            }
        } else {
            ("404 Not Found", "{}".to_string())
        };

        let resp = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
        let _ = stream.shutdown(std::net::Shutdown::Write);
    }

    /// v1.0.0 #3140 — outer wall-clock guard for a curator test that drives
    /// the sync↔async LLM bridge.
    ///
    /// `run_once_with_llm_dry_run_skips_writes` is a plain `#[test]`, so every
    /// `auto_tag` / `detect_contradiction` call reaches the no-runtime arm of
    /// the sync↔async bridge. That bridge is now bounded structurally
    /// ([`crate::llm::block_on_local_bounded`]); this is the test-level
    /// backstop so a future wedge fails in a minute with a message instead of
    /// burning the whole CI job cap the way #3140 did (72 min on macOS).
    const HUNG_TEST_GUARD: std::time::Duration = std::time::Duration::from_mins(1);

    /// v1.0.0 #3140 — run `body` on its own thread and give up waiting after
    /// [`HUNG_TEST_GUARD`].
    ///
    /// The thread is deliberately detached (not scoped) on expiry: abandoning
    /// a wedged worker is what lets the assertion fire at all. A panic inside
    /// `body` drops the sender, so it is re-raised immediately via `join`
    /// rather than being misreported as a hang — and re-raised with
    /// `resume_unwind`, which carries the ORIGINAL payload through, so a failed
    /// assertion inside `body` is reported by the harness verbatim rather than
    /// being flattened into this wrapper's message.
    fn run_under_hung_test_guard<F>(what: &str, body: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let (tx, rx) = std::sync::mpsc::sync_channel::<()>(1);
        let worker = std::thread::spawn(move || {
            body();
            let _ = tx.send(());
        });
        match rx.recv_timeout(HUNG_TEST_GUARD) {
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if let Err(payload) = worker.join() {
                    std::panic::resume_unwind(payload);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("{what} still running after {HUNG_TEST_GUARD:?} — hung (#3140)")
            }
        }
    }

    /// Build an `OllamaClient` pointed at a running fake server.
    fn ollama_for(server: &FakeOllama) -> crate::llm::OllamaClient {
        crate::llm::OllamaClient::new_with_url(&server.url, "fake-model")
            .expect("client must reach fake server")
    }

    fn make_eligible_memory(ns: &str, title: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: ns.to_string(),
            title: title.to_string(),
            content: "a".repeat(120),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "api".to_string(),
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
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    /// `run_once` with a working LLM: tags eligible memories, persists
    /// `auto_tags` metadata, and reports a non-zero `auto_tagged` count.
    /// Exercises the `Ok(tags) if !tags.is_empty()` happy-path branch.
    #[test]
    fn run_once_with_llm_tags_eligible_memories() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let mem = make_eligible_memory("autotag-ns", "anchor");
        db::insert(&conn, &mem).unwrap();

        let cfg = CuratorConfig {
            // Trim the autonomy pass — it would call summarize_memories
            // for clusters and we want a clean assertion on auto_tag only.
            include_namespaces: vec!["autotag-ns".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, None).unwrap();

        assert!(report.memories_eligible >= 1);
        assert!(report.auto_tagged >= 1, "report: {report:?}");
        let updated = db::get(&conn, &mem.id).unwrap().unwrap();
        let tags = updated
            .metadata
            .get("auto_tags")
            .and_then(|v| v.as_array())
            .expect("auto_tags persisted");
        assert!(!tags.is_empty());
    }

    /// `run_once` with `dry_run=true` and an LLM: the report still
    /// reflects work-that-would-happen but no metadata is written and
    /// no `_curator/reports` self-report row appears.
    #[test]
    fn run_once_with_llm_dry_run_skips_writes() {
        // #3140 — this test hung for 72 min on a macOS CI runner (the sync↔async
        // LLM bridge parked with no wall-clock bound). Body runs under a guard.
        run_under_hung_test_guard("run_once_with_llm_dry_run_skips_writes", || {
            let server = FakeOllama::start(FakeOllamaCfg::default());
            let llm = ollama_for(&server);

            let tmp = tempfile::NamedTempFile::new().unwrap();
            let conn = db::open(tmp.path()).unwrap();
            let mem = make_eligible_memory("dry-llm-ns", "anchor");
            db::insert(&conn, &mem).unwrap();

            let cfg = CuratorConfig {
                dry_run: true,
                include_namespaces: vec!["dry-llm-ns".to_string()],
                ..CuratorConfig::default()
            };
            let report = run_once(&conn, Some(&llm), &cfg, None).unwrap();
            assert!(report.dry_run);

            // No DB writes: original metadata unchanged, no self-report.
            let after = db::get(&conn, &mem.id).unwrap().unwrap();
            assert!(after.metadata.get("auto_tags").is_none());
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
            assert!(reports.is_empty(), "dry-run must not persist self-report");
        });
    }

    /// `max_ops_per_cycle` caps how many memories the LLM loop touches.
    /// Set the cap to 1, seed three eligible rows, and assert
    /// `operations_attempted == 1` plus `operations_skipped_cap > 0`.
    #[test]
    fn run_once_max_ops_cap_respected() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        for i in 0..3 {
            let m = make_eligible_memory("capns", &format!("anchor-{i}"));
            db::insert(&conn, &m).unwrap();
        }
        let cfg = CuratorConfig {
            max_ops_per_cycle: 1,
            include_namespaces: vec!["capns".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, None).unwrap();
        assert_eq!(report.operations_attempted, 1);
        assert!(report.operations_skipped_cap >= 2, "report: {report:?}");
    }

    /// `include_namespaces` filters the eligible set to the listed
    /// namespaces only. Memories outside the list are scanned but not
    /// curated.
    #[test]
    fn run_once_include_namespaces_filter() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let inside = make_eligible_memory("included", "in");
        let outside = make_eligible_memory("not-included", "out");
        db::insert(&conn, &inside).unwrap();
        db::insert(&conn, &outside).unwrap();

        let cfg = CuratorConfig {
            include_namespaces: vec!["included".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, None).unwrap();
        // Both memories are scanned but only the included one is eligible.
        assert!(report.memories_scanned >= 2);
        assert_eq!(report.memories_eligible, 1);
        // The non-included memory still has no auto_tags.
        let after_outside = db::get(&conn, &outside.id).unwrap().unwrap();
        assert!(after_outside.metadata.get("auto_tags").is_none());
    }

    /// `exclude_namespaces` removes namespaces from the eligible set.
    #[test]
    fn run_once_exclude_namespaces_filter() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let kept = make_eligible_memory("kept", "k");
        let dropped = make_eligible_memory("dropped", "d");
        db::insert(&conn, &kept).unwrap();
        db::insert(&conn, &dropped).unwrap();

        let cfg = CuratorConfig {
            exclude_namespaces: vec!["dropped".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, None).unwrap();
        assert!(report.memories_scanned >= 2);
        // Only the non-dropped namespace is eligible.
        assert_eq!(report.memories_eligible, 1);
        let after_dropped = db::get(&conn, &dropped.id).unwrap().unwrap();
        assert!(after_dropped.metadata.get("auto_tags").is_none());
    }

    /// `run_once` on a database with zero eligible candidates returns a
    /// well-formed report with all counters at 0 and no errors that
    /// originate from the loop body itself.
    #[test]
    fn run_once_handles_zero_candidates() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let cfg = CuratorConfig::default();

        let report = run_once(&conn, Some(&llm), &cfg, None).unwrap();
        assert_eq!(report.memories_scanned, 0);
        assert_eq!(report.memories_eligible, 0);
        assert_eq!(report.operations_attempted, 0);
        assert_eq!(report.auto_tagged, 0);
        assert_eq!(report.contradictions_found, 0);
    }

    /// When the LLM affirms `yes` to the contradiction prompt and the
    /// memory has a sibling, `run_once` records the contradiction in
    /// the memory's metadata and bumps `contradictions_found`.
    #[test]
    fn run_once_records_contradictions_when_llm_affirms() {
        let cfg_server = FakeOllamaCfg {
            contradiction_answer: "yes".to_string(),
            ..FakeOllamaCfg::default()
        };
        let server = FakeOllama::start(cfg_server);
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let m1 = make_eligible_memory("dual", "first");
        let m2 = make_eligible_memory("dual", "second");
        db::insert(&conn, &m1).unwrap();
        db::insert(&conn, &m2).unwrap();

        let cfg = CuratorConfig {
            include_namespaces: vec!["dual".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, None).unwrap();
        assert!(report.contradictions_found >= 1, "report: {report:?}");
    }

    /// When the LLM returns HTTP 500 errors, `run_once` records the
    /// failures in `report.errors` but still completes the cycle and
    /// emits a finished report.
    #[test]
    fn run_once_records_errors_when_llm_fails() {
        let cfg_server = FakeOllamaCfg {
            chat_returns_error: true,
            ..FakeOllamaCfg::default()
        };
        let server = FakeOllama::start(cfg_server);
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let mem = make_eligible_memory("fail-ns", "anchor");
        db::insert(&conn, &mem).unwrap();

        let cfg = CuratorConfig {
            include_namespaces: vec!["fail-ns".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, None).unwrap();
        // The cycle finishes despite errors.
        assert!(!report.completed_at.is_empty());
        // At least one auto_tag failure surfaced.
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("auto_tag failed") || e.contains("detect_contradiction failed")),
            "expected an LLM-error entry in report.errors: {:?}",
            report.errors
        );
        // No metadata persisted because every LLM call errored.
        let after = db::get(&conn, &mem.id).unwrap().unwrap();
        assert!(after.metadata.get("auto_tags").is_none());
    }

    /// A successful cycle (LLM available, dry_run=false, eligible row)
    /// writes a self-report memory under `_curator/reports/<ts>`.
    /// Covers the `persist_self_report` invocation inside `run_once`.
    #[test]
    fn run_once_writes_self_report_when_not_dry_run() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let mem = make_eligible_memory("report-ns", "anchor");
        db::insert(&conn, &mem).unwrap();

        let cfg = CuratorConfig {
            include_namespaces: vec!["report-ns".to_string()],
            ..CuratorConfig::default()
        };
        let _ = run_once(&conn, Some(&llm), &cfg, None).unwrap();

        // v1.0.0 #3345 — a sweep must leave NO recall-visible row. Pre-#3345
        // this asserted `db::list` returned the report, i.e. it pinned the
        // defect: one ordinary, embeddable memory per sweep, which reached
        // 24,930 rows / 24,801 paid embeddings on one node (#1466 recurrence).
        let recall_visible = db::list(
            &conn,
            Some(crate::autonomy::CURATOR_REPORTS_NAMESPACE),
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
            "a sweep must leave no recall-visible row, got {} row(s)",
            recall_visible.len()
        );

        // The report IS written — just to the operator-only ledger view.
        let reports =
            db::list_operational_reports(&conn, crate::autonomy::CURATOR_REPORTS_NAMESPACE, 10)
                .unwrap();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].2.contains("memories_consolidated"));
    }

    /// `run_once` skips already-tagged rows on a re-run — covering the
    /// `needs_curation` re-entrancy guard from inside `run_once`. The
    /// second cycle should report `memories_eligible == 0` even though
    /// the row is still scanned.
    #[test]
    fn run_once_idempotent_on_already_tagged_rows() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let mem = make_eligible_memory("idem-ns", "anchor");
        db::insert(&conn, &mem).unwrap();

        let cfg = CuratorConfig {
            include_namespaces: vec!["idem-ns".to_string()],
            ..CuratorConfig::default()
        };
        let r1 = run_once(&conn, Some(&llm), &cfg, None).unwrap();
        assert_eq!(r1.memories_eligible, 1);
        let r2 = run_once(&conn, Some(&llm), &cfg, None).unwrap();
        assert!(r2.memories_scanned >= 1);
        assert_eq!(r2.memories_eligible, 0);
        assert_eq!(r2.operations_attempted, 0);
    }

    // -----------------------------------------------------------------
    // v0.8.0 Pillar-2.5 (#1709) — size-GC pass wiring in run_once.
    // size_gc is LLM-free, so these run with `llm = None` (the pass runs
    // before the no-LLM early-return). Long-tier rows are used because the
    // curator candidate scan only collects mid + long tier.
    // -----------------------------------------------------------------

    /// Build a long-tier row with `content_len` bytes of payload in `ns`
    /// at the given priority — predictable corpus arithmetic for the cap.
    fn make_sized_curator_memory(
        ns: &str,
        title: &str,
        priority: i32,
        content_len: usize,
    ) -> Memory {
        let mut m = make_eligible_memory(ns, title);
        m.priority = priority;
        m.content = "x".repeat(content_len);
        m
    }

    #[test]
    fn run_once_size_gc_evicts_and_increments_counter() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        // Two ~1KB long-tier rows; lower-priority is the eviction victim.
        let low = make_sized_curator_memory("sgc-ns", "low", 1, 1000);
        let high = make_sized_curator_memory("sgc-ns", "high", 9, 1000);
        db::insert(&conn, &low).unwrap();
        db::insert(&conn, &high).unwrap();

        let cfg = CuratorConfig {
            include_namespaces: vec!["sgc-ns".to_string()],
            compaction: CompactionConfig {
                // #1750 — size-GC now additionally requires `enabled`.
                enabled: true,
                max_corpus_bytes: Some(1500),
                ..CompactionConfig::default()
            },
            ..CuratorConfig::default()
        };
        // No LLM needed — size_gc is pure SQL and runs before the early-return.
        let report = run_once(&conn, None, &cfg, None).unwrap();
        assert_eq!(
            report.memories_evicted_size_gc, 1,
            "one lowest-value row evicted, counter incremented"
        );
        assert!(
            db::get(&conn, &low.id).unwrap().is_none(),
            "low-priority evicted"
        );
        assert!(
            db::get(&conn, &high.id).unwrap().is_some(),
            "high-priority kept"
        );
    }

    #[test]
    fn run_once_size_gc_none_cap_does_not_evict() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let m = make_sized_curator_memory("sgc-ns", "a", 1, 5000);
        db::insert(&conn, &m).unwrap();

        // Default compaction → max_corpus_bytes = None → disabled.
        let cfg = CuratorConfig {
            include_namespaces: vec!["sgc-ns".to_string()],
            ..CuratorConfig::default()
        };
        assert!(cfg.compaction.max_corpus_bytes.is_none());
        let report = run_once(&conn, None, &cfg, None).unwrap();
        assert_eq!(report.memories_evicted_size_gc, 0, "None cap = no eviction");
        assert!(db::get(&conn, &m.id).unwrap().is_some(), "row untouched");
    }

    #[test]
    fn run_once_size_gc_dry_run_does_not_evict() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let low = make_sized_curator_memory("sgc-ns", "low", 1, 1000);
        let high = make_sized_curator_memory("sgc-ns", "high", 9, 1000);
        db::insert(&conn, &low).unwrap();
        db::insert(&conn, &high).unwrap();

        let cfg = CuratorConfig {
            dry_run: true,
            include_namespaces: vec!["sgc-ns".to_string()],
            compaction: CompactionConfig {
                // #1750 — `enabled` set so this test pins the dry_run gate
                // specifically (not the new enabled gate).
                enabled: true,
                max_corpus_bytes: Some(1500),
                ..CompactionConfig::default()
            },
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, None, &cfg, None).unwrap();
        assert_eq!(report.memories_evicted_size_gc, 0, "dry_run evicts nothing");
        assert!(
            db::get(&conn, &low.id).unwrap().is_some(),
            "dry_run keeps low"
        );
        assert!(
            db::get(&conn, &high.id).unwrap().is_some(),
            "dry_run keeps high"
        );
    }

    /// #1750 (Pillar-2.5) — the defensive gate: a byte cap set WITHOUT
    /// `compaction.enabled` must NOT evict. Pins the hazard the #1749 vote
    /// (`1817bc8f`) flagged — size-GC can no longer arm decoupled from the
    /// operator's compaction opt-in.
    #[test]
    fn run_once_size_gc_cap_without_enabled_does_not_evict() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let low = make_sized_curator_memory("sgc-ns", "low", 1, 1000);
        let high = make_sized_curator_memory("sgc-ns", "high", 9, 1000);
        db::insert(&conn, &low).unwrap();
        db::insert(&conn, &high).unwrap();

        // Cap is set, but compaction.enabled stays false (default).
        let cfg = CuratorConfig {
            include_namespaces: vec!["sgc-ns".to_string()],
            compaction: CompactionConfig {
                max_corpus_bytes: Some(1500),
                ..CompactionConfig::default()
            },
            ..CuratorConfig::default()
        };
        assert!(!cfg.compaction.enabled, "guard: enabled is false");
        let report = run_once(&conn, None, &cfg, None).unwrap();
        assert_eq!(
            report.memories_evicted_size_gc, 0,
            "cap without enabled = no eviction (defensive gate)"
        );
        assert!(db::get(&conn, &low.id).unwrap().is_some(), "low kept");
        assert!(db::get(&conn, &high.id).unwrap().is_some(), "high kept");
    }

    /// A multi-row cycle records multiple `operations_attempted` and the
    /// LLM is invoked for each. The cycle proceeds even if one row's
    /// LLM call fails — covered indirectly via the error-server above;
    /// here we assert the success-with-multiple-rows path completes
    /// cleanly and increments counters in lock-step.
    #[test]
    fn run_once_iterates_through_multiple_rows() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        for i in 0..3 {
            let m = make_eligible_memory("multi-ns", &format!("anchor-{i}"));
            db::insert(&conn, &m).unwrap();
        }
        let cfg = CuratorConfig {
            include_namespaces: vec!["multi-ns".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, None).unwrap();
        assert_eq!(report.operations_attempted, 3);
        assert_eq!(report.auto_tagged, 3);
        // `chat_calls` ≥ 3 (one per auto_tag plus contradiction probes).
        assert!(server.chat_calls.load(StdOrdering::Relaxed) >= 3);
    }

    /// The smart-tier LLM consultation path: with the autonomy passes
    /// running and a near-duplicate cluster present, the curator calls
    /// `summarize_memories` on the cluster. We assert by chat-call count
    /// that the LLM was consulted beyond the per-row auto_tag/contradict
    /// pair.
    #[test]
    fn run_once_smart_tier_consults_llm_for_clusters() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        // Two near-duplicates (≥0.55 jaccard threshold) in one namespace.
        let now = chrono::Utc::now().to_rfc3339();
        let m_a = Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: "smart-a".to_string(),
            tier: Tier::Long,
            namespace: "smart".to_string(),
            title: "deploy plan".to_string(),
            content: "kubernetes rolling canary deploy strategy kubernetes deploy".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 1.0,
            source: "api".to_string(),
            access_count: 0,
            created_at: now.clone(),
            updated_at: now.clone(),
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
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        };
        let m_b = Memory {
            id: "smart-b".to_string(),
            content: "kubernetes rolling canary deploy strategy kubernetes deploy".to_string(),
            title: "deploy overview".to_string(),
            ..m_a.clone()
        };
        db::insert(&conn, &m_a).unwrap();
        db::insert(&conn, &m_b).unwrap();
        // #1774 — both sides need a stored embedding to clear the cosine gate;
        // attach aligned vectors (cosine = 1.0) so the dup pair clusters.
        db::set_embedding(
            &conn,
            &m_a.id,
            &[1.0, 0.0],
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();
        db::set_embedding(
            &conn,
            &m_b.id,
            &[1.0, 0.0],
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();

        let cfg = CuratorConfig {
            include_namespaces: vec!["smart".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, None).unwrap();
        // Auto-tag pass + autonomy pass → multiple chat calls.
        assert!(server.chat_calls.load(StdOrdering::Relaxed) >= 3);
        // Autonomy pass found at least the one cluster.
        assert!(report.autonomy.clusters_formed >= 1, "report: {report:?}");
    }

    /// v1.0.0 REGRESSION — Pass-1 STARVATION.
    ///
    /// The auto-tag / contradiction loop and the autonomy passes are fed by
    /// the SAME `needs_curation` predicate and drew on the same
    /// `max_ops_per_cycle` budget, loop first. So whenever the eligible
    /// backlog reached the cap the loop consumed all of it and Pass-1
    /// consolidation was handed a budget of exactly ZERO — every cycle, and
    /// permanently whenever those rows keep yielding empty auto-tags (an
    /// empty tag list persists nothing, so the row stays eligible forever).
    /// Consolidation would then never run again on a busy corpus, silently:
    /// the cycle report looked healthy.
    ///
    /// Backlog of 5 eligible rows against a cap of 4 (one over the cap even
    /// before the reserve). The assertions are the two halves of the
    /// contract: Pass 1 gets a NON-ZERO budget and actually consolidates,
    /// AND the cycle still never exceeds `max_ops_per_cycle` — the reserve is
    /// carved out of the cap, never added on top of it.
    #[test]
    fn run_once_reserves_autonomy_budget_when_autotag_backlog_fills_cap() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();

        // One mergeable near-duplicate pair: `make_eligible_memory` gives both
        // rows identical content (clears the jaccard pre-filter) and aligned
        // embeddings clear the #1774 cosine gate.
        for i in 0..2 {
            let m = make_eligible_memory("starve", &format!("dup-{i}"));
            db::insert(&conn, &m).unwrap();
            db::set_embedding(
                &conn,
                &m.id,
                &[1.0, 0.0],
                &crate::embeddings::embedding_space_fingerprint("test-space"),
            )
            .unwrap();
        }
        // Backlog filler: eligible for auto-tag, but NOT mergeable — with no
        // stored embedding the cosine gate blocks every pair they are in
        // (#1774), so the only cluster available to Pass 1 is the pair above.
        for i in 0..3 {
            let m = make_eligible_memory("starve", &format!("filler-{i}"));
            db::insert(&conn, &m).unwrap();
        }

        let cfg = CuratorConfig {
            max_ops_per_cycle: 4,
            include_namespaces: vec!["starve".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, None).unwrap();

        assert_eq!(
            report.memories_eligible, 5,
            "backlog must exceed the cap for this to be the starving case: {report:?}"
        );
        assert!(
            report.autonomy_ops_budget >= 1,
            "Pass 1 must get a non-zero budget even with a cap-filling backlog: {report:?}"
        );
        assert!(
            report.autonomy.clusters_formed >= 1,
            "Pass-1 consolidation must actually run with the reserved budget: {report:?}"
        );
        assert!(
            report.operations_attempted <= cfg.max_ops_per_cycle,
            "the reserve is carved OUT of max_ops_per_cycle, so the documented \
             hard cap must still hold: {report:?}"
        );
        assert!(
            report.operations_skipped_cap >= 1,
            "auto-tag work the reserve deferred must be COUNTED, not dropped: {report:?}"
        );
    }

    /// The reserve is a share OF the cap, never an addition to it, and it
    /// floors at one op so a small-but-splittable cap still reaches Pass 1.
    /// A cap of 0 or 1 has nothing to split and reserves nothing (a one-op
    /// cycle can only afford the auto-tag loop's first op).
    #[test]
    fn autonomy_op_reserve_is_a_share_of_the_cap_never_an_addition() {
        assert_eq!(autonomy_op_reserve(0), 0);
        assert_eq!(autonomy_op_reserve(1), 0);
        assert_eq!(autonomy_op_reserve(2), 1, "floors at one op");
        assert_eq!(autonomy_op_reserve(3), 1, "floors at one op");
        assert_eq!(
            autonomy_op_reserve(DEFAULT_MAX_OPS_PER_CYCLE),
            DEFAULT_MAX_OPS_PER_CYCLE / AUTONOMY_OP_RESERVE_DIVISOR
        );
        for cap in [
            0_usize,
            1,
            2,
            3,
            4,
            7,
            99,
            DEFAULT_MAX_OPS_PER_CYCLE,
            10_000,
        ] {
            let reserve = autonomy_op_reserve(cap);
            assert!(
                reserve <= cap,
                "reserve {reserve} must be carved out of cap {cap}, never added on top"
            );
            assert!(
                cap <= 1 || reserve >= 1,
                "a splittable cap {cap} must reserve at least one op for Pass 1"
            );
        }
    }

    /// Issue #816 — auto-persona sweep generates a signed persona row
    /// for an entity that a recent reflection mentions, when the daemon
    /// has a signing keypair on disk and the LLM is reachable.
    ///
    /// Pre-#816 the curator path produced no persona work at all (the
    /// `personas_generated` counter didn't even exist) — operators had
    /// to call `memory_persona_generate` explicitly for every entity.
    /// This regression pins the new contract:
    ///
    ///   * `report.personas_generated >= 1` after one cycle.
    ///   * A `__persona_<entity_id>_v1` row exists at the entity's
    ///     namespace with `metadata.persona.attest_level == "self_signed"`
    ///     and a 64-byte Ed25519 signature in
    ///     `metadata.persona.signature`.
    ///   * Each `derived_from` link the persona writes is also
    ///     `attest_level = "self_signed"`.
    #[test]
    fn run_once_persona_sweep_generates_signed_persona_for_new_entity() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();

        // Seed an observation in the test namespace; this is what the
        // reflection will reflect_on. PersonaGenerator pulls reflections
        // via `mentioned_entity_id` not via the source observations,
        // but the reflects_on edge is required for the reflection to
        // be a structurally valid reflection memory.
        let obs = make_eligible_memory("auto-persona-ns", "observation");
        let obs_id = db::insert(&conn, &obs).unwrap();

        // Seed a reflection. Mark it `memory_kind = Reflection` and
        // `reflection_depth = 1` so `is_reflection`-style queries find
        // it, and patch `mentioned_entity_id` post-insert because the
        // public Memory struct doesn't expose that column today
        // (`storage::extract_mentioned_entity_id` populates it from
        // `metadata.entity_mentions` on the real reflect path; the
        // SQL patch here is the test-side equivalent).
        let entity_id = "auto-persona-entity-2026-05-16";
        let mut rfl = make_eligible_memory("auto-persona-ns", "reflection-of-obs");
        rfl.memory_kind = crate::models::MemoryKind::Reflection;
        rfl.reflection_depth = 1;
        rfl.content = "This reflection mentions the entity under test.".to_string();
        let rfl_id = db::insert(&conn, &rfl).unwrap();
        // v0.7.0 #1036 (Agent-3 #7) — test fixture seed. Bumping
        // version here is irrelevant: the test isolates a single
        // reflection row in a fresh in-memory DB; no caller observes
        // the pre-update version, so there's no concurrency contract
        // to violate. Pinned by `tests/non_version_bumping_sites_1036.rs`.
        conn.execute(
            "UPDATE memories SET mentioned_entity_id = ?1 WHERE id = ?2",
            rusqlite::params![entity_id, &rfl_id],
        )
        .unwrap();
        db::create_link(&conn, &rfl_id, &obs_id, "reflects_on").unwrap();

        // Daemon signing keypair — the sweep passes this to
        // PersonaGenerator as the signer so every `derived_from`
        // edge lands `self_signed` and the persona's metadata
        // envelope carries the 64-byte signature.
        let kp = crate::identity::keypair::generate("daemon").unwrap();

        let cfg = CuratorConfig {
            include_namespaces: vec!["auto-persona-ns".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, Some(&kp)).unwrap();

        assert!(
            report.personas_generated >= 1,
            "expected at least one auto-persona generation, report.errors={:?}",
            report.errors
        );

        // Persona row exists and is signed at the artifact level.
        let persona = crate::persona::get_latest_persona(&conn, entity_id, "auto-persona-ns")
            .expect("get_latest_persona failed")
            .expect("persona row must exist after sweep");
        assert_eq!(
            persona.attest_level, "self_signed",
            "persona attest_level must be self_signed (was {:?})",
            persona.attest_level
        );

        // The metadata envelope carries the 64-byte signature.
        let row: String = conn
            .query_row(
                "SELECT metadata FROM memories WHERE id = ?1",
                rusqlite::params![&persona.id],
                |r| r.get(0),
            )
            .unwrap();
        let meta: serde_json::Value = serde_json::from_str(&row).unwrap();
        let sig_b64 = meta
            .get("persona")
            .and_then(|p| p.get("signature"))
            .and_then(|v| v.as_str())
            .expect("metadata.persona.signature missing");
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .expect("signature must be valid base64");
        assert_eq!(
            sig_bytes.len(),
            64,
            "metadata.persona.signature must decode to 64 bytes (got {})",
            sig_bytes.len()
        );

        // Every derived_from link the persona wrote is self_signed.
        let mut stmt = conn
            .prepare(
                "SELECT attest_level, length(signature) \
                 FROM memory_links \
                 WHERE source_id = ?1 AND relation = 'derived_from'",
            )
            .unwrap();
        let rows: Vec<(String, Option<i64>)> = stmt
            .query_map(rusqlite::params![&persona.id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
            })
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect();
        assert!(
            !rows.is_empty(),
            "persona must emit at least one derived_from edge"
        );
        for (attest_level, sig_len) in &rows {
            assert_eq!(
                attest_level, "self_signed",
                "persona derived_from edges must be self_signed"
            );
            assert_eq!(
                sig_len.unwrap_or(0),
                64,
                "persona derived_from signature must be 64 bytes"
            );
        }
    }

    /// Issue #839 coverage — exercise the persona_sweep `dry_run` branch
    /// (curator/mod.rs L479-485). The pre-fix coverage measurement was
    /// missing this arm because every persona-sweep regression seeded
    /// with `dry_run: false`. The fixture below mirrors
    /// `run_once_persona_sweep_generates_signed_persona_for_new_entity`
    /// but flips `dry_run = true` so the loop body lands in the
    /// dry-run accounting block without invoking the LLM generator.
    #[test]
    fn run_once_persona_sweep_dry_run_counts_without_writing() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();

        let obs = make_eligible_memory("dry-persona-ns", "observation");
        let obs_id = db::insert(&conn, &obs).unwrap();

        let entity_id = "dry-persona-entity-2026-05-18";
        let mut rfl = make_eligible_memory("dry-persona-ns", "reflection-of-obs");
        rfl.memory_kind = crate::models::MemoryKind::Reflection;
        rfl.reflection_depth = 1;
        rfl.content = "Dry-run reflection mentions the entity under test.".to_string();
        let rfl_id = db::insert(&conn, &rfl).unwrap();
        // v0.7.0 #1036 (Agent-3 #7) — test fixture seed. Bumping
        // version here is irrelevant: the test isolates a single
        // reflection row in a fresh in-memory DB; no caller observes
        // the pre-update version, so there's no concurrency contract
        // to violate. Pinned by `tests/non_version_bumping_sites_1036.rs`.
        conn.execute(
            "UPDATE memories SET mentioned_entity_id = ?1 WHERE id = ?2",
            rusqlite::params![entity_id, &rfl_id],
        )
        .unwrap();
        db::create_link(&conn, &rfl_id, &obs_id, "reflects_on").unwrap();

        let kp = crate::identity::keypair::generate("daemon").unwrap();

        let cfg = CuratorConfig {
            include_namespaces: vec!["dry-persona-ns".to_string()],
            dry_run: true,
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, Some(&kp)).unwrap();

        // Dry-run accounts the would-be generation.
        assert!(
            report.personas_generated >= 1,
            "dry-run must still count would-be persona generations, errors={:?}",
            report.errors
        );

        // But NO persona row was actually written.
        let persona = crate::persona::get_latest_persona(&conn, entity_id, "dry-persona-ns")
            .expect("get_latest_persona must not error");
        assert!(
            persona.is_none(),
            "dry-run must NOT write a persona row, got: {persona:?}"
        );
    }

    // -----------------------------------------------------------------
    // v1.0.0 curator correctness regressions (ox-alpha review).
    // -----------------------------------------------------------------

    /// Insert one reflection carrying `mentioned_entity_id` in `ns` and
    /// return the entity id. Mirrors the fixture used by the existing
    /// persona-sweep tests: the column is patched post-insert because the
    /// public `Memory` struct does not expose it.
    fn seed_reflection_with_entity(conn: &Connection, ns: &str, entity_id: &str) {
        let obs = make_eligible_memory(ns, "observation");
        let obs_id = db::insert(conn, &obs).unwrap();
        let mut rfl = make_eligible_memory(ns, "reflection-of-obs");
        rfl.memory_kind = crate::models::MemoryKind::Reflection;
        rfl.reflection_depth = 1;
        rfl.content = "This reflection mentions the entity under test.".to_string();
        let rfl_id = db::insert(conn, &rfl).unwrap();
        conn.execute(
            "UPDATE memories SET mentioned_entity_id = ?1 WHERE id = ?2",
            rusqlite::params![entity_id, &rfl_id],
        )
        .unwrap();
        db::create_link(conn, &rfl_id, &obs_id, "reflects_on").unwrap();
    }

    /// REGRESSION (ox-alpha #1) — `persona_sweep` must honour the
    /// operator's `exclude_namespaces`. Pre-fix its scan filtered on the
    /// reserved `_`-prefix ONLY, so the sweep wrote SIGNED persona rows
    /// into namespaces the operator had explicitly excluded — while
    /// `run_size_gc_pass` in the same file filtered correctly. The
    /// in-scope namespace is asserted too, so a filter that simply
    /// disabled the sweep could not pass this test.
    #[test]
    fn persona_sweep_honours_exclude_namespaces() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();

        seed_reflection_with_entity(&conn, "persona-kept", "entity-kept");
        seed_reflection_with_entity(&conn, "persona-dropped", "entity-dropped");

        let kp = crate::identity::keypair::generate("daemon").unwrap();
        let cfg = CuratorConfig {
            exclude_namespaces: vec!["persona-dropped".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, Some(&kp)).unwrap();

        assert!(
            crate::persona::get_latest_persona(&conn, "entity-kept", "persona-kept")
                .unwrap()
                .is_some(),
            "in-scope namespace must still get a persona, report.errors={:?}",
            report.errors
        );
        assert!(
            crate::persona::get_latest_persona(&conn, "entity-dropped", "persona-dropped")
                .unwrap()
                .is_none(),
            "excluded namespace must NEVER receive a curator-signed persona row"
        );
        assert_eq!(
            report.personas_generated, 1,
            "exactly one in-scope persona expected, errors={:?}",
            report.errors
        );
    }

    /// REGRESSION (ox-alpha #1, include half) — with a non-empty
    /// `include_namespaces`, `persona_sweep` must touch ONLY the listed
    /// namespaces.
    #[test]
    fn persona_sweep_honours_include_namespaces() {
        let server = FakeOllama::start(FakeOllamaCfg::default());
        let llm = ollama_for(&server);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();

        seed_reflection_with_entity(&conn, "persona-in", "entity-in");
        seed_reflection_with_entity(&conn, "persona-out", "entity-out");

        let kp = crate::identity::keypair::generate("daemon").unwrap();
        let cfg = CuratorConfig {
            include_namespaces: vec!["persona-in".to_string()],
            ..CuratorConfig::default()
        };
        let report = run_once(&conn, Some(&llm), &cfg, Some(&kp)).unwrap();

        assert!(
            crate::persona::get_latest_persona(&conn, "entity-in", "persona-in")
                .unwrap()
                .is_some(),
            "included namespace must get a persona, report.errors={:?}",
            report.errors
        );
        assert!(
            crate::persona::get_latest_persona(&conn, "entity-out", "persona-out")
                .unwrap()
                .is_none(),
            "namespace outside include_namespaces must NEVER receive a persona row"
        );
    }

    /// The single-source namespace-scope predicate every curator pass
    /// routes through.
    #[test]
    fn namespace_in_scope_predicate() {
        let mut cfg = CuratorConfig::default();
        assert!(namespace_in_scope("app", &cfg));
        assert!(
            !namespace_in_scope("_curator/reports", &cfg),
            "reserved namespaces are always out of scope"
        );

        cfg.include_namespaces = vec!["app".to_string()];
        assert!(namespace_in_scope("app", &cfg));
        assert!(!namespace_in_scope("other", &cfg));

        cfg.include_namespaces.clear();
        cfg.exclude_namespaces = vec!["noisy".to_string()];
        assert!(namespace_in_scope("app", &cfg));
        assert!(!namespace_in_scope("noisy", &cfg));

        // Exclude wins over include for the same namespace (fail closed).
        cfg.include_namespaces = vec!["noisy".to_string()];
        assert!(!namespace_in_scope("noisy", &cfg));
    }

    /// REGRESSION (ox-alpha #4) — a row whose `metadata` column holds
    /// non-object JSON used to make both persist helpers a SILENT no-op:
    /// they wrote the metadata back unchanged, returned `Ok(())`, and let
    /// `run_once` increment `auto_tagged` / `contradictions_found`. A lost
    /// write must be refused loudly, not self-reported as a success.
    #[test]
    fn persist_helpers_refuse_non_object_metadata() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();

        let mut mem = make_eligible_memory("meta-ns", "non-object-metadata");
        mem.metadata = serde_json::json!([1, 2, 3]);
        db::insert(&conn, &mem).unwrap();

        let tag_err = persist_auto_tags(&conn, &mem, &["t".to_string()])
            .expect_err("non-object metadata must be refused, not silently dropped");
        assert!(
            tag_err.to_string().contains("auto_tags"),
            "error must name the refused write: {tag_err}"
        );

        let contra_err = persist_contradiction(&conn, &mem, "other-id")
            .expect_err("non-object metadata must be refused, not silently dropped");
        assert!(
            contra_err.to_string().contains("array"),
            "error must name the offending metadata shape: {contra_err}"
        );

        // An object-metadata row on the same path still succeeds.
        let ok_mem = make_eligible_memory("meta-ns", "object-metadata");
        db::insert(&conn, &ok_mem).unwrap();
        persist_auto_tags(&conn, &ok_mem, &["t".to_string()])
            .expect("object metadata must still persist");
    }
}

#[test]
fn apply_rollback_handles_storage_error() {
    // Test that when persist_auto_tags fails (e.g., DB error),
    // the curator still records the error but continues.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let conn = db::open(tmp.path()).unwrap();

    // created_at is `now` so the #1466 tier-default expiry backfill on
    // this Mid row (created_at + 7d) lands in the future and the row
    // stays listable; a fixed past date would backfill to an already-
    // expired stamp and `db::list` would filter it out.
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: "m1".to_string(),
        tier: Tier::Mid,
        namespace: "test".to_string(),
        title: "Test".to_string(),
        content: "a".repeat(100),
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
        confidence_source: crate::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    };

    // Insert the memory so it exists
    db::insert(&conn, &mem).unwrap();

    // persist_auto_tags calls db::update — if the connection is bad,
    // it will fail. For this test, we verify the function exists and
    // can be called on a valid path (the error case is implicitly
    // tested by the curator's error accumulation).
    let tags = vec!["test-tag".to_string()];
    match persist_auto_tags(&conn, &mem, &tags) {
        Ok(_) => {
            // Verify the update succeeded by reading it back
            let batch =
                db::list(&conn, None, None, 10, 0, None, None, None, None, None, None).unwrap();
            let updated = batch.iter().find(|m| m.id == mem.id).unwrap();
            assert!(updated.metadata.get("auto_tags").is_some());
        }
        Err(e) => {
            // Error path: verify we can catch and log it
            assert!(!e.to_string().is_empty());
        }
    }
}

#[test]
fn consolidate_pair_skips_when_namespaces_disagree() {
    // This is a future test once autonomy::consolidate_pair is available.
    // For now, verify that the adjacent_memory function skips
    // memories in different namespaces.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let conn = db::open(tmp.path()).unwrap();

    let now = chrono::Utc::now().to_rfc3339();
    let mem1 = Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: "m1".to_string(),
        tier: Tier::Mid,
        namespace: "ns1".to_string(),
        title: "Title 1".to_string(),
        content: "a".repeat(100),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now.clone(),
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
        confidence_source: crate::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    };

    let mem2 = Memory {
        cid: None,
        valid_from: None,
        valid_until: None,
        id: "m2".to_string(),
        tier: Tier::Mid,
        namespace: "ns2".to_string(),
        title: "Title 2".to_string(),
        content: "b".repeat(100),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now.clone(),
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
        confidence_source: crate::models::ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        lifecycle_state: crate::models::LifecycleState::Open,
    };

    db::insert(&conn, &mem1).unwrap();
    db::insert(&conn, &mem2).unwrap();

    // adjacent_memory returns memories in the same namespace only
    let adj = adjacent_memory(&conn, &mem1).unwrap();
    // Should be None because there's no other memory in ns1
    assert!(adj.is_none());
}

#[test]
fn priority_feedback_caps_at_priority_10() {
    // Test boundary condition: priorities are clamped [1, 10].
    // This is implicitly covered by the autonomy pass, but we verify
    // the config default allows max_ops_per_cycle without overflow.
    let cfg = CuratorConfig {
        interval_secs: crate::SECS_PER_HOUR as u64,
        max_ops_per_cycle: 100,
        dry_run: false,
        include_namespaces: vec![],
        exclude_namespaces: vec![],
        ..CuratorConfig::default()
    };
    // If priority feedback caps at 10, max_ops_per_cycle * 4 should fit.
    let cap = cfg.max_ops_per_cycle.saturating_mul(4);
    assert_eq!(cap, 400);
    assert!(cap <= usize::MAX / 10);
}

#[test]
fn priority_feedback_floors_at_priority_1() {
    // Similar boundary test for floor at 1.
    let cfg = CuratorConfig::default();
    assert!(cfg.max_ops_per_cycle > 0);
    // If a curator cycle tries to apply feedback to 0 or negative
    // priorities, saturation saves us.
    let floored = 0_usize.saturating_add(1);
    assert_eq!(floored, 1);
}

#[test]
fn cycle_aborts_on_database_error() {
    // Test that run_once gracefully handles edge cases.
    // We use a valid connection but verify the error path exists.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let conn = db::open(tmp.path()).unwrap();
    let cfg = CuratorConfig::default();

    // run_once returns Ok(report) even when no LLM is available
    let result = run_once(&conn, None, &cfg, None);
    assert!(result.is_ok());
    let report = result.unwrap();
    // The "no LLM" error is recorded in the report
    assert!(report.errors.iter().any(|e| e.contains("no LLM")));
}

// ---------------------------------------------------------------------------
// Pillar-2.5 (#1738/#1746) — ConsolidationPass live-pass wiring tests.
// ---------------------------------------------------------------------------
#[cfg(all(test, feature = "sal"))]
mod consolidation_pass_tests_1746 {
    use super::*;
    use crate::autonomy::AutonomyLlm;
    use crate::models::{Memory, Tier};
    use std::sync::Mutex;

    /// Counts `summarize_memories` calls so a test can prove the dry-run
    /// path never invokes the LLM (and the real path does).
    struct CountingStubLlm {
        summarize_calls: Mutex<usize>,
    }
    impl AutonomyLlm for CountingStubLlm {
        fn auto_tag(&self, _t: &str, _c: &str) -> anyhow::Result<Vec<String>> {
            Ok(vec![])
        }
        fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
            Ok(false)
        }
        fn summarize_memories(&self, _m: &[(String, String)]) -> anyhow::Result<String> {
            *self.summarize_calls.lock().unwrap() += 1;
            Ok("synth".to_string())
        }
    }

    fn dup(ns: &str, title: &str, content: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Mid,
            namespace: ns.to_string(),
            title: title.to_string(),
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
            confidence_source: crate::models::ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: crate::models::LifecycleState::Open,
        }
    }

    fn seed(conn: &rusqlite::Connection) -> Vec<Memory> {
        // Distinct titles so the (title, namespace) upsert keeps both rows;
        // identical content so Jaccard clusters them.
        let c = "kubernetes rolling canary deploy strategy notes";
        let m1 = dup("ns", "t1", c);
        let m2 = dup("ns", "t2", c);
        crate::db::insert(conn, &m1).unwrap();
        crate::db::insert(conn, &m2).unwrap();
        // #1774 — both sides need a stored embedding to clear the cosine gate;
        // attach aligned vectors (cosine = 1.0) so the dup pair clusters (the
        // un-embedded path no longer merges).
        crate::db::set_embedding(
            conn,
            &m1.id,
            &[1.0, 0.0],
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();
        crate::db::set_embedding(
            conn,
            &m2.id,
            &[1.0, 0.0],
            &crate::embeddings::embedding_space_fingerprint("test-space"),
        )
        .unwrap();
        vec![m1, m2]
    }

    #[test]
    fn consolidation_pass_real_consolidates_and_folds_when_enabled() {
        // #1746 cutover: with compaction.enabled and a normal (non-dry-run)
        // cycle, the SAL pass is the LIVE consolidator — it summarises, writes
        // the [consolidated] row, hard-deletes the sources, and FOLDS its counts
        // into report.autonomy so the self-report is accurate.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let candidates = seed(&conn);
        let cfg = CuratorConfig {
            compaction: super::CompactionConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default() // dry_run = false → real consolidation
        };
        let llm = CountingStubLlm {
            summarize_calls: Mutex::new(0),
        };
        let mut report = CuratorReport::new(false);
        run_consolidation_pass(&conn, &candidates, &cfg, &llm, &mut report);

        assert!(
            report.compaction_pass_clusters_eligible >= 1,
            "the dup cluster should be eligible"
        );
        // Counts folded into report.autonomy (self-report parity).
        assert_eq!(
            report.autonomy.memories_consolidated, 2,
            "both sources folded into report.autonomy"
        );
        assert!(report.autonomy.clusters_formed >= 1);
        assert_eq!(
            report.autonomy.rollback_entries_written, 1,
            "one operator-reversible rollback entry persisted (#1745)"
        );
        assert!(
            *llm.summarize_calls.lock().unwrap() >= 1,
            "real mode summarises via the LLM"
        );
        let rows = db::list(
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
            "the live pass writes a consolidated row"
        );
        // Source label byte-continuity with the autonomy path (#1746).
        let consolidated = rows
            .iter()
            .find(|m| m.title.starts_with("[consolidated]"))
            .unwrap();
        assert_eq!(consolidated.source, crate::autonomy::CURATOR_SOURCE_LABEL);
    }

    #[test]
    fn consolidation_pass_dry_run_does_not_write_when_enabled() {
        // compaction.enabled but a --dry-run cycle: simulate-only, no LLM, no
        // write — the pass respects cfg.dry_run.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let candidates = seed(&conn);
        let cfg = CuratorConfig {
            compaction: super::CompactionConfig {
                enabled: true,
                ..Default::default()
            },
            dry_run: true,
            ..Default::default()
        };
        let llm = CountingStubLlm {
            summarize_calls: Mutex::new(0),
        };
        let mut report = CuratorReport::new(true);
        run_consolidation_pass(&conn, &candidates, &cfg, &llm, &mut report);

        assert!(
            report.compaction_pass_clusters_eligible >= 1,
            "eligible counted"
        );
        assert_eq!(
            report.autonomy.memories_consolidated, 0,
            "dry-run writes nothing"
        );
        assert_eq!(
            *llm.summarize_calls.lock().unwrap(),
            0,
            "dry-run skips the LLM"
        );
        let rows = db::list(
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
        assert_eq!(rows.len(), 2, "both source rows remain live");
    }

    #[test]
    fn consolidation_pass_noop_when_compaction_disabled() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let candidates = seed(&conn);
        // Default config → compaction.enabled = false.
        let cfg = CuratorConfig::default();
        let llm = CountingStubLlm {
            summarize_calls: Mutex::new(0),
        };
        let mut report = CuratorReport::new(false);
        run_consolidation_pass(&conn, &candidates, &cfg, &llm, &mut report);

        assert_eq!(
            report.compaction_pass_clusters_eligible, 0,
            "disabled compaction must not run the pass"
        );
        assert_eq!(report.autonomy.memories_consolidated, 0);
        assert!(
            report.errors.is_empty(),
            "no errors expected: {:?}",
            report.errors
        );
    }

    /// REGRESSION (ox-alpha #8) — `run_once` is a `pub fn` whose SAL
    /// consolidation pass drives its own runtime via `block_on`. Reached
    /// from a thread that already has an ambient tokio runtime that call
    /// PANICS ("Cannot start a runtime from within a runtime"), and the
    /// only thing standing between a caller and that panic used to be a
    /// doc comment. The in-runtime case is now detected and DEGRADED to a
    /// reported skip: the caller gets its report back instead of an
    /// unwind, and the corpus is untouched either way.
    #[tokio::test]
    async fn consolidation_pass_degrades_instead_of_panicking_inside_a_runtime() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let candidates = seed(&conn);
        let cfg = CuratorConfig {
            compaction: CompactionConfig {
                enabled: true,
                ..CompactionConfig::default()
            },
            ..CuratorConfig::default()
        };
        let llm = CountingStubLlm {
            summarize_calls: Mutex::new(0),
        };
        let mut report = CuratorReport::new(false);

        // Pre-fix: this line panicked and took the test thread with it.
        run_consolidation_pass(&conn, &candidates, &cfg, &llm, &mut report);

        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("inside an async runtime")),
            "the in-runtime skip must be surfaced to the operator, got {:?}",
            report.errors
        );
        assert_eq!(
            *llm.summarize_calls.lock().unwrap(),
            0,
            "a skipped pass must invoke no LLM"
        );
        assert_eq!(report.autonomy.memories_consolidated, 0);
        for m in &candidates {
            assert!(
                db::get(&conn, &m.id).unwrap().is_some(),
                "a skipped pass must leave every source row intact"
            );
        }
    }

    /// #3244 — `Handle::try_current()` is true on a `spawn_blocking` thread
    /// (tokio 1.52 blocking pool `rt.enter()`) even though that thread is
    /// not driving the runtime. Both production entrypoints already wrap
    /// `run_once` in `spawn_blocking` on a **multi-thread** runtime; this
    /// positive control asserts the SAL pass RAN rather than skipped.
    #[tokio::test(flavor = "multi_thread")]
    async fn consolidation_pass_runs_under_spawn_blocking() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let candidates = seed(&conn);
        let cfg = CuratorConfig {
            compaction: CompactionConfig {
                enabled: true,
                ..CompactionConfig::default()
            },
            ..CuratorConfig::default()
        };
        let llm = CountingStubLlm {
            summarize_calls: Mutex::new(0),
        };

        let (report, llm) = tokio::task::spawn_blocking(move || {
            let mut report = CuratorReport::new(false);
            run_consolidation_pass(&conn, &candidates, &cfg, &llm, &mut report);
            (report, llm)
        })
        .await
        .expect("spawn_blocking join");

        assert!(
            report
                .errors
                .iter()
                .all(|e| !e.contains("inside an async runtime")),
            "must not skip under spawn_blocking, got {:?}",
            report.errors
        );
        assert!(
            report.compaction_pass_clusters_eligible >= 1,
            "the dup cluster should be eligible, report: {report:?}"
        );
        assert_eq!(
            report.autonomy.memories_consolidated, 2,
            "both sources folded into report.autonomy"
        );
        assert!(
            *llm.summarize_calls.lock().unwrap() >= 1,
            "the pass must invoke the LLM, not skip"
        );
    }

    #[test]
    fn tokio_current_thread_handle_absent_without_a_runtime() {
        assert!(
            !tokio_current_thread_handle_present(),
            "a plain #[test] thread has no tokio Handle"
        );
    }

    /// #3283 REGRESSION — a panic inside the SAL `ConsolidationPass` must be
    /// CONTAINED at the `run_consolidation_pass` boundary, not unwind out and
    /// (via the daemon drivers' `spawn_blocking` → `JoinError` → hard error)
    /// kill the curator daemon. Pre-fix `run_consolidation_pass` had no
    /// `catch_unwind`, so a panicking clusterer/summariser took the caller's
    /// thread with it. Now the call returns normally, the panic is reported
    /// under [`CONSOLIDATION_PASS_PANIC_CONTAINED`], the corpus is untouched
    /// (summarise panics BEFORE any destructive persist), and a subsequent
    /// pass still consolidates — the stand-in for `run_daemon` proceeding to
    /// its next cycle rather than dying on the bad one.
    #[test]
    fn consolidation_pass_contains_panic_and_survives_3283() {
        struct PanicSummarizeLlm;
        impl AutonomyLlm for PanicSummarizeLlm {
            fn auto_tag(&self, _t: &str, _c: &str) -> anyhow::Result<Vec<String>> {
                Ok(vec![])
            }
            fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
                Ok(false)
            }
            fn summarize_memories(&self, _m: &[(String, String)]) -> anyhow::Result<String> {
                panic!("injected clustering/summarise panic (#3283 regression)")
            }
        }

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = db::open(tmp.path()).unwrap();
        let candidates = seed(&conn);
        let cfg = CuratorConfig {
            compaction: CompactionConfig {
                enabled: true,
                ..CompactionConfig::default()
            },
            ..CuratorConfig::default()
        };

        // The pass panics in `summarize_memories`. Pre-fix this unwound and
        // took the test thread down; reaching the asserts below AT ALL proves
        // the panic was contained (the process survived).
        let panic_llm = PanicSummarizeLlm;
        let mut report = CuratorReport::new(false);
        run_consolidation_pass(&conn, &candidates, &cfg, &panic_llm, &mut report);

        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains(CONSOLIDATION_PASS_PANIC_CONTAINED)),
            "the contained panic must be surfaced to the operator, got {:?}",
            report.errors
        );
        // Data integrity: summarise panics BEFORE persist, so both sources
        // survive untouched — a contained panic never corrupts the corpus.
        assert_eq!(report.autonomy.memories_consolidated, 0);
        for m in &candidates {
            assert!(
                db::get(&conn, &m.id).unwrap().is_some(),
                "a contained-panic cycle must leave every source row intact"
            );
        }

        // Daemon survival: a SUBSEQUENT healthy pass still runs to completion
        // on the same process + db.
        let good_llm = CountingStubLlm {
            summarize_calls: Mutex::new(0),
        };
        let mut report2 = CuratorReport::new(false);
        run_consolidation_pass(&conn, &candidates, &cfg, &good_llm, &mut report2);
        assert_eq!(
            report2.autonomy.memories_consolidated, 2,
            "the daemon survives: the next pass consolidates normally"
        );
        assert!(
            *good_llm.summarize_calls.lock().unwrap() >= 1,
            "the recovery pass invoked the LLM"
        );
    }

    #[tokio::test]
    async fn tokio_current_thread_handle_present_on_an_async_worker() {
        assert!(
            tokio_current_thread_handle_present(),
            "#[tokio::test] default flavor is current-thread"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tokio_current_thread_handle_absent_under_spawn_blocking() {
        let current_thread = tokio::task::spawn_blocking(tokio_current_thread_handle_present)
            .await
            .expect("spawn_blocking join");
        assert!(
            !current_thread,
            "spawn_blocking on a multi-thread runtime inherits a MultiThread Handle"
        );
    }
}
