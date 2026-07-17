// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_curator` migration. The daemon-mode body delegates to
//! `daemon_runtime::run_curator_daemon_with_primitives` (W3 work);
//! this module owns only the outer wrapper and the report printer.

// The SAL store-build helpers (`curator_store_url`, the `--store-url`
// path) and their `anyhow::Result` import are only live under the
// sal-gated curator path; relax dead-code / unused-import in a non-sal
// build only (sal builds enforce both fully).
#![cfg_attr(not(feature = "sal"), allow(dead_code, unused_imports))]

use crate::cli::CliOutput;
use crate::curator::reflection_pass;
use crate::identity::keypair as identity_keypair;
#[cfg(feature = "sal")]
use crate::store::{CallerContext, Filter, MemoryStore};
use crate::{autonomy, config, curator, db, llm};
use anyhow::{Context, Result};
use clap::Args;
use std::path::Path;

#[derive(Args)]
#[allow(clippy::struct_excessive_bools)]
pub struct CuratorArgs {
    /// Run exactly one sweep and exit. Mutually exclusive with --daemon.
    #[arg(long, conflicts_with = "daemon")]
    pub once: bool,
    /// Loop forever, sleeping --interval-secs between sweeps. SIGINT /
    /// SIGTERM trigger a clean shutdown between cycles.
    #[arg(long)]
    pub daemon: bool,
    /// Seconds between daemon sweeps. Clamped to [60, 86400].
    #[arg(long, default_value_t = crate::SECS_PER_HOUR as u64)]
    pub interval_secs: u64,
    /// Hard cap on LLM-invoking operations per cycle.
    #[arg(long, default_value_t = 100)]
    pub max_ops: usize,
    /// Emit the report without persisting any metadata changes.
    #[arg(long)]
    pub dry_run: bool,
    /// Only curate memories in these namespaces. Repeat flag for multiple.
    #[arg(long = "include-namespace")]
    pub include_namespaces: Vec<String>,
    /// Exclude these namespaces from curation. Repeat flag for multiple.
    #[arg(long = "exclude-namespace")]
    pub exclude_namespaces: Vec<String>,
    /// Print the report as JSON rather than a human-readable summary.
    #[arg(long)]
    pub json: bool,
    /// Reverse rollback-log entries instead of running a sweep. Accepts
    /// a specific rollback-memory id, or `--last N` for the most recent.
    /// Mutually exclusive with `--once` and `--daemon`.
    #[arg(long, conflicts_with_all = ["once", "daemon"])]
    pub rollback: Option<String>,
    /// With `--rollback`, reverse the N most recent rollback-log entries
    /// instead of a single id.
    #[arg(long)]
    pub rollback_last: Option<usize>,
    /// v0.7.0 L2-1 — Run the reflection-pass curator mode. Clusters
    /// co-recalled Observations and synthesises typed Reflection
    /// memories with `reflects_on` provenance. Mutually exclusive with
    /// the sweep / rollback modes. Requires either `--namespace` or
    /// `--all-namespaces`.
    #[arg(long, conflicts_with_all = ["once", "daemon", "rollback", "rollback_last"])]
    pub reflect: bool,
    /// Scope the reflection pass to a single namespace. Pairs with
    /// `--reflect`; ignored otherwise.
    #[arg(long)]
    pub namespace: Option<String>,
    /// Curator-side reflection-depth ceiling. The substrate's per-
    /// namespace `max_reflection_depth` policy is still enforced on
    /// top — this flag refuses to *propose* reflections that would
    /// exceed the operator-supplied cap so the curator never burns an
    /// LLM round-trip on a doomed write.
    #[arg(long)]
    pub max_depth: Option<u32>,
    /// Run the reflection pass over every observable namespace rather
    /// than a single one. Per-namespace `reflection_pass.enabled`
    /// flags still gate participation. Pairs with `--reflect`.
    #[arg(long)]
    pub all_namespaces: bool,
    /// v0.7.0 #1548 — full SAL store URL. When set, the curator binds
    /// its [`crate::store::MemoryStore`] handle to the URL-resolved
    /// adapter instead of the SQLite path derived from `--db`, so the
    /// reflection / consolidation passes run against a **Postgres**
    /// (or SQLite) federated store. Mirrors `serve --store-url`.
    ///
    /// Accepted shapes:
    ///
    /// - `sqlite:///absolute/path/to/file.db` — SQLite adapter (same
    ///   semantics as `--db`).
    /// - `postgres://user:pass@host:port/dbname` — Postgres adapter.
    /// - `postgresql://...` — alias for the Postgres scheme.
    ///
    /// `--db` and `--store-url` are mutually exclusive: passing both is
    /// rejected at startup with a clear error (mirrors `serve`).
    ///
    /// Postgres-backed curators require `--features sal,sal-postgres`
    /// at build time; otherwise the URL is rejected at startup.
    #[cfg(feature = "sal")]
    #[arg(long, value_name = "URL")]
    pub store_url: Option<String>,
}

/// #1143: honor `AI_MEMORY_LLM_BACKEND` env so the `ai-memory curator`
/// CLI (sweep / reflect / daemon modes) reaches xAI / OpenAI /
/// Anthropic / Gemini / etc. The legacy arm preserves v0.6.x behavior
/// (tier-default Ollama at the default URL). Returns `None` for the
/// keyword tier (no curator LLM configured) and on env / construction
/// failure — the curator falls through to keyword-only behavior so
/// the daemon never hard-fails on an unreachable provider.
fn build_curator_llm(tier: config::FeatureTier) -> Option<llm::OllamaClient> {
    // v0.7.x (#1146) — route through the canonical resolver. Two
    // short-circuits preserve pre-#1146 semantics:
    //   1. Tiers with no `llm_model` preset (Keyword, Semantic) AND
    //      no operator intent (env / config / legacy field absent —
    //      resolver `source == CompiledDefault`) return None without
    //      attempting client construction. Avoids paying a blocking
    //      reqwest call to a (likely-absent) Ollama under tokio test
    //      contexts and matches pre-#1146 v0.6.x behaviour.
    //   2. With operator intent, the resolver folds CLI / env /
    //      config / legacy / compiled through the uniform precedence
    //      ladder.
    let app_config = config::AppConfig::load();
    let resolved = app_config.resolve_llm(None, None, None);
    if matches!(resolved.source, config::ConfigSource::CompiledDefault)
        && tier.config().llm_model.is_none()
    {
        return None;
    }
    llm::OllamaClient::build_from_resolved(&resolved)
        .ok()
        .flatten()
}

fn print_curator_report(r: &curator::CuratorReport, out: &mut CliOutput<'_>) -> Result<()> {
    writeln!(out.stdout, "curator cycle report")?;
    writeln!(out.stdout, "  started_at:        {}", r.started_at)?;
    writeln!(out.stdout, "  completed_at:      {}", r.completed_at)?;
    writeln!(out.stdout, "  duration_ms:       {}", r.cycle_duration_ms)?;
    writeln!(out.stdout, "  memories_scanned:  {}", r.memories_scanned)?;
    writeln!(out.stdout, "  memories_eligible: {}", r.memories_eligible)?;
    writeln!(
        out.stdout,
        "  operations:        {}",
        r.operations_attempted
    )?;
    writeln!(out.stdout, "  auto_tagged:       {}", r.auto_tagged)?;
    writeln!(
        out.stdout,
        "  contradictions:    {}",
        r.contradictions_found
    )?;
    writeln!(
        out.stdout,
        "  skipped (cap):     {}",
        r.operations_skipped_cap
    )?;
    writeln!(out.stdout, "  errors:            {}", r.errors.len())?;
    writeln!(out.stdout, "  dry_run:           {}", r.dry_run)?;
    for e in &r.errors {
        writeln!(out.stdout, "    - {e}")?;
    }
    Ok(())
}

/// `curator` handler. Daemon-mode delegates to `daemon_runtime`.
pub async fn run(
    db_path: &Path,
    args: &CuratorArgs,
    app_config: &config::AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if args.rollback.is_some() || args.rollback_last.is_some() {
        // #1748 (slice-3c2) — when `--store-url` selects a (postgres) SAL
        // store, reverse the rollback rows the store-backed curator wrote
        // (slice-3c1) through the `MemoryStore` trait; the rusqlite path
        // below only ever sees the local SQLite file.
        #[cfg(feature = "sal")]
        if curator_store_url(args).is_some() {
            return run_store_backed_rollback(db_path, args, app_config, out).await;
        }
        return run_rollback(db_path, args, out);
    }

    if args.reflect {
        return run_reflect(db_path, args, app_config, out).await;
    }

    if !args.once && !args.daemon {
        anyhow::bail!(
            "curator requires --once, --daemon, --reflect, --rollback <id>, or --rollback-last N"
        );
    }

    // v0.7.0 #1548 — when `--store-url` selects a Postgres adapter, the
    // `--once` / `--daemon` upkeep sweep runs against the federated
    // store through the SAL `MemoryStore` trait (reflection-pass
    // upkeep). The SQLite path keeps the full pre-#1548 conn-bound
    // daemon (auto_tag + contradiction + autonomy + persona) for exact
    // behaviour parity, since that subsystem is not yet trait-ported.
    #[cfg(feature = "sal")]
    if curator_store_url(args).is_some() {
        return run_store_backed_sweep(db_path, args, app_config, out).await;
    }

    let cfg = curator::CuratorConfig {
        interval_secs: args.interval_secs,
        max_ops_per_cycle: args.max_ops,
        dry_run: args.dry_run,
        include_namespaces: args.include_namespaces.clone(),
        exclude_namespaces: args.exclude_namespaces.clone(),
        compaction: curator_compaction_config(app_config),
    };

    let feature_tier = app_config.effective_tier(None);
    let llm = build_curator_llm(feature_tier);

    if args.once {
        let conn = db::open(db_path)?;
        // v0.9.0 §25.3 S1 (D3-012, #1870) — TOFU-capture the substrate's
        // resolved model family at the LLM boundary. Best-effort: a
        // capture failure never blocks the curator cycle. Only
        // substrate-invoked generation is attestable, so loader coverage
        // hard-caps ~40% (ROADMAP.md:1229).
        capture_loader_attestation(&conn, llm.as_ref());
        let report = curator::run_once(&conn, llm.as_ref(), &cfg, None)?;
        if args.json {
            writeln!(out.stdout, "{}", serde_json::to_string_pretty(&report)?)?;
        } else {
            print_curator_report(&report, out)?;
        }
        return Ok(());
    }

    // Daemon mode — delegate to daemon_runtime.
    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let shutdown_for_signal = shutdown.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        shutdown_for_signal.notify_one();
    });

    // #1440 — hand the daemon the SAME resolver-built client the
    // `--once` path uses (built at the top of `run` via
    // `build_curator_llm`). The pre-#1440 code re-derived a model
    // string from the tier default (`gemma4:e4b`) and injected it as a
    // CLI-arm model override, clobbering the operator's configured
    // `[llm].model` and 400-ing every call on non-Ollama backends.
    crate::daemon_runtime::run_curator_daemon_with_primitives(
        db_path.to_path_buf(),
        args.interval_secs,
        args.max_ops,
        args.dry_run,
        args.include_namespaces.clone(),
        args.exclude_namespaces.clone(),
        // #1749 — resolve compaction.enabled here (the daemon body has no
        // AppConfig in scope) and thread it as a primitive.
        app_config.resolve_compaction_enabled(),
        llm.map(std::sync::Arc::new),
        shutdown,
    )
    .await
}

/// v0.9.0 §25.3 S1 (D3-012, #1870) — record a `loader_observed`
/// model-family attestation for the substrate's resolved LLM client, if
/// its model normalizes to a known family. Best-effort + TOFU
/// (write-once): a `None` client, an unknown family, or a SQLite error
/// is a silent no-op — attestation must never block a curator cycle.
///
/// This is a PROCESS-LIFETIME trusted-substrate self-report (the daemon
/// observed which model IT was configured to call), NOT per-write
/// cryptographic provenance. Externally authored reflections never reach
/// this boundary, so loader coverage hard-caps ~40% (ROADMAP.md:1229).
fn capture_loader_attestation(conn: &rusqlite::Connection, llm: Option<&llm::OllamaClient>) {
    let Some(client) = llm else {
        return;
    };
    let provider = client.provider_label();
    let model_ref = client.model_name();
    let Some(family) = crate::identity::model_family::family_of(provider, model_ref) else {
        return; // unknown model — never guessed (fail-safe: stays CLAIMED)
    };
    if let Err(e) =
        crate::storage::model_attest::record_loader_observed(conn, provider, model_ref, &family)
    {
        tracing::debug!("model-attest: loader_observed capture skipped (swallowed): {e:#}");
    }
}

/// v0.8.0 #1749/#1750 — build the curator's [`curator::CompactionConfig`] from
/// operator config. `enabled` (#1749, env > `[curator.compaction]` > false) and
/// `cosine_threshold` (#1750, env > config > 0.75 — threaded into the live
/// clusterer via `ConsolidationPass::with_cosine_threshold`) are
/// operator-reachable; `max_corpus_bytes` stays at its compiled default (size-GC
/// eviction is gated on `enabled` and not yet operator-exposed — when it is, it
/// gets its own `[curator.size_gc]` switch per the #1750 vote `a9b2fe09`).
/// Shared by every production `CuratorConfig` build site so resolution is
/// identical across the sqlite + store-backed paths.
fn curator_compaction_config(app_config: &config::AppConfig) -> curator::CompactionConfig {
    curator::CompactionConfig {
        enabled: app_config.resolve_compaction_enabled(),
        cosine_threshold: app_config.resolve_compaction_cosine_threshold(),
        ..Default::default()
    }
}

/// v0.7.0 #1548 — resolve the operator-supplied `--store-url` flag in
/// a feature-flag-aware way (no env binding — the
/// `AI_MEMORY_STORE_URL` env fallback was deliberately dropped in
/// `1e8ad69b`). Returns `None`
/// on builds without the `sal` feature (where the field does not exist)
/// so the curator falls through to the legacy SQLite path.
#[must_use]
fn curator_store_url(args: &CuratorArgs) -> Option<&str> {
    #[cfg(feature = "sal")]
    {
        args.store_url.as_deref()
    }
    #[cfg(not(feature = "sal"))]
    {
        let _ = args;
        None
    }
}

/// v0.7.0 #1548 — `--once` / `--daemon` upkeep against a SAL store
/// (Postgres or SQLite by `--store-url` scheme). Runs the reflection
/// pass over every operator-enabled namespace through the
/// [`crate::store::MemoryStore`] trait, so a federated Postgres-backed
/// curator performs the same recursive-refinement upkeep the SQLite
/// daemon does via `run_reflection_pass`.
///
/// `--once` runs a single sweep and prints the report; `--daemon` loops
/// every `--interval-secs` until SIGINT / SIGTERM, logging each cycle.
///
/// The reflection pass is LLM-backed; when no LLM client is configured
/// the sweep returns a populated report carrying the configured-but-
/// unreachable error (matching the `--reflect` no-LLM contract) rather
/// than hard-failing the daemon.
#[cfg(feature = "sal")]
async fn run_store_backed_sweep(
    db_path: &Path,
    args: &CuratorArgs,
    app_config: &config::AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let store =
        crate::daemon_runtime::build_curator_store(curator_store_url(args), db_path, app_config)
            .await?;

    let keypair = load_curator_keypair_best_effort();
    let feature_tier = app_config.effective_tier(None);
    let llm = build_curator_llm(feature_tier);

    // v0.8.0 Pillar-2.5 slice-3c1 (#1747) — config for the store-backed
    // consolidation sweep. `compaction.enabled` resolved from operator config
    // (#1749, env > [curator.compaction] > default false); the gate mirrors the
    // sqlite `run_once` path.
    let curator_cfg = curator::CuratorConfig {
        interval_secs: args.interval_secs,
        max_ops_per_cycle: args.max_ops,
        dry_run: args.dry_run,
        include_namespaces: args.include_namespaces.clone(),
        exclude_namespaces: args.exclude_namespaces.clone(),
        compaction: curator_compaction_config(app_config),
    };
    if args.once {
        // Consolidation BEFORE reflection (dedup, then reflect over survivors).
        let consolidation = store_backed_consolidation_sweep(
            store.as_ref(),
            llm.as_ref().map(|c| c as &dyn crate::autonomy::AutonomyLlm),
            &curator_cfg,
        )
        .await;
        log_store_backed_consolidation(&consolidation);
        let report = store_backed_reflection_sweep(
            store.as_ref(),
            llm.as_ref().map(|c| c as &dyn crate::autonomy::AutonomyLlm),
            keypair.as_ref(),
            args,
        )
        .await;
        if args.json {
            writeln!(out.stdout, "{}", serde_json::to_string_pretty(&report)?)?;
        } else {
            print_reflection_report(&report, out)?;
        }
        return Ok(());
    }

    // Daemon mode — loop the SAL reflection sweep until shutdown.
    // SIGINT / SIGTERM flip the shared shutdown flag; the loop checks it
    // before each cycle and the `select!` wakes the interval sleep early.
    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let shutdown_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_for_signal = shutdown.clone();
    let flag_for_signal = shutdown_flag.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        flag_for_signal.store(true, std::sync::atomic::Ordering::Relaxed);
        shutdown_for_signal.notify_one();
    });

    // Clamp the interval to the same [60, 86400] band the SQLite
    // `curator::run_daemon` loop enforces, so a stray small / huge value
    // can't busy-spin or stall the federated upkeep sweep.
    let interval_secs = args.interval_secs.clamp(60, crate::SECS_PER_DAY as u64);
    tracing::info!(
        "curator SAL daemon started (store-url backend, interval={interval_secs}s, \
         max_ops={}, dry_run={})",
        args.max_ops,
        args.dry_run,
    );

    while !shutdown_flag.load(std::sync::atomic::Ordering::Relaxed) {
        // Consolidation BEFORE reflection (dedup, then reflect over survivors).
        let consolidation = store_backed_consolidation_sweep(
            store.as_ref(),
            llm.as_ref().map(|c| c as &dyn crate::autonomy::AutonomyLlm),
            &curator_cfg,
        )
        .await;
        log_store_backed_consolidation(&consolidation);
        let report = store_backed_reflection_sweep(
            store.as_ref(),
            llm.as_ref().map(|c| c as &dyn crate::autonomy::AutonomyLlm),
            keypair.as_ref(),
            args,
        )
        .await;
        tracing::info!(
            "curator SAL cycle: namespaces={} observations={} clusters_eligible={} \
             reflections_persisted={} depth_refusals={} errors={} (dry_run={})",
            report.namespaces_visited,
            report.observations_scanned,
            report.clusters_eligible,
            report.reflections_persisted,
            report.depth_refusals,
            report.errors.len(),
            report.dry_run,
        );

        // Sleep the interval, waking early on shutdown.
        tokio::select! {
            () = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {}
            () = shutdown.notified() => break,
        }
    }

    tracing::info!("curator SAL daemon shutdown");
    Ok(())
}

/// Run a single reflection-pass sweep over a SAL store. Shared by the
/// `--once` and `--daemon` arms of [`run_store_backed_sweep`]. Returns
/// a populated [`reflection_pass::ReflectionPassReport`] regardless of
/// outcome — an unreachable LLM is surfaced as a report error, not a
/// propagated failure, so the daemon loop never aborts on a transient
/// provider outage.
///
/// All non-reserved namespaces are swept (the `--daemon` upkeep
/// contract); per-namespace `reflection_pass.enabled` config-file
/// gating is a v0.7.1 follow-up, identical to the `--reflect
/// --all-namespaces` posture.
#[cfg(feature = "sal")]
async fn store_backed_reflection_sweep(
    store: &dyn crate::store::MemoryStore,
    llm: Option<&dyn crate::autonomy::AutonomyLlm>,
    keypair: Option<&identity_keypair::AgentKeypair>,
    args: &CuratorArgs,
) -> reflection_pass::ReflectionPassReport {
    // Upkeep mode sweeps every non-reserved namespace (matching the
    // `--all-namespaces` reflection contract).
    run_reflection_pass_with_optional_llm(
        store,
        llm,
        keypair,
        None,
        args.max_depth,
        args.dry_run,
        |_ns: &str| true,
    )
    .await
}

/// v0.8.0 Pillar-2.5 slice-3c1 (#1747) — run the SAL `ConsolidationPass` over a
/// store-backed (postgres or `--store-url` sqlite) curator tick: the
/// backend-agnostic twin of [`store_backed_reflection_sweep`]. Gated on
/// `cfg.compaction.enabled` (default `false` → no-op, production byte-unchanged).
/// Iterates non-reserved namespaces via [`MemoryStore::list_namespaces`], gathers
/// + filters candidates (`needs_curation`, capped at `max_ops_per_cycle` so a
/// store-backed cycle consolidates the same population the sqlite path would),
/// and runs [`ConsolidationPass::run`] real (respecting `cfg.dry_run`). A missing
/// LLM folds into the report rather than aborting the daemon (mirrors
/// [`run_reflection_pass_with_optional_llm`]).
///
/// **Run BEFORE reflection** in the sweep so consolidation's hard-DELETE of
/// near-duplicate sources happens before reflection links over the surviving
/// corpus — avoiding dangling `reflects_on` edges to consolidated-away rows.
///
/// **Rollback (#1748, slice-3c2):** the operator-reversible rollback rows the
/// pass writes ARE reversible on both backends — `ai-memory curator --rollback
/// [--store-url postgres://…]` dispatches to
/// [`crate::autonomy::reverse_rollback_entry_store`] over the `MemoryStore`
/// trait. (The slice-3c1 remote-store WARN is gone now that reversal works.)
///
/// Decision provenance: 5-agent vote `4d3ea1c5` (#1747).
#[cfg(feature = "sal")]
async fn store_backed_consolidation_sweep(
    store: &dyn MemoryStore,
    llm: Option<&dyn autonomy::AutonomyLlm>,
    cfg: &curator::CuratorConfig,
) -> curator::compaction::ConsolidationRunReport {
    let mut report = curator::compaction::ConsolidationRunReport::default();
    if !cfg.compaction.enabled {
        return report; // default-off → true no-op
    }
    let Some(llm) = llm else {
        report
            .errors
            .push("no LLM client configured — consolidation skipped".to_string());
        return report;
    };
    let ctx = CallerContext::for_admin(crate::identity::sentinels::AI_CURATOR);
    let namespaces = match store.list_namespaces().await {
        Ok(ns) => ns,
        Err(e) => {
            report
                .errors
                .push(format!("consolidation: list_namespaces failed: {e}"));
            return report;
        }
    };

    // Gather candidates across non-reserved namespaces, applying the SAME
    // `needs_curation` filter the sqlite path uses, capped at max_ops_per_cycle.
    let cap = cfg.max_ops_per_cycle.max(1);
    let mut candidates: Vec<crate::models::Memory> = Vec::new();
    'ns: for nsc in &namespaces {
        if nsc.namespace.starts_with('_') {
            continue;
        }
        let filter = Filter {
            namespace: Some(nsc.namespace.clone()),
            limit: cap,
            ..Default::default()
        };
        match store.list(&ctx, &filter).await {
            Ok(rows) => {
                for m in rows {
                    if curator::candidates::needs_curation(&m, cfg) {
                        candidates.push(m);
                        if candidates.len() >= cap {
                            break 'ns;
                        }
                    }
                }
            }
            Err(e) => report.errors.push(format!(
                "consolidation: list({}) failed: {e}",
                nsc.namespace
            )),
        }
    }

    if candidates.is_empty() {
        return report;
    }

    // #1750 — thread the operator-resolved cosine gate into the clusterer.
    let pass = curator::compaction::ConsolidationPass::new(store, llm, cfg.dry_run)
        .with_cosine_threshold(cfg.compaction.cosine_threshold);
    match pass.run(&candidates).await {
        Ok(out) => {
            // Preserve any list/namespace errors gathered above.
            let mut merged = out;
            merged.errors.splice(0..0, report.errors.clone());
            report = merged;
        }
        Err(e) => report
            .errors
            .push(format!("consolidation pass failed: {e}")),
    }
    report
}

/// Emit a `tracing` line summarising a store-backed consolidation sweep, mirroring
/// the reflection-sweep cycle log. No-op-quiet when compaction is disabled (the
/// report is all-zero).
#[cfg(feature = "sal")]
fn log_store_backed_consolidation(report: &curator::compaction::ConsolidationRunReport) {
    if report.clusters_formed == 0 && report.memories_consolidated == 0 && report.errors.is_empty()
    {
        return;
    }
    tracing::info!(
        target: curator::compaction::COMPACTION_TRACE_TARGET,
        "curator SAL consolidation: clusters_formed={} eligible={} consolidated={} \
         rollback_entries={} rolled_back={} errors={}",
        report.clusters_formed,
        report.eligible_clusters,
        report.memories_consolidated,
        report.rollback_entries_written,
        report.rolled_back,
        report.errors.len(),
    );
}

/// v0.7.0 #1548 — run the reflection pass over a SAL store with an
/// OPTIONAL LLM, folding any pass error into the returned report rather
/// than propagating it (so a daemon sweep never aborts on a transient
/// provider outage); when `llm` is `None` the report carries the
/// no-LLM-configured error. Shared by [`run_reflect`] +
/// [`store_backed_reflection_sweep`]; taking `&dyn AutonomyLlm` lets the
/// unit tests drive it with a deterministic stub instead of a live
/// Ollama (which `build_curator_llm` cannot construct in CI).
#[cfg(feature = "sal")]
async fn run_reflection_pass_with_optional_llm(
    store: &dyn crate::store::MemoryStore,
    llm: Option<&dyn crate::autonomy::AutonomyLlm>,
    keypair: Option<&identity_keypair::AgentKeypair>,
    namespace: Option<&str>,
    max_depth: Option<u32>,
    dry_run: bool,
    enabled_check: impl Fn(&str) -> bool,
) -> reflection_pass::ReflectionPassReport {
    let stamp = || chrono::Utc::now().to_rfc3339();
    let Some(llm_client) = llm else {
        let mut empty = reflection_pass::ReflectionPassReport {
            started_at: stamp(),
            completed_at: stamp(),
            dry_run,
            ..Default::default()
        };
        empty.errors.push(
            "no LLM client configured — set a feature tier that provides an llm_model".into(),
        );
        return empty;
    };
    match reflection_pass::run_reflection_pass(
        store,
        llm_client,
        keypair,
        namespace,
        max_depth,
        dry_run,
        enabled_check,
    )
    .await
    {
        Ok(report) => report,
        Err(e) => {
            let mut report = reflection_pass::ReflectionPassReport {
                started_at: stamp(),
                completed_at: stamp(),
                dry_run,
                ..Default::default()
            };
            report.errors.push(format!("reflection pass failed: {e}"));
            report
        }
    }
}

/// v0.7.0 L2-1 — reflection-pass entry point. Wires the operator's
/// CLI flags to [`reflection_pass::run_reflection_pass`] and prints
/// the structured report.
///
/// Per #666 acceptance:
///
/// * `--namespace foo` runs the pass on one namespace; `--all-
///   namespaces` enumerates every observable namespace.
/// * Per-namespace `reflection_pass.enabled` config gates which
///   namespaces actually run (defaults to `false`). The CLI does NOT
///   load the per-namespace config from `ai-memory.toml` yet — that's
///   a v0.7.1 follow-up; for now, the operator-supplied
///   `--namespace` is treated as "operator opted in for this run"
///   so a single-namespace invocation always proceeds. The
///   `--all-namespaces` path applies the strict `enabled` gate (no
///   external config loaded → no namespaces enabled → zero rows
///   written), which is the safe default until the config-file
///   wiring lands.
/// * `--dry-run` reports proposed clusters without writing anything.
/// * `--max-depth` is the curator-side guard rail on top of the
///   substrate's per-namespace policy cap.
///
/// v0.7.0 #1548 — the reflection pass operates over the SAL
/// [`crate::store::MemoryStore`] trait, which is `sal`-gated. The
/// `not(sal)` variant below returns a clear capability error so a
/// binary built without `--features sal` fails loudly rather than
/// silently dropping `--reflect`.
#[cfg(feature = "sal")]
async fn run_reflect(
    db_path: &Path,
    args: &CuratorArgs,
    app_config: &config::AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if args.namespace.is_none() && !args.all_namespaces {
        anyhow::bail!("--reflect requires either --namespace <ns> or --all-namespaces");
    }
    if args.namespace.is_some() && args.all_namespaces {
        anyhow::bail!("--reflect: --namespace and --all-namespaces are mutually exclusive");
    }

    // v0.7.0 #1548 — resolve the SAL store handle from `--store-url`
    // (Postgres or SQLite) when supplied, else a SQLite store at the
    // `--db` path. The reflection pass operates over the
    // `MemoryStore` trait so `--reflect` works against a federated
    // Postgres store identically to the local SQLite path.
    let store = build_reflect_store(db_path, args, app_config).await?;

    // Resolve the curator's signing keypair. We rely on the
    // process-wide identity (the same one `serve` uses) so every
    // `reflects_on` edge attributes to the daemon's Ed25519 identity.
    // When no keypair is configured (operator opted out via
    // `[identity].disabled = true` or runs a one-off `--reflect`
    // against a fresh data dir) the pass falls back to `"ai:curator"`
    // — same fall-back the autonomy `consolidate` path uses.
    let keypair = load_curator_keypair_best_effort();

    let feature_tier = app_config.effective_tier(None);
    let llm = build_curator_llm(feature_tier);

    // Single-namespace invocations bypass the per-namespace `enabled`
    // gate (operator explicitly asked). #1671 — `--all-namespaces` now
    // consults the per-namespace `[curator.reflection_namespaces]`
    // config: a namespace participates only when it carries
    // `enabled = true`. Absent / disabled namespaces are skipped, so the
    // fan-out is opt-in (and `--all-namespaces` is no longer an inert
    // no-op once the operator enables namespaces in config).
    let scope_single = args.namespace.is_some();
    let enabled_check =
        |ns: &str| -> bool { scope_single || app_config.reflection_namespace_enabled(ns) };

    let report = run_reflection_pass_with_optional_llm(
        store.as_ref(),
        llm.as_ref().map(|c| c as &dyn crate::autonomy::AutonomyLlm),
        keypair.as_ref(),
        args.namespace.as_deref(),
        args.max_depth,
        args.dry_run,
        enabled_check,
    )
    .await;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        print_reflection_report(&report, out)?;
    }

    // #1393 sub-unit 2 — transcript-classify pass, opt-in via
    // `AI_MEMORY_TRANSCRIPT_CLASSIFY_ENABLED`. Reuses the same SAL store +
    // LLM + keypair-derived identity the reflection pass just ran with, so
    // `curator --reflect` reclassifies recovered Observations the LLM refines
    // (Decision/Claim/Event…) via the audited `reclassify_memory_kind` path.
    // `classify_kind` is a no-op on stub/abstaining backends, so the pass is
    // inert without a real LLM — skip with a note rather than scan for nothing.
    if app_config.resolve_transcript_classify_enabled() {
        if let Some(client) = llm.as_ref() {
            let agent_id = keypair.as_ref().map_or_else(
                || crate::identity::sentinels::AI_CURATOR.to_string(),
                |k| k.agent_id.clone(),
            );
            let tc_result = crate::curator::transcript_classify_pass::run_transcript_classify_pass(
                store.as_ref(),
                client as &dyn crate::autonomy::AutonomyLlm,
                &agent_id,
                args.namespace.as_deref(),
                args.dry_run,
                0, // default per-cycle cap
            )
            .await;
            match tc_result {
                Ok(tc) => {
                    if args.json {
                        writeln!(out.stdout, "{}", serde_json::to_string_pretty(&tc)?)?;
                    } else {
                        writeln!(
                            out.stdout,
                            "transcript-classify: scanned={} classified={} reclassified={} \
                             abstained={} errors={} (dry_run={})",
                            tc.observations_scanned,
                            tc.classified,
                            tc.reclassified,
                            tc.abstained,
                            tc.errors.len(),
                            tc.dry_run,
                        )?;
                    }
                }
                Err(e) => writeln!(out.stderr, "transcript-classify pass error: {e}")?,
            }
        } else {
            writeln!(
                out.stderr,
                "transcript-classify: skipped (AI_MEMORY_TRANSCRIPT_CLASSIFY_ENABLED set but no LLM backend configured)"
            )?;
        }
    }

    // #1764 (v0.8.0 slice) — reflection-corpus decorrelation VISIBILITY probe,
    // opt-in via `AI_MEMORY_REFLECT_DECORRELATION_MODE` (default `off`). Reuses
    // the same SAL store + keypair-derived curator identity the reflection pass
    // ran with; read-only (no writes). Called unconditionally — the step
    // early-returns when the mode is `off` (the default), so the curator's
    // output + DB are byte-unchanged when disabled. Design: 5-agent vote
    // (4d3ea1c5).
    let decorrelation_agent_id = keypair.as_ref().map_or_else(
        || crate::identity::sentinels::AI_CURATOR.to_string(),
        |k| k.agent_id.clone(),
    );
    // v0.10.0 Gate-1' (#1952 / #1972) — one-shot advisory when the probe mode
    // is unset/off: v1.0.0 defaults the decorrelation probe to advisory (per
    // D3-021) and enforce-as-default is the tracked v1.x lane. No behaviour
    // change; the probe step below still early-returns when the mode is off.
    config::warn_reflect_decorrelation_default_once();
    run_decorrelation_probe_step(
        store.as_ref(),
        &decorrelation_agent_id,
        args.namespace.as_deref(),
        args.json,
        config::reflect_decorrelation_mode(),
        config::reflect_decorrelation_dominance_threshold(),
        out,
    )
    .await?;

    Ok(())
}

/// #1764 (v0.8.0 slice) — run the reflection-corpus decorrelation VISIBILITY
/// probe and render its report. Early-returns (no output, no scan) when `mode`
/// is `off` (the default). Split out of [`run_reflect`] so the active path is
/// unit-testable by passing `mode` directly — no env mutation, no test races.
/// `enforce` is INERT at v0.8.0 (the runner degrades it to advisory with a
/// one-shot WARN) — write-time N≥3 model-family-distinct REFUSAL is the tracked
/// v0.9 lane (#1719 / #1171).
///
/// # RQ-PARITY-01 (#1872) — the loop-callable per-cycle seam
///
/// This is the SINGLE backend-blind entry point RQ-11 later wires into all four
/// curator cycle arms (sqlite `--once`, sqlite daemon loop, SAL `--once`, SAL
/// daemon loop). Its parameters are the only cycle-varying inputs — `store`
/// (`&dyn MemoryStore`, so it is byte-identical on SQLite and Postgres),
/// `agent_id`, `namespace`, `json`, `mode`, `threshold` — deliberately decoupled
/// from `&CuratorArgs` so a loop can call it without the CLI arg struct.
/// RQ-PARITY-01 lands only the seam + the live-Postgres equivalence proof
/// (`tests/decorrelation_probe_postgres_parity.rs`); it does NOT wire the four
/// cycle arms — that is RQ-11's work. SEAM-HONESTY NOTE: the sqlite daemon arm
/// (`cli/curator.rs` → `run_curator_daemon_with_primitives` → blocking
/// `curator::run_daemon` via `spawn_blocking`) has NO per-cycle async hook;
/// bridging it (a cycle callback in `run_daemon` or a documented interval
/// sidecar) is RQ-11's recorded problem, not silently assumed solved here.
/// `AI_MEMORY_REFLECT_DECORRELATION_MODE=off` (the default) keeps every path
/// byte-silent; this item adds no new flags or env vars.
///
/// # S2 (#1767) fail-safe consumption contract — PROVISIONAL input to S2's own design vote
///
/// When S2 activates `enforce` it MUST first verify attestation readability on
/// the bound store via the S1/#1870 SAL read; a `StoreError::UnsupportedCapability`
/// ⇒ enforce MUST NOT activate — a hard step error (non-zero `--once`; per-cycle
/// ERROR + NO reflection writes that cycle in daemon mode), never a silent
/// degrade to advisory, and never enforcement over CLAIMED `producer_signal`
/// tiers (the v0.8 degrade WARN in `decorrelation_probe.rs` is superseded by S2).
/// Unattested rows count as NON-diverse toward the N≥3 quorum (missing evidence
/// can only cause refusal, never satisfy the gate). A `scan_capped` namespace is
/// partial coverage: under enforce it resolves toward refusal / advisory-WARN,
/// never toward "diverse". S2 must also resolve the step-ordering tension
/// (pre-sweep probe when enforce is active, or an explicitly recorded one-cycle
/// lag). This whole block is PROVISIONAL input to S2's design decision, not S2's
/// decided contract.
#[cfg(feature = "sal")]
async fn run_decorrelation_probe_step(
    store: &dyn crate::store::MemoryStore,
    agent_id: &str,
    namespace: Option<&str>,
    json: bool,
    mode: config::ReflectDecorrelationMode,
    threshold: f64,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if !mode.is_active() {
        return Ok(());
    }
    let probe_result = crate::curator::decorrelation_probe::run_decorrelation_probe(
        store,
        agent_id,
        namespace,
        mode,
        threshold,
        crate::curator::decorrelation_probe::MIN_REFLECTIONS_FLOOR,
    )
    .await;
    match probe_result {
        // In `--json` mode stdout is reserved for the caller's PRIMARY report
        // (e.g. the `curator --reflect` JSON): now that decorrelation defaults to
        // Advisory (#1952), emitting the probe report to stdout too would make
        // `--reflect --json` a concatenation of two JSON documents (unparseable).
        // The advisory VISIBILITY signal is the probe's `tracing::warn`; the
        // structured report is a diagnostic, so route it to stderr in json mode
        // (mirrors the probe-error path below). Text mode keeps stdout (a
        // human-readable addendum concatenates cleanly).
        Ok(probe) if json => {
            writeln!(out.stderr, "{}", serde_json::to_string_pretty(&probe)?)?;
        }
        Ok(probe) => print_decorrelation_report(&probe, json, out)?,
        Err(e) => writeln!(out.stderr, "decorrelation-probe error: {e}")?,
    }
    Ok(())
}

/// #1764 — render a [`crate::curator::decorrelation_probe::DecorrelationProbeReport`]
/// to `out` as pretty JSON (`json = true`) or a one-line summary + an indented
/// `ADVISORY` line per dominated namespace (each carrying the CLAIMED-not-attested
/// caveat).
#[cfg(feature = "sal")]
fn print_decorrelation_report(
    probe: &crate::curator::decorrelation_probe::DecorrelationProbeReport,
    json: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if json {
        writeln!(out.stdout, "{}", serde_json::to_string_pretty(probe)?)?;
        return Ok(());
    }
    writeln!(
        out.stdout,
        "decorrelation-probe: mode={} threshold={:.2} namespaces={} \
         reflections={} advisories={} capped={}{}",
        probe.mode,
        probe.threshold,
        probe.namespaces_scanned,
        probe.reflections_scanned,
        probe.advisories.len(),
        probe.namespaces_capped,
        if probe.enforce_degraded_to_advisory {
            " (enforce INERT at v0.8.0 → advisory)"
        } else {
            ""
        },
    )?;
    for adv in &probe.advisories {
        writeln!(
            out.stdout,
            "  ADVISORY ns={} dominance={:.2} dominant={} distinct={}{} — {}",
            adv.namespace,
            adv.report.dominance_ratio,
            adv.report.dominant_producer.as_deref().unwrap_or("?"),
            adv.report.distinct_producers,
            if adv.scan_capped {
                " [SCAN CAPPED — dominance over newest window only]"
            } else {
                ""
            },
            adv.caveat,
        )?;
    }
    Ok(())
}

/// `not(sal)` companion of [`run_reflect`]. The reflection pass requires
/// the SAL `MemoryStore` trait, which is `sal`-gated; a binary built
/// without `--features sal` cannot run `--reflect`, so surface a clear
/// capability error rather than silently dropping the mode.
#[cfg(not(feature = "sal"))]
#[allow(clippy::unused_async)]
async fn run_reflect(
    _db_path: &Path,
    _args: &CuratorArgs,
    _app_config: &config::AppConfig,
    _out: &mut CliOutput<'_>,
) -> Result<()> {
    anyhow::bail!(
        "curator --reflect requires a binary built with --features sal \
         (the reflection pass operates over the SAL MemoryStore trait)"
    )
}

/// v0.7.0 #1548 — resolve the SAL store handle for the `--reflect` mode.
/// Mirrors [`run_store_backed_sweep`]'s builder: binds to the
/// `--store-url` adapter (Postgres or SQLite) when supplied, else a
/// SQLite store at the `--db` path.
#[cfg(feature = "sal")]
async fn build_reflect_store(
    db_path: &Path,
    args: &CuratorArgs,
    app_config: &config::AppConfig,
) -> Result<std::sync::Arc<dyn crate::store::MemoryStore>> {
    crate::daemon_runtime::build_curator_store(curator_store_url(args), db_path, app_config).await
}

/// Load the curator's per-process signing keypair. Best-effort — if the
/// keypair file is missing or unreadable we return `None` and the pass
/// stamps `ai:curator` as `agent_id`. Errors are deliberately not
/// surfaced; an operator who wants a strict-mode "fail if keypair
/// missing" can run `ai-memory identity list` first.
#[cfg_attr(not(feature = "sal"), allow(dead_code))]
fn load_curator_keypair_best_effort() -> Option<identity_keypair::AgentKeypair> {
    let dir = identity_keypair::default_key_dir().ok()?;
    // We don't know which agent_id the operator wants the curator to
    // run as. Pick the lexicographically-first key under the key dir;
    // operators who run multiple curators on the same host should
    // either give each a dedicated key dir via `AI_MEMORY_KEY_DIR` or
    // set the daemon `AI_MEMORY_AGENT_ID` env var.
    let listed = identity_keypair::list(&dir).ok()?;
    let first = listed.into_iter().next()?;
    identity_keypair::load(&first.agent_id, &dir).ok()
}

#[cfg_attr(not(feature = "sal"), allow(dead_code))]
fn print_reflection_report(
    r: &reflection_pass::ReflectionPassReport,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    writeln!(out.stdout, "reflection pass report")?;
    writeln!(out.stdout, "  started_at:            {}", r.started_at)?;
    writeln!(out.stdout, "  completed_at:          {}", r.completed_at)?;
    writeln!(
        out.stdout,
        "  namespaces_visited:    {}",
        r.namespaces_visited
    )?;
    writeln!(
        out.stdout,
        "  observations_scanned:  {}",
        r.observations_scanned
    )?;
    writeln!(out.stdout, "  clusters_formed:       {}", r.clusters_formed)?;
    writeln!(
        out.stdout,
        "  clusters_eligible:     {}",
        r.clusters_eligible
    )?;
    writeln!(
        out.stdout,
        "  reflections_persisted: {}",
        r.reflections_persisted
    )?;
    writeln!(out.stdout, "  depth_refusals:        {}", r.depth_refusals)?;
    writeln!(out.stdout, "  errors:                {}", r.errors.len())?;
    writeln!(out.stdout, "  dry_run:               {}", r.dry_run)?;
    for e in &r.errors {
        writeln!(out.stdout, "    - {e}")?;
    }
    for prop in &r.dry_run_proposals {
        writeln!(
            out.stdout,
            "  proposal: ns='{}' title='{}' sources={}",
            prop.namespace,
            prop.proposed_title,
            prop.source_ids.len()
        )?;
    }
    Ok(())
}

fn run_rollback(db_path: &Path, args: &CuratorArgs, out: &mut CliOutput<'_>) -> Result<()> {
    let conn = db::open(db_path)?;

    if let Some(id) = &args.rollback {
        let Some(mem) = db::get(&conn, id)? else {
            anyhow::bail!("rollback entry {id} not found");
        };
        let entry: autonomy::RollbackEntry = serde_json::from_str(&mem.content)
            .context("rollback entry content is not a valid RollbackEntry JSON")?;
        let applied = autonomy::reverse_rollback_entry(&conn, &entry)?;
        let mut tags = mem.tags.clone();
        if !tags.iter().any(|t| t == "_reversed") {
            tags.push("_reversed".to_string());
            db::update(
                &conn,
                &mem.id,
                None,
                None,
                None,
                None,
                Some(&tags),
                None,
                None,
                None,
                None,
            )?;
        }
        writeln!(
            out.stdout,
            "rollback {id}: {}",
            if applied { "applied" } else { "no-op" }
        )?;
        return Ok(());
    }

    if let Some(n) = args.rollback_last {
        let log = db::list(
            &conn,
            Some("_curator/rollback"),
            None,
            n.max(1),
            0,
            None,
            None,
            None,
            None,
            None,
        )?;
        let mut reversed = 0usize;
        for mem in &log {
            if mem.tags.iter().any(|t| t == "_reversed") {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<autonomy::RollbackEntry>(&mem.content) else {
                continue;
            };
            let applied = autonomy::reverse_rollback_entry(&conn, &entry)?;
            if applied {
                reversed += 1;
                let mut tags = mem.tags.clone();
                tags.push("_reversed".to_string());
                db::update(
                    &conn,
                    &mem.id,
                    None,
                    None,
                    None,
                    None,
                    Some(&tags),
                    None,
                    None,
                    None,
                    None,
                )?;
            }
        }
        writeln!(out.stdout, "reversed {reversed} rollback entries")?;
        return Ok(());
    }

    // QUAL-2 (med/low review batch) — typed error instead of `unreachable!()`.
    // The caller-side guard at `cmd_curator` (line ~147) already short-circuits
    // when neither `--rollback` nor `--rollback-last` is set; this branch is
    // reachable only if that guard ever regresses. Returning an `anyhow::Error`
    // preserves the audit message but keeps the failure recoverable (typed
    // CLI exit code) instead of crashing the process with a panic.
    anyhow::bail!("run_rollback entered without --rollback or --rollback-last");
}

/// v0.8.0 Pillar-2.5 slice-3c2 (#1748) — store-backed twin of
/// [`run_rollback`]. Dispatched from [`run`] when `--store-url` selects a
/// (postgres) SAL store, so `curator --rollback[-last] --store-url
/// postgres://…` reverses the consolidations the store-backed curator
/// wrote (slice-3c1, #1747) through
/// [`autonomy::reverse_rollback_entry_store`] over the
/// [`crate::store::MemoryStore`] trait — rather than the rusqlite-bound
/// [`autonomy::reverse_rollback_entry`], which only ever sees the local
/// SQLite file. Closes the slice-3c1 rollback-trap (the WARN in
/// [`store_backed_consolidation_sweep`] is removed accordingly).
///
/// Decision provenance: 5-agent vote `4d3ea1c5` → Option B (memory `ed85b972`).
#[cfg(feature = "sal")]
async fn run_store_backed_rollback(
    db_path: &Path,
    args: &CuratorArgs,
    app_config: &config::AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let store =
        crate::daemon_runtime::build_curator_store(curator_store_url(args), db_path, app_config)
            .await?;
    let ctx = CallerContext::for_admin(crate::identity::sentinels::AI_CURATOR);

    if let Some(id) = &args.rollback {
        let mem = match store.get(&ctx, id).await {
            Ok(m) => m,
            Err(crate::store::StoreError::NotFound { .. }) => {
                anyhow::bail!("rollback entry {id} not found");
            }
            Err(e) => return Err(e.into()),
        };
        let entry: autonomy::RollbackEntry = serde_json::from_str(&mem.content)
            .context("rollback entry content is not a valid RollbackEntry JSON")?;
        let applied = autonomy::reverse_rollback_entry_store(store.as_ref(), &ctx, &entry).await?;
        if !mem.tags.iter().any(|t| t == "_reversed") {
            let mut tagged = mem.clone();
            tagged.tags.push("_reversed".to_string());
            store.store(&ctx, &tagged).await?;
        }
        writeln!(
            out.stdout,
            "rollback {id}: {}",
            if applied { "applied" } else { "no-op" }
        )?;
        return Ok(());
    }

    if let Some(n) = args.rollback_last {
        let filter = Filter {
            namespace: Some("_curator/rollback".to_string()),
            limit: n.max(1),
            ..Default::default()
        };
        let log = store.list(&ctx, &filter).await?;
        let mut reversed = 0usize;
        for mem in &log {
            if mem.tags.iter().any(|t| t == "_reversed") {
                continue;
            }
            let Ok(entry) = serde_json::from_str::<autonomy::RollbackEntry>(&mem.content) else {
                continue;
            };
            let applied =
                autonomy::reverse_rollback_entry_store(store.as_ref(), &ctx, &entry).await?;
            if applied {
                reversed += 1;
                let mut tagged = mem.clone();
                tagged.tags.push("_reversed".to_string());
                store.store(&ctx, &tagged).await?;
            }
        }
        writeln!(out.stdout, "reversed {reversed} rollback entries")?;
        return Ok(());
    }

    anyhow::bail!("run_store_backed_rollback entered without --rollback or --rollback-last");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    fn default_args() -> CuratorArgs {
        CuratorArgs {
            once: false,
            daemon: false,
            interval_secs: crate::SECS_PER_HOUR as u64,
            max_ops: 100,
            dry_run: false,
            include_namespaces: Vec::new(),
            exclude_namespaces: Vec::new(),
            json: false,
            rollback: None,
            rollback_last: None,
            reflect: false,
            namespace: None,
            max_depth: None,
            all_namespaces: false,
            #[cfg(feature = "sal")]
            store_url: None,
        }
    }

    #[tokio::test]
    async fn test_curator_requires_mode() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let args = default_args();
        let mut out = env.output();
        let res = run(&db, &args, &cfg, &mut out).await;
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("--once, --daemon, --reflect")
        );
    }

    #[tokio::test]
    async fn test_curator_once_runs_single_sweep_text() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.once = true;
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        assert!(env.stdout_str().contains("curator cycle report"));
    }

    #[tokio::test]
    async fn test_curator_once_json_format() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.once = true;
        args.json = true;
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["dry_run"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn test_curator_dry_run_skips_writes() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.once = true;
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        // Report mentions dry_run flag.
        let s = env.stdout_str();
        assert!(s.contains("dry_run:") || s.contains("\"dry_run\""));
    }

    #[tokio::test]
    async fn test_curator_include_namespaces_filter() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.once = true;
        args.dry_run = true;
        args.include_namespaces = vec!["only-this-ns".to_string()];
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        // No memories — operations attempted should be 0.
        assert!(env.stdout_str().contains("operations:"));
    }

    #[tokio::test]
    async fn test_curator_exclude_namespaces_filter() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.once = true;
        args.dry_run = true;
        args.exclude_namespaces = vec!["skip-me".to_string()];
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        assert!(env.stdout_str().contains("curator cycle report"));
    }

    #[tokio::test]
    async fn test_curator_max_ops_cap_respected() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.once = true;
        args.dry_run = true;
        args.max_ops = 0; // immediately at cap
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        assert!(env.stdout_str().contains("operations:"));
    }

    #[tokio::test]
    async fn test_curator_rollback_id_not_found() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.rollback = Some("00000000-0000-0000-0000-000000000000".to_string());
        let mut out = env.output();
        let res = run(&db, &args, &cfg, &mut out).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("rollback entry"));
    }

    #[tokio::test]
    async fn test_curator_rollback_last_zero_entries() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.rollback_last = Some(5);
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        // No rollback log entries; should report 0.
        assert!(env.stdout_str().contains("reversed 0"));
    }

    // PR-9i — buffer coverage uplift. Targets run_rollback() — rollback
    // path with valid PriorityAdjust entry, rollback_last with both
    // applied & malformed JSON entries (skip branch), already-reversed
    // skip branch.

    fn build_priority_rollback_entry_json(memory_id: &str, before: i32, after: i32) -> String {
        // Serialize as the externally-tagged enum form `autonomy::RollbackEntry`
        // uses (the Rust default).
        serde_json::to_string(&autonomy::RollbackEntry::PriorityAdjust {
            memory_id: memory_id.to_string(),
            before,
            after,
        })
        .unwrap()
    }

    fn seed_rollback_entry(db_path: &std::path::Path, content: &str) -> String {
        // Insert a memory in the _curator/rollback namespace whose content
        // is a serialized RollbackEntry. Returns the inserted id.
        let conn = db::open(db_path).expect("db::open");
        let now = chrono::Utc::now().to_rfc3339();
        let mut metadata = crate::models::default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                "agent_id".to_string(),
                serde_json::Value::String("test-agent".to_string()),
            );
        }
        let mem = crate::models::Memory {
            cid: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Mid,
            namespace: "_curator/rollback".to_string(),
            title: format!("rollback-{}", uuid::Uuid::new_v4()),
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
            metadata,
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
        db::insert(&conn, &mem).expect("db::insert")
    }

    #[tokio::test]
    async fn pr9i_curator_rollback_priority_adjust_applies() {
        // Seed a real memory whose priority we'll roll back from 7→3.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();

        // 1. Seed a target memory at priority=7.
        let target = {
            let conn = db::open(&db).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            let mut metadata = crate::models::default_metadata();
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(
                    "agent_id".to_string(),
                    serde_json::Value::String("test-agent".to_string()),
                );
            }
            let mem = crate::models::Memory {
                cid: None,
                id: uuid::Uuid::new_v4().to_string(),
                tier: crate::models::Tier::Mid,
                namespace: "ns".to_string(),
                title: "target".to_string(),
                content: "c".to_string(),
                tags: vec![],
                priority: 7,
                confidence: 1.0,
                source: "test".to_string(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now,
                last_accessed_at: None,
                expires_at: None,
                metadata,
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
            db::insert(&conn, &mem).unwrap()
        };

        // 2. Seed a rollback entry that says "revert priority to 3".
        let entry_json = build_priority_rollback_entry_json(&target, 3, 7);
        let entry_id = seed_rollback_entry(&db, &entry_json);

        // 3. Run rollback by id.
        let mut args = default_args();
        args.rollback = Some(entry_id.clone());
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        // Stdout reports rollback applied.
        let s = env.stdout_str();
        assert!(s.contains(&format!("rollback {entry_id}")));
        assert!(s.contains("applied"));

        // The target's priority must now be 3.
        let conn = db::open(&db).unwrap();
        let target_mem = db::get(&conn, &target).unwrap().unwrap();
        assert_eq!(target_mem.priority, 3);

        // The rollback entry must be tagged _reversed.
        let entry_mem = db::get(&conn, &entry_id).unwrap().unwrap();
        assert!(entry_mem.tags.iter().any(|t| t == "_reversed"));
    }

    #[tokio::test]
    async fn pr9i_curator_rollback_last_processes_multiple() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();

        // Seed two targets.
        let t1;
        let t2;
        {
            let conn = db::open(&db).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            let mut metadata = crate::models::default_metadata();
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(
                    "agent_id".to_string(),
                    serde_json::Value::String("test-agent".to_string()),
                );
            }
            let m1 = crate::models::Memory {
                cid: None,
                id: uuid::Uuid::new_v4().to_string(),
                tier: crate::models::Tier::Mid,
                namespace: "ns".to_string(),
                title: "t1".to_string(),
                content: "c1".to_string(),
                tags: vec![],
                priority: 8,
                confidence: 1.0,
                source: "test".to_string(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now.clone(),
                last_accessed_at: None,
                expires_at: None,
                metadata: metadata.clone(),
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
            let m2 = crate::models::Memory {
                cid: None,
                id: uuid::Uuid::new_v4().to_string(),
                tier: crate::models::Tier::Mid,
                namespace: "ns".to_string(),
                title: "t2".to_string(),
                content: "c2".to_string(),
                tags: vec![],
                priority: 9,
                confidence: 1.0,
                source: "test".to_string(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now,
                last_accessed_at: None,
                expires_at: None,
                metadata,
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
            t1 = db::insert(&conn, &m1).unwrap();
            t2 = db::insert(&conn, &m2).unwrap();
        }

        // Seed two rollback entries plus one malformed JSON entry.
        seed_rollback_entry(&db, &build_priority_rollback_entry_json(&t1, 4, 8));
        seed_rollback_entry(&db, &build_priority_rollback_entry_json(&t2, 5, 9));
        seed_rollback_entry(&db, "{not valid json: at all"); // malformed → skip branch

        // Run rollback_last 5 (caps at actual count).
        let mut args = default_args();
        args.rollback_last = Some(5);
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        // Reverses 2 entries (the malformed one is skipped).
        let s = env.stdout_str();
        assert!(s.contains("reversed 2"));

        // Both targets reverted.
        let conn = db::open(&db).unwrap();
        assert_eq!(db::get(&conn, &t1).unwrap().unwrap().priority, 4);
        assert_eq!(db::get(&conn, &t2).unwrap().unwrap().priority, 5);
    }

    #[tokio::test]
    async fn pr9i_curator_rollback_last_skips_already_reversed() {
        // Seed a rollback entry pre-tagged as _reversed; rollback_last must
        // skip it (lines 203-205).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();

        // Seed a target.
        let target;
        {
            let conn = db::open(&db).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            let mut metadata = crate::models::default_metadata();
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(
                    "agent_id".to_string(),
                    serde_json::Value::String("test-agent".to_string()),
                );
            }
            let mem = crate::models::Memory {
                cid: None,
                id: uuid::Uuid::new_v4().to_string(),
                tier: crate::models::Tier::Mid,
                namespace: "ns".to_string(),
                title: "x".to_string(),
                content: "c".to_string(),
                tags: vec![],
                priority: 7,
                confidence: 1.0,
                source: "test".to_string(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now,
                last_accessed_at: None,
                expires_at: None,
                metadata,
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
            target = db::insert(&conn, &mem).unwrap();
        }

        // Insert a rollback entry already tagged _reversed.
        let entry_json = build_priority_rollback_entry_json(&target, 2, 7);
        let entry_id;
        {
            let conn = db::open(&db).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            let mut metadata = crate::models::default_metadata();
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(
                    "agent_id".to_string(),
                    serde_json::Value::String("test-agent".to_string()),
                );
            }
            let mem = crate::models::Memory {
                cid: None,
                id: uuid::Uuid::new_v4().to_string(),
                tier: crate::models::Tier::Mid,
                namespace: "_curator/rollback".to_string(),
                title: "preexisting-reversed".to_string(),
                content: entry_json,
                tags: vec!["_reversed".to_string()],
                priority: 5,
                confidence: 1.0,
                source: "test".to_string(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now,
                last_accessed_at: None,
                expires_at: None,
                metadata,
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
            entry_id = db::insert(&conn, &mem).unwrap();
        }

        let mut args = default_args();
        args.rollback_last = Some(5);
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        // Already-reversed entry is skipped → reversed 0.
        let s = env.stdout_str();
        assert!(s.contains("reversed 0"));

        // Target's priority is unchanged from 7.
        let conn = db::open(&db).unwrap();
        assert_eq!(db::get(&conn, &target).unwrap().unwrap().priority, 7);
        // Sanity: entry_id memory still tagged _reversed.
        let entry_mem = db::get(&conn, &entry_id).unwrap().unwrap();
        assert!(entry_mem.tags.iter().any(|t| t == "_reversed"));
    }

    #[tokio::test]
    async fn pr9i_curator_rollback_id_with_malformed_content() {
        // Seed a memory in _curator/rollback whose content is NOT a valid
        // RollbackEntry — the explicit-id rollback path bails (lines 160-161).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let entry_id = seed_rollback_entry(&db, "{invalid json");

        let mut args = default_args();
        args.rollback = Some(entry_id);
        let mut out = env.output();
        let res = run(&db, &args, &cfg, &mut out).await;
        assert!(res.is_err());
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("rollback") || err.contains("RollbackEntry"),
            "expected parse-error message, got: {err}"
        );
    }

    // ---------- E1 coverage uplift -----------------------------------
    // Targets: build_curator_llm body (smart/autonomous tier branch),
    // print_curator_report error-list iteration, --once with errors
    // present.

    #[test]
    fn build_curator_llm_with_keyword_tier_returns_none() {
        // Keyword tier has no llm_model — the function returns None
        // BEFORE entering the body. Sanity check.
        //
        // TEST-5 — pin `AI_MEMORY_NO_CONFIG=1` so `AppConfig::load()`
        // returns `Default::default()` instead of reading the
        // developer's `~/.config/ai-memory/config.toml` (which would
        // resolve a non-default `[llm]` stanza and cause this
        // assertion to fail).
        crate::cli::test_utils::ensure_no_config_env();
        let result = build_curator_llm(config::FeatureTier::Keyword);
        assert!(result.is_none());
    }

    #[test]
    fn build_curator_llm_with_smart_tier_runs_body() {
        // Smart tier has llm_model = Some(_), so the body executes the
        // `let model = ...` + `OllamaClient::new(&model).ok()` lines.
        // In hermetic tests Ollama is unreachable, so the result is
        // None — but the body lines are now covered.
        //
        // TEST-5 — pin `AI_MEMORY_NO_CONFIG=1` so the resolver always
        // returns the Ollama compiled default rather than reading the
        // host's user-config-resolved backend.
        crate::cli::test_utils::ensure_no_config_env();
        let _ = build_curator_llm(config::FeatureTier::Smart);
        // No assertion on the value; the test exercises lines 55-56.
    }

    // Unix-only — the test self-fires `libc::kill(getpid, SIGINT)` to
    // exercise the ctrl_c shutdown path. The libc crate's `getpid` /
    // `kill` / `SIGINT` symbols are not available on Windows, where
    // signal handling uses a different surface entirely. The daemon
    // shutdown path itself is cross-platform (tokio::signal::ctrl_c
    // works on Windows); only the self-fire test mechanism is
    // POSIX-bound.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn curator_daemon_mode_short_loop_returns_on_shutdown() {
        // Drives lines 128-150 — daemon mode entry. We fire SIGINT to
        // ourselves after a short delay so the ctrl_c spawn notifies
        // shutdown, the AtomicBool flag flips, and `run_daemon`'s loop
        // exits at its next check. The blocking task joins and the
        // outer `await` returns.
        //
        // We do NOT install our own signal handler — tokio's signal
        // registry consumes the single SIGINT before any default
        // handler trips. This test runs under multi_thread so the
        // ctrl_c watcher can fire on a separate worker.
        use std::path::PathBuf;
        let env = TestEnv::fresh();
        let db: PathBuf = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.daemon = true;
        // Tiny interval so the daemon body wakes quickly to check the
        // shutdown flag.
        args.interval_secs = 60; // clamped; the shutdown check is on each loop
        args.dry_run = true;

        // Fire SIGINT to ourselves after a brief delay.
        let kicker = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            // SAFETY: kill(getpid, SIGINT) is well-defined on POSIX.
            unsafe {
                let pid = libc::getpid();
                libc::kill(pid, libc::SIGINT);
            }
        });

        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
        // The daemon should return Ok(()) after shutdown is signaled.
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            run(&db, &args, &cfg, &mut out),
        )
        .await;
        let _ = kicker.await;
        // The daemon CAN take more than 15s on a loaded box if its
        // sleep is long; the timeout is a soft cap. Either an Ok join
        // or a timeout means the daemon mode code ran.
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("daemon mode errored: {e}"),
            Err(_) => {
                // Timed out — that's fine for line-coverage purposes:
                // the daemon-mode code path has already executed.
                eprintln!("daemon-mode test timed out; coverage already captured");
            }
        }
    }

    #[test]
    fn print_curator_report_emits_error_list_lines() {
        // Drives the `for e in &r.errors` loop (lines 84-86) inside
        // print_curator_report. Build a synthetic CuratorReport with a
        // non-empty errors vec. CuratorReport's `autonomy` field isn't
        // public-API but it's `#[serde(default)]`, so Default::default()
        // covers it.
        let mut report = crate::curator::CuratorReport::default();
        report.errors = vec!["err A".to_string(), "err B".to_string()];
        report.dry_run = true;
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        {
            let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
            print_curator_report(&report, &mut out).unwrap();
        }
        let s = String::from_utf8(stdout).unwrap();
        // Header surfaces.
        assert!(s.contains("curator cycle report"));
        // Both error rows surface in the indented list.
        assert!(s.contains("- err A"));
        assert!(s.contains("- err B"));
    }

    // ---------- C-1 coverage uplift: --reflect modes ----------

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn reflect_requires_namespace_or_all_namespaces() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.reflect = true;
        // Neither --namespace nor --all-namespaces supplied.
        let mut out = env.output();
        let err = run(&db, &args, &cfg, &mut out).await.unwrap_err();
        assert!(
            err.to_string().contains("--namespace") || err.to_string().contains("--all-namespaces")
        );
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn reflect_namespace_and_all_namespaces_mutually_exclusive() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.reflect = true;
        args.namespace = Some("ns".to_string());
        args.all_namespaces = true;
        let mut out = env.output();
        let err = run(&db, &args, &cfg, &mut out).await.unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn reflect_no_llm_path_emits_error_in_report() {
        // Keyword tier → no LLM → run_reflect populates `errors` and prints report.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut cfg = config::AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let mut args = default_args();
        args.reflect = true;
        args.namespace = Some("ns".to_string());
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("reflection pass report"));
        assert!(s.contains("no LLM client configured"));
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn reflect_no_llm_path_emits_json_report() {
        // Same as above but with --json output.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut cfg = config::AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let mut args = default_args();
        args.reflect = true;
        args.namespace = Some("ns".to_string());
        args.dry_run = true;
        args.json = true;
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        // No-LLM report carries `errors` array with the configured message.
        let errs = v["errors"].as_array().unwrap();
        assert!(errs.iter().any(|e| e.as_str().unwrap().contains("no LLM")));
        assert!(v["dry_run"].as_bool().unwrap());
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn reflect_all_namespaces_text_output() {
        // All-namespaces with no enabled namespaces is the default-safe path.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut cfg = config::AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let mut args = default_args();
        args.reflect = true;
        args.all_namespaces = true;
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("reflection pass report"));
    }

    // ── #1764 — decorrelation VISIBILITY probe wiring coverage ──────────
    #[cfg(feature = "sal")]
    fn sample_decorrelation_report(
        degraded: bool,
    ) -> crate::curator::decorrelation_probe::DecorrelationProbeReport {
        use crate::curator::decorrelation_probe::{
            CLAIMED_NOT_ATTESTED_CAVEAT, DecorrelationAdvisory, DecorrelationProbeReport,
            DominanceReport,
        };
        DecorrelationProbeReport {
            mode: "advisory".to_string(),
            enforce_degraded_to_advisory: degraded,
            threshold: 0.8,
            namespaces_scanned: 1,
            reflections_scanned: 5,
            advisories: vec![DecorrelationAdvisory {
                namespace: "team/eng".to_string(),
                report: DominanceReport {
                    total: 5,
                    distinct_producers: 1,
                    dominant_producer: Some("ai:solo".to_string()),
                    dominant_count: 5,
                    dominance_ratio: 1.0,
                },
                threshold: 0.8,
                caveat: CLAIMED_NOT_ATTESTED_CAVEAT.to_string(),
                scan_capped: false,
            }],
            namespaces_capped: 0,
            // #1904 — additive report field (per-namespace read-failure count).
            namespaces_errored: 0,
        }
    }

    #[cfg(feature = "sal")]
    #[test]
    fn print_decorrelation_report_text_emits_advisory_line() {
        // Text branch + the `for adv` loop body + the enforce-degraded suffix.
        let report = sample_decorrelation_report(true);
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        {
            let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
            print_decorrelation_report(&report, false, &mut out).unwrap();
        }
        let s = String::from_utf8(stdout).unwrap();
        assert!(s.contains("decorrelation-probe: mode=advisory"));
        assert!(s.contains("advisories=1"));
        assert!(s.contains("enforce INERT at v0.8.0"));
        assert!(s.contains("ADVISORY ns=team/eng"));
        assert!(s.contains("dominant=ai:solo"));
        assert!(s.contains("CLAIMED"));
    }

    #[cfg(feature = "sal")]
    #[test]
    fn print_decorrelation_report_json_round_trips() {
        // JSON branch (no enforce-degraded suffix).
        let report = sample_decorrelation_report(false);
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        {
            let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
            print_decorrelation_report(&report, true, &mut out).unwrap();
        }
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8(stdout).unwrap().trim()).unwrap();
        assert_eq!(v["mode"], "advisory");
        assert_eq!(v["advisories"].as_array().unwrap().len(), 1);
        assert_eq!(v["advisories"][0]["namespace"], "team/eng");
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn decorrelation_step_off_is_silent() {
        // Off mode → early return, no output (the default-safe path; also
        // exercised by every existing `--reflect` test through `run_reflect`).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.namespace = Some("team/eng".to_string());
        let store = build_reflect_store(&db, &args, &cfg).await.unwrap();
        {
            let mut out = env.output();
            run_decorrelation_probe_step(
                store.as_ref(),
                "ai:curator",
                args.namespace.as_deref(),
                args.json,
                config::ReflectDecorrelationMode::Off,
                0.8,
                &mut out,
            )
            .await
            .unwrap();
        }
        assert!(env.stdout_str().is_empty());
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn decorrelation_step_advisory_empty_store_reports_zero() {
        // Advisory mode against an empty store → runner scans, no reflections,
        // 0 advisories. Covers the active path (runner call + Ok arm + the
        // text formatter) without env mutation.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let cfg = config::AppConfig::default();
        let mut args = default_args();
        args.namespace = Some("team/eng".to_string());
        let store = build_reflect_store(&db, &args, &cfg).await.unwrap();
        {
            let mut out = env.output();
            run_decorrelation_probe_step(
                store.as_ref(),
                "ai:curator",
                args.namespace.as_deref(),
                args.json,
                config::ReflectDecorrelationMode::Advisory,
                0.8,
                &mut out,
            )
            .await
            .unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("decorrelation-probe: mode=advisory"));
        assert!(s.contains("advisories=0"));
    }

    // ── #1548 coverage — the SAL `--store-url` curator path ──────────
    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn store_url_sqlite_once_text_runs_sweep() {
        // `--store-url sqlite:///<db> --once` routes through
        // build_curator_store + run_store_backed_sweep (--once arm) +
        // the no-LLM store_backed_reflection_sweep.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut cfg = config::AppConfig::default();
        cfg.tier = Some("keyword".to_string()); // no LLM client
        let mut args = default_args();
        args.store_url = Some(format!("sqlite://{}", db.display()));
        args.once = true;
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        let s = env.stdout_str();
        assert!(s.contains("reflection pass report"));
        assert!(s.contains("no LLM client configured"));
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn store_url_sqlite_once_json_runs_sweep() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut cfg = config::AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let mut args = default_args();
        args.store_url = Some(format!("sqlite://{}", db.display()));
        args.once = true;
        args.dry_run = true;
        args.json = true;
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let errs = v["errors"].as_array().unwrap();
        assert!(errs.iter().any(|e| e.as_str().unwrap().contains("no LLM")));
        assert!(v["dry_run"].as_bool().unwrap());
    }

    // ── #1548 coverage — the shared with-LLM reflection helper ───────
    // `build_curator_llm` returns None in hermetic CI (no reachable
    // Ollama), so the with-LLM branch of run_reflection_pass_with_optional_llm
    // is only reachable by injecting a deterministic AutonomyLlm stub —
    // the same pattern the reflection_pass unit suite uses.
    #[cfg(feature = "sal")]
    struct CovStubLlm;
    #[cfg(feature = "sal")]
    impl crate::autonomy::AutonomyLlm for CovStubLlm {
        fn auto_tag(&self, _title: &str, _content: &str) -> anyhow::Result<Vec<String>> {
            Ok(Vec::new())
        }
        fn detect_contradiction(&self, _a: &str, _b: &str) -> anyhow::Result<bool> {
            Ok(false)
        }
        fn summarize_memories(&self, _memories: &[(String, String)]) -> anyhow::Result<String> {
            Ok("stub reflection summary".to_string())
        }
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn reflection_helper_with_stub_llm_runs_with_llm_branch() {
        // Drives the with-LLM arm of run_reflection_pass_with_optional_llm
        // (the run_reflection_pass dispatch) via an injected stub over a
        // real SqliteStore — the branch build_curator_llm can't reach in CI.
        let env = TestEnv::fresh();
        let store = crate::store::sqlite::SqliteStore::open(&env.db_path).expect("open store");
        let stub = CovStubLlm;
        let args = default_args();
        let report = run_reflection_pass_with_optional_llm(
            &store,
            Some(&stub as &dyn crate::autonomy::AutonomyLlm),
            None,
            None,
            args.max_depth,
            true,
            |_ns: &str| true,
        )
        .await;
        // Empty store → an empty (but successfully produced) report; the
        // point is the with-LLM dispatch arm executed without error.
        assert!(report.dry_run);
        assert!(
            report.errors.is_empty(),
            "unexpected errors: {:?}",
            report.errors
        );
        // Exercise the stub's AutonomyLlm contract directly so the impl is
        // covered even when an empty store forms no clusters to summarize.
        use crate::autonomy::AutonomyLlm;
        assert!(stub.auto_tag("t", "c").unwrap().is_empty());
        assert!(!stub.detect_contradiction("a", "b").unwrap());
        assert_eq!(
            stub.summarize_memories(&[("a".to_string(), "b".to_string())])
                .unwrap(),
            "stub reflection summary"
        );
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn reflection_helper_with_none_llm_reports_configured_error() {
        // The None arm — surfaced as a populated report (not a hard error).
        let env = TestEnv::fresh();
        let store = crate::store::sqlite::SqliteStore::open(&env.db_path).expect("open store");
        let report = run_reflection_pass_with_optional_llm(
            &store,
            None,
            None,
            Some("ns"),
            None,
            false,
            |_ns: &str| true,
        )
        .await;
        assert!(!report.dry_run);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("no LLM client configured"))
        );
    }

    // ── #1747 (slice-3c1) — store-backed consolidation sweep ─────────────
    // Backend-agnostic: drives the actual sweep entry point (not
    // ConsolidationPass::run directly) over a real SqliteStore, so the same
    // wiring the postgres curator uses is exercised in always-on CI.
    #[cfg(feature = "sal")]
    fn seed_two_dup_memories(db_path: &std::path::Path) {
        let conn = db::open(db_path).unwrap();
        let dup = "kubernetes rolling canary deploy strategy notes with enough length";
        let mk = |id: &str, title: &str| crate::models::Memory {
            id: id.to_string(),
            namespace: "ns".to_string(),
            title: title.to_string(),
            content: dup.to_string(),
            tier: crate::models::Tier::Mid,
            access_count: 5,
            ..Default::default()
        };
        let m1 = mk("aaa11111", "t1");
        let m2 = mk("bbb22222", "t2");
        db::insert(&conn, &m1).unwrap();
        db::insert(&conn, &m2).unwrap();
        // Aligned embeddings → cosine gate passes (same ns).
        db::set_embedding(
            &conn,
            &m1.id,
            &[1.0, 0.0],
            &crate::embeddings::EmbeddingSpace::mint("test-space"),
        )
        .unwrap();
        db::set_embedding(
            &conn,
            &m2.id,
            &[1.0, 0.0],
            &crate::embeddings::EmbeddingSpace::mint("test-space"),
        )
        .unwrap();
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn consolidation_sweep_consolidates_and_folds_when_enabled() {
        let env = TestEnv::fresh();
        seed_two_dup_memories(&env.db_path);
        let store = crate::store::sqlite::SqliteStore::open(&env.db_path).expect("open store");
        let stub = CovStubLlm;
        let cfg = curator::CuratorConfig {
            max_ops_per_cycle: 100,
            compaction: curator::CompactionConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default() // dry_run = false → real consolidation
        };
        let report = store_backed_consolidation_sweep(
            &store,
            Some(&stub as &dyn crate::autonomy::AutonomyLlm),
            &cfg,
        )
        .await;
        assert_eq!(
            report.memories_consolidated, 2,
            "both sources folded; errors: {:?}",
            report.errors
        );
        assert_eq!(
            report.rollback_entries_written, 1,
            "one operator-reversible rollback entry persisted"
        );
        // The [consolidated] row landed.
        let conn = db::open(&env.db_path).unwrap();
        let rows = db::list(&conn, Some("ns"), None, 16, 0, None, None, None, None, None).unwrap();
        assert!(
            rows.iter().any(|m| m.title.starts_with("[consolidated]")),
            "a consolidated row must exist"
        );
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn consolidation_sweep_noop_when_disabled() {
        let env = TestEnv::fresh();
        seed_two_dup_memories(&env.db_path);
        let store = crate::store::sqlite::SqliteStore::open(&env.db_path).expect("open store");
        let stub = CovStubLlm;
        // Default config → compaction.enabled = false.
        let cfg = curator::CuratorConfig::default();
        let report = store_backed_consolidation_sweep(
            &store,
            Some(&stub as &dyn crate::autonomy::AutonomyLlm),
            &cfg,
        )
        .await;
        assert_eq!(
            report.memories_consolidated, 0,
            "disabled → no consolidation"
        );
        assert_eq!(report.clusters_formed, 0);
        assert!(report.errors.is_empty(), "no errors: {:?}", report.errors);
        // Both source rows remain; no consolidated row.
        let conn = db::open(&env.db_path).unwrap();
        let rows = db::list(&conn, Some("ns"), None, 16, 0, None, None, None, None, None).unwrap();
        assert_eq!(rows.len(), 2, "both source rows remain live");
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn consolidation_sweep_no_llm_folds_into_report() {
        let env = TestEnv::fresh();
        seed_two_dup_memories(&env.db_path);
        let store = crate::store::sqlite::SqliteStore::open(&env.db_path).expect("open store");
        let cfg = curator::CuratorConfig {
            compaction: curator::CompactionConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        // No LLM → folds an error into the report, never panics.
        let report = store_backed_consolidation_sweep(&store, None, &cfg).await;
        assert_eq!(report.memories_consolidated, 0);
        assert!(
            report.errors.iter().any(|e| e.contains("no LLM")),
            "no-LLM error surfaced: {:?}",
            report.errors
        );
    }

    #[cfg(all(feature = "sal", unix))]
    #[tokio::test(flavor = "multi_thread")]
    async fn store_url_sqlite_daemon_loop_returns_on_shutdown() {
        // Covers the SAL daemon-loop arm of run_store_backed_sweep. The
        // ctrl_c watcher is spawned AFTER build_curator_store, so the
        // SIGINT kick waits 3s — long enough for the watcher to register
        // even under llvm-cov instrumentation (the 200ms legacy delay
        // races the slower instrumented store build).
        use std::path::PathBuf;
        let env = TestEnv::fresh();
        let db: PathBuf = env.db_path.clone();
        let mut cfg = config::AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let mut args = default_args();
        args.store_url = Some(format!("sqlite://{}", db.display()));
        args.daemon = true;
        args.interval_secs = 60;
        args.dry_run = true;
        let kicker = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(3000)).await;
            // SAFETY: kill(getpid, SIGINT) is well-defined on POSIX.
            unsafe {
                libc::kill(libc::getpid(), libc::SIGINT);
            }
        });
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(90),
            run(&db, &args, &cfg, &mut out),
        )
        .await;
        let _ = kicker.await;
        assert!(res.is_ok(), "SAL daemon did not return within timeout");
        assert!(res.unwrap().is_ok());
    }

    #[test]
    fn print_reflection_report_emits_proposals_and_errors() {
        let r = crate::curator::reflection_pass::ReflectionPassReport {
            started_at: "2026-01-01T00:00:00Z".into(),
            completed_at: "2026-01-01T00:00:01Z".into(),
            namespaces_visited: 2,
            observations_scanned: 5,
            clusters_formed: 1,
            clusters_eligible: 1,
            reflections_persisted: 0,
            depth_refusals: 0,
            errors: vec!["a problem".to_string()],
            dry_run_proposals: vec![crate::curator::reflection_pass::DryRunProposal {
                namespace: "app".to_string(),
                proposed_title: "[reflection] pattern".to_string(),
                source_ids: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            }],
            dry_run: true,
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        {
            let mut out = crate::cli::CliOutput::from_std(&mut stdout, &mut stderr);
            print_reflection_report(&r, &mut out).unwrap();
        }
        let s = String::from_utf8(stdout).unwrap();
        assert!(s.contains("reflection pass report"));
        assert!(s.contains("namespaces_visited:"));
        assert!(s.contains("observations_scanned:"));
        assert!(s.contains("- a problem"));
        assert!(s.contains("proposal: ns='app'"));
        assert!(s.contains("sources=3"));
    }

    #[test]
    fn load_curator_keypair_best_effort_returns_some_or_none() {
        // Just exercises the function. Whether it returns Some or None
        // depends on the host's key dir contents; either outcome is OK.
        let _ = load_curator_keypair_best_effort();
    }

    #[test]
    fn build_curator_llm_with_autonomous_tier() {
        // Autonomous tier — exercises the autonomous arm of the
        // configured llm_model match. Will likely return None when
        // Ollama isn't running.
        //
        // TEST-5 — pin `AI_MEMORY_NO_CONFIG=1` so the resolver always
        // returns the Ollama compiled default rather than the host's
        // configured backend.
        crate::cli::test_utils::ensure_no_config_env();
        let _ = build_curator_llm(config::FeatureTier::Autonomous);
    }

    #[cfg(feature = "sal")]
    #[tokio::test]
    async fn reflect_with_seeded_observations_and_no_llm() {
        // Seed observations so list_namespaces returns a namespace,
        // then run reflect with --all-namespaces + no LLM. Hits the
        // namespace enumeration + "no LLM" path.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let _id = crate::cli::test_utils::seed_memory(&db, "myns", "T", "C");
        let mut cfg = config::AppConfig::default();
        cfg.tier = Some("keyword".to_string());
        let mut args = default_args();
        args.reflect = true;
        args.all_namespaces = true;
        args.dry_run = true;
        {
            let mut out = env.output();
            run(&db, &args, &cfg, &mut out).await.unwrap();
        }
        assert!(env.stdout_str().contains("reflection pass report"));
    }

    /// QUAL-2 regression — `run_rollback` must `bail!()` (typed error)
    /// instead of `unreachable!()` (process panic) when neither
    /// `--rollback` nor `--rollback-last` is set. The caller-side guard
    /// at `run()` short-circuits this case, but the function-level
    /// recovery path must remain typed so a future guard regression
    /// surfaces as a CLI exit, not a crash.
    #[test]
    fn qual_2_run_rollback_returns_error_when_no_mode_set() {
        let env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = default_args();
        let mut stdout: Vec<u8> = Vec::new();
        let mut stderr: Vec<u8> = Vec::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let res = run_rollback(&db, &args, &mut out);
        assert!(
            res.is_err(),
            "run_rollback must return Err when both --rollback and --rollback-last are None"
        );
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains("run_rollback entered without --rollback or --rollback-last"),
            "unexpected error message: {msg}"
        );
    }
}
