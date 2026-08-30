// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `cmd_recall` migration. See `cli::store` for the design pattern.
//!
//! W6 (v0.6.3) — embedder construction was unified into
//! [`crate::daemon_runtime::build_embedder`]. Both `serve()` and this
//! handler now call the same builder, killing the per-call-site
//! duplication that the original W5b note flagged. The TestHelper that
//! used to live here (`build_embedder_for_recall`) is gone.

use crate::cli::CliOutput;
use crate::cli::helpers::{human_age, id_short};
use crate::config::AppConfig;
use crate::embeddings::Embed;
use crate::models::field_names;
use crate::{color, daemon_runtime, db, embeddings, hnsw, reranker, validate};
use anyhow::Result;
use clap::Args;
use std::path::Path;

/// Clap-derived arg shape for the `recall` subcommand. Definition moved
/// from `main.rs` verbatim in W5b — fields and attrs unchanged.
#[derive(Args)]
pub struct RecallArgs {
    #[arg(allow_hyphen_values = true)]
    pub context: String,
    #[arg(long, short)]
    pub namespace: Option<String>,
    #[arg(long, default_value_t = 10)]
    pub limit: usize,
    #[arg(long)]
    pub tags: Option<String>,
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long)]
    pub until: Option<String>,
    /// #1834 claim-bitemporal as-of: RFC3339 point in valid-time. Returns only
    /// claims asserted to hold at this instant (valid_from/valid_until window).
    #[arg(long)]
    pub valid_at: Option<String>,
    /// Feature tier for recall: keyword, semantic, smart, autonomous
    #[arg(long, short = 'T')]
    pub tier: Option<String>,
    /// Task 1.5: querying agent's namespace position. Enables scope-based
    /// visibility filtering (private/team/unit/org/collective).
    #[arg(long)]
    pub as_agent: Option<String>,
    /// Task 1.11: context-budget-aware recall. Return the top-ranked
    /// memories whose cumulative estimated tokens fit within N. Omit
    /// for unlimited (limit-based only).
    #[arg(long)]
    pub budget_tokens: Option<usize>,
    /// v0.6.0.0 contextual recall. Comma-separated list of recent
    /// conversation tokens used to bias the query embedding at 70/30
    /// (primary/context). Shifts the recall towards memories that
    /// match both the explicit query and the conversation's nearby
    /// topics.
    #[arg(long, value_delimiter = ',')]
    pub context_tokens: Option<Vec<String>>,
    /// v0.7.0 (issue #518) — when set, splice defaults from
    /// `[agents.defaults.recall_scope]` in `config.toml` for any
    /// filter field not explicitly passed on the command line.
    /// Resolution: explicit args > recall_scope defaults > compiled
    /// defaults. Default `false` preserves v0.6.x recall semantics.
    #[arg(long)]
    pub session_default: bool,
    /// v0.7.0 WT-1-E — when set, recall returns archived sources
    /// (those replaced by their atoms after WT-1-B atomisation)
    /// alongside the atoms. Default `false` surfaces atoms only,
    /// which is the canonical post-atomisation recall unit.
    #[arg(long)]
    pub include_archived: bool,
    /// v0.7.0 Form 4 (issue #757) — restrict results to memories
    /// whose `citations` array is non-empty. Composes with the
    /// other filters; default `false` (no provenance filter).
    #[arg(long)]
    pub has_citations: bool,
    /// v0.7.0 Form 4 (issue #757) — restrict results to memories
    /// whose `source_uri` starts with this prefix. Matches the
    /// substring exactly (no glob/regex). Typical use:
    /// `--source-uri-prefix doc:` to surface every atom or memory
    /// pointing at a substrate doc; `--source-uri-prefix uri:https://`
    /// to surface every memory citing an HTTP source.
    #[arg(long)]
    pub source_uri_prefix: Option<String>,
    /// v0.7.x Form 6 (issue #759) — Batman-taxonomy memory-kind
    /// filter. Comma-separated. Examples:
    ///   --kind concept
    ///   --kind concept,entity,claim
    ///   --kinds concept,entity,claim    (plural alias for MCP parity)
    /// Recognised values: observation, reflection, persona, concept,
    /// entity, claim, relation, event, conversation, decision.
    /// OR-of-kinds within the flag; AND with the other filters.
    /// Pass 'all' or omit for no filter.
    ///
    /// Cluster E audit API-3 (issue #767): the MCP tool param is
    /// `kinds` (plural), so the CLI accepts both spellings via an
    /// alias for cross-interface ergonomics.
    #[arg(long = "kind", alias = "kinds", value_name = "KIND[,KIND...]")]
    pub kind: Option<String>,
    /// v0.7.0 #1098 — restrict to memories whose confidence tier
    /// matches one of {high, medium, low}. Wired through to
    /// [`crate::models::RecallRequest::confidence_tier`] via
    /// `RecallRequest::from_cli_args`; the MCP / HTTP surfaces have
    /// accepted this filter since RC, the CLI surface closes the
    /// three-surface parity gap.
    #[arg(long = "confidence-tier", value_name = "TIER", value_parser = ["high", "medium", "low"])]
    pub confidence_tier: Option<String>,
    /// v0.7.0 #1098 — when set, emit per-row provenance decoration
    /// (Gap-7 #890): `citations`, `source_uri`, `source_span`,
    /// `confidence_source`, `confidence_signals`. The flag flows
    /// through the DTO so MCP / HTTP / CLI agree on the verbose
    /// envelope shape; the JSON renderer downstream owns the actual
    /// expansion (today's CLI emits the full `Memory` row already,
    /// so the flag is preserved for cross-surface parity).
    #[arg(long = "verbose-provenance")]
    pub verbose_provenance: bool,
    /// v0.7.0 #1098 — response format selector: `human` (default
    /// pretty text), `json` (the same envelope `--json` produces),
    /// or `toon` (TOON, ~79% smaller than JSON; see [`crate::toon`]).
    /// The MCP / HTTP surfaces accept the same vocabulary via
    /// `RecallRequest::format`. Default `human` preserves v0.6.x CLI
    /// semantics.
    ///
    /// v1.0.0 #3005 — this selector is now actually READ by the render
    /// path. Pre-fix it was declared, `value_parser`-validated and
    /// marshalled into the DTO, but the only renderer branch was the
    /// global `--json`, so all three values produced byte-identical
    /// HUMAN output: `--format json` silently lied and TOON was
    /// unreachable from the CLI. The global `--json` still takes
    /// precedence (existing scripts keep their exact envelope).
    #[arg(long = "format", value_name = "FORMAT", value_parser = ["human", "json", "toon"], default_value = "human")]
    pub format: String,
    /// v0.7.0 #1257 — session-id parity flag (DTO C2 #967, +0.05
    /// rerank boost under #518). Pre-#1257 this was hard-coded to
    /// `None` in `RecallRequest::from_cli_args`, so a CLI caller
    /// could not reach the in-session ring boost even though MCP
    /// (`{"session_id": "…"}` param) and HTTP (`?session_id=…` or
    /// JSON body) callers could. Optional; omit to preserve v0.6.x
    /// recall semantics.
    #[arg(long = "session-id", value_name = "SESSION_ID")]
    pub session_id: Option<String>,
}

/// v0.7.0 Form 4 (issue #757) — post-filter a recall result set by
/// the Form 4 fact-provenance criteria. Composes with the existing
/// substrate-level WHERE clauses (those run inside SQL); these
/// filters run in Rust because both criteria are read-only checks
/// on already-deserialised Memory rows and the alternative would
/// be a substrate-wide signature change on `recall` / `recall_hybrid`.
#[must_use]
pub fn apply_form4_recall_filters(
    results: Vec<(crate::models::Memory, f64)>,
    has_citations: bool,
    source_uri_prefix: Option<&str>,
) -> Vec<(crate::models::Memory, f64)> {
    if !has_citations && source_uri_prefix.is_none() {
        return results;
    }
    results
        .into_iter()
        .filter(|(m, _)| {
            if has_citations && m.citations.is_empty() {
                return false;
            }
            if let Some(prefix) = source_uri_prefix {
                match m.source_uri.as_deref() {
                    Some(uri) if uri.starts_with(prefix) => {}
                    _ => return false,
                }
            }
            true
        })
        .collect()
}

/// `recall` handler. Mirrors `cmd_recall` from the pre-W5b `main.rs`
/// verbatim except every emit routes through `out.stdout` / `out.stderr`
/// instead of `println!` / `eprintln!`. The embedder is built via the
/// shared [`crate::daemon_runtime::build_embedder`] helper so the offline
/// recall path and the HTTP daemon use identical construction logic.
#[allow(clippy::too_many_lines)]
pub fn run(
    db_path: &Path,
    args: &RecallArgs,
    json_out: bool,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // #151: validate --as-agent namespace
    if let Some(ref a) = args.as_agent {
        validate::validate_namespace(a)?;
    }
    // v1.0.0 #1834 — RFC3339-validate --valid-at at the CLI entry.
    if let Some(ref v) = args.valid_at {
        validate::validate_valid_at(v)?;
    }
    let mut conn = db::open(db_path)?;
    let _ = db::gc_if_needed(&conn, app_config.effective_archive_on_gc());

    // Resolve feature tier
    let feature_tier = app_config.effective_tier(args.tier.as_deref());

    // Initialize embedder if tier supports it. Use the shared builder so
    // recall and the HTTP daemon agree on tier→embedder semantics
    // (embed_url, model selection, error fallback). The shared builder
    // is async; we drive it on a dedicated OS thread that owns a fresh
    // current-thread runtime. Tier=Keyword short-circuits inside the
    // builder before any tokio work happens, so the thread's only cost
    // is the keyword path.
    let embedder = {
        // #1182: `build_embedder` internally `.await`s a `spawn_blocking`
        // for the candle / HF-Hub model load. Driving it via
        // `block_in_place(|| handle.block_on(..))` on the ambient
        // multi-thread runtime (the case when `run()` is reached through
        // `#[tokio::main]`) can deadlock under a scheduling race: the
        // main thread parks inside `block_on` while every worker is idle
        // and no thread is left to drive the blocking task to completion.
        // A standalone `std::thread` is never a tokio runtime worker, so
        // creating a fresh current-thread runtime and `block_on`-ing it
        // there is always safe regardless of whether `run()` was invoked
        // from inside `#[tokio::main]` (the CLI) or a sync `#[test]`. This
        // unifies both prior branches into one deadlock-free path.
        let built = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map(|rt| {
                            rt.block_on(daemon_runtime::build_embedder(
                                feature_tier,
                                app_config,
                                db_path,
                            ))
                        })
                })
                .join()
        });
        match built {
            Ok(Ok(embedder)) => embedder,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => anyhow::bail!("embedder build thread panicked"),
        }
    };
    // Delegate to the embedder-injected helper so test code can reach
    // every branch downstream without owning a real candle Embedder.
    let embedder_ref: Option<&dyn Embed> = embedder.as_ref().map(|e| e as &dyn Embed);
    // #1598 — model_description now returns an owned String (the
    // remote variant reports its live model id + dim).
    let embedder_model_description = embedder
        .as_ref()
        .map(crate::embeddings::Embedder::model_description);
    run_with_embedder(
        &mut conn,
        args,
        json_out,
        app_config,
        feature_tier,
        embedder_ref,
        embedder_model_description.as_deref(),
        out,
    )
}

/// #1579 B3 — should a ONE-SHOT CLI invocation pay the HNSW
/// graph-construction cost for `embedded_rows` stored embeddings?
/// `false` below [`hnsw::CLI_HNSW_BUILD_MIN_ENTRIES`] (the recall
/// pipeline's linear-scan fallback is faster end-to-end there — see
/// the const for the P1 numbers); negative/garbage counts never
/// build.
pub(crate) fn should_build_cli_hnsw(embedded_rows: i64) -> bool {
    usize::try_from(embedded_rows).is_ok_and(|n| n >= hnsw::CLI_HNSW_BUILD_MIN_ENTRIES)
}

/// Test-injectable core of [`run`]. Production callers go through `run`
/// which builds an [`Embedder`] via `daemon_runtime::build_embedder` and
/// delegates here. Tests can pass a `MockEmbedder` directly without the
/// candle / HuggingFace dependency chain.
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_with_embedder(
    conn: &mut rusqlite::Connection,
    args: &RecallArgs,
    json_out: bool,
    app_config: &AppConfig,
    feature_tier: crate::config::FeatureTier,
    embedder: Option<&dyn Embed>,
    embedder_model_description: Option<&str>,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let tier_config = feature_tier.config();
    // v0.8.0 #1720 A3 — owner-keyed scope=private visibility caller for
    // the `db::recall*` SQL gate. CLI is single-tenant operator-as-
    // actor: `resolve_read_visibility_caller` returns the agent_id when
    // `AI_MEMORY_AGENT_ID` is set + shape-valid, else `None` (trust-all
    // read posture preserved). DISTINCT from `--as-agent` (namespace).
    let vis_caller = crate::identity::resolve_read_visibility_caller();
    // v0.7.0 (issue #518) — when `--session-default` is passed AND a
    // given filter axis is absent on the CLI, splice in the
    // `[agents.defaults.recall_scope]` value from config.toml.
    let scope = if args.session_default {
        app_config.effective_recall_scope()
    } else {
        None
    };
    let effective_namespace: Option<String> = args.namespace.clone().or_else(|| {
        scope
            .and_then(|s| s.namespaces.as_ref())
            .and_then(|v| v.first())
            .cloned()
    });
    let effective_since: Option<String> = args.since.clone().or_else(|| {
        scope.and_then(|s| {
            s.since.as_deref().and_then(|d| {
                crate::config::parse_duration_string(d).map(|dur| {
                    let cutoff = chrono::Utc::now() - dur;
                    cutoff.to_rfc3339()
                })
            })
        })
    });
    let effective_limit_usize = if args.limit == 10
        && let Some(v) = scope.and_then(|s| s.limit)
    {
        usize::try_from(v).unwrap_or(usize::MAX)
    } else {
        args.limit
    };
    let _effective_recall_tier: Option<String> = scope.and_then(|s| s.tier.clone());

    // v0.7.x Form 6 — parse the optional --kind filter. Treat the
    // literal "all" as "no filter" to match the MCP `kinds: "all"`
    // shorthand, and accept comma-separated tokens otherwise.
    let kinds_filter: Option<Vec<crate::models::MemoryKind>> = args.kind.as_deref().and_then(|s| {
        if s.trim().eq_ignore_ascii_case("all") {
            None
        } else {
            crate::models::MemoryKind::parse_csv(s)
        }
    });

    if let Some(desc) = embedder_model_description {
        writeln!(out.stderr, "ai-memory: embedder loaded ({desc})")?;
    } else if tier_config.embedding_model.is_some() {
        writeln!(
            out.stderr,
            "ai-memory: embedder failed to load, falling back to keyword"
        )?;
    }

    // Backfill embeddings for memories that don't have them.
    //
    // #1579 B6-CLI — routed through the same batched helper the MCP
    // boot path uses (`run_embedding_backfill_with_batch_size`:
    // `embed_batch` chunks + `set_embeddings_batch`) instead of the
    // legacy per-row `emb.embed` loop. On the local candle backend a
    // true batched forward is ~10-20× faster than row-at-a-time
    // (PERF-5), and the batch size follows the canonical #1146
    // `[embeddings].backfill_batch` resolver instead of being
    // implicitly 1.
    if let Some(emb) = embedder {
        let batch_size = app_config.resolve_embeddings().backfill_batch as usize;
        if let Err(e) = crate::mcp::run_embedding_backfill_with_batch_size(conn, emb, batch_size) {
            writeln!(out.stderr, "ai-memory: backfill failed: {e}")?;
        }
    }

    // Build HNSW vector index if embedder is available.
    //
    // #1579 B3 — but ONLY above the SSOT row threshold
    // (`hnsw::CLI_HNSW_BUILD_MIN_ENTRIES`). A one-shot CLI recall
    // pays the full graph-construction cost per invocation (P1
    // audit: ~40 s at 10k vectors) while the recall pipeline's
    // linear-scan fallback answers in ≤ 35 ms at that scale — so
    // below the threshold we skip the build entirely (pass `None`;
    // the semantic phase linear-scans the embedding column). The
    // cheap COUNT probe avoids even decoding the blobs when the
    // build is going to be skipped.
    // v1.0.0 #2167 §3.3 layer 1 — the CLI-local HNSW seed set is filtered
    // to the active embedder's space (foreign vectors never enter the
    // graph). `None` when there is no embedder (keyword-only).
    // v1.0.0 #2606 — the fingerprint omits the vector dim, so the seed set is
    // narrowed by the live embedder's width too; otherwise a config-only dim
    // change seeds the CLI graph with two dim populations under one stamp.
    // The width is tracked SEPARATELY from the fingerprint on purpose: an
    // embedder that cannot report its width must not also drop the #2167 §3
    // space gate below, which is a different (and still-correct) control.
    let cli_active_space: Option<String> = embedder.as_ref().map(|e| e.space_fingerprint());
    // `None` for an embedder that reports no width. The index is then NOT
    // built — the semantic phase linear-scans the embedding column with the
    // fail-closed full-dim rescoring, which is slower and always correct;
    // seeding a graph at a guessed width is the failure this closes.
    let cli_active_dim: Option<usize> = embedder.as_ref().and_then(|e| e.embedding_dim());
    let vector_index = if let (Some(active), Some(active_dim)) =
        (cli_active_space.as_deref(), cli_active_dim)
        && db::count_embedded_memories(conn).is_ok_and(should_build_cli_hnsw)
    {
        match db::get_all_embeddings(conn, active, active_dim) {
            Ok(entries) if !entries.is_empty() => Some(hnsw::VectorIndex::build(entries)),
            _ => Some(hnsw::VectorIndex::empty()),
        }
    } else {
        None
    };

    let reranker = if tier_config.cross_encoder {
        Some(reranker::BatchedReranker::new(
            reranker::CrossEncoder::new_neural(),
        ))
    } else {
        None
    };

    let resolved_ttl = app_config.effective_ttl();
    let resolved_scoring = app_config.effective_scoring();

    // Perform recall: hybrid if embedder available, keyword otherwise.
    // F-L8a — the 4th tuple element is the recall telemetry carrying the
    // space/unverified/dim rows withheld from semantic scoring; the keyword
    // branches contribute a zeroed telemetry (no semantic scoring ran).
    let (results, outcome, mode, telemetry) = if let Some(emb) = embedder {
        // v1.0.0 #2577 — bounded funnel (cache -> wall-clock budget ->
        // degrade-to-keyword), shared with the HTTP + MCP recall surfaces.
        match crate::embeddings::recall_query_embedding(emb, &args.context) {
            Some(primary_emb) => {
                let query_emb = match args.context_tokens.as_deref() {
                    Some(tokens) if !tokens.is_empty() => {
                        let joined = tokens.join(" ");
                        match crate::embeddings::recall_query_embedding(emb, &joined) {
                            Some(ctx_emb) => embeddings::Embedder::fuse(
                                &primary_emb,
                                &ctx_emb,
                                crate::RECALL_PRIMARY_CTX_BLEND,
                            ),
                            None => {
                                writeln!(
                                    out.stderr,
                                    "ai-memory: context_tokens embed unavailable, using primary only"
                                )?;
                                primary_emb
                            }
                        }
                    }
                    _ => primary_emb,
                };
                let (results, outcome, telemetry) = db::recall_hybrid_with_telemetry(
                    conn,
                    &args.context,
                    &query_emb,
                    effective_namespace.as_deref(),
                    effective_limit_usize.min(50),
                    args.tags.as_deref(),
                    effective_since.as_deref(),
                    args.until.as_deref(),
                    // v0.9 #1005 — coerce the concrete CLI-local index to
                    // the seam trait object at the pipeline boundary.
                    vector_index
                        .as_ref()
                        .map(|i| i as &dyn hnsw::VectorSearchIndex),
                    resolved_ttl.short_extend_secs,
                    resolved_ttl.mid_extend_secs,
                    args.as_agent.as_deref(),
                    args.budget_tokens,
                    &resolved_scoring,
                    args.include_archived,
                    args.source_uri_prefix.as_deref(),
                    vis_caller.as_deref(),
                    // v1.0.0 #2167 §3 — active embedder fingerprint gate.
                    cli_active_space.as_deref(),
                    // v1.0.0 #1834 — claim-bitemporal AS-OF instant.
                    args.valid_at.as_deref(),
                )?;
                if let Some(ref ce) = reranker {
                    (
                        ce.rerank(&args.context, results),
                        outcome,
                        crate::models::RECALL_MODE_HYBRID_RERANK,
                        telemetry,
                    )
                } else {
                    (results, outcome, "hybrid", telemetry)
                }
            }
            None => {
                // v1.0.0 #2577 — the structured WARN + counter are emitted
                // by `recall_query_embedding`; this line keeps the
                // human-facing CLI message operators already parse.
                writeln!(
                    out.stderr,
                    "ai-memory: embedding query unavailable within budget, falling back to keyword"
                )?;
                let (results, outcome) = db::recall(
                    conn,
                    &args.context,
                    effective_namespace.as_deref(),
                    effective_limit_usize,
                    args.tags.as_deref(),
                    effective_since.as_deref(),
                    args.until.as_deref(),
                    resolved_ttl.short_extend_secs,
                    resolved_ttl.mid_extend_secs,
                    args.as_agent.as_deref(),
                    args.budget_tokens,
                    args.include_archived,
                    args.source_uri_prefix.as_deref(),
                    vis_caller.as_deref(),
                    args.valid_at.as_deref(),
                )?;
                (
                    results,
                    outcome,
                    "keyword",
                    crate::models::RecallTelemetry::default(),
                )
            }
        }
    } else {
        let (results, outcome) = db::recall(
            conn,
            &args.context,
            effective_namespace.as_deref(),
            effective_limit_usize,
            args.tags.as_deref(),
            effective_since.as_deref(),
            args.until.as_deref(),
            resolved_ttl.short_extend_secs,
            resolved_ttl.mid_extend_secs,
            args.as_agent.as_deref(),
            args.budget_tokens,
            args.include_archived,
            args.source_uri_prefix.as_deref(),
            vis_caller.as_deref(),
            args.valid_at.as_deref(),
        )?;
        (
            results,
            outcome,
            "keyword",
            crate::models::RecallTelemetry::default(),
        )
    };

    // v0.7.0 Form 4 (issue #757) — fact-provenance post-filter.
    let results = apply_form4_recall_filters(
        results,
        args.has_citations,
        args.source_uri_prefix.as_deref(),
    );

    // v0.7.x Form 6 — apply the parsed kinds filter to the result set
    // in-place. No-op when `kinds_filter == None`. Cheap (results are
    // already capped at limit.min(50)), and avoids touching the recall
    // SQL on the existing storage path.
    let results: Vec<(crate::models::Memory, f64)> = match kinds_filter.as_deref() {
        None => results,
        Some(allowed) => results
            .into_iter()
            .filter(|(m, _)| allowed.contains(&m.memory_kind))
            .collect(),
    };

    // v0.7.0 #1468 / v1.0.0 #2990 — per-row ownership visibility post-filter,
    // mirroring the MCP/HTTP recall paths (`crate::mcp::tools::recall::
    // handle_recall_dto`'s `apply_visibility_filter`). The `db::recall*` SQL
    // gate applies the #151 namespace-scope (`--as-agent`) gate but NOT the
    // per-row `scope=private` ownership predicate UNLESS `--as-agent` was
    // passed: with `as_agent=None` (the common CLI case) the
    // `visibility_clause` private prefix (`?8`) binds NULL, short-circuiting
    // the whole gate to "all visible" so a cross-agent `scope=private` row
    // would otherwise reach the CLI wire. When `vis_caller` is `Some`, drop
    // every row the caller does not own via the canonical
    // `crate::visibility::is_visible_to_caller` predicate (owner OR
    // inbox-target for private; collective + subtree-matched team/unit/org
    // pass). `None` (no stable `AI_MEMORY_AGENT_ID`) keeps the single-tenant
    // trust-all read posture. Fail-closed: this can only HIDE rows, never
    // widen the returned set.
    let results: Vec<(crate::models::Memory, f64)> = match vis_caller.as_deref() {
        None => results,
        Some(c) => results
            .into_iter()
            .filter(|(m, _)| crate::visibility::is_visible_to_caller(m, c))
            .collect(),
    };

    // v0.9.0 P0-1 (#1869, T8) — CLI ledger append: with recall pure by
    // default, a recall that writes no `recall_observations` row
    // vanishes from the access signal (its counts freeze). Record the
    // post-filter RETURNED set, best-effort + table-probe-gated,
    // mirroring the MCP/HTTP writers; rows are stamped pre-folded
    // under the sync legacy flag via the shared insert-layer stamp.
    // A ledger error never blocks the recall output.
    if crate::observations::table_exists(conn) {
        let recall_id = uuid::Uuid::new_v4().to_string();
        #[allow(clippy::cast_possible_wrap)]
        let candidates: Vec<crate::observations::Candidate<'_>> = results
            .iter()
            .enumerate()
            .map(|(i, (m, s))| crate::observations::Candidate {
                memory_id: m.id.as_str(),
                retriever: mode,
                rank: (i + 1) as i64,
                score: *s,
            })
            .collect();
        // #2988 — bind the RECALLING agent's identity into the ledger, NOT
        // `--as-agent` (a NAMESPACE). The MCP/HTTP recall path stamps the
        // read-visibility caller (`resolve_read_visibility_caller`) here
        // (see `mcp::tools::recall::record_recall_observations`, which passes
        // `caller`); reuse the same `vis_caller` so the #1705 cross-agent
        // replay guard (`mark_consumed_guarded`: `agent_id IS NULL OR
        // agent_id = ?`) is bound to the true recaller (or `NULL` when no
        // stable identity is set) instead of a namespace in the identity
        // column. Pre-fix `args.as_agent.as_deref()` wrote the namespace into
        // the identity slot, making the guard inert on the CLI surface.
        // `--as-agent` remains the namespace-scope visibility knob.
        if let Err(e) = crate::observations::record_recall_with_identity(
            conn,
            &recall_id,
            &candidates,
            vis_caller.as_deref(),
            effective_namespace.as_deref(),
        ) {
            writeln!(out.stderr, "ai-memory: recall ledger append failed: {e}")?;
        }
    }

    // #3005 — `--format {human,json,toon}` now SELECTS the renderer. Pre-fix
    // `args.format` was declared (with a `value_parser`), marshalled into the
    // `RecallRequest` DTO and pinned by a parity test — but nothing in this
    // handler ever read it, so all three values rendered byte-identical HUMAN
    // output: `--format json` silently LIED and TOON was unreachable from the
    // CLI even though the MCP + HTTP surfaces have honoured it since v0.6.x.
    //
    // Precedence: the GLOBAL `--json` still wins, so every existing
    // `--json`-driven script keeps its exact envelope regardless of `--format`.
    // Otherwise the value chosen on `--format` decides.
    let want_toon = !json_out && args.format == crate::toon::FORMAT_TOON;
    let want_json = json_out || args.format == crate::toon::FORMAT_JSON;
    if want_json || want_toon {
        let scored: Vec<serde_json::Value> = results
            .iter()
            .map(|(m, s)| {
                let mut v = serde_json::to_value(m).unwrap_or_default();
                if let Some(obj) = v.as_object_mut() {
                    obj.insert(
                        "score".to_string(),
                        serde_json::json!((s * 1000.0).round() / 1000.0),
                    );
                }
                v
            })
            .collect();
        let mut body = serde_json::json!({
            "memories": scored,
            "count": results.len(),
            "mode": mode,
            (field_names::TOKENS_USED): outcome.tokens_used,
        });
        if let Some(b) = args.budget_tokens {
            body[field_names::BUDGET_TOKENS] = serde_json::json!(b);
            // Phase P6 (R1) meta block — same shape as MCP / HTTP paths.
            body["meta"] = serde_json::json!({
                "budget_tokens_used": outcome.tokens_used,
                "budget_tokens_remaining": outcome.tokens_remaining.unwrap_or(0),
                (field_names::MEMORIES_DROPPED): outcome.memories_dropped,
                "budget_overflow": outcome.budget_overflow,
            });
        }
        // F-L8a — fold the MEASURED semantic-withheld block into `meta`
        // (creating it if the budget sub-block above did not), so a
        // JSON-consuming CLI caller sees in-band when `mode:"hybrid"`
        // scored fewer rows than the corpus holds. CLI recall is a
        // MEASURED sqlite funnel.
        let sw = crate::models::SemanticWithheld::measured(&telemetry);
        let sw_value = serde_json::to_value(&sw).unwrap_or(serde_json::Value::Null);
        let meta = body
            .as_object_mut()
            .expect("recall body is always a JSON object")
            .entry("meta".to_string())
            .or_insert_with(|| serde_json::json!({}));
        if let Some(obj) = meta.as_object_mut() {
            obj.insert("semantic_withheld".to_string(), sw_value);
        }
        if want_toon {
            // Non-compact TOON: the full column set, via the SAME encoder the
            // MCP + HTTP surfaces use (`crate::toon`), fed the identical
            // envelope the JSON arm emits — so a `--format toon` reader and a
            // `--json` reader can never disagree about the result set.
            writeln!(
                out.stdout,
                "{}",
                crate::toon::memories_to_toon(&body, false)
            )?;
        } else {
            writeln!(out.stdout, "{}", serde_json::to_string(&body)?)?;
        }
        return Ok(());
    }
    // F-L8a — human-readable path: a concise stderr note when rows were
    // withheld from semantic scoring this query, so an operator running
    // `ai-memory recall` sees the same in-band degrade signal the JSON
    // caller gets (no `/metrics` on a one-shot CLI).
    {
        let withheld = telemetry.embedding_space_mismatch
            + telemetry.embedding_unverified_space
            + telemetry.embedding_dim_mismatch;
        if withheld > 0 {
            writeln!(
                out.stderr,
                "ai-memory: {withheld} row(s) withheld from semantic scoring \
                 (space_mismatch={}, unverified_space={}, dim_mismatch={}); \
                 kept keyword-recallable. Run `ai-memory reembed` to heal.",
                telemetry.embedding_space_mismatch,
                telemetry.embedding_unverified_space,
                telemetry.embedding_dim_mismatch,
            )?;
        }
    }
    if results.is_empty() {
        writeln!(out.stderr, "no memories found for: {}", args.context)?;
        return Ok(());
    }
    for (mem, score) in &results {
        let age = human_age(&mem.updated_at);
        let config = if mem.confidence < 1.0 {
            format!(" conf={:.0}%", mem.confidence * 100.0)
        } else {
            String::new()
        };
        writeln!(
            out.stdout,
            "[{}] {} {} score={:.2} (ns={}, {}x, {}{})",
            color::tier_color(
                mem.tier.as_str(),
                &format!("{}/{}", mem.tier, id_short(&mem.id))
            ),
            color::bold(&mem.title),
            color::priority_bar(mem.priority),
            score,
            color::cyan(&mem.namespace),
            mem.access_count,
            color::dim(&age),
            config
        )?;
        let preview: String = mem.content.chars().take(200).collect();
        writeln!(out.stdout, "  {}\n", color::dim(&preview))?;
    }
    writeln!(
        out.stdout,
        "{} memory(ies) recalled [{}]",
        results.len(),
        mode
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::{TestEnv, seed_memory};
    use crate::config::FeatureTier;

    fn default_args() -> RecallArgs {
        RecallArgs {
            context: "needle".to_string(),
            namespace: None,
            limit: 10,
            tags: None,
            since: None,
            until: None,
            valid_at: None,
            tier: Some("keyword".to_string()),
            as_agent: None,
            budget_tokens: None,
            context_tokens: None,
            session_default: false,
            include_archived: false,
            has_citations: false,
            source_uri_prefix: None,
            kind: None,
            // v0.7.0 #1098 — three CLI parity flags wired in via
            // `RecallRequest::from_cli_args`. Test fixtures default
            // to None / false / "human" so existing tests keep their
            // pre-#1098 semantics.
            confidence_tier: None,
            verbose_provenance: false,
            format: "human".to_string(),
            // v0.7.0 #1257 — CLI parity for session_id (DTO C2 #967).
            // Test fixtures default to None so existing tests keep
            // their pre-#1257 semantics (no in-session boost).
            session_id: None,
        }
    }

    #[test]
    fn test_recall_keyword_tier_no_embedder() {
        // Keyword tier => no embedder; the keyword branch must run
        // happily and find the seeded title.
        // #3092 isolation — pin AI_MEMORY_AGENT_ID UNSET (trust-all read)
        // so a concurrent `recall_cli_drops_cross_agent_private_row_2990`
        // set-var window can't hide the owner-keyed seeded row.
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "haystack content");
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, false, &cfg, &mut out).unwrap();
        }
        let stdout = env.stdout_str();
        assert!(stdout.contains("needle title"), "got: {stdout}");
        assert!(stdout.contains("[keyword]"), "got: {stdout}");
    }

    #[test]
    fn test_recall_json_emits_semantic_withheld_meta_fl8a() {
        // F-L8a — the CLI JSON envelope MUST carry the additive
        // `meta.semantic_withheld` block so a JSON-consuming CLI caller has
        // the same in-band withheld signal MCP/HTTP gained. Keyword tier
        // (no embedder) is a MEASURED sqlite funnel with no semantic
        // scoring, so the block is present, `measured:true`, and a truthful
        // zero.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "haystack content");
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let sw = &v["meta"]["semantic_withheld"];
        assert_eq!(sw["measured"], serde_json::json!(true), "got: {v}");
        assert_eq!(sw["total"], serde_json::json!(0), "got: {sw}");
        assert_eq!(sw["space_mismatch"], serde_json::json!(0));
        assert_eq!(sw["unverified_space"], serde_json::json!(0));
        assert_eq!(sw["dim_mismatch"], serde_json::json!(0));
    }

    // ---- #3005 — `--format {human,json,toon}` selects the renderer -------

    /// Pre-#3005 all three `--format` values rendered byte-identical HUMAN
    /// output. The three assertions below are exactly the measurement the
    /// issue reported (identical bytes for all three) inverted into a pin.
    #[test]
    fn recall_format_selects_the_renderer_3005() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let cfg = AppConfig::default();

        // OWNERSHIP-12 — return the captured bytes by value; `env` is local to
        // the closure, so handing back its `&str` view would dangle (E0515).
        let render = |format: &str| -> String {
            let mut env = TestEnv::fresh();
            let db = env.db_path.clone();
            seed_memory(&db, "test", "needle title", "haystack content");
            let mut args = default_args();
            args.format = format.to_string();
            {
                let mut out = env.output();
                run(&db, &args, false, &cfg, &mut out).unwrap();
            }
            env.stdout_str().to_string()
        };

        let human = render("human");
        let json = render(crate::toon::FORMAT_JSON);
        let toon = render(crate::toon::FORMAT_TOON);

        // human — the v0.6.x pretty renderer, unchanged.
        assert!(human.contains("needle title"), "got: {human}");
        assert!(human.contains("memory(ies) recalled"), "got: {human}");

        // json — parses as the same envelope `--json` produces.
        let v: serde_json::Value =
            serde_json::from_str(json.trim()).unwrap_or_else(|e| panic!("{e}: {json}"));
        assert_eq!(v["count"], serde_json::json!(1), "got: {v}");
        assert_eq!(v["memories"][0]["title"], serde_json::json!("needle title"));

        // toon — the TOON encoder's header+rows shape, NOT JSON, NOT human.
        assert!(toon.contains("memories["), "got: {toon}");
        assert!(toon.contains("needle title"), "got: {toon}");
        assert!(
            serde_json::from_str::<serde_json::Value>(toon.trim()).is_err(),
            "toon output must not be JSON: {toon}"
        );

        // The defect was that these were byte-identical.
        assert_ne!(human, json);
        assert_ne!(human, toon);
        assert_ne!(json, toon);
    }

    /// The GLOBAL `--json` keeps precedence over `--format`, so every
    /// pre-#3005 `--json` script keeps its exact envelope.
    #[test]
    fn recall_global_json_flag_wins_over_format_toon_3005() {
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "haystack content");
        let mut args = default_args();
        args.format = crate::toon::FORMAT_TOON.to_string();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"], serde_json::json!(1), "got: {v}");
    }

    #[test]
    fn test_recall_keyword_empty_results() {
        // No seeded rows => empty results => stderr emits "no memories
        // found for: ..." and stdout stays empty (text mode).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, false, &cfg, &mut out).unwrap();
        }
        assert_eq!(env.stdout_str(), "");
        assert!(
            env.stderr_str().contains("no memories found for: needle"),
            "got: {}",
            env.stderr_str()
        );
    }

    #[test]
    fn test_recall_keyword_with_namespace_filter() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "ns-a", "needle in a", "content a");
        seed_memory(&db, "ns-b", "needle in b", "content b");
        let mut args = default_args();
        args.namespace = Some("ns-a".to_string());
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        // JSON mode — parse and verify only the ns-a row came back.
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let mems = v["memories"].as_array().unwrap();
        for m in mems {
            assert_eq!(m["namespace"].as_str().unwrap(), "ns-a");
        }
    }

    #[test]
    fn test_recall_keyword_with_tags_filter() {
        // tags filter takes a string; absence of tags on seeded rows
        // means the filter excludes them. Just verify the call shape
        // doesn't error when a tags filter is supplied.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "content");
        let mut args = default_args();
        args.tags = Some("nonexistent".to_string());
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        // No row has the "nonexistent" tag => 0 results.
        assert_eq!(v["count"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_recall_keyword_with_since_until_window() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "content");
        let mut args = default_args();
        // A date range that excludes the just-now timestamp.
        args.since = Some("1970-01-01T00:00:00Z".to_string());
        args.until = Some("1970-01-02T00:00:00Z".to_string());
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 0);
    }

    #[test]
    fn test_recall_with_as_agent_scope_filter() {
        // --as-agent must validate as a namespace; passing a real
        // namespace exercises the validation branch and succeeds.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "content");
        let mut args = default_args();
        args.as_agent = Some("test".to_string());
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        // No assertion error; JSON shape comes through.
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert!(v["memories"].is_array());
    }

    /// v1.0.0 #2990 — seed a memory with an explicit `scope` + owner
    /// `agent_id` (the two `metadata` keys the visibility predicate reads),
    /// so the cross-agent private-visibility regression can assert on real
    /// scoped rows. Mirrors `seed_memory` field-for-field except for the two
    /// injected keys.
    fn seed_scoped(
        db_path: &Path,
        namespace: &str,
        title: &str,
        content: &str,
        scope: &str,
        owner: &str,
    ) -> String {
        use crate::models::{self, ConfidenceSource};
        let conn = db::open(db_path).expect("db::open");
        let now = chrono::Utc::now().to_rfc3339();
        let mut metadata = models::default_metadata();
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                crate::META_KEY_AGENT_ID.to_string(),
                serde_json::Value::String(owner.to_string()),
            );
            obj.insert(
                crate::META_KEY_SCOPE.to_string(),
                serde_json::Value::String(scope.to_string()),
            );
        }
        let mem = models::Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: models::Tier::Mid,
            namespace: namespace.to_string(),
            title: title.to_string(),
            content: content.to_string(),
            priority: 5,
            confidence: 1.0,
            source: "import".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata,
            memory_kind: models::MemoryKind::Observation,
            confidence_source: ConfidenceSource::CallerProvided,
            version: 1,
            lifecycle_state: models::LifecycleState::Open,
            ..Default::default()
        };
        db::insert(&conn, &mem).expect("db::insert")
    }

    #[test]
    fn recall_cli_drops_cross_agent_private_row_2990() {
        // v1.0.0 #2990 (GA Wave-1) — the shell-to-CLI recall path MUST apply
        // the same per-row ownership post-filter the MCP/HTTP recall paths
        // apply. Without `--as-agent`, the `db::recall*` SQL visibility gate
        // short-circuits to "all visible" (`?8`/private-prefix binds NULL),
        // so a cross-agent `scope=private` row would reach the CLI wire. The
        // `is_visible_to_caller` post-filter keyed on `AI_MEMORY_AGENT_ID`
        // closes the leak: agent A must NOT see agent B's private row, owner
        // B must, and a `collective` row is visible to both.
        //
        // Serialize on the crate-wide agent-id env lock (#1772) since this
        // test mutates `AI_MEMORY_AGENT_ID` process-wide.
        let _envg = crate::identity::agent_id_env_test_lock();
        let prev = std::env::var_os("AI_MEMORY_AGENT_ID");

        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Agent B's private row and a world-readable collective row, both
        // keyword-matching "needle". No `--as-agent` on the recall (the
        // common CLI shape that leaves the SQL gate inert).
        seed_scoped(
            &db,
            "test",
            "needle private",
            "bob secret",
            "private",
            "ai:bob",
        );
        seed_scoped(
            &db,
            "test",
            "needle collective",
            "shared body",
            "collective",
            "ai:bob",
        );

        let titles_for = |agent: &str, env: &mut TestEnv, db: &Path| -> Vec<String> {
            // SAFETY: process-global env mutation serialized on the
            // crate-wide agent-id test lock held for this test's body.
            unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", agent) };
            let args = default_args();
            let cfg = AppConfig::default();
            {
                let mut out = env.output();
                run(db, &args, true, &cfg, &mut out).unwrap();
            }
            let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
            let titles = v["memories"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["title"].as_str().unwrap().to_string())
                .collect::<Vec<_>>();
            env.stdout.clear();
            env.stderr.clear();
            titles
        };

        // Agent A (ai:alice) — private row owned by ai:bob is HIDDEN; the
        // collective row is visible.
        let alice = titles_for("ai:alice", &mut env, &db);
        assert!(
            !alice.iter().any(|t| t == "needle private"),
            "CONFIDENTIALITY LEAK: agent A saw agent B's private row: {alice:?}"
        );
        assert!(
            alice.iter().any(|t| t == "needle collective"),
            "collective row must be visible to agent A: {alice:?}"
        );

        // Owner B (ai:bob) — sees its own private row AND the collective row.
        let bob = titles_for("ai:bob", &mut env, &db);
        assert!(
            bob.iter().any(|t| t == "needle private"),
            "owner B must see its own private row: {bob:?}"
        );
        assert!(
            bob.iter().any(|t| t == "needle collective"),
            "collective row must be visible to owner B: {bob:?}"
        );

        // Restore the pre-test env (still holding the lock).
        // SAFETY: serialized on the crate-wide agent-id test lock.
        match prev {
            Some(v) => unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", v) },
            None => unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") },
        }
    }

    /// #2988 — the recall ledger MUST bind the RECALLING agent's identity
    /// (the `resolve_read_visibility_caller` value the MCP/HTTP surface
    /// stamps), NEVER the `--as-agent` NAMESPACE. Pre-fix the CLI wrote
    /// `--as-agent` into the `agent_id` column, making the #1705 cross-agent
    /// replay guard (`mark_consumed_guarded`: `agent_id IS NULL OR
    /// agent_id = ?`) inert — a namespace can't gate an identity, and a
    /// WRONG identity is worse than NULL. This pins the caller-identity bind.
    #[test]
    fn recall_ledger_binds_caller_identity_not_as_agent_2988() {
        // Serialize on the crate-wide agent-id env lock (#1772) since this
        // test mutates `AI_MEMORY_AGENT_ID` process-wide.
        let _envg = crate::identity::agent_id_env_test_lock();
        let prev = std::env::var_os("AI_MEMORY_AGENT_ID");

        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Seed a COLLECTIVE row so the #2990 per-row ownership post-filter does
        // not hide it from the non-owner caller (else there would be no ledger
        // row to inspect).
        seed_scoped(
            &db,
            "proj/a",
            "needle ledger title",
            "content",
            "collective",
            "ai:owner",
        );

        let mut args = default_args();
        args.namespace = Some("proj/a".to_string());
        // A NAMESPACE, deliberately equal-shaped to a slash-scoped id so the
        // pre-fix "namespace in the identity column" bug would go unnoticed by
        // a shape check alone.
        args.as_agent = Some("proj/a".to_string());
        let cfg = AppConfig::default();

        // SAFETY: process-global env mutation serialized on the crate-wide
        // agent-id test lock held for this test's body.
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:cert-fed-proxy") };
        {
            let mut out = env.output();
            let _ = run(&db, &args, true, &cfg, &mut out);
        }
        // Restore BEFORE asserting so a failure never leaks the var.
        // SAFETY: serialized on the crate-wide agent-id test lock.
        match prev {
            Some(v) => unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", v) },
            None => unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") },
        }

        let conn = db::open(&db).unwrap();
        let ids: Vec<Option<String>> = conn
            .prepare("SELECT DISTINCT agent_id FROM recall_observations")
            .unwrap()
            .query_map([], |r| r.get::<_, Option<String>>(0))
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect();
        assert!(
            ids.iter()
                .any(|id| id.as_deref() == Some("ai:cert-fed-proxy")),
            "recall ledger must bind the caller identity (#2988); got {ids:?}"
        );
        assert!(
            !ids.iter().any(|id| id.as_deref() == Some("proj/a")),
            "the --as-agent NAMESPACE must NOT land in the agent_id column (#2988); got {ids:?}"
        );
    }

    #[test]
    fn test_recall_with_budget_tokens_caps_results() {
        // budget_tokens flips through into recall(); JSON envelope
        // includes the budget echo when set.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle one", "content one");
        seed_memory(&db, "test", "needle two", "content two");
        let mut args = default_args();
        args.budget_tokens = Some(64);
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["budget_tokens"].as_u64().unwrap(), 64);
    }

    #[test]
    fn test_recall_json_output_includes_score_mode_tokens() {
        // #3092 isolation — see note on `test_recall_keyword_tier_no_embedder`:
        // this test asserts the seeded row is PRESENT, so it must run with
        // AI_MEMORY_AGENT_ID unset (serialized against the #2990 mutator).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "haystack content");
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["mode"].as_str().unwrap(), "keyword");
        assert!(v["tokens_used"].is_number());
        let mems = v["memories"].as_array().unwrap();
        assert!(!mems.is_empty(), "expected at least one match");
        for m in mems {
            assert!(m["score"].is_number());
        }
    }

    #[test]
    fn test_recall_text_output_formats_correctly() {
        // #3092 isolation — asserts the seeded row is PRESENT in stdout;
        // pin AI_MEMORY_AGENT_ID unset (serialized against the #2990 mutator).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test-ns", "needle title", "haystack content");
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, false, &cfg, &mut out).unwrap();
        }
        let stdout = env.stdout_str();
        // Header line: tier/short-id, title, score, namespace.
        assert!(stdout.contains("needle title"));
        assert!(stdout.contains("ns="));
        assert!(stdout.contains("score="));
        assert!(stdout.contains("memory(ies) recalled"));
    }

    #[test]
    fn test_recall_invalid_as_agent_namespace_validation_error() {
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut args = default_args();
        // Invalid namespace: empty after trimming, or contains illegal chars.
        args.as_agent = Some(String::new());
        let cfg = AppConfig::default();
        let mut out = env.output();
        let res = run(&db, &args, false, &cfg, &mut out);
        assert!(res.is_err(), "expected validate_namespace to reject");
    }

    #[test]
    fn test_recall_with_context_tokens_fusion() {
        // With tier=keyword, no embedder is built, so the fusion path
        // is skipped entirely and the call falls through the keyword
        // branch. This proves the fall-through path exists when an
        // embedder is absent. The actual fusion path requires a real
        // embedder and is exercised under feature = "test-with-models".
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "content");
        let mut args = default_args();
        args.context_tokens = Some(vec!["recent".to_string(), "talk".to_string()]);
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["mode"].as_str().unwrap(), "keyword");
    }

    #[test]
    fn test_recall_embedder_failure_falls_back_to_keyword() {
        // Same shape as the no-embedder test, but routed through the
        // build_embedder_for_recall path. Keyword tier => Ok(None) and
        // no stderr emission about embedder failure.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "content");
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["mode"].as_str().unwrap(), "keyword");
        // No embedder messages on stderr in the keyword branch.
        let stderr = env.stderr_str();
        assert!(
            !stderr.contains("embedder loaded"),
            "no embedder should be loaded on keyword tier"
        );
    }

    /// Coverage lift (per-module floor): pins the text-mode
    /// `conf=NN%` suffix arm. Rows with `confidence < 1.0` must render
    /// their confidence percentage in the header line; the seeded
    /// default (1.0) never exercises that arm, so this seeds a 0.5-
    /// confidence row directly via `db::insert`.
    #[test]
    fn test_recall_text_output_shows_confidence_below_full() {
        // #3092 isolation — asserts the inserted row renders `conf=50%`, i.e.
        // it must be PRESENT; pin AI_MEMORY_AGENT_ID unset (serialized against
        // the #2990 mutator). The row's owner ("") never equals a leaked agent.
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        {
            let conn = crate::db::open(&db).unwrap();
            let now = chrono::Utc::now().to_rfc3339();
            let mem = crate::models::Memory {
                cid: None,
                valid_from: None,
                valid_until: None,
                id: uuid::Uuid::new_v4().to_string(),
                tier: crate::models::Tier::Mid,
                namespace: "test".to_string(),
                title: "needle low-confidence".to_string(),
                content: "uncertain content".to_string(),
                tags: vec![],
                priority: 5,
                confidence: 0.5,
                source: "import".to_string(),
                access_count: 0,
                created_at: now.clone(),
                updated_at: now,
                last_accessed_at: None,
                expires_at: None,
                metadata: crate::models::default_metadata(),
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
            crate::db::insert(&conn, &mem).unwrap();
        }
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, false, &cfg, &mut out).unwrap();
        }
        let stdout = env.stdout_str();
        assert!(
            stdout.contains("conf=50%"),
            "confidence < 1.0 must render the conf= suffix; got: {stdout}"
        );
    }

    /// Coverage lift (per-module floor): pins the
    /// `Handle::try_current()` → `block_in_place` bridge arm. When
    /// `run()` is invoked from inside an existing multi-threaded tokio
    /// runtime (the `daemon_runtime::run` path), it must NOT build a
    /// nested runtime — it drives `build_embedder` on the ambient
    /// handle via `block_in_place`. Keyword tier keeps the embedder
    /// build a no-op so the test stays model-free and offline.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_recall_inside_runtime_uses_block_in_place_bridge() {
        // #3092 isolation — asserts `count >= 1` (seeded row PRESENT); pin
        // AI_MEMORY_AGENT_ID unset (serialized against the #2990 mutator).
        // The guard is !Send but is held across no await in this body.
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "haystack content");
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["mode"].as_str().unwrap(), "keyword");
        assert!(v["count"].as_u64().unwrap() >= 1, "seeded row must match");
    }

    #[tokio::test]
    async fn test_shared_build_embedder_keyword_returns_none() {
        // W6 — recall now delegates embedder construction to
        // `daemon_runtime::build_embedder`. Smoke-test that the keyword
        // tier short-circuit still yields `None` (no model load attempt,
        // no panic).
        let cfg = AppConfig::default();
        let res = daemon_runtime::build_embedder(
            FeatureTier::Keyword,
            &cfg,
            std::path::Path::new(crate::daemon_runtime::DEFAULT_DB),
        )
        .await;
        assert!(res.is_none(), "keyword tier must not build an embedder");
    }

    // ----------------------------------------------------------------
    // L0.7-3 chunk-e2 — coverage uplift to ≥95%.
    // ----------------------------------------------------------------

    /// Build an AppConfig with a recall_scope so `--session-default`
    /// has something to splice in. Uses TOML parsing because
    /// `AppConfig` does not directly expose builder methods for the
    /// nested defaults block.
    fn app_config_with_recall_scope() -> AppConfig {
        let toml = r#"
tier = "keyword"

[agents.defaults.recall_scope]
namespaces = ["scope-ns"]
since = "1d"
tier = "long"
limit = 25
"#;
        toml::from_str(toml).expect("parse test config")
    }

    #[test]
    fn recall_session_default_splices_namespace_and_since_from_scope() {
        // Drives the session_default scope path (lines 90-110).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Seed a memory in the scoped namespace.
        seed_memory(&db, "scope-ns", "needle title", "scoped");
        // Seed a memory in another namespace which should be filtered out.
        seed_memory(&db, "other-ns", "needle elsewhere", "other");
        let mut args = default_args();
        args.session_default = true;
        // Leave namespace=None so the scope splice picks "scope-ns".
        let cfg = app_config_with_recall_scope();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        // Only memories in scope-ns survive.
        for m in v["memories"].as_array().unwrap() {
            assert_eq!(m["namespace"].as_str().unwrap(), "scope-ns");
        }
    }

    #[test]
    fn recall_session_default_explicit_namespace_wins_over_scope() {
        // Explicit args > scope (line 95: args.namespace.clone().or_else).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "scope-ns", "needle title", "content");
        seed_memory(&db, "explicit-ns", "needle elsewhere", "content");
        let mut args = default_args();
        args.session_default = true;
        args.namespace = Some("explicit-ns".to_string());
        let cfg = app_config_with_recall_scope();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        for m in v["memories"].as_array().unwrap() {
            assert_eq!(m["namespace"].as_str().unwrap(), "explicit-ns");
        }
    }

    #[test]
    fn recall_session_default_with_explicit_limit_does_not_apply_scope_limit() {
        // When args.limit != default (10), the scope.limit splice is
        // skipped (line 117 condition).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        for i in 0..5 {
            seed_memory(&db, "scope-ns", &format!("needle {i}"), "c");
        }
        let mut args = default_args();
        args.session_default = true;
        args.limit = 2; // explicit override
        let cfg = app_config_with_recall_scope();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        let mems = v["memories"].as_array().unwrap();
        assert!(mems.len() <= 2, "explicit limit=2 should cap results");
    }

    // ------------------------------------------------------------------
    // L0.7-3 chunk-e2 — embedder-driven branches via run_with_embedder.
    // ------------------------------------------------------------------

    /// Embedder that returns an error on `embed` — drives the
    /// "embedding query failed, falling back to keyword" branch.
    struct FailingEmbedder;
    impl Embed for FailingEmbedder {
        fn embed(&self, _text: &str) -> Result<Vec<f32>> {
            anyhow::bail!("synthetic embed failure for test")
        }
    }

    /// Embedder that errors only when the input is exactly "joined
    /// context tokens" — drives the fuse-failure branch (primary
    /// succeeds, context_tokens embed fails).
    struct FailOnContextTokens {
        joined_marker: String,
    }
    impl Embed for FailOnContextTokens {
        fn embed(&self, text: &str) -> Result<Vec<f32>> {
            if text == self.joined_marker {
                anyhow::bail!("synthetic context-tokens failure")
            }
            let mock = crate::embeddings::test_support::MockEmbedder::new_local()?;
            mock.embed(text)
        }
    }

    #[test]
    fn recall_with_embedder_takes_hybrid_path() {
        // run_with_embedder + MockEmbedder drives the `embedder.is_some()`
        // branch in run_with_embedder including embedder-loaded banner,
        // backfill, vector index build, and the hybrid recall_hybrid call.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "content");
        let mut conn = db::open(&db).unwrap();
        let mock = crate::embeddings::test_support::MockEmbedder::new_local().unwrap();
        let args = default_args();
        let cfg = AppConfig::default();
        let feature_tier = FeatureTier::Keyword;
        {
            let mut out = env.output();
            run_with_embedder(
                &mut conn,
                &args,
                true,
                &cfg,
                feature_tier,
                Some(&mock as &dyn Embed),
                Some(mock.model_description()),
                &mut out,
            )
            .unwrap();
        }
        let stderr = env.stderr_str();
        assert!(stderr.contains("embedder loaded"), "got: {stderr}");
        // #1579 B6-CLI: the backfill banner now comes from the shared
        // batched helper (process stderr, not the captured CliOutput),
        // so assert the backfill EFFECT instead: the seeded row gained
        // an embedding.
        {
            let conn2 = db::open(&db).unwrap();
            let ids = db::get_unembedded_ids(&conn2).unwrap();
            assert!(
                ids.is_empty(),
                "batched backfill must embed every unembedded row; left: {ids:?}"
            );
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["mode"].as_str().unwrap(), "hybrid");
    }

    // -----------------------------------------------------------------
    // #1579 B3 — CLI HNSW build threshold
    // -----------------------------------------------------------------

    #[test]
    fn b3_1579_should_build_cli_hnsw_threshold() {
        use crate::hnsw::CLI_HNSW_BUILD_MIN_ENTRIES;
        assert!(
            !should_build_cli_hnsw(0),
            "empty corpus never builds a graph"
        );
        assert!(
            !should_build_cli_hnsw(i64::try_from(CLI_HNSW_BUILD_MIN_ENTRIES - 1).unwrap()),
            "one under the threshold: linear scan wins"
        );
        assert!(
            should_build_cli_hnsw(i64::try_from(CLI_HNSW_BUILD_MIN_ENTRIES).unwrap()),
            "at the threshold: build"
        );
        assert!(!should_build_cli_hnsw(-1), "garbage counts never build");
    }

    #[test]
    fn b3_1579_small_corpus_recall_skips_hnsw_and_still_answers_semantically() {
        // Below CLI_HNSW_BUILD_MIN_ENTRIES the vector_index is None and
        // the recall pipeline's linear-scan fallback serves the
        // semantic phase — results must still come back in hybrid mode.
        // #3092 isolation — asserts the seeded row is PRESENT; pin
        // AI_MEMORY_AGENT_ID unset (serialized against the #2990 mutator).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "needle content body");
        let mut conn = db::open(&db).unwrap();
        let mock = crate::embeddings::test_support::MockEmbedder::new_local().unwrap();
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run_with_embedder(
                &mut conn,
                &args,
                true,
                &cfg,
                FeatureTier::Keyword,
                Some(&mock as &dyn Embed),
                Some(mock.model_description()),
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(
            v["mode"].as_str().unwrap(),
            "hybrid",
            "semantic phase must still answer via the linear-scan fallback"
        );
        assert!(
            v["memories"].as_array().is_some_and(|r| !r.is_empty()),
            "seeded row must be recalled without an HNSW graph; got: {v}"
        );
    }

    #[test]
    fn recall_with_embedder_failing_primary_falls_back_to_keyword() {
        // FailingEmbedder errors on the primary `embed(query)`. The
        // recall handler emits the "embedding query failed" banner and
        // falls back to db::recall (lines 272-291 in original).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "content");
        let mut conn = db::open(&db).unwrap();
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run_with_embedder(
                &mut conn,
                &args,
                true,
                &cfg,
                FeatureTier::Keyword,
                Some(&FailingEmbedder as &dyn Embed),
                Some("failing-mock"),
                &mut out,
            )
            .unwrap();
        }
        let stderr = env.stderr_str();
        // v1.0.0 #2577 — wording changed with the bounded funnel: the CLI
        // line no longer interpolates the embedder error (the structured
        // `recall.embed.degraded` WARN carries it), and now names the
        // BUDGET, because "unavailable within budget" is the new cause an
        // operator has to act on. The invariant under test is unchanged:
        // an embed failure emits a visible banner and the recall degrades
        // to keyword.
        assert!(
            stderr.contains("embedding query unavailable within budget"),
            "expected fallback banner; got: {stderr}"
        );
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["mode"].as_str().unwrap(), "keyword");
    }

    #[test]
    fn recall_with_embedder_context_tokens_fail_uses_primary_only() {
        // Primary embed OK, context_tokens embed fails → emit the
        // "context_tokens embed failed" banner and continue with
        // primary_emb alone.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "content");
        let mut conn = db::open(&db).unwrap();
        let mock = FailOnContextTokens {
            joined_marker: "alpha beta".to_string(),
        };
        let mut args = default_args();
        args.context_tokens = Some(vec!["alpha".into(), "beta".into()]);
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run_with_embedder(
                &mut conn,
                &args,
                true,
                &cfg,
                FeatureTier::Keyword,
                Some(&mock as &dyn Embed),
                Some("primary-ok-context-fail"),
                &mut out,
            )
            .unwrap();
        }
        let stderr = env.stderr_str();
        // v1.0.0 #2577 — see the wording note above; same invariant.
        assert!(
            stderr.contains("context_tokens embed unavailable"),
            "got: {stderr}"
        );
    }

    #[test]
    fn recall_with_embedder_context_tokens_success_drives_fuse() {
        // Primary OK + context_tokens OK → triggers the fuse() path.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "content");
        let mut conn = db::open(&db).unwrap();
        let mock = crate::embeddings::test_support::MockEmbedder::new_local().unwrap();
        let mut args = default_args();
        args.context_tokens = Some(vec!["a".into(), "b".into()]);
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run_with_embedder(
                &mut conn,
                &args,
                true,
                &cfg,
                FeatureTier::Keyword,
                Some(&mock as &dyn Embed),
                Some(mock.model_description()),
                &mut out,
            )
            .unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["mode"].as_str().unwrap(), "hybrid");
    }

    #[test]
    fn recall_with_embedder_load_failed_emits_failed_banner() {
        // tier_config.embedding_model.is_some() && embedder=None → emit
        // the "embedder failed to load, falling back to keyword" banner.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "content");
        let mut conn = db::open(&db).unwrap();
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run_with_embedder(
                &mut conn,
                &args,
                true,
                &cfg,
                FeatureTier::Semantic, // tier_config.embedding_model = Some
                None,                  // simulate failed load
                None,
                &mut out,
            )
            .unwrap();
        }
        let stderr = env.stderr_str();
        assert!(
            stderr.contains("embedder failed to load"),
            "expected failed-load banner; got: {stderr}"
        );
    }

    #[test]
    fn recall_text_output_no_embedder_with_low_confidence_emits_conf_pct() {
        // Drives the `confidence < 1.0` branch in the text output loop
        // (line 350) which formats " conf=XX%". Use a custom inserted
        // memory with confidence below 1.0.
        // #3092 isolation — asserts the inserted row renders `conf=42%`
        // (PRESENT); pin AI_MEMORY_AGENT_ID unset (serialized against the
        // #2990 mutator). The row's owner "t" never equals a leaked agent.
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        // Insert a low-confidence memory directly.
        let mut conn = db::open(&db).unwrap();
        let mut mem = crate::models::Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Mid,
            namespace: "test".to_string(),
            title: "needle low".to_string(),
            content: "low confidence content".to_string(),
            tags: vec![],
            priority: 5,
            confidence: 0.42,
            source: "import".to_string(),
            access_count: 0,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            last_accessed_at: None,
            expires_at: None,
            metadata: crate::models::default_metadata(),
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
        if let Some(obj) = mem.metadata.as_object_mut() {
            obj.insert("agent_id".to_string(), serde_json::json!("t"));
        }
        db::insert(&conn, &mem).unwrap();
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            // text mode (json_out=false) — drives the text-rendering loop.
            run_with_embedder(
                &mut conn,
                &args,
                false,
                &cfg,
                FeatureTier::Keyword,
                None,
                None,
                &mut out,
            )
            .unwrap();
        }
        let stdout = env.stdout_str();
        assert!(stdout.contains("conf=42%"), "got: {stdout}");
        assert!(stdout.contains("memory(ies) recalled"), "got: {stdout}");
    }

    #[test]
    fn recall_text_output_no_results_emits_no_memories_message() {
        // Empty result text path (lines 343-345).
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        let mut conn = db::open(&db).unwrap();
        let args = default_args();
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run_with_embedder(
                &mut conn,
                &args,
                false,
                &cfg,
                FeatureTier::Keyword,
                None,
                None,
                &mut out,
            )
            .unwrap();
        }
        let stderr = env.stderr_str();
        assert!(stderr.contains("no memories found"), "got: {stderr}");
    }

    #[test]
    fn recall_session_default_off_does_not_splice_scope() {
        // session_default=false short-circuits the scope branch to None
        // (line 92), so the configured scope is invisible.
        // #3092 isolation — asserts both seeded namespaces are PRESENT
        // (`nses.len() >= 2 || contains("other-ns")`); pin AI_MEMORY_AGENT_ID
        // unset (serialized against the #2990 mutator). This is the exact
        // assertion observed flaking in CI.
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "scope-ns", "needle title", "content");
        seed_memory(&db, "other-ns", "needle elsewhere", "content");
        let mut args = default_args();
        args.session_default = false;
        let cfg = app_config_with_recall_scope();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        // Both namespaces should be visible — no scope splice.
        let nses: std::collections::HashSet<String> = v["memories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["namespace"].as_str().unwrap().to_string())
            .collect();
        assert!(nses.len() >= 2 || nses.contains("other-ns"));
    }

    // -----------------------------------------------------------------
    // v0.7-polish coverage recovery (issue #767) — Form 4 + Form 6
    // filter coverage. Drives apply_form4_recall_filters every-branch
    // and the run() integration of --source-uri-prefix / --has-citations
    // / --kind no-match paths.
    // -----------------------------------------------------------------

    #[test]
    fn apply_form4_recall_filters_no_filter_passes_through() {
        // Both filters absent → original results returned verbatim.
        let m = crate::models::Memory {
            id: "id".to_string(),
            ..Default::default()
        };
        let input = vec![(m.clone(), 0.5)];
        let out = apply_form4_recall_filters(input, false, None);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn apply_form4_recall_filters_has_citations_drops_empty_citations() {
        let mut a = crate::models::Memory {
            id: "a".to_string(),
            ..Default::default()
        };
        a.citations = vec![crate::models::Citation {
            uri: "doc:x".to_string(),
            accessed_at: "2026-01-01T00:00:00Z".to_string(),
            hash: None,
            span: None,
        }];
        let b = crate::models::Memory {
            id: "b".to_string(),
            ..Default::default()
        };
        let input = vec![(a, 0.9), (b, 0.8)];
        let out = apply_form4_recall_filters(input, true, None);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.id, "a");
    }

    #[test]
    fn apply_form4_recall_filters_source_uri_prefix_drops_non_matches() {
        let mut a = crate::models::Memory {
            id: "a".to_string(),
            ..Default::default()
        };
        a.source_uri = Some("uri:https://example.com/path".to_string());
        let mut b = crate::models::Memory {
            id: "b".to_string(),
            ..Default::default()
        };
        b.source_uri = Some("uri:https://other.org/elsewhere".to_string());
        let c = crate::models::Memory {
            id: "c".to_string(),
            ..Default::default()
        };
        // c has source_uri = None → excluded by prefix filter.
        let input = vec![(a, 1.0), (b, 0.9), (c, 0.8)];
        let out = apply_form4_recall_filters(input, false, Some("uri:https://example.com"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.id, "a");
    }

    #[test]
    fn apply_form4_recall_filters_source_uri_prefix_no_matches_returns_empty() {
        // The 0.2% gap closure for cli/recall.rs — drives the
        // "filter declared, nothing matches" path.
        let mut a = crate::models::Memory {
            id: "a".to_string(),
            ..Default::default()
        };
        a.source_uri = Some("uri:https://example.com/path".to_string());
        let input = vec![(a, 1.0)];
        let out =
            apply_form4_recall_filters(input, false, Some("uri:https://nothing-matches.invalid"));
        assert!(out.is_empty(), "expected no matches for unrelated prefix");
    }

    #[test]
    fn apply_form4_recall_filters_combined_has_citations_and_prefix() {
        let mut a = crate::models::Memory {
            id: "a".to_string(),
            ..Default::default()
        };
        a.citations = vec![crate::models::Citation {
            uri: "doc:x".to_string(),
            accessed_at: "2026-01-01T00:00:00Z".to_string(),
            hash: None,
            span: None,
        }];
        a.source_uri = Some("uri:https://example.com/x".to_string());
        // Has citations but wrong prefix.
        let mut b = crate::models::Memory {
            id: "b".to_string(),
            ..Default::default()
        };
        b.citations = vec![crate::models::Citation {
            uri: "doc:y".to_string(),
            accessed_at: "2026-01-01T00:00:00Z".to_string(),
            hash: None,
            span: None,
        }];
        b.source_uri = Some("uri:https://other.org/y".to_string());
        let input = vec![(a, 0.9), (b, 0.8)];
        let out = apply_form4_recall_filters(input, true, Some("uri:https://example.com"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.id, "a");
    }

    #[test]
    fn recall_with_source_uri_prefix_no_match_returns_empty_envelope() {
        // End-to-end via run(): seed two memories without source_uri,
        // then ask for source_uri_prefix that never matches.
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "haystack content");
        let mut args = default_args();
        args.source_uri_prefix = Some("uri:https://no-such-source.invalid".to_string());
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        assert_eq!(v["count"].as_u64().unwrap(), 0);
        assert!(v["memories"].as_array().unwrap().is_empty());
    }

    #[test]
    fn recall_with_kind_filter_all_keyword_is_noop() {
        // --kind=all parses to None → no filter applied.
        // #3092 isolation — asserts `count >= 1` (seeded row PRESENT); pin
        // AI_MEMORY_AGENT_ID unset (serialized against the #2990 mutator).
        let _agent_env = crate::identity::agent_id_env_unset_guard();
        let mut env = TestEnv::fresh();
        let db = env.db_path.clone();
        seed_memory(&db, "test", "needle title", "haystack content");
        let mut args = default_args();
        args.kind = Some("ALL".to_string());
        let cfg = AppConfig::default();
        {
            let mut out = env.output();
            run(&db, &args, true, &cfg, &mut out).unwrap();
        }
        let v: serde_json::Value = serde_json::from_str(env.stdout_str().trim()).unwrap();
        // The "all" sentinel passes through every memory (no kind filter).
        assert!(
            v["count"].as_u64().unwrap() >= 1,
            "expected at least one match under --kind=all"
        );
    }
}
