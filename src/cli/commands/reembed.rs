// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1598 — `ai-memory reembed` CLI subcommand.
//!
//! The operator-facing vector-space migration tool for the API-wired
//! embeddings train: re-embeds EVERY live memory (optionally
//! namespace-filtered) with the currently-resolved embedding backend +
//! model, REPLACING each stored vector. Unlike the boot backfill
//! (which only fills `embedding IS NULL` rows), `reembed` rewrites
//! rows that already carry vectors — it is the tool that moves a
//! corpus from one model/dim to another (e.g. local MiniLM 384-dim →
//! an OpenAI-compatible API model at 768/1536-dim).
//!
//! ## Resolution contract
//!
//! The embedder is resolved through the SAME path as daemon/MCP boot:
//! [`crate::config::AppConfig::resolve_embeddings`] +
//! [`crate::embeddings::Embedder::from_resolved`], with the tier model
//! gated exactly like [`crate::daemon_runtime::build_embedder`] (API
//! backends bypass the local model picker; the tier preset only gates
//! whether embeddings are enabled at all). A keyword-only tier errors
//! out with a clear message ([`EXIT_NO_EMBEDDER`]).
//!
//! ## Failure isolation
//!
//! Per-chunk embedding routes through the shared #1595 primitive
//! ([`crate::mcp::embed_rows_with_fallback`]): a chunk-level
//! `embed_batch` fault falls back to per-row embeds; rows that still
//! fail (or exceed the client-side
//! [`crate::embeddings::EMBED_MAX_BYTES`] cap) are skipped with a WARN
//! naming the row id + reason and KEEP their previous vector. Writes
//! go through [`crate::db::set_embeddings_batch_reembed`], the
//! replace-semantics writer that legitimately bypasses the G4
//! namespace-dim invariant mid-migration (the H7 recall read-guards
//! skip dim-mismatched vectors during the transition).

use std::path::Path;

use anyhow::Result;
use clap::Args;
use serde_json::json;

use crate::cli::CliOutput;
use crate::config::AppConfig;
use crate::db;
use crate::embeddings::Embed;

/// Exit code when no embedding-capable tier/backend is configured
/// (503-equivalent — the embedding surface is unreachable by config).
pub const EXIT_NO_EMBEDDER: i32 = 2;

/// Exit code when an embedder is configured but its construction
/// failed (502-equivalent — dead endpoint, bad key, unknown dim).
pub const EXIT_EMBEDDER_INIT_FAILED: i32 = 3;

/// CLI args for `ai-memory reembed`.
#[derive(Args, Debug, Clone)]
pub struct ReembedArgs {
    /// Restrict the sweep to one namespace (default: every namespace).
    #[arg(long)]
    pub namespace: Option<String>,

    /// Print the migration plan ({total_rows, rows_with_embeddings,
    /// rows_missing_embeddings, target_model, target_dim, backend})
    /// and exit 0 without writing anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Rows per embed/write batch. Overrides the resolved
    /// `[embeddings].backfill_batch` / AI_MEMORY_EMBED_BACKFILL_BATCH
    /// value; 0 falls through to the resolved value.
    #[arg(long)]
    pub batch: Option<usize>,

    /// Emit machine-readable JSON (the plan on --dry-run, the
    /// {total, reembedded, skipped, model, dim, duration_ms} summary
    /// on a live run) instead of the human-readable lines.
    #[arg(long)]
    pub json: bool,
}

/// Dry-run migration plan — what the sweep WOULD touch plus the
/// resolved target vector space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReembedPlan {
    pub(crate) total_rows: u64,
    pub(crate) rows_with_embeddings: u64,
    pub(crate) rows_missing_embeddings: u64,
    pub(crate) target_model: String,
    pub(crate) target_dim: usize,
    pub(crate) backend: String,
}

/// Live-run totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ReembedOutcome {
    /// Rows scanned (the namespace-filtered live corpus).
    pub(crate) total: usize,
    /// Rows whose vector was written this run.
    pub(crate) reembedded: usize,
    /// Rows skipped (oversize input or per-row embed failure); they
    /// keep their previous vector (or stay unembedded).
    pub(crate) skipped: usize,
}

/// Build the dry-run plan for the (optionally namespace-filtered)
/// corpus against the resolved target model/dim/backend.
///
/// # Errors
///
/// Bubbles the underlying SQLite error from the coverage counts.
pub(crate) fn build_plan(
    conn: &rusqlite::Connection,
    namespace: Option<&str>,
    target_model: &str,
    target_dim: usize,
    backend: &str,
) -> Result<ReembedPlan> {
    let (total_rows, rows_with_embeddings) = db::embedding_coverage(conn, namespace)?;
    Ok(ReembedPlan {
        total_rows,
        rows_with_embeddings,
        rows_missing_embeddings: total_rows.saturating_sub(rows_with_embeddings),
        target_model: target_model.to_string(),
        target_dim,
        backend: backend.to_string(),
    })
}

/// `--batch` precedence: an explicit positive flag wins; 0 / absent
/// falls through to the resolved `backfill_batch`; a degenerate 0
/// from BOTH sources is coerced to the compiled default so the keyset
/// scan can never become a no-op-forever `LIMIT 0`.
pub(crate) fn resolve_batch_size(batch_flag: Option<usize>, resolved_default: usize) -> usize {
    batch_flag
        .filter(|&n| n > 0)
        .or(Some(resolved_default).filter(|&n| n > 0))
        .unwrap_or(crate::mcp::DEFAULT_EMBED_BACKFILL_BATCH_SIZE)
}

/// The full-corpus replace sweep. Scans live memories in `id`-keyset
/// batches ([`db::get_memory_texts_batch`]), embeds each chunk with
/// per-row failure isolation ([`crate::mcp::embed_rows_with_fallback`],
/// Document role — `Embed::embed` applies the document task prefix
/// where the model requires one), and REPLACES the stored vectors via
/// [`db::set_embeddings_batch_reembed`]. Skip WARNs go to `out.stderr`
/// (one line per row + the totals in the summary the caller prints).
///
/// # Errors
///
/// Bubbles SQLite scan/write errors and stderr I/O errors. Per-row
/// embed failures do NOT propagate — they are counted as skips.
pub(crate) fn run_reembed_live(
    conn: &mut rusqlite::Connection,
    emb: &dyn Embed,
    namespace: Option<&str>,
    batch_size: usize,
    out: &mut CliOutput<'_>,
) -> Result<ReembedOutcome> {
    let mut outcome = ReembedOutcome::default();
    let mut cursor: Option<String> = None;
    loop {
        let chunk = db::get_memory_texts_batch(conn, namespace, cursor.as_deref(), batch_size)?;
        if chunk.is_empty() {
            break;
        }
        outcome.total += chunk.len();
        cursor = chunk.last().map(|(id, _, _)| id.clone());

        let embedded = crate::mcp::embed_rows_with_fallback(emb, &chunk);
        for (id, reason) in &embedded.skipped {
            writeln!(
                out.stderr,
                "reembed: skipped row {id}: {reason} (previous vector kept, #1598)"
            )?;
        }
        outcome.skipped += embedded.skipped.len();
        if embedded.entries.is_empty() {
            continue;
        }
        outcome.reembedded += db::set_embeddings_batch_reembed(conn, &embedded.entries)?;
    }
    Ok(outcome)
}

/// `ai-memory reembed` dispatch entry. Resolves the embedder through
/// the boot ladder, prints the loud pre-flight dim disclosure, then
/// either prints the plan (`--dry-run`) or runs the replace sweep.
///
/// Exit-code contract (mirrors `ai-memory expand`):
/// - `0` — success (plan printed, or sweep completed).
/// - [`EXIT_NO_EMBEDDER`] (`2`) — keyword-only tier, no embedding
///   model configured.
/// - [`EXIT_EMBEDDER_INIT_FAILED`] (`3`) — embedder construction
///   failed (dead endpoint, bad key, unknown dim).
///
/// # Errors
///
/// Propagates DB open/scan/write failures and stdout/stderr I/O
/// errors. Embedder-configuration outcomes map to exit codes.
pub async fn cmd_reembed(
    db_path: &Path,
    args: &ReembedArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let feature_tier = app_config.effective_tier(None);
    let tier_config = feature_tier.config();
    let resolved = app_config.resolve_embeddings();

    // Mirror `daemon_runtime::build_embedder` (#1598): API backends
    // wire the operator's model id verbatim (tier only gates Some vs
    // None); local/ollama backends go through the model picker.
    let tier_model = if crate::config::is_api_embed_backend(&resolved.backend) {
        tier_config.embedding_model
    } else {
        crate::daemon_runtime::resolve_embedder_model(&tier_config, app_config)
    };
    let Some(tier_model) = tier_model else {
        writeln!(
            out.stderr,
            "reembed: tier '{}' is keyword-only (no embedding model) — reembed \
             requires an embedding-capable tier (set `tier = \"semantic\"` or \
             above in config.toml, or configure [embeddings] / \
             AI_MEMORY_EMBED_* for an API backend)",
            feature_tier.as_str()
        )?;
        return Ok(EXIT_NO_EMBEDDER);
    };

    // Same spawn_blocking discipline as `build_embedder`: HF-Hub +
    // candle construction spin their own runtime internally.
    let resolved_for_build = resolved.clone();
    let built = tokio::task::spawn_blocking(move || {
        crate::embeddings::Embedder::from_resolved(&resolved_for_build, Some(tier_model))
    })
    .await?;
    let embedder = match built {
        Ok(Some(emb)) => emb,
        // Unreachable with `Some(tier_model)` threaded above; kept
        // explicit so the keyword-tier contract of `from_resolved`
        // stays loud (#1598).
        Ok(None) => {
            writeln!(
                out.stderr,
                "reembed: resolver returned no embedder for tier '{}'",
                feature_tier.as_str()
            )?;
            return Ok(EXIT_NO_EMBEDDER);
        }
        Err(e) => {
            writeln!(
                out.stderr,
                "reembed: embedder init failed (backend={}, model={}, url={}, \
                 source={}): {e:#}",
                resolved.backend,
                resolved.model,
                resolved.url,
                resolved.source.as_str(),
            )?;
            return Ok(EXIT_EMBEDDER_INIT_FAILED);
        }
    };

    let mut conn = db::open(db_path)?;
    let ns = args.namespace.as_deref();
    let target_model = embedder.model_description();
    let target_dim = embedder.dim();
    let plan = build_plan(&conn, ns, &target_model, target_dim, &resolved.backend)?;

    // Loud pre-flight: this run changes the corpus's vector space.
    let stored_dims = db::distinct_embedding_dims(&conn, ns)?;
    writeln!(
        out.stderr,
        "reembed: PRE-FLIGHT — stored embedding dims: {stored_dims:?}; target: \
         {target_dim}-dim ({target_model}); every scanned row's vector will be \
         REPLACED (vector-space migration, #1598)"
    )?;
    if stored_dims.iter().any(|&d| d != target_dim) {
        writeln!(
            out.stderr,
            "reembed: NOTE — stored dims {stored_dims:?} differ from target \
             {target_dim}; recall dim-guards skip mismatched vectors until the \
             sweep completes"
        )?;
    }

    if args.dry_run {
        if args.json {
            writeln!(
                out.stdout,
                "{}",
                serde_json::to_string(&json!({
                    "total_rows": plan.total_rows,
                    "rows_with_embeddings": plan.rows_with_embeddings,
                    "rows_missing_embeddings": plan.rows_missing_embeddings,
                    "target_model": plan.target_model,
                    "target_dim": plan.target_dim,
                    "backend": plan.backend,
                }))?
            )?;
        } else {
            writeln!(
                out.stdout,
                "reembed plan: total_rows={} rows_with_embeddings={} \
                 rows_missing_embeddings={} target_model='{}' target_dim={} \
                 backend={} (dry-run: nothing written)",
                plan.total_rows,
                plan.rows_with_embeddings,
                plan.rows_missing_embeddings,
                plan.target_model,
                plan.target_dim,
                plan.backend,
            )?;
        }
        return Ok(0);
    }

    let batch_size = resolve_batch_size(args.batch, resolved.backfill_batch as usize);
    let started = std::time::Instant::now();
    let outcome = run_reembed_live(&mut conn, &embedder, ns, batch_size, out)?;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    if args.json {
        writeln!(
            out.stdout,
            "{}",
            serde_json::to_string(&json!({
                "total": outcome.total,
                "reembedded": outcome.reembedded,
                "skipped": outcome.skipped,
                "model": target_model,
                "dim": target_dim,
                "duration_ms": duration_ms,
            }))?
        )?;
    } else {
        writeln!(
            out.stdout,
            "reembed: {}/{} re-embedded, {} skipped (model {target_model}, \
             {target_dim}-dim, {duration_ms} ms)",
            outcome.reembedded, outcome.total, outcome.skipped,
        )?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Memory, Tier};

    fn seed(conn: &rusqlite::Connection, ns: &str, title: &str, content: &str) -> String {
        let now = chrono::Utc::now().to_rfc3339();
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
        };
        db::insert(conn, &mem).unwrap()
    }

    fn test_conn() -> rusqlite::Connection {
        db::open(std::path::Path::new(":memory:")).unwrap()
    }

    /// Fixed-dim test embedder; errors on texts carrying the marker.
    struct FixedDimEmbedder {
        dim: usize,
        poison_marker: Option<&'static str>,
    }
    impl Embed for FixedDimEmbedder {
        fn embed(&self, text: &str) -> anyhow::Result<Vec<f32>> {
            if let Some(marker) = self.poison_marker
                && text.contains(marker)
            {
                anyhow::bail!("test: synthetic per-row embed failure");
            }
            Ok(vec![0.5_f32; self.dim])
        }
    }

    /// #1598 — the dry-run plan counts the (namespace-filtered) corpus
    /// truthfully and carries the resolved target facts verbatim.
    #[test]
    fn build_plan_counts_and_namespace_filter_1598() {
        let conn = test_conn();
        let id_a = seed(&conn, "plan-a", "a-1", "content");
        seed(&conn, "plan-a", "a-2", "content");
        seed(&conn, "plan-b", "b-1", "content");
        db::set_embedding(&conn, &id_a, &[0.1, 0.2]).unwrap();

        let all = build_plan(&conn, None, "model-x (8-dim, remote)", 8, "openrouter").unwrap();
        assert_eq!(
            all,
            ReembedPlan {
                total_rows: 3,
                rows_with_embeddings: 1,
                rows_missing_embeddings: 2,
                target_model: "model-x (8-dim, remote)".to_string(),
                target_dim: 8,
                backend: "openrouter".to_string(),
            }
        );

        let only_a = build_plan(&conn, Some("plan-a"), "m", 8, "b").unwrap();
        assert_eq!(only_a.total_rows, 2);
        assert_eq!(only_a.rows_with_embeddings, 1);
        assert_eq!(only_a.rows_missing_embeddings, 1);

        let none = build_plan(&conn, Some("plan-nope"), "m", 8, "b").unwrap();
        assert_eq!(none.total_rows, 0);
        assert_eq!(none.rows_missing_embeddings, 0);
    }

    /// #1598 — a live run REPLACES existing vectors (dim migration)
    /// and embeds previously-unembedded rows; this is a re-embed, not
    /// a backfill.
    #[test]
    fn live_run_replaces_existing_vectors_1598() {
        let mut conn = test_conn();
        let id_old = seed(&conn, "live-ns", "old", "already embedded");
        let id_new = seed(&conn, "live-ns", "new", "never embedded");
        db::set_embedding(&conn, &id_old, &[0.1, 0.2, 0.3, 0.4]).unwrap();

        let emb = FixedDimEmbedder {
            dim: 8,
            poison_marker: None,
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let outcome = run_reembed_live(&mut conn, &emb, Some("live-ns"), 1, &mut out).unwrap();

        assert_eq!(
            outcome,
            ReembedOutcome {
                total: 2,
                reembedded: 2,
                skipped: 0,
            }
        );
        assert_eq!(
            db::get_embedding(&conn, &id_old).unwrap().unwrap().len(),
            8,
            "existing vector replaced at the new dim"
        );
        assert_eq!(db::get_embedding(&conn, &id_new).unwrap().unwrap().len(), 8);
    }

    /// #1598 — the namespace filter leaves other namespaces' vectors
    /// untouched.
    #[test]
    fn live_run_namespace_filter_leaves_others_untouched_1598() {
        let mut conn = test_conn();
        let id_in = seed(&conn, "ns-in", "in", "inside the filter");
        let id_out = seed(&conn, "ns-out", "out", "outside the filter");
        db::set_embedding(&conn, &id_out, &[0.9, 0.8]).unwrap();

        let emb = FixedDimEmbedder {
            dim: 4,
            poison_marker: None,
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let outcome = run_reembed_live(&mut conn, &emb, Some("ns-in"), 16, &mut out).unwrap();

        assert_eq!(outcome.total, 1);
        assert_eq!(outcome.reembedded, 1);
        assert_eq!(db::get_embedding(&conn, &id_in).unwrap().unwrap().len(), 4);
        let untouched = db::get_embedding(&conn, &id_out).unwrap().unwrap();
        assert_eq!(untouched.len(), 2, "out-of-namespace vector untouched");
    }

    /// #1595/#1598 — per-row fallback: a poison row is skipped with a
    /// WARN naming its id, KEEPS its previous vector, and the sweep
    /// continues to re-embed every other row.
    #[test]
    fn live_run_per_row_fallback_skips_poison_row_1598() {
        const MARKER: &str = "reembed-poison-marker";
        let mut conn = test_conn();
        let id_ok_a = seed(&conn, "fb-ns", "ok-a", "healthy");
        let id_bad = seed(&conn, "fb-ns", "bad", MARKER);
        let id_ok_b = seed(&conn, "fb-ns", "ok-b", "healthy");
        db::set_embedding(&conn, &id_bad, &[0.7, 0.7]).unwrap();

        let emb = FixedDimEmbedder {
            dim: 4,
            poison_marker: Some(MARKER),
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let outcome = run_reembed_live(&mut conn, &emb, Some("fb-ns"), 16, &mut out).unwrap();

        assert_eq!(
            outcome,
            ReembedOutcome {
                total: 3,
                reembedded: 2,
                skipped: 1,
            }
        );
        assert_eq!(
            db::get_embedding(&conn, &id_ok_a).unwrap().unwrap().len(),
            4
        );
        assert_eq!(
            db::get_embedding(&conn, &id_ok_b).unwrap().unwrap().len(),
            4
        );
        assert_eq!(
            db::get_embedding(&conn, &id_bad).unwrap().unwrap().len(),
            2,
            "poison row keeps its previous vector"
        );
        let warn = String::from_utf8(stderr).unwrap();
        assert!(
            warn.contains(&id_bad) && warn.contains("skipped row"),
            "WARN must name the skipped row id, got: {warn}"
        );
    }

    /// #1598 — `--batch` precedence: positive flag > resolved value >
    /// compiled default (degenerate zeros fall through).
    #[test]
    fn resolve_batch_size_precedence_1598() {
        assert_eq!(resolve_batch_size(Some(7), 100), 7);
        assert_eq!(
            resolve_batch_size(Some(0), 100),
            100,
            "0 flag falls through"
        );
        assert_eq!(resolve_batch_size(None, 100), 100);
        assert_eq!(
            resolve_batch_size(None, 0),
            crate::mcp::DEFAULT_EMBED_BACKFILL_BATCH_SIZE,
            "double-degenerate input coerces to the compiled default"
        );
    }

    /// #1598 — an empty corpus is a clean no-op.
    #[test]
    fn live_run_empty_corpus_is_noop_1598() {
        let mut conn = test_conn();
        let emb = FixedDimEmbedder {
            dim: 4,
            poison_marker: None,
        };
        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut stdout, &mut stderr);
        let outcome = run_reembed_live(&mut conn, &emb, None, 16, &mut out).unwrap();
        assert_eq!(outcome, ReembedOutcome::default());
    }
}
