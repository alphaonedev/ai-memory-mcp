// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 #1443 — `ai-memory expand` CLI subcommand.
//!
//! Closes the three-surface-parity gap on query expansion. The MCP tool
//! ([`crate::mcp::handle_expand_query`]) and the HTTP route
//! (`POST /api/v1/expand_query`) landed previously; this module wires
//! the CLI surface so an automation harness (notably the binary-faithful
//! `benchmarks/longmemeval/harness.py`) can inject LLM query-expansion
//! in-process via a `recall`-style one-shot — without standing up an MCP
//! stdio server or an HTTP daemon per call.
//!
//! ## DRY contract
//!
//! No expansion logic lives here — this module is a clap arg-parser plus
//! an output formatter. The actual `llm.expand_query` call lives in
//! [`crate::mcp::handle_expand_query`]; the MCP, HTTP, and CLI surfaces
//! all share that one implementation, so the expanded-terms set is
//! byte-equal across the three.
//!
//! ## LLM resolution
//!
//! The LLM client is resolved through the same
//! [`crate::daemon_runtime::build_llm_client`] ladder the daemon uses
//! (CLI flag > `AI_MEMORY_LLM_*` env > `[llm]` section > legacy fields >
//! compiled tier preset). An entirely Ollama-free configuration —
//! `AI_MEMORY_LLM_BACKEND=openrouter` plus a key — drives expansion
//! against a cloud backend, which is exactly the no-Ollama path the
//! v0.7.0 LongMemEval reproduction exercised.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::config::AppConfig;

/// Exit code when no LLM backend is configured (503-equivalent — the
/// expansion primitive is unreachable, not failing).
pub const EXIT_NO_LLM: i32 = 2;

/// Exit code when an LLM backend is configured but the expansion call
/// itself failed (502-equivalent — upstream error).
pub const EXIT_LLM_FAILED: i32 = 3;

/// CLI args for `ai-memory expand`. Mirrors the MCP `memory_expand_query`
/// `input_schema` shape (a single free-text `query`).
#[derive(Args, Debug, Clone)]
pub struct ExpandArgs {
    /// Free-text query to expand into semantic reformulations.
    #[arg(value_name = "QUERY")]
    pub query: String,

    /// Emit the raw JSON envelope
    /// (`{query, expanded_terms, elapsed_ms, key_source}`) on stdout
    /// instead of a human-readable summary. Built for harness
    /// consumption.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory expand` dispatch entry. Resolves the LLM client through
/// the daemon ladder, routes the query through the shared substrate
/// primitive ([`crate::mcp::handle_expand_query`]), and emits the
/// expanded terms — guaranteeing the term set is byte-equal with the
/// MCP / HTTP surfaces.
///
/// Returns an exit code rather than propagating an error so the no-LLM
/// and upstream-failure cases get stable, harness-detectable codes:
/// - `0` — success, terms emitted.
/// - [`EXIT_NO_LLM`] (`2`) — no LLM configured (503-equivalent).
/// - [`EXIT_LLM_FAILED`] (`3`) — LLM configured but the call failed.
///
/// # Errors
///
/// Propagates only fatal I/O errors (writing to stdout/stderr) and
/// `serde_json::to_string` serialisation failures. Every expansion
/// outcome is mapped to an exit code and returned as `Ok(code)`.
pub async fn cmd_expand(
    args: &ExpandArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let feature_tier = app_config.effective_tier(None);
    let llm = crate::daemon_runtime::build_llm_client(feature_tier, app_config).await;
    let key_source = app_config
        .resolve_llm(None, None, None)
        .api_key_source
        .as_str()
        .to_string();
    run_with_llm(args, llm.as_ref(), &key_source, out)
}

/// Visible-for-test core. Production resolves the client via
/// [`cmd_expand`]; the test suite injects a wiremock-backed
/// [`crate::llm::OllamaClient`] (or `None` for the no-LLM path) so the
/// exit-code contract can be pinned without a live LLM. `key_source` is
/// the resolved API-key provenance label (e.g. `env`, `config`, `none`)
/// surfaced in the envelope for harness observability.
///
/// # Errors
///
/// Propagates only fatal stdout/stderr I/O errors and JSON
/// serialisation failures. See [`cmd_expand`] for the exit-code map.
pub fn run_with_llm(
    args: &ExpandArgs,
    llm: Option<&crate::llm::OllamaClient>,
    key_source: &str,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    if llm.is_none() {
        let msg = "query expansion requires a configured LLM backend \
                   (set AI_MEMORY_LLM_BACKEND + key, or use smart/autonomous tier)";
        if args.json {
            writeln!(
                out.stdout,
                "{}",
                serde_json::to_string(&json!({
                    "query": args.query,
                    "error": msg,
                    "key_source": key_source,
                }))?
            )?;
        } else {
            writeln!(out.stderr, "expand: {msg}")?;
        }
        return Ok(EXIT_NO_LLM);
    }

    let params = json!({ "query": args.query });
    let started = std::time::Instant::now();
    let result = crate::mcp::handle_expand_query(llm, &params);
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

    match result {
        Ok(envelope) => {
            let terms = envelope
                .get("expanded_terms")
                .cloned()
                .unwrap_or_else(|| json!([]));
            if args.json {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::to_string(&json!({
                        "query": args.query,
                        "expanded_terms": terms,
                        "elapsed_ms": elapsed_ms,
                        "key_source": key_source,
                    }))?
                )?;
            } else {
                let term_strs: Vec<&str> = terms
                    .as_array()
                    .map_or_else(Vec::new, |a| a.iter().filter_map(Value::as_str).collect());
                writeln!(
                    out.stdout,
                    "expand: {} term(s) (elapsed {elapsed_ms}ms, key_source={key_source})",
                    term_strs.len(),
                )?;
                for t in &term_strs {
                    writeln!(out.stdout, "  - {t}")?;
                }
            }
            Ok(0)
        }
        Err(e) => {
            if args.json {
                writeln!(
                    out.stdout,
                    "{}",
                    serde_json::to_string(&json!({
                        "query": args.query,
                        "error": e,
                        "elapsed_ms": elapsed_ms,
                        "key_source": key_source,
                    }))?
                )?;
            } else {
                writeln!(out.stderr, "expand: LLM call failed: {e}")?;
            }
            Ok(EXIT_LLM_FAILED)
        }
    }
}
