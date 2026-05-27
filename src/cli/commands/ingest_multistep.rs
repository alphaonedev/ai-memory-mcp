// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 ARCH-3 / FX-C3 (batch2) — `ai-memory ingest-multistep`
//! CLI subcommand.
//!
//! Closes the three-surface-parity gap on `memory_ingest_multistep`
//! (Form 3, issue #756). The MCP tool
//! ([`crate::mcp::handle_ingest_multistep`]) and the HTTP route landed
//! previously; this module wires the CLI surface so operators can
//! drive the multi-step ingest orchestrator from a terminal.
//!
//! ## Tier gate
//!
//! Form 3 LLM stages require the smart / autonomous tier. On the
//! keyword / semantic tiers the CLI receives the tier-locked advisory
//! envelope verbatim (mirrors the MCP / HTTP behaviour). Operators
//! who want the LLM pipeline must drive the daemon via MCP / HTTP
//! where the LLM client is wired into the dispatcher.

use anyhow::Result;
use clap::Args;
use serde_json::{Value, json};

use crate::cli::CliOutput;
use crate::config::AppConfig;

/// CLI args for `ai-memory ingest-multistep`.
#[derive(Args, Debug, Clone)]
pub struct IngestMultistepArgs {
    /// Content to ingest.
    #[arg(long, value_name = "TEXT")]
    pub content: String,

    /// Routing hint for the FTS classifier (default `global`).
    #[arg(long, value_name = "NS")]
    pub namespace: Option<String>,

    /// Pipeline variant — `two_phase` (default) or `four_step`.
    #[arg(long = "pipeline-variant", value_name = "VARIANT")]
    pub pipeline_variant: Option<String>,

    /// Emit the raw JSON envelope.
    #[arg(long)]
    pub json: bool,
}

/// `ai-memory ingest-multistep` dispatch entry.
///
/// # Errors
///
/// - The substrate refuses the call (validation, pipeline failure).
/// - `serde_json::to_string` cannot serialise the envelope.
pub fn cmd_ingest_multistep(
    args: &IngestMultistepArgs,
    app_config: &AppConfig,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    let mut params = json!({"content": args.content});
    if let Some(ns) = &args.namespace {
        params["namespace"] = json!(ns);
    }
    if let Some(v) = &args.pipeline_variant {
        params["pipeline_variant"] = json!(v);
    }

    // CLI does not own the LLM dispatch — pass `handler = None` so the
    // tier-locked advisory envelope returns when the operator drives
    // this from a terminal. The MCP / HTTP daemon owns the dispatch.
    let feature_tier = app_config.effective_tier(None);
    let envelope = crate::mcp::handle_ingest_multistep(&params, None, feature_tier)
        .map_err(|e| anyhow::anyhow!("ingest-multistep: {e}"))?;

    if args.json {
        writeln!(out.stdout, "{}", serde_json::to_string(&envelope)?)?;
        return Ok(());
    }

    if let Some(locked) = envelope.get("tier-locked").and_then(Value::as_str) {
        writeln!(out.stdout, "ingest-multistep: tier-locked: {locked}")?;
    } else {
        let variant = envelope
            .get("variant")
            .and_then(Value::as_str)
            .unwrap_or("?");
        writeln!(out.stdout, "ingest-multistep: variant={variant}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_utils::TestEnv;

    #[test]
    fn ingest_multistep_cli_tier_locked_when_no_llm() {
        let mut env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let args = IngestMultistepArgs {
            content: "hello".into(),
            namespace: None,
            pipeline_variant: None,
            json: true,
        };
        {
            let mut out = env.output();
            cmd_ingest_multistep(&args, &cfg, &mut out).expect("ok");
        }
        let stdout = env.stdout_str();
        let envelope: Value = serde_json::from_str(stdout.trim()).expect("parse envelope");
        // No LLM in the CLI dispatcher → tier-locked advisory.
        assert!(envelope.get("tier-locked").is_some());
    }

    #[test]
    fn ingest_multistep_cli_empty_content_returns_err() {
        let mut env = TestEnv::fresh();
        let cfg = AppConfig::default();
        let args = IngestMultistepArgs {
            content: String::new(),
            namespace: None,
            pipeline_variant: None,
            json: true,
        };
        let mut out = env.output();
        let err = cmd_ingest_multistep(&args, &cfg, &mut out).expect_err("must fail");
        assert!(err.to_string().contains("ingest-multistep"), "got: {err}");
    }
}
