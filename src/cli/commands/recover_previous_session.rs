// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 (issue #1389) — `ai-memory recover-previous-session` CLI
//! subcommand. Fail-safe recovery of agent context from a host's
//! per-turn transcript file when the previous session terminated
//! ungracefully (SIGKILL, tmux lockup, host crash) between turns.
//!
//! # Wire shape
//!
//! ```bash
//! ai-memory recover-previous-session              # auto-resolve, quiet
//! ai-memory recover-previous-session --json       # JSON report
//! ai-memory recover-previous-session \
//!     --host claude-code \
//!     --since 2026-05-28T12:00:00Z \
//!     --limit 50 \
//!     --dry-run
//! ```
//!
//! # SessionStart-hook integration
//!
//! Chain after the existing `ai-memory boot` invocation:
//!
//! ```jsonc
//! {
//!   "hooks": {
//!     "SessionStart": [{
//!       "matcher": "*",
//!       "hooks": [{
//!         "type": "command",
//!         "command": "ai-memory boot --quiet --limit 10 --budget-tokens 4096 && ai-memory recover-previous-session --quiet"
//!       }]
//!     }]
//!   }
//! }
//! ```
//!
//! The common-case fast path (no gap to recover) costs <100 ms p95
//! so the chained hook command doesn't measurably slow boot.

use std::path::Path;

use anyhow::Result;
use clap::Args;

use crate::cli::CliOutput;
use crate::recover::{HostKind, RecoverOpts, recover_from_transcript};

/// CLI args for `ai-memory recover-previous-session`. Mirrored by
/// the MCP-tool surface's `RecoverPreviousSessionRequest` so both
/// surfaces accept the same per-call inputs.
#[derive(Args, Debug, Clone)]
pub struct RecoverPreviousSessionArgs {
    /// Which host's transcript layout to walk. `auto` (the default)
    /// walks every supported host's candidate set and picks the
    /// most-recently-modified transcript across all of them.
    #[arg(long, value_name = "HOST", default_value = "auto")]
    pub host: String,

    /// Explicit transcript path override. When set, the resolver is
    /// bypassed and this file is parsed directly. Useful for
    /// recovering from a transcript that lives outside the standard
    /// per-host location (e.g., a backup).
    #[arg(long, value_name = "PATH")]
    pub transcript: Option<std::path::PathBuf>,

    /// Filter to transcript lines whose timestamp is at or after
    /// this RFC3339 instant. When omitted, recovery starts from
    /// the most-recent `memory_store` watermark for this agent_id.
    #[arg(long, value_name = "RFC3339")]
    pub since: Option<String>,

    /// Namespace to land recovered memories in. Defaults to the
    /// agent's resolved default namespace per `AppConfig`.
    #[arg(long, value_name = "NS")]
    pub namespace: Option<String>,

    /// Maximum number of transcript lines to atomise this run.
    /// Excess lines are counted under `lines_skipped_limit` in the
    /// report. Default 100 — covers the common "lost the last hour"
    /// failure mode without unbounded SessionStart-hook latency.
    #[arg(long, default_value_t = 100, value_name = "N")]
    pub limit: usize,

    /// Parse the transcript and emit the report but write nothing
    /// to the DB. Used for operator inspection.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,

    /// Emit a compact report: cap `memories_created` at the first
    /// 10 entries and suppress per-memory stdout. Recommended for
    /// SessionStart-hook chaining so the hook output stays bounded.
    #[arg(long, default_value_t = false)]
    pub quiet: bool,

    /// Emit the report as JSON on stdout instead of the human-
    /// readable text shape. The JSON wire shape is the
    /// `crate::recover::RecoverReport` struct (field names + order
    /// stable).
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Dispatch entry-point called from `daemon_runtime::run`. The
/// substantive work lives in [`crate::recover::recover_from_transcript`];
/// this function owns only the Args→Opts mapping + the output
/// serialization for the CLI surface.
///
/// # Errors
///
/// Propagates DB-open failures from `recover_from_transcript`.
/// Per-line / per-turn errors are NOT propagated — they surface
/// under `RecoverReport.errors` so the SessionStart-hook chain
/// can't be wedged by a single bad transcript line.
pub fn run(
    _db_path: &Path,
    args: &RecoverPreviousSessionArgs,
    out: &mut CliOutput<'_>,
) -> Result<i32> {
    let host = parse_host_kind(&args.host).unwrap_or(HostKind::Auto);
    // agent_id resolution lives in the dispatch caller for now —
    // the slice C1 work threads the resolved agent_id through here.
    // Until that lands, we use a placeholder that the stub respects.
    let agent_id = std::env::var("AI_MEMORY_AGENT_ID")
        .unwrap_or_else(|_| "ai:recover-cli:placeholder".to_string());

    let opts = RecoverOpts {
        host,
        transcript_override: args.transcript.clone(),
        since_iso: args.since.clone(),
        namespace: args.namespace.clone(),
        limit: args.limit,
        dry_run: args.dry_run,
        quiet: args.quiet,
        agent_id,
    };

    let report = match recover_from_transcript(&opts) {
        Ok(r) => r,
        Err(e) => {
            // Graceful failure — write the error to stderr and exit 0
            // when --quiet (SessionStart-hook integration must not
            // wedge the agent boot); exit 2 otherwise so operator
            // runs see the failure code.
            let _ = writeln!(out.stderr, "ai-memory recover-previous-session: {e}");
            return Ok(if args.quiet { 0 } else { 2 });
        }
    };

    if args.json {
        let json = serde_json::to_string_pretty(&report)?;
        writeln!(out.stdout, "{json}")?;
    } else {
        emit_human(&report, args.quiet, out)?;
    }

    Ok(0)
}

fn parse_host_kind(s: &str) -> Option<HostKind> {
    match s {
        "auto" => Some(HostKind::Auto),
        "claude-code" => Some(HostKind::ClaudeCode),
        "codex" => Some(HostKind::Codex),
        "gemini" => Some(HostKind::Gemini),
        _ => None,
    }
}

fn emit_human(
    report: &crate::recover::RecoverReport,
    quiet: bool,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    if quiet {
        // Compact one-liner suitable for chaining into a
        // SessionStart hook. Always emits exit 0 so the hook
        // doesn't fail the boot.
        writeln!(
            out.stdout,
            "recover-previous-session: host={} transcript={} atomised={} skipped_dedup={} skipped_limit={} fast_path={} elapsed_ms={}",
            report.host_kind.as_str(),
            report
                .transcript_path
                .as_deref()
                .map_or("none".to_string(), |p| p.display().to_string()),
            report.lines_atomised,
            report.lines_skipped_dedup,
            report.lines_skipped_limit,
            report.fast_path_hit,
            report.elapsed_ms,
        )?;
        return Ok(());
    }

    writeln!(
        out.stdout,
        "recover-previous-session report (host={}, elapsed={} ms):",
        report.host_kind.as_str(),
        report.elapsed_ms
    )?;
    if let Some(p) = &report.transcript_path {
        writeln!(out.stdout, "  transcript    : {}", p.display())?;
    } else {
        writeln!(out.stdout, "  transcript    : (none located)")?;
    }
    writeln!(out.stdout, "  fast_path_hit : {}", report.fast_path_hit)?;
    writeln!(
        out.stdout,
        "  lines         : total={} atomised={} skipped_dedup={} skipped_limit={}",
        report.lines_total,
        report.lines_atomised,
        report.lines_skipped_dedup,
        report.lines_skipped_limit
    )?;
    writeln!(
        out.stdout,
        "  elapsed (ms)  : resolve_path={} dedup_query={} parse={} writes={}",
        report.elapsed_ms_resolve_path,
        report.elapsed_ms_dedup_query,
        report.elapsed_ms_parse,
        report.elapsed_ms_writes
    )?;
    if !report.memories_created.is_empty() {
        writeln!(
            out.stdout,
            "  memories_created ({}):",
            report.memories_created.len()
        )?;
        for id in &report.memories_created {
            writeln!(out.stdout, "    - {id}")?;
        }
    }
    if !report.errors.is_empty() {
        writeln!(out.stdout, "  errors ({}):", report.errors.len())?;
        for e in &report.errors {
            writeln!(out.stdout, "    - {e}")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_kind_known_values() {
        assert_eq!(parse_host_kind("auto"), Some(HostKind::Auto));
        assert_eq!(parse_host_kind("claude-code"), Some(HostKind::ClaudeCode));
        assert_eq!(parse_host_kind("codex"), Some(HostKind::Codex));
        assert_eq!(parse_host_kind("gemini"), Some(HostKind::Gemini));
    }

    #[test]
    fn parse_host_kind_unknown_returns_none() {
        assert_eq!(parse_host_kind("cursor"), None);
        assert_eq!(parse_host_kind(""), None);
    }
}
