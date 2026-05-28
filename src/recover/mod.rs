// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory recover-previous-session` — fail-safe recovery of agent
//! context from host-written transcript files.
//!
//! Closes the substrate failure mode documented in issue
//! [#1388](https://github.com/alphaonedev/ai-memory-mcp/issues/1388):
//! when an AI agent session terminates ungracefully (SIGKILL, tmux
//! lockup, host crash) between conversation turns, any decisions /
//! plans / agreed scope from those turns are lost because the agent
//! is `memory_store`-volunteer mode. The transcript file Claude
//! Code / Codex CLI / Gemini CLI writes per-turn to disk SURVIVES
//! the kill, but ai-memory has no bridge to that durable artifact —
//! until this module.
//!
//! The recovery surface is **dual**: a CLI subcommand
//! (`ai-memory recover-previous-session`) for SessionStart-hook
//! integration, and an MCP tool (`memory_recover_previous_session`)
//! for in-session agent self-recovery. Both call into
//! [`recover_from_transcript`] which is the canonical handler.
//!
//! See issue [#1389](https://github.com/alphaonedev/ai-memory-mcp/issues/1389)
//! for the full design + acceptance criteria; see CLAUDE.md
//! §"Auto-capture" for operator-facing documentation.

pub mod parsers;
pub mod transcript_paths;

use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};

pub use transcript_paths::{HostKind, resolve_transcript};

/// Per-call recovery report. Doubles as the JSON wire shape for
/// `ai-memory recover-previous-session --json` and as the MCP-tool
/// return shape; field names + serialization order are the wire
/// contract.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RecoverReport {
    /// Absolute path of the transcript file the recovery walked,
    /// or `None` when no transcript was located (host stub had
    /// no transcripts on disk).
    pub transcript_path: Option<PathBuf>,
    /// Host whose transcript was recovered. Echoes the resolver
    /// arm that won (or `--host` flag value if explicit).
    pub host_kind: HostKind,
    /// Total wall-clock from `recover_from_transcript` entry to
    /// return, in milliseconds. Pinned by the regression test
    /// against the per-scenario budget (see #1389 perf design).
    pub elapsed_ms: u64,
    /// Wall-clock for path resolution + `stat(2)` only.
    pub elapsed_ms_resolve_path: u64,
    /// Wall-clock for the dedup-table SELECT.
    pub elapsed_ms_dedup_query: u64,
    /// Wall-clock for the JSONL stream parse.
    pub elapsed_ms_parse: u64,
    /// Wall-clock for the INSERTs into `memories` and
    /// `transcript_line_dedup`.
    pub elapsed_ms_writes: u64,
    /// Total lines read from the transcript (pre-filter).
    pub lines_total: u32,
    /// Lines atomised into new memories this run.
    pub lines_atomised: u32,
    /// Lines skipped because their sha256 was already in the
    /// dedup table from a prior recovery.
    pub lines_skipped_dedup: u32,
    /// Lines skipped because the `--limit` cap was reached.
    pub lines_skipped_limit: u32,
    /// IDs of memories created this run. Capped at the first 10 in
    /// `--quiet` mode to keep the JSON payload bounded.
    pub memories_created: Vec<String>,
    /// Best-effort errors surfaced during recovery. A non-empty
    /// list is NOT a hard failure — the recover verb is graceful
    /// by design so SessionStart-hook integration can't wedge an
    /// agent boot.
    pub errors: Vec<String>,
    /// `CURRENT_SCHEMA_VERSION` at the time recovery ran. Pinned
    /// in `RecoverReport` so a future schema migration that
    /// changes the dedup-table shape can be diagnosed from the
    /// JSON wire payload.
    pub schema_version_at_run: i64,
    /// `true` when the common-case fast-path short-circuited
    /// (transcript mtime ≤ most-recent `memory_store` write for
    /// this agent_id). When `true`, parse + writes never ran and
    /// the elapsed budget is the resolve-path + dedup-query sum.
    pub fast_path_hit: bool,
}

impl RecoverReport {
    /// New empty report scaffold; callers fill fields as work
    /// happens. The `Instant` tracker pattern is captured in the
    /// `RecoverTimer` helper below.
    #[must_use]
    pub fn new(host_kind: HostKind, schema_version: i64) -> Self {
        Self {
            transcript_path: None,
            host_kind,
            elapsed_ms: 0,
            elapsed_ms_resolve_path: 0,
            elapsed_ms_dedup_query: 0,
            elapsed_ms_parse: 0,
            elapsed_ms_writes: 0,
            lines_total: 0,
            lines_atomised: 0,
            lines_skipped_dedup: 0,
            lines_skipped_limit: 0,
            memories_created: Vec::new(),
            errors: Vec::new(),
            schema_version_at_run: schema_version,
            fast_path_hit: false,
        }
    }
}

/// Per-phase elapsed-ms accumulator. Lightweight wrapper around
/// `Instant::now()` deltas so the recovery body can record each
/// phase's wall-clock without scattering bookkeeping noise.
pub struct RecoverTimer {
    overall_start: Instant,
    phase_start: Instant,
}

impl Default for RecoverTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoverTimer {
    #[must_use]
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            overall_start: now,
            phase_start: now,
        }
    }

    /// Return elapsed ms since the most recent `phase_lap()` call
    /// (or, on first call, since construction). Resets the phase
    /// anchor for the next call.
    pub fn phase_lap(&mut self) -> u64 {
        let now = Instant::now();
        let ms =
            u64::try_from(now.duration_since(self.phase_start).as_millis()).unwrap_or(u64::MAX);
        self.phase_start = now;
        ms
    }

    /// Total wall-clock from construction.
    #[must_use]
    pub fn overall_ms(&self) -> u64 {
        u64::try_from(self.overall_start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Per-call recovery options. Both surfaces (CLI + MCP) build one
/// of these from their respective Args / Request shapes and pass
/// it into [`recover_from_transcript`].
#[derive(Debug, Clone)]
pub struct RecoverOpts {
    /// Which host's transcript format + path-resolver arm to use.
    pub host: HostKind,
    /// Explicit transcript path; when `None`, the resolver walks
    /// the per-host candidate set and picks the most-recent.
    pub transcript_override: Option<PathBuf>,
    /// Filter to lines whose timestamp is at or after this RFC3339
    /// instant. When `None`, recovery starts from the
    /// most-recent-`memory_store` watermark for this agent_id.
    pub since_iso: Option<String>,
    /// Namespace to land recovered memories in. When `None`,
    /// defaults to the agent's resolved default namespace per
    /// `AppConfig`.
    pub namespace: Option<String>,
    /// Maximum number of transcript lines to atomise this run.
    /// Excess lines are skipped + counted under
    /// `lines_skipped_limit`. Default = 100.
    pub limit: usize,
    /// When `true`, parse the transcript and emit the report but
    /// write nothing to the DB. Used by `--dry-run` for operator
    /// inspection.
    pub dry_run: bool,
    /// When `true`, drop every memory_id from
    /// `memories_created` except the first 10; bounds the JSON
    /// payload for SessionStart-hook log capture.
    pub quiet: bool,
    /// agent_id to attribute recovered memories to. Resolved from
    /// the calling surface (CLI flag / MCP CallerContext / config).
    pub agent_id: String,
}

impl RecoverOpts {
    /// Sensible defaults for SessionStart-hook integration.
    /// Callers override `agent_id` (required) and any other field
    /// that diverges from the hook-friendly defaults.
    #[must_use]
    pub fn for_session_start_hook(host: HostKind, agent_id: String) -> Self {
        Self {
            host,
            transcript_override: None,
            since_iso: None,
            namespace: None,
            limit: 100,
            dry_run: false,
            quiet: true,
            agent_id,
        }
    }
}

/// Canonical recovery handler. Both the CLI subcommand and the MCP
/// tool dispatch into this function with a `RecoverOpts` they
/// constructed from their respective wire shapes. The function
/// returns a populated [`RecoverReport`] which both surfaces then
/// serialize through their respective output paths.
///
/// **Performance contract** (see #1389 comment 4565477566):
///
/// - Common case (no gap): <100 ms p95 (fast-path short-circuit).
/// - Gap case, 100 turns: <1 s p95 (raw observation INSERTs, no LLM call).
/// - Gap case, 1000 turns: <5 s p95 with default `limit=100`
///   bounding the work; remainder logged under `lines_skipped_limit`.
///
/// **Failure semantics**: never panics on a parse error; surfaces
/// errors via `RecoverReport.errors` and continues. SessionStart-hook
/// integration depends on this — a transcript-parse exception MUST
/// NOT wedge the operator's session boot.
///
/// # Errors
///
/// Returns an error ONLY when the underlying DB connection cannot
/// be established (treating "no transcript found" as a benign empty
/// report, not an error). The callers' `--quiet` path catches even
/// the DB-open error and downgrades to a stderr WARN + exit 0.
///
/// # Panics
///
/// Does not panic.
pub fn recover_from_transcript(_opts: &RecoverOpts) -> Result<RecoverReport, RecoverError> {
    // TODO(#1389): full implementation lands in the next commits.
    // This stub returns an empty report so the module compiles + the
    // CLI/MCP surfaces can wire through to it. Subsequent commits
    // implement the body in vertical slices:
    //
    // - C1: path-resolver + stat(2) fast-path short-circuit.
    // - C2: JSONL streaming parser + sha256 dedup.
    // - C3: raw observation memory writes (no LLM call) + dedup-table insert.
    // - C4: schema v52 additive migration (transcript_line_dedup).
    // - C5: regression test + perf assertion.
    //
    // Each slice lands as its own commit on `feat/1389-recover-previous-session`,
    // followed by the pm-v3.2 three-audit QC pass before the merge gate.
    let mut report = RecoverReport::new(_opts.host, 0);
    report.errors.push(
        "recover_from_transcript: not yet implemented; this is the skeleton commit (see #1389 \
         for the implementation slices)"
            .to_string(),
    );
    Ok(report)
}

/// Errors that escape [`recover_from_transcript`]. Most failure
/// modes are surfaced under `RecoverReport.errors` rather than
/// returned — see the function's "Failure semantics" docstring.
/// This enum carries only failures that can't be made graceful
/// (e.g., the DB-open path failed before any report could be built).
#[derive(Debug)]
pub enum RecoverError {
    /// DB connection could not be established.
    DbOpen(String),
    /// Invalid `RecoverOpts` (e.g., conflicting `--since` + explicit
    /// timestamps in `--transcript`).
    InvalidOpts(String),
}

impl std::fmt::Display for RecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DbOpen(msg) => write!(f, "recover: db open failed: {msg}"),
            Self::InvalidOpts(msg) => write!(f, "recover: invalid opts: {msg}"),
        }
    }
}

impl std::error::Error for RecoverError {}
