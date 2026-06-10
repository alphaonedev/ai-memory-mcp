// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Per-host transcript parsers. Each module implements
//! [`TranscriptParser`] for one host's transcript format; the
//! [`crate::recover::recover_from_transcript`] handler dispatches
//! to the right parser by `HostKind`.
//!
//! The parser surface is intentionally minimal: a parser takes a
//! path + a `since` filter and yields an iterator of [`ParsedTurn`]
//! values. The downstream recovery logic owns sha256-keyed dedup,
//! memory-writes, and progress reporting; the parser owns only the
//! transcript-format-specific concerns (JSONL framing, field
//! mapping, timestamp parsing, role classification).

pub mod claude_code_jsonl;

use std::path::Path;

use serde::{Deserialize, Serialize};

/// One transcript turn parsed out of a host's transcript file.
///
/// The `role` field classifies the turn for downstream memory-kind
/// assignment: a `user`-role turn becomes an `observation` memory
/// tagged `operator-directive`; an `assistant`-role turn becomes
/// an `observation` memory tagged `agent-response`. The v0.8
/// decision-detector (#1393) will run an LLM classifier over these
/// raw observations to refine them into `plan`/`decision`/`commitment`
/// memories; the v0.7.0 recovery surface stops at the raw layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedTurn {
    /// RFC3339 timestamp of the turn (when the host wrote it).
    /// Used both for the `since` filter and for the recovered
    /// memory's `created_at` (so the recovered memory's timeline
    /// matches the original conversation rather than the recovery-
    /// run wall-clock).
    pub timestamp_iso: String,
    /// Role classification — `user`, `assistant`, `tool_use`,
    /// `tool_result`, or `other`. Drives the tag set the recovered
    /// memory inherits.
    pub role: TurnRole,
    /// Verbatim content of the turn. For multi-content `assistant`
    /// turns (text + tool_use + text), the parser concatenates the
    /// text parts; tool-use bodies surface under [`Self::tool_calls`].
    pub content_text: String,
    /// Tool-call summaries from this turn. Each entry is one
    /// `{tool, brief}` pair; the full args are not preserved at
    /// this layer (the recovered memory's content is the user-
    /// visible decision text, not the agent's tool-call trace).
    pub tool_calls: Vec<ToolCallSummary>,
    /// Stable sha256 of the source line content. Retained for audit
    /// (memory title + metadata) and as the legacy back-compat dedup
    /// probe; post-#1573 the dedup KEY is
    /// `(host_session_id, host_turn_index)` when the host format
    /// provides both, else [`Self::normalized_sha256_hex`].
    pub line_sha256_hex: String,
    /// Host-assigned session identifier for the turn (e.g. the
    /// Claude Code JSONL `sessionId` field). `None` when the host
    /// format does not carry one. Half of the #1573 canonical dedup
    /// key, mirroring the L4 `memory_capture_turn` envelope.
    pub host_session_id: Option<String>,
    /// Host-assigned monotonic per-session turn counter. `None` when
    /// the host format does not carry one (the Claude Code JSONL
    /// format has no numeric turn counter — a line ordinal is NOT a
    /// substitute because it need not agree with the counter the L4
    /// `memory_capture_turn` envelope supplies, and a coincidental
    /// match would falsely dedup a distinct turn).
    pub host_turn_index: Option<i64>,
}

impl ParsedTurn {
    /// #1573 — sha256 over the turn's NORMALIZED semantic content
    /// (session id, timestamp, role, text, tool-call summaries) with
    /// `0x00` field separators and `0x1f`/`0x1e` intra-list
    /// separators. Unlike the raw-line hash, this is invariant under
    /// host re-serialization (whitespace, JSON key order), so the
    /// same turn rewritten by a host upgrade still dedups; distinct
    /// turns that merely share text still differ via the
    /// session-id + timestamp components.
    #[must_use]
    pub fn normalized_sha256_hex(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.host_session_id.as_deref().unwrap_or("").as_bytes());
        h.update([0x00]);
        h.update(self.timestamp_iso.as_bytes());
        h.update([0x00]);
        h.update(self.role.as_str().as_bytes());
        h.update([0x00]);
        h.update(self.content_text.as_bytes());
        h.update([0x00]);
        for tc in &self.tool_calls {
            h.update(tc.tool.as_bytes());
            h.update([0x1f]);
            h.update(tc.brief.as_bytes());
            h.update([0x1e]);
        }
        format!("{:x}", h.finalize())
    }
}

/// Role classification for one parsed transcript turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnRole {
    /// Operator-typed prompt or directive.
    User,
    /// LLM-generated response.
    Assistant,
    /// LLM-initiated tool invocation.
    ToolUse,
    /// Tool-call result returned to the LLM.
    ToolResult,
    /// Any other line shape (system messages, attachments,
    /// permission-mode toggles, etc.) — preserved as low-priority
    /// observations rather than dropped.
    Other,
}

impl TurnRole {
    /// Stable wire string for the role. Single source for the
    /// recovered-memory tags/metadata AND the #1573 normalized
    /// dedup hash, so the two can never drift.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::ToolUse => "tool_use",
            Self::ToolResult => "tool_result",
            Self::Other => "other",
        }
    }
}

/// One tool-call mention extracted from an assistant turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallSummary {
    /// Tool name (e.g., `Bash`, `Read`, `mcp__memory__memory_store`).
    pub tool: String,
    /// One-line target / brief — for `Bash`, the command's
    /// `description` arg; for `Read`, the file path; for an MCP
    /// tool, the first 1-2 fields of the request struct.
    pub brief: String,
}

/// Trait every per-host parser implements. The blanket
/// [`crate::recover::recover_from_transcript`] entry-point dispatches
/// to the right impl by `HostKind`.
pub trait TranscriptParser {
    /// Stream-parse a transcript file from disk, filtering to
    /// turns whose timestamp is at or after `since_iso` when set.
    /// Returns parsed turns in transcript order.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be opened. Per-line
    /// parse errors are NOT propagated — the parser swallows them
    /// and surfaces a partial result; SessionStart-hook integration
    /// can't tolerate a single bad line wedging recovery.
    fn parse(&self, path: &Path, since_iso: Option<&str>) -> Result<Vec<ParsedTurn>, ParseError>;
}

/// Errors surfaced by a parser. Most parse failures are non-fatal
/// (see the parser-trait docstring); this enum carries only
/// errors that prevent the parse from starting at all.
#[derive(Debug)]
pub enum ParseError {
    /// File could not be opened or read.
    Read(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(msg) => write!(f, "parser: read failed: {msg}"),
        }
    }
}

impl std::error::Error for ParseError {}
