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

pub mod nag;
pub mod parsers;
pub mod transcript_paths;

use std::path::{Path, PathBuf};
use std::time::Instant;

use rusqlite::OptionalExtension;
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
    /// IDs of memories created this run. Capped at the first
    /// [`QUIET_MEMORY_ID_PREVIEW_CAP`] in `--quiet` mode to keep the
    /// JSON payload bounded.
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

/// Default cap on transcript lines atomised per recovery run. Bounds
/// the gap-path work so a 1000-turn transcript can't blow the
/// SessionStart-hook latency budget; the remainder is counted under
/// `RecoverReport.lines_skipped_limit`. Used by
/// [`RecoverOpts::for_session_start_hook`]; the CLI / MCP surfaces
/// override via their `--limit` wire field.
pub const DEFAULT_RECOVER_LIMIT: usize = 100;

/// Cap on `RecoverReport.memories_created` IDs retained in `--quiet`
/// mode. Bounds the JSON payload so SessionStart-hook log capture
/// stays small regardless of how many memories a gap recovery wrote;
/// the full set is still persisted to the DB, only the echoed-ID list
/// is truncated.
pub const QUIET_MEMORY_ID_PREVIEW_CAP: usize = 10;

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
    /// `lines_skipped_limit`. Defaults to [`DEFAULT_RECOVER_LIMIT`].
    pub limit: usize,
    /// When `true`, parse the transcript and emit the report but
    /// write nothing to the DB. Used by `--dry-run` for operator
    /// inspection.
    pub dry_run: bool,
    /// When `true`, drop every memory_id from `memories_created`
    /// except the first [`QUIET_MEMORY_ID_PREVIEW_CAP`]; bounds the
    /// JSON payload for SessionStart-hook log capture.
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
            limit: DEFAULT_RECOVER_LIMIT,
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
/// - Gap case, 1000 turns: <5 s p95 with the default
///   [`DEFAULT_RECOVER_LIMIT`] bounding the work; remainder logged
///   under `lines_skipped_limit`.
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
pub fn recover_from_transcript(
    db_path: &Path,
    opts: &RecoverOpts,
) -> Result<RecoverReport, RecoverError> {
    use parsers::TranscriptParser;
    use parsers::claude_code_jsonl::ClaudeCodeJsonlParser;

    let mut timer = RecoverTimer::new();
    let schema_version = crate::storage::migrations::current_schema_version();
    let mut report = RecoverReport::new(opts.host, schema_version);

    // The DB-open path is the ONLY hard failure: every later error is
    // surfaced via `report.errors` so a SessionStart-hook chain can't
    // be wedged by a bad transcript line.
    let conn = crate::storage::open(db_path).map_err(|e| RecoverError::DbOpen(e.to_string()))?;

    // Step 1 — resolve the transcript. An explicit `--transcript`
    // override bypasses the resolver; otherwise walk the per-host
    // candidate set for the current working directory.
    let path = match opts.transcript_override.clone() {
        Some(p) => Some(p),
        None => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            match resolve_transcript(opts.host, &cwd) {
                Ok(p) => p,
                Err(e) => {
                    report.errors.push(format!("path resolve failed: {e}"));
                    None
                }
            }
        }
    };
    let Some(path) = path else {
        // No transcript located — a benign steady state (fresh box, or
        // no agent has written a transcript for this cwd).
        report.elapsed_ms_resolve_path = timer.phase_lap();
        report.elapsed_ms = timer.overall_ms();
        return Ok(report);
    };
    report.transcript_path = Some(path.clone());

    let mtime = std::fs::metadata(&path)
        .ok()
        .and_then(|m| m.modified().ok());
    report.elapsed_ms_resolve_path = timer.phase_lap();

    // Step 2 — fast-path short-circuit. The watermark is the most
    // recent `created_at` across ALL of this agent's memories (normal
    // L1 stores included). When the transcript has not been modified
    // since the agent last wrote a memory there is nothing to recover,
    // so we skip the parse + write phases entirely.
    let watermark: Option<String> = conn
        .query_row(
            "SELECT MAX(created_at) FROM memories \
             WHERE json_extract(metadata, '$.agent_id') = ?1",
            rusqlite::params![&opts.agent_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .unwrap_or(None);
    report.elapsed_ms_dedup_query = timer.phase_lap();

    if let (Some(mtime), Some(watermark_iso)) = (mtime, watermark.as_deref()) {
        if let Ok(watermark_dt) = chrono::DateTime::parse_from_rfc3339(watermark_iso) {
            let mtime_dt: chrono::DateTime<chrono::Utc> = mtime.into();
            if mtime_dt <= watermark_dt.with_timezone(&chrono::Utc) {
                report.fast_path_hit = true;
                report.elapsed_ms = timer.overall_ms();
                return Ok(report);
            }
        }
    }

    // Step 3 — gap-path. The `transcript_line_dedup` table is the sole
    // idempotency mechanism (each already-recovered line is skipped by
    // its sha256 in step 4), so the parse is NOT pre-filtered by the
    // memory watermark. Deriving `since` from the watermark would be
    // unsound: recovered memories are stamped with their conversational
    // turn timestamp (not wall-clock), and any normal L1 `memory_store`
    // advances `MAX(created_at)` to wall-clock-now — either could push
    // the watermark past an un-recovered gap turn and silently drop it.
    // Only an explicit operator `--since` narrows the parse window.
    let since = opts.since_iso.clone();
    let turns = match ClaudeCodeJsonlParser.parse(&path, since.as_deref()) {
        Ok(t) => t,
        Err(e) => {
            report.errors.push(format!("parse failed: {e}"));
            report.elapsed_ms = timer.overall_ms();
            return Ok(report);
        }
    };
    report.lines_total = u32::try_from(turns.len()).unwrap_or(u32::MAX);
    report.elapsed_ms_parse = timer.phase_lap();

    // Step 4 — per-turn dedup + write. Each new turn becomes one
    // observation memory + one `transcript_line_dedup` row, written
    // atomically under BEGIN IMMEDIATE (mirroring the L4 storage tx in
    // `src/mcp/tools/capture_turn.rs::handle_capture_turn`).
    let namespace = opts
        .namespace
        .clone()
        .unwrap_or_else(|| "global".to_string());
    let host_kind = opts.host.as_str().to_string();

    for turn in turns {
        if usize::try_from(report.lines_atomised).unwrap_or(usize::MAX) >= opts.limit {
            report.lines_skipped_limit += 1;
            continue;
        }

        let Ok(sha_bytes) = hex::decode(&turn.line_sha256_hex) else {
            report.errors.push(format!(
                "skipping turn with malformed sha256: {}",
                turn.line_sha256_hex
            ));
            continue;
        };

        let already: Option<String> = conn
            .query_row(
                "SELECT memory_id FROM transcript_line_dedup WHERE sha256 = ?1",
                rusqlite::params![&sha_bytes],
                |row| row.get(0),
            )
            .optional()
            .unwrap_or(None);
        if already.is_some() {
            report.lines_skipped_dedup += 1;
            continue;
        }

        if opts.dry_run {
            // Inspection mode: count the would-be write, persist nothing.
            report.lines_atomised += 1;
            continue;
        }

        match write_recovered_turn(
            &conn, &turn, &sha_bytes, &namespace, &host_kind, &path, opts,
        ) {
            Ok(memory_id) => {
                report.lines_atomised += 1;
                report.memories_created.push(memory_id);
            }
            Err(e) => report.errors.push(e),
        }
    }

    // Bound the JSON payload for SessionStart-hook log capture.
    if opts.quiet && report.memories_created.len() > QUIET_MEMORY_ID_PREVIEW_CAP {
        report
            .memories_created
            .truncate(QUIET_MEMORY_ID_PREVIEW_CAP);
    }

    report.elapsed_ms_writes = timer.phase_lap();
    report.elapsed_ms = timer.overall_ms();
    Ok(report)
}

/// Stable wire string for a parsed turn's role.
fn role_label(role: parsers::TurnRole) -> &'static str {
    match role {
        parsers::TurnRole::User => "user",
        parsers::TurnRole::Assistant => "assistant",
        parsers::TurnRole::ToolUse => "tool_use",
        parsers::TurnRole::ToolResult => "tool_result",
        parsers::TurnRole::Other => "other",
    }
}

/// Write one recovered transcript turn as an `observation` memory plus
/// its `transcript_line_dedup` row under a single BEGIN IMMEDIATE
/// transaction. Mirrors the L4 storage transaction in
/// `src/mcp/tools/capture_turn.rs::handle_capture_turn`: on any failure
/// the transaction rolls back so an orphaned memory can never exist
/// without its dedup row.
fn write_recovered_turn(
    conn: &rusqlite::Connection,
    turn: &parsers::ParsedTurn,
    sha_bytes: &[u8],
    namespace: &str,
    host_kind: &str,
    transcript_path: &Path,
    opts: &RecoverOpts,
) -> Result<String, String> {
    use crate::models::{Memory, MemoryKind, Tier};

    let role = role_label(turn.role);
    let now_iso = chrono::Utc::now().to_rfc3339();

    // Prefer the turn's text; fall back to a tool-call summary so a
    // tool_use-only turn still produces a non-empty observation.
    let content = if turn.content_text.trim().is_empty() {
        let briefs: Vec<String> = turn
            .tool_calls
            .iter()
            .map(|tc| format!("{}: {}", tc.tool, tc.brief))
            .collect();
        format!("[tool calls] {}", briefs.join("; "))
    } else {
        turn.content_text.clone()
    };

    // The line sha256 makes the title unique per transcript line.
    // `storage::insert` upserts on `(title, namespace)` and the dedup
    // table guarantees one memory per line, so the only "same-title"
    // case is a true re-recovery of the same line.
    let title = format!(
        "L2 recovered {role} turn {} @ {}",
        turn.line_sha256_hex, turn.timestamp_iso
    );

    let mut tags = vec![
        "captured-via-l2".to_string(),
        "recovered-from-transcript".to_string(),
        format!("host:{host_kind}"),
        format!("role:{role}"),
    ];
    tags.push(match turn.role {
        parsers::TurnRole::User => "operator-directive".to_string(),
        parsers::TurnRole::Assistant => "agent-response".to_string(),
        _ => "transcript-line".to_string(),
    });

    // User-role turns (operator directives) are the highest-value
    // recovery target per the #1388 failure mode; bias their priority.
    let priority = if turn.role == parsers::TurnRole::User {
        6
    } else {
        5
    };

    let metadata = serde_json::json!({
        "agent_id": opts.agent_id,
        "host_kind": host_kind,
        "transcript_path": transcript_path.display().to_string(),
        "line_sha256": turn.line_sha256_hex,
        "role": role,
        "capture_layer": "L2",
        "tool_calls": turn.tool_calls,
    });

    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title,
        content,
        tags,
        priority,
        confidence: 1.0,
        source: "recover".to_string(),
        metadata,
        // Use the turn's own timestamp so the recovered memory's
        // timeline matches the original conversation.
        created_at: turn.timestamp_iso.clone(),
        updated_at: now_iso.clone(),
        last_accessed_at: Some(now_iso),
        memory_kind: MemoryKind::Observation,
        ..Memory::default()
    };

    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| format!("TX_BEGIN_FAILED: {e}"))?;

    let tx_result = (|| -> Result<String, String> {
        let inserted_id =
            crate::storage::insert(conn, &mem).map_err(|e| format!("MEMORY_INSERT_FAILED: {e}"))?;
        let recovered_at_ms = chrono::Utc::now().timestamp_millis();
        conn.execute(
            "INSERT INTO transcript_line_dedup \
             (sha256, memory_id, host_kind, transcript_path, \
              host_session_id, host_turn_index, recovered_at) \
             VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5)",
            rusqlite::params![
                sha_bytes,
                inserted_id,
                host_kind,
                transcript_path.display().to_string(),
                recovered_at_ms,
            ],
        )
        .map_err(|e| format!("DEDUP_INSERT_FAILED: {e}"))?;
        Ok(inserted_id)
    })();

    match tx_result {
        Ok(memory_id) => {
            conn.execute_batch("COMMIT")
                .map_err(|e| format!("TX_COMMIT_FAILED: {e}"))?;
            Ok(memory_id)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const USER_LINE_1: &str = r#"{"timestamp":"2026-05-28T12:00:00Z","type":"user","message":{"content":[{"type":"text","text":"operator directive one"}]}}"#;
    const USER_LINE_2: &str = r#"{"timestamp":"2026-05-28T12:01:00Z","type":"user","message":{"content":[{"type":"text","text":"operator directive two"}]}}"#;
    const USER_LINE_3: &str = r#"{"timestamp":"2026-05-28T12:02:00Z","type":"user","message":{"content":[{"type":"text","text":"operator directive three"}]}}"#;

    /// In-tree scratch root honoring the project no-`/tmp` HARD RULE.
    /// Tempdirs land under the repo's gitignored `.local-runs/`, never
    /// on a tmpfs path.
    fn fresh_dir() -> tempfile::TempDir {
        let root = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".local-runs")
            .join("issue-1389-recover-unit-test");
        std::fs::create_dir_all(&root).ok();
        tempfile::tempdir_in(&root).expect("tempdir under .local-runs")
    }

    fn write_transcript(dir: &Path, lines: &[&str]) -> PathBuf {
        let p = dir.join("session.jsonl");
        let mut f = std::fs::File::create(&p).unwrap();
        for l in lines {
            writeln!(f, "{l}").unwrap();
        }
        f.flush().unwrap();
        p
    }

    fn base_opts(transcript: PathBuf, agent_id: &str) -> RecoverOpts {
        RecoverOpts {
            host: HostKind::ClaudeCode,
            transcript_override: Some(transcript),
            since_iso: None,
            namespace: Some("test-recover".to_string()),
            limit: DEFAULT_RECOVER_LIMIT,
            dry_run: false,
            quiet: false,
            agent_id: agent_id.to_string(),
        }
    }

    #[test]
    fn gap_path_writes_one_memory_per_turn() {
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let transcript = write_transcript(dir.path(), &[USER_LINE_1, USER_LINE_2]);
        let report = recover_from_transcript(&db, &base_opts(transcript, "ai:test:gap")).unwrap();
        assert!(!report.fast_path_hit);
        assert_eq!(report.lines_total, 2);
        assert_eq!(report.lines_atomised, 2);
        assert_eq!(report.memories_created.len(), 2);
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
    }

    #[test]
    fn rerun_dedups_already_recovered_turns() {
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let transcript = write_transcript(dir.path(), &[USER_LINE_1, USER_LINE_2]);
        let opts = base_opts(transcript, "ai:test:dedup");
        let first = recover_from_transcript(&db, &opts).unwrap();
        assert_eq!(first.lines_atomised, 2);
        let second = recover_from_transcript(&db, &opts).unwrap();
        // Same transcript content -> every line dedup-skipped, nothing new.
        assert_eq!(second.lines_atomised, 0);
        assert_eq!(second.lines_skipped_dedup, 2);
        assert!(second.memories_created.is_empty());
    }

    #[test]
    fn limit_caps_atomised_lines() {
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let transcript = write_transcript(dir.path(), &[USER_LINE_1, USER_LINE_2, USER_LINE_3]);
        let mut opts = base_opts(transcript, "ai:test:limit");
        opts.limit = 2;
        let report = recover_from_transcript(&db, &opts).unwrap();
        assert_eq!(report.lines_atomised, 2);
        assert_eq!(report.lines_skipped_limit, 1);
    }

    #[test]
    fn dry_run_persists_nothing() {
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let transcript = write_transcript(dir.path(), &[USER_LINE_1, USER_LINE_2]);
        let mut opts = base_opts(transcript, "ai:test:dry");
        opts.dry_run = true;
        let report = recover_from_transcript(&db, &opts).unwrap();
        assert_eq!(report.lines_atomised, 2, "would-be writes are counted");
        assert!(report.memories_created.is_empty());
        let conn = crate::storage::open(&db).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM transcript_line_dedup", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 0, "dry-run must not write dedup rows");
    }

    #[test]
    fn fast_path_short_circuits_when_watermark_newer_than_mtime() {
        use crate::models::{Memory, MemoryKind, Tier};
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let transcript = write_transcript(dir.path(), &[USER_LINE_1]);
        // Seed a memory for this agent with a far-future created_at so
        // the watermark exceeds the transcript mtime.
        {
            let conn = crate::storage::open(&db).unwrap();
            let mem = Memory {
                id: uuid::Uuid::new_v4().to_string(),
                tier: Tier::Long,
                namespace: "test-recover".to_string(),
                title: "watermark seed".to_string(),
                content: "seed".to_string(),
                priority: 5,
                confidence: 1.0,
                source: "test".to_string(),
                metadata: serde_json::json!({"agent_id": "ai:test:fast"}),
                created_at: "2999-01-01T00:00:00Z".to_string(),
                updated_at: "2999-01-01T00:00:00Z".to_string(),
                memory_kind: MemoryKind::Observation,
                ..Memory::default()
            };
            crate::storage::insert(&conn, &mem).unwrap();
        }
        let report = recover_from_transcript(&db, &base_opts(transcript, "ai:test:fast")).unwrap();
        assert!(report.fast_path_hit, "expected fast-path short-circuit");
        assert_eq!(report.lines_atomised, 0);
    }

    #[test]
    fn missing_transcript_is_graceful() {
        let dir = fresh_dir();
        let db = dir.path().join("mem.db");
        let missing = dir.path().join("does-not-exist.jsonl");
        let report = recover_from_transcript(&db, &base_opts(missing, "ai:test:missing")).unwrap();
        // Parse fails gracefully -> error recorded, no panic, no writes.
        assert_eq!(report.lines_atomised, 0);
        assert!(!report.errors.is_empty());
    }
}
