// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! L1 — `memory_capture_nag` watcher. Enforces the CLAUDE.md
//! HARD-RULE (`memory_store` FIRST on operator multi-step
//! directives) by tracking per-(agent_id, session_id) turn counters
//! and emitting a single stderr WARN + a `capture_lag` signed event
//! after a configurable threshold of non-`memory_store` MCP tool
//! calls in a row.
//!
//! # Why this exists
//!
//! The substrate is volunteer-mode about capture. Even with the
//! CLAUDE.md HARD-RULE in place, the agent can drift — system-prompt
//! adherence is best-effort. The nag watcher is the substrate-side
//! enforcement layer that surfaces the drift to operators in real
//! time rather than at next-session-recovery time (L2).
//!
//! # What this catches
//!
//! The common case from #1388: an agent that calls many MCP tools
//! (file ops, tool runs, network calls) without ever calling
//! `memory_store`. After threshold N (default 5) non-store calls,
//! the watcher fires.
//!
//! # What this does NOT do
//!
//! - It does NOT block the agent's tool calls. The WARN is
//!   observability, not enforcement. Blocking would be a substrate-
//!   level policy decision; nag is intentionally observation-only.
//! - It does NOT semantically classify the user prompt. The MCP
//!   server sees tool calls, not user prompts; the watcher operates
//!   on observable substrate state only.
//! - It does NOT count READ-class memory tool calls (`memory_recall`,
//!   `memory_get`, etc.) as "captures" — only writes (`memory_store`,
//!   `memory_update`, `memory_link`, `memory_atomise` family) reset
//!   the counter.
//!
//! # Integration
//!
//! The MCP dispatch loop in `src/mcp/mod.rs::handle_request` calls
//! [`CaptureNagWatcher::observe_tool_call`] before dispatching every
//! tool call; the result is one of [`NagAction::None`],
//! [`NagAction::Warn`], or [`NagAction::WarnAndEscalate`]. The
//! dispatch loop honors the action by emitting to stderr +
//! `signed_events` as appropriate.
//!
//! # Configuration
//!
//! - `AI_MEMORY_CAPTURE_NAG_THRESHOLD` — turn threshold for the first
//!   WARN. Default `5`. Set to `0` to disable.
//! - `AI_MEMORY_CAPTURE_NAG_ESCALATE_THRESHOLD` — turn threshold for
//!   the escalation WARN (signaling sustained drift). Default `20`.
//!   Set to `0` to disable escalation.

use std::collections::HashMap;
use std::sync::Mutex;

/// Env var overriding the primary nag threshold (first WARN).
pub const NAG_THRESHOLD_ENV: &str = "AI_MEMORY_CAPTURE_NAG_THRESHOLD";

/// Env var overriding the escalation nag threshold (sustained-drift WARN).
pub const NAG_ESCALATE_THRESHOLD_ENV: &str = "AI_MEMORY_CAPTURE_NAG_ESCALATE_THRESHOLD";

/// Default primary threshold: number of consecutive non-write tool
/// calls before the first `capture_lag` WARN fires. Overridable via
/// [`NAG_THRESHOLD_ENV`]; `0` disables.
pub const DEFAULT_NAG_THRESHOLD: u32 = 5;

/// Default escalation threshold: consecutive non-write tool calls
/// before the sustained-drift WARN fires. Overridable via
/// [`NAG_ESCALATE_THRESHOLD_ENV`]; `0` disables.
pub const DEFAULT_NAG_ESCALATE_THRESHOLD: u32 = 20;

/// Per-`(agent_id, session_id)` non-store-call counter, plus the
/// "have we already warned this session" flag so each session
/// gets at most one WARN per threshold (no log spam).
#[derive(Debug, Clone, Copy, Default)]
struct SessionCounter {
    /// Count of consecutive MCP tool calls in this session that
    /// were NOT memory-write-class. Reset on every memory-write
    /// call (`memory_store`, `memory_update`, `memory_link`,
    /// `memory_atomise`, etc.).
    non_store_streak: u32,
    /// `true` after the first WARN has been emitted in this
    /// session, so the dispatch loop doesn't spam every subsequent
    /// non-store call.
    primary_warned: bool,
    /// `true` after the escalation WARN has been emitted.
    escalation_warned: bool,
}

/// Action the dispatch loop should take after a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NagAction {
    /// No action — counter incremented, threshold not reached, or
    /// session already warned at this threshold.
    None,
    /// Primary threshold hit — emit a single stderr WARN + a single
    /// `capture_lag` signed event for this session.
    Warn,
    /// Sustained drift — emit a sustained-drift WARN + an
    /// escalation signed event. Implies primary already fired.
    WarnAndEscalate,
}

/// Watcher singleton held inside the daemon's runtime context. The
/// inner state is mutex-guarded because the MCP dispatch loop is
/// single-threaded but the HTTP daemon may call it from parallel
/// Axum handler tasks; the lock is uncontended in the stdio MCP
/// path and microsecond-contended in the HTTP path.
pub struct CaptureNagWatcher {
    inner: Mutex<HashMap<(String, String), SessionCounter>>,
    primary_threshold: u32,
    escalation_threshold: u32,
}

/// Per-tool-call classification. Memory-write-class calls reset
/// the counter; everything else increments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    /// `memory_store`, `memory_update`, `memory_link`,
    /// `memory_atomise`, `memory_ingest_multistep`, `memory_consolidate`,
    /// or any other write-class memory tool. Resets the counter.
    MemoryWrite,
    /// Any other tool — read-class memory tool, non-memory tool,
    /// file op, bash, etc.
    Other,
}

impl CaptureNagWatcher {
    /// Create a new watcher with thresholds from environment vars
    /// (or defaults if unset / unparseable).
    ///
    /// Default thresholds: primary [`DEFAULT_NAG_THRESHOLD`],
    /// escalation [`DEFAULT_NAG_ESCALATE_THRESHOLD`]. Set either to
    /// `0` to disable that threshold.
    #[must_use]
    pub fn new_from_env() -> Self {
        let primary = parse_threshold_env(NAG_THRESHOLD_ENV, DEFAULT_NAG_THRESHOLD);
        let escalation =
            parse_threshold_env(NAG_ESCALATE_THRESHOLD_ENV, DEFAULT_NAG_ESCALATE_THRESHOLD);
        Self::new(primary, escalation)
    }

    /// Construct with explicit thresholds. Useful in tests.
    #[must_use]
    pub fn new(primary_threshold: u32, escalation_threshold: u32) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            primary_threshold,
            escalation_threshold,
        }
    }

    /// Observe one tool call. The dispatch loop calls this BEFORE
    /// dispatching the tool itself; the returned [`NagAction`]
    /// indicates whether to emit a WARN / escalate.
    ///
    /// The observation is idempotent on the WARN — once a session
    /// has been warned at a threshold, subsequent calls at the
    /// same threshold return [`NagAction::None`] until the next
    /// threshold tier is crossed.
    ///
    /// # Panics
    ///
    /// Does not panic. A poisoned mutex (which should not occur in
    /// practice) downgrades to no-op so the dispatch loop never
    /// fails on this side effect.
    pub fn observe_tool_call(
        &self,
        agent_id: &str,
        session_id: &str,
        tool_kind: ToolKind,
    ) -> NagAction {
        let key = (agent_id.to_string(), session_id.to_string());
        let Ok(mut state) = self.inner.lock() else {
            // Mutex poisoned — silently degrade. The dispatch
            // loop's correctness does not depend on nag emission.
            return NagAction::None;
        };
        let entry = state.entry(key).or_default();

        match tool_kind {
            ToolKind::MemoryWrite => {
                // Reset on every write — including the warned
                // flag, so a future drift in the same session
                // re-arms the watcher.
                *entry = SessionCounter::default();
                NagAction::None
            }
            ToolKind::Other => {
                entry.non_store_streak = entry.non_store_streak.saturating_add(1);

                // Escalation threshold takes priority. The check
                // order matters because the escalation flag also
                // protects against repeated emission once both
                // thresholds have fired.
                if self.escalation_threshold > 0
                    && entry.non_store_streak >= self.escalation_threshold
                    && !entry.escalation_warned
                {
                    entry.escalation_warned = true;
                    return NagAction::WarnAndEscalate;
                }
                if self.primary_threshold > 0
                    && entry.non_store_streak >= self.primary_threshold
                    && !entry.primary_warned
                {
                    entry.primary_warned = true;
                    return NagAction::Warn;
                }
                NagAction::None
            }
        }
    }

    /// Streak count for a `(agent_id, session_id)` — exposed so
    /// the capabilities envelope can report `nag_active` + the
    /// current streak per active session.
    #[must_use]
    pub fn streak_for(&self, agent_id: &str, session_id: &str) -> u32 {
        let key = (agent_id.to_string(), session_id.to_string());
        let Ok(state) = self.inner.lock() else {
            return 0;
        };
        state.get(&key).map_or(0, |c| c.non_store_streak)
    }

    /// Drop a session's counter — called by the dispatch loop
    /// when the MCP session closes so the HashMap doesn't grow
    /// unboundedly across long-running daemon uptime.
    pub fn drop_session(&self, agent_id: &str, session_id: &str) {
        let key = (agent_id.to_string(), session_id.to_string());
        if let Ok(mut state) = self.inner.lock() {
            state.remove(&key);
        }
    }

    /// Current primary threshold. Exposed for the capabilities
    /// envelope.
    #[must_use]
    pub fn primary_threshold(&self) -> u32 {
        self.primary_threshold
    }

    /// Current escalation threshold. Exposed for the capabilities
    /// envelope.
    #[must_use]
    pub fn escalation_threshold(&self) -> u32 {
        self.escalation_threshold
    }
}

impl Default for CaptureNagWatcher {
    fn default() -> Self {
        Self::new_from_env()
    }
}

/// Classify an MCP tool name into [`ToolKind`]. The classifier is
/// allowlist-style: only known memory-write tools count as
/// resets. Anything else (including future tools added after this
/// match) defaults to `Other`, which is the safe default for the
/// nag layer (an unrecognized tool is treated as "no capture
/// happened").
#[must_use]
pub fn classify_tool(tool_name: &str) -> ToolKind {
    match tool_name {
        "memory_store"
        | "memory_update"
        | "memory_link"
        | "memory_atomise"
        | "memory_ingest_multistep"
        | "memory_consolidate"
        | "memory_promote"
        | "memory_reflect"
        | "memory_persona_generate"
        | "memory_entity_register"
        | "memory_share"
        | "memory_subscribe"
        | "memory_notify"
        | "memory_skill_register"
        | "memory_skill_promote_from_reflection"
        | "memory_namespace_set_standard"
        | "memory_kg_invalidate"
        | "memory_capture_turn" => ToolKind::MemoryWrite,
        _ => ToolKind::Other,
    }
}

fn parse_threshold_env(name: &str, default_value: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(default_value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_tool_recognizes_writes() {
        assert_eq!(classify_tool("memory_store"), ToolKind::MemoryWrite);
        assert_eq!(classify_tool("memory_update"), ToolKind::MemoryWrite);
        assert_eq!(classify_tool("memory_link"), ToolKind::MemoryWrite);
        assert_eq!(classify_tool("memory_atomise"), ToolKind::MemoryWrite);
        assert_eq!(
            classify_tool("memory_capture_turn"),
            ToolKind::MemoryWrite,
            "L4 surface MUST reset the nag counter"
        );
    }

    #[test]
    fn classify_tool_defaults_to_other() {
        assert_eq!(classify_tool("memory_recall"), ToolKind::Other);
        assert_eq!(classify_tool("memory_get"), ToolKind::Other);
        assert_eq!(classify_tool("bash"), ToolKind::Other);
        assert_eq!(classify_tool("unknown_future_tool"), ToolKind::Other);
    }

    #[test]
    fn primary_threshold_fires_exactly_once() {
        let w = CaptureNagWatcher::new(3, 10);
        for _ in 0..2 {
            assert_eq!(
                w.observe_tool_call("agent", "session", ToolKind::Other),
                NagAction::None
            );
        }
        // 3rd call hits threshold.
        assert_eq!(
            w.observe_tool_call("agent", "session", ToolKind::Other),
            NagAction::Warn
        );
        // 4th call should NOT re-emit primary WARN.
        assert_eq!(
            w.observe_tool_call("agent", "session", ToolKind::Other),
            NagAction::None
        );
    }

    #[test]
    fn memory_write_resets_streak() {
        let w = CaptureNagWatcher::new(3, 10);
        // Build streak.
        for _ in 0..2 {
            w.observe_tool_call("agent", "session", ToolKind::Other);
        }
        assert_eq!(w.streak_for("agent", "session"), 2);
        // Write resets.
        assert_eq!(
            w.observe_tool_call("agent", "session", ToolKind::MemoryWrite),
            NagAction::None
        );
        assert_eq!(w.streak_for("agent", "session"), 0);
        // Now we can build a fresh streak that re-arms the WARN.
        for _ in 0..2 {
            w.observe_tool_call("agent", "session", ToolKind::Other);
        }
        assert_eq!(
            w.observe_tool_call("agent", "session", ToolKind::Other),
            NagAction::Warn,
            "re-armed WARN after reset"
        );
    }

    #[test]
    fn escalation_threshold_fires_after_sustained_drift() {
        let w = CaptureNagWatcher::new(2, 4);
        // Hit primary at call 2.
        w.observe_tool_call("agent", "session", ToolKind::Other);
        assert_eq!(
            w.observe_tool_call("agent", "session", ToolKind::Other),
            NagAction::Warn
        );
        // Calls 3 + 4: 3 is no-op (already warned primary), 4 hits escalation.
        assert_eq!(
            w.observe_tool_call("agent", "session", ToolKind::Other),
            NagAction::None
        );
        assert_eq!(
            w.observe_tool_call("agent", "session", ToolKind::Other),
            NagAction::WarnAndEscalate
        );
        // 5th call: no further emission.
        assert_eq!(
            w.observe_tool_call("agent", "session", ToolKind::Other),
            NagAction::None
        );
    }

    #[test]
    fn per_session_counters_are_independent() {
        let w = CaptureNagWatcher::new(2, 10);
        // Session A approaches threshold.
        w.observe_tool_call("agent", "session-a", ToolKind::Other);
        // Session B's counter is independent.
        assert_eq!(w.streak_for("agent", "session-b"), 0);
        // Session A hits threshold.
        assert_eq!(
            w.observe_tool_call("agent", "session-a", ToolKind::Other),
            NagAction::Warn
        );
        // Session B's first call: still no warn.
        assert_eq!(
            w.observe_tool_call("agent", "session-b", ToolKind::Other),
            NagAction::None
        );
    }

    #[test]
    fn per_agent_counters_are_independent() {
        let w = CaptureNagWatcher::new(2, 10);
        w.observe_tool_call("agent-a", "session", ToolKind::Other);
        assert_eq!(w.streak_for("agent-b", "session"), 0);
    }

    #[test]
    fn drop_session_clears_counter() {
        let w = CaptureNagWatcher::new(2, 10);
        w.observe_tool_call("agent", "session", ToolKind::Other);
        assert_eq!(w.streak_for("agent", "session"), 1);
        w.drop_session("agent", "session");
        assert_eq!(w.streak_for("agent", "session"), 0);
    }

    #[test]
    fn disabled_thresholds_never_fire() {
        let w = CaptureNagWatcher::new(0, 0);
        for _ in 0..100 {
            assert_eq!(
                w.observe_tool_call("agent", "session", ToolKind::Other),
                NagAction::None
            );
        }
    }

    #[test]
    fn streak_saturates_instead_of_overflowing() {
        // Smoke test for the saturating_add — the dispatch loop
        // ought never to deliver u32::MAX tool calls in a single
        // session, but we should not panic if it does.
        let w = CaptureNagWatcher::new(5, 10);
        // Force the streak high without going through the normal
        // observe path — we only verify the saturating behavior
        // here.
        let key = ("agent".to_string(), "session".to_string());
        {
            let mut state = w.inner.lock().unwrap();
            state.insert(
                key,
                SessionCounter {
                    non_store_streak: u32::MAX - 1,
                    primary_warned: true,
                    escalation_warned: true,
                },
            );
        }
        // Two more calls — saturates rather than wrapping.
        w.observe_tool_call("agent", "session", ToolKind::Other);
        w.observe_tool_call("agent", "session", ToolKind::Other);
        assert_eq!(w.streak_for("agent", "session"), u32::MAX);
    }
}
