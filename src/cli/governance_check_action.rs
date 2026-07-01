// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.0 issue #863 — `ai-memory governance check-action` CLI
//! subcommand. Shell-side parity surface for the MCP tool
//! `memory_check_agent_action`. Operators can dry-run any substrate
//! agent-action rule (R001-R004 plus any operator-added rule) from
//! a terminal without driving JSON-RPC over stdio.
//!
//! ## Wire shape
//!
//! ```text
//! ai-memory governance check-action \
//!     --kind <bash|filesystem_write|network_request|process_spawn|custom> \
//!     [--command <str>]   (bash)
//!     [--path <str>]      (filesystem_write)
//!     [--host <str>]      (network_request)
//!     [--binary <str>]    (process_spawn)
//!     [--custom-kind <str>] (custom)
//!     [--agent-id <str>]
//!     [--json]
//! ```
//!
//! Defaults `agent_id` to the same `anonymous:mcp` sentinel the MCP
//! handler uses so the audit trail is symmetric across surfaces.
//!
//! ## Output
//!
//! - Human (default): one line per outcome
//!   `Allow` / `Refuse: <rule_id> — <reason>` / `Warn: <rule_id> — <reason>`.
//! - `--json`: the wire envelope from
//!   [`crate::mcp::tools::check_agent_action::run_check`] unchanged
//!   (`{"decision":{...},"kind":"...","agent_id":"..."}`).
//!
//! ## DRY contract
//!
//! Every per-kind validation and the rule-engine call route through
//! [`crate::mcp::tools::check_agent_action::build_action`] and
//! [`crate::mcp::tools::check_agent_action::run_check`]. No business
//! logic lives here — this module is a clap arg-parser plus an output
//! formatter.

use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;

use crate::cli::CliOutput;
use crate::mcp::tools::check_agent_action::{
    DEFAULT_AGENT_ID, build_action as build_agent_action, run_check,
};

/// CLI args for `ai-memory governance check-action`. The per-kind
/// fields are optional at the clap layer; the substrate shared helper
/// validates which fields are required for the supplied `--kind`.
#[derive(Args, Debug, Clone)]
pub struct CheckActionArgs {
    /// AgentAction kind — one of `bash`, `filesystem_write`,
    /// `network_request`, `process_spawn`, `custom`. Mirrors the
    /// `governance_rules.kind` enum. Required UNLESS
    /// `--from-pretool-stdin` (#1811), which derives the kind from the
    /// Claude Code PreToolUse event read off stdin.
    #[arg(
        long,
        value_name = "KIND",
        required_unless_present = "from_pretool_stdin"
    )]
    pub kind: Option<String>,

    /// Shell command (required when `--kind bash`).
    #[arg(long, value_name = "COMMAND")]
    pub command: Option<String>,

    /// Filesystem path (required when `--kind filesystem_write`).
    #[arg(long, value_name = "PATH")]
    pub path: Option<String>,

    /// Host (required when `--kind network_request`).
    #[arg(long, value_name = "HOST")]
    pub host: Option<String>,

    /// Resolved binary name (required when `--kind process_spawn`).
    #[arg(long, value_name = "BINARY")]
    pub binary: Option<String>,

    /// Inner custom kind (required when `--kind custom`).
    #[arg(long = "custom-kind", value_name = "KIND")]
    pub custom_kind: Option<String>,

    /// Optional agent id stamped into the audit row. Defaults to the
    /// same `anonymous:mcp` sentinel the MCP handler uses.
    #[arg(long = "agent-id", value_name = "ID")]
    pub agent_id: Option<String>,

    /// Emit the raw JSON envelope (same shape as the MCP tool) instead
    /// of the human-readable verdict line.
    #[arg(long)]
    pub json: bool,

    /// #1811 — read a Claude Code PreToolUse hook event JSON object from
    /// stdin (`tool_name` + `tool_input`), map the proposed tool to a
    /// substrate `AgentAction` (Bash → `bash`/`command`;
    /// Edit/Write/MultiEdit/NotebookEdit → `filesystem_write`/`path`),
    /// evaluate the rules, and emit the Claude Code PreToolUse decision
    /// contract on stdout (`hookSpecificOutput.permissionDecision = deny`
    /// on Refuse/Escalate, `ask` on Warn, nothing on Allow). This is the
    /// form the installed `type:command` governance hook invokes — it
    /// owns the harness-contract translation in-binary so a Refuse
    /// actually BLOCKS the tool (a `type:mcp_tool` hook cannot: an MCP
    /// tool's `isError`/non-decision response is non-blocking per the
    /// Claude Code hooks contract). Mutually exclusive with the per-kind
    /// flags. See 5-agent vote `4d3ea1c5`.
    #[arg(
        long = "from-pretool-stdin",
        conflicts_with_all = ["kind", "command", "path", "host", "binary", "custom_kind"]
    )]
    pub from_pretool_stdin: bool,
}

impl CheckActionArgs {
    /// Convert the CLI arg-bag into the JSON object shape the shared
    /// [`build_agent_action`] helper expects.
    fn to_arguments(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "kind".to_string(),
            Value::String(self.kind.clone().unwrap_or_default()),
        );
        if let Some(v) = &self.command {
            obj.insert("command".to_string(), Value::String(v.clone()));
        }
        if let Some(v) = &self.path {
            obj.insert("path".to_string(), Value::String(v.clone()));
        }
        if let Some(v) = &self.host {
            obj.insert("host".to_string(), Value::String(v.clone()));
        }
        if let Some(v) = &self.binary {
            obj.insert("binary".to_string(), Value::String(v.clone()));
        }
        if let Some(v) = &self.custom_kind {
            obj.insert(
                crate::models::field_names::CUSTOM_KIND.to_string(),
                Value::String(v.clone()),
            );
        }
        Value::Object(obj)
    }
}

/// Dispatch entry called from the daemon-runtime `GovernanceAction`
/// match arm.
///
/// # Errors
///
/// - The rules DB at `db_path` cannot be opened.
/// - The shared `build_action` rejects the supplied kind / fields
///   (e.g. `--kind filesystem_write` without `--path`).
/// - The shared `run_check` call returns an error (rules-table SQL
///   failure, audit emit failure).
/// - `--json` mode and `serde_json` cannot serialise the envelope
///   (in practice never happens with the shapes used here).
pub fn run(
    db_path: &std::path::Path,
    args: &CheckActionArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    // #1811 — Claude Code PreToolUse `type:command` hook entry point.
    if args.from_pretool_stdin {
        return run_from_pretool_stdin(db_path, args, out);
    }

    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("governance check-action: open db at {}", db_path.display()))?;

    // `--kind` is `required_unless_present = "from_pretool_stdin"`, so it is
    // always `Some` on this (non-stdin) path; the `bail!` is a belt-and-
    // suspenders guard if the clap contract ever changes.
    let kind = args
        .kind
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("governance check-action: --kind is required"))?;

    let arguments = args.to_arguments();
    let action = build_agent_action(kind, &arguments)
        .map_err(|e| anyhow::anyhow!("governance check-action: {e}"))?;
    let agent_id = args
        .agent_id
        .clone()
        .unwrap_or_else(|| DEFAULT_AGENT_ID.to_string());

    let envelope = run_check(&conn, &agent_id, kind, &action)
        .map_err(|e| anyhow::anyhow!("governance check-action: {e}"))?;

    if args.json {
        // v0.7.0 #1103 — structured Deny envelope. When the resolved
        // decision is `refuse`, lift `rule_id` + `reason` to the top
        // level and tag the payload with `error: "GOVERNANCE_REFUSED"`
        // (uppercase, matching the HTTP error-envelope tag for
        // governance refusals so MCP / HTTP / CLI surfaces are
        // byte-equal under JSON parsing). Allow / warn keep emitting
        // the unchanged envelope so existing consumers don't break.
        let decision_obj = envelope.get("decision").cloned().unwrap_or(Value::Null);
        let verdict = decision_obj
            .get("decision")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let payload = if verdict == "refuse" {
            let rule_id = decision_obj
                .get("rule_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let reason = decision_obj
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("");
            serde_json::json!({
                "error": crate::errors::error_codes::GOVERNANCE_REFUSED,
                "decision": "deny",
                "rule_id": rule_id,
                "reason": reason,
                "kind": kind,
                "agent_id": agent_id,
            })
        } else {
            envelope.clone()
        };
        writeln!(
            out.stdout,
            "{}",
            serde_json::to_string(&payload)
                .context("governance check-action: serialise JSON envelope")?
        )?;
        return Ok(());
    }

    // Human-readable verdict line. The `decision` sub-object follows the
    // serde-tagged shape from `governance::agent_action::Decision`:
    // {"decision": "allow"} / {"decision": "refuse", "rule_id": "...", "reason": "..."}
    let decision = envelope.get("decision").cloned().unwrap_or(Value::Null);
    let verdict = decision
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    match verdict {
        "allow" => writeln!(out.stdout, "Allow")?,
        "refuse" => {
            let rule_id = decision
                .get("rule_id")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let reason = decision
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("?");
            writeln!(out.stdout, "Refuse: {rule_id} — {reason}")?;
        }
        "warn" => {
            let rule_id = decision
                .get("rule_id")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let reason = decision
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("?");
            writeln!(out.stdout, "Warn: {rule_id} — {reason}")?;
        }
        "escalate" => {
            // §22 PE-5 — human-escalation verdict. Fails closed
            // (the action is blocked pending human review).
            let rule_id = decision
                .get("rule_id")
                .and_then(Value::as_str)
                .unwrap_or("?");
            let reason = decision
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("?");
            writeln!(out.stdout, "Escalate: {rule_id} — {reason}")?;
        }
        other => writeln!(out.stdout, "Unknown verdict: {other}")?,
    }
    Ok(())
}

// --- #1811 Claude Code PreToolUse `type:command` hook wrapper -------------
//
// The installer wires `ai-memory governance check-action --from-pretool-stdin`
// as a Claude Code `type:command` PreToolUse hook (matcher `Bash|Edit|Write`).
// This wrapper OWNS the Claude Code hook contract in-binary, which a
// `type:mcp_tool` hook structurally cannot deliver: per the Claude Code hooks
// spec an mcp_tool hook whose tool returns `isError:true` (e.g. the old
// "kind is required" failure) "produces a non-blocking error and execution
// continues", and a tool whose text content is not the CC decision JSON is
// "shown as plain text" — so a substrate Refuse never actually blocked the
// tool. Reading the PreToolUse event here and emitting the documented
// `hookSpecificOutput.permissionDecision` lets a Refuse BLOCK. (5-agent vote
// `4d3ea1c5`.)

/// Decision the wrapper emits back to Claude Code, or `None` to allow the
/// tool to proceed (the wrapper writes nothing and exits 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PretoolDecision {
    /// Claude Code `permissionDecision` — `"deny"` (Refuse/Escalate) or
    /// `"ask"` (Warn — surface to the human).
    permission: &'static str,
    /// Human-facing `permissionDecisionReason` (`<rule_id> — <reason>`).
    reason: String,
}

impl PretoolDecision {
    /// Render the Claude Code PreToolUse `hookSpecificOutput` JSON that, on
    /// stdout with exit 0, drives the harness decision.
    fn to_cc_json(&self) -> Value {
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": self.permission,
                "permissionDecisionReason": self.reason,
            }
        })
    }
}

/// Map a Claude Code tool name + `tool_input` to a substrate `AgentAction`
/// arg-bag, or `None` when the tool is not a governed action surface (the
/// hook then allows it). Bash → `bash`/`command`; Edit/Write/MultiEdit →
/// `filesystem_write`/`path` (`file_path`); NotebookEdit →
/// `filesystem_write`/`path` (`notebook_path`). A governed tool whose
/// expected field is absent also yields `None` (degenerate event → allow,
/// never brick a tool on a malformed payload).
fn map_tool_to_action(tool_name: &str, tool_input: &Value) -> Option<(&'static str, Value)> {
    use crate::governance::agent_action::action_kinds as ak;
    match tool_name {
        "Bash" => {
            let command = tool_input.get("command").and_then(Value::as_str)?;
            let mut bag = serde_json::Map::new();
            bag.insert("kind".into(), Value::String(ak::BASH.into()));
            bag.insert("command".into(), Value::String(command.into()));
            if let Some(cwd) = tool_input.get("cwd").and_then(Value::as_str) {
                bag.insert("cwd".into(), Value::String(cwd.into()));
            }
            Some((ak::BASH, Value::Object(bag)))
        }
        "Edit" | "Write" | "MultiEdit" | "NotebookEdit" => {
            // NotebookEdit carries `notebook_path`; the rest carry `file_path`.
            let path = tool_input
                .get("file_path")
                .or_else(|| tool_input.get("notebook_path"))
                .and_then(Value::as_str)?;
            let mut bag = serde_json::Map::new();
            bag.insert("kind".into(), Value::String(ak::FILESYSTEM_WRITE.into()));
            bag.insert("path".into(), Value::String(path.into()));
            Some((ak::FILESYSTEM_WRITE, Value::Object(bag)))
        }
        // Any other tool the matcher happened to route here is ungoverned.
        _ => None,
    }
}

/// Core, stdin/stdout-free decision logic so it is unit-testable without a
/// live hook. Evaluates a parsed Claude Code PreToolUse `event` against the
/// substrate rules on `conn` and returns the decision to emit, or `None` to
/// allow.
///
/// # Errors
///
/// Propagates a [`run_check`] failure (DB / SQL / audit-emit error) so the
/// caller can apply the configured fail-open / fail-closed posture.
pub(crate) fn decide_pretool_event(
    conn: &rusqlite::Connection,
    agent_id: &str,
    event: &Value,
) -> Result<Option<PretoolDecision>, String> {
    let tool_name = event.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let tool_input = event.get("tool_input").cloned().unwrap_or(Value::Null);

    let Some((kind, arguments)) = map_tool_to_action(tool_name, &tool_input) else {
        return Ok(None); // ungoverned tool / degenerate event → allow
    };
    let action = match build_agent_action(kind, &arguments) {
        Ok(a) => a,
        // A governed tool missing its required field is a malformed event,
        // not a policy violation — allow rather than brick the tool.
        Err(_) => return Ok(None),
    };

    let envelope = run_check(conn, agent_id, kind, &action)?;
    let decision = envelope.get("decision").cloned().unwrap_or(Value::Null);
    let verdict = decision
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or("allow");
    let rule_id = decision
        .get("rule_id")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let reason = decision
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("?");

    let mapped = match verdict {
        // Refuse + Escalate both block the action (Escalate fails closed
        // pending human review; the harness "deny" is the closest contract).
        "refuse" | "escalate" => Some(PretoolDecision {
            permission: "deny",
            reason: format!("{rule_id} — {reason}"),
        }),
        // Warn surfaces to the human via the harness "ask" decision.
        "warn" => Some(PretoolDecision {
            permission: "ask",
            reason: format!("{rule_id} — {reason}"),
        }),
        // Allow (and any unknown verdict) → pass through.
        _ => None,
    };
    Ok(mapped)
}

/// `--from-pretool-stdin` entry: read the PreToolUse event off stdin, decide,
/// and emit the Claude Code contract. Availability-first error handling: a
/// malformed/empty stdin payload allows the tool (never brick a session on a
/// bad hook payload); a deeper rule-check failure honors the documented
/// `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR` posture (default fail-CLOSED →
/// emit `deny`).
fn run_from_pretool_stdin(
    db_path: &std::path::Path,
    args: &CheckActionArgs,
    out: &mut CliOutput<'_>,
) -> Result<()> {
    use std::io::Read as _;

    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("governance check-action: read PreToolUse stdin")?;

    // Empty or unparseable payload → not a governable event; allow.
    let event: Value = match serde_json::from_str(buf.trim()) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };

    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("governance check-action: open db at {}", db_path.display()))?;
    // Tolerate brief write-lock contention with the curator/MCP writers
    // (the rule check emits a signed audit row).
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));

    let agent_id = args
        .agent_id
        .clone()
        .unwrap_or_else(|| DEFAULT_AGENT_ID.to_string());

    match decide_pretool_event(&conn, &agent_id, &event) {
        Ok(Some(decision)) => {
            writeln!(
                out.stdout,
                "{}",
                serde_json::to_string(&decision.to_cc_json())?
            )?;
        }
        Ok(None) => { /* allow: emit nothing, exit 0 */ }
        Err(e) => {
            // Deeper failure (DB/SQL/audit). The inner rule-consultation
            // path already applied AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR;
            // reaching here means infra failed. Honor the same knob.
            writeln!(out.stderr, "ai-memory governance hook: {e}")?;
            if !crate::daemon_runtime::governance_fail_open_on_error() {
                let deny = PretoolDecision {
                    permission: "deny",
                    reason: format!(
                        "governance subsystem error (fail-closed); set \
                         AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR=1 to allow on error: {e}"
                    ),
                };
                writeln!(out.stdout, "{}", serde_json::to_string(&deny.to_cc_json())?)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use tempfile::NamedTempFile;

    fn seed_rules_db() -> NamedTempFile {
        let tmp = NamedTempFile::new().unwrap();
        let conn = rusqlite::Connection::open(tmp.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE governance_rules (
                 id TEXT PRIMARY KEY,
                 kind TEXT NOT NULL,
                 matcher TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 reason TEXT NOT NULL,
                 namespace TEXT NOT NULL DEFAULT '_global',
                 created_by TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 enabled INTEGER NOT NULL DEFAULT 1,
                 signature BLOB,
                 attest_level TEXT NOT NULL DEFAULT 'unsigned'
             );
             CREATE TABLE signed_events (
                 id TEXT PRIMARY KEY,
                 agent_id TEXT NOT NULL,
                 event_type TEXT NOT NULL,
                 payload_hash BLOB NOT NULL,
                 signature BLOB,
                 attest_level TEXT NOT NULL DEFAULT 'unsigned',
                 timestamp TEXT NOT NULL,
                 prev_hash BLOB,
                 sequence INTEGER, cause_hash BLOB
             );",
        )
        .unwrap();
        // Seed R001-style filesystem_write rule (enabled = 1, no signature
        // required because tests force_no_operator_pubkey_for_test below).
        conn.execute(
            "INSERT INTO governance_rules (id, kind, matcher, severity, reason, \
             namespace, created_by, created_at, enabled, signature, attest_level) \
             VALUES (?1, ?2, ?3, 'refuse', ?4, '_global', 'test', 0, 1, NULL, 'unsigned')",
            params![
                "R001",
                "filesystem_write",
                r#"{"glob":"/tmp/**"}"#,
                "no /tmp writes",
            ],
        )
        .unwrap();
        tmp
    }

    #[test]
    fn refuses_filesystem_write_to_tmp() {
        // v0.7.0 #1043 (Agent-6 #6) — acquire the forensic-sink
        // lock alongside the pubkey guard. `run()` → `run_check`
        // → `check_agent_action` → `emit_forensic_decision` →
        // `record_decision` writes to the process-wide
        // `governance::audit::SINK`. Without the lock, a sibling
        // test in the same lib-test binary that called
        // `audit::init` with its own tempdir could bleed decisions
        // into our tempdir (or vice-versa). Today's lib-test
        // scheduler keeps this benign on macOS/Linux, but the
        // explicit lock makes the isolation invariant load-bearing.
        let _audit_lock = crate::governance::audit::forensic_sink_test_lock().lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let tmp = seed_rules_db();
        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        let args = CheckActionArgs {
            kind: Some("filesystem_write".into()),
            command: None,
            path: Some("/tmp/foo.txt".into()),
            host: None,
            binary: None,
            custom_kind: None,
            agent_id: None,
            from_pretool_stdin: false,
            json: true,
        };
        run(tmp.path(), &args, &mut out).unwrap();
        let stdout = String::from_utf8(so).unwrap();
        let v: Value = serde_json::from_str(stdout.trim()).unwrap();
        // v0.7.0 #1103 — structured Deny envelope. Pre-#1103 the JSON
        // shape was the raw `run_check` envelope (`decision.decision`,
        // `decision.rule_id`). Post-#1103 a refuse verdict is lifted
        // to the top-level `GOVERNANCE_REFUSED` envelope so MCP / HTTP /
        // CLI agree on the uppercase tag + flat-fielded shape.
        assert_eq!(
            v["error"], "GOVERNANCE_REFUSED",
            "#1103: refuse verdict must surface `error=GOVERNANCE_REFUSED`"
        );
        assert_eq!(
            v["decision"], "deny",
            "#1103: refuse verdict must surface `decision=deny` (CLI/HTTP parity tag)"
        );
        assert_eq!(
            v["rule_id"], "R001",
            "#1103: refuse verdict must surface flat `rule_id` at the top level"
        );
        assert_eq!(
            v["kind"], "filesystem_write",
            "#1103: refuse envelope echoes the action kind"
        );
        assert!(
            v["reason"].as_str().unwrap_or("").contains("/tmp"),
            "#1103: refuse envelope carries the substrate `reason` string"
        );
    }

    /// v0.7.0 #1103 — Allow / warn verdicts keep the legacy envelope
    /// shape so existing callers that parse `decision.decision` aren't
    /// broken. Only the refuse path lifts to the `GOVERNANCE_REFUSED`
    /// tag. Pins the back-compat half of the #1103 fix.
    #[test]
    fn allow_verdict_keeps_legacy_envelope_1103() {
        let _audit_lock = crate::governance::audit::forensic_sink_test_lock().lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let tmp = seed_rules_db();
        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        let args = CheckActionArgs {
            kind: Some("filesystem_write".into()),
            command: None,
            // Path outside /tmp — substrate rule allows.
            path: Some("/home/user/ok.txt".into()),
            host: None,
            binary: None,
            custom_kind: None,
            agent_id: None,
            from_pretool_stdin: false,
            json: true,
        };
        run(tmp.path(), &args, &mut out).unwrap();
        let stdout = String::from_utf8(so).unwrap();
        let v: Value = serde_json::from_str(stdout.trim()).unwrap();
        // Allow path keeps the raw envelope shape.
        assert_eq!(v["decision"]["decision"], "allow");
        assert!(
            v.get("error").is_none(),
            "#1103: allow verdicts must NOT carry the GOVERNANCE_REFUSED tag"
        );
    }

    #[test]
    fn allows_filesystem_write_outside_tmp() {
        // v0.7.0 #1043 — see comment on
        // `refuses_filesystem_write_to_tmp` for the lock rationale.
        let _audit_lock = crate::governance::audit::forensic_sink_test_lock().lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let tmp = seed_rules_db();
        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        let args = CheckActionArgs {
            kind: Some("filesystem_write".into()),
            command: None,
            path: Some("/home/user/ok.txt".into()),
            host: None,
            binary: None,
            custom_kind: None,
            agent_id: None,
            from_pretool_stdin: false,
            json: false,
        };
        run(tmp.path(), &args, &mut out).unwrap();
        let stdout = String::from_utf8(so).unwrap();
        assert!(stdout.trim() == "Allow", "got: {stdout}");
    }

    #[test]
    fn missing_required_field_errors() {
        // v0.7.0 #1043 — even error-path tests acquire the lock so
        // a future change that starts emitting forensic rows on the
        // missing-field error path inherits the isolation.
        let _audit_lock = crate::governance::audit::forensic_sink_test_lock().lock();
        let tmp = seed_rules_db();
        let mut so = Vec::<u8>::new();
        let mut se = Vec::<u8>::new();
        let mut out = CliOutput::from_std(&mut so, &mut se);
        let args = CheckActionArgs {
            kind: Some("filesystem_write".into()),
            command: None,
            path: None,
            host: None,
            binary: None,
            custom_kind: None,
            agent_id: None,
            from_pretool_stdin: false,
            json: false,
        };
        let err = run(tmp.path(), &args, &mut out).unwrap_err();
        assert!(err.to_string().contains("path"), "got: {err}");
    }

    // --- #1811 PreToolUse `--from-pretool-stdin` wrapper regression tests ---
    //
    // These pin the exact bug class #1811 reported: the hook → tool-args
    // contract. The OLD installer wrote a `type:mcp_tool` entry with no
    // `input`, so the tool errored "kind is required" and the gate never
    // evaluated a rule (and even a Refuse would not block). The wrapper now
    // owns the mapping; a re-introduction of a missing-field / wrong-kind
    // mapping, or a Refuse that fails to translate into a `deny`, trips here.

    fn open_seeded_conn(tmp: &NamedTempFile) -> rusqlite::Connection {
        rusqlite::Connection::open(tmp.path()).unwrap()
    }

    #[test]
    fn pretool_filesystem_write_to_tmp_denies() {
        let _audit_lock = crate::governance::audit::forensic_sink_test_lock().lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let tmp = seed_rules_db();
        let conn = open_seeded_conn(&tmp);
        // Synthetic Claude Code PreToolUse event for an Edit into /tmp.
        let event = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": { "file_path": "/tmp/foo.txt", "old_string": "a", "new_string": "b" },
        });
        let decision = decide_pretool_event(&conn, "anonymous:mcp", &event)
            .expect("rule check ok")
            .expect("a refuse rule must yield a decision");
        assert_eq!(
            decision.permission, "deny",
            "#1811: a substrate Refuse must translate to a Claude Code `deny` so the tool BLOCKS"
        );
        assert!(
            decision.reason.contains("/tmp"),
            "deny reason must carry the substrate rule reason, got: {}",
            decision.reason
        );
        // And the emitted wire JSON is the documented CC contract shape.
        let cc = decision.to_cc_json();
        assert_eq!(cc["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(cc["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn pretool_filesystem_write_outside_tmp_allows() {
        let _audit_lock = crate::governance::audit::forensic_sink_test_lock().lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let tmp = seed_rules_db();
        let conn = open_seeded_conn(&tmp);
        let event = serde_json::json!({
            "tool_name": "Write",
            "tool_input": { "file_path": "/home/user/ok.txt", "content": "hi" },
        });
        let decision = decide_pretool_event(&conn, "anonymous:mcp", &event).expect("rule check ok");
        assert!(
            decision.is_none(),
            "a non-matching path must allow (no output)"
        );
    }

    #[test]
    fn pretool_bash_no_rule_allows() {
        let _audit_lock = crate::governance::audit::forensic_sink_test_lock().lock();
        let _no_pubkey = crate::governance::rules_store::force_no_operator_pubkey_for_test();
        let tmp = seed_rules_db();
        let conn = open_seeded_conn(&tmp);
        // Bash maps to kind=bash; seeded DB only has a filesystem_write rule,
        // so this must allow — proving the kind mapping is wired (no "kind is
        // required" error, the #1811 symptom).
        let event = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": "ls -la", "description": "list" },
        });
        let decision = decide_pretool_event(&conn, "anonymous:mcp", &event).expect("rule check ok");
        assert!(decision.is_none(), "bash with no matching rule allows");
    }

    #[test]
    fn pretool_unmapped_tool_allows() {
        let tmp = seed_rules_db();
        let conn = open_seeded_conn(&tmp);
        // A read-only tool the matcher should never route here; if it does,
        // it is ungoverned → allow without ever touching the rules engine.
        let event = serde_json::json!({
            "tool_name": "Read",
            "tool_input": { "file_path": "/tmp/whatever" },
        });
        let decision = decide_pretool_event(&conn, "anonymous:mcp", &event).expect("ok");
        assert!(decision.is_none(), "ungoverned tool allows");
    }

    #[test]
    fn pretool_degenerate_event_missing_field_allows() {
        let tmp = seed_rules_db();
        let conn = open_seeded_conn(&tmp);
        // Governed tool but no `command` → degenerate event → allow, never
        // brick the tool (and never error "command is required").
        let event = serde_json::json!({ "tool_name": "Bash", "tool_input": {} });
        let decision = decide_pretool_event(&conn, "anonymous:mcp", &event).expect("ok");
        assert!(decision.is_none(), "missing required field allows");
    }

    #[test]
    fn map_notebook_edit_uses_notebook_path() {
        let (kind, bag) = map_tool_to_action(
            "NotebookEdit",
            &serde_json::json!({ "notebook_path": "/nb/x.ipynb", "new_source": "1" }),
        )
        .expect("NotebookEdit is governed");
        assert_eq!(kind, "filesystem_write");
        assert_eq!(bag["path"], "/nb/x.ipynb");
    }
}
