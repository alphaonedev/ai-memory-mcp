// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_check_agent_action` handler (issue #691).
//!
//! Read-only entry point into the substrate-level agent-action rules
//! engine. The harness's PreToolUse hook (type=`mcp_tool`) calls this
//! tool with the action it is about to execute and honors the
//! returned [`Decision`]. The engine never has authority to MODIFY
//! the action; it returns Allow / Refuse / Warn.
//!
//! # Why this is the only governance-write MCP tool
//!
//! Per issue #691 design revision 2026-05-13, MUTATION over MCP
//! stdio is explicitly disabled — `rule_add` / `rule_remove` /
//! `rule_enable` / `rule_disable` are NOT registered as MCP tools.
//! An MCP caller that tries to mutate must route through the CLI
//! (operator key on disk) or the HTTP admin endpoints
//! (`X-AI-Memory-Operator-Signature` header). `check_agent_action`
//! is the *read-side* MCP surface; it is the load-bearing tool the
//! PreToolUse hook calls on every Bash / Write / Edit dispatch.

use serde_json::{Value, json};

use crate::governance::agent_action::{AgentAction, check_agent_action};

/// Default `agent_id` echoed back when the caller (MCP or CLI) does
/// not supply one. Kept as a `pub const` so the CLI `governance
/// check-action` handler reuses the exact same wire string and the
/// MCP/CLI surfaces stay symmetric for issue #863.
pub const DEFAULT_AGENT_ID: &str = "anonymous:mcp";

/// Handler for `memory_check_agent_action`. Expects `arguments`:
///
/// ```json
/// {
///   "kind": "bash" | "filesystem_write" | "network_request" | "process_spawn" | "custom",
///   "command": "...",         // bash
///   "path": "...",            // filesystem_write
///   "host": "...",            // network_request
///   "binary": "...",          // process_spawn
///   "agent_id": "..."         // optional; defaults to the MCP-resolved id
/// }
/// ```
///
/// Returns a JSON object with the [`crate::governance::agent_action::Decision`]
/// shape (`{"decision":"allow"}` / `{"decision":"refuse","rule_id":...,"reason":...}`
/// / `{"decision":"warn","rule_id":...,"reason":...}`).
pub fn handle_check_agent_action(
    conn: &rusqlite::Connection,
    arguments: &Value,
) -> Result<Value, String> {
    let kind = arguments
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "kind is required".to_string())?;
    let action = build_action(kind, arguments)?;
    let agent_id = arguments
        .get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_AGENT_ID)
        .to_string();
    run_check(conn, &agent_id, kind, &action)
}

/// Shared core: evaluate a pre-built [`AgentAction`] against the
/// `governance_rules` table on the supplied connection and return
/// the canonical MCP/CLI JSON envelope (`{decision, kind, agent_id}`).
///
/// Issue #863 — extracted from [`handle_check_agent_action`] so the
/// `ai-memory governance check-action` CLI subcommand can reuse the
/// exact same path. DRY: there is only ONE implementation of "check
/// an agent action against the rules table"; the MCP tool and the
/// CLI verb are both thin parsers that funnel into this function.
///
/// # Errors
///
/// Propagates any error from [`check_agent_action`] (rules DB query
/// failure, audit emit failure) as a `String` so both call sites can
/// surface it without an `anyhow` dependency in the response shape.
pub fn run_check(
    conn: &rusqlite::Connection,
    agent_id: &str,
    kind: &str,
    action: &AgentAction,
) -> Result<Value, String> {
    // v0.7.0 #1023 (Agent-1 #9) — MCP-side `memory_check_agent_action`
    // intentionally uses the un-cached entry point. The MCP server
    // runs as a SEPARATE process from the HTTP daemon (stdio
    // JSON-RPC at `ai-memory mcp`) so the daemon's `Arc<RuleCache>`
    // is not in scope; the MCP path opens its own
    // `rusqlite::Connection` per dispatch (`ai-memory mcp` boots
    // the connection at startup and reuses it for the loop's
    // lifetime — see `src/mcp/mod.rs::main_loop`), but there is no
    // long-lived RuleCache wiring through `ToolDispatchCtx` today.
    //
    // The cost is bounded: this entry point is operator-driven
    // (debugging / policy verification), NOT a hot path. The
    // wire-action hot paths (storage `GOVERNANCE_PRE_WRITE` hook
    // + wire_check `GOVERNANCE_PRE_ACTION` hook) DO use the cache
    // via `daemon_runtime.rs`'s hook closures (#991 + #1017), so
    // production-rate governance evaluation is cache-served.
    //
    // A future change that adds `rule_cache: Option<Arc<RuleCache>>`
    // to `ToolDispatchCtx` would let this entry point switch to
    // `check_agent_action_cached(conn, Some(&cache), agent_id, action)`
    // with no other call-site change. Tracked as follow-up to #1023.
    let decision = check_agent_action(conn, agent_id, action).map_err(|e| e.to_string())?;
    Ok(json!({
        "decision": decision,
        "kind": kind,
        "agent_id": agent_id,
    }))
}

/// Build an [`AgentAction`] from the MCP/CLI JSON arg-bag for the
/// given `kind`. Shared between the MCP tool handler and the CLI
/// `governance check-action` subcommand (issue #863).
///
/// # Errors
///
/// Returns a `String` error when `kind` is not one of the five
/// canonical kinds or when the required per-kind fields are missing
/// (`command` for bash, `path` for filesystem_write, etc.).
pub fn build_action(kind: &str, arguments: &Value) -> Result<AgentAction, String> {
    use std::path::PathBuf;

    match kind {
        "bash" => {
            let command = arguments
                .get("command")
                .and_then(Value::as_str)
                .ok_or_else(|| "bash kind requires `command`".to_string())?
                .to_string();
            let cwd = arguments
                .get("cwd")
                .and_then(Value::as_str)
                .map(PathBuf::from);
            Ok(AgentAction::Bash { command, cwd })
        }
        "filesystem_write" => {
            let path = arguments
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| "filesystem_write kind requires `path`".to_string())?
                .to_string();
            let byte_estimate = arguments.get("byte_estimate").and_then(Value::as_u64);
            Ok(AgentAction::FilesystemWrite {
                path: PathBuf::from(path),
                byte_estimate,
            })
        }
        "network_request" => {
            let host = arguments
                .get("host")
                .and_then(Value::as_str)
                .ok_or_else(|| "network_request kind requires `host`".to_string())?
                .to_string();
            let scheme = arguments
                .get("scheme")
                .and_then(Value::as_str)
                .unwrap_or("https")
                .to_string();
            Ok(AgentAction::NetworkRequest { host, scheme })
        }
        "process_spawn" => {
            let binary = arguments
                .get("binary")
                .and_then(Value::as_str)
                .ok_or_else(|| "process_spawn kind requires `binary`".to_string())?
                .to_string();
            let args = arguments
                .get("args")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            Ok(AgentAction::ProcessSpawn { binary, args })
        }
        "custom" => {
            let custom_kind = arguments
                .get("custom_kind")
                .or_else(|| arguments.get("kind_inner"))
                .and_then(Value::as_str)
                .ok_or_else(|| "custom kind requires `custom_kind`".to_string())?
                .to_string();
            Ok(AgentAction::Custom {
                custom_kind,
                payload: arguments.clone(),
            })
        }
        other => Err(format!("unknown kind `{other}`")),
    }
}

/// Reusable refusal value for rule-mutation tools that are
/// explicitly disabled over MCP. Wired by `mcp/mod.rs` if a future
/// caller tries to invoke a mutation tool name — today the
/// mutation tools are simply not registered, so the dispatch returns
/// "unknown tool". This constant is kept around for the wire-name
/// stability test in `tests/governance_immutability.rs`.
// Stable wire string consumed by `tests/governance_immutability.rs` to
// pin the error returned when a future caller tries to mutate rules
// over MCP. The mutation tools are NOT registered today, so the
// dispatch returns "unknown tool" instead — this constant documents
// the canonical error vocabulary the test suite asserts on.
#[allow(dead_code)]
pub const MCP_MUTATION_DISABLED_ERROR: &str = "governance.not_available_over_mcp: rule mutation is operator-only \
     (CLI `ai-memory rules` or HTTP `POST /api/v1/governance/rules`)";

// --- D1.5 (#986): per-tool McpTool impl for memory_check_agent_action ---

use crate::mcp::registry::McpTool;
use schemars::JsonSchema;
use serde::Deserialize;

/// v0.7.0 #972 D1.5 (#986) — request body for `memory_check_agent_action`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[allow(dead_code)]
pub struct CheckAgentActionRequest {
    pub kind: String,

    /// kind=bash.
    #[serde(default)]
    pub command: Option<String>,

    /// kind=bash cwd.
    #[serde(default)]
    pub cwd: Option<String>,

    /// kind=filesystem_write.
    #[serde(default)]
    pub path: Option<String>,

    /// Bytes-to-write hint.
    #[serde(default)]
    pub byte_estimate: Option<i64>,

    /// kind=network_request.
    #[serde(default)]
    pub host: Option<String>,

    /// Default https.
    #[serde(default)]
    pub scheme: Option<String>,

    /// kind=process_spawn.
    #[serde(default)]
    pub binary: Option<String>,

    /// process_spawn argv.
    #[serde(default)]
    pub args: Vec<String>,

    /// kind=custom.
    #[serde(default)]
    pub custom_kind: Option<String>,

    /// Caller id (audit).
    #[serde(default)]
    pub agent_id: Option<String>,
}

/// v0.7.0 #972 D1.5 (#986) — `McpTool` impl for `memory_check_agent_action`.
#[allow(dead_code)]
pub struct CheckAgentActionTool;

impl McpTool for CheckAgentActionTool {
    fn name() -> &'static str {
        crate::mcp::registry::tool_names::MEMORY_CHECK_AGENT_ACTION
    }
    fn description() -> &'static str {
        "Check action vs governance_rules (#691); Allow/Refuse/Warn."
    }
    fn docs() -> &'static str {
        "#691: read-only rule check. Harness PreToolUse hook calls on every Bash/Write/Edit. Rule MUTATION over MCP is disabled — use `ai-memory rules --sign` CLI or signed HTTP admin endpoints."
    }
    fn input_schema() -> Value {
        let schema = schemars::schema_for!(CheckAgentActionRequest);
        serde_json::to_value(schema).expect("schemars schema must serialize to Value")
    }
    fn family() -> &'static str {
        "power"
    }
}

#[cfg(test)]
mod d1_5_986_tests {
    //! D1.5 (#986) — schema parity for `memory_check_agent_action`.
    //! Shared helpers live at [`crate::mcp::parity_test_helpers`].
    use super::*;
    use crate::mcp::parity_test_helpers::{
        assert_descriptions_match, assert_property_set_parity, derived_props_for,
    };

    #[test]
    fn check_agent_action_parity_986() {
        let derived = derived_props_for::<CheckAgentActionRequest>();
        assert_property_set_parity("memory_check_agent_action", &derived);
        assert_descriptions_match("memory_check_agent_action", &derived);
    }

    #[test]
    fn check_agent_action_tool_metadata_986() {
        assert_eq!(CheckAgentActionTool::name(), "memory_check_agent_action");
        assert_eq!(CheckAgentActionTool::family(), "power");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::rules_store::{self, Rule};

    /// Issue #899 — guard against cross-test forensic-sink bleed.
    ///
    /// `handle_check_agent_action` calls `check_agent_action`, which
    /// indirectly fires `crate::governance::audit::record_decision`
    /// via `emit_forensic_decision`. If a sibling test in
    /// `governance::audit::tests` has initialised the process-wide
    /// forensic sink at its tempdir, this thread's `record_decision`
    /// would land a row in that sibling's tempdir.
    ///
    /// Every test in this module that fires
    /// `handle_check_agent_action` MUST hold this lock for the
    /// duration of the call. See `governance::audit::forensic_sink_test_lock`.
    #[must_use = "the guard must be held for the scope of the test"]
    fn forensic_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::governance::audit::forensic_sink_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn fresh_conn() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
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
                 -- v34 (V-4 closeout, #698) — cross-row chain columns.
                 prev_hash BLOB,
                 sequence INTEGER
             );",
        )
        .unwrap();
        conn
    }

    #[test]
    fn missing_kind_errors() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let r = handle_check_agent_action(&conn, &json!({}));
        assert!(r.is_err());
    }

    #[test]
    fn bash_kind_allows_when_no_rule() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let r = handle_check_agent_action(&conn, &json!({"kind":"bash","command":"ls"})).unwrap();
        assert_eq!(r["decision"]["decision"], "allow");
    }

    #[test]
    fn filesystem_write_kind_refuses_on_glob() {
        // Issue #819 — suppress operator pubkey resolution for the
        // scope of this test so the unsigned R001 fixture below
        // enforces consistently regardless of dev-host / CI-runner
        // state (other tests in the same binary may have created
        // an operator.key.pub file at the platform config path).
        let _forensic = forensic_lock();
        let _no_pubkey = rules_store::force_no_operator_pubkey_for_test();
        let conn = fresh_conn();
        rules_store::insert(
            &conn,
            &Rule {
                id: "R001".into(),
                kind: "filesystem_write".into(),
                matcher: r#"{"glob":"/tmp/**"}"#.into(),
                severity: "refuse".into(),
                reason: "no /tmp".into(),
                namespace: "_global".into(),
                created_by: "test".into(),
                created_at: 0,
                enabled: true,
                signature: None,
                attest_level: "unsigned".into(),
            },
        )
        .unwrap();
        let r =
            handle_check_agent_action(&conn, &json!({"kind":"filesystem_write","path":"/tmp/foo"}))
                .unwrap();
        assert_eq!(r["decision"]["decision"], "refuse");
        assert_eq!(r["decision"]["rule_id"], "R001");
    }

    #[test]
    fn unknown_kind_errors() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let r = handle_check_agent_action(&conn, &json!({"kind":"nope"}));
        assert!(r.is_err());
    }

    #[test]
    fn missing_required_field_errors() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let r = handle_check_agent_action(&conn, &json!({"kind":"bash"}));
        assert!(r.is_err());
    }

    #[test]
    fn mutation_disabled_error_string_is_stable() {
        assert!(MCP_MUTATION_DISABLED_ERROR.starts_with("governance.not_available_over_mcp"));
    }

    // ─────────────────────────────────────────────────────────────────
    // Coverage C-2 — additional tests for the build_action branch
    // coverage and the agent_id default.

    // filesystem_write requires `path`.
    #[test]
    fn filesystem_write_missing_path_errors() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let err =
            handle_check_agent_action(&conn, &json!({"kind": "filesystem_write"})).unwrap_err();
        assert!(err.contains("path"), "got: {err}");
    }

    // filesystem_write happy path with optional byte_estimate.
    #[test]
    fn filesystem_write_with_byte_estimate_allows_when_no_rule() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let resp = handle_check_agent_action(
            &conn,
            &json!({
                "kind": "filesystem_write",
                "path": "/home/test/file.txt",
                "byte_estimate": 1024u64,
            }),
        )
        .expect("ok");
        assert_eq!(resp["decision"]["decision"], "allow");
    }

    // network_request happy path with default scheme.
    #[test]
    fn network_request_default_scheme_allows() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let resp = handle_check_agent_action(
            &conn,
            &json!({"kind": "network_request", "host": "example.com"}),
        )
        .expect("ok");
        assert_eq!(resp["decision"]["decision"], "allow");
    }

    // network_request with custom scheme.
    #[test]
    fn network_request_custom_scheme() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let resp = handle_check_agent_action(
            &conn,
            &json!({"kind": "network_request", "host": "host.local", "scheme": "ssh"}),
        )
        .expect("ok");
        assert_eq!(resp["decision"]["decision"], "allow");
    }

    // network_request missing host → error.
    #[test]
    fn network_request_missing_host_errors() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let err =
            handle_check_agent_action(&conn, &json!({"kind": "network_request"})).unwrap_err();
        assert!(err.contains("host"), "got: {err}");
    }

    // process_spawn happy path with no args.
    #[test]
    fn process_spawn_no_args_allows() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let resp = handle_check_agent_action(
            &conn,
            &json!({"kind": "process_spawn", "binary": "/usr/bin/ls"}),
        )
        .expect("ok");
        assert_eq!(resp["decision"]["decision"], "allow");
    }

    // process_spawn with args array.
    #[test]
    fn process_spawn_with_args() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let resp = handle_check_agent_action(
            &conn,
            &json!({
                "kind": "process_spawn",
                "binary": "/bin/echo",
                "args": ["hello", "world"],
            }),
        )
        .expect("ok");
        assert_eq!(resp["decision"]["decision"], "allow");
    }

    // process_spawn missing binary → error.
    #[test]
    fn process_spawn_missing_binary_errors() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let err = handle_check_agent_action(&conn, &json!({"kind": "process_spawn"})).unwrap_err();
        assert!(err.contains("binary"), "got: {err}");
    }

    // custom kind with custom_kind field.
    #[test]
    fn custom_kind_allows() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let resp = handle_check_agent_action(
            &conn,
            &json!({"kind": "custom", "custom_kind": "my-custom-action"}),
        )
        .expect("ok");
        assert_eq!(resp["decision"]["decision"], "allow");
    }

    // custom kind missing custom_kind → error.
    #[test]
    fn custom_kind_missing_custom_kind_errors() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let err = handle_check_agent_action(&conn, &json!({"kind": "custom"})).unwrap_err();
        assert!(err.contains("custom_kind"), "got: {err}");
    }

    // custom kind with `kind_inner` alias.
    #[test]
    fn custom_kind_kind_inner_alias() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let resp = handle_check_agent_action(
            &conn,
            &json!({"kind": "custom", "kind_inner": "alias-action"}),
        )
        .expect("ok");
        assert_eq!(resp["decision"]["decision"], "allow");
    }

    // Bash with cwd specified.
    #[test]
    fn bash_with_cwd_allows() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let resp = handle_check_agent_action(
            &conn,
            &json!({"kind": "bash", "command": "pwd", "cwd": "/tmp"}),
        )
        .expect("ok");
        assert_eq!(resp["decision"]["decision"], "allow");
    }

    // Agent_id provided in arguments — echoed in response.
    #[test]
    fn agent_id_echoed_in_response() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let resp = handle_check_agent_action(
            &conn,
            &json!({
                "kind": "bash",
                "command": "ls",
                "agent_id": "ai:alice",
            }),
        )
        .expect("ok");
        assert_eq!(resp["agent_id"].as_str(), Some("ai:alice"));
    }

    // Default agent_id ("anonymous:mcp") used when omitted.
    #[test]
    fn default_agent_id_when_omitted() {
        let _forensic = forensic_lock();
        let conn = fresh_conn();
        let resp = handle_check_agent_action(&conn, &json!({"kind": "bash", "command": "ls"}))
            .expect("ok");
        assert_eq!(resp["agent_id"].as_str(), Some("anonymous:mcp"));
    }

    // Warn severity surfaces structured rule_id + reason. The bash
    // matcher uses the `command_regex` substring key.
    #[test]
    fn warn_severity_surfaces_rule_id() {
        // Issue #819 — suppress operator pubkey resolution.
        let _forensic = forensic_lock();
        let _no_pubkey = rules_store::force_no_operator_pubkey_for_test();
        let conn = fresh_conn();
        rules_store::insert(
            &conn,
            &Rule {
                id: "W001".into(),
                kind: "bash".into(),
                matcher: r#"{"command_regex":"warn-this"}"#.into(),
                severity: "warn".into(),
                reason: "warn reason".into(),
                namespace: "_global".into(),
                created_by: "test".into(),
                created_at: 0,
                enabled: true,
                signature: None,
                attest_level: "unsigned".into(),
            },
        )
        .unwrap();
        let resp = handle_check_agent_action(
            &conn,
            &json!({"kind": "bash", "command": "warn-this please"}),
        )
        .expect("ok");
        assert_eq!(resp["decision"]["decision"], "warn");
        assert_eq!(resp["decision"]["rule_id"], "W001");
    }

    // Process spawn refusal — assert structured rule_id surfaces.
    #[test]
    fn process_spawn_refuses_on_binary_match() {
        // Issue #819 — suppress operator pubkey resolution.
        let _forensic = forensic_lock();
        let _no_pubkey = rules_store::force_no_operator_pubkey_for_test();
        let conn = fresh_conn();
        rules_store::insert(
            &conn,
            &Rule {
                id: "P002".into(),
                kind: "process_spawn".into(),
                matcher: r#"{"binary":"/bin/forbidden"}"#.into(),
                severity: "refuse".into(),
                reason: "binary not allowed".into(),
                namespace: "_global".into(),
                created_by: "test".into(),
                created_at: 0,
                enabled: true,
                signature: None,
                attest_level: "unsigned".into(),
            },
        )
        .unwrap();
        let resp = handle_check_agent_action(
            &conn,
            &json!({"kind": "process_spawn", "binary": "/bin/forbidden"}),
        )
        .expect("ok");
        assert_eq!(resp["decision"]["decision"], "refuse");
        assert_eq!(resp["decision"]["rule_id"], "P002");
    }

    /// v0.7.0 #1023 + #1114 — `handle_check_agent_action` runtime
    /// behavior pin.
    ///
    /// Per #1023 the MCP entry point uses the un-cached
    /// `check_agent_action` (NOT `check_agent_action_cached`) by
    /// design because the operator-driven debugging path does not
    /// have the `ToolDispatchCtx`-borne RuleCache today. The hot-
    /// path governance hooks (storage `GOVERNANCE_PRE_WRITE` +
    /// wire_check `GOVERNANCE_PRE_ACTION`) DO consult the cache —
    /// those paths are pinned by
    /// `tests/rules_store_isolation_pin.rs::governance_hooks_capture_consultation_connection_at_install_time_1017`.
    ///
    /// The #1114 follow-up surfaced that the doc comment at
    /// `handle_check_agent_action` describes the cache-served hot
    /// path AND the un-cached operator path. The pin below uses a
    /// SHARED Connection for two sequential calls — semantics that
    /// would diverge if a future refactor split the substrate read
    /// across two connections without a cache layer. This is the
    /// structural-shape equivalent of the #1017
    /// hook-connection-reuse pin.
    #[test]
    fn handle_check_agent_action_uses_uncached_path_1114() {
        let body = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/mcp/tools/check_agent_action.rs"
        ))
        .expect("read self");

        // Structural pin 1: the handler must NOT have switched to
        // `check_agent_action_cached` without a documented cache
        // wiring through `ToolDispatchCtx`. If a future refactor
        // wires the cache through, the doc-comment above the
        // `check_agent_action(conn, ...)` call line must also flip
        // to call out the cache (so the documentation drift sweep
        // surfaces the change). For now, the un-cached path is the
        // documented v0.7.0 contract.
        let calls_uncached = body.contains("check_agent_action(conn, agent_id, action)");
        let calls_cached_no_doc =
            body.contains("check_agent_action_cached(conn, ") && !body.contains("operator-driven");
        assert!(
            calls_uncached || !calls_cached_no_doc,
            "#1023 + #1114: handle_check_agent_action must use the un-cached \
             check_agent_action path (operator-driven debug entry point) UNLESS \
             the cache wiring is documented above the call site. A silent flip \
             without doc-comment update fails this pin."
        );

        // Structural pin 2: the doc-comment block above the call
        // site must mention either the un-cached path's operator-
        // driven framing OR the cache-served hot path's hook-based
        // framing. A future refactor that removes the documentation
        // (without replacing it) surfaces here.
        assert!(
            body.contains("operator-driven") || body.contains("check_agent_action_cached"),
            "#1023 + #1114: the documentation block above the substrate \
             read must describe either the un-cached operator path or the \
             cache-served hook path — neither marker found"
        );
    }
}
