// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 wire-layer constants (#1558 batch 3).
//!
//! The MCP stdio transport speaks JSON-RPC 2.0; every version tag,
//! reserved error code, method name, and protocol-revision string the
//! dispatcher emits or matches on lives here as one named const. These
//! are wire-contract values — a drifted copy at one site silently
//! breaks interop with every MCP client, so scattering them as inline
//! literals is exactly the failure mode the #1558 campaign removes.
//!
//! Error codes are the JSON-RPC 2.0 spec's reserved range
//! (<https://www.jsonrpc.org/specification#error_object>).

/// The JSON-RPC protocol version tag carried in every request and
/// response envelope (`"jsonrpc": "2.0"`).
pub const VERSION: &str = "2.0";

/// Invalid JSON was received by the server (spec `-32700 Parse error`).
pub const PARSE_ERROR: i64 = -32700;

/// The JSON sent is not a valid Request object (spec `-32600 Invalid
/// Request`).
pub const INVALID_REQUEST: i64 = -32600;

/// The method does not exist / is not available (spec `-32601 Method
/// not found`). Also used for `tools/call` against an unknown or
/// not-loaded tool — the MCP-idiomatic mapping.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// Invalid method parameter(s) (spec `-32602 Invalid params`).
pub const INVALID_PARAMS: i64 = -32602;

/// Internal JSON-RPC error (spec `-32603 Internal error`). Used for
/// application refusals that are not a protocol violation, e.g. a
/// record-stop write fence on `tools/call`.
pub const INTERNAL_ERROR: i64 = -32603;

/// MCP protocol revisions this server implements end to end, NEWEST FIRST
/// (#6157). `initialize` echoes the client's requested `protocolVersion`
/// when it is a member and otherwise answers with the newest entry (the
/// spec's "respond with another version you support" downgrade); see
/// [`negotiate_protocol_revision`].
///
/// The list is deliberately truthful: a revision belongs here only after
/// every behavioural delta of that revision is implemented and tested.
/// `2025-03-26` is NOT listed because it makes JSON-RPC batch receipt a
/// MUST and adds the Streamable HTTP transport; the stdio loop parses one
/// request object per line and answers a JSON array with `-32700`, so
/// claiming it would advertise semantics the server does not implement.
/// `2025-06-18` and `2026-07-28` are likewise unaudited. The pin
/// `tests/mcp_protocol_revision_ssot_6157.rs` walks the whole repository
/// (clients, cookbooks, benches, docs, tests, scripts) and keeps every
/// `protocolVersion` it names inside this list.
pub const SUPPORTED_PROTOCOL_REVISIONS: &[&str] = &[NEWEST_PROTOCOL_REVISION];

/// The newest entry of [`SUPPORTED_PROTOCOL_REVISIONS`]: what a client that
/// asks for an unsupported (or no) revision is answered with. Keep this the
/// first element of the list.
pub const NEWEST_PROTOCOL_REVISION: &str = "2024-11-05";

/// Pre-#6157 name of [`NEWEST_PROTOCOL_REVISION`], public at v0.9.0. Kept
/// as a deprecated alias (the #1558 crate-root alias precedent) so
/// downstream callers keep compiling; it is the revision `initialize`
/// answers when the client asks for an unsupported or no revision.
#[deprecated(note = "use NEWEST_PROTOCOL_REVISION (#6157)")]
pub const PROTOCOL_REVISION: &str = NEWEST_PROTOCOL_REVISION;

/// Wire name of the `initialize` request param and result field that carries
/// the MCP revision.
pub const PROTOCOL_VERSION_FIELD: &str = "protocolVersion";

/// Longest slice of a client-supplied `protocolVersion` echoed into the
/// stderr diagnostic (the value is untrusted and rendered `{:?}`-escaped).
const DIAGNOSTIC_ECHO_MAX_CHARS: usize = 64;

/// Resolve the `protocolVersion` to answer an `initialize` with.
///
/// Returns `(revision, downgraded)`. A string `params.protocolVersion`
/// that is a member of [`SUPPORTED_PROTOCOL_REVISIONS`] is echoed with
/// `downgraded == false`. An unsupported, missing or non-string value
/// yields the newest supported revision with `downgraded == true`, so the
/// caller can emit a diagnostic. Total: it never fails and never panics
/// (fail closed to the newest revision the server really speaks).
#[must_use]
pub fn negotiate_protocol_revision(params: &serde_json::Value) -> (&'static str, bool) {
    match params
        .get(PROTOCOL_VERSION_FIELD)
        .and_then(serde_json::Value::as_str)
        .and_then(|asked| {
            SUPPORTED_PROTOCOL_REVISIONS
                .iter()
                .copied()
                .find(|r| *r == asked)
        }) {
        Some(supported) => (supported, false),
        None => (NEWEST_PROTOCOL_REVISION, true),
    }
}

/// The stderr line emitted when `initialize` downgrades the client
/// (#6157). Never carries more than [`DIAGNOSTIC_ECHO_MAX_CHARS`] of the
/// untrusted request value, `{:?}`-escaped.
#[must_use]
pub fn protocol_downgrade_diagnostic(params: &serde_json::Value, answered: &str) -> String {
    let asked = match params.get(PROTOCOL_VERSION_FIELD) {
        None => "<missing>".to_string(),
        Some(serde_json::Value::String(s)) => {
            let clipped: String = s.chars().take(DIAGNOSTIC_ECHO_MAX_CHARS).collect();
            format!("{clipped:?}")
        }
        Some(_) => "<non-string>".to_string(),
    };
    format!(
        "ai-memory: MCP initialize downgrade: client protocolVersion {asked} is not supported; responding with {answered} (supported: {SUPPORTED_PROTOCOL_REVISIONS:?})"
    )
}

/// `initialize` — MCP handshake; carries `clientInfo` + capabilities.
pub const METHOD_INITIALIZE: &str = "initialize";

/// `notifications/initialized` — post-handshake client notification.
pub const METHOD_NOTIFICATIONS_INITIALIZED: &str = "notifications/initialized";

/// `ping` — liveness probe.
pub const METHOD_PING: &str = "ping";

/// `tools/list` — tool-catalog enumeration.
pub const METHOD_TOOLS_LIST: &str = "tools/list";

/// `tools/call` — tool dispatch.
pub const METHOD_TOOLS_CALL: &str = "tools/call";

/// `prompts/list` — prompt-catalog enumeration.
pub const METHOD_PROMPTS_LIST: &str = "prompts/list";

/// `prompts/get` — prompt-content fetch.
pub const METHOD_PROMPTS_GET: &str = "prompts/get";

/// `resources/list` — resource-catalog enumeration (declared for
/// wire-shape completeness; the dispatcher currently has no resources
/// surface).
pub const METHOD_RESOURCES_LIST: &str = "resources/list";

/// `resources/read` — resource fetch (declared for wire-shape
/// completeness; see [`METHOD_RESOURCES_LIST`]).
pub const METHOD_RESOURCES_READ: &str = "resources/read";

#[cfg(test)]
mod tests_6157 {
    use super::*;

    /// #6157 round 2: `PROTOCOL_REVISION` was public at v0.9.0; the
    /// deprecated alias must keep compiling for downstream callers and
    /// must equal the revision `initialize` answers by default.
    #[test]
    #[allow(deprecated)]
    fn issue_6157_deprecated_protocol_revision_alias_is_the_negotiated_default() {
        let (answered, downgraded) = negotiate_protocol_revision(&serde_json::json!({}));
        assert!(downgraded, "a missing protocolVersion is a downgrade");
        assert_eq!(PROTOCOL_REVISION, answered);
        assert_eq!(PROTOCOL_REVISION, NEWEST_PROTOCOL_REVISION);
    }

    fn params_asking(asked: &str) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert(
            PROTOCOL_VERSION_FIELD.to_string(),
            serde_json::Value::String(asked.to_string()),
        );
        serde_json::Value::Object(map)
    }

    /// #6157 round 2: a 5000-char `protocolVersion` is clipped to exactly
    /// the first `DIAGNOSTIC_ECHO_MAX_CHARS` chars; nothing past the clip
    /// reaches stderr.
    #[test]
    fn issue_6157_downgrade_diagnostic_clips_long_value_to_first_64_chars() {
        const TOTAL_CHARS: usize = 5000;
        const TAIL_MARKER: &str = "TAIL6157";
        // Pin the literal: the test name, doc comment and changelog all
        // promise 64, so a changed const must fail here (round-3 code F4).
        assert_eq!(DIAGNOSTIC_ECHO_MAX_CHARS, 64);
        let head = "A".repeat(DIAGNOSTIC_ECHO_MAX_CHARS);
        let filler = "~".repeat(TOTAL_CHARS - DIAGNOSTIC_ECHO_MAX_CHARS - TAIL_MARKER.len());
        let asked = format!("{head}{TAIL_MARKER}{filler}");
        assert_eq!(asked.chars().count(), TOTAL_CHARS);

        let line = protocol_downgrade_diagnostic(&params_asking(&asked), NEWEST_PROTOCOL_REVISION);

        assert!(
            line.contains(&format!("protocolVersion \"{head}\" is not supported")),
            "the echo must be exactly the first {DIAGNOSTIC_ECHO_MAX_CHARS} chars: {line}"
        );
        assert!(
            !line.contains(TAIL_MARKER),
            "text past the clip leaked: {line}"
        );
        assert!(!line.contains('~'), "filler past the clip leaked: {line}");
    }

    /// #6157 round 2: terminal and bidi control characters in the untrusted
    /// value are escaped, so the diagnostic is one inert line.
    #[test]
    fn issue_6157_downgrade_diagnostic_escapes_control_and_bidi_chars() {
        let asked = "a\u{1b}[31mb\nc\rd\u{202e}e\0f\u{2028}g\u{2029}h\u{85}i\u{2066}j\u{2067}k\u{2068}l\u{2069}m";
        let line = protocol_downgrade_diagnostic(&params_asking(asked), NEWEST_PROTOCOL_REVISION);

        for raw in [
            '\u{1b}', '\n', '\r', '\u{202e}', '\0', '\u{2028}', '\u{2029}', '\u{85}', '\u{2066}',
            '\u{2067}', '\u{2068}', '\u{2069}',
        ] {
            assert!(
                !line.contains(raw),
                "raw {raw:?} reached the diagnostic: {line:?}"
            );
        }
        assert_eq!(
            line.lines().count(),
            1,
            "diagnostic must be one line: {line:?}"
        );
        for escaped in [
            r"\u{1b}",
            r"\n",
            r"\r",
            r"\u{202e}",
            r"\0",
            r"\u{2028}",
            r"\u{2029}",
            r"\u{85}",
            r"\u{2066}",
            r"\u{2067}",
            r"\u{2068}",
            r"\u{2069}",
        ] {
            assert!(line.contains(escaped), "missing escape {escaped}: {line}");
        }
    }

    /// #6536: a non-string `protocolVersion` (object, array) is never echoed:
    /// the diagnostic carries `<non-string>` in its place, so a client-sized
    /// value with U+2028 or bidi controls (which `serde_json` serialisation
    /// does not escape) cannot reach stderr. The line is the same, byte for
    /// byte, as the one for a scalar non-string, and stays short.
    #[test]
    fn issue_6536_downgrade_diagnostic_never_echoes_non_string_values() {
        const MARKER: &str = "NONSTRING6536";
        const MAX_BYTES: usize = 300;
        let big = format!("{MARKER}\u{2028}\u{202e}{}", "x".repeat(10_000));
        let diagnostic_for = |value: serde_json::Value| {
            let mut map = serde_json::Map::new();
            map.insert(PROTOCOL_VERSION_FIELD.to_string(), value);
            protocol_downgrade_diagnostic(&serde_json::Value::Object(map), NEWEST_PROTOCOL_REVISION)
        };
        let baseline = diagnostic_for(serde_json::Value::Bool(true));
        for value in [
            serde_json::json!({ "v": big.clone() }),
            serde_json::json!([big.clone()]),
        ] {
            let line = diagnostic_for(value);
            assert!(line.contains("<non-string>"), "no redaction: {line:?}");
            assert!(!line.contains(MARKER), "the value leaked: {line:?}");
            assert!(!line.contains('\u{2028}'), "raw U+2028 leaked: {line:?}");
            assert!(!line.contains('\u{202e}'), "raw U+202E leaked: {line:?}");
            assert!(line.len() < MAX_BYTES, "{} bytes: {line:?}", line.len());
            assert_eq!(
                line, baseline,
                "the redacted line must not depend on the value"
            );
        }
    }
}
