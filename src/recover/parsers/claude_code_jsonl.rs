// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Claude Code transcript-JSONL parser. The transcript file is one
//! JSON object per line; each object carries at least `timestamp`
//! (ISO-8601 Z) and `type` (`user` / `assistant` / `tool_use` /
//! `tool_result` / etc.) plus type-specific payload fields.
//!
//! This parser swallows per-line errors (a malformed line is a
//! warning, not a fatal); the partial result is what
//! `recover_from_transcript` writes. See the v0.7.0 #1389
//! implementation slice §C2 for the verbatim line-shape reference
//! and the surviving `f755c061-...jsonl` example dossier path.

use crate::models::field_names;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{ParseError, ParsedTurn, ToolCallSummary, TranscriptParser, TurnRole};

/// Zero-sized parser implementing [`TranscriptParser`] for the
/// Claude Code transcript format.
pub struct ClaudeCodeJsonlParser;

impl TranscriptParser for ClaudeCodeJsonlParser {
    fn parse(&self, path: &Path, since_iso: Option<&str>) -> Result<Vec<ParsedTurn>, ParseError> {
        let f = File::open(path).map_err(|e| ParseError::Read(e.to_string()))?;
        let reader = BufReader::new(f);
        let mut turns = Vec::new();

        for line_res in reader.lines() {
            let Ok(line) = line_res else {
                // Per the parser-trait contract, we swallow read
                // errors and continue. SessionStart-hook integration
                // can't tolerate a single bad line wedging recovery.
                continue;
            };
            if line.trim().is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let Some(parsed) = parse_one_turn(&v, &line) else {
                continue;
            };
            if let Some(filter) = since_iso {
                if parsed.timestamp_iso.as_str() < filter {
                    continue;
                }
            }
            turns.push(parsed);
        }

        Ok(turns)
    }
}

/// Parse one JSONL line into a [`ParsedTurn`]. Returns `None` for
/// line shapes we don't recognize (e.g., `permission-mode` toggles,
/// `last-prompt` sentinels). The dedup-sha is computed from the
/// verbatim line content so cross-version line-shape drift doesn't
/// re-atomise already-stored turns.
fn parse_one_turn(v: &Value, raw_line: &str) -> Option<ParsedTurn> {
    let timestamp_iso = v.get("timestamp")?.as_str()?.to_string();
    let type_tag = v.get("type")?.as_str()?;
    let role = match type_tag {
        "user" => TurnRole::User,
        "assistant" => TurnRole::Assistant,
        "tool_use" => TurnRole::ToolUse,
        "tool_result" => TurnRole::ToolResult,
        _ => TurnRole::Other,
    };

    let mut content_text = String::new();
    let mut tool_calls = Vec::new();

    // Claude Code transcripts carry the user/assistant text under
    // `message.content`; that field is either a string (legacy) or
    // an array of typed blocks (current).
    if let Some(msg) = v.get("message") {
        let content = msg.get("content");
        match content {
            Some(Value::String(s)) => content_text.push_str(s),
            Some(Value::Array(blocks)) => {
                for b in blocks {
                    if let Some(t) = b.get("type").and_then(Value::as_str) {
                        match t {
                            "text" => {
                                if let Some(s) = b.get("text").and_then(Value::as_str) {
                                    if !content_text.is_empty() {
                                        content_text.push('\n');
                                    }
                                    content_text.push_str(s);
                                }
                            }
                            "tool_use" => {
                                let tool = b
                                    .get("name")
                                    .and_then(Value::as_str)
                                    .unwrap_or("?")
                                    .to_string();
                                let brief = tool_use_brief(b);
                                tool_calls.push(ToolCallSummary { tool, brief });
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Some line shapes (esp. user-side wrapper events for
    // tool_result) carry text directly under top-level `content`.
    if content_text.is_empty() {
        if let Some(s) = v.get("content").and_then(Value::as_str) {
            content_text.push_str(s);
        }
    }

    // If we have neither text nor tool calls, the line is not
    // recovery-worthy (typically `last-prompt` or `permission-mode`
    // sentinels). Return None to skip.
    if content_text.is_empty() && tool_calls.is_empty() {
        return None;
    }

    let line_sha256_hex = sha256_hex(raw_line);

    // #1573 — surface the host session identifier so the dedup layer
    // can key on `(host_session_id, host_turn_index)` when available.
    // Claude Code JSONL carries `sessionId` per line but NO numeric
    // turn counter, so `host_turn_index` stays `None` here (a line
    // ordinal is not a substitute — see the `ParsedTurn` field doc).
    let host_session_id = v
        .get("sessionId")
        .and_then(Value::as_str)
        .map(ToString::to_string);

    Some(ParsedTurn {
        timestamp_iso,
        role,
        content_text,
        tool_calls,
        line_sha256_hex,
        host_session_id,
        host_turn_index: None,
    })
}

/// Best-effort one-line brief for a tool-use payload. Picks the
/// most informative field (`description` / `command` / `file_path`
/// / first arg key) and truncates to 200 chars.
fn tool_use_brief(b: &Value) -> String {
    let input = b.get("input");
    let pick = |key: &str| -> Option<String> {
        input
            .and_then(|i| i.get(key))
            .and_then(Value::as_str)
            .map(ToString::to_string)
    };
    let brief = pick(field_names::DESCRIPTION)
        .or_else(|| pick("command"))
        .or_else(|| pick("file_path"))
        .or_else(|| pick("query"))
        .or_else(|| {
            input
                .and_then(Value::as_object)
                .and_then(|m| m.iter().next().map(|(k, v)| format!("{k}={v}")))
        })
        .unwrap_or_default();
    truncate(&brief, 200)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut out = s.chars().take(max).collect::<String>();
        out.push('…');
        out
    }
}

fn sha256_hex(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parses_typed_user_text_block() {
        let line = r#"{"timestamp":"2026-05-28T12:00:00Z","type":"user","message":{"content":[{"type":"text","text":"hello"}]}}"#;
        let v: Value = serde_json::from_str(line).unwrap();
        let p = parse_one_turn(&v, line).unwrap();
        assert_eq!(p.role, TurnRole::User);
        assert_eq!(p.content_text, "hello");
        assert_eq!(p.timestamp_iso, "2026-05-28T12:00:00Z");
        assert!(p.tool_calls.is_empty());
        assert_eq!(p.line_sha256_hex.len(), 64);
    }

    #[test]
    fn parses_assistant_with_tool_use_blocks() {
        let line = r#"{"timestamp":"2026-05-28T12:01:00Z","type":"assistant","message":{"content":[{"type":"text","text":"running command"},{"type":"tool_use","name":"Bash","input":{"command":"ls","description":"list files"}}]}}"#;
        let v: Value = serde_json::from_str(line).unwrap();
        let p = parse_one_turn(&v, line).unwrap();
        assert_eq!(p.role, TurnRole::Assistant);
        assert_eq!(p.content_text, "running command");
        assert_eq!(p.tool_calls.len(), 1);
        assert_eq!(p.tool_calls[0].tool, "Bash");
        assert_eq!(p.tool_calls[0].brief, "list files");
    }

    #[test]
    fn skips_sentinel_lines() {
        // The `last-prompt` and `permission-mode` lines have neither
        // text content nor tool_use blocks; recovery should skip
        // them.
        let line = r#"{"type":"last-prompt"}"#;
        let v: Value = serde_json::from_str(line).unwrap();
        assert!(parse_one_turn(&v, line).is_none());
    }

    #[test]
    fn since_filter_excludes_earlier_lines() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"2026-05-28T10:00:00Z","type":"user","message":{{"content":"a"}}}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"2026-05-28T12:00:00Z","type":"user","message":{{"content":"b"}}}}"#
        )
        .unwrap();
        let parser = ClaudeCodeJsonlParser;
        let turns = parser
            .parse(f.path(), Some("2026-05-28T11:00:00Z"))
            .unwrap();
        assert_eq!(turns.len(), 1);
        assert_eq!(turns[0].content_text, "b");
    }

    #[test]
    fn sha256_dedup_is_stable_for_same_line() {
        let s = r#"{"timestamp":"2026-05-28T12:00:00Z","type":"user","message":{"content":"x"}}"#;
        let a = sha256_hex(s);
        let b = sha256_hex(s);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    // Coverage uplift (2026-06-12): per-line skip branches, the
    // tool_use_brief field-picking ladder, the truncate over-max arm,
    // and the parse()-level malformed-line tolerance.

    #[test]
    fn parse_one_turn_requires_timestamp_and_type() {
        let v: Value = serde_json::from_str(r#"{"type":"user"}"#).unwrap();
        assert!(parse_one_turn(&v, "{}").is_none());
        let v2: Value = serde_json::from_str(r#"{"timestamp":"2026-05-28T12:00:00Z"}"#).unwrap();
        assert!(parse_one_turn(&v2, "{}").is_none());
    }

    #[test]
    fn parse_one_turn_classifies_tool_roles_and_other() {
        for (tag, want) in [
            ("tool_use", TurnRole::ToolUse),
            ("tool_result", TurnRole::ToolResult),
            ("system", TurnRole::Other),
        ] {
            let line = format!(
                r#"{{"timestamp":"2026-05-28T12:00:00Z","type":"{tag}","message":{{"content":"body"}}}}"#
            );
            let v: Value = serde_json::from_str(&line).unwrap();
            let p = parse_one_turn(&v, &line).unwrap();
            assert_eq!(p.role, want, "tag {tag}");
        }
    }

    #[test]
    fn parse_one_turn_legacy_string_content_and_top_level_content() {
        let line = r#"{"timestamp":"2026-05-28T12:00:00Z","type":"user","message":{"content":"legacy string"}}"#;
        let v: Value = serde_json::from_str(line).unwrap();
        assert_eq!(
            parse_one_turn(&v, line).unwrap().content_text,
            "legacy string"
        );

        let line2 = r#"{"timestamp":"2026-05-28T12:00:00Z","type":"tool_result","content":"top level body"}"#;
        let v2: Value = serde_json::from_str(line2).unwrap();
        assert_eq!(
            parse_one_turn(&v2, line2).unwrap().content_text,
            "top level body"
        );
    }

    #[test]
    fn parse_one_turn_captures_session_id() {
        let line = r#"{"timestamp":"2026-05-28T12:00:00Z","type":"user","sessionId":"sess-xyz","message":{"content":"hi"}}"#;
        let v: Value = serde_json::from_str(line).unwrap();
        let p = parse_one_turn(&v, line).unwrap();
        assert_eq!(p.host_session_id.as_deref(), Some("sess-xyz"));
        assert!(p.host_turn_index.is_none());
    }

    #[test]
    fn tool_use_brief_field_picking_ladder() {
        let b = serde_json::json!({"name":"X","input":{"description":"d","command":"c"}});
        assert_eq!(tool_use_brief(&b), "d");
        let b = serde_json::json!({"name":"X","input":{"command":"ls -la"}});
        assert_eq!(tool_use_brief(&b), "ls -la");
        let b = serde_json::json!({"name":"Read","input":{"file_path":"/a/b.rs"}});
        assert_eq!(tool_use_brief(&b), "/a/b.rs");
        let b = serde_json::json!({"name":"Search","input":{"query":"needle"}});
        assert_eq!(tool_use_brief(&b), "needle");
        let b = serde_json::json!({"name":"Z","input":{"weird":"value"}});
        assert_eq!(tool_use_brief(&b), "weird=\"value\"");
        let b = serde_json::json!({"name":"Z"});
        assert_eq!(tool_use_brief(&b), "");
    }

    #[test]
    fn truncate_appends_ellipsis_over_max() {
        assert_eq!(truncate("abc", 200), "abc");
        let long: String = "x".repeat(250);
        let out = truncate(&long, 200);
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), 201);
    }

    #[test]
    fn parse_skips_blank_and_malformed_lines_but_keeps_good_ones() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f).unwrap();
        writeln!(f, "not json at all").unwrap();
        writeln!(f, r#"{{"type":"last-prompt"}}"#).unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"2026-05-28T12:00:00Z","type":"user","message":{{"content":"good"}}}}"#
        )
        .unwrap();
        f.flush().unwrap();
        let turns = ClaudeCodeJsonlParser.parse(f.path(), None).unwrap();
        assert_eq!(turns.len(), 1, "only the well-formed content turn survives");
        assert_eq!(turns[0].content_text, "good");
    }

    #[test]
    fn parse_open_error_surfaces_read_error() {
        let missing = std::path::Path::new("/nonexistent/dir/does-not-exist.jsonl");
        let err = ClaudeCodeJsonlParser.parse(missing, None).unwrap_err();
        assert!(matches!(err, ParseError::Read(_)));
    }
}
