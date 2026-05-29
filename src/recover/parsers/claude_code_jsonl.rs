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

    Some(ParsedTurn {
        timestamp_iso,
        role,
        content_text,
        tool_calls,
        line_sha256_hex,
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
    let brief = pick("description")
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
}
