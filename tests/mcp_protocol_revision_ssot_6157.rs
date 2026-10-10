// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6157 SSOT pin: every MCP revision string (`20xx-xx-xx`) that a test,
//! script, source file or doc uses AS a `protocolVersion` must be a member
//! of `ai_memory::mcp::jsonrpc::SUPPORTED_PROTOCOL_REVISIONS`.
//!
//! The pre-fix tree hard-coded `2024-11-05` in 21 files with nothing tying
//! them to the server's real answer; a revision bump would have drifted
//! silently. This walk closes that: a new fixture or doc that names a
//! revision the server does not honour fails here.
//!
//! A "protocolVersion use" is a line that names `protocolVersion`,
//! `Protocol version`, or `speaks MCP` AND carries a date-shaped token.
//! Prose that merely cites a spec revision for its tool-result convention
//! (for example "MCP 2025-03-26 puts malformed request STRUCTURE ...")
//! names none of those markers and is deliberately out of the pin.

use std::fs;
use std::path::{Path, PathBuf};

use ai_memory::mcp::jsonrpc::{SUPPORTED_PROTOCOL_REVISIONS, negotiate_protocol_revision};
use serde_json::json;

const MARKERS: [&str; 3] = ["protocolVersion", "Protocol version", "speaks MCP"];
const ROOTS: [&str; 4] = ["tests", "src", "docs", "scripts"];
const EXTENSIONS: [&str; 6] = ["rs", "md", "html", "sh", "py", "json"];
/// This file documents the pattern and names example strings.
const SELF: &str = "tests/mcp_protocol_revision_ssot_6157.rs";

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| EXTENSIONS.contains(&e))
        {
            out.push(path);
        }
    }
}

/// Every `20dd-dd-dd` token on `line`.
fn dates(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i + 10 <= bytes.len() {
        let w = &bytes[i..i + 10];
        let shaped = w[0] == b'2'
            && w[1] == b'0'
            && w[2].is_ascii_digit()
            && w[3].is_ascii_digit()
            && w[4] == b'-'
            && w[5].is_ascii_digit()
            && w[6].is_ascii_digit()
            && w[7] == b'-'
            && w[8].is_ascii_digit()
            && w[9].is_ascii_digit();
        let bounded_left = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        let bounded_right = i + 10 == bytes.len() || !bytes[i + 10].is_ascii_alphanumeric();
        if shaped && bounded_left && bounded_right {
            // ASCII-only window, so the slice is on char boundaries.
            if let Some(token) = line.get(i..i + 10) {
                found.push(token);
            }
            i += 10;
        } else {
            i += 1;
        }
    }
    found
}

#[test]
fn issue_6157_every_protocol_version_use_is_a_supported_revision() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for sub in ROOTS {
        walk(&root.join(sub), &mut files);
    }
    assert!(files.len() > 100, "walk found only {} files", files.len());
    let mut offenders = Vec::new();
    let mut uses = 0usize;
    for file in &files {
        let rel = file.strip_prefix(root).unwrap_or(file);
        if rel == Path::new(SELF) {
            continue;
        }
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            if !MARKERS.iter().any(|m| line.contains(m)) {
                continue;
            }
            for date in dates(line) {
                uses += 1;
                if !SUPPORTED_PROTOCOL_REVISIONS.contains(&date) {
                    offenders.push(format!("{}:{}: {date}", rel.display(), n + 1));
                }
            }
        }
    }
    assert!(
        uses >= 15,
        "pin matched only {uses} protocolVersion uses; the walk is broken"
    );
    assert!(
        offenders.is_empty(),
        "protocolVersion uses outside SUPPORTED_PROTOCOL_REVISIONS {SUPPORTED_PROTOCOL_REVISIONS:?}:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn issue_6157_supported_list_is_well_formed_newest_first() {
    assert!(!SUPPORTED_PROTOCOL_REVISIONS.is_empty());
    for rev in SUPPORTED_PROTOCOL_REVISIONS {
        assert_eq!(
            dates(rev),
            vec![*rev],
            "{rev:?} is not a 20xx-xx-xx revision"
        );
    }
    // ISO dates order lexicographically; the list is newest first, strictly.
    for pair in SUPPORTED_PROTOCOL_REVISIONS.windows(2) {
        assert!(
            pair[0] > pair[1],
            "list must be strictly newest-first: {pair:?}"
        );
    }
    // The revision this server has always spoken stays supported.
    assert!(SUPPORTED_PROTOCOL_REVISIONS.contains(&"2024-11-05"));
}

#[test]
fn issue_6157_negotiate_echoes_supported_and_downgrades_everything_else() {
    let newest = SUPPORTED_PROTOCOL_REVISIONS[0];
    for rev in SUPPORTED_PROTOCOL_REVISIONS {
        assert_eq!(
            negotiate_protocol_revision(&json!({"protocolVersion": rev})),
            (*rev, false)
        );
    }
    for params in [
        json!({"protocolVersion": "1999-01-01"}),
        json!({"protocolVersion": ""}),
        json!({"capabilities": {}}),
        json!({"protocolVersion": null}),
        json!({"protocolVersion": 20_241_105}),
        json!({"protocolVersion": ["2024-11-05"]}),
        json!(null),
        json!("2024-11-05"),
    ] {
        assert_eq!(
            negotiate_protocol_revision(&params),
            (newest, true),
            "params {params}"
        );
    }
}
