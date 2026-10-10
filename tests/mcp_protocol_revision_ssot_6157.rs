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
//!
//! Round 2 (#6157 review F1-F3): the walk starts at the repository root, so
//! first-party clients, cookbooks, benches and SDKs (`.ts`, `.mjs`, `.js`,
//! `.toml`, ... included) are pinned too, minus the [`EXCLUDED_DIRS`] below.
//! It never follows a symlink, and a directory or file it cannot read, or a
//! file that is not UTF-8, FAILS the pin instead of being skipped: a pin that
//! cannot see a file must not report it clean.

use std::fs;
use std::path::{Path, PathBuf};

use ai_memory::mcp::jsonrpc::{
    NEWEST_PROTOCOL_REVISION, SUPPORTED_PROTOCOL_REVISIONS, negotiate_protocol_revision,
};
use serde_json::json;

const MARKERS: [&str; 3] = ["protocolVersion", "Protocol version", "speaks MCP"];
/// Directory names the walk never enters, at any depth. Each is either not
/// first-party source or not part of the tree:
/// - `.git`: object store; `target`: cargo output; `node_modules`: npm
///   installs under `clients/*`; `.local-runs`: agent scratch (repo rule);
///   `.codegraph`: local symbol index; `.cloud-review`: review sandbox output.
/// - `vendor`: the vendored upstream `paste` crate; a hit there could not be
///   fixed in-tree, and it carries no MCP code.
const EXCLUDED_DIRS: [&str; 7] = [
    ".git",
    "target",
    "node_modules",
    ".local-runs",
    ".codegraph",
    ".cloud-review",
    "vendor",
];
const EXTENSIONS: [&str; 14] = [
    "rs", "md", "html", "sh", "py", "json", "ts", "tsx", "mjs", "cjs", "js", "toml", "yml", "yaml",
];
/// This file documents the pattern and names example strings.
const SELF: &str = "tests/mcp_protocol_revision_ssot_6157.rs";
/// Lower bounds that prove the walk still reaches the tree (round 2 widened
/// it from four sub-trees to the repository root).
const MIN_FILES_WALKED: usize = 2000;
const MIN_PROTOCOL_VERSION_USES: usize = 40;

/// Collect every candidate file under `dir`. Symlinks are never followed
/// (`symlink_metadata`), and any directory that cannot be listed is recorded
/// in `unreadable` so the pin fails closed.
fn walk(dir: &Path, out: &mut Vec<PathBuf>, unreadable: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            unreadable.push(format!("{}: read_dir: {e}", dir.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                unreadable.push(format!("{}: dir entry: {e}", dir.display()));
                continue;
            }
        };
        let path = entry.path();
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) => {
                unreadable.push(format!("{}: symlink_metadata: {e}", path.display()));
                continue;
            }
        };
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            let excluded = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| EXCLUDED_DIRS.contains(&n));
            if !excluded {
                walk(&path, out, unreadable);
            }
        } else if file_type.is_file()
            && path
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
    let mut unreadable = Vec::new();
    walk(root, &mut files, &mut unreadable);
    assert!(
        files.len() >= MIN_FILES_WALKED,
        "walk found only {} files",
        files.len()
    );
    let mut offenders = Vec::new();
    let mut uses = 0usize;
    for file in &files {
        let rel = file.strip_prefix(root).unwrap_or(file);
        if rel == Path::new(SELF) {
            continue;
        }
        let text = match fs::read(file).map(String::from_utf8) {
            Ok(Ok(text)) => text,
            Ok(Err(e)) => {
                unreadable.push(format!("{}: not UTF-8: {e}", rel.display()));
                continue;
            }
            Err(e) => {
                unreadable.push(format!("{}: read: {e}", rel.display()));
                continue;
            }
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
        unreadable.is_empty(),
        "the pin cannot see these paths, so it cannot vouch for them:\n{}",
        unreadable.join("\n")
    );
    assert!(
        uses >= MIN_PROTOCOL_VERSION_USES,
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
    assert_eq!(SUPPORTED_PROTOCOL_REVISIONS[0], NEWEST_PROTOCOL_REVISION);
    // The revision this server has always spoken stays supported.
    assert!(SUPPORTED_PROTOCOL_REVISIONS.contains(&"2024-11-05"));
}

#[test]
fn issue_6157_negotiate_echoes_supported_and_downgrades_everything_else() {
    let newest = NEWEST_PROTOCOL_REVISION;
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
