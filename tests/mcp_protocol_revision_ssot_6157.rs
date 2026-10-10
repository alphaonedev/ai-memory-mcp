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
/// - Gitignored local artefacts a developer or agent machine can hold but a
///   clean checkout never has (round 3, #6157 F2): `dist` and `build` (tsc and
///   packaging output, e.g. `clients/*-shim-ts/dist`), `.venv` and `venv`
///   (Python virtualenvs whose `site-packages` ship other SDKs' revision
///   strings), `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.ruff_cache`
///   (tool caches) and `worktrees` (sibling Claude Code worktrees under the
///   ignored `.claude/worktrees`, which can sit at an older base). `.claude`
///   itself is NOT excluded: `.claude/settings.json` is tracked. No tracked
///   directory carries any of these names (`git ls-files` check in the PR).
const EXCLUDED_DIRS: [&str; 16] = [
    ".git",
    "target",
    "node_modules",
    ".local-runs",
    ".codegraph",
    ".cloud-review",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "worktrees",
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

/// #6157 round 3 (code F2 / cloud F2): the walk must not read gitignored local
/// artefacts. Plants an old-revision `protocolVersion` line under every
/// directory name that is a build output, virtualenv, tool cache or sibling
/// agent worktree, plus one tracked-style file that must still be seen, and
/// asserts the walk returns only the latter. The scratch tree lives under the
/// repo's `.local-runs/` (project rule: never `/tmp`).
#[test]
fn issue_6157_walk_skips_gitignored_local_artefact_dirs() {
    const LOCAL_ARTEFACT_DIRS: [&str; 10] = [
        "dist",
        "build",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "worktrees",
        "node_modules",
    ];
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join(format!("ssot-6157-walk-{}", std::process::id()));
    let _ = fs::remove_dir_all(&scratch);
    let plant = r#"{"protocolVersion": "2025-03-26"}"#;
    for dir in LOCAL_ARTEFACT_DIRS {
        // Nested one level down: the exclusion applies at any depth.
        let nested = scratch.join("clients").join("shim").join(dir);
        fs::create_dir_all(&nested).expect("create planted dir");
        fs::write(nested.join("x.json"), plant).expect("plant json");
        fs::write(nested.join("x.md"), plant).expect("plant md");
    }
    let kept = scratch.join("docs");
    fs::create_dir_all(&kept).expect("create kept dir");
    fs::write(kept.join("kept.md"), plant).expect("plant kept");

    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    walk(&scratch, &mut files, &mut unreadable);
    let seen: Vec<String> = files
        .iter()
        .filter_map(|f| f.strip_prefix(&scratch).ok())
        .map(|p| p.display().to_string())
        .collect();
    let _ = fs::remove_dir_all(&scratch);

    assert!(unreadable.is_empty(), "unreadable: {unreadable:?}");
    assert_eq!(
        seen,
        vec!["docs/kept.md".to_string()],
        "the walk read gitignored local artefacts (or lost a tracked dir)"
    );
}

/// A fresh scratch tree under the repo's gitignored `.local-runs/` (project
/// rule: never `/tmp`). The walk is rooted at the scratch dir, so only the
/// `.gitignore` files a test copies into it apply there.
fn scratch_tree(tag: &str) -> PathBuf {
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join(format!("ssot-6157-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch).expect("create scratch tree");
    scratch
}

/// Write `body` at `scratch/rel`, creating parent directories.
fn plant(scratch: &Path, rel: &str, body: &str) {
    let path = scratch.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create plant parent");
    }
    fs::write(&path, body).expect("write plant");
}

/// Copy the repository's real `.gitignore` at `rel` (a tracked path) into the
/// scratch tree at the same relative path.
fn copy_gitignore(scratch: &Path, rel: &str) {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    let body = fs::read_to_string(&src).expect("read tracked .gitignore");
    plant(scratch, rel, &body);
}

/// Walk `scratch` and return the relative paths it collected, sorted, minus
/// the copied `.gitignore` files themselves.
fn walked(scratch: &Path) -> (Vec<String>, Vec<String>) {
    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    walk(scratch, &mut files, &mut unreadable);
    let mut seen: Vec<String> = files
        .iter()
        .filter_map(|f| f.strip_prefix(scratch).ok())
        .map(|p| p.display().to_string())
        .filter(|p| !p.ends_with(".gitignore"))
        .collect();
    seen.sort();
    (seen, unreadable)
}

const PLANT: &str = "{\"protocolVersion\": \"2099-01-01\"}\n";

/// #6521: the walk must honour the repository's `.gitignore` files, not a
/// hand-kept list of directory names. Every path below is gitignored by a
/// tracked `.gitignore` (round-3 code review probe `s2_plants.py`) and none
/// sits under a name the round-3 denylist knew; a developer or agent tree
/// can hold all of them while `git status` is clean.
#[test]
fn issue_6521_walk_skips_every_path_the_repository_gitignores() {
    const GITIGNORES: [&str; 5] = [
        ".gitignore",
        "clients/anthropic-shim-py/.gitignore",
        "sdk/python/.gitignore",
        "sdk/typescript/.gitignore",
        "infra/federation-lab/.gitignore",
    ];
    const IGNORED: [&str; 11] = [
        "clients/anthropic-shim-py/probe_shim.egg-info/PKG-INFO.json",
        "sdk/python/probe.egg-info/meta.json",
        "coverage/html/probe.html",
        "sdk/typescript/coverage/probe.json",
        ".local-runs-probe6157/probe.md",
        ".cargo-probe-target/package/probe.rs",
        "infra/federation-lab/run/probe.json",
        ".claude/probe6157/probe.md",
        "benchmarks/longmemeval/results/probe.json",
        ".agentic/probe.md",
        "sdk/python/env/probe.py",
    ];
    let scratch = scratch_tree("6521");
    for rel in GITIGNORES {
        copy_gitignore(&scratch, rel);
    }
    for rel in IGNORED {
        plant(&scratch, rel, PLANT);
    }
    plant(&scratch, "docs/kept.md", PLANT);
    // Negation: `.claude/*` is ignored but `!.claude/settings.json` is not.
    plant(&scratch, ".claude/settings.json", PLANT);
    let (seen, unreadable) = walked(&scratch);
    let _ = fs::remove_dir_all(&scratch);

    assert!(unreadable.is_empty(), "unreadable: {unreadable:?}");
    assert_eq!(
        seen,
        vec![
            ".claude/settings.json".to_string(),
            "docs/kept.md".to_string()
        ],
        "the walk read a gitignored path (false red on a clean tree) or lost a trackable one"
    );
}
