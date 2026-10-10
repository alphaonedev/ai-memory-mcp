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
//! `.toml`, ... included) are pinned too.
//!
//! #6521: the walk reads exactly the files git would not ignore. It parses
//! every `.gitignore` it meets plus `$GIT_DIR/info/exclude` (gitignore(5)
//! precedence: deeper files and later lines win, `!` re-includes) instead of
//! a hand-kept list of directory names, so a gitignored local artefact on a
//! developer or agent tree never turns the pin red and a trackable file is
//! never skipped. Beyond the ignore rules it skips only `.git` entries and
//! the root [`VENDOR_DIR`]. It does not consult `core.excludesFile` (a
//! per-user setting outside the repository).
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
/// The root directory holding the vendored upstream `paste` crate. The walk
/// skips it by exact root path, never by name at any depth.
const VENDOR_DIR: &str = "vendor";
/// #6522: every file the walk reaches is read except these binary formats,
/// which cannot carry a `protocolVersion` line and are not UTF-8 (matched
/// case-insensitively, skipped without reading). Any other file that is not
/// UTF-8 still fails the pin closed. The tracked tree holds one `.pdf` and
/// one `.jpg`; the rest are common binary artefacts a developer tree holds.
const BINARY_EXTENSIONS: [&str; 17] = [
    "png", "jpg", "jpeg", "gif", "ico", "webp", "pdf", "woff", "woff2", "ttf", "otf", "db",
    "sqlite", "gz", "tgz", "zip", "wasm",
];
/// macOS Finder metadata: binary, never tracked, and not gitignored by the
/// root `.gitignore` (only by the client shims' own files).
const BINARY_FILE_NAMES: [&str; 1] = [".DS_Store"];
/// This file documents the pattern and names example strings.
const SELF: &str = "tests/mcp_protocol_revision_ssot_6157.rs";
/// Lower bounds that prove the walk still reaches the tree (round 2 widened
/// it from four sub-trees to the repository root).
const MIN_FILES_WALKED: usize = 2000;
const MIN_PROTOCOL_VERSION_USES: usize = 40;

/// One parsed `.gitignore` line (#6521). Only the syntax the repository's
/// tracked `.gitignore` files use is supported; anything else (a backslash
/// escape) is reported as unreadable so the pin fails closed instead of
/// guessing what git would ignore.
struct IgnoreRule {
    /// Directory of the `.gitignore` relative to the walk root, `""` at the
    /// root, otherwise ending in `/`.
    base: String,
    pattern: String,
    negate: bool,
    dir_only: bool,
    /// A pattern with a `/` before its last character matches the path
    /// relative to `base`; one without matches the entry name at any depth.
    anchored: bool,
}

/// Parse one `.gitignore` line per gitignore(5). `Ok(None)` for blank lines
/// and comments.
fn parse_ignore_line(line: &str, base: &str) -> Result<Option<IgnoreRule>, String> {
    let line = line.trim_end_matches('\r').trim_end_matches(' ');
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    if line.contains('\\') {
        return Err(format!("unsupported .gitignore escape in {line:?}"));
    }
    let (negate, rest) = match line.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let (dir_only, rest) = match rest.strip_suffix('/') {
        Some(rest) => (true, rest),
        None => (false, rest),
    };
    let anchored = rest.contains('/');
    let pattern = rest.strip_prefix('/').unwrap_or(rest);
    if pattern.is_empty() {
        return Err(format!("empty .gitignore pattern in {line:?}"));
    }
    Ok(Some(IgnoreRule {
        base: base.to_string(),
        pattern: pattern.to_string(),
        negate,
        dir_only,
        anchored,
    }))
}

/// gitignore(5) glob: `*` and `?` never match `/`, `[...]` is a class (with
/// `!`/`^` negation and `a-z` ranges), a `**/` segment matches zero or more
/// directories and any other `**` matches everything. `None` on a malformed
/// class (fail closed).
fn glob(p: &[u8], s: &[u8]) -> Option<bool> {
    let Some(&c) = p.first() else {
        return Some(s.is_empty());
    };
    match c {
        b'*' if p.get(1) == Some(&b'*') => {
            let rest = &p[2..];
            if let Some(after) = rest.strip_prefix(b"/") {
                if glob(after, s)? {
                    return Some(true);
                }
                for (i, b) in s.iter().enumerate() {
                    if *b == b'/' && glob(after, &s[i + 1..])? {
                        return Some(true);
                    }
                }
                Some(false)
            } else {
                for i in 0..=s.len() {
                    if glob(rest, &s[i..])? {
                        return Some(true);
                    }
                }
                Some(false)
            }
        }
        b'*' => {
            for i in 0..=s.len() {
                if glob(&p[1..], &s[i..])? {
                    return Some(true);
                }
                if s.get(i) == Some(&b'/') {
                    break;
                }
            }
            Some(false)
        }
        b'?' => match s.first() {
            Some(&b) if b != b'/' => glob(&p[1..], &s[1..]),
            _ => Some(false),
        },
        b'[' => {
            let mut i = 1;
            let negated = matches!(p.get(1), Some(b'!' | b'^'));
            if negated {
                i += 1;
            }
            let start = i;
            let mut hit = false;
            let Some(&b) = s.first() else {
                return Some(false);
            };
            loop {
                let &cur = p.get(i)?;
                if cur == b']' && i > start {
                    break;
                }
                if p.get(i + 1) == Some(&b'-') && p.get(i + 2).is_some_and(|e| *e != b']') {
                    let &hi = p.get(i + 2)?;
                    hit |= (cur..=hi).contains(&b);
                    i += 3;
                } else {
                    hit |= cur == b;
                    i += 1;
                }
            }
            if hit != negated && b != b'/' {
                glob(&p[i + 1..], &s[1..])
            } else {
                Some(false)
            }
        }
        _ => match s.first() {
            Some(&b) if b == c => glob(&p[1..], &s[1..]),
            _ => Some(false),
        },
    }
}

/// Last matching rule wins (gitignore(5)); rules from deeper `.gitignore`
/// files come later in `rules`, so they override shallower ones. `Err` on a
/// pattern [`glob`] cannot evaluate.
fn is_ignored(rel: &str, is_dir: bool, rules: &[IgnoreRule]) -> Result<bool, String> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let mut ignored = false;
    for rule in rules {
        if rule.dir_only && !is_dir {
            continue;
        }
        let Some(below) = rel.strip_prefix(rule.base.as_str()) else {
            continue;
        };
        let subject = if rule.anchored { below } else { name };
        let matched = glob(rule.pattern.as_bytes(), subject.as_bytes())
            .ok_or_else(|| format!("malformed .gitignore class in {:?}", rule.pattern))?;
        if matched {
            ignored = !rule.negate;
        }
    }
    Ok(ignored)
}

/// Append the rules of the ignore file at `path` (if it exists) to `rules`.
/// A missing file adds nothing; any other failure is recorded in
/// `unreadable` so the pin fails closed.
fn load_ignore_file(
    path: &Path,
    base: &str,
    rules: &mut Vec<IgnoreRule>,
    unreadable: &mut Vec<String>,
) {
    let text = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            unreadable.push(format!("{}: symlink_metadata: {e}", path.display()));
            return;
        }
        Ok(meta) if !meta.file_type().is_file() => {
            unreadable.push(format!(
                "{}: ignore file is not a regular file",
                path.display()
            ));
            return;
        }
        Ok(_) => match fs::read(path).map(String::from_utf8) {
            Ok(Ok(text)) => text,
            Ok(Err(e)) => {
                unreadable.push(format!("{}: not UTF-8: {e}", path.display()));
                return;
            }
            Err(e) => {
                unreadable.push(format!("{}: read: {e}", path.display()));
                return;
            }
        },
    };
    for line in text.lines() {
        match parse_ignore_line(line, base) {
            Ok(Some(rule)) => rules.push(rule),
            Ok(None) => {}
            Err(e) => unreadable.push(format!("{}: {e}", path.display())),
        }
    }
}

/// The repository-local exclude file git also honours: `$GIT_DIR/info/exclude`,
/// following a worktree's `.git` file (`gitdir: ...`) and its `commondir`.
/// `None` when the root carries no `.git` (a scratch tree or a source
/// tarball).
fn info_exclude(root: &Path, unreadable: &mut Vec<String>) -> Option<PathBuf> {
    let dot_git = root.join(".git");
    let meta = fs::symlink_metadata(&dot_git).ok()?;
    if meta.is_dir() {
        return Some(dot_git.join("info").join("exclude"));
    }
    let text = match fs::read_to_string(&dot_git) {
        Ok(text) => text,
        Err(e) => {
            unreadable.push(format!("{}: read: {e}", dot_git.display()));
            return None;
        }
    };
    let Some(gitdir) = text.trim_end().strip_prefix("gitdir: ") else {
        unreadable.push(format!("{}: no `gitdir: ` line", dot_git.display()));
        return None;
    };
    let gitdir = root.join(gitdir);
    let common = match fs::read_to_string(gitdir.join("commondir")) {
        Ok(rel) => gitdir.join(rel.trim_end()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => gitdir,
        Err(e) => {
            unreadable.push(format!("{}: commondir: {e}", gitdir.display()));
            return None;
        }
    };
    Some(common.join("info").join("exclude"))
}

/// Collect every candidate file under `root` that git would not ignore.
/// Symlinks are never followed (`symlink_metadata`), and any directory that
/// cannot be listed, or ignore rule that cannot be evaluated, is recorded in
/// `unreadable` so the pin fails closed.
fn walk(root: &Path, out: &mut Vec<PathBuf>, unreadable: &mut Vec<String>) {
    let mut rules = Vec::new();
    if let Some(exclude) = info_exclude(root, unreadable) {
        load_ignore_file(&exclude, "", &mut rules, unreadable);
    }
    walk_dir(root, root, &mut rules, out, unreadable);
}

fn walk_dir(
    root: &Path,
    dir: &Path,
    rules: &mut Vec<IgnoreRule>,
    out: &mut Vec<PathBuf>,
    unreadable: &mut Vec<String>,
) {
    let depth = rules.len();
    let base = match dir.strip_prefix(root).map(|p| p.to_str()) {
        Ok(Some("")) => String::new(),
        Ok(Some(rel)) => format!("{rel}/"),
        _ => {
            unreadable.push(format!(
                "{}: path is not UTF-8 below the root",
                dir.display()
            ));
            return;
        }
    };
    load_ignore_file(&dir.join(".gitignore"), &base, rules, unreadable);
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            unreadable.push(format!("{}: read_dir: {e}", dir.display()));
            rules.truncate(depth);
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
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            unreadable.push(format!("{}: file name is not UTF-8", path.display()));
            continue;
        };
        // git never tracks a `.git` entry (object store, or a nested
        // checkout's gitdir file), and the vendored upstream `paste` crate
        // under the root `vendor/` carries no MCP code and cannot be fixed
        // in-tree. Both are matched exactly, never by name elsewhere.
        if name == ".git" || (base.is_empty() && name == VENDOR_DIR) {
            continue;
        }
        let rel = format!("{base}{name}");
        match is_ignored(&rel, file_type.is_dir(), rules) {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => {
                unreadable.push(format!("{rel}: {e}"));
                continue;
            }
        }
        if file_type.is_dir() {
            walk_dir(root, &path, rules, out, unreadable);
        } else if file_type.is_file() && !is_binary(name) {
            out.push(path);
        }
    }
    rules.truncate(depth);
}

/// A file the walk skips without reading (#6522): a known binary name or
/// extension.
fn is_binary(name: &str) -> bool {
    BINARY_FILE_NAMES.contains(&name)
        || name.rsplit_once('.').is_some_and(|(_, ext)| {
            BINARY_EXTENSIONS
                .iter()
                .any(|b| b.eq_ignore_ascii_case(ext))
        })
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

/// #6522: the walk must read every trackable text file, not a 14-extension
/// allowlist. Each plant mirrors a tracked file type the allowlist skipped
/// (`requirements.txt`, a `.jsonl` scenario set, a `Dockerfile`, a `.sql`
/// bootstrap, a golden `.out`); all must be collected. A known binary type
/// (`.pdf`, `.jpg`) is skipped without being read.
#[test]
fn issue_6522_walk_reads_every_trackable_text_file_type() {
    const KEPT: [&str; 6] = [
        "Dockerfile",
        "benchmarks/longmemeval/requirements.txt",
        "benchmarks/longmemeval_reflection/data/scenarios.jsonl",
        "deploy/hive-1461/provision/pg-age/bootstrap.sql",
        "deploy/zz/Dockerfile",
        "tests/golden/probe.out",
    ];
    let scratch = scratch_tree("6522");
    copy_gitignore(&scratch, ".gitignore");
    for rel in KEPT {
        plant(&scratch, rel, PLANT);
    }
    plant(&scratch, "docs/logo.jpg", "");
    fs::write(scratch.join("docs/logo.jpg"), [0xff_u8, 0xd8, 0xff, 0xe0]).expect("plant jpg");
    let (seen, unreadable) = walked(&scratch);
    let _ = fs::remove_dir_all(&scratch);

    assert!(unreadable.is_empty(), "unreadable: {unreadable:?}");
    let mut want: Vec<String> = KEPT.iter().map(ToString::to_string).collect();
    want.sort();
    assert_eq!(
        seen, want,
        "the walk skipped a trackable text file type (false green)"
    );
}
