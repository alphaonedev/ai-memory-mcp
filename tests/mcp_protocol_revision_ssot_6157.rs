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
//! A "protocolVersion use" is a date-shaped token on a line that names
//! `protocolVersion`, `Protocol version`, or `speaks MCP`, or (#6535), when
//! that line carries no date, on the next line holding a letter or digit
//! (a value split from its key by pretty-printing).
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
//! The matcher follows git where the two could differ (#7017): a run of
//! asterisks is `**` only as a whole path segment, a POSIX bracket class
//! fails closed, and `core.ignorecase` folds ASCII case.
//! It never follows a symlink, and a directory or file it cannot read, or a
//! file that is not UTF-8, FAILS the pin instead of being skipped: a pin that
//! cannot see a file must not report it clean.

use std::collections::BTreeSet;
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

/// What git knows that the ignore files alone cannot say (#7008, #7017).
/// A scratch tree or a source export carries no `.git`, so it gets the
/// default: nothing tracked, `core.ignorecase` off.
#[derive(Default)]
struct Env {
    /// Every tracked file, relative to the walk root. git applies no ignore
    /// rule to a tracked path.
    tracked: BTreeSet<String>,
    /// Every directory that holds a tracked file, so an ignored directory
    /// that carries one is still entered.
    tracked_dirs: BTreeSet<String>,
    /// `core.ignorecase`: ignore patterns then match with ASCII case folded.
    ignore_case: bool,
}

impl Env {
    /// An [`Env`] for the tracked `paths` (relative, `/`-separated).
    fn from_tracked<'a>(paths: impl IntoIterator<Item = &'a str>, ignore_case: bool) -> Self {
        let mut env = Env {
            ignore_case,
            ..Env::default()
        };
        for path in paths {
            env.tracked.insert(path.to_string());
            let mut dir = path;
            while let Some((parent, _)) = dir.rsplit_once('/') {
                env.tracked_dirs.insert(parent.to_string());
                dir = parent;
            }
        }
        env
    }
}

/// One parsed `.gitignore` line (#6521). Only the syntax the repository's
/// tracked `.gitignore` files use is supported; what is not (a backslash
/// escape, an empty pattern, a POSIX bracket class, an unterminated class)
/// is reported as unreadable so the pin fails closed instead of guessing
/// what git would ignore.
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
/// `!`/`^` negation and `a-z` ranges, a `]` first being a member). A run of
/// two or more asterisks is special only as a whole path segment: a leading
/// `**/` and an inner `/**/` match zero or more directories, a trailing
/// `/**` (or a bare `**`) matches everything below; anywhere else (#7017) the
/// run is one regular `*`, which never crosses `/`. `None` (fail closed) on
/// a malformed class and on a POSIX bracket class (`[:`, `[.`, `[=`), which
/// is not implemented.
fn glob(pat: &[u8], text: &[u8]) -> Option<bool> {
    glob_at(pat, text, true)
}

/// [`glob`], where `segment_start` says the pattern byte under `pat` opens
/// a path segment (the start of the pattern, or right after a `/`).
fn glob_at(pat: &[u8], text: &[u8], segment_start: bool) -> Option<bool> {
    let Some(&head) = pat.first() else {
        return Some(text.is_empty());
    };
    match head {
        b'*' => {
            let run = pat.iter().take_while(|byte| **byte == b'*').count();
            let rest = &pat[run..];
            let whole_segment =
                run >= 2 && segment_start && matches!(rest.first(), None | Some(b'/'));
            if whole_segment {
                let Some(after) = rest.strip_prefix(b"/") else {
                    return Some(true);
                };
                if glob_at(after, text, true)? {
                    return Some(true);
                }
                for (at, byte) in text.iter().enumerate() {
                    if *byte == b'/' && glob_at(after, &text[at + 1..], true)? {
                        return Some(true);
                    }
                }
                return Some(false);
            }
            for at in 0..=text.len() {
                if glob_at(rest, &text[at..], false)? {
                    return Some(true);
                }
                if text.get(at) == Some(&b'/') {
                    break;
                }
            }
            Some(false)
        }
        b'?' => match text.first() {
            Some(&byte) if byte != b'/' => glob_at(&pat[1..], &text[1..], false),
            _ => Some(false),
        },
        b'[' => {
            let mut at = 1;
            let negated = matches!(pat.get(1), Some(b'!' | b'^'));
            if negated {
                at += 1;
            }
            let start = at;
            let mut hit = false;
            let Some(&byte) = text.first() else {
                return Some(false);
            };
            loop {
                let &cur = pat.get(at)?;
                if cur == b']' && at > start {
                    break;
                }
                if cur == b'[' && matches!(pat.get(at + 1), Some(b':' | b'.' | b'=')) {
                    return None;
                }
                if pat.get(at + 1) == Some(&b'-') && pat.get(at + 2).is_some_and(|e| *e != b']') {
                    let &hi = pat.get(at + 2)?;
                    hit |= (cur..=hi).contains(&byte);
                    at += 3;
                } else {
                    hit |= cur == byte;
                    at += 1;
                }
            }
            if hit != negated && byte != b'/' {
                glob_at(&pat[at + 1..], &text[1..], false)
            } else {
                Some(false)
            }
        }
        _ => match text.first() {
            Some(&byte) if byte == head => glob_at(&pat[1..], &text[1..], head == b'/'),
            _ => Some(false),
        },
    }
}

/// Last matching rule wins (gitignore(5)); rules from deeper `.gitignore`
/// files come later in `rules`, so they override shallower ones. `Err` on a
/// pattern [`glob`] cannot evaluate.
fn is_ignored(
    rel: &str,
    is_dir: bool,
    rules: &[IgnoreRule],
    ignore_case: bool,
) -> Result<bool, String> {
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
        let matched = if ignore_case {
            glob(
                rule.pattern.to_ascii_lowercase().as_bytes(),
                subject.to_ascii_lowercase().as_bytes(),
            )
        } else {
            glob(rule.pattern.as_bytes(), subject.as_bytes())
        }
        .ok_or_else(|| format!("unsupported .gitignore class in {:?}", rule.pattern))?;
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
    let env = git_env(root, unreadable);
    walk_with(root, &env, out, unreadable);
}

/// Run `git -C root <args>` with the repository-selecting environment
/// cleared. A spawn failure is recorded in `unreadable` (fail closed).
fn git_output(
    root: &Path,
    args: &[&str],
    unreadable: &mut Vec<String>,
) -> Option<std::process::Output> {
    match std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
    {
        Ok(out) => Some(out),
        Err(e) => {
            unreadable.push(format!("git {args:?}: {e}"));
            None
        }
    }
}

/// The facts git itself would use for `root` (#7008, #7017): the tracked
/// files (git applies no ignore rule to a tracked path) and
/// `core.ignorecase`. A root without `.git` has nothing tracked. When `.git`
/// exists but git cannot answer for exactly this root, the failure is
/// recorded in `unreadable` (fail closed).
fn git_env(root: &Path, unreadable: &mut Vec<String>) -> Env {
    if !root.join(".git").exists() {
        return Env::default();
    }
    // An empty `.git` directory is not a repository: git would climb to an
    // enclosing one. The root must be the top level (empty prefix).
    let Some(prefix) = git_output(root, &["rev-parse", "--show-prefix"], unreadable) else {
        return Env::default();
    };
    if !prefix.status.success() || !prefix.stdout.iter().all(u8::is_ascii_whitespace) {
        unreadable.push(format!(
            "{}: git does not report this directory as a repository top level",
            root.display()
        ));
        return Env::default();
    }
    let mut env = Env::default();
    if let Some(list) = git_output(root, &["ls-files", "-z"], unreadable) {
        if list.status.success() {
            for raw in list.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
                match std::str::from_utf8(raw) {
                    Ok(path) => {
                        env.tracked.insert(path.to_string());
                        let mut dir = path;
                        while let Some((parent, _)) = dir.rsplit_once('/') {
                            env.tracked_dirs.insert(parent.to_string());
                            dir = parent;
                        }
                    }
                    Err(_) => unreadable.push("git ls-files: a tracked path is not UTF-8".into()),
                }
            }
        } else {
            unreadable.push(format!("git ls-files failed: {}", list.status));
        }
    }
    if let Some(case) = git_output(
        root,
        &["config", "--bool", "--get", "core.ignorecase"],
        unreadable,
    ) {
        match case.status.code() {
            Some(0) => env.ignore_case = case.stdout.starts_with(b"true"),
            // Exit 1: the key is unset, which git treats as false.
            Some(1) => {}
            _ => unreadable.push(format!(
                "git config core.ignorecase failed: {}",
                case.status
            )),
        }
    }
    env
}

/// [`walk`] with the git facts supplied by the caller.
fn walk_with(root: &Path, env: &Env, out: &mut Vec<PathBuf>, unreadable: &mut Vec<String>) {
    let mut rules = Vec::new();
    if let Some(exclude) = info_exclude(root, unreadable) {
        load_ignore_file(&exclude, "", &mut rules, unreadable);
    }
    walk_dir(root, root, env, &mut rules, out, unreadable);
}

fn walk_dir(
    root: &Path,
    dir: &Path,
    env: &Env,
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
        let Some(name) = utf8_name(&path, unreadable) else {
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
        match is_ignored(&rel, file_type.is_dir(), rules, env.ignore_case) {
            // git applies no ignore rule to a tracked path, and a directory
            // holding one must still be entered (#7008).
            Ok(true) => {
                let tracked = if file_type.is_dir() {
                    env.tracked_dirs.contains(&rel)
                } else {
                    env.tracked.contains(&rel)
                };
                if !tracked {
                    continue;
                }
            }
            Ok(false) => {}
            Err(e) => {
                unreadable.push(format!("{rel}: {e}"));
                continue;
            }
        }
        if file_type.is_dir() {
            walk_dir(root, &path, env, rules, out, unreadable);
        } else if file_type.is_file() && !is_binary(name) {
            out.push(path);
        }
    }
    rules.truncate(depth);
}

/// The final component of `path` as UTF-8; a name that is not UTF-8 is
/// recorded in `unreadable` (fail closed) and yields `None`.
fn utf8_name<'a>(path: &'a Path, unreadable: &mut Vec<String>) -> Option<&'a str> {
    let name = path.file_name().and_then(|n| n.to_str());
    if name.is_none() {
        unreadable.push(format!("{}: file name is not UTF-8", path.display()));
    }
    name
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

/// A line that opens with a comment token of the languages the repository
/// carries (`#`, `//`, `/*`, `*`, `--`, `<!--`).
fn is_comment_line(line: &str) -> bool {
    let line = line.trim_start();
    ["#", "//", "/*", "*", "--", "<!--"]
        .iter()
        .any(|token| line.starts_with(token))
}

/// #6535 residue: the dates a value placed after comment lines carries.
/// From line index `start` on, every line holding a letter or digit
/// contributes its dates; the scan ends after the first line that is not a
/// comment, or at the next marker line (a use of its own).
fn dates_after_comments<'a>(
    lines: &[&'a str],
    start: usize,
    has_marker: impl Fn(&str) -> bool,
) -> Vec<(usize, &'a str)> {
    let mut found = Vec::new();
    for (m, line) in lines.iter().enumerate().skip(start) {
        if !line.bytes().any(|b| b.is_ascii_alphanumeric()) {
            continue;
        }
        if has_marker(line) {
            break;
        }
        found.extend(dates(line).into_iter().map(|date| (m + 1, date)));
        if !is_comment_line(line) {
            break;
        }
    }
    found
}

/// Every `(1-based line number, date)` that `text` uses as a
/// `protocolVersion`: each date on a line that names one of [`MARKERS`],
/// and (#6535) when such a line carries no date, each date on the next line
/// that holds an ASCII letter or digit, unless that line names a marker
/// itself (it is then a use of its own). Only whitespace, punctuation such
/// as `:` or `=` and comment lines can sit between a key and its value, so
/// this follows a value that JSON, YAML, TOML, Rust or TS put on a later
/// line, past any comment lines in between (their dates count too).
fn protocol_version_uses(text: &str) -> Vec<(usize, &str)> {
    let has_marker = |line: &str| MARKERS.iter().any(|m| line.contains(m));
    let lines: Vec<&str> = text.lines().collect();
    let mut uses = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        if !has_marker(line) {
            continue;
        }
        let here = dates(line);
        if !here.is_empty() {
            uses.extend(here.into_iter().map(|date| (n + 1, date)));
            continue;
        }
        let value_line = lines
            .iter()
            .enumerate()
            .skip(n + 1)
            .find(|(_, next)| next.bytes().any(|b| b.is_ascii_alphanumeric()));
        if let Some((m, next)) = value_line
            && !has_marker(next)
        {
            uses.extend(dates(next).into_iter().map(|date| (m + 1, date)));
            if is_comment_line(next) {
                uses.extend(dates_after_comments(&lines, m + 1, has_marker));
            }
        }
    }
    uses
}

/// Read every file in `files` and return the number of `protocolVersion`
/// uses plus the ones outside [`SUPPORTED_PROTOCOL_REVISIONS`]. A file that
/// cannot be read or is not UTF-8 is recorded in `unreadable` (fail closed).
fn scan_files(
    root: &Path,
    files: &[PathBuf],
    unreadable: &mut Vec<String>,
) -> (usize, Vec<String>) {
    let mut offenders = Vec::new();
    let mut uses = 0usize;
    for file in files {
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
        for (line_no, date) in protocol_version_uses(&text) {
            uses += 1;
            if !SUPPORTED_PROTOCOL_REVISIONS.contains(&date) {
                offenders.push(format!("{}:{line_no}: {date}", rel.display()));
            }
        }
    }
    (uses, offenders)
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
    let (uses, offenders) = scan_files(root, &files, &mut unreadable);
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

/// #6533: a directory NAME is never a reason to skip. Round 3 skipped
/// `build`, `dist`, `venv`, `target`, `worktrees` and five cache names at
/// any depth, so a tracked file under `infra/build/` or `src/target/` was
/// never read (false green). Under the repository's real root `.gitignore`
/// every path in `KEPT` is trackable (`git check-ignore` exit 1) and must be
/// read; `__pycache__`, which that file ignores at any depth, must not be.
#[test]
fn issue_6533_walk_reads_tracked_files_under_formerly_excluded_names() {
    const KEPT: [&str; 10] = [
        "deploy/worktrees/zz_plant.md",
        "docs/.mypy_cache/zz_plant.md",
        "docs/.pytest_cache/zz_plant.md",
        "docs/.ruff_cache/zz_plant.md",
        "docs/.venv/zz_plant.md",
        "docs/dist/zz_plant.md",
        "docs/node_modules/zz_plant.md",
        "infra/build/zz_plant.json",
        "scripts/venv/zz_plant.py",
        "src/target/zz_plant.rs",
    ];
    let scratch = scratch_tree("6533");
    copy_gitignore(&scratch, ".gitignore");
    for rel in KEPT {
        plant(&scratch, rel, PLANT);
    }
    plant(&scratch, "tools/__pycache__/zz_plant.md", PLANT);
    let (seen, unreadable) = walked(&scratch);
    let _ = fs::remove_dir_all(&scratch);

    assert!(unreadable.is_empty(), "unreadable: {unreadable:?}");
    let want: Vec<String> = KEPT.iter().map(ToString::to_string).collect();
    assert_eq!(
        seen, want,
        "the walk skipped a trackable file by directory name (false green) \
         or read a path the root .gitignore ignores"
    );
}

/// #6534: the walk reads every trackable file whatever its extension. The
/// round-3 allowlist (`rs md html sh py json ts tsx mjs cjs js toml yml
/// yaml`) skipped the issue's three plants (`.jsonl`, an extension-less
/// `Dockerfile`, `.txt`) and the tracked shapes `.github/Dockerfile.ci` and
/// a golden `.out`; all five must be read.
#[test]
fn issue_6534_walk_reads_files_outside_the_round3_extension_allowlist() {
    const KEPT: [&str; 5] = [
        ".github/Dockerfile.ci",
        "benchmarks/zz_plant.jsonl",
        "deploy/zz_plant/Dockerfile",
        "docs/zz_plant.txt",
        "tests/golden/zz_plant.out",
    ];
    let scratch = scratch_tree("6534");
    copy_gitignore(&scratch, ".gitignore");
    for rel in KEPT {
        plant(&scratch, rel, PLANT);
    }
    let (seen, unreadable) = walked(&scratch);
    let _ = fs::remove_dir_all(&scratch);

    assert!(unreadable.is_empty(), "unreadable: {unreadable:?}");
    let want: Vec<String> = KEPT.iter().map(ToString::to_string).collect();
    assert_eq!(
        seen, want,
        "the walk skipped a trackable file by extension (false green)"
    );
}

/// One #6535 case: what it shows, the file text, the uses expected.
type SplitCase = (&'static str, &'static str, Vec<(usize, &'static str)>);

/// #6535: a revision on a line after its marker is still a use. Pretty-
/// printed JSON, YAML, TOML, Rust and TS put a key and its value on
/// different lines; the round-3 line scan never checked such a value, so an
/// unsupported revision passed by line placement alone (false green).
#[test]
fn issue_6535_a_revision_split_from_its_marker_is_still_a_use() {
    let cases: [SplitCase; 6] = [
        (
            "pretty-printed JSON",
            "{\n  \"protocolVersion\":\n    \"2099-01-01\"\n}\n",
            vec![(3, "2099-01-01")],
        ),
        (
            "JSON key, colon and value on three lines",
            "{\"protocolVersion\"\n:\n\"2099-01-02\"}\n",
            vec![(3, "2099-01-02")],
        ),
        (
            "YAML key, blank line, value",
            "protocolVersion:\n\n  2099-01-03\n",
            vec![(3, "2099-01-03")],
        ),
        (
            "same-line control",
            "{\"protocolVersion\": \"2099-01-04\"}\n",
            vec![(1, "2099-01-04")],
        ),
        (
            "a marker line with its own date does not take the next line's",
            "protocolVersion: 2099-01-05\nreleased 2099-01-06\n",
            vec![(1, "2099-01-05")],
        ),
        (
            "a dateless marker followed by another marker line",
            "protocolVersion:\nprotocolVersion: 2099-01-07\n",
            vec![(2, "2099-01-07")],
        ),
    ];
    for (what, text, want) in cases {
        assert_eq!(protocol_version_uses(text), want, "{what}");
    }
}

/// #6535 residue (security review round 4): a comment line between a key
/// and its value was taken as the value line, so the real value two lines
/// down was never checked. Dates on the comment lines themselves are kept
/// as uses (a bulleted value looks like a comment), and the scan stops at
/// the first line that is not a comment or at the next marker.
#[test]
fn issue_6535_a_comment_between_key_and_value_does_not_hide_the_value() {
    let cases: [SplitCase; 6] = [
        (
            "YAML comment line",
            "protocolVersion:\n  # pinned by the client\n  \"2099-01-08\"\n",
            vec![(3, "2099-01-08")],
        ),
        (
            "TS line comment",
            "protocolVersion:\n  // note\n  '2099-01-09'\n",
            vec![(3, "2099-01-09")],
        ),
        (
            "block comment",
            "protocolVersion =\n/* note */\n\"2099-01-10\"\n",
            vec![(3, "2099-01-10")],
        ),
        (
            "a comment that carries a date of its own",
            "protocolVersion:\n# was 2099-01-11\n2099-01-12\n",
            vec![(2, "2099-01-11"), (3, "2099-01-12")],
        ),
        (
            "two comment lines",
            "protocolVersion:\n# a\n// b\n\"2099-01-13\"\n",
            vec![(4, "2099-01-13")],
        ),
        (
            "a marker after the comment is a use of its own",
            "protocolVersion:\n# a\nprotocolVersion: 2099-01-14\n2099-01-15\n",
            vec![(3, "2099-01-14")],
        ),
    ];
    for (what, text, want) in cases {
        assert_eq!(protocol_version_uses(text), want, "{what}");
    }
}

/// Every tracked `.gitignore` outside the skipped root `vendor/`. The #6524
/// test pins that the real walk finds exactly these, so a new ignore file
/// cannot join the tree without joining the plant test below.
const TRACKED_GITIGNORES: [&str; 15] = [
    ".gitignore",
    "clients/anthropic-shim-py/.gitignore",
    "clients/anthropic-shim-ts/.gitignore",
    "clients/host-adapter-shim/python/.gitignore",
    "clients/openai-shim-py/.gitignore",
    "clients/openai-shim-ts/.gitignore",
    "deploy/do-1461/terraform/.gitignore",
    "deploy/hive-1461/terraform/.gitignore",
    "infra/do-hive/.gitignore",
    "infra/do-hive/crypto/.gitignore",
    "infra/federation-lab/.gitignore",
    "infra/pgbouncer/.gitignore",
    "infra/pillar4-envelope/.gitignore",
    "sdk/python/.gitignore",
    "sdk/typescript/.gitignore",
];

/// A concrete path, relative to the `.gitignore`'s directory, that the
/// pattern on `line` matches, and whether the line re-includes (`!`).
/// `*` and `**` become `zz`, `?` becomes `z`, a `[...]` class its first
/// member; a pattern without a slash is planted one directory deeper to
/// exercise any-depth matching, and a dir-only pattern gets a file inside.
fn concrete_path(line: &str) -> Option<(String, bool)> {
    let line = line.trim_end();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (negate, rest) = line
        .strip_prefix('!')
        .map_or((false, line), |rest| (true, rest));
    let (dir_only, rest) = rest
        .strip_suffix('/')
        .map_or((false, rest), |rest| (true, rest));
    let anchored = rest.contains('/');
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    let mut path = String::new();
    let rest = rest.replace("**", "zz");
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '*' => path.push_str("zz"),
            '?' => path.push('z'),
            '[' => {
                let first = chars.next().expect("class member");
                assert!(first != '!' && first != '^', "negated class in {line:?}");
                path.push(first);
                for c in chars.by_ref() {
                    if c == ']' {
                        break;
                    }
                }
            }
            c => path.push(c),
        }
    }
    if !anchored {
        path = format!("nest/{path}");
    }
    if dir_only {
        path.push_str("/plant.txt");
    }
    Some((path, negate))
}

/// The last path component of a relative path.
fn base_name(rel: &str) -> &str {
    rel.rsplit('/').next().unwrap_or(rel)
}

/// #6524: every exclusion the walk applies is pinned, derived from the
/// rules themselves rather than a second hand-written list.
///
/// 1. The real walk finds exactly [`TRACKED_GITIGNORES`].
/// 2. Tree `lines`: for every line of every tracked `.gitignore` a path that
///    line matches is planted. An ignore line's plant must be skipped, a `!`
///    line's plant must be read. The exact skips (`.git` entries, the root
///    `vendor/`) and `$GIT_DIR/info/exclude` are exercised too, and a
///    `vendor/` below the root must be read.
/// 3. Tree `files`: every dir-only line gets a plain FILE of that name,
///    which must be read (a dir-only pattern never matches a file).
/// 4. Tree `controls`, carrying only the nested `.gitignore` files: every
///    nested ignore line's plant is repeated OUTSIDE that file's directory
///    (`ctl/...`), where it must be read (a rule never reaches above its
///    own `.gitignore`).
///
/// Every expected set was cross-checked against `git ls-files -o
/// --exclude-standard` on the same plants (lines: 134 plants, 4 read;
/// files: 49, 49 read; controls: 94, 94 read). A plant whose name the walk
/// treats as binary (`.DS_Store`, #6522) is expected unread.
#[test]
fn issue_6524_walk_skips_every_exclusion_its_rules_name() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    walk(root, &mut files, &mut unreadable);
    let mut found: Vec<String> = files
        .iter()
        .filter_map(|f| f.strip_prefix(root).ok())
        .map(|p| p.display().to_string())
        .filter(|p| base_name(p) == ".gitignore")
        .collect();
    found.sort();
    let mut want: Vec<String> = TRACKED_GITIGNORES.iter().map(ToString::to_string).collect();
    want.sort();
    assert_eq!(found, want, "a .gitignore joined or left the tree");

    let lines = scratch_tree("6524-lines");
    let dir_files = scratch_tree("6524-files");
    let controls = scratch_tree("6524-ctl");
    let mut want_lines = Vec::new();
    let mut want_files = Vec::new();
    let mut want_controls = Vec::new();
    let mut negations = 0_usize;
    for rel in TRACKED_GITIGNORES {
        copy_gitignore(&lines, rel);
        copy_gitignore(&dir_files, rel);
        let base = rel.strip_suffix(".gitignore").unwrap_or_default();
        if !base.is_empty() {
            copy_gitignore(&controls, rel);
        }
        let body = fs::read_to_string(root.join(rel)).expect("read tracked .gitignore");
        for line in body.lines() {
            let Some((path, negate)) = concrete_path(line) else {
                continue;
            };
            let planted = format!("{base}{path}");
            plant(&lines, &planted, PLANT);
            if negate {
                negations += 1;
                if !is_binary(base_name(&planted)) {
                    want_lines.push(planted);
                }
                continue;
            }
            if let Some(file) = planted.strip_suffix("/plant.txt") {
                plant(&dir_files, file, PLANT);
                if !is_binary(base_name(file)) {
                    want_files.push(file.to_string());
                }
            }
            if !base.is_empty() {
                let control = format!("ctl/{}{path}", base.replace('/', "-"));
                plant(&controls, &control, PLANT);
                if !is_binary(base_name(&control)) {
                    want_controls.push(control);
                }
            }
        }
    }
    for rel in [".git/config.json", "docs/.git", "vendor/paste/src/lib.rs"] {
        plant(&lines, rel, PLANT);
    }
    plant(&lines, ".git/info/exclude", "zz-excluded.md\n");
    plant(&lines, "zz-excluded.md", PLANT);
    plant(&lines, "docs/vendor/kept.md", PLANT);
    want_lines.push("docs/vendor/kept.md".to_string());

    let mut results = Vec::new();
    for (tree, mut want) in [
        (&lines, want_lines),
        (&dir_files, want_files),
        (&controls, want_controls),
    ] {
        let (seen, unreadable) = walked(tree);
        want.sort();
        want.dedup();
        results.push((tree.display().to_string(), seen, want, unreadable));
    }
    for tree in [&lines, &dir_files, &controls] {
        let _ = fs::remove_dir_all(tree);
    }

    assert!(
        negations >= 4,
        "the tracked rules carry at least four `!` lines"
    );
    for (tree, seen, want, unreadable) in results {
        assert!(unreadable.is_empty(), "{tree}: unreadable: {unreadable:?}");
        assert!(want.len() >= 4, "{tree}: too few expected plants: {want:?}");
        assert_eq!(
            seen, want,
            "{tree}: the walk read a path its rules exclude, or skipped a path no rule excludes"
        );
    }
}

/// #6524: a linked worktree's `.git` is a file (`gitdir: ...`) whose
/// `commondir` leads to the shared `info/exclude`; the walk follows both.
#[test]
fn issue_6524_walk_honours_a_worktree_info_exclude() {
    let tree = scratch_tree("6524-wt");
    let common = scratch_tree("6524-wt-common");
    let gitdir = common.join("worktrees").join("wt");
    plant(&common, "worktrees/wt/commondir", "../..\n");
    plant(&common, "info/exclude", "# local\nzz-wt-excluded.md\n");
    plant(&tree, ".git", &format!("gitdir: {}\n", gitdir.display()));
    plant(&tree, "zz-wt-excluded.md", PLANT);
    plant(&tree, "kept.md", PLANT);
    let (seen, unreadable) = walked(&tree);
    let _ = fs::remove_dir_all(&tree);
    let _ = fs::remove_dir_all(&common);
    assert!(unreadable.is_empty(), "unreadable: {unreadable:?}");
    assert_eq!(seen, vec!["kept.md".to_string()]);
}

/// #6524: the gitignore(5) matcher, case by case. Every row was
/// cross-checked with `git check-ignore` (22 rows, 0 disagreements).
#[test]
fn issue_6524_glob_and_parse_follow_gitignore5() {
    let cases: [(&[&str], &str, bool, bool); 22] = [
        (&["docs/*.md"], "docs/a/b.md", false, false),
        (&["docs/*.md"], "docs/b.md", false, true),
        (&["x/a?b"], "x/a/b", false, false),
        (&["x/a?b"], "x/acb", false, true),
        (&["[!a]bc"], "xbc", false, true),
        (&["[!a]bc"], "abc", false, false),
        (&["[^a]bc"], "abc", false, false),
        (&["[a-c]x"], "bx", false, true),
        (&["[a-c]x"], "dx", false, false),
        (&["**/foo"], "foo", false, true),
        (&["**/foo"], "a/b/foo", false, true),
        (&["a/**/b"], "a/b", false, true),
        (&["a/**/b"], "a/x/y/b", false, true),
        (&["a/**"], "a/x/y", false, true),
        (&["foo "], "foo", false, true),
        (&["build/"], "build", false, false),
        (&["build/"], "build", true, true),
        (&["*.log", "!keep.log"], "keep.log", false, false),
        (&["*.log", "!keep.log"], "x.log", false, true),
        (&["/root.md"], "sub/root.md", false, false),
        (&["/root.md"], "root.md", false, true),
        (&["name.md"], "a/b/name.md", false, true),
    ];
    for (lines, rel, is_dir, want) in cases {
        let rules: Vec<IgnoreRule> = lines
            .iter()
            .filter_map(|line| parse_ignore_line(line, "").expect("parse"))
            .collect();
        assert_eq!(
            is_ignored(rel, is_dir, &rules, false),
            Ok(want),
            "{lines:?} vs {rel:?} (dir: {is_dir})"
        );
    }
    // Fail closed on what the walk does not implement or cannot evaluate.
    assert!(parse_ignore_line("fo\\o", "").is_err(), "escape accepted");
    assert!(
        parse_ignore_line("/", "").is_err(),
        "empty pattern accepted"
    );
    let malformed: Vec<IgnoreRule> = parse_ignore_line("[abc", "")
        .into_iter()
        .flatten()
        .collect();
    assert!(
        is_ignored("abc", false, &malformed, false).is_err(),
        "malformed class matched"
    );
}

/// The verdict of the walk's matcher for `rel` under the ignore `lines`.
fn ignored_by(lines: &[&str], rel: &str, is_dir: bool, ignore_case: bool) -> Result<bool, String> {
    let mut rules = Vec::new();
    for line in lines {
        rules.extend(parse_ignore_line(line, "")?);
    }
    is_ignored(rel, is_dir, &rules, ignore_case)
}

/// #7017: gitignore(5) gives `**` its meaning only as a whole path segment
/// (leading `**/`, trailing `/**`, inner `/**/`); any other run of asterisks
/// is a regular `*` that never crosses `/`. The round-4 matcher treated
/// every `**` as match-everything, so `docs/**draft` skipped the tracked
/// `docs/a/xdraft` (fail-open). A `]` first in a class is a literal member
/// (mutant R09). Every row's verdict is git 2.54.0 `git check-ignore`.
#[test]
fn issue_7017_glob_follows_git_for_double_stars_inside_a_segment_and_leading_brackets() {
    let rows: [(&str, &str, bool, bool); 13] = [
        ("docs/**draft", "docs/a/xdraft", false, false),
        ("docs/**draft", "docs/xdraft", false, true),
        ("a**/b", "ax/y/b", false, false),
        ("a**/b", "a/b", false, true),
        ("a**/b", "ax/b", false, true),
        ("x/a**", "x/abc", false, true),
        ("x/a**", "x/ab", true, true),
        ("x/***/y", "x/a/y", false, true),
        ("x/***/y", "x/a/b/y", false, true),
        ("[]a]x", "]x", false, true),
        ("[]a]x", "bx", false, false),
        ("[]a]x", "ax", false, true),
        ("**", "q/r", false, true),
    ];
    for (line, rel, is_dir, want) in rows {
        assert_eq!(
            ignored_by(&[line], rel, is_dir, false),
            Ok(want),
            "{line:?} vs {rel:?} (dir: {is_dir})"
        );
    }
}

/// #7017: a POSIX bracket class (`[[:digit:]]`, `[[.a.]]`, `[[=a=]]`) is not
/// implemented, so the matcher must fail closed instead of reading it as a
/// plain set (git ignores `5x` under `[[:digit:]]x` and tracks `d]x`; the
/// set reading did the reverse). A `.gitignore` that uses one is reported as
/// unreadable and the pin goes red rather than guessing.
#[test]
fn issue_7017_posix_bracket_classes_fail_closed() {
    for line in ["[[:digit:]]x", "[[.a.]]x", "[[=a=]]x", "[a[:digit:]]x"] {
        assert!(
            ignored_by(&[line], "5x", false, false).is_err(),
            "{line:?} was evaluated instead of failing closed"
        );
    }
    let scratch = scratch_tree("7017-posix");
    plant(&scratch, ".gitignore", "[[:digit:]]x\n");
    plant(&scratch, "5x", PLANT);
    let (_, unreadable) = walked(&scratch);
    let _ = fs::remove_dir_all(&scratch);
    assert!(
        unreadable.iter().any(|u| u.contains("[[:digit:]]x")),
        "the walk did not report the POSIX class: {unreadable:?}"
    );
}

/// #7017: with `core.ignorecase=true` (the default `git init` sets on macOS
/// and Windows) git ignores `notes.md` under the rule `Notes.md`; the
/// round-4 matcher was always case-sensitive (false red on such a tree).
/// The fold is ASCII, as git's `tolower` is.
#[test]
fn issue_7017_ignore_case_folds_pattern_and_name() {
    for (line, rel, fold, want) in [
        ("Notes.md", "notes.md", true, true),
        ("Notes.md", "notes.md", false, false),
        ("Notes.md", "NOTES.MD", true, true),
        ("[A-C]x", "bx", true, true),
        ("[A-C]x", "bx", false, false),
        ("docs/README", "DOCS/readme", true, true),
    ] {
        assert_eq!(
            ignored_by(&[line], rel, false, fold),
            Ok(want),
            "{line:?} vs {rel:?} (ignorecase: {fold})"
        );
    }
}

/// Walk `scratch` with the git facts `env` and return the relative paths
/// collected (minus `.gitignore` files) plus what was unreadable.
fn walked_with(scratch: &Path, env: &Env) -> (Vec<String>, Vec<String>) {
    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    walk_with(scratch, env, &mut files, &mut unreadable);
    let mut seen: Vec<String> = files
        .iter()
        .filter_map(|f| f.strip_prefix(scratch).ok())
        .map(|p| p.display().to_string())
        .filter(|p| !p.ends_with(".gitignore"))
        .collect();
    seen.sort();
    (seen, unreadable)
}

/// Run `git -C dir <args>` with the repository-selecting environment
/// cleared; the command must succeed.
fn git_ok(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .expect("run git")
        .status;
    assert!(status.success(), "git {args:?} failed in {}", dir.display());
}

/// #7008: git applies no ignore rule to a file it tracks (`git add -f`, or a
/// file committed before its rule existed), so the pin must read it. The
/// round-4 walk skipped every path an ignore rule matched, tracked or not
/// (plant docs/.env.example MISSED while `git ls-files -ci` listed it).
/// A tracked file inside an ignored directory is read too, and an untracked
/// file the same rules ignore is still skipped.
#[test]
fn issue_7008_walk_reads_tracked_files_the_ignore_rules_match() {
    let scratch = scratch_tree("7008-env");
    plant(&scratch, ".gitignore", ".env.*\nbuild-out/\n");
    plant(&scratch, "docs/.env.example", PLANT);
    plant(&scratch, "docs/.env.local", PLANT);
    plant(&scratch, "docs/plain.md", PLANT);
    plant(&scratch, "build-out/keep/tracked.json", PLANT);
    plant(&scratch, "build-out/other.json", PLANT);
    let env = Env::from_tracked(["docs/.env.example", "build-out/keep/tracked.json"], false);
    let (seen, unreadable) = walked_with(&scratch, &env);
    let _ = fs::remove_dir_all(&scratch);

    assert!(unreadable.is_empty(), "unreadable: {unreadable:?}");
    assert_eq!(
        seen,
        vec![
            "build-out/keep/tracked.json".to_string(),
            "docs/.env.example".to_string(),
            "docs/plain.md".to_string(),
        ],
        "a tracked path the ignore rules match was skipped (fail-open), \
         or an untracked ignored path was read"
    );
}

/// A throwaway git repository at `scratch` with `core.ignorecase` set.
fn git_scratch_repo(tag: &str, ignore_case: bool) -> PathBuf {
    let scratch = scratch_tree(tag);
    git_ok(&scratch, &["init", "-q"]);
    git_ok(
        &scratch,
        &[
            "config",
            "core.ignorecase",
            if ignore_case { "true" } else { "false" },
        ],
    );
    scratch
}

/// #7008 end to end: in a real repository the walk asks git which paths are
/// tracked. docs/.env.example matches `.env.*` and is force-added, so git
/// lists it (`ls-files -ci`) and the walk must read it.
#[test]
fn issue_7008_walk_in_a_git_repo_reads_force_added_ignored_files() {
    let scratch = git_scratch_repo("7008-git", false);
    plant(&scratch, ".gitignore", ".env.*\n");
    plant(&scratch, "docs/.env.example", PLANT);
    plant(&scratch, "docs/.env.untracked", PLANT);
    git_ok(&scratch, &["add", "-f", "docs/.env.example"]);
    let (seen, unreadable) = walked(&scratch);
    let _ = fs::remove_dir_all(&scratch);

    assert!(unreadable.is_empty(), "unreadable: {unreadable:?}");
    assert_eq!(
        seen,
        vec!["docs/.env.example".to_string()],
        "the walk must read the force-added file and skip the untracked ignored one"
    );
}

/// #7017 end to end: the walk reads `core.ignorecase` from git. With it
/// true, `Notes.md` ignores `notes.md`; with it false it does not.
#[test]
fn issue_7017_walk_honours_core_ignorecase_from_git_config() {
    for (ignore_case, want) in [(true, Vec::new()), (false, vec!["notes.md".to_string()])] {
        let scratch = git_scratch_repo(&format!("7017-case-{ignore_case}"), ignore_case);
        plant(&scratch, ".gitignore", "Notes.md\n");
        plant(&scratch, "notes.md", PLANT);
        let (seen, unreadable) = walked(&scratch);
        let _ = fs::remove_dir_all(&scratch);
        assert!(unreadable.is_empty(), "unreadable: {unreadable:?}");
        assert_eq!(seen, want, "core.ignorecase={ignore_case}");
    }
}

/// #7008: when the root has a `.git` but git cannot answer for exactly this
/// root, the walk reports it (fail closed) instead of treating the tree as
/// having nothing tracked. An empty `.git` directory is not a repository,
/// so git would climb to an enclosing one; a `.git` file naming a missing
/// gitdir makes git fail outright.
#[test]
fn issue_7008_walk_fails_closed_when_git_cannot_list_the_root() {
    for (tag, dot_git_is_dir) in [("7008-dir", true), ("7008-file", false)] {
        let scratch = scratch_tree(tag);
        if dot_git_is_dir {
            fs::create_dir_all(scratch.join(".git")).expect("create .git dir");
        } else {
            plant(&scratch, ".git", "gitdir: /nonexistent/ssot-6157\n");
        }
        plant(&scratch, "docs/a.md", PLANT);
        let (_, unreadable) = walked(&scratch);
        let _ = fs::remove_dir_all(&scratch);
        assert!(
            unreadable.iter().any(|u| u.contains("git")),
            "{tag}: the walk did not report that git could not list the root: {unreadable:?}"
        );
    }
}
