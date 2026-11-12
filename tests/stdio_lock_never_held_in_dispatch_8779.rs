// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8779 class ratchet: no process-global stdout/stderr lock is held by a CLI
//! dispatch arm.
//!
//! `curator --once` held `std::io::stderr().lock()` across the
//! `spawn_blocking` sweep. The worker thread's first tracing event (the
//! subscriber writes to stderr) then blocked on the reentrant mutex owned by
//! the dispatch thread, which was itself waiting on the worker: a deadlock
//! that never ends. Every other dispatch arm used the same
//! `let mut so = stdout.lock(); let mut se = stderr.lock();` shape around an
//! `.await`, so the whole class is locked here: a `Stdout` / `Stderr` handle
//! (which takes the lock per write) is the only accepted form, and the few
//! synchronous sites that take the lock for one bounded write are named below
//! with their exact count. A new lock site fails this test with its
//! `file:line`. The detector tracks stdio BINDINGS, not spellings: any
//! `.lock()` on a `Stdout`/`Stderr`/`Stdin` binding, any `StdoutLock` /
//! `StderrLock` / `StdinLock` type, any line split (#9185 L-E).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Constructors of a process-global stdio handle. `<ctor>.lock()` (any
/// whitespace, any line split) takes the lock directly. The input
/// constructor needle is joined by `concat!` so this source-scan file never
/// spells the call itself: `scripts/check-test-stdin-reads.sh` (#1989) treats
/// that spelling in a test file as a real read. The joined value is the same
/// `&'static str`, so the detector is unchanged.
const STDIO_CTORS: [&str; 3] = ["stdout()", "stderr()", STDIN_CTOR];

/// The input constructor needle (see `STDIO_CTORS`).
const STDIN_CTOR: &str = concat!("std", "in()");

/// The guard types: naming one means a lock is held somewhere in that scope.
const STDIO_LOCK_TYPES: [&str; 3] = ["StdoutLock", "StderrLock", "StdinLock"];

/// The unlocked handle types; a binding of one of these is tracked so that
/// `<binding>.lock()` is a site under any binding name (#9185 L-E: the
/// literal-spelling needles missed `stdout_handle.lock()`).
const STDIO_HANDLE_TYPES: [&str; 3] = ["Stdout", "Stderr", "Stdin"];

/// The conventional binding names, always tracked (the pre-#9185 needles),
/// so a handle bound in another file or a macro is still a receiver.
const STDIO_CONVENTIONAL_NAMES: [&str; 3] = ["stdout", "stderr", "stdin"];

/// Reviewed synchronous sites: the lock is taken for one bounded write and
/// dropped before any tracing, await or thread hand-off. The count per file
/// is exact; growing it needs a new review entry here.
const ALLOWED_LOCK_SITES: [(&str, usize, &str); 4] = [
    (
        "src/storage/escalation_deferral.rs",
        1,
        "write_open_report: raw fd write, lock dropped before the caller traces",
    ),
    (
        "src/storage/escalation_frame_reporting_8184_tests.rs",
        1,
        "test: holds the lock to prove the report writer serialises",
    ),
    (
        "src/daemon_runtime.rs",
        2,
        "cmd_bench: synchronous one-line stderr notices, no await",
    ),
    (
        "src/mcp/mod.rs",
        1,
        "MCP stdio read loop: the one reader owns the STDIN lock for the server's \
         life; tracing and every reply write stdout/stderr, never stdin, so no \
         worker can block on it",
    ),
];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The identifier that ends right before byte `end` of `line`, if any.
fn ident_before(line: &str, end: usize) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut start = end;
    while start > 0 && is_ident_byte(bytes[start - 1]) {
        start -= 1;
    }
    (start < end).then(|| &line[start..end])
}

/// Names bound to an unlocked stdio handle in `code`: `let [mut] x = ..stdout()`
/// (the constructor on the same line) and `x: [&][mut] [path::]Stdout` params.
fn stdio_bindings(code: &[String]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in code {
        if let Some(rest) = line.trim_start().strip_prefix("let ")
            && STDIO_CTORS.iter().any(|c| line.contains(c))
        {
            let rest = rest.trim_start();
            let rest = rest.strip_prefix("mut ").unwrap_or(rest).trim_start();
            let name: String = rest
                .bytes()
                .take_while(|b| is_ident_byte(*b))
                .map(char::from)
                .collect();
            if !name.is_empty() {
                names.insert(name);
            }
        }
        for ty in STDIO_HANDLE_TYPES {
            let mut from = 0;
            while let Some(off) = line[from..].find(ty) {
                let at = from + off;
                let after = at + ty.len();
                from = after;
                let bytes = line.as_bytes();
                let whole = (at == 0 || !is_ident_byte(bytes[at - 1]))
                    && (after == bytes.len() || !is_ident_byte(bytes[after]));
                if !whole {
                    continue;
                }
                // Walk back over `path::`, `mut`, `&` and whitespace to `name:`.
                let mut head = line[..at].trim_end();
                while let Some(stripped) = head.strip_suffix("::") {
                    head = stripped;
                    while head.as_bytes().last().is_some_and(|b| is_ident_byte(*b)) {
                        head = &head[..head.len() - 1];
                    }
                    head = head.trim_end();
                }
                head = head.strip_suffix("mut").map_or(head, str::trim_end);
                head = head.strip_suffix('&').map_or(head, str::trim_end);
                if let Some(before_colon) = head.strip_suffix(':')
                    && !before_colon.ends_with(':')
                {
                    let before_colon = before_colon.trim_end();
                    if let Some(name) = ident_before(before_colon, before_colon.len()) {
                        names.insert(name.to_string());
                    }
                }
            }
        }
    }
    names
}

/// The 1-based lines of `text` that acquire or hold a process-global stdio
/// lock, under ANY binding name or line split.
fn lock_lines(text: &str) -> Vec<usize> {
    let code: Vec<String> = text
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                String::new()
            } else {
                l.to_string()
            }
        })
        .collect();
    let names = stdio_bindings(&code);
    let receivers: Vec<String> = STDIO_CTORS
        .iter()
        .map(|c| (*c).to_string())
        .chain(STDIO_CONVENTIONAL_NAMES.iter().map(|n| (*n).to_string()))
        .chain(names.iter().cloned())
        .collect();
    let compact: Vec<String> = code
        .iter()
        .map(|l| l.split_whitespace().collect())
        .collect();
    let ends_with_receiver = |line: &str, recv: &str| {
        line.ends_with(recv)
            && (recv.ends_with(')') || ident_before(line, line.len()).is_some_and(|id| id == recv))
    };
    let mut hits = Vec::new();
    for (idx, line) in compact.iter().enumerate() {
        let mut hit = STDIO_LOCK_TYPES.iter().any(|t| code[idx].contains(t));
        let mut from = 0;
        while !hit && let Some(off) = line[from..].find(".lock()") {
            let at = from + off;
            from = at + 1;
            hit = receivers.iter().any(|r| ends_with_receiver(&line[..at], r));
        }
        if !hit && line.starts_with(".lock()") && idx > 0 {
            let prev = &compact[idx - 1];
            hit = receivers.iter().any(|r| ends_with_receiver(prev, r));
        }
        if hit {
            hits.push(idx + 1);
        }
    }
    hits
}

/// Returns `(relative path, [line numbers])` for every file with a lock site.
fn lock_sites(root: &Path) -> Vec<(String, Vec<usize>)> {
    let mut files = Vec::new();
    rust_sources(&root.join("src"), &mut files);
    files.sort();
    let mut sites = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(root)
            .expect("under manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&file).expect("read source");
        let lines = lock_lines(&text);
        if !lines.is_empty() {
            sites.push((rel, lines));
        }
    }
    sites
}

/// The detector itself is pinned: every spelling of the class is a site, and
/// the unlocked forms and unrelated mutexes are not (#9185 L-E).
#[test]
fn detector_finds_every_spelling_of_the_class_9185() {
    const CASES: [(&str, &str, usize); 12] = [
        ("literal stdout", "let mut so = stdout.lock();", 1),
        (
            "renamed binding",
            "let stdout_handle = std::io::stdout();\nlet g = stdout_handle.lock();",
            1,
        ),
        (
            "renamed stderr",
            "let h = io::stderr();\nlet g = h.lock();",
            1,
        ),
        (
            "stdin reader",
            concat!(
                "let stdin = std::io::",
                "std",
                "in();\nlet mut r = stdin.lock();"
            ),
            1,
        ),
        ("ctor chain", "let g = std::io::stdout().lock();", 1),
        ("ctor split", "let g = std::io::stderr()\n    .lock();", 1),
        (
            "param binding",
            "fn f(out: &mut std::io::Stdout) {\n    let g = out.lock();\n}",
            1,
        ),
        ("guard type", "fn f(g: StdoutLock<'_>) {}", 1),
        (
            "unlocked handle",
            "let mut so = std::io::stdout();\nwriteln!(so, \"x\");",
            0,
        ),
        (
            "other mutex",
            "let g = STATE.lock().unwrap_or_else(|e| e.into_inner());",
            0,
        ),
        (
            "similar name",
            "let stdout_count = 3;\nlet g = stdout_count_lock.lock();",
            0,
        ),
        ("comment", "// stdout.lock() was the old form", 0),
    ];
    // The joined needle is byte-identical to the constructor call, so the
    // stdin cells above still exercise the real spelling.
    assert_eq!(STDIN_CTOR, ["std", "in", "()"].concat());
    for (name, src, want) in CASES {
        assert_eq!(lock_lines(src).len(), want, "case {name}: {src}");
    }
}

#[test]
fn no_stdio_lock_outside_reviewed_sync_sites_8779() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for (rel, lines) in lock_sites(root) {
        let allowed = ALLOWED_LOCK_SITES
            .iter()
            .find(|(path, _, _)| *path == rel)
            .map_or(0, |(_, count, _)| *count);
        if lines.len() > allowed {
            offenders.push(format!(
                "{rel}: {} lock site(s), {allowed} reviewed, lines {lines:?}",
                lines.len()
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "#8779: a process-global stdout/stderr lock held by a dispatch arm \
         deadlocks any worker thread that traces; pass the unlocked handle \
         instead: {offenders:?}"
    );
}

/// The allowlist only shrinks: an entry whose file no longer has that many
/// sites must be lowered, so a removed site cannot be silently re-added.
#[test]
fn reviewed_stdio_lock_allowlist_is_exact_8779() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sites = lock_sites(root);
    let mut stale = Vec::new();
    for (path, count, why) in ALLOWED_LOCK_SITES {
        let found = sites
            .iter()
            .find(|(rel, _)| rel == path)
            .map_or(0, |(_, lines)| lines.len());
        if found != count {
            stale.push(format!("{path}: allowlist {count}, found {found} ({why})"));
        }
    }
    assert!(
        stale.is_empty(),
        "#8779: lower the reviewed stdio lock allowlist to the real count: {stale:?}"
    );
}
