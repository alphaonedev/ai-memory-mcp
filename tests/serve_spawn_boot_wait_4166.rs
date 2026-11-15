//! #4166: every integration test that spawns the real `serve` binary must keep
//! the boot off the embedder download path, and must not fail because a healthy
//! boot was slow.
//!
//! Class: a test spawns `serve` (with or without `env_clear`) and waits on
//! `/health`, a log line or the db file under a fixed deadline. Without
//! `AI_MEMORY_EMBED_OFFLINE` the semantic tier tries a model fetch under an
//! empty `HOME`, the boot outlasts the deadline on a loaded runner, and the
//! test fails although nothing is wrong (PR #8602 linux-fed, PR #8705
//! macos-fed).
//!
//! Invariants, checked here over every `tests/**/*.rs` source file:
//!   (a) EVERY spawn of the binary with a `"serve"` argument carries the
//!       embedder-offline knob. A spawn is the window from the command's
//!       constructor (`Command::new(`, `cargo_bin(`, or a call to a function of
//!       the same file that builds the command) to its `.spawn()` /
//!       `.output()` / `.assert()` / `.status()`, widened to the whole function
//!       when the command was built earlier. The window must contain
//!       `common::serve_test_env(`, an `AI_MEMORY_EMBED_OFFLINE` or
//!       `HF_HUB_OFFLINE` literal (the product honours both, see
//!       `src/embeddings.rs:1985-1991` `remote_fetch_disabled()`), or a call to
//!       a command-building function whose own body sets one of them. A knob
//!       elsewhere in the file does not count. A file is exempt only through a
//!       row in [`EXEMPT`] whose checkable [`ExemptKind`] the guard verifies;
//!   (b) every function under `tests/common/` that builds the binary command
//!       sets the knob itself, so a `"serve"` passed to a shared helper in
//!       another file is covered;
//!   (c) in every file that spawns `serve`, every loop that probes `/health`
//!       and sleeps (a boot wait, counted `for _ in 0..N` or `loop` / `while`
//!       against a deadline) contains `try_wait(` or calls a function of the
//!       same file whose body calls `try_wait(`, so the wait ends on child
//!       exit (with the child's stderr) or on a health answer, never only on a
//!       timeout;
//!   (d) such a file never asserts on a bare `Instant::now() < deadline` while
//!       the child is still running unless the handle reaps the child on drop.
//!
//! The scan is a text scan with named fixtures proving both directions, and the
//! real-tree tests delete every single instance of the knob and of the exit
//! check in memory and require the guard to turn red at that instance.

use std::fs;
use std::path::{Path, PathBuf};

/// The knobs the spawned child may carry. `AI_MEMORY_EMBED_OFFLINE` is the
/// product's own switch; `HF_HUB_OFFLINE` is read by the same
/// `remote_fetch_disabled()` (`src/embeddings.rs:1985-1991`), so it blocks the
/// download identically.
const KNOB_LITERALS: [&str; 2] = ["\"AI_MEMORY_EMBED_OFFLINE\"", "\"HF_HUB_OFFLINE\""];

/// The shared helper every serve spawn may call (tests/common/mod.rs).
const SERVE_ENV_HELPER: &str = "serve_test_env(";

/// A line that builds the real binary's command: the cargo-provided path or the
/// `assert_cmd`-style lookup.
const BIN_MARKERS: [&str; 2] = ["CARGO_BIN_EXE_ai-memory", "cargo_bin("];

/// A call that starts a command for any program.
const COMMAND_NEW: &str = "Command::new(";

/// What a command ends in. Only `.spawn()` leaves a child running.
const SPAWN_TERMINAL: &str = ".spawn()";
const WAIT_TERMINALS: [&str; 3] = [".output()", ".assert()", ".status()"];

const SERVE_LITERAL: &str = "\"serve\"";
const HEALTH_LITERAL: &str = "/health";
const TRY_WAIT_CALL: &str = "try_wait(";
const SLEEP_CALL: &str = "sleep(";

/// Tokens of a probe inside a loop whose URL was built above it.
const PROBE_TOKENS: [&str; 6] = ["curl", "reqwest", "client", "url", "TcpStream", "health"];

/// Closure-parameter types that mark a wait helper whose probe is passed in.
const PROBE_CLOSURE_PARAMS: [&str; 2] = ["FnMut() -> bool", "Fn() -> bool"];

/// How many lines below `fn` the signature is searched for a probe closure.
const PROBE_PARAM_HEADER_LINES: usize = 6;

/// This guard's own source quotes every pattern it looks for.
const SELF_FILE: &str = "serve_spawn_boot_wait_4166.rs";

/// What the guard verifies about an exempt file. A row with only a free-text
/// reason is not accepted: each kind is a property the guard re-checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExemptKind {
    /// Every `"serve"` spawn in the file ends in `.output()` / `.assert()` /
    /// `.status()` (the test waits for the process to exit: help text or a
    /// refusal) and the file never probes `/health`. No daemon outlives the
    /// call, so the embedder is not on any boot path.
    NoLongLivedChild,
    /// The `"serve"` literals are data (a table of subcommand names) and no
    /// spawn window forms around them.
    NoSpawnWindow,
}

/// Files that name `"serve"` and spawn the binary but are deliberately not
/// given the knob, each with a checkable kind and the human reason.
const EXEMPT: &[(&str, ExemptKind, &str)] = &[
    (
        "cli_integration.rs",
        ExemptKind::NoLongLivedChild,
        "serve is spawned only with `--help` from a subcommand table and ends in \
         `.assert()`; no daemon boots",
    ),
    (
        "cli_serve_help_text.rs",
        ExemptKind::NoLongLivedChild,
        "asserts `serve --help` text and a clap refusal; every spawn ends in \
         `.assert()`, no daemon boots",
    ),
    (
        "credential_to_sink_3711.rs",
        ExemptKind::NoLongLivedChild,
        "serve is refused (--db with --store-url conflict) before any embedder \
         init; the test waits for the process exit",
    ),
    (
        "store_url_ambiguous_userinfo_6096.rs",
        ExemptKind::NoLongLivedChild,
        "serve is refused (ambiguous store URL) before any embedder init; the \
         test waits for the process exit",
    ),
    (
        "federation_peer_posture_3582.rs",
        ExemptKind::NoLongLivedChild,
        "every serve spawn is refused by the peer-posture gate before the \
         database opens; output() waits for the exit, there is no /health wait",
    ),
];

// ---------------------------------------------------------------------------
// Source model
// ---------------------------------------------------------------------------

/// One source line with comments dropped.
struct Line {
    /// 1-based line number in the file.
    n: usize,
    /// The line without a trailing `//` comment.
    text: String,
    /// `text` with the contents of string and char literals blanked, for brace
    /// counting and token matching that must not see literal text.
    bare: String,
}

/// Split a line into code text and blanked text, dropping a trailing comment.
fn split_line(l: &str) -> (String, String) {
    let chars: Vec<char> = l.chars().collect();
    let mut bare = chars.clone();
    let mut cut = chars.len();
    let mut in_str = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            if c == '\\' {
                bare[i] = ' ';
                if i + 1 < chars.len() {
                    bare[i + 1] = ' ';
                }
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            } else {
                bare[i] = ' ';
            }
        } else if c == '"' {
            in_str = true;
        } else if c == '\'' {
            if i + 2 < chars.len() && chars[i + 1] != '\\' && chars[i + 2] == '\'' {
                bare[i + 1] = ' ';
                i += 3;
                continue;
            }
            if i + 3 < chars.len() && chars[i + 1] == '\\' && chars[i + 3] == '\'' {
                bare[i + 2] = ' ';
                i += 4;
                continue;
            }
        } else if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            cut = i;
            break;
        }
        i += 1;
    }
    (chars[..cut].iter().collect(), bare[..cut].iter().collect())
}

/// Source lines with comment-only lines and trailing comments dropped.
fn code_lines(src: &str) -> Vec<Line> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
        .map(|(i, l)| {
            let (text, bare) = split_line(l);
            Line {
                n: i + 1,
                text,
                bare,
            }
        })
        .collect()
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Whether `text` calls `name(` as a free function (not a method, not a path
/// segment, not the definition). `allow_method` also accepts `.name(`.
fn has_call(text: &str, name: &str, allow_method: bool) -> bool {
    call_positions(text, name, allow_method).next().is_some()
}

fn call_positions<'a>(
    text: &'a str,
    name: &str,
    allow_method: bool,
) -> impl Iterator<Item = usize> + 'a {
    let needle = format!("{name}(");
    text.match_indices(&needle)
        .map(|(i, _)| i)
        .filter(move |&i| {
            let before = &text[..i];
            let prev = before.chars().next_back();
            if prev.is_some_and(is_ident) || prev == Some(':') {
                return false;
            }
            if prev == Some('.') {
                return allow_method;
            }
            !before.trim_end().ends_with("fn")
        })
        .collect::<Vec<_>>()
        .into_iter()
}

/// A function of the file: its name and the inclusive line-index range up to
/// the next function start.
struct FnInfo {
    name: String,
    start: usize,
    end: usize,
    /// The signature returns a `Command`: the function is a command builder.
    returns_command: bool,
}

fn fn_name(bare: &str) -> Option<String> {
    let t = bare.trim_start();
    let idx = t.find("fn ")?;
    let head = &t[..idx];
    let modifiers_only = head.split_whitespace().all(|w| {
        w == "pub" || w == "async" || w == "const" || w == "unsafe" || w.starts_with("pub(")
    });
    if !modifiers_only {
        return None;
    }
    let rest = &t[idx + 3..];
    let name: String = rest.chars().take_while(|c| is_ident(*c)).collect();
    (!name.is_empty()).then_some(name)
}

fn fn_infos(lines: &[Line]) -> Vec<FnInfo> {
    let starts: Vec<(usize, String)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| fn_name(&l.bare).map(|n| (i, n)))
        .collect();
    starts
        .iter()
        .enumerate()
        .map(|(k, (start, name))| {
            // The body ends where its braces balance; a function without a
            // body (a trait item) or with unbalanced raw-string braces ends
            // before the next function start instead.
            let limit = starts.get(k + 1).map_or(lines.len(), |(s, _)| *s) - 1;
            let mut depth: i64 = 0;
            let mut opened = false;
            let mut end = limit;
            for (n, line) in lines.iter().enumerate().skip(*start) {
                let open = i64::try_from(line.bare.matches('{').count()).unwrap_or(0);
                let close = i64::try_from(line.bare.matches('}').count()).unwrap_or(0);
                opened |= open > 0;
                depth += open - close;
                if opened && depth <= 0 {
                    end = n;
                    break;
                }
                if n >= limit && !opened {
                    break;
                }
            }
            FnInfo {
                name: name.clone(),
                start: *start,
                end,
                returns_command: returns_command(lines, *start),
            }
        })
        .collect()
}

/// Whether the signature starting at line `start` returns a `Command`.
fn returns_command(lines: &[Line], start: usize) -> bool {
    let mut sig = String::new();
    for line in &lines[start..] {
        sig.push_str(&line.bare);
        sig.push(' ');
        if line.bare.contains('{') || line.bare.trim_end().ends_with(';') {
            break;
        }
    }
    let head = sig.split('{').next().unwrap_or("");
    head.split("->").nth(1).is_some_and(|ret| {
        ret.trim_start()
            .trim_start_matches("std::process::")
            .starts_with("Command")
    })
}

fn range_text(lines: &[Line], a: usize, b: usize) -> String {
    lines[a..=b]
        .iter()
        .map(|l| l.text.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn sets_knob_text(text: &str) -> bool {
    text.contains(SERVE_ENV_HELPER) || KNOB_LITERALS.iter().any(|k| text.contains(k))
}

fn builds_binary_command(text: &str) -> bool {
    BIN_MARKERS.iter().any(|m| text.contains(m))
}

/// Upper bound on call-graph rounds when deriving command builders.
const MAX_CTOR_ROUNDS: usize = 12;

/// The analysed shape of one file.
struct Model {
    lines: Vec<Line>,
    fns: Vec<FnInfo>,
    /// Functions that build the binary's command, directly or through another
    /// such function: `(name, sets_knob)`.
    ctors: Vec<(String, bool)>,
    /// Names of the functions that build the binary's command themselves (a
    /// method such as `Sandbox::base_command` is called as `sb.base_command()`,
    /// so these also match as method calls; a function that only wraps one
    /// matches as a free call).
    direct: Vec<String>,
}

impl Model {
    fn new(src: &str) -> Self {
        let lines = code_lines(src);
        let fns = fn_infos(&lines);
        let bodies: Vec<String> = fns
            .iter()
            .map(|f| range_text(&lines, f.start, f.end))
            .collect();
        // Fixpoint over the call graph, recomputed from the previous round so
        // two functions with one name (a free fn and a method) cannot flip each
        // other: a name sets the knob when any function of that name does (a method
        // `command` that wraps the free fn `command` shares its name). Bounded; the table only grows, so it settles in a few rounds.
        let mut ctors: Vec<(String, bool)> = Vec::new();
        for _ in 0..MAX_CTOR_ROUNDS {
            let mut next: Vec<(String, bool)> = Vec::new();
            for (f, body) in fns.iter().zip(&bodies) {
                let direct = builds_binary_command(body) || f.returns_command;
                let via: Vec<&(String, bool)> = ctors
                    .iter()
                    .filter(|(n, _)| has_call(body, n, false))
                    .collect();
                if !direct && via.is_empty() {
                    continue;
                }
                let knob = sets_knob_text(body) || via.iter().any(|(_, k)| *k);
                match next.iter_mut().find(|(n, _)| *n == f.name) {
                    Some(entry) => entry.1 |= knob,
                    None => next.push((f.name.clone(), knob)),
                }
            }
            next.sort();
            ctors.sort();
            if next == ctors {
                break;
            }
            ctors = next;
        }
        let direct = fns
            .iter()
            .zip(&bodies)
            .filter(|(f, body)| builds_binary_command(body) || f.returns_command)
            .map(|(f, _)| f.name.clone())
            .collect();
        Self {
            lines,
            fns,
            ctors,
            direct,
        }
    }

    /// `Some(Wait)` when the text calls a command helper of this file whose body
    /// only runs the command to completion (`.output()` / `.assert()` /
    /// `.status()`, never `.spawn()`), as a `run_bin` helper does.
    fn helper_terminal(&self, text: &str) -> Option<Terminal> {
        self.fns
            .iter()
            .filter(|f| {
                self.ctors.iter().any(|(n, _)| *n == f.name)
                    && has_call(text, &f.name, self.method_call_ok(&f.name))
            })
            .any(|f| {
                let body = range_text(&self.lines, f.start, f.end);
                !body.contains(SPAWN_TERMINAL) && WAIT_TERMINALS.iter().any(|t| body.contains(t))
            })
            .then_some(Terminal::Wait)
    }

    /// A direct ctor also matches as a method call (`sb.base_command()`),
    /// except under a name that std's `Command` / `Child` use for their own
    /// methods, which would match every `cmd.spawn()` of the file.
    fn method_call_ok(&self, name: &str) -> bool {
        const STD_COMMAND_METHODS: [&str; 8] = [
            "spawn",
            "output",
            "status",
            "assert",
            "args",
            "arg",
            "env",
            "current_dir",
        ];
        self.direct.iter().any(|d| d == name) && !STD_COMMAND_METHODS.contains(&name)
    }

    fn calls_ctor(&self, text: &str) -> bool {
        self.ctors
            .iter()
            .any(|(n, _)| has_call(text, n, self.method_call_ok(n)))
    }

    fn calls_knob_ctor(&self, text: &str) -> bool {
        self.ctors
            .iter()
            .any(|(n, k)| *k && has_call(text, n, self.method_call_ok(n)))
    }

    /// Whether the line starts a command for the binary (or any program).
    fn is_spawn_start(&self, text: &str) -> bool {
        text.contains(COMMAND_NEW) || text.contains("cargo_bin(") || self.calls_ctor(text)
    }
}

fn terminal_of(text: &str) -> Option<Terminal> {
    if text.contains(SPAWN_TERMINAL) {
        Some(Terminal::Spawn)
    } else if WAIT_TERMINALS.iter().any(|t| text.contains(t)) {
        Some(Terminal::Wait)
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Terminal {
    Spawn,
    Wait,
}

/// One spawn of the binary with a `"serve"` argument.
struct Window {
    /// Line of the `"serve"` literal, the line the failure names.
    serve_line: usize,
    /// Inclusive 1-based line range of the command.
    first: usize,
    last: usize,
    /// How the command ends, `None` when no terminal call follows in the
    /// function.
    terminal: Option<Terminal>,
    sets_knob: bool,
}

/// `x == "serve"` / `x != "serve"` only compares a name; it is not an argument.
fn is_verb_comparison(text: &str) -> bool {
    text.contains("== \"serve\"") || text.contains("!= \"serve\"")
}

fn serve_windows(m: &Model) -> Vec<Window> {
    let mut out = Vec::new();
    for (i, l) in m.lines.iter().enumerate() {
        if !l.text.contains(SERVE_LITERAL) || is_verb_comparison(&l.text) {
            continue;
        }
        // Innermost function whose body holds the literal; a literal outside
        // every function (a table constant) forms no spawn window.
        let Some((fn_first, fn_last)) = m
            .fns
            .iter()
            .rev()
            .find(|f| f.start <= i && i <= f.end)
            .map(|f| (f.start, f.end))
        else {
            continue;
        };
        let next_terminal = (i..=fn_last).find(|&k| terminal_of(&m.lines[k].text).is_some());
        let last = next_terminal.unwrap_or(fn_last);
        let prev_terminal = (fn_first..i)
            .rev()
            .find(|&k| terminal_of(&m.lines[k].text).is_some());
        let mut first = prev_terminal.map_or(fn_first, |p| p + 1);
        if !(first..=last).any(|k| m.is_spawn_start(&m.lines[k].text)) {
            first = fn_first;
        }
        if !(first..=last).any(|k| m.is_spawn_start(&m.lines[k].text)) {
            continue;
        }
        let text = range_text(&m.lines, first, last);
        out.push(Window {
            serve_line: l.n,
            first: m.lines[first].n,
            last: m.lines[last].n,
            terminal: next_terminal
                .and_then(|k| terminal_of(&m.lines[k].text))
                .or_else(|| m.helper_terminal(&text)),
            sets_knob: sets_knob_text(&text) || m.calls_knob_ctor(&text),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Invariant (a): every serve spawn carries the knob
// ---------------------------------------------------------------------------

/// Serve-literal lines of the spawns that carry no knob.
fn spawns_without_knob(src: &str) -> Vec<usize> {
    serve_windows(&Model::new(src))
        .iter()
        .filter(|w| !w.sets_knob)
        .map(|w| w.serve_line)
        .collect()
}

// ---------------------------------------------------------------------------
// Invariant (b): shared spawners set the knob themselves
// ---------------------------------------------------------------------------

/// Lines of the functions that build the binary's command from a body that
/// sets no knob (used on every file under `tests/common/`).
fn common_spawners_without_knob(src: &str) -> Vec<usize> {
    let m = Model::new(src);
    m.fns
        .iter()
        .filter(|f| m.ctors.iter().any(|(n, knob)| *n == f.name && !*knob))
        .map(|f| m.lines[f.start].n)
        .collect()
}

// ---------------------------------------------------------------------------
// Invariant (c): every boot wait ends on child exit or health
// ---------------------------------------------------------------------------

/// One loop of the file: inclusive 1-based line range.
struct LoopInfo {
    first: usize,
    last: usize,
    probes_health: bool,
    exit_aware: bool,
}

fn loop_header(bare: &str) -> bool {
    let t = bare.trim_start();
    (t.starts_with("for ")
        || t.starts_with("while ")
        || t.starts_with("loop ")
        || t.contains("= loop {"))
        && t.contains('{')
}

/// Brace-matched loops of a source, each classified as a boot-wait probe and
/// as exit-aware.
fn loops(m: &Model) -> Vec<LoopInfo> {
    let health_fns: Vec<&str> = m
        .fns
        .iter()
        .filter(|f| range_text(&m.lines, f.start, f.end).contains(HEALTH_LITERAL))
        .map(|f| f.name.as_str())
        .collect();
    let exit_fns: Vec<&str> = m
        .fns
        .iter()
        .filter(|f| range_text(&m.lines, f.start, f.end).contains(TRY_WAIT_CALL))
        .map(|f| f.name.as_str())
        .collect();
    let mut out = Vec::new();
    for (i, l) in m.lines.iter().enumerate() {
        if !loop_header(&l.bare) {
            continue;
        }
        let mut depth: i64 = 0;
        let mut last = i;
        for (k, line) in m.lines.iter().enumerate().skip(i) {
            depth += i64::try_from(line.bare.matches('{').count()).unwrap_or(0);
            depth -= i64::try_from(line.bare.matches('}').count()).unwrap_or(0);
            last = k;
            if depth <= 0 {
                break;
            }
        }
        let text = range_text(&m.lines, i, last);
        // The URL is often built before the loop (`let url = format!(".../health")`),
        // so a sleeping loop that uses a URL or an HTTP client counts when the
        // enclosing function names `/health` above it.
        let url_built_above = m
            .fns
            .iter()
            .rev()
            .find(|f| f.start <= i && i <= f.end)
            .is_some_and(|f| range_text(&m.lines, f.start, i).contains(HEALTH_LITERAL))
            && PROBE_TOKENS.iter().any(|t| text.contains(t));
        // A wait helper that takes its probe as a closure (`impl FnMut() -> bool`)
        // names no `/health` itself; its callers do.
        let probe_param = m
            .fns
            .iter()
            .rev()
            .find(|f| f.start <= i && i <= f.end)
            .is_some_and(|f| {
                let header = range_text(
                    &m.lines,
                    f.start,
                    (f.start + PROBE_PARAM_HEADER_LINES).min(i),
                );
                PROBE_CLOSURE_PARAMS.iter().any(|p| header.contains(p))
            });
        let probes_health = (text.contains(HEALTH_LITERAL)
            || url_built_above
            || probe_param
            || health_fns.iter().any(|f| has_call(&text, f, true)))
            && text.contains(SLEEP_CALL);
        let exit_aware =
            text.contains(TRY_WAIT_CALL) || exit_fns.iter().any(|f| has_call(&text, f, true));
        out.push(LoopInfo {
            first: l.n,
            last: m.lines[last].n,
            probes_health,
            exit_aware,
        });
    }
    out
}

/// Whether the file spawns the binary with a `"serve"` argument at all.
fn spawns_serve(m: &Model) -> bool {
    !serve_windows(m).is_empty()
}

/// Lines of boot-wait loops in a file that spawns `serve` and never checks
/// child exit. Empty for a file that spawns no `serve`.
fn waits_without_exit_check(src: &str) -> Vec<usize> {
    let m = Model::new(src);
    if !spawns_serve(&m) {
        return Vec::new();
    }
    loops(&m)
        .iter()
        .filter(|l| l.probes_health && !l.exit_aware)
        .map(|l| l.first)
        .collect()
}

// ---------------------------------------------------------------------------
// Invariant (d): no bare deadline assert while the child still runs
// ---------------------------------------------------------------------------

/// Whether `src` is in the class: clears the env, spawns `serve`, probes
/// `/health`. Returns the line of the first `env_clear()` call.
fn class_line(src: &str) -> Option<usize> {
    let lines = code_lines(src);
    let has = |needle: &str| lines.iter().any(|l| l.text.contains(needle));
    if !(has(SERVE_LITERAL) && has(HEALTH_LITERAL)) {
        return None;
    }
    lines
        .iter()
        .find(|l| l.text.contains("env_clear()"))
        .map(|l| l.n)
}

/// `Some(line)` of an `assert!(` whose condition is a bare
/// `Instant::now() < <deadline>` comparison in a file of the class whose
/// child handle does not reap on drop (`impl Drop for` plus `.kill()`).
fn bare_deadline_assert(src: &str) -> Option<usize> {
    class_line(src)?;
    let code = code_lines(src);
    let reaps_on_drop = code.iter().any(|l| l.text.contains("impl Drop for"))
        && code.iter().any(|l| l.text.contains(".kill()"));
    if reaps_on_drop {
        return None;
    }
    let lines: Vec<&str> = src.lines().collect();
    lines.iter().enumerate().find_map(|(i, l)| {
        let t = l.trim();
        if t.starts_with("//") || !t.starts_with("assert!(") {
            return None;
        }
        // The condition is the rest of this line or the next one.
        let cond = if t == "assert!(" {
            lines.get(i + 1).map_or("", |n| n.trim())
        } else {
            t
        };
        (cond.contains("Instant::now() <") && cond.contains("deadline")).then_some(i + 1)
    })
}

// ---------------------------------------------------------------------------
// Exempt rows
// ---------------------------------------------------------------------------

/// Why an exempt row no longer holds, `None` when it does.
fn exempt_violation(src: &str, kind: ExemptKind) -> Option<String> {
    let m = Model::new(src);
    if !m.lines.iter().any(|l| l.text.contains(SERVE_LITERAL)) {
        return Some("no longer names serve; drop the row".to_owned());
    }
    let windows = serve_windows(&m);
    match kind {
        ExemptKind::NoSpawnWindow => windows
            .first()
            .map(|w| format!("a spawn window forms at line {}", w.serve_line)),
        ExemptKind::NoLongLivedChild => {
            if windows.is_empty() {
                return Some("no spawn window left; drop the row".to_owned());
            }
            if windows.iter().all(|w| w.sets_knob) {
                return Some("every spawn now sets the knob; drop the row".to_owned());
            }
            if let Some(w) = windows.iter().find(|w| w.terminal != Some(Terminal::Wait)) {
                return Some(format!(
                    "the spawn at line {} does not end in output()/assert()/status()",
                    w.serve_line
                ));
            }
            m.lines
                .iter()
                .find(|l| l.text.contains(HEALTH_LITERAL))
                .map(|l| format!("the file probes /health at line {}", l.n))
        }
    }
}

// ---------------------------------------------------------------------------
// Tree walk
// ---------------------------------------------------------------------------

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") && !p.ends_with(SELF_FILE) {
            out.push(p);
        }
    }
}

fn all_test_sources() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut out = Vec::new();
    rust_sources(&root, &mut out);
    assert!(out.len() > 100, "scan found only {} test files", out.len());
    out
}

fn exempt_row(path: &Path) -> Option<&'static (&'static str, ExemptKind, &'static str)> {
    let name = path.file_name().and_then(|n| n.to_str())?;
    EXEMPT.iter().find(|(f, _, _)| *f == name)
}

fn is_common(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "common")
}

fn rel(path: &Path) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `file:line` strings for every line a per-file check returns.
fn scan(check: fn(&str) -> Vec<usize>, skip_exempt: bool, only_common: bool) -> Vec<String> {
    all_test_sources()
        .iter()
        .filter(|p| !(skip_exempt && exempt_row(p).is_some()))
        .filter(|p| !only_common || is_common(p))
        .flat_map(|p| {
            check(&read(p))
                .into_iter()
                .map(|line| format!("{}:{line}", rel(p)))
                .collect::<Vec<_>>()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// 1-based line of the first line of `src` containing `needle`.
fn line_of(src: &str, needle: &str) -> usize {
    src.lines()
        .position(|l| l.contains(needle))
        .unwrap_or_else(|| panic!("fixture lacks {needle}"))
        + 1
}

/// Fixture: the shape of the sites that flaked.
const SPAWN_WITHOUT_KNOB: &str = r#"
fn command(root: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("HOME", root)
        .env("RUST_LOG", "error");
    cmd
}
fn boot(root: &Path) {
    let mut cmd = command(root);
    cmd.args(["serve", "--port", "0"]);
    let url = "https://127.0.0.1/api/v1/health";
}
"#;

/// Fixture: two serve spawns in one file; the first has no knob, the second
/// has one. The old per-file check passed this whole file.
const TWO_SPAWNS: &str = r#"
fn first_spawn(db: &Path) {
    let child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args(["serve", "--port", "0"])
        .env("RUST_LOG", "error")
        .spawn()
        .unwrap();
}
fn second_spawn(db: &Path) {
    let child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args(["serve", "--port", "0"])
        .env("AI_MEMORY_EMBED_OFFLINE", "1")
        .spawn()
        .unwrap();
}
"#;

#[test]
fn guard_flags_a_spawn_without_the_knob_4166() {
    assert_eq!(
        spawns_without_knob(SPAWN_WITHOUT_KNOB),
        vec![line_of(SPAWN_WITHOUT_KNOB, "\"serve\"")]
    );
}

#[test]
fn guard_flags_a_spawn_without_env_clear_or_health_wait_4166() {
    // The class is every serve spawn, not only cleared-env /health waiters.
    let inherited = SPAWN_WITHOUT_KNOB.replace("cmd.env_clear()\n        .env(", "cmd.env(");
    assert_eq!(
        spawns_without_knob(&inherited),
        vec![line_of(&inherited, "\"serve\"")]
    );
    let log_wait = SPAWN_WITHOUT_KNOB.replace("/health", "/ready-log");
    assert_eq!(
        spawns_without_knob(&log_wait),
        vec![line_of(&log_wait, "\"serve\"")]
    );
    let cargo_bin_lookup = SPAWN_WITHOUT_KNOB.replace(
        "Command::new(env!(\"CARGO_BIN_EXE_ai-memory\"))",
        "Command::new(cargo_bin(\"ai-memory\"))",
    );
    assert_eq!(
        spawns_without_knob(&cargo_bin_lookup),
        vec![line_of(&cargo_bin_lookup, "\"serve\"")]
    );
}

#[test]
fn guard_accepts_the_helper_or_either_knob_literal_4166() {
    for knob in ["AI_MEMORY_EMBED_OFFLINE", "HF_HUB_OFFLINE"] {
        let with_knob = SPAWN_WITHOUT_KNOB.replace(
            ".env(\"RUST_LOG\", \"error\");",
            &format!(".env(\"{knob}\", \"1\");"),
        );
        assert!(with_knob.contains(&format!("\"{knob}\"")));
        assert!(spawns_without_knob(&with_knob).is_empty(), "{knob}");
    }
    let with_helper = SPAWN_WITHOUT_KNOB.replace(
        "    cmd\n}",
        "    common::serve_test_env(&mut cmd);\n    cmd\n}",
    );
    assert!(with_helper.contains("serve_test_env("));
    assert_eq!(spawns_without_knob(&with_helper), []);
}

#[test]
fn guard_ignores_a_knob_or_helper_that_is_only_in_a_comment_4166() {
    let commented = SPAWN_WITHOUT_KNOB.replace(
        "        .env(\"RUST_LOG\", \"error\");",
        "        // .env(\"AI_MEMORY_EMBED_OFFLINE\", \"1\")\n        // common::serve_test_env(&mut cmd);\n        .env(\"RUST_LOG\", \"error\"); // serve_test_env(&mut cmd)",
    );
    assert_eq!(
        spawns_without_knob(&commented),
        vec![line_of(&commented, "\"serve\"")]
    );
}

#[test]
fn guard_skips_files_that_never_spawn_serve_4166() {
    // Spawns the binary but never with a serve argument.
    let other_verb = SPAWN_WITHOUT_KNOB.replace("\"serve\"", "\"doctor\"");
    assert_eq!(spawns_without_knob(&other_verb), []);
    // Names serve but never spawns a command (a string or a table only).
    let no_spawn = "fn t() {\n    assert!(REASON.contains(\"serve\"));\n}\n";
    assert_eq!(spawns_without_knob(no_spawn), []);
}

/// M1: one knob elsewhere in the file must not pass a spawn that has none.
#[test]
fn guard_checks_each_spawn_not_the_file_4166() {
    assert_eq!(
        spawns_without_knob(TWO_SPAWNS),
        vec![line_of(TWO_SPAWNS, "\"serve\"")],
        "the first spawn is flagged at its own serve line, the second passes"
    );
    // Both spawns bare: both are named, in order.
    let both_bare = TWO_SPAWNS.replace("AI_MEMORY_EMBED_OFFLINE", "RUST_LOG");
    let first = line_of(&both_bare, "\"serve\"");
    let second = both_bare
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("\"serve\""))
        .map(|(i, _)| i + 1)
        .nth(1)
        .expect("second serve line");
    assert_eq!(spawns_without_knob(&both_bare), vec![first, second]);
    // A knob set on the helper that precedes the spawns in the same file but
    // outside the command does not count either.
    let knob_in_other_fn = format!(
        "{TWO_SPAWNS}\nfn unrelated(c: &mut Command) {{\n    c.env(\"HF_HUB_OFFLINE\", \"1\");\n}}\n"
    );
    assert_eq!(
        spawns_without_knob(&knob_in_other_fn),
        vec![line_of(&knob_in_other_fn, "\"serve\"")]
    );
}

/// A spawn through a command-building function is covered iff that function's
/// own body sets the knob.
#[test]
fn guard_verifies_the_builder_body_not_the_builder_name_4166() {
    let builder_without_knob = r#"
fn cmd(bin: &str) -> Command {
    let mut c = Command::new(bin);
    c.env("RUST_LOG", "error");
    c
}
fn boot(bin: &str) {
    let child = cmd(bin).args(["serve"]).spawn().unwrap();
}
"#;
    assert_eq!(
        spawns_without_knob(builder_without_knob),
        vec![line_of(builder_without_knob, "\"serve\"")]
    );
    let builder_with_knob =
        builder_without_knob.replace("\"RUST_LOG\", \"error\"", "\"HF_HUB_OFFLINE\", \"1\"");
    assert_eq!(spawns_without_knob(&builder_with_knob), []);
    // A builder that reaches the knob through another builder is covered.
    let chained = r#"
fn base(root: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    common::serve_test_env(&mut c);
    c
}
fn command(root: &Path) -> Command {
    base(root)
}
fn boot(root: &Path) {
    let child = command(root).args(["serve"]).spawn().unwrap();
}
"#;
    assert_eq!(spawns_without_knob(chained), []);
    let chained_bare = chained.replace("    common::serve_test_env(&mut c);\n", "");
    assert_eq!(
        spawns_without_knob(&chained_bare),
        vec![line_of(&chained_bare, "\"serve\"")]
    );
    // A command built earlier and given the knob in the spawning function.
    let built_earlier = r#"
fn base_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ai-memory"))
}
fn boot() {
    let mut cmd = base_command();
    common::serve_test_env(&mut cmd);
    cmd.args(["serve"]);
    let child = cmd.spawn().unwrap();
}
"#;
    assert_eq!(spawns_without_knob(built_earlier), []);
    let built_earlier_bare = built_earlier.replace("    common::serve_test_env(&mut cmd);\n", "");
    assert_eq!(
        spawns_without_knob(&built_earlier_bare),
        vec![line_of(&built_earlier_bare, "\"serve\"")]
    );
}

/// An arg vector built first and spawned through a builder later.
#[test]
fn guard_covers_a_serve_arg_vector_spawned_later_4166() {
    let vec_form = r#"
fn cmd(bin: &str) -> Command {
    let mut c = Command::new(bin);
    c.env("AI_MEMORY_EMBED_OFFLINE", "1");
    c
}
fn boot(bin: &str) {
    let args: Vec<String> = vec!["--db".into(), "serve".into()];
    let child = cmd(bin).args(&args).spawn().unwrap();
}
"#;
    assert_eq!(spawns_without_knob(vec_form), []);
    let raw = vec_form.replace("cmd(bin).args", "Command::new(bin).args");
    assert_eq!(spawns_without_knob(&raw), vec![line_of(&raw, "\"serve\"")]);
}

/// L2: a spawner under `tests/common/` that builds the binary's command must
/// set the knob itself, because the caller's file holds only a `"serve"`
/// literal and no spawn marker.
#[test]
fn guard_requires_common_spawners_to_set_the_knob_4166() {
    let bare_spawner = r#"
pub fn spawn_any(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args(args)
        .spawn()
        .unwrap()
}
"#;
    assert_eq!(
        common_spawners_without_knob(bare_spawner),
        vec![line_of(bare_spawner, "pub fn spawn_any")]
    );
    let helper_spawner = bare_spawner.replace(
        "    Command::new(env!(\"CARGO_BIN_EXE_ai-memory\"))\n        .args(args)",
        "    let mut cmd = Command::new(env!(\"CARGO_BIN_EXE_ai-memory\"));\n    super::serve_test_env(&mut cmd);\n    cmd.args(args)",
    );
    assert!(helper_spawner.contains("serve_test_env("));
    assert_eq!(common_spawners_without_knob(&helper_spawner), []);
    let knob_spawner = bare_spawner.replace(
        ".args(args)",
        ".env(\"AI_MEMORY_EMBED_OFFLINE\", \"1\")\n        .args(args)",
    );
    assert_eq!(common_spawners_without_knob(&knob_spawner), []);
    // A wrapper over a bare spawner is itself a bare spawner.
    let wrapper = format!(
        "{bare_spawner}\npub fn spawn_serve(db: &Path) -> Child {{\n    spawn_any(&[\"serve\"])\n}}\n"
    );
    assert_eq!(
        common_spawners_without_knob(&wrapper),
        vec![
            line_of(&wrapper, "pub fn spawn_any"),
            line_of(&wrapper, "pub fn spawn_serve"),
        ]
    );
}

// --- (c) boot waits ---------------------------------------------------------

/// A serve spawn plus a counted `for _ in 0..N` /health wait.
const COUNTED_WAIT: &str = r#"
fn boot() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    common::serve_test_env(&mut cmd);
    let mut child = cmd.args(["serve"]).spawn().unwrap();
    let mut ok = false;
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if curl("https://127.0.0.1/api/v1/health") {
            ok = true;
            break;
        }
    }
    let _ = child.kill();
}
"#;

/// The same wait written as `loop` against a deadline.
const DEADLINE_WAIT: &str = r#"
fn boot() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    common::serve_test_env(&mut cmd);
    let mut child = cmd.args(["serve"]).spawn().unwrap();
    let deadline = Instant::now() + HANG_GUARD;
    loop {
        if curl("https://127.0.0.1/api/v1/health") {
            break;
        }
        if Instant::now() >= deadline {
            panic!("never healthy");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
"#;

/// And as `while` with the probe in a helper of the same file.
const HELPER_WAIT: &str = r#"
fn boot() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    common::serve_test_env(&mut cmd);
    let mut child = cmd.args(["serve"]).spawn().unwrap();
    while Instant::now() < deadline {
        if probe(port) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn probe(port: u16) -> bool {
    curl(&format!("https://127.0.0.1:{port}/api/v1/health"))
}
"#;

#[test]
fn guard_flags_a_boot_wait_without_a_child_exit_check_4166() {
    for (name, src, header) in [
        ("counted", COUNTED_WAIT, "for _ in 0..30"),
        ("deadline", DEADLINE_WAIT, "    loop {"),
        ("helper", HELPER_WAIT, "while Instant::now()"),
    ] {
        assert_eq!(
            waits_without_exit_check(src),
            vec![line_of(src, header)],
            "{name}"
        );
    }
}

#[test]
fn guard_accepts_a_boot_wait_that_checks_child_exit_4166() {
    let counted = COUNTED_WAIT.replace(
        "        if curl(",
        "        if let Ok(Some(status)) = child.try_wait() {\n            panic!(\"exited {status}\");\n        }\n        if curl(",
    );
    assert_eq!(waits_without_exit_check(&counted), []);
    let deadline = DEADLINE_WAIT.replace(
        "        if Instant::now() >= deadline {",
        "        if child.try_wait().unwrap().is_some() {\n            panic!(\"exited\");\n        }\n        if Instant::now() >= deadline {",
    );
    assert_eq!(waits_without_exit_check(&deadline), []);
    let helper = HELPER_WAIT.replace(
        "        if probe(port) {",
        "        if exited(&mut child) {\n            panic!(\"exited\");\n        }\n        if probe(port) {",
    ) + "fn exited(c: &mut Child) -> bool {\n    c.try_wait().is_ok_and(|s| s.is_some())\n}\n";
    assert_eq!(waits_without_exit_check(&helper), []);
    // A comment that mentions try_wait is not an exit check.
    let commented = COUNTED_WAIT.replace(
        "        if curl(",
        "        // child.try_wait() is not needed here\n        if curl(",
    );
    assert_eq!(
        waits_without_exit_check(&commented),
        vec![line_of(&commented, "for _ in 0..30")]
    );
}

#[test]
fn guard_leaves_waits_outside_serve_files_and_non_waits_alone_4166() {
    // No serve spawn in the file: not this guard's class.
    let no_serve = COUNTED_WAIT.replace("\"serve\"", "\"doctor\"");
    assert_eq!(waits_without_exit_check(&no_serve), []);
    // A loop that reads /health without sleeping is a measurement, not a wait.
    let measurement = COUNTED_WAIT.replace(
        "        std::thread::sleep(Duration::from_millis(100));\n",
        "",
    );
    assert_eq!(waits_without_exit_check(&measurement), []);
    // A sleeping loop that never touches /health is a different wait.
    let other = COUNTED_WAIT.replace("/api/v1/health", "/api/v1/other");
    assert_eq!(waits_without_exit_check(&other), []);
}

// --- (d) bare deadline asserts -----------------------------------------------

#[test]
fn guard_flags_a_bare_deadline_assert_and_accepts_a_reaping_wait_4166() {
    let bare = format!(
        "{SPAWN_WITHOUT_KNOB}\nfn wait() {{\n    assert!(\n        Instant::now() < deadline,\n        \"x\"\n    );\n}}\n"
    );
    assert_eq!(
        bare_deadline_assert(&bare),
        Some(line_of(&bare, "    assert!("))
    );
    let inline = format!(
        "{SPAWN_WITHOUT_KNOB}\nfn wait() {{\n    assert!(Instant::now() < deadline, \"x\");\n}}\n"
    );
    assert_eq!(
        bare_deadline_assert(&inline),
        Some(line_of(&inline, "assert!(Instant::now() < deadline"))
    );
    let reaping = format!(
        "{SPAWN_WITHOUT_KNOB}\nfn wait() {{\n    if Instant::now() >= deadline {{\n        let _ = child.kill();\n        panic!(\"x\");\n    }}\n}}\n"
    );
    assert_eq!(bare_deadline_assert(&reaping), None);
    // A handle that kills and reaps the child on drop makes the panic safe.
    let dropped = format!(
        "{bare}\nimpl Drop for Daemon {{\n    fn drop(&mut self) {{\n        let _ = self.child.kill();\n    }}\n}}\n"
    );
    assert_eq!(bare_deadline_assert(&dropped), None);
    // Outside the class the same assert is not this guard's business.
    let other = "fn wait() {\n    assert!(Instant::now() < deadline);\n}\n";
    assert_eq!(bare_deadline_assert(other), None);
}

// --- exempt rows ------------------------------------------------------------

#[test]
fn guard_checks_exempt_rows_against_their_kind_4166() {
    let refusal = r#"
fn refused() {
    let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .args(["serve", "--port", "0"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
"#;
    assert_eq!(
        exempt_violation(refusal, ExemptKind::NoLongLivedChild),
        None
    );
    let daemon = refusal.replace(".output()", ".spawn()");
    assert!(
        exempt_violation(&daemon, ExemptKind::NoLongLivedChild)
            .is_some_and(|v| v.contains("does not end in output()")),
    );
    let with_health = format!("{refusal}\nconst URL: &str = \"https://h/api/v1/health\";\n");
    assert!(
        exempt_violation(&with_health, ExemptKind::NoLongLivedChild)
            .is_some_and(|v| v.contains("probes /health"))
    );
    let knob = refusal.replace(".args(", ".env(\"HF_HUB_OFFLINE\", \"1\").args(");
    assert!(
        exempt_violation(&knob, ExemptKind::NoLongLivedChild)
            .is_some_and(|v| v.contains("now sets the knob"))
    );
    let table = "const NAMES: [&str; 2] = [\"serve\", \"mcp\"];\n";
    assert_eq!(exempt_violation(table, ExemptKind::NoSpawnWindow), None);
    assert!(exempt_violation(refusal, ExemptKind::NoSpawnWindow).is_some());
    assert!(exempt_violation("fn none() {}\n", ExemptKind::NoLongLivedChild).is_some());
}

/// Every exemption names a file that still holds its kind, with a real reason;
/// a stale row would hide a regression.
#[test]
fn exemptions_are_current_and_checkable_4166() {
    let sources = all_test_sources();
    for (name, kind, reason) in EXEMPT {
        assert!(reason.len() > 20, "{name}: exemption needs a real reason");
        let path = sources
            .iter()
            .find(|p| p.file_name().is_some_and(|n| n == *name))
            .unwrap_or_else(|| panic!("exempt file {name} does not exist"));
        if let Some(why) = exempt_violation(&read(path), *kind) {
            panic!("{name} ({kind:?}): {why}");
        }
    }
}

// ---------------------------------------------------------------------------
// Real tree
// ---------------------------------------------------------------------------

/// Invariant (a) over the real tree.
#[test]
fn every_serve_spawn_sets_embed_offline_4166() {
    let offenders = scan(spawns_without_knob, true, false);
    assert!(
        offenders.is_empty(),
        "every serve spawn must call serve_test_env(), set {KNOB_LITERALS:?} or use a \
         command builder that does (#4166), or be listed in EXEMPT with a checkable kind; \
         missing at: {offenders:?}"
    );
}

/// Invariant (b) over the real tree.
#[test]
fn common_spawners_set_embed_offline_4166() {
    let offenders = scan(common_spawners_without_knob, false, true);
    assert!(
        offenders.is_empty(),
        "every function under tests/common that builds the ai-memory command must set \
         the embedder-offline knob itself (#4166); missing at: {offenders:?}"
    );
}

/// Invariant (c) over the real tree.
#[test]
fn every_serve_boot_wait_ends_on_child_exit_or_health_4166() {
    let offenders = scan(waits_without_exit_check, false, false);
    assert!(
        offenders.is_empty(),
        "a serve boot wait must contain try_wait() or call a function that does, so it \
         ends on child exit (with the child's stderr) or on health (#4166); \
         wait without an exit check at: {offenders:?}"
    );
}

/// Invariant (d) over the real tree.
#[test]
fn no_serve_boot_wait_asserts_on_a_bare_deadline_4166() {
    let offenders = scan(
        |s| bare_deadline_assert(s).into_iter().collect(),
        false,
        false,
    );
    assert!(
        offenders.is_empty(),
        "a serve boot wait must end on child exit or health and kill the child \
         when its hang guard trips, not assert on a bare deadline with the \
         child still running (#4166); found at: {offenders:?}"
    );
}

/// Replace the knob (literals, helper, knob-setting builder calls) on the lines
/// of `window`, so the spawn carries none.
fn without_knob(src: &str, window: &Window, m: &Model) -> String {
    let knob_builders: Vec<&str> = m
        .ctors
        .iter()
        .filter(|(_, k)| *k)
        .map(|(n, _)| n.as_str())
        .collect();
    src.lines()
        .enumerate()
        .map(|(i, l)| {
            let n = i + 1;
            if n < window.first || n > window.last {
                return l.to_owned();
            }
            let mut out = l.to_owned();
            for k in KNOB_LITERALS {
                out = out.replace(k, "\"NOT_A_KNOB\"");
            }
            out = out.replace(SERVE_ENV_HELPER, "serve_test_env_removed(");
            for b in &knob_builders {
                let pos = call_positions(&out, b, false).next();
                if let Some(pos) = pos {
                    out = format!("{}Command::new({}", &out[..pos], &out[pos + b.len() + 1..]);
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Class test for (a): deleting the knob from any ONE real serve spawn turns the
/// guard red at that spawn. This is the check the per-file guard failed.
#[test]
fn removing_the_knob_from_any_single_spawn_turns_the_guard_red_4166() {
    let mut checked = 0_usize;
    for path in all_test_sources() {
        if exempt_row(&path).is_some() {
            continue;
        }
        let src = read(&path);
        let m = Model::new(&src);
        for w in serve_windows(&m) {
            let mutated = without_knob(&src, &w, &m);
            let flagged = spawns_without_knob(&mutated);
            assert!(
                flagged.contains(&w.serve_line),
                "{}:{}: removing the knob from this spawn did not turn the guard red \
                 (flagged {flagged:?})",
                rel(&path),
                w.serve_line
            );
            checked += 1;
        }
    }
    assert!(checked >= 25, "only {checked} serve spawns were mutated");
}

/// Replace the exit check on the lines of `lp`.
fn without_exit_check(src: &str, lp: &LoopInfo, exit_fns: &[String]) -> String {
    src.lines()
        .enumerate()
        .map(|(i, l)| {
            let n = i + 1;
            if n < lp.first || n > lp.last {
                return l.to_owned();
            }
            let mut out = l.replace(TRY_WAIT_CALL, "try_wait_removed(");
            for f in exit_fns {
                out = out.replace(&format!("{f}("), &format!("{f}_removed("));
            }
            out
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Class test for (c): deleting the exit check from any ONE real boot wait turns
/// the guard red at that wait.
#[test]
fn removing_the_exit_check_from_any_single_boot_wait_turns_the_guard_red_4166() {
    let mut checked = 0_usize;
    for path in all_test_sources() {
        let src = read(&path);
        let m = Model::new(&src);
        if !spawns_serve(&m) {
            continue;
        }
        let exit_fns: Vec<String> = m
            .fns
            .iter()
            .filter(|f| range_text(&m.lines, f.start, f.end).contains(TRY_WAIT_CALL))
            .map(|f| f.name.clone())
            .collect();
        for lp in loops(&m).iter().filter(|l| l.probes_health && l.exit_aware) {
            let mutated = without_exit_check(&src, lp, &exit_fns);
            assert!(
                waits_without_exit_check(&mutated).contains(&lp.first),
                "{}:{}: removing the exit check from this wait did not turn the guard red",
                rel(&path),
                lp.first
            );
            checked += 1;
        }
    }
    assert!(checked >= 5, "only {checked} boot waits were mutated");
}

/// The widened guard run over the tree: every boot wait it finds, listed so a
/// reviewer can see what (c) covers. Run with `--nocapture`.
#[test]
fn boot_waits_found_by_the_guard_are_all_exit_aware_4166() {
    let mut total = 0_usize;
    for path in all_test_sources() {
        let src = read(&path);
        let m = Model::new(&src);
        if !spawns_serve(&m) {
            continue;
        }
        for lp in loops(&m).iter().filter(|l| l.probes_health) {
            println!(
                "boot-wait {}:{} exit_aware={}",
                rel(&path),
                lp.first,
                lp.exit_aware
            );
            total += 1;
        }
    }
    assert!(total >= 5, "only {total} boot waits found");
}

/// A wait helper whose probe is a closure: the helper names no `/health`, its
/// callers do, so the loop is recognised by the `impl FnMut() -> bool` parameter.
const CLOSURE_WAIT: &str = r#"
fn boot() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    common::serve_test_env(&mut cmd);
    let mut child = cmd.args(["serve"]).spawn().unwrap();
    wait_with(&mut child, || curl("https://127.0.0.1/api/v1/health"));
}

fn wait_with(child: &mut Child, mut healthy: impl FnMut() -> bool) {
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(100));
        if healthy() {
            return;
        }
    }
}
"#;

#[test]
fn guard_flags_a_closure_probe_wait_without_a_child_exit_check_4166() {
    assert_eq!(
        waits_without_exit_check(CLOSURE_WAIT),
        vec![line_of(CLOSURE_WAIT, "for _ in 0..30")]
    );
    let aware = CLOSURE_WAIT.replace(
        "        if healthy() {",
        "        if child.try_wait().is_ok_and(|s| s.is_some()) {\n            panic!(\"exited\");\n        }\n        if healthy() {",
    );
    assert_eq!(waits_without_exit_check(&aware), []);
}

/// A builder that is a method (`sb.base_command()`) is a spawn start too: the
/// spawn through it is checked for the knob, and a knob in the builder body or
/// at the call site passes it.
const METHOD_BUILDER_SPAWN: &str = r#"
impl Sandbox {
    fn base_command(&self) -> Command {
        Command::new(env!("CARGO_BIN_EXE_ai-memory"))
    }
}

fn boot(sb: &Sandbox) {
    let mut cmd = sb.base_command();
    cmd.args(["serve"]);
    let _child = cmd.spawn().unwrap();
}
"#;

#[test]
fn guard_sees_a_spawn_through_a_method_builder_4166() {
    assert_eq!(
        spawns_without_knob(METHOD_BUILDER_SPAWN),
        vec![line_of(METHOD_BUILDER_SPAWN, "\"serve\"")]
    );
    let call_site = METHOD_BUILDER_SPAWN.replace(
        "    cmd.args([\"serve\"]);",
        "    common::serve_test_env(&mut cmd);\n    cmd.args([\"serve\"]);",
    );
    assert_eq!(spawns_without_knob(&call_site), []);
}
