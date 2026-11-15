// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3971 W-11 — every `ExecStart=`, `ExecStartPre=` and `ExecStartPost=` line
//! the package ships under `packaging/` is passed through the REAL CLI parser.
//!
//! A unit line that names a flag the binary no longer accepts (or a flag
//! combination clap refuses) fails at service start on a customer host, not in
//! CI. This test fails on any such line. It also pins the count of lines that
//! run as root (`+` prefix, #3971 W-12) and the refusal exit code the root
//! hand-off reports.

use std::path::{Path, PathBuf};

use ai_memory::daemon_runtime::Cli;
use clap::Parser as _;

/// The packaged binary path every unit invokes.
const BIN: &str = "/usr/bin/ai-memory";
/// Directives whose command lines are checked.
const EXEC_DIRECTIVES: [&str; 3] = ["ExecStart=", "ExecStartPre=", "ExecStartPost="];
/// systemd command-line prefixes (`+` = full privileges, `-` = ignore
/// failure, `@` = argv0, `:` = no env expansion, `!` = no uid change).
const EXEC_PREFIXES: [char; 5] = ['+', '-', '@', ':', '!'];
/// The number of packaged command lines that run as root (#3971 W-12): the
/// refresher's `--publish-snapshot` hand-off and nothing else.
const ROOT_LINES: usize = 1;

/// Placeholder value for each environment variable a unit expands; an
/// unknown variable fails the test so a new one is reviewed here.
fn expand(var: &str) -> Option<Expansion> {
    match var {
        "SOCKET" => Some(Expansion::Value("/run/ai-memory-hub/hub.sock")),
        "ALLOWLIST" => Some(Expansion::Value("/run/ai-memory-hub/hub-allow.json")),
        "PEERS" => Some(Expansion::Value("http://127.0.0.1:9077")),
        "AI_MEMORY_CURATOR_INTERVAL_SECS" => Some(Expansion::Value("3600")),
        "AI_MEMORY_CURATOR_MAX_OPS" => Some(Expansion::Value("100")),
        // Operator-supplied extra flags; empty by default.
        "EXTRA_ARGS" => Some(Expansion::Empty),
        _ => None,
    }
}

/// What a known unit variable expands to: one word, or nothing at all.
enum Expansion {
    Value(&'static str),
    Empty,
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("read packaging dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// One logical directive line: backslash continuations joined, comments
/// skipped.
fn exec_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if !EXEC_DIRECTIVES.iter().any(|d| line.starts_with(d)) {
            continue;
        }
        let mut joined = line.to_owned();
        while joined.ends_with('\\') {
            joined.pop();
            match lines.next() {
                Some(next) => {
                    joined.push(' ');
                    joined.push_str(next.trim());
                }
                None => break,
            }
        }
        out.push(joined);
    }
    out
}

/// POSIX-ish word split: single and double quotes, backslash escapes.
fn shell_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    cur.push(q);
                }
            }
            '"' => {
                in_word = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' => cur.extend(chars.next()),
                        _ => cur.push(q),
                    }
                }
            }
            '\\' => {
                in_word = true;
                cur.extend(chars.next());
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            _ => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

/// Expand `$VAR` / `${VAR}` words. A word that is not wholly one variable
/// and still contains `$` is returned as an error.
fn expand_word(word: &str) -> Result<Option<String>, String> {
    if !word.contains('$') {
        return Ok(Some(word.to_owned()));
    }
    let name = word
        .strip_prefix("${")
        .and_then(|w| w.strip_suffix('}'))
        .or_else(|| word.strip_prefix('$'))
        .filter(|n| n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .ok_or_else(|| format!("unexpandable word {word:?}"))?;
    expand(name)
        .map(|v| match v {
            Expansion::Value(s) => Some(s.to_owned()),
            Expansion::Empty => None,
        })
        .ok_or_else(|| format!("unknown unit variable ${name}; add it to expand()"))
}

/// Every `/usr/bin/ai-memory` invocation in one command line, as argv
/// vectors ready for the parser.
fn invocations(line: &str) -> Result<Vec<Vec<String>>, String> {
    let words = shell_words(line);
    let shell =
        words.first().is_some_and(|w| w == "/bin/sh") && words.get(1).is_some_and(|w| w == "-c");
    let words = if shell {
        let script = words.get(2).ok_or("`/bin/sh -c` with no script")?;
        shell_words(script)
    } else {
        words
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        if words[i] != BIN {
            i += 1;
            continue;
        }
        let mut argv = vec!["ai-memory".to_owned()];
        i += 1;
        while i < words.len() {
            let w = &words[i];
            if ["&&", "||", ";", "|", "{", "}"].contains(&w.as_str())
                || w.starts_with('>')
                || w.starts_with("2>")
            {
                break;
            }
            let (word, ends) = match w.strip_suffix(';') {
                Some(head) => (head, true),
                None => (w.as_str(), false),
            };
            if let Some(v) = expand_word(word)? {
                argv.push(v);
            }
            i += 1;
            if ends {
                break;
            }
        }
        out.push(argv);
    }
    Ok(out)
}

/// Strip the directive name and the systemd prefixes; report whether `+`
/// (full privileges) was among them.
fn command_of(line: &str) -> (bool, &str) {
    let value = EXEC_DIRECTIVES
        .iter()
        .find_map(|d| line.strip_prefix(d))
        .unwrap_or(line);
    let cmd = value.trim_start_matches(EXEC_PREFIXES);
    let prefixes = &value[..value.len() - cmd.len()];
    (prefixes.contains('+'), cmd)
}

/// For `/usr/bin/env [-i] [VAR=val]... CMD ARGS`, the `CMD ARGS` part.
fn strip_env(cmd: &str) -> String {
    let words = shell_words(cmd);
    if words.first().map(String::as_str) != Some("/usr/bin/env") {
        return cmd.to_owned();
    }
    let rest: Vec<_> = words
        .into_iter()
        .skip(1)
        .skip_while(|w| w.starts_with('-') || w.contains('='))
        .collect();
    rest.join(" ")
}

struct Checked {
    invocations: usize,
    root_lines: Vec<String>,
}

fn check_all() -> Checked {
    let mut failures = Vec::new();
    let mut checked = Checked {
        invocations: 0,
        root_lines: Vec::new(),
    };
    for path in files_under(&repo().join("packaging")) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in exec_lines(&text) {
            let (root, cmd) = command_of(&line);
            if root {
                checked.root_lines.push(line.clone());
            }
            let cmd = strip_env(cmd);
            match invocations(&cmd) {
                Err(e) => failures.push(format!("{}: {line}: {e}", path.display())),
                Ok(argvs) => {
                    for argv in argvs {
                        checked.invocations += 1;
                        if let Err(e) = Cli::try_parse_from(&argv) {
                            failures.push(format!(
                                "{}: {argv:?} does not parse: {}",
                                path.display(),
                                e.kind()
                            ));
                        }
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "packaged Exec lines that do not parse:\n{}",
        failures.join("\n")
    );
    checked
}

#[test]
fn every_packaged_exec_line_parses_through_the_real_cli_3971() {
    let checked = check_all();
    assert!(
        checked.invocations > 0,
        "the walker found no ai-memory invocation; it is not checking anything"
    );
}

#[test]
fn exactly_one_packaged_line_runs_as_root_and_it_is_the_publish_hand_off_3971() {
    let checked = check_all();
    assert_eq!(
        checked.root_lines.len(),
        ROOT_LINES,
        "root (`+`) lines: {:?}",
        checked.root_lines
    );
    let line = &checked.root_lines[0];
    assert!(
        line.starts_with(
            "ExecStartPost=+/usr/bin/env -i AI_MEMORY_NO_CONFIG=1 /usr/bin/ai-memory wake-hub"
        ),
        "{line}"
    );
    assert!(line.contains("--publish-snapshot"), "{line}");
}

#[test]
fn the_walker_rejects_a_line_the_parser_refuses_3971() {
    // Negative control: the same pipeline must fail a bogus flag and a
    // refused mode combination, or a green run proves nothing.
    for bad in [
        "/usr/bin/ai-memory wake-hub --no-such-flag",
        "/bin/sh -c '/usr/bin/ai-memory wake-hub --socket \"$SOCKET\" --publish-snapshot /a --allowlist /b'",
        "/usr/bin/env -i AI_MEMORY_NO_CONFIG=1 /usr/bin/ai-memory wake-hub --publish-snapshot /a",
    ] {
        let argvs = invocations(&strip_env(bad)).expect("split");
        assert_eq!(argvs.len(), 1, "{bad}");
        assert!(
            Cli::try_parse_from(&argvs[0]).is_err(),
            "{bad} must not parse"
        );
    }
    assert!(
        invocations("/usr/bin/ai-memory serve --port $UNKNOWN_VAR").is_err(),
        "an unknown unit variable must fail, not vanish"
    );
}

#[test]
fn the_publish_refusal_exit_code_is_pinned_3971() {
    // Units and operators key on these; they are the stable part of the
    // packaging-internal interface.
    assert_eq!(ai_memory::cli::wake_hub::EXIT_PUBLISH_REFUSED, 1);
    assert_eq!(
        ai_memory::cli::wake_hub::PUBLISH_REFUSED_PREFIX,
        "wake-hub: --publish-snapshot refused:"
    );
}
