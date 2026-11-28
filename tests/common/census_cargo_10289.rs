// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10289: crate renames, read from every walked `Cargo.toml`.
//!
//! The token census finds a watched crate by its name in Rust source. A
//! manifest can give that crate another name (`foo = { package = "proptest"
//! }`), or give another crate a watched name, and then the source never
//! spells what it runs. This module reads each manifest with a strict
//! parser for the subset of TOML the workspace uses and refuses:
//!
//! * a `package =` key whose value is a watched crate, or that renames a
//!   dependency keyed by a watched crate;
//! * a `[patch.<registry>.<watched>]` table or a `[replace]` key naming a
//!   watched crate;
//! * a `[lib]`, `[package]` or `[[bin]]` `name` that is a watched crate;
//! * a manifest that is not UTF-8 or that the parser cannot read.
//!
//! The parser is one pass over the characters with a nesting cap, so the
//! cost is linear. Anything outside its subset (multi-line strings, floats,
//! dates) is a finding, not a skip. A symbolic link is already red in the
//! tree walk.

/// The crates whose rename would hide a process start or a proptest run,
/// written as Cargo normalises them (lower case, `-` read as `_`).
pub(crate) const WATCHED_CRATES: &[&str] =
    &["libc", "nix", "proptest", "rusty_fork", "wait_timeout"];

/// The deepest nesting of arrays and inline tables the parser follows.
pub(crate) const MAX_DEPTH: usize = 32;

/// One scalar of the manifest, flattened to its key path.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Leaf {
    /// A basic or literal string, decoded.
    Str(String),
    /// An integer or a boolean.
    Other,
}

/// A key path and its scalar; array items are segments `#0`, `#1`, ...
pub(crate) type Entry = (Vec<String>, Leaf);

struct Parser<'a> {
    s: &'a [char],
    i: usize,
    line: usize,
    out: Vec<Entry>,
}

fn norm(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "_")
}

pub(crate) fn watched(name: &str) -> bool {
    WATCHED_CRATES.contains(&norm(name).as_str())
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn err(&self, what: &str) -> String {
        format!("line {}: {what}", self.line)
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.bump();
        }
    }

    /// Blanks, newlines and comments (between items, and inside arrays).
    fn ws_lines(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\n' | '\r') => {
                    self.bump();
                }
                Some('#') => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                }
                _ => return,
            }
        }
    }

    /// The end of a key-value line or a header: an optional comment, then a
    /// newline or the end.
    fn eol(&mut self) -> Result<(), String> {
        self.ws();
        if self.peek() == Some('#') {
            while self.peek().is_some_and(|c| c != '\n') {
                self.bump();
            }
        }
        if self.peek() == Some('\r') {
            self.bump();
        }
        match self.peek() {
            None => Ok(()),
            Some('\n') => {
                self.bump();
                Ok(())
            }
            Some(c) => Err(self.err(&format!("unexpected {c:?} after a value"))),
        }
    }

    fn string(&mut self) -> Result<String, String> {
        let q = self.bump().ok_or_else(|| self.err("missing quote"))?;
        if self.peek() == Some(q) && self.s.get(self.i + 1) == Some(&q) {
            return Err(self.err("a multi-line string is outside the parsed subset"));
        }
        let mut v = String::new();
        loop {
            match self.bump() {
                None | Some('\n') => return Err(self.err("an unterminated string")),
                Some(c) if c == q => return Ok(v),
                Some('\\') if q == '"' => {
                    let e = self
                        .bump()
                        .ok_or_else(|| self.err("an unterminated escape"))?;
                    match e {
                        '"' => v.push('"'),
                        '\\' => v.push('\\'),
                        'n' => v.push('\n'),
                        't' => v.push('\t'),
                        'r' => v.push('\r'),
                        'u' => {
                            let mut code = 0u32;
                            for _ in 0..4 {
                                let d = self
                                    .bump()
                                    .and_then(|c| c.to_digit(16))
                                    .ok_or_else(|| self.err("a bad \\u escape"))?;
                                code = code * 16 + d;
                            }
                            v.push(
                                char::from_u32(code).ok_or_else(|| self.err("a bad \\u escape"))?,
                            );
                        }
                        other => {
                            return Err(self.err(&format!(
                                "the escape \\{other} is outside the parsed subset"
                            )));
                        }
                    }
                }
                Some(c) => v.push(c),
            }
        }
    }

    fn key(&mut self) -> Result<Vec<String>, String> {
        let mut parts = Vec::new();
        loop {
            self.ws();
            let part = if let Some('"' | '\'') = self.peek() {
                self.string()?
            } else {
                let mut b = String::new();
                while let Some(c) = self
                    .peek()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                {
                    b.push(c);
                    self.bump();
                }
                if b.is_empty() {
                    return Err(self.err("an empty or unreadable key"));
                }
                b
            };
            parts.push(part);
            self.ws();
            if self.peek() == Some('.') {
                self.bump();
            } else {
                return Ok(parts);
            }
        }
    }

    fn value(&mut self, path: &[String], depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting deeper than the parser follows"));
        }
        match self.peek() {
            Some('"' | '\'') => {
                let v = self.string()?;
                self.out.push((path.to_vec(), Leaf::Str(v)));
            }
            Some('[') => {
                self.bump();
                let mut n = 0usize;
                loop {
                    self.ws_lines();
                    if self.peek() == Some(']') {
                        self.bump();
                        break;
                    }
                    let mut p = path.to_vec();
                    p.push(format!("#{n}"));
                    self.value(&p, depth + 1)?;
                    n += 1;
                    self.ws_lines();
                    match self.bump() {
                        Some(',') => {}
                        Some(']') => break,
                        _ => return Err(self.err("an array item not followed by , or ]")),
                    }
                }
            }
            Some('{') => {
                self.bump();
                self.ws();
                if self.peek() == Some('}') {
                    self.bump();
                    return Ok(());
                }
                loop {
                    let k = self.key()?;
                    self.ws();
                    if self.bump() != Some('=') {
                        return Err(self.err("an inline-table key without ="));
                    }
                    self.ws();
                    let mut p = path.to_vec();
                    p.extend(k);
                    self.value(&p, depth + 1)?;
                    self.ws();
                    match self.bump() {
                        Some(',') => self.ws(),
                        Some('}') => break,
                        _ => return Err(self.err("an inline-table item not followed by , or }")),
                    }
                }
            }
            _ => {
                let mut b = String::new();
                while let Some(c) = self.peek().filter(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-' | '.' | ':')
                }) {
                    b.push(c);
                    self.bump();
                }
                let digits = b.strip_prefix(['+', '-']).unwrap_or(&b);
                let int = !digits.is_empty()
                    && digits.starts_with(|c: char| c.is_ascii_digit())
                    && digits.chars().all(|c| c.is_ascii_digit() || c == '_');
                if !(int || b == "true" || b == "false") {
                    return Err(self.err(&format!("the value {b:?} is outside the parsed subset")));
                }
                self.out.push((path.to_vec(), Leaf::Other));
            }
        }
        Ok(())
    }

    fn document(&mut self) -> Result<(), String> {
        let mut table: Vec<String> = Vec::new();
        let mut arrays: std::collections::BTreeMap<Vec<String>, usize> =
            std::collections::BTreeMap::new();
        loop {
            self.ws_lines();
            let Some(c) = self.peek() else { return Ok(()) };
            if c == '[' {
                self.bump();
                let array = self.peek() == Some('[');
                if array {
                    self.bump();
                }
                let k = self.key()?;
                for _ in 0..=usize::from(array) {
                    // The line of the header, not the line a newline in
                    // its place would move the count to.
                    let line = self.line;
                    if self.bump() != Some(']') {
                        return Err(format!("line {line}: an unclosed table header"));
                    }
                }
                table.clone_from(&k);
                if array {
                    let n = arrays.entry(k).or_insert(0);
                    table.push(format!("#{n}"));
                    *n += 1;
                }
                self.eol()?;
            } else {
                let k = self.key()?;
                self.ws();
                if self.bump() != Some('=') {
                    return Err(self.err("a key without ="));
                }
                self.ws();
                let mut p = table.clone();
                p.extend(k);
                self.value(&p, 0)?;
                self.eol()?;
            }
        }
    }
}

/// The flattened entries of one manifest, or why it cannot be read.
pub(crate) fn parse(text: &str) -> Result<Vec<Entry>, String> {
    let s: Vec<char> = text.chars().collect();
    let mut p = Parser {
        s: &s,
        i: 0,
        line: 1,
        out: Vec::new(),
    };
    p.document()?;
    Ok(p.out)
}

fn is_index(seg: &str) -> bool {
    seg.starts_with('#')
}

/// The rename findings of one manifest's entries.
pub(crate) fn rename_findings(rel: &str, entries: &[Entry]) -> Vec<String> {
    let mut out = Vec::new();
    for (path, leaf) in entries {
        let shown = path.join(".");
        let last = path.last().map_or("", String::as_str);
        let value = match leaf {
            Leaf::Str(s) => Some(s.as_str()),
            Leaf::Other => None,
        };
        let shown_value = value.map_or_else(
            || "a value that is not a string".to_string(),
            |s| format!("{s:?}"),
        );
        if last == "package" && path.len() >= 2 {
            let dep = &path[path.len() - 2];
            if value.is_some_and(watched) || watched(dep) {
                out.push(format!(
                    "{rel}: {shown} = {shown_value} renames a watched crate; the census reads a watched crate only by its own name (#10289)"
                ));
            }
        }
        if path.first().is_some_and(|s| s == "patch") && path.get(2).is_some_and(|s| watched(s)) {
            out.push(format!(
                "{rel}: {shown} patches the watched crate {}; a patched watched crate runs code the census never reads (#10289)",
                path[2]
            ));
        }
        if path.first().is_some_and(|s| s == "replace")
            && path
                .get(1)
                .is_some_and(|s| watched(s.split(':').next().unwrap_or(s)))
        {
            out.push(format!(
                "{rel}: {shown} replaces the watched crate {}; a replaced watched crate runs code the census never reads (#10289)",
                path[1]
            ));
        }
        let named_target = match path.as_slice() {
            [a, b] => (a == "lib" || a == "package") && b == "name",
            [a, i, b] => a == "bin" && is_index(i) && b == "name",
            _ => false,
        };
        if named_target && value.is_some_and(watched) {
            out.push(format!(
                "{rel}: {shown} = {shown_value} gives a target a watched crate's name (#10289)"
            ));
        }
    }
    out
}

/// The findings of one manifest's bytes: unreadable, unparseable or a rename.
pub(crate) fn manifest_findings(rel: &str, bytes: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return vec![format!(
            "{rel}: not UTF-8; an unreadable Cargo.toml is not clean (#10289)"
        )];
    };
    match parse(text) {
        Ok(entries) => rename_findings(rel, &entries),
        Err(e) => vec![format!(
            "{rel}: {e}; an unparseable Cargo.toml is not clean (#10289)"
        )],
    }
}
