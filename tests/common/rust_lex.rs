// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10176: the Rust token lexer layer 2 shares. Comments (nested block
//! comments included) are dropped; string, raw string, byte string and C string
//! literals become one `Str` token holding the decoded text; a char or byte
//! literal becomes `Char` holding its source text, quotes and prefix included;
//! a numeric literal becomes `Num` holding its source text, suffix included
//! (#10302); `::` is `PathSep`; a lifetime is `Punct('\'')`.
//!
//! Characters (#10305): the blanks are the Unicode `Pattern_White_Space` set
//! ([`PATTERN_WHITE_SPACE`], the set rustc skips), and every other non-ASCII
//! character is an identifier character, so the lexer gives the same tokens
//! as the Python mirror (`scripts/ci/census_rows_10286.py`) on every text,
//! with no standard-library Unicode table on either side. Used by
//! `tests/test_child_spawner_isolation_10176.rs` and
//! `tests/process_start_census_10176.rs` through `#[path]`.

#![allow(dead_code)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    Ident(String),
    Punct(char),
    PathSep,
    Str(String),
    Char(String),
    Num(String),
}

/// The Unicode `Pattern_White_Space` characters (UAX #31), the blanks of a
/// Rust source file.
pub const PATTERN_WHITE_SPACE: [char; 11] = [
    '\t', '\n', '\u{b}', '\u{c}', '\r', ' ', '\u{85}', '\u{200e}', '\u{200f}', '\u{2028}',
    '\u{2029}',
];

/// Whether `x` is a blank of a Rust source file.
pub fn is_blank(x: char) -> bool {
    PATTERN_WHITE_SPACE.contains(&x)
}

/// Whether `x` can start an identifier: an ASCII letter, `_` or any
/// non-ASCII character that is not a blank.
pub fn is_ident_start(x: char) -> bool {
    x.is_ascii_alphabetic() || x == '_' || (!x.is_ascii() && !is_blank(x))
}

/// Whether `x` can continue an identifier.
pub fn is_ident_char(x: char) -> bool {
    x.is_ascii_digit() || is_ident_start(x)
}

#[derive(Debug, Clone)]
pub struct Lexed {
    pub tok: Tok,
    pub line: usize,
}

/// Decode the body of a (non-raw) string literal starting after the opening
/// quote at `c[i]`; returns the decoded text and the index after the quote.
pub fn decode_quoted(c: &[char], mut i: usize, line: &mut usize) -> (String, usize) {
    let mut out = String::new();
    while i < c.len() {
        let ch = c[i];
        if ch == '"' {
            return (out, i + 1);
        }
        if ch == '\n' {
            *line += 1;
        }
        if ch != '\\' {
            out.push(ch);
            i += 1;
            continue;
        }
        let Some(&e) = c.get(i + 1) else {
            return (out, c.len());
        };
        i += 2;
        match e {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '0' => out.push('\0'),
            '\\' | '\'' | '"' => out.push(e),
            'x' => {
                let hex: String = c[i..c.len().min(i + 2)].iter().collect();
                if let Ok(v) = u8::from_str_radix(&hex, 16) {
                    out.push(char::from(v));
                }
                i += 2;
            }
            'u' => {
                let close = c[i..]
                    .iter()
                    .position(|&x| x == '}')
                    .map_or(c.len(), |p| i + p);
                let hex: String = c[i..close]
                    .iter()
                    .filter(|x| x.is_ascii_hexdigit())
                    .collect();
                if let Some(v) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    out.push(v);
                }
                i = close + 1;
            }
            '\n' => {
                *line += 1;
                while i < c.len() && is_blank(c[i]) {
                    if c[i] == '\n' {
                        *line += 1;
                    }
                    i += 1;
                }
            }
            other => out.push(other),
        }
    }
    (out, i)
}

pub fn lex(src: &str) -> Vec<Lexed> {
    let chars: Vec<char> = src.chars().collect();
    let is_ident = is_ident_char;
    let mut out = Vec::new();
    let mut line = 1usize;
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        let next = chars.get(i + 1).copied();
        if ch == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        if is_blank(ch) {
            i += 1;
            continue;
        }
        if ch == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if ch == '/' && next == Some('*') {
            let mut depth = 0usize;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if chars[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            continue;
        }
        // String prefixes: b"..", c"..", r".." / r#".."#, br, cr.
        if is_ident_start(ch) {
            let mut j = i;
            while j < chars.len() && is_ident(chars[j]) {
                j += 1;
            }
            let word: String = chars[i..j].iter().collect();
            let at = line;
            if matches!(word.as_str(), "r" | "br" | "cr") && matches!(chars.get(j), Some('"' | '#'))
            {
                let mut k = j;
                let mut hashes = 0usize;
                while chars.get(k) == Some(&'#') {
                    hashes += 1;
                    k += 1;
                }
                if chars.get(k) == Some(&'"') {
                    k += 1;
                    let start = k;
                    while k < chars.len()
                        && !(chars[k] == '"'
                            && (0..hashes).all(|h| chars.get(k + 1 + h) == Some(&'#')))
                    {
                        if chars[k] == '\n' {
                            line += 1;
                        }
                        k += 1;
                    }
                    let body: String = chars[start..k.min(chars.len())].iter().collect();
                    out.push(Lexed {
                        tok: Tok::Str(body),
                        line: at,
                    });
                    i = k + 1 + hashes;
                    continue;
                }
                if word == "r" && hashes == 1 && chars.get(k).is_some_and(|x| is_ident_start(*x)) {
                    // Raw identifier r#name.
                    let mut m = k;
                    while m < chars.len() && is_ident(chars[m]) {
                        m += 1;
                    }
                    out.push(Lexed {
                        tok: Tok::Ident(chars[k..m].iter().collect()),
                        line: at,
                    });
                    i = m;
                    continue;
                }
            }
            if matches!(word.as_str(), "b" | "c") && chars.get(j) == Some(&'"') {
                let (body, end) = decode_quoted(&chars, j + 1, &mut line);
                out.push(Lexed {
                    tok: Tok::Str(body),
                    line: at,
                });
                i = end;
                continue;
            }
            if word == "b" && chars.get(j) == Some(&'\'') {
                // An escaped quote (b'\'') is not the closing quote (#10305).
                let from = if chars.get(j + 1) == Some(&'\\') {
                    j + 3
                } else {
                    j + 1
                };
                let close = chars
                    .get(from..)
                    .unwrap_or_default()
                    .iter()
                    .position(|&x| x == '\'')
                    .map_or(chars.len(), |p| from + p);
                let end = (close + 1).min(chars.len());
                out.push(Lexed {
                    tok: Tok::Char(chars[i..end].iter().collect()),
                    line: at,
                });
                i = close + 1;
                continue;
            }
            out.push(Lexed {
                tok: Tok::Ident(word),
                line: at,
            });
            i = j;
            continue;
        }
        if ch.is_ascii_digit() {
            let start = i;
            while i < chars.len()
                && (is_ident(chars[i])
                    || chars[i] == '.' && chars.get(i + 1).is_some_and(char::is_ascii_digit))
            {
                i += 1;
            }
            out.push(Lexed {
                tok: Tok::Num(chars[start..i].iter().collect()),
                line,
            });
            continue;
        }
        if ch == '"' {
            let at = line;
            let (body, end) = decode_quoted(&chars, i + 1, &mut line);
            out.push(Lexed {
                tok: Tok::Str(body),
                line: at,
            });
            i = end;
            continue;
        }
        if ch == '\'' {
            // Char literal or lifetime.
            let close = if next == Some('\\') {
                // The escaped character is never the closing quote (#10305).
                chars
                    .get(i + 3..)
                    .unwrap_or_default()
                    .iter()
                    .position(|&x| x == '\'')
                    .map(|p| i + 3 + p)
            } else if chars.get(i + 2) == Some(&'\'') {
                Some(i + 2)
            } else {
                None
            };
            if let Some(end) = close {
                out.push(Lexed {
                    tok: Tok::Char(chars[i..=end.min(chars.len() - 1)].iter().collect()),
                    line,
                });
                i = end + 1;
                continue;
            }
            out.push(Lexed {
                tok: Tok::Punct('\''),
                line,
            });
            i += 1;
            continue;
        }
        if ch == ':' && next == Some(':') {
            out.push(Lexed {
                tok: Tok::PathSep,
                line,
            });
            i += 2;
            continue;
        }
        out.push(Lexed {
            tok: Tok::Punct(ch),
            line,
        });
        i += 1;
    }
    out
}

pub fn is_ident_tok(t: &Lexed, name: &str) -> bool {
    matches!(&t.tok, Tok::Ident(s) if s == name)
}

/// Index of the token closing the group opened at `open` (which holds `(`,
/// `[` or `{`), or the end.
pub fn group_end(toks: &[Lexed], open: usize) -> usize {
    let mut depth = 0usize;
    for (k, t) in toks.iter().enumerate().skip(open) {
        match t.tok {
            Tok::Punct('(' | '[' | '{') => depth += 1,
            Tok::Punct(')' | ']' | '}') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return k;
                }
            }
            _ => {}
        }
    }
    toks.len()
}
