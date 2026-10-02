// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared token-scan helpers for the "unchecked federation writer" ceiling
//! tests (#4023, #4447): blank comments and string/char literals, then find
//! whole-identifier occurrences in the masked code. Leaf module, `std` only.

#![allow(dead_code)]

/// Blank every comment and string/char literal body with spaces (newlines
/// kept) so a token inside a doc line or an error-context string is never
/// counted as code.
pub fn mask(src: &str) -> String {
    let c: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let blank = |out: &mut String, ch: char| out.push(if ch == '\n' { '\n' } else { ' ' });
    let is_ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        let next = c.get(i + 1).copied();
        if ch == '/' && next == Some('/') {
            while i < c.len() && c[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if ch == '/' && next == Some('*') {
            let mut depth = 0usize;
            while i < c.len() {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out.push_str("  ");
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out.push_str("  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    blank(&mut out, c[i]);
                    i += 1;
                }
            }
            continue;
        }
        let prev_ident = i > 0 && is_ident(c[i - 1]);
        // Raw string r"..", r#".."#, br#".."#.
        let raw_at = if ch == 'r' && !prev_ident {
            Some(i + 1)
        } else if ch == 'b' && next == Some('r') && !prev_ident {
            Some(i + 2)
        } else {
            None
        };
        if let Some(mut j) = raw_at {
            let mut hashes = 0usize;
            while c.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if c.get(j) == Some(&'"') {
                while i <= j {
                    out.push(' ');
                    i += 1;
                }
                loop {
                    if i >= c.len() {
                        break;
                    }
                    if c[i] == '"' && (0..hashes).all(|k| c.get(i + 1 + k) == Some(&'#')) {
                        for _ in 0..=hashes {
                            out.push(' ');
                        }
                        i += 1 + hashes;
                        break;
                    }
                    blank(&mut out, c[i]);
                    i += 1;
                }
                continue;
            }
        }
        if ch == '"' {
            out.push(' ');
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    out.push(' ');
                    i += 1;
                    if i < c.len() {
                        blank(&mut out, c[i]);
                        i += 1;
                    }
                    continue;
                }
                if c[i] == '"' {
                    out.push(' ');
                    i += 1;
                    break;
                }
                blank(&mut out, c[i]);
                i += 1;
            }
            continue;
        }
        // Char literal (not a lifetime): `'x'`, `'\n'`, `'"'`.
        if ch == '\'' && !prev_ident {
            let close = if next == Some('\\') {
                c[i + 2..]
                    .iter()
                    .position(|&x| x == '\'')
                    .map(|p| i + 2 + p)
            } else if c.get(i + 2) == Some(&'\'') {
                Some(i + 2)
            } else {
                None
            };
            if let Some(end) = close {
                while i <= end {
                    blank(&mut out, c[i]);
                    i += 1;
                }
                continue;
            }
        }
        out.push(ch);
        i += 1;
    }
    out
}

/// Byte offsets of every whole-identifier occurrence of `ident` in `masked`.
pub fn ident_offsets(masked: &str, ident: &str) -> Vec<usize> {
    let b = masked.as_bytes();
    let is_ident = |x: u8| x.is_ascii_alphanumeric() || x == b'_';
    masked
        .match_indices(ident)
        .filter(|(at, _)| {
            let before_ok = *at == 0 || !is_ident(b[*at - 1]);
            let end = *at + ident.len();
            let after_ok = end >= b.len() || !is_ident(b[end]);
            before_ok && after_ok
        })
        .map(|(at, _)| at)
        .collect()
}
