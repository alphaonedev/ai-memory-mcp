// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8855 round 2, invariants (d) and (e): the screen is fail closed by
//! construction, not by a list of forms.
//!
//! - (d) NESTING: a value that carries escapes (JSON / backslash), invisible
//!   format characters, fullwidth or homoglyph letters, or `%XX` escapes is
//!   screened again in its decoded *views*. The chain unescapes at most
//!   [`MAX_NESTED_SCREEN_DEPTH`] levels; a value that still decodes past the
//!   bound is a finding ([`KIND_DEPTH_BOUND`]). Views are built only for a
//!   text of at most [`MAX_VIEW_SCREEN_BYTES`]; a larger text that needs a
//!   view is a finding ([`KIND_SIZE_BOUND`]).
//! - (e) RE-SCREEN: after redaction the redacted copy is screened AGAIN, and
//!   so is every view of it. Anything other than clean adds
//!   [`KIND_RESIDUAL`] and the whole value becomes the placeholder; the
//!   write funnels refuse such a copy instead of storing it
//!   ([`super::ResidualRefusal`]).
//!
//! Every pass is linear: each view is one forward walk over its input and
//! the chain has a fixed length, so the cost is `O(depth * n)`.

use super::REDACTION_PLACEHOLDER;

/// Unescape levels the screen resolves (ruling (d)).
pub const MAX_NESTED_SCREEN_DEPTH: usize = 4;
/// Largest text, in bytes, the decoded views are built for (ruling (d)).
pub const MAX_VIEW_SCREEN_BYTES: usize = 1 << 20;

/// Added when the redacted copy, or a view of it, still screens as a hit.
pub const KIND_RESIDUAL: &str = "redaction_residual";
/// Added when a value still decodes past [`MAX_NESTED_SCREEN_DEPTH`].
pub const KIND_DEPTH_BOUND: &str = "nested_depth_bound";
/// Added when a text that needs a view is larger than [`MAX_VIEW_SCREEN_BYTES`].
pub const KIND_SIZE_BOUND: &str = "nested_size_bound";

/// One screen pass: the kinds it found and the redacted copy.
pub(super) type Pass = fn(&str) -> (Vec<&'static str>, String);

/// The escape byte of JSON / C-family strings.
const ESCAPE: char = '\\';
/// The percent-encoding sigil.
const PERCENT: char = '%';
/// Hex digits of a `\uXXXX` escape.
const UNICODE_ESCAPE_DIGITS: usize = 4;
/// Distance from a fullwidth form (U+FF01..=U+FF5E) to its ASCII twin.
const FULLWIDTH_OFFSET: u32 = 0xFEE0;
const FULLWIDTH_FIRST: char = '\u{ff01}';
const FULLWIDTH_LAST: char = '\u{ff5e}';
/// Highest byte a `%XX` escape decodes to in a view (ASCII only, so a view
/// is always valid UTF-8).
const MAX_PERCENT_DECODED: u8 = 0x7f;

/// Invisible format characters a view drops (zero-width, bidi controls,
/// word joiners, BOM).
fn is_invisible_format(c: char) -> bool {
    matches!(c,
        '\u{00ad}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

/// Cyrillic and Greek letters that render as a Latin letter.
fn homoglyph(c: char) -> Option<char> {
    Some(match c {
        'а' | 'α' => 'a',
        'е' | 'ε' => 'e',
        'о' | 'ο' => 'o',
        'р' | 'ρ' => 'p',
        'с' => 'c',
        'у' => 'y',
        'х' => 'x',
        'ѕ' => 's',
        'і' | 'ι' => 'i',
        'ј' => 'j',
        'ԁ' => 'd',
        'ԝ' | 'ω' => 'w',
        'А' | 'Α' => 'A',
        'В' | 'Β' => 'B',
        'Е' | 'Ε' => 'E',
        'К' | 'Κ' => 'K',
        'М' | 'Μ' => 'M',
        'Н' | 'Η' => 'H',
        'О' | 'Ο' => 'O',
        'Р' | 'Ρ' => 'P',
        'С' => 'C',
        'Т' | 'Τ' => 'T',
        'Х' | 'Χ' => 'X',
        'Ѕ' => 'S',
        'І' | 'Ι' => 'I',
        _ => return None,
    })
}

fn hex_value(c: char) -> Option<u32> {
    c.to_digit(16)
}

/// The canonical view: invisible format characters dropped, fullwidth forms
/// and homoglyphs folded to ASCII, and `%XX` escapes of ASCII bytes decoded.
/// One forward walk.
fn canonical(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if is_invisible_format(c) {
            continue;
        }
        if (FULLWIDTH_FIRST..=FULLWIDTH_LAST).contains(&c)
            && let Some(ascii) = char::from_u32(u32::from(c) - FULLWIDTH_OFFSET)
        {
            out.push(ascii);
            continue;
        }
        if let Some(latin) = homoglyph(c) {
            out.push(latin);
            continue;
        }
        if c == PERCENT {
            let mut probe = chars.clone();
            if let (Some(hi), Some(lo)) = (
                probe.next().and_then(hex_value),
                probe.next().and_then(hex_value),
            ) && let Ok(byte) = u8::try_from(hi * 16 + lo)
                && byte <= MAX_PERCENT_DECODED
            {
                out.push(char::from(byte));
                chars = probe;
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// One level of backslash unescaping (`\" \\ \/ \' \n \t \r \b \f \uXXXX`).
/// An escape that is not one of these, and a `\u` that names no scalar
/// value, is kept as written. One forward walk.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != ESCAPE {
            out.push(c);
            continue;
        }
        let decoded = match chars.peek().copied() {
            Some(q @ ('"' | '\\' | '/' | '\'')) => Some(q),
            Some('n') => Some('\n'),
            Some('t') => Some('\t'),
            Some('r') => Some('\r'),
            Some('b') => Some('\u{8}'),
            Some('f') => Some('\u{c}'),
            Some('u') => {
                let mut probe = chars.clone();
                probe.next();
                let mut value = 0u32;
                let mut digits = 0usize;
                while digits < UNICODE_ESCAPE_DIGITS {
                    match probe.next().and_then(hex_value) {
                        Some(d) => value = value * 16 + d,
                        None => break,
                    }
                    digits += 1;
                }
                match char::from_u32(value) {
                    Some(ch) if digits == UNICODE_ESCAPE_DIGITS => {
                        out.push(ch);
                        chars = probe;
                        continue;
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        match decoded {
            Some(d) => {
                out.push(d);
                chars.next();
            }
            None => out.push(c),
        }
    }
    out
}

/// The screen: one pass, then the re-screen of the redacted copy and of its
/// decoded views. Returns the sorted, deduplicated kinds and the redacted
/// copy; any residual makes the whole copy the placeholder (ruling (e)).
pub(super) fn screen_with_views(content: &str, pass: Pass) -> (Vec<&'static str>, String) {
    let (mut kinds, redacted) = pass(content);
    let mut residual: Vec<&'static str> = Vec::new();
    // (e) the redacted copy itself is screened again.
    if !kinds.is_empty() {
        residual.extend(pass(&redacted).0);
    }
    // (d) the decoded views of the redacted copy, at most
    // MAX_NESTED_SCREEN_DEPTH unescapes deep.
    let first = canonical(&redacted);
    if first != redacted || redacted.contains(ESCAPE) {
        if redacted.len() > MAX_VIEW_SCREEN_BYTES {
            residual.push(KIND_SIZE_BOUND);
        } else {
            if first != redacted {
                residual.extend(pass(&first).0);
            }
            let mut level = first;
            let mut depth = 0usize;
            loop {
                let next = canonical(&unescape(&level));
                if next == level {
                    break;
                }
                if depth == MAX_NESTED_SCREEN_DEPTH {
                    residual.push(KIND_DEPTH_BOUND);
                    break;
                }
                depth += 1;
                residual.extend(pass(&next).0);
                level = next;
            }
        }
    }
    if !residual.is_empty() {
        kinds.extend(residual);
        kinds.push(KIND_RESIDUAL);
    }
    kinds.sort_unstable();
    kinds.dedup();
    if kinds.contains(&KIND_RESIDUAL) {
        return (kinds, REDACTION_PLACEHOLDER.to_string());
    }
    (kinds, redacted)
}
