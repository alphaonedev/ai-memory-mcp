// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10299: the names an environment-name argument may be, besides one string
//! literal. A name is a named constant only when the tree binds it by a
//! `const` or `static [mut]` item whose initializer is one string literal and
//! binds it nowhere else: not by another `const` or `static` (any other
//! initializer, or a const generic parameter), a `let` or `for` pattern, a fn
//! or closure parameter, a match-arm pattern, a `NAME @` binding or a
//! `NAME :` (a struct field, a typed parameter or binding, a field pattern).
//! The census has no scope model, so a name bound twice is refused (the fail
//! closed side). Each pass is linear: every span is walked once. The Python
//! scanner (`scripts/ci/census_rows_10286.py`, `const_names`) is the same
//! rule; the shared table `census_env_name_10299.json` holds them together.

use std::collections::BTreeSet;

use crate::census_pins::Prep;
use crate::rust_lex::{Lexed, Tok};

/// Keywords after which a `|` opens closure parameters.
const CLOSURE_AFTER_KEYWORD: [&str; 7] = ["move", "return", "in", "else", "match", "if", "while"];

fn is_p(toks: &[Lexed], k: usize, c: char) -> bool {
    matches!(toks.get(k).map(|x| &x.tok), Some(Tok::Punct(prep)) if *prep == c)
}

fn punct(toks: &[Lexed], k: usize) -> Option<char> {
    match toks.get(k).map(|x| &x.tok) {
        Some(Tok::Punct(c)) => Some(*c),
        _ => None,
    }
}

fn ident_at(toks: &[Lexed], k: usize) -> Option<&str> {
    match toks.get(k).map(|x| &x.tok) {
        Some(Tok::Ident(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn close(prep: &Prep<'_>, k: usize) -> usize {
    prep.close
        .get(k)
        .copied()
        .flatten()
        .unwrap_or(prep.toks.len())
}

/// At a `const` or `static` token: the index of the NAME of
/// `const|static [mut] NAME :` and whether its initializer is one string
/// literal (`= "..." ;`); `None` when no NAME follows.
fn item_binding(prep: &Prep<'_>, k: usize) -> Option<(usize, bool)> {
    let toks = prep.toks;
    let mut j = k + 1;
    if ident_at(toks, k) == Some("static") && ident_at(toks, j) == Some("mut") {
        j += 1;
    }
    ident_at(toks, j)?;
    if !is_p(toks, j + 1, ':') {
        return None;
    }
    let mut m = j + 2;
    while m < toks.len() {
        match punct(toks, m) {
            Some('(' | '[' | '{') => {
                m = close(prep, m) + 1;
                continue;
            }
            Some('=') => break,
            Some(';' | '}' | ')' | ',' | ']' | '>') => return Some((j, false)),
            _ => {}
        }
        m += 1;
    }
    let lit =
        matches!(toks.get(m + 1).map(|x| &x.tok), Some(Tok::Str(_))) && is_p(toks, m + 2, ';');
    Some((j, lit))
}

/// A `|` at `k` opens closure parameters: the token before it ends no operand.
fn closure_open(toks: &[Lexed], k: usize) -> bool {
    let Some(prev) = k.checked_sub(1).and_then(|j| toks.get(j)) else {
        return true;
    };
    match &prev.tok {
        Tok::Ident(s) => CLOSURE_AFTER_KEYWORD.contains(&s.as_str()),
        Tok::Str(_) | Tok::Num(_) | Tok::Char(_) => false,
        Tok::Punct(c) => !matches!(c, ')' | ']' | '|'),
        Tok::PathSep => true,
    }
}

/// From `a` to the first top-level `=` (a `let`) or `in` (a `for`), `;` or
/// closer; a `for` also ends at a `{` that is not a pattern's (one not
/// followed by `in`).
fn forward(prep: &Prep<'_>, a: usize, is_let: bool) -> usize {
    let toks = prep.toks;
    let mut m = a;
    while m < toks.len() {
        match punct(toks, m) {
            Some(c @ ('(' | '[' | '{')) => {
                let end = close(prep, m);
                if c == '{' && !is_let && ident_at(toks, end + 1) != Some("in") {
                    return m;
                }
                m = end + 1;
                continue;
            }
            Some(';' | ')' | ']' | '}') => return m,
            Some('=') if is_let => return m,
            None if !is_let && ident_at(toks, m) == Some("in") => return m,
            _ => {}
        }
        m += 1;
    }
    toks.len()
}

/// The end of the closure parameters opened at `k` (the closing `|`, or the
/// `;` or closer where they stop).
fn closure_end(prep: &Prep<'_>, k: usize) -> usize {
    let toks = prep.toks;
    let mut m = k + 1;
    while m < toks.len() && !is_p(toks, m, '|') {
        match punct(toks, m) {
            Some('(' | '[' | '{') => {
                m = close(prep, m) + 1;
                continue;
            }
            Some(';' | ')' | ']' | '}') => break,
            _ => {}
        }
        m += 1;
    }
    m
}

/// The parameter list `(` of a `fn NAME [<..>] (`, if one follows `k`.
fn fn_params(toks: &[Lexed], k: usize) -> Option<usize> {
    ident_at(toks, k + 1)?;
    let mut j = k + 2;
    let mut depth = 0usize;
    while j < toks.len() {
        match punct(toks, j) {
            Some('(') if depth == 0 => return Some(j),
            Some('<') => depth += 1,
            Some('>') if !is_p(toks, j.wrapping_sub(1), '-') => depth = depth.saturating_sub(1),
            Some(';' | '{' | '}') => return None,
            _ => {}
        }
        j += 1;
    }
    None
}

/// The first index of the match-arm pattern ending at the `=` of `=>` at `k`.
fn arm_start(prep: &Prep<'_>, opener: &[Option<usize>], k: usize) -> usize {
    let toks = prep.toks;
    let mut j = k;
    while let Some(i) = j.checked_sub(1) {
        match punct(toks, i) {
            Some(',' | ';' | '{' | '(' | '[') => return j,
            Some('>') if is_p(toks, i.wrapping_sub(1), '=') => return j,
            Some(')' | ']') => match opener[i] {
                Some(o) => {
                    j = o;
                    continue;
                }
                None => return j,
            },
            Some('}') => match opener[i] {
                Some(o) if o > 0 && ident_at(toks, o - 1).is_some() => {
                    j = o;
                    continue;
                }
                _ => return j,
            },
            _ => {}
        }
        j = i;
    }
    0
}

/// Every name one file binds other than at an item NAME in `defs`.
fn binder_names(prep: &Prep<'_>, defs: &BTreeSet<usize>, out: &mut BTreeSet<String>) {
    let toks = prep.toks;
    let n = toks.len();
    let mut opener = vec![None; n];
    for (o, c) in prep.close.iter().enumerate() {
        if let Some(c) = *c
            && c < n
        {
            opener[c] = Some(o);
        }
    }
    let mark = |a: usize, b: usize, out: &mut BTreeSet<String>| {
        for x in toks.get(a..b.min(n)).unwrap_or(&[]) {
            if let Tok::Ident(s) = &x.tok {
                out.insert(s.clone());
            }
        }
    };
    let mut k = 0;
    while k < n {
        match &toks[k].tok {
            Tok::Ident(s) => {
                if !defs.contains(&k) && (is_p(toks, k + 1, ':') || is_p(toks, k + 1, '@')) {
                    out.insert(s.clone());
                }
                if s == "let" || s == "for" {
                    mark(k + 1, forward(prep, k + 1, s == "let"), out);
                } else if s == "fn"
                    && let Some(j) = fn_params(toks, k)
                {
                    mark(j + 1, close(prep, j), out);
                }
            }
            Tok::Punct('|') if closure_open(toks, k) => {
                let m = closure_end(prep, k);
                mark(k + 1, m, out);
                k = if is_p(toks, m, '|') { m + 1 } else { m };
                continue;
            }
            Tok::Punct('=') if is_p(toks, k + 1, '>') => {
                mark(arm_start(prep, &opener, k), k, out);
            }
            _ => {}
        }
        k += 1;
    }
}

/// The names an environment-name argument may be: bound in the tree by a
/// `const` or `static [mut]` with one string literal and nowhere else.
pub(crate) fn const_names(preps: &[Prep<'_>]) -> BTreeSet<String> {
    let mut literal = BTreeSet::new();
    let mut other = BTreeSet::new();
    for prep in preps {
        let toks = prep.toks;
        let mut defs = BTreeSet::new();
        for k in 0..toks.len() {
            if !matches!(ident_at(toks, k), Some("const" | "static")) {
                continue;
            }
            if let Some((j, lit)) = item_binding(prep, k)
                && let Some(name) = ident_at(toks, j)
            {
                defs.insert(j);
                if lit {
                    literal.insert(name.to_string());
                } else {
                    other.insert(name.to_string());
                }
            }
        }
        binder_names(prep, &defs, &mut other);
    }
    literal.difference(&other).cloned().collect()
}
