// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Whole-value grammar walkers for the named non-credential shapes of an
//! unquoted password-assignment value (#9351).
//!
//! A shape is accepted only when its grammar matches the WHOLE judged value,
//! first byte to last: a prefix match (`starts_with`, a base name before the
//! first bracket, a type name followed by anything) accepts every value that
//! merely begins like the shape and carries a secret after it. Each walker
//! reads each byte at most once and advances only over ASCII bytes, so every
//! position it returns is a char boundary (OWNERSHIP-15). No regex, no
//! backtracking, no `unwrap` / `expect` (ERRORS-06).

use super::{
    ANNOTATION_TYPE_NAMES, ENV_LOOKUP_PREFIXES, JUDGED_TRAILERS, LIFETIME_SIGIL, ident_end,
    is_ident_byte, skip_blanks,
};

/// Bracket depth past which a type expression is not accepted. Real types
/// nest a handful of levels; the cap bounds the closer stack.
const MAX_TYPE_NESTING: usize = 64;
/// Path separator inside a type (`std::string::String`).
const PATH_SEPARATOR: &[u8] = b"::";
/// The Rust `?` operator that may follow a closed lookup once.
const TRY_OPERATOR: u8 = b'?';
/// Fallback operators that put a default after a lookup (`x or "d"`,
/// `x || "d"`, `x ?? "d"`, `x ?: "d"`, Perl `x // "d"`).
const FALLBACK_OPERATORS: [&[u8]; 4] = [b"||", b"??", b"?:", b"//"];
/// The Python / Ruby / Perl word fallback operator.
const FALLBACK_WORD: &[u8] = b"or";
/// Closers of an enclosing construct that may follow an annotation
/// (`fn f(pwd: &str)`, `Vec<&str>`, `{ pwd: String }`).
const ENCLOSING_CLOSERS: [u8; 4] = [b')', b'>', b']', b'}'];

/// How an unquoted judged value matches the env-lookup grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EnvShape {
    /// No [`ENV_LOOKUP_PREFIXES`] entry starts the value.
    NotLookup,
    /// The whole value is one lookup: `HEAD NAME CLOSER [?]`.
    Whole,
    /// A lookup head followed by bytes its grammar does not hold.
    /// `unclosed` when the head's closer never appears in the value, so the
    /// lookup runs past the value's end and its true extent is unknown.
    Broken { unclosed: bool },
}

/// The closer the head's last byte opens; `None` for a member-access head
/// (`process.env.`), whose name runs to the end of the value.
fn closer_of(head: &str) -> Option<u8> {
    match head.as_bytes().last() {
        Some(b'[') => Some(b']'),
        Some(b'(') => Some(b')'),
        Some(b'{') => Some(b'}'),
        _ => None,
    }
}

/// Bytes after an identifier that starts at `at`: the end of a non-empty
/// identifier, or `None` when no identifier byte is at `at`.
fn nonempty_ident_end(bytes: &[u8], at: usize) -> Option<usize> {
    let end = ident_end(bytes, at);
    (end > at).then_some(end)
}

/// Judge `v` (an unquoted judged value) against the env-lookup grammar:
/// `HEAD` from [`ENV_LOOKUP_PREFIXES`], then for a member-access head an
/// identifier to the end; for a bracket head a NAME (an identifier, or a
/// quote, identifier bytes, the same quote), the head's closer, at most one
/// [`TRY_OPERATOR`], then the end of the value.
pub(super) fn env_lookup_shape(v: &str) -> EnvShape {
    let Some(head) = ENV_LOOKUP_PREFIXES.iter().find(|p| v.starts_with(*p)) else {
        return EnvShape::NotLookup;
    };
    let rest = &v.as_bytes()[head.len()..];
    let Some(closer) = closer_of(head) else {
        return if nonempty_ident_end(rest, 0) == Some(rest.len()) {
            EnvShape::Whole
        } else {
            EnvShape::Broken { unclosed: false }
        };
    };
    let whole = || -> Option<()> {
        let name_end = match rest.first() {
            Some(&q @ (b'"' | b'\'')) => {
                let end = nonempty_ident_end(rest, 1)?;
                (rest.get(end) == Some(&q)).then_some(end + 1)?
            }
            _ => nonempty_ident_end(rest, 0)?,
        };
        (rest.get(name_end) == Some(&closer)).then_some(())?;
        let mut k = name_end + 1;
        if rest.get(k) == Some(&TRY_OPERATOR) {
            k += 1;
        }
        (k == rest.len()).then_some(())
    };
    match whole() {
        Some(()) => EnvShape::Whole,
        None => EnvShape::Broken {
            unclosed: !rest.contains(&closer),
        },
    }
}

/// True when a fallback operator follows the value that ends at `end`, on
/// the same line after blanks: the lookup then carries a default whose
/// extent is expression grammar, so the line is a finding.
pub(super) fn fallback_follows(bytes: &[u8], end: usize) -> bool {
    let at = skip_blanks(bytes, end);
    let rest = bytes.get(at..).unwrap_or_default();
    FALLBACK_OPERATORS.iter().any(|op| rest.starts_with(op))
        || (rest.starts_with(FALLBACK_WORD)
            && !rest
                .get(FALLBACK_WORD.len())
                .is_some_and(|&c| is_ident_byte(c)))
}

/// How a type expression starting at a position walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TypeWalk {
    /// No [`ANNOTATION_TYPE_NAMES`] entry is the base name.
    NotType,
    /// A complete type expression ends right before this position.
    End(usize),
    /// An unclosed, mismatched or over-nested bracket, or a byte a type
    /// expression cannot hold inside a bracket.
    Broken,
}

/// The closer an opening type bracket needs.
fn type_closer(open: u8) -> Option<u8> {
    match open {
        b'<' => Some(b'>'),
        b'[' => Some(b']'),
        b'(' => Some(b')'),
        _ => None,
    }
}

/// Walk the type expression at `at`: a base name from
/// [`ANNOTATION_TYPE_NAMES`], then path segments (`::IDENT`) and balanced
/// `<…>` / `[…]` / `(…)` groups whose interior holds identifiers, paths,
/// lifetimes, `&`, `,` and blanks. At depth 0 the expression ends at the
/// first byte it cannot continue with, and right after the bracket that
/// returns the depth to 0. Inside a bracket any other byte, the end of
/// input, a wrong closer or a depth past [`MAX_TYPE_NESTING`] is
/// [`TypeWalk::Broken`]. Each byte is read once.
pub(super) fn walk_type(bytes: &[u8], at: usize) -> TypeWalk {
    let name_end = ident_end(bytes, at);
    let name = bytes.get(at..name_end).unwrap_or_default();
    if !ANNOTATION_TYPE_NAMES.iter().any(|n| n.as_bytes() == name) {
        return TypeWalk::NotType;
    }
    let mut closers: Vec<u8> = Vec::new();
    let mut k = name_end;
    loop {
        let depth = closers.len();
        let end_here = if depth == 0 {
            TypeWalk::End(k)
        } else {
            TypeWalk::Broken
        };
        let Some(&c) = bytes.get(k) else {
            return end_here;
        };
        if is_ident_byte(c) {
            k = ident_end(bytes, k);
        } else if bytes.get(k..k + PATH_SEPARATOR.len()) == Some(PATH_SEPARATOR) {
            let seg = k + PATH_SEPARATOR.len();
            match nonempty_ident_end(bytes, seg) {
                Some(seg_end) => k = seg_end,
                None => return end_here,
            }
        } else if let Some(closer) = type_closer(c) {
            if depth >= MAX_TYPE_NESTING {
                return TypeWalk::Broken;
            }
            closers.push(closer);
            k += 1;
        } else if matches!(c, b'>' | b']' | b')') {
            match closers.pop() {
                None => return TypeWalk::End(k),
                Some(want) if want != c => return TypeWalk::Broken,
                Some(_) if closers.is_empty() => return TypeWalk::End(k + 1),
                Some(_) => k += 1,
            }
        } else if depth > 0 && matches!(c, b'&' | b',' | b' ' | b'\t') {
            k += 1;
        } else if depth > 0 && c == LIFETIME_SIGIL {
            let lifetime_end = ident_end(bytes, k + 1);
            let starts_ident = bytes
                .get(k + 1)
                .is_some_and(|&b| b.is_ascii_alphabetic() || b == b'_');
            if !starts_ident || bytes.get(lifetime_end) == Some(&LIFETIME_SIGIL) {
                return TypeWalk::Broken;
            }
            k = lifetime_end;
        } else {
            return end_here;
        }
    }
}

/// True when the bytes from `e` (the end of a type expression) hold only
/// what may follow an annotation: closers of an enclosing construct
/// ([`ENCLOSING_CLOSERS`]), then [`JUDGED_TRAILERS`], then ASCII whitespace
/// or the end of input.
pub(super) fn annotation_suffix_ok(bytes: &[u8], e: usize) -> bool {
    let mut k = e;
    while bytes.get(k).is_some_and(|c| ENCLOSING_CLOSERS.contains(c)) {
        k += 1;
    }
    while bytes
        .get(k)
        .is_some_and(|&c| JUDGED_TRAILERS.contains(&char::from(c)))
    {
        k += 1;
    }
    bytes.get(k).is_none_or(u8::is_ascii_whitespace)
}

/// End of the unquoted token from `from`: the first ASCII whitespace, else
/// the end of input (always a char boundary).
pub(super) fn token_end(bytes: &[u8], from: usize) -> usize {
    let mut k = from;
    while k < bytes.len() && !bytes[k].is_ascii_whitespace() {
        k += 1;
    }
    k
}

/// `${IDENT}` exactly: the whole value is one shell parameter reference with
/// no operator (`${X:-default}` carries a literal default).
pub(super) fn is_brace_reference(v: &str) -> bool {
    v.strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .is_some_and(|name| {
            let b = name.as_bytes();
            b.first()
                .is_some_and(|&c| c.is_ascii_alphabetic() || c == b'_')
                && nonempty_ident_end(b, 0) == Some(b.len())
        })
}

/// `<…>` exactly: first byte `<`, last byte `>`, and no `<` / `>` between
/// them, so `<a>secret>` (a closed placeholder then bytes) is not one.
pub(super) fn is_angle_placeholder(v: &str) -> bool {
    v.strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
        .is_some_and(|inner| !inner.bytes().any(|c| c == b'<' || c == b'>'))
}
