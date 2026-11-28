// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10286: the site pins of the process-start census, and the linear scans
//! the census and `scripts/ci/census_rows_10286.py` both compute (the Python
//! scanner is a second, independent implementation; it shares no code with
//! this file).
//!
//! A site is one place in a file where a watched name is reached:
//!
//! * `T`: every identifier token of a watched process, libc, nix or proptest
//!   name (or of a name bound to one), with [`SITE_RADIUS`] tokens on each
//!   side;
//! * `U`: every `use` declaration that names `env`, an environment function
//!   or a name bound to either, from `use` to its `;` (at most [`USE_CAP`]
//!   tokens);
//! * `E`: every environment reach whose name is not one literal or one named
//!   constant (see [`env_calls`]), from two tokens before the name to the end
//!   of the first group (at most [`ARG_CAP`] tokens after its opener).
//!
//! Each site's tokens are written as kind, UTF-8 byte length, `:` and text
//! (`^` and `$` for positions before and after the file), prefixed with the
//! site kind, hashed with SHA-256 ([`sha256`], hand-written, no dependency)
//! and cut to [`DIGEST_HEX`] hex digits. `SITE_ROWS` holds every file's
//! ordered digests.
//!
//! What a pin proves: any edit of a token inside a site window (a swap of
//! one watched call for another, a changed argument, a renamed path segment,
//! a token added or removed next to a watched token) changes that site's
//! digest, so the file is red with the site index, line and token until its
//! row changes, even when the per-file count stays the same. A new or
//! removed site shifts the list and is red the same way.
//!
//! What a pin does not prove: that a change is safe. A pin only makes every
//! change at a watched site visible in review, as a changed row. An edit
//! wholly outside every window (a value computed elsewhere and passed in by a
//! name that is not watched) does not change a pin; the env rules of part C
//! and the macro rules of part B (`census_macros_10287.rs`) are the checks
//! for those forms. A whole site moved to another place with the same
//! [`SITE_RADIUS`] neighbours on each side, keeping the order of the file's
//! sites, keeps its pin: the pin binds the reach and its neighbours, not the
//! enclosing item (the start rules of the census bind the item). Sixteen hex
//! digits are 64 bits of SHA-256: for n pins the chance of any accidental
//! collision is about n^2 / 2^65, about 1.3e-13 for the ~2200 pins of the
//! tree (#10306), and the pin is a review signal, not a secret. The hash is
//! checked against the FIPS 180-4 vectors by
//! `census_sha256_fips_180_4_vectors_10306`.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::rust_lex::{Lexed, Tok};

/// Tokens on each side of a watched token in a `T` site.
pub(crate) const SITE_RADIUS: usize = 2;
/// The most tokens of an `E` site after its group opener.
pub(crate) const ARG_CAP: usize = 64;
/// The most tokens of a `U` site after its `use`.
pub(crate) const USE_CAP: usize = 256;
/// The most tokens of an impl header read; a longer one is an impl form.
pub(crate) const IMPL_CAP: usize = 512;
/// Hex digits of a site digest.
pub(crate) const DIGEST_HEX: usize = 16;

/// The seed of the module name of the environment functions.
pub(crate) const ENV_MOD_SEED: &[&str] = &["env"];
/// The seed of the environment functions that read or change a variable.
pub(crate) const ENV_FN_SEED: &[&str] = &["remove_var", "set_var", "var", "var_os"];

// ---------------------------------------------------------------- SHA-256

const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 of `data` (FIPS 180-4), written out so the census needs no crate.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let bits = u64::try_from(data.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    let mut h = H0;
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (slot, b) in w.iter_mut().zip(chunk.as_chunks::<4>().0) {
            *slot = u32::from_be_bytes(*b);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for (kc, wc) in K.iter().zip(w) {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(*kc)
                .wrapping_add(wc);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for (x, y) in h.iter_mut().zip(v) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (dst, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *dst = word.to_be_bytes();
    }
    out
}

/// The first [`DIGEST_HEX`] lower-case hex digits of SHA-256 of `kind` and `body`.
pub(crate) fn digest(kind: &str, body: &str) -> String {
    let mut text = String::with_capacity(kind.len() + body.len());
    text.push_str(kind);
    text.push_str(body);
    let mut out = String::with_capacity(DIGEST_HEX);
    for b in sha256(text.as_bytes()).iter().take(DIGEST_HEX / 2) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ---------------------------------------------------------------- tokens

fn tok_at(t: &[Lexed], k: usize) -> Option<&Tok> {
    t.get(k).map(|x| &x.tok)
}

fn is_p(t: &[Lexed], k: usize, c: char) -> bool {
    matches!(tok_at(t, k), Some(Tok::Punct(p)) if *p == c)
}

/// `is_p` at `k - 1`, false at the start of the file.
fn is_p_before(t: &[Lexed], k: usize, c: char) -> bool {
    k.checked_sub(1).is_some_and(|j| is_p(t, j, c))
}

fn ident_at(t: &[Lexed], k: usize) -> Option<&str> {
    match tok_at(t, k) {
        Some(Tok::Ident(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn is_sep(t: &[Lexed], k: usize) -> bool {
    matches!(tok_at(t, k), Some(Tok::PathSep))
}

fn in_set(t: &[Lexed], k: usize, set: &BTreeSet<String>) -> bool {
    ident_at(t, k).is_some_and(|s| set.contains(s))
}

fn is_opener(t: &[Lexed], k: usize) -> bool {
    matches!(tok_at(t, k), Some(Tok::Punct('(' | '[' | '{')))
}

/// A `use` declaration starts at `k` (not a path segment named `use`).
fn is_use(t: &[Lexed], k: usize) -> bool {
    ident_at(t, k) == Some("use") && !k.checked_sub(1).is_some_and(|j| is_sep(t, j))
}

/// The bracket, `;` and `;{}` tables of one file, computed once (one pass each).
pub(crate) struct Prep<'a> {
    pub(crate) toks: &'a [Lexed],
    /// For each opener its closer (the length when unclosed); `None` elsewhere.
    pub(crate) close: Vec<Option<usize>>,
    /// For each index the next `;` at or after it (the length when none).
    pub(crate) semi: Vec<usize>,
    /// For each index the next `;`, `{` or `}` at or after it.
    pub(crate) stop: Vec<usize>,
}

fn next_of(t: &[Lexed], stops: &[char]) -> Vec<usize> {
    let mut out = vec![t.len(); t.len() + 1];
    for k in (0..t.len()).rev() {
        out[k] = match &t[k].tok {
            Tok::Punct(c) if stops.contains(c) => k,
            _ => out[k + 1],
        };
    }
    out
}

/// The count prefix: `out[k]` is the number of tokens before `k` that hit.
fn prefix(t: &[Lexed], hit: impl Fn(&Tok) -> bool) -> Vec<usize> {
    let mut out = vec![0usize; t.len() + 1];
    for (k, x) in t.iter().enumerate() {
        out[k + 1] = out[k] + usize::from(hit(&x.tok));
    }
    out
}

fn named_prefix(t: &[Lexed], set: &BTreeSet<String>) -> Vec<usize> {
    prefix(t, |x| matches!(x, Tok::Ident(s) if set.contains(s)))
}

impl<'a> Prep<'a> {
    pub(crate) fn new(toks: &'a [Lexed]) -> Self {
        let mut close = vec![None; toks.len()];
        let mut stack = Vec::new();
        for (k, x) in toks.iter().enumerate() {
            match x.tok {
                Tok::Punct('(' | '[' | '{') => stack.push(k),
                Tok::Punct(')' | ']' | '}') => {
                    if let Some(o) = stack.pop() {
                        close[o] = Some(k);
                    }
                }
                _ => {}
            }
        }
        for o in stack {
            close[o] = Some(toks.len());
        }
        Prep {
            toks,
            close,
            semi: next_of(toks, &[';']),
            stop: next_of(toks, &[';', '{', '}']),
        }
    }

    /// The closer of the opener at `k` (the length when unclosed).
    fn close_of(&self, k: usize) -> usize {
        self.close
            .get(k)
            .copied()
            .flatten()
            .unwrap_or(self.toks.len())
    }
}

/// The seed and every name bound to a member, to a fixpoint over the tree:
/// `X as Y` and `self as Y` in a `use`, `extern crate X as Y`,
/// `type Y = .. X ..` and a `macro_rules! Y` whose body names one. Each pass
/// is linear in the tokens of the tree.
pub(crate) fn closure(files: &[Prep<'_>], seed: &[&str]) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = seed.iter().map(|s| (*s).to_string()).collect();
    loop {
        let mut add = BTreeSet::new();
        for p in files {
            bound_in(p, &names, &mut add);
        }
        let before = names.len();
        names.extend(add);
        if names.len() == before {
            return names;
        }
    }
}

#[expect(
    clippy::many_single_char_names,
    reason = "token-walk indices (p, t, n, k, e) follow the lexer convention of every census scan"
)]
fn bound_in(p: &Prep<'_>, names: &BTreeSet<String>, add: &mut BTreeSet<String>) {
    let t = p.toks;
    let n = t.len();
    let prefixed = named_prefix(t, names);
    let mut use_until = 0usize;
    for k in 0..n {
        match ident_at(t, k) {
            Some("use") => {
                if k < use_until {
                    continue;
                }
                let end = p.semi[k];
                use_until = end;
                let mut seen = false;
                for j in k..end {
                    seen |= in_set(t, j, names);
                    let Some(y) = ident_at(t, j + 2) else {
                        continue;
                    };
                    if y == "_" || j + 2 >= end || ident_at(t, j + 1) != Some("as") {
                        continue;
                    }
                    if in_set(t, j, names) || (ident_at(t, j) == Some("self") && seen) {
                        add.insert(y.to_string());
                    }
                }
            }
            Some("extern")
                if ident_at(t, k + 1) == Some("crate") && ident_at(t, k + 3) == Some("as") =>
            {
                if let Some(y) = ident_at(t, k + 4)
                    && in_set(t, k + 2, names)
                    && y != "_"
                {
                    add.insert(y.to_string());
                }
            }
            Some("type") if !k.checked_sub(1).is_some_and(|j| is_sep(t, j)) => {
                let Some(y) = ident_at(t, k + 1) else {
                    continue;
                };
                let e = p.stop[k + 1];
                if e > k + 2 && prefixed[e] > prefixed[k + 2] {
                    add.insert(y.to_string());
                }
            }
            Some("macro_rules") if is_p(t, k + 1, '!') => {
                let Some(y) = ident_at(t, k + 2) else {
                    continue;
                };
                let open = k + 3;
                let end = match p.close.get(open).copied().flatten() {
                    Some(c) => c,
                    None => open,
                };
                if prefixed[end.min(n)] > prefixed[open.min(n)] {
                    add.insert(y.to_string());
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------- shapes

/// Every form of one file the census does not model, `(kind, line)`; linear
/// (an impl header is read at most [`IMPL_CAP`] tokens, and a longer one
/// counts as an impl form).
#[expect(
    clippy::many_single_char_names,
    reason = "token-walk indices (p, t, n, k, e) follow the lexer convention of every census scan"
)]
pub(crate) fn shapes_of(p: &Prep<'_>, watched: &BTreeSet<String>) -> Vec<(&'static str, usize)> {
    let t = p.toks;
    let n = t.len();
    let mut out = Vec::new();
    let stars = prefix(t, |x| matches!(x, Tok::Punct('*')));
    let named = named_prefix(t, watched);
    for k in 0..n {
        let line = t[k].line;
        let v = ident_at(t, k);
        if v == Some("impl") {
            let (mut m, mut d, mut hit) = (k + 1, 0usize, false);
            let cap = n.min(k + 1 + IMPL_CAP);
            while m < cap {
                match &t[m].tok {
                    Tok::Punct('<' | '(' | '[') => d += 1,
                    Tok::Punct('>' | ')' | ']') => d = d.saturating_sub(1),
                    Tok::Punct('{' | ';') if d == 0 => break,
                    Tok::Ident(s) if watched.contains(s) => hit = true,
                    _ => {}
                }
                m += 1;
            }
            if m == cap && cap < n {
                hit = true;
            }
            if hit {
                out.push(("impl", line));
            }
        }
        if in_set(t, k, watched) && is_sep(t, k + 1) && is_p(t, k + 2, '$') {
            out.push(("metavar", line));
        }
        if is_use(t, k) {
            let e = p.semi[k];
            if stars[e] > stars[k] && named[e] > named[k] {
                out.push(("glob", line));
            }
        }
        if is_p(t, k, '[') && is_p(t, k + 1, '<') {
            out.push(("paste", line));
        }
        if matches!(v, Some("paste" | "concat_idents")) && is_p(t, k + 1, '!') {
            out.push(("paste", line));
        }
        if matches!(v, Some("asm" | "global_asm" | "naked_asm")) && is_p(t, k + 1, '!') {
            out.push(("asm", line));
        }
        if v == Some("extern")
            && (is_p(t, k + 1, '{')
                || (matches!(tok_at(t, k + 1), Some(Tok::Str(_))) && is_p(t, k + 2, '{')))
        {
            out.push(("extern", line));
        }
    }
    out
}

// ---------------------------------------------------------------- C: env reach

/// The first argument of the group opened at `open` (nested groups skipped
/// whole, in one pass).
pub(crate) fn first_arg<'t>(p: &Prep<'t>, open: usize) -> &'t [Lexed] {
    let t = p.toks;
    let end = p.close_of(open).min(t.len());
    let mut k = open + 1;
    while k < end {
        if is_opener(t, k) {
            k = p.close_of(k) + 1;
            continue;
        }
        if is_p(t, k, ',') {
            return &t[open + 1..k];
        }
        k += 1;
    }
    t.get(open + 1..end).unwrap_or(&[])
}

/// Whether an environment-name argument is one string literal or one named
/// constant (`[&] [path ::] NAME`, NAME upper case).
pub(crate) fn name_ok(arg: &[Lexed]) -> bool {
    if let [one] = arg
        && matches!(one.tok, Tok::Str(_))
    {
        return true;
    }
    let arg = match arg.first() {
        Some(x) if matches!(x.tok, Tok::Punct('&')) => &arg[1..],
        _ => arg,
    };
    let Some(Tok::Ident(last)) = arg.last().map(|x| &x.tok) else {
        return false;
    };
    let mut chars = last.chars();
    let caps = chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    caps && arg.iter().enumerate().all(|(i, x)| {
        if i % 2 == 0 {
            matches!(x.tok, Tok::Ident(_))
        } else {
            matches!(x.tok, Tok::PathSep)
        }
    })
}

/// One environment reach whose name is not one literal or one constant: the
/// name token and the window of its `E` site (`lo` may be before the file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EnvCall {
    pub(crate) k: usize,
    pub(crate) lo: i64,
    pub(crate) hi: i64,
}

fn signed(k: usize) -> i64 {
    i64::try_from(k).unwrap_or(i64::MAX)
}

/// Every environment reach of one file whose name is not ok: a call of an
/// environment function (by any name bound to one, through any import form)
/// whose first argument is not one literal or one constant, `.env(` and
/// `.env_remove(` and `env!` and `option_env!` likewise, every `.envs(`, and
/// every environment function named as a value (not called, not a method,
/// not a definition, not in a `use`).
pub(crate) fn env_calls(p: &Prep<'_>, env_fns: &BTreeSet<String>) -> Vec<EnvCall> {
    let t = p.toks;
    let n = t.len();
    let mut out = Vec::new();
    let mut in_use_until: Option<usize> = None;
    for k in 0..n {
        let Some(v) = ident_at(t, k) else { continue };
        if is_use(t, k) {
            in_use_until = Some(p.semi[k]);
        }
        let after_fn =
            is_p_before(t, k, '.') || k.checked_sub(1).and_then(|j| ident_at(t, j)) == Some("fn");
        let is_fn = env_fns.contains(v);
        let call = is_p(t, k + 1, '(');
        let ks = signed(k);
        let radius = signed(SITE_RADIUS);
        if is_fn && !after_fn && !call && in_use_until.is_none_or(|u| k > u) {
            out.push(EnvCall {
                k,
                lo: ks - radius,
                hi: ks + radius,
            });
            continue;
        }
        let dot = is_p_before(t, k, '.');
        let (open, always) = if (call && is_fn && !after_fn)
            || (matches!(v, "env" | "env_remove") && dot && call)
        {
            (Some(k + 1), false)
        } else if v == "envs" && dot && call {
            (Some(k + 1), true)
        } else if matches!(v, "env" | "option_env") && is_p(t, k + 1, '!') && is_opener(t, k + 2) {
            (Some(k + 2), false)
        } else {
            (None, false)
        };
        let Some(open) = open else { continue };
        if always || !name_ok(first_arg(p, open)) {
            let hi = p
                .close_of(open)
                .min(open + ARG_CAP)
                .min(n.saturating_sub(1));
            out.push(EnvCall {
                k,
                lo: ks - radius,
                hi: signed(hi),
            });
        }
    }
    out
}

/// `(use index, end index)` of every `use` declaration naming an env name.
fn use_sites(p: &Prep<'_>, env_names: &BTreeSet<String>) -> Vec<(usize, usize)> {
    let t = p.toks;
    let named = named_prefix(t, env_names);
    (0..t.len())
        .filter(|&k| is_use(t, k) && named[p.semi[k]] > named[k])
        .map(|k| (k, p.semi[k]))
        .collect()
}

// ---------------------------------------------------------------- pins

/// The written tokens `lo..=hi`, with `^` and `$` for positions outside.
pub(crate) fn encode(t: &[Lexed], lo: i64, hi: i64) -> String {
    let mut out = String::new();
    for m in lo..=hi {
        let Ok(i) = usize::try_from(m) else {
            out.push('^');
            continue;
        };
        let Some(x) = t.get(i) else {
            out.push('$');
            continue;
        };
        let (kind, text): (char, String) = match &x.tok {
            Tok::Ident(s) => ('I', s.clone()),
            Tok::Punct(c) => ('P', c.to_string()),
            Tok::PathSep => ('S', "::".to_string()),
            Tok::Str(s) => ('Q', s.clone()),
            Tok::Char(v) => ('C', v.clone()),
            Tok::Num(v) => ('N', v.clone()),
        };
        let _ = write!(out, "{kind}{}:{text}", text.len());
    }
    out
}

/// One pinned site: its token index, line, token text and digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Site {
    pub(crate) k: usize,
    pub(crate) line: usize,
    pub(crate) what: String,
    pub(crate) digest: String,
}

/// The ordered sites of one file (by token index, then T, U, E).
pub(crate) fn sites_of(
    p: &Prep<'_>,
    watched: &BTreeSet<String>,
    env_names: &BTreeSet<String>,
    env_fns: &BTreeSet<String>,
) -> Vec<Site> {
    let t = p.toks;
    let mut found: Vec<(usize, u8, String)> = Vec::new();
    let radius = signed(SITE_RADIUS);
    for k in 0..t.len() {
        if in_set(t, k, watched) {
            let ks = signed(k);
            found.push((k, 0, digest("T", &encode(t, ks - radius, ks + radius))));
        }
    }
    for (k, end) in use_sites(p, env_names) {
        let hi = end.min(k + USE_CAP);
        found.push((k, 1, digest("U", &encode(t, signed(k), signed(hi)))));
    }
    for c in env_calls(p, env_fns) {
        found.push((c.k, 2, digest("E", &encode(t, c.lo, c.hi))));
    }
    found.sort();
    found
        .into_iter()
        .map(|(k, kind, digest)| {
            let name = match &t[k].tok {
                Tok::Ident(s) => s.clone(),
                _ => String::new(),
            };
            let what = match kind {
                0 => name,
                1 => "a use of env".to_string(),
                _ => format!("env reach {name}"),
            };
            Site {
                k,
                line: t[k].line,
                what,
                digest,
            }
        })
        .collect()
}

/// The site findings of one file against its `SITE_ROWS` row (`None`: no row).
pub(crate) fn site_findings(rel: &str, sites: &[Site], row: Option<&[&str]>) -> Vec<String> {
    let want = row.unwrap_or(&[]);
    let mut out = Vec::new();
    if sites.len() != want.len() {
        out.push(format!(
            "{rel}: {} watched sites, SITE_ROWS has {}; a new or removed site needs its row (#10286)",
            sites.len(),
            want.len()
        ));
    }
    if let Some((i, s)) = sites
        .iter()
        .enumerate()
        .find(|(i, s)| want.get(*i) != Some(&s.digest.as_str()))
    {
        out.push(format!(
            "{rel}: site {i} (line {}, {}) pins {}, SITE_ROWS has {}; an edit at or next to a watched token needs its row (#10286)",
            s.line,
            s.what,
            s.digest,
            want.get(i).copied().unwrap_or("nothing")
        ));
    }
    out
}

/// The table findings of `SITE_ROWS` itself: every row for a file with no
/// site, a digest that is not [`DIGEST_HEX`] lower-case hex digits, and
/// rows out of order or twice.
pub(crate) fn site_table_findings(rows: &[(&str, &[&str])], have: &BTreeSet<&str>) -> Vec<String> {
    let mut out = Vec::new();
    for (rel, pins) in rows {
        if !have.contains(rel) {
            out.push(format!(
                "{rel}: 0 watched sites, SITE_ROWS has {}; a stale row is red (#10286)",
                pins.len()
            ));
        }
        for d in *pins {
            if d.len() != DIGEST_HEX || !d.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                out.push(format!(
                    "{rel}: SITE_ROWS digest {d:?} is not {DIGEST_HEX} lower-case hex digits (#10286)"
                ));
            }
        }
    }
    for w in rows.windows(2) {
        if w[0].0 >= w[1].0 {
            out.push(format!(
                "{}: SITE_ROWS is not sorted or holds the file twice (#10286)",
                w[1].0
            ));
        }
    }
    out
}
