// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9414 — ONE lexical classifier of Rust 2024 source for the structural
//! test scanners. Every char of the input is code (identifier, raw
//! identifier, lifetime, punctuation, number, whitespace), a comment (line,
//! nested block, doc) or a literal (string, raw string with any `#` count up
//! to 255, byte / C string and their raw forms, char, byte char). A form it
//! cannot classify is a [`TokenError`] naming the line, never skipped and
//! never read as code (fail closed). One pass, linear in the input: the only
//! look-ahead is the closing delimiter of a raw string, capped at
//! [`RAW_HASH_LIMIT`] chars per quote. Leaf module, `std` only.

/// rustc's limit on the `#` count of a raw string delimiter.
pub const RAW_HASH_LIMIT: usize = 255;
/// Longest char literal body after the opening quote (`\u{10FFFF}'`).
const CHAR_BODY_LIMIT: usize = 11;
/// Punctuation chars of the Rust grammar.
const PUNCT: &str = ";,.(){}[]@#~?:$=!<>-&|+*/^%";

/// What a token is. Only literal and comment kinds are blanked by [`code_mask`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Whitespace,
    Ident,
    RawIdent,
    Lifetime,
    Punct,
    Number,
    LineComment,
    BlockComment,
    Str,
    RawStr,
    ByteStr,
    RawByteStr,
    CStr,
    RawCStr,
    Char,
    Byte,
}

impl Kind {
    /// A string, raw string or char form of any prefix.
    #[must_use]
    pub fn is_literal(self) -> bool {
        matches!(
            self,
            Self::Str
                | Self::RawStr
                | Self::ByteStr
                | Self::RawByteStr
                | Self::CStr
                | Self::RawCStr
                | Self::Char
                | Self::Byte
        )
    }

    /// A line, block or doc comment.
    #[must_use]
    pub fn is_comment(self) -> bool {
        matches!(self, Self::LineComment | Self::BlockComment)
    }
}

/// One token: `kind`, byte range `start..end`, and for a literal the byte
/// range `body` between its delimiters (`start..start` otherwise).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub kind: Kind,
    pub start: usize,
    pub end: usize,
    pub body: (usize, usize),
}

/// A form the tokenizer cannot classify: 1-based `line` and the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenError {
    pub line: usize,
    pub reason: &'static str,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

struct Lexer<'a> {
    src: &'a str,
    pos: usize,
    steps: u64,
}

impl Lexer<'_> {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.src[self.pos..].chars().nth(ahead)
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.pos += c.len_utf8();
        self.steps += 1;
        Some(c)
    }

    fn fail(&self, at: usize, reason: &'static str) -> TokenError {
        // One more segment than newlines before `at`: the 1-based line.
        let line = self.src.as_bytes()[..at].split(|b| *b == b'\n').count();
        TokenError { line, reason }
    }

    fn ident_tail(&mut self) {
        while self.peek(0).is_some_and(is_ident_continue) {
            self.bump();
        }
    }

    /// After the opening `"`: an escaped string; returns the body end.
    fn quoted(&mut self, start: usize) -> Result<usize, TokenError> {
        loop {
            let at = self.pos;
            match self.bump() {
                None => return Err(self.fail(start, "unterminated string literal")),
                Some('\\') => {
                    if self.bump().is_none() {
                        return Err(self.fail(start, "unterminated string literal"));
                    }
                }
                Some('"') => return Ok(at),
                Some(_) => {}
            }
        }
    }

    /// At the first `#` or `"` after a raw prefix; returns the body range.
    fn raw(&mut self, start: usize) -> Result<(usize, usize), TokenError> {
        let mut hashes = 0usize;
        while self.peek(0) == Some('#') {
            self.bump();
            hashes += 1;
        }
        if hashes > RAW_HASH_LIMIT {
            return Err(self.fail(start, "raw string delimiter has more than 255 #"));
        }
        if self.bump() != Some('"') {
            return Err(self.fail(start, "unclassifiable raw prefix"));
        }
        let body = self.pos;
        loop {
            let at = self.pos;
            match self.bump() {
                None => return Err(self.fail(start, "unterminated raw string literal")),
                Some('"') => {
                    let rest = &self.src.as_bytes()[self.pos..];
                    let closes = rest.len() >= hashes && rest[..hashes].iter().all(|b| *b == b'#');
                    self.steps += hashes as u64;
                    if closes {
                        self.pos += hashes;
                        return Ok((body, at));
                    }
                }
                Some(_) => {}
            }
        }
    }

    /// After the opening `'` of a char or byte char; returns the body end.
    fn char_body(&mut self, start: usize) -> Result<usize, TokenError> {
        let body = self.pos;
        if self.peek(0) == Some('\\') {
            for _ in 0..CHAR_BODY_LIMIT {
                let at = self.pos;
                match self.bump() {
                    Some('\'') if at > body + 1 => return Ok(at),
                    None | Some('\n') => break,
                    Some(_) => {}
                }
            }
            return Err(self.fail(start, "unterminated char literal"));
        }
        match (self.peek(0), self.peek(1)) {
            (Some(c), Some('\'')) if c != '\n' && c != '\'' => {
                self.bump();
                let at = self.pos;
                self.bump();
                Ok(at)
            }
            _ => Err(self.fail(start, "unterminated char literal")),
        }
    }

    /// At `'`: a char literal or a lifetime (`'a`, `'static`, `'r#a`).
    fn quote(&mut self, start: usize) -> Result<Token, TokenError> {
        self.bump();
        let (c1, c2) = (self.peek(0), self.peek(1));
        let is_char = c1 == Some('\\') || (c2 == Some('\'') && c1.is_some_and(|c| c != '\n'));
        if is_char {
            let end = self.char_body(start)?;
            return Ok(lit(Kind::Char, start, self.pos, (start + 1, end)));
        }
        match c1 {
            Some('r') if c2 == Some('#') => {
                self.bump();
                self.bump();
                if !self.peek(0).is_some_and(is_ident_start) {
                    return Err(self.fail(start, "unclassifiable quote"));
                }
                self.ident_tail();
            }
            Some(c) if is_ident_start(c) => self.ident_tail(),
            _ => return Err(self.fail(start, "unclassifiable quote")),
        }
        if self.peek(0) == Some('\'') {
            return Err(self.fail(start, "char literal with more than one character"));
        }
        Ok(code(Kind::Lifetime, start, self.pos))
    }

    /// At an identifier start: an identifier, a raw identifier or a
    /// prefixed literal (`b`, `br`, `c`, `cr`, `r`).
    fn word(&mut self, start: usize) -> Result<Token, TokenError> {
        self.ident_tail();
        let word = &self.src[start..self.pos];
        let (kind, raw_kind) = match word {
            "r" => (Kind::Str, Some(Kind::RawStr)),
            "b" => (Kind::ByteStr, None),
            "br" => (Kind::ByteStr, Some(Kind::RawByteStr)),
            "c" => (Kind::CStr, None),
            "cr" => (Kind::CStr, Some(Kind::RawCStr)),
            _ => (Kind::Ident, None),
        };
        match self.peek(0) {
            Some('"') if word == "b" || word == "c" => {
                self.bump();
                let body = self.pos;
                let end = self.quoted(start)?;
                Ok(lit(kind, start, self.pos, (body, end)))
            }
            Some('\'') if word == "b" => {
                self.bump();
                let end = self.char_body(start)?;
                Ok(lit(Kind::Byte, start, self.pos, (start + 2, end)))
            }
            Some('#') if word == "r" && self.peek(1).is_some_and(is_ident_start) => {
                self.bump();
                self.ident_tail();
                Ok(code(Kind::RawIdent, start, self.pos))
            }
            Some('"' | '#') if raw_kind.is_some() => {
                let body = self.raw(start)?;
                Ok(lit(raw_kind.unwrap_or(kind), start, self.pos, body))
            }
            Some('"' | '#' | '\'') => Err(self.fail(start, "reserved literal prefix")),
            _ => Ok(code(Kind::Ident, start, self.pos)),
        }
    }

    fn number(&mut self, start: usize) -> Token {
        let hex = self.src[start..].starts_with("0x") || self.src[start..].starts_with("0X");
        loop {
            match (self.peek(0), self.peek(1)) {
                (Some(c), _) if is_ident_continue(c) => {
                    self.bump();
                }
                (Some('.'), Some(d)) if d.is_ascii_digit() => {
                    self.bump();
                }
                (Some('+' | '-'), _)
                    if !hex
                        && matches!(self.src[..self.pos].chars().next_back(), Some('e' | 'E')) =>
                {
                    self.bump();
                }
                _ => return code(Kind::Number, start, self.pos),
            }
        }
    }

    fn next_token(&mut self, c: char) -> Result<Token, TokenError> {
        let start = self.pos;
        match (c, self.peek(1)) {
            (w, _) if w.is_whitespace() => {
                while self.peek(0).is_some_and(char::is_whitespace) {
                    self.bump();
                }
                Ok(code(Kind::Whitespace, start, self.pos))
            }
            ('/', Some('/')) => {
                while self.peek(0).is_some_and(|ch| ch != '\n') {
                    self.bump();
                }
                Ok(lit(Kind::LineComment, start, self.pos, (start, self.pos)))
            }
            ('/', Some('*')) => {
                let mut depth = 0usize;
                loop {
                    match (self.bump(), self.peek(0)) {
                        (None, _) => return Err(self.fail(start, "unterminated block comment")),
                        (Some('/'), Some('*')) => {
                            self.bump();
                            depth += 1;
                        }
                        (Some('*'), Some('/')) => {
                            self.bump();
                            depth -= 1;
                            if depth == 0 {
                                return Ok(lit(
                                    Kind::BlockComment,
                                    start,
                                    self.pos,
                                    (start, self.pos),
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
            ('"', _) => {
                self.bump();
                let end = self.quoted(start)?;
                Ok(lit(Kind::Str, start, self.pos, (start + 1, end)))
            }
            ('\'', _) => self.quote(start),
            ('#', Some('"' | '#')) => Err(self.fail(start, "reserved guarded string literal")),
            (d, _) if d.is_ascii_digit() => Ok(self.number(start)),
            (w, _) if is_ident_start(w) => self.word(start),
            (p, _) if PUNCT.contains(p) => {
                self.bump();
                Ok(code(Kind::Punct, start, self.pos))
            }
            _ => Err(self.fail(start, "unclassifiable character")),
        }
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_ident_continue(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn code(kind: Kind, start: usize, end: usize) -> Token {
    Token {
        kind,
        start,
        end,
        body: (start, start),
    }
}

fn lit(kind: Kind, start: usize, end: usize, body: (usize, usize)) -> Token {
    Token {
        kind,
        start,
        end,
        body,
    }
}

/// Tokenize `src`, also returning the number of chars stepped (the linear
/// bound's op count: at most `chars + RAW_HASH_LIMIT * quotes`).
pub fn tokenize_steps(src: &str) -> (Result<Vec<Token>, TokenError>, u64) {
    let mut lx = Lexer {
        src,
        pos: 0,
        steps: 0,
    };
    let mut out = Vec::new();
    while let Some(c) = lx.peek(0) {
        match lx.next_token(c) {
            Ok(t) => out.push(t),
            Err(e) => return (Err(e), lx.steps),
        }
    }
    (Ok(out), lx.steps)
}

/// Tokenize `src`; the first unclassifiable form is the error.
#[allow(dead_code, reason = "#9414: a scanner binary may use only code_mask")]
pub fn tokenize(src: &str) -> Result<Vec<Token>, TokenError> {
    tokenize_steps(src).0
}

/// `src` with every comment blanked and every literal BODY blanked (its
/// prefix and delimiters kept, so `extern "C"` still reads as a string).
/// One space per blanked char, newlines kept, so line numbers are stable.
pub fn code_mask(src: &str) -> Result<String, TokenError> {
    let tokens = tokenize_steps(src).0?;
    let mut out = String::with_capacity(src.len());
    for t in tokens {
        if t.kind.is_comment() || t.kind.is_literal() {
            let (b0, b1) = if t.kind.is_comment() {
                (t.start, t.end)
            } else {
                t.body
            };
            out.push_str(&src[t.start..b0]);
            out.extend(
                src[b0..b1]
                    .chars()
                    .map(|c| if c == '\n' { '\n' } else { ' ' }),
            );
            out.push_str(&src[b1..t.end]);
        } else {
            out.push_str(&src[t.start..t.end]);
        }
    }
    Ok(out)
}
