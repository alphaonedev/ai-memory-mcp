//! #9730 - deny-by-default census of the key-dir tokens over the tracked tree.
//!
//! What it checks. For each tracked `.rs` file (`git ls-files -z` at the crate
//! root, which is the repository root, so every crate and directory; not a walk
//! of one path) [`lex`] counts nine tokens, each as a whole word: the variable
//! name `AI_MEMORY_KEY_DIR`, the constant `KEY_DIR_ENV`, the module name
//! `test_key_dir`, the setter routes of `src/identity/test_key_dir.rs`
//! (`set_env`, `unset_env`, `set_key_dir_env`, `bind_key_dir_env`,
//! `KeyDirEnvBind`) and the one test route of `src/cli/store.rs` that binds the
//! key dir (`bind_key_dir`). Words are counted in code identifiers (`r#name`
//! too), in line comments, in nested block comments, in raw string bodies, and
//! in string, byte string and C string literals after their escapes are decoded
//! (so `\x5f` and `\u{5f}` spell `_`). The count per (file, token) must EQUAL
//! the count of [`ALLOW`], a table written by hand with a reason per row. More,
//! fewer, a file with a token and no row, a row whose file is not tracked, two
//! rows for one (file, token) and a row that allows 0 are each a violation with
//! its own message ([`census`]).
//!
//! The census does not look at how a token is used, so a turbofish call,
//! `<T>::set`, a function pointer, a `macro_rules!` body, a helper with its own
//! parameter name, a `let` binding and a comment that names the allowed route
//! all change a count ([`PROBES`], S01 to S15).
//!
//! What it does not see. A name that is built at compile or run time
//! (`concat!`, `format!`, bytes joined) has no token in the text. Probe S16
//! pins that this form stays green; the gap is recorded as a decision for the
//! conductor of #9730, not claimed as covered.
//!
//! Degenerate input refuses with a pinned message ([`degenerate_inputs_refuse_9730`]):
//! zero tracked files, an unreadable, empty or non-UTF-8 file, a lexer error
//! (unterminated comment, string, raw string or char literal, an invalid
//! escape, a malformed raw string), a row whose file is gone, and a git
//! failure.
//!
//! Cost. [`lex`] is one forward pass: the scanner consumes each byte once (a
//! char literal looks ahead at most 3 bytes, which are then consumed), and the
//! word counter reads each comment, raw body and decoded literal byte once more,
//! so the step count is at most `2 * len + 16` for every input, balanced or
//! not ([`lexer_is_linear_9730`]).
//!
//! This is its own test binary (own process) on purpose:
//! `scripts/check-test-env-lock.sh` arm (d) counts env-mutation text per file in
//! the lib test binary (#3475). Nothing here mutates the process environment.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

/// Prefix of every violation message.
const PREFIX: &str = "#9730 census: ";

/// The counted tokens. The derived order is the order of the messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Token {
    VarName,
    ConstName,
    SandboxModule,
    SetEnv,
    UnsetEnv,
    SetKeyDirEnv,
    BindKeyDirEnv,
    BindKeyDir,
    BindStruct,
}

/// Every token the lexer counts.
const ALL: [Token; 9] = [
    Token::VarName,
    Token::ConstName,
    Token::SandboxModule,
    Token::SetEnv,
    Token::UnsetEnv,
    Token::SetKeyDirEnv,
    Token::BindKeyDirEnv,
    Token::BindKeyDir,
    Token::BindStruct,
];

impl Token {
    const fn spelling(self) -> &'static str {
        match self {
            Token::VarName => "AI_MEMORY_KEY_DIR",
            Token::ConstName => "KEY_DIR_ENV",
            Token::SandboxModule => "test_key_dir",
            Token::SetEnv => "set_env",
            Token::UnsetEnv => "unset_env",
            Token::SetKeyDirEnv => "set_key_dir_env",
            Token::BindKeyDirEnv => "bind_key_dir_env",
            Token::BindKeyDir => "bind_key_dir",
            Token::BindStruct => "KeyDirEnvBind",
        }
    }
}

/// Input the lexer cannot classify; each is a violation, never skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LexError {
    BlockComment(usize),
    Str(usize),
    RawStr(usize),
    Char(usize),
    Escape(usize),
    RawMalformed(usize),
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::BlockComment(at) => write!(f, "unterminated block comment at byte {at}"),
            Self::Str(at) => write!(f, "unterminated string literal at byte {at}"),
            Self::RawStr(at) => write!(f, "unterminated raw string literal at byte {at}"),
            Self::Char(at) => write!(f, "unterminated char literal at byte {at}"),
            Self::Escape(at) => write!(f, "invalid escape at byte {at}"),
            Self::RawMalformed(at) => write!(f, "malformed raw string at byte {at}"),
        }
    }
}

const fn is_word(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric() || b >= 0x80
}

const fn is_word_start(b: u8) -> bool {
    is_word(b) && !b.is_ascii_digit()
}

fn token_of(word: &[u8]) -> Option<Token> {
    ALL.into_iter().find(|t| t.spelling().as_bytes() == word)
}

fn bump(counts: &mut BTreeMap<Token, usize>, word: &[u8]) {
    if let Some(t) = token_of(word) {
        *counts.entry(t).or_insert(0) += 1;
    }
}

/// Count the token words of `text` (a comment, a raw body or a decoded
/// literal); one step per byte.
fn count_words(text: &[u8], counts: &mut BTreeMap<Token, usize>, steps: &mut usize) {
    let mut i = 0;
    while i < text.len() {
        if is_word(text[i]) {
            let start = i;
            while i < text.len() && is_word(text[i]) {
                i += 1;
                *steps += 1;
            }
            bump(counts, &text[start..i]);
        } else {
            i += 1;
            *steps += 1;
        }
    }
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    steps: usize,
    counts: BTreeMap<Token, usize>,
}

impl Lexer<'_> {
    fn peek(&self, k: usize) -> Option<u8> {
        self.src.get(self.pos + k).copied()
    }

    fn step(&mut self) {
        self.pos += 1;
        self.steps += 1;
    }

    fn count(&mut self, from: usize, to: usize) {
        let src = self.src;
        count_words(&src[from..to], &mut self.counts, &mut self.steps);
    }

    fn run(&mut self) -> Result<(), LexError> {
        while let Some(c) = self.peek(0) {
            match c {
                b'/' if self.peek(1) == Some(b'/') => self.line_comment(),
                b'/' if self.peek(1) == Some(b'*') => self.block_comment()?,
                b'"' => {
                    let start = self.pos;
                    self.step();
                    self.cooked(start, b'"')?;
                }
                b'\'' => self.quote()?,
                _ if is_word_start(c) => self.word()?,
                _ if c.is_ascii_digit() => {
                    while self.peek(0).is_some_and(is_word) {
                        self.step();
                    }
                }
                _ => self.step(),
            }
        }
        Ok(())
    }

    fn line_comment(&mut self) {
        let start = self.pos;
        while self.peek(0).is_some_and(|b| b != b'\n') {
            self.step();
        }
        self.count(start, self.pos);
    }

    fn block_comment(&mut self) -> Result<(), LexError> {
        let start = self.pos;
        self.step();
        self.step();
        let mut depth = 1_usize;
        while depth > 0 {
            match (self.peek(0), self.peek(1)) {
                (None, _) => return Err(LexError::BlockComment(start)),
                (Some(b'/'), Some(b'*')) => {
                    depth += 1;
                    self.step();
                    self.step();
                }
                (Some(b'*'), Some(b'/')) => {
                    depth -= 1;
                    self.step();
                    self.step();
                }
                _ => self.step(),
            }
        }
        self.count(start, self.pos);
        Ok(())
    }

    /// A string, byte string, C string, char or byte char body; `pos` is just
    /// after the opening quote. The decoded bytes are counted as words.
    fn cooked(&mut self, start: usize, quote: u8) -> Result<(), LexError> {
        let unterminated = if quote == b'"' {
            LexError::Str(start)
        } else {
            LexError::Char(start)
        };
        let mut out = Vec::new();
        loop {
            let Some(c) = self.peek(0) else {
                return Err(unterminated);
            };
            if c == quote {
                self.step();
                break;
            }
            if c != b'\\' {
                out.push(c);
                self.step();
                continue;
            }
            let at = self.pos;
            let Some(e) = self.peek(1) else {
                return Err(unterminated);
            };
            self.step();
            self.step();
            match e {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'0' => out.push(0),
                b'\\' | b'\'' | b'"' => out.push(e),
                b'x' => {
                    let hi = self.hex_digit(at)?;
                    let lo = self.hex_digit(at)?;
                    out.push(hi * 16 + lo);
                }
                b'u' => self.unicode(at, &mut out)?,
                b'\n' | b'\r' => {
                    while self
                        .peek(0)
                        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
                    {
                        self.step();
                    }
                }
                _ => return Err(LexError::Escape(at)),
            }
        }
        count_words(&out, &mut self.counts, &mut self.steps);
        Ok(())
    }

    fn hex_digit(&mut self, at: usize) -> Result<u8, LexError> {
        let digit = self
            .peek(0)
            .and_then(|b| char::from(b).to_digit(16))
            .and_then(|d| u8::try_from(d).ok())
            .ok_or(LexError::Escape(at))?;
        self.step();
        Ok(digit)
    }

    /// `\u{...}`: `pos` is just after the `u`; 1 to 6 hex digits, `_` allowed.
    fn unicode(&mut self, at: usize, out: &mut Vec<u8>) -> Result<(), LexError> {
        if self.peek(0) != Some(b'{') {
            return Err(LexError::Escape(at));
        }
        self.step();
        let mut value: u32 = 0;
        let mut digits = 0_usize;
        loop {
            match self.peek(0) {
                Some(b'}') => {
                    self.step();
                    break;
                }
                Some(b'_') => self.step(),
                Some(b) if digits < 6 => {
                    let d = char::from(b).to_digit(16).ok_or(LexError::Escape(at))?;
                    value = value * 16 + d;
                    digits += 1;
                    self.step();
                }
                _ => return Err(LexError::Escape(at)),
            }
        }
        let ch = char::from_u32(value)
            .filter(|_| digits > 0)
            .ok_or(LexError::Escape(at))?;
        let mut tmp = [0_u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
        Ok(())
    }

    /// At `'`: an escape, one UTF-8 char and a quote (a char literal), a
    /// lifetime or label (its name is lexed next as a word), or a violation.
    fn quote(&mut self) -> Result<(), LexError> {
        let start = self.pos;
        match self.peek(1) {
            None => Err(LexError::Char(start)),
            Some(b'\\') => {
                self.step();
                self.cooked(start, b'\'')
            }
            Some(first) => {
                let mut j = 2;
                while j < 5 && self.peek(j).is_some_and(|b| (0x80..0xC0).contains(&b)) {
                    j += 1;
                    self.steps += 1;
                }
                if self.peek(j) == Some(b'\'') {
                    for _ in 0..=j {
                        self.step();
                    }
                    Ok(())
                } else if is_word_start(first) {
                    self.step();
                    Ok(())
                } else {
                    Err(LexError::Char(start))
                }
            }
        }
    }

    fn word(&mut self) -> Result<(), LexError> {
        let src = self.src;
        let start = self.pos;
        while self.peek(0).is_some_and(is_word) {
            self.step();
        }
        let word = &src[start..self.pos];
        match (word, self.peek(0)) {
            (b"r" | b"br" | b"cr", Some(b'"' | b'#')) => self.raw(start, word == b"r"),
            (b"b" | b"c", Some(b'"')) => {
                self.step();
                self.cooked(start, b'"')
            }
            (b"b", Some(b'\'')) => {
                self.step();
                self.cooked(start, b'\'')
            }
            _ => {
                bump(&mut self.counts, word);
                Ok(())
            }
        }
    }

    /// After `r`, `br` or `cr`: a raw string, or (`r#` and a word) a raw
    /// identifier. The close scan never re-reads a byte.
    fn raw(&mut self, start: usize, may_be_ident: bool) -> Result<(), LexError> {
        let src = self.src;
        let mut hashes = 0_usize;
        while self.peek(0) == Some(b'#') {
            hashes += 1;
            self.step();
        }
        match self.peek(0) {
            Some(b'"') => {}
            Some(b) if may_be_ident && hashes > 0 && is_word_start(b) => {
                let from = self.pos;
                while self.peek(0).is_some_and(is_word) {
                    self.step();
                }
                bump(&mut self.counts, &src[from..self.pos]);
                return Ok(());
            }
            _ => return Err(LexError::RawMalformed(start)),
        }
        self.step();
        let body = self.pos;
        loop {
            match self.peek(0) {
                None => return Err(LexError::RawStr(start)),
                Some(b'"') => {
                    let end = self.pos;
                    self.step();
                    let mut seen = 0_usize;
                    while seen < hashes && self.peek(0) == Some(b'#') {
                        seen += 1;
                        self.step();
                    }
                    if seen == hashes {
                        self.count(body, end);
                        return Ok(());
                    }
                }
                Some(_) => self.step(),
            }
        }
    }
}

/// The token counts of one file, or the first input the lexer cannot
/// classify, and the steps taken either way.
struct Lexed {
    result: Result<BTreeMap<Token, usize>, LexError>,
    steps: usize,
}

fn lex(src: &[u8]) -> Lexed {
    let mut lx = Lexer {
        src,
        pos: 0,
        steps: 0,
        counts: BTreeMap::new(),
    };
    let outcome = lx.run();
    Lexed {
        result: outcome.map(|()| std::mem::take(&mut lx.counts)),
        steps: lx.steps,
    }
}

/// One allowed (file, token) count and why it is allowed.
#[derive(Clone, Copy, Debug)]
struct Row {
    file: &'static str,
    token: Token,
    count: usize,
    reason: &'static str,
}

const fn row(file: &'static str, token: Token, count: usize, reason: &'static str) -> Row {
    Row {
        file,
        token,
        count,
        reason,
    }
}

/// A tracked file name and its bytes, or why it could not be read.
type Source = (String, Result<Vec<u8>, String>);

/// The census of a file list before it is judged against a table.
struct Tally {
    names: BTreeSet<String>,
    violations: Vec<String>,
    counts: BTreeMap<String, BTreeMap<Token, usize>>,
}

fn tally(files: &[Source]) -> Tally {
    let mut out = Tally {
        names: BTreeSet::new(),
        violations: Vec::new(),
        counts: BTreeMap::new(),
    };
    for (name, bytes) in files {
        out.names.insert(name.clone());
        let found = match bytes {
            Err(why) => Err(format!("unreadable: {why}")),
            Ok(b) if b.is_empty() => Err("empty file".to_owned()),
            Ok(b) if std::str::from_utf8(b).is_err() => Err("not UTF-8".to_owned()),
            Ok(b) => lex(b).result.map_err(|e| e.to_string()),
        };
        match found {
            Ok(counts) => {
                out.counts.insert(name.clone(), counts);
            }
            Err(why) => out.violations.push(format!("{PREFIX}{name}: {why}")),
        }
    }
    out
}

fn judge(tally: &Tally, table: &[Row]) -> Vec<String> {
    if tally.names.is_empty() {
        return vec![format!("{PREFIX}zero tracked .rs files")];
    }
    let mut out = Vec::new();
    let mut allowed: BTreeMap<(&str, Token), usize> = BTreeMap::new();
    for r in table {
        let name = r.token.spelling();
        if allowed.insert((r.file, r.token), r.count).is_some() {
            out.push(format!(
                "{PREFIX}allow table has two rows for {} {name}",
                r.file
            ));
        }
        if r.count == 0 {
            out.push(format!(
                "{PREFIX}allow table row {} {name} allows 0",
                r.file
            ));
        }
        if !tally.names.contains(r.file) {
            out.push(format!(
                "{PREFIX}allow table names {}, which is not a tracked .rs file",
                r.file
            ));
        }
    }
    out.extend(tally.violations.iter().cloned());
    let mut row_tokens: BTreeMap<&str, BTreeSet<Token>> = BTreeMap::new();
    for r in table {
        row_tokens.entry(r.file).or_default().insert(r.token);
    }
    for (file, counts) in &tally.counts {
        let mut tokens: BTreeSet<Token> = ALL.into_iter().collect();
        if let Some(extra) = row_tokens.get(file.as_str()) {
            tokens.extend(extra.iter().copied());
        }
        for t in tokens {
            let found = counts.get(&t).copied().unwrap_or(0);
            let want = allowed.get(&(file.as_str(), t)).copied().unwrap_or(0);
            if found != want {
                out.push(format!(
                    "{PREFIX}{file}: {} found {found}, allowed {want}",
                    t.spelling()
                ));
            }
        }
    }
    out
}

/// Every violation of `files` against `table`; empty means the tree matches.
fn census(files: &[Source], table: &[Row]) -> Vec<String> {
    judge(&tally(files), table)
}

/// The tracked `.rs` names under `root`, from git (never a directory walk).
fn tracked_rs(root: &Path) -> Result<Vec<String>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .map_err(|e| format!("{PREFIX}git ls-files -z did not run: {:?}", e.kind()))?;
    if !out.status.success() {
        return Err(format!("{PREFIX}git ls-files -z failed: {}", out.status));
    }
    let text = String::from_utf8(out.stdout)
        .map_err(|_| format!("{PREFIX}git ls-files -z printed a name that is not UTF-8"))?;
    Ok(text
        .split('\0')
        .filter(|n| Path::new(n).extension().is_some_and(|e| e == "rs"))
        .map(str::to_owned)
        .collect())
}

fn read_tracked(root: &Path, name: &str) -> Result<Vec<u8>, String> {
    std::fs::read(root.join(name)).map_err(|e| format!("{:?}", e.kind()))
}

fn tree_sources() -> Vec<Source> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let names = tracked_rs(root).unwrap_or_else(|e| panic!("{e}"));
    names
        .into_iter()
        .map(|n| {
            let bytes = read_tracked(root, &n);
            (n, bytes)
        })
        .collect()
}

/// Reasons, written once each.
const DOC: &str = "named in doc comments only";
const CHILD: &str = "pinned on a spawned child process";
const CHILD_DOC: &str = "pinned on a spawned child process; named in doc comments";
const OWN_SET: &str = "own test binary sets the variable in process";
const OWN_SET_DOC: &str = "own test binary sets the variable in process; named in doc comments";
const OWN_CONST: &str = "own test binary sets the variable through the keypair constant";
const UNIT: &str = "unit tests of this file set and read the variable under the env lock";
const INSTALL: &str = "calls the sandbox install or temp-dir helpers by module path";
const PAIRS: &str = "env-name list or sandbox install pair";
const DEFINES: &str = "defines the constant and its docs";
const DECLARES: &str = "declares the sandbox module under its test-support cfg";
const SANDBOX: &str = "the sandbox module itself: its routes, their docs and tests";
const ROUTE: &str = "the one test helper that binds the key dir, its callers and its env test";
const SELF_ROWS: &str = "this guard: spelling table, allow rows, probes and messages";

/// The allow table: every (file, token) count of the tracked tree, by hand.
/// One row per line (rustfmt skip), so a diff of the table is one line per row.
#[rustfmt::skip]
const ALLOW: &[Row] = &[
    // allow-rows:start
    // allow-rows:end
];

/// The store file the probes are inserted into.
const STORE: &str = "src/cli/store.rs";
const STORE_RS: &str = include_str!("../src/cli/store.rs");
/// Probes go in front of this test, inside the test module of the store file.
const ANCHOR: &str = "    #[test]\n    fn test_store_sign_with_bound_key_stamps_agent_attested() {";

const VAR_13: &str = "#9730 census: src/cli/store.rs: AI_MEMORY_KEY_DIR found 13, allowed 12";
const CONST_1: &str = "#9730 census: src/cli/store.rs: KEY_DIR_ENV found 1, allowed 0";
const MODULE_2: &str = "#9730 census: src/cli/store.rs: test_key_dir found 2, allowed 1";
const ROUTE_7: &str = "#9730 census: src/cli/store.rs: bind_key_dir found 7, allowed 6";

const S01: &str = r#"        let key = "AI_MEMORY_KEY_DIR";
        let _g = EnvVarGuard::set(key, p.as_os_str());"#;
const S02: &str =
    r#"        unsafe { std::env::set_var::<&str, &std::path::Path>("AI_MEMORY_KEY_DIR", p) };"#;
const S03: &str = r#"        let setter = EnvVarGuard::set;
        let _g = setter("AI_MEMORY_KEY_DIR", p.as_os_str());"#;
const S04: &str = r#"        let _g = EnvVarGuard::set("AI_MEMORY_KEY\x5fDIR", p.as_os_str());"#;
const S05: &str = r#"        let _g = <EnvVarGuard>::set("AI_MEMORY_KEY_DIR", p.as_os_str());"#;
const S06: &str = r#"        macro_rules! bind_raw {
            ($d:expr) => {
                EnvVarGuard::set("AI_MEMORY_KEY_DIR", $d.as_os_str())
            };
        }
        let _g = bind_raw!(p);"#;
const S07: &str = r#"        // inline copy of fn bind_key_dir
        let _g = EnvVarGuard::set("AI_MEMORY_KEY_DIR", p.as_os_str());"#;
const S08: &str = r"        use crate::identity::keypair::KEY_DIR_ENV as KD;
        let _g = EnvVarGuard::set(KD, p.as_os_str());";
const S09: &str =
    r"        unsafe { ::std::env::set_var(crate::identity::keypair::KEY_DIR_ENV, p) };";
const S10: &str = r#"        fn put_k(k: &str, v: &std::path::Path) -> EnvVarGuard {
            EnvVarGuard::set(k, v.as_os_str())
        }
        let _g = put_k("AI_MEMORY_KEY_DIR", p);"#;
const S11: &str = r#"        fn put_key(key: &str, v: &std::path::Path) -> EnvVarGuard {
            EnvVarGuard::set(key, v.as_os_str())
        }
        let _g = put_key("AI_MEMORY_KEY_DIR", p);"#;
const S12: &str = r#"        let _g = EnvVarGuard::set(
            // the key dir
            "AI_MEMORY_KEY_DIR",
            p.as_os_str(),
        );"#;
const S13: &str = r#"        // never write EnvVarGuard::set("AI_MEMORY_KEY_DIR", p) here
        let _ = p;"#;
const S14: &str = r#"        let _doc = "std::env::set_var(KEY_DIR_ENV, p)";
        let _ = p;"#;
const S15: &str = r"        crate::identity::test_key_dir::bind_override(p);";
const S16: &str =
    r#"        let _g = EnvVarGuard::set(concat!("AI_MEMORY_", "KEY_DIR"), p.as_os_str());"#;

/// One probe of the round-2 verdict and the exact census it must give.
struct Probe {
    name: &'static str,
    body: &'static str,
    expect: &'static [&'static str],
}

/// The deny table: the 16 probes of REVIEW-9763-combined-r2. S16 is the one
/// form a text census cannot see; it stays green and is pinned as the gap.
const PROBES: [Probe; 16] = [
    Probe {
        name: "probe_s01",
        body: S01,
        expect: &[VAR_13],
    },
    Probe {
        name: "probe_s02",
        body: S02,
        expect: &[VAR_13],
    },
    Probe {
        name: "probe_s03",
        body: S03,
        expect: &[VAR_13],
    },
    Probe {
        name: "probe_s04",
        body: S04,
        expect: &[VAR_13],
    },
    Probe {
        name: "probe_s05",
        body: S05,
        expect: &[VAR_13],
    },
    Probe {
        name: "probe_s06",
        body: S06,
        expect: &[VAR_13],
    },
    Probe {
        name: "probe_s07",
        body: S07,
        expect: &[VAR_13, ROUTE_7],
    },
    Probe {
        name: "probe_s08",
        body: S08,
        expect: &[CONST_1],
    },
    Probe {
        name: "probe_s09",
        body: S09,
        expect: &[CONST_1],
    },
    Probe {
        name: "probe_s10",
        body: S10,
        expect: &[VAR_13],
    },
    Probe {
        name: "probe_s11",
        body: S11,
        expect: &[VAR_13],
    },
    Probe {
        name: "probe_s12",
        body: S12,
        expect: &[VAR_13],
    },
    Probe {
        name: "probe_s13",
        body: S13,
        expect: &[VAR_13],
    },
    Probe {
        name: "probe_s14",
        body: S14,
        expect: &[CONST_1],
    },
    Probe {
        name: "probe_s15",
        body: S15,
        expect: &[MODULE_2],
    },
    Probe {
        name: "probe_s16",
        body: S16,
        expect: &[],
    },
];

fn store_rows() -> Vec<Row> {
    ALLOW.iter().copied().filter(|r| r.file == STORE).collect()
}

/// The census of one store-file text against the store rows only.
fn store_census(text: &str) -> Vec<String> {
    census(
        &[(STORE.to_owned(), Ok(text.as_bytes().to_vec()))],
        &store_rows(),
    )
}

/// `text` with the one occurrence of `from` replaced by `to`.
fn replace_once(text: &str, from: &str, to: &str) -> String {
    assert!(
        text.contains(from) && text.matches(from).nth(1).is_none(),
        "expected exactly one {from:?} in the store file"
    );
    text.replacen(from, to, 1)
}

fn source(name: &str, text: &[u8]) -> Source {
    (name.to_owned(), Ok(text.to_vec()))
}

/// #9730: the whole tracked tree matches the allow table, count for count.
#[test]
fn key_dir_override_goes_through_bind_key_dir_9730() {
    let got = census(&tree_sources(), ALLOW);
    assert!(got.is_empty(), "{}", got.join("\n"));
}

/// Each allow row is load-bearing: one more, or the row gone, is red with the
/// exact message (a mutant per row, computed on one tally of the tree).
#[test]
fn allow_table_every_row_is_load_bearing_9730() {
    let t = tally(&tree_sources());
    assert!(judge(&t, ALLOW).is_empty(), "tree does not match the table");
    for (i, r) in ALLOW.iter().enumerate() {
        let name = r.token.spelling();
        let mut wider = ALLOW.to_vec();
        wider[i].count = r.count + 1;
        assert_eq!(
            judge(&t, &wider),
            vec![format!(
                "{PREFIX}{}: {name} found {}, allowed {}",
                r.file,
                r.count,
                r.count + 1
            )],
            "row {i} widened ({})",
            r.reason
        );
        let mut without = ALLOW.to_vec();
        without.remove(i);
        assert_eq!(
            judge(&t, &without),
            vec![format!(
                "{PREFIX}{}: {name} found {}, allowed 0",
                r.file, r.count
            )],
            "row {i} removed"
        );
    }
}

/// The deny table: each probe inserted into the store tests gives its exact
/// census. The unmodified store file is green.
#[test]
fn probes_are_each_red_with_the_exact_message_9730() {
    assert_eq!(store_census(STORE_RS), Vec::<String>::new());
    for p in &PROBES {
        let wrapped = format!(
            "    #[test]\n    fn {}() {{\n        let p = std::path::Path::new(\"/x\");\n{}\n    }}\n\n{ANCHOR}",
            p.name, p.body
        );
        let text = replace_once(STORE_RS, ANCHOR, &wrapped);
        assert_eq!(store_census(&text), p.expect, "{}", p.name);
    }
}

/// Check 4 of the round-2 verdict: the rows that used to fail open, each with
/// the whole text.
#[test]
fn check_4_rows_refuse_with_the_whole_text_9730() {
    assert_eq!(
        store_census(""),
        vec!["#9730 census: src/cli/store.rs: empty file".to_owned()]
    );
    assert_eq!(
        store_census(&replace_once(STORE_RS, "mod tests {", "mod tests{")),
        Vec::<String>::new()
    );
    let mut cut = replace_once(
        STORE_RS,
        "        EnvVarGuard::set(\"AI_MEMORY_KEY_DIR\", dir.as_os_str())",
        "        todo!()",
    );
    cut = replace_once(
        &cut,
        "unsafe { std::env::set_var(\"AI_MEMORY_KEY_DIR\", prior.path().as_os_str()) };",
        "",
    );
    cut = replace_once(
        &cut,
        "let _g = EnvVarGuard::set(\"AI_MEMORY_KEY_DIR\", other.path().as_os_str());",
        "",
    );
    assert_eq!(
        store_census(&cut),
        vec!["#9730 census: src/cli/store.rs: AI_MEMORY_KEY_DIR found 9, allowed 12".to_owned()]
    );
    assert_eq!(
        store_census("mod tests {\n}\n"),
        vec![
            "#9730 census: src/cli/store.rs: AI_MEMORY_KEY_DIR found 0, allowed 12".to_owned(),
            "#9730 census: src/cli/store.rs: test_key_dir found 0, allowed 1".to_owned(),
            "#9730 census: src/cli/store.rs: bind_key_dir found 0, allowed 6".to_owned(),
        ]
    );
    assert_eq!(
        census(&[(STORE.to_owned(), Err("gone".to_owned()))], &store_rows()),
        vec!["#9730 census: src/cli/store.rs: unreadable: gone".to_owned()]
    );
}

/// Unset and degenerate inputs refuse, each with its exact text.
#[test]
fn degenerate_inputs_refuse_9730() {
    let one = [row("src/a.rs", Token::VarName, 1, "probe row")];
    let a_var = source("src/a.rs", b"\"AI_MEMORY_KEY_DIR\"");
    assert_eq!(
        census(std::slice::from_ref(&a_var), &one),
        Vec::<String>::new()
    );
    assert_eq!(
        census(&[], &one),
        vec!["#9730 census: zero tracked .rs files".to_owned()]
    );
    assert_eq!(
        census(&[source("src/b.rs", b"fn b() {}")], &one),
        vec![
            "#9730 census: allow table names src/a.rs, which is not a tracked .rs file".to_owned()
        ]
    );
    assert_eq!(
        census(std::slice::from_ref(&a_var), &[one[0], one[0]]),
        vec!["#9730 census: allow table has two rows for src/a.rs AI_MEMORY_KEY_DIR".to_owned()]
    );
    assert_eq!(
        census(
            std::slice::from_ref(&a_var),
            &[one[0], row("src/a.rs", Token::ConstName, 0, "probe row")]
        ),
        vec!["#9730 census: allow table row src/a.rs KEY_DIR_ENV allows 0".to_owned()]
    );
    assert_eq!(
        census(&[source("src/a.rs", b"fn a() {}")], &one),
        vec!["#9730 census: src/a.rs: AI_MEMORY_KEY_DIR found 0, allowed 1".to_owned()]
    );
    assert_eq!(
        census(
            &[a_var.clone(), source("src/new.rs", b"// KEY_DIR_ENV")],
            &one
        ),
        vec!["#9730 census: src/new.rs: KEY_DIR_ENV found 1, allowed 0".to_owned()]
    );
    assert_eq!(
        census(&[source("src/a.rs", b"")], &one),
        vec!["#9730 census: src/a.rs: empty file".to_owned()]
    );
    assert_eq!(
        census(&[source("src/a.rs", &[0x22, 0xff, 0x22])], &one),
        vec!["#9730 census: src/a.rs: not UTF-8".to_owned()]
    );
    assert_eq!(
        census(&[("src/a.rs".to_owned(), Err("gone".to_owned()))], &one),
        vec!["#9730 census: src/a.rs: unreadable: gone".to_owned()]
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(
        read_tracked(root, "src/no_such_file_9730.rs"),
        Err("NotFound".to_owned())
    );
    assert_eq!(
        tracked_rs(&root.join("no_such_dir_9730")),
        Err("#9730 census: git ls-files -z failed: exit status: 128".to_owned())
    );
    let lex_rows: [(&[u8], &str); 9] = [
        (b"/* x /* y */", "unterminated block comment at byte 0"),
        (b"let s = \"abc", "unterminated string literal at byte 8"),
        (b"x r#\"abc\"", "unterminated raw string literal at byte 2"),
        (b"br##x", "malformed raw string at byte 0"),
        (b"'", "unterminated char literal at byte 0"),
        (b"a '+b", "unterminated char literal at byte 2"),
        (b"\"\\q\"", "invalid escape at byte 1"),
        (b"\"\\x4\"", "invalid escape at byte 1"),
        (b"\"\\u{110000}\"", "invalid escape at byte 1"),
    ];
    for (input, why) in lex_rows {
        assert_eq!(
            census(&[source("src/a.rs", input)], &one),
            vec![format!("#9730 census: src/a.rs: {why}")],
            "{}",
            String::from_utf8_lossy(input)
        );
    }
}

/// The lexer table: every spelling form counts, and near misses do not.
#[test]
fn lexer_counts_every_spelling_form_9730() {
    use Token::{
        BindKeyDir, BindKeyDirEnv, BindStruct, ConstName, SandboxModule, SetEnv, SetKeyDirEnv,
        UnsetEnv, VarName,
    };
    let rows: [(&str, &[(Token, usize)]); 22] = [
        (r#""AI_MEMORY_KEY\x5fDIR""#, &[(VarName, 1)]),
        (r#""\u{41}I_MEMORY_KEY_DIR""#, &[(VarName, 1)]),
        (r#""AI_MEMORY_\u{4_b}EY_DIR""#, &[(VarName, 1)]),
        (r#""KEY_DIR_\x45NV""#, &[(ConstName, 1)]),
        (r#"b"KEY_DIR_ENV" c"KEY_DIR_ENV""#, &[(ConstName, 2)]),
        (
            r###"br"KEY_DIR_ENV" r##"a "# KEY_DIR_ENV"##"###,
            &[(ConstName, 2)],
        ),
        ("r#KEY_DIR_ENV", &[(ConstName, 1)]),
        (
            "/* /* test_key_dir */ set_env */ x",
            &[(SandboxModule, 1), (SetEnv, 1)],
        ),
        ("// unset_env\nfn f() {}", &[(UnsetEnv, 1)]),
        ("\"line \\\n    set_key_dir_env\"", &[(SetKeyDirEnv, 1)]),
        ("bind_key_dir_env", &[(BindKeyDirEnv, 1)]),
        ("bind_key_dir(p)", &[(BindKeyDir, 1)]),
        ("struct KeyDirEnvBind;", &[(BindStruct, 1)]),
        ("fn f<'a>(x: &'a str) { set_env(x) }", &[(SetEnv, 1)]),
        (
            "let c = 'x'; let q = '\\''; let b = b'\\''; set_env",
            &[(SetEnv, 1)],
        ),
        ("let e = 'é'; unset_env", &[(UnsetEnv, 1)]),
        ("AI_MEMORY_KEY_DIRS xKEY_DIR_ENV test_key_dir2", &[]),
        ("1set_env 0x_unset_env", &[]),
        ("\"AI_MEMORY_KEY_DI\" \"R\"", &[]),
        ("'label: loop { break 'label; }", &[]),
        ("r\"set_env\" cr\"set_env\"", &[(SetEnv, 2)]),
        ("\"\\\\\" set_env \"\\\"\"", &[(SetEnv, 1)]),
    ];
    for (input, want) in rows {
        let want: BTreeMap<Token, usize> = want.iter().copied().collect();
        assert_eq!(lex(input.as_bytes()).result, Ok(want), "{input}");
    }
}

/// Q1 of the round-2 verdict and the unbalanced inputs, each 200K+ bytes, stay
/// under a step ceiling of `2 * len + 16` and give their exact outcome.
#[test]
fn lexer_is_linear_9730() {
    type Want = Result<BTreeMap<Token, usize>, LexError>;
    let q1 = "set_var(".repeat(25_000);
    let q1_quoted = "\"set_var(\"".repeat(25_000);
    let block = format!("/*{}", "a".repeat(200_000));
    let nested = "/*".repeat(100_001);
    let string = format!("\"{}", "a".repeat(200_000));
    let raw = format!("r##\"{}", "\"#".repeat(100_000));
    let quotes = "'a".repeat(100_000);
    let rows: [(&str, Want); 7] = [
        (&q1, Ok(BTreeMap::new())),
        (&q1_quoted, Ok(BTreeMap::new())),
        (&block, Err(LexError::BlockComment(0))),
        (&nested, Err(LexError::BlockComment(0))),
        (&string, Err(LexError::Str(0))),
        (&raw, Err(LexError::RawStr(0))),
        (&quotes, Ok(BTreeMap::new())),
    ];
    for (input, want) in rows {
        assert!(input.len() >= 200_000, "input under 200K bytes");
        let out = lex(input.as_bytes());
        assert_eq!(out.result, want);
        assert!(
            out.steps <= 2 * input.len() + 16,
            "{} steps for {} bytes",
            out.steps,
            input.len()
        );
    }
}
