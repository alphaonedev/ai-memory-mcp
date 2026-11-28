#!/usr/bin/env python3
"""Regenerate or check the generated tables of the process-start census (#10176, #10290).

The census (`tests/process_start_census_10176.rs`) holds per-file exact counts and,
since #10286, per-file site pins. Those tables are data written by this scanner:

* `tests/common/census_rows_10176.rs`: TOKEN_ROWS, SHAPE_ROWS and ENV_NAME_ROWS.
* `tests/common/census_sites_10286.rs`: SITE_ROWS, the ordered site digests of
  every file with a watched site.

`--write` writes both files from a fresh scan of the tree; `--check` exits 1
when a committed file differs from a fresh scan and names the first differing
line of each. The census then checks the same tables against its own scan, so
the two scans are compared on every CI run.

This scanner shares no code with the census: its lexer, its name closure, its
site rules and its SHA-256 (hashlib here, a hand-written one in the census) are
written apart. A disagreement of the two lexers on any token in a site window
shows as a mismatch in the census, never as a silent pass.

Site pins (one digest per site, in token order):

* T: every identifier token of a watched name (the seed below and every name
  bound to one).
* U: every `use` declaration that names `env` or an environment function, or a
  name bound to one.
* E: every environment call whose name argument is not one string literal or
  one named constant, every `.envs(` call, and every environment function
  named as a value (not called).

Every pin covers every token of the statement that holds the site (#10303):
the tokens from the end of the previous statement to the closing `;` or the
`{` that opens a body; see `statements`. A statement over STMT_CAP tokens is
refused, the scan fails, and a pin never cuts a statement.

Every scan is linear in the tokens: brackets, `;` and `;{}` ends are tables
built once, counts over a range are prefix sums, and an impl header is read at
most IMPL_CAP tokens (a longer one counts as an impl form).

A token is written as its kind letter (I, P, S, Q, C, N), its UTF-8 byte
length, `:` and its full text. The digest is the first DIGEST_HEX (32) hex
digits of SHA-256 over the site kind letter and the written tokens (#10302).
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import os
import pathlib
import re
import stat
import sys
import tomllib

SKIPPED = frozenset({"target", ".git", ".local-runs", ".codegraph", "node_modules"})
IMPL_CAP = 512
DIGEST_HEX = 32
STMT_CAP = 2_048

CENSUS = "tests/process_start_census_10176.rs"
ROWS_OUT = "tests/common/census_rows_10176.rs"
SITES_OUT = "tests/common/census_sites_10286.rs"

WATCHED_SEED = frozenset({
    "Command", "CommandCargoExt", "CommandExt", "TestRunner", "audited_command",
    "audited_tokio_command", "cargo_bin", "cargo_bin_cmd", "libc", "nix", "process",
    "prop", "prop_assert",
    "prop_assert_eq", "prop_assert_ne", "prop_assume", "prop_compose", "prop_oneof",
    "property_test", "proptest", "proptest_helper", "rusty_fork", "rusty_fork_test",
    "wait_timeout",
})
ENV_MOD_SEED = frozenset({"env"})
ENV_FN_SEED = frozenset({"remove_var", "set_var", "var", "var_os"})

# The Unicode Pattern_White_Space set (UAX #31), the blanks rustc skips; the
# Rust lexer holds the same eleven characters (#10305). Every other non-ASCII
# character is an identifier character on both sides.
PATTERN_WHITE_SPACE = frozenset("\t\n\x0b\x0c\r \x85\u200e\u200f\u2028\u2029")
HEX = frozenset("0123456789abcdefABCDEF")

IDENT, PUNCT, SEP, STR, CHAR, NUM = "I", "P", "S", "Q", "C", "N"


class Tok:
    """One token: kind (IDENT, PUNCT, SEP, STR, CHAR, NUM), text, 1-based line."""

    __slots__ = ("kind", "text", "line")

    def __init__(self, kind: str, text: str, line: int) -> None:
        self.kind = kind
        self.text = text
        self.line = line


# ---------------------------------------------------------------- lexer


def _ident_start(c: str) -> bool:
    if c.isascii():
        return c.isalpha() or c == "_"
    return c not in PATTERN_WHITE_SPACE


def _ident_char(c: str) -> bool:
    return ("0" <= c <= "9") or _ident_start(c)


def _hex_value(text: str) -> int | None:
    """The value of a hex run as Rust's from_str_radix reads it, or None."""
    body = text[1:] if text.startswith("+") else text
    if not body or any(c not in HEX for c in body):
        return None
    return int(body, 16)


def _push_scalar(out: list[str], value: int | None) -> None:
    if value is not None and value <= 0x10FFFF and not 0xD800 <= value <= 0xDFFF:
        out.append(chr(value))


def _quoted(s: str, i: int, line: int) -> tuple[str, int, int]:
    """Decode a quoted body that starts after its opening quote."""
    out: list[str] = []
    n = len(s)
    while i < n:
        c = s[i]
        if c == '"':
            return "".join(out), i + 1, line
        if c == "\n":
            line += 1
        if c != "\\":
            out.append(c)
            i += 1
            continue
        if i + 1 >= n:
            return "".join(out), n, line
        e = s[i + 1]
        i += 2
        match e:
            case "n":
                out.append("\n")
            case "r":
                out.append("\r")
            case "t":
                out.append("\t")
            case "0":
                out.append("\0")
            case "\\" | "'" | '"':
                out.append(e)
            case "x":
                value = _hex_value(s[i:i + 2])
                if value is not None and value <= 0xFF:
                    out.append(chr(value))
                i += 2
            case "u":
                close = s.find("}", i)
                close = n if close < 0 else close
                digits = "".join(ch for ch in s[i:close] if ch in HEX)
                value = int(digits, 16) if digits else None
                _push_scalar(out, value if value is None or value <= 0xFFFFFFFF else None)
                i = close + 1
            case "\n":
                line += 1
                while i < n and s[i] in PATTERN_WHITE_SPACE:
                    if s[i] == "\n":
                        line += 1
                    i += 1
            case _:
                out.append(e)
    return "".join(out), i, line


def lex(s: str) -> list[Tok]:
    """Tokens of Rust source; comments are dropped, a number or char keeps its source text."""
    toks: list[Tok] = []
    i, n, line = 0, len(s), 1
    while i < n:
        c = s[i]
        nx = s[i + 1] if i + 1 < n else ""
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in PATTERN_WHITE_SPACE:
            i += 1
            continue
        if c == "/" and nx == "/":
            while i < n and s[i] != "\n":
                i += 1
            continue
        if c == "/" and nx == "*":
            depth = 0
            while i < n:
                if s.startswith("/*", i):
                    depth += 1
                    i += 2
                elif s.startswith("*/", i):
                    depth -= 1
                    i += 2
                    if depth == 0:
                        break
                else:
                    if s[i] == "\n":
                        line += 1
                    i += 1
            continue
        if _ident_start(c):
            j = i
            while j < n and _ident_char(s[j]):
                j += 1
            word = s[i:j]
            at = line
            if word in ("r", "br", "cr") and j < n and s[j] in '"#':
                k = j
                hashes = 0
                while k < n and s[k] == "#":
                    hashes += 1
                    k += 1
                if k < n and s[k] == '"':
                    start = k + 1
                    close = '"' + "#" * hashes
                    end = s.find(close, start)
                    end = n if end < 0 else end
                    body = s[start:end]
                    line += body.count("\n")
                    toks.append(Tok(STR, body, at))
                    i = end + len(close)
                    continue
                if word == "r" and hashes == 1 and k < n and _ident_start(s[k]):
                    m = k
                    while m < n and _ident_char(s[m]):
                        m += 1
                    toks.append(Tok(IDENT, s[k:m], at))
                    i = m
                    continue
            if word in ("b", "c") and j < n and s[j] == '"':
                body, end, line = _quoted(s, j + 1, line)
                toks.append(Tok(STR, body, at))
                i = end
                continue
            if word == "b" and j < n and s[j] == "'":
                # An escaped quote (b'\'') is not the closing quote (#10305).
                close = s.find("'", j + 3 if s[j + 1:j + 2] == "\\" else j + 1)
                close = n if close < 0 else close
                toks.append(Tok(CHAR, s[i:close + 1], at))
                i = close + 1
                continue
            toks.append(Tok(IDENT, word, at))
            i = j
            continue
        if "0" <= c <= "9":
            start = i
            while i < n and (_ident_char(s[i]) or (s[i] == "." and i + 1 < n and "0" <= s[i + 1] <= "9")):
                i += 1
            toks.append(Tok(NUM, s[start:i], line))
            continue
        if c == '"':
            at = line
            body, end, line = _quoted(s, i + 1, line)
            toks.append(Tok(STR, body, at))
            i = end
            continue
        if c == "'":
            close = None
            if nx == "\\":
                # The escaped character is never the closing quote (#10305).
                p = s.find("'", i + 3)
                close = p if p >= 0 else None
            elif i + 2 < n and s[i + 2] == "'":
                close = i + 2
            if close is not None:
                toks.append(Tok(CHAR, s[i:close + 1], line))
                i = close + 1
                continue
            toks.append(Tok(PUNCT, "'", line))
            i += 1
            continue
        if c == ":" and nx == ":":
            toks.append(Tok(SEP, "::", line))
            i += 2
            continue
        toks.append(Tok(PUNCT, c, line))
        i += 1
    return toks


# ---------------------------------------------------------------- helpers


def is_p(t: list[Tok], k: int, c: str) -> bool:
    return 0 <= k < len(t) and t[k].kind == PUNCT and t[k].text == c


def ident_at(t: list[Tok], k: int) -> str | None:
    if 0 <= k < len(t) and t[k].kind == IDENT:
        return t[k].text
    return None


def brackets(t: list[Tok]) -> list[int]:
    """For each opening bracket its closing index (or len); -1 elsewhere. One stack pass."""
    close = [-1] * len(t)
    stack: list[int] = []
    for k, x in enumerate(t):
        if x.kind != PUNCT:
            continue
        if x.text in "([{":
            stack.append(k)
        elif x.text in ")]}" and stack:
            close[stack.pop()] = k
    for k in stack:
        close[k] = len(t)
    return close


def next_of(t: list[Tok], stops: str) -> list[int]:
    """For each index the index of the next punctuation in `stops` at or after it (or len)."""
    out = [len(t)] * (len(t) + 1)
    for k in range(len(t) - 1, -1, -1):
        out[k] = k if t[k].kind == PUNCT and t[k].text in stops else out[k + 1]
    return out


def semis(t: list[Tok]) -> list[int]:
    """For each index the index of the next `;` at or after it (or len)."""
    return next_of(t, ";")


def prefix(t: list[Tok], hit) -> list[int]:
    """prefix[k] is the number of tokens before k for which hit(token) holds."""
    out = [0] * (len(t) + 1)
    for k, x in enumerate(t):
        out[k + 1] = out[k] + (1 if hit(x) else 0)
    return out


def is_use(t: list[Tok], k: int) -> bool:
    """A `use` declaration starts at k (not a path segment named use)."""
    return ident_at(t, k) == "use" and not (k > 0 and t[k - 1].kind == SEP)


def first_arg(t: list[Tok], open_: int, close: list[int]) -> list[Tok]:
    end = min(close[open_], len(t))
    k = open_ + 1
    while k < end:
        if t[k].kind == PUNCT and t[k].text in "([{":
            k = close[k] + 1
            continue
        if is_p(t, k, ","):
            return t[open_ + 1:k]
        k += 1
    return t[open_ + 1:end]


def name_ok(arg: list[Tok], consts: frozenset[str]) -> bool:
    """One string literal, or `[&] [path ::] NAME` with NAME in `consts` (#10299)."""
    if len(arg) == 1 and arg[0].kind == STR:
        return True
    if arg and arg[0].kind == PUNCT and arg[0].text == "&":
        arg = arg[1:]
    if not arg or arg[-1].kind != IDENT or arg[-1].text not in consts:
        return False
    return all(x.kind == (IDENT if i % 2 == 0 else SEP) for i, x in enumerate(arg))


def item_binding(t: list[Tok], k: int, close: list[int]) -> tuple[int, bool] | None:
    """At a `const` or `static` token: the index of the NAME of `const|static [mut] NAME :` and
    whether its initializer is one string literal (`= "..." ;`); None when no NAME follows."""
    j = k + 1
    if t[k].text == "static" and ident_at(t, j) == "mut":
        j += 1
    if ident_at(t, j) is None or not is_p(t, j + 1, ":"):
        return None
    m = j + 2
    while m < len(t):
        x = t[m]
        if x.kind == PUNCT:
            if x.text in "([{":
                m = close[m] + 1
                continue
            if x.text == "=":
                break
            if x.text in ";}),]>":
                return j, False
        m += 1
    return j, m + 2 < len(t) and t[m + 1].kind == STR and is_p(t, m + 2, ";")


CLOSURE_AFTER_KEYWORD = frozenset({"move", "return", "in", "else", "match", "if", "while"})


def closure_open(t: list[Tok], k: int) -> bool:
    """A `|` at `k` that opens closure parameters: the token before it ends no operand."""
    if k == 0:
        return True
    p = t[k - 1]
    if p.kind == IDENT:
        return p.text in CLOSURE_AFTER_KEYWORD
    if p.kind in (STR, NUM, CHAR):
        return False
    return not (p.kind == PUNCT and p.text in ")]|")


def binder_names(t: list[Tok], close: list[int], defs: set[int]) -> set[str]:
    """Every name `t` binds other than at an item NAME in `defs`: a `let` or `for` pattern, fn
    and closure parameters, a match-arm pattern, a `NAME @` binding, and every `NAME :` (a struct
    field, a typed parameter or binding, a field pattern). One pass; each span is walked once."""
    n = len(t)
    out: set[str] = set()
    opener = [-1] * n
    for o, c in enumerate(close):
        if 0 <= c < n:
            opener[c] = o

    def mark(a: int, b: int) -> None:
        out.update(x.text for x in t[max(a, 0):min(b, n)] if x.kind == IDENT)

    def forward(a: int, is_let: bool) -> int:
        """From `a` to the first top-level `=` (a `let`) or `in` (a `for`), `;` or closer; a
        `for` also ends at a `{` that is not a pattern's (one not followed by `in`)."""
        m = a
        while m < n:
            x = t[m]
            if x.kind == PUNCT:
                if x.text in "([{":
                    if x.text == "{" and not is_let and ident_at(t, close[m] + 1) != "in":
                        return m
                    m = close[m] + 1
                    continue
                if x.text in ";)]}" or (is_let and x.text == "="):
                    return m
            elif not is_let and x.kind == IDENT and x.text == "in":
                return m
            m += 1
        return n

    k = 0
    while k < n:
        x = t[k]
        if x.kind == IDENT:
            if k not in defs and (is_p(t, k + 1, ":") or is_p(t, k + 1, "@")):
                out.add(x.text)
            if x.text in ("let", "for"):
                mark(k + 1, forward(k + 1, x.text == "let"))
            elif x.text == "fn" and ident_at(t, k + 1) is not None:
                j, depth = k + 2, 0
                while j < n and not (depth == 0 and is_p(t, j, "(")):
                    if is_p(t, j, "<"):
                        depth += 1
                    elif is_p(t, j, ">") and not is_p(t, j - 1, "-"):
                        depth -= 1
                    elif t[j].kind == PUNCT and t[j].text in ";{}":
                        break
                    j += 1
                if is_p(t, j, "("):
                    mark(j + 1, close[j])
        elif x.kind == PUNCT and x.text == "|" and closure_open(t, k):
            m = k + 1
            while m < n and not is_p(t, m, "|"):
                if t[m].kind == PUNCT and t[m].text in "([{":
                    m = close[m] + 1
                    continue
                if t[m].kind == PUNCT and t[m].text in ";)]}":
                    break
                m += 1
            mark(k + 1, m)
            k = m + 1 if is_p(t, m, "|") else m
            continue
        elif x.kind == PUNCT and x.text == "=" and is_p(t, k + 1, ">"):
            j = k - 1
            while j >= 0:
                y = t[j]
                if y.kind == PUNCT:
                    if y.text in ",;{([" or (y.text == ">" and is_p(t, j - 1, "=")):
                        break
                    if y.text in ")]" and opener[j] >= 0:
                        j = opener[j] - 1
                        continue
                    if y.text == "}":
                        o = opener[j]
                        if o > 0 and t[o - 1].kind == IDENT:
                            j = o - 1
                            continue
                        break
                j -= 1
            mark(j + 1, k)
        k += 1
    return out


def const_names(files: list[list[Tok]]) -> frozenset[str]:
    """#10299: the names bound in the tree by a `const` or `static [mut]` item whose initializer
    is one string literal, minus every name bound anywhere else (another initializer, a pattern,
    a parameter, a field). The census has no scope model, so a name bound twice is refused."""
    literal: set[str] = set()
    other: set[str] = set()
    for t in files:
        close = brackets(t)
        defs: set[int] = set()
        for k, x in enumerate(t):
            if x.kind == IDENT and x.text in ("const", "static"):
                got = item_binding(t, k, close)
                if got is not None:
                    j, lit = got
                    defs.add(j)
                    (literal if lit else other).add(t[j].text)
        other |= binder_names(t, close, defs)
    return frozenset(literal - other)


Prepared = list[tuple[str, list[Tok], list[int], list[int], list[int]]]


def prepare(lexed: list[tuple[str, list[Tok]]]) -> Prepared:
    """Each file with its bracket, `;` and `;{}` tables, computed once."""
    return [(rel, t, brackets(t), semis(t), next_of(t, ";{}")) for rel, t in lexed]


class RenameGraph:
    """#10304: the rename graph of a tree, built once. A node is a name or a binder
    (one `self as Y`, `type Y` or `macro_rules! Y`); an edge a -> b means b is
    reached when a is. A token has one range edge (the innermost range that holds
    it), so the graph is linear in the tokens. Overlapping ranges need no edge of
    their own: the name of an inner binder is a token of the outer range."""

    def __init__(self, prepared: Prepared) -> None:
        self.ids: dict[str, int] = {}
        self.name_of: list[str | None] = []
        self.out: list[list[int]] = []
        for _rel, t, close, semi, stop in prepared:
            self._uses(t, semi)
            self._types(t, stop)
            self._macros(t, close)

    def name(self, s: str) -> int:
        if s not in self.ids:
            self.ids[s] = self.binder()
            self.name_of[self.ids[s]] = s
        return self.ids[s]

    def binder(self) -> int:
        self.name_of.append(None)
        self.out.append([])
        return len(self.out) - 1

    def _uses(self, t: list[Tok], semi: list[int]) -> None:
        use_until = -1
        for k, x in enumerate(t):
            if x.kind != IDENT:
                continue
            if x.text == "use":
                if k < use_until:
                    continue
                end = semi[k]
                use_until = end
                pending: list[int] = []
                for j in range(k, end):
                    a = ident_at(t, j)
                    if a is not None:
                        pending.append(self.name(a))
                    y = ident_at(t, j + 2)
                    if y is None or y == "_" or j + 2 >= end or ident_at(t, j + 1) != "as":
                        continue
                    yi = self.name(y)
                    if a is not None:
                        self.out[self.name(a)].append(yi)
                    if a == "self":
                        s = self.binder()
                        self.out[s].append(yi)
                        for p in pending:
                            self.out[p].append(s)
                        pending = []
            elif x.text == "extern" and ident_at(t, k + 1) == "crate" and ident_at(t, k + 3) == "as":
                a, y = ident_at(t, k + 2), ident_at(t, k + 4)
                if a is not None and y is not None and y != "_":
                    self.out[self.name(a)].append(self.name(y))

    def _types(self, t: list[Tok], stop: list[int]) -> None:
        starts: list[tuple[int, int, int]] = []
        for k, x in enumerate(t):
            if x.kind != IDENT or x.text != "type" or (k > 0 and t[k - 1].kind == SEP):
                continue
            y = ident_at(t, k + 1)
            if y is None:
                continue
            e = stop[k + 1]
            if e > k + 2:
                b = self.binder()
                self.out[b].append(self.name(y))
                starts.append((k + 2, e, b))
        q = 0
        cur: tuple[int, int] | None = None
        for i in range(len(t)):
            if cur is not None and cur[0] <= i:
                cur = None
            while q < len(starts) and starts[q][0] <= i:
                _s, e, b = starts[q]
                q += 1
                cur = (e, b)
            a = ident_at(t, i)
            if cur is not None and a is not None:
                self.out[self.name(a)].append(cur[1])

    def _macros(self, t: list[Tok], close: list[int]) -> None:
        n = len(t)
        opens: list[tuple[int, int, int]] = []
        for k, x in enumerate(t):
            if x.kind != IDENT or x.text != "macro_rules" or not is_p(t, k + 1, "!"):
                continue
            y = ident_at(t, k + 2)
            if y is None:
                continue
            open_ = min(k + 3, n)
            end = min(close[k + 3] if k + 3 < n and close[k + 3] >= 0 else open_, n)
            if end > open_:
                b = self.binder()
                self.out[b].append(self.name(y))
                opens.append((open_, end, b))
        q = 0
        stack: list[tuple[int, int]] = []
        for i in range(n):
            while stack and stack[-1][0] <= i:
                stack.pop()
            while q < len(opens) and opens[q][0] <= i:
                _o, e, b = opens[q]
                q += 1
                stack.append((e, b))
            a = ident_at(t, i)
            if stack and a is not None:
                self.out[self.name(a)].append(stack[-1][1])

    def nodes(self) -> int:
        """The number of nodes."""
        return len(self.out)

    def walk(self, seed: frozenset[str]) -> tuple[set[str], int]:
        """The seed and every name reached from it, and the pushes: one worklist,
        each node pushed at most once. The loop is bounded by the node count as
        well, so a broken visited check ends with pushes over the node count
        instead of running on."""
        names = set(seed)
        visited = [False] * len(self.out)
        work = []
        pushes = 0
        for s in sorted(seed):
            if s in self.ids and not visited[self.ids[s]]:
                visited[self.ids[s]] = True
                work.append(self.ids[s])
                pushes += 1
        budget = len(self.out)
        while budget > 0 and work:
            budget -= 1
            x = work.pop()
            if self.name_of[x] is not None:
                names.add(self.name_of[x])
            for y in self.out[x]:
                if not visited[y]:
                    visited[y] = True
                    work.append(y)
                    pushes += 1
        return names, pushes

    def reach(self, seed: frozenset[str]) -> set[str]:
        """The names of [`walk`]."""
        return self.walk(seed)[0]


def closure(prepared: Prepared, seed: frozenset[str]) -> set[str]:
    """The seed and every name bound to a member: one worklist over the rename graph
    (#10304), linear in the tokens for a chain in any order."""
    return RenameGraph(prepared).reach(seed)


# ---------------------------------------------------------------- tables


def shapes_of(t: list[Tok], watched: set[str]) -> list[tuple[str, int]]:
    """Every form the census does not model, (kind, line); linear (an impl header is
    read at most IMPL_CAP tokens, and a longer one counts as an impl form)."""
    out = []
    semi = semis(t)
    stars = prefix(t, lambda x: x.kind == PUNCT and x.text == "*")
    named = prefix(t, lambda x: x.kind == IDENT and x.text in watched)
    for k, x in enumerate(t):
        v, ln = x.text, x.line
        nxt = t[k + 1] if k + 1 < len(t) else None
        if x.kind == IDENT and v == "impl":
            m, d, hit = k + 1, 0, False
            cap = min(len(t), k + 1 + IMPL_CAP)
            while m < cap:
                y = t[m]
                if y.kind == PUNCT and y.text in "<([":
                    d += 1
                elif y.kind == PUNCT and y.text in ">)]":
                    d = max(d - 1, 0)
                elif y.kind == PUNCT and y.text in "{;" and d == 0:
                    break
                if y.kind == IDENT and y.text in watched:
                    hit = True
                m += 1
            if m == cap < len(t):
                hit = True
            if hit:
                out.append(("impl", ln))
        if x.kind == IDENT and v in watched and nxt is not None and nxt.kind == SEP and is_p(t, k + 2, "$"):
            out.append(("metavar", ln))
        if is_use(t, k):
            e = semi[k]
            if stars[e] > stars[k] and named[e] > named[k]:
                out.append(("glob", ln))
        if is_p(t, k, "[") and is_p(t, k + 1, "<"):
            out.append(("paste", ln))
        if x.kind == IDENT and v in ("paste", "concat_idents") and is_p(t, k + 1, "!"):
            out.append(("paste", ln))
        if x.kind == IDENT and v in ("asm", "global_asm", "naked_asm") and is_p(t, k + 1, "!"):
            out.append(("asm", ln))
        if x.kind == IDENT and v == "extern" and (
            is_p(t, k + 1, "{") or (nxt is not None and nxt.kind == STR and is_p(t, k + 2, "{"))
        ):
            refused = extern_refused(t, k + 1 if is_p(t, k + 1, "{") else k + 2)
            if refused is not None:
                raise ValueError(f"line {ln}: an extern block declares {refused}; "
                                 "only acl_* functions may be declared in one (#10311)")
            out.append(("extern", ln))
    return out


def extern_refused(t: list[Tok], open_k: int) -> str | None:
    """#10311: the first item of the extern block opened at `open_k` that is not an
    `acl_*` function, named as the Rust census names it (`#[name]` for an
    attribute, the name of a `static`, `type` or other `fn`, else the first token
    of the item), or None. Stops at the first refusal, so an acl-only block is read
    once and the scan stays linear."""
    k = open_k + 1

    def item_end(j: int) -> int:
        d = 0
        while j < len(t):
            if t[j].kind == PUNCT and t[j].text in "([{":
                d += 1
            elif t[j].kind == PUNCT and t[j].text in ")]}":
                if d == 0:
                    return j
                d -= 1
            elif d == 0 and is_p(t, j, ";"):
                return j + 1
            j += 1
        return j

    while k < len(t):
        v = ident_at(t, k)
        if is_p(t, k, "}"):
            return None
        if v == "pub" and is_p(t, k + 1, "("):
            k = _group_after(t, k + 1)
        elif v in ("pub", "unsafe", "safe"):
            k += 1
        elif v == "fn":
            n = ident_at(t, k + 1)
            if n is None or len(n) <= len("acl_") or not n.startswith("acl_"):
                return n if n is not None else "fn"
            k = item_end(k + 1)
        elif v in ("static", "type"):
            at = k + 2 if v == "static" and ident_at(t, k + 1) == "mut" else k + 1
            return ident_at(t, at) or v
        elif is_p(t, k, ";"):
            k += 1
        elif is_p(t, k, "#"):
            br = k + 2 if is_p(t, k + 1, "!") else k + 1
            return f"#[{ident_at(t, br + 1) or '?'}]" if is_p(t, br, "[") else "#"
        else:
            return t[k].text if t[k].kind != STR else repr(t[k].text)
    return None


def _group_after(t: list[Tok], open_k: int) -> int:
    """The index after the group opened at `open_k`."""
    d = 0
    for j in range(open_k, len(t)):
        if t[j].kind == PUNCT and t[j].text in "([{":
            d += 1
        elif t[j].kind == PUNCT and t[j].text in ")]}":
            d -= 1
            if d == 0:
                return j + 1
    return len(t)


def env_calls(t: list[Tok], env_fns: set[str], close: list[int], consts: frozenset[str]) -> list[int]:
    """The name index of every environment reach whose name
    is not ok: a call of an environment function (by any name bound to one) whose
    first argument is not one literal or one constant, `.env(`/`.env_remove(` and
    `env!`/`option_env!` likewise, every `.envs(`, and every environment function
    named as a value (not called, not a method, not a definition, not in a `use`)."""
    out = []
    semi = semis(t)
    in_use_until = -1
    for k, x in enumerate(t):
        if x.kind != IDENT:
            continue
        v = x.text
        if is_use(t, k):
            in_use_until = semi[k]
        open_ = None
        always = False
        after_fn = is_p(t, k - 1, ".") or ident_at(t, k - 1) == "fn"
        if v in env_fns and not after_fn and not is_p(t, k + 1, "(") and k > in_use_until:
            out.append(k)
            continue
        if is_p(t, k + 1, "(") and v in env_fns and not after_fn:
            open_ = k + 1
        elif v in ("env", "env_remove") and is_p(t, k - 1, ".") and is_p(t, k + 1, "("):
            open_ = k + 1
        elif v == "envs" and is_p(t, k - 1, ".") and is_p(t, k + 1, "("):
            open_, always = k + 1, True
        elif v in ("env", "option_env") and is_p(t, k + 1, "!") and k + 2 < len(t) and (
            t[k + 2].kind == PUNCT and t[k + 2].text in "([{"
        ):
            open_ = k + 2
        if open_ is None:
            continue
        if always or not name_ok(first_arg(t, open_, close), consts):
            out.append(k)
    return out


def env_counts(prepared: Prepared, env_fns: set[str], consts: frozenset[str] | None = None) -> dict[str, int]:
    """The number of environment reaches whose name is not ok, per file that has one; the
    constant names are those of all of `prepared` (#10299)."""
    if consts is None:
        consts = const_names([t for _rel, t, *_rest in prepared])
    out: dict[str, int] = {}
    for rel, t, close, *_rest in prepared:
        e = env_calls(t, env_fns, close, consts)
        if e:
            out[rel] = len(e)
    return out


def use_sites(t: list[Tok], env_names: set[str]) -> list[int]:
    """The `use` index of every `use` declaration that names an env name."""
    semi = semis(t)
    named = prefix(t, lambda x: x.kind == IDENT and x.text in env_names)
    return [k for k in range(len(t)) if is_use(t, k) and named[semi[k]] > named[k]]


def statements(t: list[Tok]) -> list[tuple[int, int]]:
    """(first, last) of every statement, in order; together they hold every token once.

    A statement ends, inclusive, at a `;`, `{` or `}` with no `(` or `[` open, so a
    call's whole argument list (closures and blocks in it too) is in one statement,
    and a body's `{` ends the statement or item head before it. Inside a `use`
    declaration (from a `use` with no `(` or `[` open to its `;`) braces do not end
    it. A closer pops the top opener whatever it is, as `brackets` does. The last
    statement may end at the file end. One pass, linear."""
    out = []
    stack: list[str] = []
    groups = 0
    in_use = False
    start = 0
    for k, x in enumerate(t):
        end = False
        if x.kind == PUNCT:
            c = x.text
            if c in "([":
                stack.append(c)
                groups += 1
            elif c == "{":
                stack.append(c)
                end = groups == 0 and not in_use
            elif c in ")]}":
                if stack and stack.pop() != "{":
                    groups -= 1
                end = c == "}" and groups == 0 and not in_use
            elif c == ";" and groups == 0:
                in_use = False
                end = True
        elif groups == 0 and is_use(t, k):
            in_use = True
        if end:
            out.append((start, k))
            start = k + 1
    if start < len(t):
        out.append((start, len(t) - 1))
    return out


def encode(t: list[Tok], lo: int, hi: int) -> str:
    """The written tokens lo..=hi, each `<kind><byte len>:<full text>`."""
    return "".join(f"{x.kind}{len(x.text.encode())}:{x.text}" for x in t[lo:hi + 1])


def digest(kind: str, body: str) -> str:
    return hashlib.sha256((kind + body).encode()).hexdigest()[:DIGEST_HEX]


def sites_of(t: list[Tok], watched: set[str], env_names: set[str], env_fns: set[str],
             consts: frozenset[str] | None = None) -> list[str]:
    """The pin of every site in token order: the digest of the site kind and the
    whole statement that holds the site. Each statement is written and hashed
    once per kind, so the cost is linear. A site in a statement over STMT_CAP
    tokens raises ValueError (#10303)."""
    close = brackets(t)
    spans = statements(t)
    of = [0] * len(t)
    for i, (a, b) in enumerate(spans):
        for m in range(a, b + 1):
            of[m] = i
    memo: dict[tuple[int, str], str] = {}

    def pin(k: int, kind: str) -> str:
        i = of[k]
        if (i, kind) not in memo:
            a, b = spans[i]
            n = b - a + 1
            if n > STMT_CAP:
                raise ValueError(f"line {t[a].line}: a watched statement of {n} tokens is over STMT_CAP "
                                 f"{STMT_CAP}; a pin never cuts a statement (#10303)")
            memo[(i, kind)] = digest(kind, encode(t, a, b))
        return memo[(i, kind)]

    found: list[tuple[int, int, str]] = []
    for k, x in enumerate(t):
        if x.kind == IDENT and x.text in watched:
            found.append((k, 0, pin(k, "T")))
    for k in use_sites(t, env_names):
        found.append((k, 1, pin(k, "U")))
    if consts is None:
        consts = const_names([t])
    for k in env_calls(t, env_fns, close, consts):
        found.append((k, 2, pin(k, "E")))
    found.sort()
    return [d for _k, _o, d in found]


# ---------------------------------------------------------------- tree


LINK_FINDING = "a symbolic link; the census never follows links (#10176)"
DOTS_FINDING = ("holds an empty, '.' or '..' component; the census opens a path below the root one name at a time "
                "(#10345)")
DIR_WALK_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# A test seam (#10345): when set, called with each relative prefix just before
# the walk opens it, so a test can swap a directory between two walk steps.
WALK_HOOK = None


def _refuse_link(rel: str, part: str, dir_fd: int, name: str, e: OSError) -> None:
    """Raise the link finding naming `part` when `name` under `dir_fd` is a
    link (looked up with no link followed); return to re-raise `e` otherwise."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"{rel}: {part} is {LINK_FINDING}") from e


def open_in_root(root: pathlib.Path, rel: str, flags: int, mode: int = 0o644) -> int:
    """An fd of `rel` below `root`, opened by a walk from a root directory fd
    one name at a time: every directory with O_DIRECTORY | O_NOFOLLOW and the
    last name with O_NOFOLLOW, each relative to the fd before it, so the
    in-root decision and the open are the same act and no component below the
    root is ever a link followed (#10345). ValueError naming the path and the
    linked component; any other OSError of an open is raised as it is."""
    parts = rel.split("/")
    if rel.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise ValueError(f"{rel}: {DOTS_FINDING}")
    cur = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for i, name in enumerate(parts):
            part = "/".join(parts[: i + 1])
            if WALK_HOOK is not None:
                WALK_HOOK(part)
            last = i == len(parts) - 1
            try:
                if last:
                    nxt = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=cur)
                else:
                    nxt = os.open(name, DIR_WALK_FLAGS, dir_fd=cur)
            except OSError as e:
                if not last and e.errno in (errno.ELOOP, errno.ENOTDIR):
                    _refuse_link(rel, part, cur, name, e)
                raise
            os.close(cur)
            cur = nxt
        fd, cur = cur, -1
        return fd
    finally:
        if cur != -1:
            os.close(cur)


def read_scanned(root: pathlib.Path, rel: str) -> bytes:
    """The bytes of a file of the walk, opened with no link followed in any
    component (#10345); ValueError naming the relative path and the cause
    otherwise."""
    try:
        fd = open_in_root(root, rel, os.O_RDONLY)
        with os.fdopen(fd, "rb") as f:
            return f.read()
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise ValueError(f"{rel}: {LINK_FINDING}") from e
        raise ValueError(f"{rel}: unreadable ({e.strerror or e})") from e


def tree_rs(root: pathlib.Path, found: list[str] | None = None) -> list[tuple[str, str]]:
    """(relative path, text) of every regular .rs file outside SKIPPED. A link
    anywhere in the walk is a finding, as in the Rust census; every failure
    names the relative path and the cause. The findings go to `found` when
    given, else ValueError (one finding per line)."""
    out = []
    errors = [] if found is None else found
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError as e:
            errors.append(f"{d.relative_to(root).as_posix()}: unreadable ({e.strerror or e})")
            continue
        for p in entries:
            rel = p.relative_to(root).as_posix()
            if rel in SKIPPED:
                continue
            if p.is_symlink():
                errors.append(f"{rel}: {LINK_FINDING}")
            elif p.is_dir():
                stack.append(p)
            elif p.is_file() and p.suffix.lower() == ".rs":
                try:
                    out.append((rel, read_scanned(root, rel).decode("utf-8")))
                except UnicodeDecodeError as e:
                    errors.append(f"{rel}: not UTF-8 ({e.reason}); the census cannot read it (#10176)")
                except ValueError as e:
                    errors.append(str(e))
    if errors and found is None:
        raise ValueError("\n".join(sorted(errors)))
    return sorted(out)


# ---------------------------------------------------------------- cargo config (#10301)

# The crates whose replacement would hide a process start or a proptest run,
# written as Cargo normalises them; the Rust list is census_cargo WATCHED_CRATES.
WATCHED_CRATES = frozenset({"libc", "nix", "proptest", "rusty_fork", "wait_timeout"})
# The file names cargo reads its configuration from, inside a `.cargo` dir.
CONFIG_DIR = ".cargo"
CONFIG_NAMES = ("config.toml", "config")
# Top-level tables that cannot replace a crate or start a process.
CONFIG_PLAIN = frozenset({"alias", "cache", "cargo-new", "doc", "future-incompat-report", "http", "net", "term"})
# `build` keys that cannot replace a crate or start a process; rustflags are read.
BUILD_PLAIN = frozenset({"dep-info-basedir", "incremental", "jobs", "target", "target-dir"})
FLAG_KEYS = frozenset({"rustflags", "rustdocflags"})
FLAG_SPLIT_RE = re.compile(r"[^A-Za-z0-9_-]+")
# ASCII-only case folding, as Rust to_ascii_lowercase and to_ascii_uppercase do. str.lower()
# and str.upper() also map non-ASCII letters (U+212A, U+017F) to ASCII, which cargo and
# proptest never do, so the two census sides would disagree (#10301).
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
CFG_PATCH = "{rel}: {shown} patches the watched crate {name}; a patched watched crate runs code the census never reads (#10301)"
CFG_PATHS = ("{rel}: paths overrides crates with local copies; a path override can replace a watched crate with code "
             "the census never reads (#10301)")
CFG_SOURCE = "{rel}: {shown} replaces a crate source; a replaced source can serve a watched crate the census never reads (#10301)"
CFG_FLAG = ("{rel}: {shown} names a watched crate or an extern in a compiler flag; a flag can replace a watched crate "
            "with code the census never reads (#10301)")
CFG_ENV = "{rel}: {shown} sets a proptest variable for every cargo command; a config can switch proptest fork on (#10301)"
CFG_UNKNOWN = ("{rel}: {shown} is a cargo config form the census does not understand; a form it does not read is a "
               "process start nobody counted (#10301)")
CFG_NOT_UTF8 = "{rel}: not UTF-8; an unreadable cargo config is not clean (#10301)"
CFG_NOT_TOML = "{rel}: not TOML the census reads; an unparseable cargo config is not clean (#10301)"


def crate_watched(name: str) -> bool:
    return name.translate(ASCII_LOWER).replace("-", "_") in WATCHED_CRATES


def is_config(rel: str) -> bool:
    """Whether `rel` is a file cargo reads its configuration from, at any depth."""
    parts = rel.split("/")
    return len(parts) >= 2 and parts[-2] == CONFIG_DIR and parts[-1] in CONFIG_NAMES


def _flatten(value: object, path: list[str], out: list[tuple[list[str], str | None]]) -> bool:
    """Flatten to (key path, string or None) as census_cargo::parse does; False on a
    value outside the Rust parser's subset (a float or a date)."""
    if isinstance(value, dict):
        return all(_flatten(v, [*path, k], out) for k, v in value.items())
    if isinstance(value, list):
        return all(_flatten(v, [*path, f"#{i}"], out) for i, v in enumerate(value))
    if isinstance(value, str):
        out.append((path, value))
        return True
    if isinstance(value, (bool, int)):
        out.append((path, None))
        return True
    return False


def _flag_hit(value: str | None) -> bool:
    if value is None:
        return False
    return "extern" in value.translate(ASCII_LOWER) or any(crate_watched(w) for w in FLAG_SPLIT_RE.split(value) if w)


def config_findings(rel: str, data: bytes) -> list[str]:
    """The #10301 findings of one cargo config file, sorted and without repeats."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [CFG_NOT_UTF8.format(rel=rel)]
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return [CFG_NOT_TOML.format(rel=rel)]
    entries: list[tuple[list[str], str | None]] = []
    if not _flatten(doc, [], entries):
        return [CFG_NOT_TOML.format(rel=rel)]
    out: set[str] = set()
    for path, value in entries:
        top = path[0]
        if top == "patch" and len(path) >= 3:
            name = path[2]
            if crate_watched(name):
                out.add(CFG_PATCH.format(rel=rel, shown=".".join(path[:3]), name=name))
            elif path[-1] == "package" and value is not None and crate_watched(value):
                out.add(CFG_PATCH.format(rel=rel, shown=".".join(path[:3]), name=value))
        elif top == "patch":
            out.add(CFG_UNKNOWN.format(rel=rel, shown=".".join(path)))
        elif top == "paths":
            out.add(CFG_PATHS.format(rel=rel))
        elif top == "source":
            out.add(CFG_SOURCE.format(rel=rel, shown=".".join(path[:2])))
        elif top == "env" and len(path) >= 2:
            if path[1].translate(ASCII_UPPER).startswith("PROPTEST"):
                out.add(CFG_ENV.format(rel=rel, shown=".".join(path[:2])))
        elif top == "build" and len(path) >= 2 and path[1] in FLAG_KEYS:
            if _flag_hit(value):
                out.add(CFG_FLAG.format(rel=rel, shown=".".join(path)))
        elif top == "build" and len(path) >= 2 and path[1] in BUILD_PLAIN:
            pass
        elif top == "build":
            out.add(CFG_UNKNOWN.format(rel=rel, shown=".".join(path[:2])))
        elif top == "target" and len(path) >= 3 and path[2] in FLAG_KEYS:
            if _flag_hit(value):
                out.add(CFG_FLAG.format(rel=rel, shown=".".join(path)))
        elif top == "target":
            out.add(CFG_UNKNOWN.format(rel=rel, shown=".".join(path[:3])))
        elif top not in CONFIG_PLAIN:
            out.add(CFG_UNKNOWN.format(rel=rel, shown=top))
    return sorted(out)


def tree_configs(root: pathlib.Path, found: list[str] | None = None) -> list[tuple[str, bytes]]:
    """(relative path, bytes) of every regular cargo config file outside SKIPPED.
    A link anywhere in the walk is a finding and every failure names the
    relative path and the cause, as in `tree_rs`."""
    out = []
    errors = [] if found is None else found
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError as e:
            errors.append(f"{d.relative_to(root).as_posix()}: unreadable ({e.strerror or e})")
            continue
        for p in entries:
            rel = p.relative_to(root).as_posix()
            if rel in SKIPPED:
                continue
            if p.is_symlink():
                errors.append(f"{rel}: {LINK_FINDING}")
            elif p.is_dir():
                stack.append(p)
            elif p.is_file() and is_config(rel):
                try:
                    out.append((rel, read_scanned(root, rel)))
                except ValueError as e:
                    errors.append(str(e))
    if errors and found is None:
        raise ValueError("\n".join(sorted(errors)))
    return sorted(out)


# ---------------------------------------------------------------- include sites (#10300)

# The include macro whose target is Rust code, and the form each site is
# written as in a finding. `include_str!` and `include_bytes!` name data that is
# never compiled as Rust, so they are not sites (#10300 design call).
INCLUDE_MACRO = "include"
INCLUDE_FORM = "include!"
PATH_FORM = "#[path]"
# The largest include target the census reads or accepts, in bytes.
INCLUDE_CAP = 4 * 1024 * 1024
# The longest include argument the census resolves, in bytes (PATH_MAX); it
# bounds the lookups of one site.
INCLUDE_PATH_CAP = 4096
OPENERS = "([{"


def shown(s: str) -> str:
    """`s` with `\\` and `"` escaped and every character outside printable ASCII
    written `\\u{hex}`; the Rust census writes the same text."""
    out = []
    for c in s:
        if c in '\\"':
            out.append("\\" + c)
        elif " " <= c <= "~":
            out.append(c)
        else:
            out.append(f"\\u{{{ord(c):x}}}")
    return "".join(out)


def _top_items(t: list[Tok], close: list[int], lo: int, hi: int) -> list[tuple[int, int]]:
    """The comma-separated items of t[lo:hi], each (first, end), nested groups jumped."""
    items = []
    start = k = lo
    while k < hi:
        if t[k].kind == PUNCT and t[k].text in OPENERS:
            k = close[k] + 1
            continue
        if is_p(t, k, ","):
            items.append((start, k))
            start = k + 1
        k += 1
    if start < hi:
        items.append((start, hi))
    return items


def _one_literal(t: list[Tok], lo: int, hi: int) -> str | None:
    return t[lo].text if hi == lo + 1 and t[lo].kind == STR else None


def include_sites(t: list[Tok], close: list[int]) -> list[tuple[int, str, int, str | None]]:
    """(token index, form, line, the one string-literal argument or None) of every
    `include!` call and every `path = ..` of a
    `#[path]` or `#[cfg_attr(.., path = ..)]` attribute, in token order. Each
    attribute is walked once with a worklist, so the cost is linear."""
    out = []
    done = 0
    n = len(t)
    for k, x in enumerate(t):
        if (x.kind == IDENT and x.text == INCLUDE_MACRO and is_p(t, k + 1, "!")
                and k + 2 < n and t[k + 2].kind == PUNCT and t[k + 2].text in OPENERS):
            o = k + 2
            out.append((k, INCLUDE_FORM, x.line, _one_literal(t, o + 1, close[o])))
            continue
        if k < done or not is_p(t, k, "#"):
            continue
        b = k + 2 if is_p(t, k + 1, "!") else k + 1
        if not is_p(t, b, "[") or ident_at(t, b + 1) not in ("path", "cfg_attr"):
            continue
        end = close[b]
        done = end + 1
        work = [(b + 1, end)]
        while work:
            lo, hi = work.pop()
            name = ident_at(t, lo)
            if name == "path" and is_p(t, lo + 1, "="):
                out.append((lo, PATH_FORM, t[lo].line, _one_literal(t, lo + 2, hi)))
            elif name == "cfg_attr" and is_p(t, lo + 1, "("):
                inner = close[lo + 1]
                work.extend(_top_items(t, close, lo + 2, min(inner, hi))[1:])
    return sorted(out, key=lambda s: s[0])


def include_steps(rel: str, path: str) -> list[str] | None:
    """Every tree path a lookup of `path` from the directory of `rel` passes,
    in order, the target last (`.` and `..` folded, so a component later undone
    by `..` is still listed); None when it leaves the tree, is absolute or
    holds a backslash."""
    if path.startswith("/") or "\\" in path:
        return None
    parts = rel.split("/")[:-1]
    steps = []
    for p in path.split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(p)
            steps.append("/".join(parts))
    steps.append("/".join(parts))
    return steps


def include_target(root: pathlib.Path, rel: str, form: str, line: int, arg: str | None) -> tuple[str | None, str | None]:
    """(target, None) for a site whose target is a regular file of at most
    INCLUDE_CAP bytes reached with no symbolic link on any step, else (None,
    finding)."""
    at = f"{rel}:{line}: {form}"
    if arg is None:
        return None, f"{at} with an argument that is not one string literal; the census cannot resolve it (#10300)"
    if len(arg.encode()) > INCLUDE_PATH_CAP:
        return None, f"{at} with an argument over {INCLUDE_PATH_CAP} bytes; the census cannot resolve it (#10300)"
    steps = include_steps(rel, arg)
    if steps is None:
        return None, f'{at} "{shown(arg)}" leaves the repository root (#10300)'
    target = steps[-1]
    named = f'{at} "{shown(arg)}" names {shown(target)}'
    st = None
    for step in steps:
        try:
            st = (root / step).lstat() if step else None
        except FileNotFoundError:
            return None, f"{named}, which is not a regular file (#10300)"
        except OSError as e:
            return None, f"{named}, which cannot be read (errno {e.errno}) (#10300)"
        if st is not None and stat.S_ISLNK(st.st_mode):
            return None, f"{named}, a symbolic link or a path through one; the census never follows links (#10300)"
    if st is None or not stat.S_ISREG(st.st_mode):
        return None, f"{named}, which is not a regular file (#10300)"
    if st.st_size > INCLUDE_CAP:
        return None, f"{named}, a file over {INCLUDE_CAP} bytes; the census does not read it (#10300)"
    return target, None


def read_target(root: pathlib.Path, target: str) -> bytes:
    """The bytes of a target found by `include_target`: opened with no link
    followed, at most INCLUDE_CAP bytes read, and refused when the file opened
    is not the file looked up (the Rust census does the same); ValueError with
    the finding otherwise."""
    try:
        st = (root / target).lstat()
        fd = open_in_root(root, target, os.O_RDONLY)
    except OSError as e:
        raise ValueError(f"{target}: cannot be read (errno {e.errno}) (#10300)") from e
    with os.fdopen(fd, "rb") as f:
        m = os.fstat(f.fileno())
        if (m.st_dev, m.st_ino) != (st.st_dev, st.st_ino) or not stat.S_ISREG(m.st_mode):
            raise ValueError(f"{target}: changed while the census read it; the census never follows links (#10300)")
        data = f.read(INCLUDE_CAP + 1)
    if len(data) > INCLUDE_CAP:
        raise ValueError(f"{target}: grew over {INCLUDE_CAP} bytes while the census read it (#10300)")
    return data


def join_includes(root: pathlib.Path, lexed: list[tuple[str, list[Tok]]]) -> tuple[
        list[tuple[str, int, str, str]], list[str]]:
    """Follow every include site of `lexed`, appending each target not yet lexed
    (a visited set bounds cycles and the cost; each appended target's own sites
    follow the same rule). Returns every site as (file, line, form, target) and
    the findings."""
    seen = {rel for rel, _t in lexed}
    sites: list[tuple[str, int, str, str]] = []
    errors: list[str] = []
    i = 0
    while i < len(lexed):
        rel, t = lexed[i]
        i += 1
        for _k, form, line, arg in include_sites(t, brackets(t)):
            target, bad = include_target(root, rel, form, line, arg)
            if target is None:
                errors.append(bad)
                continue
            sites.append((rel, line, form, target))
            if target not in seen:
                seen.add(target)
                try:
                    text = read_target(root, target).decode("utf-8")
                except UnicodeDecodeError as e:
                    errors.append(f"{target}: not UTF-8 ({e.reason}); the census cannot read it (#10176)")
                    continue
                except ValueError as e:
                    errors.append(str(e))
                    continue
                lexed.append((target, lex(text)))
    return sites, errors


def start_files(census: str) -> set[str]:
    b = census.index("START_ROWS_BEGIN")
    e = census.index("START_ROWS_END")
    return {m.group(1) for m in re.finditer(r'"([^"]+)",\s*\d+', census[b:e])}


HEADER = '''// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10176 round 3: the token, shape and environment-name tables of the
//! process-start census (`tests/process_start_census_10176.rs`), one row per
//! file with its exact count and its reason. Written by
//! `scripts/ci/census_rows_10286.py --write` (#10290); `--check` is red when
//! this file differs from a fresh scan. A change of any count is red until
//! its row changes with it.

/// Starts a process at the sites its `START_ROWS` row counts; part B checks each
/// one is covered by an expect.
pub(crate) const R_TOK_START: &str =
    "starts a process only at the sites of its START_ROWS row, each covered by an expect";
/// Names a process type, id or module and starts nothing.
pub(crate) const R_TOK_NAME: &str =
    "names a process type, id, exit status or the CLI Command enum and starts nothing";
/// Names libc or nix for a call that is not a start.
pub(crate) const R_TOK_LIBC: &str =
    "names libc or nix for calls that start nothing; a libc start name is refused by part B";
/// Uses proptest's config or strategies; part A1 holds its blocks guarded.
#[rustfmt::skip]
pub(crate) const R_TOK_PROPTEST: &str =
    "uses proptest's config or strategies; every proptest! block it holds opens with proptest_guarded";
/// Names a local, a field or a parameter `prop`, not the proptest module.
pub(crate) const R_TOK_PROP_NAME: &str =
    "names a local, a field or a parameter prop, which is not the proptest prop module";
/// An impl or impl-Trait parameter whose header names a process type.
pub(crate) const R_SHAPE_IMPL: &str =
    "an impl or impl-Trait parameter over Command or Stdio; it starts nothing beyond START_ROWS";
/// The extern blocks of the macOS ACL functions.
pub(crate) const R_SHAPE_EXTERN: &str =
    "extern blocks of the macOS acl_* functions, which read an ACL and start nothing";
/// A glob import of the proptest prelude.
pub(crate) const R_SHAPE_GLOB: &str =
    "imports the proptest prelude by glob for strategies used inside guarded blocks";
/// The libc pin macro of the spawn-gate test.
pub(crate) const R_SHAPE_METAVAR: &str =
    "the spawn-gate pin macro names libc::$name to prove each start name stays disallowed";
/// The paste crate's own tests, vendored and never built by this workspace.
pub(crate) const R_SHAPE_PASTE: &str =
    "the vendored paste crate's own tests of [< >] pasting; the workspace never builds them";
/// An environment name that is a parameter or a built string.
#[rustfmt::skip]
pub(crate) const R_ENV_NAME: &str =
    "an environment name passed as a parameter or built at run time, a constant not bound to one string literal (#10299), or a local named like an environment function; none is a proptest variable";
'''

SITES_HEADER = '''// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10286: the site pins of the process-start census, one row per file with
//! the ordered digests of its watched sites (see the module doc of
//! `tests/common/census_pins_10286.rs`). Written by
//! `scripts/ci/census_rows_10286.py --write`; `--check` is red when this file
//! differs from a fresh scan.

/// Every file with a watched site, with its ordered site digests.
#[rustfmt::skip]
pub(crate) const SITE_ROWS: &[(&str, &[&str])] = &[
'''


# #10311: the reasons are the R_ constants of HEADER; a table's rows keep one of
# the constants with that table's prefix. `--write` never assigns a reason: it
# keeps the committed one and refuses a scanned file that has no committed row.
REASONS = frozenset(re.findall(r"^pub\(crate\) const (R_[A-Z_]+): &str =$", HEADER, re.M))
TABLES = (
    ("TOKEN_ROWS", "R_TOK_", "watched process, libc, nix or proptest tokens"),
    ("SHAPE_ROWS", "R_SHAPE_", "forms the census does not model"),
    ("ENV_NAME_ROWS", "R_ENV_", "environment names that are not one string literal or one named constant"),
)
TABLE_OPEN_RE = re.compile(r"pub\(crate\) const ([A-Z_]+): &\[\(&str, usize, &str\)\] = &\[")
ROW_RE = re.compile(r'    \("([^"\\]+)", (\d+), ([A-Za-z_][A-Za-z0-9_]*)\),')
TABLE_CLOSE = "];"
NO_ROW = ("{rel}: {n} {what}, and {table} has no committed row for it; --write never adds a row or a reason, so "
          "add the row by hand with a reason that is true for the file (#10311)")


class NoCommittedRow(Exception):
    """#10311: scanned files with no committed row, one refusal line each."""

    def __init__(self, lines: list[str]) -> None:
        super().__init__("\n".join(lines))
        self.lines = lines


def parse_rows(text: str) -> dict[str, dict[str, str]]:
    """The committed reason of every row of the three tables, read row by row;
    ValueError naming the rows file and the line otherwise (#10311)."""
    prefixes = {name: prefix for name, prefix, _what in TABLES}
    out: dict[str, dict[str, str]] = {}
    current: str | None = None
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()  # the end of the file after its last newline, not a line
    for no, line in enumerate(lines, 1):
        if current is None:
            m = TABLE_OPEN_RE.fullmatch(line)
            if m is None or m.group(1) not in prefixes:
                continue
            if m.group(1) in out:
                raise ValueError(f"{ROWS_OUT}:{no}: a second {m.group(1)} table (#10311)")
            current = m.group(1)
            out[current] = {}
            continue
        if line == TABLE_CLOSE:
            current = None
            continue
        r = ROW_RE.fullmatch(line)
        if r is None:
            raise ValueError(f"{ROWS_OUT}:{no}: not a row of {current}; the committed table is read row by row "
                             "and an unread line is not clean (#10311)")
        rel, reason = r.group(1), r.group(3)
        if reason not in REASONS or not reason.startswith(prefixes[current]):
            raise ValueError(f"{ROWS_OUT}:{no}: {reason} is not a reason of {current}; a row keeps one of the "
                             f"{prefixes[current]} reasons (#10311)")
        if rel in out[current]:
            raise ValueError(f"{ROWS_OUT}:{no}: {current} holds {rel} twice (#10311)")
        out[current][rel] = reason
    if current is not None:
        raise ValueError(f"{ROWS_OUT}: {current} is not closed by `{TABLE_CLOSE}` (#10311)")
    for name, _prefix, _what in TABLES:
        if name not in out:
            raise ValueError(f"{ROWS_OUT}: holds no {name} table; the committed table is read before the scan "
                             "(#10311)")
    return out


def load_rows(root: pathlib.Path) -> dict[str, dict[str, str]]:
    """The committed rows file, opened with no link followed; an absent file is
    three empty tables, so every scanned file is refused (#10311)."""
    try:
        fd = open_in_root(root, ROWS_OUT, os.O_RDONLY)
    except OSError as e:
        if e.errno == errno.ENOENT:
            return {name: {} for name, _prefix, _what in TABLES}
        if e.errno == errno.ELOOP:
            raise ValueError(f"{ROWS_OUT}: {LINK_FINDING}") from e
        raise ValueError(f"{ROWS_OUT}: unreadable ({e.strerror or e})") from e
    try:
        with os.fdopen(fd, "rb") as f:
            data = f.read()
    except OSError as e:
        raise ValueError(f"{ROWS_OUT}: unreadable ({e.strerror or e})") from e
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"{ROWS_OUT}: not UTF-8 ({e.reason}); the census cannot read it (#10176)") from e
    return parse_rows(text)


def table(name: str, doc: str, items: dict[str, int], reason: dict[str, str]) -> str:
    out = [doc, "#[rustfmt::skip]", f"pub(crate) const {name}: &[(&str, usize, &str)] = &["]
    for rel, n in sorted(items.items()):
        out.append(f'    ("{rel}", {n}, {reason[rel]}),')
    out.append("];")
    return "\n".join(out)


def scan(root: pathlib.Path) -> tuple[str, str, dict[str, int]]:
    """The two generated files' text and a few totals. The committed rows file is
    read first and every reason comes from it; NoCommittedRow when a scanned file
    has no committed row (#10311)."""
    committed = load_rows(root)
    # The census must hold its START_ROWS block (#10290); no reason is drawn from it (#10311).
    start_files(read_scanned(root, CENSUS).decode("utf-8"))
    walk_errors: list[str] = []
    config_errors = [f for rel, data in tree_configs(root, walk_errors) for f in config_findings(rel, data)]
    lexed = [(rel, lex(text)) for rel, text in tree_rs(root, walk_errors)]
    walk_errors = sorted(set(walk_errors))
    if config_errors:
        raise ValueError("\n".join(config_errors + walk_errors))
    include_sites_all, include_errors = join_includes(root, lexed)
    if walk_errors or include_errors:
        raise ValueError("\n".join(walk_errors + include_errors))
    prepared = prepare(lexed)
    graph = RenameGraph(prepared)
    watched = graph.reach(WATCHED_SEED)
    env_mod = graph.reach(ENV_MOD_SEED)
    env_fns = graph.reach(ENV_FN_SEED)
    env_names = env_mod | env_fns
    consts = const_names([t for _rel, t in lexed])
    env = env_counts(prepared, env_fns, consts)
    tok: dict[str, int] = {}
    shape: dict[str, int] = {}
    sites: dict[str, list[str]] = {}
    for rel, t in lexed:
        n_tok = sum(1 for x in t if x.kind == IDENT and x.text in watched)
        if n_tok:
            tok[rel] = n_tok
        try:
            s = shapes_of(t, watched)
        except ValueError as e:
            raise ValueError(f"{rel}: {e}") from e
        if s:
            shape[rel] = len(s)
        try:
            pins = sites_of(t, watched, env_names, env_fns, consts)
        except ValueError as e:
            raise ValueError(f"{rel}: {e}") from e
        if pins:
            sites[rel] = pins
    scanned = {"TOKEN_ROWS": tok, "SHAPE_ROWS": shape, "ENV_NAME_ROWS": env}
    missing = [NO_ROW.format(rel=rel, n=n, what=what, table=name)
               for name, _prefix, what in TABLES
               for rel, n in sorted(scanned[name].items()) if rel not in committed[name]]
    if missing:
        raise NoCommittedRow(missing)
    rows = "\n\n".join([
        table("TOKEN_ROWS", "/// Every file that holds a watched process, libc, nix or proptest token, with the count.",
              tok, committed["TOKEN_ROWS"]),
        table("SHAPE_ROWS", "/// Every file that holds a form the census does not model, with the count.",
              shape, committed["SHAPE_ROWS"]),
        table("ENV_NAME_ROWS",
              "/// Every file that names an environment variable by anything but one literal or constant.",
              env, committed["ENV_NAME_ROWS"]),
    ])
    site_lines = [SITES_HEADER.rstrip("\n")]
    for rel in sorted(sites):
        site_lines.append(f'    ("{rel}", &[')
        site_lines.extend(f'        "{d}",' for d in sites[rel])
        site_lines.append("    ]),")
    site_lines.append("];")
    totals = {
        "token_files": len(tok), "tokens": sum(tok.values()), "shape_files": len(shape),
        "env_files": len(env), "env_sites": sum(env.values()), "site_files": len(sites),
        "sites": sum(len(v) for v in sites.values()),
        "include_sites": len(include_sites_all),
        "include_files": len({s[0] for s in include_sites_all}),
    }
    return HEADER + "\n" + rows + "\n", "\n".join(site_lines) + "\n", totals


def first_diff(a: str, b: str) -> str:
    al, bl = a.splitlines(), b.splitlines()
    for i, (x, y) in enumerate(zip(al, bl), 1):
        if x != y:
            return f"line {i}: committed {x.strip()!r}, scan {y.strip()!r}"
    return f"line {min(len(al), len(bl)) + 1}: committed has {len(al)} lines, scan has {len(bl)}"


def write_table(root: pathlib.Path, rel: str, text: str) -> None:
    """Write one generated table, opened by `open_in_root`: the walk from the
    root fd is the in-root decision and the open in one act, so no write goes
    through a link in any component or lands outside the root (#10345);
    ValueError naming the path otherwise."""
    try:
        fd = open_in_root(root, rel, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise ValueError(f"{rel}: {LINK_FINDING}") from e
        raise ValueError(f"{rel}: not writable ({e.strerror or e})") from e


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="write both tables from a fresh scan")
    mode.add_argument("--check", action="store_true", help="exit 1 when a committed table differs")
    ap.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[2])
    ap.add_argument("--stats", action="store_true", help="print the scan totals")
    a = ap.parse_args(argv)
    root = a.root.resolve()
    try:
        rows, sites, totals = scan(root)
    except NoCommittedRow as e:
        for line in e.lines:
            print(f"census_rows_10286: {line}", file=sys.stderr)
        return 1
    except (OSError, UnicodeDecodeError, ValueError) as e:
        print(f"census_rows_10286: scan failed: {e}", file=sys.stderr)
        return 2
    if a.stats:
        print(" ".join(f"{k}={v}" for k, v in totals.items()))
    want = {ROWS_OUT: rows, SITES_OUT: sites}
    if a.write:
        try:
            for rel, text in want.items():
                write_table(root, rel, text)
        except ValueError as e:
            print(f"census_rows_10286: write failed: {e}", file=sys.stderr)
            return 2
        return 0
    bad = 0
    for rel, text in want.items():
        try:
            have = read_scanned(root, rel).decode("utf-8")
        except UnicodeDecodeError as e:
            print(f"census_rows_10286: {rel}: not UTF-8 ({e.reason}); the census cannot read it (#10176)",
                  file=sys.stderr)
            bad += 1
            continue
        except ValueError as e:
            print(f"census_rows_10286: {e}", file=sys.stderr)
            bad += 1
            continue
        if have != text:
            print(f"census_rows_10286: {rel} differs from a fresh scan at {first_diff(have, text)}; "
                  f"run scripts/ci/census_rows_10286.py --write and review the change", file=sys.stderr)
            bad += 1
    if bad:
        return 1
    print(f"census_rows_10286: {len(want)} tables match a fresh scan")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
