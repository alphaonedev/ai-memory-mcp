#!/usr/bin/env python3
"""Closed-world gate for #5084: no production SQLite transaction in ``src/``
may open DEFERRED.

A DEFERRED transaction that reads and then writes upgrades its lock at the
first write.  Under WAL, when another connection committed in between, that
upgrade fails immediately with SQLITE_BUSY_SNAPSHOT and ``busy_timeout`` does
not retry it (the #2250 class).  ``BEGIN IMMEDIATE`` takes the write lock at
BEGIN, where contention is retryable, so every production write transaction
must open IMMEDIATE (or EXCLUSIVE).  The one sanctioned entry point is
``crate::storage::connection::WriteTxn::begin``.

Rules (each has a mutant in ``--self-test``):
  R0  the source cannot be read with certainty (an unterminated string or
      comment, a ``cfg(test)`` module whose layout the indent cannot place):
      fail closed instead of guessing (#6154).
  R1  ``.transaction()`` / ``unchecked_transaction()`` open DEFERRED.
  R2  ``transaction_with_behavior`` / ``Transaction::new_unchecked`` /
      ``TransactionBehavior::Deferred`` must not name Deferred.
  R3  a raw ``BEGIN`` / ``BEGIN DEFERRED`` / ``BEGIN TRANSACTION`` SQL string
      or ``SQL_BEGIN_DEFERRED`` is DEFERRED.
  R4  ``WriteTxn::begin_deferred`` is DEFERRED (the helper no longer has it).
  R5  an allowlisted DEFERRED function must be read-only: its body may not
      contain a write statement (INSERT / UPDATE / DELETE / REPLACE / CREATE /
      DROP / ALTER).  A DEFERRED function that reads then writes, or writes
      first, is refused by R1-R4 (it is not allowlistable) and by R5.

  R6  ``.savepoint()`` / ``savepoint_with_name`` / a raw ``SAVEPOINT`` open a
      DEFERRED transaction when no transaction is open.

SQL text rules (R3 literals, R6 literals) read EVERY string literal of a SQLite
source file, in any case, in batches ("BEGIN; ...") and format strings
("BEGIN {m}"), whole (a multi-line literal is read to its closing quote, #6155),
wherever it sits: a let / const / static value, a format!/String::from
argument, a helper's return value, a match arm, a struct field, an argument of
any call.  Only a literal that is an argument of a MESSAGE SINK is skipped
(#6152, #6154): ``expect`` / ``expect_err`` / ``context`` / ``with_context``;
the macros ``panic!`` ``assert*!`` ``debug_assert*!`` ``unreachable!``
``todo!`` ``unimplemented!`` ``trace!/debug!/info!/warn!/error!``
``print!/println!/eprint!/eprintln!`` ``write!/writeln!`` ``anyhow!/bail!/ensure!``
``params!/named_params!``; and ``format!`` / ``concat!`` when it is itself an
argument of one of those.  A literal that reaches a block ``{..}``, an array
or any other call before a sink is NOT a message and stays scanned.  Source
text is lexed once per file (strings, raw strings, byte strings, char
literals, nested block comments), so a quote anywhere cannot desynchronise a
later line.  They skip the Postgres adapter files (sqlx has its own
transaction model).

Closed world: only sites in ``ALLOWLIST`` (file, enclosing fn) pass, and each
carries a written reason.  A stale allowlist entry (no matching site) also
fails, so the list cannot rot.  Test code is skipped only by cfg: ``tests/`` is
not scanned; in ``src/`` a ``#[cfg(test)]`` / ``#[cfg(all(test, ..))]`` module
block, an external ``mod x;`` under such a cfg or declared inside such a block
(``#[path]`` honoured; #6152), and a file with ``#![cfg(test)]``.  A ``mod x;``
inside such a block whose indentation does not place it inside the block (or
any other ambiguous nesting) is reported as R0 instead of resolving a guessed
path (#6154).  No file is skipped by name and no file is cut short, so
production code after a test module is scanned.

Known limit (R5): it reads SQL literals in the allowlisted fn body only; a
write through a helper call or a caller-supplied closure is not seen.

Python 3.9 stdlib only.  Exit 0 = clean, 1 = violation, 2 = usage error.
"""
import argparse
import bisect
import re
import sys
from collections import namedtuple
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (relative file, enclosing fn) -> reason.  Read-only snapshots only.
ALLOWLIST = {
    ("src/governance/policy_version.rs", "with_read_snapshot"): (
        "read-only snapshot: two reads must share one view; it never writes, "
        "so there is no lock upgrade to fail"
    ),
    ("src/cli/keys.rs", "sqlite"): (
        "preview arm only: opens read-only (open_read_only) and issues plain "
        "BEGIN for a consistent read; the delete arm is BEGIN IMMEDIATE"
    ),
}

FN = re.compile(r"\bfn\s+([A-Za-z0-9_]+)")
RULES = [
    (
        "R1",
        re.compile(
            r"\.transaction\s*\(\s*\)|unchecked_transaction\s*\(\s*\)"
            r"|::\s*(?:unchecked_)?transaction\s*\("
        ),
    ),
    (
        "R2",
        re.compile(
            r"TransactionBehavior::Deferred"
            r"|transaction_with_behavior\s*\((?![^)]*(?:Immediate|Exclusive))"
            r"|Transaction::new(?:_unchecked)?\s*\((?![^)]*(?:Immediate|Exclusive))"
            r"|\bnew_unchecked\s*\((?![^)]*(?:Immediate|Exclusive))"
        ),
    ),
    ("R3", re.compile(r"SQL_BEGIN_DEFERRED|execute(?:_batch)?\s*\(\s*&?\s*concat!\s*\(")),
    ("R4", re.compile(r"WriteTxn::begin_deferred")),
    ("R6", re.compile(r"\.savepoint\s*\(\s*\)|\bsavepoint_with_name\s*\(")),
]
# R3 / R6 on the CONTENTS of string literals (SQLite files only), every literal
# of the file (#6154): a statement that starts with BEGIN and does not name
# IMMEDIATE / EXCLUSIVE, in any case, including a batch "BEGIN; ...", a format
# string "BEGIN {mode}" and a raw string; a raw SAVEPOINT outside a transaction
# opens DEFERRED.
BEGIN_SQL = re.compile(
    r"(?:^|;)\s*BEGIN(?:\s+(?:DEFERRED|TRANSACTION))*\s*(?:;|$|\{)", re.IGNORECASE
)
SAVEPOINT_SQL = re.compile(r"(?:^|;)\s*SAVEPOINT\b", re.IGNORECASE)
LIT_RULES = [("R3", BEGIN_SQL), ("R6", SAVEPOINT_SQL)]

NONLITERAL_EXEC = re.compile(r"\.execute(?:_batch)?\s*\(\s*(?!\"|r#*\"|if\b)\S")
WRITE_SQL = re.compile(r"\b(?:INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b", re.IGNORECASE)
# A test-only cfg: cfg(test) or cfg(all(test, ...)).  cfg(any(test, ...)) also
# compiles outside tests, so it is production code and is scanned.
TEST_CFG = re.compile(r"#\[cfg\(\s*(?:test|all\(\s*test\b[^\]]*)\s*\)\]")
MOD_DECL = re.compile(r"^\s*(?:pub(?:\([a-z]+\))?\s+)?mod\s+(\w+)\s*([;{])")
PATH_ATTR = re.compile(r'#\[path\s*=\s*"([^"]+)"\]')

# --- message sinks (#6152, #6154) -------------------------------------------
# A string literal is NOT scanned for SQL only when it is an argument of one of
# these: it is a message or a bound value, never a statement.  Everything else
# (let / const / static values, format!/String::from, helper returns, match
# arms, struct fields, arrays, closures, any other call) stays scanned.
SINK_METHODS = frozenset({"expect", "expect_err", "context", "with_context"})
SINK_MACROS = frozenset(
    {
        "panic", "assert", "assert_eq", "assert_ne", "debug_assert",
        "debug_assert_eq", "debug_assert_ne", "unreachable", "todo",
        "unimplemented", "trace", "debug", "info", "warn", "error", "print",
        "println", "eprint", "eprintln", "write", "writeln", "anyhow", "bail",
        "ensure", "params", "named_params",
    }
)
# format! / concat! only pass a literal on to whatever contains them.
WRAP_MACROS = frozenset({"format", "format_args", "concat"})
_CLOSERS = {")": "(", "]": "[", "}": "{"}
_MACRO_BEFORE = re.compile(r"([A-Za-z_]\w*)\s*!$")
_IDENT_BEFORE = re.compile(r"([A-Za-z_]\w*)$")


def _opener(masked, k, bracket):
    """Verdict for the innermost enclosing bracket ``masked[k]``: True when it
    is a message sink, False when the literal must be scanned, None when the
    walk continues outward (a grouping paren, a tuple, a format!/concat!)."""
    head = masked[max(0, k - 200) : k].rstrip()
    macro = _MACRO_BEFORE.search(head)
    if macro:
        name = macro.group(1)
        if name in SINK_MACROS:
            return True
        return None if name in WRAP_MACROS and bracket == "(" else False
    if bracket != "(":
        return False  # a block, struct body, array or index is a wall
    ident = _IDENT_BEFORE.search(head)
    if ident:
        name = ident.group(1)
        return name in SINK_METHODS and re.search(r"\.\s*" + name + r"$", head) is not None
    if head and head[-1] in ")]}>":
        return False  # a call on a computed value: unknown, scan
    return None  # grouping / tuple paren


def message_sink(masked, pos):
    """True when the literal that starts at ``masked[pos]`` is an argument of a
    message sink.  Walk the enclosing brackets outwards; fail closed (False,
    meaning "scan it") on a statement boundary, an unknown call or a mismatch."""
    stack, k = [], pos - 1
    while k >= 0:
        c = masked[k]
        if c in _CLOSERS:
            stack.append(_CLOSERS[c])
        elif c in "([{":
            if stack:
                if stack.pop() != c:
                    return False
            else:
                verdict = _opener(masked, k, c)
                if verdict is not None:
                    return verdict
        elif c == ";" and not stack:
            return False
        k -= 1
    return False


# --- lexer (#6154): one whole-file pass ---------------------------------------
# Comments, string literals (plain, raw r#".."#, byte, c-string) and char
# literals are lexed once per file, so a quote anywhere cannot desynchronise a
# later line (the old 3-line window could).  ``masked`` is the source with
# comments and char literals blanked and string bodies blanked (quotes kept),
# same length and same newlines; ``lits`` holds every string literal whole.
Lit = namedtuple("Lit", "line pos body raw")
CHAR_LIT = re.compile(r"'(?:[^'\\\n]|\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|[^xu\n]))'")
_RAW_START = r'(?<![A-Za-z0-9_])(?:br|cr|r)(#*)"'
_BLOCK = re.compile(r"/\*|\*/")
_STR_END = re.compile(r'\\.|"', re.S)
_ESC = re.compile(r"\\(\r?\n[ \t\r\n]*|[nrt0\\\"']|x[0-9A-Fa-f]{2})")
_SIMPLE_ESC = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", '"': '"', "'": "'"}


def _build_token(raw=True):
    parts = [r"//[^\n]*", r"/\*"] + ([_RAW_START] if raw else []) + ['"', "'"]
    return re.compile("|".join("(?:%s)" % p for p in parts))


TOKEN = _build_token()


def _blank(s):
    return re.sub(r"[^\n]", " ", s)


def _blank_lit(s):
    return re.sub(r"[^\n]", " ", s)


def unescape(body):
    """The text a plain string literal denotes, for the escapes that matter to
    SQL: ``\\n`` ``\\t`` ``\\"`` and a line-continuation backslash."""

    def rep(m):
        g = m.group(1)
        if g[0] in "\r\n":
            return ""
        if g[0] == "x":
            return chr(int(g[1:], 16))
        return _SIMPLE_ESC[g]

    return _ESC.sub(rep, body)


def lex(text):
    """(masked, literals, problems) for one source text."""
    starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_of(off):
        return bisect.bisect_right(starts, off)

    out, lits, problems = [], [], []
    pos = last = 0
    while True:
        m = TOKEN.search(text, pos)
        if not m:
            break
        t, s = m.group(0), m.start()
        if t.startswith("//"):
            out += [text[last:s], _blank(t)]
            pos = last = m.end()
        elif t == "/*":
            depth, e = 1, m.end()
            while depth:
                b = _BLOCK.search(text, e)
                if not b:
                    problems.append((line_of(s), "unterminated block comment: fail closed"))
                    e = len(text)
                    break
                depth += 1 if b.group(0) == "/*" else -1
                e = b.end()
            out += [text[last:s], _blank(text[s:e])]
            pos = last = e
        elif t == "'":
            c = CHAR_LIT.match(text, s)
            if c:
                out += [text[last:s], _blank_lit(c.group(0))]
                pos = last = c.end()
            else:
                pos = m.end()  # a lifetime or loop label
        else:
            raw = t != '"'
            body_start = m.end()
            if raw:
                close = '"' + "#" * t.count("#")
                j = text.find(close, body_start)
                body_end, end = (j, j + len(close)) if j >= 0 else (len(text), len(text))
                closed = j >= 0
            else:
                close, e, closed = '"', body_start, False
                while True:
                    q = _STR_END.search(text, e)
                    if not q:
                        break
                    e = q.end()
                    if q.group(0) == '"':
                        closed = True
                        break
                body_end, end = (e - 1, e) if closed else (len(text), len(text))
            if not closed:
                problems.append((line_of(s), "unterminated string literal: fail closed"))
            body = text[body_start:body_end]
            out += [text[last:body_start], _blank_lit(body), close if closed else ""]
            lits.append(Lit(line_of(s), s, body, raw))
            pos = last = end
    out.append(text[last:])
    return "".join(out), lits, problems


class Src:
    """One lexed source file."""

    def __init__(self, text):
        self.text = text
        self.masked, self.lits, self.problems = lex(text)
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]
        trim = 1 if text.endswith("\n") else 0
        self.raw = text.split("\n")[: len(self.starts) - trim]
        self.lines = self.masked.split("\n")[: len(self.starts) - trim]

    def line_of(self, off):
        return bisect.bisect_right(self.starts, off)

    def fn_names(self):
        """Enclosing fn name per line (masked, so a comment cannot name one)."""
        cur, out = "?", []
        for code in self.lines:
            m = FN.search(code)
            if m:
                cur = m.group(1)
            out.append(cur)
        return out


# --- cfg(test) regions ------------------------------------------------------
def _child_dir(rel):
    """Directory that holds the child modules of the file ``rel``."""
    p = Path(rel)
    if p.name in ("mod.rs", "lib.rs", "main.rs"):
        return p.parent
    return p.parent / p.stem


def block_balanced(lines, j, k):
    """True when the braces of ``lines[j..k]`` balance, i.e. the closing brace
    found by indent really closes the module opened on line ``j``."""
    return sum(l.count("{") for l in lines[j : k + 1]) == sum(l.count("}") for l in lines[j : k + 1])


def mod_inside(stack):
    """True when the indent of a ``mod x;`` places it inside the test block."""
    return bool(stack)


def _nested_ext(rel, lines, raw, j, k, name):
    """(external files, problems) of ``mod x;`` declared inside the cfg(test)
    block ``lines[j..k]`` (#6152).  A module nested in ``mod a { mod b; }`` lives
    at ``<child dir of rel>/a/b.rs`` or ``.../a/b/mod.rs``; ``#[path]`` is
    relative to that directory.  Blocks are tracked by rustfmt indent; a layout
    the indent cannot place with certainty is a problem, never a guessed path
    (#6154)."""
    found, problems = set(), []
    if not block_balanced(lines, j, k):
        problems.append(
            (
                j + 1,
                "cfg(test) module `%s`: braces do not balance at the indent of its "
                "closing brace, nesting is ambiguous: fail closed" % name,
            )
        )
        return found, problems
    stack = [(len(lines[j]) - len(lines[j].lstrip(" ")), name)]
    for idx in range(j + 1, k + 1):
        line = lines[idx]
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        while stack and indent <= stack[-1][0]:
            stack.pop()
        m = MOD_DECL.match(line)
        if not m:
            continue
        if m.group(2) == "{":
            if line.count("{") != line.count("}"):
                stack.append((indent, m.group(1)))
            continue
        if not mod_inside(stack):
            problems.append(
                (
                    idx + 1,
                    "`mod %s;` sits inside the braces of cfg(test) module `%s` but its "
                    "indentation places it outside: ambiguous layout, fail closed"
                    % (m.group(1), name),
                )
            )
            continue
        base = _child_dir(rel).joinpath(*[n for _, n in stack])
        path_attr = None
        back = idx - 1
        while back > j and lines[back].lstrip().startswith("#["):
            pm = PATH_ATTR.search(raw[back])
            if pm:
                path_attr = pm.group(1)
            back -= 1
        if path_attr:
            found.add((base / path_attr).as_posix())
        else:
            found.add((base / (m.group(1) + ".rs")).as_posix())
            found.add((base / m.group(1) / "mod.rs").as_posix())
    return found, problems


def test_regions(rel, lines, raw):
    """(skip_line_numbers, external_test_files, problems) for one file, from
    its masked ``lines`` (``raw`` supplies ``#[path]`` values).

    A test-only cfg attribute (possibly followed by other attributes) applied
    to ``mod x { ... }`` skips that block up to its closing brace at the same
    indent (rustfmt layout); applied to ``mod x;`` it marks the external file.
    A file-level ``#![cfg(test)]`` skips the whole file.  Layout the indent
    cannot resolve is reported in ``problems`` (R0).
    """
    skip, ext, problems = set(), set(), []
    if any(re.match(r"#!\[cfg\(\s*test\s*\)\]", l.strip()) for l in lines[:40]):
        return set(range(1, len(lines) + 1)), ext, problems
    i = 0
    while i < len(lines):
        if not TEST_CFG.search(lines[i]):
            i += 1
            continue
        j, path_attr = i + 1, None
        while j < len(lines) and lines[j].lstrip().startswith("#["):
            m = PATH_ATTR.search(raw[j])
            if m:
                path_attr = m.group(1)
            j += 1
        m = MOD_DECL.match(lines[j]) if j < len(lines) else None
        if not m:
            i += 1
            continue
        name, kind = m.group(1), m.group(2)
        if kind == ";":
            base = Path(rel).parent if path_attr else _child_dir(rel)
            if path_attr:
                ext.add((base / path_attr).as_posix())
            else:
                ext.add((base / (name + ".rs")).as_posix())
                ext.add((base / name / "mod.rs").as_posix())
            i = j + 1
            continue
        indent = len(lines[j]) - len(lines[j].lstrip(" "))
        k = j
        closed = lines[j].count("{") == lines[j].count("}")  # one-line ``mod x { .. }``
        while not closed and k < len(lines):
            skip.add(k + 1)
            if k > j and lines[k].rstrip() == " " * indent + "}":
                closed = True
                break
            k += 1
        skip.add(j + 1)
        if closed and k > j:
            e, p = _nested_ext(rel, lines, raw, j, k, name)
            ext |= e
            problems += p
        if not closed:
            # Fail closed: never swallow the rest of the file silently.
            problems.append((j + 1, "unterminated cfg(test) module: fail closed"))
        for a in range(i, j):
            skip.add(a + 1)
        i = max(k, j) + 1
    return skip, ext, problems


def scan(files, srcs=None):
    """files: {rel_path: text}.  Returns sorted [(rel, line, fn, rule, text)].

    No file is skipped by name and no file is cut short: only test-only cfg
    regions and test-only external modules are skipped.  Every string literal
    of a SQLite file is read, whole, unless it is a message-sink argument.
    """
    if srcs is None:
        srcs = {rel: Src(text) for rel, text in files.items()}
    regions, ext, hits = {}, set(), []
    for rel, src in srcs.items():
        sk, ex, bad = test_regions(rel, src.lines, src.raw)
        regions[rel] = sk
        ext |= ex
        for n, msg in sorted(bad + src.problems):
            hits.append((rel, n, "?", "R0", msg))
    for rel in sorted(srcs):
        if rel in ext:
            continue
        src, skip = srcs[rel], regions[rel]
        fns = src.fn_names()
        cands = {}  # line -> (priority, rule); one hit per line, rule order wins

        def note(n, prio, rule):
            if n not in skip and (n not in cands or prio < cands[n][0]):
                cands[n] = (prio, rule)

        for prio, (rule, rx) in enumerate(RULES):
            for mm in rx.finditer(src.masked):
                note(src.line_of(mm.start()), prio, rule)
        # SQL-text rules (R3 literal, R6 literal) apply to SQLite code only;
        # the Postgres adapter (sqlx) has its own transaction model.
        if "postgres" not in rel:
            for lit in src.lits:
                if lit.line in skip or message_sink(src.masked, lit.pos):
                    continue
                body = lit.body if lit.raw else unescape(lit.body)
                for off, (rule, rx) in enumerate(LIT_RULES):
                    if rx.search(body):
                        note(lit.line, len(RULES) + off, rule)
                        break
        for n in sorted(cands):
            hits.append((rel, n, fns[n - 1], cands[n][1], src.raw[n - 1].strip()))
    return sorted(hits, key=lambda h: (h[0], h[1], h[3]))


def fn_span(lines, name):
    """(first, last) line indexes of ``fn name`` up to its closing brace at the
    same indent, or None."""
    for i, code in enumerate(lines):
        if not re.search(r"\bfn\s+" + re.escape(name) + r"\b", code):
            continue
        if "{" in code and code.count("{") == code.count("}"):
            return i, i
        indent = len(code) - len(code.lstrip(" "))
        for j in range(i + 1, len(lines)):
            if lines[j].rstrip() == " " * indent + "}":
                return i, j
        return i, len(lines) - 1
    return None


def evaluate(files, allowlist):
    srcs = {rel: Src(text) for rel, text in files.items()}
    hits = scan(files, srcs)
    used, bad = set(), []
    for rel, n, fn, rule, text in hits:
        key = (rel, fn)
        if key in allowlist:
            used.add(key)
        else:
            bad.append((rel, n, fn, rule, text))
    for rel, fn in sorted(used):
        src = srcs[rel]
        defs = [l for l in src.lines if re.search(r"\bfn\s+" + re.escape(fn) + r"\b", l)]
        if len(defs) != 1:
            bad.append((rel, 0, fn, "R5", "allowlisted fn name defined %d times in file" % len(defs)))
        span = fn_span(src.lines, fn)
        if span is None:
            continue
        a, b = span
        rows = set()
        for idx in range(a, b + 1):
            # SQL passed by name (a const or variable) cannot be proven read-only.
            if NONLITERAL_EXEC.search(src.lines[idx]):
                rows.add(idx + 1)
        for lit in src.lits:
            if a + 1 <= lit.line <= b + 1:
                body = lit.body if lit.raw else unescape(lit.body)
                if WRITE_SQL.search(body):
                    rows.add(lit.line)
        for n in sorted(rows):
            bad.append((rel, 0, fn, "R5", src.raw[n - 1].strip()))
    stale = sorted(k for k in allowlist if k not in used)
    return bad, stale, len(hits)


def load_tree(root):
    files = {}
    for p in sorted((root / "src").rglob("*.rs")):
        files[p.relative_to(root).as_posix()] = p.read_text(encoding="utf-8")
    return files


def _probes():
    """Run every red/green probe against the current engine.

    Returns (failures, counts)."""
    allow = {("src/ok.rs", "ro"): "probe"}

    def run(text, name="src/x.rs"):
        return evaluate({name: text}, allow)

    failures, counts = [], {"green": 0, "red": 0, "mutant": 0}

    def expect(label, cond):
        counts[label.split(":", 1)[0]] = counts.get(label.split(":", 1)[0], 0) + 1
        if not cond:
            failures.append(label)

    green = {
        "WriteTxn::begin": "fn f(c: &Connection) {\n let t = WriteTxn::begin(c)?;\n}\n",
        "immediate behavior": (
            "fn f(c: &Connection) {\n"
            " let t = Transaction::new_unchecked(c, TransactionBehavior::Immediate)?;\n}\n"
        ),
        "begin immediate sql": 'fn f(c: &Connection) {\n c.execute_batch("BEGIN IMMEDIATE")?;\n}\n',
        "exclusive behavior": (
            "fn f(c: &Connection) {\n"
            " let t = c.transaction_with_behavior(TransactionBehavior::Exclusive)?;\n}\n"
        ),
        "comment mention": "fn f() {\n // unchecked_transaction() was DEFERRED\n}\n",
        "string text": 'fn f() {\n let _ = "see BEGIN IMMEDIATE docs";\n}\n',
        "cfg(test) module": (
            "fn f() {}\n#[cfg(test)]\nmod tests {\n fn t(c: &Connection) { c.unchecked_transaction(); }\n}\n"
        ),
    }
    for label, text in green.items():
        bad, stale, _ = run(text)
        expect("green:" + label, not bad)
    bad, stale, _ = evaluate(
        {"src/ok.rs": "fn ro(c: &Connection) {\n let t = c.unchecked_transaction()?;\n}\n"}, allow
    )
    expect("green:allowlisted", not bad and not stale)
    files = {
        "src/a.rs": "#[cfg(test)]\nmod hidden;\nfn real() {}\n",
        "src/a/hidden.rs": "fn t(c: &Connection) { c.unchecked_transaction(); }\n",
        "src/m/mod.rs": "#[cfg(all(test, feature = \"sal\"))]\n#[path = \"x_tests.rs\"]\nmod x;\n",
        "src/m/x_tests.rs": "fn t(c: &Connection) { c.unchecked_transaction(); }\n",
        "src/whole.rs": "#![cfg(test)]\nfn t(c: &Connection) { c.unchecked_transaction(); }\n",
    }
    bad, _, _ = evaluate(files, {})
    expect("green:cfg(test) external mod / path attr / file-level cfg skipped", not bad)

    red = {
        "R1 transaction()": ("R1", "fn f(c: &mut Connection) {\n let t = c.transaction()?;\n}\n"),
        "R1 unchecked": ("R1", "fn f(c: &Connection) {\n let t = c.unchecked_transaction()?;\n}\n"),
        "R2 Deferred": (
            "R2",
            "fn f(c: &mut Connection) {\n"
            " let t = c.transaction_with_behavior(TransactionBehavior::Deferred)?;\n}\n",
        ),
        "R2 new_unchecked default": (
            "R2",
            "fn f(c: &Connection) {\n let t = Transaction::new_unchecked(c, behavior)?;\n}\n",
        ),
        "R3 BEGIN": ("R3", 'fn f(c: &Connection) {\n c.execute_batch("BEGIN")?;\n}\n'),
        "R3 BEGIN DEFERRED": ("R3", 'fn f(c: &Connection) {\n c.execute_batch("BEGIN DEFERRED;")?;\n}\n'),
        "R3 const": ("R3", "fn f(c: &Connection) {\n c.execute_batch(SQL_BEGIN_DEFERRED)?;\n}\n"),
        "R3 conditional": (
            "R3",
            'fn f(c: &Connection, d: bool) {\n c.execute_batch(if d { "BEGIN IMMEDIATE" } else { "BEGIN" })?;\n}\n',
        ),
        "R4 begin_deferred": ("R4", "fn f(c: &Connection) {\n let t = WriteTxn::begin_deferred(c)?;\n}\n"),
        "R2 Transaction::new var": ("R2", "fn f(c: &mut Connection) {\n let t = Transaction::new(c, b)?;\n}\n"),
        "R3 lowercase begin": ("R3", 'fn f(c: &Connection) {\n c.execute_batch("begin;")?;\n}\n'),
        "R3 batch": ("R3", 'fn f(c: &Connection) {\n c.execute_batch("BEGIN; UPDATE t SET a = 1; COMMIT;")?;\n}\n'),
        "R3 format": ("R3", 'fn f(c: &Connection) {\n c.execute_batch(&format!("BEGIN {m}"))?;\n}\n'),
        "R1 UFCS": ("R1", "fn f(c: &Connection) {\n let t = rusqlite::Connection::unchecked_transaction(c)?;\n}\n"),
        "R1 split line": ("R1", "fn f(c: &Connection) {\n let t = c\n .unchecked_transaction(\n )?;\n}\n"),
        "R1 after raw string with //": (
            "R1",
            'fn f(c: &Connection) {\n let s = r#"a"b//"#; let t = c.unchecked_transaction()?;\n}\n',
        ),
        "R3 concat": ("R3", 'fn f(c: &Connection) {\n c.execute_batch(concat!("BEG", "IN"))?;\n}\n'),
        "R6 savepoint": ("R6", "fn f(c: &mut Connection) {\n let s = c.savepoint()?;\n}\n"),
        "R6 SAVEPOINT sql": ("R6", 'fn f(c: &Connection) {\n c.execute_batch("SAVEPOINT sp")?;\n}\n'),
    }
    # no file is skipped by name, and code after a test module is scanned
    bad, _, _ = run("fn f(c: &Connection) {\n c.unchecked_transaction();\n}\n", "src/model_attest.rs")
    expect("red:file named *test* is scanned", len(bad) == 1)
    text = (
        "#[cfg(test)]\nmod tests {\n    fn t(c: &Connection) { c.unchecked_transaction(); }\n}\n"
        "fn after(c: &Connection) {\n c.unchecked_transaction();\n}\n"
    )
    bad, _, _ = run(text)
    expect("red:code after a test module is scanned", [b[2] for b in bad] == ["after"])
    # #5754: in a non-mod.rs file `#[cfg(test)] mod x;` is src/<stem>/x.rs,
    # so a same-named production sibling src/x.rs is still scanned.
    bad = scan(
        {
            "src/foo.rs": "#[cfg(test)]\nmod bar;\npub fn x() {}\n",
            "src/bar.rs": "fn prod(c: &Connection) {\n c.unchecked_transaction();\n}\n",
            "src/foo/bar.rs": "fn t(c: &Connection) {\n c.unchecked_transaction();\n}\n",
        }
    )
    expect("red:non-mod.rs child module resolves to <stem>/x.rs", [h[0] for h in bad] == ["src/bar.rs"])
    bad = scan({"src/mod.rs": "#[cfg(test)]\nmod bar;\n", "src/bar.rs": "fn t(c: &Connection) {\n c.unchecked_transaction();\n}\n"})
    expect("green:mod.rs child module is the external test file", not bad)
    bad = scan({"src/a.rs": "#[cfg(test)]\nmod tests;\n\nfn p(c: &Connection) {\n c.unchecked_transaction();\n}\n"})
    expect("red:code after a bare mod tests; is scanned", [h[2] for h in bad] == ["p"])
    # R5 reads write keywords in any case
    for kw in ("insert into t values (1)", "Update t set a = 1", "delete from t"):
        text = 'fn ro(c: &Connection) {\n let t = c.unchecked_transaction()?;\n c.execute("%s", [])?;\n}\n' % kw
        bad, _, _ = evaluate({"src/ok.rs": text}, allow)
        expect("red:R5 lowercase write " + kw.split()[0], [b[3] for b in bad] == ["R5"])
    # R5: a second fn with the allowlisted name, and SQL passed by name, fail
    text = "fn ro(c: &Connection) {\n let t = c.unchecked_transaction()?;\n}\nmod m {\n fn ro() {}\n}\n"
    bad, _, _ = evaluate({"src/ok.rs": text}, allow)
    expect("red:R5 allowlisted name defined twice", [b[3] for b in bad] == ["R5"])
    text = "fn ro(c: &Connection) {\n let t = c.unchecked_transaction()?;\n t.execute(SQL_X, [])?;\n}\n"
    bad, _, _ = evaluate({"src/ok.rs": text}, allow)
    expect("red:R5 SQL by name", [b[3] for b in bad] == ["R5"])
    # a comment cannot name the enclosing fn (allowlist spoof)
    text = "fn ro(c: &Connection) {}\nfn w(c: &Connection) {\n // like fn ro\n c.unchecked_transaction();\n}\n"
    bad, _, _ = evaluate({"src/ok.rs": text}, allow)
    expect("red:comment cannot spoof allowlisted fn", [b[2] for b in bad] == ["w"])
    for label, (rule, text) in red.items():
        bad, _, _ = run(text)
        expect("red:" + label, len(bad) == 1 and bad[0][3] == rule)
    # R5: an allowlisted DEFERRED function that writes is refused, whichever
    # order it reads and writes in; a read-only one stays green.
    for label, body in (
        (
            "read-then-write",
            'let r = c.query_row("SELECT 1", [], |_| Ok(()))?;\n c.execute("INSERT INTO t VALUES (1)", [])?;\n',
        ),
        ("write-first", 'c.execute("UPDATE t SET a = 1", [])?;\n'),
    ):
        text = "fn ro(c: &Connection) {\n let t = c.unchecked_transaction()?;\n " + body + "}\n"
        bad, _, _ = evaluate({"src/ok.rs": text}, allow)
        expect("red:R5 allowlisted " + label, [b[3] for b in bad] == ["R5"])
    text = 'fn ro(c: &Connection) {\n let t = c.unchecked_transaction()?;\n c.query_row("SELECT 1", [], |_| Ok(()))?;\n}\n'
    bad, _, _ = evaluate({"src/ok.rs": text}, allow)
    expect("green:R5 read-only allowlisted", not bad)
    # a non-allowlisted DEFERRED read-then-write / write-first fn is refused
    for label, body in (
        ("read-then-write", 'c.query_row("SELECT 1", [], |_| Ok(()))?; c.execute("DELETE FROM t", [])?;'),
        ("write-first", 'c.execute("INSERT INTO t VALUES (1)", [])?;'),
    ):
        bad, _, _ = run("fn f(c: &Connection) {\n let t = c.unchecked_transaction()?;\n " + body + "\n}\n")
        expect("red:DEFERRED " + label + " refused", len(bad) == 1 and bad[0][3] == "R1")
    # --- round 2 (#5231 #5232 #5233 #5234 + review mutants) ---
    for label, text in (
        ("R1 UFCS generic path", "fn f(c: &mut Connection) {\n let t = rusqlite::Connection::transaction(&mut c)?;\n}\n"),
        ("R1 UFCS split after ::", "fn f(c: &Connection) {\n let t = Connection::\n unchecked_transaction(c)?;\n}\n"),
        ("R1 call after a char literal quote", "fn f(c: &Connection) {\n let q = '\"'; let t = c.unchecked_transaction()?;\n}\n"),
        ("R3 multi-line literal", 'fn f(c: &Connection) {\n c.execute_batch("BEGIN;\n UPDATE t SET a = 1;\n COMMIT;")?;\n}\n'),
        ("R3 raw string BEGIN", 'fn f(c: &Connection) {\n c.execute_batch(r#"BEGIN"#)?;\n}\n'),
        ("R3 mixed case", 'fn f(c: &Connection) {\n c.execute_batch("Begin Deferred")?;\n}\n'),
    ):
        bad, _, _ = run(text)
        expect("red:" + label, len(bad) == 1)
    text = (
        "#[cfg(test)]\nmod t { fn a(c: &Connection) { c.unchecked_transaction(); } }\n"
        "fn after(c: &Connection) {\n c.unchecked_transaction();\n}\n"
    )
    bad, _, _ = run(text)
    expect("red:code after a one-line cfg(test) mod is scanned", [b[2] for b in bad] == ["after"])
    bad, _, _ = run("#[cfg(test)]\nmod tests {\n fn t() {}\nfn after() {}\n")
    expect("red:unterminated cfg(test) module fails closed (R0)", [b[3] for b in bad] == ["R0"])
    bad, _, _ = run("fn f(c: &Connection) {\n let s = \"begin transaction docs\";\n}\n", "src/store/postgres.rs")
    expect("green:postgres adapter prose is not SQLite SQL", not bad)
    bad, _, _ = run("fn f() {\n let q = '\"'; // c.unchecked_transaction()\n}\n")
    expect("green:char-literal quote then comment is a comment", not bad)
    # a production file whose name contains 'test' is scanned (#5234)
    for name in ("src/identity/attest.rs", "src/storage/model_attest.rs", "src/peer_attestation.rs"):
        bad, _, _ = run("fn f(c: &Connection) {\n c.unchecked_transaction();\n}\n", name)
        expect("red:" + name + " is scanned", len(bad) == 1)
    # --- #6152: the BEGIN literal rule reads SQL argument positions only ---
    for label, text in (
        ("expect(\"begin\")", 'fn f(c: &Connection) {\n let t = WriteTxn::begin(c).expect("begin");\n}\n'),
        ("expect(\"BEGIN\")", 'fn f(c: &Connection) {\n let t = WriteTxn::begin(c).expect("BEGIN");\n}\n'),
        ("expect(\"begin a ..\")", 'fn f(c: &Connection) {\n let t = WriteTxn::begin(c).expect("begin a write txn");\n}\n'),
        ("panic message", 'fn f() {\n panic!("begin");\n}\n'),
        ("assert message", 'fn f(a: u8) {\n assert_eq!(a, 1, "begin");\n}\n'),
        ("split expect", 'fn f(c: &Connection) {\n let t = WriteTxn::begin(c)\n .expect(\n "begin",\n );\n}\n'),
        ("param value", 'fn f(c: &Connection) {\n c.execute("INSERT INTO t(a) VALUES (?1)", params!["begin"])?;\n}\n'),
    ):
        bad, _, _ = run(text)
        expect("green:#6152 message literal is not SQL: " + label, not bad)
    for label, text in (
        ("prepare", 'fn f(c: &Connection) {\n let s = c.prepare("BEGIN")?;\n}\n'),
        ("prepare_cached", 'fn f(c: &Connection) {\n let s = c.prepare_cached("BEGIN")?;\n}\n'),
        ("query_row", 'fn f(c: &Connection) {\n c.query_row("BEGIN", [], |_| Ok(()))?;\n}\n'),
        ("execute split line", 'fn f(c: &Connection) {\n c.execute(\n "BEGIN",\n [],\n )?;\n}\n'),
        ("const item", 'const OPEN: &str = "BEGIN";\nfn f() {}\n'),
        ("static item", 'static OPEN: &str = "BEGIN DEFERRED";\nfn f() {}\n'),
        ("let binding", 'fn f(c: &Connection) {\n let sql = "BEGIN";\n c.execute_batch(sql)?;\n}\n'),
    ):
        bad, _, _ = run(text)
        expect("red:#6152 SQL position still fires: " + label, len(bad) == 1 and bad[0][3] == "R3")
    # --- #6152: `mod x;` declared inside a cfg(test) block is test code ---
    # (src/daemon_runtime.rs declares escalate_under_write_lock_4116_tests so)
    deferred = "fn t(c: &Connection) { c.unchecked_transaction(); }\n"
    for label, files, flagged in (
        (
            "inline block in a non-mod.rs file",
            {
                "src/foo.rs": "#[cfg(test)]\nmod t {\n    mod inner;\n    fn h() {}\n}\nfn prod() {}\n",
                "src/foo/t/inner.rs": deferred,
            },
            [],
        ),
        (
            "inline block in a mod.rs file, <name>/mod.rs layout",
            {
                "src/m/mod.rs": "#[cfg(test)]\nmod t {\n    mod inner;\n}\n",
                "src/m/t/inner/mod.rs": deferred,
            },
            [],
        ),
        (
            "two levels of nesting",
            {
                "src/foo.rs": "#[cfg(test)]\nmod t {\n    mod u {\n        mod inner;\n    }\n}\n",
                "src/foo/t/u/inner.rs": deferred,
            },
            [],
        ),
        (
            "a sibling outside the test mod directory is still scanned",
            {
                "src/foo.rs": "#[cfg(test)]\nmod t {\n    mod inner;\n}\n",
                "src/foo/t/inner.rs": deferred,
                "src/foo/inner.rs": deferred,
            },
            ["src/foo/inner.rs"],
        ),
        (
            "mod x; after the test block closes is not test code",
            {
                "src/foo.rs": "#[cfg(test)]\nmod t {\n    fn h() {}\n}\nmod inner;\n",
                "src/foo/inner.rs": deferred,
            },
            ["src/foo/inner.rs"],
        ),
    ):
        got = sorted({h[0] for h in scan(files)})
        expect("red:#6152 nested mod in cfg(test): " + label, got == flagged)
    # --- #6154 review R2 (F1): every literal is read; only message sinks skip ---
    # Decision (single correct answer, fail closed; no vote): the base gate read
    # every string literal, and the #6152 narrowing to SQL argument positions let
    # DEFERRED statements escape.  Keep the base behaviour and exempt only
    # literals that are arguments of message sinks.
    f_open = "fn f(c: &Connection) -> Result<()> {\n%s\n    Ok(())\n}\n"
    for label, text in (
        ("let String::from", f_open % '    let sql = String::from("BEGIN");\n    c.execute_batch(&sql)?;'),
        ("let to_string", f_open % '    let sql = "BEGIN".to_string();\n    c.execute_batch(&sql)?;'),
        ("as_str chain", f_open % '    let sql = String::from("BEGIN");\n    c.execute_batch(sql.as_str())?;'),
        ("helper fn returns literal", "fn open_sql() -> &'static str {\n    \"BEGIN\"\n}\n"),
        ("helper fn one-line return", "fn open_sql() -> &'static str { \"BEGIN\" }\n"),
        ("pub(crate) const", 'pub(crate) const OPEN: &str = "BEGIN";\n'),
        ("pub(in path) const", 'pub(in crate::storage) const OPEN: &str = "BEGIN";\n'),
        ("const wrapped by rustfmt", 'const OPEN_AND_LOG: &str =\n    "BEGIN";\n'),
        ("let wrapped by rustfmt", f_open % '    let sql =\n        "BEGIN";\n    c.execute_batch(sql)?;'),
        ("UFCS execute_batch", f_open % '    rusqlite::Connection::execute_batch(c, "BEGIN")?;'),
        ("UFCS split", f_open % '    rusqlite::Connection::execute_batch(\n        c,\n        "BEGIN",\n    )?;'),
        ("query_row_and_then", f_open % '    c.query_row_and_then("BEGIN", [], |_| Ok::<(), rusqlite::Error>(()))?;'),
        ("prepare_with_flags", f_open % '    c.prepare_with_flags("BEGIN", PrepFlags::empty())?;'),
        ("Batch::new", f_open % '    let mut b = rusqlite::Batch::new(c, "BEGIN");'),
        ("helper wrapper arg", f_open % '    exec(c, "BEGIN")?;'),
        ("if expr let", f_open % '    let sql = if ro { "BEGIN" } else { "BEGIN IMMEDIATE" };\n    c.execute_batch(sql)?;'),
        (
            "match arm",
            f_open % '    let sql = match m {\n        Mode::Read => "BEGIN",\n        Mode::Write => "BEGIN IMMEDIATE",\n    };\n    c.execute_batch(sql)?;',
        ),
        ("reassign mut", f_open % '    let mut sql = "SELECT 1";\n    sql = "BEGIN";\n    c.execute_batch(sql)?;'),
        ("struct field", f_open % '    let s = Stmt { sql: "BEGIN" };\n    c.execute_batch(s.sql)?;'),
        ("array of statements", f_open % '    for s in ["BEGIN", "INSERT INTO t VALUES (1)"] {\n        c.execute(s, [])?;\n    }'),
        ("format! in let", f_open % '    let sql = format!("BEGIN {}", mode);\n    c.execute_batch(&sql)?;'),
        ("format! arg literal in execute_batch", f_open % '    c.execute_batch(&format!("{}", "BEGIN"))?;'),
        ("closure return", f_open % '    let open = || "BEGIN";\n    c.execute_batch(open())?;'),
        ("Some(literal)", f_open % '    let sql = Some("BEGIN");\n    c.execute_batch(sql.unwrap_or_default())?;'),
        ("String::from SAVEPOINT", f_open % '    let s = String::from("SAVEPOINT a");\n    c.execute_batch(&s)?;'),
        ("plain fn named info (not a macro)", f_open % '    info(c, "BEGIN")?;'),
        ("free fn named expect (not a method)", f_open % '    expect("BEGIN");'),
        ("block inside assert!", f_open % '    assert!({ let s = "BEGIN"; c.execute_batch(s).is_ok() });'),
        ("unknown call inside a sink", f_open % '    panic!("{}", exec(c, "BEGIN"));'),
        ("let inside a closure passed to context", f_open % '    r.with_context(|| { let s = "BEGIN"; s })?;'),
    ):
        rule = "R6" if "SAVEPOINT" in text else "R3"
        bad, _, _ = run(text)
        expect("red:#6154 F1 literal escapes the SQL-position rule: " + label, [b[3] for b in bad] == [rule])
    for label, text in (
        ("expect", 'let t = WriteTxn::begin(c).expect("begin");'),
        ("expect_err", 'let e = WriteTxn::begin(c).expect_err("BEGIN");'),
        ("context", 'let t = WriteTxn::begin(c).context("BEGIN")?;'),
        ("with_context", 'let t = WriteTxn::begin(c).with_context(|| format!("begin {}", n))?;'),
        ("expect(&format!)", 'let t = WriteTxn::begin(c).expect(&format!("BEGIN {}", n));'),
        ("panic!", 'panic!("BEGIN");'),
        ("assert!", 'assert!(ok, "begin");'),
        ("assert_eq!", 'assert_eq!(a, 1, "BEGIN");'),
        ("assert_ne!", 'assert_ne!(a, 1, "begin;");'),
        ("debug_assert!", 'debug_assert!(ok, "begin");'),
        ("debug_assert_eq!", 'debug_assert_eq!(a, 1, "BEGIN");'),
        ("unreachable!", 'unreachable!("begin");'),
        ("todo!", 'todo!("BEGIN");'),
        ("unimplemented!", 'unimplemented!("begin");'),
        ("trace!", 'trace!("BEGIN");'),
        ("debug!", 'debug!("begin");'),
        ("info!", 'info!("BEGIN");'),
        ("warn!", 'warn!("begin");'),
        ("error!", 'error!("BEGIN");'),
        ("tracing::info!", 'tracing::info!("BEGIN");'),
        ("print!", 'print!("BEGIN");'),
        ("println!", 'println!("begin");'),
        ("eprint!", 'eprint!("BEGIN");'),
        ("eprintln!", 'eprintln!("begin");'),
        ("write!", 'write!(f, "BEGIN")?;'),
        ("writeln!", 'writeln!(f, "begin")?;'),
        ("anyhow!", 'return Err(anyhow!("BEGIN"));'),
        ("bail!", 'bail!("begin");'),
        ("ensure!", 'ensure!(ok, "BEGIN");'),
        ("params!", 'c.execute("INSERT INTO t(a) VALUES (?1)", params!["BEGIN"])?;'),
        ("named_params!", 'c.execute("INSERT INTO t(a) VALUES (:a)", named_params! {":a": "begin"})?;'),
        ("format! inside panic!", 'panic!("{}", format!("BEGIN {}", n));'),
        ("rustfmt-wrapped expect", 'let t = WriteTxn::begin(c)\n        .expect(\n            "BEGIN",\n        );'),
    ):
        bad, _, _ = run("fn f(c: &Connection) {\n    %s\n}\n" % text)
        expect("green:#6154 F1 message sink literal is not SQL: " + label, not bad)
    # --- #6154 review R2 (F2): one whole-file literal pass, no 3-line window ---
    for label, text in (
        (
            "multi-line SQL execute closing within 3 lines, then BEGIN",
            'fn f(c: &Connection) -> Result<()> {\n    c.execute(\n        "UPDATE t SET a = 1\n'
            '         WHERE b = 2\n         AND c = 3\n         AND d = 4",\n        [],\n    )?;\n'
            '    c.execute_batch("BEGIN")?;\n    Ok(())\n}\n',
        ),
        ("char literal quote on the line above", "fn f(c: &Connection) {\n    let q = '\"';\n    c.execute_batch(\"BEGIN\")?;\n}\n"),
        (
            "open multi-line string above",
            'fn f(c: &Connection) {\n    let note = "line one\n        line two";\n    c.execute_batch("BEGIN")?;\n}\n',
        ),
        (
            "raw string with a quote above",
            'fn f(c: &Connection) {\n    let s = r#"a"b"#;\n    c.execute_batch("BEGIN")?;\n}\n',
        ),
        ("escaped quote above", 'fn f(c: &Connection) {\n    let s = "a\\"";\n    c.execute_batch("BEGIN")?;\n}\n'),
        ("byte string with a quote above", 'fn f(c: &Connection) {\n    let s = b"\\"";\n    c.execute_batch("BEGIN")?;\n}\n'),
        (
            "block comment with a quote above",
            'fn f(c: &Connection) {\n    /* it"s */\n    c.execute_batch("BEGIN")?;\n}\n',
        ),
    ):
        bad, _, _ = run(text)
        expect("red:#6154 F2 unbalanced quote outside the window: " + label, [b[3] for b in bad] == ["R3"])
    bad, _, _ = run("fn f() {\n    let s = \"c.unchecked_transaction()\";\n}\n")
    expect("green:#6154 F2 code-looking text inside a string literal is not code", not bad)
    # --- #6155 (closed by the whole-literal read): a multi-line literal is read whole ---
    for label, text in (
        ("raw const, BEGIN on the 2nd line", 'const S: &str = r#"\nBEGIN;\nINSERT INTO t VALUES (1);\n"#;\n'),
        ("plain string batch", 'fn f(c: &Connection) {\n    c.execute_batch("\n        BEGIN;\n        COMMIT;")?;\n}\n'),
        ("statement after a semicolon on line 2", 'fn f(c: &Connection) {\n    c.execute_batch("PRAGMA x = 1;\n BEGIN")?;\n}\n'),
    ):
        bad, _, _ = run(text)
        expect("red:#6155 multi-line literal read whole: " + label, [b[3] for b in bad] == ["R3"])
    bad, _, _ = run('const S: &str = r#"\nBEGIN IMMEDIATE;\nINSERT INTO t VALUES (1);\n"#;\n')
    expect("green:#6155 multi-line BEGIN IMMEDIATE batch", not bad)
    # --- #6154 review R2 (F3): ambiguous mod layout in a cfg(test) block fails closed ---
    deferred = "fn t(c: &Connection) { c.unchecked_transaction(); }\n"
    for label, files in (
        (
            "mod x; at the block indent, non-rustfmt",
            {
                "src/a.rs": "#[cfg(test)]\nmod tests {\nmod helpers;\n}\n",
                "src/a/tests/helpers.rs": deferred,
                "src/a/helpers.rs": deferred,
            },
        ),
        (
            "mod x; left of the block indent",
            {
                "src/a.rs": "    #[cfg(test)]\n    mod tests {\n  mod helpers;\n    }\n",
                "src/a/tests/helpers.rs": deferred,
                "src/a/helpers.rs": deferred,
            },
        ),
        (
            "mod x; closing brace missing before the next item",
            {
                "src/a.rs": "#[cfg(test)]\nmod tests {\n    mod u {\n        fn h() {}\n}\n",
                "src/a/tests/u.rs": deferred,
            },
        ),
    ):
        got = {(h[0], h[3]) for h in scan(files)}
        expect("red:#6154 F3 ambiguous cfg(test) layout is a violation: " + label, ("src/a.rs", "R0") in got)
    got = sorted({h[0] for h in scan({
        "src/a.rs": "#[cfg(test)]\nmod tests {\n        mod helpers;\n}\n",
        "src/a/tests/helpers.rs": deferred,
    })})
    expect("green:#6154 F3 mod x; indented deeper than the block is test code", got == [])
    got = sorted({h[0] for h in scan({
        "src/lib.rs": "mod prod;\n#[cfg(test)]\n#[path = \"unit_tests.rs\"]\nmod unit;\n",
        "src/prod.rs": deferred,
        "src/unit_tests.rs": deferred,
    })})
    expect("red:#6154 F3 mod x; outside a cfg(test) block is scanned, #[path] honoured", got == ["src/prod.rs"])
    # stale allowlist entry must fail
    _, stale, _ = evaluate({"src/x.rs": "fn f() {}\n"}, allow)
    expect("red:stale allowlist", stale == [("src/ok.rs", "ro")])
    # allowlist is keyed by fn: same file, other fn still fails
    bad, _, _ = evaluate(
        {"src/ok.rs": "fn other(c: &Connection) {\n c.unchecked_transaction();\n}\n"}, allow
    )
    expect("red:allowlist scoped to fn", len(bad) == 1)
    return failures, counts


def _never(*_args, **_kw):
    return False


def _always(*_args, **_kw):
    return True


def _identity(s):
    return s


def self_test():
    """Red/green probes against the real engine, then mutants: each one breaks a
    single mechanism and must make at least one probe fail (killed)."""
    failures, counts = _probes()
    g = globals()
    full_rules, full_lit = list(RULES), list(LIT_RULES)

    def drop_rule(rule):
        def patch():
            g["RULES"] = [r for r in full_rules if r[0] != rule]
            g["LIT_RULES"] = [r for r in full_lit if r[0] != rule]

        return patch

    mutants = [("rule %s dropped" % r, drop_rule(r)) for r, _ in full_rules]
    mutants += [
        ("R5 write-keyword scan removed", lambda: g.update(WRITE_SQL=re.compile(r"(?!)"))),
        ("R5 SQL-by-name check removed", lambda: g.update(NONLITERAL_EXEC=re.compile(r"(?!)"))),
        ("sink-skip removed (every literal scanned)", lambda: g.update(message_sink=_never)),
        ("sink-skip widened (every literal skipped)", lambda: g.update(message_sink=_always)),
        ("literal blanking removed", lambda: g.update(_blank_lit=_identity)),
        ("raw-string handling removed", lambda: g.update(TOKEN=_build_token(raw=False))),
        ("char-literal handling removed", lambda: g.update(CHAR_LIT=re.compile(r"(?!)"))),
        ("ambiguous-mod guard removed (indent placement)", lambda: g.update(mod_inside=_always)),
        ("ambiguous-mod guard removed (brace balance)", lambda: g.update(block_balanced=_always)),
    ]
    saved = {k: g[k] for k in (
        "RULES", "LIT_RULES", "WRITE_SQL", "NONLITERAL_EXEC", "message_sink",
        "_blank_lit", "TOKEN", "CHAR_LIT", "mod_inside", "block_balanced",
    )}
    killed = 0
    try:
        for label, patch in mutants:
            patch()
            try:
                got, _ = _probes()
            finally:
                g.update(saved)
            if got:
                killed += 1
            else:
                failures.append("mutant survived (no probe fails): " + label)
    finally:
        g.update(saved)
    if failures:
        for f in failures:
            print("SELF-TEST FAIL: " + f, file=sys.stderr)
        return 1
    print(
        "self-test ok: %d green, %d red probes, %d/%d mutants killed, %d rules"
        % (counts["green"], counts["red"], killed, len(mutants), len(RULES) + 1)
    )
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--self-test", action="store_true", help="run red/green probes and mutants")
    ap.add_argument("--root", default=str(ROOT), help="repository root (default: this checkout)")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    root = Path(args.root)
    if not (root / "src").is_dir():
        print("check-sqlite-write-txn-immediate: no src/ under %s" % root, file=sys.stderr)
        return 2
    bad, stale, total = evaluate(load_tree(root), ALLOWLIST)
    for rel, n, fn, rule, text in bad:
        if rule == "R0":
            print("%s:%d: [R0] layout or lexing cannot be resolved with certainty: %s" % (rel, n, text))
            continue
        why = (
            "allowlisted read-only fn contains a write"
            if rule == "R5"
            else (
                "DEFERRED transaction (use WriteTxn::begin, or "
                "Transaction::new_unchecked(.., TransactionBehavior::Immediate) "
                "where a &Transaction is required, #5084)"
            )
        )
        print("%s:%d: [%s] fn %s: %s: %s" % (rel, n, rule, fn, why, text))
    for rel, fn in stale:
        print("stale allowlist entry (no matching site): %s fn %s" % (rel, fn))
    if bad or stale:
        return 1
    print("check-sqlite-write-txn-immediate: ok (%d allowlisted read-only site(s))" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
