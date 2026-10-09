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

SQL text rules (R3 literals, R6 literals) match string-literal contents in any
case and in batches ("BEGIN; ...") and format strings ("BEGIN {m}"); they skip
the Postgres adapter files (sqlx has its own transaction model).

Closed world: only sites in ``ALLOWLIST`` (file, enclosing fn) pass, and each
carries a written reason.  A stale allowlist entry (no matching site) also
fails, so the list cannot rot.  Test code is skipped only by cfg: ``tests/`` is
not scanned; in ``src/`` a ``#[cfg(test)]`` / ``#[cfg(all(test, ..))]`` module
block, an external ``mod x;`` under such a cfg (``#[path]`` honoured), and a
file with ``#![cfg(test)]``.  No file is skipped by name and no file is cut
short, so production code after a test module is scanned.

Known limit (R5): it reads SQL literals in the allowlisted fn body only; a
write through a helper call or a caller-supplied closure is not seen.

Python 3.9 stdlib only.  Exit 0 = clean, 1 = violation, 2 = usage error.
"""
import argparse
import re
import sys
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
            r"\.transaction\s*\(\s*(?:\)|$)|unchecked_transaction\s*\(\s*(?:\)|$)"
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
# R3 on string-literal contents: a statement that starts with BEGIN and does not
# name IMMEDIATE / EXCLUSIVE, in any case, including a batch "BEGIN; ...",
# a format string "BEGIN {mode}" and a raw string.
BEGIN_SQL = re.compile(
    r"(?:^|;)\s*BEGIN(?:\s+(?:DEFERRED|TRANSACTION))*\s*(?:;|$|\{)", re.IGNORECASE
)
# R6 on string-literal contents (SQLite files only): a raw SAVEPOINT outside a
# transaction opens DEFERRED.
SAVEPOINT_SQL = re.compile(r"(?:^|;)\s*SAVEPOINT\b", re.IGNORECASE)
LIT_RULES = [("R3", BEGIN_SQL), ("R6", SAVEPOINT_SQL)]
STRING_LIT = re.compile(r'r#*"(?:[^"]|"(?!#))*"#*|"(?:[^"\\]|\\.)*"')
NONLITERAL_EXEC = re.compile(r"\.execute(?:_batch)?\s*\(\s*(?!\"|r#*\"|if\b)\S")
WRITE_SQL = re.compile(r"\b(?:INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b", re.IGNORECASE)
# A test-only cfg: cfg(test) or cfg(all(test, ...)).  cfg(any(test, ...)) also
# compiles outside tests, so it is production code and is scanned.
TEST_CFG = re.compile(r"#\[cfg\(\s*(?:test|all\(\s*test\b[^\]]*)\s*\)\]")
MOD_DECL = re.compile(r"^\s*(?:pub(?:\([a-z]+\))?\s+)?mod\s+(\w+)\s*([;{])")
PATH_ATTR = re.compile(r'#\[path\s*=\s*"([^"]+)"\]')


CHAR_LIT = re.compile(r"'(?:[^'\\]|\\.[^']*)'")


def strip_comment(line):
    """Drop a trailing ``//`` comment that is not inside a string literal
    (plain ``"..."``, raw ``r#"..."#``) or a char literal (``'"'``)."""
    out, i, n = [], 0, len(line)
    while i < n:
        if line[i] == "'":
            ch = CHAR_LIT.match(line, i)
            if ch:
                out.append(ch.group(0))
                i = ch.end()
                continue
        m = re.match(r'r(#*)"', line[i:]) if line[i] == "r" and (i == 0 or not (line[i - 1].isalnum() or line[i - 1] == "_")) else None
        if m:
            close = '"' + m.group(1)
            j = line.find(close, i + len(m.group(0)))
            j = n if j < 0 else j + len(close)
            out.append(line[i:j])
            i = j
            continue
        c = line[i]
        if c == '"':
            j, esc = i + 1, False
            while j < n:
                if esc:
                    esc = False
                elif line[j] == "\\":
                    esc = True
                elif line[j] == '"':
                    break
                j += 1
            out.append(line[i : j + 1])
            i = j + 1
            continue
        if line[i : i + 2] == "//":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _child_dir(rel):
    """Directory that holds the child modules of the file ``rel``."""
    p = Path(rel)
    if p.name in ("mod.rs", "lib.rs", "main.rs"):
        return p.parent
    return p.parent / p.stem


def test_regions(rel, lines):
    """(skip_line_numbers, external_test_files, unterminated_lines) for one file.

    A test-only cfg attribute (possibly followed by other attributes) applied
    to ``mod x { ... }`` skips that block up to its closing brace at the same
    indent (rustfmt layout); applied to ``mod x;`` it marks the external file.
    A file-level ``#![cfg(test)]`` skips the whole file.
    """
    skip, ext, unterminated = set(), set(), []
    if any(re.match(r"#!\[cfg\(\s*test\s*\)\]", l.strip()) for l in lines[:40]):
        return set(range(1, len(lines) + 1)), ext, unterminated
    i = 0
    while i < len(lines):
        if not TEST_CFG.search(lines[i]):
            i += 1
            continue
        j, path_attr = i + 1, None
        while j < len(lines) and lines[j].lstrip().startswith("#["):
            m = PATH_ATTR.search(lines[j])
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
        closed = False
        if strip_comment(lines[j]).count("{") == strip_comment(lines[j]).count("}"):
            closed = True  # one-line ``mod x { .. }``
        while not closed and k < len(lines):
            skip.add(k + 1)
            if k > j and lines[k].rstrip() == " " * indent + "}":
                closed = True
                break
            k += 1
        skip.add(j + 1)
        if not closed:
            # Fail closed: never swallow the rest of the file silently.
            unterminated.append(j + 1)
        for a in range(i, j):
            skip.add(a + 1)
        i = max(k, j) + 1
    return skip, ext, unterminated


def scan(files):
    """files: {rel_path: text}.  Returns sorted [(rel, line, fn, rule, text)].

    No file is skipped by name and no file is cut short: only test-only cfg
    regions and test-only external modules are skipped.
    """
    regions, ext, hits = {}, set(), []
    for rel, text in files.items():
        sk, ex, bad = test_regions(rel, text.splitlines())
        regions[rel] = sk
        ext |= ex
        for n in bad:
            hits.append((rel, n, "?", "R0", "unterminated cfg(test) module: fail closed"))
    hits = list(hits)
    for rel in sorted(files):
        if rel in ext:
            continue
        lines = files[rel].splitlines()
        skip = regions[rel]
        # SQL-text rules (R3 literal, R6 literal) apply to SQLite code only;
        # the Postgres adapter (sqlx) has its own transaction model.
        sqlite_file = "postgres" not in rel
        cur = "?"
        for n, raw in enumerate(lines, 1):
            if n in skip:
                continue
            code = strip_comment(raw)
            if not code.strip() or code.lstrip().startswith("//"):
                continue
            m = FN.search(code)
            if m:
                cur = m.group(1)
            rule_hit = None
            # A call split across lines (rustfmt chains) still matches when it
            # STARTS on this line: look 3 lines ahead, keep only starts here.
            window = " ".join([code] + [strip_comment(l).strip() for l in lines[n : n + 2]])
            for rule, rx in RULES:
                mm = rx.search(window)
                if mm and mm.start() < len(code):
                    rule_hit = rule
                    break
            if rule_hit is None and sqlite_file:
                bodies = [re.sub(r'^r#*"|"#*$|^"|"$', "", lit) for lit in STRING_LIT.findall(code)]
                # A literal that opens here and closes on a later line (a
                # multi-line SQL string): its first line is checked as text.
                rest = STRING_LIT.sub("", code)
                opened = re.search(r'r#*"|"', rest)
                if opened:
                    bodies.append(rest[opened.end():])
                for body in bodies:
                    rule_hit = next((r for r, rx in LIT_RULES if rx.search(body)), None)
                    if rule_hit:
                        break
            if rule_hit:
                hits.append((rel, n, cur, rule_hit, raw.strip()))
    return hits


def fn_body(text, name):
    """Lines of ``fn name`` up to its closing brace at the same indent."""
    lines = text.splitlines()
    for i, raw in enumerate(lines):
        m = re.search(r"\bfn\s+" + re.escape(name) + r"\b", strip_comment(raw))
        if not m:
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        out = [raw]
        for nxt in lines[i + 1 :]:
            out.append(nxt)
            if nxt.rstrip() == " " * indent + "}":
                break
        return out
    return []


def evaluate(files, allowlist):
    hits = scan(files)
    used, bad = set(), []
    for rel, n, fn, rule, text in hits:
        key = (rel, fn)
        if key in allowlist:
            used.add(key)
        else:
            bad.append((rel, n, fn, rule, text))
    for rel, fn in sorted(used):
        defs = [l for l in files[rel].splitlines()
                if re.search(r"\bfn\s+" + re.escape(fn) + r"\b", strip_comment(l))]
        if len(defs) != 1:
            bad.append((rel, 0, fn, "R5", "allowlisted fn name defined %d times in file" % len(defs)))
        for raw in fn_body(files[rel], fn):
            code = strip_comment(raw)
            # SQL passed by name (a const or variable) cannot be proven read-only.
            if NONLITERAL_EXEC.search(code):
                bad.append((rel, 0, fn, "R5", raw.strip()))
                continue
            # Only SQL text: look inside string literals, ignore identifiers.
            if any(WRITE_SQL.search(lit) for lit in re.findall(r'"(?:[^"\\]|\\.)*"', code)):
                bad.append((rel, 0, fn, "R5", raw.strip()))
    stale = sorted(k for k in allowlist if k not in used)
    return bad, stale, len(hits)


def load_tree(root):
    files = {}
    for p in sorted((root / "src").rglob("*.rs")):
        files[p.relative_to(root).as_posix()] = p.read_text(encoding="utf-8")
    return files


def self_test():
    """Red/green probes plus one mutant per rule."""
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
    # stale allowlist entry must fail
    _, stale, _ = evaluate({"src/x.rs": "fn f() {}\n"}, allow)
    expect("red:stale allowlist", stale == [("src/ok.rs", "ro")])
    # allowlist is keyed by fn: same file, other fn still fails
    bad, _, _ = evaluate(
        {"src/ok.rs": "fn other(c: &Connection) {\n c.unchecked_transaction();\n}\n"}, allow
    )
    expect("red:allowlist scoped to fn", len(bad) == 1)
    # mutants: dropping any one rule must make at least one red probe pass
    # undetected (proves each rule is load-bearing, not vacuous).
    global RULES, LIT_RULES
    full, full_lit = RULES, LIT_RULES
    try:
        for dropped, _ in full:
            RULES = [r for r in full if r[0] != dropped]
            LIT_RULES = [r for r in full_lit if r[0] != dropped]
            silent = True  # every probe of the dropped rule goes unflagged
            for rule, text in red.values():
                if rule == dropped and run(text)[0]:
                    silent = False
            expect("mutant:%s dropped goes silent (rule is load-bearing)" % dropped, silent)
    finally:
        RULES, LIT_RULES = full, full_lit
    if failures:
        for f in failures:
            print("SELF-TEST FAIL: " + f, file=sys.stderr)
        return 1
    print(
        "self-test ok: %d green, %d red probes, %d mutants, %d rules"
        % (counts["green"], counts["red"], counts["mutant"], len(RULES) + 1)
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
