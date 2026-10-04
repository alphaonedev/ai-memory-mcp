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

Closed world: only sites in ``ALLOWLIST`` (file, enclosing fn) pass, and each
carries a written reason.  A stale allowlist entry (no matching site) also
fails, so the list cannot rot.  Test code (``tests/`` is not scanned; in
``src/``: ``*test*`` file names, ``#[cfg(test)]`` modules and ``#[cfg(test)]``
external ``mod x;`` files) is skipped.

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
    ("R1", re.compile(r"\.transaction\s*\(\s*\)|unchecked_transaction\s*\(\s*\)")),
    (
        "R2",
        re.compile(
            r"TransactionBehavior::Deferred"
            r"|transaction_with_behavior\s*\((?![^)]*(?:Immediate|Exclusive))"
            r"|new_unchecked\s*\((?![^)]*(?:Immediate|Exclusive))"
        ),
    ),
    (
        "R3",
        re.compile(
            r"\"BEGIN\s*(?:DEFERRED(?:\s+TRANSACTION)?|TRANSACTION)?\s*;?\s*\""
            r"|\"BEGIN\"|SQL_BEGIN_DEFERRED"
            r"|\bif\b[^\n]*\{\s*\"BEGIN IMMEDIATE\"\s*\}\s*else\s*\{\s*\"BEGIN\"\s*\}"
            r"|\"BEGIN IMMEDIATE\"\s*\}?\s*else\s*\{?\s*\"BEGIN\""
        ),
    ),
    ("R4", re.compile(r"WriteTxn::begin_deferred")),
]
CFG_TEST_MOD_FILE = re.compile(r"#\[cfg\(test\)\]\s*(?:pub(?:\([a-z]+\))?\s+)?mod\s+(\w+)\s*;")


def strip_comment(line):
    """Drop a trailing ``//`` comment that is not inside a string literal."""
    out, in_str, esc, i = [], False, False, 0
    while i < len(line):
        c = line[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
                out.append(c)
            elif c == "/" and line[i : i + 2] == "//":
                break
            else:
                out.append(c)
        i += 1
    return "".join(out)


def test_only_files(files):
    """Paths of ``#[cfg(test)] mod x;`` external modules."""
    skip = set()
    for rel, text in files.items():
        parent = Path(rel).parent
        for m in CFG_TEST_MOD_FILE.finditer(text.replace("\n", " ")):
            name = m.group(1)
            skip.add((parent / f"{name}.rs").as_posix())
            skip.add((parent / name / "mod.rs").as_posix())
    return skip


def scan(files):
    """files: {rel_path: text}.  Returns sorted [(rel, line, fn, rule, text)]."""
    skip = test_only_files(files)
    hits = []
    for rel in sorted(files):
        name = Path(rel).name
        if "test" in name or rel in skip:
            continue
        lines = files[rel].splitlines()
        cur = "?"
        for n, raw in enumerate(lines, 1):
            if not raw.startswith(" "):
                nxt = lines[n] if n < len(lines) else ""
                if re.match(r"mod tests?\b", raw) or (
                    raw.startswith("#[cfg(test)]")
                    and re.match(r"(?:pub(?:\([a-z]+\))? )?mod \w+ \{", nxt)
                ):
                    break
            m = FN.search(raw)
            if m:
                cur = m.group(1)
            code = strip_comment(raw)
            if not code.strip() or code.lstrip().startswith("//"):
                continue
            for rule, rx in RULES:
                if rx.search(code):
                    hits.append((rel, n, cur, rule, raw.strip()))
                    break
    return hits


def evaluate(files, allowlist):
    hits = scan(files)
    used, bad = set(), []
    for rel, n, fn, rule, text in hits:
        key = (rel, fn)
        if key in allowlist:
            used.add(key)
        else:
            bad.append((rel, n, fn, rule, text))
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

    failures = []

    def expect(label, cond):
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
    bad, _, _ = run("fn f(c: &Connection) {\n c.unchecked_transaction();\n}\n", "src/my_test_helpers.rs")
    expect("green:test file skipped", not bad)
    files = {
        "src/a.rs": "#[cfg(test)]\nmod hidden;\nfn real() {}\n",
        "src/hidden.rs": "fn t(c: &Connection) { c.unchecked_transaction(); }\n",
    }
    bad, _, _ = evaluate(files, {})
    expect("green:cfg(test) external mod skipped", not bad)

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
    }
    for label, (rule, text) in red.items():
        bad, _, _ = run(text)
        expect("red:" + label, len(bad) == 1 and bad[0][3] == rule)
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
    global RULES
    full = RULES
    try:
        for dropped, _ in full:
            RULES = [r for r in full if r[0] != dropped]
            silent = True  # every probe of the dropped rule goes unflagged
            for rule, text in red.values():
                if rule == dropped and run(text)[0]:
                    silent = False
            expect("mutant:%s dropped goes silent (rule is load-bearing)" % dropped, silent)
    finally:
        RULES = full
    if failures:
        for f in failures:
            print("SELF-TEST FAIL: " + f, file=sys.stderr)
        return 1
    print("self-test ok: %d green, %d red probes, %d rules" % (len(green) + 3, len(red) + 2, len(RULES)))
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
        print("%s:%d: [%s] DEFERRED transaction in fn %s (use WriteTxn::begin, #5084): %s" % (rel, n, rule, fn, text))
    for rel, fn in stale:
        print("stale allowlist entry (no matching site): %s fn %s" % (rel, fn))
    if bad or stale:
        return 1
    print("check-sqlite-write-txn-immediate: ok (%d allowlisted read-only site(s))" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
