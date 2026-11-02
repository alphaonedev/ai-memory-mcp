#!/usr/bin/env python3
"""Workflow lint (#8473 item 6): every cargo build/test/clippy/check/run/doc/
bench/llvm-cov/nextest/fetch invocation in a `run:` block carries --locked, and
`cargo update` never appears, so CI builds the reviewed Cargo.lock or fails.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only (workflows are read as text).
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORKFLOWS = REPO / ".github" / "workflows"
VERBS = ("build", "test", "clippy", "check", "run", "doc", "bench", "llvm-cov", "nextest", "fetch")
CARGO_RE = re.compile(r"(?<![\w./$-])cargo(?:\s+\+\S+)?\s+(%s|update)(?![\w-])" % "|".join(VERBS))
RUN_KEY_RE = re.compile(r"^(\s*)(?:-\s+)?run:\s*(.*)$")
SEGMENT_END_RE = re.compile(r"&&|\|\||;|\|")


def run_lines(text):
    """Yield (lineno, line) for every line inside a `run:` value."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = RUN_KEY_RE.match(lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(2).strip()
        if rest and not re.match(r"^[|>][-+]?\d*$", rest):
            yield i + 1, rest
            i += 1
            continue
        i += 1
        while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent):
            yield i + 1, lines[i]
            i += 1


def find_sites(text):
    """Return [(lineno, verb, has_locked, line)] for command-position cargo calls."""
    rows = list(run_lines(text))
    by_no = dict(rows)
    sites = []
    for no, raw in rows:
        line = raw.strip()
        if not line or line.startswith("#") or re.match(r"^(echo|printf)\b", line):
            continue
        for m in CARGO_RE.finditer(line):
            if line[:m.start()].count('"') % 2 or line[:m.start()].count("'") % 2:
                continue  # inside a quoted string
            tail, last = line[m.start():], no
            while tail.rstrip().endswith("\\") and (last + 1) in by_no:
                last += 1
                tail = tail.rstrip()[:-1] + " " + by_no[last].strip()
            segment = SEGMENT_END_RE.split(tail)[0]
            sites.append((no, m.group(1), bool(re.search(r"(?<!\S)--locked(?!\S)", segment)), line))
    return sites


class WorkflowCargoLocked(unittest.TestCase):
    def test_every_cargo_invocation_is_locked_and_none_updates(self):
        bad = []
        seen = 0
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            for no, verb, locked, line in find_sites(wf.read_text()):
                seen += 1
                if verb == "update":
                    bad.append("%s:%d cargo update must not run in CI: %s" % (wf.name, no, line[:80]))
                elif not locked:
                    bad.append("%s:%d cargo %s without --locked: %s" % (wf.name, no, verb, line[:80]))
        self.assertGreaterEqual(seen, 40, "the scanner found too few cargo invocations to be trusted")
        self.assertEqual(bad, [], "%d site(s):\n%s" % (len(bad), "\n".join(bad)))

    def test_scanner_flags_the_known_shapes(self):
        wf = (
            "jobs:\n  a:\n    steps:\n"
            "      - run: cargo test --lib\n"
            "      - run: |\n"
            "          echo \"cargo build is quoted\"\n"
            "          cargo build \\\n            --release --locked\n"
            "          cargo clippy --all-targets -- -D warnings && cargo update\n"
            "          # cargo check in a comment\n"
        )
        got = [(v, locked) for _, v, locked, _ in find_sites(wf)]
        self.assertEqual(got, [("test", False), ("build", True), ("clippy", False), ("update", False)])


if __name__ == "__main__":
    unittest.main()
