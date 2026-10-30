#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Paste-safety guard for fenced shell blocks in the docs (#8311).

An interactive zsh without `interactivecomments` treats `#` as an ordinary
word: a pasted `cmd args   # reason` hands the comment words to `cmd` as
operands, and a comment line holding a backtick or `$(` runs the substitution
before the command lookup fails. A reader pastes a fence whole, so every
bash / sh / zsh / console fence must hold commands only.

Scanned: README.md and every docs/**/*.md. Flagged inside a shell fence:

  (a) a command line ending in ` # comment` (trailing comment);
  (b) a full-line comment containing a backtick or `$(`;
  (c) a full-line `#` comment that sits between two command lines.

A leading `#!` line, comment-only fences (no command line at all) and the
text of a heredoc body are not flagged.

OPT-OUT MARKER (one, explicit): a fence whose FIRST line is exactly
`# not-for-paste` is documentation of a script body, not a paste target; the
guard skips that fence. Move comments above the fence as prose instead of
using the marker wherever the block is meant to be pasted.

Run: python3 -I -m unittest scripts/ci/tests/test_docs_shell_paste_safe_8311.py
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SHELL_LANGS = {"bash", "sh", "zsh", "console", "shell"}
MARKER = "# not-for-paste"
FENCE_RE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)")
HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def trailing_comment(line):
    """True when the command line has an unquoted ` #` comment."""
    quote = None
    depth = 0
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 1
            elif ch == quote:
                quote = None
        elif ch == "\\":
            i += 1
        elif ch in "'\"`":
            quote = ch
        elif line.startswith("$(", i) or line.startswith("${", i):
            depth += 1
            i += 1
        elif ch in ")}":
            depth = max(0, depth - 1)
        elif ch == "#" and depth == 0 and i > 0 and line[i - 1] in " \t":
            return True
        i += 1
    return False


def fences(text):
    """Yield (lang, first_body_line_no, [lines]) for each fenced block."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = FENCE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        marker, lang = m.group(2), m.group(3).lower()
        body = []
        j = i + 1
        while j < len(lines) and not lines[j].strip().startswith(marker):
            body.append(lines[j])
            j += 1
        yield lang, i + 2, body
        i = j + 1


def scan_block(first_no, body):
    """Return [(line_no, reason)] for one shell fence body."""
    if body and body[0].strip() == MARKER:
        return []
    kinds = []
    heredoc = None
    for off, raw in enumerate(body):
        no = first_no + off
        s = raw.strip()
        if heredoc:
            if s == heredoc:
                heredoc = None
            continue
        if not s:
            continue
        if s.startswith("#"):
            kinds.append((no, "comment", s))
            continue
        kinds.append((no, "command", s))
        m = HEREDOC_RE.search(s)
        if m:
            heredoc = m.group(2)
    if not any(k == "command" for _, k, _ in kinds):
        return []
    out = []
    for idx, (no, kind, s) in enumerate(kinds):
        if kind == "command":
            if trailing_comment(s):
                out.append((no, "trailing comment on a command line"))
        elif s.startswith("#!"):
            continue
        elif "`" in s or "$(" in s:
            out.append((no, "comment line holds a backtick or $("))
        else:
            before = any(k == "command" for _, k, _ in kinds[:idx])
            after = any(k == "command" for _, k, _ in kinds[idx + 1:])
            if before and after:
                out.append((no, "comment line between two commands"))
    return out


def scan_file(path):
    rel = path.relative_to(ROOT).as_posix()
    found = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for lang, first_no, body in fences(text):
        if lang in SHELL_LANGS:
            for no, why in scan_block(first_no, body):
                found.append("%s:%d: %s" % (rel, no, why))
    return found


def doc_files():
    files = [ROOT / "README.md"] + sorted((ROOT / "docs").rglob("*.md"))
    return [f for f in files if f.is_file()]


BASELINE = ROOT / "scripts" / "qc-allowlists" / "docs-shell-paste-baseline-8311.txt"
STRICT = ("docs/DEV-CI-ENVIRONMENT.md", "docs/DEVELOPER_SETUP_NOTES.md")


def read_baseline():
    """Parse `<count> <path>` lines; `#` lines are comments."""
    out = {}
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            n, rel = line.split(None, 1)
            out[rel] = int(n)
    return out


def current_counts():
    counts, detail = {}, {}
    for f in doc_files():
        hits = scan_file(f)
        rel = f.relative_to(ROOT).as_posix()
        if hits:
            counts[rel] = len(hits)
            detail[rel] = hits
    return counts, detail


class DocsShellPasteSafe8311(unittest.TestCase):
    """The two files named by #8311 must be clean; every other doc is held
    to a ratchet baseline that may only fall (thresholds rise, never fall)."""

    def test_8311_named_docs_are_paste_safe(self):
        _, detail = current_counts()
        found = [h for rel in STRICT for h in detail.get(rel, [])]
        self.assertEqual(
            found, [], "%d paste hazard(s):\n%s" % (len(found), "\n".join(found))
        )

    def test_8311_other_docs_do_not_regress(self):
        counts, _ = current_counts()
        base = read_baseline()
        for rel in STRICT:
            self.assertNotIn(rel, base, "%s must not be baselined" % rel)
        worse = [
            "%s: %d > baseline %d" % (rel, n, base.get(rel, 0))
            for rel, n in sorted(counts.items())
            if rel not in STRICT and n > base.get(rel, 0)
        ]
        self.assertEqual(worse, [], "new paste hazards:\n" + "\n".join(worse))
        stale = [
            "%s: baseline %d, now %d" % (rel, n, counts.get(rel, 0))
            for rel, n in sorted(base.items())
            if counts.get(rel, 0) < n
        ]
        self.assertEqual(
            stale, [], "lower the baseline (it only falls):\n" + "\n".join(stale)
        )

    def test_8311_scanner_flags_each_shape(self):
        body = ["a --x   # why", "# note", "b", "echo `x`", "# `y`", "# end"]
        got = {why for _, why in scan_block(1, body)}
        self.assertEqual(
            got,
            {
                "trailing comment on a command line",
                "comment line between two commands",
                "comment line holds a backtick or $(",
            },
        )

    def test_8311_scanner_ignores_safe_shapes(self):
        self.assertEqual(scan_block(1, ["# only a comment", "# another"]), [])
        self.assertEqual(scan_block(1, ["#!/bin/sh", "echo '# x' \"# y\" ${#v}"]), [])
        self.assertEqual(scan_block(1, ["cat <<E", "a # b", "E", "ls"]), [])
        self.assertEqual(scan_block(1, [MARKER, "a # b", "# c", "d"]), [])
        self.assertEqual(scan_block(1, ["# lead", "a", "b"]), [])


if __name__ == "__main__":
    unittest.main()
