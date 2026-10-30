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

A leading `#!` line, a comment-only fence whose comments hold no backtick
or `$(` (class (b) is still flagged there; class (c) needs commands on both
sides), and the text of a heredoc body are not flagged. A heredoc operator
inside quotes or `$(( ))`, a here-string `<<<` and an arithmetic shift do not
open a heredoc (nor does `$[ ]`); a heredoc ends only on its exact terminator
line (fence indent removed, `<<-` tabs removed; the delimiter word is parsed
whole, quotes and backslashes dropped); a heredoc whose terminator never appears before the closing
fence is not trusted: its would-be body is scanned as normal lines.

OPT-OUT MARKER (one, explicit): a fence whose FIRST line is exactly
`# not-for-paste` is documentation of a script body, not a paste target; the
guard skips that fence. Move comments above the fence as prose instead of
using the marker wherever the block is meant to be pasted.

Run: python3 -I -m unittest discover -s scripts/ci/tests -p test_docs_shell_paste_safe_8311.py
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
SHELL_LANGS = {"bash", "sh", "zsh", "console", "shell"}
MARKER = "# not-for-paste"
FENCE_RE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*([A-Za-z0-9_+-]*)")
HEREDOC_RE = re.compile(r"(?<!<)<<(?!<)(-?)[ \t]*(?=[A-Za-z_'\"\\])")
WORD_END = " \t;&|<>()"


def parse_heredoc_word(line, start):
    """Parse the delimiter word at `start`: it runs to whitespace or a shell
    metachar outside quotes, and quote characters and backslashes are dropped
    (`E"OF"` and `\\EOF` both give `EOF`, as in bash). Returns the word."""
    out = []
    quote = None
    i = start
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == quote:
                quote = None
            else:
                out.append(ch)
        elif ch in "'\"":
            quote = ch
        elif ch == "\\":
            i += 1
            if i < len(line):
                out.append(line[i])
        elif ch in WORD_END:
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def heredoc_word(line):
    """Return (terminator word, strips_tabs) opened by `line`, else None.

    Quote, `$(( ))` and legacy `$[ ]` tracking mirrors `trailing_comment`: an
    operator inside quotes or arithmetic is not a heredoc; `<<<` is a
    here-string. `strips_tabs` is True for the `<<-` form."""
    quote = None
    arith = 0
    brk = 0
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
        elif line.startswith("((", i):
            arith += 1
            i += 1
        elif line.startswith("))", i) and arith:
            arith -= 1
            i += 1
        elif line.startswith("$[", i):
            brk += 1
            i += 1
        elif ch == "[" and brk:
            brk += 1
        elif ch == "]" and brk:
            brk -= 1
        elif line.startswith("<<", i) and not arith and not brk:
            m = HEREDOC_RE.match(line, i)
            if m:
                word = parse_heredoc_word(line, m.end())
                if word:
                    return word, bool(m.group(1))
            i += 1
        i += 1
    return None


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
    """Yield (lang, first_body_line_no, [lines], fence_indent) per block."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = FENCE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        indent, marker, lang = m.group(1), m.group(2), m.group(3).lower()
        body = []
        j = i + 1
        while j < len(lines) and not lines[j].strip().startswith(marker):
            body.append(lines[j])
            j += 1
        yield lang, i + 2, body, indent
        i = j + 1


def ends_heredoc(raw, word, strips_tabs, indent):
    """True when `raw` is the exact terminator line of a heredoc: at most the
    fence indent is removed, then (for `<<-`) leading tabs only."""
    if indent and raw.startswith(indent):
        raw = raw[len(indent):]
    if strips_tabs:
        raw = raw.lstrip("\t")
    return raw == word


def scan_block(first_no, body, indent=""):
    """Return [(line_no, reason)] for one shell fence body."""
    if body and body[0].strip() == MARKER:
        return []
    kinds = []
    skip_to = -1
    for off, raw in enumerate(body):
        no = first_no + off
        s = raw.strip()
        if off <= skip_to or not s:
            continue
        if s.startswith("#"):
            kinds.append((no, "comment", s))
            continue
        kinds.append((no, "command", s))
        opened = heredoc_word(s)
        if opened:
            word, strips_tabs = opened
            for end in range(off + 1, len(body)):
                if ends_heredoc(body[end], word, strips_tabs, indent):
                    skip_to = end
                    break
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
    for lang, first_no, body, indent in fences(text):
        if lang in SHELL_LANGS:
            for no, why in scan_block(first_no, body, indent):
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
        # S1: class (b) in a comment-only fence.
        self.assertEqual(len(scan_block(1, ["# run `id` first"])), 1)
        self.assertEqual(len(scan_block(1, ["# a", "# $(id)"])), 1)
        # S2/F2: a false heredoc must not hide the next line's hazard.
        for first in (
            "cat <<<word",
            "echo $((1<<FOO))",
            'echo "<<EOF"',
            "echo '<<EOF'",
        ):
            self.assertEqual(len(scan_block(1, [first, "a # b"])), 1, first)
        # An unterminated heredoc is rescanned as normal lines.
        self.assertEqual(len(scan_block(1, ["cat <<EOF", "a # b"])), 1)
        # `<<\EOF` is a quoted-word heredoc: its body is not flagged.
        self.assertEqual(scan_block(1, ["cat <<\\EOF", "a # b", "EOF", "ls"]), [])

    def test_8311_heredoc_ends_only_on_exact_terminator(self):
        # S3: an indented or space-padded line is not a terminator, so the
        # second heredoc stays inside the first and the hazard is seen.
        pad_in = ["data <<X", "EOF", "ls # hazard", "X"]
        for opener, mid in (
            ("cat <<EOF", " EOF"),
            ("cat <<EOF", "EOF "),
            ('cat <<E"OF"', "E"),
            ('cat <<E"OF"', " EOF"),
        ):
            body = [opener, mid] + pad_in
            self.assertEqual(len(scan_block(1, body)), 1, body)
        # An unterminated heredoc is rescanned (the padded line is a command).
        self.assertEqual(len(scan_block(1, ["cat <<EOF", " EOF", "ls # hazard"])), 1)
        # S4: legacy `$[ ]` arithmetic opens no heredoc.
        self.assertEqual(len(scan_block(1, ["echo $[1<<FOO]", "ls # hazard", "FOO"])), 1)

    def test_8311_heredoc_terminator_forms_stay_clean(self):
        # A list-indented fence: the terminator carries only the fence indent.
        self.assertEqual(
            scan_block(1, ["cat <<EOF", "a # b", "  EOF", "ls"], "  "), []
        )
        # `EOFX` never ends an `EOF` heredoc; quoted words reduce to `EOF`.
        self.assertEqual(scan_block(1, ["cat <<EOF", "a # b", "EOFX", "EOF", "ls"]), [])
        self.assertEqual(scan_block(1, ['cat <<E"OF"', "a # b", "EOF", "ls"]), [])
        # `<<-` strips leading tabs only.
        self.assertEqual(scan_block(1, ["cat <<-EOF", "a # b", "\t\tEOF", "ls"]), [])

    def test_8311_scanner_ignores_safe_shapes(self):
        self.assertEqual(scan_block(1, ["# only a comment", "# another"]), [])
        self.assertEqual(scan_block(1, ["#!/bin/sh", "echo '# x' \"# y\" ${#v}"]), [])
        self.assertEqual(scan_block(1, ["cat <<E", "a # b", "E", "ls"]), [])
        self.assertEqual(scan_block(1, [MARKER, "a # b", "# c", "d"]), [])
        self.assertEqual(scan_block(1, ["# lead", "a", "b"]), [])


if __name__ == "__main__":
    unittest.main()
