#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
#
# #3943 — detect a LITERAL bool in the SECOND argument of
# `CallerContext::for_admin_checked(<caller>, <is_admin>)`.
#
# Why this is a defect (not tidiness): the #1062 constructor's second
# argument is the admin-gate result. When it is threaded from a
# `require_admin` Ok arm (`let (caller, is_admin) = match .. { Ok(c) =>
# (c, true), .. }`), deleting or moving the gate leaves `is_admin`
# undefined — a COMPILE error. A free-standing literal (`.., true`) still
# compiles after the gate is removed, silently yielding an admin-bypass
# context. So the guard keys on the SECOND ARGUMENT being a `true`/`false`
# literal, NOT on a bare `true` token (the blessed `Ok(c) => (c, true)`
# gate shape must PASS).
#
# Input : the file's PRODUCTION lines on stdin (test items already blanked
#         by scripts/lib/production-lines.sh, line numbers preserved).
# Argv  : argv[1] = repo-root-relative path, for the finding line.
# Output: one `path:lineno: ...` finding per literal second argument.
#         Exit 0 always — the caller (qc-codegraph-precheck.sh) decides the
#         HARD-BLOCK; this tool only reports.
#
# Requirements it satisfies (f2r 3943 pre-review §5 + addendum):
#   (a) keys on the SECOND ARGUMENT, so `for_admin_checked(caller, is_admin)`
#       and the gate's own `Ok(c) => (c, true)` never trip it;
#   (b) paren-aware + multi-line — balances parens and splits on TOP-LEVEL
#       commas, so `for_admin_checked(caller.clone(), true)` (inner parens)
#       and rustfmt-wrapped calls are parsed correctly;
#   (c) skips comment lines and trailing `// ...` comments, so prose that
#       spells the pattern is not flagged.

import sys

KEY = "for_admin_checked("
COMMENT_LINE_STARTS = ("//", "///", "//!", "*", "/*")
OPENERS = "([{"
CLOSERS = ")]}"


def strip_trailing_comment(text: str) -> str:
    """Drop a trailing `// ...` line comment. Best-effort: not string-aware,
    which is safe here because a for_admin_checked argument list never
    contains `//` inside a string literal in this codebase."""
    idx = text.find("//")
    return text[:idx] if idx >= 0 else text


def is_comment_line(line: str) -> bool:
    return line.lstrip().startswith(COMMENT_LINE_STARTS)


def top_level_args(argstr: str):
    """Split an argument list on TOP-LEVEL commas (depth 0)."""
    args, cur, depth = [], [], 0
    for ch in argstr:
        if ch in OPENERS:
            depth += 1
            cur.append(ch)
        elif ch in CLOSERS:
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        args.append("".join(cur))
    return args


def find_literal_sites(lines):
    findings = []
    n = len(lines)
    i = 0
    while i < n:
        line = lines[i]
        if is_comment_line(line):
            i += 1
            continue
        pos = line.find(KEY)
        if pos < 0:
            i += 1
            continue
        # KEY after a `//` on this line is prose, not a call.
        cpos = line.find("//")
        if 0 <= cpos < pos:
            i += 1
            continue

        # Capture the balanced argument list from the '(' of KEY, across
        # lines, skipping comment-only continuation lines and stripping any
        # trailing `// ...` from each captured chunk.
        open_at = pos + len(KEY) - 1  # index of '('
        chunks = [strip_trailing_comment(line[open_at:])]

        def depth(chs):
            code = "".join(chs)
            return code.count("(") - code.count(")")

        j = i
        while depth(chunks) > 0 and j + 1 < n:
            j += 1
            nxt = lines[j]
            if is_comment_line(nxt):
                continue
            chunks.append("\n" + strip_trailing_comment(nxt))

        blob = "".join(chunks)  # starts at '('
        # Extract the balanced arg list between the first '(' and its match.
        d, argstr = 0, None
        for k, ch in enumerate(blob):
            if ch == "(":
                d += 1
            elif ch == ")":
                d -= 1
                if d == 0:
                    argstr = blob[1:k]
                    break

        if argstr is not None:
            args = top_level_args(argstr)
            if len(args) >= 2 and args[1].strip() in ("true", "false"):
                findings.append((i + 1, args[1].strip()))

        i = j + 1 if j > i else i + 1
    return findings


def main() -> int:
    rel = sys.argv[1] if len(sys.argv) > 1 else "<stdin>"
    lines = sys.stdin.read().splitlines()
    for lineno, val in find_literal_sites(lines):
        print(f"{rel}:{lineno}: for_admin_checked(.., {val}) literal second argument")
    return 0


if __name__ == "__main__":
    sys.exit(main())
