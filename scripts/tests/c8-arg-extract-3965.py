#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3965 follow-up (Codex review): paren-balanced argument extraction for the C8 gate.

Usage: c8-arg-extract-3965.py <file> <lineno> <pattern>
Prints the FIRST argument of the first `<pattern>(` call that starts on line
<lineno> of <file>, read across up to 25 following lines, whitespace-collapsed,
with one leading `&` removed and a pure path reduced to its last `::` segment
(the same normalisation the regex path applies). Prints `<unparsed>` when the
call cannot be read. The gate never discards a call it cannot parse: a candidate
it cannot key is a site it cannot license, so it must fail CLOSED.
"""
import re
import sys

path, lineno, pattern = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().split("\n")
except OSError:
    print("<unparsed>")
    sys.exit(0)
text = "\n".join(lines[lineno - 1 : lineno + 24])
start = text.find(pattern + "(")
if start < 0:
    print("<unparsed>")
    sys.exit(0)
i = start + len(pattern) + 1
depth, arg, in_str, esc = 0, [], False, False
while i < len(text):
    ch = text[i]
    if in_str:
        arg.append(ch)
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == '"':
            in_str = False
    elif ch == '"':
        in_str = True
        arg.append(ch)
    elif ch in "([{":
        depth += 1
        arg.append(ch)
    elif ch in ")]}":
        if depth == 0:
            break
        depth -= 1
        arg.append(ch)
    elif ch == "," and depth == 0:
        break
    else:
        arg.append(ch)
    i += 1
else:
    print("<unparsed>")
    sys.exit(0)
expr = re.sub(r"\s+", "", "".join(arg))
if expr.startswith("&"):
    expr = expr[1:]
if not expr:
    print("<unparsed>")
elif re.fullmatch(r"[A-Za-z0-9_:]+", expr):
    print(expr.split("::")[-1])
else:
    print(expr)
