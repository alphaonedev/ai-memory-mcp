#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3970: the C8 gate's enclosing-function key, derived from SCOPE.

Usage: c8-enclosing-fn-3970.py <file> <pattern> <lineno>...
Prints one `<lineno>\t<key>` line per requested line number.

<key> names the innermost function whose `{ ... }` body CONTAINS the first
code occurrence of `<pattern>(` on that line. It is qualified by every named
scope around it, outermost first: `mod`, `trait`, `impl <Type>` (the
implementing type, generics stripped), and enclosing functions, joined by
`.` so the key never contains `:` (the allowlist entry is colon-delimited and
a literal may itself contain `:`). Examples:
`PostgresStore.resolve_governance_policy`, `outer.inner`. A site inside no
function is `<top>`.

Why a lexer: the first #3970 cut took "the nearest preceding `fn <name>`"
from the raw text. A comment, a string literal, or a nested item containing
`fn <approved_name>` placed between a moved site and its real function then
re-keyed the site to the approved function (f2r's review of 58a916fa1). Here
comments (nested `/* */` included), string, raw-string, byte-string and char
literals are skipped, and scope comes from a brace stack, so only real
function bodies can contain a site.

Fail closed (the #3965 precedent): if the file does not lex (an unterminated
literal or comment, or unbalanced braces), or if the requested line has no
code occurrence of `<pattern>(`, the key is `<unparsed>`. The gate treats that
as a site it cannot license, so it blocks.
"""
import sys

UNPARSED = "<unparsed>"
TOP = "<top>"


def is_ident_start(ch):
    return ch.isalpha() or ch == "_"


def is_ident_char(ch):
    return ch.isalnum() or ch == "_"


class LexError(Exception):
    pass


def impl_type_name(toks):
    """The implementing type of an `impl` header's tokens (after `impl`)."""
    i = 0
    # Skip the impl's own generic parameters: `impl<T: Bound> ...`.
    if i < len(toks) and toks[i] == "<":
        depth = 0
        while i < len(toks):
            if toks[i] == "<":
                depth += 1
            elif toks[i] == ">":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
    rest = toks[i:]
    # Cut the `where` clause, then keep what follows a top-level `for`.
    depth = 0
    cut = len(rest)
    last_for = None
    for j, t in enumerate(rest):
        if t == "<":
            depth += 1
        elif t == ">":
            depth -= 1
        elif depth == 0 and t == "where":
            cut = j
            break
        elif depth == 0 and t == "for":
            last_for = j
    rest = rest[:cut]
    if last_for is not None:
        rest = rest[last_for + 1 :]
    name = None
    j = 0
    while j < len(rest) and rest[j] in ("&", "mut", "dyn", "(", "!") or (
        j < len(rest) and rest[j].startswith("'")
    ):
        j += 1
    while j < len(rest) and is_ident_start(rest[j][0]):
        name = rest[j]
        if j + 1 < len(rest) and rest[j + 1] == "::":
            j += 2
            continue
        break
    return name or "<impl>"


def scan(text, pattern):
    """Map each line holding a code occurrence of `pattern(` to its key."""
    n = len(text)
    i = 0
    line = 1
    stack = []  # entries: (kind, name, paren_depth_at_open)
    paren = 0
    pending = None  # ("fn"|"impl"|"trait"|"mod", name_or_tokens, paren_depth)
    prev = None  # previous significant token
    sites = {}
    call = pattern + "("

    def key():
        names = []
        innermost_fn = -1
        for idx, (kind, name, _) in enumerate(stack):
            if kind != "block":
                names.append((kind, name))
                if kind == "fn":
                    innermost_fn = len(names) - 1
        if innermost_fn < 0:
            return TOP
        return ".".join(name for _, name in names[: innermost_fn + 1])

    def skip_ws_comments(k):
        nonlocal line
        while k < n:
            ch = text[k]
            if ch == "\n":
                line += 1
                k += 1
            elif ch.isspace():
                k += 1
            elif text.startswith("//", k):
                while k < n and text[k] != "\n":
                    k += 1
            elif text.startswith("/*", k):
                k = skip_block_comment(k)
            else:
                break
        return k

    def skip_block_comment(k):
        nonlocal line
        depth = 0
        while k < n:
            if text.startswith("/*", k):
                depth += 1
                k += 2
            elif text.startswith("*/", k):
                depth -= 1
                k += 2
                if depth == 0:
                    return k
            else:
                if text[k] == "\n":
                    line += 1
                k += 1
        raise LexError("unterminated block comment")

    def skip_string(k):
        # k at the opening quote of an escaped string.
        nonlocal line
        k += 1
        while k < n:
            ch = text[k]
            if ch == "\\":
                if k + 1 < n and text[k + 1] == "\n":
                    line += 1
                k += 2
                continue
            if ch == "\n":
                line += 1
            if ch == '"':
                return k + 1
            k += 1
        raise LexError(f"unterminated string from line {line}")

    def skip_raw_string(k):
        # k just past the `r`; at zero or more `#` then `"`.
        nonlocal line
        hashes = 0
        while k < n and text[k] == "#":
            hashes += 1
            k += 1
        if k >= n or text[k] != '"':
            raise LexError("malformed raw string")
        close = '"' + "#" * hashes
        end = text.find(close, k + 1)
        if end < 0:
            raise LexError("unterminated raw string")
        line += text.count("\n", k, end)
        return end + len(close)

    def skip_char_or_lifetime(k):
        # k at `'`. A char literal is `'\...'` or `'x'`; otherwise a lifetime
        # or loop label, which is `'` followed by an identifier.
        if k + 1 < n and text[k + 1] == "\\":
            # `'\''`, `'\n'`, `'\u{1F600}'`: an escape consumes the character
            # after the backslash, so an escaped quote does not close it.
            end = k + 1
            while end < n:
                c = text[end]
                if c == "\\":
                    end += 2
                elif c == "'":
                    return end + 1, "char"
                elif c == "\n":
                    break
                else:
                    end += 1
            raise LexError(f"unterminated char literal at line {line}")
        if k + 2 < n and text[k + 2] == "'" and text[k + 1] != "\n":
            return k + 3, "char"
        end = k + 1
        while end < n and is_ident_char(text[end]):
            end += 1
        return end, "lifetime"

    while True:
        i = skip_ws_comments(i)
        if i >= n:
            break
        ch = text[i]
        tok = None
        # Literals with a prefix: r"", r#""#, b"", br"", c"", cr"", b'x'.
        if ch in "rbc" and i + 1 < n:
            if ch == "r" and text[i + 1] in '"#':
                if text[i + 1] == "#" and i + 2 < n and is_ident_start(text[i + 2]):
                    # Raw identifier r#name.
                    end = i + 2
                    while end < n and is_ident_char(text[end]):
                        end += 1
                    tok = text[i + 2 : end]
                    i = end
                else:
                    i = skip_raw_string(i + 1)
                    prev = "<lit>"
                    continue
            elif ch in "bc" and text[i + 1] == "r" and i + 2 < n and text[i + 2] in '"#':
                i = skip_raw_string(i + 2)
                prev = "<lit>"
                continue
            elif ch in "bc" and text[i + 1] == '"':
                i = skip_string(i + 1)
                prev = "<lit>"
                continue
            elif ch == "b" and text[i + 1] == "'":
                i, _ = skip_char_or_lifetime(i + 1)
                prev = "<lit>"
                continue
        if tok is None:
            if ch == '"':
                i = skip_string(i)
                prev = "<lit>"
                continue
            if ch == "'":
                i, kind = skip_char_or_lifetime(i)
                prev = "<lit>" if kind == "char" else "'lt"
                if pending and pending[0] == "impl":
                    pending[1].append("'lt")
                continue
            if is_ident_start(ch):
                if text.startswith(call, i) and line not in sites:
                    sites[line] = key()
                end = i
                while end < n and is_ident_char(text[end]):
                    end += 1
                tok = text[i:end]
                i = end
            elif ch.isdigit():
                end = i
                while end < n and (is_ident_char(text[end]) or text[end] == "."):
                    if text[end] == "." and not (end + 1 < n and text[end + 1].isdigit()):
                        break
                    end += 1
                i = end
                prev = "<lit>"
                continue
            else:
                two = text[i : i + 2]
                if two in ("::", "->", "=>"):
                    tok = two
                    i += 2
                else:
                    tok = ch
                    i += 1

        # Structure.
        if tok == "fn" and pending is None:
            j = skip_ws_comments(i)
            if j < n and is_ident_start(text[j]):
                end = j
                while end < n and is_ident_char(text[end]):
                    end += 1
                pending = ("fn", text[j:end], paren)
                i = end
                prev = "<fnname>"
                continue
        elif tok in ("impl", "trait", "mod") and pending is None and prev in (
            None, ";", "}", "{", "]", "unsafe", "default", "pub", "auto", ")",
        ):
            if tok == "impl":
                pending = ("impl", [], paren)
            else:
                j = skip_ws_comments(i)
                end = j
                while end < n and is_ident_char(text[end]):
                    end += 1
                if end > j:
                    pending = (tok, text[j:end], paren)
                    i = end
                    prev = "<itemname>"
                    continue
        elif tok in ("(", "["):
            paren += 1
        elif tok in (")", "]"):
            paren -= 1
        elif tok == "{":
            if pending is not None and pending[2] == paren:
                kind, name, _ = pending
                if kind == "impl":
                    name = impl_type_name(name)
                stack.append((kind, name, paren))
                pending = None
            else:
                stack.append(("block", None, paren))
        elif tok == "}":
            if not stack:
                raise LexError(f"unbalanced }} at line {line}")
            stack.pop()
        elif tok == ";" and pending is not None and pending[2] == paren:
            pending = None
        if pending is not None and pending[0] == "impl" and tok not in ("impl", "{"):
            pending[1].append(tok)
        prev = tok
    if stack or paren != 0:
        raise LexError("unbalanced at end of file")
    return sites


def main():
    path, pattern = sys.argv[1], sys.argv[2]
    wanted = [int(x) for x in sys.argv[3:]]
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            sites = scan(fh.read(), pattern)
    except (OSError, LexError):
        sites = {}
    for ln in wanted:
        print(f"{ln}\t{sites.get(ln, UNPARSED)}")


if __name__ == "__main__":
    main()
