#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3970: the C8 gate's enclosing-function key, derived from SCOPE.

Usage: c8-enclosing-fn-3970.py <file> <pattern> <lineno>...
Prints one `<lineno>\t<key>` line per requested line number.

<key> names the innermost function whose `{ ... }` body CONTAINS the first
code occurrence of `<pattern>(` on that line. It is qualified by every named
scope around it, outermost first: `mod`, `trait`, `impl <Type>` (the
implementing type, generics stripped, with `[Trait]` appended for a trait
impl so an inherent method and a trait method of one name differ), and
enclosing functions, joined by
`.` so the key never contains `:` (the allowlist entry is colon-delimited and
a literal may itself contain `:`). Examples:
`PostgresStore[MemoryStore].resolve_governance_policy`, `Foo.new`,
`outer.inner`. A site inside no
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
import re
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
    trait = None
    if last_for is not None:
        trait = path_last_ident(rest[:last_for])
        rest = rest[last_for + 1 :]
    name = path_last_ident(rest) or "<impl>"
    # f2r's #3970 review: an inherent impl and a trait impl on one type may
    # both define `get`; keyed `Type.get` alike, a site could move between
    # them silently. A trait impl is keyed `Type[Trait]`.
    return f"{name}[{trait}]" if trait else name


def path_last_ident(toks):
    """Last segment of the first type path in `toks`, generics ignored."""
    name = None
    j = 0
    while j < len(toks) and (toks[j] in ("&", "mut", "dyn", "(", "!") or toks[j].startswith("'")):
        j += 1
    while j < len(toks) and is_ident_start(toks[j][0]):
        name = toks[j]
        if j + 1 < len(toks) and toks[j + 1] == "::":
            j += 2
            continue
        break
    return name


def scan(text, method, literal_only=False):
    """Find every site of `<anything>::<method>` in code.

    Returns `(sites, renames)`. `sites` is a list of `(line, key, arg)`, one
    per CALL (two calls on one line are two sites); `arg` is the normalised
    first argument, or `<unparsed>` for a bare function-item reference such as
    `let mk = CallerContext::for_admin;`. `renames` lists the lines of a
    `CallerContext as <alias>` renaming import.

    #4020: the gate used to find sites by the TEXT `CallerContext::for_admin(`,
    so `use ..::CallerContext as Cc; Cc::for_admin(x)` and a fn-item reference
    both escaped it. Any path prefix counts here (`Cc::`, `Self::`, `<T>::`).
    With `literal_only` (the for_agent literal gate) only a call whose first
    argument starts with a string literal is a site, as before.
    """
    n = len(text)
    i = 0
    line = 1
    stack = []  # entries: (kind, name, paren_depth_at_open)
    paren = 0
    # [kind, name_or_tokens, paren_depth, brace_depth, angle_depth]. A header's
    # body opens only at the header's own paren AND brace depth, and only
    # when no `<` it opened is still unclosed: a const-generic argument
    # `Gk<{ .. }>` is otherwise mistaken for the body (tmux-22's G3/G4).
    pending = None
    prev = None  # previous significant token
    sites = []
    renames = []
    # A bare reference to the checked constructor is how an alias would dodge
    # #3943's `for_admin_checked(.., <literal>)` matcher, so it is a
    # for_admin site too (keyed `<unparsed>`). Its CALLS stay #3943's.
    ref_only = {"for_admin_checked"} if method == "for_admin" else set()

    def key():
        # Anonymous scopes are not in the key, so a fn inside an ITEM-LEVEL
        # anonymous block (a const/static initializer `= { .. }`, a
        # `macro_rules!` body, an item-level macro invocation) would key
        # exactly like a top-level fn of the same name. That was tmux-22's
        # G1/G2 retest gap on #3970. Such a fn is keyed `<unparsed>` (fail
        # closed, which blocks). A block INSIDE a fn body is ordinary control
        # flow; a helper fn nested there keeps its `outer.inner` key.
        names = []
        innermost_fn = -1
        seen_fn = False
        item_block = False
        for kind, name, _depth in stack:
            if kind == "block":
                if not seen_fn:
                    item_block = True
                continue
            if kind == "fn":
                if item_block:
                    return UNPARSED
                seen_fn = True
            names.append((kind, name))
            if kind == "fn":
                innermost_fn = len(names) - 1
        if innermost_fn < 0:
            return TOP
        return ".".join(name for _, name in names[: innermost_fn + 1])

    def in_header(pend):
        # A token belongs to the pending header only at the header's own
        # paren and brace depth; anything nested (a const expression inside
        # `{ .. }`, a parenthesised argument list) is not part of it.
        return pend is not None and pend[2] == paren and pend[3] == len(stack)

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

        # Sites (#4020): a code token `<method>` right after `::`.
        if prev == "::" and (tok == method or tok in ref_only):
            arg = first_arg(text, i)
            if tok in ref_only:
                if arg is None:
                    sites.append((line, key(), UNPARSED))
            elif arg is None:
                if not literal_only:
                    sites.append((line, key(), UNPARSED))
            elif not literal_only or arg.lstrip().startswith('"'):
                sites.append((line, key(), normalise_arg(arg)))
        elif tok == "as" and prev == "CallerContext":
            renames.append(line)

        # Structure.
        if tok == "fn" and pending is None:
            j = skip_ws_comments(i)
            if j < n and is_ident_start(text[j]):
                end = j
                while end < n and is_ident_char(text[end]):
                    end += 1
                pending = ["fn", text[j:end], paren, len(stack), 0]
                i = end
                prev = "<fnname>"
                continue
        elif tok in ("impl", "trait", "mod") and pending is None and prev in (
            None, ";", "}", "{", "]", "unsafe", "default", "pub", "auto", ")",
        ):
            if tok == "impl":
                pending = ["impl", [], paren, len(stack), 0]
            else:
                j = skip_ws_comments(i)
                end = j
                while end < n and is_ident_char(text[end]):
                    end += 1
                if end > j:
                    pending = [tok, text[j:end], paren, len(stack), 0]
                    i = end
                    prev = "<itemname>"
                    continue
        elif tok in ("(", "["):
            paren += 1
        elif tok in (")", "]"):
            paren -= 1
        elif tok in ("<", ">") and in_header(pending):
            # `->` and `=>` are separate two-char tokens, so a bare `>` here
            # only ever closes a generic.
            pending[4] = pending[4] + 1 if tok == "<" else max(0, pending[4] - 1)
        elif tok == "{":
            if in_header(pending) and pending[4] == 0:
                kind, name = pending[0], pending[1]
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
        elif tok == ";" and in_header(pending):
            pending = None
        if pending is not None and pending[0] == "impl" and tok not in ("impl", "{"):
            pending[1].append(tok)
        prev = tok
    if stack or paren != 0:
        raise LexError("unbalanced at end of file")
    return sites, renames


def first_arg(text, k):
    """Source text of the first argument of a call whose name ends at `k`,
    or None when no `(` follows (a function-item reference). Literals and
    comments are skipped the same way the main lexer skips them, so a `,` or
    `)` inside one never ends the argument."""
    n = len(text)

    def skip_trivia(j):
        while j < n:
            if text[j].isspace():
                j += 1
            elif text.startswith("//", j):
                while j < n and text[j] != "\n":
                    j += 1
            elif text.startswith("/*", j):
                depth = 0
                while j < n:
                    if text.startswith("/*", j):
                        depth, j = depth + 1, j + 2
                    elif text.startswith("*/", j):
                        depth, j = depth - 1, j + 2
                        if depth == 0:
                            break
                    else:
                        j += 1
            else:
                break
        return j

    j = skip_trivia(k)
    if j >= n or text[j] != "(":
        return None
    j += 1
    start = j
    depth = 0
    while j < n:
        ch = text[j]
        if ch == '"':
            j += 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            j += 1
            continue
        if ch == "r" and text[j + 1 : j + 2] in ('"', "#") and not is_ident_char(text[j - 1]):
            h = j + 1
            while h < n and text[h] == "#":
                h += 1
            if h < n and text[h] == '"':
                close = '"' + "#" * (h - j - 1)
                end = text.find(close, h + 1)
                j = n if end < 0 else end + len(close)
                continue
        if ch == "'" and j + 2 < n and (text[j + 1] == "\\" or text[j + 2] == "'"):
            # A char literal (`'x'`, `'\''`, `'\u{..}'`); a lifetime is left
            # to the default arm, which just steps over the `'`.
            j += 1
            while j < n and text[j] != "'":
                j += 2 if text[j] == "\\" else 1
            j += 1
            continue
        if text.startswith("//", j) or text.startswith("/*", j):
            j = skip_trivia(j)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return text[start:j]
            depth -= 1
        elif ch == "," and depth == 0:
            return text[start:j]
        j += 1
    return ""


def normalise_arg(arg):
    """The #3965 key for a first argument, byte-identical to the old gate:
    whitespace removed, one leading `&` dropped, a pure string literal is its
    content, a pure path is its last `::` segment, anything else verbatim.
    An empty argument is `<unparsed>`."""
    expr = re.sub(r"\s+", "", arg)
    if expr.startswith("&"):
        expr = expr[1:]
    if not expr:
        return UNPARSED
    lit = re.fullmatch(r'"([^"\\]*)"', expr)
    if lit:
        return lit.group(1)
    if re.fullmatch(r"[A-Za-z0-9_:]+", expr):
        return expr.split("::")[-1]
    return expr


def main():
    """`c8-enclosing-fn-3970.py <file> <method> <literal|any-arg>`, with the
    file's PRODUCTION text (test regions blanked, line numbers preserved) on
    stdin. Prints `site\t<line>\t<fn key>\t<arg>` per call and
    `rename\t<line>` per `CallerContext as` import, on production lines only.
    A file that does not lex yields one `<unparsed>` site, which blocks."""
    path, method, mode = sys.argv[1], sys.argv[2], sys.argv[3]
    production = sys.stdin.read().split("\n")

    def is_production(ln):
        return 0 < ln <= len(production) and production[ln - 1].strip() != ""

    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            sites, renames = scan(fh.read(), method, literal_only=(mode == "literal"))
    except (OSError, LexError) as e:
        print(f"site\t0\t{UNPARSED}\t{UNPARSED}")
        print(f"lexerror\t{e}", file=sys.stderr)
        return
    for ln, key, arg in sites:
        if is_production(ln):
            print(f"site\t{ln}\t{key}\t{arg}")
    for ln in renames:
        if is_production(ln):
            print(f"rename\t{ln}")


if __name__ == "__main__":
    main()
