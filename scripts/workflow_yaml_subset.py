#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Standard-library, fail-closed reader for the subset of workflow YAML this repository uses.

The reader was written for scripts/test/test_workflow_pr_triggers_5447.py (#5447), where it
was differential-tested against PyYAML 6.0.1 yaml.SafeLoader (see that file's docstring for
the grammar and the differential runs).  It lives here so the verifier
scripts/check_carrier_ruleset_live.py reads workflow files with the SAME grammar instead of
regular expressions (#6481, #6482, #6542, #6543, #6545): a construct the reader does not model
(anchor, alias, merge key, tab, a second document, a duplicate key in a block or a flow mapping,
BOM, NEL and the other exotic line breaks, a quoted key below the top level, a flow collection
that does not close on its row) raises ``Unparsed`` and the caller fails closed.  ``parse_workflow`` prefixes the
message with ``line N:``.  The functions from ``Unparsed`` to ``_check_top_level`` are moved
from the test unchanged, except that ``_meaningful`` takes an optional ``detail`` list (one
record per row) that the tree reader at the end of this file uses.

The reader is the Python standard library only; no PyYAML is imported.
"""
from __future__ import annotations

import bisect
import re
import unicodedata
from typing import Dict, List, Optional, Set, Tuple


class Unparsed(Exception):
    """Raised when the reader cannot interpret a trigger (a FAILURE, never a skip).

    The message is passed through ``mask`` (#6681), so no refusal reprints a GitHub-token-shaped
    string or the literal value of a credential-named key, whichever site built it.
    """

    def __init__(self, *args: object) -> None:
        super().__init__(*(mask(a) if isinstance(a, str) else a for a in args))


# #6681: a refusal or problem reprints at most ECHO_LIMIT characters of a workflow row or value, with
# every GitHub-token-shaped string masked and the literal value of a credential-named key withheld.
# #6735 #6738: a credential value is withheld to the end of its row, whatever characters it holds (``,``
# ``#`` ``]`` ``}`` and quotes are all part of it); only a value that is exactly one ``${{ ... }}``
# expression with no quote inside is kept, because such a value names a source and is not a literal.
ECHO_LIMIT = 120
# #6736 #6737: no word boundary, so a token glued after a letter, digit, ``_`` or ``%3A`` is masked too.
# #6791: a prefix whose body is cut short by the end of the masked text is masked too, so a token cut by the
# mask window of ``clip`` never prints up to seven body characters.
_TOKEN_SHAPE = re.compile(r"(gh[pousr]_|github_pat_)(?:[A-Za-z0-9_]{8,}|[A-Za-z0-9_]*\Z)")
# A key (a word, optionally quoted) and its ``:`` or ``=``; the lookbehind starts a match only at the
# start of a word, so the scan is linear in the text (no nested backtracking).
_PAIR_KEY = re.compile(r"(?<![\w.-])([\w.-]+)['\"]?[ \t]*[:=][ \t]*")
# #6739: the credential vocabulary (substring match on the key name, any letter case).
_CREDENTIAL_WORD = re.compile(
    r"token|secret|pass|pwd|credential|api[_-]?key|private[_-]?key|access[_-]?key|auth|bearer|session|cookie|signing",
    re.IGNORECASE)
_PAIR_VALUE = re.compile(r"[^\n]+")
# #6782: the kept expression holds only context references (``github.token``, ``needs.a.outputs.b``) joined by
# ``||`` ``&&`` ``==`` ``!=``, with ``!`` and parentheses; a number, ``true``, ``false``, ``null``, ``NaN`` or
# ``Infinity`` operand can be a literal credential, so it is withheld.  Each repeated part starts with a
# distinct character, so the match is linear in the row.
_CONTEXT_REF = r"(?!(?i:true|false|null|nan|infinity)\b)[A-Za-z_][\w.-]*"
_OPERAND = r"(?:[!(][ \t]*)*" + _CONTEXT_REF + r"(?:[ \t]*\))*"
_EXPRESSION_VALUE = re.compile(
    r"['\"]?\$\{\{[ \t]*" + _OPERAND + r"(?:[ \t]*(?:\|\||&&|==|!=)[ \t]*" + _OPERAND + r")*[ \t]*\}\}['\"]*[ \t]*(?=\n|\Z)")
# #6792: ``mask`` keeps a value only when it is exactly one marker that ``mask`` itself wrote, which always runs
# to the end of its row, so a committed value that merely starts with that text is withheld like any other.
_WITHHELD_MARK = re.compile(r"<withheld \d+ chars>[ \t]*(?=\n|\Z)")


def is_credential_key(name: str) -> bool:
    """True when ``name`` is credential-named, so the value under it is withheld (#6735, #6739)."""
    return _CREDENTIAL_WORD.search(name) is not None


def mask(text: str) -> str:
    """``text`` with credential-named values withheld and token-shaped strings masked (idempotent, #6681)."""
    out: List[str] = []
    pos = 0
    for key in _PAIR_KEY.finditer(text):
        if key.start() < pos or not is_credential_key(key.group(1)):
            continue
        if _WITHHELD_MARK.match(text, key.end()) or _EXPRESSION_VALUE.match(text, key.end()):
            continue
        val = _PAIR_VALUE.match(text, key.end())
        if val is None:
            continue
        out.append(text[pos:key.end()])
        out.append("<withheld %d chars>" % len(val.group()))
        pos = val.end()
    out.append(text[pos:])
    return _TOKEN_SHAPE.sub(lambda m: m.group(1) + "<masked>", "".join(out))


def clip(text: str) -> str:
    """``mask(text)`` cut to ECHO_LIMIT characters, with ``...`` when it was cut (#6681).

    Only a bounded window of the text is masked, so a very long row costs no more than a short one.
    """
    raw = str(text)
    text = mask(raw[:4 * ECHO_LIMIT])
    return text[:ECHO_LIMIT] + "..." if len(raw) > 4 * ECHO_LIMIT or len(text) > ECHO_LIMIT else text


def echo(text: str) -> str:
    """The quoted ``clip`` of a row for a refusal message (#6681)."""
    return repr(clip(text))


def _strip_comment(line: str) -> str:
    """Drop a trailing comment and trailing ASCII space, tab or CR (one row at a time, #5748)."""
    out: List[str] = []
    quote: Optional[str] = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).rstrip(" \t\r")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _unquote(item: str) -> str:
    item = item.strip(" ")  # only ASCII space is YAML white space here (#5748)
    if len(item) >= 2 and item[0] == item[-1] and item[0] in ("'", '"'):
        return item[1:-1]
    return item


def _parse_inline_list(text: str) -> List[str]:
    """The items of an inline filter list; each must be one scalar (#5733)."""
    text = text.strip(" ")
    if not text.startswith("["):
        raise Unparsed("unterminated or non-list flow value: " + echo(text))
    # _value already read this flow collection to its end and refused any text after
    # it (_tail), so nothing follows it here (#5777).
    items = _flow(text, 0)[1]
    for item in items:  # type: ignore[attr-defined]
        if not isinstance(item, str):
            raise Unparsed("inline list item is not one scalar (#5733): " + echo(text))
        if isinstance(item, _Plain) and _typed_plain(item):
            raise Unparsed("plain scalar YAML 1.1 reads as other than a string (#5734): " + echo(text))
    return [str(item) for item in items]  # type: ignore[attr-defined]


# Line-break and separator characters other than LF and CR. PyYAML 6 reads NEL,
# U+2028 and U+2029 as line breaks and refuses the other six as non-printable;
# the reader refuses all nine (#5707).
_EXOTIC_BREAKS = "\x0b\x0c\x1c\x1d\x1e\x1f\x85  "
# C0 and C1 control characters other than tab, LF and CR; all 66 Unicode
# noncharacters (U+FDD0-U+FDEF and the last two code points of each of the 17
# planes); and a BOM anywhere but the stream start (#5732). PyYAML 6 refuses
# U+FFFE and U+FFFF and accepts the other 64 noncharacters; the reader refuses
# all 66 so no file it reads holds one.
_NONCHARACTERS = "\ufdd0-\ufdef" + "".join(chr(plane << 16 | 0xFFFE) + chr(plane << 16 | 0xFFFF)
                                          for plane in range(17))
_FORBIDDEN = re.compile("[\x00-\x08\x0e-\x1f\x7f-\x9f\ufeff" + _NONCHARACTERS + "]")
# Characters that start an anchor, alias, tag or reserved token.
_NODE_PROPERTY = "&*!%@`"
# Characters that end a plain scalar inside a flow collection.
_FLOW_STOPS = ",[]{}"
# A plain scalar YAML 1.1 may resolve to a number or a date: an optional sign, then
# a digit or a dot and a digit; or the .inf and .nan forms (#5734).
_NUMERIC_PLAIN = re.compile(r"[-+]?\.?[0-9].*|[-+]?\.(?:inf|nan)", re.IGNORECASE | re.DOTALL)


class _Plain(str):
    """A plain (unquoted) scalar read from a flow collection."""


def _typed_plain(text: str) -> bool:
    """True when YAML 1.1 may read the plain scalar as other than a string (#5734).

    That is: a null or YAML 1.1 boolean word in any case, or a number or date
    form.  An empty item, the merge key ``<<`` and the value key ``=`` are refused
    before this check, wherever they stand (#5733, #5749).
    """
    return text.lower() in YAML11_BOOLEANS + ("null", "~") or _NUMERIC_PLAIN.fullmatch(text) is not None


def _space_like(ch: str) -> bool:
    """True for a tab and any Unicode space, separator, control or format character."""
    return ch == "\t" or ch.isspace() or unicodedata.category(ch) in ("Zs", "Zl", "Zp", "Cc", "Cf")


def _quoted_end(s: str, i: int) -> int:
    """Index just past the quoted scalar that opens at s[i]; it must close on its row.

    A double-quoted scalar may hold no backslash and a single-quoted one no doubled
    quote (#5706): an escape can move the real closing quote to a later line.
    """
    end = s.find(s[i], i + 1)
    if end < 0:
        raise Unparsed("quoted scalar does not close on its row: " + echo(s))
    if s[i] == '"' and "\\" in s[i + 1:end]:
        raise Unparsed("double-quoted scalar holds a backslash (#5706): " + echo(s))
    if s[i] == "'" and s[end + 1:end + 2] == "'":
        raise Unparsed("single-quoted scalar holds a doubled quote (#5706): " + echo(s))
    return end + 1


def _tail(s: str, i: int, what: str) -> str:
    """s[:i] when only spaces and a comment follow position i, else Unparsed."""
    rest = s[i:]
    after = rest.lstrip(" ")
    if not after or (after[0] == "#" and len(after) < len(rest)):
        return s[:i]
    raise Unparsed("text after " + what + ": " + echo(s))


def _flow_space(s: str, j: int) -> int:
    """Index of the next non-space in a flow collection; a comment or the row end is Unparsed."""
    while j < len(s) and s[j] == " ":
        j += 1
    if j == len(s) or (s[j] == "#" and s[j - 1] == " "):
        raise Unparsed("flow collection does not close on its row: " + echo(s))
    return j


def _flow_plain(s: str, j: int, key: bool) -> Tuple[int, str]:
    """(stop index, text) of a plain scalar inside a flow collection (#5733).

    It starts with no indicator and holds printable ASCII only, with no quote, no
    ``#`` and no ``:`` except the one that ends a mapping key.
    """
    ch = s[j]
    if ch in ",]}":
        raise Unparsed("empty flow entry or trailing comma (#5733): " + echo(s))
    if ch in _NODE_PROPERTY:
        raise Unparsed("anchor, alias, tag or reserved indicator in a flow collection (#5733): " + echo(s))
    if ch in "-?:|>[{":
        raise Unparsed("flow entry starts with an indicator (#5733): " + echo(s))
    k = j
    while k < len(s) and s[k] not in _FLOW_STOPS:
        ch = s[k]
        if ch in "'\"":
            raise Unparsed("quote inside a plain flow scalar: " + echo(s))
        if ch == ":":
            if key:
                break
            raise Unparsed("':' inside a plain flow scalar (#5733): " + echo(s))
        if ch == "#":
            if s[k - 1] == " ":
                raise Unparsed("flow collection does not close on its row: " + echo(s))
            raise Unparsed("'#' inside a plain flow scalar (#5733): " + echo(s))
        if not " " <= ch <= "~":
            raise Unparsed("non-ASCII or control character in a flow scalar (#5733): " + echo(s))
        k += 1
    text = s[j:k].rstrip(" ")
    if text in ("<<", "="):
        raise Unparsed("plain << or = (merge or value tag) in a flow collection (#5749): " + echo(s))
    return k, _Plain(text)


# #6612: deepest block (indentation) or flow (bracket) nesting the reader models.  GitHub's own
# workflow parser rejects far shallower documents; deeper input is a named refusal, never a
# RecursionError.
MAX_DEPTH = 64


def _flow_node(s: str, j: int, depth: int = 1) -> Tuple[int, object]:
    """(index past, value) of one flow entry: a flow collection, quoted or plain scalar."""
    ch = s[j]
    if ch in "[{":
        return _flow(s, j, depth + 1)
    if ch in "'\"":
        end = _quoted_end(s, j)
        if "," in s[j:end]:
            raise Unparsed("quoted flow item with an embedded comma (#5733): " + echo(s))
        return end, s[j + 1:end - 1]
    return _flow_plain(s, j, False)


def _flow(s: str, i: int, depth: int = 1) -> Tuple[int, object]:
    """(index past, value) of the flow collection that opens at s[i] (#5733).

    It must close on its row. A sequence holds entries; a mapping holds
    ``key: value`` entries with a plain key; a key repeated in any letter case is
    refused (#6680), never read last-wins. Entries are separated by a comma, and
    only ASCII spaces may stand around them; an empty entry, a trailing comma and
    any other text are refused.
    """
    if depth > MAX_DEPTH:
        raise Unparsed("flow collection nested deeper than %d levels (#6612): %s" % (MAX_DEPTH, echo(s)))
    close = "]" if s[i] == "[" else "}"
    items: List[object] = []
    pairs: Dict[str, object] = {}
    folded: Set[str] = set()  # #6680: casefolded keys of this flow mapping, as parse_workflow compares
    j = _flow_space(s, i + 1)
    if s[j] == close:
        return j + 1, (items if close == "]" else pairs)
    while True:
        if close == "]":
            j, value = _flow_node(s, j, depth)
            items.append(value)
        else:
            if s[j] in "'\"":
                raise Unparsed("flow mapping entry with a quoted key (#5733): " + echo(s))
            j, key = _flow_plain(s, j, True)
            if s[j:j + 2] != ": ":
                raise Unparsed("flow mapping entry is not key: value (#5733): " + echo(s))
            j = _flow_space(s, j + 1)
            if s[j] in ",}":
                raise Unparsed("flow mapping entry with no value (#5733): " + echo(s))
            if key.casefold() in folded:
                raise Unparsed("repeated flow mapping key %s (#6680): %s" % (echo(key), echo(s)))
            folded.add(key.casefold())
            j, value = _flow_node(s, j, depth)
            pairs[key] = value
        j = _flow_space(s, j)
        if s[j] == close:
            return j + 1, (items if close == "]" else pairs)
        if s[j] != ",":
            raise Unparsed("text after a flow entry (#5733): " + echo(s))
        j = _flow_space(s, j + 1)


def _value(s: str, i: int) -> Tuple[str, bool]:
    """(row text without its comment, opens-a-block-scalar) for the node at s[i:]."""
    while i < len(s) and s[i] == " ":
        i += 1
    if i == len(s) or s[i] == "#":
        return s[:i].rstrip(" "), False
    ch = s[i]
    if ch in "'\"":
        return _tail(s, _quoted_end(s, i), "a quoted scalar"), False
    if ch in "[{":
        return _tail(s, _flow(s, i)[0], "a flow collection"), False
    if ch in "|>":
        header = re.compile(r"[|>][-+]?").match(s, i)
        assert header is not None
        return _tail(s, header.end(), "a block scalar header"), True
    if ch in _NODE_PROPERTY:
        raise Unparsed("anchor, alias, tag or reserved indicator: " + echo(s))
    if ch in ",]}" or (ch in "?:-" and s[i + 1:i + 2] in ("", " ")):
        raise Unparsed("indicator where a value belongs: " + echo(s))
    cut = s.find(" #", i)
    end = len(s) if cut < 0 else cut
    plain = s[i:end].rstrip(" ")
    if ": " in plain or plain.endswith(":"):
        raise Unparsed("nested mapping on one row: " + echo(s))
    if plain in ("<<", "="):
        raise Unparsed("plain << or = (merge or value tag) as a value (#5749): " + echo(s))
    return s[:end].rstrip(" "), False


def _plain_key_colon(s: str, i: int) -> int:
    """Index of the ':' that ends a plain key starting at s[i], or -1."""
    j = i
    while j < len(s):
        if s[j] == "#" and s[j - 1] == " ":
            return -1
        if s[j] == ":" and s[j + 1:j + 2] in ("", " "):
            return j
        j += 1
    return -1


def _opens_block(s: str, i: int) -> bool:
    """True when the node at s[i:] is empty (only spaces and a comment follow)."""
    after = s[i:].lstrip(" ")
    return not after or after[0] == "#"


def _scan_row(rest: str) -> Tuple[str, str, int, bool, List[int], bool]:
    """Positive rules for one structure row (text after its ASCII-space indentation).

    Returns (row text without comment, mapping key or '', column offset of the node
    that owns a block scalar, opens-a-block-scalar, column offset of each ``- ``
    prefix, value-is-empty). A row is accepted only as a mapping key row or a
    sequence entry, each optionally after ``- `` prefixes; anything else is Unparsed.
    """
    i = 0
    dashes: List[int] = []
    while rest.startswith("-", i) and rest[i + 1:i + 2] in ("", " "):
        dashes.append(i)
        i += 1
        while i < len(rest) and rest[i] == " ":
            i += 1
    if i < len(rest) and rest[i] in "'\"":
        end = _quoted_end(rest, i)
        j = end
        while j < len(rest) and rest[j] == " ":
            j += 1
        if rest.startswith(":", j) and rest[j + 1:j + 2] in ("", " "):
            body, header = _value(rest, j + 1)
            return body, rest[i:end], i, header, dashes, _opens_block(rest, j + 1)
    elif i < len(rest) and rest[i] not in "[{|>,]}#?:" + _NODE_PROPERTY:
        colon = _plain_key_colon(rest, i)
        if colon >= 0:
            key = rest[i:colon].rstrip(" ")
            if key == "<<":
                raise Unparsed("merge key: " + echo(rest))
            body, header = _value(rest, colon + 1)
            return body, key, i, header, dashes, _opens_block(rest, colon + 1)
    if not dashes:
        raise Unparsed("row is neither a mapping key, a sequence entry nor a comment: " + echo(rest))
    body, header = _value(rest, i)
    return body, "", dashes[-1], header, dashes, _opens_block(rest, i)


def _nest(stack: List[Tuple[int, str]], opened: Optional[int], ind: int, kind: str, raw: str) -> None:
    """Place a structure row that starts a node of ``kind`` at column ``ind`` (#5730).

    ``stack`` holds (column, "map" or "seq") for every open block collection, and
    ``opened`` is the column of the node on the row above when its value is empty.
    Only such a row may be followed by a deeper row, which opens a nested block. A
    row is otherwise placed at the column of an open block of its own kind; a
    deeper row continues the scalar above it in YAML and is refused, and so is a
    row between two open columns or a sequence at its own key's column.
    """
    if opened is not None and ind > opened:
        stack.append((ind, kind))
        return
    if opened is not None and ind == opened and kind == "seq" and stack and stack[-1] == (ind, "map"):
        raise Unparsed("indentless sequence (a sequence at its key's column): " + echo(raw))
    if not stack:
        stack.append((ind, kind))
        return
    if ind > stack[-1][0]:
        raise Unparsed("row indented past its block continues the scalar above it: " + echo(raw))
    while stack[-1][0] > ind:
        stack.pop()
        if not stack:
            raise Unparsed("row is less indented than the first row: " + echo(raw))
    if stack[-1][0] != ind:
        raise Unparsed("row is indented to no open block's column: " + echo(raw))
    if stack[-1][1] != kind:
        raise Unparsed("row is of the other kind than its block (key row or sequence entry): " + echo(raw))


def _row_value(body: str, key: str, node: int) -> str:
    """The value text of a structure row: after ``key:`` for a key row, after ``-`` for an entry."""
    if key:
        return body[node + len(key):].lstrip(" ")[1:].strip(" ")
    return body[node + 1:].strip(" ")


def _meaningful(text: str, detail: Optional[list] = None) -> List[Tuple[int, str, str]]:
    """(indent, row text, mapping key or '') per structure row; closed world (#5660, #5705).

    Every line must be accepted by a positive rule: a blank line, a comment line, a
    content line of a block scalar (indented past its owner by ASCII spaces, its
    first character no tab or Unicode space, separator, control or format
    character, #5732), a column-0 ``---`` or ``...``
    row (which _check_top_level accepts only as one leading ``---``), or a
    structure row that _scan_row accepts. A structure row starts with printable
    ASCII after ASCII-space indentation and holds no tab.

    When ``detail`` is a list, one record ``(line number, indent, node column, dash
    columns, value text)`` is appended per row, in step with the returned rows (#6481).
    """
    if re.search(r"\r(?!\n)", text):
        raise Unparsed("lone carriage return line break")
    if any(ch in _EXOTIC_BREAKS for ch in text):
        bad = next(ch for ch in text if ch in _EXOTIC_BREAKS)
        raise Unparsed("line-break character other than LF or CR LF: U+%04X" % ord(bad))
    bad = _FORBIDDEN.search(text)
    if bad:
        raise Unparsed("control character, noncharacter or inner BOM: U+%04X" % ord(bad.group()))
    rows: List[Tuple[int, str, str]] = []
    owner: Optional[int] = None  # column of the node that owns an open block scalar
    content: Optional[int] = None  # indentation of that block scalar's first line
    blank = 0  # spaces on its longest blank line before that first line (#5750)
    stack: List[Tuple[int, str]] = []  # open block collections (#5730)
    opened: Optional[int] = None  # column of the node above whose value is empty
    for lineno, raw in enumerate(text.split("\n"), 1):
        if raw.endswith("\r"):
            raw = raw[:-1]
        ind = _indent(raw)
        rest = raw[ind:]
        if owner is not None:
            if not rest:
                if content is None:
                    blank = max(blank, ind)
                continue
            if ind > owner:
                if _space_like(rest[0]):
                    raise Unparsed("block scalar line starts with a tab or a Unicode space, separator, control or format"
                               " character (#5732): " + echo(raw))
                if content is None:
                    if blank > ind:
                        raise Unparsed("leading blank line of a block scalar holds more spaces than its first"
                                       " line (#5750): " + echo(raw))
                    content = ind
                elif ind < content:
                    raise Unparsed("block scalar line less indented than its first line: " + echo(raw))
                continue
            owner = None
        if not rest:
            continue
        if not " " < rest[0] <= "~":
            raise Unparsed("row starts with non-space whitespace or a non-ASCII character: " + echo(raw))
        if "\t" in rest:
            raise Unparsed("tab on a structure row: " + echo(raw))
        if rest[0] == "#":
            continue
        if ind == 0 and _strip_comment(rest) in ("---", "..."):
            rows.append((0, _strip_comment(rest), ""))
            if detail is not None:
                detail.append((lineno, 0, 0, [], _strip_comment(rest)))
            continue
        body, key, node, header, dashes, empty = _scan_row(rest)
        _nest(stack, opened, ind, "seq" if dashes and dashes[0] == 0 else "map", raw)
        for d in dashes[1:]:
            stack.append((ind + d, "seq"))
        if key and dashes:
            stack.append((ind + node, "map"))
        opened = ind + node if empty else None
        if key[:1] in ("'", '"') and ind > 0:
            raise Unparsed("quoted mapping key below the top level (#5731): " + echo(raw))
        rows.append((ind, body, key))
        if detail is not None:
            detail.append((lineno, ind, node, dashes, _row_value(body, key, node)))
        if header:
            owner, content, blank = ind + node, None, 0
    return rows


TOP_KEY = re.compile(r"""("[^"\\]*"|'[^']*'|[A-Za-z_][A-Za-z0-9_-]*)""")
# The words of the YAML 1.1 bool type. PyYAML 6 resolves yes, no, true, false, on
# and off (lower, Capitalised or UPPER case) to a boolean key and reads y and n as
# strings; the rule below refuses every case and quoting of all eight (#5708).
YAML11_BOOLEANS = ("y", "yes", "n", "no", "true", "false", "on", "off")
ON_KEYS = ('on', '"on"', "'on'")


def _check_top_level(rows: List[Tuple[int, str, str]]) -> None:
    """Closed-world top level: only mapping keys, each once (#5667, #5668, #5705).

    A single leading ``---`` is accepted; every other indent-0 row must be a bare
    word key or an escape-free quoted key. Keys are compared case-folded and
    unquoted. A key whose folded spelling is a YAML 1.1 boolean (y, yes, n, no,
    true, false, on, off) is accepted only when spelled exactly on, "on" or 'on',
    so no two boolean spellings can form a duplicate the reader misses (#5708).
    Every other document marker, a directive, a sequence entry, a complex key, a
    merge key, an anchor, a tag and a flow collection at the top level is
    refused, because the reader does not model them.
    """
    seen: Set[str] = set()
    for idx, (ind, body, key) in enumerate(rows):
        if ind != 0:
            continue
        if idx == 0 and body == "---":
            continue
        if not key or not TOP_KEY.fullmatch(key):
            raise Unparsed("top-level row is not a plain mapping key (#5668): " + echo(body))
        name = key.strip("\"'").lower()
        if name in YAML11_BOOLEANS and key not in ON_KEYS:
            raise Unparsed("top-level key is a YAML 1.1 boolean other than on (#5708): " + echo(body))
        if key[0] in ("'", '"') and key not in ON_KEYS:
            raise Unparsed("quoted mapping key other than a top-level on (#5731): " + echo(body))
        if name in seen:
            raise Unparsed("repeated top-level key (#5667): " + echo(body))
        seen.add(name)


# ---------------------------------------------------------------------------------------------
# Tree reader (#6481, #6482, #6542, #6545).  It adds no grammar: every row has already been
# accepted by ``_meaningful`` and ``_check_top_level``; the tree only records which row sits
# under which key, by column, the way ``_nest`` already guarantees is unambiguous.
# ---------------------------------------------------------------------------------------------


class Node:
    """One mapping key (kind ``key``), sequence entry (``item``) or the document (``root``)."""

    __slots__ = ("kind", "name", "value", "line", "end", "col", "children", "block", "block_lines")

    def __init__(self, kind: str, name: str, value: str, line: int, col: int) -> None:
        self.kind = kind
        self.name = name  # the key as written (a quoted top-level ``on`` keeps its quotes)
        self.value = value  # the value text after the colon or the dash, comment removed
        self.line = line  # 1-based line of the row that opens the node
        self.end = line  # 1-based last line that belongs to the node
        self.col = col
        self.children: List["Node"] = []
        # (first, last) 1-based lines of this node's block-scalar content, or None.  A ``#`` in
        # such a line is text, not a comment, so a scan must not strip it (a ``${{ }}`` there is
        # expanded before the shell runs).
        self.block: Optional[Tuple[int, int]] = None
        # (line, text) of each block-scalar content line, CR removed (#6617: the accessor reads these).
        self.block_lines: List[Tuple[int, str]] = []

    def keys(self) -> List["Node"]:
        return [c for c in self.children if c.kind == "key"]

    def items(self) -> List["Node"]:
        return [c for c in self.children if c.kind == "item"]

    def get(self, name: str) -> Optional["Node"]:
        """The child key written exactly ``name`` (keys are unique among siblings)."""
        for child in self.children:
            if child.kind == "key" and child.name == name:
                return child
        return None

    def walk(self):
        """This node and every descendant, in document order (iterative: no recursion limit, #6612)."""
        todo = [self]
        while todo:
            node = todo.pop()
            yield node
            todo.extend(reversed(node.children))


def _text_failure_line(text: str) -> Optional[int]:
    """Line of the first character the whole-stream checks of ``_meaningful`` refuse, or None."""
    lone = re.search(r"\r(?!\n)", text)
    exotic = next((i for i, ch in enumerate(text) if ch in _EXOTIC_BREAKS), None)
    bad = _FORBIDDEN.search(text)
    hits = [m for m in (lone.start() if lone else None, exotic, bad.start() if bad else None) if m is not None]
    return text.count("\n", 0, min(hits)) + 1 if hits else None


def _failing_line(text: str) -> int:
    """1-based line on which ``_meaningful`` or ``_check_top_level`` first refuses ``text``."""
    at = _text_failure_line(text)
    if at is not None:
        return at
    lines = text.split("\n")
    lo, hi = 1, len(lines)
    try:
        _meaningful(text)
    except Unparsed:
        while lo < hi:  # smallest prefix that is refused; the refusal is deterministic per row
            mid = (lo + hi) // 2
            try:
                _meaningful("\n".join(lines[:mid]))
                lo = mid + 1
            except Unparsed:
                hi = mid
        return lo
    detail: list = []
    rows = _meaningful(text, detail)
    lo, hi = 1, len(rows)
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            _check_top_level(rows[:mid])
            lo = mid + 1
        except Unparsed:
            hi = mid
    return detail[lo - 1][0] if detail else 1


def key_name(raw: str) -> str:
    """A mapping key without its quotes (only a top-level ``on`` can be quoted)."""
    return _unquote(raw)


def parse_workflow(text: str) -> Node:
    """The document as a tree.  Raises ``Unparsed("line N: ...")`` on anything not modelled.

    No BOM is stripped (a BOM is refused, #6543); a second document, a duplicate key at any
    level of a block or a flow mapping (compared casefolded, #6680), an alias, an anchor, a merge
    key, a tab and a quoted key below the top level are all refused by the reader or here.
    """
    detail: list = []
    try:
        rows = _meaningful(text, detail)
        _check_top_level(rows)
    except Unparsed as exc:
        raise Unparsed("line %d: %s" % (_failing_line(text), exc)) from None
    total = text.count("\n") + 1
    root = Node("root", "", "", 0, -1)
    stack: List[Node] = [root]
    # #6611: casefolded key -> first line, per parent (by id), so the duplicate check is one lookup
    # per key instead of a scan of every earlier sibling.
    seen: Dict[int, Dict[str, int]] = {}

    def push(node: Node) -> None:
        while stack[-1].col >= node.col:
            done = stack.pop()
            done.end = max(done.line, node.line - 1)
        if len(stack) > MAX_DEPTH:
            raise Unparsed("line %d: nesting deeper than %d levels (#6612)" % (node.line, MAX_DEPTH))
        parent = stack[-1]
        if node.kind == "key":
            if node.col > 0 and ("'" in node.name or '"' in node.name):
                # YAML reads a quote inside a plain key as text; a lexical reader that toggles a quote
                # state on it misreads the rest of the row (#6617), so the tree refuses such keys.
                raise Unparsed("line %d: quote character inside a plain mapping key %s (#6617)"
                               % (node.line, echo(node.name)))
            folded = key_name(node.name).casefold()
            known = seen.setdefault(id(parent), {})
            if folded in known:
                raise Unparsed("line %d: repeated mapping key %s (first on line %d)"
                               % (node.line, echo(node.name), known[folded]))
            known[folded] = node.line
        parent.children.append(node)
        stack.append(node)

    for (ind, _body, key), (lineno, _ind, node_col, dashes, value) in zip(rows, detail):
        if ind == 0 and not key and _body == "---":
            continue
        for d in dashes:
            push(Node("item", "", value if (not key and d == dashes[-1]) else "", lineno, ind + d))
        if key:
            push(Node("key", key, value, lineno, ind + node_col))
    for node in stack[1:]:
        node.end = total
    root.end = total
    row_lines = [d[0] for d in detail]
    lines = text.split("\n")
    for node in root.walk():
        if node.kind == "root" or not node.value or node.value[0] not in "|>":
            continue
        # #6611: row_lines is ascending, so the next structure row is one bisection, not a scan.
        nxt = bisect.bisect_right(row_lines, node.line)
        last = (row_lines[nxt] - 1) if nxt < len(row_lines) else total
        while last > node.line and (not lines[last - 1].strip(" ")
                                    or len(lines[last - 1]) - len(lines[last - 1].lstrip(" ")) <= node.col):
            last -= 1  # trailing blank or less-indented comment lines are not content
        node.block = (node.line + 1, last) if last > node.line else None
        if node.block:
            node.block_lines = [(n, lines[n - 1].rstrip("\r")) for n in range(node.block[0], node.block[1] + 1)]
    return root


def flow_of(value: str):
    """The list or dict of a one-row flow collection value (the reader has already checked it)."""
    return _flow(value, 0)[1]


def scalar_of(value: str) -> str:
    """The string of a plain or quoted one-row scalar value."""
    return _unquote(value)


# ---------------------------------------------------------------------------------------------
# Allowed-shape accessor (#6610, #6617, #6618; 3-agent vote (6def5ab6), option C).  Every pin in
# scripts/check_carrier_ruleset_live.py reads a node through ``read``/``value``/``strings``: the
# caller names the shapes it accepts, and any other shape is ``Unparsed("line N: ...")``.  Values
# are the parsed scalars (quotes removed, comments gone, flow collections read), never row text.
# ---------------------------------------------------------------------------------------------

EMPTY = "empty"  # a key with no value and no children (YAML null)
PLAIN = "plain scalar"
QUOTED = "quoted scalar"
BLOCK_SCALAR = "block scalar"
FLOW_SEQ = "flow sequence"
FLOW_MAP = "flow mapping"
MAP = "block mapping"
SEQ = "block sequence"
SCALAR = (PLAIN, QUOTED)


def shape(node: Node) -> str:
    """The shape of a key or item node's value (the reader guarantees exactly one applies)."""
    if node.children:
        return MAP if node.children[0].kind == "key" else SEQ
    value = node.value
    if not value:
        return EMPTY
    if value[0] in "|>":
        return BLOCK_SCALAR
    if value[0] == "[":
        return FLOW_SEQ
    if value[0] == "{":
        return FLOW_MAP
    if value[0] in "'\"":
        return QUOTED
    return PLAIN


def where(node: Node) -> str:
    """``line N: <key>`` (``line N: sequence entry``, ``line N: document``) for a refusal message."""
    label = clip(key_name(node.name)) if node.kind == "key" else ("document" if node.kind == "root" else "sequence entry")
    return "line %d: %s" % (node.line, label)


def value(node: Node, allowed: Tuple[str, ...]):
    """The parsed value of ``node`` when its shape is in ``allowed``; any other shape is Unparsed.

    plain / quoted scalar: the string (quotes removed); flow sequence / mapping: the list / dict;
    block scalar: [(line, text)] of its content lines; block mapping / sequence: the node; empty:
    None.
    """
    got = shape(node)
    if got not in allowed:
        raise Unparsed("%s has the shape %s; allowed: %s" % (where(node), got, ", ".join(allowed)))
    if got in SCALAR:
        return _unquote(node.value)
    if got in (FLOW_SEQ, FLOW_MAP):
        return _flow(node.value, 0)[1]
    if got == BLOCK_SCALAR:
        return list(node.block_lines)
    if got == EMPTY:
        return None
    return node


def child(node: Node, name: str) -> Optional[Node]:
    """The child key spelled exactly ``name``; a sibling that differs only in letter case is Unparsed.

    GitHub reads workflow keys case-sensitively, so ``Permissions:`` is not ``permissions:``; a pin
    that looked only for the exact spelling would miss what the variant does on another reader.
    ``node`` itself must be a block mapping (the document included): a flow mapping, a scalar, an
    empty value or a sequence is Unparsed with its line, never read as "no such key" (#6679).
    """
    value(node, (MAP,))
    for sub in node.children:
        if sub.kind == "key" and key_name(sub.name).casefold() == name.casefold():
            if key_name(sub.name) != name:
                raise Unparsed("%s is not spelled %s" % (where(sub), name))
            return sub
    return None


def read(node: Node, path: Tuple[str, ...], allowed: Tuple[str, ...]):
    """(node, parsed value) at ``path`` below ``node``; (None, None) when a key on the path is absent.

    Every node on the way must be a block mapping; the last must have a shape in ``allowed``.
    """
    here = node
    for name in path:
        found = child(here, name)  # child() refuses a node on the path that is not a block mapping
        if found is None:
            return None, None
        here = found
    return here, value(here, allowed)


def read_map(node: Node, spec: Dict[str, Tuple[str, ...]]) -> Dict[str, Node]:
    """The keys of a block mapping checked against a closed ``spec`` of key -> allowed shapes.

    A key not in ``spec`` (in any letter case) or a value of a shape ``spec`` does not allow is
    Unparsed.  Returns key -> node.
    """
    value(node, (MAP,))
    out: Dict[str, Node] = {}
    for sub in node.keys():
        name = key_name(sub.name)
        allowed = spec.get(name)
        if allowed is None:
            raise Unparsed("%s is not an allowed key here (allowed: %s)" % (where(sub), ", ".join(sorted(spec))))
        value(sub, allowed)
        out[name] = sub
    return out


def _flow_strings(obj, owner: str = "") -> List[Tuple[str, str]]:
    """(owning key, string) for every key and scalar of a parsed flow collection, depth first (#6735).

    The owner of a scalar is the key it is the value of (the enclosing ``owner`` for a sequence item);
    a key has the owner ``""``."""
    out: List[Tuple[str, str]] = []
    todo = [(obj, owner)]
    while todo:
        item, own = todo.pop()
        if isinstance(item, str):
            out.append((own, str(item)))
        elif isinstance(item, dict):
            for k, v in item.items():
                out.append(("", str(k)))
                todo.append((v, str(k)))
        else:
            todo.extend((sub, own) for sub in item)
    return out


def owned_strings(node: Node) -> List[Tuple[int, str, str]]:
    """(line, owning key, text) for every parsed string a node and its descendants hold, in document order.

    A key contributes ``name:`` (owner ``""``); a scalar its parsed text; a flow collection every key and
    scalar; a block scalar each content line whole (a ``#`` there is text).  Comments are never included
    and quoting never shifts what is read (#6617).  The owner of a value is the key it sits under, so a
    caller that echoes the value can pass the key to ``mask`` (#6735).
    """
    out: List[Tuple[int, str, str]] = []
    owner_of = {id(node): ""}
    for sub in node.walk():
        own = owner_of.get(id(sub), "")
        if sub.kind == "key":
            out.append((sub.line, "", key_name(sub.name) + ":"))
            own = key_name(sub.name)
        for child in sub.children:
            owner_of[id(child)] = own
        if sub.kind == "root":
            continue
        got = shape(sub)
        if got in SCALAR:
            out.append((sub.line, own, _unquote(sub.value)))
        elif got in (FLOW_SEQ, FLOW_MAP):
            out.extend((sub.line, o, s) for o, s in _flow_strings(_flow(sub.value, 0)[1], own))
        elif got == BLOCK_SCALAR:
            out.extend((number, own, text) for number, text in sub.block_lines)
    return out


def strings(node: Node) -> List[Tuple[int, str]]:
    """(line, text) for every parsed string a node and its descendants hold (``owned_strings`` without the owner)."""
    return [(number, text) for number, _owner, text in owned_strings(node)]
