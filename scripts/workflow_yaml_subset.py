#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Standard-library, fail-closed reader for the subset of workflow YAML this repository uses.

The reader was written for scripts/test/test_workflow_pr_triggers_5447.py (#5447), where it
was differential-tested against PyYAML 6.0.1 yaml.SafeLoader (see that file's docstring for
the grammar and the differential runs).  It lives here so the verifier
scripts/check_carrier_ruleset_live.py reads workflow files with the SAME grammar instead of
regular expressions (#6481, #6482): a construct the reader does not model raises
``Unparsed`` and the caller fails closed.  The functions from ``Unparsed`` to
``_check_top_level`` are moved from the test unchanged, except that ``_meaningful`` takes an
optional ``detail`` list (one record per row, for the tree reader below).

The reader is the Python standard library only; no PyYAML is imported.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Optional, Set, Tuple


class Unparsed(Exception):
    """Raised when the reader cannot interpret a trigger (a FAILURE, never a skip)."""


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
        raise Unparsed("unterminated or non-list flow value: " + text)
    # _value already read this flow collection to its end and refused any text after
    # it (_tail), so nothing follows it here (#5777).
    items = _flow(text, 0)[1]
    for item in items:  # type: ignore[attr-defined]
        if not isinstance(item, str):
            raise Unparsed("inline list item is not one scalar (#5733): " + text)
        if isinstance(item, _Plain) and _typed_plain(item):
            raise Unparsed("plain scalar YAML 1.1 reads as other than a string (#5734): " + text)
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
        raise Unparsed("quoted scalar does not close on its row: " + repr(s))
    if s[i] == '"' and "\\" in s[i + 1:end]:
        raise Unparsed("double-quoted scalar holds a backslash (#5706): " + repr(s))
    if s[i] == "'" and s[end + 1:end + 2] == "'":
        raise Unparsed("single-quoted scalar holds a doubled quote (#5706): " + repr(s))
    return end + 1


def _tail(s: str, i: int, what: str) -> str:
    """s[:i] when only spaces and a comment follow position i, else Unparsed."""
    rest = s[i:]
    after = rest.lstrip(" ")
    if not after or (after[0] == "#" and len(after) < len(rest)):
        return s[:i]
    raise Unparsed("text after " + what + ": " + repr(s))


def _flow_space(s: str, j: int) -> int:
    """Index of the next non-space in a flow collection; a comment or the row end is Unparsed."""
    while j < len(s) and s[j] == " ":
        j += 1
    if j == len(s) or (s[j] == "#" and s[j - 1] == " "):
        raise Unparsed("flow collection does not close on its row: " + repr(s))
    return j


def _flow_plain(s: str, j: int, key: bool) -> Tuple[int, str]:
    """(stop index, text) of a plain scalar inside a flow collection (#5733).

    It starts with no indicator and holds printable ASCII only, with no quote, no
    ``#`` and no ``:`` except the one that ends a mapping key.
    """
    ch = s[j]
    if ch in ",]}":
        raise Unparsed("empty flow entry or trailing comma (#5733): " + repr(s))
    if ch in _NODE_PROPERTY:
        raise Unparsed("anchor, alias, tag or reserved indicator in a flow collection (#5733): " + repr(s))
    if ch in "-?:|>[{":
        raise Unparsed("flow entry starts with an indicator (#5733): " + repr(s))
    k = j
    while k < len(s) and s[k] not in _FLOW_STOPS:
        ch = s[k]
        if ch in "'\"":
            raise Unparsed("quote inside a plain flow scalar: " + repr(s))
        if ch == ":":
            if key:
                break
            raise Unparsed("':' inside a plain flow scalar (#5733): " + repr(s))
        if ch == "#":
            if s[k - 1] == " ":
                raise Unparsed("flow collection does not close on its row: " + repr(s))
            raise Unparsed("'#' inside a plain flow scalar (#5733): " + repr(s))
        if not " " <= ch <= "~":
            raise Unparsed("non-ASCII or control character in a flow scalar (#5733): " + repr(s))
        k += 1
    text = s[j:k].rstrip(" ")
    if text in ("<<", "="):
        raise Unparsed("plain << or = (merge or value tag) in a flow collection (#5749): " + repr(s))
    return k, _Plain(text)


def _flow_node(s: str, j: int) -> Tuple[int, object]:
    """(index past, value) of one flow entry: a flow collection, quoted or plain scalar."""
    ch = s[j]
    if ch in "[{":
        return _flow(s, j)
    if ch in "'\"":
        end = _quoted_end(s, j)
        if "," in s[j:end]:
            raise Unparsed("quoted flow item with an embedded comma (#5733): " + repr(s))
        return end, s[j + 1:end - 1]
    return _flow_plain(s, j, False)


def _flow(s: str, i: int) -> Tuple[int, object]:
    """(index past, value) of the flow collection that opens at s[i] (#5733).

    It must close on its row. A sequence holds entries; a mapping holds
    ``key: value`` entries with a plain key. Entries are separated by a comma, and
    only ASCII spaces may stand around them; an empty entry, a trailing comma and
    any other text are refused.
    """
    close = "]" if s[i] == "[" else "}"
    items: List[object] = []
    pairs: Dict[str, object] = {}
    j = _flow_space(s, i + 1)
    if s[j] == close:
        return j + 1, (items if close == "]" else pairs)
    while True:
        if close == "]":
            j, value = _flow_node(s, j)
            items.append(value)
        else:
            if s[j] in "'\"":
                raise Unparsed("flow mapping entry with a quoted key (#5733): " + repr(s))
            j, key = _flow_plain(s, j, True)
            if s[j:j + 2] != ": ":
                raise Unparsed("flow mapping entry is not key: value (#5733): " + repr(s))
            j = _flow_space(s, j + 1)
            if s[j] in ",}":
                raise Unparsed("flow mapping entry with no value (#5733): " + repr(s))
            j, value = _flow_node(s, j)
            pairs[key] = value
        j = _flow_space(s, j)
        if s[j] == close:
            return j + 1, (items if close == "]" else pairs)
        if s[j] != ",":
            raise Unparsed("text after a flow entry (#5733): " + repr(s))
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
        raise Unparsed("anchor, alias, tag or reserved indicator: " + repr(s))
    if ch in ",]}" or (ch in "?:-" and s[i + 1:i + 2] in ("", " ")):
        raise Unparsed("indicator where a value belongs: " + repr(s))
    cut = s.find(" #", i)
    end = len(s) if cut < 0 else cut
    plain = s[i:end].rstrip(" ")
    if ": " in plain or plain.endswith(":"):
        raise Unparsed("nested mapping on one row: " + repr(s))
    if plain in ("<<", "="):
        raise Unparsed("plain << or = (merge or value tag) as a value (#5749): " + repr(s))
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
                raise Unparsed("merge key: " + repr(rest))
            body, header = _value(rest, colon + 1)
            return body, key, i, header, dashes, _opens_block(rest, colon + 1)
    if not dashes:
        raise Unparsed("row is neither a mapping key, a sequence entry nor a comment: " + repr(rest))
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
        raise Unparsed("indentless sequence (a sequence at its key's column): " + repr(raw))
    if not stack:
        stack.append((ind, kind))
        return
    if ind > stack[-1][0]:
        raise Unparsed("row indented past its block continues the scalar above it: " + repr(raw))
    while stack[-1][0] > ind:
        stack.pop()
        if not stack:
            raise Unparsed("row is less indented than the first row: " + repr(raw))
    if stack[-1][0] != ind:
        raise Unparsed("row is indented to no open block's column: " + repr(raw))
    if stack[-1][1] != kind:
        raise Unparsed("row is of the other kind than its block (key row or sequence entry): " + repr(raw))


def _meaningful(text: str) -> List[Tuple[int, str, str]]:
    """(indent, row text, mapping key or '') per structure row; closed world (#5660, #5705).

    Every line must be accepted by a positive rule: a blank line, a comment line, a
    content line of a block scalar (indented past its owner by ASCII spaces, its
    first character no tab or Unicode space, separator, control or format
    character, #5732), a column-0 ``---`` or ``...``
    row (which _check_top_level accepts only as one leading ``---``), or a
    structure row that _scan_row accepts. A structure row starts with printable
    ASCII after ASCII-space indentation and holds no tab.
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
    for raw in text.split("\n"):
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
                               " character (#5732): " + repr(raw))
                if content is None:
                    if blank > ind:
                        raise Unparsed("leading blank line of a block scalar holds more spaces than its first"
                                       " line (#5750): " + repr(raw))
                    content = ind
                elif ind < content:
                    raise Unparsed("block scalar line less indented than its first line: " + repr(raw))
                continue
            owner = None
        if not rest:
            continue
        if not " " < rest[0] <= "~":
            raise Unparsed("row starts with non-space whitespace or a non-ASCII character: " + repr(raw))
        if "\t" in rest:
            raise Unparsed("tab on a structure row: " + repr(raw))
        if rest[0] == "#":
            continue
        if ind == 0 and _strip_comment(rest) in ("---", "..."):
            rows.append((0, _strip_comment(rest), ""))
            continue
        body, key, node, header, dashes, empty = _scan_row(rest)
        _nest(stack, opened, ind, "seq" if dashes and dashes[0] == 0 else "map", raw)
        for d in dashes[1:]:
            stack.append((ind + d, "seq"))
        if key and dashes:
            stack.append((ind + node, "map"))
        opened = ind + node if empty else None
        if key[:1] in ("'", '"') and ind > 0:
            raise Unparsed("quoted mapping key below the top level (#5731): " + repr(raw))
        rows.append((ind, body, key))
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
            raise Unparsed("top-level row is not a plain mapping key (#5668): " + repr(body))
        name = key.strip("\"'").lower()
        if name in YAML11_BOOLEANS and key not in ON_KEYS:
            raise Unparsed("top-level key is a YAML 1.1 boolean other than on (#5708): " + body)
        if key[0] in ("'", '"') and key not in ON_KEYS:
            raise Unparsed("quoted mapping key other than a top-level on (#5731): " + body)
        if name in seen:
            raise Unparsed("repeated top-level key (#5667): " + body)
        seen.add(name)
