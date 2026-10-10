#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the pull_request / push branch filters of every workflow (#5447).

THE DEFECT (#5447).  The batch landing line ``rehearsal/audit-wip`` is the BASE of
every stacked PR, yet no gating workflow named ``rehearsal/**`` in its
``pull_request.branches`` filter, so a PR based on the carrier showed
``mergeStateStatus=CLEAN`` with zero (PR 5528) or one (PR 4524) check-run.

THE RULING.  Add ``rehearsal/**`` to ``pull_request.branches`` of every workflow
that gates PRs into main / develop / release.  NEVER add it to ``push.branches``:
#2523 and #2508 require that ``push.branches`` never overlaps a branch that is a
PR head, and ``rehearsal/audit-wip`` is the head of the promotion PR (the
duplicate push + pull_request run share one concurrency key and cancel each
other).  The shape follows the #2506 precedent in ``token-budget.yml``.

THE CHAIN RULING (#6117).  A Promotion carrier (``chain/**``) is a long-lived
integration branch that the conductor merges into with local signed merges; while
no promotion PR is open against it, a push to it ran NO workflow, so carrier-only
defects (#6115, #6116) surfaced only once a PR was opened against the carrier.
The required-set workflows (``CHAIN_PUSH_WORKFLOWS``) therefore list ``chain/**``
in ``push.branches``.  ``chain/promo6-ssh`` is also the HEAD of the promotion PR
(#6160), the #2508 shape, so the ruling is only sound when the concurrency key of
every such dual-trigger workflow is event-distinct (it names
``github.event_name``): the push run and the pull_request run then never share a
cancel-in-progress group.  Precedent for the key: ``release-shape.yml``,
``cert-postgres-age.yml``, ``postgres-ignored.yml``; the sanctioned remedy named
in ``scripts/qc-allowlists/dual-trigger-cancel-allow.txt`` and by rule (d) of
``scripts/check-required-contexts.sh``.  ``rehearsal/**`` stays banned from
``push.branches`` (R-PUSH): the ruling is for the chain carriers only.

RULES ENFORCED (all closed-world: a trigger the reader cannot parse is a FAILURE):
  R-CHAIN every workflow named in ``CHAIN_PUSH_WORKFLOWS`` lists the literal
         entry ``chain/**`` in ``push.branches`` and its filter matches
         ``chain/promo6-ssh`` (#6117).
  R-CHAIN-KEY a workflow whose ``push`` filter can match any ref under ``chain/``
         AND that also triggers on ``pull_request`` or ``pull_request_target``
         AND that declares a top-level ``concurrency:`` block must name
         ``github.event_name`` in that block's ``group`` (#2508, #6117).  A
         ``concurrency:`` block without a ``group`` row counts as not
         event-distinct.
  R-PR   every workflow whose ``pull_request`` filter can match main, develop or
         release/v1.0.0 lists the literal entry ``rehearsal/**`` and its filter
         matches ``rehearsal/audit-wip``.
  R-PUSH no workflow's ``push`` filter lists any pattern that can match the
         branch ``rehearsal`` or any ref under ``rehearsal/`` (literal, glob or
         wildcard form; #5659), and every ``push.branches`` item must stay in the
         plain glob charset (letters, digits, ``._/*-``, optional leading ``!``):
         quotes inside, tags, ``?``, ``+``, ``[``, backslash and alias-like
         ``*name`` items are undecidable and fail.  A push trigger with no
         ``branches`` and no ``tags`` key matches every branch and counts.
  R-SHAPE (#5660, #5667, #5668, #5705-#5708, #5730-#5736,
         #5748-#5750, #5968) the whole file is
         read closed-world by the grammar below.  A file the reader cannot read
         is a failure whatever words it holds (#5731).

ACCEPTED GRAMMAR (every other line or form is refused with a named reason):
  stream      the text, minus one leading BOM, holds no lone CR, no line break
              other than LF or CR LF, no control character other than tab, LF
              and CR, none of the 66 Unicode noncharacters (#5732) and no inner
              BOM.
  line        blank | comment | block-scalar content | one leading ``---`` |
              structure row.
  comment     ASCII-space indentation, then ``#``.
  structure   ASCII-space indentation, a printable ASCII first character, no
  row         tab; then zero or more ``- `` prefixes and either a mapping key
              row ``key: value`` or a sequence entry ``value``.
  key         a plain scalar that does not start with an indicator and is not
              ``<<``; a quoted key only as a top-level on spelling (#5731).
  value       empty (a comment may follow) | a plain scalar on one line with no
              ``: `` and no trailing ``:`` | a quoted scalar that closes on its
              row (no backslash in double quotes, no doubled single quote) | a
              flow collection (below) | a block-scalar header ``|`` or ``>``
              with an optional ``-`` or ``+``.  Anchors, aliases, tags and
              reserved indicators are refused, and so is a plain ``<<`` or
              ``=``, which YAML 1.1 reads as the merge or value tag (#5749).
  flow        ``[`` entries ``]`` or ``{`` pairs ``}``, closed on its row.  An
              entry is a flow collection, a quoted scalar with no comma inside,
              or a plain scalar of printable ASCII that starts with no indicator
              and holds no quote, ``#`` or ``:`` and is not ``<<`` or ``=``
              (#5749); a pair is a plain key, ``: ``
              and an entry.  Commas separate entries and only ASCII spaces
              surround them; an empty entry and a trailing comma are refused
              (#5733).
  nesting     a row sits at the column of an open block of its own kind (key
              row or sequence entry).  Only a row whose value is empty may be
              followed by a deeper row, which opens a nested block; a deeper row
              after any other row would continue a scalar and is refused, as are
              a row between two open columns and a sequence at its key's column
              (#5730).
  block-scalar every line indented past the node that owns the header, led by
  content     an ASCII space, none less indented than the first; no blank line
              before the first holds more spaces than it (#5750).
  top level   mapping keys at column 0, each once (folded and unquoted); a YAML
              1.1 boolean key only as on, "on" or 'on'.
  on block    trigger keys at one indentation, each once, none a YAML 1.1
              boolean or null word in any case (#5735); a gated trigger
              (pull_request, pull_request_target, push) spelled exactly so.  A
              gated trigger is empty, ``~``, ``null`` or a block of the filter
              keys branches, tags, paths, paths-ignore, types, each once.
  filter      an inline (flow) list of scalars on the key's row (#5733), or a
              block list indented past the key (a block list at the key's own
              column is refused, #5730, #5732) whose every row is ``- `` and
              one plain or simply quoted scalar (#5730); ``types`` may also be
              one word, plain or simply quoted.  A plain item is never a form YAML 1.1 may read as
              other than a string: empty, a null or boolean word in any case, a
              number or date (#5734), ``<<`` or ``=`` (#5749).  A filter key with
              neither a list nor a word is refused: its YAML value is null, not a
              list (#5736).
  pattern     a ``pull_request`` or ``pull_request_target`` branches item is
              matched only in these modelled constructs: letters, digits,
              ``.``, ``_``, ``/`` and ``-`` as themselves, ``*`` (any run
              without ``/``) and ``**`` (any run).  Every other character or
              construct is refused with R-SHAPE cannot match filters, naming
              the trigger and the item: a ``[`` character class (whatever its
              body) and a ``!`` anywhere in the item, a leading negation
              included (#5968, #5854, #5943, 5-agent vote 4d3ea1c5); ``?``,
              ``+``, a backslash, a ``]``, braces, parentheses, a space, a
              non-ASCII character, a run of three or more ``*`` and an empty
              item (#5943, #5856, #5857).  The refusal of a class and of a
              negation names the way out: list the base branches positively
              as plain patterns in ``branches``.  ``branches-ignore`` is no
              way out, this reader refuses it as an unsupported filter key.
              The read constructs ``*`` and ``**`` follow GitHub's documented
              filter pattern cheat sheet; they were not measured against
              GitHub's own evaluator (open tracker entry: #5969).

The reader is the Python standard library only (no PyYAML) so it runs on any CI
image.  The mutation legs at the bottom prove the reader is not vacuous: each
mutant of the LIVE workflow files must be rejected, and the unmutated control
must be accepted first.

PyYAML 6.0.1 (yaml.SafeLoader) stood in for GitHub's own workflow parser in a
differential that runs outside this file (PR #5665 rounds 4 to 8): 20,000 seeded
mutations of the live files at seed 5665 and 20,000 at seed 5666, plus the named
cells of that round as fixed cases.  Each run gave 0 disagreements and 0 of 20
live files refused: round 4 at 528c2195 ran 15 named cells, round 5 at 0e5758dc
ran 16, round 6 at 3d953877 ran 22, round 7 at 1452e37f ran 38 (16 refused by this
reader and 22 read the same as PyYAML) and round 8 at e325ddfb ran 51 (16 refused
by this reader and 35 read the same as PyYAML).  The differential compares
parse_triggers() with yaml.SafeLoader only: it never calls violations(),
filter_matches() or glob_match(), so it is no evidence on how a branches pattern
is matched.  Where GitHub's parser and PyYAML differ, it does not see it.

Run:  python3 scripts/test/test_workflow_pr_triggers_5447.py
"""
from __future__ import annotations

import json
import os
import re
import shlex
import string
import subprocess
import sys
import tempfile
import unicodedata
import unittest
import unittest.mock
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

CARRIER = "rehearsal/audit-wip"
CARRIER_PATTERN = "rehearsal/**"
GATED_BASES = ("main", "develop", "release/v1.0.0")
# #6117: the Promotion 6 carrier and the pattern the required-set workflows must
# list in push.branches so every signed merge into a chain carrier has a verdict.
CHAIN_CARRIER = "chain/promo6-ssh"
CHAIN_PATTERN = "chain/**"
CHAIN_PREFIX = "chain/"
CHAIN_BRANCH = "chain"
# The required-set carriers: the five COVERED_WORKFLOWS of
# scripts/check-required-contexts.sh plus release-shape.yml, which #6117 names.
CHAIN_PUSH_WORKFLOWS = ("ci.yml", "c8-precheck.yml", "coverage.yml", "release-shape.yml",
                        "cert-postgres-age.yml", "postgres-ignored.yml")
# The one discriminator rule (d) of scripts/check-required-contexts.sh accepts as
# proof that a push run and a pull_request run resolve different group keys.
EVENT_DISTINCT = "github.event_name"
PR_TRIGGERS = ("pull_request", "pull_request_target")
KNOWN_FILTER_KEYS = ("branches", "tags", "paths", "paths-ignore", "types")


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


def parse_triggers(text: str) -> Dict[str, Dict[str, List[str]]]:
    """Return {trigger: {filter_key: [items]}} for the workflow's ``on:`` block."""
    if text.startswith("﻿"):
        text = text[1:]  # a BOM at the very start of the stream is not content
    rows = _meaningful(text)
    _check_top_level(rows)
    start = None
    for idx, (ind, _body, key) in enumerate(rows):
        if ind == 0 and key in ON_KEYS:
            start = idx
            break
    if start is None:
        raise Unparsed("no top-level on: block")
    on_key = rows[start][2]
    head = rows[start][1][len(on_key):].lstrip(" ")[1:].strip(" ")
    if head:
        raise Unparsed("flow/scalar on: form: " + head)
    block: List[Tuple[int, str]] = []
    for ind, body, _key in rows[start + 1:]:
        if ind == 0:
            break
        block.append((ind, body))
    if not block:
        raise Unparsed("empty on: block")
    trig_indent = block[0][0]
    triggers: Dict[str, Dict[str, List[str]]] = {}
    seen_triggers: Set[str] = set()
    i = 0
    while i < len(block):
        # Deeper rows are read below as the trigger's filters; _nest refuses a row
        # between column 0 and the trigger column (no open block there, #5777).
        body = block[i][1]
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*) *:(?: +(.*))?$", body)
        if not m:
            raise Unparsed("unreadable trigger line: " + body)
        name, rest = m.group(1), (m.group(2) or "").strip(" ")  # a Unicode space is text (#5748)
        if name.lower() in YAML11_BOOLEANS + ("null",):
            raise Unparsed("trigger name YAML 1.1 reads as a boolean or null (#5735): " + name)
        if name.lower() in PR_TRIGGERS + ("push",) and name not in PR_TRIGGERS + ("push",):
            raise Unparsed("gated trigger name in another case (#5731): " + name)
        if name.lower() in seen_triggers:
            raise Unparsed("repeated trigger key in on: block (#5666): " + name)
        seen_triggers.add(name.lower())
        j = i + 1
        while j < len(block) and block[j][0] > trig_indent:
            j += 1
        sub = block[i + 1:j]
        i = j
        if name not in PR_TRIGGERS and name != "push":
            triggers.setdefault(name, {})
            continue
        if rest and rest not in ("~", "null"):
            raise Unparsed(name + ": inline value not supported: " + rest)
        triggers[name] = _parse_filters(name, sub)
    return triggers


def _filter_item(where: str, line: str) -> str:
    """The scalar of one block-list row under a filter key (#5730).

    The row must be ``- `` and one single-line plain or simply quoted scalar: a
    nested sequence, a mapping, a flow collection, a block scalar or an empty
    entry is refused, because its YAML value is not the row's text.
    """
    if not line.startswith("- ") and line != "-":
        raise Unparsed(where + ": non-list item: " + line)
    text = line[2:].lstrip(" ")
    if text[:1] in ("'", '"') and _quoted_end(text, 0) == len(text):
        return text[1:-1]
    if not text or text[0] in "-?:,[]{}#&*!|>'\"%@`" or ": " in text or text.endswith(":"):
        raise Unparsed(where + ": list item is not one scalar: " + line)
    if _typed_plain(text):
        raise Unparsed(where + ": plain scalar YAML 1.1 reads as other than a string (#5734): " + line)
    return text


def _parse_filters(trigger: str, sub: List[Tuple[int, str]]) -> Dict[str, List[str]]:
    filters: Dict[str, List[str]] = {}
    if not sub:
        return filters
    key_indent = sub[0][0]
    seen_keys: Set[str] = set()
    k = 0
    while k < len(sub):
        # Deeper rows are read below as the key's list items; _nest refuses a row
        # between the trigger column and the key column (no open block there, #5777).
        body = sub[k][1]
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*) *:(?: +(.*))?$", body)
        if not m:
            raise Unparsed(trigger + ": unreadable filter line: " + body)
        key, rest = m.group(1), (m.group(2) or "").strip(" ")  # a Unicode space is text (#5748)
        if key.lower() in seen_keys:
            raise Unparsed(trigger + ": repeated filter key (#5666): " + key)
        seen_keys.add(key.lower())
        if key not in KNOWN_FILTER_KEYS:
            raise Unparsed(trigger + ": unsupported filter key: " + key)
        n = k + 1
        items: List[str] = []
        while n < len(sub) and sub[n][0] > key_indent:
            items.append(_filter_item(trigger + "." + key, sub[n][1]))
            n += 1
        if rest:
            # items is empty here: _nest refuses a deeper row after a row whose
            # value is not empty (it would continue that scalar, #5730, #5777).
            if key == "types" and not rest.startswith("["):
                word = _unquote(rest)
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", word):
                    raise Unparsed(trigger + ".types: scalar is not one plain word (#5669): " + rest)
                if word == rest and _typed_plain(word):
                    raise Unparsed(trigger + ".types: plain scalar YAML 1.1 reads as other than a string (#5734): "
                                   + rest)
                items = [word]
            else:
                items = _parse_inline_list(rest)
        elif not items:
            raise Unparsed(trigger + "." + key + ": filter key with no value (#5736)")
        filters[key] = items
        k = n
    return filters


# The only characters glob_match reads as themselves (#5943); '*' and '**' are read
# separately.  A '[' class and a '!' negation are refused, not read (#5968).
_PATTERN_LITERALS = frozenset(string.ascii_letters + string.digits + "._/-")
# What a contributor can do instead of a class or a negation.  branches-ignore is no
# way out: this reader refuses it as an unsupported filter key (KNOWN_FILTER_KEYS).
WAY_OUT = ("list the base branches positively as plain patterns in branches "
           "(branches-ignore is refused too: unsupported filter key)")
_REFUSED_READS = {
    "[": "a character class is not read",
    "!": "a negation is not read",
}


def glob_match(pattern: str, ref: str) -> bool:
    """True when one branches pattern matches ref.

    The pattern is translated to a Python regex and must match the whole ref.
    Read, each pinned by a test:
      ``**``     regex ``.*``: any run of characters, '/' included.
      ``*``      regex ``[^/]*``: any run of characters other than '/'.
      a letter, a digit, ``.``, ``_``, ``/`` or ``-``: itself.
    Refused with Unparsed: an empty pattern, a run of three or more '*', and
    every other character, for example ``[`` (a class), ``!`` (a negation),
    ``?``, ``+``, a backslash, ``]``, ``{``, ``(``, ``@``, ``^``, ``$``, ``|``, a
    space or a non-ASCII letter.  The refusal of a class and of a negation names
    the way out (WAY_OUT).  The read forms follow GitHub's documented filter pattern
    cheat sheet; this function was not compared with GitHub's own evaluator.
    """
    if not pattern:
        raise Unparsed("empty pattern has no modelled GitHub meaning (#5943)")
    regex: List[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            run = len(pattern) - i - len(pattern[i:].lstrip("*"))
            if run > 2:
                raise Unparsed("a run of three or more '*' has no modelled GitHub meaning (#5943): " + pattern)
            regex.append(".*" if run == 2 else "[^/]*")
            i += run
            continue
        if ch not in _PATTERN_LITERALS:
            why = _REFUSED_READS.get(ch)
            if why:
                raise Unparsed("pattern character " + repr(ch) + " has no modelled GitHub meaning (" + why
                               + ", #5968): " + pattern + "; " + WAY_OUT)
            raise Unparsed("pattern character " + repr(ch) + " has no modelled GitHub meaning (#5943): " + pattern)
        regex.append(re.escape(ch))
        i += 1
    return re.fullmatch("".join(regex), ref) is not None


def filter_matches(patterns: List[str], ref: str) -> bool:
    """True when any branches item matches ref.

    Every item is read, so a refused item (a ``[`` class or a ``!`` negation
    among them) raises Unparsed even after an earlier item matched.
    """
    matched = False
    for pat in patterns:
        if glob_match(pat, ref):
            matched = True
    return matched


PUSH_ITEM_ALLOWED = re.compile(r"^[A-Za-z0-9._/*-]+$")
PUSH_ITEM_ALIAS_LIKE = re.compile(r"^\*[A-Za-z0-9_-]+$")
REHEARSAL_PREFIX = "rehearsal/"
REHEARSAL_BRANCH = "rehearsal"


def _push_item_problem(pat: str) -> str:
    """Why a push.branches item cannot be decided (allowlist: plain glob charset only)."""
    body = pat[1:] if pat.startswith("!") else pat
    if not PUSH_ITEM_ALLOWED.match(body):
        return "uses a form outside the plain glob allowlist (quote, tag, ?, +, [, backslash, ...)"
    if PUSH_ITEM_ALIAS_LIKE.match(body):
        return "is indistinguishable from a YAML alias"
    return ""


def _push_can_match_rehearsal(pat: str) -> bool:
    """True when a decidable push glob can match the branch ``rehearsal`` or any ref under ``rehearsal/``."""
    return _push_can_match_under(pat, REHEARSAL_PREFIX, REHEARSAL_BRANCH)


def _push_can_match_chain(pat: str) -> bool:
    """True when a decidable push glob can match the branch ``chain`` or any ref under ``chain/`` (#6117)."""
    return _push_can_match_under(pat, CHAIN_PREFIX, CHAIN_BRANCH)


def _push_can_match_under(pat: str, prefix: str, branch: str) -> bool:
    """True when a decidable push glob can match ``branch`` or any ref under ``prefix`` (closed-world, #5659)."""
    if branch in pat:
        return True
    tokens: List[str] = []
    i = 0
    while i < len(pat):
        if pat[i:i + 2] == "**":
            tokens.append("**")
            i += 2
        else:
            tokens.append(pat[i])
            i += 1

    def close(states: set) -> set:
        out = set(states)
        stack = list(states)
        while stack:
            st = stack.pop()
            if st < len(tokens) and tokens[st] in ("*", "**") and st + 1 not in out:
                out.add(st + 1)
                stack.append(st + 1)
        return out

    states = close({0})
    for ch in prefix:
        nxt = set()
        for st in states:
            if st >= len(tokens):
                continue
            tok = tokens[st]
            if tok == "**" or (tok == "*" and ch != "/") or tok == ch:
                nxt.add(st if tok in ("*", "**") else st + 1)
        states = close(nxt)
        if not states:
            break
    # Any live state after the whole prefix can still complete: literals extend the
    # ref and stars match empty, so some ref under the prefix matches.
    return bool(states) or glob_match(pat, branch)


def concurrency_group(text: str) -> Optional[str]:
    """The ``group`` value of the top-level ``concurrency:`` block, '' without a group row, None without the block.

    Read from the same closed-world rows parse_triggers() uses (#6117), so a file
    the reader refuses never yields a group here either.
    """
    if text.startswith("﻿"):
        text = text[1:]
    rows = _meaningful(text)
    start = None
    for idx, (ind, _body, key) in enumerate(rows):
        if ind == 0 and key == "concurrency":
            start = idx
            break
    if start is None:
        return None
    for ind, body, key in rows[start + 1:]:
        if ind == 0:
            break
        if key == "group":
            return body[len("group"):].lstrip(" ")[1:].strip(" ")
    return ""


def violations(name: str, text: str) -> List[str]:
    """Every rule violation for one workflow file's text (empty list = clean)."""
    try:
        triggers = parse_triggers(text)
        group = concurrency_group(text)
    except Unparsed as exc:
        # Closed world (#5731): a file the reader cannot read is a failure, whatever
        # words its raw text holds; an escaped key spells a trigger with none of them.
        return [f"{name}: R-SHAPE cannot parse triggers ({exc})"]
    try:
        return _rule_violations(name, triggers, group)
    except Unparsed as exc:
        # A filter item the glob reader cannot read (a [ class, a ! negation, an
        # empty item, or any character or construct outside the modelled set) is
        # a named failure too, not an exception out of violations() (#5777,
        # #5853, #5854, #5943, #5968).
        return [f"{name}: R-SHAPE cannot match filters ({exc})"]


def _rule_violations(name: str, triggers: Dict[str, Dict[str, List[str]]],
                     group: Optional[str] = None) -> List[str]:
    """R-PR, R-PUSH, R-CHAIN and R-CHAIN-KEY violations for one file's parsed triggers.

    ``group`` is the top-level concurrency group (see concurrency_group()); None
    means the file declares no ``concurrency:`` block.
    """
    found: List[str] = []
    for trig in PR_TRIGGERS:
        if trig not in triggers:
            continue
        flt = triggers[trig]
        if "branches" not in flt:
            continue  # no base filter: matches every base, carrier included
        branches = flt["branches"]
        for pat in branches:
            # Every item is read before any verdict, so one the matcher does not
            # model is refused by its trigger and its full spelling (#5943).
            try:
                glob_match(pat, CARRIER)
            except Unparsed as exc:
                raise Unparsed(f"{trig}.branches item {pat!r}: {exc}") from exc
        if any(filter_matches(branches, base) for base in GATED_BASES):
            if CARRIER_PATTERN not in branches:
                found.append(f"{name}: R-PR {trig}.branches lacks {CARRIER_PATTERN}")
            if not filter_matches(branches, CARRIER):
                found.append(f"{name}: R-PR {trig}.branches does not match {CARRIER}")
    if "push" in triggers:
        flt = triggers["push"]
        if "branches" in flt:
            patterns = flt["branches"]
            for pat in patterns:
                problem = _push_item_problem(pat)
                if problem:
                    found.append(f"{name}: R-PUSH push.branches item {pat!r} {problem}")
                elif not pat.startswith("!") and _push_can_match_rehearsal(pat):
                    found.append(f"{name}: R-PUSH push.branches item {pat!r} can match a rehearsal ref")
        elif "tags" not in flt:
            found.append(f"{name}: R-PUSH push has no branches and no tags filter (matches every branch)")
    # R-CHAIN (#6117): the required-set workflows run on every push to a chain carrier.
    push_branches = (triggers.get("push") or {}).get("branches") or []
    if name in CHAIN_PUSH_WORKFLOWS:
        if CHAIN_PATTERN not in push_branches:
            found.append(f"{name}: R-CHAIN push.branches lacks {CHAIN_PATTERN} (#6117)")
        elif not filter_matches(push_branches, CHAIN_CARRIER):
            found.append(f"{name}: R-CHAIN push.branches does not match {CHAIN_CARRIER} (#6117)")
    # R-CHAIN-KEY (#2508, #6117): a chain carrier is a PR HEAD (the promotion PR), so a
    # workflow that runs on both events for it must key its cancel group per event.
    chain_push = [pat for pat in push_branches
                  if not _push_item_problem(pat) and not pat.startswith("!") and _push_can_match_chain(pat)]
    if chain_push and any(trig in triggers for trig in PR_TRIGGERS) and group is not None \
            and EVENT_DISTINCT not in group:
        found.append(f"{name}: R-CHAIN-KEY push.branches {chain_push[0]!r} can match a chain ref, the workflow "
                     f"also triggers on pull_request, and concurrency.group does not name {EVENT_DISTINCT} "
                     "(#2508 cancelled twin, #6117)")
    return found


def load_all() -> Dict[str, str]:
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    return {p.name: p.read_text(encoding="utf-8") for p in files}


def _replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) < 1:
        raise AssertionError("mutation anchor not found: " + old)
    return text.replace(old, new, 1)


def named_cells() -> List[Tuple[str, str, str]]:
    """(name, text, refusal reason) for each known-bad shape of PR #5665 rounds 3 to 8.

    Sixteen cells are reproducers from the round-3 review (F1 #5730, F2 #5731, F3
    #5732), from the round-4 differential (#5733-#5736, #5748-#5750) or from the
    round-4 review (F2, an indented first row, #5777).  Six are the class items of
    round 6 (#5853, #5854).  Sixteen are the pattern items of round 7 (#5943,
    #5856, #5857).  Thirteen are the class and negation items of round 8 (#5968;
    a class in each position, a negated class, a '!' before and after a positive
    item, a list of only '!' items, '!!x', '!' with '**').  PyYAML 6.0.1 reads each
    round-6, round-7 and round-8 item as the same plain string the reader hands to
    the glob.  The test below runs every cell each time.  The PyYAML differential
    of each round ran the cells that existed then as fixed cases (see the module
    docstring); it compares parse_triggers() only, so for the round-6, round-7 and
    round-8 cells, which are refused by the glob and not by the parse, it checks
    the item text and not the refusal.
    """
    jobs = "jobs:\n  a:\n    runs-on: x\n"
    ci = _replace_once(load_all()["ci.yml"], '    branches: [main, develop, "release/**", "rehearsal/**", "chain/**"]\n',
                       '    branches:\n      - main\n      - develop\n      - "release/**"\n'
                       '      - release/v1.0.0\n        - rehearsal/**\n')
    escape = "double-quoted scalar holds a backslash"
    pr = "on:\n" + GOOD_PR
    return [
        ("F1-5730-block-list-continuation", ci, "continues the scalar"),
        ("F2-5731-escaped-push-key", 'on:\n  "pu\\x73h":\n    branches: ["rehearsal/**"]\n' + jobs, escape),
        ("F2-5731-escaped-pull-request-key", 'on:\n  "pull\\x5frequest":\n    branches: [main]\n' + jobs, escape),
        ("F2-5731-escaped-on-key", '"o\\x6e":\n  "pu\\x73h":\n    branches: ["rehearsal/**"]\n' + jobs, escape),
        ("F3-5732-noncharacter-fdd0", "name: x  # \ufdd0\n" + pr, "noncharacter"),
        ("F3-5732-noncharacter-1fffe", "name: x  # \U0001fffe\n" + pr, "noncharacter"),
        ("F3-5732-block-list-at-key-column", "on:\n  pull_request:\n    branches:\n    - main\n", "indentless sequence"),
        ("5733-empty-flow-entry", "on:\n  pull_request:\n    branches: [main,, 'rehearsal/**']\n", "empty flow entry"),
        ("5733-colon-in-flow-scalar", "on:\n  pull_request:\n    branches: [main, 'rehearsal/**', a:b]\n",
         "':' inside a plain flow scalar"),
        ("5734-typed-block-item", pr + "    paths:\n      - yes\n", "reads as other than a string"),
        ("5735-boolean-trigger-name", "on:\n  ON:\n    branches: [x]\n" + GOOD_PR, "reads as a boolean or null"),
        ("5736-filter-key-no-value", "on:\n  push:\n    branches:\n    tags: [v1]\n", "filter key with no value"),
        ("5748-unicode-space-before-flow", "on:\n  push:\n    branches: \u2003[main]\n" + GOOD_PR,
         "unterminated or non-list flow value"),
        ("5749-merge-key-list-entry", "name: x\n" + pr + "x:\n  - a\n  - <<\n", "plain << or ="),
        ("5750-deeper-leading-blank", "name: x\n" + pr + "x: |-\n    \n  contents: read\n",
         "leading blank line of a block scalar"),
        ("R4-F2-indented-first-row", "  name: x\n" + pr, "less indented than the first row"),
    ] + [
        ("R6-" + tag + "-class-item", "on:\n  pull_request:\n    branches: [main, 'rehearsal/**', '" + item + "']\n", why)
        for tag, item, why in (
            ("5853-empty-class", "a[]b", "a character class is not read"),
            ("5853-reversed-range", "[z-a]", "a character class is not read"),
            ("5854-bang-led", "[!a]", "a character class is not read"),
            ("5854-caret-led", "[^a]", "a character class is not read"),
            ("5854-close-bracket-first", "[]a]", "a character class is not read"),
            ("5854-underscore", "[_]", "a character class is not read"),
        )
    ] + [
        ("R7-" + tag, "on:\n  pull_request:\n    branches: [main, 'rehearsal/**', '" + item + "']\n",
         "no modelled GitHub meaning")
        for tag, item in (
            ("5943-plus-excludes-carrier", "!rehearsal/audit+-wip"),
            ("5943-question-excludes-carrier", "!rehearsal/audi?t-wip"),
            ("5943-backslash-excludes-carrier", "!rehearsal/\\audit-wip"),
            ("5856-question", "a?b"),
            ("5856-plus", "a+b"),
            ("5857-backslash", "a\\b"),
            ("5857-lone-close-bracket", "a]b"),
            ("5857-mid-pattern-bang", "a!b"),
            ("5943-double-bang", "!!rehearsal/audit-wip"),
            ("5943-extglob", "rehearsal/@(audit)-wip"),
            ("5943-three-stars", "rehearsal/***"),
            ("5943-space", "rehearsal/a b"),
            ("5943-non-ascii", "rehearsal/é"),
        )
    ] + [
        ("R7-5943-brace-block-list", "on:\n  pull_request:\n    branches:\n      - main\n      - 'rehearsal/**'\n"
         "      - 'rehearsal/{audit,x}-wip'\n", "no modelled GitHub meaning"),
        ("R7-5943-empty-item", "on:\n  pull_request:\n    branches: [main, 'rehearsal/**', '']\n", "empty pattern"),
        ("R7-5943-bare-bang", "on:\n  pull_request:\n    branches: [main, 'rehearsal/**', '!']\n",
         "a negation is not read"),
    ] + [
        ("R8-5968-" + tag, "on:\n  pull_request:\n    branches: " + flow + "\n", why)
        for tag, flow, why in (
            ("class-leading", "[main, 'rehearsal/**', '[a-c]x']", "a character class is not read"),
            ("class-middle", "[main, 'rehearsal/**', 'x[a-c]y']", "a character class is not read"),
            ("class-trailing", "[main, 'rehearsal/**', 'x[a-c]']", "a character class is not read"),
            ("class-whole-item", "[main, 'rehearsal/**', '[a-c]']", "a character class is not read"),
            ("class-after-double-star", "[main, 'rehearsal/**', 'rehearsal/**/[a-c]']",
             "a character class is not read"),
            ("negated-class-bang", "[main, 'rehearsal/**', 'rehearsal/[!a]']", "a character class is not read"),
            ("negated-class-caret", "[main, 'rehearsal/**', 'rehearsal/[^a]']", "a character class is not read"),
            ("bang-before-positive", "['!rehearsal/audit-wip', main, 'rehearsal/**']", "a negation is not read"),
            ("bang-after-positive", "[main, 'rehearsal/**', '!rehearsal/audit-wip']", "a negation is not read"),
            ("only-bang-items", "['!main', '!develop']", "a negation is not read"),
            ("double-bang", "[main, 'rehearsal/**', '!!x']", "a negation is not read"),
            ("bang-with-double-star", "[main, 'rehearsal/**', '!rehearsal/**']", "a negation is not read"),
            ("bang-then-class", "[main, 'rehearsal/**', '![a-z]x']", "a negation is not read"),
        )
    ]


class NamedCells5665(unittest.TestCase):
    """Every named known-bad cell is refused with its own reason (rounds 3 to 8)."""

    def test_5665_named_cells_refused(self) -> None:
        cells = named_cells()
        self.assertEqual(51, len(cells))
        for name, text, why in cells:
            got = violations("x.yml", text)
            self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (name, why, got))


class LiveWorkflows5447(unittest.TestCase):
    def test_5447_live_workflows_clean(self) -> None:
        workflows = load_all()
        self.assertGreaterEqual(len(workflows), 20, "workflow census shrank")
        found: List[str] = []
        for name, text in workflows.items():
            found.extend(violations(name, text))
        self.assertEqual([], found, "\n".join(found))

    def test_5447_census_has_gating_workflows(self) -> None:
        # Guards the reader against going vacuous: the gating population exists
        # and the reader classifies it as gating (not silently skipped).
        gating = []
        for name, text in load_all().items():
            try:
                trig = parse_triggers(text)
            except Unparsed:
                continue
            for t in PR_TRIGGERS:
                flt = trig.get(t)
                if flt is not None and "branches" in flt and any(
                    filter_matches(flt["branches"], b) for b in GATED_BASES
                ):
                    gating.append(name)
        for required in ("ci.yml", "c8-precheck.yml", "token-budget.yml", "coverage.yml"):
            self.assertIn(required, gating)
        self.assertGreaterEqual(len(gating), 12)


class Mutants5447(unittest.TestCase):
    """Unmutated control first, then mutants of the live files; none may survive."""

    def setUp(self) -> None:
        self.live = load_all()

    def test_5447_control_unmutated_is_clean(self) -> None:
        for name in ("ci.yml", "c8-precheck.yml", "token-budget.yml", "coverage.yml"):
            self.assertEqual([], violations(name, self.live[name]), name)

    def _assert_killed(self, name: str, mutant: str, needle: str) -> None:
        got = violations(name, mutant)
        self.assertTrue(any(needle in v for v in got), f"mutant survived: {name} {needle}: {got}")

    def test_5447_m01_remove_entry_from_ci(self) -> None:
        t = self.live["ci.yml"]
        m = re.sub(r'(pull_request:\s*\n\s*branches: \[[^\]]*?), "rehearsal/\*\*"', r"\1", t, count=1)
        self.assertNotEqual(t, m)
        self._assert_killed("ci.yml", m, "R-PR")

    def test_5447_m02_remove_entry_from_c8(self) -> None:
        t = self.live["c8-precheck.yml"]
        m = re.sub(r'(pull_request:\s*\n\s*branches: \[[^\]]*?), "rehearsal/\*\*"', r"\1", t, count=1)
        self.assertNotEqual(t, m)
        self._assert_killed("c8-precheck.yml", m, "R-PR")

    def test_5447_m03_remove_entry_from_every_file(self) -> None:
        for name, text in self.live.items():
            m = re.sub(r'(pull_request:\s*\n\s*branches: \[[^\]]*?), "rehearsal/\*\*"', r"\1", text, count=1)
            if m != text:
                self._assert_killed(name, m, "R-PR")

    def test_5447_m04_add_to_push_ci(self) -> None:
        t = self.live["ci.yml"]
        m = re.sub(r'(push:\s*\n\s*branches: \[[^\]]*?)\]', r'\1, "rehearsal/**"]', t, count=1)
        self.assertNotEqual(t, m)
        self._assert_killed("ci.yml", m, "R-PUSH")

    def test_5447_m05_add_literal_carrier_to_push(self) -> None:
        t = self.live["token-budget.yml"]
        m = re.sub(r'(push:\s*\n\s*branches: \[[^\]]*?)\]', r'\1, "rehearsal/audit-wip"]', t, count=1)
        self.assertNotEqual(t, m)
        self._assert_killed("token-budget.yml", m, "R-PUSH")

    def test_5447_m06_push_wide_glob_matches_carrier(self) -> None:
        t = self.live["c8-precheck.yml"]
        m = re.sub(r'(push:\s*\n\s*branches: \[[^\]]*?)\]', r'\1, "re*/**"]', t, count=1)
        self.assertNotEqual(t, m)
        self._assert_killed("c8-precheck.yml", m, "R-PUSH")

    def test_5447_m07_rename_pattern_in_pull_request(self) -> None:
        t = self.live["ci.yml"]
        m = _replace_once(t, '"rehearsal/**"', '"rehearsals/**"')
        self._assert_killed("ci.yml", m, "R-PR")

    def test_5447_m08_branches_ignore_shape(self) -> None:
        t = self.live["ci.yml"]
        m = re.sub(r"(pull_request:\s*\n\s*)branches:", r"\1branches-ignore:", t, count=1)
        self.assertNotEqual(t, m)
        self._assert_killed("ci.yml", m, "R-SHAPE")

    def test_5447_m09_flow_style_on(self) -> None:
        t = self.live["ci.yml"]
        m = re.sub(r"(?m)^on:\s*$", "on: [push, pull_request]", t, count=1)
        self.assertNotEqual(t, m)
        self._assert_killed("ci.yml", m, "R-SHAPE")

    def test_5447_m10_unterminated_list(self) -> None:
        t = self.live["ci.yml"]
        m = re.sub(r'(pull_request:\s*\n\s*branches: \[[^\]]*?)\]', r"\1", t, count=1)
        self.assertNotEqual(t, m)
        self._assert_killed("ci.yml", m, "R-SHAPE")

    def test_5447_m11_push_without_branches_or_tags(self) -> None:
        t = self.live["token-budget.yml"]
        m = re.sub(r"(push:\s*\n)\s*branches: \[[^\]]*\]", r"\1    paths: ['src/**']", t, count=1)
        self.assertNotEqual(t, m)
        self._assert_killed("token-budget.yml", m, "R-PUSH")

    def test_5447_m12_unknown_filter_key(self) -> None:
        t = self.live["ci.yml"]
        m = re.sub(r"(pull_request:\s*\n)", r"\1    mystery-filter: [a]\n", t, count=1)
        self.assertNotEqual(t, m)
        self._assert_killed("ci.yml", m, "R-SHAPE")

    def test_5447_m13_negated_entry_excludes_carrier(self) -> None:
        # A leading '!' is refused, not read (#5968, 5-agent vote 4d3ea1c5): the
        # mutant is killed by the R-SHAPE refusal, not by an R-PR finding.
        t = self.live["c8-precheck.yml"]
        m = re.sub(
            r'(pull_request:\s*\n\s*branches: \[[^\]]*?)\]', r'\1, "!rehearsal/audit-wip"]', t, count=1
        )
        self.assertNotEqual(t, m)
        self._assert_killed("c8-precheck.yml", m, "R-SHAPE cannot match filters")

    def test_5447_m14_block_list_form_without_entry(self) -> None:
        t = (
            "name: x\non:\n  pull_request:\n    branches:\n      - main\n"
            "      - develop\n  push:\n    branches: [main]\njobs: {}\n"
        )
        self._assert_killed("x.yml", t, "R-PR")

    def test_5447_m15_block_list_form_with_entry_is_clean(self) -> None:
        t = (
            "name: x\non:\n  pull_request:\n    branches:\n      - main\n"
            "      - 'rehearsal/**'\n  push:\n    branches: [main]\njobs: {}\n"
        )
        self.assertEqual([], violations("x.yml", t))

    def test_5447_m16_tags_only_push_is_clean(self) -> None:
        t = "name: x\non:\n  push:\n    tags:\n      - 'v*'\njobs: {}\n"
        self.assertEqual([], violations("x.yml", t))

    def test_5447_m17_pull_request_target_checked(self) -> None:
        t = "name: x\non:\n  pull_request_target:\n    branches: [main]\njobs: {}\n"
        self._assert_killed("x.yml", t, "R-PR")


def _with_on_block(body: str) -> str:
    return "name: x\non:\n" + body + "jobs: {}\n"


GOOD_PR = "  pull_request:\n    branches: [main, 'rehearsal/**']\n"
GOOD_PUSH = "  push:\n    branches: [main]\n"


class LeadingWhitespace5660(unittest.TestCase):
    """#5660: a non-space leading character must fail closed, never end the on: block."""

    def _red(self, text: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v for v in got), got)

    def test_5660_control_clean(self) -> None:
        self.assertEqual([], violations("x.yml", _with_on_block(GOOD_PUSH + GOOD_PR)))

    def test_5660_tab_before_trigger(self) -> None:
        self._red(_with_on_block(GOOD_PUSH + "\tpull_request:\n    branches: [main]\n"))

    def test_5660_tab_before_filter_key(self) -> None:
        self._red(_with_on_block("  pull_request:\n\tbranches: [main]\n" + GOOD_PUSH))

    def test_5660_mixed_space_tab(self) -> None:
        self._red(_with_on_block(GOOD_PUSH + " \tpull_request:\n    branches: [main]\n"))

    def test_5660_nbsp_leading(self) -> None:
        self._red(_with_on_block(GOOD_PUSH + "\u00a0pull_request:\n    branches: [main]\n"))

    def test_5660_form_feed_leading(self) -> None:
        self._red(_with_on_block(GOOD_PUSH + "\x0cpull_request:\n    branches: [main]\n"))

    def test_5660_bom_led_line(self) -> None:
        self._red(_with_on_block(GOOD_PUSH + "\ufeff  pull_request:\n    branches: [main]\n"))

    def test_5660_lone_cr_line_break(self) -> None:
        self._red(_with_on_block(GOOD_PUSH + GOOD_PR).replace("\n  push:", "\r  push:", 1))

    def test_5660_lone_cr_hides_a_trigger_in_a_comment(self) -> None:
        # Without the lone-CR rule the CR-separated trigger vanishes into the comment
        # (the file is then refused for a repeated branches key instead);
        # test_5705_lone_cr_is_refused_by_its_own_rule pins the lone-CR reason.
        self._red(_with_on_block(GOOD_PUSH + "  # note\r  pull_request:\n    branches: [main]\n"))

    def test_5660_crlf_trailing_whitespace_stripped(self) -> None:
        self.assertEqual("x: y", _strip_comment("x: y \r"))

    def test_5660_unicode_line_separator(self) -> None:
        self._red(_with_on_block(GOOD_PUSH + GOOD_PR + "  # x\u2028  y\n"))

    def test_5660_crlf_file_stays_clean(self) -> None:
        text = _with_on_block(GOOD_PUSH + GOOD_PR).replace("\n", "\r\n")
        self.assertEqual([], violations("x.yml", text))

    def test_5660_bom_at_stream_start_stays_clean(self) -> None:
        self.assertEqual([], violations("x.yml", "\ufeff" + _with_on_block(GOOD_PUSH + GOOD_PR)))

    def test_5660_tab_led_line_after_a_block_scalar_header_is_refused(self) -> None:
        # Changed by #5705: a tab-led row is refused wherever it is, because it can
        # also sit inside a multi-line quoted scalar that hides rows from the reader.
        self._red(_with_on_block(GOOD_PUSH + GOOD_PR) + "x:\n  run: |\n\t\techo hi\n")


def _push_text(entries: str) -> str:
    return _with_on_block("  push:\n    branches: " + entries + "\n" + GOOD_PR)


class PushNeverRehearsal5659(unittest.TestCase):
    """#5659: push.branches may never match any ref under rehearsal/ (closed-world)."""

    def _red(self, entries: str) -> None:
        got = violations("x.yml", _push_text(entries))
        self.assertTrue(any("R-PUSH" in v for v in got), (entries, got))

    def _clean(self, entries: str) -> None:
        self.assertEqual([], violations("x.yml", _push_text(entries)), entries)

    def test_5659_live_sweep_has_no_rehearsal_push_entry(self) -> None:
        for name, text in load_all().items():
            flt = parse_triggers(text).get("push") or {}
            for pat in flt.get("branches", []):
                self.assertNotIn("rehearsal", pat, name)
                self.assertFalse(_push_can_match_rehearsal(pat), (name, pat))

    def test_5659_other_rehearsal_branch_literal(self) -> None:
        self._red("[main, develop, 'release/**', 'rehearsal/landing']")

    def test_5659_double_quoted_literal(self) -> None:
        self._red('[main, "rehearsal/landing"]')

    def test_5659_bare_rehearsal_branch_name(self) -> None:
        self._red("[main, rehearsal]")

    def test_5659_single_star_under_rehearsal(self) -> None:
        self._red("[main, 'rehearsal/*']")

    def test_5659_wildcard_prefix_re_star(self) -> None:
        self._red("[main, 're*']")

    def test_5659_star_star_everything(self) -> None:
        self._red("[main, '**']")

    def test_5659_slash_star_pairs(self) -> None:
        self._red("[main, '*/*']")

    def test_5659_star_slash_carrier_tail(self) -> None:
        self._red("[main, '*/audit-wip']")

    def test_5659_r_star_star(self) -> None:
        self._red("[main, 'r*/**']")

    def test_5659_rehearsal_word_anywhere_is_listed(self) -> None:
        for pat in ("rehearsalx", "xrehearsal", "rehearsal-landing"):
            self._red("[main, '" + pat + "']")

    def test_5659_wildcards_not_matching_the_carrier_literal(self) -> None:
        # None of these match rehearsal/audit-wip; each can match another rehearsal ref.
        for pat in ("*/landing", "**/landing", "r*/land*", "*/land**", "re*/x"):
            self.assertFalse(filter_matches([pat], CARRIER), pat)
            self._red("[main, '" + pat + "']")

    def test_5659_cannot_match_under_rehearsal_slash_is_clean(self) -> None:
        # Star never crosses '/', so this cannot match a ref UNDER rehearsal/.
        self._clean("[main, 'rehear*-x']")
        self._clean("[main, 'release/*', 'rel*/**', 'main*']")

    def test_5659_inline_list_quote_rules(self) -> None:
        for bad in ("[a, 'b,c']", "[a, b']", "[a, 'b]", "['a, b']"):
            with self.assertRaises(Unparsed):
                _parse_inline_list(bad)
        self.assertEqual(["a", "b"], _parse_inline_list("[a, 'b']"))

    def test_5659_pull_request_wildcard_without_literal_entry_is_red(self) -> None:
        text = _with_on_block("  pull_request:\n    branches: [main, 'rehearsal/*']\n" + GOOD_PUSH)
        got = violations("x.yml", text)
        self.assertTrue(any("lacks" in v for v in got), got)

    def test_5659_block_list_form(self) -> None:
        text = _with_on_block("  push:\n    branches:\n      - main\n      - rehearsal/landing\n" + GOOD_PR)
        self.assertTrue(any("R-PUSH" in v for v in violations("x.yml", text)))

    def test_5659_undecidable_special_forms_fail_closed(self) -> None:
        for pat in ("re+hearsal/**", "r[e]hearsal/**", "re?hearsal/x", "rehearsal\\\\/x"):
            self._red("[main, '" + pat + "']")

    def test_5659_yaml_tag_and_alias_forms_fail_closed(self) -> None:
        # Since #5733 a plain tag or alias inside a flow list is an R-SHAPE refusal
        # (PyYAML: a str tag, and a ComposerError for the undefined alias); a quoted
        # one stays an R-PUSH failure of the plain glob charset.
        for entries in ("[main, !!str rehearsal/landing]", "[main, *prb]"):
            got = violations("x.yml", _push_text(entries))
            self.assertTrue(any("R-SHAPE" in v and "anchor, alias, tag" in v for v in got), (entries, got))
        self._red("[main, '!!str x']")

    def test_5659_branches_ignore_interplay_is_shape_red(self) -> None:
        text = _with_on_block("  push:\n    branches-ignore: ['rehearsal/**']\n" + GOOD_PR)
        self.assertTrue(any("R-SHAPE" in v for v in violations("x.yml", text)))

    def test_5659_quoted_comma_is_unparsed(self) -> None:
        got = violations("x.yml", _push_text("[main, 'a,rehearsal/x']"))
        self.assertTrue(got, got)

    def test_5659_negation_only_entry_is_clean(self) -> None:
        self._clean("[main, '!rehearsal/**']")

    def test_5659_benign_lists_stay_clean(self) -> None:
        self._clean("[main, develop, 'release/**']")
        self._clean("[main, 'release/v0.6.3.1', feat/v0.7.0-grand-slam]")
        self._clean("[release/**]")


HOUSE_KEY = ("x-${{ github.event.pull_request.head.repo.full_name == github.repository && "
             "github.event.pull_request.head.ref || github.event.pull_request.number || github.ref_name }}")
EVENT_KEY = "x-${{ github.event_name }}-${{ github.event.pull_request.number || github.ref_name }}"


def _with_conc(body: str, group: Optional[str]) -> str:
    """A workflow text with the given on: body and a concurrency block (None = no block, '' = no group row)."""
    text = "name: x\non:\n" + body
    if group is None:
        return text + "jobs: {}\n"
    if group == "":
        return text + "concurrency:\n  cancel-in-progress: true\njobs: {}\n"
    return text + "concurrency:\n  group: " + group + "\n  cancel-in-progress: true\njobs: {}\n"


class ChainPushCoverage6117(unittest.TestCase):
    """#6117: the required-set workflows run on every push to a chain carrier, under an event-distinct key."""

    CHAIN_PUSH = "  push:\n    branches: [main, develop, 'release/**', 'chain/**']\n"

    def setUp(self) -> None:
        self.live = load_all()

    # ---- live sweep (red on the pre-#6117 tree, green once the trigger lands) ----

    def test_6117_live_required_set_lists_chain_on_push(self) -> None:
        for name in CHAIN_PUSH_WORKFLOWS:
            self.assertIn(name, self.live, "required-set workflow missing from the census")
            flt = parse_triggers(self.live[name]).get("push") or {}
            branches = flt.get("branches", [])
            self.assertIn(CHAIN_PATTERN, branches, (name, branches))
            self.assertTrue(filter_matches(branches, CHAIN_CARRIER), (name, branches))
            self.assertEqual([], [v for v in violations(name, self.live[name]) if "R-CHAIN" in v])

    def test_6117_live_chain_push_workflows_key_per_event(self) -> None:
        # Every live workflow that pushes on a chain ref AND gates PRs keys its cancel
        # group per event; the six required-set carriers must be among them.
        keyed = []
        for name, text in self.live.items():
            trig = parse_triggers(text)
            pats = (trig.get("push") or {}).get("branches", [])
            if not any(_push_can_match_chain(p) for p in pats if not _push_item_problem(p)):
                continue
            if not any(t in trig for t in PR_TRIGGERS):
                continue
            group = concurrency_group(text)
            self.assertIsNotNone(group, name)
            self.assertIn(EVENT_DISTINCT, group or "", (name, group))
            keyed.append(name)
        for name in CHAIN_PUSH_WORKFLOWS:
            self.assertIn(name, keyed)

    def test_6117_live_rehearsal_stays_off_push(self) -> None:
        # The chain ruling does not loosen R-PUSH: no live push filter matches rehearsal/.
        for name, text in self.live.items():
            for pat in (parse_triggers(text).get("push") or {}).get("branches", []):
                self.assertFalse(_push_can_match_rehearsal(pat), (name, pat))

    # ---- mutants of the live files ----

    def _assert_killed(self, name: str, mutant: str, needle: str) -> None:
        got = violations(name, mutant)
        self.assertTrue(any(needle in v for v in got), f"mutant survived: {name} {needle}: {got}")

    def test_6117_m01_remove_chain_from_each_required_push(self) -> None:
        for name in CHAIN_PUSH_WORKFLOWS:
            t = self.live[name]
            m = re.sub(r'(push:\s*\n\s*branches: \[[^\]]*?), "chain/\*\*"', r"\1", t, count=1)
            self.assertNotEqual(t, m, name)
            self._assert_killed(name, m, "R-CHAIN push.branches lacks")

    def test_6117_m02_drop_event_name_from_each_dual_trigger_key(self) -> None:
        for name in CHAIN_PUSH_WORKFLOWS:
            t = self.live[name]
            m = t.replace("${{ github.event_name }}-", "", 1)
            self.assertNotEqual(t, m, name)
            self._assert_killed(name, m, "R-CHAIN-KEY")

    def test_6117_m03_narrow_chain_to_a_literal_that_is_not_the_carrier(self) -> None:
        t = self.live["ci.yml"]
        m = t.replace('"chain/**"]', '"chain/promo5"]', 1)
        self.assertNotEqual(t, m)
        self._assert_killed("ci.yml", m, "R-CHAIN push.branches lacks")

    def test_6117_control_unmutated_required_set_is_clean(self) -> None:
        for name in CHAIN_PUSH_WORKFLOWS:
            self.assertEqual([], violations(name, self.live[name]), name)

    # ---- synthetic shapes ----

    def test_6117_rule_is_scoped_to_the_required_set(self) -> None:
        # A workflow outside CHAIN_PUSH_WORKFLOWS owes no chain push entry.
        self.assertEqual([], violations("token-budget.yml", _with_conc(GOOD_PUSH + GOOD_PR, HOUSE_KEY)))
        got = violations("ci.yml", _with_conc(GOOD_PUSH + GOOD_PR, HOUSE_KEY))
        self.assertTrue(any("R-CHAIN push.branches lacks chain/**" in v for v in got), got)

    def test_6117_wildcard_without_the_literal_entry_is_red(self) -> None:
        text = _with_conc("  push:\n    branches: [main, 'chain/*']\n" + GOOD_PR, EVENT_KEY)
        got = violations("coverage.yml", text)
        self.assertTrue(any("R-CHAIN push.branches lacks chain/**" in v for v in got), got)

    def test_6117_house_key_with_chain_push_and_pr_is_red(self) -> None:
        got = violations("x.yml", _with_conc(self.CHAIN_PUSH + GOOD_PR, HOUSE_KEY))
        self.assertTrue(any("R-CHAIN-KEY" in v and "chain/**" in v for v in got), got)
        self.assertFalse(any("R-CHAIN push" in v for v in got), got)

    def test_6117_house_key_with_a_glob_that_reaches_chain_is_red(self) -> None:
        for pat in ("ch*/**", "*/promo6-ssh", "**", "chain", "chainx"):
            text = _with_conc("  push:\n    branches: [main, '" + pat + "']\n" + GOOD_PR, HOUSE_KEY)
            got = violations("x.yml", text)
            self.assertTrue(any("R-CHAIN-KEY" in v for v in got), (pat, got))

    def test_6117_event_distinct_key_is_clean(self) -> None:
        self.assertEqual([], violations("x.yml", _with_conc(self.CHAIN_PUSH + GOOD_PR, EVENT_KEY)))
        self.assertEqual([], violations("ci.yml", _with_conc(self.CHAIN_PUSH + GOOD_PR, EVENT_KEY)))

    def test_6117_push_only_workflow_needs_no_event_key(self) -> None:
        # One trigger cannot produce the #2508 twin (rule (d) near-miss shape).
        self.assertEqual([], violations("x.yml", _with_conc(self.CHAIN_PUSH, HOUSE_KEY)))

    def test_6117_no_concurrency_block_is_clean_and_no_group_row_is_red(self) -> None:
        self.assertEqual([], violations("x.yml", _with_conc(self.CHAIN_PUSH + GOOD_PR, None)))
        got = violations("x.yml", _with_conc(self.CHAIN_PUSH + GOOD_PR, ""))
        self.assertTrue(any("R-CHAIN-KEY" in v for v in got), got)

    def test_6117_pull_request_target_counts_as_a_pr_trigger(self) -> None:
        text = _with_conc(self.CHAIN_PUSH + "  pull_request_target:\n    branches: [main, 'rehearsal/**']\n",
                          HOUSE_KEY)
        self.assertTrue(any("R-CHAIN-KEY" in v for v in violations("x.yml", text)))

    def test_6117_undecidable_push_item_is_r_push_not_r_chain_key(self) -> None:
        got = violations("x.yml", _with_conc("  push:\n    branches: [main, 'ch?in/**']\n" + GOOD_PR, HOUSE_KEY))
        self.assertTrue(any("R-PUSH" in v for v in got), got)
        self.assertFalse(any("R-CHAIN-KEY" in v for v in got), got)

    def test_6117_negated_chain_item_is_clean_for_the_key_rule(self) -> None:
        text = _with_conc("  push:\n    branches: [main, '!chain/**']\n" + GOOD_PR, HOUSE_KEY)
        self.assertFalse(any("R-CHAIN-KEY" in v for v in violations("x.yml", text)))

    def test_6117_concurrency_group_reader(self) -> None:
        self.assertIsNone(concurrency_group(_with_conc(GOOD_PR, None)))
        self.assertEqual("", concurrency_group(_with_conc(GOOD_PR, "")))
        self.assertEqual(EVENT_KEY, concurrency_group(_with_conc(GOOD_PR, EVENT_KEY)))
        self.assertEqual('"q-${{ github.ref }}"', concurrency_group(_with_conc(GOOD_PR, '"q-${{ github.ref }}"')))
        # A job-level concurrency block is not the top-level one.
        text = "name: x\non:\n" + GOOD_PR + "jobs:\n  a:\n    concurrency:\n      group: j\n    runs-on: x\n"
        self.assertIsNone(concurrency_group(text))
        # The live required-set files all declare one.
        for name in CHAIN_PUSH_WORKFLOWS:
            self.assertTrue(concurrency_group(self.live[name]), name)

    def test_6117_chain_prefix_matcher_mirrors_the_rehearsal_one(self) -> None:
        for pat in ("chain/**", "chain/*", "chain", "ch*/x", "*/x", "**", "c*"):
            self.assertTrue(_push_can_match_chain(pat), pat)
        for pat in ("main", "release/**", "rehearsal/**", "chai*-x", "x/*", "cha*n-x"):
            self.assertFalse(_push_can_match_chain(pat), pat)
        self.assertTrue(_push_can_match_rehearsal("rehearsal/**"))
        self.assertFalse(_push_can_match_rehearsal("chain/**"))


class DuplicateKeys5666(unittest.TestCase):
    """#5666: a repeated trigger name or filter key under on: is Unparsed, never last-wins."""

    BAD = "    branches: ['rehearsal/x']\n"

    def _shape(self, text: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v for v in got), got)

    def test_5666_duplicate_push_first_is_bad(self) -> None:
        self._shape(_with_on_block("  push:\n" + self.BAD + GOOD_PUSH + GOOD_PR))

    def test_5666_duplicate_push_last_is_bad(self) -> None:
        self._shape(_with_on_block(GOOD_PUSH + "  push:\n" + self.BAD + GOOD_PR))

    def test_5666_duplicate_push_clean_twice(self) -> None:
        self._shape(_with_on_block(GOOD_PUSH + GOOD_PUSH + GOOD_PR))

    def test_5666_duplicate_push_other_case(self) -> None:
        self._shape(_with_on_block("  push:\n" + self.BAD + "  Push:\n    branches: [main]\n" + GOOD_PR))

    def test_5666_duplicate_push_capital_first(self) -> None:
        self._shape(_with_on_block("  Push:\n    branches: [main]\n" + "  push:\n" + self.BAD + GOOD_PR))

    def test_5666_duplicate_pull_request(self) -> None:
        self._shape(_with_on_block(GOOD_PUSH + GOOD_PR + GOOD_PR))

    def test_5666_duplicate_branches_under_push(self) -> None:
        self._shape(_with_on_block("  push:\n" + self.BAD + "    branches: [main]\n" + GOOD_PR))

    def test_5666_duplicate_branches_under_pull_request(self) -> None:
        self._shape(_with_on_block(GOOD_PUSH + GOOD_PR + "    branches: [main]\n"))

    def test_5666_duplicate_filter_key_other_case(self) -> None:
        self._shape(_with_on_block("  push:\n    branches: [main]\n    Branches: [x]\n" + GOOD_PR))

    def test_5666_duplicate_paths_filter(self) -> None:
        self._shape(_with_on_block(GOOD_PUSH + GOOD_PR + "    paths: [a]\n    paths: [b]\n"))

    def test_5666_duplicate_non_gated_trigger(self) -> None:
        self._shape(_with_on_block(GOOD_PUSH + GOOD_PR + "  workflow_dispatch:\n  workflow_dispatch:\n"))

    def test_5666_branches_and_branches_ignore_together(self) -> None:
        self._shape(_with_on_block("  push:\n    branches: [main]\n    branches-ignore: [x]\n" + GOOD_PR))

    def test_5666_distinct_keys_stay_clean(self) -> None:
        text = _with_on_block(GOOD_PUSH + GOOD_PR + "    paths: [a]\n  workflow_dispatch:\n")
        self.assertEqual([], violations("x.yml", text))


class DuplicateTopLevel5667(unittest.TestCase):
    """#5667: a repeated top-level key (compared unquoted and case-folded) is Unparsed.

    Since #5708 a second on spelled true, yes or On is refused as a YAML 1.1
    boolean key before the repeat check sees it.
    """

    TAIL = "  push:\n    branches: ['rehearsal/x']\n"

    def _shape(self, text: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v for v in got), got)

    def _base(self) -> str:
        return _with_on_block(GOOD_PUSH + GOOD_PR)

    def test_5667_control_clean(self) -> None:
        self.assertEqual([], violations("x.yml", self._base()))

    def test_5667_second_on_after_jobs(self) -> None:
        self._shape(self._base() + "on:\n" + self.TAIL)

    def test_5667_second_on_double_quoted(self) -> None:
        self._shape(self._base() + '"on":\n' + self.TAIL)

    def test_5667_second_on_single_quoted(self) -> None:
        self._shape(self._base() + "'on':\n" + self.TAIL)

    def test_5667_second_on_spelled_true(self) -> None:
        self._shape(self._base() + "true:\n" + self.TAIL)

    def test_5667_second_on_spelled_yes(self) -> None:
        self._shape(self._base() + "yes:\n" + self.TAIL)

    def test_5667_second_on_other_case(self) -> None:
        self._shape(self._base() + "On:\n" + self.TAIL)
        self._shape(self._base() + "ON:\n" + self.TAIL)

    def test_5667_repeated_unrelated_top_level_key(self) -> None:
        self._shape(self._base() + "name: y\n")

    def test_5667_repeated_key_other_case(self) -> None:
        self._shape(self._base() + "Name: y\n")

    def test_5667_repeated_key_quoted_and_bare(self) -> None:
        self._shape(self._base() + '"name": y\n')

    def test_5667_first_on_quoted_second_bare(self) -> None:
        text = 'name: x\n"on":\n' + GOOD_PUSH + GOOD_PR + "jobs: {}\non:\n" + self.TAIL
        self._shape(text)


class TopLevelShapes5668(unittest.TestCase):
    """#5668: every indent-0 row except one leading --- must be a mapping key, else Unparsed.

    The key is a bare word or an escape-free quoted word (TOP_KEY).
    """

    def _shape(self, text: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v for v in got), got)

    def _base(self) -> str:
        return _with_on_block(GOOD_PUSH + GOOD_PR)

    BAD = "on:\n  push:\n    branches: ['rehearsal/x']\n"

    def test_5668_control_clean(self) -> None:
        self.assertEqual([], violations("x.yml", self._base()))

    def test_5668_single_leading_document_start_is_clean(self) -> None:
        self.assertEqual([], violations("x.yml", "---\n" + self._base()))

    def test_5668_second_document(self) -> None:
        self._shape(self._base() + "---\nextra: y\n")

    def test_5668_document_end_marker(self) -> None:
        self._shape(self._base() + "...\n")

    def test_5668_two_leading_document_starts(self) -> None:
        self._shape("---\n---\n" + self._base())

    def test_5668_document_start_with_content(self) -> None:
        self._shape("--- !!map\n" + self._base())

    def test_5668_yaml_directive(self) -> None:
        self._shape("%YAML 1.1\n" + self._base())

    def test_5668_top_level_sequence_entry(self) -> None:
        self._shape(self._base() + "- x\n")

    def test_5668_complex_key(self) -> None:
        self._shape(self._base() + "? on\n")

    def test_5668_merge_key(self) -> None:
        self._shape(self._base() + "<<: *a\n")

    def test_5668_anchored_key(self) -> None:
        self._shape("&a on:\n  push:\n    branches: [main]\n" + GOOD_PR)

    def test_5668_tagged_key(self) -> None:
        self._shape(self._base() + "!!str x: y\n")

    def test_5668_flow_mapping_document(self) -> None:
        self._shape("{on: {push: {branches: ['rehearsal/x']}}}\n")

    def test_5668_flow_sequence_document(self) -> None:
        self._shape("[on, push]\n")

    def test_5668_escaped_double_quoted_key(self) -> None:
        self._shape(self._base() + '"o\\x6e": 1\n')

    def test_5668_multiline_double_quoted_value(self) -> None:
        self._shape('name: "x\n' + self._base()[len("name: x\n"):] + 'extra: "\n')

    def test_5668_multiline_single_quoted_value(self) -> None:
        self._shape("name: 'x\n" + self._base()[len("name: x\n"):] + "extra: '\n")

    def test_5668_non_ascii_first_character_row(self) -> None:
        self._shape(self._base() + "\u00e9: 1\n")

    def test_5668_scalar_document(self) -> None:
        self._shape("just text\n" + self._base())

    def test_5668_block_scalar_value_stays_clean(self) -> None:
        self.assertEqual([], violations("x.yml", "name: |\n  text\n" + self._base()[len("name: x\n"):]))


class TypesScalar5669(unittest.TestCase):
    """#5669: a scalar after types: must be one plain or quoted word, else Unparsed."""

    def _pr(self, types_line: str) -> str:
        return _with_on_block(GOOD_PUSH + GOOD_PR + "    " + types_line + "\n")

    def _shape(self, types_line: str) -> None:
        got = violations("x.yml", self._pr(types_line))
        self.assertTrue(any("R-SHAPE" in v for v in got), (types_line, got))

    def test_5669_plain_and_quoted_words_stay_clean(self) -> None:
        for line in ("types: opened", "types: 'opened'", 'types: "synchronize"', "types: [opened, closed]"):
            self.assertEqual([], violations("x.yml", self._pr(line)), line)

    def test_5669_block_scalar_indicators(self) -> None:
        for line in ("types: |", "types: >", "types: |-", "types: >+"):
            self._shape(line)

    def test_5669_anchor_alias_tag(self) -> None:
        for line in ("types: &a", "types: &a opened", "types: *a", "types: !!str opened"):
            self._shape(line)

    def test_5669_flow_mapping(self) -> None:
        self._shape("types: {a: b}")

    def test_5669_unbalanced_or_spaced_scalar(self) -> None:
        for line in ("types: 'opened", 'types: opened"', "types: opened closed", "types: -"):
            self._shape(line)


class ClosedWorld5705(unittest.TestCase):
    """#5705: every line needs a positive rule; a line no rule accepts is Unparsed.

    Measured against the reader at b5bcf59b9: every refusal case here except
    test_5705_form_feed_and_vertical_tab_mid_row failed there, and the clean
    cases passed. Each PyYAML 6.0.1 view quoted in a comment was measured with
    yaml.safe_load on the same text.
    """

    J = "jobs:\n  a:\n    runs-on: x\n"
    PUSH_BAD = "on:\n  push:\n    branches: ['rehearsal/**']\n"
    LEAD = "non-space whitespace or a non-ASCII"

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5705_control_clean(self) -> None:
        self.assertEqual([], violations("x.yml", "name: x\non:\n" + GOOD_PUSH + GOOD_PR + self.J))

    def test_5705_nbsp_led_first_on_row(self) -> None:
        # PyYAML: the first key is the string NBSP+"on"; the second on: is the trigger block.
        self._shape("\u00a0on:\n" + GOOD_PR + self.PUSH_BAD + self.J, self.LEAD)

    def test_5705_tab_led_first_on_row(self) -> None:
        self._shape("\ton:\n" + GOOD_PR + self.PUSH_BAD + self.J, self.LEAD)

    def test_5705_tab_row_inside_escaped_double_quote(self) -> None:
        # Round-2 reproducer 2. PyYAML: name swallows the tab row; on = the push block.
        # Since #5706 the escaped quote is refused first; the tab row alone is pinned
        # by test_5705_tab_led_first_on_row.
        self._shape('name: "a\\"\n\ton:\n' + GOOD_PR + 'zz: 1 #"\n' + self.PUSH_BAD + self.J, "backslash")

    def test_5705_unicode_space_led_rows(self) -> None:
        for lead in ("\u200b", "\u2003", "\u3000", "\u00a0 ", " \u00a0"):
            self._shape("name: x\non:\n" + GOOD_PR + lead + "zz: 1\n" + self.J, self.LEAD)

    def test_5705_tab_or_nbsp_before_a_colon(self) -> None:
        self._shape("name: x\non\t:\n" + GOOD_PR + self.J, "tab on a structure row")
        # PyYAML: the trigger key is the string "pull_request" + NBSP, not pull_request.
        self._shape("name: x\non:\n  pull_request\u00a0:\n    branches: [main]\n" + self.J, "unreadable trigger")
        self._shape("name: x\non:\n" + GOOD_PR + "    branches\u00a0: [main]\n" + self.J, "unreadable filter")

    def test_5705_tab_after_a_colon(self) -> None:
        self._shape("name: x\non:\t\n" + GOOD_PR + self.J, "tab on a structure row")
        self._shape("name: x\non:\n" + GOOD_PR + "zz:\t{}\n" + self.J, "tab on a structure row")

    def test_5705_nested_multiline_quote_hides_column_0_rows(self) -> None:
        # PyYAML: in the first text jobs.a.name swallows the on: rows and the file has
        # no on key at all. The second text is a PyYAML ParserError; both are refused.
        self._shape("name: x\njobs:\n  a:\n    name: \"a\non:\n" + GOOD_PR + "zz: 1 #\"\n    runs-on: x\n",
                    "does not close on its row")
        self._shape("name: x\njobs:\n  a:\n    - 'a\non:\n" + GOOD_PR + "zz: 1 #'\n", "does not close on its row")

    def test_5705_multiline_flow_collection(self) -> None:
        self._shape("name: x\njobs:\n  a:\n    with: [a,\non:\n" + GOOD_PR + "zz: b]\n", "does not close on its row")
        self._shape("name: x\non:\n" + GOOD_PR + "x:\n  with: {a: b,\n    c: d}\n", "does not close on its row")

    def test_5705_single_row_flow_collections_stay_clean(self) -> None:
        text = "name: x\non:\n" + GOOD_PR + "x:\n  with: {a: 'b', c: [\"d\", e]}\n"
        self.assertEqual([], violations("x.yml", text))

    def test_5705_block_scalar_lines_led_by_tab_or_nbsp(self) -> None:
        base = "name: x\non:\n" + GOOD_PR + "x:\n  run: |\n"
        self._shape(base + "\t\techo hi\n", self.LEAD)
        self._shape(base + "    echo a\n    \techo hi\n", "block scalar line starts with a tab or a Unicode space")
        self._shape(base + "    \u00a0echo hi\n", "block scalar line starts with a tab or a Unicode space")

    def test_5705_block_scalar_line_less_indented_than_first(self) -> None:
        self._shape("name: x\non:\n" + GOOD_PR + "x:\n  run: |\n      echo a\n    echo b\n", "less indented")

    def test_5705_block_scalar_content_is_not_read_as_rows(self) -> None:
        body = "x:\n  - run: |\n      on:\n      \"a\\\n      '\n    # ok\n  - y: >-\n\n      z: 'w\n"
        self.assertEqual([], violations("x.yml", "name: x\non:\n" + GOOD_PUSH + GOOD_PR + body))

    def test_5705_block_scalar_indentation_indicator(self) -> None:
        self._shape("name: x\non:\n" + GOOD_PR + "x:\n  run: |2\n    echo\n", "after a block scalar header")

    def test_5705_inner_bom_and_control_characters(self) -> None:
        for ch in ("\ufeff", "\x07", "\x00", "\x7f", "\x9b", "\ufffe"):
            self._shape("name: x" + ch + "\non:\n" + GOOD_PR, "control character")

    def test_5705_form_feed_and_vertical_tab_mid_row(self) -> None:
        for ch in ("\x0c", "\x0b"):
            self._shape("name: a" + ch + "b\non:\n" + GOOD_PR, "line-break character")

    def test_5705_plain_scalar_continuation_row(self) -> None:
        # PyYAML: name is "a b"; the reader refuses the bare row instead of guessing.
        self._shape("name: a\n  b\non:\n" + GOOD_PR + self.J, "neither a mapping key")

    def test_5705_indented_document_markers(self) -> None:
        for row in ("  ---\n", "  ...\n"):
            self._shape("name: x\non:\n" + GOOD_PR + "x:\n" + row, "neither a mapping key")

    def test_5705_nested_anchor_alias_tag_merge_and_complex_key(self) -> None:
        cases = (("  a: &x 1\n", "anchor"), ("  b: *x\n", "anchor"), ("  c: !!str 1\n", "anchor"),
                 ("  <<: *x\n", "merge key"), ("  ? c\n", "neither a mapping key"),
                 ("  - ? c\n", "indicator where a value"), ("  d: e: f\n", "nested mapping"))
        for row, why in cases:
            self._shape("name: x\non:\n" + GOOD_PR + "x:\n" + row, why)

    def test_5705_sequence_rows_stay_clean(self) -> None:
        body = "x:\n  - a\n  -\n  - - b\n  - 'c'\n  - \"d\"  # e\n  - k: v\n    l: [m]\n"
        self.assertEqual([], violations("x.yml", "name: x\non:\n" + GOOD_PR + body))

    def test_5705_every_live_file_is_read(self) -> None:
        # GREEN CONTROL: every real workflow parses; none is waved through as Unparsed.
        live = load_all()
        for name, text in live.items():
            self.assertTrue(parse_triggers(text), name)
        self.assertGreaterEqual(len(live), 20)


class QuotedScalars5706(unittest.TestCase):
    """#5706: a quoted scalar holds no backslash and no quote of its own kind, else Unparsed."""

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5706_escaped_double_quote_hides_the_on_block(self) -> None:
        # PyYAML: name holds the on: rows as text; the file has no on key at all.
        self._shape('name: "a\\"\non:\n' + GOOD_PR + 'zz: 1 #"\njobs: {}\n', "backslash")

    def test_5706_escaped_double_quote_at_nested_level(self) -> None:
        self._shape("name: x\non:\n" + GOOD_PR + 'x:\n  a: "b\\"\n  c: 1 #"\n', "backslash")
        self._shape("name: x\non:\n" + GOOD_PR + 'x:\n  - "b\\"\n', "backslash")

    def test_5706_any_backslash_in_double_quotes(self) -> None:
        self._shape("name: x\non:\n" + GOOD_PR + 'x:\n  a: "b\\nc"\n', "backslash")
        self._shape('"o\\x6e":\n' + GOOD_PR, "backslash")

    def test_5706_doubled_single_quote(self) -> None:
        self._shape("name: 'it''s'\non:\n" + GOOD_PR, "doubled quote")
        self._shape("name: x\non:\n" + GOOD_PR + "x:\n  - 'a''\n", "doubled quote")

    def test_5706_escapes_inside_flow_collections(self) -> None:
        self._shape("name: x\non:\n  pull_request:\n    branches: [main, \"a\\\", 'rehearsal/**']\n", "backslash")
        self._shape("name: x\non:\n" + GOOD_PR + "x: ['it''s']\n", "doubled quote")

    def test_5706_other_kind_of_quote_inside_stays_clean(self) -> None:
        text = "name: \"a'b\"\non:\n" + GOOD_PR + "x:\n  a: 'c\"d'\n  e: [\"f'g\", 'h\"i']\n"
        self.assertEqual([], violations("x.yml", text))


class BooleanKeys5708(unittest.TestCase):
    """#5708: a top-level YAML 1.1 boolean spelling is accepted only as on, "on" or 'on'."""

    def _shape(self, text: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and "YAML 1.1 boolean" in v for v in got), got)

    def test_5708_false_family_pairs(self) -> None:
        # PyYAML: off and no are one False key. YAML 1.1 also reads false and n as one
        # key; PyYAML reads n as a string.
        self._shape("off: 1\nno: 2\non:\n" + GOOD_PR)
        self._shape("false: 1\nn: 2\non:\n" + GOOD_PR)

    def test_5708_every_other_spelling_any_case_or_quoting(self) -> None:
        for word in ("y", "Y", "yes", "Yes", "n", "N", "no", "NO", "true", "True", "false", "FALSE",
                     "off", "Off", "On", "ON", '"On"', "'TRUE'", '"off"', "'y'"):
            self._shape("name: x\non:\n" + GOOD_PR + word + ": 1\n")

    def test_5708_true_is_not_read_as_the_on_block(self) -> None:
        # A YAML 1.2 reader reads true: as the boolean true key, not as on.
        self._shape("name: x\ntrue:\n" + GOOD_PR)

    def test_5708_on_spellings_stay_clean(self) -> None:
        for key in ("on", '"on"', "'on'"):
            self.assertEqual([], violations("x.yml", "name: x\n" + key + ":\n" + GOOD_PR), key)


class DocTruth5707(unittest.TestCase):
    """#5707: each reason the reader gives, and each claim its comments make, is measured.

    Every refused line-break character is named by its code point, and none of
    them is called a YAML 1.1 line break: YAML 1.1 breaks only on LF, CR, NEL,
    U+2028 and U+2029, while form feed, vertical tab and U+001C..U+001F are refused
    because str.splitlines (or, for U+001F, the YAML printable set) disagrees.
    """

    BREAKS = ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x1f", "\x85", " ", " ")

    def test_5707_each_extra_line_break_is_named_by_code_point(self) -> None:
        for ch in self.BREAKS:
            got = violations("x.yml", "name: a" + ch + "b\non:\n" + GOOD_PR)
            code = "U+%04X" % ord(ch)
            self.assertTrue(any("R-SHAPE" in v and code in v and "YAML 1.1" not in v for v in got),
                            (code, got))

    def test_5707_document_markers_only_one_leading_start(self) -> None:
        # _meaningful keeps column-0 markers as rows; _check_top_level accepts only a
        # leading ---. A trailing --- or ... is refused like any other marker.
        self.assertEqual([], violations("x.yml", "---\nname: x\non:\n" + GOOD_PR))
        for tail in ("---\n", "...\n", "--- # c\n", "... # c\n"):
            got = violations("x.yml", "name: x\non:\n" + GOOD_PR + tail)
            self.assertTrue(any("R-SHAPE" in v and "not a plain mapping key" in v for v in got), (tail, got))

    def test_5707_space_like_covers_control_and_format_characters(self) -> None:
        for ch in ("\t", " ", " ", " ", "\x85", "\x01", "​", "‎"):
            self.assertTrue(_space_like(ch), repr(ch))
        for ch in ("a", "#", "-", "é"):
            self.assertFalse(_space_like(ch), repr(ch))


class ReaderMutants5705(unittest.TestCase):
    """#5705: cases added for reader mutants the earlier cases let survive.

    Each case names the rule it pins in the reason it requires.
    """

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5705_quote_inside_a_plain_flow_scalar(self) -> None:
        # PyYAML: ['a"b', 'c"']. The reader does not split such items; it refuses them.
        self._shape("name: x\non:\n" + GOOD_PR + 'x: [a"b, c"]\n', "quote inside a plain flow scalar")

    def test_5705_comment_inside_a_flow_collection(self) -> None:
        # PyYAML: the comment swallows the closing bracket, so the collection runs on
        # into the next rows (here a ParserError).
        self._shape("name: x\non:\n" + GOOD_PR + "x: [a, # c]\n", "does not close on its row")

    def test_5705_block_scalar_content_one_column_past_its_owner(self) -> None:
        # PyYAML: run is "echo\n"; content may start one column past the key that owns it.
        for body in ("x: |\n a\n", "x:\n  - run: |\n     echo\n"):
            self.assertEqual([], violations("x.yml", "name: x\non:\n" + GOOD_PR + body), body)

    def test_5705_lone_cr_is_refused_by_its_own_rule(self) -> None:
        for text in (_with_on_block(GOOD_PUSH + GOOD_PR).replace("\n  push:", "\r  push:", 1),
                     _with_on_block(GOOD_PUSH + "  # note\r  pull_request:\n    branches: [main]\n")):
            self._shape(text, "lone carriage return")

    def test_5705_comment_needs_a_space_before_it(self) -> None:
        # PyYAML 6 reads "a"#c as "a" plus a comment; YAML 1.2 needs a space before #.
        self._shape("name: x\non:\n" + GOOD_PR + 'x: "a"#c\n', "text after a quoted scalar")
        self._shape("name: x\non:\n" + GOOD_PR + "x: [a]#c\n", "text after a flow collection")


class FailClosed5731(unittest.TestCase):
    """#5731: a file the reader cannot read is a failure whatever words it holds.

    Measured at 71fe391b4: each escaped-key text below was clean there, because the
    old escape hatch let an unreadable file pass when the literal words
    pull_request, pull_request_target and push were absent. PyYAML 6.0.1 reads the
    escaped key as push, pull_request or on.
    """

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5731_escaped_trigger_keys(self) -> None:
        for text in ('on:\n  "pu\\x73h":\n    branches: ["rehearsal/**"]\n',
                     'on:\n  "pull\\x5frequest":\n    branches: [main]\n',
                     '"o\\x6e":\n  "pu\\x73h":\n    branches: ["rehearsal/**"]\n'):
            self._shape(text + ClosedWorld5705.J, "cannot parse")

    def test_5731_unreadable_file_without_trigger_words(self) -> None:
        self._shape("name: x\non:\n  workflow_dispatch:\nzz: [a,\n", "cannot parse")

    def test_5731_gated_trigger_name_in_another_case(self) -> None:
        # PyYAML keeps Push and PULL_REQUEST as distinct keys; how GitHub matches
        # event names by case is not measured here, so the reader refuses them.
        for name in ("Push", "PUSH", "Pull_Request", "pull_request_TARGET"):
            self._shape("on:\n  " + name + ":\n    branches: [main]\n", "gated trigger name in another case")

    def test_5731_quoted_mapping_keys_below_the_top_level(self) -> None:
        for row in ('  "push":\n', "  'push':\n", '  "x":\n', "  - 'k': v\n"):
            self._shape("name: x\non:\n" + GOOD_PR + "x:\n" + row, "quoted mapping key")
        for row in ('"jobs": 1\n', "'x': 1\n"):
            self._shape("name: x\non:\n" + GOOD_PR + row, "quoted mapping key other than a top-level on")

    def test_5731_top_level_on_spellings_stay_clean(self) -> None:
        for key in ("on", '"on"', "'on'"):
            self.assertEqual([], violations("x.yml", key + ":\n" + GOOD_PR), key)


class BlockStructure5730(unittest.TestCase):
    """#5730: a row must sit at the column of an open block of its own kind.

    Measured at 71fe391b4: 18 of the 20 refusal cases here were accepted there. The
    other two were refused there for another reason and now carry the #5730 one:
    x: then - a at column 0 (a column-0 row that is not a key) and the pull_request
    filter row between two columns (an unexpected filter indentation).  Each PyYAML
    6.0.1 view quoted in a comment was measured with yaml.safe_load on the same text.
    """

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5730_deeper_dash_row_continues_a_plain_entry(self) -> None:
        # The round-3 reproducer. PyYAML: [..., 'release/v1.0.0 - rehearsal/**'].
        ci = load_all()["ci.yml"]
        old = '    branches: [main, develop, "release/**", "rehearsal/**", "chain/**"]\n'
        new = ('    branches:\n      - main\n      - develop\n      - "release/**"\n'
               '      - release/v1.0.0\n        - rehearsal/**\n')
        self._shape(_replace_once(ci, old, new), "continues the scalar")

    def test_5730_deeper_rows_after_a_scalar_value(self) -> None:
        # PyYAML: the first is one plain scalar ('a\n- b'); the others are errors (#5776).
        for body in ("x:\n  - a\n\n    - b\n", "x:\n  - a\n    # c\n    - b\n",
                     "x: a\n  b: c\n", "x: 'a'\n  b: c\n", "x: [a]\n  - b\n", "x: |\n  a\nz: b\n   c: d\n"):
            self._shape("name: x\non:\n" + GOOD_PR + body, "continues the scalar")

    def test_5730_row_between_two_open_blocks(self) -> None:
        self._shape("name: x\non:\n" + GOOD_PR + "x:\n    a: 1\n  b: 2\n", "no open block")
        self._shape("name: x\non:\n  pull_request:\n      branches: [main]\n    types: [opened]\n", "no open block")
        self._shape("name: x\non:\n" + GOOD_PR + "x:\n  k:\n      a: b\n    c: d\n", "no open block")

    def test_5730_row_of_the_other_kind(self) -> None:
        self._shape("name: x\non:\n" + GOOD_PR + "x:\n  - a\n  b: c\n", "other kind")
        self._shape("name: x\non:\n" + GOOD_PR + "x:\n  b: c\n  - a\n", "other kind")

    def test_5730_indentless_sequence(self) -> None:
        # PyYAML: x is ['a'], then k is ['a']. The reader refuses a sequence at its key's column.
        self._shape("name: x\non:\n" + GOOD_PR + "x:\n- a\n", "indentless sequence")
        self._shape("name: x\non:\n" + GOOD_PR + "x:\n  k:\n  - a\n", "indentless sequence")
        self._shape("name: x\non:\n" + GOOD_PR + "x:\n  - k:\n    - a\n", "indentless sequence")

    def test_5730_filter_item_is_one_scalar(self) -> None:
        # PyYAML: [['a']], [{'a': 'b'}], [['a']], ['x\n'], [None] respectively.
        for item in ("- - a\n", "- a: b\n", "- [a]\n", "- |\n        x\n", "-\n"):
            self._shape("on:\n  pull_request:\n    branches:\n      " + item, "not one scalar")

    def test_5730_nested_blocks_stay_clean(self) -> None:
        body = ("x:\n  - a\n  -\n    - b\n  - - c\n    - d\n  - k: v\n    l:\n      - m\n"
                "    n: |\n      o\n  -\n    p: q\nw:\n  z: 1\n")
        self.assertEqual([], violations("x.yml", "name: x\non:\n" + GOOD_PR + body))


class FlowCollections5733(unittest.TestCase):
    """#5733: a flow collection is parsed entry by entry, not split on commas.

    Measured at 25af8bc7 (round-4 differential, seed 5665): every refusal case here
    was accepted there. Each PyYAML 6.0.1 view quoted in a comment was measured with
    yaml.safe_load on the same text.
    """

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def _branches(self, flow: str, why: str) -> None:
        self._shape("on:\n  pull_request:\n    branches: " + flow + "\n", why)

    def test_5733_empty_entries(self) -> None:
        # PyYAML: ParserError for the first two; a trailing comma ends the list and the
        # mapping with no further entry. The reader refuses all four.
        for flow in ("[main,, 'rehearsal/**']", "[,main, 'rehearsal/**']", "[main, 'rehearsal/**', ]"):
            self._branches(flow, "empty flow entry or trailing comma")
        self._shape("name: x\non:\n" + GOOD_PR + "x: {a: b, }\n", "empty flow entry or trailing comma")

    def test_5733_node_properties_inside_a_flow_collection(self) -> None:
        # PyYAML: ConstructorError (unknown tag), ComposerError (undefined alias), and
        # the anchored entry is the string 'rehearsal/**'.
        self._branches("[main, !x develop, 'rehearsal/**']", "anchor, alias, tag or reserved indicator")
        self._shape("name: x\non:\n" + GOOD_PR + "x: [a, *a]\n", "anchor, alias, tag or reserved indicator")
        self._branches("[main, &a rehearsal/**]", "anchor, alias, tag or reserved indicator")

    def test_5733_indicator_at_the_start_of_a_flow_entry(self) -> None:
        # PyYAML: ParserError for "- a"; "? a" is the one-pair mapping {'a': None} and
        # "-a" the string '-a'. The reader models none of them and refuses all three.
        for flow in ("[main, - a, 'rehearsal/**']", "[main, ? a, 'rehearsal/**']", "[main, -a, 'rehearsal/**']"):
            self._branches(flow, "flow entry starts with an indicator")

    def test_5733_colon_inside_a_plain_flow_scalar(self) -> None:
        # PyYAML: [..., {'ma': 'in'}] for the pair; 'a:b' is one plain scalar.
        for flow in ("[main, 'rehearsal/**', ma: in]", "[main, 'rehearsal/**', a:b]"):
            self._branches(flow, "':' inside a plain flow scalar")

    def test_5733_hash_inside_a_plain_flow_scalar(self) -> None:
        # PyYAML: 'a#b' is one plain scalar; the reader refuses it.
        self._branches("[main, a#b, 'rehearsal/**']", "'#' inside a plain flow scalar")

    def test_5733_non_ascii_inside_a_flow_collection(self) -> None:
        # PyYAML: 'rehearsal/**\xa0' and '\xa0rehearsal/**'; Python's str.strip() dropped
        # the no-break space, so the old reader read 'rehearsal/**' both times.
        self._branches("[main, rehearsal/**\u00a0]", "non-ASCII or control character in a flow scalar")
        self._branches("[main,\u00a0rehearsal/**]", "non-ASCII or control character in a flow scalar")

    def test_5733_text_after_a_flow_entry(self) -> None:
        # PyYAML: ParserError.
        self._branches("[main, [a] b, 'rehearsal/**']", "text after a flow entry")

    def test_5733_flow_mapping_entries(self) -> None:
        # PyYAML: {'a': None}, {'a:b': None}, {'a': 'b'} and {'a': None}; the reader
        # accepts only a plain key, ': ' and a value.
        for flow in ("{a}", "{a:b}", "{'a': b}", "{a: }"):
            self._shape("name: x\non:\n" + GOOD_PR + "x: " + flow + "\n", "flow mapping entry")

    def test_5733_inline_filter_list_holds_scalars_only(self) -> None:
        # PyYAML: [..., ['x']] and [..., {'a': 'b'}].
        for flow in ("[main, 'rehearsal/**', [x]]", "[main, 'rehearsal/**', {a: b}]"):
            self._branches(flow, "inline list item is not one scalar")

    def test_5733_flow_values_match_yaml(self) -> None:
        self.assertEqual(["main", "rehearsal/**"], _parse_inline_list("[ main ,  'rehearsal/**' ]"))
        self.assertEqual(["a b", "c"], _parse_inline_list("[a b, c]"))
        self.assertEqual([], _parse_inline_list("[ ]"))
        text = "name: x\non:\n" + GOOD_PR + "x:\n  with: { fetch-depth: 2 }\n  y: {}\n  z: [{a: [b, 'c']}, []]\n"
        self.assertEqual([], violations("x.yml", text))


class TypedPlainItems5734(unittest.TestCase):
    """#5734: a plain filter item YAML 1.1 reads as other than a string is refused.

    Measured at 25af8bc7 (round-4 differential, seed 5665): every refusal case here
    was accepted there. PyYAML 6.0.1 reads every plain word below as None, a
    bool, an int, a float or a date, or refuses it (<< and = in a sequence are a
    ConstructorError), except 0o7 and +.5, which it keeps as strings and YAML 1.2
    reads as numbers; the reader refuses them all.
    """

    WORDS = ("~", "null", "Null", "NULL", "yes", "No", "TRUE", "on", "Off", "1", "+1", "0x1f", "0o7",
             "1_000", "1:20", "1.5", ".5", "+.5", ".inf", "+.Inf", ".NaN", "2026-10-05", "<<", "=")

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    @staticmethod
    def _why(word: str) -> str:
        # << and = are refused wherever they stand, before the #5734 rule (#5749).
        if word in ("<<", "="):
            return "plain << or = (merge or value tag)"
        return "plain scalar YAML 1.1 reads as other than a string"

    def test_5734_plain_block_items(self) -> None:
        for word in self.WORDS:
            self._shape("on:\n  push:\n    branches: [main]\n    paths:\n      - " + word + "\n", self._why(word))

    def test_5734_plain_inline_items(self) -> None:
        # 1:20 is refused inside a flow collection by the #5733 colon rule.
        for word in (w for w in self.WORDS if ":" not in w):
            self._shape("on:\n  pull_request:\n    branches: [main, 'rehearsal/**', " + word + "]\n",
                        self._why(word))

    def test_5734_plain_types_word(self) -> None:
        for word in ("on", "yes", "Null", "NO"):
            self._shape("on:\n  pull_request:\n    types: " + word + "\n",
                        "plain scalar YAML 1.1 reads as other than a string")

    def test_5734_strings_stay_clean(self) -> None:
        # PyYAML: every item below is a string (quoted, or plain and not a typed form).
        body = ("on:\n  pull_request:\n    branches: [main, 'rehearsal/**', 'yes', \"1\"]\n"
                "    paths:\n      - .github/workflows/x.yml\n      - '~'\n      - v1.0\n      - nope\n"
                "    types: 'on'\n  push:\n    tags: ['1.0', v1.*]\n")
        self.assertEqual([], violations("x.yml", body))


class TriggerNames5735(unittest.TestCase):
    """#5735: a trigger name YAML 1.1 reads as a boolean or null is refused.

    Measured at 25af8bc7 (round-4 differential, seed 5665): every refusal case here
    was accepted there. PyYAML 6.0.1 reads ON, Yes, off and True as the key True or
    False, and null and NULL as the key None; it keeps y and n as strings, which the
    reader refuses too so every YAML11_BOOLEANS word is treated alike.
    """

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5735_boolean_or_null_trigger_names(self) -> None:
        for name in ("ON", "Yes", "off", "True", "null", "NULL", "y"):
            self._shape("on:\n  " + name + ":\n    branches: [x]\n  push:\n    branches: [main]\n",
                        "trigger name YAML 1.1 reads as a boolean or null")

    def test_5735_other_trigger_names_stay_clean(self) -> None:
        body = "on:\n  workflow_dispatch:\n  schedule:\n    - cron: '0 1 * * *'\n  nightly:\n" + GOOD_PR
        self.assertEqual([], violations("x.yml", body))


class EmptyFilterValue5736(unittest.TestCase):
    """#5736: a filter key with no value is refused; its YAML value is null.

    Measured at 25af8bc7 (round-4 differential, seed 5665): every refusal case here
    was accepted there with the key read as an empty list. PyYAML 6.0.1 reads each
    such key as None.
    """

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5736_filter_key_with_no_value(self) -> None:
        for body in ("  push:\n    branches:\n    tags: [v1]\n", "  push:\n    tags: [v1]\n    branches: # c\n",
                     GOOD_PR + "    paths:\n"):
            self._shape("on:\n" + body, "filter key with no value")

    def test_5736_empty_lists_stay_clean(self) -> None:
        self.assertEqual([], violations("x.yml", "on:\n" + GOOD_PR + "    paths: []\n"))


class CommentTruth5732(unittest.TestCase):
    """#5732: the stream comment and the filter row say only what the reader does.

    Measured at 252d250e: U+FDD0 and U+1FFFE in a comment were accepted, so the
    comment "noncharacters" was untrue; PyYAML 6.0.1 accepts 64 of the 66
    noncharacters and refuses U+FFFE and U+FFFF.  A block list at its key's own
    column (valid YAML) is refused, as the filter row now states.
    """

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5732_every_noncharacter_is_refused(self) -> None:
        for ch in ("﷐", "﷯", "\U0001fffe", "\U0010ffff"):
            self._shape("name: x  # " + ch + "\non:\n" + GOOD_PR, "noncharacter")

    def test_5732_other_non_ascii_in_a_comment_stays_clean(self) -> None:
        for ch in ("﷏", "ﷰ", "\U0001fffd", "é"):
            self.assertEqual([], violations("x.yml", "name: x  # " + ch + "\non:\n" + GOOD_PR))

    def test_5732_block_list_at_the_key_column_is_refused(self) -> None:
        body = GOOD_PR.replace("    branches: [main, 'rehearsal/**']\n", "    branches:\n    - main\n")
        self.assertNotEqual(body, GOOD_PR)
        got = violations("x.yml", "on:\n" + body)
        self.assertTrue(any("R-SHAPE" in v for v in got), got)


class UnicodeSpaceIsText5748(unittest.TestCase):
    """#5748: only ASCII space and tab are YAML white space; other Unicode spaces are text.

    Measured at 90a3f698 (round-4 differential, seed 5665, text 8715): each refusal
    case here was accepted there because Python's str.strip() dropped an EM SPACE
    (U+2003) that PyYAML 6.0.1 keeps, so the reader saw a list or a null where
    PyYAML reads the string shown in each comment.
    """

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5748_unicode_space_around_a_filter_value(self) -> None:
        # PyYAML: '\u2003[main]' (a string, not a list).
        self._shape("on:\n  push:\n    branches: \u2003[main]\n" + GOOD_PR, "unterminated or non-list flow value")
        # PyYAML: types 'opened\u2003'.
        self._shape("on:\n" + GOOD_PR + "    types: opened\u2003\n", "scalar is not one plain word")

    def test_5748_unicode_space_around_a_null_trigger(self) -> None:
        # PyYAML: push '\u2003~' and '~\u2003' (strings, not null).
        for value in ("\u2003~", "~\u2003"):
            self._shape("on:\n  push: " + value + "\n" + GOOD_PR, "inline value not supported")

    def test_5748_ascii_space_still_stripped(self) -> None:
        got = parse_triggers("on:\n  push:   ~  \n" + GOOD_PR + "    types:  opened  \n")
        self.assertEqual({"push": {}, "pull_request": {"branches": ["main", "rehearsal/**"], "types": ["opened"]}}, got)


class MergeAndValueScalars5749(unittest.TestCase):
    """#5749: a plain << or = is refused wherever it stands as a value or flow key.

    Measured at 90a3f698 (round-4 differential, seed 5665, texts 4721 and 15559):
    each refusal case here was accepted there.  PyYAML 6.0.1 resolves a plain << to
    the merge tag and a plain = to the value tag; as a value either raises
    ConstructorError, and {<<: {b: c}} merges to {b: c}.  Quoted, both are strings.
    """

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5749_plain_merge_or_value_scalar(self) -> None:
        why = "plain << or = (merge or value tag)"
        for tail in ("x: <<\n", "x: =\n", "x:\n  - a\n  - <<\n", "x:\n  - =\n", "x: [a, <<]\n",
                     "x: {a: =}\n", "x: {<<: {b: c}}\n"):
            self._shape("name: x\non:\n" + GOOD_PR + tail, why)

    def test_5749_quoted_or_longer_forms_stay_clean(self) -> None:
        for tail in ("x: '<<'\n", "x: \"=\"\n", "x: << b\n", "x: a=b\n", "x: [==, '<<']\n", "x:\n  =: y\n"):
            self.assertEqual([], violations("x.yml", "name: x\non:\n" + GOOD_PR + tail), tail)


class BlockScalarLeadingBlank5750(unittest.TestCase):
    """#5750: a leading blank line of a block scalar may not hold more spaces than its first line.

    Measured at 90a3f698 (round-4 differential, seed 5665, text 2130): the refusal
    case here was accepted there.  PyYAML 6.0.1 takes the block scalar's indentation
    from the longest leading blank line, so a shallower first content line ends the
    scalar and the row after it is a ParserError.
    """

    def _shape(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5750_deeper_leading_blank_line(self) -> None:
        why = "leading blank line of a block scalar holds more spaces than its first line"
        self._shape("name: x\non:\n" + GOOD_PR + "x: |-\n    \n  contents: read\n", why)
        self._shape("name: x\non:\n" + GOOD_PR + "x: >\n\n     \n   a\n   b\n", why)

    def test_5750_equal_or_shallower_blank_lines_stay_clean(self) -> None:
        # PyYAML: '\nb' for the first; the blank lines after content are content.
        for tail in ("x: |-\n    \n    b\n", "x: |\n  \n    b\n", "x: |\n  b\n      \n  c\n", "x: |-\n   \n  \nz: c\n"):
            self.assertEqual([], violations("x.yml", "name: x\non:\n" + GOOD_PR + tail), tail)


class ReasonTruth5732(unittest.TestCase):
    """#5732: each refusal reason and grammar row names only what the reader checks.

    Measured at 04e75e0e: a quoted flow item was refused as holding "an embedded
    comma or quote" though only a comma is checked there (a quote of the other
    kind is accepted); a block-scalar line led by U+200D (a format character, not
    white space) was refused as "non-space whitespace"; and the filter row said a
    types value is "one plain word" though a quoted word is accepted.
    """

    def _reason(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5732_embedded_comma_reason_names_the_comma_only(self) -> None:
        text = "on:\n  pull_request:\n    branches: [main, 'rehearsal/**', 'a,b']\n"
        self._reason(text, "quoted flow item with an embedded comma (#5733): ")
        quote = "on:\n  pull_request:\n    branches: [main, 'rehearsal/**', 'a\"b']\n"
        self.assertEqual({"pull_request": {"branches": ["main", "rehearsal/**", 'a"b']}}, parse_triggers(quote))

    def test_5732_block_scalar_lead_reason_names_what_is_refused(self) -> None:
        why = "block scalar line starts with a tab or a Unicode space, separator, control or format character"
        for ch in ("‍", " ", "\t"):
            self._reason("name: x\non:\n" + GOOD_PR + "x: |\n  " + ch + "a\n", why)

    def test_5732_types_row_says_a_quoted_word_is_accepted(self) -> None:
        text = "on:\n  pull_request:\n    branches: [main, 'rehearsal/**']\n    types: 'opened'\n"
        self.assertEqual(["opened"], parse_triggers(text)["pull_request"]["types"])
        doc = " ".join((__doc__ or "").split())
        self.assertIn("``types`` may also be one word, plain or simply quoted", doc)
        self.assertNotIn("``types`` may also be one plain word", doc)


class RoundFourMutants5665(unittest.TestCase):
    """Cases that pin reader lines round 4 changed, each named for the mutant it kills.

    The round-4 mutation run over 71fe391b..f321cc6b left eight mutants alive
    (N01, N02, N13, N18, N19, N20, N31, M08); each case below fails under one of
    them.  Each PyYAML 6.0.1 view quoted in a comment was measured with
    yaml.safe_load on the same text.
    """

    def _reason(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5748_strip_comment_keeps_unicode_space_as_text(self) -> None:
        # N01, N02. PyYAML: {'x': 'a #b'}; a '#' after U+2003 starts no comment.
        self.assertEqual("a #b", _strip_comment("a #b"))
        self.assertEqual("--- ", _strip_comment("--- "))
        # PyYAML: ScannerError; ---U+2003 is no document marker.
        self._reason("--- \nname: x\non:\n" + GOOD_PR, "row is neither a mapping key")

    def test_5748_unicode_space_on_value_is_a_scalar_on_form(self) -> None:
        # N31. PyYAML: {True: ' '}; the on: value is a string, not an empty block.
        self._reason("name: x\non:  \n", "flow/scalar on: form")

    def test_5733_flow_mapping_entry_with_no_value_before_a_comma(self) -> None:
        # N13. PyYAML: {'a': None, 'b': 'c'}; the reader refuses the null value.
        self._reason("name: x\non:\n" + GOOD_PR + "x: {a: , b: c}\n", "flow mapping entry with no value (#5733)")

    def test_5733_comment_after_a_quoted_flow_entry(self) -> None:
        # M08. PyYAML: ParserError; ' #' starts a comment, so the collection stays open.
        self._reason("name: x\non:\n" + GOOD_PR + "x: ['a' #c]\n", "flow collection does not close on its row")
        branches = "on:\n  pull_request:\n    branches: [main, 'rehearsal/**' # c]\n"
        self._reason(branches, "flow collection does not close on its row")

    def test_5750_longest_leading_blank_line_counts(self) -> None:
        # N18, N19. PyYAML: ParserError for both; the deepest leading blank line
        # sets the indentation, even when a shallower one follows it.
        why = "leading blank line of a block scalar holds more spaces than its first line (#5750)"
        self._reason("name: x\non:\n" + GOOD_PR + "x: |\n      \n  \n    a\n", why)
        self._reason("name: x\non:\n" + GOOD_PR + "x: |\n     \n    a\n", why)

    def test_5750_blank_count_resets_for_each_block_scalar(self) -> None:
        # N20. PyYAML: {'x': '\na\n', 'z': 'b\n'}.
        tail = "x: |\n      \n      a\nz: |\n  b\n"
        self.assertEqual([], violations("x.yml", "name: x\non:\n" + GOOD_PR + tail))


class RefusalBranches5665(unittest.TestCase):
    """#5777: every refusal branch of the reader is reached by a case that names it.

    The round-5 census at 528c2195 found ten branches no case reached.  Six are
    reachable and each case below asserts its reason; the other four were dead
    (an earlier rule refuses their input) and were removed.  Each PyYAML 6.0.1
    view quoted in a comment was measured with yaml.safe_load on the same text.
    """

    def _reason(self, text: str, why: str) -> None:
        got = violations("x.yml", text)
        self.assertTrue(any("R-SHAPE" in v and why in v for v in got), (why, got))

    def test_5665_first_row_indented(self) -> None:
        # Round-4 review F2. PyYAML: ParserError for both ("expected '<document
        # start>', but found '<block mapping start>'" at the on: row).
        why = "row is less indented than the first row"
        self._reason("  name: x\non:\n" + GOOD_PR, why)
        self._reason("  name: x\non:\n  push:\n    branches: ['rehearsal/**']\n", why)

    def test_5665_comment_after_a_space_inside_a_plain_flow_entry(self) -> None:
        # PyYAML: ParserError; ' #' starts a comment, so the collection stays open.
        self._reason("name: x\non:\n  pull_request:\n    branches: [main #c, 'rehearsal/**']\n",
                     "flow collection does not close on its row")

    def test_5665_no_on_block(self) -> None:
        # PyYAML: {'name': 'x', 'jobs': {...}}; the file has no on key at all.
        self._reason("name: x\njobs:\n  a:\n    runs-on: x\n", "no top-level on: block")

    def test_5665_empty_on_block(self) -> None:
        # PyYAML: the on key (True) holds None.
        self._reason("name: x\non:\njobs:\n  a:\n    runs-on: x\n", "empty on: block")

    def test_5665_mapping_under_a_filter_key(self) -> None:
        # PyYAML: branches is {'main': 'x'}, a mapping and not a list.
        self._reason("name: x\non:\n  pull_request:\n    branches:\n      main: x\n",
                     "pull_request.branches: non-list item")

    def test_5665_unterminated_class_in_a_branches_item(self) -> None:
        # PyYAML: branches is ['main', 'rehearsal/**', 'a[b'] in both texts.
        why = "R-SHAPE cannot match filters (pull_request.branches item 'a[b': pattern character '[' "
        for branches in (" [main, 'rehearsal/**', 'a[b']\n", "\n      - main\n      - rehearsal/**\n      - a[b\n"):
            got = violations("x.yml", "name: x\non:\n  pull_request:\n    branches:" + branches)
            self.assertTrue(any(why in v for v in got), got)


class ClosedWorldClass5854(unittest.TestCase):
    """#5854, #5968: a [...] class is refused whatever its body.

    Measured at 0e5758dc: '[!a]' returned no finding because Python reads '!' in
    a class as a literal and '^' as negation, so the checker gave a definite
    answer for spellings it had not proven it reads like GitHub.  Round 6 read a
    class only for a proven body; round 8 refuses every class (5-agent vote
    4d3ea1c5, decision 602cec39): the proven-body list is a grammar, not a finite
    set, and no live workflow uses a class.  The table below holds every probed
    spelling, the proven bodies of round 6 included.
    """

    NEIGHBOURS = (
        "[!a]", "[^a]", "[]a]", "[a\\]]", "[a-]", "[-a]", "[[]", "[!]", "[a-Z]", "[a-9]", "[z-a]", "[a-a]",
        "[[a]]", "[a-c-e]", "[a b]", "[a/b]", "[._]", "[a.b]", "[_]", "[a_b]", "[a-z-]", "[*]", "[?]",
        "rehearsal/**/[!a]", "![!a]", "a[]b", "a[b",
        "[a-z0-9]", "[ab]", "[A-Z]", "[0-9]", "[a-cx-z]", "[aZ9]", "[a-b]", "[y-z]", "a[bc]d",
        "rehearsal/[a-z]*/**", "**/[a-z]", "[a-z]-[0-9]", "![a-z]x",
    )

    def _verdict(self, item: str) -> List[str]:
        text = "name: x\non:\n  pull_request:\n    branches: [main, 'rehearsal/**', '" + item + "']\n"
        return violations("x.yml", text)

    def test_5854_every_neighbour_is_refused_with_the_class_reason(self) -> None:
        for item in self.NEIGHBOURS:
            got = self._verdict(item)
            reason = "a negation is not read" if item.startswith("!") else "a character class is not read"
            self.assertTrue(any("R-SHAPE cannot match filters" in v and reason in v and repr(item) in v
                                for v in got), (item, got))

    def test_5854_a_class_is_refused_by_the_glob_itself(self) -> None:
        for pat in ("a[b-d]e", "[a-cx-z]1", "[ab]", "[0-9]", "[A-C]", "[!a]", "a[]b", "a[b"):
            with self.assertRaises(Unparsed, msg=pat):
                glob_match(pat, "ace")

    def test_5854_the_refusal_names_the_way_out(self) -> None:
        for item in ("[a-c]", "!x"):
            got = self._verdict(item)
            self.assertTrue(any(WAY_OUT in v for v in got), (item, got))
        self.assertIn("branches-ignore is refused too: unsupported filter key", WAY_OUT)
        # The way out must be true: branches-ignore is itself refused today.
        got = violations("x.yml", "name: x\non:\n  pull_request:\n    branches-ignore: [main]\n")
        self.assertTrue(any("unsupported filter key: branches-ignore" in v for v in got), got)
        # ... and a positive list of the same bases is accepted.
        self.assertEqual([], violations(
            "x.yml", "name: x\non:\n  pull_request:\n    branches: [main, 'rehearsal/**']\n"))

    def test_5853_empty_and_reversed_classes_are_named_refusals_not_re_error(self) -> None:
        # #5853: both raised re.error out of violations() at 0e5758dc.
        for item in ("a[]b", "[z-a]"):
            self.assertTrue(any("R-SHAPE cannot match filters" in v and item in v for v in self._verdict(item)),
                            item)


class ClosedWorldPattern5943(unittest.TestCase):
    """#5943 (with #5856, #5857): a branches item is read only in the modelled constructs.

    Measured at 3d953877: '!rehearsal/audi?t-wip', '!rehearsal/audit+-wip' and
    '!rehearsal/\\audit-wip' returned no finding, and so did every other character
    outside a class ('?' was read as one non-'/' character, the rest as literals).
    The modelled constructs are letters, digits, '.', '_', '/', '-', '*' and '**'.
    Everything else is refused, a '[' class and a '!' negation included (#5968).
    """

    REFUSED = (
        "!rehearsal/audit+-wip", "!rehearsal/audi?t-wip", "!rehearsal/\\audit-wip",
        "a?b", "a+b", "a\\b", "a]b", "a!b", "?", "+", "\\", "rehearsal/?", "rehearsal/**?",
        "re?hearsal/**", "rehearsal/audit-wi+p", "!rehearsal/audit-wip\\", "!!rehearsal/audit-wip",
        "!rehearsal/audit-wip!", "rehearsal/@(audit)-wip", "!rehearsal/*(x)audit-wip", "rehearsal/audit-wip$",
        "^rehearsal/**", "rehearsal/a|b", "rehearsal/~x", "rehearsal/a b", "rehearsal/a%b", "rehearsal/a=b",
        "rehearsal/a;b", "rehearsal/a(b)", "rehearsal/***", "!rehearsal/***", "rehearsal/é",
        "rehearsal/a​b", "!rehearsal/a]b", "rehearsal/a]", "rehearsal/{audit}-wip",
        "!rehearsal/x", "a[b-d]e", "![a-z]x", "!**", "!rehearsal/**", "![a]", "x!", "!x!",
    )
    READ = (
        "rehearsal/**", "release/v1.0.0", "release/**", "rehearsal/*",
        "feature/a_b.c-d", "**", "*", "-x", ".x",
    )

    def _flow(self, item: str, trigger: str = "pull_request") -> List[str]:
        text = "name: x\non:\n  " + trigger + ":\n    branches: [main, 'rehearsal/**', '" + item + "']\n"
        return violations("x.yml", text)

    def _block(self, item: str) -> List[str]:
        text = "name: x\non:\n  pull_request:\n    branches:\n      - main\n      - 'rehearsal/**'\n      - '" \
               + item + "'\n"
        return violations("x.yml", text)

    def _assert_refused(self, item: str, got: List[str]) -> None:
        self.assertTrue(any("R-SHAPE cannot match filters" in v and "no modelled GitHub meaning" in v
                            and ".branches item " + repr(item) + ": " in v for v in got), (item, got))

    def test_5943_unmodelled_items_are_refused_in_flow_and_block_lists(self) -> None:
        for item in self.REFUSED:
            self._assert_refused(item, self._flow(item))
            self._assert_refused(item, self._block(item))
            self._assert_refused(item, self._flow(item, "pull_request_target"))

    def test_5943_refusal_names_the_trigger(self) -> None:
        got = self._flow("a?b", "pull_request_target")
        self.assertTrue(any("pull_request_target.branches" in v for v in got), got)

    def test_5943_brace_item_in_a_block_list_is_refused(self) -> None:
        # A flow list refuses the comma first (#5733); the block list reaches the glob.
        self._assert_refused("rehearsal/{audit,x}-wip", self._block("rehearsal/{audit,x}-wip"))

    def test_5943_empty_item_is_refused(self) -> None:
        got = self._flow("")
        self.assertTrue(any("R-SHAPE cannot match filters" in v and "empty pattern" in v for v in got), got)

    def test_5968_a_bare_negation_is_refused_as_a_negation(self) -> None:
        got = self._flow("!")
        self.assertTrue(any("R-SHAPE cannot match filters" in v and "a negation is not read" in v for v in got),
                        got)

    def test_5943_modelled_items_keep_a_definite_verdict(self) -> None:
        for item in self.READ:
            self.assertEqual([], self._flow(item), item)
            self.assertEqual([], self._block(item), item)

    def test_5943_modelled_constructs_match_as_stated(self) -> None:
        self.assertTrue(glob_match("a*", "abc"))
        self.assertFalse(glob_match("a*", "a/b"))
        self.assertTrue(glob_match("a**", "a/b/c"))
        self.assertTrue(glob_match("a**b", "a/x/b"))
        self.assertTrue(glob_match("x.y_z-1/2", "x.y_z-1/2"))
        self.assertFalse(glob_match("x.y", "xzy"))
        self.assertTrue(filter_matches(["a", "b"], "b"))
        self.assertFalse(filter_matches(["a", "b"], "c"))
        self.assertFalse(filter_matches([], "a"))

    def test_5943_text_after_a_star_is_still_matched(self) -> None:
        # Mutation M08 of round 7 (skip one character after '*') survived the
        # tests above: no pattern had a literal after a single '*'.
        self.assertTrue(glob_match("rehearsal/*-wip", "rehearsal/audit-wip"))
        self.assertFalse(glob_match("rehearsal/*-wip", "rehearsal/audit_wip"))
        self.assertFalse(glob_match("a*b", "axxc"))
        self.assertTrue(glob_match("a**b", "a/x/b"))
        self.assertFalse(glob_match("a**b", "a/x/c"))

    def test_5968_filter_matches_refuses_every_negation_in_any_position(self) -> None:
        # Mutations M33 and M38 of round 7 targeted the removed negation reading.
        # Retargeted: a '!' item raises from filter_matches itself, first, last,
        # alone, doubled, with '**', and after a positive item that matches.
        for items in (["!main"], ["main", "!main"], ["!main", "main"], ["!!main"], ["main", "!!main"], ["!!"],
                      ["!"], ["!a", "!b"], ["main", "!**"], ["main", "!rehearsal/**"], ["!x", "main"]):
            with self.assertRaises(Unparsed, msg=items):
                filter_matches(items, "main")

    def test_5968_filter_matches_refuses_a_class_even_after_a_match(self) -> None:
        # A refused item is red, never a no-match: the earlier matching item must
        # not hide it (any() would stop early; the loop reads every item).
        for items in (["main", "[a-z]"], ["[a-z]", "main"], ["main", "a[b"]):
            with self.assertRaises(Unparsed, msg=items):
                filter_matches(items, "main")

    def test_5943_each_reproducer_refused_where_github_excludes_the_carrier(self) -> None:
        # Under the documented reading each of these excludes the carrier; the
        # checker must refuse, never pass (a negation is refused outright, #5968).
        for item in ("!rehearsal/audit+-wip", "!rehearsal/audi?t-wip", "!rehearsal/\\audit-wip"):
            got = self._flow(item)
            self.assertNotEqual([], got, item)
            self.assertTrue(all("R-SHAPE" in v for v in got), (item, got))


class GlobDocTruth5944(unittest.TestCase):
    """#5944: the glob_match docstring states only what the function does.

    Measured at 3d953877: the docstring said "GitHub Actions filter glob: ... ? is
    one non-/ char", presenting the function's own '?' reading as GitHub's.
    """

    def _doc(self) -> str:
        return " ".join((glob_match.__doc__ or "").split())

    def test_5944_no_sentence_presents_the_reading_as_githubs(self) -> None:
        doc = self._doc()
        self.assertNotIn("GitHub Actions filter glob", doc)
        self.assertNotIn("? is one", doc)
        self.assertIn("was not compared with GitHub's own evaluator", doc)

    def test_5944_every_refused_form_in_the_docstring_is_refused(self) -> None:
        doc = self._doc()
        self.assertIn("Refused with Unparsed:", doc)
        refused = doc.split("Refused with Unparsed:", 1)[1].split("The read forms", 1)[0]
        tokens = re.findall(r"``([^`]+)``", refused)
        self.assertEqual(["[", "!", "?", "+", "]", "{", "(", "@", "^", "$", "|"], tokens)
        for phrase, ch in (("a backslash", "\\"), ("a space", " "), ("a non-ASCII letter", "é")):
            self.assertIn(phrase, refused)
            tokens.append(ch)
        for ch in tokens:
            with self.assertRaises(Unparsed, msg=ch):
                glob_match("a" + ch + "b", "ab")
        self.assertIn("an empty pattern", refused)
        with self.assertRaises(Unparsed):
            glob_match("", "")
        self.assertIn("a run of three or more '*'", refused)
        with self.assertRaises(Unparsed):
            glob_match("a***", "a")

    def test_5944_every_read_form_in_the_docstring_reads_as_stated(self) -> None:
        doc = self._doc()
        self.assertIn("``**`` regex ``.*``: any run of characters, '/' included.", doc)
        self.assertTrue(glob_match("a**", "a/b/c") and glob_match("a**", "a"))
        self.assertIn("``*`` regex ``[^/]*``: any run of characters other than '/'.", doc)
        self.assertTrue(glob_match("a*", "abc") and glob_match("a*", "a"))
        self.assertFalse(glob_match("a*", "a/b"))
        self.assertNotIn("class whose body", doc)
        self.assertNotIn("_class_regex", doc)
        self.assertIn("a letter, a digit, ``.``, ``_``, ``/`` or ``-``: itself.", doc)
        for ch in "aZ7._/-":
            self.assertTrue(glob_match("x" + ch, "x" + ch), ch)
            self.assertFalse(glob_match("x" + ch, "xq" if ch != "q" else "xr"), ch)


class DifferentialTruth5945(unittest.TestCase):
    """#5945: the stated PyYAML differential runs name their cells and their limit.

    Measured at 3d953877: the module docstring said the round-4 differential ran
    "the named_cells() below" (22 cells at that tip; round 4 ran 15) and neither it
    nor the named_cells docstring said the differential never reads a pattern.
    """

    def _doc(self) -> str:
        return " ".join((sys.modules[__name__].__doc__ or "").split())

    def test_5945_each_stated_run_names_its_cell_count(self) -> None:
        doc = self._doc()
        self.assertNotIn("plus the named_cells() below as fixed cases", doc)
        for run in ("round 4 at 528c2195 ran 15 named cells", "round 5 at 0e5758dc ran 16",
                    "round 6 at 3d953877 ran 22", "round 7 at 1452e37f ran 38", "round 8 at e325ddfb ran " + str(len(named_cells()))):
            self.assertIn(run, doc)

    def test_5945_the_parse_only_limit_is_stated(self) -> None:
        doc = self._doc()
        self.assertIn("compares parse_triggers() with yaml.SafeLoader only", doc)
        self.assertIn("never calls violations(), filter_matches() or glob_match()", doc)
        cells = " ".join((named_cells.__doc__ or "").split())
        self.assertNotIn("the round-4 PyYAML probe runs the same cells", cells)
        self.assertIn("parse_triggers()", cells)

    def test_5945_cell_rounds_add_up(self) -> None:
        names = [n for n, _t, _w in named_cells()]
        self.assertEqual(16, sum(1 for n in names if not n.startswith(("R6-", "R7-", "R8-"))))
        self.assertEqual(6, sum(1 for n in names if n.startswith("R6-")))
        self.assertEqual(16, sum(1 for n in names if n.startswith("R7-")))
        self.assertEqual(13, sum(1 for n in names if n.startswith("R8-")))
        cells = " ".join((named_cells.__doc__ or "").split())
        self.assertIn("Sixteen cells are reproducers", cells)
        self.assertIn("Six are the class items of round 6", cells)
        self.assertIn("Sixteen are the pattern items of round 7", cells)
        self.assertIn("Thirteen are the class and negation items of round 8", cells)


class DocTruth5968(unittest.TestCase):
    """#5968: the docstring rows for classes and negation say what the code does."""

    def _doc(self) -> str:
        return " ".join((sys.modules[__name__].__doc__ or "").split())

    def test_5968_pattern_row_states_the_refusals_and_the_way_out(self) -> None:
        doc = self._doc()
        self.assertIn("a ``[`` character class (whatever its body) and a ``!`` anywhere in the item, "
                      "a leading negation included", doc)
        self.assertIn("5-agent vote 4d3ea1c5", doc)
        self.assertIn("list the base branches positively as plain patterns in ``branches``", doc)
        self.assertIn("``branches-ignore`` is no way out, this reader refuses it as an unsupported filter key", doc)
        # The stated limit stays and names its open tracker entry.
        self.assertIn("they were not measured against GitHub's own evaluator (open tracker entry: #5969)", doc)

    def test_5968_no_sentence_still_says_a_class_or_negation_is_read(self) -> None:
        doc = self._doc()
        for gone in ("is read only when its body", "last match wins", "and a class as above", "one leading ``!``",
                     "proven class", "proven form"):
            self.assertNotIn(gone, doc)
        for func in (glob_match, filter_matches):
            text = " ".join((func.__doc__ or "").split())
            for gone in ("last match wins", "a leading '!' negates", "proven form", "_class_regex"):
                self.assertNotIn(gone, text)

    def test_5968_the_removed_class_reader_leaves_nothing_behind(self) -> None:
        for name in ("_class_regex", "_CLASS_LOWER", "_CLASS_UPPER", "_CLASS_DIGIT"):
            self.assertNotIn(name, globals())
        self.assertEqual(frozenset(string.ascii_letters + string.digits + "._/-"), _PATTERN_LITERALS)
        self.assertEqual({"[", "!"}, set(_REFUSED_READS))
        self.assertIn("negation", " ".join((filter_matches.__doc__ or "").split()))

    def test_5968_each_refusal_reason_names_its_own_form(self) -> None:
        with self.assertRaises(Unparsed) as cls:
            glob_match("a[b]", "ab")
        self.assertIn("a character class is not read", str(cls.exception))
        self.assertNotIn("a negation is not read", str(cls.exception))
        with self.assertRaises(Unparsed) as neg:
            glob_match("!a", "a")
        self.assertIn("a negation is not read", str(neg.exception))
        self.assertNotIn("a character class is not read", str(neg.exception))
        for exc in (cls.exception, neg.exception):
            self.assertIn(WAY_OUT, str(exc))
        with self.assertRaises(Unparsed) as other:
            glob_match("a?b", "ab")
        self.assertNotIn(WAY_OUT, str(other.exception))


class GlobSemantics5447(unittest.TestCase):
    def test_5447_glob_rules(self) -> None:
        self.assertTrue(glob_match("rehearsal/**", CARRIER))
        self.assertTrue(glob_match("release/**", "release/v1.0.0"))
        self.assertFalse(glob_match("release/**", CARRIER))
        self.assertFalse(glob_match("rehearsal/*", "rehearsal/a/b"))
        self.assertTrue(glob_match("rehearsal/*", CARRIER))
        self.assertTrue(filter_matches(["rehearsal/**", "release/**"], CARRIER))
        self.assertFalse(filter_matches(["release/**"], CARRIER))
        with self.assertRaises(Unparsed):
            filter_matches(["rehearsal/**", "!rehearsal/audit-wip"], CARRIER)


# ---------------------------------------------------------------------------
# #6117 round 2: the carrier push must judge what the promotion PR judges.
# These cells run the workflow STEP TEXT itself (extracted from c8-precheck.yml)
# against throwaway Git histories under .local-runs/, so a pass here is a
# behavioural fact about the step, not a grep of its words.
# ---------------------------------------------------------------------------

C8_WORKFLOW = WORKFLOWS / "c8-precheck.yml"
GEOMETRY_PY = ROOT / "scripts" / "check_promotion_geometry.py"
GEOMETRY_SH = ROOT / "scripts" / "check-promotion-geometry.sh"
APPROVAL_PY = ROOT / "scripts" / "check_external_pr_approval.py"
GEOMETRY_STEP = "Promotion ancestry soundness (#3872"
CARRIER_RANGE_STEP = "Resolve the range start for a carrier push (#6117)"
APPROVAL_JOB = "external-pr-operator-approval-gate"
REQUIRED_CONTEXTS_JOB = "required-contexts-gate"
RELEASE_6117 = "release/v1.0.0"
REPO_6117 = "alphaonedev/ai-memory-mcp"
OPERATOR_6117 = "alphaonedev"


def _job_text(text: str, job_id: str) -> str:
    """The lines of one top-level job (``  <job_id>:`` up to the next job key)."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line == f"  {job_id}:":
            start = i
            break
    if start is None:
        raise AssertionError(f"job {job_id} not found")
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[j]) or re.match(r"^[A-Za-z]", lines[j]):
            end = j
            break
    return "\n".join(lines[start:end]) + "\n"


def _step_runs(text: str, step_prefix: str) -> List[str]:
    """The ``run:`` body of every step whose name starts with ``step_prefix`` (dedented)."""
    lines = text.splitlines()
    bodies: List[str] = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)- name: \"?(.*?)\"?\s*$", line)
        if not m or not m.group(2).startswith(step_prefix):
            continue
        item_indent = len(m.group(1))
        for j in range(i + 1, len(lines)):
            row = lines[j]
            if row.strip() and len(row) - len(row.lstrip(" ")) <= item_indent:
                raise AssertionError(f"step {step_prefix!r} has no run: key")
            rm = re.match(r"^(\s*)run:\s*(.*)$", row)
            if not rm:
                continue
            key_indent = len(rm.group(1))
            if rm.group(2) not in ("|", "|-"):
                bodies.append(rm.group(2) + "\n")
                break
            body: List[str] = []
            for k in range(j + 1, len(lines)):
                b = lines[k]
                if b.strip() and len(b) - len(b.lstrip(" ")) <= key_indent:
                    break
                body.append(b[key_indent + 2:] if b.strip() else "")
            bodies.append("\n".join(body).rstrip("\n") + "\n")
            break
    return bodies


def _clean_git_env() -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _g(repo: Path, *args: str) -> str:
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                         env=_clean_git_env(), timeout=60, check=False)
    if out.returncode:
        raise AssertionError(f"git {' '.join(args)}: {out.stderr}")
    return out.stdout.strip()


class _History6117:
    """origin.git + a work clone on chain/promo6-ssh; ``shape`` picks the release geometry.

    ahead     release/v1.0.0 = root, carrier = root + one commit (behind=0)
    behind    release/v1.0.0 = root + a release-only commit the carrier lacks
    unrelated release/v1.0.0 is an orphan history (no merge-base)
    absent    origin has no release/v1.0.0 at all
    The work clone holds NO refs/remotes/origin/release/* until a step fetches it.
    """

    def __init__(self, td: Path, shape: str, scripts: Optional[Dict[str, str]] = None) -> None:
        self.origin = td / "origin.git"
        self.work = td / "work"
        _g(td, "init", "--quiet", "--bare", str(self.origin))
        _g(td, "init", "--quiet", "--initial-branch=chain/promo6-ssh", str(self.work))
        w = self.work
        _g(w, "config", "user.name", "fixture")
        _g(w, "config", "user.email", "fixture@example.invalid")
        _g(w, "config", "commit.gpgsign", "false")
        _g(w, "remote", "add", "origin", str(self.origin))
        self.root = self._commit("root.txt")
        if shape == "unrelated":
            _g(w, "checkout", "--quiet", "--orphan", "rel")
            _g(w, "rm", "--quiet", "-rf", "--cached", ".")
            self._commit("orphan.txt")
            _g(w, "push", "--quiet", "origin", "rel:refs/heads/" + RELEASE_6117)
            _g(w, "checkout", "--quiet", "-f", "chain/promo6-ssh")
            _g(w, "branch", "--quiet", "-D", "rel")
        elif shape == "behind":
            _g(w, "checkout", "--quiet", "-b", "rel")
            self._commit("release-only.txt")
            _g(w, "push", "--quiet", "origin", "rel:refs/heads/" + RELEASE_6117)
            _g(w, "checkout", "--quiet", "chain/promo6-ssh")
            _g(w, "branch", "--quiet", "-D", "rel")
        elif shape == "ahead":
            _g(w, "push", "--quiet", "origin", "HEAD:refs/heads/" + RELEASE_6117)
        elif shape != "absent":
            raise AssertionError(shape)
        self.head = self._commit("carrier.txt")
        _g(w, "push", "--quiet", "origin", "chain/promo6-ssh")
        for ref in _g(w, "for-each-ref", "--format=%(refname)", "refs/remotes/origin/release").splitlines():
            _g(w, "update-ref", "-d", ref)
        (w / "scripts").mkdir()
        sources = scripts or {}
        for path in (GEOMETRY_PY, GEOMETRY_SH):
            text = sources.get(path.name, path.read_text(encoding="utf-8"))
            (w / "scripts" / path.name).write_text(text, encoding="utf-8")
        self.output = td / "github_output"
        self.output.write_text("")
        self.event = td / "event.json"

    def _commit(self, name: str) -> str:
        (self.work / name).write_text(name + "\n")
        _g(self.work, "add", "--", name)
        _g(self.work, "commit", "--quiet", "--no-gpg-sign", "-m", name)
        return _g(self.work, "rev-parse", "HEAD")

    def run(self, body: str, ref: str = "refs/heads/chain/promo6-ssh", event: str = "push",
            payload: Optional[dict] = None) -> Tuple[int, str]:
        if payload is None:
            payload = {"ref": ref, "before": self.root, "after": self.head}
        self.event.write_text(json.dumps(payload))
        env = _clean_git_env()
        env.update({"GITHUB_OUTPUT": str(self.output), "GITHUB_EVENT_PATH": str(self.event),
                    "GITHUB_EVENT_NAME": event, "EVENT_NAME": event, "GITHUB_REF": ref, "REF": ref,
                    "GITHUB_SHA": self.head, "CARRIER_RELEASE_REF": RELEASE_6117})
        out = subprocess.run(["bash", "-c", body], cwd=str(self.work), capture_output=True,
                             text=True, env=env, timeout=120, check=False)
        return out.returncode, out.stdout + out.stderr


class _Scratch6117(unittest.TestCase):
    def setUp(self) -> None:
        scratch = ROOT / ".local-runs"
        scratch.mkdir(exist_ok=True)
        self._td = tempfile.TemporaryDirectory(prefix="r2-6117-", dir=str(scratch))
        self.td = Path(self._td.name)
        self.c8 = C8_WORKFLOW.read_text(encoding="utf-8")

    def tearDown(self) -> None:
        self._td.cleanup()

    def history(self, shape: str, scripts: Optional[Dict[str, str]] = None) -> _History6117:
        sub = Path(tempfile.mkdtemp(dir=str(self.td)))
        return _History6117(sub, shape, scripts)

    def geometry_body(self) -> str:
        bodies = _step_runs(_job_text(self.c8, REQUIRED_CONTEXTS_JOB), GEOMETRY_STEP)
        self.assertEqual(1, len(bodies), "exactly one #3872 geometry step in the required-context job")
        return bodies[0]


class CarrierPushGeometry6117(_Scratch6117):
    """C-F1: on a carrier push the REQUIRED geometry context measures the carrier, never INAPPLICABLE."""

    def test_6117_r2_cf1_carrier_push_behind_release_fails(self) -> None:
        h = self.history("behind")
        rc, out = h.run(self.geometry_body())
        self.assertEqual(1, rc, out)
        self.assertIn("behind=1", out)

    def test_6117_r2_cf1_carrier_push_ahead_of_release_measures_and_passes(self) -> None:
        h = self.history("ahead")
        rc, out = h.run(self.geometry_body())
        self.assertEqual(0, rc, out)
        self.assertIn("ahead=1 behind=0", out)
        self.assertNotIn("INAPPLICABLE", out)

    def test_6117_r2_cf1_carrier_push_without_release_ref_fails_closed(self) -> None:
        h = self.history("absent")
        rc, out = h.run(self.geometry_body())
        self.assertNotEqual(0, rc, out)

    def test_6117_r2_cf1_carrier_push_with_malformed_after_sha_fails_closed(self) -> None:
        h = self.history("ahead")
        rc, out = h.run(self.geometry_body(),
                        payload={"ref": "refs/heads/chain/promo6-ssh", "after": "HEAD"})
        self.assertNotEqual(0, rc, out)

    def test_6117_r2_cf1_carrier_push_judges_the_pushed_sha_not_the_checkout(self) -> None:
        # The event's `after` is the judged commit: a BEHIND sha stays BEHIND even when
        # the checkout HEAD has been moved onto a commit that contains the release.
        h = self.history("behind")
        behind_sha = h.head
        _g(h.work, "fetch", "--quiet", "origin", "+refs/heads/release/v1.0.0:refs/heads/rel")
        _g(h.work, "merge", "--quiet", "--no-edit", "--no-gpg-sign", "rel")
        rc, out = h.run(self.geometry_body(),
                        payload={"ref": "refs/heads/chain/promo6-ssh", "after": behind_sha})
        self.assertEqual(1, rc, out)
        self.assertIn("behind=1", out)

    def test_6117_r2_cf1_unfetchable_release_fails_even_with_a_stale_local_ref(self) -> None:
        # The step fetches the release ref itself: a stale remote-tracking ref left on the
        # runner must not stand in for an origin it cannot reach. Fetch failure = job failure.
        h = self.history("ahead")
        _g(h.work, "fetch", "--quiet", "origin",
           "+refs/heads/release/v1.0.0:refs/remotes/origin/release/v1.0.0")
        _g(h.work, "remote", "set-url", "origin", str(h.work / "no-such-origin.git"))
        rc, out = h.run(self.geometry_body())
        self.assertNotEqual(0, rc, out)
        self.assertIn("::error::", out)

    def test_6117_r2_cf1_control_non_carrier_push_stays_inapplicable(self) -> None:
        h = self.history("behind")
        rc, out = h.run(self.geometry_body(), ref="refs/heads/main",
                        payload={"ref": "refs/heads/main", "after": "0" * 40})
        self.assertEqual(0, rc, out)
        self.assertIn("INAPPLICABLE", out)

    def test_6117_r2_cf1_m01_script_without_the_carrier_arm_is_killed(self) -> None:
        # Mutant: the geometry script answers every push INAPPLICABLE again (the d1dd551
        # behaviour). The behind cell must turn red against it.
        src = GEOMETRY_PY.read_text(encoding="utf-8")
        anchor = 'CARRIER_PREFIX = "refs/heads/chain/"\n'
        self.assertIn(anchor, src, "mutation anchor (the carrier ref prefix)")
        mutant = src.replace(anchor, 'CARRIER_PREFIX = "refs/heads/never-a-carrier/"\n', 1)
        h = self.history("behind", scripts={GEOMETRY_PY.name: mutant})
        rc, out = h.run(self.geometry_body())
        self.assertEqual(0, rc, "mutant should be INAPPLICABLE (exit 0); the live cell above expects 1")
        self.assertIn("INAPPLICABLE", out)


class CarrierRangeStep6117(_Scratch6117):
    """S-F3 / S-F4: the four carrier range-start steps fail loudly and read the release ref from one source."""

    def bodies(self) -> List[str]:
        bodies = _step_runs(self.c8, CARRIER_RANGE_STEP)
        self.assertEqual(4, len(bodies), "four carrier range-start steps (#6187 tracks the dedup)")
        return bodies

    def test_6117_r2_sf3_unrelated_history_fails_with_an_error_annotation(self) -> None:
        for body in self.bodies():
            h = self.history("unrelated")
            rc, out = h.run(body)
            self.assertNotEqual(0, rc, out)
            self.assertIn("::error::", out, "a refused carrier range must say why (S-F3)")

    def test_6117_r2_sf3_control_related_history_resolves_the_merge_base(self) -> None:
        for body in self.bodies():
            h = self.history("ahead")
            rc, out = h.run(body)
            self.assertEqual(0, rc, out)
            self.assertIn(f"before={h.root}", h.output.read_text())

    def test_6117_r2_sf3_control_non_carrier_push_yields_an_empty_range_start(self) -> None:
        for body in self.bodies():
            h = self.history("unrelated")
            rc, out = h.run(body, ref="refs/heads/main")
            self.assertEqual(0, rc, out)
            self.assertEqual("before=\n", h.output.read_text())

    def test_6117_r2_sf4_release_ref_has_one_source(self) -> None:
        # S-F4: no workflow pins the carrier release ref by hand; every carrier step and
        # the geometry step derive it from check_promotion_geometry.RELEASE.
        for name, text in load_all().items():
            # An env key (`CARRIER_RELEASE_REF: <value>` at line start), not the
            # `$CARRIER_RELEASE_REF:refs/...` refspec inside a fetch line.
            self.assertNotRegex(text, r"(?m)^\s*CARRIER_RELEASE_REF:\s*\S", name)
        derive = "python3 -I scripts/check_promotion_geometry.py --print-release"
        for body in self.bodies() + [self.geometry_body()]:
            self.assertIn(derive, body)
        out = subprocess.run([sys.executable, str(GEOMETRY_PY), "--print-release"],
                             capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(0, out.returncode, out.stderr)
        src = GEOMETRY_PY.read_text(encoding="utf-8")
        pinned = re.search(r'^RELEASE = "([^"]+)"$', src, re.M)
        self.assertIsNotNone(pinned)
        self.assertEqual(pinned.group(1) + "\n", out.stdout)

    def test_6117_r2_sf4_hardcoded_release_in_a_range_step_is_killed(self) -> None:
        # Mutant: one carrier step goes back to a hand-pinned env value.
        derive = 'CARRIER_RELEASE_REF="$(python3 -I scripts/check_promotion_geometry.py --print-release)"'
        self.assertIn(derive, self.c8)
        mutant = self.c8.replace(derive, "CARRIER_RELEASE_REF=release/v1.0.0", 1)
        bodies = _step_runs(mutant, CARRIER_RANGE_STEP) + [
            _step_runs(_job_text(mutant, REQUIRED_CONTEXTS_JOB), GEOMETRY_STEP)[0]]
        self.assertTrue(any("--print-release" not in b for b in bodies))


# ---- S-F1: the External-PR operator-approval gate on non-PR events (#6193) ----

def _load_approval():
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_external_pr_approval_6117", str(APPROVAL_PY))
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load " + str(APPROVAL_PY))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


def _pr(number: int, sha: str, assoc: str = "NONE", head_repo: Optional[str] = "fork/ai-memory-mcp") -> dict:
    head: dict = {"sha": sha, "repo": None if head_repo is None else {"full_name": head_repo}}
    return {"number": number, "author_association": assoc, "user": {"login": "someone"}, "head": head}


def _review(sha: str, login: str = OPERATOR_6117, state: str = "APPROVED",
            submitted_at: object = "2026-10-01T00:00:00Z", review_id: object = 1) -> dict:
    # #6329: the gate orders the operator's deciding reviews by (submitted_at, id).
    return {"id": review_id, "user": {"login": login}, "state": state, "commit_id": sha,
            "submitted_at": submitted_at}


# #6325: the real merge_group payload.  GITHUB_SHA and merge_group.head_sha are the queue
# commit (SHA_C); the <sha> in head_ref is merge_group.base_sha, the queue commit's PARENT
# (SHA_E), never head_sha (10 of 10 recorded runs, QueueRefBaseSha6325.REAL_RUNS).
SHA_E = "e" * 40


def _merge_group_event(number: int, base: str = "main", sha: str = SHA_E, base_sha: Optional[str] = SHA_E,
                       head_sha: str = SHA_C) -> dict:
    ref = f"refs/heads/gh-readonly-queue/{base}/pr-{number}-{sha}"
    group = {"head_sha": head_sha, "head_ref": ref, "base_ref": f"refs/heads/{base}"}
    if base_sha is not None:
        group["base_sha"] = base_sha
    return {"action": "checks_requested", "merge_group": group}


def _fake_api(pulls: List[dict], reviews: Optional[Dict[int, List[dict]]] = None, fail: bool = False):
    calls: List[str] = []

    def api(path: str):
        calls.append(path)
        if fail:
            raise _APPROVAL.GateError("HTTP 502 from the API")
        m = re.search(r"/pulls/(\d+)/reviews", path)
        if m:
            return (reviews or {}).get(int(m.group(1)), [])
        if re.search(r"/pulls\?", path) and "state=open" in path:
            return pulls
        raise AssertionError("unexpected API path " + path)

    api.calls = calls  # type: ignore[attr-defined]
    return api


_APPROVAL = None  # loaded per test class


def _approval_cases(mod) -> List[str]:
    """Names of the decision cells ``mod.run_gate`` gets WRONG (empty list = all right)."""
    wrong: List[str] = []

    def cell(name: str, want: int, event: str, sha: str, api, payload: Optional[dict] = None) -> None:
        try:
            rc, _lines = mod.run_gate(event, payload or {}, REPO_6117, sha, OPERATOR_6117, api)
        except Exception as exc:  # a crash is a wrong answer, never a pass
            wrong.append(f"{name} (raised {exc!r})")
            return
        if rc != want:
            wrong.append(f"{name} (rc={rc}, want {want})")

    ext = _pr(7, SHA_A)
    cell("push-unapproved-external-PR-head-fails", 1, "push", SHA_A, _fake_api([ext]))
    cell("push-approved-external-PR-head-passes", 0, "push", SHA_A,
         _fake_api([ext], {7: [_review(SHA_A)]}))
    cell("push-approval-on-another-commit-fails", 1, "push", SHA_A,
         _fake_api([ext], {7: [_review(SHA_B)]}))
    cell("push-approval-by-another-login-fails", 1, "push", SHA_A,
         _fake_api([ext], {7: [_review(SHA_A, login="mallory")]}))
    cell("push-commented-not-approved-fails", 1, "push", SHA_A,
         _fake_api([ext], {7: [_review(SHA_A, state="COMMENTED")]}))
    cell("push-team-same-repo-PR-passes", 0, "push", SHA_A,
         _fake_api([_pr(8, SHA_A, "MEMBER", REPO_6117)]))
    cell("push-team-author-fork-head-needs-approval", 1, "push", SHA_A,
         _fake_api([_pr(9, SHA_A, "COLLABORATOR", "fork/ai-memory-mcp")]))
    cell("push-deleted-head-repo-is-external", 1, "push", SHA_A,
         _fake_api([_pr(10, SHA_A, "OWNER", None)]))
    cell("push-no-PR-heads-the-sha-passes", 0, "push", SHA_A, _fake_api([_pr(7, SHA_B)]))
    cell("push-one-of-two-PRs-unapproved-fails", 1, "push", SHA_A,
         _fake_api([_pr(7, SHA_A), _pr(11, SHA_A)], {7: [_review(SHA_A)]}))
    # #6227: a merge_group run's GITHUB_SHA is the queue commit, never a PR head.  The PR
    # under test is named by merge_group.head_ref (gh-readonly-queue/<base>/pr-<N>-<sha>).
    cell("merge-group-queue-sha-external-unapproved-fails", 1, "merge_group", SHA_C,
         _fake_api([ext]), _merge_group_event(7))
    cell("merge-group-queue-sha-external-approved-passes", 0, "merge_group", SHA_C,
         _fake_api([ext], {7: [_review(SHA_A)]}), _merge_group_event(7))
    cell("merge-group-approval-on-another-commit-fails", 1, "merge_group", SHA_C,
         _fake_api([ext], {7: [_review(SHA_B)]}), _merge_group_event(7))
    cell("merge-group-team-same-repo-passes", 0, "merge_group", SHA_C,
         _fake_api([_pr(8, SHA_A, "MEMBER", REPO_6117)]), _merge_group_event(8))
    cell("merge-group-nested-base-branch-parses", 1, "merge_group", SHA_C,
         _fake_api([ext]), _merge_group_event(7, base="release/v1.0.0"))
    cell("merge-group-named-pr-not-open-fails-closed", 1, "merge_group", SHA_C,
         _fake_api([_pr(9, SHA_B)]), _merge_group_event(7))
    cell("merge-group-missing-payload-fails-closed", 1, "merge_group", SHA_C, _fake_api([ext]), {})
    cell("merge-group-unparsable-head-ref-fails-closed", 1, "merge_group", SHA_C,
         _fake_api([_pr(8, SHA_A, "MEMBER", REPO_6117)]),
         {"merge_group": {"head_ref": "refs/heads/gh-readonly-queue/main/not-a-pr"}})
    cell("merge-group-zero-pr-number-fails-closed", 1, "merge_group", SHA_C,
         _fake_api([_pr(8, SHA_A, "MEMBER", REPO_6117)]), _merge_group_event(0))
    cell("merge-group-non-string-head-ref-fails-closed", 1, "merge_group", SHA_C,
         _fake_api([ext]), {"merge_group": {"head_ref": 7}})
    cell("api-error-fails-closed", 1, "push", SHA_A, _fake_api([ext], fail=True))
    cell("malformed-pull-entry-fails-closed", 1, "push", SHA_A, _fake_api([{"number": 7}]))
    cell("non-sha-commit-fails-closed", 1, "push", "HEAD", _fake_api([]))
    pr_event = {"pull_request": ext}
    cell("pull-request-external-unapproved-fails", 1, "pull_request", "", _fake_api([]), pr_event)
    cell("pull-request-external-approved-passes", 0, "pull_request", "",
         _fake_api([], {7: [_review(SHA_A)]}), pr_event)
    cell("pull-request-team-same-repo-passes", 0, "pull_request", "", _fake_api([]),
         {"pull_request": _pr(8, SHA_A, "MEMBER", REPO_6117)})
    cell("pull-request-missing-payload-fails-closed", 1, "pull_request", "", _fake_api([]), {})
    return wrong


class ExternalPrApprovalOnPush6117(unittest.TestCase):
    """S-F1 / #6193: a push run evaluates the same approval condition for every open PR headed by its sha."""

    def setUp(self) -> None:
        global _APPROVAL
        if not APPROVAL_PY.is_file():
            self.fail(f"{APPROVAL_PY.relative_to(ROOT)} is missing: the approval gate has no evaluator (#6193)")
        _APPROVAL = _load_approval()
        self.mod = _APPROVAL

    def test_6117_r2_sf1_decision_table(self) -> None:
        self.assertEqual([], _approval_cases(self.mod))

    def test_6117_r2_sf1_m01_unconditional_non_pr_pass_is_killed(self) -> None:
        # Mutant: the d1dd551 behaviour, every non-pull_request event passes.
        src = APPROVAL_PY.read_text(encoding="utf-8")
        anchor = "def run_gate(event_name, event, repo, sha, operator, api):\n"
        self.assertIn(anchor, src)
        mutant_src = src.replace(
            anchor, anchor + '    if event_name != "pull_request":\n        return 0, ["mutant"]\n', 1)
        ns: dict = {"__name__": "approval_mutant_6117"}
        exec(compile(mutant_src, "approval_mutant_6117", "exec"), ns)

        class _M:  # attribute view over the mutant namespace
            pass

        m = _M()
        for k, v in ns.items():
            setattr(m, k, v)
        wrong = _approval_cases(m)
        self.assertIn("push-unapproved-external-PR-head-fails (rc=0, want 1)", wrong)

    def test_6117_r2_sf1_paginated_output_is_concatenated_arrays(self) -> None:
        self.assertEqual([{"a": 1}, {"b": 2}], self.mod.parse_pages('[{"a": 1}]\n[{"b": 2}]\n'))
        self.assertEqual([], self.mod.parse_pages("[]"))
        for bad in ("", "not json", '{"message": "Bad credentials"}', "[1] trailing"):
            with self.assertRaises(self.mod.GateError, msg=bad):
                self.mod.parse_pages(bad)

    def test_6117_r2_sf1_workflow_runs_the_evaluator_on_every_event(self) -> None:
        job = _job_text(C8_WORKFLOW.read_text(encoding="utf-8"), APPROVAL_JOB)
        runs = "\n".join(_step_runs(job, "Evaluate external-PR approval requirement"))
        self.assertIn("python3 -I scripts/check_external_pr_approval.py", runs)
        self.assertNotIn("gate not applicable (pass)", job)
        self.assertNotRegex(job, r'"\$EVENT" != "pull_request"')
        # rule (f): the job always runs and always reports.
        self.assertNotRegex(job, r"(?m)^    (needs|if):")
        # The evaluator is read from a checkout that does not keep the token on disk.
        self.assertIn("persist-credentials: false", job)
        self.assertIn("pull-requests: read", job)

    APPROVAL_STEPS = ("Self-test the external-PR approval evaluator (#6193)",
                      "Evaluate external-PR approval requirement")
    STEP_NEUTRALISER = r"""(?m)^\s+(?:- )?["']?(?:if|continue-on-error)["']?\s*:|^\s+timeout-minutes\s*:\s*0\s*$"""

    def test_6117_r3_f2_approval_steps_cannot_be_neutralised(self) -> None:
        # Cloud F2: a step-level `if:` or `continue-on-error` turns the required context green.
        job = _job_text(C8_WORKFLOW.read_text(encoding="utf-8"), APPROVAL_JOB)
        for name in self.APPROVAL_STEPS:
            with self.subTest(step=name):
                block = _step_block(job, name)
                self.assertTrue(block, f"step {name!r} is missing")
                self.assertNotRegex(block, self.STEP_NEUTRALISER)

    def test_6117_r3_f2_mutants_are_killed(self) -> None:
        job = _job_text(C8_WORKFLOW.read_text(encoding="utf-8"), APPROVAL_JOB)
        for label, extra in (("approval-step-continue-on-error", "        continue-on-error: true\n"),
                             ("approval-step-if-pull_request-only",
                              "        if: github.event_name == 'pull_request'\n"),
                             ("approval-step-timeout-zero", "        timeout-minutes: 0\n")):
            for name in self.APPROVAL_STEPS:
                with self.subTest(mutant=label, step=name):
                    block = _step_block(job, name)
                    head, _, rest = block.partition("\n")
                    self.assertRegex(head + "\n" + extra + rest, self.STEP_NEUTRALISER)

    def test_6117_r2_sf1_self_test_passes(self) -> None:
        out = subprocess.run([sys.executable, str(APPROVAL_PY), "--self-test"],
                             capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(0, out.returncode, out.stdout + out.stderr)
        job = _job_text(C8_WORKFLOW.read_text(encoding="utf-8"), APPROVAL_JOB)
        self.assertIn("python3 -I scripts/check_external_pr_approval.py --self-test", job)


class ExternalPrApprovalEntrypoint6226(_Scratch6117):
    """#6226: the two fail-closed paths of the evaluator that the injected-api cells never reach.

    ``gh_api`` builds the real ``gh`` argv and ``main`` reads the event payload; both are
    exercised here through the script's own entry point with a fake ``gh`` on PATH.
    """

    FAKE_GH = (
        "#!{python}\n"
        "import json, os, sys\n"
        "with open(os.environ['FAKE_GH_LOG'], 'a', encoding='utf-8') as fh:\n"
        "    fh.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "def pr(n, sha, assoc, repo):\n"
        "    return {{'number': n, 'author_association': assoc, 'user': {{'login': 'x'}},\n"
        "            'head': {{'sha': sha, 'repo': {{'full_name': repo}}}}}}\n"
        "mode = os.environ.get('FAKE_GH_MODE', '')\n"
        "if mode == 'rate-limit-403':\n"
        "    sys.stderr.write('gh: API rate limit exceeded (HTTP 403) ghp_' + 'A1' * 18 + '\\nsecond line\\n')\n"
        "    sys.exit(1)\n"
        "def pr_meta(n, sha):\n"
        "    return {{'number': n, 'author_association': 'NONE\\n::set-output x', 'user': {{'login': 'x\\n::error::forged'}},\n"
        "            'head': {{'sha': sha, 'repo': {{'full_name': 'f/r\\n::error::forged2'}}}}}}\n"
        "if mode == 'metachar-names':\n"
        "    print(json.dumps([pr_meta(3, '{a}')]))\n"
        "    sys.exit(0)\n"
        "page1 = [pr(1, '{b}', 'MEMBER', '{repo}')]\n"
        "page2 = [pr(2, '{a}', 'NONE', 'fork/ai-memory-mcp')]\n"
        "if '/reviews' in sys.argv[-1]:\n"
        "    print('[]')\n"
        "elif '--paginate' in sys.argv:\n"
        "    print(json.dumps(page1)); print(json.dumps(page2))\n"
        "else:\n"
        "    print(json.dumps(page1))\n")

    def setUp(self) -> None:
        super().setUp()
        self.bin = self.td / "bin"
        self.bin.mkdir()
        self.log = self.td / "gh.log"
        gh = self.bin / "gh"
        gh.write_text(self.FAKE_GH.format(python=sys.executable, a=SHA_A, b=SHA_B, repo=REPO_6117),
                      encoding="utf-8")
        gh.chmod(0o755)

    def run_script(self, event: str, payload_path: str = "", sha: str = SHA_A, mode: str = ""):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "OPERATOR_"))}
        env.update({"PATH": str(self.bin) + os.pathsep + env.get("PATH", ""),
                    "FAKE_GH_LOG": str(self.log), "GITHUB_EVENT_NAME": event,
                    "GITHUB_EVENT_PATH": payload_path, "GITHUB_REPOSITORY": REPO_6117,
                    "GITHUB_SHA": sha, "OPERATOR_LOGIN": OPERATOR_6117, "FAKE_GH_MODE": mode})
        out = subprocess.run([sys.executable, "-I", str(APPROVAL_PY)], capture_output=True,
                             text=True, env=env, timeout=60, check=False)
        return out.returncode, out.stdout + out.stderr

    def test_6226_push_lists_open_prs_with_paginate_and_judges_page_two(self) -> None:
        rc, out = self.run_script("push")
        calls = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(calls, "the evaluator never called gh")
        for argv in calls:
            self.assertIn("--paginate", argv, "every gh api call must paginate (#6226)")
        # The external PR sits on page 2: without --paginate the gate would pass vacuously.
        self.assertEqual(1, rc, out)
        self.assertIn("PR #2", out)

    def test_6226_pull_request_payload_unreadable_fails_closed(self) -> None:
        for name, path in (("missing", str(self.td / "no-such-event.json")), ("unset", "")):
            with self.subTest(payload=name):
                rc, out = self.run_script("pull_request", path)
                self.assertEqual(1, rc, out)
                self.assertIn("::error::cannot read the pull_request event payload", out)
        bad = self.td / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with self.subTest(payload="malformed"):
            rc, out = self.run_script("pull_request", str(bad))
            self.assertEqual(1, rc, out)
            self.assertIn("::error::cannot read the pull_request event payload", out)

    def test_6117_r3_f4_rate_limit_stderr_is_not_relayed_with_a_token(self) -> None:
        rc, out = self.run_script("push", mode="rate-limit-403")
        self.assertEqual(1, rc, out)
        self.assertNotIn("ghp_", out)
        self.assertIn("rate limit exceeded", out)
        self.assertNotIn("second line", out)

    def test_6117_r3_f4_metachar_names_cannot_forge_annotations(self) -> None:
        rc, out = self.run_script("push", mode="metachar-names")
        self.assertEqual(1, rc, out)
        for line in out.splitlines():
            self.assertFalse(line.startswith(("::error::forged", "::set-output")), line)
        self.assertNotIn("forged", out.replace("::error::External-PR", ""))

    def test_6227_merge_group_payload_unreadable_fails_closed(self) -> None:
        rc, out = self.run_script("merge_group", str(self.td / "no-such-event.json"), sha=SHA_C)
        self.assertEqual(1, rc, out)
        self.assertIn("::error::cannot read the merge_group event payload", out)

    def test_6227_merge_group_judges_the_pr_named_by_the_queue_ref(self) -> None:
        event = self.td / "merge_group.json"
        event.write_text(json.dumps(_merge_group_event(2)), encoding="utf-8")
        rc, out = self.run_script("merge_group", str(event), sha=SHA_C)
        self.assertEqual(1, rc, out)  # PR #2 is the external PR of the fake gh
        self.assertIn("PR #2", out)

    def test_6226_m01_dropping_paginate_is_killed(self) -> None:
        src = APPROVAL_PY.read_text(encoding="utf-8")
        needle = '["gh", "api", "--paginate", path]'
        self.assertIn(needle, src)
        mutant = self.td / "check_external_pr_approval_nopaginate.py"
        mutant.write_text(src.replace(needle, '["gh", "api", path]', 1), encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "OPERATOR_"))}
        env.update({"PATH": str(self.bin) + os.pathsep + env.get("PATH", ""),
                    "FAKE_GH_LOG": str(self.log), "GITHUB_EVENT_NAME": "push",
                    "GITHUB_REPOSITORY": REPO_6117, "GITHUB_SHA": SHA_A,
                    "OPERATOR_LOGIN": OPERATOR_6117})
        out = subprocess.run([sys.executable, "-I", str(mutant)], capture_output=True, text=True,
                             env=env, timeout=60, check=False)
        self.assertEqual(0, out.returncode, "the mutant must pass vacuously, proving the cell is load-bearing")


CARRIER_CONSUMERS = (
    ("Run declaration hash gate", "DECLARATION_GATE_BASE",
     "${{ github.event.pull_request.base.sha || steps.carrier.outputs.before || github.event.before }}"),
    ("Run enterprise-federation cert-expiry gate", "GITHUB_EVENT_BEFORE",
     "${{ steps.carrier.outputs.before || github.event.before }}"),
    ("Run stale contract-assertion gate over the change range", "GITHUB_EVENT_BEFORE",
     "${{ steps.carrier.outputs.before || github.event.before }}"),
    ("Run count-assertion declaration gate over the change range", "GITHUB_EVENT_BEFORE",
     "${{ steps.carrier.outputs.before || github.event.before }}"),
)
CARRIER_ARM_IF = 'if [ "$EVENT_NAME" = "push" ] && [ "${GITHUB_REF#refs/heads/chain/}" != "$GITHUB_REF" ]; then'
CARRIER_ARM_IF_COVERAGE = ('if [ "${{ github.event_name }}" = "push" ] && '
                           '[ "${GITHUB_REF#refs/heads/chain/}" != "$GITHUB_REF" ]; then')


def _step_block(text: str, name: str) -> str:
    """Raw lines of the step ``- name: <name>`` up to the next step or dedent."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)- name: \"?(.*?)\"?\s*$", line)
        if m and m.group(2) == name:
            indent = len(m.group(1))
            end = len(lines)
            for j in range(i + 1, len(lines)):
                row = lines[j]
                if row.strip() and len(row) - len(row.lstrip(" ")) <= indent:
                    end = j
                    break
            return "\n".join(lines[i:end]) + "\n"
    return ""


def _carrier_arm(text: str, job: str, if_line: str) -> str:
    """The body of the carrier-push arm inside the classify job (``""`` when absent)."""
    body = _job_text(text, job)
    start = body.find(if_line)
    if start < 0:
        return ""
    end = body.find("\n          fi\n", start)
    return body[start:end] if end > 0 else ""


def _carrier_consumption_problems(ci: str, cov: str, c8: str) -> List[str]:
    """What the carrier range is NOT doing (empty list = every consumer and arm is intact)."""
    problems: List[str] = []
    for step, key, rhs in CARRIER_CONSUMERS:
        block = _step_block(c8, step)
        if not block:
            problems.append(f"c8-precheck step {step!r} is missing")
        elif f"{key}: {rhs}\n" not in block:
            problems.append(f"c8-precheck step {step!r} no longer reads {key}: {rhs}")
    bound = c8.count(f"      - name: {CARRIER_RANGE_STEP}\n        id: carrier\n")
    if bound != c8.count(f"- name: {CARRIER_RANGE_STEP}"):
        problems.append("a carrier range step lost its `id: carrier` binding (steps.carrier.outputs would be empty)")
    arm = _carrier_arm(ci, "classify", CARRIER_ARM_IF)
    for want in ('echo "docs_only=false"', 'echo "test_impact=__ALL__"', "exit 0"):
        if want not in arm:
            problems.append(f"ci.yml classify carrier arm lacks {want}")
    arm = _carrier_arm(cov, "classify", CARRIER_ARM_IF_COVERAGE)
    for want in ('echo "docs_only=false"', "exit 0"):
        if want not in arm:
            problems.append(f"coverage.yml classify carrier arm lacks {want}")
    return problems


class CarrierRangeConsumed6117(unittest.TestCase):
    """Cloud F1: the carrier range is CONSUMED and both classify steps keep the carrier arm.

    The step that computes ``steps.carrier.outputs.before`` is pinned elsewhere; nothing
    pinned that a gate reads it, nor that a docs-only lane merge onto a carrier still
    classifies ``docs_only=false`` (a skipped job reports success and masks the verdict).
    """

    def setUp(self) -> None:
        self.ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.cov = (WORKFLOWS / "coverage.yml").read_text(encoding="utf-8")
        self.c8 = C8_WORKFLOW.read_text(encoding="utf-8")

    def mutate(self, which: str, old: str, new: str, count: int = 1) -> List[str]:
        texts = {"ci": self.ci, "cov": self.cov, "c8": self.c8}
        self.assertEqual(count, texts[which].count(old), f"mutation anchor {old!r}")
        texts[which] = texts[which].replace(old, new)
        return _carrier_consumption_problems(texts["ci"], texts["cov"], texts["c8"])

    def test_6117_r3_f1_live_tree_is_intact(self) -> None:
        self.assertEqual([], _carrier_consumption_problems(self.ci, self.cov, self.c8))

    def test_6117_r3_f1_ci_classify_carrier_arm_removed_is_killed(self) -> None:
        self.assertTrue(self.mutate("ci", CARRIER_ARM_IF, "if false; then"))

    def test_6117_r3_f1_coverage_classify_carrier_arm_removed_is_killed(self) -> None:
        self.assertTrue(self.mutate("cov", CARRIER_ARM_IF_COVERAGE, "if false; then"))

    def test_6117_r3_f1_cert_expiry_range_start_reverted_is_killed(self) -> None:
        step = _step_block(self.c8, "Run enterprise-federation cert-expiry gate")
        mutant = step.replace("steps.carrier.outputs.before || ", "")
        self.assertNotEqual(step, mutant)
        self.assertTrue(self.mutate("c8", step, mutant))

    def test_6117_r3_f1_declaration_gate_base_reverted_is_killed(self) -> None:
        old = "github.event.pull_request.base.sha || steps.carrier.outputs.before || github.event.before"
        self.assertTrue(self.mutate("c8", old, "github.event.pull_request.base.sha || github.event.before"))

    def test_6117_r3_f1_all_four_before_consumers_reverted_is_killed(self) -> None:
        mutant = self.c8.replace("steps.carrier.outputs.before || ", "")
        self.assertEqual(4, self.c8.count("steps.carrier.outputs.before || "))
        problems = _carrier_consumption_problems(self.ci, self.cov, mutant)
        self.assertEqual(4, len(problems), problems)


BEFORE_EXPR_OK = (
    "${{ steps.carrier.outputs.before || github.event.before }}",
    "${{ github.event.pull_request.base.sha || steps.carrier.outputs.before || github.event.before }}",
)
# The two classify steps read the bare push `before` only AFTER their carrier arm has
# exited with docs_only=false (pinned by CarrierRangeConsumed6117), so they never see a
# carrier push.  Any other bare consumer is a gate that narrows a carrier push.  The
# exemption is by POSITION (#6260): an occurrence is exempt only when it lies inside the
# classify job of the file that names it, not when the file merely contains one.
BEFORE_CLASSIFY_OK = {
    "ci.yml": ("${{ github.event.before }}",),
    "coverage.yml": ("${{ github.event.before }}",),
}
# `${{ github.event.before }}` and its bracket spellings.
BEFORE_ANY_RE = re.compile(
    r"\$\{\{[^}]*github\.event(?:\.before|\[\s*['\"]before['\"]\s*\])[^}]*\}\}")
# Any other way to reach the push `before` sha: the raw event payload file or a whole-event dump.
# The one reader below is the geometry verdict step, which has its own carrier arm (pinned
# by CarrierPushGeometry6117).
EVENT_PAYLOAD_RE = re.compile(r"GITHUB_EVENT_PATH|github\.event_path|toJSON\(\s*github\.event\s*\)")
EVENT_PAYLOAD_OK = ('bash scripts/check-promotion-geometry.sh --github-event "$GITHUB_EVENT_PATH"',)


def _classify_span(text: str) -> Tuple[int, int]:
    """The (start, end) character offsets of the classify job in ``text`` ((0, 0) when absent)."""
    if "\n  classify:\n" not in text:
        return 0, 0
    body = _job_text(text, "classify")
    start = text.index(body)
    return start, start + len(body)


def _bare_before_consumers(texts: Dict[str, str]) -> List[str]:
    """Every read of the push ``before`` sha that has no carrier fallback, in any workflow."""
    bad: List[str] = []
    for name, text in texts.items():
        lo, hi = _classify_span(text)
        for m in BEFORE_ANY_RE.finditer(text):
            expr = m.group(0)
            if expr in BEFORE_EXPR_OK:
                continue
            if expr in BEFORE_CLASSIFY_OK.get(name, ()) and lo <= m.start() < hi:
                continue
            line = text.count("\n", 0, m.start()) + 1
            bad.append(f"{name}:{line}: {expr}")
        for lineno, row in enumerate(text.splitlines(), 1):
            if EVENT_PAYLOAD_RE.search(row) and not any(ok in row for ok in EVENT_PAYLOAD_OK):
                bad.append(f"{name}:{lineno}: reads the raw event payload: {row.strip()}")
    return bad


class CarrierBeforeClosedWorld6117(unittest.TestCase):
    """Cloud F1 / vote 4d3ea1c5 testability lens: a fifth range consumer needs the carrier fallback."""

    def texts(self) -> Dict[str, str]:
        return _all_workflow_texts()

    def test_6117_r3_f1_every_github_event_before_has_the_carrier_fallback(self) -> None:
        self.assertEqual([], _bare_before_consumers(self.texts()))

    def test_6117_r3_f1_new_bare_consumer_is_killed(self) -> None:
        texts = self.texts()
        anchor = "          GITHUB_EVENT_BEFORE: ${{ steps.carrier.outputs.before || github.event.before }}\n"
        self.assertIn(anchor, texts["c8-precheck.yml"])
        texts["c8-precheck.yml"] = texts["c8-precheck.yml"].replace(
            anchor, anchor + "          EXTRA_BASE: ${{ github.event.before }}\n", 1)
        bad = _bare_before_consumers(texts)
        self.assertEqual(1, len(bad), bad)
        self.assertIn("c8-precheck.yml", bad[0])

    def test_6117_r3_f1_bare_consumer_outside_classify_is_killed(self) -> None:
        texts = self.texts()
        texts["release-shape.yml"] += "      # x\n          B: ${{ github.event.before }}\n"
        self.assertEqual(1, len(_bare_before_consumers(texts)))


class ApprovalDocTruth6213(unittest.TestCase):
    """Cloud F5 / F6: the docs and a pin comment do not overclaim against the #6213 residual."""

    def test_6117_r3_f5_docs_do_not_say_never_or_cannot(self) -> None:
        for rel in ("docs/AI_DEVELOPER_GOVERNANCE.md", "docs/contributing-external.md"):
            with self.subTest(doc=rel):
                text = " ".join((ROOT / rel).read_text(encoding="utf-8").split())
                self.assertNotIn("a push run never reports a pass where the PR run would fail", text)
                self.assertNotIn("a push run cannot report a pass beside a failing PR run", text)
                self.assertIn("#6213", text)
                self.assertIn("named by the queue ref", text)

    def test_6117_r3_f6_claude_md_size_comment_states_the_current_rule(self) -> None:
        raw = (ROOT / "scripts" / "check-claude-md-size.py").read_text(encoding="utf-8")
        text = " ".join(raw.replace("\n#", "\n").split())
        self.assertNotIn("must NOT name rehearsal/** or chain/**", text)
        self.assertIn("chain/** is admitted on push ONLY in the required-set workflows", text)


class GateScriptsRunIsolated6117(unittest.TestCase):
    """N-2 (#5163 class): the gate scripts the c8 workflow runs use ``python3 -I``.

    ``python3 scripts/x.py`` puts ``scripts/`` first on ``sys.path``, so a sibling
    ``scripts/json.py`` or ``scripts/re.py`` would run inside the gate.  ``-I`` removes
    the script directory and the user site from the import path.  Precedent:
    ``claude-md-rule-compare.yml`` and the cert-expiry steps of this workflow.
    """

    GATE_SCRIPTS = {"check_promotion_geometry.py": 5, "check_external_pr_approval.py": 2}

    def test_6117_r3_n2_gate_scripts_run_with_isolated_python(self) -> None:
        text = C8_WORKFLOW.read_text(encoding="utf-8")
        for script, expected in self.GATE_SCRIPTS.items():
            with self.subTest(script=script):
                bare = re.findall(r"python3 (?!-I )\S*scripts/" + re.escape(script), text)
                self.assertEqual([], bare, f"{script} must run as `python3 -I` (#5163)")
                isolated = re.findall(r"python3 -I scripts/" + re.escape(script), text)
                self.assertEqual(expected, len(isolated),
                                 f"{script}: expected {expected} isolated invocations")


class MergeGroupDocTruth6227(unittest.TestCase):
    """#6227: no doc says the merge_group arm judges a PR head it cannot see."""

    def test_6227_changelog_names_the_queue_ref_not_the_sha(self) -> None:
        text = " ".join((ROOT / "changelog.d" / "6117.security.md").read_text(encoding="utf-8").split())
        self.assertIn("head_ref", text)
        self.assertNotIn("judges push and merge-queue runs", text)

    def test_6227_evaluator_docstring_names_the_queue_ref(self) -> None:
        src = APPROVAL_PY.read_text(encoding="utf-8")
        self.assertIn("gh-readonly-queue", src)


class RoundTwoDocTruth6117(unittest.TestCase):
    """C-F3: the classify comment no longer says push events never gate merges."""

    def test_6117_r2_cf3_ci_classify_comment_names_the_carrier_exception(self) -> None:
        ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("push events do not gate merges", " ".join(ci.replace("#", " ").split()))


# ---- Round 4, item 1 (#6259): bot authors, and every F4 validator pinned ----

def _exec_approval_src(src: str):
    """The approval evaluator compiled from ``src`` (a mutant), as an attribute namespace."""
    import types
    ns: dict = {"__name__": "approval_mutant_6259"}
    exec(compile(src, "approval_mutant_6259", "exec"), ns)
    mod = types.SimpleNamespace()
    for key, value in ns.items():
        setattr(mod, key, value)
    return mod


def _pr_event_with(login: str = "someone", assoc: str = "NONE",
                   head_repo: Optional[str] = "fork/ai-memory-mcp") -> dict:
    pr = _pr(5, SHA_A, assoc, head_repo)
    pr["user"] = {"login": login}
    return {"pull_request": pr}


def _gate_text(mod, event: dict, reviews: Optional[List[dict]] = None, repo: str = REPO_6117) -> Tuple[int, str]:
    api = _fake_api([], {5: reviews or []})
    rc, lines = mod.run_gate("pull_request", event, repo, "", OPERATOR_6117, api)
    return rc, "\n".join(lines)


class ApprovalValidators6259(unittest.TestCase):
    """#6259 (code 1, 4): bot authors are judged, and each F4 validator is load-bearing."""

    def setUp(self) -> None:
        self.mod = _load_approval()
        self.src = APPROVAL_PY.read_text(encoding="utf-8")

    def test_6259_bot_authors_are_judged_not_refused(self) -> None:
        for login in ("dependabot[bot]", "github-actions[bot]"):
            with self.subTest(login=login):
                rc, out = _gate_text(self.mod, _pr_event_with(login))
                self.assertEqual(1, rc, out)  # external and unapproved
                self.assertIn("operator-approval gate FAILED for PR #5", out)
                self.assertNotIn("invalid author login", out)
                rc, out = _gate_text(self.mod, _pr_event_with(login), [_review(SHA_A)])
                self.assertEqual(0, rc, out)  # the operator approval cures a bot PR

    def test_6259_malformed_bot_suffixes_fail_closed(self) -> None:
        for login in ("evil[bot]x", "[bot]", "a[bot][bot]", "a[bot", "a]bot[", "a[BOT]", "a[bot]\n"):
            with self.subTest(login=login):
                rc, out = _gate_text(self.mod, _pr_event_with(login), [_review(SHA_A)])
                self.assertEqual(1, rc, out)
                self.assertIn("invalid author login", out)

    def test_6259_replays_the_real_dependabot_payload_shape(self) -> None:
        # PR #4127 (dependabot[bot], NONE, same-repo head): external by association, so it
        # needs the approval and never the login refusal.
        event = _pr_event_with("dependabot[bot]", "NONE", REPO_6117)
        rc, out = _gate_text(self.mod, event)
        self.assertEqual(1, rc, out)
        self.assertNotIn("invalid", out)

    HOSTILE = (
        ("login", lambda: _pr_event_with("x\n::error::forged"), "invalid author login"),
        ("association", lambda: _pr_event_with(assoc="NONE\n::set-output x"), "invalid author_association"),
        ("head-repo-name", lambda: _pr_event_with(head_repo="f/r\n::error::forged"), "invalid head repository name"),
        ("head-repo-name-101-chars", lambda: _pr_event_with(head_repo="o/" + "r" * 101),
         "invalid head repository name"),
    )

    def hostile_misses(self, mod) -> List[str]:
        missed: List[str] = []
        for name, make, text in self.HOSTILE:
            rc, out = _gate_text(mod, make())
            if rc != 1 or text not in out:
                missed.append(name)
        return missed

    def test_6259_live_validators_refuse_every_hostile_field(self) -> None:
        self.assertEqual([], self.hostile_misses(self.mod))

    def test_6259_repo_name_length_cap_is_100(self) -> None:
        ok = "o/" + "r" * 100
        rc, out = _gate_text(self.mod, _pr_event_with(head_repo=ok))
        self.assertNotIn("invalid head repository name", out)
        rc, out = _gate_text(self.mod, _pr_event_with(), repo="o/" + "r" * 101)
        self.assertEqual(1, rc, out)
        self.assertIn("is not owner/name", out)

    MUTANTS = (
        ("login validation removed", "not isinstance(author, str) or not LOGIN_RE.fullmatch(author)", "False",
         "login"),
        ("association validation removed",
         'assoc is not None and (not isinstance(assoc, str) or not ASSOC_RE.fullmatch(assoc))', "False",
         "association"),
        ("head-repo-name validation removed",
         "full_name is not None and (not isinstance(full_name, str) or not REPO_RE.fullmatch(full_name))",
         "False", "head-repo-name"),
    )

    def test_6259_m01_each_validator_removal_is_killed(self) -> None:
        for label, old, new, hostile in self.MUTANTS:
            with self.subTest(mutant=label):
                self.assertEqual(1, self.src.count(old), f"mutation anchor {old!r}")
                missed = self.hostile_misses(_exec_approval_src(self.src.replace(old, new, 1)))
                self.assertIn(hostile, missed)


# ---- Round 4, item 2 (#6260, #6239): the closed-world scan is closed ----

def _all_workflow_texts() -> Dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(WORKFLOWS.glob("*.yml"))}


def _insert_after_job_header(text: str, job: str, line: str) -> str:
    header = f"\n  {job}:\n"
    assert text.count(header) == 1, (job, text.count(header))
    return text.replace(header, header + line, 1)


class BeforeClosedWorld6260(unittest.TestCase):
    """#6260 / #6239: a bare ``github.event.before`` read outside the classify job is a defect.

    The round-3 exemption asked whether the classify job contains the expression anywhere,
    not whether THIS occurrence lies inside classify, so a new bare consumer in any other
    ci.yml or coverage.yml job passed every test.
    """

    def texts(self) -> Dict[str, str]:
        return _all_workflow_texts()

    def test_6260_scan_set_is_every_workflow_file(self) -> None:
        scanned = set(CarrierBeforeClosedWorld6117().texts())
        self.assertEqual({p.name for p in WORKFLOWS.glob("*.yml")}, scanned)
        self.assertIn("coverage.yml", scanned)

    def test_6260_live_tree_has_no_uncovered_before_read(self) -> None:
        self.assertEqual([], _bare_before_consumers(self.texts()))

    def test_6260_m01_bare_read_in_another_ci_job_is_killed(self) -> None:
        texts = self.texts()
        texts["ci.yml"] = _insert_after_job_header(
            texts["ci.yml"], "lint", "    env:\n      BARE: ${{ github.event.before }}\n")
        bad = _bare_before_consumers(texts)
        self.assertEqual(1, len(bad), bad)
        self.assertTrue(bad[0].startswith("ci.yml:"), bad)

    def test_6260_m02_bare_read_in_the_coverage_thresholds_job_is_killed(self) -> None:
        texts = self.texts()
        texts["coverage.yml"] = _insert_after_job_header(
            texts["coverage.yml"], "per-module-thresholds",
            "    env:\n      BARE: ${{ github.event.before }}\n")
        bad = _bare_before_consumers(texts)
        self.assertEqual(1, len(bad), bad)
        self.assertTrue(bad[0].startswith("coverage.yml:"), bad)

    def test_6260_m03_bracket_form_read_is_killed(self) -> None:
        texts = self.texts()
        texts["c8-precheck.yml"] = _insert_after_job_header(
            texts["c8-precheck.yml"], REQUIRED_CONTEXTS_JOB,
            "    env:\n      BARE: ${{ github.event['before'] }}\n")
        self.assertEqual(1, len(_bare_before_consumers(texts)))

    def test_6260_m04_shell_read_of_the_payload_is_killed(self) -> None:
        texts = self.texts()
        texts["c8-precheck.yml"] = _insert_after_job_header(
            texts["c8-precheck.yml"], REQUIRED_CONTEXTS_JOB,
            "    steps:\n      - run: base=$(jq -r .before \"$GITHUB_EVENT_PATH\")\n")
        self.assertEqual(1, len(_bare_before_consumers(texts)))

    def test_6260_m05_bare_read_in_a_new_workflow_file_is_killed(self) -> None:
        texts = self.texts()
        texts["brand-new.yml"] = "jobs:\n  x:\n    steps:\n      - run: echo ${{ github.event.before }}\n"
        bad = _bare_before_consumers(texts)
        self.assertEqual(["brand-new.yml:4: ${{ github.event.before }}"], bad)


# ---- Round 4, item 3 (#6261): the approval job cannot be neutralised ----

APPROVAL_EVALUATE_STEP = "Evaluate external-PR approval requirement"
APPROVAL_SELFTEST_STEP = "Self-test the external-PR approval evaluator (#6193)"
APPROVAL_STEP_NEUTRALISER = r"""(?m)^\s+(?:- )?["']?(?:if|continue-on-error)["']?\s*:|^\s+timeout-minutes\s*:\s*0\s*$"""
# The exact commands (no `|| true`, no swapped flag): the Evaluate step must run the real check.
APPROVAL_SELFTEST_RUN = "python3 -I scripts/check_external_pr_approval.py --self-test"
APPROVAL_EVALUATE_RUN = "python3 -I scripts/check_external_pr_approval.py"
# The approving authority the context name, the governance doc and contributing-external.md promise.
APPROVAL_OPERATOR = "alphaonedev"


APPROVAL_JOB_PERMISSIONS = {"contents": "read", "pull-requests": "read"}
WORKFLOW_PERMISSIONS = {"contents": "read"}
APPROVAL_EVALUATE_ENV = {"GH_TOKEN": "${{ github.token }}", "OPERATOR_LOGIN": APPROVAL_OPERATOR}
APPROVAL_STEP_KEYS = [["uses", "with"], ["name", "run"], ["name", "env", "run"]]
APPROVAL_JOB_KEYS = ["name", "runs-on", "timeout-minutes", "permissions", "steps"]


def _row_scalar(body: str) -> str:
    """The scalar after the first ``:`` of a mapping row (empty for a block owner)."""
    return body.split(":", 1)[1].strip() if ":" in body else ""


def _approval_job_shape(c8: str) -> Dict[str, object]:
    """The approval job and workflow top level as parsed by the closed-world scanner (#6335).

    ``job_keys``: the job's own keys in order; ``permissions_row``/``permissions``: the job's
    permissions row and its children; ``steps``: per step, its keys in order and its env
    mapping; ``top_keys``, ``top_permissions_row``, ``top_permissions``: the same for the
    workflow.  Raises Unparsed when the scanner refuses a row.
    """
    job_rows = _meaningful(_job_text(c8, APPROVAL_JOB))
    shape: Dict[str, object] = {"job_keys": [], "permissions_row": None, "permissions": {}, "steps": []}
    job_keys: List[str] = shape["job_keys"]  # type: ignore[assignment]
    permissions: Dict[str, str] = shape["permissions"]  # type: ignore[assignment]
    steps: List[Dict[str, object]] = shape["steps"]  # type: ignore[assignment]
    section = ""
    step: Optional[Dict[str, object]] = None
    sub = ""
    for indent, body, key in job_rows[1:]:
        if indent <= 4:
            job_keys.append(key if indent == 4 else body)
            section = key
            if key == "permissions":
                shape["permissions_row"] = body
            continue
        if section == "permissions":
            if indent == 6:
                permissions[key] = _row_scalar(body)
            else:
                permissions["<nested>"] = body
        elif section == "steps":
            if indent == 6 and body.startswith("- "):
                step = {"keys": [key], "env": {}}
                steps.append(step)
                sub = key
            elif indent == 8 and step is not None:
                step["keys"].append(key)  # type: ignore[union-attr]
                sub = key
            elif indent == 10 and step is not None and sub == "env":
                step["env"][key] = _row_scalar(body)  # type: ignore[index]
    top_keys: List[str] = []
    top_permissions: Dict[str, str] = {}
    shape["top_permissions_row"] = None
    owner = ""
    for indent, body, key in _meaningful(c8):
        if indent == 0:
            top_keys.append(key)
            owner = key
            if key == "permissions":
                shape["top_permissions_row"] = body
        elif owner == "permissions":
            top_permissions[key if indent == 2 else "<nested>"] = _row_scalar(body)
    shape["top_keys"] = top_keys
    shape["top_permissions"] = top_permissions
    return shape


def _approval_job_problems(c8: str) -> List[str]:
    """Ways the approval job could pass while the evaluator does not decide (empty = intact)."""
    job = _job_text(c8, APPROVAL_JOB)
    problems: List[str] = []
    if re.search(r"(?m)^    (needs|if|continue-on-error):", job):
        problems.append("job-level needs/if/continue-on-error")
    if not re.search(r"(?m)^    timeout-minutes:\s*[1-9][0-9]*\s*$", job):
        problems.append("job timeout-minutes is not a positive integer")
    for name, command in ((APPROVAL_SELFTEST_STEP, APPROVAL_SELFTEST_RUN),
                          (APPROVAL_EVALUATE_STEP, APPROVAL_EVALUATE_RUN)):
        block = _step_block(job, name)
        if not block:
            problems.append(f"step {name!r} is missing")
            continue
        if re.search(APPROVAL_STEP_NEUTRALISER, block):
            problems.append(f"step {name!r} is neutralised")
        runs = [r.strip() for r in _step_runs(block, name)]
        if runs != [command]:
            problems.append(f"step {name!r} runs {runs!r}, not exactly {command!r}")
    evaluate = _step_block(job, APPROVAL_EVALUATE_STEP)
    if f"          OPERATOR_LOGIN: {APPROVAL_OPERATOR}\n" not in evaluate:
        problems.append(f"the Evaluate step no longer sets OPERATOR_LOGIN: {APPROVAL_OPERATOR}")
    try:
        shape = _approval_job_shape(c8)
    except Unparsed as exc:
        return problems + [f"c8-precheck.yml does not parse: {exc}"]
    # #6387: the job's own keys are exact, so `if :`/`needs :`/`continue-on-error :` with a
    # space before the colon (which YAML and actionlint accept) cannot slip past a regex.
    if shape["job_keys"] != APPROVAL_JOB_KEYS:
        problems.append(f"approval job keys are {shape['job_keys']!r}, not exactly {APPROVAL_JOB_KEYS!r}")
    # #6335: the token scopes are exact, for the job and for the workflow default.
    if shape["permissions_row"] != "permissions:" or shape["permissions"] != APPROVAL_JOB_PERMISSIONS:
        problems.append(f"job permissions are {shape['permissions_row']!r} {shape['permissions']!r}, "
                        f"not exactly {APPROVAL_JOB_PERMISSIONS!r}")
    if shape["top_permissions_row"] != "permissions:" or shape["top_permissions"] != WORKFLOW_PERMISSIONS:
        problems.append(f"workflow permissions are {shape['top_permissions']!r}, not exactly {WORKFLOW_PERMISSIONS!r}")
    # #6341: the only env in the job is the Evaluate step's, and its token is the job-scoped
    # github.token (bounded by the permissions above), never a repository secret.
    envs = [step["env"] for step in shape["steps"] if "env" in step["keys"]]  # type: ignore[union-attr,index,operator]
    if envs != [APPROVAL_EVALUATE_ENV]:
        problems.append(f"step env mappings are {envs!r}, not exactly [{APPROVAL_EVALUATE_ENV!r}]")
    if any("secrets." in body for _, body, _ in _meaningful(job)):
        problems.append("the approval job references `secrets.`; it may use only github.token")
    # #6388: no step key beyond the pinned ones (so no `shell:`), and no `defaults:` on the
    # job or the workflow: either reroutes the step's script through another command.
    step_keys = [step["keys"] for step in shape["steps"]]  # type: ignore[union-attr,index]
    if step_keys != APPROVAL_STEP_KEYS:
        problems.append(f"approval step keys are {step_keys!r}, not exactly {APPROVAL_STEP_KEYS!r}")
    for where, keys in (("job", shape["job_keys"]), ("workflow", shape["top_keys"])):
        if "defaults" in keys:  # type: ignore[operator]
            problems.append(f"the {where} declares `defaults:`; an approval step's shell may not be overridden")
    return problems


class ApprovalJobPinned6261(unittest.TestCase):
    """#6261 (code 3): job-level continue-on-error, `|| true` and a swapped command are killed."""

    def setUp(self) -> None:
        self.c8 = C8_WORKFLOW.read_text(encoding="utf-8")

    def mutated(self, old: str, new: str, count: int = 1) -> List[str]:
        job = _job_text(self.c8, APPROVAL_JOB)
        self.assertEqual(count, job.count(old), f"mutation anchor {old!r}")
        mutant_job = job.replace(old, new, 1)
        self.assertEqual(1, self.c8.count(job))
        return _approval_job_problems(self.c8.replace(job, mutant_job, 1))

    def test_6261_live_job_is_intact(self) -> None:
        self.assertEqual([], _approval_job_problems(self.c8))

    def test_6261_m01_job_level_continue_on_error_is_killed(self) -> None:
        self.assertTrue(self.mutated("    timeout-minutes: 5\n", "    timeout-minutes: 5\n    continue-on-error: true\n"))

    def test_6261_m02_evaluate_or_true_is_killed(self) -> None:
        self.assertTrue(self.mutated("        run: python3 -I scripts/check_external_pr_approval.py\n",
                                     "        run: python3 -I scripts/check_external_pr_approval.py || true\n"))

    def test_6261_m03_evaluate_running_the_self_test_is_killed(self) -> None:
        self.assertTrue(self.mutated("        run: python3 -I scripts/check_external_pr_approval.py\n",
                                     "        run: python3 -I scripts/check_external_pr_approval.py --self-test\n"))

    def test_6261_m04_job_timeout_zero_is_killed(self) -> None:
        self.assertTrue(self.mutated("    timeout-minutes: 5\n", "    timeout-minutes: 0\n"))

    def test_6261_m05_evaluate_script_swapped_is_killed(self) -> None:
        self.assertTrue(self.mutated("        run: python3 -I scripts/check_external_pr_approval.py\n",
                                     "        run: python3 -I scripts/check_promotion_geometry.py --self-test\n"))

    def test_6261_m06_evaluate_step_removed_is_killed(self) -> None:
        self.assertTrue(self.mutated("      - name: Evaluate external-PR approval requirement\n",
                                     "      - name: Something else\n"))


# ---- Round 4, item 4 (#6240 = sec S2, #6241): every workflow python step runs isolated ----

GEOMETRY_WRAPPER = ROOT / "scripts" / "check-promotion-geometry.sh"
# `python3 path/to/script.py ...` without -I puts the script's directory first on sys.path (#5163).
# #6389: a positive rule, not a regex. Every `python3` whose first non-option argument ends in
# `.py` must carry -I among its options; options and quoted paths are tokenised with shlex.
PYTHON_CALL_RE = re.compile(r"(?<![\w./@-])python3(?=\s)")
PYTHON_OPTIONS_WITH_ARGUMENT = "XW"
SHELL_PUNCTUATION = "();<>|&"


def _bare_python_script(rest: str) -> Optional[str]:
    """The `python3 ... x.py` text when ``rest`` (what follows `python3`) runs a script without -I, else None.

    A command line shlex cannot tokenise up to the decision is reported (fail closed).
    """
    lexer = shlex.shlex(rest, posix=True, punctuation_chars=SHELL_PUNCTUATION)
    lexer.whitespace_split = True
    seen: List[str] = []
    isolated = False
    skip_next = False
    try:
        for token in lexer:
            seen.append(token)
            if skip_next:
                skip_next = False
                continue
            if token and all(ch in SHELL_PUNCTUATION for ch in token):
                return None
            if token.startswith("--"):
                continue
            if token.startswith("-") and len(token) > 1:
                for pos, flag in enumerate(token[1:], 1):
                    if flag == "I":
                        isolated = True
                    elif flag in "cm":
                        return None
                    elif flag in PYTHON_OPTIONS_WITH_ARGUMENT:
                        skip_next = pos == len(token) - 1
                        break
                continue
            if token.endswith(".py") and not isolated:
                return "python3 " + " ".join(seen)
            return None
    except ValueError:
        return f"python3 {rest.strip()} (shlex cannot tokenise it)"
    return None


def _bare_python_script_runs(texts: Dict[str, str]) -> List[str]:
    found: List[str] = []
    for name, text in texts.items():
        for lineno, row in enumerate(text.splitlines(), 1):
            if row.lstrip().startswith("#"):
                continue
            for m in PYTHON_CALL_RE.finditer(row):
                bare = _bare_python_script(row[m.end():])
                if bare is not None:
                    found.append(f"{name}:{lineno}: {bare}")
    return found


class WrapperAndWorkflowPythonIsolated6240(unittest.TestCase):
    """#6240 (the geometry wrapper) and #6241 (every other workflow python script step)."""

    def test_6240_geometry_wrapper_runs_python_isolated(self) -> None:
        text = GEOMETRY_WRAPPER.read_text(encoding="utf-8")
        self.assertRegex(text, r'(?m)^exec python3 -I "\$SCRIPT_DIR/check_promotion_geometry\.py" "\$@"$')

    def test_6240_m01_wrapper_without_isolation_is_killed(self) -> None:
        text = GEOMETRY_WRAPPER.read_text(encoding="utf-8")
        mutant = text.replace("python3 -I ", "python3 ")
        self.assertNotEqual(text, mutant)
        self.assertNotRegex(mutant, r'(?m)^exec python3 -I "\$SCRIPT_DIR/check_promotion_geometry\.py" "\$@"$')

    def test_6240_wrapper_still_runs_the_geometry_script(self) -> None:
        out = subprocess.run(["bash", str(GEOMETRY_WRAPPER), "--print-release"], capture_output=True,
                             text=True, timeout=60, check=False)
        self.assertEqual(0, out.returncode, out.stdout + out.stderr)
        self.assertEqual("release/v1.0.0", out.stdout.strip())

    def test_6241_no_workflow_runs_a_python_script_without_isolation(self) -> None:
        self.assertEqual([], _bare_python_script_runs(_all_workflow_texts()))

    def test_6241_m01_a_bare_script_run_in_any_workflow_is_killed(self) -> None:
        texts = _all_workflow_texts()
        texts["new.yml"] = "jobs:\n  x:\n    steps:\n      - run: python3 scripts/check-x.py --self-test\n"
        mine = [f for f in _bare_python_script_runs(texts) if f.startswith("new.yml:")]
        self.assertEqual(["new.yml:4: python3 scripts/check-x.py"], mine)
        texts = _all_workflow_texts()
        self.assertIn("python3 -I scripts/", texts["ci.yml"])
        texts["ci.yml"] = texts["ci.yml"].replace("python3 -I scripts/", "python3 scripts/", 1)
        self.assertTrue(any(f.startswith("ci.yml:") for f in _bare_python_script_runs(texts)))


# ---- Round 4, item 5 (#6242): the queue ref sha is bound to the queued head ----

SHA_D = "d" * 40


class QueueRefShaBinding6242(unittest.TestCase):
    """The ``<sha>`` in ``gh-readonly-queue/<base>/pr-<N>-<sha>`` must be a full sha equal to ``merge_group.base_sha``.

    #6325 corrected the binding: the ref names the queue commit's parent (base_sha), not head_sha.
    """

    def setUp(self) -> None:
        self.mod = _load_approval()
        self.ext = _pr(7, SHA_A)

    def run_group(self, event: dict, pulls: Optional[List[dict]] = None) -> Tuple[int, str]:
        api = _fake_api(pulls if pulls is not None else [self.ext], {7: [_review(SHA_A)]})
        rc, lines = self.mod.run_gate("merge_group", event, REPO_6117, SHA_C, OPERATOR_6117, api)
        return rc, "\n".join(lines)

    def test_6242_matching_sha_is_judged(self) -> None:
        rc, out = self.run_group(_merge_group_event(7))
        self.assertEqual(0, rc, out)

    def test_6242_ref_sha_differing_from_base_sha_fails_closed(self) -> None:
        rc, out = self.run_group(_merge_group_event(7, sha=SHA_D))
        self.assertEqual(1, rc, out)
        self.assertIn("cannot establish its verdict", out)
        self.assertIn("is not merge_group.base_sha", out)

    def test_6242_short_or_non_hex_ref_sha_fails_closed(self) -> None:
        for sha in ("abc", "c" * 39, "C" * 40, "g" * 40, "c" * 41, "c" * 65):
            with self.subTest(sha=sha):
                rc, out = self.run_group(_merge_group_event(7, sha=sha))
                self.assertEqual(1, rc, out)
                self.assertIn("cannot establish its verdict", out)

    def test_6242_missing_base_sha_fails_closed(self) -> None:
        rc, out = self.run_group(_merge_group_event(7, base_sha=None))
        self.assertEqual(1, rc, out)
        self.assertIn("is not merge_group.base_sha", out)

    def test_6242_m01_dropping_the_equality_is_killed(self) -> None:
        src = APPROVAL_PY.read_text(encoding="utf-8")
        needle = " or ref_sha != base_sha"
        self.assertIn(needle, src)
        mod = _exec_approval_src(src.replace(needle, ""))
        api = _fake_api([self.ext], {7: [_review(SHA_A)]})
        rc, lines = mod.run_gate("merge_group", _merge_group_event(7, sha=SHA_D), REPO_6117, SHA_C,
                                 OPERATOR_6117, api)
        self.assertEqual(0, rc, lines)  # the mutant accepts a forged ref sha ...
        self.assertEqual(1, self.run_group(_merge_group_event(7, sha=SHA_D))[0])  # ... the live gate does not


# ---- Round 4, item 7 (#6244): bounded PR-number digits ----


class QueueRefDigitCap6244(unittest.TestCase):
    """A queue ref with an enormous digit run fails closed with one short error line, never a traceback."""

    def setUp(self) -> None:
        self.mod = _load_approval()

    def gate(self, digits: str) -> Tuple[int, List[str]]:
        ref = f"refs/heads/gh-readonly-queue/main/pr-{digits}-{SHA_C}"
        event = {"merge_group": {"head_sha": SHA_C, "base_sha": SHA_C, "head_ref": ref}}
        return self.mod.run_gate("merge_group", event, REPO_6117, SHA_C, OPERATOR_6117, _fake_api([_pr(7, SHA_A)]))

    def test_6244_oversized_digit_run_fails_closed_with_one_short_line(self) -> None:
        for digits in ("9" * 5000, "9" * 10, "1" + "0" * 4400):
            with self.subTest(digits=len(digits)):
                rc, lines = self.gate(digits)
                self.assertEqual(1, rc, lines)
                self.assertEqual(1, len(lines), lines)
                self.assertLess(len(lines[0]), 600, len(lines[0]))
                self.assertIn("cannot establish its verdict", lines[0])

    def test_6244_ordinary_pr_numbers_still_parse(self) -> None:
        for digits in ("7", "6117", "123456789"):
            with self.subTest(digits=digits):
                ref = f"refs/heads/gh-readonly-queue/main/pr-{digits}-{SHA_C}"
                event = {"merge_group": {"head_sha": SHA_C, "base_sha": SHA_C, "head_ref": ref}}
                self.assertEqual(int(digits), self.mod.merge_group_pr_number(event))

    def test_6244_m01_removing_the_cap_is_killed(self) -> None:
        src = APPROVAL_PY.read_text(encoding="utf-8")
        needle = "pr-([0-9]{1,9})-"
        self.assertIn(needle, src)
        mod = _exec_approval_src(src.replace(needle, "pr-([0-9]+)-"))
        ref = f"refs/heads/gh-readonly-queue/main/pr-{'9' * 5000}-{SHA_C}"
        event = {"merge_group": {"head_sha": SHA_C, "base_sha": SHA_C, "head_ref": ref}}
        # #6326: the kill must not depend on the interpreter. Python >= 3.11 caps int() at 4300
        # digits (ValueError); 3.9/3.10 parse 5000 digits and the mutant then echoes the whole
        # number in its error line. Either way the mutant loses the property the cap gives: one
        # bounded line naming no oversized number. The live gate keeps it on every version.
        self.assertIsNone(self.mod.QUEUE_REF_RE.fullmatch(ref))
        self.assertIsNotNone(mod.QUEUE_REF_RE.fullmatch(ref))
        try:
            rc, lines = mod.run_gate("merge_group", event, REPO_6117, SHA_C, OPERATOR_6117,
                                     _fake_api([_pr(7, SHA_A)]))
        except ValueError:
            pass  # killed: the mutant crashes instead of failing closed
        else:
            self.assertEqual(1, rc, lines)
            self.assertGreaterEqual(max(len(line) for line in lines), 5000, lines)  # killed: unbounded line
        live_rc, live_lines = self.gate("9" * 5000)
        self.assertEqual((1, 1), (live_rc, len(live_lines)))
        self.assertLess(len(live_lines[0]), 600)


# ---- Round 4, item 6 (#6243): workflow-command data is escaped; fine-grained tokens are redacted ----

PAT_6243 = "github_pat_" + "A1b2C3d4E5f6G7h8I9j0K1" + "_" + "x" * 40


class WorkflowCommandEscaping6243(unittest.TestCase):
    """Text the gate relays into ``::error::`` lines can never start another workflow command."""

    def setUp(self) -> None:
        self.mod = _load_approval()

    def failing_gate(self, message: str) -> List[str]:
        def api(path: str):
            raise self.mod.GateError(message)
        _rc, lines = self.mod.run_gate("push", {}, REPO_6117, SHA_A, OPERATOR_6117, api)
        return lines

    def test_6243_forged_workflow_commands_in_relayed_text_are_neutralised(self) -> None:
        for hostile in ("boom\n::error::forged", "boom\r::set-output name=x::y", "100% sure\n::add-mask::z",
                        "boom\u2028::error::forged", "boom\x1b[31m red"):
            with self.subTest(hostile=hostile):
                lines = self.failing_gate(hostile)
                self.assertEqual(1, len(lines), lines)
                text = "".join(lines)
                self.assertEqual(1, len(text.splitlines()), text)  # one physical line, one command
                for bad in ("\n", "\r", "\x1b", "\u2028"):
                    self.assertNotIn(bad, text)

    def test_6243_percent_and_newlines_are_escaped_not_dropped(self) -> None:
        text = self.failing_gate("a%b\nc\rd")[0]
        self.assertIn("a%25b%0Ac%0Dd", text)

    def test_6243_fine_grained_token_is_redacted(self) -> None:
        text = self.failing_gate("HTTP 401 for " + PAT_6243)[0]
        self.assertNotIn("github_pat_", text)
        self.assertIn("[redacted]", text)

    def test_6243_classic_tokens_are_still_redacted(self) -> None:
        text = self.failing_gate("HTTP 401 for ghp_" + "a" * 36)[0]
        self.assertNotIn("ghp_", text)

    def test_6243_gh_stderr_is_escaped_and_redacted_end_to_end(self) -> None:
        import types
        hostile = "bad credentials " + PAT_6243 + "\x1b[0m\r::error::forged\nsecond line"

        def fake_run(*_a, **_k):
            return types.SimpleNamespace(returncode=1, stdout="", stderr=hostile)
        with unittest.mock.patch.object(self.mod.subprocess, "run", fake_run):
            _rc, lines = self.mod.run_gate("push", {}, REPO_6117, SHA_A, OPERATOR_6117, self.mod.gh_api)
        text = "\n".join(lines)
        self.assertEqual(1, len(lines), lines)
        self.assertEqual(1, len(text.splitlines()), text)
        self.assertNotIn("github_pat_", text)
        self.assertNotIn("\x1b", text)

    def test_6243_m01_every_error_emission_uses_the_escaper(self) -> None:
        src = APPROVAL_PY.read_text(encoding="utf-8")
        self.assertEqual(1, src.count('"::error::"'))  # only the escaper builds the prefix
        self.assertNotRegex(src, r'f"::error::')
        self.assertGreaterEqual(src.count("workflow_error("), 3)
        mutant = src.replace("def workflow_error(message):", "def workflow_error(message):\n    return '::error::' + message")
        self.assertNotEqual(src, mutant)
        mod = _exec_approval_src(mutant)

        def api(path: str):
            raise mod.GateError("x\n::error::forged")
        _rc, lines = mod.run_gate("push", {}, REPO_6117, SHA_A, OPERATOR_6117, api)
        self.assertIn("\n", "".join(lines))  # the mutant leaks the raw newline; the live module does not


# ---- Round 4: cloud round-2 F3 (operator pin), F6 (key-shape), F7 (carrier id), F8 (header comment) ----


class CloudR2ApprovalPins(unittest.TestCase):
    def setUp(self) -> None:
        self.c8 = C8_WORKFLOW.read_text(encoding="utf-8")

    def mutated_job(self, old: str, new: str) -> List[str]:
        job = _job_text(self.c8, APPROVAL_JOB)
        self.assertEqual(1, job.count(old), f"mutation anchor {old!r}")
        return _approval_job_problems(self.c8.replace(job, job.replace(old, new, 1), 1))

    def test_cloud_r2_f3_operator_login_is_pinned(self) -> None:
        self.assertEqual([], _approval_job_problems(self.c8))
        self.assertTrue(self.mutated_job("OPERATOR_LOGIN: alphaonedev\n", "OPERATOR_LOGIN: mallory\n"))
        self.assertTrue(self.mutated_job("          OPERATOR_LOGIN: alphaonedev\n", ""))

    def test_cloud_r2_f6_spaced_and_quoted_step_keys_are_neutralisers(self) -> None:
        anchor = "      - name: Evaluate external-PR approval requirement\n"
        for extra in ("        if : github.event_name == 'pull_request'\n",
                      '        "if": github.event_name == \'pull_request\'\n',
                      "        'continue-on-error' : true\n",
                      "        continue-on-error : true\n"):
            with self.subTest(extra=extra):
                self.assertTrue(self.mutated_job(anchor, anchor + extra), extra)

    def test_cloud_r2_f8_header_comment_matches_the_per_event_behaviour(self) -> None:
        header = _job_text(self.c8, APPROVAL_JOB)
        self.assertNotIn("applies the rule above to each", header)
        self.assertIn("named by the queue ref", header)
        self.assertIn("base_sha", header)  # #6325: the ref sha is the queue commit's parent


class CarrierIdPinned6117(unittest.TestCase):
    """Cloud r2 F7: every carrier step keeps ``id: carrier`` so ``steps.carrier.outputs`` resolves."""

    def test_cloud_r2_f7_renamed_carrier_id_is_killed(self) -> None:
        ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        cov = (WORKFLOWS / "coverage.yml").read_text(encoding="utf-8")
        c8 = C8_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual([], _carrier_consumption_problems(ci, cov, c8))
        self.assertEqual(4, c8.count("        id: carrier\n"))
        mutant = c8.replace("        id: carrier\n", "        id: carrier0\n")
        self.assertTrue(_carrier_consumption_problems(ci, cov, mutant))
        one = c8.replace("        id: carrier\n", "        id: carrier0\n", 1)
        self.assertTrue(_carrier_consumption_problems(ci, cov, one))


# ---- Round 5 (#6325, #6391): the queue-ref sha is merge_group.base_sha; real payload shapes ----


class QueueRefBaseSha6325(unittest.TestCase):
    """The ``<sha>`` in ``gh-readonly-queue/<base>/pr-<N>-<sha>`` is the queue commit's parent.

    GitHub builds the queue commit on top of ``merge_group.base_sha`` and names the ref after
    that parent; ``merge_group.head_sha`` is the queue commit itself.  REAL_RUNS are the three
    distinct payload shapes of the ten runs cited by the round-4 review (run id, PR, head_ref,
    the queue commit's only parent = base_sha, head_sha), read from the public Actions API.
    """

    REAL_RUNS = (
        ("bevyengine/bevy run 37836253771", 26056,
         "refs/heads/gh-readonly-queue/main/pr-26056-f0391870df745bd4904218c3270e09808eabd9b9",
         "f0391870df745bd4904218c3270e09808eabd9b9", "59fed6a181902d40ccd739dd8f7c97d6d5714f42"),
        ("bevyengine/bevy run 37832290092", 26060,
         "refs/heads/gh-readonly-queue/main/pr-26060-383d525c841dd6d1c087b3b1b3b3c4b3248c5345",
         "383d525c841dd6d1c087b3b1b3b3c4b3248c5345", "f0391870df745bd4904218c3270e09808eabd9b9"),
        ("github/docs run 37797829023", 46236,
         "refs/heads/gh-readonly-queue/main/pr-46236-be8d52465d374661778ab1b5bc493f4403805221",
         "be8d52465d374661778ab1b5bc493f4403805221", "ca64eb3491bce1212c3d3dddbbb8af2d494b6df3"),
    )

    def setUp(self) -> None:
        self.mod = _load_approval()

    def gate(self, event: dict, number: int = 7, approved: bool = True, assoc: str = "NONE",
             head_repo: Optional[str] = "fork/ai-memory-mcp", mod=None) -> Tuple[int, str]:
        pr = _pr(number, SHA_A, assoc, head_repo)
        api = _fake_api([pr], {number: [_review(SHA_A)] if approved else []})
        head = event.get("merge_group", {}).get("head_sha", SHA_C)
        rc, lines = (mod or self.mod).run_gate("merge_group", event, REPO_6117, head, OPERATOR_6117, api)
        return rc, "\n".join(lines)

    def test_6325_real_shape_approved_external_pr_passes(self) -> None:
        rc, out = self.gate(_merge_group_event(7))
        self.assertEqual(0, rc, out)
        self.assertIn("judging PR #7 named by the queue ref", out)

    def test_6325_real_shape_team_pr_passes(self) -> None:
        rc, out = self.gate(_merge_group_event(8), number=8, approved=False, assoc="MEMBER", head_repo=REPO_6117)
        self.assertEqual(0, rc, out)

    def test_6325_real_shape_unapproved_external_pr_fails(self) -> None:
        rc, out = self.gate(_merge_group_event(7), approved=False)
        self.assertEqual(1, rc, out)
        self.assertIn("gate FAILED for PR #7", out)

    def test_6325_ref_sha_equal_to_head_sha_not_base_sha_fails_closed(self) -> None:
        # The round-4 binding: a ref naming the queue commit itself.  GitHub never emits it.
        rc, out = self.gate(_merge_group_event(7, sha=SHA_C))
        self.assertEqual(1, rc, out)
        self.assertIn("cannot establish its verdict", out)
        self.assertIn("base_sha", out)

    def test_6325_missing_or_malformed_base_sha_fails_closed(self) -> None:
        for base_sha in (None, "", 7, SHA_E[:39], SHA_E.upper(), SHA_E + "e", ["e" * 40]):
            with self.subTest(base_sha=base_sha):
                event = _merge_group_event(7)
                if base_sha is None:
                    del event["merge_group"]["base_sha"]
                else:
                    event["merge_group"]["base_sha"] = base_sha
                rc, out = self.gate(event)
                self.assertEqual(1, rc, out)
                self.assertIn("cannot establish its verdict", out)

    def test_6325_short_or_non_hex_ref_sha_fails_closed_even_when_base_sha_matches(self) -> None:
        for sha in ("abc", "e" * 39, "E" * 40, "g" * 40):
            with self.subTest(sha=sha):
                rc, out = self.gate(_merge_group_event(7, sha=sha, base_sha=sha))
                self.assertEqual(1, rc, out)

    def test_6325_real_payload_replay(self) -> None:
        for label, number, ref, base_sha, head_sha in self.REAL_RUNS:
            event = {"action": "checks_requested",
                     "merge_group": {"head_ref": ref, "base_sha": base_sha, "head_sha": head_sha,
                                     "base_ref": "refs/heads/main"}}
            with self.subTest(run=label):
                self.assertNotEqual(base_sha, head_sha)
                self.assertEqual(number, self.mod.merge_group_pr_number(event))
                self.assertEqual(0, self.gate(event, number=number)[0])
                self.assertEqual(1, self.gate(event, number=number, approved=False)[0])

    def test_6391_slashed_release_base_parses_and_is_judged(self) -> None:
        event = _merge_group_event(7, base="release/v1.0.0")
        self.assertIn("gh-readonly-queue/release/v1.0.0/pr-7-", event["merge_group"]["head_ref"])
        self.assertEqual(7, self.mod.merge_group_pr_number(event))
        self.assertEqual(0, self.gate(event)[0])
        self.assertEqual(1, self.gate(event, approved=False)[0])

    def test_6391_m01_single_segment_base_mutant_is_killed(self) -> None:
        src = APPROVAL_PY.read_text(encoding="utf-8")
        needle = "gh-readonly-queue/.+/pr-"
        self.assertEqual(1, src.count(needle))
        mutant = _exec_approval_src(src.replace(needle, "gh-readonly-queue/[^/]+/pr-"))
        event = _merge_group_event(7, base="release/v1.0.0")
        self.assertEqual(1, self.gate(event, mod=mutant)[0])  # the mutant fails every real queue run here
        self.assertEqual(0, self.gate(event)[0])

    def test_6325_m01_head_sha_binding_mutant_is_killed(self) -> None:
        src = APPROVAL_PY.read_text(encoding="utf-8")
        needle = 'group.get("base_sha")'
        self.assertEqual(1, src.count(needle))
        mutant = _exec_approval_src(src.replace(needle, 'group.get("head_sha")'))
        self.assertEqual(1, self.gate(_merge_group_event(7), mod=mutant)[0])  # wedges every real run
        self.assertEqual(0, self.gate(_merge_group_event(7, sha=SHA_C), mod=mutant)[0])  # passes a forged one

    def test_6325_self_test_uses_the_real_shape(self) -> None:
        out = subprocess.run([sys.executable, "-I", str(APPROVAL_PY), "--self-test"],
                             capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(0, out.returncode, out.stdout + out.stderr)
        for case in ("merge-group-approved", "merge-group-release-base-approved",
                     "merge-group-ref-sha-is-head-sha-not-base-sha", "merge-group-missing-base-sha"):
            self.assertIn(f"self-test PASS: {case} ", out.stdout)

    def test_6325_workflow_comment_and_docstring_name_base_sha(self) -> None:
        header = _job_text(C8_WORKFLOW.read_text(encoding="utf-8"), APPROVAL_JOB)
        flat = " ".join(header.replace("#", " ").split())
        self.assertNotIn("must equal merge_group.head_sha", flat)
        self.assertIn("merge_group.base_sha", flat)
        doc = " ".join(APPROVAL_PY.read_text(encoding="utf-8").split('"""')[1].split())
        self.assertIn("merge_group.base_sha", doc)



# ---- Round 5 (#6327): the approval docs disclose every open residual of the gate ----


class ApprovalDocResiduals6327(unittest.TestCase):
    """Both pages scope the merge-boundary guarantee and name each open residual next to it.

    #6213 (a PR opened later on an already-judged sha), #6223 (on pull_request the job runs the
    workflow and the evaluator from the PR's own merge ref) and #6229 (a merge_group run judges
    only the PR named by the queue ref).  The pin stays until those issues close.
    """

    DOCS = ("docs/AI_DEVELOPER_GOVERNANCE.md", "docs/contributing-external.md")

    def paragraph(self, rel: str) -> str:
        text = (ROOT / rel).read_text(encoding="utf-8")
        start = text.index("External-PR operator-approval gate (author outside team => @alphaonedev review)")
        end = text.find("\n3. " if rel.endswith("GOVERNANCE.md") else "\n4. ", start)
        self.assertGreater(end, start, rel)
        return " ".join(text[start:end].split())

    def test_6327_each_page_names_all_open_residuals_beside_the_guarantee(self) -> None:
        for rel in self.DOCS:
            para = self.paragraph(rel)
            for issue in ("#6213", "#6223", "#6229"):
                with self.subTest(doc=rel, issue=issue):
                    self.assertIn(issue, para)

    def test_6327_the_guarantee_is_scoped(self) -> None:
        for rel in self.DOCS:
            with self.subTest(doc=rel):
                para = self.paragraph(rel)
                self.assertIn("open residuals", para)
                self.assertIn("own merge ref", para)  # #6223
                self.assertIn("only the PR named by the queue ref", para)  # #6229



# ---- Round 5 (#6328): Bearer / Basic / token authorization values are redacted ----


class AuthorizationRedaction6328(unittest.TestCase):
    """An authorization value in relayed gh stderr never reaches the ``::error::`` line."""

    # Synthetic shapes only: a JWT-like triple and a base64 user:pass blob.
    JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLXZhbHVl"
    BASIC = "dXNlcjpwYXNzd29yZC12YWx1ZQ=="
    OPAQUE = "v1.0123456789abcdef0123456789abcdef"

    def setUp(self) -> None:
        self.mod = _load_approval()

    def relayed(self, stderr: str) -> str:
        import types

        def fake_run(*_a, **_k):
            return types.SimpleNamespace(returncode=1, stdout="", stderr=stderr)
        with unittest.mock.patch.object(self.mod.subprocess, "run", fake_run):
            _rc, lines = self.mod.run_gate("push", {}, REPO_6117, SHA_A, OPERATOR_6117, self.mod.gh_api)
        self.assertEqual(1, len(lines), lines)
        return lines[0]

    def test_6328_authorization_schemes_are_redacted_in_relayed_stderr(self) -> None:
        for scheme, secret in (("Bearer", self.JWT), ("bearer", self.JWT), ("Basic", self.BASIC),
                               ("token", self.OPAQUE), ("TOKEN", self.OPAQUE)):
            with self.subTest(scheme=scheme):
                line = self.relayed(f"HTTP 401: Authorization: {scheme} {secret}\n")
                self.assertIn("[redacted]", line)
                for i in range(len(secret) - 7):
                    self.assertNotIn(secret[i:i + 8], line)

    def test_6328_authorization_value_is_redacted_by_the_escaper_too(self) -> None:
        line = self.mod.workflow_error(f"header Authorization: Bearer {self.JWT}")
        self.assertNotIn(self.JWT[:8], line)
        self.assertIn("[redacted]", line)

    def test_6328_ordinary_words_survive(self) -> None:
        line = self.mod.workflow_error("Bad credentials (HTTP 401)")
        self.assertIn("Bad credentials (HTTP 401)", line)



# ---- Round 5 (#6329): the operator's LATEST deciding review of the head decides ----


class OperatorLatestReview6329(unittest.TestCase):
    """3-agent vote (6def5ab6) Q2 option D.

    Only the operator's reviews whose commit_id is the PR head count.  APPROVED,
    CHANGES_REQUESTED and DISMISSED decide; COMMENTED and PENDING are ignored; any other state
    fails closed.  Deciding reviews are ordered by (submitted_at, id) and the gate passes iff
    the last one is APPROVED.  A deciding review without a ``YYYY-MM-DDTHH:MM:SSZ``
    submitted_at or an integer id fails closed.
    """

    T1, T2, T3 = "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", "2026-10-03T00:00:00Z"

    def setUp(self) -> None:
        self.mod = _load_approval()

    def gate(self, reviews: List[dict]) -> Tuple[int, str]:
        api = _fake_api([_pr(7, SHA_A)], {7: reviews})
        rc, lines = self.mod.run_gate("push", {}, REPO_6117, SHA_A, OPERATOR_6117, api)
        return rc, "\n".join(lines)

    def both_orders(self, reviews: List[dict], want: int) -> None:
        for order in (reviews, list(reversed(reviews))):
            rc, out = self.gate(order)
            self.assertEqual(want, rc, out)

    def test_6329_changes_requested_after_approval_fails(self) -> None:
        self.both_orders([_review(SHA_A, submitted_at=self.T1, review_id=1),
                          _review(SHA_A, state="CHANGES_REQUESTED", submitted_at=self.T2, review_id=2)], 1)

    def test_6329_approval_after_changes_requested_passes(self) -> None:
        self.both_orders([_review(SHA_A, state="CHANGES_REQUESTED", submitted_at=self.T1, review_id=1),
                          _review(SHA_A, submitted_at=self.T2, review_id=2)], 0)

    def test_6329_dismissed_after_approval_fails(self) -> None:
        self.both_orders([_review(SHA_A, submitted_at=self.T1, review_id=1),
                          _review(SHA_A, state="DISMISSED", submitted_at=self.T2, review_id=2)], 1)

    def test_6329_comment_or_pending_after_approval_does_not_revoke(self) -> None:
        for state in ("COMMENTED", "PENDING"):
            with self.subTest(state=state):
                self.both_orders([_review(SHA_A, submitted_at=self.T1, review_id=1),
                                  _review(SHA_A, state=state, submitted_at=self.T3, review_id=3)], 0)

    def test_6329_equal_timestamps_are_ordered_by_id(self) -> None:
        self.both_orders([_review(SHA_A, submitted_at=self.T2, review_id=5),
                          _review(SHA_A, state="CHANGES_REQUESTED", submitted_at=self.T2, review_id=9)], 1)
        self.both_orders([_review(SHA_A, state="CHANGES_REQUESTED", submitted_at=self.T2, review_id=5),
                          _review(SHA_A, submitted_at=self.T2, review_id=9)], 0)

    def test_6329_reviews_of_other_commits_or_users_do_not_decide(self) -> None:
        self.both_orders([_review(SHA_A, submitted_at=self.T1, review_id=1),
                          _review(SHA_B, state="CHANGES_REQUESTED", submitted_at=self.T3, review_id=3),
                          _review(SHA_A, login="someone-else", state="CHANGES_REQUESTED",
                                  submitted_at=self.T3, review_id=4)], 0)

    def test_6329_unknown_operator_state_fails_closed(self) -> None:
        rc, out = self.gate([_review(SHA_A, submitted_at=self.T1, review_id=1),
                             _review(SHA_A, state="REVOKED", submitted_at=self.T2, review_id=2)])
        self.assertEqual(1, rc, out)
        self.assertIn("cannot establish its verdict", out)

    def test_6329_malformed_order_fields_fail_closed(self) -> None:
        for submitted_at, review_id in ((None, 1), ("", 1), ("2026-10-01 00:00:00", 1),
                                        ("2026-10-01T00:00:00+00:00", 1), ("2026-10-01T00:00:00.5Z", 1),
                                        (20261001, 1), (self.T1, None), (self.T1, "1"), (self.T1, True),
                                        (self.T1, 1.0)):
            with self.subTest(submitted_at=submitted_at, review_id=review_id):
                rc, out = self.gate([_review(SHA_A, submitted_at=submitted_at, review_id=review_id)])
                self.assertEqual(1, rc, out)
                self.assertIn("cannot establish its verdict", out)

    def test_6329_self_test_covers_the_revocation(self) -> None:
        out = subprocess.run([sys.executable, "-I", str(APPROVAL_PY), "--self-test"],
                             capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(0, out.returncode, out.stdout + out.stderr)
        self.assertIn("self-test PASS: push-approved-then-changes-requested (exit 1, want 1)", out.stdout)

    def test_6329_docs_and_header_say_latest_review(self) -> None:
        header = " ".join(_job_text(C8_WORKFLOW.read_text(encoding="utf-8"), APPROVAL_JOB)
                          .replace("#", " ").split())
        self.assertIn("latest review", header)
        for rel in ("docs/AI_DEVELOPER_GOVERNANCE.md", "docs/contributing-external.md"):
            with self.subTest(doc=rel):
                text = " ".join((ROOT / rel).read_text(encoding="utf-8").split())
                self.assertIn("latest review", text)



# ---- Round 5 (#6331): the team-association allowlist is pinned ----


class TeamAssociations6331(unittest.TestCase):
    """Only OWNER / MEMBER / COLLABORATOR with a same-repo head skip the operator approval."""

    NON_TEAM = ("CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "MANNEQUIN", "NONE")

    def setUp(self) -> None:
        self.mod = _load_approval()

    def gate(self, assoc: str, mod=None) -> int:
        api = _fake_api([_pr(7, SHA_A, assoc, REPO_6117)], {7: []})
        return (mod or self.mod).run_gate("push", {}, REPO_6117, SHA_A, OPERATOR_6117, api)[0]

    def test_6331_allowlist_is_exactly_the_three_team_associations(self) -> None:
        self.assertEqual(frozenset({"OWNER", "MEMBER", "COLLABORATOR"}), self.mod.TEAM_ASSOCIATIONS)

    def test_6331_every_non_team_association_needs_approval_on_a_same_repo_head(self) -> None:
        for assoc in self.NON_TEAM:
            with self.subTest(assoc=assoc):
                self.assertEqual(1, self.gate(assoc))
        for assoc in ("OWNER", "MEMBER", "COLLABORATOR"):
            with self.subTest(assoc=assoc):
                self.assertEqual(0, self.gate(assoc))

    def test_6331_m01_contributor_widening_is_killed(self) -> None:
        src = APPROVAL_PY.read_text(encoding="utf-8")
        needle = '("OWNER", "MEMBER", "COLLABORATOR")'
        self.assertEqual(1, src.count(needle))
        mutant = _exec_approval_src(src.replace(needle, '("OWNER", "MEMBER", "COLLABORATOR", "CONTRIBUTOR")'))
        self.assertEqual(0, self.gate("CONTRIBUTOR", mod=mutant))  # the mutant exempts a contributor
        self.assertEqual(1, self.gate("CONTRIBUTOR"))

    def test_6331_self_test_covers_a_same_repo_contributor(self) -> None:
        out = subprocess.run([sys.executable, "-I", str(APPROVAL_PY), "--self-test"],
                             capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(0, out.returncode, out.stdout + out.stderr)
        self.assertIn("self-test PASS: push-contributor-same-repo-unapproved (exit 1, want 1)", out.stdout)



# ---- Round 5 (#6332): an error page after a valid page fails closed ----


class PaginatedErrorPage6332(unittest.TestCase):
    """``gh api --paginate`` output whose later page is an error object fails closed on both lists."""

    ERROR_PAGE = '{"message": "API rate limit exceeded"}'

    def setUp(self) -> None:
        self.mod = _load_approval()

    def run_with_pages(self, mod, pulls_out: str, reviews_out: str) -> Tuple[int, str]:
        import types

        def fake_run(argv, **_k):
            out = reviews_out if "/reviews" in argv[-1] else pulls_out
            return types.SimpleNamespace(returncode=0, stdout=out, stderr="")
        with unittest.mock.patch.object(mod.subprocess, "run", fake_run):
            rc, lines = mod.run_gate("push", {}, REPO_6117, SHA_A, OPERATOR_6117, mod.gh_api)
        return rc, "\n".join(lines)

    def cells(self):
        other = json.dumps([_pr(8, SHA_B)])
        target = json.dumps([_pr(7, SHA_A)])
        approved = json.dumps([_review(SHA_A)])
        yield "pulls", other + "\n" + self.ERROR_PAGE + "\n" + target, approved
        yield "reviews", target, approved + self.ERROR_PAGE

    def test_6332_error_page_after_a_valid_page_fails_closed(self) -> None:
        for name, pulls_out, reviews_out in self.cells():
            with self.subTest(list=name):
                rc, out = self.run_with_pages(self.mod, pulls_out, reviews_out)
                self.assertEqual(1, rc, out)
                self.assertIn("not an array", out)

    def test_6332_m01_skipping_non_array_pages_is_killed(self) -> None:
        src = APPROVAL_PY.read_text(encoding="utf-8")
        needle = "        if not isinstance(page, list):\n"
        self.assertEqual(1, src.count(needle))
        mutant = _exec_approval_src(src.replace(needle, needle + "            continue\n"))
        rc, out = self.run_with_pages(mutant, json.dumps([_pr(8, SHA_B)]) + self.ERROR_PAGE, "[]")
        self.assertEqual(0, rc, out)  # the mutant drops page 2 and passes "no PR heads this sha"
        rc, out = self.run_with_pages(self.mod, json.dumps([_pr(8, SHA_B)]) + self.ERROR_PAGE, "[]")
        self.assertEqual(1, rc, out)

    def test_6332_self_test_covers_an_error_page_after_a_valid_page(self) -> None:
        out = subprocess.run([sys.executable, "-I", str(APPROVAL_PY), "--self-test"],
                             capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(0, out.returncode, out.stdout + out.stderr)
        self.assertIn("self-test PASS: parse_pages refuses '[1]{\"message\": \"rate limit\"}'", out.stdout)



# ---- Round 5 (#6335, #6341, #6388, #6387): the approval job's structure is pinned exactly ----


def _c8_mutant_problems(c8: str, old: str, new: str) -> List[str]:
    """_approval_job_problems of c8-precheck.yml with ``old`` (present exactly once) replaced."""
    if c8.count(old) != 1:
        raise AssertionError(f"mutation anchor {old!r} occurs {c8.count(old)} times")
    return _approval_job_problems(c8.replace(old, new, 1))


class ApprovalJobPermissions6335(unittest.TestCase):
    """The job's token scopes are exactly contents: read + pull-requests: read; the workflow's are contents: read."""

    def setUp(self) -> None:
        self.c8 = C8_WORKFLOW.read_text(encoding="utf-8")
        self.block = "    permissions:\n      contents: read\n      pull-requests: read\n    steps:\n"
        self.assertIn(self.block, _job_text(self.c8, APPROVAL_JOB))

    def test_6335_live_job_is_intact(self) -> None:
        self.assertEqual([], _approval_job_problems(self.c8))

    def test_6335_added_or_widened_job_scopes_are_killed(self) -> None:
        for mutant in ("    permissions:\n      contents: read\n      pull-requests: read\n      actions: write\n    steps:\n",
                       "    permissions:\n      contents: write\n      pull-requests: read\n    steps:\n",
                       "    permissions:\n      contents: read\n      pull-requests: read\n      id-token: write\n    steps:\n",
                       "    permissions:\n      contents: read\n      pull-requests: read\n      checks: write\n    steps:\n",
                       "    permissions: write-all\n    steps:\n",
                       "    permissions:\n      contents: read\n    steps:\n"):
            with self.subTest(mutant=mutant):
                self.assertTrue(_c8_mutant_problems(self.c8, self.block, mutant))

    def test_6335_widened_workflow_scopes_are_killed(self) -> None:
        for mutant in ("permissions:\n  contents: read\n  actions: write\n\n",
                       "permissions:\n  contents: write\n\n",
                       "permissions: write-all\n\n"):
            with self.subTest(mutant=mutant):
                self.assertTrue(_c8_mutant_problems(self.c8, "permissions:\n  contents: read\n\n", mutant))



class ApprovalJobTokenSource6341(unittest.TestCase):
    """The Evaluate step's env is exactly GH_TOKEN from github.token + OPERATOR_LOGIN; no `secrets.` in the job."""

    ENV = "          GH_TOKEN: ${{ github.token }}\n          OPERATOR_LOGIN: alphaonedev\n"
    SELF_TEST = "        run: python3 -I scripts/check_external_pr_approval.py --self-test\n"

    def setUp(self) -> None:
        self.c8 = C8_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(self.ENV, _job_text(self.c8, APPROVAL_JOB))

    def test_6341_live_job_is_intact(self) -> None:
        self.assertEqual([], _approval_job_problems(self.c8))

    def test_6341_token_source_swaps_are_killed(self) -> None:
        for mutant in ("          GH_TOKEN: ${{ secrets.OPERATOR_PAT }}\n          OPERATOR_LOGIN: alphaonedev\n",
                       '          GH_TOKEN: "${{ secrets.OPERATOR_PAT }}"\n          OPERATOR_LOGIN: alphaonedev\n',
                       "          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n          OPERATOR_LOGIN: alphaonedev\n",
                       "          GH_TOKEN: ${{ github.token }}\n          OPERATOR_LOGIN: alphaonedev\n"
                       "          GH_DEBUG: api\n",
                       "          OPERATOR_LOGIN: alphaonedev\n"):
            with self.subTest(mutant=mutant):
                self.assertTrue(_c8_mutant_problems(self.c8, self.ENV, mutant))

    def test_6341_secret_reference_anywhere_in_the_job_is_killed(self) -> None:
        mutant = self.SELF_TEST + "        env:\n          EXTRA: ${{ secrets.OPERATOR_PAT }}\n"
        self.assertTrue(_c8_mutant_problems(self.c8, self.SELF_TEST, mutant))



class ApprovalJobShellOverride6388(unittest.TestCase):
    """No `shell:` on an approval step, no `defaults:` on the job or the workflow."""

    EVALUATE_RUN = "        run: python3 -I scripts/check_external_pr_approval.py\n"
    SELF_TEST_RUN = "        run: python3 -I scripts/check_external_pr_approval.py --self-test\n"
    JOB_PERMISSIONS = "    permissions:\n      contents: read\n      pull-requests: read\n"

    def setUp(self) -> None:
        self.c8 = C8_WORKFLOW.read_text(encoding="utf-8")

    def test_6388_live_job_is_intact(self) -> None:
        self.assertEqual([], _approval_job_problems(self.c8))

    def test_6388_step_shell_overrides_are_killed(self) -> None:
        for anchor in (self.EVALUATE_RUN, self.SELF_TEST_RUN):
            for shell in ('        shell: "true {0}"\n', "        shell: python {0}\n", "        shell : sh\n"):
                with self.subTest(anchor=anchor, shell=shell):
                    self.assertTrue(_c8_mutant_problems(self.c8, anchor, anchor + shell))

    def test_6388_job_defaults_shell_is_killed(self) -> None:
        mutant = '    defaults:\n      run:\n        shell: "true {0}"\n' + self.JOB_PERMISSIONS
        self.assertTrue(_c8_mutant_problems(self.c8, self.JOB_PERMISSIONS, mutant))

    def test_6388_workflow_defaults_shell_is_killed(self) -> None:
        mutant = 'defaults:\n  run:\n    shell: "true {0}"\n\njobs:\n'
        self.assertTrue(_c8_mutant_problems(self.c8, "\njobs:\n", "\n" + mutant))



class ApprovalJobSpacedKeys6387(unittest.TestCase):
    """The approval job's own keys are exactly name, runs-on, timeout-minutes, permissions, steps."""

    ANCHOR = "    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    # #3591"

    def setUp(self) -> None:
        self.c8 = C8_WORKFLOW.read_text(encoding="utf-8")

    def test_6387_live_job_is_intact(self) -> None:
        self.assertEqual([], _approval_job_problems(self.c8))

    def test_6387_spaced_and_extra_job_keys_are_killed(self) -> None:
        for row in ("    if : github.event_name == 'workflow_dispatch'\n",
                    "    needs : [c8-precheck]\n",
                    "    continue-on-error : true\n",
                    "    environment : release\n"):
            with self.subTest(row=row):
                self.assertTrue(_c8_mutant_problems(self.c8, self.ANCHOR, row + self.ANCHOR))



class WorkflowPythonOptionIsolation6389(unittest.TestCase):
    """Every `python3 <options> <x>.py` in a workflow has -I among its options, quoted paths included."""

    SITE = re.compile(r"python3 -I (scripts/[^\s\"']+\.py)")

    def ci_findings(self, ci: str) -> List[str]:
        texts = _all_workflow_texts()
        texts["ci.yml"] = ci
        return [f for f in _bare_python_script_runs(texts) if f.startswith("ci.yml:")]

    def test_6389_single_site_non_isolating_option_is_killed(self) -> None:
        ci = _all_workflow_texts()["ci.yml"]
        self.assertTrue(self.SITE.search(ci))
        for option in ("-u", "-B", "-O", "-X dev", "-W error"):
            with self.subTest(option=option):
                self.assertTrue(self.ci_findings(self.SITE.sub(rf"python3 {option} \1", ci, count=1)))

    def test_6389_single_site_quoted_path_is_killed(self) -> None:
        ci = _all_workflow_texts()["ci.yml"]
        for replacement in (r'python3 "\1"', r"python3 '\1'", r'python3 -u "\1"'):
            with self.subTest(replacement=replacement):
                self.assertTrue(self.ci_findings(self.SITE.sub(replacement, ci, count=1)))

    def test_6389_isolated_or_non_script_forms_are_not_flagged(self) -> None:
        for run in ('python3 -u -I "scripts/x.py"', "python3 -IB scripts/x.py", "python3 -I 'scripts/x.py' --self-test",
                    'python3 -c "import sys"', "python3 -m pip install x", "python3 --version",
                    'echo "$(python3 --version)"', "command -v python3 >/dev/null"):
            with self.subTest(run=run):
                texts = {"new.yml": f"jobs:\n  x:\n    steps:\n      - run: {run}\n"}
                self.assertEqual([], _bare_python_script_runs(texts))



# ---- Round 5 (#6390, #6392, #6393, #6394, #6395): the evaluator's guards are pinned ----

# Synthetic, non-repeating token bodies (never real credentials).
_TOKEN_ALPHABET = string.ascii_letters + string.digits


def _token_body(length: int, offset: int = 0) -> str:
    return "".join(_TOKEN_ALPHABET[(offset + 7 * i) % len(_TOKEN_ALPHABET)] for i in range(length))


def _leaked_windows(secret: str, text: str, width: int = 8) -> List[str]:
    """Every ``width``-character window of ``secret`` that appears in ``text``."""
    return [secret[i:i + width] for i in range(len(secret) - width + 1) if secret[i:i + width] in text]


class TokenRedactionAlphabet6390(unittest.TestCase):
    """Every GitHub token prefix is redacted whole: no 8-character window of its secret part survives."""

    def setUp(self) -> None:
        self.mod = _load_approval()

    def relayed(self, token: str) -> str:
        def api(path: str):
            raise self.mod.GateError("HTTP 401 for " + token + " (end)")
        _rc, lines = self.mod.run_gate("push", {}, REPO_6117, SHA_A, OPERATOR_6117, api)
        return "\n".join(lines)

    def test_6390_every_classic_prefix_is_redacted(self) -> None:
        for n, prefix in enumerate(("ghp_", "gho_", "ghu_", "ghs_", "ghr_")):
            body = _token_body(36, n)
            with self.subTest(prefix=prefix):
                text = self.relayed(prefix + body)
                self.assertEqual([], _leaked_windows(body, text), text)
                self.assertIn("[redacted]", text)

    def test_6390_fine_grained_pat_tail_is_redacted(self) -> None:
        secret = _token_body(22, 3) + "_" + _token_body(59, 11)
        text = self.relayed("github_pat_" + secret)
        self.assertEqual([], _leaked_windows(secret, text), text)
        self.assertEqual([], _leaked_windows(secret[23:], text), text)  # the 59-character tail on its own

    def test_6390_twenty_character_body_is_the_lower_bound(self) -> None:
        for prefix in ("ghp_", "ghs_"):
            body = _token_body(20, 5)
            with self.subTest(prefix=prefix):
                self.assertEqual([], _leaked_windows(body, self.relayed(prefix + body)))

if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False, verbosity=1).result.wasSuccessful() else 1)
