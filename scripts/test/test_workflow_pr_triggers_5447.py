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

RULES ENFORCED (all closed-world: a trigger the reader cannot parse is a FAILURE):
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
  R-SHAPE (#5660, #5667, #5668, #5705-#5708) the whole file is read closed-world:
         each line must be blank, a comment, a block scalar content line, one
         leading ``---``, or a mapping-key row or sequence entry whose quoted
         scalars and flow collections close on that row, with no backslash in
         a double-quoted and no doubled quote in a single-quoted scalar.  Any
         other line fails, and so do a lone CR, another line-break character,
         a control character or inner BOM, a repeated top-level key and a
         top-level YAML 1.1 boolean key other than ``on`` (bare or quoted).
         Under ``on:`` a ``pull_request`` / ``push`` trigger fails when it
         does not use only the keys branches, tags, paths, paths-ignore,
         types; ``branches`` must be an
         inline list or a block list.  Anything else (branches-ignore, scalar
         ``on:`` forms, flow-style ``on:``, an unterminated list) fails.

The reader is the Python standard library only (no PyYAML) so it runs on any CI
image.  The mutation legs at the bottom prove the reader is not vacuous: each
mutant of the LIVE workflow files must be rejected, and the unmutated control
must be accepted first.

Run:  python3 scripts/test/test_workflow_pr_triggers_5447.py
"""
from __future__ import annotations

import re
import sys
import unicodedata
import unittest
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

CARRIER = "rehearsal/audit-wip"
CARRIER_PATTERN = "rehearsal/**"
GATED_BASES = ("main", "develop", "release/v1.0.0")
PR_TRIGGERS = ("pull_request", "pull_request_target")
KNOWN_FILTER_KEYS = ("branches", "tags", "paths", "paths-ignore", "types")


class Unparsed(Exception):
    """Raised when the reader cannot interpret a trigger (a FAILURE, never a skip)."""


def _strip_comment(line: str) -> str:
    """Drop a trailing comment and trailing whitespace (one row at a time)."""
    out: List[str] = []
    quote: Optional[str] = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            break
        out.append(ch)
    return "".join(out).rstrip()


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _unquote(item: str) -> str:
    item = item.strip()
    if len(item) >= 2 and item[0] == item[-1] and item[0] in ("'", '"'):
        return item[1:-1]
    return item


def _parse_inline_list(text: str) -> List[str]:
    text = text.strip()
    if not (text.startswith("[") and text.endswith("]")):
        raise Unparsed("unterminated or non-list flow value: " + text)
    inner = text[1:-1].strip()
    if not inner:
        return []
    pieces = [p.strip() for p in inner.split(",") if p.strip()]
    for piece in pieces:
        if piece[0] in ("'", '"') and not (len(piece) >= 2 and piece[-1] == piece[0]):
            raise Unparsed("quoted flow item with an embedded comma or quote: " + piece)
        if piece[-1] in ("'", '"') and piece[0] != piece[-1]:
            raise Unparsed("unbalanced quote in flow item: " + piece)
    return [_unquote(p) for p in pieces]


# Line-break and separator characters other than LF and CR. PyYAML 6 reads NEL,
# U+2028 and U+2029 as line breaks and refuses the other six as non-printable;
# the reader refuses all nine (#5707).
_EXOTIC_BREAKS = "\x0b\x0c\x1c\x1d\x1e\x1f\x85  "
# Control characters, noncharacters, and a BOM anywhere but the stream start.
_FORBIDDEN = re.compile("[\x00-\x08\x0e-\x1f\x7f-\x9f﻿￾￿]")
# Characters that start an anchor, alias, tag or reserved token.
_NODE_PROPERTY = "&*!%@`"
# Characters that may stand directly before a quoted scalar inside a flow collection.
_FLOW_OPENERS = ("", "[", "{", ",", ":")


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


def _flow_end(s: str, i: int) -> int:
    """Index just past the flow collection that opens at s[i]; it must close on its row."""
    depth = 0
    prev = ""
    j = i
    while j < len(s):
        ch = s[j]
        if ch in "'\"":
            if prev not in _FLOW_OPENERS:
                raise Unparsed("quote inside a plain flow scalar: " + repr(s))
            j = _quoted_end(s, j)
            prev = ch
            continue
        if ch == "#" and s[j - 1] == " ":
            break
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
            if depth == 0:
                return j + 1
        if ch != " ":
            prev = ch
        j += 1
    raise Unparsed("flow collection does not close on its row: " + repr(s))


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
        return _tail(s, _flow_end(s, i), "a flow collection"), False
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


def _scan_row(rest: str) -> Tuple[str, str, int, bool]:
    """Positive rules for one structure row (text after its ASCII-space indentation).

    Returns (row text without comment, mapping key or '', column offset of the node
    that owns a block scalar, opens-a-block-scalar). A row is accepted only as a
    mapping key row or a sequence entry, each optionally after ``- `` prefixes;
    anything else is Unparsed.
    """
    i = 0
    dash = -1
    while rest.startswith("-", i) and rest[i + 1:i + 2] in ("", " "):
        dash = i
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
            return body, rest[i:end], i, header
    elif i < len(rest) and rest[i] not in "[{|>,]}#?:" + _NODE_PROPERTY:
        colon = _plain_key_colon(rest, i)
        if colon >= 0:
            key = rest[i:colon].rstrip(" ")
            if key == "<<":
                raise Unparsed("merge key: " + repr(rest))
            body, header = _value(rest, colon + 1)
            return body, key, i, header
    if dash < 0:
        raise Unparsed("row is neither a mapping key, a sequence entry nor a comment: " + repr(rest))
    body, header = _value(rest, i)
    return body, "", dash, header


def _meaningful(text: str) -> List[Tuple[int, str, str]]:
    """(indent, row text, mapping key or '') per structure row; closed world (#5660, #5705).

    Every line must be accepted by a positive rule: a blank line, a comment line, a
    content line of a block scalar (indented past its owner, no whitespace other
    than ASCII space before its first character), a column-0 ``---`` or ``...``
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
    for raw in text.split("\n"):
        if raw.endswith("\r"):
            raw = raw[:-1]
        ind = _indent(raw)
        rest = raw[ind:]
        if owner is not None:
            if not rest:
                continue
            if ind > owner:
                if _space_like(rest[0]):
                    raise Unparsed("block scalar line starts with non-space whitespace: " + repr(raw))
                if content is None:
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
        body, key, node, header = _scan_row(rest)
        rows.append((ind, body, key))
        if header:
            owner, content = ind + node, None
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
    head = rows[start][1][len(on_key):].lstrip(" ")[1:].strip()
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
        ind, body = block[i]
        if ind != trig_indent:
            raise Unparsed("unexpected indentation in on: block: " + body)
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*) *:(?: +(.*))?$", body)
        if not m:
            raise Unparsed("unreadable trigger line: " + body)
        name, rest = m.group(1), (m.group(2) or "").strip()
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


def _parse_filters(trigger: str, sub: List[Tuple[int, str]]) -> Dict[str, List[str]]:
    filters: Dict[str, List[str]] = {}
    if not sub:
        return filters
    key_indent = sub[0][0]
    seen_keys: Set[str] = set()
    k = 0
    while k < len(sub):
        ind, body = sub[k]
        if ind != key_indent:
            raise Unparsed(trigger + ": unexpected indentation: " + body)
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*) *:(?: +(.*))?$", body)
        if not m:
            raise Unparsed(trigger + ": unreadable filter line: " + body)
        key, rest = m.group(1), (m.group(2) or "").strip()
        if key.lower() in seen_keys:
            raise Unparsed(trigger + ": repeated filter key (#5666): " + key)
        seen_keys.add(key.lower())
        if key not in KNOWN_FILTER_KEYS:
            raise Unparsed(trigger + ": unsupported filter key: " + key)
        n = k + 1
        items: List[str] = []
        while n < len(sub) and sub[n][0] > key_indent:
            line = sub[n][1]
            if not line.startswith("- ") and line != "-":
                raise Unparsed(trigger + "." + key + ": non-list item: " + line)
            items.append(_unquote(line[1:].strip()))
            n += 1
        if rest:
            if items:
                raise Unparsed(trigger + "." + key + ": mixed inline and block list")
            if key == "types" and not rest.startswith("["):
                word = _unquote(rest)
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", word):
                    raise Unparsed(trigger + ".types: scalar is not one plain word (#5669): " + rest)
                items = [word]
            else:
                items = _parse_inline_list(rest)
        filters[key] = items
        k = n
    return filters


def glob_match(pattern: str, ref: str) -> bool:
    """GitHub Actions filter glob: ** crosses '/', * does not, ? is one non-/ char."""
    regex: List[str] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if pattern[i:i + 2] == "**":
                regex.append(".*")
                i += 2
                continue
            regex.append("[^/]*")
        elif ch == "?":
            regex.append("[^/]")
        elif ch == "[":
            end = pattern.find("]", i + 1)
            if end == -1:
                raise Unparsed("unterminated character class: " + pattern)
            regex.append(pattern[i:end + 1])
            i = end + 1
            continue
        else:
            regex.append(re.escape(ch))
        i += 1
    return re.fullmatch("".join(regex), ref) is not None


def filter_matches(patterns: List[str], ref: str) -> bool:
    """Ordered include/exclude evaluation; a leading '!' negates (last match wins)."""
    matched = False
    for pat in patterns:
        if pat.startswith("!"):
            if glob_match(pat[1:], ref):
                matched = False
        elif glob_match(pat, ref):
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
    if "rehearsal" in pat:
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
    for ch in REHEARSAL_PREFIX:
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
    # ref and stars match empty, so some ref under rehearsal/ matches.
    return bool(states) or glob_match(pat, REHEARSAL_BRANCH)


def violations(name: str, text: str) -> List[str]:
    """Every rule violation for one workflow file's text (empty list = clean)."""
    try:
        triggers = parse_triggers(text)
    except Unparsed as exc:
        # Closed-world: only a workflow that does not mention a PR/push trigger at
        # all may be unparseable; otherwise the reader failing is itself a failure.
        if re.search(r"\b(pull_request|pull_request_target|push)\b", text):
            return [f"{name}: R-SHAPE cannot parse triggers ({exc})"]
        return []
    found: List[str] = []
    for trig in PR_TRIGGERS:
        if trig not in triggers:
            continue
        flt = triggers[trig]
        if "branches" not in flt:
            continue  # no base filter: matches every base, carrier included
        branches = flt["branches"]
        gates = any(filter_matches(branches, base) for base in GATED_BASES)
        if gates:
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
    return found


def load_all() -> Dict[str, str]:
    files = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    return {p.name: p.read_text(encoding="utf-8") for p in files}


def _replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) < 1:
        raise AssertionError("mutation anchor not found: " + old)
    return text.replace(old, new, 1)


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
        t = self.live["c8-precheck.yml"]
        m = re.sub(
            r'(pull_request:\s*\n\s*branches: \[[^\]]*?)\]', r'\1, "!rehearsal/audit-wip"]', t, count=1
        )
        self.assertNotEqual(t, m)
        self._assert_killed("c8-precheck.yml", m, "R-PR")

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
        # Without the lone-CR rule the CR-separated trigger vanishes into a comment.
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
        self._red("[main, !!str rehearsal/landing]")
        self._red("[main, *prb]")
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
        self._shape(base + "    echo a\n    \techo hi\n", "block scalar line starts with non-space")
        self._shape(base + "    \u00a0echo hi\n", "block scalar line starts with non-space")

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


class GlobSemantics5447(unittest.TestCase):
    def test_5447_glob_rules(self) -> None:
        self.assertTrue(glob_match("rehearsal/**", CARRIER))
        self.assertTrue(glob_match("release/**", "release/v1.0.0"))
        self.assertFalse(glob_match("release/**", CARRIER))
        self.assertFalse(glob_match("rehearsal/*", "rehearsal/a/b"))
        self.assertTrue(glob_match("rehearsal/*", CARRIER))
        self.assertTrue(filter_matches(["rehearsal/**", "!rehearsal/audit-wip"], "rehearsal/x") )
        self.assertFalse(filter_matches(["rehearsal/**", "!rehearsal/audit-wip"], CARRIER))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False, verbosity=1).result.wasSuccessful() else 1)
