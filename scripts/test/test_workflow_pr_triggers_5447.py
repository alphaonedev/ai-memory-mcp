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
image.  It lives in scripts/workflow_yaml_subset.py (moved unchanged, #6481) and is
shared with scripts/check_carrier_ruleset_live.py.  The mutation legs at the bottom prove the reader is not vacuous: each
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

import importlib.util
import re
import string
import sys
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


# The reader (Unparsed .. _check_top_level) lives in scripts/workflow_yaml_subset.py (#6481)
# and is shared with scripts/check_carrier_ruleset_live.py; its behaviour is unchanged.


def _load_subset():
    """Load scripts/workflow_yaml_subset.py by path (works under ``python3 -I``)."""
    path = ROOT / "scripts" / "workflow_yaml_subset.py"
    spec = importlib.util.spec_from_file_location("workflow_yaml_subset", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["workflow_yaml_subset"] = module
    spec.loader.exec_module(module)
    return module


_SUBSET = _load_subset()
(Unparsed, _strip_comment, _indent, _unquote, _parse_inline_list, _Plain, _typed_plain, _space_like,
 _quoted_end, _tail, _flow_space, _flow_plain, _flow_node, _flow, _value, _plain_key_colon, _opens_block,
 _scan_row, _nest, _meaningful, _check_top_level, TOP_KEY, YAML11_BOOLEANS, ON_KEYS, _EXOTIC_BREAKS,
 _NONCHARACTERS, _FORBIDDEN, _NODE_PROPERTY, _FLOW_STOPS, _NUMERIC_PLAIN) = (
    getattr(_SUBSET, _n) for _n in (
        "Unparsed", "_strip_comment", "_indent", "_unquote", "_parse_inline_list", "_Plain", "_typed_plain",
        "_space_like", "_quoted_end", "_tail", "_flow_space", "_flow_plain", "_flow_node", "_flow", "_value",
        "_plain_key_colon", "_opens_block", "_scan_row", "_nest", "_meaningful", "_check_top_level", "TOP_KEY",
        "YAML11_BOOLEANS", "ON_KEYS", "_EXOTIC_BREAKS", "_NONCHARACTERS", "_FORBIDDEN", "_NODE_PROPERTY",
        "_FLOW_STOPS", "_NUMERIC_PLAIN"))

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
        # Closed world (#5731): a file the reader cannot read is a failure, whatever
        # words its raw text holds; an escaped key spells a trigger with none of them.
        return [f"{name}: R-SHAPE cannot parse triggers ({exc})"]
    try:
        return _rule_violations(name, triggers)
    except Unparsed as exc:
        # A filter item the glob reader cannot read (a [ class, a ! negation, an
        # empty item, or any character or construct outside the modelled set) is
        # a named failure too, not an exception out of violations() (#5777,
        # #5853, #5854, #5943, #5968).
        return [f"{name}: R-SHAPE cannot match filters ({exc})"]


def _rule_violations(name: str, triggers: Dict[str, Dict[str, List[str]]]) -> List[str]:
    """R-PR and R-PUSH violations for one file's parsed triggers."""
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


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False, verbosity=1).result.wasSuccessful() else 1)
