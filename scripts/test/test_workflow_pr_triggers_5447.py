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
  R-SHAPE (#5660) a tab, NBSP, form feed or BOM-led line, a lone CR or a YAML 1.1
         line-break character inside the ``on:`` block fails; so does a
         ``pull_request`` / ``push`` trigger that does not use only the keys
         branches, tags, paths, paths-ignore, types; ``branches`` must be an
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


# Characters YAML 1.1 parsers treat as a line break besides LF/CR (PyYAML does).
_EXOTIC_BREAKS = "\x0b\x0c\x1c\x1d\x1e\x1f\x85\u2028\u2029"


def _suspect(raw: str, line: str) -> str:
    """Reason a non-blank line cannot be trusted to keep its column, else ''."""
    lead = raw[: len(raw) - len(raw.lstrip())]
    if any(ch != " " for ch in lead):
        return "non-space leading whitespace"
    first = line.lstrip()[:1]
    if first and not (" " < first <= "~"):
        return "non-ASCII or control first character"
    return ""


def _meaningful(text: str) -> List[Tuple[int, str, str]]:
    """(indent, body, suspect) per non-blank, non-comment line (#5660)."""
    if re.search(r"\r(?!\n)", text):
        raise Unparsed("lone carriage return line break")
    if any(ch in _EXOTIC_BREAKS for ch in text):
        raise Unparsed("YAML 1.1 line-break character (form feed, NEL, U+2028/9, ...)")
    rows: List[Tuple[int, str, str]] = []
    for raw in text.split("\n"):
        line = _strip_comment(raw)
        if line.strip():
            rows.append((_indent(line), line.strip(), _suspect(raw, line)))
    return rows


TOP_KEY = re.compile(r"""^("[^"\\]*"|'[^']*'|[A-Za-z_][A-Za-z0-9_-]*)\s*:(\s|$)""")
ON_SPELLINGS = ("on", "true", "yes")  # all resolve to the boolean True key (YAML 1.1)


def _refuse_repeated_top_level(rows: List[Tuple[int, str, str]]) -> None:
    """A top-level key may appear once (#5667); a YAML reader would keep the last."""
    seen: Set[str] = set()
    for ind, body, _sus in rows:
        if ind != 0:
            continue
        m = TOP_KEY.match(body)
        if not m:
            continue
        key = m.group(1).strip("\"'").lower()
        if key in ON_SPELLINGS:
            key = "on"
        if key in seen:
            raise Unparsed("repeated top-level key (#5667): " + body)
        seen.add(key)


def parse_triggers(text: str) -> Dict[str, Dict[str, List[str]]]:
    """Return {trigger: {filter_key: [items]}} for the workflow's ``on:`` block."""
    rows = _meaningful(text)
    _refuse_repeated_top_level(rows)
    start = None
    for idx, (ind, body, _sus) in enumerate(rows):
        if ind == 0 and re.match(r"""^("on"|'on'|on|true)\s*:""", body):
            start = idx
            break
    if start is None:
        raise Unparsed("no top-level on: block")
    head = re.match(r"""^("on"|'on'|on|true)\s*:\s*(.*)$""", rows[start][1])
    assert head is not None
    if head.group(2).strip():
        raise Unparsed("flow/scalar on: form: " + head.group(2).strip())
    block: List[Tuple[int, str]] = []
    for ind, body, sus in rows[start + 1:]:
        if sus:
            # Includes the line that would otherwise silently END the block (#5660).
            raise Unparsed("on: block line is untrustworthy (" + sus + "): " + repr(body))
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
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$", body)
        if not m:
            raise Unparsed("unreadable trigger line: " + body)
        name, rest = m.group(1), m.group(2).strip()
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
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(.*)$", body)
        if not m:
            raise Unparsed(trigger + ": unreadable filter line: " + body)
        key, rest = m.group(1), m.group(2).strip()
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
                items = [_unquote(rest)]
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

    def test_5660_tab_in_later_block_scalar_is_not_inspected(self) -> None:
        text = _with_on_block(GOOD_PUSH + GOOD_PR) + "x:\n  run: |\n\t\techo hi\n"
        self.assertEqual([], violations("x.yml", text))


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
    """#5667: a repeated top-level key (any quoting or case; on/true/yes are one key) is Unparsed."""

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
