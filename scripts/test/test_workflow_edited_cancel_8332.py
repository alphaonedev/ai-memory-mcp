#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""A body-only PR edit never cancels or restarts a required check (#8332).

Defect: ci.yml, coverage.yml and claude-md-rule-compare.yml listed ``edited`` in
their pull_request(_target) types and set ``cancel-in-progress`` for pull_request
runs, so every PR title or body edit cancelled the running required checks and
started them again from zero.

The rules this guard pins (a ratchet over EVERY workflow):

1. No workflow lists ``edited`` under a ``pull_request`` or ``pull_request_target``
   trigger, in ANY YAML form (inline ``types: [..]``, a block sequence ``- edited``, or a
   flow-mapping ``on: {pull_request: {types: [..]}}``), except claude-md-rule-compare.yml
   (a one-entry allow-list; its ``cancel-in-progress`` guard is pinned by rule 2). The
   scan is stdlib only (PyYAML is not installed on every runner and no other workflow
   test imports it): ONE quote-aware scanner (``_Scanner``) reads every line, carrying the
   quote, flow-depth and block-scalar state across lines, and it fails closed: a workflow
   whose ``on:`` section it cannot fully account for (no or a second ``on`` key, an anchor,
   alias or tag, an open quote or flow, an early-closing flow, an unrecognised line, a
   column-0 line after the section that is not a workflow key) is refused by name, and any
   ``edited`` word inside a pull_request(_target) trigger body counts as listed. The
   ``ORACLE`` table pins every shape from rounds 3-6; where PyYAML is importable a
   differential test checks the table against it.
2. Where ``edited`` is listed, every ``cancel-in-progress`` key at ANY indent (a
   job-level concurrency block too) is the literal ``false``, the guard
   ``${{ github.event_name == 'pull_request' }}``, the body-only guard
   ``${{ github.event.action != 'edited' }}``, or one of those guards joined by ``&&``
   to another clause. An ``||`` form is rejected. A workflow with a pull_request(_target)
   trigger and a concurrency block without the key is a violation.
3. The only ``pull_request_target`` workflow is claude-md-rule-compare.yml. A second one
   is a failure: no ``pull_request_target`` workflow has ever run in this repository
   (#8337), so a new one would never fire before it lands on the default branch.
4. A base retarget (#7072) is landed only after a new head push, checked at landing by
   scripts/ci/pr_retarget_check.py (tested by test_pr_retarget_check_8332.py).

Stdlib only. Run: ``python3 -I scripts/test/test_workflow_edited_cancel_8332.py``.
"""
import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
SCRATCH = ROOT / ".local-runs"
WF = ROOT / ".github" / "workflows"
NO_EDITED = ("ci.yml", "coverage.yml")
EDITED_ALLOW = {"claude-md-rule-compare.yml"}
TARGET_ALLOW = {"claude-md-rule-compare.yml"}
ACCEPTED_GUARDS = (
    "github.event_name == 'pull_request'",
    "github.event.action != 'edited'",
)
KINDS = ("pull_request", "pull_request_target")
ACTIVITY_TYPES = {"assigned", "unassigned", "labeled", "unlabeled", "opened", "edited", "closed", "reopened",
                  "synchronize", "converted_to_draft", "locked", "unlocked", "enqueued", "dequeued",
                  "milestoned", "demilestoned", "ready_for_review", "review_requested",
                  "review_request_removed", "auto_merge_enabled", "auto_merge_disabled"}
ON_KEY_RE = re.compile(r"""^(?:on|"on"|'on')[ \t]*:(?:[ \t]+(.*))?$""")
TOP_KEY_RE = re.compile(r"""^(["']?)(?:name|run-name|on|permissions|env|defaults|concurrency|jobs)\1[ \t]*:(?:[ \t]|$)""")
ANCHOR_RE = re.compile(r"(?:^|[\s\[{,:])[&*!][A-Za-z_!<]|<<\s*:|(?:^|[\s\[{,])\?(?:\s|$)")
BLOCK_SCALAR_RE = re.compile(r"(?:^[ \t]*|:[ \t]+|(?:^|[ \t])-[ \t]+)[|>][1-9+-]*$")
CANCEL_RE = re.compile(r"^[ \t]*cancel-in-progress:[ \t]*(.*?)[ \t]*$", re.M)
CONCURRENCY_RE = re.compile(r"^[ \t]*concurrency:", re.M)
WORD_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


class ParseFailure(Exception):
    """The workflow trigger section cannot be read; the caller fails closed."""


class Line(NamedTuple):
    """One scanned line: comments cut, quoted and block-scalar text reduced to words (see ``scan``)."""

    text: str  # structure text; inside quotes only word characters survive (others become spaces)
    cont: bool  # starts inside a quoted scalar or is block-scalar content: never a key line
    depth: int  # flow-collection depth BEFORE this line


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _words(raw: str) -> str:
    """Block-scalar content: keep the indent and the word characters only (no brackets, colons or quotes)."""
    body = raw.lstrip(" ")
    return " " * (len(raw) - len(body)) + "".join(c if c in WORD_CHARS else " " for c in body)


class _Scanner:
    """The ONE quote-aware, stateful YAML line scanner of this guard (round 6).

    decision (round 6, REVIEW-8332-security-r5 S9/S10, REVIEW-8332-code-r5 F1): rounds 3, 4 and 5 each
    failed open on a new shape (quoted keys, quoted brackets, then a quoted space-# and an apostrophe in
    a plain scalar) because comments, quotes and brackets were handled by separate per-line regexes. One
    scanner now walks every character once, carrying the quote state, the flow depth and the block-scalar
    state across lines. A quoted scalar opens only at a scalar start (line start, after ``[ { ,``, after
    ``:``/``-``/``?`` followed by whitespace), as in YAML; ``''`` and backslash escapes are honoured; a ``#``
    starts a comment only outside quotes and after whitespace or at line start; flow brackets count only
    in flow context or at a scalar start (``${{ }}`` in a plain scalar is text); a ``|``/``>`` block scalar's
    lines are reduced to words. An open quote or an open flow collection at the end of the file is a
    ParseFailure.
    """

    def __init__(self):
        self.quote = ""
        self.depth = 0
        self.block = -1  # indent of the line that opened a block scalar, or -1

    def _quoted(self, raw: str, i: int, out: list) -> int:
        """Consume one character inside a quoted scalar; return the next index."""
        c = raw[i]
        if self.quote == '"' and c == "\\":
            out.append("  " if i + 1 < len(raw) else " ")
            return i + 2
        if c == self.quote:
            if self.quote == "'" and raw[i + 1:i + 2] == "'":
                out.append("  ")
                return i + 2
            self.quote = ""
            out.append(c)
            return i + 1
        out.append(c if c in WORD_CHARS else " ")
        return i + 1

    def _plain(self, raw: str, i: int, out: list, start: bool) -> bool:
        """Account for one character outside quotes; return the new scalar-start state."""
        c, nxt = raw[i], raw[i + 1:i + 2]
        out.append(c)
        if c in "\"'" and start:
            self.quote = c
            return False
        if c in "[{" and (start or self.depth):
            self.depth += 1
            return True
        if c in "]}" and self.depth:
            self.depth -= 1
            return False
        if c == "," and self.depth:
            return True
        if c in "-?":
            return start and nxt in ("", " ", "\t")
        if c == ":":  # a key separator; a JSON-like "key":"value" in flow opens the value at once
            return nxt in ("", " ", "\t") or (raw[i - 1] in "\"'" and nxt in ("\"", "'"))
        return start if c in " \t" else False

    def line(self, raw: str) -> Line:
        """Scan one raw line and return its Line record."""
        depth, cont = self.depth, bool(self.quote)
        if self.block >= 0 and (not raw.strip() or _indent(raw) > self.block):
            return Line(_words(raw), True, depth)
        self.block = -1
        out, i, start = [], 0, not cont
        while i < len(raw):
            if self.quote:
                i = self._quoted(raw, i, out)
                continue
            if raw[i] == "#" and (i == 0 or raw[i - 1] in " \t"):
                break
            start = self._plain(raw, i, out, start)
            i += 1
        text = "".join(out).rstrip()
        if not self.quote and not self.depth and BLOCK_SCALAR_RE.search(text):
            self.block = _indent(raw)
        return Line(text, cont, depth)


def scan(text: str) -> list:
    """Every line of a workflow as a Line; ParseFailure on a quote or flow still open at the end."""
    sc = _Scanner()
    lines = []
    for raw in text.splitlines():
        lines.append(sc.line(raw))
    if sc.quote:
        raise ParseFailure("unterminated quoted scalar")
    if sc.depth:
        raise ParseFailure("unclosed flow collection; the `on:` section cannot be bounded")
    return lines


def _on_section(lines: list):
    """Locate the one top-level ``on:`` key: (its inline value, its section lines).

    The section runs to the next line at column 0 outside any flow collection and quoted scalar.
    decision (round 6, REVIEW-8332-security-r5 S10): that next column-0 line must be a top-level
    workflow key; anything else means the scanner lost track of the ``on:`` section, so the file is
    refused by name rather than read short. A second top-level ``on:`` is refused too.
    """
    keys = [i for i, ln in enumerate(lines) if not ln.cont and not ln.depth and ON_KEY_RE.match(ln.text)]
    if not keys:
        raise ParseFailure("no top-level `on:` key")
    if len(keys) > 1:
        raise ParseFailure("more than one top-level `on:` key")
    start = keys[0]
    end = start + 1
    while end < len(lines):
        ln = lines[end]
        if ln.text.strip() and not ln.cont and not ln.depth and not ln.text[0].isspace():
            if not TOP_KEY_RE.match(ln.text):
                raise ParseFailure(f"line {end + 1} at column 0 after the `on:` section is not a top-level key")
            break
        end += 1
    rest = (ON_KEY_RE.match(lines[start].text).group(1) or "").strip()
    return rest, [ln for ln in lines[start + 1:end] if ln.text.strip()]


def _flow_body(rest: str, section: list) -> str:
    """The whole flow collection of the ``on:`` section; it must close on the section's last line."""
    tail = section if rest else section[1:]
    if any(not ln.depth for ln in tail):
        raise ParseFailure("flow collection ended before the `on:` section did (unread lines)")
    return "\n".join(([rest] if rest else []) + [ln.text for ln in section])


def _block_triggers(section: list) -> dict:
    """Map each pull_request(_target) key of a block-form ``on:`` section to its body text."""
    out, current = {}, None
    child = _indent(section[0].text)
    for ln in section:
        x, ind = ln.text, _indent(ln.text)
        if ln.cont or ln.depth or ind > child:
            if current in KINDS:
                out[current] += "\n" + x
            continue
        m = re.match(rf"""^ {{{child}}}(?:-[ \t]+)?(["']?)([\w-]+)\1[ \t]*:(?:[ \t]+(.*))?$""", x)
        seq = re.match(rf"""^ {{{child}}}-[ \t]+(["']?)([\w-]+)\1$""", x)
        if ind < child or not (m or seq):
            raise ParseFailure(f"unrecognised line in the `on:` section: {x.strip()[:40]!r}")
        current = (m or seq).group(2)
        if current in KINDS:
            out[current] = (m.group(3) or "") if m else ""
    return out


def triggers(text: str) -> dict:
    """Map each pull_request(_target) trigger found in ``on:`` to its body text.

    Raises ParseFailure (the caller fails closed) for anything the scanner cannot account for: no or a
    second ``on:`` key, an anchor, alias, tag or explicit key, an open quote or flow, a flow that closes
    early, a scalar ``on:`` value with more lines under it, an unrecognised trigger-level line, or a
    column-0 line after the section that is not a workflow key.
    """
    rest, section = _on_section(scan(text))
    if ANCHOR_RE.search("\n".join([rest] + [ln.text for ln in section])):
        raise ParseFailure("anchor, alias, tag or explicit key in the `on:` section")
    first = rest or (section[0].text.strip() if section else "")
    if first[:1] in ("{", "["):
        body = _flow_body(rest, section)
    elif rest:
        if section:
            raise ParseFailure("scalar `on:` value followed by more lines")
        body = rest
    elif section:
        return _block_triggers(section)
    else:
        raise ParseFailure("empty `on:` section")
    return {kind: body for kind in KINDS if re.search(rf"""(?<![\w-]){kind}(?![\w-])""", body)}


def pr_types(text: str, kinds=KINDS) -> set:
    """Activity types named in the body of every listed pull_request(_target) trigger.

    Over-approximates (any activity word in the body, whatever the YAML form): fail closed.
    """
    out = set()
    for kind, body in triggers(text).items():
        if kind in kinds and re.search(r"\btypes\b", body):
            out |= set(re.findall(r"[a-z_]+", body.lower())) & ACTIVITY_TYPES
    return out


def has_trigger(text: str, kind: str) -> bool:
    return kind in triggers(text)


def guard_ok(value: str) -> bool:
    """True for literal false, an accepted guard, or an accepted guard joined by &&."""
    value = value.split(" #")[0].strip()
    if value == "false":
        return True
    m = re.fullmatch(r"\$\{\{(.*)\}\}", value)
    if m is None:
        return False
    expr = m.group(1).strip()
    if "||" in expr:
        return False
    return any(clause.strip() in ACCEPTED_GUARDS for clause in expr.split("&&"))


def cancel_violations(name: str, text: str) -> list:
    """Problems for one workflow file's text (empty list = compliant)."""
    try:
        triggered = bool(triggers(text))
    except ParseFailure as exc:
        return [f"{name}: cannot parse the trigger section ({exc}); failing closed"]
    if not triggered:
        return []
    problems = []
    keys = CANCEL_RE.findall(text)
    if len(CONCURRENCY_RE.findall(text)) > len(keys):
        problems.append(f"{name}: a concurrency block has no cancel-in-progress key")
    if "edited" in pr_types(text):
        for value in keys:
            if not guard_ok(value):
                problems.append(f"{name}: lists `edited` with cancel-in-progress `{value}` and no accepted guard")
    return problems


def edited_listed(name: str, text: str) -> list:
    try:
        listed = "edited" in pr_types(text)
    except ParseFailure as exc:
        return [f"{name}: cannot parse the trigger section ({exc}); failing closed"]
    if listed and name not in EDITED_ALLOW:
        return [f"{name}: lists `edited` under pull_request(_target) types (#8332)"]
    return []


def target_extras(texts: dict) -> list:
    extra, broken = [], []
    for n, t in sorted(texts.items()):
        try:
            if has_trigger(t, "pull_request_target") and n not in TARGET_ALLOW:
                extra.append(n)
        except ParseFailure as exc:
            broken.append(f"{n}: cannot parse the trigger section ({exc}); failing closed")
    return broken + [f"{n}: second pull_request_target workflow; none has ever run in this repository (#8337)"
                     for n in extra]


def _all(directory=WF):
    """Every workflow text, ``*.yml`` and ``*.yaml`` (GitHub reads both; test_workflow_pr_triggers_5447 too)."""
    paths = sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml")))
    return {p.name: p.read_text(encoding="utf-8") for p in paths}


BASE_BAD = (
    "on:\n  pull_request:\n    types: [opened, synchronize, reopened, edited]\n"
    "concurrency:\n  group: g\n  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n"
)


class BodyOnlyEditNeverCancels8332(unittest.TestCase):
    def test_every_workflow_cancel_key_is_guarded(self):
        problems = []
        for name, text in _all().items():
            problems += cancel_violations(name, text)
        self.assertEqual(problems, [])

    def test_no_workflow_lists_edited_beyond_the_allow_list(self):
        problems = []
        for name, text in _all().items():
            problems += edited_listed(name, text)
        self.assertEqual(problems, [])

    def test_ci_and_coverage_do_not_list_edited(self):
        for name in NO_EDITED:
            types = pr_types((WF / name).read_text(encoding="utf-8"), ("pull_request",))
            self.assertTrue(types, f"{name}: pull_request.types not found")
            self.assertNotIn("edited", types, name)

    def test_only_one_pull_request_target_workflow(self):
        texts = _all()
        self.assertEqual(target_extras(texts), [])
        self.assertTrue(has_trigger(texts["claude-md-rule-compare.yml"], "pull_request_target"))

    def test_retarget_workflow_is_gone(self):
        self.assertFalse((WF / "pr-retarget.yml").exists())
        self.assertTrue((ROOT / "scripts" / "ci" / "pr_retarget_check.py").is_file())

    def test_rule_compare_keeps_edited_with_guard(self):
        text = (WF / "claude-md-rule-compare.yml").read_text(encoding="utf-8")
        self.assertIn("edited", pr_types(text))
        self.assertEqual(cancel_violations("claude-md-rule-compare.yml", text), [])

    # ---- mutation self-tests: each shape must be caught ----
    def test_mutation_job_level_key_true(self):
        bad = BASE_BAD.replace("${{ github.event_name == 'pull_request' }}", "false") + (
            "jobs:\n  a:\n    concurrency:\n      group: j\n      cancel-in-progress: true\n")
        self.assertEqual(len(cancel_violations("m.yml", bad)), 1)

    def test_mutation_missing_key(self):
        bad = BASE_BAD.replace("  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n", "")
        self.assertEqual(len(cancel_violations("m.yml", bad)), 1)

    def test_mutation_or_true(self):
        bad = BASE_BAD.replace("'pull_request' }}", "'pull_request' || true }}")
        self.assertEqual(len(cancel_violations("m.yml", bad)), 1)

    def test_mutation_or_push_event(self):
        bad = BASE_BAD.replace("'pull_request' }}", "'pull_request' || github.event_name == 'push' }}")
        self.assertEqual(len(cancel_violations("m.yml", bad)), 1)

    def test_accepted_forms(self):
        for value in ("false", "${{ github.event_name == 'pull_request' }}",
                      "${{ github.event.action != 'edited' }}",
                      "${{ github.event_name == 'pull_request' && github.ref != 'refs/heads/main' }}"):
            ok = BASE_BAD.replace("${{ github.event_name == 'pull_request' }}", value)
            self.assertEqual(cancel_violations("ok.yml", ok), [], value)

    def test_mutation_edited_injected_into_ci_and_coverage(self):
        for name in NO_EDITED:
            text = (WF / name).read_text(encoding="utf-8")
            self.assertEqual(edited_listed(name, text), [])
            mutated = text.replace("types: [opened, synchronize, reopened]",
                                   "types: [opened, synchronize, reopened, edited]", 1)
            self.assertNotEqual(mutated, text, name)
            self.assertEqual(len(edited_listed(name, mutated)), 1, name)

    def test_mutation_edited_under_pull_request_target(self):
        bad = BASE_BAD.replace("  pull_request:", "  pull_request_target:")
        self.assertEqual(len(edited_listed("m.yml", bad)), 1)

    def test_mutation_edited_as_block_sequence(self):
        bad = ("on:\n  pull_request:\n    types:\n      - opened\n      - edited\n"
               "concurrency:\n  group: g\n  cancel-in-progress: false\n")
        self.assertEqual(len(edited_listed("m.yml", bad)), 1)
        self.assertIn("edited", pr_types(bad))

    def test_mutation_edited_in_flow_mapping_trigger(self):
        bad = "on: {pull_request: {types: [opened, edited]}}\n"
        self.assertEqual(len(edited_listed("m.yml", bad)), 1)
        tgt = "on: {pull_request_target: {types: [edited]}}\n"
        self.assertEqual(len(edited_listed("m.yml", tgt)), 1)
        self.assertEqual(len(target_extras({"m.yml": tgt})), 1)

    def test_block_and_flow_forms_without_edited_pass(self):
        for good in ("on:\n  pull_request:\n    types:\n      - opened\n      - synchronize\n",
                     "on: {pull_request: {types: [opened, synchronize]}}\n",
                     "on:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\n"):
            self.assertEqual(edited_listed("ok.yml", good), [], good)

    def test_mutation_parse_failure_fails_closed(self):
        for bad in ("name: x\njobs: {}\n",
                    "on: &t\n  pull_request:\n    types: *x\n",
                    "on:\n"):
            self.assertEqual(len(edited_listed("m.yml", bad)), 1, bad)
            self.assertEqual(len(cancel_violations("m.yml", bad)), 1, bad)
            self.assertEqual(len(target_extras({"m.yml": bad})), 1, bad)

    def test_mutation_quoted_trigger_keys(self):
        for q in ('"', "'"):
            block = f"on:\n  {q}pull_request{q}:\n    types: [opened, edited]\n"
            self.assertEqual(len(edited_listed("m.yml", block)), 1, block)
            seq = f"on:\n  {q}pull_request{q}:\n    types:\n      - {q}edited{q}\n"
            self.assertEqual(len(edited_listed("m.yml", seq)), 1, seq)
            tgt = f"on:\n  {q}pull_request_target{q}:\n    types: [edited]\n"
            self.assertEqual(len(target_extras({"m.yml": tgt})), 1, tgt)
            flow = f"on: {{{q}pull_request{q}: {{types: [edited]}}}}\n"
            self.assertEqual(len(edited_listed("m.yml", flow)), 1, flow)

    def test_mutation_multiline_flow_mapping(self):
        for bad in ("on: {\n  pull_request: {\n    types: [opened,\n      edited]\n  }\n}\n",
                    "on:\n  {\n  pull_request: {types: [opened, edited]}\n  }\nname: x\n",
                    "on: [push,\n  pull_request]\n"):
            if "edited" in bad:
                self.assertEqual(len(edited_listed("m.yml", bad)), 1, bad)
            self.assertTrue(has_trigger(bad, "pull_request"), bad)
        tgt = "on: {\n  pull_request_target: {types: [edited]}\n}\n"
        self.assertEqual(len(target_extras({"m.yml": tgt})), 1)
        ok = "on: {\n  pull_request: {types: [opened, synchronize]}\n}\njobs: {}\n"
        self.assertEqual(edited_listed("ok.yml", ok), [])

    def test_mutation_quoted_bracket_in_multiline_flow(self):
        # A quoted `}` or `]` must not end the join early (REVIEW-8332-security-r4 S7).
        for q in ('"', "'"):
            for br in ("}", "]", "}]"):
                bad = (f"on: {{\n  pull_request: {{branches: [{q}rel{br}x{q}],\n"
                       "    types: [edited]}\n}\njobs: {}\n")
                self.assertEqual(len(edited_listed("m.yml", bad)), 1, bad)
        short = "on: {pull_request: {types: [opened]}}\n  types: [edited]\njobs: {}\n"
        out = edited_listed("short.yml", short)
        self.assertEqual(len(out), 1)
        self.assertIn("short.yml", out[0])

    def test_quoted_value_without_brackets_still_joins(self):
        ok = ('on: {\n  pull_request: {branches: ["release/v1", \'main\'],\n'
              "    types: [opened, synchronize]}\n}\njobs: {}\n")
        self.assertEqual(edited_listed("ok.yml", ok), [])
        self.assertTrue(has_trigger(ok, "pull_request"))

    def test_mutation_unclosed_flow_is_refused_by_name(self):
        bad = "on: {\n  pull_request: {types: [opened, edited]\n"
        out = edited_listed("unclosed.yml", bad)
        self.assertEqual(len(out), 1)
        self.assertIn("unclosed.yml", out[0])
        self.assertIn("unclosed flow", out[0])

    def test_mutation_capitalised_edited(self):
        bad = BASE_BAD.replace("edited]", "Edited]")
        self.assertEqual(len(edited_listed("m.yml", bad)), 1)

    def test_yaml_extension_workflows_are_scanned(self):
        SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp:
            d = Path(tmp)
            (d / "a.yml").write_text("on:\n  push:\n", encoding="utf-8")
            (d / "b.yaml").write_text(BASE_BAD, encoding="utf-8")
            texts = _all(d)
            self.assertEqual(sorted(texts), ["a.yml", "b.yaml"])
            self.assertEqual(len(edited_listed("b.yaml", texts["b.yaml"])), 1)

    def test_mutation_second_pull_request_target_workflow(self):
        texts = dict(_all())
        texts["second.yml"] = "on:\n  pull_request_target:\n    types: [opened]\n"
        out = target_extras(texts)
        self.assertEqual(len(out), 1)
        self.assertIn("#8337", out[0])


EDITED, CLEAN, REFUSE = "edited", "clean", "refuse"
CANCEL_TRUE = "concurrency:\n  group: g\n  cancel-in-progress: true\n"
APOSTROPHE_COL0 = ("on: {workflow_dispatch: {inputs: {mode: {description: it's a mode, type: choice, "
                   "options: ['a', 'b']}}},\nKIND: {types: [edited]}}\n")
# The oracle: every trigger shape that made the ratchet fail open in rounds 3-6, with what it must read.
# EDITED = edited listed under a pull_request(_target) trigger; CLEAN = not listed; REFUSE = refused by name.
ORACLE = (
    ("r3 double-quoted block key", 'on:\n  "pull_request":\n    types: [opened, edited]\n', EDITED),
    ("r3 single-quoted key, quoted sequence item", "on:\n  'pull_request':\n    types:\n      - 'edited'\n", EDITED),
    ("r3 quoted flow key", 'on: {"pull_request": {types: [edited]}}\n', EDITED),
    ("r3 two-line flow", "on: {pull_request: {types: [opened,\n  edited]}}\n", EDITED),
    ("r3 three-line flow", "on: {\n  pull_request: {types: [opened, edited]}\n}\n", EDITED),
    ("r3 five-line flow", "on: {\n  pull_request: {\n    types: [opened,\n      edited]\n  }\n}\n", EDITED),
    ("r3 unclosed flow", "on: {\n  pull_request: {types: [opened, edited]\n", REFUSE),
    ("r3 Edited", "on:\n  pull_request:\n    types: [opened, Edited]\n", EDITED),
    ("r3 EDITED", "on:\n  pull_request:\n    types: [opened, EDITED]\n", EDITED),
    ("r3 list form", "on: [pull_request]\n", CLEAN),
    ("r3 comment lines holding edited", "on:\n  pull_request:\n    # edited\n    types: [opened]  # edited\n", CLEAN),
    ("r4 double-quoted } in a multi-line flow",
     'on: {\n  pull_request: {branches: ["rel}x"],\n    types: [edited]}\n}\n', EDITED),
    ("r4 single-quoted ] in a multi-line flow",
     "on: {\n  pull_request: {branches: ['rel]x'],\n    types: [edited]}\n}\n", EDITED),
    ("r4 short join, indented lines left", "on: {pull_request: {types: [opened]}}\n  types: [edited]\njobs: {}\n", REFUSE),
    ("r5 real comment holding } after the flow", "on: {pull_request: {types: [opened]}}  # }\njobs: {}\n", CLEAN),
    ("r5 real comment holding } inside a multi-line flow",
     "on: {\n  pull_request: {types: [opened]}, # }\n  pull_request_target: {types: [edited]}\n}\n", EDITED),
    ("r5 quoted scalar spanning lines with }}}", 'on: {pull_request: {branches: ["a\n  }}}"], types: [edited]}}\n', EDITED),
    ("r6 quoted space-# dq, block key inline flow", 'on:\n  pull_request: {paths: ["docs #x"], types: [edited]}\n', EDITED),
    ("r6 quoted space-# sq, block key inline flow", "on:\n  pull_request: {paths: ['docs #x'], types: [edited]}\n", EDITED),
    ("r6 quoted space-#, multi-line flow", 'on: {pull_request: {paths: ["docs #x"], types: [\n  edited]}}\n', EDITED),
    ("r6 quoted space-#, single-line flow", 'on: {pull_request: {paths: ["docs #x"], types: [edited]}}\n', EDITED),
    ("r6 quoted space-#, no edited", 'on:\n  pull_request: {paths: ["docs #x"], types: [opened]}\n', CLEAN),
    ("r6 escaped double quote then space-#", 'on:\n  pull_request: {branches: ["a\\" #x"], types: [edited]}\n', EDITED),
    ("r6 doubled single quote then space-#", "on:\n  pull_request: {branches: ['it''s #x'], types: [edited]}\n", EDITED),
    ("r6 apostrophe in a plain scalar, column-0 continuation",
     APOSTROPHE_COL0.replace("KIND", "pull_request"), EDITED),
    ("r6 apostrophe in a plain scalar, column-0 continuation, target",
     APOSTROPHE_COL0.replace("KIND", "pull_request_target"), EDITED),
    ("r6 column-0 continuation", "on: {push: {branches: [main]},\npull_request: {types: [edited]}}\n", EDITED),
    ("r6 apostrophe and quotes in a block plain scalar",
     "on:\n  workflow_dispatch:\n    inputs:\n      x:\n        description: it's a 'mode' [\n"
     "  pull_request:\n    types: [edited]\n", EDITED),
    ("r6 block scalar holding quotes and brackets",
     "on:\n  workflow_dispatch:\n    inputs:\n      x:\n        description: |\n          it's [edited { \"#\n"
     "  pull_request:\n    types: [opened]\n", CLEAN),
    ("r6 column-0 non-key after the on: section", "on:\n  pull_request:\n    types: [opened]\ntypes: [edited]\n", REFUSE),
    ("r6 unterminated quoted scalar", 'on:\n  pull_request:\n    branches: ["a\n    types: [edited]\n', REFUSE),
    ("r6 second top-level on: key", "on:\n  push:\non:\n  pull_request:\n    types: [edited]\n", REFUSE),
    ("r6 whole-document flow mapping", '{"on": {"pull_request": {"types": ["edited"]}}}\n', REFUSE),
)


def oracle_verdict(name: str, text: str) -> str:
    """The scanner's reading of one oracle shape: EDITED, CLEAN or REFUSE (by name)."""
    out = edited_listed(name, text)
    if not out:
        return CLEAN
    return REFUSE if "cannot parse" in out[0] and name in out[0] else EDITED


def yaml_verdict(yaml_mod, text: str) -> str:
    """PyYAML's reading: a pull_request(_target) trigger with a types key and the word edited in it."""
    data = yaml_mod.safe_load(text)
    on = data.get("on", data.get(True)) if isinstance(data, dict) else None
    for kind in KINDS:
        body = on.get(kind) if isinstance(on, dict) else None
        if isinstance(body, dict) and "types" in body:
            stack, words = [body], set()
            while stack:
                item = stack.pop()
                if isinstance(item, dict):
                    stack.extend(list(item.keys()) + list(item.values()))
                elif isinstance(item, list):
                    stack.extend(item)
                elif isinstance(item, str):
                    words |= set(re.findall(r"[a-z_]+", item.lower()))
            if "edited" in words:
                return EDITED
    return CLEAN


class EditedRatchetOracle8332(unittest.TestCase):
    """Round 6 (REVIEW-8332-security-r5 S9/S10, REVIEW-8332-code-r5 F1): the oracle that ends the class."""

    def test_oracle_table(self):
        for name, text, want in ORACLE:
            with self.subTest(name):
                fname = re.sub(r"\W+", "-", name) + ".yml"
                self.assertEqual(oracle_verdict(fname, text), want, text)
                if want == REFUSE:
                    self.assertEqual(len(cancel_violations(fname, text)), 1, text)
                    self.assertEqual(len(target_extras({fname: text})), 1, text)
                elif want == EDITED:
                    self.assertGreaterEqual(len(cancel_violations(fname, text + CANCEL_TRUE)), 1, text)

    def test_mutation_apostrophe_and_column0_continuation(self):
        for kind in KINDS:
            text = APOSTROPHE_COL0.replace("KIND", kind)
            self.assertEqual(oracle_verdict("apos.yml", text), EDITED, text)
            self.assertEqual(len(cancel_violations("apos.yml", text + CANCEL_TRUE)), 1, text)
        tgt = APOSTROPHE_COL0.replace("KIND", "pull_request_target")
        self.assertEqual(len(target_extras({"apos.yml": tgt})), 1)
        out = edited_listed("col0.yml", "on:\n  pull_request:\n    types: [opened]\ntypes: [edited]\n")
        self.assertEqual(len(out), 1)
        self.assertIn("col0.yml", out[0])
        self.assertIn("not a top-level key", out[0])

    def test_mutation_quoted_space_hash(self):
        for q in ('"', "'"):
            for text in (f"on:\n  pull_request: {{paths: [{q}docs #x{q}], types: [edited]}}\n",
                         f"on: {{pull_request: {{paths: [{q}docs #x{q}], types: [\n  edited]}}}}\n",
                         f"on: {{pull_request: {{paths: [{q}docs #x{q}], types: [edited]}}}}\n"):
                self.assertEqual(oracle_verdict("hash.yml", text), EDITED, text)
            ok = f"on:\n  pull_request: {{paths: [{q}docs #x{q}], types: [opened]}}\n"
            self.assertEqual(oracle_verdict("hash.yml", ok), CLEAN, ok)
            self.assertTrue(has_trigger(ok, "pull_request"))

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML not importable on this interpreter")
    def test_oracle_matches_pyyaml(self):
        import yaml
        for name, text, want in ORACLE:
            if want == REFUSE:
                continue  # a refusal is the fail-closed answer whatever YAML reads
            with self.subTest(name):
                self.assertEqual(yaml_verdict(yaml, text), want, text)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
