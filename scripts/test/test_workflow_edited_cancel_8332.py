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
   test imports it), so it fails closed: a workflow whose ``on:`` section it cannot read
   (no ``on`` key, an anchor or alias in it) is a failure, and any ``edited`` word inside a
   pull_request(_target) trigger body counts as listed.
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
import re
import sys
import tempfile
import unittest
from pathlib import Path

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
ON_KEY_RE = re.compile(r"""^(?:on|"on"|'on')[ \t]*:(.*)$""")
ANCHOR_RE = re.compile(r"(?:^|[\s\[{,:])[&*][A-Za-z_]|<<\s*:")
CANCEL_RE = re.compile(r"^[ \t]*cancel-in-progress:[ \t]*(.*?)[ \t]*$", re.M)
CONCURRENCY_RE = re.compile(r"^[ \t]*concurrency:", re.M)


class ParseFailure(Exception):
    """The workflow trigger section cannot be read; the caller fails closed."""


def _strip(line: str) -> str:
    return re.sub(r"(^|\s)#.*$", "", line).rstrip()


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _join_flow(first: str, remaining: list) -> str:
    """Join a flow collection to its closing brace across lines; fail closed when it never closes.

    decision (round 4, REVIEW-8332-security-r3 S5): join (not refuse) a multi-line flow, because
    that is valid YAML; an UNCLOSED flow is refused by name via ParseFailure.
    """
    pieces = [first]
    depth = sum(first.count(c) for c in "{[") - sum(first.count(c) for c in "}]")
    lines = list(remaining)
    while depth > 0:
        if not lines:
            raise ParseFailure("unclosed flow collection in the `on:` section")
        nxt = lines.pop(0)
        pieces.append(nxt)
        depth += sum(nxt.count(c) for c in "{[") - sum(nxt.count(c) for c in "}]")
    return "\n".join(pieces)


def triggers(text: str) -> dict:
    """Map each pull_request(_target) trigger found in ``on:`` to its body text.

    Raises ParseFailure when ``on:`` is missing or uses an anchor or alias.
    """
    lines = [_strip(x) for x in text.splitlines()]
    start = next((i for i, x in enumerate(lines) if ON_KEY_RE.match(x)), None)
    if start is None:
        raise ParseFailure("no top-level `on:` key")
    rest = ON_KEY_RE.match(lines[start]).group(1).strip()
    section = []
    for x in lines[start + 1:]:
        if x and not x[0].isspace():
            break
        if x.strip():
            section.append(x)
    if ANCHOR_RE.search("\n".join([rest] + section)):
        raise ParseFailure("anchor or alias in the `on:` section")
    out = {}
    after = lines[start + 1:]
    flow, remaining = "", after
    if rest[:1] in ("{", "["):
        flow = rest
    elif not rest and section and section[0].strip()[:1] in ("{", "["):
        idx = next(i for i, x in enumerate(after) if x.strip())
        flow, remaining = section[0].strip(), after[idx + 1:]
    if flow:  # a flow mapping or sequence, possibly spread over several lines: join to its closing brace
        flow = _join_flow(flow, remaining)
        if ANCHOR_RE.search(flow):
            raise ParseFailure("anchor or alias in the `on:` section")
        rest = flow
    if rest:  # inline scalar, flow sequence or flow mapping: the whole text is the body
        for kind in KINDS:
            if re.search(rf"""(?<![\w-]){kind}(?![\w-])""", rest):
                out[kind] = rest
        return out
    if not section:
        raise ParseFailure("empty `on:` section")
    child = _indent(section[0])
    current = None
    for x in section:
        ind = _indent(x)
        m = re.match(rf"""^ {{{child}}}(?:-[ \t]+)?["']?([\w-]+)["']?[ \t]*:(.*)$""", x) if ind == child else None
        seq = re.match(rf"""^ {{{child}}}-[ \t]+["']?([\w-]+)["']?[ \t]*$""", x) if ind == child else None
        if seq:
            current = seq.group(1)
            if current in KINDS:
                out[current] = ""
        elif m:
            current = m.group(1)
            if current in KINDS:
                out[current] = m.group(2)
        elif ind > child and current in KINDS:
            out[current] += "\n" + x
    return out


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


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
