#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""A body-only PR edit never cancels or restarts a required check (#8332).

Defect: ci.yml, coverage.yml and claude-md-rule-compare.yml listed ``edited`` in
their pull_request(_target) types and set ``cancel-in-progress`` for pull_request
runs, so every PR title or body edit cancelled the running required checks and
started them again from zero.

The rule this guard pins (a ratchet over EVERY workflow):

1. A workflow whose pull_request or pull_request_target trigger lists ``edited``
   must have a ``cancel-in-progress`` that is the literal ``false`` or an
   expression carrying the body-only guard ``github.event.action != 'edited'``.
2. ci.yml and coverage.yml do not list ``edited`` at all (a skipped-by-``if`` run
   would report a passing ``skipped`` for a required context). Their base-retarget
   case (#7072) lives in pr-retarget.yml, which dispatches them on the head, and
   pr-retarget.yml must keep its ``changes.base`` job guard.

Stdlib only. Run: ``python3 -I scripts/test/test_workflow_edited_cancel_8332.py``.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github" / "workflows"
BODY_ONLY_GUARD = "github.event.action != 'edited'"
RETARGET = "pr-retarget.yml"
NO_EDITED = ("ci.yml", "coverage.yml")
TRIGGER_RE = re.compile(r"^  (pull_request|pull_request_target):\s*\n((?:    .*\n|\s*\n|  #.*\n)+)", re.M)
TYPES_RE = re.compile(r"^    types: \[([^\]]*)\]\s*$", re.M)
CANCEL_RE = re.compile(r"^  cancel-in-progress: (.+?)\s*$", re.M)


def pr_types(text: str) -> set:
    """Union of the activity types of every pull_request(_target) trigger."""
    out = set()
    for m in TRIGGER_RE.finditer(text):
        t = TYPES_RE.search(m.group(2))
        if t:
            out |= {x.strip().strip("'\"") for x in t.group(1).split(",") if x.strip()}
    return out


def edited_cancel_violations(name: str, text: str) -> list:
    """Return problems for one workflow file's text (empty list = compliant)."""
    if "edited" not in pr_types(text):
        return []
    m = CANCEL_RE.search(text)
    if m is None:
        return []
    value = m.group(1)
    if value == "false" or BODY_ONLY_GUARD in value:
        return []
    return [f"{name}: lists `edited` with cancel-in-progress `{value}` and no body-only guard"]


class BodyOnlyEditNeverCancels8332(unittest.TestCase):
    def test_every_workflow_guards_edited(self):
        problems = []
        for path in sorted(WF.glob("*.yml")):
            problems += edited_cancel_violations(path.name, path.read_text(encoding="utf-8"))
        self.assertEqual(problems, [])

    def test_ci_and_coverage_do_not_list_edited(self):
        for name in NO_EDITED:
            types = pr_types((WF / name).read_text(encoding="utf-8"))
            self.assertTrue(types, f"{name}: pull_request.types not found")
            self.assertNotIn("edited", types, name)

    def test_retarget_workflow_is_gated_on_a_base_change(self):
        text = (WF / RETARGET).read_text(encoding="utf-8")
        self.assertEqual(pr_types(text), {"edited"})
        self.assertIn("github.event.changes.base", text)
        for target in NO_EDITED:
            self.assertIn(target, text)

    def test_rule_compare_keeps_edited_with_guard(self):
        text = (WF / "claude-md-rule-compare.yml").read_text(encoding="utf-8")
        self.assertIn("edited", pr_types(text))
        self.assertEqual(edited_cancel_violations("claude-md-rule-compare.yml", text), [])

    def test_detector_flags_the_defect_shape(self):
        bad = (
            "on:\n  pull_request:\n    types: [opened, synchronize, reopened, edited]\n"
            "concurrency:\n  group: g\n  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n"
        )
        self.assertEqual(len(edited_cancel_violations("bad.yml", bad)), 1)
        self.assertEqual(edited_cancel_violations("ok.yml", bad.replace(
            "${{ github.event_name == 'pull_request' }}", "${{ github.event.action != 'edited' }}")), [])
        self.assertEqual(edited_cancel_violations("ok2.yml", bad.replace(
            "${{ github.event_name == 'pull_request' }}", "false")), [])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
