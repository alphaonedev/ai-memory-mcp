#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the pull_request activity types of ci.yml and coverage.yml (#7072, #7782).

#7072 added ``edited`` so that retargeting a PR base queued a run. #7782 removed
it again: every PR title or body edit then created a new CI and coverage run for
an unchanged head and, through ``cancel-in-progress``, cancelled the run that was
already building it. ``pull_request.types`` is now exactly
``opened, synchronize, reopened``. A base retarget is re-run by closing and
reopening the PR (``reopened`` stays subscribed), which keeps the #7072
guarantee. The ``merge_group`` trigger (``checks_requested``) is untouched.

Stdlib only. Run: ``python3 -I scripts/test/test_workflow_edited_7072.py``
or ``python3 -I -m unittest`` with the file path loaded by the repo runner.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github" / "workflows"
EXPECTED_TYPES = {"opened", "synchronize", "reopened"}


def _read(name: str) -> str:
    return (WF / name).read_text(encoding="utf-8")


def _types(text: str, trigger: str) -> set:
    """Return the set from ``types: [..]`` directly under the given trigger."""
    m = re.search(r"^  " + trigger + r":\n((?:    .*\n|\s*\n|  #.*\n)+)", text, re.M)
    if not m:
        raise AssertionError(trigger + " trigger block not found")
    t = re.search(r"^    types: \[([^\]]*)\]\s*$", m.group(1), re.M)
    if not t:
        raise AssertionError(trigger + ".types list not found")
    return {x.strip().strip("'\"") for x in t.group(1).split(",") if x.strip()}


class PullRequestNoEdited7782(unittest.TestCase):
    def test_ci_yml_types_exclude_edited(self):
        self.assertEqual(_types(_read("ci.yml"), "pull_request"), EXPECTED_TYPES)

    def test_coverage_yml_types_exclude_edited(self):
        self.assertEqual(_types(_read("coverage.yml"), "pull_request"), EXPECTED_TYPES)

    def test_merge_group_trigger_untouched(self):
        for name in ("ci.yml", "coverage.yml"):
            self.assertEqual(_types(_read(name), "merge_group"), {"checks_requested"}, name)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
