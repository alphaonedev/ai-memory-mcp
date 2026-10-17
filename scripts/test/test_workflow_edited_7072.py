#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the pull_request activity types of ci.yml and coverage.yml (#7072).

#7072: ci.yml and coverage.yml used the default pull_request activity types
(opened, synchronize, reopened), so retargeting a PR base (an ``edited`` event)
queued no run. Both must list ``edited`` in ``pull_request.types``.

Stdlib only. Run: ``python3 -I scripts/test/test_workflow_edited_7072.py``
or ``python3 -I -m unittest`` with the file path loaded by the repo runner.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github" / "workflows"
REQUIRED_TYPES = {"opened", "synchronize", "reopened", "edited"}


def _read(name: str) -> str:
    return (WF / name).read_text(encoding="utf-8")


def _pr_types(text: str) -> set:
    """Return the set from ``types: [..]`` directly under the pull_request trigger."""
    m = re.search(r"^  pull_request:\n((?:    .*\n|\s*\n|  #.*\n)+)", text, re.M)
    if not m:
        raise AssertionError("pull_request trigger block not found")
    t = re.search(r"^    types: \[([^\]]*)\]\s*$", m.group(1), re.M)
    if not t:
        raise AssertionError("pull_request.types list not found")
    return {x.strip().strip("'\"") for x in t.group(1).split(",") if x.strip()}


class PullRequestEdited7072(unittest.TestCase):
    def test_ci_yml_types_include_edited(self):
        self.assertEqual(_pr_types(_read("ci.yml")), REQUIRED_TYPES)

    def test_coverage_yml_types_include_edited(self):
        self.assertEqual(_pr_types(_read("coverage.yml")), REQUIRED_TYPES)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
