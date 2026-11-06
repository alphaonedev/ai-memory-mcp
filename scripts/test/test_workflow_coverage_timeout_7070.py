#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the coverage.yml per-module job timeout (#7070).

#7070: the ``per-module-thresholds`` job of coverage.yml was cancelled at its
75-minute cap; its ``timeout-minutes`` must be 110.

Stdlib only. Run: ``python3 -I scripts/test/test_workflow_coverage_timeout_7070.py``
or ``python3 -I -m unittest`` with the file path loaded by the repo runner.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github" / "workflows"


def _read(name: str) -> str:
    return (WF / name).read_text(encoding="utf-8")


def _job_timeout(text: str, job: str) -> int:
    m = re.search(r"^  " + re.escape(job) + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.M | re.S)
    if not m:
        raise AssertionError("job not found: " + job)
    t = re.search(r"^    timeout-minutes: (\d+)\s*$", m.group(1), re.M)
    if not t:
        raise AssertionError("job-level timeout-minutes not found: " + job)
    return int(t.group(1))


class CoverageTimeout7070(unittest.TestCase):
    def test_per_module_thresholds_timeout_is_110(self):
        self.assertEqual(_job_timeout(_read("coverage.yml"), "per-module-thresholds"), 110)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
