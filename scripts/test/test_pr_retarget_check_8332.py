#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""scripts/ci/pr_retarget_check.py refuses a landing after a stale base change (#8332).

Offline: every case feeds fixtures through ``--json-dir`` (timeline.json plus
runs.json), so no network call and no ``gh`` binary is needed.

Stdlib only. Run: ``python3 -I scripts/test/test_pr_retarget_check_8332.py``.
"""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ci" / "pr_retarget_check.py"
FIX = ROOT / "scripts" / "test" / "fixtures" / "pr_retarget_check_8332"
HEAD = "b" * 40


def run_check(case: str):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--repo", "o/r", "--pr", "1", "--head", HEAD,
         "--json-dir", str(FIX / case)],
        capture_output=True, text=True, check=False,
    )


class PrRetargetCheck8332(unittest.TestCase):
    def test_a_no_base_change(self):
        r = run_check("a_no_change")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("retarget-check: no base change", r.stdout)

    def test_b_base_change_older_than_both_runs(self):
        r = run_check("b_change_older")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_c_base_change_newer_than_ci_run(self):
        r = run_check("c_ci_stale")
        self.assertEqual(r.returncode, 65, r.stdout + r.stderr)
        self.assertIn("REFUSE: base retargeted at 2026-10-30T12:00:00Z after the latest pull_request run of ci.yml", r.stdout)

    def test_d_base_change_newer_than_coverage_run_only(self):
        r = run_check("d_cov_stale")
        self.assertEqual(r.returncode, 65, r.stdout + r.stderr)
        self.assertIn("run of coverage.yml", r.stdout)

    def test_e_change_on_second_timeline_page(self):
        r = run_check("e_two_pages")
        self.assertEqual(r.returncode, 65, r.stdout + r.stderr)

    def test_f_gh_failure_is_a_tool_error(self):
        r = run_check("f_gh_failure")
        self.assertEqual(r.returncode, 70, r.stdout + r.stderr)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
