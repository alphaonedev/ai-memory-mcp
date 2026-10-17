#!/usr/bin/env python3
"""Regression tests for #7336: git_limits() must not raise on macOS and must keep the memory guard on Linux.

On macOS the kernel refuses every finite RLIMIT_AS (setrlimit raises ValueError "current limit exceeds maximum
limit"), so the git child of scripts/claude-md-rule-compare.py never started. Every check runs git_limits() in a
fresh child interpreter so the test process keeps its own limits. This is a sibling of test_codeql_6163.py because
the setUp of those classes itself needs git_limits() and fails before any test body runs on macOS.
Run with python3 -I -m unittest.
"""
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / 'scripts' / 'claude-md-rule-compare.py'
CHILD_TIMEOUT_SECONDS = 60
LOWERED_HARD_DIVISOR = 2  # the child lowers its hard limit to half of the requested size before git_limits()
# Child program: argv[1] = script path, argv[2] = "lower" to pre-lower the hard RLIMIT_AS (exit 3 when refused).
CHILD = '''
import importlib.util, json, resource, sys
spec = importlib.util.spec_from_file_location("compare_7336", sys.argv[1])
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)
lowered = None
if sys.argv[2] == "lower":
    lowered = compare.MAX_GIT_MEMORY_BYTES // %d
    try:
        resource.setrlimit(resource.RLIMIT_AS, (lowered, lowered))
    except ValueError:
        sys.exit(3)
compare.git_limits()
print(json.dumps({"as": resource.getrlimit(resource.RLIMIT_AS), "fsize": resource.getrlimit(resource.RLIMIT_FSIZE),
                  "want_as": compare.MAX_GIT_MEMORY_BYTES, "want_fsize": compare.MAX_GIT_FILE_BYTES,
                  "lowered": lowered}))
''' % LOWERED_HARD_DIVISOR
PROBE = '''
import resource, sys
try:
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
except ValueError:
    sys.exit(3)
'''


def run_child(program, *args):
    """Run program in a fresh isolated interpreter; return the completed process."""
    return subprocess.run([sys.executable, '-I', '-c', program, *args], capture_output=True, text=True,
                          timeout=CHILD_TIMEOUT_SECONDS, check=False)


def kernel_lowers_rlimit_as():
    """True where the kernel lets a process lower RLIMIT_AS (Linux); False on macOS."""
    return run_child(PROBE).returncode == 0


class GitLimitsTests(unittest.TestCase):
    """git_limits() in a child process (#7336)."""

    def limits(self, mode):
        result = run_child(CHILD, str(SCRIPT), mode)
        if result.returncode == 3:
            self.skipTest('kernel refuses to lower RLIMIT_AS')
        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        return json.loads(result.stdout)

    def test_git_limits_does_not_raise(self):
        self.limits('plain')

    def test_fsize_limit_applied_on_every_platform(self):
        report = self.limits('plain')
        self.assertEqual(report['fsize'], [report['want_fsize'], report['want_fsize']])

    def test_address_space_limit_applied_where_the_kernel_allows_it(self):
        if not kernel_lowers_rlimit_as():
            self.skipTest('kernel refuses to lower RLIMIT_AS (macOS)')
        report = self.limits('plain')
        self.assertEqual(report['as'][0], report['want_as'])

    def test_requested_limit_is_clamped_to_a_lower_hard_limit(self):
        report = self.limits('lower')
        lowered = report['lowered']
        self.assertEqual(report['as'], [lowered, lowered])


if __name__ == '__main__':
    unittest.main()
