"""Regression for #8024: concurrent suite runs must not share a scratch dir.

The partition, evict-r5, sccache, per-runner, sync and prune suites used fixed
``.local-runs`` scratch paths that each setUp/tearDown ``rmtree``'d, so two
concurrent discover runs in one checkout destroyed each other's fixtures.
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TESTS_DIR = Path(__file__).resolve().parent
PATTERNS = (
    "test_partition_test_binaries.py",
    "test_evict_r5_7219.py",
    "test_sccache_r3_7199.py",
    "test_sccache_and_eviction_7199.py",
    "test_per_runner_target_7188.py",
    "test_sync_r4_7219.py",
    "test_prune_runner_artifacts_7188.py",
)
CHILD_COUNT = 3
TIMEOUT_SECS = 600
KILL_WAIT_SECS = 30
MIN_TESTS_PER_CHILD = 5  # a child that matched no suite runs 0 tests (#8161)
RAN_RE = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)
OK_RE = re.compile(r"^OK(?: \(.*\))?$", re.MULTILINE)


class ConcurrentScratch8024(unittest.TestCase):
    def test_concurrent_runs_do_not_collide(self):
        procs = []
        results = []
        try:
            for _ in range(CHILD_COUNT):
                for pattern in PATTERNS:
                    cmd = [sys.executable, "-I", "-m", "unittest", "discover",
                           "-s", str(TESTS_DIR), "-p", pattern]
                    procs.append((pattern, subprocess.Popen(
                        cmd, cwd=str(REPO), stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True)))
            for pattern, proc in procs:
                out, _ = proc.communicate(timeout=TIMEOUT_SECS)
                results.append((pattern, proc.returncode, out))
        finally:
            for _, proc in procs:
                if proc.poll() is None:
                    proc.kill()
                try:
                    proc.communicate(timeout=KILL_WAIT_SECS)
                except subprocess.TimeoutExpired:
                    pass
        self.assertEqual(len(results), CHILD_COUNT * len(PATTERNS))
        for pattern, returncode, out in results:
            with self.subTest(pattern=pattern):
                self.assertEqual(returncode, 0, out[-2000:])
                ran = RAN_RE.search(out)
                self.assertIsNotNone(ran, out[-2000:])
                self.assertGreaterEqual(int(ran.group(1)), MIN_TESTS_PER_CHILD, out[-2000:])
                self.assertRegex(out, OK_RE)


if __name__ == "__main__":
    unittest.main()
