"""Regression for #8024: concurrent suite runs must not share a scratch dir.

The partition and evict-r5 suites used fixed ``.local-runs`` scratch paths that
each setUp/tearDown ``rmtree``'d, so two concurrent discover runs in one
checkout destroyed each other's fixtures.
"""

import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
TESTS_DIR = Path(__file__).resolve().parent
PATTERNS = ("test_partition_test_binaries.py", "test_evict_r5_7219.py")
CHILD_COUNT = 3
TIMEOUT_SECS = 600


class ConcurrentScratch8024(unittest.TestCase):
    def test_concurrent_runs_do_not_collide(self):
        procs = []
        for _ in range(CHILD_COUNT):
            for pattern in PATTERNS:
                cmd = [sys.executable, "-I", "-m", "unittest", "discover",
                       "-s", str(TESTS_DIR), "-p", pattern]
                procs.append(subprocess.Popen(
                    cmd, cwd=str(REPO), stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True))
        for proc in procs:
            out, _ = proc.communicate(timeout=TIMEOUT_SECS)
            self.assertEqual(proc.returncode, 0, out[-2000:])


if __name__ == "__main__":
    unittest.main()
