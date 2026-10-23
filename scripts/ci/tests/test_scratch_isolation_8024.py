"""Regression for #8024: concurrent suite runs must not share a scratch dir.

The partition, evict-r5, sccache, per-runner, sync and prune suites used fixed
``.local-runs`` scratch paths that each setUp/tearDown ``rmtree``'d, so two
concurrent discover runs in one checkout destroyed each other's fixtures.
"""

import importlib
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


TEARDOWN_RE = re.compile(r"^def tearDownModule\(", re.MULTILINE)


class PatternsComplete8024(unittest.TestCase):
    """PATTERNS must name exactly the suites that own a per-run module scratch."""

    def test_patterns_match_every_suite_with_a_tear_down_module(self):
        found = {p.name for p in TESTS_DIR.glob("test_*.py")
                 if TEARDOWN_RE.search(p.read_text(encoding="utf-8"))}
        self.assertGreater(len(PATTERNS), 0, "PATTERNS is empty")
        self.assertEqual(set(PATTERNS), found)


class PerRunScratch8024(unittest.TestCase):
    """Deterministic guard: each suite's setUpModule must mint a fresh scratch dir (F1 of r2).

    The concurrent test below can miss a suite that finishes before its sibling
    children start (sync-r4 runs in 0.036 s), so this one needs no timing.
    """

    def test_every_suite_mints_a_distinct_dir_under_local_runs(self):
        sys.path.insert(0, str(TESTS_DIR))
        self.addCleanup(sys.path.remove, str(TESTS_DIR))
        parent = (REPO / ".local-runs").resolve()
        self.assertGreater(len(PATTERNS), 0, "PATTERNS is empty")
        for pattern in PATTERNS:
            with self.subTest(pattern=pattern):
                mod = importlib.import_module(pattern[:-len(".py")])
                self.assertTrue(hasattr(mod, "setUpModule"), "no setUpModule: fixed scratch")
                made = []
                try:
                    for _ in range(2):
                        mod.setUpModule()
                        made.append(mod.SCRATCH)
                    self.assertNotEqual(made[0], made[1])
                    for path in made:
                        self.assertTrue(Path(path).is_dir(), path)
                        self.assertEqual(Path(path).resolve().parent, parent)
                finally:
                    for path in made:
                        mod.SCRATCH = path
                        mod.tearDownModule()
                    mod.SCRATCH = None
                for path in made:
                    self.assertFalse(Path(path).exists(), path)


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
        self.assertGreater(len(PATTERNS), 0, "PATTERNS is empty")
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
