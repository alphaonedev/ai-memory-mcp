#!/usr/bin/env python3
"""Parallel, fail-closed runner of the scripts/ci unit modules (#9734).

Class: a serial run of independent test modules on a multi-core runner. Invariant: the whole
scripts/ci unit discovery runs every module exactly once, fails closed, and its wall time is
bounded by the slowest module plus the queue, not by the sum.

The cells run the real runner (`scripts/ci/run_unit_modules.py`) on synthetic directories of
tiny modules: green, failing, timing out, zero tests, no `Ran` line, zero modules, a vanished
module, a stale serial entry, serial ordering and the wall-time bound. A further cell pins
that the runner's module set equals the set plain unittest discovery loads.

Run: python3 -m unittest discover -s scripts/ci/tests -p test_run_unit_modules_9734.py
Python 3.12+, standard library only.
"""
import importlib.util
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
RUNNER = REPO / "scripts" / "ci" / "run_unit_modules.py"
REAL_TESTS = REPO / "scripts" / "ci" / "tests"
SCRATCH = REPO / ".local-runs"

EXIT_OK = 0
EXIT_BAD_MODULE = 1
EXIT_USAGE = 2
SLEEP_MODULES = 6
SLEEP_S = 1.0
SLEEP_JOBS = 6
# wall < sum / 2 with jobs >= 2 (the fast-wall invariant); the margin absorbs process start cost.
WALL_FRACTION = 0.5
TIMEOUT_S = 1
HANG_S = 60
RUN_LIMIT_S = 120
SUMMARY_RE = re.compile(
    r"^SUMMARY modules=(\d+) bad=(\d+) \[(.*)\] tests=(\d+) wall=([0-9.]+)s$", re.MULTILINE)

GREEN = "import unittest\nclass T(unittest.TestCase):\n    def test_a(self):\n        self.assertTrue(True)\n    def test_b(self):\n        self.assertTrue(True)\n"
RED = "import unittest\nclass T(unittest.TestCase):\n    def test_a(self):\n        self.assertEqual(1, 2, 'RED-MARKER-9734')\n"
EMPTY = "import unittest\n"
NO_RAN = "import os\nos._exit(0)\n"
# rc 0 with a `Ran 0 tests` line: only the runner's own zero-test check can catch it (unittest itself exits 5).
RAN_ZERO_RC0 = "import os, sys\nsys.stderr.write('Ran 0 tests in 0.000s\\n\\nOK\\n')\nos._exit(0)\n"
HANG = "import time, unittest\nclass T(unittest.TestCase):\n    def test_a(self):\n        time.sleep(%d)\n" % HANG_S
SLEEP = "import time, unittest\nclass T(unittest.TestCase):\n    def test_a(self):\n        time.sleep(%s)\n" % SLEEP_S


def stamped(marker_dir: Path, name: str) -> str:
    """A module that records its start and end monotonic-free wall clock times."""
    return (
        "import time, unittest\n"
        "class T(unittest.TestCase):\n"
        "    def test_a(self):\n"
        "        start = time.time()\n"
        "        time.sleep(0.4)\n"
        "        open(%r, 'w').write('%%r %%r' %% (start, time.time()))\n"
    ) % str(marker_dir / name)


def load_runner():
    spec = importlib.util.spec_from_file_location("run_unit_modules_9734", RUNNER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Synthetic(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self._tmp = tempfile.TemporaryDirectory(dir=SCRATCH, prefix="runner9734-")
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def write(self, name: str, body: str):
        (self.dir / name).write_text(body)

    def run_runner(self, *extra):
        started = time.monotonic()
        done = subprocess.run(
            [sys.executable, str(RUNNER), "--tests-dir", str(self.dir), *extra],
            cwd=REPO, capture_output=True, text=True, timeout=RUN_LIMIT_S, check=False)
        return done, time.monotonic() - started

    def summary(self, done):
        m = SUMMARY_RE.search(done.stdout)
        self.assertIsNotNone(m, "no SUMMARY line in: %r" % done.stdout[-400:])
        return int(m.group(1)), int(m.group(2)), m.group(3), int(m.group(4)), float(m.group(5))


class GreenAndRed(Synthetic):
    def test_all_green_counts_every_module_and_test(self):
        for i in range(3):
            self.write("test_g%d.py" % i, GREEN)
        done, _ = self.run_runner("--jobs", "2")
        self.assertEqual(done.returncode, EXIT_OK, done.stdout + done.stderr)
        modules, bad, names, tests, _wall = self.summary(done)
        self.assertEqual((modules, bad, names, tests), (3, 0, "", 6))
        self.assertIn("test_g0.py rc=0 Ran 2 tests", done.stdout)
        self.assertEqual(len(re.findall(r"^test_g\d\.py rc=0 ", done.stdout, re.MULTILINE)), 3)

    def test_failing_module_exits_one_and_prints_its_output_after_the_summary(self):
        self.write("test_ok.py", GREEN)
        self.write("test_red.py", RED)
        done, _ = self.run_runner("--jobs", "2")
        self.assertEqual(done.returncode, EXIT_BAD_MODULE)
        modules, bad, names, _tests, _wall = self.summary(done)
        self.assertEqual((modules, bad, names), (2, 1, "test_red.py"))
        self.assertGreater(done.stdout.index("RED-MARKER-9734"), done.stdout.index("SUMMARY"))

    def test_module_with_zero_tests_fails_closed(self):
        self.write("test_empty.py", EMPTY)
        done, _ = self.run_runner()
        self.assertEqual(done.returncode, EXIT_BAD_MODULE)
        self.assertEqual(self.summary(done)[1:3], (1, "test_empty.py"))
        self.assertIn("Ran 0 tests", done.stdout)

    def test_rc_zero_with_ran_zero_tests_fails_closed(self):
        self.write("test_ranzero.py", RAN_ZERO_RC0)
        done, _ = self.run_runner()
        self.assertEqual(done.returncode, EXIT_BAD_MODULE)
        self.assertEqual(self.summary(done)[1:3], (1, "test_ranzero.py"))

    def test_module_that_prints_no_ran_line_fails_closed(self):
        self.write("test_silent.py", NO_RAN)
        done, _ = self.run_runner()
        self.assertEqual(done.returncode, EXIT_BAD_MODULE)
        self.assertEqual(self.summary(done)[1:3], (1, "test_silent.py"))

    def test_timeout_kills_the_module_and_fails_closed(self):
        self.write("test_hang.py", HANG)
        done, elapsed = self.run_runner("--timeout", str(TIMEOUT_S))
        self.assertEqual(done.returncode, EXIT_BAD_MODULE)
        self.assertEqual(self.summary(done)[1:3], (1, "test_hang.py"))
        self.assertIn("TIMEOUT", done.stdout)
        self.assertLess(elapsed, HANG_S / 2)


class UsageErrors(Synthetic):
    def test_zero_modules_is_a_usage_error(self):
        done, _ = self.run_runner()
        self.assertEqual(done.returncode, EXIT_USAGE, done.stdout)
        self.assertNotIn("SUMMARY modules=0 bad=0", done.stdout)

    def test_missing_tests_dir_is_a_usage_error(self):
        done = subprocess.run([sys.executable, str(RUNNER), "--tests-dir", str(self.dir / "absent")],
                              cwd=REPO, capture_output=True, text=True, timeout=RUN_LIMIT_S, check=False)
        self.assertEqual(done.returncode, EXIT_USAGE)

    def test_vanished_module_is_a_discovery_error(self):
        runner = load_runner()
        self.write("test_a.py", GREEN)
        with self.assertRaises(runner.DiscoveryError):
            runner.run_modules(["test_a.py", "test_gone.py"], tests_dir=self.dir, repo=REPO,
                               jobs=2, timeout_s=RUN_LIMIT_S, serial=frozenset())

    def test_stale_serial_entry_is_a_discovery_error(self):
        runner = load_runner()
        self.write("test_a.py", GREEN)
        with self.assertRaises(runner.DiscoveryError):
            runner.run_modules(["test_a.py"], tests_dir=self.dir, repo=REPO, jobs=2,
                               timeout_s=RUN_LIMIT_S, serial=frozenset({"test_not_here.py"}))


class WallTime(Synthetic):
    def test_independent_modules_run_in_parallel(self):
        for i in range(SLEEP_MODULES):
            self.write("test_s%d.py" % i, SLEEP)
        done, _ = self.run_runner("--jobs", str(SLEEP_JOBS))
        self.assertEqual(done.returncode, EXIT_OK, done.stdout + done.stderr)
        wall = self.summary(done)[4]
        total = SLEEP_MODULES * SLEEP_S
        self.assertLess(wall, total * WALL_FRACTION, "wall %.1f s, serial sum %.1f s" % (wall, total))

    def test_jobs_one_is_serial(self):
        for i in range(2):
            self.write("test_s%d.py" % i, SLEEP)
        done, _ = self.run_runner("--jobs", "1")
        self.assertGreaterEqual(self.summary(done)[4], 2 * SLEEP_S)

    def test_serial_modules_start_after_the_pool_ends(self):
        runner = load_runner()
        markers = self.dir / "marks"
        markers.mkdir()
        for name in ("test_p1.py", "test_p2.py", "test_ser.py"):
            self.write(name, stamped(markers, name))
        result = runner.run_modules(["test_p1.py", "test_p2.py", "test_ser.py"], tests_dir=self.dir,
                                    repo=REPO, jobs=3, timeout_s=RUN_LIMIT_S,
                                    serial=frozenset({"test_ser.py"}))
        self.assertEqual(result.bad, [])
        spans = {n: tuple(float(x) for x in (markers / n).read_text().split()) for n in
                 ("test_p1.py", "test_p2.py", "test_ser.py")}
        pool_end = max(spans["test_p1.py"][1], spans["test_p2.py"][1])
        self.assertGreaterEqual(spans["test_ser.py"][0], pool_end)


class RealSuite(unittest.TestCase):
    def test_module_set_equals_plain_discovery(self):
        runner = load_runner()
        found = set(runner.discover_modules(REAL_TESTS))
        by_glob = {p.name for p in REAL_TESTS.glob("test*.py")}
        self.assertEqual(found, by_glob)
        loaded = unittest.TestLoader().discover(str(REAL_TESTS))
        names = set()

        def walk(suite):
            for item in suite:
                if isinstance(item, unittest.TestSuite):
                    walk(item)
                else:
                    names.add(type(item).__module__.rsplit(".", 1)[-1] + ".py")
        walk(loaded)
        self.assertTrue(names, "plain discovery loaded no test")
        self.assertEqual(sorted(names - found), [], "plain discovery loads modules the runner drops")

    def test_serial_modules_are_real_and_have_a_reason(self):
        runner = load_runner()
        present = {p.name for p in REAL_TESTS.glob("test*.py")}
        for name, reason in runner.SERIAL_MODULES.items():
            self.assertIn(name, present)
            self.assertTrue(reason.strip(), name)


if __name__ == "__main__":
    unittest.main()
