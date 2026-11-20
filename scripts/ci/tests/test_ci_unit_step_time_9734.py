#!/usr/bin/env python3
"""Time ceiling of the `Shard partition and wiring unit tests (#6344)` step (#9734).

Class: a CI step named for a small set of tests must run that set and nothing else, so its
wall time stays flat. PR 9684 (#9593) moved the whole `scripts/ci/tests` discovery (3197 tests,
659 s measured) into the build-script-vetting job under that step name, so a step named for
the shard wiring tests took 11 minutes.

Invariant for every push: the #6344 step runs only the shard wiring tests (a `-p` filter), it
finishes under FAST_STEP_CEILING_S seconds, and the whole discovery still runs, once, in the
sibling step FULL_STEP of the same job (no test and no assertion is dropped).

Every workflow check is a pure function over the workflow text that returns the problem lines;
the cells assert an empty list on the real file and an exact message on a broken copy.

Run: python3 -m unittest discover -s scripts/ci/tests -p test_ci_unit_step_time_9734.py
Python 3.12+, standard library only.
"""
import re
import shlex
import subprocess
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
CI_YML = REPO / ".github" / "workflows" / "ci.yml"

UNIT_JOB = "build-script-vetting"
FAST_STEP = "Shard partition and wiring unit tests (#6344)"
# The glob does not spell the test file path: a workflow that spells a cargo-skip test file turns the
# cargo-skip read-set tests (8322, 8328) red (#9646 N1).
FAST_COMMAND = "python3 -m unittest discover -s scripts/ci/tests -p \"*_shard_wiring_6344.py\""
FULL_STEP = "All scripts/ci unit tests (#9734)"
FULL_COMMAND = "python3 scripts/ci/run_unit_modules.py"
# The invariant of #9734: the step runs under this many seconds on a GitHub-hosted runner.
FAST_STEP_CEILING_S = 10.0
# This module's own wall time (it runs the step command once) may not pass the same ceiling.
MODULE_CEILING_S = FAST_STEP_CEILING_S
SUBPROCESS_TIMEOUT_S = 60
FILTER_FLAG = " -p "

JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):[ \t]*$")
STEP_RE = re.compile(r"^      - name: (.*)$")
RUN_RE = re.compile(r"^        run: (.*)$")
RAN_RE = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)

_started = 0.0


def setUpModule():
    global _started
    _started = time.monotonic()


def tearDownModule():
    elapsed = time.monotonic() - _started
    if elapsed > MODULE_CEILING_S:
        raise AssertionError("module wall time %.1f s passed the ceiling %.1f s (#9734)" % (elapsed, MODULE_CEILING_S))


def job_steps(text: str, job: str) -> list:
    """(name, run-or-None) of every step of `job`, in file order."""
    inside = False
    out = []
    for line in text.split("\n"):
        m = JOB_RE.match(line)
        if m:
            inside = m.group(1) == job
            continue
        if not inside:
            continue
        s = STEP_RE.match(line)
        if s:
            out.append([s.group(1).strip(), None])
            continue
        r = RUN_RE.match(line)
        if r and out and out[-1][1] is None:
            out[-1][1] = r.group(1).strip()
    return [(n, r) for n, r in out]


def problems_unit_steps(text: str) -> list:
    """The problem lines of the two unit-test steps of the unit job."""
    where = "ci.yml " + UNIT_JOB
    steps = job_steps(text, UNIT_JOB)
    out = []
    fast = [r for n, r in steps if n == FAST_STEP]
    full = [r for n, r in steps if n == FULL_STEP]
    if len(fast) != 1:
        out.append("%s: the step %r must exist exactly once, found %d" % (where, FAST_STEP, len(fast)))
    elif fast[0] != FAST_COMMAND:
        out.append("%s: the step %r must run %r, not %r (it may run only the shard wiring tests)"
                   % (where, FAST_STEP, FAST_COMMAND, fast[0]))
    if len(full) != 1:
        out.append("%s: the step %r must exist exactly once, found %d" % (where, FULL_STEP, len(full)))
    elif full[0] != FULL_COMMAND:
        out.append("%s: the step %r must run the whole discovery %r, not %r" % (where, FULL_STEP, FULL_COMMAND, full[0]))
    return out


def run_step_command(command: str) -> tuple:
    """(rc, seconds, tests run, stderr tail) of the step command, run from the repo root."""
    started = time.monotonic()
    done = subprocess.run(shlex.split(command), cwd=REPO, capture_output=True, text=True,
                          timeout=SUBPROCESS_TIMEOUT_S, check=False)
    seconds = time.monotonic() - started
    ran = RAN_RE.search(done.stderr)
    return done.returncode, seconds, int(ran.group(1)) if ran else 0, done.stderr[-400:]


class RealWorkflow(unittest.TestCase):
    def test_9734_unit_steps_are_split(self):
        self.assertEqual(problems_unit_steps(CI_YML.read_text()), [])

    def test_9734_fast_step_runs_under_the_ceiling(self):
        steps = dict(job_steps(CI_YML.read_text(), UNIT_JOB))
        command = steps.get(FAST_STEP)
        # A step with no filter runs the whole discovery (659 s measured); never run that here.
        self.assertIsNotNone(command, "the step %r is missing" % FAST_STEP)
        self.assertIn(FILTER_FLAG, command, "the step %r runs the whole discovery: %r" % (FAST_STEP, command))
        rc, seconds, tests, tail = run_step_command(command)
        self.assertEqual(rc, 0, tail)
        self.assertGreater(tests, 0)
        self.assertLess(seconds, FAST_STEP_CEILING_S, "step took %.1f s, ceiling %.1f s" % (seconds, FAST_STEP_CEILING_S))


class BrokenCopies(unittest.TestCase):
    def _real(self) -> str:
        return CI_YML.read_text()

    def _swap(self, old: str, new: str) -> str:
        text = self._real()
        self.assertEqual(text.count(old), 1, old)
        return text.replace(old, new)

    def test_fast_step_back_to_the_whole_discovery(self):
        broken = self._swap("        run: " + FAST_COMMAND + "\n", "        run: " + FULL_COMMAND + "\n")
        self.assertEqual(problems_unit_steps(broken), [
            "ci.yml %s: the step %r must run %r, not %r (it may run only the shard wiring tests)"
            % (UNIT_JOB, FAST_STEP, FAST_COMMAND, FULL_COMMAND)])

    def test_full_step_narrowed(self):
        broken = self._swap("        run: " + FULL_COMMAND + "\n", "        run: " + FAST_COMMAND + "\n")
        self.assertEqual(problems_unit_steps(broken), [
            "ci.yml %s: the step %r must run the whole discovery %r, not %r"
            % (UNIT_JOB, FULL_STEP, FULL_COMMAND, FAST_COMMAND)])

    def test_full_step_dropped(self):
        broken = self._swap("      - name: " + FULL_STEP + "\n", "      - name: Other\n")
        self.assertEqual(problems_unit_steps(broken), [
            "ci.yml %s: the step %r must exist exactly once, found 0" % (UNIT_JOB, FULL_STEP)])

    def test_ceiling_is_the_ten_second_invariant(self):
        self.assertEqual(FAST_STEP_CEILING_S, 10.0)


if __name__ == "__main__":
    unittest.main()
