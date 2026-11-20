#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the #9682 invariant: same required checks, same tests, less wall time.

The `check` matrix of .github/workflows/ci.yml must start every leg as soon as
`classify` is done (`max-parallel` is never below the number of legs), while
the set of job names (the required contexts), the test-bearing steps, the
Linux host semaphore (2 slots) and the absence of any cross-run concurrency
group stay as they are.

Every expected set below is written by hand from the pinned required-context
list (scripts/qc-allowlists/required-contexts-live-pin.txt) and the workflow at
the base sha; none is derived from the workflow under test.

The workflow under test is ci.yml, or the file named by the environment
variable WORKFLOW_UNDER_TEST (used to run the mutants on copies).

Run: python3.12 -m unittest scripts/ci/tests/test_ci_check_matrix_max_parallel_9682.py
Python 3.12+, standard library only (the workflow is read by line).
"""
import os
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
ENV_KEY = "WORKFLOW_UNDER_TEST"
WORKFLOW = Path(os.environ.get(ENV_KEY) or REPO / ".github" / "workflows" / "ci.yml")

# job id -> job `name:`, every job of ci.yml, by hand. A context a required
# check is made of (for example `Check (<leg>)`) is the name with the matrix
# value filled in.
EXPECTED_JOB_NAMES = {
    "select": "Impact selection",
    "classify": "Classify changes",
    "lint": "Lint (fmt + clippy)",
    "build-script-vetting": "Build-script custom-build ledger gate (#2635)",
    "actionlint": "actionlint (workflow-injection guard)",
    "msrv": "MSRV (Rust 1.98)",
    "check": "Check (${{ matrix.leg }})",
    "postgres-feature": "Postgres feature gate",
    "mobile-cross-compile": "Cross-compile (${{ matrix.target }})",
    "sal-feature": "SAL-only feature gate",
    "vectorlite-feature": "vectorlite feature gate",
    "dockerfile-validate": "Dockerfile build (no push)",
    "ci-gate": "ci-gate",
}

# The four legs of `check`, by hand: they expand to the four pinned contexts
# `Check (linux-fed,enterprise-fed)`, `Check (macos-fed,enterprise-fed)`,
# `Check (macos-fed,sqlite)` and `Check (ubuntu-latest,sqlite)`.
EXPECTED_LEGS = [
    "linux-fed,enterprise-fed",
    "macos-fed,enterprise-fed",
    "macos-fed,sqlite",
    "ubuntu-latest,sqlite",
]

# Steps that run tests or gate the result; none may be dropped or moved out of
# the job that owns it.
EXPECTED_STEPS = {
    "check": [
        "Load gate (#6795)",
        "Run tests (impact-aware)",
        "Run the pg_isolated_binary live cells (enterprise-fed legs only)",
        "Security audit",
        "Build release (once leg — release-profile smoke)",
    ],
    "lint": ["Check formatting", "Clippy"],
    "msrv": ["cargo check on MSRV"],
    "sal-feature": ["Run lib tests (sal feature)"],
    "vectorlite-feature": ["Run vectorlite no-native-lib seam tests (#1860)"],
    "postgres-feature": ["Clippy (sal-postgres feature, lib + tests)"],
    "dockerfile-validate": ["Smoke-test the built image"],
}

EXPECTED_SEMAPHORE_SLOTS = "2"
JOB_HEADER = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")


def lines():
    return WORKFLOW.read_text(encoding="utf-8").splitlines()


def jobs():
    """Map job id -> list of its lines, from the top-level `jobs:` key on."""
    src = lines()
    start = src.index("jobs:")
    out = {}
    current = None
    for ln in src[start + 1:]:
        m = JOB_HEADER.match(ln)
        if m:
            current = m.group(1)
            out[current] = []
        elif current is not None:
            out[current].append(ln)
    return out


def job_name(body):
    for ln in body:
        m = re.match(r"^    name:\s*(.+?)\s*$", ln)
        if m:
            return m.group(1).strip("\"'")
    return None


def step_names(body):
    return [m.group(1).strip("\"'") for ln in body
            for m in [re.match(r"^      - name:\s*(.+?)\s*$", ln)] if m]


def active(body):
    return [ln for ln in body if not ln.lstrip().startswith("#")]


def legs(body):
    return [m.group(1) for ln in active(body)
            for m in [re.match(r"^          - leg:\s*(\S+)\s*$", ln)] if m]


def max_parallel(body):
    found = [int(m.group(1)) for ln in active(body)
             for m in [re.match(r"^      max-parallel:\s*(\d+)\s*$", ln)] if m]
    return found


class RequiredContexts(unittest.TestCase):
    def test_job_names_are_exactly_the_pinned_set(self):
        actual = {jid: job_name(body) for jid, body in jobs().items()}
        self.assertEqual(actual, EXPECTED_JOB_NAMES)

    def test_check_legs_are_exactly_the_four_pinned_contexts(self):
        self.assertEqual(sorted(legs(jobs()["check"])), EXPECTED_LEGS)

    def test_test_bearing_steps_stay_in_their_job(self):
        all_jobs = jobs()
        for jid, wanted in EXPECTED_STEPS.items():
            names = step_names(all_jobs[jid])
            for step in wanted:
                self.assertIn(step, names, "%s lost step %r" % (jid, step))

    def test_check_still_needs_only_classify(self):
        needs = [ln for ln in active(jobs()["check"]) if re.match(r"^    needs:", ln)]
        self.assertEqual([ln.strip() for ln in needs], ["needs: classify"])


class MaxParallel(unittest.TestCase):
    def test_every_leg_starts_once_classify_is_done(self):
        body = jobs()["check"]
        caps = max_parallel(body)
        self.assertEqual(len(caps), 1, "check must declare max-parallel once")
        self.assertGreaterEqual(caps[0], len(legs(body)))

    def test_no_job_with_a_matrix_caps_below_its_legs(self):
        for jid, body in jobs().items():
            caps = max_parallel(body)
            if not caps:
                continue
            count = len(legs(body)) or len(
                [ln for ln in active(body)
                 if re.match(r"^          - (target|leg):", ln)])
            self.assertGreaterEqual(caps[0], count, jid)

    def test_cap_is_four_for_the_four_leg_check_matrix(self):
        self.assertEqual(max_parallel(jobs()["check"]), [4])


class HostGuards(unittest.TestCase):
    def test_semaphore_slots_are_two_on_linux_fed_enterprise_fed(self):
        body = "\n".join(jobs()["check"])
        m = re.search(r"HOST_SEMAPHORE_SLOTS: \$\{\{ (.+?) \}\}", body)
        self.assertIsNotNone(m)
        self.assertIn("'%s' || '0'" % EXPECTED_SEMAPHORE_SLOTS, m.group(1))
        self.assertIn("matrix.node == 'linux-fed'", m.group(1))
        self.assertIn("--name linux-fed-tests --slots \"$HOST_SEMAPHORE_SLOTS\"", body)

    def test_load_gate_runs_before_the_tests(self):
        names = step_names(jobs()["check"])
        self.assertLess(names.index("Load gate (#6795)"),
                        names.index("Run tests (impact-aware)"))

    def test_no_cross_run_concurrency_group_on_any_job(self):
        for jid, body in jobs().items():
            self.assertFalse(
                [ln for ln in active(body) if re.match(r"^    concurrency:", ln)],
                "%s declares a job-level concurrency group" % jid)
        check = "\n".join(jobs()["check"])
        self.assertNotIn("linux-fed-tests", re.sub(r"--name linux-fed-tests", "", check))


if __name__ == "__main__":
    unittest.main()
