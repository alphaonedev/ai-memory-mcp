#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the #9682 invariant: same required checks, same tests, less wall time.

The `check` matrix of .github/workflows/ci.yml must start every leg as soon as
`classify` is done, while the set of job names (the required contexts), the
test-bearing steps and the Linux host semaphore (2 slots) stay as they are.

The cap pin is green ONLY when the `strategy:` block of the `check` job carries
`max-parallel` as a plain integer equal to EXPECTED_CAP, that value is at least
the number of legs this module COUNTED, and `fail-fast: false` stands in that
block. Every form the module cannot read or count is RED with a message that
names the job and the form (never green by skipping): a quoted value, an
expression, a cap outside `strategy:`, a second cap key, a matrix whose legs it
cannot count, a missing key, an unreadable file.

Concurrency groups: this module checks only that no JOB declares a job-level
`concurrency:` group. The workflow-level group (ci.yml, top-level
`concurrency:`) is pinned by scripts/test/test_workflow_concurrency_6340.py,
not here.

Every expected value below is written by hand from the pinned required-context
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

CHECK_JOB = "check"
CAP_KEY = "max-parallel"
FAIL_FAST_KEY = "fail-fast"
# The pinned cap of the `check` matrix: the number of its legs (#9682).
EXPECTED_CAP = 4

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
    ],
    # #9680 moved the audit and the release smoke to the android entry.
    "mobile-cross-compile": [
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
STRATEGY_HEAD = re.compile(r"^    strategy:\s*$")
LEG_ENTRY = re.compile(r"^          - (?:leg|target):\s*(\S.*?)\s*$")
INDENT_CAP = 6
INDENT_MATRIX_AXIS = 8
PLAIN_INT = re.compile(r"\d+")
PLAIN_FALSE = re.compile(r"false")
TRAILING_COMMENT = re.compile(r"\s+#.*$")


class PinError(AssertionError):
    """A form of the workflow the pin cannot read or count (a red, not a skip)."""


def lines():
    try:
        return WORKFLOW.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise PinError("workflow file %s is unreadable (%s)" % (WORKFLOW, exc))


def top_level_and_jobs():
    """Return (lines before the top-level `jobs:` key, job id -> its lines)."""
    src = lines()
    if "jobs:" not in src:
        raise PinError("workflow %s has no top-level `jobs:` key" % WORKFLOW)
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
    return src[:start], out


def jobs():
    """Map job id -> list of its lines, from the top-level `jobs:` key on."""
    return top_level_and_jobs()[1]


def job_of(jid):
    all_jobs = jobs()
    if jid not in all_jobs:
        raise PinError("job %s is missing from the workflow" % jid)
    return all_jobs[jid]


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
    return [ln for ln in body if ln.strip() and not ln.lstrip().startswith("#")]


def indent_of(ln):
    return len(ln) - len(ln.lstrip())


def strategy_block(jid, body):
    """The active lines of the job's single block-form `strategy:` mapping."""
    act = active(body)
    heads = [i for i, ln in enumerate(act) if re.match(r"^    strategy:", ln)]
    if not heads:
        return None
    if len(heads) > 1:
        raise PinError("job %s declares `strategy:` %d times" % (jid, len(heads)))
    if not STRATEGY_HEAD.match(act[heads[0]]):
        raise PinError("job %s: `strategy:` is not a block mapping (inline or "
                       "expression form: %r), so its cap cannot be read"
                       % (jid, act[heads[0]].strip()))
    block = []
    for ln in act[heads[0] + 1:]:
        if indent_of(ln) <= 4:
            break
        block.append(ln)
    return block


def read_cap(jid, body):
    """The plain-integer cap of the job's `strategy:` block, or None when the job
    carries no cap anywhere. Any unreadable form raises PinError, named."""
    act = active(body)
    mentions = [ln for ln in act if CAP_KEY in ln]
    if not mentions:
        return None
    block = strategy_block(jid, body)
    if block is None:
        raise PinError("job %s: %s appears but the job has no `strategy:` block"
                       % (jid, CAP_KEY))
    inside = [ln for ln in block if CAP_KEY in ln]
    if len(inside) != len(mentions):
        raise PinError("job %s: %s appears outside the `strategy:` block (for "
                       "example in `env:`), so it is not the real cap: %r"
                       % (jid, CAP_KEY, [ln.strip() for ln in mentions
                                         if ln not in inside]))
    if len(inside) != 1:
        raise PinError("job %s: `strategy:` carries %d %s keys, exactly one is "
                       "required" % (jid, len(inside), CAP_KEY))
    line = inside[0]
    m = re.match(r"^ {%d}%s:\s*(.*?)\s*$" % (INDENT_CAP, CAP_KEY), line)
    if not m:
        raise PinError("job %s: %s is not a direct key of `strategy:` (nested or "
                       "quoted key: %r)" % (jid, CAP_KEY, line.strip()))
    value = TRAILING_COMMENT.sub("", m.group(1))
    if not PLAIN_INT.fullmatch(value):
        raise PinError("job %s: %s is not a plain integer (quoted, expression or "
                       "empty value: %r)" % (jid, CAP_KEY, value))
    return int(value)


def read_fail_fast(jid, body):
    """True only for a plain `fail-fast: false` directly in the strategy block."""
    block = strategy_block(jid, body)
    if block is None:
        raise PinError("job %s has no `strategy:` block, so %s is missing"
                       % (jid, FAIL_FAST_KEY))
    found = [ln for ln in block if FAIL_FAST_KEY in ln]
    if len(found) != 1:
        raise PinError("job %s: `strategy:` carries %d %s keys, exactly one "
                       "`%s: false` is required"
                       % (jid, len(found), FAIL_FAST_KEY, FAIL_FAST_KEY))
    m = re.match(r"^ {%d}%s:\s*(.*?)\s*$" % (INDENT_CAP, FAIL_FAST_KEY), found[0])
    if not m:
        raise PinError("job %s: %s is not a direct key of `strategy:` (%r)"
                       % (jid, FAIL_FAST_KEY, found[0].strip()))
    return bool(PLAIN_FALSE.fullmatch(TRAILING_COMMENT.sub("", m.group(1))))


def count_legs(jid, body):
    """The leg names of the job's `matrix: include:` list; a matrix this cannot
    count (list form, extra axes, no include entries) raises PinError, named."""
    block = strategy_block(jid, body)
    if block is None:
        raise PinError("job %s has no `strategy:` block, so its legs cannot be "
                       "counted" % jid)
    if not any(re.match(r"^      matrix:\s*$", ln) for ln in block):
        raise PinError("job %s: `matrix:` is not a block mapping, so its legs "
                       "cannot be counted" % jid)
    axes = [ln.strip() for ln in block
            if indent_of(ln) == INDENT_MATRIX_AXIS and not ln.strip().startswith("include:")]
    if axes:
        raise PinError("job %s: matrix has axes besides `include:` (%r), so its "
                       "legs cannot be counted" % (jid, axes))
    if not any(re.match(r"^        include:\s*$", ln) for ln in block):
        raise PinError("job %s: matrix has no `include:` list, so its legs "
                       "cannot be counted" % jid)
    found = [m.group(1).strip("\"'") for ln in block
             for m in [LEG_ENTRY.match(ln)] if m]
    if not found:
        raise PinError("job %s: no `- leg:` or `- target:` entries under "
                       "`include:`, so its legs cannot be counted" % jid)
    return found


class RequiredContexts(unittest.TestCase):
    def test_job_names_are_exactly_the_pinned_set(self):
        actual = {jid: job_name(body) for jid, body in jobs().items()}
        for jid in sorted(set(actual) | set(EXPECTED_JOB_NAMES)):
            self.assertEqual(actual.get(jid), EXPECTED_JOB_NAMES.get(jid),
                             "job %s: name differs from the pinned required context" % jid)

    def test_check_legs_are_exactly_the_four_pinned_contexts(self):
        self.assertEqual(sorted(count_legs(CHECK_JOB, job_of(CHECK_JOB))),
                         EXPECTED_LEGS,
                         "job check: legs differ from the four pinned contexts")

    def test_test_bearing_steps_stay_in_their_job(self):
        all_jobs = jobs()
        for jid, wanted in EXPECTED_STEPS.items():
            self.assertIn(jid, all_jobs, "job %s is missing" % jid)
            names = step_names(all_jobs[jid])
            for step in wanted:
                self.assertIn(step, names, "%s lost step %r" % (jid, step))

    def test_check_still_needs_only_classify(self):
        needs = [ln for ln in active(job_of(CHECK_JOB)) if re.match(r"^    needs:", ln)]
        self.assertEqual([ln.strip() for ln in needs], ["needs: classify"],
                         "job check: `needs:` changed from classify only")


class MaxParallel(unittest.TestCase):
    def test_check_cap_is_the_pinned_plain_integer_in_strategy(self):
        self.assertEqual(read_cap(CHECK_JOB, job_of(CHECK_JOB)), EXPECTED_CAP,
                         "job check: %s differs from the pinned %d (or is missing)"
                         % (CAP_KEY, EXPECTED_CAP))

    def test_check_cap_covers_every_counted_leg(self):
        body = job_of(CHECK_JOB)
        cap = read_cap(CHECK_JOB, body)
        self.assertIsNotNone(cap, "job check: %s is missing, so legs queue" % CAP_KEY)
        counted = count_legs(CHECK_JOB, body)
        self.assertGreaterEqual(
            cap, len(counted),
            "job check: %s %d is below the %d counted legs %r"
            % (CAP_KEY, cap, len(counted), counted))

    def test_check_matrix_does_not_fail_fast(self):
        self.assertTrue(
            read_fail_fast(CHECK_JOB, job_of(CHECK_JOB)),
            "job check: `strategy:` must carry `%s: false` (true would cancel "
            "required legs on the first red)" % FAIL_FAST_KEY)

    def test_no_job_with_a_cap_caps_below_its_counted_legs(self):
        for jid, body in jobs().items():
            cap = read_cap(jid, body)
            if cap is None:
                continue
            counted = count_legs(jid, body)
            self.assertGreaterEqual(
                cap, len(counted),
                "job %s: %s %d is below the %d counted legs" % (jid, CAP_KEY, cap, len(counted)))

    def test_no_cap_key_outside_a_job(self):
        head, _ = top_level_and_jobs()
        self.assertEqual(
            [ln for ln in active(head) if CAP_KEY in ln], [],
            "workflow level (before `jobs:`): %s appears outside any job" % CAP_KEY)


class CapReaderRefusals(unittest.TestCase):
    """The readers on hand-written job bodies: every unreadable form is a named
    refusal, and the one plain form is read. Green without any mutant."""

    HEAD = ["    runs-on: x"]
    GOOD = ["    strategy:",
            "      fail-fast: false",
            "      max-parallel: 4",
            "      matrix:",
            "        include:",
            "          - leg: a",
            "          - leg: b"]

    def body(self, replace=None, extra_job_lines=()):
        out = list(self.HEAD) + list(self.GOOD)
        for old, new in (replace or {}).items():
            out = [new if ln == old else ln for ln in out]
        return [ln for ln in out if ln is not None] + list(extra_job_lines)

    def refused(self, body, fragment, reader=read_cap):
        with self.assertRaisesRegex(PinError, fragment):
            reader("jobX", body)

    def test_plain_form_is_read(self):
        self.assertEqual(read_cap("jobX", self.body()), 4, "job jobX: plain cap")
        self.assertTrue(read_fail_fast("jobX", self.body()), "job jobX: plain fail-fast")
        self.assertEqual(count_legs("jobX", self.body()), ["a", "b"], "job jobX: legs")

    def test_no_cap_anywhere_is_none_not_a_refusal(self):
        body = [ln for ln in self.body() if "max-parallel" not in ln]
        self.assertIsNone(read_cap("jobX", body), "job jobX: no cap")

    def test_quoted_value_is_refused(self):
        self.refused(self.body({"      max-parallel: 4": "      max-parallel: '3'"}),
                     "not a plain integer")

    def test_expression_value_is_refused(self):
        self.refused(self.body({"      max-parallel: 4": "      max-parallel: ${{ 4 }}"}),
                     "not a plain integer")

    def test_stray_cap_in_env_is_refused_even_with_a_quoted_real_cap(self):
        body = self.body({"      max-parallel: 4": "      max-parallel: '3'"},
                         extra_job_lines=["    env:", "      max-parallel: 4"])
        self.refused(body, "outside the `strategy:` block")

    def test_cap_moved_out_of_strategy_is_refused(self):
        body = self.body({"      max-parallel: 4": None},
                         extra_job_lines=["    env:", "      max-parallel: 4"])
        self.refused(body, "outside the `strategy:` block")

    def test_two_cap_keys_in_strategy_are_refused(self):
        body = self.body()
        body.insert(len(self.HEAD) + 3, "      max-parallel: 4")
        self.refused(body, "carries 2 max-parallel keys")

    def test_cap_without_a_strategy_block_is_refused(self):
        self.refused(["    runs-on: x", "    env:", "      max-parallel: 4"],
                     "no `strategy:` block")

    def test_inline_strategy_is_refused(self):
        self.refused(["    strategy: ${{ fromJson(needs.x.outputs.s) }}",
                      "      max-parallel: 4"], "not a block mapping")

    def test_nested_cap_key_is_refused(self):
        self.refused(self.body({"      max-parallel: 4": "        max-parallel: 4"}),
                     "not a direct key")

    def test_fail_fast_true_quoted_expression_or_missing_is_not_green(self):
        for form in ("      fail-fast: true", "      fail-fast: 'false'",
                     "      fail-fast: ${{ false }}"):
            body = self.body({"      fail-fast: false": form})
            self.assertFalse(read_fail_fast("jobX", body), "job jobX: %s" % form)
        missing = self.body({"      fail-fast: false": None})
        self.refused(missing, "carries 0 fail-fast keys", reader=read_fail_fast)

    def test_uncountable_matrices_are_refused(self):
        listed = ["    strategy:", "      max-parallel: 1", "      matrix:",
                  "        leg: [a, b, c, d]"]
        self.refused(listed, "axes besides `include:`", reader=count_legs)
        no_entries = ["    strategy:", "      matrix:", "        include:"]
        self.refused(no_entries, "cannot be counted", reader=count_legs)
        expression = ["    strategy:", "      matrix: ${{ fromJson(x) }}"]
        self.refused(expression, "not a block mapping", reader=count_legs)

    def test_unreadable_file_is_a_named_red(self):
        global WORKFLOW
        saved = WORKFLOW
        try:
            WORKFLOW = saved.parent / "no-such-workflow-9682.yml"
            with self.assertRaisesRegex(PinError, "is unreadable"):
                lines()
        finally:
            WORKFLOW = saved


class HostGuards(unittest.TestCase):
    def test_semaphore_slots_are_two_on_linux_fed_enterprise_fed(self):
        body = "\n".join(job_of(CHECK_JOB))
        m = re.search(r"HOST_SEMAPHORE_SLOTS: \$\{\{ (.+?) \}\}", body)
        self.assertIsNotNone(m, "job check: HOST_SEMAPHORE_SLOTS expression is missing")
        self.assertIn("'%s' || '0'" % EXPECTED_SEMAPHORE_SLOTS, m.group(1),
                      "job check: leg linux-fed,enterprise-fed lost its 2 slots")
        self.assertIn("matrix.node == 'linux-fed'", m.group(1),
                      "job check: the semaphore slots are no longer keyed to linux-fed")
        self.assertIn("--name linux-fed-tests --slots \"$HOST_SEMAPHORE_SLOTS\"", body,
                      "job check: the semaphore invocation changed")

    def test_load_gate_runs_before_the_tests(self):
        names = step_names(job_of(CHECK_JOB))
        self.assertLess(names.index("Load gate (#6795)"),
                        names.index("Run tests (impact-aware)"),
                        "job check: the load gate no longer runs before the tests")

    def test_no_job_declares_a_job_level_concurrency_group(self):
        for jid, body in jobs().items():
            self.assertFalse(
                [ln for ln in active(body) if re.match(r"^    concurrency:", ln)],
                "%s declares a job-level concurrency group" % jid)

    def test_semaphore_name_is_used_only_by_its_own_flag_in_check(self):
        check = "\n".join(job_of(CHECK_JOB))
        self.assertNotIn(
            "linux-fed-tests", re.sub(r"--name linux-fed-tests", "", check),
            "job check: the host semaphore name linux-fed-tests is used outside "
            "its `--name` flag")


if __name__ == "__main__":
    unittest.main()
