#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the #9821 admission rule (I5): drafts do not occupy self-hosted runners,
and a leg that did not run never reports success.

Invariant (PR 9838 class A): for every required `Check (...)` context and every
pull-request state (draft or ready, `ci-fix` or not, fork or not, a re-run of a
draft-era run), a leg whose real work did not run concludes `failure`, never
`success`.  A self-hosted leg of a draft pull request without `ci-fix` flips to
a hosted runner (it never waits in the self-hosted queue) and its one step that
runs fails with the exact line DRAFT_ERROR.  `ci-fix` is the one label that
admits a draft; there is no other.  An unknown draft state is not `== true`, so
the leg runs (fails open to run, never to skip).

How the skip is made without changing a required name (rule (b1) of
scripts/check-required-contexts.sh forbids a job-level `if:` on this matrix
job): a job-level env `LEG_SKIP` carries the decision, `runs-on` flips a
skipped leg to a hosted runner, and every step that does work carries
`env.LEG_SKIP != 'true'` next to its `cargo_skip` guard.  The fork refusal is
NOT guarded by LEG_SKIP: a draft fork pull request fails on the fork refusal,
as at the base.

A re-run of a draft-era run reuses that run's frozen event payload, so LEG_SKIP
stays 'true' and the re-run stays red; the run GitHub starts on
`ready_for_review` is a new run with the new payload and runs the legs.

The allow and deny tables below are hand-written.  The real expression is read
from the workflow and evaluated by a small evaluator for the expression subset
(&&, ||, !, ==, !=, contains, fromJSON) so the table tests the shipped text, and
the steps that run before checkout are executed in bash so the conclusion is
measured, not read.  The workflow under test is ci.yml or the file named by
WORKFLOW_UNDER_TEST.

Run: python3.12 -m unittest scripts/ci/tests/test_ci_draft_admission_9821.py
Python 3.12+, standard library only (the workflow is read by line).
"""
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORKFLOW = Path(os.environ.get("WORKFLOW_UNDER_TEST") or REPO / ".github" / "workflows" / "ci.yml")
GATE_PY = REPO / "scripts" / "ci" / "impact" / "gate.py"
NOT_REQUIRED_LEDGER = REPO / "scripts" / "qc-allowlists" / "required-contexts-not-required.txt"
SCRATCH = REPO / ".local-runs"
CHECK_JOB = "check"
SKIP_ENV = "LEG_SKIP"
SKIP_GUARD = "env.LEG_SKIP != 'true'"
CARGO_GUARD = "needs.classify.outputs.cargo_skip != 'true'"
HOSTED = '["ubuntu-latest"]'
LINUX_FED = '["self-hosted","linux-fed"]'
MACOS_FED = '["self-hosted","macos-fed"]'
EXPECTED_LEGS = ["ubuntu-latest,sqlite", "linux-fed,enterprise-fed", "macos-fed,sqlite", "macos-fed,enterprise-fed"]
EXPECTED_CHECK_NAME = "Check (${{ matrix.leg }})"
# Vote DSP2 A-4: the ONE place that holds the skip step's exact name and its exit line.  The agent-skills
# constant SKIP_STEP_NAME (skills/pre-merge-checklist/scripts/draft_skip.py, PR 558 head d362912d,
# line 47) is the READER of this name: its gates count a leg as draft-skipped only when a step has
# this exact name.  A rename here or in ci.yml fails test_skip_step_pin_name_and_exit_in_one_place
# in this repository; change both repositories together (vote DSP1 A-3, DSP2 A-4).
SKIP_STEP_NAME = "Draft skip (#9821)"
SKIP_EXIT_LINE = "exit 1"
NEUTRALISER = "continue-on-error"  # swallows the red; banned on the check job and its steps (vote DSP1 A-1)
EXIT_FAIL = 1
FORK_STEP = "Fork-PR refusal (self-hosted legs never run fork code)"
CHECKOUT_PREFIX = "actions/checkout"
ADMIT_LABEL = "ci-fix"
UNKNOWN_LABEL = "run-self-hosted"  # never created (b29 07d44e43); it admits nothing
REMOVED_JOB = "draft-admission"
DRAFT_ERROR = "::error::draft PR without the ci-fix label, self-hosted leg not run, mark ready or add the label"
FORK_ERROR = "::error::Refusing to run fork PR code on a self-hosted runner (leg %s)."
REPOSITORY = "alphaonedev/ai-memory-mcp"
FORK_REPOSITORY = "someone/ai-memory-mcp"
STEP_TIMEOUT_SECS = 30
# Vote DSP2 A-5: every job that holds the skip step, written out (never computed from the workflow).
EXPECTED_SKIP_JOBS = ["check"]
# The steps of such a job that do NOT carry SKIP_GUARD, by name, written out: the skip step itself and
# the checkout (a skipped leg checks out on a hosted runner), plus the two steps that already were
# unguarded at the base and cannot run next to the skip step's success-looking leg: the fork refusal
# (exits 1, so a draft fork leg stays red; pinned below) and the cargo_skip short-circuit (its `if` is
# the exact complement of the skip step's cargo_skip guard, pinned below, so it never runs on a leg the
# skip step runs on).  Nothing else.
CARGO_SKIP_STEP = "cargo_skip short-circuit"
CARGO_SKIP_ONLY_IF = "needs.classify.outputs.cargo_skip == 'true'"
EXPECTED_UNGUARDED = sorted([SKIP_STEP_NAME, FORK_STEP, CHECKOUT_PREFIX, CARGO_SKIP_STEP])
FAILURE = "failure"
WORK_RUNS = "work runs"  # the real work steps run; their own result decides the conclusion
FROZEN_CONTEXTS = {
    "github.event_name",
    "github.event.pull_request.draft",
    "github.event.pull_request.labels.*.name",
    "matrix.runner",
}


# ---------------------------------------------------------- expression ----


def tokenize(text):
    pattern = re.compile(r"\s*(&&|\|\||!=|==|!|\(|\)|,|'(?:[^']|'')*'|[A-Za-z_][A-Za-z0-9_.*-]*)")
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = pattern.match(text, pos)
        if not m:
            raise ValueError("cannot tokenize at %r" % text[pos:pos + 20])
        out.append(m.group(1))
        pos = m.end()
    return out


class Evaluator:
    """GitHub expression subset; JS-like truthiness; && and || return operands."""

    def __init__(self, tokens, context):
        self.t, self.i, self.ctx = tokens, 0, context

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, expect=None):
        tok = self.peek()
        if tok is None or (expect is not None and tok != expect):
            raise ValueError("expected %r got %r" % (expect, tok))
        self.i += 1
        return tok

    @staticmethod
    def truthy(value):
        return value not in (False, None, 0, "")

    def parse(self):
        value = self.or_()
        if self.peek() is not None:
            raise ValueError("trailing %r" % self.peek())
        return value

    def or_(self):
        left = self.and_()
        while self.peek() == "||":
            self.take()
            right = self.and_()
            left = left if self.truthy(left) else right
        return left

    def and_(self):
        left = self.eq()
        while self.peek() == "&&":
            self.take()
            right = self.eq()
            left = right if self.truthy(left) else left
        return left

    def eq(self):
        left = self.unary()
        while self.peek() in ("==", "!="):
            op = self.take()
            right = self.unary()
            same = left == right
            left = same if op == "==" else not same
        return left

    def unary(self):
        if self.peek() == "!":
            self.take()
            return not self.truthy(self.unary())
        return self.atom()

    def atom(self):
        tok = self.take()
        if tok == "(":
            value = self.or_()
            self.take(")")
            return value
        if tok.startswith("'"):
            return tok[1:-1].replace("''", "'")
        if tok in ("true", "false"):
            return tok == "true"
        if self.peek() == "(":
            self.take("(")
            args = []
            while self.peek() != ")":
                args.append(self.or_())
                if self.peek() == ",":
                    self.take()
            self.take(")")
            return self.call(tok, args)
        if tok not in self.ctx:
            raise ValueError("unknown context %r" % tok)
        return self.ctx[tok]

    @staticmethod
    def call(name, args):
        if name == "contains":
            search, item = args
            if isinstance(search, list):
                return item in search
            return isinstance(search, str) and isinstance(item, str) and item in search
        if name == "fromJSON":
            return args[0]
        raise ValueError("unknown function %r" % name)


def context(event, draft, labels, runner, fork=False, leg_skip=None):
    ctx = {
        "github.event_name": event,
        "github.event.pull_request.draft": draft,
        "github.event.pull_request.labels.*.name": list(labels),
        "github.event.pull_request.head.repo.full_name": FORK_REPOSITORY if fork else REPOSITORY,
        "github.repository": REPOSITORY,
        "matrix.runner": runner,
        "needs.classify.outputs.cargo_skip": "false",
    }
    if leg_skip is not None:
        ctx["env.LEG_SKIP"] = leg_skip
    return ctx


def evaluate(expr, event, draft, labels, runner):
    return Evaluator(tokenize(expr), context(event, draft, labels, runner)).parse()


def referenced(expr):
    """Context names an expression reads (not literals, operators or function names)."""
    toks = tokenize(expr)
    out = set()
    for i, tok in enumerate(toks):
        if tok.startswith("'") or tok in ("&&", "||", "!", "==", "!=", "(", ")", ",", "true", "false"):
            continue
        if i + 1 < len(toks) and toks[i + 1] == "(":
            continue
        out.add(tok)
    return out


# ----------------------------------------------------------- workflow ----


def workflow_lines():
    return WORKFLOW.read_text(encoding="utf-8").splitlines()


def job_names():
    return [m.group(1) for m in (re.match(r"  ([A-Za-z0-9_-]+):\s*$", l) for l in workflow_lines()) if m]


def job_block(job):
    lines = workflow_lines()
    start = next((i for i, l in enumerate(lines) if l == "  %s:" % job), None)
    if start is None:
        raise AssertionError("job %s not found in %s" % (job, WORKFLOW))
    end = next((i for i in range(start + 1, len(lines)) if re.match(r"  [A-Za-z0-9_-]+:\s*$", lines[i])), len(lines))
    return lines[start:end]


def check_block():
    return job_block(CHECK_JOB)


def wrapped(line, key):
    """Value of `key: ${{ ... }}` on one line, the expression inside the braces."""
    m = re.match(r"\s*%s:\s*\$\{\{\s*(.*?)\s*\}\}\s*$" % re.escape(key), line)
    return m.group(1) if m else None


def job_expr(key):
    found = [wrapped(l, key) for l in check_block() if l.startswith(("    %s:" % key, "      %s:" % key))]
    found = [f for f in found if f is not None]
    if len(found) != 1:
        raise AssertionError("expected exactly one %s expression in job %s, found %d" % (key, CHECK_JOB, len(found)))
    return found[0]


def step_records(block=None):
    """[{name, if, run, continue-on-error}] of the check job (or of the given job block) in order; one-line if, `run: |` blocks."""
    out, in_steps, cur, in_run = [], False, None, False
    for line in (check_block() if block is None else block):
        if line == "    steps:":
            in_steps = True
            continue
        if not in_steps:
            continue
        if line.startswith("      - "):
            m = re.match(r"      - (?:name: (.*)|uses: (.*))", line)
            cur = {"name": (m.group(1) or m.group(2)) if m else line.strip(), "if": None, "run": None, NEUTRALISER: None}
            out.append(cur)
            in_run = False
            continue
        if cur is None:
            continue
        if in_run:
            if line.startswith("          ") or not line.strip():
                cur["run"] += line[10:] + "\n"
                continue
            in_run = False
        if line.startswith("        if:") and cur["if"] is None:
            value = line.split("if:", 1)[1].strip()
            if value.startswith((">", "|")):
                raise AssertionError("multi-line if in step %r cannot be read" % cur["name"])
            cur["if"] = value
        elif line.startswith("        %s:" % NEUTRALISER):
            cur[NEUTRALISER] = line.split(":", 1)[1].strip()
        elif line.startswith("        run: |"):
            cur["run"], in_run = "", True
        elif line.startswith("        run: "):
            cur["run"] = line.split("run: ", 1)[1] + "\n"
    return out


def steps():
    return [(s["name"], s["if"]) for s in step_records()]


def matrix_legs():
    """[(leg, runner)] from the include list of the check job."""
    block = check_block()
    out = []
    for i, line in enumerate(block):
        m = re.match(r"          - leg: (.*)", line)
        if m:
            runner = next(re.match(r"            runner: '(.*)'", l).group(1) for l in block[i + 1:] if re.match(r"            runner: ", l))
            out.append((m.group(1), runner))
    return out


def run_step(script, leg):
    """Run one step's script in bash as the runner would; (rc, stdout lines)."""
    if "${{" in script.replace("${{ matrix.leg }}", ""):
        raise AssertionError("step script holds an expression this test does not model: %r" % script)
    SCRATCH.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=SCRATCH) as tmp:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GITHUB_ENV": str(Path(tmp) / "env"), "HOME": tmp}
        proc = subprocess.run(["bash", "-e", "-c", script.replace("${{ matrix.leg }}", leg)], env=env, cwd=tmp,
                              capture_output=True, text=True, timeout=STEP_TIMEOUT_SECS)
    return proc.returncode, proc.stdout.splitlines()


def conclusion(leg, runner, event, draft, labels, fork=False):
    """(conclusion, failing step, its ::error:: line) of one leg up to checkout.

    Every step before checkout whose `if` holds is executed; the first that
    exits non-zero fails the job, unless it is continue-on-error (any value but
    the absent key is taken as on, as an expression can turn it on).  If none
    fails the work steps run.
    """
    leg_skip = Evaluator(tokenize(job_expr(SKIP_ENV)), context(event, draft, labels, runner)).parse()
    ctx = context(event, draft, labels, runner, fork=fork, leg_skip=leg_skip)
    for step in step_records():
        if step["name"].startswith(CHECKOUT_PREFIX):
            return WORK_RUNS if leg_skip != "true" else "success", None, None
        cond = step["if"] or "true"
        if not Evaluator.truthy(Evaluator(tokenize(cond), ctx).parse()):
            continue
        if step["run"] is None:
            continue
        rc, out = run_step(step["run"], leg)
        if rc != 0 and step[NEUTRALISER] in (None, "false"):
            errors = [l for l in out if l.startswith("::error::")]
            return FAILURE, step["name"], errors[0] if len(errors) == 1 else errors
    raise AssertionError("checkout step not found")


def job_neutralisers():
    """Lines of the check job that can turn a red leg green or skipped: a job-level `if:`
    (the leg becomes skipped) or any continue-on-error key, at job, matrix or step level."""
    return [l.strip() for l in check_block()
            if l.startswith("    if:") or re.match(r"\s*(?:- )?%s\s*:" % re.escape(NEUTRALISER), l)]


def top_level_conjuncts(cond):
    """Token lists of the `&&`-separated parts of an if expression at parenthesis depth 0, or None.

    None (unclassifiable, so the step counts as unguarded) when the text does not tokenize, has a
    `||` at depth 0, has unbalanced parentheses, or is empty.  Fail closed: a form this test cannot
    read never counts as a guard.
    """
    try:
        toks = tokenize(cond)
    except ValueError:
        return None
    parts, cur, depth = [], [], 0
    for tok in toks:
        if tok == "(":
            depth += 1
        elif tok == ")":
            depth -= 1
            if depth < 0:
                return None
        elif depth == 0 and tok == "||":
            return None
        if depth == 0 and tok == "&&":
            parts.append(cur)
            cur = []
        else:
            cur.append(tok)
    parts.append(cur)
    return None if depth != 0 or not toks or any(not p for p in parts) else parts


def has_leg_skip_guard(cond):
    """True only when SKIP_GUARD is one whole top-level `&&` conjunct of the step's one-line `if`."""
    if not cond:
        return False
    parts = top_level_conjuncts(cond)
    return parts is not None and tokenize(SKIP_GUARD) in parts


def unguarded_step_names(block):
    """Sorted names of the job's steps without the SKIP_GUARD conjunct; every checkout counts as CHECKOUT_PREFIX."""
    return sorted(CHECKOUT_PREFIX if s["name"].startswith(CHECKOUT_PREFIX) else s["name"]
                  for s in step_records(block) if not has_leg_skip_guard(s["if"]))


def jobs_with_skip_step():
    return [j for j in job_names() if any(s["name"] == SKIP_STEP_NAME for s in step_records(job_block(j)))]


# ---------------------------------------------------------------- tests ----


class AdmissionTables(unittest.TestCase):
    """Allow (leg runs) and deny (leg skipped) rows, written by hand."""

    # (event, draft, labels, runner, leg is skipped)
    ROWS = [
        ("pull_request", True, [], LINUX_FED, True),
        ("pull_request", True, [], MACOS_FED, True),
        ("pull_request", True, ["bug"], LINUX_FED, True),
        ("pull_request", True, [ADMIT_LABEL], LINUX_FED, False),
        ("pull_request", True, [UNKNOWN_LABEL], MACOS_FED, True),  # not a label: it admits nothing
        ("pull_request", True, [UNKNOWN_LABEL], LINUX_FED, True),
        ("pull_request", True, ["bug", ADMIT_LABEL, UNKNOWN_LABEL], LINUX_FED, False),
        ("pull_request", False, [], LINUX_FED, False),
        ("pull_request", False, [ADMIT_LABEL], LINUX_FED, False),
        ("pull_request", None, [], LINUX_FED, False),  # unknown draft state fails open: the leg runs
        ("pull_request", True, [], HOSTED, False),  # the hosted leg is never skipped
        ("push", None, [], LINUX_FED, False),
        ("merge_group", None, [], LINUX_FED, False),
        ("workflow_dispatch", None, [], LINUX_FED, False),
        ("schedule", None, [], MACOS_FED, False),
    ]

    def test_leg_skip_table(self):
        expr = job_expr(SKIP_ENV)
        for event, draft, labels, runner, skipped in self.ROWS:
            with self.subTest(event=event, draft=draft, labels=labels, runner=runner):
                got = evaluate(expr, event, draft, labels, runner)
                self.assertEqual(Evaluator.truthy(got) and got == "true", skipped)

    def test_runs_on_table(self):
        expr = job_expr("runs-on")
        for event, draft, labels, runner, skipped in self.ROWS:
            with self.subTest(event=event, draft=draft, labels=labels, runner=runner):
                got = evaluate(expr, event, draft, labels, runner)
                self.assertEqual(got, HOSTED if skipped else runner)

    def test_runs_on_and_env_share_one_condition(self):
        runs_on = job_expr("runs-on")
        leg_skip = job_expr(SKIP_ENV)
        m = re.match(r"fromJSON\((.*) && '\[\"ubuntu-latest\"\]' \|\| matrix\.runner\)$", runs_on)
        self.assertIsNotNone(m, "runs-on is not fromJSON(<condition> && hosted || matrix.runner): %s" % runs_on)
        self.assertEqual(leg_skip, "%s && 'true' || 'false'" % m.group(1))


class SkippedLegConclusion(unittest.TestCase):
    """PR 9838 class A: a skipped leg concludes failure, never success, under its required name.

    One test per self-hosted context; rows are (draft, labels, fork) -> (conclusion,
    failing step, exact ::error:: line).  The steps before checkout are run in bash.
    """

    def legs(self):
        legs = dict(matrix_legs())
        self.assertEqual(list(legs), EXPECTED_LEGS)
        return legs

    def rows(self, leg):
        fork_error = FORK_ERROR % leg
        return [
            (True, [], False, (FAILURE, SKIP_STEP_NAME, DRAFT_ERROR)),
            (True, ["bug"], False, (FAILURE, SKIP_STEP_NAME, DRAFT_ERROR)),
            (True, [UNKNOWN_LABEL], False, (FAILURE, SKIP_STEP_NAME, DRAFT_ERROR)),
            (True, [], True, (FAILURE, FORK_STEP, fork_error)),  # a draft fork fails on the fork refusal, as at base
            (True, [ADMIT_LABEL], True, (FAILURE, FORK_STEP, fork_error)),
            (False, [], True, (FAILURE, FORK_STEP, fork_error)),
            (True, [ADMIT_LABEL], False, (WORK_RUNS, None, None)),
            (False, [], False, (WORK_RUNS, None, None)),
            (None, [], False, (WORK_RUNS, None, None)),
        ]

    def check_context(self, leg):
        # Vote DSP1 A-1: the red is job-level under this context's name, so nothing on the
        # job may turn it green (continue-on-error) or skipped (a job-level if:).
        self.assertEqual(job_neutralisers(), [], "Check (%s) can end green or skipped, not red" % leg)
        runner = self.legs()[leg]
        for draft, labels, fork, want in self.rows(leg):
            with self.subTest(context="Check (%s)" % leg, draft=draft, labels=labels, fork=fork):
                self.assertEqual(conclusion(leg, runner, "pull_request", draft, labels, fork), want)

    def test_context_linux_fed_enterprise_fed_skip_is_failure(self):
        self.check_context("linux-fed,enterprise-fed")

    def test_context_macos_fed_sqlite_skip_is_failure(self):
        self.check_context("macos-fed,sqlite")

    def test_context_macos_fed_enterprise_fed_skip_is_failure(self):
        self.check_context("macos-fed,enterprise-fed")

    def test_hosted_context_never_skips(self):
        runner = self.legs()["ubuntu-latest,sqlite"]
        for draft, labels, fork in [(True, [], False), (True, [], True), (False, [], False)]:
            with self.subTest(draft=draft, labels=labels, fork=fork):
                self.assertEqual(conclusion("ubuntu-latest,sqlite", runner, "pull_request", draft, labels, fork),
                                 (WORK_RUNS, None, None))

    def test_rerun_of_draft_era_run_stays_red(self):
        # The skip reads only the frozen event payload and the matrix: a re-run of a
        # draft-era run (after ready_for_review or after the label) sees draft == true
        # again and fails again.  Only the new run of the ready_for_review event runs.
        self.assertLessEqual(referenced(job_expr(SKIP_ENV)), FROZEN_CONTEXTS)
        self.assertLessEqual(referenced(job_expr("runs-on")), FROZEN_CONTEXTS)
        frozen = (True, [])
        self.assertEqual(conclusion("linux-fed,enterprise-fed", LINUX_FED, "pull_request", *frozen),
                         (FAILURE, SKIP_STEP_NAME, DRAFT_ERROR))
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(text, r"\n    types: \[opened, synchronize, reopened, ready_for_review\]\n")


class StepPins(unittest.TestCase):
    def test_every_cargo_guarded_step_also_honours_leg_skip(self):
        seen = 0
        for name, cond in steps():
            if cond and CARGO_GUARD in cond and name not in (SKIP_STEP_NAME, FORK_STEP):
                seen += 1
                self.assertIn(SKIP_GUARD, cond, "step %r does not honour %s" % (name, SKIP_ENV))
        self.assertGreaterEqual(seen, 25)  # the guarded steps counted at the base sha are 29

    def test_checkout_stays_unguarded(self):
        for name, cond in steps():
            if name.startswith(CHECKOUT_PREFIX):
                self.assertEqual(cond, None)  # rule b3 exempts checkout; a skipped leg checks out on a hosted runner
                return
        self.fail("checkout step not found")

    def test_fork_refusal_is_not_guarded_by_the_draft_rule(self):
        by_name = dict(steps())
        self.assertNotIn(SKIP_ENV, by_name[FORK_STEP])

    def test_draft_step_guard(self):
        by_name = dict(steps())
        # rule (b3) of check-required-contexts.sh wants a cargo_skip/docs_only guard on every step
        self.assertEqual(by_name[SKIP_STEP_NAME], "%s && env.%s == 'true'" % (CARGO_GUARD, SKIP_ENV))
        self.assertNotIn("GH_TOKEN", "\n".join(check_block()))  # a secret here is a tainted-job violation

    def test_skip_step_one_error_exit_1_on_hosted(self):
        # Vote DSP1 A-2: the skip step prints exactly one ::error:: line, the pinned text, and
        # exits 1; every self-hosted leg it fails is placed on the hosted runner first.
        step = next(s for s in step_records() if s["name"] == SKIP_STEP_NAME)
        self.assertIsNone(step[NEUTRALISER])
        rc, out = run_step(step["run"], "linux-fed,enterprise-fed")
        self.assertEqual(rc, EXIT_FAIL)
        self.assertEqual([l for l in out if "::error::" in l], [DRAFT_ERROR])
        for leg, runner in matrix_legs():
            if "self-hosted" in runner:
                with self.subTest(context="Check (%s)" % leg):
                    self.assertEqual(evaluate(job_expr("runs-on"), "pull_request", True, [], runner), HOSTED)

    def test_skip_step_pin_name_and_exit_in_one_place(self):
        # Vote DSP2 A-4 (3-agent vote 71472661).  The agent-skills gates find a draft-skipped
        # leg by this exact step name only (SKIP_STEP_NAME, draft_skip.py); a rename here would
        # let them count the leg green, so it goes red in this repository.  The exit line is
        # the primary control: the run block ends in SKIP_EXIT_LINE with the one pinned ::error::.
        name_lines = [l for l in workflow_lines() if SKIP_STEP_NAME in l and not l.lstrip().startswith("#")]
        self.assertEqual(len(name_lines), 1, "the workflow must name %r on exactly one non-comment line" % SKIP_STEP_NAME)
        found = [s for s in step_records() if s["name"] == SKIP_STEP_NAME]
        self.assertEqual(len(found), 1, "the check job must hold exactly one %r step" % SKIP_STEP_NAME)
        self.assertIsNotNone(found[0]["run"], "the skip step must have a run block")
        run_lines = [l.strip() for l in found[0]["run"].splitlines() if l.strip()]
        self.assertEqual(run_lines[-1], SKIP_EXIT_LINE, "the skip step run block must end in %r" % SKIP_EXIT_LINE)
        self.assertEqual(run_lines.count(SKIP_EXIT_LINE), 1)
        self.assertEqual([l for l in run_lines if "::error::" in l], ['echo "%s"' % DRAFT_ERROR])

    def test_skip_step_jobs_are_exactly_the_expected_list(self):
        # Vote DSP2 A-5 (3-agent vote 71472661): a job that gains the skip step without being in
        # EXPECTED_SKIP_JOBS goes red, and so does a listed job that loses it.
        self.assertEqual(jobs_with_skip_step(), EXPECTED_SKIP_JOBS)

    def test_only_the_expected_steps_lack_the_leg_skip_guard(self):
        # Vote DSP2 A-5: in every job with the skip step, the steps without the LEG_SKIP guard are
        # exactly EXPECTED_UNGUARDED.  The agent-skills tools hold a success-concluding skip leg only
        # by the step name and only while no second unguarded step runs (900 real jobs: no step
        # count separates a draft-skipped leg from a ready cargo_skip leg).
        for job in EXPECTED_SKIP_JOBS:
            with self.subTest(job=job):
                self.assertEqual(unguarded_step_names(job_block(job)), EXPECTED_UNGUARDED)

    def test_the_two_other_unguarded_steps_cannot_run_beside_the_skip_leg(self):
        # Vote DSP2 A-5: the fork refusal fails the leg (run block ends in SKIP_EXIT_LINE) and the
        # cargo_skip short-circuit runs only when cargo_skip == 'true', the complement of the skip
        # step's guard, so a leg never runs both and a leg the skip step runs never reports success.
        for job in EXPECTED_SKIP_JOBS:
            records = {s["name"]: s for s in step_records(job_block(job))}
            with self.subTest(job=job):
                fork_run = [l.strip() for l in records[FORK_STEP]["run"].splitlines() if l.strip()]
                self.assertEqual(fork_run[-1], SKIP_EXIT_LINE)
                self.assertEqual(records[CARGO_SKIP_STEP]["if"], CARGO_SKIP_ONLY_IF)
                self.assertTrue(records[SKIP_STEP_NAME]["if"].startswith(CARGO_GUARD + " && "))

    def test_guard_classifier_fails_closed(self):
        # Hand-written table: (if expression, counts as guarded).  Only SKIP_GUARD as a whole
        # top-level && conjunct guards; every form the classifier cannot read, or that can let the step run
        # on a skipped leg, is unguarded.
        rows = [
            (SKIP_GUARD, True),
            ("%s && %s" % (CARGO_GUARD, SKIP_GUARD), True),
            ("%s && runner.environment == 'self-hosted' && %s" % (CARGO_GUARD, SKIP_GUARD), True),
            ("always() && %s && %s" % (CARGO_GUARD, SKIP_GUARD), True),
            ("always() && (a == 'b' || c == 'd') && %s" % SKIP_GUARD, True),  # a || inside parentheses
            (None, False),
            ("", False),
            (CARGO_GUARD, False),
            ("always()", False),
            ("%s && always()" % CARGO_GUARD, False),
            ("%s || always()" % SKIP_GUARD, False),
            ("%s || true" % SKIP_GUARD, False),
            ("%s && %s || true" % (CARGO_GUARD, SKIP_GUARD), False),
            ("(%s)" % SKIP_GUARD, False),  # parenthesised: not a whole conjunct, so unguarded (fail closed)
            ("!%s" % SKIP_GUARD, False),
            ("env.LEG_SKIP == 'true'", False),
            ("env.LEG_SKIP != 'false'", False),
            ("env.LEG_SKIP != 'true' || env.LEG_SKIP == 'true'", False),
            ("%s && (%s" % (CARGO_GUARD, SKIP_GUARD), False),  # unbalanced
            ("${{ %s }}" % SKIP_GUARD, False),  # does not tokenize
            ("%s && " % SKIP_GUARD, False),  # empty conjunct
            ("env.LEG_SKIP != 'true' @", False),  # does not tokenize
        ]
        for cond, guarded in rows:
            with self.subTest(cond=cond):
                self.assertEqual(has_leg_skip_guard(cond), guarded)

    def test_check_needs_only_classify(self):
        # security MEDIUM-1: no needs edge to a job that is not required.
        needs = [l.strip() for l in check_block() if l.startswith("    needs:")]
        self.assertEqual(needs, ["needs: classify"])  # the base form, byte for byte
        self.assertNotIn(REMOVED_JOB, job_names())
        gate = job_block("ci-gate")
        self.assertFalse([l for l in gate if l.strip() == "- %s" % REMOVED_JOB])
        self.assertNotIn('"%s"' % REMOVED_JOB, GATE_PY.read_text(encoding="utf-8"))
        self.assertNotIn(" %s " % REMOVED_JOB, NOT_REQUIRED_LEDGER.read_text(encoding="utf-8"))

    def test_no_reference_to_the_unknown_label(self):
        for path in (WORKFLOW, REPO / "docs" / "ci" / "CARRIER-BRANCH-GATES.md", REPO / "changelog.d" / "9821.changed.md"):
            with self.subTest(path=path.name):
                self.assertNotIn(UNKNOWN_LABEL, path.read_text(encoding="utf-8"))

    def test_ready_for_review_starts_a_run(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(text, r"\n    types: \[opened, synchronize, reopened, ready_for_review\]\n")
        self.assertNotIn("labeled", re.search(r"\n    types: \[[^\]]*\]\n", text).group(0))  # a label event cancels in-flight runs

    def test_required_names_unchanged(self):
        block = check_block()
        self.assertIn("    name: %s" % EXPECTED_CHECK_NAME, block)
        self.assertEqual([leg for leg, _ in matrix_legs()], EXPECTED_LEGS)
        self.assertFalse([l for l in block if l.startswith("    if:")], "job-level if on a matrix job breaks rule (b1)")


if __name__ == "__main__":
    unittest.main()
