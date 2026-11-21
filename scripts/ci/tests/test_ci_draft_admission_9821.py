#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the #9821 admission rule (I5): drafts do not occupy self-hosted runners.

Invariant: a self-hosted `Check` leg of ci.yml does not run for a draft pull
request unless it carries `ci-fix` or `run-self-hosted`; the leg still reports
(same job, same name, success), the hosted and the macOS-less hosted leg are
unaffected, and an unknown draft state fails open (the leg runs).

How the skip is made without changing a required name (rule (b1) of
scripts/check-required-contexts.sh forbids a job-level `if:` on this matrix
job): a job-level env `LEG_SKIP` carries the decision, `runs-on` flips a
skipped leg to a hosted runner so it never waits in the self-hosted queue, and
every step that does work carries `env.LEG_SKIP != 'true'` next to its
`cargo_skip` guard.  A skipped leg runs only the notice and the re-check step
which fails the leg unless the `draft-admission` job (one gh call and one jq
filter, no checkout, so no pull-request code can reach its token) re-read the
PR and still found a draft without either label: a stale re-run cannot turn a
now-ready PR into a green skip.

The allow and deny tables below are hand-written.  The real expression is read
from the workflow and evaluated by a small evaluator for the expression subset
(&&, ||, !, ==, !=, contains, fromJSON) so the table tests the shipped text.
The workflow under test is ci.yml or the file named by WORKFLOW_UNDER_TEST.

Run: python3.12 -m unittest scripts/ci/tests/test_ci_draft_admission_9821.py
Python 3.12+, standard library only (the workflow is read by line).
"""
import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WORKFLOW = Path(os.environ.get("WORKFLOW_UNDER_TEST") or REPO / ".github" / "workflows" / "ci.yml")

CHECK_JOB = "check"
SKIP_ENV = "LEG_SKIP"
SKIP_GUARD = "env.LEG_SKIP != 'true'"
CARGO_GUARD = "needs.classify.outputs.cargo_skip != 'true'"
HOSTED = '["ubuntu-latest"]'
LINUX_FED = '["self-hosted","linux-fed"]'
MACOS_FED = '["self-hosted","macos-fed"]'
EXPECTED_LEGS = ["ubuntu-latest,sqlite", "linux-fed,enterprise-fed", "macos-fed,sqlite", "macos-fed,enterprise-fed"]
EXPECTED_CHECK_NAME = "Check (${{ matrix.leg }})"
NOTICE_STEP = "Draft admission skip (#9821)"
RECHECK_JOB = "draft-admission"


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


def evaluate(expr, event, draft, labels, runner):
    ctx = {
        "github.event_name": event,
        "github.event.pull_request.draft": draft,
        "github.event.pull_request.labels.*.name": list(labels),
        "matrix.runner": runner,
    }
    return Evaluator(tokenize(expr), ctx).parse()


# ----------------------------------------------------------- workflow ----


def job_block(job):
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
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


def steps():
    """[(name, if-expression or None)] of the check job, one-line if only."""
    out, in_steps, cur = [], False, None
    for line in check_block():
        if line == "    steps:":
            in_steps = True
            continue
        if not in_steps:
            continue
        if line.startswith("      - "):
            if cur:
                out.append(tuple(cur))
            m = re.match(r"      - (?:name: (.*)|uses: (.*))", line)
            cur = [(m.group(1) or m.group(2)) if m else line.strip(), None]
        elif cur and cur[1] is None and line.startswith("        if:"):
            value = line.split("if:", 1)[1].strip()
            if value.startswith((">", "|")):
                raise AssertionError("multi-line if in step %r cannot be read" % cur[0])
            cur[1] = value
        elif cur and cur[0].startswith("actions/checkout") is False and line.startswith("        name:") and cur[0] == line.strip():
            pass
    if cur:
        out.append(tuple(cur))
    return out


# ---------------------------------------------------------------- tests ----


class AdmissionTables(unittest.TestCase):
    """Allow (leg runs) and deny (leg skipped) rows, written by hand."""

    # (event, draft, labels, runner, leg is skipped)
    ROWS = [
        ("pull_request", True, [], LINUX_FED, True),
        ("pull_request", True, [], MACOS_FED, True),
        ("pull_request", True, ["bug"], LINUX_FED, True),
        ("pull_request", True, ["ci-fix"], LINUX_FED, False),
        ("pull_request", True, ["run-self-hosted"], MACOS_FED, False),
        ("pull_request", True, ["bug", "ci-fix", "run-self-hosted"], LINUX_FED, False),
        ("pull_request", False, [], LINUX_FED, False),
        ("pull_request", False, ["ci-fix"], LINUX_FED, False),
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


class StepPins(unittest.TestCase):
    def test_every_cargo_guarded_step_also_honours_leg_skip(self):
        seen = 0
        for name, cond in steps():
            if cond and CARGO_GUARD in cond and name != NOTICE_STEP:
                seen += 1
                self.assertIn(SKIP_GUARD, cond, "step %r does not honour %s" % (name, SKIP_ENV))
        self.assertGreaterEqual(seen, 25)  # the guarded steps counted at the base sha are 29

    def test_checkout_is_skipped_too(self):
        for name, cond in steps():
            if name.startswith("actions/checkout"):
                self.assertEqual(cond, None)  # checkout stays unguarded (rule b3 exempts it)
                return
        self.fail("checkout step not found")

    def test_notice_and_recheck_steps(self):
        by_name = dict(steps())
        self.assertIn(NOTICE_STEP, by_name)
        # rule (b3) of check-required-contexts.sh wants a cargo_skip/docs_only guard on every step
        self.assertEqual(by_name[NOTICE_STEP], "%s && env.%s == 'true'" % (CARGO_GUARD, SKIP_ENV))
        text = "\n".join(check_block())
        self.assertIn("needs: [classify, draft-admission]", text)
        self.assertIn('VERDICT: ${{ needs.draft-admission.outputs.verdict }}', text)
        self.assertIn('test "${VERDICT}" = skip', text)  # anything but an explicit skip fails the leg
        self.assertNotIn("GH_TOKEN", text)  # a secret in the check job is a tainted-job violation (taint_boundary.py)

    def test_recheck_job_holds_the_token_without_pr_code(self):
        block = job_block(RECHECK_JOB)
        text = "\n".join(block)
        self.assertNotIn("checkout", text)  # no pull-request code ever shares the token
        self.assertNotIn("uses:", text)
        self.assertIn("    runs-on: ubuntu-latest", block)
        self.assertIn("      pull-requests: read", block)
        self.assertNotRegex(text, r"(?m)^\s+(pull-requests|contents|issues|actions): write")
        # No step-level continue-on-error (#9698 allows it only in the select job): a failed read leaves
        # the verdict empty through `|| true`, and an empty verdict fails the skipped leg closed.
        self.assertNotIn("continue-on-error", text)
        self.assertIn("|| true)\"", text)
        self.assertIn("        if: github.event_name == 'pull_request'", block)

    def test_ready_for_review_starts_a_run(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(text, r"\n    types: \[opened, synchronize, reopened, ready_for_review\]\n")
        self.assertNotIn("labeled", re.search(r"\n    types: \[[^\]]*\]\n", text).group(0))  # a label event cancels in-flight runs

    def test_required_names_unchanged(self):
        block = check_block()
        self.assertIn("    name: %s" % EXPECTED_CHECK_NAME, block)
        legs = [re.match(r"          - leg: (.*)", l).group(1) for l in block if re.match(r"          - leg: ", l)]
        self.assertEqual(legs, EXPECTED_LEGS)
        self.assertFalse([l for l in block if l.startswith("    if:")], "job-level if on a matrix job breaks rule (b1)")


class Recheck(unittest.TestCase):
    """The re-check filter shipped in the workflow: a stale skip must fail, never pass."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("jq") is None:
            raise unittest.SkipTest("jq is not installed")
        text = "\n".join(job_block(RECHECK_JOB))
        m = re.search(r"--jq '([^']*)'", text)
        if m is None:
            raise AssertionError("re-check jq filter not found in the %s job" % RECHECK_JOB)
        cls.filter = m.group(1)

    def verdict(self, payload):
        proc = subprocess.run(["jq", "-r", self.filter], input=json.dumps(payload), capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() if proc.returncode == 0 else "jq-error"

    def test_rows(self):
        pr = lambda draft, *labels: {"draft": draft, "labels": [{"name": n} for n in labels]}
        rows = [
            (pr(True), "skip"),
            (pr(True, "bug"), "skip"),
            (pr(False), "run"),
            (pr(True, "ci-fix"), "run"),
            (pr(True, "run-self-hosted"), "run"),
            (pr(True, "bug", "ci-fix"), "run"),
            ({"draft": None, "labels": []}, "run"),
            ({"draft": "true", "labels": []}, "run"),
            ({"labels": []}, "run"),
            ({"draft": True, "labels": None}, "run"),
            ({"draft": True}, "run"),
            ({"draft": True, "labels": "ci-fix"}, "run"),
        ]
        for payload, want in rows:
            with self.subTest(payload=payload):
                self.assertEqual(self.verdict(payload), want)

    def test_job_writes_the_verdict_output(self):
        text = "\n".join(job_block(RECHECK_JOB))
        self.assertIn("verdict: ${{ steps.recheck.outputs.verdict }}", text)
        self.assertIn('echo "verdict=${verdict}" >> "$GITHUB_OUTPUT"', text)


if __name__ == "__main__":
    unittest.main()
