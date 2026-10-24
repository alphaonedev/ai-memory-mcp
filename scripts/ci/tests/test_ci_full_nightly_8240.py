"""Nightly full run (ci-full.yml) must report its real outcome (#8240 S4/S6/F5).

The workflow dispatches ci.yml, waits for the dispatched run, fails when it is
not green, and opens or updates ONE labelled issue so a red nightly is visible.
The ref is never hard-coded: github.ref_name on schedule, an input on dispatch.
"""
import json
import re
import unittest
from pathlib import Path

import impact_fixture as fx
import workflow_text
import ci_full_nightly as nightly

CI_FULL = fx.REPO_ROOT / ".github" / "workflows" / "ci-full.yml"
REPO = "owner/repo"
REF = "feature/x"


class FakeGh:
    """Scripted gh runner: records calls, answers by subcommand."""

    def __init__(self, runs_before=None, runs_after=None, view=None, issues=None):
        self.calls = []
        self.runs_before = runs_before or []
        self.runs_after = runs_after or []
        self.view = view or []
        self.issues = issues or []
        self.dispatched = False

    def __call__(self, args):
        self.calls.append(list(args))
        if args[:2] == ["workflow", "run"]:
            self.dispatched = True
            return 0, ""
        if args[:2] == ["run", "list"]:
            rows = self.runs_after if self.dispatched else self.runs_before
            return 0, json.dumps(rows)
        if args[:2] == ["run", "view"]:
            return 0, json.dumps(self.view.pop(0) if len(self.view) > 1 else self.view[0])
        if args[:2] == ["issue", "list"]:
            return 0, json.dumps(self.issues)
        return 0, ""

    def verbs(self):
        return [" ".join(c[:2]) for c in self.calls]


def run_row(run_id):
    return {"databaseId": run_id, "url": "https://example.invalid/runs/%d" % run_id}


def no_sleep(_seconds):
    return None


class WorkflowText(unittest.TestCase):
    def setUp(self):
        self.text = CI_FULL.read_text()
        self.jobs = workflow_text.read_jobs(CI_FULL)

    def test_no_hard_coded_branch(self):
        self.assertNotIn("chain/promo", self.text)
        self.assertNotRegex(self.text, r"FULL_RUN_REF:\s*[A-Za-z0-9]")

    def test_ref_comes_from_event_context(self):
        self.assertIn("github.ref_name", self.text)
        self.assertIn("inputs.ref", self.text)
        self.assertRegex(self.text, r"workflow_dispatch:\s*\n\s+inputs:")

    def test_aggregate_job_runs_always_and_needs_the_dispatch(self):
        aggregates = {n: j for n, j in self.jobs.items() if j["if"] == "always()"}
        self.assertEqual(len(aggregates), 1, self.jobs)
        (name, job), = aggregates.items()
        others = set(self.jobs) - {name}
        self.assertEqual(set(job["needs"]), others)

    def test_issue_permission_is_job_scoped(self):
        self.assertRegex(self.text, r"issues:\s*write")
        self.assertRegex(self.text.split("jobs:")[0], r"permissions:\s*\n\s+contents:\s*read")
        self.assertNotRegex(self.text.split("jobs:")[0], r"issues:\s*write")

    def test_no_expression_inside_run_scripts(self):
        in_run = False
        for line in self.text.split("\n"):
            if re.match(r"\s+run:", line):
                in_run = True
                self.assertNotIn("${{", line)
            elif in_run and line.strip() and not line.startswith("          "):
                in_run = False
            elif in_run:
                self.assertNotIn("${{", line)


class ValidateRef(unittest.TestCase):
    def test_accepts_branch_names(self):
        for ref in ("main", "chain/promo6-ssh-r2", "release/v1.0.0", "a_b-c.d"):
            self.assertEqual(nightly.validate_ref(ref), ref)

    def test_rejects_unsafe_refs(self):
        for ref in ("", "a b", "x;rm", "$(id)", "-flag", "a\nb", "x" * 300, "../x"):
            with self.subTest(ref=ref):
                with self.assertRaises(ValueError):
                    nightly.validate_ref(ref)


class Dispatch(unittest.TestCase):
    def test_green_run(self):
        gh = FakeGh(runs_before=[run_row(1)], runs_after=[run_row(2), run_row(1)],
                    view=[{"status": "in_progress", "conclusion": ""},
                          {"status": "completed", "conclusion": "success"}])
        result = nightly.dispatch_and_wait(gh, REPO, REF, sleep=no_sleep)
        self.assertEqual(result["conclusion"], "success")
        self.assertEqual(result["run_id"], 2)
        self.assertEqual(result["url"], "https://example.invalid/runs/2")

    def test_red_run_reports_the_conclusion(self):
        gh = FakeGh(runs_after=[run_row(7)],
                    view=[{"status": "completed", "conclusion": "failure"}])
        result = nightly.dispatch_and_wait(gh, REPO, REF, sleep=no_sleep)
        self.assertEqual(result["conclusion"], "failure")

    def test_run_never_appears_is_an_error(self):
        gh = FakeGh(runs_after=[])
        with self.assertRaises(nightly.NightlyError):
            nightly.dispatch_and_wait(gh, REPO, REF, sleep=no_sleep, find_attempts=3)

    def test_dispatch_failure_is_an_error(self):
        def failing(args):
            return (1, "boom") if args[:2] == ["workflow", "run"] else (0, "[]")
        with self.assertRaises(nightly.NightlyError):
            nightly.dispatch_and_wait(failing, REPO, REF, sleep=no_sleep)

    def test_wait_budget_exhausted_is_an_error(self):
        gh = FakeGh(runs_after=[run_row(9)], view=[{"status": "in_progress", "conclusion": ""}])
        with self.assertRaises(nightly.NightlyError):
            nightly.dispatch_and_wait(gh, REPO, REF, sleep=no_sleep, wait_attempts=3)


class Report(unittest.TestCase):
    def test_green_opens_nothing_and_exits_zero(self):
        gh = FakeGh()
        rc = nightly.report(gh, REPO, "success", "success", "u", REF)
        self.assertEqual(rc, 0)
        self.assertEqual(gh.calls, [])

    def test_red_conclusion_opens_one_labelled_issue_and_exits_one(self):
        gh = FakeGh(issues=[])
        rc = nightly.report(gh, REPO, "success", "failure", "https://x/runs/2", REF)
        self.assertEqual(rc, 1)
        creates = [c for c in gh.calls if c[:2] == ["issue", "create"]]
        self.assertEqual(len(creates), 1)
        self.assertIn(nightly.ISSUE_LABEL, creates[0])
        self.assertIn(nightly.ISSUE_TITLE, creates[0])

    def test_existing_open_issue_is_commented_not_duplicated(self):
        gh = FakeGh(issues=[{"number": 12, "title": nightly.ISSUE_TITLE}])
        rc = nightly.report(gh, REPO, "success", "failure", "https://x/runs/2", REF)
        self.assertEqual(rc, 1)
        self.assertEqual([c for c in gh.calls if c[:2] == ["issue", "create"]], [])
        comments = [c for c in gh.calls if c[:2] == ["issue", "comment"]]
        self.assertEqual(len(comments), 1)
        self.assertIn("12", comments[0])

    def test_title_match_is_exact(self):
        gh = FakeGh(issues=[{"number": 5, "title": nightly.ISSUE_TITLE + " (other)"}])
        nightly.report(gh, REPO, "success", "failure", "u", REF)
        self.assertEqual(len([c for c in gh.calls if c[:2] == ["issue", "create"]]), 1)

    def test_dispatch_job_failure_also_reports(self):
        for job_result in ("failure", "cancelled", "skipped", ""):
            with self.subTest(job_result=job_result):
                gh = FakeGh(issues=[])
                rc = nightly.report(gh, REPO, job_result, "", "", REF)
                self.assertEqual(rc, 1)
                self.assertEqual(len([c for c in gh.calls if c[:2] == ["issue", "create"]]), 1)

    def test_other_conclusions_are_red(self):
        for conclusion in ("cancelled", "timed_out", "startup_failure", "", "neutral"):
            with self.subTest(conclusion=conclusion):
                self.assertEqual(nightly.report(FakeGh(), REPO, "success", conclusion, "u", REF), 1)

    def test_issue_failure_still_exits_one(self):
        def broken(args):
            return 1, "no"
        self.assertEqual(nightly.report(broken, REPO, "success", "failure", "u", REF), 1)


if __name__ == "__main__":
    unittest.main()
