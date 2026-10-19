#!/usr/bin/env python3
"""Issue 7833: resolve historical suites using authenticated current ownership."""

import copy
import unittest

import test_check_codeql_alerts_7337 as original


RUN_KEY = "actions/runs/400"
RUNS_KEY = "actions/workflows/300/runs"
ATTEMPT_KEY = RUN_KEY + "/attempts/1"
JOBS_KEY = ATTEMPT_KEY + "/jobs"
CHECKS_KEY = "commits/" + original.HEAD + "/check-runs"


class CodeQL7833Tests(unittest.TestCase):
    setUp = original.CodeQL7337Tests.setUp
    api = original.CodeQL7337Tests.api
    run_gate = original.CodeQL7337Tests.run_gate
    refused = original.CodeQL7337Tests.refused

    def historical_suite(self):
        """Two successful suites on one head, as observed live on PR 7761."""
        old_run = copy.deepcopy(self.data[RUN_KEY])
        old_run.update(id=399, run_number=19, check_suite_id=499,
                       created_at="2026-10-18T12:00:00Z",
                       run_started_at="2026-10-18T12:00:00Z",
                       updated_at="2026-10-18T12:02:00Z")
        self.data[RUNS_KEY]["workflow_runs"].append(old_run)
        self.data[RUNS_KEY]["total_count"] += 1
        checks = self.data[CHECKS_KEY]
        for job in list(checks["check_runs"][1:]):
            old_job = copy.deepcopy(job)
            old_job.update(id=job["id"] + 1000, check_suite={"id": 499},
                           started_at="2026-10-18T12:00:00Z",
                           completed_at="2026-10-18T12:02:00Z")
            checks["check_runs"].append(old_job)
            checks["total_count"] += 1
        # GitHub may reuse the aggregate from the historical suite.
        aggregate = self.data["check-runs/100"]
        aggregate.update(started_at="2026-10-18T12:00:00Z",
                         completed_at="2026-10-18T12:02:00Z")

    def test_7833_historical_and_current_suites_clear(self):
        self.historical_suite()
        self.run_gate()

    def test_7833_check_response_order_does_not_choose_history(self):
        self.historical_suite()
        self.data[CHECKS_KEY]["check_runs"].reverse()
        self.run_gate()

    def test_7833_current_queued_before_any_jobs_exist(self):
        self.data[RUN_KEY].update(status="queued", conclusion=None)
        self.data[JOBS_KEY] = {"total_count": 0, "jobs": []}
        self.refused("workflow.*success")

    def test_7833_newer_run_queued_with_old_green_checks(self):
        newer = copy.deepcopy(self.data[RUN_KEY])
        newer.update(id=401, run_number=21, check_suite_id=501,
                     status="queued", conclusion=None)
        self.data[RUNS_KEY]["workflow_runs"].append(newer)
        self.data[RUNS_KEY]["total_count"] += 1
        self.refused("workflow.*success")

    def test_7833_newer_attempt_failed_or_in_progress_with_old_green_jobs(self):
        for status, conclusion in (("completed", "failure"), ("in_progress", None),
                                   ("queued", None), ("waiting", None)):
            with self.subTest(status=status):
                self.data[RUN_KEY].update(run_attempt=2, status=status, conclusion=conclusion)
                self.refused("workflow.*success")

    def test_7833_attempt_cannot_reuse_jobs_from_prior_attempt(self):
        self.data[RUN_KEY]["run_attempt"] = 2
        self.data[RUN_KEY + "/attempts/2"] = self.data[RUN_KEY]
        self.data[RUN_KEY + "/attempts/2/jobs"] = self.data[JOBS_KEY]
        self.refused("attempt")

    def test_7833_wrong_workflow_identity(self):
        for key, value in (("workflow_id", 301), ("path", "other.yml"),
                           ("head_sha", original.OLD), ("event", "push")):
            with self.subTest(key=key):
                self.data = original.fixture()
                self.data[RUN_KEY][key] = value
                self.refused("workflow")

    def test_7833_wrong_suite_or_job_app_or_head(self):
        for key, value in (("check_suite", {"id": 999}),
                           ("app", {"slug": "other-app"}),
                           ("head_sha", original.OLD)):
            with self.subTest(key=key):
                self.data = original.fixture()
                self.data[CHECKS_KEY]["check_runs"][1][key] = value
                self.refused("suite|identity|head")

    def test_7833_job_from_wrong_run_or_check_url(self):
        for key, value in (("run_id", 399), ("check_run_url", "https://example.invalid/check/101")):
            with self.subTest(key=key):
                self.data = original.fixture()
                self.data[JOBS_KEY]["jobs"][0][key] = value
                self.refused("ownership")

    def test_7833_current_analyses_from_wrong_run_interval(self):
        self.historical_suite()
        self.data["code-scanning/analyses:merge"][0]["created_at"] = "2026-10-18T12:01:00Z"
        self.refused("analysis.*interval")

    def test_7833_duplicate_aggregate_is_still_ambiguous(self):
        checks = self.data[CHECKS_KEY]
        checks["check_runs"].append(copy.deepcopy(checks["check_runs"][0]))
        checks["total_count"] += 1
        self.refused("ambiguous check: CodeQL")

    def test_7833_duplicate_owned_check_is_ambiguous(self):
        checks = self.data[CHECKS_KEY]
        checks["check_runs"].append(copy.deepcopy(checks["check_runs"][1]))
        checks["total_count"] += 1
        self.refused("ambiguous")

    def test_7833_duplicate_current_job_is_ambiguous(self):
        jobs = self.data[JOBS_KEY]
        jobs["jobs"].append(copy.deepcopy(jobs["jobs"][0]))
        jobs["total_count"] += 1
        self.refused("ambiguous")

    def test_7833_duplicate_run_number_is_ambiguous(self):
        runs = self.data[RUNS_KEY]
        runs["workflow_runs"].append(dict(self.data[RUN_KEY], id=401))
        runs["total_count"] += 1
        self.refused("ambiguous")

    def test_7833_workflow_rerun_changes_during_read(self):
        api = self.api
        reads = 0
        def moving(endpoint):
            nonlocal reads
            result = api(endpoint)
            if "/workflows/300/runs?" in endpoint:
                reads += 1
                if reads > 1:
                    result["workflow_runs"][0].update(run_attempt=2, status="queued", conclusion=None)
            return result
        with self.assertRaisesRegex(self.gate.GateError, "workflow.*success"):
            self.gate.check_clearance(moving, original.REPO, original.PR,
                                      original.HEAD, original.CHECK)


if __name__ == "__main__":
    unittest.main()
