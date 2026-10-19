#!/usr/bin/env python3
"""Offline #7337 clearance regressions using GitHub-shaped API fixtures."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "scripts/ci/check_codeql_alerts.py"
REPO = "fixture/project"
HEAD = "a" * 40
BASE = "b" * 40
MERGE = "c" * 40
OLD = "d" * 40
PR = 17
CHECK = 100
LANGUAGES = ("rust", "javascript-typescript", "python", "actions")
START = "2026-10-19T12:00:00Z"
CREATED = "2026-10-19T12:01:00Z"
END = "2026-10-19T12:02:00Z"


def fixture():
    """Mirror observed aggregate, job, analysis and PR REST response shapes."""
    aggregate = {
        "id": CHECK, "name": "CodeQL", "head_sha": HEAD,
        "status": "completed", "conclusion": "success",
        "app": {"slug": "github-advanced-security"},
        "started_at": START, "completed_at": END,
        "output": {"title": "No new alerts", "annotations_count": 0},
    }
    jobs = [dict(aggregate, id=CHECK + offset + 1,
                 name="CodeQL analysis (" + language + ")",
                 app={"slug": "github-actions"},
                 output={"title": None, "annotations_count": 3})
            for offset, language in enumerate(LANGUAGES)]
    analyses = [{
        "id": offset + 1, "ref": "refs/pull/17/merge", "commit_sha": MERGE,
        "analysis_key": ".github/workflows/codeql-rust.yml:analyze",
        "category": "/language:" + language,
        "created_at": CREATED, "error": "", "warning": "",
        "tool": {"name": "CodeQL"},
    } for offset, language in enumerate(LANGUAGES)]
    return {
        "pulls/17": {"number": PR, "state": "open", "head": {"sha": HEAD},
                     "base": {"sha": BASE}, "merge_commit_sha": MERGE},
        "commits/" + MERGE: {"sha": MERGE, "parents": [{"sha": BASE}, {"sha": HEAD}]},
        "check-runs/100": aggregate,
        "commits/" + HEAD + "/check-runs": {"total_count": len(jobs) + 1,
                                             "check_runs": [aggregate] + jobs},
        "code-scanning/analyses:head": [],
        "code-scanning/analyses:merge": analyses,
        "code-scanning/alerts:head": [],
        "code-scanning/alerts:merge": [],
    }


class CodeQL7337Tests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.is_file(), "#7337 preventive gate is absent")
        spec = importlib.util.spec_from_file_location("codeql_gate_7337", HELPER)
        self.gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.gate)
        self.data = fixture()
        self.calls = []

    def api(self, endpoint):
        self.calls.append(endpoint)
        path, _, query = endpoint.partition("?")
        key = path.removeprefix("repos/" + REPO + "/")
        if key.startswith("code-scanning/"):
            key += ":head" if "head" in query else ":merge"
        return copy.deepcopy(self.data[key])

    def run_gate(self):
        return self.gate.check_clearance(self.api, REPO, PR, HEAD, CHECK)

    def refused(self, text):
        with self.assertRaisesRegex(self.gate.GateError, text):
            self.run_gate()

    def test_7337_valid_current_merge_only_coverage(self):
        self.run_gate()
        self.assertTrue(any("alerts?" in call and "head" in call for call in self.calls))
        self.assertTrue(any("alerts?" in call and "merge" in call for call in self.calls))

    def test_7337_success_with_alert_title(self):
        self.data["check-runs/100"]["output"]["title"] = "8 new alerts"
        self.refused("No new alerts")

    def test_7337_nonzero_or_malformed_annotations(self):
        for value in (1, None, False, "0"):
            with self.subTest(value=value):
                self.data["check-runs/100"]["output"]["annotations_count"] = value
                self.refused("annotations")

    def test_7337_head_empty_merge_open(self):
        self.data["code-scanning/alerts:merge"] = [{"number": 545, "state": "open"}]
        self.refused("open alerts.*merge")

    def test_7337_head_open_merge_empty(self):
        self.data["code-scanning/alerts:head"] = [{"number": 545, "state": "open"}]
        self.refused("open alerts.*head")

    def test_7337_both_empty_without_analysis(self):
        self.data["code-scanning/analyses:merge"] = []
        self.refused("missing.*analysis")

    def test_7337_missing_language_analysis(self):
        self.data["code-scanning/analyses:merge"].pop()
        self.refused("missing.*analysis")

    def test_7337_stale_analysis_commit(self):
        self.data["code-scanning/analyses:merge"][0]["commit_sha"] = OLD
        self.refused("stale.*analysis")

    def test_7337_stale_head_analysis(self):
        analysis = copy.deepcopy(self.data["code-scanning/analyses:merge"][0])
        analysis.update(ref="refs/pull/17/head", commit_sha=OLD)
        self.data["code-scanning/analyses:head"] = [analysis]
        self.refused("stale.*analysis")

    def test_7337_current_head_analysis_is_allowed(self):
        analysis = copy.deepcopy(self.data["code-scanning/analyses:merge"][0])
        analysis.update(ref="refs/pull/17/head", commit_sha=HEAD)
        self.data["code-scanning/analyses:head"] = [analysis]
        self.run_gate()

    def test_7337_latest_analysis_cannot_fall_back_to_old_success(self):
        analysis = copy.deepcopy(self.data["code-scanning/analyses:merge"][0])
        analysis.update(id=200, created_at=END, commit_sha=OLD)
        self.data["code-scanning/analyses:merge"].append(analysis)
        self.refused("stale.*analysis")

    def test_7337_head_mismatch(self):
        self.data["pulls/17"]["head"]["sha"] = OLD
        self.refused("head")

    def test_7337_stale_merge_base(self):
        self.data["commits/" + MERGE]["parents"][0]["sha"] = OLD
        self.refused("parents")

    def test_7337_pending_or_failed_aggregate(self):
        for status, conclusion in (("queued", None), ("completed", "failure")):
            with self.subTest(status=status):
                self.data["check-runs/100"].update(status=status, conclusion=conclusion)
                self.refused("completed.*success")

    def test_7337_pending_or_failed_language_job(self):
        jobs = self.data["commits/" + HEAD + "/check-runs"]["check_runs"]
        for status, conclusion in (("in_progress", None), ("completed", "cancelled")):
            with self.subTest(status=status):
                jobs[1].update(status=status, conclusion=conclusion)
                self.refused("completed.*success")

    def test_7337_missing_job(self):
        checks = self.data["commits/" + HEAD + "/check-runs"]
        checks["check_runs"].pop()
        checks["total_count"] -= 1
        self.refused("missing.*check")

    def test_7337_analysis_predates_current_job(self):
        self.data["code-scanning/analyses:merge"][0]["created_at"] = "2026-10-18T12:00:00Z"
        self.refused("analysis.*job")

    def test_7337_analysis_error_or_warning(self):
        for field in ("error", "warning"):
            with self.subTest(field=field):
                self.data = fixture()
                self.data["code-scanning/analyses:merge"][0][field] = "incomplete upload"
                self.refused("analysis")

    def test_7337_malformed_missing_api_fields(self):
        for key in ("output", "head_sha", "app", "id"):
            with self.subTest(key=key):
                self.data = fixture()
                del self.data["check-runs/100"][key]
                with self.assertRaises(self.gate.GateError):
                    self.run_gate()

    def test_7337_wrong_check_identity(self):
        self.data["check-runs/100"]["app"]["slug"] = "github-actions"
        self.refused("aggregate")

    def test_7337_pr_moves_during_read(self):
        original = self.api
        count = 0

        def moving_api(endpoint):
            nonlocal count
            result = original(endpoint)
            if endpoint.endswith("pulls/17"):
                count += 1
                if count > 1:
                    result["base"]["sha"] = OLD
            return result

        with self.assertRaisesRegex(self.gate.GateError, "changed"):
            self.gate.check_clearance(moving_api, REPO, PR, HEAD, CHECK)

    def test_7337_pagination_finds_later_alert(self):
        original = self.api

        def pages(endpoint):
            if "alerts?" in endpoint and "merge" in endpoint:
                if "page=1&" in endpoint:
                    return [{"number": i} for i in range(self.gate.PAGE_SIZE)]
                return [{"number": 545}]
            return original(endpoint)

        with self.assertRaisesRegex(self.gate.GateError, "open alerts"):
            self.gate.check_clearance(pages, REPO, PR, HEAD, CHECK)

    def test_7337_gh_failure_malformed_json_and_timeout(self):
        client = self.gate.GhApi(Path.cwd())
        failures = [subprocess.CompletedProcess([], 1, "", "HTTP 403 denied"),
                    subprocess.CompletedProcess([], 0, "not json", "")]
        for response in failures:
            with self.subTest(response=response), patch.object(
                    self.gate.subprocess, "run", return_value=response):
                with self.assertRaises(self.gate.GateError):
                    client("repos/fixture/project/pulls/17")
        with patch.object(self.gate.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired("gh", 60)):
            with self.assertRaises(self.gate.GateError):
                client("repos/fixture/project/pulls/17")

    def test_7337_gh_read_only_argv_and_explicit_cwd(self):
        response = subprocess.CompletedProcess([], 0, "[]", "")
        with patch.object(self.gate.subprocess, "run", return_value=response) as run:
            self.assertEqual(self.gate.GhApi(Path.cwd())("repos/fixture/project/test"), [])
        args, kwargs = run.call_args
        self.assertEqual(args[0][:4], ["gh", "api", "--method", "GET"])
        self.assertEqual(kwargs["cwd"], Path.cwd())
        self.assertGreater(kwargs["timeout"], 0)
        self.assertNotIn("--slurp", args[0])

    def test_7337_cli_success_and_failure(self):
        argv = [str(CHECK), "--repo", REPO, "--pr", str(PR), "--head", HEAD]
        with patch.object(self.gate, "GhApi", return_value=self.api):
            self.assertEqual(self.gate.main(argv), 0)
            self.data["check-runs/100"]["output"]["title"] = "1 new alert"
            self.assertEqual(self.gate.main(argv), 1)


if __name__ == "__main__":
    unittest.main()
