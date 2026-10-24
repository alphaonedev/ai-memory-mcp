#!/usr/bin/env python3
"""Offline #7337 clearance regressions using GitHub-shaped API fixtures."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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
WORKFLOW = ".github/workflows/codeql-rust.yml"
WORKFLOW_ID = 300
RUN = 400
SUITE = 500


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
                 check_suite={"id": SUITE},
                 output={"title": None, "annotations_count": 3})
            for offset, language in enumerate(LANGUAGES)]
    run = {
        "id": RUN, "workflow_id": WORKFLOW_ID, "path": WORKFLOW,
        "event": "pull_request", "head_sha": HEAD, "run_number": 20,
        "run_attempt": 1, "check_suite_id": SUITE,
        "status": "completed", "conclusion": "success",
        "created_at": START, "run_started_at": START, "updated_at": END,
        "pull_requests": [{"number": PR, "head": {"sha": HEAD}}],
    }
    attempt_jobs = [dict(job, run_id=RUN, run_attempt=1,
                         check_run_url="https://api.github.com/repos/" + REPO
                         + "/check-runs/" + str(job["id"])) for job in jobs]
    analyses = [{
        "id": offset + 1, "ref": "refs/pull/17/merge", "commit_sha": MERGE,
        "analysis_key": ".github/workflows/codeql-rust.yml:analyze",
        "category": "/language:" + language,
        "created_at": CREATED, "error": "", "warning": "",
        "tool": {"name": "CodeQL"},
    } for offset, language in enumerate(LANGUAGES)]
    return {
        "actions/workflows/codeql-rust.yml": {"id": WORKFLOW_ID, "path": WORKFLOW},
        "actions/workflows/300/runs": {"total_count": 1, "workflow_runs": [run]},
        "actions/runs/400": run,
        "actions/runs/400/attempts/1": run,
        "actions/runs/400/attempts/1/jobs": {"total_count": len(jobs),
                                            "jobs": attempt_jobs},
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

    def test_7337_live_clean_title_and_near_matches(self):
        output = self.data["check-runs/100"]["output"]
        output["title"] = "No new alerts in code changed by this pull request"
        self.run_gate()
        for title in ("No new alerts ", "No new alerts; 1 existing alert",
                      "No new alerts in code changed by this pull request: 1 warning",
                      "no new alerts", "No new alerts\n"):
            with self.subTest(title=title):
                output["title"] = title
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

    def test_7337_pagination_collects_every_page_and_rejects_overflow(self):
        first = [{"id": index} for index in range(self.gate.PAGE_SIZE)]
        with patch.object(self.gate, "MAX_PAGES", 2):
            responses = iter([first, [{"id": 200}]])
            self.assertEqual(len(self.gate.pages(lambda _: next(responses), "fixture")),
                             self.gate.PAGE_SIZE + 1)
            with self.assertRaisesRegex(self.gate.GateError, "pagination exceeds"):
                self.gate.pages(lambda _: first, "fixture")

    def test_7337_malformed_or_truncated_pages(self):
        for response in (None, {}, [None], {"check_runs": [], "total_count": 1}):
            with self.subTest(response=response), self.assertRaises(self.gate.GateError):
                self.gate.pages(lambda _: response, "fixture",
                                key="check_runs" if isinstance(response, dict) else None)

    def test_7337_old_aggregate_id_cannot_clear_latest_check(self):
        checks = copy.deepcopy(self.data["commits/" + HEAD + "/check-runs"])
        checks["check_runs"][0]["id"] += 1000
        self.data["commits/" + HEAD + "/check-runs"] = checks
        self.refused("id mismatch")

    def test_7337_rerun_pending_during_read(self):
        original = self.api
        count = 0

        def moving_api(endpoint):
            nonlocal count
            result = original(endpoint)
            if "/check-runs?" in endpoint:
                count += 1
                if count > 1:
                    result["check_runs"][1]["status"] = "queued"
            return result

        with self.assertRaisesRegex(self.gate.GateError, "completed.*success"):
            self.gate.check_clearance(moving_api, REPO, PR, HEAD, CHECK)

    def test_7337_wrong_ref_and_unconfigured_analysis(self):
        for field, value in (("ref", "refs/heads/main"),
                             ("analysis_key", "other.yml:analyze"),
                             ("category", "/language:unknown")):
            with self.subTest(field=field):
                self.data = fixture()
                self.data["code-scanning/analyses:merge"][0][field] = value
                with self.assertRaises(self.gate.GateError):
                    self.run_gate()

    def test_7337_actual_cli_with_mock_gh(self):
        scratch = ROOT / ".local-runs" / "codeql-7337-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            fake_gh = root / "gh"
            fake_gh.write_text(
                "#!" + sys.executable + "\n"
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "from urllib.parse import parse_qs, urlsplit\n"
                "assert sys.argv[1:4] == ['api', '--method', 'GET']\n"
                "endpoint = urlsplit(sys.argv[4])\n"
                "key = endpoint.path.removeprefix('repos/fixture/project/')\n"
                "if key.startswith('code-scanning/'):\n"
                "    key += ':' + parse_qs(endpoint.query)['ref'][0].rsplit('/', 1)[1]\n"
                "data = json.loads(Path(os.environ['CODEQL_FIXTURE']).read_text())\n"
                "print(json.dumps(data[key]))\n",
                encoding="utf-8",
            )
            fake_gh.chmod(0o700)
            source = root / "fixture.json"
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       CODEQL_FIXTURE=str(source))
            command = [sys.executable, str(HELPER), str(CHECK), "--repo", REPO,
                       "--pr", str(PR), "--head", HEAD]
            for alert, expected in ((False, 0), (True, 1)):
                with self.subTest(alert=alert):
                    data = fixture()
                    if alert:
                        data["code-scanning/alerts:merge"] = [{"number": 545}]
                    source.write_text(json.dumps(data), encoding="utf-8")
                    result = subprocess.run(command, cwd=Path.cwd(), env=env,
                                            capture_output=True, text=True, timeout=30,
                                            check=False)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertIn("open alerts" if alert else "CodeQL clear",
                                  result.stderr if alert else result.stdout)

    def test_7337_gh_failure_malformed_json_and_timeout(self):
        client = self.gate.GhApi(Path.cwd())
        failures = [subprocess.CompletedProcess([], 1, "", "HTTP 403 denied"),
                    subprocess.CompletedProcess([], 0, "not json", ""),
                    subprocess.CompletedProcess([], 0, '{"id": 1, "id": 2}', ""),
                    subprocess.CompletedProcess([], 0, '{"id": NaN}', "")]
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
