#!/usr/bin/env python3
"""Issue 8615: audit accepts only verified clean npm reports."""
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0

import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

CI_DIR = Path(__file__).resolve().parents[1]
FIXTURE_DIR = Path(__file__).resolve().parent / "data" / "npm_audit_8615"
sys.path.insert(0, str(CI_DIR))
import check_npm_audit as gate


class NpmAudit8615Tests(unittest.TestCase):
    def setUp(self):
        self.clean = json.loads((FIXTURE_DIR / "clean.json").read_text())
        self.vulnerable = json.loads((FIXTURE_DIR / "vulnerable.json").read_text())

    def run_gate(self, report, returncode=0):
        result = subprocess.CompletedProcess([], returncode, json.dumps(report), "")
        with patch.object(gate.subprocess, "run", return_value=result) as run:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = gate.main([])
        return code, run

    def test_8615_recorded_clean_report(self):
        code, run = self.run_gate(self.clean)
        self.assertEqual(code, 0)
        self.assertEqual(run.call_args.args[0], ["npm", "audit", "--json", "--audit-level=low", "--prefix", "sdk/typescript"])
        self.assertTrue(run.call_args.kwargs["capture_output"])
        self.assertGreater(run.call_args.kwargs["timeout"], 0)
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_8615_recorded_low_advisory(self):
        self.assertEqual(self.run_gate(self.vulnerable, 1)[0], 1)

    def test_8615_advisory_with_success_exit_is_rejected(self):
        self.assertEqual(self.run_gate(self.vulnerable)[0], 1)

    def test_8615_each_severity_is_rejected(self):
        for severity in ("low", "moderate", "high", "critical"):
            with self.subTest(severity=severity):
                report = copy.deepcopy(self.clean)
                report["vulnerabilities"] = {"example": {"severity": severity}}
                report["metadata"]["vulnerabilities"].update({severity: 1, "total": 1})
                self.assertEqual(self.run_gate(report)[0], 1)

    def test_8615_summary_cannot_hide_advisories(self):
        report = copy.deepcopy(self.vulnerable)
        report["metadata"] = self.clean["metadata"]
        self.assertEqual(self.run_gate(report)[0], 1)

    def test_8615_details_cannot_hide_summary(self):
        report = copy.deepcopy(self.vulnerable)
        report["vulnerabilities"] = {}
        self.assertEqual(self.run_gate(report)[0], 1)

    def test_8615_invalid_schema_fails_closed(self):
        invalid = [None, [], {}, {"error": {"code": "E403"}}, dict(self.clean, auditReportVersion=1)]
        for field, value in (("vulnerabilities", []), ("metadata", None)):
            invalid.append(dict(self.clean, **{field: value}))
        for value in (-1, True, "0", None):
            report = copy.deepcopy(self.clean)
            report["metadata"]["vulnerabilities"]["low"] = value
            invalid.append(report)
        report = copy.deepcopy(self.clean)
        del report["metadata"]["vulnerabilities"]["critical"]
        invalid.append(report)
        report = copy.deepcopy(self.clean)
        report["metadata"]["vulnerabilities"]["unknown"] = 1
        invalid.append(report)
        for report in invalid:
            with self.subTest(report=report):
                self.assertEqual(self.run_gate(report)[0], 1)

    def test_8615_command_failure_with_clean_output(self):
        for code in (1, 2, -9):
            self.assertEqual(self.run_gate(self.clean, code)[0], 1)

    def test_8615_invalid_json(self):
        for output in ("", "not json", '{"auditReportVersion":2,"auditReportVersion":2}'):
            result = subprocess.CompletedProcess([], 0, output, "")
            with patch.object(gate.subprocess, "run", return_value=result):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(gate.main([]), 1)

    def test_8615_missing_npm_timeout_and_encoding_error(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired("npm", 1), UnicodeError()):
            with patch.object(gate.subprocess, "run", side_effect=error):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(gate.main([]), 1)

    def test_8615_prefix_is_one_argument(self):
        result = subprocess.CompletedProcess([], 0, json.dumps(self.clean), "")
        with patch.object(gate.subprocess, "run", return_value=result) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main(["--prefix", "sdk with spaces"]), 0)
        self.assertEqual(run.call_args.args[0][-1], "sdk with spaces")


if __name__ == "__main__":
    unittest.main()
