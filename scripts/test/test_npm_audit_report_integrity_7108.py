#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Reject malformed audit data and process failures (#7108, #7109, #7110)."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-npm-audit-sdk.py"
SCRATCH = Path(os.environ.get("TMPDIR") or ROOT / ".local-runs")
SEVERITIES = ("info", "low", "moderate", "high", "critical")
DIAGNOSTIC = "check-npm-audit-sdk:"


def report_for(*severities):
    """Supply a complete report with matching counts and package severities."""
    counts = {level: severities.count(level) for level in SEVERITIES}
    counts["total"] = len(severities)
    return {
        "auditReportVersion": 2,
        "metadata": {"vulnerabilities": counts},
        "vulnerabilities": {
            "fixture-" + str(index): {"severity": level, "range": "*"}
            for index, level in enumerate(severities)
        },
    }


class AuditReportIntegrity(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.directory.cleanup)

    def invoke_report(self, report):
        path = Path(self.directory.name) / "audit.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        proc = subprocess.run([sys.executable, str(SCRIPT), "--json-file", str(path)],
                              capture_output=True, text=True, check=False)
        return proc.returncode, proc.stdout + proc.stderr

    def assert_gate_error(self, result):
        rc, output = result
        self.assertEqual(rc, 2, output)
        self.assertIn(DIAGNOSTIC, output)
        self.assertNotIn("can't open file", output)
        self.assertNotIn("Traceback", output)
        self.assertNotIn("OK: no findings", output)

    def test_healthy_and_advisory_controls(self):
        for severities, expected in (((), 0), (("low", "moderate"), 0), (("high",), 1)):
            with self.subTest(severities=severities):
                rc, output = self.invoke_report(report_for(*severities))
                self.assertEqual(rc, expected, output)

    def test_null_and_non_mapping_reports_are_errors(self):
        for report in (None, [], "report", True):
            with self.subTest(report=report):
                self.assert_gate_error(self.invoke_report(report))

    def test_missing_counts_are_errors(self):
        for field in (*SEVERITIES, "total"):
            report = report_for()
            del report["metadata"]["vulnerabilities"][field]
            with self.subTest(field=field):
                self.assert_gate_error(self.invoke_report(report))

    def test_non_integer_and_negative_counts_are_errors(self):
        for value in (-1, 0.5, True, "0", None):
            report = report_for("critical")
            report["metadata"]["vulnerabilities"]["high"] = value
            with self.subTest(value=value):
                self.assert_gate_error(self.invoke_report(report))

    def test_inconsistent_counts_are_errors(self):
        hidden_finding = report_for("critical")
        hidden_finding["metadata"] = report_for()["metadata"]
        incorrect_total = report_for()
        incorrect_total["metadata"]["vulnerabilities"]["total"] = 1
        missing_entries = report_for("high")
        missing_entries["vulnerabilities"] = {}
        for report in (hidden_finding, incorrect_total, missing_entries):
            with self.subTest(report=report):
                self.assert_gate_error(self.invoke_report(report))

    def test_error_payload_is_not_clean(self):
        report = report_for()
        report["error"] = {"code": "EAUDIT", "summary": "fixture failure"}
        self.assert_gate_error(self.invoke_report(report))

    def test_invalid_vulnerability_entries_are_errors(self):
        for entry in (None, {}, {"severity": "unknown"}):
            report = report_for("high")
            report["vulnerabilities"]["fixture-0"] = entry
            with self.subTest(entry=entry):
                self.assert_gate_error(self.invoke_report(report))

    def invoke_npm(self, report, returncode):
        spec = importlib.util.spec_from_file_location("gate", str(SCRIPT))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fake = mock.Mock(stdout=json.dumps(report), stderr="", returncode=returncode)
        output = io.StringIO()
        with mock.patch.object(module.shutil, "which", return_value="/fixture/npm"), \
                mock.patch.object(module.subprocess, "run", return_value=fake), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            rc = module.main([])
        return rc, output.getvalue()

    def test_operational_exit_is_not_clean(self):
        for returncode in (2, -15):
            with self.subTest(returncode=returncode):
                self.assert_gate_error(self.invoke_npm(report_for(), returncode))

    def test_process_status_and_report_agree(self):
        for report, returncode in ((report_for(), 1), (report_for("critical"), 0)):
            with self.subTest(returncode=returncode):
                self.assert_gate_error(self.invoke_npm(report, returncode))

    def test_valid_process_controls(self):
        for report, expected in ((report_for(), 0), (report_for("high"), 1)):
            with self.subTest(expected=expected):
                rc, output = self.invoke_npm(report, expected)
                self.assertEqual(rc, expected, output)


if __name__ == "__main__":
    unittest.main()
