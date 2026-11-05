#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Issue 8615: reject advisory reports and incomplete audit evidence offline."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "scripts/ci/check_cargo_audit.py"
DATA = Path(__file__).resolve().parent / "data"
SPEC = importlib.util.spec_from_file_location("cargo_audit_8615", HELPER)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)
CLEAN = json.loads((DATA / "cargo_audit_clean_8615.json").read_text())
ADVISORY = json.loads((DATA / "cargo_audit_advisory_8615.json").read_text())


class CargoAudit8615Tests(unittest.TestCase):
    """The subprocess boundary must preserve every failure as a failed gate."""

    def run_gate(self, report=CLEAN, returncode=0, stdout=None):
        result = subprocess.CompletedProcess(
            ["cargo", "audit", "--json"], returncode,
            json.dumps(report) if stdout is None else stdout, "")
        with patch.object(GATE.subprocess, "run", return_value=result) as run:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = GATE.main([])
        return code, run

    def test_8615_clean_report_passes(self):
        code, run = self.run_gate()
        self.assertEqual(code, 0)
        self.assertEqual(run.call_args.args[0], ["cargo", "audit", "--json", "--deny", "warnings"])
        self.assertEqual(run.call_args.kwargs["cwd"], ROOT)
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_8615_vulnerability_fails_even_if_tool_returns_success(self):
        self.assertEqual(self.run_gate(ADVISORY)[0], 1)

    def test_8615_vulnerability_exit_fails(self):
        self.assertEqual(self.run_gate(ADVISORY, returncode=1)[0], 1)

    def test_8615_recorded_unfiltered_lock_fails(self):
        report = json.loads((DATA / "cargo_audit_unfiltered_8615.json").read_text())
        self.assertEqual(self.run_gate(report, returncode=1)[0], 1)

    def test_8615_recorded_ignored_report_fails_despite_audit_success(self):
        report = json.loads((DATA / "cargo_audit_ignored_8615.json").read_text())
        self.assertEqual(self.run_gate(report)[0], 1)

    def test_8615_all_warning_categories_fail(self):
        for category in ("unmaintained", "unsound", "notice", "yanked", "future-kind"):
            report = copy.deepcopy(CLEAN)
            report["warnings"][category] = [{"advisory": {"id": "fixture-advisory"}}]
            with self.subTest(category=category):
                self.assertEqual(self.run_gate(report)[0], 1)

    def test_8615_empty_warning_categories_pass(self):
        report = copy.deepcopy(CLEAN)
        report["warnings"]["unmaintained"] = []
        self.assertEqual(self.run_gate(report)[0], 0)

    def test_8615_tool_failure_with_clean_report_fails(self):
        self.assertEqual(self.run_gate(returncode=2)[0], 1)

    def test_8615_invalid_json_fails(self):
        for text in ("", "not json", "null", "[]", "{}"):
            with self.subTest(text=text):
                self.assertEqual(self.run_gate(stdout=text)[0], 1)

    def test_8615_missing_sections_fail(self):
        for key in ("vulnerabilities", "warnings", "settings", "lockfile"):
            report = copy.deepcopy(CLEAN)
            del report[key]
            with self.subTest(key=key):
                self.assertEqual(self.run_gate(report)[0], 1)

    def test_8615_inconsistent_vulnerability_summary_fails(self):
        for key, value in (("count", 1), ("found", True), ("count", False),
                           ("list", {}), ("found", 0)):
            report = copy.deepcopy(CLEAN)
            report["vulnerabilities"][key] = value
            with self.subTest(key=key, value=value):
                self.assertEqual(self.run_gate(report)[0], 1)

    def test_8615_malformed_warning_buckets_fail(self):
        for warnings in ([], None, {"notice": None}, {"notice": {}}):
            report = copy.deepcopy(CLEAN)
            report["warnings"] = warnings
            with self.subTest(warnings=warnings):
                self.assertEqual(self.run_gate(report)[0], 1)

    def test_8615_filtered_advisories_fail(self):
        for key, value in (("ignore", ["RUSTSEC-2026-0429"]), ("severity", "high")):
            report = copy.deepcopy(CLEAN)
            report["settings"][key] = value
            with self.subTest(key=key):
                self.assertEqual(self.run_gate(report)[0], 1)

    def test_8615_empty_or_malformed_crate_count_fails(self):
        for count in (0, -1, True, "1", None):
            report = copy.deepcopy(CLEAN)
            report["lockfile"]["dependency-count"] = count
            with self.subTest(count=count):
                self.assertEqual(self.run_gate(report)[0], 1)

    def test_8615_allowlist_is_empty(self):
        self.assertEqual(json.loads(GATE.ALLOWLIST.read_text()), [])

    def test_8615_nonempty_or_malformed_allowlist_fails_before_audit(self):
        for text in ('["RUSTSEC-2026-0429"]', '{}', 'invalid'):
            with self.subTest(text=text), patch.object(Path, "read_text", return_value=text):
                code, run = self.run_gate()
                self.assertEqual(code, 1)
                run.assert_not_called()

    def test_8615_missing_audit_tool_fails(self):
        with patch.object(GATE.subprocess, "run", side_effect=FileNotFoundError):
            with redirect_stderr(io.StringIO()):
                self.assertEqual(GATE.main([]), 1)

    def test_8615_audit_timeout_fails(self):
        with patch.object(GATE.subprocess, "run", side_effect=subprocess.TimeoutExpired("cargo", 1)):
            with redirect_stderr(io.StringIO()):
                self.assertEqual(GATE.main([]), 1)


if __name__ == "__main__":
    unittest.main()
