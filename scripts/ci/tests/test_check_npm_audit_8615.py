#!/usr/bin/env python3
"""Issue 8615: audit accepts only verified clean npm reports."""
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0

import contextlib
import copy
from datetime import date, timedelta
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

CI_DIR = Path(__file__).resolve().parents[1]
FIXTURE_DIR = Path(__file__).resolve().parent / "data" / "npm_audit_8615"
sys.path.insert(0, str(CI_DIR))
import check_npm_audit as gate

TODAY = date(2026, 11, 5)
ADVISORY_ID = "GHSA-gcqx-w48m-w2h4"
DEEP_MERGE_NODE = "node_modules/deepmerge"
TEST_SCRATCH = Path(os.environ.get("TMPDIR", str(CI_DIR.parents[1] / ".local-runs")))


class NpmExceptions8615Tests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads((FIXTURE_DIR / "vulnerable.json").read_text())
        self.entries = [{"advisory": ADVISORY_ID, "package": "deepmerge",
                         "version": "4.3.1", "issue": 8616,
                         "expires": "2027-02-03", "reason": "No patched release; tracked remediation."}]
        self.versions = {DEEP_MERGE_NODE: "4.3.1"}

    def check(self):
        return gate.check_audit(json.dumps(self.report), self.entries, self.versions, TODAY)

    def test_8615_unlisted_advisory_is_rejected(self):
        self.entries = []
        with self.assertRaises(gate.AuditError):
            self.check()

    def test_8615_expired_exception_is_rejected(self):
        self.entries[0]["expires"] = (TODAY - timedelta(days=1)).isoformat()
        with self.assertRaises(gate.AuditError):
            self.check()

    def test_8615_stale_package_version_or_absent_advisory_is_rejected(self):
        for field, value in (("package", "jest"), ("version", "4.3.2")):
            with self.subTest(field=field):
                original = self.entries[0][field]
                self.entries[0][field] = value
                with self.assertRaises(gate.AuditError):
                    self.check()
                self.entries[0][field] = original
        self.report = json.loads((FIXTURE_DIR / "clean.json").read_text())
        with self.assertRaises(gate.AuditError):
            self.check()

    def test_8615_missing_exception_fields_are_rejected(self):
        original = dict(self.entries[0])
        for field in original:
            with self.subTest(field=field):
                self.entries = [{key: value for key, value in original.items() if key != field}]
                with self.assertRaises(gate.AuditError):
                    self.check()

    def test_8615_exact_live_exception_covers_all_seven_via_nodes(self):
        self.assertEqual(self.check(), 1)

    def test_8615_version_is_taken_from_actual_nodes_not_advisory_range(self):
        self.versions[DEEP_MERGE_NODE] = "4.2.2"
        with self.assertRaises(gate.AuditError):
            self.check()

    def test_8615_every_installed_copy_must_match(self):
        nested = "node_modules/other/node_modules/deepmerge"
        self.report["vulnerabilities"]["deepmerge"]["nodes"].append(nested)
        self.versions[nested] = "4.3.0"
        with self.assertRaises(gate.AuditError):
            self.check()

    def test_8615_unknown_advisory_on_listed_package_is_rejected(self):
        advisory = copy.deepcopy(self.report["vulnerabilities"]["deepmerge"]["via"][0])
        advisory["url"] = "https://github.com/advisories/GHSA-2345-2345-2345"
        self.report["vulnerabilities"]["deepmerge"]["via"].append(advisory)
        with self.assertRaises(gate.AuditError):
            self.check()

    def test_8615_unresolved_empty_and_cyclic_via_chains_are_rejected(self):
        for via in (["missing"], [], ["jest"]):
            with self.subTest(via=via):
                self.report["vulnerabilities"]["jest"]["via"] = via
                with self.assertRaises(gate.AuditError):
                    self.check()

    def test_8615_invalid_exception_values_are_rejected(self):
        original = dict(self.entries[0])
        for field, value in (("expires", "20270203"), ("expires", "2027-02-04"),
                             ("issue", True), ("issue", 0), ("reason", ""),
                             ("reason", "two\nlines"), ("version", "^4.3.1"),
                             ("advisory", "not-an-advisory")):
            with self.subTest(field=field, value=value):
                self.entries = [dict(original, **{field: value})]
                with self.assertRaises(gate.AuditError):
                    self.check()

    def test_8615_duplicate_exception_is_rejected(self):
        self.entries.append(dict(self.entries[0]))
        with self.assertRaises(gate.AuditError):
            self.check()

    def test_8615_expiry_date_itself_is_accepted(self):
        self.entries[0]["expires"] = TODAY.isoformat()
        self.assertEqual(self.check(), 1)

    def test_8615_report_node_package_must_match_advisory_package(self):
        self.report["vulnerabilities"]["deepmerge"]["via"][0]["name"] = "jest"
        with self.assertRaises(gate.AuditError):
            self.check()

    def test_8615_cli_accepts_only_expected_advisory_exit_code(self):
        for status in (0, 1, 2):
            with self.subTest(status=status):
                result = subprocess.CompletedProcess([], status, json.dumps(self.report), "")
                with patch.object(gate.subprocess, "run", return_value=result), \
                        patch.object(gate, "load_exception_file", return_value=self.entries), \
                        patch.object(gate, "read_versions", return_value=self.versions), \
                        patch.object(gate, "datetime") as clock, \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    clock.now.return_value.date.return_value = TODAY
                    self.assertEqual(gate.main([]), 0 if status == 1 else 1)

    def test_8615_exception_document_shape_is_strict(self):
        for entries in ({}, None, [None], [dict(self.entries[0], extra="unknown")]):
            with self.subTest(entries=entries), self.assertRaises(gate.AuditError):
                gate.check_audit(json.dumps(self.report), entries, self.versions, TODAY)

    def test_8615_malformed_expiry_is_rejected(self):
        self.entries[0]["expires"] = "2027-99-01"
        with self.assertRaises(gate.AuditError):
            self.check()


class NpmInstalledVersions8615Tests(unittest.TestCase):
    def setUp(self):
        TEST_SCRATCH.mkdir(parents=True, exist_ok=True)
        scratch = tempfile.TemporaryDirectory(prefix="npm-audit-8615-", dir=TEST_SCRATCH)
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.prefix = self.root / "sdk"
        self.package = self.prefix / DEEP_MERGE_NODE / "package.json"
        self.package.parent.mkdir(parents=True)
        self.package.write_text(json.dumps({"name": "deepmerge", "version": "4.3.1"}))
        self.lock = self.prefix / "package-lock.json"
        self.lock.write_text(json.dumps({"packages": {DEEP_MERGE_NODE: {"version": "4.3.1"}}}))
        self.report = {"deepmerge": {"nodes": [DEEP_MERGE_NODE]}}

    def test_8615_lock_and_installed_version_agree(self):
        self.assertEqual(gate.read_versions(self.prefix, self.report), {DEEP_MERGE_NODE: "4.3.1"})

    def test_8615_installed_version_drift_is_rejected(self):
        self.package.write_text(json.dumps({"name": "deepmerge", "version": "4.3.0"}))
        with self.assertRaises(gate.AuditError):
            gate.read_versions(self.prefix, self.report)

    def test_8615_lockfile_version_drift_is_rejected(self):
        self.lock.write_text(json.dumps({"packages": {DEEP_MERGE_NODE: {"version": "4.3.0"}}}))
        with self.assertRaises(gate.AuditError):
            gate.read_versions(self.prefix, self.report)

    def test_8615_missing_installed_package_is_rejected(self):
        self.package.unlink()
        with self.assertRaises(OSError):
            gate.read_versions(self.prefix, self.report)

    def test_8615_node_must_name_reported_package(self):
        for node in ("node_modules/jest", "../node_modules/deepmerge", "/node_modules/deepmerge"):
            with self.subTest(node=node), self.assertRaises(gate.AuditError):
                gate.read_versions(self.prefix, {"deepmerge": {"nodes": [node]}})

    def test_8615_installed_symlink_escape_is_rejected(self):
        outside = self.root / "outside.json"
        outside.write_bytes(self.package.read_bytes())
        self.package.unlink()
        self.package.symlink_to(outside)
        with self.assertRaises(gate.AuditError):
            gate.read_versions(self.prefix, self.report)


class NpmAudit8615Tests(unittest.TestCase):
    def setUp(self):
        self.clean = json.loads((FIXTURE_DIR / "clean.json").read_text())
        self.vulnerable = json.loads((FIXTURE_DIR / "vulnerable.json").read_text())

    def run_gate(self, report, returncode=0):
        result = subprocess.CompletedProcess([], returncode, json.dumps(report), "")
        with patch.object(gate.subprocess, "run", return_value=result) as run, \
                patch.object(gate, "load_exception_file", return_value=[]), \
                patch.object(gate, "read_versions", return_value={}):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = gate.main([])
        return code, run

    def test_8615_recorded_clean_report(self):
        code, run = self.run_gate(self.clean)
        self.assertEqual(code, 0)
        self.assertEqual(run.call_args.args[0], ["npm", "audit", "--json", "--audit-level=low", "--include=dev", "--include=optional", "--include=peer", "--prefix", "sdk/typescript"])
        self.assertTrue(run.call_args.kwargs["capture_output"])
        self.assertGreater(run.call_args.kwargs["timeout"], 0)
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_8615_recorded_low_advisory(self):
        self.assertEqual(self.run_gate(self.vulnerable, 1)[0], 1)

    def test_8615_production_environment_cannot_omit_development_audit(self):
        with patch.dict(os.environ, {"NODE_ENV": "production", "npm_config_omit": "dev"}):
            code, run = self.run_gate(self.clean)
        self.assertEqual(code, 0)
        self.assertIn("--include=dev", run.call_args.args[0])
        self.assertIn("--include=optional", run.call_args.args[0])
        self.assertIn("--include=peer", run.call_args.args[0])

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
        with patch.object(gate.subprocess, "run", return_value=result) as run, \
                patch.object(gate, "load_exception_file", return_value=[]), \
                patch.object(gate, "read_versions", return_value={}):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main(["--prefix", "sdk with spaces"]), 0)
        self.assertEqual(run.call_args.args[0][-1], "sdk with spaces")


if __name__ == "__main__":
    unittest.main()
