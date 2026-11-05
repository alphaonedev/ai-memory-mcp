#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Issue 8615: reject advisory reports and incomplete audit evidence offline."""

import copy
from datetime import date, timedelta
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
RECORDED = json.loads((DATA / "cargo_audit_unfiltered_8615.json").read_text())
TODAY = date(2026, 11, 5)
EXCEPTIONS = [
    {"id": "RUSTSEC-2023-0071", "package": "rsa", "version": "0.9.10",
     "issue": 8473, "expires": date(2027, 2, 3), "reason": "SQLx sibling driver; tracked removal."},
    {"id": "RUSTSEC-2024-0449", "package": "unsafe-libyaml", "version": "0.2.11",
     "issue": 8476, "expires": date(2027, 2, 3), "reason": "YAML parser replacement tracked."},
]


class TrackedExceptions8615Tests(unittest.TestCase):
    """R2 policy reconciles every report entry with one dated tracked exception."""

    def refusal(self, report, entries, pattern, identity=EXCEPTIONS[0]):
        """Every policy refusal carries the public identity needed for triage."""
        with self.assertRaisesRegex(ValueError, pattern) as caught:
            GATE.validate_report(report, entries, TODAY)
        for field in ("id", "package", "version"):
            self.assertIn(identity[field], str(caught.exception), field)
        return str(caught.exception)

    def test_unlisted_advisory_is_rejected(self):
        self.refusal(RECORDED, EXCEPTIONS[:1], "unlisted advisory", EXCEPTIONS[1])

    def test_expired_exception_is_rejected(self):
        entries = copy.deepcopy(EXCEPTIONS)
        entries[0]["expires"] = date(2026, 11, 4)
        message = self.refusal(RECORDED, entries, "expired exception")
        self.assertIn("2026-11-04", message)

    def test_stale_version_or_absent_entry_is_rejected(self):
        entries = copy.deepcopy(EXCEPTIONS)
        entries[0]["version"] = "0.9.9"
        message = self.refusal(RECORDED, entries, "stale exception")
        self.assertIn("0.9.9", message)
        self.refusal(CLEAN, EXCEPTIONS, "stale exception")

    def test_missing_exception_fields_are_rejected(self):
        for field in EXCEPTIONS[0]:
            entries = copy.deepcopy(EXCEPTIONS)
            del entries[0][field]
            with self.subTest(field=field):
                self.refusal(RECORDED, entries, "missing exception fields")

    def test_all_reported_advisories_match_unexpired_entries(self):
        self.assertEqual(GATE.validate_report(RECORDED, EXCEPTIONS, TODAY), (565, 1, 1))

    def test_invalid_expiry_issue_reason_and_duplicate_are_rejected(self):
        for field, value in (("expires", date(2027, 2, 4)), ("expires", "2027-02-03"),
                             ("issue", True), ("issue", 0), ("reason", ""),
                             ("reason", "two\nlines"), ("version", ">=0.9.10")):
            entries = copy.deepcopy(EXCEPTIONS)
            entries[0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError) as caught:
                GATE.validate_report(RECORDED, entries, TODAY)
            self.assertIn(EXCEPTIONS[0]["id"], str(caught.exception))
            self.assertIn(EXCEPTIONS[0]["package"], str(caught.exception))
        self.refusal(RECORDED, EXCEPTIONS + EXCEPTIONS[:1], "duplicate exception")

    def test_expiry_beyond_ninety_days_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "horizon"):
            GATE.validate_report(RECORDED, EXCEPTIONS, date(2026, 11, 4))

    def test_changed_package_is_stale(self):
        entries = copy.deepcopy(EXCEPTIONS)
        entries[0]["package"] = "other-package"
        message = self.refusal(RECORDED, entries, "stale exception")
        self.assertIn("other-package", message)


class CargoAudit8615Tests(unittest.TestCase):
    """The subprocess boundary must preserve every failure as a failed gate."""

    def run_gate(self, report=CLEAN, returncode=0, stdout=None, entries=None, today=TODAY):
        result = subprocess.CompletedProcess(
            ["cargo", "audit", "--json"], returncode,
            json.dumps(report) if stdout is None else stdout, "")
        with patch.object(GATE.subprocess, "run", return_value=result) as run, \
                patch.object(GATE, "load_policy", return_value=[] if entries is None else entries):
            with redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as error:
                code = GATE.main([], today=today)
            self.stdout = output.getvalue()
            self.stderr = error.getvalue()
        return code, run

    def test_8615_entry_expiring_today_passes(self):
        today = date(2027, 3, 4)
        entries = [dict(entry, expires=today) for entry in EXCEPTIONS]
        self.assertEqual(self.run_gate(RECORDED, 1, entries=entries, today=today)[0], 0)

    def test_8615_entry_expired_yesterday_fails(self):
        today = date(2027, 2, 4)
        self.assertEqual(self.run_gate(RECORDED, 1, entries=EXCEPTIONS, today=today)[0], 1)
        for entry in EXCEPTIONS:
            for field in ("id", "package", "version"):
                self.assertIn(entry[field], self.stderr)
        self.assertIn("2027-02-03", self.stderr)
        self.assertIn("Cargo audit ratchet:", self.stdout)

    def test_8615_entry_at_rolling_ceiling_passes(self):
        today = date(2027, 3, 4)
        expires = today + timedelta(days=GATE.MAX_EXCEPTION_DAYS)
        entries = [dict(entry, expires=expires) for entry in EXCEPTIONS]
        self.assertEqual(self.run_gate(RECORDED, 1, entries=entries, today=today)[0], 0)

    def test_8615_entry_beyond_rolling_ceiling_fails(self):
        today = date(2027, 3, 4)
        expires = today + timedelta(days=GATE.MAX_EXCEPTION_DAYS + 1)
        entries = [dict(entry, expires=expires) for entry in EXCEPTIONS]
        self.assertEqual(self.run_gate(RECORDED, 1, entries=entries, today=today)[0], 1)
        self.assertIn("horizon", self.stderr)
        self.assertIn(EXCEPTIONS[0]["id"], self.stderr)
        self.assertIn(expires.isoformat(), self.stderr)

    def test_8615_all_unlisted_messages_reach_workflow_output(self):
        self.assertEqual(self.run_gate(RECORDED, 1)[0], 1)
        self.assertIn("Cargo audit ratchet:", self.stdout)
        for entry in EXCEPTIONS:
            for field in ("id", "package", "version"):
                self.assertIn(entry[field], self.stderr)
        self.assertNotIn('"vulnerabilities"', self.stderr)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("          python3 scripts/ci/check_cargo_audit.py\n", workflow)

    def test_8615_clean_report_passes(self):
        code, run = self.run_gate()
        self.assertEqual(code, 0)
        self.assertEqual(run.call_args.args[0], ["cargo", "audit", "--json", "--deny", "warnings",
                                               "--file", str(ROOT / "Cargo.lock")])
        workdir = Path(run.call_args.kwargs["cwd"])
        self.assertEqual(workdir.parent, ROOT / ".local-runs")
        self.assertNotEqual(workdir, ROOT)
        self.assertFalse(workdir.exists(), "isolated cwd must be removed")
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_8615_vulnerability_fails_even_if_tool_returns_success(self):
        self.assertEqual(self.run_gate(ADVISORY)[0], 1)

    def test_8615_vulnerability_exit_fails(self):
        self.assertEqual(self.run_gate(ADVISORY, returncode=1)[0], 1)

    def test_8615_recorded_unfiltered_lock_fails(self):
        report = json.loads((DATA / "cargo_audit_unfiltered_8615.json").read_text())
        self.assertEqual(self.run_gate(report, returncode=1)[0], 1)

    def test_8615_recorded_unfiltered_lock_with_tracked_exceptions_passes(self):
        self.assertEqual(self.run_gate(RECORDED, returncode=1, entries=EXCEPTIONS)[0], 0)

    def test_8615_tool_status_must_agree_with_report(self):
        self.assertEqual(self.run_gate(RECORDED, returncode=0, entries=EXCEPTIONS)[0], 1)
        self.assertEqual(self.run_gate(RECORDED, returncode=2, entries=EXCEPTIONS)[0], 1)
        self.assertEqual(self.run_gate(CLEAN, returncode=1)[0], 1)

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

    def test_8615_policy_has_only_authorized_exceptions(self):
        entries = GATE.load_policy()
        identities = [(entry["id"], entry["package"], entry["version"], entry["issue"])
                      for entry in entries]
        expected = [(entry["id"], entry["package"], entry["version"], entry["issue"])
                    for entry in EXCEPTIONS]
        self.assertEqual(identities, expected)
        GATE.exception_index(entries, TODAY)
        for entry in entries:
            self.assertLessEqual(entry["expires"], date(2027, 2, 3))
        self.assertFalse((ROOT / "scripts/ci/cargo_audit_allowlist.json").exists())

    def test_8615_missing_or_malformed_policy_fails(self):
        for text in ('[advisories]\nignore = []', '{}', 'invalid'):
            with self.subTest(text=text), patch.object(Path, "read_text", return_value=text):
                with self.assertRaises(ValueError):
                    GATE.load_policy()

    def test_8615_ignore_ids_must_equal_metadata_ids(self):
        policy = GATE.POLICY.read_text()
        for edited in (policy.replace('    "RUSTSEC-2023-0071",', ''),
                       policy.replace('ignore = [', 'ignore = ["RUSTSEC-2099-0001",')):
            with patch.object(Path, "read_text", return_value=edited):
                with self.assertRaisesRegex(ValueError, "disagree"):
                    GATE.load_policy()

    def test_8615_filtered_or_missing_warning_classes_fail(self):
        for field, value in (("target_arch", ["x86_64"]), ("target_os", ["linux"]),
                             ("informational_warnings", []), ("informational_warnings", [{}])):
            report = copy.deepcopy(CLEAN)
            report["settings"][field] = value
            with self.subTest(field=field, value=value):
                self.assertEqual(self.run_gate(report)[0], 1)

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
