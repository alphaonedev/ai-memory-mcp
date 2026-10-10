#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Reject ambiguous raw JSON through the file and actual npm-process paths."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.test.test_npm_audit_report_integrity_7108 import report_for

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'check-npm-audit-sdk.py'
SCRATCH = Path(os.environ.get('TMPDIR') or ROOT / '.local-runs')
REPORT_NAME = 'audit.json'
NPM_NAME = 'npm'
FIXTURE_PATH_ENV = 'AUDIT_RAW_FIXTURE_7119'
FIXTURE_STATUS_ENV = 'AUDIT_PROCESS_STATUS_7119'
CANARY = 'REPORT_OR_STDERR_CANARY_7119'
DIAGNOSTIC = 'check-npm-audit-sdk:'
PROCESS_TIMEOUT_SECONDS = 20
EXECUTABLE_MODE = 0o755
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def ambiguous_reports():
    """Raw members are intentional: a Python dictionary cannot retain duplicates."""
    clean = json.dumps(report_for())
    low = json.dumps(report_for('low'))
    return {
        'hidden-top-level': '{"vulnerabilities":{"hidden":{"severity":"critical"}},'
                            + clean[1:],
        'hidden-counts': clean.replace('"critical": 0', '"critical": 1,"critical": 0')
                             .replace('"total": 0', '"total": 1,"total": 0'),
        'hidden-severity': low.replace('"severity": "low"',
                                     '"severity":"critical","severity":"low"'),
        'escaped-equal-key': '{"' + CANARY + '":1,"\\u0052' + CANARY[1:] + '":2,'
                             + clean[1:],
        'nested-array': clean.replace('"metadata": {',
                                     '"metadata": {"details":[{"k":1,"k":2}],'),
        'empty-member': '{"":1,"":2,' + clean[1:],
    }


class DuplicateAuditMembers(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.report_path = self.directory / REPORT_NAME
        npm = self.directory / NPM_NAME
        npm.write_text(
            '#!' + sys.executable + '\n'
            '"""Return the exact raw fixture, with no JSON normalization."""\n'
            'import os, pathlib, sys\n'
            'sys.stdout.write(pathlib.Path(os.environ[' + repr(FIXTURE_PATH_ENV) + ']).read_text())\n'
            'sys.stderr.write(' + repr(CANARY) + ')\n'
            'sys.exit(int(os.environ[' + repr(FIXTURE_STATUS_ENV) + ']))\n')
        npm.chmod(EXECUTABLE_MODE)

    def invoke(self, raw, source, process_status=EXIT_CLEAN):
        self.report_path.write_text(raw, encoding='utf-8')
        environment = dict(os.environ, PATH=str(self.directory))
        environment[FIXTURE_PATH_ENV] = str(self.report_path)
        environment[FIXTURE_STATUS_ENV] = str(process_status)
        arguments = (['--json-file', str(self.report_path)] if source == 'file'
                     else ['--dir', str(self.directory)])
        result = subprocess.run([sys.executable, str(SCRIPT)] + arguments, env=environment,
                                capture_output=True, text=True, timeout=PROCESS_TIMEOUT_SECONDS,
                                check=False)
        return result.returncode, result.stdout + result.stderr

    def test_duplicate_members_are_rejected_in_both_routes(self):
        for name, raw in ambiguous_reports().items():
            for source in ('file', 'process'):
                with self.subTest(case=name, source=source):
                    code, output = self.invoke(raw, source)
                    self.assertEqual(code, EXIT_ERROR, output)
                    self.assertIn(DIAGNOSTIC, output)
                    self.assertNotIn(CANARY, output)
                    self.assertNotIn('Traceback', output)
                    self.assertNotIn('OK: no findings', output)

    def test_clean_and_advisory_controls(self):
        for source in ('file', 'process'):
            for severities, expected in (((), EXIT_CLEAN), (('critical',), EXIT_FINDINGS)):
                with self.subTest(source=source, severities=severities):
                    code, output = self.invoke(json.dumps(report_for(*severities)), source, expected)
                    self.assertEqual(code, expected, output)
                    self.assertNotIn(CANARY, output)

    def test_distinct_member_names_and_duplicate_text_values_are_valid(self):
        report = report_for()
        report['metadata']['note'] = '{"critical":1,"critical":0}'
        report['metadata']['same_values'] = ['same', 'same']
        report['metadata']['Upper'] = 'value'
        report['metadata']['upper'] = 'value'
        for source in ('file', 'process'):
            with self.subTest(source=source):
                code, output = self.invoke(json.dumps(report), source)
                self.assertEqual(code, EXIT_CLEAN, output)
                self.assertNotIn(CANARY, output)


if __name__ == '__main__':
    unittest.main()
