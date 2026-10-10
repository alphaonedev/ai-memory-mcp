# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Exercise the LAN runner as a process with inert PostgreSQL/Cargo stand-ins."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[3]
RUNNER_DIRECTORY = Path('infra/lan-parity-test')
PYTHON_RUNNER = 'run-parity-tests.py'
SHELL_RUNNER = 'run-parity-tests.sh'
PROCESS_TIMEOUT = 30
FAILURE_STATUS = 7
STAND_IN = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

NAME = Path(sys.argv[0]).name
ARGUMENTS = sys.argv[1:]
CASE = os.environ.get('LAN_TEST_CASE', 'healthy')
FAILURE_STATUS = 7
EVENTS = Path(os.environ['LAN_TEST_EVENTS'])
with EVENTS.open('a') as output:
    output.write(json.dumps({'program': NAME, 'arguments': ARGUMENTS,
                            'url': os.environ.get('AI_MEMORY_TEST_POSTGRES_URL', '')}) + '\n')
if NAME == 'cargo':
    if '--no-run' in ARGUMENTS:
        if CASE == 'enumeration-fails':
            raise SystemExit(FAILURE_STATUS)
        print(json.dumps({'reason': 'compiler-artifact', 'profile': {'test': True},
                          'executable': os.environ['LAN_TEST_BINARY']}))
    elif CASE == 'default-fails':
        raise SystemExit(FAILURE_STATUS)
elif NAME == 'psql':
    statement = ARGUMENTS[ARGUMENTS.index('-c') + 1] if '-c' in ARGUMENTS else ''
    if CASE == 'create-fails' and statement.startswith('CREATE DATABASE'):
        raise SystemExit(FAILURE_STATUS)
    if CASE == 'drop-fails' and statement.startswith('DROP DATABASE'):
        raise SystemExit(FAILURE_STATUS)
    if CASE == 'extension-fails' and 'CREATE EXTENSION' in statement:
        raise SystemExit(FAILURE_STATUS)
elif NAME == 'live-test':
    if '--list' in ARGUMENTS:
        if CASE == 'listing-fails':
            raise SystemExit(FAILURE_STATUS)
        print('live_postgres_control: test')
    else:
        print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out')
'''


class LanParityRunner7086(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        runner_dir = self.root / RUNNER_DIRECTORY
        runner_dir.mkdir(parents=True)
        source = ROOT / RUNNER_DIRECTORY / PYTHON_RUNNER
        interpreter = sys.executable
        if not source.exists():
            source = ROOT / RUNNER_DIRECTORY / SHELL_RUNNER
            interpreter = 'bash'
        destination = runner_dir / source.name
        shutil.copyfile(source, destination)
        self.command = [interpreter, str(destination)]
        fake_bin = self.root / 'bin'
        fake_bin.mkdir()
        for name in ('cargo', 'psql', 'live-test'):
            executable = fake_bin / name
            executable.write_text(STAND_IN)
            executable.chmod(0o700)
        self.events = self.root / 'events.jsonl'
        self.ca = self.root / 'ca & unicode-é.pem'
        self.ca.write_text('inert certificate; stand-in psql never connects\n')
        self.environment = dict(os.environ)
        for key in ('AI_MEMORY_TEST_POSTGRES_URL', 'CARGO_TARGET_DIR'):
            self.environment.pop(key, None)
        self.environment.update(
            PATH=str(fake_bin) + os.pathsep + os.environ['PATH'], PG_CA=str(self.ca),
            LAN_TEST_EVENTS=str(self.events), LAN_TEST_BINARY=str(fake_bin / 'live-test'),
            TMPDIR=str(self.root), TMP=str(self.root), TEMP=str(self.root))

    def run_case(self, case):
        result = subprocess.run(self.command, env=dict(self.environment, LAN_TEST_CASE=case),
                                cwd=self.root, capture_output=True, text=True,
                                timeout=PROCESS_TIMEOUT)
        events = [json.loads(line) for line in self.events.read_text().splitlines()]
        return result, events

    @staticmethod
    def statements(events):
        return [event['arguments'][event['arguments'].index('-c') + 1]
                for event in events if event['program'] == 'psql' and '-c' in event['arguments']]

    def test_default_failure_still_executes_live_pass(self):
        result, events = self.run_case('default-fails')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(any(event['program'] == 'live-test'
                            and '--include-ignored' in event['arguments'] for event in events),
                        'Pass 1 failure must not suppress the live PostgreSQL pass')

    def test_healthy_two_passes_are_serial_and_use_distinct_owned_databases(self):
        result, events = self.run_case('healthy')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        runs = [event for event in events if '--test-threads=1' in event['arguments']]
        self.assertEqual(len(runs), 2, 'both passes must execute serially')
        databases = [urlsplit(event['url']).path for event in runs]
        self.assertEqual(len(set(databases)), 2, 'each pass must have isolated ownership')
        self.assertTrue(all(name != '/ai_memory_test' for name in databases))
        for event in runs:
            query = parse_qs(urlsplit(event['url']).query)
            self.assertEqual(query.get('sslmode'), ['verify-full'])
            self.assertEqual(query.get('sslrootcert'), [str(self.ca)])
        statements = self.statements(events)
        self.assertFalse(any('FORCE' in statement for statement in statements))
        self.assertFalse(any('LIKE' in statement for statement in statements),
                         'a runner must not reap other executions by prefix')

    def test_failed_create_does_not_acquire_drop_ownership(self):
        result, events = self.run_case('create-fails')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(statement.startswith('DROP DATABASE')
                             for statement in self.statements(events)))

    def test_cleanup_failure_is_not_reported_as_success(self):
        result, _ = self.run_case('drop-fails')
        self.assertNotEqual(result.returncode, 0, 'failed cleanup must fail the runner')

    def test_failed_listing_is_not_a_zero_ignored_test_success(self):
        result, _ = self.run_case('listing-fails')
        self.assertNotEqual(result.returncode, 0, 'failed discovery is missing coverage')

    def test_failed_enumeration_is_not_a_success(self):
        result, _ = self.run_case('enumeration-fails')
        self.assertNotEqual(result.returncode, 0)

    def test_extension_failure_still_cleans_acquired_databases(self):
        result, events = self.run_case('extension-fails')
        self.assertNotEqual(result.returncode, 0)
        statements = self.statements(events)
        self.assertTrue(any(statement.startswith('CREATE DATABASE') for statement in statements))
        self.assertTrue(any(statement.startswith('DROP DATABASE') for statement in statements))


if __name__ == '__main__':
    unittest.main()
