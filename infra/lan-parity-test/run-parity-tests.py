#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Run both serialized LAN PostgreSQL passes with per-run database ownership.

Pass 1 runs the ordinary release suite in a fresh database. Pass 2 enumerates
test binaries and runs each binary containing ignored tests in another fresh
database. A failed first pass does not suppress the second pass. Only databases
whose CREATE succeeded in this process are cleaned up, using ordinary DROP.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from urllib.parse import quote, urlencode
import uuid

ROOT = Path(__file__).resolve().parents[2]
RUN_DIRECTORY = ROOT / '.local-runs'
DEFAULT_CA = RUN_DIRECTORY / 'lan-parity-ca.pem'
DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = '15432'
DEFAULT_USER = 'ai_memory'
DEFAULT_PASSWORD = 'ai_memory_test'
DEFAULT_MAINTENANCE = 'ai_memory_test'
PASS_ONE_PREFIX = 'ai_memory_test_p1_'
PASS_TWO_PREFIX = 'ai_memory_test_p2_'
FEATURES = 'sal,sal-postgres'
SERIAL_ARGUMENT = '--test-threads=1'
SQL_TIMEOUT_SECONDS = 30
CHILD_DRAIN_SECONDS = 30
FAILURE_STATUS = 1
CONFIGURATION_STATUS = 2
INTERRUPTED_STATUS = 130
SQL_EXTENSIONS = 'CREATE EXTENSION IF NOT EXISTS age; CREATE EXTENSION IF NOT EXISTS vector;'
SQL_PREFLIGHT = "SELECT 'pg+age reachable' AS status;"
TEST_RESULT = re.compile(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;')
PSQL_COMMAND = ['psql', '-X', '-q', '-At', '-v', 'ON_ERROR_STOP=1']


class RunnerError(Exception):
    """A required discovery, database or execution step failed."""


class Runner:
    def __init__(self, args, log):
        self.args = args
        self.log = log
        self.owned = set()
        self.cleanup_failed = False
        self.environment = dict(os.environ)
        self.environment.pop('AI_MEMORY_TEST_POSTGRES_URL', None)
        self.environment.update(AI_MEMORY_NO_CONFIG='1', PGHOST=args.pg_host,
                                PGPORT=args.pg_port, PGUSER=args.pg_user,
                                PGPASSWORD=os.environ.get('PGPASSWORD', DEFAULT_PASSWORD),
                                PGDATABASE=args.maintenance_database, PGSSLMODE='verify-full',
                                PGSSLROOTCERT=str(args.ca), TMPDIR=str(RUN_DIRECTORY),
                                TMP=str(RUN_DIRECTORY), TEMP=str(RUN_DIRECTORY))
        self.cargo = ([sys.executable, str(args.cargo_wrapper), 'cargo']
                      if args.cargo_wrapper else ['cargo'])

    def announce(self, message):
        line = '[lan-parity] ' + message
        print(line, flush=True)
        self.log.write(line + '\n')
        self.log.flush()

    def execute(self, arguments, database=None, capture=False, timeout=None):
        environment = dict(self.environment)
        if database:
            environment['AI_MEMORY_TEST_POSTGRES_URL'] = self.database_url(database)
        process = subprocess.Popen(arguments, cwd=ROOT, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True,
                                   start_new_session=True)
        try:
            output, _ = process.communicate(timeout=timeout)
        except BaseException:
            # Signal only this newly created process group, then drain it before
            # attempting ordinary database cleanup. Never terminate PG sessions.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=CHILD_DRAIN_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate(timeout=CHILD_DRAIN_SECONDS)
            raise
        self.log.write(output)
        self.log.flush()
        if not capture:
            print(output, end='', flush=True)
        return process.returncode, output

    def database_url(self, database):
        # Keep credentials in the child environment, never command arguments or
        # runner announcements. Encode CA paths containing '&', spaces or Unicode.
        user = quote(self.args.pg_user, safe='')
        password = quote(self.environment['PGPASSWORD'], safe='')
        host = self.args.pg_host
        if ':' in host and not host.startswith('['):
            host = '[' + host + ']'
        query = urlencode({'sslmode': 'verify-full', 'sslrootcert': str(self.args.ca)})
        return 'postgres://' + user + ':' + password + '@' + host + ':' + self.args.pg_port + '/' + database + '?' + query

    def sql(self, statement, database=None):
        args = PSQL_COMMAND + ['-d', database or self.args.maintenance_database, '-c', statement]
        status, _ = self.execute(args, capture=True, timeout=SQL_TIMEOUT_SECONDS)
        if status:
            raise RunnerError('PostgreSQL command failed (connection details omitted)')

    def create(self, prefix):
        name = prefix + uuid.uuid4().hex
        self.sql('CREATE DATABASE "' + name + '"')
        # CREATE refusal grants no ownership. Initialization failures still leave
        # the successful acquisition registered for the caller's finally block.
        self.owned.add(name)
        self.sql(SQL_EXTENSIONS, name)
        return name

    def drop(self, name):
        if name not in self.owned:
            raise RunnerError('refusing cleanup without acquired ownership')
        try:
            self.sql('DROP DATABASE "' + name + '"')
        except (RunnerError, OSError, subprocess.TimeoutExpired):
            self.cleanup_failed = True
            self.announce('Owned database cleanup failed: ' + name)
            return False
        self.owned.remove(name)
        return True

    def cleanup(self):
        for name in sorted(self.owned):
            self.drop(name)

    def default_pass(self):
        self.announce('Pass 1/2: default suite (serialized)')
        database = None
        try:
            database = self.create(PASS_ONE_PREFIX)
            status, _ = self.execute(self.cargo + ['test', '--features', FEATURES,
                                                    '--release', '--', SERIAL_ARGUMENT], database)
            return status
        except (RunnerError, OSError, subprocess.TimeoutExpired) as error:
            self.announce('Pass 1 failed: ' + type(error).__name__)
            return FAILURE_STATUS
        finally:
            if database is not None:
                self.drop(database)
            # A failed extension initialization has ownership but no returned name.
            self.cleanup()

    def binaries(self):
        status, output = self.execute(self.cargo + ['test', '--features', FEATURES,
                                                    '--release', '--no-run', '--message-format=json'],
                                      capture=True)
        if status:
            raise RunnerError('test binary enumeration failed')
        binaries = []
        for line in output.splitlines():
            if not line.startswith('{'):
                continue
            try:
                message = json.loads(line)
            except ValueError as error:
                raise RunnerError('malformed compiler artifact record') from error
            if not isinstance(message, dict):
                raise RunnerError('invalid compiler artifact record')
            if message.get('reason') != 'compiler-artifact':
                continue
            executable = message.get('executable')
            profile = message.get('profile')
            if executable and isinstance(profile, dict) and profile.get('test'):
                path = Path(executable)
                if not path.is_file() or not os.access(path, os.X_OK):
                    raise RunnerError('enumerated test executable is unavailable')
                if path not in binaries:
                    binaries.append(path)
        if not binaries:
            raise RunnerError('no test binaries enumerated for Pass 2')
        return binaries

    def live_pass(self):
        self.announce('Pass 2/2: ignored live tests (per-binary database isolation)')
        try:
            binaries = self.binaries()
        except (RunnerError, OSError, subprocess.TimeoutExpired) as error:
            self.announce('Pass 2 discovery failed: ' + type(error).__name__)
            return FAILURE_STATUS
        failed = False
        exercised = 0
        for binary in binaries:
            database = None
            try:
                status, listing = self.execute([str(binary), '--list', '--ignored', '--format', 'terse'],
                                               capture=True)
                if status:
                    raise RunnerError('ignored-test listing failed')
                ignored = sum(line.endswith(': test') for line in listing.splitlines())
                if not ignored:
                    self.announce('No ignored tests in ' + binary.name)
                    continue
                database = self.create(PASS_TWO_PREFIX)
                self.announce('Running ' + binary.name + ' in ' + database)
                status, output = self.execute([str(binary), '--include-ignored', SERIAL_ARGUMENT], database)
                counts = TEST_RESULT.findall(output)
                if status or not counts or sum(int(passed) for passed, _, _ in counts) < ignored:
                    raise RunnerError('live test execution failed or did not execute discovered tests')
                exercised += 1
            except (RunnerError, OSError, subprocess.TimeoutExpired) as error:
                failed = True
                self.announce('Live binary failed: ' + binary.name + ' (' + type(error).__name__ + ')')
            finally:
                if database is not None:
                    self.drop(database)
                self.cleanup()
        self.announce('Live binaries completed: ' + str(exercised))
        return FAILURE_STATUS if failed else 0


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ca', type=Path, default=Path(os.environ.get('PG_CA', DEFAULT_CA)))
    parser.add_argument('--pg-host', default=DEFAULT_HOST)
    parser.add_argument('--pg-port', default=DEFAULT_PORT)
    parser.add_argument('--pg-user', default=DEFAULT_USER)
    parser.add_argument('--maintenance-database', default=DEFAULT_MAINTENANCE)
    parser.add_argument('--cargo-wrapper', type=Path,
                        help='Python admission wrapper invoked before each Cargo command')
    args = parser.parse_args()
    if not args.ca.is_file() or not args.ca.stat().st_size:
        print('[lan-parity] ERROR: fleet CA is missing or empty; set PG_CA or --ca.', file=sys.stderr)
        return CONFIGURATION_STATUS
    RUN_DIRECTORY.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H-%M-%SZ')
    log_path = RUN_DIRECTORY / ('lan-parity-' + timestamp + '-' + uuid.uuid4().hex + '.log')
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        with log_path.open('x') as log:
            runner = Runner(args, log)
            default_status = live_status = FAILURE_STATUS
            interrupted_status = 0
            try:
                runner.sql(SQL_PREFLIGHT)
                default_status = runner.default_pass()
                live_status = runner.live_pass()
            except KeyboardInterrupt:
                interrupted_status = INTERRUPTED_STATUS
                runner.announce('Interrupted; cleaning only acquired resources')
            except (RunnerError, OSError, subprocess.TimeoutExpired) as error:
                runner.announce('Runner failed: ' + type(error).__name__)
            finally:
                runner.cleanup()
            status = interrupted_status or default_status or live_status or int(runner.cleanup_failed)
            runner.announce('Overall exit code: ' + str(status) + ' (default=' + str(default_status)
                            + ', ignored=' + str(live_status) + ')')
            runner.announce('Log preserved at: ' + str(log_path))
            return status
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    raise SystemExit(main())
