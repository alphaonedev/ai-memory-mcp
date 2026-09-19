#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Native federation data-tier certification; credentials remain in environment."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import re
import select
import time
import shutil
import signal
import subprocess
import sys
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit
import uuid

ROOT = Path(__file__).resolve().parents[2]
TESTS = ('cov_ga2_pg_federation', 'federation_postgres_fanout',
         'g4_postgres_link_projects_into_age_graph')
MAX_COMMAND_OUTPUT = 32 * 1024 * 1024  # Diagnostic budget, not a data/result cap.
FLOOR = 35  # 19 data-tier pins plus 16 shared-helper tests in two binaries.

class Failure(Exception):
    """Static, credential-free diagnostic safe to publish."""

class Unavailable(Failure):
    """The explicitly configured native cluster cannot be reached."""

def configuration(url):
    try:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, strict_parsing=True)
        options = dict(pairs)
        valid = (parts.scheme in ('postgres', 'postgresql')
                 and parts.hostname in ('127.0.0.1', 'localhost')
                 and parts.port == 5445 and not parts.fragment
                 and parts.path not in ('', '/')
                 and len(options) == len(pairs)
                 and options.get('sslmode') == 'verify-full'
                 and set(options) <= {'sslmode', 'sslrootcert', 'sslcert', 'sslkey', 'connect_timeout'})
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise Failure('configuration requires a loopback port5445 database URL with unique TLS verify-full options')
    return parts

def redact(text, urls):
    for url in urls:
        parts = urlsplit(url)
        for secret in (url, parts.password, unquote(parts.password or ''), quote(unquote(parts.password or ''), safe='')):
            if secret:
                text = text.replace(secret, '[REDACTED]')
    return re.sub(r'postgres(?:ql)?://[^\s\x1b"\'<>]+', '[REDACTED_DATABASE_URL]', text)

def complete(text, listed):
    if re.search(r'(?im)(?:^|\s)skip(?:ped)?(?::|\s)', text):
        raise Failure('completeness refused a skip token')
    rows = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    passed = sum(int(row[1]) for row in rows)
    if (not rows or listed < FLOOR or passed != listed
            or any(row[0] != 'ok' or int(row[2]) or int(row[3]) for row in rows)):
        raise Failure('completeness requires all listed tests, no failures/ignored tests, and the committed floor')
    return passed

def certify(value):
    if value != 't|18.6|1.8.0|0.8.6':
        raise Failure('native TLS/version pin mismatch (requires PG18.6 AGE1.8.0 pgvector0.8.6)')

def command(argv, env, seconds):
    """Bound diagnostic memory and the entire owned child process group."""
    process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.monotonic() + seconds
    chunks, size = [], 0
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise Failure('owned native command timed out')
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_COMMAND_OUTPUT:
                raise Failure('native diagnostic output exceeded the 32MiB memory budget')
            chunks.append(chunk)
        code = process.wait(timeout=max(1, deadline - time.monotonic()))
        return code, b''.join(chunks).decode(errors='replace')
    except (subprocess.TimeoutExpired, Failure, KeyboardInterrupt):
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        raise Failure('owned native command interrupted or exceeded its diagnostic/time budget') from None
    finally:
        process.stdout.close()

class Cluster:
    def __init__(self, url, psql):
        self.parts = configuration(url)
        self.url = url
        self.psql = psql

    def environment(self, url):
        parts = configuration(url)
        env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
        env.update(PGHOST=parts.hostname, PGPORT=str(parts.port),
                   PGUSER=unquote(parts.username or ''), PGPASSWORD=unquote(parts.password or ''),
                   PGDATABASE=unquote(parts.path[1:]), PGCONNECT_TIMEOUT='5')
        for key, value in parse_qsl(parts.query):
            env['PG' + key.upper()] = value
        # The caller cannot override the harness's bounded connection deadline.
        env['PGCONNECT_TIMEOUT'] = '5'
        return env

    def sql(self, url, statement):
        code, output = command([self.psql, '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', statement],
                               self.environment(url), 30)
        if code:
            raise Failure('native SQL failed; credential-bearing driver details suppressed')
        return output.strip()

    def preflight(self):
        try:
            self.sql(self.url, 'SELECT 1')
        except Failure:
            raise Unavailable('native connection unavailable') from None
        env = self.environment(self.url)
        env.update(PGHOST='invalid-native-cert-host.invalid', PGHOSTADDR='127.0.0.1')
        code, output = command([self.psql, '-X', '-A', '-t', '-c', 'SELECT 1'], env, 30)
        if code == 0 or 'does not match host name' not in output:
            raise Failure('TLS negative control did not reject the mismatched certificate hostname')
        print('NATIVE_TLS verify-full hostname-positive=pass hostname-negative=refused', flush=True)

    @contextlib.contextmanager
    def database(self):
        name = 'astra_native_' + uuid.uuid4().hex
        url = urlunsplit(self.parts._replace(path='/' + name))
        # Generated ASCII identifier, never interpolated caller input.
        self.sql(self.url, 'CREATE DATABASE "' + name + '"')
        print('NATIVE_DATABASE created ' + name, flush=True)
        try:
            yield url
        finally:
            self.sql(self.url, 'DROP DATABASE "' + name + '" WITH (FORCE)')
            absent = self.sql(self.url, "SELECT NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='" + name + "')")
            if absent != 't':
                raise Failure('native database cleanup was not confirmed')
            print('NATIVE_DATABASE dropped-and-verified ' + name, flush=True)


def interrupted(_signum, _frame):
    raise Failure('native run interrupted')

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-native', action='store_true', help='turn an explicit cluster skip into failure')
    parser.add_argument('--psql', default=shutil.which('psql'))
    args = parser.parse_args(argv)
    url = os.environ.get('AI_MEMORY_NATIVE_ADMIN_URL') or os.environ.get('AI_MEMORY_TEST_POSTGRES_URL')
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        if not url:
            raise Unavailable('admin URL unset')
        cluster = Cluster(url, args.psql)
        if not args.psql:
            raise Failure('psql executable must be on PATH or explicitly supplied')
        for key in ('CARGO_TARGET_DIR', 'TMPDIR'):
            if not os.environ.get(key):
                raise Failure('explicit CARGO_TARGET_DIR and TMPDIR are required')
        cluster.preflight()
        out = ROOT / '.local-runs/native-federation' / uuid.uuid4().hex
        out.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not out.resolve().is_relative_to(ROOT / '.local-runs/native-federation'):
            raise Failure('native evidence directory escapes the repository')
        sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, timeout=10).strip()
        records = {'commit': sha, 'tests': list(TESTS), 'working_tree_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True, timeout=10).strip())}
        with cluster.database() as child_url:
            cluster.sql(child_url, 'CREATE EXTENSION age; CREATE EXTENSION vector;')
            value = cluster.sql(child_url, "SELECT ssl::text || '|' || split_part(current_setting('server_version'),' ',1) || '|' || (SELECT extversion FROM pg_extension WHERE extname='age') || '|' || (SELECT extversion FROM pg_extension WHERE extname='vector') FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
            # bool::text yields true, while psql's bare boolean uses t.
            certify(value.replace('true|', 't|', 1))
            print('NATIVE_VERSIONS PG=18.6 AGE=1.8.0 vector=0.8.6 TLS=verify-full', flush=True)
            env = os.environ.copy()
            env.update(AI_MEMORY_TEST_POSTGRES_URL=child_url, AI_MEMORY_TEST_AGE_URL=child_url,
                       AI_MEMORY_NO_CONFIG='1', CARGO_BUILD_JOBS='2', CARGO_TERM_COLOR='never')
            cargo = ['cargo', 'test', '--features', 'sal-postgres']
            for test in TESTS:
                cargo += ['--test', test]
            print('CARGO_TARGET_DIR=' + env['CARGO_TARGET_DIR'], flush=True)
            code, listing = command(cargo + ['--', '--include-ignored', '--list'], env, 1800)
            listing = redact(listing, [url, child_url])
            (out / 'list.log').write_text(listing)
            if code:
                raise Failure('native test listing failed; see sanitized list.log')
            listed = len(re.findall(r'^\S+: test$', listing, re.MULTILINE))
            print('CARGO_TARGET_DIR=' + env['CARGO_TARGET_DIR'], flush=True)
            code, output = command(cargo + ['--', '--include-ignored', '--test-threads=1', '--nocapture'], env, 1800)
            output = redact(output, [url, child_url])
            (out / 'run.log').write_text(output)
            for line in output.splitlines():
                if line.startswith('test result:'):
                    print(line, flush=True)
            records.update(exit=code, listed=listed)
            (out / 'result.json').write_text(json.dumps(records, indent=2) + '\n')
            if code:
                raise Failure('native test command failed; see sanitized run.log')
            passed = complete(output, listed)
            guard, guard_output = command(['bash', 'scripts/check-cert-leg-nonvacuity.sh',
                '--leg', 'native-federation', '--log', str(out / 'run.log'), '--listed', str(listed)], env, 120)
            print(guard_output.strip(), flush=True)
            if guard:
                raise Failure('repository completeness guard refused native evidence')
        records.update(passed=passed, cleanup='verified', versions='18.6/1.8.0/0.8.6')
        (out / 'result.json').write_text(json.dumps(records, indent=2) + '\n')
        print(f'NATIVE_COMPLETE tests={passed} commit={sha} cleanup=verified', flush=True)
        return 0
    except Unavailable as error:
        print('skip: native-federation reason=' + str(error), flush=True)
        return 1 if args.require_native else 77
    except (Failure, OSError):
        # Neither argv/environment nor driver exception text is printed.
        print('NATIVE_FAILURE certification failed; inspect sanitized local evidence', flush=True)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)

if __name__ == '__main__':
    sys.exit(main())
