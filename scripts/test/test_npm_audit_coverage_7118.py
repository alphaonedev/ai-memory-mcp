#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Exercise real npm audit coverage against an inert loopback advisory service.

Protocol: https://docs.npmjs.com/cli/v11/commands/npm-audit/#bulk-advisory-endpoint
No package is installed and no public registry is needed. These tests inspect
actual npm requests and gate results, not an imitation of CLI argument parsing.
"""
import gzip
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'check-npm-audit-sdk.py'
SCRATCH = Path(os.environ.get('TMPDIR') or ROOT / '.local-runs')
HOST = '127.0.0.1'
PACKAGE = 'audit-coverage-canary-7118'
FIXTURE_PROJECT = 'audit-coverage-fixture-7118'
VERSION = '1.0.0'
VULNERABLE_RANGE = '<2.0.0'
ADVISORY_ID = 7118
ADVISORY_URL = 'https://example.invalid/advisory-7118'
ADVISORY_TITLE = 'inert test advisory'
BULK_ENDPOINT = '/-/npm/v1/security/advisories/bulk'
HTTP_OK = 200
HTTP_NOT_FOUND = 404
TIMEOUT_SECONDS = 30
LOCK_VERSION = 3
DEPENDENCY_FIELDS = {'dev': 'devDependencies', 'optional': 'optionalDependencies',
                     'peer': 'peerDependencies', 'prod': 'dependencies'}
PROXY_KEYS = ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')
EXIT_CLEAN = 0
EXIT_FINDINGS = 1


@unittest.skipUnless(shutil.which('npm'), 'real npm unavailable: coverage fixtures not evaluated')
class NpmCoveragePolicy(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.requests = []
        self.vulnerable = True
        owner = self

        class Registry(http.server.BaseHTTPRequestHandler):
            """Return a documented advisory payload; npm computes the report itself."""

            def respond(self, payload, status=HTTP_OK):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                if self.path != BULK_ENDPOINT:
                    self.respond({}, HTTP_NOT_FOUND)
                    return
                data = self.rfile.read(int(self.headers['Content-Length']))
                if self.headers.get('Content-Encoding') == 'gzip':
                    data = gzip.decompress(data)
                dependencies = json.loads(data)
                owner.requests.append(dependencies)
                advisory = {'name': PACKAGE, 'id': ADVISORY_ID, 'url': ADVISORY_URL,
                            'title': ADVISORY_TITLE, 'severity': 'critical',
                            'vulnerable_versions': VULNERABLE_RANGE}
                self.respond({PACKAGE: [advisory]} if owner.vulnerable and PACKAGE in dependencies
                             else {})

            def do_GET(self):
                if self.path != '/' + PACKAGE:
                    self.respond({}, HTTP_NOT_FOUND)
                    return
                self.respond({'name': PACKAGE, 'dist-tags': {'latest': VERSION},
                              'versions': {VERSION: {'name': PACKAGE, 'version': VERSION}}})

            def log_message(self, *_unused):
                pass

        server = http.server.ThreadingHTTPServer((HOST, 0), Registry)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()

        def stop_server():
            server.shutdown()
            server.server_close()
            worker.join(timeout=TIMEOUT_SECONDS)
        self.addCleanup(stop_server)
        self.registry = 'http://' + HOST + ':' + str(server.server_port) + '/'
        self.sequence = 0

    def invoke(self, kind='dev', settings=None, project_config='', arguments=()):
        self.sequence += 1
        directory = self.directory / str(self.sequence)
        directory.mkdir()
        manifest = {'name': FIXTURE_PROJECT, 'version': VERSION,
                    DEPENDENCY_FIELDS[kind]: {PACKAGE: VERSION}}
        entry = {'version': VERSION}
        if kind != 'prod':
            entry[kind] = True
        lock = {'name': FIXTURE_PROJECT, 'version': VERSION, 'lockfileVersion': LOCK_VERSION,
                'requires': True, 'packages': {'': manifest, 'node_modules/' + PACKAGE: entry}}
        (directory / 'package.json').write_text(json.dumps(manifest))
        (directory / 'package-lock.json').write_text(json.dumps(lock))
        (directory / '.npmrc').write_text(project_config)
        user_config = directory / 'user-config'
        global_config = directory / 'global-config'
        user_config.touch()
        global_config.touch()
        environment = {
            key: value for key, value in os.environ.items()
            if not key.lower().startswith('npm_config_') and key != 'NODE_ENV'
            and key.lower() not in PROXY_KEYS
        }
        environment.update(npm_config_registry=self.registry,
                           npm_config_cache=str(directory / 'cache'),
                           npm_config_userconfig=str(user_config),
                           npm_config_globalconfig=str(global_config),
                           TMPDIR=str(directory), TMP=str(directory), TEMP=str(directory),
                           NO_PROXY=HOST)
        environment.update(settings or {})
        self.requests.clear()
        result = subprocess.run([sys.executable, str(SCRIPT), '--dir', str(directory)]
                                + list(arguments), env=environment, capture_output=True,
                                text=True, timeout=TIMEOUT_SECONDS, check=False)
        submitted = any(PACKAGE in request for request in self.requests)
        return result.returncode, result.stdout + result.stderr, submitted

    def assert_full_finding(self, result):
        code, output, submitted = result
        self.assertEqual(code, EXIT_FINDINGS, output)
        self.assertTrue(submitted, 'actual npm request omitted the fixture package')
        self.assertIn('critical=1', output)

    def test_ordinary_vulnerable_control(self):
        self.assert_full_finding(self.invoke())

    def test_full_audit_overrides_production_defaults(self):
        for settings in ({'NODE_ENV': 'production'}, {'npm_config_production': 'true'},
                         {'npm_config_only': 'prod'}):
            with self.subTest(settings=settings):
                self.assert_full_finding(self.invoke(settings=settings))

    def test_full_audit_overrides_omit_environment_for_every_class(self):
        for kind in ('dev', 'optional', 'peer'):
            with self.subTest(kind=kind):
                self.assert_full_finding(self.invoke(kind, {'npm_config_omit': kind}))

    def test_full_audit_overrides_project_omit_configuration(self):
        for kind in ('dev', 'optional', 'peer'):
            with self.subTest(kind=kind):
                self.assert_full_finding(self.invoke(kind, project_config='omit=' + kind + '\n'))

    def test_healthy_control_still_submits_the_full_graph(self):
        self.vulnerable = False
        code, output, submitted = self.invoke(settings={'NODE_ENV': 'production'})
        self.assertEqual(code, EXIT_CLEAN, output)
        self.assertTrue(submitted, 'a clean result must come from auditing the fixture package')

    def test_explicit_runtime_mode_excludes_dev_despite_inherited_include(self):
        code, output, submitted = self.invoke(settings={'npm_config_include': 'dev'},
                                              arguments=('--omit-dev',))
        self.assertEqual(code, EXIT_CLEAN, output)
        self.assertFalse(submitted, 'explicit runtime-only policy unexpectedly submitted dev data')

    def test_explicit_runtime_mode_retains_runtime_optional_and_peer(self):
        for kind in ('prod', 'optional', 'peer'):
            with self.subTest(kind=kind):
                self.assert_full_finding(self.invoke(kind, arguments=('--omit-dev',)))


if __name__ == '__main__':
    unittest.main()
