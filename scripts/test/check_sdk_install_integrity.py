#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Exercise ordinary SDK npm installation against an inert native fallback (#7117).

Run after a healthy npm ci has populated the cache. This Linux x64 GNU probe
omits optional bindings, refuses the fallback's nested npm install, and serves
inert tar bytes from loopback. The native payload is never executed. Evidence
must be a new directory outside tmpfs; success requires zero fallback requests
and an explicit missing-binding error when the resolver is subsequently used.
"""

import argparse
import base64
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import threading

DEFAULT_SDK = Path(__file__).resolve().parents[2] / 'sdk' / 'typescript'
SUPPORTED_SYSTEM = 'Linux'
SUPPORTED_MACHINES = ('x86_64', 'amd64')
SUPPORTED_LIBC = 'glibc'
HOST = '127.0.0.1'
TIMEOUT_SECONDS = 180
PAYLOAD = b'INSTALL_REGRESSION_INERT_BYTES_NOT_A_NATIVE_LIBRARY\n'
BINARY = 'resolver.linux-x64-gnu.node'
LOCK_PACKAGE = 'node_modules/@unrs/resolver-binding-linux-x64-gnu'
PACKAGE_FILES = ('package.json', 'package-lock.json')
POLICY_NAME = '.npmrc'
MODULES = Path('node_modules')
RESOLVER = 'unrs-resolver'
IGNORE_SCRIPTS_ENV = 'npm_config_ignore_scripts'
NAPI_ENV_PREFIX = 'NAPI_RS_'
LOAD_COMMAND = ['node', '-e', 'require("unrs-resolver")']
MISSING_BINDING_MESSAGE = 'Cannot find native binding'
CI_ARGS = ['ci', '--offline', '--omit=optional', '--no-audit', '--no-fund', '--foreground-scripts']
HTTP_OK = 200
EXIT_FAILURE = 1


def exercise(sdk: Path, evidence: Path) -> int:
    """Install the actual locked packages; assert behavior, not configuration text."""
    npm_binary = shutil.which('npm')
    if not npm_binary:
        raise RuntimeError('npm is required; installation was not evaluated')
    evidence.mkdir(parents=True, exist_ok=False)
    target = evidence / 'install'
    target.mkdir()
    for name in PACKAGE_FILES:
        shutil.copyfile(sdk / name, target / name)
    if (sdk / POLICY_NAME).exists():
        shutil.copyfile(sdk / POLICY_NAME, target / POLICY_NAME)
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        member = tarfile.TarInfo('package/' + BINARY)
        member.size = len(PAYLOAD)
        tar.addfile(member, io.BytesIO(PAYLOAD))
    data = archive.getvalue()
    lock = json.loads((target / PACKAGE_FILES[1]).read_text())
    expected = lock['packages'][LOCK_PACKAGE]['integrity']
    actual = 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()
    if actual == expected:
        raise RuntimeError('the adversarial archive must differ from locked integrity')
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        """Serve only inert test data; never proxy registry traffic."""

        def do_GET(self):
            requests.append(self.path)
            self.send_response(HTTP_OK)
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_unused):
            pass

    server = http.server.ThreadingHTTPServer((HOST, 0), Handler)
    registry = 'http://' + HOST + ':' + str(server.server_port) + '/'
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        shim_dir = target / 'bin'
        shim_dir.mkdir()
        shim = shim_dir / 'npm'
        shim.write_text(
            '#!' + sys.executable + '\n'
            '"""Refuse nested installation; expose the inert loopback registry."""\n'
            'import sys\nREGISTRY = ' + repr(registry) + '\n'
            'if sys.argv[1:] == ["config", "get", "registry"]:\n'
            ' print(REGISTRY)\n sys.exit(0)\nsys.exit(1)\n')
        shim.chmod(0o755)
        environment = {
            key: value for key, value in os.environ.items()
            if key.lower() != IGNORE_SCRIPTS_ENV and not key.startswith(NAPI_ENV_PREFIX)
        }
        user_config = target / 'empty-user-config'
        global_config = target / 'empty-global-config'
        user_config.touch()
        global_config.touch()
        environment.update(PATH=str(shim_dir) + os.pathsep + os.environ['PATH'],
                           TMPDIR=str(target), TMP=str(target), TEMP=str(target),
                           npm_config_userconfig=str(user_config),
                           npm_config_globalconfig=str(global_config))
        command = [npm_binary] + CI_ARGS
        with (evidence / 'npm-ci.log').open('x') as log:
            result = subprocess.run(command, cwd=target, env=environment, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=TIMEOUT_SECONDS)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=TIMEOUT_SECONDS)
    native = target / MODULES / RESOLVER / BINARY
    accepted = native.exists() and native.read_bytes() == PAYLOAD
    report = {'command': command, 'returncode': result.returncode,
              'requests': requests, 'inert_binary_accepted': accepted,
              'integrity_matches': actual == expected, 'native_payload_executed': False}
    if result.returncode == 0 and not native.exists() and not requests:
        with (evidence / 'missing-binding-load.log').open('x') as log:
            load = subprocess.run(LOAD_COMMAND, cwd=target, env=environment, stdout=log,
                                  stderr=subprocess.STDOUT, timeout=TIMEOUT_SECONDS)
        report['missing_binding_load_exit'] = load.returncode
        report['missing_binding_diagnostic'] = MISSING_BINDING_MESSAGE in (
            evidence / 'missing-binding-load.log').read_text(errors='replace')
    (evidence / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    if result.returncode != 0:
        raise RuntimeError('installation failed before reaching the intended success path')
    if native.exists() or requests:
        raise RuntimeError('ordinary npm ci invoked the unverified native fallback')
    if not report.get('missing_binding_load_exit') or not report.get('missing_binding_diagnostic'):
        raise RuntimeError('missing binding did not produce the intended explicit refusal')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, default=DEFAULT_SDK)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if (platform.system() != SUPPORTED_SYSTEM or platform.machine() not in SUPPORTED_MACHINES
            or platform.libc_ver()[0] != SUPPORTED_LIBC):
        parser.error('this native fallback regression requires Linux x64 GNU; not evaluated')
    try:
        return exercise(args.sdk.resolve(), args.evidence.resolve())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        return EXIT_FAILURE


if __name__ == '__main__':
    sys.exit(main())
