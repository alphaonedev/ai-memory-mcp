#!/usr/bin/env python3
"""Install cargo-nextest into a directory this CI job owns (#7259).

``cargo install cargo-nextest --locked --version <V> --root <root>`` from
crates.io, then put ``<root>/bin`` on the PATH of the later steps through
``$GITHUB_PATH``.

Why a per-job root and not ``~/.cargo/bin``: some self-hosted runners keep
``~/.cargo/bin`` write-protected (``Operation not permitted``), and a binary an
earlier job left in a shared folder is not something a later job may trust. The
root is ``$RUNNER_TEMP/cargo-nextest``: ``RUNNER_TEMP`` is created fresh for the
job and removed after it, on hosted and self-hosted runners alike, and it is
always writable by the job's user. Unlike ``RUNNER_TOOL_CACHE`` it is not shared
between jobs. Hosted runners restore a previously built root through the
workflow's existing ``Swatinem/rust-cache`` step (``cache-directories``); cargo
then reports the package as already installed, and the version of the binary
that ends up on the PATH is checked here either way.

The version comes from ``--version`` or the workflow-level ``NEXTEST_VERSION``
env var, the single place the pin is written.

Exit codes: 0 installed and verified, 1 the installed binary is not the pinned
version, 2 bad arguments or environment, otherwise cargo's own exit code.
Standard library only, Python 3.9+.
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, Mapping, Optional

EXIT_WRONG_VERSION = 1
EXIT_USAGE = 2
VERSION_ENV = 'NEXTEST_VERSION'
ROOT_DIRNAME = 'cargo-nextest'
_VERSION_RE = re.compile(r'^\d+\.\d+\.\d+$')


class InstallError(Exception):
    """Unusable arguments or environment."""


def check_version(version: str) -> str:
    if not _VERSION_RE.match(version or ''):
        raise InstallError('version must look like 0.9.146, got %r' % (version,))
    return version


def default_root(env: Mapping[str, str]) -> Path:
    temp = env.get('RUNNER_TEMP', '')
    if not temp:
        raise InstallError('RUNNER_TEMP is not set; pass --root explicitly')
    return Path(temp) / ROOT_DIRNAME


def install_argv(version: str, root: Path) -> List[str]:
    return ['cargo', 'install', 'cargo-nextest', '--locked', '--version', version, '--root', str(root)]


def run(version: str, root: Path, github_path: Optional[Path],
        runner: Callable = subprocess.run) -> int:
    """Install, verify the installed binary, then extend ``$GITHUB_PATH``."""
    done = runner(install_argv(version, root))
    if done.returncode != 0:
        print('::error::cargo install cargo-nextest %s failed (exit %d)' % (version, done.returncode))
        return done.returncode
    binary = root / 'bin' / 'cargo-nextest'
    probe = runner([str(binary), 'nextest', '--version'], capture_output=True, text=True)
    first = (probe.stdout or '').splitlines()[0] if (probe.stdout or '').strip() else ''
    if probe.returncode != 0 or first.split()[:2] != ['cargo-nextest', version]:
        print('::error::installed cargo-nextest is %r, expected %s' % (first, version))
        return EXIT_WRONG_VERSION
    if github_path is not None:
        with github_path.open('a', encoding='utf-8') as handle:
            handle.write(str(root / 'bin') + '\n')
    print('cargo-nextest %s installed in %s' % (version, root / 'bin'))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--version', default=os.environ.get(VERSION_ENV, ''),
                        help='pinned version (default: $%s)' % VERSION_ENV)
    parser.add_argument('--root', default=None, help='install root (default: $RUNNER_TEMP/%s)' % ROOT_DIRNAME)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        version = check_version(args.version)
        root = Path(args.root) if args.root else default_root(os.environ)
    except InstallError as exc:
        print('install_nextest: %s' % exc, file=sys.stderr)
        return EXIT_USAGE
    target = os.environ.get('GITHUB_PATH')
    return run(version, root, Path(target) if target else None)


if __name__ == '__main__':
    sys.exit(main())
