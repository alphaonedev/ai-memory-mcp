#!/usr/bin/env python3
"""Behavioral security regressions for #6163; run with python3 -I -m unittest.

All credential-shaped strings are synthetic canaries, never real credentials.
The W1/R2 contract is authorized by conductor ruling 274361a0.
"""
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
SCRATCH = ROOT / '.local-runs' / 'codeql-6163'
CANARY = 'SYNTHETIC_6163_CONFIDENTIAL_VALUE'
PRIVATE_MODE = 0o600
DIRECTORY_MODE = 0o700
REPOSITORY = 'alphaonedev/ai-memory-mcp'
ISOLATED_FLAGS = argparse.Namespace(**{name: getattr(sys.flags, name) for name in dir(sys.flags)
                                      if isinstance(getattr(sys.flags, name), int)})
ISOLATED_FLAGS.isolated = 1
HISTORICAL_SHAPES = (
    'password=' + CANARY,
    'secret: # comment\n  # another comment\n  ' + CANARY,
    'token: !tag &anchor |2\n  ' + CANARY,
    'secret: """\n' + CANARY + '\n"""',
    'https://user:' + CANARY + '/?#@[::1]/',
    '[link](https://user:' + CANARY + '@host_name).',
    '-----BEGIN PRIVATE KEY-----\n' + CANARY + '\n-----END PRIVATE KEY-----',
    '---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n' + CANARY,
    'AGE-SECRET-KEY-' + CANARY,
    '{"kty":"oct","k":"' + CANARY + '"}',
    'password' + (' ' * 9000) + ':\n' + CANARY,
    'ordinary prose\u2028' + CANARY + '\u2029end',
)


def module(name, relative):
    """Load only the author checkout's first-party script."""
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class ComparisonTests(unittest.TestCase):
    """Exercise actual Git objects and both production output sinks."""

    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.compare = module('compare_6163', 'scripts/claude-md-rule-compare.py')
        self.guard = module('guard_6163', 'scripts/check-claude-md-size.py')
        self.repo = self.work / 'repo'
        self.base = self.compare.make_repo(self.guard, self.repo)
        self.base_root = self.work / 'base'
        shutil.copytree(self.repo, self.base_root, ignore=shutil.ignore_patterns('.git'))
        shutil.copyfile(ROOT / self.compare.GUARD_REL, self.base_root / self.compare.GUARD_REL)

    def run_head(self, payload, approved=False):
        """Return verdict and stdout/stderr/summary from the real compare/run path."""
        path = self.repo / 'CLAUDE.md'
        path.write_text(path.read_text().replace('The tool limit is 103 tools.', payload, 1))
        with contextlib.redirect_stderr(io.StringIO()):
            self.guard.update_manifest_quiet(self.repo)
        message = 'change' + ('\n\nRule-Change-Approved-By: ' + CANARY if approved else '')
        head = self.compare.commit_all(self.repo, message)
        args = argparse.Namespace(base_root=str(self.base_root), repo=str(self.repo), base_sha=self.base,
                                  head_sha=head, scratch=str(self.work / 'data'),
                                  summary=str(self.work / 'summary'), event=None)
        compare = self.compare.compare

        def actual(*args):
            return compare(*args, index_pins=self.guard.fixture_index_pins())

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(self.compare, 'compare', side_effect=actual), \
                mock.patch.object(self.compare.sys, 'flags', ISOLATED_FLAGS), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = self.compare.run(args)
        return result, out.getvalue() + err.getvalue() + (self.work / 'summary').read_text(), head

    def test_historical_shapes_never_reach_output_but_verdict_and_navigation_do(self):
        for approved in (False, True):
            for payload in HISTORICAL_SHAPES:
                with self.subTest(approved=approved, shape=HISTORICAL_SHAPES.index(payload)):
                    # Reset only this synthetic file; no branch reset or inherited work is touched.
                    shutil.copyfile(self.base_root / 'CLAUDE.md', self.repo / 'CLAUDE.md')
                    (self.work / 'summary').unlink(missing_ok=True)
                    result, output, head = self.run_head(payload, approved)
                    self.assertEqual(result, 0 if approved else 1)
                    self.assertNotIn(CANARY, output)
                    self.assertIn('RULE TEXT CHANGED', output)
                    self.assertIn('/blob/' + head + '/CLAUDE.md#L', output)
                    self.assertIn('section=', output)
                    self.assertIn('RESULT: PASS' if approved else 'RESULT: FAIL', output)

    def test_healthy_prose_change_retains_verdict_and_navigation(self):
        result, output, head = self.run_head('The tool limit is changed.')
        self.assertEqual(result, 1)
        self.assertIn('RULE TEXT CHANGED', output)
        self.assertIn('/blob/' + head + '/CLAUDE.md#L', output)

    def test_head_heading_and_guard_error_do_not_escape(self):
        result, output, _ = self.run_head('## ' + CANARY + '\nrule\n## ' + CANARY)
        self.assertEqual(result, 1)
        self.assertNotIn(CANARY, output)
        self.assertIn('BASE GUARD REFUSES THE HEAD', output)

    def test_exception_paths_do_not_echo_untrusted_text(self):
        for exception in (OSError(CANARY), RuntimeError(CANARY), ValueError(CANARY), SyntaxError(CANARY)):
            with self.subTest(kind=type(exception).__name__):
                args = argparse.Namespace(scratch=str(self.work), base_root=str(self.base_root),
                                          repo=str(self.repo), base_sha=self.base, head_sha=self.base,
                                          summary=str(self.work / 'summary-error'), event=None)
                out, err = io.StringIO(), io.StringIO()
                with mock.patch.object(self.compare, 'compare', side_effect=exception), \
                        mock.patch.object(self.compare.sys, 'flags', ISOLATED_FLAGS), \
                        contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(self.compare.run(args), 1)
                self.assertNotIn(CANARY, out.getvalue() + err.getvalue() + Path(args.summary).read_text())

    def test_git_environment_cannot_replace_objects(self):
        changed = self.repo / 'CLAUDE.md'
        changed.write_text('replacement content')
        head = self.compare.commit_all(self.repo, 'replacement')
        subprocess.run(['git', '-C', str(self.repo), 'replace', self.base, head], check=True)
        with self.assertRaises(RuntimeError):
            self.compare.compare(self.base_root, self.repo, self.base, self.base,
                                 self.work / 'data', self.guard.fixture_index_pins())

    def event(self, head=None):
        """A trusted event binds a PR number, repository and immutable endpoints."""
        return {'number': 6163, 'repository': {'full_name': REPOSITORY}, 'pull_request': {
            'number': 6163, 'base': {'sha': self.base, 'repo': {'full_name': REPOSITORY}},
            'head': {'sha': head or self.base}}}

    def test_w1_private_bare_store_cleanup_and_immutable_binding(self):
        # Use Git's local transport only inside the test double; production accepts one HTTPS remote.
        calls = []

        def acquire(repo, base, head, number):
            calls.append((repo, base, head, number))
            subprocess.run(['git', '-C', str(repo), 'fetch', '--quiet', str(self.repo),
                            base, head], check=True)

        with mock.patch.object(self.compare, 'fetch_objects', side_effect=acquire):
            with self.compare.isolated_objects(self.repo, self.event(), self.work / 'outside') as objects:
                self.assertTrue(self.compare.git(objects, 'rev-parse', '--is-bare-repository').strip() == b'true')
                self.assertNotIn(self.repo, objects.resolve().parents)
                self.assertEqual(stat.S_IMODE(objects.parent.stat().st_mode), DIRECTORY_MODE)
                self.assertEqual(self.compare.git(objects, 'rev-parse', self.base).decode().strip(), self.base)
                self.assertFalse((objects / 'CLAUDE.md').exists())
            self.assertFalse(objects.exists())
        self.assertEqual(len(calls), 1)

    def test_w1_rejects_mismatch_and_inside_checkout_before_acquisition(self):
        for event, scratch in ((self.event('a' * 40), self.repo / 'nested'),
                               (dict(self.event(), number=True), self.work / 'outside')):
            with mock.patch.object(self.compare, 'fetch_objects') as fetch:
                with self.assertRaises(RuntimeError):
                    with self.compare.isolated_objects(self.repo, event, scratch):
                        self.fail('invalid boundary accepted')
                fetch.assert_not_called()

    def test_w1_missing_objects_fail_closed_and_clean_up(self):
        outside = self.work / 'outside'
        with mock.patch.object(self.compare, 'fetch_objects'):
            with self.assertRaises(RuntimeError):
                with self.compare.isolated_objects(self.repo, self.event(), outside):
                    self.fail('missing objects accepted')
        self.assertEqual(list(outside.iterdir()), [])


class ResourceTests(unittest.TestCase):
    """Close every descriptor and restore exact fixture permissions."""

    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def test_deep_scratch_close_failure_does_not_leak_other_descriptors(self):
        cert = module('cert_6163', 'scripts/check_cert_expiry.py')
        opened, closed = [], []
        real_open, real_close = os.open, os.close

        def record_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.append(fd)
            return fd

        def fail_first_close(fd):
            closed.append(fd)
            real_close(fd)
            if len(closed) == 1:
                raise OSError('synthetic close failure')

        try:
            with mock.patch.object(cert.os, 'open', side_effect=record_open), \
                    mock.patch.object(cert.os, 'close', side_effect=fail_first_close):
                with self.assertRaises(OSError):
                    cert.deep_scratch(self.work, len(os.fsencode(self.work)) + 500)
            self.assertGreater(len(opened), 1)
            self.assertEqual(set(closed), set(opened))
        finally:
            for fd in set(opened) - set(closed):
                real_close(fd)

    def test_deep_scratch_healthy_control(self):
        cert = module('cert_control_6163', 'scripts/check_cert_expiry.py')
        target = len(os.fsencode(self.work)) + 500
        base, deepest = cert.deep_scratch(self.work, target)
        self.assertEqual(len(os.fsencode(deepest)), target)
        self.assertTrue(deepest.is_dir())
        shutil.rmtree(base)

    def test_permission_probes_restore_private_modes(self):
        guard = module('guard_modes_6163', 'scripts/check-claude-md-size.py')
        roots = []

        def fresh():
            root = self.work / str(len(roots))
            root.mkdir()
            guard.build_fixture(root)
            for relative in (guard.MANIFEST_PATH, 'docs/reference/ARCHITECTURE_REFERENCE.md',
                             'docs/reference/CODE_STYLE.md'):
                (root / relative).chmod(PRIVATE_MODE)
            roots.append(root)
            return root

        changed = []
        real_chmod = os.chmod

        def record_chmod(path, mode, **kwargs):
            changed.append((Path(path), mode))
            real_chmod(path, mode, **kwargs)

        with mock.patch.object(guard.os, 'chmod', side_effect=record_chmod), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(guard.run_manifest_cases(fresh))
            self.assertTrue(guard.run_ref_cases(fresh, 'docs/reference/ARCHITECTURE_REFERENCE.md',
                                               'docs/reference/CODE_STYLE.md'))
        restored = [mode for _, mode in changed if mode != 0]
        self.assertGreaterEqual(len(restored), 3)
        self.assertEqual(set(restored), {PRIVATE_MODE})


if __name__ == '__main__':
    unittest.main()
