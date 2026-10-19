#!/usr/bin/env python3
"""LOW7731: configured scratch roots use the shared owner/mode/symlink policy."""
import argparse
import contextlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest
import unittest.mock as mock

from test_evidence_generator_5040_5042 import ScratchCase, load

CALLER_CWD = Path.cwd()
RUNNER = Path(__file__).resolve().parents[2] / 'evidence' / 'run_cert.py'
TIP = 'a' * 40
PRIVATE_MODE = 0o700
GROUP_MODE = 0o775
UNSAFE_MODE = 0o777


class ConfiguredScratch7731(ScratchCase):
    def setUp(self):
        super().setUp()
        self.rc = load('run_cert')
        self.tmpdir = self.dir / 'scratch'
        self.targets = self.dir / 'targets'
        self.tmpdir.mkdir(mode=PRIVATE_MODE)
        self.targets.mkdir(mode=PRIVATE_MODE)
        self.marker = self.dir / 'launched'

    def args(self):
        return argparse.Namespace(tip=TIP, wt=str(self.dir), outd=str(self.dir / 'out'), leg='battery',
                                  tmpdir=str(self.tmpdir), targets=str(self.targets))

    def drive(self, root, source, configured=None):
        """Use the actual parser and constructor; any unexpected leg execution leaves a marker."""
        selected = configured or getattr(self, root)
        argv = ['run_cert.py', 'battery', '--tip', TIP, '--wt', str(self.dir), '--outd', str(self.dir / 'out'),
                '--targets', str(self.targets), '--tmpdir', str(self.tmpdir)]
        option = '--' + root
        argv[argv.index(option) + 1] = str(selected)
        env_name = 'CERT_' + root.upper()
        if source == 'env':
            index = argv.index(option)
            del argv[index:index + 2]
        output = io.StringIO()
        def launched(_runner):
            self.marker.write_text('launched')
            return 0
        with mock.patch.dict(os.environ, {env_name: str(selected)}), mock.patch.object(sys, 'argv', argv), \
                mock.patch.object(self.rc.Run, 'battery', launched), contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(output):
            code = self.rc.main()
        return code, output.getvalue()

    def test_world_writable_cli_and_environment_roots_refuse_before_launch_7731(self):
        for root in ('tmpdir', 'targets'):
            path = getattr(self, root)
            path.chmod(UNSAFE_MODE)
            for source in ('arg', 'env'):
                with self.subTest(root=root, source=source):
                    code, text = self.drive(root, source)
                    self.assertEqual(code, 64, text)
                    self.assertIn('world writable', text)
                    self.assertFalse(self.marker.exists())
            path.chmod(PRIVATE_MODE)

    def test_symlink_cli_and_environment_roots_refuse_before_launch_7731(self):
        for root in ('tmpdir', 'targets'):
            link = self.dir / (root + '-link')
            link.symlink_to(getattr(self, root), target_is_directory=True)
            for source in ('arg', 'env'):
                with self.subTest(root=root, source=source):
                    code, text = self.drive(root, source, link)
                    self.assertEqual(code, 64, text)
                    self.assertIn('not a plain directory', text)
                    self.assertFalse(self.marker.exists())

    def test_owned_private_and_group_writable_controls_run_7731(self):
        for mode in (PRIVATE_MODE, GROUP_MODE):
            self.tmpdir.chmod(mode)
            self.targets.chmod(mode)
            for source in ('arg', 'env'):
                with self.subTest(mode=oct(mode), source=source):
                    code, text = self.drive('tmpdir', source)
                    self.assertEqual(code, 0, text)
                    self.assertTrue(self.marker.exists())
                    self.marker.unlink()
                    self.assertEqual(stat.S_IMODE(self.tmpdir.stat().st_mode), mode)
                    self.assertEqual(stat.S_IMODE(self.targets.stat().st_mode), mode)

    def test_actual_entry_refuses_unsafe_tmpdir_before_preflight_7731(self):
        self.tmpdir.chmod(UNSAFE_MODE)
        for source in ('arg', 'env'):
            command = [sys.executable, str(RUNNER), 'battery', '--tip', TIP, '--wt', str(self.dir),
                       '--outd', str(self.dir / ('entry-' + source)), '--targets', str(self.targets),
                       '--cargo-slot', str(self.dir / 'missing-wrapper')]
            if source == 'arg':
                command.extend(['--tmpdir', str(self.tmpdir)])
            env = dict(os.environ, CERT_TMPDIR=str(self.tmpdir))
            result = subprocess.run(command, cwd=CALLER_CWD, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
            self.assertIn('world writable', result.stderr)
            self.assertNotIn('preflight', result.stdout)

    def test_foreign_owned_root_is_refused_when_fixture_is_feasible_7731(self):
        other_uid = os.geteuid() + 1
        try:
            os.chown(self.tmpdir, other_uid, -1)
        except PermissionError:
            self.skipTest('cannot establish a genuinely foreign-owned fixture without privileges')
        self.addCleanup(os.chown, self.tmpdir, os.geteuid(), -1)
        self.assertEqual(self.tmpdir.stat().st_uid, other_uid)
        code, text = self.drive('tmpdir', 'arg')
        self.assertEqual(code, 64, text)
        self.assertIn('owned by uid', text)
        self.assertFalse(self.marker.exists())

    def test_guard_is_rechecked_before_creating_private_child_directories_7731(self):
        runner = self.rc.Run(self.args())
        self.tmpdir.chmod(UNSAFE_MODE)
        with self.assertRaises(self.rc.ConfigError):
            runner.run(['true'], self.dir / 'child.out', gate=False)
        self.assertEqual(list(self.tmpdir.iterdir()), [])

    def test_owned_roots_allow_real_isolated_child_and_cleanup_7731(self):
        for mode in (PRIVATE_MODE, GROUP_MODE):
            self.tmpdir.chmod(mode)
            self.targets.chmod(mode)
            runner = self.rc.Run(self.args())
            output = self.dir / ('child-' + str(mode) + '.out')
            code = runner.run([sys.executable, '-c', 'import os; print(oct(os.stat(".").st_mode & 0o777))'],
                              output, gate=False)
            self.assertEqual(code, 0)
            self.assertEqual(output.read_text().strip(), '0o700')
            self.assertEqual(list(self.tmpdir.iterdir()), [])

    def test_replaced_root_refuses_before_creation_or_launch_7731(self):
        for root in ('tmpdir', 'targets'):
            with self.subTest(root=root):
                runner = self.rc.Run(self.args())
                path = getattr(self, root)
                saved = path.with_name(root + '-saved')
                path.rename(saved)
                path.mkdir(mode=GROUP_MODE)
                with self.assertRaisesRegex(self.rc.ConfigError, 'replaced'), \
                        mock.patch.object(self.rc.subprocess, 'run') as launch:
                    runner.run(['true'], self.dir / 'child.out', gate=False)
                launch.assert_not_called()
                self.assertEqual(list(self.tmpdir.iterdir()), [])
                path.rmdir()
                saved.rename(path)

    def test_private_creation_uses_checked_fd_when_root_is_renamed_7731(self):
        runner = self.rc.Run(self.args())
        moved = self.dir / 'moved-scratch'
        real_mkdir = os.mkdir
        observed = []
        def swap(path, mode=0o777, *, dir_fd=None):
            if dir_fd is not None and not observed:
                self.tmpdir.rename(moved)
                real_mkdir(self.tmpdir, PRIVATE_MODE)
                observed.append(os.fstat(dir_fd).st_ino)
            return real_mkdir(path, mode, dir_fd=dir_fd)
        with mock.patch.object(os, 'mkdir', side_effect=swap), \
                mock.patch.object(self.rc.subprocess, 'run') as launch, \
                self.assertRaisesRegex(self.rc.ConfigError, 'replaced'):
            runner.run(['true'], self.dir / 'child.out', gate=False)
        launch.assert_not_called()
        self.assertEqual(observed, [moved.stat().st_ino])
        self.assertEqual(list(self.tmpdir.iterdir()), [])
        self.assertEqual(list(moved.iterdir()), [], 'cleanup stays relative to the original checked root')

    def test_cleanup_leaves_replacement_private_directory_untouched_7731(self):
        runner = self.rc.Run(self.args())
        replacement = []
        real_run = subprocess.run
        def swap_after_child(*args, **kwargs):
            result = real_run(*args, **kwargs)
            box = Path(kwargs['cwd'])
            box.rename(self.dir / 'original-child')
            box.mkdir(mode=PRIVATE_MODE)
            canary = box / 'untouched'
            canary.write_text('preserve')
            replacement.append(canary)
            return result
        with mock.patch.object(self.rc.subprocess, 'run', side_effect=swap_after_child):
            self.assertEqual(runner.run(['true'], self.dir / 'child.out', gate=False), 0)
        self.assertEqual(len(replacement), 1)
        self.assertEqual(replacement[0].read_text(), 'preserve')
        self.assertEqual(runner.bad, 1)
        self.assertIn('was replaced; left in place', runner.log.read_text())


if __name__ == '__main__':
    unittest.main()
