#!/usr/bin/env python3
"""Unit tests for scripts/ci/install_nextest.py (#7259 round 2).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_install_nextest_7259.py

The installer builds cargo-nextest from crates.io (pinned, --locked) into a
directory this job owns and puts that directory first on the PATH of later
steps. It never trusts a binary somebody else left in ~/.cargo/bin.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'ci' / 'install_nextest.py'
SPEC = importlib.util.spec_from_file_location('install_nextest', SCRIPT)
inst = importlib.util.module_from_spec(SPEC)
sys.modules['install_nextest'] = inst
SPEC.loader.exec_module(inst)


class Recorder:
    """Stand-in for subprocess.run: records argv, answers `--version`."""

    def __init__(self, version_line='cargo-nextest 0.9.146 (abc 2026-10-01)', install_rc=0):
        self.calls = []
        self.version_line = version_line
        self.install_rc = install_rc

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        done = type('Done', (), {})()
        done.returncode = self.install_rc if argv[:2] == ['cargo', 'install'] else 0
        done.stdout = self.version_line + '\n'
        return done


class InstallCommand(unittest.TestCase):
    def test_install_is_pinned_locked_and_rooted_in_the_job_directory(self):
        argv = inst.install_argv('0.9.146', Path('/job/tmp/cargo-nextest'))
        self.assertEqual(argv, ['cargo', 'install', 'cargo-nextest', '--locked', '--version', '0.9.146',
                                '--root', '/job/tmp/cargo-nextest'])

    def test_root_defaults_under_runner_temp_never_cargo_home(self):
        root = inst.default_root({'RUNNER_TEMP': '/job/tmp', 'CARGO_HOME': '/home/x/.cargo'})
        self.assertEqual(root, Path('/job/tmp') / 'cargo-nextest')

    def test_missing_runner_temp_is_refused(self):
        with self.assertRaises(inst.InstallError):
            inst.default_root({})

    def test_version_must_be_three_numeric_parts(self):
        for bad in ('', '0.9', '0.9.146 --git x', 'latest', '0.9.146;rm'):
            with self.assertRaises(inst.InstallError, msg=bad):
                inst.check_version(bad)
        self.assertEqual(inst.check_version('0.9.146'), '0.9.146')


class Run(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.root = base / 'cargo-nextest'
        self.github_path = base / 'github_path'

    def run_install(self, recorder, version='0.9.146'):
        return inst.run(version, self.root, self.github_path, runner=recorder)

    def test_installs_verifies_the_installed_binary_and_extends_github_path(self):
        rec = Recorder()
        self.assertEqual(self.run_install(rec), 0)
        self.assertEqual(rec.calls[0][:2], ['cargo', 'install'])
        self.assertEqual(rec.calls[1], [str(self.root / 'bin' / 'cargo-nextest'), 'nextest', '--version'])
        self.assertEqual(self.github_path.read_text(encoding='utf-8'), str(self.root / 'bin') + '\n')

    def test_there_is_no_version_shortcut_the_install_always_runs(self):
        rec = Recorder()
        self.run_install(rec)
        self.assertEqual(rec.calls[0][:2], ['cargo', 'install'])
        self.assertNotIn(['cargo', 'nextest', '--version'], rec.calls)

    def test_failed_install_is_a_failure_and_leaves_github_path_alone(self):
        rec = Recorder(install_rc=101)
        self.assertEqual(self.run_install(rec), 101)
        self.assertFalse(self.github_path.exists())

    def test_installed_binary_of_the_wrong_version_is_refused(self):
        rec = Recorder(version_line='cargo-nextest 0.9.100 (abc 2025-01-01)')
        self.assertEqual(self.run_install(rec), 1)
        self.assertFalse(self.github_path.exists())

    def test_prefix_of_the_version_is_not_a_match(self):
        rec = Recorder(version_line='cargo-nextest 0.9.1461 (abc)')
        self.assertEqual(self.run_install(rec), 1)


class NoShell(unittest.TestCase):
    def test_script_is_python_without_shell_true(self):
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertTrue(text.startswith('#!/usr/bin/env python3'))
        self.assertNotIn('shell=True', text)


if __name__ == '__main__':
    unittest.main()
