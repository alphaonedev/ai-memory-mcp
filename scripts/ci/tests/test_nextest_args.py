#!/usr/bin/env python3
"""Unit tests for scripts/ci/nextest_args.py (#7259).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_nextest_args.py

The CI helpers (``run_tests``, ``run_isolated_lane``) build ``cargo test``
shaped argument lists: libtest flags after a ``--``. ``cargo nextest run``
rejects ``--test-threads`` after the ``--``, so the translator moves it in
front and keeps the libtest filters (``--skip``, positional prefixes,
``--exact``) after the ``--``.
"""
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'ci' / 'nextest_args.py'
SPEC = importlib.util.spec_from_file_location('nextest_args', SCRIPT)
na = importlib.util.module_from_spec(SPEC)
sys.modules['nextest_args'] = na
SPEC.loader.exec_module(na)


class Translate(unittest.TestCase):
    def test_plain_selection_passes_through(self):
        self.assertEqual(na.translate(['--features', 'sal-postgres', '--lib']),
                         ['--features', 'sal-postgres', '--lib'])

    def test_empty_selection_stays_empty(self):
        self.assertEqual(na.translate([]), [])

    def test_test_threads_equals_form_moves_before_the_separator(self):
        self.assertEqual(na.translate(['--lib', '--', '--test-threads=3']),
                         ['--lib', '--test-threads', '3'])

    def test_test_threads_space_form_is_accepted(self):
        self.assertEqual(na.translate(['--lib', '--', '--test-threads', '1']),
                         ['--lib', '--test-threads', '1'])

    def test_skip_and_positional_filters_stay_after_the_separator(self):
        got = na.translate(['--lib', '--', '--test-threads=3', '--skip', 'store::postgres',
                            '--skip=background::auto_tag_worker'])
        self.assertEqual(got, ['--lib', '--test-threads', '3', '--',
                              '--skip', 'store::postgres', '--skip', 'background::auto_tag_worker'])
        got = na.translate(['--lib', '--', '--test-threads=1', 'store::postgres', 'curator::compaction'])
        self.assertEqual(got, ['--lib', '--test-threads', '1', '--', 'store::postgres', 'curator::compaction'])

    def test_exact_is_kept_and_ignored_flags_map_to_run_ignored(self):
        self.assertEqual(na.translate(['--', '--exact', 'a::b']), ['--', '--exact', 'a::b'])
        self.assertEqual(na.translate(['--', '--ignored']), ['--run-ignored', 'only'])
        self.assertEqual(na.translate(['--', '--include-ignored']), ['--run-ignored', 'all'])
        self.assertEqual(na.translate(['--', '--nocapture']), ['--no-capture'])

    def test_doc_tests_are_refused_because_nextest_cannot_run_them(self):
        with self.assertRaises(na.ArgError):
            na.translate(['--doc'])

    def test_bad_thread_counts_fail_closed(self):
        for bad in ('0', '-1', 'x', ''):
            with self.assertRaises(na.ArgError, msg=bad):
                na.translate(['--', '--test-threads=%s' % bad])
        with self.assertRaises(na.ArgError):
            na.translate(['--', '--test-threads'])

    def test_unknown_libtest_flag_fails_closed(self):
        with self.assertRaises(na.ArgError):
            na.translate(['--', '--shuffle'])

    def test_skip_without_value_fails_closed(self):
        with self.assertRaises(na.ArgError):
            na.translate(['--', '--skip'])


class RunnerDetection(unittest.TestCase):
    def test_nextest_prefix_is_recognised(self):
        self.assertTrue(na.is_nextest(['cargo', 'nextest', 'run', '--profile', 'ci']))
        self.assertFalse(na.is_nextest(['cargo', 'test', '--no-fail-fast']))
        self.assertFalse(na.is_nextest(['cargo', 'nextest', 'list']))
        self.assertFalse(na.is_nextest([]))

    def test_command_for_nextest_translates_the_libtest_tail(self):
        got = na.command_for(['cargo', 'nextest', 'run', '--profile', 'ci', '--no-fail-fast'],
                             ['--test', 'foo_6383'], ['--test-threads=1'])
        self.assertEqual(got, ['cargo', 'nextest', 'run', '--profile', 'ci', '--no-fail-fast',
                               '--test', 'foo_6383', '--test-threads', '1'])

    def test_command_for_cargo_test_keeps_the_libtest_shape(self):
        got = na.command_for(['cargo', 'test', '--no-fail-fast'], ['--test', 'foo'], ['--test-threads=1'])
        self.assertEqual(got, ['cargo', 'test', '--no-fail-fast', '--test', 'foo', '--', '--test-threads=1'])

    def test_command_for_without_test_args_adds_no_separator(self):
        self.assertEqual(na.command_for(['cargo', 'test'], ['--test', 'foo'], []), ['cargo', 'test', '--test', 'foo'])


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT)] + list(args), capture_output=True, text=True)

    def test_prints_one_translated_argument_per_line(self):
        done = self.run_cli('--', '--features', 'sal-postgres', '--lib', '--', '--test-threads=3', '--skip', 'a::b')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.splitlines(),
                         ['--features', 'sal-postgres', '--lib', '--test-threads', '3', '--', '--skip', 'a::b'])

    def test_empty_selection_prints_nothing_and_succeeds(self):
        done = self.run_cli('--')
        self.assertEqual((done.returncode, done.stdout), (0, ''))

    def test_untranslatable_input_exits_two(self):
        done = self.run_cli('--', '--doc')
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, '')
        self.assertIn('nextest', done.stderr)


class NoShell(unittest.TestCase):
    def test_script_is_python_without_shell_true(self):
        text = SCRIPT.read_text(encoding='utf-8')
        self.assertTrue(text.startswith('#!/usr/bin/env python3'))
        self.assertNotIn('shell=True', text)


if __name__ == '__main__':
    unittest.main()
