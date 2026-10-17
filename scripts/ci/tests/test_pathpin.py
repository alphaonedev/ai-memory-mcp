#!/usr/bin/env python3
"""Unit tests for scripts/ci/pathpin.py (#7260).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_pathpin.py

A gate that names a path literally scans nothing and passes when the path
moves. ``pathpin`` is the fail-closed resolver: a missing path, or fewer than
the required files or symbol matches, is exit 2, never a quiet zero.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'ci' / 'pathpin.py'
SPEC = importlib.util.spec_from_file_location('pathpin', SCRIPT)
pp = importlib.util.module_from_spec(SPEC)
sys.modules['pathpin'] = pp
SPEC.loader.exec_module(pp)

EXIT_RED = 2
SYMBOL = r'fn\s+needle_symbol'


def make_tree(root):
    """A tiny repo: src/a.rs (has the symbol), src/sub/b.rs, docs/readme.md."""
    (root / 'src' / 'sub').mkdir(parents=True)
    (root / 'docs').mkdir()
    (root / 'src' / 'a.rs').write_text('pub fn needle_symbol() {}\n')
    (root / 'src' / 'sub' / 'b.rs').write_text('pub fn other() {}\n')
    (root / 'docs' / 'readme.md').write_text('docs\n')


class PinFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='pathpin-7260-')
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        make_tree(self.root)


class PinPath(PinFixture):
    def test_present_directory_is_green_and_counts_files(self):
        self.assertEqual(pp.pin_path(self.root, 'src', glob='*.rs'), 2)

    def test_present_file_is_green(self):
        self.assertEqual(pp.pin_path(self.root, 'src/a.rs'), 1)

    def test_missing_path_is_red(self):
        with self.assertRaises(pp.PinError) as ctx:
            pp.pin_path(self.root, 'src/nope')
        self.assertIn('missing', str(ctx.exception))

    def test_moved_directory_is_red(self):
        (self.root / 'src').rename(self.root / 'lib_moved')
        with self.assertRaises(pp.PinError):
            pp.pin_path(self.root, 'src', glob='*.rs')

    def test_moved_file_is_red(self):
        (self.root / 'src' / 'a.rs').rename(self.root / 'src' / 'a_moved.rs')
        with self.assertRaises(pp.PinError):
            pp.pin_path(self.root, 'src/a.rs')

    def test_zero_glob_matches_is_red(self):
        with self.assertRaises(pp.PinError) as ctx:
            pp.pin_path(self.root, 'docs', glob='*.rs')
        self.assertIn('0 files', str(ctx.exception))

    def test_min_files_is_enforced(self):
        self.assertEqual(pp.pin_path(self.root, 'src', glob='*.rs', min_files=2), 2)
        with self.assertRaises(pp.PinError):
            pp.pin_path(self.root, 'src', glob='*.rs', min_files=3)

    def test_empty_directory_is_red_by_default(self):
        (self.root / 'empty').mkdir()
        with self.assertRaises(pp.PinError):
            pp.pin_path(self.root, 'empty')

    def test_minimum_below_one_is_refused(self):
        with self.assertRaises(pp.PinError):
            pp.pin_path(self.root, 'src', min_files=0)

    def test_path_escaping_the_root_is_red(self):
        with self.assertRaises(pp.PinError):
            pp.pin_path(self.root, '../outside')


class PinMatches(PinFixture):
    def test_symbol_present_is_green(self):
        self.assertEqual(pp.pin_matches(self.root, 'src', SYMBOL, glob='*.rs'), 1)

    def test_zero_symbol_matches_is_red(self):
        with self.assertRaises(pp.PinError) as ctx:
            pp.pin_matches(self.root, 'src', r'fn\s+not_there', glob='*.rs')
        self.assertIn('0 matches', str(ctx.exception))

    def test_moved_file_makes_the_symbol_pin_red(self):
        (self.root / 'src' / 'a.rs').rename(self.root / 'docs' / 'a.rs')
        with self.assertRaises(pp.PinError):
            pp.pin_matches(self.root, 'src', SYMBOL, glob='*.rs')

    def test_min_matches_is_enforced(self):
        with self.assertRaises(pp.PinError):
            pp.pin_matches(self.root, 'src', SYMBOL, glob='*.rs', min_matches=2)

    def test_missing_path_is_red_for_the_symbol_pin(self):
        with self.assertRaises(pp.PinError):
            pp.pin_matches(self.root, 'gone', SYMBOL)

    def test_invalid_regex_is_red(self):
        with self.assertRaises(pp.PinError):
            pp.pin_matches(self.root, 'src', '(', glob='*.rs')


class Cli(PinFixture):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), '--root', str(self.root), *args],
                              capture_output=True, text=True, check=False)

    def test_green_prints_counts_and_exits_zero(self):
        run = self.run_cli('--path', 'src', '--glob', '*.rs', '--min-files', '2')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('files=2', run.stdout)

    def test_missing_path_exits_two(self):
        run = self.run_cli('--path', 'src/gone')
        self.assertEqual(run.returncode, EXIT_RED)
        self.assertIn('missing', run.stderr)

    def test_too_few_files_exits_two(self):
        run = self.run_cli('--path', 'src', '--glob', '*.rs', '--min-files', '9')
        self.assertEqual(run.returncode, EXIT_RED)

    def test_symbol_green_and_red(self):
        green = self.run_cli('--path', 'src', '--glob', '*.rs', '--symbol', SYMBOL)
        self.assertEqual(green.returncode, 0, green.stderr)
        self.assertIn('matches=1', green.stdout)
        red = self.run_cli('--path', 'src', '--glob', '*.rs', '--symbol', SYMBOL, '--min-matches', '5')
        self.assertEqual(red.returncode, EXIT_RED)

    def test_move_after_a_green_run_turns_the_cli_red(self):
        self.assertEqual(self.run_cli('--path', 'src', '--glob', '*.rs').returncode, 0)
        (self.root / 'src').rename(self.root / 'moved')
        self.assertEqual(self.run_cli('--path', 'src', '--glob', '*.rs').returncode, EXIT_RED)

    def test_several_paths_are_all_pinned(self):
        run = self.run_cli('--path', 'src', '--path', 'docs')
        self.assertEqual(run.returncode, 0, run.stderr)
        run = self.run_cli('--path', 'src', '--path', 'nope')
        self.assertEqual(run.returncode, EXIT_RED)

    def test_real_repo_root_is_the_default(self):
        run = subprocess.run([sys.executable, str(SCRIPT), '--path', 'scripts/ci/pathpin.py'],
                             capture_output=True, text=True, check=False, cwd=os.fspath(self.root))
        self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == '__main__':
    unittest.main()
