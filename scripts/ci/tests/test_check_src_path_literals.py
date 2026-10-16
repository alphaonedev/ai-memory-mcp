#!/usr/bin/env python3
"""Unit tests for scripts/ci/check_src_path_literals.py (#7260).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_check_src_path_literals.py

The ratchet counts hard-coded ``src/`` path literals in tests/, scripts/ and
.github/workflows/ against a committed per-file baseline. A new literal fails,
the baseline may only shrink, and a missing scan root is red (never a pass).
"""
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'ci' / 'check_src_path_literals.py'
SPEC = importlib.util.spec_from_file_location('check_src_path_literals', SCRIPT)
cs = importlib.util.module_from_spec(SPEC)
sys.modules['check_src_path_literals'] = cs
SPEC.loader.exec_module(cs)

EXIT_RED = 2
EXIT_VIOLATION = 1
BASELINE_REL = 'scripts/qc-allowlists/src-path-literals-baseline.txt'


class CountLiterals(unittest.TestCase):
    def test_counts_each_src_path_literal(self):
        self.assertEqual(cs.count_literals('read("src/a.rs"); read("src/b/c.rs");'), 2)

    def test_ignores_prefixed_paths_and_words(self):
        self.assertEqual(cs.count_literals('sdk/typescript/src/wake.ts and tsrc/x and mysrc/y'), 0)

    def test_counts_a_bare_src_directory_with_a_trailing_slash(self):
        self.assertEqual(cs.count_literals('ls src/'), 1)

    def test_plain_word_src_is_not_a_path_literal(self):
        self.assertEqual(cs.count_literals('let src = String::new();'), 0)


class Baseline(unittest.TestCase):
    def test_round_trip(self):
        data = {'tests/a.rs': 3, 'scripts/b.py': 1}
        self.assertEqual(cs.parse_baseline(cs.render_baseline(data)), data)

    def test_comments_and_blanks_are_ignored(self):
        self.assertEqual(cs.parse_baseline('# c\n\n2 tests/a.rs\n'), {'tests/a.rs': 2})

    def test_malformed_line_is_refused(self):
        with self.assertRaises(cs.RatchetError):
            cs.parse_baseline('not-a-count tests/a.rs\n')

    def test_duplicate_entry_is_refused(self):
        with self.assertRaises(cs.RatchetError):
            cs.parse_baseline('1 tests/a.rs\n2 tests/a.rs\n')


class Compare(unittest.TestCase):
    def test_equal_is_clean(self):
        violations, shrinkable = cs.compare({'tests/a.rs': 2}, {'tests/a.rs': 2})
        self.assertEqual((violations, shrinkable), ([], []))

    def test_new_file_with_literals_is_a_violation(self):
        violations, _ = cs.compare({'tests/a.rs': 1, 'tests/new.rs': 1}, {'tests/a.rs': 1})
        self.assertEqual(len(violations), 1)
        self.assertIn('tests/new.rs', violations[0])

    def test_increase_is_a_violation(self):
        violations, _ = cs.compare({'tests/a.rs': 3}, {'tests/a.rs': 2})
        self.assertEqual(len(violations), 1)

    def test_decrease_is_reported_as_shrinkable(self):
        violations, shrinkable = cs.compare({'tests/a.rs': 1}, {'tests/a.rs': 2})
        self.assertEqual(violations, [])
        self.assertEqual(len(shrinkable), 1)

    def test_removed_file_is_shrinkable(self):
        violations, shrinkable = cs.compare({}, {'tests/a.rs': 2})
        self.assertEqual(violations, [])
        self.assertEqual(len(shrinkable), 1)


class LoweredBaseline(unittest.TestCase):
    def test_lowers_counts_and_drops_cleared_files(self):
        got = cs.lowered_baseline({'tests/a.rs': 1}, {'tests/a.rs': 2, 'tests/gone.rs': 4})
        self.assertEqual(got, {'tests/a.rs': 1})

    def test_refuses_to_raise_a_count(self):
        with self.assertRaises(cs.RatchetError):
            cs.lowered_baseline({'tests/a.rs': 3}, {'tests/a.rs': 2})

    def test_refuses_to_add_a_file(self):
        with self.assertRaises(cs.RatchetError):
            cs.lowered_baseline({'tests/a.rs': 1, 'tests/new.rs': 1}, {'tests/a.rs': 1})


class Repo(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='srclit-7260-')
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        for rel, text in (('tests/a.rs', 'read("src/a.rs");\nread("src/b.rs");\n'),
                          ('scripts/x.py', 'P = "src/x.rs"\n'),
                          ('.github/workflows/ci.yml', 'run: cat src/lib.rs\n')):
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        (self.root / 'scripts' / 'qc-allowlists').mkdir(parents=True, exist_ok=True)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), '--root', str(self.root), *args],
                              capture_output=True, text=True, check=False)

    def seed_baseline(self):
        counts = cs.scan(self.root)
        (self.root / BASELINE_REL).write_text(cs.render_baseline(counts))
        return counts

    def test_scan_counts_per_file_over_all_three_roots(self):
        self.assertEqual(cs.scan(self.root), {'tests/a.rs': 2, 'scripts/x.py': 1,
                                              '.github/workflows/ci.yml': 1})

    def test_matching_baseline_is_green(self):
        self.seed_baseline()
        run = self.run_cli()
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_new_literal_fails(self):
        self.seed_baseline()
        (self.root / 'tests' / 'a.rs').write_text('read("src/a.rs");\nread("src/b.rs");\nread("src/c.rs");\n')
        run = self.run_cli()
        self.assertEqual(run.returncode, EXIT_VIOLATION)
        self.assertIn('tests/a.rs', run.stderr)

    def test_new_file_fails(self):
        self.seed_baseline()
        (self.root / 'tests' / 'n.rs').write_text('read("src/n.rs");\n')
        self.assertEqual(self.run_cli().returncode, EXIT_VIOLATION)

    def test_missing_baseline_is_red(self):
        self.assertEqual(self.run_cli().returncode, EXIT_RED)

    def test_missing_scan_root_is_red(self):
        self.seed_baseline()
        (self.root / '.github' / 'workflows' / 'ci.yml').unlink()
        (self.root / '.github' / 'workflows').rmdir()
        run = self.run_cli()
        self.assertEqual(run.returncode, EXIT_RED)
        self.assertIn('missing', run.stderr)

    def test_moved_scan_root_is_red(self):
        self.seed_baseline()
        (self.root / 'tests').rename(self.root / 'tests_moved')
        self.assertEqual(self.run_cli().returncode, EXIT_RED)

    def test_update_baseline_lowers_only(self):
        self.seed_baseline()
        (self.root / 'tests' / 'a.rs').write_text('read("src/a.rs");\n')
        run = self.run_cli('--update-baseline')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(cs.parse_baseline((self.root / BASELINE_REL).read_text())['tests/a.rs'], 1)

    def test_update_baseline_refuses_an_increase_and_leaves_the_file(self):
        self.seed_baseline()
        before = (self.root / BASELINE_REL).read_text()
        (self.root / 'tests' / 'a.rs').write_text('read("src/a.rs");\n' * 5)
        run = self.run_cli('--update-baseline')
        self.assertEqual(run.returncode, EXIT_VIOLATION)
        self.assertEqual((self.root / BASELINE_REL).read_text(), before)


if __name__ == '__main__':
    unittest.main()
