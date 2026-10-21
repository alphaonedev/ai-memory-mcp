"""Red-first tests for #7878 (manifest shape -> rc 2 + one ::error::) and #7879 (exact raw in the error)."""
import io
import json
import shutil
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import shard_budget as sb  # noqa: E402

SCRATCH = HERE.parents[2] / '.local-runs' / 'shard-budget-7878'
BUDGETS = ['--budget', 'serial=660', '--budget', 'parallel_1=900', '--budget', 'parallel_2=900']
DEEP_LEVELS = 200000
RC_BAD = 2


class Base(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        SCRATCH.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def run_text(self, text, name='manifest.json'):
        path = SCRATCH / name
        path.write_text(text)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = sb.main(['gate', '--manifest', str(path)] + BUDGETS)
        return rc, out.getvalue(), err.getvalue()

    def assert_one_error(self, text, name='manifest.json'):
        rc, _, err = self.run_text(text, name)
        self.assertEqual(rc, RC_BAD, err)
        lines = err.splitlines()
        self.assertEqual(len(lines), 1, err)
        self.assertTrue(lines[0].startswith('::error::'), err)
        return lines[0]


class Shape(Base):
    def test_top_level_list(self):
        self.assertIn('manifest.json', self.assert_one_error('[1, 2]'))

    def test_top_level_null(self):
        self.assertIn('manifest.json', self.assert_one_error('null'))

    def test_top_level_scalar(self):
        self.assert_one_error('42')
        self.assert_one_error('"text"')

    def test_estimates_not_an_object(self):
        self.assert_one_error(json.dumps({'estimate_seconds': [1, 2]}))
        self.assert_one_error(json.dumps({'estimate_seconds': None}))
        self.assert_one_error(json.dumps({'estimate_seconds': 7}))

    def test_deep_nesting(self):
        self.assertIn('manifest.json', self.assert_one_error('[' * DEEP_LEVELS + ']' * DEEP_LEVELS))

    def test_deep_nesting_inside_object(self):
        self.assert_one_error('{"estimate_seconds": ' + '[' * DEEP_LEVELS + ']' * DEEP_LEVELS + '}')

    def test_path_cannot_forge_error_lines(self):
        self.assert_one_error('[]', name='m\n::error::forged.json')

    def test_path_with_carriage_return(self):
        self.assert_one_error('[]', name='a\r::error::x.json')


class ExactRaw(Base):
    def test_fractional_raw_printed_exactly(self):
        text = json.dumps({'estimate_seconds': {'serial_threads_1': 1000.1,
                                                'parallel_1_est_min_tests_threads': 1,
                                                'parallel_2_est_min_tests_threads': 1}})
        rc, _, err = self.run_text(text)
        self.assertEqual(rc, RC_BAD)
        self.assertIn('(raw 1000.1s x 0.66)', err)
        self.assertIn('estimate 661s', err)


if __name__ == '__main__':
    unittest.main()
