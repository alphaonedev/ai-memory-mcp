#!/usr/bin/env python3
"""Unit tests for scripts/ci/load_gate.py (#6795).

The gate may wait on host load but must never fail on it: exit 0 after the
max wait, exit 2 only on bad arguments. Load and sleep are injected so no test
sleeps or reads the real load average.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only.
"""
import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import load_gate  # noqa: E402


class ShouldWait(unittest.TestCase):
    def test_boundary_is_strictly_greater(self):
        self.assertFalse(load_gate.should_wait(15.0, 10, 1.5))
        self.assertTrue(load_gate.should_wait(15.01, 10, 1.5))
        self.assertFalse(load_gate.should_wait(0.0, 10, 1.5))

    def test_high_load_waits(self):
        self.assertTrue(load_gate.should_wait(101.0, 10, 1.5))

    def test_unknown_core_count_never_waits(self):
        self.assertFalse(load_gate.should_wait(500.0, 0, 1.5))
        self.assertFalse(load_gate.should_wait(500.0, None, 1.5))


class Notice(unittest.TestCase):
    def test_format(self):
        line = load_gate.format_notice('macos-fed/enterprise-fed', 101.25, 10, 1.5, 30)
        self.assertEqual(
            line,
            "::notice::[#6795 load gate] 'macos-fed/enterprise-fed': "
            'load=101.25 cores=10 ratio=1.5 waited=30s',
        )


class Run(unittest.TestCase):
    def run_gate(self, loads, **kw):
        it = iter(loads)
        last = [loads[-1]]
        sleeps = []

        def fake_load():
            try:
                last[0] = next(it)
            except StopIteration:
                pass
            return last[0]

        out = io.StringIO()
        with redirect_stdout(out):
            rc = load_gate.run(
                label=kw.get('label', 'x'), max_ratio=1.5,
                max_wait_secs=kw.get('max_wait', 120), poll_secs=30,
                cores=10, load_fn=fake_load, sleep_fn=sleeps.append,
            )
        return rc, out.getvalue(), sleeps

    def test_idle_host_proceeds_without_sleeping(self):
        rc, out, sleeps = self.run_gate([1.0])
        self.assertEqual((rc, sleeps), (0, []))
        self.assertIn('waited=0s', out)

    def test_waits_then_proceeds_when_load_drops(self):
        rc, out, sleeps = self.run_gate([90.0, 80.0, 10.0])
        self.assertEqual(rc, 0)
        self.assertEqual(sleeps, [30, 30])
        self.assertIn('waited=60s', out)
        self.assertNotIn('::warning::', out)

    def test_never_fails_on_load_alone(self):
        rc, out, sleeps = self.run_gate([100.0], max_wait=90)
        self.assertEqual(rc, 0)
        self.assertEqual(sum(sleeps), 90)
        self.assertIn('::warning::[#6795 load gate]', out)

    def test_only_first_and_last_lines_are_annotations(self):
        rc, out, _ = self.run_gate([90.0, 80.0, 70.0, 10.0])
        self.assertEqual(out.count('::notice::[#6795 load gate]'), 2)
        self.assertIn('load=80.00', out)
        self.assertIn('load=70.00', out)
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith('::notice::'))
        self.assertTrue(lines[-1].startswith('::notice::'))

    def test_unreadable_load_warns_and_exits_0(self):
        def boom():
            raise OSError('no loadavg')
        out = io.StringIO()
        with redirect_stdout(out):
            rc = load_gate.run('x', 1.5, 60, 30, 10, boom, lambda s: None)
        self.assertEqual(rc, 0)
        self.assertIn('::warning::[#6795 load gate]', out.getvalue())


class Main(unittest.TestCase):
    def test_bad_args_exit_2(self):
        for argv in (['--max-ratio', '0'], ['--poll-secs', '0'], ['--max-wait-secs', '-1']):
            with self.assertRaises(SystemExit) as cm:
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    load_gate.main(argv + ['--label', 'x'])
            self.assertEqual(cm.exception.code, 2, argv)


if __name__ == '__main__':
    unittest.main()
