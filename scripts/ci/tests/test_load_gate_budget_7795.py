#!/usr/bin/env python3
"""Budget admission regression tests for #7795; fake clocks never sleep."""
import io
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import load_gate


class Budget7795(unittest.TestCase):
    def gate(self, budget=100, reserve=80, loads=(100,), wait=60, oversleep=0,
             read_time=0):
        clock = [0]
        sleeps = []
        samples = iter(loads)
        last = [loads[-1]]

        def load():
            clock[0] += read_time
            last[0] = next(samples, last[0])
            return last[0]

        def sleep(seconds):
            sleeps.append(seconds)
            clock[0] += seconds + oversleep

        out = io.StringIO()
        with redirect_stdout(out):
            rc = load_gate.run('test', 1.5, wait, 30, 10, load, sleep,
                               budget_secs=budget, min_suite_secs=reserve,
                               clock_fn=lambda: clock[0])
        return rc, out.getvalue(), sleeps

    def test_7795_saturated_insufficient_budget_fails_before_wait(self):
        rc, out, sleeps = self.gate(budget=79)
        self.assertEqual((rc, sleeps), (3, []))
        self.assertIn('remaining budget 79', out)
        self.assertIn('configured suite reserve 80', out)

    def test_7795_saturated_sufficient_budget_keeps_bounded_wait(self):
        rc, out, sleeps = self.gate(budget=200)
        self.assertEqual((rc, sum(sleeps)), (0, 60))
        self.assertIn('::warning::', out)

    def test_7795_idle_sufficient_budget_proceeds(self):
        self.assertEqual(self.gate(loads=(1,))[::2], (0, []))

    def test_7795_idle_insufficient_budget_fails(self):
        self.assertEqual(self.gate(budget=79, loads=(1,))[0], 3)

    def test_7795_wait_stops_at_reserve_boundary(self):
        self.assertEqual(self.gate()[::2], (0, [20]))

    def test_7795_oversleep_charged_before_load_clears(self):
        self.assertEqual(self.gate(loads=(100, 1), oversleep=1)[0], 3)

    def test_7795_load_read_time_charged(self):
        self.assertEqual(self.gate(budget=80, loads=(1,), read_time=1)[0], 3)

    def test_7795_wait_deadline_includes_oversleep(self):
        self.assertEqual(self.gate(budget=300, wait=40, oversleep=20)[::2], (0, [30]))

    def test_7795_targeted_zero_reserve_refuses_expired_budget(self):
        self.assertEqual(self.gate(budget=-1, reserve=0)[0], 3)

    def test_7795_zero_wait_rechecks_without_sleep(self):
        self.assertEqual(self.gate(wait=0)[::2], (0, []))

    def test_7795_unreadable_load_cannot_bypass_budget(self):
        with redirect_stdout(io.StringIO()):
            rc = load_gate.run('test', 1.5, 0, 30, 10,
                               lambda: (_ for _ in ()).throw(OSError('unavailable')),
                               lambda _: None, budget_secs=1, min_suite_secs=2)
        self.assertEqual(rc, 3)


class Cli7795(unittest.TestCase):
    def invoke(self, argv, env=None):
        with patch.dict(os.environ, env or {}, clear=True), \
                patch.object(load_gate.time, 'time', return_value=1000), \
                patch.object(load_gate, 'run', return_value=0) as run, \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = load_gate.main(argv)
        return rc, run.call_args

    def test_7795_job_minutes_elapsed_and_safety_counted_once(self):
        rc, call = self.invoke(['--job-timeout-minutes', '60', '--min-suite-secs', '400'],
                               {'JOB_T0': '900'})
        self.assertEqual(rc, 0)
        self.assertEqual(call.kwargs['budget_secs'], 3200)
        self.assertEqual(call.kwargs['min_suite_secs'], 400)

    def test_7795_expired_job_budget_is_not_clamped(self):
        _, call = self.invoke(['--job-timeout-minutes', '1', '--min-suite-secs', '0'],
                              {'JOB_T0': '900'})
        self.assertEqual(call.kwargs['budget_secs'], -340)

    def test_7795_invalid_budget_arguments_fail_closed(self):
        cases = [(['--budget-secs', value, '--min-suite-secs', '1'], {})
                 for value in ('nan', 'inf', '-inf', 'bad', '1.5')]
        cases += [(['--budget-secs', '100'], {}),
                  (['--min-suite-secs', '1'], {}),
                  (['--budget-secs', '100', '--min-suite-secs', '-1'], {}),
                  (['--max-ratio', 'nan'], {}), (['--max-ratio', 'inf'], {})]
        for start in ('', 'bad', '0', '-1', '1001', 'nan', '0900'):
            cases.append((['--job-timeout-minutes', '60', '--min-suite-secs', '1'],
                          {'JOB_T0': start}))
        for argv, env in cases:
            with self.subTest(argv=argv, env=env):
                with self.assertRaises(SystemExit) as error:
                    self.invoke(argv, env)
                self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
