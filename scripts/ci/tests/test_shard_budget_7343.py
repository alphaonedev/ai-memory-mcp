#!/usr/bin/env python3
"""Fail-fast gate and budget ratchet of the sharded enterprise-fed suite (#7343).

Measured on run 39063295132 (linux-fed enterprise-fed): the partitioner's own
estimate for the serial shard was 6274 s against a 4099 s budget, and the shard
was killed at 100% of the budget with no hung test. Two checks come out of it:

* gate: after the partition and before any shard starts, a shard whose
  calibrated estimate is above its budget fails the step at once, naming the
  shard, the estimate and the budget (the #1492 watchdog stays the hang guard);
* ratchet: a shard that passed but used more than 85% of its budget warns,
  more than 95% fails.

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only. Fixtures live under .local-runs/.
"""
import io
import json
import re
import shutil
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import shard_budget as sb  # noqa: E402

REPO = HERE.parents[2]
CI = (REPO / '.github' / 'workflows' / 'ci.yml').read_text()
SCRATCH = REPO / '.local-runs' / 'shard-budget-7343'


def function_body(text, name):
    m = re.search(r'^(\s*)%s\(\) \{\n' % re.escape(name), text, re.M)
    if not m:
        raise AssertionError('function %s() not found' % name)
    end = text.index('\n%s}\n' % m.group(1), m.end())
    return text[m.end():end]


def manifest(serial, p1, p2):
    return {'estimate_seconds': {'serial_threads_1': serial,
                                 'parallel_1_est_min_tests_threads': p1,
                                 'parallel_2_est_min_tests_threads': p2}}


def notice(shard, label, ran, of):
    return "::notice::[#1492] '[%s] %s' ran %ds of the %ds per-invocation watchdog budget (0%% used)\n" % (
        shard, label, ran, of)


class Fixture(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)
        SCRATCH.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = sb.main(argv)
        return rc, out.getvalue(), err.getvalue()


class Calibration(unittest.TestCase):
    def test_scales_come_from_the_measured_run(self):
        # run 39063295132: measured shard seconds / raw estimate
        self.assertAlmostEqual(sb.ESTIMATE_SCALE['serial'], 0.66)
        self.assertAlmostEqual(sb.ESTIMATE_SCALE['parallel_1'], 1.76)
        self.assertAlmostEqual(sb.ESTIMATE_SCALE['parallel_2'], 2.63)

    def test_thresholds(self):
        self.assertEqual((sb.WARN_FRACTION, sb.FAIL_FRACTION), (0.85, 0.95))


class Gate(Fixture):
    def write(self, serial, p1, p2):
        p = SCRATCH / 'manifest.json'
        p.write_text(json.dumps(manifest(serial, p1, p2)))
        return str(p)

    def args(self, mpath, serial, p1, p2):
        return ['gate', '--manifest', mpath, '--budget', 'serial=%d' % serial,
                '--budget', 'parallel_1=%d' % p1, '--budget', 'parallel_2=%d' % p2]

    def test_serial_estimate_above_budget_fails_at_once_and_names_everything(self):
        m = self.write(6274, 1620, 881)  # the run 39063295132 estimates
        rc, _, err = self.run_main(self.args(m, 4099, 4099, 4099))
        self.assertEqual(rc, 2)
        self.assertIn('::error::[#7343 fail-fast] shard serial', err)
        self.assertIn('estimate 4141s', err)  # 6274 x 0.66
        self.assertIn('raw 6274s', err)
        self.assertIn('budget 4099s', err)
        self.assertNotIn('shard parallel_1', err)

    def test_every_shard_over_budget_is_named(self):
        m = self.write(9000, 2000, 1500)
        rc, _, err = self.run_main(self.args(m, 4099, 3000, 3000))
        self.assertEqual(rc, 2)
        for shard in ('serial', 'parallel_1', 'parallel_2'):
            self.assertIn('shard %s' % shard, err)

    def test_within_budget_passes_and_prints_the_headroom(self):
        m = self.write(5000, 1620, 881)
        rc, out, _ = self.run_main(self.args(m, 4099, 4099, 4099))
        self.assertEqual(rc, 0)
        self.assertIn('serial', out)
        self.assertIn('budget 4099s', out)

    def test_equal_to_budget_passes(self):
        m = self.write(1000, 100, 100)
        rc, _, _ = self.run_main(self.args(m, 660, 4099, 4099))
        self.assertEqual(rc, 0)

    def gate_rc(self, serial, budget=4099):
        m = self.write(serial, 1, 1)
        return self.run_main(self.args(m, budget, 4099, 4099))

    def test_fractional_overrun_fails_7807(self):
        # raw 1000.1 x 0.66 = 660.066 s is above a 660 s budget; rounding hid it
        rc, _, err = self.gate_rc(1000.1, 660)
        self.assertEqual(rc, 2)
        self.assertIn('::error::[#7343 fail-fast] shard serial', err)
        self.assertIn('budget 660s', err)

    def test_equality_still_passes_7807(self):
        self.assertEqual(self.gate_rc(1000, 660)[0], 0)

    def test_negative_estimate_fails_closed_7808(self):
        rc, _, err = self.gate_rc(-1)
        self.assertEqual(rc, 2)
        self.assertIn('::error::', err)
        self.assertIn('shard serial', err)
        self.assertIn('-1', err)
        self.assertIn('budget 4099s', err)

    def test_nan_estimate_fails_closed_7808(self):
        rc, _, err = self.gate_rc(float('nan'))
        self.assertEqual(rc, 2)
        self.assertIn('::error::', err)
        self.assertIn('shard serial', err)
        self.assertIn('nan', err)

    def test_infinite_estimates_fail_closed_7808(self):
        for bad in (float('inf'), float('-inf')):
            rc, _, err = self.gate_rc(bad)
            self.assertEqual(rc, 2, bad)
            self.assertIn('::error::', err)
            self.assertIn('shard serial', err)

    def test_boolean_string_and_container_estimates_fail_closed_7808(self):
        for bad in (True, False, 'abc', '12', [1], {'a': 1}, None):
            rc, _, err = self.gate_rc(bad)
            self.assertEqual(rc, 2, bad)
            self.assertIn('::error::', err)

    def test_zero_estimate_still_passes_7808(self):
        self.assertEqual(self.gate_rc(0)[0], 0)

    def test_oversized_integer_estimate_fails_closed_7808(self):
        rc, _, err = self.gate_rc(10 ** 400)
        self.assertEqual(rc, 2)
        self.assertIn('::error::', err)

    def test_missing_manifest_or_budget_fails_closed(self):
        rc, _, err = self.run_main(['gate', '--manifest', str(SCRATCH / 'nope.json'), '--budget', 'serial=1'])
        self.assertEqual(rc, 2)
        self.assertIn('::error::', err)
        m = self.write(1, 1, 1)
        rc, _, err = self.run_main(['gate', '--manifest', m, '--budget', 'serial=100'])
        self.assertEqual(rc, 2)
        self.assertIn('parallel_1', err)

    def test_non_positive_or_non_numeric_budget_fails_closed(self):
        m = self.write(1, 1, 1)
        for bad in ('serial=0', 'serial=-5', 'serial=abc', 'serial', 'bogus=10'):
            rc, _, _ = self.run_main(['gate', '--manifest', m, '--budget', bad,
                                      '--budget', 'parallel_1=10', '--budget', 'parallel_2=10'])
            self.assertEqual(rc, 2, bad)


class Ratchet(Fixture):
    def shard(self, name, lines, budget):
        (SCRATCH / (name + '.log')).write_text(''.join(lines))
        (SCRATCH / (name + '.budget')).write_text('%d\n' % budget)

    def all_shards(self, serial_ran, p1_ran=1000, p2_ran=1000, budget=4000):
        self.shard('serial', [notice('serial', 'lib unittests', 90, budget),
                              notice('serial', 'test binaries', serial_ran, budget),
                              notice('serial', 'doc tests', 10, budget)], budget)
        self.shard('parallel_1', [notice('parallel_1', 'lib unittests', p1_ran, budget)], budget)
        self.shard('parallel_2', [notice('parallel_2', 'test binaries', p2_ran, budget)], budget)

    def run_ratchet(self, rc_s=0, rc_1=0, rc_2=0):
        return self.run_main(['ratchet', '--dir', str(SCRATCH), '--rc', 'serial=%d' % rc_s,
                              '--rc', 'parallel_1=%d' % rc_1, '--rc', 'parallel_2=%d' % rc_2])

    def test_under_85_percent_is_quiet(self):
        self.all_shards(3200)  # 3300/4000 = 82.5%
        rc, out, err = self.run_ratchet()
        self.assertEqual(rc, 0)
        self.assertNotIn('::warning::', out + err)

    def test_over_85_percent_warns_but_passes(self):
        self.all_shards(3350)  # 3450/4000 = 86.25%
        rc, out, err = self.run_ratchet()
        self.assertEqual(rc, 0)
        self.assertIn('::warning::[#7343 ratchet] shard serial used 3450s of 4000s (86%)', out + err)

    def test_exactly_85_percent_does_not_warn(self):
        self.all_shards(3300)  # 3400/4000 = 85.0%
        rc, out, err = self.run_ratchet()
        self.assertEqual(rc, 0)
        self.assertNotIn('::warning::', out + err)

    def test_over_95_percent_fails(self):
        self.all_shards(3720)  # 3820/4000 = 95.5%
        rc, out, err = self.run_ratchet()
        self.assertEqual(rc, 1)
        self.assertIn('::error::[#7343 ratchet] shard serial used 3820s of 4000s (96%)', out + err)

    def test_exactly_95_percent_warns_only(self):
        self.all_shards(3700)  # 3800/4000 = 95.0%
        rc, out, err = self.run_ratchet()
        self.assertEqual(rc, 0)
        self.assertIn('::warning::', out + err)

    def test_a_failed_shard_is_not_a_ratchet_matter(self):
        self.all_shards(3990)  # 100% and killed: its own exit code already fails the step
        rc, out, err = self.run_ratchet(rc_s=124)
        self.assertEqual(rc, 0)
        self.assertNotIn('ratchet', out + err)

    def test_usage_sums_every_invocation_of_the_shard(self):
        self.all_shards(1000, p1_ran=2000, budget=4000)
        (SCRATCH / 'parallel_1.log').write_text(
            notice('parallel_1', 'lib unittests', 2000, 4000) + notice('parallel_1', 'test binaries', 1900, 2000))
        rc, out, err = self.run_ratchet()
        self.assertEqual(rc, 1)  # 3900/4000
        self.assertIn('shard parallel_1 used 3900s of 4000s', out + err)

    def test_missing_budget_file_fails_closed(self):
        self.all_shards(100)
        (SCRATCH / 'serial.budget').unlink()
        rc, _, err = self.run_ratchet()
        self.assertEqual(rc, 2)
        self.assertIn('::error::', err)

    def test_worst_shard_decides(self):
        self.all_shards(100, p1_ran=3900, p2_ran=3500)
        rc, out, err = self.run_ratchet()
        self.assertEqual(rc, 1)
        self.assertIn('shard parallel_1', out + err)
        self.assertIn('shard parallel_2', out + err)


class Wiring(unittest.TestCase):
    def test_gate_runs_after_the_budgets_exist_and_before_any_shard_starts(self):
        body = function_body(CI, 'run_sharded')
        gate = body.index('scripts/ci/shard_budget.py gate')
        self.assertGreater(gate, body.index('SERIAL_BUDGET_SECS=$(('))
        self.assertGreater(gate, body.index('scripts/ci/partition_test_binaries.py'))
        self.assertLess(gate, body.index('( run_shard serial'))
        line = body[gate:body.index('\n', gate)]
        for needle in ('--manifest "$sd/manifest.json"', '--budget serial="$SERIAL_BUDGET_SECS"',
                       '--budget parallel_1="$PARALLEL_BUDGET_SECS"', '--budget parallel_2="$PARALLEL_BUDGET_SECS"',
                       '|| return "$?"'):
            self.assertIn(needle, line)
        self.assertIn('PARALLEL_BUDGET_SECS="$(cap_to_job_left "$WATCHDOG_SECS")"', body)

    def test_ratchet_runs_after_every_shard_exit_code_is_known(self):
        body = function_body(CI, 'run_sharded')
        self.assertIn('scripts/ci/shard_budget.py ratchet', body)
        self.assertGreater(body.index('scripts/ci/shard_budget.py ratchet'), body.index('wait "$pid_2"'))
        line = body[body.index('scripts/ci/shard_budget.py ratchet'):]
        line = line[:line.index('\n')]
        for needle in ('--dir "$sd"', '--rc serial="$rc_s"', '--rc parallel_1="$rc_1"', '--rc parallel_2="$rc_2"'):
            self.assertIn(needle, line)

    def test_ratchet_failure_fails_the_step(self):
        body = function_body(CI, 'run_sharded')
        self.assertRegex(body, r'shard_budget\.py ratchet[^\n]*\|\| rc_r=\$\?')
        self.assertIn('rc_r', body[body.index('shard_budget.py ratchet') + 40:])

    def test_run_shard_records_its_budget_for_the_ratchet(self):
        body = function_body(CI, 'run_shard')
        self.assertIn('echo "$SHARD_BUDGET" > "$sd/$name.budget"', body)

    def test_no_budget_is_raised(self):
        self.assertEqual(len(re.findall(r'^\s*WATCHDOG_SECS=7800\s*$', CI, re.M)), 1)
        self.assertIn('SERIAL_BUDGET_SECS=$(( JOB_TIMEOUT_MIN * 60 - (job_now - JOB_T0) - 300 ))', CI)


if __name__ == '__main__':
    unittest.main()
